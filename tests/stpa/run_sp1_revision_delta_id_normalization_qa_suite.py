#!/usr/bin/env python3
"""UI-only QA suite for SP1 revision-delta ID normalization.

This is the executable form of
``features/qa_sp1_revision_delta_id_normalization.md``. It starts a
deterministic OpenAI-compatible fixture server, drives only the public
``asago-scenario-generator stpa-run`` and ``stpa-report`` commands, and inspects their
published YAML, JSONL, manifest, and HTML artifacts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

from sp2_qa_stub_llm import _build_fill_response
from sp3_qa_stub_llm import (
    _build_attack_tree_response,
    _build_bdi_response,
    _build_gherkin_response,
    _build_narrative_response,
    _determine_call_type,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUCCESS_WARNING_TERMS = ("revision failed", "revision delta merge degraded")
UNRESOLVED_FIELDS = (
    ("feedback-updates", "missing-state"),
    ("process-feedback-source", "missing-controller"),
    ("control-action-target", "missing-process"),
    ("feedback-source", "missing-process"),
    ("coordination-source", "missing-controller"),
    ("coordination-target", "missing-controller"),
    ("coordination-shared-pm", "missing-state"),
)


def _responsibility(
    resp_id: str,
    *,
    rc_id: str,
    pm_id: str,
    ca_id: str,
    fb_id: str,
    description: str,
    updates: str | None = None,
    feedback_source: str | None = None,
    target: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    process_model_part: dict[str, Any] = {
        "pm_id": pm_id,
        "description": f"{description} state",
    }
    if feedback_source is not None:
        process_model_part["feedback_source"] = {
            "type": "responsibility",
            "id": feedback_source,
        }

    control_action: dict[str, Any] = {
        "ca_id": ca_id,
        "description": f"{description} action",
    }
    if target is not None:
        control_action["target"] = {
            "type": "controlled_process",
            "id": target,
        }

    feedback_channel: dict[str, Any] = {
        "fb_id": fb_id,
        "description": f"{description} feedback",
        "updates": updates or pm_id,
    }
    if source is not None:
        feedback_channel["source"] = {
            "type": "controlled_process",
            "id": source,
        }

    return {
        "resp_id": resp_id,
        "description": description,
        "responsibility_constraints": [
            {"rc_id": rc_id, "description": f"{description} constraint"}
        ],
        "security_constraint_refs": ["SC-1"],
        "process_model_parts": [process_model_part],
        "control_actions": [control_action],
        "feedback_channels": [feedback_channel],
    }


def _coordination_link(
    link_id: str,
    *,
    source: str,
    target: str,
    shared_pm: str,
    cm_id: str,
    description: str = "Revision coordination",
) -> dict[str, Any]:
    return {
        "link_id": link_id,
        "source": source,
        "target": target,
        "shared_pm": shared_pm,
        "coordination_mechanism": {
            "cm_id": cm_id,
            "description": f"{description} mechanism",
            "payload": "revision-payload",
        },
        "description": description,
    }


def _base_responsibilities() -> dict[str, Any]:
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Original responsibility one",
                "responsibility_constraints": [
                    {"rc_id": "RC-1-1", "description": "Original constraint one"}
                ],
                "security_constraint_refs": ["SC-1"],
                "process_model_parts": [
                    {
                        "pm_id": "PM-1-1",
                        "description": "Original state one",
                        "feedback_source": {
                            "type": "responsibility",
                            "id": "RESP-2",
                        },
                    }
                ],
            },
            {
                "resp_id": "RESP-2",
                "description": "Original responsibility two",
                "responsibility_constraints": [
                    {"rc_id": "RC-2-1", "description": "Original constraint two"}
                ],
                "security_constraint_refs": ["SC-1"],
                "process_model_parts": [
                    {
                        "pm_id": "PM-2-1",
                        "description": "Original state two",
                        "feedback_source": {
                            "type": "responsibility",
                            "id": "RESP-1",
                        },
                    }
                ],
            },
        ]
    }


def _base_control_elements() -> dict[str, Any]:
    return {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Original action one",
                "target": {"type": "controlled_process", "id": "CP-1"},
            },
            {
                "ca_id": "CA-2-1",
                "description": "Original action two",
                "target": {"type": "controlled_process", "id": "CP-1"},
            },
        ],
        "feedback_channels": [
            {
                "fb_id": "FB-1-1",
                "description": "Original feedback one",
                "updates": "PM-1-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
            },
            {
                "fb_id": "FB-2-1",
                "description": "Original feedback two",
                "updates": "PM-2-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
            },
        ],
        "controlled_processes": [{"cp_id": "CP-1", "description": "Original process"}],
    }


def _base_coordination() -> dict[str, Any]:
    return {
        "coordination_links": [
            _coordination_link(
                "CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                cm_id="CM-1",
                description="Original coordination",
            )
        ],
        "integrity_findings": [],
    }


def _addition(
    prefix: str,
    *,
    description: str = "Revision addition",
) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
    ids = {
        "resp": f"{prefix}-controller",
        "rc": f"{prefix}-constraint",
        "pm": f"{prefix}-state",
        "ca": f"{prefix}-action",
        "fb": f"{prefix}-feedback",
        "cp": f"{prefix}-process",
        "link": f"{prefix}-link",
        "cm": f"{prefix}-mechanism",
    }
    responsibility = _responsibility(
        ids["resp"],
        rc_id=ids["rc"],
        pm_id=ids["pm"],
        ca_id=ids["ca"],
        fb_id=ids["fb"],
        description=description,
        feedback_source=ids["resp"],
        target=ids["cp"],
        source=ids["cp"],
    )
    link = _coordination_link(
        ids["link"],
        source=ids["resp"],
        target="RESP-1",
        shared_pm=ids["pm"],
        cm_id=ids["cm"],
    )
    return responsibility, ids, link


def _revision_delta(variant: str) -> dict[str, Any]:
    if variant == "noop":
        return {}

    if variant in {"malformed", "deterministic-a", "deterministic-b"}:
        prefix = {
            "malformed": "source",
            "deterministic-a": "alpha",
            "deterministic-b": "omega",
        }[variant]
        added, ids, link = _addition(prefix)
        return {
            "new_responsibilities": [added],
            "new_controlled_processes": [
                {"cp_id": ids["cp"], "description": "Revision process"}
            ],
            "new_coordination_links": [link],
            "modified_responsibilities": [],
        }

    if variant == "duplicates":
        shared = {
            "rc_id": "shared-constraint",
            "pm_id": "shared-state",
            "ca_id": "shared-action",
            "fb_id": "shared-feedback",
        }
        modified = _responsibility(
            "RESP-2",
            **shared,
            description="Updated duplicate-source responsibility",
            feedback_source="RESP-2",
            target="CP-1",
            source="CP-1",
        )
        added = _responsibility(
            "added-controller",
            **shared,
            description="Added duplicate-source responsibility",
            feedback_source="added-controller",
            target="CP-1",
            source="CP-1",
        )
        return {
            "new_responsibilities": [added],
            "modified_responsibilities": [modified],
        }

    if variant == "references":
        modified = _responsibility(
            "RESP-2",
            rc_id="revised-constraint",
            pm_id="revised-state",
            ca_id="revised-action",
            fb_id="revised-feedback",
            description="Updated reference responsibility",
            feedback_source="revised-controller",
            target="revised-process",
            source="revised-process",
        )
        added = _responsibility(
            "revised-controller",
            rc_id="controller-constraint",
            pm_id="controller-state",
            ca_id="controller-action",
            fb_id="controller-feedback",
            description="Added reference controller",
            feedback_source="revised-controller",
            target="revised-process",
            source="revised-process",
        )
        return {
            "new_responsibilities": [added],
            "new_controlled_processes": [
                {"cp_id": "revised-process", "description": "Revised process"}
            ],
            "new_coordination_links": [
                _coordination_link(
                    "revised-link",
                    source="revised-controller",
                    target="RESP-1",
                    shared_pm="revised-state",
                    cm_id="revised-mechanism",
                )
            ],
            "modified_responsibilities": [modified],
        }

    if variant == "positions":
        modified = _responsibility(
            "RESP-2",
            rc_id="RC-90-1",
            pm_id="PM-90-1",
            ca_id="CA-90-1",
            fb_id="FB-90-1",
            description="Updated position responsibility",
            feedback_source="RESP-1",
            target="CP-1",
            source="CP-1",
        )
        added = _responsibility(
            "RESP-90",
            rc_id="RC-90-2",
            pm_id="PM-90-2",
            ca_id="CA-90-2",
            fb_id="FB-90-2",
            description="Added position responsibility",
            feedback_source="RESP-90",
            target="CP-70",
            source="CP-70",
        )
        return {
            "new_responsibilities": [added],
            "new_controlled_processes": [
                {"cp_id": "CP-70", "description": "Added position process"}
            ],
            "new_coordination_links": [
                _coordination_link(
                    "CL-80",
                    source="RESP-90",
                    target="RESP-1",
                    shared_pm="PM-90-2",
                    cm_id="CM-60",
                )
            ],
            "modified_responsibilities": [modified],
        }

    if variant == "canonical":
        modified = _responsibility(
            "RESP-2",
            rc_id="RC-2-1",
            pm_id="PM-2-1",
            ca_id="CA-2-1",
            fb_id="FB-2-1",
            description="Canonical updated responsibility",
            feedback_source="RESP-1",
            target="CP-1",
            source="CP-1",
        )
        added = _responsibility(
            "RESP-3",
            rc_id="RC-3-1",
            pm_id="PM-3-1",
            ca_id="CA-3-1",
            fb_id="FB-3-1",
            description="Canonical addition",
            feedback_source="RESP-3",
            target="CP-2",
            source="CP-2",
        )
        return {
            "new_responsibilities": [added],
            "new_controlled_processes": [
                {"cp_id": "CP-2", "description": "Canonical process"}
            ],
            "new_coordination_links": [
                _coordination_link(
                    "CL-2",
                    source="RESP-3",
                    target="RESP-1",
                    shared_pm="PM-3-1",
                    cm_id="CM-2",
                )
            ],
            "modified_responsibilities": [modified],
        }

    if variant == "report":
        delta = _revision_delta("duplicates")
        delta["new_controlled_processes"] = [
            {"cp_id": "report-process", "description": "Report process"}
        ]
        delta["new_coordination_links"] = [
            _coordination_link(
                "report-link",
                source="added-controller",
                target="RESP-1",
                shared_pm="PM-1-1",
                cm_id="report-mechanism",
            )
        ]
        return delta

    if variant.startswith("unresolved-"):
        field = variant.removeprefix("unresolved-")
        missing = dict(UNRESOLVED_FIELDS)[field]
        added = _responsibility(
            "unresolved-controller",
            rc_id="unresolved-constraint",
            pm_id="unresolved-state",
            ca_id="unresolved-action",
            fb_id="unresolved-feedback",
            description="Unresolved revision responsibility",
            feedback_source="unresolved-controller",
            target="CP-1",
            source="CP-1",
        )
        if field == "feedback-updates":
            added["feedback_channels"][0]["updates"] = missing
        elif field == "process-feedback-source":
            added["process_model_parts"][0]["feedback_source"]["id"] = missing
        elif field == "control-action-target":
            added["control_actions"][0]["target"]["id"] = missing
        elif field == "feedback-source":
            added["feedback_channels"][0]["source"]["id"] = missing

        link = _coordination_link(
            "unresolved-link",
            source="unresolved-controller",
            target="RESP-1",
            shared_pm="unresolved-state",
            cm_id="unresolved-mechanism",
        )
        coordination_fields = {
            "coordination-source": "source",
            "coordination-target": "target",
            "coordination-shared-pm": "shared_pm",
        }
        if field in coordination_fields:
            link[coordination_fields[field]] = missing
        return {
            "new_responsibilities": [added],
            "new_coordination_links": [link],
        }

    raise ValueError(f"Unknown revision fixture variant: {variant}")


def _sp1_response(model: str, system_prompt: str) -> dict[str, Any]:
    variant = model.removeprefix("rev-")
    prompt = system_prompt.lower()
    if "single revision attempt" in prompt:
        return _revision_delta(variant)
    if "completeness critic" in prompt:
        return {
            "gaps": [
                {
                    "gap_type": "missing_responsibility",
                    "description": "Missing revision coverage",
                    "related_attack_path": "A revision gap",
                    "suggested_remedy": "Add revision coverage",
                }
            ],
            "checklist_results": {"revision_coverage": "absent_unjustified"},
            "taxonomy_probe_results": {},
        }
    if "security architect analyzing" in prompt:
        return {
            "entry_points": [
                {
                    "name": "user request",
                    "entry_point_type": "user_input",
                    "direction": "input",
                    "controllability": "direct",
                }
            ],
            "confidence": "high",
            "kc_subcodes": ["KC1.1"],
            "tool_inventory": [],
        }
    if "organizational risks previously identified" in prompt:
        return {
            "risk_card_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Unauthorized action causes stakeholder loss",
                    "provenance": "risk_card",
                    "source_risk_cards": ["atlas-001"],
                }
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "Unauthorized action is accepted",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "The system must reject unauthorized actions",
                    "related_hazards": ["H-1"],
                    "applies_when": [],
                }
            ],
        }
    if "performing a gap analysis" in prompt:
        return {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
        }
    if "deriving requirements" in prompt:
        return {
            "requirements": [
                {
                    "req_id": "REQ-1",
                    "description": "Authorize every action",
                    "classification": "control",
                    "source_constraint": "SC-1",
                }
            ]
        }
    if "deriving control responsibilities" in prompt:
        return _base_responsibilities()
    if "completing the control loop design" in prompt:
        return _base_control_elements()
    if "cross-responsibility analysis" in prompt:
        return _base_coordination()
    raise ValueError(f"Unrecognized SP1 prompt for {model}")


class _FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.endswith("/chat/completions"):
            self.send_error(404, "Not Found")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length) or b"{}")
            messages = request.get("messages", [])
            system_prompt = "".join(
                str(message.get("content", ""))
                for message in messages
                if message.get("role") == "system"
            )
            user_prompt = "".join(
                str(message.get("content", ""))
                for message in messages
                if message.get("role") == "user"
            )
            model = str(request.get("model", ""))
            if model.startswith("rev-"):
                content = json.dumps(_sp1_response(model, system_prompt))
            elif model == "sp2-qa-stub":
                content = json.dumps(_build_fill_response(user_prompt))
            elif model == "sp3-qa-stub":
                if request.get("response_format") is not None:
                    content = json.dumps(_build_bdi_response(user_prompt))
                else:
                    call_type = _determine_call_type(system_prompt)
                    if call_type == "narrative":
                        content = _build_narrative_response(user_prompt)
                    elif call_type == "attack_tree":
                        content = _build_attack_tree_response(user_prompt)
                    else:
                        content = _build_gherkin_response(user_prompt)
            else:
                raise ValueError(f"Unknown fixture model {model}")
            body = json.dumps(
                {
                    "id": "chatcmpl-revision-normalization-qa",
                    "object": "chat.completion",
                    "created": 0,
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": content,
                                "refusal": None,
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:  # noqa: BLE001
            self.send_error(500, str(exc))


def _write_inputs(
    work_dir: Path,
    port: int,
) -> tuple[Path, Path, Path]:
    use_case = work_dir / "use-case.txt"
    use_case.write_text(
        "A user-facing agent authorizes requests and invokes a controlled service.",
        encoding="utf-8",
    )
    risks = work_dir / "risk-extraction.json"
    risks.write_text(
        json.dumps(
            {
                "risks": [
                    {
                        "risk_id": "atlas-001",
                        "risk_name": "Unauthorized action",
                        "risk_description": "An attacker causes an unauthorized action.",
                        "taxonomy": "ibm-risk-atlas",
                        "confidence": 0.9,
                        "grounding_confidence": "high",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    profiles = work_dir / "profiles.yaml"
    variants = [
        "noop",
        "malformed",
        "duplicates",
        "references",
        "positions",
        "canonical",
        "deterministic-a",
        "deterministic-b",
        "report",
        *(f"unresolved-{field}" for field, _missing in UNRESOLVED_FIELDS),
    ]
    profile_names = [
        *(f"rev-{variant}" for variant in variants),
        "sp2-qa-stub",
        "sp3-qa-stub",
    ]
    profiles.write_text(
        yaml.safe_dump(
            {
                name: {
                    "base_url": f"http://127.0.0.1:{port}/v1",
                    "model": name,
                    "api_key": "unused",
                    "temperature": 0.0,
                }
                for name in profile_names
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return use_case, risks, profiles


def _run_cli(
    work_dir: Path,
    variant: str,
    inputs: tuple[Path, Path, Path],
) -> tuple[subprocess.CompletedProcess[str], Path]:
    use_case, risks, profiles = inputs
    output_dir = work_dir / variant
    env = {
        **os.environ,
        "PATH": f"/opt/homebrew/bin:{os.environ.get('PATH', '')}",
    }
    result = subprocess.run(
        [
            "uv",
            "run",
            "asago-scenario-generator",
            "stpa-run",
            "--use-case",
            str(use_case),
            "--risk-extraction",
            str(risks),
            "--output-dir",
            str(output_dir),
            "--sp1-profile",
            f"rev-{variant}",
            "--sp2-profile",
            "sp2-qa-stub",
            "--sp3-profile",
            "sp3-qa-stub",
            "--profiles-file",
            str(profiles),
        ],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    return result, output_dir


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _load_calls(output_dir: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in (output_dir / "calls.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]


def _assert_revision_manifest(
    output_dir: Path,
    *,
    degraded: bool = False,
    missing_id: str | None = None,
) -> None:
    manifest = _load_yaml(output_dir / "run-manifest.yaml")
    calls = _load_calls(output_dir)
    assert manifest.get("revised") is True, "manifest does not mark revision attempted"
    assert any(
        call.get("step") == "revision" and call.get("success") is True for call in calls
    ), "successful revision call is not logged"
    warnings = manifest.get("post_revision_warnings", [])
    warning_text = " ".join(str(warning) for warning in warnings).lower()
    if degraded:
        assert "revision delta merge degraded" in warning_text, warning_text
        assert missing_id is not None and missing_id in warning_text, warning_text
    else:
        assert not any(term in warning_text for term in SUCCESS_WARNING_TERMS), (
            warning_text
        )
        assert not manifest.get("stage_errors"), manifest.get("stage_errors")


def _responsibility_by_id(
    structure: dict[str, Any],
    resp_id: str,
) -> dict[str, Any]:
    return next(
        responsibility
        for responsibility in structure["responsibilities"]
        if responsibility["resp_id"] == resp_id
    )


def _nested_ids(responsibility: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        responsibility["responsibility_constraints"][0]["rc_id"],
        responsibility["process_model_parts"][0]["pm_id"],
        responsibility["control_actions"][0]["ca_id"],
        responsibility["feedback_channels"][0]["fb_id"],
    )


def _run_report(output_dir: Path) -> Path:
    report_path = output_dir / "qa-revision-normalization-report.html"
    result = subprocess.run(
        [
            "uv",
            "run",
            "asago-scenario-generator",
            "stpa-report",
            "--output-dir",
            str(output_dir),
            "--output",
            str(report_path),
        ],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "PATH": f"/opt/homebrew/bin:{os.environ.get('PATH', '')}",
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert report_path.exists() and report_path.stat().st_size > 0
    return report_path


def _assert_success(
    result: subprocess.CompletedProcess[str],
    output_dir: Path,
) -> dict[str, Any]:
    assert result.returncode == 0, result.stdout + result.stderr
    _assert_revision_manifest(output_dir)
    return _load_yaml(output_dir / "control-structure.yaml")


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    passed = 0
    try:
        with tempfile.TemporaryDirectory(
            prefix="sp1-revision-normalization-qa-",
            dir=PROJECT_ROOT / "tmp",
        ) as raw_work_dir:
            work_dir = Path(raw_work_dir)
            inputs = _write_inputs(work_dir, server.server_address[1])

            baseline_result, baseline_dir = _run_cli(work_dir, "noop", inputs)
            baseline = _assert_success(baseline_result, baseline_dir)

            result, output_dir = _run_cli(work_dir, "malformed", inputs)
            malformed = _assert_success(result, output_dir)
            added = _responsibility_by_id(malformed, "RESP-3")
            assert _nested_ids(added) == ("RC-3-1", "PM-3-1", "CA-3-1", "FB-3-1")
            assert [item["cp_id"] for item in malformed["controlled_processes"]] == [
                "CP-1",
                "CP-2",
            ]
            assert [item["link_id"] for item in malformed["coordination_links"]] == [
                "CL-1",
                "CL-2",
            ]
            assert (
                malformed["coordination_links"][1]["coordination_mechanism"]["cm_id"]
                == "CM-2"
            )
            assert "Revision addition" in json.dumps(added)
            print("PASS QA-SP1-REV-ID-01")
            passed += 1

            result, output_dir = _run_cli(work_dir, "duplicates", inputs)
            duplicate = _assert_success(result, output_dir)
            modified = _responsibility_by_id(duplicate, "RESP-2")
            added = _responsibility_by_id(duplicate, "RESP-3")
            assert _nested_ids(modified) == ("RC-2-1", "PM-2-1", "CA-2-1", "FB-2-1")
            assert _nested_ids(added) == ("RC-3-1", "PM-3-1", "CA-3-1", "FB-3-1")
            assert modified["feedback_channels"][0]["updates"] == "PM-2-1"
            assert added["feedback_channels"][0]["updates"] == "PM-3-1"
            all_nested_ids = [
                nested_id
                for responsibility in duplicate["responsibilities"]
                for nested_id in _nested_ids(responsibility)
            ]
            assert len(all_nested_ids) == len(set(all_nested_ids))
            print("PASS QA-SP1-REV-ID-02")
            passed += 1

            result, output_dir = _run_cli(work_dir, "references", inputs)
            references = _assert_success(result, output_dir)
            modified = _responsibility_by_id(references, "RESP-2")
            assert (
                modified["process_model_parts"][0]["feedback_source"]["id"] == "RESP-3"
            )
            assert modified["control_actions"][0]["target"]["id"] == "CP-2"
            assert modified["feedback_channels"][0]["source"]["id"] == "CP-2"
            assert modified["feedback_channels"][0]["updates"] == "PM-2-1"
            link = references["coordination_links"][1]
            assert (link["source"], link["target"], link["shared_pm"]) == (
                "RESP-3",
                "RESP-1",
                "PM-2-1",
            )
            assert "revised-" not in json.dumps(references)
            print("PASS QA-SP1-REV-ID-03")
            passed += 1

            result, output_dir = _run_cli(work_dir, "positions", inputs)
            positioned = _assert_success(result, output_dir)
            assert [item["resp_id"] for item in positioned["responsibilities"]] == [
                "RESP-1",
                "RESP-2",
                "RESP-3",
            ]
            assert positioned["responsibilities"][0]["description"] == (
                "Original responsibility one"
            )
            assert positioned["responsibilities"][1]["description"] == (
                "Updated position responsibility"
            )
            assert positioned["responsibilities"][2]["description"] == (
                "Added position responsibility"
            )
            assert [item["cp_id"] for item in positioned["controlled_processes"]] == [
                "CP-1",
                "CP-2",
            ]
            assert [item["link_id"] for item in positioned["coordination_links"]] == [
                "CL-1",
                "CL-2",
            ]
            assert [
                item["coordination_mechanism"]["cm_id"]
                for item in positioned["coordination_links"]
            ] == ["CM-1", "CM-2"]
            assert positioned["coordination_links"][0]["target"] == "RESP-2"
            print("PASS QA-SP1-REV-ID-04")
            passed += 1

            result, output_dir = _run_cli(work_dir, "canonical", inputs)
            canonical = _assert_success(result, output_dir)
            assert [item["resp_id"] for item in canonical["responsibilities"]] == [
                "RESP-1",
                "RESP-2",
                "RESP-3",
            ]
            assert _nested_ids(_responsibility_by_id(canonical, "RESP-2")) == (
                "RC-2-1",
                "PM-2-1",
                "CA-2-1",
                "FB-2-1",
            )
            assert _nested_ids(_responsibility_by_id(canonical, "RESP-3")) == (
                "RC-3-1",
                "PM-3-1",
                "CA-3-1",
                "FB-3-1",
            )
            assert _responsibility_by_id(canonical, "RESP-2")["description"] == (
                "Canonical updated responsibility"
            )
            print("PASS QA-SP1-REV-ID-05")
            passed += 1

            for field, missing_id in UNRESOLVED_FIELDS:
                result, output_dir = _run_cli(
                    work_dir,
                    f"unresolved-{field}",
                    inputs,
                )
                assert result.returncode == 0, result.stdout + result.stderr
                structure = _load_yaml(output_dir / "control-structure.yaml")
                assert structure == baseline
                assert missing_id not in json.dumps(structure)
                _assert_revision_manifest(
                    output_dir,
                    degraded=True,
                    missing_id=missing_id,
                )
                assert missing_id in (output_dir / "calls.jsonl").read_text(
                    encoding="utf-8"
                )
            print("PASS QA-SP1-REV-ID-06 (7 unresolved reference fields)")
            passed += 1

            result_a, output_a = _run_cli(work_dir, "deterministic-a", inputs)
            deterministic_a = _assert_success(result_a, output_a)
            result_b, output_b = _run_cli(work_dir, "deterministic-b", inputs)
            deterministic_b = _assert_success(result_b, output_b)
            assert deterministic_a == deterministic_b
            print("PASS QA-SP1-REV-ID-07")
            passed += 1

            result, output_dir = _run_cli(work_dir, "report", inputs)
            report_structure = _assert_success(result, output_dir)
            assert _nested_ids(_responsibility_by_id(report_structure, "RESP-2")) == (
                "RC-2-1",
                "PM-2-1",
                "CA-2-1",
                "FB-2-1",
            )
            assert _nested_ids(_responsibility_by_id(report_structure, "RESP-3")) == (
                "RC-3-1",
                "PM-3-1",
                "CA-3-1",
                "FB-3-1",
            )
            _run_report(output_dir)
            print("PASS QA-SP1-REV-ID-08")
            passed += 1
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    print(f"SP1 revision-delta normalization QA: {passed}/8 procedures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

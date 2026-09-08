#!/usr/bin/env python3
"""Executable UI-only QA suite for ``qa_sp1_id_renumbering.md``.

The suite starts a deterministic OpenAI-compatible fixture endpoint and drives
only the published ``asago-scenario-generator stpa-run`` and ``stpa-report`` commands.
It validates the resulting YAML, JSONL, manifest, and HTML artifacts without
importing asago-scenario-generator implementation modules.
"""

from __future__ import annotations

import json
import os
import re
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
ID_PATTERNS = {
    "resp_id": re.compile(r"^RESP-\d+$"),
    "rc_id": re.compile(r"^RC-\d+-\d+$"),
    "pm_id": re.compile(r"^PM-\d+-\d+$"),
    "ca_id": re.compile(r"^CA-\d+-\d+$"),
    "fb_id": re.compile(r"^FB-\d+-\d+$"),
    "cp_id": re.compile(r"^CP-\d+$"),
    "link_id": re.compile(r"^CL-\d+$"),
    "cm_id": re.compile(r"^CM-\d+$"),
}
SP1_ERROR_TERMS = (
    "duplicate",
    "must match format",
    "namespace collision",
    "occurs in multiple element-type namespaces",
)


def _source_ids(variant: str) -> dict[str, Any]:
    if variant == "conforming":
        return {
            "resp": ["RESP-1", "RESP-2"],
            "rc": [["RC-1-1", "RC-1-2"], ["RC-2-1", "RC-2-2"]],
            "pm": [["PM-1-1", "PM-1-2"], ["PM-2-1", "PM-2-2"]],
            "ca": [["CA-1-1", "CA-1-2"], ["CA-2-1", "CA-2-2"]],
            "fb": [["FB-1-1", "FB-1-2"], ["FB-2-1", "FB-2-2"]],
            "cp": ["CP-1", "CP-2"],
            "link": ["CL-1", "CL-2"],
            "cm": ["CM-1", "CM-2"],
        }
    if variant == "ambiguous-responsibility":
        ids = _source_ids("mixed-a")
        ids["resp"] = ["ambiguous-global", "ambiguous-global"]
        return ids
    if variant in {
        "ambiguous-control-action-target",
        "ambiguous-feedback-source",
    }:
        ids = _source_ids("mixed-a")
        ids["cp"] = ["ambiguous-global", "ambiguous-global"]
        return ids
    if variant == "mixed-b":
        return {
            "resp": ["RESP-8", "RESP-4"],
            "rc": [["other-rc-a", "other-rc-b"], ["other-rc-c", "other-rc-d"]],
            "pm": [
                ["other-state-a", "local-shared"],
                ["local-shared", "other-state-d"],
            ],
            "ca": [["CA-8-71", "CA-8-71"], ["CA-4-63", "CA-4-63"]],
            "fb": [["FB-8-71", "FB-8-71"], ["FB-4-63", "FB-4-63"]],
            "cp": ["other-process-a", "other-process-b"],
            "link": ["CL-70", "CL-6"],
            "cm": ["other-mechanism", "other-mechanism"],
        }
    return {
        "resp": ["RESP-90", "RESP-3"],
        "rc": [["RC-9-9", "rc-1"], ["RC-2-99", "rc-1"]],
        "pm": [["RC-9-9", "shared-state"], ["shared-state", "pm-two"]],
        "ca": [["CA-90-99", "CA-90-99"], ["CA-3-1", "CA-3-1"]],
        "fb": [["FB-90-99", "FB-90-99"], ["FB-3-1", "FB-3-1"]],
        "cp": ["CP-99-1", "process-beta"],
        "link": ["CL-20", "CL-4"],
        "cm": ["duplicate-mechanism", "duplicate-mechanism"],
    }


def _responsibility_response(variant: str) -> dict[str, Any]:
    ids = _source_ids(variant)
    responsibilities = []
    for index in range(2):
        responsibilities.append(
            {
                "resp_id": ids["resp"][index],
                "description": f"Controller {index + 1}",
                "responsibility_constraints": [
                    {
                        "rc_id": source_id,
                        "description": f"Constraint {index + 1}.{child + 1}",
                    }
                    for child, source_id in enumerate(ids["rc"][index])
                ],
                "security_constraint_refs": ["SC-1"],
                "process_model_parts": [
                    {
                        "pm_id": source_id,
                        "description": f"State {index + 1}.{child + 1}",
                        "feedback_source": (
                            {
                                "type": "responsibility",
                                "id": ids["resp"][1 - index],
                            }
                            if child == 0
                            else None
                        ),
                    }
                    for child, source_id in enumerate(ids["pm"][index])
                ],
            }
        )
    if variant == "ambiguous-responsibility":
        for responsibility in responsibilities:
            for process_model_part in responsibility["process_model_parts"]:
                process_model_part["feedback_source"] = None
        responsibilities[0]["process_model_parts"][0]["feedback_source"] = {
            "type": "responsibility",
            "id": "ambiguous-global",
        }
    return {"responsibilities": responsibilities}


def _control_element_response(
    variant: str,
    unresolved: str | None,
) -> dict[str, Any]:
    ids = _source_ids(variant)
    control_actions = []
    feedback_channels = []
    for index in range(2):
        for child in range(2):
            control_actions.append(
                {
                    "ca_id": ids["ca"][index][child],
                    "description": f"Action {index + 1}.{child + 1}",
                    "target": (
                        {
                            "type": "controlled_process",
                            "id": ids["cp"][1 - index],
                        }
                        if child == 0
                        else None
                    ),
                }
            )
            feedback_channels.append(
                {
                    "fb_id": ids["fb"][index][child],
                    "description": f"Feedback {index + 1}.{child + 1}",
                    "updates": ids["pm"][index][child],
                    "source": (
                        {
                            "type": "controlled_process",
                            "id": ids["cp"][index],
                        }
                        if child == 0
                        else None
                    ),
                }
            )

    if unresolved == "feedback-updates":
        feedback_channels[0]["updates"] = "absent-feedback-updates"
    if unresolved == "control-action-target":
        control_actions[0]["target"]["id"] = "absent-control-action-target"
    elif unresolved == "feedback-source":
        feedback_channels[0]["source"]["id"] = "absent-feedback-source"
    if variant == "ambiguous-control-action-target":
        for control_action in control_actions:
            control_action["target"] = None
        for feedback_channel in feedback_channels:
            feedback_channel["source"] = None
        control_actions[0]["target"] = {
            "type": "controlled_process",
            "id": "ambiguous-global",
        }
    elif variant == "ambiguous-feedback-source":
        for control_action in control_actions:
            control_action["target"] = None
        for feedback_channel in feedback_channels:
            feedback_channel["source"] = None
        feedback_channels[0]["source"] = {
            "type": "controlled_process",
            "id": "ambiguous-global",
        }

    return {
        "control_actions": control_actions,
        "feedback_channels": feedback_channels,
        "controlled_processes": [
            {"cp_id": source_id, "description": f"Process {index + 1}"}
            for index, source_id in enumerate(ids["cp"])
        ],
    }


def _coordination_response(
    variant: str,
    unresolved: str | None,
) -> dict[str, Any]:
    ids = _source_ids(variant)
    links = [
        {
            "link_id": ids["link"][0],
            "source": ids["resp"][0],
            "target": ids["resp"][1],
            "shared_pm": ids["pm"][0][0],
            "coordination_mechanism": {
                "cm_id": ids["cm"][0],
                "description": "Coordinate first state",
                "payload": "payload-one",
            },
            "description": "Link one",
        },
        {
            "link_id": ids["link"][1],
            "source": ids["resp"][1],
            "target": ids["resp"][0],
            "shared_pm": ids["pm"][1][1],
            "coordination_mechanism": {
                "cm_id": ids["cm"][1],
                "description": "Coordinate second state",
                "payload": "payload-two",
            },
            "description": "Link two",
        },
    ]
    coordination_fields = {
        "coordination-source": "source",
        "coordination-target": "target",
        "coordination-shared-pm": "shared_pm",
    }
    if unresolved in coordination_fields:
        field = coordination_fields[unresolved]
        links[0][field] = f"absent-{unresolved}"
    if variant == "ambiguous-shared-pm":
        links[0]["shared_pm"] = "shared-state"
    return {"coordination_links": links, "integrity_findings": []}


def _sp1_response(model: str, system_prompt: str) -> dict[str, Any]:
    variant = "conforming" if model == "sp1-conforming" else model.removeprefix("sp1-")
    unresolved = None
    if variant.startswith("unresolved-"):
        unresolved = variant.removeprefix("unresolved-")
        variant = "mixed-a"

    prompt = system_prompt.lower()
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
        response = _responsibility_response(variant)
        if unresolved == "process-feedback-source":
            response["responsibilities"][0]["process_model_parts"][0][
                "feedback_source"
            ]["id"] = "absent-process-feedback-source"
        return response
    if "completing the control loop design" in prompt:
        return _control_element_response(variant, unresolved)
    if "cross-responsibility analysis" in prompt:
        return _coordination_response(variant, unresolved)
    if "completeness critic" in prompt:
        return {
            "gaps": [],
            "checklist_results": {"input_validation": "present"},
            "taxonomy_probe_results": {},
        }
    raise ValueError(f"Unrecognized SP1 prompt for model {model}")


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
            if model.startswith("sp1-"):
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
                    "id": "chatcmpl-sp1-id-qa",
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


def _write_inputs(work_dir: Path, port: int) -> tuple[Path, Path, Path, Path]:
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
    capability = work_dir / "capability-profile.yaml"
    capability.write_text(
        yaml.safe_dump(
            {
                "zones_active": ["input", "reasoning"],
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
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    profiles = work_dir / "profiles.yaml"
    profile_names = [
        "sp1-mixed-a",
        "sp1-mixed-b",
        "sp1-conforming",
        "sp1-unresolved-feedback-updates",
        "sp1-unresolved-process-feedback-source",
        "sp1-unresolved-control-action-target",
        "sp1-unresolved-feedback-source",
        "sp1-unresolved-coordination-source",
        "sp1-unresolved-coordination-target",
        "sp1-unresolved-coordination-shared-pm",
        "sp1-ambiguous-responsibility",
        "sp1-ambiguous-control-action-target",
        "sp1-ambiguous-feedback-source",
        "sp1-ambiguous-shared-pm",
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
    return use_case, risks, capability, profiles


def _run_cli(
    work_dir: Path,
    profile: str,
    inputs: tuple[Path, Path, Path, Path],
) -> tuple[subprocess.CompletedProcess[str], Path]:
    use_case, risks, _capability, profiles = inputs
    output_dir = work_dir / profile
    command = [
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
        profile,
        "--sp2-profile",
        "sp2-qa-stub",
        "--sp3-profile",
        "sp3-qa-stub",
        "--profiles-file",
        str(profiles),
    ]
    env = os.environ.copy()
    env["PATH"] = f"/opt/homebrew/bin:{env.get('PATH', '')}"
    result = subprocess.run(
        command,
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


def _all_ids(structure: dict[str, Any]) -> dict[str, list[str]]:
    ids = {key: [] for key in ID_PATTERNS}
    for responsibility in structure["responsibilities"]:
        ids["resp_id"].append(responsibility["resp_id"])
        for child in responsibility["responsibility_constraints"]:
            ids["rc_id"].append(child["rc_id"])
        for child in responsibility["process_model_parts"]:
            ids["pm_id"].append(child["pm_id"])
        for child in responsibility["control_actions"]:
            ids["ca_id"].append(child["ca_id"])
        for child in responsibility["feedback_channels"]:
            ids["fb_id"].append(child["fb_id"])
    ids["cp_id"] = [process["cp_id"] for process in structure["controlled_processes"]]
    ids["link_id"] = [link["link_id"] for link in structure["coordination_links"]]
    ids["cm_id"] = [
        link["coordination_mechanism"]["cm_id"]
        for link in structure["coordination_links"]
    ]
    return ids


def _assert_canonical_structure(structure: dict[str, Any]) -> None:
    ids = _all_ids(structure)
    assert ids["resp_id"] == ["RESP-1", "RESP-2"]
    assert ids["rc_id"] == ["RC-1-1", "RC-1-2", "RC-2-1", "RC-2-2"]
    assert ids["pm_id"] == ["PM-1-1", "PM-1-2", "PM-2-1", "PM-2-2"]
    assert ids["ca_id"] == ["CA-1-1", "CA-1-2", "CA-2-1", "CA-2-2"]
    assert ids["fb_id"] == ["FB-1-1", "FB-1-2", "FB-2-1", "FB-2-2"]
    assert ids["cp_id"] == ["CP-1", "CP-2"]
    assert ids["link_id"] == ["CL-1", "CL-2"]
    assert ids["cm_id"] == ["CM-1", "CM-2"]
    _assert_ids_valid_and_unique(ids)


def _assert_ids_valid_and_unique(ids: dict[str, list[str]]) -> None:
    for key, values in ids.items():
        assert len(values) == len(set(values)), f"duplicate {key}: {values}"
        assert all(ID_PATTERNS[key].fullmatch(value) for value in values), (
            f"malformed {key}: {values}"
        )
    flattened = [value for values in ids.values() for value in values]
    assert len(flattened) == len(set(flattened)), "cross-namespace ID collision"


def _assert_references(structure: dict[str, Any]) -> None:
    first, second = structure["responsibilities"]
    assert [item["updates"] for item in first["feedback_channels"]] == [
        "PM-1-1",
        "PM-1-2",
    ]
    assert [item["updates"] for item in second["feedback_channels"]] == [
        "PM-2-1",
        "PM-2-2",
    ]
    assert first["process_model_parts"][0]["feedback_source"] == {
        "type": "responsibility",
        "id": "RESP-2",
    }
    assert first["control_actions"][0]["target"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }
    assert second["feedback_channels"][0]["source"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }
    assert structure["coordination_links"][0]["source"] == "RESP-1"
    assert structure["coordination_links"][0]["target"] == "RESP-2"
    assert structure["coordination_links"][0]["shared_pm"] == "PM-1-1"


def _manifest_text(output_dir: Path) -> str:
    path = output_dir / "run-manifest.yaml"
    assert path.exists(), f"missing manifest: {path}"
    return path.read_text(encoding="utf-8")


def _assert_no_id_errors(output_dir: Path) -> None:
    text = _manifest_text(output_dir).lower()
    assert not any(term in text for term in SP1_ERROR_TERMS), text


def _run_report(output_dir: Path) -> Path:
    report = output_dir / "qa-sp1-report.html"
    result = subprocess.run(
        [
            "uv",
            "run",
            "asago-scenario-generator",
            "stpa-report",
            "--output-dir",
            str(output_dir),
            "--output",
            str(report),
        ],
        cwd=PROJECT_ROOT,
        env={**os.environ, "PATH": f"/opt/homebrew/bin:{os.environ.get('PATH', '')}"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert report.exists() and report.stat().st_size > 0
    return report


def _assert_unresolved_case(
    result: subprocess.CompletedProcess[str],
    output_dir: Path,
    field: str,
) -> None:
    missing = f"absent-{field}"
    diagnostics = result.stdout + result.stderr
    calls_path = output_dir / "calls.jsonl"
    assert calls_path.exists(), f"missing calls.jsonl for {field}"
    calls = calls_path.read_text(encoding="utf-8")
    manifest = _manifest_text(output_dir)
    searchable = "\n".join((diagnostics, calls, manifest))
    assert missing in searchable, f"diagnostics do not identify {missing}"

    structure_path = output_dir / "control-structure.yaml"
    if structure_path.exists():
        structure = _load_yaml(structure_path)
        references = json.dumps(structure)
        assert missing not in references
        _assert_ids_valid_and_unique(_all_ids(structure))
        _run_report(output_dir)


def _assert_ambiguous_case(
    result: subprocess.CompletedProcess[str],
    output_dir: Path,
    field: str,
    source_id: str,
) -> None:
    calls_path = output_dir / "calls.jsonl"
    assert calls_path.exists(), f"missing calls.jsonl for ambiguous {field}"
    manifest = _manifest_text(output_dir)
    diagnostics = "\n".join((result.stdout, result.stderr, manifest))
    assert source_id in diagnostics, (
        f"user-visible diagnostics do not identify ambiguous source ID {source_id}"
    )
    assert field in diagnostics, (
        f"user-visible diagnostics do not identify ambiguous field {field}"
    )
    assert result.returncode != 0 or "error" in manifest.lower(), (
        "ambiguous reference did not fail validation"
    )

    structure_path = output_dir / "control-structure.yaml"
    if structure_path.exists():
        structure = _load_yaml(structure_path)
        assert source_id not in json.dumps(structure)
        _assert_ids_valid_and_unique(_all_ids(structure))
        _run_report(output_dir)


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    passed = 0
    try:
        with tempfile.TemporaryDirectory(
            prefix="sp1-id-qa-", dir=PROJECT_ROOT / "tmp"
        ) as raw:
            work_dir = Path(raw)
            inputs = _write_inputs(work_dir, server.server_address[1])

            mixed_result, mixed_dir = _run_cli(work_dir, "sp1-mixed-a", inputs)
            assert mixed_result.returncode == 0, (
                mixed_result.stdout + mixed_result.stderr
            )
            mixed = _load_yaml(mixed_dir / "control-structure.yaml")
            _assert_canonical_structure(mixed)
            _assert_references(mixed)
            _assert_no_id_errors(mixed_dir)
            _run_report(mixed_dir)
            print("PASS QA-SP1-ID-01/02/03/05/07")
            passed += 5

            variant_result, variant_dir = _run_cli(work_dir, "sp1-mixed-b", inputs)
            assert variant_result.returncode == 0, (
                variant_result.stdout + variant_result.stderr
            )
            variant = _load_yaml(variant_dir / "control-structure.yaml")
            assert variant == mixed, (
                "source IDs changed canonical output or non-ID content"
            )
            print("PASS QA-SP1-ID-04")
            passed += 1

            conforming_result, conforming_dir = _run_cli(
                work_dir, "sp1-conforming", inputs
            )
            assert conforming_result.returncode == 0, (
                conforming_result.stdout + conforming_result.stderr
            )
            conforming = _load_yaml(conforming_dir / "control-structure.yaml")
            _assert_canonical_structure(conforming)
            _assert_references(conforming)
            _assert_no_id_errors(conforming_dir)
            print("PASS QA-SP1-ID-08")
            passed += 1

            unresolved_fields = (
                "feedback-updates",
                "process-feedback-source",
                "control-action-target",
                "feedback-source",
                "coordination-source",
                "coordination-target",
                "coordination-shared-pm",
            )
            for field in unresolved_fields:
                result, output_dir = _run_cli(
                    work_dir, f"sp1-unresolved-{field}", inputs
                )
                _assert_unresolved_case(result, output_dir, field)
            print("PASS QA-SP1-ID-06 (7 unresolved reference fields)")
            passed += 1

            ambiguous_global_cases = (
                ("responsibility", "feedback_source"),
                ("control-action-target", "target"),
                ("feedback-source", "source"),
            )
            for profile_suffix, field in ambiguous_global_cases:
                result, output_dir = _run_cli(
                    work_dir, f"sp1-ambiguous-{profile_suffix}", inputs
                )
                _assert_ambiguous_case(
                    result,
                    output_dir,
                    field,
                    "ambiguous-global",
                )
            print("PASS QA-SP1-ID-09 (3 ambiguous typed global references)")
            passed += 1

            shared_pm_result, shared_pm_dir = _run_cli(
                work_dir, "sp1-ambiguous-shared-pm", inputs
            )
            _assert_ambiguous_case(
                shared_pm_result,
                shared_pm_dir,
                "shared_pm",
                "shared-state",
            )
            print("PASS QA-SP1-ID-10")
            passed += 1
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    print(f"SP1 ID renumbering QA: {passed}/10 procedures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""UI-only QA suite for ``qa_sp1_id_normalization_repairs.md``.

The suite serves deterministic OpenAI-compatible responses, drives only the
published ``asago-scenario-generator stpa-run`` and ``stpa-report`` commands, and
inspects their console output and published artifacts.  It does not import
project implementation modules.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

import run_sp1_id_renumbering_qa_suite as base

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CASES = (
    "prod",
    "inferred",
    "valid",
    "blank",
    "kept",
    "explicit",
    "invalid",
    "revision",
    "bare-cp",
    "bare-resp",
    "production",
    "bare-unknown",
    "stable",
)
PROD_LOG = PROJECT_ROOT / "output/runs/20260811-full2-airbnb/calls.jsonl"
PROD_FIX = PROJECT_ROOT / "tests/stpa/fixtures/sp1_airbnb_call2.json"
BAD_TERMS = (
    "assemble_control_structure",
    "fallback stripping",
    "revision delta merge degraded",
)


def _desc(case: str, kind: str, index: int = 1) -> str:
    if case == "blank":
        return ""
    if case == "kept":
        return f"Kept {kind} {index}: Mixed CASE!"
    return f"Fixture {kind} {index}"


def _ref_type(case: str, source: str, valid: str) -> str:
    return valid if case == "valid" else source


def _with_id(
    case: str,
    field: str,
    source: str,
    *,
    generic: str | None = None,
) -> dict[str, str]:
    result = {"id": generic or source}
    if case == "explicit":
        result[field] = source
    return result


def _resp(case: str) -> dict[str, Any]:
    if case == "production":
        return _prod("call_2a_responsibilities")

    source_ids = ("RESP-3", "RESP-9")
    result = []
    for index, source in enumerate(source_ids, start=1):
        item: dict[str, Any] = {
            **_with_id(
                case,
                "resp_id",
                source,
                generic="ignored-resp" if case == "explicit" else None,
            ),
            "description": _desc(case, "responsibility", index),
            "responsibility_constraints": [
                {
                    **_with_id(case, "rc_id", f"RC-{source.split('-')[1]}-1"),
                    "description": _desc(case, "constraint", index),
                }
            ],
            "security_constraint_refs": ["SC-1"],
            "process_model_parts": [
                {
                    **_with_id(case, "pm_id", f"PM-{source.split('-')[1]}-1"),
                    "description": _desc(case, "process model", index),
                }
            ],
        }
        result.append(item)
    if case == "bare-cp":
        result[0]["process_model_parts"][0]["feedback_source"] = "CP-9"
    elif case == "bare-resp":
        result[0]["process_model_parts"][0]["feedback_source"] = "RESP-9"
    else:
        result[0]["process_model_parts"][0]["feedback_source"] = {
            "type": _ref_type(case, "RESP-9", "responsibility"),
            "id": "RESP-9",
        }
    if case == "stable":
        result[1]["process_model_parts"][0]["feedback_source"] = None
    return {"responsibilities": result}


def _controls(case: str) -> dict[str, Any]:
    if case == "production":
        return _prod("call_2b_control_elements")

    result: dict[str, Any] = {
        "control_actions": [],
        "feedback_channels": [],
        "controlled_processes": [],
    }
    for index, number in enumerate((3, 9), start=1):
        target = "CP-8" if index == 1 else "CP-4"
        source = "CP-8" if index == 1 else "CP-4"
        action = {
            **_with_id(
                case,
                "ca_id",
                f"CA-{number}-1",
                generic="ignored-action" if case == "explicit" else None,
            ),
            "description": _desc(case, "control action", index),
            "target": {
                "type": _ref_type(case, target, "controlled_process"),
                "id": target,
            },
        }
        if case == "invalid" and index == 1:
            action["target"] = {
                "type": "process-alpha",
                "id": "process-alpha",
            }
        elif case == "bare-unknown" and index == 1:
            action["target"] = "process-alpha"
        elif case == "bare-cp":
            action["target"] = "CP-9"
        elif case == "bare-resp":
            action["target"] = "RESP-9"
        elif case == "stable" and index == 2:
            action["target"] = None
        channel = {
            **_with_id(
                case,
                "fb_id",
                f"FB-{number}-1",
                generic="ignored-feedback" if case == "explicit" else None,
            ),
            "updates": f"PM-{number}-1",
            "source": {
                "type": _ref_type(case, source, "controlled_process"),
                "id": source,
            },
        }
        if case not in {"prod", "inferred"}:
            channel["description"] = _desc(case, "feedback", index)
        if case == "bare-cp":
            channel["source"] = "CP-9"
        elif case == "bare-resp":
            channel["source"] = "RESP-9"
        elif case == "stable" and index == 2:
            channel["source"] = None
        result["control_actions"].append(action)
        result["feedback_channels"].append(channel)

    cp_ids = ("CP-4", "CP-9") if case == "bare-cp" else ("CP-4", "CP-8")
    for index, source in enumerate(cp_ids, start=1):
        if case == "invalid" and index == 1:
            source = "process-alpha"
        result["controlled_processes"].append(
            {
                **_with_id(
                    case,
                    "cp_id",
                    source,
                    generic="ignored-process" if case == "explicit" else None,
                ),
                "description": _desc(case, "controlled process", index),
            }
        )
    return result


def _coord(case: str) -> dict[str, Any]:
    target = "RESP-2" if case == "production" else "RESP-9"
    shared_pm = "PM-1-1" if case == "production" else "PM-3-1"
    return {
        "coordination_links": [
            {
                **_with_id(case, "link_id", "CL-7"),
                "source": "RESP-3",
                "target": target,
                "shared_pm": shared_pm,
                "coordination_mechanism": {
                    **_with_id(case, "cm_id", "CM-7"),
                    "description": _desc(case, "coordination mechanism"),
                    "payload": "fixture payload",
                },
                "description": _desc(case, "coordination link"),
            }
        ],
        "integrity_findings": [],
    }


def _prod(step: str) -> dict[str, Any]:
    if PROD_LOG.exists():
        rows = [
            json.loads(line)
            for line in PROD_LOG.read_text(encoding="utf-8").splitlines()
        ]
        row = next(
            (
                item
                for item in rows
                if item.get("step") == step and item.get("success") is True
            ),
            None,
        )
        assert row is not None, f"Missing successful production response for {step}"
        result = json.loads(row["response_content"])
    else:
        captured = json.loads(PROD_FIX.read_text(encoding="utf-8"))
        result = captured[step]

    if step == "call_2b_control_elements":
        refs = [
            *[item.get("target") for item in result["control_actions"]],
            *[item.get("source") for item in result["feedback_channels"]],
        ]
        assert len(refs) == 27
        assert all(isinstance(item, str) for item in refs)
    return result


def _revision() -> dict[str, Any]:
    return {
        "new_responsibilities": [
            {
                "id": "RESP-9",
                "description": "Revised controller",
                "responsibility_constraints": [],
                "security_constraint_refs": ["SC-1"],
                "process_model_parts": [
                    {
                        "id": "PM-9-1",
                        "description": "Revised state",
                    }
                ],
                "control_actions": [
                    {
                        "id": "CA-9-1",
                        "description": "Revised action",
                        "target": {"type": "CP-8", "id": "CP-8"},
                    }
                ],
                "feedback_channels": [
                    {
                        "id": "FB-9-1",
                        "description": "",
                        "updates": "PM-9-1",
                        "source": {"type": "CP-8", "id": "CP-8"},
                    }
                ],
            }
        ],
        "new_controlled_processes": [{"id": "CP-8", "description": "Revised process"}],
        "modified_responsibilities": [],
    }


def _sp1_response(model: str, system_prompt: str) -> dict[str, Any]:
    case = model.removeprefix("sp1-repair-")
    prompt = system_prompt.lower()
    if "single revision attempt" in prompt:
        return _revision()
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
        return _resp(case)
    if "completing the control loop design" in prompt:
        return _controls(case)
    if "cross-responsibility analysis" in prompt:
        return _coord(case)
    if "completeness critic" in prompt:
        if case == "revision":
            return {
                "gaps": [
                    {
                        "gap_type": "missing_responsibility",
                        "description": "Add revision fixture coverage",
                        "related_attack_path": "Revision path",
                        "suggested_remedy": "Add one controller and process",
                    }
                ],
                "checklist_results": {"revision_fixture": "absent_unjustified"},
                "taxonomy_probe_results": {},
            }
        return {
            "gaps": [],
            "checklist_results": {"fixture": "present"},
            "taxonomy_probe_results": {},
        }
    raise ValueError(f"Unrecognized repair fixture prompt for {model}")


def _write_inputs(work_dir: Path, port: int) -> tuple[Path, Path, Path, Path]:
    use_case = work_dir / "use-case.txt"
    use_case.write_text(
        "A user-facing agent authorizes requests and invokes a service.",
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
    names = [*(f"sp1-repair-{case}" for case in CASES), "sp2-qa-stub", "sp3-qa-stub"]
    profiles.write_text(
        yaml.safe_dump(
            {
                name: {
                    "base_url": f"http://127.0.0.1:{port}/v1",
                    "model": name,
                    "api_key": "unused",
                    "temperature": 0.0,
                }
                for name in names
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return use_case, risks, capability, profiles


def _run_cli(
    work_dir: Path,
    case: str,
    inputs: tuple[Path, Path, Path, Path],
) -> tuple[subprocess.CompletedProcess[str], Path]:
    use_case, risks, capability, profiles = inputs
    output_dir = work_dir / case
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
            "--capability-profile",
            str(capability),
            "--sp1-profile",
            f"sp1-repair-{case}",
            "--sp2-profile",
            "sp2-qa-stub",
            "--sp3-profile",
            "sp3-qa-stub",
            "--profiles-file",
            str(profiles),
        ],
        cwd=PROJECT_ROOT,
        env={**os.environ, "PATH": f"/opt/homebrew/bin:{os.environ.get('PATH', '')}"},
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    return result, output_dir


def _load(output_dir: Path) -> dict[str, Any]:
    return yaml.safe_load(
        (output_dir / "control-structure.yaml").read_text(encoding="utf-8")
    )


def _diag(result: subprocess.CompletedProcess[str], output_dir: Path) -> str:
    parts = [result.stdout, result.stderr]
    for name in ("calls.jsonl", "run-manifest.yaml"):
        path = output_dir / name
        if path.exists():
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def _assert_clean(result: subprocess.CompletedProcess[str], output_dir: Path) -> None:
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [
        json.loads(line)
        for line in (output_dir / "calls.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    failed = [call for call in calls if call.get("success") is False]
    assert not failed, failed
    manifest = yaml.safe_load(
        (output_dir / "run-manifest.yaml").read_text(encoding="utf-8")
    )
    assert not manifest.get("stage_errors"), manifest.get("stage_errors")
    warnings = " ".join(manifest.get("post_revision_warnings", [])).lower()
    assert not any(term in warnings for term in BAD_TERMS), warnings


def _assert_refs(structure: dict[str, Any]) -> None:
    first = structure["responsibilities"][0]
    assert first["process_model_parts"][0]["feedback_source"] == {
        "type": "responsibility",
        "id": "RESP-2",
    }
    assert first["control_actions"][0]["target"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }
    assert first["feedback_channels"][0]["source"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }


def _all_desc(structure: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for responsibility in structure["responsibilities"]:
        values.append(responsibility["description"])
        for field in (
            "responsibility_constraints",
            "process_model_parts",
            "control_actions",
            "feedback_channels",
        ):
            values.extend(item["description"] for item in responsibility[field])
    values.extend(item["description"] for item in structure["controlled_processes"])
    for link in structure["coordination_links"]:
        values.append(link["description"])
        values.append(link["coordination_mechanism"]["description"])
    return values


def _run_report(output_dir: Path) -> None:
    report = output_dir / "qa-repair-report.html"
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


def _check(
    case: str, result: subprocess.CompletedProcess[str], output_dir: Path
) -> None:
    if case in {"invalid", "bare-unknown"}:
        text = _diag(result, output_dir)
        assert "process-alpha" in text, text
        if (output_dir / "control-structure.yaml").exists():
            assert "process-alpha" not in json.dumps(_load(output_dir))
        return

    _assert_clean(result, output_dir)
    structure = _load(output_dir)
    if case in {"prod", "inferred", "valid", "explicit"}:
        _assert_refs(structure)
    if case == "prod":
        assert [item["resp_id"] for item in structure["responsibilities"]] == [
            "RESP-1",
            "RESP-2",
        ]
        assert [item["cp_id"] for item in structure["controlled_processes"]] == [
            "CP-1",
            "CP-2",
        ]
        assert all(_all_desc(structure))
    elif case == "blank":
        first = structure["responsibilities"][0]
        assert first["description"] == "Responsibility RESP-1"
        assert first["responsibility_constraints"][0]["description"] == (
            "Responsibility constraint RC-1-1"
        )
        assert first["process_model_parts"][0]["description"] == (
            "Process model part PM-1-1"
        )
        assert first["control_actions"][0]["description"] == "Control action CA-1-1"
        assert first["feedback_channels"][0]["description"] == (
            "Feedback from controlled process CP-2 updating process model part PM-1-1"
        )
        assert structure["controlled_processes"][0]["description"] == (
            "Controlled process CP-1"
        )
        assert structure["coordination_links"][0]["description"] == (
            "Coordination link CL-1"
        )
        assert (
            structure["coordination_links"][0]["coordination_mechanism"]["description"]
            == "Coordination mechanism CM-1"
        )
        _run_report(output_dir)
    elif case == "kept":
        assert all(value.startswith("Kept ") for value in _all_desc(structure))
    elif case == "explicit":
        assert "ignored-" not in json.dumps(structure)
    elif case == "revision":
        manifest = yaml.safe_load(
            (output_dir / "run-manifest.yaml").read_text(encoding="utf-8")
        )
        assert manifest.get("revised") is True
        added = structure["responsibilities"][-1]
        assert added["resp_id"] == "RESP-3"
        assert added["control_actions"][0]["target"] == {
            "type": "controlled_process",
            "id": "CP-3",
        }
        assert added["feedback_channels"][0]["description"] == (
            "Feedback from controlled process CP-3 updating process model part PM-3-1"
        )
    elif case in {"bare-cp", "bare-resp"}:
        expected = {
            "type": "controlled_process" if case == "bare-cp" else "responsibility",
            "id": "CP-2" if case == "bare-cp" else "RESP-2",
        }
        first = structure["responsibilities"][0]
        assert first["process_model_parts"][0]["feedback_source"] == expected
        assert first["control_actions"][0]["target"] == expected
        assert first["feedback_channels"][0]["source"] == expected
    elif case == "production":
        actions = [
            action
            for responsibility in structure["responsibilities"]
            for action in responsibility["control_actions"]
        ]
        feedback = [
            channel
            for responsibility in structure["responsibilities"]
            for channel in responsibility["feedback_channels"]
        ]
        refs = [
            *[item["target"] for item in actions],
            *[item["source"] for item in feedback],
        ]
        assert len(actions) == 11
        assert len(feedback) == 16
        assert len(refs) == 27
        assert all(
            isinstance(item, dict)
            and item["type"] in {"controlled_process", "responsibility"}
            and item["id"].startswith(("CP-", "RESP-"))
            for item in refs
        )
    elif case == "stable":
        first, second = structure["responsibilities"]
        assert first["process_model_parts"][0]["feedback_source"] == {
            "type": "responsibility",
            "id": "RESP-2",
        }
        assert first["control_actions"][0]["target"] == {
            "type": "controlled_process",
            "id": "CP-2",
        }
        assert first["feedback_channels"][0]["source"] == {
            "type": "controlled_process",
            "id": "CP-2",
        }
        # Published YAML omits optional nulls; absence is its documented null form.
        assert second["process_model_parts"][0].get("feedback_source") is None
        assert second["control_actions"][0].get("target") is None
        assert second["feedback_channels"][0].get("source") is None


def main() -> int:
    base._sp1_response = _sp1_response
    server = ThreadingHTTPServer(("127.0.0.1", 0), base._FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    passed = 0
    try:
        with tempfile.TemporaryDirectory(
            prefix="sp1-repair-qa-",
            dir=PROJECT_ROOT / "tmp",
        ) as raw:
            work_dir = Path(raw)
            inputs = _write_inputs(work_dir, server.server_address[1])
            for number, case in enumerate(CASES, start=1):
                result, output_dir = _run_cli(work_dir, case, inputs)
                _check(case, result, output_dir)
                print(f"PASS QA-SP1-ID-REPAIR-{number:02d}")
                passed += 1
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    print(f"SP1 ID normalization repairs QA: {passed}/{len(CASES)} procedures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""UI-only QA suite for ``qa_sp1_tolerant_decode_missing_fields.md``.

The suite serves deterministic OpenAI-compatible fixture responses, drives the
published ``asago-scenario-generator stpa-run`` and ``stpa-report`` commands, and
inspects only console output and published YAML, JSONL, manifest, and HTML
artifacts.  It does not import project implementation modules.
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
FORBIDDEN_DIAGNOSTICS = ("attributeerror", "has no attribute")


def _loss_response() -> dict[str, Any]:
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


def _responsibilities(case: str) -> dict[str, Any]:
    source_numbers = (8, 4) if case in {"01", "02", "06"} else (8,)
    return {
        "responsibilities": [
            {
                "resp_id": f"RESP-{number}",
                "description": f"Controller {index}",
                "responsibility_constraints": [
                    {
                        "rc_id": f"RC-{number}-1",
                        "description": f"Constraint {index}",
                    }
                ],
                "security_constraint_refs": ["SC-1"],
                "process_model_parts": [
                    {
                        "pm_id": f"PM-{number}-1",
                        "description": f"State {index}",
                    }
                ],
            }
            for index, number in enumerate(source_numbers, start=1)
        ]
    }


def _feedback(source_number: int, *, fb_id: str | None = None) -> dict[str, Any]:
    value = {
        "description": f"Feedback for {source_number}",
        "updates": f"PM-{source_number}-1",
    }
    if fb_id is not None:
        value["fb_id"] = fb_id
    return value


def _control_elements(case: str) -> dict[str, Any]:
    if case == "01":
        return {
            "control_actions": [
                {"description": "First action"},
                {"ca_id": "CA-4-9", "description": "Second action"},
            ],
            "feedback_channels": [
                _feedback(8, fb_id="FB-8-1"),
                _feedback(4, fb_id="FB-4-1"),
            ],
            "controlled_processes": [],
        }
    if case == "02":
        return {
            "control_actions": [
                {"description": "Action 1.1"},
                {"ca_id": "", "description": "Action 1.2"},
                {"description": "Action 2.1"},
                {"ca_id": "", "description": "Action 2.2"},
            ],
            "feedback_channels": [
                _feedback(8),
                _feedback(8, fb_id=""),
                _feedback(4),
                _feedback(4, fb_id=""),
            ],
            "controlled_processes": [
                {"description": "Process one"},
                {"cp_id": "", "description": "Process two"},
            ],
        }
    if case == "03":
        return {
            "control_actions": [{"ca_id": "source-action"}],
            "feedback_channels": [_feedback(8, fb_id="FB-8-1")],
            "controlled_processes": [],
        }
    if case == "04":
        return {
            "control_actions": [
                {
                    "description": "Fallback action",
                    "target": {"type": "controlled_process", "id": "CP-99"},
                }
            ],
            "feedback_channels": [_feedback(8, fb_id="FB-8-1")],
            "controlled_processes": [],
        }
    if case == "05":
        return {"control_actions": [{"description": "Defaulted action"}]}
    return {
        "control_actions": [
            {"ca_id": "CA-8-1", "description": "First action"},
            {"ca_id": "CA-4-1", "description": "Second action"},
        ],
        "feedback_channels": [
            _feedback(8, fb_id="FB-8-1"),
            _feedback(4, fb_id="FB-4-1"),
        ],
        "controlled_processes": [],
    }


def _coordination(case: str) -> dict[str, Any]:
    if case != "06":
        return {"coordination_links": [], "integrity_findings": []}
    return {
        "coordination_links": [
            {
                "link_id": "source-link",
                "source": "RESP-8",
                "target": "RESP-4",
                "shared_pm": "PM-8-1",
                "description": "Malformed link",
            }
        ],
        "integrity_findings": [],
    }


def _sp1_response(model: str, system_prompt: str) -> dict[str, Any]:
    case = model.removeprefix("sp1-tolerant-")
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
        return _loss_response()
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
        return _responsibilities(case)
    if "completing the control loop design" in prompt:
        return _control_elements(case)
    if "cross-responsibility analysis" in prompt:
        return _coordination(case)
    if "completeness critic" in prompt:
        return {
            "gaps": [],
            "checklist_results": {"input_validation": "present"},
            "taxonomy_probe_results": {},
        }
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
            if model.startswith("sp1-tolerant-"):
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
                    "id": "chatcmpl-tolerant-decode-qa",
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
    names = [
        *(f"sp1-tolerant-{case}" for case in ("01", "02", "03", "04", "05", "06")),
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
                for name in names
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return use_case, risks, capability, profiles


def _run_stpa(
    work_dir: Path,
    case: str,
    inputs: tuple[Path, Path, Path, Path],
) -> tuple[subprocess.CompletedProcess[str], Path]:
    use_case, risks, capability, profiles = inputs
    output_dir = work_dir / f"case-{case}"
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
            f"sp1-tolerant-{case}",
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


def _artifact_text(result: subprocess.CompletedProcess[str], output_dir: Path) -> str:
    parts = [result.stdout, result.stderr]
    for name in ("calls.jsonl", "run-manifest.yaml"):
        path = output_dir / name
        if path.exists():
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def _assert_no_missing_attribute(
    result: subprocess.CompletedProcess[str],
    output_dir: Path,
) -> None:
    text = _artifact_text(result, output_dir).lower()
    assert not any(term in text for term in FORBIDDEN_DIAGNOSTICS), text


def _load_structure(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "control-structure.yaml"
    assert path.exists(), f"missing {path}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _run_report(output_dir: Path) -> None:
    report = output_dir / "qa-tolerant-decode-report.html"
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


def _case_01(result: subprocess.CompletedProcess[str], output_dir: Path) -> None:
    assert result.returncode == 0, result.stdout + result.stderr
    structure = _load_structure(output_dir)
    responsibilities = structure["responsibilities"]
    assert [item["resp_id"] for item in responsibilities] == ["RESP-1", "RESP-2"]
    assert [item["control_actions"][0]["ca_id"] for item in responsibilities] == [
        "CA-1-1",
        "CA-2-1",
    ]
    assert [item["control_actions"][0]["description"] for item in responsibilities] == [
        "First action",
        "Second action",
    ]


def _case_02(result: subprocess.CompletedProcess[str], output_dir: Path) -> None:
    assert result.returncode == 0, result.stdout + result.stderr
    structure = _load_structure(output_dir)
    responsibilities = structure["responsibilities"]
    assert [
        action["ca_id"]
        for responsibility in responsibilities
        for action in responsibility["control_actions"]
    ] == ["CA-1-1", "CA-1-2", "CA-2-1", "CA-2-2"]
    assert [
        channel["fb_id"]
        for responsibility in responsibilities
        for channel in responsibility["feedback_channels"]
    ] == ["FB-1-1", "FB-1-2", "FB-2-1", "FB-2-2"]
    assert [item["cp_id"] for item in structure["controlled_processes"]] == [
        "CP-1",
        "CP-2",
    ]


def _case_03(result: subprocess.CompletedProcess[str], output_dir: Path) -> None:
    assert result.returncode == 1, result.stdout + result.stderr
    diagnostics = _artifact_text(result, output_dir).lower()
    assert "description" in diagnostics, diagnostics
    assert "ca_id" not in result.stderr.lower(), result.stderr
    assert "traceback" not in result.stderr.lower(), result.stderr
    assert not (output_dir / "control-structure.yaml").exists()


def _case_04(result: subprocess.CompletedProcess[str], output_dir: Path) -> None:
    assert result.returncode == 0, result.stdout + result.stderr
    structure = _load_structure(output_dir)
    action = structure["responsibilities"][0]["control_actions"][0]
    assert action["ca_id"] == "CA-1-1"
    assert action.get("target") is None
    diagnostics = _artifact_text(result, output_dir)
    assert "CP-99" in diagnostics, diagnostics
    assert "Stripped invalid target" in diagnostics, diagnostics


def _case_05(result: subprocess.CompletedProcess[str], output_dir: Path) -> None:
    assert result.returncode == 0, result.stdout + result.stderr
    structure = _load_structure(output_dir)
    action = structure["responsibilities"][0]["control_actions"][0]
    assert action.get("target") is None
    assert structure["controlled_processes"] == []
    entries = [
        json.loads(line)
        for line in (output_dir / "calls.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    call_2b = next(
        entry for entry in entries if entry.get("step") == "call_2b_control_elements"
    )
    response = json.loads(call_2b["response_content"])
    assert response == {"control_actions": [{"description": "Defaulted action"}]}


def _case_06(result: subprocess.CompletedProcess[str], output_dir: Path) -> None:
    assert result.returncode == 0, result.stdout + result.stderr
    structure = _load_structure(output_dir)
    assert structure["coordination_links"] == []
    diagnostics = _artifact_text(result, output_dir).lower()
    assert "coordination_mechanism" in diagnostics, diagnostics


CASE_CHECKS = {
    "01": _case_01,
    "02": _case_02,
    "03": _case_03,
    "04": _case_04,
    "05": _case_05,
    "06": _case_06,
}


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    passed = 0
    try:
        with tempfile.TemporaryDirectory(
            prefix="sp1-tolerant-decode-qa-",
            dir=PROJECT_ROOT / "tmp",
        ) as raw:
            work_dir = Path(raw)
            inputs = _write_inputs(work_dir, server.server_address[1])
            for case, check in CASE_CHECKS.items():
                result, output_dir = _run_stpa(work_dir, case, inputs)
                _assert_no_missing_attribute(result, output_dir)
                check(result, output_dir)
                if result.returncode == 0:
                    _run_report(output_dir)
                print(f"PASS QA-SP1-TOLERANT-{case}")
                passed += 1
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    print(f"SP1 tolerant-decode QA: {passed}/6 procedures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

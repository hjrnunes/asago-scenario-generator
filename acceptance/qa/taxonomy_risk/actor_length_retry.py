#!/usr/bin/env python3
"""UI-only end-to-end QA for taxonomy actor-profile length retries.

The suite serves deterministic OpenAI-compatible responses, invokes only the
public ``asago-scenario-generator generate`` command, and inspects fixture
requests plus published run artifacts. It never imports project modules or
contacts a live model.

Usage:
    uv run python acceptance/qa/taxonomy_risk/actor_length_retry.py
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[3]
LIMIT = 16384
SCHEMA_NAME = "Call0Response"
FILTER_SCHEMA_NAME = "BatchFilterResponse"
SEED_RE = re.compile(r'seed_id "([^"]+)"')
CANDIDATE_RE = re.compile(r"cand:v2:[0-9a-f]{32}")


class FixtureState:
    """Thread-safe-enough request state for the local sequential QA fixture."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.actor_counts: dict[str, int] = {}


STATE = FixtureState()


def _schema_name(request: dict[str, Any]) -> str:
    response_format = request.get("response_format") or {}
    return str((response_format.get("json_schema") or {}).get("name", ""))


def _messages(request: dict[str, Any]) -> str:
    return "\n".join(
        str(message.get("content", "")) for message in request.get("messages", [])
    )


def _filter_response(prompt: str) -> dict[str, Any]:
    seed_match = SEED_RE.search(prompt)
    if seed_match is None:
        raise AssertionError("candidate-filter request omitted its seed_id")
    seed_id = seed_match.group(1)
    candidate_ids = list(dict.fromkeys(CANDIDATE_RE.findall(prompt)))
    return {
        "seed_id": seed_id,
        "verdicts": [
            {
                "candidate_id": candidate_id,
                "verdict": (
                    "accept" if seed_id == "AP-T6-01" and index == 0 else "reject"
                ),
                "rationale": "Deterministic offline QA candidate verdict.",
            }
            for index, candidate_id in enumerate(candidate_ids)
        ],
    }


def _actor_response(case: str) -> tuple[str, str]:
    count = STATE.actor_counts.get(case, 0) + 1
    STATE.actor_counts[case] = count
    if case == "bounded" or (case == "success" and count == 1):
        return "", "length"
    if case == "nonlength":
        return json.dumps({"actor_type": 7}), "stop"
    return (
        json.dumps(
            {
                "actor_type": "adversarial-user",
                "capability_level": "intermediate",
                "beliefs": ["The system accepts user input."],
                "desires": ["Influence the system."],
                "intentions": ["Submit crafted input."],
                "resources": ["A client application."],
                "access_class": "public",
                "influence_source": None,
                "influence_mechanism": None,
                "trust_boundary_id": None,
                "material_insider_advantage": None,
            }
        ),
        "stop",
    )


class Handler(BaseHTTPRequestHandler):
    """Serve deterministic chat-completion responses."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.endswith("/chat/completions"):
            self.send_error(404)
            return
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size) or b"{}")
        STATE.requests.append(request)
        schema_name = _schema_name(request)
        model = str(request.get("model", "qa-success"))
        case = model.removeprefix("qa-")

        if schema_name == FILTER_SCHEMA_NAME:
            content = json.dumps(_filter_response(_messages(request)))
            finish_reason = "stop"
        elif schema_name == SCHEMA_NAME:
            content, finish_reason = _actor_response(case)
        else:
            # A successful actor retry must advance to the narrative request.
            # Invalid downstream data keeps this focused QA fixture small while
            # still exercising the public lifecycle and artifact publication.
            content = "{}"
            finish_reason = "stop"

        body = json.dumps(
            {
                "id": f"actor-retry-{case}",
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
                        "finish_reason": finish_reason,
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


def _write_inputs(work: Path) -> tuple[Path, Path, Path, Path]:
    risk = work / "risk-extraction.json"
    risk.write_text(
        json.dumps(
            {
                "risks": [
                    {
                        "risk_id": "qa-risk",
                        "risk_name": "Prompt injection",
                        "risk_description": (
                            "An attacker submits crafted input to influence the "
                            "AI assistant."
                        ),
                        "taxonomy": "ibm-risk-atlas",
                        "confidence": 0.99,
                        "grounding_confidence": "high",
                        "threat": "An attacker submits crafted input.",
                        "vulnerability": "Instruction-data confusion.",
                        "consequence": "The agent follows attacker instructions.",
                        "impact": "Unauthorized behavior.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    sssom = work / "risk-to-llm.sssom.tsv"
    sssom.write_text(
        "subject_id\tsubject_source\tpredicate_id\tobject_id\t"
        "object_source\tmapping_justification\n"
        "qa-risk\tibm-risk-atlas\tskos:relatedMatch\t"
        "llm01-prompt-injection\towasp-llm\t"
        "semapv:ManualMappingCuration\n",
        encoding="utf-8",
    )
    profile = work / "capability-profile.yaml"
    profile.write_text(
        yaml.safe_dump(
            {
                "zones_active": ["input", "reasoning"],
                "entry_points": [
                    {
                        "name": "chat",
                        "direction": "input",
                        "controllability": "direct",
                    }
                ],
                "confidence": "high",
                "kc_subcodes": ["KC1.1"],
                "entry_point_completeness": "operator_confirmed_complete",
                "entry_point_evidence": ["Deterministic QA fixture review"],
                "external_integrations": [
                    {
                        "name": "CRM",
                        "integration_type": "api",
                        "auth_method": "oauth",
                        "data_sensitivity": "high",
                    }
                ],
                "trust_boundaries": [
                    {
                        "name": "user-to-agent",
                        "from_zone": "input",
                        "to_zone": "reasoning",
                        "confidence": "explicit",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    facts = work / "qualification-facts.yaml"
    facts.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "facts": [
                    {
                        "fact": {
                            "namespace": "profile",
                            "fact_id": "capabilities.planning_interface",
                            "value_type": "boolean",
                            "property_path": [],
                        },
                        "status": "present",
                        "value": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return risk, sssom, profile, facts


def _command() -> list[str]:
    search_path = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
    uv = shutil.which("uv", path=search_path)
    if uv:
        return [uv, "run", "asago-scenario-generator"]
    executable = ROOT / ".venv" / "bin" / "asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def _run_case(
    case: str, work: Path, port: int, inputs: tuple[Path, Path, Path, Path]
) -> tuple[subprocess.CompletedProcess[str], Path, list[dict[str, Any]]]:
    risk, sssom, profile, facts = inputs
    output = work / f"output-{case}"
    start = len(STATE.requests)
    command = [
        *_command(),
        "generate",
        "--use-case",
        "An AI assistant accepts user chat input and follows instructions.",
        "--risk-extraction",
        str(risk),
        "--sssom",
        str(sssom),
        "--output-dir",
        str(output),
        "--profile",
        str(profile),
        "--qualification-facts",
        str(facts),
        "--base-url",
        f"http://127.0.0.1:{port}/v1",
        "--api-key",
        "unused",
        "--model",
        f"qa-{case}",
        "--no-eval",
    ]
    env = os.environ.copy()
    env["ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS"] = str(LIMIT)
    env.pop("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", None)
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    run_dirs = list(output.glob("*"))
    assert len(run_dirs) == 1, (case, result.stdout, result.stderr, run_dirs)
    return result, run_dirs[0], STATE.requests[start:]


def _call_log(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "calls.jsonl"
    assert path.is_file(), f"missing call log: {path}"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _actor_requests(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [request for request in requests if _schema_name(request) == SCHEMA_NAME]


def _assert_common_requests(requests: list[dict[str, Any]], count: int) -> None:
    actors = _actor_requests(requests)
    assert len(actors) == count, [_schema_name(request) for request in requests]
    assert all(request.get("max_completion_tokens") == LIMIT for request in actors)


def _assert_degraded_run(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 1, (result.returncode, result.stdout, result.stderr)
    assert "completed_with_errors" in result.stdout


def _assert_success(
    result: subprocess.CompletedProcess[str],
    run_dir: Path,
    requests: list[dict[str, Any]],
) -> None:
    _assert_degraded_run(result)
    _assert_common_requests(requests, 2)
    actors = _actor_requests(requests)
    retry_prompt = _messages(actors[1]).lower()
    assert retry_prompt.endswith(
        "return only a schema-matching object with bounded lists and concise prose."
    )
    assert (
        sum(_schema_name(request).startswith("Call1Response") for request in requests)
        >= 1
    )

    actor_logs = [
        entry for entry in _call_log(run_dir) if entry.get("call") == "actor_profile"
    ]
    assert len(actor_logs) == 2
    assert "error" in actor_logs[0]
    assert "error" not in actor_logs[1]
    required = {
        "capability-profile.yaml",
        "coverage-gaps.json",
        "coverage-plan.json",
        "finalization-inventory.json",
        "planning-checkpoint.json",
        "report.html",
        "run-manifest.yaml",
        "threat-surface.yaml",
    }
    assert required <= {path.name for path in run_dir.iterdir()}


def _assert_bounded(
    result: subprocess.CompletedProcess[str],
    run_dir: Path,
    requests: list[dict[str, Any]],
) -> None:
    _assert_degraded_run(result)
    _assert_common_requests(requests, 2)
    actor_logs = [
        entry for entry in _call_log(run_dir) if entry.get("call") == "actor_profile"
    ]
    assert len(actor_logs) == 2
    assert all(entry.get("code") == "completion_length" for entry in actor_logs)
    assert not any(
        _schema_name(request).startswith("Call1Response") for request in requests
    )


def _assert_nonlength(
    result: subprocess.CompletedProcess[str],
    run_dir: Path,
    requests: list[dict[str, Any]],
) -> None:
    _assert_degraded_run(result)
    _assert_common_requests(requests, 3)
    actor_logs = [
        entry for entry in _call_log(run_dir) if entry.get("call") == "actor_profile"
    ]
    assert len(actor_logs) == 3
    assert all(entry.get("code") != "completion_length" for entry in actor_logs)
    assert all(entry.get("error") for entry in actor_logs)
    assert not any(
        _schema_name(request).startswith("Call1Response") for request in requests
    )


def main() -> int:
    """Run the three offline UI-only QA procedures."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="actor-length-retry-qa-") as tmp:
            work = Path(tmp)
            inputs = _write_inputs(work)
            checks = {
                "success": _assert_success,
                "bounded": _assert_bounded,
                "nonlength": _assert_nonlength,
            }
            for case, check in checks.items():
                result, run_dir, requests = _run_case(
                    case, work, server.server_port, inputs
                )
                check(result, run_dir, requests)
                print(f"PASS QA-TALR-{list(checks).index(case) + 1:02d}: {case}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

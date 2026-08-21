#!/usr/bin/env python3
"""UI-only end-to-end QA for STPA execution projection production wiring.

This is the executable form of ``execution_projection_production_wiring.md``.
It drives only ``uv run python scripts/run_sp3.py`` and
``asago-scenario-generator validate-stpa-projection``, inspects published
artifacts with standard JSON/YAML readers, and never imports project
modules or contacts a live model.

Usage:
    uv run python acceptance/qa/stpa/execution_projection_production_wiring.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "acceptance" / "qa"))
from qa_harness import QARunner, child_env, run_command  # noqa: E402

SCHEMA_VERSION = "stpa-execution-projection-v1"
CANDIDATE_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = "RESP-1:CA-1-1:WRONG_TIMING:1"
SCENARIO_ID = "SCN-001"
UCA_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"

CONTROL_STRUCTURE_YAML = """\
responsibilities:
- resp_id: RESP-1
  description: Controller
  process_model_parts:
  - pm_id: PM-1-1
    description: Parsed intent
  - pm_id: PM-1-2
    description: Schema compliance
  control_actions:
  - ca_id: CA-1-1
    description: Select action
    target:
      type: controlled_process
      id: CP-1
  - ca_id: CA-1-2
    description: Validate parameters
    target:
      type: controlled_process
      id: CP-1
  feedback_channels:
  - fb_id: FB-1-1
    description: Intent feedback
    updates: PM-1-1
    source:
      type: controlled_process
      id: CP-1
  - fb_id: FB-1-2
    description: Validation feedback
    updates: PM-1-2
    source:
      type: controlled_process
      id: CP-1
controlled_processes:
- cp_id: CP-1
  description: Interface
"""

LOSS_ANALYSIS_YAML = """\
risk_card_losses:
- loss_id: L-1
  description: Stakeholder loss
  provenance: risk_card
  source_risk_cards:
  - r1
use_case_losses: []
hazards:
- hazard_id: H-1
  description: Hazardous state
  related_losses:
  - L-1
security_constraints:
- constraint_id: SC-1
  description: Must validate inputs
  related_hazards:
  - H-1
"""

ENRICHED_THREATS_YAML = f"""\
structural_threats:
- ica_slot_id: {UCA_SLOT}
  provenance: structural
  ica_id: {ICA_ID}
  ica_text: Unsafe control action issued with wrong timing
  hazardous_context: Context
  loss_scenario: Loss scenario
  related_hazards:
  - H-1
  related_constraints:
  - SC-1
  catalog_mappings: []
  na_reconciliation_flag: false
coverage_analysis:
  structural_coverage:
    total_slots: 1
    non_na: 1
    na: 0
    coverage_rate: 1.0
  structural_consideration:
    total_slots: 1
    considered: 1
    rate: 1.0
  na_quality:
    na_count: 0
    quality_count: 0
    quality_rate: 1.0
"""

DECLARED_FACTORS = [
    {
        "kind": "PROCESS_MODEL_FLAW",
        "source_id": "PM-1-1",
        "evidence": "model diverges after injection",
    },
    {
        "kind": "FEEDBACK_DELAY",
        "source_id": "FB-1-1",
        "evidence": "state updates lag",
    },
]

INVALID_FACTORS = [
    {
        "kind": "PROCESS_MODEL_FLAW",
        "source_id": "PM-99-1",
        "evidence": "unknown process model",
    },
]

TIMED_FACTORS = [
    {
        "kind": "PROCESS_MODEL_FLAW",
        "source_id": "PM-1-1",
        "evidence": "model is stale before the next step",
        "timing": "ordering before S-2",
    },
    {
        "kind": "FEEDBACK_DELAY",
        "source_id": "FB-1-1",
        "evidence": "feedback arrives late",
        "timing": "delay 250 milliseconds",
    },
    {
        "kind": "PROCESS_MODEL_FLAW",
        "source_id": "PM-1-2",
        "evidence": "schema belief remains wrong",
        "timing": "duration 5 seconds",
    },
    {
        "kind": "SENSOR_ANOMALY",
        "source_id": "FB-1-2",
        "evidence": "sensor reports in a bounded window",
        "timing": "window from 10 to 20 milliseconds",
    },
    {
        "kind": "ACTUATOR_ANOMALY",
        "source_id": "CA-1-2",
        "evidence": "actuator is absent until the next step",
        "timing": "absence until S-2",
    },
]

UNKNOWN_TIMING_FACTORS = [
    {
        "kind": "FEEDBACK_DELAY",
        "source_id": "FB-1-1",
        "evidence": "feedback lag is declared without a measured delay",
    },
]


class FixtureState:
    """Thread-safe-enough request state for the local sequential QA fixture."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.causal_factors: list[dict[str, Any]] = list(DECLARED_FACTORS)
        self.eval_observations: dict[str, Any] | None = None


STATE = FixtureState()


def _messages(request: dict[str, Any]) -> tuple[str, str]:
    system_prompt = ""
    user_prompt = ""
    for message in request.get("messages", []):
        role = message.get("role")
        content = str(message.get("content", ""))
        if role == "system":
            system_prompt += content
        elif role == "user":
            user_prompt += content
    return system_prompt, user_prompt


def _is_structured(request: dict[str, Any]) -> bool:
    return request.get("response_format") is not None


def _call_type(system_prompt: str) -> str:
    lowered = system_prompt.lower()
    if "attack tree" in lowered:
        return "attack_tree"
    if "gherkin" in lowered or "should/but" in lowered:
        return "gherkin"
    return "narrative"


def _bdi_response() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "defender_vulnerabilities": {
            "PM-1-1": "Parsed intent can be poisoned through FB-1-1.",
            "PM-1-2": "Schema compliance can be marked incorrectly.",
        },
        "attacker_bdi": {
            "beliefs": ["The defender relies on PM-1-1 for decisions."],
            "desires": ["Induce the unsafe control action on CA-1-1."],
            "intentions": [
                "Poison FB-1-1 to corrupt process model state",
                "Trigger CA-1-1 with incorrect timing",
            ],
        },
        "causal_factors": list(STATE.causal_factors),
    }
    return payload


def _narrative_response() -> str:
    return (
        "Step 1: The defender's process model starts correct. "
        "The controller maintains an accurate view of PM-1-1.\n\n"
        "Step 2: The attacker manipulates a control loop element. "
        "The attacker injects crafted data through FB-1-1.\n\n"
        "Step 3: The process model diverges from reality. "
        "The corrupted feedback causes PM-1-1 to hold stale information.\n\n"
        "Step 4: The defender acts on false beliefs. "
        "Relying on the corrupted PM-1-1, the controller decides to issue CA-1-1.\n\n"
        "Step 5: The ICA occurs. "
        "The unsafe control action CA-1-1 is issued with WRONG_TIMING.\n\n"
        "Step 6: The hazard is realized. "
        "The system-level hazard manifests from the mistimed action.\n\n"
        "Step 7: The loss follows. "
        "The ultimate loss L-1 occurs as the hazard propagates."
    )


def _attack_tree_response() -> str:
    return json.dumps(
        {
            "root": "Induce ICA WRONG_TIMING on CA-1-1",
            "branches": [
                {
                    "category": "controller_side",
                    "label": "WHY THE UCA OCCURS",
                    "children": [
                        {
                            "label": "Corrupt process model",
                            "children": [
                                {
                                    "label": "Poison PM-1-1 via FB-1-1",
                                    "details": "Attacker injects false data.",
                                }
                            ],
                        }
                    ],
                },
                {
                    "category": "path_side",
                    "label": "WHY CORRECT ACTION IS NOT EXECUTED",
                    "children": [
                        {
                            "label": "Actuator/executor failure",
                            "children": [
                                {
                                    "label": "Tool execution for CA-1-1 fails silently",
                                    "details": "The selected tool does not execute.",
                                }
                            ],
                        }
                    ],
                },
            ],
            "leaves": [
                "Poison PM-1-1 via FB-1-1",
                "Tool execution for CA-1-1 fails silently",
            ],
        }
    )


def _gherkin_response() -> str:
    return json.dumps(
        {
            "feature": "Safe orchestration for CA-1-1",
            "scenario": SCENARIO_ID,
            "given": [
                "Given the process model state PM-1-1 holds the correct system state"
            ],
            "when": ["When an attacker injects crafted input into the feedback path"],
            "then_expected": [
                "Then the system should validate all inputs against the security constraint before executing CA-1-1"
            ],
            "then_actual": [
                "But the controller issues WRONG_TIMING for CA-1-1 based on the corrupted PM-1-1",
                "And the loss L-1 is realized",
            ],
        }
    )


class Handler(BaseHTTPRequestHandler):
    """Serve deterministic OpenAI-compatible Stage 5 and Stage 6 responses."""

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
        system_prompt, _user_prompt = _messages(request)
        if _is_structured(request):
            content = json.dumps(_bdi_response())
        else:
            call_type = _call_type(system_prompt)
            if call_type == "attack_tree":
                content = _attack_tree_response()
            elif call_type == "gherkin":
                content = _gherkin_response()
            else:
                content = _narrative_response()
        body = json.dumps(
            {
                "id": "chatcmpl-stpa-proj-qa",
                "object": "chat.completion",
                "created": 0,
                "model": request.get("model", "stpa-proj-qa"),
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
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _write_inputs(work: Path) -> dict[str, Path]:
    inputs = work / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    control = inputs / "control-structure.yaml"
    loss = inputs / "loss-analysis.yaml"
    threats = inputs / "enriched-threats.yaml"
    control.write_text(CONTROL_STRUCTURE_YAML, encoding="utf-8")
    loss.write_text(LOSS_ANALYSIS_YAML, encoding="utf-8")
    threats.write_text(ENRICHED_THREATS_YAML, encoding="utf-8")
    return {
        "control_structure": control,
        "loss_analysis": loss,
        "enriched_threats": threats,
    }


def _write_profile(work: Path, port: int) -> Path:
    path = work / "profiles.yaml"
    path.write_text(
        (
            "stpa-proj-qa:\n"
            f"  base_url: http://127.0.0.1:{port}/v1\n"
            "  model: stpa-proj-qa\n"
            "  api_key: unused\n"
            "  temperature: 0.4\n"
        ),
        encoding="utf-8",
    )
    return path


def _run_sp3(
    output_dir: Path,
    inputs: dict[str, Path],
    profiles: Path,
) -> subprocess.CompletedProcess[str]:
    STATE.requests = []
    return run_command(
        [
            "uv",
            "run",
            "python",
            "scripts/run_sp3.py",
            "--enriched-threats",
            str(inputs["enriched_threats"]),
            "--control-structure",
            str(inputs["control_structure"]),
            "--loss-analysis",
            str(inputs["loss_analysis"]),
            "--output-dir",
            str(output_dir),
            "--profiles-file",
            str(profiles),
            "--profile",
            "stpa-proj-qa",
        ],
        cwd=ROOT,
        env=child_env(ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=None),
        timeout=180,
    )


def _validate_projection(path: Path) -> subprocess.CompletedProcess[str]:
    return run_command(
        [
            "uv",
            "run",
            "asago-scenario-generator",
            "validate-stpa-projection",
            str(path),
        ],
        cwd=ROOT,
        env=child_env(ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=None),
        timeout=60,
    )


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _call_log(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "calls.jsonl"
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _stage6_prompts() -> list[str]:
    prompts: list[str] = []
    for request in STATE.requests:
        if _is_structured(request):
            continue
        system_prompt, user_prompt = _messages(request)
        prompts.extend([system_prompt, user_prompt])
    return prompts


def _alignment_section(prompt: str) -> str:
    start = prompt.index("Projection ID:")
    end = prompt.index("Realize the projection rows", start)
    return prompt[start:end].rstrip()


def _table_rows(table: str) -> list[str]:
    return [
        line
        for line in table.splitlines()
        if line.strip().startswith("|") and "---" not in line
    ][1:]


def _combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}\n{result.stderr}"


def _scenario_yaml(run_dir: Path) -> Path:
    return run_dir / "scenarios" / f"{SCENARIO_ID}.yaml"


def _scenario_feature(run_dir: Path) -> Path:
    return run_dir / "scenarios" / f"{SCENARIO_ID}.feature"


def _projection_json(run_dir: Path) -> Path:
    return run_dir / "scenarios" / "canonical" / f"{SCENARIO_ID}.projection.json"


def _projection_yaml(run_dir: Path) -> Path:
    return run_dir / "scenarios" / "canonical" / f"{SCENARIO_ID}.projection.yaml"


def _qa_01(qa: QARunner, work: Path, inputs: dict[str, Path], profiles: Path) -> None:
    STATE.causal_factors = list(DECLARED_FACTORS)
    STATE.eval_observations = None
    output_dir = work / "qa-01"
    result = _run_sp3(output_dir, inputs, profiles)
    combined = _combined_output(result)
    qa.check("QA-STPA-PROJ-01 run succeeds", result.returncode == 0, combined[-500:])

    scenario_path = _scenario_yaml(output_dir)
    qa.check("QA-STPA-PROJ-01 scenario YAML exists", scenario_path.is_file())
    if not scenario_path.is_file():
        return
    scenario = _load_yaml(scenario_path)
    factors = (scenario.get("scenario_spec") or {}).get("causal_factors") or []
    source_ids = [factor.get("source_id") for factor in factors]
    qa.check(
        "QA-STPA-PROJ-01 declared factor order",
        source_ids == ["PM-1-1", "FB-1-1"],
        str(source_ids),
    )

    stage6 = [prompt for prompt in _stage6_prompts() if "Projection ID:" in prompt]
    qa.check(
        "QA-STPA-PROJ-01 Stage 6 requests include alignment",
        len(stage6) >= 6,
        f"alignment prompts={len(stage6)}",
    )
    if len(stage6) < 3:
        return
    tables = [_alignment_section(prompt) for prompt in stage6]
    qa.check(
        "QA-STPA-PROJ-01 alignment tables are byte-identical",
        all(table == tables[0] for table in tables),
    )
    rows = _table_rows(tables[0])
    qa.check("QA-STPA-PROJ-01 alignment has three rows", len(rows) == 3, str(rows))
    if len(rows) == 3:
        qa.check(
            "QA-STPA-PROJ-01 PM-1-1 then FB-1-1 then CA-1-1",
            "PM-1-1" in rows[0]
            and "FB-1-1" in rows[1]
            and "CA-1-1" in rows[2]
            and "UNSAFE_CONTROL_ACTION" in rows[2],
            "\n".join(rows),
        )
    qa.check(
        "QA-STPA-PROJ-01 no extra inferred factor row",
        all("PM-1-2" not in row and "FB-1-2" not in row for row in rows),
        "\n".join(rows),
    )
    qa.check(
        "QA-STPA-PROJ-01 Stage 6 forbids invention",
        all("Do not invent any causal factor" in prompt for prompt in stage6),
    )


def _qa_02(qa: QARunner, work: Path, inputs: dict[str, Path], profiles: Path) -> None:
    STATE.causal_factors = list(INVALID_FACTORS)
    STATE.eval_observations = None
    output_dir = work / "qa-02"
    result = _run_sp3(output_dir, inputs, profiles)
    combined = _combined_output(result)
    manifest_path = output_dir / "run-manifest.yaml"
    manifest = _load_yaml(manifest_path) if manifest_path.is_file() else {}
    diagnostics = combined + json.dumps(manifest)
    rejected = (
        result.returncode != 0
        or "Causal factor" in diagnostics
        or any(
            "Causal factor" in str(error) for error in manifest.get("stage_errors", [])
        )
    )
    qa.check(
        "QA-STPA-PROJ-02 reports causal-factor reference error",
        rejected and "PM-99-1" in diagnostics,
        diagnostics[-800:],
    )
    stage6 = [request for request in STATE.requests if not _is_structured(request)]
    qa.check("QA-STPA-PROJ-02 no Stage 6 request", stage6 == [], str(len(stage6)))
    qa.check(
        "QA-STPA-PROJ-02 no projection artifact",
        not _projection_json(output_dir).exists()
        and not _scenario_yaml(output_dir).exists(),
    )


def _qa_03(qa: QARunner, work: Path, inputs: dict[str, Path], profiles: Path) -> None:
    STATE.causal_factors = []
    STATE.eval_observations = None
    output_dir = work / "qa-03"
    result = _run_sp3(output_dir, inputs, profiles)
    qa.check(
        "QA-STPA-PROJ-03 run succeeds", result.returncode == 0, result.stderr[-400:]
    )
    scenario_path = _scenario_yaml(output_dir)
    json_path = _projection_json(output_dir)
    yaml_path = _projection_yaml(output_dir)
    feature_path = _scenario_feature(output_dir)
    qa.check(
        "QA-STPA-PROJ-03 legacy YAML and feature remain",
        scenario_path.is_file() and feature_path.is_file(),
    )
    qa.check(
        "QA-STPA-PROJ-03 canonical projection files exist",
        json_path.is_file() and yaml_path.is_file(),
    )
    if not (scenario_path.is_file() and json_path.is_file()):
        return
    scenario = _load_yaml(scenario_path)
    spec_factors = (scenario.get("scenario_spec") or {}).get("causal_factors")
    qa.check(
        "QA-STPA-PROJ-03 ScenarioSpec causal_factors present empty",
        spec_factors == [],
        str(spec_factors),
    )
    doc = _load_json(json_path)
    qa.check(
        "QA-STPA-PROJ-03 projection vectors present empty",
        doc.get("causal_factors") == []
        and doc.get("assertions") == []
        and doc.get("steps") == [],
        json.dumps(
            {key: doc.get(key) for key in ("causal_factors", "assertions", "steps")}
        ),
    )
    qa.check(
        "QA-STPA-PROJ-03 no invented temporal behavior",
        doc.get("uca_constraint") in (None, {}),
        str(doc.get("uca_constraint")),
    )
    stage6 = _stage6_prompts()
    qa.check(
        "QA-STPA-PROJ-03 no Stage 6 alignment table",
        all("Projection ID:" not in prompt for prompt in stage6),
    )


def _equivalent(left: Any, right: Any) -> bool:
    if isinstance(left, dict) and isinstance(right, dict):
        return set(left) == set(right) and all(
            _equivalent(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _equivalent(item, other) for item, other in zip(left, right, strict=True)
        )
    return left == right


def _qa_04(qa: QARunner, work: Path, inputs: dict[str, Path], profiles: Path) -> None:
    STATE.causal_factors = list(DECLARED_FACTORS)
    STATE.eval_observations = None
    output_dir = work / "qa-04"
    result = _run_sp3(output_dir, inputs, profiles)
    qa.check(
        "QA-STPA-PROJ-04 run succeeds", result.returncode == 0, result.stderr[-400:]
    )
    json_path = _projection_json(output_dir)
    yaml_path = _projection_yaml(output_dir)
    qa.check(
        "QA-STPA-PROJ-04 canonical files beside legacy artifacts",
        json_path.is_file()
        and yaml_path.is_file()
        and _scenario_yaml(output_dir).is_file()
        and _scenario_feature(output_dir).is_file(),
    )
    if not json_path.is_file():
        return
    json_doc = _load_json(json_path)
    yaml_doc = _load_yaml(yaml_path)
    qa.check(
        "QA-STPA-PROJ-04 schema version",
        json_doc.get("schema_version") == SCHEMA_VERSION
        and yaml_doc.get("schema_version") == SCHEMA_VERSION,
    )
    qa.check(
        "QA-STPA-PROJ-04 JSON and YAML are equivalent",
        _equivalent(json_doc, yaml_doc),
    )
    qa.check(
        "QA-STPA-PROJ-04 candidate identity is structural",
        json_doc.get("candidate_id") == CANDIDATE_ID,
        str(json_doc.get("candidate_id")),
    )
    qa.check(
        "QA-STPA-PROJ-04 ICA and scenario IDs are separate",
        json_doc.get("ica_id") == ICA_ID and json_doc.get("scenario_id") == SCENARIO_ID,
        json.dumps(
            {
                "ica_id": json_doc.get("ica_id"),
                "scenario_id": json_doc.get("scenario_id"),
            }
        ),
    )
    copied = json.loads(json.dumps(json_doc))
    copied["ica_id"] = "RESP-9:CA-9-9:WRONG_TIMING:9"
    copied["scenario_id"] = "SCN-999"
    qa.check(
        "QA-STPA-PROJ-04 changing separate identities does not rewrite candidate_id",
        copied["candidate_id"] == CANDIDATE_ID,
        copied["candidate_id"],
    )
    qa.check(
        "QA-STPA-PROJ-04 factor and step order preserved",
        [factor.get("source_id") for factor in json_doc.get("causal_factors", [])]
        == ["PM-1-1", "FB-1-1"]
        and [step.get("source_id") for step in json_doc.get("steps", [])]
        == ["PM-1-1", "FB-1-1", "CA-1-1"],
    )


def _validation_codes(result: subprocess.CompletedProcess[str]) -> list[str]:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return [item.get("code", "") for item in payload.get("violations", [])]


def _qa_05(qa: QARunner, work: Path, inputs: dict[str, Path], profiles: Path) -> None:
    STATE.causal_factors = list(DECLARED_FACTORS)
    STATE.eval_observations = None
    output_dir = work / "qa-05"
    _run_sp3(output_dir, inputs, profiles)
    json_path = _projection_json(output_dir)
    qa.check("QA-STPA-PROJ-05 source projection exists", json_path.is_file())
    if not json_path.is_file():
        return
    source = _load_json(json_path)
    copies = work / "qa-05-copies"
    copies.mkdir(parents=True, exist_ok=True)

    for key, code in (
        ("causal_factors", "causal_factors_missing"),
        ("assertions", "assertions_missing"),
        ("steps", "steps_missing"),
    ):
        mutated = json.loads(json.dumps(source))
        mutated.pop(key, None)
        path = copies / f"missing-{key}.json"
        path.write_text(json.dumps(mutated), encoding="utf-8")
        validation = _validate_projection(path)
        codes = _validation_codes(validation)
        qa.check(
            f"QA-STPA-PROJ-05 absent {key} fails closed",
            validation.returncode != 0 and code in codes,
            validation.stdout[-400:] or validation.stderr[-400:],
        )

    empty = json.loads(json.dumps(source))
    empty["causal_factors"] = []
    empty["assertions"] = []
    empty["steps"] = []
    empty["uca_constraint"] = None
    empty_path = copies / "present-empty.json"
    empty_path.write_text(json.dumps(empty), encoding="utf-8")
    empty_result = _validate_projection(empty_path)
    empty_payload = json.loads(empty_result.stdout or "{}")
    qa.check(
        "QA-STPA-PROJ-05 present-empty is valid",
        empty_result.returncode == 0 and empty_payload.get("valid") is True,
        empty_result.stdout[-400:] or empty_result.stderr[-400:],
    )

    identity = json.loads(json.dumps(source))
    identity["candidate_id"] = "EXEC:RESP-9:CA-1-1:WRONG_TIMING"
    identity_path = copies / "forged-identity.json"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")
    identity_result = _validate_projection(identity_path)
    qa.check(
        "QA-STPA-PROJ-05 forged identity fails",
        identity_result.returncode != 0
        and "candidate_identity_mismatch" in _validation_codes(identity_result),
        identity_result.stdout[-400:],
    )

    assertion = json.loads(json.dumps(source))
    assertion["assertions"][0]["source_id"] = "PM-9-9"
    assertion_path = copies / "forged-assertion-source.json"
    assertion_path.write_text(json.dumps(assertion), encoding="utf-8")
    assertion_result = _validate_projection(assertion_path)
    assertion_payload = json.loads(assertion_result.stdout or "{}")
    qa.check(
        "QA-STPA-PROJ-05 forged assertion source fails with earliest element",
        assertion_result.returncode != 0
        and "assertion_source_mismatch" in _validation_codes(assertion_result)
        and any(
            item.get("element_id") == "TA-1"
            for item in assertion_payload.get("violations", [])
            if item.get("code") == "assertion_source_mismatch"
        ),
        assertion_result.stdout[-400:],
    )

    final_step = json.loads(json.dumps(source))
    final_step["steps"][-1]["source_id"] = "CA-9-9"
    final_path = copies / "forged-final-step.json"
    final_path.write_text(json.dumps(final_step), encoding="utf-8")
    final_result = _validate_projection(final_path)
    qa.check(
        "QA-STPA-PROJ-05 forged final UCA fails",
        final_result.returncode != 0
        and "uca_step_mismatch" in _validation_codes(final_result),
        final_result.stdout[-400:],
    )

    provenance = json.loads(json.dumps(source))
    provenance["assertions"][0]["source_kind"] = "unsafe_control_action"
    provenance_path = copies / "forged-provenance.json"
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
    provenance_result = _validate_projection(provenance_path)
    qa.check(
        "QA-STPA-PROJ-05 forged provenance fails",
        provenance_result.returncode != 0
        and "typed_provenance_mismatch" in _validation_codes(provenance_result),
        provenance_result.stdout[-400:],
    )


def _constraint_by_source(doc: dict[str, Any], source_id: str) -> dict[str, Any] | None:
    for assertion in doc.get("assertions") or []:
        if assertion.get("source_id") == source_id:
            return assertion.get("constraint")
    return None


def _qa_06(qa: QARunner, work: Path, inputs: dict[str, Path], profiles: Path) -> None:
    STATE.causal_factors = list(TIMED_FACTORS)
    STATE.eval_observations = None
    known_dir = work / "qa-06-known"
    known_result = _run_sp3(known_dir, inputs, profiles)
    qa.check(
        "QA-STPA-PROJ-06 known-timing run succeeds",
        known_result.returncode == 0,
        known_result.stderr[-400:],
    )
    known_path = _projection_json(known_dir)
    if known_path.is_file():
        known = _load_json(known_path)
        ordering = _constraint_by_source(known, "PM-1-1") or {}
        delay = _constraint_by_source(known, "FB-1-1") or {}
        duration = _constraint_by_source(known, "PM-1-2") or {}
        window = _constraint_by_source(known, "FB-1-2") or {}
        absence = _constraint_by_source(known, "CA-1-2") or {}
        qa.check(
            "QA-STPA-PROJ-06 ordering constraint",
            ordering.get("type") == "ordering" and ordering.get("ordering") == "before",
            json.dumps(ordering),
        )
        qa.check(
            "QA-STPA-PROJ-06 delay uses canonical milliseconds",
            delay.get("type") == "delay" and delay.get("delay_ms") == 250,
            json.dumps(delay),
        )
        qa.check(
            "QA-STPA-PROJ-06 duration uses canonical seconds",
            duration.get("type") == "duration" and duration.get("duration_s") == 5,
            json.dumps(duration),
        )
        qa.check(
            "QA-STPA-PROJ-06 window uses canonical milliseconds",
            window.get("type") == "window"
            and window.get("window_from_ms") == 10
            and window.get("window_to_ms") == 20,
            json.dumps(window),
        )
        qa.check(
            "QA-STPA-PROJ-06 absence constraint",
            absence.get("type") == "absence",
            json.dumps(absence),
        )
        uca = known.get("uca_constraint") or {}
        qa.check(
            "QA-STPA-PROJ-06 explicit UCA outcome mapping",
            uca.get("type") == "uca_outcome"
            and uca.get("control_action_id") == "CA-1-1"
            and uca.get("uca_type") == "WRONG_TIMING",
            json.dumps(uca),
        )
        serialized = json.dumps(known)
        qa.check(
            "QA-STPA-PROJ-06 known projection has no runtime observations",
            "observation" not in serialized.lower(),
        )

    STATE.causal_factors = list(UNKNOWN_TIMING_FACTORS)
    STATE.eval_observations = {"delay_ms": 999, "observed_at": "runtime"}
    unknown_dir = work / "qa-06-unknown"
    unknown_result = _run_sp3(unknown_dir, inputs, profiles)
    qa.check(
        "QA-STPA-PROJ-06 unknown-timing run succeeds",
        unknown_result.returncode == 0,
        unknown_result.stderr[-400:],
    )
    unknown_path = _projection_json(unknown_dir)
    if unknown_path.is_file():
        unknown = _load_json(unknown_path)
        assertions = unknown.get("assertions") or []
        qa.check(
            "QA-STPA-PROJ-06 unknown timing has one assertion", len(assertions) == 1
        )
        if assertions:
            qa.check(
                "QA-STPA-PROJ-06 unknown timing is unbound",
                assertions[0].get("constraint") is None
                and assertions[0].get("requires_binding") is True,
                json.dumps(assertions[0]),
            )
        qa.check(
            "QA-STPA-PROJ-06 observations stay out of the projection",
            "runtime_observations" not in unknown
            and "observation" not in json.dumps(unknown).lower(),
        )
    eval_path = unknown_dir / "eval-scorecard.yaml"
    qa.check("QA-STPA-PROJ-06 evaluation artifact exists", eval_path.is_file())


def main() -> int:
    """Run the six offline UI-only QA procedures."""
    qa = QARunner()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="stpa-proj-wiring-qa-") as tmp:
            work = Path(tmp)
            inputs = _write_inputs(work)
            profiles = _write_profile(work, server.server_port)
            _qa_01(qa, work, inputs, profiles)
            _qa_02(qa, work, inputs, profiles)
            _qa_03(qa, work, inputs, profiles)
            _qa_04(qa, work, inputs, profiles)
            _qa_05(qa, work, inputs, profiles)
            _qa_06(qa, work, inputs, profiles)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return qa.summary()


if __name__ == "__main__":
    raise SystemExit(main())

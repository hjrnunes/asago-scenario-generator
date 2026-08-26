#!/usr/bin/env python3
"""Executable end-to-end QA suite for taxonomy narrative outside boundaries.

Mirrors ``narrative_outside_boundaries.md`` (QA-TNOB-01..04).  Drives only
``asago-scenario-generator generate`` against a deterministic loopback
OpenAI-compatible fixture and inspects CLI output, recorded prompts,
manifests, coverage-gaps.json, and admitted scenario YAML.  Never imports
project modules and never sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Pinned live generate contract (reported, not silently bent)
  1. Live generate uses semantic NarrativeDraftV3.  The fixture authors
     region/handle grouping only; the compiler attaches zones, IDs, and
     realizations.  Procedure IDs
     ``attacker.observe/prepare/deliver`` plus ``operator.impact`` are not
     a committed catalog chain.  The suite admits AP-T6-04
     (crossing ``reconnaissance``, outside ``setup``, crossing
     ``delivery``, inside ``impact``).
  2. QA-TNOB-01's two consecutive outside steps plus an extra outside-only
     mapping cannot be injected: AP-T6-04 has one outside prepare step in
     its own region.  The suite asserts that the published
     ``zone_sequence`` preserves the outside prepare step
     (``input,outside,reasoning``) without remapping IDs or zones.
  3. QA-TNOB-02's mixed-boundary / wrong-zone defects cannot be injected as
     provider-authored zones.  The finite region schema rejects a mixed
     outside+inside beat as ``cross_region_step_handle``.  The suite drives
     that public-UI defect through the bounded narrative retry (one owner
     retry) and records that inactive-zone / wrong-zone labels remain
     unit/acceptance contracts.
  4. QA-TNOB-03 cannot add extra outside-only traversal through the public
     generate UI.  The suite asserts that faceting and coverage credit
     only active Schneider zones from the admitted sequence, that
     ``tool_execution`` stays uncovered, and that the mandatory tree leaf
     for the first active region is not zoned ``outside``.
  5. QA-TNOB-04's non-semantic prompt still explains literal ``outside``.
     Live semantic-draft prompts replace that block with region-grouping
     rules and compiler-owned ``zone=outside`` / ``boundary=outside`` on
     the prepare handle.  The suite inspects the recorded user prompt.

Run with::

    uv run python acceptance/qa/taxonomy_risk/narrative_outside_boundaries.py

Exit status is 0 only when every pinned assertion passes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
QA_PIPELINE_ENV = "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"

failures: list[str] = []
notes: list[str] = []

_SEARCH_PATH = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
_UV = shutil.which("uv", path=_SEARCH_PATH) or "uv"

_USE_CASE = "An AI assistant accepts user chat input and follows instructions."
_BASE_CARD = "atlas-prompt-injection"
_CARD_TEXT = {
    "threat": "An attacker submits crafted input to influence the AI assistant.",
    "vulnerability": "Instruction-data confusion.",
    "consequence": "The agent follows attacker instructions.",
    "impact": "Unauthorized behavior.",
}
ACCEPT_AP_T6_04 = "Reflection loop resource exhaustion trap"
FILTER_RE = re.compile(r"\*\*Candidate handle:\*\* `(c\d+)`")
ACTOR_CHOICE_RE = re.compile(r"^- (ac\d+): actor=([^;]+); capability=(.+)$", re.M)
HANDLE_RE = re.compile(
    r"- (s\d+): order=(\d+); zone=([^;]+); action_kind=([^;]+); boundary=(\S+)"
)
REGION_RE = re.compile(r"^- (r\d+):$")
PROSE = "Deterministic QA fixture prose with sufficient detail."
EXPECTED_ZONE_SEQUENCE = ["input", "outside", "reasoning"]
EXPECTED_ACTIVE_ZONES = ["input", "reasoning"]
EXPECTED_MAPPINGS = (
    (("reconnaissance",), "input"),
    (("setup",), "outside"),
    (("delivery",), "reasoning"),
    (("impact",), "reasoning"),
)


def _command() -> list[str]:
    if shutil.which("uv", path=_SEARCH_PATH):
        return [_UV, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv" / "bin" / "asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def _schema_name(request: dict) -> str:
    response_format = request.get("response_format") or {}
    return str((response_format.get("json_schema") or {}).get("name", ""))


def _parse_regions(user_prompt: str) -> dict[str, list[dict[str, str]]]:
    """Parse compiler-owned region/handle inventory from a narrative prompt."""
    regions: dict[str, list[dict[str, str]]] = {}
    current: str | None = None
    in_inventory = False
    for line in user_prompt.splitlines():
        stripped = line.strip()
        if stripped.startswith("Compatibility regions and projected-step handles:"):
            in_inventory = True
            continue
        if not in_inventory:
            continue
        region_match = REGION_RE.match(stripped)
        if region_match:
            current = region_match.group(1)
            regions[current] = []
            continue
        handle_match = HANDLE_RE.search(stripped)
        if handle_match and current is not None:
            regions[current].append(
                {
                    "handle": handle_match.group(1),
                    "order": handle_match.group(2),
                    "zone": handle_match.group(3),
                    "action_kind": handle_match.group(4),
                    "boundary": handle_match.group(5),
                }
            )
    return regions


def _valid_regions(user_prompt: str) -> dict[str, list[dict]]:
    """Author one beat per handle inside its compiler-owned region."""
    return {
        region: [
            {
                "step_handles": [item["handle"]],
                "action": f"Deterministic action for {item['handle']}",
                "consequence": f"Deterministic consequence for {item['handle']}",
                "transition": None,
            }
            for item in handles
        ]
        for region, handles in _parse_regions(user_prompt).items()
    }


def _mixed_boundary_regions(user_prompt: str) -> dict[str, list[dict]] | None:
    """Combine an outside handle with an inside/crossing handle in one beat."""
    parsed = _parse_regions(user_prompt)
    outside_region = None
    inside_region = None
    for region, handles in parsed.items():
        if any(item["boundary"] == "outside" for item in handles):
            outside_region = region
        if any(item["boundary"] != "outside" for item in handles):
            inside_region = region
    if outside_region is None or inside_region is None:
        return None
    outside_handle = next(
        item["handle"]
        for item in parsed[outside_region]
        if item["boundary"] == "outside"
    )
    inside_handle = next(
        item["handle"]
        for item in parsed[inside_region]
        if item["boundary"] != "outside"
    )
    regions = _valid_regions(user_prompt)
    regions[outside_region] = [
        {
            "step_handles": [outside_handle, inside_handle],
            "action": "Deterministic mixed-boundary action",
            "consequence": "Deterministic mixed-boundary consequence",
            "transition": None,
        }
    ]
    return regions


class FixtureHandler(BaseHTTPRequestHandler):
    """Deterministic drafts; optional mixed-boundary narrative defect."""

    protocol_version = "HTTP/1.1"
    accepted_once = False
    requests: list[dict] = []
    narrative_mode = "valid"

    def reset() -> None:  # noqa: N805
        FixtureHandler.accepted_once = False
        FixtureHandler.requests = []

    def log_message(self, *args) -> None:  # noqa: N802
        pass

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.endswith("/chat/completions"):
            self.send_error(404)
            return
        try:
            self._handle()
        except Exception:  # pragma: no cover - fixture robustness
            self.send_error(500)
            return

    def _handle(self) -> None:  # noqa: C901
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size) or b"{}")
        user_prompt = "\n".join(
            str(message.get("content", ""))
            for message in request.get("messages", [])
            if message.get("role") == "user"
        )
        schema = _schema_name(request)
        FixtureHandler.requests.append({"schema": schema, "user_prompt": user_prompt})

        if schema.startswith("FilterMapDraftV3For"):
            handles = FILTER_RE.findall(user_prompt)
            if not handles:
                self.send_error(500)
                return
            accept_pattern = os.environ.get("ACCEPT_PATTERN", "")
            name_match = re.search(r"\*\*Name:\*\* ([^\n]+)", user_prompt)
            pattern_name = name_match.group(1) if name_match else "?"
            matches = not accept_pattern or pattern_name == accept_pattern
            accepted = matches and not FixtureHandler.accepted_once
            if matches:
                FixtureHandler.accepted_once = True
            content = json.dumps(
                {
                    handle: {
                        "relevant": accepted and i == 0,
                        "rationale": "Deterministic QA fixture verdict.",
                    }
                    for i, handle in enumerate(handles)
                }
            )
        elif schema.startswith("ActorDraftV3For"):
            choices = ACTOR_CHOICE_RE.findall(user_prompt)
            if not choices:
                self.send_error(500)
                return
            levels = {"novice": 0, "intermediate": 1, "advanced": 2, "expert": 3}
            handle = max(choices, key=lambda c: levels.get(c[2].strip(), -1))[0]
            content = json.dumps(
                {
                    "actor_choice_handle": handle,
                    "beliefs": [PROSE],
                    "desires": [PROSE],
                    "intentions": [PROSE],
                    "resource_handles": [],
                    "rationale": "Deterministic QA fixture actor draft.",
                }
            )
        elif schema.startswith("NarrativeDraftV3For"):
            if FixtureHandler.narrative_mode == "mixed":
                regions = _mixed_boundary_regions(user_prompt)
            else:
                regions = _valid_regions(user_prompt)
            if not regions:
                self.send_error(500)
                return
            content = json.dumps(
                {
                    "title": "Deterministic QA narrative title",
                    "summary": "Deterministic QA narrative summary.",
                    "regions": regions,
                }
            )
        elif schema.startswith("BehaviorDraftV2For"):

            def _embedded_array(label: str):
                match = re.search(label + ":\n", user_prompt)
                if not match:
                    return None
                value, _end = json.JSONDecoder().raw_decode(user_prompt, match.end())
                return value

            actions = _embedded_array("Action handles")
            assertions = _embedded_array("Required assertion handles")
            if actions is None or assertions is None:
                self.send_error(500)
                return
            steps = []
            for action in actions:
                examples = {}
                for param in action.get("parameters", []) or []:
                    if not param.get("required", True):
                        continue
                    value_type = param.get("value_type", "string")
                    examples[param["name"]] = {
                        "string": "fixture-value",
                        "boolean": True,
                        "integer": 1,
                        "number": 1.0,
                    }[value_type]
                steps.append(
                    {
                        "kind": "action",
                        "handle": action["handle"],
                        "text": f"Deterministic fixture action for {action['handle']}.",
                        "examples": examples,
                    }
                )
            for assertion in assertions:
                steps.append(
                    {
                        "kind": "assertion",
                        "handle": assertion["handle"],
                        "text": (
                            f"Deterministic fixture assertion for {assertion['handle']}."
                        ),
                        "examples": {},
                    }
                )
            content = json.dumps(
                {
                    "scenarios": [
                        {
                            "title": "Deterministic QA behavior scenario",
                            "steps": steps,
                        }
                    ]
                }
            )
        elif schema.startswith("AttackTreeDraftV3For"):
            tree_match = re.search(
                r"Canonical leaf inventory \(respond with handles only\):\n(.+)",
                user_prompt,
                re.S,
            )
            if not tree_match:
                self.send_error(500)
                return
            inventory = json.loads(tree_match.group(1))
            handles = [item["handle"] for item in inventory]
            content = json.dumps(
                {
                    "root_label": "Deterministic QA attack root",
                    "root_description": "Deterministic QA attack tree.",
                    "groups": [
                        {
                            "label": "Deterministic QA group",
                            "description": "Deterministic QA group.",
                            "leaf_handles": handles,
                        }
                    ],
                }
            )
        else:
            self.send_error(500)
            return

        body = json.dumps(
            {
                "id": f"qa-{schema}",
                "object": "chat.completion",
                "created": 0,
                "model": "qa-fixture",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": content,
                            "refusal": None,
                        },
                        "logprobs": None,
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


def _write_inputs(ws: Path) -> None:
    risks = [
        {
            "risk_id": _BASE_CARD,
            "risk_name": "Prompt injection",
            "risk_description": "Risk description for atlas-prompt-injection",
            "taxonomy": "ibm-risk-atlas",
            "confidence": 0.99,
            "grounding_confidence": "high",
            **_CARD_TEXT,
        }
    ]
    (ws / "risk-extraction.json").write_text(
        json.dumps({"risks": risks}) + "\n", encoding="utf-8"
    )
    rows = [
        f"{_BASE_CARD}\tibm-risk-atlas\tskos:relatedMatch\tllm01-prompt-injection"
        "\towasp-llm\tsemapv:ManualMappingCuration",
        f"{_BASE_CARD}\tibm-risk-atlas\tskos:relatedMatch\tllm06-excessive-agency"
        "\towasp-llm\tsemapv:ManualMappingCuration",
    ]
    (ws / "risk-to-llm.sssom.tsv").write_text(
        "subject_id\tsubject_source\tpredicate_id\tobject_id"
        "\tobject_source\tmapping_justification\n" + "\n".join(rows) + "\n",
        encoding="utf-8",
    )
    cross = {
        "t_to_llm": [
            {"source": "T6", "target": "LLM01"},
            {"source": "T11", "target": "LLM01"},
            {"source": "T2", "target": "LLM06"},
            {"source": "T13", "target": "LLM06"},
        ],
        "t_to_atlas": [],
        "t_to_asi": [],
        "t_direct": [],
    }
    (ws / "cross-taxonomy-mappings.yaml").write_text(
        yaml.safe_dump(cross, sort_keys=False), encoding="utf-8"
    )
    profile = {
        "zones_active": ["input", "reasoning", "tool_execution", "inter_agent"],
        "entry_points": [
            {"name": "chat", "direction": "input", "controllability": "direct"}
        ],
        "confidence": "high",
        "kc_subcodes": ["KC1.1", "KC6.4", "KC2.3"],
        "entry_point_completeness": "operator_confirmed_complete",
        "entry_point_evidence": ["Deterministic QA fixture review"],
        "tool_inventory": [
            {"name": "search-api", "description": "Deterministic QA search tool."},
            {
                "name": "shell-interpreter",
                "description": "Deterministic QA command interpreter tool.",
            },
        ],
        "tool_inventory_completeness": "operator_confirmed_complete",
        "tool_inventory_evidence": ["Deterministic QA fixture review"],
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
    (ws / "capability-profile.yaml").write_text(
        yaml.safe_dump(profile, sort_keys=False), encoding="utf-8"
    )
    facts = {
        "schema_version": "1",
        "facts": [
            {
                "fact": {
                    "namespace": "profile",
                    "fact_id": f"capabilities.{capability}",
                    "value_type": "boolean",
                    "property_path": [],
                },
                "status": "present",
                "value": True,
            }
            for capability in (
                "code_interpreter",
                "external_content_ingestion",
                "feedback_loop",
                "nl_command_translation",
                "planning_interface",
                "reflection_mechanism",
            )
        ],
    }
    (ws / "qualification-facts.yaml").write_text(
        yaml.safe_dump(facts, sort_keys=False), encoding="utf-8"
    )


def _new_workspace(case: str) -> Path:
    ws = RUN_ROOT / "workspaces" / case
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    _write_inputs(ws)
    (ws / "output").mkdir(exist_ok=True)
    return ws


def _run_cli(
    case: str,
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 2400,
) -> subprocess.CompletedProcess:
    capture_dir = RUN_ROOT / "captures" / case
    capture_dir.mkdir(parents=True, exist_ok=True)
    child_env = os.environ.copy()
    child_env.pop(QA_PIPELINE_ENV, None)
    child_env.pop("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None)
    if env:
        child_env.update(env)
    completed = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=child_env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    (capture_dir / "command.txt").write_text(" ".join(argv) + "\n", encoding="utf-8")
    (capture_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (capture_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (capture_dir / "exit.txt").write_text(f"{completed.returncode}\n", encoding="utf-8")
    (capture_dir / "requests.json").write_text(
        json.dumps(FixtureHandler.requests, indent=2) + "\n",
        encoding="utf-8",
    )
    return completed


def _generate(
    case: str, server: ThreadingHTTPServer, *, narrative_mode: str
) -> tuple[subprocess.CompletedProcess, Path | None]:
    ws = _new_workspace(case)
    FixtureHandler.reset()
    FixtureHandler.narrative_mode = narrative_mode
    os.environ["ACCEPT_PATTERN"] = ACCEPT_AP_T6_04
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env.pop(QA_PIPELINE_ENV, None)
    argv = [
        *_command(),
        "generate",
        "--use-case",
        _USE_CASE,
        "--risk-extraction",
        str(ws / "risk-extraction.json"),
        "--sssom",
        str(ws / "risk-to-llm.sssom.tsv"),
        "--cross-taxonomy",
        str(ws / "cross-taxonomy-mappings.yaml"),
        "--output-dir",
        str(ws / "output"),
        "--profile",
        str(ws / "capability-profile.yaml"),
        "--qualification-facts",
        str(ws / "qualification-facts.yaml"),
        "--base-url",
        f"http://127.0.0.1:{server.server_port}/v1",
        "--api-key",
        "unused",
        "--model",
        "qa-fixture",
        "--max-scenario-techniques",
        "1",
        "--generation-mode",
        "coverage",
    ]
    completed = _run_cli(case, argv, env=env)
    runs = sorted(path for path in (ws / "output").glob("*") if path.is_dir())
    return completed, runs[-1] if runs else None


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def _narrative_requests() -> list[dict]:
    return [
        item
        for item in FixtureHandler.requests
        if item["schema"].startswith("NarrativeDraftV3For")
    ]


def _admitted_envelopes(run_dir: Path) -> list[dict]:
    scenarios = run_dir / "scenarios"
    if not scenarios.is_dir():
        return []
    envelopes = []
    for path in sorted(scenarios.glob("*.yaml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and payload.get("narrative"):
            envelopes.append(payload)
    return envelopes


def _iter_leaves(node: dict) -> list[dict]:
    if not isinstance(node, dict):
        return []
    children = node.get("children") or []
    if children:
        leaves: list[dict] = []
        for child in children:
            leaves.extend(_iter_leaves(child))
        return leaves
    return [node]


def _assert_shared_admission(
    case: str, completed: subprocess.CompletedProcess, run_dir: Path | None
) -> list[dict]:
    _check(
        case, completed.returncode == 0, f"expected exit 0, got {completed.returncode}"
    )
    _check(case, run_dir is not None, "no run directory")
    if run_dir is None:
        return []
    manifest_path = run_dir / "run-manifest.yaml"
    _check(case, manifest_path.exists(), "missing run-manifest.yaml")
    manifest = (
        yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        if manifest_path.exists()
        else {}
    )
    if isinstance(manifest, dict):
        _check(
            case,
            manifest.get("status") == "completed",
            f"manifest status {manifest.get('status')!r}",
        )
    admitted = re.search(r"Candidates admitted:\s+(\d+)", completed.stdout)
    _check(
        case,
        admitted is not None and int(admitted.group(1)) == 1,
        "expected one admitted candidate",
    )
    return _admitted_envelopes(run_dir)


def qa_tnob_01(server: ThreadingHTTPServer) -> tuple[list[dict], Path | None]:
    """QA-TNOB-01: compiler-owned outside steps are admitted unchanged."""
    case = "TNOB-01"
    completed, run_dir = _generate(case, server, narrative_mode="valid")
    envelopes = _assert_shared_admission(case, completed, run_dir)
    _check(case, envelopes, "no admitted scenario YAML")
    if not envelopes:
        return [], run_dir
    narrative = envelopes[0].get("narrative") or {}
    steps = narrative.get("steps") or []
    mappings = [
        (tuple(step.get("projected_step_ids") or ()), step.get("zone"))
        for step in steps
    ]
    _check(
        case,
        mappings == list(EXPECTED_MAPPINGS),
        f"published mappings {mappings} != {list(EXPECTED_MAPPINGS)}",
    )
    _check(
        case,
        narrative.get("zone_sequence") == EXPECTED_ZONE_SEQUENCE,
        f"zone_sequence {narrative.get('zone_sequence')!r} != {EXPECTED_ZONE_SEQUENCE}",
    )
    notes.append(
        "01: live AP-T6-04 has one outside prepare step, not two consecutive "
        "outside steps plus an extra outside-only mapping. Published "
        "zone_sequence is input,outside,reasoning."
    )
    return envelopes, run_dir


def _load_manifest(run_dir: Path | None) -> dict:
    if run_dir is None:
        return {}
    path = run_dir / "run-manifest.yaml"
    if not path.exists():
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _narrative_failure_detail(manifest: dict) -> str:
    records = (manifest.get("semantic_generation") or {}).get("stage_records") or []
    details: list[str] = []
    for record in records:
        if record.get("stage") != "narrative":
            continue
        attempts = ((record.get("semantic_evidence") or {}).get("attempts")) or []
        for attempt in attempts:
            detail = attempt.get("failure_detail") or ""
            if detail:
                details.append(str(detail))
            for violation in attempt.get("validation_violations") or []:
                details.append(str(violation.get("detail") or ""))
    return "\n".join(details)


def qa_tnob_02(server: ThreadingHTTPServer) -> None:
    """QA-TNOB-02: mixed-boundary grouping fails closed through public generate."""
    case = "TNOB-02"
    completed, run_dir = _generate(case, server, narrative_mode="mixed")
    narrative_requests = _narrative_requests()
    admitted = re.search(r"Candidates admitted:\s+(\d+)", completed.stdout)
    admitted_count = int(admitted.group(1)) if admitted else -1
    envelopes = _admitted_envelopes(run_dir) if run_dir is not None else []
    manifest = _load_manifest(run_dir)
    detail = _narrative_failure_detail(manifest)
    stages = (
        (manifest.get("semantic_generation") or {}).get("candidates") or {}
    ).values()
    narrative_outcomes = [item.get("stages", {}).get("narrative") for item in stages]
    quarantine = (
        list((run_dir / "quarantine").glob("*.json")) if run_dir is not None else []
    )
    _check(
        case,
        completed.returncode != 0,
        f"expected nonzero exit, got {completed.returncode}",
    )
    _check(
        case,
        admitted_count == 0,
        f"expected zero admitted candidates, got {admitted_count}",
    )
    _check(case, not envelopes, "defective scenario YAML was published")
    _check(
        case,
        manifest.get("status") == "completed_with_errors",
        f"manifest status {manifest.get('status')!r}",
    )
    _check(
        case,
        1 <= len(narrative_requests) <= 2,
        f"narrative request count {len(narrative_requests)} outside bounded retry",
    )
    _check(case, quarantine, "no quarantine evidence was published")
    _check(
        case,
        "protocol_failure" in narrative_outcomes,
        f"narrative outcomes {narrative_outcomes}",
    )
    _check(
        case,
        "step_handles" in detail and "at most 1 item" in detail,
        f"missing mixed-boundary schema diagnostic: {detail[-400:]!r}",
    )
    notes.append(
        "02: live generate cannot inject provider-authored zones. The finite "
        "region schema rejects a mixed outside+non-outside beat as a "
        "protocol_failure before compiler zone repair. Inactive Schneider "
        "zone and wrong-zone labels remain unit/acceptance contracts."
    )


def qa_tnob_03(envelopes: list[dict], run_dir: Path | None) -> None:
    """QA-TNOB-03: outside is not credited as an active zone."""
    case = "TNOB-03"
    if not envelopes or run_dir is None:
        failures.append(f"{case}: no admitted envelope from TNOB-01")
        return
    envelope = envelopes[0]
    faceting = ((envelope.get("faceting") or {}).get("capability_profile")) or {}
    traversed = faceting.get("zones_traversed")
    _check(
        case,
        traversed == EXPECTED_ACTIVE_ZONES,
        f"faceting zones_traversed {traversed!r} != {EXPECTED_ACTIVE_ZONES}",
    )
    _check(
        case,
        "outside" not in (traversed or []),
        f"faceting credited outside: {traversed!r}",
    )
    coverage_path = run_dir / "coverage-gaps.json"
    _check(case, coverage_path.exists(), "missing coverage-gaps.json")
    coverage = (
        json.loads(coverage_path.read_text(encoding="utf-8"))
        if coverage_path.exists()
        else {}
    )
    uncovered = ((coverage.get("coverage_gaps") or {}).get("uncovered_zones")) or []
    _check(
        case,
        "tool_execution" in uncovered,
        f"coverage did not report tool_execution uncovered: {uncovered}",
    )
    _check(
        case,
        "outside" not in uncovered,
        f"coverage treated outside as an active uncovered zone: {uncovered}",
    )
    _check(
        case,
        "input" not in uncovered and "reasoning" not in uncovered,
        f"coverage failed to credit active traversal: {uncovered}",
    )
    leaves = _iter_leaves((envelope.get("attack_tree") or {}).get("root") or {})
    first_active = [
        leaf
        for leaf in leaves
        if (leaf.get("action") or {}).get("kind") == "initial_ingress"
    ]
    _check(case, first_active, "missing initial_ingress leaf")
    for leaf in first_active:
        _check(
            case,
            leaf.get("zone") != "outside",
            "mandatory ingress leaf used outside as its zone",
        )
    notes.append(
        "03: extra outside-only traversal cannot be injected through live "
        "generate. Active-zone consumers are asserted against the admitted "
        "AP-T6-04 sequence."
    )


def qa_tnob_04() -> None:
    """QA-TNOB-04: the live narrative prompt explains outside ownership."""
    case = "TNOB-04"
    narrative_requests = _narrative_requests()
    if not narrative_requests:
        capture = RUN_ROOT / "captures" / "TNOB-01" / "requests.json"
        if capture.exists():
            recorded = json.loads(capture.read_text(encoding="utf-8"))
            narrative_requests = [
                item
                for item in recorded
                if str(item.get("schema", "")).startswith("NarrativeDraftV3For")
            ]
    _check(case, narrative_requests, "no narrative request recorded")
    if not narrative_requests:
        return
    prompt = narrative_requests[0]["user_prompt"]
    parsed = _parse_regions(prompt)
    handles = [item for items in parsed.values() for item in items]
    by_kind = {item["action_kind"]: item for item in handles}
    _check(case, "prepare" in by_kind, f"missing prepare handle: {handles}")
    if "prepare" in by_kind:
        _check(
            case,
            by_kind["prepare"]["zone"] == "outside",
            f"prepare zone {by_kind['prepare']['zone']!r} != outside",
        )
        _check(
            case,
            by_kind["prepare"]["boundary"] == "outside",
            f"prepare boundary {by_kind['prepare']['boundary']!r} != outside",
        )
    _check(
        case,
        "Never move a handle to another region or combine regions in one causal beat."
        in prompt
        or "Never move a step handle to another region or combine steps across regions."
        in prompt,
        "prompt does not forbid combining outside and non-outside handles",
    )
    _check(
        case,
        "zones_active" in prompt,
        "prompt does not mention the profile-active zone list",
    )
    _check(
        case,
        "The literal zone `outside` is permitted only" not in prompt,
        "live semantic-draft prompt unexpectedly contains the non-semantic outside block",
    )
    notes.append(
        "04: live semantic-draft prompts replace the non-semantic literal-outside "
        "block with region-grouping rules and compiler-owned zone/boundary on "
        "the prepare handle."
    )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        envelopes, run_dir = qa_tnob_01(server)
        print("  [done] qa_tnob_01", flush=True)
        qa_tnob_02(server)
        print("  [done] qa_tnob_02", flush=True)
        qa_tnob_03(envelopes, run_dir)
        print("  [done] qa_tnob_03", flush=True)
        FixtureHandler.narrative_mode = "valid"
        qa_tnob_04()
        print("  [done] qa_tnob_04", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        os.environ.pop("ACCEPT_PATTERN", None)

    print("\n=== SUMMARY ===", flush=True)
    print(f"  Failures: {len(failures)}", flush=True)
    for failure in failures:
        print(f"    - {failure}", flush=True)
    for note in notes:
        print(f"  note: {note}", flush=True)
    print("  Result: FAIL" if failures else "  Result: PASS", flush=True)
    return 1 if failures else 0


RUN_ROOT = (
    REPO_ROOT
    / "tmp"
    / "qa-taxonomy-narrative-outside-boundaries"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

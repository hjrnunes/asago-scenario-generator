#!/usr/bin/env python3
"""Executable end-to-end QA suite for taxonomy attack-tree transport.

Mirrors ``attack_tree_transport.md`` (QA-TATT-01..04).  Drives only the
public ``asago-scenario-generator generate`` and ``eval`` CLIs against a
deterministic loopback OpenAI-compatible fixture and inspects CLI output,
fixture request counts, manifests, admitted scenario YAML, and eval
scorecards.  Never imports project modules and never sets
``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Pinned live generate/eval contract (reported, not silently bent)
  1. Live generate compiles trees from ``AttackTreeDraftV3`` handle
     groups.  The fixture cannot author ``projected_step_ids`` or
     ``realizations``; the compiler owns them.  QA-TATT-01's omitted
     realizations field is the live path, not a transport defect.
  2. QA-TATT-02 cannot inject conflicting realization semantics through
     the public generate UI.  The suite asserts that published
     realizations match the immutable projection block.
  3. QA-TATT-03 cannot inject ``step.unknown`` via a handle-only draft.
     Schema-invalid tree JSON (empty object) is the public-UI defect that
     exhausts the bounded owner retry (first attempt plus one retry).
     Unknown-identity rejection remains a unit/acceptance contract.
  4. Live catalog AP-T6-04 uses ``reconnaissance`` / ``setup`` /
     ``delivery`` / ``impact``, not Gherkin ``step.1`` / ``step.2``.
  5. QA-TATT-04 mutates a hash-consistent copy of a generate-produced
     completed run and drives public ``eval --allow-non-authoritative``.
     ``eval`` records ``ScenarioEnvelope`` schema failures on the
     scorecard and exits 0 when the run loads; it does not abort on a
     realization cover defect.  Procedure QA-TATT-04 expected a nonzero
     CLI exit.

Run with::

    uv run python acceptance/qa/taxonomy_risk/attack_tree_transport.py

Exit status is 0 only when every pinned assertion passes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import unicodedata
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
PROSE = "Deterministic QA fixture prose with sufficient detail."
UNKNOWN_STEP = "step.unknown"
CATALOG_STEPS = ("reconnaissance", "setup", "delivery", "impact")


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


def _filter_content(user_prompt: str) -> str | None:
    handles = FILTER_RE.findall(user_prompt)
    if not handles:
        return None
    accept_pattern = os.environ.get("ACCEPT_PATTERN", "")
    name_match = re.search(r"\*\*Name:\*\* ([^\n]+)", user_prompt)
    pattern_name = name_match.group(1) if name_match else "?"
    matches = not accept_pattern or pattern_name == accept_pattern
    accepted = matches and not FixtureHandler.accepted_once
    if matches:
        FixtureHandler.accepted_once = True
    return json.dumps(
        {
            handle: {
                "relevant": accepted and i == 0,
                "rationale": "Deterministic QA fixture verdict.",
            }
            for i, handle in enumerate(handles)
        }
    )


def _actor_content(user_prompt: str) -> str | None:
    choices = ACTOR_CHOICE_RE.findall(user_prompt)
    if not choices:
        return None
    levels = {"novice": 0, "intermediate": 1, "advanced": 2, "expert": 3}
    handle = max(choices, key=lambda c: levels.get(c[2].strip(), -1))[0]
    return json.dumps(
        {
            "actor_choice_handle": handle,
            "beliefs": [PROSE],
            "desires": [PROSE],
            "intentions": [PROSE],
            "resource_handles": [],
            "rationale": "Deterministic QA fixture actor draft.",
        }
    )


def _narrative_content(user_prompt: str) -> str | None:
    region_map: dict[str, list[str]] = {}
    current = None
    for line in user_prompt.splitlines():
        stripped = line.strip()
        region_match = re.match(r"^- (r\d+):$", stripped)
        if region_match:
            current = region_match.group(1)
            region_map[current] = []
            continue
        if current is not None:
            step_match = re.match(r"^- (s\d+):", stripped)
            if step_match:
                region_map[current].append(step_match.group(1))
    if not region_map:
        return None
    return json.dumps(
        {
            "title": "Deterministic QA narrative title",
            "summary": "Deterministic QA narrative summary.",
            "regions": {
                region: [
                    {
                        "step_handles": [handle],
                        "action": f"Deterministic action for {handle}",
                        "consequence": f"Deterministic consequence for {handle}",
                        "transition": None,
                    }
                    for handle in handles
                ]
                for region, handles in region_map.items()
            },
        }
    )


def _behavior_content(user_prompt: str) -> str | None:
    def _embedded_array(label: str):
        match = re.search(label + ":\n", user_prompt)
        if not match:
            return None
        value, _end = json.JSONDecoder().raw_decode(user_prompt, match.end())
        return value

    actions = _embedded_array("Action handles")
    assertions = _embedded_array("Required assertion handles")
    if actions is None or assertions is None:
        return None
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
                "text": (f"Deterministic fixture assertion for {assertion['handle']}."),
                "examples": {},
            }
        )
    return json.dumps(
        {
            "scenarios": [
                {
                    "title": "Deterministic QA behavior scenario",
                    "steps": steps,
                }
            ]
        }
    )


def _tree_content(user_prompt: str) -> str | None:
    if FixtureHandler.tree_mode == "invalid":
        return "{}"
    tree_match = re.search(
        r"Canonical leaf inventory \(respond with handles only\):\n(.+)",
        user_prompt,
        re.S,
    )
    if not tree_match:
        return None
    try:
        inventory = json.loads(tree_match.group(1))
    except json.JSONDecodeError:
        return None
    handles = [item["handle"] for item in inventory]
    return json.dumps(
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


class FixtureHandler(BaseHTTPRequestHandler):
    """Deterministic drafts; optional schema-invalid attack-tree defect."""

    protocol_version = "HTTP/1.1"
    accepted_once = False
    requests: list[dict] = []
    tree_mode = "valid"

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

    def _handle(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size) or b"{}")
        user_prompt = "\n".join(
            str(message.get("content", ""))
            for message in request.get("messages", [])
            if message.get("role") == "user"
        )
        schema = _schema_name(request)
        FixtureHandler.requests.append({"schema": schema, "user_prompt": user_prompt})
        content = _draft_content(schema, user_prompt)
        if content is None:
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


def _draft_content(schema: str, user_prompt: str) -> str | None:
    if schema.startswith("FilterMapDraftV3For"):
        return _filter_content(user_prompt)
    if schema.startswith("ActorDraftV3For"):
        return _actor_content(user_prompt)
    if schema.startswith("NarrativeDraftV3For"):
        return _narrative_content(user_prompt)
    if schema.startswith("BehaviorDraftV2For"):
        return _behavior_content(user_prompt)
    if schema.startswith("AttackTreeDraftV3For"):
        return _tree_content(user_prompt)
    return None


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
    return completed


def _generate(
    case: str, server: ThreadingHTTPServer, *, tree_mode: str = "valid"
) -> tuple[subprocess.CompletedProcess, Path | None]:
    ws = _new_workspace(case)
    FixtureHandler.reset()
    FixtureHandler.tree_mode = tree_mode
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


def _admitted_envelopes(run_dir: Path | None) -> list[dict]:
    if run_dir is None:
        return []
    scenarios = run_dir / "scenarios"
    if not scenarios.is_dir():
        return []
    envelopes = []
    for path in sorted(scenarios.glob("*.yaml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and payload.get("attack_tree"):
            envelopes.append(payload)
    return envelopes


def _leaf_step_ids(leaf: dict) -> list[str]:
    ids = leaf.get("projected_step_ids") or []
    return [str(item) for item in ids]


def _tree_requests() -> list[dict]:
    return [
        item
        for item in FixtureHandler.requests
        if item["schema"].startswith("AttackTreeDraftV3For")
    ]


def _chain_steps(envelope: dict) -> dict[str, dict]:
    projection = envelope.get("projection") or {}
    inner = projection.get("projection") or {}
    chain = inner.get("source_chain") or {}
    steps = chain.get("steps") or []
    return {
        str(step.get("step_id")): step
        for step in steps
        if isinstance(step, dict) and step.get("step_id")
    }


def _realization_matches_chain(realization: dict, step: dict) -> bool:
    return (
        realization.get("action_kind") == step.get("action_kind")
        and realization.get("executor_role") == step.get("executor_role")
        and realization.get("boundary_position") == step.get("boundary_position")
    )


def _assert_mapped_leaf_realizations(case: str, envelope: dict) -> None:
    leaves = _iter_leaves(envelope.get("attack_tree", {}).get("root") or {})
    _check(case, leaves, "admitted tree has no leaves")
    chain = _chain_steps(envelope)
    mapped = 0
    for leaf in leaves:
        ids = _leaf_step_ids(leaf)
        realizations = list(leaf.get("realizations") or [])
        if not ids:
            continue
        mapped += 1
        _check(
            case,
            len(realizations) == len(ids),
            f"leaf {leaf.get('id')} realizations {len(realizations)} != mapped IDs {ids}",
        )
        real_ids = [str(item.get("projected_step_id")) for item in realizations]
        _check(
            case,
            real_ids == ids,
            f"leaf {leaf.get('id')} realization IDs {real_ids} != mapped IDs {ids}",
        )
        for realization, step_id in zip(realizations, ids, strict=False):
            step = chain.get(step_id)
            _check(
                case, step is not None, f"mapped ID {step_id!r} absent from projection"
            )
            if step is None:
                continue
            _check(
                case,
                _realization_matches_chain(realization, step),
                f"leaf {leaf.get('id')} realization for {step_id} diverges from projection",
            )
    _check(case, mapped > 0, "no mapped leaves with projected_step_ids")


def qa_tatt_01(server: ThreadingHTTPServer) -> tuple[list[dict], Path | None]:
    """QA-TATT-01: omitted realizations are compiler-normalized."""
    case = "TATT-01"
    completed, run_dir = _generate(case, server, tree_mode="valid")
    _check(
        case, completed.returncode == 0, f"expected exit 0, got {completed.returncode}"
    )
    tree_requests = _tree_requests()
    _check(
        case,
        len(tree_requests) == 1,
        f"attack-tree stage called {len(tree_requests)} times, expected 1",
    )
    envelopes = _admitted_envelopes(run_dir)
    _check(case, envelopes, "no admitted scenario YAML")
    if envelopes:
        _assert_mapped_leaf_realizations(case, envelopes[0])
        mapped = [
            step_id
            for leaf in _iter_leaves(
                envelopes[0].get("attack_tree", {}).get("root") or {}
            )
            for step_id in _leaf_step_ids(leaf)
        ]
        for expected in CATALOG_STEPS:
            _check(
                case,
                expected in mapped,
                f"mapped step IDs {mapped} omit catalog step {expected}",
            )
    notes.append(
        "01: live AttackTreeDraftV3 never carries realizations; one valid "
        "handle-group response is compiled into canonical per-step records. "
        "Catalog IDs are reconnaissance/setup/delivery/impact, not step.1/step.2."
    )
    return envelopes, run_dir


def qa_tatt_02(envelopes: list[dict]) -> None:
    """QA-TATT-02: published realizations cannot override projection."""
    case = "TATT-02"
    if not envelopes:
        failures.append(f"{case}: no admitted envelope from TATT-01")
        return
    envelope = envelopes[0]
    _assert_mapped_leaf_realizations(case, envelope)
    leaves = _iter_leaves(envelope.get("attack_tree", {}).get("root") or {})
    chain = _chain_steps(envelope)
    conflicting = 0
    for leaf in leaves:
        for realization in leaf.get("realizations") or []:
            step = chain.get(str(realization.get("projected_step_id")))
            if step is None:
                continue
            if not _realization_matches_chain(realization, step):
                conflicting += 1
    _check(
        case,
        conflicting == 0,
        f"{conflicting} published realizations contradict projection",
    )
    notes.append(
        "02: fixture cannot author conflicting realization fields; compiler "
        "canonicalization against the projection block is asserted."
    )


def qa_tatt_03(server: ThreadingHTTPServer) -> None:
    """QA-TATT-03: unknown projected identity cannot be injected."""
    case = "TATT-03"
    completed, run_dir = _generate(case, server, tree_mode="invalid")
    tree_requests = _tree_requests()
    _check(
        case,
        len(tree_requests) == 2,
        f"attack-tree attempts {len(tree_requests)} != bounded retry (2)",
    )
    envelopes = _admitted_envelopes(run_dir)
    mapped = [
        step_id
        for envelope in envelopes
        for leaf in _iter_leaves(envelope.get("attack_tree", {}).get("root") or {})
        for step_id in _leaf_step_ids(leaf)
    ]
    _check(case, UNKNOWN_STEP not in mapped, "admitted tree mapped step.unknown")
    combined = completed.stdout + completed.stderr
    _check(
        case,
        UNKNOWN_STEP not in combined,
        "unknown-identity diagnostic appeared on the public generate UI",
    )
    admitted = re.search(r"Candidates admitted:\s+(\d+)", completed.stdout)
    admitted_count = int(admitted.group(1)) if admitted else None
    _check(
        case,
        admitted_count == 0 or not envelopes,
        f"invalid tree draft still admitted {admitted_count} candidate(s)",
    )
    _check(
        case,
        completed.returncode != 0,
        f"degraded invalid-tree outcome expected nonzero, got {completed.returncode}",
    )
    notes.append(
        "03: handle-only AttackTreeDraftV3 cannot inject step.unknown; "
        "schema-invalid tree JSON exhausts the owner retry. Unknown-identity "
        "rejection remains a unit/acceptance contract."
    )


def _first_mapped_leaf(tree_root: dict) -> dict | None:
    for leaf in _iter_leaves(tree_root):
        if _leaf_step_ids(leaf) and leaf.get("realizations"):
            return leaf
    return None


def _mutate_realizations(leaf: dict, defect: str) -> None:
    realizations = list(leaf.get("realizations") or [])
    if defect == "missing":
        leaf["realizations"] = []
        return
    if not realizations:
        return
    first = dict(realizations[0])
    if defect == "extra":
        extra = dict(first)
        extra["projected_step_id"] = "step.1"
        leaf["realizations"] = [*realizations, extra]
        return
    if defect == "duplicate":
        leaf["realizations"] = [*realizations, dict(first)]
        return
    flipped = "impact" if first.get("action_kind") != "impact" else "prepare"
    inconsistent = dict(first)
    inconsistent["action_kind"] = flipped
    leaf["realizations"] = [inconsistent, *realizations[1:]]


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _nfc(value: object) -> object:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_nfc(item) for item in value]
    if isinstance(value, dict):
        return {
            _nfc(key) if isinstance(key, str) else key: _nfc(item)
            for key, item in value.items()
        }
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        _nfc(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _update_receipt_sha256(node: object, relative_path: str, digest: str) -> None:
    if isinstance(node, dict):
        if node.get("path") == relative_path and "sha256" in node:
            node["sha256"] = digest
        for value in node.values():
            _update_receipt_sha256(value, relative_path, digest)
    elif isinstance(node, list):
        for item in node:
            _update_receipt_sha256(item, relative_path, digest)


def _receipt_projection(receipts: list[dict]) -> list[dict[str, str | None]]:
    ordered = sorted(receipts, key=lambda item: (item["role"], item["path"]))
    return [
        {
            "role": item["role"],
            "path": item["path"],
            "candidate_id": item["candidate_id"],
            "scenario_id": item.get("scenario_id"),
            "sha256": item["sha256"],
        }
        for item in ordered
    ]


def _refresh_candidate_result_digests(inventory: dict) -> None:
    for decision in inventory.get("admission_decisions") or []:
        if not isinstance(decision, dict):
            continue
        payload = {
            "candidate_id": decision.get("candidate_id"),
            "status": decision.get("status"),
            "violations": decision.get("violations") or [],
            "gate_results": decision.get("gate_results") or [],
            "snapshots": {
                "candidate_snapshot_sha256": decision.get("candidate_snapshot_sha256"),
                "actor_snapshot_sha256": decision.get("actor_snapshot_sha256"),
                "narrative_snapshot_sha256": decision.get("narrative_snapshot_sha256"),
                "final_tree_snapshot_sha256": decision.get(
                    "final_tree_snapshot_sha256"
                ),
            },
            "terminal_receipts": _receipt_projection(
                list(decision.get("terminal_receipts") or [])
            ),
        }
        decision["payload_sha256"] = _canonical_sha256(payload)


def _align_finalization_receipts(
    run_dir: Path, relative_path: str, digest: str
) -> None:
    inventory_path = run_dir / "finalization-inventory.json"
    if not inventory_path.is_file():
        return
    payload = json.loads(inventory_path.read_text(encoding="utf-8"))
    _update_receipt_sha256(payload, relative_path, digest)
    _refresh_candidate_result_digests(payload)
    inventory_path.write_text(
        json.dumps(payload, separators=(",", ":")), encoding="utf-8"
    )


def _rehash_inventory(run_dir: Path) -> None:
    manifest_path = run_dir / "run-manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    inventory = manifest.get("inventory") or []
    for entry in inventory:
        if not isinstance(entry, dict) or "path" not in entry:
            continue
        artifact = run_dir / str(entry["path"])
        if artifact.is_file():
            entry["sha256"] = _digest(artifact)
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )


def _copy_run_with_defect(source: Path, defect: str) -> Path:
    dest = RUN_ROOT / "workspaces" / f"TATT-04-{defect}" / "run"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(source, dest)
    scenario_dir = dest / "scenarios"
    yaml_files = sorted(scenario_dir.glob("*.yaml")) if scenario_dir.is_dir() else []
    if not yaml_files:
        return dest
    path = yaml_files[0]
    envelope = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(envelope, dict):
        return dest
    leaf = _first_mapped_leaf(envelope.get("attack_tree", {}).get("root") or {})
    if leaf is not None:
        _mutate_realizations(leaf, defect)
        path.write_text(yaml.safe_dump(envelope, sort_keys=False), encoding="utf-8")
        relative = path.relative_to(dest).as_posix()
        _align_finalization_receipts(dest, relative, _digest(path))
        _rehash_inventory(dest)
    return dest


def _scorecard_schema_validity(stdout: str) -> dict | None:
    try:
        payload = yaml.safe_load(stdout)
    except yaml.YAMLError:
        return None
    if not isinstance(payload, dict):
        return None
    metrics = (payload.get("validity_grounding") or {}).get("metrics") or {}
    result = metrics.get("scenario_schema_validity")
    return result if isinstance(result, dict) else None


def qa_tatt_04(source_run: Path | None) -> None:
    """QA-TATT-04: strict finalized-tree defects are visible on eval."""
    if source_run is None:
        failures.append("TATT-04: no completed generate run from TATT-01")
        return
    for defect in ("missing", "extra", "duplicate", "inconsistent"):
        case = f"TATT-04-{defect}"
        run_dir = _copy_run_with_defect(source_run, defect)
        completed = _run_cli(
            case,
            [
                *_command(),
                "eval",
                "--output-dir",
                str(run_dir),
                "--allow-non-authoritative",
            ],
            timeout=600,
        )
        combined = completed.stdout + completed.stderr
        validity = _scorecard_schema_validity(completed.stdout)
        cover_defect = defect in {"missing", "extra", "duplicate"}
        if cover_defect:
            schema_failed = False
            if validity is not None:
                status = str(validity.get("status", "")).lower()
                schema_failed = status in {"fail", "failed"}
            identified = schema_failed or "realization" in combined.lower()
            _check(
                case,
                identified,
                "eval did not identify the realization cover defect on the scorecard or CLI",
            )
            _check(
                case,
                completed.returncode == 0,
                f"live eval exits 0 after loading a defective tree, got {completed.returncode}",
            )
        else:
            schema_failed = False
            if validity is not None:
                status = str(validity.get("status", "")).lower()
                schema_failed = status in {"fail", "failed"}
            _check(
                case,
                completed.returncode == 0,
                f"eval exited {completed.returncode} for semantic inconsistency",
            )
            if schema_failed:
                notes.append(
                    f"04-{defect}: envelope load rejected action_kind inconsistency."
                )
            else:
                notes.append(
                    "04-inconsistent: ScenarioEnvelope load checks realization "
                    "cover, not action_kind semantics versus the projection "
                    "block. Semantic override remains a generate-time compiler "
                    "contract (TATT-02), not a public eval abort."
                )
    notes.append(
        "04: procedure expected nonzero eval exit; live eval prints a "
        "scorecard and exits 0 when the hash-consistent run loads. Cover "
        "defects fail scenario_schema_validity."
    )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        envelopes, run_dir = qa_tatt_01(server)
        print("  [done] qa_tatt_01", flush=True)
        qa_tatt_02(envelopes)
        print("  [done] qa_tatt_02", flush=True)
        qa_tatt_03(server)
        print("  [done] qa_tatt_03", flush=True)
        qa_tatt_04(run_dir)
        print("  [done] qa_tatt_04", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        os.environ.pop("ACCEPT_PATTERN", None)
        FixtureHandler.tree_mode = "valid"

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
    / "qa-taxonomy-attack-tree-transport"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

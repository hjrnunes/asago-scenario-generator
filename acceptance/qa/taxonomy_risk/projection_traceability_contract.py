#!/usr/bin/env python3
"""Executable end-to-end QA suite for taxonomy projection traceability.

Mirrors ``projection_traceability_contract.md`` (QA-TPTC-01..05).  Drives
only ``asago-scenario-generator generate`` against a deterministic loopback
OpenAI-compatible fixture and inspects CLI output, fixture request schemas,
manifests, and admitted scenario YAML.  Never imports project modules and
never sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Pinned live generate contract (reported, not silently bent)
  1. Live generate compiles attack trees from ``AttackTreeDraftV3`` handle
     groups.  The fixture cannot author zones, technique IDs, projected
     step IDs, or realizations; the compiler owns them.
  2. QA-TPTC-01's synthetic chain
     ``attacker.observe, attacker.prepare, attacker.deliver, operator.impact``
     is not a committed catalog pattern.  The suite admits AP-T6-04
     (``reconnaissance`` crossing observe, ``setup`` outside prepare,
     ``delivery`` crossing deliver, ``impact`` inside system impact) and
     records the identity deviation.
  3. QA-TPTC-02/03 transport-normalization cases (invalid zone/technique on
     a provider-authored leaf, injected valid technique IDs) cannot be
     driven through the public generate UI.  The suite asserts compiler
     canonicalization of the outside prepare leaf and that published
     technique IDs, when present, match ATLAS/LAAF format.
  4. QA-TPTC-04/05 (unmapped inside/crossing external leaves, unknown
     ``step.unknown``) cannot be injected by a handle-only draft.  The
     suite asserts that no admitted leaf maps an unknown ID and that no
     non-outside step is mapped by ``external_precondition``.

Run with::

    uv run python acceptance/qa/taxonomy_risk/projection_traceability_contract.py

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
PROSE = "Deterministic QA fixture prose with sufficient detail."
TECHNIQUE_RE = re.compile(r"^(AML\.T\d{4}(\.\d{3})?|[SML]\d+)$")


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


class FixtureHandler(BaseHTTPRequestHandler):
    """Deterministic drafts for every generation stage."""

    protocol_version = "HTTP/1.1"
    accepted_once = False
    requests: list[dict] = []

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
                self.send_error(500)
                return
            content = json.dumps(
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
    return completed


def _generate(
    case: str, server: ThreadingHTTPServer
) -> tuple[subprocess.CompletedProcess, Path | None]:
    ws = _new_workspace(case)
    FixtureHandler.reset()
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


def _admitted_envelopes(run_dir: Path) -> list[dict]:
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
    envelopes = _admitted_envelopes(run_dir)
    _check(case, len(envelopes) >= 1, "no admitted scenario YAML")
    tree_requests = [
        item
        for item in FixtureHandler.requests
        if item["schema"].startswith("AttackTreeDraftV3For")
    ]
    _check(case, tree_requests, "no attack-tree request")
    empty_compat = [
        item
        for item in FixtureHandler.requests
        if "empty action/executor compatibility" in item["user_prompt"]
        or "compatibility intersection" in item["user_prompt"].lower()
        and "empty" in item["user_prompt"].lower()
    ]
    _check(
        case,
        not empty_compat,
        "attack-tree retry mentions an empty action/executor compatibility intersection",
    )
    return envelopes


def qa_tptc_01(server: ThreadingHTTPServer) -> list[dict]:
    """QA-TPTC-01: aligned chain reaches admission."""
    case = "TPTC-01"
    completed, run_dir = _generate(case, server)
    envelopes = _assert_shared_admission(case, completed, run_dir)
    if not envelopes:
        return []
    envelope = envelopes[0]
    leaves = _iter_leaves(envelope.get("attack_tree", {}).get("root") or {})
    _check(case, leaves, "admitted tree has no leaves")
    kinds = [((leaf.get("action") or {}).get("kind")) for leaf in leaves]
    mapped_ids = [step_id for leaf in leaves for step_id in _leaf_step_ids(leaf)]
    _check(
        case,
        "initial_ingress" in kinds,
        f"missing initial_ingress leaf; kinds={kinds}",
    )
    _check(
        case,
        "external_precondition" in kinds,
        f"missing external_precondition leaf; kinds={kinds}",
    )
    _check(case, "impact" in kinds, f"missing impact leaf; kinds={kinds}")
    for expected in ("reconnaissance", "setup", "delivery", "impact"):
        _check(
            case,
            expected in mapped_ids,
            f"mapped step IDs {mapped_ids} omit catalog step {expected}",
        )
    for leaf in leaves:
        ids = _leaf_step_ids(leaf)
        realizations = leaf.get("realizations") or []
        if ids:
            _check(
                case,
                len(realizations) == len(ids),
                f"leaf {leaf.get('id')} realizations {len(realizations)} != mapped IDs {ids}",
            )
            for realization, step_id in zip(realizations, ids, strict=False):
                _check(
                    case,
                    realization.get("projected_step_id") == step_id,
                    f"realization identity {realization.get('projected_step_id')!r} != {step_id!r}",
                )
    notes.append(
        "01: live catalog AP-T6-04 uses reconnaissance/setup/delivery/impact, "
        "not attacker.observe/attacker.prepare/attacker.deliver/operator.impact."
    )
    return envelopes


def qa_tptc_02(envelopes: list[dict]) -> None:
    """QA-TPTC-02: invalid external metadata is canonicalized by the compiler."""
    case = "TPTC-02"
    if not envelopes:
        failures.append(f"{case}: no admitted envelope from TPTC-01")
        return
    leaves = _iter_leaves(envelopes[0].get("attack_tree", {}).get("root") or {})
    outside = [
        leaf
        for leaf in leaves
        if (leaf.get("action") or {}).get("kind") == "external_precondition"
        and "setup" in _leaf_step_ids(leaf)
    ]
    _check(case, outside, "no outside setup external_precondition leaf")
    for leaf in outside:
        _check(
            case,
            leaf.get("zone") in (None, ""),
            f"outside leaf zone {leaf.get('zone')!r}",
        )
        technique = leaf.get("technique_id")
        _check(
            case,
            technique in (None, "") or TECHNIQUE_RE.match(str(technique)),
            f"outside leaf kept invalid technique {technique!r}",
        )
        _check(
            case, "setup" in _leaf_step_ids(leaf), "outside leaf dropped setup mapping"
        )
        _check(
            case, leaf.get("realizations"), "outside leaf has no canonical realization"
        )
    notes.append(
        "02: live generate never accepts provider-authored zone/technique on "
        "external_precondition leaves; compiler canonicalization is asserted."
    )


def qa_tptc_03(envelopes: list[dict]) -> None:
    """QA-TPTC-03: valid technique formats survive publication."""
    case = "TPTC-03"
    if not envelopes:
        failures.append(f"{case}: no admitted envelope from TPTC-01")
        return
    leaves = _iter_leaves(envelopes[0].get("attack_tree", {}).get("root") or {})
    techniques = [
        leaf.get("technique_id") for leaf in leaves if leaf.get("technique_id")
    ]
    for technique in techniques:
        _check(
            case,
            bool(TECHNIQUE_RE.match(str(technique))),
            f"published technique {technique!r} is not ATLAS/LAAF format",
        )
    notes.append(
        "03: fixture cannot inject AML.T0051 / AML.T0051.001 / S1 / M2 / L3; "
        "published technique IDs are compiler-owned catalog values."
    )


def qa_tptc_04(envelopes: list[dict]) -> None:
    """QA-TPTC-04: inside and crossing steps are not mapped by external leaves."""
    case = "TPTC-04"
    if not envelopes:
        failures.append(f"{case}: no admitted envelope from TPTC-01")
        return
    leaves = _iter_leaves(envelopes[0].get("attack_tree", {}).get("root") or {})
    for leaf in leaves:
        if (leaf.get("action") or {}).get("kind") != "external_precondition":
            continue
        mapped = set(_leaf_step_ids(leaf))
        _check(
            case,
            "reconnaissance" not in mapped and "delivery" not in mapped,
            f"external_precondition leaf mapped non-outside steps {mapped}",
        )
        if not mapped:
            _check(
                case,
                not leaf.get("realizations"),
                "unmapped external leaf has realizations",
            )
            _check(
                case,
                leaf.get("zone") in (None, ""),
                "unmapped external leaf has a zone",
            )
    notes.append(
        "04: live AP-T6-04 has no system.observe step; the suite pins that "
        "crossing reconnaissance/delivery are not mapped by external_precondition."
    )


def qa_tptc_05(envelopes: list[dict], completed: subprocess.CompletedProcess) -> None:
    """QA-TPTC-05: unknown semantic identity cannot be published."""
    case = "TPTC-05"
    if not envelopes:
        failures.append(f"{case}: no admitted envelope from TPTC-01")
        return
    leaves = _iter_leaves(envelopes[0].get("attack_tree", {}).get("root") or {})
    mapped = [step_id for leaf in leaves for step_id in _leaf_step_ids(leaf)]
    _check(case, "step.unknown" not in mapped, "admitted tree mapped step.unknown")
    _check(
        case,
        "step.unknown" not in completed.stderr,
        "unknown-identity diagnostic appeared on a successful admission",
    )
    notes.append(
        "05: handle-only AttackTreeDraftV3 cannot inject step.unknown; "
        "unknown-identity rejection remains a unit/acceptance contract, not a "
        "live generate injection."
    )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        envelopes = qa_tptc_01(server)
        print("  [done] qa_tptc_01", flush=True)
        qa_tptc_02(envelopes)
        print("  [done] qa_tptc_02", flush=True)
        qa_tptc_03(envelopes)
        print("  [done] qa_tptc_03", flush=True)
        qa_tptc_04(envelopes)
        print("  [done] qa_tptc_04", flush=True)
        stdout = ""
        if envelopes:
            capture = RUN_ROOT / "captures" / "TPTC-01" / "stdout.txt"
            stderr_path = RUN_ROOT / "captures" / "TPTC-01" / "stderr.txt"
            stdout = capture.read_text(encoding="utf-8") if capture.exists() else ""
            stderr = (
                stderr_path.read_text(encoding="utf-8") if stderr_path.exists() else ""
            )
            qa_tptc_05(envelopes, subprocess.CompletedProcess([], 0, stdout, stderr))
        print("  [done] qa_tptc_05", flush=True)
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
    / "qa-taxonomy-projection-traceability"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Executable end-to-end QA suite for taxonomy candidate-filter quarantine.

Mirrors ``candidate_filter_quarantine.md`` (QA-TCFQ-01..03).  Drives only
``asago-scenario-generator generate`` against a deterministic loopback
OpenAI-compatible fixture and inspects CLI output, ``calls.jsonl``,
``run-manifest.yaml``, and admitted scenario YAML.  Never imports project
modules and never sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Pinned live generate contract (reported, not silently bent)
  1. Live generate requests ``FilterMapDraftV3`` with exact ``cN`` keys and
     ``extra=forbid``.  Canonical ``cand:v2:...`` IDs never cross the
     provider wire, so the procedure's unknown ID
     ``cand:v2:ffffffffffffffffffffffffffffffff`` cannot be injected as a
     reconciled identity.  Schema-invalid filter JSON (empty object) is
     the public-UI defect that forces the bounded retry.
  2. ``generate`` calls the filter with ``advisory_on_failure=True``, not
     ``quarantine_on_failure``.  An irreconcilable seed is retried once,
     then every rule-eligible candidate is retained with a
     ``candidate_filter_unavailable`` call-log warning.  No
     ``candidate-filter-quarantine.json`` is published.  CLI
     ``Candidates quarantined`` stays 0.
  3. That warning is a declared authoritative note, so the manifest is
     ``completed_with_warnings``.  With at least one admitted candidate
     the CLI exit is 0 (``completed_with_errors`` or zero admitted is the
     nonzero contract).  Procedure QA-TCFQ-02 expected a quarantined seed
     and a default nonzero exit; those are unit/acceptance contracts for
     ``quarantine_on_failure``, not live generate.
  4. QA-TCFQ-03's expected/received/missing/unknown ``cand:v2`` evidence
     is not a public generate surface under advisory failure.  The suite
     asserts two failed filter attempts, no quarantine bundle, and that
     the unknown ID is not admitted.
  5. AP-T1-01 reaches the filter on an indirect ``document-ingest``
     candidate (AML.T0070).  Authoritative projection then rejects that
     filtered seed for no exact ingress match, so AP-T1-01 does not
     publish a scenario.  AP-T2-01 is the admitted sibling.

Run with::

    uv run python acceptance/qa/taxonomy_risk/candidate_filter_quarantine.py

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
BASE_CARD = "atlas-prompt-injection"
MEMORY_CARD = "atlas-memory-poisoning"
_CARD_TEXT = {
    "threat": "An attacker submits crafted input to influence the AI assistant.",
    "vulnerability": "Instruction-data confusion.",
    "consequence": "The agent follows attacker instructions.",
    "impact": "Unauthorized behavior.",
}
AP_T1_01_NAME = "Persistent memory rule injection"
AP_T2_01_NAME = "Parameter pollution via function-call manipulation"
UNKNOWN_ID = "cand:v2:ffffffffffffffffffffffffffffffff"
FILTER_RE = re.compile(r"\*\*Candidate handle:\*\* `(c\d+)`")
ACTOR_CHOICE_RE = re.compile(r"^- (ac\d+): actor=([^;]+); capability=(.+)$", re.M)
PROSE = "Deterministic QA fixture prose with sufficient detail."


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


def _pattern_name(user_prompt: str) -> str:
    match = re.search(r"\*\*Name:\*\* ([^\n]+)", user_prompt)
    return match.group(1).strip() if match else "?"


def _valid_filter_map(handles: list[str], *, accept_first: bool) -> str:
    return json.dumps(
        {
            handle: {
                "relevant": accept_first and i == 0,
                "rationale": "Deterministic QA fixture verdict.",
            }
            for i, handle in enumerate(handles)
        }
    )


class FixtureHandler(BaseHTTPRequestHandler):
    """Deterministic drafts; optional schema-invalid filter attempts."""

    protocol_version = "HTTP/1.1"
    requests: list[dict] = []
    filter_attempts: dict[str, int] = {}
    filter_mode = "retry"

    @staticmethod
    def reset(mode: str = "retry") -> None:
        FixtureHandler.requests = []
        FixtureHandler.filter_attempts = {}
        FixtureHandler.filter_mode = mode

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
        pattern_name = _pattern_name(user_prompt)
        FixtureHandler.requests.append(
            {
                "schema": schema,
                "user_prompt": user_prompt,
                "pattern_name": pattern_name,
            }
        )

        if schema.startswith("FilterMapDraftV3For"):
            content = self._filter_content(user_prompt, pattern_name)
            if content is None:
                self.send_error(500)
                return
        elif schema.startswith("ActorDraftV3For"):
            content = _actor_content(user_prompt)
            if content is None:
                self.send_error(500)
                return
        elif schema.startswith("NarrativeDraftV3For"):
            content = _narrative_content(user_prompt)
            if content is None:
                self.send_error(500)
                return
        elif schema.startswith("BehaviorDraftV2For"):
            content = _behavior_content(user_prompt)
            if content is None:
                self.send_error(500)
                return
        elif schema.startswith("AttackTreeDraftV3For"):
            content = _tree_content(user_prompt)
            if content is None:
                self.send_error(500)
                return
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

    def _filter_content(self, user_prompt: str, pattern_name: str) -> str | None:
        handles = FILTER_RE.findall(user_prompt)
        if not handles:
            return None
        attempt = FixtureHandler.filter_attempts.get(pattern_name, 0) + 1
        FixtureHandler.filter_attempts[pattern_name] = attempt
        accept_first = pattern_name in {AP_T1_01_NAME, AP_T2_01_NAME}
        if pattern_name == AP_T1_01_NAME:
            if FixtureHandler.filter_mode == "retry" and attempt == 1:
                return "{}"
            if FixtureHandler.filter_mode == "irreconcilable":
                return "{}"
        return _valid_filter_map(handles, accept_first=accept_first)


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


def _write_inputs(ws: Path) -> None:
    risks = [
        {
            "risk_id": MEMORY_CARD,
            "risk_name": "Memory poisoning",
            "risk_description": "Risk description for atlas-memory-poisoning",
            "taxonomy": "ibm-risk-atlas",
            "confidence": 0.99,
            "grounding_confidence": "high",
            **_CARD_TEXT,
        },
        {
            "risk_id": BASE_CARD,
            "risk_name": "Prompt injection",
            "risk_description": "Risk description for atlas-prompt-injection",
            "taxonomy": "ibm-risk-atlas",
            "confidence": 0.99,
            "grounding_confidence": "high",
            **_CARD_TEXT,
        },
    ]
    (ws / "risk-extraction.json").write_text(
        json.dumps({"risks": risks}) + "\n", encoding="utf-8"
    )
    rows = [
        f"{MEMORY_CARD}\tibm-risk-atlas\tskos:relatedMatch\tllm04-vulnerable-plugin-design"
        "\towasp-llm\tsemapv:ManualMappingCuration",
        f"{BASE_CARD}\tibm-risk-atlas\tskos:relatedMatch\tllm06-excessive-agency"
        "\towasp-llm\tsemapv:ManualMappingCuration",
    ]
    (ws / "risk-to-llm.sssom.tsv").write_text(
        "subject_id\tsubject_source\tpredicate_id\tobject_id"
        "\tobject_source\tmapping_justification\n" + "\n".join(rows) + "\n",
        encoding="utf-8",
    )
    cross = {
        "t_to_llm": [
            {"source": "T1", "target": "LLM04"},
            {"source": "T2", "target": "LLM06"},
        ],
        "t_to_atlas": [
            {"source": "T1", "targets": ["AML.T0070"]},
            {"source": "T2", "targets": ["AML.T0053"]},
        ],
        "t_to_asi": [],
        "t_direct": [],
    }
    (ws / "cross-taxonomy-mappings.yaml").write_text(
        yaml.safe_dump(cross, sort_keys=False), encoding="utf-8"
    )
    profile = {
        "zones_active": ["input", "reasoning", "memory", "tool_execution"],
        "entry_points": [
            {"name": "chat", "direction": "input", "controllability": "direct"},
            {
                "name": "document-ingest",
                "direction": "input",
                "controllability": "indirect",
            },
        ],
        "confidence": "high",
        "kc_subcodes": ["KC4.3", "KC6.4", "KCX-PMEM"],
        "entry_point_completeness": "operator_confirmed_complete",
        "entry_point_evidence": ["Deterministic QA fixture review"],
        "memory_mechanisms": [
            {
                "type": "vector_store",
                "scope": "shared",
                "persistence": "long_term",
                "writable_by_agent": True,
            }
        ],
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
        json.dumps(
            [
                {
                    "schema": item["schema"],
                    "pattern_name": item["pattern_name"],
                    "prompt_len": len(item["user_prompt"]),
                }
                for item in FixtureHandler.requests
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return completed


def _generate(
    case: str, server: ThreadingHTTPServer, *, mode: str
) -> tuple[subprocess.CompletedProcess, Path | None]:
    ws = _new_workspace(case)
    FixtureHandler.reset(mode)
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
        "--max-scenarios-per-pattern",
        "1",
        "--generation-mode",
        "exhaustive",
    ]
    completed = _run_cli(case, argv, env=env)
    runs = sorted(path for path in (ws / "output").glob("*") if path.is_dir())
    return completed, runs[-1] if runs else None


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def _load_manifest(run_dir: Path | None) -> dict:
    if run_dir is None:
        return {}
    path = run_dir / "run-manifest.yaml"
    if not path.exists():
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _filter_requests(pattern_name: str) -> list[dict]:
    return [
        item
        for item in FixtureHandler.requests
        if item["schema"].startswith("FilterMapDraftV3For")
        and item["pattern_name"] == pattern_name
    ]


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if isinstance(payload, dict):
            entries.append(payload)
    return entries


def _filter_call_logs(run_dir: Path | None) -> list[dict]:
    if run_dir is None:
        return []
    return [
        item
        for item in _read_jsonl(run_dir / "calls.jsonl")
        if item.get("call") == "candidate_filter"
    ]


def _admitted_envelopes(run_dir: Path | None) -> list[dict]:
    if run_dir is None:
        return []
    scenarios = run_dir / "scenarios"
    if not scenarios.is_dir():
        return []
    envelopes = []
    for path in sorted(scenarios.glob("*.yaml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            envelopes.append(payload)
    return envelopes


def _seed_ids(envelopes: list[dict]) -> set[str]:
    seeds: set[str] = set()
    for envelope in envelopes:
        metadata = envelope.get("scenario_seed_metadata") or {}
        seed_id = metadata.get("seed_id")
        if seed_id:
            seeds.add(str(seed_id))
    return seeds


def _candidate_ids(envelopes: list[dict]) -> set[str]:
    return {
        str(envelope.get("candidate_id"))
        for envelope in envelopes
        if envelope.get("candidate_id")
    }


def _summary_int(stdout: str, label: str) -> int | None:
    match = re.search(rf"{re.escape(label)}:\s+(\d+)", stdout)
    return int(match.group(1)) if match else None


def _assert_no_unknown_id(
    case: str, envelopes: list[dict], run_dir: Path | None
) -> None:
    admitted = _candidate_ids(envelopes)
    _check(
        case,
        UNKNOWN_ID not in admitted,
        f"unknown identity {UNKNOWN_ID} was admitted",
    )
    if run_dir is None:
        return
    for path in run_dir.rglob("*"):
        if not path.is_file() or path.suffix not in {
            ".yaml",
            ".yml",
            ".json",
            ".jsonl",
        }:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        _check(
            case,
            UNKNOWN_ID not in text,
            f"{path.relative_to(run_dir)} contains {UNKNOWN_ID}",
        )


def qa_tcfq_01(server: ThreadingHTTPServer) -> None:
    """QA-TCFQ-01: corrected retry succeeds; no seed is quarantined."""
    case = "TCFQ-01"
    completed, run_dir = _generate(case, server, mode="retry")
    _check(
        case,
        completed.returncode == 0,
        f"expected exit 0, got {completed.returncode}",
    )
    t1_filters = _filter_requests(AP_T1_01_NAME)
    t2_filters = _filter_requests(AP_T2_01_NAME)
    _check(
        case,
        len(t1_filters) == 2,
        f"AP-T1-01 filter attempts {len(t1_filters)} != 2",
    )
    _check(
        case,
        len(t2_filters) == 1,
        f"AP-T2-01 filter attempts {len(t2_filters)} != 1",
    )
    logs = _filter_call_logs(run_dir)
    t1_logs = [item for item in logs if item.get("seed_id") == "AP-T1-01"]
    t2_logs = [item for item in logs if item.get("seed_id") == "AP-T2-01"]
    t1_attempts = [item.get("attempt") for item in t1_logs if "attempt" in item]
    t2_attempts = [item.get("attempt") for item in t2_logs if "attempt" in item]
    _check(case, t1_attempts == [1, 2], f"AP-T1-01 call-log attempts {t1_attempts}")
    _check(case, t2_attempts == [1], f"AP-T2-01 call-log attempts {t2_attempts}")
    _check(
        case,
        not any(item.get("warning") == "candidate_filter_unavailable" for item in logs),
        "retry success recorded candidate_filter_unavailable",
    )
    envelopes = _admitted_envelopes(run_dir)
    seeds = _seed_ids(envelopes)
    _check(case, envelopes, "no admitted scenario YAML")
    _check(
        case,
        "AP-T2-01" in seeds,
        f"AP-T2-01 did not contribute admitted artifacts; seeds={sorted(seeds)}",
    )
    _check(
        case,
        "AP-T1-01" not in seeds,
        f"AP-T1-01 reached admission after projection drop; seeds={sorted(seeds)}",
    )
    _check(
        case,
        "Seed AP-T1-01: 1/1 candidates accepted" in completed.stderr,
        "retry did not accept AP-T1-01 at the filter",
    )
    quarantined = _summary_int(completed.stdout, "Candidates quarantined")
    _check(case, quarantined == 0, f"Candidates quarantined {quarantined} != 0")
    manifest = _load_manifest(run_dir)
    _check(
        case,
        manifest.get("status") == "completed",
        f"manifest status {manifest.get('status')!r}",
    )
    _check(
        case,
        run_dir is None or not (run_dir / "candidate-filter-quarantine.json").exists(),
        "quarantine evidence published after a successful retry",
    )
    _assert_no_unknown_id(case, envelopes, run_dir)
    notes.append(
        "01: live FilterMapDraftV3 cannot carry cand:v2 unknown IDs; the "
        "first AP-T1-01 attempt is schema-invalid JSON, the retry reconciles. "
        "Projection then drops AP-T1-01 for no exact ingress match."
    )


def qa_tcfq_02(server: ThreadingHTTPServer) -> None:
    """QA-TCFQ-02: irreconcilable seed is advisory, not quarantined."""
    case = "TCFQ-02"
    completed, run_dir = _generate(case, server, mode="irreconcilable")
    t1_filters = _filter_requests(AP_T1_01_NAME)
    t2_filters = _filter_requests(AP_T2_01_NAME)
    _check(
        case,
        len(t1_filters) == 2,
        f"AP-T1-01 filter attempts {len(t1_filters)} != 2",
    )
    _check(
        case,
        len(t2_filters) == 1,
        f"AP-T2-01 filter attempts {len(t2_filters)} != 1",
    )
    logs = _filter_call_logs(run_dir)
    t1_logs = [item for item in logs if item.get("seed_id") == "AP-T1-01"]
    t1_attempts = [item.get("attempt") for item in t1_logs if "attempt" in item]
    _check(case, t1_attempts == [1, 2], f"AP-T1-01 call-log attempts {t1_attempts}")
    _check(
        case,
        any(
            item.get("seed_id") == "AP-T1-01"
            and item.get("warning") == "candidate_filter_unavailable"
            for item in logs
        ),
        "missing candidate_filter_unavailable warning for AP-T1-01",
    )
    _check(
        case,
        run_dir is None or not (run_dir / "candidate-filter-quarantine.json").exists(),
        "live generate published candidate-filter-quarantine.json",
    )
    envelopes = _admitted_envelopes(run_dir)
    seeds = _seed_ids(envelopes)
    _check(
        case,
        "AP-T2-01" in seeds,
        f"AP-T2-01 missing from admitted seeds {sorted(seeds)}",
    )
    _check(
        case,
        "AP-T1-01" not in seeds,
        f"projection-dropped AP-T1-01 reached admission; seeds={sorted(seeds)}",
    )
    quarantined = _summary_int(completed.stdout, "Candidates quarantined")
    _check(case, quarantined == 0, f"Candidates quarantined {quarantined} != 0")
    manifest = _load_manifest(run_dir)
    status = manifest.get("status")
    _check(
        case, status != "failed", f"run failed by the irreconcilable seed: {status!r}"
    )
    _check(
        case,
        status == "completed_with_warnings",
        f"manifest status {status!r} != completed_with_warnings",
    )
    _check(
        case,
        completed.returncode == 0,
        f"live advisory+admitted contract is exit 0, got {completed.returncode}",
    )
    _assert_no_unknown_id(case, envelopes, run_dir)
    notes.append(
        "02: live generate uses advisory_on_failure, so AP-T1-01 is not "
        "quarantined after two failed attempts; rule-eligible candidates "
        "continue and Candidates quarantined stays 0. Procedure expected "
        "seed quarantine and a default nonzero exit. Authoritative "
        "projection still drops AP-T1-01 for no exact ingress match."
    )


def qa_tcfq_03(server: ThreadingHTTPServer) -> None:
    """QA-TCFQ-03: advisory failure does not publish cand:v2 set arithmetic."""
    case = "TCFQ-03"
    completed, run_dir = _generate(case, server, mode="irreconcilable")
    t1_filters = _filter_requests(AP_T1_01_NAME)
    _check(
        case,
        len(t1_filters) == 2,
        f"AP-T1-01 filter attempts {len(t1_filters)} != 2",
    )
    logs = _filter_call_logs(run_dir)
    t1_logs = [item for item in logs if item.get("seed_id") == "AP-T1-01"]
    _check(case, any(item.get("attempt") == 2 for item in t1_logs), "missing attempt 2")
    _check(
        case,
        run_dir is None or not (run_dir / "candidate-filter-quarantine.json").exists(),
        "quarantine evidence published under advisory failure",
    )
    combined = completed.stdout + completed.stderr
    for identity in (
        "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        UNKNOWN_ID,
    ):
        _check(
            case,
            identity not in combined,
            f"CLI summary unexpectedly recorded {identity}",
        )
    envelopes = _admitted_envelopes(run_dir)
    _assert_no_unknown_id(case, envelopes, run_dir)
    notes.append(
        "03: FilterMapDraftV3 extra=forbid plus advisory_on_failure means "
        "expected/received/missing/unknown cand:v2 sets are not a public "
        "generate surface. The suite pins two failed attempts and that "
        "received metadata cannot create an admitted identity."
    )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        qa_tcfq_01(server)
        print("  [done] qa_tcfq_01", flush=True)
        qa_tcfq_02(server)
        print("  [done] qa_tcfq_02", flush=True)
        qa_tcfq_03(server)
        print("  [done] qa_tcfq_03", flush=True)
    finally:
        server.shutdown()
        server.server_close()

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
    / "qa-taxonomy-candidate-filter-quarantine"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

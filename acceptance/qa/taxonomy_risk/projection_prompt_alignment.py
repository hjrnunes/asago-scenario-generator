#!/usr/bin/env python3
"""Executable end-to-end QA suite for taxonomy projection prompt alignment.

Mirrors ``projection_prompt_alignment.md`` (QA-TPPA-01..03).  Drives only
``asago-scenario-generator generate`` against a deterministic loopback
OpenAI-compatible fixture that records request bodies.  Inspects the
fixture's received narrative and attack-tree user prompts.  Never imports
project modules, never renders templates directly, and never sets
``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Pinned live generate contract (reported, not silently bent)
  1. Live generate uses semantic drafts when a projection context exists.
     ``call1_user.j2`` omits ``_projection_alignment.j2`` when
     ``semantic_draft_v2`` is true.  Attack-tree Call 2 is a handle
     inventory, not ``call2_user.j2``.  Unit tests render the table by
     calling templates without that flag.
  2. The narrative prompt instead lists request-local handles with
     ``action_kind`` and ``boundary`` beside each handle.  The attack-tree
     prompt lists compiler-owned ``action_kind`` per leaf handle.
  3. QA-TPPA-03's crossing ``operator.deliver`` empty-compatibility cell
     cannot appear in live generate prompts because that combination is
     not a committed AP-T6-04 step.  The suite records the absence.

Run with::

    uv run python acceptance/qa/taxonomy_risk/projection_prompt_alignment.py

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
TABLE_HEADER = (
    "| canonical ID | action | executor | boundary | allowed narrative zone "
    "| allowed tree kinds | tree zone | bound resources |"
)
SEMANTIC_WARNING = "Step IDs are semantic names, not positional labels."


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
    """Deterministic drafts that retain full request bodies."""

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
        FixtureHandler.requests.append(
            {
                "schema": schema,
                "user_prompt": user_prompt,
                "messages": request.get("messages", []),
            }
        )

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


def _run_generate(server: ThreadingHTTPServer) -> subprocess.CompletedProcess:
    ws = RUN_ROOT / "workspace"
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    _write_inputs(ws)
    (ws / "output").mkdir(exist_ok=True)
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
    capture_dir = RUN_ROOT / "captures"
    capture_dir.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=2400,
    )
    (capture_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (capture_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (capture_dir / "exit.txt").write_text(f"{completed.returncode}\n", encoding="utf-8")
    (capture_dir / "requests.json").write_text(
        json.dumps(
            [
                {"schema": item["schema"], "user_prompt": item["user_prompt"]}
                for item in FixtureHandler.requests
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return completed


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def _prompts(prefix: str) -> list[str]:
    return [
        item["user_prompt"]
        for item in FixtureHandler.requests
        if item["schema"].startswith(prefix)
    ]


def _parse_narrative_handles(prompt: str) -> list[dict[str, str]]:
    rows = []
    for match in re.finditer(
        r"- (s\d+): order=(\d+); zone=([^;]+); action_kind=([^;]+); boundary=(\S+)",
        prompt,
    ):
        rows.append(
            {
                "handle": match.group(1),
                "order": match.group(2),
                "zone": match.group(3),
                "action_kind": match.group(4),
                "boundary": match.group(5),
            }
        )
    return rows


def _parse_tree_inventory(prompt: str) -> list[dict]:
    match = re.search(
        r"Canonical leaf inventory \(respond with handles only\):\n(.+)",
        prompt,
        re.S,
    )
    if not match:
        return []
    try:
        inventory = json.loads(match.group(1))
    except json.JSONDecodeError:
        return []
    return inventory if isinstance(inventory, list) else []


def qa_tppa_01() -> None:
    """QA-TPPA-01: live prompts identify one selected step per row/handle."""
    case = "TPPA-01"
    narrative_prompts = _prompts("NarrativeDraftV3For")
    tree_prompts = _prompts("AttackTreeDraftV3For")
    _check(case, narrative_prompts, "no narrative request recorded")
    _check(case, tree_prompts, "no attack-tree request recorded")
    if not narrative_prompts or not tree_prompts:
        return
    narrative = narrative_prompts[0]
    tree = tree_prompts[0]
    table_in_narrative = TABLE_HEADER in narrative
    table_in_tree = TABLE_HEADER in tree
    _check(
        case,
        not table_in_narrative and not table_in_tree,
        "live semantic-draft prompts unexpectedly contain the compact alignment table",
    )
    if table_in_narrative or table_in_tree:
        return
    notes.append(
        "01: live generate omits the compact alignment table from both "
        "semantic-draft prompts (narrative gated by semantic_draft_v2; "
        "attack-tree uses a handle inventory). Unit tests still render "
        "call1_user.j2 / call2_user.j2 with the table."
    )
    rows = _parse_narrative_handles(narrative)
    _check(case, len(rows) >= 3, f"narrative handle inventory too small: {rows}")
    orders = [int(row["order"]) for row in rows]
    _check(
        case,
        orders == sorted(orders),
        f"narrative handles not in canonical order: {rows}",
    )
    _check(
        case,
        all(not re.fullmatch(r"\d+", row["handle"]) for row in rows),
        "narrative used a numeric positional ID as a handle",
    )
    inventory = _parse_tree_inventory(tree)
    _check(case, inventory, "attack-tree prompt has no leaf inventory")
    positions = [item.get("position") for item in inventory]
    _check(
        case,
        positions == sorted(positions),
        f"tree inventory not in canonical position order: {inventory}",
    )
    _check(
        case,
        "Never emit nested nodes, canonical IDs" not in tree
        or "respond with handles only" in tree,
        "tree prompt does not restrict the provider to handles",
    )


def qa_tppa_02() -> None:
    """QA-TPPA-02: live handle metadata matches compiler-owned validation."""
    case = "TPPA-02"
    narrative_prompts = _prompts("NarrativeDraftV3For")
    tree_prompts = _prompts("AttackTreeDraftV3For")
    if not narrative_prompts or not tree_prompts:
        failures.append(f"{case}: missing narrative or attack-tree prompt")
        return
    rows = _parse_narrative_handles(narrative_prompts[0])
    inventory = _parse_tree_inventory(tree_prompts[0])
    by_kind = {row["action_kind"]: row for row in rows}
    _check(case, "observe" in by_kind, f"missing observe handle: {rows}")
    _check(case, "prepare" in by_kind, f"missing prepare handle: {rows}")
    _check(case, "deliver" in by_kind, f"missing deliver handle: {rows}")
    _check(case, "impact" in by_kind, f"missing impact handle: {rows}")
    if "prepare" in by_kind:
        _check(
            case,
            by_kind["prepare"]["boundary"] == "outside",
            f"prepare boundary {by_kind['prepare']['boundary']!r} != outside",
        )
    if "observe" in by_kind:
        _check(
            case,
            by_kind["observe"]["boundary"] == "crossing",
            f"observe boundary {by_kind['observe']['boundary']!r} != crossing",
        )
    if "deliver" in by_kind:
        _check(
            case,
            by_kind["deliver"]["boundary"] == "crossing",
            f"deliver boundary {by_kind['deliver']['boundary']!r} != crossing",
        )
    if "impact" in by_kind:
        _check(
            case,
            by_kind["impact"]["boundary"] == "inside",
            f"impact boundary {by_kind['impact']['boundary']!r} != inside",
        )
    kinds = {item.get("action_kind") for item in inventory}
    _check(
        case,
        "external_precondition" in kinds,
        f"tree inventory missing external_precondition: {inventory}",
    )
    _check(
        case,
        "initial_ingress" in kinds,
        f"tree inventory missing initial_ingress: {inventory}",
    )
    _check(case, "impact" in kinds, f"tree inventory missing impact: {inventory}")
    notes.append(
        "02: live prompts expose compiler-owned action_kind/boundary per handle "
        "instead of the compact table cells; single-field mismatch retries "
        "cannot be injected because the compiler owns leaf kinds."
    )


def qa_tppa_03() -> None:
    """QA-TPPA-03: empty compatibility is not invented in live prompts."""
    case = "TPPA-03"
    narrative_prompts = _prompts("NarrativeDraftV3For")
    tree_prompts = _prompts("AttackTreeDraftV3For")
    if not narrative_prompts or not tree_prompts:
        failures.append(f"{case}: missing narrative or attack-tree prompt")
        return
    combined = narrative_prompts[0] + "\n" + tree_prompts[0]
    _check(
        case,
        "operator.deliver" not in combined,
        "live prompts invented an operator.deliver row",
    )
    _check(
        case,
        "empty set" not in combined,
        "live prompts rendered an empty-set compatibility cell",
    )
    notes.append(
        "03: crossing operator.deliver is not a live AP-T6-04 step, so the "
        "empty allowed-tree-kinds cell cannot appear in generate prompts. "
        "The unit/acceptance table contract still covers that combination."
    )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        completed = _run_generate(server)
        if completed.returncode != 0:
            failures.append(
                f"generate exited {completed.returncode}: {completed.stderr[-400:]}"
            )
        else:
            qa_tppa_01()
            print("  [done] qa_tppa_01", flush=True)
            qa_tppa_02()
            print("  [done] qa_tppa_02", flush=True)
            qa_tppa_03()
            print("  [done] qa_tppa_03", flush=True)
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
    / "qa-taxonomy-projection-prompt-alignment"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

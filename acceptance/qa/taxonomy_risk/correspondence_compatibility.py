#!/usr/bin/env python3
"""Executable end-to-end QA suite for correspondence compatibility.

Mirrors ``correspondence_compatibility.md`` (QA-CC-01..02).  Drives
only the existing public commands ``generate`` and ``stpa-run`` without
correspondence flags.  Uses deterministic local OpenAI-compatible
fixture endpoints or resume-from-fixture inputs, fresh output
collections, and valid offline inputs.  Inspects console output,
published run files, and request logs.  Never imports project modules
and never sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Run with::

    uv run python acceptance/qa/taxonomy_risk/correspondence_compatibility.py

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
    """Deterministic drafts for taxonomy generate plus a request log."""

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
        content = _fixture_content(schema, user_prompt)
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


def _fixture_content(schema: str, user_prompt: str) -> str | None:
    if schema.startswith("Stage1Profile"):
        return json.dumps(
            {
                "entry_points": [
                    {
                        "name": "ze-query",
                        "direction": "input",
                        "controllability": "direct",
                    }
                ],
                "confidence": "high",
                "kc_subcodes": ["KC1.1"],
                "tool_inventory": [],
            }
        )
    if schema.startswith("FilterMapDraftV3For"):
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
    if schema.startswith("ActorDraftV3For"):
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
    if schema.startswith("NarrativeDraftV3For"):
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
    if schema.startswith("BehaviorDraftV2For"):
        return _behavior_content(user_prompt)
    if schema.startswith("AttackTreeDraftV3For"):
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
    return None


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
                "text": f"Deterministic fixture assertion for {assertion['handle']}.",
                "examples": {},
            }
        )
    return json.dumps(
        {"scenarios": [{"title": "Deterministic QA behavior scenario", "steps": steps}]}
    )


def _write_generate_inputs(ws: Path) -> None:
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
    (ws / "use-case.txt").write_text(_USE_CASE + "\n", encoding="utf-8")
    (ws / "output").mkdir(exist_ok=True)


def _new_workspace(case: str) -> Path:
    ws = RUN_ROOT / "workspaces" / case
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    return ws


def _run_cli(
    case: str,
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 2400,
) -> subprocess.CompletedProcess[str]:
    capture_dir = RUN_ROOT / "captures" / case
    capture_dir.mkdir(parents=True, exist_ok=True)
    child = os.environ.copy()
    child.pop(QA_PIPELINE_ENV, None)
    child.pop("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None)
    if env:
        child.update(env)
    completed = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=child,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    (capture_dir / "command.txt").write_text(" ".join(argv) + "\n", encoding="utf-8")
    (capture_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (capture_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (capture_dir / "exit.txt").write_text(f"{completed.returncode}\n", encoding="utf-8")
    return completed


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def _no_correspondence_artifact(case: str, root: Path) -> None:
    found = [
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and (
            "correspondence" in path.name.lower()
            or "proposal-set" in path.name.lower()
            or "reconciliation-result" in path.name.lower()
        )
    ]
    _check(case, not found, f"correspondence artifact added: {found}")


def _file_index(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _generate_argv(ws: Path, server: ThreadingHTTPServer) -> list[str]:
    return [
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


def _run_dir(ws: Path) -> Path | None:
    runs = sorted(path for path in (ws / "output").glob("*") if path.is_dir())
    return runs[-1] if runs else None


def _count_line(stdout: str, label: str) -> str | None:
    match = re.search(rf"{label}:\s+(\S+)", stdout)
    return match.group(1) if match else None


def qa_cc_01(server: ThreadingHTTPServer) -> None:
    """QA-CC-01: default taxonomy generate outputs are unchanged."""
    case = "CC-01"
    help_run = _run_cli(f"{case}-help", [*_command(), "generate", "--help"], timeout=60)
    _check(case, help_run.returncode == 0, "generate --help failed")
    _check(
        case,
        "correspondence" not in help_run.stdout.lower(),
        "generate --help grew correspondence flags",
    )
    captured: list[tuple[Path, subprocess.CompletedProcess[str], list[dict]]] = []
    for label in ("fixture", "live"):
        ws = _new_workspace(f"{case}-{label}")
        _write_generate_inputs(ws)
        FixtureHandler.reset()
        os.environ["ACCEPT_PATTERN"] = ACCEPT_AP_T6_04
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = "0"
        env.pop(QA_PIPELINE_ENV, None)
        completed = _run_cli(
            f"{case}-{label}",
            _generate_argv(ws, server),
            env=env,
        )
        run_dir = _run_dir(ws)
        if completed.returncode != 0 or run_dir is None:
            failures.append(
                f"{case}-{label}: generate exited {completed.returncode}: "
                f"{completed.stderr[-400:]!r}"
            )
            return
        captured.append((run_dir, completed, list(FixtureHandler.requests)))
        _no_correspondence_artifact(f"{case}-{label}", run_dir)
    (fixture_dir, fixture_cli, fixture_reqs), (live_dir, live_cli, live_reqs) = captured
    fixture_features = sorted(
        path.read_bytes() for path in fixture_dir.rglob("*.feature")
    )
    live_features = sorted(path.read_bytes() for path in live_dir.rglob("*.feature"))
    _check(
        case,
        fixture_features == live_features,
        ".feature contents drifted from fixture",
    )
    fixture_roles = sorted(
        path.name
        for path in fixture_dir.rglob("*")
        if path.is_file() and not path.name.startswith("scenario:")
    )
    live_roles = sorted(
        path.name
        for path in live_dir.rglob("*")
        if path.is_file() and not path.name.startswith("scenario:")
    )
    _check(
        case,
        fixture_roles == live_roles,
        f"run artifact roles drifted: {fixture_roles} vs {live_roles}",
    )
    _check(
        case,
        len(list(fixture_dir.rglob("*.feature")))
        == len(list(live_dir.rglob("*.feature"))),
        "feature file count drifted",
    )
    _check(
        case,
        len([p for p in fixture_dir.rglob("*.yaml") if p.name.startswith("scenario:")])
        == len([p for p in live_dir.rglob("*.yaml") if p.name.startswith("scenario:")]),
        "scenario YAML count drifted",
    )
    for label in (
        "Candidates admitted",
        "Candidates quarantined",
        "Candidates failed",
        "Scenarios generated",
        "Governance-only",
    ):
        _check(
            case,
            _count_line(fixture_cli.stdout, label)
            == _count_line(live_cli.stdout, label),
            f"{label} drifted from fixture",
        )
    fixture_schemas = [item["schema"] for item in fixture_reqs]
    live_schemas = [item["schema"] for item in live_reqs]
    _check(
        case,
        fixture_schemas == live_schemas,
        f"provider schemas drifted: {fixture_schemas} vs {live_schemas}",
    )
    notes.append(
        "01: successive generate runs mint distinct scenario:v2 hashes; "
        "the suite compares feature text, artifact roles, counts, and request schemas."
    )
    notes.append(f"01: compared fixture {fixture_dir.name} to live {live_dir.name}")


def _write_stpa_fixture(ws: Path) -> None:
    (ws / "use-case.txt").write_text("My agentic system use case\n", encoding="utf-8")
    (ws / "risk-extraction.json").write_text(
        json.dumps(
            {
                "risks": [
                    {
                        "risk_id": "atlas-001",
                        "risk_name": "Risk 1",
                        "risk_description": "Description 1",
                        "taxonomy": "ibm-risk-atlas",
                        "confidence": 0.9,
                        "grounding_confidence": "high",
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = ws / "output"
    out.mkdir()
    (out / "loss-analysis.yaml").write_text(
        """\
risk_card_losses: []
use_case_losses:
- loss_id: L-1
  description: Loss
  provenance: use_case
hazards:
- hazard_id: H-1
  description: Hazard
  related_losses:
  - L-1
security_constraints:
- constraint_id: SC-1
  description: Constraint
  related_hazards:
  - H-1
""",
        encoding="utf-8",
    )
    (out / "capability-profile.yaml").write_text(
        """\
zones_active:
- input
entry_points:
- name: chat
  direction: input
  controllability: direct
confidence: medium
kc_subcodes:
- KC1.1
tool_inventory:
- name: test-tool
  description: A test tool
""",
        encoding="utf-8",
    )
    (out / "control-structure.yaml").write_text(
        """\
responsibilities:
- resp_id: RESP-1
  description: Controller
  process_model_parts:
  - pm_id: PM-1-1
    description: State
  control_actions:
  - ca_id: CA-1-1
    description: Action
  feedback_channels:
  - fb_id: FB-1-1
    description: Feedback
    updates: PM-1-1
    source:
      type: responsibility
      id: RESP-1
""",
        encoding="utf-8",
    )
    (out / "ica-enumeration.yaml").write_text("slots: []\n", encoding="utf-8")
    (out / "enriched-threats.yaml").write_text(
        """\
structural_threats:
- ica_slot_id: RESP-1:CA-1-1:NOT_PROVIDED
  provenance: structural
  ica_id: RESP-1:CA-1-1:NOT_PROVIDED:1
  ica_text: ICA text
  hazardous_context: Context
  loss_scenario: Scenario
  related_hazards:
  - H-1
  related_constraints:
  - SC-1
coverage_analysis:
  structural_coverage:
    total_slots: 1
    non_na: 1
    na: 0
    coverage_rate: 1.0
""",
        encoding="utf-8",
    )
    scenarios = out / "scenarios"
    scenarios.mkdir()
    (scenarios / "scenario-001.yaml").write_text("dummy: true\n", encoding="utf-8")
    (scenarios / "scenario-001.feature").write_text(
        "Feature: Test\n  Scenario: Test\n    Then pass\n",
        encoding="utf-8",
    )
    (out / "eval-scorecard.yaml").write_text(
        "metrics:\n  consistency:\n    rate: 1.0\n", encoding="utf-8"
    )
    (out / "coverage-gaps.json").write_text("{}\n", encoding="utf-8")
    (out / "run-manifest.yaml").write_text(
        "run_id: fixture-stpa\nscenario_count: 1\n", encoding="utf-8"
    )


def qa_cc_02() -> None:
    """QA-CC-02: default STPA stpa-run outputs are unchanged."""
    case = "CC-02"
    help_run = _run_cli(f"{case}-help", [*_command(), "stpa-run", "--help"], timeout=60)
    _check(case, help_run.returncode == 0, "stpa-run --help failed")
    _check(
        case,
        "correspondence" not in help_run.stdout.lower(),
        "stpa-run --help grew correspondence flags",
    )
    captured: list[tuple[Path, dict[str, str]]] = []
    for label in ("fixture", "live"):
        ws = _new_workspace(f"{case}-{label}")
        _write_stpa_fixture(ws)
        before = _file_index(ws / "output")
        argv = [
            *_command(),
            "stpa-run",
            "--use-case",
            str(ws / "use-case.txt"),
            "--risk-extraction",
            str(ws / "risk-extraction.json"),
            "--output-dir",
            str(ws / "output"),
            "--resume",
        ]
        completed = _run_cli(f"{case}-{label}", argv, timeout=180)
        if completed.returncode != 0:
            failures.append(
                f"{case}-{label}: stpa-run exited {completed.returncode}: "
                f"{completed.stderr[-400:]!r}"
            )
            return
        _no_correspondence_artifact(f"{case}-{label}", ws / "output")
        after = _file_index(ws / "output")
        for name in (
            "loss-analysis.yaml",
            "control-structure.yaml",
            "ica-enumeration.yaml",
            "enriched-threats.yaml",
            "scenario-001.yaml",
            "scenario-001.feature",
        ):
            matches = [
                digest for rel, digest in after.items() if Path(rel).name == name
            ]
            before_matches = [
                digest for rel, digest in before.items() if Path(rel).name == name
            ]
            _check(
                f"{case}-{label}",
                matches == before_matches,
                f"{name} changed during resume",
            )
        captured.append((ws / "output", after))
    (_fixture_out, fixture_index), (_live_out, live_index) = captured
    fixture_names = {Path(rel).name for rel in fixture_index}
    live_names = {Path(rel).name for rel in live_index}
    _check(
        case,
        fixture_names == live_names,
        f"STPA artifact names drifted: {sorted(fixture_names ^ live_names)}",
    )
    notes.append("02: resume fixture compared without correspondence flags")


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        qa_cc_01(server)
        print("  [done] qa_cc_01", flush=True)
        qa_cc_02()
        print("  [done] qa_cc_02", flush=True)
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
    / "qa-taxonomy-correspondence-compatibility"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

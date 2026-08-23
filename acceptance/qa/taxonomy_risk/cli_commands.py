#!/usr/bin/env python3
"""Executable end-to-end QA suite for the taxonomy/risk CLI command contracts.

Mirrors ``cli_commands.md`` (QA-TCLC-01..15).  Drives only the public
``asago-scenario-generator`` commands (``generate``,
``projection-preflight``, ``report``, ``eval``, ``profile``,
``validate-catalog-qualification``) and inspects CLI stdout, stderr, exit
status, and published artifacts.  Never imports project modules, never
calls ``run_pipeline`` / ``run_profile_only`` / ``run_projection_preflight``
/ ``run_evaluation`` / ``generate_report`` or any other project API, and
never sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Offline except for one deterministic loopback OpenAI-compatible fixture
endpoint on 127.0.0.1 (ephemeral port) that serves stage drafts for
``generate`` and a Stage1 capability profile for ``profile``; every other
case touches no network surface.  Fixtures live in a fresh disposable
workspace (one ``mktemp``-style directory per case) below
``tmp/qa-taxonomy-cli-commands/``.

Pinned fixture contract: ``report`` (QA-TCLC-09/10) and ``eval``
(QA-TCLC-11/12) require an authoritative ``completed`` manifest-v3 run
whose inventory hashes match its artifacts and whose coverage-plan,
finalization-inventory, planning-checkpoint, and capability-profile
entries reconcile.  Such a run cannot be obtained without importing the
project's finalization machinery, so the suite produces the fixture by
driving the public ``generate`` CLI against the deterministic loopback
endpoint (the same pattern the threat-surface-derivation suite uses).
The run is then treated as immutable evidence: report/eval must not
modify it (byte-for-byte comparison).

Run with::

    uv run python acceptance/qa/taxonomy_risk/cli_commands.py

Exit status is 0 only when every pinned assertion passes.  Set
``QA_SKIP_GATES=1`` to iterate on the CLI cases without rerunning the
repository gate sequence (QA-TCLC-15).
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


def _command() -> list[str]:
    """Resolve the CLI launcher (uv run, falling back to the venv binary)."""
    if shutil.which("uv", path=_SEARCH_PATH):
        return [_UV, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv" / "bin" / "asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


# ---------------------------------------------------------------------------
# LLM fixture: deterministic loopback OpenAI-compatible endpoint
# ---------------------------------------------------------------------------

PROSE = "Deterministic QA fixture prose with sufficient detail."
FILTER_RE = re.compile(r"\*\*Candidate handle:\*\* `(c\d+)`")
ACTOR_CHOICE_RE = re.compile(r"^- (ac\d+): actor=([^;]+); capability=(.+)$", re.M)
REGION_RE = re.compile(r"^- (r\d+):$", re.M)


def _schema_name(request: dict) -> str:
    response_format = request.get("response_format") or {}
    return str((response_format.get("json_schema") or {}).get("name", ""))


class FixtureHandler(BaseHTTPRequestHandler):
    """Deterministic drafts for every generation stage plus stage 1."""

    protocol_version = "HTTP/1.1"
    accepted_once = False
    request_log: Path | None = None

    def reset() -> None:  # noqa: N805
        FixtureHandler.accepted_once = False

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
        model = str(request.get("model", "qa-fixture"))
        if FixtureHandler.request_log is not None:
            with FixtureHandler.request_log.open("a", encoding="utf-8") as log:
                log.write(
                    json.dumps(
                        {
                            "schema": schema,
                            "model": model,
                            "user_prompt_excerpt": user_prompt[:200],
                        }
                    )
                    + "\n"
                )

        if schema.startswith("Stage1Profile"):
            content = json.dumps(
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
        elif schema.startswith("FilterMapDraftV3For"):
            handles = FILTER_RE.findall(user_prompt)
            if not handles:
                self.send_error(500)
                return
            accept_index = int(os.environ.get("ACCEPT_INDEX", "0"))
            accept_pattern = os.environ.get("ACCEPT_PATTERN", "")
            name_match = re.search(r"\*\*Name:\*\* ([^\n]+)", user_prompt)
            pattern_name = name_match.group(1) if name_match else "?"
            matches = not accept_pattern or pattern_name == accept_pattern
            accepted = matches and not FixtureHandler.accepted_once
            if matches:
                FixtureHandler.accepted_once = True
            body_map = {}
            for i, handle in enumerate(handles):
                body_map[handle] = {
                    "relevant": accepted and i == accept_index,
                    "rationale": "Deterministic QA fixture verdict.",
                }
            content = json.dumps(body_map)
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
            regions_body = {}
            for region, handles in region_map.items():
                regions_body[region] = [
                    {
                        "step_handles": [handle],
                        "action": f"Deterministic action for {handle}",
                        "consequence": f"Deterministic consequence for {handle}",
                        "transition": None,
                    }
                    for handle in handles
                ]
            content = json.dumps(
                {
                    "title": "Deterministic QA narrative title",
                    "summary": "Deterministic QA narrative summary.",
                    "regions": regions_body,
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
            try:
                inventory = json.loads(tree_match.group(1))
            except json.JSONDecodeError:
                self.send_error(500)
                return
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
                "model": model,
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


# ---------------------------------------------------------------------------
# Offline fixture writers (disposable workspace)
# ---------------------------------------------------------------------------

_BASE_CARD = "atlas-prompt-injection"

_CARD_TEXT = {
    "threat": "An attacker submits crafted input to influence the AI assistant.",
    "vulnerability": "Instruction-data confusion.",
    "consequence": "The agent follows attacker instructions.",
    "impact": "Unauthorized behavior.",
}


def _write_offline_inputs(ws: Path) -> None:
    """Write the offline input files shared by the validation cases.

    Shapes mirror the projection-readiness suites: a risk-extraction card
    (``ibm-risk-atlas``), an SSSOM TSV mapping that card to two OWASP LLM
    IDs, a reviewed capability profile, and the cross-taxonomy mappings
    used for deterministic pattern selection.
    """
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
    (ws / "use-case.txt").write_text(_USE_CASE + "\n", encoding="utf-8")
    (ws / "missing").mkdir(exist_ok=True)
    (ws / "output").mkdir(exist_ok=True)


def _write_qualification_facts(ws: Path) -> None:
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
    """One fresh disposable workspace per case."""
    ws = RUN_ROOT / "workspaces" / case
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    _write_offline_inputs(ws)
    return ws


# ---------------------------------------------------------------------------
# CLI runner
# ---------------------------------------------------------------------------


def _run_cli(
    case: str,
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 1800,
) -> subprocess.CompletedProcess:
    """Run one CLI command, capturing stdout, stderr, and exit status."""
    capture_dir = RUN_ROOT / "captures" / case
    capture_dir.mkdir(parents=True, exist_ok=True)
    child_env = os.environ.copy()
    child_env.pop(QA_PIPELINE_ENV, None)
    child_env.pop("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None)
    if env:
        child_env.update(env)
    try:
        completed = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{case}: command timed out after {timeout}s") from exc
    (capture_dir / "command.txt").write_text(" ".join(argv) + "\n", encoding="utf-8")
    (capture_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (capture_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (capture_dir / "exit.txt").write_text(f"{completed.returncode}\n", encoding="utf-8")
    return completed


def _base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}/v1"


def _tree_hashes(path: Path) -> dict[str, str]:
    """Map every file under *path* (relative) to its SHA-256."""
    return {
        file.relative_to(path).as_posix(): hashlib.sha256(file.read_bytes()).hexdigest()
        for file in sorted(path.rglob("*"))
        if file.is_file()
    }


def _assert_run_dir_unchanged(case: str, run_dir: Path, before: dict[str, str]) -> None:
    after = _tree_hashes(run_dir)
    if after != before:
        failures.append(f"{case}: run directory changed (before/after differ)")
    for rel, digest in after.items():
        if "_injected" in rel or rel.endswith(".tmp"):
            failures.append(f"{case}: unexpected artifact appeared: {rel}")


# ---------------------------------------------------------------------------
# Completed manifest-v3 run fixture (produced by the public generate CLI)
# ---------------------------------------------------------------------------

_FIXTURE_RUN_DIR: Path | None = None
_FIXTURE_TRACE: str = ""


def _generate_completed_run(server: ThreadingHTTPServer) -> Path | None:
    """Produce the authoritative completed v3 run used by report/eval cases.

    Drives the public ``generate`` CLI against the deterministic loopback
    endpoint exactly once and caches the resulting run directory.
    """
    global _FIXTURE_RUN_DIR, _FIXTURE_TRACE
    if _FIXTURE_RUN_DIR is not None:
        return _FIXTURE_RUN_DIR

    case = "fixture-generate"
    ws = _new_workspace(case)
    _write_qualification_facts(ws)
    FixtureHandler.reset()
    os.environ["ACCEPT_PATTERN"] = "Reflection loop resource exhaustion trap"
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env.pop(QA_PIPELINE_ENV, None)
    command = [
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
        _base_url(server),
        "--api-key",
        "unused",
        "--model",
        "qa-fixture",
        "--max-scenario-techniques",
        "1",
        "--generation-mode",
        "coverage",
    ]
    try:
        completed = _run_cli(case, command, env=env, timeout=2400)
    except RuntimeError as exc:
        failures.append(f"{case}: {exc}")
        _FIXTURE_TRACE = "generate fixture timed out"
        return None
    if completed.returncode != 0:
        failures.append(
            f"{case}: generate fixture exited {completed.returncode} "
            f"(stderr tail: {completed.stderr[-500:].strip()})"
        )
        _FIXTURE_TRACE = "generate fixture failed"
        return None
    runs = sorted(path for path in (ws / "output").glob("*") if path.is_dir())
    if not runs:
        failures.append(f"{case}: generate fixture produced no run directory")
        return None
    run_dir = runs[-1]
    manifest_path = run_dir / "run-manifest.yaml"
    if not manifest_path.exists():
        failures.append(f"{case}: fixture run has no run-manifest.yaml")
        return None
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != "3":
        failures.append(
            f"{case}: fixture run is not manifest v3: {manifest.get('manifest_version')!r}"
        )
    if manifest.get("status") != "completed":
        failures.append(
            f"{case}: fixture run is not completed: {manifest.get('status')!r}"
        )
    _FIXTURE_RUN_DIR = run_dir
    note = (
        f"fixture: authoritative v3 completed run {manifest.get('run_id')} "
        f"in {run_dir.relative_to(RUN_ROOT)}"
    )
    notes.append(note)
    print(f"  note: {note}", flush=True)
    return run_dir


def _fixture_manifest(case: str, server: ThreadingHTTPServer) -> dict | None:
    """Return the fixture run manifest; record a failure when unavailable."""
    run_dir = _generate_completed_run(server)
    if run_dir is None:
        failures.append(f"{case}: completed-run fixture unavailable")
        return None
    manifest = yaml.safe_load(
        (run_dir / "run-manifest.yaml").read_text(encoding="utf-8")
    )
    if not manifest or not isinstance(manifest, dict):
        failures.append(f"{case}: fixture manifest unreadable")
        return None
    return manifest


# ---------------------------------------------------------------------------
# QA procedures
# ---------------------------------------------------------------------------


def qa_tclc_01(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-01: generate rejects a missing risk-extraction file."""
    case = "TCLC-01"
    ws = _new_workspace(case)
    missing = ws / "missing" / "risk-extraction.json"
    completed = _run_cli(
        case,
        [
            *_command(),
            "generate",
            "--use-case",
            _USE_CASE,
            "--risk-extraction",
            str(missing),
            "--sssom",
            str(ws / "risk-to-llm.sssom.tsv"),
            "--output-dir",
            str(ws / "output"),
        ],
    )
    if completed.returncode != 1:
        failures.append(f"{case}: expected exit 1, got {completed.returncode}")
    if f"Error: risk-extraction file not found: {missing}" not in completed.stderr:
        failures.append(f"{case}: wrong error on stderr: {completed.stderr[-300:]!r}")
    if (ws / "output").exists() and any((ws / "output").iterdir()):
        failures.append(f"{case}: output collection created despite failure")


def qa_tclc_02(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-02: generate rejects a missing SSSOM file."""
    case = "TCLC-02"
    ws = _new_workspace(case)
    missing = ws / "missing" / "risk-to-llm.sssom.tsv"
    completed = _run_cli(
        case,
        [
            *_command(),
            "generate",
            "--use-case",
            _USE_CASE,
            "--risk-extraction",
            str(ws / "risk-extraction.json"),
            "--sssom",
            str(missing),
            "--output-dir",
            str(ws / "output"),
        ],
    )
    if completed.returncode != 1:
        failures.append(f"{case}: expected exit 1, got {completed.returncode}")
    if f"Error: SSSOM file not found: {missing}" not in completed.stderr:
        failures.append(f"{case}: wrong error on stderr: {completed.stderr[-300:]!r}")
    if (ws / "output").exists() and any((ws / "output").iterdir()):
        failures.append(f"{case}: output collection created despite failure")


def qa_tclc_03(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-03: generate rejects a missing @file use-case reference."""
    case = "TCLC-03"
    ws = _new_workspace(case)
    missing_ref = f"@{ws / 'missing' / 'use-case.txt'}"
    completed = _run_cli(
        case,
        [
            *_command(),
            "generate",
            "--use-case",
            missing_ref,
            "--risk-extraction",
            str(ws / "risk-extraction.json"),
            "--sssom",
            str(ws / "risk-to-llm.sssom.tsv"),
            "--output-dir",
            str(ws / "output"),
        ],
    )
    if completed.returncode != 1:
        failures.append(f"{case}: expected exit 1, got {completed.returncode}")
    if "Error: use-case file not found:" not in completed.stderr:
        failures.append(f"{case}: wrong error on stderr: {completed.stderr[-300:]!r}")
    if f"{ws / 'missing' / 'use-case.txt'}" not in completed.stderr:
        failures.append(f"{case}: error does not name the missing file")
    if any("run_pipeline" in line for line in completed.stderr.splitlines()):
        failures.append(
            f"{case}: pipeline error leaked instead of file resolution error"
        )
    if (ws / "output").exists() and any((ws / "output").iterdir()):
        failures.append(f"{case}: output collection created despite failure")


def qa_tclc_04(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-04: projection-preflight rejects each missing required input."""
    for option, label, filename in (
        ("--risk-extraction", "risk-extraction file", "risk-extraction.json"),
        ("--sssom", "SSSOM file", "risk-to-llm.sssom.tsv"),
        ("--profile", "capability profile file", "capability-profile.yaml"),
    ):
        case = f"TCLC-04-{option.strip('-')}"
        ws = _new_workspace(case)
        missing = ws / "missing" / filename
        argv = [
            *_command(),
            "projection-preflight",
            "--use-case",
            _USE_CASE,
            "--risk-extraction",
            str(
                missing
                if option == "--risk-extraction"
                else ws / "risk-extraction.json"
            ),
            "--sssom",
            str(missing if option == "--sssom" else ws / "risk-to-llm.sssom.tsv"),
            "--profile",
            str(missing if option == "--profile" else ws / "capability-profile.yaml"),
            "--cross-taxonomy",
            str(ws / "cross-taxonomy-mappings.yaml"),
        ]
        completed = _run_cli(case, argv)
        if completed.returncode != 1:
            failures.append(f"{case}: expected exit 1, got {completed.returncode}")
        if f"Error: {label} not found: {missing}" not in completed.stderr:
            failures.append(
                f"{case}: wrong error on stderr: {completed.stderr[-300:]!r}"
            )
        if completed.stdout.strip():
            failures.append(
                f"{case}: stdout carries output: {completed.stdout[:200]!r}"
            )


def qa_tclc_05(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-05: validate-catalog-qualification rejects a missing artifact."""
    for contract in ("matrix", "campaign", "report"):
        case = f"TCLC-05-{contract}"
        ws = _new_workspace(case)
        missing = ws / "missing" / "matrix.yaml"
        completed = _run_cli(
            case,
            [
                *_command(),
                "validate-catalog-qualification",
                str(missing),
                "--contract",
                contract,
            ],
        )
        if completed.returncode != 1:
            failures.append(f"{case}: expected exit 1, got {completed.returncode}")
        if not completed.stderr.lstrip().startswith("Error:"):
            failures.append(
                f"{case}: stderr not Error-prefixed: {completed.stderr[:200]!r}"
            )
        if completed.stdout.strip():
            failures.append(f"{case}: stdout carries JSON: {completed.stdout[:200]!r}")


def qa_tclc_06(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-06: validate-catalog-qualification rejects invalid content."""
    committed_matrix = REPO_ROOT / "data" / "catalog-qualification-matrix-v1.yaml"

    def _removed_required_key(ws: Path) -> None:
        data = yaml.safe_load(committed_matrix.read_text(encoding="utf-8"))
        del data["catalog_sha256"]
        (ws / "corrupted.yaml").write_text(
            yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
        )

    def _unrelated_document(ws: Path) -> None:
        (ws / "corrupted.yaml").write_text(
            (ws / "use-case.txt").read_text(encoding="utf-8"), encoding="utf-8"
        )

    for variant, artifact_writer in (
        ("removed-key", _removed_required_key),
        ("unrelated", _unrelated_document),
    ):
        case = f"TCLC-06-{variant}"
        ws = _new_workspace(case)
        artifact_writer(ws)
        artifact = ws / "corrupted.yaml"
        completed = _run_cli(
            case,
            [
                *_command(),
                "validate-catalog-qualification",
                str(artifact),
                "--contract",
                "matrix",
            ],
        )
        if completed.returncode != 1:
            failures.append(f"{case}: expected exit 1, got {completed.returncode}")
        if not completed.stderr.lstrip().startswith("Error:"):
            failures.append(
                f"{case}: stderr not Error-prefixed: {completed.stderr[:200]!r}"
            )
        if completed.stdout.strip():
            failures.append(f"{case}: stdout carries JSON: {completed.stdout[:200]!r}")


def qa_tclc_07(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-07: validate-catalog-qualification rejects an invalid contract."""
    case = "TCLC-07"
    valid = REPO_ROOT / "data" / "catalog-qualification-matrix-v1.yaml"
    completed = _run_cli(
        case,
        [
            *_command(),
            "validate-catalog-qualification",
            str(valid),
            "--contract",
            "unknown",
        ],
    )
    if completed.returncode != 1:
        failures.append(f"{case}: expected exit 1, got {completed.returncode}")
    if "Error: contract must be matrix, campaign, or report" not in completed.stderr:
        failures.append(f"{case}: wrong error on stderr: {completed.stderr[-300:]!r}")
    if completed.stdout.strip():
        failures.append(f"{case}: stdout carries output: {completed.stdout[:200]!r}")


def qa_tclc_08(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-08: report and eval reject a missing run directory."""
    for command in ("report", "eval"):
        case = f"TCLC-08-{command}"
        ws = _new_workspace(case)
        missing = ws / "missing" / "run"
        completed = _run_cli(
            case,
            [*_command(), command, "--output-dir", str(missing)],
        )
        if completed.returncode != 1:
            failures.append(f"{case}: expected exit 1, got {completed.returncode}")
        if f"Error: directory not found: {missing}" not in completed.stderr:
            failures.append(
                f"{case}: wrong error on stderr: {completed.stderr[-300:]!r}"
            )
        if command == "eval" and completed.stdout.strip():
            failures.append(
                f"{case}: stdout carries output: {completed.stdout[:200]!r}"
            )


def qa_tclc_09(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-09: report rejects an output destination inside the run dir."""
    case = "TCLC-09"
    run_dir = _generate_completed_run(server)
    if run_dir is None:
        failures.append(f"{case}: completed-run fixture unavailable")
        return
    before = _tree_hashes(run_dir)
    injected = run_dir / "injected.html"
    completed = _run_cli(
        case,
        [
            *_command(),
            "report",
            "--output-dir",
            str(run_dir),
            "--output",
            str(injected),
        ],
    )
    if completed.returncode != 1:
        failures.append(f"{case}: expected exit 1, got {completed.returncode}")
    if "inside the immutable run directory" not in completed.stderr:
        failures.append(
            f"{case}: stderr does not explain the immutable-run rejection: "
            f"{completed.stderr[-300:]!r}"
        )
    if injected.exists():
        failures.append(f"{case}: injected.html appeared inside the run directory")
    _assert_run_dir_unchanged(case, run_dir, before)


def qa_tclc_10(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-10: report writes the HTML artifact outside the run directory."""
    case = "TCLC-10"
    run_dir = _generate_completed_run(server)
    if run_dir is None:
        failures.append(f"{case}: completed-run fixture unavailable")
        return
    before = _tree_hashes(run_dir)
    ws = _new_workspace(case)
    report_path = ws / "report.html"
    completed = _run_cli(
        case,
        [
            *_command(),
            "report",
            "--output-dir",
            str(run_dir),
            "--output",
            str(report_path),
        ],
    )
    if completed.returncode != 0:
        failures.append(
            f"{case}: report exited {completed.returncode}: {completed.stderr[-300:]!r}"
        )
    if f"Report written to {report_path}" not in completed.stdout:
        failures.append(
            f"{case}: stdout does not announce the written path: "
            f"{completed.stdout[-300:]!r}"
        )
    if not report_path.is_file() or report_path.stat().st_size == 0:
        failures.append(f"{case}: report.html missing or empty")
    elif "<html" not in report_path.read_text(encoding="utf-8"):
        failures.append(f"{case}: report.html is not an HTML document")
    _assert_run_dir_unchanged(case, run_dir, before)


def _assert_scorecard(
    case: str, completed: subprocess.CompletedProcess, manifest: dict
) -> None:
    """Shared assertions for QA-TCLC-11/12 scorecard output."""
    if completed.returncode != 0:
        failures.append(
            f"{case}: eval exited {completed.returncode}: {completed.stderr[-300:]!r}"
        )
        return
    stdout = completed.stdout.strip()
    if not stdout:
        failures.append(f"{case}: eval printed no scorecard")
        return
    try:
        scorecard = yaml.safe_load(stdout)
        if not isinstance(scorecard, dict):
            raise ValueError("not a mapping")
    except Exception as exc:
        failures.append(f"{case}: stdout does not parse as one mapping: {exc}")
        return
    expected_keys = {
        "manifest_version",
        "schema_version",
        "run_id",
        "scenario_count",
        "feature_file_count",
        "presence_coverage",
        "validity_grounding",
        "cross_artifact_agreement",
        "semantic_quality_diagnostics",
        "release_qualification",
        "qualification",
    }
    missing_keys = sorted(expected_keys - set(scorecard))
    if missing_keys:
        failures.append(f"{case}: scorecard missing keys: {missing_keys}")
    if scorecard.get("schema_version") != "1":
        failures.append(
            f"{case}: schema_version={scorecard.get('schema_version')!r}, expected '1'"
        )
    if scorecard.get("run_id") != manifest.get("run_id"):
        failures.append(
            f"{case}: run_id mismatch: {scorecard.get('run_id')!r} vs "
            f"manifest {manifest.get('run_id')!r}"
        )
    admitted = sum(
        1
        for entry in manifest.get("inventory", [])
        if entry.get("role") == "scenario_yaml"
    )
    if scorecard.get("scenario_count") != admitted:
        failures.append(
            f"{case}: scenario_count={scorecard.get('scenario_count')!r}, "
            f"expected admitted count {admitted}"
        )


def qa_tclc_11(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-11: eval prints the YAML scorecard from a completed fixture."""
    case = "TCLC-11"
    manifest = _fixture_manifest(case, server)
    if manifest is None:
        return
    run_dir = _FIXTURE_RUN_DIR
    assert run_dir is not None
    before = _tree_hashes(run_dir)
    completed = _run_cli(case, [*_command(), "eval", "--output-dir", str(run_dir)])
    _assert_scorecard(case, completed, manifest)
    if completed.returncode == 0:
        scorecard = yaml.safe_load(completed.stdout.strip())
        assert isinstance(scorecard, dict)
        if scorecard.get("manifest_version") != "3":
            failures.append(
                f"{case}: manifest_version={scorecard.get('manifest_version')!r}, "
                f"expected '3'"
            )
    _assert_run_dir_unchanged(case, run_dir, before)


def qa_tclc_12(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-12: eval prints the JSON scorecard with --format json."""
    case = "TCLC-12"
    manifest = _fixture_manifest(case, server)
    if manifest is None:
        return
    run_dir = _FIXTURE_RUN_DIR
    assert run_dir is not None
    before = _tree_hashes(run_dir)
    completed = _run_cli(
        case, [*_command(), "eval", "--output-dir", str(run_dir), "--format", "json"]
    )
    _assert_scorecard(case, completed, manifest)
    if completed.returncode == 0 and completed.stdout.strip():
        try:
            scorecard = json.loads(completed.stdout.strip())
        except json.JSONDecodeError as exc:
            failures.append(f"{case}: stdout is not valid JSON: {exc}")
        else:
            if isinstance(scorecard, dict) and scorecard.get("schema_version") != "1":
                failures.append(f"{case}: JSON schema_version incorrect")
    _assert_run_dir_unchanged(case, run_dir, before)


def qa_tclc_13(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-13: profile writes the capability profile YAML."""
    case = "TCLC-13"
    ws = _new_workspace(case)
    output = ws / "capability-profile.yaml"
    for variant, use_case_arg in (
        ("inline", _USE_CASE),
        ("atfile", f"@{ws / 'use-case.txt'}"),
    ):
        variant_case = f"{case}-{variant}"
        completed = _run_cli(
            variant_case,
            [
                *_command(),
                "profile",
                "--use-case",
                use_case_arg,
                "--output",
                str(output),
                "--base-url",
                _base_url(server),
                "--api-key",
                "unused",
                "--model",
                "qa-fixture",
            ],
        )
        if completed.returncode != 0:
            failures.append(
                f"{variant_case}: profile exited {completed.returncode}: "
                f"{completed.stderr[-300:]!r}"
            )
            continue
        if f"Profile written to {output}" not in completed.stdout:
            failures.append(
                f"{variant_case}: stdout does not announce the written path: "
                f"{completed.stdout[-300:]!r}"
            )
        written_line = completed.stdout.find(f"Profile written to {output}")
        tokens_line = completed.stdout.find("LLM tokens:")
        if tokens_line == -1:
            failures.append(f"{variant_case}: token-summary line missing")
        elif written_line != -1 and tokens_line < written_line:
            failures.append(
                f"{variant_case}: token-summary appears before the written path"
            )
        if not output.is_file():
            failures.append(f"{variant_case}: profile file not written")
            continue
        parsed = yaml.safe_load(output.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            failures.append(f"{variant_case}: profile is not a YAML mapping")
            continue
        entry_points = parsed.get("entry_points")
        if not isinstance(entry_points, list) or not entry_points:
            failures.append(f"{variant_case}: entry_points missing")
        else:
            names = [
                item.get("name") if isinstance(item, dict) else item
                for item in entry_points
            ]
            if "ze-query" not in names:
                failures.append(
                    f"{variant_case}: fixture entry point ze-query absent: {names}"
                )


def qa_tclc_14(server: ThreadingHTTPServer) -> None:
    """QA-TCLC-14: projection-preflight prints the requirements report."""
    case = "TCLC-14"
    ws = _new_workspace(case)
    base_argv = [
        *_command(),
        "projection-preflight",
        "--use-case",
        _USE_CASE,
        "--risk-extraction",
        str(ws / "risk-extraction.json"),
        "--sssom",
        str(ws / "risk-to-llm.sssom.tsv"),
        "--profile",
        str(ws / "capability-profile.yaml"),
        "--cross-taxonomy",
        str(ws / "cross-taxonomy-mappings.yaml"),
    ]

    # Run 1: no qualification facts and no template.
    completed = _run_cli(f"{case}-run1", base_argv)
    if completed.returncode != 0:
        failures.append(
            f"{case}-run1: preflight exited {completed.returncode}: "
            f"{completed.stderr[-300:]!r}"
        )
        return
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        failures.append(f"{case}-run1: stdout is not valid JSON: {exc}")
        return
    for key in ("readiness", "fact_states", "facts_template", "explicit_facts_source"):
        if key not in report:
            failures.append(f"{case}-run1: report missing key {key!r}")
    readiness = report.get("readiness")
    if not isinstance(readiness, dict) or not isinstance(readiness.get("ready"), bool):
        failures.append(f"{case}-run1: readiness lacks a boolean ready flag")
    missing_facts = readiness.get("missing_facts")
    if not isinstance(missing_facts, list) or not missing_facts:
        failures.append(
            f"{case}-run1: missing_facts should be non-empty without facts "
            f"(got {missing_facts!r})"
        )
    if report.get("explicit_facts_source") is not False:
        failures.append(f"{case}-run1: explicit_facts_source should be false")
    statuses = {"present", "absent", "unknown", "stale", "contradictory"}
    for state in report.get("fact_states", []):
        if state.get("status") not in statuses:
            failures.append(
                f"{case}-run1: fact state status {state.get('status')!r} not allowed"
            )

    # Run 2: --facts-template writes exactly once with unknown statuses.
    template = ws / "facts-template.yaml"
    argv2 = [*base_argv, "--facts-template", str(template)]
    completed = _run_cli(f"{case}-run2", argv2)
    if completed.returncode != 0:
        failures.append(
            f"{case}-run2: preflight exited {completed.returncode}: "
            f"{completed.stderr[-300:]!r}"
        )
        return
    if not template.is_file():
        failures.append(f"{case}-run2: facts template not written")
        return
    template_data = yaml.safe_load(template.read_text(encoding="utf-8"))
    if (
        not isinstance(template_data, dict)
        or template_data.get("schema_version") != "1"
    ):
        failures.append(f"{case}-run2: template schema_version not 1")
    facts = template_data.get("facts")
    if not isinstance(facts, list) or not facts:
        failures.append(f"{case}-run2: template facts list missing")
    else:
        for fact in facts:
            if fact.get("status") != "unknown":
                failures.append(
                    f"{case}-run2: template fact status {fact.get('status')!r} "
                    f"not 'unknown'"
                )
    if report.get("explicit_facts_source") is not False:
        failures.append(f"{case}-run2: explicit_facts_source should be false")
    if completed.stdout.strip():
        try:
            run2_report = json.loads(completed.stdout)
            if run2_report.get("explicit_facts_source") is not False:
                failures.append(f"{case}-run2: stdout explicit_facts_source not false")
        except json.JSONDecodeError:
            failures.append(f"{case}-run2: run-2 stdout is not the JSON report")

    # Run 3: the same command refuses to overwrite the existing template.
    template_bytes = template.read_bytes()
    completed = _run_cli(f"{case}-run3", argv2)
    if completed.returncode != 1:
        failures.append(f"{case}-run3: expected exit 1, got {completed.returncode}")
    if "Error:" not in completed.stderr or "already exists" not in completed.stderr:
        failures.append(
            f"{case}-run3: stderr does not state the template already exists: "
            f"{completed.stderr[-300:]!r}"
        )
    if template.read_bytes() != template_bytes:
        failures.append(f"{case}-run3: existing template was modified")
    if completed.stdout.strip():
        failures.append(f"{case}-run3: stdout carries a JSON report")


def _run_gate(name: str, argv: list[str], timeout: int = 1800) -> tuple[bool, str]:
    """Run one documented gate and return (ok, message)."""
    env = os.environ.copy()
    env.pop(QA_PIPELINE_ENV, None)
    try:
        completed = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"{name} timed out"
    ok = completed.returncode == 0
    tail = (completed.stdout or "")[-800:] + (completed.stderr or "")[-800:]
    return ok, f"{name}: exit {completed.returncode}\n{tail.strip()[-700:]}"


def qa_tclc_15() -> None:
    """QA-TCLC-15: deterministic repository gates and output hygiene."""
    if os.environ.get(QA_PIPELINE_ENV):
        failures.append("15: ASAGO_SCENARIO_GENERATOR_QA_PIPELINE must not be set")
    statuses = [
        _run_gate("quality.sh", ["./scripts/quality.sh"], timeout=900),
        _run_gate("acceptance.sh", ["./scripts/acceptance.sh"], timeout=3600),
        _run_gate("unit tests", [_UV, "run", "pytest", "tests/", "-q"], timeout=3600),
    ]
    for ok, message in statuses:
        if ok:
            notes.append(f"15: {message.splitlines()[0]}")
        else:
            failures.append(f"15: {message}")
    hygiene = subprocess.run(
        ["git", "status", "--short", "--untracked-files=all"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    dirty = [line for line in hygiene.stdout.splitlines() if line.strip()]
    unexpected = [
        line
        for line in dirty
        if any(
            marker in line
            for marker in (
                "build/acceptance",
                "acceptance/generated",
                "acceptance/ir",
                "lcov.info",
                "coverage",
                "htmlcov",
                "tmp/qa-taxonomy-cli-commands",
            )
        )
    ]
    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    staged_paths = [line for line in staged.stdout.splitlines() if line.strip()]
    if unexpected:
        failures.append(
            "15: unexpected tracked/staged generated artifacts:\n"
            + "\n".join(unexpected)
        )
    if staged_paths:
        failures.append(f"15: staged paths present: {staged_paths}")
    if not unexpected and not staged_paths:
        notes.append(
            "15: no generated acceptance IR, coverage, or QA captures tracked/staged"
        )


def main() -> int:
    """Run all taxonomy CLI command-contract QA procedures."""
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)

    FixtureHandler.reset()
    FixtureHandler.request_log = RUN_ROOT / "captures" / "fixture" / "requests.jsonl"
    FixtureHandler.request_log.parent.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        for procedure in (
            qa_tclc_01,
            qa_tclc_02,
            qa_tclc_03,
            qa_tclc_04,
            qa_tclc_05,
            qa_tclc_06,
            qa_tclc_07,
            qa_tclc_08,
            qa_tclc_09,
            qa_tclc_10,
            qa_tclc_11,
            qa_tclc_12,
            qa_tclc_13,
            qa_tclc_14,
        ):
            procedure(server)
            print(f"  [done] {procedure.__name__}", flush=True)
        if os.environ.get("QA_SKIP_GATES"):
            print("\n--- QA-TCLC-15 skipped (QA_SKIP_GATES set) ---", flush=True)
        else:
            print("\n--- QA-TCLC-15: deterministic repository gates ---", flush=True)
            qa_tclc_15()
    finally:
        server.shutdown()
        server.server_close()

    print("\n=== SUMMARY ===", flush=True)
    print(f"  Failures: {len(failures)}", flush=True)
    for failure in failures:
        print(f"    - {failure}", flush=True)
    for note in notes:
        print(f"  note: {note}", flush=True)
    if failures:
        print("  Result: FAIL", flush=True)
    else:
        print("  Result: PASS", flush=True)
    return 1 if failures else 0


RUN_ROOT = (
    REPO_ROOT
    / "tmp"
    / "qa-taxonomy-cli-commands"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

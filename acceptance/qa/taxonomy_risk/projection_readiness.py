#!/usr/bin/env python3
"""Executable end-to-end QA suite for taxonomy projection architecture readiness.

Mirrors ``projection_readiness.md`` (QA-TPR-01..03).  Drives only the public
``asago-scenario-generator generate`` CLI against a deterministic loopback
OpenAI-compatible fixture endpoint and inspects CLI stdout, stderr, exit
status, fixture request schemas, and published run files.  Never imports
project modules and never sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Pinned live generate contract (reported, not silently bent)
  1. Readiness is evaluated after candidate filter, immediately before
     authoritative projection (Stage 3.6).  Filter and Stage 1 inference
     requests may occur on fail-closed paths; actor/narrative/tree/behavior
     requests must not.
  2. QA-TPR-02 uses Stage 1 inference (no ``--profile``).  ``Stage1Profile``
     cannot emit ``external_integrations`` or ``trust_boundaries``, so an
     inferred profile omits both categories required by AP-T6-04.
  3. QA-TPR-03 cannot select AP-T6-07 through public generate: candidate
     expansion skips seeds with empty ATLAS/LAAF technique pools, so
     readiness never sees that pattern's missing fact.  The suite instead
     admits AP-T6-04 (same TPR-01 profile) and omits
     ``capabilities.reflection_mechanism`` from ``--qualification-facts``.
     Procedure/Gherkin still name
     ``deployment.attacker_code_execution_on_agent_host``; the live catalog
     fact_id for AP-T6-07 is ``attacker_code_execution_on_agent_host``
     (namespace ``runtime_state``).
  4. The runner logs ``[Stage 3.6] Projecting authoritative candidates...``
     before the readiness gate; fail-closed diagnostics still state that
     projection failed before projection and that no enrichment workflow
     launched.

Run with::

    uv run python acceptance/qa/taxonomy_risk/projection_readiness.py

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

GENERATION_SCHEMAS = (
    "ActorDraftV3For",
    "NarrativeDraftV3For",
    "AttackTreeDraftV3For",
    "BehaviorDraftV2For",
)


def _command() -> list[str]:
    """Resolve the CLI launcher (uv run, falling back to the venv binary)."""
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
    """Deterministic drafts for every generation stage plus Stage 1."""

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
        model = str(request.get("model", "qa-fixture"))
        FixtureHandler.requests.append(
            {
                "schema": schema,
                "model": model,
                "user_prompt": user_prompt,
            }
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
            body_map = {
                handle: {
                    "relevant": accepted and i == accept_index,
                    "rationale": "Deterministic QA fixture verdict.",
                }
                for i, handle in enumerate(handles)
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
            regions_body = {
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
            }
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
    (ws / "use-case.txt").write_text(_USE_CASE + "\n", encoding="utf-8")
    (ws / "output").mkdir(exist_ok=True)


def _write_ap_t6_04_profile(ws: Path) -> None:
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


def _write_ap_t6_04_facts(ws: Path, *, omit: tuple[str, ...] = ()) -> None:
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
            if capability not in omit
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
    return ws


def _run_cli(
    case: str,
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 1800,
) -> subprocess.CompletedProcess:
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
    (capture_dir / "requests.json").write_text(
        json.dumps(
            [
                {"schema": item["schema"], "prompt_len": len(item["user_prompt"])}
                for item in FixtureHandler.requests
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return completed


def _base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}/v1"


def _generate_argv(
    ws: Path,
    server: ThreadingHTTPServer,
    *,
    profile: bool,
    qualification_facts: bool,
) -> list[str]:
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
    if profile:
        argv.extend(["--profile", str(ws / "capability-profile.yaml")])
    if qualification_facts:
        argv.extend(["--qualification-facts", str(ws / "qualification-facts.yaml")])
    return argv


def _run_dir(ws: Path) -> Path | None:
    runs = sorted(path for path in (ws / "output").glob("*") if path.is_dir())
    return runs[-1] if runs else None


def _load_manifest(run_dir: Path | None) -> dict | None:
    if run_dir is None:
        return None
    path = run_dir / "run-manifest.yaml"
    if not path.exists():
        return None
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else None


def _schemas() -> list[str]:
    return [item["schema"] for item in FixtureHandler.requests]


def _has_generation_request() -> bool:
    return any(
        schema.startswith(prefix)
        for schema in _schemas()
        for prefix in GENERATION_SCHEMAS
    )


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def qa_tpr_01(server: ThreadingHTTPServer) -> None:
    """QA-TPR-01: ready architecture proceeds into projection."""
    case = "TPR-01"
    ws = _new_workspace(case)
    _write_ap_t6_04_profile(ws)
    _write_ap_t6_04_facts(ws)
    FixtureHandler.reset()
    os.environ["ACCEPT_PATTERN"] = ACCEPT_AP_T6_04
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env.pop(QA_PIPELINE_ENV, None)
    completed = _run_cli(
        case,
        _generate_argv(ws, server, profile=True, qualification_facts=True),
        env=env,
        timeout=2400,
    )
    combined = f"{completed.stdout}\n{completed.stderr}"
    _check(
        case, completed.returncode == 0, f"expected exit 0, got {completed.returncode}"
    )
    _check(
        case,
        "Projection readiness failed" not in combined,
        "architecture-readiness error appeared on a ready run",
    )
    _check(
        case,
        "[Stage 3.6] Projecting authoritative candidates..." in combined,
        "Stage 3.6 projection did not start",
    )
    _check(
        case,
        _has_generation_request(),
        f"no scenario-generation request after projection; schemas={_schemas()}",
    )
    admitted = re.search(r"Candidates admitted:\s+(\d+)", completed.stdout)
    _check(case, admitted is not None, "admitted-count line missing")
    if admitted is not None:
        _check(
            case,
            int(admitted.group(1)) >= 1,
            f"expected at least one admitted candidate, got {admitted.group(1)}",
        )


def qa_tpr_02(server: ThreadingHTTPServer) -> None:
    """QA-TPR-02: missing resource categories stop before projection."""
    case = "TPR-02"
    ws = _new_workspace(case)
    FixtureHandler.reset()
    os.environ["ACCEPT_PATTERN"] = ACCEPT_AP_T6_04
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env.pop(QA_PIPELINE_ENV, None)
    completed = _run_cli(
        case,
        _generate_argv(ws, server, profile=False, qualification_facts=False),
        env=env,
    )
    combined = f"{completed.stdout}\n{completed.stderr}"
    _check(
        case,
        completed.returncode != 0,
        f"expected nonzero exit, got {completed.returncode}",
    )
    _check(
        case,
        "Pipeline complete." not in completed.stdout,
        "run reported normal completion",
    )
    _check(
        case,
        "Projection readiness failed before projection" in completed.stderr,
        f"missing readiness diagnostic: {completed.stderr[-400:]!r}",
    )
    _check(
        case,
        "external_integrations" in completed.stderr
        and "trust_boundaries" in completed.stderr,
        "diagnostic does not name both missing resource categories",
    )
    _check(
        case,
        "--profile" in completed.stderr,
        "diagnostic does not direct the user to --profile",
    )
    _check(
        case,
        "No architecture enrichment workflow was launched" in completed.stderr,
        "diagnostic does not deny architecture enrichment",
    )
    _check(
        case,
        not _has_generation_request(),
        f"scenario-generation request occurred; schemas={_schemas()}",
    )
    schemas = _schemas()
    _check(
        case,
        any(name.startswith("Stage1Profile") for name in schemas),
        "Stage 1 inference request missing (expected for a no --profile run)",
    )
    _check(
        case,
        not any("enrich" in name.lower() for name in schemas),
        f"unexpected enrichment-shaped request: {schemas}",
    )
    manifest = _load_manifest(_run_dir(ws))
    if manifest is None:
        notes.append(
            "02: no failed manifest was published (gate aborted before finalization)"
        )
    else:
        status = str(manifest.get("status", ""))
        _check(
            case,
            status not in {"completed", "completed_with_errors"},
            f"manifest status {status!r} claims completion",
        )
    notes.append(
        "02: inferred Stage1Profile cannot populate external_integrations or "
        "trust_boundaries; AP-T6-04 requires both categories."
    )
    if "[Stage 3.6]" in combined:
        notes.append(
            "02: Stage 3.6 log line is emitted before the readiness gate; "
            "the diagnostic still states projection failed before projection."
        )


def qa_tpr_03(server: ThreadingHTTPServer) -> None:
    """QA-TPR-03: missing fact evidence is actionable."""
    case = "TPR-03"
    ws = _new_workspace(case)
    _write_ap_t6_04_profile(ws)
    _write_ap_t6_04_facts(ws, omit=("reflection_mechanism",))
    FixtureHandler.reset()
    os.environ["ACCEPT_PATTERN"] = ACCEPT_AP_T6_04
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env.pop(QA_PIPELINE_ENV, None)
    completed = _run_cli(
        case,
        _generate_argv(ws, server, profile=True, qualification_facts=True),
        env=env,
    )
    _check(
        case,
        completed.returncode != 0,
        f"expected nonzero exit, got {completed.returncode}",
    )
    _check(
        case,
        "Pipeline complete." not in completed.stdout,
        "run reported normal completion",
    )
    _check(
        case,
        "Projection readiness failed before projection" in completed.stderr,
        f"missing readiness diagnostic: {completed.stderr[-400:]!r}",
    )
    _check(
        case,
        "capabilities.reflection_mechanism" in completed.stderr,
        "diagnostic does not name the live catalog fact_id",
    )
    _check(
        case,
        "--qualification-facts" in completed.stderr,
        "diagnostic does not direct the user to --qualification-facts",
    )
    _check(
        case,
        "No architecture enrichment workflow was launched" in completed.stderr,
        "diagnostic does not deny architecture enrichment",
    )
    _check(
        case,
        not _has_generation_request(),
        f"scenario-generation request occurred; schemas={_schemas()}",
    )
    notes.append(
        "03: AP-T6-07 cannot reach readiness via public generate because "
        "expansion skips seeds with empty ATLAS/LAAF technique pools. The "
        "suite omits AP-T6-04 fact_id 'capabilities.reflection_mechanism'. "
        "Procedure/Gherkin still name "
        "'deployment.attacker_code_execution_on_agent_host'."
    )
    manifest = _load_manifest(_run_dir(ws))
    if manifest is not None:
        status = str(manifest.get("status", ""))
        _check(
            case,
            status not in {"completed", "completed_with_errors"},
            f"manifest status {status!r} claims completion",
        )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    FixtureHandler.reset()
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        for procedure in (qa_tpr_01, qa_tpr_02, qa_tpr_03):
            procedure(server)
            print(f"  [done] {procedure.__name__}", flush=True)
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
    / "qa-taxonomy-projection-readiness"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Executable end-to-end QA suite for the taxonomy obligation planner.

Mirrors ``obligation_planner.md`` (QA-TOP-01..12).  Drives the public
``asago-scenario-generator plan-obligations`` file-to-file command: a
snapshot fixture file in, a published YAML or JSON plan artifact out.
Inspects the artifact with standard JSON/YAML readers, the console, and
the filesystem.  Never imports project modules, never calls
``plan_obligations``, and never sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Run with::

    uv run python acceptance/qa/taxonomy_risk/obligation_planner.py

Exit status is 0 only when every pinned assertion passes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
QA_PIPELINE_ENV = "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"
failures: list[str] = []
notes: list[str] = []

_SEARCH_PATH = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
_UV = shutil.which("uv", path=_SEARCH_PATH) or "uv"

PINNED = {
    "catalog_pin": "atlas-2026.05",
    "mapping_pin": "sssom-v1",
    "capability_content": "profile-v1",
    "qualification_facts": "facts-v1",
}


def _command() -> list[str]:
    if shutil.which("uv", path=_SEARCH_PATH):
        return [_UV, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv" / "bin" / "asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def _rel(
    risk_id: str,
    pattern_id: str | None,
    *,
    scope: str,
    qualification: str,
    projection: str,
    kind: str | None = None,
) -> dict:
    payload: dict[str, object] = {
        "risk_id": risk_id,
        "pattern_id": pattern_id,
        "scope_disposition": scope,
        "qualification_disposition": qualification,
        "projection_disposition": projection,
    }
    if kind is not None:
        payload["relationship_kind"] = kind
    return payload


def _ready(risk_id: str, pattern_id: str) -> dict:
    return _rel(
        risk_id,
        pattern_id,
        scope="applicable",
        qualification="ready",
        projection="projectable",
    )


def _snapshot(**overrides: object) -> dict:
    payload: dict[str, object] = {
        **PINNED,
        "relationships": [],
        "risk_cards": [],
        "config": {},
        "qualification_evaluations": [],
        "candidate_expansions": [],
        "ica_prose": "",
    }
    payload.update(overrides)
    return payload


def _new_workspace(case: str) -> Path:
    ws = RUN_ROOT / "workspaces" / case
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    return ws


def _write_snapshot(ws: Path, payload: dict) -> Path:
    path = ws / "snapshot.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _run_cli(
    case: str,
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
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
        timeout=120,
        check=False,
    )
    (capture_dir / "command.txt").write_text(" ".join(argv) + "\n", encoding="utf-8")
    (capture_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (capture_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (capture_dir / "exit.txt").write_text(f"{completed.returncode}\n", encoding="utf-8")
    (capture_dir / "env-qa-pipeline.txt").write_text(
        f"{QA_PIPELINE_ENV}={'set' if QA_PIPELINE_ENV in child else 'unset'}\n",
        encoding="utf-8",
    )
    return completed


def _plan_argv(snapshot: Path, output_dir: Path, fmt: str = "yaml") -> list[str]:
    return [
        *_command(),
        "plan-obligations",
        "--snapshot",
        str(snapshot),
        "--output-dir",
        str(output_dir),
        "--format",
        fmt,
    ]


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def _load_yaml(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} is not a YAML mapping")
    return payload


def _artifact_path(output_dir: Path, fmt: str) -> Path:
    name = (
        "taxonomy-obligation-plan.json"
        if fmt == "json"
        else "taxonomy-obligation-plan.yaml"
    )
    return output_dir / name


def _produce(
    case: str, payload: dict, *, fmt: str = "yaml"
) -> tuple[Path, dict, subprocess.CompletedProcess[str]]:
    ws = _new_workspace(case)
    snapshot = _write_snapshot(ws, payload)
    output_dir = ws / "plan"
    completed = _run_cli(case, _plan_argv(snapshot, output_dir, fmt))
    _check(
        case,
        completed.returncode == 0,
        f"exit {completed.returncode}: {completed.stderr[-300:]!r}",
    )
    artifact = _artifact_path(output_dir, fmt)
    _check(case, artifact.is_file(), f"missing published artifact {artifact.name}")
    plan = _load_yaml(artifact) if artifact.is_file() else {}
    return artifact, plan, completed


def _reject(case: str, payload: dict) -> tuple[Path, subprocess.CompletedProcess[str]]:
    ws = _new_workspace(case)
    snapshot = _write_snapshot(ws, payload)
    output_dir = ws / "plan"
    completed = _run_cli(case, _plan_argv(snapshot, output_dir, "yaml"))
    return output_dir, completed


def _obligations(plan: dict) -> list[dict]:
    rows = plan.get("obligations")
    return rows if isinstance(rows, list) else []


def _row(plan: dict, risk_id: str, pattern_id: str | None = None) -> dict | None:
    for row in _obligations(plan):
        if row.get("risk_id") != risk_id:
            continue
        if pattern_id is None or row.get("pattern_id") == pattern_id:
            return row
    return None


def qa_top_01() -> None:
    """QA-TOP-01: shared pattern keeps distinct risk-scoped obligations."""
    case = "TOP-01"
    artifact, plan, completed = _produce(
        case,
        _snapshot(
            relationships=[
                _ready("atlas-prompt-injection", "AP-T1-01"),
                _ready("atlas-memory-poisoning", "AP-T1-01"),
            ]
        ),
    )
    rows = [row for row in _obligations(plan) if row.get("pattern_id") == "AP-T1-01"]
    _check(case, len(rows) == 2, f"expected 2 AP-T1-01 obligations, got {len(rows)}")
    ids = {row.get("obligation_id") for row in rows}
    _check(case, len(ids) == 2, f"obligation identifiers are not distinct: {ids}")
    risks = {row.get("risk_id") for row in rows}
    _check(
        case,
        risks == {"atlas-prompt-injection", "atlas-memory-poisoning"},
        f"risk identities lost: {risks}",
    )
    _check(
        case,
        plan.get("network_calls") == 0,
        f"network_calls={plan.get('network_calls')!r}",
    )
    _check(
        case, plan.get("model_calls") == 0, f"model_calls={plan.get('model_calls')!r}"
    )
    _check(
        case,
        "http://" not in completed.stdout + completed.stderr,
        "network endpoint mentioned",
    )
    notes.append(f"01: published {artifact.name}")


def qa_top_02() -> None:
    """QA-TOP-02: applicable and capability-excluded relationships are both recorded."""
    case = "TOP-02"
    _artifact, plan, _completed = _produce(
        case,
        _snapshot(
            relationships=[
                _ready("atlas-prompt-injection", "AP-T6-01"),
                _rel(
                    "atlas-prompt-injection",
                    "AP-T11-01",
                    scope="capability_excluded",
                    qualification="not_attempted",
                    projection="not_attempted",
                ),
            ]
        ),
    )
    applicable = _row(plan, "atlas-prompt-injection", "AP-T6-01")
    excluded = _row(plan, "atlas-prompt-injection", "AP-T11-01")
    _check(
        case,
        applicable is not None and applicable.get("scope_disposition") == "applicable",
        f"missing applicable AP-T6-01: {applicable}",
    )
    _check(
        case,
        excluded is not None
        and excluded.get("scope_disposition") == "capability_excluded",
        f"missing capability-excluded AP-T11-01: {excluded}",
    )


def qa_top_03() -> None:
    """QA-TOP-03: every expected relationship has one closed disposition on every axis."""
    case = "TOP-03"
    relationships = [
        _rel(
            "atlas-prompt-injection",
            "AP-T11-01",
            scope="capability_excluded",
            qualification="not_attempted",
            projection="not_attempted",
            kind="capability-gated pattern",
        ),
        _rel(
            "atlas-orphan-risk",
            None,
            scope="governance_only",
            qualification="not_attempted",
            projection="not_attempted",
            kind="governance review",
        ),
        _rel(
            "atlas-memory-poisoning",
            "AP-T1-01",
            scope="applicable",
            qualification="missing_evidence",
            projection="not_attempted",
            kind="missing qualification facts",
        ),
        _rel(
            "atlas-memory-poisoning",
            "AP-T1-04",
            scope="applicable",
            qualification="contradictory_evidence",
            projection="not_attempted",
            kind="contradictory facts",
        ),
        _rel(
            "atlas-memory-poisoning",
            "AP-T1-03",
            scope="applicable",
            qualification="structurally_infeasible",
            projection="not_attempted",
            kind="structurally infeasible",
        ),
        _rel(
            "atlas-prompt-injection",
            "AP-T6-01",
            scope="applicable",
            qualification="ready",
            projection="projectable",
            kind="qualified projectable",
        ),
    ]
    _artifact, plan, _completed = _produce(case, _snapshot(relationships=relationships))
    rows = _obligations(plan)
    _check(case, len(rows) == 6, f"expected 6 obligations, got {len(rows)}")
    for row in rows:
        _check(
            case,
            bool(row.get("scope_disposition")),
            f"blank scope disposition: {row}",
        )
        _check(
            case,
            bool(row.get("qualification_disposition")),
            f"blank qualification disposition: {row}",
        )
        _check(
            case,
            row.get("correspondence_disposition") == "not_assessed",
            f"correspondence {row.get('correspondence_disposition')!r}",
        )
    expected = {
        ("atlas-prompt-injection", "AP-T11-01"),
        ("atlas-orphan-risk", None),
        ("atlas-memory-poisoning", "AP-T1-01"),
        ("atlas-memory-poisoning", "AP-T1-04"),
        ("atlas-memory-poisoning", "AP-T1-03"),
        ("atlas-prompt-injection", "AP-T6-01"),
    }
    actual = {(row.get("risk_id"), row.get("pattern_id")) for row in rows}
    _check(case, actual == expected, f"omitted relationships: {expected - actual}")


def qa_top_04() -> None:
    """QA-TOP-04: closed scope and qualification dispositions are explicit."""
    cases = (
        (
            "capability-gated",
            "capability-gated pattern",
            "atlas-prompt-injection",
            "AP-T11-01",
            "capability_excluded",
            "not_attempted",
            "not_attempted",
        ),
        (
            "missing-evidence",
            "missing qualification facts",
            "atlas-memory-poisoning",
            "AP-T1-01",
            "applicable",
            "missing_evidence",
            "not_attempted",
        ),
        (
            "contradictory-evidence",
            "contradictory facts",
            "atlas-memory-poisoning",
            "AP-T1-04",
            "applicable",
            "contradictory_evidence",
            "not_attempted",
        ),
        (
            "structurally-infeasible",
            "structurally infeasible",
            "atlas-memory-poisoning",
            "AP-T1-03",
            "applicable",
            "structurally_infeasible",
            "not_attempted",
        ),
        (
            "ready",
            "qualified projectable",
            "atlas-prompt-injection",
            "AP-T6-01",
            "applicable",
            "ready",
            "projectable",
        ),
    )
    for label, kind, risk_id, pattern_id, scope, qualification, projection in cases:
        case = f"TOP-04-{label}"
        _artifact, plan, _completed = _produce(
            case,
            _snapshot(
                relationships=[
                    {
                        "risk_id": risk_id,
                        "pattern_id": pattern_id,
                        "relationship_kind": kind,
                    }
                ]
            ),
        )
        row = _row(plan, risk_id, pattern_id)
        _check(
            case, row is not None, f"expected 1 obligation for {risk_id}/{pattern_id}"
        )
        if row is None:
            continue
        _check(
            case,
            row.get("scope_disposition") == scope,
            f"scope {row.get('scope_disposition')!r} != {scope!r}",
        )
        _check(
            case,
            row.get("qualification_disposition") == qualification,
            f"qualification {row.get('qualification_disposition')!r} != {qualification!r}",
        )
        _check(
            case,
            row.get("correspondence_disposition") == "not_assessed",
            f"correspondence {row.get('correspondence_disposition')!r}",
        )
        _check(
            case,
            row.get("projection_disposition") == projection,
            f"projection {row.get('projection_disposition')!r} != {projection!r}",
        )
        evidence = row.get("evidence") or {}
        _check(
            case,
            evidence.get("relationship_kind") == kind,
            f"evidence {evidence!r} missing {kind!r}",
        )


def qa_top_05() -> None:
    """QA-TOP-05: governance-only risks invent no pattern."""
    case = "TOP-05"
    _artifact, plan, _completed = _produce(
        case,
        _snapshot(
            relationships=[
                _rel(
                    "atlas-orphan-risk",
                    None,
                    scope="governance_only",
                    qualification="not_attempted",
                    projection="not_attempted",
                )
            ]
        ),
    )
    rows = [
        row for row in _obligations(plan) if row.get("risk_id") == "atlas-orphan-risk"
    ]
    _check(case, len(rows) == 1, f"expected 1 orphan obligation, got {len(rows)}")
    if rows:
        _check(
            case,
            rows[0].get("scope_disposition") == "governance_only",
            f"scope {rows[0].get('scope_disposition')!r}",
        )
        _check(
            case,
            rows[0].get("qualification_disposition") == "not_attempted",
            f"qualification {rows[0].get('qualification_disposition')!r}",
        )
        _check(
            case,
            rows[0].get("correspondence_disposition") == "not_assessed",
            f"correspondence {rows[0].get('correspondence_disposition')!r}",
        )
        _check(
            case,
            rows[0].get("pattern_id") in (None, ""),
            f"invented pattern {rows[0].get('pattern_id')!r}",
        )


def qa_top_06() -> None:
    """QA-TOP-06: qualification traces omit secrets from sensitive values."""
    case = "TOP-06"
    secret = "SECRET_live_token_END"
    artifact, plan, _completed = _produce(
        case,
        _snapshot(
            config={"api_key": secret},
            relationships=[_ready("atlas-prompt-injection", "AP-T6-01")],
            qualification_evaluations=[
                {
                    "risk_id": "atlas-prompt-injection",
                    "pattern_id": "AP-T6-01",
                    "predicate": "deployment.attacker_code_execution_on_agent_host",
                    "facts": (
                        "deployment.attacker_code_execution_on_agent_host=false "
                        f"token={secret}"
                    ),
                    "result": "false",
                    "reason": "fact present and unequal",
                }
            ],
        ),
    )
    row = _row(plan, "atlas-prompt-injection", "AP-T6-01")
    traces = row.get("qualification_trace") if row else []
    _check(case, isinstance(traces, list) and traces, "qualification trace missing")
    if traces:
        item = traces[0]
        _check(
            case,
            item.get("predicate") == "deployment.attacker_code_execution_on_agent_host",
            f"predicate {item.get('predicate')!r}",
        )
        _check(
            case,
            item.get("facts")
            == "deployment.attacker_code_execution_on_agent_host=false token=[REDACTED]",
            f"facts {item.get('facts')!r}",
        )
        _check(
            case, str(item.get("result")) == "false", f"result {item.get('result')!r}"
        )
        _check(
            case,
            item.get("reason") == "fact present and unequal",
            f"reason {item.get('reason')!r}",
        )
        for field in ("predicate", "facts", "result", "reason"):
            _check(
                case,
                secret not in str(item.get(field, "")),
                f"{field} contains {secret}",
            )
    raw = artifact.read_bytes() if artifact.is_file() else b""
    _check(
        case, secret.encode("utf-8") not in raw, "published artifact contains secret"
    )


def qa_top_07() -> None:
    """QA-TOP-07: candidate records retain projection dispositions."""
    case = "TOP-07"
    projectable = "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    infeasible = "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    deferred = "cand:v2:cccccccccccccccccccccccccccccccc"
    _artifact, plan, _completed = _produce(
        case,
        _snapshot(
            relationships=[_ready("atlas-prompt-injection", "AP-T6-01")],
            candidate_expansions=[
                {
                    "risk_id": "atlas-prompt-injection",
                    "pattern_id": "AP-T6-01",
                    "candidates": [
                        {
                            "candidate_id": projectable,
                            "projection_disposition": "projectable",
                            "reason": "qualified combination",
                        },
                        {
                            "candidate_id": infeasible,
                            "projection_disposition": "projection_infeasible",
                            "reason": "missing required resource",
                        },
                        {
                            "candidate_id": deferred,
                            "projection_disposition": "budget_deferred",
                            "reason": "projection budget exhausted",
                        },
                    ],
                }
            ],
        ),
    )
    row = _row(plan, "atlas-prompt-injection", "AP-T6-01")
    records = (row or {}).get("candidate_records") or []
    by_id = {
        item.get("candidate_id"): item for item in records if isinstance(item, dict)
    }
    expected = (
        (projectable, "projectable", "qualified combination"),
        (infeasible, "projection_infeasible", "missing required resource"),
        (deferred, "budget_deferred", "projection budget exhausted"),
    )
    for candidate_id, disposition, reason in expected:
        item = by_id.get(candidate_id)
        _check(case, item is not None, f"candidate {candidate_id} missing: {records!r}")
        if item is None:
            continue
        _check(
            case,
            item.get("projection_disposition") == disposition,
            f"{candidate_id} disposition {item.get('projection_disposition')!r}",
        )
        _check(
            case,
            item.get("reason") == reason,
            f"{candidate_id} reason {item.get('reason')!r}",
        )


def qa_top_08() -> None:
    """QA-TOP-08: planning records zero network and model calls."""
    case = "TOP-08"
    _check(
        case,
        QA_PIPELINE_ENV not in os.environ,
        f"{QA_PIPELINE_ENV} is set in the parent environment",
    )
    artifact, plan, completed = _produce(
        case,
        _snapshot(
            relationships=[
                _ready("atlas-prompt-injection", "AP-T6-01"),
                _rel(
                    "atlas-prompt-injection",
                    "AP-T11-01",
                    scope="capability_excluded",
                    qualification="not_attempted",
                    projection="not_attempted",
                ),
            ]
        ),
    )
    _check(
        case,
        plan.get("network_calls") == 0,
        f"network_calls={plan.get('network_calls')!r}",
    )
    _check(
        case, plan.get("model_calls") == 0, f"model_calls={plan.get('model_calls')!r}"
    )
    _check(
        case,
        "Network calls: 0" in completed.stdout,
        "console omitted network-call count",
    )
    _check(
        case, "Model calls:   0" in completed.stdout, "console omitted model-call count"
    )
    combined = completed.stdout + completed.stderr
    _check(case, "openai" not in combined.lower(), "LLM client mentioned")
    raw = artifact.read_bytes() if artifact.is_file() else b""
    _check(case, b"sk-" not in raw, "artifact contains a secret-shaped token")


def qa_top_09() -> None:
    """QA-TOP-09: identity-bearing input changes change obligation IDs."""
    pairs = (
        (
            "risk",
            {"relationships": [_ready("atlas-prompt-injection", "AP-T6-01")]},
            {"relationships": [_ready("atlas-memory-poisoning", "AP-T6-01")]},
            "atlas-prompt-injection",
            "atlas-memory-poisoning",
            "risk_id",
        ),
        (
            "pattern",
            {"relationships": [_ready("atlas-prompt-injection", "AP-T6-01")]},
            {"relationships": [_ready("atlas-prompt-injection", "AP-T1-01")]},
            "AP-T6-01",
            "AP-T1-01",
            "pattern_id",
        ),
        (
            "capability",
            {"capability_content": "profile-v1"},
            {"capability_content": "profile-v2"},
            "profile-v1",
            "profile-v2",
            "capability_content",
        ),
        (
            "catalog",
            {"catalog_pin": "atlas-2026.05"},
            {"catalog_pin": "atlas-2026.06"},
            "atlas-2026.05",
            "atlas-2026.06",
            "catalog_pin",
        ),
        (
            "mapping",
            {"mapping_pin": "sssom-v1"},
            {"mapping_pin": "sssom-v2"},
            "sssom-v1",
            "sssom-v2",
            "mapping_pin",
        ),
    )
    for label, extra_a, extra_b, _value_a, _value_b, _axis in pairs:
        case = f"TOP-09-{label}"
        base = {"relationships": [_ready("atlas-prompt-injection", "AP-T6-01")]}
        payload_a = _snapshot(**{**base, **extra_a})
        payload_b = _snapshot(**{**base, **extra_b})
        _artifact_a, plan_a, _completed_a = _produce(f"{case}-a", payload_a)
        _artifact_b, plan_b, _completed_b = _produce(f"{case}-b", payload_b)
        ids_a = [row.get("obligation_id") for row in _obligations(plan_a)]
        ids_b = [row.get("obligation_id") for row in _obligations(plan_b)]
        _check(case, ids_a != ids_b, f"identifiers unchanged: {ids_a}")
        _check(
            case,
            plan_a.get("semantic_digest") != plan_b.get("semantic_digest"),
            "semantic digests unchanged",
        )


def qa_top_10() -> None:
    """QA-TOP-10: ICA prose keyword changes do not change the plan."""
    case = "TOP-10"
    shared = _snapshot(relationships=[_ready("atlas-prompt-injection", "AP-T6-01")])
    _artifact_a, plan_a, _completed_a = _produce(
        f"{case}-a", {**shared, "ica_prose": "the agent injects a prompt"}
    )
    _artifact_b, plan_b, _completed_b = _produce(
        f"{case}-b", {**shared, "ica_prose": "the agent poisons memory"}
    )
    ids_a = [row.get("obligation_id") for row in _obligations(plan_a)]
    ids_b = [row.get("obligation_id") for row in _obligations(plan_b)]
    _check(case, ids_a == ids_b, f"identifiers differ: {ids_a} vs {ids_b}")
    _check(
        case,
        plan_a.get("semantic_digest") == plan_b.get("semantic_digest"),
        "semantic digests differ",
    )
    scopes_a = [row.get("scope_disposition") for row in _obligations(plan_a)]
    scopes_b = [row.get("scope_disposition") for row in _obligations(plan_b)]
    quals_a = [row.get("qualification_disposition") for row in _obligations(plan_a)]
    quals_b = [row.get("qualification_disposition") for row in _obligations(plan_b)]
    _check(
        case,
        scopes_a == scopes_b,
        f"scope dispositions differ: {scopes_a} vs {scopes_b}",
    )
    _check(
        case,
        quals_a == quals_b,
        f"qualification dispositions differ: {quals_a} vs {quals_b}",
    )


def qa_top_11() -> None:
    """QA-TOP-11: invalid scope and qualification combinations are rejected."""
    combinations = (
        ("governance_only", "ready", "AP-T6-01"),
        ("capability_excluded", "missing_evidence", "AP-T6-01"),
        ("applicable", "not_attempted", "AP-T6-01"),
    )
    for scope, qualification, pattern_id in combinations:
        case = f"TOP-11-{scope}-{qualification}"
        output_dir, completed = _reject(
            case,
            _snapshot(
                relationships=[
                    {
                        "risk_id": "atlas-prompt-injection",
                        "pattern_id": None
                        if scope == "governance_only"
                        else pattern_id,
                        "scope_disposition": scope,
                        "qualification_disposition": qualification,
                        "projection_disposition": (
                            "projectable"
                            if qualification == "ready"
                            else "not_attempted"
                        ),
                    }
                ]
            ),
        )
        _check(case, completed.returncode != 0, "planning was accepted")
        published = (
            list(output_dir.glob("taxonomy-obligation-plan.*"))
            if output_dir.exists()
            else []
        )
        _check(case, not published, f"partial plan published: {published}")
        combined = completed.stdout + completed.stderr
        _check(
            case,
            scope in combined,
            f"error omitted scope {scope!r}: {combined[-300:]!r}",
        )
        _check(
            case,
            qualification in combined,
            f"error omitted qualification {qualification!r}: {combined[-300:]!r}",
        )


def _derived_summary(rows: list[dict]) -> dict[str, int]:
    candidate_records = [
        item
        for row in rows
        for item in (row.get("candidate_records") or [])
        if isinstance(item, dict)
    ]
    use_candidates = bool(candidate_records)

    def _count_scope(disposition: str) -> int:
        return sum(1 for row in rows if row.get("scope_disposition") == disposition)

    def _count_qualification(*dispositions: str) -> int:
        return sum(
            1 for row in rows if row.get("qualification_disposition") in dispositions
        )

    def _count_projection(disposition: str) -> int:
        if use_candidates:
            return sum(
                1
                for item in candidate_records
                if item.get("projection_disposition") == disposition
            )
        return sum(
            1 for row in rows if row.get("projection_disposition") == disposition
        )

    return {
        "total": len(rows),
        "applicable": _count_scope("applicable"),
        "governance_only": _count_scope("governance_only"),
        "capability_excluded": _count_scope("capability_excluded"),
        "ready": _count_qualification("ready"),
        "missing_or_contradictory": _count_qualification(
            "missing_evidence", "contradictory_evidence"
        ),
        "structurally_infeasible": _count_qualification("structurally_infeasible"),
        "projectable": _count_projection("projectable"),
        "projection_infeasible": _count_projection("projection_infeasible"),
        "budget_deferred": _count_projection("budget_deferred"),
    }


def qa_top_12() -> None:
    """QA-TOP-12: summary counts are derived from obligation rows."""
    case = "TOP-12"
    artifact, plan, _completed = _produce(
        case,
        _snapshot(
            relationships=[
                _rel(
                    "risk-ready",
                    "AP-T6-01",
                    scope="applicable",
                    qualification="ready",
                    projection="projectable",
                ),
                _rel(
                    "risk-missing",
                    "AP-T1-01",
                    scope="applicable",
                    qualification="missing_evidence",
                    projection="not_attempted",
                ),
                _rel(
                    "risk-contradictory",
                    "AP-T1-02",
                    scope="applicable",
                    qualification="contradictory_evidence",
                    projection="not_attempted",
                ),
                _rel(
                    "risk-struct",
                    "AP-T1-03",
                    scope="applicable",
                    qualification="structurally_infeasible",
                    projection="not_attempted",
                ),
                _rel(
                    "risk-gated",
                    "AP-T11-01",
                    scope="capability_excluded",
                    qualification="not_attempted",
                    projection="not_attempted",
                ),
                _rel(
                    "risk-gov",
                    None,
                    scope="governance_only",
                    qualification="not_attempted",
                    projection="not_attempted",
                ),
            ],
            candidate_expansions=[
                {
                    "risk_id": "risk-ready",
                    "pattern_id": "AP-T6-01",
                    "candidates": [
                        {
                            "candidate_id": "cand:v2:11111111111111111111111111111111",
                            "projection_disposition": "projectable",
                            "reason": "ready",
                        },
                        {
                            "candidate_id": "cand:v2:22222222222222222222222222222222",
                            "projection_disposition": "projection_infeasible",
                            "reason": "infeasible",
                        },
                        {
                            "candidate_id": "cand:v2:33333333333333333333333333333333",
                            "projection_disposition": "budget_deferred",
                            "reason": "deferred",
                        },
                    ],
                }
            ],
        ),
    )
    rows = _obligations(plan)
    derived = _derived_summary(rows)
    expected = {
        "total": 6,
        "applicable": 4,
        "governance_only": 1,
        "capability_excluded": 1,
        "ready": 1,
        "missing_or_contradictory": 2,
        "structurally_infeasible": 1,
        "projectable": 1,
        "projection_infeasible": 1,
        "budget_deferred": 1,
    }
    summary = plan.get("summary") if isinstance(plan.get("summary"), dict) else {}
    for key, value in expected.items():
        _check(
            case,
            summary.get(key) == value,
            f"summary.{key}={summary.get(key)!r} != {value}",
        )
        _check(
            case,
            derived.get(key) == value,
            f"derived.{key}={derived.get(key)!r} != {value}",
        )
        _check(
            case,
            summary.get(key) == derived.get(key),
            f"summary.{key} drifted from rows",
        )
    raw = artifact.read_text(encoding="utf-8") if artifact.is_file() else ""
    _check(
        case,
        "taxonomy_correspondence_rate" not in summary
        and "taxonomy correspondence rate" not in raw.lower(),
        "summary includes a taxonomy correspondence rate",
    )
    _check(
        case,
        "scenario_realization_rate" not in summary
        and "scenario realization rate" not in raw.lower(),
        "summary includes a scenario realization rate",
    )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    for procedure in (
        qa_top_01,
        qa_top_02,
        qa_top_03,
        qa_top_04,
        qa_top_05,
        qa_top_06,
        qa_top_07,
        qa_top_08,
        qa_top_09,
        qa_top_10,
        qa_top_11,
        qa_top_12,
    ):
        procedure()
        print(f"  [done] {procedure.__name__}", flush=True)
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
    / "qa-taxonomy-obligation-planner"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Executable end-to-end QA suite for the taxonomy obligation planner.

Mirrors ``obligation_planner.md`` (QA-TOP-01..08).  Drives the public
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
    "taxonomy_version": "atlas-2026.05",
    "mapping_version": "sssom-v1",
    "qualification_ruleset_version": "catalog-qualification-v1",
    "template_version": "scenario-envelope-v1",
    "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
    disposition: str,
) -> dict:
    return {
        "risk_id": risk_id,
        "pattern_id": pattern_id,
        "scope": scope,
        "disposition": disposition,
    }


def _snapshot(**overrides: object) -> dict:
    payload: dict[str, object] = {
        **PINNED,
        "relationships": [],
        "risk_cards": [],
        "config": {},
        "qualification_evaluations": [],
        "candidate_expansions": [],
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


def _plan_argv(snapshot: Path, output_dir: Path, fmt: str = "both") -> list[str]:
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
    artifact = output_dir / (
        "obligation-plan.json" if fmt == "json" else "obligation-plan.yaml"
    )
    _check(case, artifact.is_file(), f"missing published artifact {artifact.name}")
    plan = _load_yaml(artifact) if artifact.is_file() else {}
    return artifact, plan, completed


def _obligations(plan: dict) -> list[dict]:
    rows = plan.get("obligations")
    return rows if isinstance(rows, list) else []


def qa_top_01() -> None:
    """QA-TOP-01: shared pattern keeps distinct risk-scoped obligations."""
    case = "TOP-01"
    artifact, plan, completed = _produce(
        case,
        _snapshot(
            relationships=[
                _rel(
                    "atlas-prompt-injection",
                    "AP-T1-01",
                    scope="in-scope",
                    disposition="generated",
                ),
                _rel(
                    "atlas-memory-poisoning",
                    "AP-T1-01",
                    scope="in-scope",
                    disposition="missing-template",
                ),
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
    """QA-TOP-02: in-scope and out-of-scope relationships are both recorded."""
    case = "TOP-02"
    _artifact, plan, _completed = _produce(
        case,
        _snapshot(
            relationships=[
                _rel(
                    "atlas-prompt-injection",
                    "AP-T6-01",
                    scope="in-scope",
                    disposition="generated",
                ),
                _rel(
                    "atlas-prompt-injection",
                    "AP-T11-01",
                    scope="out-of-scope",
                    disposition="gated",
                ),
            ]
        ),
    )
    rows = {
        (row.get("risk_id"), row.get("pattern_id"), row.get("scope"))
        for row in _obligations(plan)
    }
    _check(
        case,
        ("atlas-prompt-injection", "AP-T6-01", "in-scope") in rows,
        f"missing in-scope AP-T6-01: {rows}",
    )
    _check(
        case,
        ("atlas-prompt-injection", "AP-T11-01", "out-of-scope") in rows,
        f"missing out-of-scope AP-T11-01: {rows}",
    )


def qa_top_03() -> None:
    """QA-TOP-03: every expected relationship has one terminal outcome."""
    case = "TOP-03"
    relationships = [
        _rel(
            "atlas-prompt-injection",
            "AP-T11-01",
            scope="out-of-scope",
            disposition="gated",
        ),
        _rel(
            "atlas-orphan-risk", None, scope="in-scope", disposition="governance-only"
        ),
        _rel(
            "atlas-memory-poisoning",
            "AP-T1-01",
            scope="in-scope",
            disposition="missing-template",
        ),
        _rel(
            "atlas-memory-poisoning",
            "AP-T1-02",
            scope="in-scope",
            disposition="infeasible",
        ),
        _rel(
            "atlas-memory-poisoning",
            "AP-T1-03",
            scope="in-scope",
            disposition="unsupported",
        ),
        _rel(
            "atlas-prompt-injection",
            "AP-T6-01",
            scope="in-scope",
            disposition="generated",
        ),
    ]
    _artifact, plan, _completed = _produce(case, _snapshot(relationships=relationships))
    rows = _obligations(plan)
    _check(case, len(rows) == 6, f"expected 6 obligations, got {len(rows)}")
    dispositions = [row.get("terminal_disposition") for row in rows]
    _check(case, all(dispositions), f"blank terminal disposition: {dispositions}")
    _check(case, len(dispositions) == 6, "disposition count drifted")
    expected = {
        ("atlas-prompt-injection", "AP-T11-01"),
        ("atlas-orphan-risk", None),
        ("atlas-memory-poisoning", "AP-T1-01"),
        ("atlas-memory-poisoning", "AP-T1-02"),
        ("atlas-memory-poisoning", "AP-T1-03"),
        ("atlas-prompt-injection", "AP-T6-01"),
    }
    actual = {(row.get("risk_id"), row.get("pattern_id")) for row in rows}
    _check(case, actual == expected, f"omitted relationships: {expected - actual}")


def qa_top_04() -> None:
    """QA-TOP-04: pattern-bearing terminal dispositions are explicit."""
    cases = (
        (
            "gated",
            "atlas-prompt-injection",
            "AP-T11-01",
            "out-of-scope",
            "gated",
        ),
        (
            "missing-template",
            "atlas-memory-poisoning",
            "AP-T1-01",
            "in-scope",
            "missing-template",
        ),
        (
            "infeasible",
            "atlas-memory-poisoning",
            "AP-T1-02",
            "in-scope",
            "infeasible",
        ),
        (
            "unsupported",
            "atlas-memory-poisoning",
            "AP-T1-03",
            "in-scope",
            "unsupported",
        ),
        (
            "generated",
            "atlas-prompt-injection",
            "AP-T6-01",
            "in-scope",
            "generated",
        ),
    )
    for label, risk_id, pattern_id, scope, disposition in cases:
        case = f"TOP-04-{label}"
        _artifact, plan, _completed = _produce(
            case,
            _snapshot(
                relationships=[
                    _rel(risk_id, pattern_id, scope=scope, disposition=disposition)
                ]
            ),
        )
        rows = [
            row
            for row in _obligations(plan)
            if row.get("risk_id") == risk_id and row.get("pattern_id") == pattern_id
        ]
        _check(case, len(rows) == 1, f"expected 1 obligation, got {len(rows)}")
        if rows:
            _check(
                case,
                rows[0].get("scope") == scope,
                f"scope {rows[0].get('scope')!r} != {scope!r}",
            )
            _check(
                case,
                rows[0].get("terminal_disposition") == disposition,
                f"disposition {rows[0].get('terminal_disposition')!r} != {disposition!r}",
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
                    scope="in-scope",
                    disposition="governance-only",
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
            rows[0].get("terminal_disposition") == "governance-only",
            f"disposition {rows[0].get('terminal_disposition')!r}",
        )
        _check(
            case,
            rows[0].get("pattern_id") in (None, ""),
            f"invented pattern {rows[0].get('pattern_id')!r}",
        )


def qa_top_06() -> None:
    """QA-TOP-06: qualification traces omit secrets."""
    case = "TOP-06"
    secret = "sk-live-token"
    artifact, plan, _completed = _produce(
        case,
        _snapshot(
            config={"api_key": secret},
            relationships=[
                _rel(
                    "atlas-prompt-injection",
                    "AP-T6-01",
                    scope="in-scope",
                    disposition="generated",
                )
            ],
            qualification_evaluations=[
                {
                    "risk_id": "atlas-prompt-injection",
                    "pattern_id": "AP-T6-01",
                    "predicate": "deployment.attacker_code_execution_on_agent_host",
                    "facts": "deployment.attacker_code_execution_on_agent_host=false",
                    "result": "false",
                    "reason": "fact present and unequal",
                }
            ],
        ),
    )
    rows = _obligations(plan)
    traces = rows[0].get("qualification_trace") if rows else []
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
            == "deployment.attacker_code_execution_on_agent_host=false",
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
    raw = artifact.read_bytes() if artifact.is_file() else b""
    _check(
        case,
        secret.encode("utf-8") not in raw,
        "published artifact contains sk-live-token",
    )


def qa_top_07() -> None:
    """QA-TOP-07: accepted and rejected candidates are retained."""
    case = "TOP-07"
    accepted = "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    rejected = "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    _artifact, plan, _completed = _produce(
        case,
        _snapshot(
            relationships=[
                _rel(
                    "atlas-prompt-injection",
                    "AP-T6-01",
                    scope="in-scope",
                    disposition="generated",
                )
            ],
            candidate_expansions=[
                {
                    "risk_id": "atlas-prompt-injection",
                    "pattern_id": "AP-T6-01",
                    "accepted_candidates": [accepted],
                    "rejected_candidates": [
                        {
                            "candidate_id": rejected,
                            "reason": "rule rejected combination",
                        }
                    ],
                }
            ],
        ),
    )
    rows = _obligations(plan)
    _check(case, rows, "ledger empty")
    if rows:
        _check(
            case,
            accepted in (rows[0].get("accepted_candidates") or []),
            f"accepted candidate missing: {rows[0].get('accepted_candidates')!r}",
        )
        rejected_rows = rows[0].get("rejected_candidates") or []
        match = next(
            (
                item
                for item in rejected_rows
                if isinstance(item, dict) and item.get("candidate_id") == rejected
            ),
            None,
        )
        _check(
            case, match is not None, f"rejected candidate missing: {rejected_rows!r}"
        )
        if match is not None:
            _check(
                case,
                match.get("reason") == "rule rejected combination",
                f"rejected reason {match.get('reason')!r}",
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
                _rel(
                    "atlas-prompt-injection",
                    "AP-T6-01",
                    scope="in-scope",
                    disposition="generated",
                ),
                _rel(
                    "atlas-prompt-injection",
                    "AP-T11-01",
                    scope="out-of-scope",
                    disposition="gated",
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

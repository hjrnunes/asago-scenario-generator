#!/usr/bin/env python3
"""Executable end-to-end QA suite for the taxonomy obligation plan artifact.

Mirrors ``obligation_plan_artifact.md`` (QA-TOPA-01..04).  Drives the public
``asago-scenario-generator plan-obligations`` file-to-file command and
inspects published YAML and JSON with standard readers and byte comparison.
Never imports project modules, never calls ``plan_obligations``, and never
sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Run with::

    uv run python acceptance/qa/taxonomy_risk/obligation_plan_artifact.py

Exit status is 0 only when every pinned assertion passes.
"""

from __future__ import annotations

import json
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


def _rel(risk_id: str, pattern_id: str, *, disposition: str = "generated") -> dict:
    return {
        "risk_id": risk_id,
        "pattern_id": pattern_id,
        "scope": "in-scope",
        "disposition": disposition,
    }


def _snapshot(relationships: list[dict], **overrides: object) -> dict:
    payload: dict[str, object] = {
        **PINNED,
        "relationships": relationships,
        "risk_cards": [],
        "config": {},
        "qualification_evaluations": [],
        "candidate_expansions": [],
    }
    payload.update(overrides)
    return payload


def _rich_snapshot() -> dict:
    return _snapshot(
        [
            _rel("atlas-prompt-injection", "AP-T6-01"),
            _rel("atlas-memory-poisoning", "AP-T1-01", disposition="missing-template"),
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
        candidate_expansions=[
            {
                "risk_id": "atlas-prompt-injection",
                "pattern_id": "AP-T6-01",
                "accepted_candidates": ["cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "rejected_candidates": [
                    {
                        "candidate_id": "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "reason": "rule rejected combination",
                    }
                ],
            }
        ],
    )


def _new_workspace(case: str) -> Path:
    ws = RUN_ROOT / "workspaces" / case
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    return ws


def _run_cli(case: str, argv: list[str]) -> subprocess.CompletedProcess[str]:
    capture_dir = RUN_ROOT / "captures" / case
    capture_dir.mkdir(parents=True, exist_ok=True)
    child = os.environ.copy()
    child.pop(QA_PIPELINE_ENV, None)
    child.pop("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None)
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
    return completed


def _plan(case: str, payload: dict, *, fmt: str) -> tuple[Path, bytes, dict]:
    ws = _new_workspace(case)
    snapshot = ws / "snapshot.yaml"
    snapshot.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    output_dir = ws / "plan"
    argv = [
        *_command(),
        "plan-obligations",
        "--snapshot",
        str(snapshot),
        "--output-dir",
        str(output_dir),
        "--format",
        fmt,
    ]
    completed = _run_cli(case, argv)
    if completed.returncode != 0:
        failures.append(
            f"{case}: exit {completed.returncode}: {completed.stderr[-300:]!r}"
        )
    name = "obligation-plan.json" if fmt == "json" else "obligation-plan.yaml"
    artifact = output_dir / name
    if not artifact.is_file():
        failures.append(f"{case}: missing {name}")
        return artifact, b"", {}
    raw = artifact.read_bytes()
    parsed = json.loads(raw) if fmt == "json" else yaml.safe_load(raw)
    if not isinstance(parsed, dict):
        failures.append(f"{case}: {name} is not a mapping")
        return artifact, raw, {}
    return artifact, raw, parsed


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def qa_topa_01() -> None:
    """QA-TOPA-01: pinned snapshot versions are copied into the plan."""
    case = "TOPA-01"
    _artifact, _raw, plan = _plan(
        case, _snapshot([_rel("atlas-prompt-injection", "AP-T6-01")]), fmt="yaml"
    )
    for key, expected in PINNED.items():
        _check(
            case, plan.get(key) == expected, f"{key} {plan.get(key)!r} != {expected!r}"
        )


def qa_topa_02() -> None:
    """QA-TOPA-02: identifiers and order ignore presentation order."""
    order_a = [
        _rel("atlas-prompt-injection", "AP-T6-01"),
        _rel("atlas-memory-poisoning", "AP-T1-01", disposition="missing-template"),
    ]
    order_b = list(reversed(order_a))
    _a_path, a_raw, plan_a = _plan("TOPA-02-a", _snapshot(order_a), fmt="yaml")
    _b_path, b_raw, plan_b = _plan("TOPA-02-b", _snapshot(order_b), fmt="yaml")
    ids_a = [row.get("obligation_id") for row in plan_a.get("obligations") or []]
    ids_b = [row.get("obligation_id") for row in plan_b.get("obligations") or []]
    _check("TOPA-02", ids_a == ids_b, f"identifiers differ: {ids_a} vs {ids_b}")
    _check(
        "TOPA-02",
        ids_a == sorted(ids_a or []),
        f"ledger order is not canonical: {ids_a}",
    )
    _check(
        "TOPA-02", a_raw == b_raw, "serialized YAML artifacts are not byte-identical"
    )


def qa_topa_03() -> None:
    """QA-TOPA-03: YAML and JSON round-trip without semantic loss."""
    snapshot = _rich_snapshot()
    _yaml_path, yaml_raw, yaml_plan = _plan("TOPA-03-yaml", snapshot, fmt="yaml")
    _json_path, json_raw, json_plan = _plan("TOPA-03-json", snapshot, fmt="json")
    yaml_again = yaml.safe_load(yaml_raw)
    json_again = json.loads(json_raw)
    for label, original, round_tripped in (
        ("YAML", yaml_plan, yaml_again),
        ("JSON", json_plan, json_again),
    ):
        case = f"TOPA-03-{label.lower()}"
        orig_ids = [
            row.get("obligation_id") for row in original.get("obligations") or []
        ]
        rt_ids = [
            row.get("obligation_id") for row in round_tripped.get("obligations") or []
        ]
        _check(case, orig_ids == rt_ids, f"identities lost: {orig_ids} vs {rt_ids}")
        for key in PINNED:
            _check(case, original.get(key) == round_tripped.get(key), f"{key} lost")
        orig_disp = [
            row.get("terminal_disposition") for row in original.get("obligations") or []
        ]
        rt_disp = [
            row.get("terminal_disposition")
            for row in round_tripped.get("obligations") or []
        ]
        _check(
            case, orig_disp == rt_disp, f"dispositions lost: {orig_disp} vs {rt_disp}"
        )
        orig_trace = [
            row.get("qualification_trace") for row in original.get("obligations") or []
        ]
        rt_trace = [
            row.get("qualification_trace")
            for row in round_tripped.get("obligations") or []
        ]
        _check(case, orig_trace == rt_trace, "qualification traces lost")
        orig_cands = [
            (row.get("accepted_candidates"), row.get("rejected_candidates"))
            for row in original.get("obligations") or []
        ]
        rt_cands = [
            (row.get("accepted_candidates"), row.get("rejected_candidates"))
            for row in round_tripped.get("obligations") or []
        ]
        _check(case, orig_cands == rt_cands, "candidate evidence lost")


def qa_topa_04() -> None:
    """QA-TOPA-04: identical inputs are byte-stable."""
    snapshot = _rich_snapshot()
    for fmt in ("yaml", "json"):
        _p1, raw1, _plan1 = _plan(f"TOPA-04-{fmt}-1", snapshot, fmt=fmt)
        _p2, raw2, _plan2 = _plan(f"TOPA-04-{fmt}-2", snapshot, fmt=fmt)
        _check(
            f"TOPA-04-{fmt}", raw1 == raw2, f"{fmt} artifacts are not byte-identical"
        )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    for procedure in (qa_topa_01, qa_topa_02, qa_topa_03, qa_topa_04):
        procedure()
        print(f"  [done] {procedure.__name__}", flush=True)
    print("\n=== SUMMARY ===", flush=True)
    print(f"  Failures: {len(failures)}", flush=True)
    for failure in failures:
        print(f"    - {failure}", flush=True)
    print("  Result: FAIL" if failures else "  Result: PASS", flush=True)
    return 1 if failures else 0


RUN_ROOT = (
    REPO_ROOT
    / "tmp"
    / "qa-taxonomy-obligation-plan-artifact"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

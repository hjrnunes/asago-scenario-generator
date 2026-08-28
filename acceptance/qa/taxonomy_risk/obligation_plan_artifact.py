#!/usr/bin/env python3
"""Executable end-to-end QA suite for the taxonomy obligation plan artifact.

Mirrors ``obligation_plan_artifact.md`` (QA-TOPA-01..10).  Drives the public
``asago-scenario-generator plan-obligations`` and
``validate-obligation-plan`` file-to-file commands and inspects published
YAML and JSON with standard readers and byte comparison.  Never imports
project modules, never calls ``plan_obligations``, and never sets
``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Run with::

    uv run python acceptance/qa/taxonomy_risk/obligation_plan_artifact.py

Exit status is 0 only when every pinned assertion passes.
"""

from __future__ import annotations

import hashlib
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
    scope: str = "applicable",
    qualification: str = "ready",
    projection: str = "projectable",
) -> dict:
    return {
        "risk_id": risk_id,
        "pattern_id": pattern_id,
        "scope_disposition": scope,
        "qualification_disposition": qualification,
        "projection_disposition": projection,
    }


def _snapshot(relationships: list[dict], **overrides: object) -> dict:
    payload: dict[str, object] = {
        **PINNED,
        "relationships": relationships,
        "risk_cards": [],
        "config": {},
        "qualification_evaluations": [],
        "candidate_expansions": [],
        "ica_prose": "",
    }
    payload.update(overrides)
    return payload


def _rich_snapshot() -> dict:
    return _snapshot(
        [
            _rel("atlas-prompt-injection", "AP-T6-01"),
            _rel(
                "atlas-memory-poisoning",
                "AP-T1-01",
                qualification="missing_evidence",
                projection="not_attempted",
            ),
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
                "candidates": [
                    {
                        "candidate_id": "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "projection_disposition": "projectable",
                        "reason": "qualified combination",
                    },
                    {
                        "candidate_id": "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "projection_disposition": "projection_infeasible",
                        "reason": "missing required resource",
                    },
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


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def _artifact_name(fmt: str) -> str:
    return (
        "taxonomy-obligation-plan.json"
        if fmt == "json"
        else "taxonomy-obligation-plan.yaml"
    )


def _parse(raw: bytes, fmt: str) -> dict:
    parsed = json.loads(raw) if fmt == "json" else yaml.safe_load(raw)
    return parsed if isinstance(parsed, dict) else {}


def _sha256(value: object) -> str:
    if isinstance(value, str):
        content = value.encode("utf-8")
    else:
        content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    return hashlib.sha256(content).hexdigest()


def _plan(case: str, payload: dict, *, fmt: str) -> tuple[Path, bytes, dict]:
    ws = _new_workspace(case)
    snapshot = ws / "snapshot.yaml"
    snapshot.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    output_dir = ws / "plan"
    completed = _run_cli(
        case,
        [
            *_command(),
            "plan-obligations",
            "--snapshot",
            str(snapshot),
            "--output-dir",
            str(output_dir),
            "--format",
            fmt,
        ],
    )
    if completed.returncode != 0:
        failures.append(
            f"{case}: exit {completed.returncode}: {completed.stderr[-300:]!r}"
        )
    artifact = output_dir / _artifact_name(fmt)
    if not artifact.is_file():
        failures.append(f"{case}: missing {_artifact_name(fmt)}")
        return artifact, b"", {}
    raw = artifact.read_bytes()
    parsed = _parse(raw, fmt)
    if not parsed:
        failures.append(f"{case}: {_artifact_name(fmt)} is not a mapping")
        return artifact, raw, {}
    return artifact, raw, parsed


def _validate(case: str, artifact: Path) -> subprocess.CompletedProcess[str]:
    return _run_cli(
        case,
        [*_command(), "validate-obligation-plan", "--plan", str(artifact)],
    )


def _write_persisted(case: str, payload: dict, *, fmt: str) -> Path:
    ws = _new_workspace(case)
    name = _artifact_name(fmt)
    path = ws / name
    if fmt == "json":
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    else:
        path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    return path


def qa_topa_01() -> None:
    """QA-TOPA-01: closed schema metadata is computed from canonical content."""
    case = "TOPA-01"
    _artifact, _raw, plan = _plan(
        case,
        _snapshot([_rel("atlas-prompt-injection", "AP-T6-01")]),
        fmt="yaml",
    )
    _check(
        case,
        plan.get("schema_version") == "taxonomy-obligation-plan-v1",
        f"schema_version {plan.get('schema_version')!r}",
    )
    catalog_pins = plan.get("catalog_pins") or {}
    mapping_pins = plan.get("mapping_pins") or {}
    _check(
        case,
        "atlas-2026.05" in list(catalog_pins.values()),
        f"catalog pins {catalog_pins!r}",
    )
    _check(
        case,
        "sssom-v1" in list(mapping_pins.values()),
        f"mapping pins {mapping_pins!r}",
    )
    expected_cap = _sha256("profile-v1")
    expected_facts = _sha256("facts-v1")
    _check(
        case,
        plan.get("capability_snapshot_digest") == expected_cap,
        f"capability digest {plan.get('capability_snapshot_digest')!r}",
    )
    _check(
        case,
        plan.get("qualification_facts_digest") == expected_facts,
        f"qualification digest {plan.get('qualification_facts_digest')!r}",
    )
    for key in (
        "capability_snapshot_digest",
        "qualification_facts_digest",
        "generation_inputs_digest",
        "semantic_digest",
    ):
        value = plan.get(key)
        _check(
            case,
            isinstance(value, str) and len(value) == 64,
            f"{key} is not a computed digest: {value!r}",
        )


def qa_topa_02() -> None:
    """QA-TOPA-02: identifiers and digests ignore presentation order."""
    order_a = [
        _rel("atlas-prompt-injection", "AP-T6-01"),
        _rel(
            "atlas-memory-poisoning",
            "AP-T1-01",
            qualification="missing_evidence",
            projection="not_attempted",
        ),
    ]
    order_b = list(reversed(order_a))
    _a_path, a_raw, plan_a = _plan("TOPA-02-a", _snapshot(order_a), fmt="yaml")
    _b_path, b_raw, plan_b = _plan("TOPA-02-b", _snapshot(order_b), fmt="yaml")
    ids_a = [row.get("obligation_id") for row in plan_a.get("obligations") or []]
    ids_b = [row.get("obligation_id") for row in plan_b.get("obligations") or []]
    _check("TOPA-02", ids_a == ids_b, f"identifiers differ: {ids_a} vs {ids_b}")
    _check(
        "TOPA-02",
        plan_a.get("semantic_digest") == plan_b.get("semantic_digest"),
        "semantic digests differ",
    )
    _check(
        "TOPA-02",
        ids_a == ids_b,
        f"canonical ledger order differs: {ids_a} vs {ids_b}",
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
        for key in (
            "schema_version",
            "catalog_pins",
            "mapping_pins",
            "capability_snapshot_digest",
            "qualification_facts_digest",
            "generation_inputs_digest",
            "semantic_digest",
        ):
            _check(case, original.get(key) == round_tripped.get(key), f"{key} lost")
        orig_disp = [
            (
                row.get("scope_disposition"),
                row.get("qualification_disposition"),
                row.get("projection_disposition"),
                row.get("correspondence_disposition"),
            )
            for row in original.get("obligations") or []
        ]
        rt_disp = [
            (
                row.get("scope_disposition"),
                row.get("qualification_disposition"),
                row.get("projection_disposition"),
                row.get("correspondence_disposition"),
            )
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
            row.get("candidate_records") for row in original.get("obligations") or []
        ]
        rt_cands = [
            row.get("candidate_records")
            for row in round_tripped.get("obligations") or []
        ]
        _check(case, orig_cands == rt_cands, "candidate records lost")
        _check(
            case,
            original.get("summary") == round_tripped.get("summary"),
            "summary counts lost",
        )


def qa_topa_04() -> None:
    """QA-TOPA-04: identical inputs are byte-stable."""
    snapshot = _rich_snapshot()
    for fmt in ("yaml", "json"):
        _p1, raw1, _plan1 = _plan(f"TOPA-04-{fmt}-1", snapshot, fmt=fmt)
        _p2, raw2, _plan2 = _plan(f"TOPA-04-{fmt}-2", snapshot, fmt=fmt)
        _check(
            f"TOPA-04-{fmt}", raw1 == raw2, f"{fmt} artifacts are not byte-identical"
        )


def qa_topa_05() -> None:
    """QA-TOPA-05: tampered persisted content is rejected."""
    cases = (
        ("yaml", "catalog_pins"),
        ("json", "mapping_pins"),
        ("yaml", "obligations"),
    )
    for fmt, field in cases:
        case = f"TOPA-05-{fmt}-{field}"
        artifact, raw, plan = _plan(f"{case}-publish", _rich_snapshot(), fmt=fmt)
        if not plan:
            continue
        payload = _parse(raw, fmt)
        if field == "catalog_pins":
            pins = payload.setdefault("catalog_pins", {})
            if isinstance(pins, dict):
                pins["tampered"] = "atlas-tampered-2099"
            else:
                payload["catalog_pins"] = ["atlas-tampered-2099"]
        elif field == "mapping_pins":
            pins = payload.setdefault("mapping_pins", {})
            if isinstance(pins, dict):
                pins["tampered"] = "tampered-mapping-v99"
            else:
                payload["mapping_pins"] = ["tampered-mapping-v99"]
        else:
            rows = payload.get("obligations") or []
            if rows and isinstance(rows[0], dict):
                rows[0]["risk_id"] = "tampered-risk"
        tampered = artifact.with_name(f"tampered-{artifact.name}")
        if fmt == "json":
            tampered.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        else:
            tampered.write_text(
                yaml.safe_dump(payload, sort_keys=True), encoding="utf-8"
            )
        completed = _validate(case, tampered)
        _check(case, completed.returncode != 0, "tampered plan was accepted")
        combined = completed.stdout + completed.stderr
        _check(
            case,
            "digest" in combined.lower() and "mismatch" in combined.lower(),
            f"error omitted digest mismatch: {combined[-300:]!r}",
        )


def qa_topa_06() -> None:
    """QA-TOPA-06: unknown fields are rejected."""
    artifact, _raw, plan = _plan("TOPA-06-base", _rich_snapshot(), fmt="json")
    if not plan:
        return
    for field in ("extra_score", "covered_rate"):
        case = f"TOPA-06-{field}"
        payload = dict(plan)
        payload[field] = 12345
        path = _write_persisted(case, payload, fmt="json")
        completed = _validate(case, path)
        _check(case, completed.returncode != 0, f"{field} was accepted")
        combined = completed.stdout + completed.stderr
        _check(
            case,
            field in combined,
            f"error omitted unknown field {field!r}: {combined[-300:]!r}",
        )


def qa_topa_07() -> None:
    """QA-TOPA-07: unsupported schema versions are rejected."""
    artifact, _raw, plan = _plan("TOPA-07-base", _rich_snapshot(), fmt="json")
    if not plan:
        return
    for version in ("taxonomy-obligation-plan-v0", "taxonomy-obligation-plan-v2"):
        case = f"TOPA-07-{version}"
        payload = dict(plan)
        payload["schema_version"] = version
        path = _write_persisted(case, payload, fmt="json")
        completed = _validate(case, path)
        _check(case, completed.returncode != 0, f"{version} was accepted")
        combined = completed.stdout + completed.stderr
        _check(
            case,
            version in combined and "unsupported" in combined.lower(),
            f"error omitted unsupported {version!r}: {combined[-300:]!r}",
        )


def qa_topa_08() -> None:
    """QA-TOPA-08: caller-supplied false digests are ignored."""
    cases = (
        (
            "capability_snapshot_digest",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ),
        (
            "semantic_digest",
            "cafebebecafebebecafebebecafebebecafebebecafebebecafebebecafebebe",
        ),
        (
            "qualification_facts_digest",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
    )
    for digest_kind, false_digest in cases:
        case = f"TOPA-08-{digest_kind}"
        payload = _snapshot(
            [_rel("atlas-prompt-injection", "AP-T6-01")],
            **{digest_kind: false_digest},
        )
        _artifact, _raw, plan = _plan(case, payload, fmt="yaml")
        recorded = plan.get(digest_kind)
        _check(
            case,
            recorded != false_digest,
            f"plan recorded false {digest_kind}={recorded!r}",
        )
        _check(
            case,
            isinstance(recorded, str) and len(recorded) == 64,
            f"{digest_kind} is not a computed digest: {recorded!r}",
        )


def qa_topa_09() -> None:
    """QA-TOPA-09: YAML publication is atomic."""
    case = "TOPA-09"
    artifact, _raw, plan = _plan(case, _rich_snapshot(), fmt="yaml")
    _check(
        case,
        artifact.name == "taxonomy-obligation-plan.yaml",
        f"published name {artifact.name!r}",
    )
    published_names = {
        path.name for path in artifact.parent.iterdir() if path.is_file()
    }
    _check(
        case,
        "taxonomy-obligation-plan.yaml" in published_names,
        f"exact YAML name missing from {published_names}",
    )
    completed = _validate(f"{case}-load", artifact)
    _check(
        case,
        completed.returncode == 0,
        f"published YAML did not load: {completed.stderr[-300:]!r}",
    )
    _check(case, bool(plan.get("obligations")), "published plan is incomplete")
    leftovers = list(artifact.parent.glob("*.tmp")) + list(
        artifact.parent.glob("*.part")
    )
    _check(case, not leftovers, f"partial plan files remained: {leftovers}")


def qa_topa_10() -> None:
    """QA-TOPA-10: Phase 1 correspondence claims are rejected."""
    artifact, _raw, plan = _plan("TOPA-10-base", _rich_snapshot(), fmt="json")
    if not plan:
        return
    for disposition in ("covered", "matched", "satisfied"):
        case = f"TOPA-10-{disposition}"
        payload = json.loads(json.dumps(plan))
        rows = payload.get("obligations") or []
        if rows and isinstance(rows[0], dict):
            rows[0]["correspondence_disposition"] = disposition
        path = _write_persisted(case, payload, fmt="json")
        completed = _validate(case, path)
        _check(case, completed.returncode != 0, f"{disposition} was accepted")
        combined = completed.stdout + completed.stderr
        _check(
            case,
            disposition in combined and "invalid" in combined.lower(),
            f"error omitted invalid correspondence {disposition!r}: {combined[-300:]!r}",
        )


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    for procedure in (
        qa_topa_01,
        qa_topa_02,
        qa_topa_03,
        qa_topa_04,
        qa_topa_05,
        qa_topa_06,
        qa_topa_07,
        qa_topa_08,
        qa_topa_09,
        qa_topa_10,
    ):
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

#!/usr/bin/env python3
"""Offline end-to-end QA for the YAML taxonomy-obligation artifact.

The checks drive the public ``plan-obligations`` file adapter and inspect its
published YAML with standard readers. Inputs contain complete serialized
``AttackPattern`` and ``CapabilityFactSnapshot`` records from the shared
projection fixture; candidate records are never caller-supplied. No project
planner is imported, no endpoint is contacted, and no legacy snapshot shape is
accepted as normative input.

Run with::

    uv run python acceptance/qa/taxonomy_risk/obligation_plan_artifact.py
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import unicodedata
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
QA_PIPELINE_ENV = "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"
failures: list[str] = []

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_SEARCH_PATH = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
_UV = shutil.which("uv", path=_SEARCH_PATH) or "uv"
_ZERO = "0" * 64


def _authoritative_fixture() -> tuple[Any, dict[str, Any], Any]:
    """Load the shared full pattern, candidate, and capability snapshot."""
    from tests.helpers.projection_factory import (
        get_projected_candidate,
        get_test_raw_pattern,
        get_test_snapshot,
    )

    return get_projected_candidate(), get_test_raw_pattern(), get_test_snapshot()


def _canonical_json(value: Any) -> bytes:
    """Encode fixture values with the planner's canonical JSON conventions."""
    return json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_value(value: Any) -> Any:
    """Mirror the project's canonical JSON normalization without importing it."""
    if hasattr(value, "model_dump"):
        return _canonical_value(value.model_dump(mode="json"))
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical JSON mapping keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("canonical mapping keys collide after normalization")
            normalized[normalized_key] = _canonical_value(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def _typed_dump(value: Any) -> dict[str, Any]:
    """Return a full JSON-mode row dump for the standalone digest mirror."""
    dumped = (
        value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)
    )
    if not isinstance(dumped, dict):
        raise TypeError("mapping rows must dump to mappings")
    return dumped


def _canonical_cross_mapping(value: Any) -> dict[str, Any]:
    """Mirror the typed cross-taxonomy row dump and evidence set contract."""
    row = _typed_dump(value)
    evidence = row.get("evidence", ())
    return {
        "source_id": row["source_id"],
        "target_id": row["target_id"],
        "relation": row.get("relation", "related_match"),
        "evidence": sorted({_canonical_value(item) for item in evidence}),
        "confidence": row.get("confidence"),
        "source_taxonomy": row.get("source_taxonomy"),
        "target_taxonomy": row.get("target_taxonomy"),
    }


def _canonical_sssom_mapping(value: Any) -> dict[str, Any]:
    """Mirror the full typed SSSOM row dump for the standalone digest."""
    row = _typed_dump(value)
    return {
        "subject_id": row["subject_id"],
        "object_id": row["object_id"],
        "predicate_id": row["predicate_id"],
        "subject_source": row["subject_source"],
        "object_source": row["object_source"],
        "mapping_justification": row["mapping_justification"],
    }


def _compute_mapping_bundle_digest(
    cross_taxonomy_mappings: Any, sssom_mappings: Any
) -> str:
    """Compute the v1 edge-bundle pin with no project-module dependency."""
    payload = {
        "cross_taxonomy_mappings": sorted(
            [_canonical_cross_mapping(item) for item in cross_taxonomy_mappings],
            key=_canonical_json,
        ),
        "sssom_mappings": sorted(
            [_canonical_sssom_mapping(item) for item in sssom_mappings],
            key=_canonical_json,
        ),
    }
    return hashlib.sha256(
        b"asago-scenario-generator:obligation-mapping-bundle:v1\0"
        + _canonical_json(payload)
    ).hexdigest()


def _qualification_facts(snapshot: Any) -> dict[str, Any]:
    """Build the domain-framed qualification fact set from snapshot evidence."""
    facts: dict[str, Any] = {}
    for item in snapshot.facts:
        value = item.model_dump(mode="json")
        key = _canonical_json(value["fact"]).decode("utf-8")
        facts[key] = value
    digest = hashlib.sha256(
        b"asago-scenario-generator:qualification-facts:v1\0" + _canonical_json(facts)
    ).hexdigest()
    return {"facts": facts, "semantic_digest": digest}


def _typed_risk_card(risk_id: str) -> dict[str, Any]:
    """Return one reviewed risk card for the typed adapter fixture."""
    return {
        "risk_id": risk_id,
        "risk_name": f"Risk {risk_id}",
        "risk_description": "A reviewed risk used by artifact QA.",
        "taxonomy": "ibm-risk-atlas",
        "confidence": 1.0,
        "grounding_confidence": "high",
        "evidence": [],
        "mitigations": [],
    }


def _typed_payload(
    *,
    risk_ids: tuple[str, ...] = ("risk-a",),
    pattern_id: str | None = "AP-T1-01",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build complete typed inputs from authoritative serialized records."""
    candidate, raw_pattern, snapshot = _authoritative_fixture()
    context = raw_pattern["canonical_chain"]["taxonomy_context"]
    pattern = deepcopy(raw_pattern) if pattern_id is not None else None
    if pattern is not None and pattern["id"] != pattern_id:
        # Artifact QA only needs the canonical projectable pattern. Keep this
        # guard so a future fixture change cannot silently mismatch mappings.
        raise ValueError(f"unsupported artifact-QA pattern fixture: {pattern_id}")
    mappings = [
        {
            "source_id": risk_id,
            "target_id": pattern_id,
            "relation": "exact",
            "evidence": ["reviewed-risk-card-mapping"],
        }
        for risk_id in risk_ids
        if pattern_id is not None
    ]
    obligation_edges_pin = {
        "release": "obligation-mapping-bundle-v1",
        "digest": _compute_mapping_bundle_digest(mappings, []),
    }
    payload: dict[str, Any] = {
        "risk_cards": [_typed_risk_card(risk_id) for risk_id in risk_ids],
        "capability_snapshot": snapshot.model_dump(mode="json"),
        "attack_pattern_catalog": [pattern] if pattern is not None else [],
        "cross_taxonomy_mappings": mappings,
        "sssom_mappings": [],
        "catalog_pins": {
            "atlas": {
                "release": context["atlas"]["release"],
                "digest": candidate.projection.catalog_pin,
            }
        },
        "mapping_pins": {
            "sssom": {
                "release": context["atlas"]["release"],
                "digest": context["mapping_set_digest"],
            },
            "obligation_edges": obligation_edges_pin,
        },
        "qualification_facts": _qualification_facts(snapshot),
        "projection_budget": {"max_candidates": 100, "max_derivation_work": 4096},
        "compatibility_policy": {"allow_legacy_keyword_matches": False},
    }
    if extra:
        payload.update(extra)
    return payload


def _command() -> list[str]:
    if shutil.which("uv", path=_SEARCH_PATH):
        return [_UV, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv" / "bin" / "asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def _new_workspace(case: str) -> Path:
    workspace = RUN_ROOT / "workspaces" / case
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def _run_cli(
    case: str,
    payload: dict[str, Any],
    *,
    format_name: str = "yaml",
) -> tuple[Path, subprocess.CompletedProcess[str]]:
    """Run the public adapter against a fresh typed-input file."""
    workspace = _new_workspace(case)
    snapshot = workspace / "typed-inputs.yaml"
    snapshot.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    output_dir = workspace / "plan"
    capture_dir = RUN_ROOT / "captures" / case
    capture_dir.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.pop(QA_PIPELINE_ENV, None)
    environment.pop("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None)
    argv = [
        *_command(),
        "plan-obligations",
        "--snapshot",
        str(snapshot),
        "--output-dir",
        str(output_dir),
        "--format",
        format_name,
    ]
    completed = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    (capture_dir / "command.txt").write_text(" ".join(argv) + "\n", encoding="utf-8")
    (capture_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (capture_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (capture_dir / "exit.txt").write_text(f"{completed.returncode}\n", encoding="utf-8")
    return output_dir, completed


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def _produce(
    case: str, payload: dict[str, Any]
) -> tuple[Path, bytes, dict[str, Any], subprocess.CompletedProcess[str]]:
    """Publish one YAML artifact and parse it with a standard reader."""
    output_dir, completed = _run_cli(case, payload)
    _check(
        case,
        completed.returncode == 0,
        f"exit {completed.returncode}: {completed.stderr[-300:]!r}",
    )
    artifact = output_dir / "taxonomy-obligation-plan.yaml"
    _check(case, artifact.is_file(), "YAML plan artifact was not published")
    if not artifact.is_file():
        return artifact, b"", {}, completed
    raw = artifact.read_bytes()
    parsed = yaml.safe_load(raw)
    _check(case, isinstance(parsed, dict), "published artifact is not a mapping")
    return artifact, raw, parsed if isinstance(parsed, dict) else {}, completed


def _reject(case: str, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    """Run invalid typed input and require no partial publication."""
    output_dir, completed = _run_cli(case, payload)
    _check(case, completed.returncode != 0, "invalid typed input was accepted")
    _check(
        case,
        not list(output_dir.glob("taxonomy-obligation-plan.*")),
        "partial obligation plan was published after rejection",
    )
    return completed


def _rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    value = plan.get("obligations")
    return value if isinstance(value, list) else []


def _summary_from_rows(rows: list[dict[str, Any]]) -> dict[str, int]:
    candidates = [
        candidate
        for row in rows
        for candidate in row.get("candidate_records", [])
        if isinstance(candidate, dict)
    ]
    return {
        "total": len(rows),
        "applicable": sum(row.get("scope_disposition") == "applicable" for row in rows),
        "governance_only": sum(
            row.get("scope_disposition") == "governance_only" for row in rows
        ),
        "capability_excluded": sum(
            row.get("scope_disposition") == "capability_excluded" for row in rows
        ),
        "ready": sum(row.get("qualification_disposition") == "ready" for row in rows),
        "missing_or_contradictory": sum(
            row.get("qualification_disposition")
            in {"missing_evidence", "contradictory_evidence"}
            for row in rows
        ),
        "structurally_infeasible": sum(
            row.get("qualification_disposition") == "structurally_infeasible"
            for row in rows
        ),
        "projectable": sum(
            item.get("projection_disposition") == "projectable" for item in candidates
        ),
        "projection_infeasible": sum(
            item.get("projection_disposition") == "projection_infeasible"
            for item in candidates
        ),
        "budget_deferred": sum(
            item.get("projection_disposition") == "budget_deferred"
            for item in candidates
        ),
    }


def _risk_id(row: dict[str, Any]) -> str | None:
    reference = row.get("risk_ref")
    return reference.get("risk_id") if isinstance(reference, dict) else None


def qa_topa_01() -> None:
    """Closed metadata records the authoritative pins and content digests."""
    case = "TOPA-01"
    candidate, raw_pattern, snapshot = _authoritative_fixture()
    payload = _typed_payload()
    artifact, _raw, plan, _completed = _produce(case, payload)
    context = raw_pattern["canonical_chain"]["taxonomy_context"]
    expected_facts = _qualification_facts(snapshot)
    _check(case, artifact.suffix == ".yaml", "publication was not YAML")
    _check(
        case,
        set(plan)
        == {
            "schema_version",
            "semantic_digest",
            "capability_snapshot_digest",
            "catalog_pins",
            "mapping_pins",
            "qualification_facts_digest",
            "obligations",
            "summary",
        },
        f"top-level fields are not closed: {set(plan)}",
    )
    _check(
        case,
        plan.get("schema_version") == "taxonomy-obligation-plan-v1",
        "wrong schema",
    )
    _check(
        case,
        plan.get("capability_snapshot_digest") == snapshot.snapshot_digest,
        "capability snapshot digest was not retained",
    )
    _check(
        case,
        plan.get("qualification_facts_digest") == expected_facts["semantic_digest"],
        "qualification facts digest was not computed from facts",
    )
    catalog_pin = (plan.get("catalog_pins") or {}).get("atlas") or {}
    mapping_pins = plan.get("mapping_pins") or {}
    mapping_pin = mapping_pins.get("sssom") or {}
    obligation_edges_pin = mapping_pins.get("obligation_edges") or {}
    _check(
        case,
        set(mapping_pins) == {"sssom", "obligation_edges"},
        "mapping pin inventory changed",
    )
    _check(
        case,
        catalog_pin.get("release") == context["atlas"]["release"],
        "catalog release changed",
    )
    _check(
        case,
        catalog_pin.get("digest") == candidate.projection.catalog_pin,
        "catalog pin changed",
    )
    _check(
        case,
        mapping_pin.get("release") == context["atlas"]["release"],
        "mapping release changed",
    )
    _check(
        case,
        mapping_pin.get("digest") == context["mapping_set_digest"],
        "mapping pin changed",
    )
    _check(
        case,
        obligation_edges_pin.get("release") == "obligation-mapping-bundle-v1",
        "obligation edge pin release changed",
    )
    _check(
        case,
        obligation_edges_pin.get("digest")
        == _compute_mapping_bundle_digest(
            payload["cross_taxonomy_mappings"], payload["sssom_mappings"]
        ),
        "obligation edge pin digest changed",
    )
    _check(
        case,
        all(
            isinstance(plan.get(key), str) and len(plan[key]) == 64
            for key in (
                "semantic_digest",
                "capability_snapshot_digest",
                "qualification_facts_digest",
            )
        ),
        "one or more content digests are not SHA-256 values",
    )


def qa_topa_02() -> None:
    """Presentation order does not alter canonical rows or artifact bytes."""
    case = "TOPA-02"
    _artifact_a, raw_a, plan_a, _completed_a = _produce(
        f"{case}-a", _typed_payload(risk_ids=("risk-a", "risk-b"))
    )
    _artifact_b, raw_b, plan_b, _completed_b = _produce(
        f"{case}-b", _typed_payload(risk_ids=("risk-b", "risk-a"))
    )
    ids_a = [row.get("obligation_id") for row in _rows(plan_a)]
    ids_b = [row.get("obligation_id") for row in _rows(plan_b)]
    _check(case, ids_a == ids_b, f"canonical IDs differ: {ids_a} != {ids_b}")
    _check(
        case,
        plan_a.get("semantic_digest") == plan_b.get("semantic_digest"),
        "semantic digest differs",
    )
    _check(case, raw_a == raw_b, "canonical YAML artifacts are not byte-identical")


def qa_topa_03() -> None:
    """YAML standard-reader round-trip preserves the closed row contract."""
    case = "TOPA-03"
    candidate, _raw_pattern, _snapshot = _authoritative_fixture()
    artifact, raw, plan, _completed = _produce(
        case, _typed_payload(risk_ids=("risk-a", "risk-b"))
    )
    parsed = yaml.safe_load(raw)
    expected_row_fields = {
        "obligation_id",
        "risk_ref",
        "taxonomy_chain",
        "attack_pattern_id",
        "attack_pattern_semantic_digest",
        "scope_disposition",
        "qualification_disposition",
        "candidate_records",
        "correspondence_disposition",
        "evidence",
    }
    rows = _rows(plan)
    _check(case, len(rows) == 2, f"expected two rows, got {len(rows)}")
    for row in rows:
        _check(
            case,
            set(row) == expected_row_fields,
            f"row fields are not closed: {set(row)}",
        )
        _check(
            case,
            row.get("correspondence_disposition") == "not_assessed",
            "Phase 1 correspondence claim",
        )
    candidate_rows = [
        candidate_row
        for row in rows
        for candidate_row in row.get("candidate_records", [])
    ]
    projectable_rows = [
        candidate_row
        for candidate_row in candidate_rows
        if candidate_row.get("projection_disposition") == "projectable"
    ]
    rejected_rows = [
        candidate_row
        for candidate_row in candidate_rows
        if candidate_row.get("projection_disposition") == "projection_infeasible"
    ]
    _check(case, len(projectable_rows) == 2, "derived candidate count changed")
    _check(
        case,
        rejected_rows
        and all(row.get("reason") and row.get("evidence") for row in rejected_rows),
        "projection-infeasible records lost typed reason/evidence",
    )
    _check(
        case,
        all(
            item.get("candidate_id") == candidate.candidate_id
            for item in projectable_rows
        ),
        "candidate identity was not derived from authoritative projection",
    )
    _check(
        case,
        isinstance(parsed, dict) and parsed == plan,
        "YAML standard-reader round-trip changed the plan",
    )
    _check(case, artifact.is_file(), "published artifact disappeared")


def qa_topa_04() -> None:
    """Identical typed inputs produce byte-identical YAML artifacts."""
    case = "TOPA-04"
    _artifact_a, raw_a, _plan_a, _completed_a = _produce(f"{case}-a", _typed_payload())
    _artifact_b, raw_b, _plan_b, _completed_b = _produce(f"{case}-b", _typed_payload())
    _check(case, raw_a == raw_b, "repeated YAML artifacts are not byte-identical")


def qa_topa_05() -> None:
    """Unknown fields, invalid budgets, and stale digests fail before publish."""
    cases = (
        ("unknown-field", {"candidate_expansions": []}, "candidate_expansions"),
        (
            "invalid-budget",
            {"projection_budget": {"max_candidates": 0, "max_derivation_work": 4096}},
            "projection_budget",
        ),
        (
            "stale-qualification-digest",
            {"qualification_facts": {"semantic_digest": _ZERO}},
            "qualification",
        ),
    )
    for suffix, mutation, expected_text in cases:
        payload = _typed_payload()
        if suffix == "stale-qualification-digest":
            qualification = payload["qualification_facts"]
            assert isinstance(qualification, dict)
            qualification["semantic_digest"] = mutation["qualification_facts"][
                "semantic_digest"
            ]
        else:
            payload.update(mutation)
        completed = _reject(f"TOPA-05-{suffix}", payload)
        combined = (completed.stdout + completed.stderr).lower()
        _check(
            f"TOPA-05-{suffix}",
            expected_text.lower() in combined,
            f"diagnostic omitted {expected_text!r}: {combined[-300:]!r}",
        )


def qa_topa_06() -> None:
    """The public publication surface is YAML-only and reports no calls."""
    case = "TOPA-06"
    artifact, _raw, plan, completed = _produce(case, _typed_payload())
    _check(
        case, artifact.name == "taxonomy-obligation-plan.yaml", "wrong artifact name"
    )
    _check(
        case,
        plan.get("schema_version") == "taxonomy-obligation-plan-v1",
        "artifact did not load as closed plan",
    )
    _check(case, "Network calls: 0" in completed.stdout, "network count missing")
    _check(case, "Model calls:   0" in completed.stdout, "model count missing")
    _check(case, not list(artifact.parent.glob("*.tmp")), "temporary artifact remained")
    _check(case, not list(artifact.parent.glob("*.part")), "partial artifact remained")
    output_dir, json_completed = _run_cli(
        f"{case}-json", _typed_payload(), format_name="json"
    )
    _check(case, json_completed.returncode != 0, "JSON publication was accepted")
    _check(
        case,
        not list(output_dir.glob("taxonomy-obligation-plan.*")),
        "JSON partial artifact remained",
    )


def qa_topa_07() -> None:
    """Summary counts are recomputable from the emitted obligation rows."""
    case = "TOPA-07"
    payload = _typed_payload(risk_ids=("risk-a", "risk-b", "risk-governance-only"))
    payload["cross_taxonomy_mappings"] = [
        mapping
        for mapping in payload["cross_taxonomy_mappings"]
        if mapping["source_id"] in {"risk-a", "risk-b"}
    ]
    payload["mapping_pins"]["obligation_edges"]["digest"] = (
        _compute_mapping_bundle_digest(
            payload["cross_taxonomy_mappings"], payload["sssom_mappings"]
        )
    )
    _artifact, _raw, plan, _completed = _produce(case, payload)
    rows = _rows(plan)
    summary = plan.get("summary") if isinstance(plan.get("summary"), dict) else {}
    for key, value in _summary_from_rows(rows).items():
        _check(case, summary.get(key) == value, f"summary.{key} does not reconcile")
    _check(case, "taxonomy_correspondence_rate" not in summary, "taxonomy rate present")
    _check(case, "scenario_realization_rate" not in summary, "scenario rate present")
    _check(
        case,
        {_risk_id(row) for row in rows} == {"risk-a", "risk-b", "risk-governance-only"},
        "reviewed risk was dropped",
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

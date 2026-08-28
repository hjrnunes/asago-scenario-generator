#!/usr/bin/env python3
"""Offline end-to-end QA for the typed taxonomy-obligation planner.

The suite drives only the public ``plan-obligations`` command and reads the
published YAML artifact.  Its input is built from the same authoritative
projection fixture used by ``tests/test_obligation_planner_contract.py``;
candidate records are intentionally absent from the input.  No live endpoint
or model is contacted.

Run with::

    uv run python acceptance/qa/taxonomy_risk/obligation_planner.py
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
notes: list[str] = []

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_SEARCH_PATH = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
_UV = shutil.which("uv", path=_SEARCH_PATH) or "uv"
_ZERO = "0" * 64


def _authoritative_fixture() -> tuple[Any, dict[str, Any], Any]:
    """Load the shared, sanitized, offline projection fixture."""
    from tests.helpers.projection_factory import (
        get_projected_candidate,
        get_test_raw_pattern,
        get_test_snapshot,
    )

    return get_projected_candidate(), get_test_raw_pattern(), get_test_snapshot()


def _canonical_json(value: Any) -> bytes:
    """Encode values using the contract's canonical JSON rules."""
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
    """Build a content-addressed qualification-fact set from the fixture."""
    facts: dict[str, Any] = {}
    for item in snapshot.facts:
        raw = item.model_dump(mode="json")
        key = json.dumps(
            raw["fact"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        facts[key] = raw
    digest = hashlib.sha256(
        b"asago-scenario-generator:qualification-facts:v1\0" + _canonical_json(facts)
    ).hexdigest()
    return {"facts": facts, "semantic_digest": digest}


def _typed_pattern_variant(pattern_id: str) -> dict[str, Any]:
    """Return a complete, self-consistent authoritative pattern variant."""
    from asago_scenario_generator.models.attack_pattern import (
        compute_chain_semantic_digest,
    )

    _candidate, raw_pattern, _snapshot = _authoritative_fixture()
    variant = deepcopy(raw_pattern)
    variant["id"] = pattern_id
    variant["canonical_chain"]["pattern_id"] = pattern_id
    variant["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        variant["canonical_chain"]
    )
    return variant


def _typed_capability_variant() -> Any:
    """Return a complete capability snapshot with changed authoritative facts."""
    from asago_scenario_generator.pipeline.projection import (
        capture_capability_snapshot,
    )
    from tests.helpers.projection_factory import get_test_profile

    _candidate, _raw_pattern, snapshot = _authoritative_fixture()
    changed_fact = snapshot.facts[0].model_copy(update={"value": "inactive"})
    return capture_capability_snapshot(get_test_profile(), (changed_fact,))


def _typed_catalog_pin(pattern: dict[str, Any]) -> str:
    """Compute a catalog pin from the complete authoritative pattern record."""
    candidate, raw_pattern, _snapshot = _authoritative_fixture()
    if pattern == raw_pattern:
        return candidate.projection.catalog_pin
    from asago_scenario_generator.pipeline.projection_qualification import (
        compute_authoritative_catalog_pin,
    )
    from tests.helpers.projection_factory import get_test_resolver

    return compute_authoritative_catalog_pin([pattern], get_test_resolver())


def _typed_payload(
    *,
    risk_ids: tuple[str, ...] = ("risk-a",),
    pattern_id: str | None = "AP-T1-01",
    pattern_record: dict[str, Any] | None = None,
    catalog_release: str | None = None,
    mapping_release: str | None = None,
    capability_snapshot: Any | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build complete typed inputs with no candidate-record escape hatch."""
    _candidate, raw_pattern, snapshot = _authoritative_fixture()
    context = raw_pattern["canonical_chain"]["taxonomy_context"]
    if pattern_id is None:
        pattern: dict[str, Any] | None = None
    elif pattern_record is not None:
        pattern = deepcopy(pattern_record)
    elif pattern_id == raw_pattern["id"]:
        pattern = deepcopy(raw_pattern)
    else:
        pattern = _typed_pattern_variant(pattern_id)
    selected_snapshot = capability_snapshot or snapshot
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
    catalog_pin = {
        "release": catalog_release or context["atlas"]["release"],
        "digest": _typed_catalog_pin(pattern or raw_pattern),
    }
    mapping_pin = {
        "release": mapping_release or context["atlas"]["release"],
        "digest": context["mapping_set_digest"],
    }
    obligation_edges_pin = {
        "release": "obligation-mapping-bundle-v1",
        "digest": _compute_mapping_bundle_digest(mappings, []),
    }
    payload: dict[str, Any] = {
        "risk_cards": [
            {
                "risk_id": risk_id,
                "risk_name": f"Risk {risk_id}",
                "risk_description": "A reviewed risk used by planner QA.",
                "taxonomy": "ibm-risk-atlas",
                "confidence": 1.0,
                "grounding_confidence": "high",
                "evidence": [],
                "mitigations": [],
            }
            for risk_id in risk_ids
        ],
        "capability_snapshot": selected_snapshot.model_dump(mode="json"),
        "attack_pattern_catalog": [pattern] if pattern is not None else [],
        "cross_taxonomy_mappings": mappings,
        "sssom_mappings": [],
        "catalog_pins": {"atlas": catalog_pin},
        "mapping_pins": {
            "sssom": mapping_pin,
            "obligation_edges": obligation_edges_pin,
        },
        "qualification_facts": _qualification_facts(selected_snapshot),
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
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)
    return workspace


def _write_payload(workspace: Path, payload: dict[str, Any]) -> Path:
    path = workspace / "typed-inputs.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _run_cli(
    case: str,
    snapshot: Path,
    output_dir: Path,
    *,
    format_name: str = "yaml",
) -> subprocess.CompletedProcess[str]:
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
    return completed


def _check(case: str, condition: bool, message: str) -> None:
    if not condition:
        failures.append(f"{case}: {message}")


def _produce(
    case: str, payload: dict[str, Any]
) -> tuple[Path, dict[str, Any], subprocess.CompletedProcess[str]]:
    workspace = _new_workspace(case)
    snapshot = _write_payload(workspace, payload)
    output_dir = workspace / "plan"
    completed = _run_cli(case, snapshot, output_dir)
    _check(
        case,
        completed.returncode == 0,
        f"exit {completed.returncode}: {completed.stderr[-300:]!r}",
    )
    artifact = output_dir / "taxonomy-obligation-plan.yaml"
    _check(case, artifact.is_file(), "YAML plan artifact was not published")
    if not artifact.is_file():
        return artifact, {}, completed
    value = yaml.safe_load(artifact.read_text(encoding="utf-8"))
    _check(case, isinstance(value, dict), "published artifact is not a mapping")
    return artifact, value if isinstance(value, dict) else {}, completed


def _reject(
    case: str, payload: dict[str, Any]
) -> tuple[Path, subprocess.CompletedProcess[str]]:
    workspace = _new_workspace(case)
    snapshot = _write_payload(workspace, payload)
    output_dir = workspace / "plan"
    completed = _run_cli(case, snapshot, output_dir)
    return output_dir, completed


def _rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    value = plan.get("obligations")
    return value if isinstance(value, list) else []


def _risk_id(row: dict[str, Any]) -> str | None:
    ref = row.get("risk_ref")
    return ref.get("risk_id") if isinstance(ref, dict) else None


def _row(
    plan: dict[str, Any], risk_id: str, pattern_id: str | None = None
) -> dict[str, Any] | None:
    for row in _rows(plan):
        if _risk_id(row) == risk_id and (
            pattern_id is None or row.get("attack_pattern_id") == pattern_id
        ):
            return row
    return None


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


def qa_top_01() -> None:
    """Shared pattern retains two distinct risk-scoped rows."""
    case = "TOP-01"
    payload = _typed_payload(risk_ids=("risk-a", "risk-b"))
    _artifact, plan, _completed = _produce(case, payload)
    rows = [row for row in _rows(plan) if row.get("attack_pattern_id") == "AP-T1-01"]
    _check(case, len(rows) == 2, f"expected two rows, got {len(rows)}")
    _check(case, len({row.get("obligation_id") for row in rows}) == 2, "IDs collapsed")
    _check(
        case,
        {_risk_id(row) for row in rows} == {"risk-a", "risk-b"},
        "risk identity lost",
    )
    mapping_pins = plan.get("mapping_pins") or {}
    _check(
        case,
        set(mapping_pins) == {"sssom", "obligation_edges"},
        "mapping pin inventory changed",
    )
    edge_pin = mapping_pins.get("obligation_edges") or {}
    _check(
        case,
        edge_pin.get("release") == "obligation-mapping-bundle-v1",
        "obligation edge pin release changed",
    )
    _check(
        case,
        edge_pin.get("digest")
        == _compute_mapping_bundle_digest(
            payload["cross_taxonomy_mappings"], payload["sssom_mappings"]
        ),
        "obligation edge pin digest changed",
    )


def qa_top_02() -> None:
    """A reviewed risk without a mapping remains visible as governance-only."""
    case = "TOP-02"
    _artifact, plan, _completed = _produce(
        case, _typed_payload(risk_ids=("risk-governance-only",), pattern_id=None)
    )
    row = _row(plan, "risk-governance-only")
    _check(case, row is not None, "governance row missing")
    if row:
        _check(case, row.get("scope_disposition") == "governance_only", "wrong scope")
        _check(
            case,
            row.get("qualification_disposition") == "not_attempted",
            "wrong qualification",
        )
        _check(case, row.get("attack_pattern_id") is None, "pattern invented")


def qa_top_03() -> None:
    """The authoritative projection creates a complete closed candidate row."""
    case = "TOP-03"
    candidate, _raw_pattern, _snapshot = _authoritative_fixture()
    artifact, plan, _completed = _produce(case, _typed_payload())
    row = _row(plan, "risk-a", "AP-T1-01")
    expected_fields = {
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
    _check(case, row is not None, "projectable row missing")
    if row is None:
        return
    _check(case, set(row) == expected_fields, f"row fields differ: {set(row)}")
    records = row.get("candidate_records") or []
    projectable = [
        record
        for record in records
        if record.get("projection_disposition") == "projectable"
    ]
    rejected = [
        record
        for record in records
        if record.get("projection_disposition") == "projection_infeasible"
    ]
    _check(
        case,
        len(projectable) == 1,
        f"expected one derived projectable candidate, got {records}",
    )
    _check(
        case,
        rejected
        and all(record.get("reason") and record.get("evidence") for record in rejected),
        "projection-infeasible candidate records lost typed reason/evidence",
    )
    if projectable:
        record = projectable[0]
        _check(
            case,
            record.get("candidate_id") == candidate.candidate_id,
            "candidate ID changed",
        )
        _check(
            case,
            record.get("canonical_ingress")
            == candidate.canonical_ingress.model_dump(mode="json"),
            "canonical ingress changed",
        )
        _check(
            case,
            record.get("resource_bindings")
            == [
                binding.model_dump(mode="json")
                for binding in candidate.projection.bindings
            ],
            "resource bindings changed",
        )
    _check(case, artifact.suffix == ".yaml", "non-YAML publication surfaced")


def qa_top_04() -> None:
    """Projection evidence is retained while secrets stay out of the artifact."""
    case = "TOP-04"
    secret = "SECRET_live_token_END"
    payload = _typed_payload()
    qualification = payload["qualification_facts"]
    if isinstance(qualification, dict):
        facts = qualification.get("facts")
        if isinstance(facts, dict):
            secret_reference = {
                "namespace": "system",
                "fact_id": "qa.secret-token",
                "value_type": "string",
                "property_path": [],
            }
            secret_key = json.dumps(
                secret_reference,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            facts[secret_key] = {
                "fact": secret_reference,
                "status": "present",
                "value": secret,
            }
            qualification["semantic_digest"] = hashlib.sha256(
                b"asago-scenario-generator:qualification-facts:v1\0"
                + _canonical_json(facts)
            ).hexdigest()
    artifact, plan, _completed = _produce(case, payload)
    row = _row(plan, "risk-a", "AP-T1-01") or {}
    evidence = row.get("evidence") if isinstance(row.get("evidence"), list) else []
    _check(
        case,
        any(
            item.get("kind") == "projection"
            and item.get("source") == "unsupported_requirement_derivation"
            for item in evidence
            if isinstance(item, dict)
        ),
        "authoritative projection evidence missing",
    )
    raw = artifact.read_bytes() if artifact.is_file() else b""
    _check(case, secret.encode() not in raw, "secret leaked into YAML artifact")


def qa_top_05() -> None:
    """A false qualification content digest fails typed validation."""
    case = "TOP-05"
    payload = _typed_payload()
    qualification = payload["qualification_facts"]
    if isinstance(qualification, dict):
        qualification["semantic_digest"] = _ZERO
    output_dir, completed = _reject(case, payload)
    _check(case, completed.returncode != 0, "stale qualification digest was accepted")
    _check(
        case,
        not list(output_dir.glob("taxonomy-obligation-plan.*")),
        "partial plan published",
    )
    _check(
        case,
        "qualification" in (completed.stdout + completed.stderr).lower(),
        "digest error omitted qualification",
    )


def qa_top_06() -> None:
    """Unknown typed input fields fail before any artifact is published."""
    case = "TOP-06"
    output_dir, completed = _reject(
        case, _typed_payload(extra={"candidate_expansions": []})
    )
    _check(case, completed.returncode != 0, "unknown candidate field was accepted")
    _check(
        case,
        not list(output_dir.glob("taxonomy-obligation-plan.*")),
        "partial plan published",
    )
    _check(
        case,
        "candidate_expansions" in (completed.stdout + completed.stderr),
        "unknown field omitted",
    )


def qa_top_07() -> None:
    """Each identity-bearing input changes the obligation identity."""
    case = "TOP-07"
    variants = (
        _typed_payload(risk_ids=("risk-b",)),
        _typed_payload(pattern_id="AP-T1-02"),
        _typed_payload(capability_snapshot=_typed_capability_variant()),
        _typed_payload(catalog_release="repinned-catalog"),
        _typed_payload(mapping_release="repinned-mapping"),
    )
    _artifact, base, _completed = _produce(f"{case}-base", _typed_payload())
    base_id = _rows(base)[0].get("obligation_id") if _rows(base) else None
    base_digest = base.get("semantic_digest")
    for index, payload in enumerate(variants, start=1):
        _artifact, changed, _completed = _produce(f"{case}-{index}", payload)
        rows = _rows(changed)
        _check(
            case,
            bool(rows) and rows[0].get("obligation_id") != base_id,
            "obligation ID did not change",
        )
        _check(
            case,
            changed.get("semantic_digest") != base_digest,
            "semantic digest did not change",
        )


def qa_top_08() -> None:
    """Publication is YAML-only, atomic, and reports zero external calls."""
    case = "TOP-08"
    artifact, plan, completed = _produce(case, _typed_payload())
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
    _check(
        case, "json" not in completed.stdout.lower(), "JSON publication was advertised"
    )


def qa_top_09() -> None:
    """Summary counts reconcile directly from the emitted rows."""
    case = "TOP-09"
    payload = _typed_payload(
        risk_ids=("risk-a", "risk-b", "risk-governance-only"),
        pattern_id="AP-T1-01",
    )
    payload["cross_taxonomy_mappings"] = [
        item
        for item in payload["cross_taxonomy_mappings"]
        if item["source_id"] in {"risk-a", "risk-b"}
    ]
    payload["mapping_pins"]["obligation_edges"]["digest"] = (
        _compute_mapping_bundle_digest(
            payload["cross_taxonomy_mappings"], payload["sssom_mappings"]
        )
    )
    artifact, plan, _completed = _produce(case, payload)
    rows = _rows(plan)
    derived = _summary_from_rows(rows)
    summary = plan.get("summary") if isinstance(plan.get("summary"), dict) else {}
    for key, value in derived.items():
        _check(case, summary.get(key) == value, f"summary.{key} does not reconcile")
    _check(case, "taxonomy_correspondence_rate" not in summary, "taxonomy rate present")
    _check(case, "scenario_realization_rate" not in summary, "scenario rate present")
    _check(case, artifact.is_file(), "summary artifact missing")


def qa_top_10() -> None:
    """Invalid projection budgets fail typed validation without publication."""
    case = "TOP-10"
    output_dir, completed = _reject(
        case,
        _typed_payload(
            extra={
                "projection_budget": {"max_candidates": 0, "max_derivation_work": 4096}
            }
        ),
    )
    _check(case, completed.returncode != 0, "invalid budget was accepted")
    _check(
        case,
        not list(output_dir.glob("taxonomy-obligation-plan.*")),
        "partial plan published",
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

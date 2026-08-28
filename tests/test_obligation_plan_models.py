"""Focused unit tests for taxonomy obligation plan models and serialization."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.obligation_plan import (
    CandidateRecord,
    ObligationPlanSummary,
    QualificationTraceItem,
    TaxonomyObligation,
    TaxonomyObligationPlan,
    TaxonomyObligationSnapshot,
    compute_sha256,
)


def _make_obligation(**overrides: Any) -> TaxonomyObligation:
    defaults: dict[str, Any] = {
        "obligation_id": "ob:atlas-prompt-injection:AP-T6-01:pin-abcdef",
        "risk_id": "atlas-prompt-injection",
        "pattern_id": "AP-T6-01",
        "scope_disposition": "applicable",
        "qualification_disposition": "ready",
        "correspondence_disposition": "not_assessed",
        "projection_disposition": "projectable",
        "qualification_trace": [
            QualificationTraceItem(
                predicate="deployment.attacker_code_execution",
                facts="deployment.attacker_code_execution=false",
                result="false",
                reason="fact present and unequal",
            )
        ],
        "candidate_records": [
            CandidateRecord(
                candidate_id="cand:v2:11111111111111111111111111111111",
                projection_disposition="projectable",
                reason="qualified combination",
            ),
            CandidateRecord(
                candidate_id="cand:v2:22222222222222222222222222222222",
                projection_disposition="projection_infeasible",
                reason="rule rejected combination",
            ),
        ],
    }
    defaults.update(overrides)
    return TaxonomyObligation(**defaults)


def _make_plan(**overrides: Any) -> TaxonomyObligationPlan:
    obligations = overrides.pop("obligations", [_make_obligation()])
    summary = overrides.pop(
        "summary",
        ObligationPlanSummary(
            total=len(obligations),
            applicable=sum(
                1 for o in obligations if o.scope_disposition == "applicable"
            ),
            governance_only=sum(
                1 for o in obligations if o.scope_disposition == "governance_only"
            ),
            capability_excluded=sum(
                1 for o in obligations if o.scope_disposition == "capability_excluded"
            ),
            ready=sum(1 for o in obligations if o.qualification_disposition == "ready"),
            missing_or_contradictory=sum(
                1
                for o in obligations
                if o.qualification_disposition
                in ("missing_evidence", "contradictory_evidence")
            ),
            structurally_infeasible=sum(
                1
                for o in obligations
                if o.qualification_disposition == "structurally_infeasible"
            ),
            projectable=sum(
                1
                for o in obligations
                for c in o.candidate_records
                if c.projection_disposition == "projectable"
            ),
            projection_infeasible=sum(
                1
                for o in obligations
                for c in o.candidate_records
                if c.projection_disposition == "projection_infeasible"
            ),
            budget_deferred=sum(
                1
                for o in obligations
                for c in o.candidate_records
                if c.projection_disposition == "budget_deferred"
            ),
        ),
    )

    plan = TaxonomyObligationPlan(
        schema_version="taxonomy-obligation-plan-v1",
        catalog_pins={"catalog": "atlas-2026.05"},
        mapping_pins={"mapping": "sssom-v1"},
        capability_snapshot_digest="c" * 64,
        qualification_facts_digest="f" * 64,
        generation_inputs_digest="g" * 64,
        semantic_digest="",
        obligations=obligations,
        summary=summary,
        network_calls=0,
        model_calls=0,
    )
    plan.semantic_digest = overrides.get(
        "semantic_digest", plan.compute_semantic_digest()
    )
    return plan


def test_obligation_plan_pinned_versions_and_summary() -> None:
    ob = _make_obligation()
    plan = _make_plan(obligations=[ob])
    assert plan.schema_version == "taxonomy-obligation-plan-v1"
    assert plan.catalog_pins["catalog"] == "atlas-2026.05"
    assert plan.mapping_pins["mapping"] == "sssom-v1"
    assert len(plan.semantic_digest) == 64
    assert len(plan.obligations) == 1
    assert plan.obligations[0].obligation_id == ob.obligation_id
    assert plan.summary.total == 1
    assert plan.summary.ready == 1
    assert plan.summary.projectable == 1
    assert plan.network_calls == 0
    assert plan.model_calls == 0


def test_obligation_plan_yaml_round_trip() -> None:
    original = _make_plan(
        obligations=[
            _make_obligation(
                candidate_records=[
                    CandidateRecord(
                        candidate_id="cand:v2:11111111111111111111111111111111",
                        projection_disposition="projectable",
                        reason="qualified combination",
                    ),
                    CandidateRecord(
                        candidate_id="cand:v2:22222222222222222222222222222222",
                        projection_disposition="projection_infeasible",
                        reason="rule rejected combination",
                    ),
                ],
            )
        ],
    )

    yaml_str = original.to_yaml()
    loaded = TaxonomyObligationPlan.from_yaml(yaml_str)

    assert loaded.schema_version == original.schema_version
    assert loaded.catalog_pins == original.catalog_pins
    assert loaded.mapping_pins == original.mapping_pins
    assert loaded.capability_snapshot_digest == original.capability_snapshot_digest
    assert loaded.semantic_digest == original.semantic_digest
    assert len(loaded.obligations) == len(original.obligations)
    assert loaded.obligations[0].obligation_id == original.obligations[0].obligation_id
    assert (
        loaded.obligations[0].qualification_trace
        == original.obligations[0].qualification_trace
    )
    assert (
        loaded.obligations[0].candidate_records
        == original.obligations[0].candidate_records
    )
    assert loaded.summary == original.summary


def test_obligation_plan_json_round_trip() -> None:
    original = _make_plan(
        obligations=[
            TaxonomyObligation(
                obligation_id="ob:atlas-orphan-risk:pin-123456",
                risk_id="atlas-orphan-risk",
                pattern_id=None,
                scope_disposition="governance_only",
                qualification_disposition="not_attempted",
                correspondence_disposition="not_assessed",
                projection_disposition="not_attempted",
            )
        ],
    )

    json_str = original.to_json()
    loaded = TaxonomyObligationPlan.from_json(json_str)

    assert loaded.catalog_pins == original.catalog_pins
    assert loaded.obligations[0].obligation_id == "ob:atlas-orphan-risk:pin-123456"
    assert loaded.obligations[0].pattern_id is None
    assert loaded.obligations[0].scope_disposition == "governance_only"
    assert loaded.obligations[0].qualification_disposition == "not_attempted"


def test_obligation_plan_byte_stability() -> None:
    plan = _make_plan(
        obligations=[
            _make_obligation(
                obligation_id="ob:atlas-prompt-injection:AP-T6-01:pin-111",
                risk_id="atlas-prompt-injection",
                pattern_id="AP-T6-01",
            ),
            _make_obligation(
                obligation_id="ob:atlas-memory-poisoning:AP-T1-01:pin-222",
                risk_id="atlas-memory-poisoning",
                pattern_id="AP-T1-01",
                scope_disposition="applicable",
                qualification_disposition="missing_evidence",
                projection_disposition="not_attempted",
            ),
        ],
    )

    yaml1 = plan.to_yaml()
    yaml2 = plan.to_yaml()
    assert yaml1 == yaml2

    json1 = plan.to_json()
    json2 = plan.to_json()
    assert json1 == json2


def test_tampered_digest_rejected() -> None:
    plan = _make_plan()
    yaml_str = plan.to_yaml()
    tampered_yaml = yaml_str.replace("atlas-prompt-injection", "atlas-tampered-risk")
    with pytest.raises(ValueError, match="Digest mismatch"):
        TaxonomyObligationPlan.from_yaml(tampered_yaml)

    json_str = plan.to_json()
    tampered_json = json_str.replace("atlas-prompt-injection", "atlas-tampered-risk")
    with pytest.raises(ValueError, match="Digest mismatch"):
        TaxonomyObligationPlan.from_json(tampered_json)


def test_unsupported_schema_version_rejected() -> None:
    plan = _make_plan()
    raw = plan.model_dump(mode="json")
    raw["schema_version"] = "taxonomy-obligation-plan-v2"
    with pytest.raises(ValueError, match="Unsupported schema version"):
        TaxonomyObligationPlan.from_json(json.dumps(raw))


def test_deserialization_rejects_non_mapping_payload() -> None:
    with pytest.raises(ValueError, match="YAML data must be a dictionary"):
        TaxonomyObligationPlan.from_yaml("- one\n- two\n")
    with pytest.raises(ValueError, match="JSON data must be a dictionary"):
        TaxonomyObligationPlan.from_json(json.dumps(["not", "a", "dict"]))


def test_correspondence_claim_rejected_on_load() -> None:
    plan = _make_plan()
    raw = plan.model_dump(mode="json")
    raw["obligations"][0]["correspondence_disposition"] = "aligned"
    with pytest.raises(ValueError, match="Invalid correspondence disposition"):
        TaxonomyObligationPlan.from_json(json.dumps(raw))


def test_omitted_correspondence_disposition_defaults_on_load() -> None:
    plan = _make_plan()
    raw = plan.model_dump(mode="json")
    del raw["obligations"][0]["correspondence_disposition"]

    loaded = TaxonomyObligationPlan.from_json(json.dumps(raw))

    assert loaded.obligations[0].correspondence_disposition == "not_assessed"


def test_unknown_field_wraps_validation_error_as_value_error() -> None:
    plan = _make_plan()
    raw = plan.model_dump(mode="json")
    raw["unexpected_field"] = 1
    with pytest.raises(ValueError, match="unexpected_field"):
        TaxonomyObligationPlan.from_json(json.dumps(raw))


def test_json_serialization_is_sorted_and_trailing_newline_terminated() -> None:
    plan = _make_plan()
    text = plan.to_json()
    assert text.endswith("}\n")
    lines = [line for line in text.splitlines() if line.startswith('  "')]
    top_level_keys = [line.split('"')[1] for line in lines]
    assert top_level_keys == sorted(top_level_keys)


def test_digest_computes_over_bytes_and_defaults_to_str() -> None:
    assert compute_sha256(b"abc") == compute_sha256("abc")
    assert compute_sha256(12345) == compute_sha256("12345")
    assert compute_sha256({"b": 2, "a": 1}) == compute_sha256({"a": 1, "b": 2})


def test_pin_sync_backfills_legacy_alias_in_both_directions() -> None:
    from_legacy = TaxonomyObligationSnapshot(catalog_pin="", taxonomy_version="atlas-x")
    assert from_legacy.catalog_pin == "atlas-x"
    assert from_legacy.taxonomy_version == "atlas-x"

    from_modern = TaxonomyObligationSnapshot(catalog_pin="atlas-y")
    assert from_modern.catalog_pin == "atlas-y"
    assert from_modern.taxonomy_version == "atlas-y"

    mapping_from_legacy = TaxonomyObligationSnapshot(
        mapping_pin="", mapping_version="sssom-x"
    )
    assert mapping_from_legacy.mapping_pin == "sssom-x"
    assert mapping_from_legacy.mapping_version == "sssom-x"

    mapping_from_modern = TaxonomyObligationSnapshot(mapping_pin="sssom-y")
    assert mapping_from_modern.mapping_pin == "sssom-y"
    assert mapping_from_modern.mapping_version == "sssom-y"


def test_pin_sync_keeps_both_values_when_both_present() -> None:
    snapshot = TaxonomyObligationSnapshot(
        catalog_pin="atlas-kept",
        taxonomy_version="atlas-legacy",
        mapping_pin="sssom-kept",
        mapping_version="sssom-legacy",
    )
    assert snapshot.catalog_pin == "atlas-kept"
    assert snapshot.taxonomy_version == "atlas-legacy"
    assert snapshot.mapping_pin == "sssom-kept"
    assert snapshot.mapping_version == "sssom-legacy"


def test_pin_sync_applies_model_defaults() -> None:
    snapshot = TaxonomyObligationSnapshot()
    assert snapshot.catalog_pin == "atlas-2026.05"
    assert snapshot.taxonomy_version == "atlas-2026.05"
    assert snapshot.mapping_pin == "sssom-v1"
    assert snapshot.mapping_version == "sssom-v1"


def test_unknown_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        TaxonomyObligation(
            obligation_id="ob:1",
            risk_id="r1",
            scope_disposition="applicable",
            qualification_disposition="ready",
            correspondence_disposition="not_assessed",
            projection_disposition="projectable",
            unsupported_field="fail",  # type: ignore[call-arg]
        )

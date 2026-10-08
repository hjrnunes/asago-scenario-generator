"""Unit tests for the closed taxonomy-obligation output contract."""

from __future__ import annotations

from importlib import import_module
import unicodedata
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.models.obligation_plan import (
    CandidateRecord,
    EvidenceRecord,
    FactEvaluationEvidence,
    ObligationPlanSummary,
    QualificationFactEvidence,
    RiskReference,
    TaxonomyChainEntry,
    TaxonomyObligation,
    TaxonomyObligationPlan,
)
from asago_scenario_generator.models.attack_pattern_projection import (
    EntryPointResourceReference,
    ResourceBinding,
)
from asago_scenario_generator.pipeline.projection_contracts import ProjectionIssue
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_projected_candidate


def test_version_framed_digest_lives_in_a_neutral_shared_leaf() -> None:
    """Input and output contracts share framing without depending on each other."""
    canonical = import_module("asago_scenario_generator.models.canonical")
    output = import_module("asago_scenario_generator.models.obligation_plan")

    assert canonical.compute_framed_digest("test:v1", {"value": "e\u0301"}) == (
        canonical.compute_framed_digest("test:v1", {"value": "é"})
    )
    assert not hasattr(output, "compute_framed_digest")


def test_input_normalization_keeps_validated_models_and_rejects_collisions() -> None:
    """Raw planner input is NFC-normalized around models it already holds."""
    canonical = import_module("asago_scenario_generator.models.canonical")
    model = RiskReference(risk_id="R-1", risk_name="e\u0301")

    normalized = canonical.normalize_unicode(
        {"cafe\u0301": [model, ("o\u0301",)]}, keep_models=True
    )

    assert normalized == {"café": [model, ["ó"]]}
    assert normalized["café"][0] is model
    with pytest.raises(ValueError, match="collide after NFC"):
        canonical.normalize_unicode(
            {"café": 1, "cafe\u0301": [model]}, keep_models=True
        )


def _raw_plan() -> dict[str, Any]:
    """Return a mutable JSON representation of one valid generated plan."""
    return make_plan().model_dump(mode="json")


def _raw_row() -> dict[str, Any]:
    """Return a mutable JSON representation of one valid obligation row."""
    return _raw_plan()["obligations"][0]


def test_candidate_record_requires_authoritative_ingress_and_bindings() -> None:
    """Persisted candidates retain the real projection resource identity."""
    candidate = get_projected_candidate()
    record = CandidateRecord(
        candidate_id=candidate.candidate_id,
        canonical_ingress=candidate.canonical_ingress,
        resource_bindings=tuple(candidate.projection.bindings),
    )

    assert record.canonical_ingress == candidate.canonical_ingress
    assert record.resource_bindings == candidate.projection.bindings

    with pytest.raises(ValidationError):
        CandidateRecord(  # type: ignore[call-arg]
            candidate_id=candidate.candidate_id,
            projection_disposition="projectable",
        )


def test_projection_infeasible_record_retains_typed_reason_and_evidence() -> None:
    """Aggregate rejects may omit resources but must retain typed evidence."""
    candidate_id = "cand:v2:" + "a" * 32
    issue = ProjectionIssue(
        code="missing_compatible_resource",
        pattern_id="AP-T1-01",
        slot_id="ingress",
        detail="no compatible entry point",
    )
    record = CandidateRecord(
        candidate_id=candidate_id,
        projection_disposition="projection_infeasible",
        reason=issue.detail,
        evidence=(
            EvidenceRecord(
                kind="projection",
                source=issue.code,
                detail=issue.detail,
            ),
        ),
    )

    assert record.canonical_ingress is None
    assert record.resource_bindings == ()
    assert record.projection_disposition == "projection_infeasible"
    assert record.evidence[0].source == "missing_compatible_resource"

    with pytest.raises(ValidationError):
        CandidateRecord(
            candidate_id=candidate_id,
            projection_disposition="projection_infeasible",
            reason=issue.detail,
        )


def test_rejected_record_checks_optional_ingress_binding_coherence() -> None:
    """Concrete rejected attempts cannot carry an unbound canonical ingress."""
    candidate_id = "cand:v2:" + "b" * 32
    ingress = EntryPointResourceReference(
        kind="entry_point", entry_point_id="ep:v1:" + "c" * 32
    )
    evidence = (
        EvidenceRecord(
            kind="projection",
            source="unsupported_requirement_derivation",
            detail="unsupported requirement",
        ),
    )
    with pytest.raises(ValidationError):
        CandidateRecord(
            candidate_id=candidate_id,
            canonical_ingress=ingress,
            projection_disposition="projection_infeasible",
            reason="unsupported requirement",
            evidence=evidence,
        )

    binding = ResourceBinding(slot_id="ingress", resource_ref=ingress)
    record = CandidateRecord(
        candidate_id=candidate_id,
        canonical_ingress=ingress,
        resource_bindings=(binding,),
        projection_disposition="projection_infeasible",
        reason="unsupported requirement",
        evidence=evidence,
    )
    assert record.resource_bindings == (binding,)


def test_obligation_rejects_duplicate_candidate_id_records() -> None:
    """One obligation cannot contain two records with one candidate identity."""
    row = _raw_row()
    row["candidate_records"] = [
        row["candidate_records"][0],
        row["candidate_records"][0],
    ]
    with pytest.raises((ValidationError, ValueError), match="candidate IDs"):
        TaxonomyObligation.model_validate(row)


def test_authoritative_records_are_frozen_and_nonempty_where_required() -> None:
    """Closed output records reject mutation and empty identity-bearing values."""
    chain_entry = TaxonomyChainEntry(taxonomy="atlas", id="AP-1")
    with pytest.raises((TypeError, ValidationError)):
        chain_entry.taxonomy = "other"  # type: ignore[misc]

    with pytest.raises(ValidationError):
        TaxonomyChainEntry(taxonomy="", id="AP-1")
    with pytest.raises(ValidationError):
        TaxonomyChainEntry(taxonomy="atlas", id="")
    with pytest.raises(ValidationError):
        RiskReference(risk_id="")
    with pytest.raises(ValidationError):
        EvidenceRecord(kind="mapping", detail="")

    candidate = get_projected_candidate()
    with pytest.raises(ValidationError):
        CandidateRecord(
            candidate_id=candidate.candidate_id,
            canonical_ingress=candidate.canonical_ingress,
            resource_bindings=(),
        )


def test_qualification_evidence_requires_value_and_nonempty_explanation() -> None:
    """Typed fact evidence retains a value, step identity, and rationale."""
    fact = {
        "namespace": "profile",
        "fact_id": "agent.can_call_payment_tool",
        "value_type": "boolean",
        "property_path": ["can_call_payment_tool"],
    }
    with pytest.raises(ValidationError, match="present fact evidence requires a value"):
        QualificationFactEvidence(fact=fact, status="present")  # type: ignore[arg-type]

    present = QualificationFactEvidence(  # type: ignore[arg-type]
        fact=fact,
        status="present",
        value=True,
    )
    valid = {
        "evaluation_type": "qualification_fact",
        "step_id": "AP-T1-01",
        "result": "true",
        "facts": (present,),
        "rationale": "authoritative qualification fact is present",
    }
    for field in ("step_id", "rationale"):
        with pytest.raises(ValidationError):
            FactEvaluationEvidence.model_validate({**valid, field: ""})


def test_conflicting_readings_serialize_only_when_present() -> None:
    """Empty readings never enter the canonical dump, so plan digests hold."""
    fact = {
        "namespace": "profile",
        "fact_id": "agent.can_call_payment_tool",
        "value_type": "boolean",
        "property_path": ["can_call_payment_tool"],
    }
    plain = QualificationFactEvidence(  # type: ignore[arg-type]
        fact=fact,
        status="present",
        value=True,
    )
    dumped = plain.model_dump(mode="json")
    assert "readings" not in dumped

    conflicting = QualificationFactEvidence(  # type: ignore[arg-type]
        fact=fact,
        status="contradictory",
        readings=[
            {"value": True, "source": "profile-a"},
            {"value": False, "source": "profile-b"},
        ],
    )
    conflict_dump = conflicting.model_dump(mode="json")
    assert conflict_dump["readings"] == [
        {"value": True, "source": "profile-a"},
        {"value": False, "source": "profile-b"},
    ]
    # Round-trip keeps the readings under extra="forbid".
    assert QualificationFactEvidence.model_validate(conflict_dump) == conflicting


def test_plan_requires_nonempty_taxonomy_pins_and_nonnegative_summary() -> None:
    """Persisted plans require both lineage pin maps and valid count bounds."""
    zero_summary = ObligationPlanSummary(
        total=0,
        applicable=0,
        governance_only=0,
        capability_excluded=0,
        ready=0,
        missing_or_contradictory=0,
        structurally_infeasible=0,
        projectable=0,
        projection_infeasible=0,
        budget_deferred=0,
    )
    assert zero_summary.total == 0

    raw = _raw_plan()
    raw["catalog_pins"] = {}
    with pytest.raises(ValidationError):
        TaxonomyObligationPlan.model_validate(raw)

    raw = _raw_plan()
    raw["mapping_pins"] = {}
    with pytest.raises(ValidationError):
        TaxonomyObligationPlan.model_validate(raw)

    with pytest.raises(ValidationError):
        ObligationPlanSummary(
            total=-1,
            applicable=0,
            governance_only=0,
            capability_excluded=0,
            ready=0,
            missing_or_contradictory=0,
            structurally_infeasible=0,
            projectable=0,
            projection_infeasible=0,
            budget_deferred=0,
        )


def test_plan_has_the_closed_normative_shape() -> None:
    """Output rows expose no legacy trace, counter, or caller override fields."""
    plan = make_plan()
    raw = plan.model_dump(mode="json")
    row = raw["obligations"][0]

    assert set(raw) == {
        "schema_version",
        "semantic_digest",
        "capability_snapshot_digest",
        "catalog_pins",
        "mapping_pins",
        "qualification_facts_digest",
        "obligations",
        "summary",
    }
    assert set(row) == {
        "obligation_id",
        "risk_ref",
        "taxonomy_chain",
        "attack_pattern_id",
        "attack_pattern_semantic_digest",
        "scope_disposition",
        "qualification_disposition",
        "candidate_records",
        "evidence",
    }
    assert "qualification_trace" not in row
    assert "projection_disposition" not in row
    assert "network_calls" not in raw
    assert "model_calls" not in raw


def test_yaml_round_trip_preserves_the_generated_plan() -> None:
    """The persisted YAML format reloads the same integrity-checked model."""
    original = make_plan()

    assert TaxonomyObligationPlan.from_yaml(original.to_yaml()) == original


def test_serialization_is_deterministic_and_yaml_keys_are_sorted() -> None:
    """Repeated serialization is byte-stable and persisted YAML is key-sorted."""
    plan = make_plan()

    assert plan.to_yaml() == plan.to_yaml()
    parsed = yaml.safe_load(plan.to_yaml())
    assert list(parsed) == sorted(parsed)
    assert plan.to_yaml().endswith("\n")


def test_tampered_content_or_summary_is_rejected() -> None:
    """Loading verifies both row-derived counts and the semantic digest."""
    plan = make_plan()

    tampered = _raw_plan()
    tampered["obligations"][0]["risk_ref"]["risk_id"] = "risk-tampered"
    with pytest.raises(ValueError, match="Digest mismatch"):
        TaxonomyObligationPlan.from_yaml(yaml.safe_dump(tampered))

    bad_summary = _raw_plan()
    bad_summary["summary"]["total"] += 1
    with pytest.raises(ValueError, match="summary"):
        TaxonomyObligationPlan.from_yaml(yaml.safe_dump(bad_summary))

    assert plan.assert_integrity() is None


def test_unknown_schema_fields_and_versions_fail_closed() -> None:
    """Persisted artifacts do not silently accept unsupported contract data."""
    unsupported_version = _raw_plan()
    unsupported_version["schema_version"] = "taxonomy-obligation-plan-v2"
    with pytest.raises(ValueError, match="Unsupported schema version"):
        TaxonomyObligationPlan.from_yaml(yaml.safe_dump(unsupported_version))

    unknown_field = _raw_plan()
    unknown_field["unexpected_field"] = True
    with pytest.raises(ValueError, match="unexpected_field"):
        TaxonomyObligationPlan.from_yaml(yaml.safe_dump(unknown_field))

    with pytest.raises(ValueError, match="YAML data must be a dictionary"):
        TaxonomyObligationPlan.from_yaml("- one\n- two\n")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scope_disposition", "governance_only"),
        ("qualification_disposition", "not_attempted"),
    ],
)
def test_invalid_dispositions_fail_closed(field: str, value: str) -> None:
    """The Phase 1 row matrix rejects contradictory dispositions."""
    row = _raw_row()
    row[field] = value

    with pytest.raises((ValidationError, ValueError)):
        TaxonomyObligation.model_validate(row)


def test_non_ready_rows_cannot_retain_projectable_candidates() -> None:
    """Candidate projection status agrees with qualification disposition."""
    row = _raw_row()
    row["qualification_disposition"] = "missing_evidence"

    with pytest.raises((ValidationError, ValueError)):
        TaxonomyObligation.model_validate(row)


def test_output_contract_normalizes_strings_to_nfc() -> None:
    """Canonical output values use the repository's NFC normalization rule."""
    row = _raw_row()
    decomposed = "risco-e\u0301"
    row["risk_ref"]["risk_id"] = decomposed
    normalized = TaxonomyObligation.model_validate(row)

    assert normalized.risk_ref.risk_id == unicodedata.normalize("NFC", decomposed)
    assert normalized.risk_ref.risk_id == "risco-é"

"""Public tracer tests for the offline Phase 4 pilot-readiness gate."""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.models.hybrid_coverage import ArtifactPin
from asago_scenario_generator.models.hybrid_pilot import (
    HybridPilotReadinessInputs,
    ModelCallEvidence,
    PilotExactJoinCounts,
    PilotReadinessBlocker,
    PilotTargetIdentity,
    PilotProvenanceBundle,
)
from asago_scenario_generator.models.hybrid_scenario_projection import (
    ArtifactProjectionSourcePin,
    HybridCorrespondenceAttestation,
    HybridScenarioProjectionSet,
)
from asago_scenario_generator.pipeline.hybrid_pilot import (
    SCENARIO_ARTIFACT_DIGEST_DOMAIN,
    assess_hybrid_pilot_readiness,
)
from asago_scenario_generator.pipeline.hybrid_scenario_projection import (
    build_hybrid_scenario_projection_set,
    compute_candidate_record_digest,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    compute_candidate_v2_id,
)
from asago_scenario_generator.models.hybrid_coverage import TaxonomyCoverageInput
from tests.test_cross_artifact_consistency import _make_envelope
from tests.test_hybrid_scenario_projection import _task1_authority_fixture


def _current_audit_input() -> HybridPilotReadinessInputs:
    """Build the empty, typed audit recorded before a future live pilot."""
    digest = "a" * 64
    evidence = ModelCallEvidence.create(
        adapter_kind="none",
        model_calls=0,
        provider_calls=0,
        network_calls=0,
        settings_digest=digest,
        model_profile_digest=digest,
    )
    provenance = PilotProvenanceBundle(
        run_id="current-audit",
        generate_run_manifest_pin=ArtifactPin(
            artifact_id="generate-run",
            schema_version="run-manifest-v1",
            semantic_digest=digest,
        ),
        use_case_digest=digest,
        risk_extraction_digest=digest,
        sssom_digest=digest,
        cross_taxonomy_mapping_digest=digest,
        threats_digest=digest,
        corrected_nested_capability_profile_digest=digest,
        qualification_facts_digest=digest,
        catalog_digest=digest,
        mappings_digest=digest,
        settings_digest=digest,
        model_profile_digest=digest,
        model_call_evidence=evidence,
        expected_targets=(),
        exact_join_counts=PilotExactJoinCounts(
            expected=0,
            generated=0,
            admitted=0,
            quarantined=0,
            exact_joins=0,
        ),
    )
    return HybridPilotReadinessInputs(provenance=provenance)


def test_current_audit_is_not_ready_with_count_derived_blockers() -> None:
    result = assess_hybrid_pilot_readiness(_current_audit_input())

    assert result.ready is False
    assert {(blocker.code, blocker.message) for blocker in result.blockers} == {
        (
            "missing_corrected_plan_join",
            "exact corrected-plan joins: 0 of 0 expected targets",
        ),
        (
            "corrected_assessment_without_coverage",
            "corrected assessments: zero accepted coverage-bearing relations",
        ),
    }
    assert result.exact_join_count == 0
    assert result.model_calls == result.provider_calls == result.network_calls == 0


def test_model_call_evidence_factory_canonicalizes_before_pinning() -> None:
    digest = "a" * 64
    evidence = ModelCallEvidence.create(
        adapter_kind="none",
        model_calls=0,
        provider_calls=0,
        network_calls=0,
        settings_digest=digest,
        model_profile_digest=digest,
        scenario_artifact_digests=("c" * 64, "b" * 64),
    )

    assert evidence.scenario_artifact_digests == ("b" * 64, "c" * 64)
    assert (
        ModelCallEvidence.model_validate(evidence.model_dump(mode="python")) == evidence
    )


def test_run_id_and_pilot_values_are_strictly_closed() -> None:
    current = _current_audit_input()
    provenance_payload = current.provenance.model_dump(mode="python")
    provenance_payload["run_id"] = ""
    with pytest.raises(ValueError):
        PilotProvenanceBundle.model_validate(provenance_payload)

    blocker = PilotReadinessBlocker(code="missing_model_call_evidence", message="ok")
    with pytest.raises(ValueError, match="frozen"):
        blocker.message = "changed"


@pytest.mark.parametrize(
    "field",
    ("expected", "generated", "admitted", "quarantined", "exact_joins"),
)
def test_join_counts_require_strict_integer_values(field: str) -> None:
    payload = {
        "expected": 0,
        "generated": 0,
        "admitted": 0,
        "quarantined": 0,
        "exact_joins": 0,
    }
    payload[field] = "0"
    with pytest.raises(ValueError):
        PilotExactJoinCounts.model_validate(payload)


def test_join_counts_reject_admitted_and_quarantined_overflow() -> None:
    with pytest.raises(ValueError, match="exceed generated"):
        PilotExactJoinCounts(
            expected=2,
            generated=1,
            admitted=1,
            quarantined=1,
            exact_joins=0,
        )


@pytest.mark.parametrize("field", ("model_calls", "provider_calls", "network_calls"))
def test_model_call_counts_require_strict_integer_values(field: str) -> None:
    digest = "a" * 64
    payload = _model_call_evidence(digest).model_dump(mode="python")
    payload[field] = "0"
    with pytest.raises(ValueError):
        ModelCallEvidence.model_validate(payload)


def test_none_model_adapter_rejects_any_nonzero_call_count() -> None:
    with pytest.raises(ValueError, match="zero calls"):
        ModelCallEvidence.create(
            adapter_kind="none",
            model_calls=1,
            provider_calls=0,
            network_calls=0,
            settings_digest="a" * 64,
            model_profile_digest="a" * 64,
        )


def test_blocker_message_is_nonempty() -> None:
    with pytest.raises(ValueError):
        PilotReadinessBlocker(code="missing_model_call_evidence", message="")


def _empty_result_payload() -> dict[str, object]:
    return {
        "ready": False,
        "blockers": (
            PilotReadinessBlocker(
                code="missing_model_call_evidence",
                message="model evidence is absent",
            ),
        ),
        "expected_target_count": 0,
        "generated_target_count": 0,
        "admitted_target_count": 0,
        "quarantined_target_count": 0,
        "exact_join_count": 0,
    }


@pytest.mark.parametrize(
    "field",
    (
        "expected_target_count",
        "generated_target_count",
        "admitted_target_count",
        "quarantined_target_count",
        "exact_join_count",
    ),
)
def test_result_counts_require_strict_integer_values(field: str) -> None:
    from asago_scenario_generator.models.hybrid_pilot import HybridPilotReadinessResult

    payload = _empty_result_payload()
    payload[field] = "0"
    with pytest.raises(ValueError):
        HybridPilotReadinessResult.model_validate(payload)


def test_result_call_counts_are_fixed_zero_values() -> None:
    from asago_scenario_generator.models.hybrid_pilot import HybridPilotReadinessResult

    result = HybridPilotReadinessResult.model_validate(_empty_result_payload())
    assert (result.model_calls, result.provider_calls, result.network_calls) == (
        0,
        0,
        0,
    )
    for field in ("model_calls", "provider_calls", "network_calls"):
        payload = _empty_result_payload()
        payload[field] = 1
        with pytest.raises(ValueError):
            HybridPilotReadinessResult.model_validate(payload)


def test_pilot_mapping_rejects_nfc_key_collisions() -> None:
    with pytest.raises(ValueError, match="collide after NFC normalization"):
        PilotReadinessBlocker.model_validate(
            {
                "code": "missing_model_call_evidence",
                "message": "ok",
                "e\u0301": 1,
                "é": 2,
            }
        )


def test_pilot_mapping_rejects_non_string_keys() -> None:
    with pytest.raises(TypeError, match="mapping keys must be strings"):
        PilotReadinessBlocker.model_validate(
            {"code": "missing_model_call_evidence", "message": "ok", 1: "bad"}
        )


def test_pilot_input_rejects_raw_provenance_mapping() -> None:
    current = _current_audit_input()

    with pytest.raises(TypeError, match="provenance must be a validated typed value"):
        HybridPilotReadinessInputs(
            provenance=current.provenance.model_dump(mode="python")
        )


def test_tampered_provenance_is_rejected_at_public_seam() -> None:
    current = _current_audit_input()
    tampered = current.provenance.model_copy(update={"semantic_digest": "0" * 64})

    with pytest.raises(ValueError, match="pilot provenance semantic_digest"):
        assess_hybrid_pilot_readiness(
            current.model_copy(update={"provenance": tampered})
        )


def test_duplicate_expected_target_identity_is_rejected() -> None:
    digest = "a" * 64
    target = PilotTargetIdentity(
        relation_id="correlation:v1:" + digest,
        selected_candidate_id="cand:v2:" + "b" * 32,
    )

    with pytest.raises(ValueError, match="expected_targets must contain unique"):
        PilotProvenanceBundle(
            **{
                key: value
                for key, value in _current_audit_input()
                .provenance.model_dump(mode="python")
                .items()
                if key
                not in {"expected_targets", "exact_join_counts", "semantic_digest"}
            },
            expected_targets=(target, target),
            exact_join_counts=PilotExactJoinCounts(
                expected=2,
                generated=0,
                admitted=0,
                quarantined=0,
                exact_joins=0,
            ),
        )


def test_scenarios_cannot_be_supplied_without_the_authority_graph() -> None:
    current = _current_audit_input()

    with pytest.raises(TypeError, match="scenario and review values require"):
        assess_hybrid_pilot_readiness(
            current.model_copy(update={"scenario_envelopes": (object(),)})
        )


def test_partial_authority_graph_is_rejected() -> None:
    current = _current_audit_input()

    with pytest.raises(TypeError, match="pilot authority graph is incomplete"):
        assess_hybrid_pilot_readiness(
            current.model_copy(update={"obligation_plan": object()})
        )


def _scenario_for_candidate(candidate: object) -> object:
    base = _make_envelope()
    return base.model_copy(
        update={
            "candidate_id": candidate.candidate_id,
            "initial_entry_point_id": candidate.canonical_ingress.entry_point_id,
        }
    )


def _model_call_evidence(
    digest: str,
    scenario_digests: tuple[str, ...] = (),
) -> ModelCallEvidence:
    return ModelCallEvidence.create(
        adapter_kind="none",
        model_calls=0,
        provider_calls=0,
        network_calls=0,
        settings_digest=digest,
        model_profile_digest=digest,
        scenario_artifact_digests=scenario_digests,
    )


def _with_scenarios(
    inputs: HybridPilotReadinessInputs,
    scenarios: tuple[object, ...],
) -> HybridPilotReadinessInputs:
    """Replace scenarios and cross-attest their exact artifact pins."""
    pins = tuple(
        ArtifactPin(
            artifact_id=scenario.scenario_id,
            schema_version="scenario-envelope-v1",
            semantic_digest=compute_framed_digest(
                SCENARIO_ARTIFACT_DIGEST_DOMAIN,
                scenario.model_dump(mode="json"),
            ),
        )
        for scenario in scenarios
    )
    provenance_payload = inputs.provenance.model_dump(mode="python")
    provenance_payload["scenario_artifact_pins"] = pins
    provenance_payload["model_call_evidence"] = _model_call_evidence(
        inputs.provenance.settings_digest,
        tuple(pin.semantic_digest for pin in pins),
    )
    provenance_payload.pop("schema_version")
    provenance_payload.pop("semantic_digest")
    provenance = PilotProvenanceBundle.from_verified_artifacts(
        projection_set_digest=inputs.projection_set.semantic_digest,
        **provenance_payload,
    )
    return inputs.model_copy(
        update={"provenance": provenance, "scenario_envelopes": scenarios}
    )


def _with_stpa_projections(
    inputs: HybridPilotReadinessInputs,
    projections: tuple[object, ...],
) -> HybridPilotReadinessInputs:
    """Replace STPA projections and refresh the projection-set attestation pin."""
    stpa_payload = inputs.stpa_projection_authority.model_dump(mode="python")
    stpa_payload.update({"projections": projections, "semantic_digest": None})
    stpa = type(inputs.stpa_projection_authority).model_validate(stpa_payload)
    replacement_pin = ArtifactProjectionSourcePin.from_artifact_pin(
        ArtifactPin(
            artifact_id="pinned-stpa-projection-attestation",
            schema_version=stpa.schema_version,
            semantic_digest=stpa.semantic_digest,
        ),
        role="stpa-attestation",
    ).model_dump(mode="python")
    projection_payload = inputs.projection_set.model_dump(mode="python")
    projection_payload["source_pins"] = tuple(
        pin
        for pin in projection_payload["source_pins"]
        if pin.get("role") != "stpa-attestation"
    ) + (replacement_pin,)
    for projection in projection_payload["projections"]:
        projection["source_pins"] = tuple(
            pin
            for pin in projection["source_pins"]
            if pin.get("role") != "stpa-attestation"
        ) + (replacement_pin,)
        projection["projection_id"] = ""
        projection["semantic_digest"] = None
    projection_payload["semantic_digest"] = None
    projection_set = type(inputs.projection_set).model_validate(projection_payload)
    provenance_payload = inputs.provenance.model_dump(mode="python")
    provenance_payload.pop("schema_version")
    provenance_payload.pop("semantic_digest")
    provenance = PilotProvenanceBundle.from_verified_artifacts(
        projection_set_digest=projection_set.semantic_digest,
        **provenance_payload,
    )
    return inputs.model_copy(
        update={
            "stpa_projection_authority": stpa,
            "projection_set": projection_set,
            "provenance": provenance,
        }
    )


def _as_normative_bookkeeping_fixture(
    projection_set: HybridScenarioProjectionSet,
) -> HybridScenarioProjectionSet:
    """Relabel a complete set as the non-semantic contract fixture class."""
    payload = projection_set.model_dump(mode="python")
    payload["evidence_class"] = "normative_bookkeeping_fixture"
    payload["semantic_digest"] = None
    for projection in payload["projections"]:
        projection["evidence_class"] = "normative_bookkeeping_fixture"
        projection["projection_id"] = ""
        projection["semantic_digest"] = None
    return HybridScenarioProjectionSet.model_validate(payload)


def _with_assessment(
    inputs: HybridPilotReadinessInputs,
    assessment: object,
) -> HybridPilotReadinessInputs:
    """Replace the assessment and refresh its exact projection-set pin."""
    replacement_pin = ArtifactProjectionSourcePin.from_artifact_pin(
        ArtifactPin(
            artifact_id="hybrid-coverage-assessment",
            schema_version=assessment.schema_version,
            semantic_digest=assessment.semantic_digest,
        ),
        role="phase2-assessment",
    ).model_dump(mode="python")
    payload = inputs.projection_set.model_dump(mode="python")
    payload["assessment_digest"] = assessment.semantic_digest
    payload["source_pins"] = tuple(
        pin for pin in payload["source_pins"] if pin.get("role") != "phase2-assessment"
    ) + (replacement_pin,)
    for projection in payload["projections"]:
        projection["source_pins"] = tuple(
            pin
            for pin in projection["source_pins"]
            if pin.get("role") != "phase2-assessment"
        ) + (replacement_pin,)
        projection["projection_id"] = ""
        projection["semantic_digest"] = None
    payload["semantic_digest"] = None
    projection_set = type(inputs.projection_set).model_validate(payload)
    provenance_payload = inputs.provenance.model_dump(mode="python")
    provenance_payload.pop("schema_version")
    provenance_payload.pop("semantic_digest")
    provenance = PilotProvenanceBundle.from_verified_artifacts(
        projection_set_digest=projection_set.semantic_digest,
        **provenance_payload,
    )
    return inputs.model_copy(
        update={
            "phase2_assessment": assessment,
            "projection_set": projection_set,
            "provenance": provenance,
        }
    )


def _complete_pilot_input() -> tuple[HybridPilotReadinessInputs, object, object]:
    """Build one complete reviewed-evidence authority graph."""
    task1_inputs, relation, candidate = _task1_authority_fixture()
    relation = relation.model_copy(
        update={
            "source_pins": relation.source_pins.model_copy(
                update={
                    "control_structure_digest": task1_inputs.stpa_projection_authority.control_structure_pin.semantic_digest,
                    "ica_enumeration_digest": task1_inputs.stpa_projection_authority.ica_enumeration_pin.semantic_digest,
                    "loss_analysis_digest": task1_inputs.stpa_projection_authority.loss_analysis_pin.semantic_digest,
                }
            )
        }
    )
    semantic_inputs = task1_inputs.model_copy(
        update={"evidence_class": "reviewed_semantic_evidence"}
    )
    projection_set = build_hybrid_scenario_projection_set(semantic_inputs)
    correspondence_payload = task1_inputs.correspondence.model_dump(mode="python")
    correspondence_payload["accepted_relations"] = (relation.model_dump(mode="python"),)
    correspondence_payload["semantic_digest"] = None
    correspondence = HybridCorrespondenceAttestation.model_validate(
        correspondence_payload
    )
    projection_payload = projection_set.model_dump(mode="python")
    projection_payload["source_pins"] = tuple(
        pin
        for pin in projection_payload["source_pins"]
        if pin.get("role") != "correspondence-attestation"
    ) + (
        ArtifactProjectionSourcePin.from_artifact_pin(
            ArtifactPin(
                artifact_id="hybrid-correspondence-attestation",
                schema_version=correspondence.schema_version,
                semantic_digest=correspondence.semantic_digest,
            ),
            role="correspondence-attestation",
        ).model_dump(mode="python"),
    )
    replacement_pin = ArtifactProjectionSourcePin.from_artifact_pin(
        ArtifactPin(
            artifact_id="hybrid-correspondence-attestation",
            schema_version=correspondence.schema_version,
            semantic_digest=correspondence.semantic_digest,
        ),
        role="correspondence-attestation",
    ).model_dump(mode="python")
    for projection in projection_payload["projections"]:
        projection["source_pins"] = tuple(
            pin
            for pin in projection["source_pins"]
            if pin.get("role") != "correspondence-attestation"
        ) + (replacement_pin,)
        projection["projection_id"] = ""
        projection["semantic_digest"] = None
    projection_payload["semantic_digest"] = None
    projection_set = HybridScenarioProjectionSet.model_validate(projection_payload)
    scenario = _scenario_for_candidate(candidate)
    scenario_digest = compute_framed_digest(
        SCENARIO_ARTIFACT_DIGEST_DOMAIN,
        scenario.model_dump(mode="json"),
    )
    digest = "b" * 64
    provenance = PilotProvenanceBundle.from_verified_artifacts(
        run_id="pilot-run-1",
        generate_run_manifest_pin=ArtifactPin(
            artifact_id="generate-run-manifest",
            schema_version="generate-run-manifest-v1",
            semantic_digest=digest,
        ),
        use_case_digest=digest,
        risk_extraction_digest=digest,
        sssom_digest=digest,
        cross_taxonomy_mapping_digest=digest,
        threats_digest=digest,
        corrected_nested_capability_profile_digest=digest,
        qualification_facts_digest=task1_inputs.obligation_plan.qualification_facts_digest,
        catalog_digest=digest,
        mappings_digest=digest,
        settings_digest=digest,
        model_profile_digest=digest,
        scenario_artifact_pins=(
            ArtifactPin(
                artifact_id=scenario.scenario_id,
                schema_version="scenario-envelope-v1",
                semantic_digest=scenario_digest,
            ),
        ),
        model_call_evidence=ModelCallEvidence.create(
            adapter_kind="provider",
            model_calls=1,
            provider_calls=1,
            network_calls=1,
            settings_digest=digest,
            model_profile_digest=digest,
            scenario_artifact_digests=(scenario_digest,),
        ),
        expected_targets=(
            PilotTargetIdentity(
                relation_id=relation.relation_id,
                selected_candidate_id=candidate.candidate_id,
            ),
        ),
        generated_targets=(
            PilotTargetIdentity(
                relation_id=relation.relation_id,
                selected_candidate_id=candidate.candidate_id,
            ),
        ),
        admitted_targets=(
            PilotTargetIdentity(
                relation_id=relation.relation_id,
                selected_candidate_id=candidate.candidate_id,
            ),
        ),
        exact_join_counts=PilotExactJoinCounts(
            expected=1,
            generated=1,
            admitted=1,
            quarantined=0,
            exact_joins=1,
        ),
        projection_set_digest=projection_set.semantic_digest,
    )
    return (
        HybridPilotReadinessInputs(
            provenance=provenance,
            scenario_envelopes=(scenario,),
            obligation_plan=task1_inputs.obligation_plan,
            candidate_materializations=task1_inputs.candidate_materializations,
            phase2_assessment=task1_inputs.phase2_assessment,
            correspondence=correspondence,
            resource_map_validation=task1_inputs.resource_map_validation,
            stpa_projection_authority=task1_inputs.stpa_projection_authority,
            confirmed_reviews=task1_inputs.confirmed_reviews,
            projection_set=projection_set,
        ),
        relation,
        candidate,
    )


def test_complete_reviewed_authority_graph_is_ready() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()

    result = assess_hybrid_pilot_readiness(inputs)

    assert result.ready is True
    assert result.blockers == ()
    assert (
        result.expected_target_count,
        result.generated_target_count,
        result.admitted_target_count,
        result.quarantined_target_count,
        result.exact_join_count,
    ) == (1, 1, 1, 0, 1)
    assert result.semantic_digest
    result.assert_integrity()


def test_full_graph_requires_factory_attested_provider_provenance() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    copied_provenance = type(inputs.provenance).model_validate(
        inputs.provenance.model_dump(mode="python")
    )

    with pytest.raises(ValueError, match="verified provenance"):
        assess_hybrid_pilot_readiness(
            inputs.model_copy(update={"provenance": copied_provenance})
        )


def test_factory_provenance_must_bind_to_this_projection_set() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    payload = inputs.provenance.model_dump(mode="python")
    payload.pop("schema_version")
    payload.pop("semantic_digest")
    wrong_binding = PilotProvenanceBundle.from_verified_artifacts(
        projection_set_digest="0" * 64,
        **payload,
    )

    with pytest.raises(ValueError, match="verified provenance"):
        assess_hybrid_pilot_readiness(
            inputs.model_copy(update={"provenance": wrong_binding})
        )


def test_full_graph_requires_explicit_expected_targets() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    payload = inputs.provenance.model_dump(mode="python")
    payload.update(
        {
            "scenario_artifact_pins": (),
            "model_call_evidence": _model_call_evidence(
                inputs.provenance.settings_digest
            ),
            "expected_targets": (),
            "generated_targets": (),
            "admitted_targets": (),
            "quarantined_targets": (),
            "exact_join_counts": PilotExactJoinCounts(
                expected=0,
                generated=0,
                admitted=0,
                quarantined=0,
                exact_joins=0,
            ),
            "semantic_digest": None,
        }
    )
    payload.pop("schema_version")
    payload.pop("semantic_digest")
    empty = inputs.model_copy(
        update={
            "provenance": type(inputs.provenance).from_verified_artifacts(
                projection_set_digest=inputs.projection_set.semantic_digest,
                **payload,
            ),
            "scenario_envelopes": (),
        }
    )

    result = assess_hybrid_pilot_readiness(empty)

    assert result.ready is False
    assert any(
        blocker.code == "missing_corrected_plan_join"
        and blocker.message == "pilot requires at least one explicit expected target"
        for blocker in result.blockers
    )


def test_public_candidate_identity_seams_match_authoritative_values() -> None:
    inputs, _relation, candidate = _task1_authority_fixture()
    record = next(
        item
        for row in inputs.obligation_plan.obligations
        for item in row.candidate_records
        if item.candidate_id == candidate.candidate_id
    )

    assert (
        compute_candidate_v2_id(candidate.pattern_id, candidate.projection)
        == candidate.candidate_id
    )
    assert compute_candidate_record_digest(record) == next(
        item.phase1_candidate_record_digest
        for item in inputs.candidate_materializations.entries
        if item.selected_candidate_id == candidate.candidate_id
    )


def test_candidate_identity_checks_happen_before_taxonomy_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    scenario = inputs.scenario_envelopes[0].model_copy(
        update={"candidate_id": "cand:v2:" + "f" * 32}
    )
    invalid = _with_scenarios(inputs, (scenario,))
    calls: list[tuple[object, ...]] = []
    original = TaxonomyCoverageInput.from_scenario_envelopes

    def spy(*args: object, **kwargs: object) -> object:
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        TaxonomyCoverageInput,
        "from_scenario_envelopes",
        staticmethod(spy),
    )

    with pytest.raises(ValueError, match="candidate_id does not match its projection"):
        assess_hybrid_pilot_readiness(invalid)
    assert calls == []


def test_taxonomy_adapter_runs_once_after_exact_candidate_join(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    calls: list[tuple[object, ...]] = []
    original = TaxonomyCoverageInput.from_scenario_envelopes

    def spy(*args: object, **kwargs: object) -> object:
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        TaxonomyCoverageInput,
        "from_scenario_envelopes",
        staticmethod(spy),
    )

    result = assess_hybrid_pilot_readiness(inputs)

    assert result.ready is True
    assert len(calls) == 1
    assert calls[0][0] == inputs.obligation_plan
    assert tuple(item.scenario_id for item in calls[0][1]) == (
        inputs.scenario_envelopes[0].scenario_id,
    )


def test_absent_review_evidence_is_a_not_ready_blocker() -> None:
    inputs, relation, _candidate = _complete_pilot_input()

    result = assess_hybrid_pilot_readiness(
        inputs.model_copy(update={"confirmed_reviews": ()})
    )

    assert result.ready is False
    assert any(
        blocker.code == "missing_review_evidence"
        and blocker.target is not None
        and blocker.target.relation_id == relation.relation_id
        for blocker in result.blockers
    )
    assert result.exact_join_count == 1


def test_confirmed_review_must_match_the_projection_embedded_review() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    payload = inputs.confirmed_reviews[0].model_dump(mode="python")
    payload.update({"reviewer_id": "different-reviewer", "semantic_digest": None})
    substituted = type(inputs.confirmed_reviews[0]).model_validate(payload)

    with pytest.raises(ValueError, match="does not match its embedded projection"):
        assess_hybrid_pilot_readiness(
            inputs.model_copy(update={"confirmed_reviews": (substituted,)})
        )


def test_projection_must_retain_confirmed_review_pin_closure() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    payload = inputs.projection_set.model_dump(mode="python")
    payload["semantic_digest"] = None
    for projection in payload["projections"]:
        projection["source_pins"] = tuple(
            pin
            for pin in projection["source_pins"]
            if pin.get("role") not in {"confirmed-review", "mechanism-evidence"}
        )
        projection["projection_id"] = ""
        projection["semantic_digest"] = None
    payload["source_pins"] = tuple(
        pin
        for pin in payload["source_pins"]
        if pin.get("role") not in {"confirmed-review", "mechanism-evidence"}
    )
    without_review_pins = type(inputs.projection_set).model_validate(payload)
    provenance_payload = inputs.provenance.model_dump(mode="python")
    provenance_payload.pop("schema_version")
    provenance_payload.pop("semantic_digest")
    provenance = PilotProvenanceBundle.from_verified_artifacts(
        projection_set_digest=without_review_pins.semantic_digest,
        **provenance_payload,
    )

    with pytest.raises(ValueError, match="omit confirmed review evidence"):
        assess_hybrid_pilot_readiness(
            inputs.model_copy(
                update={
                    "projection_set": without_review_pins,
                    "provenance": provenance,
                }
            )
        )


def test_assessment_rows_must_match_the_complete_accepted_relation() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    assessment_payload = inputs.phase2_assessment.model_dump(mode="python")
    realization = dict(assessment_payload["scenario_realization"][0])
    realization["risk_id"] = "different-risk"
    assessment_payload["scenario_realization"] = (realization,)
    assessment_payload["semantic_digest"] = None
    mismatched = type(inputs.phase2_assessment).model_validate(assessment_payload)

    with pytest.raises(ValueError, match="assessment row identity"):
        assess_hybrid_pilot_readiness(_with_assessment(inputs, mismatched))


def test_missing_stpa_identity_is_a_not_ready_blocker() -> None:
    inputs, relation, _candidate = _complete_pilot_input()

    result = assess_hybrid_pilot_readiness(_with_stpa_projections(inputs, ()))

    assert result.ready is False
    assert any(
        blocker.code == "missing_stpa_identity"
        and blocker.target is not None
        and blocker.target.relation_id == relation.relation_id
        for blocker in result.blockers
    )
    assert result.exact_join_count == 1


def test_normative_bookkeeping_fixture_cannot_admit_a_semantic_pilot() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    projection_set = _as_normative_bookkeeping_fixture(inputs.projection_set)
    provenance_payload = inputs.provenance.model_dump(mode="python")
    provenance_payload.pop("schema_version")
    provenance_payload.pop("semantic_digest")
    provenance = PilotProvenanceBundle.from_verified_artifacts(
        projection_set_digest=projection_set.semantic_digest,
        **provenance_payload,
    )
    fixture = inputs.model_copy(
        update={"provenance": provenance, "projection_set": projection_set}
    )

    result = assess_hybrid_pilot_readiness(fixture)

    assert result.ready is False
    assert any(
        blocker.code == "normative_bookkeeping_fixture" for blocker in result.blockers
    )


def test_synthetic_model_evidence_cannot_admit_a_semantic_pilot() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    provenance_payload = inputs.provenance.model_dump(mode="python")
    provenance_payload["model_call_evidence"] = ModelCallEvidence.create(
        adapter_kind="fake",
        model_calls=0,
        provider_calls=0,
        network_calls=0,
        settings_digest=inputs.provenance.settings_digest,
        model_profile_digest=inputs.provenance.model_profile_digest,
        scenario_artifact_digests=(
            inputs.provenance.scenario_artifact_pins[0].semantic_digest,
        ),
    )
    provenance_payload.pop("schema_version")
    provenance_payload.pop("semantic_digest")
    fake = inputs.model_copy(
        update={
            "provenance": PilotProvenanceBundle.from_verified_artifacts(
                projection_set_digest=inputs.projection_set.semantic_digest,
                **provenance_payload,
            )
        }
    )

    result = assess_hybrid_pilot_readiness(fake)

    assert result.ready is False
    assert any(blocker.code == "synthetic_evidence" for blocker in result.blockers)


def test_extra_or_old_scenario_candidate_is_rejected_before_adapter() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    extra = inputs.scenario_envelopes[0].model_copy(
        update={"candidate_id": "cand:v2:" + "f" * 32}
    )

    with pytest.raises(ValueError, match="candidate_id does not match its projection"):
        assess_hybrid_pilot_readiness(_with_scenarios(inputs, (extra,)))


def test_duplicate_scenario_candidate_is_rejected() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    duplicate = inputs.scenario_envelopes[0].model_copy(
        update={"scenario_id": "scenario:v2:" + "c" * 64}
    )

    with pytest.raises(ValueError, match="duplicate candidate IDs"):
        assess_hybrid_pilot_readiness(
            _with_scenarios(inputs, (inputs.scenario_envelopes[0], duplicate))
        )


def test_tampered_projection_set_authority_is_fatal() -> None:
    inputs, _relation, _candidate = _complete_pilot_input()
    tampered = inputs.projection_set.model_copy(update={"assessment_digest": "0" * 64})

    with pytest.raises(ValueError, match="semantic_digest"):
        assess_hybrid_pilot_readiness(
            inputs.model_copy(update={"projection_set": tampered})
        )

"""Offline target-scoped pilot-readiness validation for Phase 4.

This module is a gate, not a runner.  It consumes exact typed artifacts from
the earlier phases and reports whether a later live semantic pilot could be
started.  It never creates a provider, reads a file, repairs an identity, or
changes a Phase 1/2/3 artifact.
"""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    HybridCoverageAssessment,
    ScenarioRealizationRow,
    TaxonomyCoverageInput,
    TaxonomyCorrespondenceRow,
)
from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.models.hybrid_pilot import (
    HybridPilotReadinessInputs,
    HybridPilotReadinessResult,
    PilotExactJoinCounts,
    PilotProvenanceBundle,
    PilotReadinessBlocker,
    PilotTargetIdentity,
    _is_verified_provenance,
)
from asago_scenario_generator.models.hybrid_scenario_projection import (
    ArtifactProjectionSourcePin,
    ConfirmedCoverageReview,
    HybridCorrespondenceAttestation,
    HybridScenarioProjection,
    HybridScenarioProjectionSet,
    MechanismProjection,
    PinnedStpaProjectionAttestation,
)
from asago_scenario_generator.models.obligation_plan import (
    CandidateRecord,
    TaxonomyObligationPlan,
)
from asago_scenario_generator.models.scenario import ScenarioEnvelope
from asago_scenario_generator.models.system_resource_map import (
    SystemResourceMapValidation,
)
from asago_scenario_generator.pipeline.hybrid_scenario_projection import (
    compute_candidate_record_digest,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    compute_candidate_v2_id,
)
from asago_scenario_generator.models.candidate_materialization import (
    CandidateMaterialization,
    CandidateMaterializationSet,
)
from asago_scenario_generator.models.correspondence import (
    AcceptedCorrespondenceRelation,
)


ZERO_ACCEPTED_COVERAGE_BLOCKER = (
    "corrected assessments: zero accepted coverage-bearing relations"
)
SCENARIO_ARTIFACT_DIGEST_DOMAIN = "asago.hybrid-pilot-scenario-envelope.v1"


@dataclass(frozen=True)
class _PilotAuthorities:
    """Copied, integrity-checked authorities used by the gate."""

    provenance: PilotProvenanceBundle
    scenarios: tuple[ScenarioEnvelope, ...]
    plan: TaxonomyObligationPlan
    materializations: CandidateMaterializationSet
    assessment: HybridCoverageAssessment
    correspondence: HybridCorrespondenceAttestation
    resource_map: SystemResourceMapValidation
    stpa: PinnedStpaProjectionAttestation
    reviews: tuple[ConfirmedCoverageReview, ...]
    projection_set: HybridScenarioProjectionSet


@dataclass(frozen=True)
class _JoinCheck:
    """The exact candidates that passed the pre-adapter join checks."""

    joined_scenarios: tuple[ScenarioEnvelope, ...]
    joined_targets: frozenset[tuple[str, str]]
    blockers: tuple[PilotReadinessBlocker, ...]


@dataclass(frozen=True)
class _CandidateIndexes:
    """Indexes reused by the ordered candidate-join checks."""

    expected: tuple[PilotTargetIdentity, ...]
    generated_keys: frozenset[tuple[str, str]]
    admitted_keys: frozenset[tuple[str, str]]
    records: dict[tuple[str, str], CandidateRecord]
    materializations: dict[tuple[str, str], CandidateMaterialization]
    relations: dict[str, AcceptedCorrespondenceRelation]
    expected_by_candidate: dict[str, PilotTargetIdentity]


def _copy_typed(value: Any, expected: type[Any], name: str) -> Any:
    """Deep-copy and revalidate a mutable authority at the gate boundary."""
    if not isinstance(value, expected):
        raise TypeError(f"{name} must be a {expected.__name__}")
    return expected.model_validate(deepcopy(value.model_dump(mode="python")))


def _copy_authorities(inputs: HybridPilotReadinessInputs) -> _PilotAuthorities:
    """Copy every exact nested source before any cross-artifact check."""
    return _PilotAuthorities(
        provenance=_copy_typed(inputs.provenance, PilotProvenanceBundle, "provenance"),
        scenarios=tuple(
            _copy_typed(item, ScenarioEnvelope, "scenario_envelope")
            for item in inputs.scenario_envelopes
        ),
        plan=_copy_typed(
            inputs.obligation_plan, TaxonomyObligationPlan, "obligation_plan"
        ),
        materializations=_copy_typed(
            inputs.candidate_materializations,
            CandidateMaterializationSet,
            "candidate_materializations",
        ),
        assessment=_copy_typed(
            inputs.phase2_assessment,
            HybridCoverageAssessment,
            "phase2_assessment",
        ),
        correspondence=_copy_typed(
            inputs.correspondence,
            HybridCorrespondenceAttestation,
            "correspondence",
        ),
        resource_map=_copy_typed(
            inputs.resource_map_validation,
            SystemResourceMapValidation,
            "resource_map_validation",
        ),
        stpa=_copy_typed(
            inputs.stpa_projection_authority,
            PinnedStpaProjectionAttestation,
            "stpa_projection_authority",
        ),
        reviews=tuple(
            _copy_typed(item, ConfirmedCoverageReview, "confirmed_review")
            for item in inputs.confirmed_reviews
        ),
        projection_set=_copy_typed(
            inputs.projection_set,
            HybridScenarioProjectionSet,
            "projection_set",
        ),
    )


def _assert_integrity(authorities: _PilotAuthorities) -> None:
    """Reject any tampered or malformed top-level authority."""
    authorities.provenance.assert_integrity()
    authorities.plan.assert_integrity()
    authorities.materializations.assert_integrity()
    authorities.assessment.assert_integrity()
    authorities.correspondence.assert_integrity()
    authorities.stpa.assert_integrity()
    authorities.projection_set.assert_integrity()
    for review in authorities.reviews:
        review.assert_integrity()
        review.mechanism_evidence.assert_integrity()
    _validate_review_bindings(authorities)
    if not authorities.resource_map.is_valid:
        raise ValueError("resource-map validation must be successful")
    if authorities.resource_map.canonical_map is None:
        raise ValueError("resource-map validation must retain its canonical map")
    authorities.resource_map.canonical_map.assert_integrity()


def _artifact_pin_digests(projection_set: HybridScenarioProjectionSet) -> set[str]:
    """Return every digest carried by an artifact source pin."""
    return {
        pin.pin.semantic_digest
        for pin in projection_set.source_pins
        if isinstance(pin, ArtifactProjectionSourcePin)
    }


def _review_pin_digests(review: ConfirmedCoverageReview) -> set[str]:
    """Return all content pins required to retain one confirmed review."""
    return {
        review.review_artifact_pin.semantic_digest,
        review.mechanism_evidence.artifact_pin.semantic_digest,
        review.semantic_digest,
    }


def _validate_review_bindings(authorities: _PilotAuthorities) -> None:
    """Bind every supplied review to its exact embedded projection record."""
    projections = {
        projection.relation_id: projection
        for projection in authorities.projection_set.projections
    }
    for review in authorities.reviews:
        _validate_one_review_binding(review, projections)


def _validate_one_review_binding(
    review: ConfirmedCoverageReview,
    projections: dict[str, HybridScenarioProjection],
) -> None:
    """Bind one review to the matching composed projection and pin closure."""
    projection = projections.get(review.relation_id)
    if projection is None:
        return
    _require_embedded_review_match(projection, review)
    _require_review_pin_closure(projection, review)


def _require_embedded_review_match(
    projection: HybridScenarioProjection,
    review: ConfirmedCoverageReview,
) -> None:
    """Require the projection's embedded review to be the supplied review."""
    if projection.confirmed_review != review:
        raise ValueError("confirmed review does not match its embedded projection")


def _require_review_pin_closure(
    projection: HybridScenarioProjection,
    review: ConfirmedCoverageReview,
) -> None:
    """Require projection pins to retain all confirmed review evidence."""
    projection_digests = {
        pin.pin.semantic_digest
        for pin in projection.source_pins
        if isinstance(pin, ArtifactProjectionSourcePin)
    }
    if not _review_pin_digests(review) <= projection_digests:
        raise ValueError("projection source pins omit confirmed review evidence")


def _scenario_artifact_digest(scenario: ScenarioEnvelope) -> str:
    """Digest one exact typed scenario envelope for provenance attestation."""
    return compute_framed_digest(
        SCENARIO_ARTIFACT_DIGEST_DOMAIN,
        scenario.model_dump(mode="json"),
    )


def _validate_scenario_artifact_pins(
    provenance: PilotProvenanceBundle,
    scenarios: Sequence[ScenarioEnvelope],
) -> None:
    """Cross-attest every loaded scenario to its declared artifact pin."""
    if not scenarios:
        return
    pins_by_artifact = {
        pin.artifact_id: pin for pin in provenance.scenario_artifact_pins
    }
    if len(pins_by_artifact) != len(scenarios):
        raise ValueError(
            "scenario artifact pins must identify every supplied scenario envelope"
        )
    for scenario in scenarios:
        _validate_one_scenario_artifact_pin(scenario, pins_by_artifact)


def _validate_one_scenario_artifact_pin(
    scenario: ScenarioEnvelope,
    pins_by_artifact: dict[str, ArtifactPin],
) -> None:
    """Cross-attest one scenario envelope to its exact artifact pin."""
    pin = pins_by_artifact.get(scenario.scenario_id)
    if pin is None:
        raise ValueError("scenario envelope has no matching artifact pin")
    if pin.semantic_digest != _scenario_artifact_digest(scenario):
        raise ValueError("scenario artifact pin does not match envelope content")


def _require_equal(actual: object, expected: object, message: str) -> None:
    """Raise one stable diagnostic when two authority leaves disagree."""
    if actual != expected:
        raise ValueError(message)


def _require_plan_authority_pins(authorities: _PilotAuthorities) -> None:
    """Require the plan, materialization, assessment, and map pins to agree."""
    plan = authorities.plan
    materializations = authorities.materializations
    assessment = authorities.assessment
    resource_map = authorities.resource_map.canonical_map
    if resource_map is None:
        raise ValueError("resource-map validation must retain its canonical map")
    _require_equal(
        materializations.obligation_plan_pin.semantic_digest,
        plan.semantic_digest,
        "candidate materializations do not pin the obligation plan",
    )
    _require_equal(
        assessment.capability_snapshot_digest,
        plan.capability_snapshot_digest,
        "assessment does not pin the obligation-plan capability snapshot",
    )
    _require_equal(
        resource_map.capability_snapshot_digest,
        plan.capability_snapshot_digest,
        "resource map does not pin the obligation-plan capability snapshot",
    )


def _require_correspondence_authority_pins(
    authorities: _PilotAuthorities,
) -> None:
    """Require correspondence and assessment pins to agree."""
    correspondence = authorities.correspondence
    _require_equal(
        correspondence.proposal_set_digest,
        correspondence.proposal_set_pin.semantic_digest,
        "correspondence proposal-set pin is inconsistent",
    )
    _require_equal(
        correspondence.reconciliation_digest,
        correspondence.reconciliation_pin.semantic_digest,
        "correspondence reconciliation pin is inconsistent",
    )
    _require_equal(
        authorities.projection_set.assessment_digest,
        authorities.assessment.semantic_digest,
        "projection set does not pin the Phase 2 assessment",
    )


def _require_provenance_authority_pins(authorities: _PilotAuthorities) -> None:
    """Require provenance to retain plan and model-call settings pins."""
    provenance = authorities.provenance
    evidence = provenance.model_call_evidence
    _require_equal(
        provenance.qualification_facts_digest,
        authorities.plan.qualification_facts_digest,
        "pilot provenance does not pin Phase 1 qualification facts",
    )
    _require_equal(
        evidence.settings_digest,
        provenance.settings_digest,
        "model-call evidence does not pin pilot settings",
    )
    _require_equal(
        evidence.model_profile_digest,
        provenance.model_profile_digest,
        "model-call evidence does not pin the model profile",
    )


def _require_relation_source_pins(authorities: _PilotAuthorities) -> None:
    """Require every accepted relation to retain its upstream source pins."""
    correspondence = authorities.correspondence
    resource_map = authorities.resource_map.canonical_map
    if resource_map is None:
        raise ValueError("resource-map validation must retain its canonical map")
    expected = (
        resource_map.semantic_digest,
        authorities.plan.capability_snapshot_digest,
        authorities.plan.semantic_digest,
        authorities.stpa.control_structure_pin.semantic_digest,
        authorities.stpa.ica_enumeration_pin.semantic_digest,
        authorities.stpa.loss_analysis_pin.semantic_digest,
    )
    for relation in correspondence.accepted_relations:
        source = relation.source_pins
        actual = (
            source.resource_map_semantic_digest,
            source.capability_snapshot_digest,
            source.obligation_plan_semantic_digest,
            source.control_structure_digest,
            source.ica_enumeration_digest,
            source.loss_analysis_digest,
        )
        _require_equal(
            actual,
            expected,
            "correspondence relation source pins disagree with authorities",
        )


def _require_projection_source_closure(authorities: _PilotAuthorities) -> None:
    """Require the composed projection set to pin every upstream authority."""
    plan = authorities.plan
    materializations = authorities.materializations
    assessment = authorities.assessment
    correspondence = authorities.correspondence
    resource_map = authorities.resource_map.canonical_map
    stpa = authorities.stpa
    if resource_map is None:
        raise ValueError("resource-map validation must retain its canonical map")
    required = {
        plan.semantic_digest,
        materializations.semantic_digest,
        assessment.semantic_digest,
        correspondence.semantic_digest,
        correspondence.proposal_set_digest,
        correspondence.reconciliation_digest,
        resource_map.semantic_digest,
        stpa.semantic_digest,
        *(
            pin.semantic_digest
            for pin in (
                stpa.loss_analysis_pin,
                stpa.control_structure_pin,
                stpa.ica_enumeration_pin,
                stpa.execution_projection_pin,
            )
        ),
    }
    missing = required - _artifact_pin_digests(authorities.projection_set)
    if missing:
        raise ValueError("projection set source pins omit an upstream authority")


def _require_pin_digests(authorities: _PilotAuthorities) -> None:
    """Require all authority digests to remain in the composed source closure."""
    _require_plan_authority_pins(authorities)
    _require_correspondence_authority_pins(authorities)
    _require_provenance_authority_pins(authorities)
    _validate_scenario_artifact_pins(authorities.provenance, authorities.scenarios)
    _require_relation_source_pins(authorities)
    _require_projection_source_closure(authorities)


def _candidate_records(
    plan: TaxonomyObligationPlan,
) -> dict[tuple[str, str], CandidateRecord]:
    """Index projectable Phase 1 candidate records by exact target identity."""
    return {
        (row.obligation_id, record.candidate_id): record
        for row in plan.obligations
        for record in row.candidate_records
        if record.projection_disposition == "projectable"
    }


def _materialization_records(
    values: CandidateMaterializationSet,
) -> dict[tuple[str, str], CandidateMaterialization]:
    """Index complete materializations by exact obligation/candidate identity."""
    return {
        (item.obligation_id, item.selected_candidate_id): item
        for item in values.entries
    }


def _scenario_candidates(
    scenarios: Sequence[ScenarioEnvelope],
) -> tuple[ScenarioEnvelope, ...]:
    """Validate scenario envelopes before any taxonomy adapter is called."""
    parsed: list[ScenarioEnvelope] = []
    for scenario in scenarios:
        if scenario.projection is None:
            raise ValueError("scenario envelope is missing its projection")
        # Re-parse the mutable envelope and embedded projection as a typed
        # value.  This catches stale nested digests before candidate matching.
        from asago_scenario_generator.models.projection_envelope import (
            ProjectionEnvelopeBlock,
        )

        ProjectionEnvelopeBlock.model_validate(
            scenario.projection.model_dump(mode="python")
        )
        recomputed = compute_candidate_v2_id(
            scenario.projection.projection.source_chain.pattern_id,
            scenario.projection.projection,
        )
        if scenario.candidate_id != recomputed:
            raise ValueError(
                "scenario envelope candidate_id does not match its projection"
            )
        if (
            scenario.initial_entry_point_id
            != scenario.projection.canonical_ingress.entry_point_id
        ):
            raise ValueError("scenario envelope ingress does not match its projection")
        parsed.append(scenario)
    return tuple(parsed)


def _target_for_candidate(
    target: PilotTargetIdentity,
    relation: AcceptedCorrespondenceRelation,
    records: dict[tuple[str, str], CandidateRecord],
    materializations: dict[tuple[str, str], CandidateMaterialization],
    scenarios: dict[str, ScenarioEnvelope],
) -> tuple[bool, ScenarioEnvelope | None]:
    """Check one exact plan/materialization/envelope join."""
    _require_target_relation_identity(target, relation)
    key = (relation.obligation_id, target.selected_candidate_id)
    record = records.get(key)
    materialization = materializations.get(key)
    scenario = scenarios.get(target.selected_candidate_id)
    if record is None or materialization is None or scenario is None:
        return False, scenario
    _require_materialization_record_binding(record, materialization)
    mechanism = materialization.mechanism_projection
    _require_materialization_identity(relation, mechanism)
    _require_materialization_candidate_identity(target, mechanism)
    _require_materialization_projection_alignment(record, mechanism, scenario)
    return True, scenario


def _require_target_relation_identity(
    target: PilotTargetIdentity,
    relation: AcceptedCorrespondenceRelation,
) -> None:
    """Require the target to select the exact accepted relation and candidate."""
    _require_equal(
        (relation.relation_id, relation.selected_candidate_id),
        (target.relation_id, target.selected_candidate_id),
        "pilot target identity does not match correspondence",
    )


def _require_materialization_record_binding(
    record: CandidateRecord,
    materialization: CandidateMaterialization,
) -> None:
    """Require materialization content to pin the exact Phase 1 record."""
    if (
        materialization.phase1_candidate_record_digest
        != compute_candidate_record_digest(record)
    ):
        raise ValueError("candidate materialization is not bound to the Phase 1 record")


def _require_materialization_identity(
    relation: AcceptedCorrespondenceRelation,
    mechanism: MechanismProjection,
) -> None:
    """Require mechanism identity to match the accepted relation."""
    _require_equal(
        (
            relation.obligation_id,
            relation.risk_id,
            relation.attack_pattern_id,
            relation.selected_candidate_id,
        ),
        (
            mechanism.obligation_id,
            mechanism.risk_id,
            mechanism.attack_pattern_id,
            mechanism.selected_candidate_id,
        ),
        "candidate materialization identity does not match correspondence",
    )


def _require_materialization_candidate_identity(
    target: PilotTargetIdentity,
    mechanism: MechanismProjection,
) -> None:
    """Require mechanism identity to retain the selected candidate."""
    if mechanism.selected_candidate_id != target.selected_candidate_id:
        raise ValueError(
            "candidate materialization selected-candidate identity mismatch"
        )


def _require_materialization_projection_alignment(
    record: CandidateRecord,
    mechanism: MechanismProjection,
    scenario: ScenarioEnvelope,
) -> None:
    """Require scenario and materialization projection leaves to be identical."""
    _require_equal(
        mechanism.projection,
        scenario.projection.projection,
        "scenario projection differs from the complete materialization",
    )
    _require_equal(
        mechanism.canonical_ingress,
        scenario.projection.canonical_ingress,
        "scenario ingress differs from the complete materialization",
    )
    _require_equal(
        record.canonical_ingress,
        scenario.projection.canonical_ingress,
        "scenario ingress differs from the Phase 1 candidate record",
    )
    _require_equal(
        record.resource_bindings,
        mechanism.projection.bindings,
        "scenario resource bindings differ from Phase 1",
    )


def _candidate_indexes(authorities: _PilotAuthorities) -> _CandidateIndexes:
    """Build exact indexes for candidate/materialization join checks."""
    expected = authorities.provenance.expected_targets
    return _CandidateIndexes(
        expected=expected,
        generated_keys=frozenset(
            item.key for item in authorities.provenance.generated_targets
        ),
        admitted_keys=frozenset(
            item.key for item in authorities.provenance.admitted_targets
        ),
        records=_candidate_records(authorities.plan),
        materializations=_materialization_records(authorities.materializations),
        relations={
            relation.relation_id: relation
            for relation in authorities.correspondence.accepted_relations
        },
        expected_by_candidate={
            target.selected_candidate_id: target for target in expected
        },
    )


def _prevalidate_candidate_scenarios(
    indexes: _CandidateIndexes,
    scenarios: Sequence[ScenarioEnvelope],
) -> dict[str, ScenarioEnvelope]:
    """Validate complete joins before collection-level ID checks."""
    by_candidate: dict[str, ScenarioEnvelope] = {}
    for scenario in scenarios:
        target = indexes.expected_by_candidate.get(scenario.candidate_id)
        if target is None or target.key not in indexes.admitted_keys:
            by_candidate.setdefault(scenario.candidate_id, scenario)
            continue
        relation = indexes.relations.get(target.relation_id)
        if relation is not None:
            _target_for_candidate(
                target,
                relation,
                indexes.records,
                indexes.materializations,
                {scenario.candidate_id: scenario},
            )
        by_candidate.setdefault(scenario.candidate_id, scenario)
    return by_candidate


def _validate_scenario_candidate_ids(
    scenarios: Sequence[ScenarioEnvelope],
    expected_by_candidate: dict[str, PilotTargetIdentity],
) -> None:
    """Reject duplicate or unrequested scenario candidate identities."""
    candidate_ids = tuple(scenario.candidate_id for scenario in scenarios)
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("scenario envelopes contain duplicate candidate IDs")
    if any(candidate_id not in expected_by_candidate for candidate_id in candidate_ids):
        raise ValueError("scenario envelope contains an extra or unrequested candidate")


def _missing_join_blocker(
    target: PilotTargetIdentity,
    message: str,
    code: str = "missing_corrected_plan_join",
) -> PilotReadinessBlocker:
    """Build one target-scoped missing-join blocker."""
    return PilotReadinessBlocker(code=code, message=message, target=target)


def _join_one_expected_target(
    target: PilotTargetIdentity,
    indexes: _CandidateIndexes,
    scenarios_by_candidate: dict[str, ScenarioEnvelope],
) -> tuple[
    tuple[str, str] | None, ScenarioEnvelope | None, PilotReadinessBlocker | None
]:
    """Resolve one expected target into a joined scenario or blocker."""
    if target.key not in indexes.generated_keys:
        return (
            None,
            None,
            _missing_join_blocker(
                target,
                "expected target was not declared as generated",
            ),
        )
    if target.key not in indexes.admitted_keys:
        return None, None, None
    return _join_one_admitted_target(target, indexes, scenarios_by_candidate)


def _join_one_admitted_target(
    target: PilotTargetIdentity,
    indexes: _CandidateIndexes,
    scenarios_by_candidate: dict[str, ScenarioEnvelope],
) -> tuple[
    tuple[str, str] | None, ScenarioEnvelope | None, PilotReadinessBlocker | None
]:
    """Resolve one generated and admitted target against its authorities."""
    relation = indexes.relations.get(target.relation_id)
    if relation is None:
        return (
            None,
            None,
            _missing_join_blocker(
                target,
                "expected target has no accepted correspondence relation",
            ),
        )
    valid, scenario = _target_for_candidate(
        target,
        relation,
        indexes.records,
        indexes.materializations,
        scenarios_by_candidate,
    )
    if not valid:
        code = (
            "missing_candidate_materialization"
            if scenario is not None
            else "missing_scenario_envelope"
        )
        return (
            None,
            None,
            _missing_join_blocker(
                target,
                "target has no exact corrected-plan candidate join",
                code,
            ),
        )
    return target.key, scenario, None


def _join_expected_targets(
    indexes: _CandidateIndexes,
    scenarios_by_candidate: dict[str, ScenarioEnvelope],
) -> _JoinCheck:
    """Resolve every expected target after candidate checks have passed."""
    joined_scenarios: dict[str, ScenarioEnvelope] = {}
    joined_targets: set[tuple[str, str]] = set()
    blockers: list[PilotReadinessBlocker] = []
    for target in indexes.expected:
        joined_key, scenario, blocker = _join_one_expected_target(
            target, indexes, scenarios_by_candidate
        )
        _record_join_result(
            joined_key,
            scenario,
            blocker,
            joined_scenarios,
            joined_targets,
            blockers,
        )
    return _JoinCheck(
        joined_scenarios=tuple(
            sorted(joined_scenarios.values(), key=lambda item: item.scenario_id)
        ),
        joined_targets=frozenset(joined_targets),
        blockers=tuple(blockers),
    )


def _record_join_result(
    joined_key: tuple[str, str] | None,
    scenario: ScenarioEnvelope | None,
    blocker: PilotReadinessBlocker | None,
    joined_scenarios: dict[str, ScenarioEnvelope],
    joined_targets: set[tuple[str, str]],
    blockers: list[PilotReadinessBlocker],
) -> None:
    """Accumulate one target join outcome in deterministic collections."""
    if blocker is not None:
        blockers.append(blocker)
    if joined_key is not None:
        joined_targets.add(joined_key)
    if scenario is not None:
        joined_scenarios[scenario.candidate_id] = scenario


def _validate_admitted_scenario_targets(
    indexes: _CandidateIndexes,
    scenarios_by_candidate: dict[str, ScenarioEnvelope],
) -> None:
    """Ensure every supplied scenario belongs to an admitted target."""
    for candidate_id in scenarios_by_candidate:
        _require_admitted_scenario_target(indexes, candidate_id)


def _require_admitted_scenario_target(
    indexes: _CandidateIndexes,
    candidate_id: str,
) -> None:
    """Require one supplied scenario candidate to belong to an admitted target."""
    target_keys = {
        item.key
        for item in indexes.expected
        if item.selected_candidate_id == candidate_id
    }
    _require_expected_scenario_target(target_keys)
    _require_admitted_target_key(target_keys, indexes.admitted_keys)


def _require_expected_scenario_target(target_keys: set[tuple[str, str]]) -> None:
    """Require a scenario candidate to occur in the expected target list."""
    if not target_keys:
        raise ValueError("scenario envelope contains an extra target")


def _require_admitted_target_key(
    target_keys: set[tuple[str, str]],
    admitted_keys: frozenset[tuple[str, str]],
) -> None:
    """Require a scenario candidate to occur in an admitted target."""
    if not target_keys & admitted_keys:
        raise ValueError("scenario envelope is not an admitted target")


def _check_candidate_joins(authorities: _PilotAuthorities) -> _JoinCheck:
    """Perform the exact target and candidate sequence before adaptation."""
    indexes = _candidate_indexes(authorities)
    parsed_scenarios = _scenario_candidates(authorities.scenarios)
    scenarios_by_candidate = _prevalidate_candidate_scenarios(
        indexes,
        parsed_scenarios,
    )
    _validate_scenario_candidate_ids(parsed_scenarios, indexes.expected_by_candidate)
    _validate_admitted_scenario_targets(indexes, scenarios_by_candidate)
    return _join_expected_targets(indexes, scenarios_by_candidate)


def _coverage_relation_ids(authorities: _PilotAuthorities) -> set[str]:
    """Return exact assessment rows that are coverage-bearing."""
    return {
        row.relation_id
        for row in authorities.assessment.scenario_realization
        if row.coverage_bearing
    }


def _review_by_relation(
    reviews: Sequence[ConfirmedCoverageReview],
) -> dict[str, ConfirmedCoverageReview]:
    """Index independently confirmed reviews by relation identity."""
    return {item.relation_id: item for item in reviews}


def _stpa_identity_matches(
    authorities: _PilotAuthorities,
    relation: AcceptedCorrespondenceRelation,
) -> bool:
    """Require the accepted relation's exact slot, ICA, and EXEC projection."""
    return any(
        projection.uca_slot_id == relation.ica_slot_id
        and projection.ica_id == relation.ica_id
        and projection.exec_candidate_id == relation.exec_candidate_id
        for projection in authorities.stpa.projections
    )


def _stpa_identity_for_relation(
    authorities: _PilotAuthorities,
    relation_id: str,
) -> bool:
    """Resolve one accepted relation before checking its STPA identity."""
    return any(
        relation.relation_id == relation_id
        and _stpa_identity_matches(authorities, relation)
        for relation in authorities.correspondence.accepted_relations
    )


def _validate_assessment_relation_identity(
    relation: AcceptedCorrespondenceRelation,
    tax_row: TaxonomyCorrespondenceRow,
    realization: ScenarioRealizationRow,
) -> None:
    """Reject assessment rows that do not retain the full accepted identity."""
    identity_checks = (
        (realization.proposal_id, relation.proposal_id),
        (realization.obligation_id, relation.obligation_id),
        (realization.risk_id, relation.risk_id),
        (realization.attack_pattern_id, relation.attack_pattern_id),
        (realization.taxonomy_candidate_ids, relation.taxonomy_candidate_ids),
        (realization.correspondence_relation_kind, relation.relation_kind),
        (tax_row.obligation_id, relation.obligation_id),
        (tax_row.risk_id, relation.risk_id),
        (tax_row.attack_pattern_id, relation.attack_pattern_id),
        (tax_row.taxonomy_candidate_ids, relation.taxonomy_candidate_ids),
    )
    _require_equal_identity_fields(identity_checks)
    _require_selected_candidate_in_taxonomy(relation, tax_row)
    if relation.relation_id not in tax_row.accepted_relation_ids:
        raise ValueError("assessment taxonomy row omits the accepted relation")


def _require_equal_identity_fields(
    checks: Sequence[tuple[object, object]],
) -> None:
    """Require every identity leaf in an assessment row to match."""
    if any(actual != expected for actual, expected in checks):
        raise ValueError("assessment row identity does not match accepted relation")


def _require_selected_candidate_in_taxonomy(
    relation: AcceptedCorrespondenceRelation,
    tax_row: TaxonomyCorrespondenceRow,
) -> None:
    """Require the accepted relation's selected candidate in its taxonomy row."""
    if relation.selected_candidate_id is None:
        raise ValueError("accepted relation has no selected candidate identity")
    if relation.selected_candidate_id not in tax_row.taxonomy_candidate_ids:
        raise ValueError("assessment row omits the accepted selected candidate")


def _assessment_rows_for_relation(
    assessment: HybridCoverageAssessment,
    relation_id: str,
    obligation_id: str,
) -> tuple[TaxonomyCorrespondenceRow, ScenarioRealizationRow] | None:
    """Find the exact taxonomy and realization rows for one relation."""
    tax_row = _taxonomy_row_for_obligation(assessment, obligation_id)
    realization = _realization_row_for_relation(assessment, relation_id)
    if tax_row is None or realization is None:
        return None
    return tax_row, realization


def _taxonomy_row_for_obligation(
    assessment: HybridCoverageAssessment,
    obligation_id: str,
) -> TaxonomyCorrespondenceRow | None:
    """Find one exact taxonomy row by obligation identity."""
    return next(
        (
            row
            for row in assessment.taxonomy_correspondence
            if row.obligation_id == obligation_id
        ),
        None,
    )


def _realization_row_for_relation(
    assessment: HybridCoverageAssessment,
    relation_id: str,
) -> ScenarioRealizationRow | None:
    """Find one exact scenario-realization row by relation identity."""
    return next(
        (
            row
            for row in assessment.scenario_realization
            if row.relation_id == relation_id
        ),
        None,
    )


def _review_has_independent_mechanism_evidence(
    review: ConfirmedCoverageReview | None,
    relation: AcceptedCorrespondenceRelation,
    coverage_ids: set[str],
) -> bool:
    """Check that a review is confirmed for a coverage-bearing relation."""
    return (
        review is not None
        and relation.relation_id in coverage_ids
        and review.mechanism_evidence.record_id == relation.proposal_id
    )


def _has_composed_projection(
    projection_set: HybridScenarioProjectionSet,
    relation_id: str,
) -> bool:
    """Require a confirmed review to have an exact composed projection."""
    return any(
        projection.relation_id == relation_id
        for projection in projection_set.projections
    )


def _bridge_reuses_review_evidence(
    projection_set: HybridScenarioProjectionSet,
    relation_id: str,
    review: ConfirmedCoverageReview,
) -> bool:
    """Reject review evidence reused as the bridge's independent evidence."""
    return any(
        evidence.artifact_pin == review.mechanism_evidence.artifact_pin
        for projection in projection_set.projections
        if projection.relation_id == relation_id
        for bridge in projection.bridge_links
        for evidence in bridge.evidence
    )


def _eligible_one_reviewed_relation(
    authorities: _PilotAuthorities,
    relation: AcceptedCorrespondenceRelation,
    coverage_ids: set[str],
    reviews: dict[str, ConfirmedCoverageReview],
) -> bool:
    """Check all exact evidence requirements for one accepted relation."""
    review = reviews.get(relation.relation_id)
    if not _review_has_independent_mechanism_evidence(review, relation, coverage_ids):
        return False
    if not _has_composed_projection(
        authorities.projection_set,
        relation.relation_id,
    ):
        return False
    rows = _assessment_rows_for_relation(
        authorities.assessment,
        relation.relation_id,
        relation.obligation_id,
    )
    if rows is None or not _stpa_identity_matches(authorities, relation):
        return False
    tax_row, realization = rows
    _validate_assessment_relation_identity(relation, tax_row, realization)
    return not _bridge_reuses_review_evidence(
        authorities.projection_set,
        relation.relation_id,
        review,
    )


def _eligible_reviewed_relations(authorities: _PilotAuthorities) -> set[str]:
    """Find accepted, coverage-bearing relations with independent evidence."""
    accepted = {
        item.relation_id: item
        for item in authorities.correspondence.accepted_relations
        if item.relation_kind != "related_but_not_coverage"
    }
    coverage_ids = _coverage_relation_ids(authorities)
    reviews = _review_by_relation(authorities.reviews)
    return {
        relation_id
        for relation_id, relation in accepted.items()
        if _eligible_one_reviewed_relation(authorities, relation, coverage_ids, reviews)
    }


def _semantic_evidence_blockers(
    authorities: _PilotAuthorities,
) -> list[PilotReadinessBlocker]:
    """Report fixture and model-call evidence that cannot support a pilot."""
    blockers: list[PilotReadinessBlocker] = []
    if authorities.projection_set.evidence_class == "normative_bookkeeping_fixture":
        blockers.append(
            PilotReadinessBlocker(
                code="normative_bookkeeping_fixture",
                message="normative bookkeeping fixtures are not semantic pilot evidence",
            )
        )
    evidence = authorities.provenance.model_call_evidence
    if evidence.adapter_kind == "fake":
        blockers.append(
            PilotReadinessBlocker(
                code="synthetic_evidence",
                message="fake model-call evidence is not semantic pilot evidence",
            )
        )
    elif (
        evidence.adapter_kind != "provider"
        or not evidence.model_calls
        or not evidence.provider_calls
    ):
        blockers.append(
            PilotReadinessBlocker(
                code="missing_model_call_evidence",
                message="semantic pilot requires nonzero provider-backed model-call evidence",
            )
        )
    return blockers


def _lineage_blockers_if_no_eligible(
    eligible: set[str],
) -> tuple[PilotReadinessBlocker, ...]:
    """Report the coverage blocker when no relation is eligible."""
    if eligible:
        return ()
    return (
        PilotReadinessBlocker(
            code="corrected_assessment_without_coverage",
            message=ZERO_ACCEPTED_COVERAGE_BLOCKER,
        ),
    )


def _target_eligibility_blocker(
    target: PilotTargetIdentity,
    authorities: _PilotAuthorities,
    coverage_ids: set[str],
    review_ids: set[str],
) -> PilotReadinessBlocker:
    """Explain why one expected target is not independently eligible."""
    if target.relation_id not in coverage_ids:
        return PilotReadinessBlocker(
            code="corrected_assessment_without_coverage",
            message="expected relation has no accepted coverage-bearing assessment row",
            target=target,
        )
    if target.relation_id not in review_ids:
        return PilotReadinessBlocker(
            code="missing_review_evidence",
            message="expected relation has no independently confirmed review evidence",
            target=target,
        )
    if not _stpa_identity_for_relation(authorities, target.relation_id):
        return PilotReadinessBlocker(
            code="missing_stpa_identity",
            message="expected relation has no exact STPA slot/ICA/EXEC identity",
            target=target,
        )
    return PilotReadinessBlocker(
        code="missing_projection",
        message="expected relation has no exact composed projection",
        target=target,
    )


def _target_gap_blockers(
    authorities: _PilotAuthorities,
    joins: _JoinCheck,
    eligible: set[str],
) -> list[PilotReadinessBlocker]:
    """Report target-scoped eligibility and exact-join gaps."""
    provenance = authorities.provenance
    coverage_ids = _coverage_relation_ids(authorities)
    review_ids = set(_review_by_relation(authorities.reviews))
    blockers = _ineligible_target_blockers(
        provenance.expected_targets,
        authorities,
        eligible,
        coverage_ids,
        review_ids,
    )
    expected_keys = {item.key for item in provenance.expected_targets}
    if len(joins.joined_targets) != len(expected_keys):
        blockers.append(
            PilotReadinessBlocker(
                code="missing_corrected_plan_join",
                message="not every expected target has an exact corrected-plan join",
            )
        )
    return blockers


def _ineligible_target_blockers(
    targets: Sequence[PilotTargetIdentity],
    authorities: _PilotAuthorities,
    eligible: set[str],
    coverage_ids: set[str],
    review_ids: set[str],
) -> list[PilotReadinessBlocker]:
    """Build blockers for expected relations lacking complete evidence."""
    return [
        _target_eligibility_blocker(target, authorities, coverage_ids, review_ids)
        for target in targets
        if target.relation_id not in eligible
    ]


def _append_gate_blockers(
    authorities: _PilotAuthorities,
    joins: _JoinCheck,
) -> list[PilotReadinessBlocker]:
    """Add semantic-pilot limitations without repairing their causes."""
    eligible = _eligible_reviewed_relations(authorities)
    blockers = list(joins.blockers)
    if not authorities.provenance.expected_targets:
        blockers.append(
            PilotReadinessBlocker(
                code="missing_corrected_plan_join",
                message="pilot requires at least one explicit expected target",
            )
        )
    blockers.extend(_semantic_evidence_blockers(authorities))
    blockers.extend(_lineage_blockers_if_no_eligible(eligible))
    blockers.extend(_target_gap_blockers(authorities, joins, eligible))
    return _deduplicate_blockers(blockers)


def _deduplicate_blockers(
    blockers: Sequence[PilotReadinessBlocker],
) -> list[PilotReadinessBlocker]:
    """Retain one deterministic copy of each typed blocker."""
    seen: set[tuple[str, str, tuple[str, str] | None]] = set()
    result: list[PilotReadinessBlocker] = []
    for blocker in blockers:
        key = (
            blocker.code,
            blocker.message,
            blocker.target.key if blocker.target is not None else None,
        )
        if key not in seen:
            seen.add(key)
            result.append(blocker)
    return sorted(
        result,
        key=lambda item: (
            item.code,
            item.message,
            item.target.key if item.target is not None else (),
        ),
    )


def _validate_provenance_counts(
    provenance: PilotProvenanceBundle,
    exact_join_count: int,
) -> None:
    """Require the caller's exact count record to match the typed lists."""
    counts = provenance.exact_join_counts
    expected = PilotExactJoinCounts(
        expected=len(provenance.expected_targets),
        generated=len(provenance.generated_targets),
        admitted=len(provenance.admitted_targets),
        quarantined=len(provenance.quarantined_targets),
        exact_joins=exact_join_count,
    )
    if counts != expected:
        raise ValueError("pilot provenance exact join counts do not reconcile")


def _current_audit_result(
    provenance: PilotProvenanceBundle,
) -> HybridPilotReadinessResult:
    """Report the supplied provenance counts without inventing joins."""
    provenance.assert_integrity()
    counts = provenance.exact_join_counts
    blockers = (
        PilotReadinessBlocker(
            code="missing_corrected_plan_join",
            message=(
                f"exact corrected-plan joins: {counts.exact_joins} of "
                f"{counts.expected} expected targets"
            ),
        ),
        PilotReadinessBlocker(
            code="corrected_assessment_without_coverage",
            message=ZERO_ACCEPTED_COVERAGE_BLOCKER,
        ),
    )
    return HybridPilotReadinessResult(
        ready=False,
        blockers=blockers,
        expected_target_count=counts.expected,
        generated_target_count=counts.generated,
        admitted_target_count=counts.admitted,
        quarantined_target_count=counts.quarantined,
        exact_join_count=0,
    )


def _authority_values(inputs: HybridPilotReadinessInputs) -> tuple[object, ...]:
    """Return the seven authorities that define a complete pilot graph."""
    return (
        inputs.obligation_plan,
        inputs.candidate_materializations,
        inputs.phase2_assessment,
        inputs.correspondence,
        inputs.resource_map_validation,
        inputs.stpa_projection_authority,
        inputs.projection_set,
    )


def _assess_without_authority_graph(
    inputs: HybridPilotReadinessInputs,
) -> HybridPilotReadinessResult:
    """Return the current audit when no future pilot authorities are supplied."""
    if inputs.scenario_envelopes or inputs.confirmed_reviews:
        raise TypeError(
            "scenario and review values require the complete pilot authority graph"
        )
    return _current_audit_result(
        _copy_typed(inputs.provenance, PilotProvenanceBundle, "provenance")
    )


def _require_verified_pilot_provenance(
    inputs: HybridPilotReadinessInputs,
) -> None:
    """Require provenance created for this exact composed projection set."""
    if not _is_verified_provenance(
        inputs.provenance,
        inputs.projection_set.semantic_digest,
    ):
        raise ValueError(
            "provenance must be produced by the verified provenance factory"
        )


def _adapt_joined_scenarios(
    authorities: _PilotAuthorities,
    joins: _JoinCheck,
) -> None:
    """Adapt only exact candidate joins after all pre-adapter checks pass."""
    if joins.joined_scenarios:
        TaxonomyCoverageInput.from_scenario_envelopes(
            authorities.plan,
            joins.joined_scenarios,
        )


def _result_for_authorities(
    authorities: _PilotAuthorities,
    joins: _JoinCheck,
) -> HybridPilotReadinessResult:
    """Build the immutable readiness result from one checked authority graph."""
    blockers = _append_gate_blockers(authorities, joins)
    exact_join_count = len(joins.joined_targets)
    _validate_provenance_counts(authorities.provenance, exact_join_count)
    counts = authorities.provenance.exact_join_counts
    return HybridPilotReadinessResult(
        ready=not blockers,
        blockers=tuple(blockers),
        expected_target_count=counts.expected,
        generated_target_count=counts.generated,
        admitted_target_count=counts.admitted,
        quarantined_target_count=counts.quarantined,
        exact_join_count=counts.exact_joins,
    )


def _assess_complete_authority_graph(
    inputs: HybridPilotReadinessInputs,
) -> HybridPilotReadinessResult:
    """Run the full offline gate after a complete graph is supplied."""
    _require_verified_pilot_provenance(inputs)
    authorities = _copy_authorities(inputs)
    _assert_integrity(authorities)
    _require_pin_digests(authorities)
    joins = _check_candidate_joins(authorities)
    _adapt_joined_scenarios(authorities, joins)
    return _result_for_authorities(authorities, joins)


def assess_hybrid_pilot_readiness(
    inputs: HybridPilotReadinessInputs,
) -> HybridPilotReadinessResult:
    """Assess whether one explicit target-scoped semantic pilot may start.

    The function is deterministic and offline.  It reports missing corpus or
    review evidence as typed blockers, while malformed or substituted
    authorities raise immediately.
    """
    if not isinstance(inputs, HybridPilotReadinessInputs):
        raise TypeError("inputs must be a HybridPilotReadinessInputs")
    authorities_present = _authority_values(inputs)
    if not any(authorities_present):
        return _assess_without_authority_graph(inputs)
    if not all(authorities_present):
        raise TypeError("pilot authority graph is incomplete")
    return _assess_complete_authority_graph(inputs)


__all__ = [
    "SCENARIO_ARTIFACT_DIGEST_DOMAIN",
    "ZERO_ACCEPTED_COVERAGE_BLOCKER",
    "assess_hybrid_pilot_readiness",
]

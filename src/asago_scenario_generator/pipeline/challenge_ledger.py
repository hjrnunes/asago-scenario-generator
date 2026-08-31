"""Pure construction seam for the offline Phase 3 STPA challenge ledger."""

from __future__ import annotations

from collections.abc import Sequence

from asago_scenario_generator.models.challenge_ledger import (
    EXPLICIT_PRIORITY_POLICY_VERSION,
    ChallengeEligibility,
    ChallengeLedgerDiagnostics,
    ChallengeRecord,
    OriginalStpaDecision,
    StpaChallengeLedger,
    compute_challenge_id,
)
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    HybridCoverageAssessment,
    StructuralConsiderationRow,
)


def _validate_assessment(assessment: HybridCoverageAssessment) -> str:
    if not isinstance(assessment, HybridCoverageAssessment):
        raise TypeError("assessment must be a HybridCoverageAssessment")
    assessment.assert_integrity()
    digest = assessment.semantic_digest
    if digest is None:  # pragma: no cover - enforced by the assessment model
        raise ValueError("assessment semantic digest is missing")
    return digest


def _validate_budget(challenge_budget: int) -> None:
    if type(challenge_budget) is not int:
        raise TypeError("challenge_budget must be an integer")
    if challenge_budget < 0:
        raise ValueError("challenge_budget must be non-negative")


def _validate_adapter_inputs(
    assessment_artifact_id: str, selection_policy_version: str
) -> None:
    if not assessment_artifact_id:
        raise ValueError("assessment_artifact_id must be non-empty")
    if selection_policy_version != EXPLICIT_PRIORITY_POLICY_VERSION:
        raise ValueError("unsupported challenge selection policy version")


def _ordered_eligibility(
    eligibility: Sequence[ChallengeEligibility],
) -> tuple[ChallengeEligibility, ...]:
    typed = tuple(eligibility)
    if any(not isinstance(item, ChallengeEligibility) for item in typed):
        raise TypeError("eligibility must contain ChallengeEligibility records")
    ordered = tuple(
        sorted(
            typed,
            key=lambda item: (item.priority, item.obligation_id, item.slot_id),
        )
    )
    pairs = tuple((item.obligation_id, item.slot_id) for item in ordered)
    if len(pairs) != len(set(pairs)):
        raise ValueError("eligibility contains duplicate obligation/STPA-slot pairs")
    return ordered


def _validate_target_identities(
    eligibility: tuple[ChallengeEligibility, ...],
    obligation_ids: set[str],
    slots: dict[str, StructuralConsiderationRow],
) -> None:
    for item in eligibility:
        if item.obligation_id not in obligation_ids:
            raise ValueError("eligibility references an unknown obligation")
        if item.slot_id not in slots:
            raise ValueError("eligibility references an unknown STPA slot")


def _original_decision(structural: StructuralConsiderationRow) -> OriginalStpaDecision:
    return OriginalStpaDecision(
        row_id=structural.row_id,
        slot_id=structural.slot_id,
        controller_id=structural.controller_id,
        control_action_id=structural.control_action_id,
        uca_type=structural.uca_type,
        disposition=structural.disposition,
        ica_ids=structural.ica_ids,
        evidence=structural.evidence,
        trace_refs=structural.trace_refs,
    )


def _challenge_record(
    item: ChallengeEligibility,
    structural: StructuralConsiderationRow,
    assessment_digest: str,
    selected: bool,
) -> ChallengeRecord:
    return ChallengeRecord(
        challenge_id=compute_challenge_id(
            assessment_digest,
            item.obligation_id,
            item.slot_id,
        ),
        obligation_id=item.obligation_id,
        slot_id=item.slot_id,
        priority=item.priority,
        eligibility_rationale=item.rationale,
        eligibility_evidence_refs=item.evidence_refs,
        selection_status="selected" if selected else "not_selected_budget",
        original_decision=_original_decision(structural),
    )


def _challenge_records(
    eligibility: tuple[ChallengeEligibility, ...],
    slots: dict[str, StructuralConsiderationRow],
    assessment_digest: str,
    challenge_budget: int,
) -> tuple[ChallengeRecord, ...]:
    return tuple(
        _challenge_record(
            item,
            slots[item.slot_id],
            assessment_digest,
            index < challenge_budget,
        )
        for index, item in enumerate(eligibility)
    )


def build_stpa_challenge_ledger(
    assessment: HybridCoverageAssessment,
    eligibility: Sequence[ChallengeEligibility],
    *,
    challenge_budget: int,
    assessment_artifact_id: str,
    selection_policy_version: str,
) -> StpaChallengeLedger:
    """Select exact eligible targets and retain their original STPA decisions."""
    digest = _validate_assessment(assessment)
    _validate_budget(challenge_budget)
    _validate_adapter_inputs(assessment_artifact_id, selection_policy_version)
    ordered = _ordered_eligibility(eligibility)
    obligation_ids = {row.obligation_id for row in assessment.taxonomy_correspondence}
    slots = {row.slot_id: row for row in assessment.structural_consideration}
    _validate_target_identities(ordered, obligation_ids, slots)
    records = _challenge_records(ordered, slots, digest, challenge_budget)

    selected = min(challenge_budget, len(records))
    return StpaChallengeLedger(
        assessment_pin=ArtifactPin(
            artifact_id=assessment_artifact_id,
            schema_version=assessment.schema_version,
            semantic_digest=digest,
        ),
        source_pins=assessment.source_pins,
        selection_policy_version=selection_policy_version,
        challenge_budget=challenge_budget,
        records=records,
        diagnostics=ChallengeLedgerDiagnostics(
            eligible_targets=len(records),
            selected_targets=selected,
            not_selected_budget=len(records) - selected,
        ),
    )


__all__ = ["build_stpa_challenge_ledger"]

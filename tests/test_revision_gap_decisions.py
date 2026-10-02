"""Gap-decision closure checks on the one bounded structural revision."""

from __future__ import annotations

from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    DraftResponsibility,
    RevisionDraft,
    RevisionGapDecision,
    StructuralRevisionResponse,
)
from asago_scenario_generator.stpa.obligation_aware.revision import (
    RevisionRunResult,
    revise_structure_once,
)
from tests.test_obligation_aware_stpa import (
    _control_structure,
    _controls,
    _loss_analysis,
)


def _gaps() -> tuple[MissingStructuralConcept, ...]:
    return (
        MissingStructuralConcept(
            concept_type="responsibility",
            description="A reviewing responsibility is missing.",
            evidence_refs=("review-gap",),
        ),
        MissingStructuralConcept(
            concept_type="feedback_channel",
            description="Review outcomes are not fed back.",
            evidence_refs=("feedback-gap",),
        ),
    )


def _decision(handle: str, disposition: str = "dismiss_unsupported"):
    return RevisionGapDecision(
        gap_handle=handle,
        disposition=disposition,
        rationale=f"{handle} rationale",
    )


def _revise(draft: RevisionDraft) -> RevisionRunResult:
    class Adapter:
        def revise(self, request):
            return StructuralRevisionResponse(
                request_digest=request.semantic_digest,
                draft=draft,
            )

    return revise_structure_once(
        Adapter(),
        gaps=_gaps(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        trigger_obligation_ids=("obligation-1",),
        controls=_controls(),
    )


def _reviewer() -> tuple[DraftResponsibility, ...]:
    return (
        DraftResponsibility(
            handle="reviewer",
            description="Review requests for policy compliance.",
        ),
    )


def test_decisions_must_name_every_request_handle_and_no_other() -> None:
    """Missing and unknown handles are both reported, missing first."""
    result = _revise(
        RevisionDraft(
            gap_decisions=(
                _decision("revision-gap-1"),
                _decision("revision-gap-9"),
            )
        )
    )

    assert result.status == "technical_failure"
    assert result.diagnostics == (
        "compile failure: ValueError: revision gap decisions do not close the "
        "request (missing gap handles: revision-gap-2; "
        "unknown gap handles: revision-gap-9)",
    )
    assert result.final_control_structure == result.baseline_control_structure


def test_unknown_handle_alone_is_reported() -> None:
    """A complete set plus an extra handle fails on the extra handle only."""
    result = _revise(
        RevisionDraft(
            gap_decisions=(
                _decision("revision-gap-1"),
                _decision("revision-gap-2"),
                _decision("revision-gap-3"),
            )
        )
    )

    assert result.status == "technical_failure"
    assert result.diagnostics == (
        "compile failure: ValueError: revision gap decisions do not close the "
        "request (unknown gap handles: revision-gap-3)",
    )


def test_decisions_reject_final_gap_ids() -> None:
    """Closed request-local decisions cannot also dismiss final gap IDs."""
    gap_id = _gaps()[0].gap_id
    assert gap_id is not None
    result = _revise(
        RevisionDraft(
            gap_decisions=(
                _decision("revision-gap-1"),
                _decision("revision-gap-2"),
            ),
            dismissed_gap_ids=(gap_id,),
        )
    )

    assert result.status == "technical_failure"
    assert result.diagnostics == (
        "compile failure: ValueError: revision draft must use request-local "
        "gap handles, not final gap IDs",
    )


def test_proposed_addition_requires_an_addition() -> None:
    """A propose_addition decision with an empty draft is a technical failure."""
    result = _revise(
        RevisionDraft(
            gap_decisions=(
                _decision("revision-gap-1", "propose_addition"),
                _decision("revision-gap-2"),
            )
        )
    )

    assert result.status == "technical_failure"
    assert result.diagnostics == (
        "compile failure: ValueError: propose_addition decisions require at "
        "least one request-local addition",
    )


def test_closed_dismissals_are_a_domain_rejection() -> None:
    """Every handle dismissed, with no addition, is a rejected revision."""
    result = _revise(
        RevisionDraft(
            gap_decisions=(
                _decision("revision-gap-2", "unresolved"),
                _decision("revision-gap-1"),
            )
        )
    )

    assert result.status == "rejected"
    assert result.diagnostics == (
        "revision-gap-2: unresolved: revision-gap-2 rationale",
        "revision-gap-1: dismiss_unsupported: revision-gap-1 rationale",
    )


def test_closed_proposal_with_an_addition_is_applied() -> None:
    """A closed decision set with a real addition revises the structure."""
    result = _revise(
        RevisionDraft(
            responsibilities=_reviewer(),
            gap_decisions=(
                _decision("revision-gap-1", "propose_addition"),
                _decision("revision-gap-2"),
            ),
        )
    )

    assert result.status == "applied"
    assert [
        item.resp_id for item in result.final_control_structure.responsibilities
    ] == ["RESP-1", "RESP-2"]

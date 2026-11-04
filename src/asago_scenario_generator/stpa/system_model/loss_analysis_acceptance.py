"""Acceptance of one Stage 1a draft, in the order every path uses.

Three Stage 1a paths accept a draft: the first reply, the deterministic
cleanup of a failed reply, and the targeted repair.  The order used to differ
between them.  This module owns the one order: re-check the draft against the
row-level repair view, merge it over the authority of an earlier call, then
normalize the citation evidence.  The caller runs its own validators
immediately after acceptance, so every path keeps its own failure messages and
repair records.

The repair model is a required argument.  A missing model once made the
re-check silently do nothing; nothing can skip it now.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from pydantic import BaseModel, ValidationError

from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
)

# A citing loss that accounts for more than this many risk cards weakens
# the "the citation is direct evidence" argument (one bulk loss can sweep
# in cards the model explicitly excluded), so those flips are flagged for
# reviewer attention in the gates artifact.
BULK_CITATION_FLAG_THRESHOLD = 8


def format_validation_errors(
    exc: ValidationError, *, limit: int = 3
) -> tuple[str, ...]:
    """Format a pydantic error's items as ``location: message`` strings."""
    return tuple(
        f"{'.'.join(str(part) for part in item.get('loc', ())) or 'row'}: "
        f"{item.get('msg', '')}"
        for item in exc.errors()[:limit]
    )


def revalidate_provider_object(
    draft: LossAnalysisDraft,
    model: type[BaseModel],
    *,
    step: str,
) -> None:
    """Re-validate the corrected draft against the original repair schema.

    After salvage and any repair or cleanup, the corrected collections must
    still satisfy the row-level repair view of the provider wire before the
    authority merge.  ``model`` is required: the check must never be a no-op.
    """
    try:
        model.model_validate(draft.model_dump(mode="json"))
    except ValidationError as exc:
        first = format_validation_errors(exc, limit=3)
        raise ValueError(
            f"{step}: the corrected response no longer satisfies the original "
            "provider schema: " + "; ".join(first)
        ) from exc


def normalize_disposition_citations(
    analysis: LossAnalysisDraft | LossAnalysis,
) -> list[str]:
    """Resolve disposition/citation contradictions from the response's own evidence.

    A ``not_applicable`` disposition for a risk card that a loss explicitly
    cites in ``source_risk_cards`` is self-contradictory wire data (spec rule
    1.1(4)).  The citation is direct evidence that the model derived that
    loss from the risk, so deterministic code flips the disposition to
    ``cited`` with exactly the citing losses and returns a warning for
    reviewer visibility in the gates artifact.  The warning retains the
    model's dropped reason and flags flips whose only citing loss is a bulk
    citation (more than :data:`BULK_CITATION_FLAG_THRESHOLD` cards), where
    the dropped reason deserves human attention.  Mutates the analysis in
    place.
    """
    warnings: list[str] = []
    citing: dict[str, list[str]] = {}
    loss_citation_counts: dict[str, int] = {}
    for loss in analysis.risk_card_losses + analysis.use_case_losses:
        loss_citation_counts[loss.loss_id] = len(set(loss.source_risk_cards))
        for risk_ref in loss.source_risk_cards:
            citing.setdefault(risk_ref, []).append(loss.loss_id)
    for disposition in analysis.risk_dispositions:
        if disposition.disposition != "not_applicable":
            continue
        loss_ids = sorted(set(citing.get(disposition.risk_ref, ())))
        if not loss_ids:
            continue
        dropped_reason = (disposition.reason or "").strip()
        disposition.disposition = "cited"
        disposition.loss_ids = loss_ids
        disposition.reason = None
        warnings.append(
            _citation_flip_warning(
                disposition.risk_ref, loss_ids, dropped_reason, loss_citation_counts
            )
        )
    return warnings


def _citation_flip_warning(
    risk_ref: str,
    loss_ids: list[str],
    dropped_reason: str,
    loss_citation_counts: dict[str, int],
) -> str:
    bulk_losses = [
        loss_id
        for loss_id in loss_ids
        if loss_citation_counts.get(loss_id, 0) > BULK_CITATION_FLAG_THRESHOLD
    ]
    bulk_note = (
        f"; bulk citation: {', '.join(bulk_losses)} cite more than "
        f"{BULK_CITATION_FLAG_THRESHOLD} cards, review the dropped reason"
        if bulk_losses
        else ""
    )
    reason_note = (
        f"; the model's dropped reason was: {dropped_reason}"
        if dropped_reason
        else "; the model gave no reason"
    )
    return (
        f"risk accounting normalized: '{risk_ref}' was "
        f"not_applicable but is cited by {', '.join(loss_ids)}"
        f"{reason_note}; flipped to cited from the response's own "
        f"citation evidence{bulk_note}"
    )


def record_warnings(warnings: Iterable[str], recorded: list[str] | None) -> None:
    """Append each new warning once, when the caller collects warnings."""
    for warning in warnings:
        if recorded is not None and warning not in recorded:
            recorded.append(warning)


def accept_stage1a_draft(
    draft: LossAnalysisDraft,
    *,
    repair_model: type[BaseModel],
    authority: Callable[[LossAnalysisDraft], LossAnalysisDraft] | None,
    warnings: list[str] | None,
    step: str,
    normalize: Callable[[LossAnalysisDraft], Iterable[str]] = (
        normalize_disposition_citations
    ),
) -> LossAnalysisDraft:
    """Re-check, merge over the authority, then normalize a Stage 1a draft.

    The order is the contract.  The re-check runs first so a draft the repair
    view refuses never reaches the authority merge.  The authority merge runs
    before citation normalization because it removes exact repeats of the
    accepted graph; normalizing first would cite a loss the merge then
    removes and would record a warning for a draft the merge rejects.  The
    caller validates the returned draft immediately after, with the validators
    and failure messages of its own path.
    """
    revalidate_provider_object(draft, repair_model, step=step)
    accepted = authority(draft) if authority is not None else draft
    record_warnings(normalize(accepted), warnings)
    return accepted

"""Acceptance of one Stage 1a draft, in the order every path uses.

Three Stage 1a paths accept a draft: the first reply, the deterministic
cleanup of a failed reply, and the targeted repair.  The order used to differ
between them.  This module owns the one order: re-check the draft against the
row-level repair view, merge it over the authority of an earlier call, then
normalize the citation evidence.  The caller runs its own validators
immediately after acceptance, so every path keeps its own failure messages and
repair records.

This module also owns the acceptance decision for a revised graph.  A revision
that fails only the class-ownership check loses the added constraints that
take over a hazard another behavior class cites alone
(:func:`_trim_failed_class_ownership`); that decision reads the prior graph
and the revision's records, so it lives here rather than in the model call
that produced them.

The repair model is a required argument.  A missing model once made the
re-check silently do nothing; nothing can skip it now.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from pydantic import BaseModel, ValidationError

from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_checks import (
    UNCLASSIFIED,
    HazardGraphDensityReport,
    _declared_class,
    check_hazard_graph_density,
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


def _fails_only_class_ownership(report: HazardGraphDensityReport) -> bool:
    return not report.passed and not (
        report.losses_without_hazard
        or report.constraints_without_hazard
        or report.hazards_without_constraint
    )


def _sole_citing_classes(analysis: LossAnalysis) -> dict[str, str]:
    """Map each hazard that one classified behavior class alone cites to it."""
    classes: dict[str, set[str]] = {}
    for constraint in analysis.security_constraints:
        for hazard_id in constraint.related_hazards:
            classes.setdefault(hazard_id, set()).add(_declared_class(constraint))
    return {
        hazard_id: next(iter(cited))
        for hazard_id, cited in classes.items()
        if len(cited) == 1 and UNCLASSIFIED not in cited
    }


def _trimmed_graph(
    revised: LossAnalysis, kept: list[SecurityConstraint], orphaned: set[str]
) -> LossAnalysis:
    return LossAnalysis.model_validate(
        {
            "risk_card_losses": revised.risk_card_losses,
            "use_case_losses": revised.use_case_losses,
            "hazards": [h for h in revised.hazards if h.hazard_id not in orphaned],
            "security_constraints": kept,
            "risk_dispositions": revised.risk_dispositions,
        }
    )


def _cross_class_hazards(
    constraint: SecurityConstraint, sole: dict[str, str]
) -> list[str]:
    """The hazards *constraint* cites that a different class cites alone."""
    declared = _declared_class(constraint)
    return [h for h in constraint.related_hazards if sole.get(h, declared) != declared]


def _cross_class_record(
    constraint_id: str, clashes: list[str], sole: dict[str, str]
) -> dict:
    owners = ", ".join(sorted({sole[h] for h in clashes}))
    return {
        "record": "security_constraint_addition",
        "constraint_id": constraint_id,
        "error": f"it cites hazard {', '.join(clashes)}, which {owners} "
        "constraints cite alone, so the revised graph leaves that behavior "
        "class without a hazard of its own",
    }


def _trim_cross_class_additions(
    prior: LossAnalysis, revised: LossAnalysis
) -> tuple[LossAnalysis, list[dict]]:
    """Drop added constraints that cite a hazard another class cites alone.

    Prior constraints stay as they are.  A new hazard only a trimmed
    constraint cited goes with it.  Returns *revised* and no records when no
    added constraint cites such a hazard.
    """
    sole = _sole_citing_classes(prior)
    prior_ids = {c.constraint_id for c in prior.security_constraints}
    kept: list[SecurityConstraint] = []
    dropped: list[dict] = []
    cited_by_dropped: set[str] = set()
    for constraint in revised.security_constraints:
        clashes = _cross_class_hazards(constraint, sole)
        if constraint.constraint_id in prior_ids or not clashes:
            kept.append(constraint)
            continue
        cited_by_dropped.update(constraint.related_hazards)
        dropped.append(_cross_class_record(constraint.constraint_id, clashes, sole))
    if not dropped:
        return revised, []
    still_cited = {h for c in kept for h in c.related_hazards}
    prior_hazards = {h.hazard_id for h in prior.hazards}
    orphaned = cited_by_dropped - still_cited - prior_hazards
    return _trimmed_graph(revised, kept, orphaned), dropped


def _trim_failed_class_ownership(
    prior: LossAnalysis,
    revised: LossAnalysis,
    density: HazardGraphDensityReport,
) -> tuple[LossAnalysis, HazardGraphDensityReport, list[dict]]:
    """Repair a revision that fails only the class-ownership check.

    The model cites a hazard it declared for another behavior class, so the
    class that owned that hazard has none of its own.  Trimming the added
    constraints that do so is the repair; the trimmed graph replaces
    *revised* only when it still adds something and passes the density
    checks.  Otherwise the result is *revised* and *density*, unchanged.
    """
    if not _fails_only_class_ownership(density):
        return revised, density, []
    trimmed, dropped = _trim_cross_class_additions(prior, revised)
    if not dropped or trimmed == prior:
        return revised, density, []
    trimmed_density = check_hazard_graph_density(trimmed)
    if not trimmed_density.passed:
        return revised, density, []
    return trimmed, trimmed_density, dropped

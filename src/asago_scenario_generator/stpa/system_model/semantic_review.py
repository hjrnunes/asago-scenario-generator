"""Apply one explicit, target-blind semantic review.

Call 3 is the final Stage 2 seam where the systemic loss graph and the
control structure are considered together.  The provider may make only
bounded, source-grounded decisions:

* preserve or revise the wording of an existing hazard or constraint, or mark
  it unresolved;
* select the existing security-constraint-to-hazard edges;
* select existing responsibility ownership and action effect labels.

The review never creates records, changes identities or ordering, rewrites
hazard loss membership, or mutates the supplied draft artifacts.  Evidence is
validated against the explicit use-case text and the supplied loss
descriptions, rather than inferred from action prose or from a domain role.
"""

from __future__ import annotations

import copy
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlStructure,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    LossAnalysis,
    Obligation,
    SecurityConstraint,
    compose_constraint_description,
)


ReviewDisposition = Literal["preserve", "revise", "unresolved"]


class _ReviewRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SourceEvidence(_ReviewRecord):
    """One exact quotation from an allowed source context."""

    source_ref: StrictStr
    quote: StrictStr = Field(min_length=1)
    meaning: StrictStr = Field(min_length=1)

    @field_validator("quote", "meaning")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("source evidence text must be nonblank")
        return value

    @field_validator("source_ref")
    @classmethod
    def restrict_source_ref_shape(cls, value: str) -> str:
        if value != "USE_CASE" and not value.startswith("L-"):
            raise ValueError("source_ref must be USE_CASE or a supplied L-* loss ID")
        return value


class HazardSemanticReview(_ReviewRecord):
    """One explicit wording/disposition decision for one supplied hazard."""

    hazard_id: StrictStr
    disposition: ReviewDisposition
    revised_description: StrictStr | None
    missing_fact: StrictStr | None
    source_evidence: tuple[SourceEvidence, ...]
    rationale: StrictStr = Field(min_length=1)


class ResponsibilityReview(_ReviewRecord):
    responsibility_id: StrictStr
    constraint_refs: tuple[StrictStr, ...]
    rationale: StrictStr = Field(min_length=1)


class ActionEffectReview(_ReviewRecord):
    control_action_id: StrictStr
    effect_kind: ControlActionEffectKind | None
    rationale: StrictStr = Field(min_length=1)


class ConstraintHazardReview(_ReviewRecord):
    """One wording/disposition and edge decision for one security constraint."""

    constraint_id: StrictStr
    disposition: ReviewDisposition
    revised_description: StrictStr | None
    missing_fact: StrictStr | None
    related_hazards: tuple[StrictStr, ...]
    source_evidence: tuple[SourceEvidence, ...]
    rationale: StrictStr = Field(min_length=1)

    @field_validator("related_hazards")
    @classmethod
    def reject_duplicate_hazards(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("semantic review contains duplicate related hazards")
        return value


class ControlStructureSemanticReview(_ReviewRecord):
    """Complete explicit decisions for the loss graph and control structure."""

    hazards: tuple[HazardSemanticReview, ...]
    constraints: tuple[ConstraintHazardReview, ...]
    responsibilities: tuple[ResponsibilityReview, ...]
    actions: tuple[ActionEffectReview, ...]

    def unresolved_ids(self) -> tuple[frozenset[str], frozenset[str]]:
        """Return the hazard and constraint IDs this review marks unresolved."""
        return (
            frozenset(
                row.hazard_id for row in self.hazards if row.disposition == "unresolved"
            ),
            frozenset(
                row.constraint_id
                for row in self.constraints
                if row.disposition == "unresolved"
            ),
        )


@dataclass(frozen=True)
class SemanticReviewResult:
    """The independent, immutable result of applying one joint review."""

    loss_analysis: LossAnalysis
    control_structure: ControlStructure


def _exact_index(records, field: str, expected: set[str]) -> dict:
    """Index exact review rows, rejecting omissions, additions and duplicates."""
    result = {getattr(record, field): record for record in records}
    if len(result) != len(records) or set(result) != expected:
        raise ValueError(f"semantic review must cover each {field} exactly once")
    return result


def _source_contexts(
    loss_analysis: LossAnalysis,
    use_case_text: str,
) -> dict[str, str]:
    """Return the complete, explicitly allowed evidence context."""
    contexts = {"USE_CASE": use_case_text}
    contexts.update(
        {
            loss.loss_id: loss.description
            for loss in loss_analysis.risk_card_losses + loss_analysis.use_case_losses
        }
    )
    return contexts


def quote_is_substring(quote: str, sources: tuple[str, ...]) -> bool:
    """Return whether *quote* appears verbatim in any supplied source text.

    Shared containment check for evidence-bearing reviews.  A quote matches
    when it is a substring of at least one source record, so a card quote
    may come from its name, description, or consequence.
    """
    return any(quote in source for source in sources)


def _validate_source_evidence(
    evidence: tuple[SourceEvidence, ...],
    contexts: dict[str, str],
) -> None:
    """Validate exact source references and quote containment."""
    for item in evidence:
        source = contexts.get(item.source_ref)
        if source is None:
            raise ValueError(
                "semantic review source_ref must be USE_CASE or a supplied loss ID"
            )
        if not quote_is_substring(item.quote, (source,)):
            raise ValueError(
                f"semantic review quote is not an exact substring of {item.source_ref}"
            )


def _validate_disposition(
    *,
    identity: str,
    original_description: str,
    disposition: ReviewDisposition,
    revised_description: str | None,
    missing_fact: str | None,
    source_evidence: tuple[SourceEvidence, ...],
    contexts: dict[str, str],
    kind: str,
) -> None:
    """Validate the closed preserve/revise/unresolved decision contract."""
    _validate_source_evidence(source_evidence, contexts)
    if disposition == "preserve":
        if revised_description is not None or missing_fact is not None:
            raise ValueError(
                f"{kind} {identity} preserve cannot provide replacement or missing_fact"
            )
        return
    if disposition == "revise":
        if (
            revised_description is None
            or not revised_description.strip()
            or revised_description.strip() == original_description.strip()
        ):
            raise ValueError(
                f"{kind} {identity} revise requires changed nonblank revised_description"
            )
        if missing_fact is not None:
            raise ValueError(f"{kind} {identity} revise cannot provide missing_fact")
        if not source_evidence:
            raise ValueError(
                f"{kind} {identity} revise requires nonempty source_evidence"
            )
        return
    # The Pydantic Literal closes this branch to the explicit unresolved value.
    if revised_description is not None:
        raise ValueError(
            f"{kind} {identity} unresolved cannot provide revised_description"
        )
    if missing_fact is None or not missing_fact.strip():
        raise ValueError(f"{kind} {identity} unresolved requires nonblank missing_fact")


def apply_control_structure_semantic_review(
    structure: ControlStructure,
    loss_analysis: LossAnalysis,
    review: ControlStructureSemanticReview,
    *,
    use_case_text: str = "",
) -> SemanticReviewResult:
    """Validate and apply one complete review to independent copies.

    ``use_case_text`` is an explicit source context for ``USE_CASE`` evidence.
    It defaults to an empty string for callers that submit only preserve or
    unresolved decisions without source quotations; any supplied USE_CASE
    quotation still fails closed when no text was provided.

    Application is ordered and bounded: hazard wording is applied first,
    constraint wording and hazard edges second, then responsibility ownership
    and action effects.  Loss records, all identities and ordering, and every
    hazard's ``related_losses`` remain unchanged.
    """
    if review is None:
        raise ValueError("semantic_review is required")

    reviewed_loss_analysis = copy.deepcopy(loss_analysis)
    reviewed_structure = copy.deepcopy(structure)
    owners, actions, hazard_rows, constraint_rows = _review_indexes(
        reviewed_structure,
        reviewed_loss_analysis,
        review,
    )
    contexts = _source_contexts(reviewed_loss_analysis, use_case_text)
    hazards_by_id = {
        hazard.hazard_id: hazard for hazard in reviewed_loss_analysis.hazards
    }
    constraints_by_id = {
        constraint.constraint_id: constraint
        for constraint in reviewed_loss_analysis.security_constraints
    }

    unresolved_hazards = _apply_hazard_review(hazard_rows, hazards_by_id, contexts)
    for constraint_id, row in constraint_rows.items():
        _apply_constraint_review(
            constraint_id,
            row,
            constraints_by_id[constraint_id],
            hazard_ids=set(hazards_by_id),
            unresolved_hazards=unresolved_hazards,
            contexts=contexts,
        )

    constraint_ids = set(constraints_by_id)
    unresolved_constraints = {
        constraint_id
        for constraint_id, row in constraint_rows.items()
        if row.disposition == "unresolved"
    }
    payload = reviewed_structure.model_dump(mode="json")
    for resp in payload["responsibilities"]:
        owner = owners[resp["resp_id"]]
        selected_constraints = _reviewed_constraints(owner, constraint_ids)
        if unresolved_constraints.intersection(selected_constraints):
            raise ValueError(
                f"responsibility {resp['resp_id']} owns an unresolved constraint"
            )
        resp["security_constraint_refs"] = selected_constraints
        for action in resp["control_actions"]:
            action["effect_kind"] = actions[action["ca_id"]].effect_kind
    reviewed_loss_analysis = LossAnalysis.model_validate(
        reviewed_loss_analysis.model_dump(mode="json")
    )
    reviewed_structure = ControlStructure.model_validate(payload)
    return SemanticReviewResult(
        loss_analysis=reviewed_loss_analysis,
        control_structure=reviewed_structure,
    )


def _apply_hazard_review(
    hazard_rows: dict[str, HazardSemanticReview],
    hazards_by_id: dict[str, Hazard],
    contexts: dict[str, str],
) -> set[str]:
    """Validate every hazard row, apply revisions, and return unresolved IDs."""
    for hazard_id, row in hazard_rows.items():
        _validate_disposition(
            identity=hazard_id,
            original_description=hazards_by_id[hazard_id].description,
            disposition=row.disposition,
            revised_description=row.revised_description,
            missing_fact=row.missing_fact,
            source_evidence=row.source_evidence,
            contexts=contexts,
            kind="hazard",
        )

    unresolved_hazards = {
        hazard_id
        for hazard_id, row in hazard_rows.items()
        if row.disposition == "unresolved"
    }
    for hazard_id, row in hazard_rows.items():
        if row.disposition == "revise":
            hazards_by_id[hazard_id].description = row.revised_description  # type: ignore[assignment]
    return unresolved_hazards


def _apply_constraint_review(
    constraint_id: str,
    row: ConstraintHazardReview,
    constraint: SecurityConstraint,
    *,
    hazard_ids: set[str],
    unresolved_hazards: set[str],
    contexts: dict[str, str],
) -> None:
    """Validate one constraint row and apply its wording and hazard edges."""
    _validate_disposition(
        identity=constraint_id,
        # Phase 1.3 as amended: the review corrects the authored rule;
        # an unchanged echo of the composed statement is not a change.
        original_description=compose_constraint_description(
            constraint.rule, constraint.applies_when
        ),
        disposition=row.disposition,
        revised_description=row.revised_description,
        missing_fact=row.missing_fact,
        source_evidence=row.source_evidence,
        contexts=contexts,
        kind="constraint",
    )
    if row.disposition == "unresolved":
        if row.related_hazards:
            raise ValueError(
                f"unresolved constraint {constraint_id} must have empty hazard edges"
            )
        constraint.related_hazards = []
        return
    if unresolved_hazards.intersection(row.related_hazards):
        raise ValueError(f"constraint {constraint_id} references an unresolved hazard")
    if row.disposition == "revise":
        _require_obligation_phrases(
            constraint_id,
            row.revised_description,  # type: ignore[arg-type]
            constraint.obligations,
        )
        # Phase 1.3 as amended: a reviewed wording correction rewrites
        # the authored rule; the composed description follows it with
        # the authored conditions intact.
        constraint.rule = row.revised_description  # type: ignore[assignment]
        constraint.description = compose_constraint_description(
            constraint.rule, constraint.applies_when
        )
    constraint.related_hazards = _reviewed_hazards(row, hazard_ids)


def _reviewed_constraints(
    review: ResponsibilityReview,
    allowed: set[str],
) -> list[str]:
    """Validate and retain the explicit responsibility constraint order."""
    selected = list(review.constraint_refs)
    if len(set(selected)) != len(selected) or not set(selected) <= allowed:
        raise ValueError("semantic review contains duplicate or unknown constraints")
    return selected


def _require_obligation_phrases(
    constraint_id: str,
    revised_rule: str,
    obligations: Sequence[Obligation],
) -> None:
    """Reject a rule rewrite that orphans an obligation's quoted phrase.

    Obligations are interpretations of exact rule wording; code cannot
    re-anchor one to new wording, so the model must keep the phrase or
    leave the rule unchanged.
    """
    folded = revised_rule.casefold()
    dropped = [
        f"{entry.obligation_id} {entry.rule_span!r}"
        for entry in obligations
        if entry.rule_span.casefold() not in folded
    ]
    if dropped:
        raise ValueError(
            f"constraint {constraint_id} revise drops obligation phrase "
            f"{', '.join(dropped)}; keep each phrase unchanged inside "
            f"revised_description, or preserve {constraint_id}"
        )


def _reviewed_hazards(
    review: ConstraintHazardReview,
    allowed: set[str],
) -> list[str]:
    """Validate and retain the explicit constraint hazard-edge order."""
    selected = list(review.related_hazards)
    if len(set(selected)) != len(selected) or not set(selected) <= allowed:
        raise ValueError("semantic review contains duplicate or unknown hazards")
    return selected


def _review_indexes(
    structure: ControlStructure,
    loss_analysis: LossAnalysis,
    review: ControlStructureSemanticReview,
) -> tuple[
    dict[str, ResponsibilityReview],
    dict[str, ActionEffectReview],
    dict[str, HazardSemanticReview],
    dict[str, ConstraintHazardReview],
]:
    """Build the four exact identity indexes required by the closed review."""
    hazards = _exact_index(
        review.hazards,
        "hazard_id",
        {hazard.hazard_id for hazard in loss_analysis.hazards},
    )
    constraints = _exact_index(
        review.constraints,
        "constraint_id",
        {sc.constraint_id for sc in loss_analysis.security_constraints},
    )
    owners = _exact_index(
        review.responsibilities,
        "responsibility_id",
        {resp.resp_id for resp in structure.responsibilities},
    )
    actions = _exact_index(
        review.actions,
        "control_action_id",
        {
            ca.ca_id
            for resp in structure.responsibilities
            for ca in resp.control_actions
        },
    )
    return owners, actions, hazards, constraints

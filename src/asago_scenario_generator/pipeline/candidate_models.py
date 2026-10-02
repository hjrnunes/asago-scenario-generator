"""Candidate identity, provenance, funnel, and filter wire models."""

from __future__ import annotations

from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from asago_scenario_generator.pipeline.seeds import ScenarioSeed

# ---------------------------------------------------------------------------
# Canonical candidate identity
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Typed stage / funnel records
# ---------------------------------------------------------------------------


class CandidateFunnel(BaseModel):
    """Typed container for the full candidate-to-scenario funnel.

    Every count is derived from typed stage records or canonical sets,
    never from potentially duplicated list lengths.  The funnel is
    persisted in the run manifest and consumed by report templates.
    """

    expanded_instances: int = Field(
        description="Raw candidate instances produced by expansion (pre-dedup).",
    )
    unique_pre_rule_identities: int = Field(
        description="Unique canonical identities after expansion dedup.",
    )
    rule_rejected: int = Field(
        description="Candidates fully rejected by deterministic rules.",
    )
    rule_transformed: int = Field(
        description=(
            "Source candidate identities that had at least one technique "
            "pruned by rules (pre-collapse, not post-dedup outputs)."
        ),
    )
    post_rule_collapsed: int = Field(
        description="Identities that collapsed during rule-pruning dedup.",
    )
    filter_submitted: int = Field(
        description="Unique candidates submitted to the LLM filter.",
    )
    filter_accepted: int = Field(
        description="Candidates accepted by the LLM filter.",
    )
    selected: int = Field(
        description=(
            "Qualified projected candidates selected for generation after "
            "coverage-aware selection.  May exceed filter_accepted because "
            "one filtered seed can fan out to multiple projected candidates "
            "with distinct concrete bindings (cmps.4)."
        ),
    )
    qualified: int = Field(
        default=0,
        description=(
            "Total qualified projected candidates after fan-out and "
            "deduplication by candidate_id (cmps.4).  Selected <= qualified."
        ),
    )
    projection_rejected: int = Field(
        default=0,
        description=(
            "Filtered seeds rejected at the projection stage (no exact "
            "ingress match to a projected candidate).  Excluded from "
            "selected — a typed projection-stage rejection, not a silent "
            "skip (422o.4)."
        ),
    )
    main_attempted: int = Field(
        description="Main generation attempts (from selected candidates).",
    )
    main_admitted: int = Field(
        description="Main scenarios successfully generated and written.",
    )
    generation_failed: int = Field(
        description="Main generation attempts that failed (recoverable).",
    )
    remediation_attempted: int = Field(
        description="Remediation generation attempts for uncovered entry points.",
    )
    remediation_admitted: int = Field(
        description="Remediation scenarios successfully generated and written.",
    )
    remediation_failed: int = Field(
        description="Remediation generation attempts that failed (recoverable).",
    )
    attempted: int = Field(
        description="Total generation attempts (main + remediation).",
    )
    admitted: int = Field(
        description="Total scenarios successfully generated and written to disk.",
    )
    quarantined: int = Field(
        description="Scenarios that failed validation (quarantined, subset of admitted).",
    )
    persisted_artifacts: int = Field(
        description="YAML/feature artifact pairs persisted to disk.",
    )

    @model_validator(mode="after")
    def _validate_funnel(self) -> CandidateFunnel:
        """Validate nonnegative counts and exact reconciliation equations."""
        _funnel_counts_nonnegative(self)
        _funnel_expansion_ordered(self)
        _funnel_submission_reconciled(self)
        _funnel_accepted_subset(self)
        _funnel_selection_within_qualified(self)
        _funnel_projection_subset(self)
        _funnel_main_lifecycle(self)
        _funnel_main_attempts_reconciled(self)
        _funnel_remediation_reconciled(self)
        _funnel_attempted_reconciled(self)
        _funnel_admitted_reconciled(self)
        _funnel_quarantine_subset(self)
        _funnel_artifacts_reconciled(self)
        return self


def _funnel_counts_nonnegative(funnel: CandidateFunnel) -> None:
    """Every funnel count must be nonnegative."""
    for field_name in type(funnel).model_fields:
        val = getattr(funnel, field_name)
        if val < 0:
            raise ValueError(
                f"CandidateFunnel field '{field_name}' must be nonnegative, got {val}"
            )


def _funnel_expansion_ordered(funnel: CandidateFunnel) -> None:
    """Expansion instances cannot be fewer than unique identities."""
    if funnel.expanded_instances < funnel.unique_pre_rule_identities:
        raise ValueError(
            f"expanded_instances ({funnel.expanded_instances}) must be >= "
            f"unique_pre_rule_identities ({funnel.unique_pre_rule_identities})"
        )


def _funnel_submission_reconciled(funnel: CandidateFunnel) -> None:
    """filter_submitted must equal pre-rule unique minus rejections."""
    expected_submitted = (
        funnel.unique_pre_rule_identities
        - funnel.rule_rejected
        - funnel.post_rule_collapsed
    )
    if funnel.filter_submitted != expected_submitted:
        raise ValueError(
            f"filter_submitted ({funnel.filter_submitted}) must equal "
            f"unique_pre_rule_identities - rule_rejected - "
            f"post_rule_collapsed = {expected_submitted}"
        )


def _funnel_accepted_subset(funnel: CandidateFunnel) -> None:
    """The filter cannot accept more candidates than it submitted."""
    if funnel.filter_accepted > funnel.filter_submitted:
        raise ValueError(
            f"filter_accepted ({funnel.filter_accepted}) must be <= "
            f"filter_submitted ({funnel.filter_submitted})"
        )


def _funnel_selection_within_qualified(funnel: CandidateFunnel) -> None:
    """cmps.4: selection cannot admit more than were qualified.

    With fan-out, one filtered seed can map to multiple projected
    candidates with distinct bindings, so selected may exceed
    filter_accepted.  The invariant is selected <= qualified.
    Enforced unconditionally — qualified defaults to 0, so selected > 0
    with qualified = 0 is a violation (cmps.4 blocker 5).
    """
    if funnel.selected > funnel.qualified:
        raise ValueError(
            f"selected ({funnel.selected}) must be <= qualified ({funnel.qualified})"
        )


def _funnel_projection_subset(funnel: CandidateFunnel) -> None:
    """Projection rejections are a subset of filter_accepted."""
    if funnel.projection_rejected > funnel.filter_accepted:
        raise ValueError(
            f"projection_rejected ({funnel.projection_rejected}) must be <= "
            f"filter_accepted ({funnel.filter_accepted})"
        )


def _funnel_main_lifecycle(funnel: CandidateFunnel) -> None:
    """Selected candidates each get one main attempt."""
    if funnel.main_attempted != funnel.selected:
        raise ValueError(
            f"main_attempted ({funnel.main_attempted}) must equal "
            f"selected ({funnel.selected})"
        )


def _funnel_main_attempts_reconciled(funnel: CandidateFunnel) -> None:
    """Each main attempt is either admitted or failed."""
    if funnel.main_attempted != funnel.main_admitted + funnel.generation_failed:
        raise ValueError(
            f"main_attempted ({funnel.main_attempted}) must equal "
            f"main_admitted ({funnel.main_admitted}) + "
            f"generation_failed ({funnel.generation_failed})"
        )


def _funnel_remediation_reconciled(funnel: CandidateFunnel) -> None:
    """Each remediation attempt is admitted or failed."""
    if funnel.remediation_attempted != (
        funnel.remediation_admitted + funnel.remediation_failed
    ):
        raise ValueError(
            f"remediation_attempted ({funnel.remediation_attempted}) must equal "
            f"remediation_admitted ({funnel.remediation_admitted}) + "
            f"remediation_failed ({funnel.remediation_failed})"
        )


def _funnel_attempted_reconciled(funnel: CandidateFunnel) -> None:
    """Aggregate attempted = main + remediation."""
    if funnel.attempted != funnel.main_attempted + funnel.remediation_attempted:
        raise ValueError(
            f"attempted ({funnel.attempted}) must equal "
            f"main_attempted ({funnel.main_attempted}) + "
            f"remediation_attempted ({funnel.remediation_attempted})"
        )


def _funnel_admitted_reconciled(funnel: CandidateFunnel) -> None:
    """Aggregate admitted = main + remediation."""
    if funnel.admitted != funnel.main_admitted + funnel.remediation_admitted:
        raise ValueError(
            f"admitted ({funnel.admitted}) must equal "
            f"main_admitted ({funnel.main_admitted}) + "
            f"remediation_admitted ({funnel.remediation_admitted})"
        )


def _funnel_quarantine_subset(funnel: CandidateFunnel) -> None:
    """Quarantine is a subset of admitted."""
    if funnel.quarantined > funnel.admitted:
        raise ValueError(
            f"quarantined ({funnel.quarantined}) must be <= "
            f"admitted ({funnel.admitted})"
        )


def _funnel_artifacts_reconciled(funnel: CandidateFunnel) -> None:
    """Every admitted scenario has exactly one persisted artifact pair."""
    if funnel.persisted_artifacts != funnel.admitted:
        raise ValueError(
            f"persisted_artifacts ({funnel.persisted_artifacts}) must equal "
            f"admitted ({funnel.admitted})"
        )


# ---------------------------------------------------------------------------
# Candidate origin provenance
# ---------------------------------------------------------------------------


class RemovalDecision(BaseModel):
    """Typed per-removal decision for a single technique pruned by a rule.

    Records the technique ID, the rejecting rule name, and the rationale,
    so that every removed technique carries its own provenance rather
    than only the first rejecting rule.
    """

    model_config = ConfigDict(frozen=True)

    technique_id: str = Field(description="Removed technique ID.")
    rule: str = Field(description="Name of the rule that rejected this technique.")
    reason: str = Field(description="Human-readable rationale for the rejection.")


class CandidateOrigin(BaseModel):
    """Provenance record for one source candidate that contributed to a
    merged/deduplicated candidate.

    When identity-changing transforms (rule pruning, capping) cause
    multiple candidates to converge to the same canonical identity,
    each source candidate's provenance is retained in this record.
    Never first-wins — all origins are preserved.
    """

    model_config = ConfigDict(frozen=True)

    source_candidate_id: str = Field(
        description="Original candidate_id before the transform.",
    )
    original_technique_ids: tuple[str, ...] = Field(
        description="Technique IDs in the source candidate before pruning.",
    )
    applied_rule: str | None = Field(
        default=None,
        description=(
            "Primary rule that caused the transform.  None for expansion-stage "
            "origins.  For rule pruning with multiple rules, this is the first "
            "rejecting rule; see ``removal_decisions`` for per-technique detail."
        ),
    )
    removed_technique_ids: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Technique IDs removed by the transform.",
    )
    removal_reasons: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Human-readable reason for each removed technique.",
    )
    removal_decisions: tuple[RemovalDecision, ...] = Field(
        default_factory=tuple,
        description=(
            "Per-removal decision records, one per removed technique, "
            "carrying the specific rule and reason.  Ordered by the "
            "original technique iteration order."
        ),
    )
    transform_stage: str = Field(
        description=(
            "Pipeline stage where the origin was recorded: "
            "'expansion', 'rule_pruning', or 'capping'."
        ),
    )


# ---------------------------------------------------------------------------
# Pre-filter: one (attack_pattern, entry_point, atlas_technique) candidate
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# LLM filter response models
# ---------------------------------------------------------------------------


class FilterVerdict(BaseModel):
    """One entry in the LLM batch filter response (wire protocol).

    The LLM labels each verdict by the opaque ``candidate_id`` provided
    in the prompt.  It never echoes entry-point or technique metadata.
    """

    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(description="The opaque candidate ID being judged.")
    verdict: Literal["accept", "reject"] = Field(
        description="Whether this candidate should proceed to generation."
    )
    rationale: str = Field(
        description="One-sentence explanation of why the candidate was accepted or rejected.",
    )


class RejectionRecord(BaseModel):
    """Provenance record for a rejected candidate (enriched after reconciliation).

    Carries the canonical ``candidate_id`` alongside the display metadata
    (entry point, technique IDs) resolved from the candidate lookup, so
    the report can show what was rejected without relying on LLM-echoed
    metadata.  For fully rejected combinations, ``removal_decisions``
    carries per-technique rule/reason provenance rather than only the
    first rationale.
    """

    candidate_id: str = Field(
        description="Opaque candidate ID of the rejected candidate."
    )
    entry_point: str = Field(description="Entry point text of the rejected candidate.")
    atlas_technique_ids: tuple[str, ...] = Field(
        description="Technique combo of the rejected candidate."
    )
    rationale: str = Field(description="Rejection rationale (primary/summary).")
    removal_decisions: tuple[RemovalDecision, ...] = Field(
        default_factory=tuple,
        description=(
            "Per-technique rejection decisions for fully rejected "
            "combinations, so every removed technique carries its own "
            "rule and reason rather than only the first."
        ),
    )


# ---------------------------------------------------------------------------
# Post-filter: seed with pinned entry point and technique
# ---------------------------------------------------------------------------


class FilteredSeed(ScenarioSeed):
    """A ScenarioSeed with pinned entry point and ATLAS technique.

    Hard assignments (not hints) produced by the candidate filter stage.
    Also carries canonical IDs and rejection records for provenance.
    """

    pinned_entry_point: str = Field(
        description="The accepted entry point (hard constraint for generation).",
    )
    pinned_technique_ids: tuple[str, ...] = Field(
        description="The accepted ATLAS technique ID(s) (hard constraint for generation).",
    )
    pinned_technique_names: tuple[str, ...] = Field(
        description="Human-readable name(s) of the pinned technique(s), for report display.",
    )
    entry_point_id: str = Field(
        description="Canonical entry point identity of the accepted candidate.",
    )
    candidate_id: str = Field(
        description="Canonical candidate identity of the accepted candidate.",
    )
    origins: list[CandidateOrigin] = Field(
        default_factory=list,
        description=(
            "Source candidate origins (provenance for converged candidates). "
            "Carried from the candidate through to the scenario envelope."
        ),
    )
    rejection_rationales: list[RejectionRecord] = Field(
        default_factory=list,
        description="Sibling candidates that were rejected (for provenance tab).",
    )
    accepted_rationale: str = Field(
        default="",
        description=(
            "LLM filter acceptance rationale for this candidate (cmps.4). "
            "Preserves the accepted FilterVerdict rationale as first-class "
            "typed evidence alongside the rejected sibling rationales."
        ),
    )

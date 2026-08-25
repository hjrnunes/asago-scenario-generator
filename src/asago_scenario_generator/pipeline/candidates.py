"""Candidate expansion and filtering pipeline.

Cross-products scenario seeds with entry points and techniques (ATLAS or
LAAF) to produce CandidateTriple objects, then defines models for the LLM
batch filter stage and downstream scenario generation.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import combinations
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    create_model,
    model_validator,
)

from asago_scenario_generator.data.atlas import (
    ATLAS_TECHNIQUE_DESCRIPTIONS,
    ATLAS_TECHNIQUE_NAMES,
    TECHNIQUE_PROPERTIES,
    THREAT_PREREQUISITES,
)
from asago_scenario_generator.llm.client import LLMClient, LLMResult
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    classify_entry_point,
    compute_entry_point_id,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.prompts import render_prompt

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical candidate identity
# ---------------------------------------------------------------------------

_CANDIDATE_ID_VERSION = "v2"


def compute_candidate_id(
    seed_id: str,
    entry_point_id: str,
    technique_ids: Sequence[str],
) -> str:
    """Compute a deterministic, versioned ``candidate_id``.

    The ID is derived from ``(seed_id, entry_point_id, sorted unique
    technique IDs)`` so that the same combination always produces the
    same ID regardless of technique ordering.

    Format: ``cand:<version>:<32-char hex digest (128-bit)>``
    """
    sorted_tech = tuple(sorted(set(technique_ids)))
    identity = f"{seed_id}|{entry_point_id}|{','.join(sorted_tech)}"
    h = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    return f"cand:{_CANDIDATE_ID_VERSION}:{h}"


# ---------------------------------------------------------------------------
# Typed stage / funnel records
# ---------------------------------------------------------------------------


class StageRecord(BaseModel):
    """Typed record for a single candidate transform stage.

    Captures exact input/output counts and the number of identities
    that collapsed during canonicalization.  Counts are derived from
    the canonical sets produced by ``canonicalize_and_dedup``, not
    from potentially duplicated list lengths.
    """

    model_config = ConfigDict(frozen=True)

    stage: str = Field(
        description=(
            "Transform stage name: 'expansion', 'rule_pruning', or 'capping'."
        ),
    )
    input_count: int = Field(
        description="Number of candidates entering the stage (pre-dedup).",
    )
    output_count: int = Field(
        description="Number of unique candidates after canonicalization.",
    )
    collapsed_count: int = Field(
        description=(
            "Number of identities that collapsed during dedup "
            "(input_count - output_count)."
        ),
    )


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


class CandidateTriple(BaseModel):
    """One (attack_pattern, entry_point, atlas_technique_combo) candidate before filtering.

    The model is frozen (immutable) so that submitted metadata cannot be
    mutated after the filter protocol has been engaged.  Supplied
    ``entry_point_id`` and ``candidate_id`` are validated against
    canonical recomputation on construction.
    """

    model_config = ConfigDict(frozen=True)

    seed_id: str = Field(description="Attack pattern ID, e.g. 'AP-T7-01'.")
    threat_id: str = Field(description="Parent threat ID, e.g. 'T7'.")
    threat_name: str = Field(description="Human-readable threat name.")
    attack_pattern_name: str = Field(description="Human-readable attack pattern name.")
    attack_pattern_description: str = Field(
        description="Full description of the attack pattern."
    )
    entry_point: str = Field(
        description="Entry point text, e.g. 'natural language customer queries via Klarna app (input)'.",
    )
    atlas_technique_ids: tuple[str, ...] = Field(
        description="ATLAS technique ID(s), e.g. ('AML.T0051',) or ('AML.T0051', 'AML.T0054')."
    )
    atlas_technique_names: tuple[str, ...] = Field(
        description="Human-readable ATLAS technique name(s)."
    )
    atlas_technique_descriptions: tuple[str, ...] = Field(
        description="Full description(s) of the ATLAS technique(s)."
    )
    risk_card_ref: RiskCardRef = Field(
        description="Back-reference to the originating risk card."
    )
    owasp_llm_ids: list[str] = Field(
        description="OWASP LLM Top-10 IDs this candidate maps from."
    )
    controllability: str | None = Field(
        default=None,
        description="Entry point controllability: 'direct', 'indirect', or 'system'.",
    )
    direction: str | None = Field(
        default=None,
        description="Entry point data flow direction: 'input', 'output', or 'bidirectional'.",
    )
    ingress_zone: str | None = Field(
        default=None,
        description="Explicit Schneider ingress zone used by canonical identity.",
    )
    entry_point_id: str = Field(
        description="Canonical, deterministic entry point identity (ep:v1:<hash>).",
    )
    candidate_id: str = Field(
        description="Canonical, deterministic candidate identity (cand:v2:<hash>).",
    )
    origins: tuple[CandidateOrigin, ...] = Field(
        default_factory=tuple,
        description=(
            "Source candidate origins (provenance for converged candidates). "
            "Each entry records a source candidate_id, original technique set, "
            "applied rule, removed techniques/reasons, and transform stage."
        ),
    )

    @model_validator(mode="after")
    def _validate_canonical_ids(self) -> CandidateTriple:
        """Validate that supplied IDs match canonical recomputation.

        This prevents forged or stale IDs from being used as join keys
        in the filter protocol or downstream provenance.
        """
        expected_ep_id = compute_entry_point_id(
            self.entry_point,
            self.direction or "bidirectional",
            self.controllability,
            self.ingress_zone,
        )
        if self.entry_point_id != expected_ep_id:
            raise ValueError(
                f"entry_point_id '{self.entry_point_id}' does not match "
                f"canonical recomputation '{expected_ep_id}' for "
                f"entry_point='{self.entry_point}', "
                f"direction={self.direction}, "
                f"controllability={self.controllability}"
            )
        expected_cand_id = compute_candidate_id(
            self.seed_id, self.entry_point_id, self.atlas_technique_ids
        )
        if self.candidate_id != expected_cand_id:
            raise ValueError(
                f"candidate_id '{self.candidate_id}' does not match "
                f"canonical recomputation '{expected_cand_id}' for "
                f"seed_id='{self.seed_id}', "
                f"entry_point_id='{self.entry_point_id}', "
                f"technique_ids={self.atlas_technique_ids}"
            )
        return self


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


class BatchFilterResponse(BaseModel):
    """Wrapper for the full batch LLM response for one seed.

    Contains only the batch ``seed_id`` and a list of
    :class:`FilterVerdict` entries keyed by opaque ``candidate_id``.
    """

    model_config = ConfigDict(extra="forbid")

    seed_id: str = Field(description="Which seed this response is for.")
    verdicts: list[FilterVerdict] = Field(
        description="Per-candidate accept/reject verdicts."
    )


class FilterDecisionDraftV2(BaseModel):
    """One advisory decision keyed by a compact request-local handle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate: str = Field(pattern=r"^c(?:0|[1-9][0-9]*)$")
    relevant: bool
    rationale: str = Field(min_length=1, max_length=240)


class BatchFilterDraftV2(BaseModel):
    """Provider-facing candidate filter protocol without canonical IDs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decisions: tuple[FilterDecisionDraftV2, ...] = Field(min_length=1)


class FilterMapDecisionDraftV3(BaseModel):
    """One advisory decision whose identity is owned by its object key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    relevant: bool
    rationale: str = Field(min_length=1, max_length=240)


class FilterMapDraftV3(BaseModel):
    """Base for request-local exact-key filter response models."""

    model_config = ConfigDict(extra="forbid", frozen=True)


def build_filter_map_response_model(
    expected_handles: Sequence[str],
) -> type[FilterMapDraftV3]:
    """Build a schema with exactly one required field per local handle."""

    handles = tuple(expected_handles)
    _handles_unique_nonempty(handles)
    _handles_cn_ordinals(handles)
    return create_model(
        f"FilterMapDraftV3For{len(handles)}Candidates",
        __base__=FilterMapDraftV3,
        **{handle: (FilterMapDecisionDraftV3, ...) for handle in handles},
    )


def _handles_unique_nonempty(handles: tuple[str, ...]) -> None:
    """Filter response handles must be non-empty and unique."""
    if not handles or len(set(handles)) != len(handles):
        raise ValueError("filter response handles must be non-empty and unique")


def _handles_cn_ordinals(handles: tuple[str, ...]) -> None:
    """Filter response handles must use cN ordinals."""
    if any(
        not handle.startswith("c") or not handle[1:].isdigit() for handle in handles
    ):
        raise ValueError("filter response handles must use cN ordinals")


def reconcile_filter_map(
    draft: FilterMapDraftV3,
    expected_handles: Sequence[str],
) -> dict[str, FilterMapDecisionDraftV3]:
    """Resolve a request-local exact-key map after defensive set checking."""

    expected = tuple(expected_handles)
    actual = tuple(draft.model_dump(mode="python"))
    if set(actual) != set(expected):
        raise ValueError(
            f"candidate handle mismatch: actual={sorted(actual)}; "
            f"expected={sorted(expected)}"
        )
    return {handle: getattr(draft, handle) for handle in expected}


def reconcile_filter_ordinals(
    draft: BatchFilterDraftV2,
    expected_handles: Sequence[str],
) -> dict[str, FilterDecisionDraftV2]:
    """Resolve an ordinal draft only after exact-set reconciliation."""
    received = [item.candidate for item in draft.decisions]
    _handles_duplicate_free(received)
    _handle_set_mismatch(set(expected_handles), set(received))
    return {item.candidate: item for item in draft.decisions}


def _handles_duplicate_free(received: list[str]) -> None:
    """Ordinal drafts may not repeat a candidate handle."""
    duplicate = sorted(handle for handle in set(received) if received.count(handle) > 1)
    if duplicate:
        raise ValueError(f"duplicate candidate handles: {', '.join(duplicate)}")


def _handle_set_mismatch(expected: set[str], actual: set[str]) -> None:
    """Raise when received handles differ from the expected set."""
    unknown = sorted(actual - expected)
    missing = sorted(expected - actual)
    if unknown or missing:
        raise ValueError(
            "candidate handle mismatch: "
            f"unknown={','.join(unknown) or 'none'}; "
            f"missing={','.join(missing) or 'none'}"
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


class FilterProtocolError(Exception):
    """Raised when the LLM filter response cannot be reconciled after retry.

    Carries the call log entries accumulated up to the failure point so
    the runner can persist them before failing the run.
    """

    def __init__(
        self,
        message: str,
        call_log_entries: list[dict] | None = None,
        reconciliation: FilterReconciliationEvidence | None = None,
    ) -> None:
        super().__init__(message)
        self.call_log_entries: list[dict] = call_log_entries or []
        self.reconciliation = reconciliation


class FilterReconciliationEvidence(BaseModel):
    """Bounded, seed-local evidence for an irreconcilable filter response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seed_id: str
    expected_ids: tuple[str, ...]
    received_ids: tuple[str, ...]
    missing_ids: tuple[str, ...]
    unknown_ids: tuple[str, ...]
    attempts: int = Field(ge=1)
    error: str


class FilterSeedQuarantine(BaseModel):
    """A candidate-filter seed removed without affecting independent seeds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seed_id: str
    reconciliation: FilterReconciliationEvidence


def _reconciliation_evidence(
    seed_id: str,
    expected_ids: set[str],
    response: BatchFilterResponse | None,
    error: str | None,
) -> FilterReconciliationEvidence:
    """Capture deterministic set arithmetic from the final filter attempt."""
    received = (
        {item.candidate_id for item in response.verdicts}
        if response is not None
        else set()
    )
    return FilterReconciliationEvidence(
        seed_id=seed_id,
        expected_ids=tuple(sorted(expected_ids)),
        received_ids=tuple(sorted(received)),
        missing_ids=tuple(sorted(expected_ids - received)),
        unknown_ids=tuple(sorted(received - expected_ids)),
        attempts=2,
        error=error or "filter response could not be reconciled",
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


_FilterResult = tuple[list[FilteredSeed], list[dict], list[FilterVerdict]]
_QuarantineFilterResult = tuple[
    list[FilteredSeed],
    list[dict],
    list[FilterVerdict],
    list[FilterSeedQuarantine],
]


# ---------------------------------------------------------------------------
# Candidate expansion: cross-product seeds x entry_points x techniques
# ---------------------------------------------------------------------------


def expand_candidates(
    seeds: list[ScenarioSeed],
    profile: CapabilityProfile,
    max_techniques: int = 1,
    stage_records: list[StageRecord] | None = None,
) -> list[CandidateTriple]:
    """Cross-product each seed with all entry points and ATLAS technique combos.

    For every ScenarioSeed, produces one CandidateTriple per
    (entry_point, technique_combo) combination, carrying full context
    needed by the downstream LLM filter stage.

    When ``max_techniques=1`` (the default), behaviour is equivalent to the
    original per-technique expansion.  With ``max_techniques=2``, both
    single-technique and two-technique combos are generated (C(N,1)+C(N,2)
    per seed x entry_point).

    Args:
        seeds: Output of ``expand_seeds()`` (Stage 3).
        profile: Capability profile with ``entry_points`` list.
        max_techniques: Maximum number of techniques in a combo (default 1).
        stage_records: Optional list to append a :class:`StageRecord`
            capturing pre-dedup/post-dedup counts.  When provided, the
            caller receives typed records for funnel accounting.

    Returns:
        Flat list of deduplicated CandidateTriple, one per unique
        canonical identity.
    """
    if not profile.entry_points:
        logger.warning("Profile has no entry points — returning empty candidate list")
        return []

    eligible_seeds = _capability_eligible_seeds(seeds, profile)
    _log_seed_eligibility(eligible_seeds, seeds)

    ingress_points = _attacker_ingress_points(profile)
    if not ingress_points:
        logger.warning(
            "Profile has %d entry points but none are input/bidirectional — "
            "returning empty candidate list",
            len(profile.entry_points),
        )
        return []

    candidates: list[CandidateTriple] = []
    for seed in eligible_seeds:
        candidates.extend(_expand_one_seed(seed, ingress_points, max_techniques))

    _log_expansion_summary(eligible_seeds, ingress_points, max_techniques, candidates)

    _check_candidate_collisions(candidates)

    # Canonicalize and deduplicate immediately after expansion.
    raw_count = len(candidates)
    candidates = canonicalize_and_dedup(candidates, stage="expansion")
    _expansion_stage_record(stage_records, raw_count, candidates)
    return candidates


def _seed_capability_supported(
    seed: ScenarioSeed, cap: str, profile: CapabilityProfile
) -> bool:
    """Whether one required capability is supported; warns when not."""
    if not _capability_available(cap, profile):
        logger.warning(
            "Skipping seed %s: requires %s but profile does not support it",
            seed.seed_id,
            cap,
        )
        return False
    return True


def _capability_available(cap: str, profile: CapabilityProfile) -> bool:
    """Profile support for one named capability (unknown caps pass)."""
    if cap == "multi_agent":
        return profile.multi_agent
    if cap == "persistent_memory":
        return profile.has_persistent_memory
    if cap == "tool_execution":
        return "tool_execution" in profile.zones_active
    return True


def _capability_eligible_seeds(
    seeds: list[ScenarioSeed], profile: CapabilityProfile
) -> list[ScenarioSeed]:
    """Pre-filter: reject seeds whose required_capabilities are not met."""
    eligible_seeds: list[ScenarioSeed] = []
    for seed in seeds:
        if seed.required_capabilities:
            skip = False
            for cap in seed.required_capabilities:
                if not _seed_capability_supported(seed, cap, profile):
                    skip = True
                    break
            if skip:
                continue
        eligible_seeds.append(seed)
    return eligible_seeds


def _log_seed_eligibility(
    eligible_seeds: list[ScenarioSeed], seeds: list[ScenarioSeed]
) -> None:
    """Log the capability-filter outcome when any seed was rejected."""
    if len(eligible_seeds) < len(seeds):
        logger.info(
            "Seed capability filter: %d/%d seeds eligible (rejected %d)",
            len(eligible_seeds),
            len(seeds),
            len(seeds) - len(eligible_seeds),
        )


def _attacker_ingress_points(
    profile: CapabilityProfile,
) -> list[Any]:
    """Attacker-accessible ingress entry points (cmps.9 correction 2).

    Excludes output-only, system-controlled, and entries whose canonical
    ingress zone is inactive.
    """
    active_zones = set(profile.zones_active) if profile.zones_active else set()
    ingress_points = [
        ep
        for ep in profile.entry_points
        if is_attacker_accessible_ingress(ep, active_zones)
    ]
    excluded_count = len(profile.entry_points) - len(ingress_points)
    if excluded_count > 0:
        logger.info(
            "Entry point filter: %d/%d entry points are attacker-accessible "
            "(%d excluded: output-only or system-controlled)",
            len(ingress_points),
            len(profile.entry_points),
            excluded_count,
        )
    return ingress_points


def _seed_technique_pool(seed: ScenarioSeed) -> tuple[str, ...] | None:
    """ATLAS technique IDs, falling back to LAAF IDs; None when empty."""
    pool = seed.atlas_technique_ids or seed.laaf_technique_ids
    if not pool:
        logger.warning(
            "Seed %s has no technique IDs (ATLAS or LAAF) — skipping",
            seed.seed_id,
        )
        return None
    return pool


def _candidate_triple_for(
    seed: ScenarioSeed,
    entry_point: Any,
    ep_id: str,
    tech_combo: tuple[str, ...],
) -> CandidateTriple:
    """One (seed, entry point, technique combo) candidate."""
    return CandidateTriple(
        seed_id=seed.seed_id,
        threat_id=seed.threat_id,
        threat_name=seed.threat_name,
        attack_pattern_name=seed.attack_pattern_name,
        attack_pattern_description=seed.attack_pattern_description,
        entry_point=entry_point.name,
        controllability=entry_point.controllability,
        direction=entry_point.direction,
        ingress_zone=entry_point.ingress_zone,
        entry_point_id=ep_id,
        candidate_id=compute_candidate_id(
            seed.seed_id,
            ep_id,
            tech_combo,
        ),
        atlas_technique_ids=tech_combo,
        atlas_technique_names=tuple(
            ATLAS_TECHNIQUE_NAMES.get(t, t) for t in tech_combo
        ),
        atlas_technique_descriptions=tuple(
            ATLAS_TECHNIQUE_DESCRIPTIONS.get(t, "") for t in tech_combo
        ),
        risk_card_ref=seed.risk_card_ref,
        owasp_llm_ids=seed.owasp_llm_ids,
        origins=(
            CandidateOrigin(
                source_candidate_id=compute_candidate_id(
                    seed.seed_id,
                    ep_id,
                    tech_combo,
                ),
                original_technique_ids=tech_combo,
                transform_stage="expansion",
            ),
        ),
    )


def _expand_one_seed(
    seed: ScenarioSeed,
    ingress_points: list[Any],
    max_techniques: int,
) -> list[CandidateTriple]:
    """Cross-product one seed with all ingress points and technique combos."""
    technique_pool = _seed_technique_pool(seed)
    if technique_pool is None:
        return []

    candidates: list[CandidateTriple] = []
    for entry_point in ingress_points:
        ep_id = entry_point.entry_point_id
        for combo_size in range(1, max_techniques + 1):
            for tech_combo in combinations(technique_pool, combo_size):
                candidates.append(
                    _candidate_triple_for(seed, entry_point, ep_id, tech_combo)
                )
    return candidates


def _average_technique_count(eligible_seeds: list[ScenarioSeed]) -> float:
    """Mean technique-pool size over seeds that have any technique IDs."""
    tech_counts = [
        len(s.atlas_technique_ids or s.laaf_technique_ids)
        for s in eligible_seeds
        if s.atlas_technique_ids or s.laaf_technique_ids
    ]
    return sum(tech_counts) / len(tech_counts) if tech_counts else 0.0


def _log_expansion_summary(
    eligible_seeds: list[ScenarioSeed],
    ingress_points: list[Any],
    max_techniques: int,
    candidates: list[CandidateTriple],
) -> None:
    """Log the expansion outcome when any seed was processed."""
    if not eligible_seeds:
        return
    avg_techniques = _average_technique_count(eligible_seeds)
    logger.info(
        "%d seeds x %d ingress entry points x avg %.1f techniques "
        "(max_techniques=%d) = %d candidates",
        len(eligible_seeds),
        len(ingress_points),
        avg_techniques,
        max_techniques,
        len(candidates),
    )


def _expansion_stage_record(
    stage_records: list[StageRecord] | None,
    raw_count: int,
    candidates: list[CandidateTriple],
) -> None:
    """Record the expansion stage counts when a ledger is supplied."""
    if stage_records is not None:
        stage_records.append(
            StageRecord(
                stage="expansion",
                input_count=raw_count,
                output_count=len(candidates),
                collapsed_count=raw_count - len(candidates),
            )
        )


def _check_candidate_collisions(candidates: list[CandidateTriple]) -> None:
    """Reject candidates with same candidate_id but different identity inputs.

    Two candidates are *semantic duplicates* when they share the same
    ``candidate_id`` and the same ``(seed_id, entry_point_id, sorted
    unique technique IDs)`` — this is expected from duplicate expansion
    and is silently deduplicated elsewhere.

    Two candidates *collide* when they share the same ``candidate_id``
    but have different identity inputs (a hash collision or forged ID).
    This is rejected because the filter protocol cannot distinguish them.

    Args:
        candidates: List of candidates to check.

    Raises:
        ValueError: If two candidates with different identity inputs
            produce the same ``candidate_id``.
    """
    seen: dict[str, tuple[str, str, tuple[str, ...]]] = {}
    for c in candidates:
        identity = (
            c.seed_id,
            c.entry_point_id,
            tuple(sorted(set(c.atlas_technique_ids))),
        )
        if c.candidate_id in seen:
            existing = seen[c.candidate_id]
            if existing != identity:
                raise ValueError(
                    f"Candidate collision: candidate_id '{c.candidate_id}' "
                    f"maps to different identity inputs "
                    f"({identity} vs {existing}). "
                    f"Remove or disambiguate one of them."
                )
            # Semantic duplicate — not an error here, just a debug log.
            logger.debug(
                "Semantic duplicate candidate_id '%s' in expansion",
                c.candidate_id,
            )
        else:
            seen[c.candidate_id] = identity


def _canonicalize_techniques(
    ids: tuple[str, ...],
    names: tuple[str, ...],
    descriptions: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Sort technique IDs and align names/descriptions deterministically.

    Detects duplicate technique IDs with conflicting names/descriptions
    (fatal), deduplicates duplicate IDs with identical metadata, and
    sorts by ID so equivalent inputs serialize identically regardless
    of input ordering.

    Raises:
        ValueError: If the same technique ID appears with conflicting
            name or description metadata.
    """
    if not ids:
        return (), (), ()

    padded_names, padded_descs = _padded_metadata(ids, names, descriptions)
    id_to_name, id_to_desc = _technique_metadata_map(ids, padded_names, padded_descs)
    return _aligned_metadata(id_to_name, id_to_desc)


def _padded_metadata(
    ids: tuple[str, ...],
    names: tuple[str, ...],
    descriptions: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Pad names/descriptions to match ids length (defensive)."""
    padded_names = tuple(names) + ("",) * max(0, len(ids) - len(names))
    padded_descs = tuple(descriptions) + ("",) * max(0, len(ids) - len(descriptions))
    return padded_names, padded_descs


def _technique_metadata_map(
    ids: tuple[str, ...],
    names: tuple[str, ...],
    descriptions: tuple[str, ...],
) -> tuple[dict[str, str], dict[str, str]]:
    """Build per-ID metadata, detecting conflicting values for one ID."""
    id_to_name: dict[str, str] = {}
    id_to_desc: dict[str, str] = {}
    for tid, name, desc in zip(ids, names, descriptions, strict=False):
        if tid in id_to_name:
            if id_to_name[tid] != name:
                raise ValueError(
                    f"Conflicting technique name for ID '{tid}': "
                    f"{id_to_name[tid]!r} vs {name!r}"
                )
            if id_to_desc[tid] != desc:
                raise ValueError(
                    f"Conflicting technique description for ID '{tid}': "
                    f"{id_to_desc[tid]!r} vs {desc!r}"
                )
        else:
            id_to_name[tid] = name
            id_to_desc[tid] = desc
    return id_to_name, id_to_desc


def _aligned_metadata(
    id_to_name: dict[str, str], id_to_desc: dict[str, str]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Sort by ID and align names/descriptions to that order."""
    sorted_ids = tuple(sorted(id_to_name))
    sorted_names = tuple(id_to_name[tid] for tid in sorted_ids)
    sorted_descs = tuple(id_to_desc[tid] for tid in sorted_ids)
    return sorted_ids, sorted_names, sorted_descs


def _canonicalize_origin(origin: CandidateOrigin) -> CandidateOrigin:
    """Return a canonicalized copy of a CandidateOrigin.

    Sorts ``original_technique_ids``, ``removed_technique_ids``, and
    ``removal_decisions`` so that the origin serializes identically
    regardless of input ordering.  ``removal_reasons`` are re-aligned
    to the sorted ``removed_technique_ids`` order.
    """
    sorted_original = tuple(sorted(origin.original_technique_ids))
    sorted_removed = tuple(sorted(origin.removed_technique_ids))
    sorted_decisions = tuple(
        sorted(
            origin.removal_decisions,
            key=lambda d: (d.technique_id, d.rule, d.reason),
        )
    )
    # Re-align removal_reasons to sorted removed_technique_ids order.
    if origin.removed_technique_ids and origin.removal_reasons:
        tid_to_reason = dict(zip(origin.removed_technique_ids, origin.removal_reasons))
        sorted_reasons = tuple(tid_to_reason.get(tid, "") for tid in sorted_removed)
    else:
        sorted_reasons = origin.removal_reasons
    return CandidateOrigin(
        source_candidate_id=origin.source_candidate_id,
        original_technique_ids=sorted_original,
        applied_rule=origin.applied_rule,
        removed_technique_ids=sorted_removed,
        removal_reasons=sorted_reasons,
        removal_decisions=sorted_decisions,
        transform_stage=origin.transform_stage,
    )


def _canonicalize_and_dedup_origins(
    all_origins: list[CandidateOrigin],
) -> list[CandidateOrigin]:
    """Canonicalize, deduplicate, and sort origins deterministically."""
    canonicalized = [_canonicalize_origin(o) for o in all_origins]
    return _dedup_canonical_origins(canonicalized)


def _origin_key(origin: CandidateOrigin) -> tuple:
    """Dedup identity for one canonicalized origin."""
    return (
        origin.source_candidate_id,
        origin.transform_stage,
        origin.original_technique_ids,
        origin.removed_technique_ids,
        origin.applied_rule,
        origin.removal_reasons,
        tuple((d.technique_id, d.rule, d.reason) for d in origin.removal_decisions),
    )


def _origin_sort_key(origin: CandidateOrigin) -> tuple:
    """Deterministic sort key for one canonicalized origin."""
    return (
        origin.source_candidate_id,
        origin.transform_stage,
        origin.original_technique_ids,
        origin.removed_technique_ids,
        origin.applied_rule or "",
        origin.removal_reasons,
        tuple((d.technique_id, d.rule, d.reason) for d in origin.removal_decisions),
    )


def _dedup_canonical_origins(
    canonicalized: list[CandidateOrigin],
) -> list[CandidateOrigin]:
    """First-seen dedup by origin key, then deterministic sort."""
    seen: set[tuple] = set()
    unique: list[CandidateOrigin] = []
    for origin in canonicalized:
        key = _origin_key(origin)
        if key not in seen:
            seen.add(key)
            unique.append(origin)
    unique.sort(key=_origin_sort_key)
    return unique


def _check_converged_technique_metadata(
    group: list[CandidateTriple],
) -> None:
    """Compare canonical technique ID/name/description mappings across
    every converged candidate and reject conflicts."""
    ref_map: dict[str, tuple[str, str]] | None = None
    for c in group:
        c_map = _candidate_technique_map(c)
        if ref_map is None:
            ref_map = c_map
            continue
        _technique_map_conflicts(ref_map, c_map)


def _candidate_technique_map(
    c: CandidateTriple,
) -> dict[str, tuple[str, str]]:
    """Per-ID (name, description) metadata of one candidate."""
    c_map: dict[str, tuple[str, str]] = {}
    for tid, name, desc in zip(
        c.atlas_technique_ids,
        c.atlas_technique_names,
        c.atlas_technique_descriptions,
        strict=False,
    ):
        c_map[tid] = (name, desc)
    return c_map


def _technique_map_conflicts(
    ref_map: dict[str, tuple[str, str]],
    c_map: dict[str, tuple[str, str]],
) -> None:
    """Reject differing ID sets or per-ID metadata across converged maps."""
    # Compare keys (technique IDs) — must be the same set.
    if set(ref_map) != set(c_map):
        raise ValueError(
            f"Conflicting technique ID sets for converged candidate: "
            f"{sorted(ref_map)} vs {sorted(c_map)}"
        )
    # Compare per-ID metadata.
    for tid in ref_map:
        if ref_map[tid] != c_map[tid]:
            raise ValueError(
                f"Conflicting technique metadata for ID '{tid}': "
                f"{ref_map[tid]!r} vs {c_map[tid]!r}"
            )


def canonicalize_and_dedup(
    candidates: list[CandidateTriple],
    stage: str,
) -> list[CandidateTriple]:
    """Canonicalize by ``(seed_id, entry_point_id, sorted unique technique IDs)``
    and deduplicate immediately.

    When multiple candidates converge to the same canonical identity
    (e.g. after rule-based technique pruning), produces **one** final
    candidate carrying **all** source origins.  Never first-wins
    provenance — every source candidate's origin is preserved.

    Args:
        candidates: List of candidates after an identity-changing transform.
        stage: Transform stage name for origin records
            (``"expansion"``, ``"rule_pruning"``, or ``"capping"``).

    Returns:
        Deduplicated list of candidates with merged origins.

    Raises:
        ValueError: If two candidates with the same canonical identity
            but different ``candidate_id`` values are found (a hash
            collision or forged ID — should be impossible given
            ``compute_candidate_id`` is deterministic).
    """
    if not candidates:
        return []

    groups: dict[tuple[str, str, tuple[str, ...]], list[CandidateTriple]] = defaultdict(
        list
    )
    for c in candidates:
        groups[_canonical_group_key(c)].append(c)

    result: list[CandidateTriple] = []
    collapsed_count = 0
    for key, group in groups.items():
        if len(group) == 1:
            result.append(_singleton_candidate(group[0]))
            continue

        # Multiple candidates converged — merge origins.
        collapsed_count += len(group) - 1
        result.append(_converged_candidate(group))

    if collapsed_count:
        logger.info(
            "Canonicalize (%s): %d candidates -> %d unique identities (%d collapsed)",
            stage,
            len(candidates),
            len(result),
            collapsed_count,
        )

    return result


def _canonical_group_key(
    c: CandidateTriple,
) -> tuple[str, str, tuple[str, ...]]:
    """Canonical dedup identity of one candidate."""
    return (
        c.seed_id,
        c.entry_point_id,
        tuple(sorted(set(c.atlas_technique_ids))),
    )


def _singleton_candidate(c: CandidateTriple) -> CandidateTriple:
    """Canonicalize a non-collapsed candidate deterministically.

    Canonicalize technique IDs/names/descriptions and origins so
    reversed technique/decision order serializes identically.
    """
    c_ids, c_names, c_descs = _canonicalize_techniques(
        c.atlas_technique_ids,
        c.atlas_technique_names,
        c.atlas_technique_descriptions,
    )
    canonical_origins = _canonicalize_and_dedup_origins(list(c.origins))
    needs_rebuild = c_ids != c.atlas_technique_ids
    if canonical_origins != list(c.origins):
        needs_rebuild = True
    if needs_rebuild:
        c = CandidateTriple.model_validate(
            c.model_dump(mode="python")
            | {
                "atlas_technique_ids": c_ids,
                "atlas_technique_names": c_names,
                "atlas_technique_descriptions": c_descs,
                "origins": tuple(canonical_origins),
            }
        )
    return c


def _converged_candidate(group: list[CandidateTriple]) -> CandidateTriple:
    """Merge one collapsed group: origins plus conflict-free metadata."""
    # Compare technique metadata across all converged candidates
    # before choosing a template.
    _check_converged_technique_metadata(group)
    all_origins: list[CandidateOrigin] = []
    for c in group:
        all_origins.extend(c.origins)
    unique_origins = _canonicalize_and_dedup_origins(all_origins)

    template = group[0]
    _non_provenance_conflicts(template, group[1:], _CONVERGED_NON_PROV_FIELDS)
    merged = CandidateTriple.model_validate(
        template.model_dump(mode="python")
        | {
            "origins": tuple(unique_origins),
        }
    )
    # Canonicalize technique IDs/names/descriptions: sort by ID and
    # align names/descriptions so equivalent inputs serialize identically.
    c_ids, c_names, c_descs = _canonicalize_techniques(
        merged.atlas_technique_ids,
        merged.atlas_technique_names,
        merged.atlas_technique_descriptions,
    )
    if c_ids != merged.atlas_technique_ids:
        merged = CandidateTriple.model_validate(
            merged.model_dump(mode="python")
            | {
                "atlas_technique_ids": c_ids,
                "atlas_technique_names": c_names,
                "atlas_technique_descriptions": c_descs,
            }
        )
    return merged


_CONVERGED_NON_PROV_FIELDS = (
    "seed_id",
    "threat_id",
    "threat_name",
    "attack_pattern_name",
    "attack_pattern_description",
    "entry_point",
    "entry_point_id",
    "direction",
    "risk_card_ref",
    "owasp_llm_ids",
    "controllability",
)


def _non_provenance_conflicts(
    template: BaseModel,
    others: Sequence[BaseModel],
    fields: Sequence[str],
) -> None:
    """Reject conflicting non-provenance metadata across converged records.

    All records with the same canonical identity must agree on metadata
    fields.
    """
    for c in others:
        for field_name in fields:
            tval = getattr(template, field_name)
            cval = getattr(c, field_name)
            if tval != cval:
                raise ValueError(
                    f"Conflicting non-provenance metadata for "
                    f"converged candidate '{template.candidate_id}': "
                    f"field '{field_name}' differs "
                    f"({tval!r} vs {cval!r})"
                )


# ---------------------------------------------------------------------------
# LLM batch filter: accept/reject candidates with rationale
# ---------------------------------------------------------------------------

_FILTER_COMPLETION_CAP = 4096


def _filter_completion_cap(client: LLMClient) -> int:
    """Bound filter output without increasing an operator transport cap."""
    transport_cap = getattr(client, "max_completion_tokens", None)
    if isinstance(transport_cap, int) and transport_cap > 0:
        return min(_FILTER_COMPLETION_CAP, transport_cap)
    return _FILTER_COMPLETION_CAP


def _reconcile_filter_response(
    batch_response: BatchFilterResponse,
    expected_seed_id: str,
    submitted_candidate_ids: set[str],
) -> tuple[bool, str | None]:
    """Reconcile an LLM filter response against the exact submitted ID set.

    Checks (order-independent):
    - ``seed_id`` matches the expected seed.
    - Exactly one verdict per submitted candidate ID.
    - No unknown IDs, no duplicate IDs, no omitted IDs.

    Args:
        batch_response: Parsed LLM response.
        expected_seed_id: The seed_id that was submitted.
        submitted_candidate_ids: The exact set of candidate IDs submitted.

    Returns:
        ``(True, None)`` if the response is valid, otherwise
        ``(False, error_message)`` describing the reconciliation failure.
    """
    if batch_response.seed_id != expected_seed_id:
        return False, (
            f"Expected seed_id '{expected_seed_id}' but response has "
            f"'{batch_response.seed_id}'"
        )

    response_ids = [v.candidate_id for v in batch_response.verdicts]
    response_id_set = set(response_ids)

    duplicates = _duplicate_response_ids(response_ids)
    if duplicates:
        return False, f"Duplicate candidate IDs in response: {duplicates}"

    unknown = _unknown_response_ids(response_id_set, submitted_candidate_ids)
    if unknown:
        return False, f"Unknown candidate IDs in response: {unknown}"

    omitted = _omitted_response_ids(response_id_set, submitted_candidate_ids)
    if omitted:
        return False, f"Missing candidate IDs in response: {omitted}"

    return True, None


def _duplicate_response_ids(response_ids: list[str]) -> list[str]:
    """Candidate IDs repeated within a response, sorted."""
    from collections import Counter

    return sorted(cid for cid, count in Counter(response_ids).items() if count > 1)


def _unknown_response_ids(
    response_id_set: set[str], submitted_candidate_ids: set[str]
) -> list[str]:
    """Response IDs that were never submitted, sorted."""
    return sorted(response_id_set - submitted_candidate_ids)


def _omitted_response_ids(
    response_id_set: set[str], submitted_candidate_ids: set[str]
) -> list[str]:
    """Submitted IDs missing from the response, sorted."""
    return sorted(submitted_candidate_ids - response_id_set)


def _build_call_log_entry(
    seed_id: str,
    llm_result: LLMResult,
    attempt: int,
) -> dict:
    """Build a call log dict for one filter LLM call."""
    raw_content = llm_result.content
    if hasattr(raw_content, "model_dump"):
        raw_content = raw_content.model_dump(mode="json")
    elif not isinstance(raw_content, str):
        raw_content = str(raw_content)
    return {
        "call": "candidate_filter",
        "seed_id": seed_id,
        "attempt": attempt,
        "system_prompt": llm_result.system_prompt,
        "user_prompt": llm_result.user_prompt,
        "response": raw_content,
        "prompt_tokens": llm_result.prompt_tokens,
        "completion_tokens": llm_result.completion_tokens,
        "duration_ms": llm_result.duration_ms,
        "request_controls": llm_result.request_controls,
    }


def _duplicate_submitted_ids(
    seed_candidates: list[CandidateTriple], seed_id: str
) -> None:
    """Reject duplicate candidate IDs in the submitted input."""
    raw_ids = [c.candidate_id for c in seed_candidates]
    if len(set(raw_ids)) != len(seed_candidates):
        from collections import Counter

        id_counts = Counter(raw_ids)
        dupes = sorted(cid for cid, count in id_counts.items() if count > 1)
        raise FilterProtocolError(
            f"Duplicate candidate IDs in submitted input for seed {seed_id}: {dupes}",
            call_log_entries=[],
        )


def _submitted_snapshot(
    seed_candidates: list[CandidateTriple],
) -> list[CandidateTriple]:
    """Deep-validated copy of the submitted candidates."""
    return [
        CandidateTriple.model_validate(c.model_dump(mode="python"))
        for c in seed_candidates
    ]


def _prompt_candidates(
    handle_lookup: dict[str, CandidateTriple],
) -> list[dict]:
    """Request-local candidate payloads for the batch filter prompt."""
    return [
        {
            "handle": handle,
            "entry_point": candidate.entry_point,
            "controllability": candidate.controllability,
            "direction": candidate.direction,
            "atlas_technique_ids": candidate.atlas_technique_ids,
            "atlas_technique_names": candidate.atlas_technique_names,
            "atlas_technique_descriptions": (candidate.atlas_technique_descriptions),
        }
        for handle, candidate in handle_lookup.items()
    ]


def _render_filter_user_prompt(
    first: CandidateTriple,
    seed_id: str,
    prompt_candidates: list[dict],
) -> str:
    """Render the seed-level batch filter user prompt."""
    return render_prompt(
        "filter_user.j2",
        seed_id=seed_id,
        attack_pattern_name=first.attack_pattern_name,
        attack_pattern_description=first.attack_pattern_description,
        threat_id=first.threat_id,
        threat_name=first.threat_name,
        owasp_llm_ids=first.owasp_llm_ids,
        risk_card_ref=first.risk_card_ref,
        candidates=prompt_candidates,
    )


def _verdicts_from_decisions(
    decisions: dict[str, FilterMapDecisionDraftV3 | FilterDecisionDraftV2],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """Translate request-local decisions into canonical verdicts."""
    return BatchFilterResponse(
        seed_id=seed_id,
        verdicts=[
            FilterVerdict(
                candidate_id=handle_lookup[handle].candidate_id,
                verdict="accept" if decision.relevant else "reject",
                rationale=decision.rationale,
            )
            for handle, decision in decisions.items()
        ],
    )


def _map_handle_draft_to_batch(
    draft: FilterMapDraftV3,
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """Exact-key V3 draft to canonical batch response."""
    decisions = reconcile_filter_map(draft, tuple(handle_lookup))
    return _verdicts_from_decisions(decisions, handle_lookup, seed_id)


def _ordinal_draft_to_batch(
    draft: BatchFilterDraftV2,
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """Ordinal V2 draft to canonical batch response after reconciliation."""
    decisions = reconcile_filter_ordinals(draft, tuple(handle_lookup))
    return _verdicts_from_decisions(decisions, handle_lookup, seed_id)


def _ordinal_draft_to_batch_or_response(
    raw_content: dict,
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """A raw dict as an ordinal draft, falling back to a typed response."""
    try:
        ordinal = BatchFilterDraftV2.model_validate(raw_content)
    except ValidationError:
        return BatchFilterResponse.model_validate(raw_content)
    return _ordinal_draft_to_batch(ordinal, handle_lookup, seed_id)


def _batch_from_dict(
    raw_content: dict,
    response_model: type[FilterMapDraftV3],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """A raw dict as the V3 map, falling back to V2 ordinal/typed shapes."""
    try:
        mapped = response_model.model_validate(raw_content)
    except ValidationError:
        return _ordinal_draft_to_batch_or_response(raw_content, handle_lookup, seed_id)
    return _map_handle_draft_to_batch(mapped, handle_lookup, seed_id)


def _typed_content_batch(
    raw_content: Any,
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse | None:
    """Typed wire-protocol content translated to a batch response."""
    if isinstance(raw_content, FilterMapDraftV3):
        return _map_handle_draft_to_batch(raw_content, handle_lookup, seed_id)
    if isinstance(raw_content, BatchFilterDraftV2):
        return _ordinal_draft_to_batch(raw_content, handle_lookup, seed_id)
    if isinstance(raw_content, BatchFilterResponse):
        return raw_content
    return None


def _parse_filter_content(
    raw_content: Any,
    response_model: type[FilterMapDraftV3],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """Translate LLM content to a batch response across wire formats."""
    typed = _typed_content_batch(raw_content, handle_lookup, seed_id)
    if typed is not None:
        return typed
    if isinstance(raw_content, dict):
        return _batch_from_dict(raw_content, response_model, handle_lookup, seed_id)
    if isinstance(raw_content, str):
        return _map_handle_draft_to_batch(
            response_model.model_validate(json.loads(raw_content)),
            handle_lookup,
            seed_id,
        )
    # Wrong content type — try to coerce via model_validate.
    return BatchFilterResponse.model_validate(raw_content)


def _exception_call_log(
    seed_id: str,
    attempt: int,
    system_prompt: str,
    user_prompt: str,
    error: str,
) -> dict:
    """Synthetic call log entry for an infrastructure/parse exception."""
    return {
        "call": "candidate_filter",
        "seed_id": seed_id,
        "attempt": attempt,
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "response": None,
        "error": error,
        "prompt_tokens": None,
        "completion_tokens": None,
        "duration_ms": None,
    }


def _filter_llm_call(
    client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_model: type[FilterMapDraftV3],
    attempt: int,
) -> tuple[LLMResult | None, str | None]:
    """One filter completion call; (result, None) or (None, error)."""
    try:
        llm_result = client.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_model,
            max_completion_tokens=_filter_completion_cap(client),
        )
    except Exception as exc:  # noqa: BLE001 - infrastructure/parse exception, records synthetic call log
        return None, f"Exception during complete(): {exc}"
    return llm_result, None


def _validate_filter_content(
    llm_result: LLMResult,
    response_model: type[FilterMapDraftV3],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> tuple[BatchFilterResponse | None, str | None]:
    """Parse one response into a batch, or (None, error)."""
    try:
        raw_content = llm_result.content
        if raw_content is None:
            raise ValueError("LLM returned None content (refusal or empty)")
        return (
            _parse_filter_content(raw_content, response_model, handle_lookup, seed_id),
            None,
        )
    except (
        ValidationError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        return None, f"Failed to parse LLM content as BatchFilterResponse: {exc}"


def _reconcile_batch(
    batch_response: BatchFilterResponse,
    seed_id: str,
    submitted_ids: set[str],
) -> tuple[bool, str | None]:
    """Reconcile one batch; unexpected exceptions become failures."""
    try:
        return _reconcile_filter_response(batch_response, seed_id, submitted_ids)
    except Exception as exc:  # noqa: BLE001 - reconciliation exception, records error
        return False, f"Reconciliation exception: {exc}"


def _filter_attempt_loop(
    client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_model: type[FilterMapDraftV3],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
    submitted_ids: set[str],
    seed_call_logs: list[dict],
) -> tuple[BatchFilterResponse | None, str | None]:
    """Run up to two filter attempts; returns (batch_response, error)."""
    batch_response: BatchFilterResponse | None = None
    reconciliation_error: str | None = None
    for attempt in (1, 2):
        batch_response, reconciliation_error = _attempt_filter_call(
            client,
            system_prompt,
            user_prompt,
            response_model,
            handle_lookup,
            seed_id,
            submitted_ids,
            attempt,
            seed_call_logs,
        )
        if reconciliation_error is None:
            break
        if attempt == 1:
            logger.warning(
                "Filter call failed for seed %s (attempt 1): %s — retrying",
                seed_id,
                reconciliation_error,
            )
            continue
    return batch_response, reconciliation_error


def _protocol_failure_raise(
    seed_id: str,
    reconciliation_error: str | None,
    batch_response: BatchFilterResponse | None,
    submitted_ids: set[str],
    seed_call_logs: list[dict],
) -> None:
    """Raise when no attempt produced a reconciled batch response."""
    if reconciliation_error is not None or batch_response is None:
        raise FilterProtocolError(
            f"Filter protocol failure for seed {seed_id} after retry: "
            f"{reconciliation_error}",
            call_log_entries=seed_call_logs,
            reconciliation=_reconciliation_evidence(
                seed_id,
                submitted_ids,
                batch_response,
                reconciliation_error,
            ),
        )


def _attempt_filter_call(
    client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_model: type[FilterMapDraftV3],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
    submitted_ids: set[str],
    attempt: int,
    seed_call_logs: list[dict],
) -> tuple[BatchFilterResponse | None, str | None]:
    """One complete filter attempt; appends call logs to ``seed_call_logs``.

    Returns ``(batch_response, None)`` on success or ``(None, error)``.
    """
    llm_result, llm_error = _filter_llm_call(
        client, system_prompt, user_prompt, response_model, attempt
    )
    if llm_error is not None:
        # Infrastructure/parse exception — record a synthetic call log
        # entry since we have no LLMResult.
        seed_call_logs.append(
            _exception_call_log(seed_id, attempt, system_prompt, user_prompt, llm_error)
        )
        return None, llm_error

    seed_call_logs.append(_build_call_log_entry(seed_id, llm_result, attempt))

    # Validate the ordinal wire protocol and translate it to the
    # established canonical verdict model only after exact-set
    # reconciliation. Historical typed responses remain accepted
    # for local test adapters; production requests V3 exclusively.
    batch_response, parse_error = _validate_filter_content(
        llm_result, response_model, handle_lookup, seed_id
    )
    if parse_error is not None:
        return None, parse_error

    ok, err = _reconcile_batch(batch_response, seed_id, submitted_ids)
    if not ok:
        # Keep the parsed batch for quarantine evidence even when the
        # response did not reconcile.
        return batch_response, err
    return batch_response, None


def _split_verdicts(
    batch_response: BatchFilterResponse,
) -> tuple[list[FilterVerdict], list[FilterVerdict]]:
    """Accepted and rejected verdicts of one batch response."""
    accepted_verdicts: list[FilterVerdict] = []
    rejected_verdicts: list[FilterVerdict] = []
    for v in batch_response.verdicts:
        if v.verdict == "accept":
            accepted_verdicts.append(v)
        else:
            rejected_verdicts.append(v)
    return accepted_verdicts, rejected_verdicts


def _rejection_records_for(
    rejected_verdicts: list[FilterVerdict],
    candidate_lookup: dict[str, CandidateTriple],
) -> list[RejectionRecord]:
    """Enriched rejection records resolved from the candidate lookup."""
    rejection_records: list[RejectionRecord] = []
    for v in rejected_verdicts:
        cand = candidate_lookup.get(v.candidate_id)
        if cand is not None:
            rejection_records.append(
                RejectionRecord(
                    candidate_id=v.candidate_id,
                    entry_point=cand.entry_point,
                    atlas_technique_ids=cand.atlas_technique_ids,
                    rationale=v.rationale,
                )
            )
    return rejection_records


def _filtered_seed_from(
    verdict: FilterVerdict,
    cand: CandidateTriple,
    original_seed: ScenarioSeed,
    rejection_records: list[RejectionRecord],
) -> FilteredSeed:
    """One accepted verdict as a filtered seed under the original seed."""
    return FilteredSeed(
        **original_seed.model_dump(),
        pinned_entry_point=cand.entry_point,
        pinned_technique_ids=cand.atlas_technique_ids,
        pinned_technique_names=cand.atlas_technique_names,
        entry_point_id=cand.entry_point_id,
        candidate_id=cand.candidate_id,
        origins=list(cand.origins),
        rejection_rationales=rejection_records,
        accepted_rationale=verdict.rationale,
    )


def _filtered_seed_results(
    accepted_verdicts: list[FilterVerdict],
    candidate_lookup: dict[str, CandidateTriple],
    original_seed: ScenarioSeed,
    rejection_records: list[RejectionRecord],
) -> list[FilteredSeed]:
    """Filtered seeds for all accepted verdicts resolvable in the lookup."""
    seed_results: list[FilteredSeed] = []
    for verdict in accepted_verdicts:
        cand = candidate_lookup.get(verdict.candidate_id)
        if cand is None:
            # Should not happen after reconciliation, but guard anyway.
            logger.error(
                "Candidate %s not in lookup after reconciliation — skipping",
                verdict.candidate_id,
            )
            continue
        seed_results.append(
            _filtered_seed_from(verdict, cand, original_seed, rejection_records)
        )
    return seed_results


def _rule_eligible_filtered_seeds(
    original_seed: ScenarioSeed,
    candidates: list[CandidateTriple],
) -> list[FilteredSeed]:
    """Preserve every rule-eligible candidate after advisory filter failure."""
    return [
        FilteredSeed(
            **original_seed.model_dump(),
            pinned_entry_point=candidate.entry_point,
            pinned_technique_ids=candidate.atlas_technique_ids,
            pinned_technique_names=candidate.atlas_technique_names,
            entry_point_id=candidate.entry_point_id,
            candidate_id=candidate.candidate_id,
            origins=list(candidate.origins),
            rejection_rationales=[],
            accepted_rationale=(
                "Candidate filter unavailable; rule-eligible candidate retained."
            ),
        )
        for candidate in candidates
    ]


def _handle_filter_protocol_failure(
    seed_id: str,
    exc: FilterProtocolError,
    advisory_on_failure: bool,
    groups: dict[str, list[CandidateTriple]],
    seed_lookup: dict[str, ScenarioSeed],
) -> tuple[list[FilteredSeed], int, list[dict], FilterProtocolError | None]:
    """Advisory admission, or deferral, for one failed seed.

    Returns (extra_results, extra_accepted, extra_logs, error_to_record).
    """
    if not advisory_on_failure:
        return [], 0, [], exc
    original_seed = seed_lookup[seed_id]
    results = _rule_eligible_filtered_seeds(original_seed, groups[seed_id])
    extra_logs = list(exc.call_log_entries)
    extra_logs.append(
        {
            "call": "candidate_filter",
            "seed_id": seed_id,
            "warning": "candidate_filter_unavailable",
            "response": None,
        }
    )
    return results, len(groups[seed_id]), extra_logs, None


def _escalate_protocol_errors(
    protocol_errors: list[FilterProtocolError],
    call_log_entries: list[dict],
    quarantine_on_failure: bool,
) -> tuple[list[dict], list[FilterSeedQuarantine]]:
    """Quarantine irreconcilable seeds, or raise when quarantine is off.

    Returns (all_call_logs, quarantined_seeds).
    """
    # Collect all call logs (including from successful seeds) so the
    # runner can persist them before failing the run.
    all_logs = list(call_log_entries)
    for err in protocol_errors:
        all_logs.extend(err.call_log_entries)
    quarantined_seeds: list[FilterSeedQuarantine] = []
    for error in protocol_errors:
        if error.reconciliation is not None and quarantine_on_failure:
            quarantined_seeds.append(
                FilterSeedQuarantine(
                    seed_id=error.reconciliation.seed_id,
                    reconciliation=error.reconciliation,
                )
            )
    if not quarantine_on_failure:
        first_err = protocol_errors[0]
        raise FilterProtocolError(str(first_err), call_log_entries=all_logs)
    return all_logs, quarantined_seeds


def _empty_filter_result(
    quarantine_on_failure: bool,
) -> _FilterResult | _QuarantineFilterResult:
    """The no-candidates result for the current failure mode."""
    if quarantine_on_failure:
        return [], [], [], []
    return [], [], []


def _filter_mode_guard(quarantine_on_failure: bool, advisory_on_failure: bool) -> None:
    """Quarantine and advisory modes are mutually exclusive."""
    if quarantine_on_failure and advisory_on_failure:
        raise ValueError(
            "quarantine_on_failure and advisory_on_failure are mutually exclusive"
        )


def _seed_lookup_from(seeds: list[ScenarioSeed]) -> dict[str, ScenarioSeed]:
    """Seed lookup for constructing FilteredSeed with full fields."""
    return {s.seed_id: s for s in seeds}


def _group_candidates(
    candidates: list[CandidateTriple],
) -> dict[str, list[CandidateTriple]]:
    """Candidates grouped by seed_id."""
    groups: dict[str, list[CandidateTriple]] = defaultdict(list)
    for c in candidates:
        groups[c.seed_id].append(c)
    return groups


def _final_filter_result(
    results: list[FilteredSeed],
    call_log_entries: list[dict],
    all_rejected_verdicts: list[FilterVerdict],
    quarantined_seeds: list[FilterSeedQuarantine],
    quarantine_on_failure: bool,
) -> _FilterResult | _QuarantineFilterResult:
    """The typed result tuple for the current failure mode."""
    if quarantine_on_failure:
        return results, call_log_entries, all_rejected_verdicts, quarantined_seeds
    return results, call_log_entries, all_rejected_verdicts


def _submission_context(
    submitted_snapshot: list[CandidateTriple],
) -> tuple[
    CandidateTriple,
    set[str],
    dict[str, CandidateTriple],
    dict[str, CandidateTriple],
]:
    """Derive (first, submitted_ids, handle_lookup, candidate_lookup)."""
    first = submitted_snapshot[0]
    submitted_ids: set[str] = {c.candidate_id for c in submitted_snapshot}
    handle_lookup = {
        f"c{index}": candidate for index, candidate in enumerate(submitted_snapshot)
    }
    candidate_lookup: dict[str, CandidateTriple] = {
        c.candidate_id: c for c in submitted_snapshot
    }
    return first, submitted_ids, handle_lookup, candidate_lookup


def _post_reconciliation_results(
    batch_response: BatchFilterResponse,
    candidate_lookup: dict[str, CandidateTriple],
    seed_lookup: dict[str, ScenarioSeed],
    seed_id: str,
    seed_candidates: list[CandidateTriple],
    seed_call_logs: list[dict],
) -> tuple[list[FilteredSeed], int, int, list[dict], list[FilterVerdict]]:
    """Resolve accepted/rejected verdicts into filtered seeds and counts."""
    accepted_verdicts, rejected_verdicts = _split_verdicts(batch_response)

    # Build enriched rejection records from candidate lookup.
    rejection_records = _rejection_records_for(rejected_verdicts, candidate_lookup)

    original_seed = seed_lookup.get(seed_id)
    if original_seed is None:
        logger.warning(
            "Seed %s not found in seed lookup — skipping %d accepted verdicts",
            seed_id,
            len(accepted_verdicts),
        )
        return (
            [],
            0,
            len(seed_candidates),
            seed_call_logs,
            rejected_verdicts,
        )

    seed_results = _filtered_seed_results(
        accepted_verdicts, candidate_lookup, original_seed, rejection_records
    )
    seed_accepted = len(accepted_verdicts)
    seed_total = len(seed_candidates)
    logger.info(
        "Seed %s: %d/%d candidates accepted",
        seed_id,
        seed_accepted,
        seed_total,
    )
    return (
        seed_results,
        seed_accepted,
        seed_total - seed_accepted,
        seed_call_logs,
        rejected_verdicts,
    )


def _iter_filter_futures(
    executor: ThreadPoolExecutor,
    groups: dict[str, list[CandidateTriple]],
    seed_lookup: dict[str, ScenarioSeed],
    advisory_on_failure: bool,
    client: LLMClient,
    system_prompt: str,
) -> Any:
    """Yield per-seed outcome deltas as futures complete.

    Each delta is (results, n_accepted, n_rejected, logs, rejected_verdicts,
    error_or_None).  Protocol and infrastructure failures are converted
    through :func:`_handle_filter_protocol_failure`.
    """
    futures = {
        executor.submit(
            _filter_one_seed, sid, cands, client, system_prompt, seed_lookup
        ): sid
        for sid, cands in groups.items()
    }
    for future in as_completed(futures):
        seed_id = futures[future]
        try:
            (
                seed_results,
                n_acc,
                n_rej,
                seed_logs,
                seed_rejected,
            ) = future.result()
            yield seed_results, n_acc, n_rej, seed_logs, seed_rejected, None
        except FilterProtocolError as exc:
            logger.error("Filter protocol failure for seed %s: %s", seed_id, exc)
            admitted, n_acc, extra_logs, error = _handle_filter_protocol_failure(
                seed_id, exc, advisory_on_failure, groups, seed_lookup
            )
            yield admitted, n_acc, 0, extra_logs, [], error
        except Exception as exc:
            # Any unexpected exception from _filter_one_seed is an
            # infrastructure/protocol failure, not an ordinary rejection.
            # Convert to FilterProtocolError so the run fails cleanly
            # with evidence rather than silently dropping a seed.
            logger.exception("Filter infrastructure failure for seed %s", seed_id)
            failure = FilterProtocolError(
                f"Filter infrastructure failure for seed {seed_id}: {exc}",
                call_log_entries=[],
            )
            admitted, n_acc, extra_logs, error = _handle_filter_protocol_failure(
                seed_id, failure, advisory_on_failure, groups, seed_lookup
            )
            yield admitted, n_acc, 0, extra_logs, [], error


def _filter_one_seed(
    seed_id: str,
    seed_candidates: list[CandidateTriple],
    client: LLMClient,
    system_prompt: str,
    seed_lookup: dict[str, ScenarioSeed],
) -> tuple[
    list[FilteredSeed],
    int,
    int,
    list[dict],
    list[FilterVerdict],
]:
    """Filter candidates for a single seed.

    Returns (accepted, n_accepted, n_rejected, call_log_entries,
    rejected_verdicts).
    Raises FilterProtocolError on irreconcilable response.
    """
    _duplicate_submitted_ids(seed_candidates, seed_id)

    # Deep-validated submission snapshot: reconstruct each candidate
    # through model_validate so forged model_copy(update=...) objects
    # are rejected and nested mutable collections are not shared with
    # the originals.  The prompt and candidate lookup are both derived
    # from this snapshot so application-resolved metadata cannot change
    # after submission.
    submitted_snapshot = _submitted_snapshot(seed_candidates)
    first, submitted_ids, handle_lookup, candidate_lookup = _submission_context(
        submitted_snapshot
    )

    prompt_candidates = _prompt_candidates(handle_lookup)
    user_prompt = _render_filter_user_prompt(first, seed_id, prompt_candidates)
    response_model = build_filter_map_response_model(tuple(handle_lookup))

    seed_call_logs: list[dict] = []
    batch_response, reconciliation_error = _filter_attempt_loop(
        client,
        system_prompt,
        user_prompt,
        response_model,
        handle_lookup,
        seed_id,
        submitted_ids,
        seed_call_logs,
    )
    _protocol_failure_raise(
        seed_id,
        reconciliation_error,
        batch_response,
        submitted_ids,
        seed_call_logs,
    )

    # Reconciliation passed — resolve metadata from candidate lookup.
    # Wrap post-reconciliation work so unexpected exceptions carry
    # accumulated seed_call_logs rather than empty evidence.
    try:
        return _post_reconciliation_results(
            batch_response,
            candidate_lookup,
            seed_lookup,
            seed_id,
            seed_candidates,
            seed_call_logs,
        )
    except Exception as exc:
        raise FilterProtocolError(
            f"Unexpected post-reconciliation failure for seed {seed_id}: {exc}",
            call_log_entries=seed_call_logs,
        ) from exc


def filter_candidates(
    candidates: list[CandidateTriple],
    seeds: list[ScenarioSeed],
    client: LLMClient,
    use_case: str,
    profile: CapabilityProfile,
    *,
    quarantine_on_failure: bool = False,
    advisory_on_failure: bool = False,
) -> _FilterResult | _QuarantineFilterResult:
    """Filter candidates via one LLM call per seed (with retry-on-malformed).

    Groups candidates by ``seed_id``, renders a batch prompt for each seed
    labelling candidates with request-local ordinals, and asks the LLM to
    accept or reject every candidate with a rationale. Canonical candidate
    IDs never cross the provider wire protocol.

    Each response is atomically reconciled against the exact submitted ID
    set: expected seed, exactly one verdict per submitted ID, no
    unknown/duplicate/omitted IDs (order-independent).  Malformed batches
    are discarded and retried exactly once.  A second failure raises
    :class:`FilterProtocolError` (failing the run with no partial
    candidate output) while retaining call/protocol evidence.

    The LLM is never authoritative for metadata — entry-point and
    technique metadata are resolved from the candidate lookup by
    ``candidate_id``.

    Args:
        candidates: Output of :func:`expand_candidates`.
        seeds: Original :class:`ScenarioSeed` list (for full field lookup).
        client: Configured :class:`LLMClient` instance.
        use_case: Free-text system description.
        profile: Capability profile of the system under assessment.

    Returns:
        Tuple of (filtered_seeds, call_log_entries, rejected_verdicts,
        quarantined_seeds).
        ``rejected_verdicts`` carries typed :class:`FilterVerdict` records
        for every LLM-rejected candidate, preserving the rationale and
        filter candidate ID for stage-ledger evidence.

    Raises:
        FilterProtocolError: If a seed's response cannot be reconciled
            after one retry and ``quarantine_on_failure`` is false.
    """
    if not candidates:
        logger.info("Filter: no candidates to filter")
        return _empty_filter_result(quarantine_on_failure)
    _filter_mode_guard(quarantine_on_failure, advisory_on_failure)

    # Build seed lookup for constructing FilteredSeed with full fields
    seed_lookup = _seed_lookup_from(seeds)

    # Group candidates by seed_id
    groups = _group_candidates(candidates)

    # Render system prompt once (shared across all seeds)
    system_prompt = render_prompt(
        "filter_system.j2",
        use_case=use_case,
        profile=profile,
    )

    total_accepted = 0
    total_rejected = 0
    results: list[FilteredSeed] = []
    call_log_entries: list[dict] = []
    all_rejected_verdicts: list[FilterVerdict] = []
    protocol_errors: list[FilterProtocolError] = []
    quarantined_seeds: list[FilterSeedQuarantine] = []

    max_workers = min(8, len(groups))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for delta in _iter_filter_futures(
            executor, groups, seed_lookup, advisory_on_failure, client, system_prompt
        ):
            results.extend(delta[0])
            total_accepted += delta[1]
            total_rejected += delta[2]
            call_log_entries.extend(delta[3])
            all_rejected_verdicts.extend(delta[4])
            if delta[5] is not None:
                protocol_errors.append(delta[5])

    if protocol_errors:
        call_log_entries, quarantined_seeds = _escalate_protocol_errors(
            protocol_errors, call_log_entries, quarantine_on_failure
        )

    logger.info(
        "Filter: %d/%d candidates survived (%d rejected)",
        total_accepted,
        total_accepted + total_rejected,
        total_rejected,
    )

    return _final_filter_result(
        results,
        call_log_entries,
        all_rejected_verdicts,
        quarantined_seeds,
        quarantine_on_failure,
    )


# ---------------------------------------------------------------------------
# Rule-based candidate pre-filter
# ---------------------------------------------------------------------------
#
# Deterministic rules that reject structurally impossible candidates
# BEFORE the LLM filter.  Each rule takes a technique ID, entry point
# name, entry point type, and capability profile; returns (reject,
# rationale).  Rules REJECT ONLY -- they never accept.  All non-rejected
# candidates pass to the LLM filter.
#
# The old DIRECT_ONLY_TECHNIQUES / apply_technique_entry_point_filter
# post-filter is absorbed here as _rule_direct_vs_indirect.
#
# Entry point controllability classification (classify_entry_point) and
# keyword constants are imported from asago_scenario_generator.models.capability_profile.


def is_indirect_entry_point(
    entry_point_name: str,
    direction: str,
    controllability: str | None = None,
) -> bool:
    """Return True if the entry point is an indirect channel.

    Convenience wrapper around :func:`classify_entry_point` for backward
    compatibility.
    """
    return (
        classify_entry_point(entry_point_name, direction, controllability) == "indirect"
    )


# Legacy constant preserved for backward compatibility in tests.
# The rule engine now uses TECHNIQUE_PROPERTIES instead.
DIRECT_ONLY_TECHNIQUES: frozenset[str] = frozenset(
    {
        tid
        for tid, props in TECHNIQUE_PROPERTIES.items()
        if props.get("requires_direct_access")
    }
)


def _get_technique_name(technique_id: str) -> str:
    """Look up human-readable name for a technique ID."""
    return ATLAS_TECHNIQUE_NAMES.get(technique_id, technique_id)


# --- Rule functions ---
#
# Each rule takes (technique_id, entry_point_name, ep_type, profile) and
# returns (reject: bool, rationale: str | None).  Rationale is a
# fixed-format template string when reject=True, None otherwise.


def _rule_supply_chain_mismatch(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """T0048/T0010 supply chain attacks are incompatible with runtime entry points."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if props.get("target_layer") != "supply_chain":
        return False, None
    if ep_type in ("direct", "indirect"):
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"supply chain attacks target the model development pipeline, "
            f"not runtime inputs."
        )
    return False, None


def _rule_entry_point_not_interactive(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """System-controlled entry points are not attacker-accessible."""
    if ep_type != "system":
        return False, None
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if "system" in props.get("incompatible_entry_types", set()):
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"system-controlled entry points are not attacker-accessible."
        )
    return False, None


def _rule_wrong_zone_direction(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Output-direction entry points cannot serve as attack ingress."""
    if ep_type != "system":
        return False, None
    # Check if the entry point name suggests output-only semantics.
    name_lower = entry_point_name.lower()
    output_signals = ("output", "response", "reply", "outbound", "emit")
    if not any(sig in name_lower for sig in output_signals):
        return False, None
    return True, (
        f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
        f"is incompatible with entry point type {ep_type} -- "
        f"output-direction entry points cannot be attack ingress channels."
    )


def _rule_technique_incompatible(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Technique's incompatible_entry_types includes this entry point type."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    incompatible = props.get("incompatible_entry_types", set())
    if ep_type in incompatible:
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"technique cannot target this entry point type."
        )
    return False, None


def _rule_direct_vs_indirect(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """T0051.000 requires direct access; T0051.001 requires indirect."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if props.get("requires_direct_access") and ep_type == "indirect":
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"technique requires direct attacker access to the prompt interface."
        )
    # T0051.001 and similar indirect-only techniques: reject on direct EPs.
    if technique_id == "AML.T0051.001" and ep_type == "direct":
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"indirect prompt injection requires a non-user-facing data channel."
        )
    return False, None


def _rule_preparatory_technique(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """T0043/T0044/T0016/T0021 are pre-attack prep, not entry-point-exploitable."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if props.get("is_preparatory"):
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"preparatory techniques are pre-attack steps that do not "
            f"directly exploit runtime entry points."
        )
    return False, None


# Layer mismatch table: (target_layer, incompatible ep_types, reason).
_LAYER_MISMATCH_REASONS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (
        "tool_schema",
        ("direct",),
        "tool schema injection targets tool metadata trust boundaries, "
        "not direct user chat interfaces.",
    ),
    (
        "training",
        ("direct", "indirect"),
        "training pipeline attacks target the model development process, "
        "not runtime inputs.",
    ),
    (
        "embedding",
        ("direct",),
        "embedding manipulation targets vector stores, not direct user input channels.",
    ),
)


def _layer_rejection(target_layer: str, ep_type: str) -> str | None:
    """The incompatibility reason for a layer/ep-type pair, if any."""
    for layer, incompatible_ep_types, reason in _LAYER_MISMATCH_REASONS:
        if target_layer == layer and ep_type in incompatible_ep_types:
            return reason
    return None


def _rule_technique_targets_wrong_layer(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Technique targets an infrastructure layer incompatible with the entry point."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    target_layer = props.get("target_layer")
    if target_layer is None:
        return False, None
    reason = _layer_rejection(target_layer, ep_type)
    if reason is None:
        return False, None
    return True, (
        f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
        f"is incompatible with entry point type {ep_type} -- {reason}"
    )


# Ordered list of all per-technique rules.  Evaluated top-to-bottom; first rejection wins.
_ALL_RULES = [
    _rule_supply_chain_mismatch,
    _rule_entry_point_not_interactive,
    _rule_wrong_zone_direction,
    _rule_technique_incompatible,
    _rule_direct_vs_indirect,
    _rule_preparatory_technique,
    _rule_technique_targets_wrong_layer,
]


# --- Threat-level prerequisite rules ---
#
# These check whether a candidate's OWASP threat (threat_id) has zone or
# capability prerequisites that the profile does not satisfy.  Unlike
# per-technique rules, these operate at the candidate level and reject
# the entire candidate regardless of technique.


def _rule_seed_profile_compatibility(
    seed_id: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Reject seeds that are structurally infeasible for the given profile.

    AP-T9-05 "false attribution via identity proxy" requires persistent
    memory for cross-user identity manipulation.  Without persistent
    session state, the attack pattern is infeasible.
    """
    if seed_id == "AP-T9-05" and not profile.has_persistent_memory:
        return True, (
            f"Rejected: seed {seed_id} (false attribution via identity proxy) "
            f"requires persistent memory for cross-user identity manipulation, "
            f"but profile has has_persistent_memory=False."
        )
    return False, None


def _rule_threat_requires_zone(
    threat_id: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Reject if the profile is missing zones required by the threat.

    Checks both ``required_zones`` (all must be present) and
    ``required_zones_any`` (at least one must be present).
    """
    prereqs = THREAT_PREREQUISITES.get(threat_id)
    if prereqs is None:
        return False, None

    active = set(profile.zones_active)

    # AND semantics: all required_zones must be active
    required = prereqs.get("required_zones", [])
    missing = _missing_required_zones(required, active)
    if missing:
        return True, (
            f"Rejected: threat {threat_id} requires zone(s) "
            f"{missing} but profile only has {sorted(active)}."
        )

    # OR semantics: at least one of required_zones_any must be active
    any_of = prereqs.get("required_zones_any", [])
    if _zone_any_unsatisfied(any_of, active):
        return True, (
            f"Rejected: threat {threat_id} requires at least one of "
            f"zone(s) {any_of} but profile only has {sorted(active)}."
        )

    return False, None


def _missing_required_zones(required: list[str], active: set[str]) -> list[str]:
    """Required zones that are not active, in declared order."""
    return [z for z in required if z not in active]


def _zone_any_unsatisfied(any_of: list[str], active: set[str]) -> bool:
    """True when OR-semantics zones exist but none is active."""
    return bool(any_of) and not active.intersection(any_of)


def _rule_threat_requires_capability(
    threat_id: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Reject if the profile is missing capabilities required by the threat."""
    prereqs = THREAT_PREREQUISITES.get(threat_id)
    if prereqs is None:
        return False, None

    required_caps = prereqs.get("required_capabilities", [])
    if not required_caps:
        return False, None

    missing = _missing_required_caps(required_caps, profile)
    if missing:
        return True, (
            f"Rejected: threat {threat_id} requires capability(ies) "
            f"{missing} but profile does not have them."
        )

    return False, None


_CAP_GETTERS: dict[str, str] = {
    "has_persistent_memory": "has_persistent_memory",
    "multi_agent": "multi_agent",
    "hitl": "hitl",
}


def _missing_required_caps(
    required_caps: list[str], profile: CapabilityProfile
) -> list[str]:
    """Required capabilities the profile lacks, in declared order."""
    missing = []
    for cap in required_caps:
        attr = _CAP_GETTERS.get(cap)
        if attr is None:
            continue
        if not getattr(profile, attr, False):
            missing.append(cap)
    return missing


# --- Rule-based filter orchestration ---


def _run_rules_on_technique(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None, str | None]:
    """Run all rules on a single (technique, entry_point) pair.

    Returns (True, rationale, rule_name) on first rejection,
    (False, None, None) if all pass.
    """
    for rule in _ALL_RULES:
        reject, rationale = rule(technique_id, entry_point_name, ep_type, profile)
        if reject:
            return True, rationale, rule.__name__
    return False, None, None


def apply_rule_based_filter(
    candidates: list[CandidateTriple],
    profile: CapabilityProfile,
    stage_records: list[StageRecord] | None = None,
) -> tuple[list[CandidateTriple], list[CandidateTriple], list[RejectionRecord]]:
    """Run deterministic rules on candidates, rejecting structural impossibilities.

    For each candidate, every technique in its combo is checked against all
    rules.  If ALL techniques in a combo are rejected, the entire candidate
    is rejected.  If some but not all techniques are rejected, the combo is
    pruned to keep only compatible techniques (the candidate survives with
    the reduced combo).

    Args:
        candidates: Output of :func:`expand_candidates`.
        profile: Capability profile (provides entry-point directions).
        stage_records: Optional list to append a :class:`StageRecord`
            for the rule-pruning dedup stage.

    Returns:
        Tuple of (rule_passed, rule_rejected, rejection_verdicts).
        ``rule_passed`` candidates are deduplicated and proceed to the
        LLM filter.  ``rule_rejected`` candidates are dropped with
        rationales.  ``rejection_verdicts`` are RejectionRecord objects
        for provenance.
    """
    if not candidates:
        return [], [], []

    rule_passed: list[CandidateTriple] = []
    rule_rejected: list[CandidateTriple] = []
    rejection_verdicts: list[RejectionRecord] = []

    for candidate in candidates:
        rejected, records, passed = _rule_filter_one_candidate(candidate, profile)
        rule_rejected.extend(rejected)
        rejection_verdicts.extend(records)
        rule_passed.extend(passed)

    _log_rule_rejections(rule_rejected, rule_passed)

    # Canonicalize and deduplicate immediately after rule pruning —
    # pruning techniques may cause two formerly-distinct candidates to
    # converge to the same canonical identity.
    raw_passed_count = len(rule_passed)
    rule_passed = canonicalize_and_dedup(rule_passed, stage="rule_pruning")
    _rule_pruning_stage_record(stage_records, raw_passed_count, rule_passed)

    return rule_passed, rule_rejected, rejection_verdicts


def _rule_filter_one_candidate(
    candidate: CandidateTriple,
    profile: CapabilityProfile,
) -> tuple[list[CandidateTriple], list[RejectionRecord], list[CandidateTriple]]:
    """Process one candidate into (rejected, rejection_records, passed)."""
    threat_reject, threat_rationale = _threat_rejection(candidate, profile)
    if threat_reject:
        return [candidate], [_threat_rejection_record(candidate, threat_rationale)], []

    ep_type = classify_entry_point(
        candidate.entry_point,
        candidate.direction or "bidirectional",
        candidate.controllability,
    )
    (
        compatible_ids,
        compatible_names,
        compatible_descs,
        combo_rationales,
        removed_tids,
        removed_rules,
        removed_reasons,
    ) = _technique_compatibilities(candidate, ep_type, profile)

    if not compatible_ids:
        # All techniques rejected -- reject the entire candidate.
        return (
            [candidate],
            [
                _full_rejection_record(
                    candidate,
                    combo_rationales,
                    removed_tids,
                    removed_rules,
                    removed_reasons,
                )
            ],
            [],
        )

    if len(compatible_ids) < len(candidate.atlas_technique_ids):
        # Partial pruning: some techniques removed from combo.
        candidate = _pruned_candidate(
            candidate,
            compatible_ids,
            compatible_names,
            compatible_descs,
            removed_tids,
            removed_rules,
            removed_reasons,
        )

    return [], [], [candidate]


def _threat_rejection_record(
    candidate: CandidateTriple, threat_rationale: str | None
) -> RejectionRecord:
    """A whole-candidate rejection from seed/threat prerequisites."""
    return RejectionRecord(
        candidate_id=candidate.candidate_id,
        entry_point=candidate.entry_point,
        atlas_technique_ids=candidate.atlas_technique_ids,
        rationale=threat_rationale or "Threat prerequisite not met.",
    )


def _log_rule_rejections(
    rule_rejected: list[CandidateTriple], rule_passed: list[CandidateTriple]
) -> None:
    """Log the rule-pruning outcome when any candidate was rejected."""
    if rule_rejected:
        logger.info(
            "Rule pre-filter: %d/%d candidates rejected, %d passed to LLM filter",
            len(rule_rejected),
            len(rule_rejected) + len(rule_passed),
            len(rule_passed),
        )


def _rule_pruning_stage_record(
    stage_records: list[StageRecord] | None,
    raw_passed_count: int,
    rule_passed: list[CandidateTriple],
) -> None:
    """Record the rule-pruning stage counts when a ledger is supplied."""
    if stage_records is not None:
        stage_records.append(
            StageRecord(
                stage="rule_pruning",
                input_count=raw_passed_count,
                output_count=len(rule_passed),
                collapsed_count=raw_passed_count - len(rule_passed),
            )
        )


# ---------------------------------------------------------------------------
# Post-filter: cap scenarios per attack pattern
# ---------------------------------------------------------------------------


def _threat_rejection(
    candidate: CandidateTriple,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Seed-level and threat-level prerequisite rejections."""
    threat_reject, threat_rationale = _rule_seed_profile_compatibility(
        candidate.seed_id,
        profile,
    )
    if not threat_reject:
        threat_reject, threat_rationale = _rule_threat_requires_zone(
            candidate.threat_id,
            profile,
        )
    if not threat_reject:
        threat_reject, threat_rationale = _rule_threat_requires_capability(
            candidate.threat_id,
            profile,
        )
    return threat_reject, threat_rationale


def _technique_compatibilities(
    candidate: CandidateTriple,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[list[str], list[str], list[str], list[str], list[str], list[str], list[str]]:
    """Split one combo into compatible and removed techniques.

    Returns (compatible_ids, compatible_names, compatible_descs,
    combo_rationales, removed_tids, removed_rules, removed_reasons).
    """
    compatible_ids: list[str] = []
    compatible_names: list[str] = []
    compatible_descs: list[str] = []
    combo_rationales: list[str] = []
    removed_tids: list[str] = []
    removed_reasons: list[str] = []
    removed_rules: list[str] = []

    for tid, tname, tdesc in zip(
        candidate.atlas_technique_ids,
        candidate.atlas_technique_names,
        candidate.atlas_technique_descriptions,
    ):
        reject, rationale, rule_name = _run_rules_on_technique(
            tid,
            candidate.entry_point,
            ep_type,
            profile,
        )
        if reject:
            combo_rationales.append(rationale)  # type: ignore[arg-type]
            removed_tids.append(tid)
            removed_reasons.append(rationale)  # type: ignore[arg-type]
            removed_rules.append(rule_name)  # type: ignore[arg-type]
        else:
            compatible_ids.append(tid)
            compatible_names.append(tname)
            compatible_descs.append(tdesc)

    return (
        compatible_ids,
        compatible_names,
        compatible_descs,
        combo_rationales,
        removed_tids,
        removed_rules,
        removed_reasons,
    )


def _removal_decisions_for(
    removed_tids: list[str],
    removed_rules: list[str],
    removed_reasons: list[str],
) -> tuple[RemovalDecision, ...]:
    """Per-removal decision records, one per removed technique."""
    return tuple(
        RemovalDecision(
            technique_id=tid,
            rule=rule_name or "unknown",
            reason=reason,
        )
        for tid, rule_name, reason in zip(removed_tids, removed_rules, removed_reasons)
    )


def _full_rejection_record(
    candidate: CandidateTriple,
    combo_rationales: list[str],
    removed_tids: list[str],
    removed_rules: list[str],
    removed_reasons: list[str],
) -> RejectionRecord:
    """A fully rejected combo, with per-technique removal decisions."""
    return RejectionRecord(
        candidate_id=candidate.candidate_id,
        entry_point=candidate.entry_point,
        atlas_technique_ids=candidate.atlas_technique_ids,
        rationale=combo_rationales[0] if combo_rationales else "Rule-rejected.",
        removal_decisions=_removal_decisions_for(
            removed_tids, removed_rules, removed_reasons
        ),
    )


def _pruned_candidate(
    candidate: CandidateTriple,
    compatible_ids: list[str],
    compatible_names: list[str],
    compatible_descs: list[str],
    removed_tids: list[str],
    removed_rules: list[str],
    removed_reasons: list[str],
) -> CandidateTriple:
    """Rebuild a partially pruned candidate with a new id and origin."""
    pruned = set(candidate.atlas_technique_ids) - set(compatible_ids)
    logger.info(
        "Rule pre-filter: pruned %s from combo for %s",
        pruned,
        candidate.entry_point,
    )
    new_candidate_id = compute_candidate_id(
        candidate.seed_id,
        candidate.entry_point_id,
        compatible_ids,
    )
    applied_rule = removed_rules[0] if removed_rules else None
    pruning_origin = CandidateOrigin(
        source_candidate_id=candidate.candidate_id,
        original_technique_ids=candidate.atlas_technique_ids,
        applied_rule=applied_rule,
        removed_technique_ids=tuple(removed_tids),
        removal_reasons=tuple(removed_reasons),
        removal_decisions=_removal_decisions_for(
            removed_tids, removed_rules, removed_reasons
        ),
        transform_stage="rule_pruning",
    )
    # Reconstruct the pruned candidate through model_validate so
    # canonical IDs are re-validated and nested collections are
    # not shared with the original.  Using model_validate instead
    # of model_copy(update=...) ensures the new candidate_id is
    # checked against the canonical recomputation.
    return CandidateTriple.model_validate(
        candidate.model_dump(mode="python")
        | {
            "atlas_technique_ids": tuple(compatible_ids),
            "atlas_technique_names": tuple(compatible_names),
            "atlas_technique_descriptions": tuple(compatible_descs),
            "candidate_id": new_candidate_id,
            "origins": candidate.origins + (pruning_origin,),
        }
    )


def cap_scenarios_per_pattern(
    filtered_seeds: Sequence[FilteredSeed],
    max_per_pattern: int,
    stage_records: list[StageRecord] | None = None,
) -> list[FilteredSeed]:
    """Cap the number of filtered seeds per attack pattern (seed_id).

    When a group exceeds ``max_per_pattern``, seeds are selected using
    greedy marginal coverage that balances both technique and entry-point
    diversity.

    At each selection step the candidate with the highest score is picked::

        score = (count of technique IDs NOT yet covered by selected set)
              + (1 if entry point NOT yet seen in selected set)

    Ties are broken by technique-combo size (prefer larger combos), then
    by original encounter order (lower index wins).

    This ensures dual-technique candidates float to the top early (more
    new technique ground), while single-technique candidates fill
    entry-point diversity once technique coverage is saturated.

    A warning is logged for every capped group.

    Args:
        filtered_seeds: Output of :func:`filter_candidates`.
        max_per_pattern: Maximum number of seeds to keep per ``seed_id``.

    Returns:
        A new list of :class:`FilteredSeed` with groups truncated as needed.
    """
    if max_per_pattern < 1:
        raise ValueError("max_per_pattern must be >= 1")

    # Group by seed_id (attack pattern), preserving encounter order.
    groups: dict[str, list[FilteredSeed]] = defaultdict(list)
    for fs in filtered_seeds:
        groups[fs.seed_id].append(fs)

    result: list[FilteredSeed] = []
    for seed_id, group in groups.items():
        if len(group) <= max_per_pattern:
            result.extend(group)
            continue

        selected = _greedy_coverage_selection(group, max_per_pattern)

        logger.warning(
            "Capped %s from %d to %d scenarios (--max-scenarios-per-pattern)",
            seed_id,
            len(group),
            len(selected),
        )
        result.extend(selected)

    # Canonicalize and deduplicate after capping — although capping
    # selects a subset, canonicalization ensures no duplicate identities
    # persist through the selection transform.
    pre_dedup_count = len(result)
    result = _dedup_filtered_seeds(result)
    if stage_records is not None:
        stage_records.append(
            StageRecord(
                stage="capping",
                input_count=pre_dedup_count,
                output_count=len(result),
                collapsed_count=pre_dedup_count - len(result),
            )
        )

    return result


def _greedy_coverage_selection(
    group: list[FilteredSeed], max_per_pattern: int
) -> list[FilteredSeed]:
    """Greedy marginal-coverage selection over one over-cap group."""
    covered_techniques: set[str] = set()
    seen_entry_points: set[str] = set()
    selected: list[FilteredSeed] = []
    remaining_indices: list[int] = list(range(len(group)))

    while len(selected) < max_per_pattern and remaining_indices:
        best_idx: int | None = None
        best_score: tuple[int, int, int] = (-1, -1, -1)

        for idx in remaining_indices:
            score = _marginal_score(
                group[idx], covered_techniques, seen_entry_points, idx
            )
            if score > best_score:
                best_score = score
                best_idx = idx

        assert best_idx is not None  # remaining_indices is non-empty
        chosen = group[best_idx]
        selected.append(chosen)
        covered_techniques.update(chosen.pinned_technique_ids)
        seen_entry_points.add(chosen.entry_point_id)
        remaining_indices.remove(best_idx)

    return selected


def _marginal_score(
    fs: FilteredSeed,
    covered_techniques: set[str],
    seen_entry_points: set[str],
    idx: int,
) -> tuple[int, int, int]:
    """(marginal coverage, combo size, -index) score tuple."""
    new_techniques = sum(
        1 for t in fs.pinned_technique_ids if t not in covered_techniques
    )
    new_entry_point = 1 if fs.entry_point_id not in seen_entry_points else 0
    marginal = new_techniques + new_entry_point
    combo_size = len(fs.pinned_technique_ids)
    # Score tuple: (marginal coverage, combo size, -index for stable ordering)
    return (marginal, combo_size, -idx)


def _dedup_filtered_seeds(
    filtered_seeds: list[FilteredSeed],
) -> list[FilteredSeed]:
    """Deduplicate FilteredSeeds by canonical identity.

    Groups by ``(seed_id, entry_point_id, sorted unique pinned_technique_ids)``
    and merges origins when duplicates are found.
    """
    if not filtered_seeds:
        return []

    groups: dict[tuple[str, str, tuple[str, ...]], list[FilteredSeed]] = defaultdict(
        list
    )
    for fs in filtered_seeds:
        groups[_filtered_seed_key(fs)].append(fs)

    result: list[FilteredSeed] = []
    for group in groups.values():
        if len(group) == 1:
            result.append(group[0])
            continue
        result.append(_merged_filtered_seed(group))

    return result


def _filtered_seed_key(fs: FilteredSeed) -> tuple[str, str, tuple[str, ...]]:
    """Canonical dedup identity of one filtered seed."""
    return (
        fs.seed_id,
        fs.entry_point_id,
        tuple(sorted(set(fs.pinned_technique_ids))),
    )


def _merged_filtered_seed(group: list[FilteredSeed]) -> FilteredSeed:
    """Merge duplicate filtered seeds: canonical origins, conflict-free."""
    all_origins: list[CandidateOrigin] = []
    for fs in group:
        all_origins.extend(fs.origins)
    unique_origins = _canonicalize_and_dedup_origins(all_origins)
    template = group[0]
    _non_provenance_conflicts(template, group[1:], _FILTERED_NON_PROV_FIELDS)
    return template.model_copy(update={"origins": unique_origins})


_FILTERED_NON_PROV_FIELDS = (
    "seed_id",
    "threat_id",
    "threat_name",
    "attack_pattern_name",
    "attack_pattern_description",
    "entry_point_id",
    "risk_card_ref",
    "owasp_llm_ids",
    "agentic_threat_ids",
)

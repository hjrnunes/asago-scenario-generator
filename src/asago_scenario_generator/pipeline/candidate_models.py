"""Candidate identity, provenance, funnel, and filter wire models."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    create_model,
    model_validator,
)

from asago_scenario_generator.models.capability_profile import compute_entry_point_id
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.seeds import ScenarioSeed

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


def _canonicalize_and_dedup_origins(
    all_origins: list[CandidateOrigin],
) -> list[CandidateOrigin]:
    """Canonicalize, deduplicate, and sort origins deterministically."""
    canonicalized = [_canonicalize_origin(o) for o in all_origins]
    return _dedup_canonical_origins(canonicalized)


def _non_provenance_conflicts(
    template: BaseModel,
    others: Sequence[BaseModel],
    fields: Sequence[str],
) -> None:
    """Reject conflicting non-provenance metadata across converged records.

    All records with the same canonical identity must agree on metadata
    fields.
    """
    for record in others:
        for field_name in fields:
            tval = getattr(template, field_name)
            cval = getattr(record, field_name)
            if tval != cval:
                raise ValueError(
                    f"Conflicting non-provenance metadata for "
                    f"converged candidate '{template.candidate_id}': "
                    f"field '{field_name}' differs "
                    f"({tval!r} vs {cval!r})"
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T18:58:53Z","module_hash":"4b9e48c77e936d22ce4b071623e7dce3ac8f622b36d47e1882beb79839ee6d9e","source_sha256":"71315833538f5a520a544d7f90574e9c935ee0167b4527dcf0e382835f7bf976","functions":[{"id":"func/compute_candidate_id","name":"compute_candidate_id","line":28,"end_line":44,"hash":"739554a8903bdeb932015a26bde6cdaf1bf84edbb108453b96f22ec33d9879d8"},{"id":"func/CandidateFunnel._validate_funnel","name":"_validate_funnel","line":170,"end_line":185,"hash":"7e113ddaea4c1291840f36dd422c09d9bb92c9f033ff8f329198b836d68f3912"},{"id":"func/_funnel_counts_nonnegative","name":"_funnel_counts_nonnegative","line":188,"end_line":195,"hash":"21a38855c210bb4526b908da64d3d52bf3d2f53435fd86fb9b2eb725095c568f"},{"id":"func/_funnel_expansion_ordered","name":"_funnel_expansion_ordered","line":198,"end_line":204,"hash":"00ab3354867fcd36b80cd6000307750e33a9122c7abce2b4fcfac0fde36b160c"},{"id":"func/_funnel_submission_reconciled","name":"_funnel_submission_reconciled","line":207,"end_line":219,"hash":"fb8a63dfd5fcf6fe2bb07c1dba54be55566c629328934398b276c9816d77375f"},{"id":"func/_funnel_accepted_subset","name":"_funnel_accepted_subset","line":222,"end_line":228,"hash":"2c36592b82554e9dc43dcc2dd857526652c9a7a8a6edf9326ba0b5c384a5855c"},{"id":"func/_funnel_selection_within_qualified","name":"_funnel_selection_within_qualified","line":231,"end_line":243,"hash":"4bfb91c1a449bf8c0c88b19fd691bea0ddc91938b92c7cb532217f65c37c9475"},{"id":"func/_funnel_projection_subset","name":"_funnel_projection_subset","line":246,"end_line":252,"hash":"d116adea1afbd989b6e27596cc86201c8e1aa50cb45649638a695e95196902b1"},{"id":"func/_funnel_main_lifecycle","name":"_funnel_main_lifecycle","line":255,"end_line":261,"hash":"61a658846c7444c52fde69977b1bf3ed18c26430f98e059629b67f44191ee9e6"},{"id":"func/_funnel_main_attempts_reconciled","name":"_funnel_main_attempts_reconciled","line":264,"end_line":271,"hash":"be31c9421b2faf02e67675e834ad6e85d1d2f87333ea50bd34b34852e40052ec"},{"id":"func/_funnel_remediation_reconciled","name":"_funnel_remediation_reconciled","line":274,"end_line":283,"hash":"58316d3b11b2d75073ba1d65d6fd4e6d32cb19c779d7d4617a95c12071229c3e"},{"id":"func/_funnel_attempted_reconciled","name":"_funnel_attempted_reconciled","line":286,"end_line":293,"hash":"7e0103dbd3a7b7c88790cf3e5c1da70bd4ce8abd51c79fe31ddabec1174a23aa"},{"id":"func/_funnel_admitted_reconciled","name":"_funnel_admitted_reconciled","line":296,"end_line":303,"hash":"fafc67a53796d208b89055df90f6924526c3da56422675e6e9915b6eb47a9713"},{"id":"func/_funnel_quarantine_subset","name":"_funnel_quarantine_subset","line":306,"end_line":312,"hash":"7993d5155ac93145ec74504d6ae9d96074b6d3b1371782ad3dfb4182971b6a5f"},{"id":"func/_funnel_artifacts_reconciled","name":"_funnel_artifacts_reconciled","line":315,"end_line":321,"hash":"5ccc594c443ed487e7a66571e70e3a283690c92e801b20501c6368dbb42f6514"},{"id":"func/_canonicalize_origin","name":"_canonicalize_origin","line":394,"end_line":424,"hash":"355d5068919a806c854051e3a7f8edee802c74f3f92bfb38033d480fbb3b4a87"},{"id":"func/_origin_key","name":"_origin_key","line":427,"end_line":437,"hash":"1b393980dbb844529fa152c4192168975c2c6b7164ab020a8131d2ca54af2168"},{"id":"func/_origin_sort_key","name":"_origin_sort_key","line":440,"end_line":450,"hash":"b3feb61920116f0ef38fad70d44e1426ed76352b4ae2181330efd503fcc5b118"},{"id":"func/_dedup_canonical_origins","name":"_dedup_canonical_origins","line":453,"end_line":465,"hash":"78c7dd427999f0f1ba56d35245dbf47983f7cc1acdd7cb63c8bbe00cb0ec221b"},{"id":"func/_canonicalize_and_dedup_origins","name":"_canonicalize_and_dedup_origins","line":468,"end_line":473,"hash":"94a6ce73784bd7d655cc0b5fd110289512a0482b9fc34128aaa8f27ea43fda1f"},{"id":"func/_non_provenance_conflicts","name":"_non_provenance_conflicts","line":476,"end_line":496,"hash":"038a22454cf5ebd2986578fabaa6102f89db6fe0d186b33c28d56685a115e921"},{"id":"func/CandidateTriple._validate_canonical_ids","name":"_validate_canonical_ids","line":568,"end_line":599,"hash":"eacd099f8a65c83df94d8abe4be12d3b57f38fff5bc8de8654854137f03c7a56"},{"id":"func/build_filter_map_response_model","name":"build_filter_map_response_model","line":673,"end_line":685,"hash":"2135104c867f4f66b221a5758709efd723586c4e0dae4676fd738cbfcbf7a0c4"},{"id":"func/_handles_unique_nonempty","name":"_handles_unique_nonempty","line":688,"end_line":691,"hash":"06c452ea3ba25d17152b3239d4a572c9d1c50d3ed8132c378a8104aa58a701ae"},{"id":"func/_handles_cn_ordinals","name":"_handles_cn_ordinals","line":694,"end_line":699,"hash":"116607d342e1d9d68563fc422f6dd3d9c96b012656b468667127c7d4deac2450"},{"id":"func/reconcile_filter_map","name":"reconcile_filter_map","line":702,"end_line":715,"hash":"152587d1e5655664f23820e53fe81e9d6bd4f238e3f8104e3e8892c2ef317593"},{"id":"func/reconcile_filter_ordinals","name":"reconcile_filter_ordinals","line":718,"end_line":726,"hash":"baed525d91019069b2ee9e3aeb18cc627e03abe686aeac290cd8e87483579c5f"},{"id":"func/_handles_duplicate_free","name":"_handles_duplicate_free","line":729,"end_line":733,"hash":"7fa69db982a6883656d136c192bac7a88f7504dd2cc29ef4bdcfcb2c963cc7bc"},{"id":"func/_handle_set_mismatch","name":"_handle_set_mismatch","line":736,"end_line":745,"hash":"066125b5774a5a59838607c1a7132d2447f25a8c3fba00c21a2fb09340f59676"},{"id":"func/FilterProtocolError.__init__","name":"__init__","line":784,"end_line":792,"hash":"5027acc8b32a4d4b9755dd458ce98c253f6e774d6b92083b62f66c7c0f35bfa3"},{"id":"func/_reconciliation_evidence","name":"_reconciliation_evidence","line":818,"end_line":838,"hash":"17c9a424cd1024c59aad458477987a6daea8cfed499d85a7026343e8322bc7aa"}]}
# mutate4py-manifest-end

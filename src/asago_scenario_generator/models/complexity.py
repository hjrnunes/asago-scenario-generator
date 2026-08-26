"""Closed, versioned attack-complexity assessment models (cmps.7).

This module separates two concepts that legacy generation conflated:

- **Actor capability** (``ActorProfile.capability_level``) — an immutable
  attribute of the generated threat actor, fixed at Call 0 and never
  relabelled afterwards to save a generated attack.
- **Attack complexity** — a deterministic, versioned assessment of the
  capability level an attack path *requires*, derived only from typed
  candidate-v2 projection inputs and typed realized action/access
  evidence.

The assessment is persisted separately from the actor profile so reports
and metrics can show actor capability and attack complexity distinctly.

Deliberately unsupported in rule version ``1`` (no typed, unambiguous
representation exists; do not invent heuristics for these):

- privileged access prerequisites at the *candidate* phase (chain
  preconditions are generic fact ASTs without a closed fact registry);
- supply-chain/training targeting at the *candidate* phase (typed only
  via realized ``ActorAccessProvenance.access_class``);
- custom exploit/code requirements (no typed field exists in the
  candidate-v2 or realized-action models);
- the ``expert`` required level (reserved for future typed evidence).

Zone counts, technique tuples, generated prose, free-text keyword
matching, and labels are never authoritative inputs.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Capability level scale (shared with ActorProfile.capability_level)
# ---------------------------------------------------------------------------

CapabilityLevel = Literal["novice", "intermediate", "advanced", "expert"]

CAPABILITY_LEVEL_ORDER: tuple[CapabilityLevel, ...] = (
    "novice",
    "intermediate",
    "advanced",
    "expert",
)
"""Canonical ascending ordering of capability levels (novice < expert)."""


def capability_level_rank(level: CapabilityLevel) -> int:
    """Return the ordinal rank of a capability level (novice=0 .. expert=3)."""
    return CAPABILITY_LEVEL_ORDER.index(level)


COMPLEXITY_RULE_VERSION: Literal["1"] = "1"
"""Closed version of the deterministic reviewed complexity rule table."""

AssessmentPhase = Literal["candidate_lower_bound", "final"]


# ---------------------------------------------------------------------------
# Reason and evidence records
# ---------------------------------------------------------------------------


class ComplexityModel(BaseModel):
    """Common closed, immutable configuration for assessment records."""

    model_config = ConfigDict(extra="forbid", frozen=True)


ComplexityEvidenceKind = Literal[
    "chain_step",
    "execution_requirement",
    "leaf_action",
    "actor_access_provenance",
]
"""Closed set of typed input surfaces an evidence reference may point at."""


class ComplexityEvidenceReference(ComplexityModel):
    """Typed pointer to the exact structured input that fired a rule."""

    kind: ComplexityEvidenceKind = Field(
        description="Which typed input surface the reference points at."
    )
    ref_id: str = Field(
        min_length=1,
        description=(
            "Stable identifier of the referenced input: canonical chain "
            "step_id, execution requirement_id, attack-tree node id, or the "
            "access-provenance initial_entry_point_id."
        ),
    )


ComplexityRuleId = Literal[
    # Candidate phase (ProjectedCandidate typed inputs).
    "chain.multi_step_attacker_control",
    "chain.deep_attacker_control",
    "access.upstream_source_influence",
    "tool.state_changing_fixture",
    # Final phase (typed realized actions and access provenance).
    "action.external_precondition",
    "access.indirect_influence_path",
    "access.privileged_prerequisite",
    "access.supply_chain_targeting",
]
"""Closed set of stable rule identifiers in rule-table version ``1``."""


AdmissionStage = Literal[
    "call0_actor_generation",
    "attack_tree_realization",
    "post_realization_validation",
]
"""Lifecycle stage responsible for remediating an admission mismatch."""

ADMISSION_STAGE_ORDER: tuple[AdmissionStage, ...] = (
    "call0_actor_generation",
    "attack_tree_realization",
    "post_realization_validation",
)
"""Canonical earliest-to-latest ordering of admission remediation stages."""


class ComplexityRuleSpec(ComplexityModel):
    """Authoritative metadata for one closed rule-table entry (version ``1``).

    Every persisted :class:`ComplexityReason` is validated against this
    table, so an impossible claim — wrong required level, wrong evidence
    kind, or a final-only rule in a candidate assessment — is
    unrepresentable.
    """

    rule_id: ComplexityRuleId = Field(description="Stable rule identifier.")
    required_level: CapabilityLevel = Field(
        description="Fixed capability level this rule requires when it fires."
    )
    origin_phase: AssessmentPhase = Field(
        description=(
            "Phase whose typed inputs fire this rule.  Candidate-origin "
            "reasons may be inherited unchanged into final assessments; "
            "final-origin reasons must never appear in candidate assessments."
        )
    )
    evidence_kinds: tuple[ComplexityEvidenceKind, ...] = Field(
        min_length=1,
        description=(
            "Closed set of evidence kinds this rule may reference, sorted "
            "ascending for determinism."
        ),
    )
    responsible_stage: AdmissionStage = Field(
        description=(
            "Earliest lifecycle stage whose bounded retry can remediate a "
            "mismatch this rule triggers: Call 0 actor generation when the "
            "evidence is known at actor generation (projection inputs and "
            "access provenance), attack-tree realization when the evidence "
            "is introduced by typed realized actions after Call 0."
        )
    )

    @model_validator(mode="after")
    def sorted_unique_evidence_kinds(self) -> ComplexityRuleSpec:
        kinds = list(self.evidence_kinds)
        if kinds != sorted(set(kinds)):
            raise ValueError("evidence_kinds must be sorted and unique")
        return self


def _spec(
    rule_id: ComplexityRuleId,
    required_level: CapabilityLevel,
    origin_phase: AssessmentPhase,
    evidence_kinds: tuple[ComplexityEvidenceKind, ...],
    responsible_stage: AdmissionStage,
) -> ComplexityRuleSpec:
    return ComplexityRuleSpec(
        rule_id=rule_id,
        required_level=required_level,
        origin_phase=origin_phase,
        evidence_kinds=evidence_kinds,
        responsible_stage=responsible_stage,
    )


_COMPLEXITY_RULE_TABLE: dict[ComplexityRuleId, ComplexityRuleSpec] = {
    # Candidate phase — typed ProjectedCandidate inputs, all known before
    # Call 0, so remediation is Call 0 bounded actor regeneration.
    "chain.multi_step_attacker_control": _spec(
        "chain.multi_step_attacker_control",
        "intermediate",
        "candidate_lower_bound",
        ("chain_step",),
        "call0_actor_generation",
    ),
    "chain.deep_attacker_control": _spec(
        "chain.deep_attacker_control",
        "advanced",
        "candidate_lower_bound",
        ("chain_step",),
        "call0_actor_generation",
    ),
    "access.upstream_source_influence": _spec(
        "access.upstream_source_influence",
        "intermediate",
        "candidate_lower_bound",
        ("execution_requirement",),
        "call0_actor_generation",
    ),
    "tool.state_changing_fixture": _spec(
        "tool.state_changing_fixture",
        "intermediate",
        "candidate_lower_bound",
        ("execution_requirement",),
        "call0_actor_generation",
    ),
    # Final phase — typed access provenance is established at Call 0 actor
    # generation (cmps.6), so these remediate at Call 0 even though they
    # only fire once realized provenance exists.
    "access.indirect_influence_path": _spec(
        "access.indirect_influence_path",
        "intermediate",
        "final",
        ("actor_access_provenance",),
        "call0_actor_generation",
    ),
    "access.privileged_prerequisite": _spec(
        "access.privileged_prerequisite",
        "intermediate",
        "final",
        ("actor_access_provenance",),
        "call0_actor_generation",
    ),
    "access.supply_chain_targeting": _spec(
        "access.supply_chain_targeting",
        "advanced",
        "final",
        ("actor_access_provenance",),
        "call0_actor_generation",
    ),
    # Final phase — typed realized actions are introduced by attack-tree
    # realization after Call 0, so remediation retries realization for a
    # simpler attack; the actor is immutable by then.
    "action.external_precondition": _spec(
        "action.external_precondition",
        "intermediate",
        "final",
        ("leaf_action",),
        "attack_tree_realization",
    ),
}

COMPLEXITY_RULE_TABLE: Mapping[ComplexityRuleId, ComplexityRuleSpec] = MappingProxyType(
    _COMPLEXITY_RULE_TABLE
)
"""The one authoritative, closed v1 rule table (metadata per rule).

Runtime-immutable: the v1 table is closed by definition, so mutation
raises ``TypeError``.  Changing a rule requires a rule-version bump.
"""


class ComplexityReason(ComplexityModel):
    """One typed reason record explaining a required-level trigger."""

    rule_id: ComplexityRuleId = Field(description="Stable rule identifier.")
    required_level: CapabilityLevel = Field(
        description="Capability level this rule requires when it fires."
    )
    detail: str = Field(
        min_length=1,
        description=(
            "Structured explanation of the trigger, including observed "
            "values (e.g. step counts) so the reason stands alone."
        ),
    )
    evidence: tuple[ComplexityEvidenceReference, ...] = Field(
        min_length=1,
        description=(
            "Typed references to the exact inputs that fired the rule. "
            "Canonicalized by ascending (kind, ref_id) at construction and "
            "on load, so the same evidence set always serializes "
            "byte-identically regardless of producer iteration order; "
            "duplicates are rejected."
        ),
    )

    @field_validator("evidence", mode="after")
    @classmethod
    def canonicalize_evidence(
        cls, value: tuple[ComplexityEvidenceReference, ...]
    ) -> tuple[ComplexityEvidenceReference, ...]:
        keys = [(ref.kind, ref.ref_id) for ref in value]
        if len(set(keys)) != len(keys):
            raise ValueError("evidence references must be unique by (kind, ref_id)")
        return tuple(sorted(value, key=lambda ref: (ref.kind, ref.ref_id)))

    @model_validator(mode="after")
    def coherent_with_rule_table(self) -> ComplexityReason:
        spec = COMPLEXITY_RULE_TABLE[self.rule_id]
        if self.required_level != spec.required_level:
            raise ValueError(
                f"rule {self.rule_id} requires level "
                f"'{spec.required_level}' in rule table v1, not "
                f"'{self.required_level}'"
            )
        allowed = set(spec.evidence_kinds)
        for ref in self.evidence:
            if ref.kind not in allowed:
                raise ValueError(
                    f"rule {self.rule_id} may only reference evidence kinds "
                    f"{sorted(allowed)}, not '{ref.kind}'"
                )
        return self


class ComplexityPhaseAssessment(ComplexityModel):
    """Assessment of one phase: candidate lower bound or final."""

    phase: AssessmentPhase
    required_level: CapabilityLevel
    reasons: tuple[ComplexityReason, ...] = Field(
        description=(
            "Reasons that fired in this phase, ordered deterministically "
            "by descending required level then ascending rule_id, deduplicated "
            "by rule_id. Empty when the phase assesses as novice."
        ),
    )

    @model_validator(mode="after")
    def deterministic_reason_order(self) -> ComplexityPhaseAssessment:
        error = _reason_order_error(self.phase, self.reasons)
        if error is not None:
            raise ValueError(error)
        level_error = _phase_level_error(self.required_level, self.reasons)
        if level_error is not None:
            raise ValueError(level_error)
        return self


def _unique_rule_ids_error(reasons: tuple[ComplexityReason, ...]) -> str | None:
    """Error when reasons repeat a rule_id, or None."""
    rule_ids = [reason.rule_id for reason in reasons]
    if len(set(rule_ids)) != len(rule_ids):
        return "complexity reasons must be unique by rule_id"
    return None


def _final_phase_reason_error(
    phase: AssessmentPhase, reasons: tuple[ComplexityReason, ...]
) -> str | None:
    """Error when a final-phase rule appears in a candidate assessment, or None."""
    for reason in reasons:
        spec = COMPLEXITY_RULE_TABLE[reason.rule_id]
        if spec.origin_phase == "final" and phase == "candidate_lower_bound":
            return (
                f"rule {reason.rule_id} originates in the final phase "
                "and cannot appear in a candidate_lower_bound assessment"
            )
    return None


def _ordered_reasons_error(reasons: tuple[ComplexityReason, ...]) -> str | None:
    """Error when reasons are not deterministically ordered, or None."""
    ordered = sorted(
        reasons,
        key=lambda r: (-capability_level_rank(r.required_level), r.rule_id),
    )
    if list(reasons) != ordered:
        return (
            "complexity reasons must be ordered by descending required "
            "level then ascending rule_id"
        )
    return None


def _reason_order_error(
    phase: AssessmentPhase, reasons: tuple[ComplexityReason, ...]
) -> str | None:
    """First reason-ordering violation message, or None when valid."""
    error = _unique_rule_ids_error(reasons)
    if error is not None:
        return error
    error = _final_phase_reason_error(phase, reasons)
    if error is not None:
        return error
    return _ordered_reasons_error(reasons)


def _phase_level_error(
    required_level: CapabilityLevel, reasons: tuple[ComplexityReason, ...]
) -> str | None:
    """Error when the phase level contradicts the reasons, or None."""
    if reasons:
        top = capability_level_rank(reasons[0].required_level)
        if capability_level_rank(required_level) != top:
            return "phase required_level must equal the highest reason level"
    elif required_level != "novice":
        return "a reasonless phase assessment must be novice"
    return None


class AttackComplexityAssessment(ComplexityModel):
    """Closed, versioned attack-complexity assessment record.

    Carries the candidate lower bound (computed before Call 0 from typed
    candidate-v2 projection inputs) and, once typed realized actions
    exist, the final required level.  Persisted separately from the
    immutable actor capability.
    """

    rule_version: Literal["1"] = Field(
        description="Closed version of the deterministic rule table used."
    )
    candidate_lower_bound: ComplexityPhaseAssessment = Field(
        description=(
            "Lower bound on actor capability computed from typed "
            "candidate-v2 projection inputs before Call 0."
        ),
    )
    final: ComplexityPhaseAssessment | None = Field(
        default=None,
        description=(
            "Final required level computed after typed realized actions "
            "exist; inherits the candidate lower bound and may only raise it."
        ),
    )

    @model_validator(mode="after")
    def coherent_phases(self) -> AttackComplexityAssessment:
        if self.candidate_lower_bound.phase != "candidate_lower_bound":
            raise ValueError(
                "candidate_lower_bound slot must carry a candidate_lower_bound "
                "phase assessment"
            )
        if self.final is not None:
            if self.final.phase != "final":
                raise ValueError("final slot must carry a final phase assessment")
            if capability_level_rank(self.final.required_level) < capability_level_rank(
                self.candidate_lower_bound.required_level
            ):
                raise ValueError(
                    "final required level cannot be below the candidate lower "
                    "bound for the same realized scenario"
                )
        return self


# ---------------------------------------------------------------------------
# Admission contract (fail-closed, typed routing)
# ---------------------------------------------------------------------------


def earliest_responsible_stage(reasons: tuple[ComplexityReason, ...]) -> AdmissionStage:
    """Earliest lifecycle stage responsible for a set of triggering reasons.

    Deterministic: minimum over the fixed ``ADMISSION_STAGE_ORDER`` of each
    rule's ``responsible_stage`` from the authoritative rule table.  This is
    the single source of truth used both by the admission helper and by the
    violation model's routing-coherence validation.
    """
    if not reasons:
        raise ValueError("at least one triggering reason is required")
    return min(
        (COMPLEXITY_RULE_TABLE[reason.rule_id].responsible_stage for reason in reasons),
        key=ADMISSION_STAGE_ORDER.index,
    )


class _AdmissionRoutingBase(ComplexityModel):
    """Shared payload for admission routing variants."""

    feedback: str = Field(
        min_length=1,
        description=(
            "Explicit reason text the owning stage can surface as retry "
            "feedback or quarantine evidence, including the required level."
        ),
    )


class Call0RegenerationRouting(_AdmissionRoutingBase):
    """Remediate at Call 0 actor generation.

    Used when the triggering evidence — candidate projection inputs or
    typed access provenance (cmps.6) — is established at actor generation
    time.  The bounded Call 0 retry loop constructs a *new* actor with a
    compatible capability level (or compatible access provenance); an
    already-constructed actor is never relabelled.
    """

    stage: Literal["call0_actor_generation"] = Field(
        default="call0_actor_generation",
        description="Earliest lifecycle stage responsible for handling.",
    )
    action: Literal["regenerate_actor_with_higher_capability"] = Field(
        default="regenerate_actor_with_higher_capability",
        description=(
            "Bounded action the owning stage must take: regenerate the "
            "actor through the existing Call 0 retry loop."
        ),
    )


class RealizationRetryRouting(_AdmissionRoutingBase):
    """Remediate at attack-tree realization.

    Used when the triggering evidence — typed realized leaf actions
    (cmps.9) — is introduced after Call 0.  The realization stage retries
    to produce a simpler attack path; the actor is immutable by then and
    is never relabelled or upgraded.
    """

    stage: Literal["attack_tree_realization"] = Field(
        default="attack_tree_realization",
        description="Earliest lifecycle stage responsible for handling.",
    )
    action: Literal["retry_realization_for_simpler_attack"] = Field(
        default="retry_realization_for_simpler_attack",
        description=(
            "Bounded action the owning stage must take: retry attack-tree "
            "realization for a simpler attack that does not trigger the "
            "raising rule."
        ),
    )


class QuarantineRouting(_AdmissionRoutingBase):
    """Fail-closed / retry-exhaustion fallback owned by cmps.5.

    cmps.7 emits this only when admission cannot be established at all
    (the requested assessment phase was never computed).  Routing an
    exhausted bounded retry to quarantine is a cmps.5 lifecycle decision;
    cmps.7 does not implement that state machine.
    """

    stage: Literal["post_realization_validation"] = Field(
        default="post_realization_validation",
        description="Earliest lifecycle stage responsible for handling.",
    )
    action: Literal["quarantine_scenario"] = Field(
        default="quarantine_scenario",
        description=(
            "Bounded action the owning stage must take: quarantine the "
            "scenario through semantic validation."
        ),
    )


ComplexityAdmissionRouting = Annotated[
    Call0RegenerationRouting | RealizationRetryRouting | QuarantineRouting,
    Field(discriminator="stage"),
]
"""Typed routing data for a capability/attack-complexity mismatch.

A discriminated union over the responsible lifecycle stage, so invalid
stage/action pairs are unrepresentable.  Identifies the earliest
responsible stage and the bounded action that stage must take through
its existing mechanism.  cmps.7 exposes this contract only; wiring into
the Call 0 retry loop, realization retry, and quarantine partition is
owned by cmps.5.
"""


class CapabilityAdmissionViolation(ComplexityModel):
    """Typed violation produced when the admission invariant fails.

    The invariant is: actor capability >= attack required level.  The
    check is fail-closed: requesting admission against an assessment
    phase that has not been computed is itself a violation.
    """

    rule_id: Literal[
        "actor_capability_below_attack_complexity",
        "complexity_assessment_phase_unavailable",
    ]
    phase: AssessmentPhase = Field(
        description="Assessment phase the admission check ran against."
    )
    rule_version: Literal["1"]
    actor_capability_level: CapabilityLevel = Field(
        description="Immutable actor capability level that was checked."
    )
    required_level: CapabilityLevel | None = Field(
        description=(
            "Required level the actor fell below; ``None`` only when the "
            "requested assessment phase was unavailable (fail-closed)."
        ),
    )
    triggering_reasons: tuple[ComplexityReason, ...] = Field(
        description=(
            "Reasons that establish the required level; empty only when "
            "the requested assessment phase was unavailable."
        ),
    )
    routing: ComplexityAdmissionRouting

    @model_validator(mode="after")
    def coherent_violation(self) -> CapabilityAdmissionViolation:
        error = (
            _below_complexity_level_error(
                self.actor_capability_level,
                self.required_level,
                self.triggering_reasons,
                self.routing.stage,
            )
            if self.rule_id == "actor_capability_below_attack_complexity"
            else _phase_unavailable_error(
                self.required_level, self.triggering_reasons, self.routing
            )
        )
        if error is not None:
            raise ValueError(error)
        return self


def _top_reason_level(reasons: tuple[ComplexityReason, ...]) -> int:
    """Rank of the highest-required-level triggering reason."""
    return max(capability_level_rank(reason.required_level) for reason in reasons)


def _routing_stage_error(
    stage: AdmissionStage, reasons: tuple[ComplexityReason, ...]
) -> str | None:
    """Error when routing stage is not the earliest responsible stage, or None."""
    expected_stage = earliest_responsible_stage(reasons)
    if stage != expected_stage:
        return (
            f"routing stage '{stage}' does not match the "
            f"deterministic earliest responsible stage "
            f"'{expected_stage}' implied by the triggering reasons"
        )
    return None


def _below_complexity_level_error(
    actor_level: CapabilityLevel,
    required_level: CapabilityLevel | None,
    reasons: tuple[ComplexityReason, ...],
    routing_stage: AdmissionStage,
) -> str | None:
    """First below-complexity coherence error, or None when coherent."""
    if required_level is None:
        return "below-complexity violations require a required_level"
    if not reasons:
        return "below-complexity violations require reasons"
    if capability_level_rank(actor_level) >= capability_level_rank(required_level):
        return (
            "below-complexity violation requires actor level strictly "
            "below the required level"
        )
    if capability_level_rank(required_level) != _top_reason_level(reasons):
        return "required_level must equal the top level of the triggering reasons"
    return _routing_stage_error(routing_stage, reasons)


def _phase_unavailable_error(
    required_level: CapabilityLevel | None,
    reasons: tuple[ComplexityReason, ...],
    routing: ComplexityAdmissionRouting,
) -> str | None:
    """First phase-unavailable coherence error, or None when coherent."""
    if required_level is not None:
        return "phase-unavailable violations must not carry a required_level"
    if reasons:
        return "phase-unavailable violations must not carry triggering reasons"
    if not isinstance(routing, QuarantineRouting):
        return (
            "phase-unavailable violations must carry quarantine routing "
            "(the fail-closed fallback owned by cmps.5)"
        )
    return None


class CapabilityAdmissionDecision(ComplexityModel):
    """Result of the fail-closed admission invariant check."""

    admitted: bool
    violation: CapabilityAdmissionViolation | None = None

    @model_validator(mode="after")
    def coherent_decision(self) -> CapabilityAdmissionDecision:
        if self.admitted != (self.violation is None):
            raise ValueError("admitted iff there is no violation")
        return self

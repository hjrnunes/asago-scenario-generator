"""Deterministic reviewed attack-complexity rule table (cmps.7).

One closed, versioned rule table with two phases:

- **Candidate lower bound** (:func:`assess_candidate_complexity`) — runs
  before Call 0 and consumes only typed candidate-v2 inputs:
  :class:`~asago_scenario_generator.pipeline.projection_contracts.ProjectedCandidate`
  ``complexity_inputs``, the immutable projection's selected steps, and
  the derived adapter-neutral execution requirements.
- **Final assessment** (:func:`assess_final_complexity`) — runs after
  typed realized actions exist and *adds only* structured typed
  action/access evidence: the discriminated attack-tree leaf actions
  (cmps.9) and the typed actor access provenance (cmps.6).

Technique tuples, generated prose, free-text keyword matching, labels,
and zone counts are never inputs.  Concepts without a typed,
unambiguous representation are documented as unsupported/deferred in
``asago_scenario_generator.models.complexity`` — no heuristic is invented for
them.  Candidate-v2 fails closed where explicit step/resource linkage
is missing; this policy does not infer those semantics either.

Admission invariant (:func:`evaluate_capability_admission`): actor
capability >= attack required level.  The check is fail-closed and
returns typed routing data for the earliest responsible stage,
determined per triggering rule by the authoritative rule table
(``COMPLEXITY_RULE_TABLE``): Call 0 bounded actor regeneration for
evidence known at actor generation (projection inputs, access
provenance), attack-tree/realization retry for evidence introduced by
typed realized actions after Call 0, and quarantine only as the
fail-closed fallback owned by cmps.5.  Wiring those mechanisms is
deferred to cmps.5 (lifecycle ownership); cmps.7 exposes only the
contract.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from asago_scenario_generator.models.attack_pattern_contracts import (
    StateChangingToolFixtureRequirement,
    UpstreamSourceInfluenceRequirement,
)
from asago_scenario_generator.models.attack_tree import (
    AttackTreeNode,
    ExternalPreconditionAction,
)
from asago_scenario_generator.models.complexity import (
    COMPLEXITY_RULE_TABLE,
    COMPLEXITY_RULE_VERSION,
    AdmissionStage,
    AssessmentPhase,
    AttackComplexityAssessment,
    Call0RegenerationRouting,
    CapabilityAdmissionDecision,
    CapabilityAdmissionViolation,
    CapabilityLevel,
    ComplexityAdmissionRouting,
    ComplexityEvidenceReference,
    ComplexityPhaseAssessment,
    ComplexityReason,
    ComplexityRuleId,
    QuarantineRouting,
    RealizationRetryRouting,
    capability_level_rank,
    earliest_responsible_stage,
)
from asago_scenario_generator.models.scenario import ActorAccessProvenance
from asago_scenario_generator.pipeline.projection_contracts import ProjectedCandidate

# ---------------------------------------------------------------------------
# Rule table v1 thresholds
# ---------------------------------------------------------------------------

_MULTI_STEP_ATTACKER_THRESHOLD = 3
_DEEP_CHAIN_ATTACKER_THRESHOLD = 5


def _level(rule_id: ComplexityRuleId) -> CapabilityLevel:
    """Fixed required level from the one authoritative rule table."""
    return COMPLEXITY_RULE_TABLE[rule_id].required_level


# ---------------------------------------------------------------------------
# Reason assembly helpers
# ---------------------------------------------------------------------------


def _assemble_phase(
    phase: AssessmentPhase, reasons: list[ComplexityReason]
) -> ComplexityPhaseAssessment:
    """Dedup by rule_id and order deterministically (level desc, rule_id)."""
    by_rule: dict[str, ComplexityReason] = {}
    for reason in reasons:
        previous = by_rule.get(reason.rule_id)
        if previous is not None and previous != reason:
            raise ValueError(f"conflicting complexity reasons for {reason.rule_id}")
        by_rule[reason.rule_id] = reason
    ordered = sorted(
        by_rule.values(),
        key=lambda r: (-capability_level_rank(r.required_level), r.rule_id),
    )
    required: CapabilityLevel = (
        ordered[0].required_level if ordered else "novice"  # type: ignore[assignment]
    )
    return ComplexityPhaseAssessment(
        phase=phase, required_level=required, reasons=tuple(ordered)
    )


# ---------------------------------------------------------------------------
# Candidate-phase rules (typed ProjectedCandidate inputs only)
# ---------------------------------------------------------------------------


def _attacker_controlled_step_ids(candidate: ProjectedCandidate) -> tuple[str, ...]:
    chain = candidate.projection.source_chain
    selected = set(candidate.projection.selected_step_ids)
    return tuple(
        step.step_id
        for step in chain.steps
        if step.step_id in selected and step.attacker_controlled
    )


def _rule_chain_multi_step(candidate: ProjectedCandidate) -> ComplexityReason | None:
    count = candidate.complexity_inputs.attacker_controlled_step_count
    if count < _MULTI_STEP_ATTACKER_THRESHOLD:
        return None
    return ComplexityReason(
        rule_id="chain.multi_step_attacker_control",
        required_level=_level("chain.multi_step_attacker_control"),
        detail=(
            f"Projected chain carries {count} attacker-controlled selected "
            f"steps (>= {_MULTI_STEP_ATTACKER_THRESHOLD}): coordinated "
            f"multi-step execution beyond a single-shot action."
        ),
        evidence=tuple(
            ComplexityEvidenceReference(kind="chain_step", ref_id=step_id)
            for step_id in _attacker_controlled_step_ids(candidate)
        ),
    )


def _rule_chain_deep(candidate: ProjectedCandidate) -> ComplexityReason | None:
    count = candidate.complexity_inputs.attacker_controlled_step_count
    if count < _DEEP_CHAIN_ATTACKER_THRESHOLD:
        return None
    return ComplexityReason(
        rule_id="chain.deep_attacker_control",
        required_level=_level("chain.deep_attacker_control"),
        detail=(
            f"Projected chain carries {count} attacker-controlled selected "
            f"steps (>= {_DEEP_CHAIN_ATTACKER_THRESHOLD}): deep campaign-level "
            f"chaining."
        ),
        evidence=tuple(
            ComplexityEvidenceReference(kind="chain_step", ref_id=step_id)
            for step_id in _attacker_controlled_step_ids(candidate)
        ),
    )


def _rule_upstream_source_influence(
    candidate: ProjectedCandidate,
) -> ComplexityReason | None:
    requirements = tuple(
        requirement
        for requirement in candidate.execution_requirements
        if isinstance(requirement, UpstreamSourceInfluenceRequirement)
    )
    if not requirements:
        return None
    return ComplexityReason(
        rule_id="access.upstream_source_influence",
        required_level=_level("access.upstream_source_influence"),
        detail=(
            "Candidate derives an upstream-source-influence execution "
            "requirement: indirect ingress through an actor-influenced "
            "upstream source across a trust boundary."
        ),
        evidence=tuple(
            ComplexityEvidenceReference(
                kind="execution_requirement", ref_id=requirement.requirement_id
            )
            for requirement in requirements
        ),
    )


def _rule_state_changing_fixture(
    candidate: ProjectedCandidate,
) -> ComplexityReason | None:
    requirements = tuple(
        requirement
        for requirement in candidate.execution_requirements
        if isinstance(requirement, StateChangingToolFixtureRequirement)
    )
    if not requirements:
        return None
    return ComplexityReason(
        rule_id="tool.state_changing_fixture",
        required_level=_level("tool.state_changing_fixture"),
        detail=(
            "Candidate derives a state-changing tool fixture execution "
            "requirement: the attack path depends on mutating persisted "
            "tool state before the terminal outcome."
        ),
        evidence=tuple(
            ComplexityEvidenceReference(
                kind="execution_requirement", ref_id=requirement.requirement_id
            )
            for requirement in requirements
        ),
    )


_CANDIDATE_RULES: tuple[
    Callable[[ProjectedCandidate], ComplexityReason | None], ...
] = (
    _rule_chain_multi_step,
    _rule_chain_deep,
    _rule_upstream_source_influence,
    _rule_state_changing_fixture,
)


# ---------------------------------------------------------------------------
# Final-phase rules (typed realized actions and access provenance only)
# ---------------------------------------------------------------------------


def _rule_external_precondition_action(
    leaves: tuple[AttackTreeNode, ...], access: ActorAccessProvenance | None
) -> ComplexityReason | None:
    del access  # this rule consumes typed actions only
    nodes = tuple(
        leaf
        for leaf in leaves
        if leaf.action is not None
        and isinstance(leaf.action, ExternalPreconditionAction)
    )
    if not nodes:
        return None
    return ComplexityReason(
        rule_id="action.external_precondition",
        required_level=_level("action.external_precondition"),
        detail=(
            "Realized attack tree stages attacker preparation outside the "
            "assessed system boundary (typed external_precondition action: "
            "attacker-hosted infrastructure, staging, or pre-positioning)."
        ),
        evidence=tuple(
            ComplexityEvidenceReference(kind="leaf_action", ref_id=node.id)
            for node in nodes
        ),
    )


def _rule_indirect_influence_path(
    leaves: tuple[AttackTreeNode, ...], access: ActorAccessProvenance | None
) -> ComplexityReason | None:
    del leaves  # this rule consumes typed access provenance only
    if access is None or access.ingress_mode != "indirect":
        return None
    return ComplexityReason(
        rule_id="access.indirect_influence_path",
        required_level=_level("access.indirect_influence_path"),
        detail=(
            "Realized access provenance is indirect: the actor influences "
            "an upstream data source across a trust boundary rather than "
            "controlling input directly."
        ),
        evidence=(
            ComplexityEvidenceReference(
                kind="actor_access_provenance",
                ref_id=access.initial_entry_point_id,
            ),
        ),
    )


def _rule_privileged_prerequisite(
    leaves: tuple[AttackTreeNode, ...], access: ActorAccessProvenance | None
) -> ComplexityReason | None:
    del leaves  # this rule consumes typed access provenance only
    if access is None or access.access_class != "privileged":
        return None
    return ComplexityReason(
        rule_id="access.privileged_prerequisite",
        required_level=_level("access.privileged_prerequisite"),
        detail=(
            "Realized access provenance declares a privileged access class: "
            "pre-existing elevated or internal access is a prerequisite of "
            "the attack path."
        ),
        evidence=(
            ComplexityEvidenceReference(
                kind="actor_access_provenance",
                ref_id=access.initial_entry_point_id,
            ),
        ),
    )


def _rule_supply_chain_targeting(
    leaves: tuple[AttackTreeNode, ...], access: ActorAccessProvenance | None
) -> ComplexityReason | None:
    del leaves  # this rule consumes typed access provenance only
    if access is None or access.access_class != "supply_chain":
        return None
    return ComplexityReason(
        rule_id="access.supply_chain_targeting",
        required_level=_level("access.supply_chain_targeting"),
        detail=(
            "Realized access provenance declares a supply-chain access "
            "class: the attack path targets the system through an upstream "
            "supply-chain or training-data position."
        ),
        evidence=(
            ComplexityEvidenceReference(
                kind="actor_access_provenance",
                ref_id=access.initial_entry_point_id,
            ),
        ),
    )


_FINAL_RULES: tuple[
    Callable[
        [tuple[AttackTreeNode, ...], ActorAccessProvenance | None],
        ComplexityReason | None,
    ],
    ...,
] = (
    _rule_external_precondition_action,
    _rule_indirect_influence_path,
    _rule_privileged_prerequisite,
    _rule_supply_chain_targeting,
)


# ---------------------------------------------------------------------------
# Public assessment API
# ---------------------------------------------------------------------------


def assess_candidate_complexity(
    candidate: ProjectedCandidate,
) -> AttackComplexityAssessment:
    """Compute the candidate lower bound before Call 0.

    Consumes only typed candidate-v2 inputs.  Pure and deterministic:
    the same candidate always yields the identical assessment.
    """
    reasons = [
        reason for rule in _CANDIDATE_RULES if (reason := rule(candidate)) is not None
    ]
    return AttackComplexityAssessment(
        rule_version=COMPLEXITY_RULE_VERSION,
        candidate_lower_bound=_assemble_phase("candidate_lower_bound", reasons),
    )


def assess_final_complexity(
    assessment: AttackComplexityAssessment,
    realized_leaves: Iterable[AttackTreeNode],
    access: ActorAccessProvenance | None,
) -> AttackComplexityAssessment:
    """Compute the final required level once typed realized actions exist.

    Starts from the candidate lower bound and adds only structured typed
    action/access evidence, so the final level can never fall below the
    candidate lower bound for the same realized scenario.  Actor
    capability is never an input and never mutated.
    """
    leaves = tuple(realized_leaves)
    reasons = list(assessment.candidate_lower_bound.reasons)
    reasons.extend(
        reason for rule in _FINAL_RULES if (reason := rule(leaves, access)) is not None
    )
    return assessment.model_copy(update={"final": _assemble_phase("final", reasons)})


def evaluate_capability_admission(
    actor_capability_level: CapabilityLevel,
    assessment: AttackComplexityAssessment,
    *,
    phase: AssessmentPhase,
) -> CapabilityAdmissionDecision:
    """Fail-closed check of the admission invariant.

    The invariant is: actor capability >= attack required level.  A
    mismatch returns a typed violation routed to the earliest
    responsible stage, chosen deterministically across all triggering
    reasons via the authoritative rule table: Call 0 bounded actor
    regeneration when the raising evidence is known at actor generation
    (projection inputs, access provenance), attack-tree/realization
    retry when the raising evidence is introduced by typed realized
    actions after Call 0.  The actor profile is never mutated or
    relabelled.  Requesting a phase whose assessment has not been
    computed fails closed to the quarantine fallback owned by cmps.5.
    """
    phase_assessment = _phase_assessment(assessment, phase)
    if phase_assessment is None:
        return CapabilityAdmissionDecision(
            admitted=False,
            violation=_quarantine_violation(assessment, phase, actor_capability_level),
        )

    required = phase_assessment.required_level
    if capability_level_rank(actor_capability_level) >= capability_level_rank(required):
        return CapabilityAdmissionDecision(admitted=True)

    return CapabilityAdmissionDecision(
        admitted=False,
        violation=_below_capability_violation(
            actor_capability_level, phase_assessment, phase, assessment.rule_version
        ),
    )


def _phase_assessment(
    assessment: AttackComplexityAssessment, phase: AssessmentPhase
) -> ComplexityPhaseAssessment | None:
    """Assessment for the requested phase, or None when not computed."""
    if phase == "candidate_lower_bound":
        return assessment.candidate_lower_bound
    return assessment.final


def _quarantine_violation(
    assessment: AttackComplexityAssessment,
    phase: AssessmentPhase,
    actor_capability_level: CapabilityLevel,
) -> CapabilityAdmissionViolation:
    """Fail-closed violation when the requested phase was never computed."""
    return CapabilityAdmissionViolation(
        rule_id="complexity_assessment_phase_unavailable",
        phase=phase,
        rule_version=assessment.rule_version,
        actor_capability_level=actor_capability_level,
        required_level=None,
        triggering_reasons=(),
        routing=QuarantineRouting(
            feedback=(
                f"No '{phase}' attack-complexity assessment exists "
                f"(rule v{assessment.rule_version}); admission cannot "
                "be established — fail closed to the quarantine "
                "fallback owned by cmps.5."
            ),
        ),
    )


def _triggering_reasons(
    phase_assessment: ComplexityPhaseAssessment, required: CapabilityLevel
) -> tuple[ComplexityReason, ...]:
    """Reasons establishing the required level, in rule-table order."""
    return tuple(
        reason
        for reason in phase_assessment.reasons
        if reason.required_level == required
    )


def _reason_rule_ids(reasons: tuple[ComplexityReason, ...]) -> str:
    """Comma-joined rule IDs for admission feedback messages."""
    return ", ".join(reason.rule_id for reason in reasons)


def _call0_feedback(
    actor_capability_level: CapabilityLevel,
    required: CapabilityLevel,
    rule_ids: str,
    phase: AssessmentPhase,
    rule_version: str,
) -> str:
    """Feedback for the bounded Call 0 actor-regeneration retry."""
    if phase == "candidate_lower_bound":
        return (
            f"Actor capability '{actor_capability_level}' is below the "
            f"candidate lower bound '{required}' (complexity rule "
            f"v{rule_version}; triggered by: {rule_ids}). "
            f"Regenerate the actor with capability_level >= '{required}' "
            "through the bounded Call 0 retry loop, or reject the "
            "candidate. Capability is fixed at construction; never "
            "relabel an existing actor."
        )
    return (
        f"Actor capability '{actor_capability_level}' is below the "
        f"final required level '{required}' (complexity rule "
        f"v{rule_version}; triggered by: {rule_ids}). "
        "The triggering evidence is established at Call 0 actor "
        "generation: rerun the bounded Call 0 retry loop to "
        f"construct an actor with capability_level >= '{required}' "
        "(or compatible access provenance). The realized actor is "
        "immutable; never relabel it. Retry exhaustion falls back "
        "to quarantine owned by cmps.5."
    )


def _realization_retry_feedback(
    actor_capability_level: CapabilityLevel,
    required: CapabilityLevel,
    rule_ids: str,
    rule_version: str,
) -> str:
    """Feedback for the attack-tree realization retry."""
    return (
        f"Actor capability '{actor_capability_level}' is below the "
        f"final required level '{required}' (complexity rule "
        f"v{rule_version}; triggered by: {rule_ids}). "
        "The complexity was introduced by typed realized actions "
        "after Call 0: retry attack-tree realization for a simpler "
        "attack that does not trigger these rules. The actor is "
        "immutable; never relabel or upgrade it. Retry exhaustion "
        "falls back to quarantine owned by cmps.5."
    )


def _violation_routing(
    actor_capability_level: CapabilityLevel,
    required: CapabilityLevel,
    rule_ids: str,
    phase: AssessmentPhase,
    rule_version: str,
    stage: AdmissionStage,
) -> ComplexityAdmissionRouting:
    """Bounded retry routing for a below-capability violation."""
    if stage == "call0_actor_generation":
        return Call0RegenerationRouting(
            feedback=_call0_feedback(
                actor_capability_level, required, rule_ids, phase, rule_version
            )
        )
    if stage == "attack_tree_realization":
        return RealizationRetryRouting(
            feedback=_realization_retry_feedback(
                actor_capability_level, required, rule_ids, rule_version
            )
        )
    # Unreachable in rule table v1: no rule is quarantine-owned, and the
    # violation model rejects below-complexity routing whose stage does
    # not match the earliest responsible stage implied by the reasons.
    raise ValueError(f"no bounded retry stage owns the triggering rules: {rule_ids}")


def _below_capability_violation(
    actor_capability_level: CapabilityLevel,
    phase_assessment: ComplexityPhaseAssessment,
    phase: AssessmentPhase,
    rule_version: str,
) -> CapabilityAdmissionViolation:
    """Typed violation routed to the earliest responsible retry stage."""
    required = phase_assessment.required_level
    triggering = _triggering_reasons(phase_assessment, required)
    rule_ids = _reason_rule_ids(triggering)
    stage = earliest_responsible_stage(triggering)
    routing = _violation_routing(
        actor_capability_level, required, rule_ids, phase, rule_version, stage
    )
    return CapabilityAdmissionViolation(
        rule_id="actor_capability_below_attack_complexity",
        phase=phase,
        rule_version=rule_version,
        actor_capability_level=actor_capability_level,
        required_level=required,
        triggering_reasons=triggering,
        routing=routing,
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T15:52:02Z","module_hash":"7a1116237bbf21eb0d633e9e3b1dfbbc71e9f905046e4724693f88ce7e05ae50","source_sha256":"8bf0464074bf937c5b8091c1e7071cdb40b94382fddb6419d91c71d8aeffba62","functions":[{"id":"func/_level","name":"_level","line":78,"end_line":80,"hash":"d553d43f382b3e79c249aa82e7ed426f9dfed4e181ad25cd668e136a68a82d96"},{"id":"func/_assemble_phase","name":"_assemble_phase","line":88,"end_line":107,"hash":"4ae23f260b6c0636fbb17304cc78fa5cfa50c7ca54828cec4aedf2282f84d011"},{"id":"func/_attacker_controlled_step_ids","name":"_attacker_controlled_step_ids","line":115,"end_line":122,"hash":"64737e0332977beedddbd60b7f53cedc1b7305747b36bfcdce9510571a99a2e2"},{"id":"func/_rule_chain_multi_step","name":"_rule_chain_multi_step","line":125,"end_line":141,"hash":"eee4a1051cae1b044d9fe262079619c0f0f639fdcc6517d9971f1badcf07a8aa"},{"id":"func/_rule_chain_deep","name":"_rule_chain_deep","line":144,"end_line":160,"hash":"193e886bc8e4783976d30a9a6d0891d4d6f0d2f3a864097c503c3ba502496f41"},{"id":"func/_rule_upstream_source_influence","name":"_rule_upstream_source_influence","line":163,"end_line":187,"hash":"a0f8f5ba69a75f6ff99179a4b6d4764d4a489b319eda05f926ed5780376b26dd"},{"id":"func/_rule_state_changing_fixture","name":"_rule_state_changing_fixture","line":190,"end_line":214,"hash":"1ac8fbb537a867be776b760eee6a98f13e445b329f4a25280add6b637c47fb54"},{"id":"func/_rule_external_precondition_action","name":"_rule_external_precondition_action","line":232,"end_line":256,"hash":"b31eb11120c50902d8a82697e382079a1e41ecd8e2681135378f6d0f15337481"},{"id":"func/_rule_indirect_influence_path","name":"_rule_indirect_influence_path","line":259,"end_line":279,"hash":"66409b96e3f1865629866cedc036bcebdb2227fb35dc52ef08aa624d224f62c1"},{"id":"func/_rule_privileged_prerequisite","name":"_rule_privileged_prerequisite","line":282,"end_line":302,"hash":"d6d255820c1295b12aa4dd5d7405e1110dd6c172c9137f8a24115ff9ab38ed32"},{"id":"func/_rule_supply_chain_targeting","name":"_rule_supply_chain_targeting","line":305,"end_line":325,"hash":"d2ea0789aaed2c7d66ba84bf38cb86bbf7ff92b4d0df783dcf31afabca132142"},{"id":"func/assess_candidate_complexity","name":"assess_candidate_complexity","line":347,"end_line":361,"hash":"766ee27b9eb2edac99553b527d934bd28c326a501af4e911715dd366d86c5840"},{"id":"func/assess_final_complexity","name":"assess_final_complexity","line":364,"end_line":381,"hash":"0bbe53b80702ce9b3f1604d7a1ecb8a91fcceff3df1efcd9c0466bd64851873e"},{"id":"func/evaluate_capability_admission","name":"evaluate_capability_admission","line":384,"end_line":419,"hash":"ff958793a95355fe9e4381222ef3163e384525c060ebe1a23f98aea53df79530"},{"id":"func/_phase_assessment","name":"_phase_assessment","line":422,"end_line":428,"hash":"579b948a12ea44cd58e1e343da52cfb95928ad22abc17873144e3fb39e8acae9"},{"id":"func/_quarantine_violation","name":"_quarantine_violation","line":431,"end_line":452,"hash":"ef1e5b6188d4ba5d6a0575536ca650f75aca08b0fa896a9becdd303a2f7f5c8d"},{"id":"func/_triggering_reasons","name":"_triggering_reasons","line":455,"end_line":463,"hash":"17f41acceddc900ef39f33d6ac7c882ce6ae82a601fc30b1b756b0cfe29eca48"},{"id":"func/_reason_rule_ids","name":"_reason_rule_ids","line":466,"end_line":468,"hash":"0ff100a57b76f74a472f1869917d4dc75034c9c4e2628fc858f8f8603dc1612b"},{"id":"func/_call0_feedback","name":"_call0_feedback","line":471,"end_line":499,"hash":"b59f2db0ae69bae6b14ff4cc2d14ca8f5dd71e014d2cf980e83ff074e9084ebd"},{"id":"func/_realization_retry_feedback","name":"_realization_retry_feedback","line":502,"end_line":518,"hash":"25c7aa2762363c4072cd26772665fe53a5c57181129fcde8b094e0d708a8762c"},{"id":"func/_violation_routing","name":"_violation_routing","line":521,"end_line":545,"hash":"aa1797839be7830fbff7892eb54642b14e3151a75779eba18cbe409cde6e1971"},{"id":"func/_below_capability_violation","name":"_below_capability_violation","line":548,"end_line":570,"hash":"95bfab3d9d1afe7e3220abdc5e7057f063929ee76014e218da027d25c1eb8127"}]}
# mutate4py-manifest-end

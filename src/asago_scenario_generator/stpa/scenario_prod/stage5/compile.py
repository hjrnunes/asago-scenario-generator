"""Compilation of validated Stage 5 drafts into BDIGenerationResult."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pydantic import (
    BaseModel,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalEvidenceStatus,
    CausalFactorKind,
    CausalMechanism,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    SemanticCondition,
)
from asago_scenario_generator.stpa.observation_contract import (
    ObservationAssessment,
    ObservationContract,
    ObservationCriterion,
    assess_observation_criteria,
    default_observation_contract,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
    AdversaryReach,
    AttackerBDI,
)
from asago_scenario_generator.stpa.discriminating_condition import (
    ConditionCheck,
    DiscriminatingCondition,
)
from ..condition_check import (
    ConditionUniverse,
    check_discriminating_condition,
    condition_failure_message,
)
from ..tool_call_binding import bind_tool_call_condition
from .wire import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    UnsafeOutcomeDeclaration,
    _CausalSourceChoice,
)
from .conditions import (
    _resolve_temporal_condition,
)
from .validate import (
    FUNCTIONAL_TEST_GAIN,
    _normalize_provider_semantic_proposition,
    _validate_intention_factor_handles,
)


_UNSELECTED_PROCESS_MODEL_MARKER = "Not selected as a causal factor in this scenario."


_CONDITION_DISCARDED_ANALYTICAL = (
    "The scenario is analytical-only, so the returned discriminating "
    "condition was discarded."
)


_CONDITION_DISCARDED_UNGROUNDED = (
    "No target operations or observations were supplied, so the returned "
    "discriminating condition was discarded."
)


def _discriminating_condition_result(
    condition: DiscriminatingCondition | None,
    universe: ConditionUniverse | None,
    assessment: ObservationAssessment | None = None,
) -> tuple[DiscriminatingCondition | None, ConditionCheck | None, str | None]:
    """Return the accepted condition, its code-owned check, and any omission."""

    if condition is None or universe is None:
        return None, None, None
    if assessment is not None and assessment.disposition == "analytical_only":
        return None, None, _CONDITION_DISCARDED_ANALYTICAL
    if not universe.grounded:
        return None, None, _CONDITION_DISCARDED_UNGROUNDED
    outcome = check_discriminating_condition(condition, universe)
    if outcome.failures:
        raise ValueError(condition_failure_message(outcome))
    return outcome.condition, outcome.check, None


def _materialize_adversary(draft: BaseModel) -> Adversary:
    """Derive the compiler-owned adversary fields (Phase 3 deviations 7-8).

    A ``kind: none`` record ignores the provider's gain text and carries the
    fixed functional-test marker. The wire carries no stimulus, so the reach
    stays null unless the adversary kind itself asserts content reach; the
    producer makes no delivery claim the handoff could publish.
    """
    if draft.kind is AdversaryKind.third_party_via_content:
        reach = AdversaryReach.retrieved_content
    else:
        reach = None
    if draft.kind is AdversaryKind.none:
        gain = FUNCTIONAL_TEST_GAIN
    else:
        gain = getattr(draft, "gain", None)
        if gain is None:
            raise ValueError("adversarial response omitted its required gain")
    return Adversary(kind=draft.kind, gain=gain, reaches_target_via=reach)


def _materialize_normal_context_bdi(
    draft: BaseModel,
    choices: tuple[_CausalSourceChoice, ...],
    context: ScenarioGenerationContext,
    observation_contract: ObservationContract | None = None,
    *,
    condition_universe: ConditionUniverse | None = None,
    condition_omitted_reason: str | None = None,
) -> BDIGenerationResult:
    """Compile a normal-path draft: semantics and evidence, no execution wire.

    The result carries no execution contract and no executable unsafe-outcome
    condition; nothing is generated and later stripped.  Lineage stays
    compiler-owned: the exact hazard/constraint IDs derive from the immutable
    context.
    """
    choices_by_handle = {choice.handle: choice for choice in choices}
    attacker_bdi = _materialize_context_attacker_bdi(draft, choices_by_handle)
    factors = _materialize_context_factors(draft, choices, choices_by_handle, context)
    outcome = draft.unsafe_outcome
    _normalize_provider_semantic_proposition(outcome, context)
    adversary = _materialize_adversary(draft.adversary)
    criteria, contract, assessment = _normal_observation_assessment(
        outcome, observation_contract
    )
    condition, condition_check, discarded_reason = _discriminating_condition_result(
        getattr(outcome, "discriminating_condition", None),
        condition_universe,
        assessment,
    )
    omitted_reason = condition_omitted_reason or discarded_reason
    binding = bind_tool_call_condition(
        condition,
        condition_universe.fact_values if condition_universe is not None else {},
        condition_omitted_reason=omitted_reason,
    )
    return BDIGenerationResult(
        defender_vulnerabilities=_materialize_context_vulnerabilities(
            factors,
            context,
        ),
        attacker_bdi=attacker_bdi,
        causal_factors=factors,
        unsafe_outcome=UnsafeOutcomeDeclaration(
            condition=None,
            semantic_proposition=outcome.semantic_proposition,
            hazard_refs=tuple(item.hazard_id for item in context.hazards),
            constraint_refs=tuple(item.constraint_id for item in context.constraints),
        ),
        adversary=adversary,
        observation_criteria=criteria,
        observation_assessment=assessment,
        observation_contract_id=contract.contract_id if contract is not None else None,
        observation_contract_digest=(
            contract.content_digest if contract is not None else None
        ),
        safe_observable_outcome=outcome.safe_observable_outcome,
        discriminating_condition=condition,
        condition_check=condition_check,
        condition_omitted_reason=omitted_reason,
        tool_call_condition_status=binding.status,
        tool_call_condition=binding.condition,
    )


def _normal_observation_assessment(
    outcome: BaseModel, observation_contract: ObservationContract | None
) -> tuple[
    list[ObservationCriterion],
    ObservationContract | None,
    ObservationAssessment | None,
]:
    criteria = [
        ObservationCriterion.model_validate(item.model_dump(mode="json"))
        for item in outcome.observation_criteria
    ]
    contract = observation_contract or (
        default_observation_contract() if criteria else None
    )
    assessment = (
        assess_observation_criteria(criteria, contract)
        if contract is not None
        else None
    )
    return criteria, contract, assessment


def _materialize_context_attacker_bdi(
    draft: BaseModel,
    choices_by_handle: Mapping[str, _CausalSourceChoice],
) -> AttackerBDI:
    """Compile provider attacker prose and local intention handles."""
    attacker_draft = draft.attacker_bdi
    _validate_intention_factor_handles(attacker_draft, draft.causal_factors)
    return AttackerBDI(
        beliefs=list(attacker_draft.beliefs),
        desires=list(attacker_draft.desires),
        intentions=[
            _materialize_intention(item, choices_by_handle)
            for item in attacker_draft.intentions
        ],
    )


def _materialize_context_factors(
    draft: BaseModel,
    choices: tuple[_CausalSourceChoice, ...],
    choices_by_handle: Mapping[str, _CausalSourceChoice],
    context: ScenarioGenerationContext,
) -> list[CausalFactorDeclaration]:
    """Compile causal factors and close their temporal references."""
    factor_order = {
        factor.source_handle: index
        for index, factor in enumerate(draft.causal_factors, start=1)
    }
    return [
        _materialize_causal_factor(
            item,
            choices_by_handle,
            temporal_condition=_resolve_temporal_condition(
                item.temporal_condition,
                item.source_handle,
                choices,
                context,
                factor_order=factor_order,
                binding_scope=f"factor-{factor_order[item.source_handle]}",
            ),
        )
        for item in draft.causal_factors
    ]


def _materialize_context_vulnerabilities(
    factors: Sequence[CausalFactorDeclaration],
    context: ScenarioGenerationContext,
) -> dict[str, str]:
    """Derive public PM annotations from one causal story.

    Contextual providers explain a process-model flaw only through the exact
    causal-factor source and evidence.  Every supplied PM still appears in
    the legacy public map; a PM without a selected factor receives a
    scenario-scoped marker rather than an assertion that its evidence is
    absent.
    """
    vulnerabilities = {
        belief.element_id: _UNSELECTED_PROCESS_MODEL_MARKER
        for belief in context.target_control_path.process_model_parts
    }
    for factor in factors:
        if factor.kind is CausalFactorKind.process_model_flaw:
            if factor.source_id in vulnerabilities:
                vulnerabilities[factor.source_id] = factor.evidence
    return vulnerabilities


def _materialize_intention(
    draft: BaseModel,
    choices: dict[str, _CausalSourceChoice],
) -> str:
    """Attach exact structural identities to one model-authored intention."""
    source_ids = tuple(
        dict.fromkeys(choices[handle].source_id for handle in draft.source_handles)
    )
    return f"{draft.description.strip()} [structural sources: {', '.join(source_ids)}]"


def _materialize_causal_factor(
    draft: BaseModel,
    choices: dict[str, _CausalSourceChoice],
    *,
    temporal_condition: SemanticCondition | None = None,
) -> CausalFactorDeclaration:
    """Compile one local causal-source handle into the closed domain record."""
    choice = choices[draft.source_handle]
    evidence_status = draft.evidence_status
    bounded_assumption = getattr(draft, "bounded_assumption", None)
    capability_refs = tuple(getattr(draft, "capability_refs", ()))
    access_refs = tuple(getattr(draft, "access_refs", ()))
    if (
        bounded_assumption is not None
        and evidence_status is CausalEvidenceStatus.structural_failure
        and not capability_refs
        and not access_refs
    ):
        evidence_status = CausalEvidenceStatus.bounded_assumption
    return CausalFactorDeclaration(
        kind=choice.kind,
        source_id=choice.source_id,
        evidence=draft.evidence,
        mechanism=getattr(draft, "mechanism", CausalMechanism.none),
        temporal_condition=(
            temporal_condition
            if temporal_condition is not None
            else getattr(draft, "temporal_condition", None)
        ),
        evidence_status=evidence_status,
        capability_refs=capability_refs,
        access_refs=access_refs,
        bounded_assumption=bounded_assumption,
    )

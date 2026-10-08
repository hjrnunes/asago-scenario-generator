"""Validation and correction of Stage 5 provider drafts."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import re
from collections.abc import Mapping, Sequence
from typing import Any
from pydantic import (
    BaseModel,
)
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalMechanism,
    validate_mechanism_pairing,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    normalize_semantic_proposition,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.observation_contract import (
    ObservationAssessment,
    ObservationContract,
    ObservationCriterion,
    SafeObservableOutcome,
    assess_observation_criteria,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AdversaryKind,
)
from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
)
from ..condition_check import (
    ConditionCheckOutcome,
    ConditionUniverse,
    build_condition_universe,
    target_observation_fact_values,
    check_discriminating_condition,
    condition_failure_message,
    condition_findings,
    condition_findings_message,
)
from ..content_surface import ContentSurfaceFacts
from ..target_observations import TargetObservationSnapshot
from .wire import (
    _CausalSourceChoice,
    _ContextAdversarialDraft,
    _ContextAttackerBDIDraft,
    _ContextFunctionalAdversaryDraft,
    _ContextSemanticOutcomeDraft,
)
from .sources import (
    _causal_source_choices,
)
from .conditions import (
    _resolve_temporal_condition,
)
from .condition_claims import ConditionClaim, condition_claim_findings
from .issues import ExactIssueError, IssueCode, ValidationIssueError
from .records import (
    Stage5Normalization,
)


def _declared_causal_handles(factor_drafts: Sequence[BaseModel]) -> set[str]:
    """Return the unique request-local handles declared by provider factors."""
    handles = {item.source_handle for item in factor_drafts}
    if len(handles) != len(factor_drafts):
        raise ValueError("causal factor source handles must be unique")
    return handles


_PROSE_STRUCTURAL_REFERENCE = re.compile(
    r"\b(?:PM|FB|CA|CM|CL|CP|RESP|H|L|SC|CF|SEM|REQ|OUTCOME|EXEC|SCN)-"
    r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\b"
)


# Phase 3 deviation 8: a ``kind: none`` record is a functional test whose
# gain is compiler-owned bookkeeping, never provider text.
FUNCTIONAL_TEST_GAIN = "Functional test: no adversary gains from this unsafe outcome."


def _normalize_gain_text(value: str) -> str:
    """Collapse a gain or constraint sentence for substring comparison."""
    collapsed = re.sub(r"\s+", " ", value.strip().casefold())
    return collapsed.strip(" \t.,;:!\"'()")


def _validate_adversary_gain(
    adversary: _ContextAdversarialDraft,
    context: ScenarioGenerationContext,
) -> None:
    """Reject a gain that restates a governing constraint instead of a benefit."""
    if adversary.gain is None:
        raise ValueError(
            "adversarial scenarios require a non-empty gain; functional "
            "kind 'none' must omit gain"
        )
    normalized_gain = _normalize_gain_text(adversary.gain)
    for constraint in context.constraints:
        if normalized_gain in _normalize_gain_text(constraint.description):
            raise ValueError(
                f"adversary gain restates constraint {constraint.constraint_id}: "
                "say what the adversary gets, not what the constraint forbids"
            )


def _validate_normal_provider_payload(
    value: BaseModel,
    context: ScenarioGenerationContext,
    content_surface: ContentSurfaceFacts | None = None,
    observation_contract: ObservationContract | None = None,
    *,
    target_operation: TargetOperationObservation | None = None,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    condition_required: bool = True,
    condition_universe: ConditionUniverse | None = None,
) -> _NormalDraftCheck:
    """Validate normal-path scenario semantics; never artifact feasibility.

    Preserved causal families: adversary kind/gain rules, causal-handle
    closure, intention factor/choice handles, evidence-status discipline,
    temporal-reference closure, condition-reference closure and semantic
    proposition bounds.  Deliberately absent: stimulus/route coherence,
    delivery/factor-kind fit and executable unsafe-outcome conditions.

    A few unambiguous provider slips are corrected instead of rejected.  The
    corrections apply to a copy of ``value``, which is returned with one
    normalization per correction; ``value`` itself is left unchanged.
    """
    value = copy.deepcopy(value)
    normalizations: list[Stage5Normalization] = []
    adversary, outcome = _normal_adversary_and_outcome(value, observation_contract)
    criteria = tuple(
        ObservationCriterion.model_validate(item.model_dump(mode="json"))
        for item in outcome.observation_criteria
    )
    if observation_contract is not None:
        assessment = _assess_normal_observation(
            outcome,
            criteria,
            observation_contract,
            target_operation=target_operation,
            execution_target_profile=execution_target_profile,
            target_observations=target_observations,
            normalizations=normalizations,
        )
    _validate_observation_operation_names(
        criteria,
        getattr(outcome, "safe_observable_outcome", None),
        target_operation=target_operation,
        execution_target_profile=execution_target_profile,
    )
    _validate_normal_adversary_response(adversary, context, content_surface)
    _validate_attacker_bdi_cardinality(value.attacker_bdi, adversary)
    _normalize_provider_semantic_proposition(outcome, context)
    choices = _causal_source_choices(context)
    allowed_handles = {choice.handle for choice in choices}
    declared_handles = _declared_causal_handles(value.causal_factors)
    if not declared_handles <= allowed_handles:
        unknown = sorted(declared_handles - allowed_handles)
        raise ValueError(
            "causal factor source handles must name supplied context choices: "
            + ", ".join(unknown)
        )
    _validate_intention_factor_handles(
        value.attacker_bdi, value.causal_factors, normalizations=normalizations
    )
    _validate_intention_choice_handles(value.attacker_bdi, allowed_handles)
    _validate_factor_mechanisms(value.causal_factors, choices)
    _validate_context_provider_temporal_conditions(
        value.causal_factors, choices, context
    )
    _validate_context_condition_reference_closure(
        value.causal_factors, choices, context
    )
    condition_outcome = None
    if observation_contract is not None:
        safe_outcome = getattr(outcome, "safe_observable_outcome", None)
        # Last, so the correction for a draft that fails another check as well
        # names that check: a failed condition can still be dropped afterwards.
        condition_outcome = _validate_discriminating_condition(
            getattr(outcome, "discriminating_condition", None),
            assessment,
            condition_universe
            if condition_universe is not None
            else build_condition_universe(
                execution_target_profile=execution_target_profile,
                target_operation=target_operation,
                target_observations=target_observations,
            ),
            required=condition_required,
            named_operations=_named_operations(criteria, safe_outcome),
            claim=ConditionClaim(
                uca_type=context.ica.uca_type,
                unsafe_operation=(
                    target_operation.reference.operation_id
                    if target_operation is not None
                    else None
                ),
                safe_outcome=safe_outcome,
            ),
        )
    return _NormalDraftCheck(
        draft=value,
        normalizations=tuple(normalizations),
        condition_outcome=condition_outcome,
    )


@dataclass(frozen=True)
class _NormalDraftCheck:
    """A normal-path draft that passed validation, with its corrections."""

    draft: BaseModel
    normalizations: tuple[Stage5Normalization, ...]
    # Where a condition-less command attempt was moved; None when it was not.
    route: str | None = None
    # The check of the draft's condition; None when no condition was checked.
    condition_outcome: ConditionCheckOutcome | None = None


def _normal_adversary_and_outcome(
    value: BaseModel,
    observation_contract: ObservationContract | None,
) -> tuple[Any, _ContextSemanticOutcomeDraft]:
    """Return the draft's adversary and semantic outcome, or reject the draft."""
    adversary = getattr(value, "adversary", None)
    if not isinstance(
        adversary, (_ContextAdversarialDraft, _ContextFunctionalAdversaryDraft)
    ):
        raise ValueError("adversary is required in corrected Stage 5 output")
    outcome = getattr(value, "unsafe_outcome", None)
    if not isinstance(outcome, _ContextSemanticOutcomeDraft):
        raise ValueError(
            "unsafe_outcome with a semantic_proposition is required in the "
            "normal Stage 5 output"
        )
    if observation_contract is not None and not outcome.observation_criteria:
        raise ValueError("observation_criteria is required in normal Stage 5 output")
    return adversary, outcome


def _assess_normal_observation(
    outcome: _ContextSemanticOutcomeDraft,
    criteria: tuple[ObservationCriterion, ...],
    observation_contract: ObservationContract,
    *,
    target_operation: TargetOperationObservation | None,
    execution_target_profile: ExecutionTargetProfile | None,
    target_observations: TargetObservationSnapshot | None,
    normalizations: list[Stage5Normalization] | None,
) -> ObservationAssessment:
    """Assess the criteria and publish the validated safe outcome in place."""
    assessment = assess_observation_criteria(criteria, observation_contract)
    # The provider must explicitly explain an analytical-only outcome.  The
    # deterministic assessment remains authoritative for the final status.
    if assessment.disposition == "analytical_only" and not any(
        not item.observable for item in criteria
    ):
        raise ValueError(
            "non-observable Stage 5 outcomes must declare observable=false with "
            "an analytical reason"
        )
    safe_outcome = getattr(outcome, "safe_observable_outcome", None)
    validated_safe_outcome = _validate_safe_observable_outcome(
        safe_outcome,
        criteria,
        assessment,
        observation_contract,
        target_operation=target_operation,
        execution_target_profile=execution_target_profile,
        target_observations=target_observations,
        normalizations=normalizations,
    )
    if validated_safe_outcome is not safe_outcome:
        outcome.safe_observable_outcome = validated_safe_outcome
    return assessment


def _validate_safe_observable_outcome(
    outcome: SafeObservableOutcome | None,
    criteria: tuple[ObservationCriterion, ...],
    assessment: ObservationAssessment,
    observation_contract: ObservationContract,
    *,
    target_operation: TargetOperationObservation | None,
    execution_target_profile: ExecutionTargetProfile | None,
    target_observations: TargetObservationSnapshot | None,
    normalizations: list[Stage5Normalization] | None = None,
) -> SafeObservableOutcome:
    """Validate the safe outcome against the supplied Stage 5 evidence.

    Returns the outcome to publish.  The deterministic assessment is
    authoritative for observability, so an ``observable`` flag that
    contradicts it is coerced when exactly one executable boundary exists,
    and a record path written into ``record_refs`` is moved to
    ``fact_refs``.  Every such change is appended to ``normalizations``.
    """

    if outcome is None:
        raise ValueError("safe_observable_outcome is required in normal Stage 5 output")
    if assessment.disposition == "analytical_only":
        return _analytical_only_safe_outcome(outcome, normalizations)
    supported_ids = set(assessment.supported_criteria)
    if not outcome.observable:
        outcome = _reply_only_safe_outcome(
            outcome, criteria, supported_ids, normalizations
        )
    outcome = _only_supported_criterion_safe_outcome(
        outcome, criteria, supported_ids, normalizations
    )
    _require_supported_safe_evidence(
        outcome, criteria, supported_ids, observation_contract
    )
    _validate_observation_operation_names(
        (),
        outcome,
        target_operation=target_operation,
        execution_target_profile=execution_target_profile,
    )
    return _validate_safe_outcome_refs(outcome, target_observations, normalizations)


def _analytical_only_safe_outcome(
    outcome: SafeObservableOutcome,
    normalizations: list[Stage5Normalization] | None,
) -> SafeObservableOutcome:
    """Clear every executable boundary from an analytical-only safe outcome."""
    if not outcome.observable:
        return outcome
    return _replace_safe_outcome(
        outcome,
        {
            "observable": False,
            "claim_level": None,
            "evidence": None,
            "operation_name": None,
            "record_refs": (),
            "fact_refs": (),
        },
        reason="observable_contradicts_analytical_only_assessment",
        normalizations=normalizations,
    )


def _reply_only_safe_outcome(
    outcome: SafeObservableOutcome,
    criteria: tuple[ObservationCriterion, ...],
    supported_ids: set[str],
    normalizations: list[Stage5Normalization] | None,
) -> SafeObservableOutcome:
    """Coerce a non-observable safe outcome when only replies are supported."""
    supported = [c for c in criteria if c.criterion_id in supported_ids]
    if not supported or not all(
        criterion.claim_level == "reply" and criterion.evidence == "assistant_message"
        for criterion in supported
    ):
        raise ValidationIssueError(
            IssueCode.safe_outcome_observability_mismatch,
            "executable scenarios require observable=true on safe_observable_outcome",
        )
    return _replace_safe_outcome(
        outcome,
        {
            "observable": True,
            "claim_level": "reply",
            "evidence": "assistant_message",
            "operation_name": None,
        },
        reason="observable_false_with_only_reply_criteria_supported",
        normalizations=normalizations,
    )


def _only_supported_criterion_safe_outcome(
    outcome: SafeObservableOutcome,
    criteria: tuple[ObservationCriterion, ...],
    supported_ids: set[str],
    normalizations: list[Stage5Normalization] | None,
) -> SafeObservableOutcome:
    """Bind the safe outcome to the one supported criterion it disagrees with.

    With exactly one supported criterion, that criterion names the only
    boundary the scenario can observe, so a safe outcome written at another
    claim level or evidence kind is moved onto it.  With several supported
    criteria the model's choice stays authoritative and a mismatch is left to
    :func:`_require_supported_safe_evidence`.
    """
    supported = [c for c in criteria if c.criterion_id in supported_ids]
    if len(supported) != 1:
        return outcome
    [criterion] = supported
    if (outcome.claim_level, outcome.evidence) == (
        criterion.claim_level,
        criterion.evidence,
    ):
        return outcome
    return _replace_safe_outcome(
        outcome,
        {
            "claim_level": criterion.claim_level,
            "evidence": criterion.evidence,
            "operation_name": criterion.operation_name,
        },
        reason="safe_outcome_differs_from_only_supported_criterion",
        normalizations=normalizations,
    )


def _require_supported_safe_evidence(
    outcome: SafeObservableOutcome,
    criteria: tuple[ObservationCriterion, ...],
    supported_ids: set[str],
    observation_contract: ObservationContract,
) -> None:
    """Require a supported criterion and contract capture for the safe evidence."""
    matching = tuple(
        criterion
        for criterion in criteria
        if criterion.criterion_id in supported_ids
        and criterion.claim_level == outcome.claim_level
        and criterion.evidence == outcome.evidence
    )
    if not matching:
        raise ValidationIssueError(
            IssueCode.safe_outcome_observability_mismatch,
            "safe observable outcome claim level and evidence must match a "
            "supported observation criterion",
        )
    if not observation_contract.supports_evidence(outcome.evidence):
        raise ValidationIssueError(
            IssueCode.safe_outcome_observability_mismatch,
            "safe observable outcome evidence is not captured by the observation "
            "contract",
        )


def _validate_safe_outcome_refs(
    outcome: SafeObservableOutcome,
    target_observations: TargetObservationSnapshot | None,
    normalizations: list[Stage5Normalization] | None,
) -> SafeObservableOutcome:
    """Require supplied record and fact references, moving record paths to facts."""
    fact_values = target_observation_fact_values(target_observations)
    allowed_facts = set(fact_values)
    allowed_records = (
        {item.observation_ref for item in target_observations.observations}
        if target_observations is not None
        else set()
    )
    if outcome.record_refs:
        outcome = _move_record_paths_to_fact_refs(
            outcome, allowed_records, allowed_facts, normalizations
        )
        unknown_records = sorted(set(outcome.record_refs) - allowed_records)
        if unknown_records:
            raise ValidationIssueError(
                IssueCode.safe_outcome_record_ref_not_supplied,
                "safe observable outcome record_refs must name supplied records: "
                + ", ".join(unknown_records),
            )
    if outcome.fact_refs:
        unknown_facts = sorted(set(outcome.fact_refs) - allowed_facts)
        if unknown_facts:
            raise ExactIssueError(
                IssueCode.safe_outcome_fact_ref_not_supplied,
                "safe observable outcome fact_refs must name supplied facts: "
                + ", ".join(unknown_facts)
                + "".join(
                    "\n- "
                    + _nearest_supplied_parent(path, fact_values, allowed_records)
                    for path in unknown_facts
                ),
            )
    return outcome


def _nearest_supplied_parent(
    path: str, fact_values: Mapping[str, object], records: set[str]
) -> str:
    """Name the longest supplied path that *path* extends, with its JSON type."""
    parts = path.split(".")
    for end in range(len(parts) - 1, 0, -1):
        parent = ".".join(parts[:end])
        if parent in fact_values:
            kind = _json_type(fact_values[parent])
        elif parent in records:
            kind = "record"
        else:
            continue
        return (
            f"`{path}` is not supplied; the nearest supplied path is "
            f"`{parent}` ({kind})"
        )
    return f"`{path}` is not supplied; no supplied path contains it"


# bool before number: a JSON boolean is a Python int.
_JSON_TYPES: tuple[tuple[type | tuple[type, ...], str], ...] = (
    (Mapping, "object"),
    ((list, tuple), "array"),
    (bool, "boolean"),
    ((int, float), "number"),
    (str, "string"),
    (type(None), "null"),
)


def _json_type(value: object) -> str:
    """Return the JSON type name of an observed fact value."""
    return next(
        (name for kinds, name in _JSON_TYPES if isinstance(value, kinds)),
        # condition_check marks a path observed twice with different values.
        "ambiguous",
    )


def _move_record_paths_to_fact_refs(
    outcome: SafeObservableOutcome,
    allowed_records: set[str],
    allowed_facts: set[str],
    normalizations: list[Stage5Normalization] | None,
) -> SafeObservableOutcome:
    """Replace supplied record or collection paths with their observation ref.

    Only a path that is itself a supplied fact under a supplied observation
    ref is moved; anything else is left for the caller to reject.
    """

    record_refs: list[str] = []
    fact_refs = list(outcome.fact_refs)
    moved: list[tuple[str, str]] = []
    for ref in outcome.record_refs:
        head = ref.split(".", 1)[0]
        if (
            ref not in allowed_records
            and head in allowed_records
            and ref in allowed_facts
        ):
            moved.append((ref, head))
            if ref not in fact_refs:
                fact_refs.append(ref)
            ref = head
        if ref not in record_refs:
            record_refs.append(ref)
    if not moved:
        return outcome
    normalized = SafeObservableOutcome.model_validate(
        {
            **outcome.model_dump(mode="python"),
            "record_refs": tuple(record_refs),
            "fact_refs": tuple(fact_refs),
        }
    )
    if normalizations is not None:
        normalizations.extend(
            Stage5Normalization(
                field="safe_observable_outcome.record_refs",
                original=path,
                normalized=observation_ref,
                reason="record_path_moved_to_fact_refs",
            )
            for path, observation_ref in moved
        )
    return normalized


def _replace_safe_outcome(
    outcome: SafeObservableOutcome,
    updates: Mapping[str, object],
    *,
    reason: str,
    normalizations: list[Stage5Normalization] | None,
) -> SafeObservableOutcome:
    """Rebuild the safe outcome with ``updates`` and record each changed field."""

    original = outcome.model_dump(mode="json")
    normalized = SafeObservableOutcome.model_validate(
        {**outcome.model_dump(mode="python"), **updates}
    )
    if normalizations is not None:
        changed = normalized.model_dump(mode="json")
        normalizations.extend(
            Stage5Normalization(
                field=f"safe_observable_outcome.{name}",
                original=original[name],
                normalized=changed[name],
                reason=reason,
            )
            for name in SafeObservableOutcome.model_fields
            if original[name] != changed[name]
        )
    return normalized


def _validate_discriminating_condition(
    condition: DiscriminatingCondition | None,
    assessment: ObservationAssessment,
    universe: ConditionUniverse,
    *,
    required: bool = True,
    named_operations: frozenset[str] = frozenset(),
    claim: ConditionClaim | None = None,
) -> ConditionCheckOutcome | None:
    """Require a resolvable, record-consistent condition for executable scenarios.

    A failure here is a result-validator failure, so the existing Stage 5
    validation retry delivers the exact message as the one correction call.
    A condition on an analytical-only or ungrounded scenario is not an error:
    materialization discards it and records why. ``claim`` holds the
    scenario fields the condition must agree with. Returns the passing check,
    or ``None`` when no condition was checked.
    """

    if assessment.disposition == "analytical_only" or not universe.grounded:
        return None
    if condition is None:
        _require_condition(required)
        return None
    outcome = check_discriminating_condition(condition, universe)
    message = condition_failure_message(outcome)
    if message is not None:
        code = IssueCode.discriminating_condition_check_failed
        raise ExactIssueError(code, message.removeprefix(f"{code.value}: "))
    _raise_condition_findings(
        outcome.condition or condition,
        universe,
        named_operations=named_operations,
        claim=claim,
    )
    return outcome


def _require_condition(required: bool) -> None:
    """Reject a missing condition unless the caller allows one."""

    if required:
        raise ValidationIssueError(
            IssueCode.discriminating_condition_missing,
            "executable scenarios require a discriminating_condition when "
            "target operations or observations are supplied. Change only "
            "discriminating_condition; keep observation_criteria and "
            "safe_observable_outcome unchanged.",
        )


def _raise_condition_findings(
    condition: DiscriminatingCondition,
    universe: ConditionUniverse,
    *,
    named_operations: frozenset[str],
    claim: ConditionClaim | None,
) -> None:
    """Reject a checked condition that cannot separate unsafe from safe calls."""

    findings = condition_findings(
        condition, universe, named_operations=named_operations
    )
    if claim is not None:
        findings += condition_claim_findings(
            condition,
            universe.fact_values,
            uca_type=claim.uca_type,
            unsafe_operation=claim.unsafe_operation,
            safe_outcome=claim.safe_outcome,
        )
    if findings:
        raise ExactIssueError(
            IssueCode(findings[0].code), condition_findings_message(findings)
        )


def _named_operations(
    criteria: Sequence[ObservationCriterion],
    safe_outcome: SafeObservableOutcome | None,
) -> frozenset[str]:
    """Return the operations the criteria and the safe outcome name."""

    named = {item.operation_name for item in (*criteria, safe_outcome) if item}
    return frozenset(name for name in named if name)


def _validate_observation_operation_names(
    criteria: Sequence[ObservationCriterion],
    safe_outcome: SafeObservableOutcome | None,
    *,
    target_operation: TargetOperationObservation | None,
    execution_target_profile: ExecutionTargetProfile | None,
) -> None:
    """Require exact operation identities for command-attempt observations."""

    allowed_operations = set(
        _stage5_observed_operation_names(
            execution_target_profile,
            target_operation=target_operation,
        )
    )
    for criterion in criteria:
        if criterion.observable:
            _require_exact_operation_name(
                criterion,
                allowed_operations,
                "observable observation criterion with claim_level "
                "command_attempt must name an exact operation from the supplied "
                "inventory or be reassessed as analytical_only",
                "observation criterion operation_name must name an exact "
                "operation from the supplied inventory",
            )
    if safe_outcome is not None and safe_outcome.observable:
        _require_exact_operation_name(
            safe_outcome,
            allowed_operations,
            "observable safe outcome with claim_level command_attempt must name "
            "an exact operation from the supplied inventory or be reassessed "
            "as analytical_only",
            "safe observable outcome operation_name must name an exact "
            "operation from the supplied inventory",
        )


def _require_exact_operation_name(
    observation: ObservationCriterion | SafeObservableOutcome,
    allowed_operations: set[str],
    missing_message: str,
    unknown_message: str,
) -> None:
    name = observation.operation_name
    if observation.claim_level == "command_attempt" and name is None:
        raise ValidationIssueError(
            IssueCode.observation_command_attempt_operation_missing, missing_message
        )
    if name is not None and name not in allowed_operations:
        raise ValidationIssueError(
            IssueCode.observation_operation_not_in_inventory, unknown_message
        )


def _stage5_observed_operation_names(
    execution_target_profile: ExecutionTargetProfile | None,
    *,
    target_operation: TargetOperationObservation | None = None,
) -> tuple[str, ...]:
    """Return exact operation IDs available to the Stage 5 observation contract."""

    if execution_target_profile is not None:
        return tuple(
            operation.operation_id
            for resource in execution_target_profile.resources
            for operation in resource.operations
        )
    if target_operation is not None:
        return (target_operation.operation_id,)
    return ()


def _validate_attacker_bdi_cardinality(
    attacker_bdi: _ContextAttackerBDIDraft,
    adversary: BaseModel,
) -> None:
    """Require BDI only for an adversary and none for a functional test."""
    if adversary.kind is AdversaryKind.none:
        if attacker_bdi.beliefs or attacker_bdi.desires or attacker_bdi.intentions:
            raise ValueError(
                "functional scenarios with adversary kind 'none' must use "
                "empty attacker_bdi"
            )
        return
    if not attacker_bdi.desires:
        raise ValueError(
            "adversarial scenarios require a non-empty attacker desires list"
        )
    if not attacker_bdi.intentions:
        raise ValueError(
            "adversarial scenarios require a non-empty attacker_bdi.intentions list"
        )


def _validate_normal_adversary_response(
    adversary: BaseModel,
    context: ScenarioGenerationContext,
    content_surface: ContentSurfaceFacts | None,
) -> None:
    """Normal-path adversary checks without stimulus/delivery semantics.

    ``third_party_via_content`` still requires the typed capability-profile
    content-surface facts, and a gain never restates a governing constraint;
    no delivery claim exists to check.
    """
    if adversary.kind is AdversaryKind.third_party_via_content:
        if content_surface is None or not content_surface.has_content_surface:
            raise ValidationIssueError(
                IssueCode.no_content_surface,
                "the capability profile records no retrieval or tool-content "
                "surface a third party could reach",
            )
    if adversary.kind is AdversaryKind.none:
        return
    _validate_adversary_gain(adversary, context)


def _validate_context_condition_reference_closure(
    factor_drafts: Sequence[BaseModel],
    choices: Sequence[_CausalSourceChoice],
    context: ScenarioGenerationContext,
) -> None:
    """Keep every structural temporal reference in the exported closure.

    Stage 6 exports declared causal-factor sources and the selected action.
    The provider prompt may explain a larger path slice, but an undeclared
    sibling process-model identity cannot become a condition reference after
    Stage 5 succeeds.
    """
    choices_by_handle = {choice.handle: choice for choice in choices}
    declared_refs = {
        choices_by_handle[factor.source_handle].source_id for factor in factor_drafts
    }
    declared_refs.add(context.target_control_path.control_action.action_id)
    for factor in factor_drafts:
        _validate_one_context_condition_reference(
            factor.temporal_condition,
            declared_refs,
            owner=f"causal factor {factor.source_handle}",
        )


def _validate_one_context_condition_reference(
    condition: object,
    declared_refs: set[str],
    *,
    owner: str,
) -> None:
    """Validate one condition's structural subject/reference identity."""
    if condition is None:
        return
    for field_name in ("reference_ref", "subject_ref"):
        reference = getattr(condition, field_name, None)
        if reference is None or reference in declared_refs:
            continue
        raise ValueError(
            f"{owner} {field_name} {reference!r} must name the target action "
            "or a declared causal-factor source"
        )


def _normalize_provider_semantic_proposition(
    unsafe_outcome: BaseModel,
    context: ScenarioGenerationContext,
) -> str | None:
    """Validate provider prose after resolving explained structural IDs.

    Structural IDs are useful in the prompt and compiler trace, but they are
    not part of the plain sentence passed to a downstream semantic judge.  A
    known ID is rendered with its exact context description; an unknown ID is
    intentionally left for the normal validator to reject, so this helper
    never invents a paraphrase or silently drops an unsupported reference.
    """
    proposition = getattr(unsafe_outcome, "semantic_proposition", None)
    if proposition is None:
        return None
    descriptions = _context_prose_reference_descriptions(context)
    normalized = _render_explained_prose_ids(proposition, descriptions)
    try:
        normalized = normalize_semantic_proposition(normalized, required=True)
    except ValueError as exc:
        raise ValidationIssueError(
            IssueCode.missing_unsafe_proposition, str(exc)
        ) from exc
    if normalized != proposition:
        setattr(unsafe_outcome, "semantic_proposition", normalized)
    return normalized


def _context_prose_reference_descriptions(
    context: ScenarioGenerationContext,
) -> dict[str, str]:
    """Return only exact IDs with an explained description in this context."""
    path = context.target_control_path
    references: dict[str, str] = {
        path.controller.element_id: path.controller.description,
        path.control_action.action_id: path.control_action.description,
    }
    references.update(
        (item.element_id, item.description) for item in path.process_model_parts
    )
    references.update((item.element_id, item.description) for item in path.feedback)
    references.update(
        (item.action_id, item.description) for item in (path.related_control_actions)
    )
    if path.responsibility is not None:
        references[path.responsibility.element_id] = path.responsibility.description
    if path.controlled_process is not None:
        references[path.controlled_process.element_id] = (
            path.controlled_process.description
        )
    if path.coordination_path is not None:
        references.update(_coordination_reference_descriptions(path.coordination_path))
    references.update((item.loss_id, item.description) for item in context.losses)
    references.update((item.hazard_id, item.description) for item in context.hazards)
    references.update(
        (item.constraint_id, item.description) for item in context.constraints
    )
    return references


def _coordination_reference_descriptions(coordination) -> dict[str, str]:
    references = {
        coordination.link_id: coordination.description,
        coordination.source.element_id: coordination.source.description,
        coordination.target.element_id: coordination.target.description,
        coordination.shared_pm.element_id: coordination.shared_pm.description,
        coordination.coordination_mechanism.element_id: (
            coordination.coordination_mechanism.description
        ),
    }
    references.update(
        (item.element_id, item.description)
        for item in coordination.controlled_processes
    )
    return references


def _render_explained_prose_ids(
    proposition: str,
    descriptions: Mapping[str, str],
) -> str:
    """Replace only explained bookkeeping IDs with their exact descriptions."""
    rendered = proposition
    for match in tuple(_PROSE_STRUCTURAL_REFERENCE.finditer(proposition)):
        reference = match.group(0)
        description = descriptions.get(reference)
        if description is None:
            continue
        rendered = re.sub(
            rf"\s*\(\s*{re.escape(reference)}\s*\)",
            "",
            rendered,
        )
        rendered = re.sub(
            rf"(?<![A-Za-z0-9._-]){re.escape(reference)}(?![A-Za-z0-9._-])",
            description,
            rendered,
        )
    return rendered


def _validate_context_provider_temporal_conditions(
    factor_drafts: Sequence[BaseModel],
    choices: Sequence[_CausalSourceChoice],
    context: ScenarioGenerationContext,
) -> None:
    """Resolve every local temporal reference before provider success."""
    factor_order = {
        factor.source_handle: index
        for index, factor in enumerate(factor_drafts, start=1)
    }
    for factor in factor_drafts:
        resolved = _resolve_temporal_condition(
            factor.temporal_condition,
            factor.source_handle,
            choices,
            context,
            factor_order=factor_order,
            binding_scope=f"factor-{factor_order[factor.source_handle]}",
        )
        # The value accepted here is the value materialization must use.
        # Keeping the canonical condition on the draft prevents a later
        # publication seam from parsing a subtly different value.
        setattr(factor, "temporal_condition", resolved)


def _validate_intention_choice_handles(
    attacker_draft: BaseModel,
    allowed_handles: set[str],
) -> None:
    """Reject intentions that cite a request-local handle not offered in context."""
    unknown = sorted(
        {
            handle
            for intention in attacker_draft.intentions
            for handle in intention.source_handles
            if handle not in allowed_handles
        }
    )
    if unknown:
        raise ValueError(
            "intention source handles must name supplied context choices: "
            + ", ".join(unknown)
        )


def _validate_factor_mechanisms(
    factor_drafts: Sequence[BaseModel],
    choices: Sequence[_CausalSourceChoice],
) -> None:
    """Require each factor's mechanism to fit its selected source."""
    by_handle = {choice.handle: choice for choice in choices}
    for factor in factor_drafts:
        mechanism = getattr(factor, "mechanism", CausalMechanism.none)
        choice = by_handle.get(factor.source_handle)
        if choice is None:
            continue
        try:
            validate_mechanism_pairing(
                CausalMechanism(mechanism), choice.kind, choice.source_kind
            )
        except ValueError as exc:
            raise ValidationIssueError(
                IssueCode.mechanism_source_mismatch, f"{factor.source_handle}: {exc}"
            ) from exc


def _validate_intention_factor_handles(
    attacker_draft: BaseModel,
    factor_drafts: list[BaseModel],
    *,
    normalizations: list[Stage5Normalization] | None = None,
) -> None:
    """Require every intention to rest on at least one declared causal factor.

    An intention that also cites undeclared handles keeps only its declared
    ones, so its materialized trace names only declared structural sources.
    An intention with no declared handle is rejected.
    """
    declared = {item.source_handle for item in factor_drafts}
    missing = sorted(
        {
            handle
            for intention in attacker_draft.intentions
            if not any(handle in declared for handle in intention.source_handles)
            for handle in intention.source_handles
        }
    )
    if missing:
        raise ValidationIssueError(
            IssueCode.intention_handle_undeclared,
            "intention source handles must have declared causal factors: "
            + ", ".join(missing),
        )
    for index, intention in enumerate(attacker_draft.intentions):
        _prune_undeclared_handles(index, intention, declared, normalizations)


def _prune_undeclared_handles(
    index: int,
    intention: BaseModel,
    declared: set[str],
    normalizations: list[Stage5Normalization] | None,
) -> None:
    handles = intention.source_handles
    kept = [handle for handle in handles if handle in declared]
    if len(kept) == len(handles):
        return
    intention.source_handles = type(handles)(kept)
    if normalizations is not None:
        normalizations.append(
            Stage5Normalization(
                field=f"attacker_bdi.intentions[{index}].source_handles",
                original=list(handles),
                normalized=kept,
                reason="undeclared_intention_handles_pruned",
            )
        )

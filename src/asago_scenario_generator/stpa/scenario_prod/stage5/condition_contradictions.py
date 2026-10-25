"""Refuse a tool-call condition that contradicts its own scenario.

The bound tool-call condition is what the consumer runs, so a contradiction
that only binding makes visible (a record selection resolved to a literal) is
checked on the bound form. Each rule reads typed data only: the scenario's
control-action category and claims, the input schemas of the target profile,
and the observed target state and reads. Where that data is silent the case
is reported undecidable, never refused.

- (a) Kind fits the category. An ``INCORRECT`` action is provided, so its
  unsafe behavior is a call; ``not_called`` on the action's own operation is
  refused (:mod:`.condition_claims`). On an action that maps to no operation
  (a coordination mechanism, or an action no operation realizes),
  ``not_called`` on the operation the command-attempt claim names is
  undecidable in every category: that call may be the downstream safe action
  whose absence is the failure, or the wrongly provided call itself, and only
  the prose says which.
- (b) Operands of one kind. A call argument compared with a literal (from a
  literal, a fact, or a record selection) is refused when the literal has a
  JSON type the argument's schema does not declare (membership in a list
  argument tests its elements, so it is not typed), or when every value the
  supplied reads passed for that argument is provably a different kind of
  value than the literal (the ID-prefix, key-domain, and field rule of
  :func:`~..condition_check.kind_mismatch`). An identifier literal compared
  with an argument no read passed and whose schema declares only a string is
  undecidable: nothing typed says which records the argument names.
- (c) Ordering needs numbers. ``tool-call-condition-v1`` orders only
  numbers, so ``gt``, ``ge``, ``lt``, or ``le`` is refused when a literal is
  not a number or an argument's schema declares no numeric type, and is
  undecidable when an argument's schema declares no type.

A refusal is a Stage 5 validation failure, corrected through the existing
correction request; undecidable cases are reported only.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from asago_scenario_generator.stpa.discriminating_condition import (
    MEMBERSHIP_OPERATORS,
    ORDERED_OPERATORS,
    ArgumentOperand,
    DiscriminatingCondition,
    NotCalledComparison,
    ObservedRecordSelection,
    ValueComparison,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.observation_contract import SafeObservableOutcome
from asago_scenario_generator.stpa.tool_call_condition import (
    ToolCallArgumentOperand,
    ToolCallCondition,
    ToolCallLiteralOperand,
    ToolCallNotCalledComparison,
    ToolCallValueComparison,
)

from ..condition_check import ConditionFinding, ConditionUniverse, kind_mismatch
from ..condition_index import StateIndex, collection_path, id_prefix
from ..tool_call_binding import bind_tool_call_condition, numeric_value
from .condition_claims import ConditionClaim, condition_claim_findings
from .issues import IssueCode

Rule = Literal["a", "b", "c"]

_NUMERIC_TYPES = frozenset({"number", "integer"})
_NEVER_HOLDS = (
    "the comparison holds on no call and the condition never detects the unsafe call"
)
_ALWAYS_HOLDS = (
    "the comparison holds on every call and the condition fires on the safe "
    "call as well"
)
_WHERE_NEVER_MATCHES = (
    "the where item matches no call, so not_called holds on every call, "
    "including the safe one"
)


@dataclass(frozen=True)
class RuleFinding:
    """One refused or undecidable comparison and the rule that judged it.

    ``code`` is the Stage 5 issue code of a refusal, ``None`` when undecidable.
    """

    rule: Rule
    detail: str
    code: str | None = None


@dataclass(frozen=True)
class ConditionContradictions:
    """The refusals and the undecidable cases of one condition, in rule order."""

    refused: tuple[RuleFinding, ...] = ()
    undecidable: tuple[RuleFinding, ...] = ()


@dataclass(frozen=True)
class _Equality:
    """A call argument tested for equality with literal values."""

    label: str
    subject: str
    argument: ToolCallArgumentOperand
    values: tuple[object, ...]
    op_word: str
    consequence: str


def tool_call_condition_findings(
    condition: DiscriminatingCondition, universe: ConditionUniverse
) -> tuple[ConditionFinding, ...]:
    """Return the rule (b) and (c) refusals of the condition's binding."""

    return tuple(
        ConditionFinding(item.code, item.detail)
        for item in _bound_contradictions(condition, universe).refused
        if item.code is not None
    )


def assess_condition(
    condition: DiscriminatingCondition,
    universe: ConditionUniverse,
    *,
    claim: ConditionClaim,
    bound: ToolCallCondition | None = None,
) -> ConditionContradictions:
    """Judge one condition under every rule; ``bound`` defaults to its binding."""

    inverted = tuple(
        RuleFinding("a", item.detail, item.code)
        for item in condition_claim_findings(
            condition,
            universe.fact_values,
            uca_type=claim.uca_type,
            unsafe_operation=claim.unsafe_operation,
            safe_outcome=claim.safe_outcome,
        )
        if item.code == IssueCode.discriminating_condition_polarity_inverted
    )
    bound_result = _bound_contradictions(condition, universe, bound)
    return ConditionContradictions(
        refused=(*inverted, *bound_result.refused),
        undecidable=(
            *_unmapped_not_called(condition, claim),
            *bound_result.undecidable,
        ),
    )


def assess_handoff(
    handoff: Mapping[str, Any],
    universe: ConditionUniverse,
    *,
    control_action_operation: str | None,
) -> ConditionContradictions | None:
    """Judge a published handoff's tool-call condition against its own fields.

    ``universe`` is built from the target profile and observations the
    handoff was generated against; ``control_action_operation`` is the
    operation its target realization selected for the control action.
    Returns ``None`` when the handoff publishes no bound condition.
    """

    raw_condition = handoff.get("discriminating_condition")
    raw_bound = handoff.get("tool_call_condition")
    if not raw_condition or not raw_bound:
        return None
    raw_safe = handoff.get("safe_observable_outcome")
    uca_type = _handoff_uca_type(handoff)
    condition = DiscriminatingCondition.model_validate(raw_condition)
    bound = ToolCallCondition.model_validate(raw_bound)
    if uca_type is None:
        return _bound_contradictions(condition, universe, bound)
    claim = ConditionClaim(
        uca_type=uca_type,
        unsafe_operation=control_action_operation,
        safe_outcome=(
            SafeObservableOutcome.model_validate(raw_safe) if raw_safe else None
        ),
    )
    return assess_condition(condition, universe, claim=claim, bound=bound)


def _handoff_uca_type(handoff: Mapping[str, Any]) -> UCAType | None:
    """Return the category the slot ID ``<controller>:<action>:<type>`` ends in."""

    slot = (handoff.get("lineage") or {}).get("ica_slot_id") or ""
    try:
        return UCAType(slot.rsplit(":", 1)[-1])
    except ValueError:
        return None


def _unmapped_not_called(
    condition: DiscriminatingCondition, claim: ConditionClaim
) -> tuple[RuleFinding, ...]:
    """Report rule (a) as undecidable where only the claim names the operation."""

    outcome = claim.safe_outcome
    if (
        claim.unsafe_operation is not None
        or outcome is None
        or not outcome.observable
        or outcome.claim_level != "command_attempt"
        or outcome.operation_name is None
    ):
        return ()
    operation = outcome.operation_name
    return tuple(
        RuleFinding(
            "a",
            f"comparisons[{index}] is not_called {operation} under a control "
            f"action of category {claim.uca_type.value} that maps to no "
            "operation: "
            f"the typed fields do not say whether a call of {operation} is that "
            "action or a downstream effect of it, so whether not_called fits "
            "the category is unknown",
        )
        for index, comparison in enumerate(condition.comparisons)
        if isinstance(comparison, NotCalledComparison)
        and comparison.operation == operation
    )


def _bound_contradictions(
    condition: DiscriminatingCondition,
    universe: ConditionUniverse,
    bound: ToolCallCondition | None = None,
) -> ConditionContradictions:
    """Apply rules (b) and (c) to every comparison of the bound condition."""

    if bound is None:
        bound = bind_tool_call_condition(condition, universe.fact_values).condition
    if bound is None:
        return ConditionContradictions()
    labels, where_labels = _bound_labels(condition, bound)
    state = StateIndex.from_fact_values(universe.fact_values)
    results: list[tuple[RuleFinding | None, RuleFinding | None]] = []
    for index, comparison in enumerate(bound.comparisons):
        if isinstance(comparison, ToolCallValueComparison):
            if comparison.op in ORDERED_OPERATORS:
                results.append(_ordering(labels[index], comparison, universe))
            else:
                equality = _value_equality(labels[index], comparison)
                if equality is not None:
                    results.append(_kinds(equality, universe, state))
        elif isinstance(comparison, ToolCallNotCalledComparison):
            for position, item in enumerate(comparison.where):
                equality = _Equality(
                    label=where_labels.get(
                        (index, position),
                        f"tool_call_condition.comparisons[{index}].where[{position}]",
                    ),
                    subject=(
                        f"the where item {comparison.operation}.{item.argument} = "
                        f"{_render(item.value)}"
                    ),
                    argument=ToolCallArgumentOperand(
                        source="argument",
                        operation=comparison.operation,
                        argument=item.argument,
                    ),
                    values=(item.value,),
                    op_word="a where item",
                    consequence=_WHERE_NEVER_MATCHES,
                )
                results.append(_kinds(equality, universe, state))
    return ConditionContradictions(
        refused=tuple(refusal for refusal, _ in results if refusal is not None),
        undecidable=tuple(case for _, case in results if case is not None),
    )


def _bound_labels(
    condition: DiscriminatingCondition, bound: ToolCallCondition
) -> tuple[list[str], dict[tuple[int, int], str]]:
    """Name the part of the authored condition each bound comparison comes from.

    Binding keeps the call-level comparisons in order, then appends one
    ``eq`` per selected argument, or a ``where`` item on every ``not_called``
    of that argument's operation. A layout that does not match falls back to
    the bound condition's own paths.
    """

    labels = [
        f"comparisons[{index}]"
        for index, comparison in enumerate(condition.comparisons)
        if not isinstance(comparison, ValueComparison)
        or any(
            isinstance(side, ArgumentOperand)
            for side in (comparison.left, comparison.right)
        )
    ]
    selection = condition.record_selection
    items = (
        selection.argument_values
        if isinstance(selection, ObservedRecordSelection)
        else []
    )
    not_called = {
        index: comparison.operation
        for index, comparison in enumerate(bound.comparisons)
        if isinstance(comparison, ToolCallNotCalledComparison)
    }
    where_labels: dict[tuple[int, int], str] = {}
    counts = dict.fromkeys(not_called, 0)
    for position, item in enumerate(items):
        label = f"record_selection.argument_values[{position}]"
        targets = [
            index for index, name in not_called.items() if name == item.operation
        ]
        for index in targets:
            where_labels[(index, counts[index])] = label
            counts[index] += 1
        if not targets:
            labels.append(label)
    if len(labels) != len(bound.comparisons):
        labels = [
            f"tool_call_condition.comparisons[{index}]"
            for index in range(len(bound.comparisons))
        ]
    return labels, where_labels


def _value_equality(
    label: str, comparison: ToolCallValueComparison
) -> _Equality | None:
    """Return an argument-versus-literal equality, or ``None`` for any other shape."""

    sides = (comparison.left, comparison.right)
    arguments = [side for side in sides if isinstance(side, ToolCallArgumentOperand)]
    literals = [side for side in sides if isinstance(side, ToolCallLiteralOperand)]
    if len(arguments) != 1 or len(literals) != 1:
        return None
    value = literals[0].value
    if comparison.op in MEMBERSHIP_OPERATORS:
        if not isinstance(value, list):
            return None
        values = tuple(value)
    else:
        values = (value,)
    return _Equality(
        label=label,
        subject=_comparison_text(comparison),
        argument=arguments[0],
        values=values,
        op_word=comparison.op,
        consequence=_NEVER_HOLDS if comparison.op in {"eq", "in"} else _ALWAYS_HOLDS,
    )


def _kinds(
    equality: _Equality, universe: ConditionUniverse, state: StateIndex
) -> tuple[RuleFinding | None, RuleFinding | None]:
    """Apply rule (b) to one equality: declared types, then observed record kinds."""

    argument = equality.argument
    types = universe.argument_types.get(argument.operation, {}).get(
        argument.argument, frozenset()
    )
    candidates = [value for value in equality.values if value is not None]
    # Membership tests each element of a list argument, whose type is unknown.
    elements = equality.op_word in MEMBERSHIP_OPERATORS and "array" in types
    if (
        types
        and candidates
        and not elements
        and not any(_fits(value, types) for value in candidates)
    ):
        return _type_refusal(equality, types, candidates), None
    identifiers = [
        value
        for value in equality.values
        if isinstance(value, str) and id_prefix(value) is not None
    ]
    if not identifiers or len(identifiers) != len(equality.values):
        return None, None
    observed = universe.observed_arguments.get(argument.argument, frozenset())
    if observed:
        if all(
            kind_mismatch(state, seen, value)
            for seen in observed
            for value in identifiers
        ):
            return _kind_refusal(equality, observed, identifiers, state), None
        return None, None
    if types and "string" not in types:
        return None, None
    if any(
        state.key_collections(value) or state.field_labels(value)
        for value in identifiers
    ):
        return None, _kind_unknown(equality, types, identifiers, state)
    return None, None


def _type_refusal(
    equality: _Equality, types: frozenset[str], values: list[object]
) -> RuleFinding:
    argument = equality.argument
    declared = " or ".join(sorted(types))
    found = " or ".join(sorted({_json_type(value) for value in values}))
    literal = (
        f"the values in {_render(list(equality.values))} are {found}"
        if equality.op_word in MEMBERSHIP_OPERATORS
        else f"{_render(equality.values[0])} is {_article(found)} {found}"
    )
    return RuleFinding(
        "b",
        f"{equality.label} binds {equality.subject} in the tool-call condition, "
        f"but the input schema of {argument.operation} declares "
        f"{argument.argument} as {declared} and {literal}; "
        "tool-call-condition-v1 never converts a value for "
        f"{equality.op_word}, so {equality.consequence}. Compare "
        f"{argument.argument} with a supplied value of type {declared}",
        IssueCode.discriminating_condition_record_kind_mismatch,
    )


def _kind_refusal(
    equality: _Equality,
    observed: frozenset[str],
    identifiers: list[str],
    state: StateIndex,
) -> RuleFinding:
    name = equality.argument.argument
    collections = sorted(
        {collection for seen in observed for collection in state.key_collections(seen)}
    )
    if collections:
        paths = " or ".join(collection_path(item) for item in collections)
        kind = f"keys of {paths}"
        advice = (
            f"such as a key of {paths}; in record_selection.argument_values, "
            "map it to the selected record's path or to a field whose values "
            "are those keys"
        )
    else:
        labels = sorted(
            {label for seen in observed for label in state.field_labels(seen)}
        )
        kind = f"values of {', '.join(labels)}" if labels else "observed values"
        advice = "such as a value supplied reads passed for it"
    literals = "; ".join(
        f"{_render(value)} is {state.describe_domain(value)}"
        for value in dict.fromkeys(identifiers)
    )
    seen = ", ".join(_render(value) for value in sorted(observed))
    return RuleFinding(
        "b",
        f"{equality.label} binds {equality.subject} in the tool-call condition, "
        f"but the values supplied reads passed for {name} ({seen}) are {kind}, "
        f"and {literals}: a different kind of value, so {equality.consequence}. "
        f"Compare {name} only with a value of the kind it takes, {advice}",
        IssueCode.discriminating_condition_record_kind_mismatch,
    )


def _kind_unknown(
    equality: _Equality,
    types: frozenset[str],
    identifiers: list[str],
    state: StateIndex,
) -> RuleFinding:
    argument = equality.argument
    literals = "; ".join(
        f"{_render(value)} is {state.describe_domain(value)}"
        for value in dict.fromkeys(identifiers)
    )
    declared = (
        f"declares it only as {' or '.join(sorted(types))}"
        if types
        else "declares no type for it"
    )
    return RuleFinding(
        "b",
        f"{equality.label} binds {equality.subject}: {literals}, but no supplied "
        f"read passed a value for {argument.argument} and the input schema of "
        f"{argument.operation} {declared}, so the kind of value "
        f"{argument.argument} takes is unknown",
    )


def _ordering(
    label: str, comparison: ToolCallValueComparison, universe: ConditionUniverse
) -> tuple[RuleFinding | None, RuleFinding | None]:
    """Apply rule (c): every side of an ordering must be a number under v1."""

    declared: dict[str, list[tuple[str, frozenset[str]]]] = {}
    literals: list[str] = []
    untyped: list[ToolCallArgumentOperand] = []
    for side in (comparison.left, comparison.right):
        if isinstance(side, ToolCallLiteralOperand):
            if numeric_value(side.value) is None:
                literals.append(f"the literal {_render(side.value)} is not a number")
            continue
        types = universe.argument_types.get(side.operation, {}).get(
            side.argument, frozenset()
        )
        if not types:
            untyped.append(side)
        elif not types & _NUMERIC_TYPES:
            declared.setdefault(side.operation, []).append((side.argument, types))
    reasons = [
        _declared_reason(operation, items) for operation, items in declared.items()
    ]
    reasons += literals
    call = _comparison_text(comparison)
    if reasons:
        return (
            RuleFinding(
                "c",
                f"{label} binds {call} in the tool-call condition, but "
                "tool-call-condition-v1 orders only numbers: "
                f"{'; '.join(reasons)}, so the comparison is unknown on every "
                "call and never detects the unsafe call. Compare numbers, or "
                "state the rule with eq, ne, in, or not_in on supplied values; "
                "the contract cannot order dates or other text",
                IssueCode.discriminating_condition_ordering_not_numeric,
            ),
            None,
        )
    if untyped:
        side = untyped[0]
        return None, RuleFinding(
            "c",
            f"{label} binds {call}: the input schema of {side.operation} "
            f"declares no type for {side.argument}, so whether it is a number "
            "under tool-call-condition-v1 is unknown",
        )
    return None, None


def _declared_reason(operation: str, items: list[tuple[str, frozenset[str]]]) -> str:
    named = " and ".join(
        f"{argument} as {' or '.join(sorted(types))}" for argument, types in items
    )
    reason = f"the input schema of {operation} declares {named}"
    if any("string" in types for _, types in items):
        reason += ", and a string is a number only when its whole text is one"
    return reason


def _fits(value: object, types: frozenset[str]) -> bool:
    """Return whether a JSON value has one of the declared JSON types."""

    if isinstance(value, bool):
        return "boolean" in types
    if isinstance(value, int):
        return bool(types & _NUMERIC_TYPES)
    if isinstance(value, float):
        return "number" in types or (value.is_integer() and "integer" in types)
    return _json_type(value) in types


def _json_type(value: object) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, Mapping):
        return "object"
    return "null"


def _article(word: str) -> str:
    return "an" if word[:1] in "aeiou" else "a"


def _comparison_text(comparison: ToolCallValueComparison) -> str:
    return (
        f"{_operand_text(comparison.left)} {comparison.op} "
        f"{_operand_text(comparison.right)}"
    )


def _operand_text(operand: object) -> str:
    if isinstance(operand, ToolCallArgumentOperand):
        return f"{operand.operation}.{operand.argument}"
    assert isinstance(operand, ToolCallLiteralOperand)
    return _render(operand.value)


def _render(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


__all__ = [
    "ConditionContradictions",
    "RuleFinding",
    "assess_condition",
    "assess_handoff",
    "tool_call_condition_findings",
]

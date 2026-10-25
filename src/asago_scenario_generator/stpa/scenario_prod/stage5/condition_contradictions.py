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
  literal, a fact, or a record selection) is refused only when the input
  schema of the argument's own operation proves the literal is never equal to
  a value it admits: the literal has a JSON type that schema does not admit
  (membership in a list argument tests its elements, so it is not typed). A
  kind mismatch that only values, names, or descriptions suggest is
  undecidable: an identifier literal of another kind than the values reads of
  that operation passed, or than the values reads of another operation passed
  for an argument of the same name, or an identifier literal compared with
  an argument no read passed and whose schema admits a string. Two compared
  arguments are judged each by the schema of its own operation: ``eq`` or
  ``ne`` is refused when the two admit no common JSON type, and is otherwise
  undecidable, as is membership of one argument in another's list.
- (c) Ordering needs numbers. ``tool-call-condition-v1`` orders only
  numbers, converting a string that ``float()`` accepts. ``gt``, ``ge``,
  ``lt``, or ``le`` is refused when a literal is not a number under that
  conversion, or when the input schema of an argument's own operation admits
  no number and no numeric string: no numeric type and no string, an
  ``enum`` or ``const`` of non-numbers, or a string ``pattern`` that no
  number matches. A side is clean only when its schema admits numbers alone:
  a numeric type without ``null``, or an ``enum`` or ``const`` of numbers or
  numeric strings. Any other side is undecidable: a string, a nullable
  number, or an untyped argument; a ``format`` only annotates, so it proves
  nothing.

A refusal is a Stage 5 validation failure, corrected through the existing
correction request. Undecidable cases are reported only: in the run's
candidate diagnostics and by the offline sweep, never in the scenario.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
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
_REGEX_SPECIAL = frozenset("\\^$.|?*+()[]{}")
# The first characters of a text ``float()`` accepts, besides digits and spaces.
_NUMBER_STARTS = frozenset("+-.iInN")
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


def undecidable_diagnostics(
    condition: DiscriminatingCondition | None,
    bound: ToolCallCondition | None,
    universe: ConditionUniverse,
    *,
    claim: ConditionClaim,
) -> tuple[str, ...]:
    """Return a run diagnostic for each undecidable case of a published condition."""

    if condition is None or bound is None:
        return ()
    result = assess_condition(condition, universe, claim=claim, bound=bound)
    return tuple(
        f"tool-call condition undecidable under rule ({item.rule}): {item.detail}"
        for item in result.undecidable
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
                else:
                    pair = _argument_pair(labels[index], comparison, universe)
                    if pair is not None:
                        results.append(pair)
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
    """Apply rule (b) to one equality: the declared type, then observed values."""

    argument = equality.argument
    types = _schema_types(_argument_schema(universe, argument))
    candidates = [value for value in equality.values if value is not None]
    # Membership tests each element of a list argument, whose type is unknown.
    elements = equality.op_word in MEMBERSHIP_OPERATORS and (
        types is None or "array" in types
    )
    if (
        types is not None
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
    if types is not None and "string" not in types:
        return None, None
    own = universe.read_arguments.get(argument.operation, {}).get(
        argument.argument, frozenset()
    )
    observed = own or universe.observed_arguments.get(argument.argument, frozenset())
    if observed:
        if all(
            kind_mismatch(state, seen, value)
            for seen in observed
            for value in identifiers
        ):
            return None, _kind_suggested(
                equality, types, observed, identifiers, state, universe, own=bool(own)
            )
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


def _kind_suggested(
    equality: _Equality,
    types: frozenset[str] | None,
    observed: frozenset[str],
    identifiers: list[str],
    state: StateIndex,
    universe: ConditionUniverse,
    *,
    own: bool,
) -> RuleFinding:
    """Report a kind mismatch that only observed values suggest."""

    argument = equality.argument
    name = argument.argument
    seen = ", ".join(_render(value) for value in sorted(observed))
    if own:
        source = f"the values reads of {argument.operation} passed for {name} ({seen})"
        limit = (
            f"a value a read passed does not prove which values "
            f"{argument.operation} accepts for {name}"
        )
    else:
        others = sorted(
            operation
            for operation, arguments in universe.read_arguments.items()
            if operation != argument.operation and name in arguments
        )
        named = f" ({', '.join(others)})" if others else ""
        source = (
            f"the values reads of another operation{named} passed for an "
            f"argument named {name} ({seen})"
        )
        limit = (
            "values passed to another operation prove nothing about "
            f"{argument.operation}.{name}"
        )
    return RuleFinding(
        "b",
        f"{equality.label} binds {equality.subject}: {source} are "
        f"{_observed_kind(observed, state)}, and {_domains(identifiers, state)}, "
        f"but {limit} and the input schema of {argument.operation} "
        f"{_declared_text(types)}, so whether {name} can take that value is "
        "unknown",
    )


def _observed_kind(observed: frozenset[str], state: StateIndex) -> str:
    collections = sorted(
        {collection for seen in observed for collection in state.key_collections(seen)}
    )
    if collections:
        return f"keys of {' or '.join(collection_path(item) for item in collections)}"
    labels = sorted({label for seen in observed for label in state.field_labels(seen)})
    return f"values of {', '.join(labels)}" if labels else "observed values"


def _domains(identifiers: list[str], state: StateIndex) -> str:
    return "; ".join(
        f"{_render(value)} is {state.describe_domain(value)}"
        for value in dict.fromkeys(identifiers)
    )


def _declared_text(types: frozenset[str] | None) -> str:
    if types is None:
        return "declares no type for it"
    return f"declares it only as {' or '.join(sorted(types))}"


def _kind_unknown(
    equality: _Equality,
    types: frozenset[str] | None,
    identifiers: list[str],
    state: StateIndex,
) -> RuleFinding:
    argument = equality.argument
    return RuleFinding(
        "b",
        f"{equality.label} binds {equality.subject}: "
        f"{_domains(identifiers, state)}, but no supplied read passed a value "
        f"for {argument.argument} and the input schema of {argument.operation} "
        f"{_declared_text(types)}, so the kind of value {argument.argument} "
        "takes is unknown",
    )


def _ordering(
    label: str, comparison: ToolCallValueComparison, universe: ConditionUniverse
) -> tuple[RuleFinding | None, RuleFinding | None]:
    """Apply rule (c): every side of an ordering must be a number under v1."""

    reasons: list[str] = []
    open_sides: dict[str, list[tuple[str, object]]] = {}
    for side in (comparison.left, comparison.right):
        if isinstance(side, ToolCallLiteralOperand):
            if numeric_value(side.value) is None:
                reasons.append(f"the literal {_render(side.value)} is not a number")
            continue
        schema = _argument_schema(universe, side)
        facts = _number_facts(schema, side.argument)
        if facts.proof == "not_number":
            reasons.append(
                f"the input schema of {side.operation} {facts.reason}, so no value "
                "it admits is a number"
            )
        elif facts.proof == "open":
            open_sides.setdefault(side.operation, []).append((side.argument, schema))
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
    if open_sides:
        return None, _ordering_open(label, call, open_sides)
    return None, None


def _ordering_open(
    label: str, call: str, open_sides: Mapping[str, list[tuple[str, object]]]
) -> RuleFinding:
    """Report an ordering whose argument schemas prove neither way."""

    declared = "; ".join(
        f"the input schema of {operation} declares "
        + " and ".join(_open_text(argument, schema) for argument, schema in items)
        for operation, items in open_sides.items()
    )
    sides = [
        _schema_types(schema) for items in open_sides.values() for _, schema in items
    ]
    text = any(types is None or "string" in types for types in sides)
    others = sorted(
        {
            name
            for types in sides
            if types is not None and "string" not in types
            for name in types - _NUMERIC_TYPES
        }
    )
    clauses = []
    if text or not others:
        clauses.append(
            "tool-call-condition-v1 orders a string only when float() accepts its "
            "whole text; nothing typed says whether the values passed are such text"
        )
    if others:
        clauses.append(
            f"tool-call-condition-v1 never orders {' or '.join(others)}; nothing "
            "typed says whether the values passed are numbers"
        )
    return RuleFinding(
        "c",
        f"{label} binds {call}: {declared}, and {'; and '.join(clauses)}, so "
        "whether the comparison can hold is unknown",
    )


def _open_text(argument: str, schema: object) -> str:
    types = _schema_types(schema)
    if not types:
        return f"no type for {argument}"
    text = f"{argument} as {' or '.join(sorted(types))}"
    text_format = schema.get("format") if isinstance(schema, Mapping) else None
    if isinstance(text_format, str):
        text += f" of format {text_format}, which JSON Schema only annotates"
    return text


def _argument_pair(
    label: str, comparison: ToolCallValueComparison, universe: ConditionUniverse
) -> tuple[RuleFinding | None, RuleFinding | None] | None:
    """Apply rule (b) to two compared arguments, each by its own operation's schema.

    Returns ``None`` when a side is not an argument. ``eq`` and ``ne`` are
    refused only when the two schemas admit no common JSON type, so no value
    of one ever equals a value of the other; anything else is undecidable,
    since no schema says that two arguments take the same kind of record.
    """

    left, right = comparison.left, comparison.right
    if not isinstance(left, ToolCallArgumentOperand) or not isinstance(
        right, ToolCallArgumentOperand
    ):
        return None
    call = _comparison_text(comparison)
    left_name = _operand_text(left)
    right_name = _operand_text(right)
    if comparison.op in MEMBERSHIP_OPERATORS:
        return None, RuleFinding(
            "b",
            f"{label} binds {call}: tool-call-condition-v1 tests whether a value "
            f"of {left_name} is a member of the list {right_name} passes, and "
            "the check compares no element types of a list argument, so whether "
            f"{left_name} can be a member is unknown",
        )
    left_types = _schema_types(_argument_schema(universe, left))
    right_types = _schema_types(_argument_schema(universe, right))
    declared = f"{_declares(left, left_types)} and {_declares(right, right_types)}"
    if left_types is None or right_types is None:
        return None, RuleFinding(
            "b",
            f"{label} binds {call}: {declared}, so whether the two arguments "
            "can take equal values is unknown",
        )
    common = _equality_classes(left_types) & _equality_classes(right_types)
    if not common:
        consequence = _NEVER_HOLDS if comparison.op == "eq" else _ALWAYS_HOLDS
        return (
            RuleFinding(
                "b",
                f"{label} binds {call} in the tool-call condition, but "
                f"{declared}; tool-call-condition-v1 never converts a value for "
                f"{comparison.op}, so no value of one equals a value of the "
                f"other and {consequence}. Compare {left.argument} with an "
                "argument or a supplied value of type "
                f"{' or '.join(sorted(left_types))}",
                IssueCode.discriminating_condition_record_kind_mismatch,
            ),
            None,
        )
    return None, RuleFinding(
        "b",
        f"{label} binds {call}: {declared}, so both admit "
        f"{' or '.join(sorted(common))}, but nothing typed says whether the two "
        "arguments take the same kind of value, so whether the comparison "
        "separates the unsafe call is unknown",
    )


def _declares(argument: ToolCallArgumentOperand, types: frozenset[str] | None) -> str:
    if types is None:
        return (
            f"the input schema of {argument.operation} declares no type for "
            f"{argument.argument}"
        )
    return (
        f"the input schema of {argument.operation} declares {argument.argument} "
        f"as {' or '.join(sorted(types))}"
    )


def _equality_classes(types: frozenset[str]) -> frozenset[str]:
    """Return the JSON types v1 equality tells apart: an integer equals a number."""

    return frozenset("number" if name == "integer" else name for name in types)


def _argument_schema(
    universe: ConditionUniverse, argument: ToolCallArgumentOperand
) -> Mapping[str, Any] | None:
    """Return the input-schema property of the argument's own operation."""

    return universe.argument_schemas.get(argument.operation, {}).get(argument.argument)


def _schema_types(schema: object) -> frozenset[str] | None:
    """Return every JSON type a schema admits, or ``None`` when that is unknown.

    ``type`` bounds the schema; without it, every ``anyOf`` (or ``oneOf``)
    branch must bound its own, or an ``enum`` or ``const`` gives the types of
    its values.
    """

    if not isinstance(schema, Mapping):
        return None
    declared = _type_names(schema.get("type"))
    if declared:
        return frozenset(declared)
    branches = schema.get("anyOf") or schema.get("oneOf")
    if isinstance(branches, list) and branches:
        types = [_schema_types(branch) for branch in branches]
        if any(item is None for item in types):
            return None
        return frozenset().union(*(item for item in types if item is not None))
    values = _enumerated(schema)
    if values is not None:
        return frozenset(_json_type(value) for value in values)
    return None


@dataclass(frozen=True)
class _NumberFacts:
    """What a schema proves about its values under the v1 number conversion.

    ``proof`` is ``number`` when every value it admits is a number,
    ``not_number`` when none is (``reason`` then says how), and ``open``
    otherwise.
    """

    proof: Literal["number", "not_number", "open"]
    reason: str = ""


_OPEN = _NumberFacts("open")


def _number_facts(schema: object, name: str) -> _NumberFacts:
    """Prove that every value a schema admits is a number under v1, or that none is.

    ``enum`` or ``const``, ``type`` with ``pattern``, and the ``anyOf`` or
    ``oneOf`` branches each constrain every value, so one that proves no
    number decides, then one that proves only numbers. ``null`` is not a
    number, so a nullable numeric type proves neither; ``format`` is only an
    annotation, so it proves nothing.
    """

    if not isinstance(schema, Mapping):
        return _OPEN
    facts = (
        _enumerated_facts(schema, name),
        _type_facts(schema, name),
        _branch_facts(schema, name),
    )
    for proof in ("not_number", "number"):
        for item in facts:
            if item.proof == proof:
                return item
    return _OPEN


def _enumerated_facts(schema: Mapping[str, Any], name: str) -> _NumberFacts:
    values = _enumerated(schema)
    if values is None:
        return _OPEN
    numbers = [numeric_value(value) is not None for value in values]
    if all(numbers):
        return _NumberFacts("number")
    if not any(numbers):
        return _NumberFacts(
            "not_number", f"restricts {name} to {_render(list(values))}"
        )
    return _OPEN


def _type_facts(schema: Mapping[str, Any], name: str) -> _NumberFacts:
    declared = set(_type_names(schema.get("type")))
    if not declared:
        return _OPEN
    if declared <= _NUMERIC_TYPES:
        return _NumberFacts("number")
    if declared & _NUMERIC_TYPES:
        return _OPEN
    types = " or ".join(sorted(declared))
    if "string" not in declared:
        return _NumberFacts("not_number", f"declares {name} as {types}")
    pattern = schema.get("pattern")
    if _pattern_excludes_numbers(pattern):
        return _NumberFacts(
            "not_number", f"declares {name} as {types} matching the pattern {pattern}"
        )
    return _OPEN


def _branch_facts(schema: Mapping[str, Any], name: str) -> _NumberFacts:
    branches = schema.get("anyOf") or schema.get("oneOf")
    if not isinstance(branches, list) or not branches:
        return _OPEN
    facts = [_number_facts(branch, name) for branch in branches]
    if all(item.proof == "number" for item in facts):
        return _NumberFacts("number")
    if all(item.proof == "not_number" for item in facts):
        return _NumberFacts("not_number", " or ".join(item.reason for item in facts))
    return _OPEN


def _pattern_excludes_numbers(pattern: object) -> bool:
    """Return whether an anchored pattern's first character starts no number.

    Only a pattern without alternation that starts ``^`` and then a plain,
    required character is judged; ``float()`` text starts with a space, a
    digit, a sign, a point, or the ``inf`` or ``nan`` of either case.
    """

    if not isinstance(pattern, str) or len(pattern) < 2 or "|" in pattern:
        return False
    first = pattern[1]
    if pattern[0] != "^" or first in _REGEX_SPECIAL or first in _NUMBER_STARTS:
        return False
    if first.isspace() or first.isdecimal():
        return False
    return pattern[2:3] not in {"?", "*", "{"}


def _enumerated(schema: Mapping[str, Any]) -> Sequence[object] | None:
    if "const" in schema:
        return (schema["const"],)
    values = schema.get("enum")
    return values if isinstance(values, list) and values else None


def _type_names(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


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
    "undecidable_diagnostics",
]

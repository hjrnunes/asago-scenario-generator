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
  a value it admits: the literal has no JSON type that schema admits, or is
  none of the values its ``enum`` and ``const`` allow. Membership compares
  each element: a list argument on the left by its ``items``, and the list on
  the right by its own; a right side that is never a list (a literal, or an
  argument whose schema admits no array) makes ``in`` and ``not_in`` unknown
  on every call, so it is refused. A kind mismatch that only values, names,
  or descriptions suggest is undecidable: an identifier literal of another
  kind than the values reads of that operation passed, or than the values
  reads of another operation passed for an argument of the same name, or an
  identifier literal compared with an argument no read passed and whose
  schema admits a string. Two compared arguments are judged each by the
  schema of its own operation, by the same facts: refused when the compared
  values share no JSON type or no listed value, and otherwise undecidable.
- (c) Ordering needs numbers. ``tool-call-condition-v1`` orders only
  numbers, converting a string that ``float()`` accepts, and every
  comparison with NaN is false. ``gt``, ``ge``, ``lt``, or ``le`` is
  refused when a side is not a number under that conversion, or is NaN on
  every call: a literal, or an argument whose schema admits no number and no
  numeric string (no numeric type and no string, an ``enum`` or ``const`` of
  non-numbers, or a string ``pattern`` that no number matches), or admits
  only NaN text. A side is clean only when its schema admits numbers alone:
  a numeric type without ``null``, or an ``enum`` or ``const`` of numbers or
  numeric strings. Any other side is undecidable: a string, a nullable
  number, or an untyped argument; a ``format`` only annotates, so it proves
  nothing.

Each schema fact is read from every keyword that asserts it: ``type`` (with
OpenAPI ``nullable``), ``enum`` and ``const``, ``pattern``, ``items`` and
``prefixItems``, and each of ``allOf``, ``anyOf``, and ``oneOf`` as its own
conjunct. A keyword the check does not read (``not``, ``$ref``, an unknown
type name) proves nothing.

A refusal is a Stage 5 validation failure, corrected through the existing
correction request. Undecidable cases are reported only: in the run's
candidate diagnostics and by the offline sweep, never in the scenario.
"""

from __future__ import annotations

import json
import math
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
_JSON_TYPES = frozenset(
    {"array", "boolean", "integer", "null", "number", "object", "string"}
)
_COMBINATORS = ("allOf", "anyOf", "oneOf")
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
_NEVER_KNOWN = (
    "the comparison is unknown on every call and never detects the unsafe call"
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
    """A call argument tested for equality with literal values.

    ``role`` says what of the argument is compared: its value (``value``),
    its value or, for a list, each element (``member``, the left side of
    ``in``), or the elements of the list it must be (``list``, the right side
    of ``in``). ``literal`` is the literal as the condition states it.
    """

    label: str
    subject: str
    argument: ToolCallArgumentOperand
    values: tuple[object, ...]
    op_word: str
    consequence: str
    role: Literal["value", "member", "list"] = "value"
    literal: object = None


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
                if isinstance(equality, RuleFinding):
                    results.append((equality, None))
                elif equality is not None:
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
                    literal=item.value,
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
) -> _Equality | RuleFinding | None:
    """Return an argument-versus-literal equality, or ``None`` for any other shape.

    A literal on the right of ``in`` or ``not_in`` that is not a list makes
    the comparison unknown on every call, so it is refused here.
    """

    left, right = comparison.left, comparison.right
    if isinstance(left, ToolCallArgumentOperand) and isinstance(
        right, ToolCallLiteralOperand
    ):
        argument, literal = left, right.value
    elif isinstance(left, ToolCallLiteralOperand) and isinstance(
        right, ToolCallArgumentOperand
    ):
        argument, literal = right, left.value
    else:
        return None
    subject = _comparison_text(comparison)
    role: Literal["value", "member", "list"] = "value"
    values: tuple[object, ...] = (literal,)
    if comparison.op in MEMBERSHIP_OPERATORS:
        if argument is left:
            if not isinstance(literal, list):
                return RuleFinding(
                    "b",
                    f"{label} binds {subject} in the tool-call condition, but the "
                    f"right side {_render(literal)} is not a list, and "
                    f"tool-call-condition-v1 gives unknown for {comparison.op} "
                    f"when the right side is not a list, so {_NEVER_KNOWN}. "
                    f"Compare {argument.argument} with a list of supplied values",
                    IssueCode.discriminating_condition_record_kind_mismatch,
                )
            role = "member"
            values = tuple(literal)
        else:
            role = "list"
            values = tuple(literal) if isinstance(literal, list) else (literal,)
    return _Equality(
        label=label,
        subject=subject,
        argument=argument,
        values=values,
        op_word=comparison.op,
        consequence=_NEVER_HOLDS if comparison.op in {"eq", "in"} else _ALWAYS_HOLDS,
        role=role,
        literal=literal,
    )


def _kinds(
    equality: _Equality, universe: ConditionUniverse, state: StateIndex
) -> tuple[RuleFinding | None, RuleFinding | None]:
    """Apply rule (b) to one equality: the declared schema, then observed values."""

    argument = equality.argument
    admitted = _argument_facts(universe, argument)
    if (
        equality.role == "list"
        and admitted.types is not None
        and "array" not in admitted.types
    ):
        return (
            _never_a_list(
                equality.label, equality.subject, equality.op_word, argument, admitted
            ),
            None,
        )
    view = _compared(admitted, equality.role)
    candidates = list(equality.values)
    if (
        view.types is not None
        and candidates
        and not any(_fits(value, view.types) for value in candidates)
    ):
        return _type_refusal(equality, admitted, view.types, candidates), None
    if (
        view.values is not None
        and candidates
        and not _common_values(tuple(candidates), view.values)
    ):
        return _value_refusal(equality, view.values), None
    types = view.types
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
    equality: _Equality,
    admitted: _Admitted,
    types: frozenset[str],
    values: list[object],
) -> RuleFinding:
    argument = equality.argument
    found = " or ".join(sorted({_json_type(value) for value in values}))
    listed = equality.role != "value" and isinstance(equality.literal, list)
    literal = (
        f"the values in {_render(equality.literal)} are {found}"
        if listed
        else f"{_render(values[0])} is {_article(found)} {found}"
    )
    elements = equality.role == "list" or (
        equality.role == "member"
        and admitted.types is not None
        and "array" in admitted.types
    )
    if elements:
        declared = _list_text(admitted)
        advice = (
            f"Compare {argument.argument} with supplied values of type "
            f"{' or '.join(sorted(types))}"
        )
    else:
        declared = " or ".join(sorted(types))
        advice = f"Compare {argument.argument} with a supplied value of type {declared}"
    return RuleFinding(
        "b",
        f"{equality.label} binds {equality.subject} in the tool-call condition, "
        f"but the input schema of {argument.operation} declares "
        f"{argument.argument} as {declared} and {literal}; "
        "tool-call-condition-v1 never converts a value for "
        f"{equality.op_word}, so {equality.consequence}. {advice}",
        IssueCode.discriminating_condition_record_kind_mismatch,
    )


def _value_refusal(equality: _Equality, admitted: tuple[object, ...]) -> RuleFinding:
    argument = equality.argument
    listed = equality.role != "value" and isinstance(equality.literal, list)
    literal = (
        f"no value in {_render(equality.literal)} is one of them"
        if listed
        else f"{_render(equality.values[0])} is none of them"
    )
    restricted = (
        f"the elements of {argument.argument}"
        if equality.role == "list"
        else argument.argument
    )
    return RuleFinding(
        "b",
        f"{equality.label} binds {equality.subject} in the tool-call condition, "
        f"but the input schema of {argument.operation} restricts {restricted} to "
        f"{_render(list(admitted))} and {literal}; tool-call-condition-v1 never "
        f"converts a value for {equality.op_word}, so {equality.consequence}. "
        f"Compare {argument.argument} with one of those values",
        IssueCode.discriminating_condition_record_kind_mismatch,
    )


def _never_a_list(
    label: str,
    subject: str,
    op: str,
    argument: ToolCallArgumentOperand,
    admitted: _Admitted,
) -> RuleFinding:
    """Refuse membership in an argument whose schema admits no list."""

    types = admitted.types or frozenset()
    return RuleFinding(
        "b",
        f"{label} binds {subject} in the tool-call condition, but the input "
        f"schema of {argument.operation} declares {argument.argument} as "
        f"{' or '.join(sorted(types))}, never a list, and tool-call-condition-v1 "
        f"gives unknown for {op} when the right side is not a list, so "
        f"{_NEVER_KNOWN}. Test membership in a list argument or in a list of "
        "supplied values",
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
    """Apply rule (c): every side of an ordering must be a number under v1.

    A side that is NaN on every call makes the comparison false on every
    call, since v1 makes every comparison with NaN false.
    """

    reasons: list[str] = []
    nan_reasons: list[str] = []
    open_sides: dict[str, list[tuple[str, object]]] = {}
    for side in (comparison.left, comparison.right):
        if isinstance(side, ToolCallLiteralOperand):
            number = numeric_value(side.value)
            if number is None:
                reasons.append(f"the literal {_render(side.value)} is not a number")
            elif math.isnan(number):
                nan_reasons.append(f"the literal {_render(side.value)} converts to NaN")
            continue
        schema = _argument_schema(universe, side)
        facts = _admitted(schema, side.argument).number
        if facts.proof == "not_number":
            reasons.append(
                f"the input schema of {side.operation} {facts.reason}, so no value "
                "it admits is a number"
            )
        elif facts.proof == "nan":
            nan_reasons.append(
                f"the input schema of {side.operation} {facts.reason}, so every "
                "value it admits converts to NaN"
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
                f"{'; '.join(reasons)}, so {_NEVER_KNOWN}. Compare numbers, or "
                "state the rule with eq, ne, in, or not_in on supplied values; "
                "the contract cannot order dates or other text",
                IssueCode.discriminating_condition_ordering_not_numeric,
            ),
            None,
        )
    if nan_reasons:
        return (
            RuleFinding(
                "c",
                f"{label} binds {call} in the tool-call condition, but "
                f"{'; '.join(nan_reasons)}, and tool-call-condition-v1 makes every "
                "comparison with NaN false, so the comparison holds on no call "
                "and never detects the unsafe call. Compare numbers, or state "
                "the rule with eq, ne, in, or not_in on supplied values",
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

    Returns ``None`` when a side is not an argument. ``eq`` and ``ne`` compare
    the two values; ``in`` and ``not_in`` compare the left value (or each of
    its elements) with the elements of the right list, and are refused when
    the right schema admits no list. The comparison is refused when the
    compared values share no JSON type, or no listed value; anything else is
    undecidable, since no schema says that two arguments take the same kind
    of record.
    """

    left, right = comparison.left, comparison.right
    if not isinstance(left, ToolCallArgumentOperand) or not isinstance(
        right, ToolCallArgumentOperand
    ):
        return None
    call = _comparison_text(comparison)
    op = comparison.op
    membership = op in MEMBERSHIP_OPERATORS
    left_admitted = _argument_facts(universe, left)
    right_admitted = _argument_facts(universe, right)
    if (
        membership
        and right_admitted.types is not None
        and "array" not in right_admitted.types
    ):
        return _never_a_list(label, call, op, right, right_admitted), None
    left_view = _compared(left_admitted, "member" if membership else "value")
    right_view = _compared(right_admitted, "list" if membership else "value")
    consequence = _NEVER_HOLDS if op in {"eq", "in"} else _ALWAYS_HOLDS
    declared = (
        f"{_declares(left, left_admitted, membership)} and "
        f"{_declares(right, right_admitted, membership)}"
    )
    if left_view.types is None or right_view.types is None:
        question = (
            f"whether a value of {_operand_text(left)} can be a member of "
            f"{_operand_text(right)}"
            if membership
            else "whether the two arguments can take equal values"
        )
        return None, RuleFinding(
            "b", f"{label} binds {call}: {declared}, so {question} is unknown"
        )
    common = _equality_classes(left_view.types) & _equality_classes(right_view.types)
    if not common:
        compared = (
            f"no value of {_operand_text(left)} equals an element of "
            f"{_operand_text(right)}"
            if membership
            else "no value of one equals a value of the other"
        )
        return (
            RuleFinding(
                "b",
                f"{label} binds {call} in the tool-call condition, but "
                f"{declared}; tool-call-condition-v1 never converts a value for "
                f"{op}, so {compared} and {consequence}. Compare "
                f"{left.argument} with an argument or a supplied value of type "
                f"{' or '.join(sorted(left_view.types))}",
                IssueCode.discriminating_condition_record_kind_mismatch,
            ),
            None,
        )
    if (
        left_view.values is not None
        and right_view.values is not None
        and not _common_values(left_view.values, right_view.values)
    ):
        restricted = (
            f"the input schema of {left.operation} restricts {left.argument} to "
            f"{_render(list(left_view.values))} and the input schema of "
            f"{right.operation} restricts "
            f"{'the elements of ' if membership else ''}{right.argument} to "
            f"{_render(list(right_view.values))}"
        )
        return (
            RuleFinding(
                "b",
                f"{label} binds {call} in the tool-call condition, but "
                f"{restricted}; tool-call-condition-v1 never converts a value for "
                f"{op}, so no listed value of one equals a listed value of the "
                f"other and {consequence}. Compare {left.argument} with an "
                "argument or a supplied value it can take",
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


def _declares(
    argument: ToolCallArgumentOperand, admitted: _Admitted, membership: bool = False
) -> str:
    if admitted.types is None:
        return (
            f"the input schema of {argument.operation} declares no type for "
            f"{argument.argument}"
        )
    declared = (
        _list_text(admitted) if membership else " or ".join(sorted(admitted.types))
    )
    return (
        f"the input schema of {argument.operation} declares {argument.argument} "
        f"as {declared}"
    )


def _list_text(admitted: _Admitted) -> str:
    """Name the admitted types, with the element types of an admitted list."""

    types = admitted.types or frozenset()
    names = sorted(types - {"array"})
    if "array" in types:
        elements = admitted.elements
        names.append(
            f"array of {' or '.join(sorted(elements))}" if elements else "array"
        )
    return " or ".join(names)


def _equality_classes(types: frozenset[str]) -> frozenset[str]:
    """Return the JSON types v1 equality tells apart: an integer equals a number."""

    return frozenset("number" if name == "integer" else name for name in types)


def _argument_schema(
    universe: ConditionUniverse, argument: ToolCallArgumentOperand
) -> Mapping[str, Any] | None:
    """Return the input-schema property of the argument's own operation."""

    return universe.argument_schemas.get(argument.operation, {}).get(argument.argument)


def _argument_facts(
    universe: ConditionUniverse, argument: ToolCallArgumentOperand
) -> _Admitted:
    return _admitted(_argument_schema(universe, argument), argument.argument)


def _schema_types(schema: object) -> frozenset[str] | None:
    """Return every JSON type a schema admits, or ``None`` when that is unknown."""

    return _admitted(schema, "").types


@dataclass(frozen=True)
class _NumberFacts:
    """What a schema proves about its values under the v1 number conversion.

    ``proof`` is ``number`` when every value it admits is a number, ``nan``
    when every value converts to NaN, ``not_number`` when none is a number
    (``reason`` then says how, as it does for ``nan``), and ``open``
    otherwise.
    """

    proof: Literal["number", "nan", "not_number", "open"]
    reason: str = ""


_OPEN = _NumberFacts("open")
_NUMBER = _NumberFacts("number")


@dataclass(frozen=True)
class _Admitted:
    """What a schema proves about the values it admits.

    Every field over-approximates the admitted values: ``types`` is every
    JSON type a value may have, ``values`` every value it may take when an
    ``enum`` or ``const`` lists them, and ``elements`` every JSON type an
    element of an admitted list may have; ``None`` means unknown.
    ``text_pattern`` is a ``pattern`` no admitted string with a number's text
    matches, and ``number`` is what the v1 number conversion makes of every
    admitted value. An empty
    ``types``, ``values``, or ``elements`` is reported as ``None``: a schema
    that admits nothing proves nothing about a call.
    """

    types: frozenset[str] | None = None
    values: tuple[object, ...] | None = None
    elements: frozenset[str] | None = None
    number: _NumberFacts = _OPEN
    text_pattern: str | None = None


_ANY = _Admitted()


def _admitted(schema: object, name: str) -> _Admitted:
    """Combine every assertion of a schema into what it admits.

    The schema's own ``type``, ``enum`` and ``const``, ``items`` and
    ``prefixItems``, and each of ``allOf``, ``anyOf``, and ``oneOf`` are
    conjuncts, so the facts intersect; ``allOf`` intersects its branches and
    ``anyOf`` and ``oneOf`` join theirs. A fact that proves no number decides
    over one that proves only numbers. ``null`` is not a number, ``format``
    only annotates, and an unknown keyword proves nothing, so each leaves the
    facts open. ``name`` is the argument named in a reason.
    """

    if not isinstance(schema, Mapping):
        return _ANY
    parts = [_own_facts(schema)]
    for key in _COMBINATORS:
        branches = schema.get(key)
        if isinstance(branches, list) and branches:
            facts = [_admitted(branch, name) for branch in branches]
            parts.append(_all_of(facts) if key == "allOf" else _any_of(facts))
    combined = _all_of(parts)
    types, values, elements = combined.types, combined.values, combined.elements
    numbers = [combined.number]
    if values is not None:
        if types is not None:
            values = tuple(value for value in values if _fits(value, types))
        types = _meet(types, frozenset(_json_type(value) for value in values))
        listed = [value for value in values if isinstance(value, list)]
        elements = _meet(
            elements, frozenset(_json_type(item) for value in listed for item in value)
        )
        numbers.append(_values_number(values, name))
    # The types and the pattern that every conjunct leaves decide together.
    numbers.append(_type_number(types, combined.text_pattern, name))
    return _published(
        _Admitted(types, values, elements, _conjoined(numbers), combined.text_pattern)
    )


def _published(facts: _Admitted) -> _Admitted:
    return _Admitted(
        types=facts.types or None,
        values=facts.values or None,
        elements=facts.elements or None,
        number=facts.number,
        text_pattern=facts.text_pattern,
    )


def _own_facts(schema: Mapping[str, Any]) -> _Admitted:
    """Return the facts of a schema's own keywords, before its combinators."""

    pattern = schema.get("pattern")
    return _Admitted(
        types=_declared_types(schema),
        values=_enumerated(schema),
        elements=_item_types(schema),
        text_pattern=pattern if _pattern_excludes_numbers(pattern) else None,
    )


def _all_of(parts: Sequence[_Admitted]) -> _Admitted:
    """Intersect facts that all hold of one value."""

    types: frozenset[str] | None = None
    values: tuple[object, ...] | None = None
    elements: frozenset[str] | None = None
    pattern = next((part.text_pattern for part in parts if part.text_pattern), None)
    for part in parts:
        types = _meet(types, part.types)
        elements = _meet(elements, part.elements)
        if part.values is not None:
            values = (
                part.values if values is None else _common_values(values, part.values)
            )
    number = _conjoined([part.number for part in parts])
    return _Admitted(types, values, elements, number, pattern)


def _any_of(parts: Sequence[_Admitted]) -> _Admitted:
    """Join facts of which at least one holds of a value."""

    types = (
        None
        if any(part.types is None for part in parts)
        else frozenset().union(*(part.types or () for part in parts))
    )
    values = (
        None
        if any(part.values is None for part in parts)
        else tuple(value for part in parts for value in part.values or ())
    )
    lists = [part for part in parts if part.types is None or "array" in part.types]
    elements = (
        None
        if any(part.elements is None for part in lists)
        else frozenset().union(*(part.elements or () for part in lists))
    )
    texts = [part for part in parts if part.types is None or "string" in part.types]
    pattern = (
        " or ".join(dict.fromkeys(part.text_pattern or "" for part in texts))
        if texts and all(part.text_pattern for part in texts)
        else None
    )
    numbers = [part.number for part in parts]
    proofs = {item.proof for item in numbers}
    if proofs in ({"not_number"}, {"nan"}):
        number = _NumberFacts(
            numbers[0].proof, " or ".join(item.reason for item in numbers)
        )
    elif proofs <= {"number", "nan"}:
        number = _NUMBER
    else:
        number = _OPEN
    return _Admitted(types, values, elements, number, pattern)


def _conjoined(facts: Sequence[_NumberFacts]) -> _NumberFacts:
    """Combine number facts that all hold: no number wins, then NaN, then number."""

    for proof in ("not_number", "nan", "number"):
        for item in facts:
            if item.proof == proof:
                return item
    return _OPEN


def _meet(
    left: frozenset[str] | None, right: frozenset[str] | None
) -> frozenset[str] | None:
    """Intersect two type sets, where every integer is also a number."""

    if left is None:
        return right
    if right is None:
        return left
    common = set(left & right)
    if ("integer" in left and "number" in right) or (
        "number" in left and "integer" in right
    ):
        common.add("integer")
    return frozenset(common)


def _declared_types(schema: Mapping[str, Any]) -> frozenset[str] | None:
    """Return the ``type`` of a schema; an unknown type name proves nothing.

    The OpenAPI ``nullable: true`` adds ``null``, so it is never left out.
    """

    names = _type_names(schema.get("type"))
    if not names or not set(names) <= _JSON_TYPES:
        return None
    types = frozenset(names)
    if schema.get("nullable") is True:
        types |= {"null"}
    return types


def _item_types(schema: Mapping[str, Any]) -> frozenset[str] | None:
    """Return every JSON type an element of a list the schema admits may have."""

    items = schema.get("items")
    prefix = schema.get("prefixItems")
    if isinstance(items, list):
        return None
    branches: list[object] = list(prefix) if isinstance(prefix, list) else []
    if isinstance(items, Mapping):
        branches.append(items)
    elif items is not False and isinstance(prefix, list):
        return None
    if not branches:
        return None
    types = [_admitted(branch, "").types for branch in branches]
    if any(item is None for item in types):
        return None
    return frozenset().union(*(item or () for item in types))


def _type_number(
    types: frozenset[str] | None, pattern: str | None, name: str
) -> _NumberFacts:
    if not types:
        return _OPEN
    if types <= _NUMERIC_TYPES:
        return _NUMBER
    if types & _NUMERIC_TYPES:
        return _OPEN
    declared = " or ".join(sorted(types))
    if "string" not in types:
        return _NumberFacts("not_number", f"declares {name} as {declared}")
    if pattern is not None:
        return _NumberFacts(
            "not_number",
            f"declares {name} as {declared} matching the pattern {pattern}",
        )
    return _OPEN


def _values_number(values: Sequence[object], name: str) -> _NumberFacts:
    if not values:
        return _OPEN
    numbers = [numeric_value(value) for value in values]
    if all(number is None for number in numbers):
        return _NumberFacts(
            "not_number", f"restricts {name} to {_render(list(values))}"
        )
    if any(number is None for number in numbers):
        return _OPEN
    if all(number is not None and math.isnan(number) for number in numbers):
        return _NumberFacts("nan", f"restricts {name} to {_render(list(values))}")
    return _NUMBER


def _compared(admitted: _Admitted, role: str) -> _Admitted:
    """Return the types and values an equality compares for an argument's role."""

    if role == "value":
        return admitted
    values = admitted.values
    if role == "list":
        return _published(
            _Admitted(
                types=admitted.elements,
                values=None
                if values is None
                else tuple(
                    item
                    for value in values
                    if isinstance(value, list)
                    for item in value
                ),
            )
        )
    types = admitted.types
    if types is not None:
        types = types - {"array"}
        if "array" in (admitted.types or ()):
            types = None if admitted.elements is None else types | admitted.elements
    return _published(
        _Admitted(
            types=types,
            values=None
            if values is None
            else tuple(
                item
                for value in values
                for item in (value if isinstance(value, list) else [value])
            ),
        )
    )


def _same(left: object, right: object) -> bool:
    """Return whether v1 equality holds between two JSON values."""

    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return float(left) == float(right)
    return bool(left == right)


def _common_values(
    left: tuple[object, ...], right: tuple[object, ...]
) -> tuple[object, ...]:
    return tuple(value for value in left if any(_same(value, other) for other in right))


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


def _enumerated(schema: Mapping[str, Any]) -> tuple[object, ...] | None:
    """Return the values ``const`` and ``enum`` both allow, or ``None``."""

    listed: list[tuple[object, ...]] = []
    if "const" in schema:
        listed.append((schema["const"],))
    values = schema.get("enum")
    if isinstance(values, list) and values:
        listed.append(tuple(values))
    if not listed:
        return None
    common = listed[0]
    for other in listed[1:]:
        common = _common_values(common, other)
    return common


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

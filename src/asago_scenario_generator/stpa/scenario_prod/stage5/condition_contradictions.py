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
  none of the values it lists. Membership compares each element: a list
  argument on the left by its ``items``, and the list on the right by its
  own, types and listed values alike; a list with no element (``items:
  false``, or listed lists that are all empty, and the literal ``[]``) has
  no member. A right side that is never a list (a literal, or an argument
  whose schema admits no array) makes ``in`` and ``not_in`` unknown on
  every call, so it is refused. A kind mismatch that
  only values, names, or descriptions suggest is undecidable: an identifier
  literal of another kind than the values reads of that operation passed, or
  than the values reads of another operation passed for an argument of the
  same name, or an identifier literal compared with an argument no read
  passed and whose schema admits a string. Two compared arguments are judged
  each by the schema of its own operation, by the same facts: refused when
  the compared values share no JSON type or no listed value, and otherwise
  undecidable.
- (c) Ordering needs numbers. ``tool-call-condition-v1`` orders only
  numbers, converting a string that ``float()`` accepts, and every
  comparison with NaN is false. ``gt``, ``ge``, ``lt``, or ``le`` is
  refused when a side admits no orderable number, each value being no
  number under that conversion or NaN: a literal, or an argument whose
  schema admits no number and no string, or lists only values that are no
  number or NaN. A side is clean only when its schema admits numbers alone:
  a numeric type without ``null``, or listed numbers or numeric strings.
  Any other side is undecidable: a string, a nullable number, or an
  untyped argument.

A refusal proves that the comparison is never true, or that it is true on
every call. Under ``tool-call-condition-v1`` an argument a call omits leaves
the comparison unknown, which is not true, so a "never true" proof (``eq``,
``in``, a right side that is never a list, an ordering) stands whether or
not the argument is required. A "true on every call" proof (``ne``,
``not_in``, or a ``where`` item that matches no call, so that ``not_called``
holds) needs every argument operand to be in its operation's ``required``
list (a ``required`` that is not a list of distinct names proves no
argument required) and every value its schema admits to make the comparison
true: for
``not_in``, the right side must admit only lists, since a null or other
non-list right side gives unknown. Otherwise the case is undecidable. The
check takes a required argument to be passed on every call, as it takes a
passed value to meet its schema.

A schema proves something only when it is of a flat grammar:

- Its keys are ``type``, ``nullable``, ``enum``, ``const``, ``items``, and
  ``pattern``, and annotations that never restrict a value, each with a
  value of the type the JSON Schema meta-schema gives it: text for
  ``title``, ``description``, ``$comment``, and ``format``, a list for
  ``examples``, a boolean for ``deprecated``, ``readOnly``, and
  ``writeOnly``, and any value for ``default``.
- ``type`` is a JSON type name or a non-empty list of distinct ones; ``nullable`` is
  a boolean, and ``true`` adds ``null``. ``enum`` is a non-empty list and
  ``const`` any value; both are data, whose keys are never read as
  keywords, and a value must be listed by both. ``items`` is a boolean or a
  schema of the same grammar. ``pattern`` is text that Python ``re``
  compiles, and it only removes the listed strings it does not match, so a
  schema with a ``pattern`` must list its values.
- Any other key (``allOf``, ``anyOf``, ``oneOf``, ``not``,
  ``prefixItems``, ``$ref``, ``if``, ``contains``, ``minLength``,
  ``maximum``, ``properties``, or one the check does not know), or a
  malformed value of a grammar key, makes the schema prove nothing: every
  rule, in every operand position, reads it as a schema without facts.

What such a schema admits is then exact, and the check assumes nothing
about satisfiability. Its listed values are those whose type the schema
admits, whose text the ``pattern`` matches, and, for a list, whose every
element ``items`` admits; with no value listed, it admits a value of every
type it declares. A schema that admits no value proves nothing either. A
list schema whose ``items`` admit nothing admits only the empty list: its
type counts, but it proves nothing about its elements. ``items: false``
states that a list holds no element, so such a schema admits ``[]`` alone;
where its types pin a finite set this way (with ``null`` and the two
booleans), equality compares against exactly that set.

A refusal is a Stage 5 validation failure, corrected through the existing
correction request. Undecidable cases are reported only: in the run's
candidate diagnostics and by the offline sweep, never in the scenario.
"""

from __future__ import annotations

import json
import math
import re
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
# The keywords of the flat grammar, and the annotations it allows beside
# them with the JSON type of their value (``object``: any value).
_GRAMMAR_KEYWORDS = frozenset({"type", "nullable", "enum", "const", "items", "pattern"})
_ANNOTATIONS: Mapping[str, type] = {
    "title": str,
    "description": str,
    "$comment": str,
    "format": str,
    "examples": list,
    "default": object,
    "deprecated": bool,
    "readOnly": bool,
    "writeOnly": bool,
}
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
    refusal = None
    if equality.role != "value" and equality.literal == []:
        refusal = _empty_list_refusal(equality)
    elif (
        view.types is not None
        and candidates
        and not any(_fits(value, view.types) for value in candidates)
    ):
        refusal = _type_refusal(equality, admitted, view.types, candidates)
    elif (
        view.values is not None
        and candidates
        and not _common_values(tuple(candidates), view.values)
    ):
        refusal = _value_refusal(equality, view.values)
    if refusal is not None:
        if equality.consequence == _NEVER_HOLDS:
            return refusal, None
        gaps = _always_gaps(universe, [(argument, admitted, equality.role == "list")])
        if not gaps:
            return refusal, None
        return None, _not_always(equality, gaps)
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
            if types
            else f"Compare {argument.argument} where it can hold a value"
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


def _empty_list_refusal(equality: _Equality) -> RuleFinding:
    argument = equality.argument
    if equality.role == "member":
        reason = "the list [] is empty, so no value is a member of it"
        advice = (
            f"Compare {argument.argument} with a list of supplied values that is "
            "not empty"
        )
    else:
        reason = "the empty list [] is a member of no list"
        advice = f"Test membership in {argument.argument} of a value that is not []"
    return RuleFinding(
        "b",
        f"{equality.label} binds {equality.subject} in the tool-call condition, "
        f"but {reason} and {equality.consequence}. {advice}",
        IssueCode.discriminating_condition_record_kind_mismatch,
    )


def _always_gaps(
    universe: ConditionUniverse,
    operands: Sequence[tuple[ToolCallArgumentOperand, _Admitted, bool]],
) -> list[str]:
    """Say why a comparison that holds when it resolves may not hold on every call.

    Each operand is an argument, its facts, and whether it must be a list
    (the right side of ``not_in``). v1 gives unknown for an argument a call
    omits and for a right side that is not a list, so a "holds on every
    call" proof needs every argument required and such a side only a list.
    """

    gaps: list[str] = []
    for argument, admitted, listed in operands:
        if argument.operation in universe.unreadable_required:
            gaps.append(
                f"the input schema of {argument.operation} has a required list "
                "that is not a list of distinct names, so it proves no argument "
                "required, and tool-call-condition-v1 gives unknown on a call "
                f"that omits {argument.argument}"
            )
        elif argument.argument not in universe.required_arguments.get(
            argument.operation, frozenset()
        ):
            gaps.append(
                f"the input schema of {argument.operation} does not require "
                f"{argument.argument}, and tool-call-condition-v1 gives unknown on "
                "a call that omits it"
            )
        if listed and (admitted.types is None or admitted.types - {"array"}):
            kind = (
                f"admits {argument.argument} as {_list_text(admitted)}"
                if admitted.types is not None
                else f"declares no type for {argument.argument}"
            )
            gaps.append(
                f"the input schema of {argument.operation} {kind}, not only a list, "
                "and tool-call-condition-v1 gives unknown where it is not one"
            )
    return gaps


def _not_always(equality: _Equality, gaps: Sequence[str]) -> RuleFinding:
    """Report a comparison that holds when resolved but may not on every call."""

    argument = equality.argument
    name = _operand_text(argument)
    literal = _render(equality.literal)
    if equality.role == "list":
        premise = (
            "the empty list [] is a member of no list"
            if equality.literal == []
            else f"no element of {name} equals {literal}"
        )
        passes = "a list"
    elif equality.role == "member":
        premise = (
            "the list [] is empty"
            if equality.literal == []
            else f"no value of {name} is a member of {literal}"
        )
        passes = argument.argument
    else:
        premise = f"no value of {name} equals {literal}"
        passes = argument.argument
    holds = (
        "the where item matches no call, so not_called holds"
        if equality.op_word == "a where item"
        else "the comparison holds"
    )
    return RuleFinding(
        "b",
        f"{equality.label} binds {equality.subject}: {premise}, so {holds} on "
        f"every call that passes {passes}, but {'; '.join(gaps)}, so whether "
        f"{'not_called' if equality.op_word == 'a where item' else 'the comparison'}"
        " holds on every call is unknown",
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
    """Apply rule (c): each side of an ordering must admit an orderable number.

    v1 gives unknown for a side that is not a number and false for NaN, so a
    side whose every admitted value is one of these never lets the
    comparison hold. A side that admits an orderable number and nothing but
    numbers is clean; any other side is undecidable.
    """

    not_numbers: list[str] = []
    nans: list[str] = []
    mixed: list[str] = []
    open_sides: dict[str, list[tuple[str, object]]] = {}
    for side in (comparison.left, comparison.right):
        if isinstance(side, ToolCallLiteralOperand):
            literal = _number_class(side.value)
            if literal == _OTHER:
                not_numbers.append(f"the literal {_render(side.value)} is not a number")
            elif literal == _NAN:
                nans.append(f"the literal {_render(side.value)} converts to NaN")
            continue
        schema = _argument_schema(universe, side)
        facts = _admitted(schema, side.argument).number
        source = f"the input schema of {side.operation} {facts.reason}"
        if facts.classes == {_OTHER}:
            not_numbers.append(f"{source}, so no value it admits is a number")
        elif facts.classes == {_NAN}:
            nans.append(f"{source}, so every value it admits converts to NaN")
        elif _ORDERABLE not in facts.classes:
            mixed.append(f"{source}, so no value it admits is a number other than NaN")
        elif _OTHER in facts.classes:
            open_sides.setdefault(side.operation, []).append((side.argument, schema))
    call = _comparison_text(comparison)
    advice = (
        "Compare numbers, or state the rule with eq, ne, in, or not_in on "
        "supplied values"
    )
    if not_numbers and not mixed:
        return (
            RuleFinding(
                "c",
                f"{label} binds {call} in the tool-call condition, but "
                "tool-call-condition-v1 orders only numbers: "
                f"{'; '.join(not_numbers)}, so {_NEVER_KNOWN}. {advice}; the "
                "contract cannot order dates or other text",
                IssueCode.discriminating_condition_ordering_not_numeric,
            ),
            None,
        )
    if nans and not mixed:
        return (
            RuleFinding(
                "c",
                f"{label} binds {call} in the tool-call condition, but "
                f"{'; '.join(nans)}, and tool-call-condition-v1 makes every "
                "comparison with NaN false, so the comparison holds on no call "
                f"and never detects the unsafe call. {advice}",
                IssueCode.discriminating_condition_ordering_not_numeric,
            ),
            None,
        )
    if mixed:
        return (
            RuleFinding(
                "c",
                f"{label} binds {call} in the tool-call condition, but "
                "tool-call-condition-v1 orders only numbers and makes every "
                f"comparison with NaN false: {'; '.join(not_numbers + nans + mixed)}"
                ", so the comparison holds on no call and never detects the "
                f"unsafe call. {advice}; the contract cannot order dates or other "
                "text",
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
    facts = [
        _admitted(schema, "") for items in open_sides.values() for _, schema in items
    ]
    sides = [item.types for item in facts if not item.nothing]
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
    if text:
        clauses.append(
            "tool-call-condition-v1 orders a string only when float() accepts its "
            "whole text; nothing typed says whether the values passed are such text"
        )
    if others:
        clauses.append(
            f"tool-call-condition-v1 never orders {' or '.join(others)}; nothing "
            "typed says whether the values passed are numbers"
        )
    if any(item.nothing for item in facts) or not clauses:
        clauses.append(
            "a schema that admits no value proves nothing about the values passed"
        )
    return RuleFinding(
        "c",
        f"{label} binds {call}: {declared}, and {'; and '.join(clauses)}, so "
        "whether the comparison can hold is unknown",
    )


def _open_text(argument: str, schema: object) -> str:
    admitted = _admitted(schema, argument)
    if admitted.nothing:
        return f"no type for {argument}, since it admits no value for {argument}"
    types = admitted.types
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
    gaps = (
        _always_gaps(
            universe,
            [(left, left_admitted, False), (right, right_admitted, membership)],
        )
        if consequence == _ALWAYS_HOLDS
        else []
    )
    premise = (
        f"no value of {_operand_text(left)} equals an element of {_operand_text(right)}"
        if membership
        else (
            f"no value of {_operand_text(left)} equals a value of "
            f"{_operand_text(right)}"
        )
    )
    not_always = RuleFinding(
        "b",
        f"{label} binds {call}: {premise}, so the comparison holds on every call "
        f"that passes both, but {'; '.join(gaps)}, so whether the comparison holds "
        "on every call is unknown",
    )
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
    if not common and gaps:
        return None, not_always
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
        if gaps:
            return None, not_always
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
    if admitted.nothing:
        return (
            f"the input schema of {argument.operation} admits no value for "
            f"{argument.argument}"
        )
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
        elements = admitted.elements.types if admitted.elements else None
        if admitted.elements is _NO_ELEMENT:
            names.append("empty array")
        else:
            names.append(
                f"array of {' or '.join(sorted(elements))}" if elements else "array"
            )
    return " or ".join(sorted(names))


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


_ORDERABLE, _NAN, _OTHER = "orderable", "nan", "other"
_EVERY_CLASS = frozenset({_ORDERABLE, _NAN, _OTHER})


@dataclass(frozen=True)
class _NumberFacts:
    """The number classes an admitted value may fall into under v1.

    The v1 conversion makes a value an orderable number, NaN (every
    comparison with it is false), or no number (``other``: an ordering with
    it is unknown). ``classes`` over-approximates the admitted values;
    ``reason`` names the fact that bounds it.
    """

    classes: frozenset[str] = _EVERY_CLASS
    reason: str = ""


_ANY_NUMBER = _NumberFacts()


@dataclass(frozen=True)
class _Admitted:
    """What a schema proves about the values it admits.

    Every field over-approximates the admitted values: ``types`` is every
    JSON type a value may have, ``values`` every value it may take when an
    ``enum`` or ``const`` lists them, and ``elements`` the facts of every
    element of an admitted list; ``None`` means unknown. ``number`` is the
    number classes of the admitted values.

    ``nothing`` marks a schema that admits no value. It carries no other
    fact, so every rule reads it as unconstrained: a schema that admits
    nothing proves nothing.
    """

    types: frozenset[str] | None = None
    values: tuple[object, ...] | None = None
    elements: _Admitted | None = None
    number: _NumberFacts = _ANY_NUMBER
    nothing: bool = False


_ANY = _Admitted()
_NOTHING = _Admitted(nothing=True)
# The elements of a list that holds none: ``items: false``, or listed lists
# that are all empty. Unlike ``_NOTHING`` it is a stated fact, so it proves
# that no value is a member of such a list.
_NO_ELEMENT = _Admitted(types=frozenset(), values=())


def _admitted(schema: object, name: str) -> _Admitted:
    """Return what a schema proves: ``_ANY`` unless it is of the flat grammar.

    ``name`` is the argument named in a reason.
    """

    facts = _flat(schema, name)
    return _ANY if facts is None else facts


def _flat(schema: object, name: str) -> _Admitted | None:
    """Read a schema of the flat grammar, or return ``None`` for any other.

    The listed values are exactly those ``const`` and ``enum`` both list
    that the type, the ``pattern``, and, element by element, ``items``
    admit; a schema left with none is ``_NOTHING``. Without listed values,
    the schema admits a value of every type it declares (a list schema the
    empty list at least).
    """

    if not isinstance(schema, Mapping) or not set(schema) <= (
        _GRAMMAR_KEYWORDS | set(_ANNOTATIONS)
    ):
        return None
    if any(
        not isinstance(schema[key], shape)
        for key, shape in _ANNOTATIONS.items()
        if key in schema
    ):
        return None
    types: frozenset[str] | None = None
    if "type" in schema:
        names = schema["type"]
        names = [names] if isinstance(names, str) else names
        if (
            not isinstance(names, list)
            or not names
            or not all(isinstance(item, str) and item in _JSON_TYPES for item in names)
            or len(set(names)) != len(names)
        ):
            return None
        types = frozenset(names)
    if "nullable" in schema:
        if not isinstance(schema["nullable"], bool):
            return None
        if schema["nullable"] and types is not None:
            types |= {"null"}
    listed: tuple[object, ...] | None = None
    if "const" in schema:
        listed = (schema["const"],)
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or not enum:
            return None
        listed = tuple(enum) if listed is None else _schema_common(listed, tuple(enum))
    pattern: re.Pattern[str] | None = None
    if "pattern" in schema:
        if listed is None or not isinstance(schema["pattern"], str):
            return None
        try:
            pattern = re.compile(schema["pattern"])
        except re.error:
            return None
    items: _Admitted | bool | None = None
    if "items" in schema:
        raw = schema["items"]
        items = raw if isinstance(raw, bool) else _flat(raw, "")
        if items is None:
            return None
    declared = _type_number(types, name)
    if listed is None:
        if items is None or items is True:
            elements = None
        elif items is False:
            elements = _NO_ELEMENT
        else:
            # Items that admit nothing prove nothing; ``_NOTHING`` keeps
            # ``_holds`` exact.
            elements = items
        return _Admitted(types, None, elements, declared)
    values = tuple(
        value for value in listed if _listed_fits(value, types, pattern, items)
    )
    if not values:
        return _NOTHING
    lists = [value for value in values if isinstance(value, list)]
    number = _conjoined([declared, _values_number(values, name)])
    if number is None:
        return _NOTHING
    return _Admitted(
        types=_meet(types, frozenset(_json_type(value) for value in values)),
        values=values,
        elements=(
            _listed_facts(tuple(item for value in lists for item in value))
            if lists
            else None
        ),
        number=number,
    )


def _listed_fits(
    value: object,
    types: frozenset[str] | None,
    pattern: re.Pattern[str] | None,
    items: _Admitted | bool | None,
) -> bool:
    """Return whether the rest of a flat schema admits one of its listed values."""

    if types is not None and not _fits(value, types):
        return False
    if pattern is not None and isinstance(value, str) and not pattern.search(value):
        return False
    if isinstance(value, list) and isinstance(items, _Admitted):
        return all(_holds(items, element) for element in value)
    if isinstance(value, list) and items is False:
        return not value
    return True


def _holds(facts: _Admitted, value: object) -> bool:
    """Return whether a flat schema's facts admit a value, exactly."""

    if facts.nothing:
        return False
    if facts.values is not None:
        return any(_schema_equal(value, item) for item in facts.values)
    if facts.types is not None and not _fits(value, facts.types):
        return False
    if isinstance(value, list) and facts.elements is not None:
        return all(_holds(facts.elements, element) for element in value)
    return True


def _listed_facts(items: tuple[object, ...]) -> _Admitted:
    """Return the facts of exactly the listed values ``items``."""

    if not items:
        return _NO_ELEMENT
    lists = [item for item in items if isinstance(item, list)]
    return _Admitted(
        types=frozenset(_json_type(item) for item in items),
        values=items,
        elements=(
            _listed_facts(tuple(element for item in lists for element in item))
            if lists
            else None
        ),
        number=_values_number(items, ""),
    )


def _schema_equal(left: object, right: object) -> bool:
    """Return whether JSON Schema equality holds: ``true`` is not ``1``."""

    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _schema_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return left.keys() == right.keys() and all(
            _schema_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, (list, Mapping)) or isinstance(right, (list, Mapping)):
        return False
    return bool(left == right)


def _schema_common(
    left: tuple[object, ...], right: tuple[object, ...]
) -> tuple[object, ...]:
    return tuple(
        value for value in left if any(_schema_equal(value, other) for other in right)
    )


def _conjoined(facts: Sequence[_NumberFacts]) -> _NumberFacts | None:
    """Intersect number facts that all hold; ``None`` when none is left."""

    known = [item for item in facts if item.classes != _EVERY_CLASS]
    if not known:
        return _ANY_NUMBER
    classes = frozenset.intersection(*(item.classes for item in known))
    if not classes:
        return None
    for item in known:
        if item.classes == classes:
            return item
    return _NumberFacts(
        classes, " and ".join(dict.fromkeys(item.reason for item in known))
    )


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


def _type_number(types: frozenset[str] | None, name: str) -> _NumberFacts:
    if not types:
        return _ANY_NUMBER
    classes: set[str] = set()
    if types & _NUMERIC_TYPES:
        classes.add(_ORDERABLE)
    if "string" in types:
        classes |= _EVERY_CLASS
    if types - _NUMERIC_TYPES - {"string"}:
        classes.add(_OTHER)
    declared = " or ".join(sorted(types))
    return _NumberFacts(frozenset(classes), f"declares {name} as {declared}")


def _values_number(values: Sequence[object], name: str) -> _NumberFacts:
    return _NumberFacts(
        frozenset(_number_class(value) for value in values),
        f"restricts {name} to {_render(list(values))}",
    )


def _number_class(value: object) -> str:
    number = numeric_value(value)
    if number is None:
        return _OTHER
    return _NAN if math.isnan(number) else _ORDERABLE


def _compared(admitted: _Admitted, role: str) -> _Admitted:
    """Return the types and values an equality compares for an argument's role.

    ``value`` compares the argument; ``list`` the elements of the list it
    must be; ``member`` the argument, or each element when it is a list. An
    empty list adds no member, so a list with no element (``_NO_ELEMENT``)
    leaves only the other alternatives; empty types then mean that no value
    is ever compared.
    """

    if role == "value":
        pinned = _pinned(admitted)
        if pinned is None or admitted.values is not None:
            return admitted
        return _Admitted(admitted.types, pinned, admitted.elements, admitted.number)
    elements = admitted.elements or _ANY
    if role == "list":
        return _Admitted(types=elements.types, values=elements.values)
    types = admitted.types
    if types is None:
        return _ANY
    scalars = types - {"array"}
    if "array" in types:
        compared = None if elements.types is None else scalars | elements.types
    else:
        compared = scalars
    values = admitted.values
    if values is not None:
        listed: tuple[object, ...] | None = tuple(
            item
            for value in values
            for item in (value if isinstance(value, list) else [value])
        )
    elif not scalars:
        listed = elements.values
    else:
        listed = None
    return _Admitted(types=compared, values=listed)


def _pinned(admitted: _Admitted) -> tuple[object, ...] | None:
    """Return every value a schema admits when its types pin a finite set.

    ``null``, ``boolean``, and a list with no element (``items: false``)
    each admit a fixed set; any other type leaves the set open (``None``).
    """

    types = admitted.types
    if not types:
        return None
    pinned: list[object] = []
    for name in sorted(types):
        if name == "null":
            pinned.append(None)
        elif name == "boolean":
            pinned.extend((False, True))
        elif name == "array" and admitted.elements is _NO_ELEMENT:
            pinned.append([])
        else:
            return None
    return tuple(pinned)


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

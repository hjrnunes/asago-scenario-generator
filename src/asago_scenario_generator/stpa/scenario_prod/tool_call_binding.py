"""Bind a checked discriminating condition to a Garak tool-call condition.

Binding resolves every observed fact up front, so the bound condition holds
only ``argument`` and ``literal`` operands. State predicates (``value``
comparisons with no argument operand) are evaluated here and never reach the
detector. The semantics are the arm 1 evaluator's, which the
``tool_call_condition`` v1 contract fixes:

- A condition with no behavioral part (no ``not_called``, no ``order``, no
  ``value`` with an argument operand, no observed record-selection target)
  is not executable (``state_only``); an unknown comparison kind is a
  ``condition_problem``. An equality between an argument and the session
  subject, and a selection that resolves to the session subject, are not
  behavior: every call of the session's own matches them.
- A false state predicate gives ``precondition_failed``. It wins over every
  later outcome, because arm 1 returns before reading call-level parts.
- A fact operand in a call-level comparison becomes a literal; an unresolved
  one gives ``unresolved_fact``, which wins over an unknown state predicate.
- An unknown state predicate with none false gives ``precondition_unknown``.
- An observed record selection adds, per argument value, a ``where`` item on
  every ``not_called`` comparison of its operation, or else an ``eq``
  comparison appended after the condition's own comparisons.
- An ownership selection is an exception when the caller names the
  operation whose call the scenario declares as its failure. The selected
  record is one example of a record outside the session subject's reach, so
  an ``eq`` on its key would miss every other such record; see
  :func:`_ownership_bindings` for what replaces it.

Facts are the producer's target-observation fact values
(:func:`~asago_scenario_generator.stpa.scenario_prod.condition_check.target_observation_fact_values`).
Comparisons use arm 1's truth rules (:func:`compare`), which differ from the
Stage 5 check's stricter ones on mixed-type operands.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
)
from asago_scenario_generator.stpa.models.target_subject_model import (
    resolve_session_subject,
)
from asago_scenario_generator.stpa.scenario_prod.condition_check import resolve_fact
from asago_scenario_generator.stpa.tool_call_condition import (
    REASON_BOUND,
    REASON_CONDITION_PROBLEM,
    REASON_NO_CONDITION,
    REASON_PRECONDITION_FAILED,
    REASON_PRECONDITION_UNKNOWN,
    REASON_STATE_ONLY,
    REASON_UNRESOLVED_FACT,
    TOOL_CALL_CONDITION_BOUND,
    TOOL_CALL_CONDITION_NOT_EXECUTABLE,
    ToolCallCondition,
    ToolCallConditionStatus,
    ToolCallNotCalledComparison,
)

Truth = bool | None

_UNRESOLVED = object()
_STATE_PREFIX = "TARGET-STATE."
# What replaces an ownership selection: a comparison, or None when a
# comparison of the condition already covers it.
_Replacement = dict[str, Any] | None


@dataclass(frozen=True)
class ToolCallBinding:
    """The binding status and, when bound, the condition."""

    status: ToolCallConditionStatus
    condition: ToolCallCondition | None = None


@dataclass(frozen=True)
class _Structure:
    has_condition: bool
    operations: tuple[str, ...] = ()
    not_called: tuple[str, ...] = ()
    static_comparisons: tuple[tuple[int, Mapping[str, Any]], ...] = ()
    problems: tuple[str, ...] = ()
    session_only: bool = False

    @property
    def behavioral(self) -> bool:
        return bool(self.operations or self.not_called)


class _UnresolvedFact(Exception):
    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.path = path


def bind_tool_call_condition(
    condition: DiscriminatingCondition | Mapping[str, Any] | None,
    fact_values: Mapping[str, object],
    *,
    condition_omitted_reason: str | None = None,
    failure_operation: str | None = None,
    read_arguments: Mapping[str, Mapping[str, frozenset[str]]] | None = None,
) -> ToolCallBinding:
    """Bind *condition* against *fact_values*; see the module docstring.

    ``failure_operation`` is the operation whose call the scenario declares
    as its failure; only a selection on it can be an ownership selection.
    ``read_arguments`` maps a read operation to the values its supplied reads
    passed per argument.
    """

    raw = (
        condition.model_dump(mode="json")
        if isinstance(condition, DiscriminatingCondition)
        else condition
    )
    structure = _analyze(raw, fact_values)
    rejection = _structure_rejection(structure, condition_omitted_reason)
    if rejection is not None:
        return rejection
    assert isinstance(raw, Mapping)

    statics = [
        (index, _static(item, fact_values))
        for index, item in structure.static_comparisons
    ]
    false = _first_index(statics, False)
    if false is not None:
        return _not_executable(
            REASON_PRECONDITION_FAILED,
            f"state predicate comparisons[{false}] is false in the target state",
        )
    try:
        comparisons = _call_comparisons(raw, fact_values)
    except _UnresolvedFact as error:
        return _not_executable(
            REASON_UNRESOLVED_FACT, f"unresolved fact operand {error.path!r}"
        )
    ownership = _ownership_bindings(
        raw, fact_values, failure_operation, read_arguments or {}
    )
    comparisons = _apply_selection(comparisons, raw, fact_values, ownership)
    unknown = _first_index(statics, None)
    if unknown is not None:
        return _not_executable(
            REASON_PRECONDITION_UNKNOWN,
            f"state predicate comparisons[{unknown}] is unknown in the target "
            "state and none is false",
        )
    detail = "every fact operand resolved and every state predicate holds"
    if ownership:
        detail += (
            f"; the selection on {failure_operation} covers every value outside "
            "the session subject's records, not only the selected record"
        )
    return ToolCallBinding(
        ToolCallConditionStatus(
            status=TOOL_CALL_CONDITION_BOUND, reason=REASON_BOUND, detail=detail
        ),
        ToolCallCondition.model_validate({"comparisons": comparisons}),
    )


def bind_missing_call(operation: str) -> ToolCallBinding:
    """Return the bound ``not_called`` condition a missing call states.

    The failure is that ``operation`` is never called, which the contract's
    ``not_called`` comparison expresses exactly: no captured call of the
    operation, with no ``where`` scope. Code derives it only for a missing
    call of an operation the target records; see ``condition_routing``.
    """

    return ToolCallBinding(
        ToolCallConditionStatus(
            status=TOOL_CALL_CONDITION_BOUND,
            reason=REASON_BOUND,
            detail=(
                f"derived by code from the failure call: {operation} is never "
                "called (missing_call)"
            ),
        ),
        ToolCallCondition(
            comparisons=[
                ToolCallNotCalledComparison(kind="not_called", operation=operation)
            ]
        ),
    )


def _structure_rejection(
    structure: _Structure, condition_omitted_reason: str | None
) -> ToolCallBinding | None:
    """Return why a condition's shape is not executable, checked in contract order."""

    if not structure.has_condition:
        detail = "the handoff publishes no discriminating condition"
        if condition_omitted_reason:
            detail = f"{detail}: {condition_omitted_reason}"
        return _not_executable(REASON_NO_CONDITION, detail)
    if structure.problems:
        return _not_executable(REASON_CONDITION_PROBLEM, structure.problems[0])
    if not structure.behavioral:
        names = (
            "the condition's only comparisons restate the session subject"
            if structure.session_only
            else "the condition holds only state predicates"
        )
        return _not_executable(
            REASON_STATE_ONLY, f"{names}, so it names no observable behavior"
        )
    return None


def _first_index(statics: list[tuple[int, Truth]], truth: Truth) -> int | None:
    return next((index for index, value in statics if value is truth), None)


def _not_executable(reason: str, detail: str) -> ToolCallBinding:
    return ToolCallBinding(
        ToolCallConditionStatus(
            status=TOOL_CALL_CONDITION_NOT_EXECUTABLE, reason=reason, detail=detail
        )
    )


def _analyze(
    raw: Mapping[str, Any] | None, fact_values: Mapping[str, object]
) -> _Structure:
    """Split a condition into behavior parts and state predicates (arm 1)."""

    if not isinstance(raw, Mapping):
        return _Structure(has_condition=False)
    session = _session_value(fact_values)
    comparisons = raw.get("comparisons") or []
    operations, not_called, static, problems = _classify(
        comparisons, session, fact_values
    )
    selected, restated = _selected_operations(raw, not_called, session, fact_values)
    operations.extend(selected)
    return _Structure(
        has_condition=True,
        operations=tuple(dict.fromkeys(operations)),
        not_called=tuple(dict.fromkeys(not_called)),
        static_comparisons=tuple(static),
        problems=tuple(problems),
        session_only=restated
        or _has_session_equality(comparisons, session, fact_values),
    )


def _selected_operations(
    raw: Mapping[str, Any],
    not_called: list[str],
    session: str | None,
    fact_values: Mapping[str, object],
) -> tuple[list[str], bool]:
    """Return the operations a selection constrains, and whether it restates the session.

    A selection whose wanted value is the session subject separates no call
    from another, so its operation does not count as behavior.
    """

    operations: list[str] = []
    restated = False
    for item in _observed_argument_values(raw):
        if item["operation"] in not_called:
            continue
        if (
            session is not None
            and selection_wanted_value(item["path"], fact_values) == session
        ):
            restated = True
        else:
            operations.append(item["operation"])
    return operations, restated


def _has_session_equality(
    comparisons: Iterable[Mapping[str, Any]],
    session: str | None,
    fact_values: Mapping[str, object],
) -> bool:
    return any(
        item.get("kind") == "value" and _is_session_equality(item, session, fact_values)
        for item in comparisons
    )


def _session_value(fact_values: Mapping[str, object]) -> str | None:
    """Return the session subject of the observed state, if exactly one exists."""

    subject = _session_subject(fact_values)
    return subject[1] if subject is not None else None


def _session_subject(fact_values: Mapping[str, object]) -> tuple[str, str] | None:
    """Return the session subject's fact path and value, if exactly one exists."""

    state = {
        path.removeprefix(_STATE_PREFIX): value
        for path, value in fact_values.items()
        if path.startswith(_STATE_PREFIX)
        and "." not in path.removeprefix(_STATE_PREFIX)
    }
    subject = resolve_session_subject(state)
    if not subject.observed or subject.path is None or subject.value is None:
        return None
    return _STATE_PREFIX + ".".join(subject.path), subject.value


def _is_session_equality(
    comparison: Mapping[str, Any],
    session: str | None,
    fact_values: Mapping[str, object],
) -> bool:
    """Return whether *comparison* is an argument equal to the session subject."""

    sides = (comparison["left"], comparison["right"])
    return (
        session is not None
        and comparison["op"] == "eq"
        and any(side.get("source") == "argument" for side in sides)
        and any(_resolves_to(side, session, fact_values) for side in sides)
    )


def _resolves_to(
    operand: Mapping[str, Any], wanted: str, fact_values: Mapping[str, object]
) -> bool:
    if operand.get("source") == "literal":
        return operand["value"] == wanted
    if operand.get("source") == "fact":
        return resolve_fact(fact_values, operand["path"]) == (True, wanted)
    return False


def _classify(
    comparisons: Iterable[Mapping[str, Any]],
    session: str | None,
    fact_values: Mapping[str, object],
) -> tuple[list[str], list[str], list[tuple[int, Mapping[str, Any]]], list[str]]:
    """Return operations, not-called operations, state predicates, and problems.

    A session equality is no operation: it separates no call from another.
    """

    operations: list[str] = []
    not_called: list[str] = []
    static: list[tuple[int, Mapping[str, Any]]] = []
    problems: list[str] = []
    for index, comparison in enumerate(comparisons):
        kind = comparison.get("kind")
        if kind == "not_called":
            not_called.append(comparison["operation"])
        elif kind == "order":
            operations.append(comparison["operation"])
        elif kind == "value":
            used = [
                side["operation"]
                for side in (comparison["left"], comparison["right"])
                if side.get("source") == "argument"
            ]
            if used and not _is_session_equality(comparison, session, fact_values):
                operations.extend(used)
            elif used:
                continue
            else:
                static.append((index, comparison))
        else:
            problems.append(f"unknown comparison kind {kind!r}")
    return operations, not_called, static, problems


def _observed_argument_values(raw: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    selection = raw.get("record_selection")
    if not isinstance(selection, Mapping) or selection.get("status") != "observed":
        return ()
    return selection.get("argument_values") or ()


def _static(comparison: Mapping[str, Any], fact_values: Mapping[str, object]) -> Truth:
    left = _static_operand(comparison["left"], fact_values)
    right = _static_operand(comparison["right"], fact_values)
    return compare(comparison["op"], left, right)


def _static_operand(
    operand: Mapping[str, Any], fact_values: Mapping[str, object]
) -> Any:
    source = operand.get("source")
    if source == "literal":
        return operand["value"]
    if source == "fact":
        found, value = resolve_fact(fact_values, operand["path"])
        return value if found else _UNRESOLVED
    return _UNRESOLVED


def _call_comparisons(
    raw: Mapping[str, Any], fact_values: Mapping[str, object]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in raw.get("comparisons") or []:
        kind = item["kind"]
        if kind == "not_called":
            out.append(
                {"kind": "not_called", "operation": item["operation"], "where": []}
            )
        elif kind == "order":
            out.append(
                {
                    "kind": "order",
                    "operation": item["operation"],
                    "requires_prior": item["requires_prior"],
                    "same_argument": item.get("same_argument"),
                }
            )
        elif any(item[side].get("source") == "argument" for side in ("left", "right")):
            out.append(
                {
                    "kind": "value",
                    "left": _call_operand(item["left"], fact_values),
                    "op": item["op"],
                    "right": _call_operand(item["right"], fact_values),
                }
            )
    return out


def _call_operand(
    operand: Mapping[str, Any], fact_values: Mapping[str, object]
) -> dict[str, Any]:
    source = operand.get("source")
    if source == "argument":
        return {
            "source": "argument",
            "operation": operand["operation"],
            "argument": operand["argument"],
        }
    if source == "literal":
        return {"source": "literal", "value": operand["value"]}
    if source == "fact":
        found, value = resolve_fact(fact_values, operand["path"])
        if not found:
            raise _UnresolvedFact(operand["path"])
        return {"source": "literal", "value": value}
    raise _UnresolvedFact(f"<{source}>")


def selection_wanted_value(path: str, fact_values: Mapping[str, object]) -> Any:
    """Return the value a selection path names: its scalar, else its last segment."""

    found, value = resolve_fact(fact_values, path)
    if found and not isinstance(value, (Mapping, list)):
        return value
    return path.rsplit(".", 1)[-1]


def _apply_selection(
    comparisons: list[dict[str, Any]],
    raw: Mapping[str, Any],
    fact_values: Mapping[str, object],
    ownership: Mapping[int, _Replacement],
) -> list[dict[str, Any]]:
    not_called = {
        item["operation"] for item in comparisons if item["kind"] == "not_called"
    }
    appended: list[dict[str, Any]] = []
    for position, item in enumerate(_observed_argument_values(raw)):
        wanted = selection_wanted_value(item["path"], fact_values)
        if position in ownership:
            replacement = ownership[position]
            if replacement is not None:
                appended.append(replacement)
        elif item["operation"] in not_called:
            for comparison in comparisons:
                if (
                    comparison["kind"] == "not_called"
                    and comparison["operation"] == item["operation"]
                ):
                    comparison["where"].append(
                        {"argument": item["argument"], "value": wanted}
                    )
        else:
            appended.append(
                {
                    "kind": "value",
                    "left": {
                        "source": "argument",
                        "operation": item["operation"],
                        "argument": item["argument"],
                    },
                    "op": "eq",
                    "right": {"source": "literal", "value": wanted},
                }
            )
    return comparisons + appended


def _ownership_bindings(
    raw: Mapping[str, Any],
    fact_values: Mapping[str, object],
    operation: str | None,
    read_arguments: Mapping[str, Mapping[str, frozenset[str]]],
) -> dict[int, _Replacement]:
    """Return what replaces each ownership selection, by selection position.

    Only ``operation`` can have one, and only when the supplied reads called
    it: its call then returns the record it names, so the call reaching a
    record outside the session subject's reach is the disclosure. A call of an
    operation no supplied read made keeps its selection. A selection on
    ``operation`` is an ownership selection when the condition compares
    something with the session subject using ``ne``:

    - An argument compared ``ne`` with the session subject already covers
      every other value, so the selection of that argument adds nothing.
    - A selected record whose owner fields the condition compares ``ne`` with
      the session subject is one record the subject is not entitled to. The
      entitled records are those of its collection that fail the condition's
      record comparisons, evaluated on each record with the same rules. A
      selection of the record's key binds ``not_in`` those keys, and so does
      a selection of an owner field for an argument whose supplied reads of
      ``operation`` passed keys of that collection: the argument takes the
      record's key, not the owner's id. A selection of an owner field for an
      argument of the same name binds ``not_in`` the session subject.

    Any other selection keeps its ``eq``. Nothing is replaced when a record
    comparison cites a fact outside the selected record, when a record of
    the collection lacks a compared field, or when a record the comparisons
    leave out is linked to the session subject through another record that
    names it: the entitlement of that record is then unknown.
    """

    session = _session_subject(fact_values)
    selection = raw.get("record_selection")
    if (
        operation not in read_arguments
        or session is None
        or not isinstance(selection, Mapping)
        or selection.get("status") != "observed"
    ):
        return {}
    comparisons = raw.get("comparisons") or []
    if any(
        item.get("kind") == "not_called" and item.get("operation") == operation
        for item in comparisons
    ):
        return {}
    record_path = selection.get("record_path")
    covered = _arguments_ne_session(comparisons, operation, session)
    owners, entitled = _entitled_keys(comparisons, record_path, fact_values, session)
    collection = _collection(record_path, fact_values)
    replaced: dict[int, _Replacement] = {}
    for position, item in enumerate(selection.get("argument_values") or ()):
        if item["operation"] != operation:
            continue
        argument, path = item["argument"], item["path"]
        if argument in covered:
            replaced[position] = None
            continue
        if entitled is None or collection is None:
            continue
        field_name = path.removeprefix(f"{record_path}.")
        reads = read_arguments.get(operation, {}).get(argument, frozenset())
        if path == record_path or (
            field_name in owners
            and argument != field_name
            and any(value in collection for value in reads)
        ):
            replaced[position] = _not_in(operation, argument, entitled)
        elif field_name in owners and argument == field_name:
            replaced[position] = _not_in(operation, argument, [session[1]])
    return replaced


def _arguments_ne_session(
    comparisons: Iterable[Mapping[str, Any]],
    operation: str,
    session: tuple[str, str],
) -> set[str]:
    """Return the arguments of ``operation`` compared ``ne`` with the session subject."""

    covered: set[str] = set()
    for item in comparisons:
        if item.get("kind") != "value" or item.get("op") != "ne":
            continue
        for mine, other in (
            (item["left"], item["right"]),
            (item["right"], item["left"]),
        ):
            if (
                mine.get("source") == "argument"
                and mine.get("operation") == operation
                and _is_session_operand(other, session)
            ):
                covered.add(mine["argument"])
    return covered


def _entitled_keys(
    comparisons: Iterable[Mapping[str, Any]],
    record_path: Any,
    fact_values: Mapping[str, object],
    session: tuple[str, str],
) -> tuple[set[str], list[str] | None]:
    """Return the owner fields compared with the session, and the entitled keys.

    The keys are ``None`` when the condition states no owner field of the
    selected record, when a record comparison cites another fact, when the
    comparisons are unknown on a record or do not hold on the selected one,
    or when a record they would leave out is linked to the session subject.
    """

    collection = _collection(record_path, fact_values)
    if collection is None:
        return set(), None
    owners: set[str] = set()
    record_comparisons: list[Mapping[str, Any]] = []
    for item in comparisons:
        if item.get("kind") != "value":
            continue
        sides = (item["left"], item["right"])
        if any(side.get("source") == "argument" for side in sides):
            continue
        fields = [_record_field(side, record_path) for side in sides]
        for side, field_name in zip(sides, fields):
            if field_name is None and not (
                side.get("source") == "literal" or _is_session_operand(side, session)
            ):
                return set(), None
        record_comparisons.append(item)
        for field_name, other in zip(fields, reversed(sides)):
            if (
                field_name
                and item["op"] == "ne"
                and _is_session_operand(other, session)
            ):
                owners.add(field_name)
    if not owners:
        return owners, None
    selected = str(record_path).rsplit(".", 1)[-1]
    entitled: list[str] = []
    for key, record in collection.items():
        truths = [
            compare(
                item["op"],
                _record_operand(item["left"], record_path, record, session),
                _record_operand(item["right"], record_path, record, session),
            )
            for item in record_comparisons
        ]
        if None in truths:
            return owners, None
        if all(truths):
            continue
        if key == selected:
            return owners, None
        entitled.append(key)
    linked = _session_linked_values(fact_values, session[1])
    if any(key in linked for key in collection if key not in entitled):
        return owners, None
    return owners, sorted(entitled)


def _session_linked_values(
    fact_values: Mapping[str, object], session: str
) -> frozenset[object]:
    """Return the field values of every record that names the session subject.

    A key among them is a record the state links to the subject, for example
    the listing of the subject's own reservation, so the condition's owner
    fields alone do not settle whether the subject may reach it.
    """

    values: set[object] = set()
    for path, records in fact_values.items():
        name = path.removeprefix(_STATE_PREFIX)
        if name == path or "." in name or not isinstance(records, Mapping):
            continue
        for record in records.values():
            if isinstance(record, Mapping) and session in record.values():
                values.update(
                    value for value in record.values() if isinstance(value, str)
                )
    return frozenset(values)


def _collection(
    record_path: Any, fact_values: Mapping[str, object]
) -> Mapping[str, Mapping[str, Any]] | None:
    """Return the records of the collection ``record_path`` selects a record of."""

    if not isinstance(record_path, str) or not record_path.startswith(_STATE_PREFIX):
        return None
    segments = record_path.removeprefix(_STATE_PREFIX).split(".")
    if len(segments) != 2:
        return None
    found, records = resolve_fact(fact_values, _STATE_PREFIX + segments[0])
    if (
        not found
        or not isinstance(records, Mapping)
        or segments[1] not in records
        or not all(isinstance(record, Mapping) for record in records.values())
    ):
        return None
    return records


def _record_field(operand: Mapping[str, Any], record_path: Any) -> str | None:
    """Return the field a fact operand names directly inside the selected record."""

    path = operand.get("path")
    if operand.get("source") != "fact" or not isinstance(path, str):
        return None
    name = path.removeprefix(f"{record_path}.")
    return name if name != path and "." not in name else None


def _record_operand(
    operand: Mapping[str, Any],
    record_path: Any,
    record: Mapping[str, Any],
    session: tuple[str, str],
) -> Any:
    field_name = _record_field(operand, record_path)
    if field_name is not None:
        return record.get(field_name, _UNRESOLVED)
    if operand.get("source") == "literal":
        return operand["value"]
    return session[1]


def _is_session_operand(operand: Mapping[str, Any], session: tuple[str, str]) -> bool:
    if operand.get("source") == "fact":
        return operand.get("path") == session[0]
    return operand.get("source") == "literal" and operand.get("value") == session[1]


def _not_in(operation: str, argument: str, values: list[str]) -> dict[str, Any]:
    return {
        "kind": "value",
        "left": {"source": "argument", "operation": operation, "argument": argument},
        "op": "not_in",
        "right": {"source": "literal", "value": list(values)},
    }


def compare(op: str, left: Any, right: Any) -> Truth:
    """Compare two resolved operands with arm 1's three-valued rules."""

    if left is _UNRESOLVED or right is _UNRESOLVED:
        return None
    if op in {"in", "not_in"}:
        return _membership(op, left, right)
    if op in {"eq", "ne"}:
        return _equal(left, right) if op == "eq" else not _equal(left, right)
    a, b = numeric_value(left), numeric_value(right)
    if a is None or b is None:
        return None
    return {"gt": a > b, "ge": a >= b, "lt": a < b, "le": a <= b}.get(op)


def _membership(op: str, left: Any, right: Any) -> Truth:
    if not isinstance(right, list):
        return None
    elements = left if isinstance(left, list) else [left]
    member = any(
        _equal(element, item) is True for element in elements for item in right
    )
    return member if op == "in" else not member


def _equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return float(left) == float(right)
    return bool(left == right)


def numeric_value(value: Any) -> float | None:
    """Return the number an ordering converts ``value`` to, or ``None``."""

    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


__all__ = [
    "ToolCallBinding",
    "bind_missing_call",
    "bind_tool_call_condition",
    "compare",
    "numeric_value",
    "selection_wanted_value",
]

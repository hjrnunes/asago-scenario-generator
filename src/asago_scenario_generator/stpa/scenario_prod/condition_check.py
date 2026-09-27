"""Deterministic resolution and evaluation of a discriminating condition.

The model chooses what separates unsafe from safe behavior; this module
checks that every reference names a supplied operation, argument, or fact,
and evaluates each value comparison against the observed values the model
selected. Order and not-called comparisons and request-dependent arguments
cannot be evaluated before execution and stay ``not_checkable``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field

from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
)
from asago_scenario_generator.stpa.discriminating_condition import (
    MEMBERSHIP_OPERATORS,
    ORDERED_OPERATORS,
    ArgumentOperand,
    ComparisonCheck,
    ComparisonResult,
    ConditionCheck,
    DiscriminatingCondition,
    FactOperand,
    LiteralOperand,
    NotCalledComparison,
    ObservedRecordSelection,
    OrderComparison,
    ValueComparison,
    overall_condition_status,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)

_AMBIGUOUS = object()
_LISTED_LIST_MAX_CHARS = 120


@dataclass(frozen=True)
class ConditionUniverse:
    """The exact operations, arguments, and fact values one request supplied."""

    operations: Mapping[str, frozenset[str]] = field(default_factory=dict)
    fact_values: Mapping[str, object] = field(default_factory=dict)

    @property
    def grounded(self) -> bool:
        """Return whether the request supplied anything a condition can cite."""

        return bool(self.operations) or bool(self.fact_values)


@dataclass(frozen=True)
class ConditionCheckOutcome:
    """Reference errors plus the evaluation, when references resolve."""

    reference_errors: tuple[str, ...]
    check: ConditionCheck | None
    # The checked condition with every argument-value path made absolute.
    condition: DiscriminatingCondition | None = None

    @property
    def failures(self) -> tuple[str, ...]:
        """Return every finding that requires a correction."""

        failures = list(self.reference_errors)
        if self.check is not None:
            failures.extend(
                f"comparisons[{item.index}] is violated: {item.reason}"
                for item in self.check.comparisons
                if item.result == "violated"
            )
        return tuple(failures)


def build_condition_universe(
    *,
    execution_target_profile: ExecutionTargetProfile | None,
    target_operation: TargetOperationObservation | None,
    target_observations: TargetObservationSnapshot | None,
) -> ConditionUniverse:
    """Collect the operation arguments and fact values of one request."""

    operations: dict[str, set[str]] = {}
    if execution_target_profile is not None:
        for resource in execution_target_profile.resources:
            schema_names = _schema_argument_names(resource.input_schema)
            for operation in resource.operations:
                names = operations.setdefault(operation.operation_id, set())
                names.update(operation.argument_names or resource.argument_names)
                names.update(schema_names)
    elif target_operation is not None:
        names = operations.setdefault(target_operation.operation_id, set())
        names.update(target_operation.argument_names)
        names.update(_schema_argument_names(target_operation.input_schema))
    return ConditionUniverse(
        operations={name: frozenset(args) for name, args in operations.items()},
        fact_values=target_observation_fact_values(target_observations),
    )


def target_observation_fact_values(
    target_observations: TargetObservationSnapshot | None,
) -> dict[str, object]:
    """Map every supplied fact path to its observed JSON value.

    Paths match the Stage 5 fact-reference universe: read-observation
    arguments as ``<ref>.arguments.<name>`` and object-key paths inside JSON
    content. Lists are values, not indexed paths. A path produced twice with
    different values is marked ambiguous rather than resolved to either.
    """

    values: dict[str, object] = {}
    if target_observations is None:
        return values
    for observation in target_observations.observations:
        prefix = observation.observation_ref
        for name, value in (observation.source_arguments or {}).items():
            _record_value(values, f"{prefix}.arguments.{name}", value)
        if observation.content_format != "json":
            continue
        try:
            content = json.loads(observation.content)
        except (TypeError, ValueError):
            continue
        _collect_values(content, prefix, values)
    return values


def check_discriminating_condition(
    condition: DiscriminatingCondition,
    universe: ConditionUniverse,
) -> ConditionCheckOutcome:
    """Resolve every reference, then evaluate each comparison."""

    errors: list[str] = []
    condition = normalize_argument_value_paths(condition, universe)
    selected = _selected_argument_values(condition, universe, errors)
    for index, comparison in enumerate(condition.comparisons):
        if isinstance(comparison, OrderComparison):
            _check_order_references(index, comparison, universe, errors)
        elif isinstance(comparison, NotCalledComparison):
            _check_operation(
                f"comparisons[{index}]", comparison.operation, universe, errors
            )
        else:
            for side in ("left", "right"):
                _check_operand_reference(
                    f"comparisons[{index}].{side}",
                    getattr(comparison, side),
                    universe,
                    errors,
                )
    if errors:
        return ConditionCheckOutcome(tuple(errors), None)

    results: list[ComparisonCheck] = []
    for index, comparison in enumerate(condition.comparisons):
        if isinstance(comparison, OrderComparison):
            results.append(
                ComparisonCheck(
                    index=index,
                    result="not_checkable",
                    reason=(
                        f"call ordering of {comparison.operation} after "
                        f"{comparison.requires_prior} is observable only at "
                        "execution time"
                    ),
                )
            )
            continue
        if isinstance(comparison, NotCalledComparison):
            results.append(
                ComparisonCheck(
                    index=index,
                    result="not_checkable",
                    reason=(
                        f"the omission of {comparison.operation} is observable "
                        "only at execution time"
                    ),
                )
            )
            continue
        result = _evaluate_value(index, comparison, universe, selected, errors)
        if result is not None:
            results.append(result)
    if errors:
        return ConditionCheckOutcome(tuple(errors), None)
    return ConditionCheckOutcome(
        (),
        ConditionCheck(
            status=overall_condition_status([item.result for item in results]),
            comparisons=results,
        ),
        condition,
    )


def normalize_argument_value_paths(
    condition: DiscriminatingCondition,
    universe: ConditionUniverse,
) -> DiscriminatingCondition:
    """Make relative ``argument_values`` paths absolute under ``record_path``.

    A path may be written relative to the selected record (``field``) or to
    its collection (``<record_key>`` or ``<record_key>.field``). A path that
    is already absolute, or whose absolute form is not a supplied fact, is
    left unchanged so the check reports it exactly as written.
    """

    selection = condition.record_selection
    if not isinstance(selection, ObservedRecordSelection):
        return condition
    record = selection.record_path
    key = record.rsplit(".", 1)[-1]
    changed = False
    items = []
    for item in selection.argument_values:
        path = item.path
        if path == record or path.startswith(record + "."):
            candidate = path
        elif path == key:
            candidate = record
        elif path.startswith(key + ".") and (
            record + path[len(key) :] in universe.fact_values
        ):
            candidate = record + path[len(key) :]
        elif f"{record}.{path}" in universe.fact_values:
            candidate = f"{record}.{path}"
        else:
            candidate = path
        if candidate != path:
            changed = True
            item = item.model_copy(update={"path": candidate})
        items.append(item)
    if not changed:
        return condition
    return condition.model_copy(
        update={
            "record_selection": selection.model_copy(update={"argument_values": items})
        }
    )


def condition_fact_listing(fact_values: Mapping[str, object]) -> str:
    """Render every citable fact path with its type and scalar value.

    Ambiguous paths are omitted because a condition cannot cite them.
    """

    lines: list[str] = []
    for path, value in fact_values.items():
        if value is _AMBIGUOUS:
            continue
        if isinstance(value, Mapping):
            lines.append(f"- {path}: object")
        elif isinstance(value, list):
            rendered = _render(value)
            if len(rendered) <= _LISTED_LIST_MAX_CHARS and all(
                _is_scalar(item) for item in value
            ):
                lines.append(f"- {path}: list {rendered}")
            else:
                lines.append(f"- {path}: list with {len(value)} entries (not indexed)")
        else:
            lines.append(f"- {path}: value {_render(value)}")
    return "\n".join(lines) if lines else "- none"


def condition_failure_message(outcome: ConditionCheckOutcome) -> str | None:
    """Render the exact correction text for a failed check, if any."""

    failures = outcome.failures
    if not failures:
        return None
    lines = "\n".join(f"- {item}" for item in failures)
    return (
        "discriminating_condition_check_failed: the discriminating condition "
        "must resolve against the supplied operations and absolute fact paths, "
        "and the selected record must meet every checkable comparison. The "
        "selected record is the record the unsafe call acts on. Fix the listed "
        "paths and references, or select a listed record that meets the "
        "comparisons; set record_selection to {status: unavailable, reason} "
        "only if no listed record meets them. Change only "
        "discriminating_condition; keep observation_criteria and "
        "safe_observable_outcome unchanged. Failures:\n" + lines
    )


def _schema_argument_names(schema: object) -> set[str]:
    if not isinstance(schema, Mapping):
        return set()
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return set()
    return {str(name) for name in properties}


def _record_value(values: dict[str, object], path: str, value: object) -> None:
    if path in values and values[path] is not _AMBIGUOUS and values[path] != value:
        values[path] = _AMBIGUOUS
    else:
        values.setdefault(path, value)


def _collect_values(value: object, prefix: str, values: dict[str, object]) -> None:
    if not isinstance(value, Mapping):
        return
    for key, child in value.items():
        path = f"{prefix}.{key}"
        _record_value(values, path, child)
        _collect_values(child, path, values)


def _check_operation(
    label: str, operation: str, universe: ConditionUniverse, errors: list[str]
) -> bool:
    if operation in universe.operations:
        return True
    available = ", ".join(sorted(universe.operations)) or "none"
    errors.append(
        f"{label} names operation {operation!r}, which is not in the supplied "
        f"operation inventory (available: {available})"
    )
    return False


def _check_argument(
    label: str,
    operation: str,
    argument: str,
    universe: ConditionUniverse,
    errors: list[str],
) -> None:
    if not _check_operation(label, operation, universe, errors):
        return
    arguments = universe.operations[operation]
    if argument not in arguments:
        available = ", ".join(sorted(arguments)) or "none"
        errors.append(
            f"{label} names argument {argument!r}, which is not in the input "
            f"schema of {operation} (available: {available})"
        )


def _check_fact(
    label: str, path: str, universe: ConditionUniverse, errors: list[str]
) -> bool:
    if path not in universe.fact_values:
        errors.append(
            f"{label} names fact path {path!r}, which is not a supplied "
            "target-observation fact"
        )
        return False
    if universe.fact_values[path] is _AMBIGUOUS:
        errors.append(f"{label} names fact path {path!r}, which is ambiguous")
        return False
    return True


def _check_operand_reference(
    label: str,
    operand: object,
    universe: ConditionUniverse,
    errors: list[str],
) -> None:
    if isinstance(operand, ArgumentOperand):
        _check_argument(label, operand.operation, operand.argument, universe, errors)
    elif isinstance(operand, FactOperand):
        _check_fact(label, operand.path, universe, errors)


def _check_order_references(
    index: int,
    comparison: OrderComparison,
    universe: ConditionUniverse,
    errors: list[str],
) -> None:
    label = f"comparisons[{index}]"
    known = [
        _check_operation(label, name, universe, errors)
        for name in (comparison.operation, comparison.requires_prior)
    ]
    if comparison.same_argument is None or not all(known):
        return
    for name in (comparison.operation, comparison.requires_prior):
        _check_argument(
            f"{label}.same_argument", name, comparison.same_argument, universe, errors
        )


def _selected_argument_values(
    condition: DiscriminatingCondition,
    universe: ConditionUniverse,
    errors: list[str],
) -> dict[tuple[str, str], tuple[str, object]]:
    """Resolve the record selection to observed values per argument."""

    selection = condition.record_selection
    if not isinstance(selection, ObservedRecordSelection):
        return {}
    label = "record_selection.record_path"
    if not _check_fact(label, selection.record_path, universe, errors):
        return {}
    if not isinstance(universe.fact_values[selection.record_path], Mapping):
        errors.append(
            f"{label} {selection.record_path!r} names a value, not an observed "
            "record object"
        )
        return {}
    selected: dict[tuple[str, str], tuple[str, object]] = {}
    for position, item in enumerate(selection.argument_values):
        item_label = f"record_selection.argument_values[{position}]"
        _check_argument(item_label, item.operation, item.argument, universe, errors)
        if item.path == selection.record_path:
            # The record path itself stands for the record's key.
            value: object = selection.record_path.rsplit(".", 1)[-1]
        else:
            if not item.path.startswith(selection.record_path + "."):
                errors.append(
                    f"{item_label}.path {item.path!r} is not inside the selected "
                    f"record {selection.record_path!r}"
                )
                continue
            if not _check_fact(f"{item_label}.path", item.path, universe, errors):
                continue
            value = universe.fact_values[item.path]
            if isinstance(value, (Mapping, list)):
                errors.append(
                    f"{item_label}.path {item.path!r} names an object or list, "
                    "not an argument value"
                )
                continue
        selected[(item.operation, item.argument)] = (item.path, value)
    return selected


def _resolve_operand(
    operand: object,
    universe: ConditionUniverse,
    selected: Mapping[tuple[str, str], tuple[str, object]],
) -> tuple[bool, object, str]:
    """Return ``(resolved, value, description)`` for one operand."""

    if isinstance(operand, LiteralOperand):
        return True, operand.value, f"literal {_render(operand.value)}"
    if isinstance(operand, FactOperand):
        value = universe.fact_values[operand.path]
        return True, value, f"fact {operand.path} = {_render(value)}"
    assert isinstance(operand, ArgumentOperand)
    key = (operand.operation, operand.argument)
    name = f"{operand.operation}.{operand.argument}"
    if key not in selected:
        return False, None, f"argument {name} is request-dependent"
    path, value = selected[key]
    return True, value, f"argument {name} = {_render(value)} (from {path})"


def _evaluate_value(
    index: int,
    comparison: ValueComparison,
    universe: ConditionUniverse,
    selected: Mapping[tuple[str, str], tuple[str, object]],
    errors: list[str],
) -> ComparisonCheck | None:
    left_ok, left, left_text = _resolve_operand(comparison.left, universe, selected)
    right_ok, right, right_text = _resolve_operand(comparison.right, universe, selected)
    label = f"comparisons[{index}]"
    if not (left_ok and right_ok):
        unresolved = [
            text
            for ok, text in ((left_ok, left_text), (right_ok, right_text))
            if not ok
        ]
        return ComparisonCheck(
            index=index,
            result="not_checkable",
            reason=(
                "; ".join(unresolved)
                + ": no observed value is selected for it before execution"
            ),
        )
    type_error = _type_error(comparison.op, left, right)
    if type_error is not None:
        errors.append(
            f"{label} cannot compare {left_text} {comparison.op} {right_text}: "
            f"{type_error}"
        )
        return None
    holds = _compare(comparison.op, left, right)
    result: ComparisonResult = "satisfied" if holds else "violated"
    verb = "holds" if holds else "does not hold"
    return ComparisonCheck(
        index=index,
        result=result,
        reason=f"{left_text} {comparison.op} {right_text} {verb}",
    )


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_scalar(value: object) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _type_error(op: str, left: object, right: object) -> str | None:
    if not _is_scalar(left):
        return "the left operand is an object or list, not a value"
    if op in ORDERED_OPERATORS:
        if not (_is_number(left) and _is_number(right)):
            return f"op {op} requires numeric operands"
        return None
    if op in MEMBERSHIP_OPERATORS:
        if not isinstance(right, list):
            return f"op {op} requires a list on the right"
        return None
    if not _is_scalar(right):
        return "the right operand is an object or list, not a value"
    return None


def _same(left: object, right: object) -> bool:
    # JSON distinguishes booleans from numbers; Python's True == 1 does not.
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if _is_number(left) and _is_number(right):
        return left == right
    return type(left) is type(right) and left == right


def _compare(op: str, left: object, right: object) -> bool:
    if op == "eq":
        return _same(left, right)
    if op == "ne":
        return not _same(left, right)
    if op == "in":
        return any(_same(left, item) for item in right)  # type: ignore[union-attr]
    if op == "not_in":
        return not any(_same(left, item) for item in right)  # type: ignore[union-attr]
    ordered = {
        "gt": lambda a, b: a > b,
        "ge": lambda a, b: a >= b,
        "lt": lambda a, b: a < b,
        "le": lambda a, b: a <= b,
    }
    return bool(ordered[op](left, right))


def _render(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


__all__ = [
    "ConditionCheckOutcome",
    "ConditionUniverse",
    "build_condition_universe",
    "check_discriminating_condition",
    "condition_failure_message",
    "condition_fact_listing",
    "normalize_argument_value_paths",
    "target_observation_fact_values",
]

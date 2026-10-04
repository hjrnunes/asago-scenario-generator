"""Generic condition-family hints derived from operation schemas and state.

A condition family names one kind of distinction a discriminating condition
can draw for an operation, with the exact argument, field paths, and
candidate records code found for it. Families are hints: the model still
authors the condition, may decline the family, and the condition checker
validates whatever it returns.

Everything is derived from the operation input schema, the operation effect
labels, and the shape and value types of the supplied TARGET-STATE. Nothing
names a target, tool, collection, field, or identifier prefix.

Argument binding (``field_name`` before ``inferred_prefix``):

- ``field_name``: the argument name equals a field whose values are all keys
  of exactly one key domain (a record-key argument for that domain), or it
  equals a string field on collection records (a field argument).
- ``inferred_prefix``: the argument name ends in ``_id``; with that suffix
  removed it is prefix-compatible, case-insensitively, with the one ID
  prefix that every key of exactly one key domain shares.

Families, in fan-out priority order:

1. ``ownership``: a record-key argument whose records (or a record one
   forward link away) carry a field holding the session subject value, with
   candidate records owned by another subject; or a subject argument (bound
   by field name to a field holding the session value, or to a key domain
   whose keys include it) with candidate values other than the session one.
2. ``flag``: a boolean field of the keyed records with both values observed.
3. ``bound``: a numeric argument and numeric fields on the keyed record or a
   record one forward link away.
4. ``state``: a status-like string field of the keyed records.

``prior_read`` is a separate timing hint: a read-only operation takes an
argument bound to the same key domain as one of this operation's record-key
arguments.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetRealizationResult,
)
from asago_scenario_generator.stpa.discriminating_condition import (
    ArgumentOperand,
    DiscriminatingCondition,
    FactOperand,
    ObservedRecordSelection,
    OrderComparison,
    ValueComparison,
)
from asago_scenario_generator.stpa.models.target_subject_model import (
    resolve_session_subject,
)

from .condition_check import target_observation_fact_values
from .condition_index import (
    STATE_REF,
    StateIndex,
    id_prefix,
    record_field_label,
    record_path,
)
from .realized_operation import realized_operation
from .target_observations import TargetObservationSnapshot

FamilyKind = Literal["ownership", "flag", "bound", "state", "prior_read"]
BindingLabel = Literal["field_name", "inferred_prefix"]
ArgumentRole = Literal["record_key", "subject", "value"]
HonouredStatus = Literal["honoured", "declined", "not_honoured", "no_condition"]

FAN_OUT_KINDS: tuple[FamilyKind, ...] = ("ownership", "flag", "bound", "state")
DEFAULT_CANDIDATE_CAP = 4
FAN_OUT_SLOT_TYPE = "INCORRECT"
PRIOR_READ_SLOT_TYPE = "WRONG_TIMING"
CONDITION_FAMILIES_FILENAME = "condition-families.yaml"
CONDITION_FAMILIES_SCHEMA_VERSION = "condition-families-v1"

_READ_EFFECTS = frozenset({"read", "observe"})
_NUMERIC_TYPES = frozenset({"number", "integer"})
_KEY_TYPES = frozenset({"string"})
_ID_SUFFIX = "_id"
# Keeps the hint short inside the tight Stage 5 prompt budget.
_PROMPT_PATHS_PER_VALUE = 4


@dataclass(frozen=True)
class FamilyCandidate:
    """Records that share one observed value of the family's field."""

    value: str
    record_paths: tuple[str, ...]


@dataclass(frozen=True)
class ConditionFamily:
    """One generic condition family for one operation."""

    kind: FamilyKind
    operation: str
    argument: str | None = None
    argument_role: ArgumentRole | None = None
    binding: BindingLabel | None = None
    collection: str | None = None
    field_paths: tuple[str, ...] = ()
    candidates: tuple[FamilyCandidate, ...] = ()
    prior_operation: str | None = None
    same_argument: str | None = None
    session_path: str | None = None
    # A bound family compares a value argument; this names the argument that
    # selects the record whose field sets the limit.
    record_argument: str | None = None

    @property
    def candidate_record_paths(self) -> tuple[str, ...]:
        """Return every candidate record path in candidate order."""

        return tuple(
            path for candidate in self.candidates for path in candidate.record_paths
        )

    def as_log(self) -> dict[str, object]:
        """Return the plain mapping written to the family sidecar."""

        return {
            "kind": self.kind,
            "operation": self.operation,
            "argument": self.argument,
            "argument_role": self.argument_role,
            "binding": self.binding,
            "collection": self.collection,
            "field_paths": list(self.field_paths),
            "candidates": [
                {"value": item.value, "record_paths": list(item.record_paths)}
                for item in self.candidates
            ],
            "prior_operation": self.prior_operation,
            "same_argument": self.same_argument,
            "session_path": self.session_path,
            "record_argument": self.record_argument,
        }


@dataclass(frozen=True)
class CandidateFamilyPlan:
    """The family hint of one Stage 5 candidate and what the cap dropped."""

    family: ConditionFamily | None = None
    capped_out: tuple[ConditionFamily, ...] = ()


@dataclass(frozen=True)
class FamilyPlan:
    """Expanded Stage 5 threats with one aligned family plan each."""

    threats: tuple[Any, ...]
    candidates: tuple[CandidateFamilyPlan, ...]


@dataclass(frozen=True)
class _Binding:
    argument: str
    label: BindingLabel
    domain: str
    # Set for a field argument: the collection field whose name it shares.
    field_name: str | None = None


@dataclass(frozen=True)
class _StateView:
    state: StateIndex
    session_path: str | None
    session_value: str | None
    session_values: frozenset[str] = field(default_factory=frozenset)


def derive_condition_families(
    operation: TargetOperationObservation,
    observed_operations: Sequence[TargetOperationObservation],
    state: StateIndex,
) -> tuple[ConditionFamily, ...]:
    """Return every family for ``operation``, fan-out kinds then prior-read.

    Fan-out families come in ``FAN_OUT_KINDS`` order; prior-read families
    follow. The order within a kind is deterministic.
    """

    view = _state_view(state)
    bindings = _bind_arguments(operation, state)
    by_kind: dict[FamilyKind, list[ConditionFamily]] = {
        kind: [] for kind in (*FAN_OUT_KINDS, "prior_read")
    }
    for binding in bindings:
        if binding.field_name is not None:
            family = _subject_field_family(operation, binding, view)
            if family is not None:
                by_kind["ownership"].append(family)
            continue
        subject = _subject_key_family(operation, binding, view)
        if subject is not None:
            by_kind["ownership"].append(subject)
        if binding.domain not in state.records:
            continue
        by_kind["ownership"].extend(_keyed_ownership(operation, binding, view))
        by_kind["flag"].extend(_flag_families(operation, binding, view))
        by_kind["bound"].extend(_bound_families(operation, binding, view))
        by_kind["state"].extend(_state_families(operation, binding, view))
    by_kind["prior_read"].extend(
        _prior_read_families(operation, bindings, observed_operations, state)
    )
    return tuple(family for kind in by_kind for family in by_kind[kind])


def plan_family_candidates(
    threats: Sequence[Any],
    realization: TargetRealizationResult | None,
    observations: TargetObservationSnapshot | None,
    *,
    cap: int = DEFAULT_CANDIDATE_CAP,
) -> FamilyPlan:
    """Expand INCORRECT threats by family and hint WRONG_TIMING threats.

    For each INCORRECT slot whose action has a realized operation, the
    fan-out families are dealt round-robin across the slot's ICAs in threat
    order. Each ICA yields one candidate per assigned family, at most
    ``cap``; the rest are recorded as capped out on its first candidate. An
    ICA with no family keeps one candidate without a hint. A WRONG_TIMING
    ICA keeps one candidate with the first prior-read family. Every other
    threat keeps one candidate without a hint.
    """

    if realization is None or observations is None:
        return expand_family_candidates(threats, lambda _action_id: (), cap=cap)
    state = StateIndex.from_fact_values(target_observation_fact_values(observations))
    observed = tuple(record.operation for record in realization.operation_records)

    def families_for(action_id: str) -> tuple[ConditionFamily, ...]:
        try:
            operation = realized_operation(realization, action_id)
        except ValueError:
            return ()
        if operation is None:
            return ()
        return derive_condition_families(operation, observed, state)

    return expand_family_candidates(threats, families_for, cap=cap)


def expand_family_candidates(
    threats: Sequence[Any],
    families_for_action: Callable[[str], Sequence[ConditionFamily]],
    *,
    cap: int = DEFAULT_CANDIDATE_CAP,
) -> FamilyPlan:
    """Apply the fan-out rules of ``plan_family_candidates`` to known families.

    ``families_for_action`` returns the families of the operation realized
    for one control action, or nothing when none is realized.
    """

    if cap < 1:
        raise ValueError("cap must be at least 1")
    families_for = _cached_families(families_for_action)
    assigned = _assign_fan_out_families(threats, families_for)

    expanded: list[Any] = []
    plans: list[CandidateFamilyPlan] = []
    for index, threat in enumerate(threats):
        parts = threat.ica_slot_id.split(":")
        slot_type = parts[2] if len(parts) >= 3 else ""
        if slot_type == FAN_OUT_SLOT_TYPE and assigned.get(index):
            for plan in _fan_out_plans(assigned[index], cap):
                expanded.append(threat)
                plans.append(plan)
            continue
        expanded.append(threat)
        plans.append(_single_candidate_plan(slot_type, parts, families_for))
    return FamilyPlan(tuple(expanded), tuple(plans))


def _cached_families(
    families_for_action: Callable[[str], Sequence[ConditionFamily]],
) -> Callable[[str], tuple[ConditionFamily, ...]]:
    """Ask for each control action's families at most once."""
    cache: dict[str, tuple[ConditionFamily, ...]] = {}

    def families_for(action_id: str) -> tuple[ConditionFamily, ...]:
        if action_id not in cache:
            cache[action_id] = tuple(families_for_action(action_id))
        return cache[action_id]

    return families_for


def _assign_fan_out_families(
    threats: Sequence[Any],
    families_for: Callable[[str], tuple[ConditionFamily, ...]],
) -> dict[int, list[ConditionFamily]]:
    """Deal each fan-out slot's families round-robin over the slot's threats."""
    slot_members: dict[str, list[int]] = {}
    for index, threat in enumerate(threats):
        slot_members.setdefault(threat.ica_slot_id, []).append(index)

    assigned: dict[int, list[ConditionFamily]] = {}
    for slot_id, members in slot_members.items():
        parts = slot_id.split(":")
        if len(parts) < 3 or parts[2] != FAN_OUT_SLOT_TYPE:
            continue
        fan_out = [
            family for family in families_for(parts[1]) if family.kind in FAN_OUT_KINDS
        ]
        for position, family in enumerate(fan_out):
            assigned.setdefault(members[position % len(members)], []).append(family)
    return assigned


def _fan_out_plans(
    families: list[ConditionFamily], cap: int
) -> list[CandidateFamilyPlan]:
    """Return one plan per kept family; the first records the capped-out rest."""
    kept, capped = families[:cap], tuple(families[cap:])
    return [
        CandidateFamilyPlan(family, capped if position == 0 else ())
        for position, family in enumerate(kept)
    ]


def _single_candidate_plan(
    slot_type: str,
    parts: list[str],
    families_for: Callable[[str], tuple[ConditionFamily, ...]],
) -> CandidateFamilyPlan:
    """Return the plan of a threat that keeps exactly one candidate."""
    if slot_type != PRIOR_READ_SLOT_TYPE:
        return CandidateFamilyPlan()
    prior = [family for family in families_for(parts[1]) if family.kind == "prior_read"]
    return (
        CandidateFamilyPlan(prior[0], tuple(prior[1:]))
        if prior
        else CandidateFamilyPlan()
    )


def family_honoured(
    family: ConditionFamily, condition: DiscriminatingCondition | None
) -> HonouredStatus:
    """Report whether a published condition follows its family hint.

    This is a diagnostic only; it never rejects a condition.
    """

    if condition is None:
        return "no_condition"
    if _cites_family(family, condition):
        return "honoured"
    if not isinstance(condition.record_selection, ObservedRecordSelection):
        return "declined"
    return "not_honoured"


def family_prompt_view(family: ConditionFamily | None) -> dict[str, object] | None:
    """Return the exact family facts the Stage 5 prompt renders."""

    if family is None:
        return None
    return {
        "kind": family.kind,
        "operation": family.operation,
        "argument": family.argument,
        "field_paths": list(family.field_paths),
        "candidates": [
            {
                "value": item.value,
                "record_paths": list(item.record_paths[:_PROMPT_PATHS_PER_VALUE]),
                "more": max(0, len(item.record_paths) - _PROMPT_PATHS_PER_VALUE),
            }
            for item in family.candidates
        ],
        "prior_operation": family.prior_operation,
        "same_argument": family.same_argument,
        "session_path": family.session_path,
        "record_argument": family.record_argument,
    }


# --- argument binding -------------------------------------------------------


def _schema_properties(operation: TargetOperationObservation) -> Mapping[str, Any]:
    properties = operation.input_schema.get("properties")
    return properties if isinstance(properties, Mapping) else {}


def _schema_types(schema: object) -> frozenset[str]:
    """Return the JSON types an argument schema admits (empty when untyped)."""

    if not isinstance(schema, Mapping):
        return frozenset()
    declared = schema.get("type")
    types: set[str] = set()
    if isinstance(declared, str):
        types.add(declared)
    elif isinstance(declared, (list, tuple)):
        types.update(item for item in declared if isinstance(item, str))
    for key in ("anyOf", "oneOf"):
        options = schema.get(key)
        if isinstance(options, (list, tuple)):
            for option in options:
                types.update(_schema_types(option))
    types.discard("null")
    return frozenset(types)


def _is_key_argument(schema: object) -> bool:
    types = _schema_types(schema)
    return not types or bool(types & _KEY_TYPES)


def _is_numeric_argument(schema: object) -> bool:
    types = _schema_types(schema)
    return bool(types) and types <= _NUMERIC_TYPES


def _bind_arguments(
    operation: TargetOperationObservation, state: StateIndex
) -> tuple[_Binding, ...]:
    bindings: list[_Binding] = []
    for argument, schema in sorted(_schema_properties(operation).items()):
        if not _is_key_argument(schema):
            continue
        linked = sorted(
            {
                target
                for (_collection, field_name), targets in state.links.items()
                if field_name == argument
                for target in targets
            }
        )
        if len(linked) == 1:
            bindings.append(_Binding(argument, "field_name", linked[0]))
            continue
        if linked:
            continue
        holders = sorted(
            name
            for name, keyed in state.records.items()
            if any(isinstance(record.get(argument), str) for record in keyed.values())
        )
        if holders:
            bindings.extend(
                _Binding(argument, "field_name", name, argument) for name in holders
            )
            continue
        domain = _prefix_domain(argument, state)
        if domain is not None:
            bindings.append(_Binding(argument, "inferred_prefix", domain))
    return tuple(bindings)


def _prefix_domain(argument: str, state: StateIndex) -> str | None:
    """Return the one key domain whose shared ID prefix fits ``argument``."""

    if not argument.lower().endswith(_ID_SUFFIX):
        return None
    stem = argument[: -len(_ID_SUFFIX)].lower()
    if not stem:
        return None
    matches = []
    for name, keys in state.key_domains.items():
        prefixes = {id_prefix(key) for key in keys}
        if len(prefixes) != 1:
            continue
        (prefix,) = prefixes
        if prefix is not None and (stem.startswith(prefix) or prefix.startswith(stem)):
            matches.append(name)
    return matches[0] if len(matches) == 1 else None


# --- family derivation ------------------------------------------------------


def _state_view(state: StateIndex) -> _StateView:
    session = resolve_session_subject(dict(state.state))
    session_values = frozenset(
        value for value in state.state.values() if isinstance(value, str)
    )
    if not session.observed or session.path is None:
        return _StateView(state, None, None, session_values)
    return _StateView(
        state,
        f"{STATE_REF}." + ".".join(session.path),
        session.value,
        session_values,
    )


def _render(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _grouped(pairs: Iterable[tuple[object, str]]) -> tuple[FamilyCandidate, ...]:
    groups: dict[str, list[str]] = {}
    for value, path in pairs:
        groups.setdefault(_render(value), []).append(path)
    return tuple(
        FamilyCandidate(value, tuple(sorted(paths)))
        for value, paths in sorted(groups.items())
    )


def _field_values(
    records: Mapping[str, Mapping[str, object]], field_name: str
) -> dict[str, object]:
    return {
        key: record[field_name]
        for key, record in records.items()
        if field_name in record
    }


def _field_names(records: Mapping[str, Mapping[str, object]]) -> list[str]:
    return sorted({name for record in records.values() for name in record})


def _forward_links(state: StateIndex, collection: str) -> list[tuple[str, str]]:
    """Return ``(field, target collection)`` pairs to collections with records."""

    return sorted(
        (field_name, target)
        for (name, field_name), targets in state.links.items()
        if name == collection
        for target in targets
        if target in state.records and target != collection
    )


def _owner_fields(view: _StateView, collection: str) -> list[str]:
    records = view.state.records[collection]
    return [
        name
        for name in _field_names(records)
        if view.session_value
        in {v for v in _field_values(records, name).values() if isinstance(v, str)}
    ]


def _keyed_ownership(
    operation: TargetOperationObservation, binding: _Binding, view: _StateView
) -> list[ConditionFamily]:
    if view.session_value is None:
        return []
    state = view.state
    records = state.records[binding.domain]
    families: list[ConditionFamily] = []
    for owner in _owner_fields(view, binding.domain):
        pairs = [
            (value, record_path(binding.domain, key))
            for key, value in _field_values(records, owner).items()
            if isinstance(value, str) and value != view.session_value
        ]
        if pairs:
            families.append(
                _family(
                    "ownership",
                    operation,
                    binding,
                    "record_key",
                    (record_field_label(binding.domain, owner),),
                    _grouped(pairs),
                    view,
                )
            )
    if families:
        return families
    for link_field, target in _forward_links(state, binding.domain):
        for owner in _owner_fields(view, target):
            pairs = []
            for key, record in records.items():
                linked = record.get(link_field)
                owner_value = state.records[target].get(str(linked), {}).get(owner)
                if isinstance(owner_value, str) and owner_value != view.session_value:
                    pairs.append((owner_value, record_path(binding.domain, key)))
            if pairs:
                families.append(
                    _family(
                        "ownership",
                        operation,
                        binding,
                        "record_key",
                        (
                            record_field_label(binding.domain, link_field),
                            record_field_label(target, owner),
                        ),
                        _grouped(pairs),
                        view,
                    )
                )
    return families


def _subject_field_family(
    operation: TargetOperationObservation, binding: _Binding, view: _StateView
) -> ConditionFamily | None:
    assert binding.field_name is not None
    records = view.state.records[binding.domain]
    values = _field_values(records, binding.field_name)
    if view.session_value is None or view.session_value not in values.values():
        return None
    pairs = [
        (value, record_path(binding.domain, key))
        for key, value in values.items()
        if isinstance(value, str) and value != view.session_value
    ]
    if not pairs:
        return None
    return _family(
        "ownership",
        operation,
        binding,
        "subject",
        (record_field_label(binding.domain, binding.field_name),),
        _grouped(pairs),
        view,
    )


def _subject_key_family(
    operation: TargetOperationObservation, binding: _Binding, view: _StateView
) -> ConditionFamily | None:
    keys = view.state.key_domains.get(binding.domain, frozenset())
    if view.session_value is None or view.session_value not in keys:
        return None
    others = sorted(keys - {view.session_value})
    if not others:
        return None
    return _family(
        "ownership",
        operation,
        binding,
        "subject",
        (),
        tuple(
            FamilyCandidate(_render(key), (record_path(binding.domain, key),))
            for key in others
        ),
        view,
    )


def _flag_families(
    operation: TargetOperationObservation, binding: _Binding, view: _StateView
) -> list[ConditionFamily]:
    records = view.state.records[binding.domain]
    families = []
    for name in _field_names(records):
        values = _field_values(records, name)
        if not values or not all(isinstance(v, bool) for v in values.values()):
            continue
        if set(values.values()) != {True, False}:
            continue
        families.append(
            _family(
                "flag",
                operation,
                binding,
                "record_key",
                (record_field_label(binding.domain, name),),
                _grouped(
                    (value, record_path(binding.domain, key))
                    for key, value in values.items()
                ),
                view,
            )
        )
    return families


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _numeric_fields(state: StateIndex, collection: str) -> list[str]:
    records = state.records[collection]
    return [
        record_field_label(collection, name)
        for name in _field_names(records)
        if (values := _field_values(records, name))
        and all(_is_number(v) for v in values.values())
    ]


def _bound_families(
    operation: TargetOperationObservation, binding: _Binding, view: _StateView
) -> list[ConditionFamily]:
    state = view.state
    fields = _numeric_fields(state, binding.domain)
    for _link_field, target in _forward_links(state, binding.domain):
        fields.extend(_numeric_fields(state, target))
    if not fields:
        return []
    numeric_arguments = sorted(
        name
        for name, schema in _schema_properties(operation).items()
        if _is_numeric_argument(schema)
    )
    return [
        ConditionFamily(
            kind="bound",
            operation=operation.operation_id,
            argument=argument,
            argument_role="value",
            binding=binding.label,
            collection=binding.domain,
            field_paths=tuple(dict.fromkeys(fields)),
            session_path=None,
            record_argument=binding.argument,
        )
        for argument in numeric_arguments
    ]


def _state_families(
    operation: TargetOperationObservation, binding: _Binding, view: _StateView
) -> list[ConditionFamily]:
    state = view.state
    records = state.records[binding.domain]
    all_keys = frozenset().union(*state.key_domains.values())
    families = []
    for name in _field_names(records):
        values = _field_values(records, name)
        if len(values) != len(records) or not all(
            isinstance(v, str) for v in values.values()
        ):
            continue
        distinct = set(values.values())
        if not 2 <= len(distinct) < len(records):
            continue
        if any(
            not value
            or any(char.isspace() for char in value)
            or id_prefix(value) is not None
            or value in all_keys
            or value in view.session_values
            for value in distinct
        ):
            continue
        families.append(
            _family(
                "state",
                operation,
                binding,
                "record_key",
                (record_field_label(binding.domain, name),),
                _grouped(
                    (value, record_path(binding.domain, key))
                    for key, value in values.items()
                ),
                view,
            )
        )
    return families


def _prior_read_families(
    operation: TargetOperationObservation,
    bindings: Sequence[_Binding],
    observed_operations: Sequence[TargetOperationObservation],
    state: StateIndex,
) -> list[ConditionFamily]:
    keyed = [binding for binding in bindings if binding.field_name is None]
    families: list[ConditionFamily] = []
    seen: set[tuple[str, str]] = set()
    for reader in sorted(observed_operations, key=lambda item: item.operation_id):
        if reader.operation_id == operation.operation_id:
            continue
        if reader.effect not in _READ_EFFECTS or reader.state_changing:
            continue
        reader_bindings = [
            item for item in _bind_arguments(reader, state) if item.field_name is None
        ]
        for binding in keyed:
            for other in reader_bindings:
                if other.domain != binding.domain:
                    continue
                key = (reader.operation_id, binding.argument)
                if key in seen:
                    continue
                seen.add(key)
                families.append(
                    ConditionFamily(
                        kind="prior_read",
                        operation=operation.operation_id,
                        argument=binding.argument,
                        argument_role="record_key",
                        binding=binding.label,
                        collection=binding.domain,
                        prior_operation=reader.operation_id,
                        same_argument=(
                            binding.argument
                            if other.argument == binding.argument
                            else None
                        ),
                    )
                )
    return families


def _family(
    kind: FamilyKind,
    operation: TargetOperationObservation,
    binding: _Binding,
    role: ArgumentRole,
    field_paths: tuple[str, ...],
    candidates: tuple[FamilyCandidate, ...],
    view: _StateView,
) -> ConditionFamily:
    return ConditionFamily(
        kind=kind,
        operation=operation.operation_id,
        argument=binding.argument,
        argument_role=role,
        binding=binding.label,
        collection=binding.domain,
        field_paths=field_paths,
        candidates=candidates,
        session_path=view.session_path if kind == "ownership" else None,
    )


# --- honoured diagnostic ----------------------------------------------------


def _matches_label(path: str, label: str) -> bool:
    marker = "<record_key>"
    if marker not in label:
        return path == label or path.startswith(label + ".")
    head, tail = label.split(marker, 1)
    if not (path.startswith(head) and path.endswith(tail)):
        return False
    middle = path[len(head) : len(path) - len(tail)]
    return bool(middle) and "." not in middle


def _cites_family(family: ConditionFamily, condition: DiscriminatingCondition) -> bool:
    for comparison in condition.comparisons:
        if isinstance(comparison, OrderComparison):
            if _order_cites_family(family, comparison):
                return True
            continue
        if not isinstance(comparison, ValueComparison) or family.kind == "prior_read":
            continue
        if any(
            _operand_cites_family(family, operand)
            for operand in (comparison.left, comparison.right)
        ):
            return True
    return False


def _order_cites_family(family: ConditionFamily, comparison: OrderComparison) -> bool:
    """Return whether an order comparison names a prior-read family's pair."""
    return (
        family.kind == "prior_read"
        and comparison.operation == family.operation
        and comparison.requires_prior == family.prior_operation
        and (
            family.same_argument is None
            or comparison.same_argument == family.same_argument
        )
    )


def _operand_cites_family(family: ConditionFamily, operand: Any) -> bool:
    """Return whether one value-comparison operand names the family's subject."""
    if isinstance(operand, FactOperand) and any(
        _matches_label(operand.path, label) for label in family.field_paths
    ):
        return True
    return (
        isinstance(operand, ArgumentOperand)
        and family.argument_role != "record_key"
        and operand.operation == family.operation
        and operand.argument == family.argument
    )


__all__ = [
    "CONDITION_FAMILIES_FILENAME",
    "CONDITION_FAMILIES_SCHEMA_VERSION",
    "DEFAULT_CANDIDATE_CAP",
    "FAN_OUT_KINDS",
    "CandidateFamilyPlan",
    "ConditionFamily",
    "FamilyCandidate",
    "FamilyPlan",
    "derive_condition_families",
    "expand_family_candidates",
    "family_honoured",
    "family_prompt_view",
    "plan_family_candidates",
]

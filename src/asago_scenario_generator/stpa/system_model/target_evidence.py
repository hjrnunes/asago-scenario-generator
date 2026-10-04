"""Discovered target evidence for the systemic analysis (Stages 1a and 2).

Owner decision (2026-09-29 STPA review, recommendation 5): the discovered
tool inventory, state schema, session fields, and the target's own policy
snippets enter the Stage 1a hazard and constraint calls and Stage 2 as
evidence.  Losses stay derived from risk cards.  The evidence enriches the
one unified analysis; it never selects a different derivation.

The block is a deterministic, bounded projection of generator-visible
discovery outputs.  Every item carries an exact evidence reference so the
model can cite it and code can validate the citation:

- ``operation:<tool>`` and ``argument:<tool>.<arg>`` from the inventory;
- ``session:<field>`` for top-level scalar state fields;
- ``state:<resource>.<field>`` for fields of state record collections;
- ``policy:<TARGET-READ-nnn>`` for captured policy reads.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ProcessModelPart,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    ProfileBasis,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)

MAX_FIELD_VALUES = 6
MAX_RECORD_KEYS = 8
MAX_POLICY_CHARS = 600
MAX_POLICIES = 8


@dataclass(frozen=True)
class EvidenceArgument:
    """One input argument of an observed operation."""

    name: str
    type: str
    required: bool


@dataclass(frozen=True)
class EvidenceOperation:
    """One observed tool with its arguments and interpreted effect."""

    name: str
    description: str
    arguments: tuple[EvidenceArgument, ...]
    effect: str | None = None

    @property
    def ref(self) -> str:
        return f"operation:{self.name}"

    def argument_ref(self, argument: EvidenceArgument) -> str:
        return f"argument:{self.name}.{argument.name}"


@dataclass(frozen=True)
class EvidenceField:
    """One field of a state record collection and its observed values."""

    resource: str
    name: str
    types: tuple[str, ...]
    values: tuple[str, ...]
    more_values: bool = False

    @property
    def ref(self) -> str:
        return f"state:{self.resource}.{self.name}"


@dataclass(frozen=True)
class EvidenceResource:
    """One state collection: its record count, sample keys, and fields."""

    name: str
    record_count: int
    record_keys: tuple[str, ...]
    fields: tuple[EvidenceField, ...]


@dataclass(frozen=True)
class EvidenceSessionField:
    """One top-level scalar state field, such as the session principal."""

    name: str
    value: str

    @property
    def ref(self) -> str:
        return f"session:{self.name}"


@dataclass(frozen=True)
class EvidencePolicy:
    """One captured policy read, quoted and bounded."""

    observation_ref: str
    source_name: str | None
    query_label: str | None
    text: str
    truncated: bool = False

    @property
    def ref(self) -> str:
        return f"policy:{self.observation_ref}"


@dataclass(frozen=True)
class TargetEvidence:
    """Bounded, citable projection of the discovered target."""

    operations: tuple[EvidenceOperation, ...] = ()
    session_fields: tuple[EvidenceSessionField, ...] = ()
    resources: tuple[EvidenceResource, ...] = ()
    policies: tuple[EvidencePolicy, ...] = ()
    diagnostics: tuple[str, ...] = field(default=())

    @property
    def is_empty(self) -> bool:
        return not (
            self.operations or self.session_fields or self.resources or self.policies
        )

    @property
    def operation_names(self) -> frozenset[str]:
        return frozenset(item.name for item in self.operations)

    def refs(self) -> frozenset[str]:
        """Return every exact evidence reference the block exposes."""
        refs: set[str] = set()
        for operation in self.operations:
            refs.add(operation.ref)
            refs.update(operation.argument_ref(arg) for arg in operation.arguments)
        refs.update(item.ref for item in self.session_fields)
        for resource in self.resources:
            refs.update(item.ref for item in resource.fields)
        refs.update(item.ref for item in self.policies)
        return frozenset(refs)

    def write(self, path: Path) -> Path:
        """Persist :meth:`to_record` as YAML at *path*."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump(self.to_record(), sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        return path

    def to_record(self) -> dict[str, Any]:
        """Return the persisted, human-reviewable evidence record."""
        return {
            "operations": [
                {
                    "ref": op.ref,
                    "description": op.description,
                    "effect": op.effect,
                    "arguments": [
                        {
                            "ref": op.argument_ref(arg),
                            "type": arg.type,
                            "required": arg.required,
                        }
                        for arg in op.arguments
                    ],
                }
                for op in self.operations
            ],
            "session_fields": [
                {"ref": item.ref, "value": item.value} for item in self.session_fields
            ],
            "resources": [
                {
                    "name": resource.name,
                    "record_count": resource.record_count,
                    "record_keys": list(resource.record_keys),
                    "fields": [
                        {
                            "ref": item.ref,
                            "types": list(item.types),
                            "values": list(item.values),
                            "more_values": item.more_values,
                        }
                        for item in resource.fields
                    ],
                }
                for resource in self.resources
            ],
            "policies": [
                {
                    "ref": item.ref,
                    "source_name": item.source_name,
                    "query_label": item.query_label,
                    "text": item.text,
                    "truncated": item.truncated,
                }
                for item in self.policies
            ],
            "diagnostics": list(self.diagnostics),
        }


def build_target_evidence(
    profile: ExecutionTargetProfile | None,
    observations: TargetObservationSnapshot | None,
) -> TargetEvidence | None:
    """Project discovery outputs into the Stage 1a/2 evidence block.

    Returns ``None`` when nothing was observed.  A simulation-basis profile
    describes a hypothetical target, so its inventory is not evidence.
    """
    diagnostics: list[str] = []
    operations: tuple[EvidenceOperation, ...] = ()
    if profile is not None and profile.basis is not ProfileBasis.simulation:
        operations = _operations(profile)
    session_fields: tuple[EvidenceSessionField, ...] = ()
    resources: tuple[EvidenceResource, ...] = ()
    policies: tuple[EvidencePolicy, ...] = ()
    if observations is not None:
        state = _observed_state(observations, diagnostics)
        session_fields, resources = _state_schema(state)
        policies = _policies(observations, _all_record_keys(state), diagnostics)
    evidence = TargetEvidence(
        operations=operations,
        session_fields=session_fields,
        resources=resources,
        policies=policies,
        diagnostics=tuple(diagnostics),
    )
    return None if evidence.is_empty else evidence


def _observed_state(
    observations: TargetObservationSnapshot, diagnostics: list[str]
) -> Mapping[str, Any]:
    """Return the observed state object, or an empty mapping when unusable."""
    state_text = next(
        (item.content for item in observations.observations if item.kind == "state"),
        None,
    )
    if state_text is None:
        return {}
    try:
        state = json.loads(state_text)
    except json.JSONDecodeError:
        diagnostics.append("target state is not JSON; state schema omitted")
        return {}
    return state if isinstance(state, Mapping) else {}


def _operations(profile: ExecutionTargetProfile) -> tuple[EvidenceOperation, ...]:
    effects = {
        item.tool_name: item.likely_effect.value for item in profile.interpretations
    }
    tools = profile.inventory.tools if profile.inventory is not None else ()
    result: list[EvidenceOperation] = []
    for tool in tools:
        schema = tool.input_schema or {}
        properties = schema.get("properties") or {}
        required = set(schema.get("required") or ())
        arguments = tuple(
            EvidenceArgument(
                name=str(name),
                type=_schema_type(properties.get(name)),
                required=name in required,
            )
            for name in sorted(properties)
        )
        effect = effects.get(tool.name)
        result.append(
            EvidenceOperation(
                name=tool.name,
                description=(tool.description or "").strip(),
                arguments=arguments,
                effect=None if effect in (None, "unknown") else effect,
            )
        )
    return tuple(sorted(result, key=lambda item: item.name))


def _schema_type(schema: object) -> str:
    if not isinstance(schema, Mapping):
        return "unknown"
    kind = schema.get("type")
    if isinstance(kind, str):
        return kind
    options = schema.get("anyOf") or schema.get("oneOf")
    if isinstance(options, list):
        kinds = sorted(
            {
                str(option.get("type"))
                for option in options
                if isinstance(option, Mapping) and option.get("type")
            }
        )
        if kinds:
            return "|".join(kinds)
    return "unknown"


def _is_scalar(value: object) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _scalar_text(value: object) -> str:
    return value if isinstance(value, str) else json.dumps(value)


def _type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "list"
    return "object"


def _state_schema(
    state: Mapping[str, Any],
) -> tuple[tuple[EvidenceSessionField, ...], tuple[EvidenceResource, ...]]:
    session: list[EvidenceSessionField] = []
    resources: list[EvidenceResource] = []
    for key in sorted(state):
        value = state[key]
        if _is_scalar(value):
            session.append(EvidenceSessionField(name=key, value=_scalar_text(value)))
        elif isinstance(value, Mapping):
            resources.append(_mapping_resource(key, value))
        elif isinstance(value, list):
            records = [item for item in value if isinstance(item, Mapping)]
            resources.append(_resource(key, records, (), record_count=len(value)))
    return tuple(session), tuple(resources)


def _mapping_resource(key: str, value: Mapping[str, Any]) -> EvidenceResource:
    """Describe a mapping state value as a keyed collection or a single record."""
    if value and all(isinstance(item, Mapping) for item in value.values()):
        return _resource(key, list(value.values()), tuple(sorted(value)))
    if value and all(isinstance(item, list) for item in value.values()):
        # A map of keyed lists (records grouped by owner) is a keyed
        # collection; its keys are record addresses, not field names.
        records = [
            item
            for group in value.values()
            for item in group
            if isinstance(item, Mapping)
        ]
        return _resource(key, records, tuple(sorted(value)), record_count=len(records))
    return _resource(key, [value], ())


def _resource(
    name: str,
    records: list[Mapping[str, Any]],
    keys: tuple[str, ...],
    *,
    record_count: int | None = None,
) -> EvidenceResource:
    names = sorted({str(field_name) for record in records for field_name in record})
    return EvidenceResource(
        name=name,
        record_count=len(records) if record_count is None else record_count,
        record_keys=keys[:MAX_RECORD_KEYS],
        fields=tuple(
            _evidence_field(name, field_name, records) for field_name in names
        ),
    )


def _evidence_field(
    resource: str, field_name: str, records: list[Mapping[str, Any]]
) -> EvidenceField:
    raw_values = [record[field_name] for record in records if field_name in record]
    values: list[str] = []
    for raw in raw_values:
        items: Iterable[object] = raw if isinstance(raw, list) else (raw,)
        for item in items:
            if _is_scalar(item) and (text := _scalar_text(item)) not in values:
                values.append(text)
    return EvidenceField(
        resource=resource,
        name=field_name,
        types=tuple(sorted({_type_name(raw) for raw in raw_values})),
        values=tuple(sorted(values)[:MAX_FIELD_VALUES]),
        more_values=len(values) > MAX_FIELD_VALUES,
    )


def _is_keyed_collection(value: object) -> bool:
    """Return whether *value* maps record addresses to records or record lists."""
    return (
        isinstance(value, Mapping)
        and bool(value)
        and (
            all(isinstance(item, Mapping) for item in value.values())
            or all(isinstance(item, list) for item in value.values())
        )
    )


def _all_record_keys(state: Mapping[str, Any]) -> frozenset[str]:
    """Return record keys and session values, the addresses of record reads."""
    keys = {
        str(key)
        for value in state.values()
        if _is_keyed_collection(value)
        for key in value
    }
    keys.update(
        _scalar_text(value)
        for value in state.values()
        if isinstance(value, (str, int)) and not isinstance(value, bool)
    )
    return frozenset(keys)


def _policies(
    observations: TargetObservationSnapshot,
    record_keys: frozenset[str],
    diagnostics: list[str],
) -> tuple[EvidencePolicy, ...]:
    # A read addressed by a state record key or session value re-reads a
    # record the state schema already covers; the remaining reads are policy
    # text.
    reads = [
        item
        for item in observations.observations
        if item.kind == "read"
        and not (
            item.source_arguments and set(item.source_arguments.values()) & record_keys
        )
    ]
    if len(reads) > MAX_POLICIES:
        diagnostics.append(
            f"{len(reads) - MAX_POLICIES} policy reads omitted beyond the "
            f"{MAX_POLICIES}-read evidence bound"
        )
    result: list[EvidencePolicy] = []
    for item in reads[:MAX_POLICIES]:
        text = _policy_text(item.content)
        query = (
            ", ".join(
                f"{key}: {value}"
                for key, value in sorted(item.source_arguments.items())
            )
            if item.source_arguments
            else None
        )
        result.append(
            EvidencePolicy(
                observation_ref=item.observation_ref,
                source_name=item.source_name,
                query_label=query,
                text=text[:MAX_POLICY_CHARS],
                truncated=len(text) > MAX_POLICY_CHARS,
            )
        )
    return tuple(result)


def _policy_text(content: str) -> str:
    """Collapse captured policy JSON to its readable document text."""
    try:
        value = json.loads(content)
    except json.JSONDecodeError:
        return " ".join(content.split())
    texts: list[str] = []
    _collect_texts(value, texts)
    return " | ".join(texts) if texts else " ".join(content.split())


def _collect_texts(value: object, texts: list[str]) -> None:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                _collect_texts(json.loads(stripped), texts)
                return
            except json.JSONDecodeError:
                pass
        if stripped:
            texts.append(" ".join(stripped.split()))
    elif isinstance(value, Mapping):
        for key in sorted(value):
            if key in {"status", "doc_id", "type"}:
                continue
            _collect_texts(value[key], texts)
    elif isinstance(value, list):
        for item in value:
            _collect_texts(item, texts)


__all__ = [
    "EvidenceArgument",
    "EvidenceField",
    "EvidenceOperation",
    "EvidencePolicy",
    "EvidenceResource",
    "EvidenceSessionField",
    "TargetEvidence",
    "build_target_evidence",
]


def check_evidence_bindings(
    control_structure: ControlStructure,
    evidence: TargetEvidence | None,
) -> tuple[ControlStructure, list[str]]:
    """Drop evidence bindings the evidence does not support; report gaps.

    A control action's ``operation`` must name an observed operation and a
    process-model part's ``evidence_refs`` must be exact evidence
    references.  Unsupported bindings are removed (the element itself stays)
    and reported as warnings; observed operations no action names are also
    reported.  The input structure is not mutated.
    """
    operation_names = evidence.operation_names if evidence is not None else frozenset()
    refs = evidence.refs() if evidence is not None else frozenset()
    warnings: list[str] = []
    updated = control_structure.model_copy(deep=True)
    bound_operations: set[str] = set()
    for resp in updated.responsibilities:
        for pm in resp.process_model_parts:
            _drop_unknown_refs(pm, refs, warnings)
        for ca in resp.control_actions:
            _bind_operation(ca, operation_names, bound_operations, warnings)
    unbound = sorted(operation_names - bound_operations)
    if unbound:
        warnings.append(
            "target_evidence: observed operation(s) without a control action: "
            + ", ".join(unbound)
        )
    return updated, warnings


def _drop_unknown_refs(
    part: ProcessModelPart, refs: frozenset[str], warnings: list[str]
) -> None:
    unknown = [ref for ref in part.evidence_refs if ref not in refs]
    if unknown:
        warnings.append(
            f"target_evidence: dropped unknown evidence ref(s) {unknown} "
            f"from {part.pm_id}"
        )
        part.evidence_refs = [ref for ref in part.evidence_refs if ref in refs]


def _bind_operation(
    action: ControlAction,
    operation_names: frozenset[str],
    bound_operations: set[str],
    warnings: list[str],
) -> None:
    if action.operation is None:
        return
    name = action.operation.removeprefix("operation:")
    if name in operation_names:
        action.operation = name
        bound_operations.add(name)
        return
    warnings.append(
        f"target_evidence: dropped unobserved operation {action.operation!r} "
        f"from {action.ca_id}"
    )
    action.operation = None

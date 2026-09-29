"""Deterministic control-structure ID normalization.

High-level SP1 policy: after an LLM payload is decoded and before
``ControlStructure`` validation, assign canonical IDs from structural
position and rewrite references to those IDs.

Recoverable LLM defects stay in this same pass.  Bare ElementRef IDs are
wrapped and types are inferred from source-ID prefixes *before* rewrite, so
the correct namespace can be chosen.  Empty description sentinels are
replaced *after* canonical IDs and rewritten references exist.

This module is a policy leaf.  It depends on the boundary schema and a
pure STPA raw-model traversal helper — never on infra/IO, LLM clients,
files, or Stage 2 orchestration.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from asago_scenario_generator.stpa._model_data import raw_model_data
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ReferenceType,
)

SourceIdEntry = tuple[str, str]
NamespaceEntries = dict[str, list[SourceIdEntry]]

_NAMESPACE_NAMES = (
    "responsibility",
    "responsibility_constraint",
    "process_model_part",
    "control_action",
    "feedback_channel",
    "controlled_process",
    "coordination_link",
    "coordination_mechanism",
)
_RESPONSIBILITY_CHILD_SPECS = (
    (
        "responsibility_constraints",
        "rc_id",
        "RC",
        "responsibility_constraint",
    ),
    ("process_model_parts", "pm_id", "PM", "process_model_part"),
    ("control_actions", "ca_id", "CA", "control_action"),
    ("feedback_channels", "fb_id", "FB", "feedback_channel"),
)
_TYPED_REFERENCE_FIELDS = (
    ("process_model_parts", "feedback_source"),
    ("control_actions", "target"),
    ("feedback_channels", "source"),
)
_TYPED_REFERENCE_NAMESPACES = {
    "responsibility": "responsibility",
    "controlled_process": "controlled_process",
}
_PREFIXES = (
    ("RESP-", "responsibility"),
    ("CP-", "controlled_process"),
)
_DESC_TYPES = {
    "responsibility": ("Responsibility", "resp_id"),
    "responsibility_constraint": (
        "Responsibility constraint",
        "rc_id",
    ),
    "process_model_part": ("Process model part", "pm_id"),
    "control_action": ("Control action", "ca_id"),
    "controlled_process": ("Controlled process", "cp_id"),
    "coordination_link": ("Coordination link", "link_id"),
    "coordination_mechanism": ("Coordination mechanism", "cm_id"),
}


@dataclass(frozen=True)
class ControlStructureNormalization:
    """Normalized control-structure payload and source-ID mappings.

    ``payload`` is a deep copy of the decoded input, with IDs assigned from
    structural positions and references rewritten to those IDs.  ``mapping``
    contains only source IDs that occur exactly once in the payload; callers
    can use it when they need a flat old-to-new lookup.  ``mappings`` keeps
    the same information grouped by element namespace.
    """

    payload: dict[str, Any]
    mapping: dict[str, str]
    mappings: dict[str, dict[str, str]]

    @property
    def old_to_new(self) -> dict[str, str]:
        """Alias for the flat source-ID mapping."""
        return self.mapping


def _payload_dict(payload: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
    """Return a deep-copied dictionary for a decoded payload."""
    if isinstance(payload, BaseModel):
        value = raw_model_data(payload)
    elif isinstance(payload, Mapping):
        value = payload
    else:
        raise TypeError(
            "Control-structure payload must be a mapping or Pydantic model, "
            f"got {type(payload).__name__}."
        )
    return raw_model_data(dict(value))


def _empty_namespace_entries() -> NamespaceEntries:
    """Return empty source-ID buckets in canonical namespace order."""
    return {namespace: [] for namespace in _NAMESPACE_NAMES}


def _collect_child_source_ids(
    children: Any,
    parent_index: int,
    id_key: str,
    prefix: str,
) -> list[SourceIdEntry]:
    """Collect source IDs from one responsibility child collection."""
    if not isinstance(children, list):
        return []
    entries: list[SourceIdEntry] = []
    for child_index, child in enumerate(children, start=1):
        entry = _child_source_id_entry(
            child,
            child_index,
            parent_index,
            id_key,
            prefix,
        )
        if entry is not None:
            entries.append(entry)
    return entries


def _child_source_id_entry(
    child: Any,
    child_index: int,
    parent_index: int,
    id_key: str,
    prefix: str,
) -> SourceIdEntry | None:
    """Return one child source-ID entry when its ID is a string."""
    if not isinstance(child, dict):
        return None
    old_id = child.get(id_key)
    if not isinstance(old_id, str):
        return None
    return old_id, f"{prefix}-{parent_index}-{child_index}"


def _collect_responsibility_source_ids(
    responsibility: dict[str, Any],
    responsibility_index: int,
) -> NamespaceEntries:
    """Collect a responsibility and its child source IDs."""
    entries: NamespaceEntries = {"responsibility": []}
    old_resp_id = responsibility.get("resp_id")
    if isinstance(old_resp_id, str):
        entries["responsibility"].append((old_resp_id, f"RESP-{responsibility_index}"))

    for child_key, id_key, prefix, namespace in _RESPONSIBILITY_CHILD_SPECS:
        entries[namespace] = _collect_child_source_ids(
            responsibility.get(child_key, []),
            responsibility_index,
            id_key,
            prefix,
        )
    return entries


def _collect_controlled_process_source_ids(
    payload: dict[str, Any],
    entries: NamespaceEntries,
) -> None:
    """Append controlled-process source IDs to *entries*."""
    processes = payload.get("controlled_processes", [])
    if not isinstance(processes, list):
        return
    for process_index, process in enumerate(processes, start=1):
        old_id = _string_id(process, "cp_id")
        if old_id is not None:
            entries["controlled_process"].append((old_id, f"CP-{process_index}"))


def _collect_coordination_source_ids(
    payload: dict[str, Any],
    entries: NamespaceEntries,
) -> None:
    """Append coordination-link and mechanism source IDs to *entries*."""
    links = payload.get("coordination_links", [])
    if not isinstance(links, list):
        return
    for link_index, link in enumerate(links, start=1):
        _collect_coordination_link_source_ids(link, link_index, entries)


def _string_id(value: Any, key: str) -> str | None:
    """Return a mapping value when *value[key]* is a string."""
    if isinstance(value, dict) and isinstance(value.get(key), str):
        return value[key]
    return None


def _collect_coordination_link_source_ids(
    link: Any,
    link_index: int,
    entries: NamespaceEntries,
) -> None:
    """Collect source IDs from one coordination link."""
    link_id = _string_id(link, "link_id")
    if link_id is not None:
        entries["coordination_link"].append((link_id, f"CL-{link_index}"))
    if not isinstance(link, dict):
        return
    mechanism = link.get("coordination_mechanism")
    mechanism_id = _string_id(mechanism, "cm_id")
    if mechanism_id is not None:
        entries["coordination_mechanism"].append((mechanism_id, f"CM-{link_index}"))


def _source_id_entries(
    payload: dict[str, Any],
) -> NamespaceEntries:
    """Collect ``(source_id, canonical_id)`` entries by namespace."""
    entries = _empty_namespace_entries()
    responsibilities = payload.get("responsibilities", [])
    if not isinstance(responsibilities, list):
        return entries

    for resp_index, resp in enumerate(responsibilities, start=1):
        if not isinstance(resp, dict):
            continue
        responsibility_entries = _collect_responsibility_source_ids(resp, resp_index)
        for namespace, source_entries in responsibility_entries.items():
            entries[namespace].extend(source_entries)

    _collect_controlled_process_source_ids(payload, entries)
    _collect_coordination_source_ids(payload, entries)
    return entries


def _unique_source_map(entries: list[tuple[str, str]]) -> dict[str, str]:
    """Return a map for source IDs that occur once in one namespace."""
    counts: dict[str, int] = {}
    result: dict[str, str] = {}
    for old_id, _new_id in entries:
        counts[old_id] = counts.get(old_id, 0) + 1
    for old_id, new_id in entries:
        if counts[old_id] == 1:
            result[old_id] = new_id
    return result


def _flat_unique_source_map(
    namespace_entries: dict[str, list[tuple[str, str]]],
) -> dict[str, str]:
    """Return source IDs that occur exactly once across all namespaces."""
    occurrences: dict[str, list[str]] = {}
    for entries in namespace_entries.values():
        for old_id, new_id in entries:
            occurrences.setdefault(old_id, []).append(new_id)
    unique: dict[str, str] = {}
    for old_id, new_ids in occurrences.items():
        if len(new_ids) == 1:
            unique[old_id] = new_ids[0]
    return unique


def _set_responsibility_canonical_ids(
    responsibilities: list[Any],
) -> None:
    """Replace responsibility and child IDs with structural IDs."""
    for resp_index, resp in enumerate(responsibilities, start=1):
        if not isinstance(resp, dict):
            continue
        resp["resp_id"] = f"RESP-{resp_index}"
        _set_responsibility_child_canonical_ids(resp, resp_index)


def _set_responsibility_child_canonical_ids(
    responsibility: dict[str, Any],
    responsibility_index: int,
) -> None:
    """Replace IDs in one responsibility's child collections."""
    for child_key, id_key, prefix, _namespace in _RESPONSIBILITY_CHILD_SPECS:
        children = responsibility.get(child_key, [])
        if not isinstance(children, list):
            continue
        for child_index, child in enumerate(children, start=1):
            if isinstance(child, dict):
                child[id_key] = f"{prefix}-{responsibility_index}-{child_index}"


def _set_controlled_process_canonical_ids(processes: list[Any]) -> None:
    """Replace controlled-process IDs with structural IDs."""
    for process_index, process in enumerate(processes, start=1):
        if isinstance(process, dict):
            process["cp_id"] = f"CP-{process_index}"


def _set_coordination_canonical_ids(links: list[Any]) -> None:
    """Replace coordination-link and mechanism IDs with structural IDs."""
    for link_index, link in enumerate(links, start=1):
        if not isinstance(link, dict):
            continue
        link["link_id"] = f"CL-{link_index}"
        mechanism = link.get("coordination_mechanism")
        if isinstance(mechanism, dict):
            mechanism["cm_id"] = f"CM-{link_index}"


def _set_canonical_ids(payload: dict[str, Any]) -> None:
    """Replace element IDs in *payload* with structural IDs."""
    responsibilities = payload.get("responsibilities", [])
    if isinstance(responsibilities, list):
        _set_responsibility_canonical_ids(responsibilities)

    controlled_processes = payload.get("controlled_processes", [])
    if isinstance(controlled_processes, list):
        _set_controlled_process_canonical_ids(controlled_processes)

    coordination_links = payload.get("coordination_links", [])
    if isinstance(coordination_links, list):
        _set_coordination_canonical_ids(coordination_links)


def _reference_type_value(value: Any) -> str | None:
    """Return the string value of an ElementRef type."""
    if isinstance(value, ReferenceType):
        return value.value
    if isinstance(value, str):
        return value
    return None


def _ref_slots(
    responsibility: dict[str, Any],
) -> Iterator[tuple[dict[str, Any], str]]:
    """Yield child dictionaries and their typed-reference fields."""
    for child_key, ref_key in _TYPED_REFERENCE_FIELDS:
        children = responsibility.get(child_key, [])
        if not isinstance(children, list):
            continue
        for child in children:
            if isinstance(child, dict):
                yield child, ref_key


def _ref_items(
    responsibility: dict[str, Any],
) -> Iterator[dict[str, Any]]:
    """Yield typed references nested in one responsibility."""
    for child, ref_key in _ref_slots(responsibility):
        reference = child.get(ref_key)
        if isinstance(reference, dict):
            yield reference


def _prefix_type(source_id: Any) -> str | None:
    """Return the ElementRef type implied by a source-ID prefix."""
    if not isinstance(source_id, str):
        return None
    for prefix, kind in _PREFIXES:
        if source_id.startswith(prefix):
            return kind
    return None


def _wrap_ref(child: dict[str, Any], ref_key: str) -> None:
    """Wrap one recognized bare ElementRef ID.

    Shape only: recognized ``CP-*`` / ``RESP-*`` strings become ``{"id": ...}``.
    Type inference is the next pass, so newly wrapped refs and already-object
    refs share one type policy.
    """
    reference = child.get(ref_key)
    if not isinstance(reference, str) or _prefix_type(reference) is None:
        return
    child[ref_key] = {"id": reference}


def _source_namespace(
    source_id: Any,
    namespace_maps: dict[str, dict[str, str]],
) -> str | None:
    """Resolve a source ID to one of the namespaces valid for ElementRef."""
    matches = _matching_reference_namespaces(source_id, namespace_maps)
    return matches[0] if len(matches) == 1 else None


def _matching_reference_namespaces(
    source_id: Any,
    namespace_maps: dict[str, dict[str, str]],
) -> list[str]:
    """Return valid ElementRef namespaces containing *source_id*."""
    if not isinstance(source_id, str):
        return []
    return [
        namespace
        for namespace in _TYPED_REFERENCE_NAMESPACES.values()
        if source_id in namespace_maps[namespace]
    ]


def _fix_type(
    reference: dict[str, Any],
    namespace_maps: dict[str, dict[str, str]],
) -> None:
    """Infer a missing ElementRef type from its source ID or namespace."""
    reference_type = _reference_type_value(reference.get("type"))
    if reference_type in _TYPED_REFERENCE_NAMESPACES:
        return
    source_namespace = _source_namespace(reference_type, namespace_maps)
    reference_id = reference.get("id")
    if (
        (not isinstance(reference_id, str) or not reference_id)
        and reference_type is not None
        and (_prefix_type(reference_type) is not None or source_namespace is not None)
    ):
        reference["id"] = reference_type
    inferred_type = _prefix_type(reference.get("id"))
    if inferred_type is None:
        inferred_type = source_namespace
    if inferred_type is not None:
        reference["type"] = inferred_type


def _repair_element_ref_types(
    payload: dict[str, Any],
    namespace_maps: dict[str, dict[str, str]],
) -> None:
    """Infer missing ElementRef types from source IDs and namespace maps."""
    responsibilities = payload.get("responsibilities", [])
    if not isinstance(responsibilities, list):
        return
    for responsibility in responsibilities:
        if not isinstance(responsibility, dict):
            continue
        for reference in _ref_items(responsibility):
            _fix_type(reference, namespace_maps)


def _wrap_bare_string_refs(payload: dict[str, Any]) -> None:
    """Wrap recognized bare ElementRef IDs in typed reference objects."""
    responsibilities = payload.get("responsibilities", [])
    if not isinstance(responsibilities, list):
        return
    for responsibility in responsibilities:
        if not isinstance(responsibility, dict):
            continue
        for child, ref_key in _ref_slots(responsibility):
            _wrap_ref(child, ref_key)


def _rewrite_typed_reference(
    reference: Any,
    maps: dict[str, dict[str, str]],
) -> None:
    """Rewrite an ElementRef ID when its typed source ID is unambiguous."""
    if not isinstance(reference, dict):
        return
    namespace = _TYPED_REFERENCE_NAMESPACES.get(
        _reference_type_value(reference.get("type"))
    )
    if namespace is None:
        return
    old_id = reference.get("id")
    if isinstance(old_id, str) and old_id in maps[namespace]:
        reference["id"] = maps[namespace][old_id]


def _rewrite_local_pm_reference(
    feedback_channel: dict[str, Any],
    local_pm_map: dict[str, str],
) -> None:
    """Rewrite a feedback channel's locally scoped ``updates`` reference."""
    source_id = _local_pm_source_id(feedback_channel.get("updates"))
    if source_id is None or source_id not in local_pm_map:
        return
    feedback_channel["updates"] = local_pm_map[source_id]


def _local_pm_source_id(reference: Any) -> str | None:
    """Extract a source PM ID from scalar or object-shaped feedback updates."""
    if isinstance(reference, str):
        return reference
    if not isinstance(reference, dict):
        return None
    if _reference_type_value(reference.get("type")) != "process_model_part":
        return None
    source_id = reference.get("id")
    return source_id if isinstance(source_id, str) else None


def _rewrite_responsibility_references(
    responsibility: dict[str, Any],
    namespace_maps: dict[str, dict[str, str]],
    local_pm_map: dict[str, str],
) -> None:
    """Rewrite typed and locally scoped references in one responsibility."""
    _rewrite_typed_responsibility_references(responsibility, namespace_maps)
    _rewrite_feedback_channel_references(responsibility, local_pm_map)


def _rewrite_typed_responsibility_references(
    responsibility: dict[str, Any],
    namespace_maps: dict[str, dict[str, str]],
) -> None:
    """Rewrite ElementRefs nested in a single responsibility."""
    for reference in _ref_items(responsibility):
        _rewrite_typed_reference(reference, namespace_maps)


def _rewrite_feedback_channel_references(
    responsibility: dict[str, Any],
    local_pm_map: dict[str, str],
) -> None:
    """Rewrite locally scoped PM references in a responsibility's feedback."""
    feedback_channels = responsibility.get("feedback_channels", [])
    if not isinstance(feedback_channels, list):
        return
    for feedback_channel in feedback_channels:
        if isinstance(feedback_channel, dict):
            _rewrite_local_pm_reference(feedback_channel, local_pm_map)
    control_actions = responsibility.get("control_actions", [])
    if not isinstance(control_actions, list):
        return
    for control_action in control_actions:
        if not isinstance(control_action, dict):
            continue
        refs = control_action.get("process_model_refs")
        if isinstance(refs, list):
            control_action["process_model_refs"] = [
                local_pm_map.get(ref, ref) if isinstance(ref, str) else ref
                for ref in refs
            ]


def _rewrite_coordination_references(
    links: list[Any],
    namespace_maps: dict[str, dict[str, str]],
) -> None:
    """Rewrite coordination references using their source-ID namespaces."""
    resp_map = namespace_maps["responsibility"]
    pm_map = namespace_maps["process_model_part"]
    for link in links:
        _rewrite_coordination_link_references(link, resp_map, pm_map)


def _rewrite_coordination_link_references(
    link: Any,
    responsibility_map: dict[str, str],
    process_model_map: dict[str, str],
) -> None:
    """Rewrite source, target, and shared-PM fields on one coordination link."""
    if not isinstance(link, dict):
        return
    reference_maps = (
        ("source", responsibility_map),
        ("target", responsibility_map),
        ("shared_pm", process_model_map),
    )
    for field_name, source_map in reference_maps:
        old_id = link.get(field_name)
        if isinstance(old_id, str) and old_id in source_map:
            link[field_name] = source_map[old_id]


def _build_source_id_maps(
    payload: dict[str, Any],
) -> tuple[NamespaceEntries, dict[str, dict[str, str]]]:
    """Collect source IDs and build unique maps for each namespace."""
    entries = _source_id_entries(payload)
    maps = {
        namespace: _unique_source_map(source_entries)
        for namespace, source_entries in entries.items()
    }
    return entries, maps


def _build_local_pm_maps(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Build per-responsibility maps for locally scoped PM references."""
    local_maps: list[dict[str, str]] = []
    responsibilities = payload.get("responsibilities", [])
    if not isinstance(responsibilities, list):
        return local_maps

    for resp_index, resp in enumerate(responsibilities, start=1):
        if not isinstance(resp, dict):
            local_maps.append({})
            continue
        entries = _collect_child_source_ids(
            resp.get("process_model_parts", []),
            resp_index,
            "pm_id",
            "PM",
        )
        local_maps.append(_unique_source_map(entries))
    return local_maps


def normalize_control_structure_payload(
    payload: Mapping[str, Any] | BaseModel,
) -> ControlStructureNormalization:
    """Assign canonical IDs and rewrite references in a decoded payload.

    The pass is deliberately performed on dictionaries, before
    :class:`ControlStructure` validation.  It therefore repairs malformed
    source IDs, duplicate IDs, and cross-namespace ID collisions without
    changing list order or non-ID fields.  Locally scoped feedback updates
    are resolved within their responsibility; typed responsibility/process
    references and coordination-link references use unique global source
    IDs.  Ambiguous source IDs are left unchanged so normal validation
    reports them as unresolved.
    """
    normalized = _payload_dict(payload)
    namespace_entries, namespace_maps = _build_source_id_maps(normalized)

    # Keep the source maps available before replacing IDs.  PM maps are
    # intentionally local for feedback updates, because the same PM source
    # ID is valid in separate responsibilities.
    local_pm_maps = _build_local_pm_maps(normalized)

    # Pass order is load-bearing:
    # 1. Wrap recognized bare ElementRef IDs into objects (shape only).
    # 2. Infer missing or invalid types from source-ID prefixes so rewrite
    #    can select a namespace.  Newly wrapped refs need this pass.
    # 3. Rewrite references while source IDs still match those maps.
    # 4. Replace published IDs with structural IDs.
    # 5. Fill empty descriptions from the now-canonical IDs and refs.
    _wrap_bare_string_refs(normalized)
    _repair_element_ref_types(normalized, namespace_maps)
    _rewrite_references_before_id_replacement(
        normalized,
        namespace_maps,
        local_pm_maps,
    )
    _set_canonical_ids(normalized)
    _repair_empty_descriptions(normalized)

    return ControlStructureNormalization(
        payload=normalized,
        mapping=_flat_unique_source_map(namespace_entries),
        mappings=namespace_maps,
    )


def _rewrite_references_before_id_replacement(
    payload: dict[str, Any],
    namespace_maps: dict[str, dict[str, str]],
    local_pm_maps: list[dict[str, str]],
) -> None:
    """Rewrite references while their source IDs still match the maps."""
    _rewrite_responsibility_references_in_payload(
        payload,
        namespace_maps,
        local_pm_maps,
    )
    coordination_links = payload.get("coordination_links", [])
    if isinstance(coordination_links, list):
        _rewrite_coordination_references(coordination_links, namespace_maps)


def _rewrite_responsibility_references_in_payload(
    payload: dict[str, Any],
    namespace_maps: dict[str, dict[str, str]],
    local_pm_maps: list[dict[str, str]],
) -> None:
    """Rewrite references nested under every responsibility."""
    responsibilities = payload.get("responsibilities", [])
    if not isinstance(responsibilities, list):
        return
    for resp_index, resp in enumerate(responsibilities):
        if not isinstance(resp, dict):
            continue
        _rewrite_responsibility_references(
            resp,
            namespace_maps,
            _local_pm_map_for_index(local_pm_maps, resp_index),
        )


def _local_pm_map_for_index(
    local_pm_maps: list[dict[str, str]],
    responsibility_index: int,
) -> dict[str, str]:
    """Return the local PM map for a responsibility, or an empty map."""
    if responsibility_index < len(local_pm_maps):
        return local_pm_maps[responsibility_index]
    return {}


def _set_empty_description(
    element: Any,
    element_type: str,
) -> None:
    """Set a placeholder description for one canonicalized element."""
    if not isinstance(element, dict) or element.get("description") != "":
        return
    type_name, id_key = _DESC_TYPES[element_type]
    element["description"] = f"{type_name} {element.get(id_key)}"


def _fb_text(feedback_channel: dict[str, Any]) -> str:
    """Build a context-based placeholder for one feedback channel."""
    updates = feedback_channel.get("updates")
    if not updates:
        return f"Feedback channel {feedback_channel.get('fb_id')}"

    source = feedback_channel.get("source")
    if isinstance(source, dict):
        source_type = _reference_type_value(source.get("type"))
        source_id = source.get("id")
        if source_type and source_id:
            return (
                f"Feedback from {source_type.replace('_', ' ')} {source_id} "
                f"updating process model part {updates}"
            )
    return f"Feedback updating process model part {updates}"


def _set_feedback_description(feedback_channel: Any) -> None:
    """Set a context-based placeholder for one empty feedback description."""
    if (
        not isinstance(feedback_channel, dict)
        or feedback_channel.get("description") != ""
    ):
        return
    feedback_channel["description"] = _fb_text(feedback_channel)


def _fix_children(children: Any, element_type: str) -> None:
    """Repair descriptions in one responsibility child collection."""
    if not isinstance(children, list):
        return
    for child in children:
        if element_type == "feedback_channel":
            _set_feedback_description(child)
        else:
            _set_empty_description(child, element_type)


def _fix_resps(responsibilities: Any) -> None:
    """Repair descriptions in responsibilities and their children."""
    if not isinstance(responsibilities, list):
        return
    for responsibility in responsibilities:
        if not isinstance(responsibility, dict):
            continue
        _set_empty_description(responsibility, "responsibility")
        for child_key, _id_key, _prefix, element_type in _RESPONSIBILITY_CHILD_SPECS:
            _fix_children(responsibility.get(child_key, []), element_type)


def _fix_list(elements: Any, element_type: str) -> None:
    """Repair descriptions in one top-level element collection."""
    if not isinstance(elements, list):
        return
    for element in elements:
        _set_empty_description(element, element_type)


def _fix_links(links: Any) -> None:
    """Repair coordination-link and mechanism descriptions."""
    if not isinstance(links, list):
        return
    for link in links:
        _set_empty_description(link, "coordination_link")
        if isinstance(link, dict):
            _set_empty_description(
                link.get("coordination_mechanism"),
                "coordination_mechanism",
            )


def _repair_empty_descriptions(payload: dict[str, Any]) -> None:
    """Repair only empty descriptions after IDs and references are canonical."""
    _fix_resps(payload.get("responsibilities", []))
    _fix_list(payload.get("controlled_processes", []), "controlled_process")
    _fix_links(payload.get("coordination_links", []))


def validate_normalized_control_structure(
    payload: Mapping[str, Any] | BaseModel,
) -> ControlStructure:
    """Normalize a decoded structure, then run ControlStructure validation."""
    normalized = normalize_control_structure_payload(payload)
    return ControlStructure.model_validate(normalized.payload)

"""Call 0: provider-authored actor semantic draft protocol and compilation.

This leaf module owns the finite handle inventories, draft response models,
and the deterministic compiler that attaches canonical actor identity and
access provenance.  ``generate.actor`` re-exports every name here so the
historical import surface stays intact; nothing in this module prompts or
calls an LLM.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, create_model, field_validator

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
)
from asago_scenario_generator.pipeline.generate.actor_rules import (
    _ep_controllability_to_ingress_mode,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _CAPABILITY_FLOORS,
    _CAPABILITY_ORDER,
    _INSIDER_ACTOR_TYPES,
)

_ACTOR_DRAFT_MAX_ITEMS = 4
_ACTOR_DRAFT_RATIONALE_MAX_LENGTH = 400
_ACTOR_DRAFT_ITEM_MAX_LENGTH = 200
_ActorDraftItem = Annotated[
    str, Field(min_length=1, max_length=_ACTOR_DRAFT_ITEM_MAX_LENGTH)
]


def _validate_distinct_resource_handles(value: list[str]) -> list[str]:
    """Reject duplicate resource handles in one actor draft."""
    if len(set(value)) != len(value):
        raise ValueError("duplicate resource handle in actor draft")
    return value


class ActorDraftV2(BaseModel):
    """Provider-authored actor semantics without canonical access fields."""

    model_config = ConfigDict(extra="forbid")

    actor_type_handle: str = Field(min_length=1, max_length=32)
    capability_level_handle: str = Field(min_length=1, max_length=32)
    beliefs: list[_ActorDraftItem] = Field(
        min_length=1, max_length=_ACTOR_DRAFT_MAX_ITEMS
    )
    desires: list[_ActorDraftItem] = Field(
        min_length=1, max_length=_ACTOR_DRAFT_MAX_ITEMS
    )
    intentions: list[_ActorDraftItem] = Field(
        min_length=1, max_length=_ACTOR_DRAFT_MAX_ITEMS
    )
    resource_handles: list[Annotated[str, Field(min_length=1, max_length=32)]] = Field(
        default_factory=list, max_length=_ACTOR_DRAFT_MAX_ITEMS
    )
    rationale: str | None = Field(
        default=None, min_length=1, max_length=_ACTOR_DRAFT_RATIONALE_MAX_LENGTH
    )

    _reject_duplicate_resource_handles = field_validator("resource_handles")(
        _validate_distinct_resource_handles
    )


class ActorDraftV3(BaseModel):
    """Provider-authored actor semantics using one compatible pair handle."""

    model_config = ConfigDict(extra="forbid")

    actor_choice_handle: str = Field(min_length=1, max_length=32)
    beliefs: list[_ActorDraftItem] = Field(
        min_length=1, max_length=_ACTOR_DRAFT_MAX_ITEMS
    )
    desires: list[_ActorDraftItem] = Field(
        min_length=1, max_length=_ACTOR_DRAFT_MAX_ITEMS
    )
    intentions: list[_ActorDraftItem] = Field(
        min_length=1, max_length=_ACTOR_DRAFT_MAX_ITEMS
    )
    resource_handles: list[Annotated[str, Field(min_length=1, max_length=32)]] = Field(
        default_factory=list, max_length=_ACTOR_DRAFT_MAX_ITEMS
    )
    rationale: str | None = Field(
        default=None, min_length=1, max_length=_ACTOR_DRAFT_RATIONALE_MAX_LENGTH
    )

    _reject_duplicate_resource_handles = field_validator("resource_handles")(
        _validate_distinct_resource_handles
    )


@dataclass(frozen=True)
class ActorDraftContext:
    """Canonical inventory used to compile one actor semantic draft."""

    actor_types: Mapping[str, str]
    capability_levels: Mapping[str, str]
    resources: Mapping[str, str]
    access: ActorAccessProvenance
    minimum_capability_level: str = "novice"
    actor_choices: Mapping[str, tuple[str, str]] | None = None


@dataclass(frozen=True)
class ActorDraftViolation:
    """Machine-readable actor draft violation for a correction request."""

    code: str
    detail: str


class ActorSemanticDraftError(ValueError):
    """An actor draft cannot be compiled without changing its semantics."""

    def __init__(self, violations: Sequence[ActorDraftViolation]) -> None:
        self.violations = tuple(violations)
        super().__init__("; ".join(item.detail for item in self.violations))


def _literal_from_handles(handles: Sequence[str]) -> Any:
    """Return a runtime ``Literal`` constrained to unique local handles."""
    values = tuple(handles)
    if not values or len(set(values)) != len(values):
        raise ValueError("handle inventory must be non-empty and unique")
    return Literal.__getitem__(values)


def create_actor_draft_model(
    *,
    actor_type_handles: Sequence[str],
    capability_level_handles: Sequence[str],
    resource_handles: Sequence[str] = (),
    compact: bool = False,
) -> type[ActorDraftV2]:
    """Build the finite provider schema for one actor request."""
    actor_handle = _literal_from_handles(actor_type_handles)
    capability_handle = _literal_from_handles(capability_level_handles)
    fields: dict[str, Any] = {
        "actor_type_handle": (actor_handle, ...),
        "capability_level_handle": (capability_handle, ...),
    }
    if resource_handles:
        resource_handle = _literal_from_handles(resource_handles)
        fields["resource_handles"] = (
            list[resource_handle],
            Field(default_factory=list, max_length=_ACTOR_DRAFT_MAX_ITEMS),
        )
    else:
        fields["resource_handles"] = (
            list[Annotated[str, Field(min_length=1, max_length=32)]],
            Field(default_factory=list, max_length=0),
        )
    model_name = (
        "CompactActorDraftV2ForCandidate" if compact else "ActorDraftV2ForCandidate"
    )
    return create_model(model_name, __base__=ActorDraftV2, **fields)


def create_actor_draft_v3_model(
    *,
    actor_choice_handles: Sequence[str],
    resource_handles: Sequence[str] = (),
    compact: bool = False,
) -> type[ActorDraftV3]:
    """Build the finite provider schema for compatible actor choices."""

    choice_handle = _literal_from_handles(actor_choice_handles)
    fields: dict[str, Any] = {"actor_choice_handle": (choice_handle, ...)}
    if resource_handles:
        resource_handle = _literal_from_handles(resource_handles)
        fields["resource_handles"] = (
            list[resource_handle],
            Field(default_factory=list, max_length=_ACTOR_DRAFT_MAX_ITEMS),
        )
    else:
        fields["resource_handles"] = (
            list[Annotated[str, Field(min_length=1, max_length=32)]],
            Field(default_factory=list, max_length=0),
        )
    model_name = (
        "CompactActorDraftV3ForCandidate" if compact else "ActorDraftV3ForCandidate"
    )
    return create_model(model_name, __base__=ActorDraftV3, **fields)


def _resolve_actor_handles(
    context: ActorDraftContext,
    draft: ActorDraftV2 | ActorDraftV3,
    violations: list[ActorDraftViolation],
) -> tuple[str | None, str | None]:
    """Resolve provider handles against the canonical actor inventories."""
    if isinstance(draft, ActorDraftV3):
        choice = (context.actor_choices or {}).get(draft.actor_choice_handle)
        if choice is None:
            violations.append(
                ActorDraftViolation(
                    "unknown_actor_choice_handle",
                    f"unknown actor choice handle '{draft.actor_choice_handle}'",
                )
            )
            return None, None
        return choice
    actor_type = context.actor_types.get(draft.actor_type_handle)
    if actor_type is None:
        violations.append(
            ActorDraftViolation(
                "unknown_actor_type_handle",
                f"unknown actor type handle '{draft.actor_type_handle}'",
            )
        )
    capability_level = context.capability_levels.get(draft.capability_level_handle)
    if capability_level is None:
        violations.append(
            ActorDraftViolation(
                "unknown_capability_level_handle",
                f"unknown capability level handle '{draft.capability_level_handle}'",
            )
        )
    return actor_type, capability_level


def _capability_floor_violation(
    actor_type: str,
    capability_level: str,
    minimum_capability_level: str,
) -> ActorDraftViolation | None:
    """Return the floor violation when capability sits below the required floor."""
    actor_floor = _CAPABILITY_FLOORS.get(actor_type, "novice")
    required_floor = max(
        (actor_floor, minimum_capability_level),
        key=_CAPABILITY_ORDER.index,
    )
    if _CAPABILITY_ORDER.index(capability_level) < _CAPABILITY_ORDER.index(
        required_floor
    ):
        return ActorDraftViolation(
            "capability_below_floor",
            f"actor '{actor_type}' requires capability '{required_floor}' "
            f"or higher, got '{capability_level}'",
        )
    return None


def _capability_floor_violations(
    context: ActorDraftContext,
    actor_type: str | None,
    capability_level: str | None,
) -> list[ActorDraftViolation]:
    """Collect the capability-floor violation for a resolved handle pair."""
    if actor_type is None or capability_level is None:
        return []
    floor_violation = _capability_floor_violation(
        actor_type, capability_level, context.minimum_capability_level
    )
    if floor_violation is None:
        return []
    return [floor_violation]


def _unknown_resource_violations(
    context: ActorDraftContext, draft: ActorDraftV2 | ActorDraftV3
) -> list[ActorDraftViolation]:
    """Collect unknown-resource violations for one actor draft."""
    unknown_resources = [
        handle for handle in draft.resource_handles if handle not in context.resources
    ]
    if not unknown_resources:
        return []
    return [
        ActorDraftViolation(
            "unknown_resource_handle",
            f"unknown resource handle(s): {unknown_resources}",
        )
    ]


def compile_actor_draft(
    context: ActorDraftContext, draft: ActorDraftV2 | ActorDraftV3
) -> ActorProfile:
    """Attach canonical actor choices and access to provider-authored BDI."""
    violations: list[ActorDraftViolation] = []
    actor_type, capability_level = _resolve_actor_handles(context, draft, violations)
    violations.extend(
        _capability_floor_violations(context, actor_type, capability_level)
    )
    violations.extend(_unknown_resource_violations(context, draft))
    if violations:
        raise ActorSemanticDraftError(violations)

    # The checks above prove these lookups succeeded. Keeping canonical
    # resolution here (rather than normalizing provider strings) makes the
    # ownership rule visible and fail-closed.
    assert actor_type is not None
    assert capability_level is not None
    return ActorProfile(
        actor_type=actor_type,
        capability_level=capability_level,
        beliefs=list(draft.beliefs),
        desires=list(draft.desires),
        intentions=list(draft.intentions),
        resources=[context.resources[handle] for handle in draft.resource_handles],
        access=context.access.model_copy(deep=True),
    )


def _compatible_actor_types_for_projection(
    prompt_context: Mapping[str, Any],
    projection_context: Mapping[str, Any],
) -> list[str]:
    """Narrow the compatible actor pool to canonical direct-access provenance."""
    compatible_actor_types = list(prompt_context["compatible_actor_types"])
    if projection_context.get("ingress_controllability") == "direct":
        compatible_actor_types = [
            actor_type
            for actor_type in compatible_actor_types
            if actor_type not in _INSIDER_ACTOR_TYPES
        ]
    if not compatible_actor_types:
        raise ValueError(
            "projection has no actor type with canonical direct-access provenance"
        )
    return compatible_actor_types


def _capability_level_inventory(
    prompt_context: Mapping[str, Any],
) -> dict[str, str]:
    """Allocate deterministic capability handles from the minimum floor onward."""
    minimum = prompt_context.get("minimum_capability_level", "novice")
    minimum_index = (
        _CAPABILITY_ORDER.index(minimum) if minimum in _CAPABILITY_ORDER else 0
    )
    return {
        f"c{index}": level
        for index, level in enumerate(_CAPABILITY_ORDER[minimum_index:])
    }


def _resource_reference_name(
    reference: Mapping[str, Any], profile: CapabilityProfile
) -> str | None:
    """Resolve one resource reference to its display name for actor drafts."""
    from asago_scenario_generator.pipeline.generate.names import (
        resource_name_for_kind,
    )

    kind = reference.get("kind")
    if kind == "agent_internal":
        return "agent internal working context"
    resource_id = next(
        (
            value
            for key, value in reference.items()
            if key.endswith("_id") and isinstance(value, str)
        ),
        None,
    )
    if resource_id is None:
        return None
    return resource_name_for_kind(kind, resource_id, profile)


def _attacker_controlled_resource_names(
    step: Mapping[str, Any], profile: CapabilityProfile
) -> list[str]:
    """Collect distinct resource names from one attacker-controlled step."""
    names: list[str] = []
    for link in step.get("resource_links", []):
        reference = link.get("resource_ref")
        if not isinstance(reference, dict):
            continue
        name = _resource_reference_name(reference, profile)
        if name is not None and name not in names:
            names.append(name)
    return names


def _selected_step_resource_names(
    projection_context: Mapping[str, Any], profile: CapabilityProfile
) -> list[str]:
    """Collect distinct attacker-controlled resource names from selected steps."""
    resource_names: list[str] = []
    for step in projection_context.get("selected_steps", []):
        if not step.get("attacker_controlled", False):
            continue
        for name in _attacker_controlled_resource_names(step, profile):
            if name not in resource_names:
                resource_names.append(name)
    return resource_names


def _actor_draft_inventories(
    prompt_context: Mapping[str, Any],
    projection_context: dict[str, Any],
    profile: CapabilityProfile,
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Allocate deterministic local handles for one actor request."""
    compatible_actor_types = _compatible_actor_types_for_projection(
        prompt_context, projection_context
    )
    actor_types = {
        f"a{index}": actor_type
        for index, actor_type in enumerate(compatible_actor_types)
    }
    capability_levels = _capability_level_inventory(prompt_context)
    resource_names = _selected_step_resource_names(projection_context, profile)
    resources = {f"r{index}": name for index, name in enumerate(resource_names)}
    return actor_types, capability_levels, resources


def _actor_choice_inventory(
    actor_types: Mapping[str, str], capability_levels: Mapping[str, str]
) -> dict[str, tuple[str, str]]:
    """Allocate handles only for compatible actor/capability pairs."""

    choices: dict[str, tuple[str, str]] = {}
    for actor_type in actor_types.values():
        actor_floor = _CAPABILITY_FLOORS.get(actor_type, "novice")
        floor_index = _CAPABILITY_ORDER.index(actor_floor)
        for capability_level in capability_levels.values():
            if _CAPABILITY_ORDER.index(capability_level) < floor_index:
                continue
            choices[f"ac{len(choices)}"] = (actor_type, capability_level)
    if not choices:
        raise ValueError("projection has no compatible actor/capability choice")
    return choices


def _derive_direct_actor_access(
    entry_point_id: str, actor_type: str
) -> ActorAccessProvenance:
    """Derive direct public-access provenance or reject insider actors."""
    if actor_type in _INSIDER_ACTOR_TYPES:
        raise ValueError("projection supplies no canonical material insider advantage")
    return ActorAccessProvenance(
        initial_entry_point_id=entry_point_id,
        ingress_mode="direct",
        access_class="public",
    )


def _derive_indirect_actor_access(
    projection_context: dict[str, Any], entry_point_id: str
) -> ActorAccessProvenance:
    """Derive supply-chain access from the single canonical influence path."""
    paths = projection_context.get("source_influence_paths", [])
    if len(paths) != 1:
        raise ValueError(
            "indirect projection must contain exactly one source-influence path"
        )
    path = paths[0]
    source_id = path.get("source_id")
    source_kind = path.get("source_identity_kind")
    boundary_id = path.get("boundary_id")
    if not all(
        isinstance(value, str) for value in (source_id, source_kind, boundary_id)
    ):
        raise ValueError("indirect projection has incomplete canonical access path")
    return ActorAccessProvenance(
        initial_entry_point_id=entry_point_id,
        ingress_mode="indirect",
        access_class="supply_chain",
        influence_source=source_id,
        influence_source_kind=source_kind,
        influence_source_id=source_id,
        influence_mechanism="Declared canonical upstream influence path",
        trust_boundary_id=boundary_id,
    )


def _derive_canonical_actor_access(
    projection_context: dict[str, Any], actor_type: str
) -> ActorAccessProvenance:
    """Derive access provenance solely from the accepted projection."""
    ingress = projection_context.get("canonical_ingress", {})
    entry_point_id = ingress.get("entry_point_id")
    if not isinstance(entry_point_id, str):
        raise ValueError("projection lacks a canonical ingress entry-point ID")
    ingress_mode = _ep_controllability_to_ingress_mode(
        projection_context.get("ingress_controllability")
    )
    if ingress_mode is None:
        raise ValueError("projection lacks attacker-accessible ingress controllability")

    if ingress_mode == "direct":
        return _derive_direct_actor_access(entry_point_id, actor_type)
    return _derive_indirect_actor_access(projection_context, entry_point_id)


def _actor_draft_prompt(
    actor_choices: Mapping[str, tuple[str, str]],
    resources: Mapping[str, str],
) -> str:
    """Render the concise V3 handle protocol appended to the semantic prompt."""
    lines = [
        "\n\n## Semantic Draft V3 Response Protocol (MANDATORY)",
        "Return one actor_choice_handle from the compatible inventory.",
        "The application owns access provenance; do not return access fields or IDs.",
        "Author all beliefs, desires, and intentions yourself.",
        "Compatible actor/capability choices:",
        *(
            f"- {handle}: actor={actor_type}; capability={capability_level}"
            for handle, (actor_type, capability_level) in actor_choices.items()
        ),
        "Resource handles (select zero to four; do not invent resources):",
        *(
            (f"- {handle}: {value}" for handle, value in resources.items())
            if resources
            else ("- none available; return an empty resource_handles list",)
        ),
    ]
    return "\n".join(lines)


def _compile_projected_actor_draft(
    *,
    resp: ActorDraftV2 | ActorDraftV3,
    actor_types: Mapping[str, str],
    capability_levels: Mapping[str, str],
    resources: Mapping[str, str],
    actor_choices: Mapping[str, tuple[str, str]],
    minimum_capability_level: str,
    projection_context: dict[str, Any],
) -> ActorProfile:
    """Compile one projected semantic draft with canonical actor identity."""
    if isinstance(resp, ActorDraftV3):
        choice = actor_choices.get(resp.actor_choice_handle)
        actor_type = choice[0] if choice is not None else None
        unknown_detail = f"unknown actor choice handle '{resp.actor_choice_handle}'"
        unknown_code = "unknown_actor_choice_handle"
    else:
        actor_type = actor_types.get(resp.actor_type_handle)
        unknown_detail = f"unknown actor type handle '{resp.actor_type_handle}'"
        unknown_code = "unknown_actor_type_handle"
    if actor_type is None:
        raise ActorSemanticDraftError(
            (
                ActorDraftViolation(
                    unknown_code,
                    unknown_detail,
                ),
            )
        )
    access = _derive_canonical_actor_access(projection_context, actor_type)
    return compile_actor_draft(
        ActorDraftContext(
            actor_types=actor_types,
            capability_levels=capability_levels,
            resources=resources,
            access=access,
            minimum_capability_level=minimum_capability_level,
            actor_choices=actor_choices,
        ),
        resp,
    )

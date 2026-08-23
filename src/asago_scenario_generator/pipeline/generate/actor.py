"""Call 0: Actor Profile generation logic."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, create_model, field_validator

from asago_scenario_generator.llm.client import (
    LengthFinishReasonError as LengthFinishReasonError,
    LLMClient,
    LLMResult,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.models.scenario import (
    ACTOR_TYPES,
    ActorAccessProvenance,
    ActorProfile,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _ADVERSARIAL_INTENTION_KEYWORDS,
    _CAPABILITY_FLOORS,
    _CAPABILITY_ORDER,
    _INSIDER_ACTOR_TYPES,
)
from asago_scenario_generator.pipeline.generate.actor_rules import (
    _ep_controllability_to_ingress_mode,
)

# Preserve the historical actor-module import surface while policy lives in
# the cycle-free actor_rules leaf.
from asago_scenario_generator.pipeline.generate.actor_rules import (
    _max_capability_level,  # noqa: F401
    compute_compatible_actor_types,  # noqa: F401
    compute_minimum_capability_level,  # noqa: F401
)
from asago_scenario_generator.pipeline.generate.actor_context import (
    build_call0_context,
)
from asago_scenario_generator.pipeline.generate.ontology import (
    _lookup_entry_point_controllability,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.prompts import render_prompt

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Intermediate model for structured output
# ---------------------------------------------------------------------------

# Conservative static bounds for every generated Call 0 field.  The schema
# is sent to the provider (response_format), so finite maxima keep
# completion-length risk bounded without reducing the operator-configured
# completion limit.
_CALL0_LIST_MAX_ITEMS = 8
_CALL0_ITEM_MAX_LENGTH = 200
_CALL0_ENUM_MAX_LENGTH = 64
_CALL0_EVIDENCE_MAX_LENGTH = 300

_Call0Item = Annotated[str, Field(min_length=1, max_length=_CALL0_ITEM_MAX_LENGTH)]


# The V2 protocol is deliberately separate from the legacy Call0 transport.
# It is the provider/compiler seam for projected non-STPA candidates: the
# provider authors bounded semantics using request-local handles, and the
# compiler is the only place that can attach canonical values.
_ACTOR_DRAFT_MAX_ITEMS = 4
_ACTOR_DRAFT_RATIONALE_MAX_LENGTH = 400
_ActorDraftItem = Annotated[str, Field(min_length=1, max_length=_CALL0_ITEM_MAX_LENGTH)]


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

    @field_validator("resource_handles")
    @classmethod
    def _reject_duplicate_resource_handles(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate resource handle in actor draft")
        return value


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

    @field_validator("resource_handles")
    @classmethod
    def _reject_duplicate_resource_handles(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate resource handle in actor draft")
        return value


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


def compile_actor_draft(
    context: ActorDraftContext, draft: ActorDraftV2 | ActorDraftV3
) -> ActorProfile:
    """Attach canonical actor choices and access to provider-authored BDI."""
    violations: list[ActorDraftViolation] = []
    if isinstance(draft, ActorDraftV3):
        choice = (context.actor_choices or {}).get(draft.actor_choice_handle)
        if choice is None:
            violations.append(
                ActorDraftViolation(
                    "unknown_actor_choice_handle",
                    f"unknown actor choice handle '{draft.actor_choice_handle}'",
                )
            )
            actor_type = None
            capability_level = None
        else:
            actor_type, capability_level = choice
    else:
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
                    f"unknown capability level handle "
                    f"'{draft.capability_level_handle}'",
                )
            )
    if actor_type is not None and capability_level is not None:
        actor_floor = _CAPABILITY_FLOORS.get(actor_type, "novice")
        required_floor = max(
            (actor_floor, context.minimum_capability_level),
            key=_CAPABILITY_ORDER.index,
        )
        if _CAPABILITY_ORDER.index(capability_level) < _CAPABILITY_ORDER.index(
            required_floor
        ):
            violations.append(
                ActorDraftViolation(
                    "capability_below_floor",
                    f"actor '{actor_type}' requires capability '{required_floor}' "
                    f"or higher, got '{capability_level}'",
                )
            )
    unknown_resources = [
        handle for handle in draft.resource_handles if handle not in context.resources
    ]
    if unknown_resources:
        violations.append(
            ActorDraftViolation(
                "unknown_resource_handle",
                f"unknown resource handle(s): {unknown_resources}",
            )
        )
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


def _actor_draft_inventories(
    prompt_context: Mapping[str, Any],
    projection_context: dict[str, Any],
    profile: CapabilityProfile,
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Allocate deterministic local handles for one actor request."""
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
    actor_types = {
        f"a{index}": actor_type
        for index, actor_type in enumerate(compatible_actor_types)
    }
    minimum = prompt_context.get("minimum_capability_level", "novice")
    minimum_index = (
        _CAPABILITY_ORDER.index(minimum) if minimum in _CAPABILITY_ORDER else 0
    )
    capability_levels = {
        f"c{index}": level
        for index, level in enumerate(_CAPABILITY_ORDER[minimum_index:])
    }

    from asago_scenario_generator.pipeline.generate.names import (
        resource_name_for_kind,
    )

    resource_names: list[str] = []
    for step in projection_context.get("selected_steps", []):
        if not step.get("attacker_controlled", False):
            continue
        for link in step.get("resource_links", []):
            reference = link.get("resource_ref")
            if not isinstance(reference, dict):
                continue
            kind = reference.get("kind")
            if kind == "agent_internal":
                name = "agent internal working context"
            else:
                resource_id = next(
                    (
                        value
                        for key, value in reference.items()
                        if key.endswith("_id") and isinstance(value, str)
                    ),
                    None,
                )
                if resource_id is None:
                    continue
                name = resource_name_for_kind(kind, resource_id, profile)
            if name not in resource_names:
                resource_names.append(name)
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
        is_insider = actor_type in _INSIDER_ACTOR_TYPES
        if is_insider:
            raise ValueError(
                "projection supplies no canonical material insider advantage"
            )
        return ActorAccessProvenance(
            initial_entry_point_id=entry_point_id,
            ingress_mode="direct",
            access_class="public",
        )

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


class Call0Response(BaseModel):
    """LLM response model for Call 0: Actor Profile."""

    actor_type: str = Field(max_length=_CALL0_ENUM_MAX_LENGTH)
    capability_level: str = Field(max_length=_CALL0_ENUM_MAX_LENGTH)
    beliefs: list[_Call0Item] = Field(
        max_length=_CALL0_LIST_MAX_ITEMS,
        description="Attacker beliefs; bounded list of concise strings.",
    )
    desires: list[_Call0Item] = Field(
        max_length=_CALL0_LIST_MAX_ITEMS,
        description="Attacker desires; bounded list of concise strings.",
    )
    intentions: list[_Call0Item] = Field(
        max_length=_CALL0_LIST_MAX_ITEMS,
        description="Attacker intentions; bounded list of concise strings.",
    )
    resources: list[_Call0Item] = Field(
        max_length=_CALL0_LIST_MAX_ITEMS,
        description="Attacker resources; bounded list of concise strings.",
    )
    # cmps.6 access provenance evidence (LLM-generated, validated post-hoc)
    access_class: str | None = Field(default=None, max_length=_CALL0_ENUM_MAX_LENGTH)
    influence_source: str | None = Field(
        default=None, max_length=_CALL0_EVIDENCE_MAX_LENGTH
    )
    influence_mechanism: str | None = Field(
        default=None, max_length=_CALL0_EVIDENCE_MAX_LENGTH
    )
    trust_boundary_id: str | None = Field(
        default=None, max_length=_CALL0_EVIDENCE_MAX_LENGTH
    )
    material_insider_advantage: str | None = Field(
        default=None, max_length=_CALL0_EVIDENCE_MAX_LENGTH
    )


class CompactCall0Response(Call0Response):
    """Provider schema name for the one causal compact-response experiment."""


# ---------------------------------------------------------------------------
# Normalization and validation helpers
# ---------------------------------------------------------------------------


def _normalize_actor_type(raw: str) -> str:
    """Normalize LLM-generated actor_type to a valid ActorType value.

    Handles cases where the LLM adds parenthetical qualifiers, e.g.
    "Nation-State (Information Warfare Unit)" -> "nation-state".
    """
    cleaned = raw.strip().lower().split("(")[0].strip()
    for valid in ACTOR_TYPES:
        if cleaned == valid or cleaned.replace(" ", "-") == valid:
            return valid
    # Substring match as last resort
    for valid in ACTOR_TYPES:
        if valid in cleaned or cleaned in valid:
            return valid
    logger.warning(
        "Unrecognized actor_type '%s', defaulting to 'adversarial-user'", raw
    )
    return "adversarial-user"


def _normalize_capability_level(raw: str) -> str:
    """Normalize LLM-generated capability_level to a valid value."""
    cleaned = raw.strip().lower().split("(")[0].strip()
    valid_levels = ("novice", "intermediate", "advanced", "expert")
    for level in valid_levels:
        if level in cleaned:
            return level
    logger.warning(
        "Unrecognized capability_level '%s', defaulting to 'intermediate'", raw
    )
    return "intermediate"


def _enforce_capability_floor(actor_type: str, capability_level: str) -> str:
    """Bump capability_level up to the actor-type floor if it is too low.

    Returns the (possibly upgraded) capability level.
    """
    floor = _CAPABILITY_FLOORS.get(actor_type)
    if floor is None:
        return capability_level
    floor_idx = _CAPABILITY_ORDER.index(floor)
    current_idx = (
        _CAPABILITY_ORDER.index(capability_level)
        if capability_level in _CAPABILITY_ORDER
        else 1  # default to intermediate if unknown
    )
    if current_idx < floor_idx:
        logger.warning(
            "Capability floor violation: %s actor had '%s', bumped to '%s'",
            actor_type,
            capability_level,
            floor,
        )
        return floor
    return capability_level


def _validate_actor_type(actor_profile: ActorProfile) -> ActorProfile:
    """Validate that a negligent-insider's BDI profile is non-adversarial.

    If the actor_type is ``negligent-insider`` but the intentions list contains
    adversarial keywords (e.g. "exploit", "jailbreak"), the actor is
    reassigned to ``adversarial-user`` and a warning is logged.  This is a
    defence-in-depth check behind the prompt reinforcement in
    ``call0_system.j2``.

    Returns the (possibly corrected) actor profile.
    """
    if actor_profile.actor_type != "negligent-insider":
        return actor_profile

    matched: list[str] = []
    for intention in actor_profile.intentions:
        intention_lower = intention.lower()
        for keyword in _ADVERSARIAL_INTENTION_KEYWORDS:
            if re.search(r"\b" + re.escape(keyword) + r"\b", intention_lower):
                matched.append(keyword)

    if matched:
        unique_matches = sorted(set(matched))
        logger.warning(
            "BDI validation: negligent-insider intentions contain adversarial "
            "keywords %s — reassigning to adversarial-user",
            unique_matches,
        )
        actor_profile = actor_profile.model_copy(
            update={"actor_type": "adversarial-user"},
        )
    return actor_profile


# ---------------------------------------------------------------------------#
# Actor access provenance (cmps.6)
# ---------------------------------------------------------------------------#


@dataclass
class ActorAccessViolation:
    """A single actor/access provenance violation detected during generation."""

    rule: str
    message: str


def build_actor_access_provenance(
    entry_point_id: str,
    ep_controllability: str | None,
    actor_type: str,
    resp: Call0Response,
    profile: CapabilityProfile | None = None,
    projection_context: dict[str, Any] | None = None,
) -> ActorAccessProvenance:
    """Construct an :class:`ActorAccessProvenance` from canonical EP identity
    and LLM-generated evidence.

    ``ingress_mode`` is derived from the entry point's canonical
    ``effective_controllability`` — never LLM-inferred.  ``access_class``
    and the evidence fields are taken from the LLM response.

    Phase 3: The LLM now outputs human-readable names for
    ``influence_source`` and ``trust_boundary_id``.  When *profile* is
    supplied, these names are resolved to canonical hex IDs before
    constructing the provenance object.

    When *projection_context* is supplied with exactly one authoritative
    source-influence path, the typed source reference, kind, and trust
    boundary are taken from the projection — the model does not choose the
    canonical IDs.  Otherwise the LLM response fields (after name
    resolution) are used.

    Unresolved/system controllability raises ``ValueError`` — system entry
    points are not eligible ingress and must never default to direct.
    """
    ingress_mode = _ep_controllability_to_ingress_mode(ep_controllability)
    if ingress_mode is None:
        raise ValueError(
            f"Entry point '{entry_point_id}' has effective controllability "
            f"'{ep_controllability}' — not eligible ingress (system/unknown)."
        )

    # Phase 3: resolve LLM-output names to canonical hex IDs
    influence_source = resp.influence_source
    influence_source_kind: str | None = None
    influence_source_id: str | None = None
    trust_boundary_id = resp.trust_boundary_id

    authoritative_paths = (
        projection_context.get("source_influence_paths", [])
        if projection_context is not None
        else []
    )
    if projection_context is not None:
        if authoritative_paths:
            if len(authoritative_paths) != 1:
                raise ValueError(
                    "projection context must contain exactly one source-influence path"
                )
            path = authoritative_paths[0]
            influence_source = path.get("source_id")
            influence_source_kind = path.get("source_identity_kind")
            influence_source_id = path.get("source_id")
            trust_boundary_id = path.get("boundary_id")
    elif profile is not None:
        from asago_scenario_generator.pipeline.generate.names import (
            resolve_name_to_entry_point_id,
            resolve_name_to_trust_boundary_id,
        )

        if influence_source:
            resolved = resolve_name_to_entry_point_id(influence_source, profile)
            if resolved is not None:
                influence_source = resolved
        if trust_boundary_id:
            resolved_tb = resolve_name_to_trust_boundary_id(trust_boundary_id, profile)
            if resolved_tb is not None:
                trust_boundary_id = resolved_tb

    return ActorAccessProvenance(
        initial_entry_point_id=entry_point_id,
        ingress_mode=ingress_mode,
        access_class=resp.access_class,
        influence_source=influence_source,
        influence_source_kind=influence_source_kind,
        influence_source_id=influence_source_id,
        influence_mechanism=resp.influence_mechanism,
        trust_boundary_id=trust_boundary_id,
        material_insider_advantage=resp.material_insider_advantage,
    )


def _canonical_checks(
    violations: list[ActorAccessViolation],
    access: ActorAccessProvenance,
    actor_type: str,
    profile: CapabilityProfile,
) -> None:
    """Populate *violations* with canonical-profile resolution checks.

    Pure function — no I/O, no logging.  Separated from
    :func:`validate_actor_access_provenance` so it can be unit-tested
    in isolation and reused by semantic validation.
    """
    # 5. Resolve initial entry point — must be eligible ingress.
    initial_ep = profile.resolve_entry_point(access.initial_entry_point_id)
    if initial_ep is None:
        violations.append(
            ActorAccessViolation(
                rule="unresolved_entry_point_id",
                message=(
                    f"initial_entry_point_id "
                    f"'{access.initial_entry_point_id}' does not resolve "
                    f"to any entry point in the capability profile."
                ),
            )
        )
        # Cannot continue canonical checks without the initial EP.
        return

    if not is_attacker_accessible_ingress(
        initial_ep,
        set(profile.zones_active) if profile.zones_active else set(),
    ):
        violations.append(
            ActorAccessViolation(
                rule="ineligible_ingress_entry_point",
                message=(
                    f"initial_entry_point_id "
                    f"'{access.initial_entry_point_id}' resolves to "
                    f"'{initial_ep.name}' which is not an attacker-"
                    f"accessible ingress route."
                ),
            )
        )

    # 5b. effective_controllability must match the declared ingress_mode.
    _ep_ctrl = initial_ep.effective_controllability
    if _ep_ctrl == "system":
        violations.append(
            ActorAccessViolation(
                rule="system_entry_point_as_ingress",
                message=(
                    f"initial_entry_point_id "
                    f"'{access.initial_entry_point_id}' has effective "
                    f"controllability 'system' — not eligible ingress."
                ),
            )
        )
    elif _ep_ctrl != access.ingress_mode:
        violations.append(
            ActorAccessViolation(
                rule="ingress_mode_controllability_mismatch",
                message=(
                    f"ingress_mode '{access.ingress_mode}' does not match "
                    f"the entry point's effective controllability "
                    f"'{_ep_ctrl}' (entry_point_id "
                    f"'{access.initial_entry_point_id}')."
                ),
            )
        )

    # 6–8. Indirect ingress canonical relation checks.
    if access.ingress_mode != "indirect":
        return

    # The legacy influence_source field remains accepted, but the typed
    # source kind/ID pair is authoritative when present.
    source_id = access.influence_source_id or access.influence_source
    source_kind = access.influence_source_kind or "entry_point"
    if not source_id or not source_id.strip():
        return  # Already flagged as missing in structural checks.

    source_ep = None
    if source_kind == "integration":
        if profile.resolve_integration(source_id) is None:
            violations.append(
                ActorAccessViolation(
                    rule="unresolved_influence_source",
                    message=(
                        f"influence_source '{source_id}' does not resolve "
                        "to an integration in the capability profile."
                    ),
                )
            )
            return
    else:
        source_ep = profile.resolve_entry_point(source_id)
        if source_ep is None:
            violations.append(
                ActorAccessViolation(
                    rule="unresolved_influence_source",
                    message=(
                        f"influence_source '{source_id}' does not resolve "
                        f"to any entry point in the capability profile."
                    ),
                )
            )
            return

        # 6a. No self-relation — source must differ from initial ingress.
        if source_ep.entry_point_id == initial_ep.entry_point_id:
            violations.append(
                ActorAccessViolation(
                    rule="self_relation_influence_source",
                    message=(
                        f"influence_source '{source_id}' is the same entry "
                        f"point as the initial ingress "
                        f"'{access.initial_entry_point_id}' — no declared "
                        f"self-relation model accepts this (cmps.6)."
                    ),
                )
            )
            return

        # 6b. Source must be attacker-accessible (not output-only or system).
        if source_ep.direction == "output":
            violations.append(
                ActorAccessViolation(
                    rule="output_influence_source",
                    message=(
                        f"influence_source '{source_id}' resolves "
                        f"to '{source_ep.name}' which is output-only — an "
                        f"output channel cannot be an actor-controlled "
                        f"influence source."
                    ),
                )
            )
        if source_ep.effective_controllability == "system":
            violations.append(
                ActorAccessViolation(
                    rule="system_influence_source",
                    message=(
                        f"influence_source '{source_id}' resolves "
                        f"to '{source_ep.name}' which is system-controlled — "
                        f"not an actor-accessible influence source."
                    ),
                )
            )

    # 7. trust_boundary_id must resolve to a declared TrustBoundary.
    if not access.trust_boundary_id or not access.trust_boundary_id.strip():
        return  # Already flagged as missing in structural checks.

    boundary = profile.resolve_trust_boundary(access.trust_boundary_id)
    if boundary is None:
        violations.append(
            ActorAccessViolation(
                rule="unresolved_trust_boundary",
                message=(
                    f"trust_boundary_id '{access.trust_boundary_id}' does "
                    f"not resolve to any TrustBoundary in the capability "
                    f"profile — fabricated boundaries are not accepted."
                ),
            )
        )
        return

    # 7a. Boundary to_zone must match the initial EP's effective_ingress_zone.
    initial_zone = initial_ep.effective_ingress_zone
    if initial_zone is not None and boundary.to_zone != initial_zone:
        violations.append(
            ActorAccessViolation(
                rule="trust_boundary_target_zone_mismatch",
                message=(
                    f"trust_boundary_id '{access.trust_boundary_id}' has "
                    f"to_zone '{boundary.to_zone}' but the initial entry "
                    f"point '{initial_ep.name}' has effective_ingress_zone "
                    f"'{initial_zone}' — boundary must target the initial "
                    f"ingress zone."
                ),
            )
        )

    # 7b. Boundary from_zone must correspond to the source EP's
    #      effective_ingress_zone or an explicitly modeled external zone.
    #      External integration sources model their own zones; only
    #      entry-point sources are zone-checked here.
    source_zone = source_ep.effective_ingress_zone if source_ep is not None else None
    if (
        source_ep is not None
        and source_zone is not None
        and boundary.from_zone != source_zone
        and boundary.from_zone != "external"
    ):
        violations.append(
            ActorAccessViolation(
                rule="trust_boundary_source_zone_mismatch",
                message=(
                    f"trust_boundary_id '{access.trust_boundary_id}' "
                    f"has from_zone '{boundary.from_zone}' but the "
                    f"influence source '{source_ep.name}' has "
                    f"effective_ingress_zone '{source_zone}' — boundary "
                    f"source side must correspond to the influence "
                    f"source zone or 'external'."
                ),
            )
        )

    # 8. Declared profile flow: the boundary must connect source→initial
    #    ingress zones, proving a declared profile flow rather than a
    #    fabricated relation.  If the boundary's from_zone is "external",
    #    the source EP must have indirect controllability (upstream data
    #    provider).  This is the relational proof — not just ID format.
    if (
        source_ep is not None
        and boundary.from_zone == "external"
        and source_ep.effective_controllability != "indirect"
    ):
        violations.append(
            ActorAccessViolation(
                rule="external_boundary_source_not_indirect",
                message=(
                    f"trust_boundary_id '{access.trust_boundary_id}' "
                    f"has from_zone 'external' but influence source "
                    f"'{source_ep.name}' has effective controllability "
                    f"'{source_ep.effective_controllability}' — external "
                    f"boundary source requires an indirect-controllable "
                    f"upstream entry point."
                ),
            )
        )


def validate_actor_access_provenance(
    actor_profile: ActorProfile,
    profile: CapabilityProfile | None = None,
) -> list[ActorAccessViolation]:
    """Validate typed access provenance evidence on an actor profile.

    Returns a list of violations (empty if valid).  This replaces keyword-
    based insider access checks and blanket allowlists with structured
    access provenance grounded in the canonical entry-point identity
    (cmps.6).

    Checks (structural — no profile needed):
    1. ``access`` provenance must be present.
    2. ``ingress_mode`` / ``access_class`` consistency (e.g. supply_chain
       access with direct ingress is inconsistent; public access with
       indirect ingress is inconsistent).
    3. Indirect ingress requires ``influence_source``,
       ``influence_mechanism``, and ``trust_boundary_id``.
    4. Insider actors using ``direct`` ingress require
       ``material_insider_advantage`` regardless of ``access_class`` —
       enum choice is not evidence.

    Checks (canonical — when *profile* is supplied):
    5. ``initial_entry_point_id`` must resolve to an eligible ingress EP.
       Its ``effective_controllability`` must match the declared
       ``ingress_mode`` and must not be ``system`` (unresolved/system
       fails, never defaults to direct).
    6. ``influence_source`` must resolve to a **different** canonical EP
       (no self-relation unless explicitly modeled).  The source EP must
       be attacker-accessible (not output-only or system-controlled).
    7. ``trust_boundary_id`` must resolve to a ``TrustBoundary`` declared
       in the profile.  The boundary's ``to_zone`` must equal the initial
       EP's ``effective_ingress_zone``.  The boundary's ``from_zone`` must
       correspond to the source EP's ``effective_ingress_zone`` or an
       explicitly modeled external relation (``external`` zone).
    8. There must be a declared profile flow connecting
       source→boundary→initial-ingress; profiles lacking enough data fail
       explicitly (partial), never silently infer the relation.
    """
    violations: list[ActorAccessViolation] = []

    access = actor_profile.access
    if access is None:
        violations.append(
            ActorAccessViolation(
                rule="missing_access_provenance",
                message=(
                    f"Actor '{actor_profile.actor_type}' has no typed access "
                    f"provenance (cmps.6)."
                ),
            )
        )
        return violations

    # 2. Ingress-mode / access-class consistency
    if access.ingress_mode == "direct" and access.access_class == "supply_chain":
        violations.append(
            ActorAccessViolation(
                rule="access_class_ingress_mode_incompatible",
                message=(
                    f"Actor '{actor_profile.actor_type}' has access_class "
                    f"'supply_chain' but ingress_mode 'direct' — supply-chain "
                    f"access requires indirect ingress (upstream influence)."
                ),
            )
        )
    if access.ingress_mode == "indirect" and access.access_class == "public":
        violations.append(
            ActorAccessViolation(
                rule="access_class_ingress_mode_incompatible",
                message=(
                    f"Actor '{actor_profile.actor_type}' has access_class "
                    f"'public' but ingress_mode 'indirect' — public access "
                    f"cannot influence upstream data sources."
                ),
            )
        )

    # 3. Indirect ingress evidence completeness
    if access.ingress_mode == "indirect":
        missing = []
        if not access.influence_source or not access.influence_source.strip():
            missing.append("influence_source")
        if not access.influence_mechanism or not access.influence_mechanism.strip():
            missing.append("influence_mechanism")
        if not access.trust_boundary_id or not access.trust_boundary_id.strip():
            missing.append("trust_boundary_id")
        if missing:
            violations.append(
                ActorAccessViolation(
                    rule="incomplete_indirect_evidence",
                    message=(
                        f"Indirect ingress requires structured evidence: "
                        f"missing {missing}."
                    ),
                )
            )

    # 4. Insider + direct ingress → material_insider_advantage (regardless
    #    of access_class — enum choice is not evidence).
    if (
        access.ingress_mode == "direct"
        and actor_profile.actor_type in _INSIDER_ACTOR_TYPES
        and (
            not access.material_insider_advantage
            or not access.material_insider_advantage.strip()
        )
    ):
        violations.append(
            ActorAccessViolation(
                rule="missing_insider_advantage",
                message=(
                    f"Insider actor '{actor_profile.actor_type}' using "
                    f"direct ingress requires structured "
                    f"material_insider_advantage evidence regardless of "
                    f"access_class ('{access.access_class}') — enum choice "
                    f"is not evidence (cmps.6)."
                ),
            )
        )

    # 5–8. Canonical resolution (when profile is provided)
    if profile is not None:
        _canonical_checks(violations, access, actor_profile.actor_type, profile)

    return violations


# ---------------------------------------------------------------------------
# Context builder and LLM call
# ---------------------------------------------------------------------------


def _complete_actor_profile(
    client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    *,
    compact_response_schema: bool = False,
    response_format: type[BaseModel] | None = None,
    max_completion_tokens: int | None = None,
) -> LLMResult:
    """Complete Call 0 exactly once with the operator-configured limit.

    Length exhaustion is normalized by the shared adapter into typed
    ``CompletionLengthError`` evidence; this helper never retries.
    Retry ownership belongs to the finalization lifecycle.
    """
    effective_max = (
        max_completion_tokens
        if max_completion_tokens is not None
        else client.max_completion_tokens
    )
    return client.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format
        or (CompactCall0Response if compact_response_schema else Call0Response),
        max_completion_tokens=effective_max,
    )


def _call_actor_profile(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    preferred_actor_type: str | None = None,
    excluded_actor_types: list[str] | None = None,
    preferred_capability_level: str | None = None,
    attack_goal: dict[str, Any] | None = None,
    pinned_technique_ids: list[str] | None = None,
    forced_actor_type: str | None = None,
    pinned_entry_point: str | None = None,
    pinned_entry_point_id: str | None = None,
    access_feedback: str | None = None,
    completion_length_feedback: str | None = None,
    compact_response_schema: bool = False,
    max_completion_tokens: int | None = None,
    projection_context: dict[str, Any] | None = None,
) -> tuple[ActorProfile, LLMResult, str | None]:
    """Generate a threat actor profile for a scenario seed (Call 0).

    Delegates context building to :func:`build_call0_context`, then renders
    templates, calls the LLM, and parses the response.

    ``completion_length_feedback`` (the finalization-owned length-retry
    suffix) is appended verbatim to the end of the rendered user prompt,
    after every semantic section.

    Returns:
        Tuple of (ActorProfile, LLMResult).
    """
    ctx = build_call0_context(
        seed=seed,
        profile=profile,
        use_case=use_case,
        preferred_actor_type=preferred_actor_type,
        excluded_actor_types=excluded_actor_types,
        preferred_capability_level=preferred_capability_level,
        attack_goal=attack_goal,
        pinned_technique_ids=pinned_technique_ids,
        forced_actor_type=forced_actor_type,
        pinned_entry_point=pinned_entry_point,
        pinned_entry_point_id=pinned_entry_point_id,
        access_feedback=access_feedback,
        projection_context=projection_context,
    )

    semantic_draft_v2 = projection_context is not None
    system_prompt = render_prompt(
        "call0_system.j2",
        zones_active=profile.zones_active,
        tool_inventory=ctx["tool_inventory"],
        semantic_draft_v2=semantic_draft_v2,
    )
    user_prompt = render_prompt(
        "call0_user.j2", **ctx, semantic_draft_v2=semantic_draft_v2
    )
    actor_types: dict[str, str] = {}
    capability_levels: dict[str, str] = {}
    actor_choices: dict[str, tuple[str, str]] = {}
    resources: dict[str, str] = {}
    response_model: type[BaseModel] | None = None
    if semantic_draft_v2:
        assert projection_context is not None
        actor_types, capability_levels, resources = _actor_draft_inventories(
            ctx, projection_context, profile
        )
        actor_choices = _actor_choice_inventory(actor_types, capability_levels)
        response_model = create_actor_draft_v3_model(
            actor_choice_handles=tuple(actor_choices),
            resource_handles=tuple(resources),
            compact=compact_response_schema,
        )
        user_prompt += _actor_draft_prompt(actor_choices, resources)
    if completion_length_feedback:
        user_prompt = f"{user_prompt}{completion_length_feedback}"
    result = _complete_actor_profile(
        client,
        system_prompt,
        user_prompt,
        compact_response_schema=compact_response_schema,
        response_format=response_model,
        max_completion_tokens=max_completion_tokens,
    )

    resp = result.content
    if isinstance(resp, (ActorDraftV2, ActorDraftV3)):
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
        actor_profile = compile_actor_draft(
            ActorDraftContext(
                actor_types=actor_types,
                capability_levels=capability_levels,
                resources=resources,
                access=access,
                minimum_capability_level=ctx["minimum_capability_level"],
                actor_choices=actor_choices,
            ),
            resp,
        )
        return actor_profile, result, ctx.get("diversity_limitation")

    # Scripted fixtures using the historical response remain supported while
    # live projected requests advertise and parse only ActorDraftV3.
    actor_type = _normalize_actor_type(resp.actor_type)
    capability_level = _normalize_capability_level(resp.capability_level)
    capability_level = _enforce_capability_floor(actor_type, capability_level)
    # Enforce computed capability-level minimum floor (estu constraint)
    minimum_capability_level = ctx["minimum_capability_level"]
    if minimum_capability_level and minimum_capability_level in _CAPABILITY_ORDER:
        min_floor_idx = _CAPABILITY_ORDER.index(minimum_capability_level)
        current_idx = (
            _CAPABILITY_ORDER.index(capability_level)
            if capability_level in _CAPABILITY_ORDER
            else 1
        )
        if current_idx < min_floor_idx:
            logger.warning(
                "Capability-level floor (estu): seed %s requires '%s', "
                "actor had '%s' — bumped",
                seed.seed_id,
                minimum_capability_level,
                capability_level,
            )
            capability_level = minimum_capability_level
    # Enforce seed-level min_complexity constraint
    if seed.min_complexity and seed.min_complexity in _CAPABILITY_ORDER:
        seed_floor_idx = _CAPABILITY_ORDER.index(seed.min_complexity)
        current_idx = (
            _CAPABILITY_ORDER.index(capability_level)
            if capability_level in _CAPABILITY_ORDER
            else 1
        )
        if current_idx < seed_floor_idx:
            logger.warning(
                "Seed min_complexity floor: %s requires '%s', actor had '%s' — bumped",
                seed.seed_id,
                seed.min_complexity,
                capability_level,
            )
            capability_level = seed.min_complexity
    actor_profile = ActorProfile(
        actor_type=actor_type,
        capability_level=capability_level,
        beliefs=resp.beliefs,
        desires=resp.desires,
        intentions=resp.intentions,
        resources=resp.resources,
    )

    # Build typed access provenance from canonical EP identity (cmps.6)
    if pinned_entry_point_id:
        ep_controllability = _lookup_entry_point_controllability(
            profile,
            pinned_entry_point,
            pinned_entry_point_id,
        )
        actor_profile.access = build_actor_access_provenance(
            entry_point_id=pinned_entry_point_id,
            ep_controllability=ep_controllability,
            actor_type=actor_type,
            resp=resp,
            profile=profile,
            projection_context=projection_context,
        )

    return actor_profile, result, ctx.get("diversity_limitation")


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-21T12:04:02Z","module_hash":"6f394168dc1d5cdedbab851be26db81a56d4a01c0d842974c69ba842904810a9","source_sha256":"f9cb699bc56b29697555d2d8604cd47b47a4d564ea5144a6bda94b63f419e4fc","functions":[{"id":"func/_normalize_actor_type","name":"_normalize_actor_type","line":112,"end_line":129,"hash":"b14a12241134138150c3a650d05ea0c25e6d6f174234ad165964d5672753684d"},{"id":"func/_normalize_capability_level","name":"_normalize_capability_level","line":132,"end_line":142,"hash":"a9c1580791267cf62ecc36250e99295564baf4b3ce757ae961cd748a69b2fa7e"},{"id":"func/_enforce_capability_floor","name":"_enforce_capability_floor","line":145,"end_line":167,"hash":"aab9a89c8d440c382d9bd5d3bedd8ba1888349f2850606a2b0a3b5775f24149b"},{"id":"func/_validate_actor_type","name":"_validate_actor_type","line":170,"end_line":201,"hash":"c95cc34d0eda29274412d741a9f8aa01a477baf6df5bab2b52d6c7a4f48a23c2"},{"id":"func/build_actor_access_provenance","name":"build_actor_access_provenance","line":217,"end_line":272,"hash":"02ca2d66c246ac8997b0811d3574988d4bafc9e76f6c240f1286ecfdec0d95dc"},{"id":"func/_canonical_checks","name":"_canonical_checks","line":275,"end_line":484,"hash":"d2b36eff3a1be48d8dc66cf0f61f69277fb93102a1fd6ca075144e915365847e"},{"id":"func/validate_actor_access_provenance","name":"validate_actor_access_provenance","line":487,"end_line":612,"hash":"c1a7a8e202aa760b400b0946a93a5d99808ff6fae33042d55d2a99790b5bfde8"},{"id":"func/_complete_actor_profile","name":"_complete_actor_profile","line":620,"end_line":634,"hash":"299c1231324c1a3eeed4ba30713c3e16467c61a7b362a0b179ce590cb212c6ce"},{"id":"func/_call_actor_profile","name":"_call_actor_profile","line":637,"end_line":754,"hash":"f9ba3ac1cef0e9c8020df5551ac781249ae3b04b52f6b6e81fc0bfce02cfffc6"}]}
# mutate4py-manifest-end

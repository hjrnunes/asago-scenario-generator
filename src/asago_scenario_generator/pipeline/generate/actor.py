"""Call 0: Actor Profile generation logic."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Annotated, Any

from pydantic import BaseModel, Field

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
    trust_boundary_id = resp.trust_boundary_id
    if profile is not None:
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

    # influence_source must be present and resolve to a different EP.
    if not access.influence_source or not access.influence_source.strip():
        return  # Already flagged as missing in structural checks.

    source_ep = profile.resolve_entry_point(access.influence_source)
    if source_ep is None:
        violations.append(
            ActorAccessViolation(
                rule="unresolved_influence_source",
                message=(
                    f"influence_source '{access.influence_source}' "
                    f"does not resolve to any entry point in the "
                    f"capability profile."
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
                    f"influence_source '{access.influence_source}' is the "
                    f"same entry point as the initial ingress "
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
                    f"influence_source '{access.influence_source}' resolves "
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
                    f"influence_source '{access.influence_source}' resolves "
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
    source_zone = source_ep.effective_ingress_zone
    if (
        source_zone is not None
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
        boundary.from_zone == "external"
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
    client: LLMClient, system_prompt: str, user_prompt: str
) -> LLMResult:
    """Complete Call 0 exactly once with the operator-configured limit.

    Length exhaustion is normalized by the shared adapter into typed
    ``CompletionLengthError`` evidence; this helper never retries.
    Retry ownership belongs to the finalization lifecycle.
    """
    return client.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=Call0Response,
        max_completion_tokens=client.max_completion_tokens,
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

    system_prompt = render_prompt(
        "call0_system.j2",
        zones_active=profile.zones_active,
        tool_inventory=ctx["tool_inventory"],
    )
    user_prompt = render_prompt("call0_user.j2", **ctx)
    if completion_length_feedback:
        user_prompt = f"{user_prompt}{completion_length_feedback}"
    result = _complete_actor_profile(client, system_prompt, user_prompt)

    resp = result.content
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
        )

    return actor_profile, result, ctx.get("diversity_limitation")

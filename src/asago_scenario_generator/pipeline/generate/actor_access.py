"""Call 0: typed actor access provenance (cmps.6) policy and response model.

This leaf module owns the historical Call0 LLM response model and the
deterministic access-provenance validation policy grounded in the canonical
capability profile.  ``generate.actor`` re-exports every name here so the
historical import surface stays intact; nothing in this module prompts or
calls an LLM.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any

from pydantic import BaseModel, Field

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    TrustBoundary,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
)
from asago_scenario_generator.pipeline.generate.actor_rules import (
    _ep_controllability_to_ingress_mode,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _INSIDER_ACTOR_TYPES,
)

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


class CompactCall0Response(Call0Response):
    """Provider schema name for the one causal compact-response experiment."""


# ---------------------------------------------------------------------------#
# Actor access provenance (cmps.6)
# ---------------------------------------------------------------------------#


@dataclass
class ActorAccessViolation:
    """A single actor/access provenance violation detected during generation."""

    rule: str
    message: str


def _projection_path_source(
    projection_context: dict[str, Any],
) -> tuple[str | None, str | None, str | None, str | None] | None:
    """Return the single authoritative source-influence path fields.

    Returns ``None`` when the projection declares no authoritative path;
    raises when it declares more than one.
    """
    paths = projection_context.get("source_influence_paths", [])
    if not paths:
        return None
    if len(paths) != 1:
        raise ValueError(
            "projection context must contain exactly one source-influence path"
        )
    path = paths[0]
    return (
        path.get("source_id"),
        path.get("source_identity_kind"),
        path.get("source_id"),
        path.get("boundary_id"),
    )


def _resolve_source_name(
    influence_source: str | None, profile: CapabilityProfile
) -> str | None:
    """Resolve one influence-source name to a canonical entry-point ID."""
    from asago_scenario_generator.pipeline.generate.names import (
        resolve_name_to_entry_point_id,
    )

    if not influence_source:
        return influence_source
    resolved = resolve_name_to_entry_point_id(influence_source, profile)
    return resolved if resolved is not None else influence_source


def _resolve_boundary_name(
    trust_boundary_id: str | None, profile: CapabilityProfile
) -> str | None:
    """Resolve one trust-boundary name to a canonical profile ID."""
    from asago_scenario_generator.pipeline.generate.names import (
        resolve_name_to_trust_boundary_id,
    )

    if not trust_boundary_id:
        return trust_boundary_id
    resolved_tb = resolve_name_to_trust_boundary_id(trust_boundary_id, profile)
    return resolved_tb if resolved_tb is not None else trust_boundary_id


def _resolve_evidence_names(
    influence_source: str | None,
    trust_boundary_id: str | None,
    profile: CapabilityProfile,
) -> tuple[str | None, str | None]:
    """Resolve LLM-evidence names to canonical profile identities."""
    return (
        _resolve_source_name(influence_source, profile),
        _resolve_boundary_name(trust_boundary_id, profile),
    )


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

    if projection_context is not None:
        path_source = _projection_path_source(projection_context)
        if path_source is not None:
            (
                influence_source,
                influence_source_kind,
                influence_source_id,
                trust_boundary_id,
            ) = path_source
    elif profile is not None:
        influence_source, trust_boundary_id = _resolve_evidence_names(
            influence_source, trust_boundary_id, profile
        )

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


def _check_initial_ingress(
    violations: list[ActorAccessViolation],
    access: ActorAccessProvenance,
    profile: CapabilityProfile,
) -> EntryPoint | None:
    """Append initial-ingress resolution and eligibility violations.

    Returns the resolved initial entry point, or ``None`` when canonical
    checks cannot continue.
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
        return None

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
    ep_ctrl = initial_ep.effective_controllability
    if ep_ctrl == "system":
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
    elif ep_ctrl != access.ingress_mode:
        violations.append(
            ActorAccessViolation(
                rule="ingress_mode_controllability_mismatch",
                message=(
                    f"ingress_mode '{access.ingress_mode}' does not match "
                    f"the entry point's effective controllability "
                    f"'{ep_ctrl}' (entry_point_id "
                    f"'{access.initial_entry_point_id}')."
                ),
            )
        )
    return initial_ep


def _influence_source_identity(
    access: ActorAccessProvenance,
) -> tuple[str, str]:
    """Return the authoritative source identity, preferring typed fields."""
    source_id = access.influence_source_id or access.influence_source
    source_kind = access.influence_source_kind or "entry_point"
    return source_id or "", source_kind


def _resolve_integration_source(
    source_id: str,
    access: ActorAccessProvenance,
    profile: CapabilityProfile,
    violations: list[ActorAccessViolation],
) -> tuple[bool, EntryPoint | None]:
    """Resolve an integration-kind influence source or record the defect."""
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
        return False, None
    return True, None


def _self_relation_influence_source(
    source_id: str,
    source_ep: EntryPoint,
    access: ActorAccessProvenance,
    initial_ep: EntryPoint,
    violations: list[ActorAccessViolation],
) -> bool:
    """Flag a source that is the same entry point as the initial ingress."""
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
        return True
    return False


def _check_source_accessibility(
    source_id: str,
    source_ep: EntryPoint,
    violations: list[ActorAccessViolation],
) -> None:
    """Append output-only and system-controlled source violations."""
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


def _resolve_entry_point_source(
    source_id: str,
    access: ActorAccessProvenance,
    profile: CapabilityProfile,
    initial_ep: EntryPoint,
    violations: list[ActorAccessViolation],
) -> tuple[bool, EntryPoint | None]:
    """Resolve an entry-point-kind influence source or record the defect."""
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
        return False, None
    if _self_relation_influence_source(
        source_id, source_ep, access, initial_ep, violations
    ):
        return False, None
    _check_source_accessibility(source_id, source_ep, violations)
    return True, source_ep


def _check_influence_source(
    violations: list[ActorAccessViolation],
    access: ActorAccessProvenance,
    profile: CapabilityProfile,
    initial_ep: EntryPoint,
) -> tuple[bool, EntryPoint | None]:
    """Append influence-source resolution and accessibility violations.

    Returns ``(continue, source_ep)``; ``continue`` is False when checks
    must stop, and ``source_ep`` is the resolved entry-point source (or
    ``None`` for integration sources).
    """
    source_id, source_kind = _influence_source_identity(access)
    if not source_id.strip():
        return False, None  # Already flagged as missing in structural checks.
    if source_kind == "integration":
        return _resolve_integration_source(source_id, access, profile, violations)
    return _resolve_entry_point_source(
        source_id, access, profile, initial_ep, violations
    )


def _check_trust_boundary(
    violations: list[ActorAccessViolation],
    access: ActorAccessProvenance,
    profile: CapabilityProfile,
    initial_ep: EntryPoint,
    source_ep: EntryPoint | None,
) -> None:
    """Append trust-boundary resolution, zone relation, and flow violations."""
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
    _check_boundary_zone_relations(boundary, initial_ep, source_ep, access, violations)


def _check_boundary_zone_relations(
    boundary: TrustBoundary,
    initial_ep: EntryPoint,
    source_ep: EntryPoint | None,
    access: ActorAccessProvenance,
    violations: list[ActorAccessViolation],
) -> None:
    """Append boundary target-zone, source-zone, and flow violations."""
    _check_boundary_target_zone(boundary, initial_ep, access, violations)
    _check_boundary_source_zone(boundary, source_ep, access, violations)
    _check_boundary_external_flow(boundary, source_ep, access, violations)


def _check_boundary_target_zone(
    boundary: TrustBoundary,
    initial_ep: EntryPoint,
    access: ActorAccessProvenance,
    violations: list[ActorAccessViolation],
) -> None:
    """Append the target-zone mismatch when the boundary misses the ingress zone."""
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


def _check_boundary_source_zone(
    boundary: TrustBoundary,
    source_ep: EntryPoint | None,
    access: ActorAccessProvenance,
    violations: list[ActorAccessViolation],
) -> None:
    """Append the source-zone mismatch unless the source side is external."""
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


def _check_boundary_external_flow(
    boundary: TrustBoundary,
    source_ep: EntryPoint | None,
    access: ActorAccessProvenance,
    violations: list[ActorAccessViolation],
) -> None:
    """Append the flow violation when an external boundary lacks indirect control."""
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


def _has_text(value: str | None) -> bool:
    """Return True when a value carries non-whitespace content."""
    return bool(value and value.strip())


def _access_class_consistency_violations(
    actor_type: str, access: ActorAccessProvenance
) -> list[ActorAccessViolation]:
    """Collect ingress-mode / access-class consistency violations (check 2)."""
    violations: list[ActorAccessViolation] = []
    if access.ingress_mode == "direct" and access.access_class == "supply_chain":
        violations.append(
            ActorAccessViolation(
                rule="access_class_ingress_mode_incompatible",
                message=(
                    f"Actor '{actor_type}' has access_class "
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
                    f"Actor '{actor_type}' has access_class "
                    f"'public' but ingress_mode 'indirect' — public access "
                    f"cannot influence upstream data sources."
                ),
            )
        )
    return violations


def _missing_evidence_fields(access: ActorAccessProvenance) -> list[str]:
    """Collect the indirect-ingress evidence fields that are missing."""
    missing = []
    if not _has_text(access.influence_source):
        missing.append("influence_source")
    if not _has_text(access.influence_mechanism):
        missing.append("influence_mechanism")
    if not _has_text(access.trust_boundary_id):
        missing.append("trust_boundary_id")
    return missing


def _incomplete_indirect_evidence_violations(
    access: ActorAccessProvenance,
) -> list[ActorAccessViolation]:
    """Collect the indirect-ingress evidence completeness violation (check 3)."""
    if access.ingress_mode != "indirect":
        return []
    missing = _missing_evidence_fields(access)
    if not missing:
        return []
    return [
        ActorAccessViolation(
            rule="incomplete_indirect_evidence",
            message=(
                f"Indirect ingress requires structured evidence: missing {missing}."
            ),
        )
    ]


def _missing_insider_advantage_violation(
    actor_profile: ActorProfile, access: ActorAccessProvenance
) -> ActorAccessViolation | None:
    """Return the insider-evidence violation when direct ingress lacks it."""
    if (
        access.ingress_mode == "direct"
        and actor_profile.actor_type in _INSIDER_ACTOR_TYPES
        and not _has_text(access.material_insider_advantage)
    ):
        return ActorAccessViolation(
            rule="missing_insider_advantage",
            message=(
                f"Insider actor '{actor_profile.actor_type}' using "
                f"direct ingress requires structured "
                f"material_insider_advantage evidence regardless of "
                f"access_class ('{access.access_class}') — enum choice "
                f"is not evidence (cmps.6)."
            ),
        )
    return None


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
    initial_ep = _check_initial_ingress(violations, access, profile)
    if initial_ep is None:
        return

    # 6–8. Indirect ingress canonical relation checks.
    if access.ingress_mode != "indirect":
        return

    continue_sources, source_ep = _check_influence_source(
        violations, access, profile, initial_ep
    )
    if not continue_sources:
        return
    _check_trust_boundary(violations, access, profile, initial_ep, source_ep)


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

    # 2-4. Structural consistency and evidence checks (profile-free).
    violations.extend(
        _access_class_consistency_violations(actor_profile.actor_type, access)
    )
    violations.extend(_incomplete_indirect_evidence_violations(access))
    insider_violation = _missing_insider_advantage_violation(actor_profile, access)
    if insider_violation is not None:
        violations.append(insider_violation)

    # 5–8. Canonical resolution (when profile is provided)
    if profile is not None:
        _canonical_checks(violations, access, actor_profile.actor_type, profile)

    return violations


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-24T01:16:40Z","module_hash":"75b2a7c4040851812f5a694b81ebbd46bd6f531db3bfcde7e664925e5504f66e","source_sha256":"31b0ce58470a44002d198a8e1210e39675b55af8dd1d245a1a0210b0894f2163","functions":[{"id":"func/_projection_path_source","name":"_projection_path_source","line":104,"end_line":125,"hash":"dac49ca8219c1a7d4782f79ed90d29ddd7c0726692884990582c87b11df0aefb"},{"id":"func/_resolve_source_name","name":"_resolve_source_name","line":128,"end_line":139,"hash":"1475281d7be6040c078d970e3d56767124758dbeac8ae1ba540b4aa7def7b7c9"},{"id":"func/_resolve_boundary_name","name":"_resolve_boundary_name","line":142,"end_line":153,"hash":"dd2ff59564848749c48272395e720a9e4b15dc1b4e1b6108af705c4663f9e587"},{"id":"func/_resolve_evidence_names","name":"_resolve_evidence_names","line":156,"end_line":165,"hash":"e9b4f9da5ebd6b567492aa5d811aab7ce600269c02f4f2cd90002d7b1abc055b"},{"id":"func/build_actor_access_provenance","name":"build_actor_access_provenance","line":168,"end_line":234,"hash":"d128e5cf81396f5236e9736b8c76a47d05447b0979a69073f5f2c4475cd6e67f"},{"id":"func/_check_initial_ingress","name":"_check_initial_ingress","line":237,"end_line":304,"hash":"a23db75943ed3bb5b540ddef60ecd48b7c77fd905ca86cf50ef9335e3ee9a3fa"},{"id":"func/_influence_source_identity","name":"_influence_source_identity","line":307,"end_line":313,"hash":"48877f72940b50824af3565f4a4bd270c4598baa64a3dbdaa645a53e42fd589b"},{"id":"func/_resolve_integration_source","name":"_resolve_integration_source","line":316,"end_line":334,"hash":"f40d18f9418ba79119a18d7c4750b223888321f43d7d4318d3f92811bfb4bb8c"},{"id":"func/_self_relation_influence_source","name":"_self_relation_influence_source","line":337,"end_line":358,"hash":"f5f1ee810a96f01132a07f8520de1b0b32f1391ad31ede0be5a10dc606b69476"},{"id":"func/_check_source_accessibility","name":"_check_source_accessibility","line":361,"end_line":389,"hash":"cc1bdd2b14584beb7f6a6443d05c6570f76e25e7a35cdc71d3aa63f0a4e01795"},{"id":"func/_resolve_entry_point_source","name":"_resolve_entry_point_source","line":392,"end_line":417,"hash":"b851009ac420b496254a4accc4028180e679efaf1b8de53c134e889d9aa61e73"},{"id":"func/_check_influence_source","name":"_check_influence_source","line":420,"end_line":439,"hash":"ede9f3cdaddf1ce153ab35699b03c81a2528a47a2d78a17766caa64f57b40d1a"},{"id":"func/_check_trust_boundary","name":"_check_trust_boundary","line":442,"end_line":467,"hash":"1f2b319bc518c1cc8908a9861911fc2dbed229f9dcbe71857e78f5a71439966f"},{"id":"func/_check_boundary_zone_relations","name":"_check_boundary_zone_relations","line":470,"end_line":480,"hash":"7525f61d07bdf912e2008ee8592f1f3d5cdf760103e860e409a4c9df610aa033"},{"id":"func/_check_boundary_target_zone","name":"_check_boundary_target_zone","line":483,"end_line":504,"hash":"1375a8aa3dae9fe202ae86bf5e5fd395e05c7e47979f0784f299c467ba032f44"},{"id":"func/_check_boundary_source_zone","name":"_check_boundary_source_zone","line":507,"end_line":537,"hash":"8f70182b936037a90fefe7a1695138eeb2773bf778063171dc12e27ae7d287ca"},{"id":"func/_check_boundary_external_flow","name":"_check_boundary_external_flow","line":540,"end_line":569,"hash":"67f1aec40157cd0b76d5a2cca709d842806dbd8df8c9001e82e15863ebcf8eae"},{"id":"func/_has_text","name":"_has_text","line":572,"end_line":574,"hash":"52012844ccb450138e0bf30a888cefbbe6b5e3b704c1caa5053bf6524489e269"},{"id":"func/_access_class_consistency_violations","name":"_access_class_consistency_violations","line":577,"end_line":604,"hash":"baa3dc8cb31cd08b44d01d42b44990bdbdc7ff8d74b71e45ddb0f21cb59f2f99"},{"id":"func/_missing_evidence_fields","name":"_missing_evidence_fields","line":607,"end_line":616,"hash":"3dd2f5fd047f7947407be7d4dd771ad994f8d3fbbdb22ce2c3cc9eaf2efef771"},{"id":"func/_incomplete_indirect_evidence_violations","name":"_incomplete_indirect_evidence_violations","line":619,"end_line":635,"hash":"f40a0358516fc80aae37c75e49468579b6768c41f4f406c53836f22dc9488c17"},{"id":"func/_missing_insider_advantage_violation","name":"_missing_insider_advantage_violation","line":638,"end_line":657,"hash":"0430012f7016d32d6028541fc230567d0d36f0c03bd162c792941831f468444e"},{"id":"func/_canonical_checks","name":"_canonical_checks","line":660,"end_line":685,"hash":"10f0323e2b7b7606367e45f6b73fb15762792040fe380b2fc7eea6f91ea1b16d"},{"id":"func/validate_actor_access_provenance","name":"validate_actor_access_provenance","line":688,"end_line":755,"hash":"73bf5b81c1fe4cab5efb341d599d36850d122068ed7adf0a0191fd6c0812ccac"}]}
# mutate4py-manifest-end

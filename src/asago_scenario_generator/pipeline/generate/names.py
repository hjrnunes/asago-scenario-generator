"""Name-to-ID resolution helpers for human-readable LLM prompts (Phase 3).

The LLM sees and outputs human-readable names (e.g. "user text prompts")
instead of opaque hex IDs (e.g. "ep:v1:a3f8b2c1e7d9...").  This module
provides:

1. Functions to convert hex IDs to names for prompt context building.
2. Functions to resolve names back to hex IDs after LLM output parsing.
"""

from __future__ import annotations

import logging
from typing import Any

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.scenario import ActorAccessProvenance

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ID → Name conversion (for prompt context)
# ---------------------------------------------------------------------------


def _influence_source_line(
    access: ActorAccessProvenance, profile: CapabilityProfile
) -> str:
    """One-line rendering of the upstream influence source, or empty."""
    if not access.influence_source:
        return ""
    source_name = resource_name_for_kind(
        getattr(access, "influence_source_kind", None) or "entry_point",
        access.influence_source,
        profile,
    )
    return f"- influence_source: {source_name}\n"


def _influence_mechanism_line(access: ActorAccessProvenance) -> str:
    """One-line rendering of the influence mechanism, or empty."""
    if not access.influence_mechanism:
        return ""
    return f"- influence_mechanism: {access.influence_mechanism}\n"


def _trust_boundary_line(
    access: ActorAccessProvenance, profile: CapabilityProfile
) -> str:
    """One-line rendering of the trust boundary name, or empty."""
    if not access.trust_boundary_id:
        return ""
    tb_name = resource_name_for_kind(
        "trust_boundary", access.trust_boundary_id, profile
    )
    return f"- trust_boundary_id: {tb_name}\n"


def _insider_advantage_line(access: ActorAccessProvenance) -> str:
    """One-line rendering of the material insider advantage, or empty."""
    if not access.material_insider_advantage:
        return ""
    return f"- material_insider_advantage: {access.material_insider_advantage}\n"


def access_provenance_block_with_names(
    access: ActorAccessProvenance | None,
    profile: CapabilityProfile,
    *,
    header: str = (
        "\n## Actor Access Provenance (AUTHORITATIVE — cmps.6)\n"
        "This structured block is authoritative over any advisory "
        "kill-chain wording. The attack tree's initial_ingress action "
        "must use exactly this entry point name and be consistent with "
        "this evidence.\n"
    ),
) -> str:
    """Build an access provenance block using human-readable names.

    Converts hex IDs in the access provenance to their canonical names
    from the capability profile.
    """
    if access is None:
        return ""

    ep_name = resource_name_for_kind(
        "entry_point", access.initial_entry_point_id, profile
    )
    base_lines = (
        f"- initial_entry_point_id: {ep_name}\n"
        f"- ingress_mode: {access.ingress_mode}\n"
        f"- access_class: {access.access_class}\n"
    )
    optional_lines = "".join(
        (
            _influence_source_line(access, profile),
            _influence_mechanism_line(access),
            _trust_boundary_line(access, profile),
            _insider_advantage_line(access),
        )
    )
    return f"{header}{base_lines}{optional_lines}"


def pinned_entry_point_name_from_id(
    pinned_entry_point_id: str | None,
    profile: CapabilityProfile | None,
) -> str | None:
    """Convert a pinned entry point hex ID to its canonical name."""
    if pinned_entry_point_id is None or profile is None:
        return None
    id_to_ep = profile.id_to_entry_point_name()
    return id_to_ep.get(pinned_entry_point_id, pinned_entry_point_id)


# Resource-ref kind → (ID field, profile name-lookup method).
_RESOURCE_REF_ID_FIELD_BY_KIND = {
    "entry_point": "entry_point_id",
    "tool": "tool_id",
    "integration": "integration_id",
    "trust_boundary": "trust_boundary_id",
    "output_surface": "entry_point_id",
}
_RESOURCE_REF_NAME_LOOKUP_BY_KIND = {
    "entry_point": "id_to_entry_point_name",
    "tool": "id_to_tool_name",
    "integration": "id_to_integration_name",
    "trust_boundary": "id_to_trust_boundary_name",
    "output_surface": "id_to_entry_point_name",
}


def _humanize_resource_id(
    result: dict[str, Any],
    resource_ref: dict[str, Any],
    kind: str,
    profile: CapabilityProfile,
) -> None:
    """Replace one typed resource ID in a ref dict with its profile name."""
    id_field = _RESOURCE_REF_ID_FIELD_BY_KIND[kind]
    resource_id = resource_ref.get(id_field)
    if not resource_id:
        return
    name_lookup = _RESOURCE_REF_NAME_LOOKUP_BY_KIND[kind]
    names = getattr(profile, name_lookup)()
    result[id_field] = names.get(resource_id, resource_id)


def humanize_resource_ref(
    resource_ref: dict[str, Any] | None,
    profile: CapabilityProfile,
) -> dict[str, Any] | None:
    """Replace hex IDs in a resource_ref dict with human-readable names."""
    if resource_ref is None:
        return None

    kind = resource_ref.get("kind")
    if kind not in _RESOURCE_REF_ID_FIELD_BY_KIND:
        return dict(resource_ref)
    result = dict(resource_ref)
    _humanize_resource_id(result, resource_ref, kind, profile)
    return result


def resource_name_for_kind(
    resource_kind: str | None,
    resource_id: str,
    profile: CapabilityProfile,
) -> str:
    """Return the profile name for a typed resource ID when it is known.

    Projection prompts keep canonical IDs in authoritative fields, but show
    profile names beside them for model readability.  Keeping the lookup in
    one helper prevents each prompt builder from maintaining its own
    kind-to-inventory mapping.
    """
    name_by_kind = {
        "entry_point": profile.id_to_entry_point_name(),
        "integration": profile.id_to_integration_name(),
        "trust_boundary": profile.id_to_trust_boundary_name(),
        "tool": profile.id_to_tool_name(),
        "output_surface": profile.id_to_entry_point_name(),
    }
    names = name_by_kind.get(resource_kind)
    if names is None:
        names = {
            **profile.integration_name_to_id(),
            **profile.entry_point_name_to_id(),
        }
        names = {value: key for key, value in names.items()}
    return names.get(resource_id, resource_id)


def _humanized_canonical_ingress_name(
    canonical_ingress: dict[str, Any],
    id_to_ep: dict[str, str],
) -> str:
    """Canonical ingress display name, or empty when absent."""
    if not canonical_ingress:
        return ""
    ep_id = canonical_ingress.get("entry_point_id")
    if ep_id:
        return id_to_ep.get(ep_id, ep_id)
    return str(canonical_ingress)


def _humanized_selected_steps(
    selected_steps: list[dict[str, Any]],
    profile: CapabilityProfile,
) -> list[dict[str, Any]]:
    """Selected steps with human-readable resource references."""
    humanized_steps: list[dict[str, Any]] = []
    for step in selected_steps:
        h_step = dict(step)
        h_links = []
        for link in step.get("resource_links", []):
            h_link = dict(link)
            h_link["resource_ref"] = humanize_resource_ref(
                link.get("resource_ref"), profile
            )
            h_links.append(h_link)
        h_step["resource_links"] = h_links
        humanized_steps.append(h_step)
    return humanized_steps


def _humanized_influence_paths(
    paths: list[dict[str, Any]],
    profile: CapabilityProfile,
) -> list[dict[str, Any]]:
    """Source-influence paths with human-readable name fields."""
    humanized_paths: list[dict[str, Any]] = []
    for path in paths:
        h_path = dict(path)
        h_path["source_name"] = resource_name_for_kind(
            path.get("source_identity_kind"),
            path.get("source_id", ""),
            profile,
        )
        h_path["boundary_name"] = resource_name_for_kind(
            "trust_boundary",
            path.get("boundary_id", ""),
            profile,
        )
        h_path["target_ingress_name"] = resource_name_for_kind(
            "entry_point",
            path.get("target_ingress_id", ""),
            profile,
        )
        humanized_paths.append(h_path)
    return humanized_paths


def humanize_projection_context(
    projection_context: dict[str, Any] | None,
    profile: CapabilityProfile,
) -> dict[str, Any] | None:
    """Replace hex IDs in projection context with human-readable names.

    Returns a new dict (does not mutate the original).  The canonical
    ingress entry_point_id and all resource_ref values are converted
    to names.
    """
    if projection_context is None:
        return None

    id_to_ep = profile.id_to_entry_point_name()
    result = dict(projection_context)

    # Convert canonical_ingress entry_point_id to name
    result["canonical_ingress_name"] = _humanized_canonical_ingress_name(
        projection_context.get("canonical_ingress", {}), id_to_ep
    )

    # Convert resource_ref values in selected_steps
    result["selected_steps"] = _humanized_selected_steps(
        projection_context.get("selected_steps", []), profile
    )

    # Keep canonical IDs in the authoritative path record so generated
    # stages cannot replace them, while supplying names for prompt prose.
    result["source_influence_paths"] = _humanized_influence_paths(
        projection_context.get("source_influence_paths", []), profile
    )

    # Note: resource_slots and bindings were removed from the projection
    # context in Phase 4 — they are no longer rendered in prompts.

    return result


# ---------------------------------------------------------------------------
# Name → ID resolution (post-processing after LLM output)
# ---------------------------------------------------------------------------


def resolve_name_to_entry_point_id(
    name: str,
    profile: CapabilityProfile,
) -> str | None:
    """Resolve an entry-point name to its canonical hex ID.

    Returns the hex ID if found, or None if the name doesn't match
    any entry point.  Also checks if the value is already a hex ID.
    """
    # Already a hex ID?
    if name.startswith("ep:v1:"):
        return name
    name_to_id = profile.entry_point_name_to_id()
    return name_to_id.get(name)


def resolve_name_to_tool_id(
    name: str,
    profile: CapabilityProfile,
) -> str | None:
    """Resolve a tool name to its canonical hex ID."""
    if name.startswith("tool:v1:"):
        return name
    name_to_id = profile.tool_name_to_id()
    return name_to_id.get(name)


def resolve_name_to_integration_id(
    name: str,
    profile: CapabilityProfile,
) -> str | None:
    """Resolve an integration name to its canonical hex ID."""
    if name.startswith("int:v1:"):
        return name
    name_to_id = profile.integration_name_to_id()
    return name_to_id.get(name)


def resolve_name_to_trust_boundary_id(
    name: str,
    profile: CapabilityProfile,
) -> str | None:
    """Resolve a trust boundary name to its canonical hex ID."""
    if name.startswith("tb:v1:"):
        return name
    name_to_id = profile.trust_boundary_name_to_id()
    return name_to_id.get(name)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:26:15Z","module_hash":"2b9a265d11cfadea35681a2e3668f14c1a7beb2d7837218f384b5a6c559da7ff","source_sha256":"17849eb2ba074bf842b28f23ff08ae8ac7c95f87ffcb6803a0624eddc6dff5dd","functions":[{"id":"func/_influence_source_line","name":"_influence_source_line","line":27,"end_line":38,"hash":"4abc417230b6f0e28fc259cff8947643ae64ea49b9eb18a2d85a8757cd6a8048"},{"id":"func/_influence_mechanism_line","name":"_influence_mechanism_line","line":41,"end_line":45,"hash":"b32f03c153e1092591b2d6e88329dc6c604fba1e81aa3a4660b388276070cac0"},{"id":"func/_trust_boundary_line","name":"_trust_boundary_line","line":48,"end_line":57,"hash":"f74f4c2c3ae1b76bdf75b8d586e28a02afef5e12099594f357663638dfc12d34"},{"id":"func/_insider_advantage_line","name":"_insider_advantage_line","line":60,"end_line":64,"hash":"05602a7530551775990a600e6e461133279ff1065b20c8e8a4e7ed148c9a2a7b"},{"id":"func/access_provenance_block_with_names","name":"access_provenance_block_with_names","line":67,"end_line":103,"hash":"cce4102cbeedfa7994bf623a0dbfaca2fdad5dc3b1f035bf19ac1f613e78f64e"},{"id":"func/pinned_entry_point_name_from_id","name":"pinned_entry_point_name_from_id","line":106,"end_line":114,"hash":"9f506c8642a6ea268b663c1d37ebce192755488b45b7bed8288bf3db12e2b313"},{"id":"func/_humanize_resource_id","name":"_humanize_resource_id","line":134,"end_line":147,"hash":"648a413e1f88f920940b121433d5f07a08d37b0ff4c3272a87d8689d4287f676"},{"id":"func/humanize_resource_ref","name":"humanize_resource_ref","line":150,"end_line":163,"hash":"b9ed635f6146d13026689e20a07c3131447a745885a79d30dc1f1f5d1828dbb2"},{"id":"func/resource_name_for_kind","name":"resource_name_for_kind","line":166,"end_line":192,"hash":"84f28d3bcb84d9dead9b2f375d0a4890f2d99cdb1fa96f765fdd4b5bbaf41813"},{"id":"func/_humanized_canonical_ingress_name","name":"_humanized_canonical_ingress_name","line":195,"end_line":205,"hash":"17b948ee3311bdc3604130086781132a268c0dab6ee961f6a963d0ce4915fc48"},{"id":"func/_humanized_selected_steps","name":"_humanized_selected_steps","line":208,"end_line":225,"hash":"ffd221f618be19fc70aba7a421df070474f78f81addf6f4f8708cd09d56f6fc7"},{"id":"func/_humanized_influence_paths","name":"_humanized_influence_paths","line":228,"end_line":252,"hash":"e95ccfc0f867bf18cb258f77bdac82a50bfff17288c4df14ecbc37464f7ceb07"},{"id":"func/humanize_projection_context","name":"humanize_projection_context","line":255,"end_line":290,"hash":"de3eb2ab734a94fb48ce6f225c789fded25e2d3eaa937621ed76e5b5e9cb2933"},{"id":"func/resolve_name_to_entry_point_id","name":"resolve_name_to_entry_point_id","line":298,"end_line":311,"hash":"778b9023e99ceb80812c7bc511cff33e503cf9e40f705e2c7e361e531232d9ea"},{"id":"func/resolve_name_to_tool_id","name":"resolve_name_to_tool_id","line":314,"end_line":322,"hash":"4a6b88139a03705baec0f6cb5856de4bec96be22f09595da02069acf12c2a5b0"},{"id":"func/resolve_name_to_integration_id","name":"resolve_name_to_integration_id","line":325,"end_line":333,"hash":"c950b743e2aaa09f5cc3a592842dd381e1fa46e9eb469abd21852d61a093cef8"},{"id":"func/resolve_name_to_trust_boundary_id","name":"resolve_name_to_trust_boundary_id","line":336,"end_line":344,"hash":"a921590bed024083a28feb7fc0be427bfc669f4dac23b8fed79503a0e2a254d9"}]}
# mutate4py-manifest-end

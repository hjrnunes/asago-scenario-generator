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

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ID → Name conversion (for prompt context)
# ---------------------------------------------------------------------------


def access_provenance_block_with_names(
    access: Any,
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

    id_to_ep = profile.id_to_entry_point_name()
    id_to_tb = profile.id_to_trust_boundary_name()

    ep_name = id_to_ep.get(access.initial_entry_point_id, access.initial_entry_point_id)
    block = (
        f"{header}"
        f"- initial_entry_point_id: {ep_name}\n"
        f"- ingress_mode: {access.ingress_mode}\n"
        f"- access_class: {access.access_class}\n"
    )
    if access.influence_source:
        source_name = id_to_ep.get(access.influence_source, access.influence_source)
        block += f"- influence_source: {source_name}\n"
    if access.influence_mechanism:
        block += f"- influence_mechanism: {access.influence_mechanism}\n"
    if access.trust_boundary_id:
        tb_name = id_to_tb.get(access.trust_boundary_id, access.trust_boundary_id)
        block += f"- trust_boundary_id: {tb_name}\n"
    if access.material_insider_advantage:
        block += f"- material_insider_advantage: {access.material_insider_advantage}\n"

    return block


def pinned_entry_point_name_from_id(
    pinned_entry_point_id: str | None,
    profile: CapabilityProfile | None,
) -> str | None:
    """Convert a pinned entry point hex ID to its canonical name."""
    if pinned_entry_point_id is None or profile is None:
        return None
    id_to_ep = profile.id_to_entry_point_name()
    return id_to_ep.get(pinned_entry_point_id, pinned_entry_point_id)


def humanize_resource_ref(
    resource_ref: dict[str, Any] | None,
    profile: CapabilityProfile,
) -> dict[str, Any] | None:
    """Replace hex IDs in a resource_ref dict with human-readable names."""
    if resource_ref is None:
        return None

    kind = resource_ref.get("kind")
    result = dict(resource_ref)

    if kind == "entry_point":
        ep_id = resource_ref.get("entry_point_id")
        if ep_id:
            id_to_ep = profile.id_to_entry_point_name()
            result["entry_point_id"] = id_to_ep.get(ep_id, ep_id)
    elif kind == "tool":
        tool_id = resource_ref.get("tool_id")
        if tool_id:
            id_to_tool = profile.id_to_tool_name()
            result["tool_id"] = id_to_tool.get(tool_id, tool_id)
    elif kind == "integration":
        int_id = resource_ref.get("integration_id")
        if int_id:
            id_to_int = profile.id_to_integration_name()
            result["integration_id"] = id_to_int.get(int_id, int_id)
    elif kind == "trust_boundary":
        tb_id = resource_ref.get("trust_boundary_id")
        if tb_id:
            id_to_tb = profile.id_to_trust_boundary_name()
            result["trust_boundary_id"] = id_to_tb.get(tb_id, tb_id)
    elif kind == "output_surface":
        ep_id = resource_ref.get("entry_point_id")
        if ep_id:
            id_to_ep = profile.id_to_entry_point_name()
            result["entry_point_id"] = id_to_ep.get(ep_id, ep_id)

    return result


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
    canonical_ingress = projection_context.get("canonical_ingress", {})
    if canonical_ingress:
        ep_id = canonical_ingress.get("entry_point_id")
        if ep_id:
            result["canonical_ingress_name"] = id_to_ep.get(ep_id, ep_id)
        else:
            result["canonical_ingress_name"] = str(canonical_ingress)
    else:
        result["canonical_ingress_name"] = ""

    # Convert resource_ref values in selected_steps
    humanized_steps = []
    for step in projection_context.get("selected_steps", []):
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
    result["selected_steps"] = humanized_steps

    # Keep canonical IDs in the authoritative path record so generated
    # stages cannot replace them, while supplying names for prompt prose.
    source_names = profile.integration_name_to_id()
    source_names.update(profile.entry_point_name_to_id())
    source_id_to_name = {value: key for key, value in source_names.items()}
    boundary_id_to_name = {
        boundary.trust_boundary_id: boundary.name
        for boundary in profile.trust_boundaries or ()
    }
    humanized_paths = []
    for path in projection_context.get("source_influence_paths", []):
        h_path = dict(path)
        h_path["source_name"] = source_id_to_name.get(
            path.get("source_id"), path.get("source_id", "")
        )
        h_path["boundary_name"] = boundary_id_to_name.get(
            path.get("boundary_id"), path.get("boundary_id", "")
        )
        h_path["target_ingress_name"] = id_to_ep.get(
            path.get("target_ingress_id"), path.get("target_ingress_id", "")
        )
        humanized_paths.append(h_path)
    result["source_influence_paths"] = humanized_paths

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

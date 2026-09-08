"""Phase 3.2: deterministic content-surface facts from a capability profile.

A ``third_party_via_content`` adversary needs a retrieval or tool-content
surface the third party could reach.  The facts derive only from typed
capability-profile records; a profile-less run fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass

from asago_scenario_generator.models.capability_profile import CapabilityProfile

# KC sub-codes that establish a content surface a third party could reach:
# RAG context data sources, web/browser access, and vector-store access.
_CONTENT_SURFACE_KC_CODES = frozenset({"KC6.3.3", "KC6.4", "KCX-VSTORE"})


@dataclass(frozen=True)
class ContentSurfaceFacts:
    """Typed content-surface facts derived once per run."""

    has_content_surface: bool
    evidence: tuple[str, ...] = ()


def content_surface_facts(profile: CapabilityProfile | None) -> ContentSurfaceFacts:
    """Derive content-surface facts from typed profile records only.

    ``None`` fails closed: an absent profile never establishes a surface.
    Only explicit typed facts count: an ``external_content`` entry point that
    admits input, an explicitly ``indirect`` controllability, or a
    content-bearing KC sub-code.  Name-keyword heuristics never contribute.
    """
    if profile is None:
        return ContentSurfaceFacts(has_content_surface=False)
    evidence: list[str] = []
    for entry_point in profile.entry_points:
        if entry_point.direction == "output":
            continue
        if entry_point.entry_point_type == "external_content":
            evidence.append(f"entry point {entry_point.name!r} admits external content")
        elif entry_point.controllability == "indirect":
            evidence.append(
                f"entry point {entry_point.name!r} has explicit indirect "
                "attacker controllability"
            )
    surface_codes = sorted(_CONTENT_SURFACE_KC_CODES & set(profile.kc_subcodes))
    if surface_codes:
        evidence.append("knowledge codes " + ", ".join(surface_codes))
    return ContentSurfaceFacts(
        has_content_surface=bool(evidence),
        evidence=tuple(evidence),
    )

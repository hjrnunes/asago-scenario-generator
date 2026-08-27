"""Cross-layer consistency metrics for scenario evaluation.

Measures alignment between the three generated layers:
- Narrative (zone_sequence, entry_point, steps)
- Attack tree (node zones, threat_ids, tree structure)
- Gherkin feature file (zone annotations, Background, steps)
"""

from __future__ import annotations

import re
from typing import Any

from asago_scenario_generator.models.capability_profile import (
    ZONE_DISPLAY_NAMES,
    ZONE_NAMES,
)


def _jaccard(a: set, b: set) -> float:
    """Jaccard similarity of two sets. Returns 1.0 if both are empty."""
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


def _collect_tree_zones(node: dict[str, Any]) -> set[str]:
    """Recursively collect all zone values from attack tree nodes."""
    zones: set[str] = set()
    zone = node.get("zone")
    if zone is not None:
        zones.add(str(zone))
    for child in node.get("children") or []:
        zones |= _collect_tree_zones(child)
    return zones


def _collect_tree_leaves(node: dict[str, Any]) -> list[dict[str, Any]]:
    """Recursively collect all leaf nodes from the attack tree."""
    children = node.get("children") or []
    if not children:
        return [node]
    leaves: list[dict[str, Any]] = []
    for child in children:
        leaves.extend(_collect_tree_leaves(child))
    return leaves


_INT_TO_ZONE_NAME = dict(enumerate(ZONE_NAMES, 1))
_ZONE_NAME_SET = frozenset(ZONE_NAMES)


def _zone_display_name_for_token(token: str) -> str | None:
    """Canonical zone whose display label contains the token, if any."""
    for zone_name, display in ZONE_DISPLAY_NAMES.items():
        if token.lower() in display.lower():
            return zone_name
    return None


def _zone_from_annotation_token(token: str) -> str | None:
    """Canonical zone name for one annotation token, or None."""
    if token.isdigit():
        return _INT_TO_ZONE_NAME.get(int(token))
    if token in _ZONE_NAME_SET:
        return token
    return _zone_display_name_for_token(token)


def _extract_gherkin_zones(gherkin_text: str) -> set[str]:
    """Extract zone annotations from Gherkin text.

    Supports both legacy integer annotations (e.g. ``# Zone 2``) and
    string zone names (e.g. ``# Zone reasoning``).  Legacy integers are
    mapped to the canonical string name via ``ZONE_NAMES``.
    """
    zones: set[str] = set()
    # Match "# Zone <word_or_number>"
    for match in re.finditer(r"#\s*[Zz]one\s+(\S+)", gherkin_text):
        name = _zone_from_annotation_token(match.group(1))
        if name is not None:
            zones.add(name)
    return zones


def _normalize_entry_point(ep: str) -> str:
    """Normalize entry point text for fuzzy matching."""
    return re.sub(r"[^a-z0-9]+", " ", ep.lower()).strip()


def zone_alignment(
    scenario: dict[str, Any],
    gherkin_text: str | None = None,
) -> float:
    """Jaccard similarity of zone sets across narrative, attack tree, and Gherkin.

    Computes pairwise Jaccard between:
    - narrative.zone_sequence zones
    - attack tree node zones (recursive)
    - Gherkin zone annotations (if gherkin_text provided)

    Returns the average pairwise Jaccard similarity.
    """
    narrative = scenario.get("narrative", {})
    narrative_zones = set(narrative.get("zone_sequence", []))

    tree_root = scenario.get("attack_tree", {}).get("root", {})
    tree_zones = _collect_tree_zones(tree_root)

    pairs: list[float] = [_jaccard(narrative_zones, tree_zones)]

    if gherkin_text is not None:
        gherkin_zones = _extract_gherkin_zones(gherkin_text)
        if gherkin_zones:  # Only count if gherkin has zone annotations
            pairs.append(_jaccard(narrative_zones, gherkin_zones))
            pairs.append(_jaccard(tree_zones, gherkin_zones))

    return sum(pairs) / len(pairs) if pairs else 1.0


def _tokens_overlap_threshold(a: str, b: str, threshold: float = 0.4) -> bool:
    """True when at least *threshold* of a's tokens also appear in b."""
    tokens_a = set(a.split())
    tokens_b = set(b.split())
    if not tokens_a:
        return False
    return len(tokens_a & tokens_b) >= len(tokens_a) * threshold


def _gherkin_background_text(gherkin_text: str | None) -> str | None:
    """Background section text when the Gherkin has one, else None."""
    if not gherkin_text:
        return None
    bg_match = re.search(
        r"Background:.*?(?=Scenario|$)", gherkin_text, re.DOTALL | re.IGNORECASE
    )
    if not bg_match:
        return None
    return bg_match.group()


def entry_point_agreement(
    scenario: dict[str, Any],
    gherkin_text: str | None = None,
) -> int:
    """Check if the narrative entry_point appears in the Gherkin Background or attack tree root.

    Returns 1 if found in at least one location, 0 otherwise.
    """
    narrative = scenario.get("narrative", {})
    entry_point = narrative.get("entry_point", "")
    if not entry_point:
        return 0

    ep_norm = _normalize_entry_point(entry_point)

    # Check attack tree root label
    tree_root = scenario.get("attack_tree", {}).get("root", {})
    root_label = _normalize_entry_point(tree_root.get("label", ""))
    root_desc = _normalize_entry_point(tree_root.get("description", "") or "")

    # Check if entry point keywords appear in root (at least 40% of tokens)
    root_text = " ".join((root_label, root_desc))
    if _tokens_overlap_threshold(ep_norm, root_text):
        return 1

    # Check Gherkin Background
    bg_text = _gherkin_background_text(gherkin_text)
    if bg_text is not None and _tokens_overlap_threshold(
        ep_norm, _normalize_entry_point(bg_text)
    ):
        return 1

    return 0


# Stopwords to exclude from step/leaf matching
_STEP_MATCH_STOPWORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "to",
        "in",
        "of",
        "and",
        "or",
        "is",
        "for",
        "with",
        "on",
        "at",
        "by",
        "from",
        "that",
        "this",
        "it",
        "as",
    }
)


def _zone_leaf_token_map(leaves: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Map zone to the union of leaf label/description tokens in that zone."""
    zone_leaf_tokens: dict[str, set[str]] = {}
    for leaf in leaves:
        z = leaf.get("zone")
        if z is not None:
            label_tokens = set(_normalize_entry_point(leaf.get("label", "")).split())
            desc_tokens = set(
                _normalize_entry_point(leaf.get("description", "") or "").split()
            )
            zone_leaf_tokens.setdefault(z, set()).update(label_tokens | desc_tokens)
    return zone_leaf_tokens


def _step_mapped(
    step: dict[str, Any],
    zone_leaf_tokens: dict[str, set[str]],
    stopwords: frozenset[str],
) -> bool:
    """True when a narrative step shares a significant word with a leaf."""
    step_zone = step.get("zone")
    step_action = _normalize_entry_point(step.get("action", ""))
    step_tokens = set(step_action.split()) - stopwords

    if step_zone not in zone_leaf_tokens:
        return False
    leaf_tokens = zone_leaf_tokens[step_zone] - stopwords
    return bool(step_tokens) and bool(leaf_tokens) and bool(step_tokens & leaf_tokens)


def step_node_correspondence(scenario: dict[str, Any]) -> float:
    """Ratio of narrative steps with a plausible mapping to attack tree leaves.

    A narrative step is considered mapped if a leaf node exists in the same zone
    and shares at least one significant word with the step action.
    """
    narrative = scenario.get("narrative", {})
    steps = narrative.get("steps", [])
    if not steps:
        return 0.0

    tree_root = scenario.get("attack_tree", {}).get("root", {})
    leaves = _collect_tree_leaves(tree_root)

    # Build a mapping of zone -> set of leaf label tokens
    zone_leaf_tokens = _zone_leaf_token_map(leaves)

    mapped = 0
    for step in steps:
        if _step_mapped(step, zone_leaf_tokens, _STEP_MATCH_STOPWORDS):
            mapped += 1

    return mapped / len(steps)


def score_consistency(
    scenario: dict[str, Any],
    gherkin_text: str | None = None,
) -> dict[str, Any]:
    """Compute all cross-layer consistency metrics for a single scenario.

    Returns:
        Dict with zone_alignment, entry_point_agreement, step_node_correspondence,
        and an overall mean score.
    """
    za = zone_alignment(scenario, gherkin_text)
    epa = entry_point_agreement(scenario, gherkin_text)
    snc = step_node_correspondence(scenario)

    return {
        "zone_alignment": round(za, 4),
        "entry_point_agreement": epa,
        "step_node_correspondence": round(snc, 4),
        "mean": round((za + epa + snc) / 3, 4),
    }

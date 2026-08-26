"""Shared traversal and artifact helpers for validation passes."""

from __future__ import annotations

import re
from functools import cache
from typing import TYPE_CHECKING, Any

from asago_scenario_generator.models.attack_tree import AttackTreeNode, GateType
from asago_scenario_generator.pipeline.tree_utils import collect_tree_zones

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope


_VALID_THREAT_IDS: frozenset[str] = frozenset(f"T{i}" for i in range(1, 18))


def _collect_node_labels(node: AttackTreeNode) -> list[tuple[str, str]]:
    """Recursively collect all (label, zone) pairs from an attack tree."""
    labels: list[tuple[str, str]] = [(node.label, node.zone)]
    if node.children:
        for child in node.children:
            labels.extend(_collect_node_labels(child))
    return labels


def _validation_passed(scenario: ScenarioEnvelope) -> bool:
    """True when all three validation blocks are currently valid."""
    return (
        scenario.validation.phantom.valid
        and scenario.validation.structural.valid
        and scenario.validation.semantic.valid
    )


# Cross-artifact consistency helpers (bv5s)
# ---------------------------------------------------------------------------


def _extract_narrative_technique_ids(
    narrative: Any,
) -> set[str]:
    """Backward-compatible set view of canonical narrative references."""
    from asago_scenario_generator.pipeline.technique_scopes import (
        narrative_reference_ids,
    )

    return set(narrative_reference_ids(narrative))


def _collect_tree_node_threat_ids(node: AttackTreeNode) -> set[str]:
    """Recursively collect all non-None threat_id values from tree nodes."""
    ids: set[str] = set()
    if node.threat_id is not None:
        ids.add(node.threat_id)
    if node.children:
        for child in node.children:
            ids.update(_collect_tree_node_threat_ids(child))
    return ids


def _collect_tree_node_zones(node: AttackTreeNode) -> set[str]:
    """Recursively collect all zone values from attack tree nodes."""
    return collect_tree_zones(node, include_empty=False)


def _zone_display_name_match(token: str, display_names: dict[str, str]) -> str | None:
    """Zone name whose display label contains the token, if any."""
    for zone_name, display in display_names.items():
        if token.lower() in display.lower():
            return zone_name
    return None


def _zone_token_to_name(
    token: str, int_to_name: dict[int, str], valid_zone_set: set[str]
) -> str | None:
    """Resolve one ``# Zone <token>`` annotation token to a zone name."""
    if token.isdigit():
        return int_to_name.get(int(token))
    if token in valid_zone_set:
        return token
    return None


def _zone_annotation_tokens(gherkin_text: str) -> set[str]:
    """Zone names from ``# Zone <word_or_number>`` annotations."""
    from asago_scenario_generator.models.capability_profile import (
        ZONE_DISPLAY_NAMES,
        ZONE_NAMES,
    )

    _INT_TO_NAME = dict(enumerate(ZONE_NAMES, 1))
    valid_zone_set = set(ZONE_NAMES)
    zones: set[str] = set()

    for match in re.finditer(r"#\s*[Zz]one\s+(\S+)", gherkin_text):
        token = match.group(1)
        resolved = _zone_token_to_name(token, _INT_TO_NAME, valid_zone_set)
        if resolved is not None:
            zones.add(resolved)
        else:
            display_match = _zone_display_name_match(token, ZONE_DISPLAY_NAMES)
            if display_match is not None:
                zones.add(display_match)

    return zones


def _inline_zone_tokens(gherkin_text: str) -> set[str]:
    """Zone names from ``(zone_name)`` inline annotations."""
    from asago_scenario_generator.models.capability_profile import ZONE_NAMES

    valid_zone_set = set(ZONE_NAMES)
    zones: set[str] = set()

    for match in re.finditer(r"\((\w+)\)", gherkin_text):
        token = match.group(1)
        if token in valid_zone_set:
            zones.add(token)

    return zones


def _extract_gherkin_zones_for_validation(gherkin_text: str) -> set[str]:
    """Extract zone annotations from Gherkin text for validation.

    Supports:
    - ``# Zone reasoning`` comments
    - ``(zone_name)`` inline annotations in step text

    Reuses the same zone name resolution as the eval layer.
    """
    return _zone_annotation_tokens(gherkin_text) | _inline_zone_tokens(gherkin_text)


@cache
def _valid_technique_ids() -> frozenset[str]:
    """Return valid tree technique IDs from their authoritative sources."""
    from asago_scenario_generator.data.atlas import ATLAS_TECHNIQUE_NAMES
    from asago_scenario_generator.data.taxonomy_pins import (
        load_atlas_technique_identifiers,
    )

    # LAAF has no bundled authoritative catalog yet.  Preserve its existing
    # explicitly curated extension identifiers while ATLAS membership comes
    # exclusively from the pinned release artifact.
    laaf_ids = {
        technique_id
        for technique_id in ATLAS_TECHNIQUE_NAMES
        if not technique_id.startswith("AML.")
    }
    return load_atlas_technique_identifiers() | laaf_ids


def _semantic_gherkin_text(scenario: ScenarioEnvelope) -> str:
    """Return the scenario's Gherkin behavior text, if any."""
    from asago_scenario_generator.models.scenario import (
        BehaviorSpec as _BS2,
    )

    behavior_spec = scenario.behavior_spec
    if behavior_spec and isinstance(behavior_spec, _BS2):
        return behavior_spec.gherkin_text
    if behavior_spec and isinstance(behavior_spec, str):
        return behavior_spec
    return ""


def _collect_leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all LEAF nodes in the tree."""
    if node.gate == GateType.LEAF:
        return [node]
    leaves: list[AttackTreeNode] = []
    if node.children:
        for child in node.children:
            leaves.extend(_collect_leaves(child))
    return leaves

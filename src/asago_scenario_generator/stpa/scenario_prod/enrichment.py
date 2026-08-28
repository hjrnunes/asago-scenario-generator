"""Deterministic envelope enrichment — system_context and consumer_hints.

Two pure functions that compute enrichment blocks from SP1 data and
Stage 6 artifacts without any LLM calls:

- :func:`compute_system_context` — resolves SP1 data into a
  :class:`SystemContext` block.
- :func:`compute_consumer_hints` — computes rule-based
  :class:`ConsumerHints` for adapter filtering.
"""

from __future__ import annotations

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    Responsibility,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    ConsumerHints,
    SystemContext,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

__all__ = ["compute_consumer_hints", "compute_system_context"]

# Keywords in attack-tree leaf text that indicate tool execution.
_TOOL_KEYWORDS: tuple[str, ...] = (
    "tool",
    "execute",
    "call",
    "invoke",
    "api",
    "command",
    "function",
    "script",
)

# Phrases in narrative text that indicate multi-turn interaction.
_MULTI_TURN_PHRASES: tuple[str, ...] = (
    "subsequent turn",
    "second message",
    "follow-up request",
    "follow up request",
    "multi-turn",
    "multi turn",
    "later turn",
    "next turn",
    "repeated interaction",
    "over multiple turns",
    "across turns",
    "second turn",
    "third turn",
    "subsequent message",
    "follow-up message",
)

# garak_testability mapping from primary attack zone.
_GARAK_TESTABILITY: dict[str, str] = {
    "input": "high",
    "reasoning": "medium",
    "tool_execution": "low",
    "memory": "low",
    "inter_agent": "low",
}


def compute_system_context(
    capability_profile: CapabilityProfile,
    control_structure: ControlStructure,
    spec: ScenarioSpec,
) -> SystemContext:
    """Resolve SP1 data into a :class:`SystemContext` block.

    Looks up ``target_responsibility_description`` and
    ``target_control_action_description`` from the control structure
    using the spec's ``target_controller`` (resp_id) and
    ``target_control_action`` (ca_id).  Inlines tool names,
    active zones, and boolean flags from the capability profile.

    Args:
        capability_profile: The SP1 capability profile.
        control_structure: The SP1 control structure.
        spec: The scenario spec providing target controller/action IDs.

    Returns:
        A populated :class:`SystemContext`.
    """
    resp = _find_responsibility(control_structure, spec.target_controller)
    resp_desc = resp.description if resp else ""
    ca_desc = _find_control_action_description(resp, spec.target_control_action)

    tool_names = _extract_tool_names(capability_profile)

    return SystemContext(
        target_responsibility_description=resp_desc,
        target_control_action_description=ca_desc,
        tool_inventory=tool_names,
        active_zones=list(capability_profile.zones_active),
        multi_agent=capability_profile.multi_agent,
        has_persistent_memory=capability_profile.has_persistent_memory,
    )


def compute_consumer_hints(
    capability_profile: CapabilityProfile,
    attack_tree: dict,
    narrative: str,
    primary_attack_zone: str,
) -> ConsumerHints:
    """Compute deterministic consumer hints for adapter filtering.

    All fields are rule-based — no LLM calls.

    Args:
        capability_profile: The SP1 capability profile.
        attack_tree: The Stage 6 attack tree dict.
        narrative: The Stage 6 narrative text.
        primary_attack_zone: The primary attack zone for this scenario
            (e.g. ``"input"``, ``"tool_execution"``).

    Returns:
        A populated :class:`ConsumerHints`.
    """
    requires_tool_execution = _tree_mentions_tools(attack_tree)
    requires_multi_turn = _narrative_indicates_multi_turn(narrative)
    requires_multi_agent = capability_profile.multi_agent
    requires_persistent_state = capability_profile.has_persistent_memory

    garak = _garak_testability(primary_attack_zone)
    midojo = _midojo_testability(
        primary_attack_zone,
        requires_tool_execution,
        requires_multi_agent,
        requires_persistent_state,
    )

    return ConsumerHints(
        primary_attack_zone=primary_attack_zone,
        requires_tool_execution=requires_tool_execution,
        requires_multi_turn=requires_multi_turn,
        requires_multi_agent=requires_multi_agent,
        requires_persistent_state=requires_persistent_state,
        garak_testability=garak,
        midojo_testability=midojo,
    )


def _tree_mentions_tools(attack_tree: dict) -> bool:
    """Check attack tree leaves for tool-related keywords."""
    leaves = attack_tree.get("leaves", [])
    if not isinstance(leaves, list):
        return False
    for leaf in leaves:
        text = _extract_leaf_text(leaf)
        if _contains_any_keyword(text, _TOOL_KEYWORDS):
            return True
    return False


def _extract_leaf_text(leaf: object) -> str:
    """Extract text from a leaf node (str or dict).

    Returns the raw text without case conversion — callers that need
    case-insensitive matching should use :func:`_contains_any_keyword`.
    """
    if isinstance(leaf, str):
        return leaf
    if isinstance(leaf, dict):
        return _extract_text_from_dict(leaf)
    return ""


def _extract_text_from_dict(leaf: dict) -> str:
    """Extract the first string value from known text keys in a dict leaf."""
    for key in ("label", "text", "description", "name"):
        val = leaf.get(key)
        if isinstance(val, str):
            return val
    return ""


def _find_responsibility(
    control_structure: ControlStructure, resp_id: str
) -> Responsibility | None:
    """Find a responsibility by ID in the control structure."""
    for resp in control_structure.responsibilities:
        if resp.resp_id == resp_id:
            return resp
    return None


def _find_control_action_description(
    responsibility: Responsibility | None, ca_id: str
) -> str:
    """Find a control action description by ID within a responsibility."""
    if responsibility is None:
        return ""
    for ca in responsibility.control_actions:
        if ca.ca_id == ca_id:
            return ca.description
    return ""


def _extract_tool_names(capability_profile: CapabilityProfile) -> list[str]:
    """Extract tool names from the capability profile inventory."""
    if capability_profile.tool_inventory:
        return [entry.name for entry in capability_profile.tool_inventory]
    return []


def _contains_any_keyword(text: str, keywords: tuple[str, ...]) -> bool:
    """Check if *text* contains any of *keywords* (case-insensitive)."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in keywords)


def _narrative_indicates_multi_turn(narrative: str) -> bool:
    """Check narrative for multi-turn indicator phrases."""
    if not narrative:
        return False
    return _contains_any_keyword(narrative, _MULTI_TURN_PHRASES)


def _garak_testability(primary_attack_zone: str) -> str:
    """Rule-based garak testability from primary attack zone.

    - ``input`` zone → ``high``
    - ``reasoning`` zone → ``medium``
    - ``tool_execution`` / ``memory`` / ``inter_agent`` zones → ``low``
    """
    return _GARAK_TESTABILITY.get(primary_attack_zone, "low")


def _midojo_testability(
    primary_attack_zone: str,
    requires_tool_execution: bool,
    requires_multi_agent: bool,
    requires_persistent_state: bool,
) -> str:
    """Rule-based midojo testability.

    - ``high`` if ``requires_tool_execution`` is True AND ``tool_execution``
      is the primary attack zone.
    - ``medium`` if ``requires_multi_agent`` OR ``requires_persistent_state``
      is True.
    - ``low`` otherwise.
    """
    if requires_tool_execution and primary_attack_zone == "tool_execution":
        return "high"
    if requires_multi_agent or requires_persistent_state:
        return "medium"
    return "low"

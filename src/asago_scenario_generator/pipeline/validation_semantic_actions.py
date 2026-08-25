"""Typed action, goal alignment, and access-provenance checks."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from asago_scenario_generator.models.scenario import SemanticViolation
from asago_scenario_generator.pipeline.validation_common import _collect_leaves

if TYPE_CHECKING:
    from asago_scenario_generator.models.capability_profile import CapabilityProfile
    from asago_scenario_generator.models.scenario import ScenarioEnvelope


def _tool_execution_leaf_untyped(action: Any, zone: str | None) -> bool:
    """True when a tool_execution leaf lacks a typed invocation action."""
    return zone == "tool_execution" and (
        action is None
        or action.kind not in {"tool_invocation", "integration_interaction"}
    )


def _check_semantic_ingress_action(
    leaf: Any,
    action: Any,
    profile: CapabilityProfile,
    is_attacker_accessible_ingress: Any,
    violations: list[SemanticViolation],
) -> None:
    """Resolve an initial_ingress action against the profile."""
    resolved_ep = profile.resolve_entry_point(action.entry_point_id)
    if resolved_ep is None:
        violations.append(
            SemanticViolation(
                rule="unknown_entry_point_id",
                message=(
                    f"Leaf node '{leaf.id}' references unknown "
                    f"entry_point_id '{action.entry_point_id}'"
                ),
                severity="major",
            )
        )
    elif not is_attacker_accessible_ingress(
        resolved_ep,
        set(profile.zones_active) if profile.zones_active else set(),
    ):
        violations.append(
            SemanticViolation(
                rule="inaccessible_ingress_entry_point",
                message=(
                    f"Leaf node '{leaf.id}' references entry "
                    f"point '{resolved_ep.name}' "
                    f"(entry_point_id '{action.entry_point_id}') "
                    f"which is not an attacker-accessible ingress "
                    f"route (output-only, system-controlled, or "
                    f"inactive ingress zone)."
                ),
                severity="major",
            )
        )


def _check_semantic_tool_action(
    leaf: Any,
    action: Any,
    profile: CapabilityProfile,
    violations: list[SemanticViolation],
) -> None:
    """Resolve a tool_invocation action against the profile."""
    if profile.resolve_tool(action.tool_id) is None:
        violations.append(
            SemanticViolation(
                rule="phantom_tool",
                message=(
                    f"Leaf node '{leaf.id}' references unknown "
                    f"tool_id '{action.tool_id}'"
                ),
                severity="major",
            )
        )
    if (
        action.integration_id is not None
        and profile.resolve_integration(action.integration_id) is None
    ):
        violations.append(
            SemanticViolation(
                rule="unknown_integration_id",
                message=(
                    f"Leaf node '{leaf.id}' references unknown "
                    f"integration_id '{action.integration_id}'"
                ),
                severity="major",
            )
        )


def _check_semantic_integration_action(
    leaf: Any,
    action: Any,
    profile: CapabilityProfile,
    violations: list[SemanticViolation],
) -> None:
    """Resolve an integration_interaction action against the profile."""
    if (
        action.kind == "integration_interaction"
        and profile.resolve_integration(action.integration_id) is None
    ):
        violations.append(
            SemanticViolation(
                rule="unknown_integration_id",
                message=(
                    f"Leaf node '{leaf.id}' references unknown "
                    f"integration_id '{action.integration_id}'"
                ),
                severity="major",
            )
        )


def _check_semantic_leaf_action(
    leaf: Any,
    profile: CapabilityProfile,
    is_attacker_accessible_ingress: Any,
    violations: list[SemanticViolation],
) -> None:
    """Resolve one leaf's typed action against the canonical profile."""
    action = leaf.action
    if _tool_execution_leaf_untyped(action, leaf.zone):
        violations.append(
            SemanticViolation(
                rule="untyped-tool-execution",
                message=(
                    f"Leaf node '{leaf.id}' is in tool_execution zone "
                    "but does not have a tool_invocation or "
                    "integration_interaction action"
                ),
                severity="major",
            )
        )
    if action is None:
        return
    if action.kind == "initial_ingress":
        _check_semantic_ingress_action(
            leaf, action, profile, is_attacker_accessible_ingress, violations
        )
    elif action.kind == "tool_invocation":
        _check_semantic_tool_action(leaf, action, profile, violations)
    else:
        _check_semantic_integration_action(leaf, action, profile, violations)


def _check_semantic_typed_actions(
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
    violations: list[SemanticViolation],
) -> None:
    """Resolve every leaf typed action against the canonical profile."""
    from asago_scenario_generator.models.capability_profile import (
        is_attacker_accessible_ingress,
    )

    for leaf in _collect_leaves(scenario.attack_tree.root):
        _check_semantic_leaf_action(
            leaf, profile, is_attacker_accessible_ingress, violations
        )


def _leaf_action_is_tool_invocation(action: Any) -> bool:
    """True when a leaf carries a tool_invocation action."""
    return action is not None and action.kind == "tool_invocation"


def _tool_name_mentions(resolved_tool: Any, keywords: list[str]) -> bool:
    """True when a resolved tool name mentions any keyword."""
    return resolved_tool is not None and any(
        kw in resolved_tool.name.lower() for kw in keywords
    )


def _scenario_has_financial_tool_leaf(
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
) -> bool:
    """True when any tree leaf invokes a financial tool."""
    _financial_keywords = ["refund", "payment", "billing", "transaction"]
    for leaf in _collect_leaves(scenario.attack_tree.root):
        if not _leaf_action_is_tool_invocation(leaf.action):
            continue
        resolved_tool = profile.resolve_tool(leaf.action.tool_id)
        if _tool_name_mentions(resolved_tool, _financial_keywords):
            return True
    return False


def _check_semantic_exfiltration_goal(
    goal_category: str,
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
    violations: list[SemanticViolation],
) -> None:
    """Flag a data exfiltration goal with financial tool leaves."""
    if goal_category.startswith("PR-1") and _scenario_has_financial_tool_leaf(
        scenario, profile
    ):
        violations.append(
            SemanticViolation(
                rule="goal_mechanism_mismatch",
                message=(
                    f"Data exfiltration goal '{goal_category}' "
                    f"assigned but attack tree contains "
                    f"financial tool leaves (refund/payment/"
                    f"billing/transaction)"
                ),
                severity="minor",
            )
        )


def _scenario_describes_social_engineering(
    scenario: ScenarioEnvelope,
) -> bool:
    """True when the narrative describes a social engineering attack."""
    _se_keywords = [
        "phishing",
        "credential",
        "social engineering",
        "impersonat",
    ]
    _narrative_text = " ".join(
        [scenario.narrative.title, scenario.narrative.summary]
        + [f"{s.action} {s.effect}" for s in scenario.narrative.steps]
    ).lower()
    return any(kw in _narrative_text for kw in _se_keywords)


def _check_semantic_safety_bypass_goal(
    goal_category: str,
    scenario: ScenarioEnvelope,
    violations: list[SemanticViolation],
) -> None:
    """Flag a safety bypass goal with social engineering narrative."""
    if goal_category.startswith("AB-1") and _scenario_describes_social_engineering(
        scenario
    ):
        violations.append(
            SemanticViolation(
                rule="goal_mechanism_mismatch",
                message=(
                    f"Safety bypass goal '{goal_category}' assigned "
                    f"but narrative describes a social "
                    f"engineering attack"
                ),
                severity="minor",
            )
        )


def _check_semantic_supply_chain_goal(
    goal_category: str,
    actor_type: Any,
    violations: list[SemanticViolation],
) -> None:
    """Flag a supply-chain goal on a non-supply-chain actor."""
    _NON_SUPPLY_CHAIN_ACTORS = {
        "negligent-insider",
        "adversarial-user",
        "cybercriminal",
    }
    if goal_category.startswith("IN-7") and actor_type in _NON_SUPPLY_CHAIN_ACTORS:
        violations.append(
            SemanticViolation(
                rule="goal_actor_mismatch",
                message=(
                    f"Supply-chain goal '{goal_category}' assigned to "
                    f"actor_type '{actor_type}' which is not a "
                    f"supply-chain actor"
                ),
                severity="moderate",
            )
        )


def _check_semantic_goal_category_alignment(
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
    violations: list[SemanticViolation],
) -> None:
    """Flag mismatches between goal_category and actor/mechanism."""
    goal_category = (
        scenario.actor_profile.goal_category if scenario.actor_profile else None
    )
    if goal_category and isinstance(goal_category, str):
        actor_type = (
            scenario.actor_profile.actor_type if scenario.actor_profile else None
        )
        _check_semantic_supply_chain_goal(goal_category, actor_type, violations)
        _check_semantic_exfiltration_goal(goal_category, scenario, profile, violations)
        _check_semantic_safety_bypass_goal(goal_category, scenario, violations)


def _scenario_ingress_actions(
    scenario: ScenarioEnvelope,
) -> list[tuple[str, Any]]:
    """Return (leaf_id, action) pairs for initial_ingress leaves."""
    return [
        (leaf.id, leaf.action)
        for leaf in _collect_leaves(scenario.attack_tree.root)
        if leaf.action is not None and leaf.action.kind == "initial_ingress"
    ]


def _scenario_actor_type(scenario: ScenarioEnvelope) -> Any:
    """Return the scenario actor type, if any."""
    return scenario.actor_profile.actor_type if scenario.actor_profile else None


def _scenario_actor_access(scenario: ScenarioEnvelope) -> Any:
    """Return the scenario actor access provenance, if any."""
    return scenario.actor_profile.access if scenario.actor_profile else None


def _missing_access_provenance(
    actor_type: Any,
    access: Any,
    ingress_actions: list[tuple[str, Any]],
) -> bool:
    """True when an actor has ingress leaves without typed access."""
    return actor_type and access is None and ingress_actions


def _check_semantic_actor_access_policy(
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
    violations: list[SemanticViolation],
) -> None:
    """Run shared actor access-policy and narrative realization validation."""
    from asago_scenario_generator.pipeline.generate.actor_access import (
        validate_actor_access_provenance as _vap,
    )
    from asago_scenario_generator.pipeline.generate.narrative_access import (
        validate_narrative_access_realization as _vnr,
    )

    for _v in _vap(scenario.actor_profile, profile):
        violations.append(
            SemanticViolation(
                rule=_v.rule,
                message=_v.message,
                severity="major",
            )
        )
    access = _scenario_actor_access(scenario)
    canonical_ep_id = scenario.initial_entry_point_id
    if access.initial_entry_point_id != canonical_ep_id:
        violations.append(
            SemanticViolation(
                rule="initial_entry_point_id_mismatch",
                message=(
                    f"Actor access initial_entry_point_id "
                    f"'{access.initial_entry_point_id}' does not "
                    f"match scenario envelope "
                    f"initial_entry_point_id '{canonical_ep_id}'."
                ),
                severity="major",
            )
        )
    for _v in _vnr(scenario.narrative, scenario.actor_profile):
        violations.append(
            SemanticViolation(
                rule=_v.rule,
                message=_v.message,
                severity="major",
            )
        )


def _check_semantic_tree_ingress_identity(
    scenario: ScenarioEnvelope,
    ingress_actions: list[tuple[str, Any]],
    violations: list[SemanticViolation],
) -> None:
    """Require every tree initial_ingress action to match the envelope entry
    point."""
    canonical_ep_id = scenario.initial_entry_point_id
    for leaf_id, ingress_act in ingress_actions:
        if ingress_act.entry_point_id != canonical_ep_id:
            violations.append(
                SemanticViolation(
                    rule="initial_entry_point_id_mismatch",
                    message=(
                        f"Attack tree initial_ingress action "
                        f"'{leaf_id}' uses entry_point_id "
                        f"'{ingress_act.entry_point_id}' which "
                        f"diverges from canonical "
                        f"'{canonical_ep_id}'."
                    ),
                    severity="major",
                )
            )


def _check_semantic_actor_access_provenance(
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
    violations: list[SemanticViolation],
) -> None:
    """Run actor/access provenance and tree-wide ingress identity checks."""
    actor_type = _scenario_actor_type(scenario)
    access = _scenario_actor_access(scenario)
    ingress_actions = _scenario_ingress_actions(scenario)
    if _missing_access_provenance(actor_type, access, ingress_actions):
        violations.append(
            SemanticViolation(
                rule="missing_access_provenance",
                message=(
                    f"Actor '{actor_type}' has no typed access provenance (cmps.6)."
                ),
                severity="moderate",
            )
        )
    if actor_type and access is not None:
        _check_semantic_actor_access_policy(scenario, profile, violations)
    _check_semantic_tree_ingress_identity(scenario, ingress_actions, violations)

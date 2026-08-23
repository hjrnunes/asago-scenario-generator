"""Single source of truth for projection step-to-leaf compatibility rules.

These validator mappings are the authoritative compatibility contract:
the projection traceability validator enforces them on finalized artifacts
and the prompt alignment table derives its per-step "allowed tree kinds"
cells from exactly these sets, so prompts stay synchronized with
validation.
"""

from __future__ import annotations

# Mapping from canonical chain step action_kind to valid tree leaf action kinds.
# Canonical action_kinds: prepare, deliver, invoke, transform, persist, observe, impact
# Tree leaf action kinds: initial_ingress, external_precondition, ai_system_action,
#   attacker_action, tool_invocation, integration_interaction, impact
STEP_TO_LEAF_ACTION_COMPAT: dict[str, set[str]] = {
    "prepare": {"external_precondition", "initial_ingress"},
    "deliver": {"initial_ingress", "attacker_action"},
    "invoke": {
        "initial_ingress",
        "attacker_action",
        "tool_invocation",
        "integration_interaction",
    },
    "transform": {"ai_system_action"},
    "persist": {"ai_system_action", "attacker_action", "tool_invocation"},
    "observe": {
        "initial_ingress",
        "attacker_action",
        "ai_system_action",
        "integration_interaction",
        "external_precondition",
    },
    "impact": {"impact"},
}

# Mapping from canonical executor_role to compatible leaf action kinds.
# 422o.4: all executor roles checked, not just attacker.
EXECUTOR_ROLE_TO_LEAF_COMPAT: dict[str, set[str]] = {
    "attacker": {
        "initial_ingress",
        "attacker_action",
        "external_precondition",
        "impact",
        "tool_invocation",
    },
    "system": {
        "initial_ingress",
        "ai_system_action",
        "tool_invocation",
        "integration_interaction",
        "impact",
    },
    "operator": {"external_precondition", "integration_interaction", "impact"},
}

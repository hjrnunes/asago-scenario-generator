"""Acceptance handlers for the execution environment-basis correction."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from runtime_bootstrap import PROJECT_ROOT
from runtime_shared import (
    _feature_state,
    World,
)

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlActionTemporality,
    ElementRef,
    ReferenceType,
)
from registry import StepTable

step = StepTable()


FEATURE_ID = "stpa_execution_environment_basis"

_ROOT = Path(PROJECT_ROOT)
_PROMPTS = (
    _ROOT / "src" / "asago_scenario_generator" / "stpa" / "system_model" / "prompts"
)


def _state(world: World) -> dict[str, Any]:
    return _feature_state(world, "execution_basis_state")


@step(r"^the execution environment-basis acceptance context is available$")
def _h_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Initialize feature state."""
    del text, examples
    _state(world).clear()
    return True, ""


@step(r"^the Stage 2 action-semantics prompts and critic prompt are inspected$")
def _h_prompts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Read the Stage 2 action and critic prompts for deterministic checks."""
    del text, examples
    paths = (
        _PROMPTS / "stage2_call2b_system.j2",
        _PROMPTS / "stage2_call2b_user.j2",
        _PROMPTS / "critic_system.j2",
    )
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        return False, f"prompt files are missing: {missing}"
    _state(world)["prompt_text"] = "\n".join(
        path.read_text(encoding="utf-8") for path in paths
    )
    return True, ""


@step(r"^Stage 2 defines all five action kinds by typed meaning$")
def _h_action_definitions(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check all five typed action meanings are stated in the prompt."""
    del text, examples
    corpus = _state(world).get("prompt_text", "").lower()
    required = {
        "model_output": ("returned by the tested model", "tested model or agent"),
        "tool_call": ("structured invocation",),
        "state_change": ("session or persistent state",),
        "agent_message": ("internal message",),
        "environment_action": ("external side effect",),
    }
    missing = [
        name
        for name, alternatives in required.items()
        if name not in corpus or not any(item in corpus for item in alternatives)
    ]
    return not missing, f"typed action definitions are missing: {missing}"


@step(r"^Stage 2 gives domain-neutral examples for all five action kinds$")
def _h_action_examples(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the five domain-neutral action-kind contrasts."""
    del text, examples
    corpus = _state(world).get("prompt_text", "").lower()
    alternatives = (
        ("advice to a user", "returning advice"),
        ("loan-renewal invocation", "structured loan-renewal"),
        ("session record", "updating a session"),
        ("risk flag", "sending a risk"),
        ("physical alarm", "activating a physical"),
    )
    missing = [
        items[0] for items in alternatives if not any(item in corpus for item in items)
    ]
    return not missing, f"domain-neutral examples are missing: {missing}"


@step(r"^the critic prompt names a typed action-effect conflict as an explicit gap$")
def _h_critic_gap(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the critic asks for an explicit typed effect conflict gap."""
    del text, examples
    corpus = _state(world).get("prompt_text", "").lower()
    required = ("typed", "effect", "conflict", "gap")
    missing = [item for item in required if item not in corpus]
    return not missing, f"critic prompt lacks typed conflict guidance: {missing}"


@step(r'^a control action whose description says "[^"]+"$')
def _h_typed_action(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Build the intentionally prose-conflicting typed control action."""
    del text, examples
    action = ControlAction(
        ca_id="CA-1-1",
        description="Return advice to a user",
        target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
        effect_kind=ControlActionEffectKind.environment_action,
        temporality=ControlActionTemporality.instantaneous,
    )
    _state(world)["typed_action"] = action
    return True, ""


@step(r'^whose typed effect kind is "[^"]+"$')
def _h_typed_effect(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the feature's declared typed effect before validation."""
    del examples
    match = re.search(r'^whose typed effect kind is "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse typed effect: {text}"
    action = _state(world).get("typed_action")
    actual = action.effect_kind.value if action and action.effect_kind else None
    expected = match.group(1)
    return actual == expected, f"expected typed effect {expected}, got {actual}"


@step(r"^the control action semantics are validated$")
def _h_typed_action_validated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Re-validate the action and ensure prose did not rewrite its effect."""
    del text, examples
    action = _state(world).get("typed_action")
    if action is None:
        return False, "typed action is unavailable"
    validated = ControlAction.model_validate(action.model_dump(mode="python"))
    _state(world)["typed_action"] = validated
    return True, ""


@step(r'^its typed effect kind remains "[^"]+"$')
def _h_typed_action_remains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert the explicit typed effect remains authoritative."""
    del examples
    match = re.search(r'^its typed effect kind remains "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse effect expectation: {text}"
    action = _state(world).get("typed_action")
    actual = action.effect_kind.value if action and action.effect_kind else None
    expected = match.group(1)
    return actual == expected, f"expected {expected}, got {actual}"


register = step.register


__all__ = ["FEATURE_ID", "register"]

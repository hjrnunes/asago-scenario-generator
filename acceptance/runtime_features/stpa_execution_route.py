"""Acceptance handlers for corrected Stage 5 execution-route selection."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from runtime_shared import (
    World,
    _make_sp3_cs,
    _make_sp3_loss_analysis,
    _make_sp3_threat,
)

from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    build_context_bdi_prompts,
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from tests.stpa.sp1_helpers import MockLLMClient


FEATURE_ID = "stpa_execution_route"


def _context():
    """Build one exact offline context for the route examples."""
    return build_scenario_generation_context(
        _make_sp3_threat(),
        _make_sp3_cs(),
        _make_sp3_loss_analysis(),
        scenario_id="SCN-001",
    )


def _route_payload(route: dict, *, stimulus: str = "user_message") -> dict:
    """Build the smallest valid corrected Stage 5 response."""
    return {
        "stimulus": {
            "category": stimulus,
            "description": "The supplied test stimulus exercises the selected factor.",
        },
        "defender_vulnerabilities": [
            {
                "belief_handle": "belief_1",
                "vulnerability": "The selected belief can be stale.",
            },
            {
                "belief_handle": "belief_2",
                "vulnerability": "The selected schema belief can be stale.",
            },
        ],
        "attacker_bdi": {
            "beliefs": ["The controller can act on stale state."],
            "desires": ["Induce the selected unsafe action."],
            "intentions": [
                {
                    "description": "Rely on the selected structural condition.",
                    "source_handles": ["cause_1"],
                }
            ],
        },
        "causal_factors": [
            {
                "source_handle": "cause_1",
                "evidence": "The selected structural condition can remain stale.",
                "temporal_condition": None,
                "evidence_status": "structural_failure",
            }
        ],
        "unsafe_outcome": {
            "condition": {
                "type": "action_presence",
                "control_action_id": "CA-1-1",
                "expected": "not_provided",
            },
            "semantic_proposition": (
                "The model response exhibits the selected unsafe behavior."
                if route.get("action_kind") == "model_output"
                else None
            ),
        },
        "execution_route": route,
    }


def _h_context(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Prepare the immutable Stage 5 context."""
    world.route_context = _context()
    return True, ""


def _h_route(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Capture a provider stimulus and request-local executable route choice."""
    match = re.search(
        r'^the provider describes stimulus "([^"]+)" and selects "([^"]+)" '
        r'with action "([^"]+)"$',
        text,
    )
    if match is None:
        return False, f"Could not parse route choice: {text}"
    stimulus, delivery, action = match.groups()
    world.route_payload = _route_payload(
        {
            "disposition": "executable_route",
            "delivery_class": delivery,
            "selected_factor_handle": "cause_1",
            "action_kind": action,
            "reason": "The supplied structural evidence supports this route.",
        },
        stimulus=stimulus,
    )
    return True, ""


def _h_analytical(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Capture an explicit analytical-only route."""
    world.route_payload = _route_payload(
        {
            "disposition": "analytical_only",
            "gaps": [
                {
                    "code": "operation_missing",
                    "detail": "The source evidence does not establish an operation.",
                    "evidence_handles": ["cause_1"],
                }
            ],
            "reason": "The finding is meaningful but not executable yet.",
        }
    )
    return True, ""


def _h_direct_feedback(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Prepare a structurally valid factor with an incompatible delivery."""
    match = re.search(r'feedback factor "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse feedback factor: {text}"
    handle = match.group(1)
    payload = _route_payload(
        {
            "disposition": "executable_route",
            "delivery_class": "direct_prompt",
            "selected_factor_handle": handle,
            "action_kind": "model_output",
            "reason": "The provider incorrectly treats feedback as direct input.",
        }
    )
    payload["causal_factors"][0]["source_handle"] = handle
    payload["attacker_bdi"]["intentions"][0]["source_handles"] = [handle]
    world.route_payload = payload
    return True, ""


def _h_render_prompt(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Render the exact contextual prompt used at the provider boundary."""
    del text, examples
    loader = TemplateLoader(PROMPTS_DIR)
    world.route_prompts = build_context_bdi_prompts(world.route_context, loader)
    return True, ""


def _h_semantic_proposition(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    rendered = "\n".join(world.route_prompts)
    required = (
        "semantic proposition",
        "Do not use `semantic_value`",
        "whole-response string placeholder",
        "semantic_proposition",
    )
    missing = [item for item in required if item not in rendered]
    return (not missing, f"prompt is missing: {missing}")


def _h_route_table(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    rendered = "\n".join(world.route_prompts)
    required = (
        "direct_prompt",
        "PROCESS_MODEL_FLAW",
        "FEEDBACK_DELAY",
        "SENSOR_ANOMALY",
    )
    missing = [item for item in required if item not in rendered]
    return (not missing, f"prompt is missing route guidance: {missing}")


def _h_materialize(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Run corrected Stage 5 against the request-local fixture."""
    client = MockLLMClient()
    if getattr(world, "omit_route", False):
        payload = _route_payload({})
        payload.pop("execution_route")
        client.set_response_queue([payload, payload])
    else:
        client.set_response_queue([world.route_payload, world.route_payload])
    world.route_result, world.route_error = generate_bdi_for_context(
        client,
        world.route_context,
        Path(tempfile.mkdtemp()),
    )
    return True, ""


def _h_contract(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the deterministic contract disposition."""
    match = re.search(r'^the materialized execution contract is "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse contract disposition: {text}"
    contract = getattr(world.route_result, "execution_contract", None)
    actual = contract.disposition.value if contract is not None else "failure"
    return (actual == match.group(1), f"expected {match.group(1)}, got {actual}")


def _h_route_fields(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the fields selected by the provider survive deterministic mapping."""
    match = re.search(
        r'^the contract uses delivery "([^"]+)" and action "([^"]+)"$', text
    )
    if match is None:
        return False, f"Could not parse contract fields: {text}"
    contract = getattr(world.route_result, "execution_contract", None)
    if contract is None or contract.delivery is None:
        return False, "contract has no executable delivery"
    actual = (contract.delivery.delivery_class.value, contract.action_kind.value)
    expected = match.groups()
    return (actual == expected, f"expected {expected}, got {actual}")


def _h_requirements(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check domain-resource requirements without counting runtime concerns."""
    match = re.search(r'^the contract has domain requirements "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse requirement expectation: {text}"
    contract = getattr(world.route_result, "execution_contract", None)
    if contract is None:
        return False, "contract is missing"
    actual = ",".join(item.purpose.value for item in contract.resource_requirements)
    expected = "" if match.group(1) == "none" else match.group(1)
    return (actual == expected, f"expected {expected!r}, got {actual!r}")


def _h_missing_route(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Mark a response with no route for the materialization step."""
    world.omit_route = True
    return True, ""


def _h_failure(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check malformed route output fails closed rather than defaulting."""
    error = getattr(world, "route_error", "") or ""
    return (
        getattr(world, "route_result", None) is None and "execution_route" in error,
        f"expected route failure, got {error!r}",
    )


def _h_fidelity_failure(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    error = getattr(world, "route_error", "") or ""
    return (
        getattr(world, "route_result", None) is None
        and "cannot exercise selected factor kind" in error,
        f"expected delivery/factor failure, got {error!r}",
    )


def register(api: object) -> None:
    """Register route-selection acceptance steps."""
    api.register(r"^a corrected Stage 5 route context is available$", _h_context)
    api.register(
        r'^the provider describes stimulus "[^"]+" and selects "[^"]+" with action "[^"]+"$',
        _h_route,
    )
    api.register(
        r"^the provider selects an explicit analytical-only route$", _h_analytical
    )
    api.register(
        r'^the provider selects direct prompt for feedback factor "[^"]+"$',
        _h_direct_feedback,
    )
    api.register(r"^corrected Stage 5 materializes the route$", _h_materialize)
    api.register(
        r'^the materialized execution contract is "[^"]+"$',
        _h_contract,
    )
    api.register(
        r'^the contract uses delivery "[^"]+" and action "[^"]+"$',
        _h_route_fields,
    )
    api.register(r'^the contract has domain requirements "[^"]+"$', _h_requirements)
    api.register(r"^the provider response omits execution_route$", _h_missing_route)
    api.register(
        r"^the materialization fails with an execution route error$", _h_failure
    )
    api.register(
        r"^materialization says the delivery cannot exercise the selected factor$",
        _h_fidelity_failure,
    )
    api.register(r"^the corrected Stage 5 route prompt is rendered$", _h_render_prompt)
    api.register(
        r"^it requires a literal semantic proposition for model output$",
        _h_semantic_proposition,
    )
    api.register(
        r"^it explains the delivery and causal-factor compatibility table$",
        _h_route_table,
    )


__all__ = ["FEATURE_ID", "register"]

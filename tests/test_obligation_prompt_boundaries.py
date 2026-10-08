"""Obligation-aware prompts keep a mechanism separate from adjacent controls.

Routing may not treat a nearby safeguard as mechanism evidence, and the ICA
prompt leaves the UCA type to the compiler and keeps the finding
mechanism-neutral.
"""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.obligation_aware import prompts as prompt_module

_LOADER = TemplateLoader(Path(prompt_module.__file__).with_name("prompt_templates"))


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_routing_prompt_separates_authentication_from_the_mechanism() -> None:
    prompt = _flat(
        _LOADER.render_prompt(
            "structural_routing_system.j2",
            obligation_count=1,
            instructions="Return one result.",
            routing_targeted_example="{}",
            routing_unresolved_example="{}",
        )
    )

    assert "authentication rejection is not poisoned tool output" in prompt
    assert "neither establishes semantic separation" in prompt


def test_ica_prompt_leaves_the_type_to_the_slot_and_the_mechanism_out() -> None:
    prompt = _flat(
        _LOADER.render_prompt(
            "synthesis_ica_system.j2",
            requested_slot_count=1,
            requested_consideration_count=1,
            instructions="Return one result.",
        )
    )

    for phrase in (
        "compiler owns the slot's exact UCA type",
        "must describe the unsafe control or system condition in mechanism-neutral",
        "a detector's score threshold is not tool-call parameter pollution",
    ):
        assert phrase in prompt

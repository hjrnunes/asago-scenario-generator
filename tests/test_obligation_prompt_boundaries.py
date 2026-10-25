"""Obligation-aware prompts keep a mechanism separate from adjacent controls.

Routing may not treat a nearby safeguard as mechanism evidence, the ICA
prompt leaves the UCA type to the compiler and keeps the finding
mechanism-neutral, and an obligation question presents the known concern as a
hypothesis rather than an attack plan.
"""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.obligation_aware import prompts as prompt_module
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_routing_prompts,
    project_obligation_question,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_aware import _control_structure, _loss_analysis
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.known_mechanism import linked_brief

_LOADER = TemplateLoader(Path(prompt_module.__file__).with_name("prompt_templates"))


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_routing_prompt_separates_authentication_from_the_mechanism() -> None:
    """The retrieved-instructions entry carries the rule to a linked concern."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    structure = _control_structure()
    system, user = build_structural_routing_prompts(
        briefs=(linked_brief(brief, "AP-T6-03"),),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        slots=create_slots(structure),
    )
    prompt = _flat(user)

    assert (
        "Authentication, or an authentication rejection: it establishes who "
        "supplied the data, not that data stays separate from instructions."
    ) in prompt
    assert "A description that matches only a counterexample" in _flat(system)


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


def test_obligation_question_treats_the_concern_as_a_hypothesis() -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]

    instruction = project_obligation_question(brief).analyst_instruction

    assert "Treat the known concern as a hypothesis" in instruction
    assert "do not prescribe an attack sequence or coverage" in instruction

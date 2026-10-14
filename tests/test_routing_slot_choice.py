"""How the structural-routing request presents slot types to the model.

The routing prompt must not cue one UCA type: its examples name no type the
model could copy as a default, and the type definitions and the selection rule
are the only place a type is named.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_routing_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_aware import _control_structure, _loss_analysis
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.test_obligation_prompt_goldens import CASES

_TYPE_SECTION = re.compile(
    r"Each slot has one UCA type:.*?The examples' types are not a default\.",
    re.DOTALL,
)


def _routing_prompts(structure=None) -> tuple[str, str]:
    structure = structure or _control_structure()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return build_structural_routing_prompts(
        briefs=build_neutral_briefs(make_plan(), (pattern,))[:1],
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        slots=create_slots(structure),
    )


def _outside_type_section(text: str) -> str:
    return _TYPE_SECTION.sub("", " ".join(text.split()))


def test_routing_system_prompt_names_no_not_provided_outside_the_type_section() -> None:
    system, _ = _routing_prompts()

    assert "NOT_PROVIDED" not in _outside_type_section(system)


def test_routing_targeted_example_names_an_incorrect_slot() -> None:
    system, _ = _routing_prompts()

    assert '"slot_ids":["RESP-1:CA-1-1:INCORRECT"]' in system


def test_coordination_sentence_names_no_uca_type() -> None:
    system, _ = _routing_prompts()

    assert "For a coordination slot such as `CL-1:CM-1:<UCA type>`" in " ".join(
        system.split()
    )


_GOLDENS = Path(__file__).parent / "golden" / "obligation_prompts"


def _ica_type_definitions() -> str:
    """Return the four type lines of the ICA prompt, as its golden pins them."""
    ica_system = (_GOLDENS / "slots-pattern.system.txt").read_text(encoding="utf-8")
    start = ica_system.index("- NOT_PROVIDED:")
    end = ica_system.index("\n", ica_system.index("- WRONG_DURATION:"))
    return ica_system[start:end]


def test_routing_system_prompt_defines_the_four_uca_types_as_the_ica_prompt_does() -> (
    None
):
    system, _ = _routing_prompts()
    definitions = _ica_type_definitions()

    assert definitions.count("\n- ") == 3
    assert definitions in system


@pytest.mark.parametrize("case", sorted(c for c in CASES if c.startswith("slots-")))
def test_ica_slot_prompts_keep_their_golden_bytes(case: str) -> None:
    for part, text in CASES[case]().items():
        golden = _GOLDENS / f"{case}.{part}.txt"
        assert text.encode("utf-8") == golden.read_bytes()

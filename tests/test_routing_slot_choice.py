"""How the structural-routing request presents slot types to the model.

The routing prompt must not cue one UCA type: its examples name no type the
model could copy as a default, and the type definitions and the selection rule
are the only place a type is named.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import ObligationRoute
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionTemporality,
    ControlStructure,
    ElementRef,
    ReferenceType,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    StructuralRoutingResponse,
)
from asago_scenario_generator.stpa.obligation_aware.governance_prompts import (
    build_governance_routing_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_routing_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.governance import _setup as governance_setup
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
    route_assessment,
)
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


def _target_index(user: str) -> dict:
    # The index YAML is key-sorted, so it starts at its ``constraints`` key.
    start = user.index("\nconstraints:", user.index("Compact STPA target index:")) + 1
    end = user.index("Return typed route dispositions")
    return yaml.safe_load(user[start:end])


def _definition_rows() -> list[dict[str, str]]:
    rows = []
    for line in _ica_type_definitions().splitlines():
        uca_type, meaning = line.removeprefix("- ").split(": ", 1)
        rows.append({"uca_type": uca_type, "meaning": meaning})
    return rows


def test_routing_glossary_lists_no_slot_id() -> None:
    _, user = _routing_prompts()
    index = _target_index(user)

    slot_ids = {row["id"] for row in index["slots"]}
    assert slot_ids
    assert not slot_ids & {entry["id"] for entry in index["id_glossary"]}


def test_routing_index_defines_each_uca_type_once_in_a_legend() -> None:
    _, user = _routing_prompts()

    assert _target_index(user)["uca_types"] == _definition_rows()


def test_governance_routing_index_keeps_its_slot_glossary_entries() -> None:
    briefs, _, losses, structure = governance_setup("risk-b")
    _, user = build_governance_routing_prompts(
        briefs=briefs,
        loss_analysis=losses,
        control_structure=structure,
        slots=create_slots(structure),
    )

    glossary_ids = {
        line.split("id: ", 1)[1] for line in user.splitlines() if "- id: " in line
    }
    assert {slot.slot_id for slot in create_slots(structure)} <= glossary_ids
    assert "uca_types" not in user


def _temporal_structure() -> ControlStructure:
    """One owner whose four actions carry each kind of temporality."""
    base = _control_structure()
    owner = base.responsibilities[0]
    temporalities = (
        ControlActionTemporality.instantaneous,
        ControlActionTemporality.discrete,
        None,
        ControlActionTemporality.continuous,
    )
    actions = tuple(
        ControlAction(
            ca_id=f"CA-1-{number}",
            description=f"Action {number}.",
            target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            temporality=temporality,
        )
        for number, temporality in enumerate(temporalities, start=1)
    )
    return base.model_copy(
        update={
            "responsibilities": [
                owner.model_copy(update={"control_actions": list(actions)})
            ]
        }
    )


def test_routing_index_offers_wrong_duration_only_for_a_continuous_action() -> None:
    _, user = _routing_prompts(_temporal_structure())

    offered = {row["id"] for row in _target_index(user)["slots"]}
    assert {item for item in offered if item.endswith(":WRONG_DURATION")} == {
        "RESP-1:CA-1-4:WRONG_DURATION"
    }
    assert {f"RESP-1:CA-1-{n}:INCORRECT" for n in range(1, 5)} <= offered


def _targeted(brief, slot_id: str) -> ObligationRoute:
    return ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        semantic_assessment=route_assessment(brief),
        slot_ids=(slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("provider-route",),
    )


def _route_twice(first_slot: str, structure: ControlStructure) -> list[str | None]:
    """Route one brief: name ``first_slot``, then a valid slot on the retry."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    feedbacks: list[str | None] = []

    class Adapter:
        def route(self, request, *, correction_feedback=None):
            feedbacks.append(correction_feedback)
            slot_id = first_slot if correction_feedback is None else _VALID_SLOT
            return StructuralRoutingResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                routes=(_targeted(brief, slot_id),),
            )

    result = route_obligations(
        Adapter(),
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        slots=create_slots(structure),
        controls=_controls(),
    )
    assert result.routes[0].slot_ids == (_VALID_SLOT,)
    return feedbacks


_VALID_SLOT = "RESP-1:CA-1-1:INCORRECT"


def test_a_route_naming_an_unanalysed_wrong_duration_slot_names_an_unknown_slot() -> (
    None
):
    feedbacks = _route_twice("RESP-1:CA-1-1:WRONG_DURATION", _control_structure())

    assert feedbacks[0] is None
    assert "unknown slot IDs: RESP-1:CA-1-1:WRONG_DURATION" in feedbacks[1]


def _untargeted_structure() -> ControlStructure:
    """CA-1-1 reaches CP-1; CA-1-2 targets a responsibility, CA-1-3 nothing."""
    base = _control_structure()
    owner = base.responsibilities[0]
    actions = (
        owner.control_actions[0],
        ControlAction(
            ca_id="CA-1-2",
            description="Notify the reviewer.",
            target=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
        ),
        ControlAction(ca_id="CA-1-3", description="Log the request."),
    )
    return base.model_copy(
        update={
            "responsibilities": [
                owner.model_copy(update={"control_actions": list(actions)})
            ]
        }
    )


def test_routing_index_leaves_out_slots_of_actions_without_a_controlled_process() -> (
    None
):
    _, user = _routing_prompts(_untargeted_structure())

    actions = {row["control_action_id"] for row in _target_index(user)["slots"]}
    assert actions == {"CA-1-1"}


def test_a_route_naming_a_slot_without_a_controlled_process_names_an_unknown_slot() -> (
    None
):
    feedbacks = _route_twice("RESP-1:CA-1-2:INCORRECT", _untargeted_structure())

    assert "unknown slot IDs: RESP-1:CA-1-2:INCORRECT" in feedbacks[1]

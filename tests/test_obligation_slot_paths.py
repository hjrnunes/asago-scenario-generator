"""Pin how each obligation-aware module resolves a slot to its control path.

Five modules read a slot's owner, action, process, or coordination link.  Each
keeps its own failure policy, so these tables fix both the resolved identities
and the exact exception type and text per module.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    ReferenceType,
)
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    _request_control_context,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    _context_references,
    _project_slot_context,
)
from asago_scenario_generator.stpa.obligation_aware.provider import _slot_path_ids
from asago_scenario_generator.stpa.obligation_aware.routing import (
    _infer_targeted_path,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    _slot_authority,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    build_stpa_index,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.threat_enum.slot_creation import SlotPlaceholder
from tests.helpers.obligation_aware import _control_structure, _loss_analysis


def _structure() -> ControlStructure:
    """One responsibility pair joined by one coordination link."""
    base = _control_structure()
    owner = base.responsibilities[0]
    reviewer = owner.model_copy(
        update={"resp_id": "RESP-2", "description": "Reviewer."}
    )
    link = CoordinationLink(
        link_id="CL-1",
        source="RESP-1",
        target="RESP-2",
        shared_pm="PM-1-1",
        coordination_mechanism=CoordinationMechanism(
            cm_id="CM-1", description="Shared signal.", payload="outcome"
        ),
        description="Coordinate review.",
    )
    return base.model_copy(
        update={"responsibilities": [owner, reviewer], "coordination_links": [link]}
    )


def _slot(**fields) -> SimpleNamespace:
    """A slot-shaped value; the resolvers read only these attributes."""
    values = {
        "slot_id": "SLOT-X",
        "responsibility": None,
        "coordination_link": None,
        "control_action": "CA-1-1",
        "action_temporality": None,
    }
    return SimpleNamespace(**{**values, **fields})


OWNED = {"responsibility": "RESP-1", "control_action": "CA-1-1"}
COORDINATION = {"coordination_link": "CL-1", "control_action": "CM-1"}
UNKNOWN_OWNER = {"responsibility": "RESP-9", "control_action": "CA-1-1"}
NOT_OWNED = {"responsibility": "RESP-1", "control_action": "CA-9-9"}
UNKNOWN_LINK = {"coordination_link": "CL-9", "control_action": "CM-9"}
MISMATCH = {"coordination_link": "CL-1", "control_action": "CM-9"}
NO_PATH = {"control_action": "CA-1-1"}


def _retargeted_structure() -> ControlStructure:
    structure = _structure()
    owner = structure.responsibilities[0]
    action = owner.control_actions[0].model_copy(
        update={"target": ElementRef(type=ReferenceType.responsibility, id="RESP-1")}
    )
    owner = owner.model_copy(update={"control_actions": [action]})
    return structure.model_copy(
        update={"responsibilities": [owner, structure.responsibilities[1]]}
    )


def _unknown_process_structure() -> ControlStructure:
    structure = _structure()
    owner = structure.responsibilities[0]
    action = owner.control_actions[0].model_copy(
        update={"target": ElementRef(type=ReferenceType.controlled_process, id="CP-9")}
    )
    owner = owner.model_copy(update={"control_actions": [action]})
    return structure.model_copy(
        update={"responsibilities": [owner, structure.responsibilities[1]]}
    )


def _outcome(call):
    try:
        return call()
    except Exception as exc:  # noqa: BLE001 - the table pins every type
        return type(exc), str(exc)


def _route(slot) -> SimpleNamespace:
    return SimpleNamespace(slot_ids=(slot.slot_id,))


ROUTING_CASES = [
    (
        OWNED,
        None,
        (
            {"RESP-1"},
            {"RESP-1"},
            {"CA-1-1"},
            {"CP-1"},
            set(),
            {"PM-1-1"},
            {"FB-1-1"},
        ),
    ),
    (
        COORDINATION,
        None,
        (
            {"RESP-1"},
            {"RESP-1", "RESP-2"},
            {"CM-1"},
            set(),
            {"CL-1"},
            {"PM-1-1"},
            set(),
        ),
    ),
    (
        UNKNOWN_OWNER,
        None,
        (ValueError, "slot SLOT-X has unknown owning responsibility RESP-9"),
    ),
    (
        NOT_OWNED,
        None,
        (
            ValueError,
            "slot SLOT-X action CA-9-9 is not owned by responsibility RESP-1",
        ),
    ),
    (
        OWNED,
        _retargeted_structure,
        (
            ValueError,
            "action CA-1-1 has no controlled-process target for the selected route",
        ),
    ),
    (
        OWNED,
        _unknown_process_structure,
        (ValueError, "action CA-1-1 targets unknown controlled process CP-9"),
    ),
    (
        UNKNOWN_LINK,
        None,
        (ValueError, "slot SLOT-X has unknown coordination link CL-9"),
    ),
    (
        MISMATCH,
        None,
        (
            ValueError,
            "slot SLOT-X action CM-9 is not the coordination mechanism for its link",
        ),
    ),
    (NO_PATH, None, (ValueError, "slot SLOT-X has no owner or coordination path")),
]


@pytest.mark.parametrize(("fields", "structure", "expected"), ROUTING_CASES)
def test_routing_proves_the_path_of_a_selected_slot(fields, structure, expected):
    slot = _slot(**fields)
    structure = structure() if structure else _structure()

    got = _outcome(lambda: _infer_targeted_path(_route(slot), structure, (slot,)))

    assert got == expected


PROVIDER_CASES = [
    (OWNED, ("CA-1-1", "RESP-1", "PM-1-1", "FB-1-1", "CP-1")),
    (COORDINATION, ("CM-1", "CL-1", "RESP-1", "RESP-2", "PM-1-1")),
    (MISMATCH, ("CM-1", "CL-1", "RESP-1", "RESP-2", "PM-1-1")),
    (NO_PATH, ()),
    (UNKNOWN_OWNER, (KeyError, "'RESP-9'")),
    (NOT_OWNED, (RuntimeError, "generator raised StopIteration")),
    (UNKNOWN_LINK, (KeyError, "'CL-9'")),
]


@pytest.mark.parametrize(("fields", "expected"), PROVIDER_CASES)
def test_provider_lists_the_verifier_context_of_a_slot_in_order(fields, expected):
    slot = _slot(**fields)
    request = SimpleNamespace(control_structure=_structure(), slots=(slot,))

    got = _outcome(lambda: _slot_path_ids(request, _route(slot)))

    assert got == expected


SLOT_FILLING_CASES = [
    (
        OWNED,
        (
            "Validate incoming requests.",
            "Validate request.",
            "CP-1",
            {"PM-1-1"},
            {"FB-1-1"},
        ),
    ),
    (
        COORDINATION,
        (
            "Validate incoming requests. (coordinating with RESP-2)",
            "Shared signal.",
            None,
            {"PM-1-1"},
            set(),
        ),
    ),
    (UNKNOWN_OWNER, (ValueError, "slot SLOT-X has unknown responsibility")),
    (
        NOT_OWNED,
        (ValueError, "slot SLOT-X action is not owned by its responsibility"),
    ),
    (UNKNOWN_LINK, (ValueError, "slot SLOT-X has unknown coordination link")),
    (
        MISMATCH,
        (ValueError, "slot SLOT-X action does not match coordination mechanism"),
    ),
    (NO_PATH, (ValueError, "slot SLOT-X has no authoritative owner")),
]


@pytest.mark.parametrize(("fields", "expected"), SLOT_FILLING_CASES)
def test_slot_filling_reads_the_authority_of_a_slot(fields, expected):
    slot = _slot(**fields)

    got = _outcome(lambda: _slot_authority(slot, _structure()))

    assert got == expected


def test_slot_filling_leaves_a_missing_link_source_to_the_caller() -> None:
    structure = _structure()
    link = structure.coordination_links[0].model_copy(update={"source": "RESP-9"})
    structure = structure.model_copy(update={"coordination_links": [link]})

    got = _outcome(lambda: _slot_authority(_slot(**COORDINATION), structure))

    assert got == (StopIteration, "")


PROMPT_CASES = [
    (OWNED, "CP-1"),
    (COORDINATION, None),
    (UNKNOWN_OWNER, None),
    (NOT_OWNED, None),
    (NO_PATH, None),
]


@pytest.mark.parametrize(("fields", "target"), PROMPT_CASES)
def test_prompt_slot_view_names_the_process_of_an_owned_action(fields, target):
    structure = _structure()
    slot = SlotPlaceholder(slot_id="SLOT-X", uca_type=UCAType.not_provided, **fields)
    refs = _context_references(structure, _loss_analysis())

    (view,) = _project_slot_context(
        (slot,), tuple(structure.responsibilities), refs, structure
    )

    assert (view.target_process.id if view.target_process else None) == target


ICA_CASES = [
    (OWNED, ("RESP-1", "Validate request.")),
    (COORDINATION, ("RESP-1", "Shared signal.")),
    (MISMATCH, ("RESP-1", "Shared signal.")),
    (UNKNOWN_OWNER, (ValueError, "unknown responsibility RESP-9")),
    (NOT_OWNED, (ValueError, "unknown control action CA-9-9")),
    (UNKNOWN_LINK, (ValueError, "unknown coordination link CL-9")),
]


@pytest.mark.parametrize(("fields", "expected"), ICA_CASES)
def test_ica_verification_resolves_the_control_context_of_a_slot(fields, expected):
    slot = _slot(**fields)
    index = build_stpa_index(_structure())

    def resolve():
        responsibility, description, *_ = _request_control_context(slot, index)
        return responsibility.resp_id, description

    assert _outcome(resolve) == expected


def test_ica_verification_leaves_a_missing_link_source_to_the_caller() -> None:
    structure = _structure()
    link = structure.coordination_links[0].model_copy(update={"source": "RESP-9"})
    index = build_stpa_index(
        structure.model_copy(update={"coordination_links": [link]})
    )

    got = _outcome(lambda: _request_control_context(_slot(**COORDINATION), index))

    assert got == (ValueError, "unknown coordination source RESP-9")

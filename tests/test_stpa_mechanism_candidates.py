"""The join from untrusted feedback to the actions and links it reaches."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    UNTRUSTED_FEEDBACK_SOURCES,
    ControlAction,
    ControlledProcess,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    CROSS_CONTROLLER_MECHANISM,
    SOURCE_MECHANISMS,
    MechanismCandidate,
    mechanism_candidates,
)

_CP = {"type": "controlled_process", "id": "CP-1"}


def _channel(fb_id: str, updates: str, source_kind: str | None) -> FeedbackChannel:
    return FeedbackChannel(
        fb_id=fb_id,
        description=f"Signal {fb_id}",
        updates=updates,
        source=_CP,
        source_kind=source_kind,
    )


def _structure() -> ControlStructure:
    """Two controllers; the first reads retrieved, user and session input."""
    first = Responsibility(
        resp_id="RESP-1",
        description="Answer and act",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-1-1", description="Policy belief"),
            ProcessModelPart(pm_id="PM-1-2", description="Claimed identity"),
            ProcessModelPart(pm_id="PM-1-3", description="Session identity"),
            ProcessModelPart(pm_id="PM-1-4", description="Unused belief"),
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-1-1",
                description="Reply",
                target=_CP,
                effect_kind="model_output",
                process_model_refs=["PM-1-1", "PM-1-2"],
            ),
            ControlAction(
                ca_id="CA-1-2",
                description="Refund",
                target=_CP,
                effect_kind="tool_call",
                operation="process_refund",
                process_model_refs=["PM-1-2", "PM-1-3"],
            ),
            ControlAction(
                ca_id="CA-1-3",
                description="Hand off",
                target={"type": "responsibility", "id": "RESP-2"},
                process_model_refs=["PM-1-1"],
            ),
        ],
        feedback_channels=[
            _channel("FB-1-1", "PM-1-1", "retrieved_content"),
            _channel("FB-1-2", "PM-1-2", "user_message"),
            _channel("FB-1-3", "PM-1-3", "session_context"),
            _channel("FB-1-4", "PM-1-4", "conversation_history"),
        ],
    )
    second = Responsibility(
        resp_id="RESP-2",
        description="Review handoffs",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-2-1", description="Earlier turns"),
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-2-1",
                description="Approve",
                target=_CP,
                effect_kind="state_change",
                process_model_refs=["PM-2-1"],
            ),
        ],
        feedback_channels=[
            _channel("FB-2-1", "PM-2-1", "conversation_history"),
            _channel("FB-2-2", "PM-2-1", None),
        ],
    )
    return ControlStructure(
        responsibilities=[first, second],
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Store")],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1", description="Share policy", payload="policy"
                ),
                description="Controller 1 shares its policy belief.",
            )
        ],
    )


def _pairs(structure: ControlStructure) -> list[tuple[str, tuple[str, ...]]]:
    return [(item.mechanism, item.path) for item in mechanism_candidates(structure)]


def test_every_untrusted_source_kind_names_a_mechanism() -> None:
    assert set(SOURCE_MECHANISMS) == set(UNTRUSTED_FEEDBACK_SOURCES)
    assert CROSS_CONTROLLER_MECHANISM not in SOURCE_MECHANISMS.values()


def test_join_walks_feedback_to_variable_to_actions_and_links_in_order() -> None:
    assert _pairs(_structure()) == [
        ("retrieved_instructions", ("FB-1-1", "PM-1-1", "CA-1-1")),
        ("retrieved_instructions", ("FB-1-1", "PM-1-1", "CA-1-3")),
        ("delegated_authority", ("FB-1-1", "PM-1-1", "CA-1-3")),
        ("retrieved_instructions", ("FB-1-1", "PM-1-1", "CL-1")),
        ("delegated_authority", ("FB-1-1", "PM-1-1", "CL-1")),
        ("user_claim", ("FB-1-2", "PM-1-2", "CA-1-1")),
        ("user_claim", ("FB-1-2", "PM-1-2", "CA-1-2")),
        ("stale_history", ("FB-2-1", "PM-2-1", "CA-2-1")),
    ]


def test_trusted_and_unclassified_feedback_starts_no_path() -> None:
    sources = {item.path[0] for item in mechanism_candidates(_structure())}

    # FB-1-3 is session context; FB-2-2 records no source kind.
    assert sources.isdisjoint({"FB-1-3", "FB-2-2"})


def test_variable_no_action_references_yields_no_candidate() -> None:
    # FB-1-4 is untrusted, but no action lists PM-1-4 and no link shares it.
    paths = [item.path for item in mechanism_candidates(_structure())]

    assert all(path[0] != "FB-1-4" for path in paths)
    assert all(path[1] != "PM-1-4" for path in paths)


def test_link_extends_only_from_its_shared_variable() -> None:
    structure = _structure()
    structure.coordination_links[0].shared_pm = "PM-1-3"

    link_paths = [
        item.path for item in mechanism_candidates(structure) if item.path[2] == "CL-1"
    ]

    # PM-1-3 is fed only by session context, so the link joins no path.
    assert link_paths == []


def _link_pairs(structure: ControlStructure) -> list[tuple[str, tuple[str, ...]]]:
    return [pair for pair in _pairs(structure) if pair[1][2] == "CL-1"]


_LINK_PAIRS = [
    ("retrieved_instructions", ("FB-1-1", "PM-1-1", "CL-1")),
    ("delegated_authority", ("FB-1-1", "PM-1-1", "CL-1")),
]


def test_link_joins_when_shared_variable_owner_is_its_source() -> None:
    structure = _structure()
    link = structure.coordination_links[0]

    assert (link.source, link.target) == ("RESP-1", "RESP-2")
    assert _link_pairs(structure) == _LINK_PAIRS


def test_link_issued_to_the_variable_owner_joins_no_path() -> None:
    structure = _structure()
    link = structure.coordination_links[0]
    # RESP-1 owns PM-1-1 and receives the link, so the link carries its
    # belief to no other controller.
    link.source, link.target = "RESP-2", "RESP-1"

    assert _link_pairs(structure) == []
    assert _pairs(structure) == [
        pair for pair in _pairs(_structure()) if pair[1][2] != "CL-1"
    ]


def test_link_from_a_controller_to_itself_joins_no_path() -> None:
    structure = _structure()
    structure.coordination_links[0].target = "RESP-1"

    assert _link_pairs(structure) == []


def test_link_between_other_controllers_joins_no_path() -> None:
    base = _structure()
    link = base.coordination_links[0].model_copy(
        update={"source": "RESP-2", "target": "RESP-3"}
    )
    third = Responsibility(resp_id="RESP-3", description="Audit")
    # The model accepts a shared variable owned by neither endpoint.
    structure = ControlStructure(
        responsibilities=[*base.responsibilities, third],
        controlled_processes=base.controlled_processes,
        coordination_links=[link],
    )

    assert _link_pairs(structure) == []
    assert _pairs(structure) == [pair for pair in _pairs(base) if pair[1][2] != "CL-1"]


def test_link_whose_variable_both_endpoints_own_joins_no_path() -> None:
    structure = _structure()
    # Validation rejects a repeated pm_id, so add the second owner afterwards.
    structure.responsibilities[1].process_model_parts.append(
        ProcessModelPart(pm_id="PM-1-1", description="Policy belief")
    )

    assert _link_pairs(structure) == []


def test_repeated_records_yield_each_candidate_once() -> None:
    structure = _structure()
    first = structure.responsibilities[0]
    first.feedback_channels.append(first.feedback_channels[0])
    first.control_actions[0].process_model_refs.append("PM-1-1")
    structure.coordination_links.append(structure.coordination_links[0])

    candidates = mechanism_candidates(structure)

    assert len(candidates) == len(set(candidates)) == len(_pairs(_structure()))
    assert candidates == mechanism_candidates(_structure())


def test_candidates_are_frozen_values() -> None:
    candidate = MechanismCandidate("user_claim", ("FB-1-2", "PM-1-2", "CA-1-1"))

    assert candidate == mechanism_candidates(_structure())[5]
    assert hash(candidate) == hash(mechanism_candidates(_structure())[5])

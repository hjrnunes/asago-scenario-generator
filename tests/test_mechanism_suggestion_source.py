"""The graph join proposes mechanism suggestions for the slots its paths reach."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.stpa.mechanism_library import MechanismId
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestions import (
    ProposedSuggestion,
    propose_mechanism_suggestions,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    DropReason,
    MechanismCandidate,
    mechanism_candidates,
)

_CP = {"type": "controlled_process", "id": "CP-1"}
_SELF = {"type": "responsibility", "id": "RESP-1"}
_PATH = ("FB-1-1", "PM-1-1", "CA-1-1")
_LINK_PATH = ("FB-1-1", "PM-1-1", "CL-1")


def _structure(
    *,
    source_kind: str = "user_message",
    source: dict[str, str] = _CP,
    authority: str | None = None,
    temporality: str | None = None,
) -> ControlStructure:
    """One controller whose untrusted channel feeds an action and a link."""
    channel: dict[str, Any] = {
        "fb_id": "FB-1-1",
        "description": "Requested refund amount",
        "updates": "PM-1-1",
        "source": source,
        "source_kind": source_kind,
    }
    if authority is not None:
        channel["authority_for_update"] = {
            "status": authority,
            "basis": f"The use case says the source is {authority}.",
        }
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Handle refunds",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="Refund amount")
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Refund",
                        target=_CP,
                        effect_kind="tool_call",
                        process_model_refs=["PM-1-1"],
                        temporality=temporality,
                    )
                ],
                feedback_channels=[FeedbackChannel.model_validate(channel)],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Approve refunds",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="Approval state")
                ],
            ),
        ],
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Chat")],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1", description="Pass amount", payload="amount"
                ),
                description="Controller 1 passes the refund amount on.",
            )
        ],
    )


def _keys(items: tuple[ProposedSuggestion, ...]) -> list[tuple[str, str]]:
    return [(item.mechanism.value, item.slot_id) for item in items]


def test_each_filtered_path_proposes_its_mechanisms_for_every_slot_it_reaches() -> None:
    proposal = propose_mechanism_suggestions(_structure())

    assert _keys(proposal.proposed) == [
        ("user_claim", "CL-1:CM-1:INCORRECT"),
        ("delegated_authority", "CL-1:CM-1:INCORRECT"),
        ("user_claim", "CL-1:CM-1:NOT_PROVIDED"),
        ("delegated_authority", "CL-1:CM-1:NOT_PROVIDED"),
        ("user_claim", "CL-1:CM-1:WRONG_TIMING"),
        ("delegated_authority", "CL-1:CM-1:WRONG_TIMING"),
        ("user_claim", "RESP-1:CA-1-1:INCORRECT"),
        ("user_claim", "RESP-1:CA-1-1:NOT_PROVIDED"),
        ("user_claim", "RESP-1:CA-1-1:WRONG_TIMING"),
    ]
    assert {item.paths for item in proposal.proposed} == {(_PATH,), (_LINK_PATH,)}
    assert proposal.filtered == {}


def test_the_candidates_to_judge_are_the_filtered_join_without_repeats() -> None:
    structure = _structure()

    candidates = propose_mechanism_suggestions(structure).candidates()

    assert set(candidates) == set(
        mechanism_candidates(structure, authority_filter=True)
    )
    assert candidates == (
        MechanismCandidate(MechanismId.user_claim, _LINK_PATH),
        MechanismCandidate(MechanismId.delegated_authority, _LINK_PATH),
        MechanismCandidate(MechanismId.user_claim, _PATH),
    )


def test_a_slot_decided_by_structure_gets_no_proposal() -> None:
    proposal = propose_mechanism_suggestions(_structure())

    assert _keys(proposal.structural) == [
        ("user_claim", "CL-1:CM-1:WRONG_DURATION"),
        ("delegated_authority", "CL-1:CM-1:WRONG_DURATION"),
        ("user_claim", "RESP-1:CA-1-1:WRONG_DURATION"),
    ]


def test_an_eligible_duration_slot_is_proposed() -> None:
    proposal = propose_mechanism_suggestions(_structure(temporality="continuous"))

    assert ("user_claim", "RESP-1:CA-1-1:WRONG_DURATION") in _keys(proposal.proposed)


def test_an_authoritative_channel_proposes_nothing_and_says_why() -> None:
    proposal = propose_mechanism_suggestions(_structure(authority="authoritative"))

    assert proposal.proposed == ()
    assert proposal.structural == ()
    assert proposal.filtered[(MechanismId.user_claim, "RESP-1:CA-1-1:INCORRECT")] == (
        DropReason.authoritative,
    )
    assert (MechanismId.delegated_authority, "CL-1:CM-1:NOT_PROVIDED") in (
        proposal.filtered
    )


def test_internal_state_labelled_as_retrieved_content_proposes_nothing() -> None:
    proposal = propose_mechanism_suggestions(
        _structure(source_kind="retrieved_content", source=_SELF)
    )

    assert proposal.proposed == ()
    assert set(proposal.filtered.values()) == {(DropReason.own_controller,)}


def test_a_supplied_slot_universe_limits_the_proposal() -> None:
    from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots

    structure = _structure()
    slots = [slot for slot in create_slots(structure) if slot.coordination_link]

    proposal = propose_mechanism_suggestions(structure, slots)

    assert {item.slot_id.split(":")[0] for item in proposal.proposed} == {"CL-1"}

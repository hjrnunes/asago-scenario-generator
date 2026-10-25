"""The authority filter on the join from untrusted feedback to actions and links."""

from __future__ import annotations

from typing import Any

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackAuthorityStatus,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    DropReason,
    MechanismCandidate,
    ReachBasis,
    mechanism_candidates,
    mechanism_join,
)

_CP = {"type": "controlled_process", "id": "CP-1"}
_SELF = {"type": "responsibility", "id": "RESP-1"}
_OTHER = {"type": "responsibility", "id": "RESP-2"}


def _authority(status: str | None) -> dict[str, str] | None:
    if status is None:
        return None
    if status == "unknown":
        return {"status": status}
    return {"status": status, "basis": f"The use case says the source is {status}."}


def _structure(
    *,
    source_kind: str | None = "user_message",
    source: dict[str, str] = _CP,
    authority: str | None = None,
    evidence_refs: list[str] | None = None,
) -> ControlStructure:
    """One controller whose channel FB-1-1 feeds an action and a link."""
    channel: dict[str, Any] = {
        "fb_id": "FB-1-1",
        "description": "Requested refund amount",
        "updates": "PM-1-1",
        "source": source,
        "source_kind": source_kind,
        "authority_for_update": _authority(authority),
    }
    first = Responsibility(
        resp_id="RESP-1",
        description="Handle refunds",
        process_model_parts=[
            ProcessModelPart(
                pm_id="PM-1-1",
                description="Refund amount",
                evidence_refs=evidence_refs or [],
            ),
            ProcessModelPart(pm_id="PM-1-2", description="Session identity"),
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-1-1",
                description="Refund",
                target=_CP,
                effect_kind="tool_call",
                operation="process_refund",
                process_model_refs=["PM-1-1", "PM-1-2"],
            ),
        ],
        feedback_channels=[
            FeedbackChannel.model_validate(channel),
            FeedbackChannel(
                fb_id="FB-1-2",
                description="Session identity",
                updates="PM-1-2",
                source=_CP,
                source_kind="session_context",
            ),
        ],
    )
    second = Responsibility(
        resp_id="RESP-2",
        description="Approve refunds",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-2-1", description="Approval state")
        ],
    )
    return ControlStructure(
        responsibilities=[first, second],
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


_USER_CLAIM_PATHS = [
    MechanismCandidate("user_claim", ("FB-1-1", "PM-1-1", "CA-1-1")),
    MechanismCandidate("user_claim", ("FB-1-1", "PM-1-1", "CL-1")),
    MechanismCandidate("delegated_authority", ("FB-1-1", "PM-1-1", "CL-1")),
]


def test_default_join_ignores_authority_and_source() -> None:
    plain = mechanism_candidates(_structure())

    assert list(plain) == _USER_CLAIM_PATHS
    assert mechanism_candidates(_structure(), authority_filter=False) == plain
    for structure in (
        _structure(authority="authoritative"),
        _structure(source=_SELF),
        _structure(authority="authoritative", source=_SELF),
    ):
        assert mechanism_candidates(structure) == plain
    # A trusted kind starts no unfiltered path, whatever the variable cites.
    trusted = _structure(
        source_kind="operation_result", evidence_refs=["argument:process_refund.a"]
    )
    assert mechanism_candidates(trusted) == ()


def test_authoritative_channel_is_dropped_with_its_reason() -> None:
    structure = _structure(authority="authoritative")

    join = mechanism_join(structure)

    assert join.kept == ()
    assert [item.candidate for item in join.dropped] == _USER_CLAIM_PATHS
    assert {item.reason for item in join.dropped} == {DropReason.authoritative}
    assert mechanism_candidates(structure, authority_filter=True) == ()


@pytest.mark.parametrize(
    ("authority", "status", "recorded", "assessed"),
    [
        ("non_authoritative", FeedbackAuthorityStatus.non_authoritative, True, True),
        ("conditional", FeedbackAuthorityStatus.conditional, True, True),
        ("unknown", FeedbackAuthorityStatus.unknown, True, False),
        (None, FeedbackAuthorityStatus.unknown, False, False),
    ],
)
def test_channel_without_authority_is_kept_and_says_why(
    authority: str | None,
    status: FeedbackAuthorityStatus,
    recorded: bool,
    assessed: bool,
) -> None:
    structure = _structure(authority=authority)

    join = mechanism_join(structure)

    assert [item.candidate for item in join.kept] == _USER_CLAIM_PATHS
    assert join.dropped == ()
    for item in join.kept:
        assert item.authority is status
        assert item.authority_recorded is recorded
        assert item.authority_assessed is assessed
        assert item.reach is ReachBasis.source_kind
    assert list(mechanism_candidates(structure, authority_filter=True)) == (
        _USER_CLAIM_PATHS
    )


_OWN_CHECK_PATHS = {
    "retrieved_content": [
        MechanismCandidate("retrieved_instructions", ("FB-1-1", "PM-1-1", "CA-1-1")),
        MechanismCandidate("retrieved_instructions", ("FB-1-1", "PM-1-1", "CL-1")),
        MechanismCandidate("delegated_authority", ("FB-1-1", "PM-1-1", "CL-1")),
    ],
    "conversation_history": [
        MechanismCandidate("stale_history", ("FB-1-1", "PM-1-1", "CA-1-1")),
        MechanismCandidate("stale_history", ("FB-1-1", "PM-1-1", "CL-1")),
        MechanismCandidate("delegated_authority", ("FB-1-1", "PM-1-1", "CL-1")),
    ],
}


@pytest.mark.parametrize("source_kind", sorted(_OWN_CHECK_PATHS))
def test_external_kind_from_its_own_controller_is_not_reachable(
    source_kind: str,
) -> None:
    structure = _structure(
        source_kind=source_kind, source=_SELF, authority="non_authoritative"
    )

    join = mechanism_join(structure)

    # The unfiltered join follows the external kind; the source says the
    # controller holds the value itself, so the kind labels its own check.
    assert list(mechanism_candidates(structure)) == _OWN_CHECK_PATHS[source_kind]
    assert join.kept == ()
    assert [item.candidate for item in join.dropped] == _OWN_CHECK_PATHS[source_kind]
    assert {item.reason for item in join.dropped} == {DropReason.own_controller}


def test_user_message_from_its_own_controller_stays_reachable() -> None:
    structure = _structure(source=_SELF, authority="non_authoritative")

    join = mechanism_join(structure)

    # The user authored the text even when its own controller relays it.
    assert [item.candidate for item in join.kept] == _USER_CLAIM_PATHS
    assert {item.reach for item in join.kept} == {ReachBasis.source_kind}
    assert join.dropped == ()
    authoritative = mechanism_join(_structure(source=_SELF, authority="authoritative"))
    assert {item.reason for item in authoritative.dropped} == {DropReason.authoritative}


def test_unreachable_reason_comes_before_authority() -> None:
    join = mechanism_join(
        _structure(
            source_kind="retrieved_content", source=_SELF, authority="authoritative"
        )
    )

    assert {item.reason for item in join.dropped} == {DropReason.own_controller}


def test_own_controller_with_a_trusted_kind_is_not_reported() -> None:
    join = mechanism_join(_structure(source_kind="other", source=_SELF))

    assert join.kept == join.dropped == ()


def test_channel_from_another_controller_falls_back_to_source_kind() -> None:
    for source_kind, paths in (
        ("user_message", _USER_CLAIM_PATHS),
        *_OWN_CHECK_PATHS.items(),
    ):
        join = mechanism_join(_structure(source_kind=source_kind, source=_OTHER))

        assert [item.candidate for item in join.kept] == paths
        assert {item.reach for item in join.kept} == {ReachBasis.source_kind}


@pytest.mark.parametrize("source_kind", ["operation_result", "session_context", None])
def test_argument_evidence_on_the_variable_leaves_a_trusted_channel_unreachable(
    source_kind: str | None,
) -> None:
    structure = _structure(
        source_kind=source_kind,
        evidence_refs=["argument:process_refund.amount", "state:orders.balance"],
    )

    join = mechanism_join(structure)

    assert mechanism_candidates(structure) == ()
    assert join.kept == join.dropped == ()


@pytest.mark.parametrize(
    "refs",
    [
        ["argument:process_refund.amount"],
        ["state:orders.amount"],
        ["session:session_id"],
        ["policy:TARGET-READ-001"],
    ],
)
def test_variable_evidence_leaves_trust_to_source_kind(refs: list[str]) -> None:
    untrusted = mechanism_join(_structure(evidence_refs=refs))
    trusted = mechanism_join(
        _structure(source_kind="operation_result", evidence_refs=refs)
    )

    assert [item.candidate for item in untrusted.kept] == _USER_CLAIM_PATHS
    assert trusted.kept == trusted.dropped == ()


def _link_items(items: tuple[Any, ...]) -> list[MechanismCandidate]:
    return [item.candidate for item in items if item.candidate.path[2] == "CL-1"]


def test_link_paths_follow_the_channel_verdict() -> None:
    kept = mechanism_join(_structure(authority="conditional")).kept
    dropped = mechanism_join(_structure(authority="authoritative")).dropped

    assert _link_items(kept) == _USER_CLAIM_PATHS[1:]
    assert {item.authority for item in kept} == {FeedbackAuthorityStatus.conditional}
    assert _link_items(dropped) == _USER_CLAIM_PATHS[1:]


def test_link_issued_to_the_variable_owner_joins_no_path_under_the_filter() -> None:
    structure = _structure(authority="non_authoritative")
    link = structure.coordination_links[0]
    link.source, link.target = "RESP-2", "RESP-1"

    join = mechanism_join(structure)

    assert _link_items(join.kept) == []
    assert [item.candidate for item in join.kept] == _USER_CLAIM_PATHS[:1]
    assert (
        _link_items(
            mechanism_join(
                _structure(source_kind="retrieved_content", source=_SELF)
            ).dropped
        )
        == _OWN_CHECK_PATHS["retrieved_content"][1:]
    )


def test_repeated_records_yield_each_kept_candidate_once() -> None:
    structure = _structure(authority="non_authoritative")
    first = structure.responsibilities[0]
    first.feedback_channels.append(first.feedback_channels[0])
    structure.coordination_links.append(structure.coordination_links[0])

    kept = mechanism_join(structure).kept

    assert [item.candidate for item in kept] == _USER_CLAIM_PATHS

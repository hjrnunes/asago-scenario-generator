"""Signature retrieval: the join matches channels against every library entry."""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from asago_scenario_generator.stpa.mechanism_library import (
    MechanismId,
    bundled_mechanism_library,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    FeedbackAuthorityStatus,
    FeedbackSourceKind,
)
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestions import (
    propose_mechanism_suggestions,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    RETRIEVAL_SOURCE_KINDS,
    DropReason,
    MechanismCandidate,
    mechanism_candidates,
    mechanism_join,
    retrieval_admits,
    signature_fits,
)

_CP = {"type": "controlled_process", "id": "CP-1"}
_SELF = {"type": "responsibility", "id": "RESP-1"}
_KINDS = (
    "user_message",
    "conversation_history",
    "retrieved_content",
    "operation_result",
    "session_context",
    "other",
)
_NEW = {MechanismId.stale_feedback, MechanismId.forged_completion}


def _authority(status: str | None) -> dict[str, str] | None:
    if status is None:
        return None
    if status == "unknown":
        return {"status": status}
    return {"status": status, "basis": f"The use case says it is {status}."}


def _structure(
    kinds: tuple[str, ...] = _KINDS,
    *,
    authority: str | None = None,
    source: dict[str, str] = _CP,
) -> ControlStructure:
    """One channel per kind, each feeding a local action, a message and a link.

    Channel ``FB-1-n`` updates ``PM-1-n``.  ``CA-1-1`` changes state and reads
    every variable; ``CA-1-2`` messages another agent and reads every variable;
    link ``CL-n`` shares ``PM-1-n`` with ``RESP-2``.
    """
    numbers = range(1, len(kinds) + 1)
    variables = [f"PM-1-{n}" for n in numbers]
    first: dict[str, Any] = {
        "resp_id": "RESP-1",
        "description": "Handle refunds",
        "process_model_parts": [
            {"pm_id": pm, "description": f"Belief {pm}"} for pm in variables
        ],
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Refund",
                "target": _CP,
                "effect_kind": "state_change",
                "process_model_refs": variables,
            },
            {
                "ca_id": "CA-1-2",
                "description": "Ask approver",
                "target": {"type": "responsibility", "id": "RESP-2"},
                "effect_kind": "agent_message",
                "process_model_refs": variables,
            },
        ],
        "feedback_channels": [
            {
                "fb_id": f"FB-1-{n}",
                "description": f"Signal {kind}",
                "updates": f"PM-1-{n}",
                "source": source,
                "source_kind": kind,
                "authority_for_update": _authority(authority),
            }
            for n, kind in zip(numbers, kinds, strict=True)
        ],
    }
    second = {
        "resp_id": "RESP-2",
        "description": "Approve refunds",
        "process_model_parts": [{"pm_id": "PM-2-1", "description": "Approval"}],
    }
    return ControlStructure.model_validate(
        {
            "responsibilities": [first, second],
            "controlled_processes": [{"cp_id": "CP-1", "description": "Store"}],
            "coordination_links": [
                {
                    "link_id": f"CL-{n}",
                    "source": "RESP-1",
                    "target": "RESP-2",
                    "shared_pm": f"PM-1-{n}",
                    "coordination_mechanism": {
                        "cm_id": f"CM-{n}",
                        "description": "Pass the belief",
                        "payload": "belief",
                    },
                    "description": "Controller 1 passes a belief on.",
                }
                for n in numbers
            ],
        }
    )


def _by_kind(candidates: tuple[MechanismCandidate, ...]) -> dict[str, list[tuple]]:
    """Map each channel's source kind to its (mechanism, end) pairs, in order."""
    result: dict[str, list[tuple]] = {kind: [] for kind in _KINDS}
    for item in candidates:
        kind = _KINDS[int(item.path[0].rsplit("-", 1)[1]) - 1]
        result[kind].append((item.mechanism.value, item.path[2]))
    return result


_LOCAL, _MESSAGE = "CA-1-1", "CA-1-2"


def _link(kind: str) -> str:
    return f"CL-{_KINDS.index(kind) + 1}"


def test_flag_off_is_the_default_join() -> None:
    structure = _structure()

    assert mechanism_candidates(structure, signature_retrieval=False) == (
        mechanism_candidates(structure)
    )
    assert mechanism_candidates(
        structure, authority_filter=True, signature_retrieval=False
    ) == mechanism_candidates(structure, authority_filter=True)
    assert mechanism_join(structure, signature_retrieval=False) == (
        mechanism_join(structure)
    )


def test_flag_off_proposes_only_the_fixed_source_and_crossing_mechanisms() -> None:
    by_kind = _by_kind(mechanism_candidates(_structure()))

    assert by_kind == {
        "user_message": [
            ("user_claim", _LOCAL),
            ("user_claim", _MESSAGE),
            ("delegated_authority", _MESSAGE),
            ("user_claim", _link("user_message")),
            ("delegated_authority", _link("user_message")),
        ],
        "conversation_history": [
            ("stale_history", _LOCAL),
            ("stale_history", _MESSAGE),
            ("delegated_authority", _MESSAGE),
            ("stale_history", _link("conversation_history")),
            ("delegated_authority", _link("conversation_history")),
        ],
        "retrieved_content": [
            ("retrieved_instructions", _LOCAL),
            ("retrieved_instructions", _MESSAGE),
            ("delegated_authority", _MESSAGE),
            ("retrieved_instructions", _link("retrieved_content")),
            ("delegated_authority", _link("retrieved_content")),
        ],
        "operation_result": [],
        "session_context": [],
        "other": [],
    }


def test_flag_on_matches_every_entry_signature_in_library_order() -> None:
    by_kind = _by_kind(mechanism_candidates(_structure(), signature_retrieval=True))

    assert by_kind == {
        # forged_completion needs an operation's own report.
        "user_message": [
            ("user_claim", _LOCAL),
            ("user_claim", _MESSAGE),
            ("delegated_authority", _MESSAGE),
            ("user_claim", _link("user_message")),
            ("delegated_authority", _link("user_message")),
        ],
        "conversation_history": [
            ("stale_history", _LOCAL),
            ("stale_history", _MESSAGE),
            ("delegated_authority", _MESSAGE),
            ("stale_history", _link("conversation_history")),
            ("delegated_authority", _link("conversation_history")),
        ],
        "retrieved_content": [
            ("retrieved_instructions", _LOCAL),
            ("retrieved_instructions", _MESSAGE),
            ("delegated_authority", _MESSAGE),
            ("retrieved_instructions", _link("retrieved_content")),
            ("delegated_authority", _link("retrieved_content")),
        ],
        # stale_feedback stays within the controller: no message, no link.
        "operation_result": [
            ("stale_feedback", _LOCAL),
            ("forged_completion", _LOCAL),
            ("forged_completion", _MESSAGE),
            ("forged_completion", _link("operation_result")),
        ],
        "session_context": [("stale_feedback", _LOCAL)],
        "other": [
            ("forged_completion", _LOCAL),
            ("forged_completion", _MESSAGE),
            ("forged_completion", _link("other")),
        ],
    }


def test_flag_on_makes_every_library_entry_proposable() -> None:
    off = {item.mechanism for item in mechanism_candidates(_structure())}
    on = {
        item.mechanism
        for item in mechanism_candidates(_structure(), signature_retrieval=True)
    }

    assert on == set(MechanismId)
    assert off == set(MechanismId) - _NEW


def test_flag_on_keeps_every_flag_off_candidate_in_the_same_order() -> None:
    for filtered in (False, True):
        off = mechanism_candidates(_structure(), authority_filter=filtered)
        on = mechanism_candidates(
            _structure(), authority_filter=filtered, signature_retrieval=True
        )

        assert [item for item in on if item in off] == list(off)


def test_authoritative_operation_result_keeps_stale_feedback_only() -> None:
    structure = _structure(("operation_result",), authority="authoritative")

    join = mechanism_join(structure, signature_retrieval=True)

    assert [
        (item.candidate.mechanism.value, item.candidate.path[2]) for item in join.kept
    ] == [("stale_feedback", _LOCAL)]
    assert join.kept[0].authority is FeedbackAuthorityStatus.authoritative
    assert {item.candidate.mechanism for item in join.dropped} == {
        MechanismId.forged_completion
    }
    assert {item.reason for item in join.dropped} == {DropReason.authoritative}


@pytest.mark.parametrize(
    "kind", ["user_message", "conversation_history", "retrieved_content"]
)
def test_existing_mechanisms_keep_their_authority_filter(kind: str) -> None:
    structure = _structure((kind,), authority="authoritative")

    off = mechanism_join(structure)
    on = mechanism_join(structure, signature_retrieval=True)

    assert off.kept == () and on.kept == ()
    assert {item.reason for item in on.dropped} == {DropReason.authoritative}
    assert [item for item in on.dropped if item in off.dropped] == list(off.dropped)


@pytest.mark.parametrize(
    "status", [None, "unknown", "non_authoritative", "conditional"]
)
def test_unassessed_or_lacking_authority_keeps_every_signature_match(
    status: str | None,
) -> None:
    structure = _structure(authority=status)

    join = mechanism_join(structure, signature_retrieval=True)

    assert join.dropped == ()
    assert tuple(item.candidate for item in join.kept) == mechanism_candidates(
        structure, signature_retrieval=True
    )


def test_the_filter_reads_each_mechanism_authority_from_its_library_entry() -> None:
    library = bundled_mechanism_library()
    for status in FeedbackAuthorityStatus:
        join = mechanism_join(
            _structure(authority=status.value), signature_retrieval=True
        )
        for item in join.kept:
            assert status in library.entry(item.candidate.mechanism).signature.authority
        for item in join.dropped:
            assert (
                status
                not in library.entry(item.candidate.mechanism).signature.authority
            )


def test_the_library_excludes_no_status_but_authoritative() -> None:
    # The filter names an authority drop ``authoritative``; a library entry that
    # excluded another status would need its own reason.
    for entry in bundled_mechanism_library().mechanisms:
        excluded = set(FeedbackAuthorityStatus) - set(entry.signature.authority)
        assert excluded <= {FeedbackAuthorityStatus.authoritative}, entry.id


def test_own_controller_channel_drops_every_signature_match() -> None:
    structure = _structure(("retrieved_content",), source=_SELF)

    join = mechanism_join(structure, signature_retrieval=True)

    assert join.kept == ()
    assert {item.candidate.mechanism for item in join.dropped} == {
        MechanismId.retrieved_instructions,
        MechanismId.delegated_authority,
    }
    assert {item.reason for item in join.dropped} == {DropReason.own_controller}


@pytest.mark.parametrize("kind", list(FeedbackSourceKind))
def test_forged_completion_needs_an_operation_report_channel(
    kind: FeedbackSourceKind,
) -> None:
    trusted = kind in {FeedbackSourceKind.operation_result, FeedbackSourceKind.other}

    assert retrieval_admits(MechanismId.forged_completion, kind) is trusted
    assert retrieval_admits(MechanismId.forged_completion, None) is False


@pytest.mark.parametrize("kind", [*FeedbackSourceKind, None])
def test_retrieval_leaves_every_other_mechanism_to_its_signature(
    kind: FeedbackSourceKind | None,
) -> None:
    assert set(RETRIEVAL_SOURCE_KINDS) == {MechanismId.forged_completion}
    for mechanism in set(MechanismId) - {MechanismId.forged_completion}:
        assert retrieval_admits(mechanism, kind)


def test_the_narrowed_kinds_stay_within_their_library_signature() -> None:
    # A kind outside the signature would be one the narrowing never admits.
    library = bundled_mechanism_library()
    for mechanism, kinds in RETRIEVAL_SOURCE_KINDS.items():
        signature = library.entry(mechanism).signature
        assert kinds < set(signature.source_kinds), mechanism
        for kind in set(signature.source_kinds) - kinds:
            assert signature_fits(signature, kind, crosses=False)


@pytest.mark.parametrize("kind", ["user_message", "retrieved_content"])
def test_untrusted_report_channels_lose_only_forged_completion(kind: str) -> None:
    for status in (None, "unknown", "non_authoritative"):
        structure = _structure((kind,), authority=status)
        on = mechanism_join(structure, signature_retrieval=True)
        off = mechanism_join(structure)

        assert MechanismId.forged_completion not in {
            item.candidate.mechanism for item in (*on.kept, *on.dropped)
        }
        assert on == off


@pytest.mark.parametrize("status", [None, "unknown", "authoritative"])
def test_stale_feedback_is_unaffected_by_the_narrowing(status: str | None) -> None:
    candidates = mechanism_candidates(
        _structure(authority=status), signature_retrieval=True
    )
    stale = [
        (kind, end)
        for kind, pairs in _by_kind(candidates).items()
        for mechanism, end in pairs
        if mechanism == "stale_feedback"
    ]

    assert stale == [("operation_result", _LOCAL), ("session_context", _LOCAL)]


def test_live_suggestions_never_turn_signature_retrieval_on() -> None:
    assert (
        "signature_retrieval"
        not in inspect.signature(propose_mechanism_suggestions).parameters
    )
    proposal = propose_mechanism_suggestions(_structure())

    assert not {item.mechanism for item in proposal.proposed} & _NEW
    assert not {item.mechanism for item in proposal.structural} & _NEW

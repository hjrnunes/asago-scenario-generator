"""The revision gives one disposition per critic gap, and code checks the claims.

Code numbers the critic gaps ``G-1`` to ``G-n`` in finding order and shows
each ID next to its gap.  The reply says, per gap, whether it ``addressed``,
``dismissed`` or kept the gap as a ``recommendation``.  An ``addressed`` claim
must name an element the published structure adds or changes; a gap with no
disposition, a disposition for an unknown gap, and an ``addressed`` claim
that changed nothing it names are unresolved.  The check sends no request and
never rejects the reply: it adds post-revision warnings and fields of the
``critic_revision`` record.  A process-model variable the revision added and
no control action reads is reported as well.  A reply in the earlier format,
with free-text ``dismissed_gaps`` and no dispositions, still loads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    RevisionDelta,
    _RevisionDeltaProviderSet,
    revise_control_structure,
)
from asago_scenario_generator.stpa.system_model.revision_dispositions import (
    GapDisposition,
    RevisionIdentity,
    changed_element_ids,
    critic_gap_ids,
    review_gap_dispositions,
    unread_added_process_model_warnings,
)
from asago_scenario_generator.stpa.system_model.run import _critic_revision_record
from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import MockLLMClient

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "stpa"


def _responsibility(number: int, description: str) -> Responsibility:
    return Responsibility(
        resp_id=f"RESP-{number}",
        description=description,
        process_model_parts=[
            ProcessModelPart(pm_id=f"PM-{number}-1", description=f"{description} state")
        ],
        control_actions=[
            ControlAction(
                ca_id=f"CA-{number}-1",
                description=f"Act on {description.lower()}",
                process_model_refs=[f"PM-{number}-1"],
            )
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{number}-1",
                description=f"{description} report",
                updates=f"PM-{number}-1",
                source=ElementRef(
                    type=ReferenceType.responsibility, id=f"RESP-{number}"
                ),
            )
        ],
    )


def _reviewed() -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            _responsibility(1, "Store drafts for review"),
            _responsibility(2, "Track draft ownership"),
            _responsibility(3, "Escalate to a reviewer"),
        ]
    )


def _gap(gap_type: str, description: str) -> CriticGap:
    return CriticGap(
        gap_type=gap_type,
        description=description,
        related_attack_path="A crafted request reaches the action",
        suggested_remedy=f"Add {description.lower()}",
    )


# Four gaps, in the order the critic reported them: G-1 to G-4.
_FINDINGS = CriticFindings(
    gaps=[
        _gap("missing_feedback", "Review outcome feedback"),
        _gap("missing_responsibility", "Argument validation"),
        _gap("missing_feedback", "Ownership feedback authority"),
        _gap("missing_pm_part", "Escalation status variable"),
    ]
)


def _disposition(
    gap_id: str, disposition: str = "addressed", *element_ids: str
) -> dict[str, Any]:
    return {
        "gap_id": gap_id,
        "disposition": disposition,
        "element_ids": list(element_ids),
        "justification": f"Disposition of {gap_id}.",
    }


def _restated_resp_1(*, read_new_variable: bool) -> dict[str, Any]:
    """RESP-1 restated with one added variable and the channel that updates it."""
    resp = _reviewed().responsibilities[0].model_dump(mode="json", exclude_none=True)
    resp["process_model_parts"].append(
        {"pm_id": "PM-1-2", "description": "Stored draft status", "values": []}
    )
    resp["feedback_channels"].append(
        {
            "fb_id": "FB-1-2",
            "description": "Status the draft was stored with",
            "updates": "PM-1-2",
            "source": {"type": "responsibility", "id": "RESP-1"},
        }
    )
    if read_new_variable:
        resp["control_actions"][0]["process_model_refs"].append("PM-1-2")
    return resp


def _new_resp_4() -> dict[str, Any]:
    resp = _responsibility(4, "Validate arguments")
    return resp.model_dump(mode="json", exclude_none=True)


def _reply(
    *dispositions: dict[str, Any], read_new_variable: bool = True, **extra: Any
) -> dict[str, Any]:
    return {
        "new_responsibilities": [_new_resp_4()],
        "new_controlled_processes": [],
        "new_coordination_links": [],
        "modified_responsibilities": [
            _restated_resp_1(read_new_variable=read_new_variable)
        ],
        "gap_dispositions": list(dispositions),
        **extra,
    }


def _revise(
    reply: dict[str, Any],
    tmp_path: Path,
    findings=_FINDINGS,
    reviewed: ControlStructure | None = None,
):
    client = MockLLMClient()
    client.set_response_queue([reply])
    outcome = revise_control_structure(
        llm_client=client,  # type: ignore[arg-type]
        control_structure=reviewed or _reviewed(),
        critic_findings=findings,
        use_case_text="Drafts are stored for later review by a person.",
        run_dir=tmp_path,
    )
    return outcome, client


def _revision_requests(tmp_path: Path) -> list[dict[str, Any]]:
    return [
        entry for entry in read_calls_jsonl(tmp_path) if entry["step"] == "revision"
    ]


# ---------------------------------------------------------------------------
# The reply that claims gaps addressed for responsibilities it does not touch
# ---------------------------------------------------------------------------


def test_claims_for_untouched_responsibilities_are_unresolved(tmp_path) -> None:
    reply = _reply(
        _disposition("G-1", "addressed", "PM-1-2", "FB-1-2"),
        _disposition("G-2", "addressed", "RESP-4"),
        # The reply restates neither RESP-2 nor RESP-3.
        _disposition("G-3", "addressed", "RESP-2", "FB-2-1"),
        _disposition("G-4", "addressed", "RESP-3"),
    )

    outcome, client = _revise(reply, tmp_path)

    # The revision is still applied, and no request beyond the revision is sent.
    assert outcome.applied is True
    assert len(client.calls) == 1
    assert len(_revision_requests(tmp_path)) == 1
    review = outcome.gap_review
    assert review is not None
    assert review.record() == {
        "gap_dispositions": {"addressed": 4, "dismissed": 0, "recommendation": 0},
        "unresolved_gaps": [
            {
                "gap_id": "G-3",
                "reason": "claimed addressed but did not change RESP-2, FB-2-1",
            },
            {"gap_id": "G-4", "reason": "claimed addressed but did not change RESP-3"},
        ],
    }
    assert (
        "Revision left critic gap G-3 unresolved: claimed addressed but did not "
        "change RESP-2, FB-2-1."
    ) in outcome.warnings
    assert (
        "Revision left critic gap G-4 unresolved: claimed addressed but did not "
        "change RESP-3."
    ) in outcome.warnings
    assert not [w for w in outcome.warnings if "G-1" in w or "G-2" in w]
    published = {resp.resp_id for resp in outcome.structure.responsibilities}
    assert published == {"RESP-1", "RESP-2", "RESP-3", "RESP-4"}


def test_a_genuinely_addressed_gap_is_not_flagged(tmp_path) -> None:
    reply = _reply(
        # The parent responsibility counts as changed when its child changes.
        _disposition("G-1", "addressed", "RESP-1"),
        _disposition("G-2", "addressed", "RESP-4", "PM-4-1"),
        _disposition("G-3", "dismissed"),
        _disposition("G-4", "recommendation"),
    )

    outcome, _ = _revise(reply, tmp_path)

    assert outcome.applied is True
    assert outcome.gap_review is not None
    assert outcome.gap_review.unresolved == ()
    assert outcome.gap_review.counts == {
        "addressed": 2,
        "dismissed": 1,
        "recommendation": 1,
    }
    assert not [w for w in outcome.warnings if "unresolved" in w]


def test_dismissals_and_recommendations_keep_their_readable_warnings(
    tmp_path,
) -> None:
    reply = _reply(
        _disposition("G-1", "addressed", "PM-1-2"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-3", "dismissed"),
        _disposition("G-4", "recommendation"),
    )

    outcome, _ = _revise(reply, tmp_path)

    assert "Revision dismissed finding G-3: Disposition of G-3." in outcome.warnings
    assert (
        "Revision dismissed finding G-4 as a design recommendation: Disposition of G-4."
    ) in outcome.warnings


def test_a_missing_disposition_is_unresolved(tmp_path) -> None:
    reply = _reply(
        _disposition("G-1", "addressed", "PM-1-2"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-4", "dismissed"),
    )

    outcome, _ = _revise(reply, tmp_path)

    assert outcome.gap_review is not None
    assert [(gap.gap_id, gap.reason) for gap in outcome.gap_review.unresolved] == [
        ("G-3", "no disposition")
    ]
    assert (
        "Revision left critic gap G-3 unresolved: no disposition." in outcome.warnings
    )


def test_a_disposition_for_an_unknown_gap_is_unresolved(tmp_path) -> None:
    reply = _reply(
        _disposition("G-1", "addressed", "PM-1-2"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-3", "dismissed"),
        _disposition("G-4", "dismissed"),
        _disposition("G-9", "addressed", "RESP-4"),
    )

    outcome, _ = _revise(reply, tmp_path)

    assert outcome.gap_review is not None
    assert [(gap.gap_id, gap.reason) for gap in outcome.gap_review.unresolved] == [
        ("G-9", "unknown gap id")
    ]
    assert outcome.gap_review.counts["addressed"] == 3
    assert (
        "Revision left critic gap G-9 unresolved: unknown gap id." in outcome.warnings
    )


def test_an_unchanged_revision_leaves_every_addressed_claim_unresolved(
    tmp_path,
) -> None:
    reply = {
        "modified_responsibilities": [],
        "gap_dispositions": [
            _disposition("G-1", "addressed", "RESP-1"),
            _disposition("G-2", "addressed"),
            _disposition("G-3", "dismissed"),
            _disposition("G-4", "recommendation"),
        ],
    }

    outcome, _ = _revise(reply, tmp_path)

    assert outcome.applied is False
    assert outcome.gap_review is not None
    assert [(gap.gap_id, gap.reason) for gap in outcome.gap_review.unresolved] == [
        ("G-1", "claimed addressed but did not change RESP-1"),
        ("G-2", "claimed addressed but named no element"),
    ]


def test_a_claim_may_name_the_id_the_reply_wrote_for_a_renumbered_element(
    tmp_path,
) -> None:
    resp = _new_resp_4()
    # The reply numbers its new responsibility RESP-7; it is published as RESP-4.
    resp_json = json.dumps(resp).replace("RESP-4", "RESP-7").replace("-4-", "-7-")
    reply = {
        "new_responsibilities": [json.loads(resp_json)],
        "gap_dispositions": [
            _disposition("G-1", "dismissed"),
            _disposition("G-2", "addressed", "RESP-7", "CA-7-1"),
            _disposition("G-3", "dismissed"),
            _disposition("G-4", "dismissed"),
        ],
    }

    outcome, _ = _revise(reply, tmp_path)

    assert outcome.applied is True
    assert [resp.resp_id for resp in outcome.structure.responsibilities][-1] == (
        "RESP-4"
    )
    assert outcome.gap_review is not None
    assert outcome.gap_review.unresolved == ()


# ---------------------------------------------------------------------------
# Element identity across the merge's renumbering
# ---------------------------------------------------------------------------


def _resp_1_with_a_variable_inserted_first(*, read_new_variable: bool) -> dict:
    """RESP-1 restated with a new variable, written PM-1-2, before PM-1-1.

    Normalization numbers by position, so the new variable publishes as
    PM-1-1 and the unchanged original as PM-1-2.
    """
    resp = _reviewed().responsibilities[0].model_dump(mode="json", exclude_none=True)
    resp["process_model_parts"].insert(
        0, {"pm_id": "PM-1-2", "description": "Stored draft status", "values": []}
    )
    if read_new_variable:
        resp["control_actions"][0]["process_model_refs"].append("PM-1-2")
    return resp


def _inserted_reply(*element_ids: str, read_new_variable: bool = True) -> dict:
    return {
        "modified_responsibilities": [
            _resp_1_with_a_variable_inserted_first(read_new_variable=read_new_variable)
        ],
        "gap_dispositions": [
            _disposition("G-1", "addressed", *element_ids),
            _disposition("G-2", "dismissed"),
            _disposition("G-3", "dismissed"),
            _disposition("G-4", "dismissed"),
        ],
    }


def _published_variables(outcome) -> list[tuple[str, str]]:
    resp = outcome.structure.responsibilities[0]
    return [(pm.pm_id, pm.description) for pm in resp.process_model_parts]


def test_a_claim_naming_a_renumbered_unchanged_variable_is_unresolved(
    tmp_path,
) -> None:
    # The claim names the original variable the reply restated unchanged.
    outcome, _ = _revise(_inserted_reply("PM-1-1"), tmp_path)

    assert outcome.applied is True
    assert _published_variables(outcome) == [
        ("PM-1-1", "Stored draft status"),
        ("PM-1-2", "Store drafts for review state"),
    ]
    assert outcome.gap_review is not None
    assert [(gap.gap_id, gap.reason) for gap in outcome.gap_review.unresolved] == [
        ("G-1", "claimed addressed but did not change PM-1-1")
    ]


def test_a_claim_naming_the_inserted_variable_as_written_is_resolved(
    tmp_path,
) -> None:
    outcome, _ = _revise(_inserted_reply("PM-1-2"), tmp_path)

    assert outcome.gap_review is not None
    assert outcome.gap_review.unresolved == ()


def test_an_inserted_unread_variable_is_reported_under_its_published_id(
    tmp_path,
) -> None:
    outcome, _ = _revise(_inserted_reply("PM-1-2", read_new_variable=False), tmp_path)

    assert (
        "Revision added process-model variable PM-1-1 (Stored draft status) that "
        "no control action reads."
    ) in outcome.warnings
    # The original keeps its reader under its new published ID.
    assert not [w for w in outcome.warnings if "PM-1-2 (" in w]


def _reviewed_with_two_links() -> ControlStructure:
    structure = _reviewed().model_dump(mode="json")
    structure["coordination_links"] = [
        {
            "link_id": f"CL-{number}",
            "source": "RESP-1",
            "target": f"RESP-{number + 1}",
            "shared_pm": "PM-1-1",
            "coordination_mechanism": {
                "cm_id": f"CM-{number}",
                "description": f"Shared draft state {number}",
                "payload": "draft state",
            },
            "description": f"Coordinate drafts with RESP-{number + 1}",
        }
        for number in (1, 2)
    ]
    return ControlStructure.model_validate(structure)


def test_a_claim_naming_a_new_mechanism_by_its_colliding_written_id_is_resolved(
    tmp_path,
) -> None:
    reply = {
        "new_coordination_links": [
            {
                "link_id": "CL-3",
                "source": "RESP-2",
                "target": "RESP-3",
                "shared_pm": "PM-2-1",
                # Collides with the existing CL-1 mechanism; it publishes as CM-3.
                "coordination_mechanism": {
                    "cm_id": "CM-1",
                    "description": "Shared ownership state",
                    "payload": "draft owner",
                },
                "description": "Coordinate ownership with escalation",
            }
        ],
        "gap_dispositions": [
            _disposition("G-1", "addressed", "CM-1"),
            _disposition("G-2", "addressed", "CL-3"),
            _disposition("G-3", "dismissed"),
            _disposition("G-4", "dismissed"),
        ],
    }

    outcome, _ = _revise(reply, tmp_path, reviewed=_reviewed_with_two_links())

    assert outcome.applied is True
    mechanisms = [
        link.coordination_mechanism.cm_id
        for link in outcome.structure.coordination_links
    ]
    assert mechanisms == ["CM-1", "CM-2", "CM-3"]
    assert outcome.gap_review is not None
    assert outcome.gap_review.unresolved == ()


def test_a_claim_naming_an_existing_mechanism_by_published_id_is_unresolved(
    tmp_path,
) -> None:
    reply = {
        "new_coordination_links": [
            {
                "link_id": "CL-3",
                "source": "RESP-2",
                "target": "RESP-3",
                "shared_pm": "PM-2-1",
                "coordination_mechanism": {
                    "cm_id": "CM-3",
                    "description": "Shared ownership state",
                    "payload": "draft owner",
                },
                "description": "Coordinate ownership with escalation",
            }
        ],
        "gap_dispositions": [
            _disposition("G-1", "addressed", "CM-2"),
            _disposition("G-2", "dismissed"),
            _disposition("G-3", "dismissed"),
            _disposition("G-4", "dismissed"),
        ],
    }

    outcome, _ = _revise(reply, tmp_path, reviewed=_reviewed_with_two_links())

    assert outcome.gap_review is not None
    assert [(gap.gap_id, gap.reason) for gap in outcome.gap_review.unresolved] == [
        ("G-1", "claimed addressed but did not change CM-2")
    ]


# ---------------------------------------------------------------------------
# A variable the revision added that no control action reads
# ---------------------------------------------------------------------------


_UNREAD_WARNING = (
    "Revision added process-model variable PM-1-2 (Stored draft status) that no "
    "control action reads."
)


def test_an_added_variable_no_action_reads_is_reported(tmp_path) -> None:
    reply = _reply(
        _disposition("G-1", "addressed", "PM-1-2"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-3", "dismissed"),
        _disposition("G-4", "dismissed"),
        read_new_variable=False,
    )

    outcome, _ = _revise(reply, tmp_path)

    assert outcome.applied is True
    assert _UNREAD_WARNING in outcome.warnings
    # The variables of the new responsibility are read by its action.
    assert not [w for w in outcome.warnings if "PM-4-1" in w]


def test_an_added_variable_an_action_reads_is_not_reported(tmp_path) -> None:
    reply = _reply(
        _disposition("G-1", "addressed", "PM-1-2"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-3", "dismissed"),
        _disposition("G-4", "dismissed"),
        read_new_variable=True,
    )

    outcome, _ = _revise(reply, tmp_path)

    assert _UNREAD_WARNING not in outcome.warnings
    assert not [w for w in outcome.warnings if "no control action reads" in w]


def test_a_pre_existing_unread_variable_is_not_reported(tmp_path) -> None:
    reviewed = _reviewed()
    reviewed.responsibilities[1].process_model_parts.append(
        ProcessModelPart(pm_id="PM-2-2", description="Unread before the revision")
    )
    resp_2 = reviewed.responsibilities[1].model_dump(mode="json", exclude_none=True)
    # A restatement may reword the variable's description; it is still the
    # reviewed variable.
    resp_2["process_model_parts"][1]["description"] = "Reworded"
    reply = {
        "modified_responsibilities": [resp_2],
        "gap_dispositions": [
            _disposition("G-1", "addressed", "PM-2-2"),
            _disposition("G-2", "dismissed"),
            _disposition("G-3", "dismissed"),
            _disposition("G-4", "dismissed"),
        ],
    }

    outcome, _ = _revise(reply, tmp_path, reviewed=reviewed)

    assert outcome.applied is True
    assert not [w for w in outcome.warnings if "no control action reads" in w]
    assert outcome.gap_review is not None
    assert outcome.gap_review.unresolved == ()


def test_the_helper_reports_an_unread_variable_whose_identity_is_new() -> None:
    published = _reviewed()
    published.responsibilities[1].process_model_parts.append(
        ProcessModelPart(pm_id="PM-2-2", description="Unread variable")
    )
    identity = RevisionIdentity.unchanged(published)

    assert unread_added_process_model_warnings(published, identity) == []
    new = RevisionIdentity(
        identities={**identity.identities, "PM-2-2": ("new", "PM", 1, 1)},
        written={},
    )
    assert unread_added_process_model_warnings(published, new) == [
        "Revision added process-model variable PM-2-2 (Unread variable) that no "
        "control action reads."
    ]


# ---------------------------------------------------------------------------
# The earlier reply format
# ---------------------------------------------------------------------------


def test_a_reply_with_free_text_dismissed_gaps_still_loads(tmp_path) -> None:
    reply = {
        "new_responsibilities": [],
        "new_controlled_processes": [],
        "new_coordination_links": [],
        "modified_responsibilities": [],
        "dismissed_gaps": ["Ownership is already confirmed by FB-2-1."],
    }

    assert RevisionDelta.model_validate(reply).dismissed_gaps == [
        "Ownership is already confirmed by FB-2-1."
    ]
    assert _RevisionDeltaProviderSet.model_validate(reply).gap_dispositions == []
    outcome, _ = _revise(reply, tmp_path)

    assert outcome.gap_review is None
    assert (
        "Revision dismissed finding: Ownership is already confirmed by FB-2-1."
        in outcome.warnings
    )
    assert not [w for w in outcome.warnings if "unresolved:" in w]


# Every saved Stage 2 revision reply fixture was written in the earlier format.
_SAVED_REPLIES = sorted(
    path
    for path in FIXTURES.glob("revision_*.json")
    if "modified_responsibilities" in json.loads(path.read_text())
)


@pytest.mark.parametrize("path", _SAVED_REPLIES, ids=lambda path: path.stem)
def test_a_saved_reply_in_the_earlier_format_validates(path: Path) -> None:
    value = json.loads(path.read_text())

    delta = _RevisionDeltaProviderSet.model_validate(value)

    assert "gap_dispositions" not in value
    assert delta.gap_dispositions == []
    assert delta.dismissed_gaps == value.get("dismissed_gaps", [])


def test_saved_replies_in_the_earlier_format_are_present() -> None:
    assert any("dismissed_gaps" in json.loads(p.read_text()) for p in _SAVED_REPLIES)


def test_the_request_schema_offers_dispositions_and_not_free_text() -> None:
    schema = _RevisionDeltaProviderSet.model_json_schema()

    assert "dismissed_gaps" not in schema["properties"]
    disposition = schema["$defs"]["_RevisionGapDisposition"]
    assert list(disposition["properties"]) == [
        "gap_id",
        "disposition",
        "element_ids",
        "justification",
    ]
    assert disposition["properties"]["disposition"]["enum"] == [
        "addressed",
        "dismissed",
        "recommendation",
    ]


# ---------------------------------------------------------------------------
# The check and the record
# ---------------------------------------------------------------------------


def test_gap_ids_follow_the_finding_order() -> None:
    assert critic_gap_ids(3) == ["G-1", "G-2", "G-3"]
    assert critic_gap_ids(0) == []


def test_changed_ids_cover_added_and_modified_elements() -> None:
    before = _reviewed()
    after = before.model_copy(deep=True)
    after.responsibilities[0].feedback_channels[0].description = "Reworded report"
    after.responsibilities.append(_responsibility(4, "Validate arguments"))

    assert changed_element_ids(before, after) == {
        "RESP-1",
        "FB-1-1",
        "RESP-4",
        "PM-4-1",
        "CA-4-1",
        "FB-4-1",
    }


def test_an_addressed_claim_counts_once_any_named_id_changed() -> None:
    review = review_gap_dispositions(
        [
            GapDisposition(
                gap_id="G-1",
                disposition="addressed",
                element_ids=["RESP-2", "FB-1-1"],
                justification="Changes the report.",
            )
        ],
        gap_count=1,
        changed_ids=frozenset({"RESP-1", "FB-1-1"}),
    )

    assert review.unresolved == ()


def test_the_record_carries_counts_and_unresolved_gaps(tmp_path) -> None:
    reply = _reply(
        _disposition("G-1", "addressed", "PM-1-2"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-3", "addressed", "RESP-2"),
    )
    outcome, _ = _revise(reply, tmp_path)

    record = _critic_revision_record(
        _FINDINGS,
        outcome.warnings,
        revised=outcome.applied,
        gap_review=outcome.gap_review,
    )

    assert record == {
        "status": "applied",
        "gap_dispositions": {"addressed": 3, "dismissed": 0, "recommendation": 0},
        "unresolved_gaps": [
            {"gap_id": "G-3", "reason": "claimed addressed but did not change RESP-2"},
            {"gap_id": "G-4", "reason": "no disposition"},
        ],
    }


def test_a_discarded_revision_records_no_gap_review(tmp_path) -> None:
    outcome, _ = _revise({"new_responsibilities": "not a list"}, tmp_path)

    assert outcome.gap_review is None
    record = _critic_revision_record(
        _FINDINGS,
        outcome.warnings,
        revised=outcome.applied,
        gap_review=outcome.gap_review,
    )
    assert record is not None
    assert set(record) == {"status", "reason"}
    assert record["status"] == "discarded"

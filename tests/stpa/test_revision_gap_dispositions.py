"""The revision gives one disposition per critic gap, and code checks the claims.

Code numbers the critic gaps ``G-1`` to ``G-n`` in finding order and shows
each ID next to its gap.  The reply says, per gap, whether it ``addressed``,
``dismissed`` or kept the gap as a ``recommendation``.  An ``addressed`` claim
must name an element the published structure adds or changes; a gap with no
disposition or with several, a disposition for an unknown gap, and an
``addressed`` claim that changed nothing it names are unresolved.  A
responsibility named with its children is judged by them, and one named
alone does not count a change another gap's claim names.  The check sends no request and
never rejects the reply: it adds post-revision warnings and fields of the
``critic_revision`` record.  A process-model variable the revision added and
no control action reads is reported as well.  A reply in the earlier format,
with free-text ``dismissed_gaps`` and no dispositions, still loads.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
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
    ElementChanges,
    GapDisposition,
    RevisionIdentity,
    changed_element_ids,
    critic_gap_ids,
    element_changes,
    element_ref_fields,
    reference_fields,
    review_gap_dispositions,
    unread_added_process_model_warnings,
)
from asago_scenario_generator.stpa.system_model.id_normalization import (
    _TYPED_REFERENCE_FIELDS,
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


def test_a_gap_given_two_dispositions_is_unresolved_and_not_counted(
    tmp_path,
) -> None:
    reply = _reply(
        # Each of G-1's claims would pass on its own.
        _disposition("G-1", "addressed", "PM-1-2"),
        _disposition("G-1", "addressed", "FB-1-2"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-3", "dismissed"),
        _disposition("G-4", "recommendation"),
    )

    outcome, client = _revise(reply, tmp_path)

    assert outcome.applied is True
    assert len(client.calls) == 1
    assert outcome.gap_review is not None
    assert outcome.gap_review.record() == {
        "gap_dispositions": {"addressed": 1, "dismissed": 1, "recommendation": 1},
        "unresolved_gaps": [
            {
                "gap_id": "G-1",
                "reason": "gave 2 dispositions: addressed (PM-1-2), addressed (FB-1-2)",
            }
        ],
    }
    assert (
        "Revision left critic gap G-1 unresolved: gave 2 dispositions: "
        "addressed (PM-1-2), addressed (FB-1-2)."
    ) in outcome.warnings


def test_a_gap_given_conflicting_dispositions_is_unresolved_and_not_counted() -> None:
    review = review_gap_dispositions(
        [
            GapDisposition(
                gap_id="G-1",
                disposition="addressed",
                element_ids=["FB-1-1"],
                justification="Changes the report.",
            ),
            GapDisposition(
                gap_id="G-1", disposition="dismissed", justification="Covered."
            ),
            GapDisposition(
                gap_id="G-1", disposition="recommendation", justification="Later."
            ),
        ],
        gap_count=1,
        changes=ElementChanges(frozenset({"RESP-1", "FB-1-1"})),
    )

    assert review.counts == {"addressed": 0, "dismissed": 0, "recommendation": 0}
    assert [(gap.gap_id, gap.reason) for gap in review.unresolved] == [
        (
            "G-1",
            "gave 3 dispositions: addressed (FB-1-1), dismissed, recommendation",
        )
    ]


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


def test_a_parent_changed_for_another_gap_does_not_resolve_a_claim(
    tmp_path,
) -> None:
    # G-1 asks for something FB-1-1 already has, and the reply restates
    # FB-1-1 unchanged.  For G-4 the reply cites a new constraint on RESP-1
    # and adds PM-1-2 and FB-1-2 to it; G-4 names RESP-1 and those children.
    reply = _reply(
        _disposition("G-1", "addressed", "RESP-1", "FB-1-1"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-3", "dismissed"),
        _disposition("G-4", "addressed", "RESP-1", "PM-1-2", "FB-1-2"),
    )
    reply["modified_responsibilities"][0]["security_constraint_refs"] = ["SC-9"]

    outcome, _ = _revise(reply, tmp_path)

    assert outcome.applied is True
    assert outcome.gap_review is not None
    assert outcome.gap_review.counts["addressed"] == 3
    assert [(gap.gap_id, gap.reason) for gap in outcome.gap_review.unresolved] == [
        (
            "G-1",
            "claimed addressed but did not change FB-1-1; RESP-1 changed only "
            "outside FB-1-1",
        )
    ]
    assert (
        "Revision left critic gap G-1 unresolved: claimed addressed but did not "
        "change FB-1-1; RESP-1 changed only outside FB-1-1."
    ) in outcome.warnings


def test_a_parent_named_alone_is_unresolved_when_another_gap_names_its_changes(
    tmp_path,
) -> None:
    reply = _reply(
        _disposition("G-1", "addressed", "RESP-1"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-3", "addressed", "PM-1-2"),
        _disposition("G-4", "addressed", "FB-1-2"),
        read_new_variable=False,
    )

    outcome, _ = _revise(reply, tmp_path)

    assert outcome.gap_review is not None
    assert [(gap.gap_id, gap.reason) for gap in outcome.gap_review.unresolved] == [
        (
            "G-1",
            "claimed addressed but RESP-1 changed only in PM-1-2, FB-1-2, "
            "which G-3, G-4 name",
        )
    ]


def test_a_parent_named_alone_resolves_through_a_change_no_other_claim_names(
    tmp_path,
) -> None:
    reply = _reply(
        _disposition("G-1", "addressed", "RESP-1"),
        _disposition("G-2", "addressed", "RESP-4"),
        # A set-aside gap's element IDs claim no change.
        _disposition("G-3", "dismissed", "FB-1-2"),
        _disposition("G-4", "addressed", "RESP-1", "PM-1-2"),
        read_new_variable=False,
    )

    outcome, _ = _revise(reply, tmp_path)

    # FB-1-2 changed RESP-1 and no other addressed claim names it.
    assert outcome.gap_review is not None
    assert outcome.gap_review.unresolved == ()


def test_a_parent_named_alone_resolves_when_its_own_fields_changed(
    tmp_path,
) -> None:
    reply = _reply(
        _disposition("G-1", "addressed", "RESP-1"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-3", "dismissed"),
        _disposition("G-4", "addressed", "RESP-1", "PM-1-2", "FB-1-2"),
        read_new_variable=False,
    )
    reply["modified_responsibilities"][0]["description"] = "Store and track drafts"

    outcome, _ = _revise(reply, tmp_path)

    assert outcome.gap_review is not None
    assert outcome.gap_review.unresolved == ()


def _claim(gap_id: str, *element_ids: str) -> GapDisposition:
    return GapDisposition(
        gap_id=gap_id,
        disposition="addressed",
        element_ids=list(element_ids),
        justification=f"Addresses {gap_id}.",
    )


def test_the_helper_judges_a_parent_named_with_a_child_by_the_child() -> None:
    changes = ElementChanges(
        ids=frozenset({"RESP-1", "PM-1-3"}),
        members={"RESP-1": ("PM-1-1", "PM-1-3", "FB-1-1")},
    )

    review = review_gap_dispositions(
        [_claim("G-1", "RESP-1", "FB-1-1"), _claim("G-2", "RESP-1", "PM-1-3")],
        gap_count=2,
        changes=changes,
    )

    assert [(gap.gap_id, gap.reason) for gap in review.unresolved] == [
        (
            "G-1",
            "claimed addressed but did not change FB-1-1; RESP-1 changed only "
            "outside FB-1-1",
        )
    ]


def test_the_helper_attributes_a_member_change_to_the_gap_that_names_it() -> None:
    changes = ElementChanges(
        ids=frozenset({"RESP-1", "PM-1-3"}),
        members={"RESP-1": ("PM-1-1", "PM-1-3")},
        member_changes={"RESP-1": ("PM-1-3",)},
    )

    review = review_gap_dispositions(
        [_claim("G-1", "RESP-1"), _claim("G-2", "PM-1-3")],
        gap_count=2,
        changes=changes,
    )

    assert [(gap.gap_id, gap.reason) for gap in review.unresolved] == [
        ("G-1", "claimed addressed but RESP-1 changed only in PM-1-3, which G-2 names")
    ]


def test_member_changes_name_the_parents_changed_only_through_members() -> None:
    before = _reviewed()
    after = before.model_copy(deep=True)
    after.responsibilities[0].feedback_channels[0].description = "Reworded report"
    after.responsibilities[1].description = "Track draft owners"
    after.responsibilities[1].feedback_channels[0].description = "Reworded report"
    after.responsibilities[2].process_model_parts.append(
        ProcessModelPart(pm_id="PM-3-2", description="Escalation status")
    )

    changes = element_changes(before, after)

    assert changes.ids == changed_element_ids(before, after)
    assert changes.members["RESP-3"] == ("PM-3-1", "PM-3-2", "CA-3-1", "FB-3-1")
    # RESP-2's own description changed, so it is not changed only through
    # its members.
    assert changes.member_changes == {
        "RESP-1": ("FB-1-1",),
        "RESP-3": ("PM-3-2",),
    }


def test_a_parent_that_lost_a_member_changed_on_its_own() -> None:
    before = _reviewed()
    after = before.model_copy(deep=True)
    after.responsibilities[0].feedback_channels = []

    changes = element_changes(before, after)

    assert "RESP-1" in changes.ids
    assert "RESP-1" not in changes.member_changes


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


def _reviewed_with_id_like_values() -> ControlStructure:
    """The reviewed structure where PM-2-1 holds an ID-like literal value."""
    reviewed = _reviewed()
    reviewed.responsibilities[1].process_model_parts[0].values = ["PM-1-1", "none"]
    return reviewed


def _insertion_and_resp_2(resp_2: dict | None, *element_ids: str) -> dict:
    """The insertion into RESP-1, optionally RESP-2 restated, one claim on G-1."""
    reply = _inserted_reply(*element_ids)
    if resp_2 is not None:
        reply["modified_responsibilities"].append(resp_2)
    return reply


def test_an_untouched_id_like_value_is_not_rewritten_by_the_renumbering(
    tmp_path,
) -> None:
    reply = _insertion_and_resp_2(None, "PM-2-1")

    outcome, _ = _revise(reply, tmp_path, reviewed=_reviewed_with_id_like_values())

    # The insertion published the new variable as PM-1-1; PM-2-1's literal
    # value "PM-1-1" is data, not a reference, and PM-2-1 is unchanged.
    assert outcome.structure.responsibilities[1].process_model_parts[0].values == [
        "PM-1-1",
        "none",
    ]
    assert outcome.gap_review is not None
    assert [(gap.gap_id, gap.reason) for gap in outcome.gap_review.unresolved] == [
        ("G-1", "claimed addressed but did not change PM-2-1")
    ]


def test_a_changed_id_like_value_is_a_change_after_the_renumbering(
    tmp_path,
) -> None:
    reviewed = _reviewed_with_id_like_values()
    resp_2 = reviewed.responsibilities[1].model_dump(mode="json", exclude_none=True)
    resp_2["process_model_parts"][0]["values"] = ["PM-1-2", "none"]
    reply = _insertion_and_resp_2(resp_2, "PM-2-1")

    outcome, _ = _revise(reply, tmp_path, reviewed=reviewed)

    assert outcome.structure.responsibilities[1].process_model_parts[0].values == [
        "PM-1-2",
        "none",
    ]
    assert outcome.gap_review is not None
    assert outcome.gap_review.unresolved == ()


def test_reference_fields_are_still_read_through_the_renumbering(tmp_path) -> None:
    # The restated action and channel still name the original variable, which
    # now publishes as PM-1-2; they are unchanged, and so is RESP-2's channel.
    reply = _inserted_reply("CA-1-1", "FB-1-1", "FB-2-1", read_new_variable=False)

    outcome, _ = _revise(reply, tmp_path)

    resp_1 = outcome.structure.responsibilities[0]
    assert resp_1.control_actions[0].process_model_refs == ["PM-1-2"]
    assert resp_1.feedback_channels[0].updates == "PM-1-2"
    assert outcome.gap_review is not None
    assert [(gap.gap_id, gap.reason) for gap in outcome.gap_review.unresolved] == [
        ("G-1", "claimed addressed but did not change CA-1-1, FB-1-1, FB-2-1")
    ]


def test_the_typed_reference_fields_come_from_the_model() -> None:
    derived = {
        (items, name)
        for model, items in (
            (ProcessModelPart, "process_model_parts"),
            (ControlAction, "control_actions"),
            (FeedbackChannel, "feedback_channels"),
        )
        for name in element_ref_fields(model)
    }

    # They are the typed references the ID normalizer rewrites.
    assert derived == set(_TYPED_REFERENCE_FIELDS)
    assert reference_fields(ProcessModelPart) == ("pm_id", "feedback_source")
    assert reference_fields(ControlAction) == ("ca_id", "process_model_refs", "target")
    assert reference_fields(FeedbackChannel) == ("fb_id", "updates", "source")
    assert reference_fields(CoordinationLink) == (
        "link_id",
        "source",
        "target",
        "shared_pm",
    )
    assert reference_fields(Responsibility) == ("resp_id",)


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


def _transport_client(*replies: dict[str, Any]) -> LLMClient:
    """A client that parses each reply into the request's schema, as live."""
    client = LLMClient(
        base_url="http://test-endpoint.invalid", api_key="test-key", model="test-model"
    )
    client._client = MagicMock()
    client._client.chat.completions.create.side_effect = [
        SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=3, completion_tokens=4),
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=json.dumps(reply)),
                    finish_reason="stop",
                )
            ],
        )
        for reply in replies
    ]
    return client


def _fields_outside_schema(
    value: Any, schema: dict[str, Any], defs: dict[str, Any], path: str = ""
) -> list[str]:
    """Return the path of each object field *value* holds that *schema* lacks."""
    if "$ref" in schema:
        schema = defs[schema["$ref"].rsplit("/", 1)[-1]]
    for option in schema.get("anyOf", ()):
        if (option.get("type") == "null") == (value is None):
            return _fields_outside_schema(value, option, defs, path)
    outside: list[str] = []
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key not in properties:
                outside.append(f"{path}/{key}")
            else:
                outside.extend(
                    _fields_outside_schema(item, properties[key], defs, f"{path}/{key}")
                )
    elif isinstance(value, list):
        for index, item in enumerate(value):
            outside.extend(
                _fields_outside_schema(
                    item, schema.get("items", {}), defs, f"{path}/{index}"
                )
            )
    return outside


def test_the_correction_shows_the_prior_reply_in_the_current_format(
    tmp_path,
) -> None:
    unmergeable = _reply(
        _disposition("G-1", "addressed", "PM-1-2"),
        _disposition("G-2", "addressed", "RESP-4"),
        _disposition("G-3", "dismissed"),
        _disposition("G-4", "dismissed"),
    )
    unmergeable["modified_responsibilities"][0]["resp_id"] = "RESP-9"
    corrected = _reply(*unmergeable["gap_dispositions"])
    client = _transport_client(unmergeable, corrected)

    outcome = revise_control_structure(
        llm_client=client,
        control_structure=_reviewed(),
        critic_findings=_FINDINGS,
        use_case_text="Drafts are stored for later review by a person.",
        run_dir=tmp_path,
    )

    assert outcome.applied is True
    first, correction = [
        call.kwargs for call in client._client.chat.completions.create.call_args_list
    ]
    request = correction["messages"][-1]["content"]
    shown = request.split("Prior structured response to correct in place:\n```json\n")[
        1
    ].split("\n```", 1)[0]
    schema = first["response_format"]["json_schema"]["schema"]
    prior = json.loads(shown)
    assert prior["modified_responsibilities"][0]["resp_id"] == "RESP-9"
    assert "dismissed_gaps" not in request
    assert _fields_outside_schema(prior, schema, schema["$defs"]) == []


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
        changes=ElementChanges(frozenset({"RESP-1", "FB-1-1"})),
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

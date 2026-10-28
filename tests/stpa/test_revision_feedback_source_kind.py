"""A critic revision that writes a source kind as a feedback source type is kept.

The fixtures are a reviewed OcciAI control structure and the revision reply a
saved run merged into it.  The reply adds RESP-2 and RESP-3, each with one
feedback channel whose ``source.type`` is a source kind (``session_context``,
``other``) and whose ``source.id`` names no element.  A source reference names
a responsibility or controlled process, so the merged structure failed
validation and the run published the reviewed structure instead.

A revision the stage discards is reported in the stage warnings and in the
Stage 2 manifest summary, which the final product manifest keeps.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ElementRef,
    FeedbackSourceKind,
    ReferenceType,
)
from asago_scenario_generator.stpa.scenario_prod.run import (
    _manifest_stage_summary,
    _preserved_stage_keys,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    RevisionDelta,
    _merge_revision_delta,
    _revision_delta_from_wire,
    _validate_revision_wire,
    run_revision,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.helpers.stpa_builders import make_risk_cards
from tests.stpa.sp1_helpers import MockLLMClient, setup_sp1_mock_client

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "stpa"

USE_CASE = "A support assistant answers account questions."


def _reviewed() -> ControlStructure:
    return read_yaml(  # type: ignore[return-value]
        FIXTURES_DIR / "control_structure_reviewed_occiai.yaml", ControlStructure
    )


def _reply() -> dict:
    return json.loads(
        (FIXTURES_DIR / "revision_source_kind_as_type_occiai.json").read_text(
            encoding="utf-8"
        )
    )


def _merge(reply: dict) -> tuple[ControlStructure, list[str]]:
    _validate_revision_wire(reply)
    return _merge_revision_delta(_reviewed(), _revision_delta_from_wire(reply))


def _channels(structure: ControlStructure) -> dict:
    return {
        fb.fb_id: fb
        for resp in structure.responsibilities
        for fb in resp.feedback_channels
    }


def _restated_channel(reply: dict, fb_id: str) -> dict:
    return next(
        fb
        for resp in reply["modified_responsibilities"]
        for fb in resp["feedback_channels"]
        if fb["fb_id"] == fb_id
    )


def test_reply_writes_a_source_kind_as_the_source_type() -> None:
    sources = {
        fb["fb_id"]: (fb["source"], fb.get("source_kind"))
        for resp in _reply()["new_responsibilities"]
        for fb in resp["feedback_channels"]
    }

    assert sources == {
        "FB-2-1": (
            {"type": "session_context", "id": "session:authenticated_patient_id"},
            None,
        ),
        "FB-3-1": ({"type": "other", "id": "intent_classifier"}, None),
    }


def test_revision_keeps_the_reply_that_writes_a_source_kind_as_the_source_type():
    merged, _ = _merge(_reply())

    assert [resp.resp_id for resp in merged.responsibilities] == [
        "RESP-1",
        "RESP-2",
        "RESP-3",
    ]
    assert [link.link_id for link in merged.coordination_links] == ["CL-1", "CL-2"]
    channels = _channels(merged)
    assert channels["FB-2-1"].source is None
    assert channels["FB-2-1"].source_kind is FeedbackSourceKind.session_context
    assert channels["FB-3-1"].source is None
    assert channels["FB-3-1"].source_kind is FeedbackSourceKind.other
    reviewed = _channels(_reviewed())
    for fb_id in ("FB-1-1", "FB-1-2"):
        assert channels[fb_id] == reviewed[fb_id], fb_id


def test_merge_reports_each_source_kind_it_moves() -> None:
    _, warnings = _merge(_reply())

    assert warnings[:2] == [
        "Revision feedback channel FB-2-1 of RESP-2 gave the source kind "
        "'session_context' as its source type; it is kept as the channel's "
        "source_kind and the source reference 'session:authenticated_patient_id', "
        "which names no responsibility or controlled process, is dropped.",
        "Revision feedback channel FB-3-1 of RESP-3 gave the source kind "
        "'other' as its source type; it is kept as the channel's source_kind "
        "and the source reference 'intent_classifier', which names no "
        "responsibility or controlled process, is dropped.",
    ]


def test_a_restated_channel_keeps_its_source_when_the_reply_gives_a_kind() -> None:
    reply = _reply()
    channel = _restated_channel(reply, "FB-1-1")
    channel["source"] = {"type": "user_message", "id": "user_message"}
    del channel["source_kind"]

    merged, _ = _merge(reply)

    restated = _channels(merged)["FB-1-1"]
    assert restated.source == ElementRef(
        type=ReferenceType.controlled_process, id="CP-1"
    )
    assert restated.source_kind is FeedbackSourceKind.user_message


def test_a_restated_channel_without_a_source_keeps_its_source() -> None:
    reply = _reply()
    del _restated_channel(reply, "FB-1-2")["source"]

    merged, _ = _merge(reply)

    assert _channels(merged)["FB-1-2"].source == ElementRef(
        type=ReferenceType.controlled_process, id="CP-9"
    )


def test_a_source_type_that_contradicts_the_source_kind_is_rejected() -> None:
    reply = _reply()
    new_channel = reply["new_responsibilities"][0]["feedback_channels"][0]
    new_channel["source_kind"] = "user_message"

    with pytest.raises(ValidationError, match="input_value='session_context'"):
        _merge(reply)


def test_run_revision_applies_the_saved_reply(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_for(RevisionDelta, _reply())
    reviewed = _reviewed()

    revised, warnings = run_revision(
        llm_client=client,
        control_structure=reviewed,
        critic_findings=_findings(),
        use_case_text=USE_CASE,
        run_dir=tmp_path,
    )

    assert revised != reviewed
    assert len(revised.responsibilities) == 3
    assert not [w for w in warnings if w.startswith("Revision delta merge degraded")]


# ---------------------------------------------------------------------------
# A discarded revision is reported
# ---------------------------------------------------------------------------


def _findings() -> CriticFindings:
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_feedback",
                description="No feedback reports the classified intent",
                related_attack_path="A crafted message is read as a routine request",
                suggested_remedy="Add intent classification feedback",
            )
        ]
    )


def _revision_reply(source: dict) -> dict:
    return {
        "new_responsibilities": [
            {
                "resp_id": "RESP-9",
                "description": "Classify the intent of each customer message",
                "process_model_parts": [
                    {"pm_id": "PM-9-1", "description": "Classified intent"}
                ],
                "control_actions": [],
                "feedback_channels": [
                    {
                        "fb_id": "FB-9-1",
                        "description": "Intent classification result",
                        "updates": "PM-9-1",
                        "source": source,
                        "source_kind": "operation_result",
                    }
                ],
            }
        ],
        "new_controlled_processes": [],
        "new_coordination_links": [],
        "modified_responsibilities": [],
        "dismissed_gaps": [],
    }


def _sp1_run(run_dir: Path, revision_reply: dict):
    client = setup_sp1_mock_client()
    client.set_response_for(CriticFindings, _findings().model_dump())
    client.set_response_for(RevisionDelta, revision_reply)
    result = run_sp1(
        llm_client=client,
        use_case_text=USE_CASE,
        risk_cards=make_risk_cards(),
        run_dir=run_dir,
    )
    manifest = yaml.safe_load((run_dir / "run-manifest.yaml").read_text())
    return result, manifest


# ``sensor`` is neither a reference type nor a source kind: nothing repairs it.
_UNKNOWN_SOURCE_TYPE = _revision_reply({"type": "sensor", "id": "classifier"})

_DISCARDED = (
    "stage_2/critic_revision: the critic revision was discarded and the "
    "reviewed control structure was published instead: "
)


def test_a_discarded_revision_is_a_stage_warning_and_a_manifest_record(tmp_path):
    result, manifest = _sp1_run(tmp_path, _UNKNOWN_SOURCE_TYPE)

    assert result.stage_errors == []
    assert result.revised is False
    [warning] = [w for w in result.stage_warnings if w.startswith(_DISCARDED)]
    reason = warning.removeprefix(_DISCARDED)
    assert reason.startswith("Revision failed: ValidationError:")
    assert "feedback_channels.0.source.type" in reason
    assert "input_value='sensor'" in reason
    assert reason in result.post_revision_warnings
    assert manifest["stage_summary"]["stage_2"]["critic_revision"] == {
        "status": "discarded",
        "reason": reason,
    }
    assert warning in manifest["stage_warnings"]
    published = read_yaml(tmp_path / "control-structure.yaml", ControlStructure)
    assert "Classify the intent of each customer message" not in [
        resp.description
        for resp in published.responsibilities  # type: ignore[attr-defined]
    ]


def test_an_applied_revision_is_recorded_without_a_warning(tmp_path):
    result, manifest = _sp1_run(
        tmp_path, _revision_reply({"type": "responsibility", "id": "RESP-1"})
    )

    record = manifest["stage_summary"]["stage_2"]["critic_revision"]
    assert record == {"status": "applied"}
    assert result.revised is True
    assert not [w for w in result.stage_warnings if w.startswith(_DISCARDED)]


def test_a_run_without_critic_gaps_records_no_revision(tmp_path):
    result = run_sp1(
        llm_client=setup_sp1_mock_client(),
        use_case_text=USE_CASE,
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    assert result.revised is False
    assert "critic_revision" not in manifest["stage_summary"]["stage_2"]


def test_the_final_manifest_keeps_the_discarded_revision_record(tmp_path):
    _, manifest = _sp1_run(tmp_path, _UNKNOWN_SOURCE_TYPE)
    record = copy.deepcopy(manifest["stage_summary"]["stage_2"]["critic_revision"])

    assert _preserved_stage_keys(tmp_path).critic_revision == record
    stage_summary = _manifest_stage_summary(tmp_path, _preserved_stage_keys(tmp_path))
    assert stage_summary["stage_2"]["critic_revision"] == record


def test_an_accepted_revision_without_changes_is_recorded_as_unchanged(tmp_path):
    reply = {
        "new_responsibilities": [],
        "new_controlled_processes": [],
        "new_coordination_links": [],
        "modified_responsibilities": [],
        "dismissed_gaps": ["The intent is already reported by the reply channel."],
    }

    result, manifest = _sp1_run(tmp_path, reply)

    assert result.revised is False
    assert manifest["stage_summary"]["stage_2"]["critic_revision"] == {
        "status": "unchanged"
    }
    assert not [w for w in result.stage_warnings if w.startswith(_DISCARDED)]

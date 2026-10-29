"""What Stage 2 is told, and keeps, about the results invoked operations return.

An observed operation that declares an output returns it to the
responsibility that invokes it.  The evidence records that fact and the
Stage 2 requests that model process-model variables and feedback name each
such operation.  What a result reports, where its information originates and
how far it can be trusted are the model's decisions: code adds no feedback
channel of its own, so an acknowledgement-only operation gains none and a
retrieval channel keeps the kind the model gave it.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    FeedbackSourceKind,
    ReferenceType,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    _CoordinationProviderEnvelope,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    build_target_evidence,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import (
    run_sp1_default,
    setup_sp1_mock_client,
    valid_empty_coordination_analysis_dict,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "miniocciai-baseline-rev2"

RESULT_INSTRUCTION = "return what they report to the responsibility that invokes them"


def _profile() -> ExecutionTargetProfile:
    return ExecutionTargetProfile.model_validate(
        json.loads((FIXTURES / "execution-target-profile.json").read_text())
    )


def _profile_with_outputs(**outputs: object) -> ExecutionTargetProfile:
    """The fixture profile with the named tools' ``output_schema`` replaced."""
    profile = _profile()
    tools = tuple(
        tool.model_copy(update={"output_schema": outputs[tool.name]})
        if tool.name in outputs
        else tool
        for tool in profile.inventory.tools
    )
    inventory = profile.inventory.model_copy(update={"tools": tools})
    return profile.model_copy(update={"inventory": inventory})


def test_a_declared_output_marks_the_operation_as_returning_a_result() -> None:
    profile = _profile_with_outputs(get_referral=None, get_education={})

    evidence = build_target_evidence(profile, None)

    assert evidence is not None
    returns = {item.name: item.returns_result for item in evidence.operations}
    # No declared output is not evidence of a result.
    assert returns["get_referral"] is False
    # An empty schema still declares an output, whatever its shape.
    assert returns["get_education"] is True
    assert returns["escalate_to_clinician"] is True


# Call 2b binds an acknowledgement-only operation (an escalation) with no
# channel from its target, and a retrieval whose channel the model classified
# as retrieved content.
_ACK_AND_RETRIEVAL = {
    "control_actions": [
        {
            "ca_id": "CA-1-1",
            "description": "Escalate the conversation to a clinician",
            "target": {"type": "controlled_process", "id": "CP-1"},
            "effect_kind": "tool_call",
            "temporality": "discrete",
            "operation": "escalate_to_clinician",
            "process_model_refs": ["PM-1-1"],
        },
        {
            "ca_id": "CA-1-2",
            "description": "Retrieve education material",
            "target": {"type": "controlled_process", "id": "CP-2"},
            "effect_kind": "tool_call",
            "temporality": "discrete",
            "operation": "get_education",
            "process_model_refs": ["PM-1-1"],
        },
    ],
    "feedback": [
        {
            "fb_id": "FB-1-1",
            "description": "Education text the retrieval returns",
            "updates": "PM-1-1",
            "source": {"type": "controlled_process", "id": "CP-2"},
            "source_kind": "retrieved_content",
        }
    ],
    "controlled_processes": [
        {"cp_id": "CP-1", "description": "Clinician escalation queue"},
        {"cp_id": "CP-2", "description": "Education library"},
    ],
}


def _run(tmp_path: Path, profile: ExecutionTargetProfile):
    client = setup_sp1_mock_client()
    client.set_response_for(ControlElementSet, _ACK_AND_RETRIEVAL)
    review = valid_empty_coordination_analysis_dict(
        constraint_ids=("SC-1", "SC-2"), action_ids=("CA-1-1", "CA-1-2")
    )
    for row in review["semantic_review"]["actions"]:
        row["effect_kind"] = "tool_call"
        row["rationale"] = "The action invokes an observed operation."
    client.set_response_for(CoordinationAnalysis, review)
    client.set_response_for(_CoordinationProviderEnvelope, review)
    result = run_sp1_default(
        client, tmp_path, target_evidence=build_target_evidence(profile, None)
    )
    assert result.control_structure is not None
    return result


def test_stage2_requests_name_the_operations_that_return_a_result(
    tmp_path: Path,
) -> None:
    _run(tmp_path, _profile_with_outputs(get_referral=None))

    rendered = {
        entry["step"]: entry["user_prompt_text"]
        for entry in read_calls_jsonl(tmp_path)
        if entry["step"]
        in {"call_2a_responsibilities", "call_2b_control_elements", "critic"}
    }
    assert set(rendered) == {
        "call_2a_responsibilities",
        "call_2b_control_elements",
        "critic",
    }
    for prompt in rendered.values():
        text = " ".join(prompt.split())
        assert RESULT_INSTRUCTION in text
        listed = text.split(RESULT_INSTRUCTION, 1)[1].split(".", 1)[0]
        assert "`operation:escalate_to_clinician`" in listed
        assert "`operation:get_education`" in listed
        assert "operation:get_referral" not in listed


def test_code_adds_no_feedback_for_an_acknowledgement_or_a_retrieval(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path, _profile())

    published = ControlStructure.model_validate(
        yaml.safe_load((tmp_path / "control-structure.yaml").read_text())
    )
    for structure in (result.control_structure, published):
        (resp,) = structure.responsibilities
        assert [pm.pm_id for pm in resp.process_model_parts] == ["PM-1-1"]
        assert [
            (fb.fb_id, fb.source.id, fb.source_kind) for fb in resp.feedback_channels
        ] == [("FB-1-1", "CP-2", FeedbackSourceKind.retrieved_content)]
        # The escalation's target still sends no feedback: whether its
        # acknowledgement reports anything is the model's call, not code's.
        assert not any(
            fb.source.type is ReferenceType.controlled_process
            and fb.source.id == "CP-1"
            for fb in resp.feedback_channels
        )

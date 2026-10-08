"""Stage 5 validation issues: typed codes drive the correction feedback."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError, model_validator

from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    ExactFeedbackError,
    call_with_policy,
    compact_validation_error,
)
from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    _condition_omitted_reason,
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.issues import (
    CONDITION_FAILURE_CODES,
    ExactIssueError,
    IssueCode,
    ValidationIssue,
    ValidationIssueError,
    issues_of,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.validate import (
    _nearest_supplied_parent,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.helpers.normal_authoring_wire import (
    _normal_payload,
    _target_operation,
    _wrong_timing_context,
)
from tests.helpers.stage5_safe_outcome import (
    _command_attempt_payload,
    _nested_observations,
)

RECORD_CODE = IssueCode.safe_outcome_record_ref_not_supplied


class _Payload(BaseModel):
    value: int

    @model_validator(mode="after")
    def reject(self) -> "_Payload":
        raise ValidationIssueError(IssueCode.mechanism_source_mismatch, "inside")


def test_issue_error_text_is_the_code_then_the_detail() -> None:
    error = ValidationIssueError(IssueCode.intention_handle_undeclared, "cause_2")

    assert str(error) == "intention_handle_undeclared: cause_2"
    assert isinstance(error, ValueError)
    assert error.issue == ValidationIssue(
        IssueCode.intention_handle_undeclared, "cause_2"
    )


def test_exact_issue_error_keeps_the_exact_feedback_rendering() -> None:
    error = ExactIssueError(IssueCode.discriminating_condition_check_failed, "a\n- b")

    assert isinstance(error, ExactFeedbackError)
    assert compact_validation_error(error).startswith(
        "ValueError: discriminating_condition_check_failed: a\n- b"
    )


def test_issues_of_reads_a_direct_error() -> None:
    error = ValidationIssueError(RECORD_CODE, "X")

    assert issues_of(error) == (ValidationIssue(RECORD_CODE, "X"),)


def test_issues_of_reads_an_error_a_model_validator_raised() -> None:
    with pytest.raises(ValidationError) as caught:
        _Payload(value=1)

    assert issues_of(caught.value) == (
        ValidationIssue(IssueCode.mechanism_source_mismatch, "inside"),
    )


@pytest.mark.parametrize("error", (None, ValueError("plain"), KeyError("k")))
def test_issues_of_ignores_an_error_without_a_code(error) -> None:
    assert issues_of(error) == ()


def test_a_callable_feedback_is_rendered_from_the_error(tmp_path) -> None:
    prompts: list[str] = []

    class Client:
        model = "m"

        def complete(self, **kwargs):
            from asago_scenario_generator.stpa.infra.llm import LLMResult

            prompts.append(kwargs["user_prompt"])
            return LLMResult(
                content='{"value": 1}',
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
            )

    seen: list[BaseException] = []

    def feedback(error: Exception) -> str:
        seen.append(error)
        return f" FEEDBACK[{type(error).__name__}]"

    outcome = call_with_policy(
        llm_client=Client(),
        system_prompt="s",
        user_prompt="u",
        response_format=_Payload,
        run_dir=tmp_path,
        stage="st",
        step="sp",
        policy=CorrectionPolicy(validation_retries=1, feedback=feedback),
    )

    assert outcome.value is None
    assert [type(item) for item in seen] == [ValidationError]
    assert prompts[1].startswith("u FEEDBACK[ValidationError]")
    assert isinstance(outcome.failure, ValidationError)
    assert issues_of(outcome.failure) == (
        ValidationIssue(IssueCode.mechanism_source_mismatch, "inside"),
    )


def test_condition_note_names_the_code_the_final_attempt_raised() -> None:
    missing = (ValidationIssue(IssueCode.discriminating_condition_missing, "x"),)
    failed = (ValidationIssue(IssueCode.discriminating_condition_check_failed, "x"),)

    assert "(discriminating_condition_missing)" in _condition_omitted_reason(missing)
    assert "(discriminating_condition_check_failed)" in _condition_omitted_reason(
        failed
    )
    assert "(discriminating_condition_invalid)" in _condition_omitted_reason(())


@pytest.mark.parametrize("code", CONDITION_FAILURE_CODES)
def test_condition_note_names_each_condition_failure_code(code) -> None:
    note = _condition_omitted_reason((ValidationIssue(code, "x"),))

    assert f"({code.value})" in note


def test_condition_note_prefers_a_missing_condition_to_a_failed_one() -> None:
    raised = (
        ValidationIssue(IssueCode.discriminating_condition_operand_mismatch, "x"),
        ValidationIssue(IssueCode.discriminating_condition_missing, "x"),
    )

    assert "(discriminating_condition_missing)" in _condition_omitted_reason(raised)


def test_condition_note_ignores_a_code_quoted_in_unrelated_prose() -> None:
    """Only a raised issue picks the code; prose that mentions one does not."""
    unrelated = (
        ValidationIssue(
            IssueCode.no_content_surface, "discriminating_condition_missing"
        ),
    )

    assert "(discriminating_condition_invalid)" in _condition_omitted_reason(unrelated)


def _generate(tmp_path, payload, **kwargs):
    client = MockLLMClient()
    client.set_response_queue([payload, payload])
    result = generate_bdi_for_context(
        client,
        _wrong_timing_context(),
        tmp_path,
        observation_contract=default_observation_contract(),
        **kwargs,
    )
    return client, result


def test_correction_lists_only_the_code_that_was_raised(tmp_path) -> None:
    payload = _command_attempt_payload(["TARGET-STATE.not_supplied"], [])

    client, (result, error) = _generate(
        tmp_path,
        payload,
        target_operation=_target_operation(),
        target_observations=_nested_observations(),
    )

    assert result is None
    retry_prompt = client.calls[1].user_prompt
    assert "- safe_outcome_record_ref_not_supplied:" in retry_prompt
    for code in IssueCode:
        if code is not RECORD_CODE:
            assert f"- {code.value}:" not in retry_prompt
    assert "observation_ref values (TARGET-STATE)" in retry_prompt
    assert "Available causal handles are cause_1" in retry_prompt
    assert "Return one complete corrected provider response." in retry_prompt


def test_an_unsupplied_fact_ref_names_its_nearest_supplied_parent(tmp_path) -> None:
    payload = _command_attempt_payload(
        ["TARGET-STATE"],
        ["TARGET-STATE.widgets.W-2.widget_id", "TARGET-STATE.order_id"],
    )

    client, (result, error) = _generate(
        tmp_path,
        payload,
        target_operation=_target_operation(),
        target_observations=_nested_observations(),
    )

    assert result is None
    assert "safe_outcome_fact_ref_not_supplied:" in error
    retry_prompt = client.calls[1].user_prompt
    assert "- safe_outcome_fact_ref_not_supplied:" in retry_prompt
    assert (
        "- `TARGET-STATE.widgets.W-2.widget_id` is not supplied; the nearest "
        "supplied path is `TARGET-STATE.widgets.W-2` (object)"
    ) in retry_prompt
    assert "`TARGET-STATE.order_id` is not supplied" not in retry_prompt


def test_an_unsupplied_fact_ref_under_an_unsupplied_record_has_no_parent(
    tmp_path,
) -> None:
    payload = _command_attempt_payload([], ["OTHER-STATE.order_id"])

    client, (result, error) = _generate(
        tmp_path,
        payload,
        target_operation=_target_operation(),
        target_observations=_nested_observations(),
    )

    assert result is None
    retry_prompt = client.calls[1].user_prompt
    assert (
        "- `OTHER-STATE.order_id` is not supplied; no supplied path contains it"
    ) in retry_prompt


def test_an_adversary_without_intentions_raises_its_own_code(tmp_path) -> None:
    payload = _command_attempt_payload([], [])
    payload["attacker_bdi"]["intentions"] = []

    client, (result, error) = _generate(
        tmp_path,
        payload,
        target_operation=_target_operation(),
        target_observations=_nested_observations(),
    )

    assert result is None
    assert "attacker_intentions_missing:" in error
    assert "- attacker_intentions_missing:" in client.calls[1].user_prompt


def test_an_observable_safe_outcome_without_a_claim_raises_its_own_code(
    tmp_path,
) -> None:
    payload = _command_attempt_payload([], [])
    payload["unsafe_outcome"]["safe_observable_outcome"].update(
        claim_level=None, evidence=None, operation_name=None
    )

    client, (result, error) = _generate(
        tmp_path,
        payload,
        target_operation=_target_operation(),
        target_observations=_nested_observations(),
    )

    assert result is None
    assert "observable safe outcomes require claim_level and evidence" in error
    retry_prompt = client.calls[1].user_prompt
    assert "- safe_outcome_claim_missing:" in retry_prompt


def test_an_unknown_operation_name_raises_its_own_code(tmp_path) -> None:
    payload = _command_attempt_payload([], [])
    payload["unsafe_outcome"]["observation_criteria"][0]["operation_name"] = (
        "wire_money"
    )

    client, (result, error) = _generate(
        tmp_path,
        payload,
        target_operation=_target_operation(),
        target_observations=_nested_observations(),
    )

    assert result is None
    assert "observation_operation_not_in_inventory:" in error
    retry_prompt = client.calls[1].user_prompt
    assert "- observation_operation_not_in_inventory:" in retry_prompt
    assert "- observation_command_attempt_operation_missing:" not in retry_prompt


def test_a_missing_command_attempt_operation_raises_its_own_code(tmp_path) -> None:
    payload = _command_attempt_payload([], [])
    payload["unsafe_outcome"]["observation_criteria"][0]["operation_name"] = None

    client, (result, error) = _generate(
        tmp_path,
        payload,
        target_operation=_target_operation(),
        target_observations=_nested_observations(),
    )

    assert result is None
    assert "observation_command_attempt_operation_missing:" in error
    retry_prompt = client.calls[1].user_prompt
    assert "- observation_command_attempt_operation_missing:" in retry_prompt
    assert "- observation_operation_not_in_inventory:" not in retry_prompt


def test_a_safe_outcome_that_matches_no_criterion_raises_the_mismatch_code(
    tmp_path,
) -> None:
    payload = _command_attempt_payload([], [])
    reply = {
        "criterion_id": "reply",
        "outcome": "The assistant reply breaks the required policy.",
        "observable": True,
        "claim_level": "reply",
        "evidence": "assistant_message",
        "reason": "The runtime captures assistant messages.",
    }
    # Two supported criteria leave the safe outcome uncoerced.
    payload["unsafe_outcome"]["observation_criteria"] = [
        reply,
        {**reply, "criterion_id": "reply_two"},
    ]
    payload["unsafe_outcome"].pop("discriminating_condition", None)

    client, (result, error) = _generate(tmp_path, payload)

    assert result is None
    assert "safe_outcome_observability_mismatch:" in error
    assert "claim level and evidence must match" in error
    retry_prompt = client.calls[1].user_prompt
    assert "- safe_outcome_observability_mismatch:" in retry_prompt


@pytest.mark.parametrize(
    ("edit", "code"),
    (
        (
            lambda payload: payload["causal_factors"][0].update(
                temporal_condition={
                    "type": "delay",
                    "reference_handle": "target_action",
                }
            ),
            IssueCode.missing_temporal_branch_field,
        ),
        (
            lambda payload: payload["causal_factors"][0].update(
                evidence_status="reachable_capability"
            ),
            IssueCode.incomplete_evidence_status_branch,
        ),
        (
            lambda payload: payload["unsafe_outcome"].update(semantic_proposition=""),
            IssueCode.missing_unsafe_proposition,
        ),
    ),
    ids=("temporal", "evidence-status", "proposition"),
)
def test_a_schema_failure_on_a_guided_field_names_that_code(
    tmp_path, edit, code
) -> None:
    payload = _normal_payload()
    edit(payload)

    client, (result, error) = _generate(tmp_path, payload)

    assert result is None
    retry_prompt = client.calls[1].user_prompt
    assert f"- {code.value}:" in retry_prompt
    for other in IssueCode:
        if other is not code:
            assert f"- {other.value}:" not in retry_prompt


@pytest.mark.parametrize(
    ("location", "code"),
    (
        (
            ("causal_factors", 0, "temporal_condition"),
            IssueCode.missing_temporal_branch_field,
        ),
        (
            ("causal_factors", 0, "evidence_status"),
            IssueCode.incomplete_evidence_status_branch,
        ),
        (
            ("causal_factors", 0, "capability_refs"),
            IssueCode.incomplete_evidence_status_branch,
        ),
        (
            ("unsafe_outcome", "semantic_proposition"),
            IssueCode.missing_unsafe_proposition,
        ),
    ),
)
def test_issues_of_classifies_a_schema_error_by_the_field_it_names(
    location, code
) -> None:
    error = ValidationError.from_exception_data(
        "Draft", [{"type": "missing", "loc": location, "input": {}}]
    )

    assert [issue.code for issue in issues_of(error)] == [code]


def test_issues_of_leaves_an_unguided_schema_error_without_a_code() -> None:
    error = ValidationError.from_exception_data(
        "Draft", [{"type": "missing", "loc": ("adversary",), "input": {}}]
    )

    assert issues_of(error) == ()


def test_a_failure_without_a_code_gets_no_code_lines(tmp_path) -> None:
    payload = _normal_payload()
    del payload["adversary"]

    client, (result, error) = _generate(tmp_path, payload)

    assert result is None
    retry_prompt = client.calls[1].user_prompt
    assert "Stable repair codes" not in retry_prompt
    assert "Correct only the fields identified by the validation error" in retry_prompt
    assert "Return one complete corrected provider response." in retry_prompt


@pytest.mark.parametrize(
    ("value", "name"),
    (
        ({"a": 1}, "object"),
        ([1], "array"),
        (True, "boolean"),
        (2.5, "number"),
        ("x", "string"),
        (None, "null"),
        (object(), "ambiguous"),
    ),
)
def test_a_parent_fact_is_named_by_its_json_type(value, name) -> None:
    assert (
        _nearest_supplied_parent("A.b.c", {"A.b": value}, {"A"})
        == f"`A.b.c` is not supplied; the nearest supplied path is `A.b` ({name})"
    )


def test_a_supplied_record_is_the_parent_of_last_resort() -> None:
    assert _nearest_supplied_parent("A.b.c", {}, {"A"}) == (
        "`A.b.c` is not supplied; the nearest supplied path is `A` (record)"
    )

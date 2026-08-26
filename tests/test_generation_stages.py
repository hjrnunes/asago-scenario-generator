"""Typed single-attempt generation seam tests for cmps.5 phase 1."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from asago_scenario_generator.llm.client import LLMResult
from asago_scenario_generator.models.projection_envelope import (
    ProjectionTraceabilityResult,
)
from asago_scenario_generator.models.scenario import CallName
from asago_scenario_generator.pipeline.finalization import (
    GeneratedArtifacts,
    GeneratedStage,
    StageInvocation,
    make_assertions_only_behavior_callback,
)
from asago_scenario_generator.pipeline.generate import generate_scenario
from asago_scenario_generator.pipeline.generate.stages import (
    BehaviorStageResult,
    GenerationRequest,
    PreparedGeneration,
    RetryDirective,
    StageAttemptFailure,
    generate_actor_stage,
    generate_behavior_stage,
    generate_narrative_stage,
    generate_tree_stage,
    prepare_generation,
)
from asago_scenario_generator.pipeline.generation_contracts import CausalRetryControl
from asago_scenario_generator.pipeline.generate.tree_semantics import (
    CanonicalCompilationError,
    DraftValidation,
    InvalidSemanticDraft,
    ProjectionInfeasible,
)
from tests.helpers.projection_factory import (
    get_projected_candidate,
    get_test_snapshot,
)


def _result() -> LLMResult:
    return LLMResult(
        content="fixture",
        prompt_tokens=1,
        completion_tokens=1,
        duration_ms=1,
        system_prompt="system",
        user_prompt="user",
    )


def _prepared() -> PreparedGeneration:
    request = GenerationRequest(
        seed=cast(Any, object()),
        profile=cast(Any, object()),
        client=cast(Any, MagicMock(model="test-model")),
        use_case="test",
        pinned_entry_point_id="ep:v1:test",
        projected_candidate=cast(Any, object()),
        capability_snapshot=cast(Any, object()),
        run_id="20260101T000000_0123456789abcdef0123456789abcdef",
    )
    return PreparedGeneration(request, "cand:v2:test", "scenario:v2:test", {"x": 1})


def test_prepare_generation_runs_tree_realizability_before_provider_calls() -> None:
    candidate = get_projected_candidate()
    snapshot = get_test_snapshot()
    request = GenerationRequest(
        seed=cast(Any, MagicMock(threat_id="T2")),
        profile=snapshot.profile,
        client=cast(Any, MagicMock(model="test-model")),
        use_case="test",
        pinned_entry_point_id=candidate.canonical_ingress.entry_point_id,
        projected_candidate=candidate,
        capability_snapshot=snapshot,
        run_id="20260101T000000_0123456789abcdef0123456789abcdef",
    )

    with (
        patch(
            "asago_scenario_generator.pipeline.generate.tree_semantics."
            "validate_tree_projection_realizability",
            side_effect=ProjectionInfeasible("unrepresentable projection"),
        ) as validate,
        pytest.raises(ProjectionInfeasible, match="unrepresentable projection"),
    ):
        prepare_generation(request)

    validate.assert_called_once()


def test_each_stage_delegates_to_exactly_one_call_primitive() -> None:
    prepared = _prepared()
    actor = cast(Any, object())
    narrative = cast(Any, object())
    tree = cast(Any, object())
    behavior = cast(Any, object())

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_actor_profile",
            return_value=(actor, _result(), None),
        ) as call0,
        patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            return_value=(narrative, _result()),
        ) as call1,
        patch(
            "asago_scenario_generator.pipeline.generate._call_attack_tree_once",
            return_value=(tree, _result()),
        ) as call2,
        patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            return_value=(behavior, _result()),
        ) as call3,
    ):
        actor_result = generate_actor_stage(prepared)
        narrative_result = generate_narrative_stage(prepared, actor)
        tree_result = generate_tree_stage(prepared, actor, narrative)
        behavior_result = generate_behavior_stage(prepared, narrative, tree)

    assert actor_result.artifact is actor
    assert narrative_result.artifact is narrative
    assert tree_result.artifact is tree
    assert behavior_result.artifact is behavior
    assert [
        actor_result.evidence.call_name,
        narrative_result.evidence.call_name,
        tree_result.evidence.call_name,
        behavior_result.evidence.call_name,
    ] == list(CallName)
    for primitive in (call0, call1, call2, call3):
        primitive.assert_called_once()


def test_semantic_stages_apply_bounded_operation_completion_caps() -> None:
    prepared = _prepared()
    prepared.request.client.max_completion_tokens = None
    actor = cast(Any, object())
    narrative = cast(Any, object())
    tree = cast(Any, object())
    behavior = cast(Any, object())

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_actor_profile",
            return_value=(actor, _result(), None),
        ) as call0,
        patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            return_value=(narrative, _result()),
        ) as call1,
        patch(
            "asago_scenario_generator.pipeline.generate._call_attack_tree_once",
            return_value=(tree, _result()),
        ) as call2,
        patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            return_value=(behavior, _result()),
        ) as call3,
    ):
        generate_actor_stage(prepared)
        generate_narrative_stage(prepared, actor)
        generate_tree_stage(prepared, actor, narrative)
        generate_behavior_stage(prepared, narrative, tree)

    assert call0.call_args.kwargs["max_completion_tokens"] == 4096
    assert call1.call_args.kwargs["max_completion_tokens"] == 8192
    assert call2.call_args.kwargs["max_completion_tokens"] == 8192
    assert call3.call_args.kwargs["max_completion_tokens"] == 4096


def test_semantic_stage_caps_never_raise_a_lower_operator_transport_cap() -> None:
    prepared = _prepared()
    prepared.request.client.max_completion_tokens = 2048
    actor = cast(Any, object())
    narrative = cast(Any, object())
    tree = cast(Any, object())
    behavior = cast(Any, object())

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_actor_profile",
            return_value=(actor, _result(), None),
        ) as call0,
        patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            return_value=(narrative, _result()),
        ) as call1,
        patch(
            "asago_scenario_generator.pipeline.generate._call_attack_tree_once",
            return_value=(tree, _result()),
        ) as call2,
        patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            return_value=(behavior, _result()),
        ) as call3,
    ):
        generate_actor_stage(prepared)
        generate_narrative_stage(prepared, actor)
        generate_tree_stage(prepared, actor, narrative)
        generate_behavior_stage(prepared, narrative, tree)

    assert {
        call0.call_args.kwargs["max_completion_tokens"],
        call1.call_args.kwargs["max_completion_tokens"],
        call2.call_args.kwargs["max_completion_tokens"],
        call3.call_args.kwargs["max_completion_tokens"],
    } == {2048}


def test_narrative_length_retry_uses_the_smaller_retry_operation_cap() -> None:
    prepared = _prepared()
    prepared.request.client.max_completion_tokens = None
    actor = cast(Any, object())
    narrative = cast(Any, object())
    retry = RetryDirective(
        feedback="be concise",
        reason="completion_length",
        causal_control=CausalRetryControl(
            control_id="stage-specific-completion-cap",
            field="max_completion_tokens",
            initial_value=8192,
            retry_value=4096,
        ),
    )

    with patch(
        "asago_scenario_generator.pipeline.generate._call_narrative",
        return_value=(narrative, _result()),
    ) as call1:
        generate_narrative_stage(prepared, actor, retry)

    assert call1.call_args.kwargs["max_completion_tokens"] == 4096


def test_finalization_behavior_port_invokes_call3_once_with_final_tree_copy() -> None:
    prepared = _prepared()
    candidate = MagicMock(candidate_id=prepared.candidate_id)
    narrative = object()
    final_tree_copy = object()
    behavior = object()
    evidence = object()
    invocation = StageInvocation(
        candidate_id=prepared.candidate_id,
        stage=GeneratedStage.behavior,
        invocation_index=0,
        owner_retry_index=0,
        artifacts=GeneratedArtifacts(narrative=narrative, tree=final_tree_copy),
        final_tree_digest="verified-digest",
    )

    with patch(
        "asago_scenario_generator.pipeline.generate.stages.generate_behavior_stage",
        return_value=BehaviorStageResult(behavior, evidence),
    ) as call3:
        result = make_assertions_only_behavior_callback(prepared)(candidate, invocation)

    call3.assert_called_once_with(prepared, narrative, final_tree_copy, None)
    assert result.artifact is behavior
    assert result.evidence is evidence


def test_behavior_port_forwards_the_retry_directive_to_call3() -> None:
    prepared = _prepared()
    candidate = MagicMock(candidate_id=prepared.candidate_id)
    narrative = object()
    final_tree_copy = object()
    behavior = object()
    evidence = object()
    invocation = StageInvocation(
        candidate_id=prepared.candidate_id,
        stage=GeneratedStage.behavior,
        invocation_index=1,
        owner_retry_index=0,
        artifacts=GeneratedArtifacts(narrative=narrative, tree=final_tree_copy),
        final_tree_digest="verified-digest",
        retry_feedback="approved suffix",
        retry_reason="completion_length",
    )

    with patch(
        "asago_scenario_generator.pipeline.generate.stages.generate_behavior_stage",
        return_value=BehaviorStageResult(behavior, evidence),
    ) as call3:
        result = make_assertions_only_behavior_callback(prepared)(candidate, invocation)

    directive = call3.call_args.args[3]
    assert directive.feedback == "approved suffix"
    assert directive.reason == "completion_length"
    assert result.artifact is behavior
    assert result.evidence is evidence


def test_behavior_port_rejects_invalid_invocations() -> None:
    prepared = _prepared()
    candidate = MagicMock(candidate_id=prepared.candidate_id)
    port = make_assertions_only_behavior_callback(prepared)

    with pytest.raises(ValueError, match="requires behavior stage"):
        port(
            candidate,
            StageInvocation(
                candidate_id=prepared.candidate_id,
                stage=GeneratedStage.actor,
                invocation_index=0,
                owner_retry_index=0,
                artifacts=GeneratedArtifacts(),
            ),
        )
    with pytest.raises(ValueError, match="differs from prepared projection"):
        port(
            MagicMock(candidate_id="other"),
            StageInvocation(
                candidate_id="other",
                stage=GeneratedStage.behavior,
                invocation_index=0,
                owner_retry_index=0,
                artifacts=GeneratedArtifacts(),
            ),
        )
    with pytest.raises(ValueError, match="verified final-tree"):
        port(
            candidate,
            StageInvocation(
                candidate_id=prepared.candidate_id,
                stage=GeneratedStage.behavior,
                invocation_index=0,
                owner_retry_index=0,
                artifacts=GeneratedArtifacts(narrative=object()),
            ),
        )
    for artifacts, final_tree_digest in (
        (GeneratedArtifacts(narrative=object(), tree=object()), None),
        (GeneratedArtifacts(narrative=object()), "verified-digest"),
    ):
        with patch(
            "asago_scenario_generator.pipeline.generate.stages.generate_behavior_stage"
        ) as call3:
            with pytest.raises(ValueError, match="verified final-tree"):
                port(
                    candidate,
                    StageInvocation(
                        candidate_id=prepared.candidate_id,
                        stage=GeneratedStage.behavior,
                        invocation_index=0,
                        owner_retry_index=0,
                        artifacts=artifacts,
                        final_tree_digest=final_tree_digest,
                    ),
                )
            call3.assert_not_called()


def test_stage_attempt_failure_normalizes_completion_length_evidence() -> None:
    from asago_scenario_generator.llm.client import CompletionLengthError
    from asago_scenario_generator.pipeline.generate.stages import (
        stage_attempt_failure,
    )

    failure = stage_attempt_failure(
        CallName.actor_profile,
        CompletionLengthError(prompt_tokens=31, completion_tokens=16),
        phase="invocation",
        invoked=True,
    )

    assert failure.code == StageAttemptFailure.COMPLETION_LENGTH_CODE
    assert failure.finish_reason == "length"
    assert failure.prompt_tokens == 31
    assert failure.completion_tokens == 16


def test_stage_attempt_failure_retains_redacted_length_diagnostics() -> None:
    from asago_scenario_generator.llm.client import CompletionLengthError
    from asago_scenario_generator.pipeline.generate.stages import (
        stage_attempt_failure,
    )

    exception = CompletionLengthError(
        prompt_tokens=31,
        completion_tokens=16,
        total_tokens=47,
        usage_details={
            "prompt_tokens": 31,
            "completion_tokens": 16,
            "total_tokens": 47,
            "prompt_tokens_details": {"cached_tokens": 3},
            "completion_tokens_details": {"reasoning_tokens": 5},
        },
        response_id="fixture-response-001",
        model="fixture-model-v1",
        partial_character_count=8,
        partial_sha256="a" * 64,
        partial_preview_prefix="[REDACTED]",
        partial_preview_suffix="[REDACTED]",
        elapsed_ms=4,
    )

    failure = stage_attempt_failure(
        CallName.actor_profile,
        exception,
        phase="invocation",
        invoked=True,
    )

    assert failure.total_tokens == 47
    assert failure.usage_details["completion_tokens_details"]["reasoning_tokens"] == 5
    assert failure.response_id == "fixture-response-001"
    assert failure.model == "fixture-model-v1"
    assert failure.partial_character_count == 8
    assert failure.partial_sha256 == "a" * 64
    assert failure.partial_preview_prefix == "[REDACTED]"
    assert failure.partial_preview_suffix == "[REDACTED]"
    assert failure.elapsed_ms == 4


def test_retry_directive_is_data_not_hidden_control_flow() -> None:
    prepared = _prepared()
    actor = cast(Any, object())
    with patch(
        "asago_scenario_generator.pipeline.generate._call_actor_profile",
        return_value=(actor, _result(), "limited"),
    ) as primitive:
        result = generate_actor_stage(
            prepared,
            RetryDirective(feedback="repair evidence", forced_actor_type="external"),
        )

    primitive.assert_called_once()
    assert primitive.call_args.kwargs["access_feedback"] == "repair evidence"
    assert primitive.call_args.kwargs["forced_actor_type"] == "external"
    assert result.diversity_limitation == "limited"


def test_completion_length_retry_feedback_uses_only_the_length_channel() -> None:
    prepared = _prepared()
    actor = cast(Any, object())
    narrative = cast(Any, object())
    tree = cast(Any, object())
    behavior = cast(Any, object())
    suffix = "approved length-retry suffix"
    retry = RetryDirective(feedback=suffix, reason="completion_length")

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_actor_profile",
            return_value=(actor, _result(), None),
        ) as call0,
        patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            return_value=(narrative, _result()),
        ) as call1,
        patch(
            "asago_scenario_generator.pipeline.generate._call_attack_tree_once",
            return_value=(tree, _result()),
        ) as call2,
        patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            return_value=(behavior, _result()),
        ) as call3,
    ):
        generate_actor_stage(prepared, retry)
        generate_narrative_stage(prepared, actor, retry)
        generate_tree_stage(prepared, actor, narrative, retry)
        generate_behavior_stage(prepared, narrative, tree, retry)

    for primitive in (call0, call1, call2, call3):
        assert primitive.call_args.kwargs["completion_length_feedback"] == suffix
    assert call0.call_args.kwargs["access_feedback"] is None
    assert call1.call_args.kwargs["realization_feedback"] is None
    assert call2.call_args.kwargs["consistency_feedback"] is None


def test_tree_post_response_rejection_retains_truthful_attempt_evidence() -> None:
    prepared = _prepared()
    prepared.request.client.complete.return_value = _result()

    def reject_after_response(seed, narrative, client, use_case, **kwargs):
        client.complete(
            system_prompt="tree system",
            user_prompt="tree user",
            response_format=None,
        )
        raise ValueError("tree parse rejected")

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_attack_tree_once",
            side_effect=reject_after_response,
        ),
        pytest.raises(StageAttemptFailure) as raised,
    ):
        generate_tree_stage(prepared, cast(Any, object()), cast(Any, object()))

    failure = raised.value
    prepared.request.client.complete.assert_called_once()
    assert failure.call_name is CallName.attack_tree
    assert failure.phase == "post_response"
    assert failure.invoked is True
    assert failure.system_prompt == "tree system"
    assert failure.user_prompt == "tree user"
    assert failure.result is prepared.request.client.complete.return_value
    assert failure.raw_response == "fixture"


def test_call3_semantic_rejection_retains_truthful_attempt_evidence() -> None:
    prepared = _prepared()
    prepared.request.client.complete.return_value = _result()

    def reject_semantics(
        seed, narrative, tree, profile, client, use_case, tag, **kwargs
    ):
        client.complete(
            system_prompt="call3 system",
            user_prompt="call3 user",
            response_format=object,
        )
        raise ValueError("Call 3 semantic rejection")

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            side_effect=reject_semantics,
        ),
        pytest.raises(StageAttemptFailure) as raised,
    ):
        generate_behavior_stage(prepared, cast(Any, object()), cast(Any, object()))

    failure = raised.value
    prepared.request.client.complete.assert_called_once()
    assert failure.call_name is CallName.behavior_spec
    assert failure.phase == "post_response"
    assert failure.result is prepared.request.client.complete.return_value
    assert failure.raw_response is None
    assert failure.exception_type == "ValueError"


@pytest.mark.parametrize(
    ("stage", "exception", "expected_code", "expected_retryable"),
    [
        (
            "tree",
            ProjectionInfeasible("no canonical leaf"),
            "projection_infeasible",
            False,
        ),
        (
            "tree",
            InvalidSemanticDraft(DraftValidation(accepted=False)),
            "semantic_draft_invalid",
            True,
        ),
        (
            "behavior",
            CanonicalCompilationError("compiler invariant failed"),
            "canonical_compilation_failed",
            False,
        ),
    ],
)
def test_tree_and_behavior_stage_failures_preserve_typed_single_attempt_codes(
    stage: str,
    exception: Exception,
    expected_code: str,
    expected_retryable: bool,
) -> None:
    prepared = _prepared()
    prepared.request.client.complete.return_value = _result()

    def fail_after_one_call(*args, **kwargs):
        client = args[2] if stage == "tree" else args[4]
        client.complete(system_prompt="system", user_prompt="user")
        raise exception

    target = (
        "asago_scenario_generator.pipeline.generate._call_attack_tree_once"
        if stage == "tree"
        else "asago_scenario_generator.pipeline.generate._call_behavior_spec"
    )
    with (
        patch(target, side_effect=fail_after_one_call),
        pytest.raises(StageAttemptFailure) as raised,
    ):
        if stage == "tree":
            generate_tree_stage(prepared, cast(Any, object()), cast(Any, object()))
        else:
            generate_behavior_stage(prepared, cast(Any, object()), cast(Any, object()))

    assert prepared.request.client.complete.call_count == 1
    assert raised.value.code == expected_code
    assert raised.value.retryable is expected_retryable
    assert raised.value.phase == "post_response"


def test_behavior_provider_validation_error_is_typed_protocol_failure() -> None:
    from asago_scenario_generator.pipeline.generate.behavior_semantics import (
        BehaviorDraftV2,
    )

    prepared = _prepared()
    prepared.request.client.complete.return_value = _result()
    with pytest.raises(Exception) as invalid:
        BehaviorDraftV2.model_validate({})

    def reject_protocol(
        seed, narrative, tree, profile, client, use_case, tag, **kwargs
    ):
        client.complete(system_prompt="system", user_prompt="user")
        raise invalid.value

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            side_effect=reject_protocol,
        ),
        pytest.raises(StageAttemptFailure) as raised,
    ):
        generate_behavior_stage(prepared, cast(Any, object()), cast(Any, object()))

    assert prepared.request.client.complete.call_count == 1
    assert raised.value.code == "semantic_draft_protocol_failed"
    assert raised.value.retryable is True
    assert raised.value.phase == "post_response"


def test_client_exception_is_invoked_without_synthesized_response() -> None:
    prepared = _prepared()
    prepared.request.client.complete.side_effect = ConnectionError("transport down")

    def invoke(seed, narrative, tree, profile, client, use_case, tag, **kwargs):
        return client.complete(
            system_prompt="call3 system",
            user_prompt="call3 user",
            response_format=object,
        )

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            side_effect=invoke,
        ),
        pytest.raises(StageAttemptFailure) as raised,
    ):
        generate_behavior_stage(prepared, cast(Any, object()), cast(Any, object()))

    failure = raised.value
    prepared.request.client.complete.assert_called_once()
    assert failure.phase == "invocation"
    assert failure.invoked is True
    assert failure.result is None
    assert failure.raw_response is None
    assert failure.exception_type == "ConnectionError"


def test_generate_scenario_legacy_adapter_preserves_call_order_output_and_logs() -> (
    None
):
    order: list[CallName] = []
    actor = MagicMock(actor_type="cybercriminal", goal_category=None)
    narrative = MagicMock(
        title="Unique title",
        summary="Summary",
        steps=[],
        entry_point="chat",
        zone_sequence=["input"],
    )
    tree = MagicMock()
    behavior = MagicMock()
    envelope = MagicMock(scenario_id="scenario:v2:compatibility")

    def call0(*args, **kwargs):
        order.append(CallName.actor_profile)
        return actor, _result(), None

    def call1(*args, **kwargs):
        order.append(CallName.narrative)
        return narrative, _result()

    def call2(*args, **kwargs):
        order.append(CallName.attack_tree)
        return tree, _result()

    def call3(*args, **kwargs):
        order.append(CallName.behavior_spec)
        return behavior, _result()

    seed = MagicMock(
        seed_id="AP-T1-01",
        threat_id="T1",
        attack_pattern_name="Pattern",
        atlas_technique_ids=[],
    )
    profile = MagicMock(tool_inventory=[])
    client = MagicMock(model="test-model")

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_actor_profile",
            side_effect=call0,
        ),
        patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            side_effect=call1,
        ),
        patch(
            "asago_scenario_generator.pipeline.generate._call_attack_tree",
            side_effect=call2,
        ),
        patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            side_effect=call3,
        ),
        patch(
            "asago_scenario_generator.pipeline.generate._validate_actor_type",
            side_effect=lambda value: value,
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.validate_actor_access_provenance",
            return_value=[],
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.narrative.validate_narrative_access_realization",
            return_value=[],
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.assembly._check_consistency",
            return_value=[],
        ),
        patch(
            "asago_scenario_generator.pipeline.generate._warn_dominant_threat_id_crossref"
        ),
        patch(
            "asago_scenario_generator.pipeline.generate._assemble_envelope",
            return_value=envelope,
        ),
        patch(
            "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability",
            return_value=ProjectionTraceabilityResult(valid=True),
        ),
    ):
        actual_envelope, logs = generate_scenario(
            seed=seed,
            profile=profile,
            client=client,
            use_case="test",
            pinned_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            run_id="20260101T000000_0123456789abcdef0123456789abcdef",
            projected_candidate=get_projected_candidate(),
            capability_snapshot=get_test_snapshot(),
        )

    assert order == list(CallName)
    assert actual_envelope is envelope
    assert [entry["call"] for entry in logs] == [item.value for item in CallName]
    assert {entry["scenario_id"] for entry in logs} == {envelope.scenario_id}


class TestAssemblyCallLogEntryError:
    """Direct branch coverage for assembly._call_log_entry_error."""

    def test_error_entry_with_model_content(self):
        from pydantic import BaseModel

        from asago_scenario_generator.pipeline.generate.assembly import (
            _call_log_entry_error,
        )

        class _Payload(BaseModel):
            value: str

        result = LLMResult(
            content=_Payload(value="x"),
            prompt_tokens=3,
            completion_tokens=4,
            duration_ms=5,
            system_prompt="sys",
            user_prompt="usr",
        )
        entry = _call_log_entry_error(
            CallName.actor_profile, result, "scenario:v2:x", "boom"
        )
        assert entry["response"] == {"value": "x"}
        assert entry["error"] == "boom"
        assert entry["call"] == "actor_profile"
        assert entry["prompt_tokens"] == 3

    def test_error_entry_with_string_content(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _call_log_entry_error,
        )

        result = LLMResult(
            content="raw text",
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt="sys",
            user_prompt="usr",
        )
        entry = _call_log_entry_error(
            CallName.narrative, result, "scenario:v2:x", "nope"
        )
        assert entry["response"] == "raw text"
        assert entry["error"] == "nope"

    def test_error_entry_with_other_content(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _call_log_entry_error,
        )

        result = LLMResult(
            content=[1, 2],
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt="sys",
            user_prompt="usr",
        )
        entry = _call_log_entry_error(
            CallName.attack_tree, result, "scenario:v2:x", "bad"
        )
        assert entry["response"] == str([1, 2])

    def test_error_entry_without_result(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _call_log_entry_error,
        )

        entry = _call_log_entry_error(
            CallName.behavior_spec, None, "scenario:v2:x", "call raised"
        )
        assert entry == {
            "scenario_id": "scenario:v2:x",
            "call": "behavior_spec",
            "error": "call raised",
        }

    def test_serialize_call_raw_content_model(self):
        from pydantic import BaseModel

        from asago_scenario_generator.pipeline.generate.assembly import (
            _serialize_call_raw_content,
        )

        class _Payload(BaseModel):
            value: str

        assert _serialize_call_raw_content(_Payload(value="x")) == {"value": "x"}

    def test_serialize_call_raw_content_str(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _serialize_call_raw_content,
        )

        assert _serialize_call_raw_content("plain") == "plain"

    def test_serialize_call_raw_content_other(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _serialize_call_raw_content,
        )

        assert _serialize_call_raw_content([1, 2]) == str([1, 2])


class TestGenerateCompatibilityHelpers:
    """Branch-level coverage for _generate_scenario_compatibility runners."""

    @staticmethod
    def _seed(threat_id: str = "T1") -> MagicMock:
        return MagicMock(
            seed_id="AP-T1-01",
            threat_id=threat_id,
            threat_name="T",
            attack_pattern_name="Pattern",
            attack_pattern_description="Desc",
            atlas_technique_ids=["AML.T0001"],
        )

    @staticmethod
    def _actor(actor_type: str = "cybercriminal") -> MagicMock:
        actor = MagicMock(actor_type=actor_type)
        actor.goal_category = None
        return actor

    @staticmethod
    def _result() -> LLMResult:
        return LLMResult(
            content="x",
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt="s",
            user_prompt="u",
        )

    def test_apply_adversarial_actor_filter_appends(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _apply_adversarial_actor_filter,
        )

        excluded = _apply_adversarial_actor_filter(self._seed("T3"), None)
        assert excluded == ["negligent-insider"]

    def test_apply_adversarial_actor_filter_preserves_existing(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _apply_adversarial_actor_filter,
        )

        excluded = _apply_adversarial_actor_filter(
            self._seed("T3"), ["cybercriminal", "negligent-insider"]
        )
        assert excluded == ["cybercriminal", "negligent-insider"]

    def test_apply_adversarial_actor_filter_unrelated_threat(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _apply_adversarial_actor_filter,
        )

        original = ["cybercriminal"]
        assert _apply_adversarial_actor_filter(self._seed("T1"), original) is original

    def test_record_diversity_limitation(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _record_diversity_limitation,
        )

        notes: list[str] = []
        _record_diversity_limitation(notes, "forced actor 'x'")
        assert len(notes) == 1
        assert "forced actor 'x'" in notes[0]

    def test_record_diversity_limitation_none(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _record_diversity_limitation,
        )

        notes: list[str] = []
        _record_diversity_limitation(notes, None)
        assert notes == []

    def test_apply_goal_category(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _apply_goal_category,
        )

        actor = self._actor()
        _apply_goal_category(
            actor, {"id": "g1", "name": "Goal", "category_name": "Cat"}
        )
        assert actor.goal_category == "g1"
        assert actor.goal_category_name == "Goal"
        assert actor.goal_category_parent == "Cat"

    def test_apply_goal_category_none(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _apply_goal_category,
        )

        actor = self._actor()
        _apply_goal_category(actor, None)
        assert actor.goal_category is None

    def test_run_call0_success(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _run_call0,
        )

        actor = self._actor()
        with patch(
            "asago_scenario_generator.pipeline.generate._call_actor_profile",
            return_value=(actor, self._result(), None),
        ):
            profile, result, limitation = _run_call0(
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                excluded_actor_types=None,
                preferred_capability_level=None,
                attack_goal=None,
                pinned_technique_ids=None,
                forced_actor_type=None,
                pinned_entry_point=None,
                pinned_entry_point_id="ep:v1:test",
                access_feedback=None,
                projection_context={},
                call_log_entries=[],
                partial_scenario_id="scenario:v2:x",
                seed_id="AP-T1-01",
            )
        assert profile is actor
        assert limitation is None

    def test_run_call0_failure(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            GenerationError,
            _run_call0,
        )

        entries: list[dict] = []
        with patch(
            "asago_scenario_generator.pipeline.generate._call_actor_profile",
            side_effect=RuntimeError("boom"),
        ):
            with pytest.raises(GenerationError, match="boom") as raised:
                _run_call0(
                    self._seed(),
                    MagicMock(),
                    MagicMock(),
                    "use case",
                    excluded_actor_types=None,
                    preferred_capability_level=None,
                    attack_goal=None,
                    pinned_technique_ids=None,
                    forced_actor_type=None,
                    pinned_entry_point=None,
                    pinned_entry_point_id="ep:v1:test",
                    access_feedback=None,
                    projection_context={},
                    call_log_entries=entries,
                    partial_scenario_id="scenario:v2:x",
                    seed_id="AP-T1-01",
                )
        assert raised.value.seed_id == "AP-T1-01"
        assert entries == [raised.value.call_log_entries[0]]
        assert entries[0]["error"] == "boom"

    def test_regenerate_actor_profile_success(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _regenerate_actor_profile,
        )

        corrected = self._actor("nation-state")
        with (
            patch(
                "asago_scenario_generator.pipeline.generate._call_actor_profile",
                return_value=(corrected, self._result(), None),
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._validate_actor_type",
                side_effect=lambda value: value,
            ),
        ):
            profile, _result, _limitation = _regenerate_actor_profile(
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                excluded_actor_types=None,
                preferred_capability_level=None,
                attack_goal=None,
                pinned_technique_ids=None,
                corrected_type="nation-state",
                pinned_entry_point=None,
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                call_log_entries=[],
                partial_scenario_id="scenario:v2:x",
                seed_id="AP-T1-01",
                original_actor_type="cybercriminal",
            )
        assert profile is corrected

    def test_regenerate_actor_profile_failure(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            GenerationError,
            _regenerate_actor_profile,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate._call_actor_profile",
            side_effect=RuntimeError("boom"),
        ):
            with pytest.raises(GenerationError, match="BDI regeneration failed"):
                _regenerate_actor_profile(
                    self._seed(),
                    MagicMock(),
                    MagicMock(),
                    "use case",
                    excluded_actor_types=None,
                    preferred_capability_level=None,
                    attack_goal=None,
                    pinned_technique_ids=None,
                    corrected_type="nation-state",
                    pinned_entry_point=None,
                    pinned_entry_point_id="ep:v1:test",
                    projection_context={},
                    call_log_entries=[],
                    partial_scenario_id="scenario:v2:x",
                    seed_id="AP-T1-01",
                    original_actor_type="cybercriminal",
                )

    def test_retry_actor_access_no_pinned_entry_point(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _retry_actor_access,
        )

        actor = self._actor()
        with patch(
            "asago_scenario_generator.pipeline.generate.validate_actor_access_provenance"
        ) as mock_validate:
            profile, result, violations, retries = _retry_actor_access(
                actor,
                self._result(),
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                excluded_actor_types=None,
                preferred_capability_level=None,
                attack_goal=None,
                pinned_technique_ids=None,
                pinned_entry_point=None,
                pinned_entry_point_id="",
                projection_context={},
                diversity_notes=[],
                partial_scenario_id="scenario:v2:x",
            )
        mock_validate.assert_not_called()
        assert retries == 0
        assert violations == []
        assert profile is actor

    def test_retry_actor_access_retry_success(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _retry_actor_access,
        )

        violation = MagicMock()
        violation.message = "bad access"
        violation.rule = "some_rule"
        actor = self._actor()
        actor2 = self._actor("nation-state")
        with (
            patch(
                "asago_scenario_generator.pipeline.generate.validate_actor_access_provenance",
                side_effect=[[violation], []],
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._call_actor_profile",
                return_value=(actor2, self._result(), None),
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._validate_actor_type",
                side_effect=lambda value: value,
            ),
        ):
            profile, _result, violations, retries = _retry_actor_access(
                actor,
                self._result(),
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                excluded_actor_types=None,
                preferred_capability_level=None,
                attack_goal=None,
                pinned_technique_ids=None,
                pinned_entry_point=None,
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                diversity_notes=[],
                partial_scenario_id="scenario:v2:x",
            )
        assert retries == 1
        assert violations == []
        assert profile is actor2

    def test_retry_actor_access_violations_persist(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _retry_actor_access,
        )

        violation = MagicMock()
        violation.message = "bad access"
        violation.rule = "some_rule"
        actor = self._actor()
        with (
            patch(
                "asago_scenario_generator.pipeline.generate.validate_actor_access_provenance",
                return_value=[violation],
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._call_actor_profile",
                return_value=(actor, self._result(), None),
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._validate_actor_type",
                side_effect=lambda value: value,
            ),
        ):
            _profile, _result, violations, retries = _retry_actor_access(
                actor,
                self._result(),
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                excluded_actor_types=None,
                preferred_capability_level=None,
                attack_goal=None,
                pinned_technique_ids=None,
                pinned_entry_point=None,
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                diversity_notes=[],
                partial_scenario_id="scenario:v2:x",
            )
        assert retries == 2
        assert violations == [violation]

    def test_retry_actor_access_retry_raises_breaks(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _retry_actor_access,
        )

        violation = MagicMock()
        violation.message = "bad access"
        violation.rule = "access_class_ingress_mode_incompatible"
        actor = self._actor()
        with (
            patch(
                "asago_scenario_generator.pipeline.generate.validate_actor_access_provenance",
                return_value=[violation],
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._call_actor_profile",
                side_effect=RuntimeError("transport down"),
            ),
        ):
            _profile, _result, violations, retries = _retry_actor_access(
                actor,
                self._result(),
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                excluded_actor_types=None,
                preferred_capability_level=None,
                attack_goal=None,
                pinned_technique_ids=None,
                pinned_entry_point=None,
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                diversity_notes=[],
                partial_scenario_id="scenario:v2:x",
            )
        assert retries == 1
        assert violations == [violation]

    def test_run_call1_success(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _run_call1,
        )

        narrative = MagicMock(title="Title")
        with patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            return_value=(narrative, self._result()),
        ):
            returned, _result = _run_call1(
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                self._actor(),
                preferred_entry_point=None,
                excluded_entry_points=None,
                excluded_patterns=None,
                excluded_structural_patterns=None,
                pinned_entry_point=None,
                pinned_technique_ids=None,
                prior_titles=None,
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                call_log_entries=[],
                partial_scenario_id="scenario:v2:x",
                seed_id="AP-T1-01",
            )
        assert returned is narrative

    def test_run_call1_failure(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            GenerationError,
            _run_call1,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            side_effect=RuntimeError("boom"),
        ):
            with pytest.raises(GenerationError, match="boom"):
                _run_call1(
                    self._seed(),
                    MagicMock(),
                    MagicMock(),
                    "use case",
                    self._actor(),
                    preferred_entry_point=None,
                    excluded_entry_points=None,
                    excluded_patterns=None,
                    excluded_structural_patterns=None,
                    pinned_entry_point=None,
                    pinned_technique_ids=None,
                    prior_titles=None,
                    pinned_entry_point_id="ep:v1:test",
                    projection_context={},
                    call_log_entries=[],
                    partial_scenario_id="scenario:v2:x",
                    seed_id="AP-T1-01",
                )

    def test_retry_call1_loop_no_retry(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _retry_call1_loop,
        )

        narrative = MagicMock(title="Unique")
        with (
            patch(
                "asago_scenario_generator.pipeline.generate.narrative.validate_narrative_access_realization",
                return_value=[],
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._call_narrative"
            ) as mock_call,
        ):
            returned, _result, retries = _retry_call1_loop(
                narrative,
                self._result(),
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                self._actor(),
                preferred_entry_point=None,
                excluded_entry_points=None,
                excluded_patterns=None,
                excluded_structural_patterns=None,
                pinned_entry_point=None,
                pinned_technique_ids=None,
                prior_titles=None,
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                partial_scenario_id="scenario:v2:x",
            )
        assert returned is narrative
        assert retries == 0
        mock_call.assert_not_called()

    def test_retry_call1_loop_duplicate_title_retries(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _retry_call1_loop,
        )

        narrative = MagicMock(title="Dup")
        narrative2 = MagicMock(title="Fresh")
        with (
            patch(
                "asago_scenario_generator.pipeline.generate.narrative.validate_narrative_access_realization",
                return_value=[],
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._call_narrative",
                return_value=(narrative2, self._result()),
            ),
        ):
            returned, _result, retries = _retry_call1_loop(
                narrative,
                self._result(),
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                self._actor(),
                preferred_entry_point=None,
                excluded_entry_points=None,
                excluded_patterns=None,
                excluded_structural_patterns=None,
                pinned_entry_point=None,
                pinned_technique_ids=None,
                prior_titles=["Dup"],
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                partial_scenario_id="scenario:v2:x",
            )
        assert retries == 1
        assert returned is narrative2

    def test_retry_call1_loop_exception_breaks(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _retry_call1_loop,
        )

        narrative = MagicMock(title="Dup")
        with (
            patch(
                "asago_scenario_generator.pipeline.generate.narrative.validate_narrative_access_realization",
                return_value=[],
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._call_narrative",
                side_effect=RuntimeError("boom"),
            ),
        ):
            returned, _result, retries = _retry_call1_loop(
                narrative,
                self._result(),
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                self._actor(),
                preferred_entry_point=None,
                excluded_entry_points=None,
                excluded_patterns=None,
                excluded_structural_patterns=None,
                pinned_entry_point=None,
                pinned_technique_ids=None,
                prior_titles=["Dup"],
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                partial_scenario_id="scenario:v2:x",
            )
        assert retries == 1
        assert returned is narrative

    def test_run_call2_success(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _run_call2,
        )

        tree = MagicMock()
        with patch(
            "asago_scenario_generator.pipeline.generate._call_attack_tree",
            return_value=(tree, self._result()),
        ):
            returned, _result = _run_call2(
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                MagicMock(),
                self._actor(),
                pinned_technique_ids=None,
                pinned_technique_names=None,
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                call_log_entries=[],
                partial_scenario_id="scenario:v2:x",
                seed_id="AP-T1-01",
            )
        assert returned is tree

    def test_run_call2_failure(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            GenerationError,
            _run_call2,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate._call_attack_tree",
            side_effect=RuntimeError("boom"),
        ):
            with pytest.raises(GenerationError, match="boom"):
                _run_call2(
                    self._seed(),
                    MagicMock(),
                    MagicMock(),
                    "use case",
                    MagicMock(),
                    self._actor(),
                    pinned_technique_ids=None,
                    pinned_technique_names=None,
                    pinned_entry_point_id="ep:v1:test",
                    projection_context={},
                    call_log_entries=[],
                    partial_scenario_id="scenario:v2:x",
                    seed_id="AP-T1-01",
                )

    def test_run_call3_success(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _run_call3,
        )

        spec = MagicMock()
        with patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            return_value=(spec, self._result()),
        ) as mock_call:
            returned, _result = _run_call3(
                self._seed(),
                MagicMock(),
                MagicMock(),
                MagicMock(),
                MagicMock(),
                "use case",
                "scenario:v2:x",
                pinned_technique_ids=None,
                projection_context={},
                call_log_entries=[],
                partial_scenario_id="scenario:v2:x",
                seed_id="AP-T1-01",
            )
        assert returned is spec
        assert mock_call.call_args.args[6] == "scenario:v2:x"

    def test_run_call3_failure(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            GenerationError,
            _run_call3,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            side_effect=RuntimeError("boom"),
        ):
            with pytest.raises(GenerationError, match="boom"):
                _run_call3(
                    self._seed(),
                    MagicMock(),
                    MagicMock(),
                    MagicMock(),
                    MagicMock(),
                    "use case",
                    "scenario:v2:x",
                    pinned_technique_ids=None,
                    projection_context={},
                    call_log_entries=[],
                    partial_scenario_id="scenario:v2:x",
                    seed_id="AP-T1-01",
                )

    def test_warn_post_call1_heuristics_string_narrative(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _warn_post_call1_heuristics,
        )

        narrative = MagicMock(
            title="Title",
            summary="Summary",
            steps=[MagicMock(action="a", effect="e")],
        )
        actor = self._actor()
        actor.goal_category = None
        _warn_post_call1_heuristics(self._seed(), narrative, actor, "scenario:v2:x")

    def test_warn_post_call1_heuristics_mock_narrative(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _warn_post_call1_heuristics,
        )

        _warn_post_call1_heuristics(
            self._seed(), MagicMock(), self._actor(), "scenario:v2:x"
        )

    def test_retry_tree_consistency_ok(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _retry_tree_consistency,
        )

        tree = MagicMock()
        with patch(
            "asago_scenario_generator.pipeline.generate.assembly._check_consistency",
            return_value=[],
        ) as mock_check:
            returned, _result, violations, retries = _retry_tree_consistency(
                tree,
                self._result(),
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                MagicMock(),
                self._actor(),
                pinned_technique_ids=None,
                pinned_technique_names=None,
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                parsimony_budget=5,
            )
        assert returned is tree
        assert retries == 0
        assert violations == []
        mock_check.assert_called_once()

    def test_retry_tree_consistency_retry_success(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _retry_tree_consistency,
        )

        tree = MagicMock()
        tree2 = MagicMock()
        with (
            patch(
                "asago_scenario_generator.pipeline.generate.assembly._check_consistency",
                side_effect=[["violation"], []],
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._call_attack_tree",
                return_value=(tree2, self._result()),
            ),
        ):
            returned, _result, violations, retries = _retry_tree_consistency(
                tree,
                self._result(),
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                MagicMock(),
                self._actor(),
                pinned_technique_ids=None,
                pinned_technique_names=None,
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                parsimony_budget=5,
            )
        assert retries == 1
        assert violations == []
        assert returned is tree2

    def test_retry_tree_consistency_exception_breaks(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _retry_tree_consistency,
        )

        tree = MagicMock()
        with (
            patch(
                "asago_scenario_generator.pipeline.generate.assembly._check_consistency",
                return_value=["violation"],
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._call_attack_tree",
                side_effect=RuntimeError("boom"),
            ),
        ):
            returned, _result, violations, retries = _retry_tree_consistency(
                tree,
                self._result(),
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                MagicMock(),
                self._actor(),
                pinned_technique_ids=None,
                pinned_technique_names=None,
                pinned_entry_point_id="ep:v1:test",
                projection_context={},
                parsimony_budget=5,
            )
        assert retries == 1
        assert violations == ["violation"]
        assert returned is tree

    def test_validate_envelope_fail_closed_ok(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _validate_envelope_fail_closed,
        )
        from asago_scenario_generator.pipeline.projection_validation import (
            ProjectionTraceabilityResult,
        )

        envelope = MagicMock(scenario_id="scenario:v2:x")
        with (
            patch(
                "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability",
                return_value=ProjectionTraceabilityResult(valid=True),
            ),
            patch(
                "asago_scenario_generator.pipeline.source_influence.validate_source_influence_provenance"
            ) as mock_prov,
        ):
            mock_prov.return_value.valid = True
            _validate_envelope_fail_closed(envelope, [], "AP-T1-01")

    def test_validate_envelope_fail_closed_traceability(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            ProjectionTraceabilityError,
            _validate_envelope_fail_closed,
        )
        from asago_scenario_generator.pipeline.projection_validation import (
            ProjectionTraceabilityResult,
        )

        envelope = MagicMock(scenario_id="scenario:v2:x")
        with patch(
            "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability",
            return_value=ProjectionTraceabilityResult(valid=False, violations=[]),
        ):
            with pytest.raises(ProjectionTraceabilityError):
                _validate_envelope_fail_closed(envelope, [], "AP-T1-01")

    def test_validate_envelope_fail_closed_provenance(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            SourceInfluenceProvenanceError,
            _validate_envelope_fail_closed,
        )
        from asago_scenario_generator.pipeline.projection_validation import (
            ProjectionTraceabilityResult,
        )

        envelope = MagicMock(scenario_id="scenario:v2:x")
        with (
            patch(
                "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability",
                return_value=ProjectionTraceabilityResult(valid=True),
            ),
            patch(
                "asago_scenario_generator.pipeline.source_influence.validate_source_influence_provenance"
            ) as mock_prov,
        ):
            mock_prov.return_value.valid = False
            mock_prov.return_value.violations = []
            with pytest.raises(SourceInfluenceProvenanceError):
                _validate_envelope_fail_closed(envelope, [], "AP-T1-01")

    def test_rewrite_call_log_scenario_ids(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _rewrite_call_log_scenario_ids,
        )

        entries = [
            {"scenario_id": "scenario:v2:partial", "call": "a"},
            {"scenario_id": "scenario:v2:partial", "call": "b"},
        ]
        _rewrite_call_log_scenario_ids(entries, "scenario:v2:final")
        assert {e["scenario_id"] for e in entries} == {"scenario:v2:final"}

    def test_parsimony_budget(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _parsimony_budget,
        )

        budget = _parsimony_budget(["AML.T0001", "AML.T0002"], self._seed())
        assert isinstance(budget, int)
        fallback = _parsimony_budget(None, self._seed())
        assert isinstance(fallback, int)


class TestStageHandleMapHelpers:
    def test_tree_handles_empty_without_result(self) -> None:
        from asago_scenario_generator.pipeline.generate.stages import (
            _tree_handles_for_result,
        )

        recorder = SimpleNamespace(result=None)
        assert _tree_handles_for_result(_prepared(), object(), recorder) == {}

    def test_tree_handles_empty_without_compiled_draft(self) -> None:
        from asago_scenario_generator.pipeline.generate.stages import (
            _tree_handles_for_result,
        )

        recorder = SimpleNamespace(result=SimpleNamespace(content="raw text"))
        assert _tree_handles_for_result(_prepared(), object(), recorder) == {}

    def test_behavior_handles_empty_without_result(self) -> None:
        from asago_scenario_generator.pipeline.generate.stages import (
            _behavior_handles_for_result,
        )

        recorder = SimpleNamespace(result=None)
        assert _behavior_handles_for_result(_prepared(), object(), recorder) == {}

    def test_behavior_handles_empty_without_compiled_draft(self) -> None:
        from asago_scenario_generator.pipeline.generate.stages import (
            _behavior_handles_for_result,
        )

        recorder = SimpleNamespace(result=SimpleNamespace(content="raw text"))
        assert _behavior_handles_for_result(_prepared(), object(), recorder) == {}


class TestGenerateCompatibilitySubHelpers:
    """Branch-level coverage for the retry/check sub-helpers."""

    @staticmethod
    def _seed(threat_id: str = "T1") -> MagicMock:
        return MagicMock(
            seed_id="AP-T1-01",
            threat_id=threat_id,
            threat_name="T",
            attack_pattern_name="Pattern",
            attack_pattern_description="Desc",
            atlas_technique_ids=["AML.T0001"],
        )

    @staticmethod
    def _actor(actor_type: str = "cybercriminal") -> MagicMock:
        actor = MagicMock(actor_type=actor_type)
        actor.goal_category = None
        return actor

    @staticmethod
    def _result() -> LLMResult:
        return LLMResult(
            content="x",
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt="s",
            user_prompt="u",
        )

    @staticmethod
    def _violations(*rules: str) -> list[SimpleNamespace]:
        return [SimpleNamespace(rule=r, message=f"violation {r}") for r in rules]

    def test_access_violations_initial_pinned(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _access_violations_initial,
        )

        violations = self._violations("v1", "v2")
        with patch(
            "asago_scenario_generator.pipeline.generate.validate_actor_access_provenance",
            return_value=violations,
        ):
            assert (
                _access_violations_initial(self._actor(), MagicMock(), "ep:v1:x")
                == violations
            )

    def test_access_violations_initial_unpinned(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _access_violations_initial,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.validate_actor_access_provenance"
        ) as mock_validate:
            assert _access_violations_initial(self._actor(), MagicMock(), "") == []
            mock_validate.assert_not_called()

    def test_access_retry_feedback_joined(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _access_retry_feedback,
        )

        assert (
            _access_retry_feedback(self._violations("a", "b"))
            == "- violation a\n- violation b"
        )

    def test_access_retry_feedback_empty(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _access_retry_feedback,
        )

        assert _access_retry_feedback([]) == ""

    def test_access_retry_force_type_incompatible(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _access_retry_force_type,
        )

        actor = self._actor("cybercriminal")
        assert (
            _access_retry_force_type(
                actor, self._violations("access_class_ingress_mode_incompatible"), 1
            )
            is None
        )

    def test_access_retry_force_type_missing_advantage(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _access_retry_force_type,
        )

        actor = self._actor("cybercriminal")
        assert (
            _access_retry_force_type(
                actor, self._violations("missing_insider_advantage"), 1
            )
            is None
        )

    def test_access_retry_force_type_other(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _access_retry_force_type,
        )

        actor = self._actor("cybercriminal")
        assert (
            _access_retry_force_type(actor, self._violations("other_rule"), 1)
            == "cybercriminal"
        )

    def test_run_access_retry_attempt_success(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _run_access_retry_attempt,
        )

        actor = self._actor()
        new_actor = self._actor("insider")
        result = self._result()
        with (
            patch(
                "asago_scenario_generator.pipeline.generate._call_actor_profile",
                return_value=(new_actor, result, "limited"),
            ),
            patch(
                "asago_scenario_generator.pipeline.generate._validate_actor_type",
                return_value=new_actor,
            ),
            patch(
                "asago_scenario_generator.pipeline.generate.assembly._record_diversity_limitation"
            ) as mock_record,
            patch(
                "asago_scenario_generator.pipeline.generate.assembly._apply_goal_category"
            ) as mock_apply,
        ):
            outcome = _run_access_retry_attempt(
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                actor,
                excluded_actor_types=None,
                preferred_capability_level=None,
                attack_goal=None,
                pinned_technique_ids=None,
                force_type=None,
                pinned_entry_point=None,
                pinned_entry_point_id="ep:v1:x",
                access_feedback="- violation a",
                projection_context={},
                diversity_notes=[],
                access_retry=1,
                partial_scenario_id="scenario:v2:x",
            )
        assert outcome == (new_actor, result)
        mock_record.assert_called_once()
        mock_apply.assert_called_once()

    def test_run_access_retry_attempt_exception(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _run_access_retry_attempt,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate._call_actor_profile",
            side_effect=RuntimeError("boom"),
        ):
            outcome = _run_access_retry_attempt(
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                self._actor(),
                excluded_actor_types=None,
                preferred_capability_level=None,
                attack_goal=None,
                pinned_technique_ids=None,
                force_type=None,
                pinned_entry_point=None,
                pinned_entry_point_id="ep:v1:x",
                access_feedback="- violation a",
                projection_context={},
                diversity_notes=[],
                access_retry=1,
                partial_scenario_id="scenario:v2:x",
            )
        assert outcome is None

    def test_call1_realization_violations(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _call1_realization_violations,
        )

        violations = self._violations("r1")
        with patch(
            "asago_scenario_generator.pipeline.generate.narrative.validate_narrative_access_realization",
            return_value=violations,
        ):
            assert (
                _call1_realization_violations(MagicMock(), self._actor()) == violations
            )

    def test_call1_retry_checks_realization_violation(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _call1_retry_checks,
        )

        violations = self._violations("r1")
        with patch(
            "asago_scenario_generator.pipeline.generate.assembly._call1_realization_violations",
            return_value=violations,
        ):
            feedback_parts, realization_feedback, needs_retry, augmented = (
                _call1_retry_checks(
                    MagicMock(title="Title", steps=[]),
                    self._actor(),
                    prior_titles=None,
                    augmented_titles=[],
                    retry_count=0,
                    partial_scenario_id="scenario:v2:x",
                )
            )
        assert needs_retry is True
        assert realization_feedback == "- violation r1"
        assert feedback_parts == ["- violation r1"]
        assert augmented == []

    def test_call1_retry_checks_duplicate_title(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _call1_retry_checks,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.assembly._call1_realization_violations",
            return_value=[],
        ):
            feedback_parts, _rf, needs_retry, augmented = _call1_retry_checks(
                MagicMock(title="Title", steps=[]),
                self._actor(),
                prior_titles=["Title"],
                augmented_titles=[],
                retry_count=0,
                partial_scenario_id="scenario:v2:x",
            )
        assert needs_retry is True
        assert "DUPLICATE — DO NOT REUSE: Title" in augmented
        assert any("duplicate" in p.lower() for p in feedback_parts)

    def test_call1_retry_checks_duplicate_already_augmented(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _call1_retry_checks,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.assembly._call1_realization_violations",
            return_value=[],
        ):
            _fp, _rf, _nr, augmented = _call1_retry_checks(
                MagicMock(title="Title", steps=[]),
                self._actor(),
                prior_titles=["Title"],
                augmented_titles=["DUPLICATE — DO NOT REUSE: Title"],
                retry_count=0,
                partial_scenario_id="scenario:v2:x",
            )
        assert augmented == ["DUPLICATE — DO NOT REUSE: Title"]

    def test_call1_retry_checks_clean(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _call1_retry_checks,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.assembly._call1_realization_violations",
            return_value=[],
        ):
            feedback_parts, realization_feedback, needs_retry, augmented = (
                _call1_retry_checks(
                    MagicMock(title="Title", steps=[]),
                    self._actor(),
                    prior_titles=None,
                    augmented_titles=[],
                    retry_count=0,
                    partial_scenario_id="scenario:v2:x",
                )
            )
        assert needs_retry is False
        assert realization_feedback is None
        assert feedback_parts == []
        assert augmented == []

    def test_run_call1_retry_attempt_success_match(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _run_call1_retry_attempt,
        )

        narrative = MagicMock(title="T", entry_point="ep")
        result = self._result()
        with patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            return_value=(narrative, result),
        ):
            outcome = _run_call1_retry_attempt(
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                self._actor(),
                preferred_entry_point=None,
                excluded_entry_points=None,
                excluded_patterns=None,
                excluded_structural_patterns=None,
                pinned_entry_point="ep",
                pinned_technique_ids=None,
                prior_titles=["T"],
                pinned_entry_point_id="ep:v1:x",
                realization_feedback=None,
                projection_context={},
                call1_retry=1,
                partial_scenario_id="scenario:v2:x",
            )
        assert outcome == (narrative, result)

    def test_run_call1_retry_attempt_success_mismatch(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _run_call1_retry_attempt,
        )

        narrative = MagicMock(title="T", entry_point="other")
        result = self._result()
        with patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            return_value=(narrative, result),
        ):
            outcome = _run_call1_retry_attempt(
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                self._actor(),
                preferred_entry_point=None,
                excluded_entry_points=None,
                excluded_patterns=None,
                excluded_structural_patterns=None,
                pinned_entry_point="ep",
                pinned_technique_ids=None,
                prior_titles=["T"],
                pinned_entry_point_id="ep:v1:x",
                realization_feedback="- violation r1",
                projection_context={},
                call1_retry=1,
                partial_scenario_id="scenario:v2:x",
            )
        assert outcome == (narrative, result)

    def test_run_call1_retry_attempt_exception(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _run_call1_retry_attempt,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            side_effect=RuntimeError("boom"),
        ):
            outcome = _run_call1_retry_attempt(
                self._seed(),
                MagicMock(),
                MagicMock(),
                "use case",
                self._actor(),
                preferred_entry_point=None,
                excluded_entry_points=None,
                excluded_patterns=None,
                excluded_structural_patterns=None,
                pinned_entry_point="ep",
                pinned_technique_ids=None,
                prior_titles=["T"],
                pinned_entry_point_id="ep:v1:x",
                realization_feedback=None,
                projection_context={},
                call1_retry=1,
                partial_scenario_id="scenario:v2:x",
            )
        assert outcome is None

    def test_warn_call1_persistent_violations_none(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _warn_call1_persistent_violations,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.assembly._call1_realization_violations",
            return_value=[],
        ):
            _warn_call1_persistent_violations(
                MagicMock(), self._actor(), 0, "scenario:v2:x"
            )

    def test_warn_call1_persistent_violations_present(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _warn_call1_persistent_violations,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.assembly._call1_realization_violations",
            return_value=self._violations("r1"),
        ):
            _warn_call1_persistent_violations(
                MagicMock(), self._actor(), 1, "scenario:v2:x"
            )

    def test_post_call1_narrative_text(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _post_call1_narrative_text,
        )

        narrative = MagicMock(
            title="Title",
            summary="Summary",
            steps=[MagicMock(action="a", effect="e")],
        )
        assert _post_call1_narrative_text(narrative) == "Title Summary a e"

    def test_warn_goal_narrative_alignment_warn(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _warn_goal_narrative_alignment,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.assembly.check_goal_narrative_alignment",
            return_value="goal warn",
        ):
            _warn_goal_narrative_alignment("g1", "text", "scenario:v2:x")

    def test_warn_goal_narrative_alignment_no_warn(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _warn_goal_narrative_alignment,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.assembly.check_goal_narrative_alignment",
            return_value=None,
        ) as mock_check:
            _warn_goal_narrative_alignment("g1", "text", "scenario:v2:x")
            mock_check.assert_called_once_with("g1", "text")

    def test_warn_goal_narrative_alignment_non_str(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _warn_goal_narrative_alignment,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.assembly.check_goal_narrative_alignment"
        ) as mock_check:
            _warn_goal_narrative_alignment(None, "text", "scenario:v2:x")
            mock_check.assert_not_called()

    def test_warn_seed_mechanism_fidelity_warn(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _warn_seed_mechanism_fidelity,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.assembly.check_seed_mechanism_fidelity",
            return_value="mechanism warn",
        ):
            _warn_seed_mechanism_fidelity("Pattern", "text", "scenario:v2:x")

    def test_warn_seed_mechanism_fidelity_no_warn(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _warn_seed_mechanism_fidelity,
        )

        with patch(
            "asago_scenario_generator.pipeline.generate.assembly.check_seed_mechanism_fidelity",
            return_value=None,
        ) as mock_check:
            _warn_seed_mechanism_fidelity("Pattern", "text", "scenario:v2:x")
            mock_check.assert_called_once_with("Pattern", "text")

"""Typed single-attempt generation seam tests for cmps.5 phase 1."""

from __future__ import annotations

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

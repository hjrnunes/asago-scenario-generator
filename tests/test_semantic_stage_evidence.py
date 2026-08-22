"""Single-attempt semantic evidence at the Call 0/1 lifecycle seam."""

from __future__ import annotations

from typing import Any, cast
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from asago_scenario_generator.llm.client import CompletionLengthError, LLMResult
from asago_scenario_generator.models.scenario import CallMetadata, CallName
from asago_scenario_generator.pipeline.generation_contracts import StageCallEvidence
from asago_scenario_generator.pipeline.generate.actor import (
    ActorDraftV2,
    ActorDraftViolation,
    ActorSemanticDraftError,
)
from asago_scenario_generator.pipeline.generate.narrative import NarrativeDraftV2
from asago_scenario_generator.pipeline.generate.behavior_semantics import (
    BehaviorDraftV2,
)
from asago_scenario_generator.pipeline.generate.tree_semantics import AttackTreeDraftV2
from asago_scenario_generator.pipeline.generate.stages import (
    GenerationRequest,
    PreparedGeneration,
    RetryDirective,
    StageAttemptFailure,
    generate_actor_stage,
    generate_behavior_stage,
    generate_narrative_stage,
    generate_tree_stage,
)
from asago_scenario_generator.pipeline.persistence import (
    _attempt_failure,
    _call_evidence,
)
from asago_scenario_generator.pipeline.runner_finalization import (
    _hydrate_stage_evidence,
)
from asago_scenario_generator.pipeline.persistence import (
    build_semantic_generation_summary,
)
from asago_scenario_generator.pipeline.semantic_generation import (
    StageAttemptEvidence,
    StageGenerationEvidence,
)


def _prepared(client: Any) -> PreparedGeneration:
    request = GenerationRequest(
        seed=cast(Any, object()),
        profile=cast(Any, object()),
        client=client,
        use_case="test",
        pinned_entry_point_id="ep:v1:test",
        projected_candidate=cast(Any, object()),
        capability_snapshot=cast(Any, object()),
        run_id="20260101T000000_0123456789abcdef0123456789abcdef",
    )
    return PreparedGeneration(
        request,
        "cand:v2:test",
        "scenario:v2:test",
        {"selected_step_ids": ["projected.prepare", "projected.deliver"]},
    )


def _result(content: Any) -> LLMResult:
    return LLMResult(
        content=content,
        prompt_tokens=3,
        completion_tokens=5,
        duration_ms=7,
        system_prompt="system",
        user_prompt="user",
        request_controls={"max_completion_tokens": 8192},
    )


def _actor_draft() -> ActorDraftV2:
    return ActorDraftV2(
        actor_type_handle="a0",
        capability_level_handle="c0",
        beliefs=["The system accepts untrusted input."],
        desires=["Influence the system response."],
        intentions=["Submit a crafted input."],
        resource_handles=["r0"],
    )


def _narrative_draft() -> NarrativeDraftV2:
    return NarrativeDraftV2.model_validate(
        {
            "summary": "A prepared input crosses the boundary and changes output.",
            "beats": [
                {
                    "step_handles": ["s0"],
                    "action": "Prepare the crafted input.",
                    "consequence": "The input is ready for delivery.",
                },
                {
                    "step_handles": ["s1"],
                    "action": "Deliver the crafted input.",
                    "consequence": "The system processes the input.",
                },
            ],
        }
    )


def test_actor_success_retains_accepted_semantic_evidence() -> None:
    draft = _actor_draft()
    llm_result = _result(draft)
    client = MagicMock()
    client.complete.return_value = llm_result
    actor = MagicMock(
        actor_type="adversarial-user",
        capability_level="intermediate",
        resources=["HTTP client"],
    )

    def call0(_seed, _profile, recorder, _use_case, **_kwargs):
        result = recorder.complete("system", "user", response_format=ActorDraftV2)
        return actor, result, None

    with patch("asago_scenario_generator.pipeline.generate._call_actor_profile", call0):
        stage = generate_actor_stage(_prepared(client))

    client.complete.assert_called_once()
    semantic = stage.evidence.semantic_evidence
    assert semantic is not None
    assert semantic.stage == "actor"
    assert semantic.accepted_draft_digest
    assert semantic.handle_map == {
        "a0": "adversarial-user",
        "c0": "intermediate",
        "r0": "HTTP client",
    }
    assert [attempt.result for attempt in semantic.attempts] == ["accepted"]


def test_actor_semantic_validation_failure_is_retryable_and_retains_draft() -> None:
    draft = _actor_draft()
    client = MagicMock()
    client.complete.return_value = _result(draft)

    def call0(_seed, _profile, recorder, _use_case, **_kwargs):
        recorder.complete("system", "user", response_format=ActorDraftV2)
        raise ActorSemanticDraftError(
            [ActorDraftViolation("capability_below_floor", "capability is too low")]
        )

    with (
        patch("asago_scenario_generator.pipeline.generate._call_actor_profile", call0),
        pytest.raises(StageAttemptFailure) as excinfo,
    ):
        generate_actor_stage(_prepared(client))

    failure = excinfo.value
    client.complete.assert_called_once()
    assert failure.code == "semantic_draft_invalid"
    assert failure.retryable is True
    assert failure.semantic_evidence is not None
    assert failure.semantic_evidence.accepted_draft_digest is None
    attempt = failure.semantic_evidence.attempts[0]
    assert attempt.result == "invalid_draft"
    assert attempt.response_digest
    assert [item.code for item in attempt.validation_violations] == [
        "capability_below_floor"
    ]


def test_actor_provider_parse_failure_is_a_typed_protocol_failure() -> None:
    parse_error: ValidationError
    try:
        ActorDraftV2.model_validate({"actor_type_handle": "a0"})
    except ValidationError as exc:
        parse_error = exc
    client = MagicMock()
    client.complete.side_effect = parse_error

    def call0(_seed, _profile, recorder, _use_case, **_kwargs):
        recorder.complete("system", "user", response_format=ActorDraftV2)
        raise AssertionError("unreachable")

    with (
        patch("asago_scenario_generator.pipeline.generate._call_actor_profile", call0),
        pytest.raises(StageAttemptFailure) as excinfo,
    ):
        generate_actor_stage(_prepared(client))

    failure = excinfo.value
    client.complete.assert_called_once()
    assert failure.code == "semantic_draft_protocol_failed"
    assert failure.retryable is True
    assert failure.semantic_evidence is not None
    assert failure.semantic_evidence.attempts[0].result == "protocol_failure"


def test_narrative_compiler_failure_is_nonretryable_and_retains_draft() -> None:
    draft = _narrative_draft()
    client = MagicMock()
    client.complete.return_value = _result(draft)

    def call1(_seed, _profile, recorder, _use_case, **_kwargs):
        recorder.complete("system", "user", response_format=NarrativeDraftV2)
        raise RuntimeError("canonical compiler defect")

    with (
        patch("asago_scenario_generator.pipeline.generate._call_narrative", call1),
        pytest.raises(StageAttemptFailure) as excinfo,
    ):
        generate_narrative_stage(_prepared(client), cast(Any, object()))

    failure = excinfo.value
    client.complete.assert_called_once()
    assert failure.code == "canonical_compilation_failed"
    assert failure.retryable is False
    assert failure.semantic_evidence is not None
    assert failure.semantic_evidence.accepted_draft_digest
    assert failure.semantic_evidence.handle_map == {
        "s0": "projected.prepare",
        "s1": "projected.deliver",
    }
    assert failure.semantic_evidence.attempts[0].result == "compiler_failure"


def test_narrative_presentation_fallback_is_retained_as_semantic_evidence() -> None:
    draft = _narrative_draft()
    client = MagicMock()
    client.complete.return_value = _result(draft)

    def call1(_seed, _profile, recorder, _use_case, **kwargs):
        assert kwargs["presentation_fallback_allowed"] is True
        result = recorder.complete("system", "user", response_format=NarrativeDraftV2)
        return cast(Any, object()), result

    with patch("asago_scenario_generator.pipeline.generate._call_narrative", call1):
        stage = generate_narrative_stage(_prepared(client), cast(Any, object()))

    assert stage.evidence.semantic_evidence is not None
    assert stage.evidence.semantic_evidence.warnings == (
        "presentation_fallback: narrative title was synthesized",
    )


def test_tree_and_behavior_success_retain_accepted_semantic_evidence() -> None:
    tree_draft = AttackTreeDraftV2(root={"kind": "leaf", "leaf_handle": "l0"})
    behavior_draft = BehaviorDraftV2(
        scenarios=(
            {
                "title": "Concrete interaction",
                "steps": ({"kind": "action", "handle": "a0", "text": "Submit input"},),
            },
        )
    )
    client = MagicMock()
    prepared = _prepared(client)

    def call2(_seed, _narrative, recorder, _use_case, **_kwargs):
        result = recorder.complete(
            "tree system", "tree user", response_format=AttackTreeDraftV2
        )
        return cast(Any, object()), result

    def call3(_seed, _narrative, _tree, _profile, recorder, _use_case, _tag, **_kwargs):
        result = recorder.complete(
            "behavior system", "behavior user", response_format=BehaviorDraftV2
        )
        return cast(Any, object()), result

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_attack_tree_once",
            call2,
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.stages._tree_handle_map",
            return_value={"l0": "projected.prepare"},
        ),
    ):
        client.complete.return_value = _result(tree_draft)
        tree_stage = generate_tree_stage(
            prepared, cast(Any, object()), cast(Any, object())
        )

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            call3,
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.stages._behavior_handle_map",
            return_value={"a0": "ba-node-1"},
        ),
    ):
        client.complete.return_value = _result(behavior_draft)
        behavior_stage = generate_behavior_stage(
            prepared, cast(Any, object()), cast(Any, object())
        )

    assert tree_stage.evidence.semantic_evidence is not None
    assert tree_stage.evidence.semantic_evidence.stage == "tree"
    assert tree_stage.evidence.semantic_evidence.handle_map == {
        "l0": "projected.prepare"
    }
    assert behavior_stage.evidence.semantic_evidence is not None
    assert behavior_stage.evidence.semantic_evidence.stage == "behavior"
    assert behavior_stage.evidence.semantic_evidence.handle_map == {"a0": "ba-node-1"}


def test_authorized_length_retry_uses_terminal_semantic_length_code() -> None:
    client = MagicMock()
    client.complete.side_effect = CompletionLengthError(
        prompt_tokens=10, completion_tokens=20
    )

    def call0(_seed, _profile, recorder, _use_case, **_kwargs):
        recorder.complete("system", "user", response_format=ActorDraftV2)
        raise AssertionError("unreachable")

    with (
        patch("asago_scenario_generator.pipeline.generate._call_actor_profile", call0),
        pytest.raises(StageAttemptFailure) as excinfo,
    ):
        generate_actor_stage(
            _prepared(client),
            RetryDirective(feedback="be concise", reason="completion_length"),
        )

    assert excinfo.value.code == "semantic_draft_length_failed"
    assert excinfo.value.retryable is False
    assert excinfo.value.semantic_evidence is not None
    attempt = excinfo.value.semantic_evidence.attempts[0]
    assert attempt.attempt_index == 1
    assert attempt.retry_class == "length"
    assert attempt.finish_reason == "length"
    assert attempt.result == "length_failure"


def test_accepted_semantic_evidence_round_trips_through_finalization_record() -> None:
    semantic = StageGenerationEvidence(
        stage="narrative",
        compiler_name="compile_narrative_draft:v2",
        handle_map={"s0": "projected.prepare"},
        attempts=(
            StageAttemptEvidence(
                attempt_index=0,
                request_digest="a" * 64,
                response_digest="b" * 64,
                finish_reason="stop",
                result="accepted",
                effective_controls={"max_completion_tokens": 8192},
            ),
        ),
        accepted_draft_digest="b" * 64,
        warnings=("presentation_fallback: narrative title was synthesized",),
    )
    result = _result(_narrative_draft())
    evidence = StageCallEvidence(
        CallName.narrative,
        result,
        CallMetadata(
            call=CallName.narrative,
            prompt_tokens=3,
            completion_tokens=5,
            duration_ms=7,
        ),
        semantic,
    )

    record = _call_evidence(evidence)
    hydrated = _hydrate_stage_evidence(SimpleNamespace(call=record))

    assert record.semantic_evidence == semantic.as_dict()
    assert hydrated is not None
    assert hydrated.semantic_evidence is not None
    assert hydrated.semantic_evidence.as_dict() == semantic.as_dict()


def test_failed_semantic_evidence_persists_retryability_and_draft_digest() -> None:
    semantic = StageGenerationEvidence(
        stage="actor",
        compiler_name="compile_actor_draft:v2",
        handle_map={},
        attempts=(
            StageAttemptEvidence(
                attempt_index=0,
                request_digest="a" * 64,
                response_digest="b" * 64,
                finish_reason="stop",
                result="compiler_failure",
                effective_controls={},
                failure_detail="RuntimeError: defect",
            ),
        ),
        accepted_draft_digest="b" * 64,
    )
    failure = StageAttemptFailure(
        call_name=CallName.actor_profile,
        exception=RuntimeError("defect"),
        phase="post_response",
        invoked=True,
        code="canonical_compilation_failed",
        retryable=False,
        semantic_evidence=semantic,
    )

    record = _attempt_failure(failure)

    assert record.retryable is False
    assert record.semantic_evidence == semantic.as_dict()


def test_manifest_summary_proves_all_four_provider_semantic_stages() -> None:
    stages = ("actor", "narrative", "tree", "behavior")
    attempts = []
    for sequence, stage in enumerate(stages, start=1):
        warnings = (
            ["presentation_fallback: narrative title was synthesized"]
            if stage == "narrative"
            else []
        )
        semantic = {
            "stage": stage,
            "compiler_name": f"compile_{stage}_draft:v2",
            "handle_map": {f"{stage[0]}0": f"canonical-{stage}"},
            "attempts": [
                {
                    "attempt_index": 0,
                    "request_digest": "a" * 64,
                    "response_digest": "b" * 64,
                    "finish_reason": "stop",
                    "result": "accepted",
                    "effective_controls": {},
                    "validation_violations": [],
                    "retry_class": None,
                    "failure_detail": None,
                }
            ],
            "accepted_draft_digest": "b" * 64,
            "warnings": warnings,
        }
        attempts.append(
            SimpleNamespace(
                sequence=sequence,
                candidate_id="candidate-1",
                stage=SimpleNamespace(value=stage),
                invocation_index=0,
                call=SimpleNamespace(semantic_evidence=semantic),
                failure=None,
            )
        )
    inventory = SimpleNamespace(
        stage_attempts=attempts,
        admission_decisions=[
            SimpleNamespace(candidate_id="candidate-1", admitted=True)
        ],
    )

    summary = build_semantic_generation_summary(inventory)
    records = summary["stage_records"]

    assert [record["outcome"] for record in records] == ["accepted"] * 4
    candidate = summary["candidates"]["candidate-1"]
    assert candidate["admitted"] is True
    assert candidate["complete_provider_semantics"] is True
    assert candidate["stages"] == {stage: "accepted" for stage in stages}
    assert candidate["presentation_fallbacks"] == [
        "presentation_fallback: narrative title was synthesized"
    ]
    assert records[0]["semantic_evidence"]["handle_map"] == {"a0": "canonical-actor"}

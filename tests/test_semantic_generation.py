"""Public-interface tests for bounded semantic stage generation."""

import json

import pytest

from asago_scenario_generator.pipeline.semantic_generation import (
    DraftValidation,
    DraftViolation,
    HandleBinding,
    HandleChoice,
    RequestHandleMap,
    OpenAICompatibleSemanticAdapter,
    ScriptedSemanticAdapter,
    SemanticAdapterDraft,
    SemanticAdapterFailure,
    SemanticAdapterFailureKind,
    SemanticAttemptRequest,
    SemanticProviderCall,
    SemanticRetryDirective,
    StageFailureCode,
    StageGenerationFailure,
    StageGenerationRequest,
    StageGenerationSuccess,
    generate_stage,
)


def test_request_handles_are_deterministic_and_resolve_canonical_choices() -> None:
    choices = {
        "s": (
            HandleChoice("step:very-long/input", "Input step"),
            HandleChoice("step:very-long/impact", "Impact step"),
        ),
        "a": (HandleChoice("action:invoke-tool", "Invoke tool"),),
    }

    first = RequestHandleMap.allocate(choices)
    second = RequestHandleMap.allocate(dict(reversed(tuple(choices.items()))))

    assert first == second
    assert first.handles == ("a0", "s0", "s1")
    assert first.resolve("s1").canonical_id == "step:very-long/impact"
    assert first.as_dict() == {
        "a0": "action:invoke-tool",
        "s0": "step:very-long/input",
        "s1": "step:very-long/impact",
    }


def test_request_handle_map_rejects_ambiguous_direct_construction() -> None:
    with pytest.raises(ValueError, match="duplicate request-local handle: s0"):
        RequestHandleMap(
            (
                HandleBinding("s0", "step:first"),
                HandleBinding("s0", "step:second"),
            )
        )


def test_generate_stage_compiles_one_valid_scripted_draft_with_evidence() -> None:
    handles = RequestHandleMap.allocate(
        {"s": (HandleChoice("step:canonical/input", "Input step"),)}
    )
    adapter = ScriptedSemanticAdapter(
        [SemanticAdapterDraft({"step": "s0", "prose": "Cause the effect"})]
    )
    request = StageGenerationRequest(
        stage="narrative",
        context={"scenario": "fixture"},
        handles=handles,
        request_payload={"candidate_id": "cand:v2:fixture"},
        effective_controls={"model": "scripted", "temperature": 0.2},
        compiler_name="narrative-v2",
        validate_draft=lambda _context, _draft: DraftValidation(),
        compile_draft=lambda _context, draft: {
            "step_id": handles.resolve(draft["step"]).canonical_id,
            "prose": draft["prose"],
        },
    )

    outcome = generate_stage(request, adapter)

    assert isinstance(outcome, StageGenerationSuccess)
    assert outcome.artifact == {
        "step_id": "step:canonical/input",
        "prose": "Cause the effect",
    }
    assert outcome.accepted_draft == {"step": "s0", "prose": "Cause the effect"}
    assert len(adapter.attempts) == 1
    assert outcome.evidence.compiler_name == "narrative-v2"
    assert outcome.evidence.handle_map == {"s0": "step:canonical/input"}
    assert outcome.evidence.attempts[0].result == "accepted"
    assert outcome.evidence.attempts[0].request_digest
    assert outcome.evidence.attempts[0].response_digest
    persisted = outcome.evidence.as_dict()
    assert persisted["handle_map"] == {"s0": "step:canonical/input"}
    assert persisted["attempts"][0]["effective_controls"] == {
        "model": "scripted",
        "temperature": 0.2,
    }
    json.dumps(persisted)


def test_invalid_draft_returns_typed_failure_after_one_adapter_call() -> None:
    violation = DraftViolation(
        code="unknown_handle",
        detail="step handle must come from this request",
        handles=("s9",),
    )
    adapter = ScriptedSemanticAdapter([SemanticAdapterDraft({"step": "s9"})])
    request = StageGenerationRequest(
        stage="narrative",
        context=None,
        handles=RequestHandleMap.allocate({"s": (HandleChoice("step:input"),)}),
        request_payload={"candidate_id": "cand:v2:fixture"},
        effective_controls={"model": "scripted"},
        compiler_name="narrative-v2",
        validate_draft=lambda _context, draft: (
            DraftValidation()
            if draft["step"] == "s0"
            else DraftValidation((violation,))
        ),
        compile_draft=lambda _context, draft: draft["step"],
    )

    outcome = generate_stage(request, adapter)

    assert isinstance(outcome, StageGenerationFailure)
    assert outcome.code is StageFailureCode.semantic_draft_invalid
    assert len(adapter.attempts) == 1
    assert [attempt.result for attempt in outcome.evidence.attempts] == [
        "invalid_draft"
    ]


def test_caller_owned_retry_directive_is_forwarded_to_one_attempt() -> None:
    violation = DraftViolation(
        "missing_handle", "required handle s0 is missing", ("s0",)
    )
    adapter = ScriptedSemanticAdapter([SemanticAdapterDraft({"steps": ["s0"]})])
    request = StageGenerationRequest(
        stage="attack_tree",
        context=None,
        handles=RequestHandleMap.allocate({"s": (HandleChoice("step:input"),)}),
        request_payload={"candidate_id": "cand:v2:fixture"},
        effective_controls={"model": "scripted"},
        compiler_name="attack-tree-v2",
        validate_draft=lambda _context, _draft: DraftValidation(),
        compile_draft=lambda _context, draft: draft,
        attempt_index=2,
        retry=SemanticRetryDirective(
            retry_class="semantic",
            feedback=(violation,),
        ),
    )

    outcome = generate_stage(request, adapter)

    assert isinstance(outcome, StageGenerationSuccess)
    assert len(adapter.attempts) == 1
    assert adapter.attempts[0].attempt_index == 2
    assert adapter.attempts[0].feedback == (violation,)
    assert outcome.evidence.attempts[0].retry_class == "semantic"


def test_length_failure_returns_typed_failure_after_one_adapter_call() -> None:
    adapter = ScriptedSemanticAdapter(
        [
            SemanticAdapterFailure(
                kind=SemanticAdapterFailureKind.length,
                detail="provider completion reached its cap",
                finish_reason="length",
            ),
        ]
    )
    request = StageGenerationRequest(
        stage="actor",
        context=None,
        handles=RequestHandleMap.allocate({}),
        request_payload={"candidate_id": "cand:v2:fixture"},
        effective_controls={"model": "scripted", "max_completion_tokens": 1024},
        compiler_name="actor-v2",
        validate_draft=lambda _context, _draft: DraftValidation(),
        compile_draft=lambda _context, draft: draft,
    )

    outcome = generate_stage(request, adapter)

    assert isinstance(outcome, StageGenerationFailure)
    assert outcome.code is StageFailureCode.semantic_draft_length_failed
    assert len(adapter.attempts) == 1
    first = outcome.evidence.attempts[0]
    assert first.result == "length_failure"
    assert first.finish_reason == "length"
    assert first.effective_controls["max_completion_tokens"] == 1024


def test_protocol_failure_returns_typed_failure_after_one_adapter_call() -> None:
    protocol_failure = SemanticAdapterFailure(
        kind=SemanticAdapterFailureKind.protocol,
        detail="response did not satisfy the dynamic schema",
        finish_reason="stop",
    )
    adapter = ScriptedSemanticAdapter([protocol_failure])
    request = StageGenerationRequest(
        stage="behavior",
        context=None,
        handles=RequestHandleMap.allocate({}),
        request_payload={"candidate_id": "cand:v2:fixture"},
        effective_controls={"model": "scripted"},
        compiler_name="behavior-v2",
        validate_draft=lambda _context, _draft: DraftValidation(),
        compile_draft=lambda _context, draft: draft,
    )

    outcome = generate_stage(request, adapter)

    assert isinstance(outcome, StageGenerationFailure)
    assert outcome.code is StageFailureCode.semantic_draft_protocol_failed
    assert len(adapter.attempts) == 1
    assert [attempt.result for attempt in outcome.evidence.attempts] == [
        "protocol_failure"
    ]


def test_compiler_defect_is_terminal_without_provider_retry() -> None:
    def broken_compiler(_context, _draft):
        raise RuntimeError("canonical mapping table is inconsistent")

    adapter = ScriptedSemanticAdapter([SemanticAdapterDraft({"leaf_handles": ["l0"]})])
    request = StageGenerationRequest(
        stage="attack_tree",
        context=None,
        handles=RequestHandleMap.allocate({"l": (HandleChoice("leaf:canonical"),)}),
        request_payload={"candidate_id": "cand:v2:fixture"},
        effective_controls={"model": "scripted"},
        compiler_name="attack-tree-v2",
        validate_draft=lambda _context, _draft: DraftValidation(),
        compile_draft=broken_compiler,
    )

    outcome = generate_stage(request, adapter)

    assert isinstance(outcome, StageGenerationFailure)
    assert outcome.code is StageFailureCode.canonical_compilation_failed
    assert outcome.detail == "RuntimeError: canonical mapping table is inconsistent"
    assert len(adapter.attempts) == 1
    assert [attempt.result for attempt in outcome.evidence.attempts] == [
        "compiler_failure"
    ]
    assert outcome.evidence.accepted_draft_digest


def test_openai_adapter_builds_and_executes_exactly_one_injected_call() -> None:
    from asago_scenario_generator.llm.client import LLMResult

    calls = []

    def complete(**kwargs):
        calls.append(kwargs)
        return LLMResult(
            content={"step": "s0"},
            prompt_tokens=10,
            completion_tokens=5,
            duration_ms=2,
        )

    adapter = OpenAICompatibleSemanticAdapter(
        complete=complete,
        build_call=lambda attempt: SemanticProviderCall(
            system_prompt=f"stage={attempt.stage}",
            user_prompt="choose one handle",
            response_format=dict,
            completion_kwargs={"temperature": 0.2},
        ),
        decode_draft=lambda content: content,
    )
    attempt = SemanticAttemptRequest(
        stage="narrative",
        attempt_index=0,
        context=None,
        handles=RequestHandleMap.allocate({"s": (HandleChoice("step:input"),)}),
        effective_controls={"temperature": 0.2},
        request_digest="a" * 64,
    )

    result = adapter.generate(attempt)

    assert result == SemanticAdapterDraft({"step": "s0"})
    assert calls == [
        {
            "system_prompt": "stage=narrative",
            "user_prompt": "choose one handle",
            "response_format": dict,
            "temperature": 0.2,
        }
    ]


def test_openai_adapter_normalizes_length_and_protocol_failures() -> None:
    from asago_scenario_generator.llm.client import CompletionLengthError, LLMResult

    attempt = SemanticAttemptRequest(
        stage="actor",
        attempt_index=0,
        context=None,
        handles=RequestHandleMap.allocate({}),
        effective_controls={},
        request_digest="a" * 64,
    )
    length_adapter = OpenAICompatibleSemanticAdapter(
        complete=lambda **_kwargs: (_ for _ in ()).throw(
            CompletionLengthError(completion_tokens=128)
        ),
        build_call=lambda _attempt: SemanticProviderCall("system", "user"),
        decode_draft=lambda content: content,
    )
    protocol_adapter = OpenAICompatibleSemanticAdapter(
        complete=lambda **_kwargs: LLMResult(
            content={}, prompt_tokens=1, completion_tokens=1, duration_ms=1
        ),
        build_call=lambda _attempt: SemanticProviderCall("system", "user"),
        decode_draft=lambda _content: (_ for _ in ()).throw(ValueError("bad schema")),
    )

    length = length_adapter.generate(attempt)
    protocol = protocol_adapter.generate(attempt)

    assert isinstance(length, SemanticAdapterFailure)
    assert length.kind is SemanticAdapterFailureKind.length
    assert length.finish_reason == "length"
    assert isinstance(protocol, SemanticAdapterFailure)
    assert protocol.kind is SemanticAdapterFailureKind.protocol
    assert protocol.detail == "ValueError: bad schema"

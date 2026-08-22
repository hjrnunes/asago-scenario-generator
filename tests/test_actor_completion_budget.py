"""Regression coverage for actor-profile completion budgets and retries."""

from unittest.mock import MagicMock

import pytest

from asago_scenario_generator.pipeline.generate import actor


def _stub_actor_context(monkeypatch) -> None:
    monkeypatch.setattr(
        actor,
        "build_call0_context",
        lambda **_kwargs: {
            "tool_inventory": [],
            "minimum_capability_level": None,
            "diversity_limitation": None,
        },
    )
    monkeypatch.setattr(actor, "render_prompt", lambda *_args, **_kwargs: "prompt")


def _successful_actor_result() -> actor.LLMResult:
    return actor.LLMResult(
        content=actor.Call0Response(
            actor_type="adversarial-user",
            capability_level="intermediate",
            beliefs=["The system accepts user input."],
            desires=["Influence the system."],
            intentions=["Submit crafted input."],
            resources=["A client application."],
        ),
        prompt_tokens=1,
        completion_tokens=1,
        duration_ms=1,
    )


@pytest.mark.parametrize("completion_limit", [2048, 16384])
def test_actor_profile_call_uses_configured_completion_limit(
    monkeypatch, completion_limit
) -> None:
    """The actor call forwards the configured operator limit unchanged."""
    _stub_actor_context(monkeypatch)
    client = MagicMock()
    client.max_completion_tokens = completion_limit
    client.complete.side_effect = RuntimeError("stop after invocation")

    with pytest.raises(RuntimeError, match="stop after invocation"):
        actor._call_actor_profile(
            seed=MagicMock(),
            profile=MagicMock(zones_active=[]),
            client=client,
            use_case="test",
        )

    assert client.complete.call_count == 1
    assert client.complete.call_args.kwargs["max_completion_tokens"] == completion_limit


def test_actor_profile_call_does_not_supply_a_fallback_limit(monkeypatch) -> None:
    """An unset client limit remains unset instead of using a stage cap."""
    _stub_actor_context(monkeypatch)
    client = MagicMock(max_completion_tokens=None)
    client.complete.side_effect = RuntimeError("stop after invocation")

    with pytest.raises(RuntimeError, match="stop after invocation"):
        actor._call_actor_profile(
            seed=MagicMock(),
            profile=MagicMock(zones_active=[]),
            client=client,
            use_case="test",
        )

    assert client.complete.call_args.kwargs["max_completion_tokens"] is None


def test_actor_profile_call_supports_compact_response_schema(monkeypatch) -> None:
    """The lifecycle's causal retry can select the compact provider schema."""
    _stub_actor_context(monkeypatch)
    client = MagicMock(max_completion_tokens=2048)
    client.complete.return_value = _successful_actor_result()

    actor._call_actor_profile(
        seed=MagicMock(min_complexity=None),
        profile=MagicMock(zones_active=[]),
        client=client,
        use_case="test",
        compact_response_schema=True,
    )

    assert client.complete.call_args.kwargs["response_format"] is actor.CompactCall0Response


def test_actor_profile_length_failure_is_typed_and_never_retried(monkeypatch) -> None:
    """One invocation performs exactly one completion; length is typed data.

    The stage helper no longer owns the corrective retry — the shared
    adapter raises typed CompletionLengthError evidence and the lifecycle
    decides.  A second completion in the same invocation can never happen.
    """
    from asago_scenario_generator.llm.client import CompletionLengthError

    _stub_actor_context(monkeypatch)
    client = MagicMock(max_completion_tokens=16384)
    client.complete.side_effect = CompletionLengthError(
        prompt_tokens=31, completion_tokens=16
    )

    with pytest.raises(CompletionLengthError) as excinfo:
        actor._call_actor_profile(
            seed=MagicMock(min_complexity=None),
            profile=MagicMock(zones_active=[]),
            client=client,
            use_case="test",
        )

    assert client.complete.call_count == 1
    request = client.complete.call_args.kwargs
    assert request["max_completion_tokens"] == 16384
    assert request["response_format"] is actor.Call0Response
    assert excinfo.value.prompt_tokens == 31
    assert excinfo.value.completion_tokens == 16
    assert excinfo.value.finish_reason == "length"


def test_actor_profile_lifecycle_retry_reuses_limit_with_suffix(monkeypatch) -> None:
    """A lifecycle re-invocation retries once with the same limit and suffix.

    The retry is an explicit second stage invocation (the finalization
    lifecycle's single completion-length retry), not a hidden helper loop:
    each invocation still performs exactly one completion.
    """
    _stub_actor_context(monkeypatch)
    client = MagicMock(max_completion_tokens=16384)
    client.complete.side_effect = [
        _successful_actor_result(),
        _successful_actor_result(),
    ]

    first = actor._call_actor_profile(
        seed=MagicMock(min_complexity=None),
        profile=MagicMock(zones_active=[]),
        client=client,
        use_case="test",
    )
    suffix = (
        "Return only a schema-matching object with bounded lists and "
        "concise prose."
    )
    actor._call_actor_profile(
        seed=MagicMock(min_complexity=None),
        profile=MagicMock(zones_active=[]),
        client=client,
        use_case="test",
        completion_length_feedback=suffix,
    )

    assert client.complete.call_count == 2
    first_request, retry_request = [
        call.kwargs for call in client.complete.call_args_list
    ]
    assert first_request["user_prompt"] != retry_request["user_prompt"]
    assert retry_request["user_prompt"] == first_request["user_prompt"] + suffix
    assert retry_request["max_completion_tokens"] == 16384
    assert first[1].content is not None


@pytest.mark.parametrize("invalid_floor", ["context", "seed"])
def test_invalid_capability_floor_values_are_ignored(monkeypatch, invalid_floor) -> None:
    """Malformed internal floor data must not turn a valid response into an error."""
    client = MagicMock(max_completion_tokens=2048)
    client.complete.return_value = _successful_actor_result()

    minimum_capability_level = "not-a-capability-level" if invalid_floor == "context" else None
    seed_min_complexity = "not-a-capability-level" if invalid_floor == "seed" else None
    monkeypatch.setattr(
        actor,
        "build_call0_context",
        lambda **_kwargs: {
            "tool_inventory": [],
            "minimum_capability_level": minimum_capability_level,
            "diversity_limitation": None,
        },
    )
    monkeypatch.setattr(actor, "render_prompt", lambda *_args, **_kwargs: "prompt")

    result = actor._call_actor_profile(
        seed=MagicMock(seed_id="seed-1", min_complexity=seed_min_complexity),
        profile=MagicMock(zones_active=[]),
        client=client,
        use_case="test",
    )

    assert result[0].capability_level == "intermediate"

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


def test_actor_profile_length_failure_gets_one_concise_retry(monkeypatch) -> None:
    """A length failure is retried once with feedback and the same limit."""

    class LengthFinishReasonError(Exception):
        pass

    monkeypatch.setattr(actor, "LengthFinishReasonError", LengthFinishReasonError)
    _stub_actor_context(monkeypatch)
    client = MagicMock(max_completion_tokens=16384)
    client.complete.side_effect = [
        LengthFinishReasonError("completion truncated"),
        _successful_actor_result(),
    ]

    actor._call_actor_profile(
        seed=MagicMock(min_complexity=None),
        profile=MagicMock(zones_active=[]),
        client=client,
        use_case="test",
    )

    assert client.complete.call_count == 2
    first, retry = [call.kwargs for call in client.complete.call_args_list]
    assert first["max_completion_tokens"] == 16384
    assert retry["max_completion_tokens"] == 16384
    assert retry["user_prompt"].endswith(
        "The prior response was truncated. Return only a concise "
        "schema-matching response with no explanation."
    )


def test_actor_profile_length_retry_is_bounded(monkeypatch) -> None:
    """A second length failure is surfaced without a third completion."""

    class LengthFinishReasonError(Exception):
        pass

    monkeypatch.setattr(actor, "LengthFinishReasonError", LengthFinishReasonError)
    _stub_actor_context(monkeypatch)
    client = MagicMock(max_completion_tokens=16384)
    client.complete.side_effect = [
        LengthFinishReasonError("first truncation"),
        LengthFinishReasonError("second truncation"),
    ]

    with pytest.raises(LengthFinishReasonError, match="second truncation"):
        actor._call_actor_profile(
            seed=MagicMock(),
            profile=MagicMock(zones_active=[]),
            client=client,
            use_case="test",
        )

    assert client.complete.call_count == 2
    assert all(
        call.kwargs["max_completion_tokens"] == 16384
        for call in client.complete.call_args_list
    )

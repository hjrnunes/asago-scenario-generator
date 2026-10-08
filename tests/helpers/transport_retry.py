"""Shared test builders moved out of test modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import httpx
import openai
from openai.types.chat import ChatCompletion
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from tests.helpers.provider_call_record import (
    _Answer,
    _answer,
    _http_response,
    _Provider,
)


_REQUEST = httpx.Request("POST", "https://provider.invalid/v1/chat")


def _connection_error() -> openai.APIConnectionError:
    return openai.APIConnectionError(message="connection reset", request=_REQUEST)


def _status_error(status: int) -> openai.APIStatusError:
    if status == 429:
        return openai.RateLimitError(
            "slow down", response=_http_response(429), body=None
        )
    if status >= 500:
        return openai.InternalServerError(
            "upstream failed", response=_http_response(status), body=None
        )
    return openai.BadRequestError(
        "bad request", response=_http_response(status), body=None
    )


def _failing_then(*failures: BaseException) -> _Provider:
    """Raise each failure in turn, then answer."""
    pending = list(failures)

    def respond(**kwargs: Any) -> ChatCompletion:
        if pending:
            raise pending.pop(0)
        return _answer()

    return _Provider(respond)


def _call(client: Any, tmp_path: Path) -> Any:
    return call_with_policy(
        llm_client=client,
        system_prompt="s",
        user_prompt="u",
        response_format=_Answer,
        run_dir=tmp_path,
        stage="stage_x",
        step="call_answer",
        policy=CorrectionPolicy(),
    )

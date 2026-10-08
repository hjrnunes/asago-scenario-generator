"""Shared test builders moved out of test modules."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any
import httpx
from openai.types.chat import ChatCompletion
from pydantic import BaseModel
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.provider_record import RECORD_FILENAME


ENDPOINT = "http://fake-endpoint.invalid/v1"


SECRET = "sk-test-secret-value"


HEADER_SECRET = "header-secret-value"


class _Answer(BaseModel):
    answer: str


def _completion(
    content: str | None,
    *,
    finish_reason: str = "stop",
    response_id: str = "chatcmpl-test-1",
) -> ChatCompletion:
    return ChatCompletion.model_validate(
        {
            "id": response_id,
            "object": "chat.completion",
            "created": 1_700_000_000,
            "model": "served-model-name",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": finish_reason,
                    "message": {"role": "assistant", "content": content},
                }
            ],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 7,
                "total_tokens": 18,
            },
        }
    )


class _Provider:
    """Stand-in for the OpenAI SDK client: one scripted function per request."""

    def __init__(self, respond: Any) -> None:
        self.respond = respond
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        completions = SimpleNamespace(create=self._create)
        self.chat = SimpleNamespace(completions=completions)

    def _create(self, **kwargs: Any) -> ChatCompletion:
        with self._lock:
            self.requests.append(kwargs)
        return self.respond(**kwargs)


def _client(provider: _Provider | None = None, **overrides: Any) -> LLMClient:
    settings: dict[str, Any] = {
        "base_url": ENDPOINT,
        "api_key": SECRET,
        "model": "scripted-model",
        "extra_headers": {"X-Auth": HEADER_SECRET},
        "temperature": 0.4,
        "max_completion_tokens": 2048,
    }
    settings.update(overrides)
    client = LLMClient(**settings)
    if provider is not None:
        client._client = provider
    return client


def _records(directory: Path) -> list[dict[str, Any]]:
    path = directory / RECORD_FILENAME
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _answer(**kwargs: Any) -> ChatCompletion:
    return _completion('{"answer": "42"}')


def _http_response(status: int) -> httpx.Response:
    return httpx.Response(
        status, request=httpx.Request("POST", "https://provider.invalid/v1/chat")
    )

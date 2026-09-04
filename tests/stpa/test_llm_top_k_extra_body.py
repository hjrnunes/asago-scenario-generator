"""Unit tests for LLM top_k routing through extra_body.

Covers LLM-TOPK-01 through LLM-TOPK-06 from the Gherkin feature file:
  features/sp1_llm_top_k_extra_body.feature

Tests verify that top_k is routed through extra_body instead of as a
top-level kwarg, and that standard params remain top-level kwargs.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMClient


class _DummyResponse:
    """Minimal mock response object for the OpenAI SDK.

    ``parsed`` is returned for structured (parse) calls; ``content`` for
    unstructured (create) calls.
    """

    def __init__(
        self, *, parsed: Any = None, content: str = "response text"
    ) -> None:
        message = type("M", (), {"parsed": parsed, "content": content})()
        self.choices = [type("C", (), {"message": message})()]
        self.usage = type("U", (), {"prompt_tokens": 10, "completion_tokens": 20})()


def _make_client(
    base_url: str = "http://test:8080",
    top_k: int | None = None,
    top_p: float | None = None,
    temperature: float | None = None,
    max_completion_tokens: int | None = None,
) -> LLMClient:
    """Build an LLMClient with patched OpenAI SDK so __init__ doesn't fail."""
    with patch("asago_scenario_generator.stpa.infra.llm.OpenAI"):
        return LLMClient(
            base_url=base_url,
            top_k=top_k,
            top_p=top_p,
            temperature=temperature,
            max_completion_tokens=max_completion_tokens,
        )


# ---------------------------------------------------------------------------
# LLM-TOPK-01: top_k routed through extra_body, not as top-level kwarg
# ---------------------------------------------------------------------------


class TestTopKRoutedThroughExtraBody:
    """LLM-TOPK-01: top_k goes into extra_body, not as a top-level kwarg."""

    def test_topk_01_top_k_not_top_level_but_in_extra_body(self):
        """top_k is absent from top-level kwargs but present in extra_body."""
        client = _make_client(top_k=40)
        kwargs = client._build_extra_kwargs(None, 0.4)
        assert "top_k" not in kwargs
        assert "extra_body" in kwargs
        assert kwargs["extra_body"]["top_k"] == 40


# ---------------------------------------------------------------------------
# LLM-TOPK-02: top_p remains a top-level kwarg
# ---------------------------------------------------------------------------


class TestTopPRemainsTopLevel:
    """LLM-TOPK-02: top_p stays as a top-level kwarg, not in extra_body."""

    def test_topk_02_top_p_is_top_level_not_in_extra_body(self):
        """top_p is a top-level kwarg and not inside extra_body."""
        client = _make_client(top_p=0.9, top_k=40)
        kwargs = client._build_extra_kwargs(None, 0.4)
        assert kwargs["top_p"] == 0.9
        assert "top_p" not in kwargs.get("extra_body", {})


# ---------------------------------------------------------------------------
# LLM-TOPK-03: temperature and max_completion_tokens remain top-level
# ---------------------------------------------------------------------------


class TestStandardParamsTopLevel:
    """LLM-TOPK-03: temperature and max_completion_tokens stay top-level."""

    def test_topk_03_temperature_and_max_tokens_top_level(self):
        """temperature and max_completion_tokens are top-level kwargs."""
        client = _make_client(top_k=40)
        kwargs = client._build_extra_kwargs(2048, 0.7)
        assert kwargs["temperature"] == 0.7
        assert kwargs["max_completion_tokens"] == 2048


# ---------------------------------------------------------------------------
# LLM-TOPK-04: top_k None means no extra_body
# ---------------------------------------------------------------------------


class TestTopKNoneNoExtraBody:
    """LLM-TOPK-04: when top_k is None, no extra_body is added."""

    def test_topk_04_no_extra_body_when_top_k_none(self):
        """When top_k is None, kwargs has no extra_body and no top_k."""
        client = _make_client(top_k=None)
        kwargs = client._build_extra_kwargs(None, 0.4)
        assert "extra_body" not in kwargs
        assert "top_k" not in kwargs


# ---------------------------------------------------------------------------
# LLM-TOPK-05: top_k forwarded while retaining raw structured responses
# ---------------------------------------------------------------------------


class TestTopKInStructuredCreateCall:
    """LLM-TOPK-05: structured create keeps top_k and the raw response."""

    @pytest.mark.parametrize("top_k_value", [40, 1])
    def test_topk_05_create_call_includes_extra_body_top_k(self, top_k_value):
        """The create call receives both strict schema and nested top_k."""
        client = _make_client(top_k=top_k_value)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _DummyResponse(
            content='{"val": 1}'
        )
        client._client = mock_client

        class _Model(BaseModel):
            val: int = 0

        client.complete(
            system_prompt="s",
            user_prompt="u",
            response_format=_Model,
        )

        create_call = mock_client.chat.completions.create
        assert create_call.called
        call_kwargs = create_call.call_args.kwargs
        assert "extra_body" in call_kwargs
        assert call_kwargs["extra_body"]["top_k"] == top_k_value
        assert "top_k" not in call_kwargs
        assert call_kwargs["response_format"]["type"] == "json_schema"


# ---------------------------------------------------------------------------
# LLM-TOPK-06: top_k forwarded in extra_body for unstructured create calls
# ---------------------------------------------------------------------------


class TestTopKInUnstructuredCreateCall:
    """LLM-TOPK-06: top_k is forwarded via extra_body in chat.completions.create()."""

    def test_topk_06_create_call_includes_extra_body_top_k(self):
        """The create call receives extra_body with top_k, not a top-level top_k."""
        client = _make_client(top_k=40)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _DummyResponse()
        client._client = mock_client

        client.complete(
            system_prompt="s",
            user_prompt="u",
            response_format=None,
        )

        create_call = mock_client.chat.completions.create
        assert create_call.called
        call_kwargs = create_call.call_args.kwargs
        assert "extra_body" in call_kwargs
        assert call_kwargs["extra_body"]["top_k"] == 40
        assert "top_k" not in call_kwargs

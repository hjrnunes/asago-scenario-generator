"""Unit and property tests for LLM top_k routing through extra_body.

Covers LLM-TOPK-01 through LLM-TOPK-06. top_k goes into extra_body, never
into the top-level kwargs, and the standard parameters stay top-level.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMClient


class _DummyResponse:
    """Minimal mock response object for the OpenAI SDK.

    ``parsed`` is returned for structured (parse) calls; ``content`` for
    unstructured (create) calls.
    """

    def __init__(self, *, parsed: Any = None, content: str = "response text") -> None:
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


st_top_k = st.one_of(st.none(), st.integers(min_value=1, max_value=200))
st_top_p = st.one_of(
    st.none(), st.floats(min_value=0.0, max_value=1.0, allow_nan=False)
)
st_temperature = st.floats(min_value=0.0, max_value=2.0, allow_nan=False)
st_max_tokens = st.one_of(st.none(), st.integers(min_value=1, max_value=100000))


def _expected_kwargs(top_k, top_p, temperature, max_tokens) -> dict[str, Any]:
    expected: dict[str, Any] = {"temperature": temperature}
    if top_p is not None:
        expected["top_p"] = top_p
    if max_tokens is not None:
        expected["max_completion_tokens"] = max_tokens
    if top_k is not None:
        expected["extra_body"] = {"top_k": top_k}
    return expected


class TestExtraKwargsShape:
    """LLM-TOPK-01 to LLM-TOPK-04: top_k lives only in extra_body; the rest is top-level."""

    def test_pinned_example(self):
        client = _make_client(top_k=40, top_p=0.9)
        assert client._build_extra_kwargs(2048, 0.7) == {
            "temperature": 0.7,
            "top_p": 0.9,
            "max_completion_tokens": 2048,
            "extra_body": {"top_k": 40},
        }

    @given(
        top_k=st_top_k,
        top_p=st_top_p,
        temperature=st_temperature,
        max_tokens=st_max_tokens,
    )
    @settings(max_examples=100, deadline=None)
    def test_kwargs_have_exactly_the_routed_shape(
        self, top_k, top_p, temperature, max_tokens
    ):
        client = _make_client(
            top_k=top_k,
            top_p=top_p,
            temperature=temperature,
            max_completion_tokens=max_tokens,
        )
        assert client._build_extra_kwargs(max_tokens, temperature) == _expected_kwargs(
            top_k, top_p, temperature, max_tokens
        )


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

"""Property-based tests for LLM top_k routing through extra_body.

These tests verify invariants that hold across broad input ranges:

- **top_k never top-level**: top_k never appears as a top-level kwarg.
- **extra_body present when top_k set**: when top_k is not None, extra_body
  contains top_k with the correct value.
- **extra_body absent when top_k None**: when top_k is None, no extra_body.
- **temperature always top-level**: temperature is always a top-level kwarg.
- **max_completion_tokens top-level when set**: when effective_max is not
  None, it appears as a top-level kwarg.
- **top_p top-level when set**: when top_p is not None, it appears as a
  top-level kwarg and never inside extra_body.
- **extra_body contains only top_k**: extra_body never leaks standard params.
"""

from __future__ import annotations

from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from asago_scenario_generator.stpa.infra.llm import LLMClient

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

st_top_k = st.one_of(st.none(), st.integers(min_value=1, max_value=200))
st_top_p = st.one_of(
    st.none(), st.floats(min_value=0.0, max_value=1.0, allow_nan=False)
)
st_temperature = st.floats(min_value=0.0, max_value=2.0, allow_nan=False)
st_max_tokens = st.one_of(st.none(), st.integers(min_value=1, max_value=100000))


def _make_client(
    top_k=None,
    top_p=None,
    temperature=None,
    max_completion_tokens=None,
) -> LLMClient:
    """Build an LLMClient with patched OpenAI SDK so __init__ doesn't fail."""
    with patch("asago_scenario_generator.stpa.infra.llm.OpenAI"):
        return LLMClient(
            base_url="http://test:8080",
            top_k=top_k,
            top_p=top_p,
            temperature=temperature,
            max_completion_tokens=max_completion_tokens,
        )


# ---------------------------------------------------------------------------
# top_k never appears as a top-level kwarg
# ---------------------------------------------------------------------------


class TestTopKNeverTopLevel:
    """top_k is never a top-level kwarg, regardless of its value."""

    @given(
        top_k=st_top_k,
        top_p=st_top_p,
        temperature=st_temperature,
        max_tokens=st_max_tokens,
    )
    @settings(max_examples=60, deadline=None)
    def test_top_k_not_top_level(self, top_k, top_p, temperature, max_tokens):
        """top_k is never a key in the returned kwargs dict."""
        client = _make_client(
            top_k=top_k,
            top_p=top_p,
            temperature=temperature,
            max_completion_tokens=max_tokens,
        )
        kwargs = client._build_extra_kwargs(max_tokens, temperature)
        assert "top_k" not in kwargs


# ---------------------------------------------------------------------------
# extra_body present when top_k is set
# ---------------------------------------------------------------------------


class TestExtraBodyPresentWhenTopKSet:
    """When top_k is not None, extra_body contains top_k with the correct value."""

    @given(top_k=st.integers(min_value=1, max_value=200))
    @settings(max_examples=50, deadline=None)
    def test_extra_body_contains_top_k(self, top_k):
        """extra_body is present and contains top_k with the right value."""
        client = _make_client(top_k=top_k)
        kwargs = client._build_extra_kwargs(None, 0.4)
        assert "extra_body" in kwargs
        assert kwargs["extra_body"]["top_k"] == top_k


# ---------------------------------------------------------------------------
# extra_body absent when top_k is None
# ---------------------------------------------------------------------------


class TestExtraBodyAbsentWhenTopKNone:
    """When top_k is None, no extra_body key is present."""

    @given(
        top_p=st_top_p,
        temperature=st_temperature,
        max_tokens=st_max_tokens,
    )
    @settings(max_examples=40, deadline=None)
    def test_no_extra_body_when_top_k_none(self, top_p, temperature, max_tokens):
        """When top_k is None, kwargs has no extra_body."""
        client = _make_client(
            top_k=None,
            top_p=top_p,
            temperature=temperature,
            max_completion_tokens=max_tokens,
        )
        kwargs = client._build_extra_kwargs(max_tokens, temperature)
        assert "extra_body" not in kwargs


# ---------------------------------------------------------------------------
# temperature always top-level
# ---------------------------------------------------------------------------


class TestTemperatureAlwaysTopLevel:
    """temperature is always a top-level kwarg."""

    @given(
        top_k=st_top_k,
        temperature=st_temperature,
        max_tokens=st_max_tokens,
    )
    @settings(max_examples=50, deadline=None)
    def test_temperature_is_top_level(self, top_k, temperature, max_tokens):
        """temperature is always present as a top-level kwarg."""
        client = _make_client(top_k=top_k, temperature=temperature)
        kwargs = client._build_extra_kwargs(max_tokens, temperature)
        assert kwargs["temperature"] == temperature


# ---------------------------------------------------------------------------
# max_completion_tokens top-level when set
# ---------------------------------------------------------------------------


class TestMaxTokensTopLevelWhenSet:
    """When effective_max is not None, it appears as a top-level kwarg."""

    @given(
        top_k=st_top_k,
        max_tokens=st.integers(min_value=1, max_value=100000),
    )
    @settings(max_examples=40, deadline=None)
    def test_max_tokens_top_level_when_set(self, top_k, max_tokens):
        """max_completion_tokens is a top-level kwarg when provided."""
        client = _make_client(top_k=top_k)
        kwargs = client._build_extra_kwargs(max_tokens, 0.4)
        assert kwargs["max_completion_tokens"] == max_tokens


# ---------------------------------------------------------------------------
# top_p top-level when set, never in extra_body
# ---------------------------------------------------------------------------


class TestTopPTopLevelNeverInExtraBody:
    """top_p is a top-level kwarg when set and never inside extra_body."""

    @given(
        top_k=st_top_k,
        top_p=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    )
    @settings(max_examples=50, deadline=None)
    def test_top_p_top_level_not_in_extra_body(self, top_k, top_p):
        """top_p is top-level and not inside extra_body."""
        client = _make_client(top_k=top_k, top_p=top_p)
        kwargs = client._build_extra_kwargs(None, 0.4)
        assert kwargs["top_p"] == top_p
        assert "top_p" not in kwargs.get("extra_body", {})


# ---------------------------------------------------------------------------
# extra_body contains only top_k (no standard param leakage)
# ---------------------------------------------------------------------------


class TestExtraBodyContainsOnlyTopK:
    """extra_body never leaks standard OpenAI parameters."""

    @given(
        top_k=st.integers(min_value=1, max_value=200),
        top_p=st_top_p,
        temperature=st_temperature,
        max_tokens=st_max_tokens,
    )
    @settings(max_examples=60, deadline=None)
    def test_extra_body_has_only_top_k(self, top_k, top_p, temperature, max_tokens):
        """extra_body contains only the top_k key, no standard params."""
        client = _make_client(
            top_k=top_k,
            top_p=top_p,
            temperature=temperature,
            max_completion_tokens=max_tokens,
        )
        kwargs = client._build_extra_kwargs(max_tokens, temperature)
        if "extra_body" in kwargs:
            assert set(kwargs["extra_body"].keys()) == {"top_k"}

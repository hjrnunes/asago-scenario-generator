"""Tests for provider-authored semantic proposition normalization."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.semantic_conditions import (
    normalize_semantic_proposition,
)


class TestNormalizeSemanticProposition:
    def test_strips_surrounding_whitespace(self) -> None:
        assert (
            normalize_semantic_proposition("  The reply leaks the secret.  ")
            == "The reply leaks the secret."
        )

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_missing_or_blank_text_is_none_when_optional(self, value) -> None:
        assert normalize_semantic_proposition(value) is None

    def test_missing_text_is_rejected_when_required(self) -> None:
        with pytest.raises(ValueError, match="is required for output-text"):
            normalize_semantic_proposition(None, required=True)

    def test_blank_text_is_rejected_when_required(self) -> None:
        with pytest.raises(ValueError, match="must be non-empty"):
            normalize_semantic_proposition("  ", required=True)

    def test_non_string_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be a string or null"):
            normalize_semantic_proposition(7)  # type: ignore[arg-type]

    def test_length_limit_is_inclusive(self) -> None:
        longest = "a" * 600

        assert normalize_semantic_proposition(longest) == longest
        with pytest.raises(ValueError, match="at most 600 characters"):
            normalize_semantic_proposition(longest + "a")

    @pytest.mark.parametrize("separator", ["\n", "\r"])
    def test_line_breaks_are_rejected(self, separator) -> None:
        with pytest.raises(ValueError, match="one plain line"):
            normalize_semantic_proposition(f"first{separator}second")

    @pytest.mark.parametrize(
        "text",
        ["Fetch https://example.test/x", "Open www.example.test", "Use ftp://host"],
    )
    def test_runtime_urls_are_rejected(self, text) -> None:
        with pytest.raises(ValueError, match="runtime URL"):
            normalize_semantic_proposition(text)

    @pytest.mark.parametrize("text", ["Violates SC-1-2 here", "See CA-1-1"])
    def test_structural_identifiers_are_rejected(self, text) -> None:
        with pytest.raises(ValueError, match="structural identifiers"):
            normalize_semantic_proposition(text)

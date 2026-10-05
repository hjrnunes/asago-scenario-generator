"""Tests for provider-authored semantic proposition normalization."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.semantic_conditions import (
    WindowCondition,
    normalize_semantic_proposition,
)

_PLACEHOLDER = {
    "binding_ref": "SEM-window",
    "value_type": "integer",
    "description": "Window bound",
}


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


class TestWindowCondition:
    @pytest.mark.parametrize(
        ("window_from", "window_to"),
        [(0, 0), (10, 250), (_PLACEHOLDER, 5), (500, _PLACEHOLDER)],
    )
    def test_ordered_or_bound_windows_are_accepted(
        self, window_from: object, window_to: object
    ) -> None:
        condition = WindowCondition.model_validate(
            {
                "reference_ref": "S-1",
                "window_from_ms": window_from,
                "window_to_ms": window_to,
            }
        )

        assert condition.type == "window"

    @pytest.mark.parametrize(
        ("reference", "window_from", "window_to", "message"),
        [
            ("H-1", 0, 1, "reference_ref must resolve"),
            ("CA-1", -1, 1, "window_from_ms must be non-negative"),
            ("CA-1", 0, 1.5, "window_to_ms must be a non-negative integer"),
            ("CA-1", 9, 3, "window_from_ms must not exceed window_to_ms"),
        ],
    )
    def test_invalid_windows_are_rejected(
        self, reference: str, window_from: object, window_to: object, message: str
    ) -> None:
        with pytest.raises(ValueError, match=message):
            WindowCondition.model_validate(
                {
                    "reference_ref": reference,
                    "window_from_ms": window_from,
                    "window_to_ms": window_to,
                }
            )

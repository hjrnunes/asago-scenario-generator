"""Unit tests for SP2 Stage 3 — N/A quality gates."""

from __future__ import annotations

from asago_scenario_generator.stpa.threat_enum.na_quality import check_structural_keywords


# ---------------------------------------------------------------------------
# Structural keyword check — pass cases (SP2-NA-01, SP2-NA-03)
# ---------------------------------------------------------------------------


class TestStructuralKeywordPass:
    """N/A justification with structural keyword passes."""

    def test_discrete(self):
        assert check_structural_keywords("Action is discrete") is True

    def test_continuous(self):
        assert check_structural_keywords("Action is continuous") is True

    def test_stateless(self):
        assert check_structural_keywords("Action is stateless") is True

    def test_stateful(self):
        assert check_structural_keywords("Action is stateful") is True

    def test_atomic(self):
        assert check_structural_keywords("Action is atomic") is True

    def test_one_shot(self):
        assert check_structural_keywords("Action is one-shot") is True

    def test_no_duration(self):
        assert check_structural_keywords("the action has no duration component") is True

    def test_none_justification(self):
        assert check_structural_keywords(None) is False


# ---------------------------------------------------------------------------
# Structural keyword check — flag case (SP2-NA-02)
# ---------------------------------------------------------------------------


class TestStructuralKeywordFlag:
    """N/A justification without structural keyword is flagged."""

    def test_no_structural_keyword(self):
        assert check_structural_keywords(
            "this control action has no hazardous context"
        ) is False


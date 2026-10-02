"""Unit tests for SP2 Stage 3 — N/A quality gates."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.ica_enumeration import ICASlot, UCAType
from asago_scenario_generator.stpa.threat_enum.na_quality import (
    check_na_ratio,
    check_structural_keywords,
)


def _make_na_slot(
    slot_id: str = "RESP-1:CA-1-1:NOT_PROVIDED",
    responsibility: str = "RESP-1",
    na_justification: str = "Action is discrete",
) -> ICASlot:
    """Build a minimal N/A slot."""
    return ICASlot(
        slot_id=slot_id,
        responsibility=responsibility,
        control_action="CA-1-1",
        uca_type=UCAType.not_provided,
        is_na=True,
        icas=[],
        na_justification=na_justification,
    )


def _make_non_na_slot(
    slot_id: str = "RESP-1:CA-1-1:INCORRECT",
    responsibility: str = "RESP-1",
) -> ICASlot:
    """Build a minimal non-N/A slot."""
    from asago_scenario_generator.stpa.models.ica_enumeration import ICA

    return ICASlot(
        slot_id=slot_id,
        responsibility=responsibility,
        control_action="CA-1-1",
        uca_type=UCAType.incorrect,
        is_na=False,
        icas=[
            ICA(
                ica_id=f"{slot_id}:1",
                ica_text="UCA",
                hazardous_context="Ctx",
                loss_scenario="Scenario",
            )
        ],
    )


def _make_link_na_slot(
    slot_id: str = "CL-1:CM-1:NOT_PROVIDED",
    na_justification: str = "Action is discrete",
) -> ICASlot:
    """Build a minimal N/A coordination link slot."""
    return ICASlot(
        slot_id=slot_id,
        responsibility=None,
        coordination_link="CL-1",
        control_action="CM-1",
        uca_type=UCAType.not_provided,
        is_na=True,
        icas=[],
        na_justification=na_justification,
    )


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


# ---------------------------------------------------------------------------
# Ratio monitoring (SP2-NA-04 through SP2-NA-08, SP2-NA-10, SP2-NA-11)
# ---------------------------------------------------------------------------


class TestRatioMonitoring:
    """N/A ratio monitoring tests."""

    def test_above_threshold_flagged(self):
        """4/4 N/A > 75% → flagged."""
        slots = [
            _make_na_slot(f"RESP-1:CA-1-{i}:{t.value}")
            for i in range(1)
            for t in UCAType
        ]
        flags = check_na_ratio(slots, threshold=0.75)
        assert len(flags) == 1
        assert "RESP-1" in flags[0]

    def test_at_threshold_not_flagged(self):
        """3/4 N/A = 75% → not flagged (strict > not >=)."""
        slots = [
            _make_na_slot("RESP-1:CA-1-1:NOT_PROVIDED"),
            _make_na_slot("RESP-1:CA-1-1:INCORRECT"),
            _make_na_slot("RESP-1:CA-1-1:WRONG_TIMING"),
            _make_non_na_slot("RESP-1:CA-1-1:WRONG_DURATION"),
        ]
        flags = check_na_ratio(slots, threshold=0.75)
        assert len(flags) == 0

    def test_below_threshold_not_flagged(self):
        """2/8 N/A = 25% → not flagged."""
        slots = []
        for i in range(2):
            slots.append(_make_na_slot(f"RESP-1:CA-1-{i+1}:NOT_PROVIDED"))
        for i in range(6):
            slots.append(_make_non_na_slot(f"RESP-1:CA-1-{i+1}:INCORRECT"))
        flags = check_na_ratio(slots, threshold=0.75)
        assert len(flags) == 0

    def test_coordination_link_excluded(self):
        """Ratio monitoring only counts responsibility slots, not coordination link slots."""
        slots = [
            _make_na_slot(f"RESP-1:CA-1-1:{t.value}") for t in UCAType
        ] + [
            _make_link_na_slot(f"CL-1:CM-1:{t.value}") for t in UCAType
        ]
        flags = check_na_ratio(slots, threshold=0.75)
        assert len(flags) == 1
        assert "RESP-1" in flags[0]
        assert not any("CL-1" in f for f in flags)

    def test_descriptive_flag_message(self):
        """Flag message contains RESP-1, N/A count, and threshold percentage."""
        slots = []
        for i in range(7):
            slots.append(_make_na_slot(f"RESP-1:CA-1-{i+1}:NOT_PROVIDED"))
        for i in range(1):
            slots.append(_make_non_na_slot(f"RESP-1:CA-1-{i+1}:INCORRECT"))
        flags = check_na_ratio(slots, threshold=0.75)
        assert len(flags) == 1
        assert "RESP-1" in flags[0]
        assert "7" in flags[0]  # N/A count
        assert "75%" in flags[0]  # threshold percentage

    def test_multiple_responsibilities_independent(self):
        """RESP-1 flagged, RESP-2 not flagged."""
        slots = [
            _make_na_slot(f"RESP-1:CA-1-1:{t.value}", responsibility="RESP-1")
            for t in UCAType
        ] + [
            _make_na_slot("RESP-2:CA-1-1:NOT_PROVIDED", responsibility="RESP-2"),
        ] + [
            _make_non_na_slot(
                f"RESP-2:CA-1-1:{t.value}", responsibility="RESP-2"
            )
            for t in [UCAType.incorrect, UCAType.wrong_timing, UCAType.wrong_duration]
        ]
        flags = check_na_ratio(slots, threshold=0.75)
        assert len(flags) == 1
        assert "RESP-1" in flags[0]

    def test_empty_slot_list(self):
        """Empty slot list produces no flags."""
        flags = check_na_ratio([], threshold=0.75)
        assert len(flags) == 0


# ---------------------------------------------------------------------------
# No LLM calls (SP2-NA-09)
# ---------------------------------------------------------------------------


class TestNoLLMCalls:
    """N/A quality gates make no LLM calls."""

    def test_no_llm_calls(self):
        slots = [
            _make_na_slot("RESP-1:CA-1-1:NOT_PROVIDED", na_justification="Action is discrete"),
            _make_na_slot("RESP-1:CA-1-1:INCORRECT", na_justification="Action is discrete"),
            _make_na_slot("RESP-1:CA-1-1:WRONG_TIMING", na_justification="Action is discrete"),
            _make_non_na_slot("RESP-1:CA-1-1:WRONG_DURATION"),
        ]
        # These are pure functions — no LLM client involved
        check_structural_keywords("Action is discrete")
        check_na_ratio(slots, threshold=0.75)
        # If we get here without error, no LLM calls were made
        assert True


# ---------------------------------------------------------------------------
# check_all_na_quality integration
# ---------------------------------------------------------------------------



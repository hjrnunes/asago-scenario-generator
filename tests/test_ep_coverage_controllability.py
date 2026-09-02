"""Tests for entry point coverage metric fix and controllability reclassification.

Bead m4a6: preserve reviewed controllability declarations during entry-point
classification.
"""

from __future__ import annotations

from asago_scenario_generator.pipeline.candidates import classify_entry_point


class TestControllabilityReclassification:
    """classify_entry_point() preserves explicit 'system' controllability
    regardless of direction — a reviewed profile declaring 'system' must
    remain system-controlled (cmps.9 review correction 5)."""

    def test_system_bidirectional_preserved(self):
        """Backend API (bidirectional, system) should remain 'system'."""
        result = classify_entry_point(
            "backend service API calls", "bidirectional", "system"
        )
        assert result == "system"

    def test_system_input_preserved(self):
        """Input-direction with system controllability -> system (preserved)."""
        result = classify_entry_point("scheduled data feed", "input", "system")
        assert result == "system"

    def test_system_output_stays_system(self):
        """Output-only with system controllability -> system (preserved)."""
        result = classify_entry_point(
            "human agent escalation triggers", "output", "system"
        )
        assert result == "system"

    def test_direct_controllability_preserved(self):
        """Explicit 'direct' is never downgraded regardless of direction."""
        assert classify_entry_point("chat", "input", "direct") == "direct"
        assert classify_entry_point("chat", "bidirectional", "direct") == "direct"
        assert classify_entry_point("chat", "output", "direct") == "direct"

    def test_indirect_controllability_preserved(self):
        """Explicit 'indirect' is never changed regardless of direction."""
        assert classify_entry_point("rag", "input", "indirect") == "indirect"
        assert classify_entry_point("rag", "bidirectional", "indirect") == "indirect"
        assert classify_entry_point("rag", "output", "indirect") == "indirect"


class TestControllabilityAdversarial:
    """Adversarial/edge cases for the controllability preservation."""

    def test_system_keyword_input_with_explicit_system(self):
        """An entry point with system keywords AND explicit system controllability
        but input direction: should remain 'system' (explicit preservation)."""
        result = classify_entry_point(
            "internal backend scheduler API", "input", "system"
        )
        assert result == "system"

    def test_no_controllability_system_keyword_input_stays_system(self):
        """Without explicit controllability, system-keyword input EPs use
        the keyword heuristic and remain 'system'."""
        result = classify_entry_point("internal backend scheduler API", "input", None)
        assert result == "system"

    def test_truly_output_only_system_entry_point(self):
        """A genuine output-only system entry point stays 'system'."""
        result = classify_entry_point("monitoring dashboard alerts", "output", "system")
        assert result == "system"

    def test_bidirectional_system_not_direct(self):
        """Explicit 'system' is preserved, not overridden to 'direct' — even
        though the heuristic for bidirectional (without explicit
        controllability) would return 'direct'."""
        result = classify_entry_point(
            "backend service API calls", "bidirectional", "system"
        )
        assert result == "system"
        # Contrast: without explicit controllability, bidirectional -> direct
        result_heuristic = classify_entry_point(
            "backend service API calls", "bidirectional", None
        )
        assert result_heuristic == "direct"

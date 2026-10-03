"""Mutation hardening tests for surviving mutants in capability_profile.py.

These tests kill mutants that survived the initial mutation run because
the STPA test suite did not directly exercise ``classify_entry_point``
or the ``EntryPoint`` frozen model config.

Mutants killed:
- classify_entry_point: controllability is not None -> is None
- classify_entry_point: direction == "output" -> != "output"
- classify_entry_point: direction == "bidirectional" -> != "bidirectional"
- classify_entry_point: indirect keyword `in` -> `not in`
- classify_entry_point: system keyword `in` -> `not in`
- EntryPoint: model_config frozen=True -> False
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.capability_profile import (
    EntryPoint,
    classify_entry_point,
)


class TestClassifyEntryPointExplicitControllability:
    """Kill: controllability is not None -> is None."""

    def test_explicit_direct_with_indirect_keyword_name(self):
        """Explicit 'direct' is returned even when heuristic would say 'indirect'."""
        # "RAG knowledge" has an indirect keyword, so the heuristic would
        # return "indirect".  Explicit controllability="direct" must win.
        assert classify_entry_point("RAG knowledge", "input", "direct") == "direct"

    def test_explicit_indirect_with_direct_keyword_name(self):
        """Explicit 'indirect' is returned even when heuristic would say 'direct'."""
        # "user chat" has a direct keyword, so the heuristic would return
        # "direct".  Explicit controllability="indirect" must win.
        assert classify_entry_point("user chat", "input", "indirect") == "indirect"


class TestClassifyEntryPointOutputDirection:
    """Kill: direction == "output" -> != "output"."""

    def test_output_direction_returns_system(self):
        """Output direction with no controllability returns 'system'."""
        # "alerts" has no keyword, so if the output check is bypassed the
        # heuristic would return "direct" (default).  The original must
        # return "system".
        assert classify_entry_point("alerts", "output", None) == "system"

    def test_output_direction_with_keyword_returns_system(self):
        """Output direction returns 'system' even with a direct keyword."""
        assert classify_entry_point("user response channel", "output", None) == "system"


class TestClassifyEntryPointBidirectionalDirection:
    """Kill: direction == "bidirectional" -> != "bidirectional"."""

    def test_bidirectional_with_indirect_keyword_returns_direct(self):
        """Bidirectional returns 'direct' even when heuristic would say 'indirect'."""
        # "RAG knowledge" has an indirect keyword, so the heuristic would
        # return "indirect".  Bidirectional must return "direct".
        assert (
            classify_entry_point("RAG knowledge-grounding", "bidirectional", None)
            == "direct"
        )


class TestClassifyEntryPointKeywordHeuristics:
    """Kill: indirect/system keyword `in` -> `not in` mutations."""

    def test_system_keyword_returns_system(self):
        """A system-keyword name with input direction returns 'system'.

        If the indirect keyword check is mutated (in -> not in), it would
        incorrectly return "indirect" for this name.
        """
        # "backend API" has no indirect keyword but has system keywords.
        # If the indirect check is mutated, any(kw not in) is True for
        # most indirect keywords, so it would return "indirect".
        assert classify_entry_point("backend API", "input", None) == "system"

    def test_direct_keyword_returns_direct(self):
        """A direct-keyword name with input direction returns 'direct'.

        If the system keyword check is mutated (in -> not in), it would
        incorrectly return "system" for this name.
        """
        # "user chat" has no system keyword but has "user" (direct).
        # If the system check is mutated, any(kw not in) is True for
        # all system keywords, so it would return "system".
        assert classify_entry_point("user chat", "input", None) == "direct"

    def test_indirect_keyword_returns_indirect(self):
        """An indirect-keyword name with input direction returns 'indirect'."""
        assert (
            classify_entry_point("RAG knowledge retrieval", "input", None) == "indirect"
        )

    def test_no_keyword_defaults_to_direct(self):
        """A name with no keywords defaults to 'direct'."""
        assert classify_entry_point("unknown channel", "input", None) == "direct"


class TestEntryPointFrozenConfig:
    """Kill: model_config frozen=True -> frozen=False."""

    def test_frozen_model_rejects_attribute_assignment(self):
        """EntryPoint is frozen — setting an attribute raises ValidationError."""
        ep = EntryPoint(name="test entry point", direction="input")
        with pytest.raises(ValidationError):
            ep.name = "changed name"

    def test_frozen_model_rejects_new_attribute(self):
        """EntryPoint is frozen — setting a new attribute raises ValidationError."""
        ep = EntryPoint(name="test entry point", direction="input")
        with pytest.raises(ValidationError):
            ep.custom_field = "value"

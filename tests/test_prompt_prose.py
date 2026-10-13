"""The prose renderer returns one exact line per section and rejects a typo."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.obligation_aware.prompts import (
    obligation_prompt_template_hashes,
    render_prose,
)


def test_a_section_renders_without_a_line_break_or_trailing_newline() -> None:
    text = render_prose("prose/routing.j2", "ledger_header")

    assert text == "AUTHORITATIVE HAZARD-CONSTRAINT PAIR LEDGER (typed IDs only):"


def test_a_value_passes_through_unchanged() -> None:
    text = render_prose(
        "prose/slot.j2", "slot_description", uca_type="X", action="a  b\n<c>"
    )

    assert (
        text == "X slot for a  b\n<c>; copy this slot handle unchanged in the response."
    )


def test_an_unknown_section_is_rejected() -> None:
    with pytest.raises(ValueError, match="no section 'missing'"):
        render_prose("prose/routing.j2", "missing")


def test_prose_templates_stay_out_of_the_recorded_template_hashes() -> None:
    assert not [name for name in obligation_prompt_template_hashes() if "prose" in name]

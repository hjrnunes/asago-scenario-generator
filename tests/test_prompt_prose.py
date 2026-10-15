"""The prose renderer returns one exact line per section and rejects a typo."""

from __future__ import annotations

import hashlib

import pytest

from asago_scenario_generator.stpa.obligation_aware.prompts import (
    PROMPT_TEMPLATES_DIR,
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


def test_the_recorded_template_hashes_cover_every_prose_template() -> None:
    prose_dir = PROMPT_TEMPLATES_DIR / "prose"
    hashes = obligation_prompt_template_hashes()

    prose = sorted(path.name for path in prose_dir.glob("*.j2"))
    assert prose
    for name in prose:
        expected = hashlib.sha256((prose_dir / name).read_bytes()).hexdigest()
        assert hashes[f"prose/{name}"] == expected
    assert "_uca_method.j2" in hashes

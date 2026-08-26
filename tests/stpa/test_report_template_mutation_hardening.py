"""Adversarial coverage for STPA report template branches."""

from __future__ import annotations

from types import SimpleNamespace

from asago_scenario_generator.stpa.report.template import (
    _advance_docstring_state,
    _build_call_entry_html,
    _build_scenario_card,
    _build_scenario_envelope_body,
    _kc_item_html,
)


def test_advance_docstring_state_exits_without_emitting_a_row() -> None:
    result: list[str] = []

    state, lines = _advance_docstring_state("plain text", False, [], result)

    assert state is False
    assert lines == []
    assert len(result) == 1


def test_kc_item_html_omits_empty_and_duplicate_labels() -> None:
    empty = _kc_item_html("KC1", "")
    duplicate = _kc_item_html("KC1", "KC1")

    assert "<span" not in empty
    assert "<span" not in duplicate


def test_scenario_envelope_body_renders_present_enrichment_sections() -> None:
    envelope = SimpleNamespace(
        scenario_spec=None,
        narrative="",
        attack_tree=None,
        gherkin_raw="",
        system_context=SimpleNamespace(target_responsibility_description="responsibility"),
        consumer_hints=SimpleNamespace(primary_attack_zone="input"),
    )

    body = "\n".join(_build_scenario_envelope_body(envelope))

    assert "System Context" in body
    assert "responsibility" in body
    assert "Consumer Hints" in body
    assert "input" in body


def test_scenario_card_does_not_duplicate_embedded_gherkin() -> None:
    envelope = SimpleNamespace(
        scenario_spec=None,
        narrative="",
        attack_tree=None,
        gherkin_raw="Feature: Embedded",
        system_context=None,
        consumer_hints=None,
    )

    card = _build_scenario_card("scenario-1", envelope, "Feature: On disk")

    assert "Embedded" in card
    assert "On disk" not in card
    assert "Gherkin Spec" not in card


def test_call_entry_defaults_are_successful_and_zero_valued() -> None:
    html = _build_call_entry_html({"stage": "sp1", "step": "step1"}, 0)

    assert "OK" in html
    assert "FAILED" not in html
    assert "tokens=0+0" in html
    assert "duration=0ms" in html

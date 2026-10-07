"""One statement of the ``rule_span`` rule reaches every model-facing copy.

The check that accepts a ``rule_span`` compares it case-insensitively
(``span_quotes_rule``), so the prompts say that, from one template partial.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import (
    Obligation,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    REVISION_CORRECTION_FEEDBACK,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    PermittedChange,
    RepairRecord,
    RepairRejected,
    SelectedObligation,
    _check_obligation_entry,
    _check_permitted_value,
)
from asago_scenario_generator.stpa.system_model.rule_span_repair import (
    RuleSpanRepair,
    RuleSpanRepairRecord,
    record_rule_span_repairs,
    rule_span_requirement,
    span_quotes_rule,
)

STALE_PHRASES = (
    "character-for-character",
    "exact contiguous substring",
    "exact substring",
    "capitalization change",
    "verbatim quote",
)


def _render(name: str, **kwargs: object) -> str:
    return TemplateLoader(PROMPTS_DIR).render_prompt(name, **kwargs)


def _norm(text: str) -> str:
    return " ".join(text.split())


def _set_rule_span_instruction() -> str:
    selected = SelectedObligation(
        constraint_id="SC-1",
        obligation_id="O1",
        original_entry_raw={},
        validation_errors=(),
        permitted_changes=(PermittedChange(kind="set_rule_span"),),
        constraint_rule="The agent must not refund twice.",
    )
    return selected.correction_instruction


COPIES = {
    "derivation and revision paragraph": lambda: _render("_obligation_entries.j2"),
    "repair user prompt": lambda: _render(
        "stage1a_obligation_repair_user.j2",
        use_case_text="Test use case",
        selected_constraints=[],
    ),
    "revision correction feedback": lambda: REVISION_CORRECTION_FEEDBACK,
    "permitted change instruction": _set_rule_span_instruction,
}


def test_the_requirement_says_contiguous_substring_and_case_insensitive() -> None:
    text = rule_span_requirement()

    assert "contiguous substring" in text
    assert "case-insensitive" in text
    assert text == text.strip()


def test_the_requirement_is_the_rendered_partial() -> None:
    assert rule_span_requirement() == _render("_rule_span_requirement.j2").strip()


@pytest.mark.parametrize("name", COPIES)
def test_each_copy_carries_the_requirement(name: str) -> None:
    assert _norm(rule_span_requirement()) in _norm(COPIES[name]())


@pytest.mark.parametrize("name", COPIES)
def test_no_copy_keeps_a_stale_phrasing(name: str) -> None:
    text = _norm(COPIES[name]())

    for phrase in STALE_PHRASES:
        assert phrase not in text, phrase


@pytest.mark.parametrize(
    "template",
    (
        "stage1a_gap_system.j2",
        "stage1a_risk_system.j2",
        "stage1a_graph_revision_system.j2",
        "stage1a_obligation_repair_system.j2",
    ),
)
def test_each_system_prompt_renders_the_requirement(template: str) -> None:
    assert _norm(rule_span_requirement()) in _norm(_render(template))


def test_the_check_the_prompt_describes_ignores_case() -> None:
    rule = "The agent MUST NOT issue a second Refund."

    assert span_quotes_rule(rule, "must not issue a second refund")
    assert not span_quotes_rule(rule, "must not issue second refund")


def _constraint_with_span(span: str) -> SecurityConstraint:
    obligation = Obligation(
        obligation_id="O1",
        kind="forbidden",
        behavior="refund twice",
        rule_span=span,
        violated_via="tool_call",
    )
    return SecurityConstraint(
        constraint_id="SC-1",
        rule="The agent must not refund twice.",
        related_hazards=["H-1"],
        obligations=[obligation],
    )


def test_the_validator_error_states_the_case_insensitive_contiguous_rule() -> None:
    with pytest.raises(ValidationError) as caught:
        _constraint_with_span("refund once")

    message = str(caught.value)
    assert "contiguous substring" in message
    assert "case-insensitive" in message
    assert "'refund once'" in message
    assert "The agent must not refund twice." in message
    for phrase in STALE_PHRASES:
        assert phrase not in message


def test_the_validator_accepts_a_span_that_differs_only_in_case() -> None:
    constraint = _constraint_with_span("MUST NOT REFUND")

    assert constraint.obligations[0].rule_span == "MUST NOT REFUND"


RULE = "The agent must not refund twice."
STATED = "a contiguous substring of the constraint rule"
STALE_REPAIR_WORDS = ("verbatim", "quote")


def test_the_entry_check_error_states_the_case_insensitive_contiguous_rule() -> None:
    _, errors = _check_obligation_entry(
        {"obligation_id": "O1", "rule_span": "refund once"}, RULE
    )

    stated = [error for error in errors if error.startswith("rule_span must be")]
    assert stated == [f"rule_span must be {STATED}, compared case-insensitively"]
    assert not any(word in error for error in errors for word in STALE_REPAIR_WORDS)


def test_the_entry_check_adds_no_span_error_for_a_case_only_difference() -> None:
    _, errors = _check_obligation_entry(
        {"obligation_id": "O1", "rule_span": "MUST NOT REFUND"}, RULE
    )

    assert not any("rule_span must be" in error for error in errors)


def _selected_for_span() -> SelectedObligation:
    return SelectedObligation(
        constraint_id="SC-1",
        obligation_id="O1",
        original_entry_raw={},
        validation_errors=(),
        permitted_changes=(PermittedChange(kind="set_rule_span"),),
        constraint_rule=RULE,
    )


def test_the_rejection_states_the_case_insensitive_contiguous_rule() -> None:
    selected = _selected_for_span()

    with pytest.raises(RepairRejected) as caught:
        _check_permitted_value(
            selected,
            selected.permitted_changes[0],
            SimpleNamespace(rule_span="refund once"),
        )

    message = str(caught.value)
    assert message == (
        "repair_unrelated_field_edit: the corrected entry for 'SC-1/O1' "
        f"still has a rule_span that is not {STATED}, compared case-insensitively"
    )
    assert not any(word in message for word in STALE_REPAIR_WORDS)


def test_the_repair_check_accepts_a_span_that_differs_only_in_case() -> None:
    selected = _selected_for_span()

    _check_permitted_value(
        selected,
        selected.permitted_changes[0],
        SimpleNamespace(rule_span="MUST NOT REFUND"),
    )


def test_the_repair_record_reason_states_the_case_insensitive_contiguous_rule() -> None:
    record = RepairRecord()
    repairs = [
        RuleSpanRepairRecord(
            constraint="SC-1",
            obligation_id="O1",
            repair=RuleSpanRepair(
                kind="ellipsis",
                original="must ... twice",
                repaired="must not refund twice",
            ),
        )
    ]

    record_rule_span_repairs(
        record,
        step="gap_analysis",
        attempt="first",
        repairs=repairs,
        outcome="applied",
    )

    (entry,) = record.entries
    assert entry.reason == (
        f"rule_span was not {STATED} (compared case-insensitively); "
        "a unique ellipsis match mapped it to text that is"
    )
    assert not any(word in entry.reason for word in STALE_REPAIR_WORDS)

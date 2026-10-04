"""Deterministic ``rule_span`` repair: whitespace and ellipsis matches."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.loss_analysis import SecurityConstraint
from asago_scenario_generator.stpa.system_model.rule_span_repair import (
    repair_obligation_rows,
    repair_rule_span,
    span_quotes_rule,
)

FINANCIAL_RULE = (
    "The AI Assistant must only execute financial actions, such as refunds or "
    "payment modifications, that are verified as legitimate and authorized "
    "within the authenticated user's context."
)


def test_observed_ellipsis_span_maps_to_the_verbatim_rule_text() -> None:
    span = (
        "must only execute financial actions... that are verified as legitimate "
        "and authorized within the authenticated user's context"
    )

    repair = repair_rule_span(FINANCIAL_RULE, span)

    assert repair is not None
    assert repair.kind == "ellipsis"
    assert repair.original == span
    assert repair.repaired == (
        "must only execute financial actions, such as refunds or payment "
        "modifications, that are verified as legitimate and authorized within "
        "the authenticated user's context"
    )
    assert repair.repaired in FINANCIAL_RULE
    SecurityConstraint(
        constraint_id="SC-5",
        rule=FINANCIAL_RULE,
        related_hazards=["H-1"],
        obligations=[
            {
                "obligation_id": "O1",
                "kind": "forbidden",
                "behavior": "execute an unverified financial action",
                "rule_span": repair.repaired,
            }
        ],
    )


@pytest.mark.parametrize("marker", ["...", "\u2026", " ... ", "....."])
def test_ellipsis_markers_and_surrounding_whitespace(marker: str) -> None:
    span = f"must only execute{marker}refunds or payment modifications"

    repair = repair_rule_span(FINANCIAL_RULE, span)

    assert repair is not None
    assert repair.repaired == (
        "must only execute financial actions, such as refunds or payment modifications"
    )


def test_whitespace_variant_maps_to_the_verbatim_rule_text() -> None:
    repair = repair_rule_span(
        FINANCIAL_RULE, "  must only\n execute   financial\tactions "
    )

    assert repair is not None
    assert repair.kind == "whitespace"
    assert repair.repaired == "must only execute financial actions"


def test_typographic_quote_variant_maps_to_the_rule_quote() -> None:
    repair = repair_rule_span(
        FINANCIAL_RULE, "within the authenticated user\u2019s context"
    )

    assert repair is not None
    assert repair.kind == "whitespace"
    assert repair.repaired == "within the authenticated user's context"


def test_whitespace_in_the_rule_is_preserved_verbatim() -> None:
    rule = "The agent must  never\nshare records."

    repair = repair_rule_span(rule, "must never share records")

    assert repair is not None
    assert repair.repaired == "must  never\nshare records"


def test_verbatim_span_needs_no_repair() -> None:
    assert repair_rule_span(FINANCIAL_RULE, "must only execute") is None
    assert repair_rule_span(FINANCIAL_RULE, "MUST ONLY EXECUTE") is None


@pytest.mark.parametrize(
    "span",
    [
        "must never execute financial actions",
        "must only execute... refunds for guests",
        "that are verified ... must only execute",
        "...",
    ],
)
def test_unmatched_span_is_left_for_validation(span: str) -> None:
    assert repair_rule_span(FINANCIAL_RULE, span) is None


@pytest.mark.parametrize(
    ("rule", "span"),
    [(None, "must only execute"), (FINANCIAL_RULE, None), (FINANCIAL_RULE, "  ")],
)
def test_non_string_or_blank_inputs_need_no_repair(rule, span) -> None:
    assert repair_rule_span(rule, span) is None


def test_ambiguous_fragment_placement_is_refused() -> None:
    # "the record" occurs twice, so the span could end after either one.
    rule = "The agent must show the record and must never alter the record."

    assert repair_rule_span(rule, "must show ... the record") is None


def test_ambiguous_start_is_refused() -> None:
    rule = "The agent must log and must alert on every refund."

    assert repair_rule_span(rule, "must ... every refund") is None


def test_repeated_middle_fragment_with_fixed_ends_is_accepted() -> None:
    # "the" occurs several times, but the first and last fragments each occur
    # once, so every placement yields the same verbatim text.
    rule = "The agent must check that the user owns the account before it acts."

    repair = repair_rule_span(rule, "must check ... the ... before it acts")

    assert repair is not None
    assert repair.kind == "ellipsis"
    assert repair.repaired == (
        "must check that the user owns the account before it acts"
    )


def test_repair_obligation_rows_rewrites_only_repairable_rows() -> None:
    rows = [
        {"obligation_id": "O1", "rule_span": "must only   execute"},
        {"obligation_id": "O2", "rule_span": "an unrelated paraphrase"},
        {"obligation_id": "O3", "rule_span": "must only execute"},
    ]

    records = repair_obligation_rows(
        constraint="SC-5", rule=FINANCIAL_RULE, obligations=rows
    )

    assert [record.as_dict() for record in records] == [
        {
            "constraint": "SC-5",
            "obligation_id": "O1",
            "kind": "whitespace",
            "original": "must only   execute",
            "repaired": "must only execute",
        }
    ]
    assert [row["rule_span"] for row in rows] == [
        "must only execute",
        "an unrelated paraphrase",
        "must only execute",
    ]
    assert all(
        span_quotes_rule(FINANCIAL_RULE, row["rule_span"])
        for row in rows
        if row["obligation_id"] != "O2"
    )

"""Quote matching folds typography the same way after the two callers share one normalizer.

The stated-rule matcher (``locate_quote``, ``normalized_text``) and the
``rule_span`` repair (``repair_rule_span``) fold different sets of typographic
code points and only the matcher ignores Markdown markers.  These tables pin
each caller's own behavior, code point by code point.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.system_model.rule_span_repair import (
    repair_rule_span,
)
from asago_scenario_generator.stpa.system_model.stated_rule_coverage import (
    locate_quote,
    normalized_text,
)

# Folded by both callers.
SHARED_FOLDS = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2010": "-",
    "\u2011": "-",
    "\u2013": "-",
    "\u2014": "-",
    "\u2212": "-",
}
# Folded only by the ``rule_span`` repair.
REPAIR_ONLY_FOLDS = {
    "\u201a": "'",
    "\u201b": "'",
    "\u2032": "'",
    "\u201e": '"',
    "\u201f": '"',
    "\u2033": '"',
    "\u2012": "-",
    "\u2015": "-",
}


def _fold_ids(table: dict[str, str]) -> list[str]:
    return [f"U+{ord(char):04X}" for char in table]


@pytest.mark.parametrize(
    ("char", "folded"), list(SHARED_FOLDS.items()), ids=_fold_ids(SHARED_FOLDS)
)
def test_matcher_folds_the_shared_code_points(char: str, folded: str) -> None:
    assert normalized_text(f"a{char}b") == f"a{folded}b"
    assert locate_quote(f"say a{char}b now", f"a{folded}b") == f"a{char}b"


@pytest.mark.parametrize(
    ("char", "folded"),
    list(REPAIR_ONLY_FOLDS.items()),
    ids=_fold_ids(REPAIR_ONLY_FOLDS),
)
def test_matcher_leaves_the_repair_only_code_points_unfolded(
    char: str, folded: str
) -> None:
    assert normalized_text(f"a{char}b") == f"a{char}b"
    assert locate_quote(f"say a{char}b now", f"a{folded}b") is None


@pytest.mark.parametrize(
    ("char", "folded"),
    list({**SHARED_FOLDS, **REPAIR_ONLY_FOLDS}.items()),
    ids=_fold_ids({**SHARED_FOLDS, **REPAIR_ONLY_FOLDS}),
)
def test_repair_folds_every_code_point(char: str, folded: str) -> None:
    repair = repair_rule_span(f"the a{folded}b rule", f"a{char}b")

    assert repair is not None
    assert repair.kind == "whitespace"
    assert repair.repaired == f"a{folded}b"


@pytest.mark.parametrize("marker", ["*", "`"])
def test_matcher_ignores_markup_on_both_sides(marker: str) -> None:
    assert normalized_text(f"a {marker}must{marker} b") == "a must b"
    assert locate_quote(f"the {marker}must{marker} rule", "must rule") == (
        f"must{marker} rule"
    )
    assert locate_quote("the must rule", f"{marker}must{marker} rule") == "must rule"
    assert normalized_text(f"a{marker}b") == "ab"
    assert normalized_text(f"a {marker} b") == "a b"


@pytest.mark.parametrize("marker", ["*", "`"])
def test_repair_keeps_markup_as_wording(marker: str) -> None:
    assert repair_rule_span(f"the {marker}must{marker} rule", "must rule") is None
    assert repair_rule_span("the must rule", f"{marker}must{marker}  rule") is None
    repair = repair_rule_span(f"the {marker}must  rule", f"{marker}must rule")
    assert repair is not None
    assert repair.repaired == f"{marker}must  rule"


def test_matcher_collapses_whitespace_runs_and_folds_case() -> None:
    assert normalized_text(" \n A \t\u00a0 b  ") == "a b"
    assert locate_quote("The  Rule\nholds.", "the rule holds") == "The  Rule\nholds"
    assert normalized_text("   ") == ""


def test_repair_maps_a_whitespace_run_back_to_the_rule_text() -> None:
    repair = repair_rule_span("see  the\n\nrule here", "the rule")

    assert repair is not None
    assert repair.repaired == "the\n\nrule"


def test_case_folding_expands_like_casefold() -> None:
    assert normalized_text("STRASSE\u00df") == "strassess"
    assert locate_quote("a \u00dfb", "ss") == "\u00df"

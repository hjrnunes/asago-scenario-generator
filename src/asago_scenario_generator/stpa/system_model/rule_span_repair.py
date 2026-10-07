"""Deterministic repair of obligation ``rule_span`` quotations.

An obligation's ``rule_span`` must quote its constraint ``rule`` verbatim
(case-insensitively, as :class:`SecurityConstraint` checks).  Models often
return a span that names the right words but differs from the rule in
whitespace or typographic punctuation, or that elides a middle stretch with
an ellipsis.  This module maps such a span back to the exact rule text it
denotes, so the published span is always a verbatim substring of the rule.

Two matches are tried, in order:

- ``whitespace``: collapse whitespace runs and normalize typographic quotes
  and dashes on both sides, then locate the span in the rule.
- ``ellipsis``: split the span on ``...`` or ``…``; every non-empty fragment
  must occur in the rule in order (with the ``whitespace`` normalization),
  and the repaired span runs from the start of the first fragment to the end
  of the last.

A repair is accepted only when every candidate placement yields the same
verbatim rule text.  An ambiguous placement (for example, a repeated
fragment that admits two different start or end positions) is refused
rather than resolved by position, and the span is left unchanged for the
ordinary validation failure and its correction path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING, Any, Literal

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR

if TYPE_CHECKING:
    from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
        RepairRecord,
    )

RULE_SPAN_REPAIR_KIND = "rule_span_repaired"
RuleSpanRepairKind = Literal["whitespace", "ellipsis"]

_TYPOGRAPHIC = str.maketrans(
    {
        "\u2018": "'",
        "\u2019": "'",
        "\u201a": "'",
        "\u201b": "'",
        "\u2032": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u201e": '"',
        "\u201f": '"',
        "\u2033": '"',
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2015": "-",
        "\u2212": "-",
    }
)
_ELLIPSIS = re.compile(r"\s*(?:\.{3,}|\u2026)\s*")


@dataclass(frozen=True)
class RuleSpanRepair:
    """One accepted mapping of a non-verbatim span to verbatim rule text."""

    kind: RuleSpanRepairKind
    original: str
    repaired: str


@dataclass(frozen=True)
class RuleSpanRepairRecord:
    """A repair applied to one obligation of one constraint."""

    constraint: str
    obligation_id: str
    repair: RuleSpanRepair

    def as_dict(self) -> dict[str, str]:
        return {
            "constraint": self.constraint,
            "obligation_id": self.obligation_id,
            "kind": self.repair.kind,
            "original": self.repair.original,
            "repaired": self.repair.repaired,
        }


def span_quotes_rule(rule: str, span: str) -> bool:
    """Apply the same verbatim test as :class:`SecurityConstraint`."""
    return span.casefold() in rule.casefold()


@cache
def rule_span_requirement() -> str:
    """The rule a ``rule_span`` must meet, as every prompt states it.

    The text comes from one template partial so the prompts that include it
    and the Python-built correction text cannot drift apart.
    """
    return (
        TemplateLoader(PROMPTS_DIR).render_prompt("_rule_span_requirement.j2").strip()
    )


def repair_rule_span(rule: str, span: str) -> RuleSpanRepair | None:
    """Map a non-verbatim ``span`` to the verbatim ``rule`` text it denotes.

    Returns ``None`` when the span already quotes the rule, when no match
    exists, or when the match is ambiguous.
    """
    if not isinstance(rule, str) or not isinstance(span, str):
        return None
    if not span.strip() or span_quotes_rule(rule, span):
        return None
    haystack, index = _normalize(rule)
    whitespace = _unique_text(rule, index, _fragment_placements(haystack, [span]))
    if whitespace is not None:
        return _accepted("whitespace", rule, span, whitespace)
    return _repair_ellipsis(rule, span, haystack, index)


def _repair_ellipsis(
    rule: str, span: str, haystack: str, index: list[int]
) -> RuleSpanRepair | None:
    if not _ELLIPSIS.search(span):
        return None
    fragments = [part for part in _ELLIPSIS.split(span) if part.strip()]
    if not fragments:
        return None
    ellipsis = _unique_text(rule, index, _fragment_placements(haystack, fragments))
    if ellipsis is not None:
        return _accepted("ellipsis", rule, span, ellipsis)
    return None


def repair_obligation_rows(
    *,
    constraint: str,
    rule: Any,
    obligations: Any,
) -> list[RuleSpanRepairRecord]:
    """Repair ``rule_span`` values in raw obligation dictionaries in place."""
    records: list[RuleSpanRepairRecord] = []
    if not isinstance(rule, str) or not isinstance(obligations, list):
        return records
    for row in obligations:
        if not isinstance(row, dict):
            continue
        repair = repair_rule_span(rule, row.get("rule_span"))
        if repair is None:
            continue
        row["rule_span"] = repair.repaired
        records.append(
            RuleSpanRepairRecord(
                constraint=constraint,
                obligation_id=str(row.get("obligation_id", "")),
                repair=repair,
            )
        )
    return records


def repair_obligation_models(
    *,
    constraint: str,
    rule: str,
    obligations: list[Any],
) -> tuple[list[Any], list[RuleSpanRepairRecord]]:
    """Return copies of obligation models with repaired ``rule_span`` values."""
    repaired: list[Any] = []
    records: list[RuleSpanRepairRecord] = []
    for obligation in obligations:
        repair = repair_rule_span(rule, getattr(obligation, "rule_span", None))
        if repair is None:
            repaired.append(obligation)
            continue
        repaired.append(obligation.model_copy(update={"rule_span": repair.repaired}))
        records.append(
            RuleSpanRepairRecord(
                constraint=constraint,
                obligation_id=str(obligation.obligation_id),
                repair=repair,
            )
        )
    return repaired, records


def record_rule_span_repairs(
    repair_record: RepairRecord | None,
    *,
    step: str,
    attempt: str,
    repairs: list[RuleSpanRepairRecord],
    outcome: str,
) -> None:
    """Append one repair-record entry per repaired obligation span."""
    if repair_record is None:
        return
    for record in repairs:
        repair = record.repair
        repair_record.add(
            stage=step,
            attempt=attempt,
            kind=RULE_SPAN_REPAIR_KIND,
            identity=f"{record.constraint}/{record.obligation_id}",
            reason=(
                "rule_span was not a contiguous substring of the constraint "
                "rule (compared case-insensitively); a unique "
                f"{repair.kind} match mapped it to text that is"
            ),
            proposed={"rule_span": repair.original},
            applied={"rule_span": repair.repaired, "match": repair.kind},
            outcome=outcome,
            raw_step=step,
        )


def _accepted(
    kind: RuleSpanRepairKind, rule: str, span: str, repaired: str
) -> RuleSpanRepair | None:
    if not repaired.strip() or not span_quotes_rule(rule, repaired):
        return None
    return RuleSpanRepair(kind=kind, original=span, repaired=repaired)


def _normalize(text: str) -> tuple[str, list[int]]:
    """Normalize ``text`` and map each output character to its source index."""
    chars: list[str] = []
    index: list[int] = []
    pending_space: int | None = None
    for position, char in enumerate(text):
        if char.isspace():
            if chars and pending_space is None:
                pending_space = position
            continue
        if pending_space is not None:
            chars.append(" ")
            index.append(pending_space)
            pending_space = None
        for folded in char.translate(_TYPOGRAPHIC).casefold():
            chars.append(folded)
            index.append(position)
    return "".join(chars), index


def _occurrences(haystack: str, needle: str) -> list[int]:
    starts: list[int] = []
    start = haystack.find(needle)
    while start != -1:
        starts.append(start)
        start = haystack.find(needle, start + 1)
    return starts


def _fragment_placements(haystack: str, fragments: list[str]) -> set[tuple[int, int]]:
    """Every (start, end) in normalized ``haystack`` covering ordered fragments."""
    needles = [_normalize(fragment)[0] for fragment in fragments]
    if not needles or not all(needles):
        return set()
    placements: set[tuple[int, int]] = set()
    for first in _occurrences(haystack, needles[0]):
        placements.update((first, end) for end in _chain_ends(haystack, needles, first))
    return placements


def _chain_ends(haystack: str, needles: list[str], first: int) -> set[int]:
    """Return every end offset of an ordered match of ``needles`` from ``first``."""
    reach = {first + len(needles[0])}
    for needle in needles[1:]:
        earliest = min(reach)
        reach = {
            start + len(needle)
            for start in _occurrences(haystack, needle)
            if start >= earliest
        }
        if not reach:
            break
    return reach


def _unique_text(
    rule: str, index: list[int], placements: set[tuple[int, int]]
) -> str | None:
    texts = {rule[index[start] : index[end - 1] + 1] for start, end in placements}
    if len(texts) != 1:
        return None
    return texts.pop()

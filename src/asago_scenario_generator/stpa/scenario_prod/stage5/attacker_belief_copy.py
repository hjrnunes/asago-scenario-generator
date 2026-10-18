"""Attacker beliefs that restate a causal factor's stated flawed belief.

With stated beliefs on, each causal factor states what the controller wrongly
takes to be true. An attacker knows that truth, so an attacker belief that
repeats a flawed belief as a fact contradicts the scenario: the handoff
renders every attacker belief as a precondition stated as fact. Code only
detects such a copy; the model rewrites the attacker belief.

Two texts are compared by their content words: lowercased ``[a-z0-9_]+``
tokens without :data:`STOP_WORDS`, each with one suffix of
:data:`SUFFIXES` stripped when the word is longer than the suffix plus
three letters.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from pydantic import BaseModel

from .flawed_belief import FlawedBeliefFrame, flawed_belief_findings
from .issues import ExactIssueError, ExactIssuesError, IssueCode, ValidationIssue
from .wire import _CausalSourceChoice

# Calibrated on the six round-4 stated-belief generations (klarna, airbnb and
# occiai, two models each): these thresholds flagged 41 of 135 attacker-belief
# preconditions, every copy that blocked authoring among them (Jaccard 0.62
# to 1.00, or containment 0.83), and 11 of 135 baseline attacker beliefs
# compared with the stated beliefs of the same slot.
JACCARD_THRESHOLD = 0.6
CONTAINMENT_THRESHOLD = 0.8

STOP_WORDS = frozenset(
    "a an the of to in on for and or is are be been being it its this that with "
    "by as at from their his her they them user's user users not no any all can "
    "will would may has have had do does did which who whom whose what when "
    "where why how than then there here into".split()
)

SUFFIXES = ("ing", "ed", "es", "s")

# Long enough to recognize a quoted belief, short enough to keep the
# correction within its bound when several pairs are listed.
_QUOTE_CHARS = 90


def _stem(word: str) -> str:
    for suffix in SUFFIXES:
        if word.endswith(suffix) and len(word) > len(suffix) + 3:
            return word[: -len(suffix)]
    return word


def content_words(text: str) -> frozenset[str]:
    """Return the stemmed content words of ``text``."""
    return frozenset(
        _stem(word)
        for word in re.findall(r"[a-z0-9_]+", text.lower())
        if word not in STOP_WORDS
    )


@dataclass(frozen=True)
class BeliefOverlap:
    """How far an attacker belief repeats one flawed belief's content words.

    ``containment`` is the share of the flawed belief's words that the
    attacker belief also holds.
    """

    jaccard: float
    containment: float

    @property
    def restates(self) -> bool:
        return (
            self.jaccard >= JACCARD_THRESHOLD
            or self.containment >= CONTAINMENT_THRESHOLD
        )


def belief_overlap(attacker_belief: str, flawed_belief: str) -> BeliefOverlap:
    """Return the overlap of an attacker belief with a flawed belief."""
    attacker, flawed = content_words(attacker_belief), content_words(flawed_belief)
    if not attacker or not flawed:
        return BeliefOverlap(0.0, 0.0)
    shared = len(attacker & flawed)
    return BeliefOverlap(shared / len(attacker | flawed), shared / len(flawed))


def _quote(text: str) -> str:
    text = " ".join(text.split())
    if len(text) > _QUOTE_CHARS:
        text = text[: _QUOTE_CHARS - 3].rstrip() + "..."
    return f'"{text}"'


def attacker_belief_copy_findings(
    attacker_beliefs: Sequence[str], factors: Sequence[BaseModel]
) -> list[str]:
    """Return one line per attacker belief that restates a factor's flawed belief.

    Pairs are listed in attacker-belief order, then factor order.
    """
    findings: list[str] = []
    for belief_index, attacker_belief in enumerate(attacker_beliefs):
        for factor_index, factor in enumerate(factors):
            flawed = (getattr(factor, "flawed_belief", None) or "").strip()
            if not flawed or not belief_overlap(attacker_belief, flawed).restates:
                continue
            where = f"attacker_bdi.beliefs[{belief_index}]"
            findings.append(
                f"{where} {_quote(attacker_belief)} restates "
                f"causal_factors[{factor_index}].flawed_belief {_quote(flawed)}; "
                "an attacker belief states what the attacker believes about the "
                "target, such as what the assistant fails to check, never the "
                f"controller's flawed belief as true; rewrite {where}."
            )
    return findings


def validate_stated_belief_reply(
    attacker_beliefs: Sequence[str],
    factors: Sequence[BaseModel],
    frame: FlawedBeliefFrame,
    choices: Sequence[_CausalSourceChoice],
) -> None:
    """Reject a reply that breaks a stated-belief rule, naming every one.

    The factor rules and the attacker-belief rule fail as one error, so one
    correction lists both.
    """
    issues: list[ValidationIssue] = []
    factor_findings = flawed_belief_findings(
        factors, frame, {choice.handle: choice for choice in choices}
    )
    if factor_findings:
        issues.append(
            ValidationIssue(
                IssueCode.flawed_belief_invalid,
                "stated flawed beliefs break these rules:\n"
                + "\n".join(f"- {line}" for line in factor_findings),
            )
        )
    copies = attacker_belief_copy_findings(attacker_beliefs, factors)
    if copies:
        issues.append(
            ValidationIssue(
                IssueCode.attacker_belief_restates_flawed_belief,
                "attacker beliefs restate flawed beliefs:\n"
                + "\n".join(f"- {line}" for line in copies),
            )
        )
    if len(issues) == 1:
        raise ExactIssueError(issues[0].code, issues[0].detail)
    if issues:
        raise ExactIssuesError(tuple(issues))

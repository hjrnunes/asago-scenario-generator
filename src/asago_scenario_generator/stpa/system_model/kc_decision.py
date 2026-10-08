"""Decide KC sub-codes that the observed target settles.

Stage 1b samples KC sub-codes from the use-case text.  A code whose catalog
definition an observed fact settles is not left to sampling: each rule below
reads the verified interpretations of an observed execution target profile
(disposition ``supported`` with interpreter/verifier agreement) and names
the codes that fact makes present or absent.  Rules are per code and use
the definitions in ``kc-threat-mapping.yaml`` and the discovery vocabulary
(``likely_state_effect``, the ``text_search`` role); they never name a
target.  Codes no rule decides stay with the model, which Stage 1b samples
several times: :func:`vote_kc_subcodes` keeps a code that at least a third
of the draws select.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from fractions import Fraction

from pydantic import BaseModel, ConfigDict

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    InterpreterVerifierAgreement,
    InventoryCompleteness,
    TargetInterpretationDisposition,
    TargetSemanticInterpretation,
    TargetStateEffect,
)

# A code that one draw in three selects is kept: the prompt asks for every
# grounded code, and a sampled draw more often omits a code than invents one.
KC_VOTE_SHARE = Fraction(1, 3)
# Draws per product Stage 1b: with one third, a code selected in half of the
# single draws is kept about nine times in ten (lane p-kc baseline).
KC_VOTE_SAMPLES = 9

DATABASE_READ_ONLY = "KC6.3.1"
DATABASE_FULL_CRUD = "KC6.3.2"
RAG_DATA_SOURCE = "KC6.3.3"
TEXT_SEARCH_ROLE = "text_search"


@dataclass(frozen=True)
class KcFactDecision:
    """KC sub-codes an observed target decides, with one reason per code."""

    present: frozenset[str] = frozenset()
    absent: frozenset[str] = frozenset()
    reasons: Mapping[str, str] = field(default_factory=dict)


def _verified(
    profile: ExecutionTargetProfile,
) -> tuple[TargetSemanticInterpretation, ...]:
    return tuple(
        item
        for item in profile.interpretations
        if item.disposition is TargetInterpretationDisposition.supported
        and item.interpreter_verifier_agreement is InterpreterVerifierAgreement.agree
    )


def _names(items: Iterable[TargetSemanticInterpretation]) -> str:
    return ", ".join(sorted(item.tool_name for item in items))


def _without_state_change(
    profile: ExecutionTargetProfile,
    verified: tuple[TargetSemanticInterpretation, ...],
) -> bool:
    """Every observed tool is verified and none can change target state."""
    return (
        profile.inventory_completeness is InventoryCompleteness.observed_complete
        and len(verified) == len(profile.interpretations)
        and all(item.likely_state_effect is TargetStateEffect.none for item in verified)
    )


def _database_access(
    profile: ExecutionTargetProfile,
    verified: tuple[TargetSemanticInterpretation, ...],
) -> KcFactDecision:
    """A verified state change means data access is not read-only (KC6.3.2).

    A complete inventory whose every tool is verified to leave state
    unchanged rules full CRUD out; it does not establish a database at all,
    so KC6.3.1 stays with the model.
    """
    writers = [
        item
        for item in verified
        if item.likely_state_effect is TargetStateEffect.changes
    ]
    if not writers:
        if not _without_state_change(profile, verified):
            return KcFactDecision()
        return KcFactDecision(
            absent=frozenset({DATABASE_FULL_CRUD}),
            reasons={
                DATABASE_FULL_CRUD: (
                    "the observed inventory is complete and no verified tool "
                    "changes target state"
                )
            },
        )
    reason = (
        f"observed tools {_names(writers)} change target state, so the "
        "target's data access is not read-only"
    )
    return KcFactDecision(
        present=frozenset({DATABASE_FULL_CRUD}),
        absent=frozenset({DATABASE_READ_ONLY}),
        reasons={DATABASE_FULL_CRUD: reason, DATABASE_READ_ONLY: reason},
    )


def _retrieval_source(
    verified: tuple[TargetSemanticInterpretation, ...],
) -> KcFactDecision:
    """A verified free-text document search feeds retrieved text to the model."""
    searchers = [item for item in verified if TEXT_SEARCH_ROLE in item.semantic_roles]
    if not searchers:
        return KcFactDecision()
    return KcFactDecision(
        present=frozenset({RAG_DATA_SOURCE}),
        reasons={
            RAG_DATA_SOURCE: (
                f"observed tools {_names(searchers)} search documents for the "
                "model's context"
            )
        },
    )


def _combine(decisions: Iterable[KcFactDecision]) -> KcFactDecision:
    present: set[str] = set()
    absent: set[str] = set()
    reasons: dict[str, str] = {}
    for decision in decisions:
        present |= decision.present
        absent |= decision.absent
        reasons.update(decision.reasons)
    return KcFactDecision(frozenset(present), frozenset(absent), reasons)


def target_kc_decision(profile: ExecutionTargetProfile | None) -> KcFactDecision:
    """Return the KC sub-codes that *profile*'s verified facts decide."""
    if profile is None:
        return KcFactDecision()
    verified = _verified(profile)
    return _combine(
        (_database_access(profile, verified), _retrieval_source(verified))
    )


def vote_kc_subcodes(draws: Sequence[Collection[str]]) -> list[str]:
    """Return the codes selected by at least ``KC_VOTE_SHARE`` of *draws*."""
    if not draws:
        raise ValueError("a KC vote needs at least one draw")
    counts = Counter(code for draw in draws for code in set(draw))
    return sorted(
        code
        for code, count in counts.items()
        if Fraction(count, len(draws)) >= KC_VOTE_SHARE
    )


def apply_kc_facts(kc_subcodes: Iterable[str], facts: KcFactDecision) -> list[str]:
    """Return *kc_subcodes* with the fact-decided codes forced in or out."""
    return sorted((set(kc_subcodes) - facts.absent) | facts.present)


class KcDecisionRecord(BaseModel):
    """How Stage 1b decided its KC sub-codes, as ``capability-kc-decision.yaml``."""

    model_config = ConfigDict(frozen=True)

    samples: int
    vote_share: str
    draws: list[list[str]]
    failed_draws: list[str]
    counts: dict[str, int]
    voted: list[str]
    fact_present: list[str]
    fact_absent: list[str]
    fact_reasons: dict[str, str]
    kc_subcodes: list[str]

    @classmethod
    def of(
        cls,
        *,
        samples: int,
        draws: list[list[str]],
        failed_draws: list[str],
        facts: KcFactDecision,
        kc_subcodes: list[str],
    ) -> KcDecisionRecord:
        counts = Counter(code for draw in draws for code in set(draw))
        return cls(
            samples=samples,
            vote_share=str(KC_VOTE_SHARE),
            draws=draws,
            failed_draws=failed_draws,
            counts=dict(sorted(counts.items())),
            voted=vote_kc_subcodes(draws),
            fact_present=sorted(facts.present),
            fact_absent=sorted(facts.absent),
            fact_reasons=dict(sorted(facts.reasons.items())),
            kc_subcodes=kc_subcodes,
        )

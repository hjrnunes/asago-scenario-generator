"""Decide KC sub-codes that the observed target settles.

Stage 1b samples KC sub-codes from the use-case text.  A code whose catalog
definition an observed fact settles is not left to sampling: each rule below
reads the verified interpretations of an observed execution target profile
(disposition ``supported`` with interpreter/verifier agreement) and names
the codes that fact makes present or absent.  Rules are per code and use
the definitions in ``kc-threat-mapping.yaml`` and the discovery vocabulary
(``likely_state_effect``, the ``text_search`` role); they never name a
target.  Codes no rule decides stay with the model.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    InterpreterVerifierAgreement,
    InventoryCompleteness,
    TargetInterpretationDisposition,
    TargetSemanticInterpretation,
    TargetStateEffect,
)

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

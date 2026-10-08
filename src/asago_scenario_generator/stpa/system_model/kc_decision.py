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
    TargetInterpretationDisposition,
    TargetSemanticInterpretation,
    TargetStateEffect,
)

DATABASE_READ_ONLY = "KC6.3.1"
DATABASE_FULL_CRUD = "KC6.3.2"


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


def _database_access(
    verified: tuple[TargetSemanticInterpretation, ...],
) -> KcFactDecision:
    """A verified state change means data access is not read-only (KC6.3.2)."""
    writers = [
        item
        for item in verified
        if item.likely_state_effect is TargetStateEffect.changes
    ]
    if not writers:
        return KcFactDecision()
    reason = (
        f"observed tools {_names(writers)} change target state, so the "
        "target's data access is not read-only"
    )
    return KcFactDecision(
        present=frozenset({DATABASE_FULL_CRUD}),
        absent=frozenset({DATABASE_READ_ONLY}),
        reasons={DATABASE_FULL_CRUD: reason, DATABASE_READ_ONLY: reason},
    )


def target_kc_decision(profile: ExecutionTargetProfile | None) -> KcFactDecision:
    """Return the KC sub-codes that *profile*'s verified facts decide."""
    if profile is None:
        return KcFactDecision()
    return _database_access(_verified(profile))

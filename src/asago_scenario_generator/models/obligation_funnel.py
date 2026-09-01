"""Shared closed vocabulary for obligation analysis stopping points."""

from typing import Literal


ObligationStopReason = Literal[
    "addressed",
    "risk_pattern_mismatch",
    "mechanism_path_unsubstantiated",
    "no_structural_route",
    "not_applicable_proven",
    "not_applicable_evidence_incomplete",
    "ica_consideration_unresolved",
    "provider_contract_failure",
    "prompt_budget_exceeded",
    "scenario_realized",
    "scenario_generation_failure",
    "scenario_not_requested",
]


__all__ = ["ObligationStopReason"]

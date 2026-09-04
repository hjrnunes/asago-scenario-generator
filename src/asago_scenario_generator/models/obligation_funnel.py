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
    "ica_hazard_contradictory",
    "ica_hazard_insufficient_evidence",
    "ica_hazard_verification_provider_failure",
    "ica_hazard_correction_exhausted",
    "unsafe_outcome_lineage_incomplete",
    "provider_contract_failure",
    "prompt_budget_exceeded",
    "scenario_realized",
    "scenario_generation_failure",
    "scenario_not_requested",
]


__all__ = ["ObligationStopReason"]

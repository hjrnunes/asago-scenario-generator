"""Compatibility façade for the candidate pipeline implementations.

The candidate pipeline is split by responsibility, while this module retains
its historical interface for callers and tests.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    classify_entry_point,
)

from . import (
    candidate_capping,
    candidate_expansion,
    candidate_filter,
    candidate_models,
    candidate_rules,
)
from .candidate_capping import cap_scenarios_per_pattern
from .candidate_expansion import canonicalize_and_dedup, expand_candidates
from .candidate_filter import filter_candidates
from .candidate_models import (
    BatchFilterDraftV2,
    BatchFilterResponse,
    CandidateFunnel,
    CandidateOrigin,
    CandidateTriple,
    FilterDecisionDraftV2,
    FilterMapDecisionDraftV3,
    FilterMapDraftV3,
    FilterProtocolError,
    FilterSeedQuarantine,
    FilterVerdict,
    FilteredSeed,
    RejectionRecord,
    RemovalDecision,
    ScenarioSeed,
    StageRecord,
    build_filter_map_response_model,
    compute_candidate_id,
    reconcile_filter_map,
    reconcile_filter_ordinals,
)
from .candidate_rules import DIRECT_ONLY_TECHNIQUES, is_indirect_entry_point


# Preserve the historical monkeypatch seam used by rule-filter tests.  The
# runner is resolved at call time so a patch on this façade remains effective.
def apply_rule_based_filter(
    candidates: list[CandidateTriple],
    profile: CapabilityProfile,
    stage_records: list[StageRecord] | None = None,
) -> tuple[list[CandidateTriple], list[CandidateTriple], list[RejectionRecord]]:
    """Run deterministic rules through the extracted rule implementation."""
    rule_runner = globals().get("_run_rules_on_technique")
    if rule_runner is None:
        rule_runner = candidate_rules._run_rules_on_technique
    return candidate_rules.apply_rule_based_filter(
        candidates,
        profile,
        stage_records,
        rule_runner=rule_runner,
    )


_COMPATIBILITY_MODULES = (
    candidate_models,
    candidate_expansion,
    candidate_filter,
    candidate_rules,
    candidate_capping,
)


# Keep named imports, including legacy private helper imports, working after
# the implementation split without copying those symbols into this façade.
def __getattr__(name: str) -> Any:
    """Resolve candidate symbols from their responsibility-specific module."""
    for module in _COMPATIBILITY_MODULES:
        try:
            return getattr(module, name)
        except AttributeError:
            continue
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = (
    "BatchFilterDraftV2",
    "BatchFilterResponse",
    "CandidateFunnel",
    "CandidateOrigin",
    "CandidateTriple",
    "DIRECT_ONLY_TECHNIQUES",
    "FilterDecisionDraftV2",
    "FilterMapDecisionDraftV3",
    "FilterMapDraftV3",
    "FilterProtocolError",
    "FilterSeedQuarantine",
    "FilterVerdict",
    "FilteredSeed",
    "RejectionRecord",
    "RemovalDecision",
    "ScenarioSeed",
    "StageRecord",
    "apply_rule_based_filter",
    "build_filter_map_response_model",
    "canonicalize_and_dedup",
    "cap_scenarios_per_pattern",
    "classify_entry_point",
    "compute_candidate_id",
    "expand_candidates",
    "filter_candidates",
    "is_indirect_entry_point",
    "reconcile_filter_map",
    "reconcile_filter_ordinals",
)

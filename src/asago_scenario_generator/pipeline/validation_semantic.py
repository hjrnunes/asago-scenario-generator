"""Scenario-level semantic validation orchestration."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from asago_scenario_generator.models.scenario import (
    CorpusClaimApplicability,
    CorpusClaimCategory,
    CorpusClaimStatus,
    SemanticValidation,
    SemanticViolation,
    ValidationBlock,
)
from asago_scenario_generator.pipeline.validation_common import (
    _valid_technique_ids,
    _validation_passed,
)
from asago_scenario_generator.pipeline.validation_semantic_actions import (
    _check_semantic_actor_access_provenance,
    _check_semantic_goal_category_alignment,
    _check_semantic_typed_actions,
)
from asago_scenario_generator.pipeline.validation_semantic_scope import (
    _check_semantic_leaf_technique_mappings,
    _check_semantic_narrative_zones,
    _check_semantic_technique_scope_evidence,
    _check_semantic_threat_ids,
    _check_semantic_tree_techniques,
    _check_semantic_zone_omissions,
    _semantic_tree_technique_set,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.capability_profile import CapabilityProfile
    from asago_scenario_generator.models.scenario import ScenarioEnvelope


def _validate_scenario_semantics_mutating(
    scenarios: list[ScenarioEnvelope],
    profile: CapabilityProfile,
) -> None:
    """Run semantic validation checks on each scenario envelope.

    Checks:
      1. ``technique_exists``: every ATLAS technique_id in the attack tree
         exists in the pinned ATLAS release, or is an explicitly curated
         LAAF extension identifier.
      2. ``zone_in_profile``: every active zone referenced in the narrative's
         zone_sequence is in the profile's ``zones_active``. The canonical
         ``outside`` boundary marker is valid narrative context, not an active
         Schneider zone.
      3. ``threat_id_range``: threat_id on attack tree nodes is in T1-T17.
      4. ``missing_scenario_threat_id``: at least one tree node carries the
         scenario's own threat_id from ``scenario_seed_metadata``.
      5. ``narrative_technique_orphan``: technique IDs mentioned in narrative
         text but absent from both scenario classifications and exact
         projected-step mappings.
      6. ``zone_omission_tree``: narrative zones missing from attack tree.
      7. ``zone_omission_gherkin``: narrative zones missing from Gherkin.
      8. Typed action IDs resolve to canonical profile resources, and
         tool_execution leaves carry tool_invocation actions.
      9. Technique scopes: scenario classifications match qualified pins (or
         the legacy seed fallback), while non-null leaf techniques match every
         projected step represented by that leaf.
     10. ``zone_coverage_dropout``: narrative zone absent from BOTH tree
         AND Gherkin — a hard consistency failure (cxy4).

    Populates ``scenario.validation.semantic`` with results.
    Scenarios are never removed -- violations are recorded as warnings.
    """
    valid_technique_ids = _valid_technique_ids()
    valid_zones = {*profile.zones_active, "outside"}
    for scenario in scenarios:
        _validate_scenario_semantics_in_place(
            scenario, profile, valid_technique_ids, valid_zones
        )


def _persist_semantic_validation(
    scenario: ScenarioEnvelope,
    semantic: SemanticValidation,
) -> None:
    """Write semantic results into the scenario validation block."""
    if scenario.validation is None:
        scenario.validation = ValidationBlock(semantic=semantic)
    else:
        scenario.validation.semantic = semantic
    scenario.validation_passed = _validation_passed(scenario)


def _validate_scenario_semantics_in_place(
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
    valid_technique_ids: frozenset[str],
    valid_zones: set[str],
) -> None:
    """Run every semantic check for one scenario and persist the result."""
    violations: list[SemanticViolation] = []
    tree_technique_set = _semantic_tree_technique_set(scenario)
    _check_semantic_tree_techniques(scenario, valid_technique_ids, violations)
    _check_semantic_narrative_zones(scenario, valid_zones, violations)
    _check_semantic_threat_ids(scenario, violations)
    _check_semantic_technique_scope_evidence(
        scenario, tree_technique_set, valid_technique_ids, violations
    )
    _check_semantic_leaf_technique_mappings(scenario, violations)
    _check_semantic_zone_omissions(scenario, violations)
    _check_semantic_typed_actions(scenario, profile, violations)
    _check_semantic_goal_category_alignment(scenario, profile, violations)
    _check_semantic_actor_access_provenance(scenario, profile, violations)
    corpus_claims = check_corpus_claims_applicability(scenario, profile)
    semantic = SemanticValidation(
        valid=len(violations) == 0,
        violations=violations,
        corpus_claim_applicability=corpus_claims,
    )
    _persist_semantic_validation(scenario, semantic)


def check_scenario_semantics(
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
) -> SemanticValidation:
    """Run the legacy semantic checks on one copy without changing the input."""
    cloned = copy.deepcopy(scenario)
    _validate_scenario_semantics_mutating([cloned], profile)
    if cloned.validation is None or cloned.validation.semantic is None:
        raise RuntimeError("semantic validation did not produce a result")
    return copy.deepcopy(cloned.validation.semantic)


def validate_scenario_semantics(
    scenarios: list[ScenarioEnvelope],
    profile: CapabilityProfile,
) -> None:
    """Compatibility batch wrapper that persists pure per-envelope results."""
    from asago_scenario_generator.models.scenario import ValidationBlock

    for scenario in scenarios:
        semantic = check_scenario_semantics(scenario, profile)
        if scenario.validation is None:
            scenario.validation = ValidationBlock(semantic=semantic)
        else:
            scenario.validation.semantic = semantic
        scenario.validation_passed = _validation_passed(scenario)


def _clean_evidence(items: tuple[str, ...] | list[str]) -> list[str]:
    """Non-blank evidence entries."""
    return [e for e in items if e and e.strip()]


def _entry_point_claim(
    profile: CapabilityProfile,
) -> CorpusClaimApplicability:
    """Corpus claim applicability for the entry-point inventory."""
    if profile.is_entry_point_inventory_complete:
        return CorpusClaimApplicability(
            category=CorpusClaimCategory.entry_points,
            status=CorpusClaimStatus.applicable,
            reason=None,
            evidence=_clean_evidence(profile.entry_point_evidence),
        )
    return CorpusClaimApplicability(
        category=CorpusClaimCategory.entry_points,
        status=CorpusClaimStatus.not_applicable,
        reason=(
            "Entry-point inventory is inferred_partial, not "
            "operator-confirmed complete — closed-world corpus "
            "claims are not applicable."
        ),
    )


def _tool_inventory_claim(
    profile: CapabilityProfile,
) -> CorpusClaimApplicability:
    """Corpus claim applicability for the tool inventory."""
    if profile.is_tool_inventory_complete:
        return CorpusClaimApplicability(
            category=CorpusClaimCategory.tool_inventory,
            status=CorpusClaimStatus.applicable,
            reason=None,
            evidence=_clean_evidence(profile.tool_inventory_evidence),
        )
    return CorpusClaimApplicability(
        category=CorpusClaimCategory.tool_inventory,
        status=CorpusClaimStatus.not_applicable,
        reason=(
            "Tool inventory is inferred_partial, not "
            "operator-confirmed complete — closed-world corpus "
            "claims are not applicable."
        ),
    )


def check_corpus_claims_applicability(
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
) -> list[CorpusClaimApplicability]:
    """Return typed category-specific closed-world corpus claim applicability.

    For each inventory category (entry_points, tool_inventory):
    - ``inferred_partial`` → ``not_applicable`` with a typed reason.
    - ``operator_confirmed_complete`` → ``applicable`` carrying evidence.

    This is independent of ``phantom.valid`` — unknown emitted IDs still
    fail regardless of completeness (cmps.9 review correction 2).
    """
    del scenario
    return [_entry_point_claim(profile), _tool_inventory_claim(profile)]


def validate_semantic(
    scenarios: list[ScenarioEnvelope],
    profile: CapabilityProfile,
) -> None:
    """Compatibility entry point for semantic scenario validation."""
    validate_scenario_semantics(scenarios, profile)

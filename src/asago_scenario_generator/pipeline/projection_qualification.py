"""Authoritative record qualification and projection gate evaluation."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from asago_scenario_generator.models.attack_pattern_chain import (
    AttackPattern,
    CanonicalAttackChain,
)
from asago_scenario_generator.models.attack_pattern_contracts import TaxonomyResolver
from asago_scenario_generator.models.attack_pattern_projection import StepOmission
from asago_scenario_generator.models.attack_pattern_validation import (
    validate_attack_pattern,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    Digest,
    ProjectionBudget,
    ProjectionIssue,
    _canonical_json,
    _content_pin,
    _evaluate_preconditions,
    _evaluate_projection_conditions,
    _normalize_semantic_order,
    _pattern_pin,
)
from asago_scenario_generator.pipeline.projection_snapshot import (
    CapabilityFactSnapshot,
)


def _resolve_projection_budget(
    budget: ProjectionBudget | None,
) -> ProjectionBudget:
    """Return the caller budget, or a default projection budget."""
    return budget or ProjectionBudget()


def _catalog_content_pin(
    qualified: list[tuple[AttackPattern, str]],
) -> str:
    """Pin the ordered, deduplicated qualified pattern catalog."""
    return _content_pin(
        "asago-scenario-generator:authoritative-catalog:v1",
        [pattern_pin for _, pattern_pin in qualified],
    )


def _sorted_emitted_candidates(
    by_identity: dict[str, Any],
) -> tuple[Any, ...]:
    """Return emitted candidates ordered by candidate id."""
    return tuple(by_identity[key] for key in sorted(by_identity))


def _infeasibility_key(item: ProjectionIssue) -> tuple[Any, ...]:
    """Return the deterministic ordering key for an infeasibility."""
    return (
        item.pattern_id,
        item.code,
        item.step_id or "",
        item.slot_id or "",
    )


def _sorted_infeasibilities(
    issues: list[ProjectionIssue],
) -> tuple[ProjectionIssue, ...]:
    """Return deduplicated infeasibilities in deterministic order."""
    return tuple(sorted(_dedupe_projection_issues(issues), key=_infeasibility_key))


def _limitation_key(item: Any) -> tuple[str, str]:
    """Return the deterministic ordering key for a limitation."""
    return (item.pattern_id, item.code)


def _sorted_limitations(
    limitations: list[Any],
) -> tuple[Any, ...]:
    """Return limitations in deterministic order."""
    return tuple(sorted(limitations, key=_limitation_key))


def _authoritative_records_type_check(records: Any) -> None:
    """Reject non-sequence record inputs up front."""
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, dict)):
        raise TypeError("authoritative projection requires a sequence of raw records")


def _qualify_authoritative_pattern(
    raw: Any,
    taxonomy_resolver: TaxonomyResolver,
) -> tuple[AttackPattern, str]:
    """Qualify one raw canonical-chain record into a pinned pattern."""
    if not isinstance(raw, dict) or "canonical_chain" not in raw:
        raise ValueError(
            "authoritative projection requires qualified canonical-chain records; "
            "legacy catalogue records are isolated"
        )
    try:
        pattern = validate_attack_pattern(raw, taxonomy_resolver)
        pattern = AttackPattern.model_validate(
            _normalize_semantic_order(pattern.model_dump(mode="json"))
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"authoritative attack pattern qualification failed: {exc}"
        ) from exc
    return pattern, _pattern_pin(pattern)


def _resolve_qualified_patterns(
    qualified: list[tuple[AttackPattern, str]],
) -> list[tuple[AttackPattern, str]]:
    """Detect conflicting duplicate pattern ids and sort by pattern id."""
    by_pattern: dict[str, tuple[AttackPattern, str]] = {}
    for item in qualified:
        pattern, pattern_pin = item
        previous = by_pattern.get(pattern.id)
        if previous is not None and previous[1] != pattern_pin:
            raise ValueError("conflicting authoritative records share one pattern id")
        by_pattern[pattern.id] = item
    return [by_pattern[key] for key in sorted(by_pattern)]


def _qualify_authoritative_records(
    records: Sequence[dict[str, Any]],
    taxonomy_resolver: TaxonomyResolver,
) -> list[tuple[AttackPattern, str]]:
    """Qualify every raw record and resolve duplicates deterministically."""
    return _resolve_qualified_patterns(
        [_qualify_authoritative_pattern(raw, taxonomy_resolver) for raw in records]
    )


def _profile_compatibility_gaps(
    pattern: AttackPattern,
    snapshot: CapabilityFactSnapshot,
) -> tuple[list[str], list[str], bool]:
    """Return (missing zones, missing KC codes, any-satisfied flag)."""
    prerequisites = pattern.prerequisite_capabilities
    missing_zones = sorted(
        set(prerequisites.min_zones) - set(snapshot.profile.zones_active)
    )
    kc_requires = prerequisites.kc_requires
    profile_kc = set(snapshot.profile.kc_subcodes)
    missing_all = sorted(set(kc_requires.all) - profile_kc) if kc_requires else []
    any_satisfied = (
        not kc_requires
        or not kc_requires.any
        or bool(set(kc_requires.any) & profile_kc)
    )
    return missing_zones, missing_all, any_satisfied


def _incompatible_profile_issue(
    pattern: AttackPattern,
    missing_zones: list[str],
    missing_all: list[str],
    any_satisfied: bool,
    kc_requires: Any,
) -> ProjectionIssue:
    """Build the incompatible_profile issue with a joined detail list."""
    details = []
    if missing_zones:
        details.append(f"missing zones: {', '.join(missing_zones)}")
    if missing_all:
        details.append(f"missing required KC codes: {', '.join(missing_all)}")
    if not any_satisfied and kc_requires:
        details.append(
            "requires any KC code from: " + ", ".join(sorted(kc_requires.any))
        )
    return ProjectionIssue(
        code="incompatible_profile",
        pattern_id=pattern.id,
        detail="; ".join(details),
    )


def _profile_gate_failure_issue(
    pattern: AttackPattern,
    snapshot: CapabilityFactSnapshot,
) -> ProjectionIssue | None:
    """Return the profile gate issue, or None when the profile fits."""
    missing_zones, missing_all, any_satisfied = _profile_compatibility_gaps(
        pattern, snapshot
    )
    if missing_zones or missing_all or not any_satisfied:
        return _incompatible_profile_issue(
            pattern,
            missing_zones,
            missing_all,
            any_satisfied,
            pattern.prerequisite_capabilities.kc_requires,
        )
    return None


def _results_contain_unknown(results: Any) -> bool:
    """True when any evaluated result is unresolved."""
    return any(item.result == "unknown" for item in results)


def _results_contain_false(results: Any) -> bool:
    """True when any evaluated result is false."""
    return any(item.result == "false" for item in results)


def _unresolved_condition_issue(
    pattern: AttackPattern,
    condition_results: Any,
) -> ProjectionIssue:
    """Build the unresolved_condition issue for projection conditions."""
    first_unknown = next(item for item in condition_results if item.result == "unknown")
    return ProjectionIssue(
        code="unresolved_condition",
        pattern_id=pattern.id,
        step_id=first_unknown.condition_step_id,
        detail="one or more authoritative condition facts are unresolved",
        condition_results=condition_results,
    )


def _unresolved_precondition_issue(
    pattern: AttackPattern,
    condition_results: Any,
    precondition_results: Any,
) -> ProjectionIssue:
    """Build the unresolved_condition issue for selected-step preconditions."""
    first_unknown = next(
        item for item in precondition_results if item.result == "unknown"
    )
    return ProjectionIssue(
        code="unresolved_condition",
        pattern_id=pattern.id,
        step_id=first_unknown.step_id,
        detail="one or more selected-step preconditions are unresolved",
        condition_results=condition_results,
        precondition_results=precondition_results,
    )


def _false_precondition_issue(
    pattern: AttackPattern,
    condition_results: Any,
    precondition_results: Any,
) -> ProjectionIssue:
    """Build the precondition_not_satisfied issue."""
    first_false = next(item for item in precondition_results if item.result == "false")
    return ProjectionIssue(
        code="precondition_not_satisfied",
        pattern_id=pattern.id,
        step_id=first_false.step_id,
        detail="one or more selected-step preconditions are false",
        condition_results=condition_results,
        precondition_results=precondition_results,
    )


def _inapplicable_projection_issue(
    pattern: AttackPattern,
    condition_results: Any,
) -> ProjectionIssue:
    """Build the inapplicable_projection issue."""
    return ProjectionIssue(
        code="inapplicable_projection",
        pattern_id=pattern.id,
        detail=(
            "condition results omit the terminal outcome or every "
            "attacker-controlled step"
        ),
        condition_results=condition_results,
    )


def _select_conditionally_required_steps(
    chain: CanonicalAttackChain,
    result_by_step: dict[str, str],
) -> tuple[str, ...]:
    """Select required steps plus conditional steps evaluated true."""
    return tuple(
        step.step_id
        for step in chain.steps
        if step.requirement == "required" or result_by_step[step.step_id] == "true"
    )


def _projection_is_applicable(
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
) -> bool:
    """True when selected steps reach the terminal outcome with an
    attacker-controlled step."""
    if chain.steps[-1].step_id not in selected:
        return False
    return any(
        step.attacker_controlled and step.step_id in set(selected)
        for step in chain.steps
    )


def _omitted_conditional_steps(
    chain: CanonicalAttackChain,
    result_by_step: dict[str, str],
) -> tuple[StepOmission, ...]:
    """Return omissions for conditional steps evaluated false."""
    return tuple(
        StepOmission(step_id=step.step_id, reason="condition_false")
        for step in chain.steps
        if step.requirement == "conditional" and result_by_step[step.step_id] == "false"
    )


def _precondition_results_or_none(
    pattern: AttackPattern,
    selected: tuple[str, ...],
    snapshot: CapabilityFactSnapshot,
    condition_results: Any,
    issues: list[ProjectionIssue],
) -> Any:
    """Return precondition results, or None after recording a gate issue."""
    precondition_results = _evaluate_preconditions(pattern, selected, snapshot)
    if _results_contain_unknown(precondition_results):
        issues.append(
            _unresolved_precondition_issue(
                pattern, condition_results, precondition_results
            )
        )
        return None
    if _results_contain_false(precondition_results):
        issues.append(
            _false_precondition_issue(pattern, condition_results, precondition_results)
        )
        return None
    return precondition_results


def _profile_and_condition_gate(
    pattern: AttackPattern,
    snapshot: CapabilityFactSnapshot,
    issues: list[ProjectionIssue],
) -> Any:
    """Return condition results, or None after recording a gate issue."""
    profile_issue = _profile_gate_failure_issue(pattern, snapshot)
    if profile_issue is not None:
        issues.append(profile_issue)
        return None
    condition_results = _evaluate_projection_conditions(pattern, snapshot)
    if _results_contain_unknown(condition_results):
        issues.append(_unresolved_condition_issue(pattern, condition_results))
        return None
    return condition_results


def _qualified_condition_state(
    pattern: AttackPattern,
    snapshot: CapabilityFactSnapshot,
    chain: CanonicalAttackChain,
    issues: list[ProjectionIssue],
) -> Any:
    """Run gate checks and return (conditions, selected, omissions,
    preconditions), or None after recording the failing issue."""
    condition_results = _profile_and_condition_gate(pattern, snapshot, issues)
    if condition_results is None:
        return None
    result_by_step = {item.condition_step_id: item.result for item in condition_results}
    selected = _select_conditionally_required_steps(chain, result_by_step)
    if not _projection_is_applicable(chain, selected):
        issues.append(_inapplicable_projection_issue(pattern, condition_results))
        return None
    omissions = _omitted_conditional_steps(chain, result_by_step)
    precondition_results = _precondition_results_or_none(
        pattern, selected, snapshot, condition_results, issues
    )
    if precondition_results is None:
        return None
    return condition_results, selected, omissions, precondition_results


def _dedupe_projection_issues(
    issues: list[ProjectionIssue],
) -> Any:
    """Deduplicate issues by canonical JSON content, preserving last."""
    return {
        _canonical_json(issue.model_dump(mode="json")): issue for issue in issues
    }.values()


def compute_authoritative_catalog_pin(
    records: Sequence[dict[str, Any]], taxonomy_resolver: TaxonomyResolver
) -> Digest:
    """Compute the canonical pin for a complete trusted authoritative catalog.

    This is deliberately separate from bounded projection: validation of a
    persisted candidate must not depend on whether its binding variant would
    be rediscovered under an arbitrary projection budget.
    """
    qualified: dict[str, str] = {}
    for raw in records:
        pattern = validate_attack_pattern(raw, taxonomy_resolver)
        pattern = AttackPattern.model_validate(
            _normalize_semantic_order(pattern.model_dump(mode="json"))
        )
        pattern_pin = _pattern_pin(pattern)
        previous = qualified.get(pattern.id)
        if previous is not None and previous != pattern_pin:
            raise ValueError("conflicting authoritative records share one pattern id")
        qualified[pattern.id] = pattern_pin
    return _content_pin(
        "asago-scenario-generator:authoritative-catalog:v1",
        [qualified[pattern_id] for pattern_id in sorted(qualified)],
    )

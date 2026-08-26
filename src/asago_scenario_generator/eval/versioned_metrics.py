"""Authoritative v3 evaluation over admitted, resolver-verified artifacts."""

from __future__ import annotations

import re
from collections import Counter
from itertools import combinations
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from asago_scenario_generator.eval.scorecard import (
    MetricResult,
    MetricSection,
    MetricStatus,
    QUALIFICATION_GATE_PATHS,
    REQUIRED_QUALIFICATION_GATE_IDS,
    ScorecardV1,
    aggregate_qualification,
    ratio_metric,
    zero_gate,
)
from asago_scenario_generator.manifest import ArtifactRole, ManifestInventoryResolver
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.scenario import ScenarioEnvelope
from asago_scenario_generator.pipeline.finalization_gate_contracts import (
    AdmissionEvidenceId,
)
from asago_scenario_generator.pipeline.persistence_journal import (
    FinalizationInventoryV1,
)
from asago_scenario_generator.pipeline.persistence_plan import CoveragePlanV2

_TITLE_TOKEN_RE = re.compile(r"[a-z0-9]+")
_NEAR_TITLE_THRESHOLD = 0.6


def _tree_leaves(node: dict[str, Any]) -> list[dict[str, Any]]:
    children = node.get("children") or []
    if not children:
        return [node]
    return [leaf for child in children for leaf in _tree_leaves(child)]


def _projected_ids(items: list[dict[str, Any]]) -> set[str]:
    return {
        str(step_id) for item in items for step_id in item.get("projected_step_ids", [])
    }


def _normal_title(value: str) -> str:
    return " ".join(_TITLE_TOKEN_RE.findall(value.casefold()))


def _title_tokens(value: str) -> set[str]:
    return set(_TITLE_TOKEN_RE.findall(value.casefold()))


def _neighbor_map(nodes: list[str], edges: set[tuple[str, str]]) -> dict[str, set[str]]:
    """Undirected adjacency map built from an edge set."""
    neighbors = {node: set() for node in nodes}
    for left, right in edges:
        neighbors[left].add(right)
        neighbors[right].add(left)
    return neighbors


def _unvisited_neighbors(
    current: str, neighbors: dict[str, set[str]], seen: set[str]
) -> list[str]:
    """Adjacent nodes not yet seen, in deterministic order."""
    return [
        neighbor
        for neighbor in sorted(neighbors[current], reverse=True)
        if neighbor not in seen
    ]


def _components(nodes: list[str], edges: set[tuple[str, str]]) -> list[list[str]]:
    neighbors = _neighbor_map(nodes, edges)
    result: list[list[str]] = []
    seen: set[str] = set()
    for node in sorted(nodes):
        if node in seen or not neighbors[node]:
            continue
        pending = [node]
        component: list[str] = []
        seen.add(node)
        while pending:
            current = pending.pop()
            component.append(current)
            for neighbor in _unvisited_neighbors(current, neighbors, seen):
                seen.add(neighbor)
                pending.append(neighbor)
        result.append(sorted(component))
    return sorted(result)


def _exact_normalized_groups(
    normalized_groups: dict[str, list[str]],
) -> list[list[str]]:
    """Sorted scenario-id groups whose normalized titles repeat."""
    return sorted(
        sorted(group)
        for title, group in normalized_groups.items()
        if title and len(group) > 1
    )


def _title_edge_similarity(left: str, right: str, titles: dict[str, str]) -> float:
    """Jaccard similarity of the token sets of two titles."""
    left_tokens = _title_tokens(titles[left])
    right_tokens = _title_tokens(titles[right])
    union = left_tokens | right_tokens
    return len(left_tokens & right_tokens) / len(union) if union else 0.0


def _title_edges(ids: list[str], titles: dict[str, str]) -> set[tuple[str, str]]:
    """Deterministic near-duplicate edges between scenario ids."""
    title_edges: set[tuple[str, str]] = set()
    for left, right in combinations(ids, 2):
        if _title_edge_similarity(
            left, right, titles
        ) >= _NEAR_TITLE_THRESHOLD and _normal_title(titles[left]) != _normal_title(
            titles[right]
        ):
            title_edges.add((left, right))
    return title_edges


def title_duplicate_components(
    titles: dict[str, str],
) -> tuple[list[list[str]], list[list[str]]]:
    """Return exact-normalized groups and deterministic near-title components."""
    normalized_groups: dict[str, list[str]] = {}
    for scenario_id, title in titles.items():
        normalized_groups.setdefault(_normal_title(title), []).append(scenario_id)
    exact_groups = _exact_normalized_groups(normalized_groups)
    ids = sorted(titles)
    return exact_groups, _components(ids, _title_edges(ids, titles))


def canonical_entry_point_sets(
    scenarios: list[dict[str, Any]], expected_ids: set[str]
) -> tuple[set[str], set[str]]:
    """Return covered and unknown IDs using only canonical envelope identity."""
    used_ids = {
        str(scenario["initial_entry_point_id"])
        for scenario in scenarios
        if scenario.get("initial_entry_point_id")
    }
    return used_ids & expected_ids, used_ids - expected_ids


def inventory_identity_mismatches(
    yaml_ids: set[str], feature_ids: set[str], receipt_ids: set[str]
) -> set[str]:
    """Return every ID preventing exact three-way inventory equality."""
    return (yaml_ids | feature_ids | receipt_ids) - (
        yaml_ids & feature_ids & receipt_ids
    )


def _count_metric(count: int, evidence: list[str], affected: list[str]) -> MetricResult:
    return MetricResult(
        status=MetricStatus.PASS,
        numerator=count,
        evidence=evidence,
        affected_ids=sorted(affected),
    )


def _resolver_orphan_fact(
    resolver: ManifestInventoryResolver, *, evidence: str
) -> MetricResult:
    check_orphans = getattr(resolver, "check_orphans", False)
    if not check_orphans:
        return MetricResult(
            status=MetricStatus.NOT_APPLICABLE,
            evidence=[
                evidence,
                "in-progress resolver does not own final orphan reconciliation",
            ],
            affected_ids=[],
        )
    return zero_gate(0, evidence=[evidence])


def _decision_evidence_records(
    decision: Any, evidence_ids: tuple[AdmissionEvidenceId, ...]
) -> dict[AdmissionEvidenceId, list[Any]]:
    """Gate-result records per required evidence id for one decision."""
    return {
        evidence_id: [
            gate for gate in decision.gate_results if gate.gate is evidence_id
        ]
        for evidence_id in evidence_ids
    }


def _wrong_record_count(records: dict[AdmissionEvidenceId, list[Any]]) -> bool:
    """True when any evidence id appears more or less than once."""
    return any(len(items) != 1 for items in records.values())


def _unexpected_applicable(
    records: dict[AdmissionEvidenceId, list[Any]],
    expected_applicable: bool | None,
) -> bool:
    """True when any record's applicable flag contradicts the expectation."""
    if expected_applicable is None:
        return False
    return any(
        items[0].applicable is not expected_applicable for items in records.values()
    )


def _not_applicable_gate(records: dict[AdmissionEvidenceId, list[Any]]) -> bool:
    """True when any evidence gate is marked not applicable."""
    return any(not items[0].applicable for items in records.values())


def _malformed_evidence_decision(
    records: dict[AdmissionEvidenceId, list[Any]],
    expected_applicable: bool | None,
) -> bool:
    """True when evidence records violate the once-per-decision contract."""
    if _wrong_record_count(records):
        return True
    if _unexpected_applicable(records, expected_applicable):
        return True
    if _not_applicable_gate(records):
        return True
    return False


def _evidence_outcome(
    decision: Any, records: dict[AdmissionEvidenceId, list[Any]]
) -> str:
    """'failed', 'exact_admitted_pass', or 'no_pass' for one decision."""
    if any(not items[0].passed for items in records.values()):
        return "failed"
    if decision.admitted:
        return "exact_admitted_pass"
    return "no_pass"


def _record_evidence_outcomes(
    decision: Any,
    records: dict[AdmissionEvidenceId, list[Any]],
    expected_applicable: bool | None,
    malformed: list[str],
    failed: list[str],
    exact_admitted_passes: list[str],
) -> None:
    """Route one decision's evidence records into the outcome lists."""
    if _malformed_evidence_decision(records, expected_applicable):
        malformed.append(decision.candidate_id)
        return
    outcome = _evidence_outcome(decision, records)
    if outcome == "failed":
        failed.append(decision.candidate_id)
    elif outcome == "exact_admitted_pass":
        exact_admitted_passes.append(decision.candidate_id)


def _admission_evidence_metric(
    final: FinalizationInventoryV1,
    evidence_ids: tuple[AdmissionEvidenceId, ...],
    *,
    expected_applicable: bool | None = None,
    evidence: list[str],
) -> MetricResult:
    """Evaluate exact, once-per-decision evidence without absence inference."""
    malformed: list[str] = []
    failed: list[str] = []
    exact_admitted_passes: list[str] = []
    for decision in final.admission_decisions:
        records = _decision_evidence_records(decision, evidence_ids)
        _record_evidence_outcomes(
            decision,
            records,
            expected_applicable,
            malformed,
            failed,
            exact_admitted_passes,
        )
    if failed:
        return ratio_metric(
            0,
            1,
            threshold=1.0,
            evidence=evidence,
            affected_ids=sorted(set(failed)),
        )
    if malformed or not exact_admitted_passes:
        return MetricResult(
            status=MetricStatus.NOT_APPLICABLE,
            evidence=[*evidence, "no exact passed admitted outcome"],
            affected_ids=sorted(malformed),
        )
    return ratio_metric(
        1,
        1,
        threshold=1.0,
        evidence=evidence,
    )


def _admission_gate_failure_metrics(
    final: FinalizationInventoryV1,
) -> dict[str, MetricResult]:
    """Return failure rates whose numerator and denominator both count outcomes."""
    gate_failures: Counter[AdmissionEvidenceId] = Counter()
    gate_failure_ids: dict[AdmissionEvidenceId, set[str]] = {}
    gate_runs: Counter[AdmissionEvidenceId] = Counter()
    for decision in final.admission_decisions:
        for gate in decision.gate_results:
            gate_runs[gate.gate] += 1
            if not gate.passed:
                gate_failures[gate.gate] += 1
                gate_failure_ids.setdefault(gate.gate, set()).add(decision.candidate_id)
    return {
        f"admission_gate_failure_rate:{evidence_id.value}": ratio_metric(
            gate_failures[evidence_id],
            run_count,
            threshold=0.0,
            evidence=[
                f"typed admission evidence_id={evidence_id.value}",
                f"denominator=gate outcomes ({run_count})",
            ],
            affected_ids=sorted(gate_failure_ids.get(evidence_id, set())),
            applicable=False,
        )
        for evidence_id, run_count in sorted(
            gate_runs.items(), key=lambda item: item[0].value
        )
    }


def evaluate_v3_scorecard(resolver: ManifestInventoryResolver) -> ScorecardV1:
    """Compute v1 metrics without discovery, repair, or artifact writes."""
    manifest = resolver.manifest
    plan, final, profile = _load_v3_scorecard_models(resolver)
    scenario_items, schema_errors = _collect_v3_scenario_items(resolver)
    scenario_ids, feature_ids = _v3_scenario_and_feature_ids(resolver, scenario_items)
    presence = _build_v3_presence_metrics(
        resolver, manifest, plan, final, scenario_items
    )
    failures, diagnostic_failures = _collect_v3_admission_failures(final)
    validity = _build_v3_validity_metrics(
        scenario_items, schema_errors, final, failures, diagnostic_failures
    )
    counters = _collect_v3_scenario_counters(scenario_items, plan, final)
    agreement = _build_v3_agreement_metrics(counters)
    diagnostics = _build_v3_diagnostics(counters)
    release = _build_v3_release_metrics(manifest, final, profile, counters)
    sections = {
        "presence_coverage": MetricSection(metrics=presence),
        "validity_grounding": MetricSection(metrics=validity),
        "cross_artifact_agreement": MetricSection(metrics=agreement),
        "semantic_quality_diagnostics": MetricSection(metrics=diagnostics),
        "release_qualification": MetricSection(metrics=release),
    }
    qualification_gates = {
        gate_id: sections[section_name].metrics[metric_id]
        for gate_id, (section_name, metric_id) in QUALIFICATION_GATE_PATHS.items()
    }
    return ScorecardV1(
        run_id=manifest.run_id,
        scenario_count=len(scenario_items),
        feature_file_count=len(feature_ids),
        **sections,
        qualification=aggregate_qualification(
            qualification_gates,
            required_gate_ids=REQUIRED_QUALIFICATION_GATE_IDS,
        ),
    )


def _load_v3_scorecard_models(
    resolver: ManifestInventoryResolver,
) -> tuple[CoveragePlanV2, FinalizationInventoryV1, CapabilityProfile]:
    """Load and validate the v3 scorecard inputs."""
    manifest = resolver.manifest
    if manifest.manifest_version != "3":
        raise ValueError("versioned evaluation requires authoritative manifest v3")
    plan_entry = resolver.entry_by_role(ArtifactRole.COVERAGE_PLAN)
    final_entry = resolver.entry_by_role(ArtifactRole.FINALIZATION_INVENTORY)
    profile_entry = resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    if plan_entry is None or final_entry is None or profile_entry is None:
        raise ValueError(
            "manifest v3 evaluation requires plan, finalization, and profile"
        )
    plan = CoveragePlanV2.model_validate_json(resolver.read_text(plan_entry))
    final = FinalizationInventoryV1.model_validate_json(resolver.read_text(final_entry))
    profile = CapabilityProfile.model_validate(resolver.read_yaml(profile_entry))
    return plan, final, profile


def _check_v3_scenario_schema(
    raw: dict[str, Any],
    scenario_id: str,
    schema_errors: list[str],
) -> None:
    """Record a scenario that violates the strict envelope schema."""
    try:
        ScenarioEnvelope.model_validate(raw)
    except ValidationError:
        schema_errors.append(scenario_id)


def _collect_v3_scenario_items(
    resolver: ManifestInventoryResolver,
) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
    """Collect scenario YAML items and schema failures."""
    scenario_items: list[tuple[str, dict[str, Any]]] = []
    schema_errors: list[str] = []
    for entry in resolver.scenario_yaml_entries():
        raw = resolver.read_yaml(entry)
        if not isinstance(raw, dict):
            schema_errors.append(entry.scenario_id or entry.path)
            continue
        scenario_id = entry.scenario_id or entry.path
        scenario_items.append((scenario_id, raw))
        _check_v3_scenario_schema(raw, scenario_id, schema_errors)
    return scenario_items, schema_errors


def _v3_feature_ids(resolver: ManifestInventoryResolver) -> list[str]:
    """Return scenario feature entry IDs in inventory order."""
    return [
        entry.scenario_id or entry.path for entry in resolver.scenario_feature_entries()
    ]


def _v3_scenario_ids(
    scenario_items: list[tuple[str, dict[str, Any]]],
) -> list[str]:
    """Return scenario IDs in inventory order."""
    return [scenario_id for scenario_id, _ in scenario_items]


def _v3_scenario_raws(
    scenario_items: list[tuple[str, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Return scenario raw payloads in inventory order."""
    return [raw for _, raw in scenario_items]


def _v3_scenario_and_feature_ids(
    resolver: ManifestInventoryResolver,
    scenario_items: list[tuple[str, dict[str, Any]]],
) -> tuple[list[str], list[str]]:
    """Return scenario and feature ID lists for the scorecard header."""
    scenario_ids = _v3_scenario_ids(scenario_items)
    feature_ids = _v3_feature_ids(resolver)
    return scenario_ids, feature_ids


def _v3_receipt_pair_bad_ids(
    admitted_receipts: list[Any],
) -> list[str]:
    """Return scenario IDs whose admitted receipt count is not two."""
    receipt_pairs = Counter(receipt.scenario_id for receipt in admitted_receipts)
    return sorted(sid for sid, count in receipt_pairs.items() if count != 2)


def _v3_receipt_pair_stats(
    final: FinalizationInventoryV1,
) -> tuple[list[str], set[str]]:
    """Return bad scenario pairs and admitted receipt scenario IDs."""
    admitted_receipts = [
        receipt
        for receipt in final.admitted_inventory
        if receipt.scenario_id is not None
    ]
    receipt_scenarios = {receipt.scenario_id for receipt in admitted_receipts}
    return _v3_receipt_pair_bad_ids(admitted_receipts), receipt_scenarios


def _build_v3_presence_metrics(
    resolver: ManifestInventoryResolver,
    manifest: Any,
    plan: CoveragePlanV2,
    final: FinalizationInventoryV1,
    scenario_items: list[tuple[str, dict[str, Any]]],
) -> dict[str, MetricResult]:
    """Build the presence/coverage metric section."""
    scenario_ids = _v3_scenario_ids(scenario_items)
    feature_ids = _v3_feature_ids(resolver)
    plan_targets = {target.entry_point_id for target in plan.targets}
    covered_targets, unknown_targets = canonical_entry_point_sets(
        _v3_scenario_raws(scenario_items), plan_targets
    )
    bad_pairs, receipt_scenarios = _v3_receipt_pair_stats(final)
    count_mismatch_ids = sorted(
        inventory_identity_mismatches(
            set(scenario_ids), set(feature_ids), receipt_scenarios
        )
    )
    return {
        "nonempty_admitted_inventory": zero_gate(
            0 if receipt_scenarios else 1,
            evidence=[
                "finalization-inventory.json:admitted_inventory must be nonempty"
            ],
            affected_ids=[] if receipt_scenarios else [manifest.run_id],
        ),
        "manifest_evaluated_count_coherence": zero_gate(
            len(count_mismatch_ids),
            evidence=[
                "manifest YAML/feature inventory",
                "finalization-inventory.json:admitted_inventory",
            ],
            affected_ids=count_mismatch_ids,
        ),
        "manifest_pair_coherence": zero_gate(
            len(bad_pairs),
            evidence=["finalization-inventory.json:admitted_inventory"],
            affected_ids=bad_pairs,
        ),
        "canonical_entry_point_coverage": ratio_metric(
            len(covered_targets),
            len(plan_targets),
            evidence=[
                "coverage-plan.json:targets",
                "admitted scenario initial_entry_point_id",
                f"completeness={plan.completeness}",
            ],
            affected_ids=sorted(plan_targets - covered_targets),
            applicable=plan.completeness == "confirmed_complete",
        ),
        "unknown_entry_point_count": zero_gate(
            len(unknown_targets),
            evidence=[
                "coverage-plan.json:targets",
                "scenario.initial_entry_point_id",
            ],
            affected_ids=sorted(unknown_targets),
        ),
        "stale_or_orphan_artifact_count": _resolver_orphan_fact(
            resolver, evidence="strict finalized resolver orphan check"
        ),
        "missing_pair_count": zero_gate(
            len(bad_pairs) + len(count_mismatch_ids),
            evidence=[
                "manifest YAML/feature pairing",
                "finalization admitted receipts",
            ],
            affected_ids=sorted(set(bad_pairs) | set(count_mismatch_ids)),
        ),
        "duplicate_or_overwritten_artifact_count": zero_gate(
            0,
            evidence=[
                "strict resolver canonical-path, inode, identity, and hash checks"
            ],
        ),
        "unmanifested_artifact_count": _resolver_orphan_fact(
            resolver, evidence="strict finalized resolver orphan check"
        ),
    }


def _accumulate_v3_gate_failures(
    decision: Any,
    failures: dict[str, set[str]],
    diagnostic_failures: dict[str, set[str]],
) -> None:
    """Add one decision's gate violations and diagnostics to the code sets."""
    for gate in decision.gate_results:
        for violation in gate.violations:
            failures.setdefault(violation.code, set()).add(decision.candidate_id)
        for diagnostic in gate.diagnostics:
            diagnostic_failures.setdefault(diagnostic.code, set()).add(
                decision.candidate_id
            )


def _accumulate_v3_admission_failure(
    decision: Any,
    failures: dict[str, set[str]],
    diagnostic_failures: dict[str, set[str]],
) -> None:
    """Add one decision's violations and gate diagnostics to the code sets."""
    destination = failures if decision.violations else diagnostic_failures
    for violation in decision.violations:
        destination.setdefault(violation.code, set()).add(decision.candidate_id)
    _accumulate_v3_gate_failures(decision, failures, diagnostic_failures)


def _collect_v3_admission_failures(
    final: FinalizationInventoryV1,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Collect violation/failure code sets keyed by decision."""
    failures: dict[str, set[str]] = {}
    diagnostic_failures: dict[str, set[str]] = {}
    for decision in final.admission_decisions:
        _accumulate_v3_admission_failure(decision, failures, diagnostic_failures)
    return failures, diagnostic_failures


def _collect_v3_quarantine_reasons(
    final: FinalizationInventoryV1,
) -> dict[str, set[str]]:
    """Collect quarantine reason codes over non-admitted decisions."""
    quarantine_reasons: dict[str, set[str]] = {}
    for decision in final.admission_decisions:
        if decision.admitted:
            continue
        for violation in decision.violations:
            quarantine_reasons.setdefault(violation.code, set()).add(
                decision.candidate_id
            )
    return quarantine_reasons


def _build_v3_validity_metrics(
    scenario_items: list[tuple[str, dict[str, Any]]],
    schema_errors: list[str],
    final: FinalizationInventoryV1,
    failures: dict[str, set[str]],
    diagnostic_failures: dict[str, set[str]],
) -> dict[str, MetricResult]:
    """Build the validity/grounding metric section."""
    decision_count = len(final.admission_decisions)
    validity: dict[str, MetricResult] = {
        "scenario_schema_validity": ratio_metric(
            len(scenario_items) - len(schema_errors),
            len(scenario_items),
            evidence=["ScenarioEnvelope schema validation"],
            affected_ids=schema_errors,
        ),
    }
    for code in sorted(set(failures) | set(diagnostic_failures)):
        affected = sorted(
            failures.get(code, set()) | diagnostic_failures.get(code, set())
        )
        validity[f"admission_failure_rate:{code}"] = ratio_metric(
            len(affected),
            decision_count,
            threshold=0.0,
            evidence=[f"finalization-inventory.json:violation_code={code}"],
            affected_ids=affected,
            applicable=False,
        )
    validity.update(_admission_gate_failure_metrics(final))
    quarantine_reasons = _collect_v3_quarantine_reasons(final)
    for code, affected in sorted(quarantine_reasons.items()):
        validity[f"kill_chain_quarantine_reason:{code}"] = _count_metric(
            len(affected),
            [f"persisted quarantine violation category={code}"],
            sorted(affected),
        )
    return validity


def _v3_admitted_by_candidate(
    final: FinalizationInventoryV1,
) -> dict[str, Any]:
    """Index admitted terminal decisions by candidate ID."""
    return {
        decision.candidate_id: decision
        for decision in final.admission_decisions
        if decision.admitted
    }


def _v3_plan_choices(plan: CoveragePlanV2) -> dict[str, Any]:
    """Index coverage choices by candidate ID."""
    return {
        choice.candidate_id: choice
        for target in plan.targets
        for choice in target.ordered_choices
    }


@dataclass
class _V3ScenarioCounters:
    """Accumulated per-scenario agreement counters."""

    scenario_items: list[tuple[str, dict[str, Any]]]
    pinned_total: int = 0
    pinned_found: int = 0
    projected_total: int = 0
    projected_all_found: int = 0
    tree_behavior_matches: int = 0
    projection_mappings: Counter[str] = field(default_factory=Counter)
    projection_problem_ids: list[str] = field(default_factory=list)
    tree_behavior_problem_ids: list[str] = field(default_factory=list)
    pinned_problem_ids: list[str] = field(default_factory=list)
    projected_problem_ids: list[str] = field(default_factory=list)
    vacuous_agreement_ids: list[str] = field(default_factory=list)
    conditional_total: int = 0
    conditional_decided: int = 0
    conditional_problem_ids: list[str] = field(default_factory=list)
    zone_difference_ids: list[str] = field(default_factory=list)
    zone_difference_sizes: Counter[int] = field(default_factory=Counter)
    titles: dict[str, str] = field(default_factory=dict)
    structures: dict[str, tuple[str, ...]] = field(default_factory=dict)


def _v3_selected_step_ids(raw: dict[str, Any]) -> set[str]:
    """Return the scenario's projected selected step IDs."""
    projection = raw.get("projection", {}).get("projection", {})
    return {str(value) for value in projection.get("selected_step_ids", [])}


def _v3_conditional_step_ids(raw: dict[str, Any]) -> set[str]:
    """Return conditional source-chain step IDs."""
    projection = raw.get("projection", {}).get("projection", {})
    source_steps = projection.get("source_chain", {}).get("steps", [])
    return {
        str(step.get("step_id"))
        for step in source_steps
        if step.get("requirement") == "conditional" and step.get("step_id")
    }


def _v3_condition_result_step_ids(raw: dict[str, Any]) -> set[str]:
    """Return condition-result step IDs."""
    projection = raw.get("projection", {}).get("projection", {})
    return {
        str(item.get("condition_step_id"))
        for item in projection.get("condition_results", [])
        if item.get("condition_step_id")
    }


def _accumulate_v3_conditional_stats(
    counters: _V3ScenarioCounters,
    scenario_id: str,
    raw: dict[str, Any],
) -> None:
    """Accumulate conditional decision coverage for one scenario."""
    conditional_ids = _v3_conditional_step_ids(raw)
    condition_results = _v3_condition_result_step_ids(raw)
    counters.conditional_total += len(conditional_ids)
    counters.conditional_decided += len(conditional_ids & condition_results)
    if conditional_ids != condition_results:
        counters.conditional_problem_ids.append(scenario_id)


def _accumulate_v3_projection_recall(
    counters: _V3ScenarioCounters,
    scenario_id: str,
    raw: dict[str, Any],
) -> None:
    """Accumulate projected-step recall for one scenario."""
    selected = _v3_selected_step_ids(raw)
    tree_ids = _projected_ids(_tree_leaves(raw.get("attack_tree", {}).get("root", {})))
    behavior_ids = _projected_ids(raw.get("behavior_spec", {}).get("actions", []))
    narrative_ids = _projected_ids(raw.get("narrative", {}).get("steps", []))
    counters.projected_total += len(selected)
    common = selected & narrative_ids & tree_ids & behavior_ids
    counters.projected_all_found += len(common)
    if common != selected:
        counters.projected_problem_ids.append(scenario_id)
    if tree_ids == behavior_ids and tree_ids == selected:
        counters.tree_behavior_matches += 1
    else:
        counters.tree_behavior_problem_ids.append(scenario_id)
    counters.structures[scenario_id] = tuple(sorted(selected))


def _v3_scenario_classifications(raw: dict[str, Any]) -> set[str]:
    """Return published scenario classification IDs or the legacy fallback."""
    scope_evidence = raw.get("technique_scope_evidence") or {}
    return set(
        scope_evidence.get("scenario_classification_ids")
        or raw.get("faceting", {})
        .get("taxonomy_chain", {})
        .get("atlas_technique_ids", [])
    )


def _accumulate_v3_pinned_stats(
    counters: _V3ScenarioCounters,
    scenario_id: str,
    pinned: set[str],
    raw: dict[str, Any],
) -> None:
    """Accumulate pinned-technique recall for one scenario."""
    scenario_classifications = _v3_scenario_classifications(raw)
    counters.pinned_total += len(pinned)
    counters.pinned_found += len(pinned & scenario_classifications)
    if pinned != scenario_classifications:
        counters.pinned_problem_ids.append(scenario_id)
    if not pinned and not scenario_classifications:
        counters.vacuous_agreement_ids.append(scenario_id)


def _accumulate_v3_projection_mappings(
    counters: _V3ScenarioCounters,
    raw: dict[str, Any],
) -> None:
    """Count projected-mapping decisions for one scenario."""
    for mapping in raw.get("projection", {}).get("projected_mappings", []):
        decision = mapping.get("mapping", {}).get("decision", "unknown")
        counters.projection_mappings[str(decision)] += 1


def _v3_narrative_zones(raw: dict[str, Any]) -> set[str]:
    """Return typed narrative step zones."""
    return {
        str(step["zone"])
        for step in raw.get("narrative", {}).get("steps", [])
        if step.get("zone") is not None
    }


def _v3_tree_zones(raw: dict[str, Any]) -> set[str]:
    """Return attack-tree leaf zones."""
    return {
        str(leaf["zone"])
        for leaf in _tree_leaves(raw.get("attack_tree", {}).get("root", {}))
        if leaf.get("zone") is not None
    }


def _accumulate_v3_zone_differences(
    counters: _V3ScenarioCounters,
    scenario_id: str,
    raw: dict[str, Any],
) -> None:
    """Accumulate narrative/tree zone-set difference size for one scenario."""
    difference_size = len(_v3_narrative_zones(raw) ^ _v3_tree_zones(raw))
    counters.zone_difference_sizes[difference_size] += 1
    if difference_size:
        counters.zone_difference_ids.append(scenario_id)


def _accumulate_v3_scenario_counters(
    counters: _V3ScenarioCounters,
    scenario_id: str,
    raw: dict[str, Any],
    choices: dict[str, Any],
    admitted_by_candidate: dict[str, Any],
) -> None:
    """Accumulate all agreement counters for one scenario."""
    candidate_id = str(raw.get("candidate_id", ""))
    choice = choices.get(candidate_id)
    _accumulate_v3_conditional_stats(counters, scenario_id, raw)
    _accumulate_v3_projection_recall(counters, scenario_id, raw)
    pinned = set(choice.pinned_technique_ids) if choice is not None else set()
    _accumulate_v3_pinned_stats(counters, scenario_id, pinned, raw)
    _accumulate_v3_projection_mappings(counters, raw)
    if candidate_id not in admitted_by_candidate:
        counters.projected_problem_ids.append(scenario_id)
    counters.titles[scenario_id] = str(raw.get("narrative", {}).get("title", ""))
    _accumulate_v3_zone_differences(counters, scenario_id, raw)


def _collect_v3_scenario_counters(
    scenario_items: list[tuple[str, dict[str, Any]]],
    plan: CoveragePlanV2,
    final: FinalizationInventoryV1,
) -> _V3ScenarioCounters:
    """Accumulate per-scenario agreement counters over admitted artifacts."""
    counters = _V3ScenarioCounters(scenario_items=scenario_items)
    admitted_by_candidate = _v3_admitted_by_candidate(final)
    choices = _v3_plan_choices(plan)
    for scenario_id, raw in scenario_items:
        _accumulate_v3_scenario_counters(
            counters, scenario_id, raw, choices, admitted_by_candidate
        )
    return counters


def _build_v3_agreement_metrics(
    counters: _V3ScenarioCounters,
) -> dict[str, MetricResult]:
    """Build the cross-artifact agreement metric section."""
    scenario_count = len(counters.scenario_items)
    agreement: dict[str, MetricResult] = {
        "pinned_technique_recall": ratio_metric(
            counters.pinned_found,
            counters.pinned_total,
            evidence=[
                "coverage-plan pinned_technique_ids",
                "admitted scenario classifications",
            ],
            affected_ids=counters.pinned_problem_ids,
        ),
        "projected_step_recall": ratio_metric(
            counters.projected_all_found,
            counters.projected_total,
            evidence=[
                "persisted projection selected_step_ids",
                "artifact projected_step_ids",
            ],
            affected_ids=counters.projected_problem_ids,
        ),
        "exact_tree_behavior_correspondence": ratio_metric(
            scenario_count - len(counters.tree_behavior_problem_ids),
            scenario_count,
            evidence=[
                "attack-tree leaves",
                "structured behavior actions",
                "projection",
            ],
            affected_ids=counters.tree_behavior_problem_ids,
        ),
        "vacuous_agreement_count": _count_metric(
            len(counters.vacuous_agreement_ids),
            ["empty pinned and attack-tree technique sets are not agreement"],
            counters.vacuous_agreement_ids,
        ),
        "projection_conditional_decision_coverage": ratio_metric(
            counters.conditional_decided,
            counters.conditional_total,
            evidence=[
                "projection source_chain conditional steps",
                "projection condition_results; denominator=conditional source steps",
            ],
            affected_ids=counters.conditional_problem_ids,
        ),
        "projection_mapping_coverage": ratio_metric(
            counters.projection_mappings["exact"],
            sum(counters.projection_mappings.values()),
            evidence=["projection.projected_mappings mapping decisions"],
            affected_ids=counters.projection_problem_ids,
        ),
    }
    for decision, count in sorted(counters.projection_mappings.items()):
        agreement[f"projection_mapping_status:{decision}"] = ratio_metric(
            count,
            sum(counters.projection_mappings.values()),
            threshold=0.0,
            evidence=["projection.projected_mappings"],
            applicable=False,
        )
    return agreement


def _v3_structural_signature_match(
    structures: dict[str, tuple[str, ...]],
    left: str,
    right: str,
) -> bool:
    """True when two scenarios share a nonempty structural signature."""
    signature = structures[left]
    return bool(signature) and signature == structures[right]


def _v3_structural_edges(
    ids: list[str],
    structures: dict[str, tuple[str, ...]],
) -> set[tuple[str, str]]:
    """Connect scenarios whose structural signatures match exactly."""
    structural_edges: set[tuple[str, str]] = set()
    for index, left in enumerate(ids):
        for right in ids[index + 1 :]:
            if _v3_structural_signature_match(structures, left, right):
                structural_edges.add((left, right))
    return structural_edges


def _v3_structural_components(
    ids: list[str],
    structures: dict[str, tuple[str, ...]],
) -> list[list[str]]:
    """Return connected components over equal structural signatures."""
    return _components(ids, _v3_structural_edges(ids, structures))


def _v3_group_affected(groups: list[list[str]]) -> list[str]:
    """Return scenario IDs participating in any group."""
    return sorted({sid for group in groups for sid in group})


def _build_v3_diagnostics(
    counters: _V3ScenarioCounters,
) -> dict[str, MetricResult]:
    """Build the semantic quality diagnostics metric section."""
    exact_groups, title_components = title_duplicate_components(counters.titles)
    ids = sorted(counters.titles)
    structural_components = _v3_structural_components(ids, counters.structures)
    exact_affected = _v3_group_affected(exact_groups)
    near_affected = _v3_group_affected(title_components)
    structural_affected = _v3_group_affected(structural_components)
    scenario_count = len(counters.scenario_items)
    diagnostics: dict[str, MetricResult] = {
        "exact_normalized_title_duplicate_count": zero_gate(
            len(exact_groups),
            evidence=[f"normalized duplicate groups={exact_groups}"],
            affected_ids=exact_affected,
        ),
        "near_duplicate_title_component_count": _count_metric(
            len(title_components),
            [
                f"deterministic Jaccard threshold={_NEAR_TITLE_THRESHOLD}",
                f"components={title_components}",
            ],
            near_affected,
        ),
        "near_duplicate_title_affected_rate": ratio_metric(
            len(near_affected),
            len(ids),
            threshold=0.0,
            evidence=[f"components={title_components}"],
            affected_ids=near_affected,
            applicable=False,
        ),
        "structural_graph_component_count": _count_metric(
            len(structural_components),
            [
                f"exact selected-step structural signatures; "
                f"components={structural_components}"
            ],
            structural_affected,
        ),
        "structural_graph_affected_rate": ratio_metric(
            len(structural_affected),
            len(ids),
            threshold=0.0,
            evidence=[f"components={structural_components}"],
            affected_ids=structural_affected,
            applicable=False,
        ),
        "narrative_tree_zone_difference_rate": ratio_metric(
            len(counters.zone_difference_ids),
            scenario_count,
            threshold=0.0,
            evidence=["typed narrative.step.zone versus attack_tree leaf.zone sets"],
            affected_ids=counters.zone_difference_ids,
            applicable=False,
        ),
    }
    for size, count in sorted(counters.zone_difference_sizes.items()):
        diagnostics[f"narrative_tree_zone_difference_size:{size}"] = ratio_metric(
            count,
            scenario_count,
            threshold=0.0,
            evidence=[
                "symmetric zone-set difference size distribution",
                "denominator=admitted scenario artifacts",
            ],
            applicable=False,
        )
    return diagnostics


def _v3_quarantine_ids(final: FinalizationInventoryV1) -> list[str]:
    """Return sorted quarantine receipt candidate IDs."""
    return sorted(receipt.candidate_id for receipt in final.quarantine_inventory)


def _v3_evaluated_candidate_ids(
    scenario_items: list[tuple[str, dict[str, Any]]],
) -> set[str]:
    """Return candidate IDs of evaluated scenario artifacts."""
    return {
        str(raw.get("candidate_id"))
        for _, raw in scenario_items
        if raw.get("candidate_id")
    }


def _v3_profile_completeness_flags(
    profile: CapabilityProfile,
) -> tuple[bool, bool]:
    """Return entry-point and tool inventory completeness flags."""
    entry_complete = (
        profile.entry_point_completeness.value == "operator_confirmed_complete"
    )
    tool_complete = (
        profile.tool_inventory_completeness.value == "operator_confirmed_complete"
    )
    return entry_complete, tool_complete


def _build_v3_release_metrics(
    manifest: Any,
    final: FinalizationInventoryV1,
    profile: CapabilityProfile,
    counters: _V3ScenarioCounters,
) -> dict[str, MetricResult]:
    """Build the release qualification metric section."""
    quarantine_ids = _v3_quarantine_ids(final)
    evaluated_candidate_ids = _v3_evaluated_candidate_ids(counters.scenario_items)
    admitted_decision_ids = {
        decision.candidate_id
        for decision in final.admission_decisions
        if decision.admitted
    }
    admission_mismatch_ids = sorted(evaluated_candidate_ids ^ admitted_decision_ids)
    entry_complete, tool_complete = _v3_profile_completeness_flags(profile)
    exact_evidence = "finalization-inventory.json:typed admission gate outcomes"
    return {
        "zero_quarantine": zero_gate(
            len(quarantine_ids),
            evidence=["finalization-inventory.json:quarantine_inventory"],
            affected_ids=quarantine_ids,
        ),
        "persisted_admission_traceability_outcome": zero_gate(
            len(admission_mismatch_ids),
            evidence=[
                "exact evaluated candidate IDs equal persisted admitted decisions"
            ],
            affected_ids=admission_mismatch_ids,
        ),
        "actor_attack_complexity": _admission_evidence_metric(
            final,
            (AdmissionEvidenceId.actor_attack_complexity,),
            evidence=[exact_evidence],
        ),
        "capability_grounding": _admission_evidence_metric(
            final,
            (AdmissionEvidenceId.capability_grounding,),
            evidence=[exact_evidence, "explicit capability semantic-rule category"],
        ),
        "tool_integration_grounding": _admission_evidence_metric(
            final,
            (AdmissionEvidenceId.tool_integration_grounding,),
            expected_applicable=tool_complete,
            evidence=[
                exact_evidence,
                f"tool_inventory_completeness="
                f"{profile.tool_inventory_completeness.value}",
            ],
        ),
        "data_access_grounding": _admission_evidence_metric(
            final,
            (AdmissionEvidenceId.data_access_grounding,),
            expected_applicable=entry_complete,
            evidence=[
                exact_evidence,
                f"entry_point_completeness={profile.entry_point_completeness.value}",
            ],
        ),
        "catalog_taxonomy_pin_validity": _admission_evidence_metric(
            final,
            (AdmissionEvidenceId.catalog_taxonomy_pin_validity,),
            evidence=[exact_evidence],
        ),
        "resource_binding_validity": _admission_evidence_metric(
            final,
            (AdmissionEvidenceId.resource_binding_validity,),
            evidence=[exact_evidence],
        ),
        "execution_requirement_drift": _admission_evidence_metric(
            final,
            (AdmissionEvidenceId.execution_requirement_drift,),
            evidence=[exact_evidence],
        ),
        "zero_schema_identifier_phantom_parsimony_failures": (
            _admission_evidence_metric(
                final,
                (
                    AdmissionEvidenceId.structural_validity,
                    AdmissionEvidenceId.identifier_validity,
                    AdmissionEvidenceId.phantom_validity,
                    AdmissionEvidenceId.tree_parsimony,
                ),
                evidence=[exact_evidence],
            )
        ),
        "kill_chain_quarantine_reasons": zero_gate(
            len(quarantine_ids),
            evidence=[
                "quarantine IDs; reason categories remain in persisted "
                "admission decisions/bundles"
            ],
            affected_ids=quarantine_ids,
        ),
    }


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T09:03:15Z","module_hash":"b8833b08f9d82699c5838702b5625aa31692c7ba5396e6b94fe8c48100de6ddf","source_sha256":"1e442a29c983157f1d2fab58e7429563a01abdd8f80088c424eec91bcf8bd0f0","functions":[{"id":"func/_tree_leaves","name":"_tree_leaves","line":39,"end_line":43,"hash":"1ccfd615517f35a000f5900ab8ef78c9ea92014bb871dcbe4dad36f3c12f677f"},{"id":"func/_projected_ids","name":"_projected_ids","line":46,"end_line":49,"hash":"12045f9e173339b73344ac5c3ed0f7c90a78bf1443f85398fb3b1b4831adac6b"},{"id":"func/_normal_title","name":"_normal_title","line":52,"end_line":53,"hash":"9a584bfd67cfc415809510ac222b630f4fa7c79e21eef23cb3b8bf903ddadef0"},{"id":"func/_title_tokens","name":"_title_tokens","line":56,"end_line":57,"hash":"3f6f0abbadabe20633fabc6c9f27239df90d8494a17202a829866ecfda2e26df"},{"id":"func/_neighbor_map","name":"_neighbor_map","line":60,"end_line":66,"hash":"e88c39be7d407850ad82e104fdf593a24f09644a3d8859b5cc8791661d40b344"},{"id":"func/_unvisited_neighbors","name":"_unvisited_neighbors","line":69,"end_line":77,"hash":"c647647a3820c37f1be5b457ea558bc72c10eb7c93331eeec30c9d5ca4666a29"},{"id":"func/_components","name":"_components","line":80,"end_line":97,"hash":"35cea171efb6615733d718fb5e0200c18bbb328ed298d0725386483074003a19"},{"id":"func/_exact_normalized_groups","name":"_exact_normalized_groups","line":100,"end_line":108,"hash":"5caff2e8842dcbfb4cca521ff7f1d63cfbcf7f2e1fd093c70f0195f063288fb5"},{"id":"func/_title_edge_similarity","name":"_title_edge_similarity","line":111,"end_line":116,"hash":"fe6528adcc84cc3c7d49ec425ef269696750d61fdc674ccb4180cdf6f2b3b328"},{"id":"func/_title_edges","name":"_title_edges","line":119,"end_line":129,"hash":"a9b3e5c35e0a528c3847143cc0e7d1d290c1c93d49212b24fbfe40c4ff2908ae"},{"id":"func/title_duplicate_components","name":"title_duplicate_components","line":132,"end_line":141,"hash":"c76e8f542d5adf8ed52854d133c5eabf85740a815f9201cfd0b55d28b7b52605"},{"id":"func/canonical_entry_point_sets","name":"canonical_entry_point_sets","line":144,"end_line":153,"hash":"66e59a1a7d80c629fd952f4e784bbcc17acf9cb82b3d87e84d3bd45f27b00722"},{"id":"func/inventory_identity_mismatches","name":"inventory_identity_mismatches","line":156,"end_line":162,"hash":"194f6c457f2b0a3c951c0b3ef402598808a43fe4be529255a356d7accbee270d"},{"id":"func/_count_metric","name":"_count_metric","line":165,"end_line":171,"hash":"d052886c62b3800f63d5262c31b3e64452890eb5f3036ab133c5d894480292c8"},{"id":"func/_resolver_orphan_fact","name":"_resolver_orphan_fact","line":174,"end_line":187,"hash":"baa9d4b31b53d2c63022badfd8146ed23c43343dcddb669dbb2e7c41cb7f7d54"},{"id":"func/_decision_evidence_records","name":"_decision_evidence_records","line":190,"end_line":199,"hash":"c1d9228be963f8e87fdbfdbc32e76b35bbe8ff255eb63bcbd9740fa2e1f14ec5"},{"id":"func/_wrong_record_count","name":"_wrong_record_count","line":202,"end_line":204,"hash":"779ac4b754af46792040b98eee3a9ff187b25df89516e4b88c8f5b2c87ff7d6a"},{"id":"func/_unexpected_applicable","name":"_unexpected_applicable","line":207,"end_line":216,"hash":"77a95aba9a31271387cabe35cf8b6caa4bda6670e546bae07a6354348feb903d"},{"id":"func/_not_applicable_gate","name":"_not_applicable_gate","line":219,"end_line":221,"hash":"2372ca2e34e730887fe9a69b3036c40a3db0af4234aa8062928d5deccb0b45ee"},{"id":"func/_malformed_evidence_decision","name":"_malformed_evidence_decision","line":224,"end_line":235,"hash":"fc16eda33517497a9caa3d04e659816848e3d5b13a8f02db9950f1311eb332f9"},{"id":"func/_evidence_outcome","name":"_evidence_outcome","line":238,"end_line":246,"hash":"37cd3b9f1ad30a65ad51f8db53f728062bd3af51b887c7a5917d6d14f2f39e18"},{"id":"func/_record_evidence_outcomes","name":"_record_evidence_outcomes","line":249,"end_line":265,"hash":"cd0fc366a1eb474c83dd467adc47ac239bf223f277c47e1f09a077ec66455a19"},{"id":"func/_admission_evidence_metric","name":"_admission_evidence_metric","line":268,"end_line":308,"hash":"1f4bd2ba58e4ddb2ba8cdc81eb62e4f33efaf83332564d6bd8378bffe4012da0"},{"id":"func/_admission_gate_failure_metrics","name":"_admission_gate_failure_metrics","line":311,"end_line":339,"hash":"da6f34bcb51c113520f20be7cff21311d0e1eb113d3b4a77e50d5ab51b36a25c"},{"id":"func/evaluate_v3_scorecard","name":"evaluate_v3_scorecard","line":342,"end_line":379,"hash":"5daa22333c2a010eaf83531f025fc86730e634968c5e7540a522157bf6887c10"},{"id":"func/_load_v3_scorecard_models","name":"_load_v3_scorecard_models","line":382,"end_line":399,"hash":"82f32bfd71997ee314bfb15ccb60e588fa487e3cd79aac0be4bce359a197109e"},{"id":"func/_check_v3_scenario_schema","name":"_check_v3_scenario_schema","line":402,"end_line":411,"hash":"ca329b3b92ac866f0422ba1fd7169ad4d2effdc34aaab4c9ca79921f9b1832b7"},{"id":"func/_collect_v3_scenario_items","name":"_collect_v3_scenario_items","line":414,"end_line":428,"hash":"b558b7edc4814ac37d9e31e326cfbcf95d4108fd726e1e8aa023a4e26a725736"},{"id":"func/_v3_feature_ids","name":"_v3_feature_ids","line":431,"end_line":435,"hash":"1c697aa49b056498e505b105c1d44b5db51c4ff396467d5daefb632b549e770e"},{"id":"func/_v3_scenario_ids","name":"_v3_scenario_ids","line":438,"end_line":442,"hash":"4f2db55b4a925f221fdaeceeff57f3adf0a2a66ffcdf2acf5c7008d476db21b8"},{"id":"func/_v3_scenario_raws","name":"_v3_scenario_raws","line":445,"end_line":449,"hash":"725dd4a41f000f6466b5772b1fb3a64bb30c13fb42db75d573f42f925a9cd70c"},{"id":"func/_v3_scenario_and_feature_ids","name":"_v3_scenario_and_feature_ids","line":452,"end_line":459,"hash":"b2100b31339d4e53fb035b53f7e990fb956d7ca41265f3e6f8205dfe955276cf"},{"id":"func/_v3_receipt_pair_bad_ids","name":"_v3_receipt_pair_bad_ids","line":462,"end_line":467,"hash":"8fdd26cc47f9df36139dfc2be188eceda0f9632ee78203540eb47e19fda87355"},{"id":"func/_v3_receipt_pair_stats","name":"_v3_receipt_pair_stats","line":470,"end_line":480,"hash":"ce37f9109b22c919bd8719e63b9adea9bfa0edcb0388ed6fc1e2c88680946e5c"},{"id":"func/_build_v3_presence_metrics","name":"_build_v3_presence_metrics","line":483,"end_line":563,"hash":"381f9eabe4ee77ad31704250132f393de0e1206bf824c7f90f341b4388293a0e"},{"id":"func/_accumulate_v3_gate_failures","name":"_accumulate_v3_gate_failures","line":566,"end_line":578,"hash":"72e908cd7c02c6df86b6683b1dfe9f7016c6d58fdb4046db0f431896bd61d644"},{"id":"func/_accumulate_v3_admission_failure","name":"_accumulate_v3_admission_failure","line":581,"end_line":590,"hash":"f7d1ccb69eb5a88e4a1ca015558d024123f3e441c3ef0b2050ef55ca3ebecc08"},{"id":"func/_collect_v3_admission_failures","name":"_collect_v3_admission_failures","line":593,"end_line":601,"hash":"751df6ca244d3bc336500cc8193eb055b9838182cee150795c46bc887cf76fff"},{"id":"func/_collect_v3_quarantine_reasons","name":"_collect_v3_quarantine_reasons","line":604,"end_line":616,"hash":"f55e6d65aad4473f00e6bf7755bf4058908ad69068d42b3e8ad8c668951663d6"},{"id":"func/_build_v3_validity_metrics","name":"_build_v3_validity_metrics","line":619,"end_line":656,"hash":"b758e561fe8f3dd982321bdef34b8f82899acb64474ac8e2254989934b467827"},{"id":"func/_v3_admitted_by_candidate","name":"_v3_admitted_by_candidate","line":659,"end_line":667,"hash":"a8e7d0a01151328dbd67f0bed895bc3375efa960bedf427e2633a95876bf3846"},{"id":"func/_v3_plan_choices","name":"_v3_plan_choices","line":670,"end_line":676,"hash":"83a6b3b89f1b12b48e13ba97cc11f7bcb71d7db62ee42ac0af29b6d282e75d85"},{"id":"func/_v3_selected_step_ids","name":"_v3_selected_step_ids","line":704,"end_line":707,"hash":"57445e77e072b05aad206c5c27a4b075857786f946560c72ec63e8f10bb05081"},{"id":"func/_v3_conditional_step_ids","name":"_v3_conditional_step_ids","line":710,"end_line":718,"hash":"1028beed0dd3034214a1264d1638701758e9b67df7c157e412aa773eeabe5b4d"},{"id":"func/_v3_condition_result_step_ids","name":"_v3_condition_result_step_ids","line":721,"end_line":728,"hash":"3268ec9a075ac593935fdef3fbf6bf7c3223141e9e2288676c7e95f300fcfa5c"},{"id":"func/_accumulate_v3_conditional_stats","name":"_accumulate_v3_conditional_stats","line":731,"end_line":742,"hash":"00cc216d9a4a83abc7fabe39c0ef192229470782cd71b348d89a9820c40c868f"},{"id":"func/_accumulate_v3_projection_recall","name":"_accumulate_v3_projection_recall","line":745,"end_line":764,"hash":"360f359c68e93d0bfa806b974a170cd31593ee394cb9c4ea1cca3e528a7ba059"},{"id":"func/_v3_scenario_classifications","name":"_v3_scenario_classifications","line":767,"end_line":775,"hash":"0a14f3fb520f46283080d93e30959fc800c073dd6f4dd19460199139e340626c"},{"id":"func/_accumulate_v3_pinned_stats","name":"_accumulate_v3_pinned_stats","line":778,"end_line":791,"hash":"c8a82d602327ff8b3616664b67ff8aa18db80d72166789c177b0ca29ad498403"},{"id":"func/_accumulate_v3_projection_mappings","name":"_accumulate_v3_projection_mappings","line":794,"end_line":801,"hash":"a10a106fcb31ab73abf9a1b9f7aa5c0cce1abf2bc0363b7a72a8c11393bf95a0"},{"id":"func/_v3_narrative_zones","name":"_v3_narrative_zones","line":804,"end_line":810,"hash":"565fc55d91ff1e2df53dd4608e330fa1e8d7acfd128e3c68c706dec003878280"},{"id":"func/_v3_tree_zones","name":"_v3_tree_zones","line":813,"end_line":819,"hash":"754f01f2272f3085becd413899d94130f7feba8ff72eb5e9b6a219d630e414a9"},{"id":"func/_accumulate_v3_zone_differences","name":"_accumulate_v3_zone_differences","line":822,"end_line":831,"hash":"95808956234924eff2a1fbd54fbf66cd2931cc54568cafd329915e9686d08464"},{"id":"func/_accumulate_v3_scenario_counters","name":"_accumulate_v3_scenario_counters","line":834,"end_line":852,"hash":"65bf5b1606ccc7430683117f1628f0570c375ea37fe5c0fd86eb5e081cb1de46"},{"id":"func/_collect_v3_scenario_counters","name":"_collect_v3_scenario_counters","line":855,"end_line":868,"hash":"ad79961eb189b9bd98b7dd1750b059315e891ff47299e0a82511e0ff18bd8501"},{"id":"func/_build_v3_agreement_metrics","name":"_build_v3_agreement_metrics","line":871,"end_line":934,"hash":"1b99b01fb865e67e162f98e02a610f730e8ed75ed59b6f85c05bae0136463b04"},{"id":"func/_v3_structural_signature_match","name":"_v3_structural_signature_match","line":937,"end_line":944,"hash":"45f485370b1c10b5eba22ade8c41356ca24ad2d3fd739616326cb8b169f7fa55"},{"id":"func/_v3_structural_edges","name":"_v3_structural_edges","line":947,"end_line":957,"hash":"0468f2898d3639df4016ac40d7f42bde9756611834e9889fa31e9b31d4d3395b"},{"id":"func/_v3_structural_components","name":"_v3_structural_components","line":960,"end_line":965,"hash":"ff79dcfa15f53030ff32f5e49340553a95f98f59121e306ec11426dee54d122d"},{"id":"func/_v3_group_affected","name":"_v3_group_affected","line":968,"end_line":970,"hash":"d0ae65f6d90f9748d49c5a54cef9c3853f1957670e6c575e08d3cae68fff6cb5"},{"id":"func/_build_v3_diagnostics","name":"_build_v3_diagnostics","line":973,"end_line":1042,"hash":"71bb0f5493c69c8dc11abf294ae6042166728621ebe6f3a776d61a8a3c94ff10"},{"id":"func/_v3_quarantine_ids","name":"_v3_quarantine_ids","line":1045,"end_line":1047,"hash":"af461916dbd2c40eedc76119906fae500a794d5ac6737f6ec8a03cf8d8a8dbaa"},{"id":"func/_v3_evaluated_candidate_ids","name":"_v3_evaluated_candidate_ids","line":1050,"end_line":1058,"hash":"466d7a3bb6821b288137f6e26bcf56ea579b7e460cb3a62a83dad6b68e309e29"},{"id":"func/_v3_profile_completeness_flags","name":"_v3_profile_completeness_flags","line":1061,"end_line":1071,"hash":"799b66de57d03649594e621e3c158495f798fdc07b7eaa97f2ef0ae243776fe6"},{"id":"func/_build_v3_release_metrics","name":"_build_v3_release_metrics","line":1074,"end_line":1168,"hash":"6302a0fc3ff794c255a42b7d18cb9f98ce75c86a5add4a819e24da95b4b50dc5"}]}
# mutate4py-manifest-end

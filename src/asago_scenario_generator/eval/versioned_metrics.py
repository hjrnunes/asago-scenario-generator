"""Authoritative v3 evaluation over admitted, resolver-verified artifacts."""

from __future__ import annotations

import re
from collections import Counter
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
from asago_scenario_generator.pipeline.persistence import (
    CoveragePlanV2,
    FinalizationInventoryV1,
)
from asago_scenario_generator.pipeline.finalization_gates import AdmissionEvidenceId

_TITLE_TOKEN_RE = re.compile(r"[a-z0-9]+")
_NEAR_TITLE_THRESHOLD = 0.6


def _ids(items: list[dict[str, Any]], key: str) -> set[str]:
    return {str(item[key]) for item in items if item.get(key)}


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


def _components(nodes: list[str], edges: set[tuple[str, str]]) -> list[list[str]]:
    neighbors = {node: set() for node in nodes}
    for left, right in edges:
        neighbors[left].add(right)
        neighbors[right].add(left)
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
            for neighbor in sorted(neighbors[current], reverse=True):
                if neighbor not in seen:
                    seen.add(neighbor)
                    pending.append(neighbor)
        result.append(sorted(component))
    return sorted(result)


def title_duplicate_components(
    titles: dict[str, str],
) -> tuple[list[list[str]], list[list[str]]]:
    """Return exact-normalized groups and deterministic near-title components."""
    normalized_groups: dict[str, list[str]] = {}
    for scenario_id, title in titles.items():
        normalized_groups.setdefault(_normal_title(title), []).append(scenario_id)
    exact_groups = sorted(
        sorted(group)
        for title, group in normalized_groups.items()
        if title and len(group) > 1
    )
    title_edges: set[tuple[str, str]] = set()
    ids = sorted(titles)
    for index, left in enumerate(ids):
        for right in ids[index + 1 :]:
            left_tokens, right_tokens = (
                _title_tokens(titles[left]),
                _title_tokens(titles[right]),
            )
            union = left_tokens | right_tokens
            similarity = len(left_tokens & right_tokens) / len(union) if union else 0.0
            if similarity >= _NEAR_TITLE_THRESHOLD and _normal_title(
                titles[left]
            ) != _normal_title(titles[right]):
                title_edges.add((left, right))
    return exact_groups, _components(ids, title_edges)


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
    if not getattr(resolver, "check_orphans", False):
        return MetricResult(
            status=MetricStatus.NOT_APPLICABLE,
            evidence=[
                evidence,
                "in-progress resolver does not own final orphan reconciliation",
            ],
            affected_ids=[],
        )
    return zero_gate(0, evidence=[evidence])


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
        records = {
            evidence_id: [
                gate for gate in decision.gate_results if gate.gate is evidence_id
            ]
            for evidence_id in evidence_ids
        }
        if any(len(items) != 1 for items in records.values()):
            malformed.append(decision.candidate_id)
            continue
        if expected_applicable is not None and any(
            items[0].applicable is not expected_applicable for items in records.values()
        ):
            malformed.append(decision.candidate_id)
            continue
        if any(not items[0].applicable for items in records.values()):
            malformed.append(decision.candidate_id)
            continue
        if any(not items[0].passed for items in records.values()):
            failed.append(decision.candidate_id)
        elif decision.admitted:
            exact_admitted_passes.append(decision.candidate_id)
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


def _v3_exact_affected(exact_groups: list[list[str]]) -> list[str]:
    """Return scenario IDs participating in exact duplicate groups."""
    return sorted({sid for group in exact_groups for sid in group})


def _v3_structural_signature_match(
    structures: dict[str, tuple[str, ...]],
    left: str,
    right: str,
) -> bool:
    """True when two scenarios share a nonempty structural signature."""
    return bool(structures[left]) and structures[left] == structures[right]


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

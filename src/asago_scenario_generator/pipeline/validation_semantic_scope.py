"""Cross-artifact and technique-scope semantic validation helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from asago_scenario_generator.models.attack_tree import AttackTreeNode
from asago_scenario_generator.models.scenario import SemanticViolation
from asago_scenario_generator.pipeline.technique_scopes import (
    narrative_reference_ids,
    projected_step_mapping_ids,
    projected_step_mapping_ids_by_step,
    resolved_technique_scope_evidence,
    stable_unique,
)
from asago_scenario_generator.pipeline.validation_common import (
    _VALID_THREAT_IDS,
    _collect_leaves,
    _collect_tree_node_threat_ids,
    _collect_tree_node_zones,
    _extract_gherkin_zones_for_validation,
    _semantic_gherkin_text,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope


def _semantic_tree_technique_set(scenario: ScenarioEnvelope) -> set[str]:
    """Return the scenario's attack-tree technique IDs as a set."""
    return set(scenario.attack_tree.collect_technique_ids())


def _check_semantic_tree_techniques(
    scenario: ScenarioEnvelope,
    valid_technique_ids: frozenset[str],
    violations: list[SemanticViolation],
) -> None:
    """Record attack-tree technique IDs absent from the pinned set."""
    for tid in scenario.attack_tree.collect_technique_ids():
        if tid not in valid_technique_ids:
            violations.append(
                SemanticViolation(
                    rule="technique_exists",
                    message=f"{tid} not in pinned technique set",
                    severity="major",
                )
            )


def _check_semantic_narrative_zones(
    scenario: ScenarioEnvelope,
    valid_zones: set[str],
    violations: list[SemanticViolation],
) -> None:
    """Record narrative zones absent from the profile's active zones."""
    for zone in scenario.narrative.zone_sequence:
        if zone not in valid_zones:
            violations.append(
                SemanticViolation(
                    rule="zone_in_profile",
                    message=(
                        f"Zone '{zone}' in narrative zone_sequence "
                        f"is not in profile's zones_active: {sorted(valid_zones)}"
                    ),
                    severity="minor",
                )
            )


def _check_semantic_threat_ids(
    scenario: ScenarioEnvelope,
    violations: list[SemanticViolation],
) -> None:
    """Record out-of-range tree threat_ids and a missing scenario threat_id."""
    seed_metadata = scenario.scenario_seed_metadata
    if seed_metadata and "threat_id" in seed_metadata:
        expected_threat = seed_metadata["threat_id"]
        _check_tree_threat_ids(
            scenario.attack_tree.root,
            expected_threat,
            violations,
        )
        all_tree_threat_ids = _collect_tree_node_threat_ids(scenario.attack_tree.root)
        if expected_threat not in all_tree_threat_ids:
            violations.append(
                SemanticViolation(
                    rule="missing_scenario_threat_id",
                    message=(
                        f"No tree node carries the scenario's threat_id "
                        f"'{expected_threat}'; tree threat_ids are "
                        f"{sorted(all_tree_threat_ids)}"
                    ),
                    severity="major",
                )
            )


def _check_semantic_unknown_scope_techniques(
    scope_evidence: Any,
    tree_technique_set: set[str],
    valid_technique_ids: frozenset[str],
    violations: list[SemanticViolation],
) -> None:
    """Record unknown ATLAS IDs in published technique-scope evidence."""
    scenario_classifications = set(scope_evidence.scenario_classification_ids)
    projected_mapping_ids = set(scope_evidence.projected_step_mapping_ids)
    for technique_id in sorted(
        (scenario_classifications | projected_mapping_ids) - tree_technique_set
    ):
        if technique_id not in valid_technique_ids:
            violations.append(
                SemanticViolation(
                    rule="technique_exists",
                    message=(
                        f"{technique_id} is unknown in published ATLAS "
                        "technique-scope evidence"
                    ),
                    severity="major",
                )
            )


def _check_semantic_narrative_orphans(
    scope_evidence: Any,
    scenario: ScenarioEnvelope,
    violations: list[SemanticViolation],
) -> None:
    """Record narrative ATLAS references with no scope grounding."""
    actual_narrative_ids = set(narrative_reference_ids(scenario.narrative))
    grounded_narrative_ids = set(scope_evidence.scenario_classification_ids) | set(
        scope_evidence.projected_step_mapping_ids
    )
    for orphan_tid in sorted(actual_narrative_ids - grounded_narrative_ids):
        violations.append(
            SemanticViolation(
                rule="narrative_technique_orphan",
                message=(
                    f"Technique '{orphan_tid}' mentioned in narrative "
                    "but absent from both scenario classifications and "
                    "projected-step mappings"
                ),
                severity="minor",
            )
        )


def _expected_scope_classifications(
    scenario: ScenarioEnvelope,
) -> list[str] | None:
    """Return qualified-pin or seed-fallback classifications."""
    candidate_filter = scenario.candidate_filter or {}
    if candidate_filter.get("pinned_technique_ids"):
        return stable_unique(candidate_filter["pinned_technique_ids"])
    if scenario.scenario_seed_metadata is not None:
        return stable_unique(
            scenario.scenario_seed_metadata.get("atlas_technique_ids") or ()
        )
    return None


def _check_semantic_classification_evidence(
    scenario: ScenarioEnvelope,
    scope_evidence: Any,
    violations: list[SemanticViolation],
) -> None:
    """Reconcile faceted and expected classifications with published scope."""
    faceted_classifications = stable_unique(
        scenario.faceting.taxonomy_chain.atlas_technique_ids or ()
    )
    if faceted_classifications != scope_evidence.scenario_classification_ids:
        violations.append(
            SemanticViolation(
                rule="scenario_classification_mismatch",
                message=(
                    "Faceted scenario classifications "
                    f"{faceted_classifications} do not equal published "
                    "technique-scope classifications "
                    f"{scope_evidence.scenario_classification_ids}."
                ),
                severity="major",
            )
        )
    expected_classifications = _expected_scope_classifications(scenario)
    if (
        expected_classifications is not None
        and expected_classifications != scope_evidence.scenario_classification_ids
    ):
        violations.append(
            SemanticViolation(
                rule="scenario_classification_mismatch",
                message=(
                    "Published scenario classifications "
                    f"{scope_evidence.scenario_classification_ids} do not "
                    "equal qualified pins or seed fallback "
                    f"{expected_classifications}."
                ),
                severity="major",
            )
        )


def _check_semantic_projection_evidence(
    scenario: ScenarioEnvelope,
    scope_evidence: Any,
    violations: list[SemanticViolation],
) -> None:
    """Reconcile canonical projection mappings with published scope."""
    canonical_mapping_ids = projected_step_mapping_ids(scenario.projection)
    if canonical_mapping_ids != scope_evidence.projected_step_mapping_ids:
        violations.append(
            SemanticViolation(
                rule="projected_step_mapping_evidence_mismatch",
                message=(
                    "Published projected-step mappings "
                    f"{scope_evidence.projected_step_mapping_ids} do not "
                    f"equal canonical mappings {canonical_mapping_ids}."
                ),
                severity="major",
            )
        )
    actual_narrative_ids = set(narrative_reference_ids(scenario.narrative))
    if actual_narrative_ids != set(scope_evidence.narrative_reference_ids):
        violations.append(
            SemanticViolation(
                rule="narrative_reference_evidence_mismatch",
                message=(
                    "Published narrative ATLAS references "
                    f"{scope_evidence.narrative_reference_ids} do not equal "
                    f"the authored narrative references "
                    f"{sorted(actual_narrative_ids)}."
                ),
                severity="major",
            )
        )


def _check_semantic_technique_scope_evidence(
    scenario: ScenarioEnvelope,
    tree_technique_set: set[str],
    valid_technique_ids: frozenset[str],
    violations: list[SemanticViolation],
) -> None:
    """Reconcile technique-scope evidence with tree, narrative, and pins."""
    scope_evidence = resolved_technique_scope_evidence(scenario)
    _check_semantic_unknown_scope_techniques(
        scope_evidence, tree_technique_set, valid_technique_ids, violations
    )
    _check_semantic_narrative_orphans(scope_evidence, scenario, violations)
    if scenario.technique_scope_evidence is not None:
        _check_semantic_classification_evidence(scenario, scope_evidence, violations)
        _check_semantic_projection_evidence(scenario, scope_evidence, violations)


def _incompatible_mapping_steps(
    technique_id: str,
    represented_steps: tuple[str, ...],
    exact_ids_by_step: dict[str, frozenset[str]],
) -> list[str]:
    """Return represented steps whose exact ATLAS mapping excludes the leaf
    technique."""
    return [
        step_id
        for step_id in represented_steps
        if technique_id not in exact_ids_by_step.get(step_id, frozenset())
    ]


def _check_semantic_leaf_technique_mapping(
    leaf: Any,
    exact_ids_by_step: dict[str, frozenset[str]],
    violations: list[SemanticViolation],
) -> None:
    """Reconcile one leaf technique with its represented projected steps."""
    if leaf.technique_id is None:
        return
    represented_steps = tuple(leaf.projected_step_ids)
    if not represented_steps:
        violations.append(
            SemanticViolation(
                rule="leaf_technique_mapping_mismatch",
                message=(
                    f"Leaf '{leaf.id}' carries technique "
                    f"'{leaf.technique_id}' without a projected-step "
                    "realization."
                ),
                severity="major",
            )
        )
        return
    incompatible_steps = _incompatible_mapping_steps(
        leaf.technique_id, represented_steps, exact_ids_by_step
    )
    if incompatible_steps:
        violations.append(
            SemanticViolation(
                rule="leaf_technique_mapping_mismatch",
                message=(
                    f"Leaf '{leaf.id}' technique '{leaf.technique_id}' "
                    "is not an exact ATLAS mapping of represented "
                    f"projected steps {incompatible_steps}."
                ),
                severity="major",
            )
        )


def _check_semantic_leaf_technique_mappings(
    scenario: ScenarioEnvelope,
    violations: list[SemanticViolation],
) -> None:
    """Reconcile every leaf technique with exact projected-step mappings."""
    if scenario.technique_scope_evidence is None:
        return
    exact_ids_by_step = projected_step_mapping_ids_by_step(scenario.projection)
    for leaf in _collect_leaves(scenario.attack_tree.root):
        _check_semantic_leaf_technique_mapping(leaf, exact_ids_by_step, violations)


def _check_semantic_tree_zone_omissions(
    artifact_coverage_zones: set[str],
    tree_zones: set[str],
    zone_seq: list[str],
    violations: list[SemanticViolation],
) -> None:
    """Record narrative zones absent from attack-tree nodes."""
    omitted_tree_zones = sorted(artifact_coverage_zones - tree_zones)
    terminal_zone = zone_seq[-1] if zone_seq else None
    compound_omission = len(omitted_tree_zones) >= 2
    for zone in omitted_tree_zones:
        is_terminal = zone == terminal_zone
        severity = "major" if is_terminal or compound_omission else "minor"
        violations.append(
            SemanticViolation(
                rule="zone_omission_tree",
                message=(
                    f"Zone '{zone}' in narrative zone_sequence "
                    f"but absent from attack tree nodes"
                ),
                severity=severity,
            )
        )


def _check_semantic_gherkin_zone_omissions(
    artifact_coverage_zones: set[str],
    gherkin_zones: set[str],
    violations: list[SemanticViolation],
) -> None:
    """Record narrative zones absent from Gherkin behavior spec."""
    for zone in sorted(artifact_coverage_zones - gherkin_zones):
        violations.append(
            SemanticViolation(
                rule="zone_omission_gherkin",
                message=(
                    f"Zone '{zone}' in narrative zone_sequence "
                    f"but absent from Gherkin behavior_spec"
                ),
                severity="minor",
            )
        )


def _check_semantic_zone_coverage_dropout(
    artifact_coverage_zones: set[str],
    tree_zones: set[str],
    gherkin_zones: set[str],
    violations: list[SemanticViolation],
) -> None:
    """Record narrative zones absent from BOTH tree and Gherkin."""
    dropped_zones = artifact_coverage_zones - (tree_zones | gherkin_zones)
    for zone in sorted(dropped_zones):
        violations.append(
            SemanticViolation(
                rule="zone_coverage_dropout",
                message=(
                    f"Zone '{zone}' in narrative zone_sequence is absent "
                    f"from BOTH attack tree nodes AND Gherkin behavior_spec"
                ),
                severity="major",
            )
        )


def _check_semantic_zone_omissions(
    scenario: ScenarioEnvelope,
    violations: list[SemanticViolation],
) -> None:
    """Run tree/Gherkin zone omission and coverage-dropout checks."""
    artifact_coverage_zones = set(scenario.narrative.zone_sequence) - {"outside"}
    tree_zones = _collect_tree_node_zones(scenario.attack_tree.root)
    _check_semantic_tree_zone_omissions(
        artifact_coverage_zones,
        tree_zones,
        scenario.narrative.zone_sequence,
        violations,
    )
    gherkin_text = _semantic_gherkin_text(scenario)
    if gherkin_text:
        gherkin_zones = _extract_gherkin_zones_for_validation(gherkin_text)
        _check_semantic_gherkin_zone_omissions(
            artifact_coverage_zones, gherkin_zones, violations
        )
    else:
        gherkin_zones = set()
    _check_semantic_zone_coverage_dropout(
        artifact_coverage_zones, tree_zones, gherkin_zones, violations
    )


def _check_tree_threat_ids(
    node: AttackTreeNode,
    expected_threat: str,
    violations: list,
) -> None:
    """Recursively check threat_id on tree nodes against valid range.

    Per ``decision-t6-crossref-policy``, per-node ``threat_id`` may reflect
    the mechanism rather than the scenario-level threat.  This check therefore
    validates **range** (is it a real OWASP threat in T1-T17?) rather than
    requiring a match to *expected_threat*.
    """
    from asago_scenario_generator.models.scenario import SemanticViolation

    tid = node.threat_id
    if tid is not None and tid not in _VALID_THREAT_IDS:
        violations.append(
            SemanticViolation(
                rule="threat_id_range",
                message=(
                    f"Node '{node.id}' has invalid threat_id '{tid}'; "
                    f"valid range is T1-T17"
                ),
                severity="major",
            )
        )

    if node.children:
        for child in node.children:
            _check_tree_threat_ids(child, expected_threat, violations)

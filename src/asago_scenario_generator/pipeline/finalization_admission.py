"""Verify-only postbehavior admission for cmps.5 Phase 3B.

The port is deliberately unwired from the production runner.  It consumes
fresh materializations supplied by :class:`TargetFinalizationMachine`, builds
one transient envelope, and aggregates hard gate failures without persisting
or repairing normal output.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.models.attack_tree import (
    ExternalPreconditionAction,
    GateType,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.models.scenario import ValidationBlock
from asago_scenario_generator.pipeline.finalization import (
    AdmissionDecision,
    GeneratedArtifacts,
    GeneratedStage,
)
from asago_scenario_generator.pipeline.finalization_gates import (
    DIAGNOSTIC_BACKED_EVIDENCE_IDS,
    EXCEPTIONAL_ADMISSION_EVIDENCE_IDS,
    NORMAL_POSTBEHAVIOR_EVIDENCE_IDS,
    AdmissionEvidenceId,
    GateCode,
    GateResult,
    GateViolation,
    check_tree_parsimony,
)
from asago_scenario_generator.pipeline.complexity import (
    assess_candidate_complexity,
    assess_final_complexity,
    evaluate_capability_admission,
)
from asago_scenario_generator.pipeline.generate.gherkin import (
    _collect_leaf_nodes_dfs,
    _leaf_step_kind,
)
from asago_scenario_generator.pipeline.projection import (
    compute_authoritative_catalog_pin,
)
from asago_scenario_generator.pipeline.projection_validation import (
    validate_projection_traceability,
)
from asago_scenario_generator.pipeline.validation import (
    check_scenario_semantics,
    validate_phantom_capabilities,
    validate_scenario_structure,
)

EnvelopeAssembler = Callable[[Any, Any, Any, Any, Any], Any]

_SEMANTIC_DIAGNOSTIC_RULES = {
    "missing_scenario_threat_id",
    "zone_omission_tree",
    "zone_omission_gherkin",
}
_TOOL_RULES = frozenset(
    {"untyped-tool-execution", "phantom_tool", "unknown_integration_id"}
)
_TRACE_OWNER_BY_STAGE = {
    ProjectionTraceabilityStage.actor_profile: GeneratedStage.actor,
    ProjectionTraceabilityStage.narrative: GeneratedStage.narrative,
    ProjectionTraceabilityStage.attack_tree: GeneratedStage.tree,
    ProjectionTraceabilityStage.behavior_spec: GeneratedStage.behavior,
}
_TRACE_OWNER_OVERRIDES: dict[
    tuple[ProjectionTraceabilityViolationCode, ProjectionTraceabilityStage],
    GeneratedStage | None,
] = {
    **{
        (code, stage): None
        for code in (
            ProjectionTraceabilityViolationCode.nested_mutation,
            ProjectionTraceabilityViolationCode.projection_drift,
            ProjectionTraceabilityViolationCode.requirement_drift,
            ProjectionTraceabilityViolationCode.authoritative_pattern_pin_mismatch,
            ProjectionTraceabilityViolationCode.authoritative_catalog_pin_mismatch,
        )
        for stage in ProjectionTraceabilityStage
    },
    (
        ProjectionTraceabilityViolationCode.forged_opaque_id,
        ProjectionTraceabilityStage.actor_profile,
    ): None,
}
_SEMANTIC_OWNER_BY_RULE: dict[str, GeneratedStage | None] = {
    "technique_exists": GeneratedStage.tree,
    "threat_id_range": GeneratedStage.tree,
    "missing_scenario_threat_id": GeneratedStage.tree,
    "narrative_technique_orphan": GeneratedStage.narrative,
    "zone_in_profile": GeneratedStage.narrative,
    "zone_omission_tree": GeneratedStage.tree,
    "zone_omission_gherkin": GeneratedStage.behavior,
    "zone_coverage_dropout": GeneratedStage.narrative,
    "untyped-tool-execution": GeneratedStage.tree,
    "unknown_entry_point_id": GeneratedStage.tree,
    "inaccessible_ingress_entry_point": GeneratedStage.tree,
    "phantom_tool": GeneratedStage.tree,
    "unknown_integration_id": GeneratedStage.tree,
    "scenario_classification_mismatch": None,
    "projected_step_mapping_evidence_mismatch": None,
    "narrative_reference_evidence_mismatch": None,
    "leaf_technique_mapping_mismatch": None,
    "goal_actor_mismatch": GeneratedStage.actor,
    "goal_mechanism_mismatch": GeneratedStage.actor,
    "missing_access_provenance": GeneratedStage.actor,
    "unresolved_entry_point_id": GeneratedStage.actor,
    "ineligible_ingress_entry_point": GeneratedStage.actor,
    "system_entry_point_as_ingress": GeneratedStage.actor,
    "ingress_mode_controllability_mismatch": GeneratedStage.actor,
    "unresolved_influence_source": GeneratedStage.actor,
    "self_relation_influence_source": GeneratedStage.actor,
    "output_influence_source": GeneratedStage.actor,
    "system_influence_source": GeneratedStage.actor,
    "unresolved_trust_boundary": GeneratedStage.actor,
    "trust_boundary_target_zone_mismatch": GeneratedStage.actor,
    "trust_boundary_source_zone_mismatch": GeneratedStage.actor,
    "external_boundary_source_not_indirect": GeneratedStage.actor,
    "access_class_ingress_mode_incompatible": GeneratedStage.actor,
    "incomplete_indirect_evidence": GeneratedStage.actor,
    "missing_insider_advantage": GeneratedStage.actor,
    "missing_access_realization": GeneratedStage.narrative,
    "realization_entry_point_mismatch": GeneratedStage.narrative,
    "realization_influence_source_mismatch": GeneratedStage.narrative,
    "realization_trust_boundary_mismatch": GeneratedStage.narrative,
    "realization_step_not_found": GeneratedStage.narrative,
    "direct_realization_has_indirect_ref": GeneratedStage.narrative,
}
_DATA_ACCESS_RULES = frozenset(
    {
        "unknown_entry_point_id",
        "inaccessible_ingress_entry_point",
        "missing_access_provenance",
        "unresolved_entry_point_id",
        "ineligible_ingress_entry_point",
        "system_entry_point_as_ingress",
        "ingress_mode_controllability_mismatch",
        "unresolved_influence_source",
        "self_relation_influence_source",
        "output_influence_source",
        "system_influence_source",
        "unresolved_trust_boundary",
        "trust_boundary_target_zone_mismatch",
        "trust_boundary_source_zone_mismatch",
        "external_boundary_source_not_indirect",
        "access_class_ingress_mode_incompatible",
        "incomplete_indirect_evidence",
        "missing_insider_advantage",
        "missing_access_realization",
        "realization_entry_point_mismatch",
        "realization_influence_source_mismatch",
        "realization_trust_boundary_mismatch",
        "realization_step_not_found",
        "direct_realization_has_indirect_ref",
    }
)
_CAPABILITY_RULES = frozenset(
    {
        "technique_exists",
        "threat_id_range",
        "narrative_technique_orphan",
        "zone_in_profile",
        "zone_coverage_dropout",
        "scenario_classification_mismatch",
        "projected_step_mapping_evidence_mismatch",
        "narrative_reference_evidence_mismatch",
        "leaf_technique_mapping_mismatch",
        "goal_actor_mismatch",
        "goal_mechanism_mismatch",
    }
)
_CANONICAL_COMPILATION_RULES = frozenset(
    {
        "scenario_classification_mismatch",
        "projected_step_mapping_evidence_mismatch",
        "narrative_reference_evidence_mismatch",
        "leaf_technique_mapping_mismatch",
    }
)
_CLASSIFIED_SEMANTIC_RULES = (
    _TOOL_RULES | _DATA_ACCESS_RULES | _CAPABILITY_RULES | _SEMANTIC_DIAGNOSTIC_RULES
)
if _CLASSIFIED_SEMANTIC_RULES != frozenset(_SEMANTIC_OWNER_BY_RULE):
    raise RuntimeError("hard semantic admission rule taxonomy is not exhaustive")


@dataclass(frozen=True, slots=True)
class PostbehaviorAdmissionReport:
    """All gate outcomes for an admitted transient envelope."""

    envelope: Any
    gate_results: tuple[GateResult, ...]

    def __post_init__(self) -> None:
        evidence_ids = tuple(result.evidence_id for result in self.gate_results)
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("postbehavior admission evidence IDs must be unique")
        exceptional = set(evidence_ids) & EXCEPTIONAL_ADMISSION_EVIDENCE_IDS
        if exceptional and (len(evidence_ids) != 1 or self.envelope is not None):
            raise ValueError("exceptional admission evidence must be a singleton")
        authoritative = tuple(
            violation for result in self.gate_results for violation in result.violations
        )
        if any(
            diagnostic not in authoritative
            for result in self.gate_results
            if result.evidence_id in DIAGNOSTIC_BACKED_EVIDENCE_IDS
            for diagnostic in result.diagnostics
        ):
            raise ValueError("category diagnostic must copy an authoritative violation")

    @property
    def diagnostics(self) -> tuple[GateViolation, ...]:
        return tuple(
            diagnostic
            for result in self.gate_results
            for diagnostic in result.diagnostics
        )


def _gate(code: GateCode, detail: str, owner: GeneratedStage | None) -> GateViolation:
    return GateViolation(code, detail, owner)


def _keyword(leaf: Any) -> str:
    kind = _leaf_step_kind(leaf)
    return "Given" if kind == "given" else "Then" if kind == "then" else "When"


def _owner_for_trace(item: Any) -> GeneratedStage | None:
    if item.code is ProjectionTraceabilityViolationCode.ingress_identity_mismatch:
        return {
            "envelope.initial_entry_point_id": None,
            "actor_profile.access.initial_entry_point_id": GeneratedStage.actor,
        }.get(item.element_id, _TRACE_OWNER_BY_STAGE[item.stage])
    return _TRACE_OWNER_OVERRIDES.get(
        (item.code, item.stage), _TRACE_OWNER_BY_STAGE[item.stage]
    )


def _owner_for_structural(detail: str) -> GeneratedStage | None:
    prefix = detail.split(".", 1)[0]
    return {
        "actor_profile": GeneratedStage.actor,
        "narrative": GeneratedStage.narrative,
        "attack_tree": GeneratedStage.tree,
        "behavior_spec": GeneratedStage.behavior,
    }.get(prefix)


class PostbehaviorAdmissionPort:
    """Concrete hard-gate callback for ``TargetFinalizationMachine``."""

    def __init__(
        self,
        envelope_assembler: EnvelopeAssembler,
        *,
        trusted_catalog: Sequence[dict[str, Any]],
        taxonomy_resolver: Any,
        capability_snapshot: Any,
        expected_scenario_id: str,
        expected_catalog_pin: str | None = None,
    ) -> None:
        self.envelope_assembler = envelope_assembler
        self.trusted_catalog = trusted_catalog
        self.taxonomy_resolver = taxonomy_resolver
        self.capability_snapshot = capability_snapshot
        self.expected_catalog_pin = expected_catalog_pin
        self.expected_scenario_id = expected_scenario_id
        self.profile = capability_snapshot.profile

    def __call__(
        self, candidate: Any, artifacts: GeneratedArtifacts, snapshot: Any
    ) -> AdmissionDecision:
        gate_results: list[GateResult] = []

        try:
            snapshot.verify_digest()
            self.capability_snapshot.assert_integrity()
            tree = snapshot.tree
            envelope = self.envelope_assembler(
                candidate,
                artifacts.actor,
                artifacts.narrative,
                tree,
                artifacts.behavior,
            )
            # The assembler only receives fresh copies.  Reverify the authority
            # after it returns so aliasing cannot silently change the snapshot.
            snapshot.verify_digest()
        except (TypeError, ValueError, AttributeError) as exc:
            violation = _gate(GateCode.snapshot_integrity, str(exc), None)
            return AdmissionDecision(
                False,
                (violation.lifecycle(),),
                value=PostbehaviorAdmissionReport(
                    envelope=None,
                    gate_results=(
                        GateResult(
                            AdmissionEvidenceId.snapshot_integrity, (violation,)
                        ),
                    ),
                ),
            )

        identity: list[GateViolation] = []
        if envelope.candidate_id != candidate.candidate_id:
            identity.append(
                _gate(
                    GateCode.candidate_identity,
                    "transient envelope candidate_id differs from verified candidate",
                    None,
                )
            )
        if envelope.scenario_id != self.expected_scenario_id:
            identity.append(
                _gate(
                    GateCode.scenario_identity,
                    "transient envelope scenario_id differs from finalization owner",
                    None,
                )
            )
        authoritative_pin = compute_authoritative_catalog_pin(
            self.trusted_catalog, self.taxonomy_resolver
        )
        trusted_context: list[GateViolation] = []
        if (
            self.expected_catalog_pin is not None
            and self.expected_catalog_pin != authoritative_pin
        ):
            trusted_context.append(
                _gate(
                    GateCode.trusted_context,
                    "supplied expected catalog pin differs from trusted "
                    "catalog recomputation",
                    None,
                )
            )
        gate_results.append(
            GateResult(
                AdmissionEvidenceId.identity, tuple((*identity, *trusted_context))
            )
        )

        pattern = next(
            (
                record
                for record in self.trusted_catalog
                if record.get("id") == candidate.pattern_id
            ),
            None,
        )
        trace_data_access: tuple[GateViolation, ...] = ()
        identifier_diagnostics: tuple[GateViolation, ...] = tuple(identity)
        if pattern is None:
            missing_pattern = _gate(
                GateCode.candidate_identity,
                f"pattern '{candidate.pattern_id}' is absent from trusted catalog",
                None,
            )
            gate_results.append(
                GateResult(
                    AdmissionEvidenceId.projection_traceability,
                    (missing_pattern,),
                )
            )
            gate_results.append(
                GateResult(
                    AdmissionEvidenceId.catalog_taxonomy_pin_validity,
                    diagnostics=(missing_pattern,),
                    outcome=False,
                )
            )
        else:
            trace = validate_projection_traceability(
                envelope,
                authoritative_pattern=pattern,
                taxonomy_resolver=self.taxonomy_resolver,
                capability_snapshot=self.capability_snapshot,
                expected_catalog_pin=authoritative_pin,
            )
            trace_categories = (
                (
                    AdmissionEvidenceId.resource_binding_validity,
                    {
                        ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                        ProjectionTraceabilityViolationCode.incorrect_ingress_binding,
                    },
                ),
                (
                    AdmissionEvidenceId.execution_requirement_drift,
                    {ProjectionTraceabilityViolationCode.requirement_drift},
                ),
                (
                    AdmissionEvidenceId.catalog_taxonomy_pin_validity,
                    {
                        ProjectionTraceabilityViolationCode.invalid_technique_mapping,
                        ProjectionTraceabilityViolationCode.authoritative_pattern_pin_mismatch,
                        ProjectionTraceabilityViolationCode.authoritative_catalog_pin_mismatch,
                    },
                ),
            )
            identifier_diagnostics = (
                *identifier_diagnostics,
                *(
                    _gate(GateCode.traceability, item.detail, _owner_for_trace(item))
                    for item in trace.violations
                    if item.code is ProjectionTraceabilityViolationCode.forged_opaque_id
                ),
            )
            for evidence_id, codes in trace_categories:
                category_violations = tuple(
                    _gate(GateCode.traceability, item.detail, _owner_for_trace(item))
                    for item in trace.violations
                    if item.code in codes
                )
                gate_results.append(
                    GateResult(
                        evidence_id,
                        diagnostics=category_violations,
                        outcome=not category_violations,
                    )
                )
            trace_data_access = tuple(
                _gate(GateCode.traceability, item.detail, _owner_for_trace(item))
                for item in trace.violations
                if item.code
                is ProjectionTraceabilityViolationCode.ingress_identity_mismatch
            )
            gate_results.append(
                GateResult(
                    AdmissionEvidenceId.projection_traceability,
                    tuple(
                        _gate(
                            GateCode.traceability, item.detail, _owner_for_trace(item)
                        )
                        for item in trace.violations
                    ),
                )
            )

        gate_results.append(
            GateResult(
                AdmissionEvidenceId.identifier_validity,
                diagnostics=identifier_diagnostics,
                outcome=not identifier_diagnostics,
            )
        )

        structural_copy = envelope.model_copy(deep=True)
        validate_scenario_structure([structural_copy])
        structural = structural_copy.validation.structural
        gate_results.append(
            GateResult(
                AdmissionEvidenceId.structural_validity,
                tuple(
                    _gate(
                        GateCode.structural,
                        detail,
                        _owner_for_structural(detail),
                    )
                    for detail in structural.violations
                ),
            )
        )

        phantom_copy = envelope.model_copy(deep=True)
        phantom_result = validate_phantom_capabilities([phantom_copy], self.profile)
        phantom_violations: list[GateViolation] = []
        for _, violations in phantom_result.flagged_scenarios:
            for item in violations:
                owner = (
                    GeneratedStage.behavior
                    if item.field == "behavior_spec"
                    else GeneratedStage.tree
                    if item.field == "attack_tree"
                    else GeneratedStage.narrative
                )
                phantom_violations.append(_gate(GateCode.phantom, item.reason, owner))
        gate_results.append(
            GateResult(AdmissionEvidenceId.phantom_validity, tuple(phantom_violations))
        )

        semantic = check_scenario_semantics(envelope, self.profile)
        semantic_hard: list[tuple[str, GateViolation]] = []
        semantic_diagnostics: list[GateViolation] = []
        for item in semantic.violations:
            # Traceability emits source-qualified evidence for this overloaded
            # rule, so do not duplicate it with an ownerless semantic string.
            if item.rule == "initial_entry_point_id_mismatch":
                continue
            owner = _SEMANTIC_OWNER_BY_RULE.get(item.rule)
            gate_code = (
                GateCode.canonical_compilation_failed
                if item.rule in _CANONICAL_COMPILATION_RULES
                else GateCode.semantic
            )
            violation = _gate(gate_code, item.message, owner)
            if item.rule in _SEMANTIC_DIAGNOSTIC_RULES:
                semantic_diagnostics.append(violation)
            else:
                semantic_hard.append((item.rule, violation))
        for evidence_id, rules in (
            (AdmissionEvidenceId.tool_integration_grounding, _TOOL_RULES),
            (AdmissionEvidenceId.data_access_grounding, _DATA_ACCESS_RULES),
            (AdmissionEvidenceId.capability_grounding, _CAPABILITY_RULES),
        ):
            selected = tuple(
                violation for rule, violation in semantic_hard if rule in rules
            )
            if evidence_id is AdmissionEvidenceId.data_access_grounding:
                selected = (*trace_data_access, *selected)
            # Category outcomes are exact evidence; the hard semantic stream
            # remains in source order in one authoritative gate.
            gate_results.append(
                GateResult(
                    evidence_id,
                    diagnostics=selected,
                    outcome=not selected,
                    applicable=(
                        self.profile.is_tool_inventory_complete
                        if evidence_id is AdmissionEvidenceId.tool_integration_grounding
                        else self.profile.is_entry_point_inventory_complete
                        if evidence_id is AdmissionEvidenceId.data_access_grounding
                        else True
                    ),
                )
            )
        gate_results.append(
            GateResult(
                AdmissionEvidenceId.semantic_validity,
                tuple(v for _, v in semantic_hard),
                tuple(semantic_diagnostics),
            )
        )

        all_leaves = tuple(_collect_leaf_nodes_dfs(tree.root))
        complexity = assess_final_complexity(
            assess_candidate_complexity(candidate), all_leaves, artifacts.actor.access
        )
        complexity_decision = evaluate_capability_admission(
            artifacts.actor.capability_level, complexity, phase="final"
        )
        complexity_violations: tuple[GateViolation, ...] = ()
        if not complexity_decision.admitted:
            routing = complexity_decision.violation.routing
            owner = (
                GeneratedStage.actor
                if routing.stage == "call0_actor_generation"
                else GeneratedStage.tree
            )
            complexity_violations = (
                _gate(GateCode.capability_complexity, routing.feedback, owner),
            )
        gate_results.append(
            GateResult(
                AdmissionEvidenceId.actor_attack_complexity, complexity_violations
            )
        )

        behavior_result = self._check_behavior(
            tree, artifacts.behavior, envelope.projection
        )
        gate_results.append(behavior_result)

        narrative_zones = {step.zone for step in envelope.narrative.steps}
        tree_zones = {
            leaf.zone
            for leaf in _collect_leaf_nodes_dfs(tree.root)
            if leaf.zone is not None
        }
        diagnostics: list[GateViolation] = []
        if narrative_zones != tree_zones:
            diagnostics.append(
                _gate(
                    GateCode.zone_difference,
                    "narrative and final-tree zone sets differ",
                    GeneratedStage.tree,
                )
            )
        leaf_count = len(_collect_leaf_nodes_dfs(tree.root))
        step_count = len(envelope.narrative.steps)
        if leaf_count and step_count:
            correspondence = min(leaf_count, step_count) / max(leaf_count, step_count)
            if correspondence < 0.7:
                diagnostics.append(
                    _gate(
                        GateCode.heuristic_correspondence,
                        f"narrative/tree count correspondence is {correspondence:.2f}",
                        GeneratedStage.tree,
                    )
                )
        gate_results.append(
            GateResult(
                AdmissionEvidenceId.narrative_tree_diagnostics,
                diagnostics=tuple(diagnostics),
            )
        )

        parsimony = check_tree_parsimony(tree)
        gate_results.append(parsimony)
        or_violations: tuple[GateViolation, ...] = ()
        if any(node.gate is GateType.OR for node in _nodes(tree.root)):
            or_violations = (
                _gate(
                    GateCode.or_tree,
                    "final tree contains an OR gate",
                    GeneratedStage.tree,
                ),
            )
        gate_results.append(
            GateResult(AdmissionEvidenceId.or_tree_prohibition, or_violations)
        )

        violations = tuple(
            violation.lifecycle()
            for result in gate_results
            for violation in result.violations
        )
        report = PostbehaviorAdmissionReport(envelope, tuple(gate_results))
        if violations:
            return AdmissionDecision(False, violations, value=report)
        if {result.evidence_id for result in report.gate_results} != set(
            NORMAL_POSTBEHAVIOR_EVIDENCE_IDS
        ):
            raise RuntimeError("successful admission requires canonical gate evidence")
        validation = ValidationBlock(
            structural=structural,
            phantom=phantom_copy.validation.phantom,
            semantic=semantic,
        )
        validated_envelope = envelope.model_copy(
            update={
                "validation": validation,
                "validation_passed": (
                    validation.structural.valid
                    and validation.phantom.valid
                    and validation.semantic.valid
                ),
            },
            deep=True,
        )
        report = PostbehaviorAdmissionReport(validated_envelope, tuple(gate_results))
        return AdmissionDecision(
            True,
            value=report,
        )

    def _check_behavior(self, tree: Any, behavior: Any, projection: Any) -> GateResult:
        violations: list[GateViolation] = []
        leaves = [
            leaf
            for leaf in _collect_leaf_nodes_dfs(tree.root)
            if leaf.projected_step_ids
        ]
        security_leaves = [
            leaf
            for leaf in leaves
            if not isinstance(leaf.action, ExternalPreconditionAction)
        ]
        actions = list(getattr(behavior, "actions", ()))
        if not security_leaves:
            violations.append(
                _gate(
                    GateCode.no_realized_security_actions,
                    "final tree has no realized security-bearing actions",
                    GeneratedStage.tree,
                )
            )
        if len(leaves) != len(actions):
            violations.append(
                _gate(
                    GateCode.tree_action_mismatch,
                    f"tree/action cardinality mismatch: {len(leaves)} != {len(actions)}",
                    GeneratedStage.tree,
                )
            )
        for index, (leaf, action) in enumerate(zip(leaves, actions, strict=False)):
            mismatch = (
                action.action_id != f"ba-{leaf.id}"
                or action.source_leaf_id != leaf.id
                or tuple(action.projected_step_ids) != tuple(leaf.projected_step_ids)
                or action.gherkin_keyword != _keyword(leaf)
                or tuple(action.realizations) != tuple(leaf.realizations)
            )
            if mismatch:
                violations.append(
                    _gate(
                        GateCode.tree_action_mismatch,
                        f"tree/action mismatch at DFS position {index} for '{leaf.id}'",
                        GeneratedStage.tree,
                    )
                )

        selected = set(projection.selected_step_ids)
        postcondition_owner: dict[str, str] = {}
        required_security: set[tuple[str, str]] = set()
        ambiguous_postconditions: set[str] = set()
        for step in projection.projection.source_chain.steps:
            if step.step_id not in selected:
                continue
            for postcondition in step.observable_postconditions:
                postcondition_id = postcondition.postcondition_id
                existing_owner = postcondition_owner.get(postcondition_id)
                if existing_owner is not None and existing_owner != step.step_id:
                    ambiguous_postconditions.add(postcondition_id)
                    violations.append(
                        _gate(
                            GateCode.candidate_identity,
                            f"postcondition '{postcondition_id}' has ambiguous owners "
                            f"'{existing_owner}' and '{step.step_id}'",
                            None,
                        )
                    )
                    continue
                postcondition_owner[postcondition_id] = step.step_id
                if postcondition.security_relevant:
                    required_security.add((step.step_id, postcondition_id))
        seen_ids: set[str] = set()
        seen_pairs: set[tuple[str, str]] = set()
        covered_security: set[tuple[str, str]] = set()
        for assertion in getattr(behavior, "assertions", ()):
            if assertion.assertion_id in seen_ids:
                violations.append(
                    _gate(
                        GateCode.assertion_mismatch,
                        f"duplicate assertion ID '{assertion.assertion_id}'",
                        GeneratedStage.behavior,
                    )
                )
            seen_ids.add(assertion.assertion_id)
            if (
                len(assertion.source_step_ids) != 1
                or len(assertion.projected_postcondition_ids) != 1
            ):
                violations.append(
                    _gate(
                        GateCode.assertion_mismatch,
                        f"assertion '{assertion.assertion_id}' must map one owner to one postcondition",
                        GeneratedStage.behavior,
                    )
                )
                continue
            source = assertion.source_step_ids[0]
            postcondition = assertion.projected_postcondition_ids[0]
            owner = postcondition_owner.get(postcondition)
            expected_id = f"assert-{owner}-{postcondition}"
            pair = (source, postcondition)
            if (
                source not in selected
                or owner is None
                or source != owner
                or assertion.assertion_id != expected_id
                or pair in seen_pairs
            ):
                violations.append(
                    _gate(
                        GateCode.assertion_mismatch,
                        f"assertion '{assertion.assertion_id}' has unknown, duplicate, or wrong-owner IDs",
                        GeneratedStage.behavior,
                    )
                )
            seen_pairs.add(pair)
            if (
                postcondition not in ambiguous_postconditions
                and pair in required_security
                and source == owner
            ):
                covered_security.add(pair)
        missing = required_security - covered_security
        if missing:
            violations.append(
                _gate(
                    GateCode.assertion_mismatch,
                    f"security-relevant postconditions lack assertions: {sorted(missing)}",
                    GeneratedStage.behavior,
                )
            )
        return GateResult(
            AdmissionEvidenceId.behavior_correspondence,
            tuple(dict.fromkeys(violations)),
        )


def _nodes(node: Any):
    yield node
    for child in node.children or ():
        yield from _nodes(child)


def make_postbehavior_admission(
    envelope_assembler: EnvelopeAssembler, **kwargs: Any
) -> PostbehaviorAdmissionPort:
    """Construct the concrete callback without production runner wiring."""
    return PostbehaviorAdmissionPort(envelope_assembler, **kwargs)

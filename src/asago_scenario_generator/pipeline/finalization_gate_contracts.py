"""Gate result contracts and admission-evidence classifications."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from asago_scenario_generator.pipeline.finalization_contracts import (
    GeneratedStage,
    LifecycleViolation,
)


class GateCode(str, Enum):
    admission_exception = "admission_exception"
    snapshot_integrity = "snapshot_integrity"
    candidate_identity = "candidate_identity"
    actor_access = "actor_access"
    narrative_access = "narrative_access"
    narrative_realization = "narrative_realization"
    narrative_step_coverage = "narrative_step_coverage"
    narrative_step_bound = "narrative_step_bound"
    tree_realization = "tree_realization"
    canonical_identity = "canonical_identity"
    or_tree = "or_tree"
    empty_realization = "empty_realization"
    no_security_actions = "no_security_actions"
    capability_complexity = "capability_complexity"
    parsimony = "parsimony"
    zone_difference = "zone_difference"
    heuristic_correspondence = "heuristic_correspondence"
    traceability = "traceability"
    structural = "structural"
    semantic = "semantic"
    canonical_compilation_failed = "canonical_compilation_failed"
    phantom = "phantom"
    tree_action_mismatch = "tree_action_mismatch"
    assertion_mismatch = "assertion_mismatch"
    no_realized_security_actions = "no_realized_security_actions"
    scenario_identity = "scenario_identity"
    trusted_context = "trusted_context"


class AdmissionEvidenceId(str, Enum):
    """Closed, durable identifiers for authoritative admission evidence."""

    admission_exception = "admission_exception"
    snapshot_integrity = "snapshot_integrity"
    identity = "identity"
    actor_attack_complexity = "actor_attack_complexity"
    capability_grounding = "capability_grounding"
    tool_integration_grounding = "tool_integration_grounding"
    data_access_grounding = "data_access_grounding"
    catalog_taxonomy_pin_validity = "catalog_taxonomy_pin_validity"
    resource_binding_validity = "resource_binding_validity"
    execution_requirement_drift = "execution_requirement_drift"
    projection_traceability = "projection_traceability"
    structural_validity = "structural_validity"
    identifier_validity = "identifier_validity"
    phantom_validity = "phantom_validity"
    semantic_validity = "semantic_validity"
    behavior_correspondence = "behavior_correspondence"
    narrative_tree_diagnostics = "narrative_tree_diagnostics"
    tree_parsimony = "tree_parsimony"
    or_tree_prohibition = "or_tree_prohibition"


EXCEPTIONAL_ADMISSION_EVIDENCE_IDS: frozenset[AdmissionEvidenceId] = frozenset(
    {
        AdmissionEvidenceId.admission_exception,
        AdmissionEvidenceId.snapshot_integrity,
    }
)
NORMAL_POSTBEHAVIOR_EVIDENCE_IDS: frozenset[AdmissionEvidenceId] = (
    frozenset(AdmissionEvidenceId) - EXCEPTIONAL_ADMISSION_EVIDENCE_IDS
)
CONDITIONALLY_APPLICABLE_EVIDENCE_IDS: frozenset[AdmissionEvidenceId] = frozenset(
    {
        AdmissionEvidenceId.tool_integration_grounding,
        AdmissionEvidenceId.data_access_grounding,
    }
)


DIAGNOSTIC_BACKED_EVIDENCE_IDS: frozenset[AdmissionEvidenceId] = frozenset(
    {
        AdmissionEvidenceId.tool_integration_grounding,
        AdmissionEvidenceId.data_access_grounding,
        AdmissionEvidenceId.capability_grounding,
        AdmissionEvidenceId.catalog_taxonomy_pin_validity,
        AdmissionEvidenceId.resource_binding_validity,
        AdmissionEvidenceId.execution_requirement_drift,
        AdmissionEvidenceId.identifier_validity,
    }
)


@dataclass(frozen=True, slots=True)
class GateViolation:
    code: GateCode
    detail: str
    owner: GeneratedStage | None

    @property
    def earliest_owner(self) -> GeneratedStage | None:
        return self.owner

    def lifecycle(self) -> LifecycleViolation:
        return LifecycleViolation(
            detail=self.detail,
            owner=self.owner,
            code=self.code.value,
            retryable=self.owner is not None,
        )


@dataclass(frozen=True, slots=True)
class GateResult:
    evidence_id: AdmissionEvidenceId
    violations: tuple[GateViolation, ...] = ()
    diagnostics: tuple[GateViolation, ...] = ()
    outcome: bool | None = None
    applicable: bool = True

    def __post_init__(self) -> None:
        if self.evidence_id in DIAGNOSTIC_BACKED_EVIDENCE_IDS:
            _check_diagnostic_backed(self)
        else:
            _check_ordinary_gate(self)

    @property
    def valid(self) -> bool:
        return not self.violations if self.outcome is None else self.outcome

    @property
    def passed(self) -> bool:
        """Compatibility spelling for callers that describe gates as pass/fail."""
        return self.valid


def _check_diagnostic_backed(gate: GateResult) -> None:
    """Diagnostic-backed categories forbid hard violations and derive outcome."""
    if gate.violations:
        raise ValueError("diagnostic-backed category forbids hard violations")
    if gate.outcome is None or gate.outcome != (not gate.diagnostics):
        raise ValueError("diagnostic-backed category outcome must match diagnostics")


def _check_ordinary_gate(gate: GateResult) -> None:
    """Ordinary gate outcomes are derived from hard violations."""
    if gate.outcome is not None:
        raise ValueError("ordinary gate outcome is derived from hard violations")

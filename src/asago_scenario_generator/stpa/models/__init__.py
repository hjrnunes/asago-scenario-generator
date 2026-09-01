"""STPA boundary schemas — Pydantic models for inter-SP data contracts.

Public API: import boundary schema classes from here rather than from
individual sub-modules.  Internal helpers (``_validation``) are not
re-exported.
"""

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    HeuristicResult,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
    check_structural_heuristics,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CatalogMapping,
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalEvidenceStatus,
    CausalFactor,
    CausalFactorEvidenceStatus,
    CausalFactorKind,
    ScenarioStepKind,
    TemporalPredicate,
    namespace_for,
    predicate_for,
    step_kind_for,
    step_text_for,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.execution_envelope import (
    AbsenceConstraint,
    CandidateExecutionEnvelope,
    DelayConstraint,
    DurationConstraint,
    OrderingConstraint,
    ScenarioStep,
    TemporalActionVector,
    TemporalAssertion,
    TemporalConstraint,
    UcaOutcomeConstraint,
    WindowConstraint,
    candidate_id_for,
    is_structural_reference,
    parse_declared_timing,
    uca_ref_for,
)
from asago_scenario_generator.stpa.models.execution_projection import (
    StpaProjectionTraceabilityResult,
    StpaProjectionTraceabilityViolation,
    StpaProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    ConsumerHints,
    GherkinSpec,
    ScenarioEnvelope,
    SystemContext,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ReachableCapability,
    ScenarioCatalogContext,
    ScenarioConstraint,
    ScenarioCoordinationPath,
    ScenarioControlPath,
    ScenarioGenerationContext,
    ScenarioHazard,
    ScenarioICAContext,
    ScenarioIdentity,
    ScenarioLoss,
    ScenarioObligationConsideration,
    ScenarioSourcePin,
    validate_factor_evidence,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)

__all__ = [
    # loss_analysis
    "Hazard",
    "Loss",
    "LossAnalysis",
    "LossProvenance",
    "SecurityConstraint",
    # control_structure
    "ControlAction",
    "ControlStructure",
    "ControlledProcess",
    "CoordinationLink",
    "CoordinationMechanism",
    "ElementRef",
    "FeedbackChannel",
    "HeuristicResult",
    "ProcessModelPart",
    "ReferenceType",
    "Responsibility",
    "ResponsibilityConstraint",
    "check_structural_heuristics",
    # ica_enumeration
    "ICA",
    "ICAEnumeration",
    "ICASlot",
    "UCAType",
    # enriched_threat_set
    "CatalogMapping",
    "CoverageAnalysis",
    "EnrichedThreatSet",
    "StructuralThreat",
    # scenario_context
    "ReachableCapability",
    "ScenarioCatalogContext",
    "ScenarioConstraint",
    "ScenarioCoordinationPath",
    "ScenarioControlPath",
    "ScenarioGenerationContext",
    "ScenarioHazard",
    "ScenarioICAContext",
    "ScenarioIdentity",
    "ScenarioLoss",
    "ScenarioObligationConsideration",
    "ScenarioSourcePin",
    # causal_factor
    "CausalEvidenceStatus",
    "CausalFactor",
    "CausalFactorEvidenceStatus",
    "CausalFactorKind",
    "ScenarioStepKind",
    "TemporalPredicate",
    "namespace_for",
    "predicate_for",
    "step_kind_for",
    "step_text_for",
    "validate_factor_evidence",
    "validate_factor_sources",
    # execution_envelope / temporal_constraints
    "AbsenceConstraint",
    "CandidateExecutionEnvelope",
    "DelayConstraint",
    "DurationConstraint",
    "OrderingConstraint",
    "ScenarioStep",
    "TemporalActionVector",
    "TemporalAssertion",
    "TemporalConstraint",
    "UcaOutcomeConstraint",
    "WindowConstraint",
    "candidate_id_for",
    "is_structural_reference",
    "parse_declared_timing",
    "uca_ref_for",
    # execution_projection
    "StpaProjectionTraceabilityResult",
    "StpaProjectionTraceabilityViolation",
    "StpaProjectionTraceabilityViolationCode",
    # scenario_spec
    "AttackerBDI",
    "DefenderBDI",
    "DefenderBelief",
    "DefenderDesire",
    "DefenderIntention",
    "ScenarioSpec",
    "ThreatSource",
    # scenario_envelope
    "ConsumerHints",
    "GherkinSpec",
    "ScenarioEnvelope",
    "SystemContext",
]

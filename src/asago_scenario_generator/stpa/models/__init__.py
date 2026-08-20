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
from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    CausalFactor,
    CausalFactorKind,
    ScenarioStep,
    ScenarioStepKind,
    TemporalActionVector,
    TemporalAssertion,
    TemporalPredicate,
    candidate_id_for,
    predicate_for,
    step_kind_for,
    uca_ref_for,
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
    # execution_envelope
    "CandidateExecutionEnvelope",
    "CausalFactor",
    "CausalFactorKind",
    "ScenarioStep",
    "ScenarioStepKind",
    "TemporalActionVector",
    "TemporalAssertion",
    "TemporalPredicate",
    "candidate_id_for",
    "predicate_for",
    "step_kind_for",
    "uca_ref_for",
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T23:13:34Z","module_hash":"5dcba9e829a9cd8df0f5cc563c3206dfd5e1b613ca540fe8e378d0ecbcdec2ae","functions":[]}
# mutate4py-manifest-end

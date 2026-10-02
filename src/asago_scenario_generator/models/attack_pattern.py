"""Compatibility façade for the authoritative attack-pattern contract.

The implementation is split by contract responsibility while this module
retains the historical import surface used by callers and tests.
"""

from __future__ import annotations

from typing import Any

from . import (
    attack_pattern_chain,
    attack_pattern_contracts,
    attack_pattern_digests,
    attack_pattern_projection,
    attack_pattern_validation,
)
from .attack_pattern_chain import (
    AttackPattern,
    CanonicalAttackChain,
    CanonicalChainStep,
    ResourceSlot,
)
from .attack_pattern_contracts import (
    AllCondition,
    AnyCondition,
    ArtifactReference,
    AuthoritativeFactReference,
    CapabilityRequirements,
    CapabilitySnapshotResolver,
    ChainMappingDecision,
    Condition,
    ConditionEvaluationResult,
    ContractModel,
    Digest,
    DirectInputControlRequirement,
    EffectReference,
    EqualityCondition,
    EvaluatedFactEvidence,
    ExactMapping,
    ExecutionRequirement,
    ExistenceCondition,
    Identifier,
    InputReference,
    MAX_CONDITION_DEPTH,
    MAX_CONDITION_NODES,
    MAX_CONDITION_OPERANDS,
    MAX_MEMBERSHIP_VALUES,
    MAX_PROPERTY_PATH_SEGMENTS,
    MappingDecision,
    MembershipCondition,
    NistClassification,
    NotApplicableMapping,
    NotCondition,
    ObservableOutcomeLink,
    ObservablePostcondition,
    ObservationRequirement,
    OutputReference,
    PrerequisiteCapabilities,
    PropertyMatchCondition,
    ProvenanceReference,
    SecurityOutcomeAssertionRequirement,
    SourceInfluencePath,
    StateChangingToolFixtureRequirement,
    StateReference,
    StepPrecondition,
    StepProvenance,
    StepResourceLink,
    TaxonomyContext,
    TaxonomyPin,
    TaxonomyResolver,
    TypedReference,
    UnmappedMapping,
    UpstreamSourceInfluenceRequirement,
    evaluate_condition,
    Scalar,
    validate_fact_scalar,
)
from .attack_pattern_digests import (
    compute_chain_semantic_digest,
    compute_projection_digest,
)
from .attack_pattern_projection import (
    AgentInternalResourceReference,
    CanonicalResourceReference,
    EntryPointResourceReference,
    IntegrationResourceReference,
    OutputSurfaceResourceReference,
    ProjectionSnapshot,
    ResourceBinding,
    StepOmission,
    ToolResourceReference,
    TrustBoundaryResourceReference,
)
from .attack_pattern_validation import (
    validate_attack_pattern,
    validate_projection_snapshot,
)


_COMPATIBILITY_MODULES = (
    attack_pattern_contracts,
    attack_pattern_chain,
    attack_pattern_projection,
    attack_pattern_digests,
    attack_pattern_validation,
)


# Keep legacy private helper imports working without copying implementation
# symbols into this façade.
def __getattr__(name: str) -> Any:
    """Resolve compatibility symbols from their responsibility module."""
    for module in _COMPATIBILITY_MODULES:
        try:
            return getattr(module, name)
        except AttributeError:
            continue
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = (
    "AgentInternalResourceReference",
    "AllCondition",
    "AnyCondition",
    "ArtifactReference",
    "AttackPattern",
    "AuthoritativeFactReference",
    "CanonicalAttackChain",
    "CanonicalChainStep",
    "CanonicalResourceReference",
    "CapabilityRequirements",
    "CapabilitySnapshotResolver",
    "ChainMappingDecision",
    "Condition",
    "ConditionEvaluationResult",
    "ContractModel",
    "Digest",
    "DirectInputControlRequirement",
    "EffectReference",
    "EntryPointResourceReference",
    "EqualityCondition",
    "EvaluatedFactEvidence",
    "ExactMapping",
    "ExecutionRequirement",
    "ExistenceCondition",
    "Identifier",
    "InputReference",
    "IntegrationResourceReference",
    "MAX_CONDITION_DEPTH",
    "MAX_CONDITION_NODES",
    "MAX_CONDITION_OPERANDS",
    "MAX_MEMBERSHIP_VALUES",
    "MAX_PROPERTY_PATH_SEGMENTS",
    "MappingDecision",
    "MembershipCondition",
    "NistClassification",
    "NotApplicableMapping",
    "NotCondition",
    "ObservableOutcomeLink",
    "ObservablePostcondition",
    "ObservationRequirement",
    "OutputSurfaceResourceReference",
    "OutputReference",
    "PrerequisiteCapabilities",
    "ProjectionSnapshot",
    "PropertyMatchCondition",
    "ProvenanceReference",
    "ResourceBinding",
    "ResourceSlot",
    "Scalar",
    "SecurityOutcomeAssertionRequirement",
    "SourceInfluencePath",
    "StateChangingToolFixtureRequirement",
    "StateReference",
    "StepOmission",
    "StepPrecondition",
    "StepProvenance",
    "StepResourceLink",
    "TaxonomyContext",
    "TaxonomyPin",
    "TaxonomyResolver",
    "ToolResourceReference",
    "TrustBoundaryResourceReference",
    "TypedReference",
    "UnmappedMapping",
    "UpstreamSourceInfluenceRequirement",
    "evaluate_condition",
    "compute_chain_semantic_digest",
    "compute_projection_digest",
    "validate_attack_pattern",
    "validate_fact_scalar",
    "validate_projection_snapshot",
)

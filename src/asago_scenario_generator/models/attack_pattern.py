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
    EvidenceLink,
    ExactMapping,
    ExecutionRequirement,
    ExistenceCondition,
    Identifier,
    InputReference,
    LegacyAttackPatternRecord,
    LegacyKillChainStep,
    LegacyPrerequisiteCapabilities,
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
    validate_legacy_attack_pattern,
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
    "EvidenceLink",
    "ExactMapping",
    "ExecutionRequirement",
    "ExistenceCondition",
    "Identifier",
    "InputReference",
    "IntegrationResourceReference",
    "LegacyAttackPatternRecord",
    "LegacyKillChainStep",
    "LegacyPrerequisiteCapabilities",
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
    "validate_legacy_attack_pattern",
    "validate_projection_snapshot",
)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T21:05:37Z","module_hash":"ac3e90a4811ff11bb410760411c106d582efbe366063bf57ae28f9c58172d503","source_sha256":"8c3ae64551d44d824ac780c4d51bf4cb8fd69232391478c59bf2077296ae2e3e","functions":[{"id":"func/__getattr__","name":"__getattr__","line":116,"end_line":123,"hash":"229f20d657080271a4f207399f9652c745c062aaae434577df084a3159235ed2"}]}
# mutate4py-manifest-end

"""Read-only façade for historical manifest-v3 record contracts.

The former façade also constructed the candidate-finalization persistence
adapter and exposed its file writers.  That lifecycle belongs to the retired
taxonomy-led generator, so this module intentionally exports only the typed
records and validators still needed to inspect historical v3 artifacts.
"""

from __future__ import annotations

from .persistence_artifacts import ArtifactReceipt
from .persistence_checkpoint import (
    read_planning_checkpoint_bytes,
    validate_planning_checkpoint,
)
from .persistence_common import canonical_json_bytes, canonical_sha256
from .persistence_decisions import AdmissionDecisionRecord
from .persistence_journal import FinalizationInventoryV1, QuarantineBundleV1
from .persistence_models import (
    CandidateAttemptRecord,
    CallMetadataRecord,
    GateResultRecord,
    LLMResultRecord,
    ParsimonyRepairRecord,
    PromptRecord,
    StageAttemptFailureRecord,
    StageAttemptRecord,
    StageCallEvidenceRecord,
    StageInputRecord,
    TransitionRecord,
    ViolationRecord,
)
from .persistence_plan import (
    CoveragePlanV2,
    CoverageTargetEntry,
    PlanningCheckpointV1,
    PlanningStageEventV1,
    QualifiedCandidateRef,
    StrictModel,
    TargetState,
)
from .persistence_summary import build_semantic_generation_summary
from .persistence_validation import validate_v3_inventories

__all__ = (
    "AdmissionDecisionRecord",
    "ArtifactReceipt",
    "CandidateAttemptRecord",
    "CallMetadataRecord",
    "CoveragePlanV2",
    "CoverageTargetEntry",
    "FinalizationInventoryV1",
    "GateResultRecord",
    "LLMResultRecord",
    "ParsimonyRepairRecord",
    "PlanningCheckpointV1",
    "PlanningStageEventV1",
    "PromptRecord",
    "QualifiedCandidateRef",
    "QuarantineBundleV1",
    "StageAttemptFailureRecord",
    "StageAttemptRecord",
    "StageCallEvidenceRecord",
    "StageInputRecord",
    "StrictModel",
    "TargetState",
    "TransitionRecord",
    "ViolationRecord",
    "build_semantic_generation_summary",
    "canonical_json_bytes",
    "canonical_sha256",
    "read_planning_checkpoint_bytes",
    "validate_planning_checkpoint",
    "validate_v3_inventories",
)

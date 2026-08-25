"""Versioned manifest models and artifact role metadata."""

from __future__ import annotations

import re
from collections.abc import Iterable
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


# Constants and versions
# --------------------------------------------------------------------------- #

LEGACY_MANIFEST_VERSION = "2"
# Compatibility constant retained for callers that historically used this as
# the v2 reader/default sentinel version.  Production opts into v3 explicitly.
MANIFEST_VERSION = LEGACY_MANIFEST_VERSION
MANIFEST_V3 = "3"
ARTIFACT_SCHEMA_VERSION = "1"
_RUN_ID_TIMESTAMP_LEN = 15  # YYYYMMDDTHHMMSS
_RUN_ID_SEPARATOR = "_"
_RUN_ID_HEX_LEN = 32  # 128 bits of collision-safe entropy
_RUN_ID_TOTAL_LEN = _RUN_ID_TIMESTAMP_LEN + 1 + _RUN_ID_HEX_LEN  # 48
_RUN_ID_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})_([0-9a-f]{32})$")
MANIFEST_FILENAME = "run-manifest.yaml"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class RunStatus(str, Enum):
    """Lifecycle status of a run."""

    STARTED = "started"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"

    @classmethod
    def final_statuses(cls) -> set[RunStatus]:
        return {
            cls.COMPLETED,
            cls.COMPLETED_WITH_WARNINGS,
            cls.COMPLETED_WITH_ERRORS,
            cls.FAILED,
        }

    @property
    def is_final(self) -> bool:
        return self in self.final_statuses()

    @property
    def is_authoritative(self) -> bool:
        """Whether a run satisfied all ordinary completion gates."""
        return self.requires_complete_inventory

    @property
    def requires_complete_inventory(self) -> bool:
        """Whether the final run must satisfy completed inventory invariants."""
        return self in {self.COMPLETED, self.COMPLETED_WITH_WARNINGS}


_DECLARED_AUTHORITATIVE_WARNING_PREFIXES = (
    "candidate_filter_unavailable:",
    "presentation_fallback:",
)


def select_final_run_status(
    ordinary_completion_succeeded: bool,
    generation_notes: Iterable[str],
) -> RunStatus:
    """Select the final status without promoting undeclared warning classes."""
    if not ordinary_completion_succeeded:
        return RunStatus.COMPLETED_WITH_ERRORS
    if any(
        note.startswith(_DECLARED_AUTHORITATIVE_WARNING_PREFIXES)
        for note in generation_notes
    ):
        return RunStatus.COMPLETED_WITH_WARNINGS
    return RunStatus.COMPLETED


class ArtifactRole(str, Enum):
    """Typed role for every persisted artifact in a run.

    The manifest container file (``run-manifest.yaml``) is **not** an
    artifact entry — it is the sole orphan exception.
    """

    USE_CASE = "use_case"
    CAPABILITY_PROFILE = "capability_profile"
    THREAT_SURFACE = "threat_surface"
    SCENARIO_YAML = "scenario_yaml"
    SCENARIO_FEATURE = "scenario_feature"
    SCENARIO_CALL_LOG = "scenario_call_log"
    PIPELINE_CALL_LOG = "pipeline_call_log"
    COVERAGE_REPORT = "coverage_report"
    EVAL_SCORECARD = "eval_scorecard"
    REPORT = "report"
    PIPELINE_LOG = "pipeline_log"
    PLANNING_CHECKPOINT = "planning_checkpoint"
    COVERAGE_PLAN = "coverage_plan"
    FINALIZATION_INVENTORY = "finalization_inventory"
    QUARANTINE_BUNDLE = "quarantine_bundle"
    CANDIDATE_FILTER_QUARANTINE = "candidate_filter_quarantine"


class AttemptDisposition(str, Enum):
    """Disposition of a generation attempt."""

    ADMITTED = "admitted"
    QUARANTINED = "quarantined"
    FAILED = "failed"


class AttemptPhase(str, Enum):
    """Phase of a generation attempt — main or remediation pass."""

    MAIN = "main"
    REMEDIATION = "remediation"


# --------------------------------------------------------------------------- #
# Role metadata
# --------------------------------------------------------------------------- #

# Expected file extension, media type, supported schema versions, and
# (for singleton roles) the exact canonical path for each role.
_ROLE_METADATA: dict[ArtifactRole, dict[str, Any]] = {
    ArtifactRole.USE_CASE: {
        "extension": ".txt",
        "media_type": "text/plain",
        "schema_versions": ["1"],
        "singleton_path": "use-case.txt",
    },
    ArtifactRole.CAPABILITY_PROFILE: {
        "extension": ".yaml",
        "media_type": "application/yaml",
        "schema_versions": ["1"],
        "singleton_path": "capability-profile.yaml",
    },
    ArtifactRole.THREAT_SURFACE: {
        "extension": ".yaml",
        "media_type": "application/yaml",
        "schema_versions": ["1"],
        "singleton_path": "threat-surface.yaml",
    },
    ArtifactRole.SCENARIO_YAML: {
        "extension": ".yaml",
        "media_type": "application/yaml",
        "schema_versions": ["1"],
        "singleton_path": None,
    },
    ArtifactRole.SCENARIO_FEATURE: {
        "extension": ".feature",
        "media_type": "text/plain",
        "schema_versions": ["1"],
        "singleton_path": None,
    },
    ArtifactRole.SCENARIO_CALL_LOG: {
        "extension": ".jsonl",
        "media_type": "application/jsonl",
        "schema_versions": ["1"],
        "singleton_path": "scenarios/calls.jsonl",
    },
    ArtifactRole.PIPELINE_CALL_LOG: {
        "extension": ".jsonl",
        "media_type": "application/jsonl",
        "schema_versions": ["1"],
        "singleton_path": "calls.jsonl",
    },
    ArtifactRole.COVERAGE_REPORT: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["1"],
        "singleton_path": "coverage-gaps.json",
    },
    ArtifactRole.EVAL_SCORECARD: {
        "extension": ".yaml",
        "media_type": "application/yaml",
        "schema_versions": ["1"],
        "singleton_path": "eval-scorecard.yaml",
    },
    ArtifactRole.REPORT: {
        "extension": ".html",
        "media_type": "text/html",
        "schema_versions": ["1"],
        "singleton_path": "report.html",
    },
    ArtifactRole.PIPELINE_LOG: {
        "extension": ".log",
        "media_type": "text/plain",
        "schema_versions": ["1"],
        "singleton_path": "pipeline.log",
    },
    ArtifactRole.PLANNING_CHECKPOINT: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["1"],
        "singleton_path": "planning-checkpoint.json",
    },
    ArtifactRole.COVERAGE_PLAN: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["2"],
        "singleton_path": "coverage-plan.json",
    },
    ArtifactRole.FINALIZATION_INVENTORY: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["1"],
        "singleton_path": "finalization-inventory.json",
    },
    ArtifactRole.QUARANTINE_BUNDLE: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["1"],
        "singleton_path": None,
    },
    ArtifactRole.CANDIDATE_FILTER_QUARANTINE: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["1"],
        "singleton_path": "candidate-filter-quarantine.json",
    },
}

# Roles that must appear at most once in the inventory.
SINGLETON_ROLES: frozenset[ArtifactRole] = frozenset(
    {
        ArtifactRole.USE_CASE,
        ArtifactRole.CAPABILITY_PROFILE,
        ArtifactRole.THREAT_SURFACE,
        ArtifactRole.COVERAGE_REPORT,
        ArtifactRole.EVAL_SCORECARD,
        ArtifactRole.REPORT,
        ArtifactRole.PIPELINE_LOG,
        ArtifactRole.PIPELINE_CALL_LOG,
        ArtifactRole.SCENARIO_CALL_LOG,
        ArtifactRole.PLANNING_CHECKPOINT,
        ArtifactRole.COVERAGE_PLAN,
        ArtifactRole.FINALIZATION_INVENTORY,
        ArtifactRole.CANDIDATE_FILTER_QUARANTINE,
    }
)


def required_singleton_roles(
    *, eval_enabled: bool, manifest_version: str = LEGACY_MANIFEST_VERSION
) -> set[ArtifactRole]:
    """Return the set of singleton roles required for ``completed`` status.

    *report* is always required.  *eval_scorecard* is required only when
    eval is enabled.
    """
    roles: set[ArtifactRole] = {
        ArtifactRole.USE_CASE,
        ArtifactRole.CAPABILITY_PROFILE,
        ArtifactRole.THREAT_SURFACE,
        ArtifactRole.COVERAGE_REPORT,
        ArtifactRole.PIPELINE_LOG,
        ArtifactRole.REPORT,
    }
    if eval_enabled:
        roles.add(ArtifactRole.EVAL_SCORECARD)
    if manifest_version == MANIFEST_V3:
        roles.update(
            {
                ArtifactRole.PLANNING_CHECKPOINT,
                ArtifactRole.COVERAGE_PLAN,
                ArtifactRole.FINALIZATION_INVENTORY,
            }
        )
    return roles


# --------------------------------------------------------------------------- #
# Pydantic models
# --------------------------------------------------------------------------- #


class ArtifactEntry(BaseModel):
    """A single persisted artifact in the run inventory.

    Every entry requires a valid SHA-256 hash, media_type, schema_version,
    canonical role/path, and applicable scenario_id/candidate_id.
    """

    role: ArtifactRole
    path: str  # canonical relative path from run root
    sha256: str
    schema_version: str = ARTIFACT_SCHEMA_VERSION
    media_type: str
    scenario_id: str | None = None
    candidate_id: str | None = None

    model_config = {"use_enum_values": False}


class AttemptRecord(BaseModel):
    """Typed record of a generation attempt keyed by candidate/scenario.

    Every attempt requires a deterministic ``scenario_id`` and
    ``candidate_id``.  Failed and quarantined attempts require typed
    ``failure_evidence``.
    """

    candidate_id: str
    scenario_id: str
    disposition: AttemptDisposition
    failure_evidence: str | None = None
    phase: AttemptPhase = AttemptPhase.MAIN

    model_config = {"use_enum_values": False}

    @model_validator(mode="after")
    def _validate_evidence(self) -> AttemptRecord:
        """Failed and quarantined attempts require nonempty evidence."""
        if self.disposition in (
            AttemptDisposition.FAILED,
            AttemptDisposition.QUARANTINED,
        ):
            if not self.failure_evidence or not self.failure_evidence.strip():
                raise ValueError(
                    f"AttemptRecord with disposition={self.disposition.value} "
                    f"requires nonempty failure_evidence"
                )
        return self


class GitProvenance(BaseModel):
    """Git source provenance for reproducibility."""

    commit: str | None = None
    dirty: bool | None = None
    source_diff_digest: str | None = None
    branch: str | None = None
    untracked_files: list[str] = Field(default_factory=list)


class InputHashes(BaseModel):
    """SHA-256 hashes of all effective inputs."""

    use_case_hash: str | None = None
    risk_extraction_hash: str | None = None
    sssom_hash: str | None = None
    cross_taxonomy_hash: str | None = None
    threats_hash: str | None = None
    source_profile_hash: str | None = None
    qualification_facts_hash: str | None = None
    effective_profile_hash: str | None = None
    attack_patterns_hash: str | None = None
    attack_patterns_sssom_hash: str | None = None
    attack_goals_taxonomy_hash: str | None = None
    threat_goal_affinity_hash: str | None = None
    # Deterministic sorted path→hash maps for all files actually loaded
    # by the attack-patterns*.yaml and attack-patterns*.sssom.tsv globs.
    attack_patterns_yaml_map: dict[str, str] = Field(default_factory=dict)
    attack_patterns_sssom_map: dict[str, str] = Field(default_factory=dict)


class ModelConfig(BaseModel):
    """Resolved LLM model configuration (effective values, not raw None args)."""

    model: str
    base_url: str | None = None
    temperature: float
    max_completion_tokens: int | None = None
    timeout: float | None = None
    top_p: float | None = None
    top_k: int | None = None
    use_guided_decoding: bool = False
    profile_name: str | None = None
    profiles_file: str | None = None
    header_names: list[str] = Field(default_factory=list)
    sources: dict[str, str] = Field(default_factory=dict)


class CommandProvenance(BaseModel):
    """Normalized command and options that invoked the run."""

    command: str = "generate"
    options: dict[str, Any] = Field(default_factory=dict)


class Provenance(BaseModel):
    """Full provenance for a run."""

    run_id: str
    command: CommandProvenance = Field(default_factory=CommandProvenance)
    package_version: str = "0.0.0"
    manifest_version: str = MANIFEST_VERSION
    artifact_schema_version: str = ARTIFACT_SCHEMA_VERSION
    timestamp_start: str
    timestamp_end: str | None = None
    model_config_provenance: ModelConfig | None = None
    prompt_template_hashes: dict[str, str] = Field(default_factory=dict)
    input_hashes: InputHashes = Field(default_factory=InputHashes)
    config_digest: str | None = None
    git: GitProvenance = Field(default_factory=GitProvenance)


class RunManifest(BaseModel):
    """The complete versioned run manifest — sentinel and final inventory.

    ``run-manifest.yaml`` is the inventory **container**, not an
    :class:`ArtifactEntry`.  It is the sole orphan exception.
    """

    manifest_version: str = MANIFEST_VERSION
    status: RunStatus = RunStatus.STARTED
    run_id: str
    timestamp_start: str
    timestamp_end: str | None = None
    package_version: str = "0.0.0"
    provenance: Provenance | None = None
    inventory: list[ArtifactEntry] = Field(default_factory=list)
    attempts: list[AttemptRecord] = Field(default_factory=list)
    error: str | None = None

    # Legacy/extension fields from the pipeline manifest
    inputs: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    seeds_generated: int = 0
    funnel: dict[str, Any] = Field(default_factory=dict)
    stage_records: list[dict[str, Any]] = Field(default_factory=list)
    rule_verdicts: list[dict[str, Any]] = Field(default_factory=list)
    scenarios_generated: int = 0
    scenarios_failed: int = 0
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    phantom_validation: dict[str, Any] = Field(default_factory=dict)
    structural_validation: dict[str, Any] = Field(default_factory=dict)
    semantic_validation: dict[str, Any] = Field(default_factory=dict)
    semantic_generation: dict[str, Any] = Field(default_factory=dict)
    leaf_technique_provenance: dict[str, Any] = Field(default_factory=dict)
    parsimony: dict[str, Any] = Field(default_factory=dict)

    model_config = {"use_enum_values": False}


# --------------------------------------------------------------------------- #

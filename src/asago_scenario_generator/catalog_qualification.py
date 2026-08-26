"""Read-only, content-addressed qualification of the synthetic catalog."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from asago_scenario_generator.data.loaders import load_attack_patterns, load_yaml_strict
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.eval.scorecard import (
    ScorecardV1,
    scorecard_qualification_gates,
)
from asago_scenario_generator.eval.versioned_metrics import evaluate_v3_scorecard
from asago_scenario_generator.manifest import (
    ArtifactEntry,
    ArtifactRole,
    ManifestIntegrityError,
    ManifestInventoryResolver,
    RunManifest,
    RunStatus,
)
from asago_scenario_generator.models.attack_pattern_contracts import (
    Digest,
    EvaluatedFactEvidence,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.scenario import ScenarioEnvelope
from asago_scenario_generator.pipeline.coverage_planning import (
    revalidate_qualified_candidate,
)
from asago_scenario_generator.pipeline.persistence import (
    CoveragePlanV2,
    FinalizationInventoryV1,
)
from asago_scenario_generator.pipeline.projection import (
    CapabilityFactSnapshot,
    ProjectionBudget,
    ProjectionIssue,
    capture_capability_snapshot,
    compute_authoritative_catalog_pin,
    project_authoritative_candidates,
)


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


_CANONICAL_PROFILE_IDS = (
    "direct-conversational",
    "influenceable-retrieval",
    "multi-agent-delegation",
    "state-changing-tools",
    "training-tool-supply-chain",
    "writable-persistent-state",
)


def _sorted_unique(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{label} must be sorted and unique")
    return values


def _is_unsafe_path_form(path: PurePosixPath, value: str) -> bool:
    """True when the path is absolute, non-canonical, or contains backslashes."""
    return path.is_absolute() or path.as_posix() != value or "\\" in value


def _has_dot_component(path: PurePosixPath) -> bool:
    """True when the path contains a '..' component.

    Single-dot components are collapsed by :class:`PurePosixPath`
    normalization and can never appear in ``parts``.
    """
    return ".." in path.parts


def _canonical_run_manifest_path_problem(value: str) -> str | None:
    """Return the first canonical run-manifest path violation, or None.

    A canonical run manifest path is relative, normalized, free of dot
    components and backslashes, and ends in ``run-manifest.yaml``.
    """
    path = PurePosixPath(value)
    if _is_unsafe_path_form(path, value):
        return "must be relative and canonical"
    if _has_dot_component(path):
        return "must not contain dot components"
    if path.name != "run-manifest.yaml":
        return "must end in run-manifest.yaml"
    return None


# --------------------------------------------------------------------------- #
# Contract validation helpers
# --------------------------------------------------------------------------- #


def _matrix_profile_ids(profiles: tuple[ReviewedProfile, ...]) -> tuple[str, ...]:
    """Return the profile IDs of a matrix in declared order."""
    return tuple(item.profile_id for item in profiles)


def _validate_canonical_profile_order(
    profiles: tuple[ReviewedProfile, ...],
) -> None:
    """Require the six canonical focused profiles in canonical order."""
    if _matrix_profile_ids(profiles) != _CANONICAL_PROFILE_IDS:
        raise ValueError("v1 matrix requires the six canonical focused profiles")


def _validate_disjoint_pattern_ownership(
    profiles: tuple[ReviewedProfile, ...],
) -> None:
    """Require matrix pattern ownership to be disjoint across profiles."""
    assignments = [
        pattern_id
        for profile in profiles
        for pattern_id in profile.applicable_pattern_ids
    ]
    if len(assignments) != len(set(assignments)):
        raise ValueError("v1 matrix pattern ownership must be disjoint")


def _validate_sorted_unique_ref_keys(
    refs: tuple[QualificationRunRef, ...], name: str
) -> None:
    """Require run references to be sorted and duplicate-free by key."""
    keys = [(item.profile_id, item.run_manifest_path) for item in refs]
    if keys != sorted(set(keys)):
        raise ValueError(f"{name} must be sorted and duplicate-free")


def _ref_paths(refs: tuple[QualificationRunRef, ...]) -> set[str]:
    """Return the referenced run manifest paths."""
    return {item.run_manifest_path for item in refs}


def _validate_unique_ref_paths(
    refs: tuple[QualificationRunRef, ...], name: str
) -> None:
    """Require run reference manifest paths to be unique."""
    if len(_ref_paths(refs)) != len(refs):
        raise ValueError(f"{name} run manifest paths must be unique")


def _validate_ref_sets_disjoint(
    qualification_paths: set[str], forensic_paths: set[str]
) -> None:
    """Require qualification and forensic references to be separate."""
    if qualification_paths & forensic_paths:
        raise ValueError("qualification and forensic references must be separate")


def _report_reviewed_ids(preflight: tuple[ProfilePreflight, ...]) -> list[str]:
    """Flatten reviewed pattern IDs across all preflight profiles."""
    return [
        pattern_id
        for profile in preflight
        for pattern_id in profile.reviewed_pattern_ids
    ]


def _validate_report_profile_order(preflight: tuple[ProfilePreflight, ...]) -> None:
    """Require the six canonical profiles in canonical order."""
    if tuple(item.profile_id for item in preflight) != _CANONICAL_PROFILE_IDS:
        raise ValueError("report requires the six canonical profiles in order")


def _validate_report_reviewed_universe(
    reviewed_ids: list[str], catalog_denominator: int
) -> None:
    """Require disjoint reviewed ownership covering the catalog denominator."""
    if len(reviewed_ids) != len(set(reviewed_ids)):
        raise ValueError("report reviewed pattern ownership must be disjoint")
    if len(reviewed_ids) != catalog_denominator:
        raise ValueError("catalog denominator must equal the reviewed universe")


def _validate_report_qualified(projected: set[str], qualified: set[str]) -> None:
    """Require qualified pattern IDs to be a projected subset."""
    if not qualified <= projected:
        raise ValueError("qualified pattern IDs must be projected")


def _validate_forensic_keys(
    forensic_history: tuple[ForensicHistoryEntry, ...],
) -> None:
    """Require forensic history entries to be canonical and unique."""
    keys = [(item.profile_id, item.path, item.status) for item in forensic_history]
    if keys != sorted(set(keys)):
        raise ValueError("forensic history must be canonical and unique")


def _validate_forensic_paths(
    forensic_history: tuple[ForensicHistoryEntry, ...],
) -> None:
    """Require forensic history paths to be unique."""
    paths = [item.path for item in forensic_history]
    if len(paths) != len(set(paths)):
        raise ValueError("forensic history paths must be unique")


def _validate_forensic_profiles(
    forensic_history: tuple[ForensicHistoryEntry, ...],
) -> None:
    """Require forensic history entries to reference canonical profiles."""
    for item in forensic_history:
        if item.profile_id not in _CANONICAL_PROFILE_IDS:
            raise ValueError("forensic history profile_id is not canonical")


def _validate_report_forensic_history(
    forensic_history: tuple[ForensicHistoryEntry, ...],
) -> None:
    """Require forensic history to be canonical, unique, and well-scoped."""
    _validate_forensic_keys(forensic_history)
    _validate_forensic_paths(forensic_history)
    _validate_forensic_profiles(forensic_history)


def _validate_preflight_contract(
    campaign_manifest_sha256: str | None,
    qualified: set[str],
    forensic_history: tuple[ForensicHistoryEntry, ...],
) -> None:
    """Require a preflight report to carry no campaign results."""
    if campaign_manifest_sha256 is not None:
        raise ValueError("preflight report cannot bind a campaign manifest")
    if qualified or forensic_history:
        raise ValueError("preflight report cannot contain campaign results")


def _validate_campaign_contract(campaign_manifest_sha256: str | None) -> None:
    """Require a campaign report to bind a campaign manifest."""
    if campaign_manifest_sha256 is None:
        raise ValueError("campaign report requires campaign manifest SHA-256")


def _validate_missing_pattern_ids(missing: set[str], expected: set[str]) -> None:
    """Require top-level missing pattern IDs to match the report kind."""
    if missing != expected:
        raise ValueError("top-level missing pattern IDs do not match report kind")


def _validate_report_kind_contract(
    kind: str,
    campaign_manifest_sha256: str | None,
    qualified: set[str],
    forensic_history: tuple[ForensicHistoryEntry, ...],
    reviewed: set[str],
    projected: set[str],
    missing: set[str],
) -> None:
    """Validate the kind-specific accounting of a qualification report."""
    if kind == "preflight":
        _validate_preflight_contract(
            campaign_manifest_sha256, qualified, forensic_history
        )
        expected_missing = reviewed - projected
    else:
        _validate_campaign_contract(campaign_manifest_sha256)
        expected_missing = reviewed - qualified
    _validate_missing_pattern_ids(missing, expected_missing)


class ReviewedProfile(_Contract):
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    rationale: str = Field(min_length=1)
    profile: CapabilityProfile
    facts: tuple[EvaluatedFactEvidence, ...]
    applicable_pattern_ids: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_collections(self) -> ReviewedProfile:
        _sorted_unique(self.applicable_pattern_ids, "applicable_pattern_ids")
        snapshot = capture_capability_snapshot(self.profile, self.facts)
        if snapshot.facts != self.facts:
            raise ValueError("facts must be sorted by unique authoritative reference")
        return self

    def snapshot(self) -> CapabilityFactSnapshot:
        """Derive the sole profile/fact snapshot; never persist duplicate state."""
        return capture_capability_snapshot(self.profile, self.facts)


class ReviewedProfileMatrixV1(_Contract):
    schema_version: Literal["1"] = "1"
    catalog_sha256: Digest
    catalog_denominator: int = Field(gt=0)
    profiles: tuple[ReviewedProfile, ...] = Field(min_length=6, max_length=6)

    @model_validator(mode="after")
    def validate_profiles(self) -> ReviewedProfileMatrixV1:
        _validate_canonical_profile_order(self.profiles)
        _validate_disjoint_pattern_ownership(self.profiles)
        return self


class QualificationRunRef(_Contract):
    profile_id: str
    run_manifest_path: str
    manifest_sha256: Digest

    @field_validator("run_manifest_path")
    @classmethod
    def canonical_manifest_path(cls, value: str) -> str:
        if _canonical_run_manifest_path_problem(value) is not None:
            raise ValueError(
                "run manifest path must be canonical, safe, relative, and end in run-manifest.yaml"
            )
        return value


class ForensicRunRef(QualificationRunRef):
    pass


class CampaignManifestV1(_Contract):
    schema_version: Literal["1"] = "1"
    catalog_sha256: Digest
    catalog_denominator: int = Field(gt=0)
    matrix_sha256: Digest
    qualification_runs: tuple[QualificationRunRef, ...] = ()
    forensic_runs: tuple[ForensicRunRef, ...] = ()

    @model_validator(mode="after")
    def validate_refs(self) -> CampaignManifestV1:
        _validate_sorted_unique_ref_keys(self.qualification_runs, "qualification_runs")
        _validate_sorted_unique_ref_keys(self.forensic_runs, "forensic_runs")
        _validate_unique_ref_paths(self.qualification_runs, "qualification")
        _validate_unique_ref_paths(self.forensic_runs, "forensic")
        _validate_ref_sets_disjoint(
            _ref_paths(self.qualification_runs), _ref_paths(self.forensic_runs)
        )
        return self


class ProfilePreflight(_Contract):
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    reviewed_pattern_ids: tuple[str, ...]
    projected_pattern_ids: tuple[str, ...]
    missing_pattern_ids: tuple[str, ...]
    issues: tuple[ProjectionIssue, ...]

    @model_validator(mode="after")
    def validate_accounting(self) -> ProfilePreflight:
        reviewed = set(
            _sorted_unique(self.reviewed_pattern_ids, "reviewed_pattern_ids")
        )
        projected = set(
            _sorted_unique(self.projected_pattern_ids, "projected_pattern_ids")
        )
        missing = set(_sorted_unique(self.missing_pattern_ids, "missing_pattern_ids"))
        if not projected <= reviewed:
            raise ValueError("projected pattern IDs must be reviewed")
        if missing != reviewed - projected:
            raise ValueError(
                "profile missing pattern IDs must equal reviewed minus projected"
            )
        return self


class ForensicHistoryEntry(_Contract):
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    path: str
    status: Literal["completed_with_errors", "failed"]

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        if _canonical_run_manifest_path_problem(value) is not None:
            raise ValueError("forensic path must be a canonical run manifest path")
        return value


class QualificationReportV1(_Contract):
    schema_version: Literal["1"] = "1"
    kind: Literal["preflight", "campaign"]
    catalog_sha256: Digest
    catalog_denominator: int = Field(gt=0)
    matrix_sha256: Digest
    campaign_manifest_sha256: Digest | None = None
    preflight: tuple[ProfilePreflight, ...]
    missing_pattern_ids: tuple[str, ...]
    qualified_pattern_ids: tuple[str, ...] = ()
    forensic_history: tuple[ForensicHistoryEntry, ...] = ()

    @model_validator(mode="after")
    def validate_report(self) -> QualificationReportV1:
        _validate_report_profile_order(self.preflight)
        reviewed_ids = _report_reviewed_ids(self.preflight)
        _validate_report_reviewed_universe(reviewed_ids, self.catalog_denominator)
        projected = {
            pattern_id
            for profile in self.preflight
            for pattern_id in profile.projected_pattern_ids
        }
        missing = set(_sorted_unique(self.missing_pattern_ids, "missing_pattern_ids"))
        qualified = set(
            _sorted_unique(self.qualified_pattern_ids, "qualified_pattern_ids")
        )
        _validate_report_qualified(projected, qualified)
        _validate_report_forensic_history(self.forensic_history)
        _validate_report_kind_contract(
            self.kind,
            self.campaign_manifest_sha256,
            qualified,
            self.forensic_history,
            set(reviewed_ids),
            projected,
            missing,
        )
        return self


PersistedContract = ReviewedProfileMatrixV1 | CampaignManifestV1 | QualificationReportV1


def validate_persisted_contract(
    path: Path, contract: Literal["matrix", "campaign", "report"]
) -> PersistedContract:
    """Standalone schema and semantic validation without running qualification."""
    models = {
        "matrix": ReviewedProfileMatrixV1,
        "campaign": CampaignManifestV1,
        "report": QualificationReportV1,
    }
    return models[contract].model_validate(load_yaml_strict(path.read_bytes()))


def _bytes(path: Path) -> bytes:
    return path.read_bytes()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_matrix(path: Path) -> ReviewedProfileMatrixV1:
    return ReviewedProfileMatrixV1.model_validate(load_yaml_strict(_bytes(path)))


def _fact_key(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _condition_fact_keys(condition: dict | None) -> set[str]:
    if not condition:
        return set()
    keys = set()
    if isinstance(condition.get("fact"), dict):
        keys.add(_fact_key(condition["fact"]))
    for operand in condition.get("operands", []):
        keys.update(_condition_fact_keys(operand))
    keys.update(_condition_fact_keys(condition.get("operand")))
    return keys


def _required_fact_keys(records: list[dict]) -> set[str]:
    keys: set[str] = set()
    for record in records:
        for step in record["canonical_chain"]["steps"]:
            keys.update(_condition_fact_keys(step.get("condition")))
            for precondition in step.get("preconditions", []):
                keys.update(_condition_fact_keys(precondition.get("condition")))
    return keys


def _preflight_inputs(
    catalog: dict[str, dict] | None,
    resolver: object | None,
    catalog_pin: str | None,
) -> tuple[dict[str, dict], list[dict], object, str]:
    """Resolve the live catalog, records, resolver, and authoritative pin."""
    catalog = catalog or load_attack_patterns()
    records = list(catalog.values())
    resolver = resolver or load_taxonomy_resolver()
    pin = catalog_pin or compute_authoritative_catalog_pin(records, resolver)
    return catalog, records, resolver, pin


def _validate_preflight_matrix_pin(
    matrix: ReviewedProfileMatrixV1,
    catalog: dict[str, dict],
    pin: str,
) -> None:
    """Require the matrix to pin the live qualified catalog."""
    if (matrix.catalog_sha256, matrix.catalog_denominator) != (pin, len(catalog)):
        raise ValueError(
            "matrix catalog pin/denominator does not match the live qualified catalog"
        )


def _validate_matrix_partition(
    matrix: ReviewedProfileMatrixV1,
    catalog: dict[str, dict],
) -> None:
    """Require an exact disjoint reviewed partition of live patterns."""
    reviewed = tuple(
        pattern_id
        for profile in matrix.profiles
        for pattern_id in profile.applicable_pattern_ids
    )
    if set(reviewed) != set(catalog) or len(reviewed) != len(catalog):
        raise ValueError(
            "matrix must provide an exact disjoint reviewed partition of live patterns"
        )


def _unknown_fact_keys(
    required_facts: set[str], actual_facts: dict[str, EvaluatedFactEvidence]
) -> list[str]:
    """Return required fact keys whose only reading is unknown."""
    unknown: list[str] = []
    for key in required_facts:
        if key in actual_facts and actual_facts[key].status == "unknown":
            unknown.append(key)
    return sorted(unknown)


def _profile_fact_readiness(
    profile: ReviewedProfile,
    catalog: dict[str, dict],
) -> None:
    """Require known explicit fact readings for every applicable condition."""
    selected = [catalog[pid] for pid in profile.applicable_pattern_ids]
    actual_facts = {
        _fact_key(item.fact.model_dump(mode="json")): item for item in profile.facts
    }
    required_facts = _required_fact_keys(selected)
    missing_facts = sorted(required_facts - set(actual_facts))
    unknown_facts = _unknown_fact_keys(required_facts, actual_facts)
    if missing_facts or unknown_facts:
        raise ValueError(
            f"profile {profile.profile_id} must provide known explicit readings "
            f"for every applicable condition fact; missing={missing_facts}, "
            f"unknown={unknown_facts}"
        )


def _projected_candidates_for(batch: Any, profile: ReviewedProfile) -> tuple[Any, ...]:
    """Return the batch candidates scoped to one reviewed profile."""
    return tuple(
        item
        for item in batch.candidates
        if item.pattern_id in profile.applicable_pattern_ids
    )


def _validate_preflight_catalog_pin(candidates: tuple[Any, ...], pin: str) -> None:
    """Require every scoped candidate to carry the full catalog pin."""
    for item in candidates:
        if item.projection.catalog_pin != pin:
            raise ValueError("preflight projection does not carry the full catalog pin")


def _infeasibilities_for(batch: Any, profile: ReviewedProfile) -> tuple[Any, ...]:
    """Return the batch infeasibilities scoped to one reviewed profile."""
    return tuple(
        item
        for item in batch.infeasibilities
        if item.pattern_id in profile.applicable_pattern_ids
    )


def _project_preflight_profile(
    profile: ReviewedProfile,
    records: list[dict],
    resolver: object,
    pin: str,
) -> ProfilePreflight:
    """Project one reviewed profile and build its preflight record."""
    batch = project_authoritative_candidates(
        records,
        resolver,
        profile.snapshot(),
        budget=ProjectionBudget(max_candidates=4096, max_derivation_work=65536),
    )
    projected_candidates = _projected_candidates_for(batch, profile)
    _validate_preflight_catalog_pin(projected_candidates, pin)
    projected = tuple(sorted({item.pattern_id for item in projected_candidates}))
    return ProfilePreflight(
        profile_id=profile.profile_id,
        reviewed_pattern_ids=tuple(profile.applicable_pattern_ids),
        projected_pattern_ids=projected,
        missing_pattern_ids=tuple(
            sorted(set(profile.applicable_pattern_ids) - set(projected))
        ),
        issues=_infeasibilities_for(batch, profile),
    )


def _preflight_matrix(
    matrix: ReviewedProfileMatrixV1,
    raw_bytes: bytes,
    *,
    catalog: dict[str, dict] | None = None,
    resolver: object | None = None,
    catalog_pin: str | None = None,
) -> QualificationReportV1:
    catalog, records, resolver, pin = _preflight_inputs(catalog, resolver, catalog_pin)
    _validate_preflight_matrix_pin(matrix, catalog, pin)
    _validate_matrix_partition(matrix, catalog)
    results = []
    projected_union: set[str] = set()
    for profile in matrix.profiles:
        _profile_fact_readiness(profile, catalog)
        result = _project_preflight_profile(profile, records, resolver, pin)
        projected_union.update(result.projected_pattern_ids)
        results.append(result)
    return QualificationReportV1(
        kind="preflight",
        catalog_sha256=pin,
        catalog_denominator=len(catalog),
        matrix_sha256=_sha(raw_bytes),
        preflight=tuple(results),
        missing_pattern_ids=tuple(sorted(set(catalog) - projected_union)),
    )


def preflight_matrix(path: Path) -> QualificationReportV1:
    raw_bytes = _bytes(path)
    matrix = ReviewedProfileMatrixV1.model_validate(load_yaml_strict(raw_bytes))
    return _preflight_matrix(matrix, raw_bytes)


def _safe_relative_read(
    root: Path, relative_path: str
) -> tuple[bytes, tuple[int, int]]:
    """Read one campaign reference without following any symlink component."""
    parts = PurePosixPath(relative_path).parts
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
                os.close(fd)
                fd = next_fd
            leaf_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                metadata = os.fstat(leaf_fd)
                if not stat.S_ISREG(metadata.st_mode):
                    raise ManifestIntegrityError(
                        f"campaign reference is not a regular file: {relative_path}"
                    )
                chunks = []
                while chunk := os.read(leaf_fd, 65536):
                    chunks.append(chunk)
                return b"".join(chunks), (metadata.st_dev, metadata.st_ino)
            finally:
                os.close(leaf_fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ManifestIntegrityError(
            f"cannot safely read campaign reference {relative_path}: {exc}"
        ) from exc


def _read_pinned_run_manifest(
    base: Path,
    ref: QualificationRunRef,
    seen_physical: set[tuple[int, int]],
) -> bytes:
    """Read one pinned campaign run manifest with duplicate/hash checks."""
    content, physical_id = _safe_relative_read(base, ref.run_manifest_path)
    if physical_id in seen_physical:
        raise ValueError(
            "campaign run manifests must reference distinct physical files"
        )
    seen_physical.add(physical_id)
    if _sha(content) != ref.manifest_sha256:
        raise ValueError(f"manifest hash mismatch: {ref.run_manifest_path}")
    return content


def _parse_pinned_run_manifest(content: bytes, ref: QualificationRunRef) -> RunManifest:
    """Parse a pinned run manifest and enforce v3 final-run requirements."""
    try:
        manifest = RunManifest.model_validate(load_yaml_strict(content))
    except Exception as exc:
        raise ManifestIntegrityError(
            f"invalid pinned run manifest {ref.run_manifest_path}: {exc}"
        ) from exc
    if manifest.manifest_version != "3":
        raise ManifestIntegrityError("catalog qualification requires manifest v3")
    if not manifest.status.is_final:
        raise ManifestIntegrityError("catalog qualification requires a final run")
    return manifest


def _validate_run_authority(manifest: RunManifest, authoritative: bool) -> None:
    """Require the run status to match the campaign reference kind."""
    if authoritative and manifest.status is not RunStatus.COMPLETED:
        raise ManifestIntegrityError(
            f"qualification run is not authoritative: {manifest.status.value}"
        )
    if not authoritative and manifest.status is RunStatus.COMPLETED:
        raise ManifestIntegrityError(
            "completed authoritative runs belong in qualification_runs"
        )


def _resolve_campaign_run(
    base: Path,
    ref: QualificationRunRef,
    *,
    authoritative: bool,
    seen_physical: set[tuple[int, int]],
) -> ManifestInventoryResolver:
    content = _read_pinned_run_manifest(base, ref, seen_physical)
    manifest = _parse_pinned_run_manifest(content, ref)
    _validate_run_authority(manifest, authoritative)
    return ManifestInventoryResolver(
        base / PurePosixPath(ref.run_manifest_path).parent,
        manifest,
        check_orphans=True,
    )


def _campaign_preflight(
    matrix_bytes: bytes,
) -> tuple[
    ReviewedProfileMatrixV1,
    QualificationReportV1,
    list[dict],
    object,
]:
    """Load the matrix and run the live authoritative preflight projection."""
    matrix = ReviewedProfileMatrixV1.model_validate(load_yaml_strict(matrix_bytes))
    catalog = load_attack_patterns()
    catalog_records = list(catalog.values())
    taxonomy_resolver = load_taxonomy_resolver()
    catalog_pin = compute_authoritative_catalog_pin(catalog_records, taxonomy_resolver)
    preflight = _preflight_matrix(
        matrix,
        matrix_bytes,
        catalog=catalog,
        resolver=taxonomy_resolver,
        catalog_pin=catalog_pin,
    )
    return matrix, preflight, catalog_records, taxonomy_resolver


def _validate_campaign_pins(
    campaign: CampaignManifestV1,
    preflight: QualificationReportV1,
) -> None:
    """Require campaign pins to match the live catalog and exact matrix bytes."""
    if (
        campaign.catalog_sha256,
        campaign.catalog_denominator,
        campaign.matrix_sha256,
    ) != (
        preflight.catalog_sha256,
        preflight.catalog_denominator,
        preflight.matrix_sha256,
    ):
        raise ValueError(
            "campaign pins do not match the live catalog and exact matrix bytes"
        )


def _require_known_profile(
    ref: QualificationRunRef,
    profiles: dict[str, ReviewedProfile],
) -> None:
    """Require the referenced profile to exist in the matrix."""
    if ref.profile_id not in profiles:
        raise ValueError(f"unknown matrix profile_id: {ref.profile_id}")


def _require_qualification_entries(
    resolver: ManifestInventoryResolver,
) -> tuple[ArtifactEntry, ArtifactEntry, ArtifactEntry, ArtifactEntry]:
    """Require the four run artifacts a qualification check needs."""
    score_entry = resolver.entry_by_role(ArtifactRole.EVAL_SCORECARD)
    final_entry = resolver.entry_by_role(ArtifactRole.FINALIZATION_INVENTORY)
    profile_entry = resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    plan_entry = resolver.entry_by_role(ArtifactRole.COVERAGE_PLAN)
    for entry in (score_entry, final_entry, profile_entry, plan_entry):
        if entry is None:
            raise ValueError(
                "qualification run lacks profile, plan, scorecard, or finalization inventory"
            )
    return score_entry, final_entry, profile_entry, plan_entry


def _validate_scorecard_equivalence(
    resolver: ManifestInventoryResolver,
    score_entry: ArtifactEntry,
) -> ScorecardV1:
    """Require the persisted scorecard to equal the canonical evaluation."""
    score = ScorecardV1.model_validate(
        load_yaml_strict(resolver.read_text(score_entry))
    )
    recomputed_score = evaluate_v3_scorecard(resolver)
    if score != recomputed_score:
        raise ValueError(
            "qualification scorecard does not equal canonical resolver evaluation"
        )
    if score.qualification.status.value != "pass":
        raise ValueError("qualification scorecard does not pass canonical gates")
    return score


def _validate_scorecard_gates(score: ScorecardV1) -> None:
    """Require every strict qualification category gate to pass."""
    nonpassing_gates = sorted(
        gate_id
        for gate_id, metric in scorecard_qualification_gates(score).items()
        if metric.status.value != "pass"
    )
    if nonpassing_gates:
        raise ValueError(
            "qualification scorecard has non-passing strict category gates: "
            + ", ".join(nonpassing_gates)
        )


def _validate_finalization_clean(final: FinalizationInventoryV1) -> None:
    """Require a qualification run to admit every candidate without quarantine."""
    if final.quarantine_inventory or any(
        not item.admitted for item in final.admission_decisions
    ):
        raise ValueError(
            "qualification run contains quarantine or non-admitted decisions"
        )


def _validate_run_profile_match(
    resolver: ManifestInventoryResolver,
    profile_entry: ArtifactEntry,
    expected: ReviewedProfile,
) -> None:
    """Require the run capability profile to equal the matrix profile."""
    run_profile = CapabilityProfile.model_validate(
        load_yaml_strict(resolver.read_text(profile_entry))
    )
    if run_profile != expected.profile:
        raise ValueError("run capability profile does not match matrix profile")


def _plan_choices(
    resolver: ManifestInventoryResolver,
    plan_entry: ArtifactEntry,
) -> dict[str, Any]:
    """Index coverage-plan ordered choices by candidate id."""
    plan = CoveragePlanV2.model_validate_json(resolver.read_text(plan_entry))
    return {
        choice.candidate_id: choice
        for target in plan.targets
        for choice in target.ordered_choices
    }


def _scenario_for_entry(
    resolver: ManifestInventoryResolver,
    entry: ArtifactEntry,
) -> ScenarioEnvelope:
    """Parse one admitted scenario envelope from verified resolver bytes."""
    return ScenarioEnvelope.model_validate(load_yaml_strict(resolver.read_text(entry)))


def _validate_scenario_snapshot(
    block: Any,
    expected: ReviewedProfile,
) -> None:
    """Require the scenario capability snapshot to equal the matrix profile."""
    if block.capability_snapshot != expected.snapshot():
        raise ValueError("scenario capability snapshot does not match matrix profile")


def _validate_scenario_pattern(
    block: Any,
    campaign: CampaignManifestV1,
    expected: ReviewedProfile,
    profile_id: str,
    projected_by_profile: dict[str, set[str]],
) -> str:
    """Validate the scenario pattern scope and return its pattern id."""
    if block.projection.catalog_pin != campaign.catalog_sha256:
        raise ValueError("scenario catalog pin does not match campaign")
    pattern_id = block.projection.source_chain.pattern_id
    if pattern_id not in expected.applicable_pattern_ids:
        raise ValueError("scenario pattern is not reviewed for its matrix profile")
    if pattern_id not in projected_by_profile[profile_id]:
        raise ValueError(
            "scenario pattern has no valid deterministic matrix projection"
        )
    return pattern_id


def _scenario_choice(scenario: Any, choices: dict[str, Any]) -> Any:
    """Return the coverage-plan choice for an admitted scenario candidate."""
    choice = choices.get(scenario.candidate_id)
    if choice is None:
        raise ValueError("admitted scenario candidate is absent from coverage plan")
    return choice


def _revalidated_identity_matches(revalidated: Any, scenario: Any, block: Any) -> bool:
    """True when candidate identity and projection core match."""
    return (
        revalidated.candidate_id == scenario.candidate_id
        and revalidated.projection == block.projection
    )


def _revalidated_ingress_matches(revalidated: Any, block: Any) -> bool:
    """True when ingress, controllability, and mappings match."""
    return (
        revalidated.canonical_ingress == block.canonical_ingress
        and revalidated.ingress_controllability == block.ingress_controllability
        and revalidated.projected_mappings == block.projected_mappings
    )


def _revalidated_requirements_match(revalidated: Any, block: Any) -> bool:
    """True when execution requirements and their digests match."""
    return (
        revalidated.execution_requirements == block.execution_requirements
        and revalidated.requirement_derivation_version
        == block.requirement_derivation_version
        and revalidated.execution_requirements_digest
        == block.execution_requirements_digest
    )


def _validate_scenario_reprojection(
    revalidated: Any,
    scenario: Any,
    block: Any,
) -> None:
    """Require the scenario projection to match the authoritative plan candidate."""
    if not (
        _revalidated_identity_matches(revalidated, scenario, block)
        and _revalidated_ingress_matches(revalidated, block)
        and _revalidated_requirements_match(revalidated, block)
    ):
        raise ValueError(
            "scenario projection does not match authoritative plan candidate"
        )


def _validate_run_scenarios(
    resolver: ManifestInventoryResolver,
    expected: ReviewedProfile,
    profile_id: str,
    projected_by_profile: dict[str, set[str]],
    campaign: CampaignManifestV1,
    choices: dict[str, Any],
    taxonomy_resolver: object,
    catalog_records: list[dict],
) -> set[str]:
    """Validate every admitted scenario against the authoritative plan."""
    qualified: set[str] = set()
    for entry in resolver.entries_by_role(ArtifactRole.SCENARIO_YAML):
        scenario = _scenario_for_entry(resolver, entry)
        block = scenario.projection
        _validate_scenario_snapshot(block, expected)
        pattern_id = _validate_scenario_pattern(
            block, campaign, expected, profile_id, projected_by_profile
        )
        choice = _scenario_choice(scenario, choices)
        revalidated = revalidate_qualified_candidate(
            choice.model_dump(mode="json"),
            taxonomy_resolver,
            expected.snapshot(),
            catalog_records,
            expected_catalog_pin=campaign.catalog_sha256,
        ).projected
        _validate_scenario_reprojection(revalidated, scenario, block)
        qualified.add(pattern_id)
    return qualified


def _validate_qualification_run(
    base: Path,
    ref: QualificationRunRef,
    seen_physical: set[tuple[int, int]],
    profiles: dict[str, ReviewedProfile],
    projected_by_profile: dict[str, set[str]],
    campaign: CampaignManifestV1,
    taxonomy_resolver: object,
    catalog_records: list[dict],
) -> set[str]:
    """Validate one authoritative run and return its qualified pattern ids."""
    _require_known_profile(ref, profiles)
    resolver = _resolve_campaign_run(
        base, ref, authoritative=True, seen_physical=seen_physical
    )
    score_entry, final_entry, profile_entry, plan_entry = (
        _require_qualification_entries(resolver)
    )
    score = _validate_scorecard_equivalence(resolver, score_entry)
    _validate_scorecard_gates(score)
    final = FinalizationInventoryV1.model_validate(
        json.loads(resolver.read_text(final_entry))
    )
    _validate_finalization_clean(final)
    expected = profiles[ref.profile_id]
    _validate_run_profile_match(resolver, profile_entry, expected)
    choices = _plan_choices(resolver, plan_entry)
    return _validate_run_scenarios(
        resolver,
        expected,
        ref.profile_id,
        projected_by_profile,
        campaign,
        choices,
        taxonomy_resolver,
        catalog_records,
    )


def _collect_forensic_history(
    base: Path,
    refs: tuple[ForensicRunRef, ...],
    profiles: dict[str, ReviewedProfile],
    seen_physical: set[tuple[int, int]],
) -> list[ForensicHistoryEntry]:
    """Collect forensic history entries for non-authoritative runs."""
    history: list[ForensicHistoryEntry] = []
    for ref in refs:
        _require_known_profile(ref, profiles)
        resolver = _resolve_campaign_run(
            base, ref, authoritative=False, seen_physical=seen_physical
        )
        history.append(
            ForensicHistoryEntry(
                profile_id=ref.profile_id,
                path=ref.run_manifest_path,
                status=resolver.manifest.status.value,
            )
        )
    return history


def _campaign_missing_pattern_ids(
    matrix: ReviewedProfileMatrixV1,
    qualified: set[str],
) -> tuple[str, ...]:
    """Return reviewed patterns that no qualification run qualified."""
    reviewed = {
        pattern_id
        for profile in matrix.profiles
        for pattern_id in profile.applicable_pattern_ids
    }
    return tuple(sorted(reviewed - qualified))


def aggregate_campaign(matrix_path: Path, campaign_path: Path) -> QualificationReportV1:
    matrix_bytes = _bytes(matrix_path)
    matrix, preflight, catalog_records, taxonomy_resolver = _campaign_preflight(
        matrix_bytes
    )
    campaign_bytes = _bytes(campaign_path)
    campaign = CampaignManifestV1.model_validate(load_yaml_strict(campaign_bytes))
    _validate_campaign_pins(campaign, preflight)
    profiles = {item.profile_id: item for item in matrix.profiles}
    projected_by_profile = {
        item.profile_id: set(item.projected_pattern_ids) for item in preflight.preflight
    }
    base = campaign_path.parent
    seen_physical: set[tuple[int, int]] = set()
    qualified: set[str] = set()
    for ref in campaign.qualification_runs:
        qualified.update(
            _validate_qualification_run(
                base,
                ref,
                seen_physical,
                profiles,
                projected_by_profile,
                campaign,
                taxonomy_resolver,
                catalog_records,
            )
        )
    forensic = _collect_forensic_history(
        base, campaign.forensic_runs, profiles, seen_physical
    )
    return QualificationReportV1(
        kind="campaign",
        catalog_sha256=preflight.catalog_sha256,
        catalog_denominator=preflight.catalog_denominator,
        matrix_sha256=preflight.matrix_sha256,
        campaign_manifest_sha256=_sha(campaign_bytes),
        preflight=preflight.preflight,
        qualified_pattern_ids=tuple(sorted(qualified)),
        missing_pattern_ids=_campaign_missing_pattern_ids(matrix, qualified),
        forensic_history=tuple(forensic),
    )

"""ReportData — typed container for all report inputs, and a loader from disk.

In cmps.1, ``load_report_data`` consumes **strict manifest inventory** entries
rather than globbing the filesystem.  Paths, hashes, and roles are verified by
the shared :class:`ManifestInventoryResolver`.

Internal (in-pipeline) callers pass an in-memory resolver via *resolver*.
Standalone callers pass a *run_dir* and the manifest must be authoritative
(``completed``) unless *allow_non_authoritative* is set.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from asago_scenario_generator.manifest import (
    ArtifactRole,
    ManifestInventoryResolver,
    find_run_dir,
    load_strict_resolver,
)

logger = logging.getLogger(__name__)


@dataclass
class ReportData:
    """All inputs needed by :func:`generate_report`.

    Each field corresponds to a pipeline artifact that was previously read
    inline inside the report generator.  By collecting them here the
    generator becomes a pure data-to-HTML function with no filesystem I/O.
    """

    profile_data: dict = field(default_factory=dict)
    threat_surface_data: dict = field(default_factory=dict)
    scenarios: list[dict] = field(default_factory=list)
    feature_files: dict[str, str] = field(default_factory=dict)
    call_logs: dict[str, list[dict]] = field(default_factory=dict)
    pipeline_call_logs: list[dict] = field(default_factory=list)
    coverage_data: dict = field(default_factory=dict)
    scorecard_data: dict = field(default_factory=dict)
    manifest_data: dict = field(default_factory=dict)
    use_case_text: str = ""
    raw_files: dict[str, str] = field(default_factory=dict)


def _resolve_resolver(
    resolver: ManifestInventoryResolver | None,
    run_dir: Path | None,
    allow_non_authoritative: bool,
) -> ManifestInventoryResolver:
    """Return the effective manifest resolver for this load.

    Internal (in-pipeline) callers supply a pre-built resolver; standalone
    callers locate one from *run_dir* and enforce the finalized/authoritative
    manifest contract.
    """
    if resolver is not None:
        return resolver
    actual_run_dir = find_run_dir(run_dir)
    return load_strict_resolver(
        actual_run_dir,
        require_final=True,
        require_authoritative=not allow_non_authoritative,
    )


def _load_yaml_artifact(
    resolver: ManifestInventoryResolver,
    role: ArtifactRole,
    raw_key: str,
    *,
    success_log: str,
    missing_log: str,
) -> tuple[dict, str | None]:
    """Read a YAML artifact and record its raw text under *raw_key*."""
    entry = resolver.entry_by_role(role)
    if entry is None:
        logger.warning(missing_log)
        return {}, None
    text = resolver.read_text(entry)
    data = yaml.safe_load(text) or {}
    logger.info(success_log)
    return data, text


def _load_json_artifact(
    resolver: ManifestInventoryResolver,
    role: ArtifactRole,
    raw_key: str,
    *,
    success_log: str,
    failure_log: str,
) -> tuple[dict, str | None]:
    """Read a JSON artifact and record its raw text under *raw_key*."""
    entry = resolver.entry_by_role(role)
    if entry is None:
        return {}, None
    try:
        text = resolver.read_text(entry)
        data = json.loads(text) or {}
        logger.info(success_log)
        return data, text
    except Exception as exc:
        logger.warning(failure_log, exc)
        return {}, None


def _load_call_log_entry_lines(
    resolver: ManifestInventoryResolver,
    role: ArtifactRole,
    *,
    success_log: str,
    failure_log: str,
) -> list[dict]:
    """Read one newline-delimited JSON call log into a list of dicts."""
    entry = resolver.entry_by_role(role)
    if entry is None:
        return []
    try:
        lines = [
            json.loads(line) for line in resolver.read_text(entry).strip().splitlines()
        ]
        logger.info(success_log, len(lines))
        return lines
    except Exception as exc:
        logger.warning(failure_log, exc)
        return []


def _load_scorecard_artifact(
    resolver: ManifestInventoryResolver,
    raw_files: dict[str, str],
) -> dict:
    """Read the eval scorecard YAML artifact, tolerating parse failures."""
    entry = resolver.entry_by_role(ArtifactRole.EVAL_SCORECARD)
    if entry is None:
        return {}
    try:
        text = resolver.read_text(entry)
        scorecard_data = yaml.safe_load(text) or {}
        raw_files["eval-scorecard.yaml"] = text
        logger.info("Loaded eval scorecard from manifest inventory")
        return scorecard_data
    except Exception as exc:
        logger.warning("Failed to load eval scorecard: %s", exc)
        return {}


def _load_scenario_yamls(
    resolver: ManifestInventoryResolver,
    raw_files: dict[str, str],
) -> list[dict]:
    """Read and parse every scenario YAML entry from the resolver."""
    scenarios: list[dict] = []
    for entry in resolver.scenario_yaml_entries():
        text = resolver.read_text(entry)
        data = yaml.safe_load(text)
        if data and isinstance(data, dict):
            scenarios.append(data)
            raw_files[f"scenarios/{Path(entry.path).name}"] = text
            logger.info("Loaded scenario %s", Path(entry.path).name)
    return scenarios


def _load_feature_files(
    resolver: ManifestInventoryResolver,
    raw_files: dict[str, str],
) -> dict[str, str]:
    """Read every scenario feature file entry from the resolver."""
    feature_files: dict[str, str] = {}
    for entry in resolver.scenario_feature_entries():
        content = resolver.read_text(entry)
        scenario_id = entry.scenario_id or Path(entry.path).stem
        feature_files[scenario_id] = content
        raw_files[f"scenarios/{Path(entry.path).name}"] = content
    return feature_files


def _load_scenario_artifacts(
    resolver: ManifestInventoryResolver,
    raw_files: dict[str, str],
) -> tuple[list[dict], dict[str, str]]:
    """Read scenario YAML files and feature files from the resolver entries."""
    scenarios = _load_scenario_yamls(resolver, raw_files)
    feature_files = _load_feature_files(resolver, raw_files)
    logger.info(
        "Loaded %d scenarios, %d feature files",
        len(scenarios),
        len(feature_files),
    )
    return scenarios, feature_files


def _load_use_case_text(
    resolver: ManifestInventoryResolver,
) -> str:
    """Read the use case description, if present in the manifest inventory."""
    uc_entry = resolver.entry_by_role(ArtifactRole.USE_CASE)
    if uc_entry is None:
        return ""
    use_case_text = resolver.read_text(uc_entry)
    logger.info("Loaded use case description from manifest inventory")
    return use_case_text


def load_report_data(
    run_dir: Path | None = None,
    *,
    resolver: ManifestInventoryResolver | None = None,
    allow_non_authoritative: bool = False,
) -> ReportData:
    """Read all pipeline artifacts into a :class:`ReportData`.

    Args:
        run_dir: Path to a run directory (or collection with one run).
            Used for **standalone** report loading.  The manifest must be
            authoritative (``completed``) unless *allow_non_authoritative*
            is set.
        resolver: Pre-built in-memory resolver for **internal** pipeline
            use.  When provided, *run_dir* is ignored.
        allow_non_authoritative: When True (standalone only), accept
            non-``completed`` finalized manifests for forensic reading.

    Missing inventory entries are tolerated (with warnings); the returned
    object will have empty defaults for any artifact not in the manifest.
    """
    resolver = _resolve_resolver(resolver, run_dir, allow_non_authoritative)

    raw_files: dict[str, str] = {}

    # --- Capability profile ---
    profile_data, profile_text = _load_yaml_artifact(
        resolver,
        ArtifactRole.CAPABILITY_PROFILE,
        "capability-profile.yaml",
        success_log="Loaded capability profile from manifest inventory",
        missing_log="capability-profile not in manifest inventory",
    )
    if profile_text is not None:
        raw_files["capability-profile.yaml"] = profile_text

    # --- Threat surface ---
    threat_surface_data, ts_text = _load_yaml_artifact(
        resolver,
        ArtifactRole.THREAT_SURFACE,
        "threat-surface.yaml",
        success_log="Loaded threat surface from manifest inventory",
        missing_log="threat-surface not in manifest inventory",
    )
    if ts_text is not None:
        raw_files["threat-surface.yaml"] = ts_text

    # --- Scenarios and feature files ---
    scenarios, feature_files = _load_scenario_artifacts(resolver, raw_files)

    # --- Scenario LLM call logs ---
    call_logs: dict[str, list[dict]] = {}
    scenario_call_lines = _load_call_log_entry_lines(
        resolver,
        ArtifactRole.SCENARIO_CALL_LOG,
        success_log="Loaded %d call log entries from manifest inventory",
        failure_log="Failed to load scenario call log: %s",
    )
    for entry_dict in scenario_call_lines:
        sid = entry_dict.get("scenario_id", "")
        call_logs.setdefault(sid, []).append(entry_dict)

    # --- Pipeline (non-scenario) LLM call logs ---
    pipeline_call_logs = _load_call_log_entry_lines(
        resolver,
        ArtifactRole.PIPELINE_CALL_LOG,
        success_log="Loaded %d pipeline call log entries from manifest inventory",
        failure_log="Failed to load pipeline call log: %s",
    )

    # --- Coverage gaps ---
    coverage_data, coverage_text = _load_json_artifact(
        resolver,
        ArtifactRole.COVERAGE_REPORT,
        "coverage-gaps.json",
        success_log="Loaded coverage gaps from manifest inventory",
        failure_log="Failed to load coverage report: %s",
    )
    if coverage_text is not None:
        raw_files["coverage-gaps.json"] = coverage_text

    # --- Eval scorecard ---
    scorecard_data = _load_scorecard_artifact(resolver, raw_files)

    # --- Run manifest ---
    # Use the supplied resolver's in-memory manifest rather than reloading
    # the persisted on-disk sentinel.  For internal pipeline use the resolver
    # carries the intended-final manifest view; for standalone use it carries
    # the loaded final manifest.
    manifest_data = resolver.manifest.model_dump(mode="json")
    logger.info("Loaded run manifest from resolver")

    # --- Use case description ---
    use_case_text = _load_use_case_text(resolver)

    return ReportData(
        profile_data=profile_data,
        threat_surface_data=threat_surface_data,
        scenarios=scenarios,
        feature_files=feature_files,
        call_logs=call_logs,
        pipeline_call_logs=pipeline_call_logs,
        coverage_data=coverage_data,
        scorecard_data=scorecard_data,
        manifest_data=manifest_data,
        use_case_text=use_case_text,
        raw_files=raw_files,
    )

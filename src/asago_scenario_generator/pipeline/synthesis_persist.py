"""Writers for the synthesis sidecars, manifest, and report."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.obligation_persistence import (
    write_taxonomy_obligation_plan,
)
from asago_scenario_generator.pipeline.synthesis_types import (
    MANIFEST_FILENAME,
    PLAN_FILENAME,
    REPORT_FILENAME,
    PersistArtifactPort,
    PersistManifestPort,
    ReportPort,
    SynthesisAdapters,
    SynthesisInputs,
)
from asago_scenario_generator.pipeline.synthesis_values import _dump
from asago_scenario_generator.pipeline.target_realization_persistence import (
    TARGET_REALIZATION_FILENAME,
    write_target_realization,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TARGET_OBSERVATIONS_FILENAME,
)

# Callers configure logging for the public synthesis module, so the report
# warning logs under that module's name.
logger = logging.getLogger("asago_scenario_generator.pipeline.synthesis")


def _persist_prepared_profile(output_dir: Path, profile: CapabilityProfile) -> Path:
    """Persist one typed profile for SP1 to reload without re-derivation.

    The ordinary ``run_sp1`` API accepts a profile path rather than an
    in-memory profile.  Writing the already prepared model once at this seam
    keeps Phase 1 and STPA on the same profile identity and ensures that SP1's
    Stage 1b is skipped.
    """
    payload = profile.model_dump(mode="json", exclude_none=True)
    path = output_dir / "capability-profile.yaml"
    atomic_write_text(
        path, yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    )
    return path


def _persist_plan(
    output_dir: Path,
    plan: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Path:
    """Persist the Phase 1 plan through its adapter and verify a reload."""
    if adapters.persist_plan is not None:
        result = adapters.persist_plan(
            output_dir=output_dir,
            plan=plan,
        )
        calls.append("persist_plan")
        return Path(result) if result is not None else output_dir / PLAN_FILENAME
    path = write_taxonomy_obligation_plan(output_dir, plan)
    calls.append("persist_plan")
    return path


def _reload_persisted_plan(plan: Any, path: Path) -> Any:
    """Use the closed, integrity-checked Phase 1 artifact downstream."""
    reloaded = TaxonomyObligationPlan.from_yaml(path.read_text(encoding="utf-8"))
    if reloaded != plan:
        raise ValueError("persisted Phase 1 plan does not match the planned artifact")
    return reloaded


def _persist_sidecar(
    output_dir: Path,
    filename: str,
    artifact: Any,
    writer: PersistArtifactPort | None,
    label: str,
) -> Path:
    """Write one closed artifact atomically, then perform a best-effort reload."""
    if writer is not None:
        result = writer(output_dir=output_dir, artifact=artifact)
        path = Path(result) if result is not None else output_dir / filename
        if not path.exists():
            raise ValueError(f"{label} persistence adapter did not write {path}")
        return path
    path = output_dir / filename
    content = _artifact_yaml(artifact)
    atomic_write_text(path, content)
    _verify_yaml_round_trip(artifact, path)
    return path


def _persist_target_realization(
    output_dir: Path,
    artifact: Any | None,
    writer: PersistArtifactPort | None,
) -> Path | None:
    """Publish the additive target lens only when a target was supplied."""
    if artifact is None:
        return None
    if writer is None:
        return write_target_realization(output_dir, artifact)
    path = _persist_sidecar(
        output_dir,
        TARGET_REALIZATION_FILENAME,
        artifact,
        writer,
        "target_realization",
    )
    return path


def _persist_manifest(
    output_dir: Path,
    manifest: Any,
    writer: PersistManifestPort | None,
) -> Path:
    """Atomically publish and verify the top-level synthesis manifest."""
    if writer is not None:
        result = writer(output_dir=output_dir, manifest=manifest)
        path = Path(result) if result is not None else output_dir / MANIFEST_FILENAME
        if not path.exists():
            raise ValueError(f"manifest persistence adapter did not write {path}")
        return path
    path = output_dir / MANIFEST_FILENAME
    atomic_write_text(path, _artifact_yaml(manifest))
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("synthesis manifest did not round-trip as a mapping")
    return path


def _render_report(
    output_dir: Path,
    manifest: Any,
    plan: Any,
    consideration: Any,
    accounting: Any,
    realization: Any,
    target_realization: Any,
    scenario_result: Any,
    renderer: ReportPort | None,
) -> Path | None:
    """Render the read-only synthesis report after all normative sidecars."""
    if renderer is not None:
        result = renderer(
            output_dir=output_dir,
            manifest=manifest,
            plan=plan,
            consideration=consideration,
            accounting=accounting,
            realization=realization,
            target_realization=target_realization,
            scenario_result=scenario_result,
        )
        return Path(result) if result is not None else None
    try:
        from asago_scenario_generator.report.synthesis import render_synthesis_report

        return render_synthesis_report(
            output_dir,
            manifest=manifest,
            plan=plan,
            consideration=consideration,
            accounting=accounting,
            realization=realization,
            target_realization=target_realization,
            scenario_result=scenario_result,
        )
    except Exception as exc:  # noqa: BLE001 - report is read-only and non-fatal
        logger.warning("synthesis report generation failed: %s", exc)
        return None


def _artifact_paths(
    output_dir: Path,
    inputs: SynthesisInputs,
    artifact_paths: dict[str, Path],
    *,
    target_realization_path: Path | None,
    operation_enrichment: Any | None,
    report_path: Path | None,
) -> dict[str, Path]:
    """Add each optional published artifact to the always-written ones."""
    if target_realization_path is not None:
        artifact_paths[TARGET_REALIZATION_FILENAME] = target_realization_path
    if operation_enrichment is not None:
        from asago_scenario_generator.pipeline.control_action_enrichment import (
            CONTROL_ACTION_ENRICHMENT_FILENAME,
        )

        artifact_paths[CONTROL_ACTION_ENRICHMENT_FILENAME] = (
            output_dir / CONTROL_ACTION_ENRICHMENT_FILENAME
        )
    target_observations_path = (
        output_dir / TARGET_OBSERVATIONS_FILENAME
        if inputs.target_observations is not None
        else None
    )
    if target_observations_path is not None and target_observations_path.exists():
        artifact_paths[TARGET_OBSERVATIONS_FILENAME] = target_observations_path
    if report_path is not None:
        artifact_paths[REPORT_FILENAME] = report_path
    return artifact_paths


def _artifact_yaml(value: Any) -> str:
    to_yaml = getattr(value, "to_yaml", None)
    if callable(to_yaml):
        text = to_yaml()
        if isinstance(text, str):
            return text
    payload = _dump(value)
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def _verify_yaml_round_trip(original: Any, path: Path) -> None:
    """Reload through a closed ``from_yaml`` hook when the artifact has one."""
    loader = getattr(type(original), "from_yaml", None)
    if callable(loader):
        loaded = loader(path.read_text(encoding="utf-8"))
        if loaded != original:
            raise ValueError(f"{path.name} failed closed-model round-trip equality")

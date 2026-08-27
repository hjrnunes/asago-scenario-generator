"""End-to-end STPA pipeline runner: SP1 → SP2 → SP3 → report.

Orchestrates the full STPA pipeline in a single call, with per-stage
LLM client resolution, resume support, and degraded-result handling.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from asago_scenario_generator.data.loaders import load_risk_extraction
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.infra.calls_html import render_calls_html
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.enriched_threat_set import EnrichedThreatSet
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.pipeline.llm_config import (
    read_use_case,
    resolve_llm_client,
)
from asago_scenario_generator.stpa.report import generate_report
from asago_scenario_generator.stpa.scenario_prod.run import SP3RunResult, run_sp3
from asago_scenario_generator.stpa.system_model.run import SP1RunResult, run_sp1
from asago_scenario_generator.stpa.threat_enum.run import SP2RunResult, run_sp2

logger = logging.getLogger(__name__)

SP1_ARTIFACT_NAMES = (
    "loss-analysis.yaml",
    "capability-profile.yaml",
    "control-structure.yaml",
)

SP2_ARTIFACT_NAMES = (
    "ica-enumeration.yaml",
    "enriched-threats.yaml",
)


@dataclass
class STPARunResult:
    """Result of a full STPA pipeline run.

    Each stage result may be ``None`` when the stage was skipped (resume)
    or failed. ``stage_errors`` collects error messages from all stages.
    """

    sp1_result: SP1RunResult | None = None
    sp2_result: SP2RunResult | None = None
    sp3_result: SP3RunResult | None = None
    report_path: Path | None = None
    stage_errors: list[str] = field(default_factory=list)
    stage_warnings: list[str] = field(default_factory=list)


def run_stpa_pipeline(
    *,
    use_case_path: str,
    risk_extraction_path: str,
    output_dir: Path,
    profile: str | None = None,
    sp1_profile: str | None = None,
    sp2_profile: str | None = None,
    sp3_profile: str | None = None,
    profiles_file: str = "config/model-profiles.yaml",
    capability_profile_path: Path | None = None,
    max_workers: int = 1,
    resume: bool = False,
    temperature: float | None = None,
) -> STPARunResult:
    """Run the full STPA pipeline: SP1 → SP2 → SP3 → report.

    Args:
        use_case_path: Path to the use-case text file (``@`` prefix optional).
        risk_extraction_path: Path to the risk extraction JSON file.
        output_dir: Directory for all pipeline artifacts.
        profile: Default model profile name for all stages.
        sp1_profile: SP1-specific model profile override.
        sp2_profile: SP2-specific model profile override.
        sp3_profile: SP3-specific model profile override.
        profiles_file: Path to the model profiles YAML file.
        capability_profile_path: Path to a pre-built capability-profile.yaml.
            When provided, SP1 Stage 1b is skipped and the profile is
            passed to SP3 for envelope enrichment.
        max_workers: Parallel workers for LLM calls within stages.
        resume: When True, skip stages whose artifacts already exist.
        temperature: Explicit temperature override for every stage. When
            omitted, each stage uses its resolved profile or environment
            configuration, then the shared 0.4 default.

    Returns:
        An :class:`STPARunResult` with per-stage results and the report path.
    """
    output_dir = Path(output_dir)
    stage_errors: list[str] = []
    stage_warnings: list[str] = []

    # --- Step 0: Input validation ---
    _validate_inputs(
        use_case_path=use_case_path,
        risk_extraction_path=risk_extraction_path,
        capability_profile_path=capability_profile_path,
        profiles_file=profiles_file,
        profile=profile,
        sp1_profile=sp1_profile,
        sp2_profile=sp2_profile,
        sp3_profile=sp3_profile,
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    # --- Step 1: SP1 ---
    skip_sp1 = _maybe_skip_stage(
        resume,
        _sp1_artifacts_exist(output_dir),
        "SP1",
    )
    sp1_result = _run_sp1_stage(
        skip=skip_sp1,
        use_case_path=use_case_path,
        risk_extraction_path=risk_extraction_path,
        output_dir=output_dir,
        profile=profile,
        sp1_profile=sp1_profile,
        profiles_file=profiles_file,
        capability_profile_path=capability_profile_path,
        max_workers=max_workers,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
        temperature=temperature,
    )

    # Load SP1 artifacts from disk (needed for SP2/SP3 and for resume)
    control_structure = _load_sp1_artifact(
        output_dir,
        "control-structure.yaml",
        ControlStructure,
    )
    if _abort_if_missing(
        control_structure,
        skip_sp1,
        "SP1",
        "control-structure.yaml",
        stage_errors,
    ):
        _persist_pipeline_diagnostics(
            output_dir,
            sp1_result=sp1_result,
            stage_errors=stage_errors,
            stage_warnings=stage_warnings,
        )
        return STPARunResult(
            sp1_result=sp1_result,
            stage_errors=stage_errors,
            stage_warnings=stage_warnings,
        )

    capability_profile = _load_sp1_artifact(
        output_dir,
        "capability-profile.yaml",
        CapabilityProfile,
    )
    loss_analysis = _load_sp1_artifact(
        output_dir,
        "loss-analysis.yaml",
        LossAnalysis,
    )

    # --- Step 2: SP2 ---
    skip_sp2 = _maybe_skip_stage(
        resume,
        _sp2_artifacts_exist(output_dir),
        "SP2",
    )
    sp2_result = _run_sp2_stage(
        skip=skip_sp2,
        output_dir=output_dir,
        control_structure=control_structure,
        capability_profile=capability_profile,
        loss_analysis=loss_analysis,
        profile=profile,
        sp2_profile=sp2_profile,
        profiles_file=profiles_file,
        max_workers=max_workers,
        stage_errors=stage_errors,
        temperature=temperature,
    )

    # Load SP2 artifacts from disk
    enriched_threat_set = _load_sp1_artifact(
        output_dir,
        "enriched-threats.yaml",
        EnrichedThreatSet,
    )
    if _abort_if_missing(
        enriched_threat_set,
        skip_sp2,
        "SP2",
        "enriched-threats.yaml",
        stage_errors,
    ):
        _persist_pipeline_diagnostics(
            output_dir,
            sp1_result=sp1_result,
            stage_errors=stage_errors,
            stage_warnings=stage_warnings,
        )
        return STPARunResult(
            sp1_result=sp1_result,
            sp2_result=sp2_result,
            stage_errors=stage_errors,
            stage_warnings=stage_warnings,
        )

    # --- Step 3: SP3 ---
    skip_sp3 = _maybe_skip_stage(
        resume,
        _sp3_artifacts_exist(output_dir),
        "SP3",
    )
    sp3_result = _run_sp3_stage(
        skip=skip_sp3,
        output_dir=output_dir,
        enriched_threat_set=enriched_threat_set,
        control_structure=control_structure,
        loss_analysis=loss_analysis,
        profile=profile,
        sp3_profile=sp3_profile,
        profiles_file=profiles_file,
        capability_profile_path=capability_profile_path,
        max_workers=max_workers,
        stage_errors=stage_errors,
        temperature=temperature,
    )

    # Later stages share the same manifest path, so restore the combined
    # diagnostics after their manifests have been written.
    _persist_pipeline_diagnostics(
        output_dir,
        sp1_result=sp1_result,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
    )

    # --- Step 4: Report (always) ---
    report_path = _generate_report(output_dir)

    # --- Step 5: Summary ---
    _print_summary(
        sp1_result=sp1_result,
        sp2_result=sp2_result,
        sp3_result=sp3_result,
        report_path=report_path,
        output_dir=output_dir,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
    )

    return STPARunResult(
        sp1_result=sp1_result,
        sp2_result=sp2_result,
        sp3_result=sp3_result,
        report_path=report_path,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
    )


def _persist_pipeline_diagnostics(
    output_dir: Path,
    *,
    sp1_result: SP1RunResult | None,
    stage_errors: list[str],
    stage_warnings: list[str],
) -> None:
    """Preserve combined fatal and recoverable diagnostics in the manifest."""
    manifest_path = output_dir / "run-manifest.yaml"
    if not manifest_path.exists():
        return
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    manifest["stage_errors"] = stage_errors
    manifest["stage_warnings"] = stage_warnings
    if sp1_result is not None:
        manifest["revised"] = sp1_result.revised
        manifest["post_revision_warnings"] = sp1_result.post_revision_warnings
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _persist_sp1_revision_diagnostics(
    output_dir: Path,
    sp1_result: SP1RunResult | None,
) -> None:
    """Compatibility wrapper preserving the former SP1-only manifest update."""
    if sp1_result is None:
        return
    manifest_path = output_dir / "run-manifest.yaml"
    if not manifest_path.exists():
        return
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    manifest["revised"] = sp1_result.revised
    manifest["post_revision_warnings"] = sp1_result.post_revision_warnings
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def _validate_inputs(
    *,
    use_case_path: str,
    risk_extraction_path: str,
    capability_profile_path: Path | None,
    profiles_file: str,
    profile: str | None,
    sp1_profile: str | None,
    sp2_profile: str | None,
    sp3_profile: str | None,
) -> None:
    """Validate that all required input files exist before starting."""
    raw_use_case = use_case_path[1:] if use_case_path.startswith("@") else use_case_path
    if not Path(raw_use_case).exists():
        raise FileNotFoundError(f"Use-case file not found: {use_case_path}")
    if not Path(risk_extraction_path).exists():
        raise FileNotFoundError(
            f"Risk extraction file not found: {risk_extraction_path}"
        )
    if (
        capability_profile_path is not None
        and not Path(capability_profile_path).exists()
    ):
        raise FileNotFoundError(
            f"Capability profile file not found: {capability_profile_path}"
        )
    _validate_profiles_file(
        profiles_file,
        profile,
        sp1_profile,
        sp2_profile,
        sp3_profile,
    )


def _validate_profiles_file(
    profiles_file: str,
    profile: str | None,
    sp1_profile: str | None,
    sp2_profile: str | None,
    sp3_profile: str | None,
) -> None:
    """Validate that the profiles file exists when a profile is requested."""
    if (
        profile is None
        and sp1_profile is None
        and sp2_profile is None
        and sp3_profile is None
    ):
        return
    if not Path(profiles_file).exists():
        raise FileNotFoundError(f"Model profiles file not found: {profiles_file}")


# ---------------------------------------------------------------------------
# Stage skip / abort helpers
# ---------------------------------------------------------------------------


def _maybe_skip_stage(
    resume: bool,
    artifacts_exist: bool,
    stage_name: str,
) -> bool:
    """Return True if the stage should be skipped (resume + artifacts on disk)."""
    if resume and artifacts_exist:
        logger.info("Resume: %s artifacts exist, skipping %s", stage_name, stage_name)
        return True
    return False


def _abort_if_missing(
    artifact: object | None,
    skip: bool,
    stage: str,
    artifact_name: str,
    stage_errors: list[str],
) -> bool:
    """Return True if the pipeline should abort due to a missing critical artifact."""
    if artifact is None and not skip:
        _abort_missing_artifact(stage, artifact_name, stage_errors)
        return True
    return False


# ---------------------------------------------------------------------------
# SP1
# ---------------------------------------------------------------------------


def _run_sp1_stage(
    *,
    skip: bool,
    use_case_path: str,
    risk_extraction_path: str,
    output_dir: Path,
    profile: str | None,
    sp1_profile: str | None,
    profiles_file: str,
    capability_profile_path: Path | None,
    max_workers: int,
    stage_errors: list[str],
    stage_warnings: list[str] | None = None,
    temperature: float | None = None,
) -> SP1RunResult | None:
    """Run SP1 and render calls.html, or return None when skipping."""
    if skip:
        return None
    llm_client, profile_name = resolve_llm_client(
        profile,
        sp1_profile,
        profiles_file,
    )
    use_case_text = read_use_case(use_case_path)
    risk_cards = load_risk_extraction(risk_extraction_path)

    logger.info("Starting SP1 pipeline...")
    result = run_sp1(
        llm_client=llm_client,
        use_case_text=use_case_text,
        risk_cards=risk_cards,
        run_dir=output_dir,
        profile_path=capability_profile_path,
        profile_name=profile_name,
        max_workers=max_workers,
        temperature=temperature if temperature is not None else llm_client.temperature,
    )

    # Render calls.html
    calls_jsonl = output_dir / "calls.jsonl"
    if calls_jsonl.exists():
        render_calls_html(calls_jsonl, output_dir / "calls.html")
        logger.info("Rendered calls.html to %s", output_dir / "calls.html")

    if result.stage_errors:
        logger.warning("SP1 completed with %d stage errors", len(result.stage_errors))
        stage_errors.extend(result.stage_errors)
    if result.stage_warnings:
        logger.warning(
            "SP1 completed with %d recoverable warnings",
            len(result.stage_warnings),
        )
        if stage_warnings is not None:
            stage_warnings.extend(result.stage_warnings)

    return result


# ---------------------------------------------------------------------------
# SP2
# ---------------------------------------------------------------------------


def _run_sp2_stage(
    *,
    skip: bool,
    output_dir: Path,
    control_structure: ControlStructure | None,
    capability_profile: CapabilityProfile | None,
    loss_analysis: LossAnalysis | None,
    profile: str | None,
    sp2_profile: str | None,
    profiles_file: str,
    max_workers: int,
    stage_errors: list[str],
    temperature: float | None = None,
) -> SP2RunResult | None:
    """Run SP2 using SP1 artifacts, or return None when skipping/unavailable."""
    if skip:
        return None
    if control_structure is None:
        return None
    llm_client, _ = resolve_llm_client(profile, sp2_profile, profiles_file)

    logger.info("Starting SP2 pipeline...")
    result = run_sp2(
        llm_client=llm_client,
        control_structure=control_structure,
        capability_profile=capability_profile,  # type: ignore[arg-type]
        loss_analysis=loss_analysis,  # type: ignore[arg-type]
        run_dir=output_dir,
        max_workers=max_workers,
        temperature=temperature if temperature is not None else llm_client.temperature,
    )

    if result.stage_errors:
        logger.warning("SP2 completed with %d stage errors", len(result.stage_errors))
        stage_errors.extend(result.stage_errors)

    return result


# ---------------------------------------------------------------------------
# SP3
# ---------------------------------------------------------------------------


def _run_sp3_stage(
    *,
    skip: bool,
    output_dir: Path,
    enriched_threat_set: EnrichedThreatSet | None,
    control_structure: ControlStructure | None,
    loss_analysis: LossAnalysis | None,
    profile: str | None,
    sp3_profile: str | None,
    profiles_file: str,
    capability_profile_path: Path | None,
    max_workers: int,
    stage_errors: list[str],
    temperature: float | None = None,
) -> SP3RunResult | None:
    """Run SP3 using SP1/SP2 artifacts, or return None when skipping/unavailable."""
    if skip:
        return None
    if enriched_threat_set is None:
        return None
    if control_structure is None:
        return None
    llm_client, _ = resolve_llm_client(profile, sp3_profile, profiles_file)

    # Pass capability_profile to SP3 only when --capability-profile was
    # explicitly provided by the user. When SP1 generates the profile,
    # don't pass it to SP3.
    capability_profile: CapabilityProfile | None = None
    if capability_profile_path is not None:
        capability_profile = read_yaml(
            Path(capability_profile_path),
            CapabilityProfile,
        )

    logger.info("Starting SP3 pipeline...")
    result = run_sp3(
        llm_client=llm_client,
        enriched_threat_set=enriched_threat_set,
        control_structure=control_structure,
        loss_analysis=loss_analysis,  # type: ignore[arg-type]
        run_dir=output_dir,
        capability_profile=capability_profile,
        max_workers=max_workers,
        temperature=temperature if temperature is not None else llm_client.temperature,
    )

    if result.stage_errors:
        logger.warning("SP3 completed with %d stage errors", len(result.stage_errors))
        stage_errors.extend(result.stage_errors)

    return result


# ---------------------------------------------------------------------------
# Resume helpers
# ---------------------------------------------------------------------------


def _sp1_artifacts_exist(output_dir: Path) -> bool:
    """Check whether all SP1 artifacts exist in *output_dir*."""
    return all((output_dir / name).exists() for name in SP1_ARTIFACT_NAMES)


def _sp2_artifacts_exist(output_dir: Path) -> bool:
    """Check whether all SP2 artifacts exist in *output_dir*."""
    return all((output_dir / name).exists() for name in SP2_ARTIFACT_NAMES)


def _sp3_artifacts_exist(output_dir: Path) -> bool:
    """Check whether SP3 scenarios directory has .yaml files."""
    scenarios_dir = output_dir / "scenarios"
    if not scenarios_dir.exists():
        return False
    return any(scenarios_dir.glob("*.yaml"))


# ---------------------------------------------------------------------------
# Artifact loading
# ---------------------------------------------------------------------------


def _load_sp1_artifact(
    output_dir: Path,
    filename: str,
    model_class: type,
) -> object | None:
    """Load an artifact from *output_dir*, returning None if missing or invalid."""
    path = output_dir / filename
    if not path.exists():
        return None
    try:
        return read_yaml(path, model_class)  # type: ignore[return-value]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load %s: %s", path, exc)
        return None


def _abort_missing_artifact(
    stage: str,
    artifact_name: str,
    stage_errors: list[str],
) -> None:
    """Log an error and record a stage error for a missing critical artifact."""
    msg = f"{stage} did not produce {artifact_name}; stopping pipeline"
    logger.error(msg)
    stage_errors.append(msg)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def _generate_report(output_dir: Path) -> Path:
    """Generate the STPA HTML report (always, even on degraded results)."""
    logger.info("Generating STPA report...")
    try:
        return generate_report(output_dir)
    except Exception as exc:  # noqa: BLE001
        logger.error("Report generation failed: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def _print_summary(
    *,
    sp1_result: SP1RunResult | None,
    sp2_result: SP2RunResult | None,
    sp3_result: SP3RunResult | None,
    report_path: Path,
    output_dir: Path,
    stage_errors: list[str],
    stage_warnings: list[str] | None = None,
) -> None:
    """Print a combined summary table to stdout."""
    print("")
    print("=" * 60)
    print("STPA PIPELINE SUMMARY")
    print("=" * 60)

    _print_sp1_summary(sp1_result, output_dir)
    _print_sp2_summary(sp2_result, output_dir)
    _print_sp3_summary(sp3_result)
    _print_report_summary(report_path)
    _print_stage_errors_summary(stage_errors)
    _print_stage_warnings_summary(stage_warnings or [])

    print("=" * 60)


def _print_sp1_summary(
    sp1_result: SP1RunResult | None,
    output_dir: Path,
) -> None:
    """Print SP1 metrics, loading from disk if the result is not in-memory."""
    print("")
    print("--- SP1: System Model ---")

    loss_analysis: LossAnalysis | None = None
    control_structure: ControlStructure | None = None

    if sp1_result is not None:
        loss_analysis = sp1_result.loss_analysis
        control_structure = sp1_result.control_structure
    else:
        # Resume: load from disk
        loss_analysis = _load_sp1_artifact(  # type: ignore[assignment]
            output_dir,
            "loss-analysis.yaml",
            LossAnalysis,
        )
        control_structure = _load_sp1_artifact(  # type: ignore[assignment]
            output_dir,
            "control-structure.yaml",
            ControlStructure,
        )

    if loss_analysis is not None:
        all_losses = loss_analysis.risk_card_losses + loss_analysis.use_case_losses
        print(f"  Losses:           {len(all_losses)}")
        print(f"  Hazards:          {len(loss_analysis.hazards)}")
        print(f"  Constraints:      {len(loss_analysis.security_constraints)}")
    else:
        print("  Loss Analysis:    DEGRADED — not produced")

    if control_structure is not None:
        total_ca = sum(
            len(r.control_actions) for r in control_structure.responsibilities
        )
        print(f"  Responsibilities: {len(control_structure.responsibilities)}")
        print(f"  Control Actions:  {total_ca}")
    else:
        print("  Control Structure: DEGRADED — not produced")


def _print_sp2_summary(
    sp2_result: SP2RunResult | None,
    output_dir: Path,
) -> None:
    """Print SP2 metrics, loading from disk if the result is not in-memory."""
    from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration

    print("")
    print("--- SP2: Threat Enumeration ---")

    if sp2_result is not None:
        ica_enumeration = sp2_result.ica_enumeration
        enriched_threat_set = sp2_result.enriched_threat_set
    else:
        ica_enumeration = _load_sp1_artifact(
            output_dir,
            "ica-enumeration.yaml",
            ICAEnumeration,
        )
        enriched_threat_set = _load_sp1_artifact(  # type: ignore[assignment]
            output_dir,
            "enriched-threats.yaml",
            EnrichedThreatSet,
        )

    _print_ica_summary(ica_enumeration)
    _print_enriched_threats_summary(enriched_threat_set)


def _print_ica_summary(ica_enumeration: object | None) -> None:
    """Print ICA enumeration metrics or a degraded message."""
    if ica_enumeration is None:
        print("  ICA Enumeration:    DEGRADED — not produced")
        return
    total = len(ica_enumeration.slots)
    na = sum(1 for s in ica_enumeration.slots if s.is_na)
    print(f"  Total slots:        {total}")
    print(f"  N/A slots:          {na}")
    if total:
        print(f"  Fill rate:          {(total - na) / total:.1%}")
    else:
        print("  Fill rate:          N/A")


def _print_enriched_threats_summary(
    enriched_threat_set: EnrichedThreatSet | None,
) -> None:
    """Print enriched threat set metrics or a degraded message."""
    if enriched_threat_set is None:
        print("  Enriched Threat Set: DEGRADED — not produced")
        return
    threats = enriched_threat_set.structural_threats
    print(f"  Structural threats: {len(threats)}")
    mapped = sum(1 for t in threats if t.catalog_mappings)
    print(f"  Mapped:             {mapped}")
    print(f"  Unmapped:           {len(threats) - mapped}")


def _print_sp3_summary(sp3_result: SP3RunResult | None) -> None:
    """Print SP3 metrics."""
    print("")
    print("--- SP3: Scenario Production ---")

    if sp3_result is not None:
        print(f"  Scenario specs:     {len(sp3_result.scenario_specs)}")
        print(f"  Scenario envelopes: {len(sp3_result.scenario_envelopes)}")
        print(f"  Validation errors:  {len(sp3_result.validation_errors)}")
        if sp3_result.eval_scorecard:
            _print_eval_metrics_summary(sp3_result.eval_scorecard)
    else:
        print("  SP3: SKIPPED or not produced")


def _print_eval_metrics_summary(eval_scorecard: dict) -> None:
    """Print a one-line summary of eval metrics."""
    metrics = eval_scorecard.get("metrics", eval_scorecard)
    if not isinstance(metrics, dict):
        return
    rates: list[str] = []
    for name, data in metrics.items():
        rate = _extract_rate(data)
        if rate is not None:
            rates.append(f"{name}={rate}")
    if rates:
        print(f"  Eval metrics:       {', '.join(rates)}")


def _extract_rate(data: object) -> str | None:
    """Extract a rate string from a metric entry (dict or scalar)."""
    if isinstance(data, dict):
        rate = data.get("rate")
        if rate is not None:
            return f"{float(rate):.1%}"
    return None


def _print_report_summary(report_path: Path) -> None:
    """Print the report path."""
    print("")
    print(f"  Report: {report_path}")


def _print_stage_errors_summary(stage_errors: list[str]) -> None:
    """Print stage error counts when errors are present."""
    if not stage_errors:
        return
    print("")
    print(f"  Stage Errors: {len(stage_errors)}")
    for err in stage_errors:
        print(f"    - {err}")


def _print_stage_warnings_summary(stage_warnings: list[str]) -> None:
    """Print recoverable stage warning counts when warnings are present."""
    if not stage_warnings:
        return
    print("")
    print(f"  Stage Warnings: {len(stage_warnings)}")
    for warning in stage_warnings:
        print(f"    - {warning}")


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T17:28:16Z","module_hash":"991a309f0b691dbd74b2c0f5fb09a8588a1646532e6496d6dabd20f316ebf6e7","functions":[{"id":"func/run_stpa_pipeline","name":"run_stpa_pipeline","line":58,"end_line":208,"hash":"2b2bf36c0e394a52dd9c8bf6cf13c75c2101067ebeb24b6654b687d66cd48f5d"},{"id":"func/_validate_inputs","name":"_validate_inputs","line":216,"end_line":241,"hash":"5969ff5a77f59095790eff2207fac98c9490d2ac3fdf8b680b7cd094641f568b"},{"id":"func/_validate_profiles_file","name":"_validate_profiles_file","line":244,"end_line":255,"hash":"4bfeca226ec1267700770d8d273683031c27fceb3981c1ea9916436ab111e940"},{"id":"func/_maybe_skip_stage","name":"_maybe_skip_stage","line":263,"end_line":270,"hash":"84c7dd5a7009068d6cafe2cc0156cde45bad75703d784546e46b67968cc3041c"},{"id":"func/_abort_if_missing","name":"_abort_if_missing","line":273,"end_line":284,"hash":"9f4de151b6cf9d2fe587b29c64e5491efe83587265b0ee61dde0d70d54e9ba99"},{"id":"func/_run_sp1_stage","name":"_run_sp1_stage","line":292,"end_line":335,"hash":"ba0d6b827e0967409273654ac363198d204f6394a6279e9ffdee1dfc11446fe3"},{"id":"func/_run_sp2_stage","name":"_run_sp2_stage","line":343,"end_line":377,"hash":"83932da16a492eaa696a7aa7c83a9187be28c9b7003385fadec99ef724fefd73"},{"id":"func/_run_sp3_stage","name":"_run_sp3_stage","line":385,"end_line":432,"hash":"650dd1d311052529894fa076d0e0ac06c8054e9f205bb2e1fdab915a549247af"},{"id":"func/_sp1_artifacts_exist","name":"_sp1_artifacts_exist","line":440,"end_line":442,"hash":"90bced979008549292061125b4e20e0c18383476c7d31168b3f7ebc0efc649d1"},{"id":"func/_sp2_artifacts_exist","name":"_sp2_artifacts_exist","line":445,"end_line":447,"hash":"62744d31eec58ac2f71ffc5a8d0dcc83301711d0e1ad401c1178d4229305ffe8"},{"id":"func/_sp3_artifacts_exist","name":"_sp3_artifacts_exist","line":450,"end_line":455,"hash":"5664a36f9734f623b33e4db40fea280c803876229e9143b8d20e99caa87cf31b"},{"id":"func/_load_sp1_artifact","name":"_load_sp1_artifact","line":463,"end_line":476,"hash":"8ff6e00e8bff74c0df5e5f26f02fd1d9db24ce44a1fdd760b31ade75b83107dd"},{"id":"func/_abort_missing_artifact","name":"_abort_missing_artifact","line":479,"end_line":487,"hash":"ca4dca693b0e8ccd0c998de9230347a5149ed313624b1f5ad530d8374b6c7319"},{"id":"func/_generate_report","name":"_generate_report","line":495,"end_line":502,"hash":"23f9ab1945bb1aede695c66420eafa4c5c73946623c39f98b85756bef82fa2b7"},{"id":"func/_print_summary","name":"_print_summary","line":510,"end_line":531,"hash":"e0f6f9f635c3fe3fcb852aa92f6b95e47fe54949f9536aacdf5ec202cea57e4e"},{"id":"func/_print_sp1_summary","name":"_print_sp1_summary","line":534,"end_line":574,"hash":"828b6cdebb193f57c27ff3db603fa2feac6b6ef1ff7f924867732174c0f21fe2"},{"id":"func/_print_sp2_summary","name":"_print_sp2_summary","line":577,"end_line":599,"hash":"2ef436cfd621712507689f247ea4006a0cae2f8840bfe1e026a192104bd51aec"},{"id":"func/_print_ica_summary","name":"_print_ica_summary","line":602,"end_line":614,"hash":"6403ab1498528328765bb7dfecad3c3fb3e71ed1b77f89d22437ffd4e98c4087"},{"id":"func/_print_enriched_threats_summary","name":"_print_enriched_threats_summary","line":617,"end_line":628,"hash":"deea4a1fc3ea6eb8997aec41eef0e1d2d863eb57d79cc8d2570dca432361662f"},{"id":"func/_print_sp3_summary","name":"_print_sp3_summary","line":631,"end_line":643,"hash":"902ae4e05690802331a17caca1f0639d68d765845f7c440be2836106ff3e7543"},{"id":"func/_print_eval_metrics_summary","name":"_print_eval_metrics_summary","line":646,"end_line":657,"hash":"078723d31e73996fe678f6618ea6e894727ff3ed252cc5203ca6d683ee5fefd1"},{"id":"func/_extract_rate","name":"_extract_rate","line":660,"end_line":666,"hash":"5a4d4760851bb72ed42ad5c2c9a4a52d9cda618b61e0ba8f20b712a9d1b5f601"},{"id":"func/_print_report_summary","name":"_print_report_summary","line":669,"end_line":672,"hash":"2356480f47ca327c536b698026300c42f3819f27f6e0ba7650c0cb6d426fb230"},{"id":"func/_print_stage_errors_summary","name":"_print_stage_errors_summary","line":675,"end_line":682,"hash":"9f335c2743007f93da7a549c8a647760079d7506cae013f79fc232050fa75531"}]}
# mutate4py-manifest-end

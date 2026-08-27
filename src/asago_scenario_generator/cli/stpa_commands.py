"""STPA surface commands: projection validation, report, and run."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import (
    _abort,
    _load_projection_payload,
    _validate_file,
)


def _first_stopping_error(stage_errors: list[str]) -> str | None:
    """Return the first pipeline-abort error, or None if the run degraded."""
    for error in stage_errors:
        if "stopping pipeline" in error:
            return error
    return None


@app.command(name="validate-stpa-projection")
def validate_stpa_projection(
    artifact: Path = typer.Argument(
        ...,
        help="Canonical STPA execution projection JSON or YAML file.",
    ),
) -> None:
    """Validate a standalone STPA execution projection document.

    Parses the file with standard JSON or YAML readers and reports typed
    traceability violations. A missing or malformed document is rejected
    rather than treated as a valid empty projection.
    """
    _validate_file(artifact, "projection file")
    try:
        from asago_scenario_generator.stpa.scenario_prod.projection import (
            validate_exported_projection,
        )

        result = validate_exported_projection(_load_projection_payload(artifact))
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        _abort(exc)
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    if not result.valid:
        raise typer.Exit(code=1)


@app.command(name="stpa-report")
def stpa_report_cmd(
    output_dir: Path = typer.Option(
        ...,
        help="Directory containing combined SP1+SP2+SP3 STPA artifacts.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write report HTML to this path (default: <output-dir>/stpa-report.html).",
    ),
) -> None:
    """Generate a self-contained HTML report from STPA pipeline output.

    Reads SP1 (loss analysis, capability profile, control structure),
    SP2 (ICA enumeration, enriched threats), SP3 (scenarios, eval scorecard),
    and infrastructure (calls.jsonl, run-manifest.yaml) artifacts from a
    single combined output directory.
    """
    from asago_scenario_generator.stpa.report import generate_report

    if not output_dir.exists():
        typer.echo(f"Error: output directory not found: {output_dir}", err=True)
        raise typer.Exit(code=1)

    try:
        result_path = generate_report(output_dir, output)
        typer.echo(f"STPA report written to: {result_path}")
    except Exception as exc:
        _abort(exc)


@app.command(name="stpa-run")
def stpa_run_cmd(
    use_case: str = typer.Option(
        ...,
        help="Path to use-case text file (@ prefix optional).",
    ),
    risk_extraction: Path = typer.Option(
        ...,
        help="Path to risk extraction JSON file.",
    ),
    output_dir: Path = typer.Option(
        ...,
        help="Output directory for all artifacts.",
    ),
    profile: str | None = typer.Option(
        None,
        help="Default model profile name.",
    ),
    sp1_profile: str | None = typer.Option(
        None,
        help="SP1 model profile override.",
    ),
    sp2_profile: str | None = typer.Option(
        None,
        help="SP2 model profile override.",
    ),
    sp3_profile: str | None = typer.Option(
        None,
        help="SP3 model profile override.",
    ),
    profiles_file: str = typer.Option(
        "config/model-profiles.yaml",
        help="Path to model profiles YAML file.",
    ),
    capability_profile: Path | None = typer.Option(
        None,
        help="Pre-built capability profile path.",
    ),
    max_workers: int = typer.Option(
        1,
        help="Parallel workers for LLM calls.",
    ),
    resume: bool = typer.Option(
        False,
        help="Skip completed stages if artifacts exist.",
    ),
    temperature: float | None = typer.Option(
        None,
        help="Override the resolved sampling temperature for every STPA stage. "
        "Defaults to the selected profile or environment value, then 0.4.",
    ),
) -> None:
    """Run the full STPA pipeline: SP1 → SP2 → SP3 → report."""
    from asago_scenario_generator.stpa.pipeline import run_stpa_pipeline

    try:
        result = run_stpa_pipeline(
            use_case_path=use_case,
            risk_extraction_path=str(risk_extraction),
            output_dir=output_dir,
            profile=profile,
            sp1_profile=sp1_profile,
            sp2_profile=sp2_profile,
            sp3_profile=sp3_profile,
            profiles_file=profiles_file,
            capability_profile_path=capability_profile,
            max_workers=max_workers,
            resume=resume,
            temperature=temperature,
        )
    except FileNotFoundError as exc:
        _abort(exc)
    except Exception as exc:
        _abort(exc)

    # Abort-level errors (missing critical artifacts) stop the pipeline
    # early.  Degrade-level errors (stage_errors from individual stages
    # that still produced artifacts) allow the pipeline to continue and
    # exit with code 0.
    abort_error = _first_stopping_error(result.stage_errors)
    if abort_error is not None:
        typer.echo(f"Error: {abort_error}", err=True)
        raise typer.Exit(code=1)

"""CLI entry point for asago-scenario-generator."""

from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml

app = typer.Typer(
    name="asago-scenario-generator",
    help="LLM-driven red-teaming scenario generator for LLM and agentic AI systems.",
)

_VERSION = "0.1.0"


def _default_generate_exit_code(
    status: str,
    admitted: int,
) -> int:
    """Return the default nonzero outcome for degraded or empty runs."""
    return 1 if status == "completed_with_errors" or admitted == 0 else 0


def _resolve_use_case(value: str) -> str:
    """If value starts with @, read from the referenced file; otherwise return as-is."""
    if value.startswith("@"):
        file_path = Path(value[1:])
        if not file_path.exists():
            typer.echo(f"Error: use-case file not found: {file_path}", err=True)
            raise typer.Exit(code=1)
        return file_path.read_text(encoding="utf-8").strip()
    return value


def _validate_file(path: Path, label: str) -> None:
    if not path.exists():
        typer.echo(f"Error: {label} not found: {path}", err=True)
        raise typer.Exit(code=1)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """asago-scenario-generator: generate red-teaming scenarios for AI systems."""
    if ctx.invoked_subcommand is None:
        typer.echo(f"asago-scenario-generator v{_VERSION} — use --help for commands")


@app.command()
def generate(
    use_case: str = typer.Option(
        ...,
        help="Use-case description (or @file.txt to read from file).",
    ),
    risk_extraction: Path = typer.Option(
        ...,
        help="Path to policy-mapper risk-extraction.json.",
    ),
    sssom: Path = typer.Option(
        ...,
        help="Path to SSSOM TSV mapping file.",
    ),
    output_dir: Path = typer.Option(
        "output",
        help="Output collection directory for pipeline artifacts (each run creates a child directory).",
    ),
    cross_taxonomy: Path | None = typer.Option(
        None,
        help="Path to cross-taxonomy-mappings.yaml (defaults to bundled).",
    ),
    threats_path: Path | None = typer.Option(
        None,
        help="Path to OWASP agentic threats YAML (defaults to bundled).",
    ),
    profile_path: Path | None = typer.Option(
        None,
        "--profile",
        help="Path to a capability-profile.yaml (skips Stage 1 inference).",
    ),
    qualification_facts: Path | None = typer.Option(
        None,
        help="Path to explicit authoritative qualification fact readings YAML.",
    ),
    base_url: str | None = typer.Option(
        None,
        help="LLM endpoint base URL (overrides ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL).",
    ),
    api_key: str | None = typer.Option(
        None,
        help="LLM API key (overrides ASAGO_SCENARIO_GENERATOR_API_KEY).",
    ),
    model: str | None = typer.Option(
        None,
        help="LLM model name (overrides ASAGO_SCENARIO_GENERATOR_MODEL_NAME).",
    ),
    max_scenario_techniques: int = typer.Option(
        1,
        help="Max ATLAS techniques per candidate combo (1=single, 2=pairs+singles, etc.).",
    ),
    max_scenarios_per_pattern: int | None = typer.Option(
        None,
        help="Max scenarios per attack pattern. Caps popular patterns; prioritises entry-point diversity.",
    ),
    zones: str | None = typer.Option(
        None,
        help="Comma-separated zone filter (e.g. 'input,reasoning,tool_execution'). Overrides profile.",
    ),
    eval: bool = typer.Option(
        True,
        "--eval/--no-eval",
        help="Run deterministic eval metrics after generation (default: enabled).",
    ),
    log_level: str = typer.Option(
        "INFO",
        help="Log level for console output.",
        case_sensitive=False,
    ),
    structured: bool = typer.Option(
        False,
        help="Use JSON-lines format for the log file.",
    ),
) -> None:
    """Run the full scenario generation pipeline (stages 1-4)."""
    from asago_scenario_generator.log_config import setup_logging

    # Console-only logging until the run directory is resolved
    setup_logging(log_level=log_level)
    typer.echo(f"\nasago-scenario-generator v{_VERSION} — generate\n{'=' * 40}")

    use_case_text = _resolve_use_case(use_case)
    _validate_file(risk_extraction, "risk-extraction file")
    _validate_file(sssom, "SSSOM file")
    if cross_taxonomy is not None:
        _validate_file(cross_taxonomy, "cross-taxonomy file")
    if threats_path is not None:
        _validate_file(threats_path, "agentic threats file")
    if profile_path is not None:
        _validate_file(profile_path, "capability profile file")
    if qualification_facts is not None:
        _validate_file(qualification_facts, "qualification facts file")

    outcome_exit_code = 1
    try:
        from asago_scenario_generator.pipeline.runner import run_pipeline

        result = run_pipeline(
            use_case=use_case_text,
            risk_extraction_path=risk_extraction,
            sssom_path=sssom,
            output_dir=output_dir,
            cross_taxonomy_path=cross_taxonomy,
            threats_path=threats_path,
            profile_path=profile_path,
            qualification_facts_path=qualification_facts,
            base_url=base_url,
            api_key=api_key,
            model=model,
            max_techniques=max_scenario_techniques,
            max_scenarios_per_pattern=max_scenarios_per_pattern,
            zones=zones,
            eval=eval,
            log_level=log_level,
            structured=structured,
        )

        status = result.manifest_status.value
        outcome_exit_code = _default_generate_exit_code(status, result.admitted_count)
        typer.echo(
            "\nPipeline complete."
            if outcome_exit_code == 0
            else "\nPipeline completed with errors."
        )
        typer.echo(f"  Manifest status:      {status}")
        typer.echo(f"  Candidates admitted:  {result.admitted_count}")
        typer.echo(f"  Candidates quarantined: {result.quarantined_count}")
        typer.echo(f"  Candidates failed:     {result.failed_count}")
        typer.echo(
            f"  Scenarios generated: {len(result.scenarios)}/{len(result.seeds)}"
        )
        typer.echo(f"  Governance-only:     {result.governance_only_count}")
        typer.echo(f"  Run directory:       {result.run_dir}")

    except Exception as exc:
        msg = f"\nError: {exc}"
        if exc.__cause__:
            msg += f"\n  Caused by: {exc.__cause__}"
        typer.echo(msg, err=True)
        raise typer.Exit(code=1)
    if outcome_exit_code:
        raise typer.Exit(code=outcome_exit_code)


@app.command()
def resume(
    run_dir: Path = typer.Argument(..., help="Exact v3 STARTED run directory."),
    base_url: str | None = typer.Option(None),
    api_key: str | None = typer.Option(None),
    model: str | None = typer.Option(None),
    log_level: str = typer.Option("INFO", case_sensitive=False),
    structured: bool = typer.Option(False),
) -> None:
    """Resume an interrupted manifest-v3 run in the same directory."""
    from asago_scenario_generator.log_config import setup_logging

    setup_logging(log_level=log_level)
    try:
        from asago_scenario_generator.pipeline.runner import resume_pipeline

        result = resume_pipeline(
            run_dir,
            base_url=base_url,
            api_key=api_key,
            model=model,
            log_level=log_level,
            structured=structured,
        )
        typer.echo(f"\nPipeline resumed: {result.run_id}")
        typer.echo(f"  Run directory: {result.run_dir}")
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        typer.echo(f"\nError: {exc}", err=True)
        raise typer.Exit(code=1)


@app.command()
def report(
    output_dir: Path = typer.Option(
        "output",
        help="Run directory (or collection) containing pipeline artifacts.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write report HTML to this path (default: stdout). "
        "Must be outside the run directory.",
    ),
    allow_non_authoritative: bool = typer.Option(
        False,
        "--allow-non-authoritative",
        help="Allow reading non-completed (non-authoritative) runs for forensic analysis.",
    ),
    log_level: str = typer.Option(
        "INFO",
        help="Log level for console output.",
        case_sensitive=False,
    ),
    structured: bool = typer.Option(
        False,
        help="Use JSON-lines format for the log file.",
    ),
) -> None:
    """Generate an HTML report from pipeline output.

    Requires an authoritative (``completed``) run by default.
    The report is emitted to stdout or *output* (which must be outside
    the run directory — finalized runs are immutable).
    """
    from asago_scenario_generator.log_config import setup_logging

    setup_logging(log_level=log_level, output_dir=None)
    typer.echo(f"\nasago-scenario-generator v{_VERSION} — report\n{'=' * 40}")

    if not output_dir.exists():
        typer.echo(f"Error: directory not found: {output_dir}", err=True)
        raise typer.Exit(code=1)

    try:
        from asago_scenario_generator.manifest import find_run_dir
        from asago_scenario_generator.report.data import load_report_data
        from asago_scenario_generator.report.generator import generate_report

        actual_run_dir = find_run_dir(output_dir)
        report_data = load_report_data(
            actual_run_dir, allow_non_authoritative=allow_non_authoritative
        )

        if output is not None:
            # Reject destination inside the run directory (immutable)
            output_resolved = output.resolve()
            run_resolved = actual_run_dir.resolve()
            try:
                output_resolved.relative_to(run_resolved)
                typer.echo(
                    f"Error: output path {output} is inside the immutable run "
                    f"directory {actual_run_dir}. Choose a destination outside.",
                    err=True,
                )
                raise typer.Exit(code=1)
            except ValueError:
                pass  # output is outside — OK
            output.parent.mkdir(parents=True, exist_ok=True)
            report_path = generate_report(report_data, output.parent)
            # generate_report writes to <parent>/report.html; rename if needed
            if report_path.name != output.name:
                report_path = report_path.rename(output)
            typer.echo(f"\nReport written to {report_path}")
        else:
            # Emit to stdout
            import tempfile

            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                generate_report(report_data, tmp_path)
                typer.echo((tmp_path / "report.html").read_text(encoding="utf-8"))

    except Exception as exc:
        msg = f"\nError: {exc}"
        if exc.__cause__:
            msg += f"\n  Caused by: {exc.__cause__}"
        typer.echo(msg, err=True)
        raise typer.Exit(code=1)


@app.command()
def profile(
    use_case: str = typer.Option(
        ...,
        help="Use-case description (or @file.txt to read from file).",
    ),
    output: Path | None = typer.Option(
        None,
        help="Write profile YAML to this file (default: stdout).",
    ),
    base_url: str | None = typer.Option(
        None,
        help="LLM endpoint base URL (overrides ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL).",
    ),
    api_key: str | None = typer.Option(
        None,
        help="LLM API key (overrides ASAGO_SCENARIO_GENERATOR_API_KEY).",
    ),
    model: str | None = typer.Option(
        None,
        help="LLM model name (overrides ASAGO_SCENARIO_GENERATOR_MODEL_NAME).",
    ),
    log_level: str = typer.Option(
        "INFO",
        help="Log level for console output.",
        case_sensitive=False,
    ),
    structured: bool = typer.Option(
        False,
        help="Use JSON-lines format for the log file.",
    ),
) -> None:
    """Infer a capability profile from a use-case description (stage 1 only)."""
    from asago_scenario_generator.log_config import setup_logging

    profile_dir = output.parent if output is not None else None
    setup_logging(log_level=log_level, output_dir=profile_dir, structured=structured)
    typer.echo(f"\nasago-scenario-generator v{_VERSION} — profile\n{'=' * 40}")

    use_case_text = _resolve_use_case(use_case)

    try:
        from asago_scenario_generator.pipeline.runner import run_profile_only

        cap_profile, llm_result = run_profile_only(
            use_case=use_case_text,
            base_url=base_url,
            api_key=api_key,
            model=model,
        )

        profile_yaml = yaml.dump(
            cap_profile.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(profile_yaml, encoding="utf-8")
            typer.echo(f"\nProfile written to {output}")
        else:
            typer.echo("")
            typer.echo(profile_yaml)

        typer.echo(
            f"  LLM tokens: {llm_result.prompt_tokens} prompt"
            f" + {llm_result.completion_tokens} completion"
            f" ({llm_result.duration_ms}ms)"
        )

    except Exception as exc:
        msg = f"\nError: {exc}"
        if exc.__cause__:
            msg += f"\n  Caused by: {exc.__cause__}"
        typer.echo(msg, err=True)
        raise typer.Exit(code=1)


@app.command(name="qualify-catalog")
def qualify_catalog(
    matrix: Path = typer.Argument(..., help="Reviewed qualification matrix YAML."),
    campaign: Path | None = typer.Option(None, help="Optional campaign manifest YAML."),
) -> None:
    """Preflight a catalog matrix or aggregate an explicit read-only campaign."""
    try:
        from asago_scenario_generator.catalog_qualification import (
            aggregate_campaign,
            preflight_matrix,
        )

        report = (
            aggregate_campaign(matrix, campaign)
            if campaign is not None
            else preflight_matrix(matrix)
        )
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)


@app.command(name="validate-catalog-qualification")
def validate_catalog_qualification(
    artifact: Path = typer.Argument(..., help="Persisted matrix, campaign, or report."),
    contract: str = typer.Option(
        ..., help="Contract type: matrix, campaign, or report."
    ),
) -> None:
    """Validate one persisted qualification contract without executing a campaign."""
    if contract not in {"matrix", "campaign", "report"}:
        typer.echo("Error: contract must be matrix, campaign, or report", err=True)
        raise typer.Exit(code=1)
    try:
        from asago_scenario_generator.catalog_qualification import (
            validate_persisted_contract,
        )

        validated = validate_persisted_contract(artifact, contract)  # type: ignore[arg-type]
        typer.echo(json.dumps(validated.model_dump(mode="json"), indent=2))
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)


@app.command(name="eval")
def eval_cmd(
    output_dir: Path = typer.Option(
        ...,
        help="Run directory (or collection) containing pipeline artifacts.",
    ),
    format: str = typer.Option(
        "yaml",
        help="Output format: yaml or json.",
    ),
    allow_non_authoritative: bool = typer.Option(
        False,
        "--allow-non-authoritative",
        help="Allow reading non-completed (non-authoritative) runs for forensic analysis.",
    ),
    log_level: str = typer.Option(
        "INFO",
        help="Log level for console output.",
        case_sensitive=False,
    ),
    structured: bool = typer.Option(
        False,
        help="Use JSON-lines format for the log file.",
    ),
) -> None:
    """Evaluate generated scenario quality (Tier 1: deterministic metrics).

    Requires an authoritative (``completed``) run by default.
    The scorecard is emitted to stdout — finalized runs are immutable
    and must not be written to.
    """
    from asago_scenario_generator.log_config import setup_logging

    setup_logging(log_level=log_level, output_dir=None)
    typer.echo(f"\nasago-scenario-generator v{_VERSION} — eval\n{'=' * 40}")

    if not output_dir.exists():
        typer.echo(f"Error: directory not found: {output_dir}", err=True)
        raise typer.Exit(code=1)

    try:
        from asago_scenario_generator.eval.runner import run_evaluation

        scorecard = run_evaluation(
            output_dir, allow_non_authoritative=allow_non_authoritative
        )

        if format.lower() == "json":
            output_text = json.dumps(scorecard, indent=2, default=str)
        else:
            output_text = yaml.dump(
                scorecard,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )

        typer.echo("")
        typer.echo(output_text)

    except Exception as exc:
        msg = f"\nError: {exc}"
        if exc.__cause__:
            msg += f"\n  Caused by: {exc.__cause__}"
        typer.echo(msg, err=True)
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

    try:
        if not output_dir.exists():
            typer.echo(f"Error: output directory not found: {output_dir}", err=True)
            raise typer.Exit(code=1)

        result_path = generate_report(output_dir, output)
        typer.echo(f"STPA report written to: {result_path}")

    except Exception as exc:
        msg = f"\nError: {exc}"
        if exc.__cause__:
            msg += f"\n  Caused by: {exc.__cause__}"
        typer.echo(msg, err=True)
        raise typer.Exit(code=1)


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
        )
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    # Abort-level errors (missing critical artifacts) stop the pipeline
    # early.  Degrade-level errors (stage_errors from individual stages
    # that still produced artifacts) allow the pipeline to continue and
    # exit with code 0.
    abort_errors = [e for e in result.stage_errors if "stopping pipeline" in e]
    if abort_errors:
        typer.echo(f"Error: {abort_errors[0]}", err=True)
        raise typer.Exit(code=1)

"""Pipeline run commands: generate, resume, and profile inference."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
import yaml

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import (
    _abort,
    _default_generate_exit_code,
    _print_banner,
    _resolve_use_case,
    _validate_file,
)


def _validate_optional_inputs(
    *,
    cross_taxonomy: Path | None,
    threats_path: Path | None,
    profile_path: Path | None,
    qualification_facts: Path | None,
    model_profile: str | None,
    profiles_file: Path,
) -> None:
    """Validate optional generate inputs that were supplied."""
    for path, label in (
        (cross_taxonomy, "cross-taxonomy file"),
        (threats_path, "agentic threats file"),
        (profile_path, "capability profile file"),
        (qualification_facts, "qualification facts file"),
    ):
        if path is not None:
            _validate_file(path, label)
    if model_profile is not None:
        _validate_file(profiles_file, "model profiles file")


def _validate_generate_enums(presentation_fallback: str, generation_mode: str) -> None:
    """Reject unsupported generate option values."""
    if presentation_fallback not in {"allow", "forbid"}:
        raise typer.BadParameter(
            "must be 'allow' or 'forbid'", param_hint="--presentation-fallback"
        )
    if generation_mode not in {"exhaustive", "coverage"}:
        raise typer.BadParameter(
            "must be 'exhaustive' or 'coverage'", param_hint="--generation-mode"
        )


def _print_pipeline_summary(result: Any) -> int:
    """Echo the pipeline outcome summary; return the outcome exit code."""
    status = result.manifest_status.value
    exit_code = _default_generate_exit_code(status, result.admitted_count)
    typer.echo(
        "\nPipeline complete."
        if exit_code == 0
        else "\nPipeline completed with errors."
    )
    typer.echo(f"  Manifest status:      {status}")
    typer.echo(f"  Candidates admitted:  {result.admitted_count}")
    typer.echo(f"  Candidates quarantined: {result.quarantined_count}")
    typer.echo(f"  Candidates failed:     {result.failed_count}")
    typer.echo(f"  Scenarios generated: {len(result.scenarios)}/{len(result.seeds)}")
    typer.echo(f"  Governance-only:     {result.governance_only_count}")
    typer.echo(f"  Run directory:       {result.run_dir}")
    return exit_code


def _dump_profile_yaml(cap_profile: Any) -> str:
    """Render a capability profile object as YAML text."""
    return yaml.dump(
        cap_profile.model_dump(mode="json"),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


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
    model_profile: str | None = typer.Option(
        None,
        help="Named model profile; explicit endpoint/model/key options override it.",
    ),
    profiles_file: Path = typer.Option(
        "config/model-profiles.yaml",
        help="Path to model profiles YAML file.",
    ),
    presentation_fallback: str = typer.Option(
        "allow",
        help="Cosmetic fallback policy: allow or forbid.",
    ),
    max_scenario_techniques: int = typer.Option(
        1,
        help="Max ATLAS techniques per candidate combo (1=single, 2=pairs+singles, etc.).",
    ),
    max_scenarios_per_pattern: int | None = typer.Option(
        None,
        help="Max scenarios per attack pattern. Caps popular patterns; prioritises entry-point diversity.",
    ),
    generation_mode: str = typer.Option(
        "exhaustive",
        "--generation-mode",
        help="Generation policy: exhaustive (all qualified candidates) or coverage (bounded smoke run).",
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
    _print_banner("generate")

    use_case_text = _resolve_use_case(use_case)
    _validate_file(risk_extraction, "risk-extraction file")
    _validate_file(sssom, "SSSOM file")
    _validate_optional_inputs(
        cross_taxonomy=cross_taxonomy,
        threats_path=threats_path,
        profile_path=profile_path,
        qualification_facts=qualification_facts,
        model_profile=model_profile,
        profiles_file=profiles_file,
    )
    _validate_generate_enums(presentation_fallback, generation_mode)

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
            model_profile=model_profile,
            profiles_file=profiles_file,
            presentation_fallback=presentation_fallback,
            max_techniques=max_scenario_techniques,
            max_scenarios_per_pattern=max_scenarios_per_pattern,
            generation_mode=generation_mode,
            zones=zones,
            eval=eval,
            log_level=log_level,
            structured=structured,
        )

        outcome_exit_code = _print_pipeline_summary(result)

    except Exception as exc:
        _abort(exc)
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
        _abort(exc)


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
    _print_banner("profile")

    use_case_text = _resolve_use_case(use_case)

    try:
        from asago_scenario_generator.pipeline.runner import run_profile_only

        cap_profile, llm_result = run_profile_only(
            use_case=use_case_text,
            base_url=base_url,
            api_key=api_key,
            model=model,
        )

        profile_yaml = _dump_profile_yaml(cap_profile)

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
        _abort(exc)

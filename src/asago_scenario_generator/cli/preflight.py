"""Offline projection-preflight command."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import (
    _abort,
    _resolve_use_case,
    _validate_file,
)


def _validate_inputs(
    risk_extraction: Path,
    sssom: Path,
    profile: Path,
    qualification_facts: Path | None,
    cross_taxonomy: Path | None,
    threats_path: Path | None,
) -> None:
    """Validate projection-preflight input paths, required and optional."""
    for path, label in (
        (risk_extraction, "risk-extraction file"),
        (sssom, "SSSOM file"),
        (profile, "capability profile file"),
    ):
        _validate_file(path, label)
    for path, label in (
        (qualification_facts, "qualification facts file"),
        (cross_taxonomy, "cross-taxonomy file"),
        (threats_path, "agentic threats file"),
    ):
        if path is not None:
            _validate_file(path, label)


@app.command(name="projection-preflight")
def projection_preflight(
    use_case: str = typer.Option(
        ..., help="Use-case description (or @file.txt to read from file)."
    ),
    risk_extraction: Path = typer.Option(...),
    sssom: Path = typer.Option(...),
    profile: Path = typer.Option(..., help="Reviewed capability-profile YAML."),
    qualification_facts: Path | None = typer.Option(None),
    cross_taxonomy: Path | None = typer.Option(None),
    threats_path: Path | None = typer.Option(None),
    facts_template: Path | None = typer.Option(
        None,
        help="Write a complete unknown-valued facts template; never overwrites.",
    ),
    max_scenario_techniques: int = typer.Option(1),
) -> None:
    """Report projection requirements without contacting an LLM endpoint."""
    from asago_scenario_generator.pipeline.preflight import (
        run_projection_preflight,
        write_facts_template,
    )

    _validate_inputs(
        risk_extraction,
        sssom,
        profile,
        qualification_facts,
        cross_taxonomy,
        threats_path,
    )

    try:
        outcome = run_projection_preflight(
            use_case=_resolve_use_case(use_case),
            risk_extraction_path=risk_extraction,
            sssom_path=sssom,
            profile_path=profile,
            qualification_facts_path=qualification_facts,
            cross_taxonomy_path=cross_taxonomy,
            threats_path=threats_path,
            max_techniques=max_scenario_techniques,
        )
        if facts_template is not None:
            write_facts_template(outcome, facts_template)
        typer.echo(json.dumps(outcome.model_dump(mode="json"), indent=2))
    except Exception as exc:
        _abort(exc)

"""Catalog qualification commands: qualify-catalog and its validation."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import _abort


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
        _abort(exc)


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
        _abort(exc)

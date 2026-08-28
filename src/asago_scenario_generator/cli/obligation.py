"""Thin file adapter for the authoritative taxonomy obligation planner."""

from __future__ import annotations

from pathlib import Path

import typer

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import (
    _abort,
    _load_payload,
    _print_banner,
    _validate_file,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.obligation_contracts import (
    TaxonomyObligationInputs,
)
from asago_scenario_generator.pipeline.obligation_persistence import (
    write_taxonomy_obligation_plan,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)


def run_plan_obligations(
    snapshot_path: Path,
    output_dir: Path,
    format_name: str = "yaml",
) -> tuple[TaxonomyObligationPlan, list[Path]]:
    """Load complete typed inputs, plan, and publish one validated YAML artifact."""
    _validate_file(snapshot_path, "obligation inputs")
    if format_name.lower() != "yaml":
        raise ValueError(
            "Phase 1 persistence publishes only taxonomy-obligation-plan.yaml"
        )
    payload = _load_payload(snapshot_path, "obligation inputs")
    inputs = TaxonomyObligationInputs.model_validate(payload)
    plan = plan_taxonomy_obligations(inputs)
    return plan, [write_taxonomy_obligation_plan(output_dir, plan)]


@app.command(name="plan-obligations")
def plan_obligations_cmd(
    snapshot: Path = typer.Option(
        ...,
        help="Complete typed taxonomy-obligation input JSON or YAML file.",
    ),
    output_dir: Path = typer.Option(
        ...,
        help="Directory for the published YAML plan artifact.",
    ),
    format: str = typer.Option(
        "yaml",
        "--format",
        help="Published artifact format (only yaml is supported).",
    ),
) -> None:
    """Publish a deterministic obligation plan from complete typed inputs."""
    _print_banner("plan-obligations")
    try:
        plan, written = run_plan_obligations(snapshot, output_dir, format)
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        _abort(exc)
    for path in written:
        typer.echo(f"Obligation plan written to {path}")
    typer.echo(f"  Obligations:   {len(plan.obligations)}")
    typer.echo("  Network calls: 0")
    typer.echo("  Model calls:   0")

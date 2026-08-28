"""Offline file-to-file taxonomy obligation planner command."""

from __future__ import annotations

from pathlib import Path

import typer

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import (
    _abort,
    _load_payload,
    _print_banner,
    _requested_formats,
    _validate_file,
)
from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan


def run_plan_obligations(
    snapshot_path: Path,
    output_dir: Path,
    format_name: str = "both",
) -> tuple[TaxonomyObligationPlan, list[Path]]:
    """Publish a deterministic obligation plan from a snapshot file."""
    from asago_scenario_generator.pipeline.obligation_planner import plan_obligations

    _validate_file(snapshot_path, "obligation snapshot")
    formats = _requested_formats(format_name)
    plan = plan_obligations(_load_payload(snapshot_path, "obligation snapshot"))
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "yaml" in formats:
        path = output_dir / "taxonomy-obligation-plan.yaml"
        atomic_write_text(path, plan.to_yaml())
        written.append(path)
    if "json" in formats:
        path = output_dir / "taxonomy-obligation-plan.json"
        atomic_write_text(path, plan.to_json())
        written.append(path)
    return plan, written


@app.command(name="plan-obligations")
def plan_obligations_cmd(
    snapshot: Path = typer.Option(
        ...,
        help="Pinned taxonomy obligation snapshot JSON or YAML file.",
    ),
    output_dir: Path = typer.Option(
        ...,
        help="Directory for published YAML and JSON plan artifacts.",
    ),
    format: str = typer.Option(
        "both",
        "--format",
        help="Published artifact format: yaml, json, or both.",
    ),
) -> None:
    """Publish a deterministic obligation plan from a pinned snapshot.

    This is a file-to-file user-interface affordance. It is not generate
    or stpa-run and it makes no network or model calls.
    """
    _print_banner("plan-obligations")
    try:
        plan, written = run_plan_obligations(snapshot, output_dir, format)
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        _abort(exc)
    for path in written:
        typer.echo(f"Obligation plan written to {path}")
    typer.echo(f"  Obligations:   {len(plan.obligations)}")
    typer.echo(f"  Network calls: {plan.network_calls}")
    typer.echo(f"  Model calls:   {plan.model_calls}")

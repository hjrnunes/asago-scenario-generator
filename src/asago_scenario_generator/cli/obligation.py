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
    from asago_scenario_generator.pipeline.obligation_planner import plan_obligations

    _print_banner("plan-obligations")
    _validate_file(snapshot, "obligation snapshot")
    formats = _requested_formats(format)
    try:
        plan = plan_obligations(_load_payload(snapshot, "obligation snapshot"))
        output_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        if "yaml" in formats:
            path = output_dir / "obligation-plan.yaml"
            path.write_text(plan.to_yaml(), encoding="utf-8")
            written.append(path)
        if "json" in formats:
            path = output_dir / "obligation-plan.json"
            path.write_text(plan.to_json(), encoding="utf-8")
            written.append(path)
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        _abort(exc)
    for path in written:
        typer.echo(f"Obligation plan written to {path}")
    typer.echo(f"  Obligations:   {len(plan.obligations)}")
    typer.echo(f"  Network calls: {plan.network_calls}")
    typer.echo(f"  Model calls:   {plan.model_calls}")

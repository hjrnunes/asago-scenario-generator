"""CLI adapter for the offline run-output visualizer."""

from __future__ import annotations

from pathlib import Path

import typer

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import _abort, _print_banner


@app.command(name="render-run")
def render_run_cmd(
    run_dir: Path = typer.Option(
        ...,
        "--run-dir",
        help="Existing run output directory containing the run artifacts.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Output HTML path (default: <run-dir>/run-visual.html).",
    ),
    max_raw_file_bytes: int = typer.Option(
        256_000,
        "--max-raw-file-bytes",
        help=(
            "Truncate raw-artifact viewer entries beyond this many bytes "
            "(0 keeps every byte)."
        ),
    ),
) -> None:
    """Render a completed run directory into one self-contained HTML file."""
    _print_banner("render-run")
    if not run_dir.is_dir():
        typer.echo(f"Error: run directory not found: {run_dir}", err=True)
        raise typer.Exit(code=1)
    if max_raw_file_bytes < 0:
        raise typer.BadParameter(
            "must be zero or positive", param_hint="--max-raw-file-bytes"
        )
    try:
        from asago_scenario_generator.report.run_visualizer import render_run_visual

        result = render_run_visual(
            run_dir,
            output,
            max_raw_file_bytes=max_raw_file_bytes or None,
        )
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _abort(exc)
    typer.echo(f"Run visualization written to: {result}")


__all__ = ["render_run_cmd"]

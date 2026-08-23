"""Run reporting commands: report and eval."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from pathlib import Path

import typer
import yaml

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import _abort, _print_banner


def _write_report_artifact(
    generator: Callable, report_data: object, output: Path
) -> Path:
    """Generate the report HTML into *output*'s parent, creating it if needed."""
    output.parent.mkdir(parents=True, exist_ok=True)
    report_path = generator(report_data, output.parent)
    # generate_report writes to <parent>/report.html; rename if needed
    if report_path.name != output.name:
        report_path = report_path.rename(output)
    return report_path


def _render_report_stdout(generator: Callable, report_data: object) -> str:
    """Render the report HTML to a string via a temporary directory."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        generator(report_data, tmp_path)
        return (tmp_path / "report.html").read_text(encoding="utf-8")


def _reject_output_inside_run_directory(output: Path, run_dir: Path) -> None:
    """Announce and reject an output destination inside the immutable run."""
    try:
        output.resolve().relative_to(run_dir.resolve())
    except ValueError:
        return  # output is outside — OK
    typer.echo(
        f"Error: output path {output} is inside the immutable run "
        f"directory {run_dir}. Choose a destination outside.",
        err=True,
    )
    raise typer.Exit(code=1)


def _render_scorecard(scorecard: object, format: str) -> str:
    """Render an eval scorecard in the requested format."""
    if format.lower() == "json":
        return json.dumps(scorecard, indent=2, default=str)
    return yaml.dump(
        scorecard,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


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
    _print_banner("report")

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
            _reject_output_inside_run_directory(output, actual_run_dir)
            report_path = _write_report_artifact(generate_report, report_data, output)
            typer.echo(f"\nReport written to {report_path}")
        else:
            # Emit to stdout
            typer.echo(_render_report_stdout(generate_report, report_data))

    except typer.Exit:
        # A rejection raised inside the try already announced itself (e.g.
        # the immutable-run-directory check); let its exit code propagate
        # instead of folding it into the generic error handler below.
        raise
    except Exception as exc:
        _abort(exc)


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
    # The banner goes to stderr so stdout stays a single parseable scorecard.
    _print_banner("eval", err=True)

    if not output_dir.exists():
        typer.echo(f"Error: directory not found: {output_dir}", err=True)
        raise typer.Exit(code=1)

    try:
        from asago_scenario_generator.eval.runner import run_evaluation

        scorecard = run_evaluation(
            output_dir, allow_non_authoritative=allow_non_authoritative
        )

        typer.echo("")
        typer.echo(_render_scorecard(scorecard, format))

    except Exception as exc:
        _abort(exc)

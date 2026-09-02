"""Typer application shell for the asago-scenario-generator CLI."""

from __future__ import annotations

import typer

app = typer.Typer(
    name="asago-scenario-generator",
    help="STPA-led adversarial-scenario analysis for LLM and agentic AI systems.",
)

_VERSION = "0.1.0"


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """asago-scenario-generator: run STPA-led adversarial analysis."""
    if ctx.invoked_subcommand is None:
        typer.echo(f"asago-scenario-generator v{_VERSION} — use --help for commands")

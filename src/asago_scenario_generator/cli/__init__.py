"""Command-line interface for asago-scenario-generator.

The package root re-exports the Typer application; importing it loads the
command modules so every ``@app.command`` registration runs.
"""

from __future__ import annotations

from asago_scenario_generator.cli._app import _VERSION, app, main
from asago_scenario_generator.cli._shared import _default_generate_exit_code
from asago_scenario_generator.cli import (
    correspondence,
    generation,
    obligation,
    preflight,
    qualification,
    reporting,
    resource_map,
    synthesis,
    stpa_commands,
)

__all__ = (
    "_VERSION",
    "_default_generate_exit_code",
    "app",
    "main",
    "correspondence",
    "generation",
    "obligation",
    "preflight",
    "qualification",
    "reporting",
    "resource_map",
    "synthesis",
    "stpa_commands",
)

"""Public CLI contract for the STPA-only execution cutover."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from asago_scenario_generator.cli import app

runner = CliRunner()


def test_root_help_exposes_one_product_run_and_advanced_stpa() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "stpa-run" in result.stdout
    assert "synthesis-run" not in result.stdout
    assert "generate" not in result.stdout


@pytest.mark.parametrize(
    "command", ["generate", "resume", "synthesis-run", "report", "eval"]
)
def test_retired_execution_command_is_absent(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])

    assert result.exit_code != 0
    assert "No such command" in result.output


def test_run_owns_the_obligation_aware_synthesis_inputs() -> None:
    result = runner.invoke(app, ["run", "--help"])

    assert result.exit_code == 0
    for option in (
        "--use-case",
        "--risk-extraction",
        "--qualification-facts",
        "--output-dir",
        "--taxonomy-inputs",
        "--sssom",
        "--resume",
    ):
        assert option in result.stdout


def test_stpa_run_is_labelled_as_advanced_and_incomplete() -> None:
    result = runner.invoke(app, ["stpa-run", "--help"])

    assert result.exit_code == 0
    assert "advanced" in result.stdout.lower()
    assert "without taxonomy-obligation completeness" in result.stdout.lower()

"""Public CLI contract for the STPA-only execution cutover."""

from __future__ import annotations

import pytest
from tests.cli_helpers import PlainCliRunner

from asago_scenario_generator.cli import app

runner = PlainCliRunner()


def test_root_help_exposes_one_product_run() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "stpa-run" not in result.stdout
    assert "synthesis-run" not in result.stdout
    assert "generate" not in result.stdout


@pytest.mark.parametrize(
    "command",
    [
        "generate",
        "resume",
        "synthesis-run",
        "report",
        "eval",
        "stpa-run",
        "stpa-report",
        "validate-stpa-projection",
        "validate-stpa-execution-bundle",
    ],
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
        "--target-profile",
        "--basis",
        "--resume",
    ):
        assert option in result.stdout


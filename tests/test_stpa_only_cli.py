"""Public CLI contract for the STPA-only execution cutover."""

from __future__ import annotations

import pytest
from tests.cli_helpers import PlainCliRunner

from asago_scenario_generator.cli import app

runner = PlainCliRunner()


def test_root_help_exposes_one_product_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "generate" in result.stdout
    assert "stpa-run" not in result.stdout
    assert "synthesis-run" not in result.stdout


@pytest.mark.parametrize(
    "command",
    [
        "run",
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


def test_generate_owns_the_obligation_aware_synthesis_inputs() -> None:
    result = runner.invoke(app, ["generate", "--help"])

    assert result.exit_code == 0
    for option in (
        "--use-case",
        "--risk-extraction",
        "--qualification-facts",
        "--output-dir",
        "--sssom",
        "--target-profile",
        "--loss-analysis",
        "--max-workers",
        "--replay-calls",
    ):
        assert option in result.stdout


@pytest.mark.parametrize(
    "option",
    [
        "--taxonomy-inputs",
        "--cross-taxonomy",
        "--capability-profile",
        "--temperature",
        "--max-batch-size",
        "--resume",
        "--sp1-profile",
        "--sp2-profile",
        "--sp3-profile",
        "--basis",
        "--requested-environment-basis",
    ],
)
def test_generate_rejects_a_retired_option(option: str) -> None:
    result = runner.invoke(app, ["generate", option, "value"])

    assert result.exit_code != 0
    assert "No such option" in result.output

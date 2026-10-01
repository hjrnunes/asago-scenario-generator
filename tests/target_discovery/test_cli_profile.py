"""CLI wiring tests for optional profile-backed target interpretation."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.cli_helpers import PlainCliRunner

from asago_scenario_generator.target_discovery.cli import app


def _args(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "mcp",
        "--server-url",
        "http://127.0.0.1:8888/sse",
        "--target-id",
        "fixture-target",
        "--authorization-scope",
        "fixture-scope",
        "--output-dir",
        str(tmp_path),
        *extra,
    ]


def test_profile_option_constructs_interpreter_and_passes_it_to_discovery(
    tmp_path: Path,
):
    interpreter = object()
    adapter = object()
    result = SimpleNamespace(profile=object(), valid=True)
    with (
        patch(
            "asago_scenario_generator.target_discovery.cli.HttpMcpInventoryAdapter",
            return_value=adapter,
        ),
        patch(
            "asago_scenario_generator.target_discovery.cli.TargetDiscoveryLlmInterpreter.from_profile",
            return_value=interpreter,
        ) as from_profile,
        patch(
            "asago_scenario_generator.target_discovery.cli.discover_mcp_target",
            return_value=result,
        ) as discover,
        patch(
            "asago_scenario_generator.target_discovery.cli.write_target_discovery",
            return_value={},
        ),
    ):
        completed = PlainCliRunner().invoke(
            app,
            _args(
                tmp_path,
                "--profile",
                "fixture-profile",
                "--profiles-file",
                str(tmp_path / "profiles.yaml"),
                "--model-name",
                "fixture-model",
                "--interpretation-batch-size",
                "1",
            ),
        )

    assert completed.exit_code == 0, completed.output
    from_profile.assert_called_once_with(tmp_path / "profiles.yaml", "fixture-profile")
    assert discover.call_args.kwargs["interpreter_factory"] is interpreter
    assert discover.call_args.args[0].model_profile == "fixture-profile"
    assert discover.call_args.args[0].model_name == "fixture-model"
    assert discover.call_args.args[0].interpretation_batch_size == 1


def test_cli_exposes_interpretation_batch_size_option():
    completed = PlainCliRunner().invoke(app, ["mcp", "--help"])
    assert completed.exit_code == 0, completed.output
    assert "--interpretation-bat" in completed.output


def test_without_profile_does_not_construct_interpreter(tmp_path: Path):
    adapter = object()
    result = SimpleNamespace(profile=object(), valid=True)
    with (
        patch(
            "asago_scenario_generator.target_discovery.cli.HttpMcpInventoryAdapter",
            return_value=adapter,
        ),
        patch(
            "asago_scenario_generator.target_discovery.cli.TargetDiscoveryLlmInterpreter.from_profile",
        ) as from_profile,
        patch(
            "asago_scenario_generator.target_discovery.cli.discover_mcp_target",
            return_value=result,
        ) as discover,
        patch(
            "asago_scenario_generator.target_discovery.cli.write_target_discovery",
            return_value={},
        ),
    ):
        completed = PlainCliRunner().invoke(app, _args(tmp_path))

    assert completed.exit_code == 0, completed.output
    from_profile.assert_not_called()
    assert discover.call_args.kwargs["interpreter_factory"] is None

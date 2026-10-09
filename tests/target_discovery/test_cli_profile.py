"""CLI wiring tests for optional profile-backed target interpretation."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

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
    interpreter = SimpleNamespace(model_name="fixture-model")
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
                "--interpretation-batch-size",
                "1",
            ),
        )

    assert completed.exit_code == 0, completed.output
    from_profile.assert_called_once_with(
        tmp_path / "profiles.yaml", "fixture-profile", run_dir=tmp_path
    )
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


_CLI = "asago_scenario_generator.target_discovery.cli"


def _scan(tmp_path: Path, *extra: str, result=None, written=None, env=None):
    """Invoke the scanner with the transport, discovery, and writer replaced."""
    result = result or SimpleNamespace(profile=object(), valid=True)
    with (
        patch(f"{_CLI}.HttpMcpInventoryAdapter", return_value=object()) as adapter,
        patch(f"{_CLI}.discover_mcp_target", return_value=result) as discover,
        patch(f"{_CLI}.write_target_discovery", return_value=written or {}),
    ):
        completed = PlainCliRunner().invoke(app, _args(tmp_path, *extra), env=env)
    return completed, adapter, discover


@pytest.mark.parametrize("mode", ["bogus", "full", "disposable_test_environment"])
def test_any_mode_other_than_schema_only_is_a_usage_error(tmp_path: Path, mode):
    completed, adapter, discover = _scan(tmp_path, "--mode", mode)

    assert completed.exit_code == 2
    assert "only schema_only is supported" in completed.output
    adapter.assert_not_called()
    discover.assert_not_called()


def test_schema_only_mode_reaches_discovery(tmp_path: Path):
    completed, _adapter, discover = _scan(tmp_path, "--mode", "schema_only")

    assert completed.exit_code == 0, completed.output
    assert discover.call_args.args[0].mode.value == "schema_only"


@pytest.mark.parametrize(
    "flag",
    ["--inspect-tool", "--max-inspection-calls", "--auth-header-env", "--model-name"],
)
def test_removed_options_are_rejected(tmp_path: Path, flag):
    completed, _adapter, discover = _scan(tmp_path, flag, "value")

    assert completed.exit_code == 2
    assert "No such option" in completed.output
    discover.assert_not_called()


def test_timeout_reaches_the_adapter_without_headers(tmp_path: Path):
    completed, adapter, _discover = _scan(tmp_path, "--timeout", "5")

    assert completed.exit_code == 0, completed.output
    adapter.assert_called_once_with("http://127.0.0.1:8888/sse", timeout=5.0)


@pytest.mark.parametrize(
    "error", [OSError("no file"), ValueError("bad"), KeyError("x")]
)
def test_unloadable_profile_is_a_usage_error_naming_only_the_error_type(
    tmp_path: Path, error
):
    with patch(f"{_CLI}.TargetDiscoveryLlmInterpreter.from_profile", side_effect=error):
        completed, _adapter, discover = _scan(tmp_path, "--profile", "missing")

    assert completed.exit_code == 2
    assert (
        f"could not load named model profile ({type(error).__name__})"
        in completed.output
    )
    discover.assert_not_called()


def test_model_name_defaults_to_the_interpreter_identity(tmp_path: Path):
    interpreter = SimpleNamespace(model_name="interpreter-model")
    with patch(
        f"{_CLI}.TargetDiscoveryLlmInterpreter.from_profile", return_value=interpreter
    ):
        completed, _adapter, discover = _scan(tmp_path, "--profile", "fixture")

    assert completed.exit_code == 0, completed.output
    assert discover.call_args.args[0].model_name == "interpreter-model"


def test_model_name_stays_unset_when_the_interpreter_has_none(tmp_path: Path):
    with patch(
        f"{_CLI}.TargetDiscoveryLlmInterpreter.from_profile", return_value=object()
    ):
        completed, _adapter, discover = _scan(tmp_path, "--profile", "fixture")

    assert completed.exit_code == 0, completed.output
    assert discover.call_args.args[0].model_name is None


def test_written_artifacts_are_listed_by_file_name(tmp_path: Path):
    written = {
        "profile": tmp_path / "target-profile.yaml",
        "report": tmp_path / "report.json",
    }

    completed, _adapter, _discover = _scan(tmp_path, written=written)

    assert completed.exit_code == 0, completed.output
    assert completed.output.splitlines() == [
        f"target discovery wrote 2 artifact(s) to {tmp_path}",
        "target-profile.yaml",
        "report.json",
    ]


def test_missing_profile_exits_with_code_one(tmp_path: Path):
    completed, _adapter, _discover = _scan(
        tmp_path, result=SimpleNamespace(profile=None, valid=False)
    )

    assert completed.exit_code == 1


def test_invalid_profile_exits_with_code_two(tmp_path: Path):
    completed, _adapter, _discover = _scan(
        tmp_path, result=SimpleNamespace(profile=object(), valid=False)
    )

    assert completed.exit_code == 2

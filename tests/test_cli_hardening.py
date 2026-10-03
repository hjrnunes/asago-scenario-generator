"""Hardening tests for the retained STPA and preparation CLI surfaces."""

from __future__ import annotations

from pathlib import Path

from tests.cli_helpers import PlainCliRunner

from asago_scenario_generator.cli import _VERSION, app

runner = PlainCliRunner()


def _write(path: Path, text: str = "fixture") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_bare_invocation_prints_version_banner() -> None:
    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert (
        f"asago-scenario-generator v{_VERSION} — use --help for commands"
        in result.stdout
    )

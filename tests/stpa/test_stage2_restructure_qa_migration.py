from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
_SUITE = _PROJECT_ROOT / "acceptance" / "qa" / "stage2_decomposition.py"
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))

from qa_harness import child_env, run_command  # noqa: E402
from stage2_decomposition import Stage2QARunner  # noqa: E402


def _run_suite(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(_SUITE), *args],
        cwd=str(cwd or _PROJECT_ROOT),
        env=env or dict(os.environ),
        capture_output=True,
        text=True,
        check=False,
    )


def test_stage2_suite_uses_shared_harness_without_local_framework() -> None:
    tree = ast.parse(_SUITE.read_text(encoding="utf-8"), filename=str(_SUITE))
    imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    ]

    assert "qa_harness" in imports
    assert not any(
        isinstance(node, ast.ClassDef) and node.name in {"CheckResult", "QARunner"}
        for node in ast.walk(tree)
    )
    assert any(
        isinstance(node, ast.ClassDef) and node.name == "Stage2QARunner"
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "run"
        for node in ast.walk(tree)
    )


def test_stage2_cli_runs_static_checks_only() -> None:
    help_result = _run_suite("--help")
    assert help_result.returncode == 0
    assert "--static" in help_result.stdout
    for retired in ("--pipeline", "--all", "--use-case", "--risk-extraction"):
        assert retired not in help_result.stdout

    default = _run_suite()
    assert default.returncode == 0
    assert "=== Static checks (no LLM required) ===" in default.stdout
    assert "QA SUMMARY:" in default.stdout

    retired_mode = _run_suite("--pipeline")
    assert retired_mode.returncode == 2
    assert "unrecognized arguments: --pipeline" in retired_mode.stderr


def test_stage2_static_mode_preserves_check_order_and_banner_summary() -> None:
    result = _run_suite("--static")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    names = [line.split("] ", 1)[1] for line in lines]
    assert names == [
        "stage2-call2a: old stage2_call2_system.j2 is absent",
        "stage2-call2a: old stage2_call2_user.j2 is absent",
        "stage2-restructure: stage2_call2a_system.j2 is present",
        "stage2-restructure: stage2_call2a_user.j2 is present",
        "stage2-restructure: stage2_call2b_system.j2 is present",
        "stage2-restructure: stage2_call2b_user.j2 is present",
        "stage2-call2a: system prompt contains 'RC-X-Y'",
        "stage2-call2a: system prompt contains 'PM-X-Y'",
        "stage2-call2a: system prompt contains 'Do NOT copy PM entries as RCs'",
        "stage2-call2a: system prompt contains 'tool_execution'",
        "stage2-call2a: system prompt contains 'memory'",
        "stage2-call2a: system prompt contains 'hitl'",
        "stage2-call2a: system prompt contains 'inter_agent'",
        "stage2-call2a: system prompt does not contain 'Control Actions'",
        "stage2-call2a: system prompt does not contain 'Feedback Channels'",
        "stage2-call2a: user prompt contains 'capability_profile'",
        "stage2-call2a: user prompt contains 'zones_active'",
        "stage2-call2a: user prompt contains 'feedback_source null'",
        "stage2-call2b: system prompt contains 'at least one feedback channel'",
        "stage2-call2b: system prompt contains 'at least N feedback channels'",
        "stage2-call2b: user prompt contains 'responsibilities'",
        "stage2-call2b: user prompt contains 'responsibility_constraints'",
        "stage2-call2b: user prompt contains 'process_model_parts'",
        "stage2-call3: system prompt contains 'Deterministic code has already checked'",
        "stage2-call3: system prompt contains 'do not fix them here'",
        "stage2-call3: system prompt contains 'Do not return an'",
        "stage2-call3: system prompt does not contain 'connection_assignments'",
        "stage2-call3: system prompt does not contain 'ConnectionSet'",
        "stage2-call3: user prompt contains 'control_structure'",
        "stage2-call3: user prompt does not contain 'responsibility_set'",
        "stage2-assembly: call1 system prompt contains 'solution-neutral'",
        "stage2-assembly: call1 system prompt does not contain old blocklist instruction",
        "stage2-assembly: stage2_call1_system.j2 does not contain 'Poh'",
        "stage2-assembly: stage2_call1_system.j2 does not contain 'STPA-Sec'",
        "stage2-assembly: stage2_call2a_system.j2 does not contain 'Poh'",
        "stage2-assembly: stage2_call2a_system.j2 does not contain 'STPA-Sec'",
        "stage2-assembly: stage2_call2b_system.j2 does not contain 'Poh'",
        "stage2-assembly: stage2_call2b_system.j2 does not contain 'STPA-Sec'",
        "stage2-assembly: stage2_call3_system.j2 does not contain 'Poh'",
        "stage2-assembly: stage2_call3_system.j2 does not contain 'STPA-Sec'",
    ]
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert "QA SUMMARY: 40/40 passed, 0 failed" in result.stdout
    assert "ALL CHECKS PASSED" in result.stdout
    assert "QA suite:" not in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index("QA SUMMARY: 40/40 passed, 0 failed")
    assert first_check > summary


def test_stage2_adapter_defers_output_and_keeps_legacy_counts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = Stage2QARunner()
    runner.check("first", True)
    runner.check("second", False, "details")
    runner.skip("pipeline", "no endpoint")

    assert capsys.readouterr().out == ""
    assert runner.summary() == 1
    output = capsys.readouterr().out
    assert output.index("QA SUMMARY: 1/3 passed, 1 failed") < output.index(
        "[PASS] first"
    )
    assert output.index("[PASS] first") < output.index("[FAIL] second")
    assert output.index("[FAIL] second") < output.index("[SKIP] pipeline")
    assert "         details" in output
    assert "1 CHECK(S) FAILED" in output


def test_stage2_child_env_isolation_uses_shared_helper() -> None:
    parent = {"QA_PARENT_ONLY": "present", "KEEP": "yes"}
    isolated = child_env(parent, QA_PARENT_ONLY=None, CHILD="only")
    assert parent["QA_PARENT_ONLY"] == "present"
    assert "QA_PARENT_ONLY" not in isolated
    assert isolated["KEEP"] == "yes"
    assert isolated["CHILD"] == "only"


def test_stage2_run_command_defaults_to_project_root_from_nested_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)

    result = run_command(
        [sys.executable, "-c", "from pathlib import Path; print(Path.cwd())"]
    )

    assert result.returncode == 0
    assert result.stdout.strip() == str(_PROJECT_ROOT)
    assert Path.cwd() == nested

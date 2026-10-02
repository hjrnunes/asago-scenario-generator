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
_SUITE = _PROJECT_ROOT / "acceptance" / "qa" / "stage1_ordering.py"
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))

from qa_harness import child_env, run_command  # noqa: E402
from stage1_ordering import Stage1QARunner  # noqa: E402


def _run_suite(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(_SUITE), *args],
        cwd=str(cwd or _PROJECT_ROOT),
        env=env or dict(os.environ),
        capture_output=True,
        text=True,
        check=False,
    )


def test_stage1_suite_uses_shared_harness_without_local_framework() -> None:
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
        isinstance(node, ast.ClassDef) and node.name == "Stage1QARunner"
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


def test_stage1_cli_runs_static_checks_only() -> None:
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


def test_stage1_static_mode_preserves_check_order_and_banner_summary() -> None:
    result = _run_suite("--static")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    names = [line.split("] ", 1)[1] for line in lines]
    assert names == [
        "stage1a-split: old stage1a_system.j2 is absent",
        "stage1a-split: old stage1a_user.j2 is absent",
        "stage1a-split: stage1a_risk_system.j2 is present",
        "stage1a-split: stage1a_risk_user.j2 is present",
        "stage1a-split: stage1a_gap_system.j2 is present",
        "stage1a-split: stage1a_gap_user.j2 is present",
        "stage1b-revision: stage1b_system.j2 contains 'KC1 — Language Models'",
        "stage1b-revision: stage1b_system.j2 contains 'KC6 — Operational Environment'",
        "stage1b-revision: stage1b_system.j2 contains 'KCX — Extended Capabilities'",
        "stage1b-revision: stage1b_system.j2 does not contain 'STPA'",
        "stage1b-revision: stage1b_system.j2 does not request 'zones_active'",
        "stage1b-revision: stage1b_system.j2 does not contain 'User input surfaces'",
        "stage1b-revision: stage1b_system.j2 does not contain 'Entry point category checklist'",
        "stage1b-revision: stage1b_user.j2 does not contain 'loss_analysis'",
        "stage1b-revision: stage1b_user.j2 does not contain 'all_losses'",
        "stage1b-revision: stage1b_user.j2 does not contain 'security_constraints'",
        "stage1b-revision: Stage1Profile does not declare 'has_persistent_memory'",
        "stage1b-revision: Stage1Profile does not declare 'multi_agent'",
        "stage1b-revision: Stage1Profile does not declare 'hitl'",
    ]
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert "QA SUMMARY: 19/19 passed, 0 failed" in result.stdout
    assert "ALL CHECKS PASSED" in result.stdout
    assert "QA suite:" not in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index("QA SUMMARY: 19/19 passed, 0 failed")
    assert first_check > summary


def test_stage1_adapter_defers_output_and_keeps_legacy_counts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = Stage1QARunner()
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


def test_stage1_child_env_isolation_uses_shared_helper() -> None:
    parent = {"QA_PARENT_ONLY": "present", "KEEP": "yes"}
    isolated = child_env(parent, QA_PARENT_ONLY=None, CHILD="only")
    assert parent["QA_PARENT_ONLY"] == "present"
    assert "QA_PARENT_ONLY" not in isolated
    assert isolated["KEEP"] == "yes"
    assert isolated["CHILD"] == "only"


def test_stage1_run_command_defaults_to_project_root_from_nested_cwd(
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

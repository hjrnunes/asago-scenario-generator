from __future__ import annotations

import ast
import io
import os
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
_SUITE = _PROJECT_ROOT / "acceptance" / "qa" / "stage2_decomposition.py"
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))

from qa_harness import child_env, find_project_root, run_command  # noqa: E402
from stage2_decomposition import Stage2QARunner, _run_stpa_pipeline  # noqa: E402


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
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_command"
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


def test_stage2_cli_preserves_modes_and_invalid_invocations() -> None:
    help_result = _run_suite("--help")
    assert help_result.returncode == 0
    assert "--static" in help_result.stdout
    assert "--pipeline" in help_result.stdout
    assert "--all" in help_result.stdout
    assert "--use-case" in help_result.stdout
    assert "--risk-extraction" in help_result.stdout
    assert "--capability-profile" in help_result.stdout

    missing_mode = _run_suite()
    assert missing_mode.returncode == 2
    assert (
        "one of the arguments --static --pipeline --all is required"
        in missing_mode.stderr
    )
    assert "[PASS]" not in missing_mode.stdout
    assert "[FAIL]" not in missing_mode.stdout

    conflicting = _run_suite("--static", "--pipeline")
    assert conflicting.returncode == 2
    assert "not allowed with argument --static" in conflicting.stderr

    missing_inputs = _run_suite("--pipeline")
    assert missing_inputs.returncode == 1
    assert (
        "ERROR: --use-case and --risk-extraction required for pipeline checks"
        in missing_inputs.stdout
    )
    assert "QA SUMMARY:" not in missing_inputs.stdout

    all_missing = _run_suite("--all")
    assert all_missing.returncode == 1
    assert "=== Static checks (no LLM required) ===" in all_missing.stdout
    assert (
        "ERROR: --use-case and --risk-extraction required for pipeline checks"
        in all_missing.stdout
    )
    assert "QA SUMMARY:" not in all_missing.stdout


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


def test_stage2_pipeline_child_is_isolated_and_cleans_temp_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    seen: dict[str, object] = {}

    def fake_run_command(argv, *, cwd=None, env=None, timeout=None, input_text=None):
        seen["argv"] = list(argv)
        seen["cwd"] = Path(cwd) if cwd is not None else None
        seen["env"] = dict(env) if env is not None else None
        seen["timeout"] = timeout
        seen["input_text"] = input_text
        seen["parent_cwd"] = Path.cwd()
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("stage2_decomposition.run_command", fake_run_command)
    output_dir = tmp_path / "stage2-output"
    result = _run_stpa_pipeline(
        "use-case.txt",
        tmp_path / "risk.json",
        output_dir,
        tmp_path / "profile.yaml",
    )

    assert result.returncode == 0
    assert seen["argv"][:4] == ["uv", "run", "asago-scenario-generator", "stpa-run"]
    assert seen["argv"][seen["argv"].index("--output-dir") + 1] == str(output_dir)
    assert seen["argv"][seen["argv"].index("--capability-profile") + 1] == str(
        tmp_path / "profile.yaml"
    )
    assert seen["cwd"] == _PROJECT_ROOT
    assert seen["env"] is not None
    assert "QA_PARENT_ONLY" in seen["env"]
    assert seen["timeout"] == 600
    assert seen["input_text"] is None
    assert seen["parent_cwd"] == nested
    assert Path.cwd() == nested
    assert os.environ["QA_PARENT_ONLY"] == "present"
    assert find_project_root() == _PROJECT_ROOT


def test_stage2_pipeline_temp_dirs_are_removed_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    created: list[Path] = []

    def fake_run_command(argv, **_kwargs):
        output_dir = Path(argv[argv.index("--output-dir") + 1])
        created.append(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "calls.jsonl").write_text("{}\n", encoding="utf-8")
        return SimpleNamespace(returncode=3, stdout="", stderr="boom")

    monkeypatch.setattr("stage2_decomposition.run_command", fake_run_command)
    runner = Stage2QARunner()
    with redirect_stdout(io.StringIO()):
        from stage2_decomposition import run_pipeline_checks

        run_pipeline_checks(runner, "use-case.txt", tmp_path / "risk.json")

    assert created
    assert all(not path.exists() for path in created)
    assert [result.name for result in runner.results] == [
        "pipeline: stpa-run exits with code 0",
        "pipeline: stpa-run produced output artifacts",
    ]
    assert runner.results[0].passed is False
    assert runner.results[1].passed is False
    assert "boom" in runner.results[0].detail


def test_stage2_pipeline_error_uses_isolated_child_streams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run_command(argv, *, cwd=None, env=None, timeout=None, input_text=None):
        captured["argv"] = list(argv)
        captured["cwd"] = Path(cwd) if cwd is not None else None
        captured["env"] = dict(env) if env is not None else None
        captured["timeout"] = timeout
        captured["input_text"] = input_text
        return SimpleNamespace(returncode=7, stdout="child-out", stderr="child-err")

    monkeypatch.setattr("stage2_decomposition.run_command", fake_run_command)
    runner = Stage2QARunner()
    with redirect_stdout(io.StringIO()) as buffer:
        from stage2_decomposition import run_pipeline_checks

        run_pipeline_checks(
            runner,
            "use-case.txt",
            tmp_path / "risk.json",
            tmp_path / "profile.yaml",
        )

    assert buffer.getvalue() == ""
    assert captured["cwd"] == _PROJECT_ROOT
    assert captured["env"] is not None
    assert captured["timeout"] == 600
    assert captured["input_text"] is None
    assert runner.results[0].detail.startswith("exit code 7, stderr: child-err")
    assert "child-out" not in runner.results[0].detail


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

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
_SUITE = _PROJECT_ROOT / "acceptance" / "qa" / "sp3_prompt_revision.py"
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))

from qa_harness import CheckResult, child_env, find_project_root, run_command  # noqa: E402
from sp3_prompt_revision import SP3072oQARunner, _format_072o_result  # noqa: E402

_STATIC_CHECKS = [
    "SP3-072o-static-01: Stage 5 system template exists",
    "SP3-072o-static-01: Stage 5 user template exists",
    "SP3-072o-static-02: Stage 5 system prompt does not contain STPA-Sec",
    "SP3-072o-static-03: Stage 5 system prompt contains security analyst framing",
    "SP3-072o-static-04: Stage 5 system prompt contains task framing ('dual-BDI', 'scenario specification')",
    "SP3-072o-static-11: Stage 5 user template contains variable defender_bdi_yaml",
    "SP3-072o-static-11: Stage 5 user template contains variable ica_text",
    "SP3-072o-static-11: Stage 5 user template contains variable hazardous_context",
    "SP3-072o-static-11: Stage 5 user template contains variable loss_scenario",
    "SP3-072o-static-11: Stage 5 user template contains variable control_structure_yaml",
    "SP3-072o-static-11: Stage 5 user template contains variable target_resp_id",
    "SP3-072o-static-11: Stage 5 user template contains variable catalog_context",
    "SP3-072o-static-12: Stage 5 system template has no malformed Jinja placeholders",
    "SP3-072o-static-12: Stage 5 user template has no malformed Jinja placeholders",
]
_DYNAMIC_CHECKS = [
    "SP3-072o-dynamic-00: project imports without error",
    "SP3-072o-dynamic-01: all SP3 prompts render without error",
    "SP3-072o-dynamic-02: Stage 5 system rendered prompt has no unresolved {{ }}",
    "SP3-072o-dynamic-02: Stage 5 user rendered prompt has no unresolved {{ }}",
    "SP3-072o-dynamic-03: Stage 5 rendered system prompt has no STPA-Sec",
    "SP3-072o-dynamic-04: Stage 5 rendered system prompt has security analyst framing",
    "SP3-072o-dynamic-42: Stage 5 system prompt with STPA-Sec jargon fails terminology requirement",
    "SP3-072o-dynamic-43: vacuous Stage 5 system prompt (security analyst removed) fails framing requirement",
]


def _run_suite(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(_SUITE), *args],
        cwd=str(cwd or _PROJECT_ROOT),
        env=env or dict(os.environ),
        capture_output=True,
        text=True,
        check=False,
    )


def _check_names(output: str) -> list[str]:
    return [
        line.split("] ", 1)[1] for line in output.splitlines() if line.startswith("  [")
    ]


def test_072o_suite_uses_shared_harness_without_local_framework() -> None:
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
        isinstance(node, ast.ClassDef) and node.name == "SP3072oQARunner"
        for node in ast.walk(tree)
    )


def test_072o_cli_preserves_modes_and_invalid_invocations() -> None:
    help_result = _run_suite("--help")
    assert help_result.returncode == 0
    assert "--static" in help_result.stdout
    assert "--dynamic" in help_result.stdout
    assert "--all" in help_result.stdout
    for retired in ("--pipeline", "--use-case"):
        assert retired not in help_result.stdout

    unrecognized = _run_suite("--bogus")
    assert unrecognized.returncode == 2
    assert "unrecognized arguments: --bogus" in unrecognized.stderr
    assert "[PASS]" not in unrecognized.stdout
    assert "[FAIL]" not in unrecognized.stdout
    assert "QA SUMMARY:" not in unrecognized.stdout

    retired_mode = _run_suite("--pipeline")
    assert retired_mode.returncode == 2
    assert "unrecognized arguments: --pipeline" in retired_mode.stderr


def test_072o_static_mode_preserves_check_order_and_banner_summary() -> None:
    result = _run_suite("--static")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _STATIC_CHECKS
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert "--- Static checks (source text) ---" in result.stdout
    assert "--- Dynamic checks" not in result.stdout
    assert "QA SUMMARY: 14/14 passed, 0 failed" in result.stdout
    assert "ALL 14 CHECK(S) PASSED" in result.stdout
    assert "QA suite:" not in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index("QA SUMMARY: 14/14 passed, 0 failed")
    assert first_check > summary


def test_072o_dynamic_mode_preserves_check_order_and_banner_summary() -> None:
    result = _run_suite("--dynamic")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _DYNAMIC_CHECKS
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert (
        "--- Dynamic checks (import + render + deterministic builders) ---"
        in result.stdout
    )
    assert "--- Static checks" not in result.stdout
    assert "QA SUMMARY: 8/8 passed, 0 failed" in result.stdout
    assert "ALL 8 CHECK(S) PASSED" in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index("QA SUMMARY: 8/8 passed, 0 failed")
    assert first_check > summary


@pytest.mark.parametrize("args", [(), ("--all",)])
def test_072o_all_mode_preserves_default_and_explicit_check_order(
    args: tuple[str, ...],
) -> None:
    result = _run_suite(*args)
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _STATIC_CHECKS + _DYNAMIC_CHECKS
    assert [line[:8] for line in lines] == ["  [PASS]"] * 22
    assert result.stdout.index(
        "--- Static checks (source text) ---"
    ) < result.stdout.index(
        "--- Dynamic checks (import + render + deterministic builders) ---"
    )
    assert "QA SUMMARY: 22/22 passed, 0 failed" in result.stdout
    assert "ALL 22 CHECK(S) PASSED" in result.stdout
    assert "QA suite:" not in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index("QA SUMMARY: 22/22 passed, 0 failed")
    assert first_check > summary


def test_072o_static_and_dynamic_flags_are_combinable() -> None:
    result = _run_suite("--static", "--dynamic")
    assert result.returncode == 0
    assert _check_names(result.stdout) == _STATIC_CHECKS + _DYNAMIC_CHECKS
    assert "QA SUMMARY: 22/22 passed, 0 failed" in result.stdout
    assert "ALL 22 CHECK(S) PASSED" in result.stdout


def test_072o_adapter_defers_output_and_reports_failures(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = SP3072oQARunner()
    runner.check("first", True, "hidden on pass")
    runner.check("second", False, "details")

    assert capsys.readouterr().out == ""
    assert runner.summary() == 1
    output = capsys.readouterr().out
    assert output.index("QA SUMMARY: 1/2 passed, 1 failed") < output.index(
        "[PASS] first"
    )
    assert output.index("[PASS] first") < output.index("[FAIL] second")
    assert "hidden on pass" not in output
    assert "         details" in output
    assert "1 CHECK(S) FAILED" in output
    assert "QA suite:" not in output


def test_072o_result_formatter_hides_pass_details() -> None:
    passed = CheckResult("ok", True, "secret")
    failed = CheckResult("bad", False, "why")
    assert _format_072o_result(passed) == "  [PASS] ok"
    assert _format_072o_result(failed) == "  [FAIL] bad\n         why"


def test_072o_static_child_isolation_from_nested_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    parent_environment = dict(os.environ)
    isolated = child_env(parent_environment, QA_PARENT_ONLY=None, CHILD="only")

    result = _run_suite("--static", cwd=nested, env=isolated)

    assert result.returncode == 0
    assert "QA SUMMARY: 14/14 passed, 0 failed" in result.stdout
    assert Path.cwd() == nested
    assert os.environ["QA_PARENT_ONLY"] == "present"
    assert parent_environment["QA_PARENT_ONLY"] == "present"
    assert "QA_PARENT_ONLY" not in isolated
    assert isolated["CHILD"] == "only"
    assert find_project_root() == _PROJECT_ROOT


def test_072o_dynamic_child_isolation_from_nested_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    isolated = child_env(dict(os.environ), QA_PARENT_ONLY=None, CHILD="only")

    result = _run_suite("--dynamic", cwd=nested, env=isolated)

    assert result.returncode == 0
    assert "QA SUMMARY: 8/8 passed, 0 failed" in result.stdout
    assert Path.cwd() == nested
    assert os.environ["QA_PARENT_ONLY"] == "present"
    assert "QA_PARENT_ONLY" not in isolated
    assert isolated["CHILD"] == "only"


def test_072o_run_command_defaults_to_project_root_from_nested_cwd(
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

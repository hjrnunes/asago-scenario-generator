from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
_SUITE = _PROJECT_ROOT / "acceptance" / "qa" / "stage2_fallback.py"
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))

from qa_harness import child_env, find_project_root, run_command  # noqa: E402
from stage2_fallback import FallbackQARunner, _temporary_run_dir  # noqa: E402

_STATIC_CHECKS = [
    "fallback-fix-static-01: _assemble_with_fallback is defined",
    "fallback-fix-static-02: _assemble_with_fallback calls _enrich_responsibilities (assigns CAs/FBs before sanitization)",
    "fallback-fix-static-03: _enrich_responsibilities is called before fallback sanitization",
    "fallback-fix-static-04: enriched responsibilities reach the further-degraded strip tier",
    "fallback-fix-static-05: _enrich_responsibilities calls _assign_elements_to_responsibilities at least twice (CAs and FBs)",
    "fallback-fix-static-06: _sanitize_for_fallback is still called in the fallback helper",
    "fallback-fix-static-07: _strip_all_element_refs is still called in the fallback helper",
    "fallback-fix-static-08: _sanitize_for_fallback does not receive raw responsibility_set.responsibilities",
    "fallback-fix-static-09: _strip_all_element_refs does not receive raw responsibility_set.responsibilities",
    "fallback-fix-static-10: feature file contains Sanitize-11 strip-tier carry-over scenario",
]
_DYNAMIC_CHECKS = [
    "fallback-fix-dynamic-01: all acceptance scenarios pass (Sanitize-01 through Sanitize-11)",
    "fallback-fix-dynamic-02: sanitize tier carries over CA-1-1 from ControlElementSet",
    "fallback-fix-dynamic-03: sanitize tier preserves valid CA target (CP-1)",
    "fallback-fix-dynamic-04: sanitize tier carries over FB-1-1 from ControlElementSet",
    "fallback-fix-dynamic-05: sanitize tier nullifies invalid FB source (RESP-99 → None)",
    "fallback-fix-dynamic-06: sanitize tier logs strip warning for FB-1-1 source",
    "fallback-fix-dynamic-07: strip tier deduplicates responsibilities",
    "fallback-fix-dynamic-08: strip tier carries over CA-1-1 from ControlElementSet",
    "fallback-fix-dynamic-09: strip tier strips CA-1-1 target to None",
    "fallback-fix-dynamic-10: strip tier carries over FB-1-1 from ControlElementSet",
    "fallback-fix-dynamic-11: strip tier strips FB-1-1 source to None",
]


def _run_suite(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None):
    with tempfile.TemporaryDirectory(prefix="fallback-acceptance-ir-") as directory:
        feature_ir = Path(directory) / "fixture.json"
        feature_ir.write_text(
            json.dumps(
                {
                    "name": "Fallback acceptance fixture",
                    "background": [],
                    "scenarios": [
                        {
                            "name": "deterministic runtime",
                            "steps": [
                                {
                                    "keyword": "Given",
                                    "text": "the quality script is invoked",
                                }
                            ],
                            "examples": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return subprocess.run(
            [
                sys.executable,
                str(_SUITE),
                *args,
                "--feature-ir",
                str(feature_ir),
            ],
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


def test_fallback_suite_uses_shared_harness_without_local_framework() -> None:
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
        isinstance(node, ast.ClassDef) and node.name == "FallbackQARunner"
        for node in ast.walk(tree)
    )


def test_fallback_cli_preserves_modes_and_invalid_invocations() -> None:
    help_result = _run_suite("--help")
    assert help_result.returncode == 0
    assert "--static" in help_result.stdout
    assert "--dynamic" in help_result.stdout
    assert "--all" in help_result.stdout
    assert "--pipeline" not in help_result.stdout
    assert "--use-case" not in help_result.stdout

    conflicting = _run_suite("--static", "--dynamic")
    assert conflicting.returncode == 2
    assert "not allowed with argument --static" in conflicting.stderr
    assert "[PASS]" not in conflicting.stdout
    assert "[FAIL]" not in conflicting.stdout
    assert "QA SUMMARY:" not in conflicting.stdout

    unrecognized = _run_suite("--bogus")
    assert unrecognized.returncode == 2
    assert "unrecognized arguments: --bogus" in unrecognized.stderr
    assert "[PASS]" not in unrecognized.stdout


def test_fallback_static_mode_preserves_check_order_and_banner_summary() -> None:
    result = _run_suite("--static")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _STATIC_CHECKS
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert "--- Static checks (AST analysis) ---" in result.stdout
    assert "--- Dynamic checks" not in result.stdout
    assert "QA SUMMARY: 10/10 passed, 0 failed" in result.stdout
    assert "ALL CHECKS PASSED" in result.stdout
    assert "QA suite:" not in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index("QA SUMMARY: 10/10 passed, 0 failed")
    assert first_check > summary


def test_fallback_dynamic_mode_preserves_check_order_and_banner_summary() -> None:
    result = _run_suite("--dynamic")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _DYNAMIC_CHECKS
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert (
        "--- Dynamic checks (acceptance runtime + direct invocation) ---"
        in result.stdout
    )
    assert "--- Static checks" not in result.stdout
    assert "QA SUMMARY: 11/11 passed, 0 failed" in result.stdout
    assert "ALL CHECKS PASSED" in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index("QA SUMMARY: 11/11 passed, 0 failed")
    assert first_check > summary


@pytest.mark.parametrize("args", [(), ("--all",)])
def test_fallback_all_mode_preserves_default_and_explicit_check_order(
    args: tuple[str, ...],
) -> None:
    result = _run_suite(*args)
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _STATIC_CHECKS + _DYNAMIC_CHECKS
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert result.stdout.index(
        "--- Static checks (AST analysis) ---"
    ) < result.stdout.index(
        "--- Dynamic checks (acceptance runtime + direct invocation) ---"
    )
    assert "QA SUMMARY: 21/21 passed, 0 failed" in result.stdout
    assert "ALL CHECKS PASSED" in result.stdout
    assert "QA suite:" not in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index("QA SUMMARY: 21/21 passed, 0 failed")
    assert first_check > summary


def test_fallback_adapter_defers_output_and_keeps_legacy_counts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = FallbackQARunner()
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
    assert "QA suite:" not in output


def test_fallback_temp_dirs_are_removed_after_success() -> None:
    created: list[Path] = []
    with _temporary_run_dir("qa_fallback_") as tmpdir:
        path = Path(tmpdir)
        created.append(path)
        (path / "calls.jsonl").write_text("{}\n", encoding="utf-8")
        assert path.exists()
    assert created
    assert all(not path.exists() for path in created)


def test_fallback_temp_dirs_are_removed_after_failure() -> None:
    created: list[Path] = []
    with pytest.raises(RuntimeError):
        with _temporary_run_dir("qa_fallback_strip_") as tmpdir:
            path = Path(tmpdir)
            created.append(path)
            (path / "calls.jsonl").write_text("{}\n", encoding="utf-8")
            raise RuntimeError("boom")
    assert created
    assert all(not path.exists() for path in created)


def test_fallback_dynamic_child_isolation_from_nested_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    parent_environment = dict(os.environ)
    isolated = child_env(parent_environment, QA_PARENT_ONLY=None, CHILD="only")

    result = _run_suite("--dynamic", cwd=nested, env=isolated)

    assert result.returncode == 0
    assert "QA SUMMARY: 11/11 passed, 0 failed" in result.stdout
    assert Path.cwd() == nested
    assert os.environ["QA_PARENT_ONLY"] == "present"
    assert parent_environment["QA_PARENT_ONLY"] == "present"
    assert "QA_PARENT_ONLY" not in isolated
    assert isolated["CHILD"] == "only"
    assert find_project_root() == _PROJECT_ROOT


def test_fallback_run_command_defaults_to_project_root_from_nested_cwd(
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

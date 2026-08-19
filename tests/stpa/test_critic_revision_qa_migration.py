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
_SUITE = _PROJECT_ROOT / "acceptance" / "qa" / "sp1_critic_revision.py"
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))

from qa_harness import CheckResult, child_env, find_project_root, run_command  # noqa: E402
from sp1_critic_revision import (  # noqa: E402
    CriticRevisionQARunner,
    _format_critic_revision_result,
    _temporary_run_dir,
    run_pipeline_checks,
)

_STATIC_CHECKS = [
    "crf-static-01: REVISION_MAX_COMPLETION_TOKENS is 8192",
    "crf-static-02: the ceiling exceeds the observed truncation point",
    "crf-static-03: run_revision is defined",
    "crf-static-04: run_revision forwards REVISION_MAX_COMPLETION_TOKENS to safe_llm_call",
    "crf-static-05: run_revision does not hardcode a numeric token cap",
    "crf-static-06: has_unjustified_gaps is defined",
    "crf-static-07[checklist_results]: has_unjustified_gaps reads findings.checklist_results",
    "crf-static-07[taxonomy_probe_results]: has_unjustified_gaps reads findings.taxonomy_probe_results",
    "crf-static-07[gaps]: has_unjustified_gaps reads findings.gaps",
    "crf-static-08: _compute_next_ids is defined",
    "crf-static-09: _compute_next_ids emits a next_cm_num key",
    "crf-static-10: next_cm_num is derived from nested coordination_mechanism.cm_id values",
    "crf-static-11[next_resp_num]: _compute_next_ids still emits next_resp_num",
    "crf-static-11[next_cl_num]: _compute_next_ids still emits next_cl_num",
    "crf-static-11[next_cp_num]: _compute_next_ids still emits next_cp_num",
    "crf-static-12: RevisionDelta is defined",
    "crf-static-13: RevisionDelta declares dismissed_gaps",
    "crf-static-14[new_responsibilities]: RevisionDelta still declares new_responsibilities",
    "crf-static-14[new_controlled_processes]: RevisionDelta still declares new_controlled_processes",
    "crf-static-14[new_coordination_links]: RevisionDelta still declares new_coordination_links",
    "crf-static-14[modified_responsibilities]: RevisionDelta still declares modified_responsibilities",
    "crf-static-15: run_completeness_critic is defined",
    "crf-static-16[loss_analysis]: run_completeness_critic accepts an optional loss_analysis",
    "crf-static-16[call3_warnings]: run_completeness_critic accepts an optional call3_warnings",
    "crf-static-17[loss_analysis]: loss_analysis is passed into the critic_user.j2 render call",
    "crf-static-17[call3_warnings]: call3_warnings is passed into the critic_user.j2 render call",
    "crf-static-18: run.py passes loss_analysis to run_completeness_critic",
    "crf-static-18b: run.py passes call3_warnings to run_completeness_critic",
    "crf-static-19[map(attribute='pm_id')]: critic_user.j2 no longer renders bare identifier lists",
    "crf-static-20[map(attribute='pm_id')]: revision_system.j2 no longer renders bare identifier lists",
    "crf-static-19[map(attribute='ca_id')]: critic_user.j2 no longer renders bare identifier lists",
    "crf-static-20[map(attribute='ca_id')]: revision_system.j2 no longer renders bare identifier lists",
    "crf-static-19[map(attribute='fb_id')]: critic_user.j2 no longer renders bare identifier lists",
    "crf-static-20[map(attribute='fb_id')]: revision_system.j2 no longer renders bare identifier lists",
    "crf-static-21[{{ rc.rc_id }}: {{ rc.description }}]: critic_user.j2 renders it",
    "crf-static-22[{{ rc.rc_id }}: {{ rc.description }}]: revision_system.j2 renders it",
    "crf-static-21[{{ pm.pm_id }}: {{ pm.description }}]: critic_user.j2 renders it",
    "crf-static-22[{{ pm.pm_id }}: {{ pm.description }}]: revision_system.j2 renders it",
    "crf-static-21[{{ ca.ca_id }}: {{ ca.description }}]: critic_user.j2 renders it",
    "crf-static-22[{{ ca.ca_id }}: {{ ca.description }}]: revision_system.j2 renders it",
    "crf-static-21[{{ fb.fb_id }}: {{ fb.description }}]: critic_user.j2 renders it",
    "crf-static-22[{{ fb.fb_id }}: {{ fb.description }}]: revision_system.j2 renders it",
    "crf-static-23[{{ pm.feedback_source.type }}]: revision_system.j2 shows the reference a new element must connect to",
    "crf-static-23[{{ ca.target.type }}]: revision_system.j2 shows the reference a new element must connect to",
    "crf-static-23[{{ fb.source.type }}]: revision_system.j2 shows the reference a new element must connect to",
    "crf-static-23[{{ fb.updates }}]: revision_system.j2 shows the reference a new element must connect to",
    "crf-static-24[{% if loss_analysis %}]: critic_user.j2 renders the loss analysis section",
    "crf-static-24[loss_analysis.risk_card_losses]: critic_user.j2 renders the loss analysis section",
    "crf-static-24[loss_analysis.use_case_losses]: critic_user.j2 renders the loss analysis section",
    "crf-static-24[loss_analysis.hazards]: critic_user.j2 renders the loss analysis section",
    "crf-static-24[related_losses]: critic_user.j2 renders the loss analysis section",
    "crf-static-24[loss_analysis.security_constraints]: critic_user.j2 renders the loss analysis section",
    "crf-static-24[sc.constraint_id]: critic_user.j2 renders the loss analysis section",
    "crf-static-24[related_hazards]: critic_user.j2 renders the loss analysis section",
    "crf-static-24[Loss analysis not available]: critic_user.j2 renders the loss analysis section",
    "crf-static-25[loss_analysis.losses]: critic_user.j2 does not reference the non-existent field loss_analysis.losses",
    "crf-static-25[loss.loss_ids]: critic_user.j2 does not reference the non-existent field loss.loss_ids",
    "crf-static-25[sc.sc_id]: critic_user.j2 does not reference the non-existent field sc.sc_id",
    "crf-static-25[sc.hazard_id]: critic_user.j2 does not reference the non-existent field sc.hazard_id",
    "crf-static-26[{% if call3_warnings %}]: critic_user.j2 has the optional coordination-warnings section",
    "crf-static-26[Coordination Analysis Warnings]: critic_user.j2 has the optional coordination-warnings section",
    "crf-static-26[{% for warning in call3_warnings %}]: critic_user.j2 has the optional coordination-warnings section",
    "crf-static-27[New coordination mechanisms]: revision_system.j2 states the coordination-mechanism ID rule",
    "crf-static-27[CM-{next_cm_num}]: revision_system.j2 states the coordination-mechanism ID rule",
    "crf-static-27[{{ next_cm_num }}]: revision_system.j2 states the coordination-mechanism ID rule",
    "crf-static-27b[New controlled processes]: revision_system.j2 states the controlled-process ID rule",
    "crf-static-27b[CP-{next_cp_num}]: revision_system.j2 states the controlled-process ID rule",
    "crf-static-27b[{{ next_cp_num }}]: revision_system.j2 states the controlled-process ID rule",
    "crf-static-28: revision_user.j2 drops the mandatory-add directive",
    "crf-static-29[dismiss it with a one-sentence justification]: revision_user.j2 offers the add-or-dismiss choice",
    "crf-static-29[dismissed_gaps]: revision_user.j2 offers the add-or-dismiss choice",
    "crf-static-30: revision_system.j2 documents the dismissal rule",
    "crf-static-31: revision_user.j2 no longer duplicates the control-structure listing",
    "crf-static-32: revision_user.j2 still excludes use_case_text",
    "crf-static-33[critic_system.j2]: the unexplained STPA-Sec framing is gone",
    "crf-static-33[revision_system.j2]: the unexplained STPA-Sec framing is gone",
    "crf-static-34: critic_system.j2 states the false-positive guidance",
    "crf-static-35[checklist_results]: critic_system.j2 preserves it",
    "crf-static-35[taxonomy_probe_results]: critic_system.j2 preserves it",
    "crf-static-35[absent_unjustified]: critic_system.j2 preserves it",
    "crf-static-35[Do NOT suggest specific IDs]: critic_system.j2 preserves it",
    "crf-static-35[{% if taxonomy_probes %}]: critic_system.j2 preserves it",
    "crf-static-36[## ID format rules]: revision_system.j2 preserves it",
    "crf-static-36[RESP-{next_resp_num}]: revision_system.j2 preserves it",
    "crf-static-36[CL-{next_cl_num}]: revision_system.j2 preserves it",
    "crf-static-36[Do NOT restate the entire control structure]: revision_system.j2 preserves it",
    "crf-static-36[modified_responsibilities list must contain ONLY responsibilities you are CHANGING]: revision_system.j2 preserves it",
    "crf-static-36[solution-neutrality]: revision_system.j2 preserves it",
    "crf-static-36[ElementRef references must be valid]: revision_system.j2 preserves it",
    "crf-static-36[feedback channel updates must reference a PM in the same responsibility]: revision_system.j2 preserves it",
    "crf-static-37[critic-gap-detection]: acceptance feature file exists",
    "crf-static-37[critic-prompt-context]: acceptance feature file exists",
    "crf-static-37[revision-gap-dismissal]: acceptance feature file exists",
    "crf-static-37[revision-all-dismissed-warning]: acceptance feature file exists",
    "crf-static-37[revision-next-cm-id]: acceptance feature file exists",
    "crf-static-37[revision-prompt-context]: acceptance feature file exists",
    "crf-static-37[revision-token-ceiling]: acceptance feature file exists",
    "crf-static-38: all-dismissed helper checks no-change condition",
    "crf-static-39: the all-dismissed warning is emitted at most once",
]
_DYNAMIC_CHECKS = [
    "crf-dynamic-01: _compute_next_ids returns a next_cm_num key",
    "crf-dynamic-02[no links]: next_cm_num is 1",
    "crf-dynamic-02[CM-1]: next_cm_num is 2",
    "crf-dynamic-02[CM-1, CM-2]: next_cm_num is 3",
    "crf-dynamic-02[CM-2, CM-1]: next_cm_num is 3",
    "crf-dynamic-02[CM-7]: next_cm_num is 8",
    "crf-dynamic-02[CM-1, CM-4, CM-2]: next_cm_num is 5",
    "crf-dynamic-03: next_cm_num is independent of next_cl_num",
    "crf-dynamic-04[next_resp_num]: the existing next-number is unchanged (3)",
    "crf-dynamic-04[next_cl_num]: the existing next-number is unchanged (2)",
    "crf-dynamic-04[next_cp_num]: the existing next-number is unchanged (2)",
    "crf-dynamic-05[checklist absent_unjustified]: revision trigger is True",
    "crf-dynamic-05[checklist mixed with one absent_unjustified]: revision trigger is True",
    "crf-dynamic-05[taxonomy absent_unjustified]: revision trigger is True",
    "crf-dynamic-05[taxonomy mixed with one absent_unjustified]: revision trigger is True",
    "crf-dynamic-05[adversarial gap only]: revision trigger is True",
    "crf-dynamic-05[three adversarial gaps only]: revision trigger is True",
    "crf-dynamic-05[all present]: revision trigger is False",
    "crf-dynamic-05[all absent_justified]: revision trigger is False",
    "crf-dynamic-05[empty findings]: revision trigger is False",
    "crf-dynamic-06: RevisionDelta().dismissed_gaps defaults to []",
    "crf-dynamic-07: RevisionDelta accepts dismissal justifications",
    "crf-dynamic-08: run_revision sends max_completion_tokens 8192",
    "crf-dynamic-09: an empty delta preserves both responsibilities",
    "crf-dynamic-10: the revision system prompt states the next coordination-mechanism number",
    "crf-dynamic-11[belief held by responsibility 1]: the revision system prompt shows the element description",
    "crf-dynamic-11[action issued by responsibility 1]: the revision system prompt shows the element description",
    "crf-dynamic-11[signal observed by responsibility 1]: the revision system prompt shows the element description",
    "crf-dynamic-12: a dismissal-only revision leaves the structure intact",
    "crf-dynamic-13: the dismissal justification is reported in the warnings",
    "crf-dynamic-14: the dismissal warning is labelled as a dismissal",
    "crf-dynamic-15: a revision with no dismissals emits no dismissal warning",
    "crf-dynamic-30: all findings dismissed + no changes emits an all-dismissed warning",
    "crf-dynamic-31: per-dismissal warnings remain when all are dismissed",
    "crf-dynamic-32: exactly one all-dismissed warning is emitted",
    "crf-dynamic-33: partial dismissal does not emit all-dismissed warning",
    "crf-dynamic-34: partial dismissal still emits per-dismissal warning",
    "crf-dynamic-35: all dismissed + new responsibility suppresses all-dismissed warning",
    "crf-dynamic-36: the new responsibility is present in the revised structure",
    "crf-dynamic-37: all dismissed + new controlled process suppresses all-dismissed warning",
    "crf-dynamic-38: empty findings does not emit all-dismissed warning",
    "crf-dynamic-39: all dismissed + modified responsibility suppresses all-dismissed warning",
    "crf-dynamic-40: RevisionDelta fields remain unchanged after all-dismissed warning feature",
    "crf-dynamic-16: a truncated revision returns the pre-revision control structure",
    "crf-dynamic-17: the truncation is reported as a warning",
    "crf-dynamic-18[PM-1-1: belief held by responsibility 1]: the critic user prompt contains it",
    "crf-dynamic-18[CA-1-1: action issued by responsibility 1]: the critic user prompt contains it",
    "crf-dynamic-18[FB-1-1: signal observed by responsibility 1]: the critic user prompt contains it",
    "crf-dynamic-18[RC-1-1: constraint on responsibility 1]: the critic user prompt contains it",
    "crf-dynamic-18[shared belief synchronisation]: the critic user prompt contains it",
    "crf-dynamic-18[**L-1**]: the critic user prompt contains it",
    "crf-dynamic-18[**H-1**]: the critic user prompt contains it",
    "crf-dynamic-18[**SC-1**]: the critic user prompt contains it",
    "crf-dynamic-18[Unauthorised disclosure of customer records]: the critic user prompt contains it",
    "crf-dynamic-18[Retrieval returns records outside the session scope]: the critic user prompt contains it",
    "crf-dynamic-18[Retrieval must be scoped to the active session]: the critic user prompt contains it",
    "crf-dynamic-18[Coordination Analysis Warnings]: the critic user prompt contains it",
    "crf-dynamic-18[CL-2 shares a process model part outside its scope]: the critic user prompt contains it",
    "crf-dynamic-19: the critic user prompt has no unrendered Jinja expression",
    "crf-dynamic-20: the critic user prompt renders without a loss analysis",
    "crf-dynamic-21: the coordination-warnings section is omitted when there are none",
    "crf-dynamic-22[**L-1**]: run_completeness_critic forwards it into the user prompt",
    "crf-dynamic-22[**H-1**]: run_completeness_critic forwards it into the user prompt",
    "crf-dynamic-22[**SC-1**]: run_completeness_critic forwards it into the user prompt",
    "crf-dynamic-22[CL-2 shares a process model part outside its scope]: run_completeness_critic forwards it into the user prompt",
    "crf-dynamic-23: the critic call carries no max_completion_tokens cap",
    "crf-dynamic-24: run_completeness_critic works without the new context arguments",
    "crf-dynamic-25: the revision system prompt renders when a PM has no feedback source",
    "crf-dynamic-26: the revision system prompt has no unrendered Jinja expression",
    "crf-dynamic-29[critic-gap-detection]: all acceptance scenarios pass",
    "crf-dynamic-29[critic-prompt-context]: all acceptance scenarios pass",
    "crf-dynamic-29[revision-gap-dismissal]: all acceptance scenarios pass",
    "crf-dynamic-29[revision-all-dismissed-warning]: all acceptance scenarios pass",
    "crf-dynamic-29[revision-next-cm-id]: all acceptance scenarios pass",
    "crf-dynamic-29[revision-prompt-context]: all acceptance scenarios pass",
    "crf-dynamic-29[revision-token-ceiling]: all acceptance scenarios pass",
]
_PIPELINE_CHECKS = [
    "crf-pipeline-01: the revision call completes without LengthFinishReasonError",
    "crf-pipeline-02: the revision completion stays under the 8192 ceiling",
    "crf-pipeline-03: the revision produces a non-empty delta",
    "crf-pipeline-04: cm_id renumber warnings become rare",
    "crf-pipeline-05: the critic stops flagging capabilities the system does not have",
    "crf-pipeline-06: the critic's findings reference the loss analysis",
    "crf-pipeline-07: dismissals are used for genuine false positives",
    "crf-pipeline-08: the all-dismissed/no-change warning surfaces in real runs",
]
_PIPELINE_SKIP_REASON = (
    "requires ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=1 and --run-dir <completed run>; "
    "no live LLM endpoint in this environment"
)
_PIPELINE_SKIP_BANNER = (
    "8 PIPELINE-MODE CHECK(S) NOT EXECUTED — these need a "
    "live LLM endpoint and a completed run; see --pipeline."
)


def _run_suite(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None):
    stems = (
        "critic-gap-detection",
        "critic-prompt-context",
        "revision-gap-dismissal",
        "revision-all-dismissed-warning",
        "revision-next-cm-id",
        "revision-prompt-context",
        "revision-token-ceiling",
    )
    with tempfile.TemporaryDirectory(prefix="critic-revision-ir-") as directory:
        ir_dir = Path(directory)
        fixture = {
            "name": "Critic revision acceptance fixture",
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
        for stem in stems:
            (ir_dir / f"{stem}.json").write_text(
                json.dumps(fixture),
                encoding="utf-8",
            )
        return subprocess.run(
            [sys.executable, str(_SUITE), *args, "--ir-dir", str(ir_dir)],
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


def test_critic_revision_suite_uses_shared_harness_without_local_framework() -> None:
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
        isinstance(node, ast.ClassDef) and node.name == "CriticRevisionQARunner"
        for node in ast.walk(tree)
    )


def test_critic_revision_cli_preserves_modes_and_invalid_invocations() -> None:
    help_result = _run_suite("--help")
    assert help_result.returncode == 0
    assert "--static" in help_result.stdout
    assert "--dynamic" in help_result.stdout
    assert "--pipeline" in help_result.stdout
    assert "--all" in help_result.stdout
    assert "--run-dir" in help_result.stdout
    assert "--use-case" not in help_result.stdout

    unrecognized = _run_suite("--bogus")
    assert unrecognized.returncode == 2
    assert "unrecognized arguments: --bogus" in unrecognized.stderr
    assert "[PASS]" not in unrecognized.stdout
    assert "[FAIL]" not in unrecognized.stdout
    assert "QA SUMMARY:" not in unrecognized.stdout


def test_critic_revision_static_mode_preserves_check_order_and_banner_summary() -> None:
    result = _run_suite("--static")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _STATIC_CHECKS
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert "--- Static checks (AST + prompt source) ---" in result.stdout
    assert "--- Dynamic checks" not in result.stdout
    assert "--- Pipeline-mode checks" not in result.stdout
    assert (
        "QA SUMMARY: 99/99 passed, 0 failed, 0 skipped (not executed)" in result.stdout
    )
    assert "ALL 99 EXECUTED CHECK(S) PASSED" in result.stdout
    assert "QA suite:" not in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index(
        "QA SUMMARY: 99/99 passed, 0 failed, 0 skipped (not executed)"
    )
    assert first_check > summary


def test_critic_revision_dynamic_mode_preserves_check_order_and_banner_summary() -> (
    None
):
    result = _run_suite("--dynamic")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _DYNAMIC_CHECKS
    assert all(line.startswith("  [PASS] ") for line in lines)
    assert (
        "--- Dynamic checks (direct invocation + acceptance runtime) ---"
        in result.stdout
    )
    assert "--- Static checks" not in result.stdout
    assert "--- Pipeline-mode checks" not in result.stdout
    assert (
        "QA SUMMARY: 76/76 passed, 0 failed, 0 skipped (not executed)" in result.stdout
    )
    assert "ALL 76 EXECUTED CHECK(S) PASSED" in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index(
        "QA SUMMARY: 76/76 passed, 0 failed, 0 skipped (not executed)"
    )
    assert first_check > summary


def test_critic_revision_pipeline_mode_skips_without_opt_in() -> None:
    result = _run_suite("--pipeline")
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == _PIPELINE_CHECKS
    assert all(line.startswith("  [SKIP] ") for line in lines)
    assert "--- Pipeline-mode checks (live LLM endpoint) ---" in result.stdout
    assert "--- Static checks" not in result.stdout
    assert "--- Dynamic checks" not in result.stdout
    assert "QA SUMMARY: 0/8 passed, 0 failed, 8 skipped (not executed)" in result.stdout
    assert "NO CHECKS WERE EXECUTED" in result.stdout
    assert _PIPELINE_SKIP_BANNER in result.stdout
    assert result.stdout.count(_PIPELINE_SKIP_REASON) == 8
    assert "QA suite:" not in result.stdout


def test_critic_revision_pipeline_env_without_run_dir_still_skips() -> None:
    env = dict(os.environ)
    env["ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"] = "1"
    result = _run_suite("--pipeline", env=env)
    assert result.returncode == 0
    assert _check_names(result.stdout) == _PIPELINE_CHECKS
    assert all(
        line.startswith("  [SKIP] ")
        for line in result.stdout.splitlines()
        if line.startswith("  [")
    )
    assert "QA SUMMARY: 0/8 passed, 0 failed, 8 skipped (not executed)" in result.stdout
    assert "NO CHECKS WERE EXECUTED" in result.stdout
    assert result.stdout.count(_PIPELINE_SKIP_REASON) == 8


@pytest.mark.parametrize("args", [(), ("--all",)])
def test_critic_revision_all_mode_preserves_default_and_explicit_check_order(
    args: tuple[str, ...],
) -> None:
    result = _run_suite(*args)
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.startswith("  [")]
    assert _check_names(result.stdout) == (
        _STATIC_CHECKS + _DYNAMIC_CHECKS + _PIPELINE_CHECKS
    )
    assert [line[:8] for line in lines] == (["  [PASS]"] * 175 + ["  [SKIP]"] * 8)
    assert result.stdout.index(
        "--- Static checks (AST + prompt source) ---"
    ) < result.stdout.index(
        "--- Dynamic checks (direct invocation + acceptance runtime) ---"
    )
    assert result.stdout.index(
        "--- Dynamic checks (direct invocation + acceptance runtime) ---"
    ) < result.stdout.index("--- Pipeline-mode checks (live LLM endpoint) ---")
    assert (
        "QA SUMMARY: 175/183 passed, 0 failed, 8 skipped (not executed)"
        in result.stdout
    )
    assert "ALL 175 EXECUTED CHECK(S) PASSED" in result.stdout
    assert _PIPELINE_SKIP_BANNER in result.stdout
    assert "QA suite:" not in result.stdout
    first_check = result.stdout.index(lines[0])
    summary = result.stdout.index(
        "QA SUMMARY: 175/183 passed, 0 failed, 8 skipped (not executed)"
    )
    assert first_check > summary


def test_critic_revision_static_and_dynamic_flags_are_combinable() -> None:
    result = _run_suite("--static", "--dynamic")
    assert result.returncode == 0
    assert _check_names(result.stdout) == _STATIC_CHECKS + _DYNAMIC_CHECKS
    assert "--- Pipeline-mode checks" not in result.stdout
    assert (
        "QA SUMMARY: 175/175 passed, 0 failed, 0 skipped (not executed)"
        in result.stdout
    )
    assert "ALL 175 EXECUTED CHECK(S) PASSED" in result.stdout


def test_critic_revision_adapter_defers_output_and_keeps_legacy_counts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = CriticRevisionQARunner()
    runner.check("first", True, "hidden on pass")
    runner.check("second", False, "details")
    runner.skip("pipeline", "no endpoint")

    assert capsys.readouterr().out == ""
    assert runner.summary() == 1
    output = capsys.readouterr().out
    assert output.index(
        "QA SUMMARY: 1/3 passed, 1 failed, 1 skipped (not executed)"
    ) < output.index("[PASS] first")
    assert output.index("[PASS] first") < output.index("[FAIL] second")
    assert output.index("[FAIL] second") < output.index("[SKIP] pipeline")
    assert "hidden on pass" not in output
    assert "         details" in output
    assert "         no endpoint" in output
    assert "1 CHECK(S) FAILED" in output
    assert (
        "1 PIPELINE-MODE CHECK(S) NOT EXECUTED — these need a "
        "live LLM endpoint and a completed run; see --pipeline."
    ) in output
    assert "QA suite:" not in output


def test_critic_revision_adapter_zero_executed_checks_is_success(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = CriticRevisionQARunner()
    runner.skip("pipeline", "no endpoint")

    assert runner.summary() == 0
    output = capsys.readouterr().out
    assert "QA SUMMARY: 0/1 passed, 0 failed, 1 skipped (not executed)" in output
    assert "NO CHECKS WERE EXECUTED" in output
    assert "ALL " not in output


def test_critic_revision_result_formatter_hides_pass_details() -> None:
    passed = CheckResult("ok", True, "secret")
    failed = CheckResult("bad", False, "why")
    skipped = CheckResult("later", True, "wait", "SKIP")
    assert _format_critic_revision_result(passed) == "  [PASS] ok"
    assert _format_critic_revision_result(failed) == "  [FAIL] bad\n         why"
    assert _format_critic_revision_result(skipped) == "  [SKIP] later\n         wait"


def test_critic_revision_temp_dirs_are_removed_after_success() -> None:
    created: list[Path] = []
    with _temporary_run_dir("qa_crf_cap_") as tmpdir:
        path = Path(tmpdir)
        created.append(path)
        (path / "calls.jsonl").write_text("{}\n", encoding="utf-8")
        assert path.exists()
    assert created
    assert all(not path.exists() for path in created)


def test_critic_revision_temp_dirs_are_removed_after_failure() -> None:
    created: list[Path] = []
    with pytest.raises(RuntimeError):
        with _temporary_run_dir("qa_crf_trunc_") as tmpdir:
            path = Path(tmpdir)
            created.append(path)
            (path / "calls.jsonl").write_text("{}\n", encoding="utf-8")
            raise RuntimeError("boom")
    assert created
    assert all(not path.exists() for path in created)


def test_critic_revision_static_child_isolation_from_nested_cwd(
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
    assert (
        "QA SUMMARY: 99/99 passed, 0 failed, 0 skipped (not executed)" in result.stdout
    )
    assert Path.cwd() == nested
    assert os.environ["QA_PARENT_ONLY"] == "present"
    assert parent_environment["QA_PARENT_ONLY"] == "present"
    assert "QA_PARENT_ONLY" not in isolated
    assert isolated["CHILD"] == "only"
    assert find_project_root() == _PROJECT_ROOT


def test_critic_revision_dynamic_child_isolation_from_nested_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    isolated = child_env(dict(os.environ), QA_PARENT_ONLY=None, CHILD="only")

    result = _run_suite("--dynamic", cwd=nested, env=isolated)

    assert result.returncode == 0
    assert (
        "QA SUMMARY: 76/76 passed, 0 failed, 0 skipped (not executed)" in result.stdout
    )
    assert Path.cwd() == nested
    assert os.environ["QA_PARENT_ONLY"] == "present"
    assert "QA_PARENT_ONLY" not in isolated
    assert isolated["CHILD"] == "only"


def test_critic_revision_run_command_defaults_to_project_root_from_nested_cwd(
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


def test_critic_revision_pipeline_local_standin_does_not_contact_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", "1")
    run_dir = tmp_path / "completed-run"
    run_dir.mkdir()
    (run_dir / "calls.jsonl").write_text(
        json.dumps(
            {
                "stage": "stage_2",
                "step": "revision",
                "success": True,
                "error": None,
                "completion_tokens": 120,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    runner = CriticRevisionQARunner()
    run_pipeline_checks(runner, run_dir)

    names = [result.name for result in runner.results]
    assert names == _PIPELINE_CHECKS
    assert runner.results[0].passed is True
    assert runner.results[0].status is None
    assert runner.results[1].passed is True
    assert runner.results[1].status is None
    assert all(result.status == "SKIP" for result in runner.results[2:])
    assert all(str(run_dir) in (result.detail or "") for result in runner.results[2:])
    assert all("http" not in (result.detail or "").lower() for result in runner.results)

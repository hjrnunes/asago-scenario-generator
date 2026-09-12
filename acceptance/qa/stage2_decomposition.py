"""End-to-end QA suite for the Stage 2 restructure feature.

This QA suite verifies the Stage 2 call decomposition restructure (bead w5tp)
through the user interface: the `asago-scenario-generator stpa-run` CLI subcommand.
It inspects output artifacts on disk (YAML files, JSONL call logs, run
manifest) and source prompt templates — never internal Python APIs.

Two execution modes:

1. **Static checks** (no LLM needed): inspect prompt templates on disk
   and verify template presence/absence and prompt content invariants.
   These run immediately and verify the structural changes.

2. **Pipeline checks** (require an LLM endpoint): run the full
   `asago-scenario-generator stpa-run` pipeline and inspect output artifacts.
   These require ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL and ASAGO_SCENARIO_GENERATOR_API_KEY
   environment variables (or equivalent).

Usage::

    # Static checks only (fast, no LLM)
    uv run python acceptance/qa/stage2_decomposition.py --static

    # Full pipeline checks (requires LLM endpoint)
    uv run python acceptance/qa/stage2_decomposition.py \\
        --use-case <path> --risk-extraction <path>

    # All checks (static + pipeline)
    uv run python acceptance/qa/stage2_decomposition.py \\
        --all --use-case <path> --risk-extraction <path>

Exit codes:
    0 — all checks passed
    1 — one or more checks failed
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

import yaml

QA_MODULES = Path(__file__).resolve().parent
if str(QA_MODULES) not in sys.path:
    sys.path.insert(0, str(QA_MODULES))

from qa_harness import (  # noqa: E402
    PROJECT_ROOT,
    CheckResult,
    QARunner,
    child_env,
    run_command,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROMPTS_DIR = (
    PROJECT_ROOT
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "system_model"
    / "prompts"
)

# Expected Stage 2 call-log steps (new decomposition)
NEW_STEPS = [
    "call_1_requirements",
    "call_2a_responsibilities",
    "call_2b_control_elements",
    "call_3_coordination",
]

# Old Stage 2 call-log steps that should be absent
OLD_STEPS = [
    "call_2_responsibilities",
    "call_3_connections",
]

# New templates that should exist
NEW_TEMPLATES = [
    "stage2_call2a_system.j2",
    "stage2_call2a_user.j2",
    "stage2_call2b_system.j2",
    "stage2_call2b_user.j2",
]

# Old templates that should be deleted
OLD_TEMPLATES = [
    "stage2_call2_system.j2",
    "stage2_call2_user.j2",
]

# All Stage 2 system prompts that should not mention Poh or STPA-Sec
ALL_SYSTEM_PROMPTS = [
    "stage2_call1_system.j2",
    "stage2_call2a_system.j2",
    "stage2_call2b_system.j2",
    "stage2_call3_system.j2",
]

EXPECTED_STAGE2_CALL_COUNT = 4


# ---------------------------------------------------------------------------
# Compatibility adapter
# ---------------------------------------------------------------------------


class Stage2QARunner(QARunner):
    """Shared harness runner with the Stage 2 suite's deferred banner summary."""

    def record(self, name: str, passed: bool, detail: str = "") -> CheckResult:
        result = CheckResult(name, bool(passed), detail)
        self.results.append(result)
        return result

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.record(name, passed, detail)
        return bool(passed)

    def skip(self, name: str, reason: str) -> CheckResult:
        result = CheckResult(name, True, reason, "SKIP")
        self.results.append(result)
        return result

    def summary(self) -> int:
        passed = sum(
            result.passed and result.status != "SKIP" for result in self.results
        )
        failed = sum(
            not result.passed and result.status != "SKIP" for result in self.results
        )
        total = len(self.results)
        print()
        print("=" * 60)
        print(f"QA SUMMARY: {passed}/{total} passed, {failed} failed")
        print("=" * 60)
        for result in self.results:
            print(result)
        if failed > 0:
            print(f"\n{failed} CHECK(S) FAILED")
            return 1
        print("\nALL CHECKS PASSED")
        return 0


# ---------------------------------------------------------------------------
# Static checks (no LLM required)
# ---------------------------------------------------------------------------


def _read_template(name: str) -> str | None:
    """Read a prompt template, returning None if missing."""
    path = PROMPTS_DIR / name
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def run_static_checks(runner: QARunner) -> None:
    """Run checks that inspect prompt templates on disk."""

    # --- Old templates removed ---
    for tmpl in OLD_TEMPLATES:
        runner.check(
            f"stage2-call2a: old {tmpl} is absent",
            not (PROMPTS_DIR / tmpl).exists(),
        )

    # --- New templates present ---
    for tmpl in NEW_TEMPLATES:
        runner.check(
            f"stage2-restructure: {tmpl} is present",
            (PROMPTS_DIR / tmpl).exists(),
        )

    # --- Call 2a system prompt: RC vs PM distinction ---
    content = _read_template("stage2_call2a_system.j2")
    if content is not None:
        runner.check(
            "stage2-call2a: system prompt contains 'RC-X-Y'",
            "RC-X-Y" in content,
        )
        runner.check(
            "stage2-call2a: system prompt contains 'PM-X-Y'",
            "PM-X-Y" in content,
        )
        runner.check(
            "stage2-call2a: system prompt contains 'Do NOT copy PM entries as RCs'",
            "Do NOT copy PM entries as RCs" in content,
        )
    else:
        runner.check(
            "stage2-call2a: stage2_call2a_system.j2 exists",
            False,
            "File not found",
        )

    # --- Call 2a system prompt: zone-driven responsibilities ---
    if content is not None:
        for marker in ("tool_execution", "memory", "hitl", "inter_agent"):
            runner.check(
                f"stage2-call2a: system prompt contains '{marker}'",
                marker in content,
            )
    else:
        for marker in ("tool_execution", "memory", "hitl", "inter_agent"):
            runner.check(
                f"stage2-call2a: system prompt contains '{marker}'",
                False,
                "File not found",
            )

    # --- Call 2a system prompt: no control actions or feedback channels ---
    if content is not None:
        runner.check(
            "stage2-call2a: system prompt does not contain 'Control Actions'",
            "Control Actions" not in content,
        )
        runner.check(
            "stage2-call2a: system prompt does not contain 'Feedback Channels'",
            "Feedback Channels" not in content,
        )

    # --- Call 2a user prompt: capability profile context ---
    user_content = _read_template("stage2_call2a_user.j2")
    if user_content is not None:
        runner.check(
            "stage2-call2a: user prompt contains 'capability_profile'",
            "capability_profile" in user_content,
        )
        runner.check(
            "stage2-call2a: user prompt contains 'zones_active'",
            "zones_active" in user_content,
        )
        runner.check(
            "stage2-call2a: user prompt contains 'feedback_source null'",
            "feedback_source null" in user_content,
        )
    else:
        runner.check(
            "stage2-call2a: stage2_call2a_user.j2 exists",
            False,
            "File not found",
        )

    # --- Call 2b system prompt: PM-FB invariant ---
    call2b_sys = _read_template("stage2_call2b_system.j2")
    if call2b_sys is not None:
        runner.check(
            "stage2-call2b: system prompt contains 'at least one feedback channel'",
            "at least one feedback channel" in call2b_sys,
        )
        runner.check(
            "stage2-call2b: system prompt contains 'at least N feedback channels'",
            "at least N feedback channels" in call2b_sys,
        )
    else:
        runner.check(
            "stage2-call2b: stage2_call2b_system.j2 exists",
            False,
            "File not found",
        )

    # --- Call 2b user prompt: responsibilities from Call 2a ---
    call2b_user = _read_template("stage2_call2b_user.j2")
    if call2b_user is not None:
        for marker in (
            "responsibilities",
            "responsibility_constraints",
            "process_model_parts",
        ):
            runner.check(
                f"stage2-call2b: user prompt contains '{marker}'",
                marker in call2b_user,
            )
    else:
        runner.check(
            "stage2-call2b: stage2_call2b_user.j2 exists",
            False,
            "File not found",
        )

    # --- Call 3 system prompt: flag not fix ---
    call3_sys = _read_template("stage2_call3_system.j2")
    if call3_sys is not None:
        runner.check(
            "stage2-call3: system prompt contains 'Deterministic code has already checked'",
            "Deterministic code has already checked" in call3_sys,
        )
        runner.check(
            "stage2-call3: system prompt contains 'do not fix them here'",
            "do not fix them here" in call3_sys,
        )
        runner.check(
            "stage2-call3: system prompt contains 'Do not return an'",
            "Do not return an" in call3_sys,
        )
        runner.check(
            "stage2-call3: system prompt does not contain 'connection_assignments'",
            "connection_assignments" not in call3_sys,
        )
        runner.check(
            "stage2-call3: system prompt does not contain 'ConnectionSet'",
            "ConnectionSet" not in call3_sys,
        )
    else:
        runner.check(
            "stage2-call3: stage2_call3_system.j2 exists",
            False,
            "File not found",
        )

    # --- Call 3 user prompt: uses control_structure ---
    call3_user = _read_template("stage2_call3_user.j2")
    if call3_user is not None:
        runner.check(
            "stage2-call3: user prompt contains 'control_structure'",
            "control_structure" in call3_user,
        )
        runner.check(
            "stage2-call3: user prompt does not contain 'responsibility_set'",
            "responsibility_set" not in call3_user,
        )
    else:
        runner.check(
            "stage2-call3: stage2_call3_user.j2 exists",
            False,
            "File not found",
        )

    # --- Call 1 system prompt: solution-neutrality principle ---
    call1_sys = _read_template("stage2_call1_system.j2")
    if call1_sys is not None:
        runner.check(
            "stage2-assembly: call1 system prompt contains 'solution-neutral'",
            "solution-neutral" in call1_sys,
        )
        runner.check(
            "stage2-assembly: call1 system prompt does not contain old blocklist instruction",
            "Do NOT use implementation-specific terms" not in call1_sys,
        )
    else:
        runner.check(
            "stage2-assembly: stage2_call1_system.j2 exists",
            False,
            "File not found",
        )

    # --- No Poh or STPA-Sec in any Stage 2 system prompt ---
    for tmpl_name in ALL_SYSTEM_PROMPTS:
        tmpl_content = _read_template(tmpl_name)
        if tmpl_content is not None:
            runner.check(
                f"stage2-assembly: {tmpl_name} does not contain 'Poh'",
                "Poh" not in tmpl_content,
            )
            runner.check(
                f"stage2-assembly: {tmpl_name} does not contain 'STPA-Sec'",
                "STPA-Sec" not in tmpl_content,
            )
        else:
            runner.check(
                f"stage2-assembly: {tmpl_name} exists",
                False,
                "File not found",
            )


# ---------------------------------------------------------------------------
# Pipeline checks (require LLM endpoint)
# ---------------------------------------------------------------------------


def _run_stpa_pipeline(
    use_case: str,
    risk_extraction: Path,
    output_dir: Path,
    capability_profile: Path | None = None,
):
    """Run `asago-scenario-generator stpa-run` and return the completed process."""
    cmd = [
        "uv",
        "run",
        "asago-scenario-generator",
        "stpa-run",
        "--use-case",
        use_case,
        "--risk-extraction",
        str(risk_extraction),
        "--output-dir",
        str(output_dir),
    ]
    if capability_profile is not None:
        cmd.extend(["--capability-profile", str(capability_profile)])
    return run_command(
        cmd,
        cwd=PROJECT_ROOT,
        env=child_env(),
        timeout=600,
    )


def _load_yaml(path: Path) -> dict | None:
    """Load a YAML file, returning None if missing."""
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_calls_jsonl(path: Path) -> list[dict]:
    """Load calls.jsonl, returning a list of entry dicts."""
    if not path.exists():
        return []
    entries = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _find_call_entries(
    calls: list[dict],
    stage: str,
    step: str,
) -> list[dict]:
    """Return all call-log entries matching the given stage and step."""
    return [c for c in calls if c.get("stage") == stage and c.get("step") == step]


def _find_first_call_index(
    calls: list[dict],
    stage: str,
    step: str,
) -> int | None:
    """Return the index of the first call-log entry matching stage and step."""
    for i, c in enumerate(calls):
        if c.get("stage") == stage and c.get("step") == step:
            return i
    return None


def run_pipeline_checks(
    runner: QARunner,
    use_case: str,
    risk_extraction: Path,
    capability_profile: Path | None = None,
) -> None:
    """Run the full pipeline and inspect output artifacts."""

    with tempfile.TemporaryDirectory(prefix="stage2-qa-") as tmpdir:
        output_dir = Path(tmpdir) / "output"

        proc = _run_stpa_pipeline(
            use_case,
            risk_extraction,
            output_dir,
            capability_profile,
        )

        runner.check(
            "pipeline: stpa-run exits with code 0",
            proc.returncode == 0,
            f"exit code {proc.returncode}, stderr: {proc.stderr[:500]}",
        )

        if proc.returncode != 0:
            runner.check(
                "pipeline: stpa-run produced output artifacts",
                False,
                "Pipeline did not complete — skipping remaining checks",
            )
            return

        # --- Load artifacts ---
        control_structure = _load_yaml(output_dir / "control-structure.yaml")
        run_manifest = _load_yaml(output_dir / "run-manifest.yaml")
        calls = _load_calls_jsonl(output_dir / "calls.jsonl")

        # --- Call log entries: all four new steps present ---
        for step in NEW_STEPS:
            entries = _find_call_entries(calls, "stage_2", step)
            runner.check(
                f"stage2-assembly: calls.jsonl has stage_2/{step} entry",
                len(entries) >= 1,
                f"found {len(entries)} entries",
            )

        # --- Old step names absent ---
        for step in OLD_STEPS:
            entries = _find_call_entries(calls, "stage_2", step)
            runner.check(
                f"stage2-assembly: calls.jsonl does not have stage_2/{step} entry",
                len(entries) == 0,
                f"found {len(entries)} entries",
            )

        # --- Call ordering ---
        idx_1 = _find_first_call_index(calls, "stage_2", "call_1_requirements")
        idx_2a = _find_first_call_index(calls, "stage_2", "call_2a_responsibilities")
        idx_2b = _find_first_call_index(calls, "stage_2", "call_2b_control_elements")
        idx_3 = _find_first_call_index(calls, "stage_2", "call_3_coordination")

        if idx_1 is not None and idx_2a is not None:
            runner.check(
                "stage2-assembly: call_1 before call_2a in call log",
                idx_1 < idx_2a,
                f"call_1 at {idx_1}, call_2a at {idx_2a}",
            )
        else:
            runner.check(
                "stage2-assembly: call_1 before call_2a in call log",
                False,
                "Missing call entries for ordering check",
            )

        if idx_2a is not None and idx_2b is not None:
            runner.check(
                "stage2-assembly: call_2a before call_2b in call log",
                idx_2a < idx_2b,
                f"call_2a at {idx_2a}, call_2b at {idx_2b}",
            )
        else:
            runner.check(
                "stage2-assembly: call_2a before call_2b in call log",
                False,
                "Missing call entries for ordering check",
            )

        if idx_2b is not None and idx_3 is not None:
            runner.check(
                "stage2-assembly: call_2b before call_3 in call log",
                idx_2b < idx_3,
                f"call_2b at {idx_2b}, call_3 at {idx_3}",
            )
        else:
            runner.check(
                "stage2-assembly: call_2b before call_3 in call log",
                False,
                "Missing call entries for ordering check",
            )

        # --- Manifest call count ---
        if run_manifest:
            stage2_count = (
                run_manifest.get("stage_summary", {})
                .get("stage_2", {})
                .get("call_count", 0)
            )
            runner.check(
                f"stage2-assembly: run-manifest stage_2 call_count is {EXPECTED_STAGE2_CALL_COUNT}",
                stage2_count == EXPECTED_STAGE2_CALL_COUNT,
                f"got {stage2_count}",
            )
        else:
            runner.check(
                "stage2-assembly: run-manifest.yaml exists",
                False,
                "File not found",
            )

        # --- Control structure: all element types ---
        if control_structure:
            responsibilities = control_structure.get("responsibilities", [])
            runner.check(
                "stage2-assembly: control-structure has non-empty responsibilities",
                len(responsibilities) > 0,
                f"count: {len(responsibilities)}",
            )

            # Every responsibility has >=1 PM, >=1 CA, >=1 FB
            all_have_pm = all(
                len(r.get("process_model_parts", [])) >= 1 for r in responsibilities
            )
            runner.check(
                "stage2-assembly: every responsibility has >=1 process_model_part",
                all_have_pm,
            )

            all_have_ca = all(
                len(r.get("control_actions", [])) >= 1 for r in responsibilities
            )
            runner.check(
                "stage2-assembly: every responsibility has >=1 control_action",
                all_have_ca,
            )

            all_have_fb = all(
                len(r.get("feedback_channels", [])) >= 1 for r in responsibilities
            )
            runner.check(
                "stage2-assembly: every responsibility has >=1 feedback_channel",
                all_have_fb,
            )

            # --- RC IDs start with RC- never PM- ---
            all_rc_ids: list[str] = []
            for r in responsibilities:
                for rc in r.get("responsibility_constraints", []):
                    rc_id = rc.get("rc_id", "")
                    if rc_id:
                        all_rc_ids.append(rc_id)

            if all_rc_ids:
                all_start_rc = all(rc_id.startswith("RC-") for rc_id in all_rc_ids)
                runner.check(
                    "stage2-call2a: every rc_id starts with 'RC-'",
                    all_start_rc,
                    f"non-RC IDs: {[r for r in all_rc_ids if not r.startswith('RC-')]}",
                )

                none_start_pm = not any(rc_id.startswith("PM-") for rc_id in all_rc_ids)
                runner.check(
                    "stage2-call2a: no rc_id starts with 'PM-'",
                    none_start_pm,
                )
            else:
                runner.check(
                    "stage2-call2a: rc_ids present in control structure",
                    False,
                    "No rc_ids found",
                )

            # --- PM-FB invariant: every PM has at least one FB updating it ---
            all_pm_covered = True
            orphan_pms: list[str] = []
            for r in responsibilities:
                pm_ids = {
                    pm.get("pm_id", "") for pm in r.get("process_model_parts", [])
                }
                updated_pms = {
                    fb.get("updates", "") for fb in r.get("feedback_channels", [])
                }
                for pm_id in pm_ids:
                    if pm_id and pm_id not in updated_pms:
                        all_pm_covered = False
                        orphan_pms.append(pm_id)

            runner.check(
                "stage2-call2b: every pm_id has at least one feedback channel updating it",
                all_pm_covered,
                f"orphan PMs: {orphan_pms}" if orphan_pms else "",
            )

            # --- FB count >= PM count per responsibility ---
            all_fb_gte_pm = True
            fb_pm_details: list[str] = []
            for r in responsibilities:
                pm_count = len(r.get("process_model_parts", []))
                fb_count = len(r.get("feedback_channels", []))
                if fb_count < pm_count:
                    all_fb_gte_pm = False
                    fb_pm_details.append(
                        f"{r.get('resp_id', '?')}: {fb_count} FB < {pm_count} PM"
                    )

            runner.check(
                "stage2-call2b: every responsibility has >= N feedback channels for N PM parts",
                all_fb_gte_pm,
                "; ".join(fb_pm_details) if fb_pm_details else "",
            )

            # --- Coordination links list present ---
            coord_links = control_structure.get("coordination_links", None)
            runner.check(
                "stage2-call3: control-structure has coordination_links list",
                coord_links is not None,
                f"type: {type(coord_links).__name__}",
            )

        else:
            runner.check(
                "stage2-assembly: control-structure.yaml exists",
                False,
                "File not found",
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="End-to-end QA suite for Stage 2 restructure."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--static",
        action="store_true",
        help="Run static checks only (no LLM needed).",
    )
    mode.add_argument(
        "--pipeline",
        action="store_true",
        help="Run pipeline checks (requires LLM endpoint and input files).",
    )
    mode.add_argument(
        "--all",
        action="store_true",
        help="Run both static and pipeline checks.",
    )
    parser.add_argument(
        "--use-case",
        type=str,
        default=None,
        help="Path to use-case text file for pipeline checks.",
    )
    parser.add_argument(
        "--risk-extraction",
        type=Path,
        default=None,
        help="Path to risk extraction JSON file for pipeline checks.",
    )
    parser.add_argument(
        "--capability-profile",
        type=Path,
        default=None,
        help="Pre-built capability profile YAML (optional).",
    )
    args = parser.parse_args()

    runner = Stage2QARunner()

    do_static = args.static or args.all
    do_pipeline = args.pipeline or args.all

    if do_static:
        print("=== Static checks (no LLM required) ===")
        run_static_checks(runner)

    if do_pipeline:
        if not args.use_case or not args.risk_extraction:
            print(
                "ERROR: --use-case and --risk-extraction required for pipeline checks"
            )
            return 1
        print("\n=== Pipeline checks (requires LLM endpoint) ===")
        run_pipeline_checks(
            runner,
            args.use_case,
            args.risk_extraction,
            args.capability_profile,
        )

    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())

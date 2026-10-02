"""Static QA suite for the Stage 2 restructure feature.

This QA suite verifies the Stage 2 call decomposition restructure (bead w5tp)
by inspecting source prompt templates on disk: template presence and absence
and prompt content invariants. It needs no LLM endpoint and never imports
internal Python APIs.

Usage::

    uv run python acceptance/qa/stage2_decomposition.py --static

Exit codes:
    0 — all checks passed
    1 — one or more checks failed
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


QA_MODULES = Path(__file__).resolve().parent
if str(QA_MODULES) not in sys.path:
    sys.path.insert(0, str(QA_MODULES))

from qa_harness import (  # noqa: E402
    PROJECT_ROOT,
    CheckResult,
    QARunner,
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

# Old Stage 2 call-log steps that should be absent

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
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="End-to-end QA suite for Stage 2 restructure."
    )
    parser.add_argument(
        "--static",
        action="store_true",
        help="Run the static checks (the only mode; accepted for compatibility).",
    )
    parser.parse_args()

    runner = Stage2QARunner()
    print("=== Static checks (no LLM required) ===")
    run_static_checks(runner)
    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())

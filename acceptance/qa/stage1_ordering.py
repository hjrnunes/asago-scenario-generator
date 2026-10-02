"""Static QA suite for the Stage 1 split-and-reorder feature.

This QA suite verifies the combined Stage 1 restructure (beads tgs3 + 82t5)
by inspecting source prompt templates and Pydantic model field declarations
on disk. It needs no LLM endpoint and never imports internal Python APIs.

Usage::

    uv run python acceptance/qa/stage1_ordering.py --static

Exit codes:
    0 — all checks passed
    1 — one or more checks failed
"""

from __future__ import annotations

import argparse
import re
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

VALID_KC_SUBCODES = frozenset(
    {
        "KC1.1",
        "KC1.2",
        "KC1.3",
        "KC1.4",
        "KC2.1",
        "KC2.2",
        "KC2.3",
        "KC3.1",
        "KC3.2",
        "KC3.3",
        "KC3.4",
        "KC4.1",
        "KC4.2",
        "KC4.3",
        "KC4.4",
        "KC4.5",
        "KC4.6",
        "KC5.1",
        "KC5.2",
        "KC5.3",
        "KC6.1.1",
        "KC6.1.2",
        "KC6.2.1",
        "KC6.2.2",
        "KC6.3.1",
        "KC6.3.2",
        "KC6.3.3",
        "KC6.4",
        "KC6.5",
        "KC6.6",
        "KC6.7",
    }
)
KCX_PREFIX = "KCX-"

_KC4_PERSISTENT = frozenset({"KC4.3", "KC4.4", "KC4.5", "KC4.6"})
_KC_MULTI_AGENT = frozenset({"KC2.3", "KCX-MAGENT"})


# ---------------------------------------------------------------------------
# Compatibility adapter
# ---------------------------------------------------------------------------


class Stage1QARunner(QARunner):
    """Shared harness runner with the Stage 1 suite's deferred banner summary."""

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


def run_static_checks(runner: QARunner) -> None:
    """Run checks that inspect prompt templates and model declarations on disk."""

    # --- stage1a-split: old templates removed ---
    runner.check(
        "stage1a-split: old stage1a_system.j2 is absent",
        not (PROMPTS_DIR / "stage1a_system.j2").exists(),
    )
    runner.check(
        "stage1a-split: old stage1a_user.j2 is absent",
        not (PROMPTS_DIR / "stage1a_user.j2").exists(),
    )

    # --- stage1a-split: new templates present ---
    for tmpl in (
        "stage1a_risk_system.j2",
        "stage1a_risk_user.j2",
        "stage1a_gap_system.j2",
        "stage1a_gap_user.j2",
    ):
        runner.check(
            f"stage1a-split: {tmpl} is present",
            (PROMPTS_DIR / tmpl).exists(),
        )

    # --- stage1b-revision: KC taxonomy in system prompt ---
    stage1b_system = PROMPTS_DIR / "stage1b_system.j2"
    if stage1b_system.exists():
        content = stage1b_system.read_text(encoding="utf-8")
        for marker in (
            "KC1 — Language Models",
            "KC6 — Operational Environment",
            "KCX — Extended Capabilities",
        ):
            runner.check(
                f"stage1b-revision: stage1b_system.j2 contains '{marker}'",
                marker in content,
            )
        # --- stage1b-revision: no STPA terminology ---
        runner.check(
            "stage1b-revision: stage1b_system.j2 does not contain 'STPA'",
            "STPA" not in content,
        )
        # --- stage1b-revision: no zones_active in system prompt ---
        runner.check(
            "stage1b-revision: stage1b_system.j2 does not request 'zones_active'",
            "zones_active" not in content,
        )
        # --- stage1b-revision: no entry-point category checklist ---
        runner.check(
            "stage1b-revision: stage1b_system.j2 does not contain 'User input surfaces'",
            "User input surfaces" not in content,
        )
        runner.check(
            "stage1b-revision: stage1b_system.j2 does not contain 'Entry point category checklist'",
            "Entry point category checklist" not in content,
        )
    else:
        runner.check(
            "stage1b-revision: stage1b_system.j2 exists",
            False,
            "File not found",
        )

    # --- stage1b-revision: user prompt has no loss-analysis context ---
    stage1b_user = PROMPTS_DIR / "stage1b_user.j2"
    if stage1b_user.exists():
        content = stage1b_user.read_text(encoding="utf-8")
        for marker in ("loss_analysis", "all_losses", "security_constraints"):
            runner.check(
                f"stage1b-revision: stage1b_user.j2 does not contain '{marker}'",
                marker not in content,
            )
    else:
        runner.check(
            "stage1b-revision: stage1b_user.j2 exists",
            False,
            "File not found",
        )

    # --- stage1b-revision: Stage1Profile model has no boolean fields ---
    # We inspect the source file for field declarations rather than
    # importing the model, to stay at the "file on disk" level.
    profile_model_path = (
        PROJECT_ROOT
        / "src"
        / "asago_scenario_generator"
        / "models"
        / "capability_profile.py"
    )
    if profile_model_path.exists():
        src = profile_model_path.read_text(encoding="utf-8")
        # Extract the Stage1Profile class body
        match = re.search(
            r"class Stage1Profile\(BaseModel\):(.*?)(?=\nclass |\Z)",
            src,
            re.DOTALL,
        )
        if match:
            class_body = match.group(1)
            for field in ("has_persistent_memory", "multi_agent", "hitl"):
                # Look for field declarations like:
                #   has_persistent_memory: bool = Field(
                # but NOT in to_capability_profile (which uses exclude=...)
                # or in comments.
                decl_pattern = rf"^\s*{field}\s*:\s*bool\s*=\s*Field"
                found = bool(re.search(decl_pattern, class_body, re.MULTILINE))
                runner.check(
                    f"stage1b-revision: Stage1Profile does not declare '{field}'",
                    not found,
                    f"Found declaration: {field}" if found else "",
                )
        else:
            runner.check(
                "stage1b-revision: Stage1Profile class found in source",
                False,
                "Could not locate class definition",
            )
    else:
        runner.check(
            "stage1b-revision: capability_profile.py exists",
            False,
            "File not found",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="End-to-end QA suite for Stage 1 split-and-reorder."
    )
    parser.add_argument(
        "--static",
        action="store_true",
        help="Run the static checks (the only mode; accepted for compatibility).",
    )
    parser.parse_args()

    runner = Stage1QARunner()
    print("=== Static checks (no LLM required) ===")
    run_static_checks(runner)
    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())

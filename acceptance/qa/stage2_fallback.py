"""End-to-end QA suite for the Stage 2 fallback regression fix (asago-scenario-generator-32aa).

This QA suite verifies the fix for the P1 regression where
``_assemble_with_fallback`` silently dropped all control actions and
feedback channels on the degraded (fallback) path because it passed
``responsibility_set.responsibilities`` (Call 2a output — no CAs/FBs)
to ``_sanitize_for_fallback`` and ``_strip_all_element_refs`` without
first assigning the CAs/FBs from the ``ControlElementSet`` (Call 2b
output) onto the responsibilities.

The fix: ``_assemble_with_fallback`` must call
``_assign_elements_to_responsibilities`` to attach CAs/FBs from the
``ControlElementSet`` onto the responsibilities BEFORE the sanitize
tier, so both the sanitize and strip tiers operate on the full
structure and preserve valid references while nullifying invalid ones.

Two execution modes:

1. **Static checks** (no LLM needed): inspect the source code of
   ``control_structure.py`` via AST analysis and run the acceptance
   feature through the acceptance runtime.  These verify the structural
   fix without requiring an LLM endpoint.

2. **Dynamic checks** (no LLM needed): invoke
   ``_assemble_with_fallback`` directly through the acceptance runtime
   with crafted inputs that trigger both the sanitize and strip tiers,
   and verify CAs/FBs are carried over with valid refs preserved and
   invalid refs nullified.

Usage::

    # Static checks only (fast, no LLM)
    uv run python acceptance/qa/stage2_fallback.py --static

    # Dynamic checks (no LLM, uses acceptance runtime)
    uv run python acceptance/qa/stage2_fallback.py --dynamic

    # All checks
    uv run python acceptance/qa/stage2_fallback.py --all

Exit codes:
    0 — all checks passed
    1 — one or more checks failed
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tempfile
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

SRC_FILE = (
    PROJECT_ROOT
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "system_model"
    / "control_structure.py"
)
ACCEPTANCE_RUNTIME = PROJECT_ROOT / "acceptance" / "acceptance_runtime.py"
FEATURE_IR = (
    PROJECT_ROOT / "build" / "acceptance" / "ir" / "sp1_merge_fallback_sanitize.json"
)
FEATURE_FILE = PROJECT_ROOT / "features" / "sp1_merge_fallback_sanitize.feature"


# ---------------------------------------------------------------------------
# Compatibility adapter
# ---------------------------------------------------------------------------


class FallbackQARunner(QARunner):
    """Shared harness runner with the fallback suite's deferred banner summary."""

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
# AST helpers
# ---------------------------------------------------------------------------


def _parse_source() -> ast.Module:
    """Parse the control_structure.py source file into an AST."""
    source = SRC_FILE.read_text(encoding="utf-8")
    return ast.parse(source, filename=str(SRC_FILE))


def _find_function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    """Find a top-level function definition by name."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _function_source(func: ast.FunctionDef) -> str:
    """Return the source text of a function node."""
    source = SRC_FILE.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    # ast.lineno is 1-based; end_lineno is inclusive
    start = func.lineno - 1
    end = func.end_lineno if func.end_lineno else func.lineno
    return "".join(lines[start:end])


def _calls_in_function(func: ast.FunctionDef) -> list[ast.Call]:
    """Return all Call nodes inside a function body."""
    return [n for n in ast.walk(func) if isinstance(n, ast.Call)]


def _call_name(call: ast.Call) -> str:
    """Return the textual name of a call's function."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _temporary_run_dir(prefix: str) -> tempfile.TemporaryDirectory[str]:
    """Create an isolated run directory that is removed after the check."""
    return tempfile.TemporaryDirectory(prefix=prefix)


# ---------------------------------------------------------------------------
# Static checks — AST analysis of _assemble_with_fallback
# ---------------------------------------------------------------------------


def run_static_checks(runner: QARunner) -> None:
    """Run AST-based static checks on the fallback fix."""

    tree = _parse_source()

    # --- Check 1: _assemble_with_fallback exists ---
    func = _find_function(tree, "_assemble_with_fallback")
    runner.check(
        "fallback-fix-static-01: _assemble_with_fallback is defined",
        func is not None,
        "" if func else "Function not found in control_structure.py",
    )
    if func is None:
        return  # Cannot proceed without the function

    calls = _calls_in_function(func)

    # --- Check 2: _enrich_responsibilities is called ---
    # The cleaner (commit 604f28c) extracted the CA/FB assignment into the
    # ``_enrich_responsibilities`` helper for DRY.  ``_assemble_with_fallback``
    # now calls ``_enrich_responsibilities`` (which internally calls
    # ``_assign_elements_to_responsibilities`` twice — once for CAs, once for
    # FBs) instead of calling ``_assign_elements_to_responsibilities`` directly.
    has_enrich = any(_call_name(c) == "_enrich_responsibilities" for c in calls)
    runner.check(
        "fallback-fix-static-02: _assemble_with_fallback calls _enrich_responsibilities (assigns CAs/FBs before sanitization)",
        has_enrich,
        "CAs/FBs must be assigned onto responsibilities before sanitization",
    )

    # --- Check 3: enrichment happens before the fallback helper ---
    # The fallback helper owns the sanitize/strip tiers after the cleaner
    # extracted them from _assemble_with_fallback. Enrichment must therefore
    # happen before the helper is called.
    source = _function_source(func)
    enrich_pos = source.find("_enrich_responsibilities")
    fallback_pos = source.find("_fallback_control_structure")
    enrich_before_fallback = (
        enrich_pos != -1 and fallback_pos != -1 and enrich_pos < fallback_pos
    )
    runner.check(
        "fallback-fix-static-03: _enrich_responsibilities is called before fallback sanitization",
        enrich_before_fallback,
        f"enrich_pos={enrich_pos}, fallback_pos={fallback_pos}",
    )

    # --- Check 4: the fallback helper owns the further-degraded strip tier ---
    fallback_func = _find_function(tree, "_fallback_control_structure")
    fallback_source = _function_source(fallback_func) if fallback_func else ""
    strip_pos = fallback_source.find("_strip_all_element_refs")
    enrich_before_strip = (
        enrich_before_fallback and fallback_func is not None and strip_pos != -1
    )
    runner.check(
        "fallback-fix-static-04: enriched responsibilities reach the further-degraded strip tier",
        enrich_before_strip,
        f"enrich_pos={enrich_pos}, fallback_pos={fallback_pos}, strip_pos={strip_pos}",
    )

    # --- Check 5: _enrich_responsibilities assigns both CAs and FBs ---
    # The helper must call _assign_elements_to_responsibilities twice:
    # once for control_actions (ca_id → control_actions) and once for
    # feedback_channels (fb_id → feedback_channels).
    enrich_func = _find_function(tree, "_enrich_responsibilities")
    if enrich_func is not None:
        enrich_calls = _calls_in_function(enrich_func)
        assign_calls = [
            c
            for c in enrich_calls
            if _call_name(c) == "_assign_elements_to_responsibilities"
        ]
        runner.check(
            "fallback-fix-static-05: _enrich_responsibilities calls _assign_elements_to_responsibilities at least twice (CAs and FBs)",
            len(assign_calls) >= 2,
            f"Found {len(assign_calls)} call(s); expected >= 2",
        )
    else:
        runner.check(
            "fallback-fix-static-05: _enrich_responsibilities calls _assign_elements_to_responsibilities at least twice (CAs and FBs)",
            False,
            "_enrich_responsibilities not found",
        )

    # --- Check 6: _fallback_control_structure owns the sanitize tier ---
    fallback_calls = _calls_in_function(fallback_func) if fallback_func else []
    has_sanitize = any(
        _call_name(c) == "_sanitize_for_fallback" for c in fallback_calls
    )
    runner.check(
        "fallback-fix-static-06: _sanitize_for_fallback is still called in the fallback helper",
        has_sanitize,
        "Sanitize tier must still exist in _fallback_control_structure",
    )

    # --- Check 7: _fallback_control_structure owns the strip tier ---
    has_strip = any(_call_name(c) == "_strip_all_element_refs" for c in fallback_calls)
    runner.check(
        "fallback-fix-static-07: _strip_all_element_refs is still called in the fallback helper",
        has_strip,
        "Strip tier must still exist in _fallback_control_structure",
    )

    # --- Check 8: The fallback does NOT pass responsibility_set.responsibilities directly to sanitize ---
    # The old bug passed responsibility_set.responsibilities (no CAs/FBs) to
    # sanitize.  The fix assigns CAs/FBs onto the responsibilities first, then
    # passes the enriched responsibilities (a local variable).  We verify
    # that _sanitize_for_fallback is NOT called with
    # responsibility_set.responsibilities as the first argument.
    buggy_sanitize = re.search(
        r"_sanitize_for_fallback\s*\(\s*responsibility_set\.responsibilities",
        source,
    )
    runner.check(
        "fallback-fix-static-08: _sanitize_for_fallback does not receive raw responsibility_set.responsibilities",
        buggy_sanitize is None,
        "The old bug pattern (passing raw responsibility_set.responsibilities to sanitize) must be removed",
    )

    buggy_strip = re.search(
        r"_strip_all_element_refs\s*\(\s*responsibility_set\.responsibilities",
        source,
    )
    runner.check(
        "fallback-fix-static-09: _strip_all_element_refs does not receive raw responsibility_set.responsibilities",
        buggy_strip is None,
        "The old bug pattern (passing raw responsibility_set.responsibilities to strip) must be removed",
    )

    # --- Check 10: Acceptance feature file contains Sanitize-11 scenario ---
    feature_text = FEATURE_FILE.read_text(encoding="utf-8")
    has_sanitize_11 = "Sanitize-11" in feature_text
    runner.check(
        "fallback-fix-static-10: feature file contains Sanitize-11 strip-tier carry-over scenario",
        has_sanitize_11,
        "Sanitize-11 verifies the strip tier carries over CAs/FBs from Call 2b",
    )


# ---------------------------------------------------------------------------
# Dynamic checks — exercise _assemble_with_fallback via acceptance runtime
# ---------------------------------------------------------------------------


def run_dynamic_checks(runner: QARunner, feature_ir: Path = FEATURE_IR) -> None:
    """Run dynamic checks through the acceptance runtime and direct invocation."""

    # --- Check D1: Acceptance feature IR passes (all scenarios green after fix) ---
    if not ACCEPTANCE_RUNTIME.exists():
        runner.check(
            "fallback-fix-dynamic-01: acceptance runtime is available",
            False,
            f"Missing: {ACCEPTANCE_RUNTIME}",
        )
    elif not feature_ir.exists():
        runner.check(
            "fallback-fix-dynamic-01: feature IR is available",
            False,
            f"Missing: {feature_ir}",
        )
    else:
        sys.path.insert(0, str(ACCEPTANCE_RUNTIME.parent))
        try:
            from acceptance_runtime import execute_ir

            passed, output = execute_ir(str(feature_ir))
            # After the fix, all scenarios should pass.
            # Before the fix, 7 instances are red (Sanitize-01 ex2/3,
            # Sanitize-04 ex2/3, Sanitize-06 ex1, Sanitize-11 ex1/2).
            fail_lines = [
                line for line in output.splitlines() if line.startswith("FAIL")
            ]
            runner.check(
                "fallback-fix-dynamic-01: all acceptance scenarios pass (Sanitize-01 through Sanitize-11)",
                passed,
                f"{len(fail_lines)} failing: {fail_lines[:5]}",
            )
        except Exception as e:
            runner.check(
                "fallback-fix-dynamic-01: acceptance runtime executes without error",
                False,
                str(e),
            )

    # --- Check D2: Direct invocation — sanitize tier preserves valid CA ref ---
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    try:
        from asago_scenario_generator.stpa.models.control_structure import (
            ControlAction,
            ControlledProcess,
            ElementRef,
            FeedbackChannel,
            ProcessModelPart,
            ReferenceType,
            Responsibility,
        )
        from asago_scenario_generator.stpa.system_model.control_structure import (
            ControlElementSet,
            ResponsibilitySet,
            _assemble_with_fallback,
        )

        # Build a ResponsibilitySet with RESP-1 (PM only, no CAs/FBs)
        rs = ResponsibilitySet(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="Controller",
                    process_model_parts=[
                        ProcessModelPart(
                            pm_id="PM-1-1",
                            description="State",
                        ),
                    ],
                    control_actions=[],
                    feedback_channels=[],
                )
            ]
        )

        # Build a ControlElementSet with a CA that has a VALID target (CP-1)
        # and an FB with an INVALID source (RESP-99) to trigger the fallback.
        ces = ControlElementSet(
            control_actions=[
                ControlAction(
                    ca_id="CA-1-1",
                    description="Action",
                    target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
                ),
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="Feedback",
                    updates="PM-1-1",
                    source=ElementRef(type=ReferenceType.responsibility, id="RESP-99"),
                ),
            ],
            controlled_processes=[
                ControlledProcess(cp_id="CP-1", description="Process"),
            ],
        )

        with _temporary_run_dir("qa_fallback_") as tmpdir:
            cs, warnings = _assemble_with_fallback(rs, ces, Path(tmpdir), "qa-model")

        resp = cs.responsibilities[0]

        # The CA-1-1 must be present on the responsibility (carried over)
        ca_ids = [ca.ca_id for ca in resp.control_actions]
        runner.check(
            "fallback-fix-dynamic-02: sanitize tier carries over CA-1-1 from ControlElementSet",
            "CA-1-1" in ca_ids,
            f"control_actions on RESP-1: {ca_ids}",
        )

        # The CA-1-1 target (CP-1) must be preserved (valid ref)
        ca = next((c for c in resp.control_actions if c.ca_id == "CA-1-1"), None)
        if ca is not None:
            runner.check(
                "fallback-fix-dynamic-03: sanitize tier preserves valid CA target (CP-1)",
                ca.target is not None and ca.target.id == "CP-1",
                f"CA-1-1 target: {ca.target}",
            )
        else:
            runner.check(
                "fallback-fix-dynamic-03: sanitize tier preserves valid CA target (CP-1)",
                False,
                "CA-1-1 not found on responsibility",
            )

        # The FB-1-1 must be present on the responsibility (carried over)
        fb_ids = [fb.fb_id for fb in resp.feedback_channels]
        runner.check(
            "fallback-fix-dynamic-04: sanitize tier carries over FB-1-1 from ControlElementSet",
            "FB-1-1" in fb_ids,
            f"feedback_channels on RESP-1: {fb_ids}",
        )

        # The FB-1-1 source (RESP-99) must be nullified (invalid ref)
        fb = next((f for f in resp.feedback_channels if f.fb_id == "FB-1-1"), None)
        if fb is not None:
            runner.check(
                "fallback-fix-dynamic-05: sanitize tier nullifies invalid FB source (RESP-99 → None)",
                fb.source is None,
                f"FB-1-1 source: {fb.source}",
            )
        else:
            runner.check(
                "fallback-fix-dynamic-05: sanitize tier nullifies invalid FB source (RESP-99 → None)",
                False,
                "FB-1-1 not found on responsibility",
            )

        # Warnings must include a sanitization warning (not just the assembly
        # failure error) that mentions stripping FB-1-1's source.
        has_strip_warning = any(
            "Stripped" in w and "FB-1-1" in w and "source" in w for w in warnings
        )
        runner.check(
            "fallback-fix-dynamic-06: sanitize tier logs strip warning for FB-1-1 source",
            has_strip_warning,
            f"warnings: {warnings}",
        )

    except Exception as e:
        import traceback

        runner.check(
            "fallback-fix-dynamic-02: sanitize tier direct invocation",
            False,
            f"{e}\n{traceback.format_exc()}",
        )

    # --- Check D3: Direct invocation — strip tier carries over CAs/FBs ---
    try:
        # Build a ResponsibilitySet with RESP-1 and a duplicate RESP-1
        # to force the strip tier (sanitize succeeds but ControlStructure
        # validation fails due to duplicate resp_id).
        rs = ResponsibilitySet(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="Controller",
                    process_model_parts=[
                        ProcessModelPart(
                            pm_id="PM-1-1",
                            description="State",
                            feedback_source=ElementRef(
                                type=ReferenceType.controlled_process,
                                id="FB-1-1",
                            ),
                        ),
                    ],
                    control_actions=[],
                    feedback_channels=[],
                ),
                # Duplicate RESP-1 — forces strip tier
                Responsibility(
                    resp_id="RESP-1",
                    description="Duplicate",
                    process_model_parts=[],
                    control_actions=[],
                    feedback_channels=[],
                ),
            ]
        )

        # ControlElementSet with CA-1-1 (valid target CP-1) and FB-1-1
        ces = ControlElementSet(
            control_actions=[
                ControlAction(
                    ca_id="CA-1-1",
                    description="Action",
                    target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
                ),
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="Feedback",
                    updates="PM-1-1",
                    source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
                ),
            ],
            controlled_processes=[
                ControlledProcess(cp_id="CP-1", description="Process"),
            ],
        )

        with _temporary_run_dir("qa_fallback_strip_") as tmpdir:
            cs, warnings = _assemble_with_fallback(rs, ces, Path(tmpdir), "qa-model")

        # The strip tier should produce a ControlStructure with one RESP-1
        # (deduplicated), carrying over CA-1-1 and FB-1-1 with all refs None.
        resp_ids = [r.resp_id for r in cs.responsibilities]
        runner.check(
            "fallback-fix-dynamic-07: strip tier deduplicates responsibilities",
            resp_ids.count("RESP-1") == 1,
            f"resp_ids: {resp_ids}",
        )

        resp = cs.responsibilities[0]
        ca_ids = [ca.ca_id for ca in resp.control_actions]
        runner.check(
            "fallback-fix-dynamic-08: strip tier carries over CA-1-1 from ControlElementSet",
            "CA-1-1" in ca_ids,
            f"control_actions on RESP-1: {ca_ids}",
        )

        ca = next((c for c in resp.control_actions if c.ca_id == "CA-1-1"), None)
        if ca is not None:
            runner.check(
                "fallback-fix-dynamic-09: strip tier strips CA-1-1 target to None",
                ca.target is None,
                f"CA-1-1 target: {ca.target}",
            )
        else:
            runner.check(
                "fallback-fix-dynamic-09: strip tier strips CA-1-1 target to None",
                False,
                "CA-1-1 not found",
            )

        fb_ids = [fb.fb_id for fb in resp.feedback_channels]
        runner.check(
            "fallback-fix-dynamic-10: strip tier carries over FB-1-1 from ControlElementSet",
            "FB-1-1" in fb_ids,
            f"feedback_channels on RESP-1: {fb_ids}",
        )

        fb = next((f for f in resp.feedback_channels if f.fb_id == "FB-1-1"), None)
        if fb is not None:
            runner.check(
                "fallback-fix-dynamic-11: strip tier strips FB-1-1 source to None",
                fb.source is None,
                f"FB-1-1 source: {fb.source}",
            )
        else:
            runner.check(
                "fallback-fix-dynamic-11: strip tier strips FB-1-1 source to None",
                False,
                "FB-1-1 not found",
            )

    except Exception as e:
        import traceback

        runner.check(
            "fallback-fix-dynamic-08: strip tier direct invocation",
            False,
            f"{e}\n{traceback.format_exc()}",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="QA suite for the Stage 2 fallback regression fix (asago-scenario-generator-32aa)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--static", action="store_true", help="Run static checks only")
    mode.add_argument("--dynamic", action="store_true", help="Run dynamic checks only")
    mode.add_argument("--all", action="store_true", help="Run all checks")
    parser.add_argument(
        "--feature-ir",
        type=Path,
        default=FEATURE_IR,
        help="Acceptance IR to execute; defaults to the generated snapshot",
    )
    args = parser.parse_args()

    if not any([args.static, args.dynamic, args.all]):
        args.all = True

    runner = FallbackQARunner()

    if args.static or args.all:
        print("--- Static checks (AST analysis) ---")
        run_static_checks(runner)

    if args.dynamic or args.all:
        print("--- Dynamic checks (acceptance runtime + direct invocation) ---")
        run_dynamic_checks(runner, args.feature_ir)

    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())

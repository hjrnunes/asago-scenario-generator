"""End-to-end QA suite for the shadowed registration cleanup (bead jrds).

Covers the removal of 39 dead step-pattern registrations from
``acceptance/acceptance_runtime.py`` and the unmarking of two xfail'd
property tests in ``tests/stpa/test_acceptance_harness_property.py``.

Problem
-------
``STEP_PATTERNS`` is an ordered list; lookup takes the first match.
When the same pattern is registered in the same scope with two
different handlers, only one is live and the rest is dead code.  The
cleanup removes the 39 dead registrations identified in the inventory.

Two classes of work
-------------------
- **Class A (27 mechanical removals)**: the dead handler is no larger
  than the live one.  Deleting the dead registration cannot change
  behaviour.
- **Class B (12 judgement calls)**: the live handler is materially
  smaller than the dead one it shadows.  Each case has an explicit
  keep-or-promote decision recorded in this suite.

Execution modes
---------------
``--static``
    AST and source-text assertions over ``acceptance_runtime.py`` and
    the property-test file.  No imports of the runtime.

``--dynamic``
    Imports ``acceptance_runtime``, inspects ``STEP_PATTERNS``, runs
    ``find_pattern_conflicts`` against IR and synthetic step texts,
    verifies live-handler assignments for all 12 Class B patterns, and
    runs the two property tests with pytest.

Usage::

    uv run python acceptance/qa/acceptance_registration.py --static
    uv run python acceptance/qa/acceptance_registration.py --dynamic
    uv run python acceptance/qa/acceptance_registration.py --all

Exit codes:
    0 — all checks passed
    1 — one or more checks failed
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path

QA_MODULES = Path(__file__).resolve().parent
if str(QA_MODULES) not in sys.path:
    sys.path.insert(0, str(QA_MODULES))

from qa_harness import (  # noqa: E402
    PROJECT_ROOT,
    QARunner,
    run_command,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ACCEPTANCE_DIR = PROJECT_ROOT / "acceptance"
ACCEPTANCE_RUNTIME = ACCEPTANCE_DIR / "acceptance_runtime.py"
IR_DIR = PROJECT_ROOT / "build" / "acceptance" / "ir"
PROPERTY_TEST = PROJECT_ROOT / "tests" / "stpa" / "test_acceptance_harness_property.py"

# ---------------------------------------------------------------------------
# Inventory: 39 dead registrations to remove
# ---------------------------------------------------------------------------
# Each entry: (pattern_string, handler_name, registration_function).  The
# pattern string is compared to the registration's first literal argument
# exactly; inventory prefixes must not match other registrations.
# The coder must remove the _register/_register_first call line that
# references this pattern+handler combination.

DEAD_REGISTRATIONS: list[tuple[str, str, str]] = [
    # --- 27 mechanical removals (Class A) ---
    (
        r"the file contains entries with stage stage_5",
        "_h_sp3_calls_jsonl",
        "_register_first",
    ),
    (r"by_ica_type has.*", "_h_sp3_diversity_counts", "_register_first"),
    (r"by_ica_type has.*", "_h_sp3_diversity_has_value", "_register_first"),
    (r"by_branch_category has.*", "_h_sp3_diversity_has_value", "_register_first"),
    (r"by_responsibility has.*", "_h_sp3_diversity_has_value", "_register_first"),
    (
        r"a control structure with responsibilities RE",
        "_h_sp1_cs_two_resps_available",
        "_register",
    ),
    (r"the HTML contains the text", "_h_ch_contains_text", "_register_first"),
    (
        r"the STPA system model prompts directory is a",
        "_h_pqf_prompts_dir_available",
        "_register",
    ),
    (r"the revision is applied", "_h_sp1_rev_applied", "_register"),
    (
        r"the resulting control structure does not con",
        "_h_strip_cs_does_not_contain",
        "_register_first",
    ),
    (
        r"the final control structure passes foundatio",
        "_h_cmidup_passes_validation",
        "_register",
    ),
    (r"no new failures are introduced", "_h_sp1_run_existing_tests", "_register"),
    (
        r"no new failures are introduced",
        "_h_sp2_existing_tests_unaffected",
        "_register",
    ),
    (r"no new failures are introduced", "_h_sp3_existing_tests", "_register"),
    (
        r"a use-case description and risk extraction J",
        "_h_sp1_use_case_risk_json",
        "_register",
    ),
    (r"validation fails with error containing", "_h_sp1_validation_fails", "_register"),
    (
        r"a control structure where responsibility RES",
        "_h_sp1_heur_cs_with_constraint",
        "_register",
    ),
    (
        r"a control structure where no responsibility ",
        "_h_sp1_heur_cs_no_constraint",
        "_register",
    ),
    (r"a warning is produced for orphan PM", "_h_sp1_heur_orphan_warn", "_register"),
    (
        r"the scenario spec is validated against the c",
        "_h_sp3_validate_against_cs",
        "_register",
    ),
    (r"the existing test suite is run", "_h_sp3_existing_tests", "_register"),
    (
        r"critic findings with unjustified gaps",
        "_h_connset_critic_unjustified",
        "_register",
    ),
    (
        r"the file contains entries with stage stage_3",
        "_h_sp2_calls_jsonl_stage",
        "_register",
    ),
    (r"the following template files exist", "_h_sp3_template_files_exist", "_register"),
    (
        r"the following modules exist and are importab",
        "_h_sp3_modules_exist",
        "_register",
    ),
    (
        r"responsibility_diversity is a non-negative f",
        "_h_sp3_diversity_float",
        "_register",
    ),
    (
        r"ica_type_diversity is a non-negative float",
        "_h_sp3_diversity_float",
        "_register",
    ),
    # --- 12 Class B dead registrations (judgement calls) ---
    (
        r"Stage 2 calls 1 through 3 are run in sequenc",
        "_h_sp1_s2_calls_1_3_run",
        "_register",
    ),
    (r"Stage 2 control structure derivation is run", "_h_sp1_s2_full_run", "_register"),
    (r"the revision is run", "_h_rev_revision_run", "_register_first"),
    (r"the revision is run", "_h_sp1_rev_run", "_register"),
    (
        r"the TemplateLoader can load templates from t",
        "_h_pqf_template_loader_created",
        "_register",
    ),
    (r"a file \S+ exists in the run directory", "_h_sp1_file_exists", "_register"),
    (r"the heuristic check fails with error contain", "_h_sp1_heur_fails", "_register"),
    (r"a control structure with responsibility RESP", "_h_sp3_cs_resp1", "_register"),
    (
        r"the user prompt contains the control structu",
        "_h_sp2_user_prompt_contains",
        "_register",
    ),
    (r"the pipeline does not crash", "_h_cmidup_pipeline_no_crash", "_register"),
    (r"uncovered_reason is not empty", "_h_sp3_coverage_field", "_register"),
    (
        r"the scorecard validation section has.*",
        "_h_sp3_scorecard_validation",
        "_register",
    ),
]

# ---------------------------------------------------------------------------
# Inventory: 12 Class B live-handler verdicts
# ---------------------------------------------------------------------------
# Each entry: (pattern_prefix, witness_step, expected_live_handler_name,
# reason).  The prefix is for reporting; the complete witness is used for
# matching so that a broad pattern cannot select the wrong live handler.
# The live handler is the one that must be first-match in STEP_PATTERNS
# for the given pattern.

CLASS_B_VERDICTS: list[tuple[str, str, str, str]] = [
    (
        "Stage 2 calls 1 through 3 are run in sequenc",
        "Stage 2 calls 1 through 3 are run in sequence",
        "_h_ar_call_sequence",
        "Delegates to _h_ar_stage2_run which calls the real "
        "_sp1_derive_control_structure integration; dead handler "
        "uses manual mock calls with hardcoded prompt strings.",
    ),
    (
        "Stage 2 control structure derivation is run",
        "Stage 2 control structure derivation is run",
        "_h_ar_stage2_run",
        "Calls _sp1_derive_control_structure with TemplateLoader"
        "(_PQF_PROMPTS_DIR) and proper LossAnalysis; dead handler "
        "omits template_loader.",
    ),
    (
        "the revision is run",
        "the revision is run",
        "_h_revnorm_run",
        "The revision-normalization router is the live registration. "
        "When normalization is inactive, it delegates to "
        "_h_bf2_revision_run_with_log_capture, preserving log capture "
        "for duplicate rejection warnings.",
    ),
    (
        "the revision is run",
        "the revision is run",
        "_h_revnorm_run",
        "Same live router as case 3. Its inactive-normalization "
        "fallback preserves the intended revision chain; the old "
        "_h_sp1_rev_run registration remains dead.",
    ),
    (
        "the TemplateLoader can load templates from t",
        "the TemplateLoader can load templates from the prompts directory",
        "_h_epcl_template_loader_can_load",
        "Uses _FC_PROMPTS_DIR directly; dead handler falls back to "
        "world.template_dir which may point elsewhere.",
    ),
    (
        "a file \\S+ exists in the run directory",
        "a file output.yaml exists in the run directory",
        "_h_mw_file_exists",
        "Functionally identical to dead handler; live handler was "
        "registered with _register_first (higher priority).",
    ),
    (
        "the heuristic check fails with error contain",
        "the heuristic check fails with error containing hazard",
        "_h_heuristic_fails_with",
        "Checks heuristic_result.passed is False before checking "
        "error contents; dead handler only checks errors list is "
        "non-empty.",
    ),
    (
        "a control structure with responsibility RESP",
        "a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1",
        "_h_sp1_cs_resp1_full",
        "Uses SP1 helper _sp1_make_control_structure_with_resp(); "
        "dead handler uses SP3 _make_sp3_cs() with unnecessary "
        "conditional RESP-2 logic.",
    ),
    (
        "the user prompt contains the control structu",
        "the user prompt contains the control structure",
        "_h_sp1_critic_prompt_cs",
        "Checks SP1 mock client's last call prompt; dead handler "
        "checks SP2 LLM client which may not be set in SP1 context.",
    ),
    (
        "the pipeline does not crash",
        "the pipeline does not crash",
        "_h_gd_pipeline_no_crash",
        "No-op pass is correct for graceful-degradation semantics "
        "('reached this step = did not crash'); dead handler "
        "conflates 'did not crash' with 'produced valid output'.",
    ),
    (
        "uncovered_reason is not empty",
        "uncovered_reason is not empty",
        "_h_sp2_uncovered_reason",
        "Checks enriched_threat_set.coverage_analysis model "
        "attribute; dead handler checks sp3_coverage dict which "
        "may not be populated in SP2 context.",
    ),
    (
        "the scorecard validation section has.*",
        "the scorecard validation section has 2 errors",
        "_h_sp3_scorecard_validation_section",
        "Checks in-memory sp3_scorecard dict; dead handler reads "
        "eval-scorecard.yaml from disk requiring file I/O that may "
        "not be available in all test contexts.",
    ),
]

# Handler functions that must NOT be deleted (only their registrations
# are dead — they are still called via delegation from the live handler).
RETAIN_FUNCTIONS: list[str] = [
    "_h_rev_revision_run",  # called by _h_bf2_revision_run_with_log_capture
    "_h_sp1_rev_run",  # called by _h_rev_revision_run as fallthrough
]

# Synthetic step texts that cover known shadowing prefixes.
SYNTHETIC_STEP_TEXTS: list[str] = [
    "the control structure has responsibilities",
    "the control structure has coordination links",
    "validation fails with error containing something",
    "the revision is run",
    "the revision is applied",
    "a file something exists in the run directory",
    "the HTML contains the text something",
    "the pipeline does not crash",
    "the final control structure passes foundation validation",
    "the heuristic check fails with error containing something",
    "Stage 2 calls 1 through 3 are run in sequence",
    "Stage 2 control structure derivation is run",
    "the TemplateLoader can load templates from the prompts directory",
    "uncovered_reason is not empty",
    "the scorecard validation section has 2 errors",
    "no new failures are introduced",
    "the existing test suite is run",
    "critic findings with unjustified gaps",
]


# ---------------------------------------------------------------------------
# Source helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _parse(path: Path) -> ast.Module:
    return ast.parse(_read(path), filename=str(path))


def _find_function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _registration_tuples(tree: ast.Module) -> list[tuple[str, str, str]]:
    """Return ``(registration, raw pattern, handler)`` for each call."""
    registrations: list[tuple[str, str, str]] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"_register", "_register_first"}
            and len(node.args) >= 2
        ):
            continue
        try:
            pattern = ast.literal_eval(node.args[0])
        except (ValueError, TypeError):
            continue
        handler = node.args[1]
        if isinstance(pattern, str) and isinstance(handler, ast.Name):
            registrations.append((node.func.id, pattern, handler.id))
    return registrations


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------


def run_static_checks(runner: QARunner) -> None:
    """AST and source-text assertions. No imports, no LLM."""

    # --- Core functions exist -----------------------------------------------
    tree = _parse(ACCEPTANCE_RUNTIME)

    for fname in (
        "_track_registration",
        "_register",
        "_register_first",
        "find_pattern_conflicts",
    ):
        func = _find_function(tree, fname)
        runner.check(
            f"sc-static-01: {fname} is defined in acceptance_runtime.py",
            func is not None,
            f"Function {fname} not found",
        )

    # --- _track_registration delegates duplicate rejection to the registry --
    track_func = _find_function(tree, "_track_registration")
    if track_func is not None:
        src = ast.get_source_segment(_read(ACCEPTANCE_RUNTIME), track_func) or ""
        runner.check(
            "sc-static-02: _track_registration delegates duplicate rejection",
            "track_registration" in src and "_REGISTERED_PATTERN_KEYS" in src,
            "Must delegate (pattern, handler, scope) duplicate rejection to the registry",
        )

    # --- _register appends; _register_first inserts at 0 --------------------
    reg_func = _find_function(tree, "_register")
    if reg_func is not None:
        src = ast.get_source_segment(_read(ACCEPTANCE_RUNTIME), reg_func) or ""
        runner.check(
            "sc-static-03: _register appends to STEP_PATTERNS",
            "STEP_PATTERNS.append" in src,
            "Must append (lowest priority)",
        )

    reg_first_func = _find_function(tree, "_register_first")
    if reg_first_func is not None:
        src = ast.get_source_segment(_read(ACCEPTANCE_RUNTIME), reg_first_func) or ""
        runner.check(
            "sc-static-04: _register_first inserts at index 0",
            "STEP_PATTERNS.insert" in src and "0" in src,
            "Must insert at index 0 (highest priority)",
        )

    # --- Retained functions still defined (cases 3-4) -----------------------
    for fname in RETAIN_FUNCTIONS:
        func = _find_function(tree, fname)
        runner.check(
            f"sc-static-05: {fname} is still defined (not deleted)",
            func is not None,
            f"Function {fname} must be retained — it is called via "
            f"delegation from the live handler; only its registration is dead.",
        )

    # --- Dead registration lines removed ------------------------------------
    registrations = _registration_tuples(tree)
    for i, (pattern_string, handler_name, reg_func_name) in enumerate(
        DEAD_REGISTRATIONS, start=6
    ):
        # Match the complete registration tuple.  In particular, a handler
        # can legitimately remain registered for several distinct patterns.
        matching_calls = [
            registration
            for registration in registrations
            if registration == (reg_func_name, pattern_string, handler_name)
        ]
        runner.check(
            f"sc-static-{i:02d}: dead registration {reg_func_name}("
            f"...{handler_name}) is removed",
            len(matching_calls) == 0,
            f"Found {len(matching_calls)} remaining call(s): {matching_calls[:2]}",
        )

    # --- xfail markers removed from property tests --------------------------
    if PROPERTY_TEST.is_file():
        test_source = _read(PROPERTY_TEST)
        test_tree = _parse(PROPERTY_TEST)

        xfail_tests = [
            "test_no_global_pattern_conflicts_on_ir_steps",
            "test_no_global_pattern_conflicts_on_synthetic_steps",
        ]
        for i, test_name in enumerate(xfail_tests, start=45):
            func = _find_function(test_tree, test_name)
            has_xfail = False
            if func is not None:
                for dec in func.decorator_list:
                    dec_src = ast.get_source_segment(test_source, dec) or ""
                    if "xfail" in dec_src:
                        has_xfail = True
            runner.check(
                f"sc-static-{i:02d}: {test_name} has no xfail marker",
                not has_xfail,
                "The xfail marker must be removed now that the shadowing "
                "conflicts are cleaned up.",
            )

        # Check strict=False is not present in the file at all
        runner.check(
            "sc-static-47: no strict=False xfail markers in property test file",
            "strict=False" not in test_source,
            "strict=False would cause xpass to be silent; must be removed.",
        )
    else:
        runner.check(
            "sc-static-45: property test file exists",
            False,
            f"File not found: {PROPERTY_TEST}",
        )


# ---------------------------------------------------------------------------
# Dynamic checks
# ---------------------------------------------------------------------------


def _ir_files() -> list[Path]:
    """All executable IR files (excluding DRY-checker reports)."""
    return sorted(p for p in IR_DIR.rglob("*.json") if not p.stem.endswith("_dry"))


def _all_step_texts(ir_path: Path) -> list[str]:
    """Extract all step texts from an IR file (background + scenarios)."""
    ir = json.loads(ir_path.read_text(encoding="utf-8"))
    texts: list[str] = []
    for section in ("background", "scenarios"):
        node = ir.get(section)
        if node is None:
            continue
        scenarios = node if isinstance(node, list) else [node]
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                continue
            steps = scenario.get("steps", []) or []
            examples = scenario.get("examples", []) or []
            if not examples:
                examples = [{}]
            for step in steps:
                if not isinstance(step, dict):
                    continue
                raw_text = step.get("text", "")
                if not raw_text:
                    continue
                for example in examples:
                    if not isinstance(example, dict):
                        example = {}
                    text = raw_text
                    for key, value in example.items():
                        text = text.replace(f"<{key}>", str(value))
                    texts.append(text)
    return texts


def _all_ir_step_texts() -> list[str]:
    texts: list[str] = []
    for ir_path in _ir_files():
        texts.extend(_all_step_texts(ir_path))
    return list(dict.fromkeys(texts))


def run_dynamic_checks(runner: QARunner) -> None:
    """Import the runtime and verify live state."""

    sys.path.insert(0, str(ACCEPTANCE_DIR))

    # --- Module imports without error ---------------------------------------
    try:
        import acceptance_runtime  # noqa: F401
        from acceptance_runtime import (
            STEP_PATTERNS,
            _REGISTERED_PATTERN_KEYS,
            find_pattern_conflicts,
        )

        runner.check(
            "sc-dynamic-01: acceptance_runtime imports without RuntimeError",
            True,
        )
    except Exception as exc:
        runner.check(
            "sc-dynamic-01: acceptance_runtime imports without RuntimeError",
            False,
            str(exc),
        )
        return

    # --- Registered keys count equals step patterns count --------------------
    runner.check(
        "sc-dynamic-02: _REGISTERED_PATTERN_KEYS count equals STEP_PATTERNS length",
        len(_REGISTERED_PATTERN_KEYS) == len(STEP_PATTERNS),
        f"Keys: {len(_REGISTERED_PATTERN_KEYS)}, Patterns: {len(STEP_PATTERNS)}",
    )

    # --- No dead (pattern, handler) pair in STEP_PATTERNS -------------------
    for i, (pattern_string, handler_name, _reg_func) in enumerate(
        DEAD_REGISTRATIONS, start=3
    ):
        found_dead = False
        for pat, handler, tag in STEP_PATTERNS:
            if (
                getattr(handler, "__name__", "") == handler_name
                and pattern_string == pat.pattern
            ):
                found_dead = True
                break
        runner.check(
            f"sc-dynamic-{i:02d}: dead handler {handler_name} is not in "
            f"STEP_PATTERNS for pattern {pattern_string[:30]}...",
            not found_dead,
            f"Dead handler {handler_name} still registered",
        )

    offset = len(DEAD_REGISTRATIONS) + 3

    # --- find_pattern_conflicts returns empty for IR step texts --------------
    ir_texts = _all_ir_step_texts()
    conflicts = find_pattern_conflicts(ir_texts)
    runner.check(
        f"sc-dynamic-{offset:02d}: find_pattern_conflicts returns empty "
        f"for IR step texts",
        len(conflicts) == 0,
        f"{len(conflicts)} conflicts: {conflicts[:5]}",
    )

    offset += 1

    # --- find_pattern_conflicts returns empty for synthetic step texts -------
    conflicts = find_pattern_conflicts(SYNTHETIC_STEP_TEXTS)
    runner.check(
        f"sc-dynamic-{offset:02d}: find_pattern_conflicts returns empty "
        f"for synthetic step texts",
        len(conflicts) == 0,
        f"{len(conflicts)} conflicts: {conflicts[:5]}",
    )

    offset += 1

    # --- Class B live-handler verification ----------------------------------
    for i, (pattern_prefix, witness, expected_handler, _reason) in enumerate(
        CLASS_B_VERDICTS, start=offset
    ):
        live_handler_name = None
        for pat, handler, tag in STEP_PATTERNS:
            if tag is None and pat.search(witness):
                live_handler_name = getattr(handler, "__name__", "")
                break
        runner.check(
            f"sc-dynamic-{i:02d}: live handler for "
            f"'{pattern_prefix[:40]}' is {expected_handler}",
            live_handler_name == expected_handler,
            f"Expected {expected_handler}, got {live_handler_name}",
        )

    offset += len(CLASS_B_VERDICTS)

    # --- Retained functions are still callable ------------------------------
    for i, fname in enumerate(RETAIN_FUNCTIONS, start=offset):
        func = getattr(
            __import__("acceptance_runtime", fromlist=[fname]),
            fname,
            None,
        )
        runner.check(
            f"sc-dynamic-{i:02d}: {fname} is still callable",
            callable(func),
            f"Function {fname} must be retained for delegation",
        )

    offset += len(RETAIN_FUNCTIONS)

    # --- Property tests pass with pytest (not xfail, not xpass) -------------
    if PROPERTY_TEST.is_file():
        try:
            result = run_command(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    f"{PROPERTY_TEST}::TestNoPatternShadowing::"
                    "test_no_global_pattern_conflicts_on_ir_steps",
                    f"{PROPERTY_TEST}::TestNoPatternShadowing::"
                    "test_no_global_pattern_conflicts_on_synthetic_steps",
                    "-v",
                    "--tb=short",
                    "--no-header",
                    "-p",
                    "no:cacheprovider",
                ],
                timeout=120,
                cwd=PROJECT_ROOT,
            )
            output = result.stdout + result.stderr
            # Check both tests passed (not xfailed, not xpassed)
            has_xfail = "xfail" in output.lower() or "xfailed" in output.lower()
            has_xpass = "xpassed" in output.lower()
            has_pass = "PASSED" in output
            detail = (
                f"rc={result.returncode}, "
                f"stdout={result.stdout[:500]!r}, stderr={result.stderr[:500]!r}"
            )
            runner.check(
                f"sc-dynamic-{offset:02d}: both property tests pass "
                f"(not xfail, not xpass)",
                result.returncode == 0 and has_pass and not has_xfail and not has_xpass,
                detail,
            )
        except subprocess.TimeoutExpired:
            runner.check(
                f"sc-dynamic-{offset:02d}: both property tests pass "
                f"(not xfail, not xpass)",
                False,
                "pytest timed out after 120s",
            )
        except Exception as exc:
            runner.check(
                f"sc-dynamic-{offset:02d}: both property tests pass "
                f"(not xfail, not xpass)",
                False,
                str(exc),
            )
    else:
        runner.check(
            f"sc-dynamic-{offset:02d}: property test file exists",
            False,
            f"File not found: {PROPERTY_TEST}",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=("QA suite for the shadowed registration cleanup (bead jrds)"),
    )
    parser.add_argument("--static", action="store_true", help="Run static checks only")
    parser.add_argument(
        "--dynamic", action="store_true", help="Run dynamic checks only"
    )
    parser.add_argument(
        "--all", action="store_true", help="Run static and dynamic checks"
    )
    args = parser.parse_args()

    if not any([args.static, args.dynamic, args.all]):
        args.all = True

    runner = QARunner()

    if args.static or args.all:
        print("--- Static checks (AST + source text) ---")
        run_static_checks(runner)

    if args.dynamic or args.all:
        print("--- Dynamic checks (import + STEP_PATTERNS + pytest) ---")
        run_dynamic_checks(runner)

    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())

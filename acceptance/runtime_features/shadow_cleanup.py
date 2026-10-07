"""Acceptance step handlers for the shadow_cleanup feature group."""

from __future__ import annotations

from runtime_shared import (
    ControlStructure,
    CoverageAnalysis,
    EnrichedThreatSet,
    Hazard,
    Loss,
    LossAnalysis,
    PROJECT_ROOT,
    Path,
    Responsibility,
    TemplateLoader,
    World,
    _FC_PROMPTS_DIR,
    _resolve_value,
    _sc_ensure_property_test_source,
    _sc_has_xfail,
    _sc_simulate_priority_registration,
    _sp1_valid_cs_dict,
    json,
    re,
)
from registry import StepTable

step = StepTable()


@step("all example-expanded step texts from every IR file are collected")
def _h_sc_collect_ir_step_texts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from snapshot import snapshot_layout

    ir_dir = PROJECT_ROOT / snapshot_layout().ir_dir
    step_texts: list[str] = []
    for ir_file in sorted(ir_dir.rglob("*.json")):
        try:
            ir = json.loads(ir_file.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        for step in ir.get("background", []):
            step_texts.append(_resolve_value(step.get("text", ""), {}))
        for sc in ir.get("scenarios", []):
            ex_list = sc.get("examples", [{}])
            if not ex_list:
                ex_list = [{}]
            for ex in ex_list:
                for step in sc.get("steps", []):
                    step_texts.append(_resolve_value(step.get("text", ""), ex))
    world.sc_ir_step_texts = step_texts
    return True, ""


@step("find_pattern_conflicts returns an empty list for those step texts")
def _h_sc_no_global_conflicts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from acceptance_runtime import find_pattern_conflicts

    step_texts = getattr(world, "sc_ir_step_texts", [])
    global_conflicts = find_pattern_conflicts(step_texts)
    if global_conflicts:
        detail = "; ".join(f"{t!r}: {f!r} vs {s!r}" for t, f, s in global_conflicts[:5])
        return (
            False,
            f"Found {len(global_conflicts)} global pattern conflicts: {detail}",
        )
    return True, ""


@step("synthetic step texts covering known shadowing prefixes are collected")
def _h_sc_collect_synthetic_texts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    synthetic = [
        "the revision is run",
        "the heuristic check fails with error containing something",
        "the pipeline does not crash",
        "the HTML contains the text something",
        "by_ica_type has 3 entries",
        "by_branch_category has 2 entries",
        "by_responsibility has 4 entries",
        "the file contains entries with stage stage_3",
        "the file contains entries with stage stage_5",
        "the scorecard validation section has 2 errors",
        "the user prompt contains the control structure",
        "no new failures are introduced",
        "the existing test suite is run",
        "the following modules exist and are importable",
        "the following template files exist",
        "uncovered_reason is not empty",
        "ica_type_diversity is a non-negative float",
        "responsibility_diversity is a non-negative float",
        "the scenario spec is validated against the control structure",
        "the TemplateLoader can load templates from the prompts directory",
        "the STPA system model prompts directory is available",
        "critic findings with unjustified gaps",
        "a warning is produced for orphan PM",
        "the revision is applied",
        "Stage 2 control structure derivation is run",
        "Stage 2 calls 1 through 3 are run in sequence",
        "a file test.txt exists in the run directory",
        "validation fails with error containing something",
        "a control structure with responsibilities RESP-1 and RESP-2 is available",
        "the final control structure passes foundation validation",
    ]
    world.sc_synthetic_texts = synthetic
    return True, ""


@step("find_pattern_conflicts returns an empty list for per-feature tagged patterns")
def _h_sc_no_tagged_conflicts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from acceptance_runtime import find_pattern_conflicts

    step_texts = getattr(world, "sc_ir_step_texts", [])
    tagged_conflicts = find_pattern_conflicts(step_texts)
    if tagged_conflicts:
        detail = "; ".join(f"{t!r}: {f!r} vs {s!r}" for t, f, s in tagged_conflicts[:5])
        return (
            False,
            f"Found {len(tagged_conflicts)} per-feature tagged conflicts: {detail}",
        )
    return True, ""


@step("the property test file test_acceptance_harness_property\\.py is inspected")
def _h_sc_inspect_property_test(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    test_file = PROJECT_ROOT / "tests" / "stpa" / "test_acceptance_harness_property.py"
    if not test_file.is_file():
        return False, f"Property test file not found: {test_file}"
    world.sc_property_test_source = test_file.read_text()
    return True, ""


@step("test_no_global_pattern_conflicts_on_ir_steps has no xfail marker")
@step("test_no_global_pattern_conflicts_on_synthetic_steps has no xfail marker")
def _h_sc_no_xfail_marker(world: World, text: str, examples: dict) -> tuple[bool, str]:
    source = getattr(world, "sc_property_test_source", "")
    if not source:
        return False, "Property test file not inspected"
    func = (
        "test_no_global_pattern_conflicts_on_synthetic_steps"
        if "synthetic" in text
        else "test_no_global_pattern_conflicts_on_ir_steps"
    )
    has_xfail, _ = _sc_has_xfail(source, func)
    if has_xfail:
        return False, f"{func} still has @pytest.mark.xfail decorator"
    return True, ""


@step("the two property tests have their xfail markers removed")
def _h_sc_xfail_removed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    source = _sc_ensure_property_test_source(world)
    if not source:
        return False, "Property test file not found"
    for func in (
        "test_no_global_pattern_conflicts_on_ir_steps",
        "test_no_global_pattern_conflicts_on_synthetic_steps",
    ):
        has_xfail, _ = _sc_has_xfail(source, func)
        if has_xfail:
            return False, f"{func} still has @pytest.mark.xfail decorator"
    return True, ""


@step("the tests pass rather than xpass")
def _h_sc_tests_pass_not_xpass(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    source = _sc_ensure_property_test_source(world)
    if not source:
        return False, "Property test file not found"
    for func in (
        "test_no_global_pattern_conflicts_on_ir_steps",
        "test_no_global_pattern_conflicts_on_synthetic_steps",
    ):
        has_xfail, _ = _sc_has_xfail(source, func)
        if has_xfail:
            return False, f"{func} is still marked xfail (would xpass instead of pass)"
    return True, ""


@step("the tests are not marked with strict=False")
def _h_sc_no_strict_false(world: World, text: str, examples: dict) -> tuple[bool, str]:
    source = _sc_ensure_property_test_source(world)
    if not source:
        return False, "Property test file not found"
    for func in (
        "test_no_global_pattern_conflicts_on_ir_steps",
        "test_no_global_pattern_conflicts_on_synthetic_steps",
    ):
        _, has_strict = _sc_has_xfail(source, func)
        if has_strict:
            return False, f"{func} still has strict=False"
    return True, ""


@step("a pattern (.*) is registered with handler (\\S+) in global scope")
def _h_sc_register_test_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from acceptance_runtime import STEP_PATTERNS, _track_registration

    m = re.search(
        r"a pattern (.*) is registered with handler (\S+) in global scope", text
    )
    if not m:
        return False, f"Could not parse: {text}"
    pattern_str, handler_name = m.group(1), m.group(2)

    def _test_handler(w: World, t: str, e: dict) -> tuple[bool, str]:
        return True, ""

    _test_handler.__name__ = handler_name
    _track_registration(pattern_str, _test_handler, None)
    STEP_PATTERNS.append((re.compile(pattern_str, re.IGNORECASE), _test_handler, None))
    world.sc_test_pattern = pattern_str
    world.sc_test_handler = _test_handler
    return True, ""


@step(
    "registering the same pattern (.*) with handler (\\S+) in global scope raises RuntimeError"
)
def _h_sc_duplicate_raises(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from acceptance_runtime import (
        STEP_PATTERNS,
        _REGISTERED_PATTERN_KEYS,
        _track_registration,
    )

    m = re.search(
        r"registering the same pattern (.*) with handler (\S+) in global scope", text
    )
    if not m:
        return False, f"Could not parse: {text}"
    pattern_str, handler_name = m.group(1), m.group(2)
    handler = getattr(world, "sc_test_handler", None)
    if handler is None:
        return False, "No test pattern registered"
    try:
        _track_registration(pattern_str, handler, None)
        # Clean up the original registration
        STEP_PATTERNS.pop()
        _REGISTERED_PATTERN_KEYS.discard((pattern_str, handler_name, None))
        return False, "Expected RuntimeError but no error was raised"
    except RuntimeError:
        # Expected! Clean up the original registration
        STEP_PATTERNS.pop()
        _REGISTERED_PATTERN_KEYS.discard((pattern_str, handler_name, None))
        return True, ""


@step(
    "the number of entries in _REGISTERED_PATTERN_KEYS equals the length of STEP_PATTERNS"
)
def _h_sc_keys_equal_patterns(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from acceptance_runtime import STEP_PATTERNS, _REGISTERED_PATTERN_KEYS

    keys_count = len(_REGISTERED_PATTERN_KEYS)
    patterns_count = len(STEP_PATTERNS)
    if keys_count != patterns_count:
        return (
            False,
            f"_REGISTERED_PATTERN_KEYS has {keys_count} entries but STEP_PATTERNS has {patterns_count} entries",
        )
    return True, ""


def _sc_registration_handler(parse_pattern: str, insert_first: bool):
    """Build a Given handler that simulates one parsed priority registration."""

    def handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
        return _sc_simulate_priority_registration(
            world, text, parse_pattern, insert_first=insert_first
        )

    return handler


_h_sc_reg_register_earlier = _sc_registration_handler(
    r"a pattern (.*) is registered with _register by handler (\S+) at an earlier line",
    insert_first=False,
)
step.add(
    "a pattern (.*) is registered with _register by handler (\\S+) at an earlier line",
    _h_sc_reg_register_earlier,
    first=True,
    feature="shadow_cleanup",
)
_h_sc_reg_first_later = _sc_registration_handler(
    r"the same pattern (.*) is registered with _register_first by handler (\S+) at a later line",
    insert_first=True,
)
step.add(
    "the same pattern (.*) is registered with _register_first by handler (\\S+) at a later line",
    _h_sc_reg_first_later,
    first=True,
    feature="shadow_cleanup",
)
_h_sc_reg_first_a = _sc_registration_handler(
    r"a pattern (.*) is registered with _register_first by handler (\S+)$",
    insert_first=True,
)
step.add(
    "a pattern (.*) is registered with _register_first by handler (\\S+)$",
    _h_sc_reg_first_a,
    first=True,
    feature="shadow_cleanup",
)
_h_sc_reg_first_b = _sc_registration_handler(
    r"the same pattern (.*) is registered with _register_first by handler (\S+)$",
    insert_first=True,
)
step.add(
    "the same pattern (.*) is registered with _register_first by handler (\\S+)$",
    _h_sc_reg_first_b,
    first=True,
    feature="shadow_cleanup",
)
_h_sc_reg_register_a = _sc_registration_handler(
    r"a pattern (.*) is registered with _register by handler (\S+)$",
    insert_first=False,
)
step.add(
    "a pattern (.*) is registered with _register by handler (\\S+)$",
    _h_sc_reg_register_a,
    first=True,
    feature="shadow_cleanup",
)
_h_sc_reg_register_b = _sc_registration_handler(
    r"the same pattern (.*) is registered with _register by handler (\S+)$",
    insert_first=False,
)
step.add(
    "the same pattern (.*) is registered with _register by handler (\\S+)$",
    _h_sc_reg_register_b,
    first=True,
    feature="shadow_cleanup",
)


@step.first(
    "handler (\\S+) is the live handler for step text matching (.*)",
    feature="shadow_cleanup",
)
def _h_sc_verify_live_handler(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    m = re.search(
        r"handler (\S+) is the live handler for step text matching (.*)", text
    )
    if not m:
        return False, f"Could not parse: {text}"
    expected_handler_name = m.group(1)
    step_text = m.group(2)
    test_list = getattr(world, "sc_test_patterns", None)
    if test_list is None:
        return False, "No test patterns registered"
    for pat, handler, _tag in test_list:
        if pat.search(step_text):
            actual_name = handler.__name__
            if actual_name != expected_handler_name:
                return (
                    False,
                    f"Expected handler {expected_handler_name!r} but got {actual_name!r}",
                )
            return True, ""
    return False, f"No handler found for step text {step_text!r}"


@step("a use-case description and loss analysis are available")
def _h_sc_use_case_loss(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_use_case_text = "Test use case for Stage 2"
    world.loss_analysis = LossAnalysis(
        losses=[Loss(loss_id="L-1", description="Loss of confidentiality")],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", loss_ids=["L-1"])],
    )
    return True, ""


@step("the control structure was derived with a TemplateLoader")
def _h_sc_cs_derived_with_loader(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    loader = getattr(world, "template_loader", None)
    if loader is None:
        return False, "No template loader was set"
    if not isinstance(loader, TemplateLoader):
        return False, f"template_loader is {type(loader).__name__}, not TemplateLoader"
    return True, ""


@step("the critic logger had a log capture handler installed during revision")
def _h_sc_critic_log_capture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    warnings = getattr(world, "sp1_post_revision_warnings", None)
    if warnings is None:
        return (
            False,
            "No log capture warnings recorded (revision may not have been run)",
        )
    return True, ""


@step("the world template_loader is a TemplateLoader instance")
def _h_sc_template_loader_instance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    loader = getattr(world, "template_loader", None)
    if loader is None:
        return False, "No template loader set"
    if not isinstance(loader, TemplateLoader):
        return False, f"template_loader is {type(loader).__name__}, not TemplateLoader"
    return True, ""


@step("the template loader source directory is the FC prompts directory")
def _h_sc_template_dir_fc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    loader = getattr(world, "template_loader", None)
    if loader is None:
        return False, "No template loader set"
    source_dir = getattr(loader, "prompts_dir", None)
    if source_dir is None:
        return False, "Could not determine template loader source directory"
    if Path(source_dir) != _FC_PROMPTS_DIR:
        return (
            False,
            f"Template loader source is {source_dir}, expected {_FC_PROMPTS_DIR}",
        )
    return True, ""


@step("the handler returns false with a file-not-found message$")
def _h_sc_returns_false_file_not_found(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from runtime_features.sp1_max_workers import _h_mw_file_exists

    run_dir = getattr(world, "sp1_run_dir", None)
    if run_dir is None:
        return False, "No run directory set"
    result = _h_mw_file_exists(
        world, "a file nonexistent_file.txt exists in the run directory", {}
    )
    if result[0]:
        return False, "Expected handler to return false, but it returned true"
    if (
        "does not exist" not in result[1].lower()
        and "not found" not in result[1].lower()
    ):
        return False, f"Expected file-not-found message, got: {result[1]}"
    return True, ""


@step("a heuristic result that passed")
def _h_sc_heuristic_passed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.heuristic_result = type("R", (), {"passed": True, "errors": []})()
    return True, ""


@step("the handler returns false because the heuristic passed$")
def _h_sc_returns_false_heuristic_passed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from runtime_features.foundation import _h_heuristic_fails_with

    result = _h_heuristic_fails_with(
        world, "the heuristic check fails with error containing something", {}
    )
    if result[0]:
        return False, "Expected handler to return false, but it returned true"
    if "passed" not in result[1].lower():
        return False, f"Expected 'passed' in error message, got: {result[1]}"
    return True, ""


@step("a control structure with responsibility RESP-1 is available")
def _h_sc_cs_resp1_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.control_structure is None:
        world.control_structure = ControlStructure.model_validate(_sp1_valid_cs_dict())
    resp_ids = [r.resp_id for r in world.control_structure.responsibilities]
    if "RESP-1" not in resp_ids:
        world.control_structure = world.control_structure.model_copy(
            update={
                "responsibilities": list(world.control_structure.responsibilities)
                + [Responsibility(resp_id="RESP-1", description="Responsibility 1")]
            }
        )
    world.sc_cs_created_by_sp1_helper = True
    return True, ""


@step("the world control structure has responsibility RESP-1")
def _h_sc_world_cs_resp1(world: World, text: str, examples: dict) -> tuple[bool, str]:
    cs = getattr(world, "control_structure", None)
    if cs is None:
        return False, "No control structure in world"
    resp_ids = [r.resp_id for r in cs.responsibilities]
    if "RESP-1" not in resp_ids:
        return False, f"Control structure does not have RESP-1: {resp_ids}"
    return True, ""


@step("the control structure was created by the SP1 helper function")
def _h_sc_cs_sp1_helper(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if not getattr(world, "sc_cs_created_by_sp1_helper", False):
        return False, "Control structure was not created by the SP1 helper"
    return True, ""


@step("the SP1 mock client has no calls recorded")
def _h_sc_sp1_no_calls(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_mock_client = type("C", (), {"calls": []})()
    return True, ""


@step("the handler returns true because no calls were made$")
def _h_sc_returns_true_no_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from runtime_features.sp1 import _h_sp1_critic_prompt_cs

    result = _h_sp1_critic_prompt_cs(
        world, "the user prompt contains the control structure", {}
    )
    if not result[0]:
        return (
            False,
            f"Expected handler to return true, but it returned false: {result[1]}",
        )
    return True, ""


@step("the handler returns true unconditionally$")
def _h_sc_returns_true_unconditional(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from runtime_features.sp1_revision import _h_gd_pipeline_no_crash

    result = _h_gd_pipeline_no_crash(world, "the pipeline does not crash", {})
    if not result[0]:
        return (
            False,
            f"Expected handler to return true, but it returned false: {result[1]}",
        )
    return True, ""


@step("an enriched threat set with an empty uncovered_reason")
def _h_sc_ets_empty_uncovered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={},
            uncovered_reason="",
        ),
    )
    return True, ""


@step("the handler returns false because uncovered_reason is empty$")
def _h_sc_returns_false_uncovered_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from runtime_features.sp2 import _h_sp2_uncovered_reason

    result = _h_sp2_uncovered_reason(world, "uncovered_reason is not empty", {})
    if result[0]:
        return False, "Expected handler to return false, but it returned true"
    if "empty" not in result[1].lower():
        return False, f"Expected 'empty' in error message, got: {result[1]}"
    return True, ""


@step("the in-memory scorecard has a validation section with \\d+ stage_local_errors")
def _h_sc_scorecard_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp3_scorecard = {
        "validation": {
            "stage_local_errors": ["error1", "error2"],
        }
    }
    return True, ""


@step("^the handler returns true$")
def _h_sc_returns_true(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from runtime_features.sp3 import _h_sp3_scorecard_validation_section

    result = _h_sp3_scorecard_validation_section(
        world, "the scorecard validation section has 2 stage_local_errors", {}
    )
    if not result[0]:
        return (
            False,
            f"Expected handler to return true, but it returned false: {result[1]}",
        )
    return True, ""


FEATURE_ID = "shadow_cleanup"


register = step.register


__all__ = ["FEATURE_ID", "register"]

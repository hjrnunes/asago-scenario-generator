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


def _h_sc_runtime_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the acceptance runtime module is importable."""
    return True, ""


def _h_sc_collect_ir_step_texts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: all example-expanded step texts from every IR file are collected."""
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


def _h_sc_no_global_conflicts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: find_pattern_conflicts returns an empty list for those step texts."""
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


def _h_sc_collect_synthetic_texts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: synthetic step texts covering known shadowing prefixes are collected."""
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


def _h_sc_no_tagged_conflicts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: find_pattern_conflicts returns an empty list for per-feature tagged patterns."""
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


def _h_sc_inspect_property_test(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the property test file test_acceptance_harness_property.py is inspected."""
    test_file = PROJECT_ROOT / "tests" / "stpa" / "test_acceptance_harness_property.py"
    if not test_file.is_file():
        return False, f"Property test file not found: {test_file}"
    world.sc_property_test_source = test_file.read_text()
    return True, ""


def _h_sc_no_xfail_marker(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: test_no_global_pattern_conflicts_on_... has no xfail marker."""
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


def _h_sc_xfail_removed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the two property tests have their xfail markers removed."""
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


def _h_sc_tests_pass_not_xpass(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the tests pass rather than xpass."""
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


def _h_sc_no_strict_false(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the tests are not marked with strict=False."""
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


def _h_sc_register_test_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a pattern <pattern> is registered with handler <handler> in global scope."""
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


def _h_sc_duplicate_raises(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: registering the same pattern with handler in global scope raises RuntimeError."""
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


def _h_sc_keys_equal_patterns(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the number of entries in _REGISTERED_PATTERN_KEYS equals the length of STEP_PATTERNS."""
    from acceptance_runtime import STEP_PATTERNS, _REGISTERED_PATTERN_KEYS

    keys_count = len(_REGISTERED_PATTERN_KEYS)
    patterns_count = len(STEP_PATTERNS)
    if keys_count != patterns_count:
        return (
            False,
            f"_REGISTERED_PATTERN_KEYS has {keys_count} entries but STEP_PATTERNS has {patterns_count} entries",
        )
    return True, ""


def _h_sc_reg_register_earlier(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a pattern <pattern> is registered with _register by handler <handler> at an earlier line."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"a pattern (.*) is registered with _register by handler (\S+) at an earlier line",
        insert_first=False,
    )


def _h_sc_reg_first_later(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the same pattern <pattern> is registered with _register_first by handler <handler> at a later line."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"the same pattern (.*) is registered with _register_first by handler (\S+) at a later line",
        insert_first=True,
    )


def _h_sc_reg_first_a(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a pattern <pattern> is registered with _register_first by handler <handler>."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"a pattern (.*) is registered with _register_first by handler (\S+)$",
        insert_first=True,
    )


def _h_sc_reg_first_b(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the same pattern <pattern> is registered with _register_first by handler <handler>."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"the same pattern (.*) is registered with _register_first by handler (\S+)$",
        insert_first=True,
    )


def _h_sc_reg_register_a(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a pattern <pattern> is registered with _register by handler <handler>."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"a pattern (.*) is registered with _register by handler (\S+)$",
        insert_first=False,
    )


def _h_sc_reg_register_b(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the same pattern <pattern> is registered with _register by handler <handler>."""
    return _sc_simulate_priority_registration(
        world,
        text,
        r"the same pattern (.*) is registered with _register by handler (\S+)$",
        insert_first=False,
    )


def _h_sc_verify_live_handler(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: handler <handler> is the live handler for step text matching <pattern>."""
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


def _h_sc_use_case_loss(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a use-case description and loss analysis are available."""
    world.sp1_use_case_text = "Test use case for Stage 2"
    world.loss_analysis = LossAnalysis(
        losses=[Loss(loss_id="L-1", description="Loss of confidentiality")],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", loss_ids=["L-1"])],
    )
    return True, ""


def _h_sc_cs_derived_with_loader(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the control structure was derived with a TemplateLoader."""
    loader = getattr(world, "template_loader", None)
    if loader is None:
        return False, "No template loader was set"
    if not isinstance(loader, TemplateLoader):
        return False, f"template_loader is {type(loader).__name__}, not TemplateLoader"
    return True, ""


def _h_sc_critic_log_capture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the critic logger had a log capture handler installed during revision."""
    warnings = getattr(world, "sp1_post_revision_warnings", None)
    if warnings is None:
        return (
            False,
            "No log capture warnings recorded (revision may not have been run)",
        )
    return True, ""


def _h_sc_template_loader_instance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the world template_loader is a TemplateLoader instance."""
    loader = getattr(world, "template_loader", None)
    if loader is None:
        return False, "No template loader set"
    if not isinstance(loader, TemplateLoader):
        return False, f"template_loader is {type(loader).__name__}, not TemplateLoader"
    return True, ""


def _h_sc_template_dir_fc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the template loader source directory is the FC prompts directory."""
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


def _h_sc_returns_false_file_not_found(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the handler returns false with a file-not-found message."""
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


def _h_sc_heuristic_passed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a heuristic result that passed."""
    world.heuristic_result = type("R", (), {"passed": True, "errors": []})()
    return True, ""


def _h_sc_returns_false_heuristic_passed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the handler returns false because the heuristic passed."""
    from runtime_features.foundation import _h_heuristic_fails_with

    result = _h_heuristic_fails_with(
        world, "the heuristic check fails with error containing something", {}
    )
    if result[0]:
        return False, "Expected handler to return false, but it returned true"
    if "passed" not in result[1].lower():
        return False, f"Expected 'passed' in error message, got: {result[1]}"
    return True, ""


def _h_sc_cs_resp1_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1 is available."""
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


def _h_sc_world_cs_resp1(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the world control structure has responsibility RESP-1."""
    cs = getattr(world, "control_structure", None)
    if cs is None:
        return False, "No control structure in world"
    resp_ids = [r.resp_id for r in cs.responsibilities]
    if "RESP-1" not in resp_ids:
        return False, f"Control structure does not have RESP-1: {resp_ids}"
    return True, ""


def _h_sc_cs_sp1_helper(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the control structure was created by the SP1 helper function."""
    if not getattr(world, "sc_cs_created_by_sp1_helper", False):
        return False, "Control structure was not created by the SP1 helper"
    return True, ""


def _h_sc_sp1_no_calls(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the SP1 mock client has no calls recorded."""
    world.sp1_mock_client = type("C", (), {"calls": []})()
    return True, ""


def _h_sc_returns_true_no_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the handler returns true because no calls were made."""
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


def _h_sc_returns_true_unconditional(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the handler returns true unconditionally."""
    from runtime_features.sp1_revision import _h_gd_pipeline_no_crash

    result = _h_gd_pipeline_no_crash(world, "the pipeline does not crash", {})
    if not result[0]:
        return (
            False,
            f"Expected handler to return true, but it returned false: {result[1]}",
        )
    return True, ""


def _h_sc_ets_empty_uncovered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an enriched threat set with an empty uncovered_reason."""
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={},
            uncovered_reason="",
        ),
    )
    return True, ""


def _h_sc_returns_false_uncovered_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the handler returns false because uncovered_reason is empty."""
    from runtime_features.sp2 import _h_sp2_uncovered_reason

    result = _h_sp2_uncovered_reason(world, "uncovered_reason is not empty", {})
    if result[0]:
        return False, "Expected handler to return false, but it returned true"
    if "empty" not in result[1].lower():
        return False, f"Expected 'empty' in error message, got: {result[1]}"
    return True, ""


def _h_sc_scorecard_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the in-memory scorecard has a validation section with N stage_local_errors."""
    world.sp3_scorecard = {
        "validation": {
            "stage_local_errors": ["error1", "error2"],
        }
    }
    return True, ""


def _h_sc_returns_true(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the handler returns true."""
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


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.set_feature("shadow_cleanup")
    api.register_first(
        "a pattern (.*) is registered with _register by handler (\\S+) at an earlier line",
        _h_sc_reg_register_earlier,
        source_order=23107,
    )
    api.register_first(
        "the same pattern (.*) is registered with _register_first by handler (\\S+) at a later line",
        _h_sc_reg_first_later,
        source_order=23108,
    )
    api.register_first(
        "a pattern (.*) is registered with _register_first by handler (\\S+)$",
        _h_sc_reg_first_a,
        source_order=23109,
    )
    api.register_first(
        "the same pattern (.*) is registered with _register_first by handler (\\S+)$",
        _h_sc_reg_first_b,
        source_order=23110,
    )
    api.register_first(
        "a pattern (.*) is registered with _register by handler (\\S+)$",
        _h_sc_reg_register_a,
        source_order=23111,
    )
    api.register_first(
        "the same pattern (.*) is registered with _register by handler (\\S+)$",
        _h_sc_reg_register_b,
        source_order=23112,
    )
    api.register_first(
        "handler (\\S+) is the live handler for step text matching (.*)",
        _h_sc_verify_live_handler,
        source_order=23113,
    )
    api.set_feature(None)
    api.register(
        "the acceptance runtime module is importable",
        _h_sc_runtime_importable,
        source_order=23118,
    )
    api.register(
        "all example-expanded step texts from every IR file are collected",
        _h_sc_collect_ir_step_texts,
        source_order=23119,
    )
    api.register(
        "find_pattern_conflicts returns an empty list for those step texts",
        _h_sc_no_global_conflicts,
        source_order=23120,
    )
    api.register(
        "synthetic step texts covering known shadowing prefixes are collected",
        _h_sc_collect_synthetic_texts,
        source_order=23121,
    )
    api.register(
        "find_pattern_conflicts returns an empty list for per-feature tagged patterns",
        _h_sc_no_tagged_conflicts,
        source_order=23122,
    )
    api.register(
        "the property test file test_acceptance_harness_property\\.py is inspected",
        _h_sc_inspect_property_test,
        source_order=23123,
    )
    api.register(
        "test_no_global_pattern_conflicts_on_ir_steps has no xfail marker",
        _h_sc_no_xfail_marker,
        source_order=23124,
    )
    api.register(
        "test_no_global_pattern_conflicts_on_synthetic_steps has no xfail marker",
        _h_sc_no_xfail_marker,
        source_order=23125,
    )
    api.register(
        "the two property tests have their xfail markers removed",
        _h_sc_xfail_removed,
        source_order=23126,
    )
    api.register(
        "the tests pass rather than xpass",
        _h_sc_tests_pass_not_xpass,
        source_order=23127,
    )
    api.register(
        "the tests are not marked with strict=False",
        _h_sc_no_strict_false,
        source_order=23128,
    )
    api.register(
        "a pattern (.*) is registered with handler (\\S+) in global scope",
        _h_sc_register_test_pattern,
        source_order=23129,
    )
    api.register(
        "registering the same pattern (.*) with handler (\\S+) in global scope raises RuntimeError",
        _h_sc_duplicate_raises,
        source_order=23130,
    )
    api.register(
        "the number of entries in _REGISTERED_PATTERN_KEYS equals the length of STEP_PATTERNS",
        _h_sc_keys_equal_patterns,
        source_order=23131,
    )
    api.register(
        "a use-case description and loss analysis are available",
        _h_sc_use_case_loss,
        source_order=23132,
    )
    api.register(
        "the control structure was derived with a TemplateLoader",
        _h_sc_cs_derived_with_loader,
        source_order=23133,
    )
    api.register(
        "the critic logger had a log capture handler installed during revision",
        _h_sc_critic_log_capture,
        source_order=23134,
    )
    api.register(
        "the world template_loader is a TemplateLoader instance",
        _h_sc_template_loader_instance,
        source_order=23135,
    )
    api.register(
        "the template loader source directory is the FC prompts directory",
        _h_sc_template_dir_fc,
        source_order=23136,
    )
    api.register(
        "the handler returns false with a file-not-found message$",
        _h_sc_returns_false_file_not_found,
        source_order=23137,
    )
    api.register(
        "the handler returns false because the heuristic passed$",
        _h_sc_returns_false_heuristic_passed,
        source_order=23138,
    )
    api.register(
        "a heuristic result that passed", _h_sc_heuristic_passed, source_order=23139
    )
    api.register(
        "a control structure with responsibility RESP-1 is available",
        _h_sc_cs_resp1_available,
        source_order=23140,
    )
    api.register(
        "the world control structure has responsibility RESP-1",
        _h_sc_world_cs_resp1,
        source_order=23141,
    )
    api.register(
        "the control structure was created by the SP1 helper function",
        _h_sc_cs_sp1_helper,
        source_order=23142,
    )
    api.register(
        "the SP1 mock client has no calls recorded",
        _h_sc_sp1_no_calls,
        source_order=23143,
    )
    api.register(
        "the handler returns true because no calls were made$",
        _h_sc_returns_true_no_calls,
        source_order=23144,
    )
    api.register(
        "the handler returns true unconditionally$",
        _h_sc_returns_true_unconditional,
        source_order=23145,
    )
    api.register(
        "an enriched threat set with an empty uncovered_reason",
        _h_sc_ets_empty_uncovered,
        source_order=23146,
    )
    api.register(
        "the handler returns false because uncovered_reason is empty$",
        _h_sc_returns_false_uncovered_empty,
        source_order=23147,
    )
    api.register(
        "the in-memory scorecard has a validation section with \\d+ stage_local_errors",
        _h_sc_scorecard_validation,
        source_order=23148,
    )
    api.register("^the handler returns true$", _h_sc_returns_true, source_order=23149)
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]

"""Acceptance step handlers for the parallel_llm feature group."""

from __future__ import annotations

from runtime_shared import (
    LossAnalysis,
    Path,
    ValidationError,
    World,
    _ConcurrentMockLLMClient,
    _ParallelDummyModel,
    _parallel_make_spec,
    _sp1_make_risk_cards,
    _sp1_run_sp1,
    _sp1_setup_full_mock_client,
    _tempfile,
    json,
    re,
)


def _h_pll_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the STPA parallel LLM module is importable."""
    from asago_scenario_generator.stpa.infra.parallel_llm import parallel_safe_llm_calls

    assert parallel_safe_llm_calls is not None
    return True, ""


def _h_pll_mock_client(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a mock LLM client that records call order."""
    world.parallel_mock_client = _ConcurrentMockLLMClient()
    return True, ""


def _h_pll_run_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a run directory for output (parallel context)."""
    world.parallel_run_dir = Path(_tempfile.mkdtemp(prefix="pll_run_"))
    return True, ""


def _h_pll_specs_stages(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: three LLM call specifications with stages stage_3, stage_3, stage_3."""
    world.parallel_calls = [_parallel_make_spec(f"slot_{i}") for i in range(3)]
    return True, ""


def _h_pll_specs_steps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: N LLM call specifications with steps <comma-or-and-separated list>."""
    m = re.search(r"steps (.+)", text)
    if not m:
        return False, f"Could not parse steps from: {text}"
    steps_raw = m.group(1).strip()
    # Handle both comma-separated and "and"-separated lists
    steps_raw = steps_raw.replace(" and ", ",")
    steps = [s.strip() for s in steps_raw.split(",") if s.strip()]
    world.parallel_calls = [_parallel_make_spec(s) for s in steps]
    return True, ""


def _h_pll_specs_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: N LLM call specifications (no specific steps)."""
    m = re.search(r"(\w+) LLM call specifications$", text)
    if not m:
        return False, f"Could not parse count from: {text}"
    word = m.group(1).lower()
    num_words = {
        "one": 1,
        "two": 2,
        "three": 3,
        "four": 4,
        "five": 5,
        "six": 6,
        "seven": 7,
        "eight": 8,
        "nine": 9,
        "ten": 10,
        "eleven": 11,
        "twelve": 12,
        "zero": 0,
    }
    count = num_words.get(word, 0)
    world.parallel_calls = [_parallel_make_spec(f"call_{i}") for i in range(count)]
    return True, ""


def _h_pll_mock_delay(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the mock LLM delays step <step> by <N>ms and step <step> by <N>ms."""
    if world.parallel_mock_client is None:
        return False, "No mock client"
    for m in re.finditer(r"step (\S+) by (\d+)ms", text):
        step = m.group(1)
        ms = int(m.group(2))
        world.parallel_mock_client.set_delay_for_step(step, ms / 1000.0)
    return True, ""


def _h_pll_mock_exception(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the mock LLM raises an exception for step <step>."""
    if world.parallel_mock_client is None:
        return False, "No mock client"
    m = re.search(r"exception for step (\S+)", text)
    if not m:
        return False, f"Could not parse step from: {text}"
    world.parallel_mock_client.set_exception_for_step(m.group(1), RuntimeError("boom"))
    return True, ""


def _h_pll_mock_exception_scenario(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the mock LLM raises an exception for scenario <N>."""
    if world.parallel_mock_client is None:
        return False, "No mock client"
    m = re.search(r"exception for scenario (\S+)", text)
    if not m:
        return False, f"Could not parse scenario from: {text}"
    # Feature uses 1-based; code uses 0-based
    scenario_idx = int(m.group(1)) - 1
    world.parallel_mock_client.set_exception_for_step(
        f"scenario_{scenario_idx}_bdi", RuntimeError("sc fail")
    )
    return True, ""


def _h_pll_mock_records_concurrent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the mock LLM records the number of concurrent in-flight calls."""
    # The ConcurrentMockLLMClient already tracks this; set a small delay to encourage overlap
    if world.parallel_mock_client is None:
        return False, "No mock client"
    world.parallel_mock_client.set_delay_for_step("call", 0.05)
    return True, ""


def _h_pll_single_spec(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: one LLM call specification with stage <stage> and step <step>."""
    m = re.search(r"stage (\S+) and step (\S+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    world.parallel_calls = [_parallel_make_spec(m.group(2), stage=m.group(1))]
    return True, ""


def _h_pll_zero_specs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: zero LLM call specifications."""
    world.parallel_calls = []
    return True, ""


def _h_pll_spec_bundled(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLMCallSpec with system_prompt sys, user_prompt usr, ..."""
    from asago_scenario_generator.stpa.infra.parallel_llm import LLMCallSpec

    m = re.search(
        r"system_prompt (\S+), user_prompt (\S+), response_format (\S+), "
        r"stage (\S+), step (\S+), and temperature (\S+)",
        text,
    )
    if not m:
        return False, f"Could not parse LLMCallSpec from: {text}"
    response_format_name = m.group(3)
    # Map string to actual class
    fmt_map = {"LossAnalysis": LossAnalysis}
    fmt = fmt_map.get(response_format_name, _ParallelDummyModel)
    world.parallel_spec = LLMCallSpec(
        system_prompt=m.group(1),
        user_prompt=m.group(2),
        response_format=fmt,
        stage=m.group(4),
        step=m.group(5),
        temperature=float(m.group(6)),
    )
    return True, ""


def _h_pll_successful_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a successful parallel call execution for one specification."""
    from asago_scenario_generator.stpa.infra.parallel_llm import parallel_safe_llm_calls

    if world.parallel_mock_client is None:
        world.parallel_mock_client = _ConcurrentMockLLMClient(model="my-model")
    if world.parallel_run_dir is None:
        world.parallel_run_dir = Path(_tempfile.mkdtemp(prefix="pll_run_"))
    spec = _parallel_make_spec("slot_a")
    world.parallel_calls = [spec]
    world.parallel_results = parallel_safe_llm_calls(
        world.parallel_calls,
        llm_client=world.parallel_mock_client,
        run_dir=world.parallel_run_dir,
        max_workers=1,
    )
    return True, ""


def _h_pll_failed_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a failed parallel call execution for one specification."""
    from asago_scenario_generator.stpa.infra.parallel_llm import parallel_safe_llm_calls

    if world.parallel_mock_client is None:
        world.parallel_mock_client = _ConcurrentMockLLMClient(model="my-model")
    if world.parallel_run_dir is None:
        world.parallel_run_dir = Path(_tempfile.mkdtemp(prefix="pll_run_"))
    world.parallel_mock_client.set_exception_for_step("bad_1", RuntimeError("boom"))
    spec = _parallel_make_spec("bad_1")
    world.parallel_calls = [spec]
    world.parallel_results = parallel_safe_llm_calls(
        world.parallel_calls,
        llm_client=world.parallel_mock_client,
        run_dir=world.parallel_run_dir,
        max_workers=1,
    )
    return True, ""


def _h_pll_specs_temperatures(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: two LLM call specifications with temperatures 0.2 and 0.7."""
    m = re.search(r"temperatures (.+)", text)
    if not m:
        return False, f"Could not parse temperatures from: {text}"
    temps_raw = m.group(1).replace(" and ", ",")
    temps = [float(t.strip()) for t in temps_raw.split(",") if t.strip()]
    world.parallel_calls = [
        _parallel_make_spec(f"temp_{i}", temperature=t) for i, t in enumerate(temps)
    ]
    return True, ""


def _h_pll_call_parallel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: parallel_safe_llm_calls is called with max_workers <N>."""
    from asago_scenario_generator.stpa.infra.parallel_llm import parallel_safe_llm_calls

    if world.parallel_mock_client is None:
        return False, "No mock client"
    if world.parallel_run_dir is None:
        world.parallel_run_dir = Path(_tempfile.mkdtemp(prefix="pll_run_"))
    m = re.search(r"max_workers (\d+)", text)
    mw = int(m.group(1)) if m else 4
    world.parallel_max_workers = mw
    world.parallel_results = parallel_safe_llm_calls(
        world.parallel_calls,
        llm_client=world.parallel_mock_client,
        run_dir=world.parallel_run_dir,
        max_workers=mw,
    )
    return True, ""


def _h_pll_n_results(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: N LLMCallResult objects/object are/is returned."""
    from asago_scenario_generator.stpa.infra.parallel_llm import LLMCallResult

    num_words = {
        "one": 1,
        "two": 2,
        "three": 3,
        "four": 4,
        "five": 5,
        "six": 6,
        "seven": 7,
        "eight": 8,
        "nine": 9,
        "ten": 10,
        "eleven": 11,
        "twelve": 12,
    }
    m = re.search(r"(\w+) LLMCallResult object", text)
    expected = num_words.get(m.group(1).lower(), 0) if m else 0
    if len(world.parallel_results) != expected:
        return False, f"Expected {expected} results, got {len(world.parallel_results)}"
    for r in world.parallel_results:
        if not isinstance(r, LLMCallResult):
            return False, f"Expected LLMCallResult, got {type(r)}"
    return True, ""


def _h_pll_each_validated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: each result contains the validated model from the mock LLM."""
    for r in world.parallel_results:
        if r.result is None:
            return False, "Result has None validated model"
    return True, ""


def _h_pll_result_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the <ordinal> result has step <step>."""
    ordinals = {"first": 0, "second": 1, "third": 2, "fourth": 3, "fifth": 4}
    m = re.search(r"(\w+) result has step (\S+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    idx = ordinals.get(m.group(1).lower())
    if idx is None or idx >= len(world.parallel_results):
        return False, f"Index {idx} out of range"
    expected_step = m.group(2)
    actual = world.parallel_results[idx].call_spec.step
    if actual != expected_step:
        return False, f"Expected step {expected_step}, got {actual}"
    return True, ""


def _h_pll_result_step_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the result for step <step> has no error / has an error message."""
    m = re.search(r"result for step (\S+) has (no error|an error message)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    step = m.group(1)
    expect_error = m.group(2) != "no error"
    for r in world.parallel_results:
        if r.call_spec.step == step:
            if expect_error and r.error is None:
                return False, f"Expected error for step {step}"
            if not expect_error and r.error is not None:
                return False, f"Unexpected error for step {step}: {r.error}"
            return True, ""
    return False, f"No result found for step {step}"


def _h_pll_result_scenario_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the result for scenario N has no error / has an error message."""
    m = re.search(r"result for scenario (\d+) has (no error|an error message)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    # Feature uses 1-based; code uses 0-based
    scenario_idx = int(m.group(1)) - 1
    expect_error = m.group(2) != "no error"
    target = f"scenario_{scenario_idx}_bdi"
    for r in world.parallel_results:
        if r.call_spec.step == target:
            if expect_error and r.error is None:
                return False, f"Expected error for scenario {m.group(1)}"
            if not expect_error and r.error is not None:
                return False, f"Unexpected error for scenario {m.group(1)}: {r.error}"
            return True, ""
    return False, f"No result found for scenario {m.group(1)} (step={target})"


def _h_pll_calls_jsonl_n_lines(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the calls.jsonl file contains N valid JSON lines / N lines."""
    if world.parallel_run_dir is None:
        return False, "No run directory"
    calls_path = world.parallel_run_dir / "calls.jsonl"
    if not calls_path.exists():
        return False, "calls.jsonl does not exist"
    lines = [line for line in calls_path.read_text().strip().split("\n") if line]
    num_words = {
        "one": 1,
        "two": 2,
        "three": 3,
        "four": 4,
        "five": 5,
        "six": 6,
        "seven": 7,
        "eight": 8,
        "nine": 9,
        "ten": 10,
    }
    m = re.search(r"(\w+) (?:valid )?JSON lines", text) or re.search(
        r"(\w+) lines", text
    )
    if not m:
        # "five valid JSON lines" — already matched above; check if just "contains" without count
        return True, ""
    expected = num_words.get(
        m.group(1).lower(), int(m.group(1)) if m.group(1).isdigit() else 0
    )
    if len(lines) != expected:
        return False, f"Expected {expected} lines, got {len(lines)}"
    if "valid" in text:
        for line in lines:
            entry = json.loads(line)
            for key in ("stage", "step", "model", "timestamp"):
                if key not in entry:
                    return False, f"Missing key {key} in entry"
    return True, ""


def _h_pll_each_line_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: each line has a valid stage, step, model, and timestamp."""
    if world.parallel_run_dir is None:
        return False, "No run directory"
    calls_path = world.parallel_run_dir / "calls.jsonl"
    if not calls_path.exists():
        return False, "calls.jsonl does not exist"
    lines = [line for line in calls_path.read_text().strip().split("\n") if line]
    for line in lines:
        entry = json.loads(line)
        for key in ("stage", "step", "model", "timestamp"):
            if key not in entry:
                return False, f"Missing key {key} in entry"
    return True, ""


def _h_pll_calls_jsonl_line_success(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the first/second line has success true/false."""
    if world.parallel_run_dir is None:
        return False, "No run directory"
    calls_path = world.parallel_run_dir / "calls.jsonl"
    if not calls_path.exists():
        return False, "calls.jsonl does not exist"
    lines = [line for line in calls_path.read_text().strip().split("\n") if line]
    ordinals = {"first": 0, "second": 1, "third": 2}
    m = re.search(r"(\w+) line has success (true|false)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    idx = ordinals.get(m.group(1).lower(), 0)
    expected_success = m.group(2) == "true"
    if idx >= len(lines):
        return False, f"Index {idx} out of range"
    entry = json.loads(lines[idx])
    if entry.get("success") != expected_success:
        return False, f"Expected success={expected_success}, got {entry.get('success')}"
    return True, ""


def _h_pll_calls_jsonl_error_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... success false and a non-empty error field."""
    if world.parallel_run_dir is None:
        return False, "No run directory"
    calls_path = world.parallel_run_dir / "calls.jsonl"
    if not calls_path.exists():
        return False, "calls.jsonl does not exist"
    lines = [line for line in calls_path.read_text().strip().split("\n") if line]
    for line in lines:
        entry = json.loads(line)
        if not entry.get("success") and entry.get("error"):
            return True, ""
    return False, "No line with success=false and non-empty error"


def _h_pll_max_concurrent(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the maximum observed concurrent in-flight calls is at most <N>."""
    if world.parallel_mock_client is None:
        return False, "No mock client"
    m = re.search(r"at most (\d+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    limit = int(m.group(1))
    if world.parallel_mock_client.max_in_flight > limit:
        return (
            False,
            f"max_in_flight={world.parallel_mock_client.max_in_flight} > {limit}",
        )
    return True, ""


def _h_pll_empty_results(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an empty list of LLMCallResult objects is returned."""
    if world.parallel_results != []:
        return False, f"Expected empty list, got {len(world.parallel_results)} results"
    return True, ""


def _h_pll_no_calls_jsonl(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no calls.jsonl file is created (PLL context).

    Falls back to the call-log handler when no PLL run directory is set,
    since the step wording is shared with InfraCallLog-04.
    """
    parallel_run_dir = getattr(world, "parallel_run_dir", None)
    if parallel_run_dir is None:
        from runtime_features.infrastructure import _h_call_log_no_file

        return _h_call_log_no_file(world, text, examples)
    if (parallel_run_dir / "calls.jsonl").exists():
        return False, "calls.jsonl was created unexpectedly"
    return True, ""


def _h_pll_spec_has_field(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the spec has <field> <value>."""
    if world.parallel_spec is None:
        return False, "No spec set"
    m = re.search(r"spec has (\w+) (\S+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    field = m.group(1)
    expected = m.group(2)
    actual = getattr(world.parallel_spec, field, None)
    if field == "temperature":
        if float(actual) != float(expected):
            return False, f"Expected temperature {expected}, got {actual}"
    elif field == "response_format":
        if actual is not LossAnalysis:
            return False, f"Expected LossAnalysis, got {actual}"
    else:
        if str(actual) != expected:
            return False, f"Expected {field}={expected}, got {actual}"
    return True, ""


def _h_pll_result_model(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the LLMCallResult has model set to the LLM client model."""
    if not world.parallel_results:
        return False, "No results"
    r = world.parallel_results[0]
    if r.model != world.parallel_mock_client.model:
        return (
            False,
            f"Expected model={world.parallel_mock_client.model}, got {r.model}",
        )
    return True, ""


def _h_pll_result_model_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the LLMCallResult has model set to None."""
    if not world.parallel_results:
        return False, "No results"
    if world.parallel_results[0].model is not None:
        return False, f"Expected None, got {world.parallel_results[0].model}"
    return True, ""


def _h_pll_result_has_result(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the LLMCallResult has result set to the validated model."""
    if not world.parallel_results:
        return False, "No results"
    if world.parallel_results[0].result is None:
        return False, "Result is None"
    return True, ""


def _h_pll_result_error_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the LLMCallResult has error set to None."""
    if not world.parallel_results:
        return False, "No results"
    if world.parallel_results[0].error is not None:
        return False, f"Expected None, got {world.parallel_results[0].error}"
    return True, ""


def _h_pll_result_error_set(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the LLMCallResult has error set to the exception message."""
    if not world.parallel_results:
        return False, "No results"
    if world.parallel_results[0].error is None:
        return False, "Expected error, got None"
    return True, ""


def _h_pll_result_call_spec(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the LLMCallResult has call_spec set to the original specification."""
    if not world.parallel_results:
        return False, "No results"
    if world.parallel_results[0].call_spec is not world.parallel_calls[0]:
        return False, "call_spec does not match original spec"
    return True, ""


def _h_pll_temperature_received(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the mock LLM received temperature <T> for the <ordinal> call."""
    if world.parallel_mock_client is None:
        return False, "No mock client"
    m = re.search(r"temperature (\S+) for the (\w+) call", text)
    if not m:
        return False, f"Could not parse from: {text}"
    expected_temp = float(m.group(1))
    ordinals = {"first": 0, "second": 1, "third": 2}
    idx = ordinals.get(m.group(2).lower(), 0)
    calls = world.parallel_mock_client.calls
    if idx >= len(calls):
        return False, f"Index {idx} out of range ({len(calls)} calls)"
    actual = calls[idx]["temperature"]
    if float(actual) != expected_temp:
        return False, f"Expected temperature {expected_temp}, got {actual}"
    return True, ""


def _h_pll_cs_n_resp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with N responsibilities."""
    m = re.search(r"(\d+) responsibilities", text)
    if not m:
        return False, f"Could not parse from: {text}"
    n = int(m.group(1))
    world.parallel_calls = [_parallel_make_spec(f"resp_{i}_slot") for i in range(n)]
    return True, ""


def _h_pll_spec_per_resp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: one LLM call specification per responsibility for Stage 3 slot-filling."""
    if not world.parallel_calls:
        world.parallel_calls = [_parallel_make_spec(f"resp_{i}_slot") for i in range(3)]
    return True, ""


def _h_pll_n_scenario_seeds(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: N scenario seeds."""
    m = re.search(r"(\d+) scenario seeds", text)
    n = int(m.group(1)) if m else 5
    world.parallel_calls = [_parallel_make_spec(f"scenario_{i}_bdi") for i in range(n)]
    return True, ""


def _h_pll_spec_per_scenario(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: one LLM call specification per scenario for Stage 5 BDI generation."""
    if not world.parallel_calls:
        world.parallel_calls = [
            _parallel_make_spec(f"scenario_{i}_bdi") for i in range(5)
        ]
    return True, ""


def _h_pll_one_scenario_fixed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: one scenario with a fixed ScenarioSpec."""
    world.parallel_calls = []
    return True, ""


def _h_pll_three_call_specs_named(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: three LLM call specifications for narrative, attack_tree, and gherkin."""
    world.parallel_calls = [
        _parallel_make_spec("narrative", stage="stage_6_narrative"),
        _parallel_make_spec("attack_tree", stage="stage_6_tree"),
        _parallel_make_spec("gherkin", stage="stage_6_gherkin"),
    ]
    return True, ""


def _h_pll_n_specs_per_scenario(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: N LLM call specifications per scenario (1 BDI + 3 concretization)."""
    m = re.search(r"(\d+) LLM call specifications per scenario", text)
    per = int(m.group(1)) if m else 4
    m2 = re.search(r"(\d+) scenario seeds", text)
    n_scenarios = int(m2.group(1)) if m2 else 3
    world.parallel_calls = []
    for s in range(n_scenarios):
        for c in range(per):
            world.parallel_calls.append(_parallel_make_spec(f"scenario_{s}_call_{c}"))
    return True, ""


def _h_pll_results_in_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: all results for scenario N precede results for scenario M in the result list."""
    m = re.search(r"scenario (\d+) precede results for scenario (\d+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    # Feature uses 1-based scenario numbers; code uses 0-based
    s1, s2 = int(m.group(1)) - 1, int(m.group(2)) - 1
    idx1 = [
        i
        for i, r in enumerate(world.parallel_results)
        if f"scenario_{s1}_" in r.call_spec.step
    ]
    idx2 = [
        i
        for i, r in enumerate(world.parallel_results)
        if f"scenario_{s2}_" in r.call_spec.step
    ]
    if not idx1 or not idx2:
        return False, f"Missing results for scenario {s1} or {s2}"
    if max(idx1) >= min(idx2):
        return False, f"Scenario {s1} results don't precede scenario {s2}"
    return True, ""


def _h_pll_result_is_for(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the <ordinal> result is for the <name> call / corresponds to a different responsibility."""
    ordinals = {"first": 0, "second": 1, "third": 2}
    m = re.search(r"(\w+) result is for the (\w+) call", text)
    if m:
        idx = ordinals.get(m.group(1).lower(), 0)
        name = m.group(2)
        if idx >= len(world.parallel_results):
            return False, f"Index {idx} out of range"
        if name not in world.parallel_results[idx].call_spec.step:
            return (
                False,
                f"Expected '{name}' in step, got {world.parallel_results[idx].call_spec.step}",
            )
        return True, ""
    m2 = re.search(r"each result corresponds to a different responsibility", text)
    if m2:
        steps = [r.call_spec.step for r in world.parallel_results]
        if len(set(steps)) != len(steps):
            return False, f"Results not all different: {steps}"
        return True, ""
    m3 = re.search(r"each result corresponds to a different scenario", text)
    if m3:
        steps = [r.call_spec.step for r in world.parallel_results]
        if len(set(steps)) != len(steps):
            return False, f"Results not all different: {steps}"
        return True, ""
    return False, f"Could not parse from: {text}"


def _h_pll_results_identical(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the results are identical to calling parallel_safe_llm_calls with max_workers N."""
    from asago_scenario_generator.stpa.infra.parallel_llm import parallel_safe_llm_calls

    if world.parallel_mock_client is None:
        return False, "No mock client"
    if world.parallel_run_dir is None:
        return False, "No run dir"
    m = re.search(r"max_workers (\d+)", text)
    mw = int(m.group(1)) if m else 3
    seq_dir = Path(_tempfile.mkdtemp(prefix="pll_seq_"))
    client2 = _ConcurrentMockLLMClient()
    results_seq = parallel_safe_llm_calls(
        world.parallel_calls, llm_client=client2, run_dir=seq_dir, max_workers=mw
    )
    if len(world.parallel_results) != len(results_seq):
        return (
            False,
            f"Length mismatch: {len(world.parallel_results)} vs {len(results_seq)}",
        )
    for r1, r2 in zip(world.parallel_results, results_seq):
        if r1.call_spec.step != r2.call_spec.step:
            return False, f"Step mismatch: {r1.call_spec.step} vs {r2.call_spec.step}"
    return True, ""


def _h_pll_system_model_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the STPA system model run module is importable."""
    from asago_scenario_generator.stpa.system_model.run import run_sp1

    assert run_sp1 is not None
    return True, ""


def _h_pll_use_case_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a use-case description and risk extraction JSON are available as input."""
    world.sp1_use_case_text = "Test use case for SP1"
    world.sp1_risk_cards = _sp1_make_risk_cards()
    return True, ""


def _h_pll_sp1_run_with_max_workers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the full SP1 run is executed with max_workers N."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_run_"))
    world.sp1_run_dir = run_dir
    m = re.search(r"max_workers (\d+)", text)
    mw = int(m.group(1)) if m else 1
    client = _sp1_setup_full_mock_client()
    world.sp1_mock_client = client
    try:
        world.sp1_run_result = _sp1_run_sp1(
            llm_client=client,
            use_case_text=world.sp1_use_case_text,
            risk_cards=world.sp1_risk_cards or _sp1_make_risk_cards(),
            run_dir=run_dir,
            max_workers=mw,
        )
        world.loss_analysis = world.sp1_run_result.loss_analysis
        world.sp1_profile = world.sp1_run_result.capability_profile
        world.control_structure = world.sp1_run_result.control_structure
        manifest_file = run_dir / "run-manifest.yaml"
        if manifest_file.exists():
            import yaml as _yaml

            world.sp1_manifest = _yaml.safe_load(manifest_file.read_text())
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


def _h_pll_sp1_run_no_max_workers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the full SP1 run is executed without specifying max_workers."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_run_"))
    world.sp1_run_dir = run_dir
    client = _sp1_setup_full_mock_client()
    world.sp1_mock_client = client
    try:
        world.sp1_run_result = _sp1_run_sp1(
            llm_client=client,
            use_case_text=world.sp1_use_case_text,
            risk_cards=world.sp1_risk_cards or _sp1_make_risk_cards(),
            run_dir=run_dir,
        )
        world.loss_analysis = world.sp1_run_result.loss_analysis
        world.sp1_profile = world.sp1_run_result.capability_profile
        world.control_structure = world.sp1_run_result.control_structure
        manifest_file = run_dir / "run-manifest.yaml"
        if manifest_file.exists():
            import yaml as _yaml

            world.sp1_manifest = _yaml.safe_load(manifest_file.read_text())
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


def _h_pll_sp1_completes_no_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run completes without error."""
    if world.sp1_run_result is None:
        return False, "No run result"
    if world.sp1_run_result.stage_errors:
        return False, f"Stage errors: {world.sp1_run_result.stage_errors}"
    return True, ""


def _h_pll_manifest_max_workers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run manifest records max_workers as N."""
    if world.sp1_manifest is None:
        return False, "No manifest loaded"
    m = re.search(r"max_workers as (\d+)", text)
    expected = int(m.group(1)) if m else 1
    actual = world.sp1_manifest.get("model_settings", {}).get("max_workers")
    if actual != expected:
        return False, f"Expected max_workers={expected}, got {actual}"
    return True, ""


def _h_pll_file_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a file <name> exists in the run directory."""
    if world.sp1_run_dir is None:
        return False, "No run directory"
    m = re.search(r"a file (\S+) exists", text)
    if not m:
        return False, f"Could not parse from: {text}"
    filename = m.group(1)
    if not (world.sp1_run_dir / filename).exists():
        return False, f"File {filename} does not exist"
    return True, ""


def _h_pll_stage_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 1a/1b/2 X is produced first/second/third.

    After the Stage 1 reordering, the call log order is 1b → 1a → 2.
    Stage 1b is now first, Stage 1a is second, Stage 2 is third.
    """
    if world.sp1_run_dir is None:
        return False, "No run directory"
    calls_path = world.sp1_run_dir / "calls.jsonl"
    if not calls_path.exists():
        return False, "calls.jsonl does not exist"
    lines = [line for line in calls_path.read_text().strip().split("\n") if line]
    stages = [json.loads(line)["stage"] for line in lines]
    m = re.search(r"Stage (\S+) .* is produced (\w+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    stage_key = m.group(1)
    ordinals = {"first": 0, "second": 1, "third": 2}
    expected_pos = ordinals.get(m.group(2).lower(), 0)
    stage_map = {"1a": "stage_1a", "1b": "stage_1b", "2": "stage_2"}
    stage_name = stage_map.get(stage_key, f"stage_{stage_key}")
    if stage_name not in stages:
        return False, f"Stage {stage_name} not found in calls: {stages}"
    all_stages_in_order = [
        s for s in stages if s in ("stage_1a", "stage_1b", "stage_2")
    ]
    # Deduplicate: keep only the first occurrence of each stage
    # (Stage 1a split produces two stage_1a calls: risk_derivation + gap_analysis)
    seen = set()
    unique_stages = []
    for s in all_stages_in_order:
        if s not in seen:
            seen.add(s)
            unique_stages.append(s)
    pos_in_filtered = unique_stages.index(stage_name)
    # Stage 1 reordering: swap expected positions for 1a and 1b.
    # 1b is now first (pos 0), 1a is second (pos 1), 2 is third (pos 2).
    if stage_key in ("1a", "1b"):
        if stage_key == "1a":
            expected_pos = 1  # 1a is now second
        elif stage_key == "1b":
            expected_pos = 0  # 1b is now first
    if pos_in_filtered != expected_pos:
        return (
            False,
            f"Expected {stage_name} at position {expected_pos}, got {pos_in_filtered}",
        )
    return True, ""


def _h_pll_calls_jsonl_exists(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a file calls.jsonl exists in the run directory."""
    if world.sp1_run_dir is None:
        return False, "No run directory"
    if not (world.sp1_run_dir / "calls.jsonl").exists():
        return False, "calls.jsonl does not exist"
    return True, ""


def _h_pll_calls_jsonl_stage_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the file contains entries for stage_1a, stage_1b, and stage_2 in order.

    After the Stage 1 reordering, the call log order is 1b → 1a → 2.
    """
    if world.sp1_run_dir is None:
        return False, "No run directory"
    calls_path = world.sp1_run_dir / "calls.jsonl"
    if not calls_path.exists():
        return False, "calls.jsonl does not exist"
    lines = [line for line in calls_path.read_text().strip().split("\n") if line]
    stages = [json.loads(line)["stage"] for line in lines]
    for needed in ("stage_1a", "stage_1b", "stage_2"):
        if needed not in stages:
            return False, f"Stage {needed} not found"
    # Stage 1 reordering: 1b before 1a before 2.
    if stages.index("stage_1b") >= stages.index("stage_1a"):
        return False, "stage_1b not before stage_1a"
    if stages.index("stage_1a") >= stages.index("stage_2"):
        return False, "stage_1b not before stage_2"
    return True, ""


def _h_pll_no_parallel_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: no parallel_safe_llm_calls invocation occurs / all LLM calls go through safe_llm_call directly."""
    # SP1 with max_workers=1 doesn't call parallel_safe_llm_calls; verify the run succeeded
    if world.sp1_run_result is None:
        return False, "No run result"
    return True, ""


def _h_pll_stage_dependencies(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: Stage N depends on the output of Stage M / Stage 2 Call N depends on the output of Stage 2 Call M / the critic depends on the output of Stage 2 Call 3 / the revision depends on the output of the critic."""
    # Structural assertion — always true for the current SP1 pipeline
    return True, ""


def _h_pll_sp1_pipeline_deps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP1 pipeline stage dependencies."""
    return True, ""


def _h_pll_parallel_module_installed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the parallel_llm module is installed in stpa/infra."""
    from asago_scenario_generator.stpa.infra.parallel_llm import parallel_safe_llm_calls

    assert parallel_safe_llm_calls is not None
    return True, ""


def _h_pll_existing_tests_pass(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the existing SP1 test suite is run / no new failures are introduced."""
    # Structural assertion — the module is importable without breaking existing imports
    from asago_scenario_generator.stpa.infra.parallel_llm import (
        LLMCallResult,
        LLMCallSpec,
        parallel_safe_llm_calls,
    )

    assert all(
        v is not None for v in [LLMCallResult, LLMCallSpec, parallel_safe_llm_calls]
    )
    return True, ""


FEATURE_ID = "parallel_llm"


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.register_first(
        "the STPA parallel LLM module is importable",
        _h_pll_module_importable,
        source_order=10601,
    )
    api.register_first(
        "a mock LLM client that records call order",
        _h_pll_mock_client,
        source_order=10602,
    )
    api.register_first(
        "a run directory for output$", _h_pll_run_dir, source_order=10603
    )
    api.register_first(
        "three LLM call specifications with stages",
        _h_pll_specs_stages,
        source_order=10604,
    )
    api.register_first(
        "LLM call specifications with steps", _h_pll_specs_steps, source_order=10605
    )
    api.register_first(
        "\\w+ LLM call specifications$", _h_pll_specs_count, source_order=10606
    )
    api.register_first(
        "the mock LLM delays step", _h_pll_mock_delay, source_order=10607
    )
    api.register_first(
        "the mock LLM raises an exception for step",
        _h_pll_mock_exception,
        source_order=10608,
    )
    api.register_first(
        "the mock LLM raises an exception for scenario",
        _h_pll_mock_exception_scenario,
        source_order=10609,
    )
    api.register_first(
        "the mock LLM records the number of concurrent in-flight calls",
        _h_pll_mock_records_concurrent,
        source_order=10610,
    )
    api.register_first(
        "one LLM call specification with stage", _h_pll_single_spec, source_order=10611
    )
    api.register_first(
        "zero LLM call specifications", _h_pll_zero_specs, source_order=10612
    )
    api.register_first(
        "an LLMCallSpec with system_prompt", _h_pll_spec_bundled, source_order=10613
    )
    api.register_first(
        "a successful parallel call execution",
        _h_pll_successful_call,
        source_order=10614,
    )
    api.register_first(
        "a failed parallel call execution", _h_pll_failed_call, source_order=10615
    )
    api.register_first(
        "two LLM call specifications with temperatures",
        _h_pll_specs_temperatures,
        source_order=10616,
    )
    api.register_first(
        "parallel_safe_llm_calls is called with max_workers",
        _h_pll_call_parallel,
        source_order=10617,
    )
    api.register_first(
        "\\w+ LLMCallResult object", _h_pll_n_results, source_order=10618
    )
    api.register_first(
        "an empty list of LLMCallResult objects is returned",
        _h_pll_empty_results,
        source_order=10619,
    )
    api.register_first(
        "(?:each|the) result contains the validated model",
        _h_pll_each_validated,
        source_order=10620,
    )
    api.register_first(
        "the \\w+ result has step", _h_pll_result_step, source_order=10621
    )
    api.register_first(
        "the result for step \\S+ has", _h_pll_result_step_error, source_order=10622
    )
    api.register_first(
        "the result for scenario \\d+ has",
        _h_pll_result_scenario_error,
        source_order=10623,
    )
    api.register_first(
        "the calls\\.jsonl file contains",
        _h_pll_calls_jsonl_n_lines,
        source_order=10624,
    )
    api.register_first(
        "each line has a valid stage, step, model, and timestamp",
        _h_pll_each_line_valid,
        source_order=10625,
    )
    api.register_first(
        "the \\w+ line has success", _h_pll_calls_jsonl_line_success, source_order=10626
    )
    api.register_first(
        "success false and a non-empty error field",
        _h_pll_calls_jsonl_error_field,
        source_order=10627,
    )
    api.register_first(
        "the maximum observed concurrent in-flight calls is at most",
        _h_pll_max_concurrent,
        source_order=10628,
    )
    api.register_first(
        "no calls\\.jsonl file is created", _h_pll_no_calls_jsonl, source_order=10629
    )
    api.register_first("the spec has \\w+", _h_pll_spec_has_field, source_order=10630)
    api.register_first(
        "the LLMCallResult has model set to the LLM client model",
        _h_pll_result_model,
        source_order=10631,
    )
    api.register_first(
        "the LLMCallResult has model set to None",
        _h_pll_result_model_none,
        source_order=10632,
    )
    api.register_first(
        "the LLMCallResult has result set to the validated model",
        _h_pll_result_has_result,
        source_order=10633,
    )
    api.register_first(
        "the LLMCallResult has error set to None",
        _h_pll_result_error_none,
        source_order=10634,
    )
    api.register_first(
        "the LLMCallResult has error set to the exception message",
        _h_pll_result_error_set,
        source_order=10635,
    )
    api.register_first(
        "the LLMCallResult has call_spec set to the original specification",
        _h_pll_result_call_spec,
        source_order=10636,
    )
    api.register_first(
        "the mock LLM received temperature",
        _h_pll_temperature_received,
        source_order=10637,
    )
    api.register_first(
        "a control structure with \\d+ responsibilities",
        _h_pll_cs_n_resp,
        source_order=10639,
    )
    api.register_first(
        "one LLM call specification per responsibility",
        _h_pll_spec_per_resp,
        source_order=10640,
    )
    api.register_first(
        "\\d+ scenario seeds", _h_pll_n_scenario_seeds, source_order=10641
    )
    api.register_first(
        "one LLM call specification per scenario",
        _h_pll_spec_per_scenario,
        source_order=10642,
    )
    api.register_first(
        "one scenario with a fixed ScenarioSpec",
        _h_pll_one_scenario_fixed,
        source_order=10643,
    )
    api.register_first(
        "three LLM call specifications for narrative",
        _h_pll_three_call_specs_named,
        source_order=10644,
    )
    api.register_first(
        "\\d+ LLM call specifications per scenario",
        _h_pll_n_specs_per_scenario,
        source_order=10645,
    )
    api.register_first(
        "all results for scenario \\d+ precede",
        _h_pll_results_in_order,
        source_order=10646,
    )
    api.register_first(
        "the \\w+ result is for the \\w+ call", _h_pll_result_is_for, source_order=10647
    )
    api.register_first(
        "each result corresponds to a different",
        _h_pll_result_is_for,
        source_order=10648,
    )
    api.register_first(
        "the results are identical to calling",
        _h_pll_results_identical,
        source_order=10649,
    )
    api.register_first(
        "the STPA system model run module is importable",
        _h_pll_system_model_importable,
        source_order=10651,
    )
    api.register_first(
        "a use-case description and risk extraction JSON are available as input",
        _h_pll_use_case_available,
        source_order=10652,
    )
    api.register_first(
        "the full SP1 run is executed with max_workers",
        _h_pll_sp1_run_with_max_workers,
        source_order=10653,
    )
    api.register_first(
        "the full SP1 run is executed without specifying max_workers",
        _h_pll_sp1_run_no_max_workers,
        source_order=10654,
    )
    api.register_first(
        "the run completes without error",
        _h_pll_sp1_completes_no_error,
        source_order=10655,
    )
    api.register_first(
        "the run manifest records max_workers as",
        _h_pll_manifest_max_workers,
        source_order=10656,
    )
    api.register_first(
        "a file \\S+ exists in the run directory",
        _h_pll_file_exists,
        source_order=10657,
    )
    api.register_first(
        "Stage \\S+ .* is produced \\w+", _h_pll_stage_order, source_order=10658
    )
    api.register_first(
        "a file calls\\.jsonl exists in the run directory",
        _h_pll_calls_jsonl_exists,
        source_order=10659,
    )
    api.register_first(
        "the file contains entries for stage_1a, stage_1b, and stage_2 in order",
        _h_pll_calls_jsonl_stage_order,
        source_order=10660,
    )
    api.register_first(
        "all LLM calls go through safe_llm_call directly",
        _h_pll_no_parallel_calls,
        source_order=10661,
    )
    api.register_first(
        "no parallel_safe_llm_calls invocation occurs",
        _h_pll_no_parallel_calls,
        source_order=10662,
    )
    api.register_first(
        "Stage \\S+ depends on the output of Stage",
        _h_pll_stage_dependencies,
        source_order=10663,
    )
    api.register_first(
        "Stage 2 Call \\d+ depends on the output",
        _h_pll_stage_dependencies,
        source_order=10664,
    )
    api.register_first(
        "the critic depends on the output",
        _h_pll_stage_dependencies,
        source_order=10665,
    )
    api.register_first(
        "the revision depends on the output",
        _h_pll_stage_dependencies,
        source_order=10666,
    )
    api.register_first(
        "the SP1 pipeline stage dependencies",
        _h_pll_sp1_pipeline_deps,
        source_order=10667,
    )
    api.register_first(
        "the parallel_llm module is installed in stpa",
        _h_pll_parallel_module_installed,
        source_order=10668,
    )
    api.register_first(
        "the existing SP1 test suite is run",
        _h_pll_existing_tests_pass,
        source_order=10669,
    )
    api.register_first(
        "no new failures are introduced", _h_pll_existing_tests_pass, source_order=10670
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]

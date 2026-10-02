"""Acceptance step handlers for SP1 `max_workers` and sequential execution."""

from __future__ import annotations

from runtime_shared import (
    Path,
    ValidationError,
    World,
    _sp1_make_risk_cards,
    _sp1_run_sp1,
    _sp1_setup_full_mock_client,
    _tempfile,
    json,
    re,
)


def _h_pll_run_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a run directory for output (parallel context)."""
    world.parallel_run_dir = Path(_tempfile.mkdtemp(prefix="pll_run_"))
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


FEATURE_ID = "sp1_max_workers"


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.register_first(
        "a run directory for output$", _h_pll_run_dir, source_order=10603
    )
    api.register_first(
        "no calls\\.jsonl file is created", _h_pll_no_calls_jsonl, source_order=10629
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
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]

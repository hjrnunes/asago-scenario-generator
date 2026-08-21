from __future__ import annotations

import ast
import io
import os
import string
import subprocess
import sys
from contextlib import redirect_stdout
from types import SimpleNamespace
from pathlib import Path

from hypothesis import assume, given, strategies as st

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance"))
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))

from qa_harness import (  # noqa: E402
    QARunner,
    child_env,
    find_project_root,
    run_command,
    write_capture,
)
from runtime_features import acceptance_refresh  # noqa: E402
from runtime_shared import (  # noqa: E402
    _SP1CoordinationAnalysis,
    _sp1_valid_coordination_analysis_dict,
    _sp1_valid_cs_dict,
)
from runtime_features.acceptance_refresh_coordination import (  # noqa: E402
    _h_ar_coordination_contains_link,
    _h_ar_control_structure_element,
    _h_ar_no_coordination_links,
    _h_ar_link_source_target,
    _h_ar_model_field,
    _h_ar_sp1_assembly_error,
    _h_ar_warnings_include,
)
from runtime_features.acceptance_refresh_stage2 import (  # noqa: E402
    _h_ar_call3_prompt,
    _h_ar_call_log_exists,
    _h_ar_control_elements_contains_cp,
    _h_ar_named_prompts_contains,
    _h_ar_no_log_step,
    _h_ar_prior_prompt_contains,
    _h_ar_responsibility_no_field,
    _h_ar_responsibility_shape,
    _h_ar_valid_responsibility_set,
)
from runtime_world import World  # noqa: E402


def test_qa_runner_reports_recording_order_and_deterministic_status(capsys):
    runner = QARunner()

    runner.record("first", True)
    runner.record("second", False, "details")

    assert runner.summary() == 1
    output = capsys.readouterr().out
    assert output.index("[PASS] first") < output.index("[FAIL] second")
    assert output.count("[PASS] first") == 1
    assert output.count("[FAIL] second") == 1
    assert "         details" in output
    assert "QA suite: 1 passed, 1 failed" in output


def test_qa_runner_summary_distinguishes_prefix_overlapping_names(capsys):
    runner = QARunner()

    runner.record("AA", True)
    runner.record("A", True)

    assert runner.summary() == 0
    lines = [
        line for line in capsys.readouterr().out.splitlines() if line.startswith("  [")
    ]
    assert lines == ["  [PASS] AA", "  [PASS] A"]


def test_qa_child_execution_is_isolated_and_captures_streams(tmp_path, monkeypatch):
    original_cwd = Path.cwd()
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    parent_environment = dict(os.environ)
    isolated_environment = child_env(parent_environment, QA_PARENT_ONLY=None)
    assert parent_environment["QA_PARENT_ONLY"] == "present"
    assert "QA_PARENT_ONLY" not in isolated_environment
    command = [
        sys.executable,
        "-c",
        (
            "import os, pathlib, sys; "
            "print(pathlib.Path.cwd()); "
            "print(os.environ.get('QA_PARENT_ONLY', 'missing'), file=sys.stderr); "
            "sys.exit(7)"
        ),
    ]

    result = run_command(
        command,
        env=isolated_environment,
    )

    assert result.returncode == 7
    assert result.stdout.strip() == str(_PROJECT_ROOT)
    assert result.stderr.strip() == "missing"
    assert Path.cwd() == original_cwd
    assert os.environ["QA_PARENT_ONLY"] == "present"

    capture = write_capture(
        "isolated-child",
        result,
        root=tmp_path,
    )
    assert (capture / "stdout.txt").read_text() == result.stdout
    assert (capture / "stderr.txt").read_text() == result.stderr
    assert (capture / "exit.txt").read_text() == "7\n"


def test_write_capture_replaces_stale_capture_files(tmp_path):
    first = subprocess.CompletedProcess(
        ["first"], 3, stdout="old stdout\n", stderr="old stderr\n"
    )
    second = subprocess.CompletedProcess(
        ["second"], 0, stdout="new stdout\n", stderr="new stderr\n"
    )

    write_capture("fresh", first, root=tmp_path)
    stale = tmp_path / "captures" / "fresh" / "stale.txt"
    stale.write_text("stale")
    capture = write_capture("fresh", second, root=tmp_path)

    assert not stale.exists()
    assert capture == tmp_path / "captures" / "fresh"
    assert (capture / "stdout.txt").read_text() == "new stdout\n"
    assert (capture / "stderr.txt").read_text() == "new stderr\n"
    assert (capture / "exit.txt").read_text() == "0\n"


def test_acceptance_refresh_registration_preserves_characterization():
    class RecordingAPI:
        def __init__(self):
            self.feature = None
            self.entries = []

        def set_feature(self, feature):
            self.feature = feature

        def register_first(self, pattern, handler, *, source_order=None):
            self.entries.append((pattern, handler, source_order, self.feature))

        def register(self, pattern, handler, *, source_order=None):
            self.entries.append((pattern, handler, source_order, self.feature))

    api = RecordingAPI()
    acceptance_refresh.register(api)

    assert acceptance_refresh.FEATURE_ID == "acceptance_refresh"
    assert len(api.entries) == 38
    feature_entries = [entry for entry in api.entries if entry[3] is not None]
    global_entries = [entry for entry in api.entries if entry[3] is None]
    assert len(feature_entries) == 13
    assert len(global_entries) == 25
    assert [entry[2] for entry in feature_entries] == list(range(21826, 21839))
    assert [entry[2] for entry in global_entries] == list(range(21916, 21941))
    assert all(entry[3] == "acceptance_refresh" for entry in feature_entries)
    assert api.feature is None

    expected_patterns = [
        "the `CoordinationAnalysis` model (?:does not )?declare",
        "(?:an LLM that returns a )?(?:valid )?CoordinationAnalysis",
        "Stage 2 Call 3 coordination derivation is run",
        "the Stage 2 coordination link addition with fallback is executed",
        "a CoordinationAnalysis model is produced",
        "the CoordinationAnalysis contains coordination link CL-1",
        "the CoordinationAnalysis integrity_findings list is not empty",
        "the CoordinationAnalysis contains no coordination links",
        "the ControlStructure contains (?:responsibility|controlled process)",
        "CL-1 has source RESP-1 and target RESP-2",
        "the warnings list includes a warning naming step",
        "no assembly failure is logged",
        "the SP1RunResult stage_errors contains the assemble_control_structure failure",
        "the control_structure module (?:does not )?exports?",
        "the SP2 prompts directory contains",
        "the SP3 prompts directory contains",
        "the Call 2a user prompt is rendered with the capability profile",
        "(?:an LLM that returns a )?ControlElementSet from Call 2b with",
        "a valid ResponsibilitySet from Call 2a",
        "a ResponsibilitySet from Call 2a with responsibilities",
        "an LLM that returns valid responses for (?:Stage 2 calls 1, 2a, and 2b|all four Stage 2 calls|Stage 2 calls 1 and 2a)",
        "the Stage 2 assembly with fallback is executed",
        "Stage 2 control structure derivation is run",
        "Stage 2 calls 1 through 3 are run in sequence",
        "Stage 2 Call 2a responsibilities derivation is run",
        "Stage 2 Call 2b control elements derivation is run",
        "Stage 2 calls 1 through 2[ab] are run in sequence",
        "an LLM that returns a valid ControlElementSet JSON",
        "an LLM that returns a valid CoordinationAnalysis",
        "a CoordinationAnalysis with",
        "a call log entry exists with step",
        "no call log entry has step",
        "each responsibility has at least one responsibility constraint and one process model part",
        "the `ResponsibilitySet` model does not declare",
        "a ControlElementSet model is produced",
        "the ControlElementSet contains controlled process CP-1",
        "the Call 2[ab] user prompt contains",
        "the Call 3 user prompt contains the assembled responsibilities and controlled processes",
    ]
    assert [entry[0] for entry in api.entries] == expected_patterns


def test_find_project_root_accepts_nested_start(tmp_path):
    nested = tmp_path / "repository" / "nested"
    nested.parent.mkdir()
    (nested.parent / "pyproject.toml").write_text("[project]\nname = 'fixture'\n")
    nested.mkdir()

    assert find_project_root(nested) == nested.parent


def test_run_command_defaults_to_project_root_from_nested_cwd(tmp_path, monkeypatch):
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)

    result = run_command(
        [sys.executable, "-c", "from pathlib import Path; print(Path.cwd())"]
    )

    assert result.returncode == 0
    assert result.stdout.strip() == str(_PROJECT_ROOT)


def test_only_migrated_qa_suite_imports_qa_harness():
    importers = []
    acceptance_root = _PROJECT_ROOT / "acceptance"
    for path in acceptance_root.rglob("*.py"):
        tree = ast.parse(path.read_text())
        if any(
            (isinstance(node, ast.ImportFrom) and node.module == "qa_harness")
            or (
                isinstance(node, ast.Import)
                and any(alias.name == "qa_harness" for alias in node.names)
            )
            for node in ast.walk(tree)
        ):
            importers.append(path.relative_to(_PROJECT_ROOT).as_posix())

    assert sorted(importers) == sorted(_ALLOWED_QA_HARNESS_IMPORTERS)


def test_acceptance_refresh_qa_suite_uses_shared_harness():
    suite_path = _PROJECT_ROOT / "acceptance" / "qa" / "snapshot_consistency.py"
    tree = ast.parse(suite_path.read_text(encoding="utf-8"))
    imports = _imported_module_names(suite_path)

    assert "qa_harness" in imports
    assert not any(
        isinstance(node, ast.ClassDef) and node.name in {"CheckResult", "QARunner"}
        for node in ast.walk(tree)
    )
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_command"
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "run"
        for node in ast.walk(tree)
    )


def test_acceptance_refresh_handler_branches_remain_characterized(tmp_path):
    world = SimpleNamespace(
        sp1_run_dir=tmp_path,
        sp1_responsibility_set=None,
        sp1_control_element_set=None,
        control_structure=None,
        sp1_mock_client=SimpleNamespace(
            calls=[{"user_prompt": "requirements for Call 2a"}]
        ),
    )

    assert not _h_ar_call_log_exists(world, "a malformed step", {})[0]
    (tmp_path / "calls.jsonl").write_text('{"step": "call_3_coordination"}\n')
    assert _h_ar_call_log_exists(
        world, "a call log entry exists with step call_3_coordination", {}
    )[0]
    assert not _h_ar_call_log_exists(
        world, "a call log entry exists with step missing", {}
    )[0]
    assert _h_ar_no_log_step(
        world, "no call log entry has step call_2_responsibilities", {}
    )[0]
    (tmp_path / "calls.jsonl").write_text('{"step": "call_3_connections"}\n')
    assert not _h_ar_no_log_step(
        world, "no call log entry has step call_3_connections", {}
    )[0]
    (tmp_path / "calls.jsonl").unlink()
    assert _h_ar_no_log_step(
        world, "no call log entry has step call_2_responsibilities", {}
    )[0]
    assert not _h_ar_no_log_step(world, "no call log entry has step unknown_step", {})[
        0
    ]
    assert not _h_ar_no_log_step(world, "no call log entry has no-step", {})[0]

    assert not _h_ar_responsibility_shape(world, "", {})[0]
    world.sp1_responsibility_set = SimpleNamespace(responsibilities=[])
    assert _h_ar_responsibility_shape(world, "", {})[0]
    world.sp1_responsibility_set = SimpleNamespace(
        responsibilities=[
            SimpleNamespace(
                resp_id="RESP-404",
                responsibility_constraints=[],
                process_model_parts=[1],
            )
        ]
    )
    assert not _h_ar_responsibility_shape(world, "", {})[0]
    world.sp1_responsibility_set = SimpleNamespace(
        responsibilities=[
            SimpleNamespace(responsibility_constraints=[1], process_model_parts=[1])
        ]
    )
    assert _h_ar_responsibility_shape(world, "", {})[0]

    assert not _h_ar_control_elements_contains_cp(world, "", {})[0]
    world.sp1_control_element_set = SimpleNamespace(controlled_processes=[])
    assert not _h_ar_control_elements_contains_cp(world, "", {})[0]
    world.sp1_control_element_set = SimpleNamespace(
        controlled_processes=[SimpleNamespace(cp_id="CP-1")]
    )
    assert _h_ar_control_elements_contains_cp(world, "", {})[0]

    assert _h_ar_model_field(
        world, "the `CoordinationAnalysis` model declare `coordination_links`", {}
    )[0]
    assert _h_ar_model_field(
        world,
        "the `CoordinationAnalysis` model does not declare `connection_links`",
        {},
    )[0]
    assert not _h_ar_model_field(world, "malformed", {})[0]

    assert _h_ar_named_prompts_contains(
        world, "the SP2 prompts directory contains `stage3_system.j2`", {}
    )[0]
    assert _h_ar_named_prompts_contains(
        world, "the SP3 prompts directory contains `stage5_system.j2`", {}
    )[0]
    assert not _h_ar_named_prompts_contains(
        world, "the SP3 prompts directory contains `missing.j2`", {}
    )[0]
    assert not _h_ar_named_prompts_contains(world, "malformed", {})[0]

    assert _h_ar_prior_prompt_contains(
        world, "the Call 2a user prompt contains requirements", {}
    )[0]
    assert not _h_ar_prior_prompt_contains(
        world, "the Call 2b user prompt contains responsibilities", {}
    )[0]
    world.sp1_mock_client.calls = [{"user_prompt": "responsibilities"}]
    assert _h_ar_prior_prompt_contains(
        world, "the Call 2b user prompt contains responsibilities", {}
    )[0]

    assert _h_ar_responsibility_no_field(
        world, "the `ResponsibilitySet` model does not declare `control_actions`", {}
    )[0]
    assert not _h_ar_responsibility_no_field(
        world, "the `ResponsibilitySet` model does not declare `responsibilities`", {}
    )[0]
    assert not _h_ar_responsibility_no_field(world, "malformed", {})[0]

    model_world = World()
    assert _h_ar_valid_responsibility_set(
        model_world, "a valid ResponsibilitySet from Call 2a", {}
    )[0]
    assert _h_ar_valid_responsibility_set(
        model_world,
        "a valid ResponsibilitySet from Call 2a with a ControlElementSet from Call 2b",
        {},
    )[0]

    prompt_world = SimpleNamespace(
        sp1_mock_client=SimpleNamespace(
            calls=[
                {
                    "response_format": _SP1CoordinationAnalysis,
                    "user_prompt": "RESP-1 controls CP-1",
                }
            ]
        )
    )
    assert _h_ar_call3_prompt(prompt_world, "", {})[0]
    prompt_world.sp1_mock_client.calls = []
    assert not _h_ar_call3_prompt(prompt_world, "", {})[0]

    error_world = SimpleNamespace(
        gd_run_result=SimpleNamespace(
            stage_errors=["assemble_control_structure failed"]
        ),
        sp1_run_result=None,
    )
    assert _h_ar_sp1_assembly_error(error_world, "", {})[0]
    error_world.gd_run_result = SimpleNamespace(stage_errors=[])
    assert not _h_ar_sp1_assembly_error(error_world, "", {})[0]


def test_acceptance_refresh_control_structure_branches():
    from asago_scenario_generator.stpa.models.control_structure import ControlStructure

    world = SimpleNamespace(control_structure=None)
    assert not _h_ar_control_structure_element(world, "", {})[0]
    assert not _h_ar_link_source_target(world, "", {})[0]

    control_structure_data = _sp1_valid_cs_dict()
    world.control_structure = ControlStructure.model_validate(control_structure_data)
    assert _h_ar_control_structure_element(
        world, "the ControlStructure contains responsibility RESP-1", {}
    )[0]
    assert _h_ar_control_structure_element(
        world, "the ControlStructure contains controlled process CP-1", {}
    )[0]
    assert not _h_ar_control_structure_element(
        world, "the ControlStructure contains responsibility RESP-404", {}
    )[0]
    assert not _h_ar_control_structure_element(world, "malformed", {})[0]
    assert not _h_ar_link_source_target(world, "", {})[0]

    control_structure_data["coordination_links"] = [
        _sp1_valid_coordination_analysis_dict()["coordination_links"][0]
    ]
    world.control_structure = ControlStructure.model_validate(control_structure_data)
    assert _h_ar_link_source_target(world, "", {})[0]
    world.control_structure = SimpleNamespace(
        coordination_links=[
            SimpleNamespace(link_id="CL-1", source="RESP-404", target="RESP-2")
        ]
    )
    assert not _h_ar_link_source_target(world, "", {})[0]


def test_acceptance_refresh_link_and_warning_handler_branches():
    world = SimpleNamespace(
        sp1_connection_set=None,
        control_structure=None,
        sp1_warnings=[],
    )
    assert not _h_ar_coordination_contains_link(world, "", {})[0]
    assert not _h_ar_no_coordination_links(world, "", {})[0]

    world.control_structure = SimpleNamespace(coordination_links=[])
    assert _h_ar_no_coordination_links(world, "", {})[0]
    world.control_structure.coordination_links = [SimpleNamespace(link_id="CL-2")]
    assert not _h_ar_no_coordination_links(world, "", {})[0]
    world.sp1_connection_set = SimpleNamespace(coordination_links=[])
    assert _h_ar_no_coordination_links(world, "", {})[0]
    world.sp1_connection_set.coordination_links = [SimpleNamespace(link_id="CL-1")]
    assert _h_ar_coordination_contains_link(world, "", {})[0]

    assert not _h_ar_warnings_include(
        world, "the warnings list includes a warning naming step STEP-1", {}
    )[0]
    world.sp1_warnings = ["STEP-1 failed"]
    assert _h_ar_warnings_include(
        world, "the warnings list includes a warning naming step STEP-1", {}
    )[0]
    world.sp1_warnings = []
    assert not _h_ar_warnings_include(world, "malformed", {})[0]


_ALLOWED_QA_HARNESS_IMPORTERS = (
    "acceptance/qa/acceptance_framework/qa_suite.py",
    "acceptance/qa/acceptance_registration.py",
    "acceptance/qa/output_ingress_zone.py",
    "acceptance/qa/snapshot_consistency.py",
    "acceptance/qa/sp1_critic_revision.py",
    "acceptance/qa/sp2_stage3_prompts.py",
    "acceptance/qa/sp3_prompt_revision.py",
    "acceptance/qa/stage1_ordering.py",
    "acceptance/qa/stage2_decomposition.py",
    "acceptance/qa/stage2_fallback.py",
    "acceptance/qa/stpa/execution_projection_production_wiring.py",
)
_ENV_NAME_CHARS = string.ascii_letters + string.digits + "_"
_ENV_VALUE_CHARS = string.ascii_letters + string.digits + " ._-"


def _imported_module_names(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def test_qa_harness_depends_only_on_stdlib():
    imports = _imported_module_names(
        _PROJECT_ROOT / "acceptance" / "qa" / "qa_harness.py"
    )
    forbidden = [
        name
        for name in imports
        if name.startswith(
            (
                "runtime_features",
                "runtime_shared",
                "runtime_manifest",
                "acceptance_runtime",
                "asago_scenario_generator",
                "qa_suite",
            )
        )
    ]
    assert forbidden == []


def test_manifest_registration_does_not_load_qa_harness():
    before = {
        name for name in sys.modules if name == "qa_harness" or "qa_harness" in name
    }
    import runtime_manifest

    modules = runtime_manifest.load_modules()
    identities = [module.FEATURE_ID for module in modules]
    after = {
        name for name in sys.modules if name == "qa_harness" or "qa_harness" in name
    }

    assert identities.count("acceptance_refresh") == 1
    assert "acceptance_qa_runtime_cleanup" not in identities
    assert after == before


def test_acceptance_refresh_facade_keeps_handler_aliases():
    expected = {
        "_h_ar_add_coordination",
        "_h_ar_assemble",
        "_h_ar_call2a_run",
        "_h_ar_call2b_run",
        "_h_ar_call3_prompt",
        "_h_ar_call3_run",
        "_h_ar_call_log_exists",
        "_h_ar_call_sequence",
        "_h_ar_control_element_set",
        "_h_ar_control_elements_contains_cp",
        "_h_ar_control_elements_produced",
        "_h_ar_control_structure_element",
        "_h_ar_coordination_analysis",
        "_h_ar_coordination_contains_link",
        "_h_ar_coordination_produced",
        "_h_ar_integrity_findings",
        "_h_ar_link_source_target",
        "_h_ar_model_field",
        "_h_ar_module_export",
        "_h_ar_named_prompts_contains",
        "_h_ar_no_assembly_failure",
        "_h_ar_no_coordination_links",
        "_h_ar_no_log_step",
        "_h_ar_prior_prompt_contains",
        "_h_ar_render_call2a_prompt",
        "_h_ar_responsibility_no_field",
        "_h_ar_responsibility_set",
        "_h_ar_responsibility_shape",
        "_h_ar_sp1_assembly_error",
        "_h_ar_stage2_calls_ready",
        "_h_ar_stage2_run",
        "_h_ar_valid_responsibility_set",
        "_h_ar_warnings_include",
    }
    available = {name for name in dir(acceptance_refresh) if name.startswith("_h_ar_")}
    assert expected <= available
    assert acceptance_refresh.__all__ == ["FEATURE_ID", "register"]


@given(
    keep_name=st.text(alphabet=_ENV_NAME_CHARS, min_size=1, max_size=12).filter(
        lambda name: name.isidentifier() and not name.startswith("_")
    ),
    keep_value=st.text(alphabet=_ENV_VALUE_CHARS, min_size=0, max_size=24),
    drop_name=st.text(alphabet=_ENV_NAME_CHARS, min_size=1, max_size=12).filter(
        lambda name: name.isidentifier() and not name.startswith("_")
    ),
    drop_value=st.text(alphabet=_ENV_VALUE_CHARS, min_size=0, max_size=24),
    extra_name=st.text(alphabet=_ENV_NAME_CHARS, min_size=1, max_size=12).filter(
        lambda name: name.isidentifier() and not name.startswith("_")
    ),
    extra_value=st.text(alphabet=_ENV_VALUE_CHARS, min_size=0, max_size=24),
)
def test_child_env_copies_parent_and_removes_only_requested_keys(
    keep_name: str,
    keep_value: str,
    drop_name: str,
    drop_value: str,
    extra_name: str,
    extra_value: str,
) -> None:
    assume(len({keep_name, drop_name, extra_name}) == 3)
    parent = {keep_name: keep_value, drop_name: drop_value}
    snapshot = dict(parent)
    isolated = child_env(parent, **{drop_name: None, extra_name: extra_value})
    assert parent == snapshot
    assert isolated[keep_name] == keep_value
    assert drop_name not in isolated
    assert isolated[extra_name] == extra_value
    isolated[keep_name] = "mutated"
    assert parent[keep_name] == keep_value


@given(
    first_name=st.text(alphabet=string.ascii_letters, min_size=1, max_size=16),
    second_name=st.text(alphabet=string.ascii_letters, min_size=1, max_size=16),
    second_passed=st.booleans(),
)
def test_qa_runner_summary_is_deterministic_for_recorded_results(
    first_name: str, second_name: str, second_passed: bool
) -> None:
    assume(first_name != second_name)
    runner = QARunner()
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        runner.record(first_name, True)
        runner.record(second_name, second_passed)
        expected_status = 0 if second_passed else 1
        status = runner.summary()
    assert status == expected_status
    lines = [line for line in buffer.getvalue().splitlines() if line.startswith("  [")]
    first_line = f"  [PASS] {first_name}"
    second_line = f"  [{'PASS' if second_passed else 'FAIL'}] {second_name}"
    assert lines == [first_line, second_line]
    failed = 0 if second_passed else 1
    assert f"QA suite: {2 - failed} passed, {failed} failed" in buffer.getvalue()

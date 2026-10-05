from __future__ import annotations

import sys
from types import SimpleNamespace
from pathlib import Path

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance"))

from runtime_features import acceptance_refresh  # noqa: E402
from runtime_shared import (  # noqa: E402
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
from asago_scenario_generator.stpa.system_model.control_structure import (  # noqa: E402
    _CoordinationProviderEnvelope,
)
import runtime_manifest  # noqa: E402
from asago_scenario_generator.stpa.models.control_structure import (  # noqa: E402
    ControlStructure,
)


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
    assert len(api.entries) == 39
    feature_entries = [entry for entry in api.entries if entry[3] is not None]
    global_entries = [entry for entry in api.entries if entry[3] is None]
    assert len(feature_entries) == 13
    assert len(global_entries) == 26
    assert [entry[2] for entry in feature_entries] == list(range(21826, 21839))
    assert [entry[2] for entry in global_entries] == [
        21942,
        21916,
        *range(21918, 21942),
    ]
    assert all(entry[3] == "acceptance_refresh" for entry in feature_entries)
    assert api.feature is None

    expected_patterns = [
        "the Call 2b wire schema forbids external effects on responsibility targets$",
        "the `CoordinationAnalysis` model (?:does not )?declare",
        "(?:an LLM that returns a )?(?:valid )?CoordinationAnalysis|a control structure with an unreferenced controlled process",
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
        "the SP1RunResult stage_warnings contains the assemble_control_structure repair",
        "the control_structure module (?:does not )?exports?",
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
        "a ControlElementSet from Call 2b whose feedback channel FB-1-1 updates",
    ]
    assert [entry[0] for entry in api.entries] == expected_patterns


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

    assert not _h_ar_named_prompts_contains(
        world, "the SP2 prompts directory contains `stage3_system.j2`", {}
    )[0]
    assert _h_ar_named_prompts_contains(
        world, "the SP3 prompts directory contains `stage5_context_system.j2`", {}
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
                    "response_format": _CoordinationProviderEnvelope,
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
            stage_warnings=["assemble_control_structure repaired"]
        ),
        sp1_run_result=None,
    )
    assert _h_ar_sp1_assembly_error(error_world, "", {})[0]
    error_world.gd_run_result = SimpleNamespace(stage_warnings=[])
    assert not _h_ar_sp1_assembly_error(error_world, "", {})[0]


def test_acceptance_refresh_control_structure_branches():
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


def test_manifest_registers_acceptance_refresh_once():
    identities = [module.FEATURE_ID for module in runtime_manifest.load_modules()]

    assert identities.count("acceptance_refresh") == 1


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

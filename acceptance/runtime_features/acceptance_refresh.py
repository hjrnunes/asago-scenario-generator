"""Compatibility and registration facade for acceptance-refresh handlers."""

from __future__ import annotations

from .acceptance_refresh_coordination import (
    _h_ar_add_coordination,
    _h_ar_call3_run,
    _h_ar_control_structure_element,
    _h_ar_coordination_analysis,
    _h_ar_coordination_contains_link,
    _h_ar_coordination_produced,
    _h_ar_integrity_findings,
    _h_ar_link_source_target,
    _h_ar_model_field,
    _h_ar_no_assembly_failure,
    _h_ar_no_coordination_links,
    _h_ar_sp1_assembly_error,
    _h_ar_warnings_include,
)
from .acceptance_refresh_stage2 import (
    _h_ar_assemble,
    _h_ar_call2a_run,
    _h_ar_call2b_run,
    _h_ar_call3_prompt,
    _h_ar_call_log_exists,
    _h_ar_call_sequence,
    _h_ar_control_element_set,
    _h_ar_control_elements_contains_cp,
    _h_ar_control_elements_produced,
    _h_ar_module_export,
    _h_ar_named_prompts_contains,
    _h_ar_no_log_step,
    _h_ar_object_shaped_feedback_update,
    _h_ar_prior_prompt_contains,
    _h_ar_render_call2a_prompt,
    _h_ar_responsibility_no_field,
    _h_ar_responsibility_set,
    _h_ar_responsibility_shape,
    _h_ar_stage2_calls_ready,
    _h_ar_stage2_run,
    _h_ar_valid_responsibility_set,
    _h_ar_wire_target_effects,
)
from registry import StepTable

step = StepTable()

FEATURE_ID = "acceptance_refresh"


step.add(
    "the Call 2b wire schema forbids external effects on responsibility targets$",
    _h_ar_wire_target_effects,
    first=True,
)
for _pattern, _handler in (
    ("the `CoordinationAnalysis` model (?:does not )?declare", _h_ar_model_field),
    (
        "(?:an LLM that returns a )?(?:valid )?CoordinationAnalysis|"
        "a control structure with an unreferenced controlled process",
        _h_ar_coordination_analysis,
    ),
    ("Stage 2 Call 3 coordination derivation is run", _h_ar_call3_run),
    (
        "the Stage 2 coordination link addition with fallback is executed",
        _h_ar_add_coordination,
    ),
    ("a CoordinationAnalysis model is produced", _h_ar_coordination_produced),
    (
        "the CoordinationAnalysis contains coordination link CL-1",
        _h_ar_coordination_contains_link,
    ),
    (
        "the CoordinationAnalysis integrity_findings list is not empty",
        _h_ar_integrity_findings,
    ),
    (
        "the CoordinationAnalysis contains no coordination links",
        _h_ar_no_coordination_links,
    ),
    (
        "the ControlStructure contains (?:responsibility|controlled process)",
        _h_ar_control_structure_element,
    ),
    ("CL-1 has source RESP-1 and target RESP-2", _h_ar_link_source_target),
    ("the warnings list includes a warning naming step", _h_ar_warnings_include),
    ("no assembly failure is logged", _h_ar_no_assembly_failure),
    (
        "the SP1RunResult stage_warnings contains the assemble_control_structure repair",
        _h_ar_sp1_assembly_error,
    ),
):
    step.add(_pattern, _handler, first=True, feature=FEATURE_ID)
for _pattern, _handler in (
    ("the control_structure module (?:does not )?exports?", _h_ar_module_export),
    ("the SP3 prompts directory contains", _h_ar_named_prompts_contains),
    (
        "the Call 2a user prompt is rendered with the capability profile",
        _h_ar_render_call2a_prompt,
    ),
    (
        "(?:an LLM that returns a )?ControlElementSet from Call 2b with",
        _h_ar_control_element_set,
    ),
    ("a valid ResponsibilitySet from Call 2a", _h_ar_valid_responsibility_set),
    (
        "a ResponsibilitySet from Call 2a with responsibilities",
        _h_ar_responsibility_set,
    ),
    (
        "an LLM that returns valid responses for (?:Stage 2 calls 1, 2a, and 2b|all four Stage 2 calls|Stage 2 calls 1 and 2a)",
        _h_ar_stage2_calls_ready,
    ),
    ("the Stage 2 assembly with fallback is executed", _h_ar_assemble),
    ("Stage 2 control structure derivation is run", _h_ar_stage2_run),
    ("Stage 2 calls 1 through 3 are run in sequence", _h_ar_call_sequence),
    ("Stage 2 Call 2a responsibilities derivation is run", _h_ar_call2a_run),
    ("Stage 2 Call 2b control elements derivation is run", _h_ar_call2b_run),
    ("Stage 2 calls 1 through 2[ab] are run in sequence", _h_ar_stage2_run),
    ("an LLM that returns a valid ControlElementSet JSON", _h_ar_control_element_set),
    ("an LLM that returns a valid CoordinationAnalysis", _h_ar_coordination_analysis),
    ("a CoordinationAnalysis with", _h_ar_coordination_analysis),
    ("a call log entry exists with step", _h_ar_call_log_exists),
    ("no call log entry has step", _h_ar_no_log_step),
    (
        "each responsibility has at least one responsibility constraint and one process model part",
        _h_ar_responsibility_shape,
    ),
    ("the `ResponsibilitySet` model does not declare", _h_ar_responsibility_no_field),
    ("a ControlElementSet model is produced", _h_ar_control_elements_produced),
    (
        "the ControlElementSet contains controlled process CP-1",
        _h_ar_control_elements_contains_cp,
    ),
    ("the Call 2[ab] user prompt contains", _h_ar_prior_prompt_contains),
    (
        "the Call 3 user prompt contains the assembled responsibilities and controlled processes",
        _h_ar_call3_prompt,
    ),
    (
        "a ControlElementSet from Call 2b whose feedback channel FB-1-1 updates",
        _h_ar_object_shaped_feedback_update,
    ),
):
    step.add(_pattern, _handler, first=True)

register = step.register


__all__ = ["FEATURE_ID", "register"]

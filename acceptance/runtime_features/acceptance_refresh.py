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
)

FEATURE_ID = "acceptance_refresh"


def register(api: object) -> None:
    """Register the characterized feature-scoped and global handlers."""
    api.set_feature(None)
    api.set_feature(FEATURE_ID)
    api.register_first(
        "the `CoordinationAnalysis` model (?:does not )?declare",
        _h_ar_model_field,
        source_order=21826,
    )
    api.register_first(
        "(?:an LLM that returns a )?(?:valid )?CoordinationAnalysis",
        _h_ar_coordination_analysis,
        source_order=21827,
    )
    api.register_first(
        "Stage 2 Call 3 coordination derivation is run",
        _h_ar_call3_run,
        source_order=21828,
    )
    api.register_first(
        "the Stage 2 coordination link addition with fallback is executed",
        _h_ar_add_coordination,
        source_order=21829,
    )
    api.register_first(
        "a CoordinationAnalysis model is produced",
        _h_ar_coordination_produced,
        source_order=21830,
    )
    api.register_first(
        "the CoordinationAnalysis contains coordination link CL-1",
        _h_ar_coordination_contains_link,
        source_order=21831,
    )
    api.register_first(
        "the CoordinationAnalysis integrity_findings list is not empty",
        _h_ar_integrity_findings,
        source_order=21832,
    )
    api.register_first(
        "the CoordinationAnalysis contains no coordination links",
        _h_ar_no_coordination_links,
        source_order=21833,
    )
    api.register_first(
        "the ControlStructure contains (?:responsibility|controlled process)",
        _h_ar_control_structure_element,
        source_order=21834,
    )
    api.register_first(
        "CL-1 has source RESP-1 and target RESP-2",
        _h_ar_link_source_target,
        source_order=21835,
    )
    api.register_first(
        "the warnings list includes a warning naming step",
        _h_ar_warnings_include,
        source_order=21836,
    )
    api.register_first(
        "no assembly failure is logged", _h_ar_no_assembly_failure, source_order=21837
    )
    api.register_first(
        "the SP1RunResult stage_warnings contains the assemble_control_structure repair",
        _h_ar_sp1_assembly_error,
        source_order=21838,
    )
    api.set_feature(None)
    api.register_first(
        "the control_structure module (?:does not )?exports?",
        _h_ar_module_export,
        source_order=21916,
    )
    api.register_first(
        "the SP2 prompts directory contains",
        _h_ar_named_prompts_contains,
        source_order=21917,
    )
    api.register_first(
        "the SP3 prompts directory contains",
        _h_ar_named_prompts_contains,
        source_order=21918,
    )
    api.register_first(
        "the Call 2a user prompt is rendered with the capability profile",
        _h_ar_render_call2a_prompt,
        source_order=21919,
    )
    api.register_first(
        "(?:an LLM that returns a )?ControlElementSet from Call 2b with",
        _h_ar_control_element_set,
        source_order=21920,
    )
    api.register_first(
        "a valid ResponsibilitySet from Call 2a",
        _h_ar_valid_responsibility_set,
        source_order=21921,
    )
    api.register_first(
        "a ResponsibilitySet from Call 2a with responsibilities",
        _h_ar_responsibility_set,
        source_order=21922,
    )
    api.register_first(
        "an LLM that returns valid responses for (?:Stage 2 calls 1, 2a, and 2b|all four Stage 2 calls|Stage 2 calls 1 and 2a)",
        _h_ar_stage2_calls_ready,
        source_order=21923,
    )
    api.register_first(
        "the Stage 2 assembly with fallback is executed",
        _h_ar_assemble,
        source_order=21924,
    )
    api.register_first(
        "Stage 2 control structure derivation is run",
        _h_ar_stage2_run,
        source_order=21925,
    )
    api.register_first(
        "Stage 2 calls 1 through 3 are run in sequence",
        _h_ar_call_sequence,
        source_order=21926,
    )
    api.register_first(
        "Stage 2 Call 2a responsibilities derivation is run",
        _h_ar_call2a_run,
        source_order=21927,
    )
    api.register_first(
        "Stage 2 Call 2b control elements derivation is run",
        _h_ar_call2b_run,
        source_order=21928,
    )
    api.register_first(
        "Stage 2 calls 1 through 2[ab] are run in sequence",
        _h_ar_stage2_run,
        source_order=21929,
    )
    api.register_first(
        "an LLM that returns a valid ControlElementSet JSON",
        _h_ar_control_element_set,
        source_order=21930,
    )
    api.register_first(
        "an LLM that returns a valid CoordinationAnalysis",
        _h_ar_coordination_analysis,
        source_order=21931,
    )
    api.register_first(
        "a CoordinationAnalysis with", _h_ar_coordination_analysis, source_order=21932
    )
    api.register_first(
        "a call log entry exists with step", _h_ar_call_log_exists, source_order=21933
    )
    api.register_first(
        "no call log entry has step", _h_ar_no_log_step, source_order=21934
    )
    api.register_first(
        "each responsibility has at least one responsibility constraint and one process model part",
        _h_ar_responsibility_shape,
        source_order=21935,
    )
    api.register_first(
        "the `ResponsibilitySet` model does not declare",
        _h_ar_responsibility_no_field,
        source_order=21936,
    )
    api.register_first(
        "a ControlElementSet model is produced",
        _h_ar_control_elements_produced,
        source_order=21937,
    )
    api.register_first(
        "the ControlElementSet contains controlled process CP-1",
        _h_ar_control_elements_contains_cp,
        source_order=21938,
    )
    api.register_first(
        "the Call 2[ab] user prompt contains",
        _h_ar_prior_prompt_contains,
        source_order=21939,
    )
    api.register_first(
        "the Call 3 user prompt contains the assembled responsibilities and controlled processes",
        _h_ar_call3_prompt,
        source_order=21940,
    )
    api.register_first(
        "a ControlElementSet from Call 2b whose feedback channel FB-1-1 updates",
        _h_ar_object_shaped_feedback_update,
        source_order=21941,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]

"""Feature-scoped handlers for the acceptance-refresh coordination scenarios."""

from __future__ import annotations

import re

from runtime_shared import (
    ControlStructure,
    TemplateLoader,
    World,
    _PQF_PROMPTS_DIR,
    _SP1CoordinationAnalysis,
    _ar_client,
    _ar_run_dir,
    _ar_stage2_defaults,
    _sp1_add_coordination_links,
    _sp1_valid_coordination_analysis_dict,
    _sp1_valid_cs_dict,
)


def _h_ar_model_field(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"`CoordinationAnalysis` model (does not )?declare `([^`]+)`", text
    )
    if not match:
        return False, f"Could not parse model field from: {text}"
    absent, field = match.groups()
    declared = field in _SP1CoordinationAnalysis.model_fields
    if bool(absent) == declared:
        expectation = "not be declared" if absent else "be declared"
        return False, f"Expected {field} to {expectation}"
    return True, ""


def _h_ar_coordination_analysis(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    response = _sp1_valid_coordination_analysis_dict()
    if "integrity finding" in text:
        response = {
            "coordination_links": [],
            "integrity_findings": ["Controlled process CP-404 is unreferenced"],
        }
    elif "non-existent responsibility" in text:
        response["coordination_links"][0]["source"] = "RESP-404"
    world.sp1_connection_set = _SP1CoordinationAnalysis.model_validate(response)
    _ar_client(world).set_response_for(_SP1CoordinationAnalysis, response)
    return True, ""


def _h_ar_call3_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from asago_scenario_generator.stpa.system_model.control_structure import (
        _call_3_coordination,
    )

    _ar_stage2_defaults(world)
    run_dir = _ar_run_dir(world)
    control_structure = ControlStructure.model_validate(_sp1_valid_cs_dict())
    world.sp1_connection_set = _call_3_coordination(
        llm_client=_ar_client(world),
        use_case_text=world.sp1_use_case_text,
        control_structure=control_structure,
        run_dir=run_dir,
        loader=TemplateLoader(_PQF_PROMPTS_DIR),
        temperature=0.4,
    )
    return True, ""


def _h_ar_add_coordination(world: World, text: str, examples: dict) -> tuple[bool, str]:
    control_structure = world.control_structure or ControlStructure.model_validate(
        _sp1_valid_cs_dict()
    )
    analysis = world.sp1_connection_set or _SP1CoordinationAnalysis.model_validate(
        _sp1_valid_coordination_analysis_dict()
    )
    world.control_structure, world.sp1_warnings = _sp1_add_coordination_links(
        control_structure, analysis, _ar_run_dir(world), "test-model"
    )
    return True, ""


def _h_ar_coordination_produced(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not isinstance(world.sp1_connection_set, _SP1CoordinationAnalysis):
        return False, "No CoordinationAnalysis model was produced"
    return True, ""


def _h_ar_coordination_contains_link(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    analysis = world.sp1_connection_set
    if analysis is None or not any(
        link.link_id == "CL-1" for link in analysis.coordination_links
    ):
        return False, "CoordinationAnalysis does not contain CL-1"
    return True, ""


def _h_ar_integrity_findings(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    analysis = world.sp1_connection_set
    if analysis is None or not analysis.integrity_findings:
        return False, "CoordinationAnalysis integrity_findings is empty"
    return True, ""


def _h_ar_no_coordination_links(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    analysis = world.sp1_connection_set
    if analysis is None:
        analysis = world.control_structure
    if analysis is None or analysis.coordination_links:
        return False, "Expected no coordination links"
    return True, ""


def _control_structure_ids(control_structure: ControlStructure, kind: str) -> list[str]:
    if kind == "responsibility":
        return [item.resp_id for item in control_structure.responsibilities]
    return [item.cp_id for item in control_structure.controlled_processes]


def _h_ar_control_structure_element(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No ControlStructure available"
    match = re.search(
        r"contains (responsibility|controlled process) (RESP-\d+|CP-\d+)", text
    )
    if not match:
        return False, f"Could not parse control structure element: {text}"
    kind, element_id = match.groups()
    values = _control_structure_ids(world.control_structure, kind)
    if element_id not in values:
        return False, f"{kind} {element_id} not found in {values}"
    return True, ""


def _coordination_link(control_structure: ControlStructure):
    return next(
        (
            item
            for item in control_structure.coordination_links
            if item.link_id == "CL-1"
        ),
        None,
    )


def _has_expected_link(link: object) -> bool:
    return link is not None and link.source == "RESP-1" and link.target == "RESP-2"


def _h_ar_link_source_target(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No ControlStructure available"
    if not _has_expected_link(_coordination_link(world.control_structure)):
        return False, "CL-1 does not connect RESP-1 to RESP-2"
    return True, ""


def _h_ar_warnings_include(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"naming step (\S+)", text)
    step = match.group(1) if match else ""
    if not any(step in warning for warning in world.sp1_warnings):
        return False, f"No warning names {step}: {world.sp1_warnings}"
    return True, ""


def _h_ar_no_assembly_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_warnings:
        return False, f"Unexpected assembly warnings: {world.sp1_warnings}"
    return True, ""


def _h_ar_sp1_assembly_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    result = world.gd_run_result or world.sp1_run_result
    warnings = getattr(result, "stage_warnings", []) if result is not None else []
    if not any("assemble_control_structure" in warning for warning in warnings):
        return False, f"No assemble_control_structure warning in {warnings}"
    return True, ""


__all__ = [
    "_h_ar_add_coordination",
    "_h_ar_call3_run",
    "_h_ar_control_structure_element",
    "_h_ar_coordination_analysis",
    "_h_ar_coordination_contains_link",
    "_h_ar_coordination_produced",
    "_h_ar_integrity_findings",
    "_h_ar_link_source_target",
    "_h_ar_model_field",
    "_h_ar_no_assembly_failure",
    "_h_ar_no_coordination_links",
    "_h_ar_sp1_assembly_error",
    "_h_ar_warnings_include",
]

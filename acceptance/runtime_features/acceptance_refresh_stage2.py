"""Global handlers for the acceptance-refresh Stage 2 scenarios."""

from __future__ import annotations

import json
import re

from runtime_shared import (
    ElementRef,
    LossAnalysis,
    ReferenceType,
    TemplateLoader,
    World,
    _PQF_PROMPTS_DIR,
    _SP1ControlElementSet,
    _SP1CoordinationAnalysis,
    _SP1RequirementSet,
    _SP1ResponsibilitySet,
    _ar_client,
    _ar_run_dir,
    _ar_stage2_defaults,
    _sp1_assemble_with_fallback,
    _sp1_derive_control_structure,
    _sp1_valid_control_element_set_dict,
    _sp1_valid_la_dict,
    _sp1_valid_req_set_dict,
    _sp1_valid_resp_set_2a_dict,
)

_KNOWN_RETIRED_STEPS = frozenset(
    {
        "call_2_responsibilities",
        "call_3_connections",
        "merge_connection_set",
    }
)


def _h_ar_module_export(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from asago_scenario_generator.stpa.system_model import control_structure

    match = re.search(r"module (does not )?exports? `([^`]+)`", text)
    if not match:
        return False, f"Could not parse symbol from: {text}"
    absent, symbol = match.groups()
    exported = hasattr(control_structure, symbol)
    if bool(absent) == exported:
        expectation = "not be exported" if absent else "be exported"
        return False, f"Expected {symbol} to {expectation}"
    return True, ""


def _h_ar_responsibility_set(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    ids = re.findall(r"RESP-\d+", text)
    response = _sp1_valid_resp_set_2a_dict()
    response["responsibilities"] = [
        responsibility
        for responsibility in response["responsibilities"]
        if responsibility["resp_id"] in ids
    ]
    world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(response)
    _ar_client(world).set_response_for(_SP1ResponsibilitySet, response)
    return True, ""


def _h_ar_valid_responsibility_set(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(
        _sp1_valid_resp_set_2a_dict()
    )
    # Handle combined step: "a valid ResponsibilitySet from Call 2a with
    # responsibility RESP-1 and a ControlElementSet from Call 2b with
    # controlled process CP-1"
    if "ControlElementSet from Call 2b" in text:
        if world.sp1_control_element_set is None:
            world.sp1_control_element_set = _SP1ControlElementSet.model_validate(
                _sp1_valid_control_element_set_dict()
            )
        _ar_client(world).set_response_for(
            _SP1ControlElementSet, world.sp1_control_element_set.model_dump()
        )
    return True, ""


def _preserve_control_element_set(
    existing: _SP1ControlElementSet,
    text: str,
) -> _SP1ControlElementSet:
    if "unresolvable feedback source reference" in text:
        for feedback in existing.feedback_channels:
            if feedback.fb_id == "FB-2-1":
                feedback.source = ElementRef(
                    type=ReferenceType.controlled_process, id="CP-404"
                )
    return existing


def _h_ar_control_element_set(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_control_element_set is not None:
        # Preserve modifications from a prior sanitize step (e.g. a CA or
        # FB with an invalid ElementRef) and apply the unresolvable
        # feedback source on top of the existing set.  Target FB-2-1
        # (not FB-1-1) so that step-2 modifications to FB-1-1 are
        # preserved.
        existing = _preserve_control_element_set(
            world.sp1_control_element_set,
            text,
        )
        _ar_client(world).set_response_for(_SP1ControlElementSet, existing.model_dump())
        return True, ""
    response = _sp1_valid_control_element_set_dict()
    if "unresolvable feedback source reference" in text:
        response["feedback_channels"][1]["source"] = {
            "type": "controlled_process",
            "id": "CP-404",
        }
    world.sp1_control_element_set = _SP1ControlElementSet.model_validate(response)
    _ar_client(world).set_response_for(_SP1ControlElementSet, response)
    return True, ""


def _h_ar_object_shaped_feedback_update(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Configure the object-shaped invalid update observed in a live run."""
    from asago_scenario_generator.stpa.infra.unvalidated_decode import (
        construct_model_unvalidated,
    )

    response = _sp1_valid_control_element_set_dict()
    response["feedback_channels"][0]["updates"] = {
        "type": "responsibility",
        "id": "RESP-1",
    }
    world.sp1_control_element_set = construct_model_unvalidated(
        response,
        _SP1ControlElementSet,
    )
    return True, ""


def _h_ar_stage2_calls_ready(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _ar_stage2_defaults(world)
    return True, ""


def _h_ar_assemble(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _ar_stage2_defaults(world)
    responsibility_set = (
        world.sp1_responsibility_set
        or _SP1ResponsibilitySet.model_validate(_sp1_valid_resp_set_2a_dict())
    )
    control_elements = (
        world.sp1_control_element_set
        or _SP1ControlElementSet.model_validate(_sp1_valid_control_element_set_dict())
    )
    world.control_structure, world.sp1_warnings = _sp1_assemble_with_fallback(
        responsibility_set, control_elements, _ar_run_dir(world), "test-model"
    )
    world.san_merge_warnings = list(world.sp1_warnings)
    return True, ""


def _h_ar_stage2_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _ar_stage2_defaults(world)
    template_loader = TemplateLoader(_PQF_PROMPTS_DIR)
    world.template_loader = template_loader
    world.control_structure, world.sp1_warnings = _sp1_derive_control_structure(
        llm_client=_ar_client(world),
        use_case_text=world.sp1_use_case_text,
        loss_analysis=LossAnalysis.model_validate(_sp1_valid_la_dict()),
        run_dir=_ar_run_dir(world),
        template_loader=template_loader,
        temperature=0.4,
    )
    return True, ""


def _h_ar_call2a_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from asago_scenario_generator.stpa.system_model.control_structure import (
        _call_2a_responsibilities,
    )

    _ar_stage2_defaults(world)
    world.sp1_responsibility_set = _call_2a_responsibilities(
        llm_client=_ar_client(world),
        use_case_text=world.sp1_use_case_text,
        requirement_set=_SP1RequirementSet.model_validate(_sp1_valid_req_set_dict()),
        capability_profile=None,
        run_dir=_ar_run_dir(world),
        loader=TemplateLoader(_PQF_PROMPTS_DIR),
        temperature=0.4,
    )
    return True, ""


def _h_ar_call2b_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from asago_scenario_generator.stpa.system_model.control_structure import (
        _call_2b_control_elements,
    )

    _ar_stage2_defaults(world)
    world.sp1_control_element_set = _call_2b_control_elements(
        llm_client=_ar_client(world),
        use_case_text=world.sp1_use_case_text,
        responsibility_set=world.sp1_responsibility_set
        or _SP1ResponsibilitySet.model_validate(_sp1_valid_resp_set_2a_dict()),
        run_dir=_ar_run_dir(world),
        loader=TemplateLoader(_PQF_PROMPTS_DIR),
        temperature=0.4,
    )
    return True, ""


def _h_ar_call_sequence(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _h_ar_stage2_run(world, text, examples)


def _h_ar_call_log_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    step = _step_name(text)
    entries = _call_log_entries(world)
    if not any(entry.get("step") == step for entry in entries):
        return False, f"No {step} entry in call log"
    return True, ""


def _step_name(text: str) -> str:
    match = re.search(r"step (\S+)", text)
    return match.group(1) if match else ""


def _call_log_entries(world: World) -> list[dict]:
    path = _ar_run_dir(world) / "calls.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def _h_ar_no_log_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    step = _step_name(text)
    if not step:
        return False, "Could not parse step name from step text"
    if step not in _KNOWN_RETIRED_STEPS:
        return False, f"'{step}' is not a recognized retired step name"
    entries = _call_log_entries(world)
    if any(entry.get("step") == step for entry in entries):
        return False, f"Unexpected {step} entry in call log"
    return True, ""


def _h_ar_named_prompts_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"the (SP2|SP3) prompts directory contains `([^`]+)`", text)
    if not match:
        return False, f"Could not parse prompt directory step: {text}"
    stage, template = match.groups()
    if stage == "SP2":
        from asago_scenario_generator.stpa.threat_enum._constants import PROMPTS_DIR
    else:
        from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
    if not (PROMPTS_DIR / template).exists():
        return False, f"Missing {stage} template: {template}"
    return True, ""


def _h_ar_render_call2a_prompt(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    loader = TemplateLoader(_PQF_PROMPTS_DIR)
    profile = world.sp1_profile
    world.template_rendered = loader.render_prompt(
        "stage2_call2a_user.j2",
        use_case_text=world.sp1_use_case_text,
        requirements=_SP1RequirementSet.model_validate(
            _sp1_valid_req_set_dict()
        ).requirements,
        capability_profile=profile,
    )
    return True, ""


def _h_ar_responsibility_shape(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_responsibility_set is None:
        return False, "No ResponsibilitySet available"
    for responsibility in world.sp1_responsibility_set.responsibilities:
        if (
            not responsibility.responsibility_constraints
            or not responsibility.process_model_parts
        ):
            return False, f"Incomplete responsibility: {responsibility.resp_id}"
    return True, ""


def _h_ar_responsibility_no_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    known_control_element_fields = frozenset(
        {
            "control_actions",
            "feedback_channels",
            "controlled_processes",
        }
    )
    field = re.search(r"does not declare `([^`]+)`", text)
    if not field:
        return False, "Could not parse field name from step text"
    field_name = field.group(1)
    if field_name in _SP1ResponsibilitySet.model_fields:
        return False, f"ResponsibilitySet declares {field_name}"
    if field_name not in known_control_element_fields:
        return False, f"'{field_name}' is not a recognized control element field"
    return True, ""


def _h_ar_control_elements_produced(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        (True, "")
        if world.sp1_control_element_set is not None
        else (False, "No ControlElementSet available")
    )


def _h_ar_control_elements_contains_cp(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    elements = world.sp1_control_element_set
    if elements is None or not any(
        process.cp_id == "CP-1" for process in elements.controlled_processes
    ):
        return False, "ControlElementSet does not contain CP-1"
    return True, ""


def _h_ar_call3_prompt(world: World, text: str, examples: dict) -> tuple[bool, str]:
    calls = _ar_client(world).calls
    prompt = next(
        (
            call["user_prompt"]
            for call in reversed(calls)
            if call["response_format"] is _SP1CoordinationAnalysis
        ),
        "",
    )
    if "RESP-1" not in prompt or "CP-1" not in prompt:
        return (
            False,
            "Call 3 prompt lacks assembled responsibilities or controlled processes",
        )
    return True, ""


def _h_ar_prior_prompt_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    expected = "requirements" if "2a" in text else "responsibilities"
    if not any(
        expected in call["user_prompt"].lower() for call in _ar_client(world).calls
    ):
        return False, f"No prompt contains {expected}"
    return True, ""


__all__ = [
    "_h_ar_call2a_run",
    "_h_ar_call2b_run",
    "_h_ar_call3_prompt",
    "_h_ar_call_log_exists",
    "_h_ar_call_sequence",
    "_h_ar_control_element_set",
    "_h_ar_control_elements_contains_cp",
    "_h_ar_control_elements_produced",
    "_h_ar_module_export",
    "_h_ar_named_prompts_contains",
    "_h_ar_no_log_step",
    "_h_ar_prior_prompt_contains",
    "_h_ar_render_call2a_prompt",
    "_h_ar_responsibility_no_field",
    "_h_ar_responsibility_set",
    "_h_ar_responsibility_shape",
    "_h_ar_stage2_calls_ready",
    "_h_ar_stage2_run",
    "_h_ar_assemble",
    "_h_ar_valid_responsibility_set",
]

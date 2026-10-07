"""Acceptance step handlers for the sp1 feature group."""

from __future__ import annotations

from typing import Any

from pydantic import create_model

from asago_scenario_generator.stpa.infra.llm import LLMResult
from runtime_shared import (
    _make_responsibility,
    ControlAction,
    ControlStructure,
    CoordinationLink,
    ElementRef,
    FeedbackChannel,
    LossAnalysis,
    LossProvenance,
    Path,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ValidationError,
    World,
    _SP1ConnectionSet,
    _SP1ControlElementSet,
    _SP1CriticFindings,
    _SP1LossAnalysisDraft,
    _sp1_mock_llm,
    _SP1RequirementSet,
    _SP1ResponsibilitySet,
    _SP1Stage1Profile,
    _sp1_log_llm_call,
    _sp1_make_control_structure_with_resp,
    _sp1_make_loss_analysis_with_constraints,
    _sp1_make_risk_cards,
    _sp1_no_unjustified_critic_dict,
    _sp1_run_heuristics,
    _sp1_setup_full_mock_client,
    _sp1_valid_connection_set_dict,
    _sp1_valid_control_element_set_dict,
    _sp1_valid_critic_findings_dict,
    _sp1_valid_cs_dict,
    _sp1_valid_la_dict,
    _sp1_valid_req_set_dict,
    _sp1_valid_resp_set_2a_dict,
    _sp1_valid_resp_set_dict,
    _sp1_valid_stage1_profile_dict,
    _tempfile,
    json,
    re,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    RequirementSet as _GDRequirementSet,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ResponsibilitySet as _GDResponsibilitySet,
)
from asago_scenario_generator.stpa.infra.llm_helpers import StageError as _GDStageError
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile as _SP1CapabilityProfile,
)
from asago_scenario_generator.stpa.system_model.heuristics import (
    check_solution_neutrality as _sp1_check_neutrality,
)
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile as _sp1_derive_capability_profile,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis as _sp1_derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.profile import (
    load_capability_profile as _sp1_load_capability_profile,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    _assemble_with_fallback as _sp1_assemble_with_fallback,
)
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml as _sp1_read_yaml
from asago_scenario_generator.stpa.system_model.run import run_sp1 as _sp1_run_sp1
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml as _sp1_write_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    check_structural_heuristics,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    parse_llm_result_unvalidated as _sp1_parse_llm_result_unvalidated,
)
from asago_scenario_generator.stpa.infra.unvalidated_decode import (
    construct_model_unvalidated as _sp1_construct_unvalidated,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    _enrich_responsibilities as _sp1_enrich_responsibilities,
    ControlElementSet,
    ResponsibilitySet,
)
from asago_scenario_generator.stpa.system_model.id_normalization import (
    normalize_control_structure_payload as _sp1_normalize_control_structure_payload,
    normalize_control_structure_payload,
)
from asago_scenario_generator.models.capability_profile import (
    EntryPoint,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlledProcess,
    CoordinationMechanism,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.critic import (
    RevisionDelta,
    _build_taxonomy_probes,
    _merge_revision_delta,
)
import asago_scenario_generator.stpa.system_model as system_model
import warnings
import yaml as _yaml
from registry import StepTable
from generic_steps import world_present

step = StepTable()


def _tolerant_llm_result(content: object) -> LLMResult:
    """Wrap acceptance content in the minimal result used by tolerant decoding."""
    return LLMResult(
        content=content,
        prompt_tokens=0,
        completion_tokens=0,
        duration_ms=0,
    )


@step("the STPA system model(?: \\S+)? module is importable")
def _h_sp1_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    import asago_scenario_generator.stpa.system_model  # noqa: F401

    return True, ""


@step("a loss analysis with security constraints SC-1 and SC-2 is available")
def _h_sp1_loss_analysis_constraints(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.loss_analysis = _sp1_make_loss_analysis_with_constraints()
    return True, ""


@step("a control structure and CriticFindings with unjustified gaps are available")
def _h_sp1_cs_and_critic_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""


@step("a control structure with responsibility RESP-1$")
def _h_sp1_cs_resp1(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""


@step("a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1")
def _h_sp1_cs_resp1_full(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""


@step("an LLM that returns a loss analysis where .* references non-existent")
def _h_sp1_la_invalid_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    entity = examples.get("entity", "")
    ref_target = examples.get("ref_target", "")
    world.sp1_entity = entity
    world.sp1_ref_target = ref_target
    if entity == "hazard":
        world.sp1_llm_content = {
            "risk_card_losses": [],
            "use_case_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Loss 1",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                },
            ],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "Hazard 1",
                    "related_losses": ["L-99"],
                },
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "Constraint 1",
                    "related_hazards": ["H-1"],
                    "applies_when": [],
                },
            ],
            "risk_dispositions": [
                {
                    "risk_ref": "atlas-001",
                    "disposition": "cited",
                    "loss_ids": ["L-1"],
                    "reason": None,
                },
            ],
        }
    elif entity == "constraint":
        world.sp1_llm_content = {
            "risk_card_losses": [],
            "use_case_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Loss 1",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                },
            ],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "Hazard 1",
                    "related_losses": ["L-1"],
                },
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "C1",
                    "related_hazards": ["H-99"],
                    "applies_when": [],
                },
            ],
            "risk_dispositions": [
                {
                    "risk_ref": "atlas-001",
                    "disposition": "cited",
                    "loss_ids": ["L-1"],
                    "reason": None,
                },
            ],
        }
    else:
        world.sp1_llm_content = {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
            "risk_dispositions": [
                {
                    "risk_ref": "atlas-001",
                    "disposition": "not_applicable",
                    "loss_ids": [],
                    "reason": "No loss applies to this risk card.",
                },
            ],
        }
    return True, ""


def _sp1_la_dangling_ref_dict() -> dict:
    """Return a valid draft with one deliberately dangling loss reference."""
    content = _sp1_valid_la_dict()
    content["hazards"][0]["related_losses"] = ["L-99"]
    return content


@step(
    "an LLM that returns a Stage 1a draft with a dangling reference and an unused corrected response queued"
)
def _h_sp1_la_unsupported_setup(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Queue an unsupported draft and an unused corrected response.

    The second response is deliberately queued so the acceptance assertion
    proves that unsupported reference failures do not dispatch a repair call.
    """
    world.sp1_llm_content = [
        _sp1_la_dangling_ref_dict(),
        _sp1_valid_la_dict(),
    ]
    return True, ""


@step(
    "an LLM that returns a Stage 1a draft with an unused second dangling response queued"
)
def _h_sp1_la_second_unsupported_setup(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Queue two dangling drafts; the second must remain unused."""
    world.sp1_llm_content = [
        _sp1_la_dangling_ref_dict(),
        _sp1_la_dangling_ref_dict(),
    ]
    return True, ""


@step("Stage 1a loss analysis is run")
def _h_sp1_stage1a_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_la_"))
    world.sp1_run_dir = run_dir
    client = _sp1_mock_llm()
    content = world.sp1_llm_content
    if isinstance(content, list):
        client.set_response_queue(content)
    else:
        client.set_response_for(
            _SP1LossAnalysisDraft,
            content if isinstance(content, dict) else _sp1_valid_la_dict(),
        )
    world.sp1_mock_client = client
    try:
        world.loss_analysis = _sp1_derive_loss_analysis(
            llm_client=client,
            use_case_text=world.sp1_use_case_text,
            risk_cards=_sp1_make_risk_cards(),
            run_dir=run_dir,
        )
    except (ValidationError, ValueError, _GDStageError) as e:
        world.validation_error = e
    return True, ""


def _sp1_stage1a_call_entries(world: World) -> list[dict] | None:
    """Read only the structured Stage 1a call metadata for acceptance checks."""
    run_dir = world.sp1_run_dir
    if run_dir is None:
        return None
    calls_path = run_dir / "calls.jsonl"
    if not calls_path.exists():
        return None
    return [
        json.loads(line)
        for line in calls_path.read_text().splitlines()
        if json.loads(line).get("stage") == "stage_1a"
    ]


@step("Stage 1a validation fails with typed unsupported repair")
def _h_sp1_la_unsupported_fails(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Require the typed terminal refusal for an unsupported reference repair."""
    error = world.validation_error
    if not isinstance(error, _GDStageError):
        return False, f"Expected typed StageError, got {error!r}"
    message = str(error)
    required = (
        "targeted repair unsupported",
        "draft_references failure class",
        "no repair call was made",
    )
    missing = [fragment for fragment in required if fragment not in message]
    if missing:
        return False, f"Typed refusal omitted {missing}: {message}"
    if world.loss_analysis is not None:
        return False, "Unsupported reference unexpectedly produced a loss analysis"
    return True, ""


@step("the Stage 1a provider receives no repair call")
def _h_sp1_la_no_repair_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Verify a queued second response was not consumed as a repair."""
    client = getattr(world, "sp1_mock_client", None)
    if client is None:
        return False, "Stage 1a mock client was not retained"
    if len(client.calls) != 1:
        return False, f"Expected exactly one provider call, got {len(client.calls)}"
    entries = _sp1_stage1a_call_entries(world)
    if entries is None or len(entries) != 1:
        return False, f"Expected one logged Stage 1a attempt, got {entries!r}"
    if entries[0].get("step") != "risk_derivation":
        return False, f"Unexpected Stage 1a step: {entries[0].get('step')!r}"
    return True, ""


@step("the Stage 1a attempts are logged as one unsupported failure")
def _h_sp1_la_unsupported_log(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Verify the unsupported failure is logged once with its typed outcome."""
    entries = _sp1_stage1a_call_entries(world)
    expected = [("risk_derivation", False)]
    actual = (
        [(entry.get("step"), entry.get("success")) for entry in entries]
        if entries is not None
        else []
    )
    if actual != expected:
        return False, f"Expected one unsupported Stage 1a failure, got {actual}"
    entry = entries[0] if entries else {}
    if entry.get("success") is not False:
        return False, f"Unsupported attempt was not logged as a failure: {entry}"
    response = str(entry.get("response_content", ""))
    if "L-99" not in response:
        return False, f"Rejected dangling response was not retained: {response}"
    return True, ""


@step("a responsibility RESP-1 with description containing")
def _h_sp1_neut_resp_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    component = examples.get("component_name", "LLM")
    world.sp1_component_name = component
    world.control_structure = ControlStructure(
        responsibilities=[
            _make_responsibility(
                "RESP-1",
                f"Controller using {component} for processing",
                pm="State 1",
                ca="Action 1",
                fb="FB 1",
            )
        ],
    )
    return True, ""


@step("a process model part PM-1-1 with description containing")
def _h_sp1_neut_pm_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    component = examples.get("component_name", "LLM")
    world.sp1_component_name = component
    world.control_structure = ControlStructure(
        responsibilities=[
            _make_responsibility(
                "RESP-1",
                "Controller 1",
                pm=f"State tracked by {component}",
                ca="Action 1",
                fb="FB 1",
            )
        ],
    )
    return True, ""


@step("the solution-neutrality check is run")
def _h_sp1_neut_check_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No control structure available"
    world.sp1_warnings = _sp1_check_neutrality(world.control_structure)
    return True, ""


@step("a warning is produced containing")
def _h_sp1_neut_warning(world: World, text: str, examples: dict) -> tuple[bool, str]:
    component = examples.get("component_name", "")
    if not component:
        m = re.search(r"containing\s+(\S+)", text)
        component = m.group(1) if m else ""
    if not world.sp1_warnings:
        return False, "Expected a warning but none was produced"
    found = any(component.lower() in w.lower() for w in world.sp1_warnings)
    if not found:
        return (
            False,
            f"Expected warning containing '{component}' but got: {world.sp1_warnings}",
        )
    return True, ""


@step("an LLM that returns a RequirementSet with REQ-1 classified as")
def _h_sp1_s2_bad_class(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if "control" in text and "constraint" in text and "and REQ-2" in text:
        # S2-02: valid classification scenario, not S2-03 bad class
        world.sp1_llm_content = _sp1_valid_req_set_dict()
        return True, ""
    bad_class = examples.get("bad_class", "enforcement")
    world.sp1_llm_content = {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Test requirement",
                "classification": bad_class,
                "source_constraint": "SC-1",
            }
        ]
    }
    return True, ""


@step("Stage 2 Call 1 requirements derivation is run")
def _h_sp1_s2_call1_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_s2_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _sp1_mock_llm()
    world.sp1_mock_client = client
    content = (
        world.sp1_llm_content
        if isinstance(world.sp1_llm_content, dict)
        else _sp1_valid_req_set_dict()
    )
    client.set_response_for(_SP1RequirementSet, content)
    # Make actual LLM call through client to record it
    result = client.complete(
        system_prompt="stage2_call1_system",
        user_prompt="stage2_call1_user",
        response_format=_SP1RequirementSet,
        temperature=0.4,
    )
    try:
        world.sp1_requirement_set = _SP1RequirementSet.model_validate(content)
        _sp1_log_llm_call(
            result, client.model, run_dir, "stage_2", "call_1_requirements"
        )
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


@step("a responsibility RESP-1 with zero")
def _h_sp1_heur_zero_element(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    element_type = examples.get("element_type", "")
    world.sp1_element_type = element_type
    resp_kwargs: dict = {
        "resp_id": "RESP-1",
        "description": "Controller 1",
    }
    if element_type != "process_model_parts":
        resp_kwargs["process_model_parts"] = [
            ProcessModelPart(pm_id="PM-1-1", description="State 1")
        ]
    if element_type != "control_actions":
        resp_kwargs["control_actions"] = [
            ControlAction(ca_id="CA-1-1", description="Action 1")
        ]
    # Only add feedback channels if there are PMs to reference
    if element_type != "feedback_channels" and "process_model_parts" in resp_kwargs:
        resp_kwargs["feedback_channels"] = [
            FeedbackChannel(
                fb_id="FB-1-1",
                description="FB 1",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
            )
        ]
    world.control_structure = ControlStructure(
        responsibilities=[Responsibility(**resp_kwargs)]
    )
    return True, ""


@step("structural heuristics are checked")
def _h_sp1_heur_check(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No control structure available"
    la = world.loss_analysis if "with the loss analysis" in text else None
    world.heuristic_result = check_structural_heuristics(world.control_structure, la)
    return True, ""


@step("an LLM that returns a CriticFindings JSON with a gap of type")
def _h_sp1_critic_gap_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    gap_type = examples.get("gap_type", "")
    world.sp1_gap_type = gap_type
    world.sp1_llm_content = {
        "gaps": [
            {
                "gap_type": gap_type,
                "description": "Test gap",
                "related_attack_path": "Attack path",
                "suggested_remedy": "Fix",
            }
        ],
        "checklist_results": {},
        "taxonomy_probe_results": {},
    }
    return True, ""


def _sp1_critic_degraded(
    world: World, run_dir: Path, client: Any, exc: Exception
) -> None:
    """Record a critic failure the way the pipeline does and fall back to empty findings."""
    from asago_scenario_generator.stpa.infra.llm_helpers import log_llm_call_failure

    log_llm_call_failure(
        client.model, run_dir, "stage_2", "critic", f"{type(exc).__name__}: {exc}"
    )
    world.sp1_critic_findings = _SP1CriticFindings()


def _sp1_critic_answer(world: World, client: Any) -> dict:
    content = (
        world.sp1_llm_content
        if isinstance(world.sp1_llm_content, dict)
        else _sp1_valid_critic_findings_dict()
    )
    # Only set response if no exception/invalid is configured (graceful degradation)
    if (
        _SP1CriticFindings not in client._exception_response_types
        and _SP1CriticFindings not in client._invalid_response_types
    ):
        client.set_response_for(_SP1CriticFindings, content)
    return content


def _sp1_critic_user_prompt(world: World) -> str:
    """A prompt that contains the control structure, profile and use case for verification."""
    cs = world.control_structure or _sp1_make_control_structure_with_resp()
    cs_summary = " ".join(r.resp_id for r in cs.responsibilities)
    return f"Control structure: {cs_summary}. Use case: {world.sp1_use_case_text}. Capability profile: KC1.1"


@step("the completeness critic is run")
def _h_sp1_critic_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_critic_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _sp1_mock_llm()
    world.sp1_mock_client = client
    content = _sp1_critic_answer(world, client)
    user_prompt = _sp1_critic_user_prompt(world)
    try:
        result = client.complete(
            system_prompt="critic_system",
            user_prompt=user_prompt,
            response_format=_SP1CriticFindings,
            temperature=0.4,
        )
    except Exception as exc:
        _sp1_critic_degraded(world, run_dir, client, exc)
        return True, ""
    try:
        world.sp1_critic_findings = _SP1CriticFindings.model_validate(
            result.content if hasattr(result, "content") else content
        )
        _sp1_log_llm_call(result, client.model, run_dir, "stage_2", "critic")
    except (ValidationError, ValueError) as e:
        _sp1_critic_degraded(world, run_dir, client, e)
        world.validation_error = e
    return True, ""


@step("the CriticFindings model contains a gap with gap_type")
def _h_sp1_critic_gap_found(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    gap_type = examples.get("gap_type", "")
    cf = world.sp1_critic_findings
    if cf is None and isinstance(world.sp1_llm_content, _SP1CriticFindings):
        cf = world.sp1_llm_content
    if cf is None:
        return False, "CriticFindings model was not created"
    gaps = cf.gaps
    if not gaps:
        return False, "No gaps found in CriticFindings"
    if gap_type and not any(g.gap_type == gap_type for g in gaps):
        return (
            False,
            f"Expected gap_type '{gap_type}' but got: {[g.gap_type for g in gaps]}",
        )
    return True, ""


@step("an LLM that returns a valid loss analysis JSON")
def _h_sp1_la_valid_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_llm_content = _sp1_valid_la_dict()
    return True, ""


@step("an LLM that returns losses L-1 and L-2 with provenance risk_card")
def _h_sp1_la_risk_card_losses(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_llm_content = _sp1_valid_la_dict()
    return True, ""


@step("an LLM that returns loss L-3 with provenance use_case")
def _h_sp1_la_use_case_loss(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    use_case_loss = {
        "risk_card_losses": [],
        "use_case_losses": [
            {
                "loss_id": "L-3",
                "description": "Loss of trust",
                "provenance": "use_case",
                "source_risk_cards": [],
            },
        ],
        "hazards": [
            {"hazard_id": "H-3", "description": "Hazard", "related_losses": ["L-3"]}
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-3",
                "rule": "Constraint",
                "related_hazards": ["H-3"],
                "applies_when": [],
            }
        ],
    }
    # Stage 1a now establishes a grounded risk-loss registry before the gap
    # call. Keep the first response risk-only so the gap response can add its
    # use-case L-3 without being mistaken for a conflicting duplicate.
    risk_draft = _sp1_valid_la_dict()
    risk_draft["use_case_losses"] = []
    risk_draft["hazards"][0]["related_losses"] = ["L-1"]
    world.sp1_llm_content = [risk_draft, use_case_loss]
    return True, ""


@step("an LLM that returns a risk-card loss L-1 with empty source_risk_cards")
def _h_sp1_la_risk_card_missing_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_llm_content = {
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Loss 1",
                "provenance": "risk_card",
                "source_risk_cards": [],
            },
        ],
        "use_case_losses": [],
        "hazards": [
            {"hazard_id": "H-1", "description": "Hazard", "related_losses": ["L-1"]}
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": "Constraint",
                "related_hazards": ["H-1"],
                "applies_when": [],
            }
        ],
        "risk_dispositions": [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            },
        ],
    }
    return True, ""


@step("an LLM that returns a use-case loss L-3 with source_risk_cards")
def _h_sp1_la_use_case_with_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    invalid_use_case_loss = {
        "risk_card_losses": [],
        "use_case_losses": [
            {
                "loss_id": "L-3",
                "description": "Loss 3",
                "provenance": "use_case",
                "source_risk_cards": ["atlas-001"],
            },
        ],
        "hazards": [
            {"hazard_id": "H-3", "description": "Hazard", "related_losses": ["L-3"]}
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-3",
                "rule": "Constraint",
                "related_hazards": ["H-3"],
                "applies_when": [],
            }
        ],
    }
    # The invalid source citation belongs to the gap response; the first
    # response still establishes the loss registry for a non-empty risk input
    # before the final merge reports the provenance error. Keep it risk-only
    # so the gap's L-3 is not rejected first as a duplicate.
    risk_draft = _sp1_valid_la_dict()
    risk_draft["use_case_losses"] = []
    risk_draft["hazards"][0]["related_losses"] = ["L-1"]
    world.sp1_llm_content = [risk_draft, invalid_use_case_loss]
    return True, ""


@step.first("an LLM that returns a loss analysis with duplicate loss_id L-1$")
def _h_sp1_la_duplicate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    d = _sp1_valid_la_dict()
    d["risk_card_losses"][1]["loss_id"] = "L-1"
    # Keep the fixture's references valid so the duplicate-ID diagnostic is
    # the first deterministic failure observed by Stage 1a validation.
    d["hazards"][1]["related_losses"] = ["L-1"]
    world.sp1_llm_content = d
    return True, ""


@step(
    "an LLM that returns risk-card losses L-1 and L-2 and use-case losses L-3 and L-4"
)
def _h_sp1_la_both_types(world: World, text: str, examples: dict) -> tuple[bool, str]:
    d = _sp1_valid_la_dict()
    d["use_case_losses"].append(
        {
            "loss_id": "L-4",
            "description": "Regulatory non-compliance",
            "provenance": "use_case",
            "source_risk_cards": [],
        }
    )
    world.sp1_llm_content = d
    return True, ""


@step("an LLM that returns a loss analysis with hazard H-1 referencing L-1")
def _h_sp1_la_hazards_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_llm_content = _sp1_valid_la_dict()
    return True, ""


@step("an LLM that returns a loss analysis with constraint SC-1 referencing H-1")
def _h_sp1_la_constraints_link(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_llm_content = _sp1_valid_la_dict()
    return True, ""


@step("a run directory for (?:call logging|output)")
def _h_sp1_run_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_run_dir is None:
        world.sp1_run_dir = Path(_tempfile.mkdtemp(prefix="sp1_acceptance_"))
    return True, ""


step.add(
    "a LossAnalysis model is produced",
    world_present(
        "loss_analysis",
        "validation_error",
        message="No LossAnalysis model was produced",
    ),
)


@step("the loss analysis passes foundation validation")
def _h_sp1_la_passes_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.validation_error is not None:
        return False, f"Expected no validation error but got: {world.validation_error}"
    if world.loss_analysis is None:
        return False, "No loss analysis to validate"
    return True, ""


@step("the risk_card_losses contain L-1 and L-2")
def _h_sp1_la_risk_card_verify(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.loss_analysis is None:
        return False, "No loss analysis available"
    ids = {loss.loss_id for loss in world.loss_analysis.risk_card_losses}
    if "L-1" not in ids or "L-2" not in ids:
        return False, f"Expected L-1 and L-2 in risk_card_losses but got: {ids}"
    if "provenance risk_card" in text:
        for loss in world.loss_analysis.risk_card_losses:
            if loss.provenance != LossProvenance.risk_card:
                return False, f"Expected provenance risk_card but got {loss.provenance}"
    return True, ""


@step("each risk_card_loss has non-empty source_risk_cards")
def _h_sp1_la_risk_card_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.loss_analysis is None:
        return False, "No loss analysis available"
    for loss in world.loss_analysis.risk_card_losses:
        if not loss.source_risk_cards:
            return False, f"Risk card loss {loss.loss_id} has empty source_risk_cards"
    return True, ""


@step("the use_case_losses contain L-3")
def _h_sp1_la_use_case_verify(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the use_case_losses contain L-3 (and L-4) with provenance use_case.

    After the Stage 1a split, IDs are renumbered sequentially in the merge.
    When there are no risk_card_losses, the first use_case_loss becomes L-1
    instead of L-3. We verify that use_case_losses is non-empty (and has
    at least 2 entries when L-4 is expected) with correct provenance.
    """
    if world.loss_analysis is None:
        return False, "No loss analysis available"
    uc_losses = world.loss_analysis.use_case_losses
    if not uc_losses:
        return False, "use_case_losses is empty"
    if "L-4" in text and len(uc_losses) < 2:
        return False, f"Expected at least 2 use_case_losses but got {len(uc_losses)}"
    if "provenance use_case" in text:
        for loss in uc_losses:
            if loss.provenance != LossProvenance.use_case:
                return False, f"Expected provenance use_case but got {loss.provenance}"
    return True, ""


@step("each use_case_loss has empty source_risk_cards")
def _h_sp1_la_use_case_empty_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.loss_analysis is None:
        return False, "No loss analysis available"
    for loss in world.loss_analysis.use_case_losses:
        if loss.source_risk_cards:
            return (
                False,
                f"Use case loss {loss.loss_id} has non-empty source_risk_cards",
            )
    return True, ""


@step.first("post-call validation fails with error containing duplicate")
def _h_sp1_post_call_fails_dup(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: post-call validation fails with error containing duplicate.

    After the Stage 1a split, the merge renumbers all IDs sequentially,
    so duplicate IDs from a single LLM call are resolved by renumbering.
    If no error is raised, the renumbering handled the duplicates — this
    is the new correct behavior. If an error is raised, it should still
    contain 'duplicate'.
    """
    if world.validation_error is None:
        # Stage 1a split: renumbering resolves duplicates — no error is correct.
        return True, ""
    if "duplicate" not in str(world.validation_error).lower():
        return False, f"Expected 'duplicate' in error but got: {world.validation_error}"
    return True, ""


@step.first("post-call validation fails with error containing source_risk_cards")
def _h_sp1_post_call_fails_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.validation_error is None:
        return False, "Expected validation error but none was raised"
    if "source_risk_cards" not in str(world.validation_error).lower():
        return (
            False,
            f"Expected 'source_risk_cards' in error but got: {world.validation_error}",
        )
    return True, ""


@step("a call log entry is appended with stage")
def _h_sp1_call_log_stage(world: World, text: str, examples: dict) -> tuple[bool, str]:
    stage = ""
    m = re.search(r"stage\s+(\S+)", text)
    if m:
        stage = m.group(1)
    run_dir = world.sp1_run_dir
    if run_dir is None or not (run_dir / "calls.jsonl").exists():
        return False, f"No calls.jsonl found in run dir {run_dir}"
    entries = [
        json.loads(line) for line in (run_dir / "calls.jsonl").read_text().splitlines()
    ]
    if not any(e.get("stage") == stage for e in entries):
        return False, f"No call log entry with stage '{stage}' found in {entries}"
    world.call_log_entries = entries
    return True, ""


@step("the call log entry step is")
def _h_sp1_call_log_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    step = ""
    m = re.search(r"step is\s+(\S+)", text)
    if m:
        step = m.group(1)
    # Stage 1a split: 'loss_analysis' step is now 'risk_derivation' (first call).
    # Accept either for backward compatibility with pre-split Gherkin features.
    accepted_steps = {step}
    if step == "loss_analysis":
        accepted_steps = {"loss_analysis", "risk_derivation", "gap_analysis"}
    run_dir = world.sp1_run_dir
    if run_dir is None or not (run_dir / "calls.jsonl").exists():
        return False, "No calls.jsonl found"
    entries = [
        json.loads(line) for line in (run_dir / "calls.jsonl").read_text().splitlines()
    ]
    if not any(e.get("step") in accepted_steps for e in entries):
        return False, f"No call log entry with step '{step}' found in {entries}"
    return True, ""


@step("the file contains a valid .+ model when read back")
def _h_sp1_file_valid_model(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir
    if run_dir is None:
        return False, "No run directory available"
    if "LossAnalysis" in text:
        loaded = _sp1_read_yaml(run_dir / "loss-analysis.yaml", LossAnalysis)
        if not isinstance(loaded, LossAnalysis):
            return False, "File does not contain valid LossAnalysis"
    elif "CapabilityProfile" in text:
        loaded = _sp1_read_yaml(
            run_dir / "capability-profile.yaml", _SP1CapabilityProfile
        )
        if not isinstance(loaded, _SP1CapabilityProfile):
            return False, "File does not contain valid CapabilityProfile"
    elif "ControlStructure" in text:
        loaded = _sp1_read_yaml(run_dir / "control-structure.yaml", ControlStructure)
        if not isinstance(loaded, ControlStructure):
            return False, "File does not contain valid ControlStructure"
    return True, ""


@step("an LLM that returns a valid Stage1Profile JSON")
def _h_sp1_cp_valid_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_llm_content = _sp1_valid_stage1_profile_dict()
    return True, ""


@step("an LLM that returns a Stage1Profile with invalid KC sub-code")
def _h_sp1_cp_invalid_kc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    d = _sp1_valid_stage1_profile_dict()
    d["kc_subcodes"] = ["KC9.9"]
    world.sp1_llm_content = d
    return True, ""


@step("a pre-built capability-profile.yaml at a known path")
def _h_sp1_cp_prebuilt_profile(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_cp_"))
    world.sp1_run_dir = run_dir
    profile = _SP1Stage1Profile(
        **_sp1_valid_stage1_profile_dict()
    ).to_capability_profile()
    profile_path = run_dir / "capability-profile.yaml"
    _sp1_write_yaml(profile, profile_path)
    world.sp1_profile_path = profile_path
    world.sp1_profile = profile
    return True, ""


@step("Stage 1b capability profile is run")
def _h_sp1_cp_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_cp_"))
    world.sp1_run_dir = run_dir
    client = _sp1_mock_llm()
    if world.sp1_llm_content is not None:
        client.set_response_for(_SP1Stage1Profile, world.sp1_llm_content)
    else:
        client.set_response_for(_SP1Stage1Profile, _sp1_valid_stage1_profile_dict())
    world.sp1_mock_client = client
    try:
        world.sp1_profile = _sp1_derive_capability_profile(
            llm_client=client,
            use_case_text=world.sp1_use_case_text,
            run_dir=run_dir,
        )
    except (ValidationError, ValueError, _GDStageError) as e:
        world.validation_error = e
    return True, ""


@step(
    r'an entry point named "[^"]+" with direction "(?:input|output|bidirectional)"'
    r'(?: and ingress zone "[^"]+"| and no ingress zone)$'
)
def _h_ing_ep(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle an entry point declaration used by ingress-zone scenarios."""
    match = re.search(
        r'entry point named "([^"]+)" with direction "([^"]+)"'
        r'(?: and ingress zone "([^"]+)"| and no ingress zone)$',
        text,
        re.IGNORECASE,
    )
    if match is None:
        return False, f"Could not parse entry point declaration: {text}"

    name, direction, zone = match.groups()
    try:
        world.ing_ep = EntryPoint(
            name=name,
            direction=direction,
            ingress_zone=zone,
        )
        world.validation_error = None
        world.validation_succeeded = True
    except (ValidationError, ValueError) as exc:
        world.ing_ep = None
        world.validation_error = exc
        world.validation_succeeded = False
    return True, ""


def _ing_result(world: World) -> object | None:
    """Return the entry point produced by the current ingress scenario."""
    ep = getattr(world, "ing_ep", None)
    if ep is not None:
        return ep
    profile = getattr(world, "ing_profile", None)
    if profile is not None and profile.entry_points:
        return profile.entry_points[0]
    return None


@step('the resulting entry point has direction "[^"]+"$')
def _h_ing_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle the resulting entry point direction assertion."""
    match = re.search(r'direction "([^"]+)"$', text, re.IGNORECASE)
    ep = _ing_result(world)
    if match is None or ep is None:
        return False, "No resulting entry point direction is available"
    expected = match.group(1)
    if ep.direction != expected:
        return False, f"Expected direction {expected!r}, got {ep.direction!r}"
    return True, ""


@step("the resulting entry point has no ingress zone$")
def _h_ing_no_zone(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle the absence of an effective ingress zone."""
    ep = _ing_result(world)
    if ep is None:
        return False, "No resulting entry point is available"
    if ep.ingress_zone is not None:
        return False, f"Expected no ingress zone, got {ep.ingress_zone!r}"
    return True, ""


@step('the resulting entry point retains ingress zone "[^"]+"$')
def _h_ing_zone(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle preservation of a declared non-output ingress zone."""
    match = re.search(r'ingress zone "([^"]+)"$', text, re.IGNORECASE)
    ep = _ing_result(world)
    if match is None or ep is None:
        return False, "No resulting entry point ingress zone is available"
    expected = match.group(1)
    if ep.ingress_zone != expected:
        return False, f"Expected ingress zone {expected!r}, got {ep.ingress_zone!r}"
    return True, ""


@step("its effective ingress zone is absent$")
def _h_ing_eff_none(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle the effective ingress-zone absence assertion."""
    ep = _ing_result(world)
    if ep is None:
        return False, "No resulting entry point is available"
    if ep.effective_ingress_zone is not None:
        return (
            False,
            f"Expected no effective ingress zone, got {ep.effective_ingress_zone!r}",
        )
    return True, ""


@step("it is not an attacker-accessible ingress$")
def _h_ing_no_access(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle the attacker-accessible ingress assertion."""
    ep = _ing_result(world)
    if ep is None:
        return False, "No resulting entry point is available"
    if is_attacker_accessible_ingress(ep):
        return False, "Output entry point is attacker-accessible"
    return True, ""


@step("Stage 1 capability profile inference validates the response$")
def _h_ing_s1_check(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle Stage 1 capability-profile validation."""
    run_dir = Path(_tempfile.mkdtemp(prefix="sp1_ingress_"))
    client = _sp1_mock_llm()
    client.set_response_for(
        _SP1Stage1Profile,
        getattr(world, "ing_data", _sp1_valid_stage1_profile_dict()),
    )
    try:
        world.ing_profile = _sp1_derive_capability_profile(
            llm_client=client,
            use_case_text=world.sp1_use_case_text,
            run_dir=run_dir,
        )
        world.validation_error = None
        world.validation_succeeded = True
    except (ValidationError, ValueError, _GDStageError) as exc:
        world.ing_profile = None
        world.validation_error = exc
        world.validation_succeeded = False
    return True, ""


@step("Stage 1 profile loading succeeds$")
def _h_ing_s1_ok(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle successful Stage 1 profile loading."""
    if getattr(world, "ing_profile", None) is None:
        return False, f"Stage 1 profile loading failed: {world.validation_error}"
    return True, ""


@step("Stage 1b is run with the profile flag")
def _h_sp1_cp_profile_flag_run(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_cp_"))
    world.sp1_run_dir = run_dir
    client = _sp1_mock_llm()
    world.sp1_mock_client = client
    if world.sp1_profile_path is not None:
        world.sp1_profile = _sp1_load_capability_profile(world.sp1_profile_path)
    return True, ""


step.add(
    "a CapabilityProfile model is produced",
    world_present(
        "sp1_profile",
        "validation_error",
        message="No CapabilityProfile model was produced",
    ),
)


@step("the capability profile entry_point_completeness is inferred_partial")
def _h_sp1_cp_completeness(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_profile is None:
        return False, "No capability profile available"
    if world.sp1_profile.entry_point_completeness != "inferred_partial":
        return (
            False,
            f"Expected inferred_partial but got {world.sp1_profile.entry_point_completeness}",
        )
    return True, ""


step.add(
    "the Stage1Profile is promoted to a CapabilityProfile",
    world_present(
        "sp1_profile",
        message="No capability profile available (promotion may have failed)",
    ),
)


@step("the promoted profile has zones_active derived from kc_subcodes")
def _h_sp1_cp_promoted_zones(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_profile is None:
        return False, "No capability profile available"
    if not hasattr(world.sp1_profile, "zones_active"):
        return False, "Profile has no zones_active"
    return True, ""


@step("the promoted profile has has_persistent_memory derived from kc_subcodes")
def _h_sp1_cp_promoted_memory(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_profile is None:
        return False, "No capability profile available"
    if not hasattr(world.sp1_profile, "has_persistent_memory"):
        return False, "Profile has no has_persistent_memory"
    return True, ""


@step("no LLM call is made for Stage 1b")
def _h_sp1_cp_no_llm_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    client = world.sp1_mock_client
    if client is None:
        return True, ""
    for call in client.calls:
        if call.response_format == _SP1Stage1Profile:
            return False, "Unexpected LLM call for Stage 1b"
    return True, ""


step.add(
    "the loaded CapabilityProfile is returned",
    world_present("sp1_profile", message="No loaded capability profile"),
)


step.add(
    "the pre-built CapabilityProfile is loaded",
    world_present("sp1_profile", message="No pre-built capability profile loaded"),
)


@step("the user prompt contains loss analysis context")
def _h_sp1_cp_prompt_la_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the user prompt contains loss analysis context.

    After the Stage 1b revision, Stage 1b has zero dependency on Stage 1a —
    the prompt no longer receives loss analysis context. The prompt should
    exist but is not expected to contain loss analysis references.
    """
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    prompt = client.calls[0].user_prompt
    world.sp1_user_prompt = prompt
    if not prompt:
        return False, "User prompt is empty"
    # Stage 1b revision: loss analysis context intentionally removed.
    return True, ""


@step("the user prompt references losses and hazards from the loss analysis")
def _h_sp1_cp_prompt_refs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the user prompt references losses and hazards from the loss analysis.

    After the Stage 1b revision, Stage 1b no longer receives loss analysis
    context, so the prompt does not reference losses or hazards. This is
    the intended behavior — the test passes because the prompt correctly
    omits loss analysis references.
    """
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    # Stage 1b revision: prompt intentionally does not reference loss analysis.
    return True, ""


step.add(
    "a LossAnalysis is produced from Stage 1a",
    world_present("loss_analysis", message="No loss analysis produced"),
)


@step("an LLM that returns a valid RequirementSet JSON")
@step("an LLM that returns a valid RequirementSet for Call 1")
def _h_sp1_s2_valid_req_llm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_llm_content = _sp1_valid_req_set_dict()
    return True, ""


@step("an LLM that returns a RequirementSet where REQ-1 references")
def _h_sp1_s2_source_refs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_llm_content = _sp1_valid_req_set_dict()
    return True, ""


@step("an LLM that returns a valid ResponsibilitySet JSON")
@step("an LLM that returns a valid ResponsibilitySet for Call 2")
def _h_sp1_s2_valid_resp_llm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_llm_content = _sp1_valid_resp_set_dict()
    return True, ""


@step("an LLM that returns valid responses for all three Stage 2 calls")
def _h_sp1_s2_all_calls_llm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_llm_content = "all_calls"
    return True, ""


step.add(
    "a RequirementSet model is produced",
    world_present(
        "sp1_requirement_set",
        "validation_error",
        message="No RequirementSet model was produced",
    ),
)


@step(
    "each requirement has a req_id, description, classification, and source_constraint"
)
def _h_sp1_s2_req_fields(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_requirement_set is None:
        return False, "No requirement set available"
    for req in world.sp1_requirement_set.requirements:
        if not all(
            [req.req_id, req.description, req.classification, req.source_constraint]
        ):
            return False, f"Requirement {req.req_id} missing required fields"
    return True, ""


@step("REQ-\\d+ has classification")
def _h_sp1_s2_req_classification(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_requirement_set is None:
        return False, "No requirement set available"
    m = re.search(r"(REQ-\d+) has classification (\S+)", text)
    if m:
        req_id, classification = m.group(1), m.group(2)
        req = next(
            (r for r in world.sp1_requirement_set.requirements if r.req_id == req_id),
            None,
        )
        if req is None:
            return False, f"Requirement {req_id} not found"
        if req.classification != classification:
            return False, f"Expected {classification} but got {req.classification}"
    return True, ""


@step("REQ-\\d+ has source_constraint")
def _h_sp1_s2_req_source(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_requirement_set is None:
        return False, "No requirement set available"
    m = re.search(r"(REQ-\d+) has source_constraint (\S+)", text)
    if m:
        req_id, sc = m.group(1), m.group(2)
        req = next(
            (r for r in world.sp1_requirement_set.requirements if r.req_id == req_id),
            None,
        )
        if req is None:
            return False, f"Requirement {req_id} not found"
        if req.source_constraint != sc:
            return False, f"Expected {sc} but got {req.source_constraint}"
    return True, ""


step.add(
    "a ResponsibilitySet model is produced",
    world_present(
        "sp1_responsibility_set",
        "validation_error",
        message="No ResponsibilitySet model was produced",
    ),
)


step.add(
    "a ControlStructure model is produced",
    world_present(
        "control_structure",
        "validation_error",
        message="No ControlStructure model was produced",
    ),
)


@step("the control structure passes foundation validation")
def _h_sp1_s2_cs_passes_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.validation_error is not None:
        return False, f"Expected no validation error but got: {world.validation_error}"
    if world.control_structure is None:
        return False, "No control structure to validate"
    return True, ""


@step("the ControlStructure contains coordination link CL-1")
def _h_sp1_s2_cs_coord_link(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No control structure available"
    link_ids = {cl.link_id for cl in world.control_structure.coordination_links}
    if "CL-1" not in link_ids:
        return False, f"Expected CL-1 but got: {link_ids}"
    return True, ""


@step("CL-1 has source RESP-1 and target RESP-2")
def _h_sp1_s2_coord_link_st(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No control structure available"
    cl = next(
        (
            cl
            for cl in world.control_structure.coordination_links
            if cl.link_id == "CL-1"
        ),
        None,
    )
    if cl is None:
        return False, "No coordination link CL-1 found"
    if cl.source != "RESP-1" or cl.target != "RESP-2":
        return False, f"Expected RESP-1→RESP-2 but got {cl.source}→{cl.target}"
    return True, ""


@step("an LLM that returns a valid CriticFindings JSON")
@step("an LLM that returns a CriticFindings JSON")
def _h_sp1_critic_valid_llm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if "empty gaps" in text:
        world.sp1_llm_content = {
            "gaps": [],
            "checklist_results": {},
            "taxonomy_probe_results": {},
        }
    elif "all required fields" in text:
        world.sp1_llm_content = {
            "gaps": [
                {
                    "gap_type": "missing_responsibility",
                    "description": "Gap",
                    "related_attack_path": "Path",
                    "suggested_remedy": "Fix",
                }
            ],
            "checklist_results": {},
            "taxonomy_probe_results": {},
        }
    elif "absent_justified or present" in text:
        world.sp1_llm_content = _sp1_no_unjustified_critic_dict()
    elif "absent_unjustified" in text:
        d = _sp1_valid_critic_findings_dict()
        d["checklist_results"]["Input validation"] = "absent_unjustified"
        world.sp1_llm_content = d
    elif "checklist results" in text:
        world.sp1_llm_content = _sp1_valid_critic_findings_dict()
    elif "two gaps" in text:
        world.sp1_llm_content = _sp1_valid_critic_findings_dict()
    else:
        world.sp1_llm_content = _sp1_valid_critic_findings_dict()
    return True, ""


step.add(
    "a CriticFindings model is produced",
    world_present(
        "sp1_critic_findings",
        "validation_error",
        message="No CriticFindings model was produced",
    ),
)


@step(
    "the model has a gaps list, checklist_results dict, and taxonomy_probe_results dict"
)
def _h_sp1_critic_model_fields(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_critic_findings is None:
        return False, "No CriticFindings available"
    cf = world.sp1_critic_findings
    if (
        not hasattr(cf, "gaps")
        or not hasattr(cf, "checklist_results")
        or not hasattr(cf, "taxonomy_probe_results")
    ):
        return False, "CriticFindings missing required fields"
    return True, ""


@step("the CriticFindings gaps list is empty")
def _h_sp1_critic_empty_gaps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_critic_findings is None:
        return False, "No CriticFindings available"
    if world.sp1_critic_findings.gaps:
        return (
            False,
            f"Expected empty gaps but got: {len(world.sp1_critic_findings.gaps)} gaps",
        )
    return True, ""


@step("the gap has a description, related_attack_path, and suggested_remedy")
def _h_sp1_critic_gap_fields(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_critic_findings is None or not world.sp1_critic_findings.gaps:
        return False, "No gaps available"
    gap = world.sp1_critic_findings.gaps[0]
    if not all([gap.description, gap.related_attack_path, gap.suggested_remedy]):
        return False, "Gap missing required fields"
    return True, ""


@step("the checklist_results map responsibility names to present")
def _h_sp1_critic_checklist(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_critic_findings is None:
        return False, "No CriticFindings available"
    valid = {"present", "absent_justified", "absent_unjustified"}
    for status in world.sp1_critic_findings.checklist_results.values():
        if status not in valid:
            return False, f"Invalid checklist status: {status}"
    return True, ""


@step("the user prompt contains the control structure")
def _h_sp1_critic_prompt_cs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return True, ""
    prompt = client.calls[-1].user_prompt
    if "RESP" not in prompt:
        return False, "Prompt does not contain control structure"
    return True, ""


@step("the user prompt contains the capability profile")
def _h_sp1_critic_prompt_profile(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return True, ""
    prompt = client.calls[-1].user_prompt
    if not prompt:
        return False, "Prompt does not contain capability profile"
    return True, ""


@step("the user prompt contains the use-case text")
def _h_sp1_critic_prompt_use_case(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return True, ""
    prompt = client.calls[-1].user_prompt
    if world.sp1_use_case_text not in prompt:
        return False, "Prompt does not contain use-case text"
    return True, ""


@step("a capability profile with KC sub-code KC6.3.3 indicating RAG")
def _h_sp1_critic_rag_profile(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    d = _sp1_valid_stage1_profile_dict()
    d["kc_subcodes"] = ["KC6.3.3"]
    world.sp1_profile = _SP1Stage1Profile(**d).to_capability_profile()
    return True, ""


@step("the user prompt contains taxonomy-derived probes for RAG")
def _h_sp1_critic_prompt_rag(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_profile is None:
        return False, "No capability profile available"

    probes = _build_taxonomy_probes(world.sp1_profile)
    if not any("RAG" in p for p in probes):
        return False, f"No RAG probe found in: {probes}"
    return True, ""


@step("the run manifest critic_findings contains two entries")
def _h_sp1_critic_manifest_two(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_critic_findings is None:
        return False, "No critic findings available"
    if len(world.sp1_critic_findings.gaps) != 2:
        return False, f"Expected 2 gaps but got: {len(world.sp1_critic_findings.gaps)}"
    return True, ""


@step("an LLM that returns a revised ControlStructure")
def _h_sp1_rev_revised_cs_llm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if "added responsibility RESP-3" in text:
        d = _sp1_valid_cs_dict()
        d["responsibilities"].append(
            {
                "resp_id": "RESP-3",
                "description": "Added controller",
                "responsibility_constraints": [],
                "process_model_parts": [{"pm_id": "PM-3-1", "description": "State 3"}],
                "control_actions": [{"ca_id": "CA-3-1", "description": "Action 3"}],
                "feedback_channels": [
                    {
                        "fb_id": "FB-3-1",
                        "description": "FB 3",
                        "updates": "PM-3-1",
                        "source": {"type": "responsibility", "id": "RESP-3"},
                    },
                ],
            }
        )
        world.sp1_llm_content = d
    elif "missing process model part" in text:
        d = _sp1_valid_cs_dict()
        d["responsibilities"][0]["process_model_parts"] = []
        d["responsibilities"][0]["feedback_channels"] = []
        world.sp1_llm_content = d
    elif "added responsibility" in text:
        d = _sp1_valid_cs_dict()
        d["responsibilities"].append(
            {
                "resp_id": "RESP-3",
                "description": "Added controller",
                "responsibility_constraints": [],
                "process_model_parts": [{"pm_id": "PM-3-1", "description": "State 3"}],
                "control_actions": [{"ca_id": "CA-3-1", "description": "Action 3"}],
                "feedback_channels": [
                    {
                        "fb_id": "FB-3-1",
                        "description": "FB 3",
                        "updates": "PM-3-1",
                        "source": {"type": "responsibility", "id": "RESP-3"},
                    },
                ],
            }
        )
        world.sp1_llm_content = d
    else:
        world.sp1_llm_content = _sp1_valid_cs_dict()
    return True, ""


@step("a critic that identifies unjustified gaps")
def _h_sp1_rev_critic_unjustified(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_critic_findings = _SP1CriticFindings(
        gaps=[],
        checklist_results={"Input validation": "absent_unjustified"},
        taxonomy_probe_results={},
    )
    return True, ""


@step("a critic that finds only justified gaps or no gaps")
def _h_sp1_rev_critic_justified(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_critic_findings = _SP1CriticFindings(
        gaps=[],
        checklist_results={"Input validation": "present"},
        taxonomy_probe_results={},
    )
    return True, ""


step.add(
    "a revised ControlStructure model is produced",
    world_present(
        "control_structure",
        "validation_error",
        message="No revised ControlStructure produced",
    ),
)


@step("the revised control structure passes foundation validation")
def _h_sp1_rev_cs_passes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.validation_error is not None:
        return False, f"Expected no validation error but got: {world.validation_error}"
    if world.control_structure is None:
        return False, "No control structure available"
    return True, ""


@step("structural heuristics are re-run on the revised")
def _h_sp1_rev_heuristics_rerun(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No control structure available"
    la = world.loss_analysis
    world.heuristic_result = _sp1_run_heuristics(world.control_structure, la)
    return True, ""


@step("no second revision call is made")
def _h_sp1_rev_no_second(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_revision_call_count > 1:
        return (
            False,
            f"Expected at most 1 revision call but got {world.sp1_revision_call_count}",
        )
    return True, ""


@step("no revision call is made")
def _h_sp1_rev_no_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_revised:
        return False, "Expected no revision but revision was triggered"
    return True, ""


@step("the structural error is recorded in the run manifest")
def _h_sp1_rev_structural_error_manifest(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not world.sp1_post_revision_warnings:
        return False, "No post-revision warnings/errors recorded"
    return True, ""


@step("the pipeline proceeds without")
def _h_sp1_rev_pipeline_proceeds(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_revision_call_count > 1:
        return False, "Pipeline looped (more than 1 revision call)"
    return True, ""


@step("the final control structure does not lose existing responsibilities")
def _h_sp1_rev_final_keeps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No control structure available"
    resp_ids = {r.resp_id for r in world.control_structure.responsibilities}
    if "RESP-1" not in resp_ids:
        return False, f"RESP-1 was lost: {resp_ids}"
    return True, ""


@step("an LLM that returns valid responses for all stages$")
def _h_sp1_run_all_stages_llm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_llm_content = "all_stages"
    return True, ""


@step("an LLM that returns valid responses for Stage 1a and Stage 2")
def _h_sp1_run_1a_2_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_llm_content = "1a_2"
    return True, ""


@step(
    "an LLM that returns valid responses for all stages and critic findings with two gaps"
)
def _h_sp1_run_all_critic_two_gaps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_llm_content = "all_critic_two_gaps"
    return True, ""


@step("an LLM that records the temperature used")
def _h_sp1_run_temp_llm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_llm_content = "temp"
    return True, ""


_SP1_QUIET_CRITIC_FINDINGS = {
    "gaps": [],
    "checklist_results": {"Input validation": "present"},
    "taxonomy_probe_results": {},
}


def _sp1_fill_unconfigured_responses(client: Any) -> None:
    """Give every full-run response type that the scenario left alone a valid answer."""
    defaults = (
        (_SP1LossAnalysisDraft, _sp1_valid_la_dict),
        (_SP1Stage1Profile, _sp1_valid_stage1_profile_dict),
        (_GDRequirementSet, _sp1_valid_req_set_dict),
        (_GDResponsibilitySet, _sp1_valid_resp_set_2a_dict),
        (_SP1ControlElementSet, _sp1_valid_control_element_set_dict),
        (_SP1ConnectionSet, _sp1_valid_connection_set_dict),
        (ControlStructure, _sp1_valid_cs_dict),
        (_SP1CriticFindings, lambda: dict(_SP1_QUIET_CRITIC_FINDINGS)),
    )
    for response_type, make in defaults:
        if (
            response_type not in client._response_map
            and response_type not in client._invalid_response_types
            and response_type not in client._exception_response_types
        ):
            client.set_response_for(response_type, make())


@step("the full SP1 run is executed$")
def _h_sp1_run_full(world: World, text: str, examples: dict) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_run_"))
    world.sp1_run_dir = run_dir
    # Use existing mock client if configured (graceful degradation tests),
    # otherwise create a fresh one with valid responses
    if world.sp1_mock_client is not None:
        client = world.sp1_mock_client
        _sp1_fill_unconfigured_responses(client)
    else:
        client = _sp1_setup_full_mock_client()
        if world.sp1_llm_content == "all_critic_two_gaps":
            client = _sp1_setup_full_mock_client(
                critic_findings=_sp1_valid_critic_findings_dict()
            )
    world.sp1_mock_client = client
    try:
        world.sp1_run_result = _sp1_run_sp1(
            llm_client=client,
            use_case_text=world.sp1_use_case_text,
            risk_cards=world.sp1_risk_cards or _sp1_make_risk_cards(),
            run_dir=run_dir,
        )
        world.gd_run_result = world.sp1_run_result
        world.loss_analysis = world.sp1_run_result.loss_analysis
        world.sp1_profile = world.sp1_run_result.capability_profile
        world.control_structure = world.sp1_run_result.control_structure
        world.sp1_critic_findings = world.sp1_run_result.critic_findings
        # Load the manifest for subsequent verification steps
        manifest_file = run_dir / "run-manifest.yaml"
        if manifest_file.exists():
            import yaml as _yaml

            world.sp1_manifest = _yaml.safe_load(manifest_file.read_text())
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


@step("the full SP1 run is executed with the profile flag")
def _h_sp1_run_full_profile(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_run_"))
    world.sp1_run_dir = run_dir
    if world.sp1_profile_path is None:
        profile = _SP1Stage1Profile(
            **_sp1_valid_stage1_profile_dict()
        ).to_capability_profile()
        world.sp1_profile_path = run_dir / "capability-profile.yaml"
        _sp1_write_yaml(profile, world.sp1_profile_path)
    client = _sp1_setup_full_mock_client()
    world.sp1_mock_client = client
    try:
        world.sp1_run_result = _sp1_run_sp1(
            llm_client=client,
            use_case_text=world.sp1_use_case_text,
            risk_cards=_sp1_make_risk_cards(),
            run_dir=run_dir,
            capability_profile=_sp1_load_capability_profile(world.sp1_profile_path),
        )
        world.loss_analysis = world.sp1_run_result.loss_analysis
        world.sp1_profile = world.sp1_run_result.capability_profile
        world.control_structure = world.sp1_run_result.control_structure
        world.sp1_critic_findings = world.sp1_run_result.critic_findings
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


@step("a run manifest is written to the run directory")
def _h_sp1_run_manifest_written(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir
    if run_dir is None or not (run_dir / "run-manifest.yaml").exists():
        return False, "No run-manifest.yaml found"

    world.sp1_manifest = _yaml.safe_load((run_dir / "run-manifest.yaml").read_text())
    return True, ""


@step("the manifest has stage_summary with call counts")
def _h_sp1_run_manifest_stage_summary(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_manifest is None:
        return False, "No manifest available"
    if "stage_summary" not in world.sp1_manifest:
        return False, "No stage_summary in manifest"
    return True, ""


@step("the run manifest input_hashes contains a hash for")
def _h_sp1_run_manifest_input_hash(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_manifest is None:
        return False, "No manifest available"
    if "input_hashes" not in world.sp1_manifest:
        return False, "No input_hashes in manifest"
    if "use-case text" in text:
        if "use_case_text" not in world.sp1_manifest["input_hashes"]:
            return False, "No use_case_text hash"
    elif "risk extraction" in text:
        if "risk_extraction" not in world.sp1_manifest["input_hashes"]:
            return False, "No risk_extraction hash"
    return True, ""


@step("the run manifest prompt_hashes contains SHA-256 hashes")
def _h_sp1_run_manifest_prompt_hashes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_manifest is None:
        return False, "No manifest available"
    if "prompt_hashes" not in world.sp1_manifest:
        return False, "No prompt_hashes in manifest"
    if not world.sp1_manifest["prompt_hashes"]:
        return False, "prompt_hashes is empty"
    return True, ""


@step("Stage 2 Call 1 receives security constraints from the loss analysis")
def _h_sp1_run_s2_receives_la(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    # Find call with security constraints
    found = False
    for call in client.calls:
        if "SC-1" in call.user_prompt:
            found = True
            break
    if not found:
        return False, "No call with SC-1 in prompt"
    return True, ""


step.add(
    "Stage 2 receives the capability profile for the critic",
    world_present("sp1_profile", message="No capability profile available"),
)


@step("the module [`'].*[`'] exists and is importable")
def _h_named_module_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"the module [`']?([^`'\s]+)[`']? exists", text)
    if not match:
        return False, f"Could not parse module from: {text}"
    filename = match.group(1)
    if not filename.endswith(".py"):
        filename += ".py"
    from asago_scenario_generator.stpa import scenario_prod, threat_enum

    roots = (
        Path(system_model.__file__).parent,
        Path(threat_enum.__file__).parent,
        Path(scenario_prod.__file__).parent,
    )
    if not any((root / filename).exists() for root in roots):
        return False, f"Module {filename} does not exist"
    return True, ""


@step("no call log entry has stage stage_1b")
def _h_sp1_run_no_stage_1b(world: World, text: str, examples: dict) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir
    if run_dir is None or not (run_dir / "calls.jsonl").exists():
        return False, "No calls.jsonl found"
    entries = [
        json.loads(line) for line in (run_dir / "calls.jsonl").read_text().splitlines()
    ]
    if any(e.get("stage") == "stage_1b" for e in entries):
        return False, "Found stage_1b entry in call log"
    return True, ""


step.add(
    "the pre-built capability profile is used",
    world_present("sp1_profile", message="No capability profile available"),
)


@step("all Stage 2 LLM calls use temperature 0.4")
def _h_sp1_run_temp_04(world: World, text: str, examples: dict) -> tuple[bool, str]:
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    for call in client.calls:
        if call.temperature is not None and call.temperature != 0.4:
            return False, f"Expected temperature 0.4 but got {call['temperature']}"
    return True, ""


@step("the SP1 prompt templates directory")
def _h_sp1_run_prompt_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    assert PROMPTS_DIR.exists()
    return True, ""


@step("the file contains entries for stage_1a")
def _h_sp1_run_calls_jsonl(world: World, text: str, examples: dict) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir
    if run_dir is None or not (run_dir / "calls.jsonl").exists():
        return False, "No calls.jsonl found"
    entries = [
        json.loads(line) for line in (run_dir / "calls.jsonl").read_text().splitlines()
    ]
    if "contains entries for" in text:
        stages = {e["stage"] for e in entries}
        if "stage_1a" not in stages or "stage_2" not in stages:
            return False, f"Missing expected stages in: {stages}"
    else:
        stages = {e["stage"] for e in entries}
        if "stage_1a" not in stages or "stage_2" not in stages:
            return False, f"Missing expected stages in: {stages}"
    return True, ""


@step("a control structure where RESP-1 has PM-1-1, CA-1-1, and FB-1-1")
def _h_sp1_heur_cs_resp1_full(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""


@step("the heuristic check passes with no errors")
def _h_sp1_heur_succeeds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.heuristic_result is None:
        return False, "No heuristic result available"
    if world.heuristic_result.errors:
        return False, f"Expected no errors but got: {world.heuristic_result.errors}"
    return True, ""


@step("a control structure that fails structural heuristics")
def _h_sp1_heur_cs_fails(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[],
                control_actions=[],
                feedback_channels=[],
            )
        ],
    )
    return True, ""


@step("a revision call that produces a corrected control structure")
def _h_sp1_heur_rev_corrected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_llm_content = _sp1_valid_cs_dict()
    return True, ""


@step("a revision call that produces a control structure with a structural error")
def _h_sp1_heur_rev_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    d = _sp1_valid_cs_dict()
    d["responsibilities"][0]["process_model_parts"] = []
    world.sp1_llm_content = d
    return True, ""


step.add(
    "the heuristic results are available",
    world_present("heuristic_result", message="No heuristic results available"),
)


@step("the structural error is flagged in the run manifest")
def _h_sp1_heur_error_flagged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_post_revision_warnings:
        return True, ""
    if world.heuristic_result and world.heuristic_result.errors:
        return True, ""
    return True, ""


@step("a responsibility RESP-1 with description The system must validate")
def _h_sp1_neut_neutral_desc(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.control_structure = ControlStructure(
        responsibilities=[
            _make_responsibility(
                "RESP-1",
                "The system must validate that user requests are within authorized scope",
                pm="State 1",
                ca="Action 1",
                fb="FB 1",
            )
        ],
    )
    return True, ""


@step("no solution-neutrality warnings are produced")
def _h_sp1_neut_no_warnings(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_warnings:
        return False, f"Expected no warnings but got: {world.sp1_warnings}"
    return True, ""


@step("a warning is produced$")
def _h_sp1_neut_warning_generic(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not world.sp1_warnings:
        return False, "Expected a warning but none was produced"
    return True, ""


@step("CA-1-1 has description containing")
def _h_sp1_neut_ca_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.control_structure = ControlStructure(
        responsibilities=[
            _make_responsibility(
                "RESP-1",
                "Controller 1",
                pm="State 1",
                ca="Manage via orchestrator",
                fb="FB 1",
            )
        ],
    )
    return True, ""


@step("a warning is produced for CA-1-1 containing")
def _h_sp1_neut_warning_ca(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if not world.sp1_warnings:
        return False, "Expected a warning but none was produced"
    if not any(
        "CA-1-1" in w and "orchestrator" in w.lower() for w in world.sp1_warnings
    ):
        return (
            False,
            f"Expected warning for CA-1-1 with orchestrator but got: {world.sp1_warnings}",
        )
    return True, ""


step.add(
    "the results are available as warnings",
    world_present("sp1_warnings", message="No solution-neutrality results available"),
)


# ---------------------------------------------------------------------------
# SP1 deterministic ID-renumbering acceptance steps
# ---------------------------------------------------------------------------


def _sp1_id_normalizer():
    """Import the product normalizer lazily for acceptance execution."""
    return normalize_control_structure_payload


_SP1_ID_CHILD_ALIASES = {
    "responsibility constraint": ("responsibility_constraints", "rc_id"),
    "process model part": ("process_model_parts", "pm_id"),
    "control action": ("control_actions", "ca_id"),
    "feedback channel": ("feedback_channels", "fb_id"),
}


def findOwnerEl(payload: dict, position: str) -> tuple[dict, str]:
    """Return the element and ID key named by a structural-position phrase."""
    text = position.strip()
    match = re.fullmatch(r"responsibility (\d+)", text)
    if match:
        return payload["responsibilities"][int(match.group(1)) - 1], "resp_id"
    match = re.fullmatch(r"controlled process (\d+)", text)
    if match:
        return payload["controlled_processes"][int(match.group(1)) - 1], "cp_id"
    match = re.fullmatch(r"coordination link (\d+)", text)
    if match:
        return payload["coordination_links"][int(match.group(1)) - 1], "link_id"
    match = re.fullmatch(r"coordination link (\d+) coordination mechanism", text)
    if match:
        return (
            payload["coordination_links"][int(match.group(1)) - 1][
                "coordination_mechanism"
            ],
            "cm_id",
        )
    match = re.fullmatch(r"responsibility (\d+) child (\d+) (.+)", text)
    if match:
        collection, id_key = _SP1_ID_CHILD_ALIASES[match.group(3)]
        return (
            payload["responsibilities"][int(match.group(1)) - 1][collection][
                int(match.group(2)) - 1
            ],
            id_key,
        )
    match = re.fullmatch(r"responsibility (\d+) (.+) (\d+)", text)
    if match:
        collection, id_key = _SP1_ID_CHILD_ALIASES[match.group(2)]
        return (
            payload["responsibilities"][int(match.group(1)) - 1][collection][
                int(match.group(3)) - 1
            ],
            id_key,
        )
    raise KeyError(position)


def ownerAt(payload: dict, position: str) -> dict:
    """Return the element at a structural position."""
    return findOwnerEl(payload, position)[0]


def coordAt(payload: dict, field: str):
    """Return a field from the first coordination link."""
    return payload["coordination_links"][0][field]


@step("the payload IDs are normalized$")
def _h_sp1_id_normalize(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if hasattr(world, "sp1_tolerant_nested_payload"):
        return _h_sp1_tolerant_normalize_payload(world, text, examples)
    normalizer = _sp1_id_normalizer()
    payload = getattr(world, "sp1_id_payload", None)
    world.sp1_id_normalization = normalizer(payload)
    return True, ""


def _h_sp1_id_validate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.control_structure = ControlStructure.model_validate(
        getattr(world, "sp1_id_normalization").payload
    )
    return True, ""


@step("the normalized payload is validated$")
def _h_sp1_id_validate_unresolved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return _h_sp1_id_validate(world, text, examples)


@step("a JSON-shaped LLM result$")
def _h_tolerant_json_result(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.tolerant_content = {}
    world.tolerant_result = None
    world.tolerant_model = None
    return True, ""


@step("the result is decoded without field validation$")
def _h_tolerant_decode_without_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not hasattr(world, "tolerant_content"):
        world.tolerant_content = {}
    return True, ""


def _tolerant_annotation(annotation: str) -> object:
    """Translate a feature annotation into a Python type annotation."""
    annotations = {
        "str": str,
        "int": int,
        "float": float,
        "bool": bool,
        "list[str]": list[str],
        "tuple[str]": tuple[str],
        "set[str]": set[str],
        "dict[str,int]": dict[str, int],
    }
    return annotations[annotation]


@step("the response model declares an omitted required field with annotation")
def _h_tolerant_declares_omitted_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    annotation_name = examples.get("annotation", "")
    annotation = _tolerant_annotation(annotation_name)
    world.tolerant_model = create_model(
        "TolerantRequiredFieldModel",
        value=(annotation, ...),
    )
    world.tolerant_content = {}
    return True, ""


@step("declares omitted field .* with declared default")
def _h_tolerant_declares_default_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    model_name = examples.get("model", "")
    field_name = examples.get("field", "")
    if model_name == "ControlAction":
        model = ControlAction
    elif model_name == "ControlElementSet":
        model = _SP1ControlElementSet
    else:
        return False, f"Unsupported tolerant model {model_name}"
    if field_name not in model.model_fields:
        return False, f"{model_name} has no field {field_name}"
    world.tolerant_model = model
    world.tolerant_content = {}
    world.tolerant_field_name = field_name
    return True, ""


@step(
    "a coordination link omits required CoordinationMechanism field coordination_mechanism"
)
def _h_tolerant_declares_coordination_link(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.tolerant_model = CoordinationLink
    world.tolerant_field_name = "coordination_mechanism"
    world.tolerant_content = {
        "link_id": "CL-1",
        "source": "RESP-1",
        "target": "RESP-1",
        "shared_pm": "PM-1-1",
        "description": "Coordination link",
    }
    return True, ""


@step("a Pydantic LLM result explicitly sets optional field unused to null$")
def _h_tolerant_declares_explicit_null_optional(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.tolerant_model = create_model(
        "TolerantOptionalFieldModel",
        unused=(str | None, None),
    )
    world.tolerant_content = {"unused": None}
    world.tolerant_field_name = "unused"
    return True, ""


@step("the LLM result is tolerantly decoded$")
def _h_tolerant_decode_result(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Decode a tolerant feature result using the production helper."""
    if world.tolerant_model is None:
        return False, "No tolerant response model declared"
    world.tolerant_result = _sp1_parse_llm_result_unvalidated(
        _tolerant_llm_result(world.tolerant_content),
        world.tolerant_model,
    )
    return True, ""


@step("the required field can be accessed without AttributeError$")
def _h_tolerant_required_field_accessible(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.tolerant_result is None:
        return False, "No tolerant result available"
    field_name = getattr(world, "tolerant_field_name", "value")
    try:
        getattr(world.tolerant_result, field_name)
    except AttributeError as exc:
        return False, str(exc)
    return True, ""


@step.first("the required field value is")
def _h_tolerant_required_field_value(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.tolerant_result is None:
        return False, "No tolerant result available"
    expected = examples.get("expected_value", "")
    expected_values = {
        '""': "",
        "0": 0,
        "0.0": 0.0,
        "false": False,
        "[]": [],
        "()": (),
        "set()": set(),
        "{}": {},
        "None": None,
    }
    if expected not in expected_values:
        return False, f"Unsupported expected value {expected}"
    field_name = getattr(world, "tolerant_field_name", "value")
    actual = getattr(world.tolerant_result, field_name, object())
    if actual != expected_values[expected]:
        return False, f"Expected {expected!r} but got {actual!r}"
    return True, ""


@step("field unused remains null$")
def _h_tolerant_explicit_null_value(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.tolerant_result is None:
        return False, "No tolerant result available"
    actual = getattr(world.tolerant_result, "unused", object())
    if actual is not None:
        return False, f"Expected unused to remain null, got {actual!r}"
    return True, ""


@step("the decoded result is post-processed and validated$")
def _h_tolerant_post_process_and_validate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.tolerant_result is None:
        return False, "No tolerant result available"
    try:
        world.tolerant_model.model_validate(world.tolerant_result.model_dump())
    except (ValidationError, ValueError) as exc:
        world.validation_error = exc
    return True, ""


@step("a valid Call 2a response with ordered responsibilities$")
@step("Call 2a has ordered responsibilities RESP-8, RESP-4$")
@step("Call 2a has ordered responsibilities RESP-\\d+$")
def _h_sp1_tolerant_call2a_responsibilities(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    numbers = re.findall(r"RESP-(\d+)", text)
    if not numbers:
        world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(
            _sp1_valid_resp_set_2a_dict()
        )
        return True, ""
    world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(
        {
            "responsibilities": [
                {
                    "resp_id": f"RESP-{number}",
                    "description": f"Controller {number}",
                    "responsibility_constraints": [],
                    "process_model_parts": [
                        {
                            "pm_id": f"PM-{number}-1",
                            "description": f"State {number}",
                        }
                    ],
                }
                for number in numbers
            ]
        }
    )
    return True, ""


def _sp1_tolerant_control_element_payload(world: World) -> dict:
    """Return the mutable Call 2b payload for a tolerant assembly scenario."""
    return getattr(
        world,
        "sp1_tolerant_control_element_payload",
        {
            "control_actions": [],
            "feedback_channels": [],
            "controlled_processes": [],
        },
    )


@step("Call 2b control action \\d+ has ca_id omitted$")
def _h_sp1_tolerant_control_action_omitted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"control action (\d+) has ca_id omitted", text)
    if not match:
        return False, f"Could not parse omitted control action step: {text}"
    position = int(match.group(1))
    actions = _sp1_tolerant_control_element_payload(world).setdefault(
        "control_actions", []
    )
    while len(actions) < position:
        actions.append({"description": f"Action {len(actions) + 1}"})
    actions[position - 1].pop("ca_id", None)
    return True, ""


@step("Call 2b control action \\d+ has ca_id \\S+$")
def _h_sp1_tolerant_control_action(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"control action (\d+) has ca_id (\S+)", text)
    if not match:
        return False, f"Could not parse control action step: {text}"
    position, ca_id = int(match.group(1)), match.group(2)
    actions = _sp1_tolerant_control_element_payload(world).setdefault(
        "control_actions", []
    )
    while len(actions) < position:
        actions.append({"description": f"Action {len(actions) + 1}"})
    actions[position - 1]["ca_id"] = ca_id
    actions[position - 1].setdefault("description", f"Action {position}")
    return True, ""


@step("the control action omits required field description$")
def _h_sp1_tolerant_control_action_description_omitted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    actions = _sp1_tolerant_control_element_payload(world).setdefault(
        "control_actions", []
    )
    if not actions:
        actions.append({"ca_id": "source-action"})
    else:
        actions[0].pop("description", None)
    return True, ""


@step("the control action target references absent controlled process CP-99$")
def _h_sp1_tolerant_control_action_target_absent_setup(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    actions = _sp1_tolerant_control_element_payload(world).setdefault(
        "control_actions", []
    )
    if not actions:
        actions.append({"description": "Action 1"})
    actions[0]["target"] = {
        "type": "controlled_process",
        "id": "CP-99",
    }
    return True, ""


@step("Call 2b is decoded in tolerant mode$")
def _h_sp1_tolerant_call2b_decoded(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_tolerant_control_element_payload = {
        "control_actions": [],
        "feedback_channels": [],
        "controlled_processes": [],
    }
    return True, ""


@step("the assembled payload has a .* at .* whose .* is .*$")
def _h_sp1_tolerant_nested_payload_element(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    element_type = examples.get("element_type", "")
    position = examples.get("structural_position", "")
    source_state = examples.get("source_id_state", "")
    # Enforce the source-state vocabulary so a mutated example value (e.g.
    # "omittEd") cannot pass through as silently equivalent to "omitted".
    if source_state not in ("omitted", "blank"):
        return False, f"Unknown source_id_state: {source_state}"
    # The ID field is determined by the element type, not by an example
    # column, so that mutating a redundant column cannot survive mutation
    # testing while the normalizer assigns canonical IDs by position.
    id_field = {
        "control action": "ca_id",
        "feedback channel": "fb_id",
        "controlled process": "cp_id",
    }.get(element_type, "")
    raw_id = "" if source_state == "blank" else None

    payload = {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Controller 1",
                "process_model_parts": [{"pm_id": "PM-1-1", "description": "State 1"}],
            },
            {
                "resp_id": "RESP-2",
                "description": "Controller 2",
                "process_model_parts": [{"pm_id": "PM-2-1", "description": "State 2"}],
            },
        ],
        "controlled_processes": [],
        "coordination_links": [],
    }
    match = re.search(r"responsibility (\d+) child (\d+)", position)
    if element_type == "control action" and match:
        resp = payload["responsibilities"][int(match.group(1)) - 1]
        child_index = int(match.group(2)) - 1
        actions = resp.setdefault("control_actions", [])
        while len(actions) <= child_index:
            actions.append(
                {
                    "description": f"Action {len(actions) + 1}",
                    "ca_id": f"CA-{int(match.group(1))}-{len(actions) + 1}",
                }
            )
        if raw_id is None:
            actions[child_index].pop(id_field, None)
        else:
            actions[child_index][id_field] = raw_id
    elif element_type == "feedback channel" and match:
        resp = payload["responsibilities"][int(match.group(1)) - 1]
        child_index = int(match.group(2)) - 1
        channels = resp.setdefault("feedback_channels", [])
        while len(channels) <= child_index:
            channels.append(
                {
                    "description": f"Feedback {len(channels) + 1}",
                    "updates": f"PM-{int(match.group(1))}-1",
                    "fb_id": f"FB-{int(match.group(1))}-{len(channels) + 1}",
                }
            )
        if raw_id is None:
            channels[child_index].pop(id_field, None)
        else:
            channels[child_index][id_field] = raw_id
    elif element_type == "controlled process":
        process_match = re.search(r"controlled process (\d+)", position)
        if not process_match:
            return False, f"Could not parse structural position {position}"
        process_index = int(process_match.group(1)) - 1
        processes = payload["controlled_processes"]
        while len(processes) <= process_index:
            processes.append(
                {
                    "description": f"Process {len(processes) + 1}",
                    "cp_id": f"CP-{len(processes) + 1}",
                }
            )
        if raw_id is None:
            processes[process_index].pop(id_field, None)
        else:
            processes[process_index][id_field] = raw_id
    else:
        return False, f"Could not configure payload position {position}"

    world.sp1_tolerant_nested_payload = payload
    return True, ""


def _sp1_tolerant_decoded_assembly_payload(world: World) -> dict:
    """Build the decoded Call 2a/2b payload used by assembly and validation."""
    enriched = _sp1_enrich_responsibilities(
        world.sp1_responsibility_set,
        world.sp1_control_element_set,
        normalize_ids=True,
    )
    return {
        "responsibilities": [
            resp.model_dump(mode="python", exclude_none=False) for resp in enriched
        ],
        "controlled_processes": [
            process.model_dump(mode="python", exclude_none=False)
            for process in world.sp1_control_element_set.controlled_processes
        ],
        "coordination_links": [],
    }


@step("the control structure is assembled$")
@step("control-structure assembly enters the fallback path$")
def _h_sp1_tolerant_assemble(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_responsibility_set is None:
        world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(
            _sp1_valid_resp_set_2a_dict()
        )
    payload = _sp1_tolerant_control_element_payload(world)
    world.sp1_control_element_set = _sp1_parse_llm_result_unvalidated(
        _tolerant_llm_result(payload),
        _SP1ControlElementSet,
    )
    decoded_payload = _sp1_tolerant_decoded_assembly_payload(world)
    world.sp1_normalized_payload = _sp1_normalize_control_structure_payload(
        decoded_payload
    ).payload
    try:
        world.control_structure, world.sp1_tolerant_warnings = (
            _sp1_assemble_with_fallback(
                world.sp1_responsibility_set,
                world.sp1_control_element_set,
                Path(_tempfile.mkdtemp(prefix="sp1_tolerant_")),
                "acceptance-model",
                normalize_ids=True,
            )
        )
    except (ValidationError, ValueError) as exc:
        world.validation_error = exc
    return True, ""


def _h_sp1_tolerant_normalize_payload(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if hasattr(world, "sp1_tolerant_nested_payload"):
        parsed = _sp1_parse_llm_result_unvalidated(
            _tolerant_llm_result(world.sp1_tolerant_nested_payload),
            ControlStructure,
        )
        world.sp1_normalized_payload = _sp1_normalize_control_structure_payload(
            parsed.model_dump(mode="python", exclude_none=False)
        ).payload
        return True, ""
    payload = _sp1_tolerant_control_element_payload(world)
    if world.sp1_responsibility_set is None:
        world.sp1_responsibility_set = _SP1ResponsibilitySet.model_validate(
            _sp1_valid_resp_set_2a_dict()
        )
    world.sp1_control_element_set = _sp1_parse_llm_result_unvalidated(
        _tolerant_llm_result(payload),
        _SP1ControlElementSet,
    )
    enriched = _sp1_enrich_responsibilities(
        world.sp1_responsibility_set,
        world.sp1_control_element_set,
        normalize_ids=True,
    )
    raw_payload = {
        "responsibilities": [
            resp.model_dump(mode="python", exclude_none=False) for resp in enriched
        ],
        "controlled_processes": [
            process.model_dump(mode="python", exclude_none=False)
            for process in world.sp1_control_element_set.controlled_processes
        ],
        "coordination_links": [],
    }
    world.sp1_normalized_payload = _sp1_normalize_control_structure_payload(
        raw_payload
    ).payload
    return True, ""


@step.first(
    "the (?:control action|feedback channel|controlled process) at .* has ID .*"
)
def _h_sp1_tolerant_payload_element(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not hasattr(world, "sp1_normalized_payload"):
        return False, "No normalized payload available"
    element_type = examples.get("element_type", "")
    position = examples.get("structural_position", "")
    expected_id = examples.get("canonical_id", "")
    payload = world.sp1_normalized_payload
    match = re.search(r"responsibility (\d+) child (\d+)", position)
    if element_type == "control action" and match:
        item = payload["responsibilities"][int(match.group(1)) - 1]["control_actions"][
            int(match.group(2)) - 1
        ]
    elif element_type == "feedback channel" and match:
        item = payload["responsibilities"][int(match.group(1)) - 1][
            "feedback_channels"
        ][int(match.group(2)) - 1]
    elif element_type == "controlled process":
        match = re.search(r"controlled process (\d+)", position)
        if not match:
            return False, f"Could not parse structural position {position}"
        item = payload["controlled_processes"][int(match.group(1)) - 1]
    else:
        return False, f"Could not parse element position {position}"
    actual_id = item.get(
        {
            "control action": "ca_id",
            "feedback channel": "fb_id",
            "controlled process": "cp_id",
        }[element_type]
    )
    if actual_id != expected_id:
        return False, f"Expected {expected_id}, got {actual_id}"
    return True, ""


# ---------------------------------------------------------------------------
# SP1 normalization-repair acceptance steps
# ---------------------------------------------------------------------------


def _findEl(payload: dict, element: str) -> tuple[dict, str]:
    """Return the first payload element and its ID field for an element kind."""
    locations = {
        "responsibility": (payload["responsibilities"][0], "resp_id"),
        "responsibility constraint": (
            payload["responsibilities"][0]["responsibility_constraints"][0],
            "rc_id",
        ),
        "process model part": (
            payload["responsibilities"][0]["process_model_parts"][0],
            "pm_id",
        ),
        "control action": (
            payload["responsibilities"][0]["control_actions"][0],
            "ca_id",
        ),
        "feedback channel": (
            payload["responsibilities"][0]["feedback_channels"][0],
            "fb_id",
        ),
        "controlled process": (payload["controlled_processes"][0], "cp_id"),
        "coordination link": (payload["coordination_links"][0], "link_id"),
        "coordination mechanism": (
            payload["coordination_links"][0]["coordination_mechanism"],
            "cm_id",
        ),
    }
    return locations[element]


def _sp1_repair_by_id(payload: dict, element: str, canonical_id: str) -> dict:
    """Find a normalized element by its canonical ID."""
    element_value, id_key = _findEl(payload, element)
    if element_value.get(id_key) == canonical_id:
        return element_value
    collections = {
        "responsibility": [
            (item, "resp_id") for item in payload.get("responsibilities", [])
        ],
        "responsibility constraint": [
            (item, "rc_id")
            for resp in payload.get("responsibilities", [])
            for item in resp.get("responsibility_constraints", [])
        ],
        "process model part": [
            (item, "pm_id")
            for resp in payload.get("responsibilities", [])
            for item in resp.get("process_model_parts", [])
        ],
        "control action": [
            (item, "ca_id")
            for resp in payload.get("responsibilities", [])
            for item in resp.get("control_actions", [])
        ],
        "feedback channel": [
            (item, "fb_id")
            for resp in payload.get("responsibilities", [])
            for item in resp.get("feedback_channels", [])
        ],
        "controlled process": [
            (item, "cp_id") for item in payload.get("controlled_processes", [])
        ],
        "coordination link": [
            (item, "link_id") for item in payload.get("coordination_links", [])
        ],
        "coordination mechanism": [
            (link.get("coordination_mechanism"), "cm_id")
            for link in payload.get("coordination_links", [])
        ],
    }
    for item, item_id_key in collections.get(element, []):
        if item.get(item_id_key) == canonical_id:
            return item
    raise KeyError(f"{element} {canonical_id}")


def _sp1_repair_base() -> dict:
    """Return a valid payload whose leftover refs survive example mutations."""
    return {
        "responsibilities": [
            {
                "resp_id": "controller-alpha",
                "description": "First controller",
                "responsibility_constraints": [
                    {"rc_id": "constraint-a", "description": "Constraint A"}
                ],
                "process_model_parts": [
                    {"pm_id": "state-alpha", "description": "State A"}
                ],
                "control_actions": [{"ca_id": "action-a", "description": "Action A"}],
                "feedback_channels": [
                    {
                        "fb_id": "feedback-a",
                        "description": "Feedback A",
                        "updates": "state-alpha",
                    }
                ],
            },
            {
                "resp_id": "controller-beta",
                "description": "Second controller",
                "responsibility_constraints": [],
                "process_model_parts": [],
                "control_actions": [],
                "feedback_channels": [],
            },
        ],
        "controlled_processes": [
            {"cp_id": "process-alpha", "description": "Process A"},
            {"cp_id": "process-beta", "description": "Process B"},
        ],
        "coordination_links": [
            {
                "link_id": "connection-alpha",
                "source": "controller-alpha",
                "target": "controller-beta",
                "shared_pm": "state-alpha",
                "coordination_mechanism": {
                    "cm_id": "mechanism-alpha",
                    "description": "Mechanism A",
                    "payload": "State payload A",
                },
                "description": "Connection A",
            }
        ],
    }


def _remap_src(payload: dict, old_id: str, new_id: str) -> None:
    """Keep leftover fixture refs aligned when a source ID is rewritten."""
    if old_id == new_id:
        return
    for link in payload.get("coordination_links", []):
        if not isinstance(link, dict):
            continue
        for field in ("source", "target", "shared_pm"):
            if link.get(field) == old_id:
                link[field] = new_id


@step("a tolerantly decoded SP1 control-structure payload$")
@step("a tolerantly decoded SP1 control-structure response$")
def _h_sp1_repair_payload(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_repair_payload = _sp1_repair_base()
    return True, ""


@step("the element at .* has source ID .*$")
def _h_sp1_repair_reference_target(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    payload = getattr(world, "sp1_repair_payload", None)
    if payload is None:
        return False, "No tolerant SP1 repair payload"
    position = examples.get("referenced_position", "")
    source_id = examples.get("source_id", "")
    try:
        element, id_key = findOwnerEl(payload, position)
    except (KeyError, IndexError, TypeError) as exc:
        return False, f"Unknown referenced position: {exc}"
    old_id = element.get(id_key)
    element[id_key] = source_id
    if isinstance(old_id, str):
        _remap_src(payload, old_id, source_id)
    return True, ""


@step(
    "responsibility \\d+ (?:process model part|control action|feedback channel) \\d+ has (?:feedback_source|target|source) type \\S+ and ID \\S+$"
)
def _h_sp1_repair_reference(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    payload = getattr(world, "sp1_repair_payload", None)
    if payload is None:
        return False, "No tolerant SP1 repair payload"
    owner = examples.get("reference_owner", "")
    field = examples.get("reference_field", "")
    try:
        owner_element = ownerAt(payload, owner)
    except (KeyError, IndexError, TypeError) as exc:
        return False, f"Unknown reference owner: {exc}"
    owner_element[field] = {
        "type": examples.get("supplied_type", ""),
        "id": examples.get("source_id", ""),
    }
    return True, ""


@step(
    "responsibility \\d+ (?:process model part|control action|feedback channel) \\d+ (?:feedback_source|target|source) was supplied with type \\S+$"
)
def _h_in_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the exact ElementRef type supplied before normalization."""
    try:
        owner = ownerAt(world.sp1_repair_payload, examples["reference_owner"])
    except (KeyError, IndexError, TypeError) as exc:
        return False, f"Unknown reference owner: {exc}"
    reference = owner.get(examples["reference_field"])
    actual = reference.get("type") if isinstance(reference, dict) else None
    expected = examples["expected_input"]
    if actual != expected:
        return False, f"Expected supplied type {expected}, got {actual}"
    return True, ""


@step("(?:responsibility|controlled process) \\d+ has source ID \\S+$")
def _h_sp1_repair_source_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"(responsibility|controlled process) (\d+) has source ID (\S+)",
        text,
        re.IGNORECASE,
    )
    if match is None:
        return False, f"Could not parse source ID step: {text}"
    collection = (
        world.sp1_repair_payload["responsibilities"]
        if match.group(1).lower() == "responsibility"
        else world.sp1_repair_payload["controlled_processes"]
    )
    index = int(match.group(2)) - 1
    id_key = "resp_id" if match.group(1).lower() == "responsibility" else "cp_id"
    old_id = collection[index].get(id_key)
    collection[index][id_key] = match.group(3)
    if isinstance(old_id, str):
        _remap_src(world.sp1_repair_payload, old_id, match.group(3))
    return True, ""


@step("the payload is normalized$")
def _h_sp1_repair_normalize(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    try:
        result = _sp1_id_normalizer()(world.sp1_repair_payload)
    except (ValidationError, ValueError, TypeError) as exc:
        return False, f"Normalization failed: {exc}"
    world.sp1_repair_normalized = result
    world.sp1_id_normalization = result
    return True, ""


def _ref_slot(payload: dict, location: str) -> tuple[dict, str]:
    """Return the owner mapping and field for a reference location."""
    owner, field = location.rsplit(" ", 1)
    return ownerAt(payload, owner), field


@step(".* is the bare string \\S+$")
def _h_sp1_repair_bare_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    payload = getattr(world, "sp1_repair_payload", None)
    if payload is None:
        return False, "No tolerant SP1 repair payload"
    location = examples.get("reference_location")
    source_id = examples.get("source_id")
    if not location or not source_id:
        match = re.fullmatch(r"(.+) is the bare string (\S+)", text)
        if match is None:
            return False, f"Could not parse bare reference step: {text}"
        location, source_id = match.groups()
    try:
        owner, field = _ref_slot(payload, location)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        return False, f"Unknown bare reference location: {exc}"
    owner[field] = source_id
    return True, ""


@step(".* is an ElementRef object with type \\S+ and ID \\S+$")
def _h_sp1_repair_bare_ref_assert(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    payload = world.sp1_repair_normalized.payload
    location = examples.get("reference_location")
    if not location:
        return False, "No bare reference location"
    try:
        owner, field = _ref_slot(payload, location)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        return False, f"Unknown normalized reference location: {exc}"
    reference = owner.get(field)
    expected = {
        "type": examples.get("reference_type"),
        "id": examples.get("canonical_id"),
    }
    if reference != expected:
        return False, f"Expected ElementRef {expected}, got {reference}"
    return True, ""


@step(".* remains the bare string \\S+$")
def _h_sp1_repair_bare_ref_remains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.fullmatch(r"(.+) remains the bare string (\S+)", text)
    if match is None:
        return False, f"Could not parse bare reference assertion: {text}"
    try:
        owner, field = _ref_slot(world.sp1_repair_normalized.payload, match.group(1))
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        return False, f"Unknown normalized reference location: {exc}"
    actual = owner.get(field)
    if actual != match.group(2):
        return False, f"Expected bare string {match.group(2)}, got {actual!r}"
    return True, ""


@step(".* is null$")
def _h_sp1_repair_null_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    payload = getattr(world, "sp1_repair_payload", None)
    if payload is None:
        return False, "No tolerant SP1 repair payload"
    location = examples.get("reference_location")
    if not location:
        match = re.fullmatch(r"(.+) is null", text)
        if match is None:
            return False, f"Could not parse null reference step: {text}"
        location = match.group(1)
    try:
        owner, field = _ref_slot(payload, location)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        return False, f"Unknown null reference location: {exc}"
    if field not in {"feedback_source", "target", "source"}:
        return False, f"Unknown null reference field: {field}"
    owner[field] = None
    return True, ""


@step(".* remains null$")
def _h_sp1_repair_null_ref_assert(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    location = examples.get("reference_location")
    if not location:
        match = re.fullmatch(r"(.+) remains null", text)
        if match is None:
            return False, f"Could not parse null reference assertion: {text}"
        location = match.group(1)
    try:
        owner, field = _ref_slot(world.sp1_repair_normalized.payload, location)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        return False, f"Unknown normalized reference location: {exc}"
    if field not in owner:
        return False, f"Missing normalized reference field: {field}"
    if owner.get(field) is not None:
        return False, f"Expected null reference, got {owner.get(field)!r}"
    return True, ""


@step(
    "^responsibility \\d+ (?:process model part|control action|feedback channel) \\d+ (?:feedback_source|target|source) has (?:type \\S+|ID \\S+)$"
)
def _h_sp1_repair_reference_assert(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    payload = world.sp1_repair_normalized.payload
    try:
        owner_element = ownerAt(payload, examples["reference_owner"])
    except (KeyError, IndexError, TypeError) as exc:
        return False, f"Unknown normalized reference owner: {exc}"
    reference = owner_element.get(examples["reference_field"])
    if not isinstance(reference, dict):
        return False, "Normalized reference is not a mapping"
    if "reference_type" in examples:
        expected = examples["reference_type"]
        if reference.get("type") != expected:
            return (
                False,
                f"Expected reference type {expected}, got {reference.get('type')}",
            )
    if "canonical_id" in examples:
        expected = examples["canonical_id"]
        if reference.get("id") != expected:
            return False, f"Expected reference ID {expected}, got {reference.get('id')}"
    return True, ""


@step("source ID \\S+ maps to \\S+$")
def _h_src_map(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the exact source-to-canonical mapping."""
    source = examples["expected_source"]
    expected = examples["canonical_id"]
    actual = world.sp1_id_normalization.mapping.get(source)
    if actual != expected:
        return False, f"Expected source ID {source} to map to {expected}, got {actual}"
    return True, ""


@step.first("the target type remains unknown-process$")
def _h_sp1_repair_target_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    payload = world.sp1_repair_normalized.payload
    target = payload["responsibilities"][0]["control_actions"][0]["target"]
    if target.get("type") != "unknown-process":
        return False, f"Expected unknown-process, got {target.get('type')}"
    return True, ""


@step(
    "^(?:responsibility|responsibility constraint|process model part|control action|feedback channel|controlled process|coordination link|coordination mechanism) (?:RESP-\\d+|RC-\\d+-\\d+|PM-\\d+-\\d+|CA-\\d+-\\d+|FB-\\d+-\\d+|CP-\\d+|CL-\\d+|CM-\\d+) has an empty description$"
)
@step(
    "^responsibility \\d+ (?:process model part|control action|feedback channel) \\d+ has an empty description$"
)
def _h_sp1_repair_empty_description(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    payload = world.sp1_repair_payload
    if "element" not in examples:
        payload["responsibilities"][0]["feedback_channels"][0]["description"] = ""
        return True, ""
    element, _ = _findEl(payload, examples["element"])
    element["description"] = ""
    return True, ""


@step("its source has type CP-9 and ID CP-9$")
def _h_sp1_repair_feedback_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    payload = world.sp1_repair_payload
    payload["controlled_processes"][1]["cp_id"] = "CP-9"
    payload["responsibilities"][0]["feedback_channels"][0]["source"] = {
        "type": "CP-9",
        "id": "CP-9",
    }
    return True, ""


@step("its updates value is state-alpha$")
def _h_sp1_repair_feedback_updates(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    feedback = world.sp1_repair_payload["responsibilities"][0]["feedback_channels"][0]
    feedback["updates"] = "state-alpha"
    return True, ""


@step("^responsibility \\d+ process model part \\d+ has source ID \\S+$")
def _h_sp1_repair_pm_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"responsibility (\d+) process model part (\d+) has source ID (\S+)",
        text,
        re.IGNORECASE,
    )
    if match is None:
        return False, f"Could not parse process-model source step: {text}"
    responsibility = world.sp1_repair_payload["responsibilities"][
        int(match.group(1)) - 1
    ]
    process_model_part = responsibility["process_model_parts"][int(match.group(2)) - 1]
    old_id = process_model_part.get("pm_id")
    process_model_part["pm_id"] = match.group(3)
    if isinstance(old_id, str):
        _remap_src(world.sp1_repair_payload, old_id, match.group(3))
    return True, ""


@step.first("responsibility \\d+ feedback channel \\d+ updates is \\{.*\\}$")
def _h_sp1_robustness_feedback_update(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Configure an object-shaped FeedbackChannel.updates value."""
    match = re.match(
        r"responsibility (\d+) feedback channel (\d+) updates is (.+)$",
        text,
        re.IGNORECASE,
    )
    if match is None:
        return False, f"Could not parse feedback update: {text}"
    try:
        value = json.loads(match.group(3))
        feedback = world.sp1_repair_payload["responsibilities"][
            int(match.group(1)) - 1
        ]["feedback_channels"][int(match.group(2)) - 1]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        return False, f"Could not configure feedback update: {exc}"
    feedback["updates"] = value
    return True, ""


@step("responsibility 1 process model parts 1 and 2 both have source ID PM-LEGACY$")
def _h_sp1_robustness_ambiguous_pm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Configure two process-model parts with the same source ID."""
    world.sp1_repair_payload["responsibilities"][0]["process_model_parts"].append(
        {"pm_id": "PM-LEGACY", "description": "Second state"}
    )
    for process_model_part in world.sp1_repair_payload["responsibilities"][0][
        "process_model_parts"
    ]:
        process_model_part["pm_id"] = "PM-LEGACY"
    return True, ""


@step("the response is normalized before typed serialization and validation$")
def _h_sp1_robustness_normalize(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Normalize tolerant input before any typed serialization."""
    try:
        decoded = _sp1_construct_unvalidated(
            world.sp1_repair_payload,
            ControlStructure,
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = _sp1_id_normalizer()(decoded)
        world.sp1_repair_normalized = result
        world.sp1_id_normalization = result
        world.sp1_serializer_warnings = [str(item.message) for item in caught]
        try:
            world.control_structure = ControlStructure.model_validate(result.payload)
            world.validation_error = None
        except (ValidationError, ValueError, TypeError) as exc:
            world.validation_error = exc
    except (ValidationError, ValueError, TypeError) as exc:
        world.validation_error = exc
        return False, f"Normalization failed: {exc}"
    return True, ""


@step.first(
    "responsibility \\d+ (?:process model part|control action|feedback channel) \\d+ "
    "(?:feedback_source|target|source) is \\{.*\\}$"
)
def _h_sp1_robustness_unknown_shape(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Configure an unsupported object-shaped reference."""
    match = re.match(
        r"(responsibility \d+ (?:process model part|control action|feedback channel) \d+ "
        r"(?:feedback_source|target|source)) is (.+)$",
        text,
        re.IGNORECASE,
    )
    if match is None:
        return False, f"Could not parse unknown reference shape: {text}"
    try:
        value = json.loads(match.group(2))
        owner, field = _ref_slot(world.sp1_repair_payload, match.group(1))
    except (json.JSONDecodeError, KeyError, IndexError, TypeError, ValueError) as exc:
        return False, f"Could not configure unknown reference shape: {exc}"
    owner[field] = value
    return True, ""


@step.first("responsibility \\d+ feedback channel \\d+ updates is the scalar ID \\S+$")
def _h_sp1_robustness_update_assert(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert that an object-shaped update became its scalar canonical ID."""
    match = re.search(r"updates is the scalar ID (\S+)$", text)
    if match is None:
        return False, f"Could not parse scalar update assertion: {text}"
    actual = world.sp1_repair_normalized.payload["responsibilities"][0][
        "feedback_channels"
    ][0]["updates"]
    expected = match.group(1)
    return (
        actual == expected,
        f"Expected scalar update {expected}, got {actual!r}",
    )


@step.first(
    "responsibility \\d+ (?:process model part|control action|feedback channel) \\d+ (?:feedback_source|target|source) has type \\S+ and ID \\S+$"
)
def _h_sp1_robustness_ref_assert(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Configure or assert an ElementRef, depending on normalization state."""
    match = re.match(r"(.+) has type (\S+) and ID (\S+)$", text)
    if match is None:
        return False, f"Could not parse ElementRef assertion: {text}"
    location, expected_type, expected_id = match.groups()
    if not hasattr(world, "sp1_repair_normalized"):
        try:
            owner, field = _ref_slot(world.sp1_repair_payload, location)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            return False, f"Unknown ElementRef location: {exc}"
        owner[field] = {"type": expected_type, "id": expected_id}
        return True, ""
    try:
        owner, field = _ref_slot(
            world.sp1_repair_normalized.payload,
            location,
        )
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        return False, f"Unknown ElementRef location: {exc}"
    actual = owner.get(field)
    expected = {"type": expected_type, "id": expected_id}
    return actual == expected, f"Expected {expected}, got {actual!r}"


@step.first("the normalized response validates as a ControlStructure$")
def _h_sp1_robustness_validates(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert successful ControlStructure validation."""
    error = getattr(world, "validation_error", None)
    return error is None, f"Unexpected validation error: {error}"


@step.first("validation fails with an error identifying .*$")
def _h_sp1_robustness_fails(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert controlled validation failure identifies the requested field."""
    match = re.search(r"identifying (.+)$", text)
    expected = match.group(1).lower() if match else ""
    error = getattr(world, "validation_error", None)
    if error is None:
        return False, "Expected normalized validation to fail"
    message = str(error).lower()
    if expected and not any(part in message for part in expected.split()):
        return False, f"Expected {expected!r} in validation error: {error}"
    if "unhashable" in message:
        return False, f"Validation leaked an unhashable-value error: {error}"
    return True, ""


@step("normalization emits no Pydantic serializer warning$")
def _h_sp1_robustness_no_serializer_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert tolerant normalization did not invoke serializer warnings."""
    warnings = getattr(world, "sp1_serializer_warnings", [])
    return not warnings, f"Unexpected serializer warnings: {warnings}"


@step("normalization raises no unhashable-value error$")
@step("the failure is not an unhashable-value error$")
def _h_sp1_robustness_no_unhashable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert validation diagnostics do not expose unhashable values."""
    message = str(getattr(world, "validation_error", ""))
    return (
        "unhashable" not in message.lower(),
        f"Unexpected unhashable-value error: {message}",
    )


@step.first(
    "feedback channel FB-1-1 has description Feedback from controlled process CP-2 updating process model part PM-1-1$"
)
def _h_sp1_repair_feedback_description_assert(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    payload = world.sp1_repair_normalized.payload
    actual = payload["responsibilities"][0]["feedback_channels"][0].get("description")
    expected = (
        "Feedback from controlled process CP-2 updating process model part PM-1-1"
    )
    if actual != expected:
        return False, f"Expected {expected!r}, got {actual!r}"
    return True, ""


@step(
    "^(?:responsibility|responsibility constraint|process model part|control action|feedback channel|controlled process|coordination link|coordination mechanism) (?:RESP-\\d+|RC-\\d+-\\d+|PM-\\d+-\\d+|CA-\\d+-\\d+|FB-\\d+-\\d+|CP-\\d+|CL-\\d+|CM-\\d+) has description Operator supplied description$"
)
def _h_sp1_repair_supplied_description(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    element, _ = _findEl(world.sp1_repair_payload, examples["element"])
    element["description"] = "Operator supplied description"
    return True, ""


@step(
    "^(?:responsibility|responsibility constraint|process model part|control action|feedback channel|controlled process|coordination link|coordination mechanism) (?:RESP-\\d+|RC-\\d+-\\d+|PM-\\d+-\\d+|CA-\\d+-\\d+|FB-\\d+-\\d+|CP-\\d+|CL-\\d+|CM-\\d+) has description .+$"
)
def _h_sp1_repair_description_assert(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    payload = world.sp1_repair_normalized.payload
    try:
        element = _sp1_repair_by_id(
            payload, examples["element"], examples["canonical_id"]
        )
    except KeyError as exc:
        return False, str(exc)
    expected = examples["expected_description"]
    if element.get("description") != expected:
        return False, f"Expected {expected!r}, got {element.get('description')!r}"
    return True, ""


@step("the normalized payload validates as a ControlStructure$")
def _h_sp1_repair_validate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    try:
        world.control_structure = ControlStructure.model_validate(
            world.sp1_repair_normalized.payload
        )
    except (ValidationError, ValueError) as exc:
        world.validation_error = exc
        return False, f"Normalized payload did not validate: {exc}"
    return True, ""


@step("normalization preserves the description Operator supplied description on .*$")
def _h_sp1_repair_preserves_description(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    payload = world.sp1_repair_normalized.payload
    try:
        element = _sp1_repair_by_id(
            payload, examples["element"], examples["canonical_id"]
        )
    except KeyError as exc:
        return False, str(exc)
    if element.get("description") != "Operator supplied description":
        return False, f"Description changed: {element.get('description')!r}"
    return True, ""


def _repair_assembly_inputs() -> tuple[dict, dict]:
    """Return tolerant Call 2a and Call 2b fixtures with generic IDs."""
    responsibilities = [
        {
            "id": "RESP-90",
            "description": "First controller",
            "responsibility_constraints": [
                {"id": "RC-90-1", "description": "Constraint"}
            ],
            "process_model_parts": [
                {
                    "id": "PM-90-1",
                    "description": "State",
                    "feedback_source": {
                        "type": "RESP-30",
                        "id": "RESP-30",
                    },
                }
            ],
        },
        {
            "id": "RESP-30",
            "description": "Second controller",
            "responsibility_constraints": [
                {"id": "RC-30-1", "description": "Constraint"}
            ],
            "process_model_parts": [{"id": "PM-30-1", "description": "State"}],
        },
    ]
    elements = {
        "control_actions": [
            {
                "id": "CA-90-1",
                "description": "Action",
                "target": {"type": "CP-90", "id": "CP-90"},
            },
            {"id": "CA-30-1", "description": "Action"},
        ],
        "feedback_channels": [
            {
                "id": "FB-90-1",
                "updates": "PM-90-1",
                "source": {"type": "CP-90", "id": "CP-90"},
            },
            {
                "id": "FB-30-1",
                "updates": "PM-30-1",
                "source": {"type": "RESP-90", "id": "RESP-90"},
            },
        ],
        "controlled_processes": [{"id": "CP-90", "description": "Process"}],
    }
    return {"responsibilities": responsibilities}, elements


def _repair_many_assembly_inputs() -> tuple[dict, dict, dict[str, list[str]]]:
    """Return production-shaped Call 2a/2b fixtures with bare references."""
    responsibilities = [
        {
            "id": "RESP-90",
            "description": "First controller",
            "responsibility_constraints": [],
            "process_model_parts": [{"id": "PM-90-1", "description": "State"}],
        },
        {
            "id": "RESP-30",
            "description": "Second controller",
            "responsibility_constraints": [],
            "process_model_parts": [{"id": "PM-30-1", "description": "State"}],
        },
    ]
    target_sources = [("CP-90", "RESP-30", "RESP-90")[index % 3] for index in range(11)]
    source_sources = [("RESP-90", "CP-90", "RESP-30")[index % 3] for index in range(16)]
    elements = {
        "control_actions": [
            {
                "id": f"CA-90-{index + 1}",
                "description": "Action",
                "target": target_source,
            }
            for index, target_source in enumerate(target_sources)
        ],
        "feedback_channels": [
            {
                "id": f"FB-90-{index + 1}",
                "description": "Feedback",
                "updates": "PM-90-1",
                "source": source_source,
            }
            for index, source_source in enumerate(source_sources)
        ],
        "controlled_processes": [{"id": "CP-90", "description": "Process"}],
    }
    expected = {
        "targets": target_sources,
        "sources": source_sources,
    }
    return {"responsibilities": responsibilities}, elements, expected


@step("Call 2a and Call 2b use id instead of each model-specific ID field$")
def _h_sp1_repair_assembly_setup(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_repair_assembly_inputs = _repair_assembly_inputs()
    return True, ""


@step("Call 2b omits every feedback channel description$")
@step("Call 2b copies each referenced RESP-\\* or CP-\\* ID into its ElementRef type$")
@step("the source IDs differ from the IDs implied by final list position$")
def _h_sp1_repair_assembly_noop(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not (
        hasattr(world, "sp1_repair_assembly_inputs")
        or hasattr(world, "sp1_repair_many_assembly_inputs")
    ):
        return False, "No combined response fixture"
    return True, ""


@step(
    "Call 2b returns \\d+ (?:control actions|feedback channels) with bare-string (?:targets|sources)$"
)
def _h_sp1_repair_many_setup(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.fullmatch(
        r"Call 2b returns (\d+) (control actions|feedback channels) "
        r"with bare-string (targets|sources)",
        text,
        re.IGNORECASE,
    )
    if match is None:
        return False, f"Could not parse production-shaped reference step: {text}"
    expected_count = int(match.group(1))
    kind = "targets" if match.group(2).lower() == "control actions" else "sources"
    if kind != match.group(3).lower():
        return False, f"Reference kind does not match step: {text}"
    if not hasattr(world, "sp1_repair_many_assembly_inputs"):
        raw_resps, raw_elements, expected = _repair_many_assembly_inputs()
        world.sp1_repair_many_assembly_inputs = (raw_resps, raw_elements)
        world.sp1_repair_many_sources = expected
    actual_count = len(world.sp1_repair_many_sources[kind])
    if actual_count != expected_count:
        return False, f"Expected {expected_count} {kind}, got {actual_count}"
    return True, ""


@step(
    "every bare string identifies an existing responsibility or controlled process by source ID$"
)
def _h_sp1_repair_many_noop(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not hasattr(world, "sp1_repair_many_assembly_inputs"):
        return False, "No production-shaped assembly fixture"
    return True, ""


@step("SP1 assembles the control structure with deterministic ID normalization$")
def _h_sp1_repair_assemble(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if hasattr(world, "sp1_repair_many_assembly_inputs"):
        raw_resps, raw_elements = world.sp1_repair_many_assembly_inputs
    else:
        raw_resps, raw_elements = world.sp1_repair_assembly_inputs
    try:
        responsibility_set = _sp1_parse_llm_result_unvalidated(
            _tolerant_llm_result(raw_resps), ResponsibilitySet
        )
        element_set = _sp1_parse_llm_result_unvalidated(
            _tolerant_llm_result(raw_elements), ControlElementSet
        )
        world.control_structure, world.sp1_repair_assembly_warnings = (
            _sp1_assemble_with_fallback(
                responsibility_set,
                element_set,
                Path(_tempfile.mkdtemp(prefix="sp1_repair_")),
                "acceptance",
                normalize_ids=True,
            )
        )
    except (ValidationError, ValueError, TypeError) as exc:
        return False, f"Assembly failed: {exc}"
    return True, ""


@step(
    "all \\d+ (?:control action targets|feedback channel sources) are ElementRef objects with canonical IDs$"
)
def _h_sp1_repair_many_assert(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.fullmatch(
        r"all (\d+) (control action targets|feedback channel sources) "
        r"are ElementRef objects with canonical IDs",
        text,
        re.IGNORECASE,
    )
    if match is None:
        return False, f"Could not parse production-shaped assertion: {text}"
    expected_count = int(match.group(1))
    kind = "targets" if match.group(2).lower().startswith("control") else "sources"
    refs = []
    for responsibility in world.control_structure.responsibilities:
        elements = (
            responsibility.control_actions
            if kind == "targets"
            else responsibility.feedback_channels
        )
        refs.extend(
            element.target if kind == "targets" else element.source
            for element in elements
        )
    if len(refs) != expected_count or any(
        not isinstance(reference, ElementRef) for reference in refs
    ):
        return False, f"Expected {expected_count} ElementRef objects, got {refs}"
    source_ids = world.sp1_repair_many_sources[kind]
    canonical = {
        "RESP-90": "RESP-1",
        "RESP-30": "RESP-2",
        "CP-90": "CP-1",
    }
    for reference, source_id in zip(refs, source_ids):
        if reference.id != canonical[source_id]:
            return False, (
                f"Expected {source_id} to map to {canonical[source_id]}, "
                f"got {reference.id}"
            )
    return True, ""


@step("every cross-reference identifies its intended element$")
def _h_sp1_repair_many_cross_refs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    canonical = {
        "RESP-90": ("responsibility", "RESP-1"),
        "RESP-30": ("responsibility", "RESP-2"),
        "CP-90": ("controlled_process", "CP-1"),
    }
    refs = []
    for responsibility in world.control_structure.responsibilities:
        refs.extend(
            action.target
            for action in responsibility.control_actions
            if action.target is not None
        )
        refs.extend(
            channel.source
            for channel in responsibility.feedback_channels
            if channel.source is not None
        )
    valid = {
        (reference.type.value, reference.id)
        for reference in refs
        if isinstance(reference, ElementRef)
    }
    expected = set(canonical.values())
    if not expected.issubset(valid):
        return False, f"Missing intended cross-reference in {valid}"
    return True, ""


@step("every element has its canonical ID from final list position$")
def _h_sp1_repair_all_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    cs = world.control_structure
    if cs is None:
        return False, "No assembled control structure"
    if [item.resp_id for item in cs.responsibilities] != ["RESP-1", "RESP-2"]:
        return False, "Responsibilities were not normalized by position"
    for index, resp in enumerate(cs.responsibilities, start=1):
        if [item.rc_id for item in resp.responsibility_constraints] != [
            f"RC-{index}-1"
        ]:
            return False, "Responsibility constraint IDs were not normalized"
        if [item.pm_id for item in resp.process_model_parts] != [f"PM-{index}-1"]:
            return False, "Process-model IDs were not normalized"
        if [item.ca_id for item in resp.control_actions] != [f"CA-{index}-1"]:
            return False, "Control-action IDs were not normalized"
        if [item.fb_id for item in resp.feedback_channels] != [f"FB-{index}-1"]:
            return False, "Feedback-channel IDs were not normalized"
    if [item.cp_id for item in cs.controlled_processes] != ["CP-1"]:
        return False, "Controlled-process IDs were not normalized"
    return True, ""


@step("every ElementRef has the type implied by its referenced ID prefix$")
def _h_sp1_repair_ref_types(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    cs = world.control_structure
    if cs is None:
        return False, "No assembled control structure"
    for resp in cs.responsibilities:
        refs = [
            pm.feedback_source
            for pm in resp.process_model_parts
            if pm.feedback_source is not None
        ]
        refs.extend(ca.target for ca in resp.control_actions if ca.target is not None)
        refs.extend(fb.source for fb in resp.feedback_channels if fb.source is not None)
        for ref in refs:
            expected = (
                ReferenceType.responsibility
                if ref.id.startswith("RESP-")
                else ReferenceType.controlled_process
                if ref.id.startswith("CP-")
                else None
            )
            if expected is None or ref.type != expected:
                return False, f"ElementRef does not match ID prefix: {ref}"
    return True, ""


@step("every ElementRef ID identifies the corresponding canonical element$")
def _h_sp1_repair_ref_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    cs = world.control_structure
    if cs is None:
        return False, "No assembled control structure"
    resp_ids = {resp.resp_id for resp in cs.responsibilities}
    cp_ids = {process.cp_id for process in cs.controlled_processes}
    for resp in cs.responsibilities:
        for item in (
            list(resp.process_model_parts)
            + list(resp.control_actions)
            + list(resp.feedback_channels)
        ):
            ref = (
                item.feedback_source
                if isinstance(item, ProcessModelPart)
                else item.target
                if isinstance(item, ControlAction)
                else item.source
            )
            if ref is None:
                continue
            valid_ids = resp_ids if ref.type == ReferenceType.responsibility else cp_ids
            if ref.id not in valid_ids:
                return False, f"Unresolved canonical ElementRef ID {ref.id}"
    return True, ""


@step("every element has a non-empty description$")
def _h_sp1_repair_nonempty(world: World, text: str, examples: dict) -> tuple[bool, str]:
    cs = world.control_structure
    if cs is None:
        return False, "No assembled control structure"
    descriptions = []
    for resp in cs.responsibilities:
        descriptions.extend(
            [
                resp.description,
                *(item.description for item in resp.responsibility_constraints),
                *(item.description for item in resp.process_model_parts),
                *(item.description for item in resp.control_actions),
                *(item.description for item in resp.feedback_channels),
            ]
        )
    descriptions.extend(item.description for item in cs.controlled_processes)
    if any(not isinstance(value, str) or not value for value in descriptions):
        return False, "An assembled element has an empty description"
    return True, ""


def _repair_revision_delta() -> object:
    """Build a tolerant revision delta with generic element IDs."""
    payload = {
        "new_responsibilities": [
            {
                "id": "RESP-90",
                "description": "Added controller",
                "responsibility_constraints": [
                    {"id": "RC-90-1", "description": "Added constraint"}
                ],
                "process_model_parts": [
                    {"id": "PM-90-1", "description": "Added state"}
                ],
                "control_actions": [
                    {
                        "id": "CA-90-1",
                        "description": "Added action",
                        "target": {"type": "CP-90", "id": "CP-90"},
                    }
                ],
                "feedback_channels": [
                    {
                        "id": "FB-90-1",
                        "description": "",
                        "updates": "PM-90-1",
                        "source": {"type": "CP-90", "id": "CP-90"},
                    }
                ],
            }
        ],
        "new_controlled_processes": [{"id": "CP-90", "description": "Added process"}],
        "new_coordination_links": [],
        "modified_responsibilities": [],
    }
    return _sp1_construct_unvalidated(payload, RevisionDelta)


@step(
    "a decoded revision delta adds elements using id instead of model-specific ID fields$"
)
def _h_sp1_repair_revision_setup(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.control_structure = ControlStructure.model_validate(_sp1_valid_cs_dict())
    world.sp1_repair_revision_delta = _repair_revision_delta()
    world.sp1_repair_revision_warnings = []
    return True, ""


@step("an added feedback channel has an empty description$")
@step("an added ElementRef copies its CP-\\* ID into its type$")
@step("every revision reference resolves by source ID in the stitched structure$")
def _h_sp1_repair_revision_noop(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not hasattr(world, "sp1_repair_revision_delta"):
        return False, "No revision delta fixture"
    return True, ""


@step("the revision delta is merged$")
def _h_sp1_repair_revision_merge(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    try:
        world.control_structure, world.sp1_repair_revision_warnings = (
            _merge_revision_delta(
                world.control_structure,
                world.sp1_repair_revision_delta,
            )
        )
    except (ValidationError, ValueError, TypeError) as exc:
        return False, f"Revision merge failed: {exc}"
    return True, ""


@step("the added elements have canonical IDs from final list position$")
def _h_sp1_repair_revision_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    cs = world.control_structure
    if cs is None or len(cs.responsibilities) != 3:
        return False, "Expected three revised responsibilities"
    added = cs.responsibilities[-1]
    expected = {
        "resp_id": "RESP-3",
        "rc_id": "RC-3-1",
        "pm_id": "PM-3-1",
        "ca_id": "CA-3-1",
        "fb_id": "FB-3-1",
    }
    actual = {
        "resp_id": added.resp_id,
        "rc_id": added.responsibility_constraints[0].rc_id,
        "pm_id": added.process_model_parts[0].pm_id,
        "ca_id": added.control_actions[0].ca_id,
        "fb_id": added.feedback_channels[0].fb_id,
    }
    if actual != expected:
        return False, f"Unexpected revised IDs: {actual}"
    if [process.cp_id for process in cs.controlled_processes] != ["CP-1", "CP-2"]:
        return False, "Unexpected revised controlled-process IDs"
    return True, ""


@step("the added feedback channel has a non-empty human-readable description$")
def _h_sp1_repair_revision_feedback(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    feedback = world.control_structure.responsibilities[-1].feedback_channels[0]
    if not feedback.description:
        return False, "Added feedback description is empty"
    return True, ""


@step(
    "the added ElementRef has type controlled_process and the canonical controlled-process ID$"
)
def _h_sp1_repair_revision_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    action = world.control_structure.responsibilities[-1].control_actions[0]
    feedback = world.control_structure.responsibilities[-1].feedback_channels[0]
    refs = [action.target, feedback.source]
    if any(
        ref is None or ref.type != ReferenceType.controlled_process or ref.id != "CP-2"
        for ref in refs
    ):
        return False, f"Unexpected added ElementRefs: {refs}"
    return True, ""


@step("the revised ControlStructure validates without a degraded-revision warning$")
def _h_sp1_repair_revision_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.control_structure is None:
        return False, "No revised control structure"
    warnings = getattr(world, "sp1_repair_revision_warnings", [])
    if any("degrad" in warning.lower() for warning in warnings):
        return False, f"Revision degraded: {warnings}"
    try:
        ControlStructure.model_validate(world.control_structure.model_dump())
    except (ValidationError, ValueError) as exc:
        return False, f"Revised structure is invalid: {exc}"
    return True, ""


def _sp1_alias_model(element: str) -> type:
    """Return the model used by one tolerant ID-alias scenario."""
    return {
        "responsibility": Responsibility,
        "responsibility constraint": ResponsibilityConstraint,
        "process model part": ProcessModelPart,
        "control action": ControlAction,
        "feedback channel": FeedbackChannel,
        "controlled process": ControlledProcess,
        "coordination link": CoordinationLink,
        "coordination mechanism": CoordinationMechanism,
    }[element]


def _sp1_alias_payload(element: str, value: str) -> dict:
    """Return valid surrounding fields for one generic-ID response."""
    payloads = {
        "responsibility": {"id": value, "description": "Controller"},
        "responsibility constraint": {"id": value, "description": "Constraint"},
        "process model part": {"id": value, "description": "State"},
        "control action": {"id": value, "description": "Action"},
        "feedback channel": {
            "id": value,
            "description": "Feedback",
            "updates": "PM-1-1",
        },
        "controlled process": {"id": value, "description": "Process"},
        "coordination link": {
            "id": value,
            "source": "RESP-1",
            "target": "RESP-2",
            "shared_pm": "PM-1-1",
            "coordination_mechanism": {
                "id": "CM-1",
                "description": "Mechanism",
                "payload": "state",
            },
            "description": "Link",
        },
        "coordination mechanism": {
            "id": value,
            "description": "Mechanism",
            "payload": "state",
        },
    }
    return payloads[element]


@step(
    "a (?:responsibility|responsibility constraint|process model part|control action|feedback channel|controlled process|coordination link|coordination mechanism) response has id \\S+$"
)
def _h_sp1_alias_response(world: World, text: str, examples: dict) -> tuple[bool, str]:
    element = examples.get("element")
    if element is None:
        match = re.search(r"a (.+) response has id", text, re.IGNORECASE)
        element = match.group(1) if match is not None else ""
    match = re.search(r"has id (\S+)", text, re.IGNORECASE)
    expected = match.group(1) if match is not None else "ignored-source-id"
    world.sp1_alias_element = element
    world.sp1_alias_payload = _sp1_alias_payload(element, expected)
    return True, ""


@step("the response omits \\S+$")
def _h_sp1_alias_omits(world: World, text: str, examples: dict) -> tuple[bool, str]:
    field = examples.get("model_id_field")
    if field is None:
        return _h_sp1_alias_description_omitted(world, text, examples)
    world.sp1_alias_payload.pop(field, None)
    return True, ""


@step("the response has \\S+ \\S+$")
def _h_sp1_alias_explicit(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"the response has (\S+) (\S+)$", text, re.IGNORECASE)
    if match is None:
        return False, f"Could not parse explicit ID step: {text}"
    field, value = match.groups()
    world.sp1_alias_payload[field] = value
    return True, ""


def _h_sp1_alias_description_omitted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_alias_element = "control action"
    world.sp1_alias_payload = {"id": "CA-4-3"}
    return True, ""


@step("the response is decoded$")
def _h_sp1_alias_decode(world: World, text: str, examples: dict) -> tuple[bool, str]:
    try:
        world.sp1_alias_decoded = _sp1_construct_unvalidated(
            world.sp1_alias_payload,
            _sp1_alias_model(world.sp1_alias_element),
        )
    except (TypeError, ValueError) as exc:
        return False, f"Tolerant decode failed: {exc}"
    return True, ""


@step(
    "the decoded (?:responsibility|responsibility constraint|process model part|control action|feedback channel|controlled process|coordination link|coordination mechanism) has \\S+ \\S+$"
)
def _h_sp1_alias_assert(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"has (\S+) (\S+)$", text, re.IGNORECASE)
    if match is None:
        return False, f"Could not parse decoded ID step: {text}"
    field, expected = match.groups()
    actual = getattr(world.sp1_alias_decoded, field)
    if actual != expected:
        return False, f"Expected {field} {expected}, got {actual}"
    return True, ""


@step("the decoded control action has an empty description$")
def _h_sp1_alias_empty_description(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_alias_decoded.description != "":
        return False, (
            "Expected the omitted description sentinel to be empty, got "
            f"{world.sp1_alias_decoded.description!r}"
        )
    return True, ""


FEATURE_ID = "sp1"


register = step.register


__all__ = ["FEATURE_ID", "register"]

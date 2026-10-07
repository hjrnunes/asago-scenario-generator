"""Acceptance step handlers for the critic_revision_fix feature group."""

from __future__ import annotations

from runtime_shared import (
    Any,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    Path,
    SecurityConstraint,
    World,
    _FC_PROMPTS_DIR,
    _KNOWN_ELEMENT_DESCRIPTIONS,
    _SP1CriticFindings,
    _sp1_mock_llm,
    _SP1Stage1Profile,
    _VALID_CRITIC_STATUSES,
    _VALID_GAP_COUNTS,
    _set_element_description,
    _sp1_no_unjustified_critic_dict,
    _sp1_valid_cs_dict,
    _sp1_valid_stage1_profile_dict,
    _tempfile,
    re,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model.critic import (
    RevisionDelta as _FCRevisionDelta,
)
from asago_scenario_generator.stpa.system_model.critic import (
    _compute_next_ids as _fc_compute_next_ids,
)
from asago_scenario_generator.stpa.system_model.critic import (
    has_unjustified_gaps as _sp1_has_unjustified_gaps,
)
from asago_scenario_generator.stpa.system_model.critic import (
    run_completeness_critic as _sp1_run_critic,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings as _CF,
    CriticGap as _CG,
    REVISION_MAX_COMPLETION_TOKENS,
    _build_taxonomy_probes as _build_probes,
)
from registry import StepTable
from generic_steps import llm_raises, world_present

step = StepTable()


@step("the control structure has coordination links CL-1 with CM-1 and CL-2 with CM-2")
def _h_cmidup_cs_with_two_cls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.control_structure is None:
        world.control_structure = ControlStructure.model_validate(_sp1_valid_cs_dict())
    cs = world.control_structure
    world.control_structure = cs.model_copy(
        update={
            "coordination_links": [
                CoordinationLink(
                    link_id="CL-1",
                    source="RESP-1",
                    target="RESP-2",
                    shared_pm="PM-1-1",
                    coordination_mechanism=CoordinationMechanism(
                        cm_id="CM-1", description="Shared state", payload="Payload"
                    ),
                    description="Coordination link 1",
                ),
                CoordinationLink(
                    link_id="CL-2",
                    source="RESP-2",
                    target="RESP-1",
                    shared_pm="PM-2-1",
                    coordination_mechanism=CoordinationMechanism(
                        cm_id="CM-2", description="Shared state 2", payload="Payload 2"
                    ),
                    description="Coordination link 2",
                ),
            ],
        }
    )
    return True, ""


def _text_value(pattern: str, text: str, default: str) -> str:
    match = re.search(pattern, text)
    return match.group(1) if match else default


def _coordination_link(
    link_id: str,
    cm_id: str,
    *,
    source: str,
    target: str,
    shared_pm: str,
    payload: str,
    description: str,
) -> dict[str, Any]:
    return {
        "link_id": link_id,
        "source": source,
        "target": target,
        "shared_pm": shared_pm,
        "coordination_mechanism": {
            "cm_id": cm_id,
            "description": "Shared state",
            "payload": payload,
        },
        "description": description,
    }


@step.first(
    "an LLM that returns a RevisionDelta with new_coordination_links containing CL-\\d+ whose cm_id is"
)
def _h_cmidup_llm_delta_with_new_cls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that returns a RevisionDelta with new_coordination_links containing CL-X whose cm_id is CM-Y.

    Also handles variants with source, target, shared_pm, description, and payload.
    """
    client = world.sp1_mock_client or _sp1_mock_llm()
    world.sp1_mock_client = client
    m_link = re.search(r"containing (CL-\d+) whose cm_id is (CM-\d+)", text)
    if not m_link:
        return False, f"Could not parse link_id/cm_id from: {text}"
    link_id, cm_id = m_link.group(1), m_link.group(2)
    new_links = [
        _coordination_link(
            link_id,
            cm_id,
            source=_text_value(r"source (RESP-\d+)", text, "RESP-1"),
            target=_text_value(r"target (RESP-\d+)", text, "RESP-2"),
            shared_pm=_text_value(r"shared_pm (PM-\d+-\d+)", text, "PM-1-1"),
            payload=_text_value(r'payload "([^"]+)"', text, "sync"),
            description=_text_value(
                r'description "([^"]+)"', text, "shared validation"
            ),
        )
    ]
    # Check for a second new link (CmDedup-06)
    m_link2 = re.search(
        r"and (CL-\d+) whose cm_id is (CM-\d+)",
        text[text.index(link_id) + len(link_id) :],
    )
    if m_link2:
        new_links.append(
            _coordination_link(
                m_link2.group(1),
                m_link2.group(2),
                source="RESP-2",
                target="RESP-1",
                shared_pm="PM-2-1",
                payload="Payload 2",
                description="Coordination link 2",
            )
        )

    delta_dict: dict[str, Any] = {"new_coordination_links": new_links}
    client.set_response_for(_FCRevisionDelta, delta_dict)
    return True, ""


@step("the final control structure has no duplicate cm_id values")
def _h_cmidup_no_duplicate_cm_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    cm_ids = [cl.coordination_mechanism.cm_id for cl in cs.coordination_links]
    if len(cm_ids) != len(set(cm_ids)):
        return False, f"Duplicate cm_ids found: {cm_ids}"
    return True, ""


@step("the warnings list includes a warning that mentions")
def _h_cmidup_warning_mentions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    # Try quoted text first, then fall back to single token
    quoted = re.search(r'includes a warning that mentions "([^"]+)"', text)
    if quoted:
        token = quoted.group(1)
    else:
        m = re.search(r"includes a warning that mentions (\S+)", text)
        if not m:
            return False, f"Could not parse from: {text}"
        token = m.group(1)
    warnings = world.sp1_post_revision_warnings or []
    wtext = " ".join(warnings)
    if token not in wtext:
        return False, f"Expected warnings to mention '{token}' but got: {wtext}"
    return True, ""


@step("the returned ControlStructure is the pre-revision control structure")
def _h_cmidup_pre_revision_cs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    # The degradation guard returns the pre-revision CS, so RESP-3 should
    # NOT be present (it was in the delta but rejected).
    resp_ids = {r.resp_id for r in cs.responsibilities}
    if "RESP-3" in resp_ids:
        return (
            False,
            "Expected pre-revision CS but RESP-3 is present (merge was applied)",
        )
    return True, ""


@step("CriticFindings whose checklist_results are")
def _h_crf_critic_findings_checklist(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: CriticFindings whose checklist_results are <statuses>.

    Builds (or updates) a CriticFindings model with the specified
    checklist result statuses.  When the text is 'none', an empty
    dict is used.
    """
    m = re.search(r"checklist_results are (.+)", text)
    if not m:
        return False, f"Could not parse checklist statuses from: {text}"
    raw = m.group(1).strip()
    if raw == "none":
        checklist: dict[str, str] = {}
    else:
        parts = [p.strip() for p in raw.split(",")]
        for p in parts:
            if p not in _VALID_CRITIC_STATUSES:
                return (
                    False,
                    f"Invalid checklist status '{p}' (expected one of {sorted(_VALID_CRITIC_STATUSES)} or 'none')",
                )
        checklist = {f"Checklist item {i + 1}": p for i, p in enumerate(parts)}
    # Preserve existing taxonomy/gaps if already set, otherwise start clean
    existing = world.sp1_critic_findings
    if existing is not None:
        world.sp1_critic_findings = _CF(
            gaps=existing.gaps,
            checklist_results=checklist,
            taxonomy_probe_results=existing.taxonomy_probe_results,
        )
    else:
        world.sp1_critic_findings = _CF(
            gaps=[],
            checklist_results=checklist,
            taxonomy_probe_results={},
        )
    return True, ""


@step("CriticFindings whose taxonomy_probe_results are")
def _h_crf_critic_findings_taxonomy(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    m = re.search(r"taxonomy_probe_results are (.+)", text)
    if not m:
        return False, f"Could not parse taxonomy statuses from: {text}"
    raw = m.group(1).strip()
    if raw == "none":
        taxonomy: dict[str, str] = {}
    else:
        parts = [p.strip() for p in raw.split(",")]
        for p in parts:
            if p not in _VALID_CRITIC_STATUSES:
                return (
                    False,
                    f"Invalid taxonomy status '{p}' (expected one of {sorted(_VALID_CRITIC_STATUSES)} or 'none')",
                )
        taxonomy = {f"Taxonomy probe {i + 1}": p for i, p in enumerate(parts)}
    existing = world.sp1_critic_findings
    if existing is not None:
        world.sp1_critic_findings = _CF(
            gaps=existing.gaps,
            checklist_results=existing.checklist_results,
            taxonomy_probe_results=taxonomy,
        )
    else:
        world.sp1_critic_findings = _CF(
            gaps=[],
            checklist_results={},
            taxonomy_probe_results=taxonomy,
        )
    return True, ""


@step("CriticFindings with \\d+ adversarial gaps")
def _h_crf_critic_findings_gaps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    m = re.search(r"with (\d+) adversarial gaps", text)
    if not m:
        return False, f"Could not parse gap count from: {text}"
    count = int(m.group(1))
    if count not in _VALID_GAP_COUNTS:
        return (
            False,
            f"Unexpected gap count {count} (expected one of {sorted(_VALID_GAP_COUNTS)})",
        )
    gaps = [
        _CG(
            gap_type="missing_responsibility",
            description=f"Adversarial gap {i + 1}",
            related_attack_path=f"Attack path {i + 1}",
            suggested_remedy="Add a control",
        )
        for i in range(count)
    ]
    existing = world.sp1_critic_findings
    if existing is not None:
        world.sp1_critic_findings = _CF(
            gaps=gaps,
            checklist_results=existing.checklist_results,
            taxonomy_probe_results=existing.taxonomy_probe_results,
        )
    else:
        world.sp1_critic_findings = _CF(
            gaps=gaps,
            checklist_results={},
            taxonomy_probe_results={},
        )
    return True, ""


@step("empty CriticFindings")
def _h_crf_empty_critic_findings(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_critic_findings = _CF()
    return True, ""


step.add(
    "an LLM whose critic call fails",
    llm_raises(_SP1CriticFindings, "Critic call failed"),
)


@step("a control structure whose \\S+ has the description")
def _h_crf_cs_element_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure whose <element_id> has the description "<desc>".

    Builds a valid CS with two responsibilities (RESP-1, RESP-2) and
    overrides the description of the specified nested element.
    """
    m = re.search(r'whose (\S+) has the description "([^"]+)"', text)
    if not m:
        return False, f"Could not parse element_id and description from: {text}"
    element_id, description = m.group(1), m.group(2)
    if element_id in _KNOWN_ELEMENT_DESCRIPTIONS:
        expected_desc = _KNOWN_ELEMENT_DESCRIPTIONS[element_id]
        if description != expected_desc:
            return (
                False,
                f"Description mismatch for {element_id}: expected '{expected_desc}', got '{description}'",
            )
    cs_dict = _sp1_valid_cs_dict()
    _set_element_description(cs_dict, element_id, description)
    world.control_structure = ControlStructure.model_validate(cs_dict)
    return True, ""


@step("a loss analysis containing loss L-1, hazard H-1, and security constraint SC-1")
def _h_crf_loss_analysis_l1_h1_sc1(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.loss_analysis = LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Unauthorised disclosure of customer records",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            ),
        ],
        use_case_losses=[],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="Retrieval returns records outside the session scope",
                related_losses=["L-1"],
            ),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Retrieval must be scoped to the active session",
                applies_when=[],
                related_hazards=["H-1"],
            ),
        ],
    )
    return True, ""


@step("no loss analysis is available")
def _h_crf_no_loss_analysis(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.loss_analysis = None
    return True, ""


@step("a coordination analysis warning")
def _h_crf_coord_warning(world: World, text: str, examples: dict) -> tuple[bool, str]:
    m = re.search(r'coordination analysis warning "([^"]+)"', text)
    if not m:
        return False, f"Could not parse warning text from: {text}"
    warning = m.group(1)
    if world.sp1_call3_warnings is None:
        world.sp1_call3_warnings = []
    world.sp1_call3_warnings.append(warning)
    return True, ""


@step("no coordination analysis warnings are available")
def _h_crf_no_coord_warnings(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.sp1_call3_warnings = None
    return True, ""


@step.first("the completeness critic is run with the loss analysis")
def _h_crf_critic_run_with_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_critic_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _sp1_mock_llm()
    world.sp1_mock_client = client
    content = world.sp1_llm_content
    if isinstance(content, dict):
        client.set_response_for(_SP1CriticFindings, content)
    else:
        client.set_response_for(_SP1CriticFindings, _sp1_no_unjustified_critic_dict())
    cs = world.control_structure
    if cs is None:
        cs = ControlStructure.model_validate(_sp1_valid_cs_dict())
        world.control_structure = cs
    profile = world.sp1_profile
    if profile is None:
        profile = _SP1Stage1Profile(
            **_sp1_valid_stage1_profile_dict()
        ).to_capability_profile()
    try:
        findings = _sp1_run_critic(
            llm_client=client,
            control_structure=cs,
            capability_profile=profile,
            use_case_text=world.sp1_use_case_text or "Test use case",
            run_dir=run_dir,
            temperature=0.4,
            loss_analysis=world.loss_analysis,
            call3_warnings=world.sp1_call3_warnings,
        )
        world.sp1_critic_findings = findings
    except Exception:
        world.sp1_critic_findings = _SP1CriticFindings()
    return True, ""


@step("the critic user prompt sent to the LLM contains")
def _h_crf_critic_prompt_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    prompt = client.calls[-1].user_prompt
    quoted = re.search(r'"([^"]+)"', text)
    if not quoted:
        return False, f"Could not extract quoted text from: {text}"
    expected = quoted.group(1)
    if expected not in prompt:
        snippet = prompt[:300]
        return (
            False,
            f"Expected '{expected}' in critic user prompt but not found. Start: {snippet}...",
        )
    return True, ""


@step("the SP1 orchestrator run\\.py is inspected")
def _h_crf_run_py_inspected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    run_py = _FC_PROMPTS_DIR.parent / "run.py"
    if not run_py.is_file():
        return False, f"run.py not found at {run_py}"
    world.sp1_run_py_source = run_py.read_text(encoding="utf-8")
    return True, ""


@step("the run_completeness_critic call in _run_stage_2_block passes")
def _h_crf_run_py_passes_arg(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_run_py_source is None:
        return False, "run.py source not loaded"
    m = re.search(r"passes the (\w+) argument", text)
    if not m:
        return False, f"Could not parse parameter name from: {text}"
    param_name = m.group(1)
    src = world.sp1_run_py_source
    # Find the run_completeness_critic call block
    idx = src.find("run_completeness_critic(")
    if idx == -1:
        return False, "run_completeness_critic call not found in run.py"
    # Extract a window around the call
    call_block = src[idx : idx + 500]
    if param_name not in call_block:
        return (
            False,
            f"Parameter '{param_name}' not found in run_completeness_critic call. Block: {call_block[:200]}",
        )
    return True, ""


@step("a RevisionDelta is constructed with no arguments")
def _h_crf_revision_delta_no_args(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.rev_delta = _FCRevisionDelta()
    return True, ""


@step("the RevisionDelta dismissed_gaps list is empty")
def _h_crf_revision_delta_empty_dismissed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.rev_delta is None:
        return False, "No RevisionDelta constructed"
    if world.rev_delta.dismissed_gaps:
        return (
            False,
            f"Expected empty dismissed_gaps but got: {world.rev_delta.dismissed_gaps}",
        )
    return True, ""


@step.first("the warnings list includes a dismissal warning")
def _h_crf_dismissal_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    warnings = world.sp1_post_revision_warnings or []
    if not any("dismiss" in w.lower() for w in warnings):
        return False, f"Expected a dismissal warning but got: {warnings}"
    return True, ""


@step.first("the warnings list does not include a dismissal warning")
def _h_crf_no_dismissal_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    warnings = world.sp1_post_revision_warnings or []
    if any("dismiss" in w.lower() for w in warnings):
        return False, f"Expected no dismissal warning but found one: {warnings}"
    return True, ""


@step("the next available ID numbers are computed")
def _h_crf_next_ids_computed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    cs = world.control_structure
    if cs is None:
        cs = ControlStructure.model_validate(_sp1_valid_cs_dict())
        world.control_structure = cs
    world.sp1_next_ids = _fc_compute_next_ids(cs)
    return True, ""


@step.first(
    "a control structure whose coordination links carry the coordination mechanisms"
)
def _h_crf_cs_with_cm_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    m = re.search(r"coordination mechanisms (.+)", text)
    if not m:
        return False, f"Could not parse CM IDs from: {text}"
    raw = m.group(1).strip()
    cs_dict = _sp1_valid_cs_dict()
    if raw == "none":
        cs_dict["coordination_links"] = []
    else:
        cm_ids = [c.strip() for c in raw.split(",")]
        for cm_id in cm_ids:
            if not re.match(r"^CM-\d+$", cm_id):
                return (
                    False,
                    f"Invalid CM ID '{cm_id}' (expected 'none' or CM-<number>)",
                )
        links = []
        for i, cm_id in enumerate(cm_ids):
            cl_id = f"CL-{i + 1}"
            links.append(
                {
                    "link_id": cl_id,
                    "source": "RESP-1",
                    "target": "RESP-2",
                    "shared_pm": "PM-1-1",
                    "coordination_mechanism": {
                        "cm_id": cm_id,
                        "description": f"Mechanism {cm_id}",
                        "payload": "data",
                    },
                    "description": f"Link {cl_id}",
                }
            )
        cs_dict["coordination_links"] = links
    world.control_structure = ControlStructure.model_validate(cs_dict)
    return True, ""


@step.first(
    "a control structure whose coordination link CL-\\d+ carries the coordination mechanism"
)
def _h_crf_cs_with_cl_cm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    m = re.search(
        r"coordination link (CL-\d+) carries the coordination mechanism (CM-\d+)", text
    )
    if not m:
        return False, f"Could not parse link_id and cm_id from: {text}"
    link_id, cm_id = m.group(1), m.group(2)
    cs_dict = _sp1_valid_cs_dict()
    cs_dict["coordination_links"] = [
        {
            "link_id": link_id,
            "source": "RESP-1",
            "target": "RESP-2",
            "shared_pm": "PM-1-1",
            "coordination_mechanism": {
                "cm_id": cm_id,
                "description": f"Mechanism {cm_id}",
                "payload": "data",
            },
            "description": f"Link {link_id}",
        }
    ]
    world.control_structure = ControlStructure.model_validate(cs_dict)
    return True, ""


@step("the computed next-ID mapping has a next_cm_num key")
def _h_crf_next_cm_key(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_next_ids is None:
        return False, "No next-ID mapping computed"
    if "next_cm_num" not in world.sp1_next_ids:
        return False, f"next_cm_num key not found in: {world.sp1_next_ids}"
    return True, ""


@step("next_cm_num is \\d+")
@step("next_cl_num is \\d+")
def _h_crf_next_id_value(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.sp1_next_ids is None:
        return False, "No next-ID mapping computed"
    m = re.search(r"(next_\w+) is (\d+)", text)
    if not m:
        return False, f"Could not parse key and value from: {text}"
    key, expected = m.group(1), int(m.group(2))
    if key not in world.sp1_next_ids:
        return False, f"Key '{key}' not found in: {world.sp1_next_ids}"
    actual = world.sp1_next_ids[key]
    if actual != expected:
        return False, f"Expected {key}={expected} but got {actual}"
    return True, ""


step.add(
    "the rendering succeeds",
    world_present(
        "template_rendered",
        "rev_rendered_system",
        message="No rendered text available — rendering may have failed",
    ),
)


@step.first("the rendered text does not contain an unrendered Jinja expression")
def _h_crf_no_unrendered_jinja(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    rendered = world.template_rendered or world.rev_rendered_system
    if rendered is None:
        return False, "No rendered text available"
    # Check for unrendered Jinja expressions ({{ ... }}) or tags ({% ... %})
    # Allow literal Jinja-like text in template source that is meant to be
    # shown as-is (e.g., in "ID format rules" sections).  The pattern we
    # check for is {{ variable }} that was NOT rendered — i.e., it still
    # has double curly braces with a variable name inside.
    if re.search(r"\{\{\s*\w+", rendered):
        return (
            False,
            f"Unrendered Jinja expression found in rendered text: {rendered[:200]}",
        )
    return True, ""


@step("a control structure whose \\S+ has no feedback source")
def _h_crf_cs_pm_no_feedback_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    cs_dict = _sp1_valid_cs_dict()
    # PM-1-1 already has no feedback_source in the default dict
    world.control_structure = ControlStructure.model_validate(cs_dict)
    return True, ""


@step("the critic module constant REVISION_MAX_COMPLETION_TOKENS equals")
def _h_crf_revision_max_tokens(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    m = re.search(r"REVISION_MAX_COMPLETION_TOKENS equals (\d+)", text)
    if not m:
        return False, f"Could not parse expected value from: {text}"
    expected = int(m.group(1))

    if REVISION_MAX_COMPLETION_TOKENS != expected:
        return (
            False,
            f"Expected REVISION_MAX_COMPLETION_TOKENS={expected} but got {REVISION_MAX_COMPLETION_TOKENS}",
        )
    return True, ""


@step("the revision succeeds without a truncation warning")
def _h_crf_revision_succeeds_no_truncation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not world.sp1_revised:
        return False, "Revision was not triggered"
    warnings = world.sp1_post_revision_warnings or []
    if any("truncat" in w.lower() or "LengthFinishReason" in w for w in warnings):
        return False, f"Expected no truncation warning but found: {warnings}"
    return True, ""


step.add(
    "an LLM whose revision call raises LengthFinishReasonError",
    llm_raises(_FCRevisionDelta, "LengthFinishReasonError"),
)


def _critic_calls(calls: list[Any]) -> list[Any]:
    """The critic requests, or every request that is not a RevisionDelta when none is typed."""
    typed = [c for c in calls if c.response_format is _SP1CriticFindings]
    return typed or [c for c in calls if c.response_format is not _FCRevisionDelta]


@step("the LLM complete call is made without a max_completion_tokens cap")
def _h_crf_llm_no_max_tokens_cap(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    critic_calls = _critic_calls(client.calls)
    if not critic_calls:
        return False, "No critic LLM calls found"
    capped = [c for c in critic_calls if c.max_completion_tokens is not None]
    if capped:
        return (
            False,
            f"Critic call has max_completion_tokens={capped[0].max_completion_tokens}",
        )
    return True, ""


@step("the critic user prompt is rendered")
def _h_crf_critic_user_prompt_rendered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    loader = TemplateLoader(_FC_PROMPTS_DIR)
    cs = world.control_structure
    if cs is None:
        cs = ControlStructure.model_validate(_sp1_valid_cs_dict())
    profile = world.sp1_profile
    if profile is None:
        profile = _SP1Stage1Profile(
            **_sp1_valid_stage1_profile_dict()
        ).to_capability_profile()
    taxonomy_probes = _build_probes(profile)
    world.template_rendered = loader.render_prompt(
        "critic_user.j2",
        use_case_text=world.sp1_use_case_text or "Test use case",
        control_structure=cs,
        capability_profile=profile,
        taxonomy_probes=taxonomy_probes,
        loss_analysis=world.loss_analysis,
        call3_warnings=world.sp1_call3_warnings,
    )
    return True, ""


@step.first(
    "the revision system prompt sent to the LLM contains a coordination mechanism"
)
def _h_crf_rev_system_prompt_has_cm_next(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    # Find the revision call (RevisionDelta as response_format)
    rev_calls = [c for c in client.calls if c.response_format is _FCRevisionDelta]
    if not rev_calls:
        return False, "No revision LLM calls found"
    system_prompt = rev_calls[-1].system_prompt
    # The rendered system prompt should contain "CM-" with a number
    # (from the "New coordination mechanisms: CM-{next_cm_num}" line)
    if not re.search(r"CM-\{?next_cm_num\}?|CM-\d", system_prompt):
        return (
            False,
            f"No coordination mechanism next number in system prompt. Start: {system_prompt[:200]}",
        )
    return True, ""


@step.first("revision is (?:not )?triggered")
def _h_crf_revision_outcome_exact(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: revision is triggered/not triggered with case-sensitive outcome matching.

    This handler is registered with _register_first so it takes priority
    over the older case-insensitive handlers.  It validates the exact
    outcome text (case-sensitive) to ensure Gherkin example-value
    mutations that dither the outcome string are detected.
    """
    m = re.search(r"revision is (.+)", text)
    if not m:
        return False, f"Could not parse revision outcome from: {text}"
    outcome = m.group(1).strip()
    if outcome == "triggered":
        if world.sp1_critic_findings is None:
            return False, "No critic findings available"
        if not _sp1_has_unjustified_gaps(world.sp1_critic_findings):
            return False, "Expected unjustified gaps but none found"
        world.sp1_revised = True
        return True, ""
    elif outcome == "not triggered":
        if world.sp1_critic_findings is None:
            return True, ""
        if _sp1_has_unjustified_gaps(world.sp1_critic_findings):
            return False, "Expected no unjustified gaps but found some"
        return True, ""
    else:
        return False, f"Unknown revision outcome (case-sensitive match): '{outcome}'"


@step.first("the warnings list includes an all-dismissed warning")
def _h_crf_all_dismissed_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the warnings list includes an all-dismissed warning.

    Checks for a warning containing the stable fragment "dismissed all
    findings", which distinguishes the all-dismissed/no-change warning
    from the per-dismissal warnings (which contain "dismissed finding").
    """
    warnings = world.sp1_post_revision_warnings or []
    if not any("dismissed all findings" in w for w in warnings):
        return False, f"Expected an all-dismissed warning but got: {warnings}"
    return True, ""


@step.first("the warnings list does not include an all-dismissed warning")
def _h_crf_no_all_dismissed_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    warnings = world.sp1_post_revision_warnings or []
    if any("dismissed all findings" in w for w in warnings):
        return False, f"Expected no all-dismissed warning but found one: {warnings}"
    return True, ""


@step.first("the warnings list includes exactly one all-dismissed warning")
def _h_crf_exactly_one_all_dismissed_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    warnings = world.sp1_post_revision_warnings or []
    count = sum(1 for w in warnings if "dismissed all findings" in w)
    if count != 1:
        return (
            False,
            f"Expected exactly 1 all-dismissed warning but found {count}: {warnings}",
        )
    return True, ""


FEATURE_ID = "critic_revision_fix"


register = step.register


__all__ = ["FEATURE_ID", "register"]

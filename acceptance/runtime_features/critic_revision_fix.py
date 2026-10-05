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
    TemplateLoader,
    World,
    _FCRevisionDelta,
    _FC_PROMPTS_DIR,
    _KNOWN_ELEMENT_DESCRIPTIONS,
    _SP1CriticFindings,
    _SP1MockLLM,
    _SP1Stage1Profile,
    _VALID_CRITIC_STATUSES,
    _VALID_GAP_COUNTS,
    _fc_compute_next_ids,
    _set_element_description,
    _sp1_has_unjustified_gaps,
    _sp1_no_unjustified_critic_dict,
    _sp1_run_critic,
    _sp1_valid_cs_dict,
    _sp1_valid_stage1_profile_dict,
    _tempfile,
    re,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings as _CF,
    CriticGap as _CG,
    REVISION_MAX_COMPLETION_TOKENS,
    _build_taxonomy_probes as _build_probes,
)


def _h_cmidup_cs_with_two_cls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the control structure has coordination links CL-1 with CM-1 and CL-2 with CM-2."""
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


def _h_cmidup_llm_delta_with_new_cls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that returns a RevisionDelta with new_coordination_links containing CL-X whose cm_id is CM-Y.

    Also handles variants with source, target, shared_pm, description, and payload.
    """
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    # Parse link_id and cm_id
    m_link = re.search(r"containing (CL-\d+) whose cm_id is (CM-\d+)", text)
    if not m_link:
        return False, f"Could not parse link_id/cm_id from: {text}"
    link_id = m_link.group(1)
    cm_id = m_link.group(2)
    # Parse optional attributes
    source = "RESP-1"
    m_src = re.search(r"source (RESP-\d+)", text)
    if m_src:
        source = m_src.group(1)
    target = "RESP-2"
    m_tgt = re.search(r"target (RESP-\d+)", text)
    if m_tgt:
        target = m_tgt.group(1)
    shared_pm = "PM-1-1"
    m_pm = re.search(r"shared_pm (PM-\d+-\d+)", text)
    if m_pm:
        shared_pm = m_pm.group(1)
    description = "shared validation"
    m_desc = re.search(r'description "([^"]+)"', text)
    if m_desc:
        description = m_desc.group(1)
    payload = "sync"
    m_payload = re.search(r'payload "([^"]+)"', text)
    if m_payload:
        payload = m_payload.group(1)

    new_links = [
        {
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
    ]
    # Check for a second new link (CmDedup-06)
    m_link2 = re.search(
        r"and (CL-\d+) whose cm_id is (CM-\d+)",
        text[text.index(link_id) + len(link_id) :],
    )
    if m_link2:
        link_id2 = m_link2.group(1)
        cm_id2 = m_link2.group(2)
        src2 = "RESP-2"
        tgt2 = "RESP-1"
        pm2 = "PM-2-1"
        new_links.append(
            {
                "link_id": link_id2,
                "source": src2,
                "target": tgt2,
                "shared_pm": pm2,
                "coordination_mechanism": {
                    "cm_id": cm_id2,
                    "description": "Shared state",
                    "payload": "Payload 2",
                },
                "description": "Coordination link 2",
            }
        )

    delta_dict: dict[str, Any] = {"new_coordination_links": new_links}
    client.set_response_for(_FCRevisionDelta, delta_dict)
    return True, ""


def _h_cmidup_llm_delta_validation_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that returns a RevisionDelta that causes a ValidationError during merge."""
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    # A new responsibility with duplicate pm_id causes ValidationError
    delta_dict: dict[str, Any] = {
        "new_responsibilities": [
            {
                "resp_id": "RESP-3",
                "description": "Dup PM",
                "process_model_parts": [{"pm_id": "PM-1-1", "description": "Dup"}],
                "control_actions": [{"ca_id": "CA-3-1", "description": "Act"}],
                "feedback_channels": [
                    {
                        "fb_id": "FB-3-1",
                        "description": "FB",
                        "updates": "missing-state",
                        "source": {"type": "responsibility", "id": "RESP-3"},
                    }
                ],
            }
        ]
    }
    client.set_response_for(_FCRevisionDelta, delta_dict)
    return True, ""


def _h_cmidup_llm_delta_dup_pm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that returns a RevisionDelta with new_responsibilities containing RESP-3 whose PM part has pm_id PM-1-1 which duplicates an existing PM."""
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    delta_dict: dict[str, Any] = {
        "new_responsibilities": [
            {
                "resp_id": "RESP-3",
                "description": "Dup PM",
                "process_model_parts": [{"pm_id": "PM-1-1", "description": "Dup"}],
                "control_actions": [{"ca_id": "CA-3-1", "description": "Act"}],
                "feedback_channels": [
                    {
                        "fb_id": "FB-3-1",
                        "description": "FB",
                        "updates": "missing-state",
                        "source": {"type": "responsibility", "id": "RESP-3"},
                    }
                ],
            }
        ]
    }
    client.set_response_for(_FCRevisionDelta, delta_dict)
    return True, ""


def _h_cmidup_cl_cm_id_not(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coordination link CL-X has a cm_id that is not CM-Y."""
    m = re.search(r"link (CL-\d+) has a cm_id that is not (CM-\d+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    link_id, cm_id = m.group(1), m.group(2)
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    cl = next((c for c in cs.coordination_links if c.link_id == link_id), None)
    if cl is None:
        return False, f"Coordination link {link_id} not found"
    if cl.coordination_mechanism.cm_id == cm_id:
        return False, f"Expected {link_id} cm_id to not be {cm_id} but it was"
    return True, ""


def _h_cmidup_cl_cm_id_is(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coordination link CL-X has cm_id CM-Y."""
    m = re.search(r"link (CL-\d+) has cm_id (CM-\d+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    link_id, cm_id = m.group(1), m.group(2)
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    cl = next((c for c in cs.coordination_links if c.link_id == link_id), None)
    if cl is None:
        return False, f"Coordination link {link_id} not found"
    if cl.coordination_mechanism.cm_id != cm_id:
        return (
            False,
            f"Expected {link_id} cm_id to be {cm_id} but got {cl.coordination_mechanism.cm_id}",
        )
    return True, ""


def _h_cmidup_cl_cm_id_format(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coordination link CL-X has a cm_id matching the format CM-N."""
    m = re.search(r"link (CL-\d+) has a cm_id matching the format CM-N", text)
    if not m:
        return False, f"Could not parse from: {text}"
    link_id = m.group(1)
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    cl = next((c for c in cs.coordination_links if c.link_id == link_id), None)
    if cl is None:
        return False, f"Coordination link {link_id} not found"
    if not re.match(r"^CM-\d+$", cl.coordination_mechanism.cm_id):
        return (
            False,
            f"Expected {link_id} cm_id to match CM-N but got {cl.coordination_mechanism.cm_id}",
        )
    return True, ""


def _h_cmidup_cl_cm_id_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coordination link CL-X has a cm_id matching the pattern ^CM-\\d+$."""
    m = re.search(r"link (CL-\d+) has a cm_id matching the pattern", text)
    if not m:
        return False, f"Could not parse from: {text}"
    link_id = m.group(1)
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    cl = next((c for c in cs.coordination_links if c.link_id == link_id), None)
    if cl is None:
        return False, f"Coordination link {link_id} not found"
    if not re.match(r"^CM-\d+$", cl.coordination_mechanism.cm_id):
        return (
            False,
            f"Expected {link_id} cm_id to match ^CM-\\d+$ but got {cl.coordination_mechanism.cm_id}",
        )
    return True, ""


def _h_cmidup_cl_cm_id_different(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coordination link CL-X has a cm_id different from CL-Y cm_id."""
    m = re.search(r"link (CL-\d+) has a cm_id different from (CL-\d+) cm_id", text)
    if not m:
        return False, f"Could not parse from: {text}"
    link_id1, link_id2 = m.group(1), m.group(2)
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    cl1 = next((c for c in cs.coordination_links if c.link_id == link_id1), None)
    cl2 = next((c for c in cs.coordination_links if c.link_id == link_id2), None)
    if cl1 is None:
        return False, f"Coordination link {link_id1} not found"
    if cl2 is None:
        return False, f"Coordination link {link_id2} not found"
    if cl1.coordination_mechanism.cm_id == cl2.coordination_mechanism.cm_id:
        return (
            False,
            f"Expected different cm_ids but both are {cl1.coordination_mechanism.cm_id}",
        )
    return True, ""


def _h_cmidup_cl_description(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coordination link CL-X has description "Y"."""
    m = re.search(r'link (CL-\d+) has description "([^"]+)"', text)
    if not m:
        return False, f"Could not parse from: {text}"
    link_id, description = m.group(1), m.group(2)
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    cl = next((c for c in cs.coordination_links if c.link_id == link_id), None)
    if cl is None:
        return False, f"Coordination link {link_id} not found"
    if cl.description != description:
        return (
            False,
            f"Expected {link_id} description '{description}' but got '{cl.description}'",
        )
    return True, ""


def _h_cmidup_cl_payload(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coordination link CL-X has coordination_mechanism payload "Y"."""
    m = re.search(r'link (CL-\d+) has coordination_mechanism payload "([^"]+)"', text)
    if not m:
        return False, f"Could not parse from: {text}"
    link_id, payload = m.group(1), m.group(2)
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    cl = next((c for c in cs.coordination_links if c.link_id == link_id), None)
    if cl is None:
        return False, f"Coordination link {link_id} not found"
    if cl.coordination_mechanism.payload != payload:
        return (
            False,
            f"Expected {link_id} payload '{payload}' but got '{cl.coordination_mechanism.payload}'",
        )
    return True, ""


def _h_cmidup_no_duplicate_cm_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the final control structure has no duplicate cm_id values."""
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    cm_ids = [cl.coordination_mechanism.cm_id for cl in cs.coordination_links]
    if len(cm_ids) != len(set(cm_ids)):
        return False, f"Duplicate cm_ids found: {cm_ids}"
    return True, ""


def _h_cmidup_warning_mentions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the warnings list includes a warning that mentions X (quoted or unquoted)."""
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


def _h_cmidup_degradation_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the warnings list includes a degradation warning."""
    warnings = world.sp1_post_revision_warnings or []
    if not any("degrad" in w.lower() for w in warnings):
        return False, f"Expected degradation warning but got: {warnings}"
    return True, ""


def _h_cmidup_no_renumber_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the warnings list does not include a renumber warning (for CM-X)."""
    warnings = world.sp1_post_revision_warnings or []
    m = re.search(r"for (CM-\d+)", text)
    if m:
        cm_id = m.group(1)
        renumber_warnings = [w for w in warnings if "Renumber" in w]
        if any(cm_id in w for w in renumber_warnings):
            return (
                False,
                f"Expected no renumber warning for {cm_id} but found one: {warnings}",
            )
    else:
        if any("Renumber" in w for w in warnings):
            return False, f"Expected no renumber warning but found: {warnings}"
    return True, ""


def _h_cmidup_no_degradation_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the warnings list does not include a degradation warning."""
    warnings = world.sp1_post_revision_warnings or []
    if any("degrad" in w.lower() for w in warnings):
        return False, f"Expected no degradation warning but found: {warnings}"
    return True, ""


def _h_cmidup_warning_mentioning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the warnings list includes a warning mentioning X."""
    m = re.search(r"includes a warning mentioning (.+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    fragment = m.group(1).strip()
    warnings = world.sp1_post_revision_warnings or []
    wtext = " ".join(warnings)
    # Special case: "the error type" means the warning should contain
    # an actual exception type name like ValidationError or ValueError.
    if fragment.lower() == "the error type":
        if "ValidationError" not in wtext and "ValueError" not in wtext:
            return False, f"Expected warnings to mention an error type but got: {wtext}"
        return True, ""
    if fragment.lower() not in wtext.lower():
        return False, f"Expected warnings to mention '{fragment}' but got: {wtext}"
    return True, ""


def _h_cmidup_pre_revision_cs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the returned ControlStructure is the pre-revision control structure."""
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


def _h_cmidup_returned_contains_resp(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the returned ControlStructure contains RESP-X."""
    m = re.search(r"contains (RESP-\d+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    resp_id = m.group(1)
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    resp_ids = {r.resp_id for r in cs.responsibilities}
    if resp_id not in resp_ids:
        return False, f"Expected {resp_id} in control structure but got: {resp_ids}"
    return True, ""


def _h_cmidup_returned_contains_cl(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the returned ControlStructure contains coordination link CL-X."""
    m = re.search(r"contains coordination link (CL-\d+)", text)
    if not m:
        return False, f"Could not parse from: {text}"
    link_id = m.group(1)
    cs = world.control_structure
    if cs is None:
        return False, "No control structure"
    cl_ids = {cl.link_id for cl in cs.coordination_links}
    if link_id not in cl_ids:
        return False, f"Expected {link_id} in control structure but got: {cl_ids}"
    return True, ""


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


def _h_crf_critic_findings_taxonomy(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: CriticFindings whose taxonomy_probe_results are <statuses>."""
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


def _h_crf_critic_findings_gaps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: CriticFindings with <N> adversarial gaps."""
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


def _h_crf_empty_critic_findings(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: empty CriticFindings."""
    world.sp1_critic_findings = _CF()
    return True, ""


def _h_crf_llm_critic_fails(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM whose critic call fails."""
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    client.set_exception_for(_SP1CriticFindings, RuntimeError("Critic call failed"))
    return True, ""


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


def _h_crf_loss_analysis_l1_h1_sc1(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a loss analysis containing loss L-1, hazard H-1, and security constraint SC-1."""
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


def _h_crf_no_loss_analysis(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: no loss analysis is available."""
    world.loss_analysis = None
    return True, ""


def _h_crf_coord_warning(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a coordination analysis warning "<text>"."""
    m = re.search(r'coordination analysis warning "([^"]+)"', text)
    if not m:
        return False, f"Could not parse warning text from: {text}"
    warning = m.group(1)
    if world.sp1_call3_warnings is None:
        world.sp1_call3_warnings = []
    world.sp1_call3_warnings.append(warning)
    return True, ""


def _h_crf_no_coord_warnings(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: no coordination analysis warnings are available."""
    world.sp1_call3_warnings = None
    return True, ""


def _h_crf_critic_run_with_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the completeness critic is run with the loss analysis and coordination warnings."""
    run_dir = world.sp1_run_dir or Path(_tempfile.mkdtemp(prefix="sp1_critic_"))
    world.sp1_run_dir = run_dir
    client = world.sp1_mock_client or _SP1MockLLM()
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


def _h_crf_critic_prompt_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the critic user prompt sent to the LLM contains "<text>"."""
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    prompt = client.calls[-1]["user_prompt"]
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


def _h_crf_run_py_inspected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP1 orchestrator run.py is inspected."""
    run_py = _FC_PROMPTS_DIR.parent / "run.py"
    if not run_py.is_file():
        return False, f"run.py not found at {run_py}"
    world.sp1_run_py_source = run_py.read_text(encoding="utf-8")
    return True, ""


def _h_crf_run_py_passes_arg(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run_completeness_critic call in _run_stage_2_block passes the <param> argument."""
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


def _h_crf_revision_delta_no_args(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a RevisionDelta is constructed with no arguments."""
    world.rev_delta = _FCRevisionDelta()
    return True, ""


def _h_crf_revision_delta_empty_dismissed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the RevisionDelta dismissed_gaps list is empty."""
    if world.rev_delta is None:
        return False, "No RevisionDelta constructed"
    if world.rev_delta.dismissed_gaps:
        return (
            False,
            f"Expected empty dismissed_gaps but got: {world.rev_delta.dismissed_gaps}",
        )
    return True, ""


def _h_crf_dismissal_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the warnings list includes a dismissal warning."""
    warnings = world.sp1_post_revision_warnings or []
    if not any("dismiss" in w.lower() for w in warnings):
        return False, f"Expected a dismissal warning but got: {warnings}"
    return True, ""


def _h_crf_no_dismissal_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the warnings list does not include a dismissal warning."""
    warnings = world.sp1_post_revision_warnings or []
    if any("dismiss" in w.lower() for w in warnings):
        return False, f"Expected no dismissal warning but found one: {warnings}"
    return True, ""


def _h_crf_next_ids_computed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the next available ID numbers are computed."""
    cs = world.control_structure
    if cs is None:
        cs = ControlStructure.model_validate(_sp1_valid_cs_dict())
        world.control_structure = cs
    world.sp1_next_ids = _fc_compute_next_ids(cs)
    return True, ""


def _h_crf_cs_with_cm_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure whose coordination links carry the coordination mechanisms <cm_ids>."""
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


def _h_crf_cs_with_cl_cm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure whose coordination link <link_id> carries the coordination mechanism <cm_id>."""
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


def _h_crf_next_cm_key(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the computed next-ID mapping has a next_cm_num key."""
    if world.sp1_next_ids is None:
        return False, "No next-ID mapping computed"
    if "next_cm_num" not in world.sp1_next_ids:
        return False, f"next_cm_num key not found in: {world.sp1_next_ids}"
    return True, ""


def _h_crf_next_id_value(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: next_cm_num is <N> or next_cl_num is <N>."""
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


def _h_crf_rendering_succeeds(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the rendering succeeds."""
    if world.template_rendered is None and world.rev_rendered_system is None:
        return False, "No rendered text available — rendering may have failed"
    return True, ""


def _h_crf_no_unrendered_jinja(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the rendered text does not contain an unrendered Jinja expression."""
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


def _h_crf_cs_pm_no_feedback_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure whose PM-1-1 has no feedback source."""
    cs_dict = _sp1_valid_cs_dict()
    # PM-1-1 already has no feedback_source in the default dict
    world.control_structure = ControlStructure.model_validate(cs_dict)
    return True, ""


def _h_crf_revision_max_tokens(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the critic module constant REVISION_MAX_COMPLETION_TOKENS equals <N>."""
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


def _h_crf_revision_succeeds_no_truncation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the revision succeeds without a truncation warning."""
    if not world.sp1_revised:
        return False, "Revision was not triggered"
    warnings = world.sp1_post_revision_warnings or []
    if any("truncat" in w.lower() or "LengthFinishReason" in w for w in warnings):
        return False, f"Expected no truncation warning but found: {warnings}"
    return True, ""


def _h_crf_llm_length_finish_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM whose revision call raises LengthFinishReasonError."""
    client = world.sp1_mock_client or _SP1MockLLM()
    world.sp1_mock_client = client
    client.set_exception_for(_FCRevisionDelta, RuntimeError("LengthFinishReasonError"))
    return True, ""


def _h_crf_llm_no_max_tokens_cap(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the LLM complete call is made without a max_completion_tokens cap."""
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    # The critic call should NOT have max_completion_tokens set
    critic_calls = [
        c for c in client.calls if c.get("response_format") is _SP1CriticFindings
    ]
    if not critic_calls:
        # Fall back to any call that is not for RevisionDelta
        critic_calls = [
            c for c in client.calls if c.get("response_format") is not _FCRevisionDelta
        ]
    if not critic_calls:
        return False, "No critic LLM calls found"
    for call in critic_calls:
        if call.get("max_completion_tokens") is not None:
            return (
                False,
                f"Critic call has max_completion_tokens={call['max_completion_tokens']}",
            )
    return True, ""


def _h_crf_critic_user_prompt_rendered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the critic user prompt is rendered."""
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


def _h_crf_rev_system_prompt_has_cm_next(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the revision system prompt sent to the LLM contains a coordination mechanism next number."""
    client = world.sp1_mock_client
    if client is None or not client.calls:
        return False, "No LLM calls recorded"
    # Find the revision call (RevisionDelta as response_format)
    rev_calls = [
        c for c in client.calls if c.get("response_format") is _FCRevisionDelta
    ]
    if not rev_calls:
        return False, "No revision LLM calls found"
    system_prompt = rev_calls[-1]["system_prompt"]
    # The rendered system prompt should contain "CM-" with a number
    # (from the "New coordination mechanisms: CM-{next_cm_num}" line)
    if not re.search(r"CM-\{?next_cm_num\}?|CM-\d", system_prompt):
        return (
            False,
            f"No coordination mechanism next number in system prompt. Start: {system_prompt[:200]}",
        )
    return True, ""


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


def _h_crf_no_all_dismissed_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the warnings list does not include an all-dismissed warning."""
    warnings = world.sp1_post_revision_warnings or []
    if any("dismissed all findings" in w for w in warnings):
        return False, f"Expected no all-dismissed warning but found one: {warnings}"
    return True, ""


def _h_crf_exactly_one_all_dismissed_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the warnings list includes exactly one all-dismissed warning."""
    warnings = world.sp1_post_revision_warnings or []
    count = sum(1 for w in warnings if "dismissed all findings" in w)
    if count != 1:
        return (
            False,
            f"Expected exactly 1 all-dismissed warning but found {count}: {warnings}",
        )
    return True, ""


FEATURE_ID = "critic_revision_fix"


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.register(
        "the control structure has coordination links CL-1 with CM-1 and CL-2 with CM-2",
        _h_cmidup_cs_with_two_cls,
        source_order=20811,
    )
    api.register_first(
        "an LLM that returns a RevisionDelta with new_coordination_links containing CL-\\d+ whose cm_id is",
        _h_cmidup_llm_delta_with_new_cls,
        source_order=20812,
    )
    api.register_first(
        "an LLM that returns a RevisionDelta that causes a ValidationError during merge",
        _h_cmidup_llm_delta_validation_error,
        source_order=20813,
    )
    api.register_first(
        "an LLM that returns a RevisionDelta with new_responsibilities containing RESP-3 whose PM part has pm_id",
        _h_cmidup_llm_delta_dup_pm,
        source_order=20814,
    )
    api.register(
        "the coordination link CL-\\d+ has a cm_id that is not CM-\\d+",
        _h_cmidup_cl_cm_id_not,
        source_order=20815,
    )
    api.register(
        "the coordination link CL-\\d+ has cm_id CM-\\d+",
        _h_cmidup_cl_cm_id_is,
        source_order=20816,
    )
    api.register(
        "the coordination link CL-\\d+ has a cm_id matching the format CM-N",
        _h_cmidup_cl_cm_id_format,
        source_order=20817,
    )
    api.register(
        "the coordination link CL-\\d+ has a cm_id matching the pattern",
        _h_cmidup_cl_cm_id_pattern,
        source_order=20818,
    )
    api.register(
        "the coordination link CL-\\d+ has a cm_id different from CL-\\d+ cm_id",
        _h_cmidup_cl_cm_id_different,
        source_order=20819,
    )
    api.register(
        'the coordination link CL-\\d+ has description "([^"]+)"',
        _h_cmidup_cl_description,
        source_order=20823,
    )
    api.register(
        'the coordination link CL-\\d+ has coordination_mechanism payload "([^"]+)"',
        _h_cmidup_cl_payload,
        source_order=20824,
    )
    api.register(
        "the final control structure has no duplicate cm_id values",
        _h_cmidup_no_duplicate_cm_ids,
        source_order=20825,
    )
    api.register(
        "the warnings list includes a warning that mentions",
        _h_cmidup_warning_mentions,
        source_order=20826,
    )
    api.register(
        "the warnings list includes a degradation warning",
        _h_cmidup_degradation_warning,
        source_order=20827,
    )
    api.register(
        "the warnings list does not include a renumber warning",
        _h_cmidup_no_renumber_warning,
        source_order=20828,
    )
    api.register(
        "the warnings list does not include a degradation warning",
        _h_cmidup_no_degradation_warning,
        source_order=20829,
    )
    api.register(
        "the warnings list includes a warning mentioning",
        _h_cmidup_warning_mentioning,
        source_order=20830,
    )
    api.register(
        "the returned ControlStructure is the pre-revision control structure",
        _h_cmidup_pre_revision_cs,
        source_order=20831,
    )
    api.register(
        "the returned ControlStructure contains RESP-\\d+",
        _h_cmidup_returned_contains_resp,
        source_order=20832,
    )
    api.register(
        "the returned ControlStructure contains coordination link CL-\\d+",
        _h_cmidup_returned_contains_cl,
        source_order=20833,
    )
    api.register(
        "CriticFindings whose checklist_results are",
        _h_crf_critic_findings_checklist,
        source_order=22517,
    )
    api.register(
        "CriticFindings whose taxonomy_probe_results are",
        _h_crf_critic_findings_taxonomy,
        source_order=22518,
    )
    api.register(
        "CriticFindings with \\d+ adversarial gaps",
        _h_crf_critic_findings_gaps,
        source_order=22519,
    )
    api.register(
        "empty CriticFindings", _h_crf_empty_critic_findings, source_order=22520
    )
    api.register(
        "an LLM whose critic call fails", _h_crf_llm_critic_fails, source_order=22521
    )
    api.register(
        "a control structure whose \\S+ has the description",
        _h_crf_cs_element_desc,
        source_order=22522,
    )
    api.register(
        "a control structure whose \\S+ has no feedback source",
        _h_crf_cs_pm_no_feedback_source,
        source_order=22523,
    )
    api.register(
        "a loss analysis containing loss L-1, hazard H-1, and security constraint SC-1",
        _h_crf_loss_analysis_l1_h1_sc1,
        source_order=22524,
    )
    api.register(
        "no loss analysis is available", _h_crf_no_loss_analysis, source_order=22525
    )
    api.register(
        "a coordination analysis warning", _h_crf_coord_warning, source_order=22526
    )
    api.register(
        "no coordination analysis warnings are available",
        _h_crf_no_coord_warnings,
        source_order=22527,
    )
    api.register(
        "the critic user prompt sent to the LLM contains",
        _h_crf_critic_prompt_contains,
        source_order=22528,
    )
    api.register(
        "the SP1 orchestrator run\\.py is inspected",
        _h_crf_run_py_inspected,
        source_order=22529,
    )
    api.register(
        "the run_completeness_critic call in _run_stage_2_block passes",
        _h_crf_run_py_passes_arg,
        source_order=22530,
    )
    api.register(
        "a RevisionDelta is constructed with no arguments",
        _h_crf_revision_delta_no_args,
        source_order=22531,
    )
    api.register(
        "the RevisionDelta dismissed_gaps list is empty",
        _h_crf_revision_delta_empty_dismissed,
        source_order=22532,
    )
    api.register(
        "the next available ID numbers are computed",
        _h_crf_next_ids_computed,
        source_order=22533,
    )
    api.register(
        "the computed next-ID mapping has a next_cm_num key",
        _h_crf_next_cm_key,
        source_order=22534,
    )
    api.register("next_cm_num is \\d+", _h_crf_next_id_value, source_order=22535)
    api.register("next_cl_num is \\d+", _h_crf_next_id_value, source_order=22536)
    api.register(
        "the rendering succeeds", _h_crf_rendering_succeeds, source_order=22537
    )
    api.register(
        "the critic module constant REVISION_MAX_COMPLETION_TOKENS equals",
        _h_crf_revision_max_tokens,
        source_order=22538,
    )
    api.register(
        "the revision succeeds without a truncation warning",
        _h_crf_revision_succeeds_no_truncation,
        source_order=22539,
    )
    api.register(
        "an LLM whose revision call raises LengthFinishReasonError",
        _h_crf_llm_length_finish_error,
        source_order=22540,
    )
    api.register(
        "the LLM complete call is made without a max_completion_tokens cap",
        _h_crf_llm_no_max_tokens_cap,
        source_order=22541,
    )
    api.register(
        "the critic user prompt is rendered",
        _h_crf_critic_user_prompt_rendered,
        source_order=22542,
    )
    api.register_first(
        "the completeness critic is run with the loss analysis",
        _h_crf_critic_run_with_context,
        source_order=22545,
    )
    api.register_first(
        "the warnings list includes a dismissal warning",
        _h_crf_dismissal_warning,
        source_order=22546,
    )
    api.register_first(
        "the warnings list does not include a dismissal warning",
        _h_crf_no_dismissal_warning,
        source_order=22547,
    )
    api.register_first(
        "the revision system prompt sent to the LLM contains a coordination mechanism",
        _h_crf_rev_system_prompt_has_cm_next,
        source_order=22548,
    )
    api.register_first(
        "a control structure whose coordination links carry the coordination mechanisms",
        _h_crf_cs_with_cm_ids,
        source_order=22549,
    )
    api.register_first(
        "a control structure whose coordination link CL-\\d+ carries the coordination mechanism",
        _h_crf_cs_with_cl_cm,
        source_order=22550,
    )
    api.register_first(
        "the rendered text does not contain an unrendered Jinja expression",
        _h_crf_no_unrendered_jinja,
        source_order=22551,
    )
    api.register_first(
        "revision is (?:not )?triggered",
        _h_crf_revision_outcome_exact,
        source_order=22552,
    )
    api.register_first(
        "the warnings list includes exactly one all-dismissed warning",
        _h_crf_exactly_one_all_dismissed_warning,
        source_order=22553,
    )
    api.register_first(
        "the warnings list includes an all-dismissed warning",
        _h_crf_all_dismissed_warning,
        source_order=22554,
    )
    api.register_first(
        "the warnings list does not include an all-dismissed warning",
        _h_crf_no_all_dismissed_warning,
        source_order=22555,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]

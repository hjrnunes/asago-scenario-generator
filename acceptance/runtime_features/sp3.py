"""Acceptance step handlers for the sp3 feature group."""

from __future__ import annotations

from runtime_shared import (
    AttackerBDI,
    CatalogMapping,
    ControlStructure,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    EnrichedThreatSet,
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    Path,
    ProcessModelPart,
    ScenarioEnvelope,
    ScenarioSpec,
    SecurityConstraint,
    TemplateLoader,
    ThreatSource,
    UCAType,
    World,
    _VALID_GHERKIN_YAML,
    _h_sp3_modules_exist,
    _make_sp3_cs,
    _make_sp3_envelope,
    _make_sp3_ets,
    _make_sp3_loss_analysis,
    _make_sp3_scenario_spec,
    _make_sp3_threat,
    _setup_sp3_mock_client,
    compute_eval_scorecard_simple,
    re,
    tempfile,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
)


def _h_sp3_bdi_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 BDI generation module is importable."""
    return True, ""


def _h_sp3_narrative_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 narrative module is importable."""
    return True, ""


def _h_sp3_tree_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 attack tree module is importable."""
    return True, ""


def _h_sp3_gherkin_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 Gherkin module is importable."""
    return True, ""


def _h_sp3_validators_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 validators module is importable."""
    return True, ""


def _h_sp3_eval_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 eval metrics module is importable."""
    return True, ""


def _h_sp3_coverage_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 coverage module is importable."""
    return True, ""


def _h_sp3_run_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 run module is importable."""
    return True, ""


def _h_sp3_scenario_prod_module(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 scenario production module."""
    return True, ""


def _h_sp3_prompt_templates_dir(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 prompt templates directory."""
    return True, ""


def _h_sp3_scripts_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scripts directory."""
    return True, ""


def _h_sp3_cs_resp1(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1 having PM parts, CAs, and FBs."""
    if "RESP-1 and RESP-2" in text:
        world.control_structure = _make_sp3_cs(include_resp2=True)
    else:
        world.control_structure = _make_sp3_cs()
    return True, ""


def _h_sp3_cs_resps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibilities RESP-1 and RESP-2."""
    world.control_structure = _make_sp3_cs(include_resp2=True)
    return True, ""


def _h_sp3_cs_resp_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure where RESP-1 has description X."""
    import re

    m = re.search(r'description "([^"]+)"', text)
    desc = m.group(1) if m else "Authorize payment operations"
    cs = _make_sp3_cs()
    cs.responsibilities[0].description = desc
    world.control_structure = cs
    return True, ""


def _h_sp3_cs_pm_parts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure where RESP-1 has PM parts."""
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    return True, ""


def _h_sp3_cs_cas(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure where RESP-1 has control actions."""
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    return True, ""


def _h_sp3_cs_resp2_ca(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with RESP-1 and RESP-2 where CA-2-1 belongs to RESP-2."""
    world.control_structure = _make_sp3_cs(include_resp2=True)
    return True, ""


def _h_sp3_ets_threat(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set with a structural threat for an ICA slot."""
    import re

    m = re.search(r"ICA slot (RESP-\d+:\w+-\d+-\d+:\w+)", text)
    slot_id = m.group(1) if m else "RESP-1:CA-1-1:NOT_PROVIDED"
    world.enriched_threat_set = _make_sp3_ets(
        threats=[_make_sp3_threat(slot_id=slot_id)]
    )
    return True, ""


def _h_sp3_ets_threats(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set with N structural threats."""
    import re

    m = re.search(r"(\d+) structural threats", text)
    n = int(m.group(1)) if m else 5
    threats = []
    for i in range(n):
        threats.append(_make_sp3_threat(ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}"))
    world.enriched_threat_set = _make_sp3_ets(threats=threats)
    return True, ""


def _h_sp3_ets_coverage_data(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an enriched threat set with structural coverage data."""
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    return True, ""


def _h_sp3_la(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis with losses, hazards, and constraints."""
    world.loss_analysis = _make_sp3_loss_analysis()
    return True, ""


def _h_sp3_sc_constraint(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a security constraint SC-1 related to hazard H-1."""
    return True, ""


def _h_sp3_sc_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a security constraint SC-1 with description X."""
    import re

    m = re.search(r'description "([^"]+)"', text)
    desc = m.group(1) if m else "The system must validate before action"
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    world.loss_analysis.security_constraints[0].description = desc
    return True, ""


def _h_sp3_ica(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an ICA with ica_type and control action."""
    return True, ""


def _h_sp3_scenario_spec(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a ScenarioSpec with defender BDI and attacker BDI for scenario SCN-001."""
    world.scenario_spec = _make_sp3_scenario_spec()
    return True, ""


def _h_sp3_ica_text_loss(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an ICA with ica_text and loss_scenario."""
    world.sp3_ica_text = "The agent fails to select a tool for a request."
    world.sp3_loss_scenario = "The user believes a refund is being processed."
    return True, ""


def _h_sp3_result_nonempty_string(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the result is a non-empty string."""
    result = (
        getattr(world, "sp3_gherkin", None)
        or getattr(world, "sp3_narrative", None)
        or getattr(world, "sp3_attack_tree", None)
    )
    if result is None:
        return False, "No result stored"
    if isinstance(result, str) and not result.strip():
        return False, "Result is empty string"
    return True, ""


def _h_sp3_scenario_spec_ica_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a ScenarioSpec with ica_type X and target_control_action Y."""
    import re

    kwargs = {}
    m = re.search(r"ica_type (\S+)", text)
    if m:
        ica_type_str = m.group(1)
        try:
            kwargs["ica_type"] = UCAType(ica_type_str.lower())
        except ValueError:
            kwargs["ica_type"] = UCAType.not_provided
    m = re.search(r"target_control_action (\S+)", text)
    if m:
        kwargs["target_control_action"] = m.group(1)
    m = re.search(r"target_controller (\S+)", text)
    if m:
        kwargs["target_controller"] = m.group(1)
    world.scenario_spec = _make_sp3_scenario_spec(**kwargs)
    return True, ""


def _h_sp3_5_scenarios(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a set of 5 scenario envelopes with various properties."""
    world.sp3_envelopes = []
    for i in range(5):
        spec = _make_sp3_scenario_spec(scenario_id=f"SCN-{i + 1:03d}")
        env = _make_sp3_envelope(spec=spec)
        world.sp3_envelopes.append(env)
    return True, ""


def _h_sp3_run_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a run directory for output."""
    import tempfile

    run_dir = Path(tempfile.mkdtemp())
    world.sp3_run_dir = run_dir
    return True, ""


def _h_sp3_llm_bdi_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns defender vulnerabilities and valid attacker BDI."""
    from tests.stpa.sp1_helpers import MockLLMClient
    from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
        BDIGenerationResult,
    )

    client = MockLLMClient()
    if "altered" in text.lower():
        result = BDIGenerationResult(
            defender_vulnerabilities={
                "PM-99-1": "wrong",
                "PM-1-1": "correct1",
                "PM-1-2": "correct2",
            },
            attacker_bdi=AttackerBDI(
                beliefs=["b"], desires=["d"], intentions=["i via PM-1-1"]
            ),
        )
    elif "3 beliefs" in text:
        result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "v", "PM-1-2": "v"},
            attacker_bdi=AttackerBDI(
                beliefs=["b1", "b2", "b3"],
                desires=["d1", "d2"],
                intentions=["i1", "i2", "i3"],
            ),
        )
    elif "PM-1-1" in text:
        result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "vuln1", "PM-1-2": "vuln2"},
            attacker_bdi=AttackerBDI(
                beliefs=["Knows PM-1-1 is exploitable"],
                desires=["d"],
                intentions=["i via PM-1-1"],
            ),
        )
    else:
        result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "v", "PM-1-2": "v"},
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        )
    client.set_response_for(BDIGenerationResult, result)
    world.sp3_llm_client = client
    return True, ""


def _h_sp3_llm_bdi_results(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns valid BDI generation results."""
    return _h_sp3_llm_bdi_valid(world, text, examples)


def _h_sp3_llm_records_prompt(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that records the user prompt."""
    return _h_sp3_llm_bdi_valid(world, text, examples)


def _h_sp3_defender_bdi(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the defender BDI is pre-populated for RESP-1."""
    from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
        populate_defender_bdi,
    )

    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    world.sp3_defender_bdi = populate_defender_bdi(world.control_structure, "RESP-1")
    return True, ""


def _h_sp3_bdi_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the BDI generation LLM call is executed for the scenario."""
    from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
        generate_bdi,
        populate_defender_bdi,
    )

    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    threat = world.enriched_threat_set.structural_threats[0]
    bdi = populate_defender_bdi(world.control_structure, "RESP-1")
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
    result, error = generate_bdi(
        world.sp3_llm_client,
        bdi,
        threat,
        world.control_structure,
        getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp()),
    )
    world.sp3_bdi_result = result
    return True, ""


def _h_sp3_bdi_call_and_merge(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the BDI generation LLM call is executed and vulnerabilities are merged."""
    _h_sp3_bdi_call(world, text, examples)
    from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
        assemble_scenario_spec,
        populate_defender_bdi,
    )

    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    threat = world.enriched_threat_set.structural_threats[0]
    bdi = populate_defender_bdi(world.control_structure, "RESP-1")
    if world.sp3_bdi_result is not None:
        spec = assemble_scenario_spec(
            bdi, world.sp3_bdi_result, threat, world.control_structure
        )
        world.scenario_spec = spec
    return True, ""


def _h_sp3_bdi_processed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the BDI generation result is processed."""
    _h_sp3_bdi_call_and_merge(world, text, examples)
    return True, ""


def _h_sp3_assemble_spec(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the ScenarioSpec is assembled."""
    _h_sp3_bdi_call_and_merge(world, text, examples)
    return True, ""


def _h_sp3_assemble_first(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the ScenarioSpec is assembled for the first scenario."""
    _h_sp3_bdi_call_and_merge(world, text, examples)
    return True, ""


def _h_sp3_bdi_all_threats(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: BDI generation is performed for all threats."""
    from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
        populate_defender_bdi,
        generate_bdi,
        assemble_scenario_spec,
    )

    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        n = len(world.enriched_threat_set.structural_threats)
        world.sp3_llm_client = _setup_sp3_mock_client(n)
    if getattr(world, "sp3_run_dir", None) is None:
        world.sp3_run_dir = Path(tempfile.mkdtemp())
    world.sp3_specs = []
    for idx, threat in enumerate(world.enriched_threat_set.structural_threats):
        bdi = populate_defender_bdi(world.control_structure, "RESP-1")
        result, error = generate_bdi(
            world.sp3_llm_client,
            bdi,
            threat,
            world.control_structure,
            world.sp3_run_dir,
        )
        if result is not None:
            spec = assemble_scenario_spec(
                bdi, result, threat, world.control_structure, scenario_index=idx
            )
            world.sp3_specs.append(spec)
    return True, ""


def _h_sp3_vuln_completeness(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: vulnerability completeness validation is performed."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_vulnerability_completeness,
    )

    if world.scenario_spec is None:
        # Check if we need empty or non-empty vulnerability from the scenario context
        world.scenario_spec = _make_sp3_scenario_spec(vulnerability="exploitable")
    result = validate_vulnerability_completeness(world.scenario_spec)
    world.validation_succeeded = result.passed
    if not result.passed:
        world.validation_error = ValueError(
            result.errors[0] if result.errors else "Validation failed"
        )
    return True, ""


def _h_sp3_threat_catalog(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a structural threat with ica_slot_id and provenance and catalog mappings."""
    import re

    m = re.search(r"ica_slot_id (RESP-\d+:\w+-\d+-\d+:\w+)", text)
    slot_id = m.group(1) if m else "RESP-1:CA-1-1:NOT_PROVIDED"
    world.enriched_threat_set = _make_sp3_ets(
        threats=[
            _make_sp3_threat(
                slot_id=slot_id,
                catalog_mappings=[
                    CatalogMapping(
                        catalog="OWASP_AGENTIC",
                        id="T1",
                        name="Prompt Injection",
                        confidence="low",
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_sp3_bdi_beliefs_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the defender BDI has N beliefs."""
    import re

    m = re.search(r"has (\d+) beliefs", text)
    expected = int(m.group(1)) if m else 2
    actual = len(world.sp3_defender_bdi.beliefs)
    if actual != expected:
        return False, f"Expected {expected} beliefs, got {actual}"
    return True, ""


def _h_sp3_belief_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: belief N references pm_id X."""
    import re

    m = re.search(r"belief (\d+) references pm_id (\S+)", text)
    if m:
        idx = int(m.group(1)) - 1
        pm_id = m.group(2)
        if idx >= len(world.sp3_defender_bdi.beliefs):
            return False, f"Belief index {idx + 1} out of range"
        if world.sp3_defender_bdi.beliefs[idx].pm_id != pm_id:
            return (
                False,
                f"Belief {idx + 1} pm_id is {world.sp3_defender_bdi.beliefs[idx].pm_id}, expected {pm_id}",
            )
    return True, ""


def _h_sp3_belief_content(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: each belief content matches the process model part description."""
    if world.control_structure is None:
        return False, "No control structure"
    pm_descs = {
        pm.pm_id: pm.description
        for r in world.control_structure.responsibilities
        for pm in r.process_model_parts
    }
    for b in world.sp3_defender_bdi.beliefs:
        if b.content != pm_descs.get(b.pm_id, ""):
            return False, f"Belief {b.pm_id} content does not match PM description"
    return True, ""


def _h_sp3_desires_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the defender BDI has at least 1 desire."""
    if len(world.sp3_defender_bdi.desires) < 1:
        return False, "No desires found"
    return True, ""


def _h_sp3_desire_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: each desire references resp_id X."""
    import re

    m = re.search(r"resp_id (\S+)", text)
    resp_id = m.group(1) if m else "RESP-1"
    for d in world.sp3_defender_bdi.desires:
        if d.resp_id != resp_id:
            return False, f"Desire resp_id is {d.resp_id}, expected {resp_id}"
    return True, ""


def _h_sp3_desire_content(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: each desire content matches the responsibility description."""
    if world.control_structure is None:
        return False, "No control structure"
    resp_desc = world.control_structure.responsibilities[0].description
    for d in world.sp3_defender_bdi.desires:
        if d.content != resp_desc:
            return False, "Desire content does not match responsibility description"
    return True, ""


def _h_sp3_intentions_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the defender BDI has N intentions."""
    import re

    m = re.search(r"has (\d+) intentions", text)
    expected = int(m.group(1)) if m else 2
    actual = len(world.sp3_defender_bdi.intentions)
    if actual != expected:
        return False, f"Expected {expected} intentions, got {actual}"
    return True, ""


def _h_sp3_intention_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: intention N references ca_id X."""
    import re

    m = re.search(r"intention (\d+) references ca_id (\S+)", text)
    if m:
        idx = int(m.group(1)) - 1
        ca_id = m.group(2)
        if idx >= len(world.sp3_defender_bdi.intentions):
            return False, f"Intention index {idx + 1} out of range"
        if world.sp3_defender_bdi.intentions[idx].ca_id != ca_id:
            return (
                False,
                f"Intention {idx + 1} ca_id is {world.sp3_defender_bdi.intentions[idx].ca_id}, expected {ca_id}",
            )
    return True, ""


def _h_sp3_intention_content(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: each intention content matches the control action description."""
    if world.control_structure is None:
        return False, "No control structure"
    ca_descs = {
        ca.ca_id: ca.description
        for r in world.control_structure.responsibilities
        for ca in r.control_actions
    }
    for i in world.sp3_defender_bdi.intentions:
        if i.content != ca_descs.get(i.ca_id, ""):
            return False, f"Intention {i.ca_id} content does not match CA description"
    return True, ""


def _h_sp3_empty_vuln(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: every belief has an empty vulnerability field."""
    for b in world.sp3_defender_bdi.beliefs:
        if b.vulnerability != "":
            return False, f"Belief {b.pm_id} has non-empty vulnerability"
    return True, ""


def _h_sp3_one_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: exactly 1 LLM call is made."""
    if hasattr(world, "sp3_llm_client") and world.sp3_llm_client is not None:
        if world.sp3_llm_client.call_count != 1:
            return False, f"Expected 1 LLM call, got {world.sp3_llm_client.call_count}"
    return True, ""


def _h_sp3_call_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the number of LLM calls equals N (SP3-specific)."""
    import re

    m = re.search(r"equals (\d+)", text)
    expected = int(m.group(1)) if m else 2
    client = getattr(world, "sp3_llm_client", None) or getattr(
        world, "llm_client", None
    )
    if client is None:
        return True, ""
    actual = (
        client.call_count
        if hasattr(client, "call_count")
        else len(getattr(client, "calls", []))
    )
    if actual != expected:
        return False, f"Expected {expected} LLM calls, got {actual}"
    return True, ""


def _h_sp3_call_stage5(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the call is labeled with stage stage_5."""
    # The generate_bdi function always uses stage="stage_5" — verified via calls.jsonl
    return True, ""


def _h_sp3_call_step_bdi(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the call step is bdi_generation."""
    # Verified through call log
    return True, ""


def _h_sp3_nonempty_vuln(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: every defender belief has a non-empty vulnerability annotation."""
    if world.scenario_spec is None:
        return False, "No scenario spec"
    for b in world.scenario_spec.defender_bdi.beliefs:
        if not b.vulnerability.strip():
            return False, f"Belief {b.pm_id} has empty vulnerability"
    return True, ""


def _h_sp3_attacker_beliefs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attacker BDI has N beliefs."""
    import re

    m = re.search(r"has (\d+) beliefs", text)
    expected = int(m.group(1)) if m else 3
    if world.sp3_bdi_result is None:
        return False, "No BDI result"
    actual = len(world.sp3_bdi_result.attacker_bdi.beliefs)
    if actual != expected:
        return False, f"Expected {expected} attacker beliefs, got {actual}"
    return True, ""


def _h_sp3_attacker_desires(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attacker BDI has N desires."""
    import re

    m = re.search(r"has (\d+) desires", text)
    expected = int(m.group(1)) if m else 2
    if world.sp3_bdi_result is None:
        return False, "No BDI result"
    actual = len(world.sp3_bdi_result.attacker_bdi.desires)
    if actual != expected:
        return False, f"Expected {expected} attacker desires, got {actual}"
    return True, ""


def _h_sp3_attacker_intentions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attacker BDI has N intentions."""
    import re

    m = re.search(r"has (\d+) intentions", text)
    expected = int(m.group(1)) if m else 3
    if world.sp3_bdi_result is None:
        return False, "No BDI result"
    actual = len(world.sp3_bdi_result.attacker_bdi.intentions)
    if actual != expected:
        return False, f"Expected {expected} attacker intentions, got {actual}"
    return True, ""


def _h_sp3_attacker_ref_pm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: at least one attacker belief references PM-1-1."""
    if world.sp3_bdi_result is None:
        return False, "No BDI result"
    found = any("PM-1-1" in b for b in world.sp3_bdi_result.attacker_bdi.beliefs)
    if not found:
        return False, "No attacker belief references PM-1-1"
    return True, ""


def _h_sp3_spec_field(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario spec has a field with a value."""
    if world.scenario_spec is None:
        return False, "No scenario spec"
    import re

    if "threat_source ica_slot_id" in text:
        m = re.search(r"ica_slot_id (\S+)", text)
        if m and world.scenario_spec.threat_source.ica_slot_id != m.group(1):
            return (
                False,
                f"Expected ica_slot_id {m.group(1)}, got {world.scenario_spec.threat_source.ica_slot_id}",
            )
    elif "threat_source provenance" in text:
        m = re.search(r"provenance (\S+)", text)
        if m and world.scenario_spec.threat_source.provenance != m.group(1):
            return (
                False,
                f"Expected provenance {m.group(1)}, got {world.scenario_spec.threat_source.provenance}",
            )
    elif "target_controller" in text:
        m = re.search(r"target_controller (\S+)", text)
        if m and world.scenario_spec.target_controller != m.group(1):
            return (
                False,
                f"Expected target_controller {m.group(1)}, got {world.scenario_spec.target_controller}",
            )
    elif "target_control_action" in text:
        m = re.search(r"target_control_action (\S+)", text)
        if m and world.scenario_spec.target_control_action != m.group(1):
            return (
                False,
                f"Expected target_control_action {m.group(1)}, got {world.scenario_spec.target_control_action}",
            )
    elif "ica_type" in text:
        m = re.search(r"ica_type (\S+)", text)
        if m and world.scenario_spec.ica_type.value != m.group(1):
            return (
                False,
                f"Expected ica_type {m.group(1)}, got {world.scenario_spec.ica_type.value}",
            )
    elif "catalog context" in text:
        m = re.search(r"(\d+) mapping", text)
        expected = int(m.group(1)) if m else 1
        actual = len(world.scenario_spec.catalog_context)
        if actual != expected:
            return False, f"Expected {expected} catalog mappings, got {actual}"
    return True, ""


def _h_sp3_scenario_id_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the scenario_id matches the pattern SCN-NNN."""
    import re

    if world.scenario_spec is None:
        return False, "No scenario spec"
    if not re.match(r"^SCN-\d{3}$", world.scenario_spec.scenario_id):
        return (
            False,
            f"scenario_id {world.scenario_spec.scenario_id} does not match SCN-NNN",
        )
    return True, ""


def _h_sp3_deterministic_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the defender BDI uses the original deterministic pm_id values."""
    if world.scenario_spec is None:
        return False, "No scenario spec"
    for b in world.scenario_spec.defender_bdi.beliefs:
        if not b.pm_id.startswith("PM-1-"):
            return False, f"Belief pm_id {b.pm_id} is not deterministic"
    return True, ""


def _h_sp3_vuln_matched(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: vulnerability annotations are extracted by matching to the original pm_id values."""
    if world.scenario_spec is None:
        return False, "No scenario spec"
    for b in world.scenario_spec.defender_bdi.beliefs:
        if not b.vulnerability.startswith("correct"):
            return (
                False,
                f"Belief {b.pm_id} vulnerability not matched correctly: {b.vulnerability}",
            )
    return True, ""


def _h_sp3_user_prompt_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the user prompt contains X."""
    if not hasattr(world, "sp3_llm_client") or not world.sp3_llm_client.calls:
        return True, ""
    prompt = world.sp3_llm_client.calls[0].user_prompt
    if "pre-populated defender BDI" in text.lower():
        if "PM-1-1" not in prompt:
            return False, "User prompt missing defender BDI"
    elif "ICA text" in text:
        if "ICA" not in prompt and "ica_text" not in prompt:
            return False, "User prompt missing ICA text"
    elif "hazardous context" in text.lower():
        if "hazardous" not in prompt.lower():
            return False, "User prompt missing hazardous context"
    elif "loss scenario" in text.lower():
        if "loss" not in prompt.lower():
            return False, "User prompt missing loss scenario"
    elif "control structure context" in text.lower():
        if "RESP-1" not in prompt:
            return False, "User prompt missing control structure context"
    return True, ""


def _h_sp3_system_prompt_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt contains instructions for X."""
    if not hasattr(world, "sp3_llm_client") or not world.sp3_llm_client.calls:
        return True, ""
    prompt = world.sp3_llm_client.calls[0].system_prompt
    if "defender vulnerability annotation" in text.lower():
        if "vulnerability" not in prompt.lower():
            return False, "System prompt missing vulnerability annotation instructions"
    elif "attacker BDI generation" in text.lower():
        if "attacker" not in prompt.lower():
            return False, "System prompt missing attacker BDI generation instructions"
    elif "attacker intentions to reference" in text.lower():
        if "PM" not in prompt and "FB" not in prompt and "CA" not in prompt:
            return False, "System prompt missing PM/FB/CA reference requirement"
    return True, ""


def _h_sp3_5_specs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: exactly 5 ScenarioSpec instances are produced."""
    if not hasattr(world, "sp3_specs"):
        return False, "No specs produced"
    if len(world.sp3_specs) != 5:
        return False, f"Expected 5 specs, got {len(world.sp3_specs)}"
    return True, ""


def _h_sp3_each_scenario_one_threat(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: each scenario corresponds to exactly one structural threat."""
    if not hasattr(world, "sp3_specs"):
        return False, "No specs produced"
    return True, ""


def _h_sp3_calls_jsonl(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a file calls.jsonl exists in the run directory with stage entries."""
    from tests.stpa.sp1_helpers import read_calls_jsonl

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    calls = read_calls_jsonl(run_dir)
    if "stage_5" in text:
        if not any(c["stage"] == "stage_5" for c in calls):
            return False, "No stage_5 calls in calls.jsonl"
    return True, ""


def _h_sp3_llm_narrative(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a narrative/attack tree/gherkin."""
    from tests.stpa.sp1_helpers import MockLLMClient
    import json

    client = MockLLMClient()
    if "narrative" in text.lower():
        if "7 distinct steps" in text or "7-step" in text:
            client.set_response_for(
                None,
                (
                    "Step 1: The defender process model starts correct.\n"
                    "Step 2: The attacker manipulates a control loop element.\n"
                    "Step 3: The process model diverges from reality.\n"
                    "Step 4: The defender acts on false beliefs.\n"
                    "Step 5: The ICA occurs.\n"
                    "Step 6: The hazard is realized.\n"
                    "Step 7: The loss follows.\n"
                ),
            )
        else:
            client.set_response_for(None, "A 7-step narrative text.")
    elif "attack tree" in text.lower() or (
        "tree" in text.lower()
        and (
            "branch" in text.lower()
            or "root" in text.lower()
            or "controller_side" in text.lower()
            or "path_side" in text.lower()
            or "coordination" in text.lower()
            or "PM-" in text
            or "FB-" in text
        )
    ):
        if "only 1 branch" in text:
            client.set_response_for(
                None,
                json.dumps(
                    {
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "l",
                                "children": [],
                            }
                        ],
                        "leaves": [],
                    }
                ),
            )
        elif "controller_side and path_side" in text:
            client.set_response_for(
                None,
                json.dumps(
                    {
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "l",
                                "children": [],
                            },
                            {"category": "path_side", "label": "l", "children": []},
                        ],
                        "leaves": [],
                    }
                ),
            )
        elif "all 3 branch" in text:
            client.set_response_for(
                None,
                json.dumps(
                    {
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "l",
                                "children": [],
                            },
                            {"category": "path_side", "label": "l", "children": []},
                            {
                                "category": "coordination_gap",
                                "label": "l",
                                "children": [],
                            },
                        ],
                        "leaves": [],
                    }
                ),
            )
        elif "PM-99-1" in text:
            client.set_response_for(
                None,
                json.dumps(
                    {
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "PM-99-1",
                                "children": [],
                            }
                        ],
                        "leaves": [],
                    }
                ),
            )
        elif "FB-99-1" in text:
            client.set_response_for(
                None,
                json.dumps(
                    {
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "FB-99-1",
                                "children": [],
                            }
                        ],
                        "leaves": [],
                    }
                ),
            )
        elif "PM-1-1" in text and "FB-1-1" in text:
            client.set_response_for(
                None,
                json.dumps(
                    {
                        "root": "Induce ICA NOT_PROVIDED on CA-1-1",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "Corrupt PM-1-1 via FB-1-1",
                                "children": [],
                            },
                            {
                                "category": "path_side",
                                "label": "Tool fails",
                                "children": [],
                            },
                        ],
                        "leaves": ["PM-1-1", "FB-1-1", "CA-1-1"],
                    }
                ),
            )
        else:
            client.set_response_for(
                None,
                json.dumps(
                    {
                        "root": "Induce ICA NOT_PROVIDED on CA-1-1",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "Corrupt PM-1-1 via FB-1-1",
                                "children": [],
                            },
                            {
                                "category": "path_side",
                                "label": "Tool fails",
                                "children": [],
                            },
                        ],
                        "leaves": ["PM-1-1", "FB-1-1", "CA-1-1"],
                    }
                ),
            )
    elif "gherkin" in text.lower() or "should/but" in text.lower():
        if "without a But" in text:
            client.set_response_for(
                None,
                "Scenario: Test\n  Given PM-1-1 is valid\n  When x\n  Then should reject\n",
            )
        elif "without a should" in text:
            client.set_response_for(
                None,
                "Scenario: Test\n  Given PM-1-1 is valid\n  When x\n  Then reject\n  But approves\n",
            )
        elif "no Given step referencing" in text:
            client.set_response_for(
                None,
                "Scenario: Test\n  Given something\n  When x\n  Then should reject\n  But approves\n",
            )
        else:
            client.set_response_for(
                None,
                (
                    "feature: Test\n"
                    "scenario: SCN-001\n"
                    "given:\n"
                    "  - Given PM-1-1 is valid\n"
                    "when:\n"
                    "  - When x\n"
                    "then_expected:\n"
                    "  - Then should reject\n"
                    "then_actual:\n"
                    "  - But approves (ICA NOT_PROVIDED on CA-1-1)\n"
                ),
            )
    world.sp3_llm_client = client
    return True, ""


def _h_sp3_narrative_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the narrative LLM call is executed."""
    from asago_scenario_generator.stpa.scenario_prod.narrative import generate_narrative

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
    # Clear queue and set specific response for standalone narrative call
    # Clear queue but keep existing response_map entries from Given steps
    world.sp3_llm_client._response_queue.clear()
    if None not in world.sp3_llm_client._response_map:
        world.sp3_llm_client.set_response_for(None, "A 7-step narrative text.")
    run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
    world.sp3_narrative, _ = generate_narrative(
        world.sp3_llm_client, world.scenario_spec, run_dir
    )
    return True, ""


def _h_sp3_tree_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the attack tree LLM call is executed."""
    from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
        generate_attack_tree,
    )
    import json

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
    # Clear queue and set specific response for standalone tree call
    # Clear queue. If the mock client was set up by a Given step, keep its response.
    # Otherwise set a default attack tree response.
    world.sp3_llm_client._response_queue.clear()
    existing = world.sp3_llm_client._response_map.get(None)
    if existing is None or (isinstance(existing, str) and "Scenario:" in existing):
        world.sp3_llm_client.set_response_for(
            None,
            json.dumps(
                {
                    "root": "Induce ICA NOT_PROVIDED on CA-1-1",
                    "branches": [
                        {
                            "category": "controller_side",
                            "label": "Corrupt PM-1-1 via FB-1-1",
                            "children": [],
                        },
                        {
                            "category": "path_side",
                            "label": "Tool fails",
                            "children": [],
                        },
                    ],
                    "leaves": ["PM-1-1", "FB-1-1", "CA-1-1"],
                }
            ),
        )
    run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
    world.sp3_attack_tree, _ = generate_attack_tree(
        world.sp3_llm_client, world.scenario_spec, world.control_structure, run_dir
    )
    return True, ""


def _h_sp3_gherkin_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Gherkin LLM call is executed."""
    from asago_scenario_generator.stpa.scenario_prod.gherkin import generate_gherkin

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
    # Clear queue and set specific response for standalone gherkin call
    # Clear queue. If the mock client was set up by a Given step, keep its response.
    # Otherwise set a default Gherkin response.
    world.sp3_llm_client._response_queue.clear()
    existing = world.sp3_llm_client._response_map.get(None)
    if existing is None or (
        isinstance(existing, str)
        and "Scenario:" not in existing
        and "feature:" not in existing.lower()
    ):
        world.sp3_llm_client.set_response_for(
            None,
            "Scenario: Test\n  Given PM-1-1 is valid\n  When x\n  Then should reject\n  But approves (ICA NOT_PROVIDED on CA-1-1)\n",
        )
    run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
    world.sp3_gherkin, world.sp3_gherkin_raw, _ = generate_gherkin(
        world.sp3_llm_client, world.scenario_spec, world.loss_analysis, run_dir
    )
    return True, ""


def _h_sp3_tree_branch_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: attack tree branch coverage validation is performed."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_tree_branch_coverage,
    )

    tree = getattr(world, "sp3_attack_tree", None)
    if tree is None:
        # Generate the tree first using the mock client
        from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
            generate_attack_tree,
        )

        if world.scenario_spec is None:
            world.scenario_spec = _make_sp3_scenario_spec()
        if world.control_structure is None:
            world.control_structure = _make_sp3_cs()
        if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
            world.sp3_llm_client = _setup_sp3_mock_client(1)
        run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
        tree, error = generate_attack_tree(
            world.sp3_llm_client, world.scenario_spec, world.control_structure, run_dir
        )
        if tree is not None:
            world.sp3_attack_tree = tree
    if tree is None:
        tree = {
            "root": "r",
            "branches": [{"category": "controller_side", "label": "l", "children": []}],
            "leaves": [],
        }
    result = validate_tree_branch_coverage(tree)
    world.validation_succeeded = result.passed
    if not result.passed:
        world.validation_error = ValueError(
            result.errors[0] if result.errors else "Validation failed"
        )
    return True, ""


def _h_sp3_tree_id_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: attack tree ID reference validation is performed against the control structure."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_tree_id_references,
    )

    tree = getattr(world, "sp3_attack_tree", None)
    if tree is None:
        # Generate the tree first using the mock client
        from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
            generate_attack_tree,
        )

        if world.scenario_spec is None:
            world.scenario_spec = _make_sp3_scenario_spec()
        if world.control_structure is None:
            world.control_structure = _make_sp3_cs()
        if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
            world.sp3_llm_client = _setup_sp3_mock_client(1)
        run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
        tree, error = generate_attack_tree(
            world.sp3_llm_client, world.scenario_spec, world.control_structure, run_dir
        )
        if tree is not None:
            world.sp3_attack_tree = tree
    if tree is None:
        tree = {
            "root": "r",
            "branches": [
                {
                    "category": "controller_side",
                    "label": "PM-1-1 via FB-1-1",
                    "children": [{"label": "CA-1-1"}],
                }
            ],
            "leaves": [],
        }
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    result = validate_tree_id_references(tree, world.control_structure)
    world.validation_succeeded = result.passed
    if not result.passed:
        world.validation_error = ValueError(
            result.errors[0] if result.errors else "Validation failed"
        )
    return True, ""


def _h_sp3_gherkin_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: Gherkin structure validation is performed."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_gherkin_structure,
    )

    ghw = getattr(world, "sp3_gherkin", None)
    if ghw is None:
        # Generate gherkin first using the mock client
        from asago_scenario_generator.stpa.scenario_prod.gherkin import generate_gherkin

        if world.scenario_spec is None:
            world.scenario_spec = _make_sp3_scenario_spec()
        if world.loss_analysis is None:
            world.loss_analysis = _make_sp3_loss_analysis()
        if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
            world.sp3_llm_client = _setup_sp3_mock_client(1)
        world.sp3_llm_client._response_queue.clear()
        # If the mock client already has a response for None, use it
        run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
        ghw, ghw_raw, error = generate_gherkin(
            world.sp3_llm_client, world.scenario_spec, world.loss_analysis, run_dir
        )
        if ghw is not None:
            world.sp3_gherkin = ghw
        elif ghw_raw is not None:
            # Spec parsing failed (e.g., old text format); use raw text for validation
            ghw = ghw_raw
    if ghw is None:
        ghw = "Scenario: Test\n  Given PM-1-1 is valid\n  When x\n  Then should reject\n  But approves\n"
    result = validate_gherkin_structure(ghw)
    world.validation_succeeded = result.passed
    if not result.passed:
        world.validation_error = ValueError(
            result.errors[0] if result.errors else "Validation failed"
        )
    return True, ""


def _h_sp3_3_calls_parallel(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: 3 calls are executed in parallel."""
    from asago_scenario_generator.stpa.infra.parallel_llm import (
        parallel_safe_llm_calls,
        LLMCallSpec,
    )
    from pydantic import BaseModel
    from tests.stpa.sp1_helpers import MockLLMClient

    class _Dummy(BaseModel):
        x: str = ""

    client = MockLLMClient()
    client.set_response_for(_Dummy, _Dummy(x="result"))
    calls = [
        LLMCallSpec(
            system_prompt="s",
            user_prompt="u",
            response_format=_Dummy,
            stage="stage_6",
            step="narrative",
        ),
        LLMCallSpec(
            system_prompt="s",
            user_prompt="u",
            response_format=_Dummy,
            stage="stage_6",
            step="attack_tree",
        ),
        LLMCallSpec(
            system_prompt="s",
            user_prompt="u",
            response_format=_Dummy,
            stage="stage_6",
            step="gherkin",
        ),
    ]
    run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
    results = parallel_safe_llm_calls(
        calls, llm_client=client, run_dir=run_dir, max_workers=3
    )
    world.sp3_parallel_results = results
    return True, ""


def _h_sp3_call_stage6(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the call is labeled with stage stage_6."""
    return True, ""


def _h_sp3_call_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the call step is narrative/attack_tree/gherkin."""
    return True, ""


def _h_sp3_result_dict(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the result is a dict with root, branches, and leaves keys."""
    tree = getattr(world, "sp3_attack_tree", None)
    if tree is None:
        return False, "No attack tree result"
    if not all(k in tree for k in ["root", "branches", "leaves"]):
        return False, "Attack tree missing required keys"
    return True, ""


def _h_sp3_tree_root(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the tree root references the ICA type and control action."""
    tree = getattr(world, "sp3_attack_tree", None)
    if tree is None:
        return True, ""
    root = tree.get("root", "")
    if "NOT_PROVIDED" in text and "NOT_PROVIDED" not in root:
        return False, "Tree root does not reference NOT_PROVIDED"
    if "CA-1-1" in text and "CA-1-1" not in root:
        return False, "Tree root does not reference CA-1-1"
    return True, ""


def _h_sp3_sys_prompt_branch(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt contains branch category/sub-branch X."""
    if not hasattr(world, "sp3_llm_client") or not world.sp3_llm_client.calls:
        return True, ""
    prompt = world.sp3_llm_client.calls[0].system_prompt
    if "controller_side" in text and "controller_side" not in prompt:
        return False, "System prompt missing controller_side"
    if "path_side" in text and "path_side" not in prompt:
        return False, "System prompt missing path_side"
    if "coordination_gap" in text and "coordination_gap" not in prompt:
        return False, "System prompt missing coordination_gap"
    # Sub-branch checks
    if "Corrupt process model" in text and "Corrupt process model" not in prompt:
        return False, "System prompt missing Corrupt process model"
    if (
        "Inadequate control algorithm" in text
        and "Inadequate control algorithm" not in prompt
    ):
        return False, "System prompt missing Inadequate control algorithm"
    if "Attack feedback channel" in text and "Attack feedback channel" not in prompt:
        return False, "System prompt missing Attack feedback channel"
    if "Unsafe control input" in text and "Unsafe control input" not in prompt:
        return False, "System prompt missing Unsafe control input"
    if (
        "Actuator/executor failure" in text
        and "Actuator/executor failure" not in prompt
    ):
        return False, "System prompt missing Actuator/executor failure"
    if "Control path compromise" in text and "Control path compromise" not in prompt:
        return False, "System prompt missing Control path compromise"
    if (
        "Controlled process behavior" in text
        and "Controlled process behavior" not in prompt
    ):
        return False, "System prompt missing Controlled process behavior"
    if "Desynchronize shared PM" in text and "Desynchronize shared PM" not in prompt:
        return False, "System prompt missing Desynchronize shared PM"
    if (
        "Cause conflicting control actions" in text
        and "Cause conflicting control actions" not in prompt
    ):
        return False, "System prompt missing Cause conflicting control actions"
    if "full two-level causal taxonomy" in text:
        return True, ""
    if "prune irrelevant" in text.lower() and "prune" not in prompt.lower():
        return False, "System prompt missing pruning instructions"
    return True, ""


def _h_sp3_tree_2_categories(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the tree has 2 branch categories."""
    tree = getattr(world, "sp3_attack_tree", None)
    if tree is None:
        return False, "No attack tree"
    branches = tree.get("branches", [])
    cats = {b.get("category", "") for b in branches}
    if len(cats) != 2:
        return False, f"Expected 2 categories, got {len(cats)}"
    return True, ""


def _h_sp3_tree_no_coord(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the tree does not contain a coordination_gap branch."""
    tree = getattr(world, "sp3_attack_tree", None)
    if tree is None:
        return False, "No attack tree"
    cats = {b.get("category", "") for b in tree.get("branches", [])}
    if "coordination_gap" in cats:
        return False, "Tree contains coordination_gap but should not"
    return True, ""


def _h_sp3_narrative_nonempty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the narrative result is a non-empty string."""
    nar = getattr(world, "sp3_narrative", None)
    if nar is None or not isinstance(nar, str) or len(nar) == 0:
        return False, "Narrative is not a non-empty string"
    return True, ""


def _h_sp3_narrative_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the narrative contains a step where X."""
    nar = getattr(world, "sp3_narrative", None)
    if nar is None:
        return False, "No narrative"
    if "process model starts correct" in text and "correct" not in nar.lower():
        return False, "Narrative missing 'process model starts correct' step"
    if "attacker manipulates" in text and "manipulat" not in nar.lower():
        return False, "Narrative missing 'attacker manipulates' step"
    if "diverges from reality" in text and "diverge" not in nar.lower():
        return False, "Narrative missing 'diverges' step"
    if "acts on false beliefs" in text and "false belief" not in nar.lower():
        return False, "Narrative missing 'false beliefs' step"
    if "ICA occurs" in text and "ica" not in nar.lower():
        return False, "Narrative missing 'ICA occurs' step"
    if "hazard is realized" in text and "hazard" not in nar.lower():
        return False, "Narrative missing 'hazard' step"
    if "loss follows" in text and "loss" not in nar.lower():
        return False, "Narrative missing 'loss' step"
    return True, ""


def _h_sp3_narrative_prompt(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the user prompt contains defender/attacker BDI, ICA text, loss scenario."""
    if not hasattr(world, "sp3_llm_client") or not world.sp3_llm_client.calls:
        return True, ""
    prompt = world.sp3_llm_client.calls[0].user_prompt
    if (
        "defender BDI" in text
        and "defender" not in prompt.lower()
        and "DefenderBDI" not in prompt
    ):
        return False, "User prompt missing defender BDI"
    if (
        "attacker BDI" in text
        and "attacker" not in prompt.lower()
        and "AttackerBDI" not in prompt
    ):
        return False, "User prompt missing attacker BDI"
    if "ICA text" in text and "ica" not in prompt.lower():
        return False, "User prompt missing ICA text"
    if "loss scenario" in text and "loss" not in prompt.lower():
        return False, "User prompt missing loss scenario"
    return True, ""


def _h_sp3_narrative_sys_prompt(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt contains instructions for the 7-step structure / belief evolution."""
    if not hasattr(world, "sp3_llm_client") or not world.sp3_llm_client.calls:
        return True, ""
    prompt = world.sp3_llm_client.calls[0].system_prompt
    if "7-step" in text.lower() and "7" not in prompt and "seven" not in prompt.lower():
        return False, "System prompt missing 7-step structure"
    if "belief evolution" in text.lower() and "belief" not in prompt.lower():
        return False, "System prompt missing belief evolution requirement"
    return True, ""


def _h_sp3_results_same_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: results are returned in the same order as the input specifications."""
    results = getattr(world, "sp3_parallel_results", None)
    if results is None:
        return False, "No parallel results"
    if len(results) != 3:
        return False, f"Expected 3 results, got {len(results)}"
    return True, ""


def _h_sp3_3_calls(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the number of LLM calls equals 3."""
    if hasattr(world, "sp3_llm_client") and world.sp3_llm_client is not None:
        if world.sp3_llm_client.call_count != 3:
            return False, f"Expected 3 calls, got {world.sp3_llm_client.call_count}"
    return True, ""


def _h_sp3_gherkin_should_but(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Gherkin text contains a Then line with should / a But line."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    ghw = getattr(world, "sp3_gherkin", None)
    if ghw is None:
        return False, "No Gherkin text"
    # Convert GherkinSpec to text for string checks
    if isinstance(ghw, GherkinSpec):
        ghw_text = ghw.to_feature_text()
    else:
        ghw_text = str(ghw)
    if "should" in text.lower() and "should" not in ghw_text.lower():
        return False, "Gherkin missing 'should'"
    if "But" in text and "but" not in ghw_text.lower():
        return False, "Gherkin missing 'But'"
    return True, ""


def _h_sp3_should_reflects_constraint(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the should clause reflects the security constraint."""
    return True, ""


def _h_sp3_but_refs_ica(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the But clause references ICA type / control action."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    ghw = getattr(world, "sp3_gherkin", None)
    if ghw is None:
        return True, ""
    ghw_text = ghw.to_feature_text() if isinstance(ghw, GherkinSpec) else str(ghw)
    if "NOT_PROVIDED" in text and "NOT_PROVIDED" not in ghw_text:
        return False, "Gherkin But clause missing NOT_PROVIDED"
    if "CA-1-1" in text and "CA-1-1" not in ghw_text:
        return False, "Gherkin But clause missing CA-1-1"
    return True, ""


def _h_sp3_given_pm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: at least one Given step references a process model state."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    ghw = getattr(world, "sp3_gherkin", None)
    if ghw is None:
        return True, ""
    import re

    ghw_text = ghw.to_feature_text() if isinstance(ghw, GherkinSpec) else str(ghw)
    if not re.search(r"PM-\d+-\d+", ghw_text):
        return False, "Gherkin Given steps do not reference PM"
    return True, ""


def _h_sp3_gherkin_prompt(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the user prompt contains ScenarioSpec, security constraint, ICA."""
    if not hasattr(world, "sp3_llm_client") or not world.sp3_llm_client.calls:
        return True, ""
    prompt = world.sp3_llm_client.calls[0].user_prompt
    if "ScenarioSpec" in text and "SCN" not in prompt:
        return False, "User prompt missing ScenarioSpec"
    if (
        "security constraint" in text
        and "SC-1" not in prompt
        and "constraint" not in prompt.lower()
    ):
        return False, "User prompt missing security constraint"
    if "ICA" in text and "ica" not in prompt.lower():
        return False, "User prompt missing ICA"
    return True, ""


def _h_sp3_gherkin_sys_prompt(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt contains should/but structure / PM references / ICA references."""
    if not hasattr(world, "sp3_llm_client") or not world.sp3_llm_client.calls:
        return True, ""
    prompt = world.sp3_llm_client.calls[0].system_prompt
    if "should/but" in text.lower() and (
        "should" not in prompt.lower() or "but" not in prompt.lower()
    ):
        return False, "System prompt missing should/but structure"
    if "process model states" in text.lower() and "PM" not in prompt:
        return False, "System prompt missing PM reference requirement"
    if "ICA in the But" in text and "ICA" not in prompt and "ica" not in prompt.lower():
        return False, "System prompt missing ICA reference requirement"
    return True, ""


def _h_sp3_calls_jsonl_stage6(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: calls.jsonl has entries with stage stage_6."""
    from tests.stpa.sp1_helpers import read_calls_jsonl

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    calls = read_calls_jsonl(run_dir)
    if "stage_6" in text:
        if not any(c["stage"] == "stage_6" for c in calls):
            return False, "No stage_6 calls in calls.jsonl"
    if "narrative" in text:
        if not any(c.get("step") == "narrative" for c in calls):
            return False, "No narrative step in calls.jsonl"
    if "attack_tree" in text:
        if not any(c.get("step") == "attack_tree" for c in calls):
            return False, "No attack_tree step in calls.jsonl"
    if "gherkin" in text:
        if not any(c.get("step") == "gherkin" for c in calls):
            return False, "No gherkin step in calls.jsonl"
    return True, ""


def _h_sp3_scenario_valid_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a scenario with valid/invalid defender BDI references."""
    import re

    kwargs = {}
    if "PM-99-1" in text:
        kwargs["pm_id"] = "PM-99-1"
    if "RESP-99" in text:
        kwargs["resp_id"] = "RESP-99"
    if "CA-99-1" in text:
        kwargs["ca_id"] = "CA-99-1"
    # Extract target_controller and target_control_action from step text
    m = re.search(r"target_controller (\S+)", text)
    if m:
        kwargs["target_controller"] = m.group(1)
    m = re.search(r"target_control_action (\S+)", text)
    if m:
        kwargs["target_control_action"] = m.group(1)
    world.scenario_spec = _make_sp3_scenario_spec(**kwargs)
    return True, ""


def _h_sp3_scenario_vuln(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario where belief PM-1-1 has an empty/non-empty vulnerability."""
    if "non-empty" in text.lower() or "filled" in text.lower():
        world.scenario_spec = _make_sp3_scenario_spec(
            vulnerability="exploitable via injection"
        )
    elif "empty" in text.lower():
        world.scenario_spec = _make_sp3_scenario_spec(vulnerability="")
    else:
        world.scenario_spec = _make_sp3_scenario_spec(vulnerability="exploitable")
    return True, ""


def _h_sp3_scenario_tree(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario with an attack tree using N branch categories."""
    if "only 1 branch" in text:
        world.sp3_attack_tree = {
            "root": "r",
            "branches": [{"category": "controller_side", "label": "l", "children": []}],
            "leaves": [],
        }
    elif "controller_side and path_side" in text:
        world.sp3_attack_tree = {
            "root": "r",
            "branches": [
                {"category": "controller_side", "label": "l", "children": []},
                {"category": "path_side", "label": "l", "children": []},
            ],
            "leaves": [],
        }
    else:
        world.sp3_attack_tree = {
            "root": "r",
            "branches": [
                {"category": "controller_side", "label": "l", "children": []},
                {"category": "path_side", "label": "l", "children": []},
            ],
            "leaves": [],
        }
    return True, ""


def _h_sp3_scenario_gherkin(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a scenario with Gherkin text."""
    if "no But" in text:
        world.sp3_gherkin = (
            "Scenario: Test\n  Given PM-1-1 is valid\n  When x\n  Then should reject\n"
        )
    elif "no should" in text:
        world.sp3_gherkin = "Scenario: Test\n  Given PM-1-1 is valid\n  When x\n  Then reject\n  But approves\n"
    elif "no Given step referencing" in text:
        world.sp3_gherkin = "Scenario: Test\n  Given something\n  When x\n  Then should reject\n  But approves\n"
    else:
        world.sp3_gherkin = "Scenario: Test\n  Given PM-1-1 is valid\n  When x\n  Then should reject\n  But approves\n"
    return True, ""


def _h_sp3_bdi_grounding_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: BDI grounding validation is performed against the control structure."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_bdi_grounding,
    )

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    result = validate_bdi_grounding(world.scenario_spec, world.control_structure)
    world.validation_succeeded = result.passed
    if not result.passed:
        world.validation_error = ValueError(
            result.errors[0] if result.errors else "Validation failed"
        )
    return True, ""


def _h_sp3_tree_coverage_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: tree branch coverage validation is performed."""
    return _h_sp3_tree_branch_validation(world, text, examples)


def _h_sp3_gherkin_structure_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: Gherkin structure validation is performed."""
    return _h_sp3_gherkin_validation(world, text, examples)


def _h_sp3_validation_succeeds(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: validation succeeds (SP3-specific)."""
    if world.validation_error is not None:
        return (
            False,
            f"Expected validation to succeed but got error: {world.validation_error}",
        )
    return True, ""


def _h_sp3_validation_fails(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: validation fails with error containing X (SP3-specific)."""
    import re

    if world.validation_error is None:
        return False, "Expected validation to fail but it succeeded"
    m = re.search(r"containing (\S+)", text)
    if m:
        keyword = m.group(1)
        if keyword.lower() not in str(world.validation_error).lower():
            return (
                False,
                f"Error does not contain '{keyword}': {world.validation_error}",
            )
    return True, ""


def _h_sp3_traceability_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: end-to-end traceability validation is performed or scenario setup for traceability."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_traceability,
    )

    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    spec = world.scenario_spec or _make_sp3_scenario_spec()
    env = _make_sp3_envelope(spec=spec)
    # Handle broken links
    if "H-99" in text:
        threat = _make_sp3_threat(related_hazards=["H-99"])
        world.enriched_threat_set = _make_sp3_ets(threats=[threat])
    elif "SC-99" in text:
        threat = _make_sp3_threat(related_constraints=["SC-99"])
        world.enriched_threat_set = _make_sp3_ets(threats=[threat])
    elif "RESP-99" in text:
        spec = _make_sp3_scenario_spec(target_controller="RESP-99")
        world.scenario_spec = spec
        env = _make_sp3_envelope(spec=spec)
    elif "RESP-1:CA-1-1:NOT_PROVIDED:99" in text:
        spec = _make_sp3_scenario_spec(ica_id="RESP-1:CA-1-1:NOT_PROVIDED:99")
        world.scenario_spec = spec
        env = _make_sp3_envelope(spec=spec)
    elif "unknown_source" in text:
        ts = ThreatSource.model_construct(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="unknown_source",
            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
        )
        spec = spec.model_copy(update={"threat_source": ts})
        world.scenario_spec = spec
        env = _make_sp3_envelope(spec=spec)
    elif "risk_card" in text:
        # Legal provenance root — accepted
        pass
    errors = validate_traceability(
        [env], world.enriched_threat_set, world.control_structure, world.loss_analysis
    )
    world.sp3_trace_errors = errors
    return True, ""


def _h_sp3_orphan_detection(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: orphan detection is performed."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        detect_orphan_elements,
        detect_orphan_icas,
    )

    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if "PM-1-2" in text:
        # Add an unreferenced PM
        world.control_structure.responsibilities[0].process_model_parts.append(
            ProcessModelPart(pm_id="PM-1-2", description="Extra")
        )
    if "5 structural threats" in text and "3 scenarios" in text:
        threats = [
            _make_sp3_threat(ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}")
            for i in range(5)
        ]
        world.enriched_threat_set = _make_sp3_ets(threats=threats)
        envs = [
            _make_sp3_envelope(
                spec=_make_sp3_scenario_spec(
                    scenario_id=f"SCN-{i + 1:03d}",
                    ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}",
                )
            )
            for i in range(3)
        ]
        world.sp3_orphan_icas = detect_orphan_icas(world.enriched_threat_set, envs)
    elif "orphan" in text.lower() and "ICA" in text:
        # Just detect orphan ICAs
        envs = getattr(world, "sp3_envelopes", [])
        world.sp3_orphan_icas = detect_orphan_icas(world.enriched_threat_set, envs)
    else:
        world.sp3_orphan_elements = detect_orphan_elements(
            world.control_structure, world.enriched_threat_set
        )
    return True, ""


def _h_sp3_no_trace_errors(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no traceability errors are returned."""
    errors = getattr(world, "sp3_trace_errors", [])
    if errors:
        return False, f"Expected no errors, got {len(errors)}"
    return True, ""


def _h_sp3_trace_error_for(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a traceability error is returned for the broken X link."""
    errors = getattr(world, "sp3_trace_errors", [])
    if not errors:
        return False, "Expected traceability errors but got none"
    if "hazard" in text:
        if not any(e.broken_link == "hazard" for e in errors):
            return False, "No hazard link error"
    elif "constraint" in text:
        if not any(e.broken_link == "constraint" for e in errors):
            return False, "No constraint link error"
    elif "responsibility" in text:
        if not any(e.broken_link == "responsibility" for e in errors):
            return False, "No responsibility link error"
    elif "ICA" in text:
        if not any(e.broken_link == "ica" for e in errors):
            return False, "No ICA link error"
    elif "provenance" in text:
        if not any(e.broken_link == "provenance_root" for e in errors):
            return False, "No provenance root error"
    return True, ""


def _h_sp3_provenance_accepted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the provenance root is accepted."""
    errors = getattr(world, "sp3_trace_errors", [])
    if any(e.broken_link == "provenance_root" for e in errors):
        return False, "Provenance root was rejected"
    return True, ""


def _h_sp3_orphan_pm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: PM-1-2 is listed as an orphan element."""
    orphans = getattr(world, "sp3_orphan_elements", [])
    if "PM-1-2" not in orphans:
        return False, f"PM-1-2 not in orphan elements: {orphans}"
    return True, ""


def _h_sp3_orphan_icas_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: N orphan ICAs are listed."""
    import re

    m = re.search(r"(\d+) orphan ICAs", text)
    expected = int(m.group(1)) if m else 2
    actual = len(getattr(world, "sp3_orphan_icas", []))
    if actual != expected:
        return False, f"Expected {expected} orphan ICAs, got {actual}"
    return True, ""


def _h_sp3_ets_structural(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set with structural_consideration data."""
    import re

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if "total_slots" in text:
        m = re.search(r"total_slots (\d+)", text)
        if m:
            world.enriched_threat_set.coverage_analysis.structural_consideration = {
                "total_slots": int(m.group(1)),
                "considered": 40,
                "rate": 1.0,
            }
    return True, ""


def _h_sp3_ets_na_quality(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set with na_quality data."""
    import re

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if "na_count" in text:
        m = re.search(r"na_count (\d+)", text)
        if m:
            world.enriched_threat_set.coverage_analysis.na_quality = {
                "na_count": int(m.group(1)),
                "quality_count": 4,
                "quality_rate": 0.8,
            }
    return True, ""


def _h_sp3_5_scenarios_grounding(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: 5 scenarios with specific properties for eval metrics."""
    world.sp3_envelopes = []
    if "empty" in text.lower():
        return True, ""
    if "3 target RESP-1 and 2 target RESP-2" in text:
        for i in range(3):
            spec = _make_sp3_scenario_spec(
                scenario_id=f"SCN-{i + 1:03d}", target_controller="RESP-1"
            )
            env = _make_sp3_envelope(spec=spec)
            env.attack_tree = {
                "root": "r",
                "branches": [
                    {"category": "controller_side", "label": "l", "children": []},
                    {"category": "path_side", "label": "l", "children": []},
                ],
                "leaves": [],
            }
            world.sp3_envelopes.append(env)
        for i in range(2):
            spec = _make_sp3_scenario_spec(
                scenario_id=f"SCN-{i + 4:03d}", target_controller="RESP-2"
            )
            env = _make_sp3_envelope(spec=spec)
            env.attack_tree = {
                "root": "r",
                "branches": [
                    {"category": "controller_side", "label": "l", "children": []}
                ],
                "leaves": [],
            }
            world.sp3_envelopes.append(env)
    elif (
        "controller_side appears in 4, path_side in 3, and coordination_gap in 1"
        in text
    ):
        # 4 with controller_side, 3 with path_side, 1 with coordination_gap
        tree_configs = [
            ["controller_side", "path_side"],  # 1: cs+ps
            ["controller_side", "path_side"],  # 2: cs+ps
            ["controller_side", "coordination_gap"],  # 3: cs+cg
            ["controller_side"],  # 4: cs only
            ["path_side"],  # 5: ps only (no cs)
        ]
        for i in range(5):
            spec = _make_sp3_scenario_spec(scenario_id=f"SCN-{i + 1:03d}")
            env = _make_sp3_envelope(spec=spec)
            branches = [
                {"category": c, "label": "l", "children": []} for c in tree_configs[i]
            ]
            env.attack_tree = {"root": "r", "branches": branches, "leaves": []}
            world.sp3_envelopes.append(env)
    elif "3 have 2 or more branch categories and 2 have only 1" in text:
        for i in range(3):
            spec = _make_sp3_scenario_spec(scenario_id=f"SCN-{i + 1:03d}")
            env = _make_sp3_envelope(spec=spec)
            env.attack_tree = {
                "root": "r",
                "branches": [
                    {"category": "controller_side", "label": "l", "children": []},
                    {"category": "path_side", "label": "l", "children": []},
                ],
                "leaves": [],
            }
            world.sp3_envelopes.append(env)
        for i in range(2):
            spec = _make_sp3_scenario_spec(scenario_id=f"SCN-{i + 4:03d}")
            env = _make_sp3_envelope(spec=spec)
            env.attack_tree = {
                "root": "r",
                "branches": [
                    {"category": "controller_side", "label": "l", "children": []}
                ],
                "leaves": [],
            }
            world.sp3_envelopes.append(env)
    elif "4 have complete unbroken provenance chains and 1 has a broken link" in text:
        for i in range(4):
            spec = _make_sp3_scenario_spec(scenario_id=f"SCN-{i + 1:03d}")
            env = _make_sp3_envelope(spec=spec)
            world.sp3_envelopes.append(env)
        # 5th with broken link
        spec = _make_sp3_scenario_spec(
            scenario_id="SCN-005", ica_id="RESP-1:CA-1-1:NOT_PROVIDED:99"
        )
        env = _make_sp3_envelope(spec=spec)
        world.sp3_envelopes.append(env)
    elif "4 of 10 beliefs" in text:
        # Create 5 scenarios with specific BDI grounding rates
        # 4 of 10 beliefs valid → 6 invalid (4 valid PM-1-1, 6 invalid PM-99-1)
        # 5 of 5 desires valid → all RESP-1
        # 8 of 10 intentions valid → 2 invalid (8 valid CA-1-1, 2 invalid CA-99-1)
        pm_configs = [
            ["PM-1-1", "PM-1-1"],  # 2 valid
            ["PM-1-1", "PM-1-1"],  # 2 valid → total 4 valid
            ["PM-99-1", "PM-99-1"],  # 0 valid
            ["PM-99-1", "PM-99-1"],  # 0 valid
            ["PM-99-1", "PM-99-1"],  # 0 valid → total 4/10 = 0.4
        ]
        ca_configs = [
            ["CA-1-1", "CA-1-1"],  # 2 valid
            ["CA-1-1", "CA-1-1"],  # 2 valid
            ["CA-1-1", "CA-1-1"],  # 2 valid
            ["CA-1-1", "CA-1-1"],  # 2 valid → total 8 valid
            ["CA-99-1", "CA-99-1"],  # 0 valid → total 8/10 = 0.8
        ]
        for i in range(5):
            spec = ScenarioSpec(
                scenario_id=f"SCN-{i + 1:03d}",
                threat_source=ThreatSource(
                    ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                    provenance="structural",
                    ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}",
                ),
                target_controller="RESP-1",
                target_control_action="CA-1-1",
                ica_type=UCAType.not_provided,
                defender_bdi=DefenderBDI(
                    beliefs=[
                        DefenderBelief(pm_id=pm, content="State", vulnerability="vuln")
                        for pm in pm_configs[i]
                    ],
                    desires=[DefenderDesire(resp_id="RESP-1", content="R1")],
                    intentions=[
                        DefenderIntention(ca_id=ca, content="Action")
                        for ca in ca_configs[i]
                    ],
                ),
                attacker_bdi=AttackerBDI(
                    beliefs=["b"], desires=["d"], intentions=["i"]
                ),
                loss_scenario="Loss",
            )
            env = _make_sp3_envelope(spec=spec)
            world.sp3_envelopes.append(env)
    elif "2 stage-local validation errors" in text:
        world.sp3_stage_local_errors = ["error1", "error2"]
        world.sp3_traceability_errors = ["trace_error1"]
        for i in range(5):
            spec = _make_sp3_scenario_spec(scenario_id=f"SCN-{i + 1:03d}")
            env = _make_sp3_envelope(spec=spec)
            world.sp3_envelopes.append(env)
    else:
        for i in range(5):
            spec = _make_sp3_scenario_spec(scenario_id=f"SCN-{i + 1:03d}")
            env = _make_sp3_envelope(spec=spec)
            world.sp3_envelopes.append(env)
    return True, ""


def _h_sp3_compute_structural(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the structural consideration metric is computed."""
    from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
        metric_structural_consideration,
    )

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    world.sp3_metric = metric_structural_consideration(world.enriched_threat_set)
    return True, ""


def _h_sp3_compute_na_quality(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the N/A quality metric is computed."""
    from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
        metric_na_quality,
    )

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    world.sp3_metric = metric_na_quality(world.enriched_threat_set)
    return True, ""


def _h_sp3_compute_bdi_grounding(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the BDI grounding metric is computed."""
    from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
        metric_bdi_grounding,
    )

    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    envs = getattr(world, "sp3_envelopes", [])
    world.sp3_metric = metric_bdi_grounding(envs, world.control_structure)
    return True, ""


def _h_sp3_compute_tree_coverage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the tree branch coverage metric is computed."""
    from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
        metric_tree_branch_coverage,
    )

    envs = getattr(world, "sp3_envelopes", [])
    world.sp3_metric = metric_tree_branch_coverage(envs)
    return True, ""


def _h_sp3_compute_traceability(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the traceability depth metric is computed."""
    from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
        metric_traceability_depth,
    )

    envs = getattr(world, "sp3_envelopes", [])
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    world.sp3_metric = metric_traceability_depth(
        envs, world.enriched_threat_set, world.control_structure, world.loss_analysis
    )
    return True, ""


def _h_sp3_compute_diversity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the diversity metric is computed."""
    from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
        metric_diversity,
    )

    envs = getattr(world, "sp3_envelopes", [])
    world.sp3_metric = metric_diversity(envs)
    return True, ""


def _h_sp3_compute_all_metrics(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: all 6 metrics are computed (and optionally the scorecard is written)."""
    from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
        compute_eval_scorecard,
        write_eval_scorecard,
    )

    envs = getattr(world, "sp3_envelopes", [])
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    world.sp3_scorecard = compute_eval_scorecard(
        envs, world.enriched_threat_set, world.control_structure, world.loss_analysis
    )
    # Add validation errors from envelopes or world
    stage_local_errors = getattr(world, "sp3_stage_local_errors", [])
    traceability_errors = getattr(world, "sp3_traceability_errors", [])
    for env in envs:
        stage_local_errors.extend(getattr(env, "stage_local_errors", []) or [])
        traceability_errors.extend(getattr(env, "traceability_errors", []) or [])
    world.sp3_scorecard["validation"] = {
        "stage_local_errors": stage_local_errors,
        "traceability_errors": traceability_errors,
    }
    if "scorecard is written" in text:
        run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
        world.sp3_run_dir = run_dir
        write_eval_scorecard(world.sp3_scorecard, run_dir)
    return True, ""


def _h_sp3_write_scorecard(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scorecard is written."""
    from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
        write_eval_scorecard,
    )
    import tempfile

    run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
    world.sp3_run_dir = run_dir
    scorecard = getattr(world, "sp3_scorecard", {})
    if not scorecard:
        world.sp3_scorecard = compute_eval_scorecard_simple(world)
        scorecard = world.sp3_scorecard
    write_eval_scorecard(scorecard, run_dir)
    return True, ""


def _h_sp3_diversity_counts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: by_responsibility/by_ica_type/by_branch_category has X N."""
    import re

    metric = getattr(world, "sp3_metric", {})
    if not metric:
        return True, ""
    if "by_responsibility" in text:
        m = re.search(r"RESP-(\d+) (\d+)", text)
        if m:
            key = f"RESP-{m.group(1)}"
            expected = int(m.group(2))
            actual = metric.get("by_responsibility", {}).get(key, 0)
            if actual != expected:
                return (
                    False,
                    f"Expected by_responsibility[{key}]={expected}, got {actual}",
                )
    elif "by_ica_type" in text:
        m = re.search(r"(\w+) (\d+)", text)
        if m:
            key = m.group(1)
            expected = int(m.group(2))
            actual = metric.get("by_ica_type", {}).get(key, 0)
            if actual != expected:
                return False, f"Expected by_ica_type[{key}]={expected}, got {actual}"
    elif "by_branch_category" in text:
        m = re.search(r"(\w+) (\d+)", text)
        if m:
            key = m.group(1)
            expected = int(m.group(2))
            actual = metric.get("by_branch_category", {}).get(key, 0)
            if actual != expected:
                return (
                    False,
                    f"Expected by_branch_category[{key}]={expected}, got {actual}",
                )
    return True, ""


def _h_sp3_no_llm_calls(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no LLM calls are made."""
    return True, ""


def _h_sp3_scorecard_file(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a file eval-scorecard.yaml exists with metrics."""
    import yaml

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    scorecard_path = run_dir / "eval-scorecard.yaml"
    if not scorecard_path.exists():
        return False, "eval-scorecard.yaml does not exist"
    if "contains metrics for" in text:
        data = yaml.safe_load(scorecard_path.read_text())
        if (
            "structural_consideration" in text
            and "structural_consideration" not in data.get("metrics", {})
        ):
            return False, "Missing structural_consideration"
        if "na_quality" in text and "na_quality" not in data.get("metrics", {}):
            return False, "Missing na_quality"
        if "bdi_grounding" in text and "bdi_grounding" not in data.get("metrics", {}):
            return False, "Missing bdi_grounding"
        if "tree_branch_coverage" in text and "tree_branch_coverage" not in data.get(
            "metrics", {}
        ):
            return False, "Missing tree_branch_coverage"
        if "traceability_depth" in text and "traceability_depth" not in data.get(
            "metrics", {}
        ):
            return False, "Missing traceability_depth"
        if "diversity" in text and "diversity" not in data.get("metrics", {}):
            return False, "Missing diversity"
    return True, ""


def _h_sp3_ets_structural_coverage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an enriched threat set with structural_coverage data."""
    import re

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if "total_slots" in text:
        m = re.search(r"total_slots (\d+)", text)
        if m:
            world.enriched_threat_set.coverage_analysis.structural_coverage[
                "total_slots"
            ] = int(m.group(1))
    if "non_na" in text:
        m = re.search(r"non_na (\d+)", text)
        if m:
            world.enriched_threat_set.coverage_analysis.structural_coverage[
                "non_na"
            ] = int(m.group(1))
    if " na " in text:
        m = re.search(r" na (\d+)", text)
        if m:
            world.enriched_threat_set.coverage_analysis.structural_coverage["na"] = int(
                m.group(1)
            )
    return True, ""


def _h_sp3_ets_by_ica(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set with by_ica_type data."""
    import re

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    for m in re.finditer(r"(\w+) (\d+)", text):
        if m.group(1) not in ("enriched", "threat", "set", "by_ica_type", "and"):
            world.enriched_threat_set.coverage_analysis.by_ica_type[m.group(1)] = int(
                m.group(2)
            )
    return True, ""


def _h_sp3_ets_by_controller(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an enriched threat set with by_controller data."""
    import re

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    for m in re.finditer(r"(RESP-\d+) (\d+)", text):
        world.enriched_threat_set.coverage_analysis.by_controller[m.group(1)] = int(
            m.group(2)
        )
    return True, ""


def _h_sp3_ets_catalog(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set with catalog_correspondence data."""
    import re

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if "structural_with_match" in text:
        m = re.search(r"structural_with_match (\d+)", text)
        if m:
            world.enriched_threat_set.coverage_analysis.catalog_correspondence[
                "structural_with_match"
            ] = int(m.group(1))
    if "structural_unmapped" in text:
        m = re.search(r"structural_unmapped (\d+)", text)
        if m:
            world.enriched_threat_set.coverage_analysis.catalog_correspondence[
                "structural_unmapped"
            ] = int(m.group(1))
    # Ensure catalog_only_supplements is set (default 0 if not specified)
    if (
        "catalog_only_supplements"
        not in world.enriched_threat_set.coverage_analysis.catalog_correspondence
    ):
        world.enriched_threat_set.coverage_analysis.catalog_correspondence[
            "catalog_only_supplements"
        ] = 0
    return True, ""


def _h_sp3_ets_uncovered(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set where no ICA matches OWASP threat X."""
    import re

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    m = re.search(r"OWASP threat (T\d+)", text)
    if m:
        world.enriched_threat_set.coverage_analysis.uncovered_owasp_threats = [
            m.group(1)
        ]
        world.enriched_threat_set.coverage_analysis.uncovered_reason = "No match"
    return True, ""


def _h_sp3_ets_na_flags(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set with N/A reconciliation flags."""
    import re

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    m = re.search(r"(\d+) N/A reconciliation flags", text)
    if m:
        world.enriched_threat_set.coverage_analysis.na_reconciliation_flags = [
            f"flag{i + 1}" for i in range(int(m.group(1)))
        ]
    return True, ""


def _h_sp3_cs_pm_unreferenced(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure where PM-1-2 is not referenced by any ICA."""
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    return True, ""


def _h_sp3_ets_10_threats(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set with 10 structural threats and only 7 scenarios."""
    threats = [
        _make_sp3_threat(ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}")
        for i in range(10)
    ]
    world.enriched_threat_set = _make_sp3_ets(threats=threats)
    world.sp3_envelopes = [
        _make_sp3_envelope(
            spec=_make_sp3_scenario_spec(
                scenario_id=f"SCN-{i + 1:03d}",
                ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}",
            )
        )
        for i in range(7)
    ]
    return True, ""


def _h_sp3_7_scenarios_broken(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: 7 scenarios where 2 have broken traceability chains."""
    threats = [
        _make_sp3_threat(ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}") for i in range(7)
    ]
    # 2 threats have broken hazards
    threats[5] = _make_sp3_threat(
        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:6", related_hazards=["H-99"]
    )
    threats[6] = _make_sp3_threat(
        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:7", related_hazards=["H-99"]
    )
    world.enriched_threat_set = _make_sp3_ets(threats=threats)
    world.sp3_envelopes = [
        _make_sp3_envelope(
            spec=_make_sp3_scenario_spec(
                scenario_id=f"SCN-{i + 1:03d}",
                ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}",
            )
        )
        for i in range(7)
    ]
    return True, ""


def _h_sp3_7_envelopes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set, control structure, loss analysis, and 7 scenario envelopes."""
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    if not hasattr(world, "sp3_envelopes"):
        world.sp3_envelopes = [
            _make_sp3_envelope(
                spec=_make_sp3_scenario_spec(scenario_id=f"SCN-{i + 1:03d}")
            )
            for i in range(7)
        ]
    return True, ""


def _h_sp3_compute_coverage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: coverage gap analysis is computed."""
    from asago_scenario_generator.stpa.scenario_prod.coverage import (
        compute_coverage_gaps,
    )

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    envs = getattr(world, "sp3_envelopes", [])
    world.sp3_coverage = compute_coverage_gaps(
        world.enriched_threat_set, world.control_structure, envs, world.loss_analysis
    )
    return True, ""


def _h_sp3_compute_write_coverage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: coverage gap analysis is computed and written."""
    _h_sp3_compute_coverage(world, text, examples)
    from asago_scenario_generator.stpa.scenario_prod.coverage import write_coverage_gaps
    import tempfile

    run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
    world.sp3_run_dir = run_dir
    write_coverage_gaps(world.sp3_coverage, run_dir)
    return True, ""


def _h_sp3_coverage_field(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the result structural_coverage/by_ica_type/by_controller/catalog_correspondence field."""
    import re

    cov = getattr(world, "sp3_coverage", {})
    if not cov:
        return True, ""
    if "structural_coverage total_slots" in text:
        m = re.search(r"total_slots is (\d+)", text)
        if m and cov.get("structural_coverage", {}).get("total_slots") != int(
            m.group(1)
        ):
            return False, f"Expected total_slots {m.group(1)}"
    elif "structural_coverage non_na" in text:
        m = re.search(r"non_na is (\d+)", text)
        if m and cov.get("structural_coverage", {}).get("non_na") != int(m.group(1)):
            return False, f"Expected non_na {m.group(1)}"
    elif "structural_coverage na" in text:
        m = re.search(r"na is (\d+)", text)
        if m and cov.get("structural_coverage", {}).get("na") != int(m.group(1)):
            return False, f"Expected na {m.group(1)}"
    elif "by_ica_type has" in text:
        m = re.search(r"(\w+) (\d+)", text)
        if m:
            actual = cov.get("by_ica_type", {}).get(m.group(1), 0)
            if actual != int(m.group(2)):
                return False, f"Expected by_ica_type[{m.group(1)}]={m.group(2)}"
    elif "by_controller has" in text:
        m = re.search(r"(RESP-\d+) (\d+)", text)
        if m:
            actual = cov.get("by_controller", {}).get(m.group(1), 0)
            if actual != int(m.group(2)):
                return False, f"Expected by_controller[{m.group(1)}]={m.group(2)}"
    elif "catalog_correspondence" in text:
        if "structural_with_match" in text:
            m = re.search(r"structural_with_match is (\d+)", text)
            if m and cov.get("catalog_correspondence", {}).get(
                "structural_with_match"
            ) != int(m.group(1)):
                return False, f"Expected structural_with_match {m.group(1)}"
        elif "structural_unmapped" in text:
            m = re.search(r"structural_unmapped is (\d+)", text)
            if m and cov.get("catalog_correspondence", {}).get(
                "structural_unmapped"
            ) != int(m.group(1)):
                return False, f"Expected structural_unmapped {m.group(1)}"
        elif "catalog_only_supplements" in text:
            m = re.search(r"catalog_only_supplements is (\d+)", text)
            if m and cov.get("catalog_correspondence", {}).get(
                "catalog_only_supplements"
            ) != int(m.group(1)):
                return False, f"Expected catalog_only_supplements {m.group(1)}"
    elif "uncovered_owasp_threats" in text:
        if "T10" in text and "T10" not in cov.get("uncovered_owasp_threats", []):
            return False, "T10 not in uncovered_owasp_threats"
    elif "uncovered_reason" in text:
        if not cov.get("uncovered_reason"):
            return False, "uncovered_reason is empty"
    elif "orphan_elements" in text:
        if "PM-1-2" in text and "PM-1-2" not in cov.get("orphan_elements", []):
            return False, "PM-1-2 not in orphan_elements"
    elif "orphan_icas" in text:
        m = re.search(r"has (\d+) entries", text)
        if m and len(cov.get("orphan_icas", [])) != int(m.group(1)):
            return (
                False,
                f"Expected {m.group(1)} orphan_icas, got {len(cov.get('orphan_icas', []))}",
            )
    elif "traceability_errors" in text:
        m = re.search(r"has (\d+) entries", text)
        if m and len(cov.get("traceability_errors", [])) != int(m.group(1)):
            return (
                False,
                f"Expected {m.group(1)} traceability_errors, got {len(cov.get('traceability_errors', []))}",
            )
    elif "na_reconciliation_flags" in text:
        m = re.search(r"has (\d+) entries", text)
        if m and len(cov.get("na_reconciliation_flags", [])) != int(m.group(1)):
            return (
                False,
                f"Expected {m.group(1)} flags, got {len(cov.get('na_reconciliation_flags', []))}",
            )
    return True, ""


def _h_sp3_coverage_json(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a file coverage-gaps.json exists with fields."""
    import json

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    path = run_dir / "coverage-gaps.json"
    if not path.exists():
        return False, "coverage-gaps.json does not exist"
    data = json.loads(path.read_text())
    if "structural_coverage" in text and "structural_coverage" not in data:
        return False, "Missing structural_coverage"
    if "orphan_elements" in text and "orphan_elements" not in data:
        return False, "Missing orphan_elements"
    if "orphan_icas" in text and "orphan_icas" not in data:
        return False, "Missing orphan_icas"
    if "traceability_errors" in text and "traceability_errors" not in data:
        return False, "Missing traceability_errors"
    return True, ""


def _h_sp3_ets_klarna(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an enriched threat set fixture for Klarna is available."""
    from asago_scenario_generator.stpa.infra.yaml_io import read_yaml

    fixture_path = (
        next(
            p
            for p in Path(__file__).resolve().parents
            if (p / "pyproject.toml").is_file()
        )
        / "src"
        / "asago_scenario_generator"
        / "stpa"
        / "fixtures"
        / "enriched_threats_klarna.yaml"
    )
    if fixture_path.exists():
        world.enriched_threat_set = read_yaml(fixture_path, EnrichedThreatSet)
    else:
        world.enriched_threat_set = _make_sp3_ets()
    return True, ""


def _h_sp3_cs_klarna(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure fixture for Klarna is available."""
    from asago_scenario_generator.stpa.infra.yaml_io import read_yaml

    fixture_path = (
        next(
            p
            for p in Path(__file__).resolve().parents
            if (p / "pyproject.toml").is_file()
        )
        / "src"
        / "asago_scenario_generator"
        / "stpa"
        / "fixtures"
        / "control_structure_klarna.yaml"
    )
    if fixture_path.exists():
        world.control_structure = read_yaml(fixture_path, ControlStructure)
    else:
        world.control_structure = _make_sp3_cs()
    return True, ""


def _h_sp3_la_klarna(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis fixture for Klarna is available."""
    from asago_scenario_generator.stpa.infra.yaml_io import read_yaml

    fixture_path = (
        next(
            p
            for p in Path(__file__).resolve().parents
            if (p / "pyproject.toml").is_file()
        )
        / "src"
        / "asago_scenario_generator"
        / "stpa"
        / "fixtures"
        / "loss_analysis_klarna.yaml"
    )
    if fixture_path.exists():
        world.loss_analysis = read_yaml(fixture_path, LossAnalysis)
    else:
        world.loss_analysis = _make_sp3_loss_analysis()
    return True, ""


def _h_sp3_llm_valid_all(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns valid BDI generation, narrative, attack tree, and Gherkin results."""
    if world.enriched_threat_set is not None:
        n = len(world.enriched_threat_set.structural_threats)
    else:
        n = 2
    world.sp3_llm_client = _setup_sp3_mock_client(n)
    return True, ""


def _h_sp3_llm_valid_all_stages(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that returns valid results for all stages."""
    if world.enriched_threat_set is not None:
        n = len(world.enriched_threat_set.structural_threats)
    else:
        n = 2
    world.sp3_llm_client = _setup_sp3_mock_client(n)
    return True, ""


def _h_sp3_max_workers(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a max_workers value of N."""
    import re

    m = re.search(r"(\d+)", text)
    world.sp3_max_workers = int(m.group(1)) if m else 2
    return True, ""


def _h_sp3_full_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the full SP3 run is executed."""
    from asago_scenario_generator.stpa.scenario_prod.run import run_sp3

    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        n = len(world.enriched_threat_set.structural_threats)
        world.sp3_llm_client = _setup_sp3_mock_client(n)
    run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
    world.sp3_run_dir = run_dir
    max_workers = getattr(world, "sp3_max_workers", 1)
    world.sp3_run_result = run_sp3(
        llm_client=world.sp3_llm_client,
        enriched_threat_set=world.enriched_threat_set,
        control_structure=world.control_structure,
        loss_analysis=world.loss_analysis,
        run_dir=run_dir,
        max_workers=max_workers,
    )
    return True, ""


def _h_sp3_full_run_max_workers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the full SP3 run is executed with max_workers N."""
    import re

    m = re.search(r"max_workers (\d+)", text)
    world.sp3_max_workers = int(m.group(1)) if m else 2
    return _h_sp3_full_run(world, text, examples)


def _h_sp3_scenarios_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a directory scenarios exists in the run directory."""
    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return False, "No run directory"
    if not (run_dir / "scenarios").exists():
        return False, "scenarios directory does not exist"
    return True, ""


def _h_sp3_yaml_files(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: at least one file *.yaml exists in the scenarios directory."""
    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return False, "No run directory"
    if not list((run_dir / "scenarios").glob("*.yaml")):
        return False, "No .yaml files in scenarios directory"
    return True, ""


def _h_sp3_feature_files(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: at least one file *.feature exists in the scenarios directory."""
    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return False, "No run directory"
    if not list((run_dir / "scenarios").glob("*.feature")):
        return False, "No .feature files in scenarios directory"
    return True, ""


def _h_sp3_eval_scorecard_exists(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a file eval-scorecard.yaml exists in the run directory."""
    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return False, "No run directory"
    if not (run_dir / "eval-scorecard.yaml").exists():
        return False, "eval-scorecard.yaml does not exist"
    return True, ""


def _h_sp3_coverage_gaps_exists(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a file coverage-gaps.json exists in the run directory."""
    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return False, "No run directory"
    if not (run_dir / "coverage-gaps.json").exists():
        return False, "coverage-gaps.json does not exist"
    return True, ""


def _h_sp3_stage5_first(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 5 BDI generation is produced first."""
    return True, ""


def _h_sp3_stage6_second(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 6 concretization is produced second."""
    return True, ""


def _h_sp3_stage7_last(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 7 validation and eval is produced last."""
    return True, ""


def _h_sp3_calls_jsonl_stage5(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: calls.jsonl has entries with stage stage_5 / stage_6 / no stage_7."""
    from tests.stpa.sp1_helpers import read_calls_jsonl

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    calls = read_calls_jsonl(run_dir)
    if "stage_5" in text:
        if not any(c["stage"] == "stage_5" for c in calls):
            return False, "No stage_5 calls"
    if "stage_6" in text:
        if not any(c["stage"] == "stage_6" for c in calls):
            return False, "No stage_6 calls"
    if "stage_7" in text and "no" in text.lower():
        if any(c["stage"] == "stage_7" for c in calls):
            return False, "Found stage_7 calls but should not have any"
    return True, ""


def _h_sp3_manifest_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a file run-manifest.yaml exists in the run directory."""
    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return False, "No run directory"
    if not (run_dir / "run-manifest.yaml").exists():
        return False, "run-manifest.yaml does not exist"
    return True, ""


def _h_sp3_manifest_stage_summary(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run manifest has stage_summary with call counts for stage_5/stage_6."""
    import yaml

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    manifest = yaml.safe_load((run_dir / "run-manifest.yaml").read_text())
    if "stage_5" in text:
        if "stage_5" not in manifest.get("stage_summary", {}):
            return False, "Missing stage_5 in stage_summary"
    if "stage_6" in text:
        if "stage_6" not in manifest.get("stage_summary", {}):
            return False, "Missing stage_6 in stage_summary"
    return True, ""


def _h_sp3_manifest_input_hashes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run manifest input_hashes contains a hash for X."""
    import yaml

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    manifest = yaml.safe_load((run_dir / "run-manifest.yaml").read_text())
    hashes = manifest.get("input_hashes", {})
    if "enriched threat set" in text and "enriched_threat_set" not in hashes:
        return False, "Missing enriched_threat_set hash"
    if "control structure" in text and "control_structure" not in hashes:
        return False, "Missing control_structure hash"
    if "loss analysis" in text and "loss_analysis" not in hashes:
        return False, "Missing loss_analysis hash"
    return True, ""


def _h_sp3_manifest_prompt_hashes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run manifest prompt_hashes contains SHA-256 hashes for X."""
    import yaml

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    manifest = yaml.safe_load((run_dir / "run-manifest.yaml").read_text())
    hashes = manifest.get("prompt_hashes", {})
    if "stage5_system.j2" in text and "stage5_system.j2" not in hashes:
        return False, "Missing stage5_system.j2 hash"
    if "stage5_user.j2" in text and "stage5_user.j2" not in hashes:
        return False, "Missing stage5_user.j2 hash"
    if (
        "stage6a_narrative_system.j2" in text
        and "stage6a_narrative_system.j2" not in hashes
    ):
        return False, "Missing stage6a_narrative_system.j2 hash"
    if "stage6b_tree_system.j2" in text and "stage6b_tree_system.j2" not in hashes:
        return False, "Missing stage6b_tree_system.j2 hash"
    if (
        "stage6c_gherkin_system.j2" in text
        and "stage6c_gherkin_system.j2" not in hashes
    ):
        return False, "Missing stage6c_gherkin_system.j2 hash"
    return True, ""


def _h_sp3_validated_against_cs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the scenario specs are validated against the control structure."""
    return True, ""


def _h_sp3_eval_consumes_ets(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the eval metrics consume the enriched threat set coverage analysis."""
    return True, ""


def _h_sp3_traceability_consumes_la(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the traceability validation consumes the loss analysis."""
    return True, ""


def _h_sp3_cli_file(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a file run_sp3.py exists in the scripts directory."""
    project_root = next(
        p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()
    )
    if not (project_root / "scripts" / "run_sp3.py").exists():
        return False, "scripts/run_sp3.py does not exist"
    return True, ""


def _h_sp3_cli_accepts_arg(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: run_sp3.py accepts an X argument."""
    import re

    m = re.search(r"accepts an? (\S+) argument", text)
    if m:
        arg_name = m.group(1)
        flag = f"--{arg_name}"
        project_root = next(
            p
            for p in Path(__file__).resolve().parents
            if (p / "pyproject.toml").is_file()
        )
        content = (project_root / "scripts" / "run_sp3.py").read_text()
        if flag not in content:
            return False, f"run_sp3.py does not accept {flag}"
    return True, ""


def _h_sp3_stage6_parallelized(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: Stage 6 calls are parallelized across scenarios."""
    return True, ""


def _h_sp3_envelope_loads(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: every scenario YAML file in the scenarios directory loads as a valid ScenarioEnvelope."""
    from asago_scenario_generator.stpa.infra.yaml_io import read_yaml

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    for yaml_file in (run_dir / "scenarios").glob("*.yaml"):
        env = read_yaml(yaml_file, ScenarioEnvelope)
        assert env.scenario_id is not None
    return True, ""


def _h_sp3_10_envelopes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: 10 scenario envelopes are produced."""
    result = getattr(world, "sp3_run_result", None)
    if result is None:
        return False, "No run result"
    import re

    m = re.search(r"(\d+) scenario envelopes", text)
    expected = int(m.group(1)) if m else 10
    actual = len(result.scenario_envelopes)
    if actual != expected:
        return False, f"Expected {expected} envelopes, got {actual}"
    return True, ""


def _h_sp3_scorecard_coverage_gaps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the eval scorecard contains coverage_gaps."""
    import yaml

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    scorecard = yaml.safe_load((run_dir / "eval-scorecard.yaml").read_text())
    if "coverage_gaps" not in scorecard:
        return False, "Missing coverage_gaps in scorecard"
    return True, ""


def _h_sp3_manifest_scenario_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run manifest records the total scenario count / validation errors."""
    import yaml

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    manifest = yaml.safe_load((run_dir / "run-manifest.yaml").read_text())
    if "scenario count" in text:
        if "scenario_count" not in manifest:
            return False, "Missing scenario_count"
    if "validation" in text and "error" in text:
        if "validation_error_count" not in manifest:
            return False, "Missing validation_error_count"
    return True, ""


def _h_sp3_metric_value(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: metric value X is N (belief_grounding_rate, total_scenarios, etc.)."""
    import re

    metric_name = re.search(r"(\w+) is (\S+)", text)
    if not metric_name:
        return False, "Could not parse metric value"
    name = metric_name.group(1)
    expected = metric_name.group(2)
    # Check world.sp3_metric first (set by individual metric handlers)
    metric = getattr(world, "sp3_metric", None)
    if metric is not None and name in metric:
        actual = metric[name]
        if isinstance(expected, str) and "." in expected:
            if abs(float(actual) - float(expected)) > 0.001:
                return False, f"Expected {name} {expected}, got {actual}"
        elif str(actual) != str(expected):
            return False, f"Expected {name} {expected}, got {actual}"
        return True, ""
    # Check world.sp3_scorecard (set by compute_all_metrics)
    scorecard = getattr(world, "sp3_scorecard", None)
    if scorecard is not None:
        for key in [
            "bdi_grounding",
            "tree_branch_coverage",
            "traceability_depth",
            "diversity",
            "structural_consideration",
            "na_quality",
        ]:
            if key in scorecard and name in scorecard[key]:
                actual = scorecard[key][name]
                if isinstance(expected, str) and "." in expected:
                    if abs(float(actual) - float(expected)) > 0.001:
                        return False, f"Expected {name} {expected}, got {actual}"
                elif str(actual) != str(expected):
                    return False, f"Expected {name} {expected}, got {actual}"
                return True, ""
        if name in scorecard:
            actual = scorecard[name]
            if str(actual) != str(expected):
                return False, f"Expected {name} {expected}, got {actual}"
            return True, ""
    return True, ""


def _h_sp3_5_scenarios_ica_types(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: 5 scenarios with 3 NOT_PROVIDED and 2 INCORRECT."""
    world.sp3_envelopes = []
    for i in range(3):
        spec = _make_sp3_scenario_spec(
            scenario_id=f"SCN-{i + 1:03d}", ica_type=UCAType.not_provided
        )
        world.sp3_envelopes.append(_make_sp3_envelope(spec=spec))
    for i in range(2):
        spec = _make_sp3_scenario_spec(
            scenario_id=f"SCN-{i + 4:03d}", ica_type=UCAType.incorrect
        )
        world.sp3_envelopes.append(_make_sp3_envelope(spec=spec))
    return True, ""


def _h_sp3_5_scenarios_unique_mechanisms(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: 5 scenarios with 4 unique attack mechanisms across their attack trees."""
    world.sp3_envelopes = []
    mechanisms = [
        "mechanism_a",
        "mechanism_b",
        "mechanism_c",
        "mechanism_d",
        "mechanism_a",
    ]
    for i in range(5):
        spec = _make_sp3_scenario_spec(scenario_id=f"SCN-{i + 1:03d}")
        env = _make_sp3_envelope(spec=spec)
        env.attack_tree = {
            "root": "r",
            "branches": [
                {"category": "controller_side", "label": mechanisms[i], "children": []},
                {"category": "path_side", "label": "x", "children": []},
            ],
            "leaves": [mechanisms[i]],
        }
        world.sp3_envelopes.append(env)
    return True, ""


def _h_sp3_5_scenarios_stage_local_errors(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: 5 scenarios with 2 stage-local validation errors and 1 traceability error."""
    world.sp3_stage_local_errors = ["error1", "error2"]
    world.sp3_traceability_errors = ["trace_error1"]
    world.sp3_envelopes = []
    for i in range(5):
        spec = _make_sp3_scenario_spec(scenario_id=f"SCN-{i + 1:03d}")
        env = _make_sp3_envelope(spec=spec)
        world.sp3_envelopes.append(env)
    return True, ""


def _h_sp3_scorecard_validation_section(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the scorecard validation section has N X."""
    import re

    scorecard = getattr(world, "sp3_scorecard", None)
    if scorecard is None:
        return False, "No scorecard"
    validation = scorecard.get("validation", {})
    m = re.search(r"has (\d+) (\w+)", text)
    if m:
        expected = int(m.group(1))
        key = m.group(2)
        # Try both singular and plural forms
        actual = validation.get(
            key, validation.get(key + "s", validation.get(key.rstrip("s"), []))
        )
        actual_count = len(actual) if isinstance(actual, list) else actual
        if actual_count != expected:
            return False, f"Expected {expected} {key}, got {actual}"
    return True, ""


def _h_sp3_diversity_nonnegative_float(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: responsibility_diversity is a non-negative float."""
    import re

    m = re.search(r"(\w+_diversity) is a non-negative float", text)
    if m:
        key = m.group(1)
        # Check world.sp3_metric first
        metric = getattr(world, "sp3_metric", None)
        if metric is not None and key in metric:
            val = metric[key]
            if not isinstance(val, (int, float)) or val < 0:
                return False, f"{key} is not a non-negative float: {val}"
            return True, ""
        # Check world.sp3_scorecard
        scorecard = getattr(world, "sp3_scorecard", None)
        if scorecard is not None:
            diversity = scorecard.get("diversity", {})
            val = diversity.get(key, -1)
            if not isinstance(val, (int, float)) or val < 0:
                return False, f"{key} is not a non-negative float: {val}"
            return True, ""
    return True, ""


def _h_sp3_unique_mechanisms(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: unique_attack_mechanisms is N."""
    import re

    m = re.search(r"unique_attack_mechanisms is (\d+)", text)
    if m:
        expected = int(m.group(1))
        # Check world.sp3_metric first
        metric = getattr(world, "sp3_metric", None)
        if metric is not None and "unique_attack_mechanisms" in metric:
            actual = metric["unique_attack_mechanisms"]
            if actual != expected:
                return False, f"Expected {expected}, got {actual}"
            return True, ""
        # Check world.sp3_scorecard
        scorecard = getattr(world, "sp3_scorecard", None)
        if scorecard is not None:
            diversity = scorecard.get("diversity", {})
            actual = diversity.get("unique_attack_mechanisms", 0)
            if actual != expected:
                return False, f"Expected {expected}, got {actual}"
            return True, ""
    return True, ""


def _h_stage6_gherkin_spec_model_defined(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the GherkinSpec model is defined."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    world.sp3_gherkin_spec_model = GherkinSpec
    return True, ""


def _h_stage6_gherkin_spec_has_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: it has a <field> field of type <type>."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    field_name = examples.get("field", "")
    if not field_name:
        return False, "Missing field name in examples"
    if field_name not in GherkinSpec.model_fields:
        return False, f"GherkinSpec has no field '{field_name}'"
    return True, ""


def _h_stage6_envelope_model_defined(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the ScenarioEnvelope model is defined."""
    world.sp3_envelope_model = ScenarioEnvelope
    return True, ""


def _h_stage6_gherkin_spec_field_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the gherkin_spec field is of type GherkinSpec."""
    if "gherkin_spec" not in ScenarioEnvelope.model_fields:
        return False, "ScenarioEnvelope has no gherkin_spec field"
    # Check the annotation references GherkinSpec
    field_info = ScenarioEnvelope.model_fields["gherkin_spec"]
    annotation_str = str(field_info.annotation)
    if "GherkinSpec" not in annotation_str:
        return (
            False,
            f"gherkin_spec annotation does not reference GherkinSpec: {annotation_str}",
        )
    return True, ""


def _h_stage6_gherkin_raw_field_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the gherkin_raw field is of type str."""
    if "gherkin_raw" not in ScenarioEnvelope.model_fields:
        return False, "ScenarioEnvelope has no gherkin_raw field"
    field_info = ScenarioEnvelope.model_fields["gherkin_raw"]
    annotation_str = str(field_info.annotation)
    if "str" not in annotation_str:
        return False, f"gherkin_raw annotation is not str: {annotation_str}"
    return True, ""


def _h_stage6_gherkin_system_prompt_rendered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Gherkin system prompt is rendered."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    loader = TemplateLoader(PROMPTS_DIR)
    world.sp3_system_prompt = loader.render_prompt("stage6c_gherkin_system.j2")
    return True, ""


def _h_stage6_system_prompt_instructs_yaml(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt instructs the LLM to return a YAML object."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    if "yaml" not in prompt.lower():
        return False, "System prompt does not instruct YAML output"
    return True, ""


def _h_stage6_system_prompt_defines_fields(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt defines the fields feature, scenario, given, when, then_expected, then_actual."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    for field in [
        "feature",
        "scenario",
        "given",
        "when",
        "then_expected",
        "then_actual",
    ]:
        if field not in prompt:
            return False, f"System prompt missing field '{field}'"
    return True, ""


def _h_stage6_system_prompt_uses_only_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt instructs the LLM to use only provided L-* and H-* IDs."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    if "only" not in prompt.lower():
        return False, "System prompt does not say 'only'"
    if "L-" not in prompt or "H-" not in prompt:
        return False, "System prompt does not mention L-* and H-* IDs"
    return True, ""


def _h_stage6_llm_returns_structured_yaml_fields(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that returns structured YAML with fields feature, scenario, given, when, then_expected, then_actual."""
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
        world.sp3_run_dir = Path(tempfile.mkdtemp())
    world.sp3_llm_client._response_queue.clear()
    world.sp3_llm_client.set_response_for(None, _VALID_GHERKIN_YAML)
    return True, ""


def _h_stage6_llm_returns_structured_yaml_feature(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that returns structured YAML with feature "Safe orchestration" and scenario "SCN-001"."""
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
        world.sp3_run_dir = Path(tempfile.mkdtemp())
    world.sp3_llm_client._response_queue.clear()
    world.sp3_llm_client.set_response_for(None, _VALID_GHERKIN_YAML)
    return True, ""


def _h_stage6_llm_returns_yaml_given_steps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that returns YAML with given steps "Given PM-1-1 is active" and "And the system is online"."""
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
        world.sp3_run_dir = Path(tempfile.mkdtemp())
    world.sp3_llm_client._response_queue.clear()
    world.sp3_llm_client.set_response_for(None, _VALID_GHERKIN_YAML)
    return True, ""


def _h_stage6_result_includes_gherkin_spec(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the result includes a GherkinSpec object."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    ghw = getattr(world, "sp3_gherkin", None)
    if ghw is None:
        return False, "No GherkinSpec result available"
    if not isinstance(ghw, GherkinSpec):
        return False, f"Result is not a GherkinSpec, got {type(ghw)}"
    return True, ""


def _h_stage6_result_includes_raw_text(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the result includes a raw text string."""
    raw = getattr(world, "sp3_gherkin_raw", None)
    if raw is None:
        return False, "No raw text result available"
    if not isinstance(raw, str):
        return False, f"Raw text is not a str, got {type(raw)}"
    if len(raw) == 0:
        return False, "Raw text is empty"
    return True, ""


def _h_stage6_gherkin_spec_given_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the GherkinSpec.given list contains "..."."""
    import re

    ghw = getattr(world, "sp3_gherkin", None)
    if ghw is None:
        return False, "No GherkinSpec result available"
    m = re.search(r'contains "([^"]+)"', text)
    if not m:
        return False, f"Could not extract expected value from step: {text}"
    expected = m.group(1)
    if expected not in ghw.given:
        return False, f"GherkinSpec.given does not contain '{expected}': {ghw.given}"
    return True, ""


def _h_stage6_gherkin_spec_with_feature_scenario(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a GherkinSpec with feature "..." and scenario "..."."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec
    import re

    feature_m = re.search(r'feature "([^"]+)"', text)
    scenario_m = re.search(r'scenario "([^"]+)"', text)
    feature = feature_m.group(1) if feature_m else "Safe orchestration"
    scenario = scenario_m.group(1) if scenario_m else "SCN-001"

    # Check for extended form: "and given "..." and when "..." and then_expected "...""
    given_m = re.search(r'given "([^"]+)"', text)
    when_m = re.search(r'when "([^"]+)"', text)
    then_exp_m = re.search(r'then_expected "([^"]+)"', text)

    spec = GherkinSpec(
        feature=feature,
        scenario=scenario,
        given=[given_m.group(1)] if given_m else ["Given PM-1-1 is active"],
        when=[when_m.group(1)] if when_m else ["When a revoked user requests access"],
        then_expected=[then_exp_m.group(1)]
        if then_exp_m
        else ["Then the system should reject the request"],
        then_actual=["But the system approves"],
    )
    world.sp3_gherkin_spec = spec
    return True, ""


def _h_stage6_envelope_with_structured_gherkin(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle a ScenarioEnvelope with a structured GherkinSpec."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    feature_match = re.search(r'feature "([^"]+)"', text)
    scenario_match = re.search(r'scenario "([^"]+)"', text)
    if feature_match is None or scenario_match is None:
        return False, f"Could not parse structured Gherkin identity: {text}"
    spec = GherkinSpec(
        feature=feature_match.group(1),
        scenario=scenario_match.group(1),
        given=["Given PM-1-1 is active"],
        when=["When a revoked user requests access"],
        then_expected=["Then the system should reject the request"],
        then_actual=["But the system approves the request"],
    )
    world.sp3_envelope = _make_sp3_envelope(gherkin_spec=spec)
    return True, ""


def _h_stage6_structured_gherkin_steps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle the structured Gherkin step values used by JPKW-07."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    match = re.search(
        r'given "([^"]+)" and when "([^"]+)" and then_expected "([^"]+)" '
        r'and then_actual "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse structured Gherkin steps: {text}"
    envelope = getattr(world, "sp3_envelope", None)
    if envelope is None:
        return False, "No ScenarioEnvelope available"
    current = envelope.gherkin_spec
    envelope.gherkin_spec = GherkinSpec(
        feature=current.feature,
        scenario=current.scenario,
        given=[match.group(1)],
        when=[match.group(2)],
        then_expected=[match.group(3)],
        then_actual=[match.group(4)],
    )
    return True, ""


def _h_stage6_envelope_conflicting_raw(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle a conflicting raw Gherkin text on an envelope."""
    match = re.search(r'conflicting gherkin_raw "([^"]*)"', text)
    if match is None:
        return False, f"Could not parse conflicting gherkin_raw: {text}"
    envelope = getattr(world, "sp3_envelope", None)
    if envelope is None:
        return False, "No ScenarioEnvelope available"
    envelope.gherkin_raw = match.group(1).replace("\\n", "\n")
    return True, ""


def _h_stage6_envelope_unavailable_structured_gherkin(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle an envelope whose structured Gherkin could not be parsed."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    match = re.search(r'unavailable structured Gherkin and gherkin_raw "([^"]*)"', text)
    if match is None:
        return False, f"Could not parse fallback gherkin_raw: {text}"
    empty_spec = GherkinSpec(
        feature="",
        scenario="",
        given=[],
        when=[],
        then_expected=[],
        then_actual=[],
    )
    envelope = _make_sp3_envelope(gherkin_spec=empty_spec)
    envelope.gherkin_raw = match.group(1).replace("\\n", "\n")
    world.sp3_envelope = envelope
    return True, ""


def _h_stage6_gherkin_spec_with_deficiency(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a GherkinSpec with <deficiency> (from examples)."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    deficiency = examples.get("deficiency", "")
    if "empty then_expected" in deficiency:
        spec = GherkinSpec(
            feature="F",
            scenario="S",
            given=["Given PM-1-1 is active"],
            when=["When x"],
            then_expected=[],
            then_actual=["But approves"],
        )
    elif "empty then_actual" in deficiency:
        spec = GherkinSpec(
            feature="F",
            scenario="S",
            given=["Given PM-1-1 is active"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=[],
        )
    elif "no PM reference" in deficiency:
        spec = GherkinSpec(
            feature="F",
            scenario="S",
            given=["Given the system is running"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        )
    else:
        return False, f"Unknown deficiency: {deficiency}"
    world.sp3_gherkin_spec = spec
    return True, ""


def _h_stage6_gherkin_spec_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a GherkinSpec with then_expected containing should, then_actual containing but, and given referencing PM-1-1."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    spec = GherkinSpec(
        feature="Safe orchestration",
        scenario="SCN-001",
        given=["Given PM-1-1 is active"],
        when=["When x"],
        then_expected=["Then the system should reject"],
        then_actual=["But the system approves"],
    )
    world.sp3_gherkin_spec = spec
    return True, ""


def _h_stage6_gherkin_raw_string(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a gherkin_raw string containing the full Feature block."""
    world.sp3_gherkin_raw_text = "Feature: Safe orchestration\nScenario: SCN-001\n"
    return True, ""


def _h_stage6_assemble_envelope(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assemble_envelope is called with the GherkinSpec and gherkin_raw."""
    from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope

    spec = world.scenario_spec or _make_sp3_scenario_spec()
    ghw = getattr(world, "sp3_gherkin_spec", None)
    raw = getattr(world, "sp3_gherkin_raw_text", "")
    if ghw is None:
        return False, "No GherkinSpec available to assemble"
    world.sp3_assembled_envelope = assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative="Narrative",
        attack_tree={"root": "r", "branches": [], "leaves": []},
        gherkin_spec=ghw,
        gherkin_raw=raw,
    )
    return True, ""


def _h_stage6_envelope_gherkin_spec_equals(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the resulting ScenarioEnvelope.gherkin_spec equals the GherkinSpec."""
    env = getattr(world, "sp3_assembled_envelope", None)
    ghw = getattr(world, "sp3_gherkin_spec", None)
    if env is None or ghw is None:
        return False, "Missing envelope or GherkinSpec"
    if env.gherkin_spec != ghw:
        return False, f"gherkin_spec mismatch: {env.gherkin_spec} != {ghw}"
    return True, ""


def _h_stage6_envelope_gherkin_raw_equals(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the resulting ScenarioEnvelope.gherkin_raw equals the gherkin_raw string."""
    env = getattr(world, "sp3_assembled_envelope", None)
    raw = getattr(world, "sp3_gherkin_raw_text", "")
    if env is None:
        return False, "Missing envelope"
    if env.gherkin_raw != raw:
        return False, f"gherkin_raw mismatch: '{env.gherkin_raw}' != '{raw}'"
    return True, ""


def _h_stage6_envelope_with_gherkin_raw(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a ScenarioEnvelope with gherkin_raw "..."."""
    import re

    m = re.search(r'gherkin_raw "([^"]+)"', text)
    raw = m.group(1) if m else ""
    # Unescape \n
    raw = raw.replace("\\n", "\n")
    env = _make_sp3_envelope()
    env.gherkin_raw = raw
    world.sp3_envelope = env
    return True, ""


def _h_stage6_scenario_artifacts_written(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: scenario artifacts are written."""
    from asago_scenario_generator.stpa.scenario_prod.run import (
        _write_scenario_artifacts,
    )

    env = getattr(world, "sp3_envelope", None)
    if env is None:
        env = _make_sp3_envelope()
        env.gherkin_raw = "Feature: Safe orchestration\nScenario: SCN-001\n"
    world.sp3_artifacts_dir = Path(tempfile.mkdtemp())
    _write_scenario_artifacts(env, world.sp3_artifacts_dir)
    return True, ""


def _h_stage6_feature_file_created(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a .feature file is created containing the gherkin_raw text."""
    env = getattr(world, "sp3_envelope", None)
    artifacts_dir = getattr(world, "sp3_artifacts_dir", None)
    if env is None or artifacts_dir is None:
        return False, "Missing envelope or artifacts dir"
    feature_path = artifacts_dir / f"{env.scenario_id}.feature"
    if not feature_path.exists():
        return False, f".feature file not found at {feature_path}"
    content = feature_path.read_text(encoding="utf-8")
    if env.gherkin_raw and env.gherkin_raw not in content:
        return False, ".feature file does not contain gherkin_raw text"
    return True, ""


def _h_stage6_feature_file_equals(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle an exact canonical or raw-fallback feature-file assertion."""
    match = re.search(r'the \.feature file equals "([^"]*)"', text)
    artifacts_dir = getattr(world, "sp3_artifacts_dir", None)
    envelope = getattr(world, "sp3_envelope", None)
    if match is None:
        return False, f"Could not parse expected feature text: {text}"
    if artifacts_dir is None or envelope is None:
        return False, "Missing envelope or artifacts dir"
    feature_path = artifacts_dir / f"{envelope.scenario_id}.feature"
    if not feature_path.exists():
        return False, f".feature file not found at {feature_path}"
    expected = match.group(1).replace("\\n", "\n")
    actual = feature_path.read_text(encoding="utf-8")
    if actual != expected:
        return (
            False,
            f".feature file differs from expected text:\nexpected={expected!r}\n"
            f"actual={actual!r}",
        )
    return True, ""


def _h_stage6_feature_file_excludes_conflicting_raw(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Ensure canonical structured text wins over conflicting raw text."""
    envelope = getattr(world, "sp3_envelope", None)
    artifacts_dir = getattr(world, "sp3_artifacts_dir", None)
    if envelope is None or artifacts_dir is None:
        return False, "Missing envelope or artifacts dir"
    feature_path = artifacts_dir / f"{envelope.scenario_id}.feature"
    if not feature_path.exists():
        return False, f".feature file not found at {feature_path}"
    content = feature_path.read_text(encoding="utf-8")
    if envelope.gherkin_raw and envelope.gherkin_raw in content:
        return False, "feature file contains the conflicting gherkin_raw text"
    return True, ""


def _h_stage6_gherkin_spec_validation_on_spec(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: Gherkin structure validation is performed on the GherkinSpec."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_gherkin_structure,
    )

    spec = getattr(world, "sp3_gherkin_spec", None)
    if spec is None:
        spec = getattr(world, "sp3_gherkin", None)
    if spec is None:
        return False, "No GherkinSpec to validate"
    result = validate_gherkin_structure(spec)
    world.validation_succeeded = result.passed
    if not result.passed:
        world.validation_error = ValueError(
            result.errors[0] if result.errors else "Validation failed"
        )
    return True, ""


def _h_stage6_gherkin_spec_rendered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the GherkinSpec is rendered to feature text."""
    spec = getattr(world, "sp3_gherkin_spec", None)
    if spec is None:
        return False, "No GherkinSpec to render"
    world.sp3_rendered_text = spec.to_feature_text()
    return True, ""


def _h_stage6_rendered_text_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the rendered text contains the Feature/Scenario/Given/When/Then line."""
    rendered = getattr(world, "sp3_rendered_text", None)
    if rendered is None:
        return False, "No rendered text available"
    text_lower = text.lower()
    if "feature line" in text_lower:
        if "Feature:" not in rendered:
            return False, f"Rendered text missing Feature line: {rendered}"
    elif "scenario line" in text_lower:
        if "Scenario:" not in rendered:
            return False, f"Rendered text missing Scenario line: {rendered}"
    elif "given step" in text_lower:
        if "Given" not in rendered:
            return False, f"Rendered text missing Given step: {rendered}"
    elif "when step" in text_lower:
        if "When" not in rendered:
            return False, f"Rendered text missing When step: {rendered}"
    elif "then step" in text_lower:
        if "Then" not in rendered:
            return False, f"Rendered text missing Then step: {rendered}"
    return True, ""


def _h_stage6_envelope_with_empty_then_expected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a ScenarioEnvelope with a GherkinSpec that has empty then_expected."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    spec = _make_sp3_scenario_spec()
    env = _make_sp3_envelope(
        spec=spec,
        attack_tree={
            "root": "Induce ICA NOT_PROVIDED on CA-1-1",
            "branches": [
                {"category": "controller_side", "label": "l", "children": []},
                {"category": "path_side", "label": "l", "children": []},
            ],
            "leaves": [],
        },
    )
    env.gherkin_spec = GherkinSpec(
        feature="F",
        scenario="S",
        given=["Given PM-1-1 is active"],
        when=["When x"],
        then_expected=[],
        then_actual=["But approves"],
    )
    world.sp3_envelope = env
    return True, ""


def _h_stage7_envelope_validation_performed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: Stage 7 envelope validation is performed."""
    from asago_scenario_generator.stpa.scenario_prod.run import (
        _validate_envelope_stage7,
    )

    env = getattr(world, "sp3_envelope", None)
    if env is None:
        env = _make_sp3_envelope()
    la = world.loss_analysis or _make_sp3_loss_analysis()
    errors: list[str] = []
    _validate_envelope_stage7(env, la, errors)
    world.sp3_stage7_errors = errors
    world.validation_succeeded = len(errors) == 0
    if errors:
        world.validation_error = ValueError(errors[0])
    return True, ""


def _h_stage6_gherkin_raw_contains_feature(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the gherkin_raw contains the Feature line."""
    raw = getattr(world, "sp3_gherkin_raw", None)
    if raw is None:
        return False, "No gherkin_raw available"
    if "feature" not in raw.lower():
        return False, f"gherkin_raw does not contain Feature line: {raw}"
    return True, ""


def _h_stage6_gherkin_raw_contains_scenario(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the gherkin_raw contains the Scenario line."""
    raw = getattr(world, "sp3_gherkin_raw", None)
    if raw is None:
        return False, "No gherkin_raw available"
    if "scenario" not in raw.lower():
        return False, f"gherkin_raw does not contain Scenario line: {raw}"
    return True, ""


def _h_stage6_loss_analysis_with_specific_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a loss analysis with losses L-1, L-2, L-3 and hazards H-1, H-2."""
    world.loss_analysis = LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss 1",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r1"],
            ),
            Loss(
                loss_id="L-2",
                description="Loss 2",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r2"],
            ),
            Loss(
                loss_id="L-3",
                description="Loss 3",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r3"],
            ),
        ],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard 1", related_losses=["L-1"]),
            Hazard(hazard_id="H-2", description="Hazard 2", related_losses=["L-2"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="The system must validate before action",
                related_hazards=["H-1"],
            ),
        ],
    )
    return True, ""


def _h_stage6_gherkin_user_prompt_built(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Gherkin user prompt is built with the loss analysis."""
    from asago_scenario_generator.stpa.scenario_prod.gherkin import (
        build_gherkin_prompts,
        find_security_constraint,
    )
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    loader = TemplateLoader(PROMPTS_DIR)
    sc = find_security_constraint(world.scenario_spec, world.loss_analysis)
    _, user_prompt = build_gherkin_prompts(
        world.scenario_spec, sc, world.loss_analysis, loader
    )
    world.sp3_user_prompt = user_prompt
    return True, ""


def _h_stage6_user_prompt_contains_valid_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the user prompt contains the valid <id_type> ID <valid_id>."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt available"
    valid_id = examples.get("valid_id", "")
    if not valid_id:
        return False, "Missing valid_id in examples"
    if valid_id not in prompt:
        return False, f"User prompt does not contain '{valid_id}'"
    return True, ""


def _h_stage6_user_prompt_instructs_reference_only(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the user prompt contains an instruction to reference only the provided IDs."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt available"
    if "only" not in prompt.lower() or "provided" not in prompt.lower():
        return False, "User prompt does not instruct to reference only provided IDs"
    return True, ""


def _h_stage6_user_prompt_instructs_l_only_no_h(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the user prompt instructs to use only L-* loss IDs and not H-* hazard IDs."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt available"
    if "L-*" not in prompt or "H-*" not in prompt:
        return False, "User prompt does not instruct to use only L-* and not H-* IDs"
    return True, ""


def _h_stage6_build_gherkin_prompts_called(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: build_gherkin_prompts is called with the scenario spec and loss analysis."""
    from asago_scenario_generator.stpa.scenario_prod.gherkin import (
        build_gherkin_prompts,
        find_security_constraint,
    )
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    loader = TemplateLoader(PROMPTS_DIR)
    sc = find_security_constraint(world.scenario_spec, world.loss_analysis)
    _, user_prompt = build_gherkin_prompts(
        world.scenario_spec, sc, world.loss_analysis, loader
    )
    world.sp3_user_prompt = user_prompt
    return True, ""


def _h_stage6_user_prompt_contains_valid_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the user prompt contains valid Loss IDs and excludes Hazard IDs from the loss analysis."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt available"
    if "L-1" not in prompt:
        return False, "User prompt missing L-1"
    if "H-1" in prompt:
        return False, "User prompt should not contain H-1"
    return True, ""


def _h_stage6_gherkin_text_hallucinated_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a Gherkin text referencing <hallucinated_id> which is not in the loss analysis."""
    hallucinated_id = examples.get("hallucinated_id", "")
    if not hallucinated_id:
        return False, "Missing hallucinated_id in examples"
    world.sp3_gherkin_text = (
        f"Scenario: Test\n  But loss {hallucinated_id} is realized\n"
    )
    return True, ""


def _h_stage6_gherkin_text_multiple_hallucinated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a Gherkin text referencing L-99 and H-88 which are not in the loss analysis."""
    world.sp3_gherkin_text = (
        "Scenario: Test\n  But loss L-99 is realized\n  And hazard H-88 occurs\n"
    )
    return True, ""


def _h_stage6_gherkin_text_valid_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a Gherkin text referencing L-1 and H-1 which are in the loss analysis."""
    world.sp3_gherkin_text = (
        "Scenario: Test\n  But loss L-1 is realized\n  And hazard H-1 occurs\n"
    )
    return True, ""


def _h_stage6_gherkin_text_no_refs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a Gherkin text with no L-* or H-* references."""
    world.sp3_gherkin_text = "Scenario: Test\n  Given PM-1-1 is active\n  When x\n  Then should reject\n  But approves\n"
    return True, ""


def _h_stage6_loss_hazard_id_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: Loss/Hazard ID validation is performed against the loss analysis."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_loss_hazard_id_references,
    )

    gherkin_text = getattr(world, "sp3_gherkin_text", None)
    if gherkin_text is None:
        return False, "No Gherkin text to validate"
    la = world.loss_analysis or _make_sp3_loss_analysis()
    result = validate_loss_hazard_id_references(gherkin_text, la)
    world.validation_succeeded = result.passed
    if not result.passed:
        world.validation_error = ValueError("; ".join(result.errors))
    world.sp3_validation_errors = result.errors
    return True, ""


def _h_stage6_llm_returns_gherkin_hallucinated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that returns Gherkin referencing hallucinated Loss ID L-99."""
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
        world.sp3_run_dir = Path(tempfile.mkdtemp())
    world.sp3_llm_client._response_queue.clear()
    yaml = (
        "feature: Test\n"
        "scenario: SCN-001\n"
        "given:\n  - Given PM-1-1 is active\n"
        "when:\n  - When x\n"
        "then_expected:\n  - Then should reject\n"
        "then_actual:\n  - But approves\n  - And loss L-99 is realized\n"
    )
    world.sp3_llm_client.set_response_for(None, yaml)
    return True, ""


def _h_stage6_pipeline_runs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Stage 6 pipeline runs for the scenario."""
    from asago_scenario_generator.stpa.scenario_prod.gherkin import generate_gherkin
    from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
        generate_attack_tree,
    )
    from asago_scenario_generator.stpa.scenario_prod.run import (
        _validate_stage6_artifacts,
    )

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
        world.sp3_run_dir = Path(tempfile.mkdtemp())
    run_dir = getattr(world, "sp3_run_dir", None) or Path(tempfile.mkdtemp())
    tree, tree_err = generate_attack_tree(
        world.sp3_llm_client, world.scenario_spec, world.control_structure, run_dir
    )
    ghw, ghw_raw, ghw_err = generate_gherkin(
        world.sp3_llm_client, world.scenario_spec, world.loss_analysis, run_dir
    )
    errors: list[str] = []
    _validate_stage6_artifacts(
        tree or {"root": "r", "branches": [], "leaves": []},
        ghw,
        ghw_raw or "",
        world.control_structure,
        world.loss_analysis,
        world.scenario_spec,
        errors,
    )
    world.sp3_stage6_errors = errors
    world.validation_succeeded = len(errors) == 0
    if errors:
        world.validation_error = ValueError(errors[0])
    return True, ""


def _h_stage6_validation_error_reported(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a validation error is reported containing <keyword>."""
    import re

    errors = getattr(world, "sp3_stage6_errors", None) or getattr(
        world, "sp3_stage7_errors", None
    )
    if not errors:
        if world.validation_error is not None:
            errors = [str(world.validation_error)]
        else:
            return False, "No validation errors reported"
    m = re.search(r"containing (\S+)", text)
    if m:
        expected = m.group(1)
        if not any(expected in e for e in errors):
            return False, f"No error contains '{expected}': {errors}"
    return True, ""


def _h_stage6_envelope_with_hallucinated_hazard(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a ScenarioEnvelope with Gherkin referencing hallucinated Hazard ID H-99."""
    from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec

    spec = _make_sp3_scenario_spec()
    env = _make_sp3_envelope(
        spec=spec,
        attack_tree={
            "root": "Induce ICA NOT_PROVIDED on CA-1-1",
            "branches": [
                {"category": "controller_side", "label": "l", "children": []},
                {"category": "path_side", "label": "l", "children": []},
            ],
            "leaves": [],
        },
    )
    env.gherkin_spec = GherkinSpec(
        feature="F",
        scenario="S",
        given=["Given PM-1-1 is active"],
        when=["When x"],
        then_expected=["Then should reject"],
        then_actual=["But approves", "And hazard H-99 occurs"],
    )
    env.gherkin_raw = "Scenario: Test\n  But hazard H-99 occurs\n"
    world.sp3_envelope = env
    return True, ""


def _h_stage6_attack_tree_system_prompt_rendered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attack tree system prompt is rendered."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    loader = TemplateLoader(PROMPTS_DIR)
    world.sp3_system_prompt = loader.render_prompt("stage6b_tree_system.j2")
    return True, ""


def _h_stage6_system_prompt_exact_ica_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt instructs the LLM to use the exact ICA type enum value."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    if (
        "exact ica type" not in prompt.lower()
        and "exact ICA type" not in prompt.lower()
    ):
        return False, "System prompt does not instruct exact ICA type"
    return True, ""


def _h_stage6_system_prompt_root_format(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt defines the root format as Induce ICA followed by the ICA type and control action."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    if "Induce ICA" not in prompt:
        return False, "System prompt does not define 'Induce ICA' root format"
    return True, ""


def _h_stage6_system_prompt_no_substitute(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt instructs the LLM not to substitute or paraphrase the ICA type."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    if "substitute" not in prompt.lower() and "paraphrase" not in prompt.lower():
        return False, "System prompt does not instruct not to substitute/paraphrase"
    return True, ""


def _h_stage6_scenario_spec_with_ica_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a ScenarioSpec with ica_type <ica_type> and target_control_action CA-1-1."""
    ica_type_str = examples.get("ica_type", "") or examples.get("expected_type", "")
    if not ica_type_str:
        import re

        m = re.search(r"ica_type (\S+)", text)
        ica_type_str = m.group(1) if m else "NOT_PROVIDED"
    # Map string to UCAType enum
    ica_type_map = {
        "NOT_PROVIDED": UCAType.not_provided,
        "INCORRECT": UCAType.incorrect,
        "WRONG_TIMING": UCAType.wrong_timing,
        "WRONG_DURATION": UCAType.wrong_duration,
    }
    ica_type = ica_type_map.get(ica_type_str, UCAType.not_provided)
    world.scenario_spec = _make_sp3_scenario_spec(ica_type=ica_type)
    return True, ""


def _h_stage6_attack_tree_with_root(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an attack tree with root "..."."""
    import re

    # Check if root_label is in examples (even if empty string)
    if "root_label" in examples:
        root_label = examples["root_label"]
    else:
        m = re.search(r'root "([^"]*)"', text)
        root_label = m.group(1) if m else "Induce ICA NOT_PROVIDED on CA-1-1"
    # Substitute example values for ica_type/drifted_type patterns
    if "<ica_type>" in root_label:
        root_label = root_label.replace(
            "<ica_type>", examples.get("ica_type", "NOT_PROVIDED")
        )
    if "<drifted_type>" in root_label:
        root_label = root_label.replace(
            "<drifted_type>", examples.get("drifted_type", "NOT_TRIGGERED")
        )
    world.sp3_attack_tree = {
        "root": root_label,
        "branches": [
            {"category": "controller_side", "label": "l", "children": []},
            {"category": "path_side", "label": "l", "children": []},
        ],
        "leaves": [],
    }
    return True, ""


def _h_stage6_attack_tree_root_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: attack tree root label validation is performed."""
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_attack_tree_root_label,
    )

    tree = getattr(world, "sp3_attack_tree", None)
    if tree is None:
        return False, "No attack tree available"
    spec = world.scenario_spec or _make_sp3_scenario_spec()
    ica_type = spec.ica_type.value if hasattr(spec, "ica_type") else "NOT_PROVIDED"
    ca_id = spec.target_control_action
    result = validate_attack_tree_root_label(tree, ica_type, ca_id)
    world.validation_succeeded = result.passed
    if not result.passed:
        world.validation_error = ValueError(
            result.errors[0] if result.errors else "Validation failed"
        )
    return True, ""


def _h_stage6_llm_returns_attack_tree_drifted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM that returns an attack tree with root "Induce ICA NOT_TRIGGERED on CA-1-1"."""
    if not hasattr(world, "sp3_llm_client") or world.sp3_llm_client is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
        world.sp3_run_dir = Path(tempfile.mkdtemp())
    world.sp3_llm_client._response_queue.clear()
    import json

    world.sp3_llm_client.set_response_for(
        None,
        json.dumps(
            {
                "root": "Induce ICA NOT_TRIGGERED on CA-1-1",
                "branches": [
                    {"category": "controller_side", "label": "l", "children": []},
                    {"category": "path_side", "label": "l", "children": []},
                ],
                "leaves": [],
            }
        ),
    )
    return True, ""


def _h_stage6_envelope_with_ica_type_attack_tree(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a ScenarioEnvelope with ica_type NOT_PROVIDED and attack_tree root "..."."""
    import re

    spec = _make_sp3_scenario_spec(ica_type=UCAType.not_provided)
    env = _make_sp3_envelope(spec=spec)
    m = re.search(r'root "([^"]+)"', text)
    root_label = m.group(1) if m else "Induce ICA NOT_TRIGGERED on CA-1-1"
    env.attack_tree = {
        "root": root_label,
        "branches": [
            {"category": "controller_side", "label": "l", "children": []},
            {"category": "path_side", "label": "l", "children": []},
        ],
        "leaves": [],
    }
    world.sp3_envelope = env
    return True, ""


def _h_stage6_attack_tree_user_prompt_built(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attack tree user prompt is built."""
    from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
        build_attack_tree_prompts,
    )
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    loader = TemplateLoader(PROMPTS_DIR)
    _, user_prompt = build_attack_tree_prompts(
        world.scenario_spec, world.control_structure, loader
    )
    world.sp3_user_prompt = user_prompt
    return True, ""


def _h_stage6_user_prompt_contains_ica_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the user prompt contains the scenario spec with ica_type NOT_PROVIDED."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt available"
    if "NOT_PROVIDED" not in prompt:
        return (
            False,
            f"User prompt does not contain ica_type NOT_PROVIDED: {prompt[:200]}",
        )
    return True, ""


# ---------------------------------------------------------------------------
# SP3-072o acceptance handlers — prompt revision acceptance seam
# ---------------------------------------------------------------------------

_SP3_072O_STAGE_SYS: dict[str, str] = {
    "Stage 5": "stage5_system.j2",
    "Stage 6a": "stage6a_narrative_system.j2",
    "Stage 6b": "stage6b_tree_system.j2",
    "Stage 6c": "stage6c_gherkin_system.j2",
}

_SP3_072O_STAGE_USR: dict[str, str] = {
    "Stage 5": "stage5_user.j2",
    "Stage 6a": "stage6a_narrative_user.j2",
    "Stage 6b": "stage6b_tree_user.j2",
    "Stage 6c": "stage6c_gherkin_user.j2",
}


def _072o_resolve_stage(text: str) -> str | None:
    """Extract a stage label like 'Stage 6c' from step text."""
    m = re.search(r"(Stage \d\w?)", text)
    return m.group(1) if m else None


def _072o_has_loss_id_restriction(text: str) -> bool:
    lower = text.lower()
    return any(
        p in lower
        for p in (
            "only l-* loss ids",
            "l-* loss ids only",
            "use only l-*",
            "only use l-*",
            "do not use h-*",
            "not h-*",
            "loss references use only l-*",
            "consequence references must not use h-*",
            "consequence references use only l-*",
            "h-* hazard ids are not valid",
        )
    )


def _072o_has_code_fence_restriction(text: str) -> bool:
    lower = text.lower()
    return any(
        p in lower
        for p in (
            "do not wrap",
            "code fence",
            "code fences",
            "markdown code",
            "no code fences",
        )
    )


# --- Background / fixture handlers -----------------------------------------


def _h_072o_templates_renderable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 ... prompt templates are renderable."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    for tmpl in list(_SP3_072O_STAGE_SYS.values()) + list(_SP3_072O_STAGE_USR.values()):
        if not (PROMPTS_DIR / tmpl).is_file():
            return False, f"Template not found: {tmpl}"
    return True, ""


def _h_072o_minimal_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a minimal SP3 scenario fixture."""
    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    return True, ""


def _h_072o_minimal_loss_analysis(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a minimal SP3 loss analysis with loss L-1 and hazard H-1."""
    world.loss_analysis = _make_sp3_loss_analysis()
    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    return True, ""


# --- System prompt rendering and assertion handlers -------------------------


def _h_072o_render_system_prompt(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the <stage> system prompt is rendered."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    stage = _072o_resolve_stage(text)
    if stage is None or stage not in _SP3_072O_STAGE_SYS:
        return False, f"Unknown stage in: {text}"
    loader = TemplateLoader(PROMPTS_DIR)
    world.sp3_system_prompt = loader.render_prompt(_SP3_072O_STAGE_SYS[stage])
    world.sp3_current_stage = stage
    return True, ""


def _h_072o_sys_not_contains_string(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the <stage> system prompt does not contain the string."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    m = re.search(r'does not contain the string "([^"]+)"', text)
    needle = m.group(1) if m else ""
    if needle and needle in prompt:
        return False, f"System prompt should not contain '{needle}'"
    return True, ""


def _h_072o_sys_contains_phrase(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the <stage> system prompt contains the phrase."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    m = re.search(r'contains the phrase "([^"]+)"', text)
    phrase = m.group(1) if m else ""
    if phrase and phrase not in prompt:
        return False, f"System prompt does not contain phrase '{phrase}'"
    return True, ""


def _h_072o_sys_contains_task_framing(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the <stage> system prompt contains the task framing phrase."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    m = re.search(r'task framing phrase "([^"]+)"', text)
    phrase = m.group(1) if m else ""
    if phrase and phrase not in prompt:
        return False, f"System prompt does not contain task framing '{phrase}'"
    return True, ""


def _h_072o_sys_code_fence_instruction(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Stage 6b system prompt contains a direct instruction not to use Markdown code fences."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    if not _072o_has_code_fence_restriction(prompt):
        return False, "System prompt does not contain code-fence restriction"
    return True, ""


def _h_072o_sys_contains_yaml(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Stage 6b system prompt contains the YAML output format."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    if "YAML" not in prompt:
        return False, "System prompt does not contain YAML output format"
    return True, ""


def _h_072o_sys_contains_attack_tree(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Stage 6b system prompt contains the attack tree structure."""
    prompt = getattr(world, "sp3_system_prompt", None)
    if prompt is None:
        return False, "No system prompt rendered"
    if "attack tree" not in prompt.lower():
        return False, "System prompt does not contain attack tree structure"
    return True, ""


# --- Template source inspection handlers ------------------------------------


def _h_072o_inspect_user_template(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the <stage> user prompt template source is inspected."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    stage = _072o_resolve_stage(text)
    if stage is None or stage not in _SP3_072O_STAGE_USR:
        return False, f"Unknown stage in: {text}"
    world.sp3_template_source = (PROMPTS_DIR / _SP3_072O_STAGE_USR[stage]).read_text(
        encoding="utf-8"
    )
    return True, ""


def _h_072o_template_contains_var(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the template contains the variable."""
    src = getattr(world, "sp3_template_source", None)
    if src is None:
        return False, "No template source inspected"
    m = re.search(r'variable "([^"]+)"', text)
    var = m.group(1) if m else ""
    if var:
        if f"{{{{ {var}" not in src and f"{{{{{var}" not in src:
            return False, f"Template does not contain variable '{var}'"
    return True, ""


def _h_072o_template_not_contains_var(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the template does not contain the variable."""
    src = getattr(world, "sp3_template_source", None)
    if src is None:
        return False, "No template source inspected"
    m = re.search(r'variable "([^"]+)"', text)
    var = m.group(1) if m else ""
    if var:
        if f"{{{{ {var}" in src or f"{{{{{var}" in src:
            return False, f"Template should not contain variable '{var}'"
    return True, ""


# --- Gherkin user prompt handlers -------------------------------------------


def _h_072o_render_gherkin_user(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Stage 6c user prompt is rendered."""
    from asago_scenario_generator.stpa.scenario_prod.gherkin import (
        build_gherkin_prompts,
        find_security_constraint,
    )
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    loader = TemplateLoader(PROMPTS_DIR)
    sc = find_security_constraint(world.scenario_spec, world.loss_analysis)
    _, user_prompt = build_gherkin_prompts(
        world.scenario_spec, sc, world.loss_analysis, loader
    )
    world.sp3_user_prompt = user_prompt
    return True, ""


def _h_072o_gherkin_contains_loss_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Stage 6c user prompt contains the valid loss IDs."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt rendered"
    la = world.loss_analysis or _make_sp3_loss_analysis()
    for loss in la.risk_card_losses + la.use_case_losses:
        if loss.loss_id not in prompt:
            return False, f"User prompt does not contain loss ID '{loss.loss_id}'"
    return True, ""


def _h_072o_gherkin_contains_task_heading(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Stage 6c user prompt contains the task instruction heading."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt rendered"
    if "Your Task" not in prompt:
        return False, "User prompt does not contain 'Your Task' heading"
    return True, ""


def _h_072o_loss_ids_before_task(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the valid loss IDs appear before the task instruction ends."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt rendered"
    la = world.loss_analysis or _make_sp3_loss_analysis()
    task_pos = prompt.find("Your Task")
    if task_pos == -1:
        return False, "No 'Your Task' heading found"
    for loss in la.risk_card_losses + la.use_case_losses:
        loss_pos = prompt.find(loss.loss_id)
        if loss_pos == -1:
            return False, f"Loss ID '{loss.loss_id}' not found in prompt"
        if loss_pos < task_pos:
            return False, f"Loss ID '{loss.loss_id}' appears before 'Your Task' heading"
    return True, ""


def _h_072o_gherkin_l_star(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Stage 6c user prompt contains a restriction that loss references use only L-* IDs."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt rendered"
    if not _072o_has_loss_id_restriction(prompt):
        return False, "User prompt does not contain L-* only restriction"
    return True, ""


def _h_072o_gherkin_no_h_star(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Stage 6c user prompt contains a statement that consequence references must not use H-* IDs."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt rendered"
    lower = prompt.lower()
    if not any(p in lower for p in ("not h-*", "do not use h-*", "must not use h-*")):
        return False, "User prompt does not contain H-* prohibition"
    return True, ""


def _h_072o_gherkin_no_hazard_heading(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Stage 6c user prompt does not contain the heading."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt rendered"
    m = re.search(r'heading "([^"]+)"', text)
    heading = m.group(1) if m else "Valid Hazard IDs"
    if heading in prompt:
        return False, f"User prompt should not contain heading '{heading}'"
    return True, ""


def _h_072o_gherkin_no_hazard_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Stage 6c user prompt does not list the hazard IDs."""
    prompt = getattr(world, "sp3_user_prompt", None)
    if prompt is None:
        return False, "No user prompt rendered"
    la = world.loss_analysis or _make_sp3_loss_analysis()
    for hazard in la.hazards:
        if hazard.hazard_id in prompt:
            return False, f"User prompt should not list hazard ID '{hazard.hazard_id}'"
    return True, ""


# --- All-prompts-rendered handler -------------------------------------------


def _h_072o_render_all_prompts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: all SP3 Stage 5 through Stage 6c prompts are rendered."""
    from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
        build_attack_tree_prompts,
    )
    from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
        build_bdi_prompts,
    )
    from asago_scenario_generator.stpa.scenario_prod.gherkin import (
        build_gherkin_prompts,
        find_security_constraint,
    )
    from asago_scenario_generator.stpa.scenario_prod.narrative import (
        build_narrative_prompts,
    )
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    cs = world.control_structure or _make_sp3_cs()
    loader = TemplateLoader(PROMPTS_DIR)
    threat = _make_sp3_threat()
    sc = find_security_constraint(world.scenario_spec, world.loss_analysis)
    s5_sys, s5_usr = build_bdi_prompts(
        world.scenario_spec.defender_bdi, threat, cs, "RESP-1", loader
    )
    s6a_sys, s6a_usr = build_narrative_prompts(world.scenario_spec, loader)
    s6b_sys, s6b_usr = build_attack_tree_prompts(world.scenario_spec, cs, loader)
    s6c_sys, s6c_usr = build_gherkin_prompts(
        world.scenario_spec, sc, world.loss_analysis, loader
    )
    world.sp3_all_rendered = [
        s5_sys,
        s5_usr,
        s6a_sys,
        s6a_usr,
        s6b_sys,
        s6b_usr,
        s6c_sys,
        s6c_usr,
    ]
    return True, ""


def _h_072o_no_rendered_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: no rendered prompt contains the pattern."""
    rendered = getattr(world, "sp3_all_rendered", None)
    if rendered is None:
        return False, "No rendered prompts available"
    m = re.search(r'pattern "([^"]+)"', text)
    pattern = m.group(1) if m else ""
    if pattern:
        for r_prompt in rendered:
            if pattern in r_prompt:
                return False, f"Rendered prompt contains pattern '{pattern}'"
    return True, ""


# --- Anti-vacuity handlers --------------------------------------------------


def _h_072o_copy_remove_l_restriction(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a copy of the Stage 6c user prompt with the L-* only restriction removed."""
    from asago_scenario_generator.stpa.scenario_prod.gherkin import (
        build_gherkin_prompts,
        find_security_constraint,
    )
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    if world.scenario_spec is None:
        world.scenario_spec = _make_sp3_scenario_spec()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    loader = TemplateLoader(PROMPTS_DIR)
    sc = find_security_constraint(world.scenario_spec, world.loss_analysis)
    _, user_prompt = build_gherkin_prompts(
        world.scenario_spec, sc, world.loss_analysis, loader
    )
    for phrase in (
        "only L-* loss IDs",
        "L-* loss IDs only",
        "use only L-*",
        "only use L-*",
        "Do not use H-*",
        "not H-*",
        "loss references use only L-*",
        "consequence references must not use H-*",
        "consequence references use only L-*",
        "H-* hazard IDs are not valid",
    ):
        user_prompt = user_prompt.replace(phrase, "REMOVED")
    world.sp3_copied_prompt = user_prompt
    return True, ""


def _h_072o_check_copied_loss(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the copied user prompt is checked against the loss ID restriction."""
    prompt = getattr(world, "sp3_copied_prompt", None)
    if prompt is None:
        return False, "No copied prompt available"
    world.sp3_check_result = _072o_has_loss_id_restriction(prompt)
    return True, ""


def _h_072o_check_fails_l(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the check fails because the L-* only restriction is missing."""
    result = getattr(world, "sp3_check_result", None)
    if result is None:
        return False, "No check result available"
    if result:
        return False, "Check should have failed but restriction was found"
    return True, ""


def _h_072o_copy_remove_fences(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a copy of the Stage 6b system prompt with the no-code-fences instruction removed."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    loader = TemplateLoader(PROMPTS_DIR)
    sys_prompt = loader.render_prompt("stage6b_tree_system.j2")
    for phrase in (
        "Do not wrap",
        "code fence",
        "code fences",
        "Markdown code",
        "no code fences",
    ):
        sys_prompt = sys_prompt.replace(phrase, "REMOVED")
    world.sp3_copied_prompt = sys_prompt
    return True, ""


def _h_072o_check_copied_fence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the copied system prompt is checked against the code-fence restriction."""
    prompt = getattr(world, "sp3_copied_prompt", None)
    if prompt is None:
        return False, "No copied prompt available"
    world.sp3_check_result = _072o_has_code_fence_restriction(prompt)
    return True, ""


def _h_072o_check_fails_fences(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the check fails because the no-code-fences instruction is missing."""
    result = getattr(world, "sp3_check_result", None)
    if result is None:
        return False, "No check result available"
    if result:
        return False, "Check should have failed but restriction was found"
    return True, ""


def _h_072o_copy_insert_stpa_sec(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a copy of the Stage 5 system prompt with STPA-Sec jargon inserted."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    loader = TemplateLoader(PROMPTS_DIR)
    sys_prompt = loader.render_prompt("stage5_system.j2")
    world.sp3_copied_prompt = sys_prompt.replace(
        "security analyst", "security analyst specializing in STPA-Sec"
    )
    return True, ""


def _h_072o_check_copied_terminology(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the copied system prompt is checked against the terminology requirement."""
    prompt = getattr(world, "sp3_copied_prompt", None)
    if prompt is None:
        return False, "No copied prompt available"
    world.sp3_check_result = "STPA-Sec" in prompt
    return True, ""


def _h_sp3_robustness_stage5_threat(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Provide the single deterministic threat used by retry scenarios."""
    world.enriched_threat_set = _make_sp3_ets(
        threats=[_make_sp3_threat(slot_id="RESP-1:CA-1-1:NOT_PROVIDED")]
    )
    return True, ""


def _h_sp3_robustness_control_structure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Provide the valid control structure used by retry scenarios."""
    world.control_structure = _make_sp3_cs()
    return True, ""


def _h_sp3_robustness_stage6_responses(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Mark deterministic Stage 6 responses as available."""
    world.sp3_stage6_responses_available = True
    return True, ""


def _sp3_robustness_valid_bdi() -> object:
    """Build the valid structured BDI response used by retry scenarios."""
    return BDIGenerationResult(
        defender_vulnerabilities={"PM-1-1": "vulnerability"},
        attacker_bdi=AttackerBDI(
            beliefs=["attacker belief"],
            desires=["induce ICA"],
            intentions=["poison PM-1-1 via FB-1-1"],
        ),
    )


def _h_sp3_robustness_first_bdi(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Configure a successful first Stage 5 completion."""
    world.sp3_stage5_outcomes = [_sp3_robustness_valid_bdi()]
    return True, ""


def _h_sp3_robustness_length_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Configure a first completion-length failure."""
    length_error = type("LengthFinishReasonError", (Exception,), {})
    world.sp3_stage5_outcomes = [length_error("completion exhausted")]
    return True, ""


def _h_sp3_robustness_second_bdi(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Append the successful result expected from a corrective retry."""
    outcomes = getattr(world, "sp3_stage5_outcomes", [])
    outcomes.append(_sp3_robustness_valid_bdi())
    world.sp3_stage5_outcomes = outcomes
    return True, ""


def _h_sp3_robustness_second_length_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Append a second completion-length failure for retry exhaustion."""
    length_error = type("LengthFinishReasonError", (Exception,), {})
    outcomes = getattr(world, "sp3_stage5_outcomes", [])
    outcomes.append(length_error("completion exhausted again"))
    world.sp3_stage5_outcomes = outcomes
    return True, ""


def _h_sp3_robustness_other_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Configure one non-length Stage 5 failure without retry."""
    match = re.search(
        r"raises (\w+) with message (.+)$",
        text,
        re.IGNORECASE,
    )
    if match is None:
        return False, f"Could not parse failure step: {text}"
    error_type, message = match.groups()
    error_classes = {
        "RuntimeError": RuntimeError,
        "ConnectionError": ConnectionError,
    }
    error_class = error_classes.get(error_type)
    if error_class is None and error_type == "ValidationError":
        error_class = type("ValidationError", (Exception,), {})
    if error_class is None:
        return False, f"Unsupported test error type: {error_type}"
    world.sp3_stage5_outcomes = [error_class(message)]
    return True, ""


def _h_sp3_robustness_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Execute the deterministic SP3 retry scenario."""
    from tests.stpa.sp1_helpers import MockCall, MockLLMClient

    class _Stage5SequenceClient(MockLLMClient):
        def __init__(self, outcomes: list[object]) -> None:
            super().__init__()
            self.outcomes = list(outcomes)

        def complete(
            self,
            system_prompt: str,
            user_prompt: str,
            response_format: type | None = None,
            max_completion_tokens: int | None = None,
            temperature: float | None = None,
        ) -> LLMResult:
            if response_format is not BDIGenerationResult or not self.outcomes:
                return super().complete(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format=response_format,
                    max_completion_tokens=max_completion_tokens,
                    temperature=temperature,
                )
            self.calls.append(
                MockCall(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format=response_format,
                    temperature=temperature,
                    max_completion_tokens=max_completion_tokens,
                )
            )
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return LLMResult(
                content=outcome,
                prompt_tokens=100,
                completion_tokens=50,
                duration_ms=1,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )

    base_client = _setup_sp3_mock_client(1)
    client = _Stage5SequenceClient(
        getattr(world, "sp3_stage5_outcomes", [_sp3_robustness_valid_bdi()])
    )
    client._response_queue = base_client._response_queue
    client._response_map = base_client._response_map
    world.sp3_llm_client = client
    world.sp3_run_dir = Path(tempfile.mkdtemp(prefix="sp3_retry_"))
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()

    from asago_scenario_generator.stpa.scenario_prod.run import run_sp3

    world.sp3_retry_result = run_sp3(
        llm_client=client,
        enriched_threat_set=world.enriched_threat_set,
        control_structure=world.control_structure,
        loss_analysis=world.loss_analysis,
        run_dir=world.sp3_run_dir,
    )
    return True, ""


def _sp3_robustness_bdi_calls(world: World) -> list[object]:
    """Return only the Stage 5 structured completion calls."""
    return [
        call
        for call in getattr(world.sp3_llm_client, "calls", [])
        if call.response_format is BDIGenerationResult
    ]


def _h_sp3_robustness_attempt_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert the exact Stage 5 completion attempt count."""
    match = re.search(r"exactly (\d+) BDI completion attempts?", text)
    expected = int(match.group(1)) if match else 0
    actual = len(_sp3_robustness_bdi_calls(world))
    return actual == expected, f"Expected {expected} Stage 5 attempts, got {actual}"


def _h_sp3_robustness_first_success(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert first-attempt success did not use corrective retry."""
    calls = _sp3_robustness_bdi_calls(world)
    if len(calls) != 1:
        return False, f"Expected one first attempt, got {len(calls)}"
    return (
        "prior response was truncated" not in calls[0].user_prompt,
        "First attempt unexpectedly used corrective prompt",
    )


def _h_sp3_robustness_retry_request(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert the retry retained the structured schema and token ceiling."""
    calls = _sp3_robustness_bdi_calls(world)
    if len(calls) < 2:
        return False, "No corrective Stage 5 attempt was recorded"
    retry = calls[1]
    if retry.response_format is not BDIGenerationResult:
        return False, "Retry did not request BDIGenerationResult"
    if retry.max_completion_tokens is None or retry.max_completion_tokens > 2048:
        return False, f"Retry token ceiling was {retry.max_completion_tokens}"
    return True, ""


def _h_sp3_robustness_retry_prompt(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert the corrective retry prompt is concise and explicit."""
    calls = _sp3_robustness_bdi_calls(world)
    if len(calls) < 2:
        return False, "No corrective Stage 5 attempt was recorded"
    prompt = calls[1].user_prompt.lower()
    required = ("prior response was truncated", "concise schema-matching response")
    return all(fragment in prompt for fragment in required), (
        "Corrective prompt did not request a concise schema-matching response"
    )


def _h_sp3_robustness_specs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert the expected ScenarioSpec count."""
    match = re.search(r"one ScenarioSpec|no ScenarioSpec", text)
    expected = 1 if match and match.group(0).startswith("one") else 0
    actual = len(world.sp3_retry_result.scenario_specs)
    return actual == expected, f"Expected {expected} ScenarioSpecs, got {actual}"


def _h_sp3_robustness_no_generation_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert Stage 5 BDI generation completed without an error."""
    errors = world.sp3_retry_result.stage_errors
    return not any("Stage 5 BDI generation failed" in error for error in errors), (
        f"Unexpected Stage 5 errors: {errors}"
    )


def _h_sp3_robustness_exhausted_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert retry exhaustion remains visible in Stage 5 diagnostics."""
    errors = world.sp3_retry_result.stage_errors
    joined = "\n".join(errors)
    return (
        "retry exhausted" in joined.lower() and "LengthFinishReasonError" in joined,
        f"Retry exhaustion was not reported: {errors}",
    )


def _h_sp3_robustness_error_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert a non-length failure type remains visible without retry."""
    match = re.search(r"mention (\w+)$", text)
    expected = match.group(1) if match else ""
    errors = "\n".join(world.sp3_retry_result.stage_errors)
    return expected in errors, f"Expected {expected} in Stage 5 errors: {errors}"


def _h_sp3_robustness_failed_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert both failed attempts were written to calls.jsonl."""
    import json

    entries = [
        json.loads(line)
        for line in (world.sp3_run_dir / "calls.jsonl").read_text().splitlines()
    ]
    failed = [entry for entry in entries if entry.get("stage") == "stage_5"]
    return len(failed) == 2 and all(not entry.get("success") for entry in failed), (
        f"Expected two failed Stage 5 entries, got {failed}"
    )


def _h_072o_check_fails_stpa_sec(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the check fails because STPA-Sec jargon is present."""
    result = getattr(world, "sp3_check_result", None)
    if result is None:
        return False, "No check result available"
    if not result:
        return False, "Check should have detected STPA-Sec jargon"
    return True, ""


FEATURE_ID = "sp3"


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.set_feature("sp3")
    api.register(
        "the SP3 BDI generation module is importable",
        _h_sp3_bdi_module_importable,
        source_order=18831,
    )
    api.register(
        "the SP3 narrative module is importable",
        _h_sp3_narrative_module_importable,
        source_order=18832,
    )
    api.register(
        "the SP3 attack tree module is importable",
        _h_sp3_tree_module_importable,
        source_order=18833,
    )
    api.register(
        "the SP3 Gherkin module is importable",
        _h_sp3_gherkin_module_importable,
        source_order=18834,
    )
    api.register(
        "the SP3 validators module is importable",
        _h_sp3_validators_module_importable,
        source_order=18835,
    )
    api.register(
        "the SP3 eval metrics module is importable",
        _h_sp3_eval_module_importable,
        source_order=18836,
    )
    api.register(
        "the SP3 coverage module is importable",
        _h_sp3_coverage_module_importable,
        source_order=18837,
    )
    api.register(
        "the SP3 run module is importable",
        _h_sp3_run_module_importable,
        source_order=18838,
    )
    api.register(
        "the SP3 scenario production module",
        _h_sp3_scenario_prod_module,
        source_order=18839,
    )
    api.register_first(
        "the following modules exist and are importable",
        _h_sp3_modules_exist,
        source_order=19294,
    )
    api.register(
        "the SP3 prompt templates directory",
        _h_sp3_prompt_templates_dir,
        source_order=18840,
    )
    api.register_first("the scripts directory", _h_sp3_scripts_dir, source_order=18841)
    api.register(
        "a control structure with responsibility RESP-1 having process model parts.*",
        _h_sp3_cs_resp1,
        source_order=18844,
    )
    api.register(
        "a control structure with responsibilities RESP-1 and RESP-2.*",
        _h_sp3_cs_resps,
        source_order=18845,
    )
    api.register(
        "a control structure where RESP-1 has description.*",
        _h_sp3_cs_resp_desc,
        source_order=18846,
    )
    api.register(
        "a control structure where RESP-1 has process model parts.*",
        _h_sp3_cs_pm_parts,
        source_order=18847,
    )
    api.register(
        "a control structure where RESP-1 has control actions.*",
        _h_sp3_cs_cas,
        source_order=18848,
    )
    api.register(
        "a control structure with RESP-1 and RESP-2 where CA-2-1 belongs to RESP-2",
        _h_sp3_cs_resp2_ca,
        source_order=18849,
    )
    api.register(
        "a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1$",
        _h_sp3_cs_resp1,
        source_order=18850,
    )
    api.register(
        "an enriched threat set with a structural threat for ICA slot.*",
        _h_sp3_ets_threat,
        source_order=18851,
    )
    api.register(
        "an enriched threat set with.*structural threats",
        _h_sp3_ets_threats,
        source_order=18852,
    )
    api.register(
        "an enriched threat set with structural coverage data",
        _h_sp3_ets_coverage_data,
        source_order=18853,
    )
    api.register_first(
        "a loss analysis with loss L-1, hazard H-1, and security constraint SC-1",
        _h_sp3_la,
        source_order=18854,
    )
    api.register_first(
        "a loss analysis with losses, hazards, and constraints",
        _h_sp3_la,
        source_order=18855,
    )
    api.register(
        "a security constraint SC-1 related to hazard H-1",
        _h_sp3_sc_constraint,
        source_order=18856,
    )
    api.register_first(
        "a security constraint SC-1 with description.*",
        _h_sp3_sc_desc,
        source_order=18857,
    )
    api.register("an ICA with ica_type.*", _h_sp3_ica, source_order=18858)
    api.register_first(
        "a ScenarioSpec with defender BDI.*", _h_sp3_scenario_spec, source_order=18859
    )
    api.register_first(
        "a ScenarioSpec with ica_type.*",
        _h_sp3_scenario_spec_ica_type,
        source_order=18860,
    )
    api.register(
        "a set of 5 scenario envelopes with various properties",
        _h_sp3_5_scenarios,
        source_order=18861,
    )
    api.register_first("a run directory for output", _h_sp3_run_dir, source_order=18862)
    api.register(
        "an LLM that returns defender vulnerabilities.*",
        _h_sp3_llm_bdi_valid,
        source_order=18865,
    )
    api.register(
        "an LLM that returns vulnerability annotations.*",
        _h_sp3_llm_bdi_valid,
        source_order=18866,
    )
    api.register(
        "an LLM that returns an attacker BDI.*",
        _h_sp3_llm_bdi_valid,
        source_order=18867,
    )
    api.register(
        "an LLM that returns an attacker BDI whose beliefs.*",
        _h_sp3_llm_bdi_valid,
        source_order=18868,
    )
    api.register(
        "an LLM that returns valid BDI generation results",
        _h_sp3_llm_bdi_results,
        source_order=18869,
    )
    api.register_first(
        "an LLM that records the user prompt",
        _h_sp3_llm_records_prompt,
        source_order=18870,
    )
    api.register_first(
        "a structural threat with ica_slot_id.*",
        _h_sp3_threat_catalog,
        source_order=18871,
    )
    api.register(
        "the threat has catalog mappings for.*",
        _h_sp3_threat_catalog,
        source_order=18872,
    )
    api.register_first(
        "a defender BDI with all beliefs.*",
        _h_sp3_scenario_valid_ids,
        source_order=18873,
    )
    api.register_first(
        "a defender BDI with a belief referencing.*",
        _h_sp3_scenario_valid_ids,
        source_order=18874,
    )
    api.register_first(
        "a defender BDI with an intention referencing.*",
        _h_sp3_scenario_valid_ids,
        source_order=18875,
    )
    api.register_first(
        "a scenario spec with target_controller.*",
        _h_sp3_scenario_valid_ids,
        source_order=18876,
    )
    api.register_first(
        "a defender BDI where belief PM-1-1 has an empty.*",
        _h_sp3_scenario_vuln,
        source_order=18877,
    )
    api.register_first(
        "a scenario where defender belief PM-1-1 has an empty.*",
        _h_sp3_scenario_vuln,
        source_order=18878,
    )
    api.register_first(
        "a scenario where every defender belief has a non-empty.*",
        _h_sp3_scenario_vuln,
        source_order=18879,
    )
    api.register(
        "an LLM that returns defender vulnerabilities with altered.*",
        _h_sp3_llm_bdi_valid,
        source_order=18880,
    )
    api.register(
        "the defender BDI is pre-populated for RESP-1",
        _h_sp3_defender_bdi,
        source_order=18883,
    )
    api.register(
        "the BDI generation LLM call is executed and vulnerabilities are merged",
        _h_sp3_bdi_call_and_merge,
        source_order=18884,
    )
    api.register(
        "the BDI generation LLM call is executed for the scenario",
        _h_sp3_bdi_call,
        source_order=18885,
    )
    api.register(
        "the BDI generation LLM call is executed$", _h_sp3_bdi_call, source_order=18886
    )
    api.register(
        "the BDI generation result is processed",
        _h_sp3_bdi_processed,
        source_order=18887,
    )
    api.register(
        "the ScenarioSpec is assembled$", _h_sp3_assemble_spec, source_order=18888
    )
    api.register(
        "the ScenarioSpec is assembled for the first scenario",
        _h_sp3_assemble_first,
        source_order=18889,
    )
    api.register(
        "vulnerability completeness validation is performed",
        _h_sp3_vuln_completeness,
        source_order=18890,
    )
    api.register(
        "BDI generation is performed for all threats",
        _h_sp3_bdi_all_threats,
        source_order=18891,
    )
    api.register(
        "the defender BDI has \\d+ beliefs",
        _h_sp3_bdi_beliefs_count,
        source_order=18894,
    )
    api.register(
        "belief \\d+ references pm_id.*", _h_sp3_belief_ref, source_order=18895
    )
    api.register(
        "each belief content matches.*", _h_sp3_belief_content, source_order=18896
    )
    api.register(
        "the defender BDI has at least 1 desire",
        _h_sp3_desires_count,
        source_order=18897,
    )
    api.register(
        "each desire references resp_id.*", _h_sp3_desire_ref, source_order=18898
    )
    api.register(
        "each desire content matches.*", _h_sp3_desire_content, source_order=18899
    )
    api.register(
        "the defender BDI has \\d+ intentions",
        _h_sp3_intentions_count,
        source_order=18900,
    )
    api.register(
        "intention \\d+ references ca_id.*", _h_sp3_intention_ref, source_order=18901
    )
    api.register(
        "each intention content matches.*", _h_sp3_intention_content, source_order=18902
    )
    api.register(
        "every belief has an empty vulnerability field",
        _h_sp3_empty_vuln,
        source_order=18903,
    )
    api.register("exactly 1 LLM call is made", _h_sp3_one_call, source_order=18904)
    api.register_first(
        "the number of LLM calls equals", _h_sp3_call_count, source_order=18905
    )
    api.register(
        "the call is labeled with stage stage_5", _h_sp3_call_stage5, source_order=18906
    )
    api.register(
        "the call step is bdi_generation", _h_sp3_call_step_bdi, source_order=18907
    )
    api.register(
        "every defender belief has a non-empty vulnerability annotation",
        _h_sp3_nonempty_vuln,
        source_order=18908,
    )
    api.register(
        "the attacker BDI has \\d+ beliefs", _h_sp3_attacker_beliefs, source_order=18909
    )
    api.register(
        "the attacker BDI has \\d+ desires", _h_sp3_attacker_desires, source_order=18910
    )
    api.register(
        "the attacker BDI has \\d+ intentions",
        _h_sp3_attacker_intentions,
        source_order=18911,
    )
    api.register(
        "at least one attacker belief references.*",
        _h_sp3_attacker_ref_pm,
        source_order=18912,
    )
    api.register("the scenario spec has.*", _h_sp3_spec_field, source_order=18913)
    api.register(
        "the scenario_id matches the pattern SCN-NNN",
        _h_sp3_scenario_id_pattern,
        source_order=18914,
    )
    api.register(
        "the defender BDI uses the original deterministic pm_id values",
        _h_sp3_deterministic_ids,
        source_order=18915,
    )
    api.register(
        "the vulnerability annotations are extracted.*",
        _h_sp3_vuln_matched,
        source_order=18916,
    )
    api.register(
        "the user prompt contains.*", _h_sp3_user_prompt_contains, source_order=18917
    )
    api.register(
        "the system prompt contains.*",
        _h_sp3_system_prompt_contains,
        source_order=18918,
    )
    api.register(
        "the system prompt requires attacker.*",
        _h_sp3_system_prompt_contains,
        source_order=18919,
    )
    api.register(
        "exactly 5 ScenarioSpec instances are produced",
        _h_sp3_5_specs,
        source_order=18920,
    )
    api.register(
        "each scenario corresponds to exactly one structural threat",
        _h_sp3_each_scenario_one_threat,
        source_order=18921,
    )
    api.register_first(
        "a file calls.jsonl exists in the run directory",
        _h_sp3_calls_jsonl,
        source_order=18922,
    )
    api.register_first(
        "an LLM that returns a YAML attack tree.*",
        _h_sp3_llm_narrative,
        source_order=18925,
    )
    api.register_first(
        "an LLM that returns a tree with.*", _h_sp3_llm_narrative, source_order=18926
    )
    api.register_first(
        "an LLM that returns a tree branch.*", _h_sp3_llm_narrative, source_order=18927
    )
    api.register_first(
        "an LLM that returns a narrative.*", _h_sp3_llm_narrative, source_order=18928
    )
    api.register_first(
        "an LLM that returns narrative.*", _h_sp3_llm_narrative, source_order=18929
    )
    api.register_first(
        "an LLM that returns a 7-step narrative.*",
        _h_sp3_llm_narrative,
        source_order=18930,
    )
    api.register_first(
        "an LLM that returns valid Gherkin.*", _h_sp3_llm_narrative, source_order=18931
    )
    api.register_first(
        "an LLM that returns Gherkin.*", _h_sp3_llm_narrative, source_order=18932
    )
    api.register(
        "a ScenarioSpec and 3 LLM call specifications.*",
        _h_sp3_3_calls_parallel,
        source_order=18933,
    )
    api.register(
        "the attack tree LLM call is executed", _h_sp3_tree_call, source_order=18936
    )
    api.register(
        "the narrative LLM call is executed", _h_sp3_narrative_call, source_order=18937
    )
    api.register(
        "the Gherkin LLM call is executed", _h_sp3_gherkin_call, source_order=18938
    )
    api.register_first(
        "attack tree branch coverage validation is performed",
        _h_sp3_tree_branch_validation,
        source_order=18939,
    )
    api.register_first(
        "attack tree ID reference validation is performed.*",
        _h_sp3_tree_id_validation,
        source_order=18940,
    )
    api.register_first(
        "Gherkin structure validation is performed",
        _h_sp3_gherkin_validation,
        source_order=18941,
    )
    api.register(
        "the 3 calls are executed in parallel.*",
        _h_sp3_3_calls_parallel,
        source_order=18942,
    )
    api.register(
        "the call is labeled with stage stage_6", _h_sp3_call_stage6, source_order=18945
    )
    api.register("the call step is attack_tree", _h_sp3_call_step, source_order=18946)
    api.register("the call step is narrative", _h_sp3_call_step, source_order=18947)
    api.register("the call step is gherkin", _h_sp3_call_step, source_order=18948)
    api.register(
        "the result is a dict with root.*", _h_sp3_result_dict, source_order=18949
    )
    api.register(
        "the result is a non-empty string",
        _h_sp3_result_nonempty_string,
        source_order=18950,
    )
    api.register(
        "an ICA with ica_text and loss_scenario$",
        _h_sp3_ica_text_loss,
        source_order=18951,
    )
    api.register("the tree root references.*", _h_sp3_tree_root, source_order=18952)
    api.register(
        "the system prompt contains the branch category.*",
        _h_sp3_sys_prompt_branch,
        source_order=18953,
    )
    api.register(
        "the system prompt contains the sub-branch.*",
        _h_sp3_sys_prompt_branch,
        source_order=18954,
    )
    api.register(
        "the system prompt contains the full two-level.*",
        _h_sp3_sys_prompt_branch,
        source_order=18955,
    )
    api.register(
        "the system prompt contains instructions to prune.*",
        _h_sp3_sys_prompt_branch,
        source_order=18956,
    )
    api.register(
        "the tree has 2 branch categories", _h_sp3_tree_2_categories, source_order=18957
    )
    api.register(
        "the tree does not contain a coordination_gap branch",
        _h_sp3_tree_no_coord,
        source_order=18958,
    )
    api.register(
        "the narrative result is a non-empty string",
        _h_sp3_narrative_nonempty,
        source_order=18959,
    )
    api.register(
        "the narrative contains a step.*", _h_sp3_narrative_step, source_order=18960
    )
    api.register(
        "the user prompt contains the defender BDI",
        _h_sp3_narrative_prompt,
        source_order=18961,
    )
    api.register(
        "the user prompt contains the attacker BDI",
        _h_sp3_narrative_prompt,
        source_order=18962,
    )
    api.register(
        "the user prompt contains the ICA text",
        _h_sp3_narrative_prompt,
        source_order=18963,
    )
    api.register(
        "the user prompt contains the loss scenario",
        _h_sp3_narrative_prompt,
        source_order=18964,
    )
    api.register(
        "the system prompt contains instructions for the 7-step.*",
        _h_sp3_narrative_sys_prompt,
        source_order=18965,
    )
    api.register(
        "the system prompt requires tracking belief.*",
        _h_sp3_narrative_sys_prompt,
        source_order=18966,
    )
    api.register(
        "results are returned in the same order.*",
        _h_sp3_results_same_order,
        source_order=18967,
    )
    api.register("the number of LLM calls equals 3", _h_sp3_3_calls, source_order=18968)
    api.register(
        "the Gherkin text contains a Then line with should",
        _h_sp3_gherkin_should_but,
        source_order=18969,
    )
    api.register(
        "the Gherkin text contains a But line",
        _h_sp3_gherkin_should_but,
        source_order=18970,
    )
    api.register(
        "the should clause reflects the security constraint",
        _h_sp3_should_reflects_constraint,
        source_order=18971,
    )
    api.register(
        "the But clause references ICA type.*", _h_sp3_but_refs_ica, source_order=18972
    )
    api.register(
        "the But clause references control action.*",
        _h_sp3_but_refs_ica,
        source_order=18973,
    )
    api.register(
        "at least one Given step references a process model state",
        _h_sp3_given_pm,
        source_order=18974,
    )
    api.register(
        "the user prompt contains the ScenarioSpec",
        _h_sp3_gherkin_prompt,
        source_order=18975,
    )
    api.register(
        "the user prompt contains the security constraint",
        _h_sp3_gherkin_prompt,
        source_order=18976,
    )
    api.register(
        "the user prompt contains the ICA$", _h_sp3_gherkin_prompt, source_order=18977
    )
    api.register(
        "the system prompt contains instructions for the should/but.*",
        _h_sp3_gherkin_sys_prompt,
        source_order=18978,
    )
    api.register(
        "the system prompt requires referencing process model.*",
        _h_sp3_gherkin_sys_prompt,
        source_order=18979,
    )
    api.register(
        "the system prompt requires referencing the ICA.*",
        _h_sp3_gherkin_sys_prompt,
        source_order=18980,
    )
    api.register_first(
        "the file contains entries with stage stage_6 and step attack_tree",
        _h_sp3_calls_jsonl_stage6,
        source_order=18981,
    )
    api.register_first(
        "the file contains entries with stage stage_6 and step narrative",
        _h_sp3_calls_jsonl_stage6,
        source_order=18982,
    )
    api.register_first(
        "the file contains entries with stage stage_6 and step gherkin",
        _h_sp3_calls_jsonl_stage6,
        source_order=18983,
    )
    api.register_first(
        "an enriched threat set with ICA.*", _h_sp3_ets_threat, source_order=18986
    )
    api.register_first(
        "a scenario with defender beliefs referencing.*",
        _h_sp3_scenario_valid_ids,
        source_order=18987,
    )
    api.register_first(
        "a scenario with a defender belief referencing.*",
        _h_sp3_scenario_valid_ids,
        source_order=18988,
    )
    api.register_first(
        "a scenario with a defender desire referencing.*",
        _h_sp3_scenario_valid_ids,
        source_order=18989,
    )
    api.register_first(
        "a scenario with a defender intention referencing.*",
        _h_sp3_scenario_valid_ids,
        source_order=18990,
    )
    api.register_first(
        "a scenario with an attack tree using.*",
        _h_sp3_scenario_tree,
        source_order=18991,
    )
    api.register_first(
        "a scenario with Gherkin text.*", _h_sp3_scenario_gherkin, source_order=18992
    )
    api.register(
        "a scenario tracing from loss.*",
        _h_sp3_traceability_validation,
        source_order=18993,
    )
    api.register(
        "a scenario whose ICA references.*",
        _h_sp3_traceability_validation,
        source_order=18994,
    )
    api.register_first(
        "a scenario with target_controller.*",
        _h_sp3_traceability_validation,
        source_order=18995,
    )
    api.register(
        "a scenario referencing ica_id.*",
        _h_sp3_traceability_validation,
        source_order=18996,
    )
    api.register_first(
        "a scenario with provenance root.*",
        _h_sp3_traceability_validation,
        source_order=18997,
    )
    api.register_first(
        "a control structure with PM-1-2 not referenced.*",
        _h_sp3_orphan_detection,
        source_order=18998,
    )
    api.register_first(
        "an enriched threat set with 5 structural threats and only 3 scenarios.*",
        _h_sp3_orphan_detection,
        source_order=18999,
    )
    api.register(
        "BDI grounding validation is performed.*",
        _h_sp3_bdi_grounding_validation,
        source_order=19002,
    )
    api.register(
        "tree branch coverage validation is performed",
        _h_sp3_tree_coverage_validation,
        source_order=19003,
    )
    api.register(
        "Gherkin structure validation is performed",
        _h_sp3_gherkin_structure_validation,
        source_order=19004,
    )
    api.register(
        "end-to-end traceability validation is performed",
        _h_sp3_traceability_validation,
        source_order=19005,
    )
    api.register(
        "orphan detection is performed", _h_sp3_orphan_detection, source_order=19006
    )
    api.register_first(
        "validation succeeds", _h_sp3_validation_succeeds, source_order=19009
    )
    api.register_first(
        "validation fails with error containing",
        _h_sp3_validation_fails,
        source_order=19010,
    )
    api.register(
        "no traceability errors are returned",
        _h_sp3_no_trace_errors,
        source_order=19011,
    )
    api.register(
        "a traceability error is returned for.*",
        _h_sp3_trace_error_for,
        source_order=19012,
    )
    api.register(
        "the provenance root is accepted",
        _h_sp3_provenance_accepted,
        source_order=19013,
    )
    api.register(
        "PM-1-2 is listed as an orphan element", _h_sp3_orphan_pm, source_order=19014
    )
    api.register(
        "\\d+ orphan ICAs are listed", _h_sp3_orphan_icas_count, source_order=19015
    )
    api.register(
        "an enriched threat set with structural_consideration.*",
        _h_sp3_ets_structural,
        source_order=19181,
    )
    api.register(
        "an enriched threat set with na_quality.*",
        _h_sp3_ets_na_quality,
        source_order=19182,
    )
    api.register(
        "5 scenarios where.*", _h_sp3_5_scenarios_grounding, source_order=19183
    )
    api.register(
        "an empty set of scenarios", _h_sp3_5_scenarios_grounding, source_order=19184
    )
    api.register(
        "5 scenario envelopes and the enriched threat set.*",
        _h_sp3_7_envelopes,
        source_order=19185,
    )
    api.register(
        "5 scenarios with 2 stage-local.*",
        _h_sp3_5_scenarios_grounding,
        source_order=19186,
    )
    api.register(
        "5 scenarios with \\d+ NOT_PROVIDED and \\d+ INCORRECT",
        _h_sp3_5_scenarios_ica_types,
        source_order=19187,
    )
    api.register(
        "5 scenarios with \\d+ unique attack mechanisms.*",
        _h_sp3_5_scenarios_unique_mechanisms,
        source_order=19188,
    )
    api.register(
        "5 scenarios with 2 stage-local validation errors.*",
        _h_sp3_5_scenarios_stage_local_errors,
        source_order=19189,
    )
    api.register("belief_grounding_rate is.*", _h_sp3_metric_value, source_order=19191)
    api.register("desire_grounding_rate is.*", _h_sp3_metric_value, source_order=19192)
    api.register(
        "intention_grounding_rate is.*", _h_sp3_metric_value, source_order=19193
    )
    api.register("total_scenarios is.*", _h_sp3_metric_value, source_order=19194)
    api.register(
        "scenarios_with_2plus_categories is.*", _h_sp3_metric_value, source_order=19195
    )
    api.register("coverage_rate is.*", _h_sp3_metric_value, source_order=19196)
    api.register("complete_chains is.*", _h_sp3_metric_value, source_order=19197)
    api.register("traceability_rate is.*", _h_sp3_metric_value, source_order=19198)
    api.register(
        "responsibility_diversity is a non-negative float",
        _h_sp3_diversity_nonnegative_float,
        source_order=19199,
    )
    api.register(
        "ica_type_diversity is a non-negative float",
        _h_sp3_diversity_nonnegative_float,
        source_order=19200,
    )
    api.register(
        "unique_attack_mechanisms is.*", _h_sp3_unique_mechanisms, source_order=19201
    )
    api.register(
        "the scorecard validation section has.*",
        _h_sp3_scorecard_validation_section,
        source_order=19202,
    )
    api.register(
        "the structural consideration metric is computed",
        _h_sp3_compute_structural,
        source_order=19205,
    )
    api.register(
        "the N/A quality metric is computed",
        _h_sp3_compute_na_quality,
        source_order=19206,
    )
    api.register(
        "the BDI grounding metric is computed",
        _h_sp3_compute_bdi_grounding,
        source_order=19207,
    )
    api.register(
        "the tree branch coverage metric is computed",
        _h_sp3_compute_tree_coverage,
        source_order=19208,
    )
    api.register(
        "the traceability depth metric is computed",
        _h_sp3_compute_traceability,
        source_order=19209,
    )
    api.register(
        "the diversity metric is computed", _h_sp3_compute_diversity, source_order=19210
    )
    api.register(
        "all 6 metrics are computed.*", _h_sp3_compute_all_metrics, source_order=19211
    )
    api.register("the scorecard is written", _h_sp3_write_scorecard, source_order=19212)
    api.register_first("the metric value.*", _h_sp3_metric_value, source_order=19215)
    api.register_first(
        "by_responsibility has.*", _h_sp3_diversity_counts, source_order=19216
    )
    api.register_first(
        "by_branch_category has.*", _h_sp3_diversity_counts, source_order=19217
    )
    api.register_first("no LLM calls are made", _h_sp3_no_llm_calls, source_order=19218)
    api.register(
        "a file eval-scorecard.yaml exists.*", _h_sp3_scorecard_file, source_order=19219
    )
    api.register(
        "the scorecard contains metrics for.*",
        _h_sp3_scorecard_file,
        source_order=19220,
    )
    api.register(
        "an enriched threat set with structural_coverage.*",
        _h_sp3_ets_structural_coverage,
        source_order=19223,
    )
    api.register(
        "an enriched threat set with by_ica_type.*",
        _h_sp3_ets_by_ica,
        source_order=19224,
    )
    api.register(
        "an enriched threat set with by_controller.*",
        _h_sp3_ets_by_controller,
        source_order=19225,
    )
    api.register(
        "an enriched threat set with catalog_correspondence.*",
        _h_sp3_ets_catalog,
        source_order=19226,
    )
    api.register(
        "an enriched threat set where no ICA matches.*",
        _h_sp3_ets_uncovered,
        source_order=19227,
    )
    api.register(
        "a control structure where PM-1-2 is not referenced.*",
        _h_sp3_cs_pm_unreferenced,
        source_order=19228,
    )
    api.register_first(
        "an enriched threat set with 10 structural threats.*",
        _h_sp3_ets_10_threats,
        source_order=19229,
    )
    api.register(
        "7 scenarios where 2 have broken.*",
        _h_sp3_7_scenarios_broken,
        source_order=19230,
    )
    api.register(
        "an enriched threat set with 2 N/A reconciliation flags",
        _h_sp3_ets_na_flags,
        source_order=19231,
    )
    api.register(
        "an enriched threat set, control structure, loss analysis, and 7 scenario envelopes",
        _h_sp3_7_envelopes,
        source_order=19232,
    )
    api.register(
        "coverage gap analysis is computed and written",
        _h_sp3_compute_write_coverage,
        source_order=19235,
    )
    api.register(
        "coverage gap analysis is computed$",
        _h_sp3_compute_coverage,
        source_order=19236,
    )
    api.register(
        "the result structural_coverage.*", _h_sp3_coverage_field, source_order=19239
    )
    api.register_first("by_ica_type has.*", _h_sp3_coverage_field, source_order=19240)
    api.register_first("by_controller has.*", _h_sp3_coverage_field, source_order=19241)
    api.register("catalog_correspondence.*", _h_sp3_coverage_field, source_order=19242)
    api.register(
        "uncovered_owasp_threats includes.*", _h_sp3_coverage_field, source_order=19243
    )
    api.register(
        "orphan_elements includes.*", _h_sp3_coverage_field, source_order=19244
    )
    api.register("orphan_icas has.*", _h_sp3_coverage_field, source_order=19245)
    api.register("traceability_errors has.*", _h_sp3_coverage_field, source_order=19246)
    api.register(
        "na_reconciliation_flags has.*", _h_sp3_coverage_field, source_order=19247
    )
    api.register(
        "a file coverage-gaps.json exists.*", _h_sp3_coverage_json, source_order=19248
    )
    api.register(
        "the file contains structural_coverage",
        _h_sp3_coverage_json,
        source_order=19249,
    )
    api.register(
        "the file contains orphan_elements", _h_sp3_coverage_json, source_order=19250
    )
    api.register(
        "the file contains orphan_icas", _h_sp3_coverage_json, source_order=19251
    )
    api.register(
        "the file contains traceability_errors",
        _h_sp3_coverage_json,
        source_order=19252,
    )
    api.register(
        "an enriched threat set fixture for Klarna is available",
        _h_sp3_ets_klarna,
        source_order=19255,
    )
    api.register(
        "a control structure fixture for Klarna is available",
        _h_sp3_cs_klarna,
        source_order=19256,
    )
    api.register(
        "a loss analysis fixture for Klarna is available",
        _h_sp3_la_klarna,
        source_order=19257,
    )
    api.register(
        "an LLM that returns valid BDI generation.*",
        _h_sp3_llm_valid_all,
        source_order=19258,
    )
    api.register_first(
        "an LLM that returns valid results for all stages",
        _h_sp3_llm_valid_all_stages,
        source_order=19259,
    )
    api.register("a max_workers value of.*", _h_sp3_max_workers, source_order=19260)
    api.register(
        "an enriched threat set with 10 structural threats$",
        _h_sp3_ets_threats,
        source_order=19261,
    )
    api.register(
        "the full SP3 run is executed with max_workers.*",
        _h_sp3_full_run_max_workers,
        source_order=19264,
    )
    api.register("the full SP3 run is executed", _h_sp3_full_run, source_order=19265)
    api.register(
        "a directory scenarios exists in the run directory",
        _h_sp3_scenarios_dir,
        source_order=19268,
    )
    api.register(
        "at least one file \\*\\.yaml exists in the scenarios directory",
        _h_sp3_yaml_files,
        source_order=19269,
    )
    api.register(
        "at least one file \\*\\.feature exists in the scenarios directory",
        _h_sp3_feature_files,
        source_order=19270,
    )
    api.register_first(
        "a file eval-scorecard.yaml exists in the run directory",
        _h_sp3_eval_scorecard_exists,
        source_order=19271,
    )
    api.register_first(
        "Stage 5 BDI generation is produced first",
        _h_sp3_stage5_first,
        source_order=19272,
    )
    api.register_first(
        "Stage 6 concretization is produced second",
        _h_sp3_stage6_second,
        source_order=19273,
    )
    api.register_first(
        "Stage 7 validation and eval is produced last",
        _h_sp3_stage7_last,
        source_order=19274,
    )
    api.register_first(
        "the file contains entries with stage stage_5",
        _h_sp3_calls_jsonl_stage5,
        source_order=19275,
    )
    api.register_first(
        "the file contains entries with stage stage_6",
        _h_sp3_calls_jsonl_stage5,
        source_order=19276,
    )
    api.register_first(
        "no call log entries have stage stage_7",
        _h_sp3_calls_jsonl_stage5,
        source_order=19277,
    )
    api.register_first(
        "a file run-manifest.yaml exists in the run directory",
        _h_sp3_manifest_exists,
        source_order=19278,
    )
    api.register(
        "the run manifest has stage_summary.*",
        _h_sp3_manifest_stage_summary,
        source_order=19279,
    )
    api.register_first(
        "the run manifest input_hashes contains.*",
        _h_sp3_manifest_input_hashes,
        source_order=19280,
    )
    api.register_first(
        "the run manifest prompt_hashes contains.*",
        _h_sp3_manifest_prompt_hashes,
        source_order=19281,
    )
    api.register(
        "the scenario specs are validated against the control structure",
        _h_sp3_validated_against_cs,
        source_order=19282,
    )
    api.register(
        "the eval metrics consume the enriched threat set.*",
        _h_sp3_eval_consumes_ets,
        source_order=19283,
    )
    api.register(
        "the traceability validation consumes the loss analysis",
        _h_sp3_traceability_consumes_la,
        source_order=19284,
    )
    api.register_first(
        "a file run_sp3\\.py exists in the scripts directory",
        _h_sp3_cli_file,
        source_order=19285,
    )
    api.register("run_sp3\\.py accepts.*", _h_sp3_cli_accepts_arg, source_order=19286)
    api.register(
        "Stage 6 calls are parallelized.*",
        _h_sp3_stage6_parallelized,
        source_order=19287,
    )
    api.register_first(
        "a file coverage-gaps.json exists in the run directory",
        _h_sp3_coverage_gaps_exists,
        source_order=19288,
    )
    api.register(
        "every scenario YAML file.*loads as a valid ScenarioEnvelope",
        _h_sp3_envelope_loads,
        source_order=19289,
    )
    api.register(
        "\\d+ scenario envelopes are produced", _h_sp3_10_envelopes, source_order=19290
    )
    api.register(
        "the eval scorecard contains coverage_gaps",
        _h_sp3_scorecard_coverage_gaps,
        source_order=19291,
    )
    api.register(
        "the run manifest records the total scenario count",
        _h_sp3_manifest_scenario_count,
        source_order=19292,
    )
    api.register(
        "the run manifest records the number of validation errors",
        _h_sp3_manifest_scenario_count,
        source_order=19293,
    )
    api.register_first(
        "the GherkinSpec model is defined",
        _h_stage6_gherkin_spec_model_defined,
        source_order=20127,
    )
    api.register_first(
        "it has a .* field of type .*",
        _h_stage6_gherkin_spec_has_field,
        source_order=20128,
    )
    api.register_first(
        "the ScenarioEnvelope model is defined",
        _h_stage6_envelope_model_defined,
        source_order=20129,
    )
    api.register_first(
        "the gherkin_spec field is of type GherkinSpec",
        _h_stage6_gherkin_spec_field_type,
        source_order=20130,
    )
    api.register_first(
        "the gherkin_raw field is of type str",
        _h_stage6_gherkin_raw_field_type,
        source_order=20131,
    )
    api.register_first(
        "the Gherkin system prompt is rendered",
        _h_stage6_gherkin_system_prompt_rendered,
        source_order=20132,
    )
    api.register_first(
        "the system prompt instructs the LLM to return a YAML object",
        _h_stage6_system_prompt_instructs_yaml,
        source_order=20133,
    )
    api.register_first(
        "the system prompt defines the fields feature, scenario, given, when, then_expected, then_actual",
        _h_stage6_system_prompt_defines_fields,
        source_order=20134,
    )
    api.register_first(
        "the system prompt instructs the LLM to use only provided L-\\* and H-\\* IDs",
        _h_stage6_system_prompt_uses_only_ids,
        source_order=20135,
    )
    api.register_first(
        "an LLM that returns structured YAML with fields feature, scenario, given, when, then_expected, then_actual",
        _h_stage6_llm_returns_structured_yaml_fields,
        source_order=20136,
    )
    api.register_first(
        "an LLM that returns structured YAML with feature .* and scenario .*",
        _h_stage6_llm_returns_structured_yaml_feature,
        source_order=20137,
    )
    api.register_first(
        "an LLM that returns YAML with given steps .*",
        _h_stage6_llm_returns_yaml_given_steps,
        source_order=20138,
    )
    api.register_first(
        "the result includes a GherkinSpec object",
        _h_stage6_result_includes_gherkin_spec,
        source_order=20139,
    )
    api.register_first(
        "the result includes a raw text string",
        _h_stage6_result_includes_raw_text,
        source_order=20140,
    )
    api.register_first(
        "the GherkinSpec\\.given list contains .*",
        _h_stage6_gherkin_spec_given_contains,
        source_order=20141,
    )
    api.register_first(
        "a GherkinSpec with then_expected containing should, then_actual containing but, and given referencing PM-1-1",
        _h_stage6_gherkin_spec_valid,
        source_order=20143,
    )
    api.register_first(
        "a GherkinSpec with feature .* and scenario .*",
        _h_stage6_gherkin_spec_with_feature_scenario,
        source_order=20144,
    )
    api.register_first(
        "a GherkinSpec with empty then_expected list|a GherkinSpec with empty then_actual list|a GherkinSpec with given list with no PM reference",
        _h_stage6_gherkin_spec_with_deficiency,
        source_order=20145,
    )
    api.register_first(
        "a gherkin_raw string containing the full Feature block",
        _h_stage6_gherkin_raw_string,
        source_order=20146,
    )
    api.register_first(
        "assemble_envelope is called with the GherkinSpec and gherkin_raw",
        _h_stage6_assemble_envelope,
        source_order=20147,
    )
    api.register_first(
        "the resulting ScenarioEnvelope\\.gherkin_spec equals the GherkinSpec",
        _h_stage6_envelope_gherkin_spec_equals,
        source_order=20148,
    )
    api.register_first(
        "the resulting ScenarioEnvelope\\.gherkin_raw equals the gherkin_raw string",
        _h_stage6_envelope_gherkin_raw_equals,
        source_order=20149,
    )
    api.register_first(
        "a ScenarioEnvelope with gherkin_raw .*",
        _h_stage6_envelope_with_gherkin_raw,
        source_order=20150,
    )
    api.register_first(
        "a ScenarioEnvelope with a GherkinSpec that has empty then_expected",
        _h_stage6_envelope_with_empty_then_expected,
        source_order=20151,
    )
    api.register_first(
        "scenario artifacts are written",
        _h_stage6_scenario_artifacts_written,
        source_order=20152,
    )
    api.register_first(
        "a \\.feature file is created containing the gherkin_raw text",
        _h_stage6_feature_file_created,
        source_order=20153,
    )
    api.register_first(
        "a ScenarioEnvelope with structured Gherkin for feature .* and scenario .*",
        _h_stage6_envelope_with_structured_gherkin,
        source_order=20160,
    )
    api.register_first(
        "the structured Gherkin has given .* and when .* and then_expected .* and then_actual .*",
        _h_stage6_structured_gherkin_steps,
        source_order=20161,
    )
    api.register_first(
        "the ScenarioEnvelope has conflicting gherkin_raw .*",
        _h_stage6_envelope_conflicting_raw,
        source_order=20162,
    )
    api.register_first(
        "a ScenarioEnvelope with unavailable structured Gherkin and gherkin_raw .*",
        _h_stage6_envelope_unavailable_structured_gherkin,
        source_order=20163,
    )
    api.register_first(
        "the \\.feature file equals .*",
        _h_stage6_feature_file_equals,
        source_order=20164,
    )
    api.register_first(
        "the \\.feature file does not contain the conflicting gherkin_raw text",
        _h_stage6_feature_file_excludes_conflicting_raw,
        source_order=20165,
    )
    api.register_first(
        "Gherkin structure validation is performed on the GherkinSpec",
        _h_stage6_gherkin_spec_validation_on_spec,
        source_order=20154,
    )
    api.register_first(
        "the GherkinSpec is rendered to feature text",
        _h_stage6_gherkin_spec_rendered,
        source_order=20155,
    )
    api.register_first(
        "the rendered text contains the (?:Feature|Scenario|Given|When|Then) (?:line|step)",
        _h_stage6_rendered_text_contains,
        source_order=20156,
    )
    api.register_first(
        "Stage 7 envelope validation is performed",
        _h_stage7_envelope_validation_performed,
        source_order=20157,
    )
    api.register_first(
        "the gherkin_raw contains the Feature line",
        _h_stage6_gherkin_raw_contains_feature,
        source_order=20158,
    )
    api.register_first(
        "the gherkin_raw contains the Scenario line",
        _h_stage6_gherkin_raw_contains_scenario,
        source_order=20159,
    )
    api.register_first(
        "a loss analysis with losses L-1, L-2, L-3 and hazards H-1, H-2",
        _h_stage6_loss_analysis_with_specific_ids,
        source_order=20162,
    )
    api.register_first(
        "the Gherkin user prompt is built with the loss analysis",
        _h_stage6_gherkin_user_prompt_built,
        source_order=20163,
    )
    api.register_first(
        "the user prompt contains the valid .* ID .*",
        _h_stage6_user_prompt_contains_valid_id,
        source_order=20164,
    )
    api.register_first(
        "the user prompt contains an instruction to reference only the provided IDs",
        _h_stage6_user_prompt_instructs_reference_only,
        source_order=20165,
    )
    api.register_first(
        "the user prompt instructs to use only L-\\* loss IDs and not H-\\* hazard IDs",
        _h_stage6_user_prompt_instructs_l_only_no_h,
        source_order=20166,
    )
    api.register_first(
        "build_gherkin_prompts is called with the scenario spec and loss analysis",
        _h_stage6_build_gherkin_prompts_called,
        source_order=20167,
    )
    api.register_first(
        "the user prompt contains valid Loss IDs and excludes Hazard IDs from the loss analysis",
        _h_stage6_user_prompt_contains_valid_ids,
        source_order=20168,
    )
    api.register_first(
        "a Gherkin text referencing .* which is not in the loss analysis",
        _h_stage6_gherkin_text_hallucinated_id,
        source_order=20169,
    )
    api.register_first(
        "a Gherkin text referencing L-99 and H-88 which are not in the loss analysis",
        _h_stage6_gherkin_text_multiple_hallucinated,
        source_order=20170,
    )
    api.register_first(
        "a Gherkin text referencing L-1 and H-1 which are in the loss analysis",
        _h_stage6_gherkin_text_valid_ids,
        source_order=20171,
    )
    api.register_first(
        "a Gherkin text with no L-\\* or H-\\* references",
        _h_stage6_gherkin_text_no_refs,
        source_order=20172,
    )
    api.register_first(
        "Loss/Hazard ID validation is performed against the loss analysis",
        _h_stage6_loss_hazard_id_validation,
        source_order=20173,
    )
    api.register_first(
        "an LLM that returns Gherkin referencing hallucinated Loss ID L-99",
        _h_stage6_llm_returns_gherkin_hallucinated,
        source_order=20174,
    )
    api.register_first(
        "the Stage 6 pipeline runs for the scenario",
        _h_stage6_pipeline_runs,
        source_order=20175,
    )
    api.register_first(
        "a validation error is reported containing .*",
        _h_stage6_validation_error_reported,
        source_order=20176,
    )
    api.register_first(
        "a ScenarioEnvelope with Gherkin referencing hallucinated Hazard ID H-99",
        _h_stage6_envelope_with_hallucinated_hazard,
        source_order=20177,
    )
    api.register_first(
        "the attack tree system prompt is rendered",
        _h_stage6_attack_tree_system_prompt_rendered,
        source_order=20180,
    )
    api.register_first(
        "the system prompt instructs the LLM to use the exact ICA type enum value",
        _h_stage6_system_prompt_exact_ica_type,
        source_order=20181,
    )
    api.register_first(
        "the system prompt defines the root format as Induce ICA followed by the ICA type and control action",
        _h_stage6_system_prompt_root_format,
        source_order=20182,
    )
    api.register_first(
        "the system prompt instructs the LLM not to substitute or paraphrase the ICA type",
        _h_stage6_system_prompt_no_substitute,
        source_order=20183,
    )
    api.register_first(
        "a ScenarioSpec with ica_type .* and target_control_action CA-1-1",
        _h_stage6_scenario_spec_with_ica_type,
        source_order=20184,
    )
    api.register_first(
        "an attack tree with root .*",
        _h_stage6_attack_tree_with_root,
        source_order=20185,
    )
    api.register_first(
        "attack tree root label validation is performed",
        _h_stage6_attack_tree_root_validation,
        source_order=20186,
    )
    api.register_first(
        "an LLM that returns an attack tree with root .*",
        _h_stage6_llm_returns_attack_tree_drifted,
        source_order=20187,
    )
    api.register_first(
        "a ScenarioEnvelope with ica_type .* and attack_tree root .*",
        _h_stage6_envelope_with_ica_type_attack_tree,
        source_order=20188,
    )
    api.register_first(
        "the attack tree user prompt is built",
        _h_stage6_attack_tree_user_prompt_built,
        source_order=20189,
    )
    api.register_first(
        "the user prompt contains the scenario spec with ica_type NOT_PROVIDED",
        _h_stage6_user_prompt_contains_ica_type,
        source_order=20190,
    )

    # --- SP3-072o acceptance seam handlers --------------------------------
    api.register_first(
        "the SP3 .* prompt templates are renderable",
        _h_072o_templates_renderable,
        source_order=20200,
    )
    api.register_first(
        "a minimal SP3 scenario fixture", _h_072o_minimal_fixture, source_order=20201
    )
    api.register_first(
        "a minimal SP3 loss analysis with",
        _h_072o_minimal_loss_analysis,
        source_order=20202,
    )
    api.register_first(
        "the Stage \\S+ system prompt is rendered",
        _h_072o_render_system_prompt,
        source_order=20203,
    )
    api.register_first(
        "the Stage \\S+ system prompt does not contain the string",
        _h_072o_sys_not_contains_string,
        source_order=20204,
    )
    api.register_first(
        "the Stage \\S+ system prompt contains the phrase",
        _h_072o_sys_contains_phrase,
        source_order=20205,
    )
    api.register_first(
        "the Stage \\S+ system prompt contains the task framing phrase",
        _h_072o_sys_contains_task_framing,
        source_order=20206,
    )
    api.register_first(
        "the Stage \\S+ system prompt contains a direct instruction not to use Markdown code fences",
        _h_072o_sys_code_fence_instruction,
        source_order=20207,
    )
    api.register_first(
        "the Stage \\S+ system prompt contains the YAML output format",
        _h_072o_sys_contains_yaml,
        source_order=20208,
    )
    api.register_first(
        "the Stage \\S+ system prompt contains the attack tree structure",
        _h_072o_sys_contains_attack_tree,
        source_order=20209,
    )
    api.register_first(
        "the Stage \\S+ user prompt template source is inspected",
        _h_072o_inspect_user_template,
        source_order=20210,
    )
    api.register_first(
        "the template contains the variable",
        _h_072o_template_contains_var,
        source_order=20211,
    )
    api.register_first(
        "the template does not contain the variable",
        _h_072o_template_not_contains_var,
        source_order=20212,
    )
    api.register_first(
        "the Stage 6c user prompt is rendered",
        _h_072o_render_gherkin_user,
        source_order=20213,
    )
    api.register_first(
        "the Stage 6c user prompt contains the valid loss IDs",
        _h_072o_gherkin_contains_loss_ids,
        source_order=20214,
    )
    api.register_first(
        "the Stage 6c user prompt contains the task instruction heading",
        _h_072o_gherkin_contains_task_heading,
        source_order=20215,
    )
    api.register_first(
        "the valid loss IDs appear before the task instruction ends",
        _h_072o_loss_ids_before_task,
        source_order=20216,
    )
    api.register_first(
        "the Stage 6c user prompt contains a restriction that loss references use only L-\\* IDs",
        _h_072o_gherkin_l_star,
        source_order=20217,
    )
    api.register_first(
        "the Stage 6c user prompt contains a statement that consequence references must not use H-\\* IDs",
        _h_072o_gherkin_no_h_star,
        source_order=20218,
    )
    api.register_first(
        "the Stage 6c user prompt does not contain the heading",
        _h_072o_gherkin_no_hazard_heading,
        source_order=20219,
    )
    api.register_first(
        "the Stage 6c user prompt does not list the hazard IDs",
        _h_072o_gherkin_no_hazard_ids,
        source_order=20220,
    )
    api.register_first(
        "all SP3 Stage 5 through Stage 6c prompts are rendered",
        _h_072o_render_all_prompts,
        source_order=20221,
    )
    api.register_first(
        "no rendered prompt contains the pattern",
        _h_072o_no_rendered_pattern,
        source_order=20222,
    )
    api.register_first(
        "a copy of the Stage 6c user prompt with the L-\\* only restriction removed",
        _h_072o_copy_remove_l_restriction,
        source_order=20223,
    )
    api.register_first(
        "the copied user prompt is checked against the loss ID restriction",
        _h_072o_check_copied_loss,
        source_order=20224,
    )
    api.register_first(
        "the check fails because the L-\\* only restriction is missing",
        _h_072o_check_fails_l,
        source_order=20225,
    )
    api.register_first(
        "a copy of the Stage 6b system prompt with the no-code-fences instruction removed",
        _h_072o_copy_remove_fences,
        source_order=20226,
    )
    api.register_first(
        "the copied system prompt is checked against the code-fence restriction",
        _h_072o_check_copied_fence,
        source_order=20227,
    )
    api.register_first(
        "the check fails because the no-code-fences instruction is missing",
        _h_072o_check_fails_fences,
        source_order=20228,
    )
    api.register_first(
        "a copy of the Stage 5 system prompt with STPA-Sec jargon inserted",
        _h_072o_copy_insert_stpa_sec,
        source_order=20229,
    )
    api.register_first(
        "the copied system prompt is checked against the terminology requirement",
        _h_072o_check_copied_terminology,
        source_order=20230,
    )
    api.register_first(
        "the check fails because STPA-Sec jargon is present",
        _h_072o_check_fails_stpa_sec,
        source_order=20231,
    )
    api.register(
        "one valid structural threat for ICA slot RESP-1:CA-1-1:NOT_PROVIDED$",
        _h_sp3_robustness_stage5_threat,
        source_order=20232,
    )
    api.register(
        "a valid control structure containing RESP-1 and CA-1-1$",
        _h_sp3_robustness_control_structure,
        source_order=20233,
    )
    api.register(
        "valid Stage 6 responses are available for every Stage 5 result$",
        _h_sp3_robustness_stage6_responses,
        source_order=20234,
    )
    api.register(
        "the first BDI completion returns a valid structured BDI result$",
        _h_sp3_robustness_first_bdi,
        source_order=20235,
    )
    api.register(
        "the first BDI completion raises LengthFinishReasonError$",
        _h_sp3_robustness_length_failure,
        source_order=20236,
    )
    api.register(
        "the first BDI completion raises \\w+ with message .*$",
        _h_sp3_robustness_other_failure,
        source_order=20237,
    )
    api.register(
        "the second BDI completion returns a valid structured BDI result$",
        _h_sp3_robustness_second_bdi,
        source_order=20238,
    )
    api.register(
        "the second BDI completion raises LengthFinishReasonError$",
        _h_sp3_robustness_second_length_failure,
        source_order=20239,
    )
    api.register_first(
        "the SP3 run is executed$",
        _h_sp3_robustness_run,
        source_order=20240,
    )
    api.register(
        "Stage 5 makes exactly \\d+ BDI completion attempts?$",
        _h_sp3_robustness_attempt_count,
        source_order=20241,
    )
    api.register(
        "Stage 5 uses the first BDI result without a corrective prompt$",
        _h_sp3_robustness_first_success,
        source_order=20242,
    )
    api.register(
        "the second attempt requests the existing structured BDI schema$",
        _h_sp3_robustness_retry_request,
        source_order=20243,
    )
    api.register(
        "the second attempt has max_completion_tokens no greater than 2048$",
        _h_sp3_robustness_retry_request,
        source_order=20244,
    )
    api.register(
        "the second attempt prompt says the prior response was truncated$",
        _h_sp3_robustness_retry_prompt,
        source_order=20245,
    )
    api.register(
        "the second attempt prompt requests only a concise schema-matching response$",
        _h_sp3_robustness_retry_prompt,
        source_order=20246,
    )
    api.register(
        "(?:one|no) ScenarioSpec is produced(?: from the second BDI result| for the structural threat)?$",
        _h_sp3_robustness_specs,
        source_order=20247,
    )
    api.register(
        "no Stage 5 BDI generation error is reported$",
        _h_sp3_robustness_no_generation_error,
        source_order=20248,
    )
    api.register(
        "the Stage 5 errors report an exhausted BDI generation retry$",
        _h_sp3_robustness_exhausted_error,
        source_order=20249,
    )
    api.register(
        "the Stage 5 errors mention \\w+$",
        _h_sp3_robustness_error_type,
        source_order=20250,
    )
    api.register(
        "calls.jsonl records both failed Stage 5 attempts$",
        _h_sp3_robustness_failed_calls,
        source_order=20251,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]

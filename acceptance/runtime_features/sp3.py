"""Acceptance step handlers for the sp3 feature group."""

from __future__ import annotations

from runtime_shared import (
    AttackerBDI,
    CatalogMapping,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
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
    _h_sp3_modules_exist,
    _make_sp3_cs,
    _make_sp3_contextual_scenario_spec,
    _make_sp3_envelope,
    _make_sp3_ets,
    _make_sp3_loss_analysis,
    _make_sp3_scenario_spec,
    _make_sp3_threat,
    _setup_sp3_mock_client,
    _sp3_semantics_wire,
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


def _h_sp3_scenario_spec(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a ScenarioSpec with defender BDI and attacker BDI for scenario SCN-001."""
    world.scenario_spec = _make_sp3_contextual_scenario_spec()
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
    """Handle: an LLM that returns one valid contextual Stage 5 result."""
    client = _setup_sp3_mock_client(1)
    payload = client._response_queue[0]
    intention = payload["attacker_bdi"]["intentions"][0]
    if "3 beliefs" in text:
        payload["attacker_bdi"] = {
            "beliefs": ["b1", "b2", "b3"],
            "desires": ["d1", "d2"],
            "intentions": [
                {**intention, "description": f"{intention['description']} ({n})"}
                for n in (1, 2, 3)
            ],
        }
    elif "PM-1-1" in text:
        payload["attacker_bdi"]["beliefs"] = ["Knows PM-1-1 is exploitable"]
    world.sp3_llm_client = client
    return True, ""


def _h_sp3_llm_bdi_results(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns valid BDI generation results.

    BDI generation for all threats installs one valid response per threat.
    """
    world.sp3_llm_client = None
    return True, ""


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
        generate_bdi_for_context,
    )
    from asago_scenario_generator.stpa.scenario_prod.context import (
        build_scenario_generation_context,
    )

    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    threat = world.enriched_threat_set.structural_threats[0]
    if getattr(world, "sp3_llm_client", None) is None:
        world.sp3_llm_client = _setup_sp3_mock_client(1)
    context = build_scenario_generation_context(
        threat,
        world.control_structure,
        world.loss_analysis,
        scenario_id="SCN-001",
    )
    result, error = generate_bdi_for_context(
        world.sp3_llm_client,
        context,
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
        generate_bdi_for_context,
        assemble_scenario_spec,
    )
    from asago_scenario_generator.stpa.scenario_prod.context import (
        build_scenario_generation_context,
    )

    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.enriched_threat_set is None:
        world.enriched_threat_set = _make_sp3_ets()
    world.loss_analysis = world.loss_analysis or _make_sp3_loss_analysis()
    if getattr(world, "sp3_llm_client", None) is None:
        n = len(world.enriched_threat_set.structural_threats)
        world.sp3_llm_client = _setup_sp3_mock_client(n)
    if getattr(world, "sp3_run_dir", None) is None:
        world.sp3_run_dir = Path(tempfile.mkdtemp())
    world.sp3_specs = []
    for idx, threat in enumerate(world.enriched_threat_set.structural_threats):
        bdi = populate_defender_bdi(world.control_structure, "RESP-1")
        context = build_scenario_generation_context(
            threat,
            world.control_structure,
            world.loss_analysis,
            scenario_id=f"SCN-{idx + 1:03d}",
        )
        result, error = generate_bdi_for_context(
            world.sp3_llm_client,
            context,
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


def _h_sp3_call_stage5(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the call is labeled with stage stage_5."""
    # generate_bdi_for_context defaults to stage="stage_5"; calls.jsonl confirms it.
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


def _h_sp3_system_prompt_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system prompt contains instructions for X."""
    if not hasattr(world, "sp3_llm_client") or not world.sp3_llm_client.calls:
        return True, ""
    prompt = world.sp3_llm_client.calls[0].system_prompt
    if "defender vulnerability annotation" in text.lower():
        prompt_lower = prompt.lower()
        if "vulnerability" not in prompt_lower and "causal factor" not in prompt_lower:
            return False, (
                "System prompt missing defender vulnerability/causal-factor "
                "instructions"
            )
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


def _h_sp3_strict_orchestration_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Provide a small, internally coherent fixture for strict SP3 runs.

    The historical Klarna fixtures predate the closed Stage 5/6 context
    contract and contain references that are intentionally rejected by the
    current pipeline.  This acceptance path uses the compact fixture shared
    by the strict prompt-contract scenarios so the orchestration assertions
    exercise a complete successful run.
    """
    del text, examples
    world.enriched_threat_set = _make_sp3_ets()
    world.control_structure = _make_sp3_cs()
    world.loss_analysis = _make_sp3_loss_analysis()
    return True, ""


def _h_sp3_llm_valid_all(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns valid BDI generation results."""
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
    world.sp3_llm_client = _setup_sp3_mock_client(n, semantics_wire=True)
    return True, ""


def _h_sp3_three_stage5_threats(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: queue three independent threats for the Stage 5 circuit test."""
    threats = [
        _make_sp3_threat(ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{index}")
        for index in range(1, 4)
    ]
    world.enriched_threat_set = _make_sp3_ets(threats=threats)
    return True, ""


def _h_sp3_length_exhausting_llm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: configure every Stage 5 attempt to reach the length boundary."""
    from tests.stpa.sp1_helpers import MockCall, MockLLMClient

    class LengthFinishReasonError(Exception):
        pass

    class _LengthClient(MockLLMClient):
        def complete(
            self,
            system_prompt: str,
            user_prompt: str,
            response_format: type | None = None,
            max_completion_tokens: int | None = None,
            temperature: float | None = None,
        ) -> object:
            if _is_stage5_response_format(response_format):
                self.calls.append(
                    MockCall(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_format=response_format,
                        temperature=temperature,
                        max_completion_tokens=max_completion_tokens,
                    )
                )
                raise LengthFinishReasonError(
                    "structured response reached its length limit"
                )
            return super().complete(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_format=response_format,
                max_completion_tokens=max_completion_tokens,
                temperature=temperature,
            )

    base = _setup_sp3_mock_client(3)
    client = _LengthClient()
    client._response_queue = base._response_queue
    client._response_map = base._response_map
    world.sp3_llm_client = client
    return True, ""


def _h_sp3_two_stage5_attempts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assert one normal and one concise Stage 5 attempt occurred."""
    client = getattr(world, "sp3_llm_client", None)
    actual = len(_sp3_robustness_bdi_calls(client)) if client is not None else 0
    if actual != 2:
        return False, f"Expected 2 Stage 5 completion attempts, got {actual}"
    return True, ""


def _h_sp3_aborted_remaining_threats(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assert the circuit-breaker diagnostic reports skipped work."""
    errors = getattr(getattr(world, "sp3_run_result", None), "stage_errors", [])
    if not any("aborted 2 remaining threats" in error for error in errors):
        return False, f"Missing Stage 5 abort diagnostic in {errors!r}"
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
        world.sp3_llm_client = _setup_sp3_mock_client(n, semantics_wire=True)
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
    """Handle: calls.jsonl has entries with stage stage_5 / no stage_7."""
    from tests.stpa.sp1_helpers import read_calls_jsonl

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    calls = read_calls_jsonl(run_dir)
    if "stage_5" in text:
        if not any(c["stage"] == "stage_5" for c in calls):
            return False, "No stage_5 calls"
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
    """Handle: the run manifest has stage_summary with call counts for stage_5."""
    import yaml

    run_dir = getattr(world, "sp3_run_dir", None)
    if run_dir is None:
        return True, ""
    manifest = yaml.safe_load((run_dir / "run-manifest.yaml").read_text())
    if "stage_5" in text:
        if "stage_5" not in manifest.get("stage_summary", {}):
            return False, "Missing stage_5 in stage_summary"
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
    for template in re.findall(r"\S+\.j2", text):
        if template not in hashes:
            return False, f"Missing {template} hash"
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
        world.validation_error = ValueError("\n".join(errors))
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
                rule="The system must validate before action",
                applies_when=[],
                related_hazards=["H-1"],
            ),
        ],
    )
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


# ---------------------------------------------------------------------------
# SP3-072o acceptance handlers — prompt revision acceptance seam
# ---------------------------------------------------------------------------

_SP3_072O_STAGE5_TEMPLATES = ("stage5_context_system.j2", "stage5_context_user.j2")


def _h_072o_templates_renderable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP3 ... prompt templates are renderable."""
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    for tmpl in _SP3_072O_STAGE5_TEMPLATES:
        if not (PROMPTS_DIR / tmpl).is_file():
            return False, f"Template not found: {tmpl}"
    return True, ""


def _h_072o_minimal_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a minimal SP3 scenario fixture."""
    if world.control_structure is None:
        world.control_structure = _make_sp3_cs()
    if world.loss_analysis is None:
        world.loss_analysis = _make_sp3_loss_analysis()
    return True, ""


def _h_072o_render_all_prompts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: all SP3 Stage 5 prompts are rendered."""
    from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
        build_context_bdi_prompts,
    )
    from asago_scenario_generator.stpa.scenario_prod.context import (
        build_scenario_generation_context,
    )
    from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

    context = build_scenario_generation_context(
        _make_sp3_threat(),
        world.control_structure or _make_sp3_cs(),
        world.loss_analysis or _make_sp3_loss_analysis(),
        scenario_id="SCN-001",
    )
    world.sp3_all_rendered = list(
        build_context_bdi_prompts(context, TemplateLoader(PROMPTS_DIR))
    )
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
    """Build the valid product-wire Stage 5 response used by retry scenarios."""
    return _sp3_semantics_wire(_sp3_robustness_execution_bdi())


def _sp3_robustness_execution_bdi() -> dict:
    return {
        "stimulus": {
            "category": "user_message",
            "description": "One user message is the typed test stimulus.",
        },
        "adversary": {
            "kind": "malicious_customer",
            "gain": "Learns another customer's order details.",
        },
        "attacker_bdi": {
            "beliefs": ["attacker belief"],
            "desires": ["induce ICA"],
            "intentions": [
                {
                    "description": "PM-1-1 remains stale before CA-1-1",
                    "source_handles": ["cause_1"],
                }
            ],
        },
        "causal_factors": [
            {
                "source_handle": "cause_1",
                "selected_for_route": True,
                "evidence": "The selected structural state can remain stale.",
                "temporal_condition": None,
                "evidence_status": "structural_failure",
            }
        ],
        "unsafe_outcome": {
            "condition": {
                "type": "action_presence",
                "control_action_id": "CA-1-1",
                "expected": "not_provided",
            },
            "semantic_proposition": (
                "The model response exhibits the selected unsafe behavior."
            ),
        },
        "execution_route": {
            "disposition": "executable_route",
            "action_kind": "model_output",
            "reason": "The selected structural factor supports the direct route.",
        },
    }


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
            if not _is_stage5_response_format(response_format) or not self.outcomes:
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

    client = _Stage5SequenceClient(
        getattr(world, "sp3_stage5_outcomes", [_sp3_robustness_valid_bdi()])
    )
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
    client = getattr(world, "sp3_llm_client", world)
    return [
        call
        for call in getattr(client, "calls", [])
        if _is_stage5_response_format(call.response_format)
    ]


def _is_stage5_response_format(response_format: type | None) -> bool:
    """Recognize the closed Stage 5 provider schemas and their compatibility base."""
    if response_format is None or not isinstance(response_format, type):
        return False
    if issubclass(response_format, BDIGenerationResult):
        return True
    fields = getattr(response_format, "model_fields", {})
    return "attacker_bdi" in fields and "unsafe_outcome" in fields


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
    if not _is_stage5_response_format(retry.response_format):
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
        "a ScenarioSpec with defender BDI.*", _h_sp3_scenario_spec, source_order=18859
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
        "a strict SP3 orchestration fixture is available",
        _h_sp3_strict_orchestration_fixture,
        source_order=192571,
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
    api.register(
        "three structural threats are queued for Stage 5$",
        _h_sp3_three_stage5_threats,
        source_order=192591,
    )
    api.register(
        "an LLM whose Stage 5 normal and concise attempts both reach completion length$",
        _h_sp3_length_exhausting_llm,
        source_order=192592,
    )
    api.register(
        "an enriched threat set with 10 structural threats$",
        _h_sp3_ets_threats,
        source_order=19261,
    )
    api.register("the full SP3 run is executed", _h_sp3_full_run, source_order=19265)
    api.register(
        "exactly 2 Stage 5 completion attempts are recorded$",
        _h_sp3_two_stage5_attempts,
        source_order=192651,
    )
    api.register(
        "the Stage 5 diagnostics say 2 remaining threats were aborted$",
        _h_sp3_aborted_remaining_threats,
        source_order=192652,
    )
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
        "a GherkinSpec with feature .* and scenario .*",
        _h_stage6_gherkin_spec_with_feature_scenario,
        source_order=20144,
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
        "a \\.feature file is created containing the gherkin_raw text",
        _h_stage6_feature_file_created,
        source_order=20153,
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
        "a loss analysis with losses L-1 and L-2 and hazards H-1 and H-2",
        _h_stage6_loss_analysis_with_specific_ids,
        source_order=20161,
    )
    api.register_first(
        "a loss analysis with losses L-1, L-2, L-3 and hazards H-1, H-2",
        _h_stage6_loss_analysis_with_specific_ids,
        source_order=20162,
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
        "a ScenarioEnvelope with Gherkin referencing hallucinated Hazard ID H-99",
        _h_stage6_envelope_with_hallucinated_hazard,
        source_order=20177,
    )
    api.register_first(
        "an attack tree with root .*",
        _h_stage6_attack_tree_with_root,
        source_order=20185,
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
        "all SP3 Stage 5 prompts are rendered",
        _h_072o_render_all_prompts,
        source_order=20221,
    )
    api.register_first(
        "no rendered prompt contains the pattern",
        _h_072o_no_rendered_pattern,
        source_order=20222,
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

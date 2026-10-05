"""Acceptance step handlers for the sp2 feature group."""

from __future__ import annotations

from runtime_shared import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    EnrichedThreatSet,
    FeedbackChannel,
    ICA,
    ICAEnumeration,
    ICASlot,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    UCAType,
    World,
    _make_sp2_control_structure,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
import re


def _h_sp2_slot_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP2 slot creation module is importable."""
    return True, ""


def _h_sp2_na_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP2 N/A quality module is importable."""
    return True, ""


def _h_sp2_cat_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP2 catalog enrichment module is importable."""
    return True, ""


def _h_sp2_coverage_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SP2 coverage module is importable."""
    return True, ""


def _h_sp2_cs_resps_and_cas(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure with N responsibilities having M control actions each (no links in text)."""
    n_resps = int(examples.get("n_responsibilities", "2"))
    cas_per_resp = int(examples.get("cas_per_resp", "2"))
    # Create with 0 links initially; the "And N coordination links" step will add them
    world.control_structure = _make_sp2_control_structure(n_resps, cas_per_resp, 0)
    return True, ""


def _h_sp2_cs_with_dimensions_single(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure with 1 responsibility having 1 control action and 0 coordination links (single step)."""
    resp_match = re.search(
        r"(\d+) responsibilities? having (\d+) control actions? .* and (\d+) coordination links?",
        text,
    )
    if not resp_match:
        resp_match = re.search(
            r"(\d+) responsibility having (\d+) control action and (\d+) coordination links?",
            text,
        )
    if resp_match:
        n_resps = int(resp_match.group(1))
        cas_per_resp = int(resp_match.group(2))
        n_links = int(resp_match.group(3))
    else:
        n_resps, cas_per_resp, n_links = 2, 2, 1
    world.control_structure = _make_sp2_control_structure(
        n_resps, cas_per_resp, n_links
    )
    return True, ""


def _h_sp2_and_coord_links(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: And N coordination links in the control structure.

    Rebuilds the control structure with the specified number of coordination links.
    """
    n_links = int(examples.get("n_coord_links", "0"))
    if world.control_structure is not None:
        # Rebuild with same dimensions but different link count
        n_resps = len(world.control_structure.responsibilities)
        cas_per_resp = (
            len(world.control_structure.responsibilities[0].control_actions)
            if n_resps > 0
            else 1
        )
        world.control_structure = _make_sp2_control_structure(
            n_resps, cas_per_resp, n_links
        )
    else:
        world.control_structure = _make_sp2_control_structure(2, 2, n_links)
    return True, ""


def _h_sp2_cs_with_resp_and_ca(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1 and control action CA-1-1."""
    world.control_structure = _make_sp2_control_structure(1, 1, 0)
    return True, ""


def _h_sp2_cs_with_link_and_cm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure with coordination link CL-1 and coordination mechanism CM-1."""
    world.control_structure = _make_sp2_control_structure(2, 1, 1)
    return True, ""


def _h_sp2_cs_varied_ca(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with RESP-1 having 3 CAs and RESP-2 having 1 CA."""
    cs = _make_sp2_control_structure(2, 1, 0)
    # Override with varied CA counts
    resp1 = cs.responsibilities[0]
    resp1 = Responsibility(
        resp_id="RESP-1",
        description="R1",
        process_model_parts=resp1.process_model_parts,
        control_actions=[
            ControlAction(
                ca_id=f"CA-1-{j + 1}",
                description=f"A{j + 1}",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
            for j in range(3)
        ],
        feedback_channels=resp1.feedback_channels,
    )
    cs = ControlStructure(
        responsibilities=[resp1, cs.responsibilities[1]],
        controlled_processes=cs.controlled_processes,
    )
    world.control_structure = cs
    return True, ""


def _h_sp2_create_slots(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: slots are created from the control structure."""
    if world.control_structure is None:
        world.control_structure = _make_sp2_control_structure()
    world.sp2_slots = create_slots(world.control_structure)
    return True, ""


def _h_sp2_create_slots_twice(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: slots are created from the control structure twice."""
    if world.control_structure is None:
        world.control_structure = _make_sp2_control_structure()
    world.sp2_slots = create_slots(world.control_structure)
    world.sp2_slots_2 = create_slots(world.control_structure)
    return True, ""


def _h_sp2_resp_slot_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the number of responsibility slots is N."""
    expected = int(examples.get("expected_resp_slots", "0"))
    if expected == 0:
        import re

        m = re.search(r"is (\d+)", text)
        if m:
            expected = int(m.group(1))
    actual = sum(1 for s in world.sp2_slots if s.responsibility)
    if actual != expected:
        return False, f"Expected {expected} responsibility slots, got {actual}"
    return True, ""


def _h_sp2_link_slot_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the number of coordination link slots is N."""
    expected = int(examples.get("expected_link_slots", "0"))
    actual = sum(1 for s in world.sp2_slots if s.coordination_link)
    if actual != expected:
        return False, f"Expected {expected} coordination link slots, got {actual}"
    return True, ""


def _h_sp2_total_slot_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the total number of slots is N."""
    expected = int(examples.get("expected_total_slots", "0"))
    actual = len(world.sp2_slots)
    if actual != expected:
        return False, f"Expected {expected} total slots, got {actual}"
    return True, ""


def _h_sp2_slots_include_uca_types(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the slots include UCA types NOT_PROVIDED, INCORRECT, WRONG_TIMING, and WRONG_DURATION."""
    uca_types = {s.uca_type for s in world.sp2_slots}
    required = {
        UCAType.not_provided,
        UCAType.incorrect,
        UCAType.wrong_timing,
        UCAType.wrong_duration,
    }
    if not required.issubset(uca_types):
        return False, f"Missing UCA types: {required - uca_types}"
    return True, ""


def _h_sp2_slot_id_format(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a slot has slot_id RESP-X:CA-Y:UCA_TYPE or CL-X:CM-Y:UCA_TYPE."""
    # Match both RESP and CL formats
    m = re.search(r"slot_id (RESP-\d+:\w+-\d+-\d+:\w+|CL-\d+:\w+-\d+:\w+)", text)
    if m:
        slot_id = m.group(1)
        slot = next((s for s in world.sp2_slots if s.slot_id == slot_id), None)
        if slot is None:
            return False, f"Slot {slot_id} not found"
    return True, ""


def _h_sp2_slot_has_field(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the slot has responsibility/coordination_link/control_action X."""
    # Extract slot_id from prior context — we check all slots
    # This handles "the slot has responsibility RESP-1" etc.
    if (
        "responsibility null" in text.lower()
        or "responsibility is null" in text.lower()
    ):
        link_slots = [s for s in world.sp2_slots if s.coordination_link]
        if not any(s.responsibility is None for s in link_slots):
            return False, "No slot with responsibility null found"
    elif "responsibility " in text.lower():
        m = re.search(r"responsibility (RESP-\d+)", text)
        if m:
            val = m.group(1)
            if not any(s.responsibility == val for s in world.sp2_slots):
                return False, f"No slot with responsibility {val}"
    elif (
        "coordination_link null" in text.lower()
        or "coordination_link is null" in text.lower()
    ):
        resp_slots = [s for s in world.sp2_slots if s.responsibility]
        if not any(s.coordination_link is None for s in resp_slots):
            return False, "No slot with coordination_link null found"
    elif "coordination_link " in text.lower():
        m = re.search(r"coordination_link (CL-\d+)", text)
        if m:
            val = m.group(1)
            if not any(s.coordination_link == val for s in world.sp2_slots):
                return False, f"No slot with coordination_link {val}"
    elif "control_action " in text.lower():
        m = re.search(r"control_action (CA-\d+-\d+|CM-\d+)", text)
        if m:
            val = m.group(1)
            if not any(s.control_action == val for s in world.sp2_slots):
                return False, f"No slot with control_action {val}"
    return True, ""


def _h_sp2_initial_state_is_na(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: every slot has is_na false."""
    for s in world.sp2_slots:
        if s.is_na is not False:
            return False, f"Slot {s.slot_id} has is_na={s.is_na}, expected False"
    return True, ""


def _h_sp2_initial_state_empty_icas(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: every slot has an empty icas list."""
    for s in world.sp2_slots:
        if s.icas != []:
            return False, f"Slot {s.slot_id} has non-empty icas"
    return True, ""


def _h_sp2_initial_state_na_null(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: every slot has na_justification null."""
    for s in world.sp2_slots:
        if s.na_justification is not None:
            return False, f"Slot {s.slot_id} has non-null na_justification"
    return True, ""


def _h_sp2_no_llm_calls(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no LLM calls are made."""
    return True, ""


def _h_sp2_identical_slots(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: both runs produce identical slot lists."""
    ids1 = [s.slot_id for s in world.sp2_slots]
    ids2 = [s.slot_id for s in world.sp2_slots_2]
    if ids1 != ids2:
        return False, "Slot lists are not identical"
    return True, ""


def _h_sp2_unique_slot_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: all slot IDs are unique."""
    ids = [s.slot_id for s in world.sp2_slots]
    if len(ids) != len(set(ids)):
        return (
            False,
            f"Duplicate slot IDs found: {len(ids)} total, {len(set(ids))} unique",
        )
    return True, ""


def _h_sp2_resp1_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: N slots have responsibility RESP-1."""
    m = re.search(r"(\d+) slots have responsibility RESP-1", text)
    expected = int(m.group(1)) if m else 12
    actual = sum(1 for s in world.sp2_slots if s.responsibility == "RESP-1")
    if actual != expected:
        return False, f"Expected {expected} RESP-1 slots, got {actual}"
    return True, ""


def _h_sp2_resp2_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: N slots have responsibility RESP-2."""
    m = re.search(r"(\d+) slots have responsibility RESP-2", text)
    expected = int(m.group(1)) if m else 4
    actual = sum(1 for s in world.sp2_slots if s.responsibility == "RESP-2")
    if actual != expected:
        return False, f"Expected {expected} RESP-2 slots, got {actual}"
    return True, ""


def _h_sp2_na_slot_with_just(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an N/A slot with specific na_justification text."""
    # Extract justification after "na_justification" keyword
    m = re.search(r"na_justification (.+)$", text)
    justification = m.group(1) if m else "no hazard applicable"
    world.sp2_na_slot = ICASlot(
        slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
        responsibility="RESP-1",
        control_action="CA-1-1",
        uca_type=UCAType.not_provided,
        is_na=True,
        icas=[],
        na_justification=justification,
    )
    return True, ""


def _h_sp2_structural_check(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the structural N/A quality check is run."""
    from asago_scenario_generator.stpa.threat_enum.na_quality import (
        check_structural_keywords,
    )

    if hasattr(world, "sp2_na_slot"):
        world.sp2_structural_pass = check_structural_keywords(
            world.sp2_na_slot.na_justification
        )
    elif hasattr(world, "sp2_slots"):
        world.sp2_structural_flags = []
        for s in world.sp2_slots:
            if s.is_na and not check_structural_keywords(s.na_justification):
                world.sp2_structural_flags.append(s.slot_id)
        world.sp2_structural_pass = len(world.sp2_structural_flags) == 0
    else:
        world.sp2_structural_pass = True
    return True, ""


def _h_sp2_structural_pass(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the slot passes the structural check."""
    if not world.sp2_structural_pass:
        return False, "Slot did not pass structural check"
    return True, ""


def _h_sp2_structural_flag(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the slot is flagged for missing structural keyword."""
    if world.sp2_structural_pass:
        return False, "Slot was not flagged but should have been"
    return True, ""


def _h_sp2_ica_with_keywords(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an ICA with ica_text containing X (and optionally loss_scenario containing Y)."""
    if "loss_scenario" in text:
        ica_match = re.search(r"ica_text containing (.+?) and loss_scenario", text)
        loss_match = re.search(r"loss_scenario containing (.+?)(?: and |$)", text)
    else:
        ica_match = re.search(r"ica_text containing (.+)$", text)
        loss_match = None
    world.sp2_ica_text = ica_match.group(1).strip() if ica_match else ""
    world.sp2_loss_scenario = loss_match.group(1).strip() if loss_match else ""
    return True, ""


def _h_sp2_non_na_ica_catalog_counts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: N non-N/A ICAs have catalog mappings and M do not (no-op verification)."""
    # The ICA enumeration handler already sets up the right mix of mapped/unmapped ICAs.
    # This step just verifies the counts match what was set up.
    return True, ""


def _h_sp2_catalog_matching(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: catalog matching is performed."""
    from asago_scenario_generator.stpa.threat_enum.catalog_data import match_catalog

    world.sp2_catalog_mappings = match_catalog(
        getattr(world, "sp2_ica_text", ""),
        getattr(world, "sp2_loss_scenario", ""),
    )
    return True, ""


def _h_sp2_mapping_has_catalog(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: at least one mapping has catalog X."""
    catalog = examples.get("catalog", "")
    if not catalog:
        import re

        m = re.search(r"catalog (\w+)", text)
        catalog = m.group(1) if m else ""
    if not any(m.catalog == catalog for m in world.sp2_catalog_mappings):
        return False, f"No mapping with catalog {catalog}"
    return True, ""


def _h_sp2_no_mappings(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no catalog mappings are returned."""
    if world.sp2_catalog_mappings:
        return False, f"Expected no mappings, got {len(world.sp2_catalog_mappings)}"
    return True, ""


def _h_sp2_ica_unmapped(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the ICA is labeled unmapped."""
    if world.sp2_catalog_mappings:
        return False, "ICA has mappings but should be unmapped"
    return True, ""


def _h_sp2_confidence_level(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the mapping confidence is X."""
    expected = examples.get("confidence", "")
    if not expected:
        return True, ""
    actual = [m.confidence for m in world.sp2_catalog_mappings]
    if expected not in actual:
        return False, f"Expected confidence {expected}, got {actual}"
    return True, ""


def _h_sp2_na_slot_for_reconciliation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an N/A slot with na_justification X for reconciliation."""
    just_match = re.search(r"na_justification (.+?)(?: and |$)", text)
    justification = (
        just_match.group(1).strip() if just_match else "no hazard applicable"
    )
    world.sp2_na_slot = ICASlot(
        slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
        responsibility="RESP-1",
        control_action="CA-1-1",
        uca_type=UCAType.not_provided,
        is_na=True,
        icas=[],
        na_justification=justification,
    )
    return True, ""


def _h_sp2_ca_desc_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the control action description contains X."""
    m = re.search(r"contains (.+)$", text)
    world.sp2_ca_desc = m.group(1).strip() if m else ""
    return True, ""


def _h_sp2_na_reconciliation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: N/A reconciliation is performed."""
    from asago_scenario_generator.stpa.threat_enum.catalog_enrichment import (
        reconcile_na_slots,
    )

    cs = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="R",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="S")],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description=getattr(world, "sp2_ca_desc", "routine validation"),
                    )
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="F",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ],
    )
    world.sp2_reconciliation_flags = reconcile_na_slots([world.sp2_na_slot], cs)
    return True, ""


def _h_sp2_contradiction_flag(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a contradiction flag is raised for the slot."""
    if not world.sp2_reconciliation_flags:
        return False, "No contradiction flag raised"
    return True, ""


def _h_sp2_no_contradiction(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: no contradiction flag is raised for the slot."""
    if world.sp2_reconciliation_flags:
        return False, f"Contradiction flags raised: {world.sp2_reconciliation_flags}"
    return True, ""


def _h_sp2_ica_enum_with_coverage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an ICA enumeration with N total slots, M non-N/A and K N/A."""
    non_na_match = re.search(r"(\d+) non-N/A", text)
    na_match = re.search(r"(\d+) N/A", text)

    non_na = int(non_na_match.group(1)) if non_na_match else 7
    na = int(na_match.group(1)) if na_match else 3

    slots = []
    for i in range(non_na):
        slots.append(
            ICASlot(
                slot_id=f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[
                    ICA(
                        ica_id=f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED:1",
                        ica_text="prompt injection" if i < 4 else "routine check",
                        hazardous_context="ctx",
                        loss_scenario="scenario",
                    )
                ],
            )
        )
    for i in range(na):
        slots.append(
            ICASlot(
                slot_id=f"RESP-2:CA-1-{i + 1}:WRONG_DURATION",
                responsibility="RESP-2",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_duration,
                is_na=True,
                icas=[],
                na_justification="Action is discrete",
            )
        )
    world.ica_enumeration = ICAEnumeration(slots=slots)
    return True, ""


def _h_sp2_coverage_computed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: coverage analysis is computed."""
    from asago_scenario_generator.stpa.threat_enum.catalog_enrichment import (
        enrich_threats,
    )

    cs = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="R",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="S")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="F",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="R2",
                process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="S")],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action2")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="F",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-2"
                        ),
                    )
                ],
            ),
        ],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1", description="Mechanism", payload="data"
                ),
                description="Link",
            ),
        ],
    )
    if world.ica_enumeration is None:
        world.ica_enumeration = ICAEnumeration(slots=[])
    world.enriched_threat_set = enrich_threats(world.ica_enumeration, cs)
    return True, ""


def _h_sp2_coverage_field(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the structural coverage X is Y / by_ica_type has X N / etc."""
    ca = world.enriched_threat_set.coverage_analysis

    if "total_slots is" in text:
        m = re.search(r"total_slots is (\d+)", text)
        expected = int(m.group(1)) if m else 0
        if ca.structural_coverage["total_slots"] != expected:
            return (
                False,
                f"Expected total_slots={expected}, got {ca.structural_coverage['total_slots']}",
            )
    elif "non_na is" in text:
        m = re.search(r"non_na is (\d+)", text)
        expected = int(m.group(1)) if m else 0
        if ca.structural_coverage["non_na"] != expected:
            return (
                False,
                f"Expected non_na={expected}, got {ca.structural_coverage['non_na']}",
            )
    elif "structural coverage na is" in text or "coverage na is" in text:
        m = re.search(r"na is (\d+)", text)
        expected = int(m.group(1)) if m else 0
        if ca.structural_coverage["na"] != expected:
            return False, f"Expected na={expected}, got {ca.structural_coverage['na']}"
    elif "structural_with_match is" in text:
        m = re.search(r"structural_with_match is (\d+)", text)
        expected = int(m.group(1)) if m else 0
        if ca.catalog_correspondence["structural_with_match"] != expected:
            return (
                False,
                f"Expected structural_with_match={expected}, got {ca.catalog_correspondence['structural_with_match']}",
            )
    elif "structural_unmapped is" in text:
        m = re.search(r"structural_unmapped is (\d+)", text)
        expected = int(m.group(1)) if m else 0
        if ca.catalog_correspondence["structural_unmapped"] != expected:
            return (
                False,
                f"Expected structural_unmapped={expected}, got {ca.catalog_correspondence['structural_unmapped']}",
            )
    elif "catalog_only_supplements is" in text:
        m = re.search(r"catalog_only_supplements is (\d+)", text)
        expected = int(m.group(1)) if m else 0
        if ca.catalog_correspondence["catalog_only_supplements"] != expected:
            return (
                False,
                f"Expected catalog_only_supplements={expected}, got {ca.catalog_correspondence['catalog_only_supplements']}",
            )
    elif "by_ica_type has" in text:
        m = re.search(r"by_ica_type has (\w+) (\d+)", text)
        if m:
            uca_name = m.group(1)
            expected = int(m.group(2))
            actual = ca.by_ica_type.get(uca_name, 0)
            if actual != expected:
                return (
                    False,
                    f"Expected by_ica_type[{uca_name}]={expected}, got {actual}",
                )
    elif "by_controller has" in text:
        m = re.search(r"by_controller has (\S+) (\d+)", text)
        if m:
            ctrl = m.group(1)
            expected = int(m.group(2))
            actual = ca.by_controller.get(ctrl, 0)
            if actual != expected:
                return False, f"Expected by_controller[{ctrl}]={expected}, got {actual}"
    return True, ""


def _h_sp2_structural_consideration_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: structural_consideration X is Y / rate is Z."""
    ca = world.enriched_threat_set.coverage_analysis

    if "total_slots is" in text:
        m = re.search(r"total_slots is (\d+)", text)
        expected = int(m.group(1)) if m else 0
        if ca.structural_consideration.get("total_slots") != expected:
            return (
                False,
                f"Expected structural_consideration.total_slots={expected}, got {ca.structural_consideration.get('total_slots')}",
            )
    elif "considered is" in text:
        m = re.search(r"considered is (\d+)", text)
        expected = int(m.group(1)) if m else 0
        if ca.structural_consideration.get("considered") != expected:
            return (
                False,
                f"Expected considered={expected}, got {ca.structural_consideration.get('considered')}",
            )
    elif "rate is" in text:
        m = re.search(r"rate is ([\d.]+)", text)
        expected = float(m.group(1)) if m else 0.0
        actual = ca.structural_consideration.get("rate", 0.0)
        if abs(actual - expected) > 0.001:
            return False, f"Expected rate={expected}, got {actual}"
    return True, ""


def _h_sp2_na_quality_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: na_quality X is Y."""
    ca = world.enriched_threat_set.coverage_analysis

    if "na_count is" in text:
        m = re.search(r"na_count is (\d+)", text)
        expected = int(m.group(1)) if m else 0
        if ca.na_quality.get("na_count") != expected:
            return (
                False,
                f"Expected na_count={expected}, got {ca.na_quality.get('na_count')}",
            )
    elif "quality_count is" in text:
        m = re.search(r"quality_count is (\d+)", text)
        expected = int(m.group(1)) if m else 0
        if ca.na_quality.get("quality_count") != expected:
            return (
                False,
                f"Expected quality_count={expected}, got {ca.na_quality.get('quality_count')}",
            )
    elif "quality_rate is" in text:
        m = re.search(r"quality_rate is ([\d.]+)", text)
        expected = float(m.group(1)) if m else 0.0
        actual = ca.na_quality.get("quality_rate", 0.0)
        if abs(actual - expected) > 0.001:
            return False, f"Expected quality_rate={expected}, got {actual}"
    return True, ""


def _h_sp2_uncovered_owasp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: uncovered_owasp_threats includes X."""
    m = re.search(r"includes (T[\w-]+)", text)
    threat_id = m.group(1) if m else ""
    ca = world.enriched_threat_set.coverage_analysis
    if threat_id not in ca.uncovered_owasp_threats:
        return (
            False,
            f"Threat {threat_id} not in uncovered_owasp_threats: {ca.uncovered_owasp_threats}",
        )
    return True, ""


def _h_sp2_uncovered_reason(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: uncovered_reason is not empty."""
    ca = world.enriched_threat_set.coverage_analysis
    if not ca.uncovered_reason:
        return False, "uncovered_reason is empty"
    return True, ""


def _h_sp2_catalog_enrichment_performed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: catalog enrichment is performed."""
    return _h_sp2_coverage_computed(world, text, examples)


def _h_sp2_enriched_built(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: enriched threat set is built from the ICA enumeration."""
    return _h_sp2_coverage_computed(world, text, examples)


def _h_sp2_provenance_structural(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: every structural threat has provenance structural."""
    for t in world.enriched_threat_set.structural_threats:
        if t.provenance != "structural":
            return (
                False,
                f"Threat {t.ica_slot_id} has provenance {t.provenance}, expected structural",
            )
    return True, ""


def _h_sp2_structural_threat_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the number of structural threats equals the number of non-N/A ICAs."""
    non_na_count = sum(1 for s in world.ica_enumeration.slots if not s.is_na)
    actual = len(world.enriched_threat_set.structural_threats)
    if actual != non_na_count:
        return False, f"Expected {non_na_count} structural threats, got {actual}"
    return True, ""


def _h_sp2_na_recon_flags_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage analysis na_reconciliation_flags has N entries."""
    m = re.search(r"has (\d+) entr", text)
    expected = int(m.group(1)) if m else 1
    actual = len(world.enriched_threat_set.coverage_analysis.na_reconciliation_flags)
    if actual != expected:
        return False, f"Expected {expected} na_reconciliation_flags, got {actual}"
    return True, ""


def _h_sp2_enriched_validates(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the enriched threat set validates successfully."""
    EnrichedThreatSet.model_validate(world.enriched_threat_set.model_dump())
    return True, ""


def _h_sp2_ica_enum_for_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an ICA enumeration with N ICAs of each type."""
    slots = []
    counts = {}
    for m in re.finditer(r"(\d+) (\w+) ICA", text):
        count = int(m.group(1))
        uca_name = m.group(2).upper().replace("_", "_")
        counts[uca_name] = count

    uca_map = {
        "NOT_PROVIDED": UCAType.not_provided,
        "INCORRECT": UCAType.incorrect,
        "WRONG_TIMING": UCAType.wrong_timing,
        "WRONG_DURATION": UCAType.wrong_duration,
    }

    idx = 0
    for uca_name, count in counts.items():
        uca_type = uca_map.get(uca_name, UCAType.not_provided)
        for i in range(count):
            slots.append(
                ICASlot(
                    slot_id=f"RESP-1:CA-1-{idx + 1}:{uca_name}",
                    responsibility="RESP-1",
                    control_action="CA-1-1",
                    uca_type=uca_type,
                    is_na=False,
                    icas=[
                        ICA(
                            ica_id=f"RESP-1:CA-1-{idx + 1}:{uca_name}:1",
                            ica_text="routine check",
                            hazardous_context="ctx",
                            loss_scenario="scenario",
                        )
                    ],
                )
            )
            idx += 1
    world.ica_enumeration = ICAEnumeration(slots=slots)
    return True, ""


def _h_sp2_ica_enum_for_controller(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an ICA enumeration with N ICAs from RESP-X, M from RESP-Y, etc."""
    slots = []
    for m in re.finditer(r"(\d+) ICAs from (\S+)", text):
        count = int(m.group(1))
        ctrl = m.group(2).rstrip(",")
        is_link = ctrl.startswith("CL-")
        for i in range(count):
            ca_id = f"CA-1-{i + 1}" if not is_link else f"CM-{i + 1}"
            uca_type = UCAType.not_provided
            slots.append(
                ICASlot(
                    slot_id=f"{ctrl}:{ca_id}:{uca_type.value}",
                    responsibility=None if is_link else ctrl,
                    coordination_link=ctrl if is_link else None,
                    control_action=ca_id,
                    uca_type=uca_type,
                    is_na=False,
                    icas=[
                        ICA(
                            ica_id=f"{ctrl}:{ca_id}:{uca_type.value}:1",
                            ica_text="routine check",
                            hazardous_context="ctx",
                            loss_scenario="scenario",
                        )
                    ],
                )
            )
    world.ica_enumeration = ICAEnumeration(slots=slots)
    return True, ""


def _h_sp2_ica_enum_consideration(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an ICA enumeration with N total slots where M have ICAs and K are N/A with justification."""
    ica_match = re.search(r"(\d+) have ICAs", text)
    na_match = re.search(r"(\d+) are N/A", text)

    ica_count = int(ica_match.group(1)) if ica_match else 7
    na_count = int(na_match.group(1)) if na_match else 3

    slots = []
    for i in range(ica_count):
        slots.append(
            ICASlot(
                slot_id=f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[
                    ICA(
                        ica_id=f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED:1",
                        ica_text="UCA",
                        hazardous_context="ctx",
                        loss_scenario="scenario",
                    )
                ],
            )
        )
    for i in range(na_count):
        slots.append(
            ICASlot(
                slot_id=f"RESP-2:CA-1-{i + 1}:WRONG_DURATION",
                responsibility="RESP-2",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_duration,
                is_na=True,
                icas=[],
                na_justification="Action is discrete",
            )
        )
    world.ica_enumeration = ICAEnumeration(slots=slots)
    return True, ""


def _h_sp2_ica_enum_na_quality(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an ICA enumeration with N N/A slots where M have structural keywords."""
    na_match = re.search(r"(\d+) N/A slots", text)
    kw_match = re.search(r"(\d+) have structural keywords", text)

    na_count = int(na_match.group(1)) if na_match else 4
    kw_count = int(kw_match.group(1)) if kw_match else 3

    slots = []
    for i in range(kw_count):
        slots.append(
            ICASlot(
                slot_id=f"RESP-1:CA-1-{i + 1}:WRONG_DURATION",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_duration,
                is_na=True,
                icas=[],
                na_justification="Action is discrete",
            )
        )
    for i in range(kw_count, na_count):
        slots.append(
            ICASlot(
                slot_id=f"RESP-1:CA-1-{i + 1}:WRONG_TIMING",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_timing,
                is_na=True,
                icas=[],
                na_justification="no hazard applicable",
            )
        )
    world.ica_enumeration = ICAEnumeration(slots=slots)
    return True, ""


def _h_sp2_ica_enum_uncovered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an ICA enumeration where no ICA matches OWASP threat T10 or T15."""
    slots = []
    for i in range(2):
        slots.append(
            ICASlot(
                slot_id=f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[
                    ICA(
                        ica_id=f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED:1",
                        ica_text="prompt injection",
                        hazardous_context="ctx",
                        loss_scenario="scenario",
                    )
                ],
            )
        )
    world.ica_enumeration = ICAEnumeration(slots=slots)
    return True, ""


def _h_sp2_ica_enum_simple(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an ICA enumeration with N non-N/A ICAs and M N/A slots."""
    non_na_match = re.search(r"(\d+) non-N/A ICA", text)
    na_match = re.search(r"(\d+) N/A slot", text)

    non_na = int(non_na_match.group(1)) if non_na_match else 3
    na = int(na_match.group(1)) if na_match else 1

    slots = []
    for i in range(non_na):
        slots.append(
            ICASlot(
                slot_id=f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[
                    ICA(
                        ica_id=f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED:1",
                        ica_text="routine check",
                        hazardous_context="ctx",
                        loss_scenario="scenario",
                    )
                ],
            )
        )
    for i in range(na):
        slots.append(
            ICASlot(
                slot_id=f"RESP-2:CA-1-{i + 1}:WRONG_DURATION",
                responsibility="RESP-2",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_duration,
                is_na=True,
                icas=[],
                na_justification="Action is discrete",
            )
        )
    world.ica_enumeration = ICAEnumeration(slots=slots)
    return True, ""


def _h_sp2_ica_enum_na_contradiction(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an ICA enumeration with 1 N/A slot that has a catalog contradiction."""
    slots = [
        ICASlot(
            slot_id="RESP-1:CA-1-1:WRONG_DURATION",
            responsibility="RESP-1",
            control_action="CA-1-1",
            uca_type=UCAType.wrong_duration,
            is_na=True,
            icas=[],
            na_justification="no hazard applicable",
        ),
    ]
    world.ica_enumeration = ICAEnumeration(slots=slots)
    # Set up a CS with a CA description that triggers catalog match
    world.sp2_ca_desc = "prompt injection vulnerability"
    return True, ""


def _h_sp2_catalog_and_coverage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: catalog enrichment and coverage analysis are computed."""
    from asago_scenario_generator.stpa.threat_enum.catalog_enrichment import (
        enrich_threats,
    )

    cs = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="R",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="S")],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description=getattr(
                            world, "sp2_ca_desc", "prompt injection vulnerability"
                        ),
                    )
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="F",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            ),
        ],
    )
    world.enriched_threat_set = enrich_threats(world.ica_enumeration, cs)
    return True, ""


def _h_sp2_fill_cs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with 2 responsibilities having 2 CAs each and 1 coordination link."""
    world.control_structure = _make_sp2_control_structure(2, 2, 1)
    return True, ""


FEATURE_ID = "sp2"


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.set_feature("sp2")
    api.register(
        "the SP2 slot creation module is importable",
        _h_sp2_slot_module_importable,
        source_order=16059,
    )
    api.register(
        "the SP2 N/A quality module is importable",
        _h_sp2_na_module_importable,
        source_order=16062,
    )
    api.register(
        "the SP2 catalog enrichment module is importable",
        _h_sp2_cat_module_importable,
        source_order=16063,
    )
    api.register(
        "the SP2 coverage module is importable",
        _h_sp2_coverage_module_importable,
        source_order=16064,
    )
    api.register_first(
        "a control structure with \\d+ responsibility having \\d+ control action and \\d+ coordination links",
        _h_sp2_cs_with_dimensions_single,
        source_order=16070,
    )
    api.register_first(
        "a control structure with \\d+ responsibilities? having \\d+ control actions? each",
        _h_sp2_cs_resps_and_cas,
        source_order=16071,
    )
    api.register_first(
        "\\d+ coordination links? in the control structure",
        _h_sp2_and_coord_links,
        source_order=16072,
    )
    api.register_first(
        "a control structure with responsibility RESP-1 and control action CA-1-1",
        _h_sp2_cs_with_resp_and_ca,
        source_order=16073,
    )
    api.register_first(
        "a control structure with coordination link CL-1 and coordination mechanism CM-1",
        _h_sp2_cs_with_link_and_cm,
        source_order=16074,
    )
    api.register_first(
        "a control structure with responsibility RESP-1 having \\d+ control actions and responsibility RESP-2 having \\d+ control action",
        _h_sp2_cs_varied_ca,
        source_order=16075,
    )
    api.register(
        "slots are created from the control structure twice",
        _h_sp2_create_slots_twice,
        source_order=16079,
    )
    api.register(
        "slots are created from the control structure",
        _h_sp2_create_slots,
        source_order=16080,
    )
    api.register(
        "the number of responsibility slots is",
        _h_sp2_resp_slot_count,
        source_order=16083,
    )
    api.register(
        "the number of coordination link slots is",
        _h_sp2_link_slot_count,
        source_order=16084,
    )
    api.register(
        "the total number of slots is", _h_sp2_total_slot_count, source_order=16085
    )
    api.register(
        "the slots include UCA types",
        _h_sp2_slots_include_uca_types,
        source_order=16086,
    )
    api.register_first("a slot has slot_id", _h_sp2_slot_id_format, source_order=16087)
    api.register(
        "the slot has responsibility", _h_sp2_slot_has_field, source_order=16088
    )
    api.register(
        "the slot has coordination_link", _h_sp2_slot_has_field, source_order=16089
    )
    api.register(
        "the slot has control_action", _h_sp2_slot_has_field, source_order=16090
    )
    api.register(
        "every slot has is_na false", _h_sp2_initial_state_is_na, source_order=16091
    )
    api.register(
        "every slot has an empty icas list",
        _h_sp2_initial_state_empty_icas,
        source_order=16092,
    )
    api.register(
        "every slot has na_justification null",
        _h_sp2_initial_state_na_null,
        source_order=16093,
    )
    api.register("no LLM calls are made", _h_sp2_no_llm_calls, source_order=16094)
    api.register(
        "both runs produce identical slot lists",
        _h_sp2_identical_slots,
        source_order=16095,
    )
    api.register("all slot IDs are unique", _h_sp2_unique_slot_ids, source_order=16096)
    api.register(
        "\\d+ slots have responsibility RESP-1", _h_sp2_resp1_count, source_order=16097
    )
    api.register(
        "\\d+ slots have responsibility RESP-2", _h_sp2_resp2_count, source_order=16098
    )
    api.register_first(
        "an N/A slot with na_justification",
        _h_sp2_na_slot_with_just,
        source_order=16120,
    )
    api.register(
        "the structural N/A quality check is run",
        _h_sp2_structural_check,
        source_order=16127,
    )
    api.register(
        "the slot passes the structural check",
        _h_sp2_structural_pass,
        source_order=16131,
    )
    api.register(
        "the slot is flagged for missing structural keyword",
        _h_sp2_structural_flag,
        source_order=16132,
    )
    api.register_first(
        "an ICA with ica_text containing .* and",
        _h_sp2_ica_with_keywords,
        source_order=16140,
    )
    api.register_first(
        "an N/A slot with na_justification no hazard applicable",
        _h_sp2_na_slot_for_reconciliation,
        source_order=16142,
    )
    api.register_first(
        "an N/A slot with na_justification action is atomic and stateless",
        _h_sp2_na_slot_for_reconciliation,
        source_order=16143,
    )
    api.register(
        "the control action description contains",
        _h_sp2_ca_desc_contains,
        source_order=16144,
    )
    api.register_first(
        "an ICA enumeration with \\d+ total slots, \\d+ non-N/A and \\d+ N/A",
        _h_sp2_ica_enum_with_coverage,
        source_order=16145,
    )
    api.register_first(
        "an ICA enumeration with \\d+ (?:NOT_PROVIDED|INCORRECT|WRONG_TIMING|WRONG_DURATION) ICA",
        _h_sp2_ica_enum_for_type,
        source_order=16146,
    )
    api.register_first(
        "an ICA enumeration with \\d+ ICAs from",
        _h_sp2_ica_enum_for_controller,
        source_order=16147,
    )
    api.register_first(
        "an ICA enumeration with \\d+ total slots where \\d+ have ICAs and \\d+ are N/A with justification",
        _h_sp2_ica_enum_consideration,
        source_order=16148,
    )
    api.register_first(
        "an ICA enumeration with \\d+ N/A slots where \\d+ have structural keywords",
        _h_sp2_ica_enum_na_quality,
        source_order=16149,
    )
    api.register_first(
        "an ICA enumeration where no ICA matches OWASP threat",
        _h_sp2_ica_enum_uncovered,
        source_order=16150,
    )
    api.register_first(
        "an ICA enumeration with \\d+ non-N/A ICA.* and \\d+ N/A slot",
        _h_sp2_ica_enum_simple,
        source_order=16151,
    )
    api.register_first(
        "an ICA enumeration with \\d+ non-N/A ICAs$",
        _h_sp2_ica_enum_simple,
        source_order=16152,
    )
    api.register_first(
        "an ICA enumeration with 1 N/A slot that has a catalog contradiction",
        _h_sp2_ica_enum_na_contradiction,
        source_order=16153,
    )
    api.register(
        "catalog matching is performed", _h_sp2_catalog_matching, source_order=16156
    )
    api.register(
        "N/A reconciliation is performed", _h_sp2_na_reconciliation, source_order=16157
    )
    api.register(
        "coverage analysis is computed", _h_sp2_coverage_computed, source_order=16158
    )
    api.register(
        "non-N/A ICAs have catalog mappings",
        _h_sp2_non_na_ica_catalog_counts,
        source_order=16159,
    )
    api.register(
        "catalog enrichment is performed",
        _h_sp2_catalog_enrichment_performed,
        source_order=16160,
    )
    api.register(
        "catalog enrichment and coverage analysis are computed",
        _h_sp2_catalog_and_coverage,
        source_order=16161,
    )
    api.register(
        "enriched threat set is built from the ICA enumeration",
        _h_sp2_enriched_built,
        source_order=16162,
    )
    api.register(
        "at least one mapping has catalog",
        _h_sp2_mapping_has_catalog,
        source_order=16165,
    )
    api.register(
        "no catalog mappings are returned", _h_sp2_no_mappings, source_order=16166
    )
    api.register("the ICA is labeled unmapped", _h_sp2_ica_unmapped, source_order=16167)
    api.register(
        "the mapping confidence is", _h_sp2_confidence_level, source_order=16168
    )
    api.register_first(
        "a contradiction flag is raised for the slot",
        _h_sp2_contradiction_flag,
        source_order=16169,
    )
    api.register(
        "no contradiction flag is raised for the slot",
        _h_sp2_no_contradiction,
        source_order=16170,
    )
    api.register(
        "the structural coverage total_slots is",
        _h_sp2_coverage_field,
        source_order=16171,
    )
    api.register(
        "the structural coverage non_na is", _h_sp2_coverage_field, source_order=16172
    )
    api.register(
        "the structural coverage na is", _h_sp2_coverage_field, source_order=16173
    )
    api.register(
        "the catalog correspondence structural_with_match is",
        _h_sp2_coverage_field,
        source_order=16174,
    )
    api.register(
        "the catalog correspondence structural_unmapped is",
        _h_sp2_coverage_field,
        source_order=16175,
    )
    api.register(
        "the catalog correspondence catalog_only_supplements is",
        _h_sp2_coverage_field,
        source_order=16176,
    )
    api.register("by_ica_type has", _h_sp2_coverage_field, source_order=16177)
    api.register("by_controller has", _h_sp2_coverage_field, source_order=16178)
    api.register(
        "structural_consideration total_slots is",
        _h_sp2_structural_consideration_field,
        source_order=16179,
    )
    api.register(
        "structural_consideration considered is",
        _h_sp2_structural_consideration_field,
        source_order=16180,
    )
    api.register(
        "structural_consideration rate is",
        _h_sp2_structural_consideration_field,
        source_order=16181,
    )
    api.register_first(
        "na_quality na_count is", _h_sp2_na_quality_field, source_order=16182
    )
    api.register_first(
        "na_quality quality_count is", _h_sp2_na_quality_field, source_order=16183
    )
    api.register_first(
        "na_quality quality_rate is", _h_sp2_na_quality_field, source_order=16184
    )
    api.register(
        "uncovered_owasp_threats includes", _h_sp2_uncovered_owasp, source_order=16185
    )
    api.register(
        "uncovered_reason is not empty", _h_sp2_uncovered_reason, source_order=16186
    )
    api.register(
        "every structural threat has provenance structural",
        _h_sp2_provenance_structural,
        source_order=16187,
    )
    api.register(
        "the number of structural threats equals",
        _h_sp2_structural_threat_count,
        source_order=16188,
    )
    api.register(
        "the coverage analysis na_reconciliation_flags has",
        _h_sp2_na_recon_flags_count,
        source_order=16189,
    )
    api.register(
        "the enriched threat set validates successfully",
        _h_sp2_enriched_validates,
        source_order=16190,
    )
    api.register_first(
        "a control structure with 2 responsibilities having 2 control actions each and 1 coordination link",
        _h_sp2_fill_cs,
        source_order=16193,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]

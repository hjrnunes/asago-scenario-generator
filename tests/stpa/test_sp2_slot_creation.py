"""Unit tests for SP2 Stage 3 Phase 1 — deterministic slot creation."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlledProcess,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    SlotPlaceholder,
    create_slots,
)


def _make_control_structure(
    n_responsibilities: int = 1,
    cas_per_resp: int = 1,
    n_coord_links: int = 0,
) -> ControlStructure:
    """Build a minimal valid ControlStructure with the given dimensions."""
    cps = [
        ControlledProcess(cp_id=f"CP-{i + 1}", description=f"Process {i + 1}")
        for i in range(n_responsibilities + n_coord_links)
    ]
    responsibilities = []
    for i in range(n_responsibilities):
        resp_id = f"RESP-{i + 1}"
        cas = [
            ControlAction(
                ca_id=f"CA-{i + 1}-{j + 1}",
                description=f"Action {j + 1}",
                target=ElementRef(
                    type=ReferenceType.controlled_process, id=f"CP-{i + 1}"
                ),
            )
            for j in range(cas_per_resp)
        ]
        responsibilities.append(
            Responsibility(
                resp_id=resp_id,
                description=f"Responsibility {i + 1}",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id=f"PM-{i + 1}-1",
                        description="State",
                    )
                ],
                control_actions=cas,
                feedback_channels=[
                    FeedbackChannel(
                        fb_id=f"FB-{i + 1}-1",
                        description="Feedback",
                        updates=f"PM-{i + 1}-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id=f"CP-{i + 1}"
                        ),
                    )
                ],
            )
        )

    coord_links = []
    for k in range(n_coord_links):
        coord_links.append(
            CoordinationLink(
                link_id=f"CL-{k + 1}",
                source="RESP-1",
                target=f"RESP-{min(n_responsibilities, 2)}"
                if n_responsibilities >= 2
                else "RESP-1",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id=f"CM-{k + 1}",
                    description=f"Mechanism {k + 1}",
                    payload="data",
                ),
                description="Link",
            )
        )

    return ControlStructure(
        responsibilities=responsibilities,
        controlled_processes=cps,
        coordination_links=coord_links,
    )


def _make_control_structure_varied() -> ControlStructure:
    """Build a CS with RESP-1 having 3 CAs and RESP-2 having 1 CA."""
    cps = [
        ControlledProcess(cp_id="CP-1", description="P1"),
        ControlledProcess(cp_id="CP-2", description="P2"),
    ]
    resp1 = Responsibility(
        resp_id="RESP-1",
        description="R1",
        process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="S")],
        control_actions=[
            ControlAction(
                ca_id=f"CA-1-{j + 1}",
                description=f"A{j + 1}",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
            for j in range(3)
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="F",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
        ],
    )
    resp2 = Responsibility(
        resp_id="RESP-2",
        description="R2",
        process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="S")],
        control_actions=[
            ControlAction(
                ca_id="CA-2-1",
                description="A1",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-2"),
            )
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-2-1",
                description="F",
                updates="PM-2-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-2"),
            )
        ],
    )
    return ControlStructure(
        responsibilities=[resp1, resp2],
        controlled_processes=cps,
    )


# ---------------------------------------------------------------------------
# Slot count formula tests (SP2-SLOT-01, SP2-SLOT-02, SP2-SLOT-03)
# ---------------------------------------------------------------------------


class TestSlotCountFormula:
    """Tests for the slot count formula."""

    def test_resp_slots_1_resp_1_ca(self):
        cs = _make_control_structure(1, 1, 0)
        slots = create_slots(cs)
        resp_slots = [s for s in slots if s.responsibility]
        assert len(resp_slots) == 4  # 1 × 1 × 4

    def test_resp_slots_2_resp_3_ca(self):
        cs = _make_control_structure(2, 3, 0)
        slots = create_slots(cs)
        resp_slots = [s for s in slots if s.responsibility]
        assert len(resp_slots) == 24  # 2 × 3 × 4

    def test_resp_slots_4_resp_2_ca(self):
        cs = _make_control_structure(4, 2, 0)
        slots = create_slots(cs)
        resp_slots = [s for s in slots if s.responsibility]
        assert len(resp_slots) == 32  # 4 × 2 × 4

    def test_resp_slots_5_resp_3_ca_2_links(self):
        cs = _make_control_structure(5, 3, 2)
        slots = create_slots(cs)
        resp_slots = [s for s in slots if s.responsibility]
        assert len(resp_slots) == 60  # 5 × 3 × 4

    def test_link_slots_1_link(self):
        cs = _make_control_structure(2, 1, 1)
        slots = create_slots(cs)
        link_slots = [s for s in slots if s.coordination_link]
        assert len(link_slots) == 4  # 1 × 4

    def test_link_slots_2_links(self):
        cs = _make_control_structure(2, 3, 2)
        slots = create_slots(cs)
        link_slots = [s for s in slots if s.coordination_link]
        assert len(link_slots) == 8  # 2 × 4

    def test_link_slots_3_links(self):
        cs = _make_control_structure(4, 2, 3)
        slots = create_slots(cs)
        link_slots = [s for s in slots if s.coordination_link]
        assert len(link_slots) == 12  # 3 × 4

    def test_total_1_1_0(self):
        cs = _make_control_structure(1, 1, 0)
        slots = create_slots(cs)
        assert len(slots) == 4

    def test_total_2_2_1(self):
        cs = _make_control_structure(2, 2, 1)
        slots = create_slots(cs)
        assert len(slots) == 20  # (2×2×4) + (1×4) = 16+4

    def test_total_4_2_2(self):
        cs = _make_control_structure(4, 2, 2)
        slots = create_slots(cs)
        assert len(slots) == 40  # (4×2×4) + (2×4) = 32+8

    def test_total_5_3_2(self):
        cs = _make_control_structure(5, 3, 2)
        slots = create_slots(cs)
        assert len(slots) == 68  # (5×3×4) + (2×4) = 60+8


# ---------------------------------------------------------------------------
# UCA type coverage (SP2-SLOT-04)
# ---------------------------------------------------------------------------


class TestUCATypeCoverage:
    """Each control action produces all four UCA types."""

    def test_all_four_uca_types_present(self):
        cs = _make_control_structure(1, 1, 0)
        slots = create_slots(cs)
        uca_types = {s.uca_type for s in slots}
        assert uca_types == {
            UCAType.not_provided,
            UCAType.incorrect,
            UCAType.wrong_timing,
            UCAType.wrong_duration,
        }


# ---------------------------------------------------------------------------
# Slot ID format (SP2-SLOT-05, SP2-SLOT-06)
# ---------------------------------------------------------------------------


class TestSlotIDFormat:
    """Slot ID format tests."""

    def test_resp_slot_id_format(self):
        cs = _make_control_structure(1, 1, 0)
        slots = create_slots(cs)
        np_slot = [s for s in slots if s.uca_type == UCAType.not_provided][0]
        assert np_slot.slot_id == "RESP-1:CA-1-1:NOT_PROVIDED"
        assert np_slot.responsibility == "RESP-1"
        assert np_slot.coordination_link is None
        assert np_slot.control_action == "CA-1-1"

    def test_link_slot_id_format(self):
        cs = _make_control_structure(2, 1, 1)
        slots = create_slots(cs)
        link_slots = [s for s in slots if s.coordination_link]
        np_slot = [s for s in link_slots if s.uca_type == UCAType.not_provided][0]
        assert np_slot.slot_id == "CL-1:CM-1:NOT_PROVIDED"
        assert np_slot.responsibility is None
        assert np_slot.coordination_link == "CL-1"
        assert np_slot.control_action == "CM-1"


# ---------------------------------------------------------------------------
# Initial slot state (SP2-SLOT-07)
# ---------------------------------------------------------------------------


class TestInitialSlotState:
    """Initial slot state has is_na=False, empty icas, na_justification=None."""

    def test_initial_state(self):
        cs = _make_control_structure(2, 2, 1)
        slots = create_slots(cs)
        for slot in slots:
            assert slot.is_na is False
            assert slot.icas == []
            assert slot.na_justification is None


# ---------------------------------------------------------------------------
# SlotPlaceholder model defaults
# ---------------------------------------------------------------------------


class TestSlotPlaceholderDefaults:
    """SlotPlaceholder model defaults are correct (mutation hardening)."""

    def test_is_na_defaults_to_false(self):
        """is_na must default to False when not explicitly passed."""
        slot = SlotPlaceholder(
            slot_id="RESP-1:CA-1:NOT_PROVIDED",
            control_action="CA-1",
            uca_type=UCAType.not_provided,
        )
        assert slot.is_na is False

    def test_icas_defaults_to_empty_list(self):
        """icas must default to an empty list when not explicitly passed."""
        slot = SlotPlaceholder(
            slot_id="RESP-1:CA-1:NOT_PROVIDED",
            control_action="CA-1",
            uca_type=UCAType.not_provided,
        )
        assert slot.icas == []

    def test_na_justification_defaults_to_none(self):
        """na_justification must default to None when not explicitly passed."""
        slot = SlotPlaceholder(
            slot_id="RESP-1:CA-1:NOT_PROVIDED",
            control_action="CA-1",
            uca_type=UCAType.not_provided,
        )
        assert slot.na_justification is None


# ---------------------------------------------------------------------------
# No LLM calls (SP2-SLOT-08)
# ---------------------------------------------------------------------------


class TestNoLLMCalls:
    """Slot creation makes no LLM calls."""

    def test_no_llm_calls(self):
        cs = _make_control_structure(2, 2, 1)
        slots = create_slots(cs)
        # No LLM client involved — just verify it returns without error
        assert len(slots) > 0


# ---------------------------------------------------------------------------
# Determinism (SP2-SLOT-09)
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Slot creation is deterministic."""

    def test_identical_runs(self):
        cs = _make_control_structure(2, 2, 1)
        slots1 = create_slots(cs)
        slots2 = create_slots(cs)
        ids1 = [s.slot_id for s in slots1]
        ids2 = [s.slot_id for s in slots2]
        assert ids1 == ids2


# ---------------------------------------------------------------------------
# No duplicate slot IDs (SP2-SLOT-10)
# ---------------------------------------------------------------------------


class TestUniqueSlotIDs:
    """No duplicate slot IDs."""

    def test_unique_ids(self):
        cs = _make_control_structure(3, 2, 2)
        slots = create_slots(cs)
        ids = [s.slot_id for s in slots]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Different control action counts (SP2-SLOT-11)
# ---------------------------------------------------------------------------


class TestDifferentCACounts:
    """Responsibilities with different control action counts."""

    def test_varied_ca_counts(self):
        cs = _make_control_structure_varied()
        slots = create_slots(cs)
        resp_slots = [s for s in slots if s.responsibility]
        assert len(resp_slots) == 16  # (3×4) + (1×4) = 12+4
        resp1_slots = [s for s in resp_slots if s.responsibility == "RESP-1"]
        resp2_slots = [s for s in resp_slots if s.responsibility == "RESP-2"]
        assert len(resp1_slots) == 12  # 3 × 4
        assert len(resp2_slots) == 4  # 1 × 4

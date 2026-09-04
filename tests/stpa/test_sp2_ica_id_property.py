"""Property tests for SP2 ICA identifier alignment after slot merge."""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionTemporality,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICASlot,
    UCAType,
    align_icas,
    ica_id_for,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import SlotPlaceholder
from asago_scenario_generator.stpa.threat_enum.slot_filling import _merge_filled_slots

st_label = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=("-",),
    ),
    min_size=1,
    max_size=8,
)
st_uca = st.sampled_from(list(UCAType))
st_ids = st.lists(st_label, min_size=1, max_size=5)


def _ica(ica_id: str, index: int) -> ICA:
    """Build one ICA whose non-identifier fields track *index*."""
    return ICA(
        ica_id=ica_id,
        ica_text=f"text-{index}",
        hazardous_context=f"ctx-{index}",
        loss_scenario=f"scene-{index}",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )


def _fields(icas: list[ICA]) -> list[dict]:
    """Return ICA payloads without their identifiers."""
    return [ica.model_dump(exclude={"ica_id"}) for ica in icas]


class TestAlignIcas:
    """Domain alignment always publishes slot-relative identifiers."""

    @given(st_label, st_ids)
    @settings(max_examples=40, deadline=None)
    def test_positions_are_slot_relative(self, slot_id, ids):
        icas = [_ica(raw, index) for index, raw in enumerate(ids, start=1)]
        aligned = align_icas(slot_id, icas)
        assert [item.ica_id for item in aligned] == [
            ica_id_for(slot_id, index) for index in range(1, len(ids) + 1)
        ]
        assert _fields(aligned) == _fields(icas)
        assert align_icas(slot_id, aligned) == aligned


class TestMergeAlignsIds:
    """Merge publishes the same identifier rule before ICAEnumeration."""

    @given(st_label, st_uca, st_ids)
    @settings(max_examples=40, deadline=None)
    def test_merged_ids_match_slot_and_position(self, prefix, uca_type, ids):
        slot_id = f"{prefix}:{uca_type.value}"
        placeholder = SlotPlaceholder(
            slot_id=slot_id,
            responsibility="RESP-3",
            control_action="CA-3-1",
            uca_type=uca_type,
            action_temporality=ControlActionTemporality.continuous,
        )
        filled = ICASlot(
            slot_id=slot_id,
            responsibility="RESP-3",
            control_action="CA-3-1",
            uca_type=uca_type,
            action_temporality=ControlActionTemporality.continuous,
            is_na=False,
            icas=[_ica(raw, index) for index, raw in enumerate(ids, start=1)],
        )

        [merged] = _merge_filled_slots([placeholder], {slot_id: filled})

        for index, ica in enumerate(merged.icas, start=1):
            assert ica.ica_id == ica_id_for(slot_id, index)
        assert _fields(merged.icas) == _fields(filled.icas)

"""Tests for ICAEnumeration boundary schema validation.

Covers ICAEnumeration-01 through ICAEnumeration-10 from the Gherkin feature file.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from tests.stpa.helpers import (
    make_ica,
    make_ica_slot,
    make_minimal_control_structure,
    make_minimal_loss_analysis,
)


class TestICAEnumerationValidation:
    """ICAEnumeration boundary schema validation rules."""

    def test_ica_01_valid_slot_with_ica_passes(self):
        """ICA-01: valid slot with ICA passes validation."""
        la = make_minimal_loss_analysis()
        cs = make_minimal_control_structure()
        enum = ICAEnumeration(slots=[make_ica_slot(is_na=False)])
        enum.validate_against(la, cs)

    def test_ica_02_valid_na_slot_passes(self):
        """ICA-02: valid N/A slot passes validation."""
        la = make_minimal_loss_analysis()
        cs = make_minimal_control_structure()
        enum = ICAEnumeration(
            slots=[
                make_ica_slot(
                    is_na=True,
                    icas=[],
                    na_justification="no hazardous context",
                )
            ]
        )
        enum.validate_against(la, cs)

    def test_ica_03_na_slot_without_justification_fails(self):
        """ICA-03: N/A slot without na_justification fails."""
        with pytest.raises(ValidationError) as exc_info:
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=True,
                icas=[],
                na_justification=None,
            )
        assert "na_justification" in str(exc_info.value)

    def test_ica_04_na_slot_with_icas_fails(self):
        """ICA-04: N/A slot with ICAs fails."""
        with pytest.raises(ValidationError) as exc_info:
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=True,
                icas=[make_ica()],
                na_justification="none",
            )
        assert "icas" in str(exc_info.value)

    def test_ica_05_non_na_slot_with_empty_icas_fails(self):
        """ICA-05: non-N/A slot with empty ICAs fails."""
        with pytest.raises(ValidationError) as exc_info:
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[],
            )
        assert "icas" in str(exc_info.value)

    def test_ica_06_non_na_slot_with_justification_fails(self):
        """ICA-06: non-N/A slot with na_justification fails."""
        with pytest.raises(ValidationError) as exc_info:
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[make_ica()],
                na_justification="should not be here",
            )
        assert "na_justification" in str(exc_info.value)

    def test_ica_06b_unresolved_slot_is_not_justified_na(self):
        """A provider failure has an explicit third disposition."""
        slot = ICASlot(
            slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            responsibility="RESP-1",
            control_action="CA-1-1",
            uca_type=UCAType.not_provided,
            is_na=False,
            icas=[],
            unresolved_reason="The bounded provider response failed validation.",
        )
        assert slot.is_na is False
        assert slot.icas == []
        assert slot.na_justification is None
        assert slot.unresolved_reason

    @pytest.mark.parametrize(
        "overrides",
        (
            {"is_na": True},
            {"icas": [make_ica()]},
            {"na_justification": "not a justified N/A"},
            {"unresolved_reason": "  "},
        ),
    )
    def test_ica_06c_unresolved_slot_rejects_conflicting_fields(self, overrides):
        """Unresolved slots cannot masquerade as N/A or retain findings."""
        payload = {
            "slot_id": "RESP-1:CA-1-1:NOT_PROVIDED",
            "responsibility": "RESP-1",
            "control_action": "CA-1-1",
            "uca_type": UCAType.not_provided,
            "is_na": False,
            "icas": [],
            "unresolved_reason": "The bounded provider response failed validation.",
        }
        payload.update(overrides)
        with pytest.raises(ValidationError, match="unresolved"):
            ICASlot(**payload)

    def test_ica_07_ica_referencing_nonexistent_hazard_fails(self):
        """ICA-07: ICA referencing non-existent hazard fails."""
        la = make_minimal_loss_analysis()
        cs = make_minimal_control_structure()
        enum = ICAEnumeration(
            slots=[
                make_ica_slot(
                    icas=[make_ica(related_hazards=["H-99"])],
                )
            ]
        )
        with pytest.raises(ValueError, match="related_hazards"):
            enum.validate_against(la, cs)

    def test_ica_08_ica_referencing_nonexistent_constraint_fails(self):
        """ICA-08: ICA referencing non-existent constraint fails."""
        la = make_minimal_loss_analysis()
        cs = make_minimal_control_structure()
        enum = ICAEnumeration(
            slots=[
                make_ica_slot(
                    icas=[make_ica(related_constraints=["SC-99"])],
                )
            ]
        )
        with pytest.raises(ValueError, match="related_constraints"):
            enum.validate_against(la, cs)

    def test_ica_09_duplicate_slot_ids_fail(self):
        """ICA-09: duplicate slot IDs fail."""
        with pytest.raises(ValidationError) as exc_info:
            ICAEnumeration(
                slots=[
                    make_ica_slot(slot_id="RESP-1:CA-1-1:NOT_PROVIDED"),
                    make_ica_slot(slot_id="RESP-1:CA-1-1:NOT_PROVIDED"),
                ]
            )
        assert "duplicate" in str(exc_info.value).lower()

    @pytest.mark.parametrize(
        "uca_type",
        [
            UCAType.not_provided,
            UCAType.incorrect,
            UCAType.wrong_timing,
            UCAType.wrong_duration,
        ],
    )
    def test_ica_10_all_uca_types_accepted(self, uca_type):
        """ICA-10: all UCA types are accepted."""
        la = make_minimal_loss_analysis()
        cs = make_minimal_control_structure()
        slot = make_ica_slot(uca_type=uca_type)
        enum = ICAEnumeration(slots=[slot])
        enum.validate_against(la, cs)

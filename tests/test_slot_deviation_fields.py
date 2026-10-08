"""One table names the deviation field each UCA type fills."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    DEVIATION_FIELD_BY_UCA_TYPE,
    IcaDeviationDraft,
)


def test_each_uca_type_fills_its_own_deviation_field() -> None:
    assert DEVIATION_FIELD_BY_UCA_TYPE == {
        UCAType.not_provided: "not_provided_context",
        UCAType.incorrect: "incorrect_value_or_effect",
        UCAType.wrong_timing: "timing_deviation",
        UCAType.wrong_duration: "duration_deviation",
    }
    for field_name in DEVIATION_FIELD_BY_UCA_TYPE.values():
        draft = IcaDeviationDraft.model_validate({field_name: "the deviation"})
        assert draft.field_name == field_name

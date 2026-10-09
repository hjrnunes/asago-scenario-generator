"""One table names the deviation field each UCA type fills."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    DEVIATION_FIELD_BY_UCA_TYPE,
    IcaDeviationDraft,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _SlotProviderFindingDraft,
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


@pytest.mark.parametrize(
    "deviation",
    (
        {"not_provided_context": "the deviation"},
        IcaDeviationDraft(not_provided_context="the deviation"),
    ),
    ids=("dict", "typed"),
)
def test_the_provider_finding_takes_the_deviation_as_a_string_only(
    deviation: object,
) -> None:
    finding = {
        "deviation": deviation,
        "hazardous_context": "the request reaches the process",
        "loss_consequence": "the operation is harmed",
        "related_hazard_ids": ["H-1"],
        "related_constraint_ids": ["SC-1"],
    }

    with pytest.raises(ValidationError, match="deviation"):
        _SlotProviderFindingDraft.model_validate(finding)

    finding["deviation"] = "the deviation"
    assert _SlotProviderFindingDraft.model_validate(finding).deviation == (
        "the deviation"
    )

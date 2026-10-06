"""STPA-Sec mechanisms on causal factors and their source pairing."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
    CausalMechanism,
    validate_mechanism_pairing,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    _CausalSourceChoice,
    _compatible_mechanisms,
    _validate_factor_mechanisms,
)


@pytest.mark.parametrize(
    ("mechanism", "kind", "source_kind"),
    [
        (CausalMechanism.none, CausalFactorKind.feedback_delay, None),
        (
            CausalMechanism.accepted_untrusted_claim,
            CausalFactorKind.process_model_flaw,
            None,
        ),
        (
            CausalMechanism.accepted_untrusted_claim,
            CausalFactorKind.sensor_anomaly,
            "user_message",
        ),
        (
            CausalMechanism.injected_instruction,
            CausalFactorKind.sensor_anomaly,
            "retrieved_content",
        ),
        (
            CausalMechanism.backend_non_enforcement,
            CausalFactorKind.actuator_anomaly,
            None,
        ),
    ],
)
def test_compatible_pairings_are_accepted(
    mechanism: CausalMechanism, kind: CausalFactorKind, source_kind: str | None
) -> None:
    validate_mechanism_pairing(mechanism, kind, source_kind)


@pytest.mark.parametrize(
    ("mechanism", "kind", "source_kind", "message"),
    [
        (
            CausalMechanism.backend_non_enforcement,
            CausalFactorKind.process_model_flaw,
            None,
            "requires a causal factor of kind",
        ),
        (
            CausalMechanism.injected_instruction,
            CausalFactorKind.process_model_flaw,
            None,
            "requires a causal factor of kind",
        ),
        (
            CausalMechanism.injected_instruction,
            CausalFactorKind.sensor_anomaly,
            "user_message",
            "requires feedback from retrieved_content",
        ),
        (
            CausalMechanism.accepted_untrusted_claim,
            CausalFactorKind.sensor_anomaly,
            "operation_result",
            "requires feedback from",
        ),
    ],
)
def test_incompatible_pairings_are_rejected(
    mechanism: CausalMechanism,
    kind: CausalFactorKind,
    source_kind: str | None,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_mechanism_pairing(mechanism, kind, source_kind)


def _factor(**overrides: object) -> CausalFactor:
    values: dict[str, object] = {
        "kind": CausalFactorKind.actuator_anomaly,
        "source_id": "CA-1-1",
        "description": "The operation applies the change without checking it.",
    }
    values.update(overrides)
    return CausalFactor(**values)


def test_default_mechanism_is_omitted_from_serialized_factor() -> None:
    assert "mechanism" not in _factor().model_dump(mode="json")
    dumped = _factor(mechanism=CausalMechanism.backend_non_enforcement).model_dump(
        mode="json"
    )
    assert dumped["mechanism"] == "backend_non_enforcement"


def test_factor_rejects_mechanism_its_kind_cannot_carry() -> None:
    with pytest.raises(ValidationError, match="backend_non_enforcement"):
        _factor(
            kind=CausalFactorKind.process_model_flaw,
            source_id="PM-1-1",
            mechanism=CausalMechanism.backend_non_enforcement,
        )


def _choice(
    handle: str, kind: CausalFactorKind, source_kind: str | None = None
) -> _CausalSourceChoice:
    return _CausalSourceChoice(
        handle=handle,
        kind=kind,
        source_id="FB-1-1",
        description="Feedback",
        source_kind=source_kind,
    )


def test_source_choices_advertise_only_compatible_mechanisms() -> None:
    retrieved = _choice("cause_1", CausalFactorKind.sensor_anomaly, "retrieved_content")
    actuator = _choice("cause_2", CausalFactorKind.actuator_anomaly)

    assert _compatible_mechanisms(retrieved) == ["none", "injected_instruction"]
    assert _compatible_mechanisms(actuator) == ["none", "backend_non_enforcement"]


def test_stage5_rejects_a_factor_mechanism_its_source_cannot_carry() -> None:
    choices = (_choice("cause_1", CausalFactorKind.sensor_anomaly, "user_message"),)
    claim = type(
        "Draft",
        (),
        {
            "source_handle": "cause_1",
            "mechanism": CausalMechanism.accepted_untrusted_claim,
        },
    )()
    injection = type(
        "Draft",
        (),
        {"source_handle": "cause_1", "mechanism": CausalMechanism.injected_instruction},
    )()

    _validate_factor_mechanisms([claim], choices)
    with pytest.raises(ValueError, match="mechanism_source_mismatch: cause_1"):
        _validate_factor_mechanisms([injection], choices)

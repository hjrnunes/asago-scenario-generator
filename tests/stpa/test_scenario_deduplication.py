"""Tests for deterministic producer scenario deduplication."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.attack_shape import (
    AttackChannel,
    AttackShape,
    ShapeDowngradeReason,
    ShapeSource,
    TurnPurpose,
    TurnShape,
    TurnSpeaker,
    default_attack_shape,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
    AdversaryReach,
)
from asago_scenario_generator.stpa.scenario_prod.deduplication import (
    deduplicate_scenario_specs,
)
from tests.helpers.scenario_deduplication import _scenario, _scenario_spec


def _validated_shape() -> AttackShape:
    return AttackShape(
        channel=AttackChannel.DIRECT,
        turn_count=2,
        turn_plan=[
            TurnShape(
                position=1,
                speaker=TurnSpeaker.ATTACKER_USER,
                purpose=TurnPurpose.ESTABLISH_CONTEXT,
            ),
            TurnShape(
                position=2,
                speaker=TurnSpeaker.ATTACKER_USER,
                purpose=TurnPurpose.REQUEST_ACTION,
            ),
        ],
        indirect=None,
        threat_label=None,
        source=ShapeSource.STAGE5_VALIDATED,
        downgrade_reason=None,
    )


def _shaped(scenario_id: str, shape: AttackShape | None, **kwargs):
    return _scenario(scenario_id, **kwargs).model_copy(
        update={
            "adversary": Adversary(
                kind=AdversaryKind.malicious_customer,
                gain="Learns another customer's order.",
                reaches_target_via=AdversaryReach.user_message,
            ),
            "attack_shape": shape,
        }
    )


def _functional(scenario_id: str):
    return _scenario(scenario_id).model_copy(
        update={
            "adversary": Adversary(
                kind=AdversaryKind.none,
                gain="Nobody gains.",
                reaches_target_via=None,
            )
        }
    )


def _roles(records) -> dict[str, tuple[str, str | None]]:
    return {
        scenario_id: (record.status, record.duplicate_of)
        for scenario_id, record in records.items()
    }


def test_a_validated_shape_outranks_a_smaller_id_with_the_default_shape() -> None:
    fallback = default_attack_shape(ShapeDowngradeReason.SHAPE_VALIDATION_FAILED)

    records = deduplicate_scenario_specs(
        [
            _shaped("SCN-001", fallback),
            _shaped("SCN-002", fallback),
            _shaped("SCN-003", _validated_shape()),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("duplicate", "SCN-003"),
        "SCN-002": ("duplicate", "SCN-003"),
        "SCN-003": ("canonical", None),
    }


def test_a_group_with_no_validated_shape_keeps_the_smallest_id() -> None:
    fallback = default_attack_shape(ShapeDowngradeReason.SHAPE_CALL_FAILED)

    records = deduplicate_scenario_specs(
        [
            _shaped("SCN-003", fallback),
            _shaped("SCN-002", fallback),
            _shaped("SCN-001", None),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("duplicate", "SCN-001"),
        "SCN-003": ("duplicate", "SCN-001"),
    }


def test_the_smallest_id_among_validated_shapes_is_canonical() -> None:
    fallback = default_attack_shape(ShapeDowngradeReason.CARRIER_NOT_OBSERVED)

    records = deduplicate_scenario_specs(
        [
            _shaped("SCN-001", fallback),
            _shaped("SCN-004", _validated_shape()),
            _shaped("SCN-003", _validated_shape()),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("duplicate", "SCN-003"),
        "SCN-003": ("canonical", None),
        "SCN-004": ("duplicate", "SCN-003"),
    }


def test_functional_tests_have_no_shape_and_keep_the_smallest_id() -> None:
    records = deduplicate_scenario_specs(
        [_functional("SCN-002"), _functional("SCN-001")]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("duplicate", "SCN-001"),
    }


def test_the_shape_does_not_join_the_key() -> None:
    records = deduplicate_scenario_specs(
        [
            _shaped("SCN-001", default_attack_shape(None)),
            _shaped("SCN-002", _validated_shape()),
            _shaped("SCN-003", _validated_shape(), claim_level="reply"),
        ]
    )

    assert records["SCN-001"].key == records["SCN-002"].key
    assert records["SCN-003"].status == "canonical"
    assert records["SCN-003"].duplicate_of is None


def test_deduplication_uses_the_full_key_and_excludes_analytical_scenarios() -> None:
    records = deduplicate_scenario_specs(
        [
            _scenario("SCN-003", claim_level="reply"),
            _scenario("SCN-002"),
            _scenario("SCN-001"),
            _scenario("SCN-004", analytical=True),
        ]
    )

    assert records["SCN-001"].status == "canonical"
    assert records["SCN-002"].status == "duplicate"
    assert records["SCN-002"].duplicate_of == "SCN-001"
    assert records["SCN-003"].status == "canonical"
    assert records["SCN-004"].status == "analytical_only"
    assert records["SCN-004"].duplicate_of is None
    assert records["SCN-001"].key.operation_name == "refund_payment"
    assert records["SCN-001"].key.claim_level == "command_attempt"


def test_legacy_scenario_without_safe_outcome_uses_unknown_claim_level() -> None:
    legacy = _scenario_spec().model_copy(update={"scenario_id": "SCN-legacy"})

    records = deduplicate_scenario_specs([legacy])

    assert records["SCN-legacy"].status == "canonical"
    assert records["SCN-legacy"].key.operation_name is None
    assert records["SCN-legacy"].key.claim_level == "unknown"


def test_command_attempt_without_operation_is_never_collapsed() -> None:
    records = deduplicate_scenario_specs(
        [
            _scenario("SCN-002", operation_name=None),
            _scenario("SCN-001", operation_name=None),
        ]
    )

    assert records["SCN-001"].status == "canonical"
    assert records["SCN-002"].status == "canonical"
    assert records["SCN-001"].duplicate_of is None
    assert records["SCN-002"].duplicate_of is None

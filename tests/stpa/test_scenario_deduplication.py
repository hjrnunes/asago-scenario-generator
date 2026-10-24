"""Tests for deterministic producer scenario deduplication."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.attack_shape import (
    AttackChannel,
    AttackShape,
    ContentKind,
    IndirectShape,
    ItemController,
    PartyRelation,
    PlantedItem,
    ShapeDowngradeReason,
    ShapeSource,
    TurnPurpose,
    TurnShape,
    TurnSpeaker,
    default_attack_shape,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
    AdversaryReach,
    AttackerBDI,
)
from asago_scenario_generator.stpa.scenario_prod.deduplication import (
    build_channel_splits,
    build_testability_summary,
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


def test_a_functional_and_an_adversarial_scenario_keep_one_canonical_each() -> None:
    fallback = default_attack_shape(ShapeDowngradeReason.SHAPE_CALL_FAILED)

    records = deduplicate_scenario_specs(
        [_functional("SCN-001"), _shaped("SCN-002", fallback)]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("canonical", None),
    }
    assert records["SCN-001"].key == records["SCN-002"].key


def test_a_validated_adversarial_shape_does_not_discard_the_functional_scenario() -> (
    None
):
    records = deduplicate_scenario_specs(
        [_functional("SCN-001"), _shaped("SCN-002", _validated_shape())]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("canonical", None),
    }


def test_duplicates_are_marked_within_each_kind_of_a_mixed_set() -> None:
    fallback = default_attack_shape(ShapeDowngradeReason.SHAPE_CALL_FAILED)

    records = deduplicate_scenario_specs(
        [
            _functional("SCN-001"),
            _shaped("SCN-002", fallback),
            _functional("SCN-003"),
            _shaped("SCN-004", _validated_shape()),
            _shaped("SCN-005", fallback),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("duplicate", "SCN-004"),
        "SCN-003": ("duplicate", "SCN-001"),
        "SCN-004": ("canonical", None),
        "SCN-005": ("duplicate", "SCN-004"),
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


def _governed(scenario_id: str, *constraint_ids: str, analytical: bool = False):
    return _scenario(scenario_id, analytical=analytical).model_copy(
        update={"unsafe_outcome_constraint_refs": list(constraint_ids)}
    )


def test_scenarios_governed_by_different_constraints_are_not_collapsed() -> None:
    records = deduplicate_scenario_specs(
        [_governed("SCN-001", "SC-1"), _governed("SCN-002", "SC-2")]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("canonical", None),
    }
    assert records["SCN-002"].key.constraint_ids == ("SC-2",)


def test_scenarios_governed_by_the_same_constraints_stay_one_group() -> None:
    records = deduplicate_scenario_specs(
        [_governed("SCN-002", "SC-2", "SC-1"), _governed("SCN-001", "SC-1", "SC-2")]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("duplicate", "SCN-001"),
    }
    assert records["SCN-002"].key.constraint_ids == ("SC-1", "SC-2")


def test_a_superset_of_constraints_is_a_different_group() -> None:
    records = deduplicate_scenario_specs(
        [_governed("SCN-001", "SC-1"), _governed("SCN-002", "SC-1", "SC-2")]
    )

    assert records["SCN-001"].status == "canonical"
    assert records["SCN-002"].status == "canonical"


def test_analytical_scenarios_stay_ungrouped_with_constraints_in_the_key() -> None:
    records = deduplicate_scenario_specs(
        [
            _governed("SCN-001", "SC-1", analytical=True),
            _governed("SCN-002", "SC-1", analytical=True),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("analytical_only", None),
        "SCN-002": ("analytical_only", None),
    }
    assert records["SCN-001"].key.constraint_ids == ("SC-1",)


def test_a_key_without_constraints_keeps_its_historical_shape() -> None:
    records = deduplicate_scenario_specs([_scenario("SCN-001")])

    assert records["SCN-001"].key.constraint_ids == ()
    assert "constraint_ids" not in records["SCN-001"].key.model_dump(mode="json")


def test_a_key_with_constraints_serializes_them_as_a_sorted_list() -> None:
    records = deduplicate_scenario_specs([_governed("SCN-001", "SC-2", "SC-1")])

    assert records["SCN-001"].key.model_dump(mode="json")["constraint_ids"] == [
        "SC-1",
        "SC-2",
    ]


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


def _indirect_shape(carrier_operation: str = "read_order_note") -> AttackShape:
    return AttackShape(
        channel=AttackChannel.INDIRECT,
        turn_count=1,
        turn_plan=[
            TurnShape(
                position=1,
                speaker=TurnSpeaker.BENIGN_USER,
                purpose=TurnPurpose.ASK_TO_READ_ITEM,
            )
        ],
        indirect=IndirectShape(
            carrier_operation=carrier_operation,
            data_item=PlantedItem(
                content_kind=ContentKind.ORDER_CONTENT, record_ref=None
            ),
            party_relation=PartyRelation(
                controller=ItemController.THIRD_PARTY, benign_user_actor_ref=None
            ),
        ),
        threat_label=None,
        source=ShapeSource.STAGE5_VALIDATED,
        downgrade_reason=None,
    )


def test_a_direct_and_an_indirect_variant_of_one_unsafe_call_both_publish() -> None:
    records = deduplicate_scenario_specs(
        [
            _shaped("SCN-001", _validated_shape()),
            _shaped("SCN-002", _indirect_shape()),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("canonical", None),
    }
    assert records["SCN-001"].key == records["SCN-002"].key


def test_indirect_variants_with_different_carriers_keep_one_canonical_each() -> None:
    records = deduplicate_scenario_specs(
        [
            _shaped("SCN-001", _indirect_shape("read_order_note")),
            _shaped("SCN-002", _indirect_shape("read_review")),
            _shaped("SCN-003", _indirect_shape("read_review")),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("canonical", None),
        "SCN-003": ("duplicate", "SCN-002"),
    }


def test_variants_with_the_same_channel_and_carrier_still_merge() -> None:
    records = deduplicate_scenario_specs(
        [
            _shaped("SCN-004", _indirect_shape()),
            _shaped("SCN-002", _indirect_shape()),
            _shaped("SCN-003", _validated_shape()),
            _shaped("SCN-001", _validated_shape()),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("canonical", None),
        "SCN-003": ("duplicate", "SCN-001"),
        "SCN-004": ("duplicate", "SCN-002"),
    }


def test_an_unvalidated_shape_stays_with_the_first_canonical() -> None:
    fallback = default_attack_shape(ShapeDowngradeReason.CARRIER_NOT_OBSERVED)

    records = deduplicate_scenario_specs(
        [
            _shaped("SCN-001", fallback),
            _shaped("SCN-002", None),
            _shaped("SCN-003", _indirect_shape()),
            _shaped("SCN-004", _validated_shape()),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("duplicate", "SCN-003"),
        "SCN-002": ("duplicate", "SCN-003"),
        "SCN-003": ("canonical", None),
        "SCN-004": ("canonical", None),
    }


def test_a_code_default_direct_shape_does_not_split_from_a_validated_one() -> None:
    records = deduplicate_scenario_specs(
        [
            _shaped("SCN-001", default_attack_shape(None)),
            _shaped("SCN-002", _indirect_shape()),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("duplicate", "SCN-002"),
        "SCN-002": ("canonical", None),
    }


def _reworded(scenario_id: str, shape: AttackShape, *, intention: str, source: str):
    return _shaped(scenario_id, shape).model_copy(
        update={
            "attacker_bdi": AttackerBDI(
                beliefs=["The order note is read back verbatim"],
                desires=["Induce NOT_PROVIDED"],
                intentions=[intention],
            ),
            "loss_scenario": f"{intention}; the user receives no service.",
            "causal_factors": [
                CausalFactor(
                    kind=CausalFactorKind.process_model_flaw,
                    source_id=source,
                    description="The agent trusts the note.",
                )
            ],
        }
    )


def test_free_text_mechanism_and_causal_factor_source_do_not_split() -> None:
    records = deduplicate_scenario_specs(
        [
            _reworded(
                "SCN-001",
                _indirect_shape(),
                intention="Plant an instruction in the order note",
                source="PM-1-1",
            ),
            _reworded(
                "SCN-002",
                _indirect_shape(),
                intention="Hide a refund request in the delivery comment",
                source="PM-1-2",
            ),
        ]
    )

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("duplicate", "SCN-001"),
    }


def test_the_channel_split_counts_extra_canonicals_per_channel() -> None:
    fallback = default_attack_shape(ShapeDowngradeReason.SHAPE_CALL_FAILED)
    specs = [
        _shaped("SCN-001", _validated_shape()),
        _shaped("SCN-002", _indirect_shape("read_order_note")),
        _shaped("SCN-003", _indirect_shape("read_review")),
        _shaped("SCN-004", _indirect_shape("read_review")),
        _shaped("SCN-005", fallback),
        _shaped("SCN-006", _indirect_shape(), claim_level="reply"),
        _functional("SCN-007"),
    ]
    records = deduplicate_scenario_specs(specs)

    assert build_channel_splits(specs, records) == {
        "direct": 0,
        "indirect": 2,
        "forged_transcript": 0,
    }


def test_the_first_canonical_of_a_group_is_not_a_split() -> None:
    specs = [
        _shaped("SCN-001", _indirect_shape()),
        _shaped("SCN-002", _validated_shape()),
    ]
    records = deduplicate_scenario_specs(specs)

    assert build_channel_splits(specs, records) == {
        "direct": 1,
        "indirect": 0,
        "forged_transcript": 0,
    }


def test_ungrouped_canonicals_are_not_splits() -> None:
    specs = [
        _shaped("SCN-001", _validated_shape(), operation_name=None),
        _shaped("SCN-002", _indirect_shape(), operation_name=None),
    ]
    records = deduplicate_scenario_specs(specs)

    assert _roles(records) == {
        "SCN-001": ("canonical", None),
        "SCN-002": ("canonical", None),
    }
    assert build_channel_splits(specs, records) == {
        "direct": 0,
        "indirect": 0,
        "forged_transcript": 0,
    }


def test_testability_summary_carries_the_channel_splits_only_when_given() -> None:
    specs = [
        _shaped("SCN-001", _validated_shape()),
        _shaped("SCN-002", _indirect_shape()),
    ]
    records = deduplicate_scenario_specs(specs)

    assert "channel_splits" not in build_testability_summary(records)
    summary = build_testability_summary(
        records, channel_splits=build_channel_splits(specs, records)
    )
    assert summary["summary"]["canonical"] == 2
    assert summary["channel_splits"] == {
        "direct": 0,
        "indirect": 1,
        "forged_transcript": 0,
    }

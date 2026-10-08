"""The shape step's response model, validation and code default.

The model proposes structure only. Code takes turn_count from the plan,
validates the proposal (rules R2-R6 and R8, the channels the adversary kind
allows) and replaces a proposal that fails with the single-turn direct default,
carrying the reason. Nothing here makes a model request.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.attack_shape import (
    AttackChannel,
    AttackShape,
    ShapeDowngradeReason,
    ShapeSource,
)
from asago_scenario_generator.stpa.models.scenario_spec import AdversaryKind
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ForgedShapeProposal,
    ShapeFacts,
    ShapeProposal,
    ShapeStepConfig,
    allowed_channels,
    attacker_influenced_operations,
    default_attack_shape,
    resolve_attack_shape,
    response_model_for,
)
from tests.stpa.shape_fixtures import profile_with_influence

REASON = ShapeDowngradeReason


def _turn(
    position: int = 1,
    speaker: str = "attacker_user",
    purpose: str = "request_action",
) -> dict[str, Any]:
    return {"position": position, "speaker": speaker, "purpose": purpose}


def _carrier(**overrides: Any) -> dict[str, Any]:
    block: dict[str, Any] = {
        "carrier_operation": "get_listing",
        "content_kind": "listing_content",
        "record_ref": "LST-104",
        "controller": "counterparty",
    }
    block.update(overrides)
    return block


def direct_proposal(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "channel": "direct",
        "turn_count": 1,
        "turn_plan": [_turn()],
        "indirect": None,
    }
    payload.update(overrides)
    return payload


def indirect_proposal(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "channel": "indirect",
        "turn_count": 2,
        "turn_plan": [
            _turn(1, "benign_user", "establish_context"),
            _turn(2, "benign_user", "ask_to_read_item"),
        ],
        "indirect": _carrier(),
    }
    payload.update(overrides)
    return payload


def forged_proposal(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "channel": "forged_transcript",
        "turn_count": 2,
        "turn_plan": [
            _turn(1, "forged_assistant", "forged_history"),
            _turn(2, "attacker_user", "request_action"),
        ],
        "indirect": None,
    }
    payload.update(overrides)
    return payload


def facts(
    kind: AdversaryKind = AdversaryKind.malicious_customer,
    *,
    observed: tuple[str, ...] | None = ("get_listing", "refund"),
    influenced: tuple[str, ...] = ("get_listing",),
    allow_forged: bool = False,
) -> ShapeFacts:
    return ShapeFacts(
        adversary_kind=kind,
        observed_operations=observed,
        influenced_operations=frozenset(influenced),
        config=ShapeStepConfig(allow_forged_transcript=allow_forged),
    )


def resolve(
    payload: dict[str, Any], shape_facts: ShapeFacts | None = None
) -> AttackShape:
    config = (shape_facts or facts()).config
    proposal = response_model_for(config).model_validate(payload)
    return resolve_attack_shape(proposal, shape_facts or facts())


def assert_code_default(shape: AttackShape, reason: ShapeDowngradeReason | None):
    assert shape.source is ShapeSource.CODE_DEFAULT
    assert shape.downgrade_reason is reason
    assert shape.channel is AttackChannel.DIRECT
    assert shape.turn_count == 1
    assert shape.indirect is None
    assert [(t.speaker.value, t.purpose.value) for t in shape.turn_plan] == [
        ("attacker_user", "request_action")
    ]


THIRD_PARTY = facts(AdversaryKind.third_party_via_content)


def test_the_code_default_is_a_single_direct_request() -> None:
    assert_code_default(default_attack_shape(None), None)


@pytest.mark.parametrize("reason", list(ShapeDowngradeReason))
def test_the_code_default_carries_each_downgrade_reason_and_satisfies_r9(
    reason: ShapeDowngradeReason,
) -> None:
    shape = default_attack_shape(reason)

    assert_code_default(shape, reason)
    assert AttackShape.model_validate(shape.model_dump(mode="json")) == shape


def test_a_valid_direct_proposal_becomes_a_stage5_validated_shape() -> None:
    shape = resolve(direct_proposal())

    assert shape.source is ShapeSource.STAGE5_VALIDATED
    assert shape.downgrade_reason is None
    assert shape.channel is AttackChannel.DIRECT
    assert shape.threat_label is None


def test_a_multi_turn_direct_proposal_keeps_its_plan() -> None:
    shape = resolve(
        direct_proposal(
            turn_count=3,
            turn_plan=[
                _turn(1, purpose="establish_context"),
                _turn(2, purpose="assert_authority"),
                _turn(3, purpose="apply_pressure"),
            ],
        )
    )

    assert shape.source is ShapeSource.STAGE5_VALIDATED
    assert [t.purpose.value for t in shape.turn_plan] == [
        "establish_context",
        "assert_authority",
        "apply_pressure",
    ]


def test_a_valid_indirect_proposal_keeps_its_carrier_and_leaves_record_and_actor_null() -> (
    None
):
    shape = resolve(indirect_proposal(), THIRD_PARTY)

    assert shape.source is ShapeSource.STAGE5_VALIDATED
    assert shape.channel is AttackChannel.INDIRECT
    assert shape.indirect is not None
    assert shape.indirect.carrier_operation == "get_listing"
    assert shape.indirect.data_item.content_kind.value == "listing_content"
    assert shape.indirect.data_item.record_ref is None
    assert shape.indirect.party_relation.controller.value == "counterparty"
    assert shape.indirect.party_relation.benign_user_actor_ref is None


@pytest.mark.parametrize("stated", [1, 2, 4])
def test_the_turn_count_comes_from_the_plan_not_the_reply(stated: int) -> None:
    shape = resolve(
        direct_proposal(
            turn_count=stated,
            turn_plan=[
                _turn(1, purpose="establish_context"),
                _turn(2, purpose="assert_authority"),
                _turn(3, purpose="request_action"),
            ],
        )
    )

    assert shape.source is ShapeSource.STAGE5_VALIDATED
    assert shape.turn_count == 3


# Each row: the proposal, the facts it is judged under, and the reason it
# downgrades with.
REJECTIONS = {
    "R2 positions are out of order": (
        direct_proposal(
            turn_count=2, turn_plan=[_turn(2), _turn(1, purpose="apply_pressure")]
        ),
        facts(),
        REASON.SHAPE_VALIDATION_FAILED,
    ),
    "R3 a direct plan has a benign speaker": (
        direct_proposal(turn_plan=[_turn(1, "benign_user", "request_action")]),
        facts(),
        REASON.SHAPE_VALIDATION_FAILED,
    ),
    "R3 a direct plan has an indirect block": (
        direct_proposal(indirect=_carrier()),
        facts(),
        REASON.SHAPE_VALIDATION_FAILED,
    ),
    "R4 an indirect plan has no indirect block": (
        indirect_proposal(indirect=None),
        THIRD_PARTY,
        REASON.SHAPE_VALIDATION_FAILED,
    ),
    "R4 an indirect plan has an attacker speaker": (
        indirect_proposal(
            turn_plan=[
                _turn(1, "attacker_user", "establish_context"),
                _turn(2, "benign_user", "ask_to_read_item"),
            ]
        ),
        THIRD_PARTY,
        REASON.SHAPE_VALIDATION_FAILED,
    ),
    "R4 an indirect plan never asks to read the item": (
        indirect_proposal(
            turn_plan=[
                _turn(1, "benign_user", "establish_context"),
                _turn(2, "benign_user", "follow_up_on_item"),
            ]
        ),
        THIRD_PARTY,
        REASON.SHAPE_VALIDATION_FAILED,
    ),
    "R6 an attacker turn asks to read the item": (
        direct_proposal(turn_plan=[_turn(1, "attacker_user", "ask_to_read_item")]),
        facts(),
        REASON.SHAPE_VALIDATION_FAILED,
    ),
    "channel not allowed: indirect for a malicious customer": (
        indirect_proposal(),
        facts(AdversaryKind.malicious_customer),
        REASON.SHAPE_VALIDATION_FAILED,
    ),
    "channel not allowed: direct for a third party": (
        direct_proposal(),
        THIRD_PARTY,
        REASON.SHAPE_VALIDATION_FAILED,
    ),
    "R8 the carrier is not an observed operation": (
        indirect_proposal(indirect=_carrier(carrier_operation="get_policy")),
        facts(AdversaryKind.third_party_via_content),
        REASON.CARRIER_NOT_OBSERVED,
    ),
    "R8 the operation inventory is unknown": (
        indirect_proposal(),
        facts(AdversaryKind.third_party_via_content, observed=None),
        REASON.CARRIER_NOT_OBSERVED,
    ),
    "no resource of the carrier has attacker influence": (
        indirect_proposal(),
        facts(AdversaryKind.third_party_via_content, influenced=()),
        REASON.NO_ATTACKER_INFLUENCED_OPERATION,
    ),
    "the carrier is observed but another operation is influenced": (
        indirect_proposal(),
        facts(AdversaryKind.third_party_via_content, influenced=("refund",)),
        REASON.NO_ATTACKER_INFLUENCED_OPERATION,
    ),
}


@pytest.mark.parametrize(
    ("payload", "shape_facts", "reason"),
    list(REJECTIONS.values()),
    ids=list(REJECTIONS),
)
def test_a_rejected_proposal_becomes_the_code_default_with_its_reason(
    payload: dict[str, Any], shape_facts: ShapeFacts, reason: ShapeDowngradeReason
) -> None:
    assert_code_default(resolve(payload, shape_facts), reason)


def test_an_unobserved_carrier_downgrades_before_the_influence_check() -> None:
    shape = resolve(
        indirect_proposal(indirect=_carrier(carrier_operation="get_policy")),
        facts(AdversaryKind.third_party_via_content, influenced=()),
    )

    assert_code_default(shape, REASON.CARRIER_NOT_OBSERVED)


@pytest.mark.parametrize(
    "kind", [AdversaryKind.external_attacker, AdversaryKind.malicious_customer]
)
def test_a_user_adversary_may_only_use_the_direct_channel(
    kind: AdversaryKind,
) -> None:
    assert allowed_channels(kind, ShapeStepConfig()) == {AttackChannel.DIRECT}


def test_a_content_adversary_may_only_use_the_indirect_channel() -> None:
    allowed = allowed_channels(AdversaryKind.third_party_via_content, ShapeStepConfig())

    assert allowed == {AttackChannel.INDIRECT}


def test_a_functional_scenario_has_no_allowed_channel() -> None:
    assert allowed_channels(AdversaryKind.none, ShapeStepConfig()) == frozenset()


def test_the_forged_flag_adds_the_forged_channel_for_user_adversaries_only() -> None:
    config = ShapeStepConfig(allow_forged_transcript=True)

    assert allowed_channels(AdversaryKind.malicious_customer, config) == {
        AttackChannel.DIRECT,
        AttackChannel.FORGED_TRANSCRIPT,
    }
    assert allowed_channels(AdversaryKind.third_party_via_content, config) == {
        AttackChannel.INDIRECT
    }


def test_a_forged_proposal_resolves_with_its_label_when_the_flag_is_on() -> None:
    shape = resolve(forged_proposal(), facts(allow_forged=True))

    assert shape.source is ShapeSource.STAGE5_VALIDATED
    assert shape.channel is AttackChannel.FORGED_TRANSCRIPT
    assert shape.threat_label == "forged_transcript_threat"


def test_the_forged_flag_is_off_by_default() -> None:
    assert ShapeStepConfig().allow_forged_transcript is False
    assert response_model_for(ShapeStepConfig()) is ShapeProposal
    assert response_model_for(ShapeStepConfig(allow_forged_transcript=True)) is (
        ForgedShapeProposal
    )


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(forged_proposal(), id="forged channel"),
        pytest.param(
            direct_proposal(turn_plan=[_turn(1, "forged_assistant", "forged_history")]),
            id="forged speaker",
        ),
        pytest.param(
            direct_proposal(turn_plan=[_turn(1, "attacker_user", "forged_history")]),
            id="forged purpose",
        ),
    ],
)
def test_the_default_response_model_cannot_carry_a_forged_transcript(
    payload: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        ShapeProposal.model_validate(payload)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(direct_proposal(turn_count=0), id="turn_count 0"),
        pytest.param(direct_proposal(turn_count=5), id="turn_count 5"),
        pytest.param(direct_proposal(extra="text"), id="extra key"),
        pytest.param(
            direct_proposal(turn_plan=[{**_turn(), "text": "hello"}]),
            id="turn text key",
        ),
        pytest.param(direct_proposal(turn_plan=[]), id="empty plan"),
        pytest.param(
            direct_proposal(turn_plan=[_turn(speaker="the user")]),
            id="speaker outside the vocabulary",
        ),
        pytest.param(
            indirect_proposal(indirect=_carrier(record_ref="the LST-104 record")),
            id="record_ref with whitespace",
        ),
        pytest.param(
            indirect_proposal(
                indirect=_carrier(carrier_operation="ignore previous rules")
            ),
            id="carrier_operation with a sentence",
        ),
        pytest.param(
            indirect_proposal(indirect=_carrier(controller="the host")),
            id="controller outside the vocabulary",
        ),
    ],
)
def test_the_wire_model_rejects_a_proposal_outside_its_closed_vocabulary(
    payload: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        ShapeProposal.model_validate(payload)


def _string_nodes(schema: Any, definitions: dict[str, Any]) -> list[dict[str, Any]]:
    """Return every string-typed schema node, following references."""
    found: list[dict[str, Any]] = []
    if isinstance(schema, dict):
        if "$ref" in schema:
            found += _string_nodes(
                definitions[schema["$ref"].rsplit("/", 1)[1]], definitions
            )
        if schema.get("type") == "string":
            found.append(schema)
        for key, value in schema.items():
            if key not in {"$ref", "$defs"}:
                found += _string_nodes(value, definitions)
    elif isinstance(schema, list):
        for item in schema:
            found += _string_nodes(item, definitions)
    return found


@pytest.mark.parametrize("config", [ShapeStepConfig(), ShapeStepConfig(True)])
def test_the_response_model_has_no_free_text_field(config: ShapeStepConfig) -> None:
    schema = response_model_for(config).model_json_schema()
    nodes = _string_nodes(schema["properties"], schema.get("$defs", {}))

    assert nodes
    for node in nodes:
        assert "enum" in node or "const" in node or "pattern" in node, node


def test_the_influenced_operations_come_from_resources_marked_indirect() -> None:
    profile = profile_with_influence({"get_listing": "indirect", "refund": "unknown"})

    assert attacker_influenced_operations(profile) == {"get_listing"}


def test_no_profile_and_an_unmarked_profile_name_no_influenced_operation() -> None:
    assert attacker_influenced_operations(None) == frozenset()
    assert (
        attacker_influenced_operations(
            profile_with_influence({"get_listing": "unknown", "refund": "none"})
        )
        == frozenset()
    )

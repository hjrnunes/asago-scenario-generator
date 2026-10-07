"""Attack shape: how an adversarial scenario reaches the agent, as structure.

The shape is part of scenario-handoff-v4. It holds closed enums, bounded
integers and identifiers only, so attack text cannot fit in it: the artifact
generator writes every turn and every planted item. An identifier admits no
whitespace, which keeps a sentence out of the identifier fields.

The field names avoid every key in ``handoff._FORBIDDEN_KEYS``, so the
ownership scan keeps its meaning ("no turn arrays, no delivery routes").
"""

from __future__ import annotations

from collections.abc import Collection
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StringConstraints,
    model_validator,
)

MAX_TURNS = 4
THREAT_LABEL_FORGED_TRANSCRIPT = "forged_transcript_threat"


class _NoWhitespaceInSchema:
    """Add the whitespace ban to the JSON schema.

    Pydantic's regex engine reads ``$`` as end of text, but Python's ``re`` (and
    so ``jsonschema``) lets ``$`` match before a final newline. The ``not``
    clause makes a schema-only reader reject that trailing newline too.
    """

    def __get_pydantic_json_schema__(self, core_schema, handler):
        schema = handler(core_schema)
        schema["not"] = {"pattern": r"\s"}
        return schema


ShapeIdentifier = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$"),
    _NoWhitespaceInSchema(),
]


class AttackChannel(StrEnum):
    """How the attack reaches the target agent. Structure only."""

    DIRECT = "direct"
    INDIRECT = "indirect"
    FORGED_TRANSCRIPT = "forged_transcript"


class TurnSpeaker(StrEnum):
    """Who speaks a planned turn.

    ``attacker_user`` and ``benign_user`` are real user turns; the ``forged_*``
    speakers exist only on the ``forged_transcript`` channel.
    """

    ATTACKER_USER = "attacker_user"
    BENIGN_USER = "benign_user"
    FORGED_ASSISTANT = "forged_assistant"
    FORGED_TOOL_RESULT = "forged_tool_result"


class TurnPurpose(StrEnum):
    """Closed vocabulary for what a turn is for. Never free text."""

    ESTABLISH_CONTEXT = "establish_context"
    ASSERT_AUTHORITY = "assert_authority"
    REQUEST_ACTION = "request_action"
    APPLY_PRESSURE = "apply_pressure"
    ASK_TO_READ_ITEM = "ask_to_read_item"
    FOLLOW_UP_ON_ITEM = "follow_up_on_item"
    FORGED_HISTORY = "forged_history"


class ContentKind(StrEnum):
    """Closed kind of the planted data item.

    The consumer chooses a concrete seed slot of this kind from the target
    manifest.
    """

    POLICY_DOCUMENT = "policy_document"
    LISTING_CONTENT = "listing_content"
    ORDER_CONTENT = "order_content"
    CLINICAL_NOTE = "clinical_note"
    EDUCATION_MATERIAL = "education_material"
    MESSAGE = "message"
    REVIEW = "review"
    OTHER = "other"


class ItemController(StrEnum):
    """Who controls the planted data item, relative to the benign user and operator."""

    THIRD_PARTY = "third_party"
    COUNTERPARTY = "counterparty"
    OPERATOR_INSIDER = "operator_insider"
    UNKNOWN = "unknown"


class ShapeSource(StrEnum):
    """Who set the shape."""

    STAGE5_VALIDATED = "stage5_validated"
    CODE_DEFAULT = "code_default"


class ShapeDowngradeReason(StrEnum):
    """Why a proposed shape was replaced by the single-turn direct default."""

    NO_ATTACKER_INFLUENCED_OPERATION = "no_attacker_influenced_operation"
    CARRIER_NOT_OBSERVED = "carrier_not_observed"
    SHAPE_VALIDATION_FAILED = "shape_validation_failed"
    SHAPE_CALL_FAILED = "shape_call_failed"


_FORGED_SPEAKERS = frozenset(
    {TurnSpeaker.FORGED_ASSISTANT, TurnSpeaker.FORGED_TOOL_RESULT}
)
_BENIGN_ONLY_PURPOSES = frozenset(
    {TurnPurpose.ASK_TO_READ_ITEM, TurnPurpose.FOLLOW_UP_ON_ITEM}
)


class _ShapeModel(BaseModel):
    """Strict base: unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid")


class TurnShape(_ShapeModel):
    """One planned turn: its position, speaker and purpose, never its words."""

    position: StrictInt = Field(ge=1, le=MAX_TURNS)
    speaker: TurnSpeaker
    purpose: TurnPurpose


class PlantedItem(_ShapeModel):
    """The planted item: its kind and the record it lives in."""

    content_kind: ContentKind
    record_ref: ShapeIdentifier | None


class PartyRelation(_ShapeModel):
    """Who controls the planted item and which actor the benign turns speak as."""

    controller: ItemController
    benign_user_actor_ref: ShapeIdentifier | None


class IndirectShape(_ShapeModel):
    """The planted-item description of an ``indirect`` attack."""

    carrier_operation: ShapeIdentifier
    data_item: PlantedItem
    party_relation: PartyRelation


def _turn_count_pairing(count: int) -> dict:
    return {
        "if": {
            "properties": {"turn_count": {"const": count}},
            "required": ["turn_count"],
        },
        "then": {"properties": {"turn_plan": {"minItems": count, "maxItems": count}}},
    }


class AttackShape(_ShapeModel):
    """The structure of an adversarial scenario's attack; never attack text.

    Every key is required and an absent value is an explicit ``null``.
    Cross-field rules R1-R6 and R9 run as model validators; the if/then blocks
    in the JSON schema mirror the ones a schema-only reader needs.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"channel": {"const": "indirect"}},
                        "required": ["channel"],
                    },
                    "then": {
                        "properties": {
                            "indirect": {"type": "object"},
                            "threat_label": {"type": "null"},
                        }
                    },
                    "else": {"properties": {"indirect": {"type": "null"}}},
                },
                {
                    "if": {
                        "properties": {"channel": {"const": "forged_transcript"}},
                        "required": ["channel"],
                    },
                    "then": {
                        "properties": {
                            "threat_label": {"const": THREAT_LABEL_FORGED_TRANSCRIPT}
                        }
                    },
                    "else": {"properties": {"threat_label": {"type": "null"}}},
                },
                *(_turn_count_pairing(count) for count in range(1, MAX_TURNS + 1)),
            ]
        },
    )

    channel: AttackChannel
    turn_count: StrictInt = Field(ge=1, le=MAX_TURNS)
    turn_plan: list[TurnShape] = Field(min_length=1, max_length=MAX_TURNS)
    indirect: IndirectShape | None
    threat_label: Literal["forged_transcript_threat"] | None
    source: ShapeSource
    downgrade_reason: ShapeDowngradeReason | None

    @model_validator(mode="after")
    def _validate_plan(self) -> "AttackShape":
        """R1 and R2: the plan has ``turn_count`` entries at positions 1..n."""

        if len(self.turn_plan) != self.turn_count:
            raise ValueError(
                f"R1: turn_plan has {len(self.turn_plan)} entries but "
                f"turn_count is {self.turn_count}"
            )
        positions = [turn.position for turn in self.turn_plan]
        if positions != list(range(1, self.turn_count + 1)):
            raise ValueError(
                f"R2: turn positions {positions} are not 1..{self.turn_count}"
            )
        return self

    @model_validator(mode="after")
    def _validate_channel(self) -> "AttackShape":
        """R3, R4 and R5: each channel fixes its speakers, block and label."""

        speakers = [turn.speaker for turn in self.turn_plan]
        if self.channel is AttackChannel.DIRECT:
            _require(
                all(s is TurnSpeaker.ATTACKER_USER for s in speakers),
                "R3: a direct shape has only attacker_user turns",
            )
            _require(self.indirect is None, "R3: a direct shape has no indirect block")
            _require(
                self.threat_label is None, "R3: a direct shape has no threat_label"
            )
        elif self.channel is AttackChannel.INDIRECT:
            _require(
                self.indirect is not None,
                "R4: an indirect shape needs an indirect block",
            )
            _require(
                all(s is TurnSpeaker.BENIGN_USER for s in speakers),
                "R4: an indirect shape has only benign_user turns",
            )
            _require(
                any(t.purpose is TurnPurpose.ASK_TO_READ_ITEM for t in self.turn_plan),
                "R4: an indirect shape needs an ask_to_read_item turn",
            )
            _require(
                self.threat_label is None, "R4: an indirect shape has no threat_label"
            )
        else:
            _require(
                self.threat_label == THREAT_LABEL_FORGED_TRANSCRIPT,
                "R5: a forged_transcript shape carries its threat_label",
            )
            _require(
                any(s in _FORGED_SPEAKERS for s in speakers),
                "R5: a forged_transcript shape needs a forged speaker",
            )
            _require(
                speakers[-1] is TurnSpeaker.ATTACKER_USER,
                "R5: a forged_transcript shape ends on attacker_user",
            )
            _require(
                self.indirect is None,
                "R5: a forged_transcript shape has no indirect block",
            )
        return self

    @model_validator(mode="after")
    def _validate_purposes(self) -> "AttackShape":
        """R6: item-reading purposes belong to the benign user, forged history to forged speakers."""

        for turn in self.turn_plan:
            if turn.purpose in _BENIGN_ONLY_PURPOSES:
                _require(
                    turn.speaker is TurnSpeaker.BENIGN_USER,
                    f"R6: purpose {turn.purpose.value} belongs to benign_user",
                )
            if turn.purpose is TurnPurpose.FORGED_HISTORY:
                _require(
                    turn.speaker in _FORGED_SPEAKERS,
                    "R6: purpose forged_history belongs to a forged speaker",
                )
        return self

    @model_validator(mode="after")
    def _validate_downgrade(self) -> "AttackShape":
        """R9: a downgrade reason implies the single-turn direct code default."""

        if self.downgrade_reason is not None:
            _require(
                self.source is ShapeSource.CODE_DEFAULT
                and self.channel is AttackChannel.DIRECT
                and self.turn_count == 1,
                "R9: downgrade_reason implies a code_default, direct, single-turn shape",
            )
        return self


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def carrier_operation_observed(
    shape: AttackShape, observed_operations: Collection[str] | None
) -> bool:
    """R8: report whether the shape's carrier is an operation the run observed.

    A shape without an indirect block names no carrier and always passes. An
    unknown inventory (``None``) cannot confirm a carrier, so it fails.
    """

    if shape.indirect is None:
        return True
    if observed_operations is None:
        return False
    return shape.indirect.carrier_operation in observed_operations


def default_attack_shape(reason: ShapeDowngradeReason | None) -> AttackShape:
    """Return the single-turn direct shape code uses when the model's does not hold."""
    return AttackShape(
        channel=AttackChannel.DIRECT,
        turn_count=1,
        turn_plan=[
            TurnShape(
                position=1,
                speaker=TurnSpeaker.ATTACKER_USER,
                purpose=TurnPurpose.REQUEST_ACTION,
            )
        ],
        indirect=None,
        threat_label=None,
        source=ShapeSource.CODE_DEFAULT,
        downgrade_reason=reason,
    )


__all__ = [
    "MAX_TURNS",
    "THREAT_LABEL_FORGED_TRANSCRIPT",
    "AttackChannel",
    "AttackShape",
    "ContentKind",
    "IndirectShape",
    "ItemController",
    "PartyRelation",
    "PlantedItem",
    "ShapeDowngradeReason",
    "ShapeIdentifier",
    "ShapeSource",
    "TurnPurpose",
    "TurnShape",
    "TurnSpeaker",
    "carrier_operation_observed",
    "default_attack_shape",
]

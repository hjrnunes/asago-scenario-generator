"""The v4 attack shape, re-exported from its home in ``stpa.models``.

The models live below ``scenario_prod`` because ``ScenarioSpec`` carries the
shape and the model layer may not import this package.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.attack_shape import (
    MAX_TURNS,
    THREAT_LABEL_FORGED_TRANSCRIPT,
    AttackChannel,
    AttackShape,
    ContentKind,
    IndirectShape,
    ItemController,
    PartyRelation,
    PlantedItem,
    ShapeDowngradeReason,
    ShapeIdentifier,
    ShapeSource,
    TurnPurpose,
    TurnShape,
    TurnSpeaker,
    carrier_operation_observed,
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
]

"""A critic revision keeps every control action's typed fields.

The fixtures are a reviewed Klarna control structure and the revision reply a
saved run merged into it.  The reply restates RESP-1 and RESP-4: CA-1-1 comes
back with no target, effect, or temporality, and every restated action carries
the prompt's display labels in its description.
"""

from __future__ import annotations

import json
from pathlib import Path

from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlActionTemporality,
    ControlStructure,
    ReferenceType,
)
from asago_scenario_generator.stpa.system_model.critic import (
    _merge_revision_delta,
    _revision_delta_from_wire,
    _validate_revision_wire,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "stpa"


def _reviewed() -> ControlStructure:
    return read_yaml(  # type: ignore[return-value]
        FIXTURES_DIR / "control_structure_reviewed_klarna.yaml", ControlStructure
    )


def _restating_reply() -> dict:
    return json.loads(
        (FIXTURES_DIR / "revision_restated_actions_klarna.json").read_text(
            encoding="utf-8"
        )
    )


def _actions(structure: ControlStructure) -> dict:
    return {
        ca.ca_id: ca
        for resp in structure.responsibilities
        for ca in resp.control_actions
    }


def test_reply_restates_an_action_without_its_typed_fields() -> None:
    restated = {
        ca["ca_id"]: ca
        for resp in _restating_reply()["modified_responsibilities"]
        for ca in resp["control_actions"]
    }

    assert restated["CA-1-1"].get("target") is None
    assert restated["CA-1-1"].get("effect_kind") is None
    assert restated["CA-1-1"].get("temporality") is None


def test_revision_keeps_the_typed_fields_of_every_reviewed_action() -> None:
    reviewed = _reviewed()
    reply = _restating_reply()
    _validate_revision_wire(reply)

    merged, _ = _merge_revision_delta(reviewed, _revision_delta_from_wire(reply))

    merged_actions = _actions(merged)
    for ca_id, before in _actions(reviewed).items():
        after = merged_actions[ca_id]
        assert (after.target, after.effect_kind, after.temporality) == (
            before.target,
            before.effect_kind,
            before.temporality,
        ), ca_id
    response = merged_actions["CA-1-1"]
    assert response.target is not None
    assert response.target.type is ReferenceType.controlled_process
    assert response.target.id == "CP-1"
    assert response.effect_kind is ControlActionEffectKind.model_output
    assert response.temporality is ControlActionTemporality.instantaneous

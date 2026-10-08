"""Shared test builders moved out of test modules."""

from __future__ import annotations

import json
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetOperationReference,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.condition_check import (
    target_observation_fact_values,
)
from asago_scenario_generator.stpa.scenario_prod.condition_family import ConditionFamily
from asago_scenario_generator.stpa.scenario_prod.condition_index import StateIndex
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)
from tests.stpa.condition_prompt_fixture import (
    realistic_observations,
    realistic_profile,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from tests.helpers.normal_authoring_wire import _wrong_timing_context


def _state() -> dict:
    return {
        "authenticated_owner_id": "OW-1",
        "session_token": "tok",
        "widgets": {
            "W-1": {
                "owner_id": "OW-1",
                "locked": False,
                "price": 10.0,
                "stage": "draft",
                "label": "Blue thing",
            },
            "W-2": {
                "owner_id": "OW-2",
                "locked": True,
                "price": 20.0,
                "stage": "draft",
                "label": "Red thing",
            },
            "W-3": {
                "owner_id": "OW-1",
                "locked": False,
                "price": 30.0,
                "stage": "final",
                "label": "Green thing",
            },
        },
        "slots": {
            "SL-1": {"widget_id": "W-1", "capacity": 5},
            "SL-2": {"widget_id": "W-2", "capacity": 7},
        },
        "events": [],
    }


def _index(state: dict) -> StateIndex:
    snapshot = TargetObservationSnapshot.create(
        target_profile_digest="d" * 64,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(state),
            ),
        ),
    )
    return StateIndex.from_fact_values(target_observation_fact_values(snapshot))


def _op(
    name: str,
    arguments: dict[str, str],
    *,
    effect: str = "update",
    state_changing: bool = True,
) -> TargetOperationObservation:
    return TargetOperationObservation(
        reference=TargetOperationReference(
            resource_id=f"resource:{name}", operation_id=name
        ),
        input_schema={
            "type": "object",
            "properties": {arg: {"type": kind} for arg, kind in arguments.items()},
        },
        effect=effect,
        state_changing=state_changing,
    )


EDIT = _op("edit_widget", {"widget_id": "string", "price": "number"})


READ = _op("read_widget", {"widget_id": "string"}, effect="read", state_changing=False)


BOOK = _op("book_slot", {"slot_id": "string"})


NOTE = _op("write_note", {"owner_id": "string", "text": "string"})


OPS = (EDIT, READ, BOOK, NOTE)


def _kind(families, kind):
    return [family for family in families if family.kind == kind]


def _request(family: ConditionFamily | None) -> tuple[str, str]:
    profile = realistic_profile()
    return build_context_bdi_prompts(
        _wrong_timing_context(),
        TemplateLoader(PROMPTS_DIR),
        execution_target_profile=profile,
        target_observations=realistic_observations(profile),
        observation_contract=default_observation_contract(),
        condition_family=family,
    )

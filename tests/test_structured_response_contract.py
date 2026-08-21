"""Regression tests for bounded taxonomy structured-response contracts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.pipeline.generate.actor import Call0Response
from asago_scenario_generator.pipeline.generate.gherkin import Call3Response
from asago_scenario_generator.pipeline.generate.narrative import (
    Call1Response,
    _map_call1_to_narrative,
    build_call1_response_model,
)


def _walk_reachable_schema(
    schema: Mapping[str, Any],
    *,
    definitions: Mapping[str, Any],
    path: str,
    active_refs: frozenset[str] = frozenset(),
) -> None:
    """Assert finite bounds on every reachable generated schema value."""
    ref = schema.get("$ref")
    if isinstance(ref, str):
        prefix = "#/$defs/"
        assert ref.startswith(prefix), f"{path} has unsupported reference {ref!r}"
        name = ref[len(prefix) :]
        assert name not in active_refs, f"recursive schema at {path}: {ref}"
        _walk_reachable_schema(
            definitions[name],
            definitions=definitions,
            path=f"{path} -> {ref}",
            active_refs=active_refs | {name},
        )
        return

    for index, branch in enumerate(schema.get("anyOf", ())):
        _walk_reachable_schema(
            branch,
            definitions=definitions,
            path=f"{path}.anyOf[{index}]",
            active_refs=active_refs,
        )
    for index, branch in enumerate(schema.get("oneOf", ())):
        _walk_reachable_schema(
            branch,
            definitions=definitions,
            path=f"{path}.oneOf[{index}]",
            active_refs=active_refs,
        )

    if schema.get("type") == "string":
        assert isinstance(schema.get("maxLength"), int), f"unbounded string at {path}"
    if schema.get("type") == "array":
        assert isinstance(schema.get("maxItems"), int), f"unbounded array at {path}"
        items = schema.get("items")
        if isinstance(items, Mapping):
            _walk_reachable_schema(
                items,
                definitions=definitions,
                path=f"{path}[]",
                active_refs=active_refs,
            )

    for name, property_schema in schema.get("properties", {}).items():
        _walk_reachable_schema(
            property_schema,
            definitions=definitions,
            path=f"{path}.{name}",
            active_refs=active_refs,
        )


@pytest.mark.parametrize("response_model", [Call0Response, Call1Response, Call3Response])
def test_provider_response_schema_bounds_every_reachable_generated_value(
    response_model: type,
) -> None:
    schema = response_model.model_json_schema()
    _walk_reachable_schema(
        schema,
        definitions=schema.get("$defs", {}),
        path=response_model.__name__,
    )


@pytest.mark.parametrize("field", ["beliefs", "desires", "intentions", "resources"])
def test_call0_item_boundaries_are_enforced(field: str) -> None:
    data: dict[str, Any] = {
        "actor_type": "adversarial-user",
        "capability_level": "intermediate",
        "beliefs": ["short"],
        "desires": ["short"],
        "intentions": ["short"],
        "resources": ["short"],
    }
    data[field] = [""]
    with pytest.raises(ValidationError):
        Call0Response.model_validate(data)

    data[field] = ["x" * 200]
    Call0Response.model_validate(data)

    data[field] = ["x" * 201]
    with pytest.raises(ValidationError):
        Call0Response.model_validate(data)


def _call1_data(*, zone: str = "input", projected_step_id: str = "step.1") -> dict[str, Any]:
    return {
        "title": "Title",
        "summary": "Summary",
        "entry_point": "Entry point",
        "zone_sequence": [zone],
        "steps": [
            {
                "step_number": 1,
                "zone": "input",
                "action": "Action",
                "effect": "Effect",
                "projected_step_ids": [projected_step_id],
            }
        ],
    }


def test_call1_zone_and_projected_step_id_item_boundaries_are_enforced() -> None:
    Call1Response.model_validate(_call1_data(zone="z" * 64))
    with pytest.raises(ValidationError):
        Call1Response.model_validate(_call1_data(zone="z" * 65))

    Call1Response.model_validate(_call1_data(projected_step_id="x" * 200))
    with pytest.raises(ValidationError):
        Call1Response.model_validate(_call1_data(projected_step_id="x" * 201))


def _call3_data(*, source_step_id: str = "step.1", postcondition_id: str = "pc.1") -> dict[str, Any]:
    return {
        "assertions": [
            {
                "assertion_id": "assert.1",
                "source_step_ids": [source_step_id],
                "projected_postcondition_ids": [postcondition_id],
                "text": "The expected effect occurs.",
            }
        ]
    }


@pytest.mark.parametrize("field", ["source_step_ids", "projected_postcondition_ids"])
def test_call3_id_item_boundaries_are_enforced(field: str) -> None:
    kwargs = {
        "source_step_id": "step.1",
        "postcondition_id": "pc.1",
    }
    Call3Response.model_validate(_call3_data(**kwargs))
    if field == "source_step_ids":
        kwargs["source_step_id"] = "x" * 201
    else:
        kwargs["postcondition_id"] = "x" * 201
    with pytest.raises(ValidationError):
        Call3Response.model_validate(_call3_data(**kwargs))


@pytest.mark.parametrize(
    "field",
    [
        "resource_ref_ids",
        "consumed_ref_ids",
        "produced_ref_ids",
        "produced_effect_ids",
        "outcome_link_pc_ids",
        "postcondition_ids",
    ],
)
def test_realization_id_list_items_are_bounded(field: str) -> None:
    data: dict[str, Any] = {
        "projected_step_id": "step.1",
        "action_kind": "prepare",
        "executor_role": "attacker",
        "boundary_position": "crossing",
        "resource_ref_ids": [],
        "consumed_ref_ids": [],
        "produced_ref_ids": [],
        "produced_effect_ids": [],
        "outcome_link_pc_ids": [],
        "postcondition_ids": [],
    }
    data[field] = ["x" * 200]
    ProjectedStepRealization.model_validate(data)

    data[field] = ["x" * 201]
    with pytest.raises(ValidationError):
        ProjectedStepRealization.model_validate(data)


def test_call1_provider_schema_has_no_realizations_and_finalization_derives_them() -> None:
    context = {
        "selected_step_ids": ["step.1", "step.2"],
        "selected_steps": [
            {
                "step_id": "step.1",
                "realization": {
                    "projected_step_id": "step.1",
                    "action_kind": "prepare",
                    "executor_role": "attacker",
                    "boundary_position": "crossing",
                    "resource_ref_ids": [],
                    "consumed_ref_ids": [],
                    "produced_ref_ids": [],
                    "produced_effect_ids": [],
                    "outcome_link_pc_ids": [],
                    "postcondition_ids": [],
                },
            },
            {
                "step_id": "step.2",
                "realization": {
                    "projected_step_id": "step.2",
                    "action_kind": "observe",
                    "executor_role": "system",
                    "boundary_position": "inside",
                    "resource_ref_ids": [],
                    "consumed_ref_ids": [],
                    "produced_ref_ids": [],
                    "produced_effect_ids": [],
                    "outcome_link_pc_ids": [],
                    "postcondition_ids": [],
                },
            },
        ],
    }
    response = Call1Response.model_validate(
        {
            **_call1_data(),
            "steps": [
                {
                    **_call1_data()["steps"][0],
                    "projected_step_ids": ["step.1", "step.2"],
                    "realizations": [
                        {
                            "projected_step_id": "step.1",
                            "action_kind": "forged",
                        }
                    ],
                }
            ],
        }
    )

    step_schema = Call1Response.model_json_schema()["$defs"]["Call1Step"]
    assert "realizations" not in step_schema["properties"]
    assert "realizations" not in response.steps[0].model_dump()

    narrative = _map_call1_to_narrative(response, context)
    assert [r.projected_step_id for r in narrative.steps[0].realizations] == [
        "step.1",
        "step.2",
    ]
    assert narrative.steps[0].realizations[0].action_kind == "prepare"
    assert narrative.steps[0].realizations[1].action_kind == "observe"


@pytest.mark.parametrize(
    ("selected_step_ids", "response_step_ids", "diagnostic"),
    [
        (["step.1", "step.2"], ["step.unknown"], "unknown projected step ID"),
        (["step.1", "step.2"], ["step.1", "step.1"], "duplicate projected step ID"),
        (["step.1", "step.2"], ["step.1"], "omitted projected step ID"),
    ],
)
def test_call1_realization_resolution_fails_closed(
    selected_step_ids: list[str],
    response_step_ids: list[str],
    diagnostic: str,
) -> None:
    context = {
        "selected_step_ids": selected_step_ids,
        "selected_steps": [
            {
                "step_id": step_id,
                "realization": {
                    "projected_step_id": step_id,
                    "action_kind": "prepare",
                    "executor_role": "attacker",
                    "boundary_position": "crossing",
                    "resource_ref_ids": [],
                    "consumed_ref_ids": [],
                    "produced_ref_ids": [],
                    "produced_effect_ids": [],
                    "outcome_link_pc_ids": [],
                    "postcondition_ids": [],
                },
            }
            for step_id in selected_step_ids
        ],
    }
    data = _call1_data(projected_step_id=response_step_ids[0])
    data["steps"][0]["projected_step_ids"] = response_step_ids
    if diagnostic.startswith("duplicate"):
        with pytest.raises(ValueError, match=diagnostic):
            Call1Response.model_validate(data)
        return
    response = Call1Response.model_validate(data)

    with pytest.raises(ValueError, match=diagnostic):
        _map_call1_to_narrative(response, context)


def test_call1_semantically_incompatible_realization_fails_closed() -> None:
    context = {
        "selected_step_ids": ["step.1"],
        "selected_steps": [
            {
                "step_id": "step.1",
                "realization": {
                    "projected_step_id": "step.other",
                    "action_kind": "prepare",
                    "executor_role": "attacker",
                    "boundary_position": "crossing",
                    "resource_ref_ids": [],
                    "consumed_ref_ids": [],
                    "produced_ref_ids": [],
                    "produced_effect_ids": [],
                    "outcome_link_pc_ids": [],
                    "postcondition_ids": [],
                },
            }
        ],
    }
    response = Call1Response.model_validate(_call1_data())

    with pytest.raises(ValueError, match="semantically incompatible"):
        _map_call1_to_narrative(response, context)


@pytest.mark.parametrize(
    ("selected_steps", "diagnostic"),
    [
        ([None], "invalid projected step context entry"),
        ([{}], "invalid projected step context ID"),
        (
            [{"step_id": "step.1"}, {"step_id": "step.1"}],
            "duplicate projected step ID",
        ),
    ],
)
def test_call1_projection_context_identity_is_validated_once(
    selected_steps: list[Any],
    diagnostic: str,
) -> None:
    response = Call1Response.model_validate(_call1_data())

    with pytest.raises(ValueError, match=diagnostic):
        _map_call1_to_narrative(
            response,
            {"selected_steps": selected_steps},
        )


@pytest.mark.parametrize(("selected_count", "maximum"), [(5, 7), (16, 16)])
def test_call1_schema_uses_candidate_specific_step_bound(
    selected_count: int,
    maximum: int,
) -> None:
    model = build_call1_response_model(selected_count)
    assert model.model_json_schema()["properties"]["steps"]["maxItems"] == maximum

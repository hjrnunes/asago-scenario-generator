"""No union reaches a request: the response-format builder refuses one.

Each response type that carries a union is built through the builder its
production request uses, and its request schema must hold no union.  A
schema that still holds one after the request rewrite makes the builder
raise instead of sending it.
"""

from __future__ import annotations

from typing import Annotated, Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.schema_unions import UnionMergeError, find_unions
from asago_scenario_generator.stpa.infra import llm
from asago_scenario_generator.stpa.infra.llm import _json_schema_response_format
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _routing_provider_payload_type,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.schema import (
    _scenario_semantics_payload_type,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    _ControlElementProviderSet,
)

_PRODUCTION_TYPES = {
    "stage5-plain": _scenario_semantics_payload_type(2),
    "stage5-duration-condition": _scenario_semantics_payload_type(
        3,
        duration_eligible=True,
        observation_criteria_required=True,
        condition_references_supplied=True,
    ),
    "stage5-criteria": _scenario_semantics_payload_type(
        1, observation_criteria_required=True
    ),
    "routing": _routing_provider_payload_type(1),
    "routing-exact-ids": _routing_provider_payload_type(
        2, obligation_ids=("ob:v1:" + "a" * 64, "ob:v1:" + "b" * 64)
    ),
    "stage2-control-elements": _ControlElementProviderSet,
}


@pytest.mark.parametrize("name", sorted(_PRODUCTION_TYPES))
def test_production_response_types_send_no_union(name: str) -> None:
    model = _PRODUCTION_TYPES[name]
    assert find_unions(model.model_json_schema()), "the type no longer has a union"
    schema = _json_schema_response_format(model)["json_schema"]["schema"]
    assert find_unions(schema) == []


def test_stage5_request_flattens_each_named_union() -> None:
    schema = _json_schema_response_format(
        _PRODUCTION_TYPES["stage5-duration-condition"]
    )
    body = schema["json_schema"]["schema"]
    adversary = body["properties"]["adversary"]
    assert adversary["properties"]["kind"]["enum"] == [
        "external_attacker",
        "malicious_customer",
        "third_party_via_content",
        "none",
    ]
    assert adversary["required"] == ["kind", "gain"]
    factor = body["properties"]["causal_factors"]["items"]
    assert factor["properties"]["evidence_status"]["enum"] == [
        "structural_failure",
        "reachable_capability",
        "bounded_assumption",
    ]
    temporal = factor["properties"]["temporal_condition"]["anyOf"][0]
    assert temporal["properties"]["type"]["enum"] == [
        "ordering",
        "delay",
        "duration",
        "window",
        "absence",
    ]
    condition = body["$defs"]["DiscriminatingCondition"]["properties"]
    comparison = condition["comparisons"]["items"]
    assert comparison["properties"]["kind"]["enum"] == ["value", "order", "not_called"]
    operand = comparison["properties"]["left"]["anyOf"][0]
    assert operand["properties"]["source"]["enum"] == ["argument", "fact", "literal"]
    selection = condition["record_selection"]
    assert selection["properties"]["status"]["enum"] == ["observed", "unavailable"]


def test_routing_request_flattens_the_route_dispositions() -> None:
    body = _json_schema_response_format(_PRODUCTION_TYPES["routing"])["json_schema"]
    route = body["schema"]["properties"]["routes"]["items"]
    assert route["properties"]["disposition"]["enum"] == [
        "targeted",
        "proposed_not_applicable",
        "upstream_gap",
        "unresolved",
    ]
    assert "missing_concepts" in route["required"]


def test_stage2_request_merges_the_two_control_action_forms() -> None:
    body = _json_schema_response_format(_ControlElementProviderSet)["json_schema"]
    action = body["schema"]["properties"]["control_actions"]["items"]
    target = action["properties"]["target"]
    assert target["properties"]["type"]["enum"] == [
        "responsibility",
        "controlled_process",
    ]
    assert action["properties"]["effect_kind"]["enum"][0] == "agent_message"
    assert len(action["properties"]["effect_kind"]["enum"]) == 5


def test_the_builder_raises_when_a_union_survives_the_rewrite(monkeypatch) -> None:
    monkeypatch.setattr(llm, "portable_request_schema", lambda schema: dict(schema))
    with pytest.raises(ValueError, match="union") as caught:
        _json_schema_response_format(_PRODUCTION_TYPES["routing"])
    assert "/properties/routes/items" in str(caught.value)


class _ATarget(BaseModel):
    type: Literal["x"]
    id: str


class _BTarget(BaseModel):
    type: Literal["y"]
    id: str


class _A(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["a", "aa"]
    shared: str
    only_a: int = 0
    gain: str = Field(min_length=1)
    target: _ATarget


class _B(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["b"]
    shared: str
    gain: str | None = Field(default=None, min_length=1)
    target: _BTarget


class _BadB(BaseModel):
    kind: Literal["b"]
    shared: int


class _Merged(BaseModel):
    item: Annotated[_A | _B, Field(discriminator="kind")]
    items: list[_A | _B]


class _Conflict(BaseModel):
    item: Annotated[_A | _BadB, Field(discriminator="kind")]


def test_synthetic_unions_of_every_merge_case_pass_the_guard() -> None:
    body = _json_schema_response_format(_Merged)["json_schema"]["schema"]
    assert find_unions(body) == []
    item = body["properties"]["item"]["properties"]
    assert item["kind"]["enum"] == ["a", "aa", "b"]
    assert item["only_a"]["description"].startswith(
        "Applies when `kind` is `a` or `aa`"
    )
    assert item["gain"]["anyOf"][1] == {"type": "null"}
    assert item["target"]["properties"]["type"]["enum"] == ["x", "y"]
    assert "$defs" not in body


def test_a_union_that_cannot_merge_stops_the_request() -> None:
    with pytest.raises(UnionMergeError, match="'shared'"):
        _json_schema_response_format(_Conflict)

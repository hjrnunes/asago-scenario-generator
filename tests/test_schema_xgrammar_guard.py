"""No rejected keyword reaches a request: the response-format builder refuses one.

vLLM's xgrammar backend answers HTTP 400 to a schema that holds one of a
fixed set of keywords.  Every request's ``response_format`` comes from
``_json_schema_response_format``, so the builder raises before a request
carries such a schema.
"""

from __future__ import annotations

import datetime
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.request_schema import portable_request_schema
from asago_scenario_generator.stpa.infra.llm import _json_schema_response_format
from asago_scenario_generator.stpa.obligation_aware.fill_reply import fill_scope
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _required_pair_keys,
    _slot_provider_payload_type,
)
from tests.helpers.obligation_aware import _provider_slot_request
from tests.test_ica_fill_correction import _route

_KEYWORDS = {
    "uniqueItems": True,
    "contains": {"type": "string"},
    "minContains": 1,
    "maxContains": 2,
    "format": "date",
    "multipleOf": 2,
    "minProperties": 1,
    "maxProperties": 3,
    "propertyNames": {"pattern": "^a"},
    "patternProperties": {"^a": {"type": "string"}},
}


def _field_model(keyword: str) -> type[BaseModel]:
    class _Field(BaseModel):
        value: list[str] = Field(json_schema_extra={keyword: _KEYWORDS[keyword]})

    return _Field


def _nested_model(keyword: str) -> type[BaseModel]:
    inner = _field_model(keyword)

    class _Outer(BaseModel):
        inner: inner  # type: ignore[valid-type]

    return _Outer


def _root_model(keyword: str) -> type[BaseModel]:
    class _Root(BaseModel):
        model_config = ConfigDict(json_schema_extra={keyword: _KEYWORDS[keyword]})
        value: str

    return _Root


@pytest.mark.parametrize("keyword", sorted(_KEYWORDS))
def test_each_rejected_keyword_stops_the_request_with_its_path(keyword: str) -> None:
    with pytest.raises(ValueError, match="xgrammar") as caught:
        _json_schema_response_format(_field_model(keyword))
    assert f"/properties/value/{keyword}" in str(caught.value)
    assert "_Field" in str(caught.value)


@pytest.mark.parametrize("keyword", sorted(_KEYWORDS))
def test_a_rejected_keyword_inside_a_definition_stops_the_request(
    keyword: str,
) -> None:
    with pytest.raises(ValueError, match="xgrammar") as caught:
        _json_schema_response_format(_nested_model(keyword))
    assert f"/$defs/_Field/properties/value/{keyword}" in str(caught.value)


@pytest.mark.parametrize("keyword", sorted(_KEYWORDS))
def test_a_rejected_keyword_at_the_top_level_stops_the_request(keyword: str) -> None:
    with pytest.raises(ValueError, match="xgrammar") as caught:
        _json_schema_response_format(_root_model(keyword))
    assert str(caught.value).endswith(f" at /{keyword}")


def test_a_date_field_stops_the_request_through_its_format() -> None:
    class _Dated(BaseModel):
        reviewed_on: datetime.date | None = None

    with pytest.raises(ValueError, match="xgrammar") as caught:
        _json_schema_response_format(_Dated)
    assert "/properties/reviewed_on/anyOf/0/format" in str(caught.value)


def test_the_error_names_every_offending_path() -> None:
    class _Two(BaseModel):
        first: list[str] = Field(json_schema_extra={"uniqueItems": True})
        second: int = Field(multiple_of=2)

    with pytest.raises(ValueError, match="xgrammar") as caught:
        _json_schema_response_format(_Two)
    message = str(caught.value)
    assert "/properties/first/uniqueItems" in message
    assert "/properties/second/multipleOf" in message


def test_a_schema_without_a_rejected_keyword_is_sent_unchanged() -> None:
    class _Plain(BaseModel):
        value: list[str] = Field(min_length=1, max_length=3)
        label: str = Field(pattern=r"^[a-z]+$")

    assert _json_schema_response_format(_Plain) == {
        "type": "json_schema",
        "json_schema": {
            "name": "_Plain",
            "strict": True,
            "schema": portable_request_schema(_Plain.model_json_schema()),
        },
    }


def test_a_property_named_like_a_keyword_or_a_default_holding_one_passes() -> None:
    class _Named(BaseModel):
        format: str
        contains: str = "x"
        notes: dict[str, str] = {"format": "date", "uniqueItems": "yes"}

    schema = _json_schema_response_format(_Named)["json_schema"]["schema"]
    assert sorted(schema["properties"]) == ["contains", "format", "notes"]


@pytest.mark.xfail(
    strict=True,
    reason="governing_pairs carries uniqueItems until the next commit removes it",
)
def test_the_ica_fill_request_schema_holds_no_rejected_keyword() -> None:
    request = _provider_slot_request(routed_routes=(_route(),))
    wire: Any = _slot_provider_payload_type(
        len(request.slots),
        len(_required_pair_keys(request)),
        scope=fill_scope(request),
    )

    body = _json_schema_response_format(wire)["json_schema"]

    assert body["name"] == wire.__name__

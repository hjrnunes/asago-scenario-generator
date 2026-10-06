"""Request schemas avoid string constraints that xgrammar cannot compile.

vLLM's xgrammar backend rejects a string schema that combines ``pattern``
with ``minLength`` or ``maxLength`` (HTTP 400, "features not supported by
xgrammar").  When the pattern cannot match an empty string, ``minLength: 1``
adds nothing, so the request schema drops it; the Pydantic model still
validates the original field.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, Field, StrictStr, ValidationError

from asago_scenario_generator.stpa.infra.llm import _json_schema_response_format
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    _context_bdi_provider_payload_type,
    _scenario_semantics_payload_type,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    _ContextOrderingConditionWire,
)


class _Ref(BaseModel):
    ref: StrictStr = Field(min_length=1, pattern=r"^SEM-[A-Za-z0-9._-]+$")


class _MaybeEmpty(BaseModel):
    ref: StrictStr = Field(min_length=1, pattern=r"^[a-z]*$")


def _pattern_length_nodes(node: Any, path: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        if "pattern" in node and ({"minLength", "maxLength"} & node.keys()):
            found.append(path)
        for key, value in node.items():
            found.extend(_pattern_length_nodes(value, f"{path}/{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_pattern_length_nodes(value, f"{path}[{index}]"))
    return found


def test_request_schema_drops_min_length_implied_by_the_pattern() -> None:
    schema = _json_schema_response_format(_Ref)["json_schema"]["schema"]
    field = schema["properties"]["ref"]
    assert field["pattern"] == r"^SEM-[A-Za-z0-9._-]+$"
    assert "minLength" not in field
    assert _Ref.model_json_schema()["properties"]["ref"]["minLength"] == 1
    with pytest.raises(ValidationError):
        _Ref.model_validate({"ref": ""})


def test_request_schema_keeps_min_length_when_the_pattern_matches_empty() -> None:
    schema = _json_schema_response_format(_MaybeEmpty)["json_schema"]["schema"]
    assert schema["properties"]["ref"]["minLength"] == 1


@pytest.mark.parametrize(
    "model",
    [
        _context_bdi_provider_payload_type(3, None),
        _context_bdi_provider_payload_type(3, None, duration_eligible=True),
        _scenario_semantics_payload_type(3),
        _scenario_semantics_payload_type(
            3, duration_eligible=True, condition_references_supplied=True
        ),
        _ContextOrderingConditionWire,
    ],
)
@pytest.mark.parametrize("strict", [False, True])
def test_stage5_request_schemas_have_no_pattern_with_length(
    model: type[BaseModel], strict: bool
) -> None:
    schema = _json_schema_response_format(model, strict_json_schema=strict)
    assert _pattern_length_nodes(schema["json_schema"]["schema"]) == []

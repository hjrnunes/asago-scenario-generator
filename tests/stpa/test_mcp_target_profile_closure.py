"""An MCP execution target profile closes exactly over its observed inventory."""

from __future__ import annotations

import copy
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    McpInventoryObservation,
)
from tests.stpa.test_execution_classification import _target_profile

Payload = dict


def _payload() -> Payload:
    return _target_profile().model_dump(mode="json", exclude={"semantic_digest"})


def _inventory(payload: Payload, *, redigest: bool = False, **fields) -> None:
    payload["inventory"].update(fields)
    payload["inventory"].pop("semantic_digest")
    if redigest:
        payload["source_inventory_digest"] = McpInventoryObservation.model_validate(
            payload["inventory"]
        ).semantic_digest


def _resource(payload: Payload, **fields) -> None:
    payload["resources"][0].update(fields)


def _interpretation(payload: Payload, **fields) -> None:
    payload["interpretations"][0].update(fields)


def _diagnostic(code: str, severity: str) -> Callable[[Payload], None]:
    def mutate(payload: Payload) -> None:
        payload["diagnostics"] = [{"code": code, "severity": severity, "detail": "d"}]

    return mutate


def _validate(mutate: Callable[[Payload], None]) -> ExecutionTargetProfile:
    payload = copy.deepcopy(_payload())
    mutate(payload)
    return ExecutionTargetProfile.model_validate(payload)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda payload: None, id="unchanged"),
        pytest.param(
            _diagnostic("inventory_protocol_failure", "warning"),
            id="inventory-warning",
        ),
        pytest.param(
            _diagnostic("interpreter_failure", "error"),
            id="non-inventory-error",
        ),
        pytest.param(
            lambda payload: (
                payload.update(inventory_completeness="unknown"),
                _inventory(payload, redigest=True, pagination_complete=False),
            ),
            id="incomplete-pagination-without-completeness-claim",
        ),
    ],
)
def test_closed_profile_is_accepted(mutate) -> None:
    profile = _validate(mutate)

    assert profile.semantic_digest == profile.compute_semantic_digest()
    assert [item.resource_id for item in profile.resources] == [
        "mcp:target-1:retrieve-1"
    ]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        pytest.param(
            lambda payload: payload.update(basis="simulation"),
            "MCP profiles require basis=target",
            id="simulation-basis",
        ),
        pytest.param(
            lambda payload: payload.update(inventory_authority=None),
            "MCP inventory authority must be observed",
            id="unobserved-authority",
        ),
        pytest.param(
            lambda payload: payload.update(inventory=None),
            "MCP profiles require an embedded inventory",
            id="no-inventory",
        ),
        pytest.param(
            lambda payload: payload.update(source_inventory_digest=None),
            "MCP profiles require source_inventory_digest",
            id="no-inventory-digest",
        ),
        pytest.param(
            lambda payload: payload.update(discovery_provenance=None),
            "MCP profiles require discovery_provenance",
            id="no-provenance",
        ),
        pytest.param(
            lambda payload: _inventory(payload, target_id="target-2"),
            "inventory target_id does not match profile target_id",
            id="inventory-target",
        ),
        pytest.param(
            lambda payload: _inventory(payload, authorization_scope_id="scope-2"),
            "inventory authorization_scope_id does not match profile scope",
            id="inventory-scope",
        ),
        pytest.param(
            lambda payload: payload.update(source_inventory_digest="0" * 64),
            "source_inventory_digest does not match embedded inventory",
            id="stale-inventory-digest",
        ),
        pytest.param(
            lambda payload: _inventory(
                payload, redigest=True, pagination_complete=False
            ),
            "observed_complete profiles require complete inventory pagination",
            id="complete-claim-with-incomplete-pagination",
        ),
        pytest.param(
            _diagnostic("inventory_protocol_failure", "error"),
            "observed_complete profiles cannot contain discovery errors",
            id="complete-claim-with-inventory-error",
        ),
        pytest.param(
            lambda payload: payload.update(resources=[]),
            "profile resources must close exactly over inventory tools",
            id="missing-resource",
        ),
        pytest.param(
            lambda payload: _resource(payload, target_id="target-2"),
            "profile resource does not match source inventory tool",
            id="resource-target",
        ),
        pytest.param(
            lambda payload: _resource(payload, title="Other"),
            "profile resource title drifted from inventory",
            id="title-drift",
        ),
        pytest.param(
            lambda payload: _resource(payload, description="Other."),
            "profile resource description drifted from inventory",
            id="description-drift",
        ),
        pytest.param(
            lambda payload: _resource(payload, input_schema={"type": "object"}),
            "profile resource input_schema drifted from inventory",
            id="input-schema-drift",
        ),
        pytest.param(
            lambda payload: _resource(payload, output_schema={"type": "object"}),
            "profile resource output_schema drifted from inventory",
            id="output-schema-drift",
        ),
        pytest.param(
            lambda payload: _resource(payload, annotations={"readOnlyHint": True}),
            "profile resource annotations drifted from inventory",
            id="annotations-drift",
        ),
        pytest.param(
            lambda payload: _resource(payload, evidence_refs=["inventory:tool:other"]),
            "MCP resource evidence_refs must resolve to inventory fields",
            id="foreign-resource-evidence",
        ),
        pytest.param(
            lambda payload: payload["resources"][0]["operations"][0].update(
                semantic_operation="retrieve-2"
            ),
            "MCP semantic_operation must equal the exact tool name",
            id="semantic-operation",
        ),
        pytest.param(
            lambda payload: payload.update(interpretations=[]),
            "profile interpretations must contain one record per inventory tool",
            id="missing-interpretation",
        ),
        pytest.param(
            lambda payload: _interpretation(payload, tool_name="retrieve-2"),
            "interpretation tool_name does not match resource",
            id="interpretation-tool",
        ),
        pytest.param(
            lambda payload: _interpretation(
                payload, evidence_refs=["inventory:tool:other:description"]
            ),
            "interpretation evidence_refs must resolve to inventory fields",
            id="foreign-interpretation-evidence",
        ),
        pytest.param(
            lambda payload: _interpretation(
                payload, observer_resource_ids=["mcp:target-1:other"]
            ),
            "interpretation observer references unknown resource",
            id="unknown-observer",
        ),
    ],
)
def test_unclosed_profile_is_rejected(mutate, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        _validate(mutate)

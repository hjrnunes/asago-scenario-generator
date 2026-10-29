"""Call 2a and the Stage 2 revision send a strict schema built from their wire models.

The request carries what the pipeline accepts: each provider class narrows its
domain model to the closed wire objects, so a reply the schema allows is a reply
the wire models accept.  These tests send the request through the real client
with a fake transport and read the ``response_format`` it put on the wire.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from asago_scenario_generator.stpa.infra.llm import (
    LLMClient,
    _json_schema_response_format,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    RequirementSet,
    ResponsibilitySet,
    _call_2a_responsibilities,
    _ResponsibilityProviderSet,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    RevisionDelta,
    _RevisionDeltaProviderSet,
    run_revision,
)
from tests.helpers.revision_delta import _make_control_structure

_REQUIREMENTS = RequirementSet(
    requirements=[
        {
            "req_id": "REQ-1",
            "description": "Check the actor",
            "classification": "control",
            "source_constraint": "SC-1",
        }
    ]
)
_FINDINGS = CriticFindings(
    gaps=[
        {
            "gap_type": "missing_responsibility",
            "description": "Missing review responsibility",
            "related_attack_path": "An attacker submits crafted input",
            "suggested_remedy": "Add a review responsibility",
        }
    ]
)
_CALL_2A_REPLY = {
    "responsibilities": [
        {
            "resp_id": "RESP-1",
            "description": "Check the actor before it acts",
            "security_constraint_refs": ["SC-1"],
        }
    ]
}
_REVISION_REPLY = {
    "new_responsibilities": [],
    "new_controlled_processes": [],
    "new_coordination_links": [],
    "modified_responsibilities": [],
    "dismissed_gaps": ["Missing review responsibility"],
}


def _transport_response(content: str) -> MagicMock:
    response = MagicMock()
    response.usage = SimpleNamespace(prompt_tokens=3, completion_tokens=4)
    response.choices = [
        SimpleNamespace(message=SimpleNamespace(content=content), finish_reason="stop")
    ]
    return response


def _client(*replies: Any, **profile: Any) -> LLMClient:
    """A real client whose transport serves ``replies`` and records each request."""
    client = LLMClient(
        base_url="http://test-endpoint.invalid",
        api_key="test-key",
        model="test-model",
        **profile,
    )
    client._client = MagicMock()
    client._client.chat.completions.create.side_effect = [
        _transport_response(json.dumps(reply)) for reply in replies
    ]
    return client


def _requests(client: LLMClient) -> list[dict[str, Any]]:
    return [
        call.kwargs for call in client._client.chat.completions.create.call_args_list
    ]


def _call_2a(client: LLMClient, tmp_path) -> ResponsibilitySet:
    return _call_2a_responsibilities(
        llm_client=client,
        use_case_text="Test use case",
        requirement_set=_REQUIREMENTS,
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
    )


def _revise(client: LLMClient, tmp_path):
    return run_revision(
        llm_client=client,
        control_structure=_make_control_structure(),
        critic_findings=_FINDINGS,
        use_case_text="An attacker submits crafted input.",
        run_dir=tmp_path,
    )


def _definition(schema: dict[str, Any], name: str) -> dict[str, Any]:
    return schema["$defs"][name]


def _target(schema: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    """Follow a ``$ref``, an array's ``items``, or an optional's object branch."""
    if "items" in node:
        node = node["items"]
    if "anyOf" in node:
        [node] = [branch for branch in node["anyOf"] if branch.get("type") != "null"]
    if "$ref" in node:
        return _definition(schema, node["$ref"].rsplit("/", 1)[-1])
    return node


def _every_object(schema: dict[str, Any]) -> list[dict[str, Any]]:
    objects = [schema, *schema.get("$defs", {}).values()]
    return [node for node in objects if node.get("type") == "object"]


class TestCall2aRequest:
    def test_the_request_is_the_strict_wire_schema(self, tmp_path) -> None:
        client = _client(_CALL_2A_REPLY)

        _call_2a(client, tmp_path)

        [request] = _requests(client)
        assert request["response_format"] == _json_schema_response_format(
            _ResponsibilityProviderSet
        )
        spec = request["response_format"]["json_schema"]
        assert request["response_format"]["type"] == "json_schema"
        assert spec["name"] == "_ResponsibilityProviderSet"
        assert spec["strict"] is True

    def test_the_schema_lists_the_fields_a_responsibility_may_carry(
        self, tmp_path
    ) -> None:
        client = _client(_CALL_2A_REPLY)

        _call_2a(client, tmp_path)

        schema = _requests(client)[0]["response_format"]["json_schema"]["schema"]
        assert list(schema["properties"]) == ["responsibilities"]
        assert schema["required"] == ["responsibilities"]
        responsibility = _target(schema, schema["properties"]["responsibilities"])
        assert list(responsibility["properties"]) == [
            "resp_id",
            "description",
            "responsibility_constraints",
            "security_constraint_refs",
            "process_model_parts",
        ]
        assert responsibility["required"] == [
            "resp_id",
            "description",
            "security_constraint_refs",
        ]
        assert "id" not in responsibility["properties"]

    def test_the_response_and_each_responsibility_are_closed_objects(
        self, tmp_path
    ) -> None:
        client = _client(_CALL_2A_REPLY)

        _call_2a(client, tmp_path)

        schema = _requests(client)[0]["response_format"]["json_schema"]["schema"]
        responsibility = _target(schema, schema["properties"]["responsibilities"])
        assert schema["additionalProperties"] is False
        assert responsibility["additionalProperties"] is False

    def test_the_schema_description_does_not_carry_parser_notes(self, tmp_path) -> None:
        client = _client(_CALL_2A_REPLY)

        _call_2a(client, tmp_path)

        text = json.dumps(_requests(client)[0]["response_format"])
        assert "generic" not in text
        assert "normalization" not in text

    def test_the_profile_decides_whether_the_schema_is_strict(self, tmp_path) -> None:
        client = _client(_CALL_2A_REPLY, json_schema_strict=False)

        _call_2a(client, tmp_path)

        spec = _requests(client)[0]["response_format"]["json_schema"]
        assert spec["strict"] is False

    def test_a_reply_the_schema_allows_becomes_the_responsibility_set(
        self, tmp_path
    ) -> None:
        client = _client(_CALL_2A_REPLY)

        result = _call_2a(client, tmp_path)

        [responsibility] = result.responsibilities
        assert responsibility.resp_id == "RESP-1"
        assert responsibility.security_constraint_refs == ["SC-1"]

    def test_a_reply_the_wire_rejects_is_corrected_once_and_then_fails(
        self, tmp_path
    ) -> None:
        wrong = {"responsibilities": [{**_CALL_2A_REPLY["responsibilities"][0]}]}
        wrong["responsibilities"][0]["notes"] = "keep"
        client = _client(wrong, wrong)

        with pytest.raises(Exception, match="notes"):
            _call_2a(client, tmp_path)

        assert len(_requests(client)) == 2
        assert all(
            request["response_format"]["json_schema"]["name"]
            == "_ResponsibilityProviderSet"
            for request in _requests(client)
        )


class TestRevisionRequest:
    def test_the_request_is_the_strict_wire_schema(self, tmp_path) -> None:
        client = _client(_REVISION_REPLY)

        _revise(client, tmp_path)

        [request] = _requests(client)
        assert request["response_format"] == _json_schema_response_format(
            _RevisionDeltaProviderSet
        )
        spec = request["response_format"]["json_schema"]
        assert request["response_format"]["type"] == "json_schema"
        assert spec["name"] == "_RevisionDeltaProviderSet"
        assert spec["strict"] is True

    def test_the_schema_lists_the_five_delta_collections(self, tmp_path) -> None:
        client = _client(_REVISION_REPLY)

        _revise(client, tmp_path)

        schema = _requests(client)[0]["response_format"]["json_schema"]["schema"]
        assert list(schema["properties"]) == [
            "new_responsibilities",
            "new_controlled_processes",
            "new_coordination_links",
            "modified_responsibilities",
            "gap_dispositions",
        ]
        assert "required" not in schema

    def test_a_reference_type_stays_text_as_the_wire_leaves_it(self, tmp_path) -> None:
        client = _client(_REVISION_REPLY)

        _revise(client, tmp_path)

        schema = _requests(client)[0]["response_format"]["json_schema"]["schema"]
        responsibility = _target(schema, schema["properties"]["new_responsibilities"])
        action = _target(schema, responsibility["properties"]["control_actions"])
        target = _target(schema, action["properties"]["target"])
        assert target["properties"]["type"].get("type") == "string"
        assert "enum" not in target["properties"]["type"]

    def test_every_object_in_the_schema_is_closed(self, tmp_path) -> None:
        client = _client(_REVISION_REPLY)

        _revise(client, tmp_path)

        schema = _requests(client)[0]["response_format"]["json_schema"]["schema"]
        open_objects = [
            node.get("title")
            for node in _every_object(schema)
            if node.get("additionalProperties") is not False
        ]
        assert open_objects == []

    def test_the_profile_decides_whether_the_schema_is_strict(self, tmp_path) -> None:
        client = _client(_REVISION_REPLY, json_schema_strict=False)

        _revise(client, tmp_path)

        spec = _requests(client)[0]["response_format"]["json_schema"]
        assert spec["strict"] is False

    def test_a_reply_the_schema_allows_is_merged(self, tmp_path) -> None:
        client = _client(_REVISION_REPLY)
        original = _make_control_structure()

        revised, warnings = _revise(client, tmp_path)

        assert revised.responsibilities == original.responsibilities
        assert not any(warning.startswith("Revision failed:") for warning in warnings)

    def test_a_reply_the_wire_rejects_keeps_the_original_and_names_the_field(
        self, tmp_path
    ) -> None:
        wrong = {**_REVISION_REPLY, "notes": "keep"}
        client = _client(wrong, wrong)
        original = _make_control_structure()

        revised, warnings = _revise(client, tmp_path)

        assert revised == original
        assert len(_requests(client)) == 2
        assert any(
            warning.startswith("Revision failed:") and "notes" in warning
            for warning in warnings
        )

    def test_the_provider_class_is_a_revision_delta(self) -> None:
        assert issubclass(_RevisionDeltaProviderSet, RevisionDelta)
        assert issubclass(_ResponsibilityProviderSet, ResponsibilitySet)

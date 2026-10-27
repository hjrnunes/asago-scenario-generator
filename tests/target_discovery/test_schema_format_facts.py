"""A tool input schema's date format counts as a declared value-format fact."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.models.value_facts import (
    ArgumentValueFact,
    DeclaredValue,
    TargetValueFacts,
    ValueFormat,
    with_argument_formats,
)
from asago_scenario_generator.target_discovery import (
    McpTargetDiscoveryInputs,
    discover_mcp_target,
)
from tests.helpers.target_discovery import InMemoryInterpreter, InMemoryInventory

FIXTURE = (
    Path(__file__).parents[2] / "data/contracts/target-discovery/mcp-tools-list.json"
)
DECLARED = {
    "arguments": [
        {
            "operation_id": "process_refund",
            "argument": "order_id",
            "record_kind": "order_id",
        }
    ]
}
# Profile digests the scanner produced for these inputs before input-schema
# formats counted as facts. A schema without a date format must keep them.
UNCHANGED_DIGESTS = {
    ("no-format", False): (
        "ca03e14db6029129ad469fd14268051b005986d7843b5191aa6559a2bcc371fb"
    ),
    ("no-format", True): (
        "86e5f80be20dc7209c3896541b3562c52025993d7d3f68d49e4902fdfa3b1d00"
    ),
    ("other-formats", False): (
        "96b80bc5e69cf13ac9d67d05f8e663c76c9ddc55114f2ec785170cc7cb0dd861"
    ),
    ("other-formats", True): (
        "cf6ac010dc84e6d6f0b463faebc4c069574eb626140fb8276df6e15b6e1e9e08"
    ),
}


def _payload(**formats: tuple[str, object]) -> dict:
    """Return the fixture tools list with ``tool=(argument, format)`` added."""
    payload = copy.deepcopy(json.loads(FIXTURE.read_text(encoding="utf-8")))
    for tool in payload["tools"]:
        if tool["name"] in formats:
            argument, value = formats[tool["name"]]
            tool["inputSchema"]["properties"][argument]["format"] = value
    return payload


def _profile(payload: dict, facts: dict | None = None):
    inputs = McpTargetDiscoveryInputs(
        target_id="mini-klarna-safe",
        authorization_scope_id="test-customer",
        value_facts=TargetValueFacts.model_validate(facts) if facts else None,
    )
    result = discover_mcp_target(
        inputs, InMemoryInventory(payload), InMemoryInterpreter()
    )
    assert result.profile is not None
    result.profile.assert_integrity()
    return result.profile


@pytest.mark.parametrize(
    ("schema_format", "expected"),
    [("date", ValueFormat.date), ("date-time", ValueFormat.date_time)],
)
def test_a_string_argument_with_a_date_format_gains_a_format_fact(
    schema_format: str, expected: ValueFormat
) -> None:
    profile = _profile(_payload(lookup_order=("order_id", schema_format)))

    assert profile.value_facts == TargetValueFacts(
        arguments=(
            ArgumentValueFact(
                operation_id="lookup_order", argument="order_id", format=expected
            ),
        )
    )
    assert profile.value_facts.argument("lookup_order", "order_id") == DeclaredValue(
        format=expected
    )


@pytest.mark.parametrize(
    "formats",
    [
        {"lookup_order": ("order_id", "email")},
        {"lookup_order": ("order_id", "uri")},
        {"lookup_order": ("order_id", "time")},
        {"lookup_order": ("order_id", "Date")},
        {"schedule_payment": ("amount", "date")},
        {"schedule_payment": ("amount", "date-time")},
    ],
    ids=["email", "uri", "time", "wrong-case", "number-date", "number-date-time"],
)
def test_other_formats_and_non_string_types_declare_no_fact(formats: dict) -> None:
    assert _profile(_payload(**formats)).value_facts is None


@pytest.mark.parametrize("schema_type", [["string"], ["string", "null"], None])
def test_only_type_string_declares_a_format_fact(schema_type: object) -> None:
    payload = _payload(lookup_order=("order_id", "date"))
    lookup = next(tool for tool in payload["tools"] if tool["name"] == "lookup_order")
    schema = lookup["inputSchema"]["properties"]["order_id"]
    if schema_type is None:
        del schema["type"]
    else:
        schema["type"] = schema_type

    assert _profile(payload).value_facts is None


def test_a_declaration_with_the_same_format_stays_one_fact() -> None:
    declared = {
        "arguments": [
            {
                "operation_id": "lookup_order",
                "argument": "order_id",
                "record_kind": "order_id",
                "format": "date",
            }
        ]
    }

    profile = _profile(_payload(lookup_order=("order_id", "date")), declared)

    assert profile.value_facts == TargetValueFacts.model_validate(declared)


def test_a_declaration_with_another_format_leaves_no_fact() -> None:
    declared = {
        "arguments": [
            {
                "operation_id": "lookup_order",
                "argument": "order_id",
                "record_kind": "order_id",
                "format": "date-time",
            },
            *DECLARED["arguments"],
        ],
        "state_fields": [{"path": "orders.*.due", "format": "date"}],
    }

    profile = _profile(_payload(lookup_order=("order_id", "date")), declared)

    assert profile.value_facts is not None
    assert profile.value_facts.argument("lookup_order", "order_id") is None
    assert profile.value_facts == TargetValueFacts.model_validate(
        {**declared, "arguments": DECLARED["arguments"]}
    )


def test_a_declaration_without_a_format_gains_the_schema_format() -> None:
    declared = {
        "arguments": [
            {
                "operation_id": "lookup_order",
                "argument": "order_id",
                "record_kind": "order_id",
            }
        ]
    }

    profile = _profile(_payload(lookup_order=("order_id", "date-time")), declared)

    assert profile.value_facts is not None
    assert profile.value_facts.argument("lookup_order", "order_id") == DeclaredValue(
        record_kind="order_id", format=ValueFormat.date_time
    )


@pytest.mark.parametrize("declared", [False, True], ids=["no-facts", "value-facts"])
@pytest.mark.parametrize("schema", ["no-format", "other-formats"])
def test_a_schema_without_a_date_format_keeps_the_profile_bytes(
    schema: str, declared: bool
) -> None:
    payload = (
        _payload()
        if schema == "no-format"
        else _payload(
            lookup_order=("order_id", "email"),
            schedule_payment=("amount", "date"),
        )
    )
    facts = DECLARED if declared else None

    profile = _profile(payload, facts)

    assert profile.semantic_digest == UNCHANGED_DIGESTS[(schema, declared)]
    expected = TargetValueFacts.model_validate(facts) if facts else None
    assert profile.value_facts == expected


def test_without_formats_the_declared_facts_return_unchanged() -> None:
    facts = TargetValueFacts.model_validate(DECLARED)

    assert with_argument_formats(facts, {}) is facts
    assert with_argument_formats(None, {}) is None

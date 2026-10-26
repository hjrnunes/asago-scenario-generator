"""Declared value facts on the execution target profile."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.value_facts import (
    DeclaredValue,
    TargetValueFacts,
    ValueFormat,
)

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "data/contracts/target-profile/target-profile-v1"
HANDOFFS = ROOT / "docs/handoffs/typed-condition-facts"


def _profile_payload() -> dict:
    payload = json.loads((KIT / "valid/minimal.json").read_text(encoding="utf-8"))
    payload.pop("semantic_digest")
    return payload


def test_a_fact_declares_a_record_kind_a_format_or_both() -> None:
    with pytest.raises(ValidationError, match="record_kind, a format, or both"):
        DeclaredValue()

    both = DeclaredValue(record_kind="order_id", format="date")

    assert both.format is ValueFormat.date


@pytest.mark.parametrize("kind", ["Order", "order-id", "_order", "order__id", ""])
def test_a_record_kind_is_lower_snake(kind: str) -> None:
    with pytest.raises(ValidationError):
        DeclaredValue(record_kind=kind)


def test_a_format_is_a_date_or_a_date_time() -> None:
    assert DeclaredValue(format="date-time").format is ValueFormat.date_time
    with pytest.raises(ValidationError):
        DeclaredValue(format="time")


@pytest.mark.parametrize(
    "facts",
    [
        {
            "arguments": [
                {"operation_id": "op", "argument": "a", "record_kind": "x"},
                {"operation_id": "op", "argument": "a", "format": "date"},
            ]
        },
        {
            "state_fields": [
                {"path": "orders.*.id", "record_kind": "x"},
                {"path": "orders.*.id", "record_kind": "y"},
            ]
        },
        {
            "state_keys": [
                {"path": "orders", "record_kind": "x"},
                {"path": "orders", "record_kind": "x"},
            ]
        },
    ],
)
def test_each_target_value_is_declared_once(facts: dict) -> None:
    with pytest.raises(ValidationError, match="declare each target value once"):
        TargetValueFacts.model_validate(facts)


@pytest.mark.parametrize("path", ["", ".orders", "orders.", "orders..id"])
def test_a_state_path_has_no_empty_segment(path: str) -> None:
    with pytest.raises(ValidationError):
        TargetValueFacts.model_validate(
            {"state_fields": [{"path": path, "record_kind": "x"}]}
        )


def test_facts_are_kept_in_canonical_order() -> None:
    facts = TargetValueFacts.model_validate(
        {
            "arguments": [
                {"operation_id": "b", "argument": "a", "record_kind": "x"},
                {"operation_id": "a", "argument": "b", "record_kind": "x"},
                {"operation_id": "a", "argument": "a", "record_kind": "x"},
            ],
            "state_fields": [
                {"path": "z", "record_kind": "x"},
                {"path": "a", "record_kind": "x"},
            ],
        }
    )

    assert [(item.operation_id, item.argument) for item in facts.arguments] == [
        ("a", "a"),
        ("a", "b"),
        ("b", "a"),
    ]
    assert [item.path for item in facts.state_fields] == ["a", "z"]


FACTS = TargetValueFacts.model_validate(
    {
        "arguments": [
            {
                "operation_id": "refund",
                "argument": "order_id",
                "record_kind": "order_id",
            }
        ],
        "state_fields": [
            {"path": "orders.*.customer_id", "record_kind": "customer_id"},
            {"path": "orders.*.due", "format": "date"},
            {"path": "*.*.owner_id", "record_kind": "customer_id"},
            {"path": "orders.*.owner_id", "record_kind": "customer_id"},
            {"path": "*.*.note", "record_kind": "free_text"},
            {"path": "orders.*.note", "record_kind": "order_note"},
        ],
        "state_keys": [{"path": "orders", "record_kind": "order_id"}],
    }
)


def test_an_argument_fact_is_found_by_operation_and_argument() -> None:
    assert FACTS.argument("refund", "order_id") == DeclaredValue(record_kind="order_id")
    assert FACTS.argument("refund", "amount") is None
    assert FACTS.argument("lookup", "order_id") is None


def test_a_star_segment_matches_any_one_key() -> None:
    assert FACTS.state_field(["orders", "ORD-1", "customer_id"]) == DeclaredValue(
        record_kind="customer_id"
    )
    assert FACTS.state_field(["orders", "ORD-1", "due"]) == DeclaredValue(format="date")
    assert FACTS.state_field(["orders", "customer_id"]) is None
    assert FACTS.state_field(["orders", "ORD-1", "x", "customer_id"]) is None
    assert FACTS.state_key(["orders"]) == DeclaredValue(record_kind="order_id")
    assert FACTS.state_key(["customers"]) is None


def test_matching_declarations_that_agree_give_the_fact() -> None:
    assert FACTS.state_field(["orders", "ORD-1", "owner_id"]) == DeclaredValue(
        record_kind="customer_id"
    )


def test_matching_declarations_that_disagree_give_no_fact() -> None:
    assert FACTS.state_field(["orders", "ORD-1", "note"]) is None
    assert FACTS.state_field(["plans", "P-1", "note"]) == DeclaredValue(
        record_kind="free_text"
    )


def test_a_profile_without_value_facts_keeps_its_bytes_and_digest() -> None:
    raw = json.loads((KIT / "valid/minimal.json").read_text(encoding="utf-8"))
    profile = ExecutionTargetProfile.model_validate(raw)

    assert profile.value_facts is None
    assert "value_facts" not in profile.model_dump(mode="json")
    assert profile.semantic_digest == raw["semantic_digest"]


def test_value_facts_are_content_addressed_with_the_profile() -> None:
    payload = _profile_payload()
    plain = ExecutionTargetProfile.model_validate(payload)
    payload["value_facts"] = {
        "arguments": [
            {
                "operation_id": "process_refund",
                "argument": "order_id",
                "record_kind": "order_id",
            }
        ]
    }

    typed = ExecutionTargetProfile.model_validate(payload)

    assert typed.semantic_digest != plain.semantic_digest
    typed.assert_integrity()


@pytest.mark.parametrize(
    ("operation", "argument"),
    [("process_refund", "customer_id"), ("lookup_order", "order_id")],
)
def test_an_argument_fact_must_name_an_argument_of_a_profile_operation(
    operation: str, argument: str
) -> None:
    payload = _profile_payload()
    payload["value_facts"] = {
        "arguments": [
            {"operation_id": operation, "argument": argument, "record_kind": "x"}
        ]
    }

    with pytest.raises(ValidationError, match=f"{operation}.{argument}"):
        ExecutionTargetProfile.model_validate(payload)


def test_the_kit_example_carries_value_facts() -> None:
    raw = json.loads((KIT / "valid/value-facts.json").read_text(encoding="utf-8"))
    digests = json.loads((KIT / "canonical-digests.json").read_text())

    profile = ExecutionTargetProfile.model_validate(raw)

    assert profile.value_facts is not None
    assert (
        profile.semantic_digest == digests["semantic_digests"]["valid/value-facts.json"]
    )


@pytest.mark.parametrize("domain", ["airbnb", "klarna", "occiai"])
def test_each_proposed_domain_facts_file_is_a_target_value_facts(domain: str) -> None:
    facts = TargetValueFacts.model_validate(
        yaml.safe_load((HANDOFFS / f"{domain}.yaml").read_text(encoding="utf-8"))
    )

    assert facts.arguments
    assert facts.state_keys

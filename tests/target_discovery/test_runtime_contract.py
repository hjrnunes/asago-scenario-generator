"""Unit tests for building a declared target's runtime contract."""

from __future__ import annotations

import copy
from types import MappingProxyType
from typing import Any

from asago_scenario_generator.target_discovery import (
    PLANTED_ITEM,
    declared_runtime_contract,
)


def _base() -> dict[str, Any]:
    return {
        "schema_version": "artifact-runtime-contract-v2",
        "authoring_transports": {"discovery": "unavailable", "target": "unavailable"},
        "delivery": ["direct_user_message", "sequential_user_turns"],
        "limits": {"max_planned_turns": 4, "max_turns": 8},
        "observation": {"tool_calls": {"availability": "captured_or_unavailable"}},
        "setup_permissions": [],
        "target_access": "downstream_only",
    }


def _slot(slot_id: str = "helpdesk.ticket.message") -> dict[str, Any]:
    return {
        "id": slot_id,
        "carrier_operation": "get_ticket",
        "field": "messages[].body",
        "controller": "third_party",
        "content_kind": "ticket_message",
        "records": ["TCK-1001"],
        "max_chars": 2000,
        "mode": "replace",
    }


def test_the_planted_item_name_is_stable() -> None:
    assert PLANTED_ITEM == "planted_item"


def test_a_declared_delivery_replaces_the_base_and_gains_the_planted_item() -> None:
    base = _base()

    contract = declared_runtime_contract(
        base,
        seed_slots=[_slot()],
        delivery=["direct_user_message"],
    )

    assert contract["delivery"] == ["direct_user_message", "planted_item"]


def test_without_a_declared_delivery_the_base_delivery_is_used() -> None:
    base = _base()

    contract = declared_runtime_contract(base, seed_slots=[_slot()])

    assert contract["delivery"] == [
        "direct_user_message",
        "sequential_user_turns",
        "planted_item",
    ]


def test_an_empty_declared_delivery_still_replaces_the_base() -> None:
    contract = declared_runtime_contract(_base(), seed_slots=[], delivery=[])

    assert contract["delivery"] == []


def test_no_seed_slot_means_no_planted_item_even_if_a_source_names_it() -> None:
    base = {**_base(), "delivery": ["direct_user_message", PLANTED_ITEM]}

    from_base = declared_runtime_contract(base, seed_slots=[])
    declared = declared_runtime_contract(
        _base(), seed_slots=[], delivery=[PLANTED_ITEM, "sequential_user_turns"]
    )

    assert from_base["delivery"] == ["direct_user_message"]
    assert declared["delivery"] == ["sequential_user_turns"]


def test_the_planted_item_is_offered_once_and_last() -> None:
    base = {**_base(), "delivery": [PLANTED_ITEM, "direct_user_message"]}

    contract = declared_runtime_contract(
        base,
        seed_slots=[_slot("a"), _slot("b")],
        delivery=[PLANTED_ITEM, "direct_user_message", PLANTED_ITEM],
    )

    assert contract["delivery"] == ["direct_user_message", "planted_item"]


def test_a_base_without_delivery_gives_an_empty_delivery() -> None:
    base = _base()
    del base["delivery"]

    assert declared_runtime_contract(base, seed_slots=[])["delivery"] == []
    assert declared_runtime_contract(base, seed_slots=[_slot()])["delivery"] == [
        "planted_item"
    ]


def test_declared_limits_override_single_base_limits_and_keep_the_rest() -> None:
    base = _base()

    contract = declared_runtime_contract(
        base, seed_slots=[], limits={"max_turns": 6, "detector_timeout_seconds": 10}
    )

    assert contract["limits"] == {
        "max_planned_turns": 4,
        "max_turns": 6,
        "detector_timeout_seconds": 10,
    }


def test_absent_or_empty_limits_keep_the_base_limits() -> None:
    base = _base()

    assert declared_runtime_contract(base, seed_slots=[])["limits"] == base["limits"]
    assert (
        declared_runtime_contract(base, seed_slots=[], limits=None)["limits"]
        == base["limits"]
    )
    assert (
        declared_runtime_contract(base, seed_slots=[], limits={})["limits"]
        == base["limits"]
    )


def test_a_base_without_limits_takes_only_the_declared_limits() -> None:
    base = _base()
    del base["limits"]

    assert declared_runtime_contract(base, seed_slots=[])["limits"] == {}
    assert declared_runtime_contract(base, seed_slots=[], limits={"max_turns": 3})[
        "limits"
    ] == {"max_turns": 3}


def test_seed_slots_are_copied_as_plain_dicts() -> None:
    slots = [_slot("a"), _slot("b")]

    contract = declared_runtime_contract(_base(), seed_slots=slots)

    assert contract["seed_slots"] == slots
    for copied, given in zip(contract["seed_slots"], slots, strict=True):
        assert type(copied) is dict
        assert copied is not given
    contract["seed_slots"][0]["id"] = "changed"
    assert slots[0]["id"] == "a"


def test_a_read_only_mapping_slot_becomes_a_dict() -> None:
    slot = MappingProxyType(_slot())

    contract = declared_runtime_contract(_base(), seed_slots=[slot])

    assert contract["seed_slots"] == [_slot()]
    assert type(contract["seed_slots"][0]) is dict


def test_every_other_base_key_is_carried_over_unchanged() -> None:
    base = {**_base(), "extra": {"kept": True}}

    contract = declared_runtime_contract(
        base, seed_slots=[_slot()], delivery=["direct_user_message"], limits={"x": 1}
    )

    for key in base.keys() - {"delivery", "limits"}:
        assert contract[key] == base[key]
    assert contract.keys() == base.keys() | {"seed_slots"}


def test_with_nothing_declared_the_contract_is_the_base_with_no_seed_slots() -> None:
    base = _base()

    contract = declared_runtime_contract(base, seed_slots=[])

    assert contract == {**base, "seed_slots": []}
    assert PLANTED_ITEM not in contract["delivery"]


def test_a_full_declaration_builds_the_expected_contract() -> None:
    base = _base()
    ticket = _slot()
    article = {
        **_slot("helpdesk.kb.article"),
        "carrier_operation": "search_kb",
        "field": "articles[].body",
        "controller": "operator_insider",
        "content_kind": "policy_document",
        "records": ["KB-210"],
        "max_chars": 4000,
        "mode": "append",
    }

    contract = declared_runtime_contract(
        base,
        seed_slots=[ticket, article],
        delivery=["direct_user_message", "sequential_user_turns"],
        limits={"max_turns": 6},
    )

    assert contract == {
        **base,
        "delivery": ["direct_user_message", "sequential_user_turns", "planted_item"],
        "limits": {**base["limits"], "max_turns": 6},
        "seed_slots": [ticket, article],
    }
    assert contract["setup_permissions"] == []


def test_the_base_and_the_inputs_are_not_mutated() -> None:
    base = _base()
    slots = [_slot()]
    delivery = ["direct_user_message", PLANTED_ITEM]
    limits = {"max_turns": 6}
    before = copy.deepcopy((base, slots, delivery, limits))

    contract = declared_runtime_contract(
        base, seed_slots=slots, delivery=delivery, limits=limits
    )

    assert (base, slots, delivery, limits) == before
    assert contract is not base
    assert contract["delivery"] is not base["delivery"]
    assert contract["limits"] is not base["limits"]

"""The mechanism verifier prompt states a standard conversation-only patterns can meet."""

from __future__ import annotations

import re

from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_mechanism_verification_prompts,
)

_ITEM = {
    "item_handle": "R1",
    "distinctive_mechanism": {"name": "Pattern", "description": "Canonical"},
    "selected_structural_path": [{"id": "CP-1", "description": "Request process."}],
}


def _system() -> str:
    system, _user = build_mechanism_verification_prompts([_ITEM])
    return " ".join(system.split())


def test_conversation_only_mechanisms_are_judged_on_the_consequence() -> None:
    system = _system()

    assert "stays within one conversation" in system
    assert "needs no tool, retrieval, or memory" in system
    assert "the selected control action produces the response the attack ends in" in (
        system
    )
    assert "govern the consequence the mechanism names" in system
    assert "A constraint on that consequence is not an adjacent concern" in system


def test_one_accepted_and_one_rejected_example_are_generic() -> None:
    system = _system()

    assert system.count("Accepted example:") == 1
    assert system.count("Rejected example:") == 1
    assert not re.search(
        r"airbnb|klarna|occiai|nhs|AP-T\d|\b(?:H|SC|RESP|CA)-\d", system, re.I
    )


def test_tool_output_rules_and_fail_closed_stay() -> None:
    system = _system()

    assert "poisoned tool or source output being interpreted as an instruction" in (
        system
    )
    assert "Do not infer missing architecture" in system
    assert "`insufficient_evidence`" in system


def test_the_request_carries_no_capability_facts() -> None:
    _system_text, user = build_mechanism_verification_prompts([_ITEM])

    assert "capabilit" not in user.lower()

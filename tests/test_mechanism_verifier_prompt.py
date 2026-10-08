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


def test_the_examples_name_no_real_system() -> None:
    system = _system()

    assert not re.search(
        r"airbnb|klarna|occiai|nhs|AP-T\d|\b(?:H|SC|RESP|CA)-\d", system, re.I
    )


def test_the_request_carries_no_capability_facts() -> None:
    _system_text, user = build_mechanism_verification_prompts([_ITEM])

    assert "capabilit" not in user.lower()

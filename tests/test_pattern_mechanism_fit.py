"""Each pattern-to-mechanism link fits its entry, on the pattern's own text.

Linked evidence is mandatory in the routing and verifier prompts, so a link
whose pattern cannot meet an entry's required evidence would force every
valid route of that pattern to ``unresolved``.  Two checks guard against it:

- ``FIT`` pins, for each link, one verbatim phrase of the pattern's
  description per ``required_evidence`` item, naming the pattern feature that
  meets it.  A new link needs a reviewed row here.
- ``MARKERS`` checks pattern fields or text for what the entry's signature
  needs: content that arrives through a source the agent ingests, an
  attacker's own message, a peer agent relaying a belief, or a state that
  changes after an earlier turn.  A mechanism without a marker rule cannot be
  linked.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import cache
import re
from typing import Any

import pytest

from asago_scenario_generator.pipeline.taxonomy_inputs import (
    bundled_attack_pattern_catalog,
)
from asago_scenario_generator.stpa.mechanism_library import (
    MechanismId,
    bundled_mechanism_library,
    bundled_pattern_mechanism_relation,
)

# ATLAS identities of injected content reaching the agent through a source it
# ingests rather than through the attacker's own prompt: indirect prompt
# injection and retrieval-index poisoning.
_INGESTED = frozenset({"AML.T0051.001", "AML.T0070"})

FIT: dict[tuple[str, MechanismId], tuple[str, ...]] = {
    ("AP-T1-06", MechanismId.retrieved_instructions): (
        "hidden instructions activate",
        "delivers content disguised as legitimate material into a data corpus "
        "feeding an AI assistant's retrieval pipeline",
    ),
    ("AP-T2-05", MechanismId.retrieved_instructions): (
        "interprets the embedded directives as legitimate operational guidance",
        "Insert adversarially crafted content into the agent's vector store",
    ),
    ("AP-T6-03", MechanismId.retrieved_instructions): (
        "misinterprets the hidden instructions as part of its operational goal",
        "Return poisoned output from a compromised or malicious data source",
    ),
    ("AP-T11-05", MechanismId.retrieved_instructions): (
        "embedded instructions that direct a computer-use agent",
        "An attacker crafts web content",
    ),
    ("AP-T15-01", MechanismId.retrieved_instructions): (
        "manipulate an AI assistant into substituting legitimate operational "
        "data (such as payment details or contact information) with "
        "attacker-controlled values",
        "An attacker uses indirect prompt injection",
    ),
    ("AP-T15-02", MechanismId.retrieved_instructions): (
        "causing it to produce urgent, authoritative messages that direct users "
        "toward malicious actions",
        "compromises an AI assistant's output generation through indirect prompt "
        "injection",
    ),
    ("AP-T16-02", MechanismId.retrieved_instructions): (
        "The receiving agent interprets the injected content as trusted protocol "
        "context and executes unintended operations",
        "An attacker crafts a server-side response",
    ),
    ("AP-T6-08", MechanismId.user_claim): (
        "by claiming authority, asserting a pretext, or splitting the request "
        "into innocuous parts. The attack stays inside one conversation",
        "another user's records, credentials, personal data, or proprietary content",
    ),
    ("AP-T12-01", MechanismId.delegated_authority): (
        "inter-agent communication channels",
        "each agent treats incoming peer messages as trusted input",
        "the injected content compounds through successive reasoning steps",
    ),
}


def _flat(text: str) -> str:
    return " ".join(text.split())


def _chain_ids(pattern: Any) -> set[str]:
    return {
        identity
        for mapping in pattern.canonical_chain.mappings
        for identity in (mapping.model_dump(mode="json").get("ids") or ())
    }


def _ingested(pattern: Any) -> bool:
    return bool(_chain_ids(pattern) & _INGESTED)


def _peer_relay(pattern: Any) -> bool:
    return "inter_agent" in pattern.prerequisite_capabilities.min_zones and bool(
        re.search(r"\bpeers?\b", pattern.description)
    )


def _changed_state(pattern: Any) -> bool:
    return bool(
        re.search(
            r"\b(?:changed|no longer (?:holds|valid|current)|outdated|stale|revoked)\b",
            pattern.description,
        )
    )


MARKERS: dict[MechanismId, Callable[[Any], bool]] = {
    MechanismId.retrieved_instructions: _ingested,
    MechanismId.user_claim: lambda pattern: not _ingested(pattern),
    MechanismId.delegated_authority: _peer_relay,
    MechanismId.stale_history: lambda pattern: (
        not _ingested(pattern) and _changed_state(pattern)
    ),
}


@cache
def _catalog() -> dict[str, Any]:
    catalog, _pin = bundled_attack_pattern_catalog()
    return {pattern.id: pattern for pattern in catalog}


def _links() -> set[tuple[str, MechanismId]]:
    return {
        (link.pattern_id, mechanism_id)
        for link in bundled_pattern_mechanism_relation().links
        for mechanism_id in link.mechanisms
    }


def test_every_link_has_exactly_one_reviewed_fit_row() -> None:
    assert set(FIT) == _links()


@pytest.mark.parametrize("link", sorted(FIT), ids=lambda link: f"{link[0]}")
def test_the_pattern_text_meets_every_required_evidence_item(
    link: tuple[str, MechanismId],
) -> None:
    pattern_id, mechanism_id = link
    description = _flat(_catalog()[pattern_id].description)
    evidence = bundled_mechanism_library().entry(mechanism_id).required_evidence

    assert len(FIT[link]) == len(evidence)
    for phrase in FIT[link]:
        assert _flat(phrase) in description, phrase


@pytest.mark.parametrize("link", sorted(FIT), ids=lambda link: f"{link[0]}")
def test_the_pattern_carries_its_mechanism_signature_marker(
    link: tuple[str, MechanismId],
) -> None:
    pattern_id, mechanism_id = link

    assert mechanism_id in MARKERS, f"{mechanism_id} has no marker rule"
    assert MARKERS[mechanism_id](_catalog()[pattern_id])


@pytest.mark.parametrize(
    ("pattern_id", "mechanism_id"),
    [
        ("AP-T1-02", MechanismId.stale_history),
        ("AP-T16-02", MechanismId.delegated_authority),
        ("AP-T6-08", MechanismId.retrieved_instructions),
        ("AP-T6-03", MechanismId.user_claim),
    ],
)
def test_an_incompatible_link_fails_its_marker(
    pattern_id: str, mechanism_id: MechanismId
) -> None:
    assert not MARKERS[mechanism_id](_catalog()[pattern_id])


@pytest.mark.parametrize(
    "mechanism_id", [MechanismId.stale_feedback, MechanismId.forged_completion]
)
def test_a_mechanism_without_a_marker_rule_cannot_be_linked(
    mechanism_id: MechanismId,
) -> None:
    assert mechanism_id not in MARKERS
    assert all(linked != mechanism_id for _pattern, linked in _links())

"""Each pattern-to-mechanism link fits its entry, on the pattern's own record.

Linked evidence is mandatory in the routing and verifier prompts, so a link
whose pattern cannot meet an entry's required evidence would force every
valid route of that pattern to ``unresolved``.  Two checks guard against it:

- ``FIT`` pins, for each link, one verbatim phrase per ``required_evidence``
  item, naming the pattern feature that meets it.  A plain phrase quotes the
  description; a :func:`_step` phrase quotes one step's postconditions, and
  ``STEP_ROLES`` then checks that step's structured fields.  A new link needs
  a reviewed row here.
- ``MARKERS`` checks pattern fields for what the entry's signature needs:
  content that arrives through a source the agent ingests, an attacker's own
  message, an issuer that relays an adversary-updated belief to a receiver
  (read from the canonical chain's data flow), or a state that changes after
  an earlier turn.  A mechanism without a marker rule cannot be linked.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import cache
import re
from types import SimpleNamespace
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

Phrase = str | tuple[str, str]


def _step(step_id: str, phrase: str) -> tuple[str, str]:
    """A phrase quoted from the postconditions of the step *step_id*."""
    return (step_id, phrase)


FIT: dict[tuple[str, MechanismId], tuple[Phrase, ...]] = {
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
    ("AP-T12-01", MechanismId.retrieved_instructions): (
        _step(
            "activate_in_peer_agents",
            "Peer agents consume the persisted messages and the injected "
            "instructions influence their reasoning processes.",
        ),
        "An attacker injects crafted messages into inter-agent communication channels",
    ),
}


def _flat(text: str) -> str:
    return " ".join(text.split())


def _postconditions(step: Any) -> str:
    return _flat(" ".join(item.description for item in step.observable_postconditions))


def _refs(items: Any) -> set[str]:
    return {item.ref_id for item in items}


def _adversary_refs(steps: Any) -> set[str]:
    """What attacker-controlled steps produce: input an adversary can author."""
    return {
        ref
        for step in steps
        if step.attacker_controlled
        for ref in _refs(step.produced)
    }


def _system_step(step: Any) -> bool:
    return step.executor_role == "system" and not step.attacker_controlled


def _ingests_adversary_input(step: Any, steps: Any) -> bool:
    """A system step that consumes what an attacker-controlled step produced."""
    return _system_step(step) and bool(_refs(step.consumed) & _adversary_refs(steps))


def _attacker_step(step: Any, steps: Any) -> bool:
    del steps
    return bool(step.attacker_controlled)


def _system_only(step: Any, steps: Any) -> bool:
    del steps
    return _system_step(step)


# For each mechanism, what a step cited for each evidence item must be.
STEP_ROLES: dict[MechanismId, tuple[Callable[[Any, Any], bool], ...]] = {
    MechanismId.retrieved_instructions: (_ingests_adversary_input, _attacker_step),
    MechanismId.user_claim: (_attacker_step, _system_only),
}


def _chain_ids(pattern: Any) -> set[str]:
    return {
        identity
        for mapping in pattern.canonical_chain.mappings
        for identity in (mapping.model_dump(mode="json").get("ids") or ())
    }


def _ingested(pattern: Any) -> bool:
    return bool(_chain_ids(pattern) & _INGESTED)


def _issuer_relay(pattern: Any) -> bool:
    """Whether the chain relays an adversary-updated belief between agents.

    It needs an inter-agent zone and three system steps in chain order: an
    issuer update that consumes adversary-authorable input and produces
    state; a ``deliver`` step that consumes that state, the relay; and a
    receiver step that consumes what the relay produced.  A receiver that
    consumes the adversary's content directly is not a relay.
    """
    if "inter_agent" not in pattern.prerequisite_capabilities.min_zones:
        return False
    steps = tuple(pattern.canonical_chain.steps)
    for index, update in enumerate(steps):
        if not _ingests_adversary_input(update, steps):
            continue
        issuer_state = {item.ref_id for item in update.produced if item.kind == "state"}
        for later, relay in enumerate(steps[index + 1 :], index + 1):
            if not (
                _system_step(relay)
                and relay.action_kind == "deliver"
                and _refs(relay.consumed) & issuer_state
            ):
                continue
            relayed = _refs(relay.produced)
            if any(
                _system_step(receiver) and _refs(receiver.consumed) & relayed
                for receiver in steps[later + 1 :]
            ):
                return True
    return False


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
    MechanismId.delegated_authority: _issuer_relay,
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
def test_the_pattern_record_meets_every_required_evidence_item(
    link: tuple[str, MechanismId],
) -> None:
    pattern_id, mechanism_id = link
    pattern = _catalog()[pattern_id]
    steps = {step.step_id: step for step in pattern.canonical_chain.steps}
    evidence = bundled_mechanism_library().entry(mechanism_id).required_evidence

    assert len(FIT[link]) == len(evidence)
    for index, phrase in enumerate(FIT[link]):
        if isinstance(phrase, str):
            assert _flat(phrase) in _flat(pattern.description), phrase
            continue
        step_id, quoted = phrase
        step = steps[step_id]
        assert _flat(quoted) in _postconditions(step), phrase
        role = STEP_ROLES[mechanism_id][index]
        assert role(step, tuple(steps.values())), f"{step_id} fails its role"


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
        ("AP-T12-01", MechanismId.delegated_authority),
        ("AP-T6-08", MechanismId.retrieved_instructions),
        ("AP-T6-03", MechanismId.user_claim),
    ],
)
def test_an_incompatible_link_fails_its_marker(
    pattern_id: str, mechanism_id: MechanismId
) -> None:
    assert not MARKERS[mechanism_id](_catalog()[pattern_id])


def test_a_cited_step_must_play_its_evidence_role() -> None:
    """AP-T12-01's attacker delivery step cannot show content being ingested."""
    pattern = _catalog()["AP-T12-01"]
    steps = {step.step_id: step for step in pattern.canonical_chain.steps}
    ingest, _authorship = STEP_ROLES[MechanismId.retrieved_instructions]

    assert ingest(steps["activate_in_peer_agents"], tuple(steps.values()))
    assert not ingest(steps["inject_messages"], tuple(steps.values()))


@pytest.mark.parametrize(
    "mechanism_id", [MechanismId.stale_feedback, MechanismId.forged_completion]
)
def test_a_mechanism_without_a_marker_rule_cannot_be_linked(
    mechanism_id: MechanismId,
) -> None:
    assert mechanism_id not in MARKERS
    assert all(linked != mechanism_id for _pattern, linked in _links())


def _chain_step(
    step_id: str,
    role: str,
    kind: str,
    consumed: tuple[str, ...],
    produced: tuple[str, ...],
) -> SimpleNamespace:
    return SimpleNamespace(
        step_id=step_id,
        executor_role=role,
        action_kind=kind,
        attacker_controlled=role == "attacker",
        consumed=[SimpleNamespace(ref_id=ref, kind="state") for ref in consumed],
        produced=[SimpleNamespace(ref_id=ref, kind="state") for ref in produced],
    )


def _chain(*steps: SimpleNamespace, zones=("input", "inter_agent")) -> Any:
    return SimpleNamespace(
        prerequisite_capabilities=SimpleNamespace(min_zones=zones),
        canonical_chain=SimpleNamespace(steps=steps),
    )


_INJECT = _chain_step("inject", "attacker", "deliver", (), ("payload",))
_UPDATE = _chain_step("update", "system", "invoke", ("payload",), ("issuer_belief",))
_RELAY = _chain_step("relay", "system", "deliver", ("issuer_belief",), ("message",))
_ACT = _chain_step("act", "system", "impact", ("message",), ("effect",))


def test_the_relay_rule_accepts_an_issuer_that_relays_an_updated_belief() -> None:
    assert _issuer_relay(_chain(_INJECT, _UPDATE, _RELAY, _ACT))


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param(_chain(_INJECT, _UPDATE, _ACT), id="no-relay"),
        pytest.param(
            _chain(
                _INJECT,
                _chain_step("relay", "system", "deliver", ("payload",), ("message",)),
                _ACT,
            ),
            id="relay-without-issuer-update",
        ),
        pytest.param(_chain(_INJECT, _UPDATE, _RELAY), id="no-receiver"),
        pytest.param(
            _chain(_INJECT, _UPDATE, _RELAY, _ACT, zones=("input",)),
            id="no-inter-agent-zone",
        ),
    ],
)
def test_the_relay_rule_rejects_a_chain_without_the_full_relay(pattern: Any) -> None:
    assert not _issuer_relay(pattern)

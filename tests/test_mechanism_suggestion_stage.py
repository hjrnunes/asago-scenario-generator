"""The synthesis stage that proposes, verifies, and caps mechanism suggestions."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from asago_scenario_generator.pipeline import synthesis_scenarios
from asago_scenario_generator.pipeline.synthesis_mechanisms import (
    MECHANISM_SUGGESTION_STAGE,
    _run_mechanism_suggestions,
)
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestions import (
    SuggestionVerdict,
)
from tests.helpers.mechanism_suggestions import suggestion_structure
from tests.helpers.obligation_aware import _control_structure, _loss_analysis


class _Verifier:
    def __init__(self, relationship: str | None = "mechanism_specific") -> None:
        self.relationship = relationship
        self.requests: list[Any] = []

    def verify_mechanism_suggestions(self, request):
        self.requests.append(request)
        return tuple(
            SuggestionVerdict(candidate, self.relationship, "r")
            for candidate in request.candidates
        )


class _Failing:
    def verify_mechanism_suggestions(self, request):
        raise RuntimeError("verifier down")


def _run(adapter, structure=None):
    return _run_mechanism_suggestions(
        loss_analysis=_loss_analysis(),
        control_structure=structure or suggestion_structure(),
        adapters=SimpleNamespace(obligation_adapter=adapter),
    )


def test_a_structure_the_join_proposes_nothing_for_sends_no_request() -> None:
    verifier = _Verifier()

    run = _run(verifier, _control_structure())

    assert verifier.requests == []
    assert run.calls == ()
    assert run.value.survivors == ()
    assert not run.value.verified


def test_an_adapter_without_the_entry_point_gets_no_suggestion() -> None:
    run = _run(object())

    assert run.value.proposal.proposed
    assert run.value.survivors == ()
    assert run.calls == ()


def test_verified_proposals_survive_within_the_cap() -> None:
    verifier = _Verifier()

    run = _run(verifier)

    (request,) = verifier.requests
    assert request.candidates == run.value.proposal.candidates()
    assert run.calls == (MECHANISM_SUGGESTION_STAGE,)
    by_slot: dict[str, list[str]] = {}
    for item in run.value.survivors:
        by_slot.setdefault(item.slot_id, []).append(item.mechanism_id.value)
    assert by_slot["CL-1:CM-1:NOT_PROVIDED"] == ["user_claim", "delegated_authority"]
    assert by_slot["RESP-1:CA-1-1:INCORRECT"] == ["user_claim"]
    assert "RESP-1:CA-1-1:WRONG_DURATION" not in by_slot


def test_rejected_proposals_reach_no_slot() -> None:
    run = _run(_Verifier("adjacent_control"))

    assert run.value.verified
    assert run.value.survivors == ()


def test_a_verifier_failure_is_reported_and_never_stops_the_run() -> None:
    run = _run(_Failing())

    assert run.value.survivors == ()
    assert run.value.failure == "verifier down"
    assert run.diagnostics == (
        "mechanism suggestion verification failed: verifier down",
    )


def _ica_kwargs(monkeypatch, suggestions) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def fill_icas(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace(ica_enumeration=None)

    monkeypatch.setattr(
        synthesis_scenarios, "_run_ica_verification", lambda result, **_: result
    )
    adapters = SimpleNamespace(fill_icas=fill_icas, obligation_adapter=None)
    inputs = SimpleNamespace(output_dir="out", max_workers=1)
    monkeypatch.setattr(synthesis_scenarios, "_systemic_inputs", lambda value: value)
    synthesis_scenarios._run_ica(
        (),
        (),
        None,
        None,
        None,
        None,
        inputs,
        None,
        adapters,
        mechanism_suggestions=suggestions,
    )
    return seen


def test_the_ica_port_sees_suggestions_only_when_there_is_one(monkeypatch) -> None:
    survivors = _run(_Verifier()).value.survivors

    assert "mechanism_suggestions" not in _ica_kwargs(monkeypatch, ())
    assert _ica_kwargs(monkeypatch, survivors)["mechanism_suggestions"] == survivors

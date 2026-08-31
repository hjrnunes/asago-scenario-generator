"""Offline acceptance handlers for the Phase 3 STPA challenge ledger."""

from __future__ import annotations

import re
import socket
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from runtime_shared import World

from asago_scenario_generator.models.challenge_ledger import (
    EXPLICIT_PRIORITY_POLICY_VERSION,
    ChallengeEligibility,
    StpaChallengeLedger,
)
from asago_scenario_generator.models.hybrid_coverage import HybridCoverageAssessment
from asago_scenario_generator.pipeline.challenge_ledger import (
    build_stpa_challenge_ledger,
)
from asago_scenario_generator.pipeline.challenge_ledger_persistence import (
    STPA_CHALLENGE_LEDGER_FILENAME,
    read_stpa_challenge_ledger,
    write_stpa_challenge_ledger,
)

FEATURE_ID = "stpa_challenge_ledger"
_ROOT = Path(__file__).resolve().parents[2]
_ASSESSMENT = _ROOT / "tests/fixtures/hybrid-coverage-assessment.yaml"


def _state(world: World) -> dict[str, Any]:
    state = getattr(world, "stpa_challenge_ledger_state", None)
    if state is None:
        state = {
            "assessment": None,
            "assessment_bytes": None,
            "matrix_snapshot": None,
            "eligibility": (),
            "ledger": None,
            "round_trip": None,
            "tamper_error": None,
            "provider_calls": [],
            "temporary_directory": None,
        }
        world.stpa_challenge_ledger_state = state
    return state


def _integer(text: str) -> int:
    match = re.search(r"\b(\d+)\b", text)
    if match is None:
        raise ValueError(f"step does not contain an integer: {text}")
    return int(match.group(1))


def _prepare(world: World) -> dict[str, Any]:
    state = _state(world)
    assessment = HybridCoverageAssessment.from_yaml(_ASSESSMENT.read_bytes())
    state.update(
        {
            "assessment": assessment,
            "assessment_bytes": assessment.to_yaml(),
            "matrix_snapshot": (
                assessment.structural_consideration,
                assessment.taxonomy_correspondence,
                assessment.scenario_realization,
            ),
        }
    )
    return state


def _one_eligibility(state: dict[str, Any], priority: int) -> ChallengeEligibility:
    assessment = state["assessment"]
    return ChallengeEligibility(
        obligation_id=assessment.taxonomy_correspondence[0].obligation_id,
        slot_id=assessment.structural_consideration[0].slot_id,
        priority=priority,
        rationale="Explicit acceptance fixture approval.",
        evidence_refs=("acceptance:review:1",),
    )


def _build(state: dict[str, Any], budget: int) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        state["provider_calls"].append("forbidden")
        raise AssertionError("challenge-ledger planning attempted an external call")

    with (
        patch("openai.OpenAI", side_effect=forbidden),
        patch.object(socket.socket, "connect", side_effect=forbidden),
    ):
        state["ledger"] = build_stpa_challenge_ledger(
            state["assessment"],
            state["eligibility"],
            challenge_budget=budget,
            assessment_artifact_id="acceptance-hybrid-coverage-assessment",
            selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
        )


def _register(api: Any) -> None:
    """Register the challenge-ledger acceptance vocabulary."""
    api.set_feature(FEATURE_ID)

    def intact(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare(world)
        return True, ""

    def offline(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        ledger = state["ledger"]
        return (
            not state["provider_calls"]
            and (
                ledger is None
                or (ledger.network_calls == 0 and ledger.model_calls == 0)
            ),
            "challenge-ledger planning must remain offline",
        )

    def explicit_pair(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        state = _state(world)
        state["eligibility"] = (_one_eligibility(state, _integer(text)),)
        return True, ""

    def build(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        _build(_state(world), _integer(text))
        return True, ""

    def selection_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = re.search(r'"([^"]+)"', text).group(1)
        actual = _state(world)["ledger"].records[0].selection_status
        return actual == expected, f"expected selection {expected}, got {actual}"

    def retained_controls(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        values = tuple(int(value) for value in re.findall(r"\b\d+\b", text))
        ledger = _state(world)["ledger"]
        actual = (ledger.challenge_budget, ledger.records[0].priority)
        return actual == values, f"expected budget/priority {values}, got {actual}"

    def original(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = re.search(r'"([^"]+)"', text).group(1)
        state = _state(world)
        source = state["assessment"].structural_consideration[0]
        retained = state["ledger"].records[0].original_decision
        return (
            retained.disposition == expected
            and retained.row_id == source.row_id
            and retained.evidence == source.evidence,
            "original STPA decision or evidence changed",
        )

    def counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        values = tuple(int(value) for value in re.findall(r"\b\d+\b", text))
        diagnostics = _state(world)["ledger"].diagnostics
        actual = (diagnostics.selected_targets, diagnostics.not_selected_budget)
        return actual == values, f"expected selection counts {values}, got {actual}"

    def unknown(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        state = _state(world)
        kind = re.search(r'"([^"]+)"', text).group(1)
        valid = _one_eligibility(state, 10).model_dump(mode="json")
        if kind == "obligation":
            valid["obligation_id"] = "ob:v1:" + "f" * 64
        elif kind == "STPA slot":
            valid["slot_id"] = "RESP-99:CA-99:INCORRECT"
        else:
            raise ValueError(f"unsupported identity kind: {kind}")
        state["eligibility"] = (ChallengeEligibility.model_validate(valid),)
        return True, ""

    def attempt(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _build(_state(world), 1)
        return True, ""

    def rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        kind = re.search(r'"([^"]+)"', text).group(1)
        error = getattr(world, "validation_error", None)
        expected = "unknown obligation" if kind == "obligation" else "unknown STPA slot"
        return (
            error is not None and expected in str(error),
            f"missing exact rejection for {kind}: {error}",
        )

    def publish(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = re.search(r'"([^"]+)"', text).group(1)
        if expected != STPA_CHALLENGE_LEDGER_FILENAME:
            raise ValueError(f"unsupported challenge artifact name: {expected}")
        state = _state(world)
        directory = tempfile.TemporaryDirectory(prefix="stpa-challenge-ledger-")
        state["temporary_directory"] = directory
        path = write_stpa_challenge_ledger(Path(directory.name), state["ledger"])
        state["round_trip"] = read_stpa_challenge_ledger(path)
        return True, ""

    def round_trip(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        return state["round_trip"] == state["ledger"], "ledger round-trip changed"

    def tamper(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        field = re.search(r'"([^"]+)"', text).group(1)
        state = _state(world)
        payload = yaml.safe_load(state["ledger"].to_yaml())
        if field != "priority":
            return False, f"unsupported tampered field: {field}"
        payload["records"][0][field] += 1
        try:
            StpaChallengeLedger.from_yaml(yaml.safe_dump(payload))
        except ValueError as error:
            state["tamper_error"] = error
        return (
            state["tamper_error"] is not None
            and "semantic_digest" in str(state["tamper_error"]),
            "tampered ledger was not rejected by its digest",
        )

    def unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        assessment = state["assessment"]
        matrices = (
            assessment.structural_consideration,
            assessment.taxonomy_correspondence,
            assessment.scenario_realization,
        )
        return (
            assessment.to_yaml() == state["assessment_bytes"]
            and matrices == state["matrix_snapshot"],
            "challenge selection changed the Phase 2 assessment",
        )

    def no_new_coverage(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = tuple(int(value) for value in re.findall(r"\b\d+\b", text))
        ledger_payload = _state(world)["ledger"].model_dump(mode="json")
        actual = (
            sum("relation" in key for key in ledger_payload),
            sum("scenario" in key for key in ledger_payload),
        )
        return actual == expected, f"challenge ledger added coverage fields: {actual}"

    registrations = (
        (
            r"^an intact Phase 2 assessment is available for challenge selection$",
            intact,
        ),
        (r"^challenge-ledger planning makes no provider calls$", offline),
        (
            r"^one explicit obligation and STPA slot pair with priority \d+$",
            explicit_pair,
        ),
        (r"^the challenge ledger is built with budget \d+$", build),
        (
            r"^the ledger retains explicit budget \d+ and priority \d+$",
            retained_controls,
        ),
        (r'^the pair has selection status "[^"]+"$', selection_status),
        (
            r'^the original STPA disposition "[^"]+" and evidence are preserved$',
            original,
        ),
        (
            r"^the ledger reports \d+ selected and \d+ budget-excluded target$",
            counts,
        ),
        (
            r'^explicit challenge eligibility references an unknown "[^"]+"$',
            unknown,
        ),
        (r"^challenge-ledger construction is attempted$", attempt),
        (
            r'^challenge-ledger construction rejects the unknown "[^"]+"$',
            rejected,
        ),
        (r"^no provider or model call was attempted$", offline),
        (r'^the challenge ledger is published as "[^"]+"$', publish),
        (r"^the persisted challenge ledger round-trips unchanged$", round_trip),
        (
            r'^changing persisted "[^"]+" is rejected by its semantic digest$',
            tamper,
        ),
        (
            r"^the Phase 2 assessment digest and matrices remain unchanged$",
            unchanged,
        ),
        (
            r"^challenge selection creates \d+ correspondence relations and \d+ hybrid scenarios$",
            no_new_coverage,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


register = _register

__all__ = ["FEATURE_ID", "register"]

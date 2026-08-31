"""Offline acceptance handlers for Phase 3 STPA challenge analysis."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from runtime_shared import World

from asago_scenario_generator.models.challenge_analysis import (
    ChallengeAdapterResponse,
    ChallengeAnalysisControls,
    IcaChallengeDraft,
    JustifiedNaChallengeDraft,
    ProposedIca,
    UnresolvedChallengeDraft,
)
from asago_scenario_generator.models.challenge_ledger import (
    EXPLICIT_PRIORITY_POLICY_VERSION,
    ChallengeEligibility,
)
from asago_scenario_generator.models.hybrid_coverage import HybridCoverageAssessment
from asago_scenario_generator.pipeline.challenge_analysis import (
    reconsider_stpa_challenge,
)
from asago_scenario_generator.pipeline.challenge_ledger import (
    build_stpa_challenge_ledger,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

FEATURE_ID = "stpa_challenge_analysis"
_ROOT = Path(__file__).resolve().parents[2]
_ASSESSMENT = _ROOT / "tests/fixtures/hybrid-coverage-assessment.yaml"
_LOSS_ANALYSIS = (
    _ROOT / "src/asago_scenario_generator/stpa/fixtures/loss_analysis_klarna.yaml"
)
_CONTROL_STRUCTURE = (
    _ROOT / "src/asago_scenario_generator/stpa/fixtures/control_structure_klarna.yaml"
)
_STPA_RUNNER = _ROOT / "src/asago_scenario_generator/stpa/pipeline/runner.py"


def _state(world: World) -> dict[str, Any]:
    state = getattr(world, "stpa_challenge_analysis_state", None)
    if state is None:
        state = {
            "assessment": None,
            "assessment_before": None,
            "ledger": None,
            "loss_analysis": None,
            "control_structure": None,
            "opted_in": False,
            "adapter_result": "unresolved",
            "adapter_constructions": 0,
            "result": None,
            "second_error": None,
        }
        world.stpa_challenge_analysis_state = state
    return state


def _prepare(world: World) -> dict[str, Any]:
    state = _state(world)
    assessment = HybridCoverageAssessment.from_yaml(_ASSESSMENT.read_bytes())
    obligation = assessment.taxonomy_correspondence[0]
    structural = assessment.structural_consideration[0]
    ledger = build_stpa_challenge_ledger(
        assessment,
        (
            ChallengeEligibility(
                obligation_id=obligation.obligation_id,
                slot_id=structural.slot_id,
                priority=1,
                rationale="Acceptance-approved exact reconsideration.",
                evidence_refs=("acceptance:phase3:analysis",),
            ),
        ),
        challenge_budget=1,
        assessment_artifact_id="acceptance-hybrid-coverage-assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )
    state.update(
        {
            "assessment": assessment,
            "assessment_before": assessment.to_yaml(),
            "ledger": ledger,
            "loss_analysis": LossAnalysis.model_validate(
                yaml.safe_load(_LOSS_ANALYSIS.read_bytes())
            ),
            "control_structure": ControlStructure.model_validate(
                yaml.safe_load(_CONTROL_STRUCTURE.read_bytes())
            ),
            "original_before": ledger.records[0].original_decision.model_dump_json(),
        }
    )
    return state


def _controls() -> ChallengeAnalysisControls:
    return ChallengeAnalysisControls(
        model_profile="phase3-acceptance",
        model_name="deterministic-fake-stpa-analyst",
        deadline_seconds=30.0,
        temperature=0.0,
    )


def _draft(state: dict[str, Any], request: Any) -> Any:
    result = state["adapter_result"]
    hazard_id = request.context.hazards[0].hazard_id
    constraint_id = next(
        item.constraint_id
        for item in request.context.constraints
        if item.constraint_id.startswith("SC-")
    )
    if result in {"ica", "invalid_ica"}:
        index = 2 if result == "ica" else 99
        original = request.original_decision
        return IcaChallengeDraft(
            proposed_ica=ProposedIca(
                ica_id=f"{original.slot_id}:{index}",
                exec_candidate_id=request.context.exec_candidate_id,
                ica_text="The selected action is unsafe in the challenged context.",
                hazardous_context="The exact timing context can expose a hazard.",
                loss_scenario="The unsafe timing contributes to the pinned loss path.",
                related_hazards=(hazard_id,),
                related_constraints=(constraint_id,),
            ),
            rationale="The bounded analysis found one exact causal STPA path.",
            evidence_refs=(hazard_id, constraint_id),
        )
    if result == "justified_na":
        return JustifiedNaChallengeDraft(
            rationale="The pinned constraint excludes the challenged hazard path.",
            evidence_refs=(hazard_id, constraint_id),
        )
    if result == "unresolved":
        return UnresolvedChallengeDraft(
            reason="missing_evidence",
            rationale="One bounded attempt could not resolve the causal path.",
            evidence_refs=(hazard_id,),
        )
    raise ValueError(f"unsupported fake adapter result: {result}")


def _adapter_factory(state: dict[str, Any]) -> Any:
    state["adapter_constructions"] += 1

    class FakeAdapter:
        def analyze(self, request: Any) -> ChallengeAdapterResponse:
            return ChallengeAdapterResponse(
                request_digest=request.semantic_digest,
                draft=_draft(state, request),
                effective_controls=request.controls,
                adapter_kind="fake",
                request_ref="memory://acceptance/challenge-request",
                response_ref="memory://acceptance/challenge-response",
                provider_calls=0,
                network_calls=0,
            )

    return FakeAdapter()


def _run(state: dict[str, Any], *, with_prior: bool = False) -> None:
    prior = (state["result"],) if with_prior else ()
    try:
        result = reconsider_stpa_challenge(
            state["ledger"],
            state["assessment"],
            state["ledger"].records[0].challenge_id,
            opted_in=state["opted_in"],
            controls=_controls(),
            loss_analysis=state["loss_analysis"],
            control_structure=state["control_structure"],
            adapter_factory=lambda: _adapter_factory(state),
            prior_results=prior,
        )
    except ValueError as error:
        state["second_error"] = error
        return
    state["result"] = result


def _quoted(text: str) -> str:
    return re.search(r'"([^"]+)"', text).group(1)


def _register(api: Any) -> None:
    """Register the Phase 3 challenge-analysis acceptance vocabulary."""
    api.set_feature(FEATURE_ID)

    def selected(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare(world)
        return True, ""

    def opt_in(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        _state(world)["opted_in"] = "not opted in" not in text
        return True, ""

    def fake_result(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        _state(world)["adapter_result"] = _quoted(text)
        return True, ""

    def reconsider(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _run(_state(world))
        return True, ""

    def reconsider_prior(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _run(_state(world), with_prior=True)
        return True, ""

    def status(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        result = _state(world)["result"]
        actual = result.status if result is not None else None
        expected = _quoted(text)
        return actual == expected, f"expected status {expected}, got {actual}"

    def disposition(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        result = _state(world)["result"]
        actual = result.outcome.disposition if result and result.outcome else None
        expected = _quoted(text)
        return actual == expected, f"expected disposition {expected}, got {actual}"

    def no_disposition(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        result = _state(world)["result"]
        return result is not None and result.outcome is None, "outcome was recorded"

    def original(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        result = state["result"]
        actual = result.original_decision.model_dump_json() if result else None
        return actual == state["original_before"], "original STPA decision changed"

    def calls(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = tuple(int(value) for value in re.findall(r"\b\d+\b", text))
        evidence = _state(world)["result"].call_evidence
        actual = (evidence.adapter_attempts, evidence.provider_calls)
        return actual == expected, f"expected calls {expected}, got {actual}"

    def changes(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = int(re.search(r"\b\d+\b", text).group())
        result = _state(world)["result"]
        actual = (result.correspondence_changes, result.coverage_changes)
        return actual == (expected, expected), f"unexpected changes {actual}"

    def no_result(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        return _state(world)["result"] is None, "opt-out produced a result"

    def constructions(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = int(re.search(r"\b\d+\b", text).group())
        actual = _state(world)["adapter_constructions"]
        return actual == expected, f"expected {expected} constructions, got {actual}"

    def failure_kind(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        failure = _state(world)["result"].technical_failure
        actual = failure.kind if failure else None
        expected = _quoted(text)
        return actual == expected, f"expected failure {expected}, got {actual}"

    def second_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        error = _state(world)["second_error"]
        expected = _quoted(text)
        return error is not None and expected in str(error), f"second error: {error}"

    def phase2_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        return (
            state["assessment"].to_yaml() == state["assessment_before"],
            "Phase 2 assessment changed",
        )

    def hybrid_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        result = _state(world)["result"]
        expected = _quoted(text)
        field = (
            "hybrid_generation_status"
            if "generation" in text
            else "hybrid_admission_status"
        )
        actual = getattr(result, field)
        return actual == expected, f"expected {field} {expected}, got {actual}"

    def ordinary_independent(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del world, text, examples
        source = _STPA_RUNNER.read_text(encoding="utf-8")
        return "challenge_analysis" not in source, "ordinary stpa-run imports Task 2"

    registrations = (
        (r"^an exact selected Phase 3 challenge target$", selected),
        (r"^closed-loop analysis is (?:explicitly opted in|not opted in)$", opt_in),
        (r'^the fake STPA adapter returns "[^"]+"$', fake_result),
        (r"^the selected target is reconsidered once$", reconsider),
        (r"^the same target is reconsidered with its prior result$", reconsider_prior),
        (r'^the analysis status is "[^"]+"$', status),
        (r'^the completed challenge disposition is "[^"]+"$', disposition),
        (r"^no completed challenge disposition is recorded$", no_disposition),
        (r"^the original STPA decision remains byte-equivalent$", original),
        (r"^the adapter reports \d+ attempt and \d+ provider calls$", calls),
        (r"^correspondence and coverage changes are both \d+$", changes),
        (r"^no challenge analysis result is produced$", no_result),
        (r"^the adapter was constructed \d+ times$", constructions),
        (r'^the technical failure kind is "[^"]+"$', failure_kind),
        (r'^the second attempt is rejected as "[^"]+"$', second_rejected),
        (r"^the Phase 2 assessment remains byte-equivalent$", phase2_unchanged),
        (r'^hybrid generation remains "[^"]+"$', hybrid_status),
        (r'^hybrid admission remains "[^"]+"$', hybrid_status),
        (
            r"^ordinary stpa-run has no Phase 3 analysis dependency$",
            ordinary_independent,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


register = _register

__all__ = ["FEATURE_ID", "register"]

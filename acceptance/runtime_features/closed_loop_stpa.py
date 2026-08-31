"""Offline acceptance handlers for bounded Phase 3 composition."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

import yaml

from runtime_features.stpa_challenge_analysis import (
    _adapter_factory,
    _controls,
    _prepare,
)
from runtime_shared import World

from asago_scenario_generator.models.challenge_ledger import ChallengeEligibility
from asago_scenario_generator.pipeline.closed_loop_stpa import run_closed_loop_stpa
from asago_scenario_generator.pipeline.closed_loop_stpa_persistence import (
    read_closed_loop_stpa_run,
    write_closed_loop_stpa_run,
)

FEATURE_ID = "closed_loop_stpa"
_ROOT = Path(__file__).resolve().parents[2]
_LINEAGE = _ROOT / "tests/fixtures/phase3-lineage-audit.yaml"
_STPA_RUNNER = _ROOT / "src/asago_scenario_generator/stpa/pipeline/runner.py"


def _state(world: World) -> dict[str, Any]:
    state = getattr(world, "closed_loop_stpa_state", None)
    if state is None:
        state = {
            "base": None,
            "eligibility": (),
            "opted_in": False,
            "run": None,
            "error": None,
            "first_bytes": None,
            "second_bytes": None,
            "lineage": None,
            "audit_case": None,
            "temporary_directory": None,
        }
        world.closed_loop_stpa_state = state
    return state


def _quoted(text: str) -> str:
    match = re.search(r'"([^"]+)"', text)
    if match is None:
        raise ValueError(f"step does not contain a quoted value: {text}")
    return match.group(1)


def _integers(text: str) -> tuple[int, ...]:
    return tuple(int(value) for value in re.findall(r"\b\d+\b", text))


def _prepare_composition(world: World) -> dict[str, Any]:
    state = _state(world)
    base = _prepare(world)
    record = base["ledger"].records[0]
    state.update(
        {
            "base": base,
            "eligibility": (
                ChallengeEligibility(
                    obligation_id=record.obligation_id,
                    slot_id=record.slot_id,
                    priority=record.priority,
                    rationale="Acceptance-approved exact composition target.",
                    evidence_refs=("acceptance:phase3:composition",),
                ),
            ),
        }
    )
    return state


def _compose(state: dict[str, Any], budget: int, *, prior: Any = None) -> Any:
    base = state["base"]
    return run_closed_loop_stpa(
        base["assessment"],
        state["eligibility"],
        challenge_budget=budget,
        assessment_artifact_id="acceptance-hybrid-coverage-assessment",
        opted_in=state["opted_in"],
        controls=_controls(),
        loss_analysis=base["loss_analysis"],
        control_structure=base["control_structure"],
        adapter_factory=lambda record: _adapter_factory(base),
        prior_run=prior,
    )


def _register(api: Any) -> None:
    """Register the closed-loop composition acceptance vocabulary."""
    api.set_feature(FEATURE_ID)

    def exact_target(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_composition(world)
        return True, ""

    def opt_in(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        _state(world)["opted_in"] = "not opted in" not in text
        return True, ""

    def fake_result(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        _state(world)["base"]["adapter_result"] = _quoted(text)
        return True, ""

    def compose(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        state = _state(world)
        state["run"] = _compose(state, _integers(text)[0])
        return True, ""

    def attempted_outcome(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected_count = _integers(text)[0]
        expected_disposition = _quoted(text)
        run = _state(world)["run"]
        actual_disposition = run.analyses[0].outcome.disposition
        actual = (run.diagnostics.attempted_targets, actual_disposition)
        expected = (expected_count, expected_disposition)
        return actual == expected, f"expected {expected}, got {actual}"

    def retained_budget(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = _integers(text)[0]
        actual = _state(world)["run"].ledger.challenge_budget
        return actual == expected, f"expected budget {expected}, got {actual}"

    def changes(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        run = _state(world)["run"]
        expected = _integers(text)
        actual = (run.correspondence_changes, run.coverage_changes)
        return actual == expected, f"expected changes {expected}, got {actual}"

    def hybrid(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        run = _state(world)["run"]
        expected = tuple(re.findall(r'"([^"]+)"', text))
        actual = (run.hybrid_generation_status, run.hybrid_admission_status)
        return actual == expected, f"expected hybrid states {expected}, got {actual}"

    def assessment_unchanged(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        base = _state(world)["base"]
        actual = base["assessment"].to_yaml()
        return actual == base["assessment_before"], "Phase 2 assessment changed"

    def selection_counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        diagnostics = _state(world)["run"].diagnostics
        expected = _integers(text)
        actual = (diagnostics.selected_targets, diagnostics.pending_selected_targets)
        return actual == expected, f"expected selection counts {expected}, got {actual}"

    def attempt_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = _integers(text)[0]
        actual = _state(world)["run"].diagnostics.attempted_targets
        return actual == expected, f"expected {expected} attempts, got {actual}"

    def constructions(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = _integers(text)[0]
        actual = _state(world)["base"]["adapter_constructions"]
        return actual == expected, f"expected {expected} constructions, got {actual}"

    def persist_resume(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        directory = tempfile.TemporaryDirectory(prefix="closed-loop-stpa-")
        state["temporary_directory"] = directory
        path = write_closed_loop_stpa_run(Path(directory.name), state["run"])
        state["first_bytes"] = path.read_bytes()
        prior = read_closed_loop_stpa_run(path)
        state["run"] = _compose(state, prior.ledger.challenge_budget, prior=prior)
        path = write_closed_loop_stpa_run(Path(directory.name), state["run"])
        state["second_bytes"] = path.read_bytes()
        return True, ""

    def same_bytes(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        return state["first_bytes"] == state["second_bytes"], "run bytes changed"

    def substitute_digest(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        assessment = _state(world)["base"]["assessment"]
        object.__setattr__(assessment, "semantic_digest", _quoted(text))
        return True, ""

    def expected_substituted_digest(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        actual = _state(world)["base"]["assessment"].semantic_digest
        expected = _quoted(text)
        return (
            actual == expected,
            f"expected substituted digest {expected}, got {actual}",
        )

    def attempt_composition(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        state = _state(world)
        try:
            state["run"] = _compose(state, _integers(text)[0])
        except ValueError as error:
            state["error"] = error
        return True, ""

    def failed(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        error = _state(world)["error"]
        expected = _quoted(text)
        return error is not None and expected in str(error), f"error was {error}"

    def lineage(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _state(world)["lineage"] = yaml.safe_load(_LINEAGE.read_bytes())
        return True, ""

    def audit_case(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        state = _state(world)
        state["audit_case"] = state["lineage"]["use_cases"][_quoted(text)]
        return True, ""

    def taxonomy_counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        case = _state(world)["audit_case"]["taxonomy"]
        actual = (
            case["envelope_count"],
            case["classifications"]["inconsistent_planning_input"],
            case["classifications"]["expected_extra_candidate"],
        )
        expected = _integers(text)
        return actual == expected, f"expected taxonomy counts {expected}, got {actual}"

    def stpa_counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        case = _state(world)["audit_case"]
        stpa = case["stpa"]
        actual = (
            stpa["exact_join_count"],
            stpa["scenario_count"],
            case["taxonomy"]["identity_lineage_bug_count"],
        )
        expected = _integers(text)
        return actual == expected, f"expected STPA counts {expected}, got {actual}"

    def inferred_targets(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        actual = len(_state(world)["audit_case"]["explicit_eligibility_targets"])
        expected = _integers(text)[0]
        return actual == expected, f"expected {expected} inferred targets, got {actual}"

    def inspect_stpa(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del world, text, examples
        return True, ""

    def no_imports(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del world, examples
        expected = _integers(text)[0]
        source = _STPA_RUNNER.read_text(encoding="utf-8")
        actual = source.count("closed_loop_stpa")
        return actual == expected, f"expected {expected} imports, got {actual}"

    def no_required_artifacts(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del world, examples
        expected = _integers(text)[0]
        source = _STPA_RUNNER.read_text(encoding="utf-8")
        actual = source.count("stpa-obligation-closed-loop-run")
        return actual == expected, f"expected {expected} artifacts, got {actual}"

    registrations = (
        (
            r"^an exact Phase 2 assessment and one explicit closed-loop target$",
            exact_target,
        ),
        (r"^closed-loop composition is (?:explicitly opted in|not opted in)$", opt_in),
        (r'^its fake adapter returns "[^"]+"$', fake_result),
        (r"^the bounded closed-loop run is composed with budget \d+$", compose),
        (r"^the run retains explicit budget \d+$", retained_budget),
        (r'^it records \d+ attempted target and "[^"]+"$', attempted_outcome),
        (r"^it reports \d+ correspondence and \d+ coverage changes$", changes),
        (r'^hybrid generation is "[^"]+" and admission is "[^"]+"$', hybrid),
        (r"^its Phase 2 assessment remains byte-equivalent$", assessment_unchanged),
        (r"^it retains \d+ selected and \d+ pending targets$", selection_counts),
        (r"^it records \d+ attempted targets$", attempt_count),
        (r"^its adapter is constructed \d+ times$", constructions),
        (r"^the exact run is persisted and resumed$", persist_resume),
        (r"^the two persisted run records are byte-equivalent$", same_bytes),
        (
            r'^the Phase 2 assessment digest is substituted with "[^"]+"$',
            substitute_digest,
        ),
        (
            r'^the substituted digest must equal "[^"]+"$',
            expected_substituted_digest,
        ),
        (
            r"^closed-loop composition is attempted with budget \d+$",
            attempt_composition,
        ),
        (r'^composition fails with "[^"]+"$', failed),
        (r"^the completed Phase 3 lineage audit$", lineage),
        (r'^I inspect audited use case "[^"]+"$', audit_case),
        (
            r"^it records \d+ taxonomy envelopes, \d+ inconsistent planning inputs, and \d+ expected extra candidates$",
            taxonomy_counts,
        ),
        (
            r"^it records \d+ of \d+ exact STPA joins with \d+ lineage bugs$",
            stpa_counts,
        ),
        (r"^it infers \d+ closed-loop eligibility targets$", inferred_targets),
        (r"^ordinary stpa-run is inspected without Phase 3 opt-in$", inspect_stpa),
        (r"^it imports \d+ closed-loop modules$", no_imports),
        (r"^it requires \d+ Phase 3 artifacts$", no_required_artifacts),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


register = _register

__all__ = ["FEATURE_ID", "register"]

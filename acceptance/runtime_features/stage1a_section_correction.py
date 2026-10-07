"""Acceptance handlers for the bounded Stage 1a section-correction contract."""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from typing import Any

from runtime_shared import World, _SP1MockLLM

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _merge_loss_analysis_correction,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from registry import StepTable

step = StepTable()


FEATURE_ID = "stage1a_section_correction"


def _risk_card() -> RiskCard:
    """Return a domain-neutral risk card for the public Stage 1a seam."""
    return RiskCard(
        risk_id="neutral-risk",
        risk_name="Request integrity risk",
        risk_description="A submitted request could be processed incorrectly.",
        taxonomy="neutral",
        confidence=0.9,
        grounding_confidence="high",
    )


def _risk_response(
    *, duplicate: bool = False, displaced: bool = False
) -> dict[str, Any]:
    """Return the baseline graph using the current local-handle wire.

    ``duplicate`` intentionally repeats a request-local handle.  The current
    provider boundary rejects that malformed response before canonical IDs are
    allocated, so the acceptance case can prove duplicate rows do not reach
    the graph compiler.
    """
    baseline_loss = {
        "handle": "risk_base_loss",
        "description": "Baseline request integrity is lost.",
        "provenance": "risk_card",
        "source_risk_cards": ["neutral-risk"],
    }
    response: dict[str, Any] = {
        "risk_card_losses": [] if displaced else [baseline_loss],
        "use_case_losses": [copy.deepcopy(baseline_loss)]
        if duplicate or displaced
        else [],
        "hazards": [
            {
                "handle": "risk_base_hazard",
                "description": "The request state becomes unsafe.",
                "related_losses": ["risk_base_loss"],
            }
        ],
        "security_constraints": [
            {
                "handle": "risk_base_constraint",
                "rule": "The request must remain authorized.",
                "related_hazards": ["risk_base_hazard"],
                "applies_when": [],
                "obligations": [],
            }
        ],
        "risk_dispositions": [
            {
                "risk_ref": "neutral-risk",
                "disposition": "cited",
                "loss_ids": ["risk_base_loss"],
                "reason": None,
            }
        ],
    }
    return response


def _section_patch_response() -> dict[str, Any]:
    """Return a valid local-handle hazard/constraint collection."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [
            {
                "handle": "gap_hazard",
                "description": "The corrected request state is unsafe.",
                "related_losses": ["gap_case_loss"],
            }
        ],
        "security_constraints": [
            {
                "handle": "current_constraint",
                "rule": "The corrected request condition must be prevented.",
                "related_hazards": ["gap_hazard"],
                "applies_when": [],
                "obligations": [],
            }
        ],
    }


def _conflicting_correction_response() -> dict[str, Any]:
    """Return a gap response that reuses a reserved canonical hazard ID.

    Current gap responses use local handles for records they add.  A response
    that attempts to reuse ``H-1`` is therefore malformed and must fail closed
    before it can overwrite the authoritative risk-derived hazard.
    """
    response = _section_patch_response()
    response["hazards"] = [
        {
            "handle": "H-1",
            "description": "The authoritative request state has changed semantics.",
            "related_losses": ["risk_base_loss"],
        }
    ]
    response["security_constraints"] = [
        {
            "handle": "current_constraint",
            "rule": "The current request condition must be prevented.",
            "related_hazards": ["H-1"],
            "applies_when": [],
            "obligations": [],
        }
    ]
    return response


def _empty_gap_response() -> dict[str, Any]:
    """Return an explicit no-gap response with all four wire collections."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [],
        "security_constraints": [],
    }


def _fixture_responses(name: str) -> list[dict[str, Any]]:
    """Build one deterministic queue for a named neutral acceptance case."""
    if name == "wire":
        return [_risk_response(), _empty_gap_response()]
    if name == "duplicate":
        return [_risk_response(duplicate=True), _empty_gap_response()]
    if name == "conflict":
        return [_risk_response(), _conflicting_correction_response()]
    raise ValueError(f"unknown Stage 1a correction fixture {name!r}")


def _section_patch_drafts(
    *, empty_correction: bool = False
) -> tuple[LossAnalysisDraft, LossAnalysisDraft]:
    """Build typed prior/correction drafts for the offline collection seam."""
    prior_hazard = {
        "hazard_id": "risk-base-hazard" if empty_correction else "obsolete-hazard",
        "description": (
            "The request state becomes unsafe."
            if empty_correction
            else "The initial gap state is unsafe."
        ),
        "related_losses": ["risk-base-loss" if empty_correction else "gap-case-loss"],
    }
    prior_constraint = {
        "constraint_id": (
            "risk-base-constraint" if empty_correction else "obsolete-constraint"
        ),
        "rule": (
            "The request must remain authorized."
            if empty_correction
            else "The obsolete gap condition must be prevented."
        ),
        "related_hazards": [
            "risk-base-hazard" if empty_correction else "obsolete-hazard"
        ],
        "applies_when": [],
    }
    prior = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                {
                    "loss_id": "risk-base-loss",
                    "description": "Baseline request integrity is lost.",
                    "provenance": "risk_card",
                    "source_risk_cards": ["neutral-risk"],
                }
            ],
            "use_case_losses": [
                {
                    "loss_id": "gap-case-loss",
                    "description": "Service continuity is lost.",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                }
            ],
            "hazards": [prior_hazard],
            "security_constraints": [prior_constraint],
            "risk_dispositions": [
                {
                    "risk_ref": "neutral-risk",
                    "disposition": "cited",
                    "loss_ids": ["risk-base-loss"],
                    "reason": None,
                }
            ],
        }
    )
    correction = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": []
            if empty_correction
            else [
                {
                    "hazard_id": "gap-hazard",
                    "description": "The corrected request state is unsafe.",
                    "related_losses": ["gap-case-loss"],
                }
            ],
            "security_constraints": []
            if empty_correction
            else [
                {
                    "constraint_id": "current-constraint",
                    "rule": "The corrected request condition must be prevented.",
                    "related_hazards": ["gap-hazard"],
                    "applies_when": [],
                }
            ],
            "risk_dispositions": [],
        }
    )
    return prior, correction


def _entries(world: World) -> list[dict[str, Any]]:
    run_dir = getattr(world, "stage1a_section_run_dir", None)
    if run_dir is None:
        return []
    path = Path(run_dir) / "calls.jsonl"
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if json.loads(line).get("stage") == "stage_1a"
    ]


@step(r'^a neutral Stage 1a correction fixture "[^"]+"$')
def _h_fixture(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del examples
    name = text.split('"', 2)[1]
    world.stage1a_section_fixture = name
    world.stage1a_section_run_dir = Path(tempfile.mkdtemp(prefix="stage1a_section_"))
    return True, ""


@step(r"^the public Stage 1a loss-analysis seam is called$")
def _h_run(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del text, examples
    if world.stage1a_section_fixture in {"section_patch", "empty_sections"}:
        return False, "public Stage 1a seam cannot run an offline-only fixture"
    client = _SP1MockLLM()
    client.set_response_queue(_fixture_responses(world.stage1a_section_fixture))
    world.stage1a_section_client = client
    try:
        world.stage1a_section_result = derive_loss_analysis(
            llm_client=client,
            use_case_text="A service receives a request and records its processing result.",
            risk_cards=[_risk_card()],
            run_dir=world.stage1a_section_run_dir,
        )
    except Exception as exc:  # assertions below distinguish expected failures
        world.stage1a_section_error = exc
        world.validation_error = exc
    return True, ""


@step(r"^the offline Stage 1a section-merge seam is called$")
def _h_offline_run(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    """Call the collection merge directly without constructing a provider."""
    del text, examples
    if world.stage1a_section_fixture not in {"section_patch", "empty_sections"}:
        return False, "offline section merge requires an offline section fixture"
    prior, correction = _section_patch_drafts(
        empty_correction=world.stage1a_section_fixture == "empty_sections"
    )
    world.stage1a_section_client = None
    world.stage1a_section_result = _merge_loss_analysis_correction(prior, correction)
    return True, ""


def _require_result(world: World) -> tuple[Any | None, str]:
    result = getattr(world, "stage1a_section_result", None)
    if result is None:
        return (
            None,
            f"Stage 1a did not produce an analysis: {getattr(world, 'stage1a_section_error', None)}",
        )
    return result, ""


def _descriptions(items: Any) -> set[str]:
    return {str(getattr(item, "description", "")) for item in items}


@step(r"^the Stage 1a wire contract requires exactly five collections$")
def _h_wire(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del text, examples
    client = getattr(world, "stage1a_section_client", None)
    if client is None or not client.calls:
        return False, "no deterministic Stage 1a call was recorded"
    schema = client.calls[0]["response_format"].model_json_schema()
    required = set(schema.get("required", ()))
    expected = {
        "risk_card_losses",
        "use_case_losses",
        "hazards",
        "security_constraints",
        "risk_dispositions",
    }
    return required == expected, f"expected five required collections, got {required}"


def _retains_description_handler(collection: str, description: str):
    """Build a Then handler requiring ``description`` in one result collection."""

    def handler(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
        del text, examples
        result, error = _require_result(world)
        return (
            not error and description in _descriptions(getattr(result, collection)),
            error,
        )

    return handler


_h_prior_risk_loss = _retains_description_handler(
    "risk_card_losses", "Baseline request integrity is lost."
)
step.add(
    r"^the corrected analysis retains the prior risk-derived loss$", _h_prior_risk_loss
)
_h_prior_use_case_loss = _retains_description_handler(
    "use_case_losses", "Service continuity is lost."
)
step.add(
    r"^the corrected analysis retains the prior use-case loss$", _h_prior_use_case_loss
)
_h_contains_hazard = _retains_description_handler(
    "hazards", "The corrected request state is unsafe."
)
step.add(
    r"^the corrected analysis contains the replacement hazard$", _h_contains_hazard
)


@step(r"^the corrected analysis retains the prior hazard$")
def _h_prior_hazard(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, error = _require_result(world)
    return (
        not error
        and "The request state becomes unsafe." in _descriptions(result.hazards),
        error or "the prior hazard was not retained",
    )


@step(r"^the corrected analysis omits the obsolete hazard$")
def _h_omits_hazard(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, error = _require_result(world)
    return (
        not error
        and "The initial gap state is unsafe." not in _descriptions(result.hazards),
        error,
    )


_h_prior_constraint = _retains_description_handler(
    "security_constraints", "The request must remain authorized."
)
step.add(
    r"^the corrected analysis retains the prior security constraint$",
    _h_prior_constraint,
)


_h_contains_constraint = _retains_description_handler(
    "security_constraints", "The corrected request condition must be prevented."
)
step.add(
    r"^the corrected analysis contains the replacement security constraint$",
    _h_contains_constraint,
)


@step(r"^the corrected analysis omits the obsolete security constraint$")
def _h_omits_constraint(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, error = _require_result(world)
    return (
        not error
        and "The obsolete gap condition must be prevented."
        not in _descriptions(result.security_constraints),
        error,
    )


@step(r"^the Stage 1a run makes no repair attempt$")
def _h_no_repair(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del text, examples
    entries = _entries(world)
    if world.stage1a_section_fixture not in {"conflict", "duplicate"}:
        return False, "no-repair assertion is only valid for malformed fixtures"
    expected = (
        [("risk_derivation", False)]
        if world.stage1a_section_fixture == "duplicate"
        else [("risk_derivation", True), ("gap_analysis", False)]
    )
    actual = [(entry.get("step"), entry.get("success")) for entry in entries]
    if actual != expected:
        return False, f"expected one failed gap attempt and no repair, got {actual}"
    client = getattr(world, "stage1a_section_client", None)
    expected_calls = 1 if world.stage1a_section_fixture == "duplicate" else 2
    if client is None or len(client.calls) != expected_calls:
        return (
            False,
            f"expected exactly {expected_calls} provider calls, got "
            f"{getattr(client, 'calls', None)}",
        )
    if any(str(entry.get("step", "")).endswith("_repair") for entry in entries):
        return False, "malformed gap response incorrectly triggered repair"
    return True, ""


@step(r"^the section merge makes no provider call$")
def _h_no_provider_call(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    client = getattr(world, "stage1a_section_client", None)
    if client is not None and client.calls:
        return False, f"offline section merge made provider calls: {client.calls}"
    return True, ""


@step(r"^Stage 1a derivation rejects the duplicate local handle$")
def _h_duplicate_rejected(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    error = getattr(world, "stage1a_section_error", None)
    return (
        error is not None
        and "duplicate request-local loss handle 'risk_base_loss'" in str(error),
        f"expected the duplicate local-handle failure, got {error}",
    )


@step(r"^the duplicate risk response remains in call evidence$")
def _h_duplicate_evidence(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    entries = _entries(world)
    if not entries:
        return False, "the malformed risk response was not logged"
    raw = entries[0].get("response_content") or ""
    return (
        "risk_base_loss" in raw,
        "raw duplicate-handle response was not retained",
    )


@step(r"^the Stage 1a run makes no correction attempt$")
def _h_no_correction(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    entries = _entries(world)
    actual = [(entry.get("step"), entry.get("success")) for entry in entries]
    expected = [("risk_derivation", True), ("gap_analysis", True)]
    return (
        actual == expected,
        f"expected no additional correction call with {expected}, got {actual}",
    )


@step(r"^Stage 1a derivation fails with a reserved canonical handle$")
def _h_conflict(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del text, examples
    error = getattr(world, "stage1a_section_error", None)
    return (
        error is not None and "reserved canonical graph ID" in str(error),
        f"expected the reserved canonical-handle failure, got {error}",
    )


@step(r"^the malformed gap response remains in call evidence$")
def _h_conflict_evidence(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    entries = _entries(world)
    if len(entries) < 2:
        return False, "the malformed gap attempt was not logged"
    raw = entries[-1].get("response_content") or ""
    return (
        "H-1" in raw and "authoritative request state has changed semantics" in raw,
        "raw malformed gap response was not retained",
    )


register = step.register


__all__ = ["FEATURE_ID", "register"]

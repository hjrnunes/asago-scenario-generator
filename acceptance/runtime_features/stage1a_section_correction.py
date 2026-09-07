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
    derive_loss_analysis,
)


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
    """Return the baseline graph with an optional repeated/displaced loss."""
    baseline_loss = {
        "loss_id": "risk-base-loss",
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
                "hazard_id": "risk-base-hazard",
                "description": "The request state becomes unsafe.",
                "related_losses": ["risk-base-loss"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "risk-base-constraint",
                "description": "The request must remain authorized.",
                "related_hazards": ["risk-base-hazard"],
            }
        ],
    }
    return response


def _invalid_gap_response() -> dict[str, Any]:
    """Return a gap response whose hazard deliberately references no loss."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [
            {
                "loss_id": "gap-case-loss",
                "description": "Service continuity is lost.",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        ],
        "hazards": [
            {
                "hazard_id": "gap-hazard",
                "description": "The initial gap state is unsafe.",
                "related_losses": ["missing-loss"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "obsolete-constraint",
                "description": "The obsolete gap condition must be prevented.",
                "related_hazards": ["gap-hazard"],
            }
        ],
    }


def _section_patch_response() -> dict[str, Any]:
    """Return a correction with empty loss sections and full hazard/SC sections."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [
            {
                "hazard_id": "gap-hazard",
                "description": "The corrected request state is unsafe.",
                "related_losses": ["gap-case-loss"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "current-constraint",
                "description": "The corrected request condition must be prevented.",
                "related_hazards": ["gap-hazard"],
            }
        ],
    }


def _conflicting_correction_response() -> dict[str, Any]:
    """Return a correction that changes the authoritative hazard semantics."""
    response = _section_patch_response()
    response["hazards"] = [
        {
            "hazard_id": "risk-base-hazard",
            "description": "The authoritative request state has changed semantics.",
            "related_losses": ["risk-base-loss"],
        }
    ]
    response["security_constraints"] = [
        {
            "constraint_id": "current-constraint",
            "description": "The current request condition must be prevented.",
            "related_hazards": ["risk-base-hazard"],
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
    if name == "section_patch":
        return [
            _risk_response(displaced=True),
            _invalid_gap_response(),
            _section_patch_response(),
        ]
    if name == "duplicate":
        return [_risk_response(duplicate=True), _empty_gap_response()]
    if name == "conflict":
        return [
            _risk_response(),
            _invalid_gap_response(),
            _conflicting_correction_response(),
        ]
    raise ValueError(f"unknown Stage 1a correction fixture {name!r}")


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


def _h_fixture(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del examples
    name = text.split('"', 2)[1]
    world.stage1a_section_fixture = name
    world.stage1a_section_run_dir = Path(tempfile.mkdtemp(prefix="stage1a_section_"))
    return True, ""


def _h_run(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del text, examples
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
    }
    return required == expected, f"expected four required collections, got {required}"


def _h_prior_risk_loss(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, error = _require_result(world)
    return (
        not error
        and "Baseline request integrity is lost."
        in _descriptions(result.risk_card_losses),
        error,
    )


def _h_prior_use_case_loss(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, error = _require_result(world)
    return (
        not error
        and "Service continuity is lost." in _descriptions(result.use_case_losses),
        error,
    )


def _h_contains_hazard(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, error = _require_result(world)
    return (
        not error
        and "The corrected request state is unsafe." in _descriptions(result.hazards),
        error,
    )


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


def _h_prior_constraint(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, error = _require_result(world)
    return (
        not error
        and "The request must remain authorized."
        in _descriptions(result.security_constraints),
        error,
    )


def _h_contains_constraint(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, error = _require_result(world)
    return (
        not error
        and "The corrected request condition must be prevented."
        in _descriptions(result.security_constraints),
        error,
    )


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


def _h_at_most_one_correction(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    entries = _entries(world)
    expected = (
        [("risk_derivation", True), ("gap_analysis", False), ("gap_analysis", False)]
        if world.stage1a_section_fixture == "conflict"
        else [
            ("risk_derivation", True),
            ("gap_analysis", False),
            ("gap_analysis", True),
        ]
    )
    actual = [(entry.get("step"), entry.get("success")) for entry in entries]
    return (
        actual == expected,
        f"expected one bounded correction with {expected}, got {actual}",
    )


def _h_rejected_gap_evidence(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    entries = _entries(world)
    if len(entries) < 2:
        return False, "the rejected gap attempt was not logged"
    raw = entries[1].get("response_content") or ""
    return "missing-loss" in raw, "raw invalid gap response was not retained"


def _h_one_risk_loss(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, error = _require_result(world)
    return (
        not error and len(result.risk_card_losses) == 1,
        error or "duplicate risk-base loss was not deduplicated",
    )


def _h_no_use_case_losses(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    result, error = _require_result(world)
    return (
        not error and not result.use_case_losses,
        error or "unexpected use-case loss remained",
    )


def _h_no_correction(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    entries = _entries(world)
    actual = [(entry.get("step"), entry.get("success")) for entry in entries]
    expected = [("risk_derivation", True), ("gap_analysis", True)]
    return (
        actual == expected,
        f"expected no correction retry with {expected}, got {actual}",
    )


def _h_conflict(world: World, text: str, examples: dict[str, str]) -> tuple[bool, str]:
    del text, examples
    error = getattr(world, "stage1a_section_error", None)
    return error is not None and "conflicting duplicate hazard ID" in str(error), str(
        error
    )


def _h_conflict_evidence(
    world: World, text: str, examples: dict[str, str]
) -> tuple[bool, str]:
    del text, examples
    entries = _entries(world)
    if len(entries) < 3:
        return False, "the conflicting correction attempt was not logged"
    raw = entries[-1].get("response_content") or ""
    return (
        "authoritative request state has changed semantics" in raw,
        "raw conflicting correction was not retained",
    )


def register(api: object) -> None:
    """Register the focused Stage 1a section-correction acceptance steps."""
    api.register(r'^a neutral Stage 1a correction fixture "[^"]+"$', _h_fixture)
    api.register(r"^the public Stage 1a loss-analysis seam is called$", _h_run)
    api.register(
        r"^the Stage 1a wire contract requires exactly four collections$", _h_wire
    )
    api.register(
        r"^the corrected analysis retains the prior risk-derived loss$",
        _h_prior_risk_loss,
    )
    api.register(
        r"^the corrected analysis retains the prior use-case loss$",
        _h_prior_use_case_loss,
    )
    api.register(
        r"^the corrected analysis contains the replacement hazard$", _h_contains_hazard
    )
    api.register(r"^the corrected analysis omits the obsolete hazard$", _h_omits_hazard)
    api.register(
        r"^the corrected analysis retains the prior security constraint$",
        _h_prior_constraint,
    )
    api.register(
        r"^the corrected analysis contains the replacement security constraint$",
        _h_contains_constraint,
    )
    api.register(
        r"^the corrected analysis omits the obsolete security constraint$",
        _h_omits_constraint,
    )
    api.register(
        r"^the Stage 1a run makes at most one correction attempt$",
        _h_at_most_one_correction,
    )
    api.register(
        r"^the rejected gap response remains in call evidence$",
        _h_rejected_gap_evidence,
    )
    api.register(
        r"^the final analysis has exactly one risk-derived loss$", _h_one_risk_loss
    )
    api.register(r"^the final analysis has no use-case losses$", _h_no_use_case_losses)
    api.register(r"^the Stage 1a run makes no correction attempt$", _h_no_correction)
    api.register(
        r"^Stage 1a derivation fails with a conflicting authoritative ID$", _h_conflict
    )
    api.register(
        r"^the conflicting correction remains in call evidence$", _h_conflict_evidence
    )


__all__ = ["FEATURE_ID", "register"]

"""Acceptance handlers for the Phase 1 loss-analysis gates."""

from __future__ import annotations

import json
import re as _gd_re

from runtime_shared import Path, World, _SP1MockLLM, _SP1RiskCard, _tempfile
import yaml as _gd_yaml

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    GATES_ARTIFACT,
    check_hazard_graph_density,
    check_risk_accounting,
    extract_subject_phrases,
    gate_loss_analysis,
)
from registry import StepTable

step = StepTable()


FEATURE_ID = "loss_analysis_gates"


def _risk_cards() -> list:
    return [
        _SP1RiskCard(
            risk_id="atlas-001",
            risk_name="Prompt injection",
            risk_description="Risk of prompt injection",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        _SP1RiskCard(
            risk_id="atlas-002",
            risk_name="Data exposure",
            risk_description="Risk of data exposure",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
    ]


def _accounted_analysis_dict() -> dict:
    """One disposed card next to one card that no record accounts for."""
    return {
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Unauthorized transaction",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            }
        ],
        "use_case_losses": [],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "The agent executes an unintended payment.",
                "related_losses": ["L-1"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": (
                    "The agent must confirm every unintended payment before execution."
                ),
                "related_hazards": ["H-1"],
                "applies_when": [],
            }
        ],
        "risk_dispositions": [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            }
        ],
    }


def _gapped_graph_dict() -> dict:
    """A graph with one failure per density check and one passing edge."""
    return {
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Payment record exposed",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            }
        ],
        "use_case_losses": [
            {
                "loss_id": "L-2",
                "description": "Customer trust lost",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        ],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": (
                    "The agent exposes the payment record to an unauthorized recipient."
                ),
                "related_losses": ["L-1"],
            },
            {
                "hazard_id": "H-2",
                "description": "The agent improvises fee amounts.",
                "related_losses": ["L-1"],
            },
            {
                "hazard_id": "H-3",
                "description": (
                    "The agent discloses another customer's order history."
                ),
                "related_losses": ["L-1"],
            },
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": (
                    "The payment record must never reach an unauthorized recipient."
                ),
                "behavior_class": "disclosure",
                "related_hazards": ["H-1"],
                "applies_when": [],
            },
            {
                "constraint_id": "SC-2",
                "rule": "The payment record must stay protected.",
                "related_hazards": [],
                "applies_when": [],
            },
            {
                "constraint_id": "SC-3",
                "rule": ("The agent must escalate every regulated topic to a human."),
                "behavior_class": "missed_escalation",
                "related_hazards": ["H-2"],
                "applies_when": [],
            },
            {
                "constraint_id": "SC-4",
                "rule": (
                    "The agent must never give wrong information about the "
                    "payment record."
                ),
                "behavior_class": "wrong_information",
                "related_hazards": ["H-1"],
                "applies_when": [],
            },
        ],
        "risk_dispositions": [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            }
        ],
    }


@step(r"^a persisted loss analysis that disposes one of two supplied risk cards$")
def _h_accounting_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    world.loss_gates_risk_cards = _risk_cards()
    world.loss_gates_analysis = LossAnalysis.model_validate(_accounted_analysis_dict())
    return True, ""


@step(r"^the deterministic risk-accounting check runs$")
def _h_run_accounting(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    world.loss_gates_accounting = check_risk_accounting(
        world.loss_gates_analysis, world.loss_gates_risk_cards
    )
    return True, ""


@step(r"^the check reports the undisposed card as unaccounted$")
def _h_unaccounted(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    report = world.loss_gates_accounting
    return (
        report.unaccounted_risk_refs == ("atlas-002",),
        f"expected atlas-002 unaccounted, got {report.unaccounted_risk_refs}",
    )


@step(r"^the check reports the disposed card as cited$")
def _h_cited(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    report = world.loss_gates_accounting
    return (
        report.cited_refs == ("atlas-001",),
        f"expected atlas-001 cited, got {report.cited_refs}",
    )


@step(r"^a persisted loss analysis with gaps in its hazard graph$")
def _h_density_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    world.loss_gates_density_analysis = LossAnalysis.model_validate(
        _gapped_graph_dict()
    )
    return True, ""


@step(r"^the deterministic hazard-graph density check runs$")
def _h_run_density(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    world.loss_gates_density = check_hazard_graph_density(
        world.loss_gates_density_analysis
    )
    return True, ""


def _h_density_failing(world: World, expected: str) -> tuple[bool, str]:
    checks = world.loss_gates_density.failing_checks
    return (
        any(expected in check for check in checks),
        f"expected {expected!r} in failing checks, got {checks}",
    )


@step(r"^the check reports each loss without a hazard$")
def _h_loss_without_hazard(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return _h_density_failing(world, "loss L-2 has no hazard")


@step(r"^the check reports each constraint without a hazard$")
def _h_constraint_without_hazard(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    return _h_density_failing(world, "constraint SC-2 has no hazard")


@step(r"^the check reports each hazard without a constraint$")
def _h_hazard_without_constraint(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    return _h_density_failing(world, "hazard H-3 has no constraint")


@step(
    r"^the check records each constraint-hazard pair that shares no subject phrase as advisory$"
)
def _h_subject_mismatch(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    expected = "constraint SC-3 and hazard H-2 share no subject phrase"
    return (
        expected in world.loss_gates_density.advisory_checks,
        f"expected {expected!r} in advisory checks, got "
        f"{world.loss_gates_density.advisory_checks}",
    )


@step(r"^the check reports each behavior class that owns no hazard of its own$")
def _h_class_without_hazard(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    return _h_density_failing(
        world, "behavior class wrong_information has no hazard of its own"
    )


@step(r"^the check passes for the constraint-hazard pair that shares a subject phrase$")
def _h_subject_match_recorded(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    edge = next(
        (
            check
            for check in world.loss_gates_density.subject_checks
            if check.constraint_id == "SC-1" and check.hazard_id == "H-1"
        ),
        None,
    )
    return (
        edge is not None and "payment record" in edge.shared_phrases,
        f"expected the SC-1/H-1 shared subject recorded, got {edge}",
    )


@step(
    r"^the deterministic subject rule extracts phrases from constraint and hazard text$"
)
def _h_subject_rule(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    generic_constraint = "The system must ensure compliance."
    generic_hazard = "The assistant must ensure safety."
    world.loss_gates_generic_shared = sorted(
        extract_subject_phrases(generic_constraint)
        & extract_subject_phrases(generic_hazard)
    )
    concrete_constraint = (
        "The agent must confirm every unintended payment before execution."
    )
    concrete_hazard = "The agent executes an unintended payment."
    world.loss_gates_concrete_shared = sorted(
        extract_subject_phrases(concrete_constraint)
        & extract_subject_phrases(concrete_hazard)
    )
    return True, ""


@step(
    r"^texts sharing only generic actor and verb vocabulary produce no shared phrase$"
)
def _h_generic_no_match(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return (
        not world.loss_gates_generic_shared,
        f"generic vocabulary produced shared phrases: "
        f"{world.loss_gates_generic_shared}",
    )


@step(r"^texts sharing a concrete noun phrase produce that shared phrase$")
def _h_concrete_match(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return (
        world.loss_gates_concrete_shared == ["unintended payment"],
        f"expected the concrete shared phrase, got {world.loss_gates_concrete_shared}",
    )


@step(r"^a persisted loss analysis that satisfies every gate check$")
def _h_dense_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    world.loss_gates_run_dir = Path(_tempfile.mkdtemp(prefix="loss_gates_"))
    world.loss_gates_client = _SP1MockLLM()
    world.loss_gates_gate_error = None
    world.loss_gates_outcome = None
    return True, ""


@step(r"^a persisted loss analysis whose only density problem is a subject mismatch$")
def _h_subject_only_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """A graph whose only density finding is an advisory subject mismatch."""
    del text, examples
    world.loss_gates_run_dir = Path(_tempfile.mkdtemp(prefix="loss_gates_"))
    world.loss_gates_client = _SP1MockLLM()
    world.loss_gates_gate_error = None
    world.loss_gates_outcome = None
    graph = _accounted_analysis_dict()
    graph["security_constraints"][0]["rule"] = (
        "The agent must escalate every regulated topic to a human."
    )
    world.loss_gates_gate_analysis = LossAnalysis.model_validate(graph)
    return True, ""


def _revision_response(**overrides) -> dict:
    """A no-op graph delta for the gapped density fixture.

    Existing hazards and constraints are carried forward by the strict
    revision adapter. Each acceptance fixture overrides only the edit or
    addition collection needed to exercise its gate behavior.
    """
    response = {
        "hazard_edits": [],
        "hazard_additions": [],
        "security_constraint_edits": [],
        "security_constraint_additions": [],
    }
    response.update(overrides)
    return response


def _conditional_gapped_graph_dict() -> dict:
    """The gapped fixture with SC-2 carrying one authored condition."""
    graph = _gapped_graph_dict()
    graph["security_constraints"][1]["applies_when"] = ["the request involves fees"]
    return graph


@step(r"^a persisted loss analysis that fails the density gate$")
def _h_failing_gate_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """A density-failing graph and a fresh mock provider for the gate."""
    del text, examples
    world.loss_gates_run_dir = Path(_tempfile.mkdtemp(prefix="loss_gates_"))
    world.loss_gates_client = _SP1MockLLM()
    world.loss_gates_gate_error = None
    world.loss_gates_outcome = None
    world.loss_gates_failing_analysis = LossAnalysis.model_validate(
        _gapped_graph_dict()
    )
    return True, ""


@step(r"^a persisted loss analysis with conditional SC-2 that fails the density gate$")
def _h_conditional_failing_gate_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """The density-failing graph with SC-2 carrying one authored condition."""
    ok, message = _h_failing_gate_fixture(world, text, examples)
    world.loss_gates_failing_analysis = LossAnalysis.model_validate(
        _conditional_gapped_graph_dict()
    )
    return ok, message


def _uncovered_hazard_graph_dict() -> dict:
    """A graph whose only density failure is the uncovered hazard H-2."""
    return {
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Payment record exposed",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            }
        ],
        "use_case_losses": [],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "The payment record is exposed without authorization.",
                "related_losses": ["L-1"],
            },
            {
                "hazard_id": "H-2",
                "description": "The agent erodes user trust.",
                "related_losses": ["L-1"],
            },
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": (
                    "The payment record must never reach an unauthorized recipient."
                ),
                "behavior_class": "disclosure",
                "related_hazards": ["H-1"],
                "applies_when": [],
            },
        ],
        "risk_dispositions": [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            }
        ],
    }


def _uncovered_hazard_revision() -> dict:
    """A revision patch that adds a new constraint for the named hazard H-2."""
    return {
        "hazard_edits": [],
        "hazard_additions": [],
        "security_constraint_edits": [],
        "security_constraint_additions": [
            {
                "handle": "trust_constraint",
                "rule": "The agent must preserve user trust.",
                "related_hazards": ["H-2"],
                "applies_when": [],
                "obligations": [],
            },
        ],
    }


@step(r"^a persisted loss analysis whose gap adds hazard H-2 without a constraint$")
def _h_uncovered_hazard_gate_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """The graph whose only density failure is the uncovered hazard H-2."""
    ok, message = _h_failing_gate_fixture(world, text, examples)
    world.loss_gates_failing_analysis = LossAnalysis.model_validate(
        _uncovered_hazard_graph_dict()
    )
    return ok, message


@step(
    r"^the loss-analysis gate runs against a mock provider that "
    r"(?:deletes a prior hazard|rewrites that rule|changes those conditions|covers that hazard|changes nothing)$"
)
def _h_run_failing_gate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Queue the mock revision patch named by the step, then run the gate."""
    del examples
    if "deletes a prior hazard" in text:
        # Deletion is outside the current delta contract. Keep this malformed
        # field so the strict parser proves omission preserves records and an
        # explicit deletion attempt fails closed.
        revision = _revision_response(hazard_deletions=["H-1"])
    elif "rewrites that rule" in text:
        # The patch rewrites SC-2's rule and re-points it to a hazard the
        # prior graph never assigned to it.
        revision = _revision_response(
            security_constraint_edits=[
                {
                    "constraint_id": "SC-2",
                    "rule": "The agent must never improvise fee amounts.",
                    "applies_when": ["the request involves fees"],
                    "related_hazards": ["H-1"],
                    "obligations": [],
                }
            ]
        )
    elif "changes those conditions" in text:
        # The patch keeps SC-2's rule and drops its condition.
        revision = _revision_response(
            security_constraint_edits=[
                {
                    "constraint_id": "SC-2",
                    "rule": "The payment record must stay protected.",
                    "applies_when": [],
                    "related_hazards": ["H-2"],
                    "obligations": [],
                }
            ]
        )
    elif "covers that hazard" in text:
        revision = _uncovered_hazard_revision()
    else:
        revision = _revision_response()
    responses = [revision]
    if "covers that hazard" not in text:
        # An invalid response earns one correction call, and a valid response
        # that still fails earns one more revision round; the provider repeats
        # its response there, so the gate still fails closed.
        responses.append(revision)
    world.loss_gates_client.set_response_queue(responses)
    try:
        world.loss_gates_outcome = gate_loss_analysis(
            llm_client=world.loss_gates_client,
            loss_analysis=world.loss_gates_failing_analysis,
            use_case_text=(
                "A service receives a request and records its processing result."
            ),
            risk_cards=_risk_cards()[:1],
            run_dir=world.loss_gates_run_dir,
            template_loader=TemplateLoader(PROMPTS_DIR),
            temperature=0.4,
        )
    except Exception as exc:
        world.loss_gates_gate_error = exc
        world.validation_error = exc
    return True, ""


@step(r"^the gate stops with the revision failure recorded as a stage error$")
def _h_gate_stops_with_revision_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    error = world.loss_gates_gate_error
    return (
        error is not None
        and "hazard_deletions" in str(error)
        and "Extra inputs are not permitted" in str(error),
        f"expected the explicit-deletion revision failure, got {error}",
    )


@step(r"^the gates artifact records the changed conditions as a normalization warning$")
def _h_artifact_records_changed_conditions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    artifact_path = world.loss_gates_run_dir / GATES_ARTIFACT
    if not artifact_path.is_file():
        return False, f"{GATES_ARTIFACT} was not written"
    artifact = _gd_yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
    warnings = artifact.get("normalization_warnings", [])
    return (
        any(
            "changed the applies_when conditions of constraint SC-2" in warning
            and "['the request involves fees']" in warning
            and "-> []" in warning
            for warning in warnings
        ),
        f"artifact does not record the changed conditions: {warnings}",
    )


@step(r"^the gate stops with the still-failing checks recorded as a stage error$")
def _h_gate_stops_with_still_failing(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    error = world.loss_gates_gate_error
    error_text = str(error)
    conditional = any(
        constraint.constraint_id == "SC-2" and constraint.applies_when
        for constraint in world.loss_gates_failing_analysis.security_constraints
    )
    expected_check = (
        "hazard H-3 has no constraint"
        if conditional
        else "constraint SC-2 has no hazard"
    )
    return (
        error is not None
        and "revision still failing" in error_text
        and expected_check in error_text,
        f"expected the exact still-failing checks, got {error}",
    )


@step(r"^the revision call received \"([^\"]+)\" as a failed check$")
def _h_revision_call_named_check(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    expected = _gd_re.findall(r'"([^"]+)"', text)[0]
    calls_path = world.loss_gates_run_dir / "calls.jsonl"
    if not calls_path.is_file():
        return False, "calls.jsonl was not written"
    calls = [
        json.loads(line) for line in calls_path.read_text(encoding="utf-8").splitlines()
    ]
    prompts = [
        call["user_prompt_text"]
        for call in calls
        if call.get("step") == "hazard_graph_revision"
    ]
    return (
        any(expected in prompt for prompt in prompts),
        f"no revision call received the failing check {expected!r}",
    )


@step(r"^the gate stops with the rewritten rule recorded as a stage error$")
def _h_gate_stops_with_rewritten_rule(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    error = world.loss_gates_gate_error
    return (
        error is not None
        and "hazard graph density gate failed" in str(error)
        and "revision still failing" in str(error),
        f"expected the still-failing gate stop, got {error}",
    )


@step(r"^the gates artifact records the rewritten rule as a normalization warning$")
def _h_artifact_records_rule_reassignment(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    artifact_path = world.loss_gates_run_dir / GATES_ARTIFACT
    if not artifact_path.is_file():
        return False, f"{GATES_ARTIFACT} was not written"
    artifact = _gd_yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
    warnings = artifact.get("normalization_warnings", [])
    return (
        any(
            "changed the rule of constraint SC-2 and re-pointed it to hazards "
            "['H-1'] sharing none of its prior hazards []" in warning
            for warning in warnings
        ),
        f"artifact does not record the rewritten rule: {warnings}",
    )


@step(r"^the gates artifact records the gate as passed after the revision$")
def _h_gate_passes_after_revision(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    artifact_path = world.loss_gates_run_dir / GATES_ARTIFACT
    if not artifact_path.is_file():
        return False, f"{GATES_ARTIFACT} was not written"
    artifact = _gd_yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
    return (
        artifact["revision_attempted"] is True
        and artifact["revision_applied"] is True
        and artifact["passed"] is True,
        f"artifact does not record a passed revision: {artifact}",
    )


@step(r"^the gates artifact records the attempted revision as not applied$")
def _h_artifact_revision_not_applied(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    artifact_path = world.loss_gates_run_dir / GATES_ARTIFACT
    if not artifact_path.is_file():
        return False, f"{GATES_ARTIFACT} was not written"
    artifact = _gd_yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
    return (
        artifact["revision_attempted"] is True
        and artifact["revision_applied"] is False
        and artifact["passed"] is False,
        f"artifact does not record a failed attempted revision: {artifact}",
    )


@step(r"^the gates artifact records (\d+) revision rounds$")
def _h_artifact_revision_rounds(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del examples
    expected = int(_gd_re.findall(r"records (\d+) revision rounds", text)[0])
    artifact_path = world.loss_gates_run_dir / GATES_ARTIFACT
    if not artifact_path.is_file():
        return False, f"{GATES_ARTIFACT} was not written"
    artifact = _gd_yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
    rounds = artifact.get("revision_rounds", [])
    return (
        [entry["round"] for entry in rounds] == list(range(1, expected + 1)),
        f"expected {expected} revision rounds, got {rounds}",
    )


@step(r"^the gates artifact retains the original failing checks$")
def _h_artifact_retains_original_checks(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    artifact_path = world.loss_gates_run_dir / GATES_ARTIFACT
    artifact = _gd_yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
    return (
        any(
            "behavior class wrong_information has no hazard of its own" in check
            for check in artifact["failing_checks"]
        ),
        f"original failing checks were not retained: {artifact['failing_checks']}",
    )


@step(r"^the loss-analysis gate runs against a mock provider$")
def _h_run_gate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    try:
        world.loss_gates_outcome = gate_loss_analysis(
            llm_client=world.loss_gates_client,
            loss_analysis=getattr(
                world,
                "loss_gates_gate_analysis",
                LossAnalysis.model_validate(_accounted_analysis_dict()),
            ),
            use_case_text=(
                "A service receives a request and records its processing result."
            ),
            risk_cards=_risk_cards()[:1],
            run_dir=world.loss_gates_run_dir,
            template_loader=TemplateLoader(PROMPTS_DIR),
            temperature=0.4,
        )
    except Exception as exc:
        world.validation_error = exc
    return True, ""


@step(r"^the gates artifact records the gate as passed with no revision$")
def _h_artifact_passed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    artifact_path = world.loss_gates_run_dir / GATES_ARTIFACT
    if not artifact_path.is_file():
        return False, f"{GATES_ARTIFACT} was not written"
    artifact = _gd_yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
    return (
        artifact["passed"] is True and artifact["revision_attempted"] is False,
        f"artifact does not record a passed gate without revision: {artifact}",
    )


@step(r"^the gates artifact records the gate as passed with the advisory check$")
def _h_artifact_advisory(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    artifact_path = world.loss_gates_run_dir / GATES_ARTIFACT
    if not artifact_path.is_file():
        return False, f"{GATES_ARTIFACT} was not written"
    artifact = _gd_yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
    expected = "constraint SC-1 and hazard H-1 share no subject phrase"
    return (
        artifact["passed"] is True
        and artifact["failing_checks"] == []
        and artifact["advisory_checks"] == [expected],
        f"artifact does not record the advisory check: {artifact}",
    )


@step(r"^the gate makes no provider call$")
def _h_no_provider_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return (
        not world.loss_gates_client.calls,
        f"the gate made provider calls: {world.loss_gates_client.calls}",
    )


@step(r"^the gate returns the unchanged analysis$")
def _h_unchanged_analysis(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    outcome = world.loss_gates_outcome
    if outcome is None:
        return False, f"the gate failed: {world.validation_error}"
    unchanged = outcome.loss_analysis == LossAnalysis.model_validate(
        _accounted_analysis_dict()
    )
    return (
        outcome.passed and not outcome.revision_attempted and unchanged,
        f"expected a passed unchanged analysis, got passed={outcome.passed}, "
        f"revision_attempted={outcome.revision_attempted}, unchanged={unchanged}",
    )


register = step.register


__all__ = ["FEATURE_ID", "register"]

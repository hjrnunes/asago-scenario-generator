"""Regression tests for Stage 5 access-evidence grounding.

These tests exercise the typed Stage 5/Stage 6 seams.  A structural causal
condition is not an attacker access path, and an access claim must resolve to
the exact capability and path retained in the immutable scenario context.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionDeliveryClass,
    RequestedEnvironmentBasis,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
)
from asago_scenario_generator.stpa.models.scenario_spec import AttackerBDI
from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionValueCondition,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioObligationConsideration,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    UnsafeOutcomeDeclaration,
    assemble_scenario_spec,
    populate_defender_bdi,
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from tests.stpa.test_sp3_scenario_continuity import (
    _control_structure,
    _contextual_spec,
    _loss_analysis,
    _threat,
)


_PROMPT_REGRESSION_FIXTURE = (
    Path(__file__).parents[1] / "fixtures" / "stpa-prompt-contract-regressions.yaml"
)


def _empty_reachability_context():
    return build_scenario_generation_context(
        _threat(),
        _control_structure(),
        _loss_analysis(),
        scenario_id="SCN-001",
    )


def _direct_execution_contract() -> SemanticExecutionContract:
    """Return the explicit target-agnostic route used by legacy test calls."""
    return SemanticExecutionContract(
        requested_environment_basis=RequestedEnvironmentBasis.target_agnostic,
        delivery=SemanticExecutionDelivery(
            delivery_class=ExecutionDeliveryClass.direct_prompt,
            factor_id="CF-1",
            source_role="direct_user_input",
        ),
        action_kind=ExecutionActionKind.model_output,
    )


def _stage5_result(factor: CausalFactorDeclaration) -> BDIGenerationResult:
    return BDIGenerationResult(
        defender_vulnerabilities={"PM-1-1": "The action count can be stale."},
        attacker_bdi=AttackerBDI(
            beliefs=["The action count can be stale."],
            desires=["Induce the selected ICA."],
            intentions=["Use the selected structural condition."],
        ),
        causal_factors=[factor],
        unsafe_outcome=UnsafeOutcomeDeclaration(
            condition=ActionValueCondition(
                control_action_id="CA-1-1",
                property="semantic_proposition",
                operator="equals",
                expected=True,
            ),
            semantic_proposition="The response exhibits the selected unsafe action.",
        ),
        execution_contract=_direct_execution_contract(),
    )


def test_empty_reachability_rejects_invented_feedback_access() -> None:
    """An empty capability view cannot support a reachable-capability factor."""
    context = _empty_reachability_context()
    captured = yaml.safe_load(_PROMPT_REGRESSION_FIXTURE.read_text(encoding="utf-8"))[
        "empty_reachability_feedback_manipulation"
    ]
    assert captured["source_run"].endswith(
        "output/runs/20260901-synthesis-nhs-prompt-contract-v3"
    )
    assert captured["reachable_capabilities"] == []
    assert "manipulate" in captured["captured_stage5"]["attacker_intention"].lower()
    captured_factor = captured["captured_stage5"]["causal_factor"]
    factor = CausalFactorDeclaration(
        kind=CausalFactorKind.process_model_flaw,
        source_id=captured_factor["source_id"],
        evidence=captured_factor["evidence"],
        evidence_status="reachable_capability",
        capability_refs=[captured_factor["capability_ref"]],
        access_refs=[captured_factor["access_ref"]],
    )

    with pytest.raises(ValueError, match="capability"):
        assemble_scenario_spec(
            populate_defender_bdi(_control_structure(), "RESP-1"),
            _stage5_result(factor),
            _threat(),
            _control_structure(),
            scenario_context=context,
        )


def test_reachable_capability_requires_exact_access_path() -> None:
    """Capability and access references resolve to one context record/path."""
    context = _contextual_spec().scenario_context
    assert context is not None
    factor = CausalFactorDeclaration(
        kind=CausalFactorKind.feedback_delay,
        source_id="FB-1-1",
        evidence="The reachable payment surface can deliver a late count update.",
        evidence_status="reachable_capability",
        capability_refs=["CAP-PAYMENT"],
        access_refs=["not-in-the-pinned-path"],
    )

    with pytest.raises(ValueError, match="access"):
        assemble_scenario_spec(
            populate_defender_bdi(_control_structure(), "RESP-1"),
            _stage5_result(factor),
            _threat(),
            _control_structure(),
            scenario_context=context,
        )


def test_bounded_assumption_is_retained_without_capability_claim() -> None:
    """An uncertain access path is explicit and cannot masquerade as evidence."""
    context = _empty_reachability_context()
    factor = CausalFactorDeclaration(
        kind=CausalFactorKind.process_model_flaw,
        source_id="PM-1-1",
        evidence="The selected process-model state may remain stale.",
        evidence_status="bounded_assumption",
        bounded_assumption="Assume the scheduled update arrives after authorization.",
    )

    spec = assemble_scenario_spec(
        populate_defender_bdi(_control_structure(), "RESP-1"),
        _stage5_result(factor),
        _threat(),
        _control_structure(),
        scenario_context=context,
    )

    assert spec.causal_factors[0].evidence_status == "bounded_assumption"
    assert (
        spec.causal_factors[0].bounded_assumption
        == "Assume the scheduled update arrives after authorization."
    )


def test_empty_reachability_prompt_allows_structural_condition_without_attack() -> None:
    """Stage 5 does not require active manipulation without access evidence."""
    context = _empty_reachability_context()
    loader = TemplateLoader(PROMPTS_DIR)
    stage5_system, stage5 = build_context_bdi_prompts(context, loader)

    combined = "\n".join((stage5_system, stage5)).lower()
    assert "do not claim" in combined or "do not describe" in combined
    assert "existing structural condition" in combined


def test_stage5_prompt_separates_delivery_from_internal_causal_proof() -> None:
    """A usable test route does not require proof of every internal transition."""
    system_prompt, user_prompt = build_context_bdi_prompts(
        _empty_reachability_context(), TemplateLoader(PROMPTS_DIR)
    )
    prompt = " ".join(f"{system_prompt}\n{user_prompt}".split()).lower()

    assert "`stimulus` is a request-local description of the actual delivery" in prompt
    assert "does not prove attacker access" in prompt
    assert "direct_prompt" in prompt
    assert "conversation_context" in prompt
    assert "missing endpoints" in prompt
    assert "make a known route parameterized, not analytical" in prompt


def test_stage5_prompt_keeps_unproved_carriers_out_of_pm_direct_routes() -> None:
    """Grounded PM flaws may use direct input without inventing retrieval access."""
    system_prompt, _user_prompt = build_context_bdi_prompts(
        _empty_reachability_context(), TemplateLoader(PROMPTS_DIR)
    )
    prompt = " ".join(system_prompt.split()).lower()

    assert "separate causal-source selection from delivery selection" in prompt
    assert (
        "when that process-model flaw is the evidence-backed explanation and no "
        "exact attacker-influenced retrieval or tool delivery is supplied"
    ) in prompt
    assert "use a `user_message` (which code maps to `direct_prompt`)" in prompt
    assert (
        "a rag/retrieval label, tool-inventory name, or adversarial wording alone"
        in prompt
    )
    assert (
        "if only a feedback sensor anomaly is supported, keep its indirect route"
        in prompt
    )


def test_stage5_prompt_contains_only_actionable_context_and_defines_references() -> (
    None
):
    """Provider context omits integrity bookkeeping and explains copied IDs."""
    context = _empty_reachability_context()
    system_prompt, user_prompt = build_context_bdi_prompts(
        context, TemplateLoader(PROMPTS_DIR)
    )
    prompt = f"{system_prompt}\n{user_prompt}"
    normalized_prompt = " ".join(prompt.split())

    assert context.context_digest not in prompt
    assert context.scenario_identity.scenario_id not in prompt
    assert context.scenario_identity.ica_id not in prompt
    assert context.target_control_path.process_model_parts[0].element_id not in prompt
    assert context.target_control_path.feedback[0].element_id not in prompt
    assert "source_pins:" not in prompt
    assert "catalog_context:" not in prompt
    assert "Do not return hazard, constraint, or loss IDs" in normalized_prompt
    assert "Use the selected target action in action conditions" in normalized_prompt
    assert "Select only when timing, lateness, staleness" in normalized_prompt
    assert (
        "The feedback itself misreports a known fact through an explained"
        in normalized_prompt
    )


def test_obligation_mechanism_is_provenance_not_causal_evidence() -> None:
    """A taxonomy finding selects the ICA but cannot establish its attack story."""
    threat = _threat()
    context = build_scenario_generation_context(
        threat,
        _control_structure(),
        _loss_analysis(),
        scenario_id="SCN-001",
        obligation_considerations=(
            ScenarioObligationConsideration(
                obligation_id="ob:v1:" + "a" * 64,
                attack_pattern_id="AP-T2-04",
                attack_pattern_name="Poisoned persistent memory",
                concise_concern=(
                    "An adversary poisons persistent memory so later decisions use "
                    "attacker-controlled state."
                ),
                disposition="finding",
                rationale=(
                    "The selected ICA is a system-specific unsafe-control path "
                    "related to the concern."
                ),
                finding_ica_id=threat.ica_id,
            ),
        ),
    )
    loader = TemplateLoader(PROMPTS_DIR)
    stage5_system, stage5_user = build_context_bdi_prompts(context, loader)

    assert "analysis provenance, not causal evidence" in " ".join(stage5_user.split())
    assert "explain why STPA considered this unsafe action" in " ".join(
        stage5_user.split()
    )
    assert "A mechanism needs exact supplied capability/access evidence" in " ".join(
        stage5_system.split()
    )

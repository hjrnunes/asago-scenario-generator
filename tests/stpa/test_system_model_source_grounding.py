"""Prompt regressions for source-grounded Stage 1 and Stage 2 analysis."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR


_LOADER = TemplateLoader(PROMPTS_DIR)


def _render(template_name: str, **kwargs: object) -> str:
    """Render a production prompt and normalize wrapping for phrase checks."""
    return " ".join(_LOADER.render_prompt(template_name, **kwargs).split())


@pytest.mark.parametrize(
    "template_name",
    ("stage1a_risk_system.j2", "stage1a_gap_system.j2"),
)
def test_loss_analysis_render_preserves_conditions_and_hazard_boundaries(
    template_name: str,
) -> None:
    """Loss-analysis prompts keep permissions separate from attack narratives."""
    rendered = _render(template_name)

    assert (
        "A stated permission, authorization, or conditional exception remains "
        "part of the behavior being analyzed."
    ) in rendered
    assert "A hazardous state is not evidence that an attacker reached it" in rendered


@pytest.mark.parametrize(
    "template_name",
    (
        "stage1a_risk_system.j2",
        "stage1a_risk_user.j2",
        "stage1a_gap_system.j2",
        "stage1a_gap_user.j2",
    ),
)
def test_stage1a_includes_systemic_findings_before_causal_feasibility(
    template_name: str,
) -> None:
    """Stage 1a does not make an attack path a prerequisite for inclusion."""
    rendered = _render(
        template_name,
        use_case_text="A records service retrieves authorized account records.",
        risk_cards=[],
        existing_losses=[],
        existing_hazards=[],
        existing_constraints=[],
        next_loss_num=1,
        next_hazard_num=1,
        next_sc_num=1,
        kc_subcodes=[],
    )

    assert (
        "Do not require an adversary, entry point, or concrete attack path for inclusion"
        in rendered
    )
    assert "adversarial relevance" in rendered.lower()
    assert "Focus on adversary-actionable threats" not in rendered
    assert "Omit operational risks with no adversarial vector" not in rendered


def test_loss_analysis_method_distinguishes_authorized_retrieval_from_boundary_hazard() -> (
    None
):
    rendered = _render("stage1a_risk_system.j2")

    assert "authorized account-record lookup is likewise not itself a loss" in rendered
    assert "recipient not authorized by the request" in rendered
    assert "preserve the authorized recipient and quantity" in rendered
    assert "a later causal question" in rendered


@pytest.mark.parametrize(
    "template_name",
    ("stage1a_risk_system.j2", "stage1a_gap_system.j2"),
)
def test_stage1a_constraints_preserve_permitted_action_effect_relationships(
    template_name: str,
) -> None:
    rendered = _render(template_name)

    assert (
        "Treat source-stated authenticated or otherwise authorized operations"
        in rendered
    )
    assert (
        "safe relationship among the source-established action, authorization or request, "
        "and intended effect"
    ) in rendered
    assert (
        "Do not blanket-ban a permitted function or invent a secondary verifier"
        in rendered
    )
    assert "preserve a supplied human-review trigger" in rendered
    assert rendered.count("Express each constraint as the safe relationship") == 1


def test_loss_analysis_method_uses_neutral_dispatch_and_sensitive_processing_example() -> (
    None
):
    rendered = _render("stage1a_risk_system.j2")

    assert "For a warehouse dispatch service" in rendered
    assert "dispatches the wrong quantity" in rendered
    assert "recipient not authorized by the request" in rendered
    assert "preserve the authorized recipient and quantity" in rendered
    assert (
        "An authorized account-record lookup is likewise not itself a loss" in rendered
    )
    assert "secondary review step" in rendered
    assert "Klarna" not in rendered


def test_responsibility_prompt_separates_functions_from_installed_safeguards() -> None:
    rendered = _render("stage2_call2a_system.j2")

    assert "Keep source-named functions distinct" in rendered
    assert (
        "only when the use-case or typed factual context explicitly establishes "
        "a separate function"
    ) in rendered
    assert (
        "treat a reviewer as a design recommendation, not a new installed element"
        in rendered
    )
    assert (
        "A security constraint is an obligation on a function, not evidence of "
        "an installed controller"
    ) in rendered
    assert "score, threshold, approval stage, or separate tool" in rendered


def test_control_element_prompt_preserves_authorized_actions_and_external_scope() -> (
    None
):
    rendered = _render("stage2_call2b_system.j2")

    assert (
        "An operation allowed only in an authenticated or reviewed state must "
        "retain that condition"
    ) in rendered
    assert "Keep distinct source-named functions and operations distinct" in rendered
    assert (
        "Declare a controlled process only when the source establishes the "
        "external entity or interface"
    ) in rendered


def test_stage2_user_prompts_do_not_launder_proposed_safeguards_as_structure() -> None:
    call2a = _render(
        "stage2_call2a_user.j2",
        use_case_text="A neutral assistant returns status information.",
        requirements=[],
        capability_profile=None,
    )
    call2b = _render(
        "stage2_call2b_user.j2",
        use_case_text="A neutral assistant returns status information.",
        responsibilities=[],
    )

    assert "explicitly establishes that safeguard as a distinct function" in call2a
    assert "retain it as a design recommendation on the established function" in call2a
    assert "separate safeguard operation explicitly established" in call2b
    assert "does not establish an installed safeguard action" in call2b


def test_semantic_review_prompt_does_not_turn_constraints_into_evidence() -> None:
    rendered = _render("stage2_call3_system.j2")

    assert (
        "a security constraint describes an obligation, not evidence of an "
        "installed controller"
    ) in rendered
    assert "Preserve source-stated authorization and conditional exceptions" in rendered
    assert "Keep distinct source-named functions distinct" in rendered


def test_critic_prompt_requires_evidence_bounded_attack_paths() -> None:
    rendered = _render("critic_system.j2", taxonomy_probes=[])

    assert (
        "An explicit requirement may still justify a proposed missing safeguard"
        in rendered
    )
    assert "Report source/function omissions as structural gaps" in rendered
    assert "a recommendation is not an observed installed capability" in rendered
    assert (
        "An attack path requires supplied attacker access and the relevant "
        "operation or state"
    ) in rendered
    assert "Do not infer a recipient, mechanism, or misuse from hazard" in rendered


def test_revision_prompt_distinguishes_known_gaps_from_new_safeguards() -> None:
    control_structure = SimpleNamespace(
        responsibilities=[],
        controlled_processes=[],
        coordination_links=[],
    )
    rendered = _render(
        "revision_system.j2",
        control_structure=control_structure,
        next_resp_num=1,
        next_pm_num=1,
        next_ca_num=1,
        next_fb_num=1,
        next_cl_num=1,
        next_cm_num=1,
        next_cp_num=1,
    )

    assert (
        'Do not turn an "only when" condition into an unconditional denial' in rendered
    )
    assert (
        "Keep a critic's proposed safeguard in the dismissed-gaps rationale unless "
        "the source establishes the omitted function"
    ) in rendered
    assert (
        "Use the new/modified delta only for a source-established omitted function"
        in rendered
    )
    assert (
        "Treat the Existing Control Structure section as current-state evidence"
        in rendered
    )
    assert (
        "Do not copy a critic's recommendation into that diagram as if it were observed"
        in rendered
    )

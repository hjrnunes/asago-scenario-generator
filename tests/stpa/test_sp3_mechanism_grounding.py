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
from asago_scenario_generator.stpa.models.scenario_spec import AttackerBDI
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    assemble_scenario_spec,
    populate_defender_bdi,
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.narrative import (
    build_narrative_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
    build_attack_tree_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.gherkin import (
    build_gherkin_prompts,
    find_security_constraint,
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


def _stage5_result(factor: CausalFactorDeclaration) -> BDIGenerationResult:
    return BDIGenerationResult(
        defender_vulnerabilities={"PM-1-1": "The action count can be stale."},
        attacker_bdi=AttackerBDI(
            beliefs=["The action count can be stale."],
            desires=["Induce the selected ICA."],
            intentions=["Use the selected structural condition."],
        ),
        causal_factors=[factor],
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
    """Stage 5 and Stage 6 do not require active manipulation without access evidence."""
    context = _empty_reachability_context()
    loader = TemplateLoader(PROMPTS_DIR)
    _stage5_system, stage5 = build_context_bdi_prompts(context, loader)
    empty_spec = _contextual_spec().model_copy(update={"scenario_context": context})
    narrative_system, narrative_user = build_narrative_prompts(empty_spec, loader)
    tree_system, tree_user = build_attack_tree_prompts(
        empty_spec, _control_structure(), loader
    )
    constraint = find_security_constraint(empty_spec, _loss_analysis())
    gherkin_system, gherkin_user = build_gherkin_prompts(
        empty_spec, constraint, _loss_analysis(), loader
    )

    combined = "\n".join(
        (
            stage5,
            narrative_system,
            narrative_user,
            tree_system,
            tree_user,
            gherkin_system,
            gherkin_user,
        )
    ).lower()
    assert "no reachable capabilities" in combined
    assert "do not claim" in combined or "do not describe" in combined
    assert "existing structural condition" in combined

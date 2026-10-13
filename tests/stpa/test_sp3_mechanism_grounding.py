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
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.stage5.sources import (
    _causal_source_choices,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from tests.helpers.sp3_scenario_continuity import (
    _control_structure,
    _contextual_spec,
    _loss_analysis,
    _threat,
)
from tests.helpers.stage5_assembly import stage5_assembly
from tests.helpers.stage5_compile import compile_draft, draft_payload, factor, handle_of


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


def _compile(context, kind: CausalFactorKind, source_id: str, **fields):
    """Compile one draft declaring a single factor on ``source_id``."""
    handle = handle_of(_causal_source_choices(context), kind, source_id)
    payload = draft_payload([factor(handle, **fields)])
    return compile_draft(
        payload, context, stage5_assembly(context, _threat(), _control_structure())
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

    with pytest.raises(ValueError, match="capability"):
        _compile(
            context,
            CausalFactorKind.process_model_flaw,
            captured_factor["source_id"],
            evidence=captured_factor["evidence"],
            evidence_status="reachable_capability",
            capability_refs=[captured_factor["capability_ref"]],
            access_refs=[captured_factor["access_ref"]],
        )


def test_reachable_capability_requires_exact_access_path() -> None:
    """Capability and access references resolve to one context record/path."""
    context = _contextual_spec().scenario_context
    assert context is not None

    with pytest.raises(ValueError, match="access"):
        _compile(
            context,
            CausalFactorKind.feedback_delay,
            "FB-1-1",
            evidence="The reachable payment surface can deliver a late count update.",
            evidence_status="reachable_capability",
            capability_refs=["CAP-PAYMENT"],
            access_refs=["not-in-the-pinned-path"],
        )


def test_bounded_assumption_is_retained_without_capability_claim() -> None:
    """An uncertain access path is explicit and cannot masquerade as evidence."""
    context = _empty_reachability_context()

    spec = _compile(
        context,
        CausalFactorKind.process_model_flaw,
        "PM-1-1",
        evidence="The selected process-model state may remain stale.",
        evidence_status="bounded_assumption",
        bounded_assumption="Assume the scheduled update arrives after authorization.",
    )

    assert spec.causal_factors[0].evidence_status == "bounded_assumption"
    assert (
        spec.causal_factors[0].bounded_assumption
        == "Assume the scheduled update arrives after authorization."
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

    assert context.context_digest not in prompt
    assert context.scenario_identity.scenario_id not in prompt
    assert context.scenario_identity.ica_id not in prompt
    assert context.target_control_path.process_model_parts[0].element_id not in prompt
    assert context.target_control_path.feedback[0].element_id not in prompt
    assert "source_pins:" not in prompt
    assert "catalog_context:" not in prompt

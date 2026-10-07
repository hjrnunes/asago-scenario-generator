"""Stage 2 runs one unified, target-blind analysis for every supplied input."""

from __future__ import annotations

from pathlib import Path

import yaml

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    valid_control_element_set_dict,
    valid_empty_coordination_analysis_dict,
    valid_requirement_set_dict,
    valid_responsibility_set_dict,
    valid_loss_analysis_dict,
    setup_sp1_mock_client,
)
from asago_scenario_generator.stpa.infra import llm_helpers as llm_helpers_module
from asago_scenario_generator.stpa.infra.prompt_preflight import PromptBudgetExceeded
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    RequirementSet,
    ResponsibilitySet,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    RevisionDelta,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.run import _run_stage_2_block, run_sp1
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    EnrichedThreatSet,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from tests.helpers.unified_stage2 import _observations, _profile

USE_CASE = (
    "MiniKlarna is a customer-support assistant for a buy-now-pay-later "
    "service. Customers ask about orders, payment plans, refunds, and "
    "policies. The assistant answers with the supplied tools and escalates "
    "regulated topics to a human agent."
)


def _capability_profile(**overrides) -> CapabilityProfile:
    payload = {
        "zones_active": ["input", "reasoning", "tool_execution"],
        "entry_points": [
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", "KC5.1", "KC6.1.1"],
        "tool_inventory": [
            {"name": "lookup_order", "description": "Look up an order"},
            {"name": "process_refund", "description": "Process a refund"},
        ],
    }
    payload.update(overrides)
    return CapabilityProfile.model_validate(payload)


def _stage2_mock_client():
    """Build a mock client wired for the ordinary target-blind Stage 2 calls."""

    client = MockLLMClient()
    client.set_response_for(RequirementSet, valid_requirement_set_dict())
    client.set_response_for(ResponsibilitySet, valid_responsibility_set_dict())
    client.set_response_for(ControlElementSet, valid_control_element_set_dict())
    client.set_response_for(
        CoordinationAnalysis,
        valid_empty_coordination_analysis_dict(
            constraint_ids=("SC-1", "SC-2"), hazard_ids=("H-1", "H-2")
        ),
    )
    client.set_response_for(
        CriticFindings,
        {
            "gaps": [],
            "checklist_results": {},
            "taxonomy_probe_results": {},
        },
    )
    client.set_response_for(
        RevisionDelta,
        {
            "new_responsibilities": [],
            "new_controlled_processes": [],
            "new_coordination_links": [],
            "modified_responsibilities": [],
        },
    )
    return client, TemplateLoader(PROMPTS_DIR)


def _run_unified_stage2(tmp_path: Path, *, capability_profile):

    client, loader = _stage2_mock_client()
    stage_errors: list[str] = []
    stage_warnings: list[str] = []
    result = _run_stage_2_block(
        client,
        USE_CASE,
        LossAnalysis.model_validate(valid_loss_analysis_dict()),
        capability_profile,
        tmp_path,
        loader,
        0.4,
        stage_errors,
        stage_warnings,
    )
    return result, stage_errors, tmp_path


def test_one_unified_stage2_analysis_for_every_supplied_input(tmp_path: Path):
    """The normal path runs one Stage 2 analysis for every supplied input.

    A multi-agent capability profile, a single-agent one, and no profile at
    all run the same target-blind derivation over the same stage-2 wire: the
    derived control structure is identical. No input selects a different
    algorithm.
    """
    reference = None
    for index, capability in enumerate(
        (
            _capability_profile(),
            _capability_profile(kc_subcodes=["KC1.1", "KC2.3"]),
        )
    ):
        run_dir = tmp_path / f"variant-{index}"
        result, stage_errors, _ = _run_unified_stage2(
            run_dir, capability_profile=capability
        )
        assert stage_errors == []
        assert result.control_structure is not None
        if reference is None:
            reference = result.control_structure
        else:
            assert result.control_structure == reference


def _stage_2_block(client, run_dir: Path, *, capability_profile=None):
    return _run_stage_2_block(
        client,
        USE_CASE,
        LossAnalysis.model_validate(valid_loss_analysis_dict()),
        capability_profile,
        run_dir,
        TemplateLoader(PROMPTS_DIR),
        0.4,
        [],
        [],
    )


def test_stage2_call_count_includes_the_critic_request(tmp_path: Path):
    client, _ = _stage2_mock_client()

    result = _stage_2_block(client, tmp_path, capability_profile=_capability_profile())

    # Calls 1, 2a, 2b and 3, then the critic; no gap, so no revision.
    assert len(client.calls) == 5
    assert result.model_call_count == 5


def test_stage2_call_count_includes_a_json_decode_retry(tmp_path: Path):
    client, _ = _stage2_mock_client()
    client.set_response_for(
        RequirementSet, ["not json {", valid_requirement_set_dict()]
    )

    result = _stage_2_block(client, tmp_path, capability_profile=_capability_profile())

    assert len(client.calls) == 6
    assert result.model_call_count == 6


def test_blocked_stage2_records_zero_calls(tmp_path: Path, monkeypatch):
    def blocked(*args, **kwargs):
        raise PromptBudgetExceeded(
            input_tokens=2,
            usable_input_tokens=1,
            context_window=1,
            maximum_completion_tokens=1,
            safety_margin=0,
        )

    monkeypatch.setattr(llm_helpers_module, "_preflight_configured_prompt", blocked)
    client, _ = _stage2_mock_client()
    stage_errors: list[str] = []

    result = _run_stage_2_block(
        client,
        USE_CASE,
        LossAnalysis.model_validate(valid_loss_analysis_dict()),
        _capability_profile(),
        tmp_path,
        TemplateLoader(PROMPTS_DIR),
        0.4,
        stage_errors,
        [],
    )

    assert client.calls == []
    assert result.control_structure is None
    assert stage_errors
    assert result.model_call_count == 0


def test_skipped_stage2_records_zero_calls(tmp_path: Path):
    client, _ = _stage2_mock_client()

    result = _stage_2_block(client, tmp_path, capability_profile=None)

    assert client.calls == []
    assert result.model_call_count == 0


def test_sp1_manifest_stage2_count_matches_the_logged_requests(tmp_path: Path):
    run_sp1(
        llm_client=setup_sp1_mock_client(),
        use_case_text=USE_CASE,
        risk_cards=[],
        run_dir=tmp_path,
    )

    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    logged = [e for e in read_calls_jsonl(tmp_path) if e["stage"] == "stage_2"]
    assert manifest["stage_summary"]["stage_2"]["call_count"] == len(logged)


def test_run_sp1_uses_one_unified_analysis_for_an_observed_target(tmp_path: Path):
    """An observed profile enriches Stage 2; it selects no algorithm mode."""

    result = run_sp1(
        llm_client=setup_sp1_mock_client(),
        use_case_text=USE_CASE,
        risk_cards=[],
        run_dir=tmp_path,
    )
    # The manifest records no algorithm-selecting field.
    assert result.stage_errors == []
    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    stage_2 = manifest["stage_summary"]["stage_2"]
    assert "mode" not in stage_2
    assert stage_2["call_count"] > 0
    steps = [entry["step"] for entry in read_calls_jsonl(tmp_path)]
    assert "target_beliefs" not in steps
    assert "target_relevance" not in steps


def test_run_sp1_then_sp3_publishes_the_handoff_without_the_retired_companion(
    tmp_path: Path,
):
    """The unified run publishes the scenario handoff and no execution bundle."""

    result = run_sp1(
        llm_client=setup_sp1_mock_client(),
        use_case_text=USE_CASE,
        risk_cards=[],
        run_dir=tmp_path,
    )
    assert result.stage_errors == []
    assert result.control_structure is not None
    assert result.loss_analysis is not None
    run_sp3(
        llm_client=MockLLMClient(),
        enriched_threat_set=EnrichedThreatSet(
            structural_threats=[],
            coverage_analysis=CoverageAnalysis(structural_coverage={}),
        ),
        control_structure=result.control_structure,
        loss_analysis=result.loss_analysis,
        run_dir=tmp_path,
        execution_target_profile=_profile(),
        target_observations=_observations(),
    )
    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    assert manifest["stage_errors"] == []
    # The retired observed-target companions are not published on this path.
    assert not (tmp_path / "execution-bundle.json").exists()
    assert not (tmp_path / "scenarios" / "canonical").exists()

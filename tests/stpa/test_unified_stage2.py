"""Stage 2 runs one unified, target-blind analysis for every supplied input."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryProvenance,
    ExecutionTargetProfile,
    ExecutionSurface,
    InventoryAuthority,
    InventoryCompleteness,
    McpInventoryObservation,
    McpToolObservation,
    ProfileBasis,
    SemanticAuthority,
    SourceProtocol,
    TargetProfileOperation,
    TargetProfileResource,
    TargetSemanticInterpretation,
    mcp_resource_id,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    valid_control_element_set_dict,
    valid_empty_coordination_analysis_dict,
    valid_requirement_set_dict,
    valid_responsibility_set_dict,
    valid_loss_analysis_dict,
    read_calls_jsonl,
    setup_sp1_mock_client,
)
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


def _tool(name: str, description: str | None) -> McpToolObservation:
    return McpToolObservation(
        name=name,
        description=description,
        source_observation_sha256="1" * 64,
        input_schema={
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
        },
    )


def _profile(
    *,
    tools=("lookup_order", "process_refund", "escalate_to_human", "retrieve_policy"),
    interpretations=True,
) -> ExecutionTargetProfile:
    observations = tuple(_tool(name, f"Observed {name} tool") for name in tools)
    inventory = McpInventoryObservation(
        target_id="target:mini",
        authorization_scope_id="scope:test",
        tools=observations,
    )
    resources = tuple(
        TargetProfileResource(
            resource_id=mcp_resource_id("target:mini", tool.name),
            target_id="target:mini",
            tool_name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            surfaces=(ExecutionSurface.tool_call, ExecutionSurface.tool_result),
            operations=(
                TargetProfileOperation(
                    operation_id=tool.name,
                    semantic_operation=tool.name,
                    argument_names=("customer_id",),
                ),
            ),
            evidence_refs=(f"inventory:tool:{tool.name}",),
        )
        for tool in observations
    )
    interpretation_rows = ()
    if interpretations:
        interpretation_rows = tuple(
            TargetSemanticInterpretation(
                resource_id=resource.resource_id,
                tool_name=resource.tool_name,
                disposition="supported",
                likely_effect=(
                    "escalate" if resource.tool_name == "escalate_to_human" else "read"
                ),
                likely_state_effect="none",
                semantic_roles=(
                    ("text_search",) if resource.tool_name == "retrieve_policy" else ()
                ),
                evidence_refs=(f"inventory:tool:{resource.tool_name}",),
                rationale="typed test interpretation",
            )
            for resource in resources
        )
    return ExecutionTargetProfile(
        target_id="target:mini",
        authorization_scope_id="scope:test",
        basis=ProfileBasis.target,
        inventory_authority=InventoryAuthority.observed,
        semantic_authority=SemanticAuthority.inferred,
        inventory_completeness=InventoryCompleteness.observed_complete,
        source_protocol=SourceProtocol.mcp,
        source_inventory_digest=inventory.semantic_digest,
        discovery_provenance=DiscoveryProvenance(
            scanner_id="scanner:test",
            interpreter_id="interpreter:test",
            verifier_id="verifier:test",
        ),
        inventory=inventory,
        resources=resources,
        interpretations=interpretation_rows,
    )


def _observations() -> TargetObservationSnapshot:
    state = {"authenticated_customer_id": "CUST001", "orders": {}}
    return TargetObservationSnapshot.create(
        target_profile_digest=_profile().semantic_digest,
        observations=[
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(state),
            )
        ],
    )


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


def test_run_sp1_uses_one_unified_analysis_for_an_observed_target(tmp_path: Path):
    """An observed profile enriches Stage 2; it selects no algorithm mode."""

    result = run_sp1(
        llm_client=setup_sp1_mock_client(),
        use_case_text=USE_CASE,
        risk_cards=[],
        run_dir=tmp_path,
        profile_path=None,
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
        profile_path=None,
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

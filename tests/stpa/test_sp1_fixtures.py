"""SP1 fixture integration tests.

Verifies that the Klarna fixtures can feed into the SP1 pipeline:
  FIX-01: loss_analysis_klarna.yaml feeds Stage 2 and the resulting
          ControlStructure passes structural heuristics.
  FIX-02: control_structure_klarna.yaml runs through the completeness
          critic and produces a valid CriticFindings model.
"""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    run_completeness_critic,
)
from asago_scenario_generator.stpa.system_model.heuristics import run_heuristics
from asago_scenario_generator.models.capability_profile import Stage1Profile
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    valid_empty_coordination_analysis_dict,
    valid_stage1_profile_dict,
    valid_requirement_set_dict,
    valid_control_element_set_dict,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "stpa"


def _valid_resp_set_dict() -> dict:
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Authorization controller",
                "security_constraint_refs": ["SC-1"],
                "responsibility_constraints": [
                    {"rc_id": "RC-1-1", "description": "Must confirm before action"},
                    {"rc_id": "RC-1-2", "description": "Must protect data"},
                    {"rc_id": "RC-1-3", "description": "Must audit actions"},
                ],
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "User intent state"}
                ],
            }
        ],
    }


def _valid_critic_findings_dict() -> dict:
    return {
        "gaps": [],
        "checklist_results": {
            "Input validation": "present",
            "Authorization": "present",
            "Action selection": "present",
            "Outcome verification": "present",
            "Context management": "present",
            "Multi-agent coordination": "absent_justified",
            "Human-in-the-loop": "absent_justified",
        },
        "taxonomy_probe_results": {},
    }


class TestSP1FixtureIntegration:
    """SP1-FIX-01 and SP1-FIX-02: fixture integration with the SP1 pipeline."""

    def test_sp1_fixture_01_loss_analysis_feeds_stage2(self, tmp_path):
        """SP1-FIX-01: loss_analysis_klarna.yaml feeds Stage 2 and CS passes heuristics."""
        la_path = FIXTURES_DIR / "loss_analysis_klarna.yaml"
        loss_analysis = read_yaml(la_path, LossAnalysis)
        assert isinstance(loss_analysis, LossAnalysis)

        client = MockLLMClient()
        client.set_response_for(RequirementSet, valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_resp_set_dict())
        client.set_response_for(ControlElementSet, valid_control_element_set_dict())
        coordination = valid_empty_coordination_analysis_dict(
            constraint_ids=tuple(
                constraint.constraint_id
                for constraint in loss_analysis.security_constraints
            ),
            hazard_ids=tuple(hazard.hazard_id for hazard in loss_analysis.hazards),
        )
        coordination["semantic_review"]["constraints"] = [
            {
                "constraint_id": constraint.constraint_id,
                "disposition": "preserve",
                "revised_description": None,
                "missing_fact": None,
                "related_hazards": list(constraint.related_hazards),
                "source_evidence": [],
                "rationale": "The fixture retains the supplied systemic relation.",
            }
            for constraint in loss_analysis.security_constraints
        ]
        client.set_response_for(CoordinationAnalysis, coordination)

        result = derive_control_structure(
            llm_client=client,
            use_case_text="Klarna payment agent use case",
            loss_analysis=loss_analysis,
            run_dir=tmp_path,
        )
        control_structure = result.control_structure
        assert isinstance(control_structure, ControlStructure)

        # Set security_constraint_refs so hazard tracing can link
        # SC-N IDs from the loss analysis to RESP-1.
        sc_ids = [sc.constraint_id for sc in loss_analysis.security_constraints]
        control_structure.responsibilities[0].security_constraint_refs = sc_ids

        # Verify the control structure passes structural heuristics
        # when checked with the loss analysis
        result = run_heuristics(control_structure, loss_analysis)
        assert result.errors == [], (
            f"Expected no heuristic errors but got: {result.errors}"
        )

    def test_sp1_fixture_02_control_structure_runs_critic(self, tmp_path):
        """SP1-FIX-02: control_structure_klarna.yaml runs through critic."""
        cs_path = FIXTURES_DIR / "control_structure_klarna.yaml"
        control_structure = read_yaml(cs_path, ControlStructure)
        assert isinstance(control_structure, ControlStructure)

        client = MockLLMClient()
        client.set_response_for(CriticFindings, _valid_critic_findings_dict())

        profile = Stage1Profile(**valid_stage1_profile_dict()).to_capability_profile()

        findings = run_completeness_critic(
            llm_client=client,
            control_structure=control_structure,
            capability_profile=profile,
            use_case_text="Klarna payment agent use case",
            run_dir=tmp_path,
        )
        assert isinstance(findings, CriticFindings)
        # CriticFindings is valid (either with gaps or confirming completeness)
        assert hasattr(findings, "gaps")
        assert hasattr(findings, "checklist_results")
        assert hasattr(findings, "taxonomy_probe_results")

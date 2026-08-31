"""Tests for SP1 Stage 2 — Control Structure derivation.

Covers SP1-S2-01 through SP1-S2-15 from the Gherkin feature file.

Stage 2 now has 4 calls:
  Call 1  — Requirements
  Call 2a — Responsibilities + RCs + PM parts
  Call 2b — Control Actions + Feedback Channels + Controlled Processes
  Call 3  — Coordination links + integrity findings
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ReferenceType,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from tests.stpa.sp1_helpers import MockLLMClient


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss 1",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            )
        ],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard 1", related_losses=["L-1"]),
            Hazard(hazard_id="H-2", description="Hazard 2", related_losses=["L-1"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Constraint 1",
                related_hazards=["H-1"],
            ),
            SecurityConstraint(
                constraint_id="SC-2",
                description="Constraint 2",
                related_hazards=["H-2"],
            ),
        ],
    )


def _valid_requirement_set_dict() -> dict:
    return {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Verify user identity before executing payments",
                "classification": "control",
                "source_constraint": "SC-1",
            },
            {
                "req_id": "REQ-2",
                "description": "Must not expose raw payment data",
                "classification": "constraint",
                "source_constraint": "SC-2",
            },
        ]
    }


def _valid_responsibility_set_dict() -> dict:
    """ResponsibilitySet with RCs and PMs only (Call 2a output)."""
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Payment authorization controller",
                "security_constraint_refs": ["SC-1"],
                "responsibility_constraints": [
                    {"rc_id": "RC-1-1", "description": "Must verify user identity"}
                ],
                "process_model_parts": [
                    {
                        "pm_id": "PM-1-1",
                        "description": "User intent and payment request state",
                    }
                ],
            },
            {
                "resp_id": "RESP-2",
                "description": "Output verification controller",
                "security_constraint_refs": ["SC-2"],
                "responsibility_constraints": [],
                "process_model_parts": [
                    {"pm_id": "PM-2-1", "description": "Response content state"}
                ],
            },
        ],
    }


def _valid_control_element_set_dict() -> dict:
    """ControlElementSet with CAs, FBs, and CPs matching the responsibilities (Call 2b output)."""
    return {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Execute payment transaction",
                "target": {"type": "controlled_process", "id": "CP-1"},
            },
            {"ca_id": "CA-2-1", "description": "Send response to user"},
        ],
        "feedback_channels": [
            {
                "fb_id": "FB-1-1",
                "description": "Transaction result",
                "updates": "PM-1-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
            },
            {
                "fb_id": "FB-2-1",
                "description": "Response delivery confirmation",
                "updates": "PM-2-1",
                "source": {"type": "responsibility", "id": "RESP-2"},
            },
        ],
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "Payment transaction system"}
        ],
    }


def _valid_coordination_analysis_dict() -> dict:
    """CoordinationAnalysis with a coordination link (Call 3 output)."""
    return {
        "coordination_links": [
            {
                "link_id": "CL-1",
                "source": "RESP-1",
                "target": "RESP-2",
                "shared_pm": "PM-2-1",
                "coordination_mechanism": {
                    "cm_id": "CM-1",
                    "description": "Shared response state",
                    "payload": "Response content status",
                },
                "description": "Payment controller coordinates with output controller",
            }
        ],
        "integrity_findings": [],
    }


def _valid_control_structure_dict() -> dict:
    """Assembled ControlStructure dict (for reference)."""
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Payment authorization controller",
                "security_constraint_refs": ["SC-1"],
                "responsibility_constraints": [
                    {"rc_id": "RC-1-1", "description": "Must verify user identity"}
                ],
                "process_model_parts": [
                    {
                        "pm_id": "PM-1-1",
                        "description": "User intent and payment request state",
                    }
                ],
                "control_actions": [
                    {
                        "ca_id": "CA-1-1",
                        "description": "Execute payment transaction",
                        "target": {"type": "controlled_process", "id": "CP-1"},
                    }
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "Transaction result",
                        "updates": "PM-1-1",
                        "source": {"type": "controlled_process", "id": "CP-1"},
                    }
                ],
            },
            {
                "resp_id": "RESP-2",
                "description": "Output verification controller",
                "security_constraint_refs": ["SC-2"],
                "responsibility_constraints": [],
                "process_model_parts": [
                    {"pm_id": "PM-2-1", "description": "Response content state"}
                ],
                "control_actions": [
                    {"ca_id": "CA-2-1", "description": "Send response to user"}
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-2-1",
                        "description": "Response delivery confirmation",
                        "updates": "PM-2-1",
                        "source": {"type": "responsibility", "id": "RESP-2"},
                    }
                ],
            },
        ],
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "Payment transaction system"}
        ],
        "coordination_links": [
            {
                "link_id": "CL-1",
                "source": "RESP-1",
                "target": "RESP-2",
                "shared_pm": "PM-2-1",
                "coordination_mechanism": {
                    "cm_id": "CM-1",
                    "description": "Shared response state",
                    "payload": "Response content status",
                },
                "description": "Payment controller coordinates with output controller",
            }
        ],
    }


def _setup_mock_client() -> MockLLMClient:
    """Set up a mock LLM client with valid responses for all four Stage 2 calls."""
    client = MockLLMClient()
    client.set_response_for(RequirementSet, _valid_requirement_set_dict())
    client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
    client.set_response_for(ControlElementSet, _valid_control_element_set_dict())
    client.set_response_for(CoordinationAnalysis, _valid_coordination_analysis_dict())
    return client


class TestRequirementSet:
    """SP1-S2-01 through SP1-S2-04: RequirementSet model and Call 1."""

    def test_s2_01_valid_requirement_set(self):
        """SP1-S2-01: valid RequirementSet with REQ-1 and REQ-2."""
        rs = RequirementSet.model_validate(_valid_requirement_set_dict())
        assert len(rs.requirements) == 2
        for req in rs.requirements:
            assert req.req_id
            assert req.description
            assert req.classification in ("control", "constraint")
            assert req.source_constraint

    def test_s2_02_requirements_classified(self):
        """SP1-S2-02: REQ-1 is control, REQ-2 is constraint."""
        rs = RequirementSet.model_validate(_valid_requirement_set_dict())
        assert rs.requirements[0].classification == "control"
        assert rs.requirements[1].classification == "constraint"

    @pytest.mark.parametrize("bad_class", ["enforcement", "policy"])
    def test_s2_03_invalid_classification_fails(self, bad_class):
        """SP1-S2-03: invalid classification fails."""
        bad = _valid_requirement_set_dict()
        bad["requirements"][0]["classification"] = bad_class
        with pytest.raises((ValidationError, ValueError), match="classification"):
            RequirementSet.model_validate(bad)

    def test_s2_04_source_constraint_references(self):
        """SP1-S2-04: each requirement references a source constraint."""
        rs = RequirementSet.model_validate(_valid_requirement_set_dict())
        assert rs.requirements[0].source_constraint == "SC-1"
        assert rs.requirements[1].source_constraint == "SC-2"


class TestResponsibilitySet:
    """SP1-S2-06 through SP1-S2-08: ResponsibilitySet and ControlElementSet models."""

    def test_s2_06_valid_responsibility_set(self):
        """SP1-S2-06: valid ResponsibilitySet with RESP-1 and RESP-2."""
        rset = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        assert len(rset.responsibilities) == 2
        for resp in rset.responsibilities:
            assert len(resp.process_model_parts) >= 1

    def test_s2_07_controlled_processes_identified(self):
        """SP1-S2-07: controlled process CP-1 is identified in ControlElementSet."""
        ces = ControlElementSet.model_validate(_valid_control_element_set_dict())
        cp_ids = {cp.cp_id for cp in ces.controlled_processes}
        assert "CP-1" in cp_ids

    def test_s2_08_element_refs_are_valid(self):
        """SP1-S2-08: ElementRef references in assembled ControlStructure point to valid IDs."""
        ces = ControlElementSet.model_validate(_valid_control_element_set_dict())
        rset = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        resp_ids = {r.resp_id for r in rset.responsibilities}
        cp_ids = {cp.cp_id for cp in ces.controlled_processes}

        for fb in ces.feedback_channels:
            if fb.source is not None:
                if fb.source.type == ReferenceType.responsibility:
                    assert fb.source.id in resp_ids
                elif fb.source.type == ReferenceType.controlled_process:
                    assert fb.source.id in cp_ids
        for ca in ces.control_actions:
            if ca.target is not None:
                if ca.target.type == ReferenceType.responsibility:
                    assert ca.target.id in resp_ids
                elif ca.target.type == ReferenceType.controlled_process:
                    assert ca.target.id in cp_ids


class TestStage2CallLogging:
    """SP1-S2-05, S2-09, S2-12: call logging for each Stage 2 call."""

    def test_s2_05_call_1_logged(self, tmp_path):
        """SP1-S2-05: Call 1 logged with stage stage_2 and step call_1_requirements."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )

        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        call1 = [e for e in entries if e["step"] == "call_1_requirements"]
        assert len(call1) == 1
        assert call1[0]["stage"] == "stage_2"

    def test_s2_09_call_2a_logged(self, tmp_path):
        """SP1-S2-09: Call 2a logged with stage stage_2 and step call_2a_responsibilities."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )

        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        call2a = [e for e in entries if e["step"] == "call_2a_responsibilities"]
        assert len(call2a) == 1
        assert call2a[0]["stage"] == "stage_2"

    def test_s2_12_call_3_logged(self, tmp_path):
        """SP1-S2-12: Call 3 logged with stage stage_2 and step call_3_coordination."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )

        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        call3 = [e for e in entries if e["step"] == "call_3_coordination"]
        assert len(call3) == 1
        assert call3[0]["stage"] == "stage_2"


class TestStage2Derivation:
    """SP1-S2-10, S2-11, S2-13: Call 3 output and file writing."""

    def test_s2_10_call_3_produces_valid_control_structure(self, tmp_path):
        """SP1-S2-10: Stage 2 produces a valid ControlStructure."""
        client = _setup_mock_client()
        cs, _ = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        assert isinstance(cs, ControlStructure)
        assert len(cs.responsibilities) == 2

    def test_s2_11_coordination_links_identified(self, tmp_path):
        """SP1-S2-11: coordination links are identified in Call 3."""
        client = _setup_mock_client()
        cs, _ = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        assert len(cs.coordination_links) == 1
        cl = cs.coordination_links[0]
        assert cl.link_id == "CL-1"
        assert cl.source == "RESP-1"
        assert cl.target == "RESP-2"

    def test_s2_13_control_structure_written_to_yaml(self, tmp_path):
        """SP1-S2-13: control-structure.yaml exists and contains valid model."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        yaml_file = tmp_path / "control-structure.yaml"
        assert yaml_file.exists()
        loaded = read_yaml(yaml_file, ControlStructure)
        assert isinstance(loaded, ControlStructure)


class TestStage2PromptPassing:
    """SP1-S2-14, S2-15: prompts receive data from previous calls."""

    def test_s2_14_call_2a_receives_requirements_from_call_1(self, tmp_path):
        """SP1-S2-14: Call 2a user prompt contains requirements from Call 1."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        # Call 2a is the second call (index 1)
        call2a = client.calls[1]
        assert "REQ-1" in call2a.user_prompt
        assert "REQ-2" in call2a.user_prompt

    def test_s2_15_call_3_receives_responsibilities_from_call_2(self, tmp_path):
        """SP1-S2-15: Call 3 user prompt contains responsibilities and CPs from Call 2."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        # Call 3 is the fourth call (index 3)
        call3 = client.calls[3]
        assert "RESP-1" in call3.user_prompt
        assert "RESP-2" in call3.user_prompt
        assert "CP-1" in call3.user_prompt

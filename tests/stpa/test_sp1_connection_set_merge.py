"""Unit tests for SP1 Stage 2 Call 3 CoordinationAnalysis and assembly.

Covers the coordination-link and controlled-process behavior that
replaced the old ConnectionSet merge (ConnSet-01 through ConnSet-11).

Stage 2 now has 4 calls:
  Call 1  — Requirements
  Call 2a — Responsibilities + RCs + PM parts
  Call 2b — Control Actions + Feedback Channels + Controlled Processes
  Call 3  — Coordination links + integrity findings
"""

from __future__ import annotations

import json


from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
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
    _CoordinationProviderEnvelope,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    run_revision,
    RevisionDelta,
)
from tests.stpa.sp1_helpers import MockLLMClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"]),
        ],
        security_constraints=[
            SecurityConstraint(constraint_id="SC-1", rule="C", related_hazards=["H-1"]),
            SecurityConstraint(
                constraint_id="SC-2", rule="C2", related_hazards=["H-1"]
            ),
        ],
    )


def _valid_requirement_set_dict() -> dict:
    return {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Verify user identity",
                "classification": "control",
                "source_constraint": "SC-1",
            },
            {
                "req_id": "REQ-2",
                "description": "Must not expose data",
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
                    {"pm_id": "PM-1-1", "description": "User intent state"}
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
    """ControlElementSet with CAs, FBs, and CPs (Call 2b output)."""
    return {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Execute payment",
                "target": {"type": "controlled_process", "id": "CP-1"},
            },
            {
                "ca_id": "CA-2-1",
                "description": "Send response",
                "target": {"type": "responsibility", "id": "RESP-2"},
            },
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
                "description": "Response confirmation",
                "updates": "PM-2-1",
                "source": {"type": "responsibility", "id": "RESP-2"},
            },
        ],
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "Payment transaction system"}
        ],
    }


def _valid_coordination_analysis_dict() -> dict:
    """Current Call 3 semantic response; code supplies integrity findings."""
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
        "semantic_review": {
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "source_evidence": [],
                    "rationale": "The supplied hazard is retained.",
                }
            ],
            "constraints": [
                {
                    "constraint_id": "SC-1",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "related_hazards": ["H-1"],
                    "source_evidence": [],
                    "rationale": "Authorization rule applies to the supplied hazard.",
                },
                {
                    "constraint_id": "SC-2",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "related_hazards": ["H-1"],
                    "source_evidence": [],
                    "rationale": "Output rule applies to the supplied hazard.",
                },
            ],
            "responsibilities": [
                {
                    "responsibility_id": "RESP-1",
                    "constraint_refs": ["SC-1"],
                    "rationale": "Authorization rule.",
                },
                {
                    "responsibility_id": "RESP-2",
                    "constraint_refs": ["SC-2"],
                    "rationale": "Output rule.",
                },
            ],
            "actions": [
                {
                    "control_action_id": "CA-1-1",
                    "effect_kind": "tool_call",
                    "rationale": "Invokes the controlled process.",
                },
                {
                    "control_action_id": "CA-2-1",
                    "effect_kind": "agent_message",
                    "rationale": "Targets a responsibility.",
                },
            ],
        },
    }


def _setup_mock_client() -> MockLLMClient:
    """Set up a mock LLM client with valid responses for all four Stage 2 calls."""
    client = MockLLMClient()
    client.set_response_for(RequirementSet, _valid_requirement_set_dict())
    client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
    client.set_response_for(ControlElementSet, _valid_control_element_set_dict())
    client.set_response_for(
        _CoordinationProviderEnvelope, _valid_coordination_analysis_dict()
    )
    return client


# ---------------------------------------------------------------------------
# ConnSet-01: Call 3 produces a CoordinationAnalysis
# ---------------------------------------------------------------------------


class TestConnSet01Call3ProducesCoordinationAnalysis:
    """ConnSet-01: Call 3 produces a CoordinationAnalysis (not ControlStructure)."""

    def test_connset_01_call_3_response_format_is_coordination_analysis(self, tmp_path):
        """Call 3's provider schema excludes code-owned integrity findings."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        # Call 3 is the fourth call (index 3)
        call3 = client.calls[3]
        assert issubclass(call3.response_format, _CoordinationProviderEnvelope)
        assert set(call3.response_format.model_fields) == {
            "coordination_links",
            "semantic_review",
        }


# ---------------------------------------------------------------------------
# ConnSet-02: CoordinationAnalysis and ControlElementSet contain expected outputs
# ---------------------------------------------------------------------------


class TestConnSet02Contents:
    """ConnSet-02: CoordinationAnalysis has CL-1; ControlElementSet has CP-1."""

    def test_connset_02_contains_coordination_links_and_cps(self, tmp_path):
        """CoordinationAnalysis has CL-1, ControlElementSet has CP-1, FB-1-1 has source."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        cs = read_yaml(tmp_path / "control-structure.yaml", ControlStructure)
        # Coordination link CL-1 present
        cl_ids = {cl.link_id for cl in cs.coordination_links}
        assert "CL-1" in cl_ids
        # Controlled process CP-1 present
        cp_ids = {cp.cp_id for cp in cs.controlled_processes}
        assert "CP-1" in cp_ids
        # FB-1-1 has source set (from ControlElementSet)
        for resp in cs.responsibilities:
            for fb in resp.feedback_channels:
                if fb.fb_id == "FB-1-1":
                    assert fb.source is not None
                    assert fb.source.id == "CP-1"


# ---------------------------------------------------------------------------
# ConnSet-03: assembly produces a valid ControlStructure
# ---------------------------------------------------------------------------


class TestConnSet03AssemblyProducesValidControlStructure:
    """ConnSet-03: assembly produces a valid ControlStructure."""

    def test_connset_03_assembly_produces_valid_control_structure(self, tmp_path):
        """Full Stage 2 derivation produces a valid ControlStructure."""
        client = _setup_mock_client()
        result = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        cs = result.control_structure
        assert isinstance(cs, ControlStructure)
        assert len(cs.responsibilities) == 2


# ---------------------------------------------------------------------------
# ConnSet-06: coordination links appear in the final ControlStructure
# ---------------------------------------------------------------------------


class TestConnSet06CoordinationLinksInFinalCS:
    """ConnSet-06: coordination links appear in the final ControlStructure."""

    def test_connset_06_coordination_link_present(self, tmp_path):
        """Coordination link CL-1 from CoordinationAnalysis appears in final CS."""
        client = _setup_mock_client()
        result = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        cs = result.control_structure
        assert len(cs.coordination_links) == 1
        cl = cs.coordination_links[0]
        assert cl.link_id == "CL-1"
        assert cl.source == "RESP-1"
        assert cl.target == "RESP-2"


# ---------------------------------------------------------------------------
# ConnSet-07: controlled processes appear in the final ControlStructure
# ---------------------------------------------------------------------------


class TestConnSet07ControlledProcessesInFinalCS:
    """ConnSet-07: controlled processes appear in the final ControlStructure."""

    def test_connset_07_controlled_process_present(self, tmp_path):
        """Controlled process CP-1 from ControlElementSet appears in final CS."""
        client = _setup_mock_client()
        result = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        cs = result.control_structure
        cp_ids = {cp.cp_id for cp in cs.controlled_processes}
        assert "CP-1" in cp_ids


# ---------------------------------------------------------------------------
# ConnSet-08: Call 3 is logged with correct stage and step
# ---------------------------------------------------------------------------


class TestConnSet08Call3Logging:
    """ConnSet-08: Call 3 logged with stage stage_2 and step call_3_coordination."""

    def test_connset_08_call_3_logged(self, tmp_path):
        """Call 3 is logged with stage=stage_2 and step=call_3_coordination."""
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


# ---------------------------------------------------------------------------
# ConnSet-09: control structure is written to control-structure.yaml
# ---------------------------------------------------------------------------


class TestConnSet09ControlStructureWrittenToYaml:
    """ConnSet-09: control-structure.yaml exists and contains valid model."""

    def test_connset_09_yaml_written_and_valid(self, tmp_path):
        """control-structure.yaml is written and contains a valid ControlStructure."""
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
        assert len(loaded.responsibilities) == 2


# ---------------------------------------------------------------------------
# ConnSet-10: Call 3 user prompt contains responsibilities from Call 2
# ---------------------------------------------------------------------------


class TestConnSet10Call3PromptContainsResponsibilities:
    """ConnSet-10: Call 3 user prompt contains responsibilities and CPs from Call 2."""

    def test_connset_10_call_3_prompt_has_resp_data(self, tmp_path):
        """Call 3 user prompt contains RESP-1, RESP-2 from Call 2."""
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


# ---------------------------------------------------------------------------
# ConnSet-11: revision still uses RevisionDelta as response format
# ---------------------------------------------------------------------------


class TestConnSet11RevisionUsesRevisionDelta:
    """ConnSet-11: revision uses RevisionDelta as response format."""

    def test_connset_11_revision_uses_revision_delta(self, tmp_path):
        """run_revision uses response_format=RevisionDelta, not ControlStructure."""
        client = MockLLMClient()
        delta_dict = {
            "new_responsibilities": [],
            "new_controlled_processes": [],
            "new_coordination_links": [],
            "modified_responsibilities": [],
        }
        client.set_response_for(RevisionDelta, delta_dict)

        cs = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="Controller",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="State")
                    ],
                    control_actions=[
                        ControlAction(ca_id="CA-1-1", description="Action")
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-1"
                            ),
                        )
                    ],
                )
            ],
        )
        findings = CriticFindings(
            gaps=[
                {
                    "gap_type": "missing_responsibility",
                    "description": "Missing validation",
                    "related_attack_path": "Attack",
                    "suggested_remedy": "Add validation",
                }
            ],
            checklist_results={"Input validation": "absent_unjustified"},
            taxonomy_probe_results={},
        )
        revised, warnings = run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        assert isinstance(revised, ControlStructure)
        # The revision call used response_format=RevisionDelta
        assert client.calls[0].response_format is RevisionDelta

"""Tests for SP1 Stage 2 — Control Structure derivation.

Covers SP1-S2-01 through SP1-S2-15 from the Gherkin feature file, and the
coordination-link and controlled-process behavior that replaced the old
ConnectionSet merge (ConnSet-01 through ConnSet-11).

Stage 2 now has 4 calls:
  Call 1  — Requirements
  Call 2a — Responsibilities + RCs + PM parts
  Call 2b — Control Actions + Feedback Channels + Controlled Processes
  Call 3  — Coordination links + integrity findings
"""

from __future__ import annotations


import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

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
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    _CoordinationProviderEnvelope,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
    PROMPTS_DIR,
    _call_2a_responsibilities,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    run_revision,
    RevisionDelta,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.helpers.calls_log import read_calls_jsonl
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from tests.helpers.sp1_control_structure import (
    _make_loss_analysis,
    _valid_control_element_set_dict,
    _valid_requirement_set_dict,
    _valid_responsibility_set_dict,
)


def test_collection_repair_preserves_the_valid_functional_record_in_context(tmp_path):

    valid = {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Return book recommendations to the patron",
                "security_constraint_refs": ["SC-1"],
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "Patron reading preferences"}
                ],
            }
        ]
    }
    client = MockLLMClient()
    client.set_response_queue([{**valid, "alternate_responsibilities": []}, valid])
    requirements = RequirementSet(
        requirements=[
            {
                "req_id": "REQ-1",
                "description": "Do not disclose another patron's borrowing history",
                "classification": "constraint",
                "source_constraint": "SC-1",
            }
        ]
    )
    result = _call_2a_responsibilities(
        llm_client=client,
        use_case_text="Recommend books without exposing other patrons' borrowing records.",
        requirement_set=requirements,
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0,
    )
    assert (
        result.responsibilities[0].description
        == valid["responsibilities"][0]["description"]
    )
    assert len(client.calls) == 2
    repair = client.calls[1].user_prompt
    assert "Return book recommendations to the patron" in repair
    assert "without redesigning valid records" in repair
    assert "replace a functional responsibility with only its safeguard" in repair


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
        "semantic_review": {
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "source_evidence": [],
                    "rationale": "Authorization hazard is retained.",
                },
                {
                    "hazard_id": "H-2",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "source_evidence": [],
                    "rationale": "Output hazard is retained.",
                },
            ],
            "constraints": [
                {
                    "constraint_id": "SC-1",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "related_hazards": ["H-1"],
                    "source_evidence": [],
                    "rationale": "Authorization constraint applies to the payment hazard.",
                },
                {
                    "constraint_id": "SC-2",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "related_hazards": ["H-2"],
                    "source_evidence": [],
                    "rationale": "Output constraint applies to the response hazard.",
                },
            ],
            "responsibilities": [
                {
                    "responsibility_id": "RESP-1",
                    "constraint_refs": ["SC-1"],
                    "rationale": "Authorization constraint.",
                },
                {
                    "responsibility_id": "RESP-2",
                    "constraint_refs": ["SC-2"],
                    "rationale": "Output constraint.",
                },
            ],
            "actions": [
                {
                    "control_action_id": "CA-1-1",
                    "effect_kind": "tool_call",
                    "rationale": "Executes a transaction.",
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


def test_control_element_wire_schema_prevents_target_effect_contradictions(tmp_path):
    """The actual Call 2b schema must prevent the saved live-run mismatch."""
    client = _setup_mock_client()
    derive_control_structure(
        llm_client=client,
        use_case_text="A conversational assistant can submit payment transactions.",
        loss_analysis=_make_loss_analysis(),
        run_dir=tmp_path,
    )
    call = next(
        call
        for call in client.calls
        if call.response_format and issubclass(call.response_format, ControlElementSet)
    )
    validator = Draft202012Validator(call.response_format.model_json_schema())
    payload = {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Return the answer to the caller",
                "target": {"type": "controlled_process", "id": "CP-1"},
                "effect_kind": "model_output",
                "temporality": "discrete",
            }
        ],
        "feedback": [],
        "controlled_processes": [{"cp_id": "CP-1", "description": "Caller interface"}],
    }
    assert not list(validator.iter_errors(payload))
    action = payload["control_actions"][0]
    action["target"] = {"type": "responsibility", "id": "RESP-2"}
    for effect in ("model_output", "tool_call", "state_change", "environment_action"):
        action["effect_kind"] = effect
        assert list(validator.iter_errors(payload)), effect
    action["effect_kind"] = "agent_message"
    assert not list(validator.iter_errors(payload))


def test_responsibility_wire_schema_rejects_stray_root_responsibility_fields():
    payload = _valid_responsibility_set_dict()
    payload["resp_id"] = "RESP-3"
    validator = Draft202012Validator(ResponsibilitySet.model_json_schema())
    assert list(validator.iter_errors(payload))


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

        entries = read_calls_jsonl(tmp_path)
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

        entries = read_calls_jsonl(tmp_path)
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

        entries = read_calls_jsonl(tmp_path)
        call3 = [e for e in entries if e["step"] == "call_3_coordination"]
        assert len(call3) == 1
        assert call3[0]["stage"] == "stage_2"


class TestStage2Derivation:
    """SP1-S2-10, S2-11, S2-13: Call 3 output and file writing."""

    def test_s2_10_call_3_produces_valid_control_structure(self, tmp_path):
        """SP1-S2-10: Stage 2 produces a valid ControlStructure."""
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

    def test_s2_11_coordination_links_identified(self, tmp_path):
        """SP1-S2-11: coordination links are identified in Call 3."""
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
        assert len(loaded.responsibilities) == 2


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


class TestConnSetCoordination:
    """ConnSet-01, -02, -07: Call 3 output and the final ControlStructure."""

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

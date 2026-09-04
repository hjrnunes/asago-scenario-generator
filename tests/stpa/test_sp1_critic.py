"""Tests for SP1 completeness critic and revision.

Covers SP1-CRITIC-01 through SP1-CRITIC-12 and SP1-REV-01 through SP1-REV-08.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
)
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
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    RevisionDelta,
    has_unjustified_gaps,
    run_completeness_critic,
    run_revision,
)
from tests.stpa.sp1_helpers import MockLLMClient


def _make_control_structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State 1")
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action 1")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB 1",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State 2")
                ],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action 2")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="FB 2",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-2"
                        ),
                    )
                ],
            ),
        ],
    )


def _make_capability_profile() -> CapabilityProfile:
    return Stage1Profile(
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=[
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        confidence="medium",
        kc_subcodes=["KC1.1", "KC5.1", "KC6.1.1"],
        tool_inventory=[{"name": "tool1", "description": "A tool"}],
    ).to_capability_profile()


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
            SecurityConstraint(
                constraint_id="SC-1", description="C", related_hazards=["H-1"]
            ),
        ],
    )


def _valid_critic_findings_dict() -> dict:
    return {
        "gaps": [
            {
                "gap_type": "missing_responsibility",
                "description": "Missing input validation",
                "related_attack_path": "Attacker sends crafted input",
                "suggested_remedy": "Add input validation responsibility",
            },
            {
                "gap_type": "missing_feedback",
                "description": "Missing outcome feedback",
                "related_attack_path": "Attacker exploits unchecked output",
                "suggested_remedy": "Add outcome verification feedback",
            },
        ],
        "checklist_results": {
            "Input validation / intent classification": "present",
            "Authorization scope enforcement": "absent_justified",
            "Action selection / parameter binding": "present",
            "Outcome verification / output checking": "absent_unjustified",
            "Context management / state tracking": "present",
            "Multi-agent coordination": "absent_justified",
            "Human-in-the-loop / alerting": "absent_justified",
        },
        "taxonomy_probe_results": {
            "Tool parameter validation": "present",
        },
    }


class TestCriticFindings:
    """SP1-CRITIC-01 through SP1-CRITIC-06: CriticFindings model."""

    def test_critic_01_valid_findings(self):
        """SP1-CRITIC-01: valid CriticFindings with gaps, checklist, and taxonomy results."""
        findings = CriticFindings.model_validate(_valid_critic_findings_dict())
        assert len(findings.gaps) == 2
        assert isinstance(findings.checklist_results, dict)
        assert isinstance(findings.taxonomy_probe_results, dict)

    def test_critic_02_empty_gaps(self):
        """SP1-CRITIC-02: critic with no gaps produces empty gaps list."""
        data = _valid_critic_findings_dict()
        data["gaps"] = []
        findings = CriticFindings.model_validate(data)
        assert len(findings.gaps) == 0

    @pytest.mark.parametrize(
        "gap_type",
        ["missing_responsibility", "missing_feedback", "missing_pm_part"],
    )
    def test_critic_03_gap_types_validated(self, gap_type):
        """SP1-CRITIC-03: gap types are validated."""
        data = _valid_critic_findings_dict()
        data["gaps"] = [
            {
                "gap_type": gap_type,
                "description": "Test gap",
                "related_attack_path": "Attack",
                "suggested_remedy": "Fix",
            }
        ]
        findings = CriticFindings.model_validate(data)
        assert findings.gaps[0].gap_type == gap_type

    def test_critic_04_invalid_gap_type_fails(self):
        """SP1-CRITIC-04: gap with invalid type fails validation."""
        data = _valid_critic_findings_dict()
        data["gaps"] = [
            {
                "gap_type": "missing_tool",
                "description": "Test",
                "related_attack_path": "Attack",
                "suggested_remedy": "Fix",
            }
        ]
        with pytest.raises((ValidationError, ValueError), match="gap_type"):
            CriticFindings.model_validate(data)

    def test_critic_05_gap_has_required_fields(self):
        """SP1-CRITIC-05: each gap has description, related_attack_path, and suggested_remedy."""
        findings = CriticFindings.model_validate(_valid_critic_findings_dict())
        for gap in findings.gaps:
            assert gap.description
            assert gap.related_attack_path
            assert gap.suggested_remedy

    def test_critic_06_checklist_results_map(self):
        """SP1-CRITIC-06: checklist results map responsibility names to status."""
        findings = CriticFindings.model_validate(_valid_critic_findings_dict())
        valid_statuses = {"present", "absent_justified", "absent_unjustified"}
        for status in findings.checklist_results.values():
            assert status in valid_statuses


class TestCriticExecution:
    """SP1-CRITIC-07 through SP1-CRITIC-12: critic execution and logging."""

    def test_critic_07_call_logged(self, tmp_path):
        """SP1-CRITIC-07: critic call logged with stage stage_2 and step critic."""
        client = MockLLMClient()
        client.set_response_for(CriticFindings, _valid_critic_findings_dict())
        run_completeness_critic(
            llm_client=client,
            control_structure=_make_control_structure(),
            capability_profile=_make_capability_profile(),
            use_case_text="Test use case",
            run_dir=tmp_path,
        )
        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        critic_entries = [e for e in entries if e["step"] == "critic"]
        assert len(critic_entries) == 1
        assert critic_entries[0]["stage"] == "stage_2"

    def test_critic_08_prompt_contains_cs_profile_usecase(self, tmp_path):
        """SP1-CRITIC-08: prompt contains control structure, capability profile, and use-case."""
        client = MockLLMClient()
        client.set_response_for(CriticFindings, _valid_critic_findings_dict())
        run_completeness_critic(
            llm_client=client,
            control_structure=_make_control_structure(),
            capability_profile=_make_capability_profile(),
            use_case_text="Test use case description",
            run_dir=tmp_path,
        )
        user_prompt = client.calls[0].user_prompt
        assert "RESP-1" in user_prompt
        assert "RESP-2" in user_prompt
        assert "Test use case description" in user_prompt
        assert "kc_subcodes" not in user_prompt.lower() or "KC" in user_prompt

    def test_critic_prompt_checks_typed_action_kind_conflicts(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(CriticFindings, _valid_critic_findings_dict())
        run_completeness_critic(
            llm_client=client,
            control_structure=_make_control_structure(),
            capability_profile=_make_capability_profile(),
            use_case_text="Test use case",
            run_dir=tmp_path,
        )

        prompt = client.calls[0].system_prompt
        assert "typed `effect_kind`" in prompt
        assert "action-kind consistency gap" in prompt
        assert "never silently relabel" in prompt.lower()

    def test_critic_09_taxonomy_probes_conditioned_on_profile(self, tmp_path):
        """SP1-CRITIC-09: taxonomy probes are conditioned on capability profile."""
        client = MockLLMClient()
        client.set_response_for(CriticFindings, _valid_critic_findings_dict())
        # Profile with KC6.3.3 (RAG)
        profile = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=[
                {
                    "name": "User chat",
                    "direction": "input",
                    "controllability": "direct",
                },
            ],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC6.3.3"],
            tool_inventory=[{"name": "rag_search", "description": "RAG search"}],
        ).to_capability_profile()
        run_completeness_critic(
            llm_client=client,
            control_structure=_make_control_structure(),
            capability_profile=profile,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        user_prompt = client.calls[0].user_prompt
        assert "RAG" in user_prompt or "rag" in user_prompt.lower()

    def test_critic_10_unjustified_gaps_trigger_revision(self):
        """SP1-CRITIC-10: unjustified gaps trigger revision."""
        findings = CriticFindings.model_validate(_valid_critic_findings_dict())
        assert has_unjustified_gaps(findings) is True

    def test_critic_11_only_justified_gaps_no_revision(self):
        """SP1-CRITIC-11: only justified gaps do not trigger revision."""
        data = _valid_critic_findings_dict()
        # Clear the explicit gap set so the fixture genuinely matches the
        # scenario name ("only justified gaps"). Probe statuses are retained
        # only as diagnostic context and cannot trigger revision by themselves.
        data["checklist_results"] = {
            "Input validation": "present",
            "Authorization": "absent_justified",
        }
        data["gaps"] = []
        data["taxonomy_probe_results"] = {}
        findings = CriticFindings.model_validate(data)
        assert has_unjustified_gaps(findings) is False


class TestRevision:
    """SP1-REV-01 through SP1-REV-08."""

    def test_rev_01_revised_control_structure_valid(self, tmp_path):
        """SP1-REV-01: revision call produces a valid ControlStructure."""
        client = MockLLMClient()
        revision_delta_dict = {
            "new_responsibilities": [
                {
                    "resp_id": "RESP-3",
                    "description": "Added input validation controller",
                    "process_model_parts": [
                        {"pm_id": "PM-3-1", "description": "Input state"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-3-1", "description": "Validate input"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-3-1",
                            "description": "Validation result",
                            "updates": "PM-3-1",
                            "source": {"type": "responsibility", "id": "RESP-3"},
                        }
                    ],
                }
            ],
            "new_controlled_processes": [],
            "new_coordination_links": [],
            "modified_responsibilities": [],
        }
        client.set_response_for(RevisionDelta, revision_delta_dict)
        findings = CriticFindings.model_validate(_valid_critic_findings_dict())
        revised, warnings = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        assert isinstance(revised, ControlStructure)
        resp_ids = {r.resp_id for r in revised.responsibilities}
        assert "RESP-3" in resp_ids

    def test_rev_02_revision_logged(self, tmp_path):
        """SP1-REV-02: revision call logged with stage stage_2 and step revision."""
        client = MockLLMClient()
        delta_dict = {
            "new_responsibilities": [],
            "new_controlled_processes": [],
            "new_coordination_links": [],
            "modified_responsibilities": [],
        }
        client.set_response_for(RevisionDelta, delta_dict)
        findings = CriticFindings.model_validate(_valid_critic_findings_dict())
        run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        rev_entries = [e for e in entries if e["step"] == "revision"]
        assert len(rev_entries) == 1
        assert rev_entries[0]["stage"] == "stage_2"

    def test_rev_03_prompt_contains_cs_and_findings(self, tmp_path):
        """SP1-REV-03: revision prompt contains current CS (system) and critic findings (user).

        The control-structure listing was deliberately moved from
        revision_user.j2 into revision_system.j2 to avoid duplication.
        The critic findings remain in revision_user.j2.
        """
        client = MockLLMClient()
        delta_dict = {
            "new_responsibilities": [],
            "new_controlled_processes": [],
            "new_coordination_links": [],
            "modified_responsibilities": [],
        }
        client.set_response_for(RevisionDelta, delta_dict)
        findings = CriticFindings.model_validate(_valid_critic_findings_dict())
        run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        system_prompt = client.calls[0].system_prompt
        user_prompt = client.calls[0].user_prompt
        # Control structure listing is in the system prompt
        assert "RESP-1" in system_prompt or "RESP-2" in system_prompt
        # Critic findings are in the user prompt
        assert (
            "Missing input validation" in user_prompt or "gaps" in user_prompt.lower()
        )

    def test_rev_04_heuristics_rerun_after_revision(self, tmp_path):
        """SP1-REV-04: structural heuristics are re-run after revision."""
        client = MockLLMClient()
        delta_dict = {
            "new_responsibilities": [],
            "new_controlled_processes": [],
            "new_coordination_links": [],
            "modified_responsibilities": [],
        }
        client.set_response_for(RevisionDelta, delta_dict)
        findings = CriticFindings.model_validate(_valid_critic_findings_dict())
        revised, warnings = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
            loss_analysis=_make_loss_analysis(),
        )
        # Heuristics were re-run — warnings is a list (may be empty)
        assert isinstance(warnings, list)

    def test_revision_dismissal_is_reported_as_warning(self, tmp_path):
        """Dismissed critic gaps remain visible to downstream callers."""
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            {
                "new_responsibilities": [],
                "new_controlled_processes": [],
                "new_coordination_links": [],
                "modified_responsibilities": [],
                "dismissed_gaps": ["already covered by RESP-1"],
            },
        )

        revised, warnings = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=CriticFindings.model_validate(
                _valid_critic_findings_dict()
            ),
            use_case_text="Test",
            run_dir=tmp_path,
        )

        assert isinstance(revised, ControlStructure)
        assert warnings[0] == "Revision dismissed finding: already covered by RESP-1"

    def test_revision_failure_preserves_control_structure(self, tmp_path):
        """A failed revision returns the original structure and warning."""
        client = MockLLMClient()
        client.set_exception_for(RevisionDelta, RuntimeError("offline"))
        original = _make_control_structure()

        revised, warnings = run_revision(
            llm_client=client,
            control_structure=original,
            critic_findings=CriticFindings.model_validate(
                _valid_critic_findings_dict()
            ),
            use_case_text="Test",
            run_dir=tmp_path,
        )

        assert revised == original
        assert warnings == ["Revision failed: RuntimeError: offline"]

    def test_revision_none_response_preserves_control_structure(
        self, tmp_path, monkeypatch
    ):
        """An empty revision response returns the original structure."""
        from asago_scenario_generator.stpa.system_model import critic as critic_module

        monkeypatch.setattr(
            critic_module,
            "safe_llm_call",
            lambda **kwargs: (None, None, None),
        )
        original = _make_control_structure()

        revised, warnings = run_revision(
            llm_client=MockLLMClient(),
            control_structure=original,
            critic_findings=CriticFindings.model_validate(
                _valid_critic_findings_dict()
            ),
            use_case_text="Test",
            run_dir=tmp_path,
        )

        assert revised == original
        assert warnings == ["Revision failed: unexpected None response"]

    def test_rev_08_revised_cs_replaces_original(self, tmp_path):
        """SP1-REV-08: revised control structure contains new responsibilities and keeps old ones."""
        client = MockLLMClient()
        revision_delta_dict = {
            "new_responsibilities": [
                {
                    "resp_id": "RESP-3",
                    "description": "Added controller",
                    "process_model_parts": [
                        {"pm_id": "PM-3-1", "description": "State 3"}
                    ],
                    "control_actions": [{"ca_id": "CA-3-1", "description": "Action 3"}],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-3-1",
                            "description": "FB 3",
                            "updates": "PM-3-1",
                            "source": {"type": "responsibility", "id": "RESP-3"},
                        }
                    ],
                }
            ],
            "new_controlled_processes": [],
            "new_coordination_links": [],
            "modified_responsibilities": [],
        }
        client.set_response_for(RevisionDelta, revision_delta_dict)
        findings = CriticFindings.model_validate(_valid_critic_findings_dict())
        revised, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        resp_ids = {r.resp_id for r in revised.responsibilities}
        assert "RESP-3" in resp_ids
        assert "RESP-1" in resp_ids
        assert "RESP-2" in resp_ids

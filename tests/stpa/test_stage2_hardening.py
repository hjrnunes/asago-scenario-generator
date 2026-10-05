"""Hardening tests for Stage 2 control-structure derivation.

These tests close coverage gaps identified by mutation testing:
  - ``_assign_elements_to_responsibilities``: element with no matching
    responsibility is silently dropped (``resp is None`` branch).
  - ``_next_fb_num``: multiple FBs with matching IDs (loop-continuation
    branch).
  - ``_add_coordination_links_with_fallback``: exception-handler path
    when coordination links reference non-existent responsibilities.
  - ``_find_orphan_pms``: direct test of the ``not in`` condition.
  - ``run_sp1``: default ``max_workers=1`` is recorded in the manifest.
"""

from __future__ import annotations

import yaml

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    CoordinationAnalysis,
    _add_coordination_links_with_fallback,
    _assign_elements_to_responsibilities,
    _find_orphan_pms,
    _next_fb_num,
    ControlElementSet,
    RequirementSet,
    ResponsibilitySet,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    valid_control_element_set_dict,
    valid_empty_coordination_analysis_dict,
    valid_requirement_set_dict,
    valid_responsibility_set_dict,
    valid_risk_draft_dict,
    valid_gap_draft_dict,
    valid_stage1_profile_dict,
)
from asago_scenario_generator.models.capability_profile import Stage1Profile
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.critic import CriticFindings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resp(resp_id: str = "RESP-1") -> Responsibility:
    return Responsibility(
        resp_id=resp_id,
        description="Controller",
        process_model_parts=[
            ProcessModelPart(
                pm_id=f"PM-{resp_id.split('-')[-1]}-1", description="State"
            )
        ],
        control_actions=[
            ControlAction(ca_id=f"CA-{resp_id.split('-')[-1]}-1", description="Action")
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{resp_id.split('-')[-1]}-1",
                description="Feedback",
                updates=f"PM-{resp_id.split('-')[-1]}-1",
            )
        ],
    )


# ---------------------------------------------------------------------------
# _assign_elements_to_responsibilities — element with no matching resp
# ---------------------------------------------------------------------------


class TestAssignElementsUnmatched:
    """Element with no matching responsibility is silently dropped."""

    def test_unmatched_ca_is_dropped(self):
        """CA whose numeric prefix has no matching RESP is not assigned."""
        resp1 = _resp("RESP-1")
        resp_by_num = {1: resp1}

        # CA-99-1 → numeric prefix 99 → no matching responsibility
        unmatched_ca = ControlAction(ca_id="CA-99-1", description="Orphan CA")
        _assign_elements_to_responsibilities(
            [unmatched_ca], "ca_id", resp_by_num, "control_actions"
        )
        assert len(resp1.control_actions) == 1  # unchanged

    def test_unmatched_fb_is_dropped(self):
        """FB whose numeric prefix has no matching RESP is not assigned."""
        resp1 = _resp("RESP-1")
        resp_by_num = {1: resp1}

        unmatched_fb = FeedbackChannel(
            fb_id="FB-99-1", description="Orphan FB", updates="PM-99-1"
        )
        _assign_elements_to_responsibilities(
            [unmatched_fb], "fb_id", resp_by_num, "feedback_channels"
        )
        assert len(resp1.feedback_channels) == 1  # unchanged

    def test_matched_and_unmatched_mixed(self):
        """Mixed elements: matched ones assigned, unmatched dropped."""
        resp1 = _resp("RESP-1")
        resp2 = _resp("RESP-2")
        resp_by_num = {1: resp1, 2: resp2}

        matched_ca = ControlAction(ca_id="CA-1-2", description="Matched")
        unmatched_ca = ControlAction(ca_id="CA-99-1", description="Unmatched")
        _assign_elements_to_responsibilities(
            [matched_ca, unmatched_ca], "ca_id", resp_by_num, "control_actions"
        )
        assert len(resp1.control_actions) == 2  # original + matched
        assert len(resp2.control_actions) == 1  # unchanged


# ---------------------------------------------------------------------------
# _next_fb_num — multiple FBs with matching IDs
# ---------------------------------------------------------------------------


class TestNextFbNumMultipleMatches:
    """_next_fb_num with multiple FBs matching the regex pattern."""

    def test_multiple_matching_fbs(self):
        """Multiple FBs with matching IDs yields max+1."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller",
            process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="S")],
            control_actions=[ControlAction(ca_id="CA-1-1", description="A")],
            feedback_channels=[
                FeedbackChannel(fb_id="FB-1-1", description="F1", updates="PM-1-1"),
                FeedbackChannel(fb_id="FB-1-3", description="F3", updates="PM-1-1"),
                FeedbackChannel(fb_id="FB-1-2", description="F2", updates="PM-1-1"),
            ],
        )
        assert _next_fb_num(resp) == 4  # max(1,2,3) + 1

    def test_no_matching_fbs(self):
        """FBs with non-matching IDs (bypassing validation) yield 1.

        Uses ``model_construct`` to create a FeedbackChannel with an
        ID that does not match the ``FB-\\d+-\\d+`` regex, simulating
        deserialized data that bypasses Pydantic validation.
        """
        fb = FeedbackChannel.model_construct(
            fb_id="FB-XYZ", description="F", updates="PM-1-1"
        )
        resp = Responsibility.model_construct(
            resp_id="RESP-1",
            description="Controller",
            process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="S")],
            control_actions=[ControlAction(ca_id="CA-1-1", description="A")],
            feedback_channels=[fb],
        )
        assert _next_fb_num(resp) == 1  # no matches → default(0) + 1

    def test_empty_feedback_channels(self):
        """No feedback channels yields 1."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller",
            process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="S")],
            control_actions=[ControlAction(ca_id="CA-1-1", description="A")],
            feedback_channels=[],
        )
        assert _next_fb_num(resp) == 1


# ---------------------------------------------------------------------------
# _find_orphan_pms — direct test of the not-in condition
# ---------------------------------------------------------------------------


class TestFindOrphanPms:
    """Direct tests for _find_orphan_pms to strengthen not-in coverage."""

    def test_all_orphan(self):
        """All PMs are orphan when no FBs exist."""
        resp = _resp("RESP-1")
        resp.feedback_channels = []
        # Add a second PM that is also orphan
        resp.process_model_parts.append(
            ProcessModelPart(pm_id="PM-1-2", description="State 2")
        )
        orphans = _find_orphan_pms(resp)
        assert set(orphans) == {"PM-1-1", "PM-1-2"}

    def test_no_orphan(self):
        """No orphans when every PM is updated by a FB."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="S1"),
                ProcessModelPart(pm_id="PM-1-2", description="S2"),
            ],
            control_actions=[ControlAction(ca_id="CA-1-1", description="A")],
            feedback_channels=[
                FeedbackChannel(fb_id="FB-1-1", description="F1", updates="PM-1-1"),
                FeedbackChannel(fb_id="FB-1-2", description="F2", updates="PM-1-2"),
            ],
        )
        orphans = _find_orphan_pms(resp)
        assert orphans == []

    def test_partial_orphan(self):
        """Only the PM not referenced by any FB is orphan."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="S1"),
                ProcessModelPart(pm_id="PM-1-2", description="S2"),
                ProcessModelPart(pm_id="PM-1-3", description="S3"),
            ],
            control_actions=[ControlAction(ca_id="CA-1-1", description="A")],
            feedback_channels=[
                FeedbackChannel(fb_id="FB-1-1", description="F1", updates="PM-1-1"),
            ],
        )
        orphans = _find_orphan_pms(resp)
        assert set(orphans) == {"PM-1-2", "PM-1-3"}


# ---------------------------------------------------------------------------
# _add_coordination_links_with_fallback — exception handler
# ---------------------------------------------------------------------------


class TestAddCoordinationLinksFallback:
    """Exception handler path when coordination links are invalid."""

    def test_invalid_link_returns_original_cs_with_warning(self, tmp_path):
        """Invalid coordination link triggers fallback with warning."""
        resp = _resp("RESP-1")
        cs = ControlStructure(responsibilities=[resp])

        # Coordination link referencing non-existent responsibility
        bad_link = CoordinationLink(
            link_id="CL-1",
            source="RESP-99",
            target="RESP-1",
            shared_pm="PM-1-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id="CM-1", description="Coord", payload="data"
            ),
            description="Bad link",
        )
        analysis = CoordinationAnalysis(
            coordination_links=[bad_link],
            integrity_findings=[],
        )

        result_cs, warnings = _add_coordination_links_with_fallback(
            cs, analysis, tmp_path, "test-model"
        )

        # Should return the original CS without coordination links
        assert len(result_cs.coordination_links) == 0
        assert len(warnings) >= 1
        assert any("add_coordination_links" in w for w in warnings)

        # Failure should be logged to calls.jsonl
        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()

    def test_empty_links_returns_original(self, tmp_path):
        """Empty coordination links return original CS with no warnings."""
        resp = _resp("RESP-1")
        cs = ControlStructure(responsibilities=[resp])
        analysis = CoordinationAnalysis(
            coordination_links=[],
            integrity_findings=[],
        )

        result_cs, warnings = _add_coordination_links_with_fallback(
            cs, analysis, tmp_path, "test-model"
        )

        assert result_cs is cs
        assert warnings == []

    def test_valid_links_added(self, tmp_path):
        """Valid coordination links are added to the CS."""
        resp1 = _resp("RESP-1")
        resp2 = _resp("RESP-2")
        cs = ControlStructure(responsibilities=[resp1, resp2])

        link = CoordinationLink(
            link_id="CL-1",
            source="RESP-1",
            target="RESP-2",
            shared_pm="PM-1-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id="CM-1", description="Coord", payload="data"
            ),
            description="Valid link",
        )
        analysis = CoordinationAnalysis(
            coordination_links=[link],
            integrity_findings=[],
        )

        result_cs, warnings = _add_coordination_links_with_fallback(
            cs, analysis, tmp_path, "test-model"
        )

        assert len(result_cs.coordination_links) == 1
        assert warnings == []


# ---------------------------------------------------------------------------
# run_sp1 — default max_workers in manifest
# ---------------------------------------------------------------------------


class TestRunSp1DefaultMaxWorkers:
    """Default max_workers=1 is recorded in the manifest."""

    def test_default_max_workers_recorded(self, tmp_path):
        """run_sp1 with default max_workers records max_workers=1 in manifest."""
        client = _setup_full_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

        manifest_file = tmp_path / "run-manifest.yaml"
        assert manifest_file.exists()
        manifest = yaml.safe_load(manifest_file.read_text())
        assert manifest["model_settings"]["max_workers"] == 1


def _setup_full_mock_client() -> MockLLMClient:
    """Set up a mock LLM client with valid responses for all SP1 stages."""

    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft, [valid_risk_draft_dict(), valid_gap_draft_dict()]
    )
    client.set_response_for(Stage1Profile, valid_stage1_profile_dict())
    client.set_response_for(RequirementSet, valid_requirement_set_dict())
    client.set_response_for(ResponsibilitySet, valid_responsibility_set_dict())
    client.set_response_for(ControlElementSet, valid_control_element_set_dict())
    client.set_response_for(
        CoordinationAnalysis,
        valid_empty_coordination_analysis_dict(constraint_ids=("SC-1", "SC-2")),
    )
    client.set_response_for(
        CriticFindings,
        {
            "gaps": [],
            "checklist_results": {
                "Input validation": "present",
                "Authorization": "present",
                "Action selection": "present",
                "Outcome verification": "present",
                "Context management": "present",
                "Multi-agent coordination": "present",
                "Human-in-the-loop": "present",
            },
            "taxonomy_probe_results": {},
        },
    )
    return client

"""Unit tests for SP1 critic ID sanitization before revision.

Covers SP1-CRITIC-SAN-01 through SP1-CRITIC-SAN-09. Tests verify that:
- The critic system prompt instructs the LLM not to suggest specific IDs.
- ``sanitize_critic_ids`` strips non-conforming IDs (e.g., PM-0, CA-0,
  FB-0) from ``suggested_remedy`` strings, replacing them with generic
  descriptions.
- Conforming IDs (RESP-1, PM-1-2, CA-2-1, FB-3-1) are preserved.
- Checklist and taxonomy probe results are preserved.
- Sanitization is called after the critic and before revision in the
  Stage 2 block.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from asago_scenario_generator.stpa.infra.templates import (
    TemplateLoader,
    TemplateLoader as TL,
)
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR, PROMPTS_DIR as PD
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    sanitize_critic_ids,
    RevisionDelta,
)
from asago_scenario_generator.stpa.system_model.run import _run_stage_2_block
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    RequirementSet,
    ResponsibilitySet,
)
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    valid_control_element_set_dict,
    valid_empty_coordination_analysis_dict,
    valid_loss_analysis_dict,
    valid_requirement_set_dict,
    valid_responsibility_set_dict,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.models.capability_profile import Stage1Profile
from tests.helpers.critic_id_sanitization import _make_control_structure


# ---------------------------------------------------------------------------
# Prompt content tests (SP1-CRITIC-SAN-01, SP1-CRITIC-SAN-02)
# ---------------------------------------------------------------------------


class TestCriticSystemPromptIDSanitization:
    """SP1-CRITIC-SAN-01 and SP1-CRITIC-SAN-02: prompt instructs no specific IDs."""

    def test_san_01_prompt_instructs_no_specific_ids(self):
        """SP1-CRITIC-SAN-01: critic system prompt instructs not to suggest IDs."""
        loader = TemplateLoader(PROMPTS_DIR)
        text = loader.render_prompt("critic_system.j2", taxonomy_probes=[])
        assert "Do NOT suggest specific IDs in remedies" in text
        assert "Describe WHAT should be added" in text
        assert "not what ID it should have" in text
        assert "Let the revision model assign IDs" in text

    def test_san_02_prompt_provides_examples_of_what_to_avoid(self):
        """SP1-CRITIC-SAN-02: prompt provides examples of what to avoid."""
        loader = TemplateLoader(PROMPTS_DIR)
        text = loader.render_prompt("critic_system.j2", taxonomy_probes=[])
        assert "a responsibility for input validation" in text
        assert "not 'add RESP-5'" in text
        assert "not 'add PM-0-1'" in text


# ---------------------------------------------------------------------------
# Sanitization function tests (SP1-CRITIC-SAN-03 through SP1-CRITIC-SAN-07)
# ---------------------------------------------------------------------------


def _make_findings_with_remedy(remedy: str) -> CriticFindings:
    """Build a CriticFindings with a single gap whose remedy is *remedy*."""
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_responsibility",
                description="Test gap",
                related_attack_path="Attack",
                suggested_remedy=remedy,
            )
        ]
    )


class TestSanitizeCriticIDs:
    """SP1-CRITIC-SAN-03 through SP1-CRITIC-SAN-07."""

    @pytest.mark.parametrize("bad_id", ["PM-0", "CA-0", "FB-0"])
    def test_san_03_non_conforming_ids_are_stripped(self, bad_id: str):
        """SP1-CRITIC-SAN-03: non-conforming IDs (with 0) are stripped."""
        findings = _make_findings_with_remedy(f"Add {bad_id} to cover the gap")
        sanitized = sanitize_critic_ids(findings)
        assert bad_id not in sanitized.gaps[0].suggested_remedy
        # Generic description should be present
        assert "a new" in sanitized.gaps[0].suggested_remedy

    @pytest.mark.parametrize(
        ("bad_id", "expected_replacement"),
        [
            ("PM-0", "a new PM part"),
            ("CA-0", "a new control action"),
            ("FB-0", "a new feedback channel"),
            ("RC-0", "a new responsibility constraint"),
        ],
    )
    def test_san_03b_specific_replacement_text(
        self, bad_id: str, expected_replacement: str
    ):
        """Each known prefix is replaced with its specific generic description.

        This also guards against the ``[0]`` → ``[1]`` index mutation in
        ``_replace_non_conforming_ids``: if the wrong split part is used as
        the prefix lookup key, the specific replacement text will be missing.
        """
        findings = _make_findings_with_remedy(f"Add {bad_id} to cover the gap")
        sanitized = sanitize_critic_ids(findings)
        assert expected_replacement in sanitized.gaps[0].suggested_remedy

    @pytest.mark.parametrize("good_id", ["RESP-1", "PM-1-2", "CA-2-1", "FB-3-1"])
    def test_san_04_conforming_ids_are_preserved(self, good_id: str):
        """SP1-CRITIC-SAN-04: conforming IDs are preserved."""
        findings = _make_findings_with_remedy(f"Add {good_id} to cover the gap")
        sanitized = sanitize_critic_ids(findings)
        assert good_id in sanitized.gaps[0].suggested_remedy

    def test_san_05_remedy_without_ids_is_unchanged(self):
        """SP1-CRITIC-SAN-05: suggested_remedy without any IDs is unchanged."""
        original_remedy = "Add a responsibility for input validation"
        findings = _make_findings_with_remedy(original_remedy)
        sanitized = sanitize_critic_ids(findings)
        assert sanitized.gaps[0].suggested_remedy == original_remedy

    def test_san_06_multiple_gaps_all_sanitized(self):
        """SP1-CRITIC-SAN-06: multiple gaps with non-conforming IDs are all sanitized."""
        findings = CriticFindings(
            gaps=[
                CriticGap(
                    gap_type="missing_pm_part",
                    description="Gap 1",
                    related_attack_path="A1",
                    suggested_remedy="Add PM-0 for state",
                ),
                CriticGap(
                    gap_type="missing_feedback",
                    description="Gap 2",
                    related_attack_path="A2",
                    suggested_remedy="Add CA-0 for action",
                ),
                CriticGap(
                    gap_type="missing_responsibility",
                    description="Gap 3",
                    related_attack_path="A3",
                    suggested_remedy="Add FB-0 for feedback",
                ),
            ]
        )
        sanitized = sanitize_critic_ids(findings)
        assert len(sanitized.gaps) == 3
        for gap in sanitized.gaps:
            assert "PM-0" not in gap.suggested_remedy
            assert "CA-0" not in gap.suggested_remedy
            assert "FB-0" not in gap.suggested_remedy

    def test_san_07_preserves_checklist_and_taxonomy(self):
        """SP1-CRITIC-SAN-07: checklist_results and taxonomy_probe_results preserved."""
        findings = CriticFindings(
            gaps=[
                CriticGap(
                    gap_type="missing_responsibility",
                    description="Gap",
                    related_attack_path="Attack",
                    suggested_remedy="Add PM-0",
                )
            ],
            checklist_results={"Input validation": "absent_unjustified"},
            taxonomy_probe_results={"Tool validation": "present"},
        )
        sanitized = sanitize_critic_ids(findings)
        assert isinstance(sanitized, CriticFindings)
        assert sanitized.checklist_results == {"Input validation": "absent_unjustified"}
        assert sanitized.taxonomy_probe_results == {"Tool validation": "present"}


# ---------------------------------------------------------------------------
# Flow-to-revision tests (SP1-CRITIC-SAN-08, SP1-CRITIC-SAN-09)
# ---------------------------------------------------------------------------


class TestSanitizationFlow:
    """SP1-CRITIC-SAN-08 and SP1-CRITIC-SAN-09."""

    def test_san_08_sanitized_findings_flow_to_revision(self, tmp_path):
        """SP1-CRITIC-SAN-08: non-conforming ID does not reach revision prompt."""
        findings = _make_findings_with_remedy("Add PM-0 for input state")
        sanitized = sanitize_critic_ids(findings)
        # After sanitization, PM-0 must not be in the suggested_remedy
        assert "PM-0" not in sanitized.gaps[0].suggested_remedy
        # And therefore would not appear in a rendered revision prompt

        loader = TL(PD)
        user_prompt = loader.render_prompt(
            "revision_user.j2",
            use_case_text="Test",
            control_structure=_make_control_structure(),
            critic_findings=sanitized,
        )
        assert "PM-0" not in user_prompt

    def test_san_09_sanitization_called_between_critic_and_revision(self, tmp_path):
        """SP1-CRITIC-SAN-09: sanitize_critic_ids called after critic, before revision."""

        client = MockLLMClient()

        # Stage 2 Call 1: RequirementSet
        client.set_response_for(RequirementSet, valid_requirement_set_dict())
        # Stage 2 Call 2a: ResponsibilitySet
        client.set_response_for(ResponsibilitySet, valid_responsibility_set_dict())
        # Stage 2 Call 2b: ControlElementSet
        client.set_response_for(ControlElementSet, valid_control_element_set_dict())
        # Stage 2 Call 3: CoordinationAnalysis
        client.set_response_for(
            CoordinationAnalysis,
            valid_empty_coordination_analysis_dict(constraint_ids=("SC-1", "SC-2")),
        )

        # Critic findings with an unjustified gap and a non-conforming ID
        critic_dict = {
            "gaps": [
                {
                    "gap_type": "missing_responsibility",
                    "description": "Missing validation",
                    "related_attack_path": "Attack",
                    "suggested_remedy": "Add PM-0 for validation state",
                }
            ],
            "checklist_results": {"Input validation": "absent_unjustified"},
            "taxonomy_probe_results": {},
        }
        client.set_response_for(CriticFindings, critic_dict)

        # Revision delta (empty — no new elements)
        revision_dict = {
            "new_responsibilities": [],
            "new_controlled_processes": [],
            "new_coordination_links": [],
            "modified_responsibilities": [],
        }
        client.set_response_for(RevisionDelta, revision_dict)

        loss_analysis = LossAnalysis.model_validate(valid_loss_analysis_dict())

        cap_profile = Stage1Profile(
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
            kc_subcodes=["KC1.1"],
            tool_inventory=[],
        ).to_capability_profile()

        with patch(
            "asago_scenario_generator.stpa.system_model.run.sanitize_critic_ids",
            wraps=sanitize_critic_ids,
        ) as mock_sanitize:
            _run_stage_2_block(
                llm_client=client,
                use_case_text="Test use case",
                loss_analysis=loss_analysis,
                capability_profile=cap_profile,
                run_dir=tmp_path,
                loader=TemplateLoader(PROMPTS_DIR),
                temperature=0.4,
                stage_errors=[],
            )
            mock_sanitize.assert_called_once()

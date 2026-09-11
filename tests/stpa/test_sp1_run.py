"""Tests for SP1 run orchestration.

Covers SP1-RUN-01 through SP1-RUN-14 from the Gherkin feature file.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
)
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    CoordinationAnalysis,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    RevisionDelta,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    read_calls_jsonl,
    valid_control_element_set_dict,
    valid_empty_coordination_analysis_dict,
    valid_requirement_set_dict,
    valid_responsibility_set_dict,
    valid_risk_draft_dict,
    valid_stage1_profile_dict,
)


def _valid_control_structure_dict() -> dict:
    rs = valid_responsibility_set_dict()
    return {
        "responsibilities": rs["responsibilities"],
        "controlled_processes": [],
        "coordination_links": [],
    }


def _valid_critic_findings_dict() -> dict:
    return {
        "gaps": [
            {
                "gap_type": "missing_responsibility",
                "description": "Missing input validation",
                "related_attack_path": "Attacker sends crafted input",
                "suggested_remedy": "Add input validation",
            },
            {
                "gap_type": "missing_feedback",
                "description": "Missing outcome feedback",
                "related_attack_path": "Attacker exploits unchecked output",
                "suggested_remedy": "Add outcome verification",
            },
        ],
        "checklist_results": {
            "Input validation": "present",
            "Authorization": "present",
            "Action selection": "present",
            "Outcome verification": "absent_justified",
            "Context management": "present",
            "Multi-agent coordination": "absent_justified",
            "Human-in-the-loop": "absent_justified",
        },
        "taxonomy_probe_results": {},
    }


def _run3_invalid_risk_draft_dict() -> dict:
    """Return the sanitized Stage 1a shape from the run-3 artifact."""
    draft = valid_risk_draft_dict()
    draft["security_constraints"] = [
        {
            "constraint_id": f"SC-{index}",
            "rule": (f"The customer payment condition {index + 1} must be prevented."),
            "related_hazards": [f"H-{index + 1}"],
            "applies_when": [],
        }
        for index in range(1, 7)
    ]
    return draft


def _coordination_with_constraints(
    constraint_count: int, *, hazard_count: int | None = None
) -> dict:
    """Build a complete Call 3 review for a synthetic loss graph."""
    hazard_count = hazard_count or constraint_count
    return valid_empty_coordination_analysis_dict(
        constraint_ids=tuple(f"SC-{index}" for index in range(1, constraint_count + 1)),
        hazard_ids=tuple(f"H-{index}" for index in range(1, hazard_count + 1)),
    )


def _reviewed_coordination_for_run() -> dict:
    """A review that rewords both constraints and swaps their hazard edges.

    The reviewed graph must still pass the offline density re-check: each
    reworded constraint shares a subject phrase with its new hazard, backed
    by exact source quotations from the supplied losses.
    """
    payload = _coordination_with_constraints(2)
    constraints = payload["semantic_review"]["constraints"]
    constraints[0].update(
        {
            "disposition": "revise",
            "revised_description": (
                "The agent must preserve user trust through transparency."
            ),
            "source_evidence": [
                {
                    "source_ref": "source_3",
                    "meaning": "The loss of trust motivates the constraint.",
                },
            ],
            "related_hazards": ["H-2"],
        }
    )
    constraints[1].update(
        {
            "disposition": "revise",
            "revised_description": (
                "The agent must confirm every unintended payment before execution."
            ),
            "source_evidence": [
                {
                    "source_ref": "source_2",
                    "meaning": "The unauthorized transaction is the loss.",
                },
            ],
            "related_hazards": ["H-1"],
        }
    )
    return payload


def _setup_mock_client(
    critic_findings: dict | None = None,
    revised_cs: dict | None = None,
) -> MockLLMClient:
    """Set up a mock LLM client with valid responses for all stages."""
    client = MockLLMClient()

    # Stage 1a: two calls (risk_derivation + gap_analysis) both use LossAnalysisDraft
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
    from tests.stpa.sp1_helpers import valid_risk_draft_dict, valid_gap_draft_dict

    client.set_response_for(
        LossAnalysisDraft,
        [valid_risk_draft_dict(), valid_gap_draft_dict()],
    )

    # Stage 1b: Stage1Profile
    from asago_scenario_generator.models.capability_profile import Stage1Profile as S1P

    client.set_response_for(S1P, valid_stage1_profile_dict())

    # Stage 2 Call 1: RequirementSet
    from asago_scenario_generator.stpa.system_model.control_structure import (
        ControlElementSet,
        CoordinationAnalysis,
        RequirementSet,
        ResponsibilitySet,
    )

    client.set_response_for(RequirementSet, valid_requirement_set_dict())

    # Stage 2 Call 2a: ResponsibilitySet
    client.set_response_for(ResponsibilitySet, valid_responsibility_set_dict())

    # Stage 2 Call 2b: ControlElementSet
    client.set_response_for(ControlElementSet, valid_control_element_set_dict())

    # Stage 2 Call 3: CoordinationAnalysis
    client.set_response_for(CoordinationAnalysis, _coordination_with_constraints(2))

    # Critic: CriticFindings
    if critic_findings is not None:
        client.set_response_for(CriticFindings, critic_findings)
    else:
        # No unjustified gaps → no revision
        no_gap = _valid_critic_findings_dict()
        no_gap["gaps"] = []
        no_gap["checklist_results"] = {
            k: "present" if "absent_unjustified" not in v else "present"
            for k, v in _valid_critic_findings_dict()["checklist_results"].items()
        }
        client.set_response_for(CriticFindings, no_gap)

    # Revision: RevisionDelta (if needed)
    if revised_cs is not None:
        # Convert the full CS dict to a RevisionDelta dict (new_responsibilities only)
        delta_dict = {
            "new_responsibilities": revised_cs.get("responsibilities", []),
            "new_controlled_processes": revised_cs.get("controlled_processes", []),
            "new_coordination_links": revised_cs.get("coordination_links", []),
            "modified_responsibilities": [],
        }
        client.set_response_for(RevisionDelta, delta_dict)

    return client


def _observed_gemma_control_element_set_dict() -> dict:
    """Return the schema-adjacent reference shapes reported in issue #36."""
    payload = valid_control_element_set_dict()
    payload["control_actions"][0]["target"] = {
        "type": "CP-5",
    }
    payload["feedback_channels"][0]["updates"] = {
        "type": "process_model_part",
        "id": "PM-1-1",
    }
    payload["feedback_channels"][0]["source"] = {
        "type": "RESP-1",
    }
    payload["controlled_processes"] = [
        {"cp_id": "CP-5", "description": "Observed controlled process"}
    ]
    return payload


def _observed_gemma_invalid_feedback_update_dict() -> dict:
    """Return the responsibility-shaped ``updates`` seen in live run 2."""
    payload = valid_control_element_set_dict()
    payload["feedback_channels"][0]["updates"] = {
        "type": "responsibility",
        "id": "RESP-1",
    }
    return payload


class TestRunOrchestration:
    """SP1-RUN-01 through SP1-RUN-14."""

    def test_run_records_typed_stage1a_reference_failure_and_stops(self, tmp_path):
        """A Stage 1a reference failure is typed, recorded, and never retried.

        The run-3 captured shape (constraints referencing undeclared hazards)
        is outside the two approved targeted-repair classes, so the run
        records the typed failure and stops Stage 1a without a second call.
        """
        from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft

        client = _setup_mock_client()
        client.set_response_for(
            LossAnalysisDraft,
            [_run3_invalid_risk_draft_dict()],
        )

        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

        assert len(result.stage_errors) == 1
        error = result.stage_errors[0]
        assert error.startswith("stage_1a/risk_derivation:")
        assert "targeted repair unsupported" in error
        assert "draft_references failure class" in error
        assert "no repair call was made" in error
        assert result.loss_analysis is None
        assert result.control_structure is None

        entries = [
            json.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        stage1a_entries = [entry for entry in entries if entry["stage"] == "stage_1a"]
        assert [entry["success"] for entry in stage1a_entries] == [False]
        # No repair call follows the reference failure.
        assert not any(entry["step"].endswith("_repair") for entry in stage1a_entries)

    def test_run_01_full_run_produces_all_artifacts(self, tmp_path):
        """SP1-RUN-01: full run produces all three output artifacts."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        assert (tmp_path / "loss-analysis.yaml").exists()
        assert (tmp_path / "capability-profile.yaml").exists()
        assert (tmp_path / "control-structure.yaml").exists()

    def test_run_publishes_reviewed_loss_analysis_and_retains_stage1a_draft(
        self, tmp_path
    ):
        client = _setup_mock_client()
        client.set_response_for(CoordinationAnalysis, _reviewed_coordination_for_run())
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        assert result.loss_analysis is not None
        assert result.loss_analysis.security_constraints[0].related_hazards == ["H-2"]
        assert result.loss_analysis.security_constraints[1].related_hazards == ["H-1"]
        draft = LossAnalysis.model_validate(
            yaml.safe_load((tmp_path / "loss-analysis-draft.yaml").read_text())
        )
        canonical = LossAnalysis.model_validate(
            yaml.safe_load((tmp_path / "loss-analysis.yaml").read_text())
        )
        assert draft.security_constraints[0].related_hazards == ["H-1"]
        assert canonical.model_dump() == result.loss_analysis.model_dump()
        entries = [
            json.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        assert (
            len(
                [
                    entry
                    for entry in entries
                    if entry["stage"] == "stage_2" and entry["step"].startswith("call_")
                ]
            )
            == 4
        )

    def test_run_02_stages_execute_in_order(self, tmp_path):
        """SP1-RUN-02: stages execute in order 1b then 1a then 2."""
        client = _setup_mock_client()
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        assert isinstance(result.loss_analysis, LossAnalysis)
        assert isinstance(result.capability_profile, CapabilityProfile)
        assert isinstance(result.control_structure, ControlStructure)
        # Verify call order by checking call log stages
        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        stages = [e["stage"] for e in entries]
        assert "stage_1a" in stages
        assert "stage_1b" in stages
        assert "stage_2" in stages
        # Stage 1b should come before stage_1a (reversed ordering)
        assert stages.index("stage_1b") < stages.index("stage_1a")
        # Stage 1a should come before stage_2
        assert stages.index("stage_1a") < stages.index("stage_2")

    def test_run_03_all_calls_logged(self, tmp_path):
        """SP1-RUN-03: all LLM calls logged to calls.jsonl."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        stages = {e["stage"] for e in entries}
        assert "stage_1a" in stages
        assert "stage_1b" in stages
        assert "stage_2" in stages

    def test_run_inherits_effective_client_temperature(self, tmp_path):
        """Stage defaults do not override the resolved client configuration."""
        client = _setup_mock_client()
        client.temperature = 1.0

        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

        assert client.calls
        assert {call.temperature for call in client.calls} == {1.0}

        import yaml

        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["model_settings"]["temperature"] == 1.0

    def test_run_04_run_manifest_written(self, tmp_path):
        """SP1-RUN-04: run manifest is written with stage_summary."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest_file = tmp_path / "run-manifest.yaml"
        assert manifest_file.exists()
        import yaml

        manifest = yaml.safe_load(manifest_file.read_text())
        assert "stage_summary" in manifest
        assert "stage_1a" in manifest["stage_summary"]
        assert "stage_2" in manifest["stage_summary"]

    def test_observed_gemma_references_are_rejected_before_typed_serialization(
        self, tmp_path
    ):
        """Malformed semantic references fail the strict Call 2b boundary."""
        client = _setup_mock_client()
        from asago_scenario_generator.stpa.system_model.control_structure import (
            ControlElementSet,
        )

        client.set_response_for(
            ControlElementSet,
            _observed_gemma_control_element_set_dict(),
        )

        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

        assert result.control_structure is None
        assert result.stage_warnings == []
        assert any(
            "call_2b_control_elements" in error
            and "target requires type and id" in error
            for error in result.stage_errors
        )

    def test_observed_invalid_feedback_update_is_rejected_without_fallback(
        self, tmp_path
    ):
        """An object-shaped update fails strict Call 2b parsing."""
        from asago_scenario_generator.stpa.system_model.control_structure import (
            ControlElementSet,
        )

        client = _setup_mock_client()
        client.set_response_for(
            ControlElementSet,
            _observed_gemma_invalid_feedback_update_dict(),
        )

        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

        assert result.control_structure is None
        assert result.stage_warnings == []
        assert any(
            "call_2b_control_elements" in error
            and "requires a non-empty updates" in error
            for error in result.stage_errors
        )

    def test_run_manifest_records_profile_name(self, tmp_path):
        """A selected model profile is preserved in the manifest configuration."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            profile_name="production-profile",
        )

        import yaml

        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["model_settings"]["profile"] == "production-profile"

    def test_run_manifest_records_effective_non_secret_sampling(self, tmp_path):
        client = _setup_mock_client()
        client.max_completion_tokens = 16384
        client.temperature = 1.0
        client.top_p = 0.95
        client.top_k = 64
        client.use_guided_decoding = True
        client.api_key = "must-not-appear"
        client.extra_headers = {"Authorization": "must-not-appear"}

        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

        import yaml

        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        settings = manifest["model_settings"]
        assert settings["max_completion_tokens"] == 16384
        assert settings["temperature"] == 1.0
        assert settings["top_p"] == 0.95
        assert settings["top_k"] == 64
        assert settings["use_guided_decoding"] is True
        assert "api_key" not in settings
        assert "headers" not in settings
        assert "must-not-appear" not in (tmp_path / "run-manifest.yaml").read_text()

    def test_run_05_manifest_records_critic_findings(self, tmp_path):
        """SP1-RUN-05: run manifest records critic findings count."""
        client = _setup_mock_client(critic_findings=_valid_critic_findings_dict())
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest_file = tmp_path / "run-manifest.yaml"
        import yaml

        manifest = yaml.safe_load(manifest_file.read_text())
        assert "critic_findings" in manifest
        assert len(manifest["critic_findings"]) == 2
        assert manifest["revised"] is False
        assert len(manifest["post_revision_warnings"]) == 1
        assert manifest["post_revision_warnings"][0].startswith("Revision failed:")

    def test_run_06_manifest_records_input_hashes(self, tmp_path):
        """SP1-RUN-06: run manifest records input hashes."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest_file = tmp_path / "run-manifest.yaml"
        import yaml

        manifest = yaml.safe_load(manifest_file.read_text())
        assert "input_hashes" in manifest
        assert "use_case_text" in manifest["input_hashes"]
        assert "risk_extraction" in manifest["input_hashes"]

    def test_run_07_manifest_records_prompt_hashes(self, tmp_path):
        """SP1-RUN-07: run manifest records prompt hashes."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest_file = tmp_path / "run-manifest.yaml"
        import yaml

        manifest = yaml.safe_load(manifest_file.read_text())
        assert "prompt_hashes" in manifest
        assert "stage1a_risk_system.j2" in manifest["prompt_hashes"]
        assert "critic_system.j2" in manifest["prompt_hashes"]

    def test_run_08_stage_2_receives_loss_analysis_and_profile(self, tmp_path):
        """SP1-RUN-08: Stage 2 Call 1 receives security constraints from loss analysis."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        # Find the call_1_requirements call (Stage 2 Call 1)
        call1 = None
        for call in client.calls:
            if "SC-1" in call.user_prompt:
                call1 = call
                break
        assert call1 is not None
        assert "SC-1" in call1.user_prompt

    def test_run_09_prompt_templates_exist(self):
        """SP1-RUN-09: all prompt template files exist (updated for stage1a split)."""
        from asago_scenario_generator.stpa.system_model import PROMPTS_DIR

        expected = [
            "stage1a_risk_system.j2",
            "stage1a_risk_user.j2",
            "stage1a_gap_system.j2",
            "stage1a_gap_user.j2",
            "stage1b_system.j2",
            "stage1b_user.j2",
            "stage2_call1_system.j2",
            "stage2_call1_user.j2",
            "stage2_call2a_system.j2",
            "stage2_call2a_user.j2",
            "stage2_call2b_system.j2",
            "stage2_call2b_user.j2",
            "stage2_call3_system.j2",
            "stage2_call3_user.j2",
            "critic_system.j2",
            "critic_user.j2",
            "revision_system.j2",
            "revision_user.j2",
        ]
        for name in expected:
            assert (PROMPTS_DIR / name).exists(), f"Missing template: {name}"

    def test_run_09b_old_stage1a_templates_absent(self):
        """Old stage1a templates are absent after the split."""
        from asago_scenario_generator.stpa.system_model import PROMPTS_DIR

        assert not (PROMPTS_DIR / "stage1a_system.j2").exists()
        assert not (PROMPTS_DIR / "stage1a_user.j2").exists()

    def test_run_10_module_layout(self):
        """SP1-RUN-10: all modules exist and are importable."""
        from asago_scenario_generator.stpa.system_model import (
            loss_analysis,
            profile,
            control_structure,
            critic,
            heuristics,
            run,
        )

        assert loss_analysis is not None
        assert profile is not None
        assert control_structure is not None
        assert critic is not None
        assert heuristics is not None
        assert run is not None

    def test_run_11_internal_models_defined(self):
        """SP1-RUN-11: internal models are defined."""
        from asago_scenario_generator.stpa.system_model import (
            RequirementSet,
            Requirement,
            ResponsibilitySet,
            CriticFindings,
            CriticGap,
        )

        assert RequirementSet is not None
        assert Requirement is not None
        assert ResponsibilitySet is not None
        assert CriticFindings is not None
        assert CriticGap is not None

    def test_run_12_profile_flag_skips_stage_1b(self, tmp_path):
        """SP1-RUN-12: run with profile flag skips Stage 1b LLM call."""
        # Write a pre-built profile
        profile = Stage1Profile(
            entry_points=[
                {
                    "name": "User chat",
                    "direction": "input",
                    "controllability": "direct",
                },
            ],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC5.1", "KC6.1.1"],
            tool_inventory=[{"name": "tool1", "description": "A tool"}],
        ).to_capability_profile()
        profile_path = tmp_path / "capability-profile.yaml"
        write_yaml(profile, profile_path)

        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            profile_path=profile_path,
        )
        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        stage_1b_entries = [e for e in entries if e["stage"] == "stage_1b"]
        assert len(stage_1b_entries) == 0

    def test_run_with_external_profile_publishes_capability_artifact(self, tmp_path):
        """A pre-built profile outside the run directory is copied to outputs."""
        profile = Stage1Profile(
            entry_points=[
                {
                    "name": "User chat",
                    "direction": "input",
                    "controllability": "direct",
                },
            ],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC5.1", "KC6.1.1"],
            tool_inventory=[{"name": "tool1", "description": "A tool"}],
        ).to_capability_profile()
        input_dir = tmp_path / "inputs"
        input_dir.mkdir()
        profile_path = input_dir / "capability-profile.yaml"
        write_yaml(profile, profile_path)
        run_dir = tmp_path / "output"

        result = run_sp1(
            llm_client=_setup_mock_client(),
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=run_dir,
            profile_path=profile_path,
        )

        artifact = run_dir / "capability-profile.yaml"
        assert artifact.exists()
        assert result.capability_profile == profile

    def test_run_13_temperature_is_0_4(self, tmp_path):
        """SP1-RUN-13: all Stage 2 LLM calls use temperature 0.4."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        # All calls should have temperature 0.4
        for call in client.calls:
            assert call.temperature == 0.4

    def test_run_14_existing_tests_unaffected(self):
        """SP1-RUN-14: existing pipeline tests are unaffected (module imports work)."""
        # Just verify the import doesn't break anything
        from asago_scenario_generator.stpa.system_model import run_sp1 as _run

        assert _run is not None

    def test_run_15_manifest_with_empty_risk_cards(self, tmp_path):
        """SP1-RUN-15: manifest is written correctly when no risk cards are provided."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=[],
            run_dir=tmp_path,
        )
        manifest_file = tmp_path / "run-manifest.yaml"
        assert manifest_file.exists()
        import yaml

        manifest = yaml.safe_load(manifest_file.read_text())
        assert "input_hashes" in manifest
        assert "risk_extraction" in manifest["input_hashes"]
        # Empty risk cards still produce a hash (of empty string)
        assert manifest["input_hashes"]["risk_extraction"]


class TestPinnedLossAnalysis:
    """A caller-pinned loss analysis replaces the Stage 1a model calls."""

    @staticmethod
    def _pinned_dict() -> dict:
        from tests.stpa.sp1_helpers import valid_loss_analysis_dict

        payload = valid_loss_analysis_dict()
        payload["risk_dispositions"] = [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            }
        ]
        return payload

    def _write_pinned(self, tmp_path: Path) -> Path:
        pinned = tmp_path / "pinned-loss-analysis.yaml"
        yaml.safe_dump(self._pinned_dict(), pinned.open("w"))
        return pinned

    def test_pinned_analysis_makes_zero_stage1a_calls(self, tmp_path):
        """The pinned path validates, gates, and publishes without a model call."""
        pinned = self._write_pinned(tmp_path)
        client = _setup_mock_client()

        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            loss_analysis_path=pinned,
        )

        assert result.stage_errors == []
        assert result.loss_analysis is not None
        assert result.control_structure is not None
        stages = [entry["stage"] for entry in read_calls_jsonl(tmp_path)]
        assert "stage_1a" not in stages
        assert "stage_1b" in stages
        assert "stage_2" in stages

    def test_pinned_analysis_is_published_byte_identically(self, tmp_path):
        """The canonical artifact matches the target-derived write of the graph."""
        pinned = self._write_pinned(tmp_path)
        run_sp1(
            llm_client=_setup_mock_client(),
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            loss_analysis_path=pinned,
        )
        published = LossAnalysis.model_validate(
            yaml.safe_load((tmp_path / "loss-analysis.yaml").read_text())
        )
        expected = LossAnalysis.model_validate(yaml.safe_load(pinned.read_text()))
        assert published.model_dump() == expected.model_dump()
        gates = yaml.safe_load((tmp_path / "loss-analysis-gates.yaml").read_text())
        assert gates["passed"] is True
        assert gates["revision_attempted"] is False

    def test_pinned_analysis_records_input_digest_and_zero_calls(self, tmp_path):
        """The manifest pins the supplied bytes and reports a zero-call stage."""
        import hashlib

        pinned = self._write_pinned(tmp_path)
        run_sp1(
            llm_client=_setup_mock_client(),
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            loss_analysis_path=pinned,
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert (
            manifest["input_hashes"]["loss_analysis"]
            == hashlib.sha256(pinned.read_bytes()).hexdigest()
        )
        stage_1a = manifest["stage_summary"]["stage_1a"]
        assert stage_1a["call_count"] == 0
        assert stage_1a["source"] == "pinned"
        assert stage_1a["risk_accounting"] == "passed"
        assert stage_1a["hazard_graph_density"] == "passed"

    def test_derived_stage_reports_source_derived(self, tmp_path):
        """The unpinned manifest keeps its call count and gains source: derived."""
        run_sp1(
            llm_client=_setup_mock_client(),
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        stage_1a = manifest["stage_summary"]["stage_1a"]
        assert stage_1a["source"] == "derived"
        assert stage_1a["call_count"] >= 2

    def test_derived_run_records_the_advisory_risk_coverage_review(self, tmp_path):
        """The derived path runs the review, records it, and writes its artifact."""
        run_sp1(
            llm_client=_setup_mock_client(),
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        stage_1a = manifest["stage_summary"]["stage_1a"]
        review = stage_1a["risk_coverage_review"]
        assert review["status"] == "completed"
        assert review["call_count"] == 1
        assert review["failure_reason"] is None
        assert review["reviewed_loss_analysis_digest"]
        # The review call is counted in Stage 1a alongside the two derivations.
        assert stage_1a["call_count"] == 3
        assert (tmp_path / "loss-analysis-risk-coverage-review.yaml").is_file()
        steps = [entry["step"] for entry in read_calls_jsonl(tmp_path)]
        assert "risk_coverage_review" in steps

    def test_manifest_records_the_post_review_graph_digest(self, tmp_path):
        """Target-blind Call 3 may reword the graph after the review.

        The manifest keeps the reviewed digest in Stage 1a and records the
        final published digest in Stage 2 when the two differ.
        """
        import hashlib

        client = _setup_mock_client()
        client.set_response_for(CoordinationAnalysis, _reviewed_coordination_for_run())
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        reviewed = manifest["stage_summary"]["stage_1a"]["risk_coverage_review"][
            "reviewed_loss_analysis_digest"
        ]
        published = hashlib.sha256(
            (tmp_path / "loss-analysis.yaml").read_bytes()
        ).hexdigest()
        assert reviewed != published
        assert (
            manifest["stage_summary"]["stage_2"]["post_review_loss_analysis_digest"]
            == published
        )

    def test_pinned_density_failure_is_fatal_without_revision(self, tmp_path):
        """A failing pinned graph is a fatal stage error with zero model calls."""
        broken = self._pinned_dict()
        broken["security_constraints"][0]["related_hazards"] = []
        pinned = tmp_path / "pinned-loss-analysis.yaml"
        yaml.safe_dump(broken, pinned.open("w"))
        client = _setup_mock_client()

        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            loss_analysis_path=pinned,
        )

        assert result.loss_analysis is None
        assert result.control_structure is None
        assert any(
            "hazard graph density gate failed" in error for error in result.stage_errors
        )
        assert "stage_1a" not in [
            entry["stage"] for entry in read_calls_jsonl(tmp_path)
        ]
        gates = yaml.safe_load((tmp_path / "loss-analysis-gates.yaml").read_text())
        assert gates["passed"] is False
        assert gates["revision_attempted"] is False
        assert gates["failing_checks"]
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        stage_1a = manifest["stage_summary"]["stage_1a"]
        assert stage_1a["hazard_graph_density"] == "failed"
        assert stage_1a["call_count"] == 0

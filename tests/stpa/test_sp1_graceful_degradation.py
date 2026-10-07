"""Unit tests for SP1 graceful degradation — recoverable and stage-error scenarios.

Covers SP1-GD-01 through SP1-GD-15 from the Gherkin feature files:
  - features/sp1_graceful_degradation_recoverable.feature
  - features/sp1_graceful_degradation_stage_error.feature

Tests use MockLLMClient configured to return invalid responses or raise
exceptions, then verify graceful degradation behavior.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossAnalysisDraft,
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
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    has_unjustified_gaps,
    run_completeness_critic,
    run_revision,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.profile import derive_capability_profile
from asago_scenario_generator.stpa.system_model.run import SP1RunResult, run_sp1
from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    valid_critic_findings_dict_no_gaps,
    valid_control_element_set_dict,
    valid_empty_coordination_analysis_dict,
    valid_gap_draft_dict,
    valid_risk_draft_dict,
    valid_stage1_profile_dict,
    valid_requirement_set_dict,
    valid_responsibility_set_dict,
)
import yaml
from pydantic import BaseModel
from asago_scenario_generator.stpa.infra.call_log import make_call_log_entry
from tests.stpa.test_critic_id_sanitization import _make_control_structure


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Unauthorized transaction",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            )
        ],
        use_case_losses=[
            Loss(
                loss_id="L-2",
                description="Loss of trust",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(
                hazard_id="H-1", description="Hazard", related_losses=["L-1", "L-2"]
            ),
        ],
        security_constraints=[
            SecurityConstraint(constraint_id="SC-1", rule="C", related_hazards=["H-1"]),
        ],
    )


def _make_capability_profile() -> CapabilityProfile:
    return Stage1Profile(
        entry_points=[
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        confidence="medium",
        kc_subcodes=["KC1.1", "KC5.1", "KC6.1.1"],
        tool_inventory=[{"name": "tool1", "description": "A tool"}],
    ).to_capability_profile()


def _valid_loss_analysis_dict() -> dict:
    """Risk draft for the risk_derivation call (shared density-safe fixture)."""
    return valid_risk_draft_dict()


def _valid_gap_draft_dict() -> dict:
    """Gap draft for the gap_analysis call (shared density-safe fixture)."""
    return valid_gap_draft_dict()


def _valid_control_structure_dict() -> dict:
    rs = valid_responsibility_set_dict()
    return {
        "responsibilities": rs["responsibilities"],
        "controlled_processes": [],
        "coordination_links": [],
    }


def _valid_critic_findings_dict_with_unjustified() -> dict:
    return {
        "gaps": [
            {
                "gap_type": "missing_responsibility",
                "description": "Missing input validation",
                "related_attack_path": "Attacker sends crafted input",
                "suggested_remedy": "Add input validation",
            },
        ],
        "checklist_results": {
            "Input validation": "absent_unjustified",
            "Authorization": "present",
        },
        "taxonomy_probe_results": {},
    }


def _setup_valid_mock_client() -> MockLLMClient:
    """Set up a mock LLM client with valid responses for all stages."""
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [_valid_loss_analysis_dict(), _valid_gap_draft_dict()],
    )
    client.set_response_for(Stage1Profile, valid_stage1_profile_dict())
    client.set_response_for(RequirementSet, valid_requirement_set_dict())
    client.set_response_for(ResponsibilitySet, valid_responsibility_set_dict())
    client.set_response_for(ControlElementSet, valid_control_element_set_dict())
    client.set_response_for(
        CoordinationAnalysis,
        valid_empty_coordination_analysis_dict(constraint_ids=("SC-1", "SC-2")),
    )
    client.set_response_for(CriticFindings, valid_critic_findings_dict_no_gaps())
    return client


# ---------------------------------------------------------------------------
# SP1-GD-01 through SP1-GD-07: Recoverable failures (critic + revision)
# ---------------------------------------------------------------------------


class TestRevisionGracefulDegradation:
    """SP1-GD-01 through SP1-GD-03: revision failure returns pre-revision CS."""

    def test_gd_01_revision_validation_failure_returns_pre_revision_cs(self, tmp_path):
        """SP1-GD-01: revision validation failure returns pre-revision CS with warning."""
        client = MockLLMClient()
        client.set_invalid_response_for(ControlStructure)
        cs = _make_control_structure()
        findings = CriticFindings.model_validate(
            _valid_critic_findings_dict_with_unjustified()
        )
        revised, warnings = run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        # Pre-revision CS returned
        assert revised is cs
        # Warning includes revision failure message
        assert any("Revision failed" in w for w in warnings)

    def test_gd_02_revision_failure_logs_with_success_false(self, tmp_path):
        """SP1-GD-02: revision failure logs the failed call with success=false."""
        client = MockLLMClient()
        client.set_invalid_response_for(ControlStructure)
        cs = _make_control_structure()
        findings = CriticFindings.model_validate(
            _valid_critic_findings_dict_with_unjustified()
        )
        run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        entries = read_calls_jsonl(tmp_path)
        rev_entries = [e for e in entries if e["step"] == "revision"]
        assert len(rev_entries) == 2
        assert all(entry["stage"] == "stage_2" for entry in rev_entries)
        assert all(entry["success"] is False for entry in rev_entries)
        assert all("error" in entry for entry in rev_entries)

    def test_gd_03_revision_llm_exception_returns_pre_revision_cs(self, tmp_path):
        """SP1-GD-03: revision LLM exception returns pre-revision CS with warning."""
        client = MockLLMClient()
        client.set_exception_for(ControlStructure, RuntimeError("API timeout"))
        cs = _make_control_structure()
        findings = CriticFindings.model_validate(
            _valid_critic_findings_dict_with_unjustified()
        )
        revised, warnings = run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        assert revised is cs
        assert any("Revision failed" in w for w in warnings)
        entries = read_calls_jsonl(tmp_path)
        rev_entries = [e for e in entries if e["step"] == "revision"]
        assert len(rev_entries) == 2
        assert all(entry["stage"] == "stage_2" for entry in rev_entries)
        assert all(entry["success"] is False for entry in rev_entries)
        assert all("error" in entry for entry in rev_entries)


class TestCriticGracefulDegradation:
    """SP1-GD-04 through SP1-GD-07: critic failure returns empty findings."""

    def test_gd_04_critic_validation_failure_returns_empty_findings(self, tmp_path):
        """SP1-GD-04: critic validation failure returns empty CriticFindings."""
        client = MockLLMClient()
        client.set_invalid_response_for(CriticFindings)
        findings = run_completeness_critic(
            llm_client=client,
            control_structure=_make_control_structure(),
            capability_profile=_make_capability_profile(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        assert isinstance(findings, CriticFindings)
        assert len(findings.gaps) == 0
        assert findings.checklist_results == {}
        assert findings.taxonomy_probe_results == {}

    def test_gd_05_critic_failure_logs_with_success_false(self, tmp_path):
        """SP1-GD-05: critic failure logs the failed call with success=false."""
        client = MockLLMClient()
        client.set_invalid_response_for(CriticFindings)
        run_completeness_critic(
            llm_client=client,
            control_structure=_make_control_structure(),
            capability_profile=_make_capability_profile(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        entries = read_calls_jsonl(tmp_path)
        critic_entries = [e for e in entries if e["step"] == "critic"]
        assert len(critic_entries) == 1
        assert critic_entries[0]["stage"] == "stage_2"
        assert critic_entries[0]["success"] is False
        assert "error" in critic_entries[0]

    def test_gd_06_critic_failure_does_not_trigger_revision(self, tmp_path):
        """SP1-GD-06: critic failure (empty findings) does not trigger revision."""
        client = MockLLMClient()
        client.set_invalid_response_for(CriticFindings)
        findings = run_completeness_critic(
            llm_client=client,
            control_structure=_make_control_structure(),
            capability_profile=_make_capability_profile(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        # Empty findings → has_unjustified_gaps is False
        assert has_unjustified_gaps(findings) is False

    def test_gd_07_critic_llm_exception_returns_empty_findings(self, tmp_path):
        """SP1-GD-07: critic LLM exception returns empty CriticFindings."""
        client = MockLLMClient()
        client.set_exception_for(CriticFindings, RuntimeError("API error"))
        findings = run_completeness_critic(
            llm_client=client,
            control_structure=_make_control_structure(),
            capability_profile=_make_capability_profile(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        assert isinstance(findings, CriticFindings)
        assert len(findings.gaps) == 0
        entries = read_calls_jsonl(tmp_path)
        critic_entries = [e for e in entries if e["step"] == "critic"]
        assert len(critic_entries) == 1
        assert critic_entries[0]["stage"] == "stage_2"
        assert critic_entries[0]["success"] is False
        assert "error" in critic_entries[0]


# ---------------------------------------------------------------------------
# SP1-GD-08: Derivation stage failure raises StageError with context
# ---------------------------------------------------------------------------


class TestDerivationStageFailure:
    """SP1-GD-08: derivation stage failure raises StageError with stage/step context."""

    @pytest.mark.parametrize(
        "stage, stage_name, step_name, setup_fn",
        [
            ("stage_1a", "stage_1a", "risk_derivation", "_setup_stage_1a_failure"),
            ("stage_1b", "stage_1b", "capability_profile", "_setup_stage_1b_failure"),
            (
                "stage_2_call_1",
                "stage_2",
                "call_1_requirements",
                "_setup_stage_2_call_1_failure",
            ),
            (
                "stage_2_call_2a",
                "stage_2",
                "call_2a_responsibilities",
                "_setup_stage_2_call_2_failure",
            ),
            (
                "stage_2_call_2b",
                "stage_2",
                "call_2b_control_elements",
                "_setup_stage_2_call_2b_failure",
            ),
            (
                "stage_2_call_3",
                "stage_2",
                "call_3_coordination",
                "_setup_stage_2_call_3_failure",
            ),
        ],
    )
    def test_gd_08_derivation_failure_raises_stage_error(
        self, stage, stage_name, step_name, setup_fn, tmp_path, request
    ):
        """SP1-GD-08: each derivation stage raises StageError on invalid response."""
        client, invoke_fn = getattr(self, setup_fn)(tmp_path)
        with pytest.raises(StageError) as exc_info:
            invoke_fn(client, tmp_path)
        assert exc_info.value.stage == stage_name
        assert exc_info.value.step == step_name

        # Verify the failed call is logged with success=false
        entries = read_calls_jsonl(tmp_path)
        failed = [e for e in entries if e.get("success") is False]
        assert len(failed) >= 1
        assert any(e["stage"] == stage_name and e["step"] == step_name for e in failed)

    def _setup_stage_1a_failure(self, tmp_path):
        client = MockLLMClient()
        client.set_invalid_response_for(LossAnalysisDraft)

        def invoke(c, d):
            derive_loss_analysis(
                llm_client=c,
                use_case_text="Test",
                risk_cards=make_risk_cards(),
                run_dir=d,
            )

        return client, invoke

    def _setup_stage_1b_failure(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_valid_loss_analysis_dict(), _valid_gap_draft_dict()],
        )
        client.set_invalid_response_for(Stage1Profile)

        def invoke(c, d):
            derive_capability_profile(
                llm_client=c,
                use_case_text="Test",
                run_dir=d,
            )

        return client, invoke

    def _setup_stage_2_call_1_failure(self, tmp_path):
        client = MockLLMClient()
        client.set_invalid_response_for(RequirementSet)

        def invoke(c, d):
            derive_control_structure(
                llm_client=c,
                use_case_text="Test",
                loss_analysis=_make_loss_analysis(),
                run_dir=d,
            )

        return client, invoke

    def _setup_stage_2_call_2_failure(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(RequirementSet, valid_requirement_set_dict())
        client.set_invalid_response_for(ResponsibilitySet)

        def invoke(c, d):
            derive_control_structure(
                llm_client=c,
                use_case_text="Test",
                loss_analysis=_make_loss_analysis(),
                run_dir=d,
            )

        return client, invoke

    def _setup_stage_2_call_2b_failure(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(RequirementSet, valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, valid_responsibility_set_dict())
        client.set_invalid_response_for(ControlElementSet)

        def invoke(c, d):
            derive_control_structure(
                llm_client=c,
                use_case_text="Test",
                loss_analysis=_make_loss_analysis(),
                run_dir=d,
            )

        return client, invoke

    def _setup_stage_2_call_3_failure(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(RequirementSet, valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, valid_responsibility_set_dict())
        client.set_response_for(ControlElementSet, valid_control_element_set_dict())
        client.set_invalid_response_for(CoordinationAnalysis)

        def invoke(c, d):
            derive_control_structure(
                llm_client=c,
                use_case_text="Test",
                loss_analysis=_make_loss_analysis(),
                run_dir=d,
            )

        return client, invoke


# ---------------------------------------------------------------------------
# SP1-GD-09 through SP1-GD-15: Run orchestration with stage failures
# ---------------------------------------------------------------------------


class TestRunOrchestrationPartialFailure:
    """SP1-GD-09 through SP1-GD-15: run returns partial results on stage failure."""

    def test_gd_09_stage_1a_failure_loss_analysis_none(self, tmp_path):
        """SP1-GD-09: Stage 1a failure → loss_analysis None, CS None.

        With the new ordering (1b before 1a), Stage 1b succeeds before
        Stage 1a fails, so capability_profile is preserved.
        """
        client = _setup_valid_mock_client()
        client.set_invalid_response_for(LossAnalysisDraft)
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        assert isinstance(result, SP1RunResult)
        assert len(result.stage_errors) >= 1
        assert any("stage_1a" in e for e in result.stage_errors)
        assert result.loss_analysis is None
        assert result.control_structure is None
        # capability_profile is preserved (1b ran before 1a)
        assert result.capability_profile is not None
        # Manifest still written
        assert (tmp_path / "run-manifest.yaml").exists()

    def test_gd_10_stage_1b_failure_preserves_loss_analysis(self, tmp_path):
        """SP1-GD-10: Stage 1b failure → profile/CS None, loss_analysis preserved.

        With the new ordering (1b before 1a), Stage 1b fails first, then
        Stage 1a runs with capability_profile=None (still produces loss_analysis).
        """
        client = _setup_valid_mock_client()
        client.set_invalid_response_for(Stage1Profile)
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        assert isinstance(result, SP1RunResult)
        assert any("stage_1b" in e for e in result.stage_errors)
        assert result.loss_analysis is not None
        assert result.capability_profile is None
        assert result.control_structure is None
        assert (tmp_path / "run-manifest.yaml").exists()

    def test_gd_11_stage_2_failure_preserves_loss_and_profile(self, tmp_path):
        """SP1-GD-11: Stage 2 failure → loss_analysis + profile preserved, CS None."""
        client = _setup_valid_mock_client()
        # Make Call 1 fail (first Stage 2 call)
        client.set_invalid_response_for(RequirementSet)
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        assert isinstance(result, SP1RunResult)
        assert any("stage_2" in e for e in result.stage_errors)
        assert result.loss_analysis is not None
        assert result.capability_profile is not None
        assert result.control_structure is None
        assert result.revised is False
        assert (tmp_path / "run-manifest.yaml").exists()

    def test_gd_12_failed_derivation_call_logged_with_success_false(self, tmp_path):
        """SP1-GD-12: failed derivation call logged with success=false and error."""
        client = _setup_valid_mock_client()
        client.set_invalid_response_for(LossAnalysisDraft)
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        entries = read_calls_jsonl(tmp_path)
        failed = [e for e in entries if e.get("success") is False]
        assert len(failed) >= 1
        stage_1a_failed = [e for e in failed if e["stage"] == "stage_1a"]
        # Stage 1a never retries an undecodable body (owner correction
        # 2026-09-12): exactly one failed attempt, then the typed terminal.
        assert len(stage_1a_failed) == 1
        assert [entry["step"] for entry in stage_1a_failed] == ["risk_derivation"]
        assert all("error" in entry for entry in stage_1a_failed)

    def test_gd_13_pipeline_does_not_crash_on_stage_2_failure(self, tmp_path):
        """SP1-GD-13: pipeline does not raise on Stage 2 validation failure."""
        client = _setup_valid_mock_client()
        client.set_invalid_response_for(RequirementSet)
        # Should not raise
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        assert isinstance(result, SP1RunResult)

    def test_gd_14_llm_exception_raises_stage_error_and_logs(self, tmp_path):
        """SP1-GD-14: LLM RuntimeError during stage_1a → partial result with stage_error."""
        client = _setup_valid_mock_client()
        client.set_exception_for(LossAnalysisDraft, RuntimeError("Connection refused"))
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        assert isinstance(result, SP1RunResult)
        assert any("stage_1a" in e for e in result.stage_errors)
        entries = read_calls_jsonl(tmp_path)
        failed = [e for e in entries if e.get("success") is False]
        assert len(failed) >= 1

    def test_gd_15_manifest_records_stage_errors(self, tmp_path):
        """SP1-GD-15: run manifest records stage_errors on partial failure."""
        client = _setup_valid_mock_client()
        client.set_invalid_response_for(Stage1Profile)
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert "stage_errors" in manifest
        assert any("stage_1b" in e for e in manifest["stage_errors"])


# ---------------------------------------------------------------------------
# Mutation-killing tests: fallback values when result is None
# ---------------------------------------------------------------------------


class TestSafeLlmCallFallbackValues:
    """When the LLM call raises before returning a result, the failure log
    entry must record zero token counts and zero duration.

    Kills the ``0 -> 1`` mutants on the fallback expressions in
    ``call_with_policy``'s except block.
    """

    def test_exception_before_result_logs_zero_tokens(self, tmp_path):
        """LLM exception with no result → log entry has prompt_tokens=0,
        completion_tokens=0, duration_ms=0."""

        class _M(BaseModel):
            val: int = 0

        client = MockLLMClient()
        client.set_exception_for(_M, RuntimeError("connection refused"))

        call_with_policy(
            llm_client=client,
            system_prompt="s",
            user_prompt="u",
            response_format=_M,
            run_dir=tmp_path,
            stage="stage_1a",
            step="loss_analysis",
            policy=CorrectionPolicy(),
        )
        entries = read_calls_jsonl(tmp_path)
        assert len(entries) == 1
        assert entries[0]["success"] is False
        assert entries[0]["prompt_tokens"] is None
        assert entries[0]["completion_tokens"] is None
        assert entries[0]["usage"]["status"] == "unavailable"
        assert entries[0]["duration_ms"] == 0


# ---------------------------------------------------------------------------
# Mutation-killing test: timestamp defaults to current time
# ---------------------------------------------------------------------------


class TestCallLogTimestampDefault:
    """``make_call_log_entry`` must set a non-None timestamp when not provided.

    Kills the ``or -> and`` mutant on the timestamp fallback expression.
    """

    def test_timestamp_not_none_when_not_provided(self):
        """When timestamp is not provided, the entry's timestamp is not None."""
        entry = make_call_log_entry(
            stage="stage_1a",
            step="loss_analysis",
            model="test-model",
        )
        assert entry["timestamp"] is not None
        assert len(entry["timestamp"]) > 0

"""Unit tests for SP1 assembly fallback — ControlElementSet validation failures.

Covers MergeFallback-01 through MergeFallback-10 from the fallback QA contract:
  tests/stpa/qa/sp1_merge_fallback_qa.md

When _assemble_with_fallback() fails because the Call 2b ControlElementSet
contains invalid cross-references, the pipeline falls back to building a
ControlStructure from the ResponsibilitySet alone (without coordination
links). The fallback preserves Call 2a responsibilities and controlled
processes, is written to control-structure.yaml, and the pipeline
completes without crashing. The assembly failure is logged and recorded
in stage_errors.
"""

from __future__ import annotations

import yaml

from asago_scenario_generator.models.capability_profile import Stage1Profile
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
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
from asago_scenario_generator.stpa.system_model.run import SP1RunResult, run_sp1
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    read_calls_jsonl,
    valid_critic_findings_dict_no_gaps,
    valid_empty_coordination_analysis_dict,
    valid_stage1_profile_dict,
)


# ---------------------------------------------------------------------------
# Shared helpers
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
            SecurityConstraint(
                constraint_id="SC-1", description="C", related_hazards=["H-1"]
            ),
            SecurityConstraint(
                constraint_id="SC-2", description="C2", related_hazards=["H-1"]
            ),
        ],
    )


def _valid_loss_analysis_dict() -> dict:
    """Risk draft for the risk_derivation call."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [],
        "security_constraints": [],
    }


def _valid_gap_draft_dict() -> dict:
    """Gap draft for the gap_analysis call."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [
            {
                "loss_id": "L-1",
                "description": "Loss",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        ],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "Hazard",
                "related_losses": ["L-1"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "description": "C",
                "related_hazards": ["H-1"],
            },
            {
                "constraint_id": "SC-2",
                "description": "C2",
                "related_hazards": ["H-1"],
            },
        ],
    }


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
    """ResponsibilitySet with two responsibilities (RCs and PMs only)."""
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Payment authorization controller",
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
                "responsibility_constraints": [],
                "process_model_parts": [
                    {"pm_id": "PM-2-1", "description": "Response content state"}
                ],
            },
        ],
    }


def _valid_control_element_set_dict() -> dict:
    """ControlElementSet matching the responsibilities (valid cross-refs)."""
    return {
        "control_actions": [
            {"ca_id": "CA-1-1", "description": "Execute payment"},
            {"ca_id": "CA-2-1", "description": "Send response"},
        ],
        "feedback_channels": [
            {
                "fb_id": "FB-1-1",
                "description": "Transaction result",
                "updates": "PM-1-1",
            },
            {
                "fb_id": "FB-2-1",
                "description": "Response confirmation",
                "updates": "PM-2-1",
                "source": {"type": "responsibility", "id": "RESP-2"},
            },
        ],
        "controlled_processes": [],
    }


def _valid_control_element_set_dict_with_cp() -> dict:
    """ControlElementSet with a controlled process CP-1 and valid cross-refs."""
    return {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Execute payment",
                "target": {"type": "controlled_process", "id": "CP-1"},
            },
            {"ca_id": "CA-2-1", "description": "Send response"},
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


def _namespace_confusion_control_element_set() -> dict:
    """ControlElementSet with namespace confusion: FB source uses a
    FeedbackChannel ID (FB-1-1) as a ControlledProcess ID.

    This triggers a ValidationError during _assemble_control_structure
    because 'FB-1-1' is not in the controlled_processes set.
    """
    return {
        "control_actions": [],
        "feedback_channels": [
            {
                "fb_id": "FB-1-1",
                "description": "FB",
                "updates": "PM-1-1",
                "source": {"type": "controlled_process", "id": "FB-1-1"},
            }
        ],
        "controlled_processes": [],
    }


def _valid_coordination_analysis_dict() -> dict:
    """A valid CoordinationAnalysis with coordination link CL-1."""
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


def _setup_stage2_client(
    resp_set_dict: dict | None = None,
    control_element_set_dict: dict | None = None,
    coordination_analysis_dict: dict | None = None,
) -> MockLLMClient:
    """Set up a mock LLM client for Stage 2 with valid Call 1/2a and a
    configurable Call 2b ControlElementSet and Call 3 CoordinationAnalysis."""
    client = MockLLMClient()
    client.set_response_for(RequirementSet, _valid_requirement_set_dict())
    client.set_response_for(
        ResponsibilitySet, resp_set_dict or _valid_responsibility_set_dict()
    )
    client.set_response_for(
        ControlElementSet,
        control_element_set_dict or _namespace_confusion_control_element_set(),
    )
    client.set_response_for(
        CoordinationAnalysis,
        coordination_analysis_dict or valid_empty_coordination_analysis_dict(),
    )
    return client


def _setup_full_run_client(
    resp_set_dict: dict | None = None,
    control_element_set_dict: dict | None = None,
    coordination_analysis_dict: dict | None = None,
) -> MockLLMClient:
    """Set up a mock LLM client for a full SP1 run with valid Stage 1a/1b
    and a configurable Stage 2 ControlElementSet."""
    from asago_scenario_generator.stpa.system_model.critic import CriticFindings

    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [_valid_loss_analysis_dict(), _valid_gap_draft_dict()],
    )
    client.set_response_for(Stage1Profile, valid_stage1_profile_dict())
    client.set_response_for(RequirementSet, _valid_requirement_set_dict())
    client.set_response_for(
        ResponsibilitySet, resp_set_dict or _valid_responsibility_set_dict()
    )
    client.set_response_for(
        ControlElementSet,
        control_element_set_dict or _namespace_confusion_control_element_set(),
    )
    client.set_response_for(
        CoordinationAnalysis,
        coordination_analysis_dict or valid_empty_coordination_analysis_dict(),
    )
    client.set_response_for(CriticFindings, valid_critic_findings_dict_no_gaps())
    return client


# ---------------------------------------------------------------------------
# MergeFallback-01: Invalid ControlElementSet triggers fallback
# ---------------------------------------------------------------------------


class TestMergeFallback01FallbackTriggered:
    """MergeFallback-01: invalid ControlElementSet triggers assembly fallback."""

    def test_merge_fallback_01_invalid_control_element_set_triggers_fallback(
        self, tmp_path
    ):
        """Invalid ControlElementSet produces a valid ControlStructure without crashing."""
        client = _setup_stage2_client()
        cs, warnings = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        assert isinstance(cs, ControlStructure)
        assert len(cs.responsibilities) == 2
        # The assembly produced warnings
        assert len(warnings) >= 1
        assert "assemble_control_structure" in warnings[0]


# ---------------------------------------------------------------------------
# MergeFallback-02: Fallback ControlStructure has empty coordination_links
# ---------------------------------------------------------------------------


class TestMergeFallback02EmptyCoordinationLinks:
    """MergeFallback-02: fallback has no coordination links (empty CoordinationAnalysis)."""

    def test_merge_fallback_02_empty_coordination_links(self, tmp_path):
        client = _setup_stage2_client()
        cs, _ = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        assert cs.coordination_links == []


# ---------------------------------------------------------------------------
# MergeFallback-03: Fallback preserves responsibilities from Call 2a
# ---------------------------------------------------------------------------


class TestMergeFallback03PreservesResponsibilities:
    """MergeFallback-03: fallback contains RESP-1 and RESP-2 from Call 2a."""

    def test_merge_fallback_03_preserves_responsibilities(self, tmp_path):
        client = _setup_stage2_client()
        cs, _ = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        resp_ids = {r.resp_id for r in cs.responsibilities}
        assert "RESP-1" in resp_ids
        assert "RESP-2" in resp_ids
        resp1 = next(r for r in cs.responsibilities if r.resp_id == "RESP-1")
        assert resp1.description == "Payment authorization controller"


# ---------------------------------------------------------------------------
# MergeFallback-04: Fallback preserves controlled_processes from Call 2b
# ---------------------------------------------------------------------------


class TestMergeFallback04PreservesControlledProcesses:
    """MergeFallback-04: fallback contains CP-1 from Call 2b."""

    def test_merge_fallback_04_preserves_controlled_processes(self, tmp_path):
        client = _setup_stage2_client(
            control_element_set_dict=_valid_control_element_set_dict_with_cp(),
        )
        cs, _ = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        cp_ids = {cp.cp_id for cp in cs.controlled_processes}
        assert "CP-1" in cp_ids


# ---------------------------------------------------------------------------
# MergeFallback-05: Assembly failure is logged to calls.jsonl
# ---------------------------------------------------------------------------


class TestMergeFallback05FailureLogged:
    """MergeFallback-05: assembly failure logged with success=false."""

    def test_merge_fallback_05_failure_logged_to_calls_jsonl(self, tmp_path):
        client = _setup_stage2_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        entries = read_calls_jsonl(tmp_path)
        assemble_entries = [
            e for e in entries if e["step"] == "assemble_control_structure"
        ]
        assert len(assemble_entries) == 1
        assert assemble_entries[0]["stage"] == "stage_2"
        assert assemble_entries[0]["success"] is False
        assert "error" in assemble_entries[0]
        assert assemble_entries[0]["error"]  # non-empty


# ---------------------------------------------------------------------------
# MergeFallback-06: Assembly repair recorded in run manifest stage_warnings
# ---------------------------------------------------------------------------


class TestMergeFallback06ManifestStageErrors:
    """MergeFallback-06: repaired assembly appears in manifest warnings."""

    def test_merge_fallback_06_manifest_records_assembly_failure(self, tmp_path):
        client = _setup_full_run_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_errors"] == []
        assert any(
            "assemble_control_structure" in warning
            for warning in manifest["stage_warnings"]
        )


# ---------------------------------------------------------------------------
# MergeFallback-07: Fallback ControlStructure written to control-structure.yaml
# ---------------------------------------------------------------------------


class TestMergeFallback07YamlWritten:
    """MergeFallback-07: fallback is written to control-structure.yaml."""

    def test_merge_fallback_07_yaml_written_and_valid(self, tmp_path):
        client = _setup_stage2_client()
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
        assert loaded.coordination_links == []


# ---------------------------------------------------------------------------
# MergeFallback-08: Fallback passes through heuristics
# ---------------------------------------------------------------------------


class TestMergeFallback08HeuristicsPass:
    """MergeFallback-08: fallback passes through heuristics without crashing."""

    def test_merge_fallback_08_fallback_passes_heuristics(self, tmp_path):
        client = _setup_full_run_client()
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        assert result.control_structure is not None
        assert isinstance(result.heuristic_errors, list)
        assert isinstance(result.heuristic_warnings, list)


# ---------------------------------------------------------------------------
# MergeFallback-09: Pipeline does not crash on assembly failure during full run
# ---------------------------------------------------------------------------


class TestMergeFallback09NoCrashFullRun:
    """MergeFallback-09: full SP1 run preserves usable fallback warnings."""

    def test_merge_fallback_09_pipeline_completes_with_fallback(self, tmp_path):
        client = _setup_full_run_client()
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        assert isinstance(result, SP1RunResult)
        assert result.control_structure is not None
        assert result.stage_errors == []
        assert any(
            "assemble_control_structure" in warning for warning in result.stage_warnings
        )

    def test_repaired_assembly_is_warning_not_fatal_stage_error(self, tmp_path):
        """A validated fallback artifact is usable despite repair diagnostics."""
        client = _setup_full_run_client()

        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert result.control_structure is not None
        assert result.stage_errors == []
        assert any(
            "assemble_control_structure" in warning for warning in result.stage_warnings
        )
        assert manifest["stage_errors"] == []
        assert any(
            "assemble_control_structure" in warning
            for warning in manifest["stage_warnings"]
        )


# ---------------------------------------------------------------------------
# MergeFallback-10: Successful assembly produces full ControlStructure
# ---------------------------------------------------------------------------


class TestMergeFallback10SuccessfulAssembly:
    """MergeFallback-10: normal case — full ControlStructure with links."""

    def test_merge_fallback_10_successful_assembly_produces_full_cs(self, tmp_path):
        client = _setup_stage2_client(
            control_element_set_dict=_valid_control_element_set_dict(),
            coordination_analysis_dict=_valid_coordination_analysis_dict(),
        )
        cs, warnings = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        assert isinstance(cs, ControlStructure)
        # Coordination link CL-1 is present
        cl_ids = {cl.link_id for cl in cs.coordination_links}
        assert "CL-1" in cl_ids
        cl = next(cl for cl in cs.coordination_links if cl.link_id == "CL-1")
        assert cl.source == "RESP-1"
        assert cl.target == "RESP-2"
        # No assembly warnings
        assert warnings == []
        # No assembly failure logged
        entries = read_calls_jsonl(tmp_path)
        assemble_entries = [
            e for e in entries if e["step"] == "assemble_control_structure"
        ]
        assert len(assemble_entries) == 0

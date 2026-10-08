"""Stage 2 assembly and coordination-link failures stop the stage.

When the assembled control structure or the Call 3 coordination links fail
validation, Stage 2 logs the failed step to ``calls.jsonl`` and raises a
``StageError`` that names every unresolved reference.  No degraded control
structure is written.
"""

from __future__ import annotations

import pytest
import yaml

from asago_scenario_generator.models.capability_profile import Stage1Profile
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.unvalidated_decode import (
    construct_model_unvalidated,
)
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
    _add_coordination_links,
    _assemble_stage2_structure,
    derive_control_structure,
)
from asago_scenario_generator.stpa.system_model.run import SP1RunResult, run_sp1
from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    valid_critic_findings_dict_no_gaps,
    valid_empty_coordination_analysis_dict,
    valid_stage1_profile_dict,
)
from asago_scenario_generator.stpa.system_model.critic import CriticFindings
from tests.helpers.sp1_control_structure import _valid_requirement_set_dict


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_loss_analysis() -> LossAnalysis:
    """One hazard, so the Call 3 semantic review needs one hazard entry."""
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


def _valid_loss_analysis_dict() -> dict:
    """Risk draft for the risk_derivation call."""
    draft = _valid_gap_draft_dict()
    loss = draft["use_case_losses"].pop()
    loss.update(provenance="risk_card", source_risk_cards=["atlas-001"])
    draft["risk_card_losses"] = [loss]
    draft["risk_dispositions"] = [
        {
            "risk_ref": "atlas-001",
            "disposition": "cited",
            "loss_ids": ["L-1"],
            "reason": None,
        }
    ]
    return draft


def _valid_gap_draft_dict() -> dict:
    """Gap draft for the gap_analysis call.

    Hazard and constraint wording shares the "payment record" subject phrase,
    so the merged graph has no subject-phrase advisory.
    """
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
                "description": ("The payment record is exposed without authorization."),
                "related_losses": ["L-1"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": (
                    "The payment record must stay protected for the "
                    "authorized customer."
                ),
                "related_hazards": ["H-1"],
                "applies_when": [],
            },
            {
                "constraint_id": "SC-2",
                "rule": ("The payment record must never reach an outside party."),
                "related_hazards": ["H-1"],
                "applies_when": [],
            },
        ],
    }


def _valid_responsibility_set_dict() -> dict:
    """ResponsibilitySet with two responsibilities (RCs and PMs only)."""
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Payment authorization controller",
                "security_constraint_refs": ["SC-1", "SC-2"],
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
                "security_constraint_refs": [],
                "responsibility_constraints": [],
                "process_model_parts": [
                    {"pm_id": "PM-2-1", "description": "Response content state"}
                ],
            },
        ],
    }


def _fallback_responsibility_set_dict() -> dict:
    """Call 2a fixture with a typed-but-unresolvable PM feedback source.

    Call 2b remains a strict, schema-complete response. The invalid reference
    is retained in Call 2a so these tests exercise the in-memory assembly
    fallback seam without asking Call 2b parsing to accept invalid provider
    data.
    """
    response = _valid_responsibility_set_dict()
    response["responsibilities"][0]["process_model_parts"][0]["feedback_source"] = {
        "type": "controlled_process",
        "id": "CP-99",
    }
    return response


def _valid_control_element_set_dict() -> dict:
    """ControlElementSet matching the responsibilities (valid cross-refs)."""
    return {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Execute payment",
                "target": {"type": "responsibility", "id": "RESP-1"},
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
                "source": {"type": "responsibility", "id": "RESP-1"},
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
                    "rationale": "The first supplied rule retains its hazard relation.",
                },
                {
                    "constraint_id": "SC-2",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "related_hazards": ["H-1"],
                    "source_evidence": [],
                    "rationale": "The second supplied rule retains its hazard relation.",
                },
            ],
            "responsibilities": [
                {
                    "responsibility_id": "RESP-1",
                    "constraint_refs": ["SC-1", "SC-2"],
                    "rationale": "Enforces both supplied rules.",
                },
                {
                    "responsibility_id": "RESP-2",
                    "constraint_refs": [],
                    "rationale": "No additional governing rule is supplied.",
                },
            ],
            "actions": [
                {
                    "control_action_id": "CA-1-1",
                    "effect_kind": "agent_message",
                    "rationale": "Internal responsibility target.",
                },
                {
                    "control_action_id": "CA-2-1",
                    "effect_kind": "agent_message",
                    "rationale": "Internal responsibility target.",
                },
            ],
        },
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
    responsibilities = resp_set_dict
    if responsibilities is None:
        responsibilities = (
            _fallback_responsibility_set_dict()
            if control_element_set_dict is None
            else _valid_responsibility_set_dict()
        )
    client.set_response_for(ResponsibilitySet, responsibilities)
    client.set_response_for(
        ControlElementSet,
        control_element_set_dict or _valid_control_element_set_dict(),
    )
    client.set_response_for(
        CoordinationAnalysis,
        _reviewed_coordination_fixture(coordination_analysis_dict),
    )
    return client


def _setup_full_run_client(
    resp_set_dict: dict | None = None,
    control_element_set_dict: dict | None = None,
    coordination_analysis_dict: dict | None = None,
) -> MockLLMClient:
    """Set up a mock LLM client for a full SP1 run with valid Stage 1a/1b
    and a configurable Stage 2 ControlElementSet."""
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [
            _valid_loss_analysis_dict(),
            {
                "risk_card_losses": [],
                "use_case_losses": [],
                "hazards": [],
                "security_constraints": [],
            },
        ],
    )
    client.set_response_for(Stage1Profile, valid_stage1_profile_dict())
    client.set_response_for(RequirementSet, _valid_requirement_set_dict())
    responsibilities = resp_set_dict
    if responsibilities is None:
        responsibilities = (
            _fallback_responsibility_set_dict()
            if control_element_set_dict is None
            else _valid_responsibility_set_dict()
        )
    client.set_response_for(ResponsibilitySet, responsibilities)
    client.set_response_for(
        ControlElementSet,
        control_element_set_dict or _valid_control_element_set_dict(),
    )
    client.set_response_for(
        CoordinationAnalysis,
        _reviewed_coordination_fixture(coordination_analysis_dict),
    )
    client.set_response_for(CriticFindings, valid_critic_findings_dict_no_gaps())
    return client


def _reviewed_coordination_fixture(value):
    selected = value or valid_empty_coordination_analysis_dict()
    return {
        **{
            key: value for key, value in selected.items() if key != "integrity_findings"
        },
        "semantic_review": _valid_coordination_analysis_dict()["semantic_review"],
    }


ASSEMBLY_ERROR = (
    "stage_2/assemble_control_structure: control structure failed validation; "
    "unresolved references: ProcessModelPart PM-1-1 feedback_source "
    "controlled_process 'CP-99'"
)


def _assembly_entries(run_dir) -> list[dict]:
    return [
        entry
        for entry in read_calls_jsonl(run_dir)
        if entry["step"] == "assemble_control_structure"
    ]


class TestAssemblyFailureStopsStage2:
    """A structure that fails validation raises instead of degrading."""

    def test_failing_assembly_raises_a_stage_error_naming_the_reference(self, tmp_path):
        client = _setup_stage2_client()

        with pytest.raises(StageError) as exc_info:
            derive_control_structure(
                llm_client=client,
                use_case_text="Test",
                loss_analysis=_make_loss_analysis(),
                run_dir=tmp_path,
            )

        assert (exc_info.value.stage, exc_info.value.step) == (
            "stage_2",
            "assemble_control_structure",
        )
        assert str(exc_info.value) == ASSEMBLY_ERROR

    def test_failing_assembly_is_logged_once_and_writes_no_structure(self, tmp_path):
        client = _setup_stage2_client()

        with pytest.raises(StageError):
            derive_control_structure(
                llm_client=client,
                use_case_text="Test",
                loss_analysis=_make_loss_analysis(),
                run_dir=tmp_path,
            )

        entries = _assembly_entries(tmp_path)
        assert len(entries) == 1
        assert entries[0]["stage"] == "stage_2"
        assert entries[0]["success"] is False
        assert "CP-99" in entries[0]["error"]
        assert not (tmp_path / "control-structure-draft.yaml").exists()
        assert not (tmp_path / "control-structure.yaml").exists()
        assert len(client.calls) == 3  # Calls 1, 2a, and 2b; no Call 3

    def test_sp1_run_records_the_failure_as_a_stage_error(self, tmp_path):
        client = _setup_full_run_client()

        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

        assert isinstance(result, SP1RunResult)
        assert result.control_structure is None
        assert result.stage_errors == [ASSEMBLY_ERROR]
        assert not any(
            "assemble_control_structure" in warning for warning in result.stage_warnings
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_errors"] == [ASSEMBLY_ERROR]
        assert not (tmp_path / "control-structure.yaml").exists()

    def test_error_names_every_unresolved_reference(self, tmp_path):
        responsibilities = _fallback_responsibility_set_dict()
        responsibilities["responsibilities"][1]["process_model_parts"][0][
            "feedback_source"
        ] = {"type": "responsibility", "id": "RESP-7"}
        elements = _valid_control_element_set_dict()
        elements["control_actions"][0]["target"] = {
            "type": "responsibility",
            "id": "RESP-9",
        }
        elements["control_actions"][0]["process_model_refs"] = ["PM-2-1"]
        elements["feedback_channels"][1]["updates"] = "PM-5-1"

        with pytest.raises(StageError) as exc_info:
            _assemble_stage2_structure(
                construct_model_unvalidated(responsibilities, ResponsibilitySet),
                construct_model_unvalidated(elements, ControlElementSet),
                tmp_path,
                "test-model",
            )

        assert exc_info.value.message == (
            "control structure failed validation; unresolved references: "
            "ProcessModelPart PM-1-1 feedback_source controlled_process 'CP-99'; "
            "ControlAction CA-1-1 target responsibility 'RESP-9'; "
            "ControlAction CA-1-1 process_model_refs 'PM-2-1'; "
            "ProcessModelPart PM-2-1 feedback_source responsibility 'RESP-7'; "
            "FeedbackChannel FB-2-1 updates 'PM-5-1'"
        )

    def test_failure_without_a_reference_reports_the_validation_error(self, tmp_path):
        empty_responsibilities = ResponsibilitySet.model_construct(responsibilities=[])

        with pytest.raises(StageError) as exc_info:
            _assemble_stage2_structure(
                empty_responsibilities,
                ControlElementSet(),
                tmp_path,
                "test-model",
            )

        assert exc_info.value.step == "assemble_control_structure"
        assert exc_info.value.message.startswith(
            "control structure failed validation: ValidationError: "
        )
        assert len(_assembly_entries(tmp_path)) == 1


class TestCoordinationLinkFailureStopsStage2:
    """Coordination links that fail validation raise instead of being dropped."""

    def _structure(self):
        return ControlStructure.model_validate(
            {
                "responsibilities": [
                    {
                        "resp_id": "RESP-1",
                        "description": "Payment controller",
                        "process_model_parts": [
                            {"pm_id": "PM-1-1", "description": "Intent"}
                        ],
                    },
                    {
                        "resp_id": "RESP-2",
                        "description": "Output controller",
                        "process_model_parts": [
                            {"pm_id": "PM-2-1", "description": "Response"}
                        ],
                    },
                ]
            }
        )

    def test_failing_links_raise_a_stage_error_naming_each_reference(self, tmp_path):
        link = _valid_coordination_analysis_dict()["coordination_links"][0]
        link.update(source="RESP-9", shared_pm="PM-9-9")
        analysis = CoordinationAnalysis.model_validate({"coordination_links": [link]})

        with pytest.raises(StageError) as exc_info:
            _add_coordination_links(self._structure(), analysis, tmp_path, "m")

        assert (exc_info.value.stage, exc_info.value.step) == (
            "stage_2",
            "add_coordination_links",
        )
        assert exc_info.value.message == (
            "control structure failed validation; unresolved references: "
            "CoordinationLink CL-1 source responsibility 'RESP-9'; "
            "CoordinationLink CL-1 shared_pm 'PM-9-9'"
        )
        entries = [
            entry
            for entry in read_calls_jsonl(tmp_path)
            if entry["step"] == "add_coordination_links"
        ]
        assert [entry["success"] for entry in entries] == [False]

    def test_valid_links_are_added(self, tmp_path):
        analysis = CoordinationAnalysis.model_validate(
            {
                "coordination_links": _valid_coordination_analysis_dict()[
                    "coordination_links"
                ]
            }
        )

        structure = _add_coordination_links(self._structure(), analysis, tmp_path, "m")

        assert [link.link_id for link in structure.coordination_links] == ["CL-1"]
        assert read_calls_jsonl(tmp_path) == []


class TestSuccessfulAssembly:
    """A valid Call 2b response produces the full control structure."""

    def test_successful_assembly_produces_full_cs(self, tmp_path):
        client = _setup_stage2_client(
            control_element_set_dict=_valid_control_element_set_dict(),
            coordination_analysis_dict=_valid_coordination_analysis_dict(),
        )
        result = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        cs, warnings = result.control_structure, result.warnings
        assert isinstance(cs, ControlStructure)
        cl = next(cl for cl in cs.coordination_links if cl.link_id == "CL-1")
        assert cl.source == "RESP-1"
        assert cl.target == "RESP-2"
        assert warnings == []
        assert _assembly_entries(tmp_path) == []
        loaded = ControlStructure.model_validate(
            yaml.safe_load((tmp_path / "control-structure.yaml").read_text())
        )
        assert loaded == cs

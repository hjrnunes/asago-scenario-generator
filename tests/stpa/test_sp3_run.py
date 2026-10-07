"""Unit tests for SP3 — Run orchestration."""

from __future__ import annotations

import json
import hashlib

import pytest
import yaml
from pathlib import Path
from tempfile import TemporaryDirectory

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlledProcess,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    ScenarioHandoff,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    BDIGenerationResult,
    _ContextScenarioSemanticsPayload,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    McpInventoryObservation,
)
from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.scenario_prod.run import (
    SP3CandidateStatus,
    run_sp3,
)

from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import MockLLMClient
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from unittest.mock import MagicMock
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)
from asago_scenario_generator.pipeline.target_realization import TargetRealizationResult


def _target_profile_fixture() -> ExecutionTargetProfile:
    """Load the producer-owned target profile fixture for orchestration tests."""
    contract_root = (
        Path(__file__).resolve().parents[2] / "data/contracts/target-profile"
    )
    payload = json.loads(
        (contract_root / "target-profile-v1/valid/minimal.json").read_text(
            encoding="utf-8"
        )
    )
    for tool in payload["inventory"]["tools"]:
        tool.setdefault(
            "source_observation_sha256",
            hashlib.sha256(
                canonical_json_bytes(
                    {
                        key: value
                        for key, value in tool.items()
                        if key != "source_observation_sha256"
                    }
                )
            ).hexdigest(),
        )
    payload["inventory"].pop("semantic_digest", None)
    inventory = McpInventoryObservation.model_validate(payload["inventory"])
    payload["inventory"] = inventory.model_dump(mode="json")
    payload["source_inventory_digest"] = inventory.semantic_digest
    payload.pop("semantic_digest", None)
    return ExecutionTargetProfile.model_validate(payload)


def test_execution_publication_needs_no_presentation_model_calls(tmp_path) -> None:
    client = _setup_mock_client(num_threats=1)
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=_make_cs(),
        loss_analysis=_make_loss_analysis(),
        run_dir=tmp_path,
    )
    assert len(result.scenario_envelopes) == 1
    assert client.call_count == 1
    assert result.stage_errors == []
    assert (tmp_path / "scenarios" / "SCN-001.yaml").is_file()
    envelope = result.scenario_envelopes[0]
    assert "hypothesis" in envelope.narrative.lower()
    assert envelope.scenario_spec.loss_scenario in envelope.narrative


def _make_cs() -> ControlStructure:
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="R1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State")
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Action",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            ),
        ],
        controlled_processes=cps,
    )


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r1"],
            ),
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Must validate",
                related_hazards=["H-1"],
            ),
        ],
    )


def _make_ets(num_threats: int = 2) -> EnrichedThreatSet:
    threats = []
    for i in range(num_threats):
        threats.append(
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}",
                ica_text=f"ICA text {i + 1}",
                hazardous_context="Context",
                loss_scenario="Loss scenario",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            )
        )
    return EnrichedThreatSet(
        structural_threats=threats,
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 4,
                "non_na": 2,
                "na": 2,
                "coverage_rate": 0.5,
            },
            structural_consideration={"total_slots": 4, "considered": 4, "rate": 1.0},
            na_quality={"na_count": 2, "quality_count": 2, "quality_rate": 1.0},
        ),
    )


def _semantics_wire(payload: dict) -> dict:
    """Reduce an execution-design Stage 5 payload to the scenario-semantics wire.

    A product run requests scenario semantics only: no stimulus, execution
    route, route selection, or executable condition.
    """
    semantics = {
        key: value
        for key, value in payload.items()
        if key not in {"stimulus", "execution_route"}
    }
    semantics["causal_factors"] = [
        {key: value for key, value in factor.items() if key != "selected_for_route"}
        for factor in payload["causal_factors"]
    ]
    semantics["unsafe_outcome"] = {
        "semantic_proposition": payload["unsafe_outcome"]["semantic_proposition"],
        "observation_criteria": [
            {
                "criterion_id": "reply_outcome",
                "outcome": "The assistant reply omits the requested action.",
                "observable": True,
                "claim_level": "reply",
                "evidence": "assistant_message",
                "reason": "The qualification adapter captures assistant messages.",
            }
        ],
        "safe_observable_outcome": {
            "observable": True,
            "statement": "The assistant reply preserves the requested action.",
            "claim_level": "reply",
            "evidence": "assistant_message",
            "operation_name": None,
            "record_refs": [],
            "fact_refs": [],
        },
    }
    return semantics


def _setup_mock_client(num_threats: int = 2) -> MockLLMClient:
    """Set up a mock LLM client with one valid Stage 5 response per threat."""
    client = MockLLMClient()

    # Stage 5 responses — one per threat
    bdi_responses = []
    for i in range(num_threats):
        bdi_responses.append(
            {
                "stimulus": {
                    "category": "user_message",
                    "description": "One user message is the typed test stimulus.",
                },
                "adversary": {
                    "kind": "malicious_customer",
                    "gain": "Learns another customer's order details.",
                },
                "attacker_bdi": {
                    "beliefs": [f"attacker belief {i + 1}"],
                    "desires": ["induce ICA"],
                    "intentions": [
                        {
                            "description": "Exploit stale PM-1-1 state before CA-1-1.",
                            "source_handles": ["cause_1"],
                        }
                    ],
                },
                "causal_factors": [
                    {
                        "source_handle": "cause_1",
                        "evidence": f"The selected state can be stale ({i + 1}).",
                        "temporal_condition": None,
                        "evidence_status": "structural_failure",
                        "selected_for_route": True,
                    }
                ],
                "unsafe_outcome": {
                    "condition": {
                        "type": "action_presence",
                        "control_action_id": "CA-1-1",
                        "expected": "not_provided",
                    },
                    "semantic_proposition": (
                        "The response does not provide the requested action."
                    ),
                },
                "execution_route": {
                    "disposition": "executable_route",
                    "action_kind": "model_output",
                    "reason": "The selected structural factor supports the direct route.",
                },
            }
        )

    client.set_response_queue([_semantics_wire(payload) for payload in bdi_responses])
    return client


class _ProfilePublicationObservingClient(MockLLMClient):
    """Record whether the target profile exists before the first provider call."""

    def __init__(self, run_dir: Path) -> None:
        super().__init__()
        self.run_dir = run_dir
        self.profile_present_on_first_call: bool | None = None

    def complete(self, *args, **kwargs):
        if not self.calls:
            self.profile_present_on_first_call = (
                self.run_dir / "execution-target-profile.json"
            ).is_file()
        return super().complete(*args, **kwargs)


def test_run_sp3_publishes_target_profile_before_stage5_provider_call(tmp_path):
    """Stage 5 must never run before the verified profile copy is available."""
    run_dir = tmp_path / "run"
    client = _ProfilePublicationObservingClient(run_dir)

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=_make_cs(),
        loss_analysis=_make_loss_analysis(),
        run_dir=run_dir,
        execution_target_profile=_target_profile_fixture(),
    )

    assert result.scenario_envelopes == []
    assert client.profile_present_on_first_call is True
    assert (run_dir / "execution-target-profile.json").is_file()


def test_run_sp3_rejects_tampered_target_profile_before_provider_call(tmp_path):
    """A tampered profile cannot reach Stage 5 or be published."""
    run_dir = tmp_path / "run"
    client = _ProfilePublicationObservingClient(run_dir)
    profile = _target_profile_fixture().model_copy(update={"target_id": "tampered"})

    with pytest.raises(ValueError, match="semantic_digest"):
        run_sp3(
            llm_client=client,
            enriched_threat_set=_make_ets(num_threats=1),
            control_structure=_make_cs(),
            loss_analysis=_make_loss_analysis(),
            run_dir=run_dir,
            execution_target_profile=profile,
        )

    assert client.calls == []
    assert not (run_dir / "execution-target-profile.json").exists()


def test_run_sp3_skips_provider_work_when_profile_publication_fails(
    tmp_path, monkeypatch
):
    """A profile publication failure closes the run before provider work."""
    run_dir = tmp_path / "run"
    client = _ProfilePublicationObservingClient(run_dir)

    def fail_publication(*_args, **_kwargs):
        raise OSError("injected profile publication failure")

    monkeypatch.setattr(
        "asago_scenario_generator.stpa.scenario_prod.run.publish_execution_target_profile",
        fail_publication,
    )

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=_make_cs(),
        loss_analysis=_make_loss_analysis(),
        run_dir=run_dir,
        execution_target_profile=_target_profile_fixture(),
    )

    assert result.scenario_envelopes == []
    assert client.calls == []
    assert any("profile publication failed" in error for error in result.stage_errors)


class TestFullRun:
    """SP3-RUN-01 through SP3-RUN-20."""

    def test_nested_run_dir_created(self):
        """run_sp3 must create nested run_dir that doesn't exist yet."""
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=1)
        client = _setup_mock_client(1)

        with TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "nested" / "deep" / "rundir"
            result = run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=run_dir,
            )
            assert len(result.scenario_envelopes) == 1
            assert run_dir.exists()
            assert [outcome.status for outcome in result.candidate_outcomes] == [
                SP3CandidateStatus.published
            ]
            assert result.candidate_outcomes[0].scenario_id == "SCN-001"

    def test_public_run_reuses_exact_scenario_context_and_publishes_handoff(
        self, tmp_path
    ):
        client = _setup_mock_client(1)
        run_dir = tmp_path / "run"

        result = run_sp3(
            llm_client=client,
            enriched_threat_set=_make_ets(num_threats=1),
            control_structure=_make_cs(),
            loss_analysis=_make_loss_analysis(),
            run_dir=run_dir,
        )

        context = result.scenario_specs[0].scenario_context
        assert context is not None
        assert len(client.calls) == 1
        stage5_prompt = client.calls[0].user_prompt
        assert context.context_digest not in stage5_prompt
        assert "source_pins" not in stage5_prompt
        handoff = read_yaml(run_dir / "scenarios/SCN-001.yaml", ScenarioHandoff)
        verify_handoff_digest(handoff)
        assert handoff.scenario_id == "SCN-001"

    def test_resolved_client_temperature_is_used_and_recorded(self):
        client = _setup_mock_client(1)
        client.temperature = 1.0

        with TemporaryDirectory() as tmpdir:
            run_sp3(
                llm_client=client,
                enriched_threat_set=_make_ets(num_threats=1),
                control_structure=_make_cs(),
                loss_analysis=_make_loss_analysis(),
                run_dir=Path(tmpdir),
            )
            manifest = yaml.safe_load((Path(tmpdir) / "run-manifest.yaml").read_text())

        assert {call.temperature for call in client.calls} == {1.0}
        assert manifest["model_config"]["temperature"] == 1.0

    def test_pre_existing_dirs_handled(self):
        """run_sp3 must not fail when run_dir and scenarios/ already exist."""
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=1)
        client = _setup_mock_client(1)

        with TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            (run_dir / "scenarios").mkdir(parents=True, exist_ok=True)
            result = run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=run_dir,
            )
            assert len(result.scenario_envelopes) == 1

    def test_produces_scenario_envelopes_and_scorecard(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=2)
        client = _setup_mock_client(2)

        with TemporaryDirectory() as tmpdir:
            result = run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            assert len(result.scenario_envelopes) == 2
            assert (Path(tmpdir) / "scenarios").exists()
            assert any(Path(tmpdir).glob("scenarios/*.yaml"))
            assert any(Path(tmpdir).glob("scenarios/*.feature"))
            assert (Path(tmpdir) / "eval-scorecard.yaml").exists()

    def test_all_llm_calls_logged(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=2)
        client = _setup_mock_client(2)

        with TemporaryDirectory() as tmpdir:
            run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            calls = read_calls_jsonl(Path(tmpdir))
            stage_5 = [c for c in calls if c["stage"] == "stage_5"]
            assert len(stage_5) == len(calls) == 2  # 1 per threat

    def test_stage_7_makes_no_llm_calls(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=2)
        client = _setup_mock_client(2)

        with TemporaryDirectory() as tmpdir:
            run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            calls = read_calls_jsonl(Path(tmpdir))
            stage_7 = [c for c in calls if c["stage"] == "stage_7"]
            assert len(stage_7) == 0

    def test_run_manifest_written(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=2)
        client = _setup_mock_client(2)

        with TemporaryDirectory() as tmpdir:
            run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            manifest_path = Path(tmpdir) / "run-manifest.yaml"
            assert manifest_path.exists()
            manifest = yaml.safe_load(manifest_path.read_text())
            assert "stage_summary" in manifest
            assert "stage_5" in manifest["stage_summary"]
            assert "input_hashes" in manifest
            assert "enriched_threat_set" in manifest["input_hashes"]
            assert "control_structure" in manifest["input_hashes"]
            assert "loss_analysis" in manifest["input_hashes"]
            assert "prompt_hashes" in manifest
            assert "stage5_context_system.j2" in manifest["prompt_hashes"]
            assert "stage5_context_user.j2" in manifest["prompt_hashes"]
            assert manifest["scenario_count"] == 2

    def test_coverage_gaps_written(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=2)
        client = _setup_mock_client(2)

        with TemporaryDirectory() as tmpdir:
            run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            assert (Path(tmpdir) / "coverage-gaps.json").exists()

    def test_scenario_yaml_loads_as_handoff(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=2)
        client = _setup_mock_client(2)

        with TemporaryDirectory() as tmpdir:
            run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            yaml_files = sorted(Path(tmpdir).glob("scenarios/*.yaml"))
            assert len(yaml_files) == 2
            for yaml_file in yaml_files:
                handoff = read_yaml(yaml_file, ScenarioHandoff)
                verify_handoff_digest(handoff)

    def test_scenario_count_equals_threats(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=3)
        client = _setup_mock_client(3)

        with TemporaryDirectory() as tmpdir:
            result = run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            assert len(result.scenario_envelopes) == 3

    def test_eval_scorecard_contains_coverage_gaps(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=2)
        client = _setup_mock_client(2)

        with TemporaryDirectory() as tmpdir:
            run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            scorecard = yaml.safe_load(
                (Path(tmpdir) / "eval-scorecard.yaml").read_text()
            )
            assert "coverage_gaps" in scorecard

    def test_max_workers_flag(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=2)
        client = _setup_mock_client(2)

        with TemporaryDirectory() as tmpdir:
            run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
                max_workers=2,
            )
            calls = read_calls_jsonl(Path(tmpdir))
            manifest = yaml.safe_load((Path(tmpdir) / "run-manifest.yaml").read_text())
            assert len(calls) == 2
            assert manifest["max_workers"] == 2


class TestPromptTemplatesExist:
    """SP3-RUN-09."""

    def test_all_template_files_exist(self):
        templates = [
            "stage5_context_system.j2",
            "stage5_context_user.j2",
        ]
        for t in templates:
            assert (PROMPTS_DIR / t).exists(), f"Missing template: {t}"


class TestModuleLayout:
    """SP3-RUN-10."""

    def test_all_modules_importable(self):
        from asago_scenario_generator.stpa.scenario_prod import (
            validators,
            eval_metrics,
            coverage,
            assembly,
            run,
        )

        assert validators is not None
        assert eval_metrics is not None
        assert coverage is not None
        assert assembly is not None
        assert run is not None


class TestErrorPaths:
    """SP3 run error handling — Stage 5 and Stage 6 failures."""

    def test_stage5_invalid_responsibility_skipped(self):
        """A threat with an invalid responsibility ID is skipped with an error."""
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = EnrichedThreatSet(
            structural_threats=[
                StructuralThreat(
                    ica_slot_id="RESP-99:CA-1-1:NOT_PROVIDED",
                    ica_id="RESP-99:CA-1-1:NOT_PROVIDED:1",
                    ica_text="t",
                    hazardous_context="c",
                    loss_scenario="l",
                    related_hazards=["H-1"],
                    related_constraints=["SC-1"],
                ),
            ],
            coverage_analysis=CoverageAnalysis(
                structural_coverage={
                    "total_slots": 1,
                    "non_na": 1,
                    "na": 0,
                    "coverage_rate": 1.0,
                },
            ),
        )
        client = MockLLMClient()

        with TemporaryDirectory() as tmpdir:
            result = run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            assert len(result.scenario_envelopes) == 0
            assert any("Stage 5" in e for e in result.stage_errors)
            assert (
                result.candidate_outcomes[0].status
                is SP3CandidateStatus.generation_failed
            )

    def test_stage5_llm_failure_skipped(self):
        """A Stage 5 LLM failure is skipped with an error."""
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=1)
        client = MockLLMClient()
        client.set_exception_for(BDIGenerationResult, RuntimeError("LLM down"))

        with TemporaryDirectory() as tmpdir:
            result = run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            assert len(result.scenario_envelopes) == 0
            assert any(
                "Stage 5 BDI generation failed" in e for e in result.stage_errors
            )
            assert (
                result.candidate_outcomes[0].status
                is SP3CandidateStatus.generation_failed
            )

    def test_repeated_structured_length_failure_aborts_remaining_threats(self):
        """An exhausted length retry opens the circuit before later threats run."""

        class LengthFinishReasonError(Exception):
            pass

        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=3)
        client = MockLLMClient()
        client.set_exception_for(
            _ContextScenarioSemanticsPayload,
            LengthFinishReasonError("structured response reached its length limit"),
        )

        with TemporaryDirectory() as tmpdir:
            result = run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )

        assert client.call_count == 2
        assert any(
            "aborted 2 remaining threats" in error and "structured-output" in error
            for error in result.stage_errors
        )
        assert [outcome.status for outcome in result.candidate_outcomes] == [
            SP3CandidateStatus.generation_failed,
            SP3CandidateStatus.skipped,
            SP3CandidateStatus.skipped,
        ]

    def test_artifact_write_failure_is_publication_failed(self, monkeypatch, tmp_path):
        """A rendered candidate whose companion write fails is not published."""
        from asago_scenario_generator.stpa.scenario_prod import run as run_module

        client = _setup_mock_client(1)

        def fail_write(*_args, **_kwargs):
            raise OSError("artifact sink unavailable")

        monkeypatch.setattr(run_module, "_write_scenario_handoff_artifacts", fail_write)
        result = run_sp3(
            llm_client=client,
            enriched_threat_set=_make_ets(num_threats=1),
            control_structure=_make_cs(),
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )

        assert (
            result.candidate_outcomes[0].status is SP3CandidateStatus.publication_failed
        )
        assert any(
            "artifact sink unavailable" in item
            for item in result.candidate_outcomes[0].diagnostics
        )

    def test_stage5_validation_failure_does_not_reach_stage6(self):
        """A structurally invalid Stage 5 result remains an unresolved scenario."""
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=1)
        client = MockLLMClient()
        client.set_response_queue(
            [
                {
                    "stimulus": {
                        "category": "user_message",
                        "description": "One user message is the typed test stimulus.",
                    },
                    "adversary": {
                        "kind": "malicious_customer",
                        "gain": "Learns another customer's order details.",
                    },
                    "attacker_bdi": {
                        "beliefs": ["b"],
                        "desires": ["d"],
                        "intentions": [
                            {
                                "description": "No structural reference is supplied.",
                                "source_handles": ["cause_2"],
                            }
                        ],
                    },
                    "causal_factors": [
                        {
                            "source_handle": "cause_1",
                            "evidence": "The selected state can be stale.",
                            "temporal_condition": None,
                            "evidence_status": "structural_failure",
                            "selected_for_route": True,
                        }
                    ],
                    "unsafe_outcome": {
                        "condition": {
                            "type": "action_presence",
                            "control_action_id": "CA-1-1",
                            "expected": "not_provided",
                        },
                        "semantic_proposition": (
                            "The response does not provide the requested action."
                        ),
                    },
                    "execution_route": {
                        "disposition": "executable_route",
                        "action_kind": "model_output",
                        "reason": "The selected structural factor supports the direct route.",
                    },
                }
            ]
        )

        with TemporaryDirectory() as tmpdir:
            result = run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )

        assert result.scenario_envelopes == []
        assert client.call_count == 2
        assert any(
            "Stage 5 BDI generation failed" in error for error in result.stage_errors
        )


class TestTargetInputPins:
    """Target observations and realization must be intact and profile-pinned."""

    @staticmethod
    def _run(tmp_path, **kwargs):
        client = MockLLMClient()
        with pytest.raises((TypeError, ValueError)) as raised:
            run_sp3(
                llm_client=client,
                enriched_threat_set=_make_ets(num_threats=1),
                control_structure=_make_cs(),
                loss_analysis=_make_loss_analysis(),
                run_dir=tmp_path / "run",
                **kwargs,
            )
        assert client.calls == []
        return raised.value

    @staticmethod
    def _pinned(spec, digest_field: str, digest: str):
        value = MagicMock(spec=spec)
        setattr(value, digest_field, digest)
        return value

    def test_observations_must_be_a_snapshot(self, tmp_path):
        error = self._run(tmp_path, target_observations={"state": {}})
        assert str(error) == "target_observations must be a TargetObservationSnapshot"

    def test_observations_require_a_target_profile(self, tmp_path):
        observations = self._pinned(
            TargetObservationSnapshot, "target_profile_digest", "0" * 64
        )
        error = self._run(tmp_path, target_observations=observations)
        assert str(error) == "target_observations requires execution_target_profile"
        observations.assert_integrity.assert_called_once_with()

    def test_realization_must_be_a_realization_result(self, tmp_path):
        error = self._run(tmp_path, target_realization=object())
        assert str(error) == "target_realization must be a TargetRealizationResult"

    def test_realization_requires_a_target_profile(self, tmp_path):
        realization = self._pinned(TargetRealizationResult, "profile_digest", "0" * 64)
        error = self._run(tmp_path, target_realization=realization)
        assert str(error) == "target_realization requires execution_target_profile"
        realization.assert_integrity.assert_called_once_with()

    def test_realization_pin_must_match_the_target_profile(self, tmp_path):
        realization = self._pinned(TargetRealizationResult, "profile_digest", "0" * 64)
        error = self._run(
            tmp_path,
            execution_target_profile=_target_profile_fixture(),
            target_realization=realization,
        )
        assert str(error) == (
            "target_realization profile pin does not match target profile"
        )

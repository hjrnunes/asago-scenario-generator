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
from asago_scenario_generator.stpa.models.scenario_envelope import ScenarioEnvelope
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    _ContextBDIProviderPayload,
)
from asago_scenario_generator.stpa.scenario_prod.execution_bundle import (
    verify_execution_bundle,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionDeliveryClass,
    ExecutionTargetProfile,
    McpInventoryObservation,
    RequestedEnvironmentBasis,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
)
from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.scenario_prod.run import (
    SP3CandidateStatus,
    run_sp3,
)

from tests.stpa.sp1_helpers import MockLLMClient, read_calls_jsonl


def _target_profile_fixture() -> ExecutionTargetProfile:
    """Load the producer-owned target profile fixture for orchestration tests."""
    contract_root = (
        Path(__file__).resolve().parents[2] / "data/contracts/stpa-execution"
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
    assert verify_execution_bundle(tmp_path).valid
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


def _direct_execution_contract() -> SemanticExecutionContract:
    """Return the explicit target-agnostic route used by test Stage 5 calls."""
    return SemanticExecutionContract(
        requested_environment_basis=RequestedEnvironmentBasis.target_agnostic,
        delivery=SemanticExecutionDelivery(
            delivery_class=ExecutionDeliveryClass.direct_prompt,
            factor_id="CF-1",
            source_role="direct_user_input",
        ),
        action_kind=ExecutionActionKind.model_output,
    )


def _is_stage5_response_format(response_format: type | None) -> bool:
    """Identify the contextual Stage 5 contract by its required fields."""
    fields = getattr(response_format, "model_fields", {})
    return "execution_route" in fields and "unsafe_outcome" in fields


def _setup_mock_client(num_threats: int = 2) -> MockLLMClient:
    """Set up a mock LLM client with valid SP3 responses."""
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

    # Stage 6 responses — 3 per scenario (narrative, attack_tree, gherkin)
    # We use None response_format for raw text calls
    # The mock returns from the queue in order
    stage6_responses = []
    for i in range(num_threats):
        # Narrative (raw text)
        stage6_responses.append(
            "Step 1: The defender process model starts correct.\n"
            "Step 2: The adversary exploits the stale PM-1-1 window.\n"
            "Step 3: The process model PM-1-1 diverges.\n"
            "Step 4: The defender acts on false beliefs.\n"
            "Step 5: The ICA occurs.\n"
            "Step 6: The hazard is realized.\n"
            "Step 7: The loss follows.\n"
        )
        # Attack tree (JSON string)
        stage6_responses.append(
            json.dumps(
                {
                    "root": "Induce ICA NOT_PROVIDED on CA-1-1",
                    "branches": [
                        {
                            "category": "controller_side",
                            "label": "Corrupt PM-1-1 via FB-1-1",
                            "children": [],
                        },
                        {
                            "category": "path_side",
                            "label": "Tool fails",
                            "children": [],
                        },
                    ],
                    "leaves": ["Replay stale FB-1-1 state", "Tool fails"],
                }
            )
        )
        # Gherkin (YAML format)
        stage6_responses.append(
            "feature: Attack scenario\n"
            f"scenario: Attack scenario {i + 1}\n"
            "given:\n"
            "  - Given PM-1-1 is in a valid state\n"
            "when:\n"
            "  - When PM-1-1 remains stale during the request\n"
            "then_expected:\n"
            "  - Then the system should reject the request\n"
            "then_actual:\n"
            "  - But the system approves the request (ICA NOT_PROVIDED on CA-1-1)\n"
            "  - And loss L-1 is realized\n"
        )

    # Set the response queue: Stage 5 responses first, then Stage 6
    client.set_response_queue(bdi_responses + stage6_responses)
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

    def test_public_run_persists_and_reuses_exact_scenario_context(self, tmp_path):
        client = _setup_mock_client(1)
        run_dir = tmp_path / "run"

        result = run_sp3(
            render_presentation=True,
            llm_client=client,
            enriched_threat_set=_make_ets(num_threats=1),
            control_structure=_make_cs(),
            loss_analysis=_make_loss_analysis(),
            run_dir=run_dir,
        )

        context = result.scenario_specs[0].scenario_context
        assert context is not None
        stage5 = [
            call
            for call in client.calls
            if _is_stage5_response_format(call.response_format)
        ]
        stage6 = [
            call
            for call in client.calls
            if not _is_stage5_response_format(call.response_format)
        ]
        assert len(stage5) == 1
        assert len(stage6) == 3
        assert context.context_digest not in stage5[0].user_prompt
        assert "source_pins" not in stage5[0].user_prompt
        assert all(context.context_digest not in call.user_prompt for call in stage6)
        assert all("source_pins" not in call.user_prompt for call in stage6)
        assert all(context.ica.exact_ica_text in call.user_prompt for call in stage6)
        persisted = yaml.safe_load(
            (run_dir / "scenarios/SCN-001.yaml").read_text(encoding="utf-8")
        )
        assert (
            persisted["scenario_spec"]["scenario_context"]["context_digest"]
            == context.context_digest
        )
        bundle = verify_execution_bundle(run_dir)
        assert bundle.valid is True
        assert bundle.index is not None
        manifest = yaml.safe_load(
            (run_dir / "run-manifest.yaml").read_text(encoding="utf-8")
        )
        assert manifest["run_id"] == bundle.index.run_id

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
                render_presentation=True,
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            calls = read_calls_jsonl(Path(tmpdir))
            stage_5 = [c for c in calls if c["stage"] == "stage_5"]
            stage_6 = [c for c in calls if c["stage"] == "stage_6"]
            assert len(stage_5) == 2  # 1 per threat
            assert len(stage_6) == 6  # 3 per scenario × 2 scenarios

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
                render_presentation=True,
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
            assert "stage_6" in manifest["stage_summary"]
            assert "input_hashes" in manifest
            assert "enriched_threat_set" in manifest["input_hashes"]
            assert "control_structure" in manifest["input_hashes"]
            assert "loss_analysis" in manifest["input_hashes"]
            assert "prompt_hashes" in manifest
            assert "stage5_system.j2" in manifest["prompt_hashes"]
            assert "stage5_user.j2" in manifest["prompt_hashes"]
            assert "stage6a_narrative_system.j2" in manifest["prompt_hashes"]
            assert "stage6b_tree_system.j2" in manifest["prompt_hashes"]
            assert "stage6c_gherkin_system.j2" in manifest["prompt_hashes"]
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

    def test_scenario_yaml_loads_as_envelope(self):
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
            from asago_scenario_generator.stpa.infra.yaml_io import read_yaml

            for yaml_file in Path(tmpdir).glob("scenarios/*.yaml"):
                env = read_yaml(yaml_file, ScenarioEnvelope)
                assert env.scenario_id is not None

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
                render_presentation=True,
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
                max_workers=2,
            )
            calls = read_calls_jsonl(Path(tmpdir))
            assert len(calls) == 8  # 2 stage_5 + 6 stage_6


class TestPromptTemplatesExist:
    """SP3-RUN-09."""

    def test_all_template_files_exist(self):
        from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR

        templates = [
            "stage5_system.j2",
            "stage5_user.j2",
            "stage6a_narrative_system.j2",
            "stage6a_narrative_user.j2",
            "stage6b_tree_system.j2",
            "stage6b_tree_user.j2",
            "stage6c_gherkin_system.j2",
            "stage6c_gherkin_user.j2",
        ]
        for t in templates:
            assert (PROMPTS_DIR / t).exists(), f"Missing template: {t}"


class TestModuleLayout:
    """SP3-RUN-10."""

    def test_all_modules_importable(self):
        from asago_scenario_generator.stpa.scenario_prod import (
            bdi_generation,
            narrative,
            attack_tree,
            gherkin,
            validators,
            eval_metrics,
            coverage,
            assembly,
            run,
        )

        assert bdi_generation is not None
        assert narrative is not None
        assert attack_tree is not None
        assert gherkin is not None
        assert validators is not None
        assert eval_metrics is not None
        assert coverage is not None
        assert assembly is not None
        assert run is not None


class TestCLIScript:
    """SP3-RUN-12."""

    def test_cli_help(self):
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "scripts/run_sp3.py", "--help"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parents[2]),
        )
        assert result.returncode == 0
        assert "--enriched-threats" in result.stdout
        assert "--control-structure" in result.stdout
        assert "--loss-analysis" in result.stdout
        assert "--output-dir" in result.stdout
        assert "--max-workers" in result.stdout


class TestErrorPaths:
    """SP3 run error handling — Stage 5 and Stage 6 failures."""

    def test_stage5_invalid_responsibility_skipped(self):
        """A threat with an invalid responsibility ID is skipped with an error."""
        from asago_scenario_generator.stpa.models.enriched_threat_set import (
            StructuralThreat,
        )

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
        client.set_exception_for(
            __import__(
                "asago_scenario_generator.stpa.scenario_prod.bdi_generation",
                fromlist=["BDIGenerationResult"],
            ).BDIGenerationResult,
            RuntimeError("LLM down"),
        )

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
            _ContextBDIProviderPayload,
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

    def test_stage6_llm_failure_does_not_publish_contextual_scenario(self):
        """Stage 6 failures retain diagnostics without publishing empty artifacts."""
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=1)
        client = MockLLMClient()

        # Stage 5 BDI response
        bdi = {
            "stimulus": {
                "category": "user_message",
                "description": "One user message is the typed test stimulus.",
            },
            "attacker_bdi": {
                "beliefs": ["b"],
                "desires": ["d"],
                "intentions": [
                    {
                        "description": "Rely on stale PM-1-1 state.",
                        "source_handles": ["cause_1"],
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
        client.set_response_queue([bdi])

        # Stage 6: all three calls raise
        client.set_exception_for(None, RuntimeError("LLM down"))

        with TemporaryDirectory() as tmpdir:
            result = run_sp3(
                render_presentation=True,
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            assert result.scenario_envelopes == []
            assert any("Stage 6" in e for e in result.stage_errors)
            assert (
                result.candidate_outcomes[0].status
                is SP3CandidateStatus.rendering_failed
            )

    def test_artifact_write_failure_is_publication_failed(self, monkeypatch, tmp_path):
        """A rendered candidate whose companion write fails is not published."""
        from asago_scenario_generator.stpa.scenario_prod import run as run_module

        client = _setup_mock_client(1)

        def fail_write(*_args, **_kwargs):
            raise OSError("artifact sink unavailable")

        monkeypatch.setattr(run_module, "_write_scenario_artifacts", fail_write)
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

    def test_malformed_gherkin_gets_one_schema_correction(self):
        """The contextual Gherkin call repairs malformed structured output once."""
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
                    "attacker_bdi": {
                        "beliefs": ["b"],
                        "desires": ["d"],
                        "intentions": [
                            {
                                "description": "Rely on stale PM-1-1 state.",
                                "source_handles": ["cause_1"],
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
                },
                "A seven-step narrative retaining PM-1-1 and CA-1-1.",
                '{"root":"Induce ICA NOT_PROVIDED on CA-1-1","branches":'
                '[{"category":"controller_side","label":"PM-1-1",'
                '"children":[]},{"category":"path_side","label":"CA-1-1",'
                '"children":[]}],"leaves":["PM-1-1","CA-1-1"]}',
                "given:\n  - Given PM-1-1 is active\n    And malformed",
                __import__(
                    "asago_scenario_generator.stpa.models.scenario_envelope",
                    fromlist=["GherkinSpec"],
                ).GherkinSpec(
                    feature="Safe operation",
                    scenario="Unsafe action",
                    given=["Given PM-1-1 is active"],
                    when=["When the selected state becomes stale"],
                    then_expected=["Then the system should remain safe"],
                    then_actual=[
                        "But the system performs NOT_PROVIDED CA-1-1",
                        "And loss L-1 is realized",
                    ],
                ),
            ]
        )

        with TemporaryDirectory() as tmpdir:
            result = run_sp3(
                render_presentation=True,
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
                max_workers=1,
            )

        assert len(result.scenario_envelopes) == 1
        assert client.call_count == 5
        correction = client.calls[-1].user_prompt
        assert "Exact validation error from the prior response" in correction
        assert '"then_actual"' in correction

"""Unit tests for SP3 — Run orchestration."""

from __future__ import annotations

import json
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
    BDIGenerationResult,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3

from tests.stpa.sp1_helpers import MockLLMClient, read_calls_jsonl


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
                description="Must validate",
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


def _setup_mock_client(num_threats: int = 2) -> MockLLMClient:
    """Set up a mock LLM client with valid SP3 responses."""
    client = MockLLMClient()

    # Stage 5 responses — one per threat
    bdi_responses = []
    for i in range(num_threats):
        bdi_responses.append(
            BDIGenerationResult(
                defender_vulnerabilities={"PM-1-1": f"vulnerability {i + 1}"},
                attacker_bdi=__import__(
                    "asago_scenario_generator.stpa.models.scenario_spec",
                    fromlist=["AttackerBDI"],
                ).AttackerBDI(
                    beliefs=[f"attacker belief {i + 1}"],
                    desires=["induce ICA"],
                    intentions=["poison PM-1-1 via FB-1-1"],
                ),
            )
        )

    # Stage 6 responses — 3 per scenario (narrative, attack_tree, gherkin)
    # We use None response_format for raw text calls
    # The mock returns from the queue in order
    stage6_responses = []
    for i in range(num_threats):
        # Narrative (raw text)
        stage6_responses.append(
            "Step 1: The defender process model starts correct.\n"
            "Step 2: The attacker manipulates FB-1-1.\n"
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
                    "leaves": ["Poison PM-1-1 via FB-1-1", "Tool fails"],
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
            "  - When the attacker sends a malicious request\n"
            "then_expected:\n"
            "  - Then the system should reject the request\n"
            "then_actual:\n"
            "  - But the system approves the request (ICA NOT_PROVIDED on CA-1-1)\n"
            "  - And loss L-1 is realized\n"
        )

    # Set the response queue: Stage 5 responses first, then Stage 6
    client.set_response_queue(bdi_responses + stage6_responses)
    return client


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

    def test_repeated_structured_length_failure_aborts_remaining_threats(self):
        """An exhausted length retry opens the circuit before later threats run."""

        class LengthFinishReasonError(Exception):
            pass

        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=3)
        client = MockLLMClient()
        client.set_exception_for(
            BDIGenerationResult,
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
            "aborted 2 remaining threats" in error
            and "structured-output" in error
            for error in result.stage_errors
        )

    def test_stage6_llm_failure_uses_fallbacks(self):
        """Stage 6 LLM failures produce envelopes with fallback empty artifacts."""
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(num_threats=1)
        client = MockLLMClient()

        # Stage 5 BDI response
        bdi = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "vuln"},
            attacker_bdi=__import__(
                "asago_scenario_generator.stpa.models.scenario_spec",
                fromlist=["AttackerBDI"],
            ).AttackerBDI(
                beliefs=["b"],
                desires=["d"],
                intentions=["i"],
            ),
        )
        client.set_response_queue([bdi])

        # Stage 6: all three calls raise
        client.set_exception_for(None, RuntimeError("LLM down"))

        with TemporaryDirectory() as tmpdir:
            result = run_sp3(
                llm_client=client,
                enriched_threat_set=ets,
                control_structure=cs,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            assert len(result.scenario_envelopes) == 1
            env = result.scenario_envelopes[0]
            assert env.narrative == ""
            assert env.attack_tree == {"root": "", "branches": [], "leaves": []}
            assert env.gherkin_raw == ""
            assert env.gherkin_spec is not None
            assert any("Stage 6" in e for e in result.stage_errors)

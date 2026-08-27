"""Unit tests for SP2 — Run orchestration."""

from __future__ import annotations

import json
import yaml
from pathlib import Path
from tempfile import TemporaryDirectory

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlledProcess,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.threat_enum.run import run_sp2
from asago_scenario_generator.stpa.threat_enum.slot_filling import ICASlotFillResult

from tests.stpa.sp1_helpers import MockLLMClient


def _make_test_control_structure() -> ControlStructure:
    """Build a control structure with 2 responsibilities, 2 CAs each, 1 coordination link."""
    cps = [
        ControlledProcess(cp_id="CP-1", description="P1"),
        ControlledProcess(cp_id="CP-2", description="P2"),
    ]
    resp1 = Responsibility(
        resp_id="RESP-1",
        description="R1",
        responsibility_constraints=[
            {"rc_id": "RC-1-1", "description": "Must validate"}
        ],
        process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
        control_actions=[
            ControlAction(
                ca_id=f"CA-1-{j + 1}",
                description=f"Action {j + 1}",
                target=ElementRef(
                    type=ReferenceType.controlled_process, id=f"CP-{j + 1}"
                ),
            )
            for j in range(2)
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="F",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
        ],
    )
    resp2 = Responsibility(
        resp_id="RESP-2",
        description="R2",
        process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="State")],
        control_actions=[
            ControlAction(
                ca_id=f"CA-2-{j + 1}",
                description=f"Action {j + 1}",
                target=ElementRef(
                    type=ReferenceType.controlled_process, id=f"CP-{j + 1}"
                ),
            )
            for j in range(2)
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-2-1",
                description="F",
                updates="PM-2-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-2"),
            )
        ],
    )
    link = CoordinationLink(
        link_id="CL-1",
        source="RESP-1",
        target="RESP-2",
        shared_pm="PM-1-1",
        coordination_mechanism=CoordinationMechanism(
            cm_id="CM-1", description="Mechanism", payload="data"
        ),
        description="Link",
    )
    return ControlStructure(
        responsibilities=[resp1, resp2],
        controlled_processes=cps,
        coordination_links=[link],
    )


def _make_test_loss_analysis() -> LossAnalysis:
    """Build a loss analysis with hazard H-1 and constraint SC-1."""
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            )
        ],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", description="Constraint", related_hazards=["H-1"]
            ),
        ],
    )


def _make_test_capability_profile() -> CapabilityProfile:
    """Build a capability profile with input zone failure modes."""
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            EntryPoint(name="chat", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=["KC1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="test-tool", description="A test tool"),
        ],
    )


def _make_valid_slot_fill_result(resp_id: str, ca_ids: list[str]) -> dict:
    """Build a valid ICASlotFillResult dict for a responsibility."""
    filled_slots = []
    for ca_id in ca_ids:
        for uca_type in UCAType:
            slot_id = f"{resp_id}:{ca_id}:{uca_type.value}"
            if uca_type == UCAType.wrong_duration:
                filled_slots.append(
                    {
                        "slot_id": slot_id,
                        "responsibility": resp_id,
                        "coordination_link": None,
                        "control_action": ca_id,
                        "uca_type": uca_type.value,
                        "is_na": True,
                        "icas": [],
                        "na_justification": "Action is atomic with no duration component",
                    }
                )
            else:
                filled_slots.append(
                    {
                        "slot_id": slot_id,
                        "responsibility": resp_id,
                        "coordination_link": None,
                        "control_action": ca_id,
                        "uca_type": uca_type.value,
                        "is_na": False,
                        "icas": [
                            {
                                "ica_id": f"{slot_id}:1",
                                "ica_text": f"Concrete failure for {ca_id} {uca_type.value}",
                                "hazardous_context": "Attacker context",
                                "loss_scenario": "Attack chain leading to harm",
                                "related_hazards": ["H-1"],
                                "related_constraints": ["SC-1"],
                            }
                        ],
                        "na_justification": None,
                    }
                )
    return {"filled_slots": filled_slots}


def _setup_mock_client() -> MockLLMClient:
    """Set up a mock LLM client with valid slot fill results."""
    client = MockLLMClient()
    client.set_response_queue(
        [
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-1", ["CA-1-1", "CA-1-2"])
            ),
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-2", ["CA-2-1", "CA-2-2"])
            ),
        ]
    )
    return client


# ---------------------------------------------------------------------------
# Full run produces both output artifacts (SP2-RUN-01)
# ---------------------------------------------------------------------------


class TestFullRunProducesArtifacts:
    """Full SP2 run produces ica-enumeration.yaml and enriched-threats.yaml."""

    def test_both_artifacts_exist(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        client = _setup_mock_client()

        with TemporaryDirectory() as tmpdir:
            run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            assert (Path(tmpdir) / "ica-enumeration.yaml").exists()
            assert (Path(tmpdir) / "enriched-threats.yaml").exists()

    def test_resolved_client_temperature_is_used_and_recorded(self):
        client = _setup_mock_client()
        client.temperature = 1.0

        with TemporaryDirectory() as tmpdir:
            run_sp2(
                llm_client=client,
                control_structure=_make_test_control_structure(),
                capability_profile=_make_test_capability_profile(),
                loss_analysis=_make_test_loss_analysis(),
                run_dir=Path(tmpdir),
            )
            manifest = yaml.safe_load((Path(tmpdir) / "run-manifest.yaml").read_text())

        assert {call.temperature for call in client.calls} == {1.0}
        assert manifest["model_config"]["temperature"] == 1.0


# ---------------------------------------------------------------------------
# All LLM calls logged to calls.jsonl (SP2-RUN-03, SP2-RUN-04)
# ---------------------------------------------------------------------------


class TestCallLogging:
    """All LLM calls are logged; Stage 4 makes no LLM calls."""

    def test_calls_jsonl_has_stage_3(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        client = _setup_mock_client()

        with TemporaryDirectory() as tmpdir:
            run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            calls_file = Path(tmpdir) / "calls.jsonl"
            assert calls_file.exists()
            entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
            stage_3_count = sum(1 for e in entries if e["stage"] == "stage_3")
            stage_4_count = sum(1 for e in entries if e["stage"] == "stage_4")
            assert stage_3_count == 2  # one per responsibility
            assert stage_4_count == 0  # Stage 4 is deterministic


# ---------------------------------------------------------------------------
# Run manifest (SP2-RUN-05, SP2-RUN-06, SP2-RUN-07, SP2-RUN-08)
# ---------------------------------------------------------------------------


class TestRunManifest:
    """Run manifest is written with stage summary, N/A quality, coverage."""

    def test_manifest_exists(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        client = _setup_mock_client()

        with TemporaryDirectory() as tmpdir:
            run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            manifest_path = Path(tmpdir) / "run-manifest.yaml"
            assert manifest_path.exists()
            manifest = yaml.safe_load(manifest_path.read_text())
            assert "stage_summary" in manifest
            assert "stage_3" in manifest["stage_summary"]
            assert "input_hashes" in manifest
            assert "prompt_hashes" in manifest
            assert "na_quality_flags" in manifest
            assert "coverage_analysis" in manifest


# ---------------------------------------------------------------------------
# Input hashes (SP2-RUN-15)
# ---------------------------------------------------------------------------


class TestInputHashes:
    """Run manifest records input hashes."""

    def test_input_hashes_present(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        client = _setup_mock_client()

        with TemporaryDirectory() as tmpdir:
            run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            manifest = yaml.safe_load((Path(tmpdir) / "run-manifest.yaml").read_text())
            hashes = manifest["input_hashes"]
            assert "control_structure" in hashes
            assert "capability_profile" in hashes
            assert "loss_analysis" in hashes
            # SHA-256 hex digest is 64 chars
            for key in hashes:
                assert len(hashes[key]) == 64


# ---------------------------------------------------------------------------
# Prompt hashes (SP2-RUN-16)
# ---------------------------------------------------------------------------


class TestPromptHashes:
    """Run manifest records prompt hashes."""

    def test_prompt_hashes_present(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        client = _setup_mock_client()

        with TemporaryDirectory() as tmpdir:
            run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            manifest = yaml.safe_load((Path(tmpdir) / "run-manifest.yaml").read_text())
            hashes = manifest["prompt_hashes"]
            assert "stage3_system.j2" in hashes
            assert "stage3_user.j2" in hashes
            for key in hashes:
                assert len(hashes[key]) == 64  # SHA-256


# ---------------------------------------------------------------------------
# Slot count in output (SP2-RUN-17)
# ---------------------------------------------------------------------------


class TestSlotCountInOutput:
    """Slot count in output matches the formula."""

    def test_slot_count_40(self):
        """4 responsibilities × 2 CAs × 4 + 2 links × 4 = 40."""
        # Use the Klarna fixture dimensions: 4 resp × 2 CA, 2 links
        cps = [
            ControlledProcess(cp_id=f"CP-{i + 1}", description=f"P{i + 1}")
            for i in range(4)
        ]
        responsibilities = []
        for i in range(4):
            responsibilities.append(
                Responsibility(
                    resp_id=f"RESP-{i + 1}",
                    description=f"R{i + 1}",
                    process_model_parts=[
                        ProcessModelPart(pm_id=f"PM-{i + 1}-1", description="S")
                    ],
                    control_actions=[
                        ControlAction(
                            ca_id=f"CA-{i + 1}-{j + 1}",
                            description=f"A{j + 1}",
                            target=ElementRef(
                                type=ReferenceType.controlled_process, id=f"CP-{j + 1}"
                            ),
                        )
                        for j in range(2)
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id=f"FB-{i + 1}-1",
                            description="F",
                            updates=f"PM-{i + 1}-1",
                            source=ElementRef(
                                type=ReferenceType.controlled_process, id=f"CP-{i + 1}"
                            ),
                        )
                    ],
                )
            )
        links = [
            CoordinationLink(
                link_id=f"CL-{k + 1}",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id=f"CM-{k + 1}", description="M", payload="data"
                ),
                description="L",
            )
            for k in range(2)
        ]
        cs = ControlStructure(
            responsibilities=responsibilities,
            controlled_processes=cps,
            coordination_links=links,
        )
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()

        # Build mock responses for 4 responsibilities
        responses = []
        for i in range(4):
            resp_id = f"RESP-{i + 1}"
            responses.append(
                ICASlotFillResult.model_validate(
                    _make_valid_slot_fill_result(
                        resp_id, [f"CA-{i + 1}-1", f"CA-{i + 1}-2"]
                    )
                )
            )
        client = MockLLMClient()
        client.set_response_queue(responses)

        with TemporaryDirectory() as tmpdir:
            result = run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            assert len(result.ica_enumeration.slots) == 40


# ---------------------------------------------------------------------------
# N/A quality gates run after slot filling (SP2-RUN-07, SP2-RUN-14)
# ---------------------------------------------------------------------------


class TestNAQualityGatesInRun:
    """N/A quality gates run after slot filling and before catalog enrichment."""

    def test_na_quality_flags_recorded(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()

        # Build responses where RESP-1 has all 4 N/A with no structural keywords
        filled_slots = []
        for ca_id in ["CA-1-1", "CA-1-2"]:
            for uca_type in UCAType:
                slot_id = f"RESP-1:{ca_id}:{uca_type.value}"
                filled_slots.append(
                    {
                        "slot_id": slot_id,
                        "responsibility": "RESP-1",
                        "coordination_link": None,
                        "control_action": ca_id,
                        "uca_type": uca_type.value,
                        "is_na": True,
                        "icas": [],
                        "na_justification": "no hazard applicable",  # no structural keyword
                    }
                )
        resp1_result = {"filled_slots": filled_slots}

        client = MockLLMClient()
        client.set_response_queue(
            [
                ICASlotFillResult.model_validate(resp1_result),
                ICASlotFillResult.model_validate(
                    _make_valid_slot_fill_result("RESP-2", ["CA-2-1", "CA-2-2"])
                ),
            ]
        )

        with TemporaryDirectory() as tmpdir:
            result = run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            # RESP-1 has 8 N/A slots (2 CAs × 4 UCA types) with no structural keywords
            # CL-1 has 4 N/A slots (unfilled coordination links) also without structural keywords
            assert len(result.na_quality_result.flagged_slots) == 12
            # 8/8 = 100% > 75% → ratio flag for RESP-1
            assert len(result.na_quality_result.ratio_flags) == 1
            assert "RESP-1" in result.na_quality_result.ratio_flags[0]


# ---------------------------------------------------------------------------
# Prompt templates exist (SP2-RUN-09)
# ---------------------------------------------------------------------------


class TestPromptTemplatesExist:
    """Prompt templates exist for Stage 3."""

    def test_template_files_exist(self):
        from asago_scenario_generator.stpa.threat_enum._constants import PROMPTS_DIR

        assert (PROMPTS_DIR / "stage3_system.j2").exists()
        assert (PROMPTS_DIR / "stage3_user.j2").exists()


# ---------------------------------------------------------------------------
# Module layout (SP2-RUN-10)
# ---------------------------------------------------------------------------


class TestModuleLayout:
    """Module layout matches spec."""

    def test_all_modules_importable(self):
        from asago_scenario_generator.stpa.threat_enum import (
            slot_creation,
            technology_context,
            slot_filling,
            na_quality,
            catalog_enrichment,
            catalog_data,
            coverage,
            run,
        )

        assert slot_creation is not None
        assert technology_context is not None
        assert slot_filling is not None
        assert na_quality is not None
        assert catalog_enrichment is not None
        assert catalog_data is not None
        assert coverage is not None
        assert run is not None


# ---------------------------------------------------------------------------
# CLI script exists (SP2-RUN-12)
# ---------------------------------------------------------------------------


class TestCLIScript:
    """SP2 CLI script exists and accepts arguments."""

    def test_cli_help(self):
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "scripts/run_sp2.py", "--help"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parents[2]),
        )
        assert result.returncode == 0
        assert "--control-structure" in result.stdout
        assert "--capability-profile" in result.stdout
        assert "--loss-analysis" in result.stdout
        assert "--output-dir" in result.stdout
        assert "--max-workers" in result.stdout


# ---------------------------------------------------------------------------
# Mutation hardening tests
# ---------------------------------------------------------------------------


class TestRunMutationHardening:
    """Additional tests to kill surviving mutants in run.py."""

    def test_run_creates_nested_directory(self):
        """run_sp2 creates nested run_dir even when parent does not exist."""
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        client = _setup_mock_client()

        with TemporaryDirectory() as tmpdir:
            nested_dir = Path(tmpdir) / "nonexistent_parent" / "sp2-run"
            run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=nested_dir,
            )
            assert nested_dir.exists()
            assert (nested_dir / "ica-enumeration.yaml").exists()

    def test_manifest_na_count_correct(self):
        """Manifest na_count matches actual N/A slot count."""
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()

        # RESP-1 all N/A, RESP-2 non-N/A
        filled_slots = []
        for ca_id in ["CA-1-1", "CA-1-2"]:
            for uca_type in UCAType:
                slot_id = f"RESP-1:{ca_id}:{uca_type.value}"
                filled_slots.append(
                    {
                        "slot_id": slot_id,
                        "responsibility": "RESP-1",
                        "coordination_link": None,
                        "control_action": ca_id,
                        "uca_type": uca_type.value,
                        "is_na": True,
                        "icas": [],
                        "na_justification": "Action is atomic with no duration component",
                    }
                )
        client = MockLLMClient()
        client.set_response_queue(
            [
                ICASlotFillResult.model_validate({"filled_slots": filled_slots}),
                ICASlotFillResult.model_validate(
                    _make_valid_slot_fill_result("RESP-2", ["CA-2-1", "CA-2-2"])
                ),
            ]
        )

        with TemporaryDirectory() as tmpdir:
            run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            manifest = yaml.safe_load((Path(tmpdir) / "run-manifest.yaml").read_text())
            # RESP-1 has 8 N/A + RESP-2 has 2 wrong_duration N/A + CL-1 has 4 N/A = 14
            assert manifest["na_count"] == 14

    def test_manifest_stage_summary_call_count(self):
        """Manifest stage_summary has exact call_count for stage_3."""
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        client = _setup_mock_client()

        with TemporaryDirectory() as tmpdir:
            run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            manifest = yaml.safe_load((Path(tmpdir) / "run-manifest.yaml").read_text())
            assert manifest["stage_summary"]["stage_3"]["call_count"] == 2

    def test_manifest_stage_summary_total_tokens(self):
        """Manifest stage_summary total_tokens is non-negative."""
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        client = _setup_mock_client()

        with TemporaryDirectory() as tmpdir:
            run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            manifest = yaml.safe_load((Path(tmpdir) / "run-manifest.yaml").read_text())
            # total_tokens should be exactly 300 (2 calls × 150 tokens from MockLLMClient)
            # Must be exact to kill 0→1 initialization mutant
            assert manifest["stage_summary"]["stage_3"]["total_tokens"] == 300

    def test_manifest_slot_count_and_fill_rate(self):
        """Manifest slot_count and fill_rate are correct."""
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        client = _setup_mock_client()

        with TemporaryDirectory() as tmpdir:
            run_sp2(
                llm_client=client,
                control_structure=cs,
                capability_profile=cp,
                loss_analysis=la,
                run_dir=Path(tmpdir),
            )
            manifest = yaml.safe_load((Path(tmpdir) / "run-manifest.yaml").read_text())
            # 2 resp × 2 CA × 4 + 1 link × 4 = 20 total
            assert manifest["slot_count"] == 20
            # RESP-1: 6 non-N/A + 2 N/A; RESP-2: 6 non-N/A + 2 N/A; CL-1: 4 N/A
            # na_count = 2 + 2 + 4 = 8; non_na = 12; fill_rate = 12/20 = 0.6
            assert manifest["na_count"] == 8
            assert manifest["fill_rate"] == 0.6

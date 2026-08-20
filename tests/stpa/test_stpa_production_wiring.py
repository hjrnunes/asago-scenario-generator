"""Tests for the production STPA projection wiring (STPA-PROD-WIRING).

Stage 5 selects exactly the declared, evidence-backed causal factors and
stores them on the ScenarioSpec; project_execution maps them into the
candidate execution envelope without inference; Stage 6 feeds one
validator-derived alignment table to every prompt; artifact writing
exports the canonical projection beside the legacy YAML and feature.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.execution_envelope import (
    CausalFactor,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    ScenarioSpec,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    assemble_scenario_spec,
    populate_defender_bdi,
)
from asago_scenario_generator.stpa.scenario_prod.projection import (
    canonical_projection_data,
    export_projection_json,
    export_projection_yaml,
    project_execution,
    validate_projection_traceability,
)
from asago_scenario_generator.stpa.scenario_prod.prompt_alignment import (
    render_projection_alignment_table,
)
from tests.stpa.helpers import make_minimal_control_structure

UCA_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = "RESP-1:CA-1-1:WRONG_TIMING:1"
CANDIDATE_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"


def _threat() -> StructuralThreat:
    return StructuralThreat(
        ica_slot_id=UCA_SLOT,
        ica_id=ICA_ID,
        ica_text="Unsafe control action",
        hazardous_context="Context",
        loss_scenario="Loss scenario",
    )


def _attacker_bdi() -> AttackerBDI:
    return AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"])


def _llm_result(
    declarations: list[CausalFactorDeclaration] | None = None,
) -> BDIGenerationResult:
    return BDIGenerationResult(
        defender_vulnerabilities={"PM-1-1": "v"},
        attacker_bdi=_attacker_bdi(),
        causal_factors=declarations or [],
    )


def _declare(
    kind: CausalFactorKind,
    source_id: str,
    evidence: str | None = None,
    timing: str | None = None,
) -> CausalFactorDeclaration:
    return CausalFactorDeclaration(
        kind=kind,
        source_id=source_id,
        evidence=evidence or f"evidence:{source_id}",
        timing=timing,
    )


def _alignment_section(prompt: str) -> str:
    """Extract the rendered projection alignment table from a prompt."""
    start = prompt.index("Projection ID:")
    end = prompt.index("Realize the projection rows", start)
    return prompt[start:end].rstrip()


def _assemble(
    declarations: list[CausalFactorDeclaration] | None = None,
) -> ScenarioSpec:
    control_structure = make_minimal_control_structure()
    bdi = populate_defender_bdi(control_structure, "RESP-1")
    return assemble_scenario_spec(
        bdi,
        _llm_result(declarations),
        _threat(),
        control_structure,
        scenario_index=0,
    )


class TestStage5EvidenceBackedSelection:
    """STPA-PROD-WIRING-01: Stage 5 preserves evidence-backed factors."""

    def test_scenario_spec_stores_declared_factors_in_order(self):
        """PM-1-1 then FB-1-1 are stored in declared order."""
        spec = _assemble(
            [
                _declare(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _declare(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        assert [factor.source_id for factor in spec.causal_factors] == [
            "PM-1-1",
            "FB-1-1",
        ]
        assert spec.scenario_id == "SCN-001"

    def test_each_factor_keeps_kind_source_and_evidence(self):
        """Declared kind, source ID, and evidence description are retained."""
        spec = _assemble(
            [
                _declare(
                    CausalFactorKind.process_model_flaw,
                    "PM-1-1",
                    evidence="model diverges after injection",
                ),
                _declare(
                    CausalFactorKind.feedback_delay,
                    "FB-1-1",
                    evidence="state updates lag",
                ),
            ]
        )
        first, second = spec.causal_factors
        assert first.kind == CausalFactorKind.process_model_flaw
        assert first.source_id == "PM-1-1"
        assert first.description == "model diverges after injection"
        assert second.kind == CausalFactorKind.feedback_delay
        assert second.source_id == "FB-1-1"
        assert second.description == "state updates lag"

    def test_scenario_spec_validates_factor_references(self):
        """validate_against accepts factors present in the control structure."""
        spec = _assemble(
            [
                _declare(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _declare(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        spec.validate_against(make_minimal_control_structure())  # no raise

    def test_no_factor_selected_from_structural_presence_alone(self):
        """Empty declarations yield an empty factor list despite structure."""
        spec = _assemble([])
        assert spec.causal_factors == []
        # The full structure still contains PM-1-1, FB-1-1, CA-1-1.
        control_structure = make_minimal_control_structure()
        spec.validate_against(control_structure)


class TestStage5InvalidReferenceStopsProjection:
    """STPA-PROD-WIRING-02: unknown factor references fail Stage 5."""

    @pytest.mark.parametrize(
        ("kind", "source_id"),
        [
            (CausalFactorKind.process_model_flaw, "PM-99-1"),
            (CausalFactorKind.feedback_delay, "FB-99-1"),
            (CausalFactorKind.actuator_anomaly, "CA-99-1"),
        ],
    )
    def test_assembly_raises_causal_factor_reference_error(self, kind, source_id):
        """Stage 5 assembly fails with a causal-factor reference error."""
        with pytest.raises(ValueError) as excinfo:
            _assemble([_declare(kind, source_id)])
        message = str(excinfo.value)
        assert "Causal factor" in message
        assert source_id in message
        assert "not a known" in message

    def test_validate_against_rejects_unknown_reference(self):
        """ScenarioSpec.validate_against fails closed for bad references."""
        spec = _assemble([_declare(CausalFactorKind.process_model_flaw, "PM-1-1")])
        bad = spec.model_copy(
            update={
                "causal_factors": [
                    CausalFactor(
                        kind=CausalFactorKind.process_model_flaw,
                        source_id="PM-99-1",
                        description="evidence",
                    )
                ]
            }
        )
        with pytest.raises(ValueError):
            bad.validate_against(make_minimal_control_structure())


class TestProjectExecutionSeam:
    """STPA-PROD-WIRING-03: project_execution is deterministic, inference-free."""

    def _spec(self, declarations):
        return _assemble(declarations)

    def test_applied_twice_yields_byte_equivalent_envelopes(self):
        """Two projections of the same spec are byte-equivalent."""
        spec = self._spec(
            [
                _declare(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _declare(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        control_structure = make_minimal_control_structure()
        assert project_execution(spec, control_structure).model_dump(
            mode="json"
        ) == project_execution(spec, control_structure).model_dump(mode="json")

    def test_envelope_candidate_identifier_is_canonical(self):
        """The envelope candidate identifier is EXEC:RESP-1:CA-1-1:WRONG_TIMING."""
        spec = self._spec([_declare(CausalFactorKind.process_model_flaw, "PM-1-1")])
        envelope = project_execution(spec, make_minimal_control_structure())
        assert envelope.candidate_id == CANDIDATE_ID

    def test_envelope_factors_follow_declared_order(self):
        """The envelope carries PM-1-1, FB-1-1 in declared order."""
        spec = self._spec(
            [
                _declare(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _declare(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        envelope = project_execution(spec, make_minimal_control_structure())
        assert [factor.source_id for factor in envelope.causal_factors] == [
            "PM-1-1",
            "FB-1-1",
        ]

    def test_no_undeclared_temporal_behavior(self):
        """The vector contains nothing beyond the declared factors."""
        spec = self._spec([_declare(CausalFactorKind.feedback_delay, "FB-1-1")])
        envelope = project_execution(spec, make_minimal_control_structure())
        vector = envelope.temporal_vector
        assert vector is not None
        assert [a.source_id for a in vector.assertions] == ["FB-1-1"]
        assert [s.source_id for s in vector.steps] == ["FB-1-1", "CA-1-1"]

    def test_envelope_carries_separate_ica_and_scenario_identity(self):
        """ICA ID and scenario ID are separate identity fields."""
        spec = self._spec([_declare(CausalFactorKind.process_model_flaw, "PM-1-1")])
        envelope = project_execution(spec, make_minimal_control_structure())
        assert envelope.ica_id == ICA_ID
        assert envelope.scenario_id == "SCN-001"


class TestExplicitEmptyContract:
    """STPA-PROD-WIRING-04: explicit empty stays present and empty."""

    def test_scenario_spec_has_present_empty_causal_factors(self):
        """An explicit empty Stage 5 list is a present empty field."""
        spec = _assemble([])
        assert spec.causal_factors == []
        assert isinstance(spec.causal_factors, list)

    def test_projection_has_present_empty_vectors(self):
        """causal_factors, assertions, and steps are present empty lists."""
        spec = _assemble([])
        doc = canonical_projection_data(
            project_execution(spec, make_minimal_control_structure())
        )
        assert doc["causal_factors"] == []
        assert doc["assertions"] == []
        assert doc["steps"] == []
        result = validate_projection_traceability(doc)
        assert result.valid is True

    def test_structural_presence_invents_nothing(self):
        """PM-1-1/FB-1-1/CA-1-1 presence never invents behavior."""
        spec = _assemble([])
        envelope = project_execution(spec, make_minimal_control_structure())
        vector = envelope.temporal_vector
        assert vector is not None
        assert vector.assertions == []
        assert vector.steps == []
        assert vector.uca_constraint is None


class TestOneAlignmentReachesEveryStage6Call:
    """STPA-PROD-WIRING-05: one alignment constrains all Stage 6 calls."""

    def _doc_and_table(self):
        spec = _assemble(
            [
                _declare(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _declare(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        doc = canonical_projection_data(
            project_execution(spec, make_minimal_control_structure())
        )
        return doc, render_projection_alignment_table(doc)

    def test_table_rows_factor_order_with_uca_last(self):
        """One row for PM-1-1, one for FB-1-1, final row for CA-1-1."""
        _doc, table = self._doc_and_table()
        rows = [
            line
            for line in table.splitlines()
            if line.strip().startswith("|") and "---" not in line
        ][1:]
        assert len(rows) == 3
        assert rows[0].split("|")[1].strip() == "PM-1-1"
        assert rows[1].split("|")[1].strip() == "FB-1-1"
        assert rows[2].split("|")[1].strip() == "CA-1-1"
        assert "UNSAFE_CONTROL_ACTION" in rows[2]

    def test_stage6_prompts_forbid_inventing(self):
        """Every Stage 6 prompt forbids inventing factors, assertions, steps."""
        from asago_scenario_generator.stpa.scenario_prod._constants import (
            PROMPTS_DIR,
        )
        from asago_scenario_generator.stpa.infra.templates import TemplateLoader
        from asago_scenario_generator.stpa.scenario_prod.gherkin import (
            build_gherkin_prompts,
        )
        from asago_scenario_generator.stpa.scenario_prod.narrative import (
            build_narrative_prompts,
        )
        from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
            build_attack_tree_prompts,
        )
        from tests.stpa.helpers import make_minimal_loss_analysis

        spec = _assemble(
            [
                _declare(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _declare(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        doc = canonical_projection_data(
            project_execution(spec, make_minimal_control_structure())
        )
        table = render_projection_alignment_table(doc)
        loader = TemplateLoader(PROMPTS_DIR)
        loss_analysis = make_minimal_loss_analysis()
        prompt_pairs = [
            build_narrative_prompts(spec, loader, projection_alignment=table),
            build_attack_tree_prompts(
                spec,
                make_minimal_control_structure(),
                loader,
                projection_alignment=table,
            ),
            build_gherkin_prompts(
                spec,
                loss_analysis.security_constraints[0],
                loss_analysis,
                loader,
                projection_alignment=table,
            ),
        ]
        for system_prompt, user_prompt in prompt_pairs:
            for prompt in (system_prompt, user_prompt):
                assert "Do not invent any causal factor" in prompt
                assert "semantic structural IDs" in prompt

    def test_alignment_table_uses_semantic_ids(self):
        """The table references semantic structural IDs, not positions."""
        _doc, table = self._doc_and_table()
        assert "semantic structural IDs" in table
        assert "not positional labels" in table


class TestArtifactWriting:
    """STPA-PROD-WIRING-06: canonical projection is written beside legacy."""

    def _write(self, tmp_path: Path) -> dict:
        spec = _assemble([_declare(CausalFactorKind.process_model_flaw, "PM-1-1")])
        envelope = project_execution(spec, make_minimal_control_structure())
        doc = canonical_projection_data(envelope)
        legacy = {
            "scenario_id": spec.scenario_id,
            "causal_factors": [
                {
                    "kind": factor.kind.value,
                    "source_id": factor.source_id,
                    "description": factor.description,
                }
                for factor in spec.causal_factors
            ],
        }
        (tmp_path / f"{spec.scenario_id}.yaml").write_text(
            yaml.safe_dump(legacy), encoding="utf-8"
        )
        (tmp_path / f"{spec.scenario_id}.feature").write_text(
            "Feature: SCN-001\n", encoding="utf-8"
        )
        canonical_dir = tmp_path / "canonical"
        canonical_dir.mkdir(parents=True, exist_ok=True)
        (canonical_dir / f"{spec.scenario_id}.projection.json").write_text(
            export_projection_json(doc), encoding="utf-8"
        )
        (canonical_dir / f"{spec.scenario_id}.projection.yaml").write_text(
            export_projection_yaml(doc), encoding="utf-8"
        )
        return doc

    def test_scenario_dir_contains_legacy_and_canonical_artifacts(self, tmp_path):
        """Legacy YAML/feature and canonical JSON/YAML all exist."""
        self._write(tmp_path)
        assert (tmp_path / "SCN-001.yaml").is_file()
        assert (tmp_path / "SCN-001.feature").is_file()
        assert (tmp_path / "canonical" / "SCN-001.projection.json").is_file()
        assert (tmp_path / "canonical" / "SCN-001.projection.yaml").is_file()

    def test_canonical_artifacts_declare_schema_version(self, tmp_path):
        """Both canonical artifacts declare stpa-execution-projection-v1."""
        self._write(tmp_path)
        json_doc = json.loads(
            (tmp_path / "canonical" / "SCN-001.projection.json").read_text(
                encoding="utf-8"
            )
        )
        yaml_doc = yaml.safe_load(
            (tmp_path / "canonical" / "SCN-001.projection.yaml").read_text(
                encoding="utf-8"
            )
        )
        assert json_doc["schema_version"] == "stpa-execution-projection-v1"
        assert yaml_doc["schema_version"] == "stpa-execution-projection-v1"

    def test_canonical_artifacts_identify_ica_and_scenario_separately(self, tmp_path):
        """ICA ID and scenario ID are separate fields in both artifacts."""
        self._write(tmp_path)
        json_doc = json.loads(
            (tmp_path / "canonical" / "SCN-001.projection.json").read_text(
                encoding="utf-8"
            )
        )
        assert json_doc["ica_id"] == ICA_ID
        assert json_doc["scenario_id"] == "SCN-001"
        assert json_doc["candidate_id"] == CANDIDATE_ID

    def test_standard_reader_parses_canonical_artifact(self, tmp_path):
        """Parsing needs only standard JSON/YAML readers."""
        self._write(tmp_path)
        json_doc = json.loads(
            (tmp_path / "canonical" / "SCN-001.projection.json").read_text(
                encoding="utf-8"
            )
        )
        assert json_doc["causal_factors"][0]["source_id"] == "PM-1-1"


class TestRunSp3ProductionWiring:
    """End-to-end run_sp3 wiring: Stage 5 → Stage 6 → artifacts."""

    def _run_sp3(
        self,
        tmp_path,
        declarations: list[CausalFactorDeclaration],
        *,
        num_threats: int = 1,
    ):
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
        )
        from asago_scenario_generator.stpa.models.loss_analysis import (
            Hazard,
            Loss,
            LossAnalysis,
            LossProvenance,
            SecurityConstraint,
        )
        from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
        from tests.stpa.sp1_helpers import MockLLMClient

        control_structure = ControlStructure(
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
                        )
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="Feedback",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.controlled_process, id="CP-1"
                            ),
                        )
                    ],
                )
            ],
            controlled_processes=[
                ControlledProcess(cp_id="CP-1", description="Interface")
            ],
        )
        loss_analysis = LossAnalysis(
            risk_card_losses=[
                Loss(
                    loss_id="L-1",
                    description="Loss",
                    provenance=LossProvenance.risk_card,
                    source_risk_cards=["r1"],
                )
            ],
            use_case_losses=[],
            hazards=[
                Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1",
                    description="Must validate",
                    related_hazards=["H-1"],
                )
            ],
        )
        threats = [
            StructuralThreat(
                ica_slot_id=UCA_SLOT,
                ica_id=ICA_ID,
                ica_text="ICA text",
                hazardous_context="Context",
                loss_scenario="Loss scenario",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            )
        ]
        enriched_threat_set = EnrichedThreatSet(
            structural_threats=threats,
            coverage_analysis=CoverageAnalysis(
                structural_coverage={
                    "total_slots": 1,
                    "non_na": 1,
                    "na": 0,
                    "coverage_rate": 1.0,
                },
                structural_consideration={
                    "total_slots": 1,
                    "considered": 1,
                    "rate": 1.0,
                },
                na_quality={"na_count": 0, "quality_count": 0, "quality_rate": 1.0},
            ),
        )

        client = MockLLMClient()
        client.set_response_queue(
            [
                BDIGenerationResult(
                    defender_vulnerabilities={"PM-1-1": "v"},
                    attacker_bdi=_attacker_bdi(),
                    causal_factors=declarations,
                ),
                (
                    "Step 1: The defender process model starts correct.\n"
                    "Step 2: The attacker manipulates FB-1-1.\n"
                    "Step 3: The process model PM-1-1 diverges.\n"
                    "Step 4: The defender acts on false beliefs.\n"
                    "Step 5: The ICA occurs.\n"
                    "Step 6: The hazard is realized.\n"
                    "Step 7: The loss follows.\n"
                ),
                json.dumps(
                    {
                        "root": "Induce ICA WRONG_TIMING on CA-1-1",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "Corrupt PM-1-1",
                                "children": [],
                            }
                        ],
                        "leaves": ["Poison PM-1-1"],
                    }
                ),
                (
                    "feature: Attack scenario\n"
                    "scenario: Attack scenario\n"
                    "given:\n"
                    "  - Given PM-1-1 is in a valid state\n"
                    "when:\n"
                    "  - When the attacker sends a malicious request\n"
                    "then_expected:\n"
                    "  - Then the system should reject the request\n"
                    "then_actual:\n"
                    "  - But the system approves the request\n"
                ),
            ]
        )
        run_dir = tmp_path / "run"
        result = run_sp3(
            llm_client=client,
            enriched_threat_set=enriched_threat_set,
            control_structure=control_structure,
            loss_analysis=loss_analysis,
            run_dir=run_dir,
        )
        return result, client, run_dir

    def test_declared_factors_reach_scenario_yaml_and_canonical_artifacts(
        self, tmp_path
    ):
        """Stage 5 factors land in the envelope YAML and canonical exports."""
        result, _client, run_dir = self._run_sp3(
            tmp_path,
            [
                _declare(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _declare(CausalFactorKind.feedback_delay, "FB-1-1"),
            ],
        )
        assert len(result.scenario_envelopes) == 1
        spec = result.scenario_envelopes[0].scenario_spec
        assert [f.source_id for f in spec.causal_factors] == ["PM-1-1", "FB-1-1"]

        scenario_yaml = (run_dir / "scenarios" / "SCN-001.yaml").read_text(
            encoding="utf-8"
        )
        assert "PM-1-1" in scenario_yaml
        assert "FB-1-1" in scenario_yaml

        canonical_json = json.loads(
            (run_dir / "scenarios" / "canonical" / "SCN-001.projection.json").read_text(
                encoding="utf-8"
            )
        )
        assert canonical_json["ica_id"] == ICA_ID
        assert canonical_json["scenario_id"] == "SCN-001"
        assert canonical_json["candidate_id"] == CANDIDATE_ID
        assert [f["source_id"] for f in canonical_json["causal_factors"]] == [
            "PM-1-1",
            "FB-1-1",
        ]
        assert (
            run_dir / "scenarios" / "canonical" / "SCN-001.projection.yaml"
        ).is_file()

    def test_stage6_calls_receive_identical_alignment_table(self, tmp_path):
        """Narrative, tree, and Gherkin prompts share one alignment table."""
        _result, client, run_dir = self._run_sp3(
            tmp_path,
            [
                _declare(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _declare(CausalFactorKind.feedback_delay, "FB-1-1"),
            ],
        )
        stage6_calls = [
            call
            for call in client.calls
            if call.system_prompt and "Projection Alignment" in call.user_prompt
        ]
        assert len(stage6_calls) == 3
        tables = [_alignment_section(call.user_prompt) for call in stage6_calls]
        assert tables[0] == tables[1] == tables[2]
        assert "PM-1-1" in tables[0] and "FB-1-1" in tables[0]
        assert "UNSAFE_CONTROL_ACTION" in tables[0]

    def test_calls_logged_with_alignment(self, tmp_path):
        """Stage 6 call log entries carry the alignment table."""
        _result, _client, run_dir = self._run_sp3(
            tmp_path,
            [_declare(CausalFactorKind.process_model_flaw, "PM-1-1")],
        )
        calls = [
            json.loads(line)
            for line in (run_dir / "calls.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        stage6 = [call for call in calls if call["stage"] == "stage_6"]
        assert len(stage6) == 3
        tables = []
        for call in stage6:
            prompt = call["user_prompt_text"]
            assert "Projection Alignment" in prompt
            tables.append(_alignment_section(prompt))
        assert tables[0] == tables[1] == tables[2]

    def test_invalid_reference_stops_before_stage6(self, tmp_path):
        """A PM-99-1 factor yields a stage error and no Stage 6 calls."""
        result, client, run_dir = self._run_sp3(
            tmp_path,
            [_declare(CausalFactorKind.process_model_flaw, "PM-99-1")],
        )
        assert result.scenario_envelopes == []
        assert any("Causal factor" in error for error in result.stage_errors)
        stage6_calls = [
            call for call in client.calls if "Projection Alignment" in call.user_prompt
        ]
        assert stage6_calls == []
        assert not (run_dir / "scenarios" / "SCN-001.yaml").exists()
        assert not (run_dir / "scenarios" / "canonical").exists()

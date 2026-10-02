"""Tests for the production STPA projection wiring (STPA-PROD-WIRING).

Stage 5 selects exactly the declared, evidence-backed causal factors and
stores them on the ScenarioSpec; project_execution maps them into the
candidate execution envelope without inference; Stage 6 feeds one
validator-derived alignment table to every prompt; artifact writing
exports the canonical projection beside the legacy YAML and feature.
"""

from __future__ import annotations

import json

import pytest

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
    UnsafeOutcomeDeclaration,
    assemble_scenario_spec,
    populate_defender_bdi,
)
from asago_scenario_generator.stpa.models.semantic_conditions import OrderingCondition
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionDeliveryClass,
    RequestedEnvironmentBasis,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
)
from tests.stpa.helpers import make_minimal_control_structure

UCA_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = "RESP-1:CA-1-1:WRONG_TIMING:1"


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


def _threat() -> StructuralThreat:
    return StructuralThreat(
        ica_slot_id=UCA_SLOT,
        ica_id=ICA_ID,
        ica_text="Unsafe control action",
        hazardous_context="Context",
        loss_scenario="Loss scenario",
    )


def _attacker_bdi() -> AttackerBDI:
    return AttackerBDI(
        beliefs=["b"],
        desires=["d"],
        intentions=["i concerning CA-1-1"],
    )


def _unsafe_outcome() -> UnsafeOutcomeDeclaration:
    """Return the typed wrong-timing outcome used by corrected Stage 5 mocks."""
    return UnsafeOutcomeDeclaration(
        condition=OrderingCondition(reference_step_id="S-1", relation="after"),
        semantic_proposition="The response exhibits the unsafe semantic behavior.",
        semantic_binding_required=False,
    )


def _llm_result(
    declarations: list[CausalFactorDeclaration] | None = None,
) -> BDIGenerationResult:
    values = {
        "defender_vulnerabilities": {"PM-1-1": "v"},
        "attacker_bdi": _attacker_bdi(),
        "causal_factors": declarations or [],
        "execution_contract": _direct_execution_contract(),
    }
    if declarations:
        return BDIGenerationResult(**values)
    # Compatibility-only fixture for pre-correction ScenarioSpec artifacts.
    # Corrected provider responses go through normal validation and cannot be
    # empty; this bypass exists solely to retain legacy projection coverage.
    return BDIGenerationResult.model_construct(**values)


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
        temporal_condition=None,
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
                    evidence="model remains stale before action selection",
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
        assert first.description == "model remains stale before action selection"
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


class TestExplicitEmptyContract:
    """STPA-PROD-WIRING-04: explicit empty stays present and empty."""

    def test_scenario_spec_has_present_empty_causal_factors(self):
        """An explicit empty Stage 5 list is a present empty field."""
        spec = _assemble([])
        assert spec.causal_factors == []
        assert isinstance(spec.causal_factors, list)





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
                    rule="Must validate",
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
                                "description": "Rely on the declared structural factors.",
                                "source_handles": (
                                    ["cause_99"]
                                    if any(
                                        declaration.source_id == "PM-99-1"
                                        for declaration in declarations
                                    )
                                    else [
                                        f"cause_{index}"
                                        for index in range(1, len(declarations) + 1)
                                    ]
                                ),
                            }
                        ],
                    },
                    "causal_factors": [
                        {
                            "source_handle": f"cause_{index}",
                            "evidence": declaration.evidence,
                            "temporal_condition": declaration.temporal_condition,
                            "evidence_status": declaration.evidence_status.value,
                            "selected_for_route": index == 1,
                        }
                        for index, declaration in enumerate(declarations, start=1)
                    ],
                    "unsafe_outcome": {
                        **_unsafe_outcome().model_dump(
                            mode="json",
                            exclude={
                                "semantic_binding_required",
                                "hazard_refs",
                                "constraint_refs",
                            },
                        ),
                        "condition": {
                            "type": "ordering",
                            "reference_handle": "cause_1",
                            "relation": "after",
                        },
                    },
                    "execution_route": {
                        "disposition": "executable_route",
                        "action_kind": "model_output",
                        "reason": "The declared structural factor supports the direct route.",
                    },
                },
                (
                    "Step 1: The defender process model starts correct.\n"
                    "Step 2: Feedback FB-1-1 arrives late.\n"
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
                            },
                            {
                                "category": "path_side",
                                "label": "Actuator/executor failure",
                                "children": [],
                            },
                        ],
                        "leaves": ["PM-1-1 remains stale"],
                    }
                ),
                (
                    "feature: Attack scenario\n"
                    "scenario: Attack scenario\n"
                    "given:\n"
                    "  - Given PM-1-1 is in a valid state\n"
                    "when:\n"
                    "  - When PM-1-1 remains stale before CA-1-1\n"
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
            render_presentation=True,
        )
        return result, client, run_dir

    def test_declared_factors_reach_scenario_yaml(self, tmp_path):
        """Stage 5 factors land in the envelope and the published scenario YAML."""
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
            if call.system_prompt and "Projection Alignment" in call.system_prompt
        ]
        assert len(stage6_calls) == 3
        tables = [_alignment_section(call.system_prompt) for call in stage6_calls]
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
            system_prompt = call["system_prompt_text"]
            user_prompt = call["user_prompt_text"]
            assert "Projection Alignment" in system_prompt
            assert "Projection Alignment" not in user_prompt
            tables.append(_alignment_section(system_prompt))
        assert tables[0] == tables[1] == tables[2]

    def test_invalid_reference_stops_before_stage6(self, tmp_path):
        """A PM-99-1 factor yields a stage error and no Stage 6 calls."""
        result, client, run_dir = self._run_sp3(
            tmp_path,
            [_declare(CausalFactorKind.process_model_flaw, "PM-99-1")],
        )
        assert result.scenario_envelopes == []
        assert any(
            "Stage 5 BDI generation failed" in error for error in result.stage_errors
        )
        stage6_calls = [
            call
            for call in client.calls
            if "Projection Alignment" in call.system_prompt
        ]
        assert stage6_calls == []
        assert not (run_dir / "scenarios" / "SCN-001.yaml").exists()
        assert not (run_dir / "scenarios" / "canonical").exists()

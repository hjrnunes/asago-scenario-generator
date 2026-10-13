"""Tests for the production STPA projection wiring (STPA-PROD-WIRING).

Stage 5 selects exactly the declared, evidence-backed causal factors and
stores them on the ScenarioSpec; run_sp3 publishes them in the scenario
handoff YAML.
"""

from __future__ import annotations


import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    StructuralThreat,
    CoverageAnalysis,
    EnrichedThreatSet,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.sources import (
    _causal_source_choices,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    CausalFactorDeclaration,
    _CausalSourceChoice,
)
from tests.stpa.helpers import (
    make_minimal_control_structure,
)
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
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from tests.stpa.sp1_helpers import MockLLMClient
from tests.helpers.sp3_run import _semantics_wire
from tests.helpers.stage5_assembly import stage5_assembly
from tests.helpers.stage5_compile import compile_draft, draft_payload, factor

UCA_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = "RESP-1:CA-1-1:WRONG_TIMING:1"


_PROPOSITION = "The response exhibits the unsafe semantic behavior."


def _threat() -> StructuralThreat:
    return StructuralThreat(
        ica_slot_id=UCA_SLOT,
        ica_id=ICA_ID,
        ica_text="Unsafe control action",
        hazardous_context="Context",
        loss_scenario="Loss scenario",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )


def _control_structure() -> ControlStructure:
    """RESP-1 controls CP-1 through CA-1-1, with PM-1-1 and FB-1-1."""
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
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Interface")],
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r1"],
            )
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", rule="Must validate", related_hazards=["H-1"]
            )
        ],
    )


def _declare(
    kind: CausalFactorKind,
    source_id: str,
    evidence: str | None = None,
) -> CausalFactorDeclaration:
    return CausalFactorDeclaration(
        kind=kind,
        source_id=source_id,
        evidence=evidence or f"evidence:{source_id}",
        temporal_condition=None,
    )


def _assemble(declarations: list[CausalFactorDeclaration]) -> ScenarioSpec:
    """Compile a draft that declares ``declarations`` in order.

    A declaration whose source the context does not offer is bound to an
    extra request-local handle, so only assembly can reject it.
    """
    control_structure = _control_structure()
    context = build_scenario_generation_context(
        _threat(), control_structure, _loss_analysis(), scenario_id="SCN-001"
    )
    choices = list(_causal_source_choices(context))
    handles = []
    for declaration in declarations:
        known = [
            choice.handle
            for choice in choices
            if (choice.kind, choice.source_id)
            == (declaration.kind, declaration.source_id)
        ]
        if not known:
            choices.append(
                _CausalSourceChoice(
                    handle=f"cause_{len(choices) + 1}",
                    kind=declaration.kind,
                    source_id=declaration.source_id,
                    description="A source outside the control structure",
                )
            )
            known = [choices[-1].handle]
        handles.append(known[0])
    payload = draft_payload(
        [
            factor(handle, declaration.evidence)
            for handle, declaration in zip(handles, declarations)
        ],
        proposition=_PROPOSITION,
    )
    return compile_draft(
        payload,
        context,
        stage5_assembly(context, _threat(), control_structure),
        choices=choices,
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
        """Only the declared factor is stored despite the structure."""
        spec = _assemble([_declare(CausalFactorKind.process_model_flaw, "PM-1-1")])
        assert [factor.source_id for factor in spec.causal_factors] == ["PM-1-1"]
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
    """STPA-PROD-WIRING-04: an explicit empty factor list never compiles."""

    def test_explicit_empty_causal_factors_are_rejected(self):
        """A draft that declares no causal factor fails Stage 5."""
        with pytest.raises(ValidationError, match="causal_factors"):
            _assemble([])


class TestRunSp3ProductionWiring:
    """End-to-end run_sp3 wiring: Stage 5 → artifacts."""

    def _run_sp3(
        self,
        tmp_path,
        declarations: list[CausalFactorDeclaration],
        *,
        num_threats: int = 1,
    ):

        control_structure = _control_structure()
        loss_analysis = _loss_analysis()
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
                _semantics_wire(
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
                            "semantic_proposition": _PROPOSITION,
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
                    }
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

    def test_invalid_reference_stops_publication(self, tmp_path):
        """A PM-99-1 factor yields a stage error and no published scenario."""
        result, client, run_dir = self._run_sp3(
            tmp_path,
            [_declare(CausalFactorKind.process_model_flaw, "PM-99-1")],
        )
        assert result.scenario_envelopes == []
        assert any(
            "Stage 5 BDI generation failed" in error for error in result.stage_errors
        )
        assert not (run_dir / "scenarios" / "SCN-001.yaml").exists()
        assert not (run_dir / "scenarios" / "canonical").exists()

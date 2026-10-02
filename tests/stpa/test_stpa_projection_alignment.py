"""Tests for Stream B Slice 4 — validator-derived Stage 6 prompt alignment.

Covers STPA-PROJ-04-01 through STPA-PROJ-04-05 from the Gherkin feature
file: every narrative, tree, and Gherkin Stage 6 prompt renders the same
projection alignment table derived from the validated projection, and the
tables cannot drift from the causal-factor validator mappings.
"""

from __future__ import annotations



from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.narrative import (
    build_narrative_prompts,
)
from tests.stpa.helpers import make_minimal_control_structure

CONTROLLER = "RESP-1"
CONTROL_ACTION = "CA-1-1"
UCA_TYPE = UCAType.wrong_timing


def _factor(kind: CausalFactorKind, source_id: str) -> CausalFactor:
    return CausalFactor(kind=kind, source_id=source_id, description=source_id)


def _envelope(
    factors: list[CausalFactor],
) -> CandidateExecutionEnvelope:
    return assemble_candidate_envelope(
        make_minimal_control_structure(),
        controller_id=CONTROLLER,
        control_action_id=CONTROL_ACTION,
        uca_type=UCA_TYPE,
        causal_factors=factors,
        derive_temporal_vector=True,
    )




def _spec(control_structure: ControlStructure | None = None) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=f"{CONTROLLER}:{CONTROL_ACTION}:{UCA_TYPE.value}",
            provenance="structural",
        ),
        target_controller=CONTROLLER,
        target_control_action=CONTROL_ACTION,
        ica_type=UCA_TYPE,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="b", vulnerability="v")],
            desires=[DefenderDesire(resp_id=CONTROLLER, content="d")],
            intentions=[DefenderIntention(ca_id=CONTROL_ACTION, content="i")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="loss",
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Constraint",
                related_hazards=["H-1"],
            )
        ],
    )


def _loader() -> TemplateLoader:
    return TemplateLoader(PROMPTS_DIR)


class TestProj0401PromptRendering:
    """STPA-PROJ-04-01: every Stage 6 prompt contains the alignment table."""

    def test_default_builders_have_no_table(self):
        """Without the optional argument the builders stay backward compatible."""
        system_prompt, user_prompt = build_narrative_prompts(_spec(), _loader())
        assert "Projection Alignment" not in system_prompt
        assert "Projection Alignment" not in user_prompt









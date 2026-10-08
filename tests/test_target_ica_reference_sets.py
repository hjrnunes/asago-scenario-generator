"""A target-derived ICA may cite a responsibility constraint as a constraint."""

from __future__ import annotations

from asago_scenario_generator.models.target_realization import SystemicStpaBaseline
from asago_scenario_generator.pipeline.target_realization import (
    _target_ica_reference_sets,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)


def test_constraint_references_include_responsibility_constraint_ids() -> None:
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(
                    loss_id="L-1",
                    description="payment loss",
                    provenance=LossProvenance.use_case,
                )
            ],
            hazards=[
                Hazard(
                    hazard_id="H-1", description="bad payment", related_losses=["L-1"]
                )
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1",
                    rule="payments are authorized",
                    related_hazards=["H-1"],
                )
            ],
        ),
        control_structure=ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="payment controller",
                    security_constraint_refs=["SC-1"],
                    responsibility_constraints=[
                        ResponsibilityConstraint(
                            rc_id="RC-1-1",
                            description="Schedule only confirmed payments",
                        )
                    ],
                )
            ]
        ),
        ica_enumeration=ICAEnumeration(slots=[]),
        baseline_id="baseline:rc",
    )

    _, hazard_ids, constraint_ids = _target_ica_reference_sets(baseline)

    assert hazard_ids == {"H-1"}
    assert constraint_ids == {"SC-1", "RC-1-1"}

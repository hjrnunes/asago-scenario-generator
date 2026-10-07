"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis


USE_CASE = (
    "A library member may retrieve their own loan records.\n\n"
    "A librarian may update catalog entries."
)


def _authorities() -> tuple[LossAnalysis, ControlStructure]:
    losses = LossAnalysis.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [
                {
                    "loss_id": "L-1",
                    "description": "A loan record is disclosed to another member.",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                }
            ],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "A member receives another member's record.",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "Return records only to the requesting member.",
                    "related_hazards": ["H-1"],
                    "applies_when": [],
                }
            ],
        }
    )
    structure = ControlStructure.model_validate(
        {
            "responsibilities": [
                {
                    "resp_id": "RESP-1",
                    "description": "Return loan records",
                    "security_constraint_refs": ["SC-1"],
                }
            ],
            "controlled_processes": [],
        }
    )
    return losses, structure

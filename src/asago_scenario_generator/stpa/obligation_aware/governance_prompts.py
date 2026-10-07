"""Prompt view and rendering for governance-risk routing."""

from __future__ import annotations

from collections.abc import Sequence
import json

from pydantic import Field

from asago_scenario_generator.models.obligation_consideration import (
    NeutralObligationBrief,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    ProviderTargetIndex,
    _Model,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    _TEMPLATE_LOADER,
    _compact_routing_target_payload,
    _yaml,
    project_control_structure_context,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import SlotPlaceholder


class GovernanceRiskRow(_Model):
    """One governance risk as the routing model sees it."""

    risk_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)


class GovernanceRoutingContext(_Model):
    """Closed provider view for one governance-routing batch."""

    rows: tuple[GovernanceRiskRow, ...] = Field(min_length=1)
    target_index: ProviderTargetIndex


def _risk_row(brief: NeutralObligationBrief) -> GovernanceRiskRow:
    risk = brief.risk_ref
    name = risk.risk_name or risk.risk_id
    return GovernanceRiskRow(
        risk_id=risk.risk_id,
        name=name,
        description=risk.risk_description or name,
    )


def project_governance_routing_context(
    *,
    briefs: Sequence[NeutralObligationBrief],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder] = (),
) -> GovernanceRoutingContext:
    """Build the provider view: the risks and the control-structure index."""
    rows = tuple(
        sorted((_risk_row(item) for item in briefs), key=lambda item: item.risk_id)
    )
    return GovernanceRoutingContext(
        rows=rows,
        target_index=project_control_structure_context(
            control_structure, slots=slots, loss_analysis=loss_analysis
        ),
    )


def governance_placement_example() -> str:
    """Render a complete schema example with fixture identifiers."""
    return _yaml_json(
        {
            "placements": [
                {
                    "risk_id": "<risk_id>",
                    "targets": [
                        {
                            "target_id": "<control action id from the index>",
                            "reason": "explains how the risk comes about through this action",
                        }
                    ],
                },
                {"risk_id": "<another risk_id>", "targets": []},
            ]
        }
    )


def _yaml_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def build_governance_routing_prompts(
    *,
    briefs: Sequence[NeutralObligationBrief],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder] = (),
) -> tuple[str, str]:
    """Render the system and user prompts for one governance batch."""
    context = project_governance_routing_context(
        briefs=briefs,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        slots=slots,
    )
    system = _TEMPLATE_LOADER.render_prompt(
        "governance_routing_system.j2",
        row_count=len(context.rows),
        placement_example=governance_placement_example(),
    )
    user = _TEMPLATE_LOADER.render_prompt(
        "governance_routing_user.j2",
        risk_rows_yaml=_yaml([row.model_dump() for row in context.rows]),
        target_index_yaml=_yaml(_compact_routing_target_payload(context.target_index)),
    )
    return system, user

"""ICAEnumeration boundary schema (Section 4.3 of the STPA-Sec foundation spec).

SP2 internal, consumed by SP2 Stage 4.

Cross-artifact validation against LossAnalysis and ControlStructure
requires the referencing model to have access to the referenced models.
This is handled by the ``validate_against`` method.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, model_validator

from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionTemporality,
)

if TYPE_CHECKING:
    from asago_scenario_generator.stpa.models.control_structure import ControlStructure
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis


def classify_ica_semantics(
    uca_type: str, *, action_state: str, hazard_path: str
) -> str:
    """Combine reviewed action/harm facts with the fixed category, not model prose.

    Callers validate their closed review vocabularies before invoking this pure
    rule. Unknown categories raise KeyError; they are not an inferred decision.
    """
    expected = {
        "NOT_PROVIDED": "absent",
        "INCORRECT": "performed_unsafe",
        "WRONG_TIMING": "wrong_timing",
        "WRONG_DURATION": "wrong_duration",
    }[uca_type]
    if hazard_path == "contradictory":
        return "contradictory"
    if action_state == "undetermined":
        return "insufficient_evidence"
    if action_state != expected:
        return "contradictory"
    return hazard_path


class UCAType(str, Enum):
    """Type of Unsafe Control Action."""

    not_provided = "NOT_PROVIDED"
    incorrect = "INCORRECT"
    wrong_timing = "WRONG_TIMING"
    wrong_duration = "WRONG_DURATION"


class ICA(BaseModel):
    """An Individual Control Action (unsafe control action instance)."""

    ica_id: str  # RESP-X:CA-Y:TYPE-Z:N
    ica_text: str
    deviation: str | None = Field(
        default=None,
        min_length=1,
        exclude_if=lambda value: value is None,
        description="Original deviation clause, separate from the rendered controller/action sentence.",
    )
    hazardous_context: str
    loss_scenario: str
    related_hazards: list[str] = Field(
        default_factory=list,
        description="Hazard ID references from LossAnalysis.",
    )
    related_constraints: list[str] = Field(
        default_factory=list,
        description="Constraint ID or RC ID references.",
    )
    context_row: str | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description="Cited row of the control action's context table.",
    )
    process_model_context: dict[str, str] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description=(
            "Process-model variable values of the cited context row, keyed by "
            "PM-X-Y; the exact context in which the action is unsafe."
        ),
    )
    quality_warnings: list[str] = Field(
        default_factory=list,
        description=(
            "Non-blocking human-facing prose diagnostics. These warnings do not "
            "change the ICA's structural validity."
        ),
    )


def ica_id_for(slot_id: str, index: int) -> str:
    """Return the deterministic ICA identifier for a 1-based slot position."""
    return f"{slot_id}:{index}"


def candidate_id_for(
    controller_id: str,
    control_action_id: str,
    uca_type: UCAType,
) -> str:
    """Return the canonical candidate identifier for an unsafe control action."""
    return f"EXEC:{controller_id}:{control_action_id}:{uca_type.value}"


def align_icas(slot_id: str, icas: list[ICA]) -> list[ICA]:
    """Give each ICA its deterministic slot-relative identifier."""
    aligned: list[ICA] = []
    for index, ica in enumerate(icas, start=1):
        wanted = ica_id_for(slot_id, index)
        if ica.ica_id == wanted:
            aligned.append(ica)
        else:
            aligned.append(ica.model_copy(update={"ica_id": wanted}))
    return aligned


class ICASlot(BaseModel):
    """A slot for enumerating ICAs for a control action and UCA type."""

    slot_id: str  # RESP-X:CA-Y:TYPE-Z or CL-X:CM-Y:TYPE-Z
    responsibility: str | None = None  # resp_id, None for coordination link slots
    coordination_link: str | None = None  # link_id, None for responsibility slots
    control_action: str  # ca_id or cm_id
    action_temporality: ControlActionTemporality | None = Field(
        default=None,
        description=(
            "Typed temporal shape copied from the authoritative control action; "
            "missing means a legacy/analytical slot."
        ),
    )
    uca_type: UCAType
    is_na: bool
    icas: list[ICA] = Field(default_factory=list)  # empty if is_na
    na_justification: str | None = None  # required if is_na
    unresolved_reason: str | None = Field(
        default=None,
        description=(
            "Typed reason why this slot could not be analyzed; unlike a true "
            "N/A decision, an unresolved slot retains no ICA findings."
        ),
    )

    def aligned(self) -> ICASlot:
        """Return a copy whose ICA identifiers match this slot's positions."""
        return self.model_copy(update={"icas": align_icas(self.slot_id, self.icas)})

    @model_validator(mode="after")
    def validate_na_exclusivity(self) -> ICASlot:
        if self.unresolved_reason is not None:
            if not self.unresolved_reason.strip():
                raise ValueError(
                    f"ICA slot {self.slot_id} unresolved_reason must be non-empty."
                )
            if self.is_na:
                raise ValueError(
                    f"ICA slot {self.slot_id} cannot be both unresolved and is_na=true."
                )
            if self.icas:
                raise ValueError(
                    f"ICA slot {self.slot_id} is unresolved but icas is non-empty."
                )
            if self.na_justification is not None:
                raise ValueError(
                    f"ICA slot {self.slot_id} is unresolved but na_justification is set."
                )
            return self
        if self.is_na:
            if self.na_justification is None:
                raise ValueError(
                    f"ICA slot {self.slot_id} is_na=true but "
                    f"na_justification is not provided."
                )
            if self.icas:
                raise ValueError(
                    f"ICA slot {self.slot_id} is_na=true but icas is non-empty."
                )
        else:
            if not self.icas:
                raise ValueError(
                    f"ICA slot {self.slot_id} is_na=false but icas is empty."
                )
            if self.na_justification is not None:
                raise ValueError(
                    f"ICA slot {self.slot_id} is_na=false but na_justification is set."
                )
        return self


class ICAEnumeration(BaseModel):
    """ICA enumeration: a collection of ICA slots."""

    slots: list[ICASlot]

    @model_validator(mode="after")
    def validate_duplicate_slot_ids(self) -> ICAEnumeration:
        seen: set[str] = set()
        for slot in self.slots:
            if slot.slot_id in seen:
                raise ValueError(f"Duplicate slot_id: '{slot.slot_id}'.")
            seen.add(slot.slot_id)
        return self

    def validate_against(
        self,
        loss_analysis: LossAnalysis,
        control_structure: ControlStructure,
    ) -> None:
        """Validate ICA references against LossAnalysis and ControlStructure.

        Checks:
        - Every ICA.related_hazards entry references a valid hazard_id
          from LossAnalysis.
        - Every ICA.related_constraints entry references a valid
          constraint_id or rc_id.

        Args:
            loss_analysis: The loss analysis to validate against.
            control_structure: The control structure to validate against.

        Raises:
            ValueError: If any reference is invalid.
        """
        hazard_ids = {h.hazard_id for h in loss_analysis.hazards}
        constraint_ids = {sc.constraint_id for sc in loss_analysis.security_constraints}
        rc_ids = _collect_rc_ids(control_structure)
        valid_constraint_refs = constraint_ids | rc_ids

        for slot in self.slots:
            for ica in slot.icas:
                _validate_ica_references(ica, hazard_ids, valid_constraint_refs)


def _collect_rc_ids(control_structure: ControlStructure) -> set[str]:
    """Collect all responsibility constraint IDs from a control structure."""
    rc_ids: set[str] = set()
    for resp in control_structure.responsibilities:
        for rc in resp.responsibility_constraints:
            rc_ids.add(rc.rc_id)
    return rc_ids


def _validate_ica_references(
    ica: ICA,
    hazard_ids: set[str],
    valid_constraint_refs: set[str],
) -> None:
    """Validate a single ICA's hazard and constraint references."""
    for ref in ica.related_hazards:
        if ref not in hazard_ids:
            raise ValueError(
                f"ICA {ica.ica_id} references non-existent "
                f"hazard '{ref}' in related_hazards."
            )
    for ref in ica.related_constraints:
        if ref not in valid_constraint_refs:
            raise ValueError(
                f"ICA {ica.ica_id} references non-existent "
                f"constraint '{ref}' in related_constraints."
            )

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

if TYPE_CHECKING:
    from asago_scenario_generator.stpa.models.control_structure import ControlStructure
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis


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


def ica_id_for(slot_id: str, index: int) -> str:
    """Return the deterministic ICA identifier for a 1-based slot position."""
    return f"{slot_id}:{index}"


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
    uca_type: UCAType
    is_na: bool
    icas: list[ICA] = Field(default_factory=list)  # empty if is_na
    na_justification: str | None = None  # required if is_na

    def aligned(self) -> ICASlot:
        """Return a copy whose ICA identifiers match this slot's positions."""
        return self.model_copy(update={"icas": align_icas(self.slot_id, self.icas)})

    @model_validator(mode="after")
    def validate_na_exclusivity(self) -> ICASlot:
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

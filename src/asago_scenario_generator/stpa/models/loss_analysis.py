"""LossAnalysis boundary schema (Section 4.1 of the STPA-Sec foundation spec).

SP1 output, consumed by SP1 Stage 2, SP2 Stage 3, and SP3 Stage 7.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import AliasChoices, BaseModel, Field, model_validator

from asago_scenario_generator.stpa.models._validation import check_duplicate_ids


class LossProvenance(str, Enum):
    """How a loss was identified."""

    risk_card = "risk_card"
    use_case = "use_case"
    critic_derived = "critic_derived"


class Loss(BaseModel):
    """A system-level loss (something stakeholders want to avoid)."""

    loss_id: str = Field(validation_alias=AliasChoices("loss_id", "id"))
    description: str
    provenance: LossProvenance
    source_risk_cards: list[str] = Field(
        default_factory=list,
        description="Risk ID references; empty for use_case/critic_derived provenance.",
    )


class Hazard(BaseModel):
    """A system-level hazard (a condition that can lead to a loss)."""

    hazard_id: str = Field(validation_alias=AliasChoices("hazard_id", "id"))
    description: str
    related_losses: list[str]  # loss_id refs


class SecurityConstraint(BaseModel):
    """A security constraint (a condition that prevents a hazard)."""

    constraint_id: str = Field(validation_alias=AliasChoices("constraint_id", "id"))
    description: str
    related_hazards: list[str]  # hazard_id refs


class LossAnalysisDraft(BaseModel):
    """Intermediate loss analysis result from a single Stage 1a LLM call.

    Unlike :class:`LossAnalysis`, allows empty hazards and security_constraints
    for cases where no risk cards are provided (risk derivation) or no gaps
    are found (gap analysis).  Cross-reference validation is deferred to the
    merged :class:`LossAnalysis`.
    """

    risk_card_losses: list[Loss] = Field(default_factory=list)
    use_case_losses: list[Loss] = Field(default_factory=list)
    hazards: list[Hazard] = Field(default_factory=list)
    security_constraints: list[SecurityConstraint] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def split_generic_losses_by_explicit_provenance(cls, value: Any) -> Any:
        """Normalize a provider ``losses`` list without guessing provenance."""
        if not isinstance(value, dict) or "losses" not in value:
            return value
        data = dict(value)
        losses = data.pop("losses")
        if not isinstance(losses, list):
            return data
        if not data.get("risk_card_losses"):
            data["risk_card_losses"] = [
                item
                for item in losses
                if isinstance(item, dict) and item.get("provenance") == "risk_card"
            ]
        if not data.get("use_case_losses"):
            data["use_case_losses"] = [
                item
                for item in losses
                if not isinstance(item, dict) or item.get("provenance") != "risk_card"
            ]
        return data


class LossAnalysis(BaseModel):
    """Loss analysis artifact: losses, hazards, and security constraints."""

    risk_card_losses: list[Loss]
    use_case_losses: list[Loss]
    hazards: list[Hazard] = Field(min_length=1)
    security_constraints: list[SecurityConstraint] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_references_and_provenance(self) -> LossAnalysis:
        all_losses = self.risk_card_losses + self.use_case_losses
        loss_ids = {loss.loss_id for loss in all_losses}

        check_duplicate_ids([loss.loss_id for loss in all_losses], "loss_id")
        check_duplicate_ids([h.hazard_id for h in self.hazards], "hazard_id")
        check_duplicate_ids(
            [sc.constraint_id for sc in self.security_constraints], "constraint_id"
        )

        _validate_risk_card_provenance(self.risk_card_losses)
        _validate_use_case_provenance(self.use_case_losses)
        _validate_hazard_references(self.hazards, loss_ids)

        hazard_ids = {h.hazard_id for h in self.hazards}
        _validate_constraint_references(self.security_constraints, hazard_ids)

        return self


def _validate_risk_card_provenance(losses: list[Loss]) -> None:
    """Ensure every loss in risk_card_losses has risk_card provenance and non-empty source."""
    for loss in losses:
        if loss.provenance != LossProvenance.risk_card:
            raise ValueError(
                f"Loss {loss.loss_id} in risk_card_losses has provenance "
                f"'{loss.provenance.value}' but must be 'risk_card'."
            )
        if not loss.source_risk_cards:
            raise ValueError(
                f"Loss {loss.loss_id} has provenance 'risk_card' but "
                f"source_risk_cards is empty."
            )


def _validate_use_case_provenance(losses: list[Loss]) -> None:
    """Ensure every loss in use_case_losses has use_case/critic_derived provenance and empty source."""
    for loss in losses:
        if loss.provenance not in (
            LossProvenance.use_case,
            LossProvenance.critic_derived,
        ):
            raise ValueError(
                f"Loss {loss.loss_id} in use_case_losses has provenance "
                f"'{loss.provenance.value}' but must be 'use_case' or "
                f"'critic_derived'."
            )
        if loss.source_risk_cards:
            raise ValueError(
                f"Loss {loss.loss_id} has provenance '{loss.provenance.value}' "
                f"but source_risk_cards is non-empty: {loss.source_risk_cards}."
            )


def _validate_hazard_references(hazards: list[Hazard], loss_ids: set[str]) -> None:
    """Ensure every hazard's related_losses reference valid loss IDs."""
    for hazard in hazards:
        for ref in hazard.related_losses:
            if ref not in loss_ids:
                raise ValueError(
                    f"Hazard {hazard.hazard_id} references non-existent "
                    f"loss '{ref}' in related_losses."
                )


def _validate_constraint_references(
    constraints: list[SecurityConstraint], hazard_ids: set[str]
) -> None:
    """Ensure every constraint's related_hazards reference valid hazard IDs."""
    for sc in constraints:
        for ref in sc.related_hazards:
            if ref not in hazard_ids:
                raise ValueError(
                    f"SecurityConstraint {sc.constraint_id} references "
                    f"non-existent hazard '{ref}' in related_hazards."
                )

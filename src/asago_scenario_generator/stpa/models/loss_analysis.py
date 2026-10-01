"""LossAnalysis boundary schema (Section 4.1 of the STPA-Sec foundation spec).

SP1 output, consumed by SP1 Stage 2, SP2 Stage 3, and SP3 Stage 7.
"""

from __future__ import annotations

from datetime import date
from enum import Enum
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator

from asago_scenario_generator.stpa.models._validation import check_duplicate_ids


class LossProvenance(str, Enum):
    """How a loss was identified."""

    risk_card = "risk_card"
    use_case = "use_case"
    critic_derived = "critic_derived"


RiskDispositionKind = Literal["cited", "not_applicable"]

# Obligation entries (owner ruling Q30, 2026-09-10): an explicit, reviewed
# failure direction for a security constraint.  A ``required`` entry names a
# behavior the rule mandates and the channel that would realize it; a
# ``forbidden`` entry names a behavior the rule prohibits and the channel a
# violation would take.  ``provider_request`` is the transmission of a prompt
# to the third-party model: a real channel, but neither an agent tool call
# nor the reply, so no oracle kind observes it on this target.
ObligationKind = Literal["required", "forbidden"]
# Channels on which a forbidden behavior can be violated.  ``state`` and
# ``result`` name effect-layer observations (a state change, a tool result)
# that no compiled oracle kind observes; recording one on an entry is how a
# reviewed graph says "unobservable on this target" and excludes every kind
# instead of borrowing a channel the entry does not have.
ObligationChannel = Literal[
    "tool_call", "reply", "state", "result", "provider_request", "unknown"
]
# Channels on which a required behavior can be realized: the observable
# attempt or the reply.  Effect-layer realization is not representable: a
# required behavior whose only evidence is a state change carries
# ``unknown`` and holds as realization_unresolved.
RealizationChannel = Literal["tool_call", "reply", "unknown"]
ObservationRole = Literal["source", "proxy"]
DirectionAuthority = Literal["proposed", "reviewed"]


class Obligation(BaseModel):
    """One reviewed failure-direction entry on a security constraint.

    ``rule_span`` must quote the constraint rule verbatim (checked
    case-insensitively by the owning constraint).  A proxy observation
    (``observation_role: proxy``) is a separately reviewed claim and must
    name the source outcome it stands for; an attempt-level realization is
    not the behavior's completion, so a required entry may record the
    ``completion`` the oracle does not observe.  ``projection``/``residual``
    keep a partial projection's coverage and remainder explicit.
    """

    obligation_id: str = Field(pattern=r"^O[1-9][0-9]*$")
    kind: ObligationKind
    behavior: str = Field(min_length=1)
    rule_span: str = Field(min_length=1)
    realized_by: RealizationChannel | None = None
    violated_via: ObligationChannel | None = None
    observation_role: ObservationRole | None = None
    source_outcome: str | None = None
    completion: str | None = None
    projection: str | None = None
    residual: str | None = None
    note: str | None = None

    @model_validator(mode="after")
    def validate_kind_channels(self) -> Obligation:
        if self.kind == "required":
            if self.violated_via is not None:
                raise ValueError(
                    f"obligation {self.obligation_id!r} is required but carries "
                    "violated_via; required entries name realized_by"
                )
            if self.observation_role is not None or self.source_outcome is not None:
                raise ValueError(
                    f"obligation {self.obligation_id!r} is required but carries "
                    "observation_role/source_outcome; those belong to forbidden "
                    "entries"
                )
            if self.realized_by is None:
                self.realized_by = "unknown"
        else:
            if self.realized_by is not None:
                raise ValueError(
                    f"obligation {self.obligation_id!r} is forbidden but carries "
                    "realized_by; forbidden entries name violated_via"
                )
            if self.completion is not None:
                raise ValueError(
                    f"obligation {self.obligation_id!r} is forbidden but carries "
                    "completion; completion belongs to required entries"
                )
            if self.violated_via is None:
                self.violated_via = "unknown"
            if (
                self.observation_role == "proxy"
                and not (self.source_outcome or "").strip()
            ):
                raise ValueError(
                    f"obligation {self.obligation_id!r} is a proxy observation "
                    "and must name its source_outcome"
                )
            if (self.source_outcome or "").strip() and self.observation_role != "proxy":
                raise ValueError(
                    f"obligation {self.obligation_id!r} names a source_outcome "
                    "but is not marked observation_role: proxy"
                )
        return self


class RiskDisposition(BaseModel):
    """One supplied risk card's accounting entry in the loss analysis.

    Every supplied risk card must appear exactly once: either cited by at
    least one loss, or explicitly excluded with a non-empty reason.
    """

    risk_ref: str
    disposition: RiskDispositionKind
    loss_ids: list[str] = Field(default_factory=list)
    reason: str | None = None

    @model_validator(mode="after")
    def validate_disposition(self) -> RiskDisposition:
        if self.disposition == "cited":
            if not self.loss_ids:
                raise ValueError(
                    f"risk_dispositions entry '{self.risk_ref}' is cited but "
                    "names no loss_ids."
                )
            # Providers habitually echo an empty reason field on cited
            # entries; normalize that harmless artifact away.  A non-empty
            # reason is contradictory evidence and stays a wire violation
            # so the bounded retry can correct it.
            if self.reason is not None and not self.reason.strip():
                self.reason = None
            elif self.reason is not None:
                raise ValueError(
                    f"risk_dispositions entry '{self.risk_ref}' is cited but "
                    "also carries a reason; omit the reason field for cited "
                    "entries."
                )
            return self
        if self.loss_ids:
            raise ValueError(
                f"risk_dispositions entry '{self.risk_ref}' is not_applicable "
                "but names loss_ids; only cited entries name losses."
            )
        if self.reason is None or not self.reason.strip():
            raise ValueError(
                f"risk_dispositions entry '{self.risk_ref}' is not_applicable "
                "and requires a non-empty reason."
            )
        return self


class Loss(BaseModel):
    """A system-level loss (something stakeholders want to avoid)."""

    loss_id: str = Field(validation_alias=AliasChoices("loss_id", "id"))
    description: str
    provenance: LossProvenance
    source_risk_cards: list[str] = Field(
        default_factory=list,
        description="Risk ID references; empty for use_case/critic_derived provenance.",
    )

    @field_validator("source_risk_cards")
    @classmethod
    def canonicalize_source_risk_cards(cls, value: list[str]) -> list[str]:
        """Treat repeated provenance references as one set-like citation."""
        return sorted(set(value))


class Hazard(BaseModel):
    """A system-level hazard (a condition that can lead to a loss)."""

    hazard_id: str = Field(validation_alias=AliasChoices("hazard_id", "id"))
    description: str
    related_losses: list[str]  # loss_id refs


def compose_constraint_description(rule: str, applies_when: list[str]) -> str:
    """Compose the persisted constraint description (Phase 1.3 as amended).

    The fixed rendering every consumer sees: ``rule`` alone when the
    constraint applies unconditionally, otherwise ``"<rule> Applies when:
    <condition 1>; <condition 2>."``  The single source of the rendering,
    shared by the model validator and the Stage 2 semantic review.
    """
    if applies_when:
        return f"{rule} Applies when: " + "; ".join(applies_when) + "."
    return rule


class SecurityConstraint(BaseModel):
    """A security constraint (a condition that prevents a hazard).

    Phase 1.3 as amended (2026-09-07): the model authors ``rule`` (the
    obligation without its limiting conditions) and ``applies_when`` (the
    conditions under which the rule is in force, in the model's own words);
    deterministic code composes the persisted ``description``.  Nothing is
    matched against the constraint text.
    """

    constraint_id: str = Field(validation_alias=AliasChoices("constraint_id", "id"))
    rule: str = Field(min_length=1)
    related_hazards: list[str]  # hazard_id refs
    # Conditions under which the rule is in force; all must hold.  Empty
    # when the rule applies unconditionally; at most four.  The provider
    # wire requires the key so the model always decides.
    applies_when: list[str] = Field(default_factory=list, max_length=4)
    # Composed deterministically from rule + applies_when; never authored.
    # Composition also runs on load, so a tampered persisted description is
    # silently recomposed (not detected as corruption); the authored fields
    # are the integrity anchor.
    description: str = ""
    # Explicit failure-direction entries (owner ruling Q30, 2026-09-10).
    # Entries on a derived graph hold ``proposed`` authority, stamped by
    # deterministic code after every derivation or revision merge; the model
    # wire cannot claim ``reviewed``.  A pinned graph carries ``reviewed``
    # with its reviewer stamp.  ``None`` means unstamped and reads as
    # ``proposed``.
    obligations: list[Obligation] = Field(
        default_factory=list, exclude_if=lambda value: not value
    )
    direction_authority: DirectionAuthority | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    reviewed_by: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    reviewed_on: date | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @field_validator("applies_when")
    @classmethod
    def validate_applies_when(cls, value: list[str]) -> list[str]:
        """Wire-shape validation only; no condition is matched against text."""
        seen: set[str] = set()
        for entry in value:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(
                    "applies_when entries must be non-empty condition sentences."
                )
            key = entry.casefold()
            if key in seen:
                raise ValueError(
                    "applies_when entries must be distinct: " + repr(entry)
                )
            seen.add(key)
        return value

    @model_validator(mode="after")
    def compose_description(self) -> SecurityConstraint:
        self.description = compose_constraint_description(self.rule, self.applies_when)
        if self.description.strip() == "" or any(
            entry.strip().casefold() == self.rule.strip().casefold()
            for entry in self.applies_when
        ):
            raise ValueError(
                "SecurityConstraint carries an invalid rule/applies_when pair: "
                "an applies_when entry must not repeat the rule, and the rule "
                "must not be empty."
            )
        return self

    @model_validator(mode="after")
    def validate_obligations(self) -> SecurityConstraint:
        """Validate the failure-direction entries against the rule text."""
        ids = [entry.obligation_id for entry in self.obligations]
        if len(ids) != len(set(ids)):
            raise ValueError(
                f"SecurityConstraint {self.constraint_id} has duplicate obligation ids."
            )
        rule_folded = self.rule.casefold()
        for entry in self.obligations:
            if entry.rule_span.casefold() not in rule_folded:
                raise ValueError(
                    f"obligation {self.constraint_id}/{entry.obligation_id} "
                    "rule_span must quote the constraint rule verbatim: "
                    f"{entry.rule_span!r} is not an exact substring of the "
                    f"rule {self.rule!r}."
                )
        if self.direction_authority == "reviewed":
            if not (self.reviewed_by or "").strip() or self.reviewed_on is None:
                raise ValueError(
                    f"SecurityConstraint {self.constraint_id} claims reviewed "
                    "direction authority and must carry reviewed_by and "
                    "reviewed_on."
                )
        elif (self.reviewed_by or "").strip() or self.reviewed_on is not None:
            raise ValueError(
                f"SecurityConstraint {self.constraint_id} carries reviewer "
                "stamps but its direction authority is not reviewed."
            )
        return self

    @property
    def failure_direction(
        self,
    ) -> Literal["required", "forbidden", "mixed", "unresolved"]:
        """The constraint's failure direction, computed from its entries."""
        kinds = {entry.kind for entry in self.obligations}
        if kinds == {"required"}:
            return "required"
        if kinds == {"forbidden"}:
            return "forbidden"
        if kinds == {"required", "forbidden"}:
            return "mixed"
        return "unresolved"

    @property
    def effective_direction_authority(self) -> DirectionAuthority:
        """The authority in force; an unstamped direction reads as proposed."""
        return self.direction_authority or "proposed"

    def obligation_by_id(self, obligation_id: str) -> Obligation | None:
        """Return the entry with the given id, or None."""
        for entry in self.obligations:
            if entry.obligation_id == obligation_id:
                return entry
        return None


class LossAnalysisDraft(BaseModel):
    """Intermediate loss analysis result from a single Stage 1a LLM call.

    Unlike :class:`LossAnalysis`, allows empty hazards and security_constraints
    for cases where no risk cards are provided (risk derivation) or no gaps
    are found (gap analysis).  Cross-reference validation is deferred to the
    merged :class:`LossAnalysis`.
    """

    risk_card_losses: list[Loss] = Field(default_factory=list, max_length=16)
    use_case_losses: list[Loss] = Field(default_factory=list, max_length=16)
    hazards: list[Hazard] = Field(default_factory=list, max_length=16)
    security_constraints: list[SecurityConstraint] = Field(
        default_factory=list, max_length=16
    )
    # Only populated by the risk-derivation call; the gap call leaves this
    # empty because it reviews an existing graph and supplies no risk cards.
    risk_dispositions: list[RiskDisposition] = Field(default_factory=list)

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
    risk_dispositions: list[RiskDisposition] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_references_and_provenance(self) -> LossAnalysis:
        all_losses = self.risk_card_losses + self.use_case_losses
        loss_ids = {loss.loss_id for loss in all_losses}

        check_duplicate_ids([loss.loss_id for loss in all_losses], "loss_id")
        check_duplicate_ids([h.hazard_id for h in self.hazards], "hazard_id")
        check_duplicate_ids(
            [sc.constraint_id for sc in self.security_constraints], "constraint_id"
        )
        check_duplicate_ids([d.risk_ref for d in self.risk_dispositions], "risk_ref")

        _validate_risk_card_provenance(self.risk_card_losses)
        _validate_use_case_provenance(self.use_case_losses)
        _validate_hazard_references(self.hazards, loss_ids)
        _validate_disposition_loss_references(self.risk_dispositions, loss_ids)

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


def _validate_disposition_loss_references(
    dispositions: list[RiskDisposition], loss_ids: set[str]
) -> None:
    """Ensure every cited disposition's loss IDs reference existing losses."""
    for disposition in dispositions:
        for ref in disposition.loss_ids:
            if ref not in loss_ids:
                raise ValueError(
                    f"risk_dispositions entry '{disposition.risk_ref}' "
                    f"references non-existent loss '{ref}' in loss_ids."
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


def stamp_proposed_direction(analysis: LossAnalysis | LossAnalysisDraft) -> None:
    """Stamp ``proposed`` direction authority on a derived graph, in place.

    Deterministic code owns the authority stamp: the model wire can author
    obligation entries but cannot claim they were reviewed, so every derived
    or revision-merged constraint is restamped ``proposed`` and any
    wire-carried reviewer stamp is cleared.  Pinned graphs are never passed
    through here; they keep their supplied ``reviewed`` stamp.
    """
    for constraint in analysis.security_constraints:
        constraint.direction_authority = "proposed" if constraint.obligations else None
        constraint.reviewed_by = None
        constraint.reviewed_on = None

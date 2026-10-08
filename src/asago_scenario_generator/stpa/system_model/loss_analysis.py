"""Stage 1a — Loss Analysis derivation (two sequential LLM calls).

Call 1 (risk_derivation): derives losses, hazards, and security constraints
from organizational risk cards.

Call 2 (gap_analysis): reviews the use-case description against Call 1's
output to find missing adversary-actionable losses.  Receives the capability
profile as additional input for systematic coverage checking.

Provider responses use request-local handles. Deterministic compilation
allocates canonical loss/hazard/SC IDs across the two calls with no
duplicates; cross-references stay valid after merge.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, NoReturn

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    create_model,
    model_validator,
)

from asago_scenario_generator.request_schema import (
    string_items_enum,
    uses_guided_decoding,
    with_keyed_rows,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    build_kc_subcodes_display,
)
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.canonical_ids import allocate_canonical_ids
from asago_scenario_generator.stpa.infra.llm import (
    DEFAULT_TEMPERATURE,
    LLMClient,
    LLMResult,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    decode_content,
    _transformation,
    parse_llm_result,
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.loss_analysis import (
    BehaviorClass,
    Hazard,
    LossAnalysis,
    LossAnalysisDraft,
    Loss,
    LossProvenance,
    Obligation,
    RiskDisposition,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    TargetEvidence,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    TRUNCATED_DISPOSITION_RECOVERY_KIND,
    DeterministicCleanup,
    DispositionRepairPlan,
    ObligationRepairPlan,
    ReferenceRepairPlan,
    RepairPlan,
    RepairRecord,
    TruncatedDispositionRecovery,
    UnsupportedRepair,
    build_repair_plan,
    classify_wire_validation_errors,
    record_cleanup_rows,
    record_truncated_disposition_recovery,
    recover_truncated_risk_dispositions,
    revalidate_provider_object,
    run_targeted_repair,
    select_disposition_repairs,
    select_reference_repairs,
)
from asago_scenario_generator.stpa.system_model.rule_span_repair import (
    RuleSpanRepairRecord,
    record_rule_span_repairs,
    repair_obligation_rows,
)

STAGE = "stage_1a"
STEP_RISK = "risk_derivation"
STEP_GAP = "gap_analysis"
STEP_MERGE = "merge"
# No automatic second dispatch on a malformed JSON body: the corrected
# Stage 1a contract (owner authorization 2026-09-11, rev2) allows exactly one
# call per stage plus at most one targeted repair, so an undecodable body is
# a typed terminal outcome of the first attempt, never a retry trigger.
JSON_DECODE_RETRIES = 0
STAGE1A_MAX_COMPLETION_TOKENS = 8192


class _ProviderSecurityConstraint(SecurityConstraint):
    """Provider wire constraint: authored rule and conditions are required.

    Phase 1.3 as amended: the model writes ``rule`` and ``applies_when``;
    code composes ``description``.  Both keys stay required (``applies_when``
    may be empty) so the model always decides rather than silently omitting
    the fields.
    """

    model_config = ConfigDict(extra="forbid")

    applies_when: list[str]


_LOCAL_HANDLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
_CANONICAL_ID_PATTERNS = {
    "loss": re.compile(r"^L-(\d+)$"),
    "hazard": re.compile(r"^H-(\d+)$"),
    "constraint": re.compile(r"^SC-(\d+)$"),
}
_CANONICAL_PREFIXES = {"loss": "L-", "hazard": "H-", "constraint": "SC-"}


class _ProviderObligation(Obligation):
    """Closed obligation entry for current Stage 1a provider responses."""

    model_config = ConfigDict(extra="forbid")


class _ProviderRiskDisposition(RiskDisposition):
    """Closed risk-accounting entry for the current provider response."""

    model_config = ConfigDict(extra="forbid")


def _provider_handle(value: Any, *, kind: str) -> str:
    """Validate one request-local provider handle.

    The provider may choose a descriptive local handle, but it must not choose
    a canonical Stage 1a identity.  Canonical allocation is a compiler
    responsibility and happens after the complete request-local graph has
    been checked.
    """
    if not isinstance(value, str) or not _LOCAL_HANDLE_RE.fullmatch(value):
        raise ValueError(
            f"{kind} handle must be a non-empty request-local identifier "
            "containing letters, digits, '-' or '_'"
        )
    # Reserve every canonical namespace in every local collection.  A
    # cross-kind value such as ``L-1`` on a hazard would otherwise be
    # ambiguous once references are compiled, because it could be mistaken
    # for an existing loss ID or a new hazard handle.
    if any(pattern.fullmatch(value) for pattern in _CANONICAL_ID_PATTERNS.values()):
        raise ValueError(
            f"{kind} handle {value!r} is a reserved canonical graph ID; use a local "
            "handle and let deterministic code allocate the final ID"
        )
    return value


class _ProviderLoss(BaseModel):
    """Model-facing loss with a request-local identity.

    The generated provider schema exposes only ``handle``. Historical graph
    records are decoded through a separate offline compatibility seam; they
    are not accepted by this current provider boundary.
    """

    model_config = ConfigDict(extra="forbid")

    handle: str
    description: str
    provenance: LossProvenance
    source_risk_cards: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_handle(self) -> _ProviderLoss:
        _provider_handle(self.handle, kind="loss")
        return self


class _ProviderHazard(BaseModel):
    """Model-facing hazard with references to canonical IDs or local handles."""

    model_config = ConfigDict(extra="forbid")

    handle: str
    description: str
    related_losses: list[str]

    @model_validator(mode="after")
    def validate_handle(self) -> _ProviderHazard:
        _provider_handle(self.handle, kind="hazard")
        return self


class _ProviderConstraint(BaseModel):
    """Model-facing constraint with references to canonical IDs or handles."""

    model_config = ConfigDict(extra="forbid")

    handle: str
    rule: str = Field(min_length=1)
    applies_when: list[str] = Field(min_length=0, max_length=4)
    # The strict wire schema requires the key; ``None`` says no class applies.
    behavior_class: BehaviorClass | None = None
    related_hazards: list[str]
    obligations: list[_ProviderObligation] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_handle(self) -> _ProviderConstraint:
        _provider_handle(self.handle, kind="constraint")
        # Reuse the domain validator for rule spans and channel exclusivity.
        SecurityConstraint(
            constraint_id="SC-1",
            rule=self.rule,
            applies_when=self.applies_when,
            related_hazards=["H-1"],
            obligations=self.obligations,
        )
        return self


class _Stage1aGapProviderDraft(BaseModel):
    """Required provider wire for the gap-analysis call.

    The internal domain draft remains partial so the two calls can exchange a
    loss registry before closing the dependent graph. The provider contract is
    separate and makes exactly four collection keys explicit on every response.
    """

    model_config = ConfigDict(extra="forbid")

    risk_card_losses: list[_ProviderLoss] = Field(min_length=0, max_length=16)
    use_case_losses: list[_ProviderLoss] = Field(min_length=0, max_length=16)
    hazards: list[_ProviderHazard] = Field(min_length=0, max_length=16)
    security_constraints: list[_ProviderConstraint] = Field(
        min_length=0,
        max_length=16,
    )

    @model_validator(mode="after")
    def validate_local_handles(self) -> _Stage1aGapProviderDraft:
        for label, records in (
            (
                "loss",
                [*self.risk_card_losses, *self.use_case_losses],
            ),
            ("hazard", self.hazards),
            ("constraint", self.security_constraints),
        ):
            handles = [record.handle for record in records]
            if len(handles) != len(set(handles)):
                duplicate = next(
                    handle for handle in handles if handles.count(handle) > 1
                )
                raise ValueError(
                    f"duplicate request-local {label} handle '{duplicate}'"
                )
        return self


class _Stage1aRiskProviderDraft(_Stage1aGapProviderDraft):
    """Provider wire for the risk-derivation call: adds risk accounting.

    Every supplied risk card must be accounted for exactly once in the
    response, so the disposition list is a required collection.
    """

    risk_dispositions: list[_ProviderRiskDisposition]


def _risk_provider_draft_type(
    risk_ids: Iterable[str],
    *,
    guided: bool,
) -> type[_Stage1aRiskProviderDraft]:
    """Build the risk-derivation wire whose schema names the supplied cards.

    Without guided decoding, or without cards, this is the static wire.
    Under guided decoding the schema closes ``source_risk_cards`` to the supplied risk-card IDs
    and asks for exactly one disposition row per card, in supplied order,
    so a guided decoder cannot invent, repeat, or skip a card.  Local
    validation is the static wire's: the risk-accounting validator still
    reports unknown, missing, or duplicate cards with its targeted repair
    feedback.  The classes keep their static names because call records and
    test clients identify the wire by name.
    """
    ids = list(dict.fromkeys(risk_ids))
    if not guided or not ids:
        return _Stage1aRiskProviderDraft
    loss = create_model(
        "_ProviderLoss",
        __base__=_ProviderLoss,
        source_risk_cards=(
            list[str],
            Field(default_factory=list, json_schema_extra=string_items_enum(ids)),
        ),
    )
    draft = create_model(
        "_Stage1aRiskProviderDraft",
        __base__=_Stage1aRiskProviderDraft,
        risk_card_losses=(list[loss], Field(min_length=0, max_length=16)),
        use_case_losses=(list[loss], Field(min_length=0, max_length=16)),
    )
    return with_keyed_rows(
        draft, array_field="risk_dispositions", key_field="risk_ref", keys=ids
    )


class _Stage1aGapRepairDraft(LossAnalysisDraft):
    """Canonical domain-shaped view used only by the repair adapter."""

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_current_provider_boundary(self) -> _Stage1aGapRepairDraft:
        _validate_repair_draft_provider_boundary(self, risk_required=False)
        return self


class _Stage1aRiskRepairDraft(_Stage1aGapRepairDraft):
    """Repair view retaining the risk wire's required disposition collection."""

    risk_dispositions: list[RiskDisposition]

    @model_validator(mode="after")
    def validate_risk_provider_boundary(self) -> _Stage1aRiskRepairDraft:
        _validate_repair_draft_provider_boundary(self, risk_required=True)
        return self


class _RevisionHazardEdit(BaseModel):
    """Complete replacement for one existing hazard, keyed by canonical ID."""

    model_config = ConfigDict(extra="forbid")

    hazard_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_losses: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_target(self) -> _RevisionHazardEdit:
        if not _CANONICAL_ID_PATTERNS["hazard"].fullmatch(self.hazard_id):
            raise ValueError(
                "hazard edit target must be an existing canonical hazard ID"
            )
        return self


class _RevisionHazardAddition(BaseModel):
    """One new hazard whose canonical ID is allocated by deterministic code."""

    model_config = ConfigDict(extra="forbid")

    handle: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_losses: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_handle(self) -> _RevisionHazardAddition:
        _provider_handle(self.handle, kind="hazard")
        return self


class _RevisionConstraintEdit(BaseModel):
    """Complete replacement for one existing security constraint.

    ``obligations`` is optional only when both the rule and its applicability
    conditions are unchanged; omission then carries the existing entries. Any
    rule or scope edit must carry an explicit list so stale interpretations
    cannot survive silently.
    """

    model_config = ConfigDict(extra="forbid")

    constraint_id: str = Field(min_length=1)
    rule: str = Field(min_length=1)
    applies_when: list[str] = Field(min_length=0, max_length=4)
    # Omitted (``None``) keeps the constraint's existing class.
    behavior_class: BehaviorClass | None = None
    related_hazards: list[str] = Field(min_length=1)
    obligations: list[_ProviderObligation] | None = None

    @model_validator(mode="after")
    def validate_target(self) -> _RevisionConstraintEdit:
        if not _CANONICAL_ID_PATTERNS["constraint"].fullmatch(self.constraint_id):
            raise ValueError(
                "security constraint edit target must be an existing canonical ID"
            )
        return self


class _RevisionConstraintAddition(BaseModel):
    """One new constraint whose canonical ID is compiler-owned."""

    model_config = ConfigDict(extra="forbid")

    handle: str = Field(min_length=1)
    rule: str = Field(min_length=1)
    applies_when: list[str] = Field(min_length=0, max_length=4)
    behavior_class: BehaviorClass | None = None
    related_hazards: list[str] = Field(min_length=1)
    obligations: list[_ProviderObligation] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_handle(self) -> _RevisionConstraintAddition:
        _provider_handle(self.handle, kind="constraint")
        return self


class _Stage1aRevisionPatch(BaseModel):
    """Explicit graph delta for the one bounded Stage 1a revision call.

    Existing records are addressed only by ``*_id`` in edit collections;
    additions use request-local ``handle`` values.  Untouched records are
    carried forward by :func:`_revision_patch_to_draft`, so omission cannot
    delete a graph record. Historical whole-graph patch decoding belongs to a
    separate offline compatibility seam and is not accepted by this current
    provider model.
    """

    hazard_edits: list[_RevisionHazardEdit] = Field(min_length=0, max_length=16)
    hazard_additions: list[_RevisionHazardAddition] = Field(min_length=0, max_length=16)
    security_constraint_edits: list[_RevisionConstraintEdit] = Field(
        min_length=0, max_length=16
    )
    security_constraint_additions: list[_RevisionConstraintAddition] = Field(
        min_length=0, max_length=16
    )

    model_config = ConfigDict(extra="forbid")


def _validate_repair_draft_provider_boundary(
    draft: LossAnalysisDraft,
    *,
    risk_required: bool,
) -> None:
    """Validate a repaired canonical draft against the current local wire.

    The targeted-repair module operates on canonical domain rows.  This
    boundary rebuilds a throwaway local-handle response so the original
    provider's closed shape and obligation validators still run after the
    repair, without making canonical IDs acceptable on the live wire.
    """
    loss_handles = _local_handles(
        [*draft.risk_card_losses, *draft.use_case_losses], "loss_id", "loss"
    )
    hazard_handles = _local_handles(draft.hazards, "hazard_id", "hazard")
    constraint_handles = _local_handles(
        draft.security_constraints, "constraint_id", "constraint"
    )
    payload: dict[str, object] = {
        "risk_card_losses": _local_wire_losses(draft.risk_card_losses, loss_handles),
        "use_case_losses": _local_wire_losses(draft.use_case_losses, loss_handles),
        "hazards": [
            {
                "handle": hazard_handles[hazard.hazard_id],
                "description": hazard.description,
                "related_losses": _mapped_references(
                    hazard.related_losses, loss_handles
                ),
            }
            for hazard in draft.hazards
        ],
        "security_constraints": [
            {
                "handle": constraint_handles[constraint.constraint_id],
                "rule": constraint.rule,
                "applies_when": constraint.applies_when,
                "behavior_class": constraint.behavior_class,
                "obligations": [
                    obligation.model_dump(mode="json", exclude_none=True)
                    for obligation in constraint.obligations
                ],
                "related_hazards": _mapped_references(
                    constraint.related_hazards, hazard_handles
                ),
            }
            for constraint in draft.security_constraints
        ],
    }
    if risk_required:
        payload["risk_dispositions"] = [
            {
                "risk_ref": disposition.risk_ref,
                "disposition": disposition.disposition,
                "loss_ids": _mapped_references(disposition.loss_ids, loss_handles),
                **(
                    {"reason": disposition.reason}
                    if disposition.reason is not None
                    else {}
                ),
            }
            for disposition in draft.risk_dispositions
        ]
        _Stage1aRiskProviderDraft.model_validate(payload)
    else:
        _Stage1aGapProviderDraft.model_validate(payload)


def _local_handles(rows: Iterable[Any], id_attr: str, prefix: str) -> dict[str, str]:
    """Map each canonical ID to a sequential local handle in sorted-ID order."""
    ordered = sorted(rows, key=lambda item: getattr(item, id_attr))
    return {
        getattr(row, id_attr): f"{prefix}_{index}"
        for index, row in enumerate(ordered, 1)
    }


def _mapped_references(references: Iterable[str], handles: dict[str, str]) -> list[str]:
    return [handles.get(reference, reference) for reference in references]


def _local_wire_losses(
    losses: Iterable[Any], loss_handles: dict[str, str]
) -> list[dict[str, object]]:
    return [
        {
            "handle": loss_handles[loss.loss_id],
            "description": loss.description,
            "provenance": loss.provenance,
            "source_risk_cards": loss.source_risk_cards,
        }
        for loss in losses
    ]


def _compact_risk_card_evidence(risk_cards: Iterable[RiskCard]) -> list[str]:
    """Select complete semantic fields for the provider-facing risk view.

    The risk extraction can contain bookkeeping, scores, evidence spans, and
    mitigation prose that duplicate the core assessment.  Keep each card's
    exact ID, name, full risk description, and full consequence; the typed
    cards remain authoritative and are never mutated or truncated.
    """
    evidence: list[str] = []
    for card in risk_cards:
        fragments = [
            f"{card.risk_id} — {card.risk_name}",
            f"description: {card.risk_description}",
        ]
        if card.consequence:
            fragments.append(f"consequence: {card.consequence}")
        evidence.append("; ".join(fragments))
    return evidence


def _allocate_provider_scope(
    records: Iterable[object],
    *,
    prior_ids: set[str],
    kind: str,
) -> dict[str, str]:
    """Allocate canonical IDs for one provider-local namespace.

    Handles are sorted before allocation so model list order cannot change
    canonical identities; the record order itself remains untouched for
    readable artifact output.
    """

    def handle_sort_key(handle: str) -> tuple[str, int, str]:
        # Generated fixture and model handles commonly use a numeric suffix
        # (``constraint_2``/``constraint_10``).  Natural ordering keeps their
        # canonical IDs contiguous while retaining lexical ordering for
        # descriptive handles such as ``privacy_loss``.
        match = re.match(r"^(.*?)(\d+)$", handle)
        if match is None:
            return (handle, -1, handle)
        return (match.group(1), int(match.group(2)), handle)

    handles = sorted(
        {str(getattr(record, "handle")) for record in records},
        key=handle_sort_key,
    )
    return allocate_canonical_ids(_CANONICAL_PREFIXES[kind], prior_ids, handles)


def _resolve_provider_reference(
    value: str,
    *,
    mapping: dict[str, str],
    existing_ids: set[str],
    kind: str,
    strict: bool = True,
    field: str | None = None,
) -> str:
    """Resolve one existing canonical ID or request-local handle.

    In the normal materialization path an unknown value is rejected before a
    newly allocated canonical ID can make it look declared.  The named repair
    adapter may request ``strict=False`` so it can preserve malformed rows for
    the existing row-level repair classifier without silently resolving them.
    """
    if value in mapping:
        return mapping[value]
    if value in existing_ids:
        return value
    if strict:
        known = sorted(existing_ids | set(mapping.values()))
        prefix = f"{field}: " if field else ""
        raise ValueError(
            f"{prefix}unknown {kind} reference '{value}' in provider graph; "
            f"Missing {kind} declarations: {value}. Known {kind} IDs: "
            f"{', '.join(known) or 'none'}"
        )
    return value


def _materialize_provider_draft(
    provider_draft: _Stage1aGapProviderDraft,
    *,
    prior: LossAnalysisDraft | None = None,
    strict_references: bool = True,
) -> LossAnalysisDraft:
    """Compile the request-local Stage 1a provider wire into a domain draft.

    Existing graph identities are preserved when a gap response references
    them. New records are allocated from the complete prior namespace, and
    all cross-references are resolved before the ordinary draft validators run.
    Existing references remain canonical IDs; only records declared in this
    provider response use request-local handles. The adapter deliberately has
    no historical-ID fallback.
    """
    prior = prior or LossAnalysisDraft()
    prior_losses = {
        loss.loss_id for loss in (*prior.risk_card_losses, *prior.use_case_losses)
    }
    prior_hazards = {hazard.hazard_id for hazard in prior.hazards}
    prior_constraints = {
        constraint.constraint_id for constraint in prior.security_constraints
    }

    all_provider_losses = [
        *provider_draft.risk_card_losses,
        *provider_draft.use_case_losses,
    ]
    loss_map = _allocate_provider_scope(
        all_provider_losses,
        prior_ids=prior_losses,
        kind="loss",
    )
    hazard_map = _allocate_provider_scope(
        provider_draft.hazards,
        prior_ids=prior_hazards,
        kind="hazard",
    )
    constraint_map = _allocate_provider_scope(
        provider_draft.security_constraints,
        prior_ids=prior_constraints,
        kind="constraint",
    )

    def materialize_loss(item: _ProviderLoss) -> Loss:
        return Loss(
            loss_id=loss_map[item.handle],
            description=item.description,
            provenance=item.provenance,
            source_risk_cards=item.source_risk_cards,
        )

    losses = [materialize_loss(item) for item in all_provider_losses]
    materialized_risk_losses = [
        materialize_loss(item) for item in provider_draft.risk_card_losses
    ]
    materialized_use_case_losses = [
        materialize_loss(item) for item in provider_draft.use_case_losses
    ]
    # Newly allocated canonical IDs are compiler outputs, not provider
    # references.  A provider may refer to a new record only by its local
    # handle; accepting a guessed ``L-n``/``H-n``/``SC-n`` here would make
    # malformed forward references appear valid.
    valid_loss_ids = prior_losses
    materialized_hazards = _materialize_provider_hazards(
        provider_draft,
        hazard_map=hazard_map,
        loss_map=loss_map,
        valid_loss_ids=valid_loss_ids,
        strict=strict_references,
    )
    materialized_constraints = _materialize_provider_constraints(
        provider_draft,
        constraint_map=constraint_map,
        hazard_map=hazard_map,
        valid_hazard_ids=prior_hazards,
        strict=strict_references,
    )
    dispositions = _materialize_provider_dispositions(
        provider_draft,
        loss_map=loss_map,
        valid_loss_ids=valid_loss_ids,
        strict=strict_references,
    )
    # Keep this assertion close to the adapter: it catches accidental changes
    # to the collection split without hiding records in a later merge.
    if len(losses) != len(materialized_risk_losses) + len(materialized_use_case_losses):
        raise AssertionError("provider loss materialization lost a record")
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": materialized_risk_losses,
            "use_case_losses": materialized_use_case_losses,
            "hazards": materialized_hazards,
            "security_constraints": materialized_constraints,
            "risk_dispositions": dispositions,
        }
    )


def _materialize_provider_hazards(
    provider_draft: _Stage1aGapProviderDraft,
    *,
    hazard_map: dict[str, str],
    loss_map: dict[str, str],
    valid_loss_ids: set[str],
    strict: bool,
) -> list[Hazard]:
    """Compile provider hazards with canonical IDs and resolved loss references."""
    return [
        Hazard(
            hazard_id=hazard_map[item.handle],
            description=item.description,
            related_losses=[
                _resolve_provider_reference(
                    reference,
                    mapping=loss_map,
                    existing_ids=valid_loss_ids,
                    kind="loss",
                    strict=strict,
                    field="related_losses",
                )
                for reference in item.related_losses
            ],
        )
        for item in provider_draft.hazards
    ]


def _materialize_provider_constraints(
    provider_draft: _Stage1aGapProviderDraft,
    *,
    constraint_map: dict[str, str],
    hazard_map: dict[str, str],
    valid_hazard_ids: set[str],
    strict: bool,
) -> list[SecurityConstraint]:
    """Compile provider constraints with canonical IDs and resolved hazards."""
    return [
        SecurityConstraint(
            constraint_id=constraint_map[item.handle],
            rule=item.rule,
            applies_when=item.applies_when,
            behavior_class=item.behavior_class,
            related_hazards=[
                _resolve_provider_reference(
                    reference,
                    mapping=hazard_map,
                    existing_ids=valid_hazard_ids,
                    kind="hazard",
                    strict=strict,
                    field="related_hazards",
                )
                for reference in item.related_hazards
            ],
            obligations=item.obligations,
        )
        for item in provider_draft.security_constraints
    ]


def _materialize_provider_dispositions(
    provider_draft: _Stage1aGapProviderDraft,
    *,
    loss_map: dict[str, str],
    valid_loss_ids: set[str],
    strict: bool,
) -> list[RiskDisposition]:
    """Copy provider dispositions with their loss references resolved."""
    return [
        disposition.model_copy(
            update={
                "loss_ids": [
                    _resolve_provider_reference(
                        reference,
                        mapping=loss_map,
                        existing_ids=valid_loss_ids,
                        kind="loss",
                        strict=strict,
                        field="loss_ids",
                    )
                    for reference in disposition.loss_ids
                ]
            }
        )
        for disposition in getattr(provider_draft, "risk_dispositions", ())
    ]


_PROVIDER_GRAPH_COLLECTIONS = (
    "risk_card_losses",
    "use_case_losses",
    "hazards",
    "security_constraints",
)


def _prepare_current_provider_repair_input(
    result: LLMResult | None,
    *,
    response_format: type[BaseModel],
    prior: LossAnalysisDraft | None,
) -> tuple[LLMResult, type[LossAnalysisDraft]] | None:
    """Adapt one current local-handle response for the legacy repair engine.

    The targeted-repair module intentionally works on domain rows because its
    approved scope is limited to dispositions and obligation entries.  Keep
    the live provider boundary strict, then translate only the failed first
    response into canonical domain rows for that engine.  A response without
    any current local handles is rejected here rather than being interpreted
    as a historical canonical wire.
    """
    if result is None:
        return None
    raw = _decode_repair_content(result.content)
    if raw is None or not _is_current_local_wire(raw, response_format):
        return None
    provider = _validate_provider_structure(raw, response_format)
    if provider is None:
        return None
    # Preserve unresolved references for the approved repair classifier; the
    # normal first-attempt compiler remains strict and rejects them before any
    # new canonical ID can be mistaken for a declaration.
    domain = _materialize_provider_draft(
        provider,
        prior=prior,
        strict_references=False,
    )
    provider_losses = [*provider.risk_card_losses, *provider.use_case_losses]
    domain_losses = [*domain.risk_card_losses, *domain.use_case_losses]
    if len(provider_losses) != len(domain_losses):
        return None
    loss_map = _handle_id_map(provider_losses, domain_losses, "loss_id")
    hazard_map = _handle_id_map(provider.hazards, domain.hazards, "hazard_id")
    constraint_map = _handle_id_map(
        provider.security_constraints, domain.security_constraints, "constraint_id"
    )
    _adapt_handle_rows(raw, "risk_card_losses", "loss_id", loss_map)
    _adapt_handle_rows(raw, "use_case_losses", "loss_id", loss_map)
    _adapt_handle_rows(
        raw, "hazards", "hazard_id", hazard_map, ("related_losses", loss_map)
    )
    _adapt_handle_rows(
        raw,
        "security_constraints",
        "constraint_id",
        constraint_map,
        ("related_hazards", hazard_map),
    )
    is_risk_wire = issubclass(response_format, _Stage1aRiskProviderDraft)
    _adapt_disposition_loss_ids(raw, loss_map, is_risk_wire=is_risk_wire)
    repair_model = _Stage1aRiskRepairDraft if is_risk_wire else _Stage1aGapRepairDraft
    return result.model_copy(update={"content": raw}), repair_model


def _handle_id_map(
    provider_rows: Iterable[Any], domain_rows: Iterable[Any], id_attr: str
) -> dict[str, str]:
    return {
        provider_row.handle: getattr(domain_row, id_attr)
        for provider_row, domain_row in zip(provider_rows, domain_rows)
    }


def _decode_repair_content(content: object) -> dict | None:
    """Return a private JSON-object copy of a response body, if it has one."""
    if isinstance(content, BaseModel):
        raw = content.model_dump(mode="json")
    elif isinstance(content, dict):
        raw = deepcopy(content)
    elif isinstance(content, str):
        try:
            raw = json.loads(content)
        except json.JSONDecodeError:
            return None
    else:
        return None
    return raw if isinstance(raw, dict) else None


def _is_current_local_wire(raw: dict, response_format: type[BaseModel]) -> bool:
    """Whether the body uses local handles, or is an empty gap graph."""
    has_current_handles = any(
        isinstance(raw.get(name), list)
        and any(isinstance(row, dict) and "handle" in row for row in raw[name])
        for name in _PROVIDER_GRAPH_COLLECTIONS
    )
    empty_gap_wire = (
        issubclass(response_format, _Stage1aGapProviderDraft)
        and all(isinstance(raw.get(name), list) for name in _PROVIDER_GRAPH_COLLECTIONS)
        and not any(raw.get(name) for name in _PROVIDER_GRAPH_COLLECTIONS)
    )
    return has_current_handles or empty_gap_wire


def _validate_provider_structure(
    raw: dict, response_format: type[BaseModel]
) -> _Stage1aRiskProviderDraft | _Stage1aGapProviderDraft | None:
    """Validate the local-handle graph without dispositions or obligations."""
    # Preserve malformed dispositions/obligations verbatim while removing only
    # those fields that prevent the structural local wire from providing the
    # canonical namespace needed by the repair engine.
    clean = deepcopy(raw)
    if issubclass(response_format, _Stage1aRiskProviderDraft):
        clean["risk_dispositions"] = []
    else:
        # Gap responses may carry a malformed disposition collection in the
        # explicitly approved C1 cleanup path.  Remove only that known
        # cleanup-scoped field before re-validating the remaining current
        # local-handle wire; the original rows stay in ``raw`` for the
        # deterministic cleanup/repair record.
        clean.pop("risk_dispositions", None)
    for row in clean.get("security_constraints", []):
        if isinstance(row, dict):
            row["obligations"] = []
    try:
        provider = response_format.model_validate(clean)
    except ValidationError:
        return None
    if not isinstance(
        provider,
        (_Stage1aRiskProviderDraft, _Stage1aGapProviderDraft),
    ):
        return None
    return provider


def _adapt_handle_rows(
    raw: dict,
    name: str,
    identity: str,
    mapping: dict[str, str],
    references: tuple[str, dict[str, str]] | None = None,
) -> None:
    """Replace each row's local handle, and its references, with canonical IDs."""
    rows = raw.get(name)
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        handle = row.get("handle")
        if isinstance(handle, str) and handle in mapping:
            row[identity] = mapping[handle]
            row.pop("handle", None)
        if references is not None:
            reference_field, reference_map = references
            refs = row.get(reference_field)
            if isinstance(refs, list):
                row[reference_field] = [
                    reference_map.get(reference, reference) for reference in refs
                ]


def _adapt_disposition_loss_ids(
    raw: dict, loss_map: dict[str, str], *, is_risk_wire: bool
) -> None:
    """Map disposition loss handles; give a gap body an empty collection."""
    dispositions = raw.get("risk_dispositions")
    if isinstance(dispositions, list):
        for row in dispositions:
            if not isinstance(row, dict):
                continue
            loss_ids = row.get("loss_ids")
            if isinstance(loss_ids, list):
                row["loss_ids"] = [loss_map.get(value, value) for value in loss_ids]
    elif not is_risk_wire:
        raw["risk_dispositions"] = []


class _DraftReferenceValidationError(ValueError):
    """Validation failure that can be sent back as bounded retry feedback."""

    def __init__(self, message: str, *, feedback: str) -> None:
        super().__init__(message)
        self.feedback = feedback


class _DraftSemanticValidationError(ValueError):
    """Semantic failure that can be sent back through the bounded retry."""

    def __init__(self, message: str, *, feedback: str) -> None:
        super().__init__(message)
        self.feedback = feedback


@dataclass(frozen=True)
class LossAnalysisDiagnostic:
    """A deterministic, human-readable loss-analysis semantic diagnostic."""

    code: str
    severity: Literal["warning", "error"]
    message: str

    def __str__(self) -> str:
        return f"{self.code} ({self.severity}): {self.message}"


# These patterns describe generic STPA concepts, not any product or domain.
# The component-failure error is anchored to the hazard's primary subject so a
# later dependency phrase such as “service failure due to an upstream issue”
# does not override an otherwise system-level hazardous state.
_COMPONENT_FAILURE_RE = re.compile(
    r"^\s*(?:(?:the|a|an)\s+)?(?:sensor|component|module|database|service|api|model|tool|server|"
    r"channel|interface|controller)\s+(?:fails?|failure|crashes?|is\s+"
    r"(?:broken|compromised|corrupted))\b",
    re.IGNORECASE,
)
_CAUSE_OR_DEPENDENCY_RE = re.compile(
    r"\b(?:dependent\s+on|depends\s+on|due\s+to|because\s+of|"
    r"caused\s+by|as\s+a\s+result\s+of|when\s+.+?\s+fails?)\b",
    re.IGNORECASE,
)
_MECHANISM_HAZARD_RE = re.compile(
    r"\b(?:injection|poison(?:ed|ing)?|spoof(?:ed|ing)?|tamper(?:ed|ing)?|"
    r"malicious\s+(?:input|content|payload|instruction)|credential\s+theft|"
    r"command\s+execution|payload|phish(?:ed|ing)?|replay(?:ed|ing)?|"
    r"flood(?:ed|ing)?|denial[-\s]of[-\s]service)\b",
    re.IGNORECASE,
)
_STATE_CUE_RE = re.compile(
    r"\b(?:remains?|becomes?|is|are|above|below|exceeds?|contains?|"
    r"exposes?|allows?|prevents?|receives?|sends?|executes?|persists?|"
    r"maintains?|outside|within|without|before|after|erodes?|damages?|"
    r"causes?|violates?|fails?)\b",
    re.IGNORECASE,
)
_ADVERSARIAL_CUE_RE = re.compile(
    r"\b(?:attack(?:er|ers)?|adversar(?:y|ial)|malicious|spoof(?:ed|ing)?|"
    r"tamper(?:ed|ing)?|inject(?:ed|ion|ing)?|poison(?:ed|ing)?|"
    r"manipulat(?:e|ed|ing|ion)|forg(?:e|ed|ing)|unauthori[sz](?:ed|ation)|"
    r"exploit(?:ed|ing)?|abus(?:e|ed|ing)|crafted|compromis(?:e|ed|ing)|"
    r"credential|bypass(?:ed|ing)?|impersonat(?:e|ed|ing)|replay(?:ed|ing)?|"
    r"exfiltrat(?:e|ed|ing|ion)|falsif(?:y|ied|ication)|override|denial)\b",
    re.IGNORECASE,
)


_HAZARD_DIAGNOSTIC_RULES: tuple[
    tuple[Callable[[str], object], str, Literal["warning", "error"], str], ...
] = (
    (
        _COMPONENT_FAILURE_RE.search,
        "hazard_not_system_state",
        "error",
        "{hazard_id} is phrased as a component failure; express "
        "the resulting system-level hazardous state or condition "
        "inside the analysis boundary instead.",
    ),
    (
        _CAUSE_OR_DEPENDENCY_RE.search,
        "hazard_cause_or_dependency",
        "warning",
        "{hazard_id} is phrased as a cause or dependency; rewrite "
        "it as the observable system-level state that can lead to "
        "the loss, and retain the cause as supporting evidence.",
    ),
    (
        _MECHANISM_HAZARD_RE.search,
        "hazard_mechanism_phrasing",
        "warning",
        "{hazard_id} names an attack mechanism in the hazard; "
        "state the resulting system condition and keep the "
        "mechanism as a separately supported cause.",
    ),
    (
        lambda description: description and not _STATE_CUE_RE.search(description),
        "hazard_state_unspecified",
        "warning",
        "{hazard_id} does not clearly state a system condition; "
        "review whether it describes a state that can lead to a loss.",
    ),
)


def _hazard_diagnostics(hazard: object) -> list[LossAnalysisDiagnostic]:
    description = str(getattr(hazard, "description", ""))
    return [
        LossAnalysisDiagnostic(
            code=code,
            severity=severity,
            message=template.format(hazard_id=getattr(hazard, "hazard_id", "unknown")),
        )
        for matches, code, severity, template in _HAZARD_DIAGNOSTIC_RULES
        if matches(description)
    ]


def diagnose_loss_analysis_semantics(
    draft: object,
    *,
    use_case_text: str = "",
    risk_cards: Iterable[RiskCard] = (),
) -> list[LossAnalysisDiagnostic]:
    """Diagnose generic semantic weaknesses in a loss-analysis graph.

    The diagnostics are intentionally domain-independent.  A hazard should
    describe a system state or condition inside the analysis boundary, not a
    failed component.  The graph should also retain an adversarially
    actionable rationale when the supplied use case or risk evidence contains
    one.  Diagnostics do not infer a taxonomy mechanism and do not use product
    names as a proxy for relevance.
    """
    hazards = getattr(draft, "hazards", ())
    descriptions = list(_loss_analysis_text(draft))
    descriptions.extend(
        str(card_text)
        for card in risk_cards
        for card_text in (
            getattr(card, "risk_name", ""),
            getattr(card, "risk_description", ""),
        )
    )
    combined_text = " ".join((use_case_text, *descriptions))
    diagnostics: list[LossAnalysisDiagnostic] = []

    for hazard in hazards:
        diagnostics.extend(_hazard_diagnostics(hazard))

    if combined_text.strip() and not _ADVERSARIAL_CUE_RE.search(combined_text):
        diagnostics.append(
            LossAnalysisDiagnostic(
                code="adversarial_relevance_unsubstantiated",
                severity="warning",
                message=(
                    "The supplied loss-analysis text does not identify a generic "
                    "adversarial action or path; retain the graph only when the "
                    "use case provides one, rather than assuming taxonomy relevance."
                ),
            )
        )
    return diagnostics


def _loss_analysis_text(draft: object) -> Iterable[str]:
    """Yield semantic text from either a draft or a merged loss analysis."""
    for field_name in (
        "risk_card_losses",
        "use_case_losses",
        "hazards",
        "security_constraints",
    ):
        for item in getattr(draft, field_name, ()):
            description = getattr(item, "description", None)
            if description:
                yield str(description)


def _validate_draft_semantics(
    draft: LossAnalysisDraft,
    *,
    context: str,
) -> None:
    """Reject component-failure hazards while leaving relevance as a diagnostic."""
    diagnostics = diagnose_loss_analysis_semantics(draft)
    errors = [item for item in diagnostics if item.severity == "error"]
    if not errors:
        return
    message = "; ".join(str(item) for item in errors)
    raise _DraftSemanticValidationError(
        f"{context} draft failed semantic validation: {message}",
        feedback=(
            f"Validation feedback: {message} Rewrite each hazard as a "
            "system-level state or condition, not the failure of a sensor, "
            "component, service, model, or other implementation element."
        ),
    )


def _gap_call_context(
    risk_draft: LossAnalysisDraft, capability_profile: CapabilityProfile | None
) -> dict[str, object]:
    """Return the gap call's view of the first draft and the capability profile."""
    existing_losses = risk_draft.risk_card_losses + risk_draft.use_case_losses
    kc_subcodes = capability_profile.kc_subcodes if capability_profile else []
    return {
        "existing_losses": existing_losses,
        "existing_hazards": risk_draft.hazards,
        "existing_constraints": risk_draft.security_constraints,
        "kc_subcodes": kc_subcodes,
        "kc_subcodes_display": build_kc_subcodes_display(kc_subcodes),
        "allowed_loss_ids": {loss.loss_id for loss in existing_losses},
        "allowed_hazard_ids": {hazard.hazard_id for hazard in risk_draft.hazards},
        "require_complete_chain": not (
            existing_losses and risk_draft.hazards and risk_draft.security_constraints
        ),
    }


def derive_loss_analysis(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    capability_profile: CapabilityProfile | None = None,
    normalization_warnings: list[str] | None = None,
    repair_record: RepairRecord | None = None,
    target_evidence: TargetEvidence | None = None,
) -> LossAnalysis:
    """Run Stage 1a: derive loss analysis via two sequential LLM calls.

    Call 1 (risk_derivation) derives losses/hazards/constraints from
    organizational risk cards.  Call 2 (gap_analysis) reviews the use-case
    for missing source-grounded systemic losses, receiving Call 1's output and
    the capability profile as context.

    Provider-local handles are compiled to canonical IDs before the two drafts
    are merged. Existing canonical IDs remain stable, new IDs are allocated
    deterministically, and cross-references are resolved before validation.

    Every Stage 1a transformation (salvage drop, deterministic cleanup,
    targeted repair, unsupported outcome) is recorded in one run-level,
    cross-stage, accumulating ``loss-analysis-repair.yaml`` artifact; both
    stages append to it, a later write never removes an earlier entry, and a
    terminal failure still writes it while preserving every earlier entry.
    A caller may supply its own :class:`RepairRecord` to read the per-stage
    counts for a run manifest.

    Args:
        llm_client: LLM client for making the completion calls.
        use_case_text: Free-text use-case description.
        risk_cards: List of RiskCard objects from risk extraction.
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).
        capability_profile: Optional capability profile from Stage 1b,
            passed to the gap analysis call for systematic coverage checking.
        normalization_warnings: Optional list collecting rendered warnings.
        repair_record: Optional caller-supplied accumulating record.
        target_evidence: Optional discovered target evidence.  Both calls
            render it to ground hazards and constraints; losses stay derived
            from risk cards and the use case.

    Returns:
        Validated LossAnalysis model.

    Raises:
        StageError: If either LLM call fails or the merged result fails
            validation.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)
    record = repair_record if repair_record is not None else RepairRecord()
    # Keep the provider context small enough to leave completion room for a
    # complete graph.  The original typed inputs remain authoritative for
    # validation and persistence; these are prompt-only projections.
    compact_risk_evidence = _compact_risk_card_evidence(risk_cards)
    risk_prompt_vars: dict[str, object] = {
        "use_case_text": use_case_text,
        "risk_cards": risk_cards,
        "target_evidence": target_evidence,
    }
    if compact_risk_evidence:
        risk_prompt_vars["risk_card_evidence"] = compact_risk_evidence

    # --- Call 1: risk_derivation ---
    try:
        risk_draft = _run_stage1a_call(
            llm_client=llm_client,
            loader=loader,
            system_template="stage1a_risk_system.j2",
            user_template="stage1a_risk_user.j2",
            run_dir=run_dir,
            step=STEP_RISK,
            temperature=temperature,
            response_format=_risk_provider_draft_type(
                (card.risk_id for card in risk_cards or ()),
                guided=uses_guided_decoding(llm_client),
            ),
            accounting_cards=risk_cards,
            require_risk_accounting=bool(risk_cards),
            **risk_prompt_vars,
            allowed_loss_ids=set(),
            allowed_hazard_ids=set(),
            # Keep the first call's provider responsibility narrow: establish
            # grounded risk-card losses.  The second call closes the dependent
            # hazard/constraint graph against that declared loss registry.
            require_losses=bool(risk_cards),
            require_complete_chain=False,
            normalization_warnings=normalization_warnings,
            repair_record=record,
        )
    finally:
        # The record survives a first-stage terminal failure with every
        # recorded entry intact.
        record.write(run_dir)
    # The gap prompt is a review of the first draft, so its context must be
    # the canonical source-separated view.  Models occasionally put a
    # risk-card loss in ``use_case_losses`` (or repeat it in both fields).
    # Classify by the typed provenance and remove exact duplicate records
    # before rendering the review context and compiling the next local scope.
    risk_draft = _canonicalize_draft_losses(risk_draft)

    # --- Call 2: gap_analysis ---
    try:
        gap_draft = _run_stage1a_call(
            llm_client=llm_client,
            loader=loader,
            system_template="stage1a_gap_system.j2",
            user_template="stage1a_gap_user.j2",
            run_dir=run_dir,
            step=STEP_GAP,
            temperature=temperature,
            response_format=_Stage1aGapProviderDraft,
            require_risk_accounting=False,
            use_case_text=use_case_text,
            target_evidence=target_evidence,
            **_gap_call_context(risk_draft, capability_profile),
            require_losses=False,
            authoritative_draft=risk_draft,
            normalization_warnings=normalization_warnings,
            repair_record=record,
        )

        # --- Merge and validate ---
        try:
            merged = _merge_drafts(risk_draft, gap_draft)
        except Exception as exc:
            # Merge validation happens after both LLM calls, so it is not covered
            # by ``call_with_policy``.  Keep the public stage boundary consistent
            # with call failures and let run_sp1 record a structured diagnostic.
            raise StageError(
                stage=STAGE,
                step=STEP_MERGE,
                message=f"{type(exc).__name__}: {exc}",
            ) from exc
        # Stage 2 may apply evidence-backed H/SC wording and edge reviews. Retain this
        # merged Stage 1a graph as an explicit draft for audit; the canonical
        # loss-analysis.yaml is replaced by the reviewed graph after Call 3.
        write_yaml(merged, run_dir / "loss-analysis-draft.yaml")
        write_yaml(merged, run_dir / "loss-analysis.yaml")
        return merged
    finally:
        # A later stage failure never erases an earlier entry: the record
        # carries everything both stages recorded, in order.
        record.write(run_dir)


def _wire_error_summary(exc: ValidationError) -> str:
    """Summarize a pydantic wire violation without dumping the full error."""
    errors = exc.errors()

    def _format(item: dict[str, object]) -> str:
        loc = ".".join(str(part) for part in item.get("loc", ()))
        return f"{loc}: {item.get('msg', '')}"[:120]

    summary = "; ".join(_format(item) for item in errors[:5])
    if len(errors) > 5:
        summary += f" (+{len(errors) - 5} more schema errors)"
    return summary


# A citing loss that accounts for more than this many risk cards weakens
# the "the citation is direct evidence" argument (one bulk loss can sweep
# in cards the model explicitly excluded), so those flips are flagged for
# reviewer attention in the gates artifact.
BULK_CITATION_FLAG_THRESHOLD = 8


def normalize_disposition_citations(
    analysis: LossAnalysisDraft | LossAnalysis,
) -> list[str]:
    """Resolve disposition/citation contradictions from the response's own evidence.

    A ``not_applicable`` disposition for a risk card that a loss explicitly
    cites in ``source_risk_cards`` is self-contradictory wire data (spec rule
    1.1(4)).  The citation is direct evidence that the model derived that
    loss from the risk, so deterministic code flips the disposition to
    ``cited`` with exactly the citing losses and returns a warning for
    reviewer visibility in the gates artifact.  The warning retains the
    model's dropped reason and flags flips whose only citing loss is a bulk
    citation (more than :data:`BULK_CITATION_FLAG_THRESHOLD` cards), where
    the dropped reason deserves human attention.  Mutates the analysis in
    place.
    """
    warnings: list[str] = []
    citing: dict[str, list[str]] = {}
    loss_citation_counts: dict[str, int] = {}
    for loss in analysis.risk_card_losses + analysis.use_case_losses:
        loss_citation_counts[loss.loss_id] = len(set(loss.source_risk_cards))
        for risk_ref in loss.source_risk_cards:
            citing.setdefault(risk_ref, []).append(loss.loss_id)
    for disposition in analysis.risk_dispositions:
        if disposition.disposition != "not_applicable":
            continue
        loss_ids = sorted(set(citing.get(disposition.risk_ref, ())))
        if not loss_ids:
            continue
        dropped_reason = (disposition.reason or "").strip()
        disposition.disposition = "cited"
        disposition.loss_ids = loss_ids
        disposition.reason = None
        warnings.append(
            _citation_flip_warning(
                disposition.risk_ref, loss_ids, dropped_reason, loss_citation_counts
            )
        )
    return warnings


def _citation_flip_warning(
    risk_ref: str,
    loss_ids: list[str],
    dropped_reason: str,
    loss_citation_counts: dict[str, int],
) -> str:
    bulk_losses = [
        loss_id
        for loss_id in loss_ids
        if loss_citation_counts.get(loss_id, 0) > BULK_CITATION_FLAG_THRESHOLD
    ]
    bulk_note = (
        f"; bulk citation: {', '.join(bulk_losses)} cite more than "
        f"{BULK_CITATION_FLAG_THRESHOLD} cards, review the dropped reason"
        if bulk_losses
        else ""
    )
    reason_note = (
        f"; the model's dropped reason was: {dropped_reason}"
        if dropped_reason
        else "; the model gave no reason"
    )
    return (
        f"risk accounting normalized: '{risk_ref}' was "
        f"not_applicable but is cited by {', '.join(loss_ids)}"
        f"{reason_note}; flipped to cited from the response's own "
        f"citation evidence{bulk_note}"
    )


@dataclass
class _Stage1aCall:
    """One Stage 1a call's inputs and the routing state of its first attempt.

    The first-attempt parser and validators record why the attempt failed;
    the repair path reads that state after the provider call returns.
    """

    llm_client: LLMClient
    loader: TemplateLoader
    run_dir: Path
    step: str
    temperature: float
    response_format: type[LossAnalysisDraft]
    allowed_loss_ids: set[str]
    allowed_hazard_ids: set[str]
    require_losses: bool
    require_complete_chain: bool
    require_risk_accounting: bool
    accounting_cards: Iterable[RiskCard]
    authoritative_draft: LossAnalysisDraft | None
    normalization_warnings: list[str] | None
    repair_record: RepairRecord | None
    template_vars: dict[str, object]
    validation_feedback: str | None = None
    first_parse_failed: bool = False
    first_wire_error: ValidationError | None = None
    # Typed label of the first failure, used to route the targeted repair:
    # wire_schema, risk_accounting, draft_references, or draft_semantics.
    failure_class: str | None = None
    span_repairs: list[RuleSpanRepairRecord] = field(default_factory=list)
    # The first response with its span repairs applied.  The repair path adapts
    # this body, not the logged provider response, so a repaired span is the
    # span every later validator reads.
    span_repaired_result: LLMResult | None = None
    truncation_recovery: tuple[LLMResult, TruncatedDispositionRecovery] | None = None

    def add_warnings(self, warnings: Iterable[str]) -> None:
        """Append each new warning once, when the caller collects warnings."""
        for warning in warnings:
            if (
                self.normalization_warnings is not None
                and warning not in self.normalization_warnings
            ):
                self.normalization_warnings.append(warning)

    def merge_authority(self, repaired: LossAnalysisDraft) -> LossAnalysisDraft:
        """Merge a draft over the authoritative draft of the earlier call."""
        return _merge_loss_analysis_correction(
            LossAnalysisDraft(),
            repaired,
            authoritative_draft=self.authoritative_draft,
        )

    def parse_first_response(
        self, result: LLMResult, cleanup: list[dict[str, Any]]
    ) -> LossAnalysisDraft:
        """Parse the first response, routing wire-schema errors into salvage.

        A pydantic wire violation (for example a malformed or semantically
        invalid ``risk_dispositions`` entry) is deterministic and actionable,
        so it joins the reference validators in the one bounded targeted
        repair instead of crashing the run with an uncorrected parse failure.
        The violation itself is retained so the repair classification can
        reject container-level damage before any salvage runs.  A body that
        never decoded as JSON is a terminal outcome of the first attempt: it
        sets the same routing state so the typed unsupported path records it,
        and the no-retry contract means it is never answered with a second
        dispatch.  The one exception is a risk-derivation body cut off at the
        completion cap inside ``risk_dispositions``: its complete graph and
        complete rows are recovered, and the missing cards reach the
        disposition repair.
        """
        self.span_repairs.clear()
        self.span_repaired_result = None
        if self.require_risk_accounting:
            result = self._recover_truncation(result, cleanup)
        draft = self._parse_provider_draft(result)
        merged = (
            self.merge_authority(draft)
            if self.authoritative_draft is not None
            else draft
        )
        self.add_warnings(normalize_disposition_citations(merged))
        return merged

    def _recover_truncation(
        self, result: LLMResult, cleanup: list[dict[str, Any]]
    ) -> LLMResult:
        """Recover the complete rows of a body cut off inside dispositions."""
        self.truncation_recovery = recover_truncated_risk_dispositions(result)
        if self.truncation_recovery is None:
            return result
        recovered_result, recovery = self.truncation_recovery
        cleanup.append(
            _transformation(
                TRUNCATED_DISPOSITION_RECOVERY_KIND,
                result.content,
                recovered_result.content,
                detail=(
                    f"kept {recovery.kept_rows} of "
                    f"{recovery.complete_rows} complete disposition "
                    "rows from a response cut off at the completion cap"
                ),
            )
        )
        return recovered_result

    def _parse_provider_draft(self, result: LLMResult) -> LossAnalysisDraft:
        """Parse the provider wire and record the failure class it raises."""
        try:
            provider_result = _repair_provider_rule_spans(result, self.span_repairs)
            if self.span_repairs:
                self.span_repaired_result = provider_result
            provider_draft = parse_llm_result(provider_result, self.response_format)
            if not isinstance(provider_draft, _Stage1aGapProviderDraft):
                return provider_draft
            draft = _materialize_provider_draft(
                provider_draft,
                prior=self.authoritative_draft,
            )
            _canonicalize_span_repairs(self.span_repairs, provider_draft, draft)
            return draft
        except ValidationError as exc:
            self.first_wire_error = exc
            self._record_first_parse_failure(
                "wire_schema",
                "Validation feedback: the prior response violated the "
                f"required response schema: {_wire_error_summary(exc)} "
                "Return the complete corrected structured object that "
                "matches the response schema exactly.",
            )
            raise
        except json.JSONDecodeError as exc:
            self._record_first_parse_failure(
                "wire_schema",
                "Validation feedback: the prior response body never decoded "
                f"as JSON ({exc.msg} at line {exc.lineno}, column "
                f"{exc.colno}); return exactly one JSON object matching the "
                "response schema.",
            )
            raise
        except ValueError as exc:
            # Provider-local references are compiled before the domain
            # validator runs.  Keep an unresolved reference eligible for
            # the existing typed repair classification, while refusing to
            # infer that a guessed canonical ID names a newly allocated
            # record.
            self._record_first_parse_failure(
                "draft_references", _provider_reference_feedback(self.step, exc)
            )
            raise

    def _record_first_parse_failure(self, failure_class: str, feedback: str) -> None:
        self.first_parse_failed = True
        self.failure_class = failure_class
        self.validation_feedback = feedback

    def run_validators(
        self,
        draft: LossAnalysisDraft,
        *,
        check_accounting: bool = True,
    ) -> None:
        """Run the stage validators and record the failure class they raise."""
        try:
            self._validate_graph(draft)
            if self.require_risk_accounting and check_accounting:
                self._validate_accounting(draft)
        except _DraftReferenceValidationError:
            self.failure_class = self.failure_class or "draft_references"
            raise
        except _DraftSemanticValidationError:
            self.failure_class = "draft_semantics"
            raise

    def _validate_graph(self, draft: LossAnalysisDraft) -> None:
        _validate_draft_references(
            draft,
            context=self.step,
            allowed_loss_ids=self.allowed_loss_ids,
            allowed_hazard_ids=self.allowed_hazard_ids,
        )
        _validate_draft_semantics(draft, context=self.step)
        if self.require_losses:
            _validate_loss_presence(
                draft,
                context=self.step,
            )
        if self.require_complete_chain:
            _validate_complete_chain(
                draft,
                context=self.step,
                allowed_loss_ids=self.allowed_loss_ids,
                allowed_hazard_ids=self.allowed_hazard_ids,
            )

    def _validate_accounting(self, draft: LossAnalysisDraft) -> None:
        try:
            _validate_risk_accounting(
                draft,
                risk_cards=list(self.accounting_cards),
                context=self.step,
            )
        except _DraftReferenceValidationError:
            # The accounting validator is one of the approved
            # repair classes; label it distinctly from generic
            # reference failures.
            self.failure_class = "risk_accounting"
            raise

    def validate_references(self, draft: LossAnalysisDraft) -> None:
        """Validate the first draft and keep the validator's feedback."""
        try:
            self.run_validators(draft)
        except (_DraftReferenceValidationError, _DraftSemanticValidationError) as exc:
            self.validation_feedback = exc.feedback
            raise

    def record_first_attempt(self, first_result: LLMResult | None) -> LLMResult | None:
        """Record the first attempt's recovery and span repairs.

        Returns the first result the repair path reads: the recovered object
        after a truncation recovery, not the undecodable provider text, and
        the body with its span repairs applied.
        """
        if self.truncation_recovery is not None:
            first_result, recovery = self.truncation_recovery
            record_truncated_disposition_recovery(
                self.repair_record, step=self.step, recovery=recovery
            )
        if self.span_repaired_result is not None:
            first_result = self.span_repaired_result
        record_rule_span_repairs(
            self.repair_record,
            step=self.step,
            attempt="first",
            repairs=self.span_repairs,
            outcome="applied",
        )
        return first_result

    def record_span_warnings(self) -> None:
        """Report each applied rule-span repair as a normalization warning."""
        if self.normalization_warnings is not None:
            self.normalization_warnings.extend(
                f"{self.step} rule_span {record.constraint}/{record.obligation_id} "
                f"repaired by {record.repair.kind} match: "
                f"{record.repair.original!r} -> {record.repair.repaired!r}"
                for record in self.span_repairs
            )

    def record_unsupported(self, identity: str, reason: str) -> None:
        """Record a first-attempt failure that gets no repair call."""
        if self.repair_record is not None:
            self.repair_record.add(
                stage=self.step,
                attempt="first",
                kind="unsupported",
                identity=identity,
                reason=reason,
                proposed={},
                applied={},
                outcome="unsupported",
                raw_step=self.step,
            )


def _provider_reference_feedback(step: str, exc: ValueError) -> str:
    """Render the feedback for an unresolved provider-local reference."""
    feedback = (
        f"Validation feedback: {step} provider graph has an invalid "
        f"cross-reference ({exc}). Declare the record or use its "
        "exact existing canonical ID."
    )
    if step == STEP_GAP and "loss" in str(exc).casefold():
        unknown_match = re.search(
            r"unknown\s+loss\s+reference\s+'([^']+)'",
            str(exc),
            flags=re.IGNORECASE,
        )
        missing_handle = (
            unknown_match.group(1) if unknown_match is not None else "the named handle"
        )
        feedback += (
            " For a genuinely new source-grounded use-case loss, "
            f"declare {missing_handle} in use_case_losses with "
            "provenance: use_case and source_risk_cards: []; "
            "otherwise correct only a mistaken reference to the exact "
            "existing loss with that meaning."
        )
    return feedback


def _run_stage1a_call(
    *,
    llm_client: LLMClient,
    loader: TemplateLoader,
    system_template: str,
    user_template: str,
    run_dir: Path,
    step: str,
    temperature: float,
    response_format: type[LossAnalysisDraft],
    allowed_loss_ids: set[str],
    allowed_hazard_ids: set[str],
    require_losses: bool,
    require_complete_chain: bool,
    require_risk_accounting: bool = False,
    accounting_cards: Iterable[RiskCard] = (),
    authoritative_draft: LossAnalysisDraft | None = None,
    normalization_warnings: list[str] | None = None,
    repair_record: RepairRecord | None = None,
    **template_vars: object,
) -> LossAnalysisDraft:
    """Render prompts, call the LLM, and return a validated draft.

    Shared by the risk_derivation and gap_analysis calls.  Raises
    :class:`StageError` if the LLM call fails.
    """
    system_prompt = loader.render_prompt(system_template)
    user_prompt = loader.render_prompt(user_template, **template_vars)
    call = _Stage1aCall(
        llm_client=llm_client,
        loader=loader,
        run_dir=run_dir,
        step=step,
        temperature=temperature,
        response_format=response_format,
        allowed_loss_ids=allowed_loss_ids,
        allowed_hazard_ids=allowed_hazard_ids,
        require_losses=require_losses,
        require_complete_chain=require_complete_chain,
        require_risk_accounting=require_risk_accounting,
        accounting_cards=accounting_cards,
        authoritative_draft=authoritative_draft,
        normalization_warnings=normalization_warnings,
        repair_record=repair_record,
        template_vars=template_vars,
    )
    first = call_with_policy(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        run_dir=run_dir,
        stage=STAGE,
        step=step,
        policy=CorrectionPolicy(json_retries=JSON_DECODE_RETRIES),
        temperature=temperature,
        max_completion_tokens=STAGE1A_MAX_COMPLETION_TOKENS,
        result_parser_with_cleanup=call.parse_first_response,
        result_validator=call.validate_references,
    )
    first_result = call.record_first_attempt(first.result)
    if first.error is None:
        assert first.value is not None  # call_with_policy guarantees this on success
        call.record_span_warnings()
        return first.value
    return _repair_stage1a_failure(call, first_result, first.error)


def _repair_stage1a_failure(
    call: _Stage1aCall,
    first_result: LLMResult | None,
    error_msg: str,
) -> LossAnalysisDraft:
    """Route a failed first attempt to its one targeted repair or typed stop."""
    # Reference validation and wire-schema violations are deterministic and
    # actionable.  The former bounded whole-object retry is replaced (owner
    # authorization 2026-09-11) by one narrowly scoped targeted repair for
    # three approved failure classes: missing or malformed risk-disposition
    # entries, malformed obligation entries within an otherwise preserved
    # constraint, and duplicate-only reference IDs (decision 47b,
    # 2026-10-04).  Every other failure class gets an explicit typed outcome
    # and no additional model call.
    if call.validation_feedback is None:
        raise StageError(stage=STAGE, step=call.step, message=error_msg)
    _reject_unsupported_wire_error(call, error_msg)
    repair_first_result, repair_response_format = _require_repair_input(
        call, first_result, error_msg
    )
    reference_plan = _check_repair_graph(
        call, repair_first_result, repair_response_format, error_msg
    )
    if reference_plan is not None:
        return _correct_references(
            call, reference_plan, repair_response_format, error_msg
        )
    outcome = build_repair_plan(
        step=call.step,
        response_format=repair_response_format,
        first_result=repair_first_result,
        first_parse_failed=call.first_parse_failed,
        failure_class=call.failure_class or "unknown",
        risk_cards=list(call.accounting_cards),
        require_risk_accounting=call.require_risk_accounting,
        constraint_wire_model=_ProviderSecurityConstraint,
        first_wire_error=call.first_wire_error,
        repair_record=call.repair_record,
        gap_wire=(
            issubclass(call.response_format, _Stage1aGapProviderDraft)
            and not issubclass(call.response_format, _Stage1aRiskProviderDraft)
        ),
    )
    if isinstance(outcome, UnsupportedRepair):
        call.record_unsupported(outcome.scope, outcome.reason)
        raise StageError(
            stage=STAGE,
            step=call.step,
            message=(
                f"targeted repair unsupported ({outcome.reason}); no repair "
                f"call was made; {call.failure_class or 'unknown'} failure class; "
                f"first attempt failed: {error_msg}. "
                f"{call.validation_feedback}"
            ),
        )
    if isinstance(outcome, DeterministicCleanup):
        return _apply_deterministic_cleanup(
            call, outcome, repair_response_format, error_msg
        )
    return _run_stage1a_repairs(call, outcome, repair_response_format)


def _correct_references(
    call: _Stage1aCall,
    plan: ReferenceRepairPlan,
    repair_response_format: type[LossAnalysisDraft],
    error_msg: str,
) -> LossAnalysisDraft:
    """Send the one reference correction; a failed one stops with the finding."""
    try:
        return _stage1a_targeted_repair(
            call,
            plan,
            call.run_validators,
            list(call.accounting_cards),
            repair_response_format,
        )
    except StageError as exc:
        raise StageError(
            stage=STAGE,
            step=call.step,
            message=(
                f"{exc.message}; {call.failure_class} failure class; first "
                f"attempt failed: {error_msg}. {call.validation_feedback}"
            ),
        ) from exc


def _reject_unsupported_wire_error(call: _Stage1aCall, error_msg: str) -> None:
    """Stop with a typed reason when the wire damage is outside repair scope."""
    # Classify container and top-level wire damage before attempting the
    # narrow repair adapter.  The adapter intentionally accepts only a
    # complete current local-handle graph; without this early classification a
    # malformed collection would be reported as a generic "no repair wire"
    # error and lose its typed terminal reason.
    if call.first_wire_error is None:
        return
    reason = classify_wire_validation_errors(call.first_wire_error).unsupported_reason
    if reason is None:
        return
    identity = next(
        (
            collection
            for collection in (
                "risk_card_losses",
                "use_case_losses",
                "hazards",
                "security_constraints",
                "risk_dispositions",
            )
            if collection in reason
        ),
        "response",
    )
    call.record_unsupported(identity, reason)
    raise StageError(
        stage=STAGE,
        step=call.step,
        message=(
            f"targeted repair unsupported ({reason}); "
            f"{call.failure_class or 'wire_schema'} failure class; "
            f"no repair call was made; first attempt failed: "
            f"{error_msg}. {call.validation_feedback}"
        ),
    )


def _require_repair_input(
    call: _Stage1aCall,
    first_result: LLMResult | None,
    error_msg: str,
) -> tuple[LLMResult, type[LossAnalysisDraft]]:
    """Adapt the failed response to the repair wire, or stop with a reason."""
    repair_input = _prepare_current_provider_repair_input(
        first_result,
        response_format=call.response_format,
        prior=call.authoritative_draft,
    )
    if repair_input is not None:
        return repair_input
    reason = _missing_repair_input_reason(call.first_wire_error, first_result)
    call.record_unsupported("response", reason)
    raise StageError(
        stage=STAGE,
        step=call.step,
        message=(
            f"targeted repair unsupported ({reason}); "
            f"{call.failure_class or 'unknown'} failure class; "
            f"no repair call was made; "
            f"first attempt failed: {error_msg}. {call.validation_feedback}"
        ),
    )


def _missing_repair_input_reason(
    first_wire_error: ValidationError | None,
    first_result: LLMResult | None,
) -> str:
    """Name why the failed response could not be adapted for repair."""
    reason = (
        "the failed response did not contain a valid current local-handle "
        "wire that can be adapted for the approved repair scope"
    )
    if first_wire_error is not None:
        wire_classification = classify_wire_validation_errors(first_wire_error)
        if wire_classification.record_errors:
            reason = "wire violation outside the approved repair scope"
    if first_result is not None and isinstance(first_result.content, str):
        try:
            json.loads(first_result.content)
        except (TypeError, json.JSONDecodeError):
            reason = "the response body never decoded as JSON"
    return reason


def _check_repair_graph(
    call: _Stage1aCall,
    repair_first_result: LLMResult,
    repair_response_format: type[LossAnalysisDraft],
    error_msg: str,
) -> ReferenceRepairPlan | None:
    """Reject a repair input whose independent graph edges do not resolve.

    Returns the reference-list repair plan when the reference gate failed on
    lists that repeat an ID or name an unknown ID.
    """
    # The bounded repair may only address dispositions, obligation rows, or
    # repeated or unknown reference IDs.  Validate the independent graph edges
    # before constructing any repair plan so a malformed local reference cannot
    # be smuggled through an otherwise repairable obligation and trigger a
    # second model call.
    try:
        graph = _repair_graph_draft(repair_first_result)
    except (ValidationError, ValueError) as exc:
        _stop_outside_graph_scope(call, exc, error_msg)
    try:
        _validate_draft_references(
            graph,
            context=call.step,
            allowed_loss_ids=call.allowed_loss_ids,
            allowed_hazard_ids=call.allowed_hazard_ids,
        )
    except _DraftReferenceValidationError as exc:
        plan = _reference_plan(
            call, graph, repair_first_result, repair_response_format, str(exc)
        )
        if plan is None:
            _stop_outside_graph_scope(call, exc, error_msg)
        return plan
    return None


def _stop_outside_graph_scope(
    call: _Stage1aCall, exc: Exception, error_msg: str
) -> NoReturn:
    """Record and raise the typed stop for an unrepairable graph failure."""
    reason = f"graph validation is outside the approved repair scope: {exc}"
    call.record_unsupported("response", reason)
    raise StageError(
        stage=STAGE,
        step=call.step,
        message=(
            f"targeted repair unsupported ({reason}); no repair call was "
            f"made; {call.failure_class or 'draft_references'} failure class; "
            f"first attempt failed: {error_msg}. {call.validation_feedback}"
        ),
    ) from exc


def _reference_plan(
    call: _Stage1aCall,
    graph: LossAnalysisDraft,
    repair_first_result: LLMResult,
    repair_response_format: type[LossAnalysisDraft],
    finding: str,
) -> ReferenceRepairPlan | None:
    """Plan the reference-list repair, or None when it does not apply.

    The repair applies when the reference gate failed (a wire failure has
    its own class) on lists that repeat an ID or name an unknown ID.  Those
    lists are every edge the reference gate checks, so the selection covers
    the whole finding; a gap list that is empty from the start is another
    defect and gets no repair call.
    """
    if call.failure_class != "draft_references" or not _relationships_present(
        call, graph
    ):
        return None
    valid_loss_ids = call.allowed_loss_ids | {
        loss.loss_id for loss in graph.risk_card_losses + graph.use_case_losses
    }
    valid_hazard_ids = call.allowed_hazard_ids | {
        hazard.hazard_id for hazard in graph.hazards
    }
    selected = select_reference_repairs(
        graph, valid_loss_ids=valid_loss_ids, valid_hazard_ids=valid_hazard_ids
    )
    if not selected:
        return None
    prior = parse_llm_result(repair_first_result, repair_response_format)
    return ReferenceRepairPlan(
        prior=prior,
        selected=selected,
        meanings=_reference_meanings(prior, call.authoritative_draft),
        feedback=finding,
    )


def _relationships_present(call: _Stage1aCall, graph: LossAnalysisDraft) -> bool:
    """Return whether every supplied gap hazard and constraint lists a link."""
    if call.step != STEP_GAP:
        return True
    try:
        _validate_gap_relationships(graph, context=call.step)
    except _DraftReferenceValidationError:
        return False
    return True


def _reference_meanings(
    draft: LossAnalysisDraft, earlier: LossAnalysisDraft | None
) -> tuple[tuple[str, str], ...]:
    """Map each loss and hazard ID either draft declares to its description."""
    meanings: dict[str, str] = {}
    for source in (earlier, draft):
        if source is None:
            continue
        for loss in source.risk_card_losses + source.use_case_losses:
            meanings[loss.loss_id] = loss.description
        for hazard in source.hazards:
            meanings[hazard.hazard_id] = hazard.description
    return tuple(sorted(meanings.items()))


def _repair_graph_draft(repair_first_result: LLMResult) -> LossAnalysisDraft:
    """Parse the repair input without its disposition rows and obligations."""
    repair_content = repair_first_result.content
    if isinstance(repair_content, BaseModel):
        repair_content = repair_content.model_dump(mode="json")
    if not isinstance(repair_content, dict):
        raise ValueError("the adapted repair graph is not a JSON object")
    graph_content = deepcopy(repair_content)
    graph_content["risk_dispositions"] = []
    constraints = graph_content.get("security_constraints", [])
    if isinstance(constraints, list):
        for row in constraints:
            if isinstance(row, dict):
                row["obligations"] = []
    return LossAnalysisDraft.model_validate(graph_content)


def _apply_deterministic_cleanup(
    call: _Stage1aCall,
    outcome: DeterministicCleanup,
    repair_response_format: type[LossAnalysisDraft],
    error_msg: str,
) -> LossAnalysisDraft:
    """Validate and return the draft a deterministic row removal produced.

    Deterministic row removal (out-of-contract disposition rows, or rows
    referencing unsupplied risk cards) is all the failure reduced to.
    The cleaned draft re-validates against the original provider schema
    (boundary 1) and then passes through the same authority merge,
    citation normalization, and full stage validators as a successful
    response.
    """
    cleaned = outcome.draft
    try:
        revalidate_provider_object(cleaned, repair_response_format, step=call.step)
    except ValueError as exc:
        _record_failed_cleanup(call, outcome, exc)
        raise StageError(
            stage=STAGE,
            step=call.step,
            message=(
                f"targeted repair unsupported (deterministic cleanup "
                f"failed re-validation of the original provider schema: "
                f"{exc}); no repair call was made; first attempt failed: "
                f"{error_msg}"
            ),
        ) from exc
    try:
        cleaned = _validate_cleaned_draft(call, cleaned)
    except (_DraftReferenceValidationError, _DraftSemanticValidationError) as exc:
        _record_failed_cleanup(call, outcome, exc)
        raise StageError(
            stage=STAGE,
            step=call.step,
            message=(
                f"targeted repair unsupported (deterministic cleanup left "
                f"a {call.failure_class or 'draft'} failure: {exc}); no repair "
                f"call was made; first attempt failed: {error_msg}. "
                f"{exc.feedback}"
            ),
        ) from exc
    except ValueError as exc:
        _record_failed_cleanup(call, outcome, exc)
        raise StageError(
            stage=STAGE,
            step=call.step,
            message=(
                "targeted repair unsupported (deterministic cleanup "
                f"produced a conflicting duplicate: {exc}); no repair call "
                f"was made; first attempt failed: {error_msg}"
            ),
        ) from exc
    call.add_warnings(outcome.warnings)
    record_cleanup_rows(
        outcome.removed_rows,
        step=call.step,
        repair_record=call.repair_record,
        outcome="removed",
    )
    return cleaned


def _validate_cleaned_draft(
    call: _Stage1aCall, cleaned: LossAnalysisDraft
) -> LossAnalysisDraft:
    """Merge, normalize, and validate a cleaned draft like a first response."""
    if call.authoritative_draft is not None:
        cleaned = call.merge_authority(cleaned)
    call.add_warnings(normalize_disposition_citations(cleaned))
    call.run_validators(cleaned)
    return cleaned


def _record_failed_cleanup(
    call: _Stage1aCall, outcome: DeterministicCleanup, exc: ValueError
) -> None:
    record_cleanup_rows(
        outcome.removed_rows,
        step=call.step,
        repair_record=call.repair_record,
        outcome="failed",
        reason=str(exc),
    )


def _run_stage1a_repairs(
    call: _Stage1aCall,
    plan: RepairPlan,
    repair_response_format: type[LossAnalysisDraft],
) -> LossAnalysisDraft:
    """Run the targeted repair, plus a disposition repair it leaves pending."""
    cards = list(call.accounting_cards)
    # An obligation repair cannot touch disposition rows, so a response that
    # also cites undeclared losses (or misses cards) would fail accounting
    # after an otherwise successful obligation repair.  Defer the accounting
    # check through the obligation repair, then spend at most one more call
    # on the approved disposition repair of exactly the failing rows.
    pending_accounting = (
        isinstance(plan, ObligationRepairPlan)
        and call.require_risk_accounting
        and bool(select_disposition_repairs(plan.prior, cards)[0])
    )
    if not pending_accounting:
        return _stage1a_targeted_repair(
            call, plan, call.run_validators, cards, repair_response_format
        )
    repaired = _stage1a_targeted_repair(
        call,
        plan,
        lambda draft: call.run_validators(draft, check_accounting=False),
        cards,
        repair_response_format,
    )
    selected, reason_pairs, removed_unknown = select_disposition_repairs(
        repaired, cards
    )
    if not selected:
        try:
            call.run_validators(repaired)
        except (_DraftReferenceValidationError, _DraftSemanticValidationError) as exc:
            raise StageError(
                stage=STAGE,
                step=call.step,
                message=f"targeted repair failed: {type(exc).__name__}: {exc}",
            ) from exc
        return repaired
    return _stage1a_targeted_repair(
        call,
        DispositionRepairPlan(
            prior=repaired,
            selected=selected,
            reasons=reason_pairs,
            removed_unknown=tuple(
                (reference, "risk reference absent from the supplied set")
                for reference in removed_unknown
            ),
        ),
        call.run_validators,
        cards,
        repair_response_format,
    )


def _stage1a_targeted_repair(
    call: _Stage1aCall,
    repair_plan: RepairPlan,
    validators: Callable[[LossAnalysisDraft], None],
    cards: list[RiskCard],
    repair_response_format: type[LossAnalysisDraft],
) -> LossAnalysisDraft:
    return run_targeted_repair(
        repair_plan,
        llm_client=call.llm_client,
        loader=call.loader,
        run_dir=call.run_dir,
        step=call.step,
        temperature=call.temperature,
        use_case_text=str(call.template_vars.get("use_case_text", "")),
        risk_cards=cards,
        run_validators=validators,
        normalizer=normalize_disposition_citations,
        authoritative_merge=(
            call.merge_authority if call.authoritative_draft is not None else None
        ),
        normalization_warnings=call.normalization_warnings,
        max_completion_tokens=STAGE1A_MAX_COMPLETION_TOKENS,
        provider_draft_model=repair_response_format,
        repair_record=call.repair_record,
    )


def _repair_provider_rule_spans(
    result: LLMResult,
    repairs_out: list[RuleSpanRepairRecord],
) -> LLMResult:
    """Return ``result`` with unambiguous ``rule_span`` repairs applied.

    The provider wire validates each obligation's span against its rule while
    parsing, so repairs run on the decoded body first.  The original result
    (and therefore the logged provider response) is never mutated; a body
    that does not decode is returned unchanged for the ordinary parser.
    """
    if isinstance(result.content, BaseModel):
        return result
    try:
        decoded = decode_content(result)
    except (TypeError, ValueError):
        return result
    if not isinstance(decoded, dict):
        return result
    content = deepcopy(decoded)
    rows = content.get("security_constraints")
    if not isinstance(rows, list):
        return result
    for row in rows:
        if isinstance(row, dict):
            repairs_out.extend(
                repair_obligation_rows(
                    constraint=str(row.get("handle", "")),
                    rule=row.get("rule"),
                    obligations=row.get("obligations"),
                )
            )
    if not repairs_out:
        return result
    return result.model_copy(update={"content": content})


def _canonicalize_span_repairs(
    repairs: list[RuleSpanRepairRecord],
    provider_draft: _Stage1aGapProviderDraft,
    draft: LossAnalysisDraft,
) -> None:
    """Name repaired constraints by their allocated canonical IDs."""
    # Materialization keeps the provider constraint order.
    canonical = {
        provider.handle: materialized.constraint_id
        for provider, materialized in zip(
            provider_draft.security_constraints, draft.security_constraints
        )
    }
    repairs[:] = [
        RuleSpanRepairRecord(
            constraint=canonical.get(record.constraint, record.constraint),
            obligation_id=record.obligation_id,
            repair=record.repair,
        )
        for record in repairs
    ]


def _merge_loss_analysis_correction(
    prior: LossAnalysisDraft,
    correction: LossAnalysisDraft,
    *,
    authoritative_draft: LossAnalysisDraft | None = None,
) -> LossAnalysisDraft:
    """Apply a collection patch and reject changed authoritative duplicates.

    A correction is intentionally collection-aware: an empty section means
    "no update" and retains the prior section, while a non-empty section is
    the complete replacement for that section.  The risk derivation is the
    authority for already-known records; exact repeated records are removed,
    but a reused identity with changed semantics fails closed.
    """
    # Provenance is the semantic section key.  Normalize both sides before
    # deciding whether a correction section is empty; otherwise a loss emitted
    # in the wrong wire container can survive alongside its corrected record
    # and be reported as a false conflicting duplicate.
    canonical_prior = _canonicalize_draft_losses(prior)
    canonical_correction = _canonicalize_draft_losses(correction)
    patched_risk_losses = _patch_collection(
        canonical_prior.risk_card_losses,
        canonical_correction.risk_card_losses,
    )
    patched_use_case_losses = _patch_collection(
        canonical_prior.use_case_losses,
        canonical_correction.use_case_losses,
    )
    patched_hazards = _patch_collection(
        canonical_prior.hazards,
        canonical_correction.hazards,
    )
    patched_constraints = _patch_collection(
        canonical_prior.security_constraints,
        canonical_correction.security_constraints,
    )
    patched_dispositions = _patch_collection(
        prior.risk_dispositions,
        correction.risk_dispositions,
    )

    patched = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": patched_risk_losses,
            "use_case_losses": patched_use_case_losses,
            "hazards": patched_hazards,
            "security_constraints": patched_constraints,
            "risk_dispositions": patched_dispositions,
        }
    )
    risk_losses, use_case_losses = _normalize_losses(patched, LossAnalysisDraft())

    if authoritative_draft is not None:
        risk_losses = _remove_authoritative_duplicates(
            risk_losses,
            (
                *authoritative_draft.risk_card_losses,
                *authoritative_draft.use_case_losses,
            ),
            "loss_id",
            "loss",
        )
        use_case_losses = _remove_authoritative_duplicates(
            use_case_losses,
            (
                *authoritative_draft.risk_card_losses,
                *authoritative_draft.use_case_losses,
            ),
            "loss_id",
            "loss",
        )
        patched_hazards = _remove_authoritative_duplicates(
            patched_hazards,
            authoritative_draft.hazards,
            "hazard_id",
            "hazard",
        )
        patched_constraints = _remove_authoritative_duplicates(
            patched_constraints,
            authoritative_draft.security_constraints,
            "constraint_id",
            "security constraint",
        )

    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": risk_losses,
            "use_case_losses": use_case_losses,
            "hazards": patched_hazards,
            "security_constraints": patched_constraints,
            "risk_dispositions": patched_dispositions,
        }
    )


def _patch_collection(
    prior: Iterable[object],
    correction: Iterable[object],
) -> list[object]:
    """Retain an empty correction or replace the prior collection."""
    source = list(correction) or list(prior)
    return [item.model_copy(deep=True) for item in source]


def _remove_authoritative_duplicates(
    items: Iterable[object],
    authoritative: Iterable[object],
    identity_field: str,
    record_label: str,
) -> list[object]:
    """Drop exact authority repeats and reject changed reused identities."""
    authoritative_by_id = {
        getattr(item, identity_field): item for item in authoritative
    }
    result: list[object] = []
    for item in items:
        identity = getattr(item, identity_field)
        baseline = authoritative_by_id.get(identity)
        if baseline is None:
            result.append(item)
            continue
        if baseline.model_dump(mode="json") == item.model_dump(mode="json"):
            continue
        raise ValueError(
            f"conflicting duplicate {record_label} ID '{identity}' "
            "between gap correction and risk derivation"
        )
    return result


def _disposition_loss_contradictions(
    losses: list[Loss],
    dispositions: list[RiskDisposition],
) -> list[str]:
    """Detect citations that contradict a not_applicable disposition.

    Spec rule 1.1(4): every loss is cited by at least one risk card or is
    marked ``use_case``.  A card marked not_applicable therefore never cites
    a loss, so no loss may list it in ``source_risk_cards``.  A cited
    disposition's loss registry is authoritative for which loss accounts for
    the card; the loss's own source list may name additional cards.
    """
    problems: list[str] = []
    for disposition in dispositions:
        if disposition.disposition != "not_applicable":
            continue
        citing = [
            loss.loss_id
            for loss in losses
            if disposition.risk_ref in loss.source_risk_cards
        ]
        if citing:
            problems.append(
                f"'{disposition.risk_ref}' is marked not_applicable but is "
                "cited by loss " + ", ".join(sorted(citing))
            )
    return problems


def _validate_risk_accounting(
    draft: LossAnalysisDraft,
    *,
    risk_cards: list[RiskCard],
    context: str,
) -> None:
    """Require exactly one disposition for every supplied risk card.

    The deterministic 1.1 gate on the provider response: a cited entry must
    name at least one loss declared in this response, a not_applicable entry
    must carry a non-empty reason, no supplied card may be missing or
    double-counted, and a not_applicable card is never cited by a loss
    (spec rule 1.1(4)).  The failure feedback lists the exact missing or
    malformed entries and never suggests hazards or losses to invent.
    """
    supplied_ids = [card.risk_id for card in risk_cards]
    if not supplied_ids:
        return
    declared_loss_ids = {
        loss.loss_id for loss in draft.risk_card_losses + draft.use_case_losses
    }
    seen: dict[str, int] = {}
    problems = _disposition_entry_problems(
        draft.risk_dispositions,
        supplied=set(supplied_ids),
        declared_loss_ids=declared_loss_ids,
        seen=seen,
    )
    problems.extend(
        _disposition_loss_contradictions(
            [*draft.risk_card_losses, *draft.use_case_losses],
            draft.risk_dispositions,
        )
    )
    problems.extend(_disposition_count_problems(supplied_ids, seen))
    if not problems:
        return
    message = f"{context} risk accounting is incomplete: " + "; ".join(problems)
    raise _DraftReferenceValidationError(
        message,
        feedback=(
            f"Validation feedback: {message}. Return exactly one "
            "risk_dispositions entry per supplied risk card: disposition "
            "'cited' with the loss_ids that account for it, or disposition "
            "'not_applicable' with a one-sentence reason and no loss_ids. "
            "Every cited loss_ids value must name a loss declared in this "
            "same response, and a not_applicable card must not be cited by "
            "any loss in source_risk_cards. Do not invent losses merely to "
            "cite a risk; a risk that produces no grounded loss stays "
            "not_applicable with its reason."
        ),
    )


def _disposition_entry_problems(
    dispositions: list[RiskDisposition],
    *,
    supplied: set[str],
    declared_loss_ids: set[str],
    seen: dict[str, int],
) -> list[str]:
    """Check each disposition entry and count its risk_ref in *seen*."""
    problems: list[str] = []
    for disposition in dispositions:
        seen[disposition.risk_ref] = seen.get(disposition.risk_ref, 0) + 1
        if disposition.risk_ref not in supplied:
            problems.append(f"'{disposition.risk_ref}' is not a supplied risk card ID")
            continue
        if disposition.disposition == "cited":
            missing = [
                loss_id
                for loss_id in disposition.loss_ids
                if loss_id not in declared_loss_ids
            ]
            if missing:
                problems.append(
                    f"cited '{disposition.risk_ref}' names undeclared losses: "
                    + ", ".join(missing)
                )
        elif not disposition.reason or not disposition.reason.strip():
            problems.append(
                f"not_applicable '{disposition.risk_ref}' has an empty reason"
            )
    return problems


def _disposition_count_problems(
    supplied_ids: list[str], seen: dict[str, int]
) -> list[str]:
    """Name supplied cards without a disposition and cards disposed twice."""
    problems: list[str] = []
    missing_cards = [card_id for card_id in supplied_ids if seen.get(card_id, 0) == 0]
    duplicate_cards = sorted(card_id for card_id, count in seen.items() if count > 1)
    if missing_cards:
        problems.append(
            "missing risk_dispositions entries for: " + ", ".join(missing_cards)
        )
    if duplicate_cards:
        problems.append(
            "duplicate risk_dispositions entries for: " + ", ".join(duplicate_cards)
        )
    return problems


def _validate_complete_chain(
    draft: LossAnalysisDraft,
    *,
    context: str,
    allowed_loss_ids: set[str] = set(),
    allowed_hazard_ids: set[str] = set(),
) -> None:
    """Require a dependency-ordered, non-empty loss-analysis chain.

    A gap response may legitimately add a hazard that points to an existing
    loss, so availability includes the prior call's IDs.  The local response
    still has to declare each new relationship explicitly; an empty collection
    is never treated as an implicit declaration or as proof of
    non-applicability.
    """
    losses = (*draft.risk_card_losses, *draft.use_case_losses)
    loss_ids = allowed_loss_ids | {loss.loss_id for loss in losses}
    hazard_ids = allowed_hazard_ids | {hazard.hazard_id for hazard in draft.hazards}
    checks = (
        (not loss_ids, "no grounded losses were declared or supplied"),
        (not hazard_ids, "no hazards were declared or supplied"),
        (not draft.security_constraints, "no security constraints were declared"),
        (
            any(not hazard.related_losses for hazard in draft.hazards),
            "every hazard must reference at least one loss",
        ),
        (
            any(not item.related_hazards for item in draft.security_constraints),
            "every security constraint must reference at least one hazard",
        ),
    )
    problems = [message for failed, message in checks if failed]
    if not problems:
        return
    message = (
        f"{context} must return a complete loss -> hazard -> security constraint chain: "
        + "; ".join(problems)
    )
    raise _DraftSemanticValidationError(
        message,
        feedback=(
            f"Validation feedback: {message}. An empty response is not valid "
            "for this call. Declare grounded losses before referencing them in "
            "hazards, then declare constraints against those hazards. Preserve "
            "the supplied risks and return linked IDs for every record."
        ),
    )


def _validate_loss_presence(
    draft: LossAnalysisDraft,
    *,
    context: str,
) -> None:
    """Require the loss-producing call to declare at least one loss.

    The first Stage 1a call owns grounded risk-card loss declarations.  It is
    intentionally not required to derive the dependent graph in the same
    response; the gap call receives this closed loss registry and derives any
    missing hazards and constraints.
    """
    declared_losses = [
        loss
        for loss in (*draft.risk_card_losses, *draft.use_case_losses)
        if loss.provenance == LossProvenance.risk_card
    ]
    if declared_losses:
        return
    message = (
        f"{context} must return a complete loss -> hazard -> security constraint "
        "chain anchor: no grounded losses were declared"
    )
    raise _DraftSemanticValidationError(
        message,
        feedback=(
            f"Validation feedback: {message}. Declare at least one grounded "
            "risk-card loss with non-empty source_risk_cards before writing "
            "hazards or security constraints. An empty response is not valid "
            "when organizational risks are supplied. Do not invent a loss or "
            "use an undeclared L-* placeholder."
        ),
    )


def _validate_draft_references(
    draft: LossAnalysisDraft,
    *,
    context: str,
    allowed_loss_ids: set[str],
    allowed_hazard_ids: set[str],
) -> None:
    """Validate draft references before a draft is accepted or serialized.

    ``risk_derivation`` is self-contained.  ``gap_analysis`` may reference
    the existing risk draft in addition to IDs introduced by its own draft.
    The caller supplies the existing IDs; local IDs are always added here.
    """
    local_loss_ids = {
        loss.loss_id for loss in draft.risk_card_losses + draft.use_case_losses
    }
    local_hazard_ids = {hazard.hazard_id for hazard in draft.hazards}
    valid_loss_ids = allowed_loss_ids | local_loss_ids
    valid_hazard_ids = allowed_hazard_ids | local_hazard_ids

    # A gap response may be legitimately empty when the first call already
    # provides a complete graph.  When it does supply hazards or constraints,
    # however, each supplied relationship must be explicit even though the
    # complete-chain gate is intentionally skipped for that case.
    if context == STEP_GAP:
        _validate_gap_relationships(draft, context=context)

    loss_edges = [(hazard.hazard_id, hazard.related_losses) for hazard in draft.hazards]
    hazard_edges = [
        (constraint.constraint_id, constraint.related_hazards)
        for constraint in draft.security_constraints
    ]
    unknown_loss_ids = _unknown_references(loss_edges, valid_loss_ids)
    unknown_hazard_ids = _unknown_references(hazard_edges, valid_hazard_ids)
    duplicate_losses = _duplicate_references(loss_edges)
    duplicate_hazards = _duplicate_references(hazard_edges)
    if not (
        unknown_loss_ids or unknown_hazard_ids or duplicate_losses or duplicate_hazards
    ):
        return
    _raise_reference_problems(
        context=context,
        unknown_loss_ids=unknown_loss_ids,
        unknown_hazard_ids=unknown_hazard_ids,
        valid_loss_ids=valid_loss_ids,
        valid_hazard_ids=valid_hazard_ids,
        duplicate_losses=duplicate_losses,
        duplicate_hazards=duplicate_hazards,
    )


def _unknown_references(
    edges: Iterable[tuple[str, list[str]]], valid_ids: set[str]
) -> list[str]:
    """Return the sorted references that name no valid ID."""
    return sorted(
        {
            reference
            for _, references in edges
            for reference in references
            if reference not in valid_ids
        }
    )


def _duplicate_references(edges: Iterable[tuple[str, list[str]]]) -> list[str]:
    """Return ``owner -> reference`` for each reference an owner lists twice.

    A repeated edge is a finding, not something to collapse: the downstream
    systemic snapshot rejects repeated reference sets.
    """
    return [
        f"{owner} -> {reference}"
        for owner, reference in sorted(
            {
                (owner, reference)
                for owner, references in edges
                for reference in references
                if references.count(reference) > 1
            }
        )
    ]


_DUPLICATE_REFERENCE_HINT = (
    "List each ID at most once in a hazard's related_losses and in a security "
    "constraint's related_hazards: remove each repeated entry named above, or "
    "replace it with the exact ID of the different record it was meant to name."
)


def _reference_problems(
    *,
    unknown_loss_ids: list[str],
    unknown_hazard_ids: list[str],
    duplicate_losses: list[str],
    duplicate_hazards: list[str],
) -> list[str]:
    """Render each non-empty reference finding in a fixed order."""
    labelled = (
        ("hazards.related_losses unknown IDs: ", unknown_loss_ids),
        ("security_constraints.related_hazards unknown IDs: ", unknown_hazard_ids),
        ("hazards.related_losses duplicate IDs: ", duplicate_losses),
        ("security_constraints.related_hazards duplicate IDs: ", duplicate_hazards),
    )
    return [label + ", ".join(values) for label, values in labelled if values]


def _raise_reference_problems(
    *,
    context: str,
    unknown_loss_ids: list[str],
    unknown_hazard_ids: list[str],
    valid_loss_ids: set[str],
    valid_hazard_ids: set[str],
    duplicate_losses: list[str],
    duplicate_hazards: list[str],
) -> None:
    """Raise the reference error with a repair hint for each finding."""
    problems = _reference_problems(
        unknown_loss_ids=unknown_loss_ids,
        unknown_hazard_ids=unknown_hazard_ids,
        duplicate_losses=duplicate_losses,
        duplicate_hazards=duplicate_hazards,
    )
    message = f"{context} draft has invalid cross-references: " + "; ".join(problems)
    if context == STEP_RISK:
        scope = "IDs declared in the risk_derivation draft"
    else:
        scope = "IDs declared in the risk_derivation or gap_analysis draft"
    hints = _missing_declaration_hints(
        context=context,
        unknown_loss_ids=unknown_loss_ids,
        unknown_hazard_ids=unknown_hazard_ids,
        valid_loss_ids=valid_loss_ids,
        valid_hazard_ids=valid_hazard_ids,
    )
    if duplicate_losses or duplicate_hazards:
        hints.append(_DUPLICATE_REFERENCE_HINT)
    repair = (
        " ".join(hints)
        or "Add each missing declaration or change the reference to an existing ID."
    )
    feedback = (
        f"Validation feedback: {message}. {repair} Use only {scope}; preserve every "
        "valid loss, hazard, and security constraint. Repair these dependencies "
        "before adding further constraints; expanding the constraint list while "
        "leaving the named declarations missing does not repair the result."
    )
    raise _DraftReferenceValidationError(message, feedback=feedback)


def _missing_declaration_hints(
    *,
    context: str,
    unknown_loss_ids: list[str],
    unknown_hazard_ids: list[str],
    valid_loss_ids: set[str],
    valid_hazard_ids: set[str],
) -> list[str]:
    """Return one repair hint per kind of unknown reference."""
    missing_declarations = []
    if unknown_loss_ids:
        missing_declarations.append(
            "Missing loss declarations: "
            + ", ".join(unknown_loss_ids)
            + ". Known loss IDs: "
            + (", ".join(sorted(valid_loss_ids)) or "none")
            + ". Declare each genuinely new stakeholder loss in the appropriate "
            "loss collection before referencing it. If this was only an ID mistake, "
            "correct the hazard to the exact known loss with that meaning instead. "
            "Do not invent a loss merely to satisfy an ID."
        )
        if context == STEP_GAP:
            missing_declarations.append(
                "For a genuinely new source-grounded use-case loss, declare "
                + ", ".join(unknown_loss_ids)
                + " in use_case_losses with provenance: use_case and "
                "source_risk_cards: []; otherwise correct only a mistaken "
                "reference to the exact existing loss with that meaning."
            )
    if unknown_hazard_ids:
        missing_declarations.append(
            "Missing hazard declarations: "
            + ", ".join(unknown_hazard_ids)
            + ". Known hazard IDs: "
            + (", ".join(sorted(valid_hazard_ids)) or "none")
            + ". Declare each grounded hazardous state against declared losses, "
            "or correct the constraint to the exact known hazard it prevents."
        )
    return missing_declarations


def _validate_gap_relationships(
    draft: LossAnalysisDraft,
    *,
    context: str,
) -> None:
    """Require explicit links on supplied gap hazards and constraints.

    An empty gap draft is valid: it declares no new records.  A declared hazard
    or security constraint is different; its relationship cannot be treated as
    implicit merely because the prior risk draft already had a complete graph.
    The risk-derivation call intentionally does not use this check because it
    may establish the loss registry before closing the dependent graph.
    """
    empty_hazards = [
        hazard.hazard_id for hazard in draft.hazards if not hazard.related_losses
    ]
    empty_constraints = [
        constraint.constraint_id
        for constraint in draft.security_constraints
        if not constraint.related_hazards
    ]
    if not empty_hazards and not empty_constraints:
        return

    problems: list[str] = []
    if empty_hazards:
        problems.append("hazards.related_losses empty for " + ", ".join(empty_hazards))
    if empty_constraints:
        problems.append(
            "security_constraints.related_hazards empty for "
            + ", ".join(empty_constraints)
        )
    message = f"{context} draft has empty cross-references: " + "; ".join(problems)
    raise _DraftReferenceValidationError(
        message,
        feedback=(
            f"Validation feedback: {message}. Every supplied hazard must list "
            "at least one related loss and every supplied security constraint "
            "must list at least one related hazard. An empty gap response is "
            "valid only when both collections are empty."
        ),
    )


def _merge_drafts(
    risk_draft: LossAnalysisDraft,
    gap_draft: LossAnalysisDraft,
) -> LossAnalysis:
    """Merge risk derivation and gap analysis drafts into a final LossAnalysis.

    Preserve every canonical identity already assigned by the compiler.  A
    direct caller may still provide local domain IDs (for example an offline
    fixture), so those are allocated once, deterministically, before the
    source-separated loss merge.  Identical repeated records are collapsed;
    a changed payload under one identity is rejected rather than silently
    replacing the authoritative risk record.
    """
    risk_draft, gap_draft = _canonicalize_domain_graph(risk_draft, gap_draft)
    all_risk_losses, all_uc_losses = _normalize_losses(risk_draft, gap_draft)
    all_hazards = _merge_identity_records(
        [*risk_draft.hazards, *gap_draft.hazards],
        identity_field="hazard_id",
        record_label="hazard",
    )
    all_constraints = _merge_identity_records(
        [*risk_draft.security_constraints, *gap_draft.security_constraints],
        identity_field="constraint_id",
        record_label="security constraint",
    )

    return LossAnalysis(
        risk_card_losses=all_risk_losses,
        use_case_losses=all_uc_losses,
        hazards=all_hazards,
        security_constraints=all_constraints,
        # Risk accounting has one owner: the risk-derivation response.  Gap
        # dispositions, if supplied by an offline caller, never alter it.
        risk_dispositions=[
            disposition.model_copy(deep=True)
            for disposition in risk_draft.risk_dispositions
        ],
    )


def _canonical_id_map(
    records: Iterable[object],
    *,
    id_attr: str,
    kind: str,
    reserved_ids: set[str] | None = None,
) -> dict[str, str]:
    """Preserve canonical IDs and allocate deterministic IDs for local ones.

    ``reserved_ids`` contains canonical identities already in the complete
    merge.  Local handles are mapped per provider scope, so the same spelling
    in the risk and gap responses cannot accidentally merge two records or
    redirect a risk disposition.
    """
    pattern = _CANONICAL_ID_PATTERNS[kind]
    values = {str(getattr(record, id_attr)) for record in records}
    used = set(reserved_ids or ())
    used.update(value for value in values if pattern.fullmatch(value))
    mapping = {value: value for value in used}
    mapping.update(
        allocate_canonical_ids(_CANONICAL_PREFIXES[kind], used, sorted(values - used))
    )
    return mapping


def _canonicalize_domain_graph(
    risk_draft: LossAnalysisDraft,
    gap_draft: LossAnalysisDraft,
) -> tuple[LossAnalysisDraft, LossAnalysisDraft]:
    """Normalize optional direct-caller local IDs without rewriting canonicals."""
    drafts = (risk_draft, gap_draft)
    all_losses = [
        loss
        for draft in drafts
        for loss in (*draft.risk_card_losses, *draft.use_case_losses)
    ]
    all_hazards = [hazard for draft in drafts for hazard in draft.hazards]
    all_constraints = [
        constraint for draft in drafts for constraint in draft.security_constraints
    ]
    used_loss_ids = _canonical_ids_in(all_losses, id_attr="loss_id", kind="loss")
    used_hazard_ids = _canonical_ids_in(all_hazards, id_attr="hazard_id", kind="hazard")
    used_constraint_ids = _canonical_ids_in(
        all_constraints,
        id_attr="constraint_id",
        kind="constraint",
    )

    normalized: list[LossAnalysisDraft] = []
    for draft in drafts:
        loss_map = _canonical_id_map(
            [
                *draft.risk_card_losses,
                *draft.use_case_losses,
            ],
            id_attr="loss_id",
            kind="loss",
            reserved_ids=used_loss_ids,
        )
        used_loss_ids.update(loss_map.values())
        hazard_map = _canonical_id_map(
            draft.hazards,
            id_attr="hazard_id",
            kind="hazard",
            reserved_ids=used_hazard_ids,
        )
        used_hazard_ids.update(hazard_map.values())
        constraint_map = _canonical_id_map(
            draft.security_constraints,
            id_attr="constraint_id",
            kind="constraint",
            reserved_ids=used_constraint_ids,
        )
        used_constraint_ids.update(constraint_map.values())
        normalized.append(
            _renumbered_draft(draft, loss_map, hazard_map, constraint_map)
        )
    return normalized[0], normalized[1]


def _canonical_ids_in(
    records: Iterable[object], *, id_attr: str, kind: str
) -> set[str]:
    """Return the record IDs that already have canonical form."""
    pattern = _CANONICAL_ID_PATTERNS[kind]
    return {
        str(getattr(record, id_attr))
        for record in records
        if pattern.fullmatch(str(getattr(record, id_attr)))
    }


def _renumbered_draft(
    draft: LossAnalysisDraft,
    loss_map: dict[str, str],
    hazard_map: dict[str, str],
    constraint_map: dict[str, str],
) -> LossAnalysisDraft:
    """Copy *draft* with every identity and reference mapped to its canonical ID."""
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                loss.model_copy(
                    update={"loss_id": loss_map[loss.loss_id]},
                    deep=True,
                )
                for loss in draft.risk_card_losses
            ],
            "use_case_losses": [
                loss.model_copy(
                    update={"loss_id": loss_map[loss.loss_id]},
                    deep=True,
                )
                for loss in draft.use_case_losses
            ],
            "hazards": [
                hazard.model_copy(
                    update={
                        "hazard_id": hazard_map[hazard.hazard_id],
                        "related_losses": [
                            loss_map.get(reference, reference)
                            for reference in hazard.related_losses
                        ],
                    },
                    deep=True,
                )
                for hazard in draft.hazards
            ],
            "security_constraints": [
                constraint.model_copy(
                    update={
                        "constraint_id": constraint_map[constraint.constraint_id],
                        "related_hazards": [
                            hazard_map.get(reference, reference)
                            for reference in constraint.related_hazards
                        ],
                    },
                    deep=True,
                )
                for constraint in draft.security_constraints
            ],
            "risk_dispositions": [
                disposition.model_copy(
                    update={
                        "loss_ids": [
                            loss_map.get(reference, reference)
                            for reference in disposition.loss_ids
                        ]
                    },
                    deep=True,
                )
                for disposition in draft.risk_dispositions
            ],
        }
    )


def _merge_identity_records(
    records: Iterable[object],
    *,
    identity_field: str,
    record_label: str,
) -> list[object]:
    """Keep first-source order while collapsing exact identities safely."""
    result: list[object] = []
    seen: dict[str, object] = {}
    for record in records:
        identity = str(getattr(record, identity_field))
        previous = seen.get(identity)
        if previous is not None:
            if previous.model_dump(mode="json") != record.model_dump(mode="json"):
                raise ValueError(
                    f"conflicting duplicate {record_label} ID '{identity}'"
                )
            continue
        clone = record.model_copy(deep=True)
        seen[identity] = clone
        result.append(clone)
    return result


def _canonicalize_draft_losses(draft: LossAnalysisDraft) -> LossAnalysisDraft:
    """Return a source-separated, duplicate-free copy of one draft.

    ``LossAnalysisDraft`` retains the two provider-facing containers for
    compatibility, but provenance is the authority for which final source a
    loss belongs to.  Canonicalizing before the gap prompt keeps the model
    from reviewing the same loss twice and keeps the context's canonical
    references stable. A conflicting duplicate ID remains a hard diagnostic;
    silently choosing one payload would corrupt references.
    """
    risk_losses, use_case_losses = _normalize_losses(
        draft,
        LossAnalysisDraft(),
    )
    return draft.model_copy(
        update={
            "risk_card_losses": risk_losses,
            "use_case_losses": use_case_losses,
        }
    )


def _normalize_losses(
    risk_draft: LossAnalysisDraft,
    gap_draft: LossAnalysisDraft,
) -> tuple[list[Loss], list[Loss]]:
    """Classify and deduplicate losses from all draft containers.

    LLM responses sometimes place a valid ``Loss`` in the opposite draft
    container (for example, a risk-card loss in ``use_case_losses``).  The
    typed ``provenance`` is the source of truth for the final artifact.  A
    repeated record with the same ID and payload is tolerated, while a
    repeated ID with a different payload is ambiguous and fails explicitly
    before any IDs or references are mutated.
    """
    seen: dict[str, Loss] = {}
    unique_losses: list[Loss] = []
    sources = (
        ("risk_derivation.risk_card_losses", risk_draft.risk_card_losses),
        ("risk_derivation.use_case_losses", risk_draft.use_case_losses),
        ("gap_analysis.risk_card_losses", gap_draft.risk_card_losses),
        ("gap_analysis.use_case_losses", gap_draft.use_case_losses),
    )

    for source, losses in sources:
        for loss in losses:
            existing = seen.get(loss.loss_id)
            if existing is not None:
                if existing.model_dump(mode="json") != loss.model_dump(mode="json"):
                    raise ValueError(
                        f"conflicting duplicate loss ID '{loss.loss_id}' "
                        f"between {source} and an earlier draft container"
                    )
                continue

            normalized_loss = loss.model_copy(deep=True)
            seen[normalized_loss.loss_id] = normalized_loss
            unique_losses.append(normalized_loss)

    risk_losses = [
        loss for loss in unique_losses if loss.provenance == LossProvenance.risk_card
    ]
    use_case_losses = [
        loss for loss in unique_losses if loss.provenance != LossProvenance.risk_card
    ]
    return risk_losses, use_case_losses

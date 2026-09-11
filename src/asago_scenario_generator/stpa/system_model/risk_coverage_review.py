"""Advisory Stage 1a risk-coverage review (spec deviation 10).

After the five offline density checks pass on a derived loss analysis, one
bounded model call reviews the whole graph against the supplied risk cards
and records, per card, what the graph protects and what it leaves
unprotected.  The review is advisory: it never changes the graph, never
blocks a run, and is not a gate.  It runs after the gates and before
Stage 2, so a later production policy can let its verdicts inform the
bounded revision.  Pinned runs (``--loss-analysis``) skip it entirely,
because the supplied graph was already reviewed.

Deterministic code owns the wire.  The ``risk_id`` is a literal of the
supplied card ids and the covering constraints are literals of the supplied
constraint ids, so the provider cannot invent a record.  Every quotation
must be an exact substring of the record it cites.  Validation is per row:
a row that breaks a rule is recorded under ``rows_invalid`` with its typed
reason and the valid rows of the same batch are kept.  The status is
``completed`` when every card has a valid row, ``partial`` when any row is
invalid or missing, and ``unavailable`` only when no batch returned a valid
row.  Nothing is inferred or repaired, and the review never blocks a run.

Split rule (amended 2026-09-11, owner authorization): the advisory review
may issue at most four calls.  A response with one row of quotations per
card can approach the profile's ``max_completion_tokens``, so before the
first call the module sizes batches with the current per-row completion
estimate: ``max_completion_tokens // _ESTIMATED_TOKENS_PER_ROW`` cards per
batch (32 at the 8,192 cap), then distributes the supplied cards
deterministically across balanced contiguous batches in supplied order.
The four-call total is a ceiling, not a retry permission and not an
assumption that every response fits: a batch that fails or omits cards is
recorded with its typed reason, cards beyond what four capacity-sized
batches cover are recorded under ``rows_missing``, and no batch is ever
retried.  The artifact records the estimate inputs, the planned batch
sizes, and the conservative prompt-plus-row estimate per batch; that
conservative figure includes a prompt-share proxy for echo overhead and is
recorded for transparency, not used for sizing, because it cannot fit any
bounded batch on large graphs.  Both prompts carry identical instructions
and the full graph, and the merged rows keep the supplied card order.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    create_model,
    field_validator,
)

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    parse_llm_result,
    safe_llm_call,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    STAGE,
    STAGE1A_MAX_COMPLETION_TOKENS,
)
from asago_scenario_generator.stpa.system_model.semantic_review import (
    SourceEvidence,
    quote_is_substring,
)

STEP_RISK_COVERAGE_REVIEW = "risk_coverage_review"
ARTIFACT_FILENAME = "loss-analysis-risk-coverage-review.yaml"
SCHEMA_VERSION = "loss-analysis-risk-coverage-review-v3"

# Owner authorization 2026-09-11: the advisory review may issue at most four
# calls.  The ceiling is a call-limit policy constant, not a retry budget.
MAX_REVIEW_BATCHES = 4

SYSTEM_TEMPLATE = "stage1a_coverage_review_system.j2"
USER_TEMPLATE = "stage1a_coverage_review_user.j2"

STATUS_COMPLETED = "completed"
STATUS_PARTIAL = "partial"
STATUS_UNAVAILABLE = "unavailable"
STATUS_SKIPPED_PINNED = "skipped_pinned"

# Conservative, deterministic split estimate.  ``_CHARS_PER_TOKEN``
# overestimates tokens (prose is closer to four characters per token) and
# ``_ESTIMATED_TOKENS_PER_ROW`` covers one row's fields plus its quotations.
_CHARS_PER_TOKEN = 3
_ESTIMATED_TOKENS_PER_ROW = 250

CoverageVerdict = Literal[
    "full",
    "partial",
    "none",
    "not_applicable_confirmed",
    "not_applicable_disputed",
]
_NOT_APPLICABLE_VERDICTS = frozenset(
    {"not_applicable_confirmed", "not_applicable_disputed"}
)
_MISSING_PROTECTION_VERDICTS = frozenset({"partial", "none", "not_applicable_disputed"})
_EVIDENCE_PER_CONSTRAINT_VERDICTS = frozenset({"full", "partial"})


class RiskCoverageEvidence(SourceEvidence):
    """One exact quotation from a risk card, constraint, hazard, or loss.

    The shared :class:`SourceEvidence` restricts ``source_ref`` to the
    use-case text and loss ids.  The review cites risk cards, constraints,
    and hazards as well.  The provider schema closes ``source_ref`` to a
    literal of the exact ids supplied for the call, and deterministic
    validation confirms each reference resolves to a supplied record.
    """

    @field_validator("source_ref")
    @classmethod
    def restrict_source_ref_shape(cls, value: str) -> str:
        """Replace the loss-only shape check; the wire closes the id set."""
        if not value.strip():
            raise ValueError("risk coverage evidence source_ref must be nonblank")
        return value


class RiskCoverageRow(BaseModel):
    """One card's coverage verdict, with exact quotations.

    Every semantic rule is enforced by :func:`_row_invalid_reason` before a
    row is built, so this model stays a closed typed record: an invalid row
    is recorded under ``rows_invalid`` rather than raised.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    risk_id: StrictStr
    protects: StrictStr
    against: StrictStr | None = None
    covering_constraints: tuple[StrictStr, ...] = ()
    coverage: CoverageVerdict
    missing_protection: StrictStr | None = None
    evidence: tuple[RiskCoverageEvidence, ...] = ()
    rationale: StrictStr


# ---------------------------------------------------------------------------
# Provider wire shape
#
# The wire row carries types and the closed literal id sets only.  Every
# semantic rule lives in :func:`_row_invalid_reason`, which records an
# invalid row instead of failing the batch, so one bad row cannot discard
# the valid rows beside it (amended 2026-09-08, owner ruling at the fourth
# checkpoint 4 review).
# ---------------------------------------------------------------------------


class RiskCoverageWireEvidence(BaseModel):
    """Lenient provider evidence: ids are closed, the text rules are code's."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_ref: StrictStr
    quote: StrictStr = ""
    meaning: StrictStr = ""


class RiskCoverageWireRow(BaseModel):
    """Lenient provider row: the closed ids and the verdict vocabulary.

    Every semantic rule lives in :func:`_row_invalid_reason`, so a row that
    breaks one is recorded as invalid instead of failing the whole batch.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    risk_id: StrictStr
    protects: StrictStr = ""
    against: StrictStr | None = None
    covering_constraints: tuple[StrictStr, ...] = ()
    coverage: CoverageVerdict
    missing_protection: StrictStr | None = None
    evidence: tuple[RiskCoverageWireEvidence, ...] = ()
    rationale: StrictStr = ""


class RiskCoverageReview(BaseModel):
    """The provider response: zero or more rows for the supplied cards."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rows: tuple[RiskCoverageWireRow, ...] = ()


class RiskCoverageInvalidRow(BaseModel):
    """One row that failed a deterministic rule, with its typed reason."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    risk_id: StrictStr
    reason: StrictStr


class RiskCoverageReading(BaseModel):
    """One partial, none, or disputed row, for the owner's reading list."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    risk_id: StrictStr
    risk_name: StrictStr
    protects: StrictStr
    against: StrictStr | None = None
    covering_constraints: tuple[StrictStr, ...] = ()
    missing_protection: StrictStr | None = None


class RiskCoverageSummary(BaseModel):
    """Counts per verdict plus the owner's reading list."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    full: int = 0
    partial: int = 0
    none: int = 0
    not_applicable_confirmed: int = 0
    not_applicable_disputed: int = 0
    rows_valid: int = 0
    rows_invalid: int = 0
    rows_missing: int = 0
    reading_list: tuple[RiskCoverageReading, ...] = ()


class RiskCoverageBatching(BaseModel):
    """The deterministic four-call batch plan, recorded before any call.

    ``row_capacity`` is the sizing basis: the retained completion cap divided
    by the current per-row completion estimate.  The conservative
    prompt-plus-row estimate is recorded for transparency; it includes a
    prompt-share proxy for echo overhead and is deliberately not the sizing
    basis, because on large graphs no bounded batch can fit it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_batches: int
    max_completion_tokens: int
    chars_per_token_estimate: int
    estimated_tokens_per_row: int
    estimated_tokens_all_cards: int
    row_capacity: int
    planned_batch_sizes: tuple[int, ...]
    planned_batch_row_estimates: tuple[int, ...]
    planned_batch_conservative_estimates: tuple[int, ...]
    beyond_ceiling_cards: tuple[StrictStr, ...] = ()
    sizing_rule: StrictStr


class RiskCoverageArtifact(BaseModel):
    """The persisted ``loss-analysis-risk-coverage-review.yaml``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["loss-analysis-risk-coverage-review-v3"] = SCHEMA_VERSION
    reviewed_loss_analysis_digest: StrictStr
    risk_set_digest: StrictStr
    status: Literal["completed", "partial", "unavailable"]
    call_count: int
    failure_reason: StrictStr | None = None
    prompt_template_hashes: dict[StrictStr, StrictStr] = Field(default_factory=dict)
    batching: RiskCoverageBatching | None = None
    rows: tuple[RiskCoverageRow, ...] = ()
    rows_invalid: tuple[RiskCoverageInvalidRow, ...] = ()
    rows_missing: tuple[StrictStr, ...] = ()
    summary: RiskCoverageSummary = Field(default_factory=RiskCoverageSummary)


@dataclass(frozen=True)
class RiskCoverageReviewOutcome:
    """Manifest-facing outcome of the advisory review."""

    status: str
    call_count: int
    failure_reason: str | None = None
    reviewed_loss_analysis_digest: str | None = None
    artifact: RiskCoverageArtifact | None = None
    warnings: tuple[str, ...] = field(default=())


# ---------------------------------------------------------------------------
# Wire schema
# ---------------------------------------------------------------------------


def _provider_review_model(
    risk_ids: tuple[str, ...],
    constraint_ids: tuple[str, ...],
    evidence_refs: tuple[str, ...],
) -> type[RiskCoverageReview]:
    """Build the closed response schema for the supplied ids.

    ``risk_id`` is a literal of the supplied card ids, ``covering_constraints``
    holds literals of the supplied constraint ids, and ``source_ref`` is a
    literal of every citable record, so the provider cannot invent a record.
    The row count is deliberately unbounded: a response that omits a card is
    a batch result with missing rows, not a schema failure that discards the
    rows it did return.
    """
    row_type: type[RiskCoverageWireRow] = RiskCoverageWireRow
    if evidence_refs:
        evidence_type = create_model(
            "ProviderRiskCoverageEvidence",
            __base__=RiskCoverageWireEvidence,
            source_ref=(Literal[tuple(evidence_refs)], ...),
        )
        row_type = create_model(
            "ProviderRiskCoverageRowEvidence",
            __base__=row_type,
            evidence=(
                tuple[evidence_type, ...],  # type: ignore[valid-type]
                Field(default=()),
            ),
        )
    if risk_ids:
        row_type = create_model(
            "ProviderRiskCoverageRow",
            __base__=row_type,
            risk_id=(Literal[tuple(risk_ids)], ...),
        )
    if constraint_ids:
        row_type = create_model(
            f"{row_type.__name__}WithConstraints",
            __base__=row_type,
            covering_constraints=(
                tuple[Literal[tuple(constraint_ids)], ...],  # type: ignore[valid-type]
                Field(default=()),
            ),
        )
    return create_model(
        "ProviderRiskCoverageReview",
        __base__=RiskCoverageReview,
        rows=(
            tuple[row_type, ...],  # type: ignore[valid-type]
            Field(default=()),
        ),
    )


# ---------------------------------------------------------------------------
# Deterministic validation
# ---------------------------------------------------------------------------


def _record_texts(
    loss_analysis: LossAnalysis,
    risk_cards: list[RiskCard],
) -> dict[str, tuple[str, ...]]:
    """Return the exact quotable text of every citable record.

    A card quote must match one of its own name, description, or
    consequence; a constraint quote must match its rule or one of its
    ``applies_when`` conditions; a hazard or loss quote must match its
    description.
    """
    texts: dict[str, tuple[str, ...]] = {}
    for card in risk_cards:
        card_texts = [
            text
            for text in (card.risk_name, card.risk_description, card.consequence)
            if text
        ]
        texts[card.risk_id] = tuple(card_texts)
    for constraint in loss_analysis.security_constraints:
        texts[constraint.constraint_id] = (
            constraint.rule,
            *constraint.applies_when,
        )
    for hazard in loss_analysis.hazards:
        texts[hazard.hazard_id] = (hazard.description,)
    for loss in loss_analysis.risk_card_losses + loss_analysis.use_case_losses:
        texts[loss.loss_id] = (loss.description,)
    return texts


def _row_invalid_reason(
    row: RiskCoverageWireRow,
    *,
    supplied: set[str],
    texts: dict[str, tuple[str, ...]],
    constraint_ids: set[str],
    not_applicable: bool,
) -> str | None:
    """Return the typed reason a wire row is invalid, or ``None``.

    Code infers nothing: a ``none`` verdict on a ``not_applicable`` card is an
    invalid row with the reason ``not_applicable_card_reports_coverage``, not
    a disputed verdict.  The order of the checks fixes the recorded reason.
    """
    if row.risk_id not in supplied:
        return "unknown_risk_id"
    if not row.protects.strip():
        return "blank_protects"
    if not row.rationale.strip():
        return "blank_rationale"
    if row.against is not None and not row.against.strip():
        return "blank_against"
    if len(set(row.covering_constraints)) != len(row.covering_constraints):
        return "repeated_covering_constraint"
    unknown_constraints = sorted(set(row.covering_constraints) - constraint_ids)
    if unknown_constraints:
        return "unknown_covering_constraint"
    if not_applicable and row.coverage not in _NOT_APPLICABLE_VERDICTS:
        return "not_applicable_card_reports_coverage"
    if not not_applicable and row.coverage in _NOT_APPLICABLE_VERDICTS:
        return "cited_card_reports_not_applicable"
    if row.coverage in _MISSING_PROTECTION_VERDICTS:
        if row.missing_protection is None or not row.missing_protection.strip():
            return "missing_protection_required"
    elif row.missing_protection is not None:
        return "missing_protection_forbidden"
    if row.coverage == "full" and not row.covering_constraints:
        return "full_without_covering_constraint"
    if row.coverage == "none" and row.covering_constraints:
        return "none_with_covering_constraint"
    if not row.evidence:
        return "no_evidence"
    if not any(item.source_ref == row.risk_id for item in row.evidence):
        return "no_own_card_quote"
    if row.coverage in _EVIDENCE_PER_CONSTRAINT_VERDICTS:
        quoted_refs = {item.source_ref for item in row.evidence}
        for constraint_id in row.covering_constraints:
            if constraint_id not in quoted_refs:
                return "no_covering_constraint_quote"
    for item in row.evidence:
        sources = texts.get(item.source_ref)
        if sources is None:
            return "unknown_evidence_source_ref"
        if not item.quote.strip() or not quote_is_substring(item.quote, sources):
            return "quote_not_a_substring"
    return None


def _to_row(row: RiskCoverageWireRow) -> RiskCoverageRow:
    """Convert a validated wire row into the artifact row."""
    return RiskCoverageRow(
        risk_id=row.risk_id,
        protects=row.protects,
        against=row.against,
        covering_constraints=row.covering_constraints,
        coverage=row.coverage,
        missing_protection=row.missing_protection,
        evidence=tuple(
            RiskCoverageEvidence(
                source_ref=item.source_ref,
                quote=item.quote,
                meaning=item.meaning or item.source_ref,
            )
            for item in row.evidence
        ),
        rationale=row.rationale,
    )


def _not_applicable_cards(
    loss_analysis: LossAnalysis,
    risk_cards: list[RiskCard],
) -> set[str]:
    """Return the supplied cards the analysis records as not applicable."""
    dispositions = {d.risk_ref: d for d in loss_analysis.risk_dispositions}
    cited_via_losses = {
        risk_ref
        for loss in loss_analysis.risk_card_losses + loss_analysis.use_case_losses
        for risk_ref in loss.source_risk_cards
    }
    return {
        card.risk_id
        for card in risk_cards
        if (
            dispositions.get(card.risk_id) is not None
            and dispositions[card.risk_id].disposition == "not_applicable"
        )
        or (
            dispositions.get(card.risk_id) is None
            and card.risk_id not in cited_via_losses
        )
    }


def _partition_rows(
    rows: tuple[RiskCoverageWireRow, ...],
    *,
    loss_analysis: LossAnalysis,
    risk_cards: list[RiskCard],
) -> tuple[
    tuple[RiskCoverageRow, ...], tuple[RiskCoverageInvalidRow, ...], tuple[str, ...]
]:
    """Split merged wire rows into valid rows, invalid rows, and missing cards.

    A card whose row failed a rule is invalid, not missing: ``rows_missing``
    lists only the cards no batch returned a row for.  Duplicate rows for one
    card keep the first and record the rest as invalid.
    """
    supplied = {card.risk_id for card in risk_cards}
    texts = _record_texts(loss_analysis, risk_cards)
    constraint_ids = {sc.constraint_id for sc in loss_analysis.security_constraints}
    not_applicable = _not_applicable_cards(loss_analysis, risk_cards)
    valid: list[RiskCoverageRow] = []
    invalid: list[RiskCoverageInvalidRow] = []
    returned: set[str] = set()
    seen: set[str] = set()
    for row in rows:
        returned.add(row.risk_id)
        if row.risk_id in seen:
            invalid.append(
                RiskCoverageInvalidRow(risk_id=row.risk_id, reason="repeated_risk_id")
            )
            continue
        reason = _row_invalid_reason(
            row,
            supplied=supplied,
            texts=texts,
            constraint_ids=constraint_ids,
            not_applicable=row.risk_id in not_applicable,
        )
        if reason is not None:
            invalid.append(RiskCoverageInvalidRow(risk_id=row.risk_id, reason=reason))
            continue
        seen.add(row.risk_id)
        valid.append(_to_row(row))
    order = {card.risk_id: index for index, card in enumerate(risk_cards)}
    valid.sort(key=lambda item: order.get(item.risk_id, len(order)))
    invalid.sort(key=lambda item: (order.get(item.risk_id, len(order)), item.reason))
    missing = tuple(card.risk_id for card in risk_cards if card.risk_id not in returned)
    return tuple(valid), tuple(invalid), missing


# ---------------------------------------------------------------------------
# Split estimate and batch plan
# ---------------------------------------------------------------------------


def estimated_review_tokens(
    system_prompt: str,
    user_prompt: str,
    card_count: int,
) -> int:
    """Return the conservative completion estimate for one review call."""
    prompt_tokens = (len(system_prompt) + len(user_prompt)) // _CHARS_PER_TOKEN
    return prompt_tokens + _ESTIMATED_TOKENS_PER_ROW * card_count


def should_split_review(
    system_prompt: str,
    user_prompt: str,
    card_count: int,
    *,
    max_completion_tokens: int,
) -> bool:
    """Return whether the conservative estimate exceeds the completion cap.

    The advisory review sizes batches from the per-row estimate (see
    :func:`plan_review_batches`); this predicate reports the historical
    conservative trigger, prompt share plus rows, and is recorded with the
    batch plan for transparency.
    """
    if card_count < 2:
        return False
    return (
        estimated_review_tokens(system_prompt, user_prompt, card_count)
        > max_completion_tokens
    )


@dataclass(frozen=True)
class ReviewBatchPlan:
    """The deterministic distribution of cards across bounded batches."""

    batches: tuple[tuple[RiskCard, ...], ...]
    batching: RiskCoverageBatching
    beyond_ceiling_cards: tuple[str, ...]


def plan_review_batches(
    *,
    system_prompt: str,
    probe_user_prompt: str,
    base_user_prompt: str,
    risk_cards: list[RiskCard],
    max_completion_tokens: int,
    max_batches: int = MAX_REVIEW_BATCHES,
) -> ReviewBatchPlan:
    """Distribute the cards deterministically across batches that fit.

    Sizing uses the current per-row completion estimate: at most
    ``max_completion_tokens // _ESTIMATED_TOKENS_PER_ROW`` cards per batch
    (32 at the 8,192 cap), in balanced contiguous batches that preserve the
    supplied card order.  When more batches than the ceiling would be
    needed, the cards beyond four capacity-sized batches are recorded as
    beyond the ceiling and are reported missing rather than silently
    dropped or squeezed into oversized batches.
    """
    total = len(risk_cards)
    row_capacity = max(1, max_completion_tokens // _ESTIMATED_TOKENS_PER_ROW)
    needed = -(-total // row_capacity)  # ceil division
    batch_count = min(needed, max_batches)
    covered = min(total, batch_count * row_capacity)
    beyond = tuple(card.risk_id for card in risk_cards[covered:])
    sizes = [
        covered // batch_count + (1 if index < covered % batch_count else 0)
        for index in range(batch_count)
    ]
    batches: list[tuple[RiskCard, ...]] = []
    cursor = 0
    for size in sizes:
        batches.append(tuple(risk_cards[cursor : cursor + size]))
        cursor += size

    per_card_chars = (
        (len(probe_user_prompt) - len(base_user_prompt)) / total if total else 0.0
    )
    row_estimates: list[int] = []
    conservative: list[int] = []
    for size in sizes:
        row_estimates.append(_ESTIMATED_TOKENS_PER_ROW * size)
        batch_chars = len(base_user_prompt) + per_card_chars * size
        conservative.append(
            (len(system_prompt) + int(batch_chars)) // _CHARS_PER_TOKEN
            + _ESTIMATED_TOKENS_PER_ROW * size
        )
    batching = RiskCoverageBatching(
        max_batches=max_batches,
        max_completion_tokens=max_completion_tokens,
        chars_per_token_estimate=_CHARS_PER_TOKEN,
        estimated_tokens_per_row=_ESTIMATED_TOKENS_PER_ROW,
        estimated_tokens_all_cards=estimated_review_tokens(
            system_prompt, probe_user_prompt, total
        ),
        row_capacity=row_capacity,
        planned_batch_sizes=tuple(sizes),
        planned_batch_row_estimates=tuple(row_estimates),
        planned_batch_conservative_estimates=tuple(conservative),
        beyond_ceiling_cards=tuple(beyond),
        sizing_rule=(
            "cards per batch = max_completion_tokens // estimated_tokens_per_row "
            "(the current per-row completion estimate); balanced contiguous "
            "batches in supplied card order; at most max_batches calls; the "
            "conservative prompt-plus-row estimate is recorded for "
            "transparency and is not the sizing basis"
        ),
    )
    return ReviewBatchPlan(
        batches=tuple(batches),
        batching=batching,
        beyond_ceiling_cards=beyond,
    )


# ---------------------------------------------------------------------------
# Summary and artifact
# ---------------------------------------------------------------------------


def _summarize(
    rows: tuple[RiskCoverageRow, ...],
    *,
    risk_cards: list[RiskCard],
    invalid_count: int = 0,
    missing_count: int = 0,
) -> RiskCoverageSummary:
    """Count verdicts and build the reading list in supplied card order."""
    names = {card.risk_id: card.risk_name for card in risk_cards}
    counts = {
        "full": 0,
        "partial": 0,
        "none": 0,
        "not_applicable_confirmed": 0,
        "not_applicable_disputed": 0,
    }
    reading: list[RiskCoverageReading] = []
    for row in rows:
        counts[row.coverage] += 1
        if row.coverage in _MISSING_PROTECTION_VERDICTS:
            reading.append(
                RiskCoverageReading(
                    risk_id=row.risk_id,
                    risk_name=names.get(row.risk_id, ""),
                    protects=row.protects,
                    against=row.against,
                    covering_constraints=row.covering_constraints,
                    missing_protection=row.missing_protection,
                )
            )
    return RiskCoverageSummary(
        full=counts["full"],
        partial=counts["partial"],
        none=counts["none"],
        not_applicable_confirmed=counts["not_applicable_confirmed"],
        not_applicable_disputed=counts["not_applicable_disputed"],
        rows_valid=len(rows),
        rows_invalid=invalid_count,
        rows_missing=missing_count,
        reading_list=tuple(reading),
    )


def _atomic_write_yaml(model: BaseModel, path: Path) -> Path:
    """Write *model* as YAML atomically, keeping explicit nulls.

    The shared ``write_yaml`` drops ``None`` fields; the artifact contract
    requires explicit ``null`` for ``failure_reason``, ``against``, and
    ``missing_protection``, so this writer dumps the full JSON-mode mapping.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = yaml.dump(
        model.model_dump(mode="json"),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, suffix=".tmp", prefix=path.name
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return path


def _write_artifact(
    run_dir: Path,
    *,
    reviewed_loss_analysis_digest: str,
    risk_set_digest: str,
    status: str,
    call_count: int,
    failure_reason: str | None,
    prompt_template_hashes: dict[str, str],
    batching: RiskCoverageBatching | None = None,
    rows: tuple[RiskCoverageRow, ...] = (),
    rows_invalid: tuple[RiskCoverageInvalidRow, ...] = (),
    rows_missing: tuple[str, ...] = (),
    summary: RiskCoverageSummary | None = None,
) -> RiskCoverageArtifact:
    """Persist the review artifact and return it."""
    artifact = RiskCoverageArtifact(
        reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
        risk_set_digest=risk_set_digest,
        status=(
            status
            if status in (STATUS_COMPLETED, STATUS_PARTIAL)
            else STATUS_UNAVAILABLE
        ),
        call_count=call_count,
        failure_reason=failure_reason,
        prompt_template_hashes=prompt_template_hashes,
        batching=batching,
        rows=rows,
        rows_invalid=rows_invalid,
        rows_missing=rows_missing,
        summary=summary or RiskCoverageSummary(),
    )
    _atomic_write_yaml(artifact, run_dir / ARTIFACT_FILENAME)
    return artifact


def risk_set_digest(risk_cards: list[RiskCard]) -> str:
    """Return the digest of the supplied risk-card identity set."""
    joined = ",".join(card.risk_id for card in risk_cards)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def canonical_graph_digest(run_dir: Path) -> str | None:
    """Return the SHA-256 of the persisted ``loss-analysis.yaml`` bytes.

    The manifest compares this final published digest with the digest the
    review recorded.  A missing file returns ``None`` rather than raising.
    """
    path = run_dir / "loss-analysis.yaml"
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def graph_digest(loss_analysis: LossAnalysis) -> str:
    """Return the SHA-256 of the bytes ``write_yaml`` would persist.

    The review is content-pinned to the exact gated graph it read.  Hashing
    the canonical serialization of that in-memory graph avoids publishing an
    intermediate file: in target-derived mode Stage 2 writes the same object,
    so the file digest matches; in target-blind mode Call 3 may reword the
    graph, and the manifest records the difference.
    """
    payload = yaml.dump(
        loss_analysis.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _review_prompt_hashes(loader: TemplateLoader) -> dict[str, str]:
    hashes = loader.hash_prompt_templates()
    return {
        name: hashes[name]
        for name in (SYSTEM_TEMPLATE, USER_TEMPLATE)
        if name in hashes
    }


def _card_view(card: RiskCard, loss_analysis: LossAnalysis) -> dict:
    disposition = next(
        (d for d in loss_analysis.risk_dispositions if d.risk_ref == card.risk_id),
        None,
    )
    citing = sorted(
        {
            loss.loss_id
            for loss in loss_analysis.risk_card_losses + loss_analysis.use_case_losses
            if card.risk_id in loss.source_risk_cards
        }
    )
    if disposition is not None:
        disposition_kind = disposition.disposition
        disposition_reason = disposition.reason
    elif citing:
        disposition_kind = "cited"
        disposition_reason = None
    else:
        disposition_kind = "unaccounted"
        disposition_reason = None
    return {
        "risk_id": card.risk_id,
        "risk_name": card.risk_name,
        "risk_description": card.risk_description,
        "consequence": card.consequence,
        "disposition": disposition_kind,
        "disposition_reason": disposition_reason,
        "citing_loss_ids": citing,
    }


def _run_one_review_call(
    *,
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    cards: list[RiskCard],
    use_case_text: str,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    max_completion_tokens: int,
) -> tuple[tuple[RiskCoverageWireRow, ...] | None, str | None]:
    """Make one review call and return its wire rows or a typed failure reason.

    The call validates only the closed wire shape (ids and vocabulary).  Every
    semantic rule is applied per row afterwards, so an invalid row cannot
    discard the valid rows beside it.
    """
    system_prompt = loader.render_prompt(SYSTEM_TEMPLATE)
    user_prompt = loader.render_prompt(
        USER_TEMPLATE,
        use_case_text=use_case_text,
        risk_cards=[_card_view(card, loss_analysis) for card in cards],
        losses=loss_analysis.risk_card_losses + loss_analysis.use_case_losses,
        hazards=loss_analysis.hazards,
        security_constraints=loss_analysis.security_constraints,
    )
    risk_ids = tuple(card.risk_id for card in cards)
    constraint_ids = tuple(
        sc.constraint_id for sc in loss_analysis.security_constraints
    )
    evidence_refs = (
        risk_ids
        + constraint_ids
        + tuple(hazard.hazard_id for hazard in loss_analysis.hazards)
        + tuple(
            loss.loss_id
            for loss in loss_analysis.risk_card_losses + loss_analysis.use_case_losses
        )
    )
    response_model = _provider_review_model(risk_ids, constraint_ids, evidence_refs)

    def parse_review(result: LLMResult) -> RiskCoverageReview:
        return parse_llm_result(result, response_model)

    review, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_model,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_RISK_COVERAGE_REVIEW,
        temperature=temperature,
        max_completion_tokens=max_completion_tokens,
        result_parser=parse_review,
        prompt_template_hashes=_review_prompt_hashes(loader),
    )
    if error_msg is not None or review is None:
        return None, error_msg or "risk coverage review returned no result"
    return tuple(review.rows), None


def run_risk_coverage_review(
    *,
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    risk_cards: list[RiskCard],
    use_case_text: str,
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
    reviewed_loss_analysis_digest: str,
    max_completion_tokens: int | None = None,
) -> RiskCoverageReviewOutcome:
    """Run the advisory review and always persist its artifact.

    The review plans its batches up front from the per-row completion
    estimate (at most four calls; see :data:`MAX_REVIEW_BATCHES`) and never
    retries a failed batch.  Every planned batch is issued regardless of
    earlier batches.  Validation is per row: an invalid row is recorded
    under ``rows_invalid`` with its typed reason and the valid rows of the
    same batch are kept.  The status is ``completed`` when every card has a
    valid row, ``partial`` when any row is invalid or missing, and
    ``unavailable`` only when no batch returned a valid row.  The review
    never raises and never blocks the run.
    """
    budget = (
        max_completion_tokens
        if max_completion_tokens is not None
        else STAGE1A_MAX_COMPLETION_TOKENS
    )
    digest = risk_set_digest(risk_cards)
    prompt_hashes = _review_prompt_hashes(template_loader)

    if not risk_cards:
        artifact = _write_artifact(
            run_dir,
            reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
            risk_set_digest=digest,
            status=STATUS_COMPLETED,
            call_count=0,
            failure_reason=None,
            prompt_template_hashes=prompt_hashes,
        )
        return RiskCoverageReviewOutcome(
            status=STATUS_COMPLETED,
            call_count=0,
            reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
            artifact=artifact,
        )

    system_prompt = template_loader.render_prompt(SYSTEM_TEMPLATE)

    def _render_user_prompt(cards: list[RiskCard]) -> str:
        return template_loader.render_prompt(
            USER_TEMPLATE,
            use_case_text=use_case_text,
            risk_cards=[_card_view(card, loss_analysis) for card in cards],
            losses=loss_analysis.risk_card_losses + loss_analysis.use_case_losses,
            hazards=loss_analysis.hazards,
            security_constraints=loss_analysis.security_constraints,
        )

    plan = plan_review_batches(
        system_prompt=system_prompt,
        probe_user_prompt=_render_user_prompt(risk_cards),
        base_user_prompt=_render_user_prompt([]),
        risk_cards=risk_cards,
        max_completion_tokens=budget,
    )
    groups = [list(batch) for batch in plan.batches]

    merged: list[RiskCoverageWireRow] = []
    failures: list[str] = []
    call_count = 0
    for group in groups:
        call_count += 1
        rows, failure_reason = _run_one_review_call(
            llm_client=llm_client,
            loss_analysis=loss_analysis,
            cards=group,
            use_case_text=use_case_text,
            run_dir=run_dir,
            loader=template_loader,
            temperature=temperature,
            max_completion_tokens=budget,
        )
        if rows is None:
            failures.append(failure_reason or "risk coverage review returned no result")
            continue
        merged.extend(rows)
        # A batch that omits one of its cards is a batch failure with a typed
        # reason, even though its other rows survive per-row validation.
        returned = {row.risk_id for row in rows}
        omitted = [card.risk_id for card in group if card.risk_id not in returned]
        if omitted:
            failures.append("batch_omitted_cards: " + ", ".join(sorted(omitted)))
    if plan.beyond_ceiling_cards:
        failures.append(
            "cards_beyond_four_call_ceiling: " + ", ".join(plan.beyond_ceiling_cards)
        )

    valid, invalid, missing = _partition_rows(
        tuple(merged),
        loss_analysis=loss_analysis,
        risk_cards=risk_cards,
    )
    summary = _summarize(
        valid,
        risk_cards=risk_cards,
        invalid_count=len(invalid),
        missing_count=len(missing),
    )
    if valid and not invalid and not missing and not failures:
        status = STATUS_COMPLETED
        failure_reason = None
    elif valid:
        status = STATUS_PARTIAL
        failure_reason = "; ".join(failures) if failures else None
    else:
        status = STATUS_UNAVAILABLE
        failure_reason = "; ".join(failures) or "no risk coverage row passed validation"

    artifact = _write_artifact(
        run_dir,
        reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
        risk_set_digest=digest,
        status=status,
        call_count=call_count,
        failure_reason=failure_reason,
        prompt_template_hashes=prompt_hashes,
        batching=plan.batching,
        rows=valid,
        rows_invalid=invalid,
        rows_missing=missing,
        summary=summary,
    )
    return RiskCoverageReviewOutcome(
        status=status,
        call_count=call_count,
        failure_reason=failure_reason,
        reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
        artifact=artifact,
    )

"""Advisory Stage 1a risk-coverage review (spec deviation 10).

After the five offline density checks pass on a derived loss analysis, one
bounded model call reviews the whole graph against the supplied risk cards
and records, per card, what the graph protects and what it leaves
unprotected.  The review is advisory: it never changes the graph, never
blocks a run, and is not a gate.  It runs after the gates and before
Stage 2, so a later production policy can let its verdicts inform the
bounded revision.  Pinned runs (``--loss-analysis``) skip it entirely,
because the supplied graph was already reviewed.

Deterministic code owns the wire.  Every row is a closed typed record; the
``risk_id`` is a literal of the supplied card ids and the covering
constraints are literals of the supplied constraint ids, so the provider
cannot invent, drop, or duplicate a card.  Every quotation must be an exact
substring of the record it cites.  Nothing is inferred or repaired: a wire
or validation failure marks the review ``unavailable`` with a typed reason
and the run continues.

Split rule (decided up front, never from a failed attempt).  A response
with one row of quotations per card can approach the profile's
``max_completion_tokens``.  Before the first call the module estimates the
completion as the rendered prompt length in tokens plus
``_ESTIMATED_TOKENS_PER_ROW`` per card and splits the cards into two calls
when the estimate exceeds the caller's ``max_completion_tokens`` (8,192 for
the gemma4-oc profile).  Both calls carry identical instructions and the
full graph, and the merged rows keep the supplied card order.  The module
never splits more than twice and never retries a failed call.
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
    model_validator,
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
SCHEMA_VERSION = "loss-analysis-risk-coverage-review-v1"

SYSTEM_TEMPLATE = "stage1a_coverage_review_system.j2"
USER_TEMPLATE = "stage1a_coverage_review_user.j2"

STATUS_COMPLETED = "completed"
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
    """One card's coverage verdict, with exact quotations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    risk_id: StrictStr
    protects: StrictStr = Field(
        min_length=1,
        description="What the risk says is at stake, in the reviewer's words.",
    )
    against: StrictStr | None = Field(
        default=None,
        description="The actor or path the card names, or null when it names none.",
    )
    covering_constraints: tuple[StrictStr, ...] = Field(
        default=(),
        description="Supplied SC-* ids whose rules protect this card's stake.",
    )
    coverage: CoverageVerdict
    missing_protection: StrictStr | None = Field(
        default=None,
        description="The specific protection no listed constraint provides.",
    )
    evidence: tuple[RiskCoverageEvidence, ...] = Field(default=())
    rationale: StrictStr = Field(min_length=1)

    @model_validator(mode="after")
    def validate_verdict_shape(self) -> RiskCoverageRow:
        if len(set(self.covering_constraints)) != len(self.covering_constraints):
            raise ValueError(
                f"risk coverage row {self.risk_id} repeats a covering constraint"
            )
        if not self.protects.strip():
            raise ValueError(
                f"risk coverage row {self.risk_id} requires nonblank protects"
            )
        if not self.rationale.strip():
            raise ValueError(
                f"risk coverage row {self.risk_id} requires nonblank rationale"
            )
        if self.against is not None and not self.against.strip():
            raise ValueError(
                f"risk coverage row {self.risk_id} against must be null or nonblank"
            )
        needs_missing = self.coverage in _MISSING_PROTECTION_VERDICTS
        if needs_missing:
            if self.missing_protection is None or not self.missing_protection.strip():
                raise ValueError(
                    f"risk coverage row {self.risk_id} coverage {self.coverage} "
                    "requires a nonblank missing_protection"
                )
        elif self.missing_protection is not None:
            raise ValueError(
                f"risk coverage row {self.risk_id} coverage {self.coverage} "
                "must leave missing_protection null"
            )
        if self.coverage == "full" and not self.covering_constraints:
            raise ValueError(
                f"risk coverage row {self.risk_id} coverage full requires at "
                "least one covering constraint"
            )
        if self.coverage == "none" and self.covering_constraints:
            raise ValueError(
                f"risk coverage row {self.risk_id} coverage none requires no "
                "covering constraint"
            )
        if not self.evidence:
            raise ValueError(
                f"risk coverage row {self.risk_id} requires at least one "
                "quotation from its own risk card"
            )
        own_quotes = [item for item in self.evidence if item.source_ref == self.risk_id]
        if not own_quotes:
            raise ValueError(
                f"risk coverage row {self.risk_id} requires at least one "
                "quotation whose source_ref is its own risk_id"
            )
        if self.coverage in _EVIDENCE_PER_CONSTRAINT_VERDICTS:
            quoted_refs = {item.source_ref for item in self.evidence}
            for constraint_id in self.covering_constraints:
                if constraint_id not in quoted_refs:
                    raise ValueError(
                        f"risk coverage row {self.risk_id} coverage "
                        f"{self.coverage} requires a quotation from covering "
                        f"constraint {constraint_id}"
                    )
        return self


class RiskCoverageReview(BaseModel):
    """One row per supplied risk card."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rows: tuple[RiskCoverageRow, ...]


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
    reading_list: tuple[RiskCoverageReading, ...] = ()


class RiskCoverageArtifact(BaseModel):
    """The persisted ``loss-analysis-risk-coverage-review.yaml``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["loss-analysis-risk-coverage-review-v1"] = SCHEMA_VERSION
    reviewed_loss_analysis_digest: StrictStr
    risk_set_digest: StrictStr
    status: Literal["completed", "unavailable"]
    call_count: int
    failure_reason: StrictStr | None = None
    prompt_template_hashes: dict[StrictStr, StrictStr] = Field(default_factory=dict)
    rows: tuple[RiskCoverageRow, ...] = ()
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
    """
    row_type: type[RiskCoverageRow] = RiskCoverageRow
    if evidence_refs:
        evidence_type = create_model(
            "ProviderRiskCoverageEvidence",
            __base__=RiskCoverageEvidence,
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
            Field(min_length=len(risk_ids), max_length=len(risk_ids)),
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


def _validate_quotes(
    review: RiskCoverageReview,
    *,
    texts: dict[str, tuple[str, ...]],
) -> None:
    """Fail closed on an unknown source_ref or a non-substring quote."""
    for row in review.rows:
        for item in row.evidence:
            sources = texts.get(item.source_ref)
            if sources is None:
                raise ValueError(
                    f"risk coverage row {row.risk_id} cites unknown source_ref "
                    f"{item.source_ref}"
                )
            if not quote_is_substring(item.quote, sources):
                raise ValueError(
                    f"risk coverage row {row.risk_id} quote is not an exact "
                    f"substring of {item.source_ref}"
                )


def _validate_rows_against_cards(
    review: RiskCoverageReview,
    *,
    loss_analysis: LossAnalysis,
    risk_cards: list[RiskCard],
) -> None:
    """Validate exact coverage of the supplied cards and verdict consistency."""
    supplied = [card.risk_id for card in risk_cards]
    rows_by_id = {row.risk_id: row for row in review.rows}
    if len(rows_by_id) != len(review.rows):
        raise ValueError("risk coverage review repeats a risk card row")
    if set(rows_by_id) != set(supplied):
        missing = sorted(set(supplied) - set(rows_by_id))
        unknown = sorted(set(rows_by_id) - set(supplied))
        raise ValueError(
            "risk coverage review must cover each supplied risk card exactly "
            f"once (missing {missing}, unknown {unknown})"
        )

    dispositions = {d.risk_ref: d for d in loss_analysis.risk_dispositions}
    cited_via_losses = {
        risk_ref
        for loss in loss_analysis.risk_card_losses + loss_analysis.use_case_losses
        for risk_ref in loss.source_risk_cards
    }
    constraint_ids = {sc.constraint_id for sc in loss_analysis.security_constraints}
    for card_id in supplied:
        row = rows_by_id[card_id]
        disposition = dispositions.get(card_id)
        not_applicable = (
            disposition is not None and disposition.disposition == "not_applicable"
        ) or (disposition is None and card_id not in cited_via_losses)
        if not_applicable and row.coverage not in _NOT_APPLICABLE_VERDICTS:
            raise ValueError(
                f"risk coverage row {card_id} is not_applicable in the analysis "
                f"but reports coverage {row.coverage}"
            )
        if not not_applicable and row.coverage in _NOT_APPLICABLE_VERDICTS:
            raise ValueError(
                f"risk coverage row {card_id} is cited in the analysis but "
                f"reports coverage {row.coverage}"
            )
        unknown_constraints = sorted(set(row.covering_constraints) - constraint_ids)
        if unknown_constraints:
            raise ValueError(
                f"risk coverage row {card_id} names unknown covering "
                "constraint(s): " + ", ".join(unknown_constraints)
            )
    _validate_quotes(
        review,
        texts=_record_texts(loss_analysis, risk_cards),
    )


# ---------------------------------------------------------------------------
# Split estimate
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
    """Return whether the cards must be split across two review calls."""
    if card_count < 2:
        return False
    return (
        estimated_review_tokens(system_prompt, user_prompt, card_count)
        > max_completion_tokens
    )


# ---------------------------------------------------------------------------
# Summary and artifact
# ---------------------------------------------------------------------------


def _summarize(
    rows: tuple[RiskCoverageRow, ...],
    *,
    risk_cards: list[RiskCard],
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
    rows: tuple[RiskCoverageRow, ...] = (),
    summary: RiskCoverageSummary | None = None,
) -> RiskCoverageArtifact:
    """Persist the review artifact and return it."""
    artifact = RiskCoverageArtifact(
        reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
        risk_set_digest=risk_set_digest,
        status="completed" if status == STATUS_COMPLETED else STATUS_UNAVAILABLE,
        call_count=call_count,
        failure_reason=failure_reason,
        prompt_template_hashes=prompt_template_hashes,
        rows=rows,
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
) -> tuple[RiskCoverageReview | None, str | None]:
    """Make one review call and return its validated rows or a typed reason."""
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

    def validate_review(review: RiskCoverageReview) -> None:
        _validate_rows_against_cards(
            review,
            loss_analysis=loss_analysis,
            risk_cards=cards,
        )

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
        result_validator=validate_review,
        prompt_template_hashes=_review_prompt_hashes(loader),
    )
    if error_msg is not None or review is None:
        return None, error_msg or "risk coverage review returned no result"
    return review, None


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

    The review makes one bounded call (two when the conservative estimate
    exceeds ``max_completion_tokens``), with zero retries.  Any failure
    marks the review ``unavailable`` with the typed reason; it never raises
    and never blocks the run.
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
    probe_prompt = template_loader.render_prompt(
        USER_TEMPLATE,
        use_case_text=use_case_text,
        risk_cards=[_card_view(card, loss_analysis) for card in risk_cards],
        losses=loss_analysis.risk_card_losses + loss_analysis.use_case_losses,
        hazards=loss_analysis.hazards,
        security_constraints=loss_analysis.security_constraints,
    )
    split = should_split_review(
        system_prompt,
        probe_prompt,
        len(risk_cards),
        max_completion_tokens=budget,
    )
    groups = (
        [risk_cards[: len(risk_cards) // 2], risk_cards[len(risk_cards) // 2 :]]
        if split
        else [risk_cards]
    )

    merged: list[RiskCoverageRow] = []
    call_count = 0
    for group in groups:
        call_count += 1
        review, failure_reason = _run_one_review_call(
            llm_client=llm_client,
            loss_analysis=loss_analysis,
            cards=group,
            use_case_text=use_case_text,
            run_dir=run_dir,
            loader=template_loader,
            temperature=temperature,
            max_completion_tokens=budget,
        )
        if review is None:
            artifact = _write_artifact(
                run_dir,
                reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
                risk_set_digest=digest,
                status=STATUS_UNAVAILABLE,
                call_count=call_count,
                failure_reason=failure_reason,
                prompt_template_hashes=prompt_hashes,
            )
            return RiskCoverageReviewOutcome(
                status=STATUS_UNAVAILABLE,
                call_count=call_count,
                failure_reason=failure_reason,
                reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
                artifact=artifact,
            )
        merged.extend(review.rows)

    order = {card.risk_id: index for index, card in enumerate(risk_cards)}
    rows = tuple(sorted(merged, key=lambda row: order.get(row.risk_id, len(order))))
    merged_review = RiskCoverageReview(rows=rows)
    try:
        _validate_rows_against_cards(
            merged_review,
            loss_analysis=loss_analysis,
            risk_cards=risk_cards,
        )
    except ValueError as exc:
        failure_reason = f"ValueError: {exc}"
        artifact = _write_artifact(
            run_dir,
            reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
            risk_set_digest=digest,
            status=STATUS_UNAVAILABLE,
            call_count=call_count,
            failure_reason=failure_reason,
            prompt_template_hashes=prompt_hashes,
        )
        return RiskCoverageReviewOutcome(
            status=STATUS_UNAVAILABLE,
            call_count=call_count,
            failure_reason=failure_reason,
            reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
            artifact=artifact,
        )

    summary = _summarize(rows, risk_cards=risk_cards)
    artifact = _write_artifact(
        run_dir,
        reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
        risk_set_digest=digest,
        status=STATUS_COMPLETED,
        call_count=call_count,
        failure_reason=None,
        prompt_template_hashes=prompt_hashes,
        rows=rows,
        summary=summary,
    )
    return RiskCoverageReviewOutcome(
        status=STATUS_COMPLETED,
        call_count=call_count,
        reviewed_loss_analysis_digest=reviewed_loss_analysis_digest,
        artifact=artifact,
    )

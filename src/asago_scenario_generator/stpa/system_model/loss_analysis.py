"""Stage 1a — Loss Analysis derivation (two sequential LLM calls).

Call 1 (risk_derivation): derives losses, hazards, and security constraints
from organizational risk cards.

Call 2 (gap_analysis): reviews the use-case description against Call 1's
output to find missing adversary-actionable losses.  Receives the capability
profile as additional input for systematic coverage checking.

IDs (loss/hazard/SC) continue sequentially across the two calls with no
duplicates; cross-references stay valid after merge.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    build_kc_subcodes_display,
)
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    parse_llm_result,
    safe_llm_call,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    LossAnalysis,
    LossAnalysisDraft,
    Loss,
    LossProvenance,
    Obligation,
    RiskDisposition,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    DeterministicCleanup,
    RepairPlan,
    UnsupportedRepair,
    build_repair_plan,
    run_targeted_repair,
)

STAGE = "stage_1a"
STEP_RISK = "risk_derivation"
STEP_GAP = "gap_analysis"
STEP_MERGE = "merge"
JSON_DECODE_RETRIES = 1
STAGE1A_MAX_COMPLETION_TOKENS = 8192
DEFAULT_TEMPERATURE = 0.4


class _ProviderSecurityConstraint(SecurityConstraint):
    """Provider wire constraint: authored rule and conditions are required.

    Phase 1.3 as amended: the model writes ``rule`` and ``applies_when``;
    code composes ``description``.  Both keys stay required (``applies_when``
    may be empty) so the model always decides rather than silently omitting
    the fields.
    """

    applies_when: list[str]


class _Stage1aGapProviderDraft(LossAnalysisDraft):
    """Required provider wire for the gap-analysis and graph-revision calls.

    The internal draft remains partial so the two calls can exchange a loss
    registry before closing the dependent graph.  The provider contract,
    however, must make all four collection keys explicit on every response.
    """

    risk_card_losses: list[Loss] = Field(max_length=16)
    use_case_losses: list[Loss] = Field(max_length=16)
    hazards: list[Hazard] = Field(max_length=16)
    security_constraints: list[_ProviderSecurityConstraint] = Field(max_length=16)


class _Stage1aRiskProviderDraft(_Stage1aGapProviderDraft):
    """Provider wire for the risk-derivation call: adds risk accounting.

    Every supplied risk card must be accounted for exactly once in the
    response, so the disposition list is a required collection.
    """

    risk_dispositions: list[RiskDisposition]


class _ProviderRevisionConstraint(BaseModel):
    """One constraint in the graph-revision patch: identity and graph only.

    Phase 1.3 as amended: the patch carries the same authored
    ``rule`` + ``applies_when`` shape as Calls 1 and 2; code composes the
    description.  ``obligations`` rides with the constraint: the patch
    replaces the constraint collection wholesale, so entries not returned
    here are dropped.
    """

    constraint_id: str
    rule: str = Field(min_length=1)
    applies_when: list[str] = Field(min_length=0, max_length=4)
    related_hazards: list[str]
    obligations: list[Obligation] = Field(default_factory=list)


class _Stage1aRevisionPatch(BaseModel):
    """Patch wire for the graph-revision call.

    The model may edit only the hazard/constraint graph, in the same
    authored ``rule`` + ``applies_when`` shape as the other Stage 1a calls.
    Losses and risk dispositions are owned by the prior analysis and are
    never on the wire, so the model cannot damage immutable records by
    echoing them (live runs v2–v7 lost complete graphs to qualifier
    flattening and loss-registry echoes).
    """

    hazards: list[Hazard] = Field(max_length=16)
    security_constraints: list[_ProviderRevisionConstraint] = Field(max_length=16)


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
        description = str(getattr(hazard, "description", ""))
        if _COMPONENT_FAILURE_RE.search(description):
            hazard_id = getattr(hazard, "hazard_id", "unknown")
            diagnostics.append(
                LossAnalysisDiagnostic(
                    code="hazard_not_system_state",
                    severity="error",
                    message=(
                        f"{hazard_id} is phrased as a component failure; express "
                        "the resulting system-level hazardous state or condition "
                        "inside the analysis boundary instead."
                    ),
                )
            )
        if _CAUSE_OR_DEPENDENCY_RE.search(description):
            hazard_id = getattr(hazard, "hazard_id", "unknown")
            diagnostics.append(
                LossAnalysisDiagnostic(
                    code="hazard_cause_or_dependency",
                    severity="warning",
                    message=(
                        f"{hazard_id} is phrased as a cause or dependency; rewrite "
                        "it as the observable system-level state that can lead to "
                        "the loss, and retain the cause as supporting evidence."
                    ),
                )
            )
        if _MECHANISM_HAZARD_RE.search(description):
            hazard_id = getattr(hazard, "hazard_id", "unknown")
            diagnostics.append(
                LossAnalysisDiagnostic(
                    code="hazard_mechanism_phrasing",
                    severity="warning",
                    message=(
                        f"{hazard_id} names an attack mechanism in the hazard; "
                        "state the resulting system condition and keep the "
                        "mechanism as a separately supported cause."
                    ),
                )
            )
        if description and not _STATE_CUE_RE.search(description):
            hazard_id = getattr(hazard, "hazard_id", "unknown")
            diagnostics.append(
                LossAnalysisDiagnostic(
                    code="hazard_state_unspecified",
                    severity="warning",
                    message=(
                        f"{hazard_id} does not clearly state a system condition; "
                        "review whether it describes a state that can lead to a loss."
                    ),
                )
            )

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
) -> LossAnalysis:
    """Run Stage 1a: derive loss analysis via two sequential LLM calls.

    Call 1 (risk_derivation) derives losses/hazards/constraints from
    organizational risk cards.  Call 2 (gap_analysis) reviews the use-case
    for missing source-grounded systemic losses, receiving Call 1's output and
    the capability profile as context.

    The two drafts are merged with sequential ID renumbering so that
    cross-references remain valid and no IDs are duplicated.

    Args:
        llm_client: LLM client for making the completion calls.
        use_case_text: Free-text use-case description.
        risk_cards: List of RiskCard objects from risk extraction.
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).
        capability_profile: Optional capability profile from Stage 1b,
            passed to the gap analysis call for systematic coverage checking.

    Returns:
        Validated LossAnalysis model.

    Raises:
        StageError: If either LLM call fails or the merged result fails
            validation.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)
    # Keep the provider context small enough to leave completion room for a
    # complete graph.  The original typed inputs remain authoritative for
    # validation and persistence; these are prompt-only projections.
    compact_risk_evidence = _compact_risk_card_evidence(risk_cards)
    risk_prompt_vars: dict[str, object] = {
        "use_case_text": use_case_text,
        "risk_cards": risk_cards,
    }
    if compact_risk_evidence:
        risk_prompt_vars["risk_card_evidence"] = compact_risk_evidence

    # --- Call 1: risk_derivation ---
    risk_draft = _run_stage1a_call(
        llm_client=llm_client,
        loader=loader,
        system_template="stage1a_risk_system.j2",
        user_template="stage1a_risk_user.j2",
        run_dir=run_dir,
        step=STEP_RISK,
        temperature=temperature,
        response_format=_Stage1aRiskProviderDraft,
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
    )
    # The gap prompt is a review of the first draft, so its context must be
    # the canonical source-separated view.  Models occasionally put a
    # risk-card loss in ``use_case_losses`` (or repeat it in both fields).
    # Classify by the typed provenance and remove exact duplicate records
    # before rendering the review context and allocating continuation IDs.
    risk_draft = _canonicalize_draft_losses(risk_draft)

    # --- Compute next IDs for gap analysis ---
    next_loss_num = (
        _max_id_num(
            [
                loss.loss_id
                for loss in risk_draft.risk_card_losses + risk_draft.use_case_losses
            ],
            "L-",
        )
        + 1
    )
    next_hazard_num = _max_id_num([h.hazard_id for h in risk_draft.hazards], "H-") + 1
    next_sc_num = (
        _max_id_num([sc.constraint_id for sc in risk_draft.security_constraints], "SC-")
        + 1
    )

    # --- Call 2: gap_analysis ---
    existing_losses = risk_draft.risk_card_losses + risk_draft.use_case_losses
    kc_subcodes = capability_profile.kc_subcodes if capability_profile else []

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
        existing_losses=existing_losses,
        existing_hazards=risk_draft.hazards,
        existing_constraints=risk_draft.security_constraints,
        next_loss_num=next_loss_num,
        next_hazard_num=next_hazard_num,
        next_sc_num=next_sc_num,
        kc_subcodes=kc_subcodes,
        kc_subcodes_display=build_kc_subcodes_display(kc_subcodes),
        allowed_loss_ids={
            loss.loss_id
            for loss in risk_draft.risk_card_losses + risk_draft.use_case_losses
        },
        allowed_hazard_ids={hazard.hazard_id for hazard in risk_draft.hazards},
        require_losses=False,
        require_complete_chain=not (
            existing_losses and risk_draft.hazards and risk_draft.security_constraints
        ),
        authoritative_draft=risk_draft,
        normalization_warnings=normalization_warnings,
    )

    # --- Merge and validate ---
    try:
        merged = _merge_drafts(risk_draft, gap_draft)
    except Exception as exc:
        # Merge validation happens after both LLM calls, so it is not covered
        # by ``safe_llm_call``.  Keep the public stage boundary consistent
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
        warnings.append(
            f"risk accounting normalized: '{disposition.risk_ref}' was "
            f"not_applicable but is cited by {', '.join(loss_ids)}"
            f"{reason_note}; flipped to cited from the response's own "
            f"citation evidence{bulk_note}"
        )
    return warnings


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
    **template_vars: object,
) -> LossAnalysisDraft:
    """Render prompts, call the LLM, and return a validated draft.

    Shared by the risk_derivation and gap_analysis calls.  Raises
    :class:`StageError` if the LLM call fails.
    """
    system_prompt = loader.render_prompt(system_template)
    user_prompt = loader.render_prompt(user_template, **template_vars)

    validation_feedback: str | None = None
    first_parse_failed = False
    # Typed label of the first failure, used to route the targeted repair:
    # wire_schema, risk_accounting, draft_references, or draft_semantics.
    failure_class: str | None = None

    def parse_first_response(result: LLMResult) -> LossAnalysisDraft:
        """Parse the first response, routing wire-schema errors into salvage.

        A pydantic wire violation (for example a malformed or semantically
        invalid ``risk_dispositions`` entry) is deterministic and actionable,
        so it joins the reference validators in the one bounded targeted
        repair instead of crashing the run with an uncorrected parse failure.
        """
        nonlocal first_parse_failed, validation_feedback, failure_class
        try:
            draft = parse_llm_result(result, response_format)
        except ValidationError as exc:
            first_parse_failed = True
            failure_class = "wire_schema"
            validation_feedback = (
                "Validation feedback: the prior response violated the "
                f"required response schema: {_wire_error_summary(exc)} "
                "Return the complete corrected structured object that "
                "matches the response schema exactly."
            )
            raise
        if authoritative_draft is not None:
            merged = _merge_loss_analysis_correction(
                LossAnalysisDraft(),
                draft,
                authoritative_draft=authoritative_draft,
            )
        else:
            merged = draft
        for warning in normalize_disposition_citations(merged):
            if (
                normalization_warnings is not None
                and warning not in normalization_warnings
            ):
                normalization_warnings.append(warning)
        return merged

    def run_validators(draft: LossAnalysisDraft) -> None:
        nonlocal failure_class
        try:
            _validate_draft_references(
                draft,
                context=step,
                allowed_loss_ids=allowed_loss_ids,
                allowed_hazard_ids=allowed_hazard_ids,
            )
            _validate_draft_semantics(draft, context=step)
            if require_losses:
                _validate_loss_presence(
                    draft,
                    context=step,
                )
            if require_complete_chain:
                _validate_complete_chain(
                    draft,
                    context=step,
                    allowed_loss_ids=allowed_loss_ids,
                    allowed_hazard_ids=allowed_hazard_ids,
                )
            if require_risk_accounting:
                try:
                    _validate_risk_accounting(
                        draft,
                        risk_cards=list(accounting_cards),
                        context=step,
                    )
                except _DraftReferenceValidationError:
                    # The accounting validator is one of the two approved
                    # repair classes; label it distinctly from generic
                    # reference failures.
                    failure_class = "risk_accounting"
                    raise
        except _DraftReferenceValidationError:
            failure_class = failure_class or "draft_references"
            raise
        except _DraftSemanticValidationError:
            failure_class = "draft_semantics"
            raise

    def validate_references(draft: LossAnalysisDraft) -> None:
        nonlocal validation_feedback
        try:
            run_validators(draft)
        except _DraftReferenceValidationError as exc:
            validation_feedback = exc.feedback
            raise
        except _DraftSemanticValidationError as exc:
            validation_feedback = exc.feedback
            raise

    draft, first_result, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        run_dir=run_dir,
        stage=STAGE,
        step=step,
        temperature=temperature,
        max_completion_tokens=STAGE1A_MAX_COMPLETION_TOKENS,
        json_decode_retries=JSON_DECODE_RETRIES,
        result_parser=parse_first_response,
        result_validator=validate_references,
    )
    if error_msg is None:
        assert draft is not None  # safe_llm_call guarantees this on success
        return draft

    # Reference validation and wire-schema violations are deterministic and
    # actionable.  The former bounded whole-object retry is replaced (owner
    # authorization 2026-09-11) by one narrowly scoped targeted repair for
    # two approved failure classes: missing or malformed risk-disposition
    # entries, and malformed obligation entries within an otherwise
    # preserved constraint.  Every other failure class gets an explicit typed
    # outcome and no additional model call.
    if validation_feedback is None:
        raise StageError(stage=STAGE, step=step, message=error_msg)

    def _merge_authority(repaired: LossAnalysisDraft) -> LossAnalysisDraft:
        return _merge_loss_analysis_correction(
            LossAnalysisDraft(),
            repaired,
            authoritative_draft=authoritative_draft,
        )

    outcome = build_repair_plan(
        step=step,
        response_format=response_format,
        first_result=first_result,
        first_parse_failed=first_parse_failed,
        failure_class=failure_class or "unknown",
        risk_cards=list(accounting_cards),
        require_risk_accounting=require_risk_accounting,
        constraint_wire_model=_ProviderSecurityConstraint,
    )
    if isinstance(outcome, UnsupportedRepair):
        raise StageError(
            stage=STAGE,
            step=step,
            message=(
                f"targeted repair unsupported ({outcome.reason}); no repair "
                f"call was made; first attempt failed: {error_msg}. "
                f"{validation_feedback}"
            ),
        )
    if isinstance(outcome, DeterministicCleanup):
        # Deterministic row removal (out-of-contract disposition rows, or rows
        # referencing unsupplied risk cards) is all the failure reduced to.
        # The cleaned draft passes through the same authority merge, citation
        # normalization, and full stage validators as a successful response.
        cleaned = outcome.draft
        try:
            if authoritative_draft is not None:
                cleaned = _merge_authority(cleaned)
            for warning in normalize_disposition_citations(cleaned):
                if (
                    normalization_warnings is not None
                    and warning not in normalization_warnings
                ):
                    normalization_warnings.append(warning)
            run_validators(cleaned)
        except (_DraftReferenceValidationError, _DraftSemanticValidationError) as exc:
            raise StageError(
                stage=STAGE,
                step=step,
                message=(
                    f"targeted repair unsupported (deterministic cleanup left "
                    f"a {failure_class or 'draft'} failure: {exc}); no repair "
                    f"call was made; first attempt failed: {error_msg}. "
                    f"{exc.feedback}"
                ),
            ) from exc
        except ValueError as exc:
            raise StageError(
                stage=STAGE,
                step=step,
                message=(
                    "targeted repair unsupported (deterministic cleanup "
                    f"produced a conflicting duplicate: {exc}); no repair call "
                    f"was made; first attempt failed: {error_msg}"
                ),
            ) from exc
        for warning in outcome.warnings:
            if (
                normalization_warnings is not None
                and warning not in normalization_warnings
            ):
                normalization_warnings.append(warning)
        return cleaned

    plan: RepairPlan = outcome
    return run_targeted_repair(
        plan,
        llm_client=llm_client,
        loader=loader,
        run_dir=run_dir,
        step=step,
        temperature=temperature,
        use_case_text=str(template_vars.get("use_case_text", "")),
        risk_cards=list(accounting_cards),
        run_validators=run_validators,
        normalizer=normalize_disposition_citations,
        authoritative_merge=(
            _merge_authority if authoritative_draft is not None else None
        ),
        normalization_warnings=normalization_warnings,
        max_completion_tokens=STAGE1A_MAX_COMPLETION_TOKENS,
    )


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
    supplied = set(supplied_ids)
    declared_loss_ids = {
        loss.loss_id for loss in draft.risk_card_losses + draft.use_case_losses
    }
    problems: list[str] = []
    seen: dict[str, int] = {}
    for disposition in draft.risk_dispositions:
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
    problems.extend(
        _disposition_loss_contradictions(
            [*draft.risk_card_losses, *draft.use_case_losses],
            draft.risk_dispositions,
        )
    )
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
    problems: list[str] = []
    if not loss_ids:
        problems.append("no grounded losses were declared or supplied")
    if not hazard_ids:
        problems.append("no hazards were declared or supplied")
    if not draft.security_constraints:
        problems.append("no security constraints were declared")
    if any(not hazard.related_losses for hazard in draft.hazards):
        problems.append("every hazard must reference at least one loss")
    if any(not constraint.related_hazards for constraint in draft.security_constraints):
        problems.append("every security constraint must reference at least one hazard")
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

    unknown_loss_ids = sorted(
        {
            reference
            for hazard in draft.hazards
            for reference in hazard.related_losses
            if reference not in valid_loss_ids
        }
    )
    unknown_hazard_ids = sorted(
        {
            reference
            for constraint in draft.security_constraints
            for reference in constraint.related_hazards
            if reference not in valid_hazard_ids
        }
    )
    if not unknown_loss_ids and not unknown_hazard_ids:
        return

    problems: list[str] = []
    if unknown_loss_ids:
        problems.append(
            "hazards.related_losses unknown IDs: " + ", ".join(unknown_loss_ids)
        )
    if unknown_hazard_ids:
        problems.append(
            "security_constraints.related_hazards unknown IDs: "
            + ", ".join(unknown_hazard_ids)
        )
    message = f"{context} draft has invalid cross-references: " + "; ".join(problems)
    if context == STEP_RISK:
        scope = "IDs declared in the risk_derivation draft"
    else:
        scope = "IDs declared in the risk_derivation or gap_analysis draft"
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
    repair = (
        " ".join(missing_declarations)
        or "Add each missing declaration or change the reference to an existing ID."
    )
    feedback = (
        f"Validation feedback: {message}. {repair} Use only {scope}; preserve every "
        "valid loss, hazard, and security constraint. Repair these dependencies "
        "before adding further constraints; expanding the constraint list while "
        "leaving the named declarations missing does not repair the result."
    )
    raise _DraftReferenceValidationError(message, feedback=feedback)


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


def _max_id_num(ids: list[str], prefix: str) -> int:
    """Return the maximum numeric suffix among IDs with the given prefix.

    Returns 0 if the list is empty or no IDs match the prefix.
    """
    max_num = 0
    pattern = re.compile(rf"^{re.escape(prefix)}(\d+)$")
    for id_str in ids:
        match = pattern.match(id_str)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num
    return max_num


def _merge_drafts(
    risk_draft: LossAnalysisDraft,
    gap_draft: LossAnalysisDraft,
) -> LossAnalysis:
    """Merge risk derivation and gap analysis drafts into a final LossAnalysis.

    Normalizes losses from both drafts by their typed provenance, removes
    identical duplicate records, and then concatenates hazards and security
    constraints.  Finally, renumbers all IDs sequentially to guarantee no
    duplicates and valid cross-references.
    """
    all_risk_losses, all_uc_losses = _normalize_losses(risk_draft, gap_draft)
    all_hazards = [
        hazard.model_copy(deep=True)
        for hazard in [*risk_draft.hazards, *gap_draft.hazards]
    ]
    all_constraints = [
        constraint.model_copy(deep=True)
        for constraint in [
            *risk_draft.security_constraints,
            *gap_draft.security_constraints,
        ]
    ]

    # --- Renumber loss IDs (risk losses first, then use-case losses) ---
    loss_id_map = _renumber_items(all_risk_losses, "loss_id", "L-")
    loss_id_map.update(
        _renumber_items(all_uc_losses, "loss_id", "L-", start=len(all_risk_losses) + 1)
    )

    # --- Renumber hazard and constraint IDs ---
    hazard_id_map = _renumber_items(all_hazards, "hazard_id", "H-")
    _renumber_items(all_constraints, "constraint_id", "SC-")

    # --- Update cross-references ---
    _remap_references(all_hazards, "related_losses", loss_id_map)
    _remap_references(all_constraints, "related_hazards", hazard_id_map)

    # Risk accounting comes from the risk-derivation draft only; remap its
    # cited loss IDs to the renumbered identities before persistence.
    remapped_dispositions = [
        disposition.model_copy(
            update={
                "loss_ids": [
                    loss_id_map.get(loss_id, loss_id)
                    for loss_id in disposition.loss_ids
                ]
            }
        )
        for disposition in risk_draft.risk_dispositions
    ]

    return LossAnalysis(
        risk_card_losses=all_risk_losses,
        use_case_losses=all_uc_losses,
        hazards=all_hazards,
        security_constraints=all_constraints,
        risk_dispositions=remapped_dispositions,
    )


def _canonicalize_draft_losses(draft: LossAnalysisDraft) -> LossAnalysisDraft:
    """Return a source-separated, duplicate-free copy of one draft.

    ``LossAnalysisDraft`` retains the two provider-facing containers for
    compatibility, but provenance is the authority for which final source a
    loss belongs to.  Canonicalizing before the gap prompt keeps the model
    from reviewing the same loss twice and makes the next-ID calculation
    agree with the context shown to it.  A conflicting duplicate ID remains a
    hard diagnostic; silently choosing one payload would corrupt references.
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


def _renumber_items(
    items: list[object],
    id_attr: str,
    prefix: str,
    *,
    start: int = 1,
) -> dict[str, str]:
    """Renumber items sequentially, returning an old-ID → new-ID map.

    Mutates each item's ``id_attr`` in place to ``{prefix}{index}`` where
    index starts at *start* and increments by 1.
    """
    id_map: dict[str, str] = {}
    for i, item in enumerate(items, start):
        old_id = getattr(item, id_attr)
        new_id = f"{prefix}{i}"
        id_map[old_id] = new_id
        setattr(item, id_attr, new_id)
    return id_map


def _remap_references(
    items: list[object],
    ref_attr: str,
    id_map: dict[str, str],
) -> None:
    """Replace each cross-reference in ``ref_attr`` using ``id_map``.

    References not found in the map are preserved unchanged.
    """
    for item in items:
        refs = getattr(item, ref_attr)
        setattr(item, ref_attr, [id_map.get(ref, ref) for ref in refs])

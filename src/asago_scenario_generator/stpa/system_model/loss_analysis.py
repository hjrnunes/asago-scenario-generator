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
from pathlib import Path

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import StageError, safe_llm_call
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
    Loss,
    LossProvenance,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR

STAGE = "stage_1a"
STEP_RISK = "risk_derivation"
STEP_GAP = "gap_analysis"
STEP_MERGE = "merge"
DEFAULT_TEMPERATURE = 0.4


class _DraftReferenceValidationError(ValueError):
    """Validation failure that can be sent back as bounded retry feedback."""

    def __init__(self, message: str, *, feedback: str) -> None:
        super().__init__(message)
        self.feedback = feedback


def derive_loss_analysis(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    capability_profile: CapabilityProfile | None = None,
) -> LossAnalysis:
    """Run Stage 1a: derive loss analysis via two sequential LLM calls.

    Call 1 (risk_derivation) derives losses/hazards/constraints from
    organizational risk cards.  Call 2 (gap_analysis) reviews the use-case
    for missing adversary-actionable losses, receiving Call 1's output and
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

    # --- Call 1: risk_derivation ---
    risk_draft = _run_stage1a_call(
        llm_client=llm_client,
        loader=loader,
        system_template="stage1a_risk_system.j2",
        user_template="stage1a_risk_user.j2",
        run_dir=run_dir,
        step=STEP_RISK,
        temperature=temperature,
        use_case_text=use_case_text,
        risk_cards=risk_cards,
        allowed_loss_ids=set(),
        allowed_hazard_ids=set(),
    )

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
        use_case_text=use_case_text,
        existing_losses=existing_losses,
        existing_hazards=risk_draft.hazards,
        existing_constraints=risk_draft.security_constraints,
        next_loss_num=next_loss_num,
        next_hazard_num=next_hazard_num,
        next_sc_num=next_sc_num,
        kc_subcodes=kc_subcodes,
        allowed_loss_ids={
            loss.loss_id
            for loss in risk_draft.risk_card_losses + risk_draft.use_case_losses
        },
        allowed_hazard_ids={hazard.hazard_id for hazard in risk_draft.hazards},
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
    write_yaml(merged, run_dir / "loss-analysis.yaml")
    return merged


def _run_stage1a_call(
    *,
    llm_client: LLMClient,
    loader: TemplateLoader,
    system_template: str,
    user_template: str,
    run_dir: Path,
    step: str,
    temperature: float,
    allowed_loss_ids: set[str],
    allowed_hazard_ids: set[str],
    **template_vars: object,
) -> LossAnalysisDraft:
    """Render prompts, call the LLM, and return a validated draft.

    Shared by the risk_derivation and gap_analysis calls.  Raises
    :class:`StageError` if the LLM call fails.
    """
    system_prompt = loader.render_prompt(system_template)
    user_prompt = loader.render_prompt(user_template, **template_vars)

    validation_feedback: str | None = None

    def validate_references(draft: LossAnalysisDraft) -> None:
        nonlocal validation_feedback
        try:
            _validate_draft_references(
                draft,
                context=step,
                allowed_loss_ids=allowed_loss_ids,
                allowed_hazard_ids=allowed_hazard_ids,
            )
        except _DraftReferenceValidationError as exc:
            validation_feedback = exc.feedback
            raise

    draft, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=LossAnalysisDraft,
        run_dir=run_dir,
        stage=STAGE,
        step=step,
        temperature=temperature,
        result_validator=validate_references,
    )
    if error_msg is None:
        assert draft is not None  # safe_llm_call guarantees this on success
        return draft

    # Reference validation is deterministic and actionable, so give the model
    # one bounded retry.  Parse/network failures do not get a duplicate call.
    if validation_feedback is None:
        raise StageError(stage=STAGE, step=step, message=error_msg)

    retry_prompt = (
        f"{user_prompt}\n\n{validation_feedback}\n"
        "Return only the corrected structured object."
    )

    def validate_retry_references(draft: LossAnalysisDraft) -> None:
        _validate_draft_references(
            draft,
            context=step,
            allowed_loss_ids=allowed_loss_ids,
            allowed_hazard_ids=allowed_hazard_ids,
        )

    draft, _, retry_error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=retry_prompt,
        response_format=LossAnalysisDraft,
        run_dir=run_dir,
        stage=STAGE,
        step=step,
        temperature=temperature,
        result_validator=validate_retry_references,
    )
    if retry_error_msg is not None:
        raise StageError(
            stage=STAGE,
            step=step,
            message=f"{error_msg}; retry failed: {retry_error_msg}",
        )

    assert draft is not None  # safe_llm_call guarantees this on success
    return draft


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
    feedback = (
        f"Validation feedback: {message}. Use only {scope}; preserve every "
        "loss, hazard, and security constraint."
    )
    raise _DraftReferenceValidationError(message, feedback=feedback)


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

    return LossAnalysis(
        risk_card_losses=all_risk_losses,
        use_case_losses=all_uc_losses,
        hazards=all_hazards,
        security_constraints=all_constraints,
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-11T11:50:53Z","module_hash":"06e356214430b4d9828468d3816ed3e24981490c507a106b3705abc29c8211fc","functions":[{"id":"func/derive_loss_analysis","name":"derive_loss_analysis","line":37,"end_line":124,"hash":"21c908533bc79b6d01657c6c6335cf95eb7c544a19bad2903de0e205dc5e1959"},{"id":"func/_run_stage1a_call","name":"_run_stage1a_call","line":127,"end_line":160,"hash":"37aad383f7dbea5e5024505d7cccd7f3b80ce9d0b597e22eb644775b3cf9221a"},{"id":"func/_max_id_num","name":"_max_id_num","line":163,"end_line":176,"hash":"6a33fe3dc4ff93f3d1859511ae0bdbec836b0ca731d6dcef08e7e0ed2bb487cb"},{"id":"func/_merge_drafts","name":"_merge_drafts","line":179,"end_line":215,"hash":"78acb5779c3bb0725d26d07091b065d434d296125cb4e524ca2f9cb34315912f"},{"id":"func/_renumber_items","name":"_renumber_items","line":218,"end_line":236,"hash":"5d4dfbcc96950022de526a41235bddac53174e3a916c2445c78b74eccad5c43b"},{"id":"func/_remap_references","name":"_remap_references","line":239,"end_line":250,"hash":"f0a6f06c65cc019b9471cc1339e2ab13e037dd073f592adfb160d29787e64545"}]}
# mutate4py-manifest-end

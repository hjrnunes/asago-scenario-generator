"""The mechanism verifier's provider stage for structural suggestions.

The graph join proposes a ``(mechanism, path)`` suggestion from typed fields
alone, so it cannot reach slot filling ungated.  This stage judges each one
against its mechanism library entry, whose required evidence and
counterexamples the glossary renders, in the obligation verifier's prompt.
Unlike that verifier it never asks for ``risk_alignment: supported``: a
suggestion carries no risk, so risk alignment is undefined for it, and the
verdict alone decides.

A suggestion cites no hazard or constraint, so each call lists the loss
analysis hazards once, with the constraints that govern each.
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import partial
from typing import TYPE_CHECKING, Any

from asago_scenario_generator.stpa.infra.call_log import (
    call_log_of,
    mark_call_published,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.mechanism_library import bundled_mechanism_library
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestions import (
    SuggestionVerdict,
    SuggestionVerificationRequest,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_mechanism_suggestion_verification_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _MECHANISM_VERIFICATION_MAX_COMPLETION_TOKENS,
    _MECHANISM_VERIFICATION_REPAIRS,
    _mechanism_prompt_hashes,
    _mechanism_verdict_payload_type,
    _require_verdict_handles,
    _verdict_map,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    MechanismCandidate,
    StpaIndex,
    build_stpa_index,
)

if TYPE_CHECKING:
    from asago_scenario_generator.stpa.obligation_aware.provider import (
        ObligationAwareLLMAdapter,
    )

MECHANISM_SUGGESTION_BATCH_SIZE = 8
"""The most suggestions one verifier call judges."""

SUGGESTION_VERIFICATION_STAGE_SUFFIX = "_mechanism_suggestion_verification"

INCOMPLETE_VERIFICATION = "the mechanism verification did not complete"


def _channel_owner(control_structure: ControlStructure, fb_id: str) -> str | None:
    return next(
        (
            owner.resp_id
            for owner in control_structure.responsibilities
            for channel in owner.feedback_channels
            if channel.fb_id == fb_id
        ),
        None,
    )


def _path_ids(
    candidate: MechanismCandidate,
    control_structure: ControlStructure,
    index: StpaIndex,
) -> tuple[str, ...]:
    """The controller, channel, variable, and the action or link with its reach."""
    fb_id, pm_id, end = candidate.path
    owner = _channel_owner(control_structure, fb_id)
    ids = [*((owner,) if owner else ()), fb_id, pm_id, end]
    action = index.control_actions.get(end)
    if action is not None:
        if action.target is not None:
            ids.append(action.target.id)
    else:
        link = index.coordination_links[end]
        ids.extend((link.coordination_mechanism.cm_id, link.target))
    return tuple(dict.fromkeys(ids))


def suggestion_verification_items(
    candidates: Sequence[MechanismCandidate],
    control_structure: ControlStructure,
) -> tuple[dict[str, Any], ...]:
    """Project each suggestion as a mechanism/path comparison ``S1``..``Sn``.

    The mechanism is the library entry's name and question, and
    ``known_mechanism_refs`` names that entry, so the glossary shows its
    required evidence and counterexamples.  The path holds exact structural
    descriptions only: no source kind, authority status, or risk.
    """
    library = bundled_mechanism_library()
    index = build_stpa_index(control_structure)
    descriptions = index.structural_descriptions()
    items: list[dict[str, Any]] = []
    for number, candidate in enumerate(candidates, 1):
        entry = library.entry(candidate.mechanism)
        items.append(
            {
                "item_handle": f"S{number}",
                "distinctive_mechanism": {
                    "name": entry.name,
                    "description": entry.question,
                },
                "selected_structural_path": [
                    {"id": identity, "description": descriptions[identity]}
                    for identity in _path_ids(candidate, control_structure, index)
                    if identity in descriptions
                ],
                "known_mechanism_refs": [entry.id.value],
            }
        )
    return tuple(items)


def suggestion_system_hazards(loss_analysis: LossAnalysis) -> list[dict[str, Any]]:
    """List every hazard with the constraints that govern it, in analysis order."""
    return [
        {
            "id": hazard.hazard_id,
            "description": hazard.description,
            "governing_constraints": [
                {"id": constraint.constraint_id, "description": constraint.description}
                for constraint in loss_analysis.security_constraints
                if hazard.hazard_id in constraint.related_hazards
            ],
        }
        for hazard in loss_analysis.hazards
    ]


def _batches(
    candidates: Sequence[MechanismCandidate],
) -> tuple[tuple[MechanismCandidate, ...], ...]:
    size = MECHANISM_SUGGESTION_BATCH_SIZE
    return tuple(
        tuple(candidates[start : start + size])
        for start in range(0, len(candidates), size)
    )


def run_suggestion_verification(
    adapter: "ObligationAwareLLMAdapter",
    request: SuggestionVerificationRequest,
) -> tuple[SuggestionVerdict, ...]:
    """Judge every candidate, in order, one bounded call per batch.

    A batch whose call fails leaves its candidates without a verdict
    (``relationship`` ``None``); the other batches stand.
    """
    candidates = tuple(dict.fromkeys(request.candidates))
    verdicts: list[SuggestionVerdict] = []
    for number, batch in enumerate(_batches(candidates), 1):
        verdicts.extend(_verify_batch(adapter, request, batch, f"suggestions-{number}"))
    return tuple(verdicts)


def _verify_batch(
    adapter: "ObligationAwareLLMAdapter",
    request: SuggestionVerificationRequest,
    batch: tuple[MechanismCandidate, ...],
    step: str,
) -> tuple[SuggestionVerdict, ...]:
    items = suggestion_verification_items(batch, request.control_structure)
    system_prompt, user_prompt = build_mechanism_suggestion_verification_prompts(
        items, suggestion_system_hazards(request.loss_analysis)
    )
    handles = tuple(item["item_handle"] for item in items)
    stage = f"{adapter.stage_prefix}{SUGGESTION_VERIFICATION_STAGE_SUFFIX}"
    outcome = call_with_policy(
        llm_client=adapter.llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=_mechanism_verdict_payload_type(len(batch)),
        run_dir=adapter.run_dir,
        stage=stage,
        step=step,
        policy=CorrectionPolicy(
            validation_retries=_MECHANISM_VERIFICATION_REPAIRS,
            feedback=" Return one verdict for each item handle, copied unchanged.",
        ),
        temperature=0.0,
        max_completion_tokens=_MECHANISM_VERIFICATION_MAX_COMPLETION_TOKENS,
        result_validator=partial(_require_verdict_handles, handles),
        prompt_template_hashes=_mechanism_prompt_hashes(),
    )
    if outcome.error is not None or outcome.value is None:
        return tuple(
            SuggestionVerdict(candidate, None, INCOMPLETE_VERIFICATION)
            for candidate in batch
        )
    by_handle = _verdict_map(handles, outcome.value.verdicts)
    mark_call_published(adapter.run_dir, stage, step, call_log_of(adapter.llm_client))
    return tuple(
        SuggestionVerdict(
            candidate,
            by_handle[handle].relationship,
            by_handle[handle].rationale,
        )
        for candidate, handle in zip(batch, handles, strict=True)
    )


__all__ = [
    "INCOMPLETE_VERIFICATION",
    "MECHANISM_SUGGESTION_BATCH_SIZE",
    "SUGGESTION_VERIFICATION_STAGE_SUFFIX",
    "run_suggestion_verification",
    "suggestion_system_hazards",
    "suggestion_verification_items",
]

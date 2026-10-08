"""Stage 1b — Capability Profile inference.

Single LLM call extracts a capability profile from the use-case
description.  No loss-analysis context is provided — Stage 1b has
zero dependency on Stage 1a.  Produces Stage1Profile which is promoted
to CapabilityProfile via to_capability_profile(). The --profile flag
skips this stage (loads a pre-built profile).
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, create_model, model_validator

from asago_scenario_generator.models.capability_profile import (
    KCX_SUBCODES,
    VALID_KC_SUBCODES,
    CapabilityProfile,
    Stage1Profile,
    ToolInventoryEntry,
    derive_zones_from_kc,
    inject_kc_subcodes_display,
)
from asago_scenario_generator.request_schema import (
    string_items_enum,
    uses_guided_decoding,
)
from asago_scenario_generator.stpa.infra.llm import DEFAULT_TEMPERATURE, LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    StageError,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml, write_yaml
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.kc_decision import (
    KcDecisionRecord,
    apply_kc_facts,
    target_kc_decision,
    vote_kc_subcodes,
)

STAGE = "stage_1b"
STEP = "capability_profile"
KC_DECISION_FILENAME = "capability-kc-decision.yaml"


def _validate_promotion(draft: Stage1Profile) -> Stage1Profile:
    """Reject a draft that the promotion to CapabilityProfile would reject.

    Promotion rules (at least one KC code, a tool inventory when a code
    activates tool execution) then fail inside the call, where the
    correction retry can report them, instead of after the call succeeded.
    """
    draft.to_capability_profile()
    return draft


# The request variants keep the static name: call records and test clients
# identify the Stage 1b wire as ``Stage1Profile``.  Adding a validator does
# not change the schema, so non-guided clients receive main's schema.
_Stage1ProfileRequest = create_model(
    "Stage1Profile",
    __base__=Stage1Profile,
    __module__=Stage1Profile.__module__,
    __doc__=Stage1Profile.__doc__,
    __validators__={
        "validate_promotion": model_validator(mode="after")(_validate_promotion)
    },
)

# Guided decoding may omit any field its schema leaves optional, so the
# guided variant requires both promotion inputs and closes the KC codes.
_GuidedStage1ProfileRequest = create_model(
    "Stage1Profile",
    __base__=_Stage1ProfileRequest,
    __module__=Stage1Profile.__module__,
    __doc__=Stage1Profile.__doc__,
    kc_subcodes=(
        list[str],
        Field(
            min_length=1,
            description=Stage1Profile.model_fields["kc_subcodes"].description,
            json_schema_extra=string_items_enum(
                sorted(VALID_KC_SUBCODES) + sorted(KCX_SUBCODES)
            ),
        ),
    ),
    tool_inventory=(
        list[ToolInventoryEntry],
        Field(description=Stage1Profile.model_fields["tool_inventory"].description),
    ),
)


def stage1_profile_request_model(llm_client: object) -> type[Stage1Profile]:
    """The Stage 1b wire for *llm_client*: tightened only under guided decoding."""
    if uses_guided_decoding(llm_client):
        return _GuidedStage1ProfileRequest
    return _Stage1ProfileRequest


def derive_capability_profile(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    samples: int = 1,
    target_profile: ExecutionTargetProfile | None = None,
) -> CapabilityProfile:
    """Run Stage 1b: derive capability profile from use-case text.

    Sends the same Stage1Profile request *samples* times.  The KC sub-codes
    are the vote of the successful draws (:func:`vote_kc_subcodes`); entry
    points, tool inventory, and confidence come from the first successful
    draw.  A draw that fails after its correction is left out of the vote;
    the stage fails only when every draw fails.  The verified facts of an
    observed *target_profile* then force the codes they decide in or out
    (:func:`target_kc_decision`); the request itself never sees the target.
    The draws, the counts, the fact decisions with their reasons, and the
    decided codes land in ``capability-kc-decision.yaml``; the profile in
    ``capability-profile.yaml``.

    Stage 1b has zero dependency on Stage 1a — no loss analysis context
    is passed to the prompt.

    Args:
        llm_client: LLM client for making the completion call.
        use_case_text: Free-text use-case description.
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).
        samples: Number of draws the KC vote takes (at least 1).
        target_profile: Optional observed execution target profile whose
            verified facts decide some KC sub-codes.

    Returns:
        Validated CapabilityProfile model.

    Raises:
        StageError: If every draw fails or the decided profile is invalid.
    """
    if samples < 1:
        raise ValueError("samples must be at least 1")
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    system_prompt = loader.render_prompt("stage1b_system.j2")
    user_prompt = loader.render_prompt(
        "stage1b_user.j2",
        use_case_text=use_case_text,
    )

    drafts, errors = _sample_drafts(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        run_dir=run_dir,
        temperature=temperature,
        samples=samples,
    )

    draws = [draft.kc_subcodes for draft in drafts]
    facts = target_kc_decision(target_profile)
    kc_subcodes = apply_kc_facts(vote_kc_subcodes(draws), facts)
    capability_profile = _decided_profile(drafts, kc_subcodes)
    write_yaml(
        KcDecisionRecord.of(
            samples=samples,
            draws=draws,
            failed_draws=errors,
            facts=facts,
            kc_subcodes=capability_profile.kc_subcodes,
        ),
        run_dir / KC_DECISION_FILENAME,
    )
    write_yaml(
        capability_profile,
        run_dir / "capability-profile.yaml",
        post_process=inject_kc_subcodes_display,
    )
    return capability_profile


def _sample_drafts(
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    run_dir: Path,
    temperature: float,
    samples: int,
) -> tuple[list[Stage1Profile], list[str]]:
    """Send the Stage 1b request *samples* times; return the drafts and errors."""
    drafts: list[Stage1Profile] = []
    errors: list[str] = []
    for index in range(1, samples + 1):
        outcome = call_with_policy(
            llm_client=llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=stage1_profile_request_model(llm_client),
            run_dir=run_dir,
            stage=STAGE,
            step=STEP if index == 1 else f"{STEP}_vote_{index}",
            policy=CorrectionPolicy(validation_retries=1, include_response=True),
            temperature=temperature,
        )
        if outcome.error is not None:
            errors.append(outcome.error)
        else:
            drafts.append(outcome.value)
    if not drafts:
        raise StageError(stage=STAGE, step=STEP, message=errors[-1])
    return drafts, errors


def _decided_profile(
    drafts: list[Stage1Profile], kc_subcodes: list[str]
) -> CapabilityProfile:
    """Promote the first draft that can carry *kc_subcodes*.

    A decided code may activate tool execution that the first draft listed
    no tools for; the first draft with a tool inventory then supplies the
    non-KC fields.
    """
    base = drafts[0]
    if "tool_execution" in derive_zones_from_kc(kc_subcodes):
        base = next((draft for draft in drafts if draft.tool_inventory), base)
    try:
        return base.model_copy(
            update={"kc_subcodes": kc_subcodes}
        ).to_capability_profile()
    except ValueError as exc:
        raise StageError(stage=STAGE, step=STEP, message=str(exc)) from exc


def load_capability_profile(profile_path: Path) -> CapabilityProfile:
    """Load a pre-built capability profile from a YAML file.

    Used when the --profile flag is provided to skip Stage 1b.

    Args:
        profile_path: Path to capability-profile.yaml.

    Returns:
        Validated CapabilityProfile model.
    """
    return read_yaml(profile_path, CapabilityProfile)

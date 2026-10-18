"""The stated-belief step behind ``--flawed-belief separate``.

Stage 5 writes each scenario exactly as it does with stated beliefs off. This
step then sends one request per Stage 5 spec, in spec order: the scenario
account, the spec's causal factors under the local source handles Stage 5
used, and the selected path's process-model variables under local handles.
The reply states one flawed belief per listed factor and, where code does not
fill the factor's variable, names the variable that holds the belief or the
variable the controller lacks.

Code checks the reply with the rules ``--flawed-belief stated`` applies and
never repairs it. A reply that breaks a rule, or does not decode, earns one
correction. A reply that still fails, and any failed or refused call, leaves
the spec unchanged, so its later requests stay the ones ``off`` sends.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, create_model

from asago_scenario_generator.stpa.infra.llm import DEFAULT_TEMPERATURE, LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    ExactFeedbackError,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

from .._constants import PROMPTS_DIR
from ..presentation import render_scenario_summary
from .flawed_belief import (
    VARIABLE_NONE,
    FlawedBeliefFrame,
    build_flawed_belief_frame,
    flawed_belief_findings,
    resolve_process_model_variable,
)
from .prompt_view import (
    _process_model_variables_yaml,
    _source_type_explanation,
    _yaml_dump,
)
from .sources import _causal_source_choices
from .wire import _CausalSourceChoice

BELIEF_STAGE = "stage5_belief"
BELIEF_STEP = "belief"
BELIEFS_FILENAME = "beliefs.json"
BELIEF_MAX_COMPLETION_TOKENS = 4096

_REJECTED_FEEDBACK = (
    "\n\nCode rejected the prior reply. Return the whole reply again with "
    "every listed problem fixed."
)
_UNDECODABLE_FEEDBACK = (
    "\n\nCode could not decode the prior reply as JSON, possibly because it ran "
    "to the token limit before the object was complete. Return the whole reply "
    "again as one complete JSON object, and end the reply at its closing brace."
)


def _feedback(error: Exception) -> str:
    if isinstance(error, json.JSONDecodeError):
        return _UNDECODABLE_FEEDBACK
    return _REJECTED_FEEDBACK


BELIEF_CORRECTION_POLICY = CorrectionPolicy(
    validation_retries=1,
    feedback=_feedback,
    include_schema=False,
    include_response=True,
    correct_undecodable=True,
)


class StatedBeliefReply(BaseModel):
    """Base of every per-request reply model: one field per listed handle."""

    model_config = ConfigDict(extra="forbid")


# A factor whose variable code fills states only its belief. No docstring: a
# class docstring would reach the request schema as a description.
class _FixedBelief(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flawed_belief: StrictStr = Field(min_length=1)


class _ChosenBeliefBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass(frozen=True)
class BeliefRequest:
    """What one spec's request lists: its factors' choices and the frame.

    ``listed`` pairs each causal factor's index in the spec with the Stage 5
    source choice it compiled from, in factor order.
    """

    listed: tuple[tuple[int, _CausalSourceChoice], ...]
    frame: FlawedBeliefFrame

    @property
    def choices(self) -> tuple[_CausalSourceChoice, ...]:
        return tuple(choice for _, choice in self.listed)


def belief_request(
    spec: ScenarioSpec, control_structure: ControlStructure
) -> BeliefRequest:
    """Match each causal factor to its Stage 5 source choice and build the frame.

    Raises:
        ValueError: When the spec has no scenario context or causal factor, or
            a factor matches no source choice of its context.
    """
    context = spec.scenario_context
    if context is None:
        raise ValueError(f"{spec.scenario_id} carries no scenario context")
    if not spec.causal_factors:
        raise ValueError(f"{spec.scenario_id} has no causal factor")
    by_source = {
        (choice.kind, choice.source_id): choice
        for choice in _causal_source_choices(context)
    }
    listed = []
    for index, factor in enumerate(spec.causal_factors):
        choice = by_source.get((factor.kind, factor.source_id))
        if choice is None:
            raise ValueError(
                f"{spec.scenario_id}: causal factor {factor.kind.value} "
                f"{factor.source_id} matches no source of its scenario context"
            )
        listed.append((index, choice))
    choices = tuple(choice for _, choice in listed)
    return BeliefRequest(
        listed=tuple(listed),
        frame=build_flawed_belief_frame(choices, context, control_structure),
    )


def belief_reply_type(request: BeliefRequest) -> type[StatedBeliefReply]:
    """Return the closed reply model: one required entry per listed handle.

    A factor whose variable code fills carries only ``flawed_belief``; every
    other factor also carries ``process_model_variable`` (one of the
    ``variable_N`` handles or ``none``) and ``missing_variable``.
    """
    count = len(request.frame.variables)
    variable_type = Literal.__getitem__(
        (*request.frame.variable_handles, VARIABLE_NONE)
    )
    chosen = create_model(
        f"_ChosenBeliefV{count}",
        __base__=_ChosenBeliefBase,
        flawed_belief=(StrictStr, Field(min_length=1)),
        process_model_variable=(variable_type, ...),
        missing_variable=(StrictStr | None, ...),
    )
    fields: dict[str, Any] = {
        choice.handle: (
            _FixedBelief
            if request.frame.fixed_variable(choice.handle) is not None
            else chosen,
            ...,
        )
        for choice in request.choices
    }
    fixed = sum(
        request.frame.fixed_variable(choice.handle) is not None
        for choice in request.choices
    )
    return create_model(
        f"_StatedBeliefReply{len(request.choices)}F{fixed}V{count}",
        __base__=StatedBeliefReply,
        **fields,
    )


def _variable_rule(choice: _CausalSourceChoice, frame: FlawedBeliefFrame) -> str:
    fixed = frame.fixed_variable(choice.handle)
    if fixed is not None:
        return f"filled by code ({fixed.handle}); give only flawed_belief"
    return (
        "your choice: the handle of the listed variable that holds the belief, "
        f"or {VARIABLE_NONE} with missing_variable"
    )


def _factors_yaml(spec: ScenarioSpec, request: BeliefRequest) -> str:
    return _yaml_dump(
        [
            {
                "source_handle": choice.handle,
                "source_type": _source_type_explanation(choice.kind),
                "source_description": choice.description,
                "factor_description": spec.causal_factors[index].description,
                "process_model_variable": _variable_rule(choice, request.frame),
            }
            for index, choice in request.listed
        ]
    )


def render_belief_prompts(
    spec: ScenarioSpec,
    request: BeliefRequest,
    loader: TemplateLoader | None = None,
) -> tuple[str, str]:
    """Return the system and user prompts of one spec's belief request."""
    loader = loader or TemplateLoader(PROMPTS_DIR)
    system = loader.render_prompt("stage5_belief_system.j2")
    user = loader.render_prompt(
        "stage5_belief_user.j2",
        account=render_scenario_summary(spec)[0],
        factors_yaml=_factors_yaml(spec, request),
        process_model_variables_yaml=_process_model_variables_yaml(request.frame),
    )
    return system, user


def _entries(reply: BaseModel, request: BeliefRequest) -> list[SimpleNamespace]:
    """View each listed entry as a factor the stated-belief rules read."""
    entries = []
    for choice in request.choices:
        entry = getattr(reply, choice.handle)
        entries.append(
            SimpleNamespace(
                source_handle=choice.handle,
                flawed_belief=entry.flawed_belief,
                process_model_variable=getattr(entry, "process_model_variable", None),
                missing_variable=getattr(entry, "missing_variable", None),
            )
        )
    return entries


def belief_failures(reply: BaseModel, request: BeliefRequest) -> list[str]:
    """Return every stated-belief rule the reply breaks, one line each."""
    return flawed_belief_findings(
        _entries(reply, request),
        request.frame,
        {choice.handle: choice for choice in request.choices},
        locate=lambda _, factor: factor.source_handle,
    )


def apply_beliefs(
    spec: ScenarioSpec, reply: BaseModel, request: BeliefRequest
) -> ScenarioSpec:
    """Return ``spec`` with each factor's stated belief and its variable."""
    factors = list(spec.causal_factors)
    for (index, _), entry in zip(request.listed, _entries(reply, request)):
        factors[index] = factors[index].model_copy(
            update={
                "flawed_belief": entry.flawed_belief.strip(),
                "process_model_variable": resolve_process_model_variable(
                    entry, request.frame
                ),
            }
        )
    return spec.model_copy(update={"causal_factors": factors})


class _BeliefRejectedError(ExactFeedbackError):
    """A parsed reply that broke a stated-belief rule."""


@dataclass
class BeliefOutcome:
    """The outcome of one spec's belief request."""

    scenario_id: str
    source: str = "none"
    requests: int = 0
    rejected: list[tuple[str, ...]] = field(default_factory=list)
    reason: str | None = None
    spec: ScenarioSpec | None = None

    @property
    def accepted(self) -> bool:
        return self.source == "model"


def state_beliefs(
    spec: ScenarioSpec,
    *,
    llm_client: LLMClient,
    run_dir: Path,
    control_structure: ControlStructure,
    loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> BeliefOutcome:
    """Send one spec's belief request, with at most one correction."""
    outcome = BeliefOutcome(scenario_id=spec.scenario_id)
    try:
        request = belief_request(spec, control_structure)
    except ValueError as exc:
        outcome.reason = str(exc)
        return outcome
    system, user = render_belief_prompts(spec, request, loader)

    def check(reply: StatedBeliefReply) -> None:
        failures = belief_failures(reply, request)
        if failures:
            outcome.rejected.append(tuple(failures))
            raise _BeliefRejectedError(
                "\n".join(
                    [
                        "stated flawed beliefs break these rules:",
                        *(f"- {item}" for item in failures),
                    ]
                )
            )

    try:
        result = call_with_policy(
            llm_client=llm_client,
            system_prompt=system,
            user_prompt=user,
            response_format=belief_reply_type(request),
            run_dir=run_dir,
            stage=BELIEF_STAGE,
            step=BELIEF_STEP,
            policy=BELIEF_CORRECTION_POLICY,
            slot_id=spec.threat_source.ica_slot_id,
            scenario_id=spec.scenario_id,
            temperature=temperature,
            max_completion_tokens=BELIEF_MAX_COMPLETION_TOKENS,
            result_validator=check,
        )
    except Exception as exc:  # noqa: BLE001 - a belief failure never stops the run
        outcome.reason = f"{type(exc).__name__}: {exc}"
        return outcome
    outcome.requests = result.calls
    if result.value is None:
        outcome.reason = result.error or "the call returned no reply"
        return outcome
    outcome.source = "model"
    outcome.spec = apply_beliefs(spec, result.value, request)
    return outcome


def beliefs_payload(outcomes: Sequence[BeliefOutcome]) -> dict[str, Any]:
    """Return the run's ``beliefs.json`` document."""
    return {
        "stage": BELIEF_STAGE,
        "step": BELIEF_STEP,
        "scenarios": [
            {
                "scenario_id": outcome.scenario_id,
                "source": outcome.source,
                "requests": outcome.requests,
                "rejected": [list(item) for item in outcome.rejected],
                "reason": outcome.reason,
            }
            for outcome in outcomes
        ],
    }


def write_beliefs_file(run_dir: Path, payload: dict[str, Any]) -> Path:
    path = run_dir / BELIEFS_FILENAME
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return path


def apply_belief_step(
    specs: Sequence[ScenarioSpec],
    *,
    llm_client: LLMClient,
    run_dir: Path,
    control_structure: ControlStructure,
    loader: TemplateLoader | None = None,
    temperature: float | None = None,
) -> list[ScenarioSpec]:
    """Request each spec's stated beliefs in order and write ``beliefs.json``.

    Every spec costs one request, plus one correction when its reply breaks a
    rule or does not decode. A spec whose request fails comes back unchanged.
    """
    effective = DEFAULT_TEMPERATURE if temperature is None else temperature
    outcomes = [
        state_beliefs(
            spec,
            llm_client=llm_client,
            run_dir=run_dir,
            control_structure=control_structure,
            loader=loader,
            temperature=effective,
        )
        for spec in specs
    ]
    write_beliefs_file(run_dir, beliefs_payload(outcomes))
    return [
        outcome.spec if outcome.spec is not None else spec
        for spec, outcome in zip(specs, outcomes)
    ]

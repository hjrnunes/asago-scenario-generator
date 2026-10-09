"""The shape step: how an adversarial scenario reaches the target, as structure.

Stage 5 compiles a scenario spec. This step then asks the model one closed-enum
question per adversarial scenario: which channel, how many turns, who speaks
each turn and why, and (for indirect attacks) which operation carries the
planted item. The reply holds no free text, so no attack words can appear in it.

Code validates the reply and never repairs it. A reply that breaks the schema,
a cross-field rule, the allowed channels, or names an unobserved or
uninfluenced carrier earns one correction request naming every broken rule.
Any failure that remains, and any failed call, replaces the proposal with the
single-turn direct default and records the reason on the shape.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from asago_scenario_generator.stpa.infra.llm import DEFAULT_TEMPERATURE, LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    ExactFeedbackError,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader

from asago_scenario_generator.stpa.models.attack_shape import (
    MAX_TURNS,
    THREAT_LABEL_FORGED_TRANSCRIPT,
    AttackChannel,
    AttackShape,
    ContentKind,
    IndirectShape,
    ItemController,
    PartyRelation,
    PlantedItem,
    ShapeDowngradeReason,
    ShapeIdentifier,
    ShapeSource,
    TurnPurpose,
    TurnShape,
    TurnSpeaker,
    carrier_operation_observed,
    default_attack_shape,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    AttackerInfluence,
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AdversaryKind,
    ScenarioSpec,
)

from .._constants import PROMPTS_DIR
from ..presentation import render_scenario_summary

SHAPE_STAGE = "stage5_shape"
SHAPE_STEP = "shape"


@dataclass(frozen=True)
class ShapeStepConfig:
    """Run-level switches for the shape step.

    ``allow_forged_transcript`` is off by default: the forged-transcript
    channel stays out of the response vocabulary until a run opts in.
    """

    allow_forged_transcript: bool = False


@dataclass(frozen=True)
class ShapeFacts:
    """What code knows about one scenario when it judges a proposal.

    ``observed_operations`` is ``None`` when the run has no target profile.
    ``influenced_operations`` holds the tools whose resource carries attacker
    influence.
    """

    adversary_kind: AdversaryKind
    observed_operations: Collection[str] | None
    influenced_operations: frozenset[str]
    config: ShapeStepConfig = ShapeStepConfig()


class _WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProposedCarrier(_WireModel):
    """The planted item of an indirect attack, named by closed values."""

    carrier_operation: ShapeIdentifier
    content_kind: ContentKind
    # The prompt does not ask for it and code never reads it; a reply that
    # still sends one validates and is dropped in ``_indirect_shape``.
    record_ref: ShapeIdentifier | None = None
    controller: ItemController


class ProposedTurn(_WireModel):
    """One planned turn; it has no text field."""

    position: StrictInt = Field(ge=1, le=MAX_TURNS)
    speaker: Literal["attacker_user", "benign_user"]
    purpose: Literal[
        "establish_context",
        "assert_authority",
        "request_action",
        "apply_pressure",
        "ask_to_read_item",
        "follow_up_on_item",
    ]


class ShapeProposal(_WireModel):
    """The shape reply when the forged-transcript channel is not allowed."""

    channel: Literal["direct", "indirect"]
    turn_count: StrictInt = Field(ge=1, le=MAX_TURNS)
    turn_plan: list[ProposedTurn] = Field(min_length=1, max_length=MAX_TURNS)
    indirect: ProposedCarrier | None


class ForgedProposedTurn(_WireModel):
    """One planned turn, with the forged speakers and purpose available."""

    position: StrictInt = Field(ge=1, le=MAX_TURNS)
    speaker: Literal[
        "attacker_user", "benign_user", "forged_assistant", "forged_tool_result"
    ]
    purpose: Literal[
        "establish_context",
        "assert_authority",
        "request_action",
        "apply_pressure",
        "ask_to_read_item",
        "follow_up_on_item",
        "forged_history",
    ]


class ForgedShapeProposal(_WireModel):
    """The shape reply when the run allows the forged-transcript channel."""

    channel: Literal["direct", "indirect", "forged_transcript"]
    turn_count: StrictInt = Field(ge=1, le=MAX_TURNS)
    turn_plan: list[ForgedProposedTurn] = Field(min_length=1, max_length=MAX_TURNS)
    indirect: ProposedCarrier | None


def response_model_for(
    config: ShapeStepConfig,
) -> type[ShapeProposal] | type[ForgedShapeProposal]:
    """Return the reply model whose vocabulary matches ``config``."""
    if config.allow_forged_transcript:
        return ForgedShapeProposal
    return ShapeProposal


def allowed_channels(
    adversary_kind: AdversaryKind, config: ShapeStepConfig
) -> frozenset[AttackChannel]:
    """Return the channels an adversary kind may use."""
    if adversary_kind is AdversaryKind.third_party_via_content:
        return frozenset({AttackChannel.INDIRECT})
    if adversary_kind is AdversaryKind.none:
        return frozenset()
    if config.allow_forged_transcript:
        return frozenset({AttackChannel.DIRECT, AttackChannel.FORGED_TRANSCRIPT})
    return frozenset({AttackChannel.DIRECT})


def attacker_influenced_operations(
    profile: ExecutionTargetProfile | None,
) -> frozenset[str]:
    """Return the tools whose profile resource marks attacker influence as indirect."""
    if profile is None:
        return frozenset()
    return frozenset(
        resource.tool_name
        for resource in profile.resources
        if resource.tool_name is not None
        and resource.attacker_influence is AttackerInfluence.indirect
    )


def observed_operation_names(
    profile: ExecutionTargetProfile | None,
) -> tuple[str, ...] | None:
    """Return the profile's inventory tool names, or ``None`` without a profile."""
    if profile is None:
        return None
    if profile.inventory is None:
        return ()
    return tuple(tool.name for tool in profile.inventory.tools)


def _indirect_shape(
    proposal: ShapeProposal | ForgedShapeProposal,
) -> IndirectShape | None:
    carrier = proposal.indirect
    if carrier is None:
        return None
    return IndirectShape(
        carrier_operation=carrier.carrier_operation,
        # The scenario account names records the target's seed slots need not
        # list; a null ref lets the consumer seed the slot's own record.
        data_item=PlantedItem(content_kind=carrier.content_kind, record_ref=None),
        party_relation=PartyRelation(
            controller=carrier.controller, benign_user_actor_ref=None
        ),
    )


def _shape_fields(proposal: ShapeProposal | ForgedShapeProposal) -> dict[str, object]:
    channel = AttackChannel(proposal.channel)
    return dict(
        channel=channel,
        # The plan is the structure; a reply whose count disagrees with it is
        # not a different shape.
        turn_count=len(proposal.turn_plan),
        turn_plan=[
            TurnShape(
                position=turn.position,
                speaker=TurnSpeaker(turn.speaker),
                purpose=TurnPurpose(turn.purpose),
            )
            for turn in proposal.turn_plan
        ],
        indirect=_indirect_shape(proposal),
        threat_label=(
            THREAT_LABEL_FORGED_TRANSCRIPT
            if channel is AttackChannel.FORGED_TRANSCRIPT
            else None
        ),
        source=ShapeSource.STAGE5_VALIDATED,
        downgrade_reason=None,
    )


def _model_rule_failures(fields: dict[str, object]) -> list[str]:
    """Run each ``AttackShape`` rule on its own, so every broken rule is named.

    Pydantic stops at the first failing model validator; a correction that
    named only that one would let the next reply break the others.
    """
    draft = AttackShape.model_construct(**fields)
    failures = []
    for rule in AttackShape.__pydantic_decorators__.model_validators.values():
        try:
            rule.func(draft)
        except ValueError as error:
            failures.append(str(error))
    return failures


def _fact_failures(
    shape: AttackShape, facts: ShapeFacts
) -> list[tuple[ShapeDowngradeReason, str]]:
    """Name each fact about the scenario or target the shape contradicts."""
    failures = []
    allowed = allowed_channels(facts.adversary_kind, facts.config)
    if shape.channel not in allowed:
        names = ", ".join(f"`{channel.value}`" for channel in sorted(allowed))
        failures.append(
            (
                ShapeDowngradeReason.SHAPE_VALIDATION_FAILED,
                f"channel `{shape.channel.value}` is not allowed for this "
                f"scenario; allowed: {names}",
            )
        )
    if shape.indirect is None:
        return failures
    carrier = shape.indirect.carrier_operation
    if not carrier_operation_observed(shape, facts.observed_operations):
        failures.append(
            (
                ShapeDowngradeReason.CARRIER_NOT_OBSERVED,
                f"R8: carrier_operation `{carrier}` is not an operation the "
                "target offers",
            )
        )
    elif carrier not in facts.influenced_operations:
        failures.append(
            (
                ShapeDowngradeReason.NO_ATTACKER_INFLUENCED_OPERATION,
                f"carrier_operation `{carrier}` is not marked `outside content: yes`",
            )
        )
    return failures


@dataclass(frozen=True)
class _Judgement:
    """A proposal's shape (or the code default) and every rule it broke."""

    shape: AttackShape
    failures: tuple[str, ...]


def _judge(
    proposal: ShapeProposal | ForgedShapeProposal, facts: ShapeFacts
) -> _Judgement:
    fields = _shape_fields(proposal)
    rule_failures = _model_rule_failures(fields)
    fact_failures = _fact_failures(AttackShape.model_construct(**fields), facts)
    failures = tuple(rule_failures + [text for _, text in fact_failures])
    if rule_failures:
        reason = ShapeDowngradeReason.SHAPE_VALIDATION_FAILED
    elif fact_failures:
        reason = fact_failures[0][0]
    else:
        return _Judgement(AttackShape(**fields), ())
    return _Judgement(default_attack_shape(reason), failures)


def resolve_attack_shape(
    proposal: ShapeProposal | ForgedShapeProposal, facts: ShapeFacts
) -> AttackShape:
    """Validate a proposal into a shape, or return the code default with its reason."""
    return _judge(proposal, facts).shape


class _ShapeRejectedError(ExactFeedbackError):
    """A parsed reply that broke a rule; ``shape`` is its code default."""

    def __init__(self, message: str, shape: AttackShape) -> None:
        super().__init__(message)
        self.shape = shape


def _rejection_message(failures: tuple[str, ...], facts: ShapeFacts) -> str:
    lines = ["the reply breaks these rules:", *(f"- {text}" for text in failures)]
    if AttackChannel.INDIRECT in allowed_channels(facts.adversary_kind, facts.config):
        names = ", ".join(f"`{name}`" for name in sorted(facts.influenced_operations))
        lines.append(f"Operations marked `outside content: yes`: {names}.")
    return "\n".join(lines)


def _rule_check(
    facts: ShapeFacts,
) -> Callable[[ShapeProposal | ForgedShapeProposal], None]:
    """Return the result validator that turns a broken rule into a correction."""

    def check(proposal: ShapeProposal | ForgedShapeProposal) -> None:
        judgement = _judge(proposal, facts)
        if judgement.failures:
            raise _ShapeRejectedError(
                _rejection_message(judgement.failures, facts), judgement.shape
            )

    return check


# One correction, through the shared policy: the prior reply is echoed so the
# model fixes it in place, and the schema is already on the request.
SHAPE_CORRECTION_POLICY = CorrectionPolicy(
    validation_retries=1,
    feedback=(
        "\n\nCode rejected the prior reply. Return the whole reply again with "
        "every listed rule fixed."
    ),
    include_schema=False,
    include_response=True,
)


@dataclass(frozen=True)
class _ShapeRun:
    """The per-run inputs every scenario's shape request shares."""

    llm_client: LLMClient
    run_dir: Path
    loader: TemplateLoader
    config: ShapeStepConfig
    temperature: float
    observed_operations: tuple[str, ...] | None
    influenced_operations: frozenset[str]


def _render_prompts(spec: ScenarioSpec, adversary_kind: AdversaryKind, run: _ShapeRun):
    operations = (
        None
        if run.observed_operations is None
        else [
            {"name": name, "influenced": name in run.influenced_operations}
            for name in run.observed_operations
        ]
    )
    system = run.loader.render_prompt(
        "stage5_shape_system.j2",
        max_turns=MAX_TURNS,
        content_kinds=[kind.value for kind in ContentKind],
        allow_forged_transcript=run.config.allow_forged_transcript,
    )
    user = run.loader.render_prompt(
        "stage5_shape_user.j2",
        scenario_id=spec.scenario_id,
        adversary_kind=adversary_kind.value,
        adversary_gain=spec.adversary.gain if spec.adversary else "",
        allowed_channels=sorted(
            channel.value for channel in allowed_channels(adversary_kind, run.config)
        ),
        account=render_scenario_summary(spec)[0],
        operations=operations,
    )
    return system, user


def _no_carrier_reason(
    adversary_kind: AdversaryKind, run: _ShapeRun
) -> ShapeDowngradeReason | None:
    """Name why an indirect-only scenario cannot have a carrier, before any request.

    Every reply such a scenario could give would be downgraded for the same
    reason, so asking would spend a request on a known outcome.
    """
    if allowed_channels(adversary_kind, run.config) != {AttackChannel.INDIRECT}:
        return None
    if run.observed_operations is None:
        return ShapeDowngradeReason.CARRIER_NOT_OBSERVED
    if not run.influenced_operations:
        return ShapeDowngradeReason.NO_ATTACKER_INFLUENCED_OPERATION
    return None


def _shape_for(spec: ScenarioSpec, run: _ShapeRun) -> AttackShape | None:
    adversary = spec.adversary
    if adversary is None:
        return default_attack_shape(None)
    if adversary.kind is AdversaryKind.none:
        return None
    unreachable = _no_carrier_reason(adversary.kind, run)
    if unreachable is not None:
        return default_attack_shape(unreachable)
    system, user = _render_prompts(spec, adversary.kind, run)
    facts = ShapeFacts(
        adversary_kind=adversary.kind,
        observed_operations=run.observed_operations,
        influenced_operations=run.influenced_operations,
        config=run.config,
    )
    outcome = call_with_policy(
        llm_client=run.llm_client,
        system_prompt=system,
        user_prompt=user,
        response_format=response_model_for(run.config),
        run_dir=run.run_dir,
        stage=SHAPE_STAGE,
        step=SHAPE_STEP,
        policy=SHAPE_CORRECTION_POLICY,
        slot_id=spec.threat_source.ica_slot_id,
        scenario_id=spec.scenario_id,
        temperature=run.temperature,
        result_validator=_rule_check(facts),
    )
    if outcome.value is not None:
        return resolve_attack_shape(outcome.value, facts)
    if isinstance(outcome.failure, _ShapeRejectedError):
        return outcome.failure.shape
    return default_attack_shape(ShapeDowngradeReason.SHAPE_CALL_FAILED)


def apply_shape_step(
    specs: Sequence[ScenarioSpec],
    *,
    llm_client: LLMClient,
    run_dir: Path,
    execution_target_profile: ExecutionTargetProfile | None,
    config: ShapeStepConfig = ShapeStepConfig(),
    temperature: float | None = None,
    loader: TemplateLoader | None = None,
) -> list[ScenarioSpec]:
    """Return ``specs`` with the shape each adversarial scenario's request produced.

    A functional scenario passes through unchanged and costs no request, as
    does an indirect-only scenario when the run has no attacker-influenced
    operation; that scenario takes the code default with the reason. Each other
    adversarial scenario costs one request, plus one correction when its reply
    breaks a rule.
    """
    run = _ShapeRun(
        llm_client=llm_client,
        run_dir=run_dir,
        loader=loader or TemplateLoader(PROMPTS_DIR),
        config=config,
        temperature=DEFAULT_TEMPERATURE if temperature is None else temperature,
        observed_operations=observed_operation_names(execution_target_profile),
        influenced_operations=attacker_influenced_operations(execution_target_profile),
    )
    shaped = []
    for spec in specs:
        shape = _shape_for(spec, run)
        shaped.append(
            spec if shape is None else spec.model_copy(update={"attack_shape": shape})
        )
    return shaped

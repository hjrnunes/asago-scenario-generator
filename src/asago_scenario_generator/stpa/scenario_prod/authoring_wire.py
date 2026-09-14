"""Current provider-facing wire for grounded scenario authoring.

The historical :class:`AuthoringResponse` model is intentionally not reused
for current provider calls.  That model is a durable compatibility surface
for saved authoring responses.  The current wire contains semantic choices
and request-local handles only; the adapter owns fixed action names, paths,
quotes, obligation references, and the other canonical representation.
"""

from __future__ import annotations

from typing import Any, Annotated, Literal, Union

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    create_model,
)

from asago_scenario_generator.models.canonical import ClosedCanonicalModel


CurrentAdversaryKind = Literal[
    "external_attacker",
    "malicious_customer",
    "third_party_via_content",
    "none",
]

CurrentTurnText = Annotated[StrictStr, Field(min_length=1)]


class CurrentAdversary(ClosedCanonicalModel):
    """The actor interpretation; reach and functional disposition are code-owned."""

    kind: CurrentAdversaryKind
    gain: StrictStr = Field(min_length=1)


class CurrentUserMessage(ClosedCanonicalModel):
    """One user message.  The role is supplied by the compiler."""

    kind: Literal["user_message"]
    text: StrictStr = Field(min_length=1)


class CurrentConversation(ClosedCanonicalModel):
    """A bounded user-only conversation; roles are supplied by the compiler."""

    kind: Literal["conversation"]
    turns: tuple[CurrentTurnText, ...] = Field(min_length=2, max_length=3)


CurrentStimulus = Annotated[
    Union[CurrentUserMessage, CurrentConversation], Field(discriminator="kind")
]


class CurrentLiteralOperand(ClosedCanonicalModel):
    """A literal value chosen by the author."""

    source: Literal["literal"]
    value: StrictStr | StrictInt | StrictFloat | StrictBool  # type: ignore[valid-type]


class CurrentStateFactOperand(ClosedCanonicalModel):
    """A value selected from one explained target-state handle."""

    source: Literal["state_fact"]
    fact_handle: StrictStr = Field(min_length=1)


class CurrentObservationOperand(ClosedCanonicalModel):
    """A value selected from one explained policy-observation handle."""

    source: Literal["observation"]
    observation_handle: StrictStr = Field(min_length=1)


CurrentOperand = Annotated[
    Union[
        CurrentLiteralOperand,
        CurrentStateFactOperand,
        CurrentObservationOperand,
    ],
    Field(discriminator="source"),
]


class CurrentStimulusEvidence(ClosedCanonicalModel):
    """Evidence selecting an exact authored user-turn source."""

    source: Literal["stimulus"]
    turn: StrictInt = Field(ge=1)
    meaning: StrictStr = Field(min_length=1)


class CurrentStateFactEvidence(ClosedCanonicalModel):
    """Evidence selecting an exact target-state fact handle."""

    source: Literal["state_fact"]
    fact_handle: StrictStr = Field(min_length=1)
    meaning: StrictStr = Field(min_length=1)


class CurrentObservationEvidence(ClosedCanonicalModel):
    """Evidence selecting an exact policy-observation handle."""

    source: Literal["observation"]
    observation_handle: StrictStr = Field(min_length=1)
    meaning: StrictStr = Field(min_length=1)


CurrentEvidence = Annotated[
    Union[
        CurrentStimulusEvidence,
        CurrentStateFactEvidence,
        CurrentObservationEvidence,
    ],
    Field(discriminator="source"),
]


class CurrentStimulusCondition(ClosedCanonicalModel):
    """Condition support taken from the authored stimulus."""

    condition: StrictInt = Field(ge=1)
    by: Literal["stimulus"]
    meaning: StrictStr = Field(min_length=1)


class CurrentStateFactCondition(ClosedCanonicalModel):
    """Condition support taken from one target-state fact handle."""

    condition: StrictInt = Field(ge=1)
    by: Literal["state_fact"]
    fact_handle: StrictStr = Field(min_length=1)
    meaning: StrictStr = Field(min_length=1)


class CurrentObservationCondition(ClosedCanonicalModel):
    """Condition support taken from one policy-observation handle."""

    condition: StrictInt = Field(ge=1)
    by: Literal["observation"]
    observation_handle: StrictStr = Field(min_length=1)
    meaning: StrictStr = Field(min_length=1)


CurrentCondition = Annotated[
    Union[
        CurrentStimulusCondition,
        CurrentStateFactCondition,
        CurrentObservationCondition,
    ],
    Field(discriminator="by"),
]


class CurrentClaimUnderTest(ClosedCanonicalModel):
    """An earlier-turn claim tied to one exact selected fact."""

    turn: StrictInt = Field(ge=1)
    fact_handle: StrictStr = Field(min_length=1)
    meaning: StrictStr = Field(min_length=1)


class CurrentToolArgumentCheck(ClosedCanonicalModel):
    """A tool-argument oracle; the fixed target tool comes from the context."""

    kind: Literal["tool_argument"]
    choice_handle: StrictStr = Field(min_length=1)
    argument: StrictStr = Field(min_length=1)
    operator: Literal[
        "equals",
        "not_equals",
        "greater_than",
        "less_than",
        "owner_differs_from_session",
    ]
    operand: CurrentOperand


class CurrentToolOrderCheck(ClosedCanonicalModel):
    """A tool-order oracle with an explicit reference-tool choice handle."""

    kind: Literal["tool_order"]
    choice_handle: StrictStr = Field(min_length=1)
    argument: StrictStr = Field(min_length=1)
    operator: Literal["equals", "not_equals", "greater_than", "less_than"]
    operand: CurrentOperand
    reference_tool_handle: StrictStr = Field(min_length=1)


class CurrentToolAbsentCheck(ClosedCanonicalModel):
    """A total-omission oracle with source-specific evidence selections."""

    kind: Literal["tool_absent"]
    choice_handle: StrictStr = Field(min_length=1)
    trigger: StrictStr = Field(min_length=1)
    trigger_evidence: tuple[CurrentEvidence, ...] = Field(min_length=1)


class CurrentResponseClaimCheck(ClosedCanonicalModel):
    """A reply-content oracle; the fixed reply action comes from the context."""

    kind: Literal["response_claim"]
    choice_handle: StrictStr = Field(min_length=1)
    proposition: StrictStr = Field(min_length=1)


CurrentUnsafeObservation = Annotated[
    Union[
        CurrentToolArgumentCheck,
        CurrentToolAbsentCheck,
        CurrentToolOrderCheck,
        CurrentResponseClaimCheck,
    ],
    Field(discriminator="kind"),
]


class CurrentScenarioDraft(ClosedCanonicalModel):
    """One current authoring answer before deterministic adaptation."""

    adversary: CurrentAdversary
    stimulus: CurrentStimulus
    unsafe_observation: CurrentUnsafeObservation
    conditions_established: tuple[CurrentCondition, ...] = ()
    claims_under_test: tuple[CurrentClaimUnderTest, ...] = ()
    safe_behaviors: tuple[StrictStr, ...] = ()


class CurrentScenariosResult(ClosedCanonicalModel):
    """A nonempty authored result carries no no-scenario bookkeeping."""

    kind: Literal["scenarios"]
    scenarios: tuple[CurrentScenarioDraft, ...] = Field(min_length=1, max_length=3)


class CurrentNoScenarioResult(ClosedCanonicalModel):
    """An explicit no-scenario decision requires meaningful explanatory text."""

    kind: Literal["no_scenario"]
    reason: Annotated[StrictStr, Field(min_length=1, pattern=r"\S")]


class CurrentAuthoringResponse(ClosedCanonicalModel):
    """One closed outcome, with durable bookkeeping derived after decoding."""

    result: Annotated[
        CurrentScenariosResult | CurrentNoScenarioResult, Field(discriminator="kind")
    ]

    @property
    def scenarios(self) -> tuple[CurrentScenarioDraft, ...]:
        """Expose the existing adapter view without another provider field."""
        return (
            self.result.scenarios
            if isinstance(self.result, CurrentScenariosResult)
            else ()
        )

    @property
    def no_scenario_reason(self) -> str | None:
        """Derive the durable null for a successful response in code."""
        return (
            self.result.reason
            if isinstance(self.result, CurrentNoScenarioResult)
            else None
        )


def _literal(values: tuple[Any, ...]) -> Any:
    """Build one non-empty request-local literal type."""
    if not values:
        raise ValueError("a bound provider schema requires at least one choice")
    return Literal[values]  # type: ignore[index]


def _discriminated_union(types: list[type[Any]], discriminator: str) -> Any:
    """Return a direct type for one variant or a closed discriminated union."""
    if not types:
        raise ValueError(f"no provider variants available for {discriminator}")
    if len(types) == 1:
        return types[0]
    return Annotated[Union[tuple(types)], Field(discriminator=discriminator)]


def _bound_model(
    base: type[Any],
    name: str,
    fields: dict[str, tuple[Any, Any]],
) -> type[Any]:
    """Create a provider model with context-specific literal fields."""
    return create_model(name, __base__=base, **fields)


def _plain_union(types: list[type[Any]]) -> Any:
    """Return a structural union when duplicate ``kind`` tags are needed.

    Context-bound branches each carry a literal ``kind`` plus a literal
    choice/operator.  They therefore cannot share the base union's ``kind``
    discriminator (which requires unique tags), but Pydantic's ordinary union
    still validates each branch and emits an explicit ``anyOf`` schema.
    """
    if not types:
        raise ValueError("a provider schema requires at least one branch")
    if len(types) == 1:
        return types[0]
    return Union[tuple(types)]


def current_authoring_response_model(context: Any) -> type[CurrentAuthoringResponse]:
    """Build the closed provider schema for one request-local context.

    The public :class:`CurrentAuthoringResponse` is the unbound current
    model used for parsing. Live calls use this derived subclass so
    the emitted schema contains only the compiling oracle kinds, choice
    handles, action arguments, reference tools, and source handles available
    in this request.  The adapter still rechecks every binding after parsing.
    """
    checks_by_kind = context.checks_by_kind
    fact_handles = tuple(source.handle for source in context.state_handles)
    observation_handles = tuple(source.handle for source in context.observation_handles)
    action_arguments = tuple(context.candidate.action_binding.argument_names)
    subject_model = context.subject_model
    if subject_model is None:
        owner_arguments = action_arguments
    else:
        owner_arguments = tuple(
            argument
            for argument in action_arguments
            if subject_model.role_for(context.candidate.action_name, argument)
            is not None
        )

    operand_models: dict[str, type[Any]] = {
        "literal": CurrentLiteralOperand,
    }
    if fact_handles:
        operand_models["state_fact"] = _bound_model(
            CurrentStateFactOperand,
            "CurrentStateFactOperandForContext",
            {"fact_handle": (_literal(fact_handles), ...)},
        )
        numeric_fact_handles = tuple(
            source.handle for source in context.state_handles if source.numeric
        )
        if numeric_fact_handles:
            operand_models["state_fact_numeric"] = _bound_model(
                CurrentStateFactOperand,
                "CurrentNumericStateFactOperandForContext",
                {"fact_handle": (_literal(numeric_fact_handles), ...)},
            )
    if observation_handles:
        operand_models["observation"] = _bound_model(
            CurrentObservationOperand,
            "CurrentObservationOperandForContext",
            {"observation_handle": (_literal(observation_handles), ...)},
        )
        numeric_observation_handles = tuple(
            source.handle for source in context.observation_handles if source.numeric
        )
        if numeric_observation_handles:
            operand_models["observation_numeric"] = _bound_model(
                CurrentObservationOperand,
                "CurrentNumericObservationOperandForContext",
                {"observation_handle": (_literal(numeric_observation_handles), ...)},
            )

    def operand_type(sources: tuple[str, ...]) -> Any:
        variants: list[type[Any]] = []
        for source in sources:
            model = operand_models.get(source)
            if model is not None:
                variants.append(model)
        if not variants:
            raise ValueError("an admissible operand has no available source")
        return _discriminated_union(variants, "source")

    def operator_operand_sources(
        choice: Any,
        operator: str,
    ) -> tuple[str, ...]:
        """Restrict one operator to the source variants it can compile.

        The context records the broad sources admitted for a check.  Numeric
        operators additionally require a numeric state/observation handle,
        while the owner relation requires a literal record address.  These
        restrictions are represented by actual typed branch models below so
        local Pydantic decoding and the provider schema enforce the same
        contract.
        """
        available = set(choice.operand_sources)
        if operator in {"greater_than", "less_than"}:
            sources: list[str] = []
            if "state_fact" in available and "state_fact_numeric" in operand_models:
                sources.append("state_fact_numeric")
            if "observation" in available and "observation_numeric" in operand_models:
                sources.append("observation_numeric")
            return tuple(sources)
        if operator == "owner_differs_from_session":
            return ("record_address",) if "literal" in available else ()
        return tuple(
            source
            for source in ("literal", "state_fact", "observation")
            if source in available
        )

    def branch_name(
        kind: str,
        choice_index: int,
        operator: str | None = None,
        reference_index: int | None = None,
    ) -> str:
        """Give each bound branch a stable, readable schema definition name."""
        stem = "".join(part.title() for part in kind.split("_"))
        if choice_index == 0 and operator is None and reference_index is None:
            return f"Current{stem}CheckForContext"
        if (
            choice_index == 0
            and operator == "equals"
            and (reference_index is None or reference_index == 0)
        ):
            return f"Current{stem}CheckForContext"
        choice_suffix = f"Choice{choice_index + 1}"
        operator_suffix = (
            "".join(part.title() for part in operator.split("_"))
            if operator is not None
            else ""
        )
        reference_suffix = (
            f"Reference{reference_index + 1}" if reference_index is not None else ""
        )
        return (
            f"Current{stem}Check{choice_suffix}{operator_suffix}"
            f"{reference_suffix}ForContext"
        )

    unsafe_variants: list[type[Any]] = []
    operand_models["record_address"] = _bound_model(
        CurrentLiteralOperand,
        "CurrentRecordAddressOperandForContext",
        {"value": (StrictStr, ...)},
    )
    evidence_variants: list[type[Any]] = [CurrentStimulusEvidence]
    if fact_handles:
        evidence_variants.append(
            _bound_model(
                CurrentStateFactEvidence,
                "CurrentStateFactEvidenceForContext",
                {"fact_handle": (_literal(fact_handles), ...)},
            )
        )
    if observation_handles:
        evidence_variants.append(
            _bound_model(
                CurrentObservationEvidence,
                "CurrentObservationEvidenceForContext",
                {
                    "observation_handle": (
                        _literal(observation_handles),
                        ...,
                    )
                },
            )
        )
    evidence_type = _discriminated_union(evidence_variants, "source")

    # Each branch fixes one choice and, for tool checks, one operator.  The
    # ordinary union at ``unsafe_observation`` is deliberate: all branches
    # retain the same ``kind`` tag, while their literal choice/operator fields
    # make the branch identity unambiguous to both Pydantic and the provider.
    for kind, base in (
        ("tool_argument", CurrentToolArgumentCheck),
        ("tool_order", CurrentToolOrderCheck),
        ("tool_absent", CurrentToolAbsentCheck),
        ("response_claim", CurrentResponseClaimCheck),
    ):
        for choice_index, choice in enumerate(checks_by_kind.get(kind, ())):
            if kind == "tool_argument":
                for operator in choice.operators:
                    sources = operator_operand_sources(choice, operator)
                    if not sources:
                        continue
                    arguments = (
                        owner_arguments
                        if operator == "owner_differs_from_session"
                        else action_arguments
                    )
                    if not arguments:
                        continue
                    unsafe_variants.append(
                        _bound_model(
                            base,
                            branch_name(kind, choice_index, operator),
                            {
                                "choice_handle": (_literal((choice.handle,)), ...),
                                "argument": (_literal(arguments), ...),
                                "operator": (_literal((operator,)), ...),
                                "operand": (operand_type(sources), ...),
                            },
                        )
                    )
            elif kind == "tool_order":
                for operator in choice.operators:
                    sources = operator_operand_sources(choice, operator)
                    if not sources:
                        continue
                    for reference_index, reference in enumerate(choice.reference_tools):
                        if not reference.shared_arguments:
                            continue
                        unsafe_variants.append(
                            _bound_model(
                                base,
                                branch_name(
                                    kind,
                                    choice_index,
                                    operator,
                                    reference_index,
                                ),
                                {
                                    "choice_handle": (
                                        _literal((choice.handle,)),
                                        ...,
                                    ),
                                    "argument": (
                                        _literal(reference.shared_arguments),
                                        ...,
                                    ),
                                    "operator": (_literal((operator,)), ...),
                                    "operand": (operand_type(sources), ...),
                                    "reference_tool_handle": (
                                        _literal((reference.handle,)),
                                        ...,
                                    ),
                                },
                            )
                        )
            elif kind == "tool_absent":
                unsafe_variants.append(
                    _bound_model(
                        base,
                        branch_name(kind, choice_index),
                        {
                            "choice_handle": (_literal((choice.handle,)), ...),
                            "trigger_evidence": (tuple[evidence_type, ...], ...),
                        },
                    )
                )
            else:
                unsafe_variants.append(
                    _bound_model(
                        base,
                        branch_name(kind, choice_index),
                        {"choice_handle": (_literal((choice.handle,)), ...)},
                    )
                )

    if not unsafe_variants:
        # A candidate with no admissible check can only return the typed
        # no-scenario response. The actual schema carries only that branch;
        # no empty scenario list or unused nullable field is requested.
        return create_model(
            "CurrentAuthoringResponseForContext",
            __base__=CurrentAuthoringResponse,
            result=(CurrentNoScenarioResult, ...),
        )

    unsafe_type = _plain_union(unsafe_variants)

    condition_indices = tuple(range(1, len(context.candidate.applies_when) + 1))
    if condition_indices:
        condition_variants: list[type[Any]] = [
            _bound_model(
                CurrentStimulusCondition,
                "CurrentStimulusConditionForContext",
                {"condition": (_literal(condition_indices), ...)},
            )
        ]
        if fact_handles:
            condition_variants.append(
                _bound_model(
                    CurrentStateFactCondition,
                    "CurrentStateFactConditionForContext",
                    {
                        "condition": (_literal(condition_indices), ...),
                        "fact_handle": (_literal(fact_handles), ...),
                    },
                )
            )
        if observation_handles:
            condition_variants.append(
                _bound_model(
                    CurrentObservationCondition,
                    "CurrentObservationConditionForContext",
                    {
                        "condition": (_literal(condition_indices), ...),
                        "observation_handle": (_literal(observation_handles), ...),
                    },
                )
            )
        condition_type = _discriminated_union(condition_variants, "by")
        conditions_field = tuple[condition_type, ...]
    else:
        conditions_field = tuple[()]

    scenario_fields: dict[str, tuple[Any, Any]] = {
        "stimulus": (
            CurrentStimulus if context.conversation_allowed else CurrentUserMessage,
            ...,
        ),
        "unsafe_observation": (unsafe_type, ...),
        "conditions_established": (conditions_field, ()),
    }
    if fact_handles:
        claim_type = _bound_model(
            CurrentClaimUnderTest,
            "CurrentClaimUnderTestForContext",
            {"fact_handle": (_literal(fact_handles), ...)},
        )
        scenario_fields["claims_under_test"] = (tuple[claim_type, ...], ())
    else:
        scenario_fields["claims_under_test"] = (tuple[()], ())
    scenario_type = _bound_model(
        CurrentScenarioDraft,
        "CurrentScenarioDraftForContext",
        scenario_fields,
    )
    scenarios_result = _bound_model(
        CurrentScenariosResult,
        "CurrentScenariosResultForContext",
        {"scenarios": (tuple[scenario_type, ...], Field(min_length=1, max_length=3))},
    )
    return create_model(
        "CurrentAuthoringResponseForContext",
        __base__=CurrentAuthoringResponse,
        result=(
            _discriminated_union([scenarios_result, CurrentNoScenarioResult], "kind"),
            ...,
        ),
    )


__all__ = [
    "CurrentAdversary",
    "CurrentAdversaryKind",
    "CurrentAuthoringResponse",
    "CurrentScenariosResult",
    "CurrentNoScenarioResult",
    "CurrentClaimUnderTest",
    "CurrentCondition",
    "CurrentConversation",
    "CurrentEvidence",
    "CurrentLiteralOperand",
    "CurrentObservationCondition",
    "CurrentObservationEvidence",
    "CurrentObservationOperand",
    "CurrentOperand",
    "CurrentResponseClaimCheck",
    "CurrentScenarioDraft",
    "CurrentStateFactCondition",
    "CurrentStateFactEvidence",
    "CurrentStateFactOperand",
    "CurrentStimulus",
    "CurrentStimulusCondition",
    "CurrentStimulusEvidence",
    "CurrentToolAbsentCheck",
    "CurrentToolArgumentCheck",
    "CurrentToolOrderCheck",
    "CurrentTurnText",
    "CurrentUnsafeObservation",
    "CurrentUserMessage",
    "current_authoring_response_model",
]

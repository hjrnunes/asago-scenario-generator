"""Versioned scenario handoff: narrative + attack path + Gherkin + metadata.

The handoff is the producer's normal publication. It is a versioned envelope
over the three existing scenario representations plus necessary metadata. It
is **not** a fourth authoritative scenario DSL and **not** an execution
projection under new field names.

The producer owns scenario meaning: what protected behavior can fail, why,
what is known, what distinguishes failure from acceptable behavior. The
artifact generator owns test design: concrete stimulus, setup selection,
environment bindings, delivery, executable detector and judge prompts.
This module therefore *excludes* prepared messages, prepared histories,
role/turn arrays, delivery routes, oracle selections, detector expressions,
judge prompts and executable setup — structurally and in prose. Every
exclusion is verified by :func:`handoff_ownership_violations`, which is the
ownership boundary enforced by the negative tests.

Schema version: the producer publishes :class:`ScenarioHandoffV5`
(:data:`HANDOFF_SCHEMA_VERSION_V5`), whose fields beyond the shared envelope
``handoff_v5`` derives. The kit lives in
``data/contracts/scenario-handoff/handoff-v5/``, and the consumer vendors it
byte-for-byte, the same discipline as ``data/contracts/target-profile/``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializationInfo,
    SerializerFunctionWrapHandler,
    StrictStr,
    ValidationError,
    field_validator,
    model_serializer,
    model_validator,
)

from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.stpa.discriminating_condition import (
    ConditionCheck,
    DiscriminatingCondition,
)
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
    render_feature_text,
)
from asago_scenario_generator.stpa.observation_contract import (
    OBSERVATION_CONTRACT_SCHEMA,
    FailureCall,
    ObservationAssessment,
    ObservationCriterion,
    SafeObservableOutcome,
)
from asago_scenario_generator.stpa.models.attack_shape import (
    AttackShape,
    default_attack_shape,
)
from asago_scenario_generator.stpa.scenario_prod.deduplication import (
    ScenarioDeduplication,
)
from asago_scenario_generator.stpa.scenario_prod.tool_call_binding import (
    bind_tool_call_condition,
)
from asago_scenario_generator.stpa.tool_call_condition import (
    TOOL_CALL_CONDITION_BOUND,
    ToolCallCondition,
    ToolCallConditionStatus,
)

HANDOFF_SCHEMA_VERSION_V5 = "scenario-handoff-v5"
HANDOFF_DIGEST_DOMAIN_V5 = "scenario-handoff-v5"
OPERATION_AUTHORITY_CRITERION = "criterion_observed_operation"
OPERATION_AUTHORITY_ENRICHMENT = "verified_control_action_specialization"
OPERATION_AUTHORITY_SAFE_OUTCOME = "safe_observable_outcome_operation"

HYPOTHESIS_FRAMING = (
    "Test hypothesis — a proposed account of how this use case can fail, not "
    "an observed execution result. The producer makes no execution claim."
)

#: The ownership boundary is scenario-handoff contract data: the consumer
#: mirrors this file byte for byte and enforces the same list.
OWNERSHIP_RULES_PATH = (
    DATA_ROOT / "contracts" / "scenario-handoff" / "ownership-rules.json"
)
_REGEX_FLAGS = {"IGNORECASE": re.IGNORECASE}


def load_ownership_rules(
    path: Path,
) -> tuple[frozenset[str], tuple[tuple[str, re.Pattern[str]], ...]]:
    """Read forbidden keys and ``(code, pattern)`` prose rules from one rules file.

    Keys are field names only artifact design may own, at any depth. Each
    pattern's code is the ``prose_hiding:<code>`` violation it reports; the
    file order is the report order.
    """
    rules = json.loads(path.read_text(encoding="utf-8"))
    patterns = []
    for entry in rules["forbidden_value_patterns"]:
        unknown = sorted(set(entry["flags"]) - _REGEX_FLAGS.keys())
        if unknown:
            raise ValueError(
                f"ownership rule {entry['code']} has unknown flags: {unknown}"
            )
        flags = 0
        for name in entry["flags"]:
            flags |= _REGEX_FLAGS[name]
        patterns.append((entry["code"], re.compile(entry["pattern"], flags)))
    return frozenset(rules["forbidden_keys"]), tuple(patterns)


_FORBIDDEN_KEYS, _FORBIDDEN_VALUE_PATTERNS = load_ownership_rules(OWNERSHIP_RULES_PATH)


class HandoffModel(BaseModel):
    """Strict base for handoff documents: unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid")


class HandoffLineage(HandoffModel):
    """Stable identity plus loss/hazard/constraint lineage."""

    loss_ids: list[str] = Field(default_factory=list)
    hazard_ids: list[str] = Field(default_factory=list)
    constraint_ids: list[str] = Field(default_factory=list)
    ica_slot_id: str = ""
    ica_id: str | None = None
    controller_id: str = ""
    control_action_id: str = ""


class HandoffRule(HandoffModel):
    """One governing rule the unsafe behavior would violate."""

    constraint_id: str
    statement: StrictStr

    @field_validator("statement")
    @classmethod
    def _strip_statement(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("governing rule statement must not be blank")
        return stripped


class HandoffOperation(HandoffModel):
    """A documented operation named only when it is supported and relevant."""

    name: str
    relevance: StrictStr
    # None when no authority is recorded for the name; the published schema
    # keeps the field optional.
    authority: (
        Literal[
            OPERATION_AUTHORITY_CRITERION,
            OPERATION_AUTHORITY_ENRICHMENT,
            OPERATION_AUTHORITY_SAFE_OUTCOME,
        ]
        | None
    ) = None


class HandoffFact(HandoffModel):
    """One source-grounded fact with its authority stamp."""

    statement: StrictStr
    source: StrictStr
    authority: str


class HandoffObservation(HandoffModel):
    """Testability metadata without a target result or gold expectation."""

    contract_schema: StrictStr
    contract_id: StrictStr
    contract_digest: StrictStr
    criteria: list[ObservationCriterion] = Field(min_length=1)
    assessment: ObservationAssessment


class HandoffGherkin(HandoffModel):
    """Declarative Gherkin: no bindings, no prompt, no detector code."""

    feature: str
    scenario: str
    given: list[str] = Field(default_factory=list)
    when: list[str] = Field(default_factory=list)
    then_expected: list[str] = Field(default_factory=list)
    then_unsafe_alternative: list[str] = Field(default_factory=list)

    def to_feature_text(self) -> str:
        """Render the declarative spec to Gherkin ``.feature`` text."""
        return render_feature_text(
            self.feature,
            self.scenario,
            self.given,
            self.when,
            self.then_expected,
            self.then_unsafe_alternative,
        )


_TOOL_CALL_CONDITION_PAIRING: dict[str, Any] = {
    "if": {
        "properties": {
            "tool_call_condition_status": {
                "properties": {"status": {"const": TOOL_CALL_CONDITION_BOUND}}
            }
        }
    },
    "then": {
        "required": ["tool_call_condition"],
        "properties": {"tool_call_condition": {"type": "object"}},
    },
    "else": {"properties": {"tool_call_condition": {"type": "null"}}},
}


class _HandoffHead(HandoffModel):
    """The handoff fields before the attack path.

    Pydantic orders inherited fields by base class, so the envelope is built
    from this head, ``_HandoffPath``, and ``_HandoffTail``; the committed
    schema.json pins that field order.
    """

    schema_version: str
    scenario_id: str
    scenario_version: int = 1
    kind: Literal["adversarial", "functional"]
    hypothesis_framing: str
    narrative: str

    @field_validator("narrative", "hypothesis_framing")
    @classmethod
    def _require_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("handoff text field must not be blank")
        return value


HandoffText = Annotated[StrictStr, Field(min_length=1, pattern=r"\S")]


#: Each handoff taxonomy scheme and the ids that belong to it.
_TAXONOMY_ID_PATTERNS = {"owasp-llm": r"^LLM\d{2}$", "owasp-asi": r"^ASI\d{2}$"}


class HandoffTaxonomyRef(HandoffModel):
    """One OWASP Top 10 entry a scenario's losses map to, in its edition.

    The id belongs to the scheme: ``LLMnn`` under ``owasp-llm``, ``ASInn``
    under ``owasp-asi``. The schema states the pairing with one if/then block
    per scheme.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"scheme": {"const": scheme}},
                        "required": ["scheme"],
                    },
                    "then": {"properties": {"id": {"pattern": pattern}}},
                }
                for scheme, pattern in _TAXONOMY_ID_PATTERNS.items()
            ]
        },
    )

    scheme: Literal["owasp-llm", "owasp-asi"]
    edition: Annotated[StrictStr, Field(pattern=r"^\d{4}$")]
    id: Annotated[StrictStr, Field(pattern=r"^(LLM|ASI)\d{2}$")]
    name: HandoffText

    @model_validator(mode="after")
    def validate_scheme_id(self) -> Self:
        """Keep each id under the scheme it belongs to."""

        if not re.match(_TAXONOMY_ID_PATTERNS[self.scheme], self.id):
            raise ValueError(
                f"taxonomy id {self.id!r} does not belong to scheme {self.scheme!r}"
            )
        return self


class HandoffTaxonomy(HandoffModel):
    """The ATLAS release the procedure cites and the scenario's OWASP references.

    The references are the OWASP tags of the policy risks the scenario's
    lineage losses came from, sorted by scheme and id, each once.
    """

    atlas_release: Annotated[StrictStr, Field(pattern=r"^\d{4}\.\d{2}$")]
    references: tuple[HandoffTaxonomyRef, ...] = ()

    @model_validator(mode="after")
    def validate_reference_order(self) -> Self:
        """Keep one reference per entry, in (scheme, id) order."""

        keys = [(ref.scheme, ref.id) for ref in self.references]
        if keys != sorted(set(keys)):
            raise ValueError(
                "taxonomy references must be sorted by scheme and id, each once"
            )
        return self


@dataclass(frozen=True)
class HandoffTaxonomyInputs:
    """What the pipeline knows about a run's taxonomies, for each handoff.

    ``references_by_loss`` maps each loss id to the OWASP references of the
    risks it came from; a handoff takes the union over its lineage losses.
    """

    atlas_release: str
    references_by_loss: Mapping[str, tuple[HandoffTaxonomyRef, ...]]


class _HandoffTail(HandoffModel):
    """The handoff fields after the attack path."""

    gherkin: HandoffGherkin
    semantic_failure_criterion: StrictStr
    semantic_failure_call: FailureCall | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description=(
            "The call the semantic failure criterion is about: its exact "
            "operation, and whether the failure is an incorrect call of it "
            "(incorrect_call) or that it is not called (missing_call). Absent "
            "when the criterion states no such call."
        ),
    )
    safe_alternative: StrictStr
    safe_observable_outcome: SafeObservableOutcome | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    deduplication: ScenarioDeduplication | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    governing_rules: list[HandoffRule] = Field(default_factory=list)
    lineage: HandoffLineage
    documented_operations: list[HandoffOperation] = Field(default_factory=list)
    sourced_facts: list[HandoffFact] = Field(default_factory=list)
    assumptions_and_unknowns: list[str] = Field(default_factory=list)
    observation: HandoffObservation | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    content_digest: str = ""
    discriminating_condition: DiscriminatingCondition | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    condition_check: ConditionCheck | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    condition_omitted_reason: StrictStr | None = Field(
        default=None,
        min_length=1,
        exclude_if=lambda value: value is None,
    )
    tool_call_condition_status: ToolCallConditionStatus
    tool_call_condition: ToolCallCondition | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    attack_shape: AttackShape | None = Field(
        description=(
            "Object for adversarial scenarios; null for functional scenarios. "
            "Required, so a producer must decide."
        ),
    )
    taxonomy: HandoffTaxonomy | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description=(
            "The ATLAS release and the OWASP 2026 references of the scenario's "
            "lineage losses. Absent when the producer did not supply them."
        ),
    )

    @field_validator("semantic_failure_criterion", "safe_alternative")
    @classmethod
    def _require_criterion_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("handoff text field must not be blank")
        return value

    @model_validator(mode="after")
    def validate_condition_fields(self) -> Self:
        """Keep the condition, its check, and an omission note consistent."""

        if (self.discriminating_condition is None) != (self.condition_check is None):
            raise ValueError(
                "discriminating_condition and condition_check are present together"
            )
        if (
            self.discriminating_condition is not None
            and self.condition_omitted_reason is not None
        ):
            raise ValueError(
                "condition_omitted_reason applies only when no condition is published"
            )
        return self

    @model_validator(mode="after")
    def validate_tool_call_condition(self) -> Self:
        """Publish a tool-call condition exactly when the status is bound."""

        bound = self.tool_call_condition_status.status == TOOL_CALL_CONDITION_BOUND
        if bound != (self.tool_call_condition is not None):
            raise ValueError(
                "tool_call_condition is present exactly when "
                "tool_call_condition_status is bound"
            )
        return self

    @model_validator(mode="after")
    def validate_attack_shape_kind(self) -> Self:
        """R7: an adversarial scenario has a shape and a functional one has none."""

        if (self.kind == "adversarial") != (self.attack_shape is not None):
            raise ValueError(
                "R7: attack_shape is an object exactly when kind is adversarial"
            )
        return self


#: Handbook Table 2.3 column names (Leveson and Thomas 2018) for ``uca.type``.
UcaType = Literal[
    "not-providing-causes-hazard",
    "providing-causes-hazard",
    "too-early-too-late-or-out-of-order",
    "stopped-too-soon-or-applied-too-long",
]
ProcedureChannel = Literal["tool_data", "user_turn", "forged_history"]
StepId = Annotated[StrictStr, Field(pattern=r"^S\d{2}$")]


class HandoffHazard(HandoffModel):
    """One hazard the unsafe control action leads to."""

    hazard_id: HandoffText
    description: HandoffText


class HandoffUca(HandoffModel):
    """The unsafe control action in the STPA Handbook's five-part form."""

    source: HandoffText
    type: UcaType
    control_action: HandoffText
    context: HandoffText
    statement: HandoffText
    hazards: list[HandoffHazard] = Field(min_length=1)


class HandoffActor(HandoffModel):
    """The misuser of an adversarial scenario: who, and what they want."""

    profile: HandoffText
    goal: HandoffText


class HandoffProcessModelVariable(HandoffModel):
    """The process-model variable that holds a stated flawed belief.

    ``id`` is ``null`` for a gap: no variable of the selected path holds the
    belief, and ``description`` describes the variable the controller would
    need.
    """

    id: Annotated[StrictStr, Field(pattern=r"^PM-\d+-\d+$")] | None
    description: HandoffText


class HandoffCausalFactor(HandoffModel):
    """One causal factor: the flawed process-model belief and its flaw."""

    source_id: HandoffText
    process_model_belief: HandoffText | None
    flaw: HandoffText
    process_model_variable: HandoffProcessModelVariable | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description=(
            "Present when process_model_belief states the controller's flawed "
            "belief: the variable that holds it, or a gap (id null) whose "
            "description names the variable the controller would need."
        ),
    )


class HandoffAtlasRef(HandoffModel):
    """One MITRE ATLAS tactic or technique."""

    id: Annotated[StrictStr, Field(pattern=r"^AML\.TA?\d{4}(\.\d{3})?$")]
    name: HandoffText


class HandoffProcedureStep(HandoffModel):
    """One step of the attack procedure, with its ATLAS tactic and technique."""

    step_id: StepId
    leads_to: list[StepId] = Field(max_length=1)
    tactic: HandoffAtlasRef | None
    technique: HandoffAtlasRef | None
    description: HandoffText
    channel: ProcedureChannel


PathNodeId = Annotated[StrictStr, Field(pattern=r"^AP-[A-Z]+(-[1-9]\d*)?$")]
PathCategory = Literal["situation", "attacker_assumption", "weak_point"]
PathEvidenceStatus = Literal[
    "structural_failure", "reachable_capability", "bounded_assumption"
]


def _omit_none(**extra: Any) -> Any:
    """Return a field that is absent from the published object when it is None."""
    return Field(default=None, exclude_if=lambda value: value is None, **extra)


class AttackPathAttacker(HandoffModel):
    """Who the attacker is, what they want, and their plan."""

    profile: HandoffText
    goal: HandoffText | None = _omit_none()
    plan: list[HandoffText]


class AttackPathCondition(HandoffModel):
    """One condition that must hold: the situation, an assumption, or a weak point."""

    node_id: PathNodeId
    category: PathCategory
    label: HandoffText
    source_ids: list[HandoffText]
    evidence_status: PathEvidenceStatus | None = _omit_none()
    belief: HandoffText | None = _omit_none()


class AttackPathStep(HandoffModel):
    """One attack step, with its ATLAS technique and the asset it touches."""

    node_id: Annotated[StrictStr, Field(pattern=r"^AP-STEP-[1-9]\d*$")]
    label: HandoffText
    technique_id: HandoffText | None = _omit_none()
    technique: HandoffText | None = _omit_none()
    asset: HandoffText | None = _omit_none()


class AttackPathSource(HandoffModel):
    """A source id and its text: a violated constraint, a hazard, or a loss."""

    source_id: HandoffText
    label: HandoffText


class AttackPathUnsafeAction(HandoffModel):
    """The unsafe control action and the constraints it violates."""

    node_id: Literal["AP-UCA"]
    label: HandoffText
    source_ids: list[HandoffText]
    violates: list[AttackPathSource]


class AttackPathFailure(HandoffModel):
    """The observable failure and the outcome that would have been safe."""

    node_id: Literal["AP-FAIL"]
    label: HandoffText
    safe_outcome: HandoffText | None = _omit_none()


class AttackPathHazard(HandoffModel):
    """The hazard the scenario reaches, with the losses it leads to."""

    node_id: Literal["AP-HAZ"]
    label: HandoffText
    source_ids: list[HandoffText]
    hazards: list[AttackPathSource]
    losses: list[AttackPathSource]


class AttackPath(HandoffModel):
    """One scenario's route to its hazard, in the order it happens.

    An adversarial scenario names its attacker and steps; a functional one has
    neither. The node ids are what the authoring model cites.
    """

    format: Literal["attack-path-v1"]
    attacker: AttackPathAttacker | None = _omit_none()
    conditions: list[AttackPathCondition]
    steps: list[AttackPathStep]
    unsafe_action: AttackPathUnsafeAction
    observable_failure: AttackPathFailure
    hazard: AttackPathHazard
    source_uncertainty: HandoffText | None = _omit_none()


class _HandoffPath(HandoffModel):
    """The scenario's attack path."""

    attack_path: AttackPath


class ScenarioHandoffV5(_HandoffTail, _HandoffPath, _HandoffHead):
    """The versioned scenario handoff envelope (v5).

    v5 carries the scenario's ``attack_path`` where v4 carries its
    ``attack_tree``, keeps every other v4 field, and adds ``uca``, ``actor``,
    ``causal_factors``, ``preconditions``, ``procedure`` and
    ``worst_case_threat``. ``actor`` is an object for ``kind: adversarial`` and
    ``null`` for ``kind: functional``; a functional scenario has no
    preconditions and no procedure.
    """

    model_config = ConfigDict(
        extra="forbid",
        title="ScenarioHandoff",
        json_schema_extra={
            "allOf": [
                _TOOL_CALL_CONDITION_PAIRING,
                {
                    "if": {
                        "properties": {"kind": {"const": "adversarial"}},
                        "required": ["kind"],
                    },
                    "then": {
                        "properties": {
                            "attack_shape": {"type": "object"},
                            "actor": {"type": "object"},
                            "procedure": {"minItems": 1},
                        }
                    },
                    "else": {
                        "properties": {
                            "attack_shape": {"type": "null"},
                            "actor": {"type": "null"},
                            "procedure": {"maxItems": 0},
                            "preconditions": {"maxItems": 0},
                        }
                    },
                },
            ]
        },
    )

    schema_version: Literal["scenario-handoff-v5"] = HANDOFF_SCHEMA_VERSION_V5  # type: ignore[assignment]
    uca: HandoffUca
    actor: HandoffActor | None
    causal_factors: list[HandoffCausalFactor] = Field(min_length=1)
    preconditions: list[HandoffText]
    procedure: list[HandoffProcedureStep]
    worst_case_threat: HandoffText

    @model_validator(mode="after")
    def validate_v5_kind(self) -> "ScenarioHandoffV5":
        """An adversarial scenario has an actor and a procedure; a functional one neither."""

        if self.kind == "adversarial":
            if self.actor is None or not self.procedure:
                raise ValueError(
                    "an adversarial v5 handoff has an actor and a procedure"
                )
        elif self.actor is not None or self.procedure or self.preconditions:
            raise ValueError(
                "a functional v5 handoff has a null actor, no preconditions "
                "and no procedure"
            )
        return self

    @model_validator(mode="after")
    def validate_procedure_chain(self) -> "ScenarioHandoffV5":
        """Number the steps S00, S01, ... and link each to the next."""

        ids = [f"S{index:02d}" for index in range(len(self.procedure))]
        for index, step in enumerate(self.procedure):
            if step.step_id != ids[index]:
                raise ValueError(f"procedure step {index} must be {ids[index]}")
            expected = ids[index + 1 : index + 2]
            if step.leads_to != expected:
                raise ValueError(
                    f"procedure step {step.step_id} must lead to {expected}"
                )
            if (step.tactic is None) != (step.technique is None):
                raise ValueError(
                    f"procedure step {step.step_id} names a tactic exactly when "
                    "it names a technique"
                )
        return self

    @model_serializer(mode="wrap")
    def _serialize_keeping_null_shape(
        self, handler: SerializerFunctionWrapHandler, info: SerializationInfo
    ) -> dict[str, Any]:
        """Keep the required nulls when ``exclude_none`` is set.

        The shape's keys are all required, so a dump that drops a null breaks
        both validation and the digest. Handoffs are dumped with
        ``exclude_none`` elsewhere; these fields are the places that must not be.
        """

        data = handler(self)
        shape = self.attack_shape
        data["attack_shape"] = (
            None if shape is None else shape.model_dump(mode=info.mode)
        )
        data["actor"] = (
            None if self.actor is None else self.actor.model_dump(mode=info.mode)
        )
        data["causal_factors"] = [
            item.model_dump(mode=info.mode) for item in self.causal_factors
        ]
        data["procedure"] = [item.model_dump(mode=info.mode) for item in self.procedure]
        return {name: data[name] for name in type(self).model_fields if name in data}


#: The published handoff.
ScenarioHandoff = ScenarioHandoffV5


def handoff_payload_digest(payload: dict[str, Any]) -> str:
    """Return the framed content digest for a handoff payload."""
    version = payload.get("schema_version")
    if version != HANDOFF_SCHEMA_VERSION_V5:
        raise ValueError(f"unsupported scenario handoff schema_version: {version!r}")
    return compute_framed_digest(HANDOFF_DIGEST_DOMAIN_V5, payload)


def finalize_handoff(handoff: ScenarioHandoff) -> ScenarioHandoff:
    """Return the handoff with its content digest computed and verified."""
    payload = handoff.model_dump(mode="json", exclude_none=True)
    payload.pop("content_digest", None)
    digest = handoff_payload_digest(payload)
    if handoff.content_digest and handoff.content_digest != digest:
        raise ValueError("scenario handoff content_digest does not match its content")
    return handoff.model_copy(update={"content_digest": digest})


def verify_handoff_digest(handoff: ScenarioHandoff) -> None:
    """Fail closed when a handoff's recorded digest does not match its bytes."""
    payload = handoff.model_dump(mode="json", exclude_none=True)
    payload.pop("content_digest", None)
    if handoff.content_digest != handoff_payload_digest(payload):
        raise ValueError("scenario handoff content_digest does not match its content")


def _iter_strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    """Yield ``(path, text)`` for every mapping key and string scalar."""
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found.append((f"{path}.{key}", str(key)))
            found.extend(_iter_strings(item, f"{path}.{key}"))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(_iter_strings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        found.append((path, value))
    return found


def handoff_ownership_violations(payload: dict[str, Any]) -> list[str]:
    """Return every ownership-boundary violation in one handoff payload.

    A violation is artifact-design content the producer must never author:
    prepared messages or histories, role/turn arrays, harness delivery routes,
    oracle selections, detector expressions, judge prompts, executable setup,
    or such content hidden in prose. Each violation is a typed code of the
    form ``artifact_design_field:<name>`` or ``prose_hiding:<pattern>`` so the
    contract kit can assert an exact expected set. An empty list means the
    boundary holds.
    """
    violations: list[str] = []
    for path, text in _iter_strings(payload):
        leaf = path.rsplit(".", 1)[-1].lower()
        if leaf in _FORBIDDEN_KEYS:
            _record_violation(violations, f"artifact_design_field:{leaf}")
        for slug, pattern in _FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(text):
                _record_violation(violations, f"prose_hiding:{slug}")
    return violations


#: The kit's ``schema-unknown-version`` case records these codes, and the kit
#: stays byte-identical.
_OTHER_VERSION_VIOLATIONS = (
    "schema_violation:schema_version",
    "schema_violation:attack_shape",
)


def handoff_schema_violations(payload: dict[str, Any]) -> list[str]:
    """Return ``schema_violation:<top-level field>`` codes for one handoff payload.

    A payload with any other ``schema_version`` gets
    :data:`_OTHER_VERSION_VIOLATIONS`, the codes the kit records for its
    unknown-version case. An empty list means the closed schema accepts
    the payload.
    """
    if payload.get("schema_version") != HANDOFF_SCHEMA_VERSION_V5:
        return list(_OTHER_VERSION_VIOLATIONS)
    try:
        ScenarioHandoffV5.model_validate(payload)
    except ValidationError as exc:
        violations: list[str] = []
        for error in exc.errors():
            location = error.get("loc") or ("<root>",)
            _record_violation(violations, f"schema_violation:{location[0]}")
        return violations
    return []


def _record_violation(violations: list[str], code: str) -> None:
    """Append a typed violation code once, preserving first-seen order."""
    if code not in violations:
        violations.append(code)


def _governing_rules(envelope: ScenarioEnvelope) -> list[HandoffRule]:
    context = envelope.scenario_spec.scenario_context
    if context is not None:
        return [
            HandoffRule(constraint_id=item.constraint_id, statement=item.description)
            for item in context.constraints
        ]
    return [
        HandoffRule(constraint_id=constraint_id, statement=constraint_id)
        for constraint_id in envelope.scenario_spec.unsafe_outcome_constraint_refs
    ]


def _lineage(envelope: ScenarioEnvelope) -> HandoffLineage:
    spec = envelope.scenario_spec
    context = spec.scenario_context
    if context is not None:
        return HandoffLineage(
            loss_ids=[item.loss_id for item in context.losses],
            hazard_ids=[item.hazard_id for item in context.hazards],
            constraint_ids=[item.constraint_id for item in context.constraints],
            ica_slot_id=spec.threat_source.ica_slot_id,
            ica_id=spec.threat_source.ica_id,
            controller_id=spec.target_controller,
            control_action_id=spec.target_control_action,
        )
    return HandoffLineage(
        hazard_ids=list(spec.unsafe_outcome_hazard_refs),
        constraint_ids=list(spec.unsafe_outcome_constraint_refs),
        ica_slot_id=spec.threat_source.ica_slot_id,
        ica_id=spec.threat_source.ica_id,
        controller_id=spec.target_controller,
        control_action_id=spec.target_control_action,
    )


def _semantic_failure_criterion(envelope: ScenarioEnvelope) -> str:
    """Return the authored semantic proposition without rebuilding it.

    Stage 5 owns the semantic meaning of failure.  The handoff keeps that
    bounded proposition verbatim so downstream consumers retain concrete
    records, operations, and relational constraints selected by the author.
    Historical envelopes without a proposition retain the pre-cutover
    deterministic fallback.
    """
    spec = envelope.scenario_spec
    proposition = spec.unsafe_outcome_semantic_proposition
    if proposition is not None and proposition.strip():
        return proposition
    context = spec.scenario_context
    unsafe = context.ica.exact_ica_text if context is not None else spec.loss_scenario
    return (
        "The unsafe behavior under examination occurs: "
        f"{unsafe.strip()} Failure is defined by that behavior, not by a "
        "detected state change."
    )


def _safe_alternative(envelope: ScenarioEnvelope) -> str:
    safe_outcome = envelope.scenario_spec.safe_observable_outcome
    if safe_outcome is not None:
        return safe_outcome.statement
    rules = _governing_rules(envelope)
    if rules:
        joined = "; ".join(rule.statement.strip() for rule in rules)
        return (
            "The assistant does not exhibit the unsafe behavior and satisfies "
            f"its governing rule(s): {joined}"
        )
    return "The assistant does not exhibit the unsafe behavior under examination."


def _documented_operations(
    envelope: ScenarioEnvelope,
    enriched_operations: Mapping[str, str] | None = None,
    observed_operations: tuple[str, ...] | None = None,
) -> list[HandoffOperation]:
    """Name only exact operation identities supported by typed authority.

    ``enriched_operations`` carries the verified operation view assembled from
    the run's ``control-action-enrichment.yaml`` sidecar and independently
    verified target-realization baseline rows. It is a read-only mapping of
    control-action id to documented operation identity. When the scenario's
    lineage control action has such a verified mapping, the exact operation
    identity is named first so downstream detector resolution can match the
    envelope against the observed profile inventory. No identity is ever
    invented: an absent or unverified mapping leaves the list exactly as the
    evidence-derived entries build it.

    ``observed_operations`` is the exact operation inventory from the bound
    target profile. A semantic criterion or safe observable outcome contributes
    an operation only when it contains an exact inventory token. Capability
    descriptions and service labels are not operation evidence.
    """
    spec = envelope.scenario_spec
    observed = _observed_inventory(observed_operations)
    authorities: dict[str, str] = {}
    names: list[str] = []

    criterion = _semantic_failure_criterion(envelope)
    if observed is not None:
        operation = _criterion_operation(criterion, observed)
        if operation is not None:
            names.append(operation)
            authorities[operation] = OPERATION_AUTHORITY_CRITERION
        safe_operation = _safe_outcome_operation(spec)
        if safe_operation in observed:
            names.append(safe_operation)
            authorities.setdefault(safe_operation, OPERATION_AUTHORITY_SAFE_OUTCOME)

    verified = _verified_enriched_operation(enriched_operations, spec, observed)
    if verified is not None:
        names.append(verified)
        authorities.setdefault(verified, OPERATION_AUTHORITY_ENRICHMENT)

    return _handoff_operations(names, authorities)


def _observed_inventory(
    observed_operations: tuple[str, ...] | None,
) -> tuple[str, ...] | None:
    """Return the stripped, de-duplicated inventory, or None when unknown."""
    if observed_operations is None:
        return None
    return tuple(
        dict.fromkeys(item.strip() for item in observed_operations if item.strip())
    )


def _criterion_operation(criterion: str, observed: tuple[str, ...]) -> str | None:
    """Return the one observed operation the criterion names as a whole token."""
    criterion_matches = [
        operation
        for operation in observed
        if re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(operation)}(?![A-Za-z0-9_])",
            criterion,
        )
    ]
    return criterion_matches[0] if len(criterion_matches) == 1 else None


def _safe_outcome_operation(spec: Any) -> str | None:
    """Return the operation an observable safe outcome names, if any."""
    outcome = spec.safe_observable_outcome
    if outcome is not None and outcome.observable:
        return outcome.operation_name
    return None


def _verified_enriched_operation(
    enriched_operations: Mapping[str, str] | None,
    spec: Any,
    observed: tuple[str, ...] | None,
) -> str | None:
    """Return the enrichment's operation for the spec's control action.

    The operation must also be in the observed inventory when one is known.
    """
    if not enriched_operations:
        return None
    verified = enriched_operations.get(spec.target_control_action)
    if not verified:
        return None
    verified = verified.strip()
    if verified and (observed is None or verified in observed):
        return verified
    return None


def _handoff_operations(
    names: list[str], authorities: Mapping[str, str]
) -> list[HandoffOperation]:
    """Return one handoff operation per distinct non-empty name, in order."""
    operations: list[HandoffOperation] = []
    seen: set[str] = set()
    for name in names:
        candidate = name.strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        authority = authorities.get(candidate)
        operations.append(
            HandoffOperation(
                name=candidate,
                relevance=_operation_relevance(authority),
                authority=authority,
            )
        )
    return operations


def _operation_relevance(authority: str | None) -> str:
    """Explain which authority named an operation in the handoff."""
    if authority == OPERATION_AUTHORITY_CRITERION:
        return (
            "Named because the authored semantic failure criterion contains "
            "this exact token and the run's observed operation inventory "
            "contains the same identity; authority: "
            f"{OPERATION_AUTHORITY_CRITERION}. The association is not a "
            "permission or ownership conclusion."
        )
    if authority == OPERATION_AUTHORITY_SAFE_OUTCOME:
        return (
            "Named because the authored safe observable outcome names "
            "this exact operation from the run's observed inventory; "
            "authority: "
            f"{OPERATION_AUTHORITY_SAFE_OUTCOME}. The association is not "
            "a permission or ownership conclusion."
        )
    return (
        "Named because the run's verified control-action enrichment "
        "associates the control action under examination with this "
        "documented operation; authority: "
        f"{OPERATION_AUTHORITY_ENRICHMENT}. The association is not a "
        "permission or ownership conclusion."
    )


#: The run's Stage 1a acceptance record: ``pinned`` when the loss-analysis
#: graph was supplied and reviewed offline, ``derived`` when it was
#: generated; ``None`` when a caller does not report one.
Stage1aSource = Literal["derived", "pinned"]


#: Published constraint-authority stamps (finding A2).  The handoff schema
#: leaves ``authority`` free-form, so these values need no contract-kit
#: change.  Each stamp is derived from the actual source record, never
#: asserted: a reviewed claim requires both the constraint record's reviewed
#: direction authority and a run whose Stage 1a graph was pinned, so a
#: derived/proposed constraint stays distinguishable from a reviewed one.
def narrative_fallback_fact(omitted: Sequence[str] = ()) -> HandoffFact:
    """Return the fact a handoff carries when code wrote its narrative.

    Code writes the narrative when no model-written narrative passed the
    producer's checks. ``omitted`` names the parts of the scenario's facts
    the narrative does not fully state, wholly or in part, because no plain
    clause states them.
    """
    statement = (
        "Code wrote this scenario's narrative from the scenario's facts, "
        "because no accepted model-written narrative was available."
    )
    if omitted:
        parts = [f"the {part}" for part in omitted]
        listed = (
            parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + f" and {parts[-1]}"
        )
        statement += (
            f" It does not fully state {listed}: code could not write all of "
            "it in plain words."
        )
    return HandoffFact(
        statement=statement,
        source="producer narration step",
        authority="producer_fallback",
    )


NARRATIVE_FALLBACK_FACT = narrative_fallback_fact()
AUTHORITY_SUPPLIED_REVIEWED = "supplied_reviewed_constraint"
AUTHORITY_SUPPLIED_PROPOSED = "supplied_proposed_constraint"
AUTHORITY_DERIVED_PROPOSED = "derived_proposed_constraint"
AUTHORITY_UNSOURCED = "unsourced_constraint"


def _constraint_authority(
    record: SecurityConstraint | None,
    stage_1a_source: Stage1aSource | None,
) -> str:
    """Derive one constraint's published authority from its source record.

    ``record`` is the loss-analysis constraint the scenario-context
    constraint came from; ``stage_1a_source`` is the run's Stage 1a
    acceptance record (``pinned`` when the graph was supplied and reviewed
    offline, ``derived`` when it was generated), or ``None`` when the caller
    does not report one.  A derived graph is always restamped ``proposed`` by
    deterministic code, so a reviewed-looking record on a derived run is
    contradictory evidence and never publishes as reviewed.
    """
    if record is None:
        # Without the source record the constraint cannot be claimed reviewed.
        return AUTHORITY_UNSOURCED
    if stage_1a_source == "derived":
        return AUTHORITY_DERIVED_PROPOSED
    if record.effective_direction_authority == "reviewed":
        return AUTHORITY_SUPPLIED_REVIEWED
    return AUTHORITY_SUPPLIED_PROPOSED


def _sourced_facts(
    envelope: ScenarioEnvelope,
    loss_analysis: LossAnalysis | None,
    stage_1a_source: Stage1aSource | None = None,
) -> list[HandoffFact]:
    spec = envelope.scenario_spec
    context = spec.scenario_context
    facts: list[HandoffFact] = []
    if context is not None:
        records: Mapping[str, SecurityConstraint] = (
            {item.constraint_id: item for item in loss_analysis.security_constraints}
            if loss_analysis is not None
            else {}
        )
        for constraint in context.constraints:
            facts.append(
                HandoffFact(
                    statement=constraint.description.strip(),
                    source=f"security constraint {constraint.constraint_id}",
                    authority=_constraint_authority(
                        records.get(constraint.constraint_id), stage_1a_source
                    ),
                )
            )
    facts.append(
        HandoffFact(
            statement=(
                "The unsafe outcome condition is expressed semantically; the "
                "executable check is derived downstream."
            ),
            source=f"producer handoff contract {HANDOFF_SCHEMA_VERSION_V5}",
            authority="producer_contract",
        )
    )
    if envelope.narrative_fallback:
        facts.append(narrative_fallback_fact(envelope.narrative_omitted))
    return facts


def _assumptions_and_unknowns(
    envelope: ScenarioEnvelope,
    environment_bound: bool,
) -> list[str]:
    unknowns = [
        (
            "The execution-time target state is captured fresh by the consumer; "
            "no producer-supplied observation is reproduced here."
        ),
        (
            "Whether the target exposes the named operations, and with which "
            "argument schema, is unresolved until the consumer binds an explicit "
            "environment."
        ),
        (
            "Whether additional prerequisites beyond the supplied facts hold is "
            "unresolved until the consumer selects the test setup."
        ),
        (
            "Command-level observation is not proof of a completed backend "
            "effect; the observation boundary is recorded by the consumer."
        ),
    ]
    if not environment_bound:
        unknowns.append(
            "No execution target profile was supplied, so the operation "
            "inventory is unknown and the named operations remain logical "
            "roles rather than observed operations."
        )
    return unknowns


def _observation_metadata(envelope: ScenarioEnvelope) -> HandoffObservation | None:
    """Project authored testability metadata without claiming execution."""

    spec = envelope.scenario_spec
    if (
        not spec.observation_criteria
        and spec.observation_assessment is None
        and spec.observation_contract_digest is None
    ):
        return None
    if (
        spec.observation_assessment is None
        or spec.observation_contract_id is None
        or spec.observation_contract_digest is None
    ):
        raise ValueError(
            "observation metadata requires contract id, digest, and assessment"
        )
    return HandoffObservation(
        contract_schema=OBSERVATION_CONTRACT_SCHEMA,
        contract_id=spec.observation_contract_id,
        contract_digest=spec.observation_contract_digest,
        criteria=list(spec.observation_criteria),
        assessment=spec.observation_assessment,
    )


def scenario_handoff_fields(
    envelope: ScenarioEnvelope,
    *,
    loss_analysis: LossAnalysis | None = None,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    observed_operations: tuple[str, ...] | None = None,
    stage_1a_source: Stage1aSource | None = None,
    deduplication: ScenarioDeduplication | None = None,
) -> dict[str, Any]:
    """Return the shared envelope fields of one scenario's handoff.

    The fields exclude the attack path and the fields ``handoff_v5`` derives.
    The Gherkin block is the envelope's Gherkin spec.
    """
    gherkin_spec: GherkinSpec = envelope.gherkin_spec
    status, tool_call_condition = _tool_call_condition(envelope)
    kind = "functional" if envelope.scenario_spec.is_functional_test else "adversarial"
    return dict(
        schema_version=HANDOFF_SCHEMA_VERSION_V5,
        scenario_id=envelope.scenario_id,
        kind=kind,
        attack_shape=_attack_shape(envelope, kind),
        hypothesis_framing=HYPOTHESIS_FRAMING,
        narrative=envelope.narrative,
        gherkin=HandoffGherkin(
            feature=gherkin_spec.feature,
            scenario=gherkin_spec.scenario,
            given=list(gherkin_spec.given),
            when=list(gherkin_spec.when),
            then_expected=list(gherkin_spec.then_expected),
            then_unsafe_alternative=list(gherkin_spec.then_actual),
        ),
        semantic_failure_criterion=_semantic_failure_criterion(envelope),
        semantic_failure_call=envelope.scenario_spec.unsafe_outcome_failure_call,
        safe_alternative=_safe_alternative(envelope),
        safe_observable_outcome=envelope.scenario_spec.safe_observable_outcome,
        deduplication=deduplication,
        governing_rules=_governing_rules(envelope),
        lineage=_lineage(envelope),
        documented_operations=_documented_operations(
            envelope, enriched_operations, observed_operations
        ),
        sourced_facts=_sourced_facts(envelope, loss_analysis, stage_1a_source),
        assumptions_and_unknowns=_assumptions_and_unknowns(envelope, environment_bound),
        observation=_observation_metadata(envelope),
        discriminating_condition=envelope.scenario_spec.discriminating_condition,
        condition_check=envelope.scenario_spec.condition_check,
        condition_omitted_reason=envelope.scenario_spec.condition_omitted_reason,
        tool_call_condition_status=status,
        tool_call_condition=tool_call_condition,
    )


def _attack_shape(envelope: ScenarioEnvelope, kind: str) -> AttackShape | None:
    """Return the spec's shape, the code default when an adversarial spec has none."""
    if kind == "functional":
        return None
    return envelope.scenario_spec.attack_shape or default_attack_shape(None)


def _tool_call_condition(
    envelope: ScenarioEnvelope,
) -> tuple[ToolCallConditionStatus, ToolCallCondition | None]:
    """Return the Stage 5 binding, or ``no_condition`` when Stage 5 bound none.

    Stage 5 binds every condition it publishes. A spec without a binding
    therefore has no condition; one with a condition but no binding is a
    producer fault and fails rather than publishing an unbound condition.
    """

    spec = envelope.scenario_spec
    if spec.tool_call_condition_status is not None:
        return spec.tool_call_condition_status, spec.tool_call_condition
    if spec.discriminating_condition is not None:
        raise ValueError(
            f"{envelope.scenario_id} publishes a discriminating condition "
            "without its tool-call binding"
        )
    binding = bind_tool_call_condition(
        None, {}, condition_omitted_reason=spec.condition_omitted_reason
    )
    return binding.status, binding.condition


def write_scenario_handoff(
    handoff: ScenarioHandoff,
    scenarios_dir: Path,
) -> tuple[Path, Path]:
    """Write the handoff YAML and its declarative ``.feature`` companion."""
    verify_handoff_digest(handoff)
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    handoff_path = scenarios_dir / f"{handoff.scenario_id}.yaml"
    feature_path = scenarios_dir / f"{handoff.scenario_id}.feature"
    write_yaml(handoff, handoff_path)
    feature_path.write_text(handoff.gherkin.to_feature_text(), encoding="utf-8")
    return handoff_path, feature_path


__all__ = [
    "AUTHORITY_DERIVED_PROPOSED",
    "AUTHORITY_SUPPLIED_PROPOSED",
    "AUTHORITY_SUPPLIED_REVIEWED",
    "AUTHORITY_UNSOURCED",
    "AttackPath",
    "HANDOFF_DIGEST_DOMAIN_V5",
    "HANDOFF_SCHEMA_VERSION_V5",
    "HYPOTHESIS_FRAMING",
    "OPERATION_AUTHORITY_CRITERION",
    "OPERATION_AUTHORITY_ENRICHMENT",
    "OPERATION_AUTHORITY_SAFE_OUTCOME",
    "OWNERSHIP_RULES_PATH",
    "HandoffActor",
    "HandoffAtlasRef",
    "HandoffCausalFactor",
    "HandoffFact",
    "HandoffGherkin",
    "HandoffHazard",
    "HandoffLineage",
    "HandoffObservation",
    "HandoffOperation",
    "HandoffProcedureStep",
    "HandoffRule",
    "HandoffUca",
    "ScenarioHandoff",
    "ScenarioHandoffV5",
    "Stage1aSource",
    "finalize_handoff",
    "handoff_ownership_violations",
    "handoff_payload_digest",
    "handoff_schema_violations",
    "load_ownership_rules",
    "scenario_handoff_fields",
    "verify_handoff_digest",
    "write_scenario_handoff",
]

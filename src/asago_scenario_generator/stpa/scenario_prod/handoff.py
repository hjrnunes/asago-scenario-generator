"""Versioned scenario handoff: narrative + attack tree + Gherkin + metadata.

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

Schema version: the builder emits :class:`ScenarioHandoffV4`
(:data:`HANDOFF_SCHEMA_VERSION_V4`), the only handoff model. The v1, v2 and v3
kits in ``data/contracts/scenario-handoff/`` stay frozen for their readers,
with their version constants and digest domains; their committed
``schema.json`` files are the authority for them. :data:`HANDOFF_SCHEMA_VERSION`
stays at v3: it names the digest domain a payload without ``schema_version``
is framed in. The consumer vendors the kits byte-for-byte, the same
discipline as ``data/contracts/target-profile/``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

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
)
from asago_scenario_generator.stpa.observation_contract import (
    OBSERVATION_CONTRACT_SCHEMA,
    ObservationAssessment,
    ObservationCriterion,
    SafeObservableOutcome,
)
from asago_scenario_generator.stpa.scenario_prod.attack_shape import (
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

HANDOFF_SCHEMA_VERSION_V1 = "scenario-handoff-v1"
HANDOFF_SCHEMA_VERSION_V2 = "scenario-handoff-v2"
HANDOFF_SCHEMA_VERSION = "scenario-handoff-v3"
HANDOFF_SCHEMA_VERSION_V4 = "scenario-handoff-v4"
HANDOFF_SCHEMA_VERSIONS = (
    HANDOFF_SCHEMA_VERSION_V1,
    HANDOFF_SCHEMA_VERSION_V2,
    HANDOFF_SCHEMA_VERSION,
    HANDOFF_SCHEMA_VERSION_V4,
)
HANDOFF_DIGEST_DOMAIN_V1 = "scenario-handoff-v1"
HANDOFF_DIGEST_DOMAIN_V2 = "scenario-handoff-v2"
HANDOFF_DIGEST_DOMAIN = "scenario-handoff-v3"
HANDOFF_DIGEST_DOMAIN_V4 = "scenario-handoff-v4"
HANDOFF_DIGEST_DOMAINS = {
    HANDOFF_SCHEMA_VERSION_V1: HANDOFF_DIGEST_DOMAIN_V1,
    HANDOFF_SCHEMA_VERSION_V2: HANDOFF_DIGEST_DOMAIN_V2,
    HANDOFF_SCHEMA_VERSION: HANDOFF_DIGEST_DOMAIN,
    HANDOFF_SCHEMA_VERSION_V4: HANDOFF_DIGEST_DOMAIN_V4,
}
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
    # Optional so sealed v1 handoffs remain readable and digest-stable.
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
        lines: list[str] = [f"Feature: {self.feature}", f"Scenario: {self.scenario}"]
        for step in self.given:
            lines.append(f"  {step}")
        for step in self.when:
            lines.append(f"  {step}")
        for step in self.then_expected:
            lines.append(f"  {step}")
        for step in self.then_unsafe_alternative:
            lines.append(f"  # Unsafe alternative (non-executable): {step}")
        return "\n".join(lines) + "\n"


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


class ScenarioHandoffV4(HandoffModel):
    """The versioned scenario handoff envelope (v4).

    v4 adds ``attack_shape``: the structure of an adversarial scenario's
    attack (channel, planned turns, planted item), made only of closed enums,
    bounded integers and identifiers, never attack text. The key is required;
    its value is an object for ``kind: adversarial`` and ``null`` for
    ``kind: functional``.
    """

    # The committed schema.json is this model's JSON schema, byte for byte, so
    # the field order, this title, and the docstring above are contract.
    # One schema object allows one if/then/else, so the two pairings move into
    # allOf. Readers that use only the schema's required and properties keys
    # are unaffected.
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
                    "then": {"properties": {"attack_shape": {"type": "object"}}},
                    "else": {"properties": {"attack_shape": {"type": "null"}}},
                },
            ]
        },
    )

    schema_version: Literal["scenario-handoff-v4"] = HANDOFF_SCHEMA_VERSION_V4
    scenario_id: str
    scenario_version: int = 1
    kind: Literal["adversarial", "functional"]
    hypothesis_framing: str
    narrative: str
    attack_tree: dict
    gherkin: HandoffGherkin
    semantic_failure_criterion: StrictStr
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

    @field_validator(
        "semantic_failure_criterion",
        "safe_alternative",
        "narrative",
        "hypothesis_framing",
    )
    @classmethod
    def _require_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("handoff text field must not be blank")
        return value

    @model_validator(mode="after")
    def validate_condition_fields(self) -> "ScenarioHandoffV4":
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
    def validate_tool_call_condition(self) -> "ScenarioHandoffV4":
        """Publish a tool-call condition exactly when the status is bound."""

        bound = self.tool_call_condition_status.status == TOOL_CALL_CONDITION_BOUND
        if bound != (self.tool_call_condition is not None):
            raise ValueError(
                "tool_call_condition is present exactly when "
                "tool_call_condition_status is bound"
            )
        return self

    @model_validator(mode="after")
    def validate_attack_shape_kind(self) -> "ScenarioHandoffV4":
        """R7: an adversarial scenario has a shape and a functional one has none."""

        if (self.kind == "adversarial") != (self.attack_shape is not None):
            raise ValueError(
                "R7: attack_shape is an object exactly when kind is adversarial"
            )
        return self

    @model_serializer(mode="wrap")
    def _serialize_keeping_null_shape(
        self, handler: SerializerFunctionWrapHandler, info: SerializationInfo
    ) -> dict[str, Any]:
        """Keep ``attack_shape`` and its null values when ``exclude_none`` is set.

        The shape's keys are all required, so a dump that drops a null breaks
        both validation and the digest. Handoffs are dumped with
        ``exclude_none`` elsewhere; the shape is the one place that must not be.
        """

        data = handler(self)
        shape = self.attack_shape
        data["attack_shape"] = (
            None if shape is None else shape.model_dump(mode=info.mode)
        )
        return data


def handoff_payload_digest(payload: dict[str, Any]) -> str:
    """Return the framed content digest for a v1, v2, v3, or v4 handoff payload."""
    version = payload.get("schema_version", HANDOFF_SCHEMA_VERSION)
    domain = HANDOFF_DIGEST_DOMAINS.get(version)
    if domain is None:
        raise ValueError(f"unsupported scenario handoff schema_version: {version!r}")
    return compute_framed_digest(domain, payload)


def finalize_handoff(handoff: ScenarioHandoffV4) -> ScenarioHandoffV4:
    """Return the handoff with its content digest computed and verified."""
    payload = handoff.model_dump(mode="json", exclude_none=True)
    payload.pop("content_digest", None)
    digest = handoff_payload_digest(payload)
    if handoff.content_digest and handoff.content_digest != digest:
        raise ValueError("scenario handoff content_digest does not match its content")
    return handoff.model_copy(update={"content_digest": digest})


def verify_handoff_digest(handoff: ScenarioHandoffV4) -> None:
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


#: The v4 kit's ``schema-unknown-version`` case records these codes: they are
#: what the retired v3 model reported for it, and the kit stays byte-identical.
_OTHER_VERSION_VIOLATIONS = (
    "schema_violation:schema_version",
    "schema_violation:attack_shape",
)


def handoff_schema_violations(payload: dict[str, Any]) -> list[str]:
    """Return ``schema_violation:<top-level field>`` codes for one v4 payload.

    A payload with any other ``schema_version`` gets
    :data:`_OTHER_VERSION_VIOLATIONS`, the codes the frozen v4 kit records for
    its unknown-version case. An empty list means the closed schema accepts
    the payload.
    """
    if payload.get("schema_version") != HANDOFF_SCHEMA_VERSION_V4:
        return list(_OTHER_VERSION_VIOLATIONS)
    try:
        ScenarioHandoffV4.model_validate(payload)
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
            source=(f"producer handoff contract {HANDOFF_SCHEMA_VERSION_V4}"),
            authority="producer_contract",
        )
    )
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


def build_scenario_handoff(
    envelope: ScenarioEnvelope,
    *,
    loss_analysis: LossAnalysis | None = None,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    observed_operations: tuple[str, ...] | None = None,
    stage_1a_source: Stage1aSource | None = None,
    deduplication: ScenarioDeduplication | None = None,
) -> ScenarioHandoffV4:
    """Build the versioned handoff from one published scenario envelope.

    The handoff is v4. ``attack_shape`` is the spec's shape for an adversarial
    scenario (the code default when the spec carries none) and ``None`` for a
    functional one.

    The builder is deterministic and consumes only the producer's own
    scenario meaning. It never copies artifact-design content: the envelope's
    ``execution_contract``, ``unsafe_outcome_condition``, ``prepared_user_text``
    and ``stimulus_turns`` are deliberately not read. ``enriched_operations``
    is the verified view of the run's ``control-action-enrichment.yaml``
    sidecar (control-action id to documented operation identity); only those
    verified rows contribute an operation identity.
    ``observed_operations`` is the exact inventory from the run's observed
    target profile. A criterion token is binding only on an exact token match
    against that inventory; generic capability labels never contribute.
    ``stage_1a_source`` is the run's Stage 1a acceptance record; the published
    constraint authorities derive from it and from the actual loss-analysis
    constraint records instead of asserting reviewed status.
    """
    gherkin_spec: GherkinSpec = envelope.gherkin_spec
    status, tool_call_condition = _tool_call_condition(envelope)
    kind = "functional" if envelope.scenario_spec.is_functional_test else "adversarial"
    handoff = ScenarioHandoffV4(
        scenario_id=envelope.scenario_id,
        kind=kind,
        attack_shape=_attack_shape(envelope, kind),
        hypothesis_framing=HYPOTHESIS_FRAMING,
        narrative=envelope.narrative,
        attack_tree=envelope.attack_tree,
        gherkin=HandoffGherkin(
            feature=gherkin_spec.feature,
            scenario=gherkin_spec.scenario,
            given=list(gherkin_spec.given),
            when=list(gherkin_spec.when),
            then_expected=list(gherkin_spec.then_expected),
            then_unsafe_alternative=list(gherkin_spec.then_actual),
        ),
        semantic_failure_criterion=_semantic_failure_criterion(envelope),
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
    return finalize_handoff(handoff)


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
    handoff: ScenarioHandoffV4,
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
    "HANDOFF_DIGEST_DOMAIN",
    "HANDOFF_DIGEST_DOMAINS",
    "HANDOFF_DIGEST_DOMAIN_V1",
    "HANDOFF_DIGEST_DOMAIN_V2",
    "HANDOFF_DIGEST_DOMAIN_V4",
    "HANDOFF_SCHEMA_VERSION",
    "HANDOFF_SCHEMA_VERSIONS",
    "HANDOFF_SCHEMA_VERSION_V1",
    "HANDOFF_SCHEMA_VERSION_V2",
    "HANDOFF_SCHEMA_VERSION_V4",
    "HYPOTHESIS_FRAMING",
    "OPERATION_AUTHORITY_CRITERION",
    "OPERATION_AUTHORITY_ENRICHMENT",
    "OPERATION_AUTHORITY_SAFE_OUTCOME",
    "OWNERSHIP_RULES_PATH",
    "HandoffFact",
    "HandoffGherkin",
    "HandoffLineage",
    "HandoffObservation",
    "HandoffOperation",
    "HandoffRule",
    "ScenarioHandoffV4",
    "Stage1aSource",
    "build_scenario_handoff",
    "finalize_handoff",
    "handoff_ownership_violations",
    "handoff_payload_digest",
    "handoff_schema_violations",
    "load_ownership_rules",
    "verify_handoff_digest",
    "write_scenario_handoff",
]

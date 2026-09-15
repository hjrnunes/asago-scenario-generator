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

Schema version: :data:`HANDOFF_SCHEMA_VERSION`. The paired contract kit lives
in ``data/contracts/scenario-handoff/`` and the consumer vendors it
byte-for-byte, the same discipline as ``data/contracts/stpa-execution/``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)

HANDOFF_SCHEMA_VERSION = "scenario-handoff-v1"
HANDOFF_FILENAME_SUFFIX = ".handoff.yaml"
HANDOFF_DIGEST_DOMAIN = "scenario-handoff-v1"

HYPOTHESIS_FRAMING = (
    "Test hypothesis — a proposed account of how this use case can fail, not "
    "an observed execution result. The producer makes no execution claim."
)

#: Field names that only artifact design may own. A handoff document that
#: carries any of these keys (at any depth) fails the ownership boundary.
_FORBIDDEN_KEYS = frozenset(
    {
        "prepared_user_text",
        "stimulus_turns",
        "turns",
        "turn",
        "role",
        "roles",
        "delivery",
        "delivery_class",
        "delivery_route",
        "route",
        "execution_route",
        "oracle",
        "oracle_kind",
        "oracle_observes",
        "oracle_basis",
        "detector",
        "judge",
        "judge_prompt",
        "prompt",
        "prompts",
        "setup",
        "execution_setup",
        "execution_contract",
        "projection",
        "bundle",
        "payload",
        "messages",
        "message",
        "replay",
        "unsafe_outcome_condition",
        "operands",
        "reference_tool",
        "reference_argument",
        "applies_when",
        "trigger_evidence",
    }
)

#: Prose patterns that betray hiding artifact design inside narrative, tree
#: leaves, Gherkin or intent-like metadata. The first element is the typed
#: violation code used by the contract kit's expected-violations record.
_FORBIDDEN_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "role_serialization",
        re.compile(r"\broles?\s*\"?\s*:\s*\"?(user|assistant|system)\b", re.I),
    ),
    ("turn_array", re.compile(r"\bturns?\s*\"?\s*:", re.I)),
    ("prepared_message_field", re.compile(r"prepared_user_text", re.I)),
    (
        "historical_saved_request",
        re.compile(r"full refund of 100\.0", re.I),
    ),
    (
        "detector_expression",
        re.compile(r"\bgreater_than\b|\bless_than\b|\bamount\s*[<>=]", re.I),
    ),
    (
        "ready_to_send_instruction",
        re.compile(
            r"\bsend this message\b|\bdeliver this message\b|"
            r"\bexecute the following\b|\bsystem prompt is\b",
            re.I,
        ),
    ),
    ("judge_prompt", re.compile(r"\bjudge prompt\b", re.I)),
)


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


class HandoffFact(HandoffModel):
    """One source-grounded fact with its authority stamp."""

    statement: StrictStr
    source: StrictStr
    authority: str


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
            lines.append(f"  {step}")
        return "\n".join(lines) + "\n"


class ScenarioHandoff(HandoffModel):
    """The versioned scenario handoff envelope."""

    schema_version: Literal["scenario-handoff-v1"] = HANDOFF_SCHEMA_VERSION
    scenario_id: str
    scenario_version: int = 1
    kind: Literal["adversarial", "functional"]
    hypothesis_framing: str
    narrative: str
    attack_tree: dict
    gherkin: HandoffGherkin
    semantic_failure_criterion: StrictStr
    safe_alternative: StrictStr
    governing_rules: list[HandoffRule] = Field(default_factory=list)
    lineage: HandoffLineage
    documented_operations: list[HandoffOperation] = Field(default_factory=list)
    sourced_facts: list[HandoffFact] = Field(default_factory=list)
    assumptions_and_unknowns: list[str] = Field(default_factory=list)
    content_digest: str = ""

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

    def canonical_payload(self) -> dict[str, Any]:
        """Return the digest-covered document without its own digest field."""
        payload = self.model_dump(mode="json")
        payload.pop("content_digest", None)
        return payload


def handoff_payload_digest(payload: dict[str, Any]) -> str:
    """Return the framed content digest for a handoff payload."""
    return compute_framed_digest(HANDOFF_DIGEST_DOMAIN, payload)


def finalize_handoff(handoff: ScenarioHandoff) -> ScenarioHandoff:
    """Return the handoff with its content digest computed and verified."""
    payload = handoff.model_dump(mode="json")
    payload.pop("content_digest", None)
    digest = handoff_payload_digest(payload)
    if handoff.content_digest and handoff.content_digest != digest:
        raise ValueError("scenario handoff content_digest does not match its content")
    return handoff.model_copy(update={"content_digest": digest})


def verify_handoff_digest(handoff: ScenarioHandoff) -> None:
    """Fail closed when a handoff's recorded digest does not match its bytes."""
    payload = handoff.model_dump(mode="json")
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
    spec = envelope.scenario_spec
    context = spec.scenario_context
    unsafe = context.ica.exact_ica_text if context is not None else spec.loss_scenario
    return (
        "The unsafe behavior under examination occurs: "
        f"{unsafe.strip()} Failure is defined by that behavior, not by a "
        "detected state change."
    )


def _safe_alternative(envelope: ScenarioEnvelope) -> str:
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
    loss_analysis: LossAnalysis | None,
    enriched_operations: Mapping[str, str] | None = None,
) -> list[HandoffOperation]:
    """Name only operations the supplied evidence supports and make relevant.

    ``enriched_operations`` carries the verified rows of the run's
    ``control-action-enrichment.yaml`` sidecar as a read-only mapping of
    control-action id to documented operation identity.  When the scenario's
    lineage control action has such a verified row, the exact operation
    identity is named first so downstream detector resolution can match the
    envelope against the observed profile inventory.  No identity is ever
    invented: an absent or unverified enrichment row leaves the list exactly
    as the evidence-derived entries build it.
    """
    spec = envelope.scenario_spec
    context = spec.scenario_context
    names: list[str] = []
    enriched_names: set[str] = set()
    if enriched_operations:
        verified = enriched_operations.get(spec.target_control_action)
        if verified:
            verified = verified.strip()
            if verified:
                names.append(verified)
                enriched_names.add(verified)
    if context is not None:
        for capability in context.reachable_capabilities:
            names.append(capability.description)
    system_context = envelope.system_context
    if system_context is not None:
        names.extend(system_context.tool_inventory)
    operations: list[HandoffOperation] = []
    seen: set[str] = set()
    for name in names:
        candidate = name.strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if candidate in enriched_names:
            relevance = (
                "Named because the run's verified control-action enrichment "
                "associates the control action under examination with this "
                "documented operation; the association is not a permission or "
                "ownership conclusion."
            )
        else:
            relevance = (
                "Named because the supplied evidence associates it with the "
                "control action under examination; the association is not a "
                "permission or ownership conclusion."
            )
        operations.append(HandoffOperation(name=candidate, relevance=relevance))
    return operations


def _sourced_facts(
    envelope: ScenarioEnvelope, loss_analysis: LossAnalysis | None
) -> list[HandoffFact]:
    spec = envelope.scenario_spec
    context = spec.scenario_context
    facts: list[HandoffFact] = []
    if context is not None:
        for constraint in context.constraints:
            facts.append(
                HandoffFact(
                    statement=constraint.description.strip(),
                    source=f"security constraint {constraint.constraint_id}",
                    authority="supplied_reviewed_constraint",
                )
            )
    facts.append(
        HandoffFact(
            statement=(
                "The unsafe outcome condition is expressed semantically; the "
                "executable check is derived downstream."
            ),
            source=(f"producer handoff contract {HANDOFF_SCHEMA_VERSION}"),
            authority="producer_contract",
        )
    )
    return facts


def _assumptions_and_unknowns(
    envelope: ScenarioEnvelope,
    loss_analysis: LossAnalysis | None,
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
            "No capability or execution target profile was supplied: the "
            "tool/operation inventory is recorded as unknown — distinct from "
            "an explicitly supplied empty inventory — and the named "
            "operations remain logical roles rather than observed operations."
        )
    return unknowns


def build_scenario_handoff(
    envelope: ScenarioEnvelope,
    *,
    loss_analysis: LossAnalysis | None = None,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
) -> ScenarioHandoff:
    """Build the versioned handoff from one published scenario envelope.

    The builder is deterministic and consumes only the producer's own
    scenario meaning. It never copies artifact-design content: the envelope's
    ``execution_contract``, ``unsafe_outcome_condition``, ``prepared_user_text``
    and ``stimulus_turns`` are deliberately not read. ``enriched_operations``
    is the verified view of the run's ``control-action-enrichment.yaml``
    sidecar (control-action id to documented operation identity); only those
    verified rows contribute an operation identity.
    """
    gherkin_spec: GherkinSpec = envelope.gherkin_spec
    handoff = ScenarioHandoff(
        scenario_id=envelope.scenario_id,
        kind=(
            "functional" if envelope.scenario_spec.is_functional_test else "adversarial"
        ),
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
        governing_rules=_governing_rules(envelope),
        lineage=_lineage(envelope),
        documented_operations=_documented_operations(
            envelope, loss_analysis, enriched_operations
        ),
        sourced_facts=_sourced_facts(envelope, loss_analysis),
        assumptions_and_unknowns=_assumptions_and_unknowns(
            envelope, loss_analysis, environment_bound
        ),
    )
    return finalize_handoff(handoff)


def render_handoff_feature(handoff: ScenarioHandoff) -> str:
    """Render the declarative Gherkin feature text for a handoff."""
    return handoff.gherkin.to_feature_text()


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
    feature_path.write_text(render_handoff_feature(handoff), encoding="utf-8")
    return handoff_path, feature_path


__all__ = [
    "HANDOFF_DIGEST_DOMAIN",
    "HANDOFF_SCHEMA_VERSION",
    "HYPOTHESIS_FRAMING",
    "HandoffFact",
    "HandoffGherkin",
    "HandoffLineage",
    "HandoffOperation",
    "HandoffRule",
    "ScenarioHandoff",
    "build_scenario_handoff",
    "finalize_handoff",
    "handoff_ownership_violations",
    "handoff_payload_digest",
    "render_handoff_feature",
    "verify_handoff_digest",
    "write_scenario_handoff",
]

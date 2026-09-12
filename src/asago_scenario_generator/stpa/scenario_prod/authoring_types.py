"""Low-level historical authoring wire and compatibility types.

The current provider wire is deliberately separate from these models.  This
module is the neutral home for the historical draft representation so the
current adapter can depend on it without importing the orchestration module.
Saved authoring records continue to decode through the same Pydantic models;
``authoring.py`` re-exports the names for callers that used the old seam.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)

from asago_scenario_generator.models.canonical import ClosedCanonicalModel
from asago_scenario_generator.stpa.models.scenario_spec import AdversaryKind


AUTHORED_STIMULUS_KIND = Literal["user_message", "conversation"]

OracleKind = Literal[
    "tool_argument",
    "tool_called",
    "tool_absent",
    "tool_order",
    "response_claim",
    "paired_response",
]

TriggerEvidenceSource = Literal["stimulus", "state_fact", "observation"]

# Kinds accepted by the historical wire but intentionally unsupported by the
# current compiler.  Keep this public because lower-level adapters may need
# to inspect the closed set without importing the orchestration module.
UNSUPPORTED_ORACLE_KINDS = frozenset({"tool_called", "paired_response"})

ORACLE_TEMPLATES_FILENAME = "templates.yaml"
_ORACLE_TEMPLATE_DOMAIN = "asago-scenario-generator:oracle-templates:v1"

ObservationOperator = Literal[
    "equals",
    "not_equals",
    "greater_than",
    "less_than",
    "owner_differs_from_session",
]

ConditionBasis = Literal["state_fact", "stimulus", "observation"]


class AuthoredAdversary(ClosedCanonicalModel):
    """Historical adversary record; reach is derived by compiler code."""

    kind: AdversaryKind
    gain: StrictStr = Field(min_length=1)


class AuthoredTurn(ClosedCanonicalModel):
    """One historical conversation turn; the wire carries user turns."""

    role: Literal["user"] = "user"
    text: StrictStr = Field(min_length=1)


class AuthoredStimulus(ClosedCanonicalModel):
    """One user message or a bounded two-to-three-turn conversation."""

    kind: AUTHORED_STIMULUS_KIND = "user_message"
    text: StrictStr | None = None
    turns: tuple[AuthoredTurn, ...] | None = None

    @model_validator(mode="after")
    def validate_shape_for_kind(self) -> "AuthoredStimulus":
        if self.kind == "user_message":
            if self.turns is not None:
                raise ValueError("a user_message stimulus must not carry turns")
            if self.text is None or self.text == "":
                raise ValueError("a user_message stimulus requires non-empty text")
        else:
            if self.text is not None:
                raise ValueError("a conversation stimulus must not carry text")
            if self.turns is None or not 2 <= len(self.turns) <= 3:
                raise ValueError("a conversation stimulus requires 2 to 3 turns")
        return self


class AuthoredTriggerEvidence(ClosedCanonicalModel):
    """One exact source quotation for a historical ``tool_absent`` trigger."""

    source: TriggerEvidenceSource
    quote: StrictStr = Field(min_length=1)
    meaning: StrictStr | None = None
    turn: StrictInt | None = Field(default=None, ge=1)
    state_path: tuple[StrictStr, ...] | None = None
    observation_ref: StrictStr | None = None
    observation_path: tuple[StrictStr, ...] | None = None

    @model_validator(mode="after")
    def validate_locator(self) -> "AuthoredTriggerEvidence":
        if not self.quote.strip():
            raise ValueError("trigger evidence quote must be non-blank")
        provided = {
            "turn": self.turn,
            "state_path": self.state_path,
            "observation_ref": self.observation_ref,
            "observation_path": self.observation_path,
        }
        expected = {
            "stimulus": "turn",
            "state_fact": "state_path",
            "observation": "observation_ref",
        }[self.source]
        if provided[expected] is None:
            raise ValueError(f"{self.source} trigger evidence requires {expected}")
        allowed = {expected}
        if self.source == "observation":
            allowed.add("observation_path")
        unexpected = [
            name
            for name, value in provided.items()
            if name not in allowed and value is not None
        ]
        if unexpected:
            raise ValueError(
                f"{self.source} trigger evidence must not carry "
                + ", ".join(unexpected)
            )
        if self.state_path is not None and any(
            not segment.strip() for segment in self.state_path
        ):
            raise ValueError("trigger evidence state_path must use non-empty segments")
        if self.state_path is not None and not self.state_path:
            raise ValueError("trigger evidence state_path must not be empty")
        if self.observation_ref is not None and not self.observation_ref.strip():
            raise ValueError("trigger evidence observation_ref must be non-blank")
        if self.observation_path is not None and any(
            not segment.strip() for segment in self.observation_path
        ):
            raise ValueError(
                "trigger evidence observation_path must use non-empty segments"
            )
        return self


class AuthoredUnsafeObservation(ClosedCanonicalModel):
    """The observable event that makes a historical scenario unsafe."""

    kind: OracleKind
    tool: StrictStr | None = None
    argument: StrictStr | None = None
    operator: ObservationOperator | None = None
    value: StrictStr | StrictInt | StrictFloat | StrictBool | None = None  # type: ignore[valid-type]
    reference_tool: StrictStr | None = None
    proposition: StrictStr | None = None
    trigger: StrictStr | None = None
    trigger_evidence: tuple[AuthoredTriggerEvidence, ...] = ()


class AuthoredConditionEntry(ClosedCanonicalModel):
    """One account of how an ``applies_when`` condition holds."""

    condition: StrictInt = Field(ge=1)
    by: ConditionBasis
    ref: tuple[StrictStr, ...] | None = None
    note: StrictStr = Field(min_length=1)


class AuthoredClaimUnderTest(ClosedCanonicalModel):
    """One earlier-turn assertion tested by a final conversation turn."""

    turn: StrictInt = Field(ge=1)
    state_path: tuple[StrictStr, ...]
    note: StrictStr = Field(min_length=1)


class AuthoredScenarioDraft(ClosedCanonicalModel):
    """One historical authored scenario draft."""

    adversary: AuthoredAdversary
    stimulus: AuthoredStimulus
    state_facts_used: tuple[tuple[StrictStr, ...], ...] = ()
    unsafe_observation: AuthoredUnsafeObservation
    conditions_established: tuple[AuthoredConditionEntry, ...] = ()
    claims_under_test: tuple[AuthoredClaimUnderTest, ...] = ()
    safe_behaviors: tuple[StrictStr, ...] = ()
    obligation_ref: StrictStr | None = None


def stimulus_user_texts(stimulus: AuthoredStimulus) -> tuple[str, ...]:
    """Return each user text in a historical stimulus, in turn order."""
    if stimulus.kind == "conversation":
        return tuple(turn.text for turn in stimulus.turns or ())
    return (stimulus.text or "",)


def _oracle_templates_path() -> Path:
    """Resolve the closed oracle-template table in source or bundled layouts."""
    package = Path(__file__).resolve()
    source = package.parents[4] / "data" / "oracles" / ORACLE_TEMPLATES_FILENAME
    if source.is_file():
        return source
    return package.parents[2] / "data" / "oracles" / ORACLE_TEMPLATES_FILENAME


def load_oracle_templates() -> dict[str, str]:
    """Load the compiler-owned oracle-template table."""
    path = _oracle_templates_path()
    with path.open(encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict) or "templates" not in payload:
        raise ValueError("oracle templates file must carry a templates mapping")
    templates = payload["templates"]
    if not isinstance(templates, dict) or not templates:
        raise ValueError("oracle templates file must define at least one template")
    return {str(key): str(value) for key, value in templates.items()}


def render_oracle_text(kind: str, **values: Any) -> str:
    """Render one compiler-owned oracle template from validated values."""
    template = load_oracle_templates().get(kind)
    if template is None:
        raise ValueError(f"no oracle template for kind {kind!r}")
    try:
        return template.format(**values)
    except KeyError as exc:
        raise ValueError(
            f"oracle template {kind!r} is missing value {exc.args[0]!r}"
        ) from exc


class AuthoringResponse(ClosedCanonicalModel):
    """The historical closed authoring output: zero to three scenarios."""

    scenarios: tuple[AuthoredScenarioDraft, ...] = Field(default=(), max_length=3)
    no_scenario_reason: StrictStr | None = None

    @model_validator(mode="after")
    def validate_empty_case(self) -> "AuthoringResponse":
        if not self.scenarios and not (self.no_scenario_reason or "").strip():
            raise ValueError("empty authoring response requires no_scenario_reason")
        if self.scenarios and self.no_scenario_reason is not None:
            raise ValueError("no_scenario_reason is only valid when scenarios is empty")
        return self


__all__ = [
    "AUTHORED_STIMULUS_KIND",
    "AuthoringResponse",
    "AuthoredAdversary",
    "AuthoredClaimUnderTest",
    "AuthoredConditionEntry",
    "AuthoredScenarioDraft",
    "AuthoredStimulus",
    "AuthoredTriggerEvidence",
    "AuthoredTurn",
    "AuthoredUnsafeObservation",
    "ConditionBasis",
    "ObservationOperator",
    "OracleKind",
    "TriggerEvidenceSource",
    "UNSUPPORTED_ORACLE_KINDS",
    "load_oracle_templates",
    "render_oracle_text",
    "stimulus_user_texts",
]

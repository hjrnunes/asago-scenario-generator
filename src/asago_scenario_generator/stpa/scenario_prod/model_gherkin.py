"""Model-written declarative Gherkin for a scenario-handoff-v5.

After the narrate step, one request per published scenario asks the model
for the scenario's Gherkin: a feature and scenario name, the context
(``given``), the triggering events (``when``), the safe behavior (``then``)
and the hypothesized unsafe behavior (``unsafe``). Each step cites the
numbered facts of the narrate step plus one appended fact, the safe behavior
the handoff publishes as ``safe_alternative``.

Code checks every reply and never repairs it. A reply that breaks a rule
earns one correction naming every broken rule. A reply that still breaks one,
and any failed or refused call, keeps the code-rendered Gherkin and records
why. Code adds the Gherkin keywords and the unsafe-alternative comment.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any

from pydantic import Field

from asago_scenario_generator.stpa.infra.llm import DEFAULT_TEMPERATURE, LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    ExactFeedbackError,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

from ._constants import PROMPTS_DIR
from .narration import (
    ATTACK_STEP,
    FAILURE,
    Fact,
    ScenarioFacts,
    build_glossary,
    lower_first,
    text_failures,
    WireModel,
    word_count,
    build_facts,
    plain,
)

GHERKIN_STAGE = "stage6_gherkin"
GHERKIN_STEP = "write_gherkin"
GHERKINS_FILENAME = "gherkins.json"
SAFE_BEHAVIOR = "safe behavior"
MAX_NAME_WORDS = 12
MAX_STEP_WORDS = 25
# The inclusive step-count range of each reply list.
STEP_COUNTS: tuple[tuple[str, int, int], ...] = (
    ("given", 1, 4),
    ("when", 1, 3),
    ("then", 1, 2),
    ("unsafe", 1, 1),
)
_PARTS = tuple(part for part, _, _ in STEP_COUNTS)

_KEYWORD = re.compile(r"^(?:(given|when|then|and|but)\b|(\*))", re.IGNORECASE)
_NUMBER_WORDS = "one|two|three|four|five|six|seven|eight|nine|ten"
_ORDINALS = (
    r"first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth"
    r"|\d+(?:st|nd|rd|th)"
)
_TURN_NUMBER = re.compile(
    rf"\bturns?\s+(?:\d+|{_NUMBER_WORDS})\b|\b(?:{_ORDINALS})\s+turns?\b",
    re.IGNORECASE,
)


class GherkinMode(str, Enum):
    """Whether a run asks the model for each handoff's Gherkin.

    ``off`` sends no request and keeps the code-rendered Gherkin. ``handoff``
    publishes each accepted model Gherkin in the v5 handoff and its
    ``.feature`` companion.
    """

    OFF = "off"
    HANDOFF = "handoff"


class GherkinStepReply(WireModel):
    """One Gherkin step, without its keyword, and the facts it draws on."""

    text: str = Field(min_length=1)
    facts: list[str] = Field(min_length=1)


class GherkinReply(WireModel):
    """The model's declarative Gherkin for one scenario."""

    feature: str
    scenario: str
    given: list[GherkinStepReply] = Field(min_length=1, max_length=8)
    when: list[GherkinStepReply] = Field(min_length=1, max_length=8)
    then: list[GherkinStepReply] = Field(min_length=1, max_length=8)
    unsafe: list[GherkinStepReply] = Field(min_length=1, max_length=8)


def gherkin_facts(spec: ScenarioSpec, safe_alternative: str) -> ScenarioFacts:
    """Return the narrate facts plus the safe behavior as the next fact.

    The glossary also explains any structural identifier the appended fact
    adds; the narrate facts and their glossary entries stay as they are.
    """
    base = build_facts(spec)
    appended = Fact(f"F{len(base.facts) + 1}", SAFE_BEHAVIOR, plain(safe_alternative))
    facts = (*base.facts, appended)
    return replace(base, facts=facts, glossary=build_glossary(spec, facts))


def required_citations(facts: ScenarioFacts) -> list[tuple[str, str, list[str]]]:
    """Return each reply list's required citation: list, what it is, fact ids."""
    citations = [
        ("then", "the safe behavior", facts.ids_in([SAFE_BEHAVIOR])),
        ("unsafe", "the failure", facts.ids_in([FAILURE])),
    ]
    if facts.kind == "adversarial":
        citations.append(("when", "an attack step", facts.ids_in([ATTACK_STEP])))
    return [(part, name, ids) for part, name, ids in citations if ids]


def render_gherkin_prompts(
    facts: ScenarioFacts, loader: TemplateLoader | None = None
) -> tuple[str, str]:
    """Return the system and user prompts of one scenario's Gherkin request."""
    loader = loader or TemplateLoader(PROMPTS_DIR)
    counts = {part: (low, high) for part, low, high in STEP_COUNTS}
    system = loader.render_prompt(
        "stage6_gherkin_system.j2",
        counts=counts,
        max_name_words=MAX_NAME_WORDS,
        max_step_words=MAX_STEP_WORDS,
    )
    user = loader.render_prompt(
        "stage6_gherkin_user.j2",
        kind=facts.kind,
        facts=facts.facts,
        glossary=facts.glossary,
        citations=[
            (part, name, ", ".join(ids))
            for part, name, ids in required_citations(facts)
        ],
    )
    return system, user


def gherkin_failures(reply: GherkinReply, facts: ScenarioFacts) -> list[str]:
    """Return every rule the reply breaks, worded for a correction request."""
    failures: list[str] = []
    known = {fact.fact_id for fact in facts.facts}
    source_text = "\n".join(fact.text for fact in facts.facts)
    for part, low, high in STEP_COUNTS:
        count = len(getattr(reply, part))
        if not low <= count <= high:
            wanted = f"exactly {low}" if low == high else f"{low} to {high}"
            failures.append(f'"{part}" has {count} steps; write {wanted}')
    for label, name in (
        ("the feature name", reply.feature),
        ("the scenario name", reply.scenario),
    ):
        failures.extend(_shared_failures(label, name, MAX_NAME_WORDS, source_text))
    for part in _PARTS:
        for index, step in enumerate(getattr(reply, part), 1):
            label = f'"{part}" step {index}'
            failures.extend(
                _shared_failures(label, step.text, MAX_STEP_WORDS, source_text)
            )
            failures.extend(_step_failures(label, step.text))
            unknown = [item for item in step.facts if item not in known]
            if unknown:
                failures.append(
                    f"{label} cites {', '.join(unknown)}, which the fact list "
                    "does not have"
                )
    for part, name, ids in required_citations(facts):
        steps = getattr(reply, part)
        if not any(set(step.facts) & set(ids) for step in steps):
            failures.append(f'no "{part}" step cites {name}; cite {_one_of(ids)}')
    return failures


def _one_of(ids: Sequence[str]) -> str:
    return ids[0] if len(ids) == 1 else f"at least one of {', '.join(ids)}"


def _shared_failures(
    label: str, text: str, max_words: int, source_text: str
) -> list[str]:
    failures: list[str] = []
    if not text.strip():
        failures.append(f"{label} is blank")
    words = word_count(text)
    if words > max_words:
        failures.append(f"{label} has {words} words; use at most {max_words}")
    if "\n" in text or "\r" in text:
        failures.append(f"{label} spans more than one line; write it on one line")
    failures.extend(text_failures(label, text, source_text))
    return failures


def _step_failures(label: str, text: str) -> list[str]:
    failures: list[str] = []
    keyword = _KEYWORD.match(text.strip())
    if keyword:
        failures.append(
            f'{label} starts with the Gherkin keyword "{keyword.group(0)}"; code '
            "adds the keywords, so start with the subject"
        )
    turn = _TURN_NUMBER.search(text)
    if turn:
        failures.append(
            f'{label} names a turn ("{turn.group(0)}"); say what happens, not '
            "in which turn"
        )
    return failures


def gherkin_spec_from_reply(reply: GherkinReply) -> GherkinSpec:
    """Map an accepted reply to the Gherkin spec the handoff publishes."""
    return GherkinSpec(
        feature=reply.feature.strip(),
        scenario=reply.scenario.strip(),
        given=_keyed("Given", reply.given),
        when=_keyed("When", reply.when),
        then_expected=_keyed("Then", reply.then),
        then_actual=[f"But {lower_first(step.text.strip())}" for step in reply.unsafe],
    )


def _keyed(keyword: str, steps: Sequence[GherkinStepReply]) -> list[str]:
    return [
        f"{keyword if index == 0 else 'And'} {lower_first(step.text.strip())}"
        for index, step in enumerate(steps)
    ]


class _GherkinRejectedError(ExactFeedbackError):
    """A parsed reply that broke a rule."""


GHERKIN_CORRECTION_POLICY = CorrectionPolicy(
    validation_retries=1,
    feedback=(
        "\n\nCode rejected the prior reply. Return the whole reply again with "
        "every listed problem fixed."
    ),
    include_schema=False,
    include_response=True,
)


@dataclass
class GherkinOutcome:
    """The outcome of one scenario's Gherkin request."""

    scenario_id: str
    source: str = "fallback"
    requests: int = 0
    rejected: list[tuple[str, ...]] = field(default_factory=list)
    reason: str | None = None
    reply: dict[str, Any] | None = None
    gherkin: GherkinSpec | None = None

    @property
    def accepted(self) -> bool:
        return self.source == "model"

    def fall_back(self, reason: str) -> None:
        """Keep the code-rendered Gherkin and record why."""
        self.source = "fallback"
        self.reason = reason
        self.gherkin = None


def write_gherkin(
    spec: ScenarioSpec,
    safe_alternative: str,
    *,
    llm_client: LLMClient,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> GherkinOutcome:
    """Send one scenario's Gherkin request, with at most one correction."""
    facts = gherkin_facts(spec, safe_alternative)
    system, user = render_gherkin_prompts(facts, loader)
    outcome = GherkinOutcome(scenario_id=spec.scenario_id)

    def check(reply: GherkinReply) -> None:
        outcome.reply = reply.model_dump(mode="json")
        failures = gherkin_failures(reply, facts)
        if failures:
            outcome.rejected.append(tuple(failures))
            raise _GherkinRejectedError(
                "\n".join(
                    [
                        "the reply breaks these rules:",
                        *(f"- {item}" for item in failures),
                    ]
                )
            )

    try:
        result = call_with_policy(
            llm_client=llm_client,
            system_prompt=system,
            user_prompt=user,
            response_format=GherkinReply,
            run_dir=run_dir,
            stage=GHERKIN_STAGE,
            step=GHERKIN_STEP,
            policy=GHERKIN_CORRECTION_POLICY,
            slot_id=spec.threat_source.ica_slot_id,
            scenario_id=spec.scenario_id,
            temperature=temperature,
            result_validator=check,
        )
    except Exception as exc:  # noqa: BLE001 - a Gherkin failure never stops the run
        outcome.fall_back(f"{type(exc).__name__}: {exc}")
        return outcome
    outcome.requests = result.calls
    if result.value is not None:
        outcome.source = "model"
        outcome.gherkin = gherkin_spec_from_reply(result.value)
    else:
        outcome.fall_back(result.error or "the call returned no reply")
    return outcome


def write_gherkins(
    items: Sequence[tuple[ScenarioSpec, str]],
    *,
    llm_client: LLMClient,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    temperature: float | None = None,
) -> dict[str, GherkinOutcome]:
    """Request each scenario's Gherkin in order, given its safe alternative."""
    effective = DEFAULT_TEMPERATURE if temperature is None else temperature
    return {
        spec.scenario_id: write_gherkin(
            spec,
            safe_alternative,
            llm_client=llm_client,
            run_dir=run_dir,
            loader=loader,
            temperature=effective,
        )
        for spec, safe_alternative in items
    }


def gherkins_payload(outcomes: Sequence[GherkinOutcome]) -> dict[str, Any]:
    """Return the run's ``gherkins.json`` document."""
    return {
        "stage": GHERKIN_STAGE,
        "step": GHERKIN_STEP,
        "scenarios": [
            {
                "scenario_id": outcome.scenario_id,
                "source": outcome.source,
                "requests": outcome.requests,
                "rejected": [list(item) for item in outcome.rejected],
                "reason": outcome.reason,
                "reply": outcome.reply,
            }
            for outcome in outcomes
        ],
    }


def write_gherkins_file(run_dir: Path, payload: dict[str, Any]) -> Path:
    path = run_dir / GHERKINS_FILENAME
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return path

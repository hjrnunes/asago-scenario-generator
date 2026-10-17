"""Model-written scenario write-ups in published formats.

After the shape step, one request per published scenario asks the model for
the scenario's lead paragraph in the STPA Handbook's loss-scenario form
(Leveson and Thomas 2018, pp. 46-47): the situation, the unsafe action
"because" the agent wrongly believes something, how that flawed belief
arises, and the harm. The model cites numbered facts that code builds from
the scenario spec, and adds no fact of its own.

Code checks every reply and never repairs it. A reply that breaks a rule
earns one correction naming every broken rule. A reply that still breaks
one, and any failed call, keeps the deterministic narrative and records why.

Code renders the rest of the write-up: the attack steps from the closed
attack shape, as an ATLAS case-study procedure with ATLAS technique IDs, and
the misuse-case fields of Sindre and Opdahl (2001): misuser profile, worst
case threat, capture guarantee, and related business rules.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.stpa.infra.llm import DEFAULT_TEMPERATURE, LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    ExactFeedbackError,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.attack_shape import (
    AttackChannel,
    AttackShape,
    TurnPurpose,
    TurnShape,
    TurnSpeaker,
    default_attack_shape,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

from ._constants import PROMPTS_DIR
from .handoff import handoff_ownership_violations
from .presentation import (
    ADVERSARY_WORDS,
    CONTROLLER_WORDS,
    PURPOSE_WORDS,
    SPEAKER_WORDS,
    item_kind,
    selected_criterion,
)

NARRATION_STAGE = "stage6_narrative"
NARRATION_STEP = "narrate"
NARRATIVES_FILENAME = "narratives.json"
# Four sentences fit the loss-scenario form's four parts. Replies run longer
# than the word count the prompt asks for, so the check allows a margin.
MAX_SENTENCES = 4
WORDS_ASKED = 75
MAX_WORDS = 100
MAX_TITLE_WORDS = 12
FRAMING = "Test hypothesis, not an observed execution result."


class NarrationMode(str, Enum):
    """Where a run publishes the model-written write-up.

    ``off`` sends no request. ``report`` writes the write-up beside the
    handoff, which stays byte-identical to ``off``. ``handoff`` also puts it
    in the handoff's ``narrative`` field. The request does not depend on the
    mode, so a ``handoff`` run can replay a ``report`` run's recording.
    """

    OFF = "off"
    REPORT = "report"
    HANDOFF = "handoff"


SITUATION = "situation"
ATTACKER = "attacker"
ATTACKER_GOAL = "attacker goal"
ATTACKER_ASSUMPTION = "attacker assumption"
ATTACKER_PLAN = "attacker plan"
ATTACK_STEP = "attack step"
AGENT_BELIEF = "agent belief"
WEAK_POINT = "weak point"
UNSAFE_ACTION = "unsafe action"
FAILURE = "failure"
HAZARD = "hazard"
LOSS = "loss"

_COVERAGE: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    ("the situation", (SITUATION,), False),
    ("the unsafe action", (UNSAFE_ACTION, FAILURE), False),
    ("the weak point", (WEAK_POINT, AGENT_BELIEF), False),
    ("how the attacker brings it about", (ATTACK_STEP, ATTACKER_PLAN), True),
    ("the harm", (HAZARD, LOSS), False),
)

# ATLAS 2026.09 techniques (mitre-atlas/atlas-data dist/v6/ATLAS-2026.09.yaml).
ATLAS_TOOL_DATA_POISONING = ("AML.T0099", "AI Agent Tool Data Poisoning")
ATLAS_INDIRECT_INJECTION = ("AML.T0051.001", "LLM Prompt Injection: Indirect")
ATLAS_DIRECT_INJECTION = ("AML.T0051.000", "LLM Prompt Injection: Direct")
ATLAS_THREAD_POISONING = ("AML.T0080.001", "AI Agent Context Poisoning: Thread")

_ANNOTATION = re.compile(
    r"\s*\((?:documented operation|values|evidence):[^()]*(?:\([^()]*\)[^()]*)*\)"
)
_SOURCE_TAG = re.compile(r"\s*\[structural sources:[^\]]*\]")
_OPERATION_PREFIX = re.compile(r"\boperation:(?=[A-Za-z_])")
_STRUCTURAL_ID = re.compile(
    r"\b(?:PM|FB|CA)-\d+-\d+\b|\b(?:RESP|CL|CM|CP|H|L|SC|SEM)-\d+\b"
)
_FACT_ID = re.compile(r"\bF\d+\b")
_IDENTIFIER = re.compile(r"\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+\b|\b[A-Z]{2,}-?\d+\b")
_NUMBER = re.compile(r"\d+(?:[.,]\d+)?")
_LONG_QUOTE = re.compile(r"[\"\u201c][^\"\u201c\u201d]{40,}[\"\u201d]")
_APPLIES_WHEN = re.compile(r"\bapplies when\s*:", re.IGNORECASE)
NOT_SELECTED = "not selected as a causal factor"
_OWNERSHIP_WORDS = {
    "turn_array": 'the word "turn" or "turns" directly followed by a colon',
    "role_serialization": 'a speaker label such as "role: user"',
    "prepared_message_field": "the name of a prepared message field",
    "detector_expression": 'a comparison written as code, such as "amount <"',
    "ready_to_send_instruction": 'an instruction such as "send this message"',
    "judge_prompt": 'the words "judge prompt"',
}


def plain(text: str) -> str:
    """Drop the producer's inline annotations so a fact reads as prose.

    The annotations are source tags and the ``operation:`` prefix of
    operation names; the name itself stays.
    """
    text = _SOURCE_TAG.sub("", _ANNOTATION.sub("", text))
    text = _OPERATION_PREFIX.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


@dataclass(frozen=True)
class Fact:
    """One numbered statement the model may cite."""

    fact_id: str
    category: str
    text: str


@dataclass(frozen=True)
class AttackStep:
    """One code-rendered step of the attack, with its ATLAS technique."""

    text: str
    technique: tuple[str, str] | None


@dataclass(frozen=True)
class ScenarioFacts:
    """What the model may say about one scenario, and what it must cover."""

    scenario_id: str
    kind: str
    facts: tuple[Fact, ...]
    glossary: tuple[tuple[str, str], ...]
    coverage: tuple[tuple[str, tuple[str, ...]], ...]
    steps: tuple[AttackStep, ...] = ()

    def ids_in(self, categories: Sequence[str]) -> list[str]:
        return [fact.fact_id for fact in self.facts if fact.category in categories]


def build_facts(spec: ScenarioSpec) -> ScenarioFacts:
    """Number the scenario's facts in causal order and name what to cover."""
    adversarial = not spec.is_functional_test
    entries: list[tuple[str, str]] = []
    context = spec.scenario_context
    if context is not None:
        entries.append((SITUATION, plain(context.ica.hazardous_context)))
    steps: tuple[AttackStep, ...] = ()
    if adversarial:
        adversary = spec.adversary
        if adversary is not None:
            entries.append(
                (ATTACKER, ADVERSARY_WORDS.get(adversary.kind.value, "an attacker"))
            )
            entries.append((ATTACKER_GOAL, plain(adversary.gain)))
        entries.extend(
            (ATTACKER_ASSUMPTION, plain(item))
            for item in spec.attacker_bdi.beliefs
            if plain(item)
        )
        entries.extend(
            (ATTACKER_PLAN, plain(item))
            for item in spec.attacker_bdi.intentions
            if plain(item)
        )
        steps = attack_steps(spec.attack_shape or default_attack_shape(None))
        entries.extend((ATTACK_STEP, step.text) for step in steps)
    beliefs = {belief.pm_id: belief for belief in spec.defender_bdi.beliefs}
    factor_texts = {plain(factor.description) for factor in spec.causal_factors}
    for factor in spec.causal_factors:
        belief = beliefs.get(factor.source_id)
        if belief is not None and plain(belief.content):
            entries.append(
                (
                    AGENT_BELIEF,
                    belief_text(belief.content, belief.vulnerability, factor_texts),
                )
            )
        if plain(factor.description):
            entries.append((WEAK_POINT, plain(factor.description)))
    if context is not None:
        entries.append((UNSAFE_ACTION, plain(context.ica.exact_ica_text)))
    entries.append((FAILURE, plain(selected_criterion(spec))))
    if context is not None:
        entries.extend((HAZARD, plain(item.description)) for item in context.hazards)
        entries.extend((LOSS, plain(item.description)) for item in context.losses)
    facts = tuple(
        Fact(f"F{index}", category, text)
        for index, (category, text) in enumerate(_unique(entries), 1)
    )
    coverage = tuple(
        (name, categories)
        for name, categories, adversarial_only in _COVERAGE
        if (adversarial or not adversarial_only)
        and any(fact.category in categories for fact in facts)
    )
    return ScenarioFacts(
        scenario_id=spec.scenario_id,
        kind="adversarial" if adversarial else "everyday",
        facts=facts,
        glossary=_glossary(spec, facts),
        coverage=coverage,
        steps=steps,
    )


def _unique(entries: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[str] = set()
    kept = []
    for category, text in entries:
        if text and text not in seen:
            seen.add(text)
            kept.append((category, text))
    return kept


def belief_text(content: str, vulnerability: str, factor_texts: set[str]) -> str:
    """Name what the flawed belief is about; add its flaw unless a factor says it."""
    text = f"The flawed belief concerns: {_lower_first(plain(content).rstrip('.'))}."
    flaw = plain(vulnerability)
    if flaw and flaw not in factor_texts and NOT_SELECTED not in flaw.lower():
        text += f" Flaw: {flaw}"
    return text


def _lower_first(text: str) -> str:
    if len(text) > 1 and text[0].isupper() and not text[1].isupper():
        return text[0].lower() + text[1:]
    return text


def attack_steps(shape: AttackShape) -> tuple[AttackStep, ...]:
    """Render the attack shape as ordered steps, each with its ATLAS technique."""
    steps: list[AttackStep] = []
    indirect = shape.indirect
    if indirect is not None:
        item = indirect.data_item
        record = f" (record {item.record_ref})" if item.record_ref else ""
        controller = CONTROLLER_WORDS[indirect.party_relation.controller.value]
        steps.append(
            AttackStep(
                _sentence(
                    f"{controller} plants {item_kind(item.content_kind.value)}"
                    f"{record} in what {indirect.carrier_operation} returns"
                ),
                ATLAS_TOOL_DATA_POISONING,
            )
        )
    for turn in shape.turn_plan:
        steps.append(
            AttackStep(
                _sentence(_turn_words(turn, shape)), _turn_technique(turn, shape)
            )
        )
    return tuple(steps)


def _turn_words(turn: TurnShape, shape: AttackShape) -> str:
    carrier = shape.indirect.carrier_operation if shape.indirect else "its carrier"
    purpose = PURPOSE_WORDS[turn.purpose].format(carrier=carrier)
    return f"{SPEAKER_WORDS[turn.speaker]} {purpose}"


def _turn_technique(turn: TurnShape, shape: AttackShape) -> tuple[str, str] | None:
    if turn.speaker in (TurnSpeaker.FORGED_ASSISTANT, TurnSpeaker.FORGED_TOOL_RESULT):
        return ATLAS_THREAD_POISONING
    if turn.speaker is TurnSpeaker.ATTACKER_USER:
        return ATLAS_DIRECT_INJECTION
    if shape.channel is AttackChannel.INDIRECT and turn.purpose in (
        TurnPurpose.ASK_TO_READ_ITEM,
        TurnPurpose.FOLLOW_UP_ON_ITEM,
    ):
        return ATLAS_INDIRECT_INJECTION
    return None


def _sentence(text: str) -> str:
    text = text.strip().rstrip(",")
    return text[:1].upper() + text[1:] + ("" if text.endswith(".") else ".")


def _glossary(spec: ScenarioSpec, facts: Sequence[Fact]) -> tuple[tuple[str, str], ...]:
    """Explain each structural identifier the facts use, so the reply can avoid it."""
    meanings = _descriptions(spec)
    found: dict[str, str] = {}
    for fact in facts:
        for identifier in _STRUCTURAL_ID.findall(fact.text):
            if identifier in found:
                continue
            meaning = plain(meanings.get(identifier, ""))
            if not meaning:
                meaning = "no description is available; leave it out"
            elif identifier.startswith("RESP-"):
                # A responsibility is a duty of the agent, not another party.
                meaning = f"a responsibility of the agent: {meaning}"
            found[identifier] = meaning
    return tuple(found.items())


def _descriptions(spec: ScenarioSpec) -> dict[str, str]:
    """Map every structural identifier on the selected path to its description."""
    context = spec.scenario_context
    found: dict[str, str] = {}
    if context is None:
        return found
    path = context.target_control_path
    for item in path.process_model_parts:
        found[item.element_id] = item.description
    for item in path.feedback:
        found[item.element_id] = item.description
    for item in path.related_control_actions:
        found[item.action_id] = item.description
    found[path.control_action.action_id] = path.control_action.description
    coordination = path.coordination_path
    if coordination is not None:
        found[coordination.link_id] = coordination.description
        found[coordination.source.element_id] = coordination.source.description
        found[coordination.target.element_id] = coordination.target.description
        found[coordination.shared_process_model.element_id] = (
            coordination.shared_process_model.description
        )
        found[coordination.coordination_mechanism.element_id] = (
            coordination.coordination_mechanism.description
        )
        for item in coordination.controlled_processes:
            found[item.element_id] = item.description
    if path.responsibility is not None:
        found[path.responsibility.element_id] = path.responsibility.description
    controller_description = getattr(path.controller, "description", None)
    if controller_description:
        found[path.controller.element_id] = controller_description
    for hazard in context.hazards:
        found[hazard.hazard_id] = hazard.description
    for loss in context.losses:
        found[loss.loss_id] = loss.description
    for constraint in context.constraints:
        found[constraint.constraint_id] = constraint.description
    return found


class _Wire(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CitedSentence(_Wire):
    """One sentence of the lead paragraph and the facts it draws on."""

    text: str = Field(min_length=1)
    facts: list[str] = Field(min_length=1)


class NarrationReply(_Wire):
    """The model's title and lead paragraph for one scenario."""

    title: str = Field(min_length=1)
    sentences: list[CitedSentence] = Field(min_length=1, max_length=8)


def render_narration_prompts(
    facts: ScenarioFacts, loader: TemplateLoader | None = None
) -> tuple[str, str]:
    """Return the system and user prompts of one scenario's narrate request."""
    loader = loader or TemplateLoader(PROMPTS_DIR)
    system = loader.render_prompt(
        "stage6_narrate_system.j2",
        max_sentences=MAX_SENTENCES,
        max_words=WORDS_ASKED,
        max_title_words=MAX_TITLE_WORDS,
    )
    user = loader.render_prompt(
        "stage6_narrate_user.j2",
        kind=facts.kind,
        facts=facts.facts,
        glossary=facts.glossary,
        coverage=[
            (name, ", ".join(facts.ids_in(categories)))
            for name, categories in facts.coverage
        ],
    )
    return system, user


def narration_failures(reply: NarrationReply, facts: ScenarioFacts) -> list[str]:
    """Return every rule the reply breaks, worded for a correction request."""
    failures: list[str] = []
    known = {fact.fact_id for fact in facts.facts}
    source_text = "\n".join(fact.text for fact in facts.facts)
    count = len(reply.sentences)
    if count < 2 or count > MAX_SENTENCES:
        failures.append(
            f"the paragraph has {count} sentences; write 2 to {MAX_SENTENCES}"
        )
    words = sum(_word_count(sentence.text) for sentence in reply.sentences)
    if words > MAX_WORDS:
        failures.append(f"the paragraph has {words} words; use at most {WORDS_ASKED}")
    cited: set[str] = set()
    for index, sentence in enumerate(reply.sentences, 1):
        label = f"sentence {index}"
        unknown = [item for item in sentence.facts if item not in known]
        if unknown:
            failures.append(
                f"{label} cites {', '.join(unknown)}, which the fact list does not have"
            )
        cited.update(item for item in sentence.facts if item in known)
        failures.extend(_text_failures(label, sentence.text, source_text))
    for name, categories in facts.coverage:
        ids = facts.ids_in(categories)
        if not cited.intersection(ids):
            failures.append(
                f"no sentence cites {name}; cite at least one of {', '.join(ids)}"
            )
    if not any(
        "because" in text and "believe" in text
        for text in (sentence.text.lower() for sentence in reply.sentences)
    ):
        failures.append(
            'no sentence says why the agent acts, as in "because it incorrectly '
            'believes that ..."'
        )
    title_words = _word_count(reply.title)
    if title_words > MAX_TITLE_WORDS:
        failures.append(
            f"the title has {title_words} words; use at most {MAX_TITLE_WORDS}"
        )
    failures.extend(_text_failures("the title", reply.title, source_text))
    return failures


def _word_count(text: str) -> int:
    return len(text.split())


def _text_failures(label: str, text: str, source_text: str) -> list[str]:
    failures: list[str] = []
    structural = _STRUCTURAL_ID.findall(text)
    for identifier in dict.fromkeys(structural):
        failures.append(
            f"{label} writes the identifier {identifier}; write what the glossary "
            "says it is instead"
        )
    for identifier in dict.fromkeys(_FACT_ID.findall(text)):
        failures.append(
            f"{label} writes the fact identifier {identifier} in its text; cite it "
            'only in "facts"'
        )
    for identifier in dict.fromkeys(_IDENTIFIER.findall(text)):
        if identifier not in structural and identifier not in source_text:
            failures.append(
                f"{label} writes {identifier}, which no fact names; use a name "
                "exactly as a fact writes it, or plain words"
            )
    for number in dict.fromkeys(_NUMBER.findall(text)):
        if number not in source_text and not any(
            number in identifier for identifier in structural
        ):
            failures.append(f"{label} writes the number {number}, which no fact gives")
    if _LONG_QUOTE.search(text):
        failures.append(
            f"{label} quotes a long passage; say in your own words what it "
            "asks for instead of quoting a message"
        )
    for code in handoff_ownership_violations({"narrative": text}):
        slug = code.split(":", 1)[-1]
        failures.append(
            f"{label} contains {_OWNERSHIP_WORDS.get(slug, slug)}; reword it"
        )
    return failures


class _NarrationRejectedError(ExactFeedbackError):
    """A parsed reply that broke a rule."""


NARRATION_CORRECTION_POLICY = CorrectionPolicy(
    validation_retries=1,
    feedback=(
        "\n\nCode rejected the prior reply. Return the whole reply again with "
        "every listed problem fixed."
    ),
    include_schema=False,
    include_response=True,
)


@dataclass
class Narration:
    """The outcome of one scenario's narrate request."""

    scenario_id: str
    source: str
    title: str | None = None
    sentences: tuple[tuple[str, tuple[str, ...]], ...] = ()
    rejected: list[tuple[str, ...]] = field(default_factory=list)
    requests: int = 0
    reason: str | None = None

    @property
    def accepted(self) -> bool:
        return self.source == "model"

    @property
    def paragraph(self) -> str:
        return " ".join(text.strip() for text, _ in self.sentences)


def narrate_scenario(
    spec: ScenarioSpec,
    *,
    llm_client: LLMClient,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> tuple[ScenarioFacts, Narration]:
    """Send one scenario's narrate request, with at most one correction."""
    facts = build_facts(spec)
    system, user = render_narration_prompts(facts, loader)
    narration = Narration(scenario_id=spec.scenario_id, source="fallback")

    def check(reply: NarrationReply) -> None:
        failures = narration_failures(reply, facts)
        if failures:
            narration.rejected.append(tuple(failures))
            raise _NarrationRejectedError(
                "\n".join(
                    [
                        "the reply breaks these rules:",
                        *(f"- {item}" for item in failures),
                    ]
                )
            )

    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=system,
        user_prompt=user,
        response_format=NarrationReply,
        run_dir=run_dir,
        stage=NARRATION_STAGE,
        step=NARRATION_STEP,
        policy=NARRATION_CORRECTION_POLICY,
        slot_id=spec.threat_source.ica_slot_id,
        scenario_id=spec.scenario_id,
        temperature=temperature,
        result_validator=check,
    )
    narration.requests = outcome.calls
    if outcome.value is not None:
        narration.source = "model"
        narration.title = outcome.value.title.strip()
        narration.sentences = tuple(
            (sentence.text.strip(), tuple(sentence.facts))
            for sentence in outcome.value.sentences
        )
    else:
        narration.reason = outcome.error or "the call returned no reply"
    return facts, narration


def narrate_scenarios(
    specs: Sequence[ScenarioSpec],
    *,
    llm_client: LLMClient,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    temperature: float | None = None,
) -> dict[str, tuple[ScenarioFacts, Narration]]:
    """Narrate each scenario in order; a failure never stops the run."""
    effective = DEFAULT_TEMPERATURE if temperature is None else temperature
    return {
        spec.scenario_id: narrate_scenario(
            spec,
            llm_client=llm_client,
            run_dir=run_dir,
            loader=loader,
            temperature=effective,
        )
        for spec in specs
    }


def render_writeup(
    spec: ScenarioSpec, facts: ScenarioFacts, narration: Narration | None
) -> str:
    """Render the full write-up: framing, title, lead paragraph, steps, fields."""
    lines = [FRAMING, ""]
    if narration is not None and narration.accepted:
        lines.extend([f"{narration.title}", "", narration.paragraph, ""])
    if facts.steps:
        lines.append("Steps (ATLAS case-study procedure):")
        lines.extend(
            f"{index}. {step.text}"
            + (f" [{step.technique[0]} {step.technique[1]}]" if step.technique else "")
            for index, step in enumerate(facts.steps, 1)
        )
        lines.append("")
    lines.extend(_misuse_fields(spec))
    return "\n".join(lines).rstrip() + "\n"


def _misuse_fields(spec: ScenarioSpec) -> list[str]:
    fields: list[str] = []
    adversary = None if spec.is_functional_test else spec.adversary
    if adversary is not None:
        actor = ADVERSARY_WORDS.get(adversary.kind.value, "an attacker")
        fields.append(f"Misuser: {actor}. Wants: {plain(adversary.gain)}")
    fields.append(f"Fails if: {plain(selected_criterion(spec))}")
    context = spec.scenario_context
    if context is not None and context.losses:
        fields.append(
            "Worst case: "
            + " ".join(_end(plain(item.description)) for item in context.losses)
        )
    if spec.safe_observable_outcome is not None:
        fields.append(f"Safe outcome: {plain(spec.safe_observable_outcome.statement)}")
    if context is not None and context.constraints:
        fields.append(
            "Rules: "
            + " ".join(
                _end(rule_text(item.description)) for item in context.constraints
            )
        )
    return fields


def _end(text: str) -> str:
    text = text.strip()
    return text if text.endswith((".", "!", "?")) else text + "."


def rule_text(description: str) -> str:
    """State the rule in full; its applicability stays in the governing rules."""
    return plain(_APPLIES_WHEN.split(description, maxsplit=1)[0]).strip(" .")


def narratives_payload(
    specs: Sequence[ScenarioSpec],
    narrated: Mapping[str, tuple[ScenarioFacts, Narration]],
    *,
    mode: NarrationMode,
    deterministic: Mapping[str, str],
) -> dict[str, Any]:
    """Return the run's ``narratives.json`` document."""
    scenarios = []
    for spec in specs:
        entry = narrated.get(spec.scenario_id)
        if entry is None:
            continue
        facts, narration = entry
        scenarios.append(
            {
                "scenario_id": spec.scenario_id,
                "kind": facts.kind,
                "source": narration.source,
                "title": narration.title,
                "sentences": [
                    {"text": text, "facts": list(cited)}
                    for text, cited in narration.sentences
                ],
                "words": sum(_word_count(text) for text, _ in narration.sentences),
                "requests": narration.requests,
                "rejected": [list(item) for item in narration.rejected],
                "reason": narration.reason,
                "facts": [
                    {
                        "fact_id": fact.fact_id,
                        "category": fact.category,
                        "text": fact.text,
                    }
                    for fact in facts.facts
                ],
                "glossary": [list(item) for item in facts.glossary],
                "steps": [
                    {
                        "text": step.text,
                        "technique_id": step.technique[0] if step.technique else None,
                        "technique": step.technique[1] if step.technique else None,
                    }
                    for step in facts.steps
                ],
                "writeup": render_writeup(spec, facts, narration),
                "deterministic_narrative": deterministic.get(spec.scenario_id),
            }
        )
    return {
        "schema": "scenario-narratives-v1",
        "mode": mode.value,
        "stage": NARRATION_STAGE,
        "scenarios": scenarios,
    }


def write_narratives(run_dir: Path, payload: Mapping[str, Any]) -> Path:
    path = run_dir / NARRATIVES_FILENAME
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return path

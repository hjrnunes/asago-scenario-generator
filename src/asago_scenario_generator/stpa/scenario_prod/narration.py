"""Model-written scenario write-ups in published formats.

After the shape step, one request per published scenario asks the model for
the scenario's lead paragraph in the STPA Handbook's loss-scenario form
(Leveson and Thomas 2018, pp. 46-47): the situation, the unsafe action
"because" the agent wrongly believes something, how that flawed belief
arises, and the harm. When every causal factor is a faulty decision rule, the
agent's belief is correct, and the paragraph says the action happens because
of that rule instead. The model cites numbered facts that code builds from
the scenario spec, and adds no fact of its own.

Code checks every reply and never repairs it. A reply that breaks a rule
earns one correction naming every broken rule. A reply that still breaks
one, and any failed call, records why and publishes a plain paragraph code
writes from the same facts: the situation, the agent's beliefs, the weak
points, the failure and the worst case, with no identifier or source label.
The analysts' code-built account stays in ``narratives.json``.

Code renders the rest of the write-up: the attack steps from the closed
attack shape, as an ATLAS case-study procedure with ATLAS technique IDs, and
the misuse-case fields of Sindre and Opdahl (2001): misuser profile, worst
case threat, capture guarantee, and related business rules.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
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
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    is_belief_flaw,
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


SITUATION = "situation"
ATTACKER = "attacker"
ATTACKER_GOAL = "attacker goal"
ATTACKER_ASSUMPTION = "attacker assumption"
ATTACKER_PLAN = "attacker plan"
ATTACK_STEP = "attack step"
AGENT_BELIEF = "agent belief"
WEAK_POINT = "weak point"
DECISION_RULE = "decision rule"
UNSAFE_ACTION = "unsafe action"
FAILURE = "failure"
HAZARD = "hazard"
LOSS = "loss"

_COVERAGE: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    ("the situation", (SITUATION,), False),
    ("the unsafe action", (UNSAFE_ACTION, FAILURE), False),
    ("the weak point", (WEAK_POINT, AGENT_BELIEF, DECISION_RULE), False),
    ("how the attacker brings it about", (ATTACK_STEP, ATTACKER_PLAN), True),
    ("the harm", (HAZARD, LOSS), False),
)

# ATLAS 2026.05 techniques (the pinned data/taxonomies/atlas/ATLAS-2026.05.yaml).
ATLAS_TOOL_DATA_POISONING = ("AML.T0099", "AI Agent Tool Data Poisoning")
ATLAS_INDIRECT_INJECTION = ("AML.T0051.001", "LLM Prompt Injection: Indirect")
ATLAS_DIRECT_INJECTION = ("AML.T0051.000", "LLM Prompt Injection: Direct")
ATLAS_THREAD_POISONING = ("AML.T0080.001", "AI Agent Context Poisoning: Thread")
# The tactic each technique above achieves (relationships.<technique>.achieves).
ATLAS_PERSISTENCE = ("AML.TA0006", "Persistence")
ATLAS_EXECUTION = ("AML.TA0005", "Execution")
ATLAS_TACTICS = {
    ATLAS_TOOL_DATA_POISONING[0]: ATLAS_PERSISTENCE,
    ATLAS_INDIRECT_INJECTION[0]: ATLAS_EXECUTION,
    ATLAS_DIRECT_INJECTION[0]: ATLAS_EXECUTION,
    ATLAS_THREAD_POISONING[0]: ATLAS_PERSISTENCE,
}
# Where a step's attacker-influenced content enters the agent's context.
CHANNEL_TOOL_DATA = "tool_data"
CHANNEL_USER_TURN = "user_turn"
CHANNEL_FORGED_HISTORY = "forged_history"
_SPEAKER_CHANNELS = {
    TurnSpeaker.ATTACKER_USER: CHANNEL_USER_TURN,
    TurnSpeaker.BENIGN_USER: CHANNEL_USER_TURN,
    TurnSpeaker.FORGED_ASSISTANT: CHANNEL_FORGED_HISTORY,
    TurnSpeaker.FORGED_TOOL_RESULT: CHANNEL_FORGED_HISTORY,
}

_ANNOTATION = re.compile(
    r"\s*\((?:documented operation|values|evidence):[^()]*(?:\([^()]*\)[^()]*)*\)"
)
_SOURCE_TAG = re.compile(r"\s*\[structural sources:[^\]]*\]")
_OPERATION_PREFIX = re.compile(r"\boperation:(?=[A-Za-z_])")
_STRUCTURAL_ID = re.compile(
    r"\b(?:PM|FB|CA)-\d+-\d+\b|\b(?:RESP|CL|CM|CP|H|L|SC|SEM)-\d+\b"
)
_FACT_ID = re.compile(r"\bF\d+\b")
# Wording that attributes a false belief, assumption or impression to the
# agent. ``noun`` names a false belief: a false-belief noun phrase ("a mistaken
# assumption") or a noun such as "misconception". ``verb`` says someone holds
# one: a belief verb qualified as wrong ("wrongly assumes", "believes,
# wrongly,"), being under an impression or mistaken, or a mis- verb of
# judgement ("misreads"). Verbs of acting or deciding, such as "wrongly
# treats", describe a decision rule and stay allowed.
_FALSE_ADJECTIVE = (
    r"(?:false|wrong|mistaken|incorrect|erroneous|flawed|faulty|inaccurate"
    r"|misguided|misplaced|untrue)"
)
_BELIEF_NOUN = (
    r"(?:beliefs?|assumptions?|understanding|impressions?|premises?"
    r"|conclusions?|notions?|perceptions?|interpretations?|picture)"
)
_FALSE_ADVERB = (
    r"(?:incorrectly|wrongly|mistakenly|falsely|erroneously|wrongfully"
    r"|inaccurately)"
)
_BELIEF_VERB = (
    r"(?:believ\w*|think\w*|thought|assum\w*|conclud\w*|suppos\w*|presum\w*"
    r"|perceiv\w*|infer\w*|judg\w*|understand\w*|understood|imagin\w*)"
)
_FALSE_BELIEF = re.compile(
    rf"(?P<noun>\b{_FALSE_ADJECTIVE}\s+(?:\w+\s+)?{_BELIEF_NOUN}\b"
    r"|\b(?:misconceptions?|misapprehensions?|delusions?|illusions?)\b)"
    rf"|(?P<verb>\b{_FALSE_ADVERB}\s+(?:\w+\s+)?{_BELIEF_VERB}\b"
    rf"|\b{_BELIEF_VERB},?\s+{_FALSE_ADVERB}\b"
    r"|\bunder\s+(?:the|a|an|any)\s+(?:\w+\s+)?"
    r"(?:impression|illusion|misapprehension|belief|assumption)\b"
    r"|\b(?:is|was|being)\s+mistaken\b"
    r"|\bmis(?:believ|judg|read|interpret|understand|understood|perceiv"
    r"|conceiv|apprehend|took|takes)\w*)",
    re.IGNORECASE,
)
# A negation directly in front of the wording, with at most a determiner
# between, denies the false belief: "holds no false belief", "not a mistaken
# assumption", "rather than a false belief", "does not wrongly assume". A
# negation of another verb or clause ("does not question its false belief",
# "without checking, it wrongly assumes") denies nothing.
_DENIED = re.compile(
    r"(?:\b(?:no|not|never|without|nor|rather\s+than|instead\s+of"
    r"|not\s+because\s+of)|n't)\s+(?:(?:a|an|any|the|its|their)\s+)?$",
    re.IGNORECASE,
)
# A rule noun phrase is the subject of a ``verb`` wording, so that "its rule
# wrongly concludes" describes the faulty decision rule rather than a belief of
# the agent, only when it opens its clause and the wording follows it with at
# most an auxiliary and an adverb between. A clause opens at the start of the
# text; after a comma, semicolon, colon or dash, optionally followed by a
# coordinator ("the agent acts, and its rule ..."); after a subordinator that
# always starts a clause ("because", "when", "although"); or after "that" or
# "which" followed by a determiner ("that its rule"). The noun phrase is an
# optional determiner, at most two modifiers from a closed set (a possessive,
# a hyphenated compound, "decision", "own", or another rule noun), and a rule
# noun. Anything else, such as a verb or preposition whose object the rule is
# ("applies its rule then wrongly assumes", "under its policy it wrongly
# assumes"), a bare coordinator ("applies its threshold and its rule then
# wrongly assumes") or "that" as a determiner ("applies that rule then"),
# leaves the agent as the subject: a false positive costs one correction, a
# bypass publishes a false belief.
_RULE_NOUN = (
    r"(?:rules?|polic(?:y|ies)|logic|criterion|criteria|thresholds?"
    r"|algorithms?|heuristics?)"
)
_DETERMINER = r"(?:the|its|their|this|these|those|each|every|a|an)"
_RULE_SUBJECT = re.compile(
    r"(?:"
    r"(?:^|[,;:\u2013\u2014]\s*(?:(?:and|but|or|yet|so)\s+)?|\s-\s+"
    r"|\b(?:because|since|when|whenever|while|where|whereas|if|although"
    r"|though)\s+)"
    rf"(?:(?:{_DETERMINER}|that)\s+)?"
    rf"|\b(?:that|which)\s+{_DETERMINER}\s+"
    r")"
    rf"(?:(?:own|decision|\w+['\u2019]s|\w+(?:-\w+)+|{_RULE_NOUN})\s+){{0,2}}"
    rf"{_RULE_NOUN}\s+"
    r"(?:(?:is|was|does|did|can|may|might|will|would)\s+)?"
    r"(?:(?:\w+ly|also|still|then|always|often)\s+)?$",
    re.IGNORECASE,
)
_IDENTIFIER = re.compile(r"\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+\b|\b[A-Z]{2,}-?\d+\b")
_NUMBER = re.compile(r"\d+(?:[.,]\d+)?")
_LONG_QUOTE = re.compile(r"[\"\u201c][^\"\u201c\u201d]{40,}[\"\u201d]")
_APPLIES_WHEN = re.compile(r"\bapplies when\s*:", re.IGNORECASE)
_SOURCE_KEY = re.compile(r"\b[A-Z]+-\d+(?:-\d+)*(?::[A-Za-z0-9_-]+)+")
_SCENARIO_ID = re.compile(r"\bSCN-\d+\b")
_ICA_CODE = re.compile(r"\b(?:UCA|ICA)-?\d+\b")
_SOURCE_LABEL = re.compile(
    r"\b(?:structural sources?|sources?|authority)\s*:", re.IGNORECASE
)
# What a fallback paragraph must not carry: structural, fact, scenario and
# source identifiers, and the source labels of the analysts' account.
_FALLBACK_BANNED = (
    _SOURCE_KEY,
    _STRUCTURAL_ID,
    _FACT_ID,
    _SCENARIO_ID,
    _ICA_CODE,
    _SOURCE_LABEL,
)
_REFERENCE = "|".join(f"(?:{pattern.pattern})" for pattern in _FALLBACK_BANNED[:5])
# A bracketed group that only annotates the statement before it: references
# alone, or a labelled source note.
_REFERENCE_NOTE = re.compile(
    rf"\s*[(\[]\s*(?:{_REFERENCE})(?:\s*(?:[,;/]|\band\b)\s*(?:{_REFERENCE}))*\s*[)\]]"
    r"|\s*[(\[]\s*(?i:structural sources?|sources?|authority|kind|evidence)\s*:"
    r"[^()\[\]]*[)\]]"
)
# The noun phrase each kind of structural identifier reads as in a sentence.
# A process-model part or feedback with a description names it.
_DESCRIBED_NOUNS = {"PM": "the agent's record of {}", "FB": "the feedback on {}"}
_KIND_NOUNS = {
    "PM": "the agent's own record",
    "FB": "the feedback the agent receives",
    "CA": "the agent's action",
    "RESP": "a duty of the agent",
    "CL": "one of the system's controllers",
    "CM": "the coordination between controllers",
    "CP": "the process the agent controls",
    "H": "a hazard",
    "L": "a loss",
    "SC": "a safety rule",
    "SEM": "a value the test supplies",
}
# Analyst commentary: a statement about how this scenario is checked or
# judged. It names the analysis's own checker (a judge, evaluator, grader or
# oracle, or a bare "the detector", "the check" or "the test" whose verdict
# falls on the reply under test), or the scenario, test or criterion itself.
# A domain statement keeps its words: a smoke detector that flags an alarm,
# or a transaction that "should be flagged as fraudulent". When in doubt a
# clause is kept.
_MODAL = r"(?:would|will|should|could|can|may|might|must)"
_VERDICT = r"(?:flag|catch|judge|score|mark|fail|pass)"
_ANALYSIS_CHECKER = r"(?:judge|evaluator|grader|oracle)s?"
_COMMENTARY = re.compile(
    rf"\b(?:the|this|an?)\s+{_ANALYSIS_CHECKER}\s+{_MODAL}\s+(?:not\s+)?{_VERDICT}\b"
    rf"|\b(?:the|this)\s+(?:detector|check|checker|test)\s+{_MODAL}\s+(?:not\s+)?"
    rf"{_VERDICT}\s+(?:it|this|that|them|the\s+(?:response|reply|output|answer|call))\b"
    rf"|\b(?:flagged|caught|judged|scored|marked)\s+by\s+(?:the|an?)\s+"
    rf"{_ANALYSIS_CHECKER}\b"
    r"|\bthis\s+(?:scenario|test|hypothesis|analysis)\s+"
    r"(?:tests|checks|shows|assumes|expects|asserts|examines)\b"
    r"|\bthe\s+(?:failure|pass|fail|semantic|unsafe[- ]outcome)\s+criterion\s+"
    r"(?:holds|fails|passes|fires|matches|is met)\b",
    re.IGNORECASE,
)
_CLAUSE_BREAK = re.compile(
    r"(;\s+|(?<=[.!?])\s+|,\s+(?:which|and|so|but)\s+|\s+(?:—|--)\s+)"
)
# Expressions the handoff's ownership rules reject in prose, and the plain
# words each reads as. A comparison reads as an adjective phrase, which fits
# both a noun it modifies ("an amount greater than 1000") and a copula
# ("the amount is not greater than 1000"); "is" joins it to a noun only where
# the noun opens a clause ("whose amount is greater than 1000").
_COMPARISON = re.compile(r"(?<![-<>=!])\s*(>=|<=|!=|==|>|<|=)\s*(?=[\w\"'$€£+-])")
_COMPARISON_WORDS = {
    ">=": "at least",
    "<=": "at most",
    "!=": "different from",
    "==": "equal to",
    "=": "equal to",
    ">": "greater than",
    "<": "less than",
}
_COPULA = re.compile(
    r"\b(?:is|are|was|were|be|been|being|isn't|aren't|wasn't|weren't)"
    r"(?:\s+(?:not|never|no longer))?\s*$",
    re.IGNORECASE,
)
_CLAUSE_OPENERS = frozenset(
    "whose when whenever if where while unless until once because after "
    "before that".split()
)
_DETERMINERS = frozenset(
    "a an the any each every its their his her our your this these those "
    "some no all both".split()
)
_PLURAL_DETERMINERS = frozenset("these those all both".split())
# The words a compared subject may hold between its nouns, each of which
# may take a determiner of its own: "the refund and the fee", "the balance
# of the account".
_SUBJECT_LINKS = frozenset("and or of".split())
# A compared subject holds no finite verb. These words always mark one: an
# auxiliary or modal, a negation or frequency adverb that sits in a verb
# phrase, or a common irregular past form.
_VERB_WORDS = frozenset(
    "is are was were be been being am has have had does do did can could will "
    "would shall should must may might not never always often sent paid made "
    "took gave got kept left held sold bought brought ran told found".split()
)
# Words ending in -s that name a thing, not an action, inside a subject.
_NOUNS_IN_S = frozenset(
    "series news goods funds savings earnings sales terms settings details "
    "means metrics analytics logistics".split()
)
# The words that can follow a compared value which closes its own clause.
_FOLLOWING_WORDS = frozenset(
    "for in on at with without by to from during after before when while if "
    "unless and or but so per of than".split()
)
_PROSE_FORMS = (
    (re.compile(r"\bgreater_than\b", re.IGNORECASE), "greater than"),
    (re.compile(r"\bless_than\b", re.IGNORECASE), "less than"),
    (re.compile(r"\bprepared_user_text\b", re.IGNORECASE), "prepared user text"),
    (
        re.compile(r"\b(roles?)\s*\"?\s*:\s*\"?(user|assistant|system)\b", re.I),
        r"the \2 \1",
    ),
    (re.compile(r"\b(turns?)\s*\"?\s*:", re.IGNORECASE), r"\1"),
    (re.compile(r"\b(send|deliver) this message\b", re.IGNORECASE), r"\1 the message"),
    (
        re.compile(r"\bexecute the following\b", re.IGNORECASE),
        "carry out the following",
    ),
    (re.compile(r"\bsystem prompt is\b", re.IGNORECASE), "system prompt reads"),
    (re.compile(r"\bjudge prompt\b", re.IGNORECASE), "judging instructions"),
)
# The parts of a fallback paragraph, as the producer report and the handoff
# name the ones a paragraph leaves out.
SITUATION_PART = "situation"
BELIEFS_PART = "agent's beliefs"
WEAK_POINTS_PART = "weak points"
FAILURE_PART = "failure"
WORST_CASE_PART = "worst case"
FALLBACK_LAST_RESORT = "The agent may take an unsafe action in this situation."
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
    channel: str


@dataclass(frozen=True)
class ScenarioFacts:
    """What the model may say about one scenario, and what it must cover."""

    scenario_id: str
    kind: str
    facts: tuple[Fact, ...]
    glossary: tuple[tuple[str, str], ...]
    coverage: tuple[tuple[str, tuple[str, ...]], ...]
    steps: tuple[AttackStep, ...] = ()
    # True when the agent-belief facts state the factors' flawed beliefs; the
    # sentence that says why the agent acts must then cite one of them.
    stated_beliefs: bool = False
    # True when every factor is a faulty decision rule: the agent's belief is
    # correct, so the sentence that says why the agent acts cites a decision
    # rule fact and says no belief is false.
    rule_only: bool = False

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
    stated = any(factor.flawed_belief for factor in spec.causal_factors)
    for factor in spec.causal_factors:
        belief = beliefs.get(factor.source_id)
        if stated:
            if factor.flawed_belief:
                entries.append((AGENT_BELIEF, stated_belief_text(factor)))
        elif belief is not None and plain(belief.content):
            entries.append(
                (
                    AGENT_BELIEF,
                    belief_text(belief.content, belief.vulnerability, factor_texts),
                )
            )
        if plain(factor.description):
            category = WEAK_POINT if is_belief_flaw(factor.kind) else DECISION_RULE
            entries.append((category, plain(factor.description)))
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
        glossary=build_glossary(spec, facts),
        coverage=coverage,
        steps=steps,
        stated_beliefs=stated,
        rule_only=bool(spec.causal_factors)
        and not any(is_belief_flaw(factor.kind) for factor in spec.causal_factors),
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
    text = f"The flawed belief concerns: {lower_first(plain(content).rstrip('.'))}."
    flaw = plain(vulnerability)
    if flaw and flaw not in factor_texts and NOT_SELECTED not in flaw.lower():
        text += f" Flaw: {flaw}"
    return text


def stated_belief_text(factor: CausalFactor) -> str:
    """State a factor's flawed belief and the variable that holds it, if any."""
    text = (
        "The agent wrongly believes that "
        f"{lower_first(plain(factor.flawed_belief or '').rstrip('.'))}."
    )
    variable = factor.process_model_variable
    if variable is not None and variable.pm_id is not None:
        text += (
            " The belief concerns: "
            f"{lower_first(plain(variable.description).rstrip('.'))}."
        )
    return text


def weak_point_belief_text(factor: CausalFactor) -> str:
    """State a factor's flawed belief and its variable, or the variable it lacks."""
    text = (
        "The agent wrongly believes that "
        f"{lower_first(plain(factor.flawed_belief or '').rstrip('.'))}."
    )
    variable = factor.process_model_variable
    if variable is None:
        return text
    description = lower_first(plain(variable.description).rstrip("."))
    if variable.pm_id is None:
        return f"{text} No process-model variable; missing: {description}."
    return f"{text} Process-model variable: {description}."


def lower_first(text: str) -> str:
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
                CHANNEL_TOOL_DATA,
            )
        )
    for turn in shape.turn_plan:
        steps.append(
            AttackStep(
                _sentence(_turn_words(turn, shape)),
                _turn_technique(turn, shape),
                _SPEAKER_CHANNELS[turn.speaker],
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


def build_glossary(
    spec: ScenarioSpec, facts: Sequence[Fact]
) -> tuple[tuple[str, str], ...]:
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


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CitedSentence(WireModel):
    """One sentence of the lead paragraph and the facts it draws on."""

    text: str = Field(min_length=1)
    facts: list[str] = Field(min_length=1)


class NarrationReply(WireModel):
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
        rule_only=facts.rule_only,
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
        belief_ids=(
            ", ".join(facts.ids_in((AGENT_BELIEF,))) if facts.stated_beliefs else ""
        ),
        rule_ids=", ".join(facts.ids_in((DECISION_RULE,))) if facts.rule_only else "",
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
    words = sum(word_count(sentence.text) for sentence in reply.sentences)
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
        failures.extend(text_failures(label, sentence.text, source_text))
    for name, categories in facts.coverage:
        ids = facts.ids_in(categories)
        if not cited.intersection(ids):
            failures.append(
                f"no sentence cites {name}; cite at least one of {', '.join(ids)}"
            )
    if facts.rule_only:
        failures.extend(_rule_reason_failures(reply, facts))
    else:
        failures.extend(_belief_reason_failures(reply, facts))
    title_words = word_count(reply.title)
    if title_words > MAX_TITLE_WORDS:
        failures.append(
            f"the title has {title_words} words; use at most {MAX_TITLE_WORDS}"
        )
    failures.extend(text_failures("the title", reply.title, source_text))
    return failures


def _belief_reason_failures(reply: NarrationReply, facts: ScenarioFacts) -> list[str]:
    """Check the sentence that explains the action by an incorrect belief."""
    failures: list[str] = []
    reasons = [
        sentence
        for sentence in reply.sentences
        if "because" in sentence.text.lower() and "believe" in sentence.text.lower()
    ]
    if not reasons:
        failures.append(
            'no sentence says why the agent acts, as in "because it incorrectly '
            'believes that ..."'
        )
    belief_ids = facts.ids_in((AGENT_BELIEF,)) if facts.stated_beliefs else []
    if (
        reasons
        and belief_ids
        and not any(set(sentence.facts) & set(belief_ids) for sentence in reasons)
    ):
        failures.append(
            "the sentence that says why the agent acts cites no agent belief "
            f"fact; cite the one whose belief it states: {', '.join(belief_ids)}"
        )
    return failures


def _rule_reason_failures(reply: NarrationReply, facts: ScenarioFacts) -> list[str]:
    """Check the sentence that explains the action by a faulty decision rule."""
    failures: list[str] = []
    reasons = [
        sentence for sentence in reply.sentences if "because" in sentence.text.lower()
    ]
    rule_ids = facts.ids_in((DECISION_RULE,))
    if not reasons:
        failures.append(
            'no sentence says why the agent acts, as in "because the rule it '
            'applies ..."'
        )
    elif rule_ids and not any(
        set(sentence.facts) & set(rule_ids) for sentence in reasons
    ):
        failures.append(
            "the sentence that says why the agent acts cites no decision rule "
            f"fact; cite the one whose rule it states: {', '.join(rule_ids)}"
        )
    labelled = [
        *(
            (f"sentence {index}", item.text)
            for index, item in enumerate(reply.sentences, 1)
        ),
        ("the title", reply.title),
    ]
    for label, text in labelled:
        wording = false_belief_wording(text)
        if wording is not None:
            failures.append(
                f'{label} attributes a false belief to the agent ("{wording}"); '
                "its belief is correct here, so explain the action by its faulty "
                "decision rule"
            )
    return failures


def false_belief_wording(text: str) -> str | None:
    """Return the first wording that attributes a false belief to the agent.

    Wording that a negation directly in front denies, such as "holds no false
    belief", does not count, and neither does a belief verb whose subject is
    a rule noun phrase that opens its clause, such as "because its rule
    wrongly concludes". A false-belief noun phrase counts whatever comes
    before it: a rule holds no belief.
    """
    for match in _FALSE_BELIEF.finditer(text):
        before = text[: match.start()]
        if _DENIED.search(before):
            continue
        if match.group("verb") and _RULE_SUBJECT.search(before):
            continue
        return match.group(0)
    return None


def word_count(text: str) -> int:
    return len(text.split())


def text_failures(label: str, text: str, source_text: str) -> list[str]:
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


@dataclass(frozen=True)
class FallbackNarrative:
    """A fallback paragraph and what of its facts it does not state.

    ``omitted`` names each part with a fact, or a clause of one, that no
    plain clause states. ``commentary`` holds the clauses of analyst
    commentary the paragraph leaves out on purpose.
    """

    text: str
    omitted: tuple[str, ...] = ()
    commentary: tuple[str, ...] = ()


@dataclass(frozen=True)
class PublishedNarrative:
    """The narrative a scenario's handoff publishes, and whether code wrote it.

    ``fallback`` is true when no accepted model paragraph was available and
    the text is :func:`write_fallback`'s; ``omitted`` names the parts that
    paragraph does not fully state.
    """

    text: str
    fallback: bool = False
    omitted: tuple[str, ...] = ()


def fallback_narrative(spec: ScenarioSpec) -> str:
    """Return the text of :func:`write_fallback`."""
    return write_fallback(spec).text


def write_fallback(spec: ScenarioSpec) -> FallbackNarrative:
    """Write the plain paragraph a scenario publishes when its narration fails.

    Fixed sentences tell the narration's facts: the situation, why the agent
    acts (its flawed beliefs and the weak points), the failure, and the worst
    case. Each fact keeps its words, without what only annotates it: a
    bracketed identifier, a fact citation, a source note, or a clause of
    analyst commentary on how the scenario is checked. A structural
    identifier that is part of the sentence reads as a noun phrase for its
    kind, and an expression the handoff's ownership rules reject, such as
    ``amount > 1000``, reads as plain words. The paragraph never carries what
    :func:`fallback_failures` names. A part with a fact, or a clause of one,
    that leaves no plain clause is named in ``omitted``, so the caller can
    record it.
    """
    meanings = _descriptions(spec)
    context = spec.scenario_context
    omitted: list[str] = []
    commentary: list[str] = []

    def stated(part: str, texts: Sequence[str | None]) -> list[str]:
        given = [text for text in texts if text and text.strip()]
        clauses: list[str] = []
        for text in dict.fromkeys(given):
            clause, removed, lost = _fact_clause(text, meanings)
            commentary.extend(removed)
            if clause and clause not in clauses:
                clauses.append(clause)
            if (lost or not clause) and part not in omitted:
                omitted.append(part)
        return clauses

    sentences: list[str] = []
    situation = stated(
        SITUATION_PART, [context.ica.hazardous_context] if context else []
    )
    if situation:
        when = re.sub(r"^when\s+", "", situation[0])
        sentences.append(f"The scenario arises when {when}.")
    sentences.extend(_reason_sentences(spec, stated))
    failure = stated(FAILURE_PART, [selected_criterion(spec)])
    if failure:
        sentences.append(f"The unsafe outcome is that {failure[0]}.")
    harms = stated(
        WORST_CASE_PART,
        [item.description for item in context.losses] if context else [],
    )
    if len(harms) == 1:
        sentences.append(f"The worst case is this: {harms[0]}.")
    elif harms:
        sentences.append(f"The worst cases are these: {'; '.join(harms)}.")
    return FallbackNarrative(
        " ".join(sentences) or FALLBACK_LAST_RESORT,
        tuple(omitted),
        tuple(dict.fromkeys(commentary)),
    )


def _reason_sentences(
    spec: ScenarioSpec, stated: Callable[[str, Sequence[str | None]], list[str]]
) -> list[str]:
    """Say why the agent acts: its flawed beliefs or rule, then the weak points."""
    factors = spec.causal_factors
    belief_factors = [factor for factor in factors if is_belief_flaw(factor.kind)]
    reason = ""
    if any(factor.flawed_belief for factor in factors):
        beliefs = stated(BELIEFS_PART, [factor.flawed_belief for factor in factors])
        if beliefs:
            reason = "it wrongly believes that " + ", and that ".join(beliefs)
    else:
        held = {belief.pm_id: belief.content for belief in spec.defender_bdi.beliefs}
        topics = stated(
            BELIEFS_PART, [held.get(factor.source_id) for factor in belief_factors]
        )
        if len(topics) == 1:
            reason = f"its belief about {topics[0]} is wrong"
        elif topics:
            reason = f"its beliefs about {' and '.join(topics)} are wrong"
    if len(belief_factors) < len(factors):
        rule = "it applies a faulty decision rule"
        reason = f"{reason}, and {rule}" if reason else rule
    weak = stated(WEAK_POINTS_PART, [factor.description for factor in factors])
    weak_text = ""
    if weak:
        noun = "weak point is" if len(weak) == 1 else "weak points are"
        weak_text = f"the {noun} that " + ", and that ".join(weak)
    if reason and weak_text:
        return [f"The agent acts unsafely because {reason}; {weak_text}."]
    if reason:
        return [f"The agent acts unsafely because {reason}."]
    if weak_text:
        return [_sentence(weak_text)]
    return []


def _fact_clause(
    text: str, meanings: Mapping[str, str]
) -> tuple[str, list[str], list[str]]:
    """Return a fact as a plain clause, its commentary, and its lost clauses.

    References and source notes go first, so a note never hides the
    statement it annotates. Each clause of analyst commentary is then left
    out, and each clause the ownership rules still reject once its
    expressions read as words is lost and reported.
    """
    text = _without_references(plain(text), meanings)
    text, commentary = _split_off(text, lambda clause: bool(_COMMENTARY.search(clause)))
    text, lost = _split_off(
        _as_prose(text),
        lambda clause: bool(handoff_ownership_violations({"narrative": clause})),
    )
    return lower_first(text.rstrip(" .;,")), commentary, lost


def _clause(text: str | None, meanings: Mapping[str, str]) -> str:
    """Return a fact as a lower-case plain clause without its end stop."""
    return _fact_clause(text or "", meanings)[0]


def _split_off(text: str, drop: Callable[[str], bool]) -> tuple[str, list[str]]:
    """Leave out each clause ``drop`` names; keep the clauses around it."""
    pieces = _CLAUSE_BREAK.split(text)
    kept: list[str] = []
    dropped: list[str] = []
    for index, segment in enumerate(pieces[0::2]):
        if segment.strip() and drop(segment):
            dropped.append(segment.strip())
            stop = segment.rstrip()[-1:]
            if kept and stop in ".!?" and not kept[-1].rstrip().endswith(stop):
                kept[-1] = kept[-1].rstrip(" ,;") + stop
            continue
        if kept:
            kept.append(pieces[2 * index - 1])
        kept.append(segment)
    return "".join(kept).strip(), dropped


def _as_prose(text: str) -> str:
    """Write the expressions the ownership rules reject as plain words."""

    def words(match: re.Match[str]) -> str:
        before = match.string[: match.start()]
        after = match.string[match.end() :]
        return f" {_comparison_words(before, match.group(1), after)} "

    text = _COMPARISON.sub(words, text)
    for pattern, replacement in _PROSE_FORMS:
        text = pattern.sub(replacement, text)
    return re.sub(r"\s+", " ", text).strip()


def _comparison_words(before: str, operator: str, after: str = "") -> str:
    """Read a comparison operator as words that fit the text around it.

    The adjective phrase fits a copula ("is not greater than") and a noun it
    modifies ("refunds greater than 1000"), so it is the reading unless the
    compared words are positively a clause's subject. Then "is" or "are"
    joins them: after a clause opener such as "if", "when", "unless" or
    "whose" ("if the refund amount is greater than 1000"), or at the clause's
    start when the compared value ends the clause or a preposition follows
    it ("The amount is at most 10 for every refund"). :func:`_subject` says
    whether the words before the operator are such a subject.
    """
    words = _COMPARISON_WORDS[operator]
    if _COPULA.search(before):
        return words
    tokens = re.findall(r"[\w'-]+|[;,.:!?(]", before)
    start = len(tokens)
    while (
        start > 0
        and tokens[start - 1][0].isalnum()
        and tokens[start - 1].lower() not in _CLAUSE_OPENERS
    ):
        start -= 1
    phrase = [token.lower() for token in tokens[start:]]
    boundary = tokens[start - 1].lower() if start > 0 else ""
    if boundary == "that" and not (phrase and phrase[0] in _DETERMINERS):
        # "that" before a bare noun is a determiner ("pays that amount").
        return words
    subject = _subject(phrase)
    if subject is None:
        return words
    if boundary not in _CLAUSE_OPENERS and not _ends_comparison(after):
        return words
    return f"{'are' if subject else 'is'} {words}"


def _subject(phrase: Sequence[str]) -> bool | None:
    """Whether ``phrase`` is a plural subject, a singular one, or no subject.

    A subject is an optional determiner and up to four words naming a thing,
    joined only by "and", "or" or "of", and holding no finite verb. A word
    is a finite verb if it is in :data:`_VERB_WORDS`, or if it ends in -s or
    -ed between two other words of the phrase, as "pays" does in "the agent
    pays amounts": the head noun before the operator and the first word
    after the determiner ("the refunded amount") are never taken for verbs.
    """
    if not phrase:
        return None
    determiner = phrase[0] if phrase[0] in _DETERMINERS else ""
    nominal = list(phrase[1:] if determiner else phrase)
    content = [word for word in nominal if word not in _SUBJECT_LINKS]
    if not content or len(content) > 4:
        return None
    for index, word in enumerate(nominal):
        if word in _VERB_WORDS:
            return None
        if word in _DETERMINERS and (
            index == 0 or nominal[index - 1] not in _SUBJECT_LINKS
        ):
            return None
        inner = (
            0 < index < len(nominal) - 1 and nominal[index - 1] not in _SUBJECT_LINKS
        )
        if inner and _verb_form(word):
            return None
    head = nominal[-1]
    if head in _SUBJECT_LINKS or head in _DETERMINERS:
        return None
    return (
        determiner in _PLURAL_DETERMINERS
        or "and" in nominal
        or (_plural_form(head) and head not in {"news", "series"})
    )


def _verb_form(word: str) -> bool:
    """Whether a word inside a subject reads as a finite verb form."""
    if word.endswith("ed"):
        return True
    return _plural_form(word) and word not in _NOUNS_IN_S


def _plural_form(word: str) -> bool:
    return word.endswith("s") and not word.endswith(("ss", "us", "is"))


def _ends_comparison(after: str) -> bool:
    """Whether the compared value ends its clause or a preposition follows it."""
    value, _, rest = after.strip().partition(" ")
    following = rest.split(" ", 1)[0]
    return (
        value[-1:] in ".,;:!?)"
        or not following
        or not following[0].isalnum()
        or following.lower() in _FOLLOWING_WORDS
    )


def _without_references(text: str, meanings: Mapping[str, str]) -> str:
    """Drop annotating references; read the others as noun phrases."""

    def noun(match: re.Match[str], *, described: bool = True) -> str:
        identifier = match.group(0)
        kind = identifier.split("-", 1)[0]
        template = _DESCRIBED_NOUNS.get(kind)
        meaning = plain(meanings.get(identifier, "")) if described else ""
        if template and meaning:
            meaning = _without_references(meaning, {}).rstrip(" .;,")
            if meaning:
                return template.format(lower_first(meaning))
        return _KIND_NOUNS.get(kind, "")

    text = _REFERENCE_NOTE.sub("", text)
    text = _SOURCE_KEY.sub("", text)
    text = _STRUCTURAL_ID.sub(lambda match: noun(match, described=bool(meanings)), text)
    text = _SCENARIO_ID.sub("this scenario", text)
    for pattern in (_FACT_ID, _ICA_CODE, _SOURCE_LABEL):
        text = pattern.sub("", text)
    text = re.sub(r"[(\[]\s*[)\]]", "", text)
    # A dropped reference can leave its conjunction or comma behind.
    text = re.sub(r"(?:\s*,|\s+(?:and|or|per))+\s*(?=[.;,)\]]|$)", "", text)
    text = re.sub(r"\s+([,.;:)\]])", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def fallback_failures(text: str) -> list[str]:
    """Return each identifier or source label a fallback paragraph carries."""
    found: list[str] = []
    for pattern in _FALLBACK_BANNED:
        found.extend(match.group(0) for match in pattern.finditer(text))
    return list(dict.fromkeys(found))


def narratives_payload(
    specs: Sequence[ScenarioSpec],
    narrated: Mapping[str, tuple[ScenarioFacts, Narration]],
    *,
    deterministic: Mapping[str, str],
    fallbacks: Mapping[str, FallbackNarrative] | None = None,
) -> dict[str, Any]:
    """Return the run's ``narratives.json`` document.

    ``fallbacks`` holds the plain paragraph each scenario without an accepted
    reply publishes, the parts it does not fully state, and the analyst
    commentary it leaves out.
    """
    scenarios = []
    for spec in specs:
        entry = narrated.get(spec.scenario_id)
        if entry is None:
            continue
        facts, narration = entry
        fallback = (fallbacks or {}).get(spec.scenario_id)
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
                "words": sum(word_count(text) for text, _ in narration.sentences),
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
                "fallback_narrative": None if fallback is None else fallback.text,
                "fallback_omitted": [] if fallback is None else list(fallback.omitted),
                "fallback_commentary": (
                    [] if fallback is None else list(fallback.commentary)
                ),
            }
        )
    return {
        "schema": "scenario-narratives-v1",
        "mode": "handoff",
        "stage": NARRATION_STAGE,
        "scenarios": scenarios,
    }


def write_narratives(run_dir: Path, payload: Mapping[str, Any]) -> Path:
    path = run_dir / NARRATIVES_FILENAME
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return path

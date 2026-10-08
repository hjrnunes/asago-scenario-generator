"""Stated use-case rule coverage for the Stage 1a hazard graph.

Stage 1a sometimes drops a behavioral rule that the use case states outright.
This step makes that loss visible and gives the graph revision one chance to
repair it:

1. Extraction (one call) lists the rules the use-case text states about the
   system's own behavior.  The request carries only the use-case text, so
   the constraints cannot bias which rules are listed.  Code keeps a rule only
   when its quote occurs in the text (case-insensitive, whitespace- and
   typography-normalized, Markdown emphasis ignored) and publishes the exact
   source excerpt.
2. Mapping (one call) judges each rule against the constraints' ``rule``
   text only; ``applies_when`` conditions are not shown, because a condition
   that mentions a subject does not state the behavior.  Every rule needs
   existing constraint IDs or a disposition (``out_of_scope`` or
   ``not_testable``) with a reason.  Anything else is a finding.
3. Findings feed the Stage 1a graph revision (see
   :func:`loss_analysis_gates.gate_loss_analysis`).  When a revision changed
   the graph, one further mapping call re-judges the rules on the final graph.

The step is advisory.  Provider errors, invalid responses, and rules the
revision did not repair become ``unavailable`` or ``unresolved`` rows and
warnings; nothing here fails the stage.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
    count_requests,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.quote_normalization import (
    MATCHER_FOLD,
    MATCHER_IGNORED,
    normalize_with_index,
)

STAGE = "stage_1a"
STEP_EXTRACT = "stated_rule_extraction"
STEP_MAP = "stated_rule_mapping"
STEP_REMAP = "stated_rule_mapping_after_revision"
EXTRACT_SYSTEM_TEMPLATE = "stage1a_stated_rules_system.j2"
EXTRACT_USER_TEMPLATE = "stage1a_stated_rules_user.j2"
MAP_SYSTEM_TEMPLATE = "stage1a_stated_rule_mapping_system.j2"
MAP_USER_TEMPLATE = "stage1a_stated_rule_mapping_user.j2"
ARTIFACT_FILENAME = "stated-rule-coverage.yaml"
SCHEMA_VERSION = "stated-rule-coverage-v1"
MAX_COMPLETION_TOKENS = 8192
# Bounds the graph change one revision can make from stated-rule findings;
# findings beyond the cap stay recorded as unresolved.
MAX_REVISION_FINDINGS = 5
# The requested restatement form.  An entry whose restatement does not state a
# rule for the system (for example "The company launched ...") breaks the
# response contract and is rejected.
_RESTATEMENT_PREFIXES = ("the system must", "the system may")
# A shared term distinguishes a rule only through a word at least this long
# that appears in at most half of the graph's constraint rules.
MIN_TERM_WORD_CHARS = 4
# A verb ending is removed only when at least this many letters remain.
MIN_VERB_STEM_CHARS = 4

STATUS_COMPLETED = "completed"
STATUS_UNAVAILABLE = "unavailable"


# ---------------------------------------------------------------------------
# Wire schemas
# ---------------------------------------------------------------------------


class _ExtractedRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    quote: str = Field(description="Exact contiguous span of the use-case text.")
    restatement: str = Field(description="At most 20 words.")
    modality: Literal["requires", "forbids", "permits"]


class StatedRuleExtractionResponse(BaseModel):
    """Provider wire shape of the extraction call."""

    model_config = ConfigDict(extra="forbid")

    rules: list[_ExtractedRule]


class _RuleMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    verdict: Literal["carried", "uncovered", "out_of_scope", "not_testable"]
    constraint_ids: list[str]
    constraint_quote: str = Field(
        description="Exact words of a cited constraint rule; empty unless carried."
    )
    shared_terms: list[str] = Field(
        description=(
            "1 to 3 words the cited rule repeats from the stated rule's specific "
            "limit; empty unless carried."
        )
    )
    reason: str


class StatedRuleMappingResponse(BaseModel):
    """Provider wire shape of the mapping call."""

    model_config = ConfigDict(extra="forbid")

    mappings: list[_RuleMapping]


# ---------------------------------------------------------------------------
# Persisted artifact
# ---------------------------------------------------------------------------

RowStatus = Literal["covered", "dispositioned", "unresolved", "unavailable"]


class RejectedTerm(BaseModel):
    """A shared term the code did not accept as evidence of coverage."""

    model_config = ConfigDict(extra="forbid")

    term: str
    reason: str


class StatedRuleRow(BaseModel):
    """One stated rule and its coverage outcome."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    quote: str
    restatement: str
    modality: Literal["requires", "forbids", "permits"]
    status: RowStatus
    disposition: Literal["out_of_scope", "not_testable"] | None = None
    constraint_ids: list[str] = Field(default_factory=list)
    shared_terms: list[str] = Field(
        default_factory=list,
        description="Accepted terms the covering rules repeat from the quote.",
    )
    rejected_terms: list[RejectedTerm] = Field(default_factory=list)
    added_by_revision: bool = False
    sent_to_revision: bool = False
    reason: str = ""


class RejectedRule(BaseModel):
    """An extracted entry that failed code validation."""

    model_config = ConfigDict(extra="forbid")

    quote: str
    reason: str


class StatedRuleRevision(BaseModel):
    """How the Stage 1a graph revision handled the findings."""

    model_config = ConfigDict(extra="forbid")

    trigger: Literal["none", "stated_rules"] = "none"
    applied: bool = False
    call_count: int = 0
    error: str | None = None


class StatedRuleCoverageArtifact(BaseModel):
    """The persisted ``stated-rule-coverage.yaml``."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["stated-rule-coverage-v1"] = SCHEMA_VERSION
    status: Literal["completed", "unavailable"]
    failure_reason: str | None = None
    use_case_digest: str
    mapped_loss_analysis_digest: str | None = Field(
        default=None,
        description="Digest of the graph the recorded mapping judged.",
    )
    final_loss_analysis_digest: str | None = Field(
        default=None,
        description="Digest of the gated graph handed to Stage 2.",
    )
    call_count: int = 0
    revision: StatedRuleRevision = Field(default_factory=StatedRuleRevision)
    rules: list[StatedRuleRow] = Field(default_factory=list)
    rejected_rules: list[RejectedRule] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# In-memory results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StatedRuleFinding:
    """A stated rule that no constraint carries; sent to the graph revision."""

    rule_id: str
    quote: str
    restatement: str


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    quote: str
    restatement: str
    modality: Literal["requires", "forbids", "permits"]


@dataclass(frozen=True)
class _Verdict:
    status: RowStatus
    constraint_ids: tuple[str, ...] = ()
    disposition: Literal["out_of_scope", "not_testable"] | None = None
    reason: str = ""
    shared_terms: tuple[str, ...] = ()
    rejected_terms: tuple[RejectedTerm, ...] = ()

    @property
    def is_finding(self) -> bool:
        return self.status == "unresolved"


@dataclass
class StatedRuleAssessment:
    """Extraction and first mapping, before any graph revision."""

    use_case_digest: str
    status: str = STATUS_COMPLETED
    failure_reason: str | None = None
    rules: list[_Rule] = field(default_factory=list)
    rejected: list[RejectedRule] = field(default_factory=list)
    verdicts: dict[str, _Verdict] = field(default_factory=dict)
    mapped_digest: str | None = None
    call_count: int = 0
    warnings: list[str] = field(default_factory=list)
    # The re-mapping of an accepted revision, set by :meth:`check_revision`.
    revised_verdicts: dict[str, _Verdict] | None = None
    revised_digest: str | None = None

    @contextmanager
    def _counting_requests(self) -> Iterator[None]:
        """Add the requests dispatched inside the block, also when it raises."""
        with count_requests() as sent:
            try:
                yield
            finally:
                self.call_count += sent.requests

    def check_revision(
        self,
        revised: LossAnalysis,
        *,
        revised_digest: str,
        llm_client: LLMClient,
        run_dir: Path,
        template_loader: TemplateLoader,
        temperature: float,
    ) -> str | None:
        """Re-map the rules on a revised graph; return why to reject it.

        A revision is rejected when the re-mapping fails, or when a rule the
        first mapping covered is no longer covered.  A covered rule whose
        cited constraints still repeat every accepted term keeps its first
        verdict whatever the re-mapping says: the revision only adds, so a
        different answer there is mapping variance, not lost coverage.
        Otherwise the new verdicts are kept for the artifact and ``None`` is
        returned.
        """
        warnings: list[str] = []
        with self._counting_requests():
            verdicts, error = _map_or_error(
                self.rules,
                llm_client=llm_client,
                loss_analysis=revised,
                run_dir=run_dir,
                template_loader=template_loader,
                temperature=temperature,
                step=STEP_REMAP,
                warnings=warnings,
            )
        if error is not None:
            return f"{STEP_REMAP} failed: {error}"
        revised_rules = {
            constraint.constraint_id: _term_key(constraint.rule)
            for constraint in revised.security_constraints
        }
        for rule_id, verdict in self.verdicts.items():
            if _lost_coverage(verdict, verdicts.get(rule_id, _UNMAPPED)) and (
                _terms_still_held(verdict, revised_rules)
            ):
                verdicts[rule_id] = verdict
        lost = [
            f"{rule_id} (now {verdicts.get(rule_id, _UNMAPPED).status})"
            for rule_id, verdict in self.verdicts.items()
            if _lost_coverage(verdict, verdicts.get(rule_id, _UNMAPPED))
        ]
        if lost:
            return "the revision lost the coverage of " + ", ".join(lost)
        self.warnings.extend(warnings)
        self.revised_verdicts = verdicts
        self.revised_digest = revised_digest
        return None

    @property
    def findings(self) -> tuple[StatedRuleFinding, ...]:
        """Findings sent to the revision, at most :data:`MAX_REVISION_FINDINGS`."""
        return tuple(
            StatedRuleFinding(rule.rule_id, rule.quote, rule.restatement)
            for rule in self.rules
            if self.verdicts.get(rule.rule_id, _UNMAPPED).is_finding
        )[:MAX_REVISION_FINDINGS]


_UNMAPPED = _Verdict(status="unavailable", reason="no mapping")


# ---------------------------------------------------------------------------
# Quote validation
# ---------------------------------------------------------------------------


def _normalize(text: str) -> tuple[str, list[int]]:
    """Normalize ``text`` and map each output character to its source index."""
    return normalize_with_index(text, MATCHER_FOLD, MATCHER_IGNORED)


def normalized_text(text: str) -> str:
    """``text`` as quote matching compares it: casefolded, single-spaced."""
    return _normalize(text)[0].strip()


def locate_quote(source: str, quote: str) -> str | None:
    """Return the exact source excerpt a quote denotes, or ``None``.

    The match is case-insensitive and ignores whitespace runs, typographic
    quote and dash variants, and Markdown emphasis markers.  The first
    occurrence is returned; repeated identical wording yields identical
    normalized text, so the choice does not change the rule.
    """
    needle, _ = _normalize(quote)
    needle = needle.strip()
    if not needle:
        return None
    haystack, index = _normalize(source)
    start = haystack.find(needle)
    if start == -1:
        return None
    end = start + len(needle) - 1
    return source[index[start] : index[end] + 1]


# ---------------------------------------------------------------------------
# Step 1 and 2: extraction and first mapping
# ---------------------------------------------------------------------------


def text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def assess_stated_rules(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    loss_analysis_digest: str,
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
) -> StatedRuleAssessment:
    """Extract the stated rules and map them onto the draft graph.

    Never raises.  A failed extraction or mapping call leaves the assessment
    ``unavailable`` (extraction) or its rows ``unavailable`` (mapping), and
    produces no findings.
    """
    assessment = StatedRuleAssessment(use_case_digest=text_digest(use_case_text))
    try:
        _extract(
            assessment,
            llm_client=llm_client,
            use_case_text=use_case_text,
            run_dir=run_dir,
            template_loader=template_loader,
            temperature=temperature,
        )
        if assessment.status != STATUS_COMPLETED or not assessment.rules:
            return assessment
        with assessment._counting_requests():
            verdicts, error = _map(
                assessment.rules,
                llm_client=llm_client,
                loss_analysis=loss_analysis,
                run_dir=run_dir,
                template_loader=template_loader,
                temperature=temperature,
                step=STEP_MAP,
                warnings=assessment.warnings,
            )
        if error is not None:
            assessment.warnings.append(f"{STEP_MAP}: {error}")
            assessment.verdicts = {
                rule.rule_id: _Verdict(
                    status="unavailable", reason=f"mapping failed: {error}"
                )
                for rule in assessment.rules
            }
        else:
            assessment.verdicts = verdicts
            assessment.mapped_digest = loss_analysis_digest
    except Exception as exc:  # noqa: BLE001 - the step must never fail the stage
        assessment.status = STATUS_UNAVAILABLE
        assessment.failure_reason = f"{type(exc).__name__}: {exc}"
        assessment.verdicts = {}
    return assessment


def _extract(
    assessment: StatedRuleAssessment,
    *,
    llm_client: LLMClient,
    use_case_text: str,
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
) -> None:
    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=template_loader.render_prompt(EXTRACT_SYSTEM_TEMPLATE),
        user_prompt=template_loader.render_prompt(
            EXTRACT_USER_TEMPLATE, use_case_text=use_case_text
        ),
        response_format=StatedRuleExtractionResponse,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_EXTRACT,
        policy=CorrectionPolicy(),
        temperature=temperature,
        max_completion_tokens=MAX_COMPLETION_TOKENS,
    )
    response, error = outcome.value, outcome.error
    assessment.call_count += outcome.calls
    if error is not None or response is None:
        assessment.status = STATUS_UNAVAILABLE
        assessment.failure_reason = f"{STEP_EXTRACT}: {error or 'no response'}"
        return
    seen: dict[str, str] = {}
    for entry in response.rules:
        excerpt = locate_quote(use_case_text, entry.quote)
        if excerpt is None:
            assessment.rejected.append(
                RejectedRule(
                    quote=entry.quote,
                    reason="quote does not occur verbatim in the use-case text",
                )
            )
            continue
        if not _normalize(entry.restatement)[0].startswith(_RESTATEMENT_PREFIXES):
            assessment.rejected.append(
                RejectedRule(
                    quote=entry.quote,
                    reason=(
                        "restatement does not state a rule for the system "
                        "('The system must ...' or 'The system may ...')"
                    ),
                )
            )
            continue
        key = _normalize(excerpt)[0]
        if key in seen:
            assessment.rejected.append(
                RejectedRule(quote=entry.quote, reason=f"duplicates {seen[key]}")
            )
            continue
        rule_id = f"R-{len(assessment.rules) + 1}"
        seen[key] = rule_id
        assessment.rules.append(
            _Rule(
                rule_id=rule_id,
                quote=excerpt,
                restatement=entry.restatement.strip(),
                modality=entry.modality,
            )
        )


def _lost_coverage(first: _Verdict, remapped: _Verdict) -> bool:
    """Whether a rule the first mapping covered is no longer covered."""
    return first.status == "covered" and remapped.status != "covered"


def _map_or_error(
    rules: Sequence[_Rule], **kwargs: Any
) -> tuple[dict[str, _Verdict], str | None]:
    """Run :func:`_map`, turning any exception into an error string."""
    try:
        return _map(rules, **kwargs)
    except Exception as exc:  # noqa: BLE001 - advisory step
        return {}, f"{type(exc).__name__}: {exc}"


def _map(
    rules: Sequence[_Rule],
    *,
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
    step: str,
    warnings: list[str],
) -> tuple[dict[str, _Verdict], str | None]:
    """Make one mapping call and validate every row against the request."""
    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=template_loader.render_prompt(MAP_SYSTEM_TEMPLATE),
        user_prompt=template_loader.render_prompt(
            MAP_USER_TEMPLATE,
            rules=rules,
            security_constraints=loss_analysis.security_constraints,
        ),
        response_format=StatedRuleMappingResponse,
        run_dir=run_dir,
        stage=STAGE,
        step=step,
        policy=CorrectionPolicy(),
        temperature=temperature,
        max_completion_tokens=MAX_COMPLETION_TOKENS,
    )
    response, error = outcome.value, outcome.error
    if error is not None or response is None:
        return {}, error or "no response"
    known_constraints = {
        constraint.constraint_id: constraint.rule
        for constraint in loss_analysis.security_constraints
    }
    verdicts = _validate_mapping_rows(
        response.mappings, rules, known_constraints, step=step, warnings=warnings
    )
    for rule in rules:
        if rule.rule_id not in verdicts:
            verdicts[rule.rule_id] = _Verdict(
                status="unresolved", reason="the mapping response omitted this rule"
            )
    return verdicts, None


def _validate_mapping_rows(
    mappings: Sequence[_RuleMapping],
    rules: Sequence[_Rule],
    known_constraints: dict[str, str],
    *,
    step: str,
    warnings: list[str],
) -> dict[str, _Verdict]:
    """Validate each requested rule's first mapping row; warn on the others."""
    requested = {rule.rule_id: rule for rule in rules}
    verdicts: dict[str, _Verdict] = {}
    for row in mappings:
        if row.rule_id not in requested:
            warnings.append(f"{step}: ignored mapping for unknown rule '{row.rule_id}'")
            continue
        if row.rule_id in verdicts:
            warnings.append(f"{step}: ignored duplicate mapping for '{row.rule_id}'")
            continue
        verdicts[row.rule_id] = _validate_mapping(
            row,
            requested[row.rule_id].quote,
            known_constraints,
            step=step,
            warnings=warnings,
        )
    return verdicts


def _validate_mapping(
    row: _RuleMapping,
    rule_quote: str,
    known_constraints: dict[str, str],
    *,
    step: str,
    warnings: list[str],
) -> _Verdict:
    reason = row.reason.strip()
    if row.verdict == "carried":
        return _validate_carried_mapping(
            row,
            rule_quote,
            known_constraints,
            step=step,
            warnings=warnings,
            reason=reason,
        )
    if row.verdict == "uncovered":
        return _Verdict(status="unresolved", reason=reason or "no constraint rule")
    if not reason:
        return _Verdict(
            status="unresolved",
            reason=f"disposition {row.verdict} was given without a reason",
        )
    if row.constraint_ids:
        warnings.append(
            f"{step}: {row.rule_id} disposition {row.verdict} ignored its "
            "constraint ids"
        )
    return _Verdict(status="dispositioned", disposition=row.verdict, reason=reason)


def _validate_carried_mapping(
    row: _RuleMapping,
    rule_quote: str,
    known_constraints: dict[str, str],
    *,
    step: str,
    warnings: list[str],
    reason: str,
) -> _Verdict:
    """Judge a ``carried`` mapping by its cited IDs and located quote."""
    valid = _existing_cited_constraints(
        row, known_constraints, step=step, warnings=warnings
    )
    if not valid:
        return _Verdict(
            status="unresolved",
            reason="mapped as carried but cited no existing constraint",
        )
    # The quote locates the carrying constraint.  A model can cite a wrong
    # ID, so the ID alone never decides coverage: an unlocated quote is a
    # finding, and a quote found only in other rules moves coverage there.
    located = _constraints_locating(row.constraint_quote.strip(), known_constraints)
    if not located:
        return _Verdict(
            status="unresolved",
            reason=(
                "mapped as carried but constraint_quote occurs in no "
                f"constraint rule: {reason}"
            ).rstrip(": "),
        )
    carrying = tuple(cid for cid in valid if cid in located)
    if not carrying:
        carrying = located
        warnings.append(
            f"{step}: {row.rule_id} cited {', '.join(valid)} but its "
            f"constraint_quote occurs in {', '.join(located)}; judged "
            f"against {', '.join(located)}"
        )
    return _judge_shared_terms(
        row, rule_quote, carrying, known_constraints, reason=reason
    )


def _existing_cited_constraints(
    row: _RuleMapping,
    known_constraints: dict[str, str],
    *,
    step: str,
    warnings: list[str],
) -> tuple[str, ...]:
    """Return the distinct cited IDs that exist; warn about the unknown ones."""
    cited = tuple(dict.fromkeys(row.constraint_ids))
    unknown = [cid for cid in cited if cid not in known_constraints]
    if unknown:
        warnings.append(
            f"{step}: {row.rule_id} cited unknown constraint(s) " + ", ".join(unknown)
        )
    return tuple(cid for cid in cited if cid in known_constraints)


def _constraints_locating(
    quote: str, known_constraints: dict[str, str]
) -> tuple[str, ...]:
    """Return the constraints whose rule text contains *quote*; none for no quote."""
    if not quote:
        return ()
    return tuple(
        cid
        for cid, rule_text in known_constraints.items()
        if locate_quote(rule_text, quote)
    )


def _term_words(text: str) -> list[str]:
    """Casefold, unify typographic variants, and split on punctuation."""
    folded = text.translate(MATCHER_FOLD).casefold()
    return re.findall(r"[^\W_]+", folded)


def _singular(word: str) -> str:
    """Reduce a simple English plural to its singular by suffix alone.

    ``-ies`` becomes ``-y``; ``-ches``, ``-shes``, ``-sses``, ``-xes`` and
    ``-zes`` drop ``-es``; any other final ``s`` after at least three letters
    drops, except ``-ss``.  Both sides of every comparison pass through this,
    so a word that is not a plural ("status") reduces identically everywhere.
    """
    if len(word) > 4 and word.endswith("ies"):
        return word[:-3] + "y"
    if word.endswith(("ches", "shes", "sses", "xes", "zes")):
        return word[:-2]
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def _word_forms(word: str) -> frozenset[str]:
    """The singular word plus the bases its verb ending may attach to.

    ``-ed`` drops ``ed`` or only ``d`` ("blocked" -> "block", "escalated" ->
    "escalate"); ``-ing`` drops ``ing`` or replaces it with ``e``
    ("escalating" -> "escalate").  A stem shorter than
    :data:`MIN_VERB_STEM_CHARS` letters is not reduced, so "feed" never
    becomes "fee".  Two words match when their form sets intersect; a noun
    and a verb with different endings ("diagnosis", "diagnose") share none.
    """
    word = _singular(word)
    forms = {word}
    if word.endswith("ed"):
        for stem in (word[:-2], word[:-1]):
            if len(stem.rstrip("e")) >= MIN_VERB_STEM_CHARS:
                forms.add(stem)
    elif word.endswith("ing"):
        stem = word[:-3]
        if len(stem) >= MIN_VERB_STEM_CHARS:
            forms.update((stem, stem + "e"))
    return frozenset(forms)


_TermKey = tuple[frozenset[str], ...]


def _term_key(text: str) -> _TermKey:
    """Matching form of ``text``: the word-form set of each word, in order."""
    return tuple(_word_forms(word) for word in _term_words(text))


def _contains_term(text_key: _TermKey, term_key: _TermKey) -> bool:
    """Whether the term's words occur consecutively, form by form, in the text."""
    width = len(term_key)
    if not width:
        return False
    return any(
        all(text_key[start + offset] & forms for offset, forms in enumerate(term_key))
        for start in range(len(text_key) - width + 1)
    )


def _terms_still_held(verdict: _Verdict, rules: dict[str, _TermKey]) -> bool:
    """Whether the verdict's cited constraints still repeat each accepted term."""
    if not verdict.shared_terms or any(
        cid not in rules for cid in verdict.constraint_ids
    ):
        return False
    return all(
        any(
            _contains_term(rules[cid], _term_key(term))
            for cid in verdict.constraint_ids
        )
        for term in verdict.shared_terms
    )


def _undistinctive_term_problem(
    term: str, rule_keys: dict[str, _TermKey]
) -> str | None:
    """Reject a term without a long word that occurs in at most half the rules."""
    total = len(rule_keys)
    long_words = [
        word for word in _term_words(term) if len(word) >= MIN_TERM_WORD_CHARS
    ]
    if not long_words:
        return f"has no word of at least {MIN_TERM_WORD_CHARS} characters"
    counts = {
        word: sum(
            1 for text in rule_keys.values() if _contains_term(text, _term_key(word))
        )
        for word in long_words
    }
    if total > 1 and all(count * 2 > total for count in counts.values()):
        most = min(counts.values())
        return (
            f"occurs in {most} of {total} constraint rules, so it "
            "does not distinguish one"
        )
    return None


def _shared_term_problem(
    term: str,
    key: _TermKey,
    quote_key: _TermKey,
    rule_keys: dict[str, _TermKey],
    carrying: tuple[str, ...],
) -> tuple[str | None, tuple[str, ...]]:
    """Return why a shared term is rejected (or ``None``) and its carrying holders."""
    holders = tuple(cid for cid in carrying if _contains_term(rule_keys[cid], key))
    if not _contains_term(quote_key, key):
        return "does not occur in the stated rule's quote", holders
    if not holders:
        return f"does not occur in the rule text of {', '.join(carrying)}", holders
    return _undistinctive_term_problem(term, rule_keys), holders


def _judge_shared_terms(
    row: _RuleMapping,
    rule_quote: str,
    carrying: tuple[str, ...],
    known_constraints: dict[str, str],
    *,
    reason: str,
) -> _Verdict:
    """Accept coverage only where a distinctive shared term backs it.

    The quote locator proves the model read a real rule; the terms show that
    rule repeats the stated limit.  A term counts only if it occurs in the
    stated rule's quote and in a carrying rule, and contains a word that is
    long enough and occurs in at most half of the constraint rules.
    """
    quote_key = _term_key(rule_quote)
    rule_keys = {cid: _term_key(text) for cid, text in known_constraints.items()}
    accepted: list[str] = []
    rejected: list[RejectedTerm] = []
    covering: set[str] = set()
    seen: set[str] = set()
    for raw in row.shared_terms:
        term = raw.strip()
        key = _term_key(term)
        if not key or key in seen:
            continue
        seen.add(key)
        problem, holders = _shared_term_problem(
            term, key, quote_key, rule_keys, carrying
        )
        if problem is None:
            accepted.append(term)
            covering.update(holders)
        else:
            rejected.append(RejectedTerm(term=term, reason=problem))
    if not accepted:
        return _Verdict(
            status="unresolved",
            reason=(
                "mapped as carried but no accepted shared term shows that "
                f"{', '.join(carrying)} repeats the stated limit: {reason}"
            ).rstrip(": "),
            rejected_terms=tuple(rejected),
        )
    return _Verdict(
        status="covered",
        constraint_ids=tuple(cid for cid in carrying if cid in covering),
        reason=reason,
        shared_terms=tuple(accepted),
        rejected_terms=tuple(rejected),
    )


# ---------------------------------------------------------------------------
# Step 3: final mapping and artifact
# ---------------------------------------------------------------------------


def finalize_stated_rule_coverage(
    assessment: StatedRuleAssessment,
    *,
    draft: LossAnalysis,
    final: LossAnalysis | None,
    final_digest: str | None,
    revision: StatedRuleRevision,
    run_dir: Path,
) -> StatedRuleCoverageArtifact:
    """Persist the artifact and return it.  Never raises.

    The rows come from the re-mapping :meth:`StatedRuleAssessment.check_revision`
    recorded when the revision was applied, and from the first mapping
    otherwise.
    """
    verdicts = dict(assessment.verdicts)
    mapped_digest = assessment.mapped_digest
    warnings = list(assessment.warnings)
    call_count = assessment.call_count
    findings = {finding.rule_id for finding in assessment.findings}
    all_findings = sum(1 for verdict in verdicts.values() if verdict.is_finding)
    if all_findings > len(findings):
        warnings.append(
            f"sent {len(findings)} of {all_findings} uncovered rules to the "
            f"revision (cap {MAX_REVISION_FINDINGS})"
        )
    if revision.applied and assessment.revised_verdicts is not None:
        verdicts = dict(assessment.revised_verdicts)
        mapped_digest = assessment.revised_digest

    rows = _stated_rule_rows(
        assessment,
        verdicts,
        draft=draft,
        final=final,
        remapped_on_final=mapped_digest != assessment.mapped_digest,
        findings=findings,
        revision=revision,
    )
    artifact = StatedRuleCoverageArtifact(
        status=(
            STATUS_COMPLETED
            if assessment.status == STATUS_COMPLETED
            else STATUS_UNAVAILABLE
        ),
        failure_reason=assessment.failure_reason,
        use_case_digest=assessment.use_case_digest,
        mapped_loss_analysis_digest=mapped_digest,
        final_loss_analysis_digest=final_digest,
        call_count=call_count,
        revision=revision,
        rules=rows,
        rejected_rules=list(assessment.rejected),
        warnings=warnings,
    )
    write_yaml(artifact, run_dir / ARTIFACT_FILENAME)
    return artifact


def _stated_rule_rows(
    assessment: StatedRuleAssessment,
    verdicts: dict[str, _Verdict],
    *,
    draft: LossAnalysis,
    final: LossAnalysis | None,
    remapped_on_final: bool,
    findings: set[str],
    revision: StatedRuleRevision,
) -> list[StatedRuleRow]:
    """Build one artifact row per stated rule from its final verdict."""
    prior_rules = {c.constraint_id: c.rule for c in draft.security_constraints}
    final_rules = (
        {c.constraint_id: c.rule for c in final.security_constraints}
        if final is not None
        else prior_rules
    )
    rows: list[StatedRuleRow] = []
    for rule in assessment.rules:
        verdict = verdicts.get(rule.rule_id, _UNMAPPED)
        # A constraint the revision added, or whose rule text it rewrote.
        added = remapped_on_final and any(
            prior_rules.get(cid) != final_rules.get(cid)
            for cid in verdict.constraint_ids
        )
        rows.append(
            StatedRuleRow(
                rule_id=rule.rule_id,
                quote=rule.quote,
                restatement=rule.restatement,
                modality=rule.modality,
                status=verdict.status,
                disposition=verdict.disposition,
                constraint_ids=list(verdict.constraint_ids),
                shared_terms=list(verdict.shared_terms),
                rejected_terms=list(verdict.rejected_terms),
                added_by_revision=added,
                sent_to_revision=rule.rule_id in findings
                and revision.trigger != "none",
                reason=verdict.reason,
            )
        )
    return rows


def coverage_warnings(artifact: StatedRuleCoverageArtifact) -> list[str]:
    """Stage warnings for the run manifest: one per unresolved or unavailable row."""
    prefix = "stage_1a/stated_rule_coverage"
    if artifact.status == STATUS_UNAVAILABLE:
        return [f"{prefix} unavailable: {artifact.failure_reason}"]
    warnings = [
        f"{prefix} {row.status} {row.rule_id}: {row.quote!r} ({row.reason})"
        for row in artifact.rules
        if row.status in ("unresolved", "unavailable")
    ]
    warnings.extend(
        f"{prefix} rejected: {item.quote!r} ({item.reason})"
        for item in artifact.rejected_rules
    )
    return warnings


def manifest_summary(artifact: StatedRuleCoverageArtifact) -> dict[str, object]:
    """Compact run-manifest summary of the artifact."""
    counts: dict[str, int] = {
        "covered": 0,
        "dispositioned": 0,
        "unresolved": 0,
        "unavailable": 0,
    }
    for row in artifact.rules:
        counts[row.status] += 1
    return {
        "artifact": ARTIFACT_FILENAME,
        "status": artifact.status,
        "call_count": artifact.call_count,
        "rules": len(artifact.rules),
        "rejected": len(artifact.rejected_rules),
        "counts": counts,
        "revision": artifact.revision.model_dump(mode="json"),
        "mapped_loss_analysis_digest": artifact.mapped_loss_analysis_digest,
    }


__all__ = [
    "ARTIFACT_FILENAME",
    "StatedRuleAssessment",
    "StatedRuleCoverageArtifact",
    "StatedRuleFinding",
    "StatedRuleRevision",
    "assess_stated_rules",
    "coverage_warnings",
    "finalize_stated_rule_coverage",
    "locate_quote",
    "manifest_summary",
]

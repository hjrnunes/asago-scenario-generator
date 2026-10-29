#!/usr/bin/env python3
"""Research pilot: a scoped semantic review of scenario safe alternatives.

    uv run --frozen python scripts/conflict_review_pilot.py select \\
        --run RUN_DIR [--run RUN_DIR ...] --out-dir DIR \\
        [--hand-manifest MANIFEST] [--sample-size 18] [--seed 20261029]

    uv run --frozen python scripts/conflict_review_pilot.py render \\
        (--fixtures FILE | --manifest MANIFEST) --case CASE_ID --out-dir DIR

    uv run --frozen python scripts/conflict_review_pilot.py run \\
        --profiles-file FILE --profile NAME \\
        (--fixtures FILE | --manifest MANIFEST) [--case CASE_ID ...] \\
        --max-live-requests N --out-dir DIR [--replay-dir DIR] \\
        [--stop-after-failures 3]

The review is not a gate and is not part of ``generate``. It compares only
requirements whose mechanisms or safe alternatives share a resource, a state
or a decision point, and records one finding per case: its class, the cited
requirements, the overlap, the mechanisms, a causal explanation and an
over-refusal judgement.

``select`` reads recorded producer runs and never writes them. For each run's
``stages/generate/output`` it loads the scenarios, ``loss-analysis.yaml``,
``control-structure.yaml`` and ``testability.yaml``, and rebuilds each ICA's
process-model context from ``target-realization.yaml``'s effective ICA
enumeration with ``ica_process_model_contexts``. It pairs the non-duplicate
scenarios that share any of: a control action plus process-model context
(``ca_context``), a failure-call operation (``operation``), a constraint
(``constraint``) or a causal-factor process-model variable
(``pm_variable``). ``control_action`` alone is counted for comparison and is
not part of the union. Outputs in ``--out-dir``:

- ``candidate-pairs.jsonl``: one row per (run, pair) with every shared element;
- ``candidate-groups.json``: per run and grouping, each element's scenarios;
- ``selector-counts.json`` and ``selector-summary.md``: pair counts by
  grouping, and with ``--hand-manifest`` how many hand-labelled candidates
  each grouping covers (a candidate is covered when two of its scenarios
  share an element of that grouping);
- ``sample-manifest.yaml``: with ``--sample-size``, a seeded sample of union
  pairs that no hand candidate contains, with empty labels.

``render`` writes one case's system and user prompts without a model.

``run`` reviews the cases one at a time through ``provider_call_session``
with ``ReplayFill(max_live_requests=N)``: every request is recorded in
``--out-dir/provider-calls.jsonl``, and a rerun given the earlier output as
``--replay-dir`` replays it for free. A reply that fails the schema or a
validator earns one correction (``CorrectionPolicy(validation_retries=1)``).
The runner starts no case once the live budget is spent, stops at the first
refused request, and stops after ``--stop-after-failures`` consecutive cases
without an accepted verdict. It writes ``verdicts/<case>.json`` per case and
``summary.json`` and ``summary.md``.

A fixtures file is ``scripts/conflict_review/paired-fixtures.yaml``. A
manifest lists recorded cases::

    cases:
      - case_id: A1
        run_dir: /path/to/run
        scenario_ids: [SCN-033, SCN-036]
        label: demonstrated_conflict        # scoring only; optional
        acceptable: [unfaithful_refinement] # scoring only; optional
        note: free text                     # scoring only; optional

Labels, expected classes and notes are kept for scoring and never reach a
prompt.
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.stpa.infra.llm import LLMClient, effective_temperature
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    ExactFeedbackError,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.provider_record import (
    RECORD_FILENAME,
    LiveRequestBudgetError,
    ProviderCallSession,
    ReplayFill,
    provider_call_session,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.scenario_prod.stage5.cross_scenario import (
    ica_process_model_contexts,
)

RESOURCES_DIR = Path(__file__).resolve().parent / "conflict_review"
PROMPTS_DIR = RESOURCES_DIR / "prompts"
FIXTURES_PATH = RESOURCES_DIR / "paired-fixtures.yaml"
SYSTEM_TEMPLATE = "conflict_review_system.j2"
USER_TEMPLATE = "conflict_review_user.j2"

REVIEW_STAGE = "research_conflict_review"
REVIEW_STEP = "review"

GROUPINGS = ("ca_context", "operation", "constraint", "pm_variable")
"""The groupings whose union gives the candidate pairs."""
COMPARISON_GROUPINGS = ("control_action",)
"""Counted beside the union for comparison only."""

FindingClass = Literal[
    "demonstrated_conflict",
    "missing_information",
    "unfaithful_refinement",
    "reinforcement",
    "no_conflict",
]
FINDING_CLASSES: tuple[str, ...] = FindingClass.__args__  # type: ignore[attr-defined]
Property = Literal[
    "confidentiality",
    "integrity",
    "availability",
    "authority",
    "attacker_access",
    "safety",
    "business_objective",
    "other",
]


# Recorded runs ------------------------------------------------------------


@dataclass
class RecordedRun:
    """The records of one producer run that the selector and cases read."""

    run_dir: Path
    scenarios: dict[str, dict[str, Any]]
    status: dict[str, str]
    contexts: dict[str, dict[str, str]]
    constraints: dict[str, dict[str, Any]]
    pm_descriptions: dict[str, str]
    use_case: str

    @property
    def label(self) -> str:
        return self.run_dir.name

    def non_duplicates(self) -> list[str]:
        return [
            scenario_id
            for scenario_id in self.scenarios
            if self.status.get(scenario_id) != "duplicate"
        ]


def _yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_run(run_dir: Path) -> RecordedRun:
    """Load one run's output records; the run directory is only read."""
    output = run_dir / "stages" / "generate" / "output"
    structure = ControlStructure.model_validate(
        _yaml(output / "control-structure.yaml")
    )
    realization = _yaml(output / "target-realization.yaml")
    enumeration = ICAEnumeration.model_validate(
        realization["effective_view"]["effective_ica_enumeration"]
    )
    scenarios = {
        path.stem: _yaml(path) for path in sorted((output / "scenarios").glob("*.yaml"))
    }
    testability = _yaml(output / "testability.yaml")
    losses = _yaml(output / "loss-analysis.yaml")
    use_case_path = run_dir / "inputs" / "target" / "use_case" / "use-case.txt"
    return RecordedRun(
        run_dir=run_dir,
        scenarios=scenarios,
        status={row["scenario_id"]: row["status"] for row in testability["scenarios"]},
        contexts=ica_process_model_contexts(enumeration, structure),
        constraints={
            item["constraint_id"]: item
            for item in losses.get("security_constraints") or []
        },
        pm_descriptions={
            part.pm_id: part.description
            for responsibility in structure.responsibilities
            for part in responsibility.process_model_parts
        },
        use_case=use_case_path.read_text(encoding="utf-8"),
    )


def _context(run: RecordedRun, scenario: Mapping[str, Any]) -> dict[str, str] | None:
    ica_id = (scenario.get("lineage") or {}).get("ica_id")
    return run.contexts.get(ica_id) if ica_id else None


# Selector -----------------------------------------------------------------


def scenario_keys(run: RecordedRun, scenario_id: str) -> dict[str, list[str]]:
    """Return the elements of each grouping that one scenario carries."""
    scenario = run.scenarios[scenario_id]
    lineage = scenario.get("lineage") or {}
    action = lineage.get("control_action_id")
    context = _context(run, scenario)
    operation = (scenario.get("semantic_failure_call") or {}).get("operation_name")
    variables = [
        (factor.get("process_model_variable") or {}).get("id")
        for factor in scenario.get("causal_factors") or []
    ]
    keys = {
        "ca_context": (
            [action + " | " + "; ".join(f"{k}={v}" for k, v in sorted(context.items()))]
            if action and context
            else []
        ),
        "operation": [operation] if operation else [],
        "constraint": list(dict.fromkeys(lineage.get("constraint_ids") or [])),
        "pm_variable": list(dict.fromkeys(v for v in variables if v)),
        "control_action": [action] if action else [],
    }
    return keys


def candidate_groups(run: RecordedRun) -> dict[str, dict[str, list[str]]]:
    """Map each grouping's elements to the non-duplicate scenarios sharing them."""
    groups: dict[str, dict[str, list[str]]] = {
        name: {} for name in GROUPINGS + COMPARISON_GROUPINGS
    }
    for scenario_id in run.non_duplicates():
        for name, elements in scenario_keys(run, scenario_id).items():
            for element in elements:
                groups[name].setdefault(element, []).append(scenario_id)
    return {
        name: {k: v for k, v in sorted(elements.items()) if len(v) > 1}
        for name, elements in groups.items()
    }


@dataclass(frozen=True)
class CandidatePair:
    first: str
    second: str
    shared: Mapping[str, tuple[str, ...]]
    """Each grouping's shared elements; a grouping with none is absent."""

    @property
    def in_union(self) -> bool:
        return any(name in self.shared for name in GROUPINGS)


def candidate_pairs(run: RecordedRun) -> list[CandidatePair]:
    """Return every non-duplicate pair that shares an element of any grouping."""
    shared: dict[tuple[str, str], dict[str, list[str]]] = {}
    for name, elements in candidate_groups(run).items():
        for element, members in elements.items():
            for first, second in itertools.combinations(sorted(members), 2):
                shared.setdefault((first, second), {}).setdefault(name, []).append(
                    element
                )
    return [
        CandidatePair(first, second, {k: tuple(v) for k, v in sorted(names.items())})
        for (first, second), names in sorted(shared.items())
    ]


def pair_counts(pairs: Sequence[CandidatePair]) -> dict[str, int]:
    counts = {
        name: sum(1 for pair in pairs if name in pair.shared)
        for name in GROUPINGS + COMPARISON_GROUPINGS
    }
    counts["union"] = sum(1 for pair in pairs if pair.in_union)
    return counts


def _covering(
    scenario_ids: Sequence[str], index: Mapping[tuple[str, str], CandidatePair]
) -> set[str]:
    names: set[str] = set()
    for first, second in itertools.combinations(sorted(set(scenario_ids)), 2):
        pair = index.get((first, second))
        if pair is not None:
            names.update(pair.shared)
    return names


def hand_coverage(
    hand_cases: Sequence[Mapping[str, Any]],
    pairs_by_run: Mapping[str, Sequence[CandidatePair]],
) -> dict[str, Any]:
    """Count the hand candidates each grouping covers.

    A candidate is covered by a grouping when two of its scenarios share an
    element of it. A candidate with fewer than two scenarios is unpairable.
    """
    indexes = {
        run: {(pair.first, pair.second): pair for pair in pairs}
        for run, pairs in pairs_by_run.items()
    }
    rows = []
    for case in hand_cases:
        run = str(Path(case["run_dir"]).resolve())
        scenario_ids = list(dict.fromkeys(case["scenario_ids"]))
        names = _covering(scenario_ids, indexes.get(run, {}))
        rows.append(
            {
                "case_id": case["case_id"],
                "pairable": len(scenario_ids) > 1,
                "covered_by": sorted(names),
                "in_union": bool(names & set(GROUPINGS)),
            }
        )
    totals = {
        name: sum(1 for row in rows if name in row["covered_by"])
        for name in GROUPINGS + COMPARISON_GROUPINGS
    }
    totals["union"] = sum(1 for row in rows if row["in_union"])
    return {
        "candidates": len(rows),
        "pairable": sum(1 for row in rows if row["pairable"]),
        "covered": totals,
        "rows": rows,
    }


def _hand_pairs(hand_cases: Sequence[Mapping[str, Any]]) -> set[tuple[str, str, str]]:
    found = set()
    for case in hand_cases:
        run = str(Path(case["run_dir"]).resolve())
        for first, second in itertools.combinations(
            sorted(set(case["scenario_ids"])), 2
        ):
            found.add((run, first, second))
    return found


def sample_unselected(
    pairs_by_run: Mapping[str, Sequence[CandidatePair]],
    hand_cases: Sequence[Mapping[str, Any]],
    size: int,
    seed: int,
) -> list[dict[str, Any]]:
    """Draw union pairs that no hand candidate holds, evenly across runs."""
    excluded = _hand_pairs(hand_cases)
    rng = random.Random(seed)
    pools = {
        run: [
            pair
            for pair in pairs
            if pair.in_union and (run, pair.first, pair.second) not in excluded
        ]
        for run, pairs in sorted(pairs_by_run.items())
    }
    drawn: list[tuple[str, CandidatePair]] = []
    runs = [run for run, pool in pools.items() if pool]
    while len(drawn) < size and runs:
        for run in list(runs):
            if len(drawn) >= size:
                break
            pool = pools[run]
            drawn.append((run, pool.pop(rng.randrange(len(pool)))))
            if not pool:
                runs.remove(run)
    return [
        {
            "case_id": f"U{index:02d}",
            "run_dir": run,
            "scenario_ids": [pair.first, pair.second],
            "shared": {k: list(v) for k, v in pair.shared.items()},
            "label": None,
            "acceptable": [],
            "note": "",
        }
        for index, (run, pair) in enumerate(drawn, 1)
    ]


# Review cases -------------------------------------------------------------


@dataclass(frozen=True)
class CaseEntry:
    ref: str | None
    heading: str | None
    lines: tuple[str, ...]


@dataclass(frozen=True)
class CaseSection:
    title: str
    entries: tuple[CaseEntry, ...]


@dataclass
class ReviewCase:
    """One review request's case data, with its scoring labels kept apart."""

    case_id: str
    source: Literal["fixture", "recorded"]
    sections: tuple[CaseSection, ...]
    identifiers: tuple[str, ...]
    request_ids: tuple[str, ...] = ()
    labels: dict[str, Any] = field(default_factory=dict)
    """Expected class, hand label and notes: for scoring, never rendered."""


def _text(value: Any) -> str:
    return " ".join(str(value).split())


def load_fixtures(path: Path = FIXTURES_PATH) -> list[dict[str, Any]]:
    return list(_yaml(path)["fixtures"])


def fixture_case(fixture: Mapping[str, Any]) -> ReviewCase:
    """Build a fixture's case from its text, leaving its labels out."""
    requirements = tuple(
        CaseEntry(item["id"], f"({_text(item['origin'])})", (_text(item["text"]),))
        for item in fixture["requirements"]
    )
    safeguard = fixture["safeguard"]
    requests = tuple(
        CaseEntry(item["id"], None, (_text(item["text"]),))
        for item in fixture["requests"]
    )
    sections = (
        CaseSection(
            "Situation", (CaseEntry(None, None, (_text(fixture["situation"]),)),)
        ),
        CaseSection("Requirements", requirements),
        CaseSection(
            "Safeguard under review",
            (
                CaseEntry(
                    safeguard["id"],
                    f"(refines {safeguard['refines']})",
                    (_text(safeguard["text"]),),
                ),
            ),
        ),
        CaseSection("Requests", requests),
    )
    request_ids = tuple(item["id"] for item in fixture["requests"])
    identifiers = (
        *(item["id"] for item in fixture["requirements"]),
        safeguard["id"],
        *request_ids,
    )
    return ReviewCase(
        case_id=fixture["fixture_id"],
        source="fixture",
        sections=sections,
        identifiers=identifiers,
        request_ids=request_ids,
        labels={
            "expected_class": fixture["expected_class"],
            "acceptable_classes": list(fixture.get("acceptable_classes") or []),
            "expected_over_refusal": fixture["expected_over_refusal"],
            "expected_requests": {
                item["id"]: item["expected"] for item in fixture["requests"]
            },
            "family": fixture.get("family"),
            "note": _text(fixture.get("note") or ""),
        },
    )


def use_case_paragraphs(text: str) -> list[str]:
    """Split the use case into paragraphs; a heading joins the paragraph after it."""
    blocks = [block.strip() for block in re.split(r"\n\s*\n", text) if block.strip()]
    paragraphs: list[str] = []
    pending: list[str] = []
    for block in blocks:
        lines = block.splitlines()
        if all(line.lstrip().startswith("#") for line in lines):
            pending.extend(line.strip() for line in lines)
            continue
        paragraphs.append("\n".join([*pending, block]))
        pending = []
    if pending:
        paragraphs.append("\n".join(pending))
    return paragraphs


def _constraint_sort_key(constraint_id: str) -> tuple[str, int]:
    prefix, _, number = constraint_id.rpartition("-")
    return (prefix, int(number) if number.isdigit() else 0)


def _scenario_entry(run: RecordedRun, scenario_id: str) -> CaseEntry:
    scenario = run.scenarios[scenario_id]
    lineage = scenario.get("lineage") or {}
    uca = scenario.get("uca") or {}
    lines = []
    action = lineage.get("control_action_id")
    lines.append(
        f"Control action: {action} ({_text(uca.get('control_action') or 'unnamed')})"
    )
    if uca.get("context"):
        lines.append(f"Context: {_text(uca['context'])}")
    context = _context(run, scenario)
    if context:
        lines.append(
            "Process-model context: "
            + "; ".join(
                f"{pm_id} ({_text(run.pm_descriptions.get(pm_id, 'no description'))})"
                f" = {_text(value)}"
                for pm_id, value in sorted(context.items())
            )
        )
    else:
        lines.append("Process-model context: not recorded")
    if uca.get("statement"):
        lines.append(f"Unsafe control action: {_text(uca['statement'])}")
    for factor in scenario.get("causal_factors") or []:
        variable = factor.get("process_model_variable") or {}
        parts = []
        if variable.get("id"):
            parts.append(
                f"{variable['id']} ({_text(variable.get('description') or '')})"
            )
        if factor.get("process_model_belief"):
            parts.append(f"belief: {_text(factor['process_model_belief'])}")
        if factor.get("flaw"):
            parts.append(f"flaw: {_text(factor['flaw'])}")
        if parts:
            lines.append("Causal factor: " + "; ".join(parts))
    for condition in scenario.get("preconditions") or []:
        lines.append(f"Precondition: {_text(condition)}")
    call = scenario.get("semantic_failure_call") or {}
    if call.get("operation_name"):
        lines.append(
            f"Failure call: {call.get('kind') or 'call'} of {call['operation_name']}"
        )
    if scenario.get("semantic_failure_criterion"):
        lines.append(
            f"Failure criterion: {_text(scenario['semantic_failure_criterion'])}"
        )
    lines.append(f"Safe alternative: {_text(scenario.get('safe_alternative') or '')}")
    constraint_ids = lineage.get("constraint_ids") or []
    lines.append(
        "Constraints: " + (", ".join(constraint_ids) if constraint_ids else "none")
    )
    return CaseEntry(
        scenario_id, f"({scenario.get('kind', 'scenario')} scenario)", tuple(lines)
    )


def _constraint_entries(constraint: Mapping[str, Any]) -> list[CaseEntry]:
    constraint_id = constraint["constraint_id"]
    applies = [_text(item) for item in constraint.get("applies_when") or []]
    entries = [
        CaseEntry(
            constraint_id,
            None,
            (
                _text(constraint.get("rule") or constraint.get("description") or ""),
                "Applies when: " + ("; ".join(applies) if applies else "not stated"),
            ),
        )
    ]
    for obligation in constraint.get("obligations") or []:
        span = obligation.get("rule_span")
        entries.append(
            CaseEntry(
                f"{constraint_id}/{obligation['obligation_id']}",
                f"({obligation.get('kind', 'obligation')} obligation)",
                (
                    _text(obligation.get("behavior") or ""),
                    *((f"Rule span: {_text(span)}",) if span else ()),
                ),
            )
        )
    return entries


def recorded_case(run: RecordedRun, item: Mapping[str, Any]) -> ReviewCase:
    """Build a recorded candidate's case: its scenarios, constraints and use case."""
    scenario_ids = list(dict.fromkeys(item["scenario_ids"]))
    unknown = [sid for sid in scenario_ids if sid not in run.scenarios]
    if unknown:
        raise SystemExit(f"{item['case_id']}: {run.label} has no {unknown}")
    constraint_ids = sorted(
        {
            constraint_id
            for sid in scenario_ids
            for constraint_id in (run.scenarios[sid].get("lineage") or {}).get(
                "constraint_ids"
            )
            or []
            if constraint_id in run.constraints
        },
        key=_constraint_sort_key,
    )
    constraint_entries = [
        entry
        for constraint_id in constraint_ids
        for entry in _constraint_entries(run.constraints[constraint_id])
    ]
    use_case = [
        CaseEntry(f"UC-{number}", None, tuple(paragraph.splitlines()))
        for number, paragraph in enumerate(use_case_paragraphs(run.use_case), 1)
    ]
    scenario_entries = [_scenario_entry(run, sid) for sid in scenario_ids]
    sections = (
        CaseSection("Use case", tuple(use_case)),
        CaseSection("Constraints and obligations", tuple(constraint_entries)),
        CaseSection("Scenarios", tuple(scenario_entries)),
    )
    identifiers = tuple(
        entry.ref
        for section in sections
        for entry in section.entries
        if entry.ref is not None
    )
    return ReviewCase(
        case_id=item["case_id"],
        source="recorded",
        sections=sections,
        identifiers=identifiers,
        labels={
            "label": item.get("label"),
            "acceptable": list(item.get("acceptable") or []),
            "note": item.get("note") or "",
            "run": run.label,
            "scenario_ids": scenario_ids,
        },
    )


def load_manifest_cases(path: Path) -> list[ReviewCase]:
    items = list(_yaml(path)["cases"])
    runs: dict[str, RecordedRun] = {}
    cases = []
    for item in items:
        run_dir = Path(item["run_dir"])
        key = str(run_dir.resolve())
        if key not in runs:
            runs[key] = load_run(run_dir)
        cases.append(recorded_case(runs[key], item))
    return cases


def load_cases(
    fixtures: Path | None, manifest: Path | None, only: Sequence[str] = ()
) -> list[ReviewCase]:
    cases: list[ReviewCase] = []
    if fixtures is not None:
        cases.extend(fixture_case(item) for item in load_fixtures(fixtures))
    if manifest is not None:
        cases.extend(load_manifest_cases(manifest))
    ids = [case.case_id for case in cases]
    repeated = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if repeated:
        raise SystemExit(f"case ids repeat: {repeated}")
    if only:
        missing = sorted(set(only) - set(ids))
        if missing:
            raise SystemExit(f"no such case: {missing}")
        cases = [case for case in cases if case.case_id in only]
    return cases


# Prompts ------------------------------------------------------------------


def render_review_prompts(
    case: ReviewCase, loader: TemplateLoader | None = None
) -> tuple[str, str]:
    """Return the system and user prompts of one case's review request."""
    loader = loader or TemplateLoader(PROMPTS_DIR)
    system = loader.render_prompt(SYSTEM_TEMPLATE)
    user = loader.render_prompt(
        USER_TEMPLATE,
        case_id=case.case_id,
        sections=case.sections,
        identifiers=case.identifiers,
        request_ids=case.request_ids,
    )
    return system, user


# Verdict schema and validators --------------------------------------------


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CitedRequirement(WireModel):
    ref: str = Field(min_length=1)
    property: Property
    requires: str = Field(min_length=1)


class OverlappingContext(WireModel):
    kind: Literal["resource", "state", "decision_point", "none"]
    description: str = Field(min_length=1)


class Mechanism(WireModel):
    ref: str = Field(min_length=1)
    mechanism: str = Field(min_length=1)


class Assertion(WireModel):
    ref: str = Field(min_length=1)
    assertion: str = Field(min_length=1)


class OverRefusal(WireModel):
    blocks_legitimate_request: bool
    request: str | None = None
    source_ref: str | None = None
    reason: str = Field(min_length=1)


class RequestDecision(WireModel):
    request_id: str = Field(min_length=1)
    decision: Literal["allow", "block", "escalate"]
    safeguard_as_written: Literal["allow", "block"]


class ConflictVerdict(WireModel):
    """The model's finding for one case."""

    finding_class: FindingClass
    requirements: list[CitedRequirement] = Field(min_length=2)
    overlapping_context: OverlappingContext
    mechanisms: list[Mechanism] = Field(min_length=1)
    causal_explanation: str = Field(min_length=1)
    missing_facts: list[str] = Field(default_factory=list)
    shared_dependency: str | None = None
    assertions: list[Assertion] = Field(default_factory=list)
    expected_behaviour: Literal["satisfy_all", "stop", "explain", "escalate"]
    over_refusal: OverRefusal
    request_decisions: list[RequestDecision] = Field(default_factory=list)


def _blank(value: str | None) -> bool:
    return value is None or not value.strip()


def verdict_failures(verdict: ConflictVerdict, case: ReviewCase) -> list[str]:
    """Return every rule the verdict breaks, worded for a correction request."""
    failures: list[str] = []
    known = set(case.identifiers)

    def check_ref(ref: str | None, where: str) -> None:
        if ref is not None and ref not in known:
            failures.append(f"{where} cites {ref!r}, which the case does not list")

    refs = [item.ref for item in verdict.requirements]
    for ref in refs:
        check_ref(ref, "requirements")
    if len(set(refs)) != len(refs):
        failures.append("requirements repeat an identifier; cite each one once")
    if len(set(refs)) < 2:
        failures.append("requirements must cite at least two distinct identifiers")
    for item in verdict.mechanisms:
        check_ref(item.ref, "mechanisms")
    for item in verdict.assertions:
        check_ref(item.ref, "assertions")
    if _blank(verdict.causal_explanation):
        failures.append("causal_explanation is empty")
    missing = [fact for fact in verdict.missing_facts if not _blank(fact)]
    kind = verdict.finding_class
    if kind == "demonstrated_conflict":
        if missing:
            failures.append(
                "a demonstrated_conflict lists missing facts; either the stated "
                "facts show the conflict and missing_facts is empty, or the "
                "class is missing_information"
            )
        if verdict.expected_behaviour == "satisfy_all":
            failures.append(
                "a demonstrated_conflict cannot satisfy every requirement; "
                "expected_behaviour must be stop, explain or escalate"
            )
    if kind == "missing_information" and not missing:
        failures.append(
            "a missing_information finding must list at least one missing fact"
        )
    if kind == "reinforcement":
        if _blank(verdict.shared_dependency):
            failures.append("a reinforcement finding must name its shared_dependency")
        asserted = [item.ref for item in verdict.assertions]
        lacking = [ref for ref in dict.fromkeys(refs) if ref not in asserted]
        extra = [ref for ref in asserted if ref not in refs]
        if lacking:
            failures.append(
                "a reinforcement finding needs one assertion per cited "
                f"requirement; none for {', '.join(lacking)}"
            )
        if extra:
            failures.append(
                f"assertions name {', '.join(extra)}, which requirements do not cite"
            )
        if len(set(asserted)) != len(asserted):
            failures.append("assertions repeat a requirement; give one per requirement")
    refusal = verdict.over_refusal
    if refusal.blocks_legitimate_request:
        if _blank(refusal.request):
            failures.append("over_refusal is flagged but names no request")
        if _blank(refusal.source_ref):
            failures.append("over_refusal is flagged but cites no source_ref")
    check_ref(refusal.source_ref, "over_refusal.source_ref")
    decided = [item.request_id for item in verdict.request_decisions]
    for request_id in decided:
        if request_id not in case.request_ids:
            failures.append(
                f"request_decisions names {request_id!r}, which is not a listed request"
            )
    lacking_requests = [rid for rid in case.request_ids if rid not in decided]
    if lacking_requests:
        failures.append(
            f"request_decisions has no decision for {', '.join(lacking_requests)}"
        )
    if len(set(decided)) != len(decided):
        failures.append("request_decisions repeats a request; decide each once")
    return failures


class _VerdictRejectedError(ExactFeedbackError):
    """A parsed verdict that broke a rule."""


REVIEW_CORRECTION_POLICY = CorrectionPolicy(
    validation_retries=1,
    feedback=(
        "\n\nCode rejected the prior reply. Return the whole reply again with "
        "every listed problem fixed."
    ),
    include_schema=False,
    include_response=True,
)


# Runner -------------------------------------------------------------------


@dataclass
class CaseResult:
    case_id: str
    source: str
    verdict: dict[str, Any] | None = None
    rejected: list[tuple[str, ...]] = field(default_factory=list)
    requests: int = 0
    error: str | None = None
    budget_refused: bool = False

    @property
    def accepted(self) -> bool:
        return self.verdict is not None


def review_case(
    case: ReviewCase,
    *,
    llm_client: LLMClient,
    run_dir: Path,
    loader: TemplateLoader | None = None,
) -> CaseResult:
    """Send one case's review request, with at most one correction."""
    system, user = render_review_prompts(case, loader)
    result = CaseResult(case_id=case.case_id, source=case.source)

    def check(reply: ConflictVerdict) -> None:
        failures = verdict_failures(reply, case)
        if failures:
            result.rejected.append(tuple(failures))
            raise _VerdictRejectedError(
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
        response_format=ConflictVerdict,
        run_dir=run_dir,
        stage=REVIEW_STAGE,
        step=REVIEW_STEP,
        policy=REVIEW_CORRECTION_POLICY,
        scenario_id=case.case_id,
        temperature=effective_temperature(llm_client),
        result_validator=check,
    )
    result.requests = outcome.calls
    if outcome.value is not None:
        result.verdict = outcome.value.model_dump(mode="json")
    else:
        result.error = outcome.error or "the call returned no reply"
        result.budget_refused = isinstance(outcome.failure, LiveRequestBudgetError)
    return result


def _live_requests(session: ProviderCallSession) -> int:
    summary = session.fill_summary() or {}
    return int(summary.get("live_requests", 0))


def run_cases(
    cases: Sequence[ReviewCase],
    *,
    llm_client: LLMClient,
    session: ProviderCallSession,
    out_dir: Path,
    max_live_requests: int,
    stop_after_failures: int = 3,
    loader: TemplateLoader | None = None,
) -> tuple[list[CaseResult], str | None]:
    """Review the cases one at a time; return the results and why it stopped.

    A case starts only while live budget remains, except that a zero budget
    still runs every case, so a replay serves what it holds and the first
    request it lacks is refused.
    """
    results: list[CaseResult] = []
    verdicts = out_dir / "verdicts"
    verdicts.mkdir(parents=True, exist_ok=True)
    consecutive_failures = 0
    for case in cases:
        if max_live_requests and _live_requests(session) >= max_live_requests:
            return results, "live request budget spent"
        result = review_case(
            case, llm_client=llm_client, run_dir=out_dir, loader=loader
        )
        results.append(result)
        record = {
            "case_id": case.case_id,
            "source": case.source,
            "accepted": result.accepted,
            "verdict": result.verdict,
            "rejected": [list(items) for items in result.rejected],
            "requests": result.requests,
            "error": result.error,
            "labels": case.labels,
        }
        (verdicts / f"{case.case_id}.json").write_text(
            json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        if result.budget_refused or session.budget_refusals:
            return results, "a request was refused by the live request budget"
        consecutive_failures = 0 if result.accepted else consecutive_failures + 1
        if stop_after_failures and consecutive_failures >= stop_after_failures:
            return (
                results,
                f"{consecutive_failures} consecutive cases had no accepted verdict",
            )
    return results, None


def score_case(case: ReviewCase, result: CaseResult) -> dict[str, Any]:
    """Compare one accepted verdict with its labels."""
    row: dict[str, Any] = {
        "case_id": case.case_id,
        "source": case.source,
        "accepted": result.accepted,
        "requests": result.requests,
        "corrections": len(result.rejected),
    }
    verdict = result.verdict
    labels = case.labels
    row["class"] = verdict["finding_class"] if verdict else None
    row["over_refusal"] = (
        verdict["over_refusal"]["blocks_legitimate_request"] if verdict else None
    )
    if case.source == "fixture":
        expected = labels["expected_class"]
        row["expected_class"] = expected
        row["class_correct"] = (
            None
            if verdict is None
            else row["class"] in (expected, *labels["acceptable_classes"])
        )
        row["expected_over_refusal"] = labels["expected_over_refusal"]
        decisions = {
            item["request_id"]: item
            for item in (verdict or {}).get("request_decisions", [])
        }
        requests = {}
        for request_id, wanted in labels["expected_requests"].items():
            decision = decisions.get(request_id)
            got = decision["decision"] if decision else None
            requests[request_id] = {
                "expected": wanted,
                "decision": got,
                "safeguard_as_written": (
                    decision["safeguard_as_written"] if decision else None
                ),
                "correct": (
                    None if got is None else (got == "allow") == (wanted == "allow")
                ),
            }
        row["requests_judged"] = requests
    else:
        label = labels.get("label")
        row["hand_label"] = label
        row["class_correct"] = (
            None if verdict is None or label is None else row["class"] == label
        )
        row["class_acceptable"] = (
            None
            if verdict is None or label is None
            else row["class"] in (label, *labels.get("acceptable", []))
        )
    return row


def provider_spend(record_dir: Path) -> dict[str, Any]:
    """Count the provider records by source, corrections and transport retries."""
    path = record_dir / RECORD_FILENAME
    records = (
        [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        if path.exists()
        else []
    )
    sources = Counter(record.get("source", "unknown") for record in records)
    return {
        "records": len(records),
        "by_source": dict(sorted(sources.items())),
        "corrections": sum(
            1
            for record in records
            if (record.get("identity") or {}).get("attempt_number", 1) > 1
        ),
        "transport_retries": sum(1 for record in records if "retry_of" in record),
        "errors": sum(1 for record in records if record.get("outcome") == "error"),
    }


def request_controls(run_dir: Path) -> list[dict[str, Any]]:
    """Return the distinct request controls the call log recorded."""
    path = run_dir / "calls.jsonl"
    if not path.exists():
        return []
    seen: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        controls = {
            "model": entry.get("model"),
            **(entry.get("request_controls") or {}),
        }
        if controls not in seen:
            seen.append(controls)
    return seen


def summarize(
    cases: Sequence[ReviewCase],
    results: Sequence[CaseResult],
    *,
    stop_reason: str | None,
    fill: Mapping[str, Any] | None,
    spend: Mapping[str, Any],
    controls: Sequence[Mapping[str, Any]],
    profile: str,
    budget_error: str | None,
) -> dict[str, Any]:
    by_id = {case.case_id: case for case in cases}
    rows = [score_case(by_id[result.case_id], result) for result in results]
    confusion: Counter[tuple[str, str]] = Counter(
        (
            str(row.get("expected_class") or row.get("hand_label")),
            str(row["class"]),
        )
        for row in rows
    )
    return {
        "schema_version": "conflict-review-pilot-summary-v1",
        "profile": profile,
        "controls": list(controls),
        "cases_listed": len(cases),
        "cases_run": len(results),
        "cases_not_run": [case.case_id for case in cases[len(results) :]],
        "accepted": sum(1 for result in results if result.accepted),
        "stop_reason": stop_reason,
        "budget_error": budget_error,
        "fill_summary": dict(fill) if fill else None,
        "spend": dict(spend),
        "confusion": [
            {"label": label, "model": model, "count": count}
            for (label, model), count in sorted(confusion.items())
        ],
        "rows": rows,
    }


def summary_markdown(summary: Mapping[str, Any]) -> str:
    lines = [
        "# Conflict review pilot",
        "",
        f"- Profile: {summary['profile']}",
        f"- Cases run: {summary['cases_run']} of {summary['cases_listed']}; "
        f"accepted: {summary['accepted']}",
        f"- Stop reason: {summary['stop_reason'] or 'none'}",
        f"- Provider records by source: {summary['spend']['by_source']}; "
        f"corrections: {summary['spend']['corrections']}; "
        f"transport retries: {summary['spend']['transport_retries']}",
        "",
        "| Case | Label | Model class | Correct | Over-refusal | Requests | Corrections |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in summary["rows"]:
        label = row.get("expected_class") or row.get("hand_label") or ""
        lines.append(
            f"| {row['case_id']} | {label} | {row['class']} | {row['class_correct']} "
            f"| {row['over_refusal']} | {row['requests']} | {row['corrections']} |"
        )
    fixture_rows = [row for row in summary["rows"] if "requests_judged" in row]
    if fixture_rows:
        lines += [
            "",
            "| Fixture | Request | Expected | Decision | Safeguard as written | Correct |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for row in fixture_rows:
            for request_id, item in row["requests_judged"].items():
                lines.append(
                    f"| {row['case_id']} | {request_id} | {item['expected']} "
                    f"| {item['decision']} | {item['safeguard_as_written']} "
                    f"| {item['correct']} |"
                )
    return "\n".join(lines) + "\n"


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def run_command(
    cases: Sequence[ReviewCase],
    *,
    out_dir: Path,
    max_live_requests: int,
    client_factory: Any,
    profile: str,
    replay_dir: Path | None = None,
    stop_after_failures: int = 3,
) -> dict[str, Any]:
    """Run the cases under a recorded, capped session and write the summary.

    *client_factory* takes the session and returns the ``LLMClient``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    if replay_dir is None:
        replay_dir = out_dir / "empty-replay"
        replay_dir.mkdir(exist_ok=True)
        (replay_dir / RECORD_FILENAME).touch()
    results: list[CaseResult] = []
    stop_reason: str | None = None
    fill: dict[str, Any] | None = None
    budget_error: str | None = None
    try:
        with provider_call_session(
            record_dir=out_dir,
            replay_dir=replay_dir,
            fill=ReplayFill(max_live_requests=max_live_requests),
        ) as session:
            client = client_factory(session)
            results, stop_reason = run_cases(
                cases,
                llm_client=client,
                session=session,
                out_dir=out_dir,
                max_live_requests=max_live_requests,
                stop_after_failures=stop_after_failures,
            )
            fill = session.fill_summary()
    except LiveRequestBudgetError as exc:
        budget_error = str(exc)
    summary = summarize(
        cases,
        results,
        stop_reason=stop_reason,
        fill=fill,
        spend=provider_spend(out_dir),
        controls=request_controls(out_dir),
        profile=profile,
        budget_error=budget_error,
    )
    _write_json(out_dir / "summary.json", summary)
    (out_dir / "summary.md").write_text(summary_markdown(summary), encoding="utf-8")
    return summary


# Commands -----------------------------------------------------------------


def _select(args: argparse.Namespace) -> None:
    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    runs = [load_run(path) for path in args.run]
    pairs_by_run = {str(run.run_dir.resolve()): candidate_pairs(run) for run in runs}
    hand = list(_yaml(args.hand_manifest)["cases"]) if args.hand_manifest else []
    with (out_dir / "candidate-pairs.jsonl").open("w", encoding="utf-8") as handle:
        for run in runs:
            for pair in pairs_by_run[str(run.run_dir.resolve())]:
                row = {
                    "run": run.label,
                    "pair": [pair.first, pair.second],
                    "shared": {k: list(v) for k, v in pair.shared.items()},
                    "in_union": pair.in_union,
                }
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    _write_json(
        out_dir / "candidate-groups.json",
        {run.label: candidate_groups(run) for run in runs},
    )
    counts = {
        "runs": {
            run.label: {
                "non_duplicate_scenarios": len(run.non_duplicates()),
                "with_process_model_context": sum(
                    1
                    for sid in run.non_duplicates()
                    if _context(run, run.scenarios[sid])
                ),
                "pairs": pair_counts(pairs_by_run[str(run.run_dir.resolve())]),
                "groups": {
                    name: len(elements)
                    for name, elements in candidate_groups(run).items()
                },
            }
            for run in runs
        },
    }
    if hand:
        counts["hand_coverage"] = hand_coverage(hand, pairs_by_run)
    _write_json(out_dir / "selector-counts.json", counts)
    (out_dir / "selector-summary.md").write_text(
        _selector_markdown(counts), encoding="utf-8"
    )
    if args.sample_size:
        sample = sample_unselected(pairs_by_run, hand, args.sample_size, args.seed)
        (out_dir / "sample-manifest.yaml").write_text(
            yaml.safe_dump({"cases": sample}, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
    print(f"wrote selector outputs to {out_dir}")


def _selector_markdown(counts: Mapping[str, Any]) -> str:
    names = (*GROUPINGS, "union", *COMPARISON_GROUPINGS)
    lines = [
        "# Candidate selector",
        "",
        "| Run | Non-duplicates | With context | " + " | ".join(names) + " |",
        "| --- | --- | --- | " + " | ".join("---" for _ in names) + " |",
    ]
    for label, run in counts["runs"].items():
        lines.append(
            f"| {label} | {run['non_duplicate_scenarios']} "
            f"| {run['with_process_model_context']} | "
            + " | ".join(str(run["pairs"][name]) for name in names)
            + " |"
        )
    coverage = counts.get("hand_coverage")
    if coverage:
        lines += [
            "",
            f"Hand candidates: {coverage['candidates']} "
            f"({coverage['pairable']} with two or more scenarios).",
            "",
            "| Grouping | Hand candidates covered |",
            "| --- | --- |",
        ]
        lines += [f"| {name} | {coverage['covered'][name]} |" for name in names]
        lines += ["", "| Candidate | Covered by |", "| --- | --- |"]
        lines += [
            f"| {row['case_id']} | {', '.join(row['covered_by']) or ('-' if row['pairable'] else 'unpairable')} |"
            for row in coverage["rows"]
        ]
    return "\n".join(lines) + "\n"


def _render(args: argparse.Namespace) -> None:
    (case,) = load_cases(args.fixtures, args.manifest, [args.case])
    system, user = render_review_prompts(case)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / f"{case.case_id}.system.txt").write_text(system, encoding="utf-8")
    (args.out_dir / f"{case.case_id}.user.txt").write_text(user, encoding="utf-8")
    print(f"wrote {case.case_id} prompts to {args.out_dir}")


def _run(args: argparse.Namespace) -> None:
    from asago_scenario_generator.stpa.pipeline.llm_config import (
        resolve_llm_client_from_profile,
    )

    cases = load_cases(args.fixtures, args.manifest, args.case or ())

    def client_factory(session: ProviderCallSession) -> LLMClient:
        client, _ = resolve_llm_client_from_profile(
            str(args.profiles_file), args.profile, session=session
        )
        return client

    summary = run_command(
        cases,
        out_dir=args.out_dir,
        max_live_requests=args.max_live_requests,
        client_factory=client_factory,
        profile=args.profile,
        replay_dir=args.replay_dir,
        stop_after_failures=args.stop_after_failures,
    )
    print(
        f"cases run {summary['cases_run']}/{summary['cases_listed']}, "
        f"accepted {summary['accepted']}, spend {summary['spend']['by_source']}, "
        f"stop: {summary['stop_reason'] or 'none'}"
    )


def _case_sources(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--manifest", type=Path)


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)

    select = commands.add_parser(
        "select", help="group recorded scenarios into candidates"
    )
    select.add_argument("--run", type=Path, action="append", required=True)
    select.add_argument("--out-dir", type=Path, required=True)
    select.add_argument("--hand-manifest", type=Path)
    select.add_argument("--sample-size", type=int, default=0)
    select.add_argument("--seed", type=int, default=20261029)
    select.set_defaults(handler=_select)

    render = commands.add_parser("render", help="write one case's prompts")
    _case_sources(render)
    render.add_argument("--case", required=True)
    render.add_argument("--out-dir", type=Path, required=True)
    render.set_defaults(handler=_render)

    run = commands.add_parser("run", help="review cases through a capped session")
    _case_sources(run)
    run.add_argument("--case", action="append")
    run.add_argument("--profiles-file", type=Path, required=True)
    run.add_argument("--profile", required=True)
    run.add_argument("--max-live-requests", type=int, required=True)
    run.add_argument("--out-dir", type=Path, required=True)
    run.add_argument("--replay-dir", type=Path)
    run.add_argument("--stop-after-failures", type=int, default=3)
    run.set_defaults(handler=_run)

    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command in ("render", "run") and not (args.fixtures or args.manifest):
        parser.error("give --fixtures or --manifest")
    args.handler(args)


if __name__ == "__main__":
    main()

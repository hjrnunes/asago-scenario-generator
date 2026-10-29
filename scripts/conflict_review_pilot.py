#!/usr/bin/env python3
"""Research pilot: a scoped semantic review of scenario safe alternatives.

    uv run --frozen python scripts/conflict_review_pilot.py select \\
        --run RUN_DIR [--run RUN_DIR ...] --out-dir DIR \\
        [--hand-manifest MANIFEST] [--sample-size 18] [--seed 20261029]

    uv run --frozen python scripts/conflict_review_pilot.py render \\
        (--fixtures FILE | --manifest MANIFEST) --case CASE_ID --out-dir DIR \\
        [--resources FILE]

    uv run --frozen python scripts/conflict_review_pilot.py run \\
        --profiles-file FILE --profile NAME \\
        (--fixtures FILE | --manifest MANIFEST) [--case CASE_ID ...] \\
        --max-live-requests N --out-dir DIR [--replay-dir DIR] \\
        [--resources FILE] [--stop-after-failures 3]

    uv run --frozen python scripts/conflict_review_pilot.py score \\
        --verdicts RUN_OUT_DIR [--verdicts RUN_OUT_DIR ...] \\
        --labels NAME=FILE [--labels NAME=FILE ...] --out-dir DIR

The review is not a gate and is not part of ``generate``. A case is either a
synthetic fixture (a safeguard ``SA-1`` among requirements and requests), one
recorded scenario reviewed alone against its use case (``single``), or two or
more recorded scenarios reviewed together (``group``). The model first lists
the requests the use case authorizes (or takes a fixture's listed requests),
judges each against the safeguards as written, and then classifies the
finding. Over-refusal is derived in code from those judgements.

``select`` reads recorded producer runs and never writes them. For each run's
``stages/generate/output`` it loads the scenarios, ``loss-analysis.yaml``,
``control-structure.yaml`` and ``testability.yaml``, and rebuilds each ICA's
process-model context from ``target-realization.yaml``'s effective ICA
enumeration with ``ica_process_model_contexts``. Non-duplicate scenarios pair
when they share one of the pair keys:

- ``operation_conflict``: the same failure-call operation, where one scenario
  requires the call (its failure is a ``missing_call``) and the other forbids
  it (its failure is an ``incorrect_call``);
- ``ca_context``: a control action plus the rebuilt process-model context;
- ``pm_variable``: a causal-factor process-model variable.

A shared ``constraint`` forms no pair; it is recorded beside a pair as
context. ``operation`` (any polarity) and ``control_action`` are counted for
comparison only. Outputs in ``--out-dir``:

- ``candidate-pairs.jsonl``: one row per (run, pair) with every shared element;
- ``candidate-groups.json``: per run and key, each element's scenarios;
- ``selector-counts.json`` and ``selector-summary.md``: pair counts per key and
  run, and with ``--hand-manifest`` how many hand-labelled candidates each key
  covers (two of the candidate's scenarios share an element of it) and how
  many single-scenario candidates the single pass covers;
- ``single-manifest.yaml``: the single-scenario pass, one case per
  non-duplicate scenario;
- ``sample-manifest.yaml``: with ``--sample-size``, a seeded sample of pairs
  that no hand candidate contains, with empty labels.

``render`` writes one case's system and user prompts without a model.

``run`` reviews the cases one at a time through ``provider_call_session``
with ``ReplayFill(max_live_requests=N)``: every request is recorded in
``--out-dir/provider-calls.jsonl``, and a rerun given the earlier output as
``--replay-dir`` replays it for free. A reply that fails the schema or a
validator earns one correction, which asks the model to decide its class
again (``CorrectionPolicy(validation_retries=1)``); the summary records the
class of each attempt and whether the correction changed it, and counts
corrections apart from the client's transport retries and tier fallbacks. The
runner
starts no case once the live budget is spent, stops at the first refused
request, and stops after ``--stop-after-failures`` consecutive cases without
an accepted verdict. It writes ``verdicts/<case>.json`` per case and
``summary.json`` and ``summary.md``.

``score`` reads the recorded verdicts of earlier ``run`` outputs and scores
them, without a model, against each label file (``cases: [{case_id, label,
acceptable, over_refusal}]``, ``over_refusal`` being ``clear`` or ``yes``,
``contingent``, or ``no``) and on the cases where every file gives the same
label. Each file is scored on the verdicts it labels, and the report says how
many verdicts that is. It writes ``score.json`` and ``score.md``.

A fixtures file is ``scripts/conflict_review/paired-fixtures.yaml``. A
manifest lists recorded cases::

    cases:
      - case_id: A1
        run_dir: /path/to/run
        scenario_ids: [SCN-033, SCN-036]
        resources: []                       # typed resources; optional
        label: demonstrated_conflict        # scoring only; optional
        acceptable: [unfaithful_refinement] # scoring only; optional
        over_refusal: clear                 # scoring only: clear | contingent
        note: free text                     # scoring only; optional

Typed resources are the budgets, deadlines, retry limits and reviewer
capacities a case may rely on. A fixture or a manifest case carries its own
under ``resources``; ``--resources FILE`` (``resources: [...]``) adds the same
list to every recorded case. Each item is ``{resource_id: RES-<n>, kind,
value, unit, applies_to}``. Without one, a finding that turns on such a
resource may only be ``missing_information``. A resource id given twice for
one case, within a source or across sources, is refused.

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
from collections.abc import Callable, Iterable, Mapping, Sequence
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
CORRECTION_TEMPLATE = "conflict_review_correction.j2"

REVIEW_STAGE = "research_conflict_review"
REVIEW_STEP = "review"

PAIR_KEYS = ("operation_conflict", "ca_context", "pm_variable")
"""The keys that pair scenarios; their union gives the candidate pairs."""
CONTEXT_KEYS = ("constraint",)
"""Recorded beside a pair as context; they form no pair."""
COMPARISON_KEYS = ("operation", "control_action")
"""Counted beside the union for comparison only."""
ALL_KEYS = PAIR_KEYS + CONTEXT_KEYS + COMPARISON_KEYS

CALL_POLARITY = {"missing_call": "requires", "incorrect_call": "forbids"}
"""A ``missing_call`` failure means the scenario requires the call; an
``incorrect_call`` failure means it forbids the call in its context."""

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
ResourceKind = Literal[
    "tool_call_budget", "deadline", "retry_limit", "reviewer_capacity"
]
Handling = Literal["allow", "block", "escalate"]

_RESOURCE_ID = re.compile(r"^RES-\d+$")
_REQUEST_ID = re.compile(r"^AR-\d+$")


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


def call_polarity(scenario: Mapping[str, Any]) -> str | None:
    """Whether the scenario requires or forbids its failure-call operation."""
    call = scenario.get("semantic_failure_call") or {}
    if not call.get("operation_name"):
        return None
    return CALL_POLARITY.get(str(call.get("kind")))


# Selector -----------------------------------------------------------------


def scenario_keys(run: RecordedRun, scenario_id: str) -> dict[str, list[str]]:
    """Return the elements of each per-scenario key that one scenario carries."""
    scenario = run.scenarios[scenario_id]
    lineage = scenario.get("lineage") or {}
    action = lineage.get("control_action_id")
    context = _context(run, scenario)
    operation = (scenario.get("semantic_failure_call") or {}).get("operation_name")
    variables = [
        (factor.get("process_model_variable") or {}).get("id")
        for factor in scenario.get("causal_factors") or []
    ]
    return {
        "ca_context": (
            [action + " | " + "; ".join(f"{k}={v}" for k, v in sorted(context.items()))]
            if action and context
            else []
        ),
        "pm_variable": list(dict.fromkeys(v for v in variables if v)),
        "constraint": list(dict.fromkeys(lineage.get("constraint_ids") or [])),
        "operation": [operation] if operation else [],
        "control_action": [action] if action else [],
    }


def candidate_groups(run: RecordedRun) -> dict[str, dict[str, Any]]:
    """Map each key's elements to the non-duplicate scenarios sharing them.

    ``operation_conflict`` maps an operation to the scenarios that require it
    and those that forbid it, and lists only operations with both.
    """
    groups: dict[str, dict[str, list[str]]] = {
        name: {} for name in ALL_KEYS if name != "operation_conflict"
    }
    roles: dict[str, dict[str, list[str]]] = {}
    for scenario_id in run.non_duplicates():
        for name, elements in scenario_keys(run, scenario_id).items():
            for element in elements:
                groups[name].setdefault(element, []).append(scenario_id)
        scenario = run.scenarios[scenario_id]
        polarity = call_polarity(scenario)
        if polarity is not None:
            operation = scenario["semantic_failure_call"]["operation_name"]
            entry = roles.setdefault(operation, {"requires": [], "forbids": []})
            entry[polarity].append(scenario_id)
    result: dict[str, dict[str, Any]] = {
        name: {k: v for k, v in sorted(elements.items()) if len(v) > 1}
        for name, elements in groups.items()
    }
    result["operation_conflict"] = {
        operation: entry
        for operation, entry in sorted(roles.items())
        if entry["requires"] and entry["forbids"]
    }
    return {name: result[name] for name in ALL_KEYS}


def run_labels(runs: Sequence[RecordedRun]) -> list[str]:
    """Name each run in the reports: its basename, or its resolved path when
    another run shares that basename. A run given twice is refused."""
    paths = [str(run.run_dir.resolve()) for run in runs]
    repeated = sorted({path for path in paths if paths.count(path) > 1})
    if repeated:
        raise SystemExit(f"runs repeat: {repeated}")
    names = Counter(run.label for run in runs)
    return [
        run.label if names[run.label] == 1 else path for run, path in zip(runs, paths)
    ]


@dataclass(frozen=True)
class CandidatePair:
    first: str
    second: str
    shared: Mapping[str, tuple[str, ...]]
    """Each key's shared elements; a key with none is absent."""

    @property
    def in_union(self) -> bool:
        return any(name in self.shared for name in PAIR_KEYS)


def candidate_pairs(run: RecordedRun) -> list[CandidatePair]:
    """Return every non-duplicate pair that shares an element of any key."""
    shared: dict[tuple[str, str], dict[str, list[str]]] = {}

    def add(first: str, second: str, name: str, element: str) -> None:
        pair = (min(first, second), max(first, second))
        shared.setdefault(pair, {}).setdefault(name, []).append(element)

    for name, elements in candidate_groups(run).items():
        if name == "operation_conflict":
            for operation, entry in elements.items():
                for first, second in itertools.product(
                    entry["requires"], entry["forbids"]
                ):
                    add(first, second, name, operation)
            continue
        for element, members in elements.items():
            for first, second in itertools.combinations(sorted(members), 2):
                add(first, second, name, element)
    return [
        CandidatePair(first, second, {k: tuple(v) for k, v in sorted(names.items())})
        for (first, second), names in sorted(shared.items())
    ]


def pair_counts(pairs: Sequence[CandidatePair]) -> dict[str, int]:
    counts = {
        name: sum(1 for pair in pairs if name in pair.shared) for name in ALL_KEYS
    }
    counts["union"] = sum(1 for pair in pairs if pair.in_union)
    counts["constraint_only"] = sum(
        1 for pair in pairs if set(pair.shared) & {"constraint"} and not pair.in_union
    )
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
    singles_by_run: Mapping[str, Iterable[str]] | None = None,
) -> dict[str, Any]:
    """Count the hand candidates each key covers.

    A candidate is covered by a key when two of its scenarios share an element
    of it. A candidate with one scenario is unpairable; the single pass covers
    it when *singles_by_run* lists that scenario.
    """
    indexes = {
        run: {(pair.first, pair.second): pair for pair in pairs}
        for run, pairs in pairs_by_run.items()
    }
    singles = {run: set(ids) for run, ids in (singles_by_run or {}).items()}
    rows = []
    for case in hand_cases:
        run = str(Path(case["run_dir"]).resolve())
        scenario_ids = list(dict.fromkeys(case["scenario_ids"]))
        names = _covering(scenario_ids, indexes.get(run, {}))
        pairable = len(scenario_ids) > 1
        rows.append(
            {
                "case_id": case["case_id"],
                "pairable": pairable,
                "covered_by": sorted(names),
                "in_union": bool(names & set(PAIR_KEYS)),
                "single_pass": not pairable
                and scenario_ids[0] in singles.get(run, set()),
            }
        )
    totals = {
        name: sum(1 for row in rows if name in row["covered_by"]) for name in ALL_KEYS
    }
    totals["union"] = sum(1 for row in rows if row["in_union"])
    totals["single_pass"] = sum(1 for row in rows if row["single_pass"])
    totals["union_or_single"] = sum(
        1 for row in rows if row["in_union"] or row["single_pass"]
    )
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


def single_pass_cases(runs: Sequence[RecordedRun]) -> list[dict[str, Any]]:
    """One single-scenario case per non-duplicate scenario of every run."""
    rows = [
        (str(run.run_dir.resolve()), scenario_id)
        for run in runs
        for scenario_id in run.non_duplicates()
    ]
    return [
        {
            "case_id": f"S{index:03d}",
            "run_dir": run,
            "scenario_ids": [scenario_id],
            "label": None,
            "acceptable": [],
            "note": "",
        }
        for index, (run, scenario_id) in enumerate(rows, 1)
    ]


# Typed resources ----------------------------------------------------------


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResourceLimit(WireModel):
    """A typed budget, deadline, retry limit or reviewer capacity."""

    resource_id: str = Field(pattern=_RESOURCE_ID.pattern)
    kind: ResourceKind
    value: int | float = Field(gt=0)
    unit: str = Field(min_length=1)
    applies_to: str = Field(min_length=1)


def parse_resources(items: Iterable[Mapping[str, Any]] | None) -> list[ResourceLimit]:
    resources = [ResourceLimit.model_validate(item) for item in items or []]
    ids = [item.resource_id for item in resources]
    repeated = sorted({rid for rid in ids if ids.count(rid) > 1})
    if repeated:
        raise SystemExit(f"resource ids repeat: {repeated}")
    return resources


def load_resources(path: Path | None) -> list[ResourceLimit]:
    return parse_resources(_yaml(path).get("resources")) if path else []


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
    mode: Literal["fixture", "single", "group"]
    under_review: str
    sections: tuple[CaseSection, ...]
    identifiers: tuple[str, ...]
    review_refs: tuple[str, ...]
    """The scenarios or the safeguard under review."""
    source_refs: tuple[str, ...]
    """The use-case paragraphs, constraints, obligations or requirements."""
    use_case_refs: tuple[str, ...] = ()
    request_ids: tuple[str, ...] = ()
    resources: tuple[ResourceLimit, ...] = ()
    labels: dict[str, Any] = field(default_factory=dict)
    """Expected class, hand label and notes: for scoring, never rendered."""


def _text(value: Any) -> str:
    return " ".join(str(value).split())


def _with_resources(case: ReviewCase, resources: Sequence[ResourceLimit]) -> None:
    """Attach the merged resources; an id given by two sources is refused."""
    ids = [item.resource_id for item in resources]
    repeated = sorted({rid for rid in ids if ids.count(rid) > 1})
    if repeated:
        raise SystemExit(f"{case.case_id}: resource ids repeat: {repeated}")
    case.resources = tuple(resources)
    case.identifiers = (*case.identifiers, *(item.resource_id for item in resources))


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
    requirement_ids = tuple(item["id"] for item in fixture["requirements"])
    request_ids = tuple(item["id"] for item in fixture["requests"])
    case = ReviewCase(
        case_id=fixture["fixture_id"],
        source="fixture",
        mode="fixture",
        under_review=(
            f"the safeguard {safeguard['id']}, against the requirements and the "
            "requests below."
        ),
        sections=sections,
        identifiers=(*requirement_ids, safeguard["id"], *request_ids),
        review_refs=(safeguard["id"],),
        source_refs=requirement_ids,
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
    _with_resources(case, parse_resources(fixture.get("resources")))
    return case


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


_POLARITY_TEXT = {
    "requires": "the failure is not making this call, so the scenario requires it",
    "forbids": "the failure is making this call, so the scenario forbids it here",
}


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
        polarity = call_polarity(scenario)
        lines.append(
            f"Failure call: {call.get('kind') or 'call'} of {call['operation_name']}"
            + (f" ({_POLARITY_TEXT[polarity]})" if polarity else "")
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


def shared_elements(run: RecordedRun, first: str, second: str) -> list[str]:
    """Describe what two recorded scenarios share, from their records."""
    keys = {sid: scenario_keys(run, sid) for sid in (first, second)}
    items: list[str] = []
    operations = set(keys[first]["operation"]) & set(keys[second]["operation"])
    for operation in sorted(operations):
        roles = {sid: call_polarity(run.scenarios[sid]) for sid in (first, second)}
        if set(roles.values()) == {"requires", "forbids"}:
            needs = next(sid for sid, role in roles.items() if role == "requires")
            bars = next(sid for sid, role in roles.items() if role == "forbids")
            items.append(
                f"failure-call operation {operation}, which {needs} requires and "
                f"{bars} forbids"
            )
        elif (role := roles[first]) is not None and role == roles[second]:
            verb = {"requires": "require", "forbids": "forbid"}[role]
            items.append(f"failure-call operation {operation}, which both {verb}")
        else:
            items.append(f"failure-call operation {operation}")
    contexts = set(keys[first]["ca_context"]) & set(keys[second]["ca_context"])
    actions = set(keys[first]["control_action"]) & set(keys[second]["control_action"])
    if contexts:
        items.append(
            "control action "
            + ", ".join(sorted(actions))
            + " in the same process-model context"
        )
    elif actions:
        items.append(
            "control action "
            + ", ".join(sorted(actions))
            + " in different or unrecorded process-model contexts"
        )
    variables = [
        v for v in keys[first]["pm_variable"] if v in keys[second]["pm_variable"]
    ]
    if variables:
        items.append("process-model variable " + ", ".join(variables))
    constraints = [
        c for c in keys[first]["constraint"] if c in keys[second]["constraint"]
    ]
    if constraints:
        items.append("constraint " + ", ".join(constraints))
    return items


def _shared_section(run: RecordedRun, scenario_ids: Sequence[str]) -> CaseSection:
    entries = []
    for first, second in itertools.combinations(scenario_ids, 2):
        items = shared_elements(run, first, second)
        if items:
            entries.append(
                CaseEntry(
                    None, None, (f"{first} and {second}: " + "; ".join(items) + ".",)
                )
            )
    entries.append(
        CaseEntry(
            None,
            None,
            (
                "A pair not listed shares no recorded operation, control action, "
                "process-model variable or constraint."
                if entries
                else "No two of these scenarios share a recorded operation, control "
                "action, process-model variable or constraint.",
            ),
        )
    )
    return CaseSection("What the scenarios share", tuple(entries))


def recorded_case(
    run: RecordedRun,
    item: Mapping[str, Any],
    resources: Sequence[ResourceLimit] = (),
) -> ReviewCase:
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
    single = len(scenario_ids) == 1
    sections: tuple[CaseSection, ...] = (
        CaseSection("Use case", tuple(use_case)),
        CaseSection("Constraints and obligations", tuple(constraint_entries)),
        CaseSection("Scenarios", tuple(scenario_entries)),
    )
    if not single:
        sections = (*sections, _shared_section(run, scenario_ids))
    identifiers = tuple(
        entry.ref
        for section in sections
        for entry in section.entries
        if entry.ref is not None
    )
    under_review = (
        f"the safe alternative of {scenario_ids[0]}, alone, against the use case "
        "and the constraints it refines."
        if single
        else "the safe alternatives of "
        + ", ".join(scenario_ids[:-1])
        + f" and {scenario_ids[-1]}, against each other, the use case and their "
        "constraints."
    )
    use_case_refs = tuple(entry.ref for entry in use_case if entry.ref)
    case = ReviewCase(
        case_id=item["case_id"],
        source="recorded",
        mode="single" if single else "group",
        under_review=under_review,
        sections=sections,
        identifiers=identifiers,
        review_refs=tuple(scenario_ids),
        source_refs=(
            *use_case_refs,
            *(entry.ref for entry in constraint_entries if entry.ref),
        ),
        use_case_refs=use_case_refs,
        labels={
            "label": item.get("label"),
            "acceptable": list(item.get("acceptable") or []),
            "expected_over_refusal": item.get("over_refusal"),
            "note": item.get("note") or "",
            "run": run.label,
            "scenario_ids": scenario_ids,
        },
    )
    _with_resources(case, [*parse_resources(item.get("resources")), *resources])
    return case


def load_manifest_cases(
    path: Path, resources: Sequence[ResourceLimit] = ()
) -> list[ReviewCase]:
    items = list(_yaml(path)["cases"])
    runs: dict[str, RecordedRun] = {}
    cases = []
    for item in items:
        run_dir = Path(item["run_dir"])
        key = str(run_dir.resolve())
        if key not in runs:
            runs[key] = load_run(run_dir)
        cases.append(recorded_case(runs[key], item, resources))
    return cases


def load_cases(
    fixtures: Path | None,
    manifest: Path | None,
    only: Sequence[str] = (),
    resources: Sequence[ResourceLimit] = (),
) -> list[ReviewCase]:
    cases: list[ReviewCase] = []
    if fixtures is not None:
        cases.extend(fixture_case(item) for item in load_fixtures(fixtures))
    if manifest is not None:
        cases.extend(load_manifest_cases(manifest, resources))
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


def _number(value: int | float) -> str:
    return str(int(value)) if float(value).is_integer() else str(value)


def render_review_prompts(
    case: ReviewCase, loader: TemplateLoader | None = None
) -> tuple[str, str]:
    """Return the system and user prompts of one case's review request."""
    loader = loader or TemplateLoader(PROMPTS_DIR)
    system = loader.render_prompt(SYSTEM_TEMPLATE)
    user = loader.render_prompt(
        USER_TEMPLATE,
        case_id=case.case_id,
        source=case.source,
        under_review=case.under_review,
        sections=case.sections,
        resources=[
            {
                "ref": item.resource_id,
                "kind": item.kind,
                "amount": f"{_number(item.value)} {item.unit}",
                "applies_to": _text(item.applies_to),
            }
            for item in case.resources
        ],
        identifiers=case.identifiers,
        review_refs=case.review_refs,
        request_ids=case.request_ids,
    )
    return system, user


def render_correction_feedback(
    prior_class: str | None, loader: TemplateLoader | None = None
) -> str:
    """Return the text a correction request adds before the exact failures."""
    loader = loader or TemplateLoader(PROMPTS_DIR)
    return (
        "\n\n"
        + loader.render_prompt(CORRECTION_TEMPLATE, prior_class=prior_class).strip()
    )


# Verdict schema and validators --------------------------------------------


class AuthorizedRequest(WireModel):
    request_id: str = Field(min_length=1)
    request: str = Field(min_length=1)
    source_ref: str = Field(min_length=1)


class RequestJudgement(WireModel):
    request_id: str = Field(min_length=1)
    required: Handling
    safeguard_as_written: Handling
    safeguard_refs: list[str] = Field(default_factory=list)


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


class ResourceUse(WireModel):
    kind: ResourceKind
    resource_ref: str | None = None


class Dependency(WireModel):
    dependent_ref: str = Field(min_length=1)
    check_ref: str = Field(min_length=1)
    check: str = Field(min_length=1)


class ConflictVerdict(WireModel):
    """The model's finding for one case."""

    authorized_requests: list[AuthorizedRequest] = Field(default_factory=list)
    request_judgements: list[RequestJudgement] = Field(default_factory=list)
    finding_class: FindingClass
    requirements: list[CitedRequirement] = Field(min_length=2)
    overlapping_context: OverlappingContext
    mechanisms: list[Mechanism] = Field(min_length=1)
    causal_explanation: str = Field(min_length=1)
    resource_limits: list[ResourceUse] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    dependency: Dependency | None = None
    expected_behaviour: Literal["satisfy_all", "stop", "explain", "escalate"]


def _blank(value: str | None) -> bool:
    return value is None or not value.strip()


def own_obligation_pairs(refs: Iterable[str]) -> list[tuple[str, str]]:
    """Return each (constraint, its own obligation) pair the refs both cite."""
    cited = list(dict.fromkeys(refs))
    return [
        (ref.split("/", 1)[0], ref)
        for ref in cited
        if "/" in ref and ref.split("/", 1)[0] in cited
    ]


def _request_failures(verdict: ConflictVerdict, case: ReviewCase) -> list[str]:
    failures: list[str] = []
    listed = [item.request_id for item in verdict.authorized_requests]
    if case.request_ids:
        if listed:
            failures.append(
                "this case lists its requests; authorized_requests must be empty"
            )
        expected = list(case.request_ids)
    else:
        if not listed:
            failures.append(
                "authorized_requests is empty; list at least one request the use "
                "case authorizes, citing its UC paragraph"
            )
        for item in verdict.authorized_requests:
            if not _REQUEST_ID.match(item.request_id):
                failures.append(
                    f"authorized_requests names {item.request_id!r}; number them "
                    "AR-1, AR-2 and so on"
                )
            if item.source_ref not in case.use_case_refs:
                failures.append(
                    f"authorized request {item.request_id} cites "
                    f"{item.source_ref!r}; cite the UC paragraph that authorizes it"
                )
        if len(set(listed)) != len(listed):
            failures.append("authorized_requests repeats an identifier")
        expected = list(dict.fromkeys(listed))
    judged = [item.request_id for item in verdict.request_judgements]
    for request_id in judged:
        if request_id not in expected:
            failures.append(
                f"request_judgements names {request_id!r}, which is not a "
                + (
                    "listed request"
                    if case.request_ids
                    else "listed authorized request"
                )
            )
    lacking = [rid for rid in expected if rid not in judged]
    if lacking:
        failures.append(f"request_judgements has no judgement for {', '.join(lacking)}")
    if len(set(judged)) != len(judged):
        failures.append("request_judgements repeats a request; judge each once")
    for item in verdict.request_judgements:
        outside = [ref for ref in item.safeguard_refs if ref not in case.review_refs]
        if outside:
            failures.append(
                f"request_judgements for {item.request_id} names "
                f"{', '.join(outside)} in safeguard_refs; name only "
                + ", ".join(case.review_refs)
            )
        if item.safeguard_as_written == "allow" and item.safeguard_refs:
            failures.append(
                f"request_judgements for {item.request_id} is allowed as written "
                "but names safeguard_refs; leave them empty"
            )
        if item.safeguard_as_written != "allow" and not item.safeguard_refs:
            failures.append(
                f"request_judgements for {item.request_id} is "
                f"{item.safeguard_as_written}ed as written but names no "
                "safeguard_refs; name the safeguard that does it"
            )
    return failures


def verdict_failures(verdict: ConflictVerdict, case: ReviewCase) -> list[str]:
    """Return every rule the verdict breaks, worded for a correction request."""
    failures: list[str] = _request_failures(verdict, case)
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
    if not set(refs) & set(case.review_refs):
        failures.append(
            "requirements cite nothing under review; cite at least one of "
            + ", ".join(case.review_refs)
        )
    if not set(refs) & set(case.source_refs):
        failures.append(
            "requirements cite no "
            + (
                "requirement (R identifier)"
                if case.source == "fixture"
                else "use-case paragraph or constraint (UC- or SC- identifier)"
            )
            + "; cite at least one"
        )
    for constraint, obligation in own_obligation_pairs(refs):
        failures.append(
            f"requirements compare {constraint} with its own obligation "
            f"{obligation}; an obligation restates its constraint, so compare "
            "what is under review with the use case or another constraint instead"
        )
    for item in verdict.mechanisms:
        check_ref(item.ref, "mechanisms")
    if _blank(verdict.causal_explanation):
        failures.append("causal_explanation is empty")
    missing = [fact for fact in verdict.missing_facts if not _blank(fact)]
    kind = verdict.finding_class
    supplied = {item.resource_id: item.kind for item in case.resources}
    for use in verdict.resource_limits:
        if use.resource_ref is None:
            if kind != "missing_information":
                failures.append(
                    f"the finding turns on a {use.kind} the case does not supply as "
                    "a typed value; such a finding may only be missing_information, "
                    f"with the {use.kind} listed in missing_facts"
                )
        elif supplied.get(use.resource_ref) != use.kind:
            failures.append(
                f"resource_limits cites {use.resource_ref!r} as a {use.kind}; cite "
                "a RES identifier of that kind from Stated resources, or null"
            )
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
        dependency = verdict.dependency
        if dependency is None:
            failures.append(
                "a reinforcement finding must name the dependency: which "
                "requirement's satisfaction depends on which other requirement's "
                "check"
            )
        else:
            for ref in (dependency.dependent_ref, dependency.check_ref):
                if ref not in refs:
                    failures.append(
                        f"dependency names {ref!r}, which requirements do not cite"
                    )
            if dependency.dependent_ref == dependency.check_ref:
                failures.append(
                    "dependency names one requirement twice; a reinforcement needs "
                    "one requirement depending on another's check"
                )
    return failures


def derived_over_refusal(verdict: Mapping[str, Any]) -> dict[str, Any]:
    """Read over-refusal from the request judgements.

    A request is over-refused when the agent must not block it (it must be
    allowed or escalated) and a safeguard as written blocks it. A request the
    agent must allow that a safeguard escalates instead is deferred.
    """
    texts = {
        item["request_id"]: item for item in verdict.get("authorized_requests") or []
    }

    def row(item: Mapping[str, Any]) -> dict[str, Any]:
        listed = texts.get(item["request_id"]) or {}
        return {
            "request_id": item["request_id"],
            "required": item["required"],
            "safeguard_as_written": item["safeguard_as_written"],
            "safeguard_refs": list(item.get("safeguard_refs") or []),
            "request": listed.get("request"),
            "source_ref": listed.get("source_ref"),
        }

    judgements = verdict.get("request_judgements") or []
    blocked = [
        row(item)
        for item in judgements
        if item["required"] != "block" and item["safeguard_as_written"] == "block"
    ]
    deferred = [
        row(item)
        for item in judgements
        if item["required"] == "allow" and item["safeguard_as_written"] == "escalate"
    ]
    return {"flagged": bool(blocked), "blocked": blocked, "deferred": deferred}


class _VerdictRejectedError(ExactFeedbackError):
    """A parsed verdict that broke a rule."""


def correction_policy(
    prior_class: Callable[[], str | None],
    loader: TemplateLoader | None = None,
    on_correction: Callable[[], None] | None = None,
) -> CorrectionPolicy:
    """One correction that asks the model to decide its class again.

    The prior reply is not shown for in-place editing: the model re-derives
    the whole finding from the case, told only which class it gave and which
    rules that reply broke. *on_correction* is called each time a correction
    request is built, so a caller counts corrections apart from transport
    retries and service-tier fallbacks.
    """

    def feedback(_exc: Exception) -> str:
        if on_correction is not None:
            on_correction()
        return render_correction_feedback(prior_class(), loader)

    return CorrectionPolicy(
        validation_retries=1,
        feedback=feedback,
        include_schema=False,
        include_response=False,
    )


# Runner -------------------------------------------------------------------


@dataclass
class CaseResult:
    case_id: str
    source: str
    verdict: dict[str, Any] | None = None
    rejected: list[tuple[str, ...]] = field(default_factory=list)
    attempt_classes: list[str | None] = field(default_factory=list)
    """The finding class of each decoded reply, in order; None when absent."""
    requests: int = 0
    """Every request the call sent, transport retries included."""
    corrections: int = 0
    """Correction requests built; one the live budget refused still counts."""
    error: str | None = None
    budget_refused: bool = False

    @property
    def accepted(self) -> bool:
        return self.verdict is not None

    @property
    def correction_changed_class(self) -> bool | None:
        """Whether the corrected reply's class differs from the first reply's.

        None when no correction was sent or a class is unknown.
        """
        if not self.corrections or len(self.attempt_classes) < 2:
            return None
        first, last = self.attempt_classes[0], self.attempt_classes[-1]
        if first is None or last is None:
            return None
        return first != last


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

    def note_class(raw: Any) -> None:
        value = raw.get("finding_class") if isinstance(raw, dict) else None
        result.attempt_classes.append(value if isinstance(value, str) else None)

    def count_correction() -> None:
        result.corrections += 1

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
        policy=correction_policy(
            lambda: result.attempt_classes[-1] if result.attempt_classes else None,
            loader,
            on_correction=count_correction,
        ),
        scenario_id=case.case_id,
        temperature=effective_temperature(llm_client),
        raw_result_validator=note_class,
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
            "mode": case.mode,
            "accepted": result.accepted,
            "verdict": result.verdict,
            "over_refusal": (
                derived_over_refusal(result.verdict) if result.verdict else None
            ),
            "rejected": [list(items) for items in result.rejected],
            "attempt_classes": result.attempt_classes,
            "correction_changed_class": result.correction_changed_class,
            "requests": result.requests,
            "corrections": result.corrections,
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
    verdict = result.verdict
    labels = case.labels
    refs = [item["ref"] for item in (verdict or {}).get("requirements", [])]
    refusal = derived_over_refusal(verdict) if verdict else None
    row: dict[str, Any] = {
        "case_id": case.case_id,
        "source": case.source,
        "mode": case.mode,
        "accepted": result.accepted,
        "requests": result.requests,
        "corrections": result.corrections,
        "attempt_classes": list(result.attempt_classes),
        "correction_changed_class": result.correction_changed_class,
        "class": verdict["finding_class"] if verdict else None,
        "cites_under_review": (
            bool(set(refs) & set(case.review_refs)) if verdict else None
        ),
        "own_obligation_pairs": len(own_obligation_pairs(refs)) if verdict else None,
        "missing_facts": (
            sum(1 for fact in verdict["missing_facts"] if not _blank(fact))
            if verdict
            else None
        ),
        "resource_limits": (
            [item["kind"] for item in verdict["resource_limits"]] if verdict else None
        ),
        "authorized_requests": (
            len(verdict["authorized_requests"]) if verdict else None
        ),
        "over_refusal": refusal["flagged"] if refusal else None,
        "over_refused": (
            [item["request_id"] for item in refusal["blocked"]] if refusal else None
        ),
        "deferred": (
            [item["request_id"] for item in refusal["deferred"]] if refusal else None
        ),
    }
    if case.source == "fixture":
        expected = labels["expected_class"]
        row["expected_class"] = expected
        row["class_correct"] = (
            None
            if verdict is None
            else row["class"] in (expected, *labels["acceptable_classes"])
        )
        row["expected_over_refusal"] = labels["expected_over_refusal"]
        row["over_refusal_correct"] = (
            None
            if refusal is None
            else refusal["flagged"] == labels["expected_over_refusal"]
        )
        judgements = {
            item["request_id"]: item
            for item in (verdict or {}).get("request_judgements", [])
        }
        requests = {}
        # ``allow`` is correct only as allow; ``block`` and ``escalate`` are
        # correct as block or escalate, the ways an agent stops a request.
        for request_id, wanted in labels["expected_requests"].items():
            judgement = judgements.get(request_id)
            got = judgement["required"] if judgement else None
            requests[request_id] = {
                "expected": wanted,
                "required": got,
                "safeguard_as_written": (
                    judgement["safeguard_as_written"] if judgement else None
                ),
                "correct": (
                    None if got is None else (got == "allow") == (wanted == "allow")
                ),
            }
        row["requests_judged"] = requests
    else:
        label = labels.get("label")
        row["run"] = labels.get("run")
        row["hand_label"] = label
        row["expected_over_refusal"] = labels.get("expected_over_refusal")
        row["class_correct"] = (
            None if verdict is None or label is None else row["class"] == label
        )
        row["class_acceptable"] = (
            None
            if verdict is None or label is None
            else row["class"] in (label, *labels.get("acceptable", []))
        )
    return row


def summary_metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate the scored rows into the measures the pilot reports."""
    accepted = [row for row in rows if row["accepted"]]
    corrected = [row for row in rows if row["corrections"]]
    metrics: dict[str, Any] = {
        "accepted": len(accepted),
        "classes": dict(sorted(Counter(row["class"] for row in accepted).items())),
        "reinforcement": sum(1 for row in accepted if row["class"] == "reinforcement"),
        "cite_nothing_under_review": sum(
            1 for row in accepted if not row["cites_under_review"]
        ),
        "own_obligation_pairs": sum(
            1 for row in accepted if row["own_obligation_pairs"]
        ),
        "missing_facts_listed": sum(1 for row in accepted if row["missing_facts"]),
        "resource_limits_named": sum(1 for row in accepted if row["resource_limits"]),
        "over_refusal_flagged": [
            row["case_id"] for row in accepted if row["over_refusal"]
        ],
        "deferred": [row["case_id"] for row in accepted if row["deferred"]],
        "corrections": sum(row["corrections"] for row in rows),
        "cases_corrected": len(corrected),
        "corrections_changed_class": sum(
            1 for row in corrected if row["correction_changed_class"] is True
        ),
        "corrections_kept_class": sum(
            1 for row in corrected if row["correction_changed_class"] is False
        ),
    }
    fixtures = [row for row in accepted if row["source"] == "fixture"]
    if fixtures:
        judged = [
            item
            for row in fixtures
            for item in row["requests_judged"].values()
            if item["correct"] is not None
        ]
        metrics["fixtures"] = {
            "class_correct": sum(1 for row in fixtures if row["class_correct"]),
            "requests_correct": sum(1 for item in judged if item["correct"]),
            "requests_judged": len(judged),
            "over_refusal_correct": sum(
                1 for row in fixtures if row["over_refusal_correct"]
            ),
            "of": len(fixtures),
        }
    recorded = [row for row in accepted if row["source"] == "recorded"]
    if recorded:
        labelled = [row for row in recorded if row["hand_label"] is not None]
        by_run: dict[str, list[str]] = {}
        for row in recorded:
            if row["over_refusal"]:
                by_run.setdefault(str(row["run"]), []).append(row["case_id"])
        expected = {
            kind: [
                row["case_id"]
                for row in recorded
                if row.get("expected_over_refusal") == kind
            ]
            for kind in ("clear", "contingent")
        }
        metrics["recorded"] = {
            "exact": sum(1 for row in labelled if row["class_correct"]),
            "acceptable": sum(1 for row in labelled if row["class_acceptable"]),
            "labelled": len(labelled),
            "over_refusal_by_run": dict(sorted(by_run.items())),
            "over_refusal_expected": expected,
            "over_refusal_found": {
                kind: [cid for cid in ids if cid in metrics["over_refusal_flagged"]]
                for kind, ids in expected.items()
            },
        }
    return metrics


def provider_spend(record_dir: Path) -> dict[str, Any]:
    """Count the provider records by source, transport retries and errors.

    These are raw record counts. A transport retry keeps its request's
    attempt number, so corrections are not read from the records here;
    ``summarize`` takes them from the counted correction attempts.
    """
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
        "schema_version": "conflict-review-pilot-summary-v2",
        "profile": profile,
        "controls": list(controls),
        "cases_listed": len(cases),
        "cases_run": len(results),
        "cases_not_run": [case.case_id for case in cases[len(results) :]],
        "accepted": sum(1 for result in results if result.accepted),
        "stop_reason": stop_reason,
        "budget_error": budget_error,
        "fill_summary": dict(fill) if fill else None,
        "spend": {
            **spend,
            "corrections": sum(result.corrections for result in results),
        },
        "metrics": summary_metrics(rows),
        "confusion": [
            {"label": label, "model": model, "count": count}
            for (label, model), count in sorted(confusion.items())
        ],
        "rows": rows,
    }


def summary_markdown(summary: Mapping[str, Any]) -> str:
    metrics = summary["metrics"]
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
        f"- Classes: {metrics['classes']}",
        f"- Cases corrected: {metrics['cases_corrected']}; the correction changed "
        f"the class in {metrics['corrections_changed_class']}",
        f"- Over-refusal flagged: {', '.join(metrics['over_refusal_flagged']) or 'none'}"
        f"; deferred: {', '.join(metrics['deferred']) or 'none'}",
        "",
        "| Case | Mode | Label | Model class | Correct | Over-refused | Requests "
        "| Attempt classes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in summary["rows"]:
        label = row.get("expected_class") or row.get("hand_label") or ""
        lines.append(
            f"| {row['case_id']} | {row['mode']} | {label} | {row['class']} "
            f"| {row['class_correct']} | {', '.join(row['over_refused'] or []) or '-'} "
            f"| {row['requests']} | {' > '.join(map(str, row['attempt_classes']))} |"
        )
    fixture_rows = [row for row in summary["rows"] if "requests_judged" in row]
    if fixture_rows:
        lines += [
            "",
            "| Fixture | Request | Expected | Required | Safeguard as written | Correct |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for row in fixture_rows:
            for request_id, item in row["requests_judged"].items():
                lines.append(
                    f"| {row['case_id']} | {request_id} | {item['expected']} "
                    f"| {item['required']} | {item['safeguard_as_written']} "
                    f"| {item['correct']} |"
                )
    return "\n".join(lines) + "\n"


# Scoring against label references -----------------------------------------


def _over_refusal_label(value: Any) -> str | None:
    """Normalize a reference's over-refusal label to clear, contingent or None.

    ``yes`` and ``no`` load from YAML as booleans.
    """
    if value is True or value in ("clear", "yes"):
        return "clear"
    if value == "contingent":
        return "contingent"
    return None


def load_label_reference(path: Path) -> dict[str, dict[str, Any]]:
    """Read a label file shaped ``cases: [{case_id, label, acceptable, ...}]``."""
    return {
        str(item["case_id"]): {
            "label": item.get("label"),
            "acceptable": list(item.get("acceptable") or []),
            "over_refusal": _over_refusal_label(item.get("over_refusal")),
        }
        for item in _yaml(path)["cases"]
    }


def load_verdict_records(directories: Sequence[Path]) -> list[dict[str, Any]]:
    """Read the accepted recorded verdicts of earlier ``run`` outputs."""
    records = []
    for directory in directories:
        for path in sorted((directory / "verdicts").glob("*.json")):
            record = json.loads(path.read_text(encoding="utf-8"))
            if record.get("source") == "recorded" and record.get("verdict"):
                records.append(record)
    ids = [record["case_id"] for record in records]
    repeated = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if repeated:
        raise SystemExit(f"case ids repeat across verdict directories: {repeated}")
    return records


def score_references(
    records: Sequence[Mapping[str, Any]],
    references: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> dict[str, Any]:
    """Score recorded verdicts against each label reference, and on the cases
    where every reference gives the same label.

    Over-refusal is the derived flag: a case is flagged when a safeguard as
    written blocks a request the agent must not block.
    """
    model = {
        record["case_id"]: {
            "class": record["verdict"]["finding_class"],
            "flagged": derived_over_refusal(record["verdict"])["flagged"],
        }
        for record in records
    }

    def compare(labels: Mapping[str, Mapping[str, Any]], ids: Iterable[str]) -> dict:
        scored = [
            cid
            for cid in ids
            if cid in model and cid in labels and labels[cid]["label"]
        ]
        return {
            "cases": len(scored),
            "exact": sum(
                1 for cid in scored if model[cid]["class"] == labels[cid]["label"]
            ),
            "acceptable": sum(
                1
                for cid in scored
                if model[cid]["class"]
                in (labels[cid]["label"], *labels[cid]["acceptable"])
            ),
        }

    def refusal(expected: Mapping[str, str | None]) -> dict[str, Any]:
        flagged = {cid for cid, row in model.items() if row["flagged"]}
        clear = sorted(cid for cid, kind in expected.items() if kind == "clear")
        contingent = sorted(
            cid for cid, kind in expected.items() if kind == "contingent"
        )
        return {
            "expected_clear": clear,
            "expected_contingent": contingent,
            "found_clear": [cid for cid in clear if cid in flagged],
            "found_contingent": [cid for cid in contingent if cid in flagged],
            "flagged_unexpected": sorted(
                cid for cid in flagged if cid in expected and expected[cid] is None
            ),
        }

    names = list(references)
    common = sorted(
        set(model).intersection(*(set(labels) for labels in references.values()))
    )
    agreed = [
        cid
        for cid in common
        if len({references[name][cid]["label"] for name in names}) == 1
        and references[names[0]][cid]["label"]
    ]
    shared_clear = {
        cid: (
            "clear"
            if all(references[name][cid]["over_refusal"] == "clear" for name in names)
            else None
        )
        for cid in common
    }
    return {
        "references": names,
        "flagged": sorted(cid for cid, row in model.items() if row["flagged"]),
        "verdicts": len(model),
        "by_reference": {
            name: {
                "covers": sum(1 for cid in model if cid in labels),
                "class": compare(labels, sorted(model)),
                "over_refusal": refusal(
                    {cid: labels[cid]["over_refusal"] for cid in model if cid in labels}
                ),
            }
            for name, labels in references.items()
        },
        "agreed": {
            "case_ids": agreed,
            "class": {name: compare(references[name], agreed) for name in names},
            "over_refusal": refusal(shared_clear) if len(names) > 1 else None,
        },
        "rows": [
            {
                "case_id": cid,
                "class": model[cid]["class"],
                "flagged": model[cid]["flagged"],
                **{
                    name: (references[name].get(cid) or {}).get("label")
                    for name in names
                },
            }
            for cid in sorted(model)
        ],
    }


def score_markdown(score: Mapping[str, Any]) -> str:
    names = score["references"]
    lines = [
        "# Conflict review scores",
        "",
        "| Reference | Covers | Labelled | Exact | Acceptable "
        "| Clear over-refusals found | Contingent found | Flagged, not expected |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name in names:
        part = score["by_reference"][name]
        refusal = part["over_refusal"]
        lines.append(
            f"| {name} | {part['covers']} of {score['verdicts']} "
            f"| {part['class']['cases']} | {part['class']['exact']} "
            f"| {part['class']['acceptable']} "
            f"| {len(refusal['found_clear'])}/{len(refusal['expected_clear'])} "
            f"{refusal['found_clear']} "
            f"| {len(refusal['found_contingent'])}/{len(refusal['expected_contingent'])} "
            f"| {refusal['flagged_unexpected']} |"
        )
    agreed = score["agreed"]
    lines += ["", f"Cases where every reference agrees: {agreed['case_ids']}", ""]
    for name in names:
        part = agreed["class"][name]
        lines.append(
            f"- {name}: exact {part['exact']}/{part['cases']}, "
            f"acceptable {part['acceptable']}/{part['cases']}"
        )
    if agreed["over_refusal"]:
        refusal = agreed["over_refusal"]
        lines.append(
            f"- over-refusals every reference calls clear: "
            f"{refusal['found_clear']} of {refusal['expected_clear']}"
        )
    lines += [
        "",
        f"Flagged by the model: {score['flagged']}",
        "",
        "| Case | Model class | Flagged | " + " | ".join(names) + " |",
        "| --- | --- | --- | " + " | ".join("---" for _ in names) + " |",
    ]
    lines += [
        f"| {row['case_id']} | {row['class']} | {row['flagged']} | "
        + " | ".join(str(row[name]) for name in names)
        + " |"
        for row in score["rows"]
    ]
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
    labelled = list(zip(run_labels(runs), runs))
    pairs_by_run = {str(run.run_dir.resolve()): candidate_pairs(run) for run in runs}
    singles_by_run = {str(run.run_dir.resolve()): run.non_duplicates() for run in runs}
    hand = list(_yaml(args.hand_manifest)["cases"]) if args.hand_manifest else []
    with (out_dir / "candidate-pairs.jsonl").open("w", encoding="utf-8") as handle:
        for label, run in labelled:
            for pair in pairs_by_run[str(run.run_dir.resolve())]:
                row = {
                    "run": label,
                    "pair": [pair.first, pair.second],
                    "shared": {k: list(v) for k, v in pair.shared.items()},
                    "in_union": pair.in_union,
                }
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    _write_json(
        out_dir / "candidate-groups.json",
        {label: candidate_groups(run) for label, run in labelled},
    )
    counts: dict[str, Any] = {
        "runs": {
            label: {
                "run_dir": str(run.run_dir.resolve()),
                "non_duplicate_scenarios": len(run.non_duplicates()),
                "with_process_model_context": sum(
                    1
                    for sid in run.non_duplicates()
                    if _context(run, run.scenarios[sid])
                ),
                "single_pass_cases": len(run.non_duplicates()),
                "pairs": pair_counts(pairs_by_run[str(run.run_dir.resolve())]),
                "groups": {
                    name: len(elements)
                    for name, elements in candidate_groups(run).items()
                },
            }
            for label, run in labelled
        },
    }
    if hand:
        counts["hand_coverage"] = hand_coverage(hand, pairs_by_run, singles_by_run)
    _write_json(out_dir / "selector-counts.json", counts)
    (out_dir / "selector-summary.md").write_text(
        _selector_markdown(counts), encoding="utf-8"
    )
    (out_dir / "single-manifest.yaml").write_text(
        yaml.safe_dump(
            {"cases": single_pass_cases(runs)}, sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )
    if args.sample_size:
        sample = sample_unselected(pairs_by_run, hand, args.sample_size, args.seed)
        (out_dir / "sample-manifest.yaml").write_text(
            yaml.safe_dump({"cases": sample}, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
    print(f"wrote selector outputs to {out_dir}")


def _selector_markdown(counts: Mapping[str, Any]) -> str:
    names = (*PAIR_KEYS, "union", *CONTEXT_KEYS, "constraint_only", *COMPARISON_KEYS)
    lines = [
        "# Candidate selector",
        "",
        "Pair keys: "
        + ", ".join(PAIR_KEYS)
        + ". Context only: "
        + ", ".join(CONTEXT_KEYS)
        + ". Comparison only: "
        + ", ".join(COMPARISON_KEYS)
        + ".",
        "",
        "| Run | Non-duplicates | With context | Single pass | "
        + " | ".join(names)
        + " |",
        "| --- | --- | --- | --- | " + " | ".join("---" for _ in names) + " |",
    ]
    for label, run in counts["runs"].items():
        lines.append(
            f"| {label} | {run['non_duplicate_scenarios']} "
            f"| {run['with_process_model_context']} | {run['single_pass_cases']} | "
            + " | ".join(str(run["pairs"][name]) for name in names)
            + " |"
        )
    coverage = counts.get("hand_coverage")
    if coverage:
        covered_names = (
            *PAIR_KEYS,
            "union",
            "single_pass",
            "union_or_single",
            *CONTEXT_KEYS,
            *COMPARISON_KEYS,
        )
        lines += [
            "",
            f"Hand candidates: {coverage['candidates']} "
            f"({coverage['pairable']} with two or more scenarios).",
            "",
            "| Key | Hand candidates covered |",
            "| --- | --- |",
        ]
        lines += [f"| {name} | {coverage['covered'][name]} |" for name in covered_names]
        lines += ["", "| Candidate | Covered by |", "| --- | --- |"]
        for row in coverage["rows"]:
            if row["pairable"]:
                covered = ", ".join(row["covered_by"]) or "-"
            else:
                covered = "single pass" if row["single_pass"] else "unpairable"
            lines.append(f"| {row['case_id']} | {covered} |")
    return "\n".join(lines) + "\n"


def _render(args: argparse.Namespace) -> None:
    (case,) = load_cases(
        args.fixtures, args.manifest, [args.case], load_resources(args.resources)
    )
    system, user = render_review_prompts(case)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / f"{case.case_id}.system.txt").write_text(system, encoding="utf-8")
    (args.out_dir / f"{case.case_id}.user.txt").write_text(user, encoding="utf-8")
    print(f"wrote {case.case_id} prompts to {args.out_dir}")


def _run(args: argparse.Namespace) -> None:
    from asago_scenario_generator.stpa.pipeline.llm_config import (
        resolve_llm_client_from_profile,
    )

    cases = load_cases(
        args.fixtures, args.manifest, args.case or (), load_resources(args.resources)
    )

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


def _score(args: argparse.Namespace) -> None:
    references = {}
    for spec in args.labels:
        name, sep, path = spec.partition("=")
        if not sep or not name or not path:
            raise SystemExit(f"--labels takes NAME=FILE, not {spec!r}")
        if name in references:
            raise SystemExit(f"label reference {name!r} repeats")
        references[name] = load_label_reference(Path(path))
    score = score_references(load_verdict_records(args.verdicts), references)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    _write_json(args.out_dir / "score.json", score)
    (args.out_dir / "score.md").write_text(score_markdown(score), encoding="utf-8")
    print(f"wrote scores to {args.out_dir}")


def _case_sources(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--resources", type=Path)


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

    score = commands.add_parser(
        "score", help="score recorded verdicts against label references"
    )
    score.add_argument("--verdicts", type=Path, action="append", required=True)
    score.add_argument("--labels", action="append", required=True)
    score.add_argument("--out-dir", type=Path, required=True)
    score.set_defaults(handler=_score)

    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command in ("render", "run") and not (args.fixtures or args.manifest):
        parser.error("give --fixtures or --manifest")
    args.handler(args)


if __name__ == "__main__":
    main()

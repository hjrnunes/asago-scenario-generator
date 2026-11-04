"""The Stage 1a revision runner: requests, corrections and their evidence.

This module owns the three calls that revise the loss-analysis graph:

- :func:`_run_density_revision`, the bounded density rounds;
- :func:`_run_stated_rule_revision`, the non-fatal stated-rule round;
- :func:`_run_graph_revision_call`, the one request each round makes.

A call receives a model client, a graph and the checks to report, and returns
a validated graph or raises :class:`StageError`.  The outcomes are the values
of :mod:`asago_scenario_generator.stpa.system_model.loss_analysis_gate_decisions`;
the artifact and the repair records are written by
:mod:`asago_scenario_generator.stpa.system_model.loss_analysis_gate_publication`.
The module imports the public revision request models from
:mod:`asago_scenario_generator.stpa.system_model.loss_analysis`, never a
private provider-model name.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from pydantic_core import ErrorDetails, InitErrorDetails

from asago_scenario_generator.stpa.infra.canonical_ids import allocate_canonical_ids
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    StageError,
    call_with_policy,
    count_requests,
    decode_content,
    parse_llm_result,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import (
    BehaviorClass,
    Hazard,
    LossAnalysis,
    LossAnalysisDraft,
    SecurityConstraint,
    stamp_proposed_direction,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    STAGE1A_MAX_COMPLETION_TOKENS,
    STAGE,
    ProviderObligation,
    RevisionConstraintAddition,
    RevisionConstraintEdit,
    RevisionHazardAddition,
    RevisionHazardEdit,
    Stage1aRevisionPatch,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_acceptance import (
    _trim_failed_class_ownership,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_checks import (
    HazardGraphDensityReport,
    RiskAccountingReport,
    check_hazard_graph_density,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_decisions import (
    Accept,
    Correct,
    KeepPrior,
    Revise,
    Stop,
    decide_correction,
    decide_density_round,
    decide_revision_call,
    decide_stated_rule_round,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_publication import (
    STEP_GRAPH_REVISION,
    revision_round_record,
    write_gates_artifact,
    write_revision_span_repairs,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    RepairRecord,
)
from asago_scenario_generator.stpa.system_model.rule_span_repair import (
    RuleSpanRepairRecord,
    repair_obligation_models,
    repair_rule_span,
    rule_span_requirement,
    span_quotes_rule,
)
from asago_scenario_generator.stpa.system_model.stated_rule_coverage import (
    StatedRuleFinding,
    StatedRuleRevision,
    normalized_text,
)

REVISION_VALIDATION_RETRIES = 1
# What a failed graph-revision reply may correct when it earns the request.
REVISION_CORRECTION_SCOPE = "the graph revision reply"
# A valid revision that still fails a structural check gets one further round
# on the revised graph; the gate stays fail-closed after the last round.
GRAPH_REVISION_ROUNDS = 2
_ROUND_FAILURE_PREFIX = {
    1: "revision still failing",
    2: "second revision still failing",
}
# Revised graph -> reason to reject the stated-rule revision, or None.
StatedRuleCheck = Callable[[LossAnalysis], "str | None"]
REVISION_CORRECTION_FEEDBACK = (
    "\n\nCorrection request: the prior graph revision response failed "
    "validation. Return the complete corrected revision patch: fix the exact "
    "error reported below and keep every other edit and addition unchanged. "
    + rule_span_requirement()
)
REVISION_UNDECODABLE_TEMPLATE = "stage1a_graph_revision_undecodable_correction.j2"
REVISION_BLANK_HAZARD_TEMPLATE = "stage1a_graph_revision_blank_hazard_error.j2"


@dataclass
class _RevisionAttempt:
    """Evidence from one parsed graph-revision response."""

    warnings: list[str] = field(default_factory=list)
    span_repairs: list[RuleSpanRepairRecord] = field(default_factory=list)
    failed: bool = False
    # The response never decoded as JSON, so no patch was read from it.
    undecodable: bool = False
    # Why an addition-only revision rejected this response outright.  A
    # rejection is final: it gets no correction call.
    rejection: str | None = None
    # The parsed patch, kept so a final attempt that failed on rule_span
    # slips can be rebuilt without the slipping records.
    patch: Stage1aRevisionPatch | None = None
    # Records this attempt left out of its patch, each with its error.
    dropped: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class _GateInputs:
    """Inputs that stay fixed across every revision round of one gate run."""

    llm_client: LLMClient
    use_case_text: str
    run_dir: Path
    template_loader: TemplateLoader
    temperature: float
    accounting: RiskAccountingReport
    accounting_normalization_warnings: list[str] | None
    repair_record: RepairRecord | None


@dataclass
class _GateProgress:
    """Gate state that the density and stated-rule revisions advance."""

    loss_analysis: LossAnalysis
    final_density: HazardGraphDensityReport
    failing: list[str]
    revision_attempted: bool = False
    revision_applied: bool = False
    revision_call_count: int = 0
    rounds: list[dict] = field(default_factory=list)
    revision_warnings: list[str] = field(default_factory=list)


def _unknown_edit_targets(prior: LossAnalysis, decoded: object) -> str | None:
    """Name the edit targets of a decoded patch that the graph does not have.

    Runs before schema validation, so a non-canonical target such as
    ``SC-4_updated`` rejects an addition-only revision instead of earning a
    correction call.
    """
    if not isinstance(decoded, dict):
        return None
    known = {
        "hazard_edits": ("hazard_id", {h.hazard_id for h in prior.hazards}),
        "security_constraint_edits": (
            "constraint_id",
            {c.constraint_id for c in prior.security_constraints},
        ),
    }
    unknown: list[str] = []
    for collection, (key, ids) in known.items():
        records = decoded.get(collection)
        if not isinstance(records, list):
            continue
        unknown.extend(
            repr(record.get(key))
            for record in records
            if isinstance(record, dict) and record.get(key) not in ids
        )
    if not unknown:
        return None
    return "the revision edits ID(s) the graph does not have: " + ", ".join(unknown)


def _extends_rule(prior_rule: str, rule: str) -> bool:
    """Whether ``rule`` still contains ``prior_rule`` after normalization.

    The prior rule's closing punctuation may move when a clause is appended.
    """
    original = normalized_text(prior_rule).rstrip(".;:!")
    return original in normalized_text(rule)


# The revision request displays conditions under a count heading and with
# numbers; providers sometimes echo either into the condition text.
_ECHOED_CONDITION_PREFIX = re.compile(
    r"^(?:(?:>=|≥|at least)?\s*\d+\s+conditions?\s*:\s*|\d+[.)]\s+)",
    re.IGNORECASE,
)


def _echo_normalized_condition(condition: str) -> str:
    """A condition with an echoed count heading or number and extra spaces removed."""
    collapsed = " ".join(condition.split())
    return _ECHOED_CONDITION_PREFIX.sub("", collapsed, count=1)


def _same_conditions(prior: list[str], echoed: list[str]) -> bool:
    return [_echo_normalized_condition(c) for c in echoed] == [
        " ".join(c.split()) for c in prior
    ]


def _extended_obligations(prior: list[dict], echoed: list[dict]) -> list[dict] | None:
    """Prior obligations followed by the added ones, or ``None`` on a change.

    Every prior obligation must be echoed unchanged; an entry whose ID is not
    a prior ID is an addition.
    """
    prior_ids = {item["obligation_id"] for item in prior}
    if any(item not in echoed for item in prior):
        return None
    added = [item for item in echoed if item not in prior]
    if any(item["obligation_id"] in prior_ids for item in added):
        return None
    return [*prior, *added]


def _changed_hazard_problems(
    hazards: dict[str, Hazard], edits: list[RevisionHazardEdit]
) -> list[str]:
    return [
        f"it changes hazard {edit.hazard_id}"
        for edit in edits
        if (
            edit.description != hazards[edit.hazard_id].description
            or edit.related_losses != hazards[edit.hazard_id].related_losses
        )
    ]


def _addition_only_patch(
    prior: LossAnalysis, patch: Stage1aRevisionPatch
) -> tuple[Stage1aRevisionPatch, str | None, tuple[str, ...]]:
    """Restrict a stated-rule revision to additions and rule extensions.

    An edit may extend an existing constraint's ``rule`` so it still
    contains the prior text and every prior obligation ``rule_span`` (read
    as the constraint validator reads it, ignoring case).  Its hazards must
    stay unchanged; its conditions must equal the prior ones once an echoed
    count heading, number, and extra whitespace are removed; its obligations,
    when returned, must repeat every prior obligation unchanged and may only
    add entries with new IDs.
    An edit of an existing hazard must repeat it unchanged.

    An edit that breaks one of these rules is dropped whole, with one note
    per broken rule, and the additions and the edits that hold stay.  Returns
    the patch with unchanged and dropped edits removed and, on extended
    rules, the prior conditions and the prior obligations plus any additions;
    the rejection reason when nothing is left to apply; and the notes of the
    dropped edits.
    """
    hazards = {hazard.hazard_id: hazard for hazard in prior.hazards}
    constraints = {c.constraint_id: c for c in prior.security_constraints}
    dropped = _changed_hazard_problems(hazards, patch.hazard_edits)
    kept_edits: list[RevisionConstraintEdit] = []
    for edit in patch.security_constraint_edits:
        edit_problems: list[str] = []
        kept = _addition_only_constraint_edit(
            constraints[edit.constraint_id], edit, edit_problems
        )
        dropped.extend(edit_problems)
        if kept is not None and not edit_problems:
            kept_edits.append(kept)
    if (
        dropped
        and not kept_edits
        and not patch.hazard_additions
        and not patch.security_constraint_additions
    ):
        return (
            patch,
            "the stated-rule revision may only add: " + "; ".join(dropped),
            (),
        )
    additions = [
        addition.model_copy(
            update={
                "applies_when": [
                    _echo_normalized_condition(c) for c in addition.applies_when
                ]
            }
        )
        for addition in patch.security_constraint_additions
    ]
    return (
        patch.model_copy(
            update={
                "hazard_edits": [],
                "security_constraint_edits": kept_edits,
                "security_constraint_additions": additions,
            }
        ),
        None,
        tuple(dropped),
    )


def _addition_only_constraint_edit(
    constraint: SecurityConstraint,
    edit: RevisionConstraintEdit,
    problems: list[str],
) -> RevisionConstraintEdit | None:
    """Check one constraint edit is an extension; return the edit to keep.

    Appends each violation to *problems*.  Returns ``None`` when the rule is
    rewritten or when the edit changes neither the rule nor the obligations.
    """
    cid = edit.constraint_id
    if not _extends_rule(constraint.rule, edit.rule):
        problems.append(f"it rewrites the rule of {cid} instead of extending it")
        return None
    if not _same_conditions(constraint.applies_when, edit.applies_when):
        problems.append(f"it changes the applies_when conditions of {cid}")
    if edit.related_hazards != constraint.related_hazards:
        problems.append(f"it changes the related_hazards of {cid}")
    prior_obligations = [
        obligation.model_dump(mode="json") for obligation in constraint.obligations
    ]
    obligations = _addition_only_obligations(cid, prior_obligations, edit, problems)
    problems.extend(
        f"obligation {cid}/{obligation.obligation_id} rule_span no longer "
        f"meets the rule_span requirement in the extended rule. "
        f"{rule_span_requirement()}"
        for obligation in constraint.obligations
        if not span_quotes_rule(edit.rule, obligation.rule_span)
    )
    if edit.rule == constraint.rule and obligations == prior_obligations:
        return None
    return edit.model_copy(
        update={
            "applies_when": list(constraint.applies_when),
            "obligations": [
                ProviderObligation.model_validate(item) for item in obligations
            ],
        }
    )


def _addition_only_obligations(
    cid: str,
    prior_obligations: list[dict],
    edit: RevisionConstraintEdit,
    problems: list[str],
) -> list[dict]:
    """Return the prior obligations plus any additions the edit returns."""
    if edit.obligations is None:
        return prior_obligations
    extended = _extended_obligations(
        prior_obligations,
        [obligation.model_dump(mode="json") for obligation in edit.obligations],
    )
    if extended is None:
        problems.append(f"it changes the obligations of {cid}")
        return prior_obligations
    return extended


def _revised_analysis(prior: LossAnalysis, revised: LossAnalysisDraft) -> LossAnalysis:
    """Restamp and validate the assembled revision into final graph shape."""
    # A revision is a derived graph, even when an untouched prior constraint
    # carried reviewed stamps.  The reviewed authority belongs only to an
    # explicitly pinned graph; deterministic revision compilation clears those
    # stamps and marks entries with proposed authority.
    stamp_proposed_direction(revised)
    return LossAnalysis.model_validate(
        {
            "risk_card_losses": revised.risk_card_losses,
            "use_case_losses": revised.use_case_losses,
            "hazards": revised.hazards,
            "security_constraints": revised.security_constraints,
            "risk_dispositions": prior.risk_dispositions,
        }
    )


def _revision_patch_to_draft(
    prior: LossAnalysis,
    patch: Stage1aRevisionPatch,
    warnings_out: list[str],
    span_repairs_out: list[RuleSpanRepairRecord] | None = None,
) -> LossAnalysisDraft:
    """Assemble an explicit graph delta over an immutable prior graph.

    The provider returns only edited records and additions.  Existing records
    omitted from the patch are copied byte-for-byte; additions receive
    canonical IDs from sorted request-local handles.  All references are
    resolved against the prior graph plus additions before the ordinary domain
    validators run.  Obligation ``rule_span`` values that map unambiguously
    to verbatim rule text are repaired first and reported in
    ``span_repairs_out``.
    """
    prior_hazards = {hazard.hazard_id: hazard for hazard in prior.hazards}
    prior_constraints = {
        constraint.constraint_id: constraint
        for constraint in prior.security_constraints
    }
    _check_revision_edit_targets(patch, prior_hazards, prior_constraints)

    hazard_additions = _unique_revision_handles(
        patch.hazard_additions,
        label="hazard addition",
    )
    constraint_additions = _unique_revision_handles(
        patch.security_constraint_additions,
        label="security constraint addition",
    )

    assembled_hazards, hazard_handle_map = _assemble_revision_hazards(
        prior, patch, hazard_additions, warnings_out
    )

    constraint_handle_map = _allocate_revision_handles(
        constraint_additions,
        existing_ids=set(prior_constraints),
        kind="constraint",
    )
    existing_hazard_ids = set(prior_hazards)
    assembled_constraints = {
        constraint_id: constraint.model_copy(deep=True)
        for constraint_id, constraint in prior_constraints.items()
    }
    failures: list[tuple[tuple[str, str], ValidationError]] = []
    for edit in patch.security_constraint_edits:
        with _collecting(failures, ("security_constraint_edits", edit.constraint_id)):
            assembled_constraints[edit.constraint_id] = _edited_constraint(
                prior_constraints[edit.constraint_id],
                edit,
                existing_hazard_ids=existing_hazard_ids,
                hazard_handle_map=hazard_handle_map,
                warnings_out=warnings_out,
                span_repairs_out=span_repairs_out,
            )
    for addition in patch.security_constraint_additions:
        with _collecting(failures, ("security_constraint_additions", addition.handle)):
            assembled_constraints[constraint_handle_map[addition.handle]] = (
                _build_constraint(
                    constraint_id=constraint_handle_map[addition.handle],
                    rule=addition.rule,
                    applies_when=addition.applies_when,
                    behavior_class=addition.behavior_class,
                    related_hazards=addition.related_hazards,
                    obligations=addition.obligations,
                    existing_hazard_ids=existing_hazard_ids,
                    hazard_handle_map=hazard_handle_map,
                    span_repairs_out=span_repairs_out,
                    addition_handle=addition.handle,
                )
            )
    _raise_collected(failures)

    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                loss.model_copy(deep=True) for loss in prior.risk_card_losses
            ],
            "use_case_losses": [
                loss.model_copy(deep=True) for loss in prior.use_case_losses
            ],
            "hazards": list(assembled_hazards.values()),
            "security_constraints": list(assembled_constraints.values()),
            "risk_dispositions": [
                disposition.model_copy(deep=True)
                for disposition in prior.risk_dispositions
            ],
        }
    )


@contextmanager
def _collecting(
    failures: list[tuple[tuple[str, str], ValidationError]], loc: tuple[str, str]
) -> Iterator[None]:
    """Collect a record's validation error, with its *loc*, so later records run.

    A reference ``ValueError`` still raises at once.
    """
    try:
        yield
    except ValidationError as exc:
        failures.append((loc, exc))


def _raise_collected(failures: list[tuple[tuple[str, str], ValidationError]]) -> None:
    """Raise one error naming every collected record failure.

    A single failure raises unchanged, so its feedback keeps its wording.  In
    the combined error, a line without a location gets its record's.
    """
    if not failures:
        return
    if len(failures) == 1:
        raise failures[0][1]
    raise ValidationError.from_exception_data(
        failures[0][1].title,
        [
            _line_error(error, loc)
            for loc, failure in failures
            for error in failure.errors()
        ],
    )


def _line_error(error: ErrorDetails, loc: tuple[str, str]) -> InitErrorDetails:
    line: InitErrorDetails = {
        "type": error["type"],
        "loc": error["loc"] or loc,
        "input": error.get("input"),
    }
    if "ctx" in error:
        line["ctx"] = error["ctx"]
    return line


def _edited_constraint(
    prior_constraint: SecurityConstraint,
    edit: RevisionConstraintEdit,
    *,
    existing_hazard_ids: set[str],
    hazard_handle_map: dict[str, str],
    warnings_out: list[str],
    span_repairs_out: list[RuleSpanRepairRecord] | None,
) -> SecurityConstraint:
    """Apply one edit; an omitted obligations list or class keeps the prior one."""
    _check_constraint_edit(prior_constraint, edit, hazard_handle_map, warnings_out)
    obligations = (
        prior_constraint.obligations if edit.obligations is None else edit.obligations
    )
    return _build_constraint(
        constraint_id=edit.constraint_id,
        rule=edit.rule,
        applies_when=edit.applies_when,
        behavior_class=edit.behavior_class or prior_constraint.behavior_class,
        related_hazards=edit.related_hazards,
        obligations=obligations,
        existing_hazard_ids=existing_hazard_ids,
        hazard_handle_map=hazard_handle_map,
        span_repairs_out=span_repairs_out,
    )


def _check_revision_edit_targets(
    patch: Stage1aRevisionPatch,
    prior_hazards: dict[str, Hazard],
    prior_constraints: dict[str, SecurityConstraint],
) -> None:
    """Reject duplicate edit targets and targets the prior graph lacks."""
    hazard_edits = _unique_revision_targets(
        patch.hazard_edits,
        target_field="hazard_id",
        label="hazard edit",
    )
    constraint_edits = _unique_revision_targets(
        patch.security_constraint_edits,
        target_field="constraint_id",
        label="security constraint edit",
    )
    for target in hazard_edits:
        if target not in prior_hazards:
            raise ValueError(f"unknown hazard edit target '{target}'")
    for target in constraint_edits:
        if target not in prior_constraints:
            raise ValueError(f"unknown security constraint edit target '{target}'")


def _assemble_revision_hazards(
    prior: LossAnalysis,
    patch: Stage1aRevisionPatch,
    hazard_additions: list[object],
    warnings_out: list[str],
) -> tuple[dict[str, Hazard], dict[str, str]]:
    """Apply hazard edits and additions; return hazards and the handle map.

    A hazard addition that restates an existing hazard resolves to that
    hazard's ID instead of creating a duplicate.
    """
    prior_hazards = {hazard.hazard_id: hazard for hazard in prior.hazards}
    losses = {
        loss.loss_id for loss in (*prior.risk_card_losses, *prior.use_case_losses)
    }
    assembled_hazards = {
        hazard_id: hazard.model_copy(deep=True)
        for hazard_id, hazard in prior_hazards.items()
    }
    for edit in patch.hazard_edits:
        assembled_hazards[edit.hazard_id] = _build_hazard(
            hazard_id=edit.hazard_id,
            description=edit.description,
            related_losses=edit.related_losses,
            valid_loss_ids=losses,
        )
    restated = _restated_hazard_handles(hazard_additions, assembled_hazards)
    for handle, hazard_id in sorted(restated.items()):
        warnings_out.append(
            f"graph revision hazard addition '{handle}' restates existing "
            f"hazard {hazard_id}; its references resolve to {hazard_id}"
        )
    hazard_additions = [
        addition
        for addition in hazard_additions
        if str(getattr(addition, "handle")) not in restated
    ]
    hazard_handle_map = _allocate_revision_handles(
        hazard_additions,
        existing_ids=set(prior_hazards),
        kind="hazard",
    )
    hazard_handle_map.update(restated)
    for addition in hazard_additions:
        assembled_hazards[hazard_handle_map[addition.handle]] = _build_hazard(
            hazard_id=hazard_handle_map[addition.handle],
            description=addition.description,
            related_losses=addition.related_losses,
            valid_loss_ids=losses,
            addition_handle=addition.handle,
        )
    return assembled_hazards, hazard_handle_map


def _check_constraint_edit(
    prior_constraint: SecurityConstraint,
    edit: RevisionConstraintEdit,
    hazard_handle_map: dict[str, str],
    warnings_out: list[str],
) -> None:
    """Reject an implicit rule change and warn about reviewer-visible edits."""
    resolved_edit_hazards = [
        hazard_handle_map.get(reference, reference)
        for reference in edit.related_hazards
    ]
    if (
        edit.rule != prior_constraint.rule
        or edit.applies_when != prior_constraint.applies_when
    ) and edit.obligations is None:
        raise ValueError(
            f"constraint {edit.constraint_id} changed rule or applicability "
            "without explicit obligations"
        )
    # Keep the prior review diagnostics for edits that are now explicit
    # enough to compile.  A condition-only change still deserves reviewer
    # visibility, while a rule that moves to a disjoint hazard set is a
    # semantic re-pointing even though the delta is structurally valid.
    if (
        prior_constraint.rule == edit.rule
        and prior_constraint.applies_when != edit.applies_when
    ):
        warnings_out.append(
            "graph revision changed the applies_when conditions of "
            f"constraint {edit.constraint_id} without changing its rule: "
            f"{prior_constraint.applies_when} -> {edit.applies_when}"
        )
    elif (
        prior_constraint.rule != edit.rule
        and set(prior_constraint.related_hazards) & set(resolved_edit_hazards) == set()
    ):
        # A rewritten rule on disjoint hazards is a semantic re-pointing;
        # preserve the old warning while explicit obligations prevent
        # stale interpretations from being carried forward.
        warnings_out.append(
            "graph revision changed the rule of constraint "
            f"{edit.constraint_id} and re-pointed it to hazards "
            f"{sorted(resolved_edit_hazards)} sharing none of its prior "
            f"hazards {sorted(prior_constraint.related_hazards)}"
        )


def _unique_revision_targets(
    records: list[object],
    *,
    target_field: str,
    label: str,
) -> set[str]:
    targets = [str(getattr(record, target_field)) for record in records]
    duplicates = sorted({target for target in targets if targets.count(target) > 1})
    if duplicates:
        raise ValueError(f"duplicate {label} target(s): {', '.join(duplicates)}")
    return set(targets)


def _with_repair_hint(
    rendered: str,
    check: str,
    density: HazardGraphDensityReport,
) -> str:
    """Append the edge a structural check needs to the rendered check."""
    for hazard_id in density.hazards_without_constraint:
        if check == f"hazard {hazard_id} has no constraint":
            return (
                f"{rendered}. Repair: return a constraint whose "
                f"`related_hazards` includes `{hazard_id}`, either a "
                "`security_constraint_additions` entry or a "
                f"`security_constraint_edits` entry that adds `{hazard_id}` "
                "to an existing constraint. A new hazard does not repair "
                f"this check, even one that restates {hazard_id}."
            )
    return rendered


def _restated_hazard_handles(
    additions: list[object],
    hazards: dict[str, Hazard],
) -> dict[str, str]:
    """Map each hazard addition that restates an existing hazard to its ID.

    A restatement has the same description (ignoring case and whitespace)
    and cites no loss the existing hazard lacks.  Adding it would create a
    duplicate hazard and leave the existing one exactly as it was.
    """

    def normalized(text: str) -> str:
        return " ".join(text.split()).casefold()

    by_description = {
        normalized(hazard.description): hazard for hazard in hazards.values()
    }
    restated: dict[str, str] = {}
    for addition in additions:
        existing = by_description.get(normalized(str(getattr(addition, "description"))))
        if existing is not None and set(getattr(addition, "related_losses")) <= set(
            existing.related_losses
        ):
            restated[str(getattr(addition, "handle"))] = existing.hazard_id
    return restated


def _unique_revision_handles(records: list[object], *, label: str) -> list[object]:
    handles = [str(getattr(record, "handle")) for record in records]
    duplicates = sorted({handle for handle in handles if handles.count(handle) > 1})
    if duplicates:
        raise ValueError(f"duplicate {label} handle(s): {', '.join(duplicates)}")
    return records


def _allocate_revision_handles(
    records: list[object],
    *,
    existing_ids: set[str],
    kind: str,
) -> dict[str, str]:
    """Allocate added-record IDs in stable local-handle order."""
    prefix = {"hazard": "H-", "constraint": "SC-"}[kind]
    handles = sorted(str(getattr(record, "handle")) for record in records)
    return allocate_canonical_ids(prefix, existing_ids, handles)


def _build_hazard(
    *,
    hazard_id: str,
    description: str,
    related_losses: list[str],
    valid_loss_ids: set[str],
    addition_handle: str | None = None,
) -> object:
    unknown = sorted(set(related_losses) - valid_loss_ids)
    if unknown:
        raise ValueError(
            f"hazard {hazard_id} references unknown loss ID(s): {', '.join(unknown)}"
        )
    repeated = sorted(
        {
            reference
            for reference in related_losses
            if related_losses.count(reference) > 1
        }
    )
    if repeated:
        raise ValueError(
            f"{_revision_record_label('hazard', hazard_id, addition_handle)} "
            f"references duplicate loss ID(s): {', '.join(repeated)}; list each "
            "loss once in related_losses"
        )
    from asago_scenario_generator.stpa.models.loss_analysis import Hazard

    return Hazard(
        hazard_id=hazard_id,
        description=description,
        related_losses=list(related_losses),
    )


def _build_constraint(
    *,
    constraint_id: str,
    rule: str,
    applies_when: list[str],
    behavior_class: BehaviorClass | None,
    related_hazards: list[str],
    obligations: list[object],
    existing_hazard_ids: set[str],
    hazard_handle_map: dict[str, str],
    span_repairs_out: list[RuleSpanRepairRecord] | None = None,
    addition_handle: str | None = None,
) -> SecurityConstraint:
    obligations, span_repairs = repair_obligation_models(
        constraint=constraint_id, rule=rule, obligations=list(obligations)
    )
    if span_repairs_out is not None:
        span_repairs_out.extend(span_repairs)
    resolved_hazards = [
        hazard_handle_map.get(reference, reference) for reference in related_hazards
    ]
    unknown = _unknown_hazard_references(
        related_hazards, existing_hazard_ids, hazard_handle_map
    )
    if unknown:
        raise ValueError(
            f"security constraint {constraint_id} references unknown hazard ID(s): "
            + ", ".join(unknown)
        )
    repeated = _repeated_resolved_references(related_hazards, resolved_hazards)
    if repeated:
        label = _revision_record_label(
            "security constraint", constraint_id, addition_handle
        )
        raise ValueError(
            f"{label} references duplicate hazard ID(s): {', '.join(repeated)}; "
            "list each hazard once in related_hazards"
        )
    try:
        return SecurityConstraint(
            constraint_id=constraint_id,
            rule=rule,
            applies_when=list(applies_when),
            behavior_class=behavior_class,
            related_hazards=resolved_hazards,
            obligations=list(obligations),
        )
    except ValidationError as exc:
        if addition_handle is None:
            raise
        raise _addition_validation_error(exc, constraint_id, addition_handle) from exc


def _unknown_hazard_references(
    related_hazards: list[str],
    existing_hazard_ids: set[str],
    hazard_handle_map: dict[str, str],
) -> list[str]:
    return sorted(
        {
            reference
            for reference in related_hazards
            if reference not in existing_hazard_ids
            and reference not in hazard_handle_map
        }
    )


def _addition_validation_error(
    exc: ValidationError, constraint_id: str, addition_handle: str
) -> ValidationError:
    # The provider never sees the compiler-assigned ID of an addition, so
    # the correction feedback must name the handle it wrote.
    prefix = (
        f"security constraint addition '{addition_handle}' (assigned {constraint_id}): "
    )
    return ValidationError.from_exception_data(
        exc.title,
        [
            {
                "type": "value_error",
                "loc": ("security_constraint_additions", addition_handle),
                "input": error.get("input"),
                "ctx": {
                    "error": ValueError(
                        prefix + str(error.get("ctx", {}).get("error", error["msg"]))
                    )
                },
            }
            for error in exc.errors()
        ],
    )


def _revision_record_label(
    kind: str, record_id: str, addition_handle: str | None
) -> str:
    """Name a revision record the way the provider wrote it.

    The provider never sees the compiler-assigned ID of an addition, so an
    addition is named by its handle as well.
    """
    if addition_handle is None:
        return f"{kind} {record_id}"
    return f"{kind} addition '{addition_handle}' (assigned {record_id})"


def _repeated_resolved_references(written: list[str], resolved: list[str]) -> list[str]:
    """Return each resolved ID cited twice, with its spellings when they differ.

    A hazard-addition handle that restates an existing hazard resolves to
    that hazard's ID, so two different written references can name one ID.
    """
    spellings: dict[str, list[str]] = {}
    for written_reference, resolved_reference in zip(written, resolved):
        spellings.setdefault(resolved_reference, []).append(written_reference)
    repeated = []
    for resolved_reference, references in sorted(spellings.items()):
        if len(references) < 2:
            continue
        if len(set(references)) == 1:
            repeated.append(resolved_reference)
            continue
        written_as = ", ".join(f"'{reference}'" for reference in sorted(references))
        repeated.append(f"{resolved_reference} (written as {written_as})")
    return repeated


def _revise_stated_rules(
    progress: _GateProgress,
    inputs: _GateInputs,
    findings: tuple[StatedRuleFinding, ...],
    stated_rule_check: StatedRuleCheck | None,
) -> tuple[tuple[StatedRuleFinding, ...], StatedRuleRevision]:
    """Return the findings sent to a revision and that revision's outcome.

    Stated-rule findings reach a revision only on a graph that passes
    density; a density failure stays exactly as fatal as it was without them.
    """
    if not findings or progress.failing:
        return (), StatedRuleRevision()
    return findings, _apply_stated_rule_revision(
        progress, inputs, findings, stated_rule_check
    )


def _run_density_revision(
    progress: _GateProgress,
    inputs: _GateInputs,
    density: HazardGraphDensityReport,
) -> None:
    """Run the bounded density revision rounds on a failing graph.

    Each round revises the previous round's valid graph.  A second round runs
    only when the first revision validated but left (or introduced)
    structural failures; a revision call that fails validation after its
    correction still stops the gate immediately, unless the only defect is
    constraint records whose obligation ``rule_span`` is not part of their
    rule or that carry a blank ``applies_when`` entry: those records are
    dropped, the rest of the revision is kept, and the round records each
    dropped record (``dropped_records``).
    """
    progress.revision_attempted = True
    current = progress.loss_analysis
    current_density = density
    round_attempts: list[list[_RevisionAttempt]] = []
    decision: Accept | Revise | Stop = Stop(
        reason="; ".join(density.failing_checks), findings=density
    )
    for round_number in range(1, GRAPH_REVISION_ROUNDS + 1):
        attempts: list[_RevisionAttempt] = []
        round_attempts.append(attempts)
        prompt_checks = [
            _with_repair_hint(
                check
                if check in density.failing_checks
                else f"{check} (introduced by the previous revision)",
                check,
                current_density,
            )
            for check in current_density.failing_checks
        ]
        try:
            with count_requests() as sent:
                revised = _run_graph_revision_call(
                    llm_client=inputs.llm_client,
                    loss_analysis=current,
                    use_case_text=inputs.use_case_text,
                    failing_checks=prompt_checks,
                    run_dir=inputs.run_dir,
                    template_loader=inputs.template_loader,
                    temperature=inputs.temperature,
                    attempts_out=attempts,
                    drop_defective_records=True,
                )
        except StageError as exc:
            # The revision itself failed (provider error or a response that
            # still failed validation after its correction).  Persist the
            # evidence, then stop the run with every failing check.
            progress.revision_call_count += sent.requests
            _record_failed_revision_round(
                exc,
                progress,
                inputs,
                round_attempts=round_attempts,
                round_number=round_number,
                before=current_density,
                original=density,
            )
            raise
        progress.revision_call_count += sent.requests
        current_density = _accept_revision_round(
            progress,
            inputs,
            revised,
            attempts=attempts,
            round_number=round_number,
            before=current_density,
            original=density,
        )
        current = revised
        decision = decide_density_round(
            revised,
            current_density,
            round_number=round_number,
            rounds=GRAPH_REVISION_ROUNDS,
        )
        if not isinstance(decision, Revise):
            break
    # Retain the unrevised graph on failure; the stage error carries every
    # still-failing check for the run manifest.
    progress.final_density = current_density
    for recorded in round_attempts:
        _record_revision_span_repairs(
            inputs.repair_record,
            inputs.run_dir,
            recorded,
            accepted=isinstance(decision, Accept),
        )
    if isinstance(decision, Accept):
        progress.revision_applied = True
        progress.loss_analysis = current
        progress.failing = []


def _record_failed_revision_round(
    exc: StageError,
    progress: _GateProgress,
    inputs: _GateInputs,
    *,
    round_attempts: list[list[_RevisionAttempt]],
    round_number: int,
    before: HazardGraphDensityReport,
    original: HazardGraphDensityReport,
) -> None:
    """Persist the evidence of a failed revision call and annotate the error."""
    progress.rounds.append(
        revision_round_record(
            round_number,
            before=before,
            after=None,
            original=original,
        )
    )
    for recorded in round_attempts:
        _record_revision_span_repairs(
            inputs.repair_record, inputs.run_dir, recorded, accepted=False
        )
    write_gates_artifact(
        inputs.run_dir,
        accounting=inputs.accounting,
        density=progress.final_density,
        failing_checks=progress.failing,
        revision_attempted=True,
        revision_applied=False,
        normalization_warnings=inputs.accounting_normalization_warnings,
        revision_call_count=progress.revision_call_count,
        revision_rounds=progress.rounds,
    )
    exc.revision_attempted = True  # type: ignore[attr-defined]
    exc.revision_call_count = progress.revision_call_count  # type: ignore[attr-defined]


def _accept_revision_round(
    progress: _GateProgress,
    inputs: _GateInputs,
    revised: LossAnalysis,
    *,
    attempts: list[_RevisionAttempt],
    round_number: int,
    before: HazardGraphDensityReport,
    original: HazardGraphDensityReport,
) -> HazardGraphDensityReport:
    """Record a valid revision round and return the revised graph's report."""
    accepted_attempt = attempts[-1]
    progress.revision_warnings.extend(accepted_attempt.warnings)
    progress.revision_warnings.extend(
        f"graph revision rule_span {record.constraint}/"
        f"{record.obligation_id} repaired by {record.repair.kind} match: "
        f"{record.repair.original!r} -> {record.repair.repaired!r}"
        for record in accepted_attempt.span_repairs
    )
    revised_density = check_hazard_graph_density(revised)
    record = revision_round_record(
        round_number,
        before=before,
        after=revised_density,
        original=original,
    )
    if accepted_attempt.dropped:
        record["dropped_records"] = accepted_attempt.dropped
        progress.revision_warnings.extend(
            _dropped_record_warnings(accepted_attempt.dropped)
        )
    progress.rounds.append(record)
    progress.failing.extend(
        f"{_ROUND_FAILURE_PREFIX[round_number]}: {check}"
        for check in revised_density.failing_checks
    )
    return revised_density


def _dropped_record_warnings(dropped: Sequence[dict]) -> list[str]:
    return [
        f"graph revision dropped {item['record']} "
        f"'{item.get('handle') or item['constraint_id']}': {item['error']}"
        for item in dropped
    ]


def _apply_stated_rule_revision(
    progress: _GateProgress,
    inputs: _GateInputs,
    findings: tuple[StatedRuleFinding, ...],
    check: StatedRuleCheck | None,
) -> StatedRuleRevision:
    """Run the stated-rule revision round and fold its result into *progress*."""
    (
        progress.loss_analysis,
        rule_revision,
        rule_round,
        rule_warnings,
    ) = _run_stated_rule_revision(
        llm_client=inputs.llm_client,
        loss_analysis=progress.loss_analysis,
        use_case_text=inputs.use_case_text,
        findings=findings,
        density=progress.final_density,
        run_dir=inputs.run_dir,
        template_loader=inputs.template_loader,
        temperature=inputs.temperature,
        repair_record=inputs.repair_record,
        round_number=len(progress.rounds) + 1,
        check=check,
    )
    progress.revision_call_count += rule_revision.call_count
    progress.rounds.append(rule_round)
    progress.revision_warnings.extend(rule_warnings)
    return rule_revision


def _warn_unclassified_constraints(progress: _GateProgress) -> None:
    """Warn about revised constraints that declare no behavior class.

    The Phase 2 relevance flow records such constraints as non-actionable
    (typed empty row with a reason), so this is recorded evidence, not a gate
    failure.
    """
    unclassified_added = sorted(
        constraint.constraint_id
        for constraint in progress.loss_analysis.security_constraints
        if constraint.behavior_class is None
    )
    if unclassified_added:
        progress.revision_warnings.append(
            "graph revision left constraint(s) "
            + ", ".join(unclassified_added)
            + " without a behavior class; the Phase 2 relevance table "
            "records them as non-actionable"
        )


def _run_stated_rule_revision(
    *,
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    use_case_text: str,
    findings: tuple[StatedRuleFinding, ...],
    density: HazardGraphDensityReport,
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
    repair_record: RepairRecord | None,
    round_number: int = 1,
    check: StatedRuleCheck | None = None,
) -> tuple[LossAnalysis, StatedRuleRevision, dict, list[str]]:
    """Run one non-fatal revision round for stated-rule findings alone.

    The graph already passes the structural checks.  The round may add
    hazards and constraints and extend an existing constraint's ``rule``
    (see :func:`_addition_only_patch`).  A failed call, a response that
    changes an existing record or names a non-canonical ID, a revision that
    breaks a structural check, and a revision ``check`` rejects all keep the
    unrevised graph, so a stated-rule finding never turns a passing gate
    into a stage failure or damages an existing constraint.

    Two repairs keep a revision that would otherwise fail.  Records whose
    ``rule_span`` is not in their rule are dropped after the correction call.
    A revision that fails only the class-ownership check loses the added
    constraints that cite a hazard another behavior class cites alone; the
    acceptance module owns that repair
    (:func:`asago_scenario_generator.stpa.system_model.loss_analysis_acceptance._trim_failed_class_ownership`).
    The round then asks :func:`decide_stated_rule_round` what to keep: the
    revision, the revision without those records, or the prior graph.
    """
    attempts: list[_RevisionAttempt] = []
    warnings: list[str] = []

    def rejected(
        reason: str, record: dict, call_count: int, verb: str = "discarded"
    ) -> tuple[LossAnalysis, StatedRuleRevision, dict, list[str]]:
        return (
            loss_analysis,
            StatedRuleRevision(
                trigger="stated_rules",
                applied=False,
                call_count=call_count,
                error=reason,
            ),
            record,
            [f"stated-rule revision {verb}; kept the unrevised graph: {reason}"],
        )

    try:
        with count_requests() as sent:
            revised = _run_graph_revision_call(
                llm_client=llm_client,
                loss_analysis=loss_analysis,
                use_case_text=use_case_text,
                failing_checks=[],
                run_dir=run_dir,
                template_loader=template_loader,
                temperature=temperature,
                attempts_out=attempts,
                stated_rules=findings,
                addition_only=True,
                drop_defective_records=True,
            )
    except Exception as exc:  # noqa: BLE001 - this revision is advisory
        _record_revision_span_repairs(repair_record, run_dir, attempts, accepted=False)
        record = revision_round_record(
            round_number, before=density, after=None, original=density
        )
        record["trigger"] = "stated_rules"
        return rejected(str(exc), record, sent.requests, "failed")
    call_count = sent.requests
    rejection = attempts[-1].rejection if attempts else None
    if rejection is not None:
        _record_revision_span_repairs(repair_record, run_dir, attempts, accepted=False)
        record = revision_round_record(
            round_number, before=density, after=None, original=density
        )
        record["trigger"] = "stated_rules"
        return rejected(rejection, record, call_count)
    revised, revised_density, trimmed = _trim_failed_class_ownership(
        loss_analysis, revised, check_hazard_graph_density(revised)
    )
    record = revision_round_record(
        round_number, before=density, after=revised_density, original=density
    )
    record["trigger"] = "stated_rules"
    dropped = [*attempts[-1].dropped, *trimmed]
    if dropped:
        record["dropped_records"] = dropped
    decision = decide_stated_rule_round(
        revised,
        rejection=_revision_rejection(revised, revised_density, check),
        records=tuple(dropped),
    )
    _record_revision_span_repairs(
        repair_record,
        run_dir,
        attempts,
        accepted=not isinstance(decision, KeepPrior),
    )
    if isinstance(decision, KeepPrior):
        return rejected(decision.reason, record, call_count)
    revised = decision.analysis
    accepted_attempt = attempts[-1]
    warnings.extend(accepted_attempt.warnings)
    warnings.extend(
        f"graph revision rule_span {item.constraint}/"
        f"{item.obligation_id} repaired by {item.repair.kind} match: "
        f"{item.repair.original!r} -> {item.repair.repaired!r}"
        for item in accepted_attempt.span_repairs
    )
    warnings.extend(_dropped_record_warnings(dropped))
    return (
        revised,
        StatedRuleRevision(trigger="stated_rules", applied=True, call_count=call_count),
        record,
        warnings,
    )


def _revision_rejection(
    revised: LossAnalysis,
    density: HazardGraphDensityReport,
    check: StatedRuleCheck | None,
) -> str | None:
    """Why the stated-rule round's graph is rejected, or ``None`` to keep it."""
    if not density.passed:
        return "revision broke structural checks: " + "; ".join(density.failing_checks)
    if check is None:
        return None
    try:
        return check(revised)
    except Exception as exc:  # noqa: BLE001 - this revision is advisory
        return f"revision check failed: {type(exc).__name__}: {exc}"


def _record_revision_span_repairs(
    repair_record: RepairRecord | None,
    run_dir: Path,
    attempts: list[_RevisionAttempt],
    *,
    accepted: bool,
) -> None:
    """Record every attempt's span repairs through the publication module."""
    write_revision_span_repairs(
        repair_record,
        run_dir,
        [attempt.span_repairs for attempt in attempts],
        accepted=accepted,
    )


def _run_graph_revision_call(
    *,
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    use_case_text: str,
    failing_checks: list[str],
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
    attempts_out: list[_RevisionAttempt],
    stated_rules: Sequence[StatedRuleFinding] = (),
    addition_only: bool = False,
    drop_defective_records: bool = False,
) -> LossAnalysis:
    """Make the bounded graph-revision call and validate its result.

    A caller counts the requests it sent, a correction included and a request
    the prompt preflight blocked excluded, with :func:`count_requests`.

    With ``drop_defective_records``, a final response that fails validation
    because some record's obligation ``rule_span`` is not part of that
    record's rule, or because a record has a blank ``applies_when`` entry,
    yields the response without those records (see
    :func:`_revision_without_defective_records`); the dropped records and their
    errors stay on the last entry of ``attempts_out``.

    With ``addition_only``, a response that edits an existing record beyond
    extending a constraint rule, or targets an ID the graph does not have,
    is rejected at once: the attempt records the ``rejection`` and the call
    returns the unchanged graph without a correction request.

    The response is an explicit edit/add delta carrying the authored ``rule``
    + ``applies_when`` shape. Losses and risk dispositions come from the
    prior analysis and deterministic code carries omitted graph records
    forward, so the model cannot damage immutable records by echoing or
    omitting them.

    A response that fails parsing or validation receives one correction call
    carrying the exact validation error and the prior response.  A response
    that never decodes as JSON gets the same one call, with instruction text
    for the decode error and the prior response without its trailing
    whitespace; a call that still fails then says it tried the correction.
    Each parsed attempt is appended to ``attempts_out`` with its own warnings
    and ``rule_span`` repairs, so only the accepted attempt's evidence is
    applied.

    The reply is judged by :func:`decide_revision_call`, which decides whether
    the call accepts the graph, keeps it without the records it dropped, or
    stops the run with the decision's reason.
    """
    system_prompt = template_loader.render_prompt(
        "stage1a_graph_revision_system.j2", stated_rules=bool(stated_rules)
    )
    user_prompt = template_loader.render_prompt(
        "stage1a_graph_revision_user.j2",
        use_case_text=use_case_text,
        losses=loss_analysis.risk_card_losses + loss_analysis.use_case_losses,
        hazards=loss_analysis.hazards,
        security_constraints=loss_analysis.security_constraints,
        failing_checks=failing_checks,
        stated_rules=list(stated_rules),
    )

    def parse_revision(
        result: LLMResult, _cleanup: list[dict[str, Any]]
    ) -> LossAnalysisDraft:
        attempt = _RevisionAttempt()
        attempts_out.append(attempt)
        try:
            if addition_only:
                attempt.rejection = _unknown_edit_targets(
                    loss_analysis, decode_content(result)
                )
                if attempt.rejection is not None:
                    return _draft_from_analysis(loss_analysis)
            patch = parse_llm_result(result, Stage1aRevisionPatch)
            attempt.patch = patch
            if addition_only:
                patch, attempt.rejection, dropped = _addition_only_patch(
                    loss_analysis, patch
                )
                if attempt.rejection is not None:
                    return _draft_from_analysis(loss_analysis)
                attempt.warnings.extend(_dropped_edit_warnings(dropped))
            _reject_blank_hazards(patch, template_loader)
            return _revision_patch_to_draft(
                loss_analysis,
                patch,
                attempt.warnings,
                span_repairs_out=attempt.span_repairs,
            )
        except Exception as exc:
            attempt.failed = True
            attempt.undecodable = isinstance(exc, json.JSONDecodeError)
            raise

    def validate_revision(draft: LossAnalysisDraft) -> None:
        try:
            _check_revision(loss_analysis, draft)
        except Exception:
            attempts_out[-1].failed = True
            raise

    first_attempt = len(attempts_out)
    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=Stage1aRevisionPatch,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_GRAPH_REVISION,
        policy=_revision_policy(template_loader),
        temperature=temperature,
        max_completion_tokens=STAGE1A_MAX_COMPLETION_TOKENS,
        response_parser=parse_revision,
        result_validator=validate_revision,
    )
    revised = outcome.value
    records: tuple[dict, ...] = ()
    if revised is None and drop_defective_records:
        revised = _revision_without_defective_records(
            loss_analysis,
            attempts_out,
            outcome.failure,
            addition_only=addition_only,
        )
        if revised is not None:
            records = tuple(attempts_out[-1].dropped)
    decision = decide_revision_call(
        revised,
        error=_revision_failure_message(outcome.error, attempts_out[first_attempt:]),
        records=records,
    )
    if isinstance(decision, Stop):
        raise StageError(
            stage=STAGE,
            step=STEP_GRAPH_REVISION,
            message=decision.reason,
        )
    return _revised_analysis(loss_analysis, decision.analysis)


def _revision_policy(template_loader: TemplateLoader) -> CorrectionPolicy:
    """The graph-revision correction: one request, also for an undecodable reply."""
    decision = decide_correction(
        scope=REVISION_CORRECTION_SCOPE, retries=REVISION_VALIDATION_RETRIES
    )
    retries = decision.retries if isinstance(decision, Correct) else 0

    def feedback(error: Exception) -> str:
        if isinstance(error, json.JSONDecodeError):
            return "\n\n" + template_loader.render_prompt(REVISION_UNDECODABLE_TEMPLATE)
        return REVISION_CORRECTION_FEEDBACK

    return CorrectionPolicy(
        validation_retries=retries,
        feedback=feedback,
        include_schema=False,
        include_response=True,
        correct_undecodable=retries > 0,
    )


def _revision_failure_message(
    error: str | None, attempts: list[_RevisionAttempt]
) -> str:
    """Word the failed call, naming the correction an undecodable reply earned.

    *attempts* are the replies this call parsed, in order; a second one means
    the correction was sent and answered.
    """
    if len(attempts) > 1 and attempts[0].undecodable:
        return (
            "graph revision call failed after one correction request for an "
            f"undecodable reply: {error}"
        )
    return f"graph revision call failed: {error}"


def _reject_blank_hazards(
    patch: Stage1aRevisionPatch, template_loader: TemplateLoader
) -> None:
    """Raise when a hazard addition or edit has a blank description.

    The schema only rejects an empty string, so a whitespace description would
    otherwise reach the graph, and synthesis keeps such a hazard out of every
    prompt's reference slice.
    """
    records = [
        f"hazard addition {hazard.handle}"
        for hazard in patch.hazard_additions
        if not hazard.description.strip()
    ] + [
        f"hazard edit {hazard.hazard_id}"
        for hazard in patch.hazard_edits
        if not hazard.description.strip()
    ]
    if records:
        raise ValueError(
            template_loader.render_prompt(
                REVISION_BLANK_HAZARD_TEMPLATE, records=records
            ).strip()
        )


def _check_revision(prior: LossAnalysis, draft: LossAnalysisDraft) -> None:
    """Raise when an assembled revision fails validation.

    Assembly copies every prior loss and keeps every prior hazard and
    constraint ID by construction (``_revision_patch_to_draft``).
    """
    # In place on the draft, before validation, even when validation
    # then fails; the prior graph keeps its own constraint objects.
    stamp_proposed_direction(draft)
    _validate_revision(prior, draft)


def _span_unusable(rule: str, span: str) -> bool:
    """Whether ``span`` fails the verbatim test and no repair maps it."""
    return not span_quotes_rule(rule, span) and repair_rule_span(rule, span) is None


def _unquoted_span_error(
    rule: str, obligations: Sequence[ProviderObligation]
) -> str | None:
    """Describe every obligation whose span no repair maps onto ``rule``."""
    errors = [
        f"obligation {obligation.obligation_id} rule_span must be a contiguous "
        "substring of the constraint rule, compared case-insensitively: "
        f"{obligation.rule_span!r} does not occur in the rule {rule!r}."
        for obligation in obligations
        if _span_unusable(rule, obligation.rule_span)
    ]
    return " ".join(errors) or None


def _blank_applies_when_error(applies_when: Sequence[str]) -> str | None:
    """Describe every blank ``applies_when`` entry (1-based)."""
    errors = [
        "applies_when entries must be non-empty condition sentences: "
        f"entry {index} is {entry!r}."
        for index, entry in enumerate(applies_when, start=1)
        if not entry.strip()
    ]
    return " ".join(errors) or None


def _record_defect_error(
    rule: str,
    applies_when: Sequence[str],
    obligations: Sequence[ProviderObligation],
) -> str | None:
    """Describe a constraint record's droppable defects, or ``None``."""
    errors = [
        error
        for error in (
            _unquoted_span_error(rule, obligations),
            _blank_applies_when_error(applies_when),
        )
        if error is not None
    ]
    return " ".join(errors) or None


def _without_defective_records(
    patch: Stage1aRevisionPatch,
) -> tuple[Stage1aRevisionPatch, list[dict]]:
    """Split constraint additions and edits into the kept patch and the dropped.

    A record is dropped when an obligation span no repair maps onto its rule,
    or when an ``applies_when`` entry is blank.  A blank entry is not read as
    "no condition": on an edit that would delete the prior conditions.
    Dropping an edit leaves the prior constraint as it was.  An edit that
    omits its obligations keeps the prior ones, which the span test skips.
    A hazard addition that only dropped records cited goes with them; a new
    hazard no kept constraint would cite fails validation.
    """
    kept_additions: list[RevisionConstraintAddition] = []
    kept_edits: list[RevisionConstraintEdit] = []
    dropped: list[dict] = []
    cited_by_dropped: set[str] = set()
    for addition in patch.security_constraint_additions:
        error = _record_defect_error(
            addition.rule, addition.applies_when, addition.obligations
        )
        if error is None:
            kept_additions.append(addition)
        else:
            cited_by_dropped.update(addition.related_hazards)
            dropped.append(
                {
                    "record": "security_constraint_addition",
                    "handle": addition.handle,
                    "error": error,
                }
            )
    for edit in patch.security_constraint_edits:
        error = _record_defect_error(
            edit.rule, edit.applies_when, edit.obligations or ()
        )
        if error is None:
            kept_edits.append(edit)
        else:
            cited_by_dropped.update(edit.related_hazards)
            dropped.append(
                {
                    "record": "security_constraint_edit",
                    "constraint_id": edit.constraint_id,
                    "error": error,
                }
            )
    still_cited = {h for r in (*kept_additions, *kept_edits) for h in r.related_hazards}
    orphaned = cited_by_dropped - still_cited
    reduced = patch.model_copy(
        update={
            "hazard_additions": _hazards_not_in(patch.hazard_additions, orphaned),
            "security_constraint_additions": kept_additions,
            "security_constraint_edits": kept_edits,
        }
    )
    return reduced, dropped


def _hazards_not_in(
    additions: list[RevisionHazardAddition], handles: set[str]
) -> list[RevisionHazardAddition]:
    return [hazard for hazard in additions if hazard.handle not in handles]


def _has_records(patch: Stage1aRevisionPatch) -> bool:
    return any(
        (
            patch.hazard_edits,
            patch.hazard_additions,
            patch.security_constraint_edits,
            patch.security_constraint_additions,
        )
    )


def _final_patch_after_validation_failure(
    attempts: list[_RevisionAttempt], failure: BaseException | None
) -> Stage1aRevisionPatch | None:
    """The final parsed patch, unless the call failed for another reason.

    A blocked or failed request is not a slip, so it keeps the stop.
    """
    if not attempts or not isinstance(failure, ValidationError):
        return None
    return attempts[-1].patch


def _droppable_final_patch(
    attempts: list[_RevisionAttempt], failure: BaseException | None
) -> tuple[Stage1aRevisionPatch, list[dict]] | None:
    """Split the final patch when dropping slipped records can help.

    Needs at least one record to drop and at least one left.
    """
    patch = _final_patch_after_validation_failure(attempts, failure)
    if patch is None:
        return None
    reduced, dropped = _without_defective_records(patch)
    if not dropped or not _has_records(reduced):
        return None
    return reduced, dropped


def _dropped_edit_warnings(notes: Sequence[str]) -> list[str]:
    return [
        f"stated-rule revision dropped an edit and kept the rest: {n}" for n in notes
    ]


def _reduced_patch_for_rebuild(
    prior: LossAnalysis, reduced: Stage1aRevisionPatch, addition_only: bool
) -> tuple[Stage1aRevisionPatch, list[str]] | None:
    """The reduced patch to rebuild from, with the notes of the edits it loses.

    The stored patch is the raw response, so an addition-only revision runs the
    filter again on the reduced patch; a rebuild must not keep an edit the
    first parse would have dropped.  ``None`` when nothing is left to apply.
    """
    if not addition_only:
        return reduced, []
    filtered, rejection, notes = _addition_only_patch(prior, reduced)
    if rejection is not None or not _has_records(filtered):
        return None
    return filtered, _dropped_edit_warnings(notes)


def _revision_without_defective_records(
    prior: LossAnalysis,
    attempts: list[_RevisionAttempt],
    failure: BaseException | None,
    *,
    addition_only: bool = False,
) -> LossAnalysisDraft | None:
    """Rebuild a failed final attempt without its defective constraint records.

    A span that no repair maps onto its rule, or a blank ``applies_when``
    entry, stays wrong after the correction call, and one bad record must not
    discard the valid rest of the revision.
    Returns ``None`` (the call then fails as before) unless the final response
    parsed, failed validation, and drops at least one record while leaving at
    least one, and the remainder passes full validation.  The accepted rebuild
    is appended to *attempts* with the dropped records and their errors.
    With ``addition_only`` the rebuild keeps only what the add-only filter keeps.
    """
    split = _droppable_final_patch(attempts, failure)
    if split is None:
        return None
    rebuild = _reduced_patch_for_rebuild(prior, split[0], addition_only)
    if rebuild is None:
        return None
    reduced, notes = rebuild
    dropped = split[1]
    rebuilt = _RevisionAttempt(dropped=dropped, patch=reduced, warnings=notes)
    try:
        draft = _revision_patch_to_draft(
            prior, reduced, rebuilt.warnings, span_repairs_out=rebuilt.span_repairs
        )
        _check_revision(prior, draft)
    except Exception:  # noqa: BLE001 - any other defect keeps the stop
        return None
    attempts.append(rebuilt)
    return draft


def _validate_revision(prior: LossAnalysis, draft: LossAnalysisDraft) -> None:
    """Raise when a stamped revision draft fails full validation.

    Validates a copy, so *draft* is left unchanged.
    """
    # Full schema validation, including cross-references and the
    # single-hazard-per-class invariants enforced by the model itself.
    _revised_analysis(prior, draft.model_copy(deep=True))


def _draft_from_analysis(analysis: LossAnalysis) -> LossAnalysisDraft:
    """Convert a merged analysis into the collection-patch draft baseline.

    The draft owns copies, so stamping or editing it leaves *analysis* intact.
    """
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                loss.model_copy(deep=True) for loss in analysis.risk_card_losses
            ],
            "use_case_losses": [
                loss.model_copy(deep=True) for loss in analysis.use_case_losses
            ],
            "hazards": [hazard.model_copy(deep=True) for hazard in analysis.hazards],
            "security_constraints": [
                constraint.model_copy(deep=True)
                for constraint in analysis.security_constraints
            ],
            "risk_dispositions": [
                disposition.model_copy(deep=True)
                for disposition in analysis.risk_dispositions
            ],
        }
    )

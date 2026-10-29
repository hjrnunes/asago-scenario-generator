"""Report-only STPA specification checks on a run's final artifacts.

Each check looks for a relationship the STPA method requires and the final
loss analysis, control structure, or retained ICA enumeration lacks.  The
relationships, and where the producer already enforces each one, are listed
in ``docs/architecture/stpa-relationship-checklist.md``.

A finding is evidence for a person to judge, not a defect to repair.  It may
show missing modelling, an established deficiency of the system (a candidate
causal scenario), or a producer bug, and code cannot tell which.  So the
checks never repair an artifact, never block a run, and never raise on a
finding; every finding's ``disposition`` stays unset until a person or a
later step records one.

The checks read their own index over the final artifacts, built here from
the typed models; they share no traversal with the mechanism join.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.stpa.infra.yaml_io import yaml_text
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ProcessModelPart,
    ReferenceType,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICA, ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

SPEC_DIAGNOSTICS_SCHEMA_VERSION = "stpa-spec-diagnostics-v1"
SPEC_DIAGNOSTICS_FILENAME = "spec-diagnostics.yaml"


class SpecCheck(str, Enum):
    """The relationship a finding says the final artifacts lack.

    - ``controlled_process_without_feedback``: a responsibility issues a
      control action to a controlled process, and none of its feedback
      channels has that process as its source;
    - ``controlled_process_unobserved``: a controlled process that a control
      action targets is the source of no feedback channel at all;
    - ``hazard_without_ica``: no retained ICA cites the hazard;
    - ``action_without_process_model_refs``: a control action names no
      process-model variable it needs;
    - ``process_model_variable_without_values``: a variable a control action
      needs has no values, so it splits no context table;
    - ``ica_without_related_constraints``: a retained ICA cites no
      constraint;
    - ``hazard_without_constraint``: no security constraint lists the hazard
      in ``related_hazards``.
    """

    controlled_process_without_feedback = "controlled_process_without_feedback"
    controlled_process_unobserved = "controlled_process_unobserved"
    hazard_without_ica = "hazard_without_ica"
    action_without_process_model_refs = "action_without_process_model_refs"
    process_model_variable_without_values = "process_model_variable_without_values"
    ica_without_related_constraints = "ica_without_related_constraints"
    hazard_without_constraint = "hazard_without_constraint"


ICA_CHECKS = (SpecCheck.hazard_without_ica, SpecCheck.ica_without_related_constraints)
"""The checks that read the retained ICA enumeration."""


class FindingDisposition(str, Enum):
    """What a person decided a finding shows; never set by these checks.

    - ``fix the model``: the analysis omitted something the system has;
    - ``accepted limitation``: the gap is known and accepted as it stands;
    - ``causal scenario``: the system really lacks the relationship, a
      candidate causal scenario.
    """

    fix_the_model = "fix the model"
    accepted_limitation = "accepted limitation"
    causal_scenario = "causal scenario"


class SpecFinding(BaseModel):
    """One missing relationship, named by the elements it concerns."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    check: SpecCheck
    subject_ids: tuple[str, ...] = Field(
        min_length=1,
        description="Element IDs the finding concerns, the primary one first.",
    )
    message: str = Field(min_length=1)
    disposition: FindingDisposition | None = Field(
        default=None,
        description="Unset until a person or a later step judges the finding.",
    )


class SpecCheckSummary(BaseModel):
    """Whether one check ran, and how many findings it produced."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    check: SpecCheck
    status: Literal["run", "not_run"]
    findings: int = Field(ge=0)
    reason: str | None = Field(
        default=None, description="Why the check did not run; set only then."
    )


class SpecDiagnostics(BaseModel):
    """Every check's summary and every finding, in check order."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["stpa-spec-diagnostics-v1"] = (
        SPEC_DIAGNOSTICS_SCHEMA_VERSION
    )
    checks: tuple[SpecCheckSummary, ...]
    findings: tuple[SpecFinding, ...] = ()


@dataclass(frozen=True)
class _ActionRef:
    resp_id: str
    ca_id: str


@dataclass(frozen=True)
class _FinalIndex:
    """The relationships the checks read, indexed from the final structure.

    ``issuers`` maps each controlled process to the actions that target it,
    grouped by issuing responsibility, in structure order.  ``observers``
    maps each controlled process to the responsibilities owning a feedback
    channel whose source it is.  ``pm_sources`` maps each responsibility to
    the controlled processes its process-model parts name as
    ``feedback_source``.
    """

    process_ids: tuple[str, ...]
    issuers: dict[str, dict[str, tuple[str, ...]]]
    observers: dict[str, tuple[str, ...]]
    pm_sources: dict[str, frozenset[str]]
    parts: dict[str, tuple[str, ProcessModelPart]]
    actions: tuple[tuple[_ActionRef, tuple[str, ...]], ...]


def _index(structure: ControlStructure) -> _FinalIndex:
    issuers: dict[str, dict[str, list[str]]] = {}
    observers: dict[str, list[str]] = {}
    pm_sources: dict[str, frozenset[str]] = {}
    parts: dict[str, tuple[str, ProcessModelPart]] = {}
    actions: list[tuple[_ActionRef, tuple[str, ...]]] = []
    for resp in structure.responsibilities:
        for action in resp.control_actions:
            actions.append(
                (
                    _ActionRef(resp.resp_id, action.ca_id),
                    tuple(action.process_model_refs),
                )
            )
            target = action.target
            if target is not None and target.type is ReferenceType.controlled_process:
                by_resp = issuers.setdefault(target.id, {})
                by_resp.setdefault(resp.resp_id, []).append(action.ca_id)
        for channel in resp.feedback_channels:
            source = channel.source
            if source is not None and source.type is ReferenceType.controlled_process:
                seen = observers.setdefault(source.id, [])
                if resp.resp_id not in seen:
                    seen.append(resp.resp_id)
        pm_sources[resp.resp_id] = frozenset(
            pm.feedback_source.id
            for pm in resp.process_model_parts
            if pm.feedback_source is not None
            and pm.feedback_source.type is ReferenceType.controlled_process
        )
        for pm in resp.process_model_parts:
            parts[pm.pm_id] = (resp.resp_id, pm)
    return _FinalIndex(
        process_ids=tuple(cp.cp_id for cp in structure.controlled_processes),
        issuers={
            cp: {resp: tuple(cas) for resp, cas in by_resp.items()}
            for cp, by_resp in issuers.items()
        },
        observers={cp: tuple(resps) for cp, resps in observers.items()},
        pm_sources=pm_sources,
        parts=parts,
        actions=tuple(actions),
    )


def _process_order(index: _FinalIndex) -> tuple[str, ...]:
    """Declared processes, then any targeted process the structure omits."""
    extra = tuple(cp for cp in index.issuers if cp not in index.process_ids)
    return index.process_ids + extra


def _controlled_process_without_feedback(index: _FinalIndex) -> Iterator[SpecFinding]:
    for cp_id in _process_order(index):
        observers = index.observers.get(cp_id, ())
        for resp_id, ca_ids in index.issuers.get(cp_id, {}).items():
            if resp_id in observers:
                continue
            notes = []
            if cp_id in index.pm_sources.get(resp_id, frozenset()):
                notes.append(
                    f"a process-model part of {resp_id} names {cp_id} as its "
                    "feedback_source, but no feedback channel carries it"
                )
            others = [resp for resp in observers if resp != resp_id]
            if others:
                notes.append(f"{', '.join(others)} observes {cp_id}")
            suffix = f" ({'; '.join(notes)})" if notes else ""
            yield SpecFinding(
                check=SpecCheck.controlled_process_without_feedback,
                subject_ids=(cp_id, resp_id, *ca_ids),
                message=(
                    f"{resp_id} issues {', '.join(ca_ids)} to {cp_id}, but none "
                    f"of its feedback channels has {cp_id} as its source{suffix}."
                ),
            )


def _controlled_process_unobserved(index: _FinalIndex) -> Iterator[SpecFinding]:
    for cp_id in _process_order(index):
        by_resp = index.issuers.get(cp_id)
        if not by_resp or index.observers.get(cp_id):
            continue
        ca_ids = tuple(ca for cas in by_resp.values() for ca in cas)
        yield SpecFinding(
            check=SpecCheck.controlled_process_unobserved,
            subject_ids=(cp_id, *ca_ids),
            message=(
                f"{', '.join(ca_ids)} target {cp_id}, but no feedback channel "
                f"has {cp_id} as its source, so no controller observes the "
                "effect of those actions."
            ),
        )


def _retained_icas(enumeration: ICAEnumeration) -> Iterator[tuple[str, ICA]]:
    for slot in enumeration.slots:
        for ica in slot.icas:
            yield slot.slot_id, ica


def _hazard_without_ica(
    loss_analysis: LossAnalysis, enumeration: ICAEnumeration
) -> Iterator[SpecFinding]:
    retained = [ica for _, ica in _retained_icas(enumeration)]
    cited = {ref for ica in retained for ref in ica.related_hazards}
    for hazard in loss_analysis.hazards:
        if hazard.hazard_id in cited:
            continue
        yield SpecFinding(
            check=SpecCheck.hazard_without_ica,
            subject_ids=(hazard.hazard_id,),
            message=(
                f"No retained ICA (of {len(retained)}) cites hazard "
                f"{hazard.hazard_id}: {hazard.description}"
            ),
        )


def _action_without_process_model_refs(index: _FinalIndex) -> Iterator[SpecFinding]:
    for action, refs in index.actions:
        if refs:
            continue
        yield SpecFinding(
            check=SpecCheck.action_without_process_model_refs,
            subject_ids=(action.ca_id, action.resp_id),
            message=(
                f"{action.ca_id} of {action.resp_id} names no process-model "
                "variable the controller needs to issue it, so it has no "
                "context table."
            ),
        )


def _process_model_variable_without_values(
    index: _FinalIndex,
) -> Iterator[SpecFinding]:
    referencing: dict[str, list[str]] = {}
    for action, refs in index.actions:
        for ref in refs:
            referencing.setdefault(ref, []).append(action.ca_id)
    for pm_id, (resp_id, part) in index.parts.items():
        ca_ids = referencing.get(pm_id)
        if not ca_ids or part.values:
            continue
        yield SpecFinding(
            check=SpecCheck.process_model_variable_without_values,
            subject_ids=(pm_id, resp_id, *ca_ids),
            message=(
                f"{pm_id} of {resp_id} is needed by {', '.join(ca_ids)} but has "
                "no values, so it adds no column to their context tables."
            ),
        )


def _ica_without_related_constraints(
    enumeration: ICAEnumeration,
) -> Iterator[SpecFinding]:
    for slot_id, ica in _retained_icas(enumeration):
        if ica.related_constraints:
            continue
        yield SpecFinding(
            check=SpecCheck.ica_without_related_constraints,
            subject_ids=(ica.ica_id,),
            message=(
                f"ICA {ica.ica_id} of slot {slot_id} cites no security or "
                "responsibility constraint."
            ),
        )


def _hazard_without_constraint(loss_analysis: LossAnalysis) -> Iterator[SpecFinding]:
    covered = {
        ref
        for constraint in loss_analysis.security_constraints
        for ref in constraint.related_hazards
    }
    for hazard in loss_analysis.hazards:
        if hazard.hazard_id in covered:
            continue
        yield SpecFinding(
            check=SpecCheck.hazard_without_constraint,
            subject_ids=(hazard.hazard_id,),
            message=(
                f"No security constraint lists hazard {hazard.hazard_id} in "
                f"related_hazards: {hazard.description}"
            ),
        )


def diagnose_final_artifacts(
    *,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    ica_enumeration: ICAEnumeration | None,
    ica_unavailable_reason: str = "no ICA enumeration was supplied",
) -> SpecDiagnostics:
    """Run every check on the final artifacts; the inputs are not modified.

    Without *ica_enumeration* the ICA checks are recorded as not run, with
    *ica_unavailable_reason*.
    """
    index = _index(control_structure)
    found: dict[SpecCheck, list[SpecFinding]] = {
        SpecCheck.controlled_process_without_feedback: list(
            _controlled_process_without_feedback(index)
        ),
        SpecCheck.controlled_process_unobserved: list(
            _controlled_process_unobserved(index)
        ),
        SpecCheck.action_without_process_model_refs: list(
            _action_without_process_model_refs(index)
        ),
        SpecCheck.process_model_variable_without_values: list(
            _process_model_variable_without_values(index)
        ),
        SpecCheck.hazard_without_constraint: list(
            _hazard_without_constraint(loss_analysis)
        ),
    }
    if ica_enumeration is not None:
        found[SpecCheck.hazard_without_ica] = list(
            _hazard_without_ica(loss_analysis, ica_enumeration)
        )
        found[SpecCheck.ica_without_related_constraints] = list(
            _ica_without_related_constraints(ica_enumeration)
        )
    checks = tuple(
        SpecCheckSummary(check=check, status="run", findings=len(found[check]))
        if check in found
        else SpecCheckSummary(
            check=check, status="not_run", findings=0, reason=ica_unavailable_reason
        )
        for check in SpecCheck
    )
    findings = tuple(finding for check in SpecCheck for finding in found.get(check, ()))
    return SpecDiagnostics(checks=checks, findings=findings)


def spec_diagnostics_yaml(diagnostics: SpecDiagnostics) -> str:
    """Return the artifact text; an unset disposition is written as ``null``."""
    return yaml_text(diagnostics, exclude_none=False)


def write_spec_diagnostics(output_dir: Path, diagnostics: SpecDiagnostics) -> Path:
    """Write ``spec-diagnostics.yaml`` in *output_dir* and return its path."""
    path = Path(output_dir) / SPEC_DIAGNOSTICS_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(spec_diagnostics_yaml(diagnostics), encoding="utf-8")
    return path


def read_spec_diagnostics(path: Path) -> SpecDiagnostics:
    """Load a written artifact, including any dispositions recorded since."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return SpecDiagnostics.model_validate(data)


__all__ = [
    "ICA_CHECKS",
    "SPEC_DIAGNOSTICS_FILENAME",
    "SPEC_DIAGNOSTICS_SCHEMA_VERSION",
    "FindingDisposition",
    "SpecCheck",
    "SpecCheckSummary",
    "SpecDiagnostics",
    "SpecFinding",
    "diagnose_final_artifacts",
    "read_spec_diagnostics",
    "spec_diagnostics_yaml",
    "write_spec_diagnostics",
]

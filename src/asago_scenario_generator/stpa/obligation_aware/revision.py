"""One bounded, additive structural revision round.

Adapters return request-local handles.  This module owns the only place where
those handles become canonical STPA identifiers, so a provider can neither
replace baseline records nor smuggle arbitrary identifiers into the final
loss/control structure.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from typing import Any, Literal

from asago_scenario_generator.models.canonical import (
    canonical_json_bytes,
    compute_framed_digest,
)
from asago_scenario_generator.models.artifact_pin import Digest
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationCallEvidence,
    MissingStructuralConcept,
    RevisionAddition,
    StructuralRevisionDelta,
)
from asago_scenario_generator.stpa.infra.llm_helpers import count_requests
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.obligation_aware.calls import call_evidence
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    AnalysisControls,
    DraftCoordinationLink,
    RevisionDraft,
    StructuralRevisionRequest,
    StructuralRevisionResponse,
    default_synthesis_controls,
)


ADDITION_DIGEST_DOMAIN = "asago-scenario-generator:stpa-structural-addition:v1"
REVISION_RESPONSE_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-revision-response:v1"
)


def _next_number(ids: Sequence[str], pattern: str) -> int:
    """Return the first free integer after the largest matching identifier."""
    expression = re.compile(pattern)
    numbers = [
        int(match.group(1)) for value in ids if (match := expression.match(value))
    ]
    return max(numbers, default=0) + 1


def _sorted_handles(values: Sequence[Any]) -> tuple[Any, ...]:
    """Sort request-local records by handle for deterministic allocation."""
    return tuple(sorted(values, key=lambda item: item.handle))


def _all_draft_handles(draft: RevisionDraft) -> tuple[str, ...]:
    """Collect every request-local handle, including child and mechanism nodes."""
    values: list[str] = []
    for collection in (
        draft.losses,
        draft.hazards,
        draft.security_constraints,
        draft.responsibilities,
        draft.controlled_processes,
        draft.process_model_parts,
        draft.control_actions,
        draft.feedback_channels,
        draft.coordination_links,
    ):
        values.extend(item.handle for item in collection)
    values.extend(
        child.handle
        for responsibility in draft.responsibilities
        for child in responsibility.responsibility_constraints
    )
    values.extend(link.mechanism.handle for link in draft.coordination_links)
    if len(values) != len(set(values)):
        raise ValueError("revision draft handles must be globally unique")
    return tuple(sorted(values))


def _reject_duplicate_additions(draft: RevisionDraft) -> None:
    """Reject semantically duplicate request-local additions."""
    collections = (
        draft.losses,
        draft.hazards,
        draft.security_constraints,
        draft.responsibilities,
        draft.controlled_processes,
        draft.process_model_parts,
        draft.control_actions,
        draft.feedback_channels,
        draft.coordination_links,
    )
    for values in collections:
        payloads: set[bytes] = set()
        for value in values:
            payload = value.model_dump(mode="json", exclude={"handle"})
            if isinstance(value, DraftCoordinationLink):
                # Coordination mechanism handles are request-local too; their
                # semantic identity should not make otherwise equal links
                # appear distinct.
                mechanism = payload.get("mechanism")
                if isinstance(mechanism, dict):
                    mechanism.pop("handle", None)
            encoded = canonical_json_bytes(payload)
            if encoded in payloads:
                raise ValueError("revision draft contains duplicate additions")
            payloads.add(encoded)


def _resolve(
    value: str | None,
    handle_map: Mapping[str, str],
    valid_ids: set[str],
    label: str,
) -> str | None:
    """Resolve one existing ID or request-local handle."""
    if value is None:
        return None
    result = handle_map.get(value, value)
    if result not in valid_ids:
        raise ValueError(f"{label} references unknown identity '{value}'")
    return result


def _element_ref(
    ref_type: Literal["responsibility", "controlled_process"] | None,
    ref_id: str | None,
    ref_handle: str | None,
    handle_map: Mapping[str, str],
    resp_ids: set[str],
    cp_ids: set[str],
    label: str,
) -> ElementRef | None:
    """Resolve a typed responsibility/controlled-process reference."""
    if ref_type is None:
        if ref_id is not None or ref_handle is not None:
            raise ValueError(f"{label} requires a reference type")
        return None
    target = _element_target(ref_id, ref_handle, handle_map, label)
    if ref_type == "responsibility":
        kind, valid_ids, reference_type = (
            "responsibility",
            resp_ids,
            ReferenceType.responsibility,
        )
    else:
        kind, valid_ids, reference_type = (
            "controlled process",
            cp_ids,
            ReferenceType.controlled_process,
        )
    if target not in valid_ids:
        raise ValueError(f"{label} references unknown {kind} '{target}'")
    return ElementRef(type=reference_type, id=target)


def _element_target(
    ref_id: str | None,
    ref_handle: str | None,
    handle_map: Mapping[str, str],
    label: str,
) -> str:
    if ref_id is not None and ref_handle is not None:
        raise ValueError(f"{label} cannot specify both ID and handle")
    target = ref_handle if ref_handle is not None else ref_id
    if target is None:
        raise ValueError(f"{label} requires an ID or handle")
    return handle_map.get(target, target)


def _addition(
    concept_type: str,
    description: str,
    references: Sequence[str],
    handle: str,
) -> RevisionAddition:
    """Create a deterministic content-addressed addition record."""
    payload = {
        "concept_type": concept_type,
        "description": description,
        "references": tuple(sorted(set(references))),
        "request_handle": handle,
    }
    digest = compute_framed_digest(ADDITION_DIGEST_DOMAIN, payload)
    return RevisionAddition(
        addition_id=f"addition:v1:{digest}",
        concept_type=concept_type,
        description=description,
        references=tuple(sorted(set(references))),
        request_handle=handle,
    )


@dataclass(frozen=True, slots=True)
class RevisionCompilation:
    """Compiled final authority plus the accepted typed additive delta."""

    loss_analysis: LossAnalysis
    control_structure: ControlStructure
    delta: StructuralRevisionDelta
    handle_map: dict[str, str]


@dataclass(slots=True)
class _RevisionAllocation:
    """Request-local identities and closed reference sets for one draft."""

    handles: dict[str, str]
    baseline_constraint_ids: tuple[str, ...]
    all_resp_ids: set[str]
    all_cp_ids: set[str]
    all_hazard_ids: set[str]
    all_constraint_ids: set[str]
    all_pm_ids: set[str]


@dataclass(slots=True)
class _RevisionRecords:
    """Mutable record lists assembled before the final model boundary."""

    losses: list[Loss]
    hazards: list[Hazard]
    security_constraints: list[SecurityConstraint]
    loss_ids: set[str]


def _validate_revision_inputs(
    draft: RevisionDraft,
    baseline_loss_analysis: LossAnalysis,
    baseline_control_structure: ControlStructure,
) -> tuple[LossAnalysis, ControlStructure]:
    """Validate inputs and copy the baseline before any mutation can occur."""
    if not isinstance(draft, RevisionDraft):
        raise TypeError("draft must be a RevisionDraft")
    if not isinstance(baseline_loss_analysis, LossAnalysis):
        raise TypeError("baseline_loss_analysis must be a LossAnalysis")
    if not isinstance(baseline_control_structure, ControlStructure):
        raise TypeError("baseline_control_structure must be a ControlStructure")
    _all_draft_handles(draft)
    _reject_duplicate_additions(draft)
    return (
        baseline_loss_analysis.model_copy(deep=True),
        baseline_control_structure.model_copy(deep=True),
    )


def _allocate_numbered_handles(
    values: Sequence[Any],
    existing_ids: Sequence[str],
    *,
    prefix: str,
    pattern: str,
    handles: dict[str, str],
) -> None:
    """Allocate sorted request handles from the next free numeric identity."""
    next_number = _next_number(existing_ids, pattern)
    for item in _sorted_handles(values):
        handles[item.handle] = f"{prefix}{next_number}"
        next_number += 1


def _allocate_responsibility_handles(
    values: Sequence[Any],
    existing_ids: Sequence[str],
    handles: dict[str, str],
) -> None:
    """Allocate or resolve responsibility handles against the baseline."""
    next_number = _next_number(existing_ids, r"^RESP-(\d+)$")
    for item in _sorted_handles(values):
        if item.existing_resp_id is None:
            handles[item.handle] = f"RESP-{next_number}"
            next_number += 1
            continue
        if item.existing_resp_id not in existing_ids:
            raise ValueError(
                f"responsibility draft references unknown existing responsibility '{item.existing_resp_id}'"
            )
        handles[item.handle] = item.existing_resp_id


def _allocate_child_handles(
    values: Sequence[Any],
    *,
    handles: dict[str, str],
    counters: dict[str, int],
    ids: list[str],
    prefix: str,
    kind: str,
    unknown_detail: str,
) -> None:
    """Allocate PM, CA, or FB identities under an owning responsibility."""
    for item in _sorted_handles(values):
        target = item.responsibility_handle or item.responsibility_id
        if target is None:
            raise ValueError(f"{kind} '{item.handle}' requires a responsibility")
        target = handles.get(target, target)
        if target not in counters:
            raise ValueError(f"{unknown_detail} '{target}'")
        identity = f"{prefix}-{target.removeprefix('RESP-')}-{counters[target]}"
        counters[target] += 1
        handles[item.handle] = identity
        ids.append(identity)


def _allocate_top_level_handles(
    draft: RevisionDraft,
    baseline_loss_analysis: LossAnalysis,
    baseline_control_structure: ControlStructure,
) -> tuple[
    dict[str, str],
    list[str],
    list[str],
    list[str],
    list[str],
    list[str],
]:
    """Allocate loss, hazard, constraint, responsibility, and CP identities."""
    handles: dict[str, str] = {}
    loss_ids = [
        item.loss_id
        for item in (
            *baseline_loss_analysis.risk_card_losses,
            *baseline_loss_analysis.use_case_losses,
        )
    ]
    _allocate_numbered_handles(
        draft.losses,
        loss_ids,
        prefix="L-",
        pattern=r"^L-(\d+)$",
        handles=handles,
    )
    hazard_ids = [item.hazard_id for item in baseline_loss_analysis.hazards]
    _allocate_numbered_handles(
        draft.hazards,
        hazard_ids,
        prefix="H-",
        pattern=r"^H-(\d+)$",
        handles=handles,
    )
    constraint_ids = [
        item.constraint_id for item in baseline_loss_analysis.security_constraints
    ]
    _allocate_numbered_handles(
        draft.security_constraints,
        constraint_ids,
        prefix="SC-",
        pattern=r"^SC-(\d+)$",
        handles=handles,
    )
    resp_ids = [item.resp_id for item in baseline_control_structure.responsibilities]
    _allocate_responsibility_handles(draft.responsibilities, resp_ids, handles)
    cp_ids = [item.cp_id for item in baseline_control_structure.controlled_processes]
    _allocate_numbered_handles(
        draft.controlled_processes,
        cp_ids,
        prefix="CP-",
        pattern=r"^CP-(\d+)$",
        handles=handles,
    )
    return handles, loss_ids, hazard_ids, constraint_ids, resp_ids, cp_ids


def _allocate_child_and_link_handles(
    draft: RevisionDraft,
    baseline_control_structure: ControlStructure,
    handles: dict[str, str],
    resp_ids: Sequence[str],
) -> list[str]:
    """Allocate child identities, then coordination links and mechanisms."""
    pm_ids = [
        item.pm_id
        for responsibility in baseline_control_structure.responsibilities
        for item in responsibility.process_model_parts
    ]
    all_responsibility_records = list(baseline_control_structure.responsibilities)
    all_responsibility_records.extend(
        Responsibility(resp_id=handles[item.handle], description=item.description)
        for item in _sorted_handles(draft.responsibilities)
        if item.existing_resp_id is None
    )
    next_pm_by_resp = _next_child_numbers(
        all_responsibility_records, "PM", "process_model_parts", "pm_id"
    )
    next_ca_by_resp = _next_child_numbers(
        all_responsibility_records, "CA", "control_actions", "ca_id"
    )
    next_fb_by_resp = _next_child_numbers(
        all_responsibility_records, "FB", "feedback_channels", "fb_id"
    )
    _allocate_child_handles(
        draft.process_model_parts,
        handles=handles,
        counters=next_pm_by_resp,
        ids=pm_ids,
        prefix="PM",
        kind="process model part",
        unknown_detail="process model part references unknown responsibility",
    )
    _allocate_child_handles(
        draft.control_actions,
        handles=handles,
        counters=next_ca_by_resp,
        ids=[],
        prefix="CA",
        kind="control action",
        unknown_detail="control action references unknown responsibility",
    )
    _allocate_child_handles(
        draft.feedback_channels,
        handles=handles,
        counters=next_fb_by_resp,
        ids=[],
        prefix="FB",
        kind="feedback channel",
        unknown_detail="feedback channel references unknown responsibility",
    )
    _allocate_link_handles(draft, baseline_control_structure, handles)
    return pm_ids


def _next_child_numbers(
    records: Sequence[Responsibility], prefix: str, children_attr: str, id_attr: str
) -> dict[str, int]:
    """Return the next free child number per responsibility."""
    return {
        resp.resp_id: _next_number(
            [getattr(item, id_attr) for item in getattr(resp, children_attr)],
            rf"^{prefix}-{re.escape(resp.resp_id.removeprefix('RESP-'))}-(\d+)$",
        )
        for resp in records
    }


def _allocate_link_handles(
    draft: RevisionDraft,
    baseline_control_structure: ControlStructure,
    handles: dict[str, str],
) -> None:
    link_ids = [item.link_id for item in baseline_control_structure.coordination_links]
    next_link = _next_number(link_ids, r"^CL-(\d+)$")
    mechanism_ids = [
        item.coordination_mechanism.cm_id
        for item in baseline_control_structure.coordination_links
    ]
    next_mechanism = _next_number(mechanism_ids, r"^CM-(\d+)$")
    for item in _sorted_handles(draft.coordination_links):
        handles[item.handle] = f"CL-{next_link}"
        next_link += 1
        handles[item.mechanism.handle] = f"CM-{next_mechanism}"
        next_mechanism += 1


def _with_new_handles(
    baseline_ids: Sequence[str], handles: Mapping[str, str], prefix: str
) -> set[str]:
    return set(baseline_ids) | {
        value for value in handles.values() if value.startswith(prefix)
    }


def _allocate_revision_handles(
    draft: RevisionDraft,
    baseline_loss_analysis: LossAnalysis,
    baseline_control_structure: ControlStructure,
) -> _RevisionAllocation:
    """Allocate every request handle before resolving any reference."""
    (
        handles,
        _loss_ids,
        hazard_ids,
        constraint_ids,
        resp_ids,
        cp_ids,
    ) = _allocate_top_level_handles(
        draft, baseline_loss_analysis, baseline_control_structure
    )
    pm_ids = _allocate_child_and_link_handles(
        draft, baseline_control_structure, handles, resp_ids
    )
    return _RevisionAllocation(
        handles=handles,
        baseline_constraint_ids=tuple(constraint_ids),
        all_resp_ids=_with_new_handles(resp_ids, handles, "RESP-"),
        all_cp_ids=_with_new_handles(cp_ids, handles, "CP-"),
        all_hazard_ids=_with_new_handles(hazard_ids, handles, "H-"),
        all_constraint_ids=_with_new_handles(constraint_ids, handles, "SC-"),
        all_pm_ids=_with_new_handles(pm_ids, handles, "PM-"),
    )


def _build_revision_records(
    draft: RevisionDraft,
    baseline_loss_analysis: LossAnalysis,
    allocation: _RevisionAllocation,
) -> _RevisionRecords:
    """Build additive loss-analysis records with resolved exact references."""
    losses = [
        *baseline_loss_analysis.risk_card_losses,
        *baseline_loss_analysis.use_case_losses,
    ]
    for item in _sorted_handles(draft.losses):
        provenance = LossProvenance(item.provenance)
        losses.append(
            Loss(
                loss_id=allocation.handles[item.handle],
                description=item.description,
                provenance=provenance,
                source_risk_cards=list(item.source_risk_cards)
                if provenance is LossProvenance.risk_card
                else [],
            )
        )
    loss_ids = {item.loss_id for item in losses}
    hazards = list(baseline_loss_analysis.hazards)
    for item in _sorted_handles(draft.hazards):
        refs = tuple(
            dict.fromkeys(
                [
                    *_resolve_many(
                        item.related_loss_ids,
                        allocation.handles,
                        loss_ids,
                        "hazard losses",
                    ),
                    *_resolve_many(
                        item.related_loss_handles,
                        allocation.handles,
                        loss_ids,
                        "hazard losses",
                    ),
                ]
            )
        )
        hazards.append(
            Hazard(
                hazard_id=allocation.handles[item.handle],
                description=item.description,
                related_losses=list(refs),
            )
        )
    security_constraints = list(baseline_loss_analysis.security_constraints)
    for item in _sorted_handles(draft.security_constraints):
        refs = tuple(
            dict.fromkeys(
                [
                    *_resolve_many(
                        item.related_hazard_ids,
                        allocation.handles,
                        allocation.all_hazard_ids,
                        "constraint hazards",
                    ),
                    *_resolve_many(
                        item.related_hazard_handles,
                        allocation.handles,
                        allocation.all_hazard_ids,
                        "constraint hazards",
                    ),
                ]
            )
        )
        security_constraints.append(
            SecurityConstraint(
                constraint_id=allocation.handles[item.handle],
                # Phase 1.3 as amended: the draft statement is the authored
                # rule with no conditions, so the composed description
                # matches the draft text exactly.
                rule=item.description,
                applies_when=[],
                related_hazards=list(refs),
            )
        )
    return _RevisionRecords(losses, hazards, security_constraints, loss_ids)


def _build_responsibilities(
    draft: RevisionDraft,
    baseline_control_structure: ControlStructure,
    handles: Mapping[str, str],
) -> dict[str, Responsibility]:
    """Copy baseline responsibilities and append new ones."""
    responsibilities = [
        item.model_copy(deep=True)
        for item in baseline_control_structure.responsibilities
    ]
    for item in _sorted_handles(draft.responsibilities):
        if item.existing_resp_id is None:
            responsibilities.append(
                Responsibility(
                    resp_id=handles[item.handle], description=item.description
                )
            )
    return {item.resp_id: item for item in responsibilities}


def _append_loss_hazard_additions(
    draft: RevisionDraft,
    allocation: _RevisionAllocation,
    loss_ids: set[str],
) -> list[RevisionAddition]:
    """Record deterministic additions for losses and hazards."""
    additions: list[RevisionAddition] = []
    for item in _sorted_handles(draft.losses):
        additions.append(_addition("loss", item.description, (), item.handle))
    for item in _sorted_handles(draft.hazards):
        references = [
            *_resolve_many(
                item.related_loss_ids, allocation.handles, loss_ids, "hazard losses"
            ),
            *_resolve_many(
                item.related_loss_handles, allocation.handles, loss_ids, "hazard losses"
            ),
        ]
        additions.append(_addition("hazard", item.description, references, item.handle))
    return additions


def _append_constraint_additions(
    draft: RevisionDraft,
    allocation: _RevisionAllocation,
    resp_by_id: Mapping[str, Responsibility],
) -> tuple[list[RevisionAddition], set[str]]:
    """Record constraints and attach their assignments to responsibilities."""
    additions: list[RevisionAddition] = []
    assigned_new_constraints: set[str] = set()
    for item in _sorted_handles(draft.security_constraints):
        references = [
            *_resolve_many(
                item.related_hazard_ids,
                allocation.handles,
                allocation.all_hazard_ids,
                "constraint hazards",
            ),
            *_resolve_many(
                item.related_hazard_handles,
                allocation.handles,
                allocation.all_hazard_ids,
                "constraint hazards",
            ),
        ]
        additions.append(
            _addition("constraint", item.description, references, item.handle)
        )
        assigned = [
            *_resolve_many(
                item.responsibility_ids,
                allocation.handles,
                allocation.all_resp_ids,
                "constraint responsibilities",
            ),
            *_resolve_many(
                item.responsibility_handles,
                allocation.handles,
                allocation.all_resp_ids,
                "constraint responsibilities",
            ),
        ]
        for resp_id in assigned:
            resolved_resp = allocation.handles.get(resp_id, resp_id)
            if resolved_resp not in resp_by_id:
                raise ValueError(
                    f"constraint assignment references unknown responsibility '{resp_id}'"
                )
            target = resp_by_id[resolved_resp]
            constraint_id = allocation.handles[item.handle]
            if constraint_id not in target.security_constraint_refs:
                target.security_constraint_refs.append(constraint_id)
            assigned_new_constraints.add(constraint_id)
    return additions, assigned_new_constraints


def _append_responsibility_additions(
    draft: RevisionDraft,
    allocation: _RevisionAllocation,
    resp_by_id: Mapping[str, Responsibility],
    assigned_new_constraints: set[str],
    additions: list[RevisionAddition],
) -> None:
    """Attach constraint and child additions to each draft responsibility."""
    new_constraint_ids = allocation.all_constraint_ids - set(
        allocation.baseline_constraint_ids
    )
    for item in _sorted_handles(draft.responsibilities):
        target = resp_by_id[allocation.handles[item.handle]]
        refs = [
            *_resolve_many(
                item.security_constraint_ids,
                allocation.handles,
                allocation.all_constraint_ids,
                "responsibility constraints",
            ),
            *_resolve_many(
                item.security_constraint_handles,
                allocation.handles,
                allocation.all_constraint_ids,
                "responsibility constraints",
            ),
        ]
        for constraint_id in refs:
            if constraint_id not in target.security_constraint_refs:
                target.security_constraint_refs.append(constraint_id)
            if constraint_id in new_constraint_ids:
                assigned_new_constraints.add(constraint_id)
        used_rc = [rc.rc_id for rc in target.responsibility_constraints]
        next_rc = _next_number(
            used_rc,
            rf"^RC-{re.escape(target.resp_id.removeprefix('RESP-'))}-(\d+)$",
        )
        for child in _sorted_handles(item.responsibility_constraints):
            identity = f"RC-{target.resp_id.removeprefix('RESP-')}-{next_rc}"
            next_rc += 1
            target.responsibility_constraints.append(
                ResponsibilityConstraint(rc_id=identity, description=child.description)
            )
            additions.append(
                _addition(
                    "responsibility", child.description, (target.resp_id,), child.handle
                )
            )
            allocation.handles[child.handle] = identity
        if item.existing_resp_id is None:
            additions.append(
                _addition("responsibility", item.description, (), item.handle)
            )


def _append_process_model_parts(
    draft: RevisionDraft,
    allocation: _RevisionAllocation,
    resp_by_id: Mapping[str, Responsibility],
    additions: list[RevisionAddition],
) -> None:
    """Attach process-model additions to their owning responsibilities."""
    for item in _sorted_handles(draft.process_model_parts):
        target_key = item.responsibility_handle or item.responsibility_id
        target = (
            allocation.handles.get(target_key, target_key)
            if target_key is not None
            else None
        )
        if target is None or target not in resp_by_id:
            raise ValueError(
                f"process model part '{item.handle}' references unknown responsibility"
            )
        source = _element_ref(
            item.feedback_source_type,
            item.feedback_source_id,
            item.feedback_source_handle,
            allocation.handles,
            allocation.all_resp_ids,
            allocation.all_cp_ids,
            f"process model part '{item.handle}' feedback source",
        )
        resp_by_id[target].process_model_parts.append(
            ProcessModelPart(
                pm_id=allocation.handles[item.handle],
                description=item.description,
                feedback_source=source,
            )
        )
        additions.append(
            _addition("process_model_part", item.description, (target,), item.handle)
        )


def _append_control_actions(
    draft: RevisionDraft,
    allocation: _RevisionAllocation,
    resp_by_id: Mapping[str, Responsibility],
    additions: list[RevisionAddition],
) -> None:
    """Attach control-action additions to their owning responsibilities."""
    for item in _sorted_handles(draft.control_actions):
        target_key = item.responsibility_handle or item.responsibility_id
        target_resp = (
            allocation.handles.get(target_key, target_key)
            if target_key is not None
            else None
        )
        if target_resp is None or target_resp not in resp_by_id:
            raise ValueError(
                f"control action '{item.handle}' references unknown responsibility"
            )
        target = _element_ref(
            item.target_type,
            item.target_id,
            item.target_handle,
            allocation.handles,
            allocation.all_resp_ids,
            allocation.all_cp_ids,
            f"control action '{item.handle}' target",
        )
        if target is None:
            raise ValueError(
                f"control action '{item.handle}' requires a controlled-process path"
            )
        resp_by_id[target_resp].control_actions.append(
            ControlAction(
                ca_id=allocation.handles[item.handle],
                description=item.description,
                target=target,
            )
        )
        additions.append(
            _addition("control_action", item.description, (target_resp,), item.handle)
        )


def _append_feedback_channels(
    draft: RevisionDraft,
    allocation: _RevisionAllocation,
    resp_by_id: Mapping[str, Responsibility],
    additions: list[RevisionAddition],
) -> None:
    """Attach feedback-channel additions to their owning responsibilities."""
    for item in _sorted_handles(draft.feedback_channels):
        target_key = item.responsibility_handle or item.responsibility_id
        target_resp = (
            allocation.handles.get(target_key, target_key)
            if target_key is not None
            else None
        )
        if target_resp is None or target_resp not in resp_by_id:
            raise ValueError(
                f"feedback channel '{item.handle}' references unknown responsibility"
            )
        updates = _resolve(
            item.updates_handle or item.updates_id,
            allocation.handles,
            allocation.all_pm_ids,
            f"feedback channel '{item.handle}' updates",
        )
        if updates is None:
            raise ValueError(
                f"feedback channel '{item.handle}' requires a process model part"
            )
        source = _element_ref(
            item.source_type,
            item.source_id,
            item.source_handle,
            allocation.handles,
            allocation.all_resp_ids,
            allocation.all_cp_ids,
            f"feedback channel '{item.handle}' source",
        )
        resp_by_id[target_resp].feedback_channels.append(
            FeedbackChannel(
                fb_id=allocation.handles[item.handle],
                description=item.description,
                updates=updates,
                source=source,
            )
        )
        additions.append(
            _addition(
                "feedback_channel",
                item.description,
                (target_resp, updates),
                item.handle,
            )
        )


def _append_controlled_processes(
    draft: RevisionDraft,
    baseline_control_structure: ControlStructure,
    handles: Mapping[str, str],
) -> tuple[list[ControlledProcess], list[RevisionAddition]]:
    """Copy baseline processes and append new process additions."""
    controlled_processes = [
        item.model_copy(deep=True)
        for item in baseline_control_structure.controlled_processes
    ]
    additions: list[RevisionAddition] = []
    for item in _sorted_handles(draft.controlled_processes):
        controlled_processes.append(
            ControlledProcess(cp_id=handles[item.handle], description=item.description)
        )
        additions.append(
            _addition("controlled_process", item.description, (), item.handle)
        )
    return controlled_processes, additions


def _append_coordination_links(
    draft: RevisionDraft,
    baseline_control_structure: ControlStructure,
    allocation: _RevisionAllocation,
) -> tuple[list[CoordinationLink], list[RevisionAddition]]:
    """Copy baseline links and append new coordination additions."""
    coordination_links = [
        item.model_copy(deep=True)
        for item in baseline_control_structure.coordination_links
    ]
    additions: list[RevisionAddition] = []
    for item in _sorted_handles(draft.coordination_links):
        source = _resolve(
            item.source_handle or item.source_id,
            allocation.handles,
            allocation.all_resp_ids,
            f"coordination link '{item.handle}' source",
        )
        target = _resolve(
            item.target_handle or item.target_id,
            allocation.handles,
            allocation.all_resp_ids,
            f"coordination link '{item.handle}' target",
        )
        shared_pm = _resolve(
            item.shared_pm_handle or item.shared_pm_id,
            allocation.handles,
            allocation.all_pm_ids,
            f"coordination link '{item.handle}' shared PM",
        )
        if source is None or target is None or shared_pm is None:
            raise ValueError(
                f"coordination link '{item.handle}' requires source, target, and shared PM"
            )
        mechanism_id = allocation.handles[item.mechanism.handle]
        coordination_links.append(
            CoordinationLink(
                link_id=allocation.handles[item.handle],
                source=source,
                target=target,
                shared_pm=shared_pm,
                coordination_mechanism=CoordinationMechanism(
                    cm_id=mechanism_id,
                    description=item.mechanism.description,
                    payload=item.mechanism.payload,
                ),
                description=item.description,
            )
        )
        additions.append(
            _addition(
                "coordination_mechanism",
                item.mechanism.description,
                (allocation.handles[item.handle],),
                item.mechanism.handle,
            )
        )
        additions.append(
            _addition(
                "coordination_link",
                item.description,
                (source, target, shared_pm, mechanism_id),
                item.handle,
            )
        )
    return coordination_links, additions


def _finish_revision_compilation(
    draft: RevisionDraft,
    baseline_loss_analysis: LossAnalysis,
    baseline_control_structure: ControlStructure,
    records: _RevisionRecords,
    resp_by_id: Mapping[str, Responsibility],
    controlled_processes: list[ControlledProcess],
    coordination_links: list[CoordinationLink],
    additions: Sequence[RevisionAddition],
    assigned_new_constraints: set[str],
    allocation: _RevisionAllocation,
    trigger_gap_ids: Sequence[str],
) -> RevisionCompilation:
    """Build the closed final models and verify additive preservation."""
    final_la = LossAnalysis(
        risk_card_losses=[
            item
            for item in records.losses
            if item.provenance is LossProvenance.risk_card
        ],
        use_case_losses=[
            item
            for item in records.losses
            if item.provenance is not LossProvenance.risk_card
        ],
        hazards=records.hazards,
        security_constraints=records.security_constraints,
    )
    new_constraint_ids = {
        allocation.handles[item.handle] for item in draft.security_constraints
    }
    if missing := sorted(new_constraint_ids - assigned_new_constraints):
        raise ValueError(
            "every new security constraint must be assigned to a responsibility: "
            + ", ".join(missing)
        )
    final_cs = ControlStructure(
        responsibilities=tuple(resp_by_id.values()),
        controlled_processes=controlled_processes,
        coordination_links=coordination_links,
    )
    if not _baseline_records_preserved(
        baseline_loss_analysis, final_la, baseline_control_structure, final_cs
    ):
        raise ValueError("revision draft replaced or removed a baseline record")
    delta = StructuralRevisionDelta(
        additions=tuple(additions),
        trigger_gap_ids=tuple(trigger_gap_ids),
        evidence=("revision:deterministic-compiler",),
    )
    return RevisionCompilation(
        loss_analysis=final_la,
        control_structure=final_cs,
        delta=delta,
        handle_map=dict(sorted(allocation.handles.items())),
    )


def compile_revision_draft(
    draft: RevisionDraft,
    *,
    baseline_loss_analysis: LossAnalysis,
    baseline_control_structure: ControlStructure,
    trigger_gap_ids: Sequence[str] = (),
) -> RevisionCompilation:
    """Compile one request-local draft into additive, validated STPA models."""
    baseline_loss_analysis, baseline_control_structure = _validate_revision_inputs(
        draft, baseline_loss_analysis, baseline_control_structure
    )
    allocation = _allocate_revision_handles(
        draft, baseline_loss_analysis, baseline_control_structure
    )
    records = _build_revision_records(draft, baseline_loss_analysis, allocation)
    resp_by_id = _build_responsibilities(
        draft, baseline_control_structure, allocation.handles
    )
    additions = _append_loss_hazard_additions(draft, allocation, records.loss_ids)
    constraint_additions, assigned_new_constraints = _append_constraint_additions(
        draft, allocation, resp_by_id
    )
    additions.extend(constraint_additions)
    _append_responsibility_additions(
        draft,
        allocation,
        resp_by_id,
        assigned_new_constraints,
        additions,
    )
    _append_process_model_parts(draft, allocation, resp_by_id, additions)
    _append_control_actions(draft, allocation, resp_by_id, additions)
    _append_feedback_channels(draft, allocation, resp_by_id, additions)
    controlled_processes, process_additions = _append_controlled_processes(
        draft, baseline_control_structure, allocation.handles
    )
    additions.extend(process_additions)
    coordination_links, link_additions = _append_coordination_links(
        draft, baseline_control_structure, allocation
    )
    additions.extend(link_additions)
    return _finish_revision_compilation(
        draft,
        baseline_loss_analysis,
        baseline_control_structure,
        records,
        resp_by_id,
        controlled_processes,
        coordination_links,
        additions,
        assigned_new_constraints,
        allocation,
        trigger_gap_ids,
    )


def _resolve_many(
    values: Sequence[str],
    handles: Mapping[str, str],
    valid_ids: set[str],
    label: str,
) -> tuple[str, ...]:
    """Resolve and validate a set of IDs/handles."""
    resolved: list[str] = []
    for value in values:
        target = _resolve(value, handles, valid_ids, label)
        if target is not None:
            resolved.append(target)
    return tuple(resolved)


def _baseline_records_preserved(
    baseline_la: LossAnalysis,
    final_la: LossAnalysis,
    baseline_cs: ControlStructure,
    final_cs: ControlStructure,
) -> bool:
    """Check that every baseline record remains, allowing additive children."""
    return _loss_analysis_preserved(
        baseline_la, final_la
    ) and _control_structure_preserved(baseline_cs, final_cs)


def _loss_analysis_preserved(baseline_la: LossAnalysis, final_la: LossAnalysis) -> bool:
    """Check that every baseline loss, hazard, and constraint is unchanged."""
    return (
        _records_preserved(
            (*baseline_la.risk_card_losses, *baseline_la.use_case_losses),
            (*final_la.risk_card_losses, *final_la.use_case_losses),
            "loss_id",
        )
        and _records_preserved(baseline_la.hazards, final_la.hazards, "hazard_id")
        and _records_preserved(
            baseline_la.security_constraints,
            final_la.security_constraints,
            "constraint_id",
        )
    )


def _records_preserved(
    baseline_items: Sequence[Any], final_items: Sequence[Any], id_attr: str
) -> bool:
    final = {getattr(item, id_attr): item for item in final_items}
    return not any(final.get(getattr(item, id_attr)) != item for item in baseline_items)


def _control_structure_preserved(
    baseline_cs: ControlStructure, final_cs: ControlStructure
) -> bool:
    """Check that every baseline structure record remains in the final one."""
    final_resp = {item.resp_id: item for item in final_cs.responsibilities}
    for baseline in baseline_cs.responsibilities:
        current = final_resp.get(baseline.resp_id)
        if current is None or not _responsibility_children_preserved(baseline, current):
            return False
    if any(
        item not in final_cs.controlled_processes
        for item in baseline_cs.controlled_processes
    ):
        return False
    return not any(
        item not in final_cs.coordination_links
        for item in baseline_cs.coordination_links
    )


def _responsibility_children_preserved(
    baseline: Responsibility, current: Responsibility
) -> bool:
    """Check existing children remain even if new children were appended."""
    return (
        all(
            child in current.responsibility_constraints
            for child in baseline.responsibility_constraints
        )
        and all(
            child in current.process_model_parts
            for child in baseline.process_model_parts
        )
        and all(child in current.control_actions for child in baseline.control_actions)
        and all(
            child in current.feedback_channels for child in baseline.feedback_channels
        )
    )


@dataclass(frozen=True, slots=True)
class RevisionRunResult:
    """Result of the one permitted revision stage."""

    status: Literal["not_required", "applied", "rejected", "technical_failure"]
    baseline_loss_analysis: LossAnalysis
    baseline_control_structure: ControlStructure
    final_loss_analysis: LossAnalysis
    final_control_structure: ControlStructure
    trigger_obligation_ids: tuple[str, ...] = ()
    trigger_gap_ids: tuple[str, ...] = ()
    request: StructuralRevisionRequest | None = None
    response: StructuralRevisionResponse | None = None
    draft: RevisionDraft | None = None
    delta: StructuralRevisionDelta | None = None
    handle_map: dict[str, str] | None = None
    call_evidence: ConsiderationCallEvidence | None = None
    diagnostics: tuple[str, ...] = ()


def _typed_revision_response(raw: Any) -> StructuralRevisionResponse:
    """Accept only the typed revision response the adapter contract names."""
    if isinstance(raw, StructuralRevisionResponse):
        return raw
    raise TypeError("revision adapter returned an unsupported response")


def _revision_call_evidence(
    request: StructuralRevisionRequest,
    controls: AnalysisControls,
    *,
    response: StructuralRevisionResponse | None,
    outcome: Literal["accepted", "rejected", "technical_failure"],
    requests_sent: int,
) -> ConsiderationCallEvidence:
    """Build one exact call record for the single revision attempt."""
    return call_evidence(
        "stpa-revision:one-round",
        requests_sent,
        outcome,
        request_digest=request.semantic_digest,
        controls=controls,
        response=response,
        digest_domain=REVISION_RESPONSE_DIGEST_DOMAIN,
    )


def _validate_gap_decisions(
    draft: RevisionDraft,
    gaps: Sequence[MissingStructuralConcept],
) -> None:
    """Validate request-local disposition coverage before compiling a delta."""
    _require_closed_gap_handles(draft, gaps)
    proposals = {
        item.gap_handle
        for item in draft.gap_decisions
        if item.disposition == "propose_addition"
    }
    if proposals and not _draft_has_additions(draft):
        raise ValueError(
            "propose_addition decisions require at least one request-local addition"
        )


def _require_closed_gap_handles(
    draft: RevisionDraft,
    gaps: Sequence[MissingStructuralConcept],
) -> None:
    """Require exactly one decision handle per request-local gap."""
    expected = {
        f"revision-gap-{index}"
        for index, _ in enumerate(
            sorted(gaps, key=lambda item: item.gap_id or ""), start=1
        )
    }
    actual = {item.gap_handle for item in draft.gap_decisions}
    unknown = actual - expected
    missing = expected - actual
    if unknown or missing:
        detail: list[str] = []
        if missing:
            detail.append("missing gap handles: " + ", ".join(sorted(missing)))
        if unknown:
            detail.append("unknown gap handles: " + ", ".join(sorted(unknown)))
        raise ValueError(
            "revision gap decisions do not close the request ("
            + "; ".join(detail)
            + ")"
        )


def _draft_has_additions(draft: RevisionDraft) -> bool:
    return bool(
        draft.losses
        or draft.hazards
        or draft.security_constraints
        or draft.responsibilities
        or draft.controlled_processes
        or draft.process_model_parts
        or draft.control_actions
        or draft.feedback_channels
        or draft.coordination_links
    )


def _request_revision(
    adapter: Any, request: StructuralRevisionRequest
) -> tuple[StructuralRevisionResponse | str, int]:
    """Ask the adapter once.

    Return its response, or the failure text, with the requests it sent.
    """
    with count_requests() as sent:
        try:
            return _typed_revision_response(adapter.revise(request)), sent.requests
        except Exception as exc:  # noqa: BLE001 - retain provider/protocol evidence
            failure = f"provider/protocol failure: {type(exc).__name__}: {exc}"
    return failure, sent.requests


def revise_structure_once(
    adapter: Any,
    *,
    gaps: Sequence[MissingStructuralConcept],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    trigger_obligation_ids: Sequence[str] = (),
    controls: AnalysisControls | None = None,
    plan_digest: Digest | None = None,
) -> RevisionRunResult:
    """Apply at most one additive revision request; never recurse."""
    baseline_la = loss_analysis.model_copy(deep=True)
    baseline_cs = control_structure.model_copy(deep=True)
    ordered_gaps = tuple(sorted(gaps, key=lambda item: item.gap_id or ""))
    obligations = tuple(sorted(set(trigger_obligation_ids)))
    gap_ids = tuple(item.gap_id for item in ordered_gaps if item.gap_id is not None)
    if not ordered_gaps:
        return RevisionRunResult(
            status="not_required",
            baseline_loss_analysis=baseline_la,
            baseline_control_structure=baseline_cs,
            final_loss_analysis=baseline_la,
            final_control_structure=baseline_cs,
        )
    if controls is None:
        controls = default_synthesis_controls()
    request = StructuralRevisionRequest(
        gaps=ordered_gaps,
        baseline_loss_analysis=baseline_la,
        baseline_control_structure=baseline_cs,
        controls=controls,
        plan_digest=plan_digest,
    )
    answer, requests_sent = _request_revision(adapter, request)
    run = _RevisionRun(
        request=request,
        controls=controls,
        baseline_la=baseline_la,
        baseline_cs=baseline_cs,
        obligations=obligations,
        gap_ids=gap_ids,
        requests_sent=requests_sent,
    )
    if isinstance(answer, str):
        return run.technical_failure(None, answer)
    response = answer
    if response.request_digest != request.semantic_digest:
        return run.technical_failure(
            response,
            "protocol failure: revision response is bound to another request",
        )
    try:
        _validate_gap_decisions(response.draft, ordered_gaps)
        compilation = compile_revision_draft(
            response.draft,
            baseline_loss_analysis=baseline_la,
            baseline_control_structure=baseline_cs,
            trigger_gap_ids=gap_ids,
        )
    except Exception as exc:  # noqa: BLE001 - retain compiler evidence
        return run.technical_failure(
            response, f"compile failure: {type(exc).__name__}: {exc}"
        )
    return run.outcome(response, compilation)


def _decisions_reject_all(draft: RevisionDraft) -> bool:
    """Return whether explicit gap decisions propose no addition at all."""
    return not any(
        item.disposition == "propose_addition" for item in draft.gap_decisions
    )


@dataclass(frozen=True)
class _RevisionRun:
    """The fixed request context shared by every revision outcome."""

    request: StructuralRevisionRequest
    controls: AnalysisControls
    baseline_la: LossAnalysis
    baseline_cs: ControlStructure
    obligations: tuple[str, ...]
    gap_ids: tuple[str, ...]
    requests_sent: int

    def technical_failure(
        self, response: StructuralRevisionResponse | None, diagnostic: str
    ) -> RevisionRunResult:
        return RevisionRunResult(
            status="technical_failure",
            baseline_loss_analysis=self.baseline_la,
            baseline_control_structure=self.baseline_cs,
            final_loss_analysis=self.baseline_la,
            final_control_structure=self.baseline_cs,
            trigger_obligation_ids=self.obligations,
            trigger_gap_ids=self.gap_ids,
            request=self.request,
            response=response,
            draft=None if response is None else response.draft,
            diagnostics=(diagnostic,),
            call_evidence=_revision_call_evidence(
                self.request,
                self.controls,
                response=response,
                outcome="technical_failure",
                requests_sent=self.requests_sent,
            ),
        )

    def outcome(
        self,
        response: StructuralRevisionResponse,
        compilation: RevisionCompilation,
    ) -> RevisionRunResult:
        if response.status == "rejected" or _decisions_reject_all(response.draft):
            return self.rejected(response, compilation)
        return self.applied(response, compilation)

    def rejected(
        self,
        response: StructuralRevisionResponse,
        compilation: RevisionCompilation,
    ) -> RevisionRunResult:
        decision_diagnostics = tuple(
            f"{item.gap_handle}: {item.disposition}: {item.rationale}"
            for item in response.draft.gap_decisions
        )
        diagnostics = (
            () if not response.draft.rationale else (response.draft.rationale,)
        ) + decision_diagnostics
        return RevisionRunResult(
            status="rejected",
            baseline_loss_analysis=self.baseline_la,
            baseline_control_structure=self.baseline_cs,
            final_loss_analysis=self.baseline_la,
            final_control_structure=self.baseline_cs,
            trigger_obligation_ids=self.obligations,
            trigger_gap_ids=self.gap_ids,
            request=self.request,
            response=response,
            draft=response.draft,
            delta=compilation.delta,
            handle_map=compilation.handle_map,
            diagnostics=diagnostics,
            call_evidence=_revision_call_evidence(
                self.request,
                self.controls,
                response=response,
                outcome="rejected",
                requests_sent=self.requests_sent,
            ),
        )

    def applied(
        self,
        response: StructuralRevisionResponse,
        compilation: RevisionCompilation,
    ) -> RevisionRunResult:
        call_evidence = _revision_call_evidence(
            self.request,
            self.controls,
            response=response,
            outcome="accepted",
            requests_sent=self.requests_sent,
        )
        return RevisionRunResult(
            status="applied",
            baseline_loss_analysis=self.baseline_la,
            baseline_control_structure=self.baseline_cs,
            final_loss_analysis=compilation.loss_analysis,
            final_control_structure=compilation.control_structure,
            trigger_obligation_ids=self.obligations,
            trigger_gap_ids=self.gap_ids,
            request=self.request,
            response=response,
            draft=response.draft,
            delta=compilation.delta,
            handle_map=compilation.handle_map,
            call_evidence=call_evidence,
        )


__all__ = [
    "RevisionCompilation",
    "RevisionRunResult",
    "compile_revision_draft",
    "revise_structure_once",
]

"""Pure, compact provider views for obligation-aware STPA stages.

Durable Phase 1 and STPA artifacts are intentionally not serialized into a
prompt.  The projector functions below select the small, explained graph a
particular model call needs; the provider adapter then renders that closed
view.  Provenance digests, pins, paths, scores, and raw mapping evidence stay
in the caller's typed records.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
import re
from typing import Any

import yaml

from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
    NeutralObligationBrief,
    ObligationRoute,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ElementRef,
    ReferenceType,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    PromptReference,
    ProviderApplicability,
    ProviderApplicabilityFact,
    ProviderConstraint,
    ProviderControlAction,
    ProviderCoordinationPath,
    ProviderFeedbackChannel,
    ProviderHazard,
    ProviderKnownConcern,
    ProviderObligationQuestion,
    ProviderProcessModelPart,
    ProviderResponsibility,
    ProviderRevisionContext,
    ProviderRevisionGap,
    ProviderReviewedRisk,
    ProviderRoutedRoute,
    ProviderRoutingContext,
    ProviderSlot,
    ProviderSystemResource,
    ProviderTargetIndex,
    PromptContractAudit,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import SlotPlaceholder


_UCA_TYPE_DEFINITIONS = """Four ICA (unsafe control action) types:

- NOT_PROVIDED: the required control action is absent when it is needed.
- INCORRECT: the action is provided, but its value, content, destination, or effect is unsafe.
- WRONG_TIMING: the action is provided too early, too late, or in an unsafe order.
- WRONG_DURATION: a continuous action stops too soon, continues too long, or is applied for an unsafe duration.

Timing and duration are distinct. A one-shot action cannot receive a
WRONG_DURATION finding without explicit continuing behavior. An ICA describes
unsafe controller behavior; a safeguard, recommendation, policy, or
requirement such as "implement MFA" or "add rate limiting" is not an ICA.
"""

_PROHIBITED_PROMPT_KEYS = (
    "semantic_digest",
    "plan_digest",
    "catalog_pins",
    "mapping_pins",
    "candidate_ids",
    "scores",
    "mitigations",
    "provider_call_id",
    "source_path",
    "artifact_path",
    "raw_mapping",
)
_ABSOLUTE_PATH = re.compile(r"(?:^|[\s\"'])/(?:Users|private|tmp|var|home)/")


def audit_prompt_contract(
    prompt_view: Any,
    *,
    system_prompt: str = "",
    user_prompt: str = "",
    stage: str = "obligation-aware",
    opaque_handles: Sequence[str] = (),
) -> PromptContractAudit:
    """Audit a typed view and rendered prompt before provider dispatch.

    The audit is deliberately deterministic and conservative.  It reports
    failures rather than deleting leaked fields or truncating a prompt; the
    caller decides whether to prevent the provider call.
    """
    issues: list[str] = []
    if not hasattr(prompt_view, "model_dump"):
        issues.append("prompt view is not a closed typed model")
        view_type = type(prompt_view).__name__
        payload: Any = {}
    else:
        view_type = type(prompt_view).__name__
        payload = prompt_view.model_dump(mode="json")
    field_names = _prompt_field_names(payload)
    for key in _PROHIBITED_PROMPT_KEYS:
        if key in field_names:
            issues.append(f"prohibited prompt field leaked: {key}")
    rendered = f"{system_prompt}\n{user_prompt}"
    if _ABSOLUTE_PATH.search(rendered):
        issues.append("absolute local path appears in rendered prompt")
    if "raw mapping" in rendered.lower() or "mapping json" in rendered.lower():
        issues.append("raw mapping payload appears in rendered prompt")
    if opaque_handles and not (
        "copy" in rendered.lower() and "unchanged" in rendered.lower()
    ):
        issues.append("opaque handles are not marked copy-only")
    if system_prompt and "json" not in system_prompt.lower():
        issues.append("requested JSON output schema is absent from system prompt")
    digest = compute_framed_digest(
        "asago-scenario-generator:prompt-contract-audit:v1",
        {"system_prompt": system_prompt, "user_prompt": user_prompt},
    )
    return PromptContractAudit(
        stage=stage,
        view_type=view_type,
        valid=not issues,
        issues=tuple(issues),
        prompt_digest=digest,
    )


def _prompt_field_names(value: Any) -> set[str]:
    """Collect exact serialized field names without inspecting prose values."""
    names: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            names.add(str(key))
            names.update(_prompt_field_names(child))
    elif isinstance(value, (list, tuple)):
        for child in value:
            names.update(_prompt_field_names(child))
    return names


def _yaml(value: Any) -> str:
    """Render a stable, readable prompt block."""
    return yaml.safe_dump(
        value,
        default_flow_style=False,
        sort_keys=True,
        allow_unicode=True,
    )


def authoritative_hazard_constraint_pairs(
    loss_analysis: LossAnalysis,
) -> tuple[tuple[str, str], ...]:
    """Return typed ``constraint_id -> hazard_id`` relationships in order.

    Provider-facing descriptions can be duplicated or contain stale parenthetical
    references. Routing therefore shares this ID-only relation projection with
    validation rather than asking a model or a human to infer a pair from prose.
    """
    if not isinstance(loss_analysis, LossAnalysis):
        raise TypeError("loss_analysis must be a LossAnalysis")
    return tuple(
        sorted(
            (
                constraint.constraint_id,
                hazard_id,
            )
            for constraint in loss_analysis.security_constraints
            for hazard_id in constraint.related_hazards
        )
    )


def _hazard_constraint_pair_ledger(loss_analysis: LossAnalysis) -> str:
    """Render a compact, ID-only ledger for structural routing."""
    pairs = authoritative_hazard_constraint_pairs(loss_analysis)
    lines = [
        "AUTHORITATIVE HAZARD-CONSTRAINT PAIR LEDGER (typed IDs only):",
        "Use only the exact constraint_id -> hazard_id pairs listed here. "
        "Descriptions, including parenthetical IDs, are not relationship evidence. "
        "This ledger validates structural references only; it does not make a "
        "taxonomy concern applicable or force a targeted route.",
    ]
    if pairs:
        lines.extend(
            f"- {constraint_id} -> {hazard_id}" for constraint_id, hazard_id in pairs
        )
    else:
        lines.append("- <none>")
    return "\n".join(lines)


def _description(value: str | None, fallback: str) -> str:
    """Return a non-empty provider-facing description without inventing meaning."""
    if value is not None and value.strip():
        return value.strip()
    return fallback


def _resource_identity(reference: Any) -> tuple[str, str]:
    """Extract one canonical resource ID and kind for explanatory rendering."""
    data = reference.model_dump(mode="json")
    kind = str(data.get("kind", "resource"))
    identity = next(
        (str(value) for key, value in data.items() if key.endswith("_id")),
        kind,
    )
    return identity, kind


def _fact_views(
    brief: NeutralObligationBrief,
) -> tuple[
    tuple[ProviderApplicabilityFact, ...], tuple[ProviderApplicabilityFact, ...]
]:
    """Project only typed qualification facts, omitting raw evidence prose."""
    relevant: list[ProviderApplicabilityFact] = []
    missing: list[ProviderApplicabilityFact] = []
    for record in brief.applicability_evidence:
        for evaluation in record.fact_evaluations:
            for fact_evidence in evaluation.facts:
                fact = fact_evidence.fact
                value = fact_evidence.value
                view = ProviderApplicabilityFact(
                    fact_id=fact.fact_id,
                    name=(
                        f"{fact.namespace} fact {fact.fact_id}"
                        + (
                            f" ({'.'.join(fact.property_path)})"
                            if fact.property_path
                            else ""
                        )
                    ),
                    value=value,
                    status=fact_evidence.status,
                    meaning=(
                        f"Qualification reading for {evaluation.step_id}; use the "
                        "status as evidence about applicability, not as proof of a "
                        "system-specific control mechanism."
                    ),
                )
                if fact_evidence.status in {"unknown", "contradictory", "absent"}:
                    missing.append(view)
                else:
                    relevant.append(view)

    def key(item: ProviderApplicabilityFact) -> tuple[str, str, str]:
        return item.fact_id, item.status, item.name

    return tuple(sorted(relevant, key=key)), tuple(sorted(missing, key=key))


def project_obligation_question(
    brief: NeutralObligationBrief,
) -> ProviderObligationQuestion:
    """Project a durable neutral brief into a compact explained question."""
    if not isinstance(brief, NeutralObligationBrief):
        raise TypeError("brief must be a NeutralObligationBrief")
    relevant_facts, missing_facts = _fact_views(brief)
    resources: list[ProviderSystemResource] = []
    for reference in brief.resource_references:
        resource_id, kind = _resource_identity(reference)
        resources.append(
            ProviderSystemResource(
                resource_id=resource_id,
                resource_type=kind,
                description=(
                    f"Known {kind} resource from the supplied system snapshot; "
                    "no mechanism or reachability is implied by this reference."
                ),
                relevance=(
                    "Contextual evidence only. Select it only when the supplied "
                    "STPA control path independently makes it relevant."
                ),
            )
        )
    risk = brief.risk_ref
    return ProviderObligationQuestion(
        obligation_handle=brief.obligation_id,
        known_concern=ProviderKnownConcern(
            attack_pattern_id=brief.attack_pattern_id,
            name=brief.attack_pattern_name,
            description=brief.attack_pattern_description,
        ),
        reviewed_risk=ProviderReviewedRisk(
            risk_id=risk.risk_id,
            name=_description(risk.risk_name, risk.risk_id),
            threat=risk.threat,
            consequence=risk.consequence,
            impact=risk.impact,
        ),
        applicability=ProviderApplicability(
            conclusion=(
                "The reviewed obligation is qualified for consideration; "
                f"qualification status is {brief.qualification_disposition}."
            ),
            relevant_facts=relevant_facts,
            missing_or_conflicting_facts=missing_facts,
        ),
        known_system_resources=tuple(
            sorted(resources, key=lambda item: item.resource_id)
        ),
        analyst_instruction=(
            "The obligation_handle is an opaque handle: copy unchanged and do "
            "not interpret its syntax. Treat the known concern as a hypothesis. "
            "Find a system-specific STPA control path or explicitly reject it; "
            "the reviewed risk and resource references are context, not proof, "
            "and do not prescribe an attack sequence or coverage."
        ),
    )


def _reference_map(control_structure: ControlStructure) -> dict[str, PromptReference]:
    """Build explained references for the structural records."""
    result: dict[str, PromptReference] = {}
    for responsibility in control_structure.responsibilities:
        result[responsibility.resp_id] = PromptReference(
            id=responsibility.resp_id,
            description=responsibility.description,
        )
        for child in responsibility.responsibility_constraints:
            result[child.rc_id] = PromptReference(
                id=child.rc_id, description=child.description
            )
        for child in responsibility.process_model_parts:
            result[child.pm_id] = PromptReference(
                id=child.pm_id, description=child.description
            )
        for child in responsibility.control_actions:
            result[child.ca_id] = PromptReference(
                id=child.ca_id, description=child.description
            )
        for child in responsibility.feedback_channels:
            result[child.fb_id] = PromptReference(
                id=child.fb_id, description=child.description
            )
    for process in control_structure.controlled_processes:
        result[process.cp_id] = PromptReference(
            id=process.cp_id, description=process.description
        )
    for link in control_structure.coordination_links:
        result[link.link_id] = PromptReference(
            id=link.link_id, description=link.description
        )
        result[link.coordination_mechanism.cm_id] = PromptReference(
            id=link.coordination_mechanism.cm_id,
            description=link.coordination_mechanism.description,
        )
    return result


def _element_reference(
    ref: ElementRef | None,
    references: dict[str, PromptReference],
) -> PromptReference | None:
    """Resolve an optional control-structure edge to an explained reference."""
    if ref is None:
        return None
    return references.get(ref.id, PromptReference(id=ref.id, description=ref.id))


def _selected_target(
    control_structure: ControlStructure,
    target_id: str | None,
) -> tuple[str, str, tuple[Any, ...], tuple[Any, ...]]:
    """Return target kind and selected responsibility/link records."""
    if target_id is None:
        return (
            "all",
            "all",
            tuple(control_structure.responsibilities),
            tuple(control_structure.coordination_links),
        )
    responsibilities = tuple(
        item for item in control_structure.responsibilities if item.resp_id == target_id
    )
    links = tuple(
        item
        for item in control_structure.coordination_links
        if item.link_id == target_id
    )
    if len(responsibilities) + len(links) != 1:
        raise ValueError(f"unknown or ambiguous STPA target {target_id}")
    kind = "responsibility" if responsibilities else "coordination_link"
    return kind, target_id, responsibilities, links


def _controlled_process_refs(
    control_structure: ControlStructure,
) -> tuple[PromptReference, ...]:
    """Return all controlled-process references for a target-index guard."""
    return tuple(
        PromptReference(id=item.cp_id, description=item.description)
        for item in control_structure.controlled_processes
    )


def _context_references(
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis | None,
) -> dict[str, PromptReference]:
    """Build the explanatory reference table used by every context helper."""
    refs = _reference_map(control_structure)
    if loss_analysis is None:
        return refs
    if not isinstance(loss_analysis, LossAnalysis):
        raise TypeError("loss_analysis must be a LossAnalysis")
    refs.update(
        {
            item.constraint_id: PromptReference(
                id=item.constraint_id,
                description=item.description,
            )
            for item in loss_analysis.security_constraints
        }
    )
    return refs


def _selected_context_slots(
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder],
    target_id: str | None,
    responsibilities: Sequence[Any],
    links: Sequence[Any],
) -> tuple[SlotPlaceholder, ...]:
    """Keep only slots owned by the selected target, if the call is scoped."""
    if target_id is None:
        return tuple(slots)
    responsibility_ids = {item.resp_id for item in responsibilities}
    link_ids = {item.link_id for item in links}
    return tuple(
        item
        for item in slots
        if item.responsibility in responsibility_ids
        or item.coordination_link in link_ids
    )


def _project_responsibility_context(
    responsibilities: Sequence[Any],
    refs: dict[str, PromptReference],
) -> tuple[
    list[ProviderResponsibility],
    list[ProviderControlAction],
    list[ProviderProcessModelPart],
    list[ProviderFeedbackChannel],
    set[str],
]:
    """Project responsibility-owned actions, process models, and feedback."""
    responsibility_views: list[ProviderResponsibility] = []
    action_views: list[ProviderControlAction] = []
    process_views: list[ProviderProcessModelPart] = []
    feedback_views: list[ProviderFeedbackChannel] = []
    selected_cp_ids: set[str] = set()
    for responsibility in responsibilities:
        assigned = tuple(
            refs[item]
            for item in responsibility.security_constraint_refs
            if item in refs
        )
        process_ids = {
            action.target.id
            for action in responsibility.control_actions
            if action.target is not None
            and action.target.type == ReferenceType.controlled_process
        }
        selected_cp_ids.update(process_ids)
        responsibility_views.append(
            ProviderResponsibility(
                id=responsibility.resp_id,
                description=responsibility.description,
                assigned_constraints=assigned,
                controlled_process=(
                    refs[next(iter(sorted(process_ids)))]
                    if len(process_ids) == 1
                    else None
                ),
            )
        )
        for action in responsibility.control_actions:
            target = _element_reference(action.target, refs)
            action_views.append(
                ProviderControlAction(
                    id=action.ca_id,
                    description=action.description,
                    owner=refs[responsibility.resp_id],
                    target_process=(
                        target
                        if action.target is not None
                        and action.target.type == ReferenceType.controlled_process
                        else None
                    ),
                )
            )
        for part in responsibility.process_model_parts:
            process_views.append(
                ProviderProcessModelPart(
                    id=part.pm_id,
                    description=part.description,
                    owner=refs[responsibility.resp_id],
                )
            )
        for channel in responsibility.feedback_channels:
            feedback_views.append(
                ProviderFeedbackChannel(
                    id=channel.fb_id,
                    description=channel.description,
                    owner=refs[responsibility.resp_id],
                    updates=refs.get(channel.updates),
                    source=_element_reference(channel.source, refs),
                )
            )
    return (
        responsibility_views,
        action_views,
        process_views,
        feedback_views,
        selected_cp_ids,
    )


def _project_coordination_context(
    links: Sequence[Any],
    refs: dict[str, PromptReference],
) -> tuple[list[ProviderCoordinationPath], list[ProviderControlAction]]:
    """Project coordination paths and their mechanism actions."""
    paths: list[ProviderCoordinationPath] = []
    actions: list[ProviderControlAction] = []
    for link in links:
        paths.append(
            ProviderCoordinationPath(
                id=link.link_id,
                description=link.description,
                source=refs[link.source],
                target=refs[link.target],
                mechanism=refs[link.coordination_mechanism.cm_id],
                shared_process_model=refs.get(
                    link.shared_pm,
                    PromptReference(id=link.shared_pm, description=link.shared_pm),
                ),
            )
        )
        actions.append(
            ProviderControlAction(
                id=link.coordination_mechanism.cm_id,
                description=link.coordination_mechanism.description,
                owner=refs[link.source],
                target_process=None,
            )
        )
    return paths, actions


def _slot_target_process(
    slot: SlotPlaceholder,
    responsibilities: Sequence[Any],
    refs: dict[str, PromptReference],
) -> PromptReference | None:
    """Resolve a responsibility slot's controlled-process edge."""
    if not slot.responsibility:
        return None
    responsibility = next(
        (item for item in responsibilities if item.resp_id == slot.responsibility),
        None,
    )
    if responsibility is None:
        return None
    control_action = next(
        (
            item
            for item in responsibility.control_actions
            if item.ca_id == slot.control_action
        ),
        None,
    )
    if control_action is None:
        return None
    return _element_reference(control_action.target, refs)


def _project_slot_context(
    slots: Sequence[SlotPlaceholder],
    responsibilities: Sequence[Any],
    refs: dict[str, PromptReference],
    control_structure: ControlStructure,
) -> list[ProviderSlot]:
    """Project exact slot identities and their local control-path meaning."""
    all_cp_ids = {item.id for item in _controlled_process_refs(control_structure)}
    views: list[ProviderSlot] = []
    for slot in slots:
        owner = refs.get(slot.responsibility) if slot.responsibility else None
        action = refs.get(slot.control_action) or PromptReference(
            id=slot.control_action,
            description=slot.control_action,
        )
        target_process = _slot_target_process(slot, responsibilities, refs)
        views.append(
            ProviderSlot(
                id=slot.slot_id,
                description=(
                    f"{slot.uca_type.value} slot for {action.description}; "
                    "copy this slot handle unchanged in the response."
                ),
                uca_type=slot.uca_type,
                owner=owner,
                control_action=action,
                target_process=(
                    target_process
                    if target_process is not None and target_process.id in all_cp_ids
                    else None
                ),
                coordination_path=(
                    refs.get(slot.coordination_link) if slot.coordination_link else None
                ),
            )
        )
    return views


def _project_loss_context(
    loss_analysis: LossAnalysis | None,
    hazard_ids: Iterable[str],
    constraint_ids: Iterable[str],
) -> tuple[list[PromptReference], list[ProviderHazard], list[ProviderConstraint]]:
    """Project selected loss, hazard, and security-constraint relationships."""
    if loss_analysis is None:
        return [], [], []
    selected_hazards = set(hazard_ids) or {
        item.hazard_id for item in loss_analysis.hazards
    }
    selected_constraints = set(constraint_ids) or {
        item.constraint_id for item in loss_analysis.security_constraints
    }
    hazards = {item.hazard_id: item for item in loss_analysis.hazards}
    losses = {
        item.loss_id: item
        for item in (*loss_analysis.risk_card_losses, *loss_analysis.use_case_losses)
    }
    constraints = {
        item.constraint_id: item for item in loss_analysis.security_constraints
    }
    loss_views = [
        PromptReference(id=loss_id, description=losses[loss_id].description)
        for hazard_id in selected_hazards
        for loss_id in (
            hazards[hazard_id].related_losses if hazard_id in hazards else ()
        )
        if loss_id in losses
    ]
    hazard_views = [
        ProviderHazard(
            id=hazard.hazard_id,
            description=hazard.description,
            related_losses=tuple(
                PromptReference(id=loss_id, description=losses[loss_id].description)
                for loss_id in hazard.related_losses
                if loss_id in losses
            ),
        )
        for hazard_id in sorted(selected_hazards)
        if (hazard := hazards.get(hazard_id)) is not None
    ]
    constraint_views = [
        ProviderConstraint(
            id=constraint.constraint_id,
            description=constraint.description,
            related_hazards=tuple(
                PromptReference(
                    id=hazard_id, description=hazards[hazard_id].description
                )
                for hazard_id in constraint.related_hazards
                if hazard_id in hazards
            ),
        )
        for constraint_id in sorted(selected_constraints)
        if (constraint := constraints.get(constraint_id)) is not None
    ]
    return loss_views, hazard_views, constraint_views


def _target_process_context(
    control_structure: ControlStructure,
    target_id: str | None,
    selected_cp_ids: set[str],
) -> tuple[PromptReference, ...]:
    """Return the process references visible to this target scope."""
    allowed = {
        item.cp_id
        for item in control_structure.controlled_processes
        if target_id is None or item.cp_id in selected_cp_ids
    }
    return tuple(
        PromptReference(id=item.cp_id, description=item.description)
        for item in control_structure.controlled_processes
        if item.cp_id in allowed
    )


def project_control_structure_context(
    control_structure: ControlStructure,
    *,
    slots: Sequence[SlotPlaceholder] = (),
    target_id: str | None = None,
    loss_analysis: LossAnalysis | None = None,
    hazard_ids: Iterable[str] = (),
    constraint_ids: Iterable[str] = (),
) -> ProviderTargetIndex:
    """Project an explained target index while retaining graph relationships.

    ``target_id`` scopes the result to one responsibility or coordination
    link.  With no target it returns the compact whole-structure index used by
    routing; it never serializes the original control-structure artifact.
    """
    if not isinstance(control_structure, ControlStructure):
        raise TypeError("control_structure must be a ControlStructure")
    refs = _context_references(control_structure, loss_analysis)
    target_kind, resolved_target, responsibilities, links = _selected_target(
        control_structure, target_id
    )
    selected_slots = _selected_context_slots(
        control_structure,
        slots,
        target_id,
        responsibilities,
        links,
    )
    (
        responsibility_views,
        action_views,
        process_views,
        feedback_views,
        selected_cp_ids,
    ) = _project_responsibility_context(responsibilities, refs)
    coordination_views, coordination_actions = _project_coordination_context(
        links, refs
    )
    action_views.extend(coordination_actions)
    slot_views = _project_slot_context(
        selected_slots,
        responsibilities,
        refs,
        control_structure,
    )
    loss_views, hazard_views, constraint_views = _project_loss_context(
        loss_analysis,
        hazard_ids,
        constraint_ids,
    )
    controlled_process_views = _target_process_context(
        control_structure,
        target_id,
        selected_cp_ids,
    )
    return ProviderTargetIndex(
        target_id=resolved_target if target_id is not None else None,
        target_kind=target_kind,
        responsibilities=tuple(sorted(responsibility_views, key=lambda item: item.id)),
        coordination_paths=tuple(sorted(coordination_views, key=lambda item: item.id)),
        controlled_processes=tuple(
            sorted(controlled_process_views, key=lambda item: item.id)
        ),
        control_actions=tuple(sorted(action_views, key=lambda item: item.id)),
        process_model_parts=tuple(sorted(process_views, key=lambda item: item.id)),
        feedback_channels=tuple(sorted(feedback_views, key=lambda item: item.id)),
        slots=tuple(sorted(slot_views, key=lambda item: item.id)),
        losses=tuple(sorted(loss_views, key=lambda item: item.id)),
        hazards=tuple(sorted(hazard_views, key=lambda item: item.id)),
        constraints=tuple(sorted(constraint_views, key=lambda item: item.id)),
    )


def project_obligation_routing_context(
    *,
    briefs: Sequence[NeutralObligationBrief],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder] = (),
) -> ProviderRoutingContext:
    """Build the compact provider view for one routing batch."""
    questions = tuple(
        sorted(
            (project_obligation_question(brief) for brief in briefs),
            key=lambda item: item.obligation_handle,
        )
    )
    if not questions:
        raise ValueError("routing context requires at least one obligation question")
    return ProviderRoutingContext(
        obligation_questions=questions,
        target_index=project_control_structure_context(
            control_structure,
            slots=slots,
            loss_analysis=loss_analysis,
        ),
        instructions=(
            "Every selectable ID below has a description and relationship. "
            "The obligation_handle is opaque and must be copied unchanged. "
            "A targeted route must prove owner, action, controlled process, slot, "
            "hazard, loss, and governing constraint relationships. Use the exact "
            "typed hazard-constraint pair ledger in the rendered prompt; do not "
            "infer a relationship from descriptions."
        ),
    )


def _revision_related_context(
    gap: MissingStructuralConcept,
    *,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> tuple[PromptReference, ...]:
    """Select compact existing context relevant to one typed gap."""
    refs = _reference_map(control_structure)
    values: list[PromptReference] = []
    if gap.concept_type in {"loss", "hazard", "constraint"}:
        for item in (
            *loss_analysis.risk_card_losses,
            *loss_analysis.use_case_losses,
        ):
            values.append(
                PromptReference(id=item.loss_id, description=item.description)
            )
        for item in loss_analysis.hazards:
            values.append(
                PromptReference(id=item.hazard_id, description=item.description)
            )
        for item in loss_analysis.security_constraints:
            values.append(
                PromptReference(id=item.constraint_id, description=item.description)
            )
    else:
        values.extend(refs.values())
    # Evidence refs are opaque observations, not final IDs to invent.  Retain
    # them only when they resolve to a supplied structural record.
    values.extend(refs[ref] for ref in gap.evidence_refs if ref in refs)
    unique = {item.id: item for item in values}
    return tuple(unique[key] for key in sorted(unique))


def project_revision_context(
    *,
    gaps: Sequence[MissingStructuralConcept],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> ProviderRevisionContext:
    """Build one atomic revision view using request-local gap handles."""
    ordered = tuple(sorted(gaps, key=lambda item: item.gap_id or ""))
    if not ordered:
        raise ValueError("revision context requires at least one gap")
    projected: list[ProviderRevisionGap] = []
    for index, gap in enumerate(ordered, start=1):
        projected.append(
            ProviderRevisionGap(
                gap_handle=f"revision-gap-{index}",
                trigger_obligation_handle=gap.obligation_id
                or "unattributed-obligation",
                plain_description=gap.description,
                why_the_concept_is_needed=(
                    "The supplied evidence says this concept is needed before "
                    "STPA can decide how the obligation relates to the system."
                ),
                expected_concept_kind=gap.concept_type,
                related_existing_context=_revision_related_context(
                    gap,
                    loss_analysis=loss_analysis,
                    control_structure=control_structure,
                ),
            )
        )
    return ProviderRevisionContext(
        gaps=tuple(projected),
        target_index=project_control_structure_context(
            control_structure,
            loss_analysis=loss_analysis,
        ),
        instructions=(
            "For every gap_handle choose exactly one disposition: "
            "propose_addition, dismiss_unsupported, or unresolved. "
            "Copy each gap_handle unchanged. Additions may reference supplied "
            "existing IDs or declared request-local handles only. Do not invent "
            "final STPA IDs; the compiler allocates them. The complete delta is "
            "validated and applied atomically as one bounded round."
        ),
    )


def _neutral_brief_payload(brief: NeutralObligationBrief) -> dict[str, Any]:
    """Compatibility helper returning the compact question payload."""
    return project_obligation_question(brief).model_dump(mode="json")


def _route_payload(
    route: ObligationRoute,
    *,
    briefs: dict[str, NeutralObligationBrief],
    target_index: ProviderTargetIndex,
) -> ProviderRoutedRoute:
    """Project one route with opaque handles and explained target references."""
    del briefs, target_index  # The question/index carry the descriptive context.
    return ProviderRoutedRoute(
        route_handle=route.route_id or "route-without-derived-id",
        obligation_handle=route.obligation_id,
        slot_ids=tuple(route.slot_ids),
        hazard_ids=tuple(route.hazard_ids),
        constraint_ids=tuple(route.constraint_ids),
        instruction=(
            "Copy route_handle and obligation_handle unchanged. These references "
            "are evidence to consider; they do not force an ICA finding."
        ),
    )


def project_ica_target_context(
    *,
    target_id: str,
    slots: Sequence[SlotPlaceholder],
    routed_briefs: Sequence[NeutralObligationBrief],
    routed_routes: Sequence[ObligationRoute],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> tuple[
    ProviderTargetIndex,
    tuple[ProviderObligationQuestion, ...],
    tuple[ProviderRoutedRoute, ...],
]:
    """Project exactly one target slice plus the obligations routed to it."""
    target_index = project_control_structure_context(
        control_structure,
        slots=slots,
        target_id=target_id,
        loss_analysis=loss_analysis,
        hazard_ids=(
            hazard_id for route in routed_routes for hazard_id in route.hazard_ids
        ),
        constraint_ids=(
            constraint_id
            for route in routed_routes
            for constraint_id in route.constraint_ids
        ),
    )
    brief_map = {brief.obligation_id: brief for brief in routed_briefs}
    questions = tuple(
        project_obligation_question(brief_map[route.obligation_id])
        for route in sorted(routed_routes, key=lambda item: item.obligation_id)
        if route.obligation_id in brief_map
    )
    routes = tuple(
        _route_payload(route, briefs=brief_map, target_index=target_index)
        for route in sorted(routed_routes, key=lambda item: item.obligation_id)
    )
    return target_index, questions, routes


def _compact_routing_target_payload(index: ProviderTargetIndex) -> dict[str, Any]:
    """Render one glossary plus ID-only graph relationships for routing.

    The typed index deliberately carries local descriptions on every edge so
    target-scoped consumers remain self-contained.  Serializing that graph
    directly for a whole-structure routing call repeats the same prose once
    per slot and edge.  This projection keeps every meaning exactly once and
    preserves the relationships as explicit IDs.
    """
    glossary: dict[str, str] = {}

    def remember(identity: str, meaning: str) -> str:
        previous = glossary.setdefault(identity, meaning)
        if previous != meaning:
            raise ValueError(
                f"prompt reference {identity!r} has conflicting descriptions"
            )
        return identity

    def ref_id(reference: PromptReference | None) -> str | None:
        if reference is None:
            return None
        return remember(reference.id, reference.description)

    responsibilities = [
        {
            "id": ref_id(item),
            "assigned_constraint_ids": tuple(
                ref_id(reference) for reference in item.assigned_constraints
            ),
            "controlled_process_id": ref_id(item.controlled_process),
        }
        for item in index.responsibilities
    ]
    coordination_paths = [
        {
            "id": ref_id(item),
            "source_id": ref_id(item.source),
            "target_id": ref_id(item.target),
            "mechanism_id": ref_id(item.mechanism),
            "shared_process_model_id": ref_id(item.shared_process_model),
        }
        for item in index.coordination_paths
    ]
    control_actions = [
        {
            "id": ref_id(item),
            "owner_id": ref_id(item.owner),
            "target_process_id": ref_id(item.target_process),
        }
        for item in index.control_actions
    ]
    process_model_parts = [
        {"id": ref_id(item), "owner_id": ref_id(item.owner)}
        for item in index.process_model_parts
    ]
    feedback_channels = [
        {
            "id": ref_id(item),
            "owner_id": ref_id(item.owner),
            "updates_id": ref_id(item.updates),
            "source_id": ref_id(item.source),
        }
        for item in index.feedback_channels
    ]
    slots = [
        {
            "id": remember(
                item.id,
                "Unsafe-control slot; its exact action, owner, target, and UCA "
                "type are stated in the slots relationship table.",
            ),
            "uca_type": item.uca_type.value,
            "owner_id": ref_id(item.owner),
            "control_action_id": ref_id(item.control_action),
            "target_process_id": ref_id(item.target_process),
            "coordination_path_id": ref_id(item.coordination_path),
        }
        for item in index.slots
    ]
    hazards = [
        {
            "id": ref_id(item),
            "related_loss_ids": tuple(
                ref_id(reference) for reference in item.related_losses
            ),
        }
        for item in index.hazards
    ]
    constraints = [
        {
            "id": ref_id(item),
            "related_hazard_ids": tuple(
                ref_id(reference) for reference in item.related_hazards
            ),
        }
        for item in index.constraints
    ]
    controlled_process_ids = tuple(ref_id(item) for item in index.controlled_processes)
    loss_ids = tuple(ref_id(item) for item in index.losses)
    return {
        "target_id": index.target_id,
        "target_kind": index.target_kind,
        "responsibilities": responsibilities,
        "coordination_paths": coordination_paths,
        "control_actions": control_actions,
        "controlled_process_ids": controlled_process_ids,
        "process_model_parts": process_model_parts,
        "feedback_channels": feedback_channels,
        "slots": slots,
        "loss_ids": loss_ids,
        "hazards": hazards,
        "constraints": constraints,
        "id_glossary": [
            {"id": identity, "meaning": glossary[identity]}
            for identity in sorted(glossary)
        ],
    }


def build_structural_routing_prompts(
    *,
    briefs: Sequence[NeutralObligationBrief],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder] = (),
) -> tuple[str, str]:
    """Build system/user prompts for one compact structural-routing batch."""
    context = project_obligation_routing_context(
        briefs=briefs,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        slots=slots,
    )
    system = f"""You are performing structural STPA analysis for taxonomy concerns.
Treat each concern as a hypothesis, not a mandatory mechanism, ordered attack sequence,
coverage claim, or execution instruction. Return exactly one route in the JSON `routes`
array for each supplied obligation ({len(context.obligation_questions)} total):
targeted, proposed_not_applicable, upstream_gap, or unresolved.

{context.instructions}

The obligation_handle is opaque: copy unchanged. Every selectable ID in the index is
paired with a description. Each namespace field must use only its matching supplied IDs.
A targeted
route requires an owner responsibility (or coordination path), its owned action, the
action's controlled process (or shared coordination process), matching slots, selected
hazards, and constraints that explicitly govern those hazards. Each selected hazard must
retain a related loss. `targeted` does not mean that an identifier merely matched; explain
the system-specific relationship. You may reject the taxonomy hypothesis.

Hazard/constraint pairing is closed over the ID-only ledger in the user prompt. Use only
the listed `constraint_id -> hazard_id` pairs. Never infer a pair from a description,
including a duplicated or parenthetical hazard ID; the typed relationship controls.

For a responsibility slot, use the slot's exact RESP owner in `controller_ids` and
`responsibility_ids`, its exact CA in `control_action_ids`, and that action's exact CP in
`controlled_process_ids`. For a coordination slot such as
`CL-1:CM-1:NOT_PROVIDED`, resolve the exact CL record: use its source responsibility as
the `controller_ids` value, include both its source and target responsibilities in
`responsibility_ids`, use the exact CM in `control_action_ids`, the exact CL in
`coordination_link_ids`, and the link's shared PM in `process_model_part_ids`. Never put
a CL in `responsibility_ids` or replace a CM with a source responsibility's CA.

The route object uses these exact fields: `obligation_id`, `disposition`, `slot_ids`,
`controller_ids`, `responsibility_ids`, `control_action_ids`, `controlled_process_ids`,
`coordination_link_ids`, `hazard_ids`, `constraint_ids`, `missing_concepts`, `rationale`,
and non-empty `evidence`. Valid example: {{"routes":[{{"obligation_id":"<obligation_handle>","disposition":"unresolved","evidence":["evidence is insufficient"]}}]}}.

Do not return route_id or gap_id. The local adapter derives durable route and gap IDs.
Slot IDs use the exact forms `RESP-*:CA-*:UCA_TYPE` or `CL-*:CM-*:UCA_TYPE`.
"""
    user = "Compact obligation questions:\n" + _yaml(
        [item.model_dump(mode="json") for item in context.obligation_questions]
    )
    user += "\n" + _hazard_constraint_pair_ledger(loss_analysis) + "\n"
    user += (
        "\nCompact STPA target index: relationships use IDs; the ID glossary "
        "explains each ID exactly once.\n"
        + _yaml(_compact_routing_target_payload(context.target_index))
    )
    user += "\nReturn typed route dispositions with exact references and evidence.\n"
    return system, user


def build_structural_revision_prompts(
    *,
    gaps: Sequence[MissingStructuralConcept],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> tuple[str, str]:
    """Build prompts for the one bounded, atomic additive revision round."""
    context = project_revision_context(
        gaps=gaps,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )
    system = f"""You may address typed upstream STPA gaps in one bounded additive round.
Use request-local handles for all new concepts and preserve every baseline record. For each
opaque gap_handle, copied unchanged, choose exactly one of:
- propose_addition: provide a closed addition using existing IDs or declared local handles;
- dismiss_unsupported: explain why the supplied evidence does not justify the gap;
- unresolved: state what evidence is still missing.

{context.instructions}
No final STPA ID is supplied or invented by the model. The deterministic compiler allocates
final IDs only after validating the complete delta. Do not prescribe an attack sequence,
execution recipe, or taxonomy coverage. Return one JSON object matching the typed draft
schema. The top-level fields are `draft` and `gap_decisions`; each decision contains
`gap_handle`, `disposition`, and `rationale`. Valid example: {{"draft":{{}},"gap_decisions":[]}}.
"""
    user = "Compact revision gaps:\n" + _yaml(
        [item.model_dump(mode="json") for item in context.gaps]
    )
    user += "\nCompact baseline STPA index:\n" + _yaml(
        context.target_index.model_dump(mode="json")
    )
    user += "\nReturn one typed gap decision for every gap_handle and one complete request-local draft.\n"
    return system, user


def build_synthesis_slot_prompts(
    *,
    target_id: str,
    slots: Sequence[SlotPlaceholder],
    routed_briefs: Sequence[NeutralObligationBrief],
    routed_routes: Sequence[ObligationRoute],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> tuple[str, str]:
    """Build an ordinary-Stage-3, target-scoped structured ICA prompt."""
    target_index, questions, routes = project_ica_target_context(
        target_id=target_id,
        slots=slots,
        routed_briefs=routed_briefs,
        routed_routes=routed_routes,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )
    slot_ids = {slot.slot_id for slot in slots}
    required_pairs = [
        {
            "route_handle": route.route_handle,
            "obligation_handle": route.obligation_handle,
            "slot_id": slot_id,
            "copy_instruction": "copy each opaque handle unchanged",
        }
        for route in routes
        for slot_id in sorted(set(route.slot_ids).intersection(slot_ids))
    ]
    system = f"""Fill every supplied STPA ICA slot for exactly this target. Analyze every
slot, including slots with no routed obligation, exactly once. Return one structured slot
draft per supplied slot. Use each slot_id as an opaque handle and copy it unchanged.

{_UCA_TYPE_DEFINITIONS}

The ordinary STPA method requires a hazardous context, a loss consequence, exact hazard and
governing-constraint references, and process-model or feedback references where relevant.
For each finding return exactly one type-specific deviation field:
`not_provided_context` for NOT_PROVIDED, `incorrect_value_or_effect` for INCORRECT,
`timing_deviation` for WRONG_TIMING, or `duration_deviation` for WRONG_DURATION. The
deterministic compiler supplies the authoritative controller and control-action prose; do
not rewrite those identities. A routed obligation is advisory: it may result in a finding,
proposed_not_applicable with complete structural evidence, or unresolved. A route never
forces an ICA finding and no consideration may claim taxonomy coverage.

The `deviation` object must have exactly one property and must omit the other three:
NOT_PROVIDED -> `{{"not_provided_context":"..."}}`; INCORRECT ->
`{{"incorrect_value_or_effect":"..."}}`; WRONG_TIMING ->
`{{"timing_deviation":"..."}}`; WRONG_DURATION ->
`{{"duration_deviation":"..."}}`. Do not return the unused properties as null or empty.

For N/A use `is_na=true`, a non-empty `na_rationale` citing a complete structural
property, and no findings. For an unsafe-control result use `is_na=false`,
`na_rationale=null`, and at least one structured item in `findings`. Do not return the
legacy `responsibility`, `control_action`, `uca_type`, or `icas` fields. Do not return
final ICA IDs, EXEC identities, or replacement controller/action text.

For every item under `Required routed consideration pairs`, put exactly one result in
the matching slot's `consideration_results` array:

- Use `finding` only when one or more findings in that same slot directly express the
  routed concern through the route's supplied hazard and governing constraint. Put the
  matching zero-based positions from the slot's `findings` array in `finding_indexes`.
- Use `proposed_not_applicable` only when that slot is N/A and its complete structural
  property proves the routed mechanism cannot occur. Leave `finding_indexes` empty.
- Use `unresolved` only when the supplied evidence is missing or contradictory. State
  what evidence is missing or contradictory; do not use `unresolved` merely because a
  route is advisory or does not force a finding. Leave `finding_indexes` empty.

Do not attach an obligation to an unrelated finding merely because both appear in the
same target. Copy each `obligation_handle` unchanged; route handles are input evidence
and are resolved locally, so they are not output fields.

An ICA finding is a system-specific scenario hypothesis about unsafe control behavior;
it is not proof that the current control already recognizes or names the taxonomy attack
technique. Choose `finding` when the known concern is a concrete way the same supplied
control action can be absent, incorrect, mistimed, or misapplied and can lead to the same
hazard. For example, an input-manipulation concern can select a finding in which the
system fails to block a malicious input even if the present control description does not
name that precise manipulation technique. Choose `unresolved` instead when the concern
requires another control path (for example, a tool-execution concern routed only to an
input filter), an unsupplied access path, or another missing system fact. State that exact
missing path or fact in the rationale.

The structured slot-draft fields are `slot_id`, `is_na`, `na_rationale`, `findings`, and
`consideration_results`; each finding contains `deviation`, `hazardous_context`,
`loss_consequence`, `related_hazard_ids`, `related_constraint_ids`, `process_model_refs`,
and `feedback_refs`. A finding consideration contains `obligation_handle`,
`disposition`, `finding_indexes`, and `rationale`. Valid example:
{{"filled_slots":[{{"slot_id":"<slot_id>","is_na":false,"na_rationale":null,
"findings":[{{"deviation":{{"not_provided_context":"the required action is absent"}},
"hazardous_context":"the supplied hazardous context","loss_consequence":"the supplied
loss consequence occurs","related_hazard_ids":["<hazard_id>"],
"related_constraint_ids":["<constraint_id>"],"process_model_refs":[],
"feedback_refs":[]}}],"consideration_results":[{{"obligation_handle":
"<obligation_handle>","disposition":"finding","finding_indexes":[0],
"rationale":"finding 0 directly expresses the routed concern"}}]}}]}}.
Return one JSON object matching the structured slot-draft schema.
"""
    user = (
        f"Target handle: {target_id} (copy unchanged)\n"
        "Compact target STPA index:\n" + _yaml(target_index.model_dump(mode="json"))
    )
    user += "\nObligation considerations for this target (hypotheses only):\n" + _yaml(
        [item.model_dump(mode="json") for item in questions]
    )
    user += "\nRouted route evidence (opaque handles; copy unchanged):\n" + _yaml(
        [item.model_dump(mode="json") for item in routes]
    )
    user += "\nRequired routed consideration pairs:\n" + _yaml(required_pairs)
    user += "\nReturn the structured slot-draft schema described above.\n"
    return system, user


# A small compatibility spelling used by some adapter callers.
build_slot_filling_prompts = build_synthesis_slot_prompts


__all__ = [
    "audit_prompt_contract",
    "build_slot_filling_prompts",
    "build_structural_revision_prompts",
    "build_structural_routing_prompts",
    "build_synthesis_slot_prompts",
    "authoritative_hazard_constraint_pairs",
    "project_control_structure_context",
    "project_ica_target_context",
    "project_obligation_question",
    "project_obligation_routing_context",
    "project_revision_context",
]

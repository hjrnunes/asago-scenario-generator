"""Pure, compact provider views for obligation-aware STPA stages.

Durable Phase 1 and STPA artifacts are intentionally not serialized into a
prompt.  The projector functions below select the small, explained graph a
particular model call needs; the provider adapter then renders that closed
view.  Provenance digests, pins, paths, scores, and raw mapping evidence stay
in the caller's typed records.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import json
from pathlib import Path
import re
from typing import Any

import yaml

from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
    NeutralObligationBrief,
    ObligationRoute,
)
from asago_scenario_generator.stpa.models.control_structure import (
    UNTRUSTED_FEEDBACK_SOURCES,
    ControlStructure,
    ElementRef,
    ReferenceType,
    control_action_context_rows,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.pipeline.risk_pattern_crosswalk import (
    resolve_risk_pattern_mapping_strength,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    PromptReference,
    ProviderApplicability,
    ProviderApplicabilityFact,
    ProviderConstraint,
    ProviderContextRow,
    ProviderContextValue,
    ProviderControlAction,
    ProviderCoordinationPath,
    ProviderFeedbackChannel,
    ProviderGovernanceQuestion,
    ProviderGovernanceRisk,
    ProviderHazard,
    ProviderKnownConcern,
    ProviderMappingStrength,
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
from asago_scenario_generator.stpa.obligation_aware.hazard_offer import slot_offer
from asago_scenario_generator.stpa.threat_enum.slot_creation import SlotPlaceholder


PROMPT_TEMPLATES_DIR = Path(__file__).with_name("prompt_templates")
_TEMPLATE_LOADER = TemplateLoader(PROMPT_TEMPLATES_DIR)

# One list serves two matchers: the local audit rejects a view key equal to an
# entry, and the repository preflight rejects a key with an entry as one of its
# snake_case words (a plural ``s`` included).  Multi-word entries therefore act
# only as exact keys.
PROHIBITED_PROMPT_FIELDS = (
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
    "digest",
    "pin",
    "score",
    "mitigation",
    "provider_call",
    "schema_name",
)
_ABSOLUTE_PATH = re.compile(r"(?:^|[\s\"'])/(?:Users|private|tmp|var|home)/")
_STRUCTURAL_REFERENCE_TOKEN = re.compile(
    r"\b(?:RESP|CA|FB|CP|PM|RC|SC|H|L|REQ|CL|CM)-[A-Za-z0-9][A-Za-z0-9_.:-]*\b"
)

_MAPPING_STRENGTH_MEANINGS = {
    "direct_curated_pair": (
        "The reviewed risk was linked directly to this attack pattern. This is "
        "discovery evidence, not proof that the mechanism exists in this system."
    ),
    "exact_then_category_expansion": (
        "The risk first matched an equivalent taxonomy concept, then expanded "
        "through a broader category to this pattern. Judge this pair explicitly."
    ),
    "broad_category_expansion": (
        "The risk reached this pattern through a broader taxonomy category. Shared "
        "category membership does not establish risk alignment."
    ),
    "related_category_expansion": (
        "The risk reached this pattern through a related taxonomy concept and a "
        "broader category. Treat the pairing as a discovery hypothesis only."
    ),
}


def obligation_prompt_template_hashes() -> dict[str, str]:
    """Hash every top-level prompt and included partial in the search root."""
    return _TEMPLATE_LOADER.hash_prompt_templates()


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
    for key in PROHIBITED_PROMPT_FIELDS:
        if key in field_names:
            issues.append(f"prohibited prompt field leaked: {key}")
    issues.extend(_rendered_prompt_issues(system_prompt, user_prompt, opaque_handles))
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


def _rendered_prompt_issues(
    system_prompt: str, user_prompt: str, opaque_handles: Sequence[str]
) -> list[str]:
    issues: list[str] = []
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
    return issues


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


def _routing_wire_examples() -> tuple[str, str]:
    """Render complete route examples through the exact provider wire model."""
    # Import lazily: provider.py imports this module for prompt construction.
    from asago_scenario_generator.stpa.obligation_aware.provider import (
        _routing_provider_payload_type,
    )

    payload_type = _routing_provider_payload_type(1)
    common = {
        "obligation_id": "ob:v1:" + "0" * 64,
        "evidence": ["sanitized structural evidence"],
    }
    semantic_assessment = {
        "mechanism_assessment": "plausible_in_system",
        "risk_alignment": "supported",
        "mechanism_rationale": "the supplied path governs the concern",
        "risk_alignment_rationale": "the path can affect the reviewed consequence",
    }
    targeted = payload_type.model_validate(
        {
            "routes": [
                {
                    **common,
                    "disposition": "targeted",
                    "semantic_assessment": semantic_assessment,
                    "slot_ids": ["RESP-1:CA-1-1:NOT_PROVIDED"],
                    "hazard_ids": ["H-1"],
                    "constraint_ids": ["SC-1"],
                    "rationale": "the selected owner, slot, hazard, and constraint form a path worth analysing",
                }
            ]
        }
    )
    unresolved = payload_type.model_validate(
        {
            "routes": [
                {
                    **common,
                    "disposition": "unresolved",
                    "semantic_assessment": {
                        **semantic_assessment,
                        "mechanism_assessment": "insufficient_evidence",
                        "risk_alignment": "insufficient_evidence",
                        "mechanism_rationale": "the required system path is not supplied",
                        "risk_alignment_rationale": "the mechanism-to-risk relationship is not established",
                    },
                    "rationale": "the supplied evidence cannot support a structural placement",
                }
            ]
        }
    )
    return tuple(
        json.dumps(item.model_dump(mode="json"), separators=(",", ":"))
        for item in (targeted, unresolved)
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
                    name=_plain_fact_name(fact),
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


def _plain_fact_name(fact: Any) -> str:
    """Describe a qualification fact without requiring identifier knowledge."""
    source = ".".join(fact.property_path) if fact.property_path else fact.fact_id
    words = source.replace("_", " ").replace(".", " ").strip()
    return f"Declared {fact.namespace} evidence: {words}"


def _routing_question_payload(item: ProviderObligationQuestion) -> dict[str, Any]:
    """Remove repeated instructions and non-semantic fact keys from one row."""
    payload = item.model_dump(mode="json")
    payload.pop("analyst_instruction", None)
    concern = payload.pop("known_concern")
    payload["known_concern_ref"] = concern["attack_pattern_id"]
    applicability = payload.get("applicability", {})
    for collection in ("relevant_facts", "missing_or_conflicting_facts"):
        for fact in applicability.get(collection, []):
            fact.pop("fact_id", None)
    return payload


def _routing_concern_catalog(
    questions: Sequence[ProviderObligationQuestion],
) -> list[dict[str, str]]:
    """Render each repeated attack-pattern concern once per routing batch."""
    by_id: dict[str, dict[str, str]] = {}
    for question in questions:
        concern = question.known_concern.model_dump(mode="json")
        identity = concern["attack_pattern_id"]
        previous = by_id.setdefault(identity, concern)
        if previous != concern:
            raise ValueError(f"conflicting concern descriptions for {identity}")
    return [by_id[identity] for identity in sorted(by_id)]


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
    mapping_strength = mapping_strength_for_brief(brief)
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
        mapping_strength=ProviderMappingStrength(
            label=mapping_strength,
            meaning=_MAPPING_STRENGTH_MEANINGS[mapping_strength],
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


def project_governance_question(
    brief: NeutralObligationBrief,
) -> ProviderGovernanceQuestion:
    """Project a governance brief: the risk in full and no attack pattern."""
    if not isinstance(brief, NeutralObligationBrief) or brief.kind != "governance":
        raise TypeError("brief must be a governance NeutralObligationBrief")
    relevant_facts, missing_facts = _fact_views(brief)
    risk = brief.risk_ref
    name = _description(risk.risk_name, risk.risk_id)
    return ProviderGovernanceQuestion(
        obligation_handle=brief.obligation_id,
        reviewed_risk=ProviderGovernanceRisk(
            risk_id=risk.risk_id,
            name=name,
            description=_description(risk.risk_description, name),
            threat=risk.threat,
            consequence=risk.consequence,
            impact=risk.impact,
        ),
        applicability=ProviderApplicability(
            conclusion=(
                "The reviewed risk is qualified for consideration; "
                f"qualification status is {brief.qualification_disposition}."
            ),
            relevant_facts=relevant_facts,
            missing_or_conflicting_facts=missing_facts,
        ),
        analyst_instruction=(
            "The obligation_handle is an opaque handle: copy unchanged and do "
            "not interpret its syntax. Treat the reviewed risk as a hypothesis. "
            "No attack pattern covers it; find a system-specific unsafe control "
            "action through which it could come about, or report that none does. "
            "Do not prescribe an attack sequence or coverage."
        ),
    )


def _slot_question(
    brief: NeutralObligationBrief,
) -> ProviderObligationQuestion | ProviderGovernanceQuestion:
    if brief.kind == "governance":
        return project_governance_question(brief)
    return project_obligation_question(brief)


def mapping_strength_for_brief(brief: NeutralObligationBrief) -> str:
    """Reduce every complete mapping path to one conservative plain label."""
    path_relations = [
        _mapping_relations(evidence.detail)
        for evidence in brief.applicability_evidence
        if evidence.kind == "mapping"
    ]
    if not path_relations:
        raise ValueError("obligation question requires mapping-path evidence")
    return resolve_risk_pattern_mapping_strength(path_relations)


def _mapping_relations(detail: str) -> tuple[str, ...]:
    """Parse exact mapping evidence without exposing it to the provider."""
    try:
        payload = json.loads(detail)
        path = payload["path"]
        return tuple(str(edge["relation"]).lower() for edge in path)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("mapping evidence is not a typed mapping path") from exc


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
    refs.update(_loss_analysis_references(loss_analysis))
    return refs


def _loss_analysis_references(
    loss_analysis: LossAnalysis,
) -> dict[str, PromptReference]:
    """Project explanatory references for loss-analysis records."""
    return {
        **{
            item.constraint_id: PromptReference(
                id=item.constraint_id,
                description=item.description,
            )
            for item in loss_analysis.security_constraints
        },
        **{
            item.hazard_id: PromptReference(
                id=item.hazard_id,
                description=item.description,
            )
            for item in loss_analysis.hazards
        },
        **{
            item.loss_id: PromptReference(
                id=item.loss_id,
                description=item.description,
            )
            for item in (
                *loss_analysis.risk_card_losses,
                *loss_analysis.use_case_losses,
            )
        },
    }


def _description_references(
    target_index: ProviderTargetIndex,
    references: Mapping[str, PromptReference],
) -> tuple[PromptReference, ...]:
    """Retain known IDs mentioned in target prose as explained context.

    A target slice can contain a legitimate sentence such as ``CL-5 shares
    state with CP-2`` even when that controlled process is not an endpoint of
    the selected link.  Preflight quite correctly rejects an unexplained
    token, so carry the known record in a separate, non-edge collection.  Any
    unknown token is intentionally *not* synthesized; the existing preflight
    audit remains the closed-world error for that case.
    """
    mentions = _description_reference_ids(target_index.model_dump(mode="python"))
    return tuple(
        references[identity] for identity in sorted(mentions) if identity in references
    )


def _description_reference_ids(value: Any) -> set[str]:
    """Collect known-ID candidates from one serialized prompt value."""
    if isinstance(value, Mapping):
        return _mapping_description_reference_ids(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return _collection_description_reference_ids(value)
    return set()


def _mapping_description_reference_ids(value: Mapping[str, Any]) -> set[str]:
    """Collect description tokens and recurse through a mapping's values."""
    description = value.get("description")
    mentions = (
        set(_STRUCTURAL_REFERENCE_TOKEN.findall(description))
        if isinstance(description, str)
        else set()
    )
    for child in value.values():
        mentions.update(_description_reference_ids(child))
    return mentions


def _collection_description_reference_ids(value: Sequence[Any]) -> set[str]:
    """Collect description tokens from a serialized collection."""
    mentions: set[str] = set()
    for child in value:
        mentions.update(_description_reference_ids(child))
    return mentions


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


def _targets_controlled_process(action: Any) -> bool:
    return (
        action.target is not None
        and action.target.type == ReferenceType.controlled_process
    )


def _controlled_process_ids(responsibility: Any) -> set[str]:
    return {
        action.target.id
        for action in responsibility.control_actions
        if _targets_controlled_process(action)
    }


def _responsibility_view(
    responsibility: Any,
    process_ids: set[str],
    refs: dict[str, PromptReference],
) -> ProviderResponsibility:
    assigned = tuple(
        refs[item] for item in responsibility.security_constraint_refs if item in refs
    )
    return ProviderResponsibility(
        id=responsibility.resp_id,
        description=responsibility.description,
        assigned_constraints=assigned,
        controlled_process=(
            refs[next(iter(sorted(process_ids)))] if len(process_ids) == 1 else None
        ),
    )


def _responsibility_action_views(
    responsibility: Any, refs: dict[str, PromptReference]
) -> list[ProviderControlAction]:
    views = []
    for action in responsibility.control_actions:
        target = _element_reference(action.target, refs)
        views.append(
            ProviderControlAction(
                id=action.ca_id,
                description=action.description,
                owner=refs[responsibility.resp_id],
                action_temporality=action.temporality,
                target_process=target if _targets_controlled_process(action) else None,
                operation=action.operation,
                process_model_refs=tuple(action.process_model_refs),
            )
        )
    return views


def _responsibility_process_views(
    responsibility: Any, refs: dict[str, PromptReference]
) -> list[ProviderProcessModelPart]:
    return [
        ProviderProcessModelPart(
            id=part.pm_id,
            description=part.description,
            owner=refs[responsibility.resp_id],
            values=tuple(part.values),
            evidence_refs=tuple(part.evidence_refs),
        )
        for part in responsibility.process_model_parts
    ]


def _responsibility_feedback_views(
    responsibility: Any, refs: dict[str, PromptReference]
) -> list[ProviderFeedbackChannel]:
    return [
        ProviderFeedbackChannel(
            id=channel.fb_id,
            description=channel.description,
            owner=refs[responsibility.resp_id],
            updates=refs.get(channel.updates),
            source=_element_reference(channel.source, refs),
            source_kind=(
                channel.source_kind.value if channel.source_kind is not None else None
            ),
            untrusted=(
                channel.source_kind in UNTRUSTED_FEEDBACK_SOURCES
                if channel.source_kind is not None
                else None
            ),
        )
        for channel in responsibility.feedback_channels
    ]


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
        process_ids = _controlled_process_ids(responsibility)
        selected_cp_ids.update(process_ids)
        responsibility_views.append(
            _responsibility_view(responsibility, process_ids, refs)
        )
        action_views.extend(_responsibility_action_views(responsibility, refs))
        process_views.extend(_responsibility_process_views(responsibility, refs))
        feedback_views.extend(_responsibility_feedback_views(responsibility, refs))
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
                action_temporality=None,
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
                action_temporality=slot.action_temporality,
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
    return (
        _selected_loss_views(selected_hazards, hazards, losses),
        _selected_hazard_views(selected_hazards, hazards, losses),
        _selected_constraint_views(selected_constraints, constraints, hazards),
    )


def _selected_loss_views(
    selected_hazards: set[str],
    hazards: dict[str, Any],
    losses: dict[str, Any],
) -> list[PromptReference]:
    """Return the losses related to the selected hazards, sorted by ID."""
    selected_loss_ids = {
        loss_id
        for hazard_id in selected_hazards
        for loss_id in (
            hazards[hazard_id].related_losses if hazard_id in hazards else ()
        )
        if loss_id in losses
    }
    return [
        PromptReference(id=loss_id, description=losses[loss_id].description)
        for loss_id in sorted(selected_loss_ids)
    ]


def _selected_hazard_views(
    selected_hazards: set[str],
    hazards: dict[str, Any],
    losses: dict[str, Any],
) -> list[ProviderHazard]:
    """Return the selected hazards with their supplied related losses."""
    return [
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


def _selected_constraint_views(
    selected_constraints: set[str],
    constraints: dict[str, Any],
    hazards: dict[str, Any],
) -> list[ProviderConstraint]:
    """Return the selected constraints with their supplied related hazards."""
    return [
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


def _context_row_views(
    control_structure: ControlStructure,
    action_views: Sequence[ProviderControlAction],
) -> tuple[ProviderContextRow, ...]:
    """Project the deterministic context tables of the target's actions."""
    return tuple(
        ProviderContextRow(
            id=row.row_id,
            # The prompt contract admits only explained identities.
            description="; ".join(
                f"{pm_id} is {value!r}" for pm_id, value in row.assignments
            ),
            control_action_id=row.control_action,
            values=tuple(
                ProviderContextValue(process_model_id=pm_id, value=value)
                for pm_id, value in row.assignments
            ),
        )
        for action in sorted(action_views, key=lambda item: item.id)
        for row in control_action_context_rows(control_structure, action.id)
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
    target_index = ProviderTargetIndex(
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
        context_rows=(
            _context_row_views(control_structure, action_views)
            if target_id is not None
            else ()
        ),
    )
    return target_index.model_copy(
        update={
            "referenced_records": _description_references(target_index, refs),
        }
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


def _route_payload(route: ObligationRoute) -> ProviderRoutedRoute:
    """Project one route with opaque handles and explained target references."""
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
    tuple[ProviderObligationQuestion | ProviderGovernanceQuestion, ...],
    tuple[ProviderRoutedRoute, ...],
]:
    """Project exactly one target slice plus the obligations routed to it."""
    offer = slot_offer(loss_analysis, routed_routes)
    target_index = project_control_structure_context(
        control_structure,
        slots=slots,
        target_id=target_id,
        loss_analysis=loss_analysis,
        hazard_ids=offer.hazard_ids,
        constraint_ids=offer.constraint_ids,
    )
    brief_map = {brief.obligation_id: brief for brief in routed_briefs}
    handles = local_obligation_handles(routed_routes)
    questions = tuple(
        _slot_question(brief_map[route.obligation_id]).model_copy(
            update={"obligation_handle": handles[route.obligation_id]}
        )
        for route in sorted(routed_routes, key=lambda item: item.obligation_id)
        if route.obligation_id in brief_map
    )
    routes = tuple(
        _route_payload(route).model_copy(
            update={
                "route_handle": handles[route.obligation_id],
                "obligation_handle": handles[route.obligation_id],
            }
        )
        for route in sorted(routed_routes, key=lambda item: item.obligation_id)
    )
    return target_index, questions, routes


def local_obligation_handles(routes: Iterable[ObligationRoute]) -> dict[str, str]:
    """Name each routed obligation ``R1``..``Rn`` for one slot request.

    The model copies handles back, and a content-addressed 64-hex handle is
    easy to corrupt by one character, so the prompt carries these short names
    and the caller maps them back to obligation identifiers.
    """
    ordered = sorted({route.obligation_id for route in routes})
    return {
        obligation_id: f"R{index}" for index, obligation_id in enumerate(ordered, 1)
    }


class _RoutingGlossary:
    """Collect each prompt reference's meaning exactly once."""

    def __init__(self) -> None:
        self.meanings: dict[str, str] = {}

    def remember(self, identity: str, meaning: str) -> str:
        previous = self.meanings.setdefault(identity, meaning)
        if previous != meaning:
            raise ValueError(
                f"prompt reference {identity!r} has conflicting descriptions"
            )
        return identity

    def ref_id(self, reference: PromptReference | None) -> str | None:
        if reference is None:
            return None
        return self.remember(reference.id, reference.description)

    def entries(self) -> list[dict[str, str]]:
        return [
            {"id": identity, "meaning": self.meanings[identity]}
            for identity in sorted(self.meanings)
        ]


def _temporality_value(item: Any) -> str | None:
    return (
        item.action_temporality.value if item.action_temporality is not None else None
    )


def _compact_routing_target_payload(index: ProviderTargetIndex) -> dict[str, Any]:
    """Render one glossary plus ID-only graph relationships for routing.

    The typed index deliberately carries local descriptions on every edge so
    target-scoped consumers remain self-contained.  Serializing that graph
    directly for a whole-structure routing call repeats the same prose once
    per slot and edge.  This projection keeps every meaning exactly once and
    preserves the relationships as explicit IDs.
    """
    glossary = _RoutingGlossary()
    ref_id = glossary.ref_id
    # The glossary rejects conflicting descriptions in first-seen order, so
    # the sections are projected in a fixed order.
    structure = _compact_routing_structure(index, glossary)
    slots = _compact_routing_slots(index, glossary)
    hazards, constraints = _compact_routing_loss_graph(index, glossary)
    controlled_process_ids = tuple(ref_id(item) for item in index.controlled_processes)
    loss_ids = tuple(ref_id(item) for item in index.losses)
    referenced_records = [{"id": ref_id(item)} for item in index.referenced_records]
    return {
        "target_id": index.target_id,
        "target_kind": index.target_kind,
        "responsibilities": structure["responsibilities"],
        "coordination_paths": structure["coordination_paths"],
        "control_actions": structure["control_actions"],
        "controlled_process_ids": controlled_process_ids,
        "process_model_parts": structure["process_model_parts"],
        "feedback_channels": structure["feedback_channels"],
        "slots": slots,
        "loss_ids": loss_ids,
        "referenced_records": referenced_records,
        "hazards": hazards,
        "constraints": constraints,
        "id_glossary": glossary.entries(),
    }


def _compact_routing_structure(
    index: ProviderTargetIndex, glossary: _RoutingGlossary
) -> dict[str, list[dict[str, Any]]]:
    """Project the control-structure relationships as ID-only rows."""
    ref_id = glossary.ref_id
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
            "action_temporality": _temporality_value(item),
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
    return {
        "responsibilities": responsibilities,
        "coordination_paths": coordination_paths,
        "control_actions": control_actions,
        "process_model_parts": process_model_parts,
        "feedback_channels": feedback_channels,
    }


def _compact_routing_slots(
    index: ProviderTargetIndex, glossary: _RoutingGlossary
) -> list[dict[str, Any]]:
    """Project the unsafe-control slots as ID-only rows."""
    ref_id = glossary.ref_id
    return [
        {
            "id": glossary.remember(
                item.id,
                "Unsafe-control slot; its exact action, owner, target, and UCA "
                "type are stated in the slots relationship table.",
            ),
            "uca_type": item.uca_type.value,
            "action_temporality": _temporality_value(item),
            "owner_id": ref_id(item.owner),
            "control_action_id": ref_id(item.control_action),
            "target_process_id": ref_id(item.target_process),
            "coordination_path_id": ref_id(item.coordination_path),
        }
        for item in index.slots
    ]


def _compact_routing_loss_graph(
    index: ProviderTargetIndex, glossary: _RoutingGlossary
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Project hazards and constraints with their related IDs."""
    ref_id = glossary.ref_id
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
    return hazards, constraints


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
    return render_structural_routing_prompts(context, loss_analysis=loss_analysis)


def render_structural_routing_prompts(
    context: ProviderRoutingContext, *, loss_analysis: LossAnalysis
) -> tuple[str, str]:
    """Render system/user prompts from an already projected routing view."""
    routing_targeted_example, routing_unresolved_example = _routing_wire_examples()
    system = _TEMPLATE_LOADER.render_prompt(
        "structural_routing_system.j2",
        obligation_count=len(context.obligation_questions),
        instructions=context.instructions,
        routing_targeted_example=routing_targeted_example,
        routing_unresolved_example=routing_unresolved_example,
    )
    user = _TEMPLATE_LOADER.render_prompt(
        "structural_routing_user.j2",
        known_concern_catalog_yaml=_yaml(
            _routing_concern_catalog(context.obligation_questions)
        ),
        obligation_questions_yaml=_yaml(
            [_routing_question_payload(item) for item in context.obligation_questions]
        ),
        hazard_constraint_pair_ledger=_hazard_constraint_pair_ledger(loss_analysis),
        target_index_yaml=_yaml(_compact_routing_target_payload(context.target_index)),
    )
    return system, user


def build_mechanism_verification_prompts(
    verification_items: Sequence[Mapping[str, Any]],
) -> tuple[str, str]:
    """Render the compact post-routing mechanism/path comparison."""
    items = tuple(dict(item) for item in verification_items)
    if not items:
        raise ValueError("mechanism verification requires at least one item")
    system = _TEMPLATE_LOADER.render_prompt("mechanism_verification_system.j2")
    user = _TEMPLATE_LOADER.render_prompt(
        "mechanism_verification_user.j2",
        verification_items_yaml=_yaml(items),
    )
    return system, user


def build_ica_hazard_verification_prompts(
    requests: Sequence[Any],
) -> tuple[str, str]:
    """Render the narrow independent verifier prompt for final ICAs.

    Only the request's STPA view is serialized.  Content-addressing and
    provenance fields and the proposed category are removed before rendering.
    Previous verdicts remain call bookkeeping, not evidence for this independent
    reading of the current finding.
    """
    if not requests:
        raise ValueError("ICA hazard verification requires at least one request")
    payloads: list[dict[str, Any]] = []
    for index, request in enumerate(requests, 1):
        if not hasattr(request, "model_dump"):
            raise TypeError("ICA hazard verification requests must be typed models")
        payload = request.model_dump(
            mode="json",
            exclude={
                "schema_version",
                "semantic_digest",
                "ica_id",
                "slot_id",
                "uca_type",
                "uca_definition",
            },
        )
        payload["review_ref"] = f"review-{index}"
        payloads.append(payload)
    system = _TEMPLATE_LOADER.render_prompt("ica_hazard_verification_system.j2")
    user = _TEMPLATE_LOADER.render_prompt(
        "ica_hazard_verification_user.j2",
        request_count=len(payloads),
        requests_yaml=_yaml(payloads),
    )
    return system, user


def build_ica_hazard_correction_prompts(
    request: Any,
    verdict: Any,
) -> tuple[str, str]:
    """Render one request-local correction prompt from STPA-only context."""
    if not hasattr(request, "model_dump") or not hasattr(verdict, "model_dump"):
        raise TypeError("ICA correction requires typed request and verdict values")
    request_payload = request.model_dump(mode="json", exclude={"semantic_digest"})
    request_payload.pop("schema_version", None)
    verdict_payload = verdict.model_dump(mode="json", exclude={"request_digest"})
    system = _TEMPLATE_LOADER.render_prompt("ica_hazard_correction_system.j2")
    user = _TEMPLATE_LOADER.render_prompt(
        "ica_hazard_correction_user.j2",
        request_yaml=_yaml(request_payload),
        verdict_yaml=_yaml(verdict_payload),
    )
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
    return render_structural_revision_prompts(context)


def render_structural_revision_prompts(
    context: ProviderRevisionContext,
) -> tuple[str, str]:
    """Render revision prompts from an already projected revision view."""
    system = _TEMPLATE_LOADER.render_prompt(
        "structural_revision_system.j2",
        instructions=context.instructions,
    )
    user = _TEMPLATE_LOADER.render_prompt(
        "structural_revision_user.j2",
        gaps_yaml=_yaml([item.model_dump(mode="json") for item in context.gaps]),
        target_index_yaml=_yaml(context.target_index.model_dump(mode="json")),
    )
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
    projection = project_ica_target_context(
        target_id=target_id,
        slots=slots,
        routed_briefs=routed_briefs,
        routed_routes=routed_routes,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )
    return render_synthesis_slot_prompts(projection, target_id=target_id, slots=slots)


def render_synthesis_slot_prompts(
    projection: tuple[
        ProviderTargetIndex,
        tuple[ProviderObligationQuestion | ProviderGovernanceQuestion, ...],
        tuple[ProviderRoutedRoute, ...],
    ],
    *,
    target_id: str,
    slots: Sequence[SlotPlaceholder],
) -> tuple[str, str]:
    """Render the ICA target prompt from an already projected target view."""
    target_index, questions, routes = projection
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
    system = _TEMPLATE_LOADER.render_prompt(
        "synthesis_ica_system.j2",
        has_governance_question=any(
            isinstance(item, ProviderGovernanceQuestion) for item in questions
        ),
    )
    user = _TEMPLATE_LOADER.render_prompt(
        "synthesis_ica_user.j2",
        target_id=target_id,
        target_index_yaml=_yaml(target_index.model_dump(mode="json")),
        obligation_questions_yaml=_yaml(
            [item.model_dump(mode="json") for item in questions]
        ),
        routed_routes_yaml=_yaml([item.model_dump(mode="json") for item in routes]),
        required_pairs_yaml=_yaml(required_pairs),
    )
    return system, user


__all__ = [
    "PROHIBITED_PROMPT_FIELDS",
    "audit_prompt_contract",
    "build_structural_revision_prompts",
    "build_structural_routing_prompts",
    "build_mechanism_verification_prompts",
    "build_ica_hazard_verification_prompts",
    "build_ica_hazard_correction_prompts",
    "build_synthesis_slot_prompts",
    "render_structural_revision_prompts",
    "render_structural_routing_prompts",
    "render_synthesis_slot_prompts",
    "authoritative_hazard_constraint_pairs",
    "local_obligation_handles",
    "project_control_structure_context",
    "project_ica_target_context",
    "project_obligation_question",
    "project_obligation_routing_context",
    "project_revision_context",
    "obligation_prompt_template_hashes",
    "mapping_strength_for_brief",
]

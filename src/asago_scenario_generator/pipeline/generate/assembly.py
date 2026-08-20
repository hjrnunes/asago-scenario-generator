"""Envelope assembly, I/O, and the generate_scenario entry point."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.llm.client import LLMClient, LLMResult
from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.projection_envelope import (
    ArtifactRealizationMapping,
    ArtifactStage,
    AssertionRealizationMapping,
    ProjectionEnvelopeBlock,
    ProjectionTraceabilityResult,
)
from asago_scenario_generator.models.source_influence_provenance import (
    SourceInfluenceProvenanceBlock,
    SourceInfluenceQualification,
)
from asago_scenario_generator.models.scenario import (
    ActorProfile,
    ArchitectureMatch,
    BehaviorAction,
    BehaviorAssertion,
    BehaviorSpec,
    CallMetadata,
    CallName,
    CapabilityProfileRef,
    FacetingMetadata,
    GenerationMetadata,
    NarrativeLayer,
    ScenarioEnvelope,
    TaxonomyChain,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _ACTOR_ACCESS_MAX_RETRIES,
    _ADVERSARIAL_ONLY_THREATS,
    _CONSISTENCY_MAX_RETRIES,
    _GENERATOR_VERSION,
    _ZONE_TO_DEFAULT_MAESTRO,
    compute_leaf_budget,
)
from asago_scenario_generator.pipeline.generate.priority import (
    _compute_priority,
    _extract_maestro_layers_from_tree,
)
from asago_scenario_generator.pipeline.generate.tree_validation import (
    _check_consistency,
)
from asago_scenario_generator.pipeline.generate.zones import active_narrative_zones
from asago_scenario_generator.pipeline.source_influence_builder import (
    assemble_source_influence_provenance,
)
from asago_scenario_generator.pipeline.projection import (
    CapabilityFactSnapshot,
    ProjectedCandidate,
    compute_derivation_context_digest,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.pipeline.validation import (
    check_goal_narrative_alignment,
    check_seed_mechanism_fidelity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Error class
# ---------------------------------------------------------------------------


class GenerationError(Exception):
    """Raised when scenario generation fails (recoverable per-scenario).

    Carries partial ``call_log_entries`` for any LLM calls that completed
    before the failure, plus a synthetic error entry for the failing call,
    so callers can persist them to ``calls.jsonl``.

    This is a *recoverable* error: the runner catches it per-scenario and
    continues to the next candidate.  Integrity violations that must abort
    the entire run should raise :class:`ScenarioForgeIntegrityError` instead.
    """

    def __init__(
        self,
        message: str,
        call_log_entries: list[dict] | None = None,
        seed_id: str = "",
    ) -> None:
        super().__init__(message)
        self.call_log_entries: list[dict] = call_log_entries or []
        self.seed_id = seed_id


class ScenarioForgeIntegrityError(Exception):
    """Fatal integrity error that aborts the entire pipeline run.

    Raised for duplicate candidate admission, duplicate scenario IDs,
    existing artifact paths, stem mismatches, orphan artifacts, and
    missing artifact pairs.  Unlike :class:`GenerationError`, this is
    **never** caught by per-scenario recoverable handling — it
    propagates to the top level and stops the run.
    """


class ProjectionTraceabilityError(GenerationError):
    """Typed fail-closed error for projection traceability violations.

    Raised on the production generation path when
    :func:`validate_projection_traceability` finds violations.  Carries
    the typed :class:`ProjectionTraceabilityResult` for cmps.5 to
    consume (retry/quarantine routing).  Generation does not retry
    here; cmps.5 owns the retry/quarantine state machine.

    This is a *recoverable* error (subclass of GenerationError): the
    runner catches it per-scenario and continues to the next candidate.
    """

    def __init__(
        self,
        result: ProjectionTraceabilityResult,
        scenario_id: str,
        call_log_entries: list[dict] | None = None,
        seed_id: str = "",
    ) -> None:
        detail = "; ".join(
            f"[{v.stage.value}:{v.code.value}] {v.detail}" for v in result.violations
        )
        super().__init__(
            f"Projection traceability violations for {scenario_id}: {detail}",
            call_log_entries=call_log_entries,
            seed_id=seed_id,
        )
        self.result = result
        self.scenario_id = scenario_id


class SourceInfluenceProvenanceError(GenerationError):
    """Typed fail-closed error for source-influence provenance violations.

    Raised on the production generation path when
    :func:`validate_source_influence_provenance` finds violations.
    Carries the typed :class:`SourceInfluenceQualification` for callers
    to consume (retry/quarantine routing).  Generation does not retry
    here; the lifecycle owner routes the failure.

    This is a *recoverable* error (subclass of GenerationError): the
    runner catches it per-scenario and continues to the next candidate.
    """

    def __init__(
        self,
        result: SourceInfluenceQualification,
        scenario_id: str,
        call_log_entries: list[dict] | None = None,
        seed_id: str = "",
    ) -> None:
        detail = "; ".join(f"[{v.code.value}] {v.detail}" for v in result.violations)
        super().__init__(
            f"Source-influence provenance violations for {scenario_id}: {detail}",
            call_log_entries=call_log_entries,
            seed_id=seed_id,
        )
        self.result = result
        self.scenario_id = scenario_id


# ---------------------------------------------------------------------------
# Run identity and scenario ID
# ---------------------------------------------------------------------------

_SCENARIO_ID_VERSION = "v2"
_RUN_ID_LEN = 48  # YYYYMMDDTHHMMSS_<32hex> = 128-bit entropy suffix
_CANDIDATE_ID_PREFIX = "cand:v2:"
_CANDIDATE_ID_HEX_LEN = 32


def generate_run_id() -> str:
    """Generate a sortable, collision-safe per-invocation run ID.

    Uses the cmps.1 sortable format: ``YYYYMMDDTHHMMSS_<32hex>`` (48 chars).
    The timestamp prefix makes run directories sortable by lexical order.
    The 128-bit random suffix prevents collisions within the same second.
    """
    from asago_scenario_generator.manifest import generate_sortable_run_id

    return generate_sortable_run_id()


def _validate_run_id(run_id: str) -> None:
    """Validate that run_id is a canonical sortable generation identifier.

    Accepts **only** the cmps.1 sortable format:
    ``YYYYMMDDTHHMMSS_<32hex>`` (48 chars, 128-bit random suffix).

    Legacy 32-char hex IDs are accepted solely by manifest forensic
    discovery/loading, not by generation APIs.
    """
    from asago_scenario_generator.manifest import validate_generation_run_id

    validate_generation_run_id(run_id)


def _validate_candidate_id(candidate_id: str) -> None:
    """Validate that candidate_id follows cand:v2:<32-char lowercase hex> format."""
    if not candidate_id or not candidate_id.startswith(_CANDIDATE_ID_PREFIX):
        raise ValueError(
            f"candidate_id must follow '{_CANDIDATE_ID_PREFIX}<32-char hex>'"
        )
    hex_part = candidate_id[len(_CANDIDATE_ID_PREFIX) :]
    if len(hex_part) != _CANDIDATE_ID_HEX_LEN:
        raise ValueError(f"candidate_id hex part must be {_CANDIDATE_ID_HEX_LEN} chars")
    if hex_part != hex_part.lower():
        raise ValueError("candidate_id hex part must be lowercase")
    try:
        int(hex_part, 16)
    except ValueError:
        raise ValueError("candidate_id hex part must be valid hex") from None


def compute_scenario_id(
    run_id: str,
    candidate_id: str,
    attempt: int = 1,
) -> str:
    """Compute a collision-safe, run-specific scenario ID.

    The ID incorporates the per-invocation ``run_id`` (128 bits of entropy),
    the stable ``candidate_id`` (128 bits), and the generation ``attempt``
    so that distinct generated narratives are not falsely the same
    scenario.

    The hash is computed over a canonical JSON encoding of the
    structured identity inputs, not an ambiguous delimiter
    concatenation, so that different values cannot collide due to
    delimiter ambiguity.

    Format: ``scenario:<version>:<256-bit hex digest>``

    Args:
        run_id: Per-invocation collision-safe run ID (128-bit hex).
        candidate_id: Stable canonical candidate identity.
        attempt: Generation attempt number (must be >= 1).

    Raises:
        ValueError: If run_id or candidate_id are invalid, or attempt < 1.
    """
    _validate_run_id(run_id)
    _validate_candidate_id(candidate_id)
    if attempt < 1:
        raise ValueError(f"attempt must be >= 1, got {attempt}")
    identity = json.dumps(
        {"run_id": run_id, "candidate_id": candidate_id, "attempt": attempt},
        sort_keys=True,
        separators=(",", ":"),
    )
    h = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"scenario:{_SCENARIO_ID_VERSION}:{h}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _call_metadata(call_name: CallName, result: LLMResult) -> CallMetadata:
    return CallMetadata(
        call=call_name,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        duration_ms=result.duration_ms,
    )


def _call_log_entry(
    call_name: CallName,
    result: LLMResult,
    scenario_id: str,
) -> dict:
    """Build a JSON-serialisable log entry for a single LLM call."""
    raw_content = result.content
    if hasattr(raw_content, "model_dump"):
        raw_content = raw_content.model_dump(mode="json")
    elif not isinstance(raw_content, str):
        raw_content = str(raw_content)
    return {
        "scenario_id": scenario_id,
        "call": call_name.value,
        "system_prompt": result.system_prompt,
        "user_prompt": result.user_prompt,
        "response": raw_content,
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
        "duration_ms": result.duration_ms,
    }


def _call_log_entry_error(
    call_name: CallName,
    result: LLMResult | None,
    scenario_id: str,
    error: str,
) -> dict:
    """Build a JSON-serialisable log entry for a *failed* LLM call.

    When ``result`` is available (e.g. the LLM returned text that failed
    parsing/validation), its prompts and raw response are preserved.  When
    ``result`` is ``None`` (e.g. the LLM call itself raised), only the
    error message is recorded.
    """
    if result is not None:
        raw_content = result.content
        if hasattr(raw_content, "model_dump"):
            raw_content = raw_content.model_dump(mode="json")
        elif not isinstance(raw_content, str):
            raw_content = str(raw_content)
        return {
            "scenario_id": scenario_id,
            "call": call_name.value,
            "system_prompt": result.system_prompt,
            "user_prompt": result.user_prompt,
            "response": raw_content,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "duration_ms": result.duration_ms,
            "error": error,
        }
    return {
        "scenario_id": scenario_id,
        "call": call_name.value,
        "error": error,
    }


# ---------------------------------------------------------------------------#
# Projection block construction from actual artifacts (422o.4)
# ---------------------------------------------------------------------------#


def _iter_leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Yield all leaf nodes in deterministic DFS order."""
    if node.gate == GateType.LEAF:
        return [node]
    leaves: list[AttackTreeNode] = []
    for child in node.children or []:
        leaves.extend(_iter_leaves(child))
    return leaves


def build_behavior_spec_from_tree(
    attack_tree: AttackTree,
    block: ProjectionEnvelopeBlock,
    gherkin_text: str | None = None,
) -> BehaviorSpec:
    """Construct a structured BehaviorSpec from tree leaves and projection.

    Structured behavior actions are deterministically derived from
    validated tree leaves (which carry ``projected_step_ids``), with stable
    IDs of the form ``ba-<leaf_id>``.  Structured assertions are derived
    from security-relevant postconditions of the projected steps, with
    stable IDs of the form ``assert-<step_id>-<postcondition_id>``.

    The Gherkin feature text is **deterministically rendered** from the
    structured actions and assertions — not from an independently authored
    LLM output.  This proves exact correspondence: every action/assertion
    ID in the structure appears in the rendered Gherkin in the correct
    order.  The LLM Call 3 output (``gherkin_text``) is cross-checked
    against the deterministic rendering to ensure the LLM did not omit,
    add, reorder, or fabricate actions/assertions.

    Validation cross-checks the structured elements against the projection
    block and the rendered Gherkin.
    """
    chain = block.projection.source_chain
    selected = set(block.projection.selected_step_ids)

    actions: list[BehaviorAction] = []
    step_by_id = {s.step_id: s for s in chain.steps}
    for leaf in _iter_leaves(attack_tree.root):
        if not leaf.projected_step_ids:
            continue
        if not all(sid in selected for sid in leaf.projected_step_ids):
            continue
        # Derive text from the tree leaf's label/description.
        text = leaf.label or leaf.id
        if leaf.description:
            text = leaf.description
        # Get canonical semantics from the first mapped projected step.
        first_step = step_by_id.get(leaf.projected_step_ids[0])
        actions.append(
            BehaviorAction(
                action_id=f"ba-{leaf.id}",
                projected_step_ids=leaf.projected_step_ids,
                source_leaf_id=leaf.id,
                gherkin_keyword="When",
                text=text,
                canonical_action_kind=(
                    first_step.action_kind if first_step else "observe"
                ),
                canonical_executor_role=(
                    first_step.executor_role if first_step else "system"
                ),
                canonical_boundary_position=(
                    first_step.boundary_position if first_step else "inside"
                ),
            )
        )

    # Build assertions from security-relevant postconditions.
    assertions: list[BehaviorAssertion] = []
    sec_pcs = block.security_relevant_postconditions()
    for step_id in block.projection.selected_step_ids:
        pc_ids = sec_pcs.get(step_id, [])
        if not pc_ids:
            continue
        # Get postcondition descriptions for assertion text.
        step_obj = next((s for s in chain.steps if s.step_id == step_id), None)
        pc_descs: list[str] = []
        for pc_id in pc_ids:
            pc = next(
                (
                    p
                    for p in (step_obj.observable_postconditions if step_obj else [])
                    if p.postcondition_id == pc_id
                ),
                None,
            )
            if pc is not None:
                pc_descs.append(pc.description)
            else:
                pc_descs.append(pc_id)
        assertion_text = "; ".join(pc_descs) if pc_descs else f"Verify {step_id}"
        assertions.append(
            BehaviorAssertion(
                assertion_id=f"assert-{step_id}-{'-'.join(pc_ids)}",
                source_step_ids=(step_id,),
                projected_postcondition_ids=tuple(pc_ids),
                gherkin_keyword="Then",
                text=assertion_text,
            )
        )

    # Build zone map from tree leaves for Gherkin zone annotations.
    zone_map: dict[str, str] = {}
    for leaf in _iter_leaves(attack_tree.root):
        if leaf.projected_step_ids and leaf.zone is not None:
            zone_map[f"ba-{leaf.id}"] = leaf.zone

    rendered = render_gherkin_from_behavior_spec(actions, assertions, zone_map=zone_map)
    return BehaviorSpec(
        actions=tuple(actions),
        assertions=tuple(assertions),
        gherkin_text=rendered,
    )


def render_gherkin_from_behavior_spec(
    actions: list[BehaviorAction],
    assertions: list[BehaviorAssertion],
    *,
    zone_map: dict[str, str] | None = None,
) -> str:
    """Deterministically render Gherkin feature text from structured behavior.

    This is the authoritative rendering: the structured actions and
    assertions are the source of truth, and the Gherkin text is derived
    from them.  This proves exact correspondence — every action/assertion
    ID appears in the rendered text in the correct order.

    When ``zone_map`` is supplied (mapping ``action_id`` → zone name),
    zone annotations are included in the Gherkin step text as
    ``(zone_name)`` suffixes, enabling zone-omission validation.
    """
    lines: list[str] = ["Feature: Projected scenario behavior", ""]

    # Background with projection context (informational).
    lines.append("  Background:")
    lines.append("    Given a target AI system with projected attack steps")
    lines.append("")

    # Scenario outline with structured actions.
    lines.append("  Scenario: Projected attack realization")
    lines.append("")

    # Preserve typed transitions.  ``And`` is only shorthand for another
    # action of the same semantic keyword as the immediately preceding action.
    previous_keyword: str | None = None
    for action in actions:
        zone_suffix = ""
        if zone_map and action.action_id in zone_map:
            zone_suffix = f" ({zone_map[action.action_id]})"
        keyword = (
            "And"
            if previous_keyword == action.gherkin_keyword
            else action.gherkin_keyword
        )
        lines.append(f"    {keyword} {action.text}{zone_suffix}")
        previous_keyword = action.gherkin_keyword

    # Render assertions (Then steps).
    for assertion in assertions:
        lines.append(f"    {assertion.gherkin_keyword} {assertion.text}")

    return "\n".join(lines) + "\n"


def _build_projection_block(
    candidate: ProjectedCandidate,
    narrative: NarrativeLayer,
    attack_tree: AttackTree | None,
    behavior_spec: BehaviorSpec | str | None,
    capability_snapshot: CapabilityFactSnapshot,
) -> ProjectionEnvelopeBlock:
    """Build a ProjectionEnvelopeBlock from a ProjectedCandidate and actual artifacts.

    Realization mappings are derived deterministically from the actual
    artifact fields (projected_step_ids on narrative steps and tree leaves,
    structured behavior actions/assertions) — never from an independently
    authored sidecar table.
    """
    # Build narrative realizations from actual narrative.steps
    narrative_realizations: list[ArtifactRealizationMapping] = []
    for step in narrative.steps:
        if step.projected_step_ids:
            narrative_realizations.append(
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.narrative,
                    element_id=str(step.step_number),
                    projected_step_ids=step.projected_step_ids,
                )
            )

    # Build tree realizations from actual tree leaf projected_step_ids fields
    tree_realizations: list[ArtifactRealizationMapping] = []
    if attack_tree is not None:
        for leaf in _iter_leaves(attack_tree.root):
            if leaf.projected_step_ids:
                tree_realizations.append(
                    ArtifactRealizationMapping(
                        artifact_stage=ArtifactStage.attack_tree,
                        element_id=leaf.id,
                        projected_step_ids=leaf.projected_step_ids,
                    )
                )

    # Build behavior/assertion realizations from structured BehaviorSpec
    behavior_realizations: list[ArtifactRealizationMapping] = []
    assertion_realizations: list[AssertionRealizationMapping] = []
    if isinstance(behavior_spec, BehaviorSpec):
        for action in behavior_spec.actions:
            behavior_realizations.append(
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.behavior,
                    element_id=action.action_id,
                    projected_step_ids=action.projected_step_ids,
                )
            )
        for assertion in behavior_spec.assertions:
            assertion_realizations.append(
                AssertionRealizationMapping(
                    element_id=assertion.assertion_id,
                    source_step_ids=assertion.source_step_ids,
                    projected_postcondition_ids=assertion.projected_postcondition_ids,
                )
            )

    return ProjectionEnvelopeBlock(
        projection=candidate.projection,
        canonical_ingress=candidate.canonical_ingress,
        ingress_controllability=candidate.ingress_controllability,
        projected_mappings=candidate.projected_mappings,
        capability_snapshot=capability_snapshot,
        execution_requirements=candidate.execution_requirements,
        requirement_derivation_version=candidate.requirement_derivation_version,
        execution_requirements_digest=candidate.execution_requirements_digest,
        derivation_context_digest=compute_derivation_context_digest(
            candidate.projection.projection_digest,
            candidate.projection.source_chain.pattern_id,
            candidate.ingress_controllability,
        ),
        narrative_realizations=tuple(narrative_realizations),
        tree_realizations=tuple(tree_realizations),
        behavior_realizations=tuple(behavior_realizations),
        assertion_realizations=tuple(assertion_realizations),
    )


def _build_projection_context(candidate: ProjectedCandidate) -> dict[str, Any]:
    """Build the immutable projection constraints passed to every Call 0–3.

    The context contains only creative-guidance data that the LLM needs
    to follow the projection:

    * **selected_steps** — ordered step list with action_kind,
      executor_role, boundary_position, requirement, and simplified
      resource_links (role + humanized resource name).
    * **selected_step_ids** / **omitted_step_ids** — which steps are
      active vs skipped.
    * **canonical_ingress** / **ingress_controllability** — the
      mandatory entry point.

    Infrastructure-only fields removed in Phase 4 (they provided zero
    creative guidance to the LLM):

    * ``condition_results`` — internal precondition evaluation records
    * ``condition_evaluations`` — precondition summary
    * ``execution_requirements`` — adapter-neutral requirement records
    * ``projected_mappings`` — step-to-taxonomy mappings (already in
      ontology context)
    * ``resource_slots`` — slot abstraction (resources visible by name
      in tool inventory and step resource_links)
    * ``bindings`` — slot-to-resource mappings (redundant after Phase 3
      humanization)

    ``observable_postconditions`` is retained because Call 3
    validation (``gherkin.py``) reads it to build postcondition
    ownership tables.

    The ``"realization"`` key on each step dict is retained because
    ``_fill_tree_realizations`` reads it during post-processing.
    """
    from asago_scenario_generator.models.realization import (
        derive_step_realization,
    )

    chain = candidate.projection.source_chain
    selected_step_ids = set(candidate.projection.selected_step_ids)
    selected_steps = [step for step in chain.steps if step.step_id in selected_step_ids]

    # Serialize concrete resource bindings with their resource_ref values.
    bindings_by_slot = {b.slot_id: b for b in candidate.projection.bindings}
    binding_by_slot = {b.slot_id: b.resource_ref for b in candidate.projection.bindings}

    # Build canonical realization records per step — retained for
    # post-processing (_fill_tree_realizations) but not rendered in prompts.
    step_realizations: dict[str, dict[str, Any]] = {}
    for step in selected_steps:
        r = derive_step_realization(step, binding_by_slot)
        step_realizations[step.step_id] = r.model_dump(mode="json")

    return {
        "selected_steps": [
            {
                "step_id": step.step_id,
                "order": step.order,
                "action_kind": step.action_kind,
                "executor_role": step.executor_role,
                "boundary_position": step.boundary_position,
                "attacker_controlled": step.attacker_controlled,
                "requirement": step.requirement,
                "resource_links": [
                    {
                        "role": link.role,
                        # Include the concrete resource_ref for this slot
                        # (humanized to names by Phase 3 before rendering).
                        "resource_ref": (
                            bindings_by_slot[link.slot_id].resource_ref.model_dump(
                                mode="json"
                            )
                            if link.slot_id in bindings_by_slot
                            else None
                        ),
                    }
                    for link in step.resource_links
                ],
                # Postconditions are retained for Call 3 validation
                # (gherkin.py builds postcondition ownership tables).
                "observable_postconditions": [
                    {
                        "postcondition_id": pc.postcondition_id,
                        "description": pc.description,
                        "security_relevant": pc.security_relevant,
                        "terminal": pc.terminal,
                    }
                    for pc in step.observable_postconditions
                ],
                # Canonical realization record — used by post-processing
                # (_fill_tree_realizations), not rendered in prompts.
                "realization": step_realizations.get(step.step_id, {}),
            }
            for step in selected_steps
        ],
        "selected_step_ids": list(candidate.projection.selected_step_ids),
        "omitted_step_ids": [o.step_id for o in candidate.projection.omissions],
        "canonical_ingress": candidate.canonical_ingress.model_dump(mode="json"),
        "ingress_controllability": candidate.ingress_controllability,
        "pattern_id": chain.pattern_id,
        "chain_id": chain.chain_id,
        "chain_semantic_revision": chain.semantic_revision,
        "chain_semantic_digest": chain.semantic_digest,
    }


# ---------------------------------------------------------------------------
# Envelope assembly
# ---------------------------------------------------------------------------


def _assemble_envelope(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    narrative: NarrativeLayer,
    attack_tree: AttackTree | None,
    behavior_spec: str | BehaviorSpec | None,
    call_metadata_list: list[CallMetadata],
    model_name: str,
    use_case: str,
    notes: list[str],
    pinned_entry_point_id: str,
    *,
    actor_profile: ActorProfile | None = None,
    pinned_technique_ids: list[str] | None = None,
    pinned_entry_point: str | None = None,
    run_id: str = "",
    candidate_id: str = "",
    attempt: int = 1,
    projected_candidate: ProjectedCandidate,
    capability_snapshot: CapabilityFactSnapshot,
    source_influence_provenance: SourceInfluenceProvenanceBlock | None = None,
) -> ScenarioEnvelope:
    _validate_run_id(run_id)
    # Derive candidate_id from projected candidate if not supplied.
    if not candidate_id:
        candidate_id = projected_candidate.candidate_id
    elif candidate_id != projected_candidate.candidate_id:
        raise ValueError(
            f"candidate_id '{candidate_id}' does not match projected "
            f"candidate identity '{projected_candidate.candidate_id}'"
        )
    _validate_candidate_id(candidate_id)
    if attempt < 1:
        raise ValueError(f"attempt must be >= 1, got {attempt}")
    scenario_id = compute_scenario_id(run_id, candidate_id, attempt)

    maestro_layers: set[int] = set()
    if attack_tree is not None:
        maestro_layers = _extract_maestro_layers_from_tree(attack_tree.root)
    if not maestro_layers:
        for z in narrative.zone_sequence:
            default = _ZONE_TO_DEFAULT_MAESTRO.get(z)
            if default is not None:
                maestro_layers.add(default)
    if not maestro_layers:
        maestro_layers = {3}

    # Derive atlas_technique_ids from the actual attack tree content,
    # not from seed metadata.  The seed's atlas_technique_ids reflects
    # upstream provenance; the tree may legitimately drop techniques
    # (e.g. the candidate filter pins fewer).  Using tree-derived IDs
    # prevents orphan claims in the taxonomy chain.
    if attack_tree is not None:
        tree_technique_ids = attack_tree.collect_technique_ids()
        reconciled_technique_ids = tree_technique_ids if tree_technique_ids else None
    else:
        # No tree — fall back to seed metadata (best available).
        reconciled_technique_ids = seed.atlas_technique_ids or None

    faceting = FacetingMetadata(
        risk_card=seed.risk_card_ref,
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=seed.owasp_llm_ids,
            agentic_threat_ids=seed.agentic_threat_ids,
            owasp_asi_ids=seed.owasp_asi_ids,
            atlas_technique_ids=reconciled_technique_ids,
            scenario_seed=seed.seed_id,
        ),
        capability_profile=CapabilityProfileRef(
            # Literal 'outside' traversal is excluded: the facade records
            # the active Schneider zones actually traversed.
            zones_traversed=active_narrative_zones(narrative.zone_sequence),
            architecture_match=ArchitectureMatch.explicit,
            entry_point=narrative.entry_point,
        ),
        maestro_layers=sorted(maestro_layers),
    )

    priority = _compute_priority(narrative, attack_tree, seed)

    generation = GenerationMetadata(
        model=model_name,
        call_metadata=call_metadata_list,
        notes=notes if notes else None,
    )

    scenario_seed_metadata = {
        "seed_id": seed.seed_id,
        "threat_id": seed.threat_id,
        "threat_name": seed.threat_name,
        "attack_pattern_name": seed.attack_pattern_name,
        "attack_pattern_description": seed.attack_pattern_description,
        "owasp_origin": seed.owasp_origin,
        "laaf_technique_ids": seed.laaf_technique_ids,
        "atlas_provenance_ids": seed.atlas_provenance_ids,
    }

    # Build the immutable projection block from the ProjectedCandidate
    # and actual generated artifacts (422o.4).
    # projected_candidate is required (enforced by type signature).

    # Call 3 now returns a structured BehaviorSpec directly (422o.4 blocker #5).
    # The BehaviorSpec is validated against the projection in _call_behavior_spec
    # and carried through to the envelope.  No deterministic replacement.
    if not isinstance(behavior_spec, BehaviorSpec):
        raise GenerationError(
            "Call 3 must return a structured BehaviorSpec (422o.4). "
            "Raw text behavior specs are no longer accepted."
        )

    projection_block = _build_projection_block(
        projected_candidate,
        narrative,
        attack_tree,
        behavior_spec,
        capability_snapshot,
    )

    # Source-influence provenance (Wave 2 slice 5, QA-TSIP contract):
    # generate always attaches the typed provenance block.  When the
    # caller supplies an explicit block it is preserved; otherwise the
    # block is assembled deterministically from the seed's risk inputs
    # (threat sources), the committed OWASP playbooks (mitigations), the
    # capability profile's KC sub-codes (constraints), and the actual
    # projected leaf/narrative artifacts.  The finalization gate then
    # re-validates the persisted qualification fail-closed.
    if source_influence_provenance is None:
        source_influence_provenance = assemble_source_influence_provenance(
            seed=seed,
            capability_snapshot=capability_snapshot,
            attack_tree=attack_tree,
            narrative=narrative,
            selected_step_ids=projected_candidate.projection.selected_step_ids,
        )

    # Use the canonical ingress ID from the projection.
    effective_entry_point_id = projected_candidate.canonical_ingress.entry_point_id

    return ScenarioEnvelope(
        scenario_id=scenario_id,
        candidate_id=candidate_id,
        version=3,
        generated_at=datetime.now(UTC),
        generator_version=_GENERATOR_VERSION,
        scenario_seed_metadata=scenario_seed_metadata,
        legitimate_task=use_case,
        actor_profile=actor_profile,
        initial_entry_point_id=effective_entry_point_id,
        projection=projection_block,
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=behavior_spec,
        faceting=faceting,
        priority=priority,
        generation=generation,
        source_influence_provenance=source_influence_provenance,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _generate_scenario_compatibility(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    pinned_entry_point_id: str,
    *,
    preferred_entry_point: str | None = None,
    excluded_entry_points: list[str] | None = None,
    excluded_patterns: list[str] | None = None,
    excluded_structural_patterns: list[str] | None = None,
    preferred_actor_type: str | None = None,
    excluded_actor_types: list[str] | None = None,
    preferred_capability_level: str | None = None,
    attack_goal: dict[str, Any] | None = None,
    pinned_entry_point: str | None = None,
    pinned_technique_ids: list[str] | None = None,
    pinned_technique_names: list[str] | None = None,
    prior_titles: list[str] | None = None,
    run_id: str = "",
    candidate_id: str = "",
    attempt: int = 1,
    projected_candidate: ProjectedCandidate,
    capability_snapshot: CapabilityFactSnapshot,
) -> tuple[ScenarioEnvelope, list[dict]]:
    """Generate a complete ScenarioEnvelope from a single seed.

    Four sequential LLM calls:
      0. Actor profile (structured output)
      1. Narrative (structured output, grounded in actor profile)
      2. Attack tree (YAML text, parsed)
      3. Behavior spec (Gherkin plain text)

    All four calls must succeed; failures propagate to the caller.
    The runner's per-scenario try/except handles logging and continuation.

    Returns:
        A tuple of (envelope, call_log_entries).  The call log entries are
        JSON-serialisable dicts suitable for writing to ``calls.jsonl``.

    Args:
        seed: The scenario seed to generate from.
        profile: The system's capability profile.
        client: LLM client for generation calls.
        use_case: Free-text description of the system under assessment.
        preferred_entry_point: Suggested entry point for diversity (hint, not enforced).
        excluded_entry_points: Entry points to avoid (already overused in this batch).
        excluded_patterns: Attack pattern keywords to avoid (already overused in this batch).
        excluded_structural_patterns: Structural attack phase sequences to avoid
            (e.g., "inject->hallucinate->persist->bypass").
        preferred_actor_type: Suggested actor type for diversity (hint, not enforced).
        excluded_actor_types: Actor types to avoid (already overused in this batch).
        preferred_capability_level: Suggested capability level for diversity
            (hint, not enforced).
        attack_goal: Selected attack goal sub-goal dict from the taxonomy.
            When provided, orients the actor's desires toward this goal category.
        pinned_entry_point: Hard-constrained entry point from the candidate filter.
            When set, overrides preferred_entry_point and excluded_entry_points.
        pinned_technique_ids: Hard-constrained ATLAS technique IDs from the candidate
            filter. When set, only these techniques are passed to prompt context.
        pinned_technique_names: Human-readable names of the pinned techniques, for
            context in prompts.
        prior_titles: List of titles already generated in this batch. Passed to
            the Call 1 diversity section so the LLM avoids duplicate titles.
        run_id: Per-invocation collision-safe run ID (128-bit hex). Required
            for collision-safe scenario identity.
        candidate_id: Stable canonical candidate identity (cand:v2:<128-bit hex>).
            Derived from the projected candidate when available; must match
            the projected candidate's identity for collision-safe scenario identity.
        attempt: Generation attempt number (default 1). Incorporated into
            scenario_id so distinct generation attempts are not the same scenario.
        projected_candidate: Qualified candidate-v2 projection (required).
            Generation is paused during the projection migration; legacy
            seed-only generation is no longer supported.
    """
    # Late imports: these names are looked up from the package namespace
    # so that unittest.mock.patch("asago_scenario_generator.pipeline.generate.X")
    # correctly intercepts them.
    import asago_scenario_generator.pipeline.generate as _gen

    _call_actor_profile = _gen._call_actor_profile
    _validate_actor_type = _gen._validate_actor_type
    _call_narrative = _gen._call_narrative
    _call_attack_tree = _gen._call_attack_tree
    _call_behavior_spec = _gen._call_behavior_spec
    _warn_dominant_threat_id_crossref_fn = _gen._warn_dominant_threat_id_crossref
    _assemble_envelope_fn = _gen._assemble_envelope
    _validate_realization = _gen.narrative.validate_narrative_access_realization

    # Derive candidate identity from the projected candidate (422o.4).
    # The projected candidate's cand:v2 identity is the authoritative
    # identity; the caller-supplied candidate_id must match or be empty
    # (in which case we use the projected candidate's identity).
    if not candidate_id:
        candidate_id = projected_candidate.candidate_id
    elif candidate_id != projected_candidate.candidate_id:
        raise ValueError(
            f"candidate_id '{candidate_id}' does not match projected "
            f"candidate identity '{projected_candidate.candidate_id}'"
        )

    # Enforce identity inputs at the generation boundary.
    _validate_run_id(run_id)
    _validate_candidate_id(candidate_id)
    if attempt < 1:
        raise ValueError(f"attempt must be >= 1, got {attempt}")

    # Build the immutable projection context that every Call 0–3 receives
    # (422o.4).  All calls get the same full ordered selected steps,
    # omissions/condition decisions, execution requirements, bindings,
    # exact opaque IDs, mappings, and canonical ingress constraints.
    projection_context = _build_projection_context(projected_candidate)

    call_metas: list[CallMetadata] = []
    scenario_id = compute_scenario_id(run_id, candidate_id, attempt)

    # Partial scenario_id for error logging (before envelope is assembled).
    partial_scenario_id = scenario_id

    # Collect call log entries incrementally so that failures still produce
    # a trace in calls.jsonl.
    call_log_entries: list[dict] = []
    results: dict[CallName, LLMResult] = {}

    # --- Pre-filter: exclude negligent-insider for adversarial-only threats ---
    if seed.threat_id in _ADVERSARIAL_ONLY_THREATS:
        excluded_actor_types = (
            list(excluded_actor_types) if excluded_actor_types else []
        )
        if "negligent-insider" not in excluded_actor_types:
            excluded_actor_types.append("negligent-insider")
            logger.debug(
                "Excluding negligent-insider for adversarial-only threat %s (seed %s)",
                seed.threat_id,
                seed.seed_id,
            )

    # --- Call 0: Actor Profile ---
    _diversity_notes: list[str] = []
    try:
        actor_profile, result0, _div_limitation = _call_actor_profile(
            seed,
            profile,
            client,
            use_case,
            preferred_actor_type=preferred_actor_type,
            excluded_actor_types=excluded_actor_types,
            preferred_capability_level=preferred_capability_level,
            attack_goal=attack_goal,
            pinned_technique_ids=pinned_technique_ids,
            pinned_entry_point=pinned_entry_point,
            pinned_entry_point_id=pinned_entry_point_id,
            projection_context=projection_context,
        )
        if _div_limitation:
            _diversity_notes.append(
                f"Diversity limitation: forced actor '{_div_limitation}' was "
                f"incompatible, replaced with feasible fallback."
            )
    except Exception as exc:
        call_log_entries.append(
            _call_log_entry_error(
                CallName.actor_profile, None, partial_scenario_id, str(exc)
            )
        )
        raise GenerationError(str(exc), call_log_entries, seed.seed_id) from exc

    original_actor_type = actor_profile.actor_type
    actor_profile = _validate_actor_type(actor_profile)

    # If BDI validation reassigned the actor type, regenerate the full profile
    # so that beliefs/desires/intentions/resources match the corrected type.
    if actor_profile.actor_type != original_actor_type:
        logger.warning(
            "BDI reassignment: regenerating actor profile with forced "
            "actor_type '%s' (was '%s') for seed %s",
            actor_profile.actor_type,
            original_actor_type,
            seed.seed_id,
        )
        corrected_type = actor_profile.actor_type
        try:
            actor_profile, result0, _div_limitation = _call_actor_profile(
                seed,
                profile,
                client,
                use_case,
                excluded_actor_types=excluded_actor_types,
                preferred_capability_level=preferred_capability_level,
                attack_goal=attack_goal,
                pinned_technique_ids=pinned_technique_ids,
                forced_actor_type=corrected_type,
                pinned_entry_point=pinned_entry_point,
                pinned_entry_point_id=pinned_entry_point_id,
                projection_context=projection_context,
            )
            if _div_limitation:
                _diversity_notes.append(
                    f"Diversity limitation: forced actor '{_div_limitation}' "
                    f"was incompatible, replaced with feasible fallback."
                )
        except Exception as exc:
            call_log_entries.append(
                _call_log_entry_error(
                    CallName.actor_profile,
                    None,
                    partial_scenario_id,
                    f"BDI regeneration failed: {exc}",
                )
            )
            raise GenerationError(
                f"BDI regeneration failed: {exc}",
                call_log_entries,
                seed.seed_id,
            ) from exc

        # Defence in depth: re-validate the regenerated profile.
        actor_profile = _validate_actor_type(actor_profile)
        if actor_profile.actor_type != corrected_type:
            logger.warning(
                "BDI regeneration: regenerated profile still has wrong "
                "actor_type '%s' (expected '%s') — accepting as-is",
                actor_profile.actor_type,
                corrected_type,
            )

    # Store the selected goal category on the actor profile (Step 5).
    if attack_goal is not None:
        actor_profile.goal_category = attack_goal["id"]
        actor_profile.goal_category_name = attack_goal["name"]
        actor_profile.goal_category_parent = attack_goal["category_name"]

    # --- Post-Call-0: actor/access provenance validation + retry (cmps.6) ---
    _validate_access = _gen.validate_actor_access_provenance
    _access_violations = (
        _validate_access(actor_profile, profile) if pinned_entry_point_id else []
    )
    _access_retry = 0
    while _access_violations and _access_retry < _ACTOR_ACCESS_MAX_RETRIES:
        _access_retry += 1
        _access_feedback = "\n".join(f"- {v.message}" for v in _access_violations)
        logger.warning(
            "Actor/access provenance violations in %s (retry %d/%d): %s",
            partial_scenario_id,
            _access_retry,
            _ACTOR_ACCESS_MAX_RETRIES,
            _access_feedback,
        )
        # cmps.6: if the violation indicates actor/evidence incompatibility,
        # do not force the same actor type — let the LLM pick a feasible one.
        _force_type: str | None = actor_profile.actor_type
        if any(
            v.rule
            in (
                "access_class_ingress_mode_incompatible",
                "missing_insider_advantage",
            )
            for v in _access_violations
        ):
            _force_type = None
            logger.info(
                "Access retry %d: not forcing actor '%s' due to "
                "access-class/ingress-mode incompatibility",
                _access_retry,
                actor_profile.actor_type,
            )
        try:
            actor_profile, result0, _div_limitation = _call_actor_profile(
                seed,
                profile,
                client,
                use_case,
                excluded_actor_types=excluded_actor_types,
                preferred_capability_level=preferred_capability_level,
                attack_goal=attack_goal,
                pinned_technique_ids=pinned_technique_ids,
                forced_actor_type=_force_type,
                pinned_entry_point=pinned_entry_point,
                pinned_entry_point_id=pinned_entry_point_id,
                access_feedback=_access_feedback,
                projection_context=projection_context,
            )
            if _div_limitation:
                _diversity_notes.append(
                    f"Diversity limitation: forced actor '{_div_limitation}' "
                    f"was incompatible, replaced with feasible fallback."
                )
            actor_profile = _validate_actor_type(actor_profile)
            if attack_goal is not None:
                actor_profile.goal_category = attack_goal["id"]
                actor_profile.goal_category_name = attack_goal["name"]
                actor_profile.goal_category_parent = attack_goal["category_name"]
        except Exception as exc:  # noqa: BLE001 - retry must catch all
            logger.warning(
                "Actor/access retry %d/%d failed for %s: %s",
                _access_retry,
                _ACTOR_ACCESS_MAX_RETRIES,
                partial_scenario_id,
                exc,
            )
            break
        _access_violations = _validate_access(actor_profile, profile)

    if _access_violations:
        logger.warning(
            "Actor/access provenance violations persist after %d retries for "
            "%s — proceeding to semantic validation for quarantine: %s",
            _access_retry,
            partial_scenario_id,
            "; ".join(v.message for v in _access_violations),
        )

    call_metas.append(_call_metadata(CallName.actor_profile, result0))
    results[CallName.actor_profile] = result0
    call_log_entries.append(
        _call_log_entry(CallName.actor_profile, result0, partial_scenario_id)
    )

    # --- Call 1: Narrative ---
    try:
        narrative, result1 = _call_narrative(
            seed,
            profile,
            client,
            use_case,
            actor_profile=actor_profile,
            preferred_entry_point=preferred_entry_point,
            excluded_entry_points=excluded_entry_points,
            excluded_patterns=excluded_patterns,
            excluded_structural_patterns=excluded_structural_patterns,
            pinned_entry_point=pinned_entry_point,
            pinned_technique_ids=pinned_technique_ids,
            prior_titles=prior_titles,
            pinned_entry_point_id=pinned_entry_point_id,
            projection_context=projection_context,
        )
    except Exception as exc:
        call_log_entries.append(
            _call_log_entry_error(
                CallName.narrative, None, partial_scenario_id, str(exc)
            )
        )
        raise GenerationError(str(exc), call_log_entries, seed.seed_id) from exc

    call_metas.append(_call_metadata(CallName.narrative, result1))
    results[CallName.narrative] = result1
    call_log_entries.append(
        _call_log_entry(CallName.narrative, result1, partial_scenario_id)
    )

    # --- Post-Call-1: unified title + access-realization validation (cmps.6) ---
    # Every accepted Call 1 result must pass BOTH title uniqueness and
    # access-realization constraints.  Title retries and realization
    # retries share one bounded retry path so no later replacement
    # can bypass access validation.
    _call1_retry = 0
    _augmented_titles = list(prior_titles) if prior_titles else []
    while _call1_retry < _ACTOR_ACCESS_MAX_RETRIES:
        _needs_retry = False
        _retry_feedback_parts: list[str] = []

        # Check access realization.
        _realization_violations = _validate_realization(narrative, actor_profile)
        if _realization_violations:
            _needs_retry = True
            _realization_feedback = "\n".join(
                f"- {v.message}" for v in _realization_violations
            )
            _retry_feedback_parts.append(_realization_feedback)
            logger.warning(
                "Narrative access realization violations in %s (retry %d/%d): %s",
                partial_scenario_id,
                _call1_retry + 1,
                _ACTOR_ACCESS_MAX_RETRIES,
                _realization_feedback,
            )

        # Check title uniqueness.
        _title_duplicate = prior_titles is not None and narrative.title in prior_titles
        if _title_duplicate:
            _needs_retry = True
            if f"DUPLICATE — DO NOT REUSE: {narrative.title}" not in _augmented_titles:
                _augmented_titles = list(prior_titles) + [
                    f"DUPLICATE — DO NOT REUSE: {narrative.title}"
                ]
            _retry_feedback_parts.append(
                f"Title '{narrative.title}' is an exact duplicate of a "
                f"previously generated title — choose a different title."
            )
            logger.warning(
                "Exact duplicate title for %s: '%s' — retrying Call 1",
                partial_scenario_id,
                narrative.title,
            )

        if not _needs_retry:
            break

        _call1_retry += 1
        _combined_feedback = "\n".join(_retry_feedback_parts)
        try:
            narrative, result1 = _call_narrative(
                seed,
                profile,
                client,
                use_case,
                actor_profile=actor_profile,
                preferred_entry_point=preferred_entry_point,
                excluded_entry_points=excluded_entry_points,
                excluded_patterns=excluded_patterns,
                excluded_structural_patterns=excluded_structural_patterns,
                pinned_entry_point=pinned_entry_point,
                pinned_technique_ids=pinned_technique_ids,
                prior_titles=_augmented_titles if _augmented_titles else prior_titles,
                pinned_entry_point_id=pinned_entry_point_id,
                realization_feedback=(
                    _realization_feedback if _realization_violations else None
                ),
                projection_context=projection_context,
            )
            if pinned_entry_point and narrative.entry_point != pinned_entry_point:
                # On candidate-v2 paths (422o.4), entry-point overwrite is
                # semantic repair and is prohibited.  The mismatch becomes
                # a typed violation for cmps.5 to route.
                logger.warning(
                    "Narrative entry point '%s' does not match pinned '%s' "
                    "for %s — not overwriting on candidate-v2 path (422o.4).",
                    narrative.entry_point,
                    pinned_entry_point,
                    partial_scenario_id,
                )
        except Exception as exc:  # noqa: BLE001 - retry must catch all
            logger.warning(
                "Call 1 retry %d/%d failed for %s: %s",
                _call1_retry,
                _ACTOR_ACCESS_MAX_RETRIES,
                partial_scenario_id,
                exc,
            )
            break

    # Re-check after loop exits (either all passed or retries exhausted).
    _realization_violations = _validate_realization(narrative, actor_profile)
    if _realization_violations:
        logger.warning(
            "Narrative access realization violations persist after %d retries "
            "for %s — proceeding to semantic validation for quarantine: %s",
            _call1_retry,
            partial_scenario_id,
            "; ".join(v.message for v in _realization_violations),
        )

    # --- Post-Call-1 heuristic checks (warn-only, gmtc) ---
    try:
        _narrative_text = " ".join(
            [narrative.title, narrative.summary]
            + [f"{s.action} {s.effect}" for s in narrative.steps]
        )

        # Part C: Goal-narrative alignment
        _goal_id = actor_profile.goal_category if actor_profile else None
        if isinstance(_goal_id, str):
            _goal_warn = check_goal_narrative_alignment(_goal_id, _narrative_text)
            if _goal_warn:
                logger.warning("Scenario %s: %s", partial_scenario_id, _goal_warn)

        # Part D: Seed mechanism fidelity
        _mechanism_warn = check_seed_mechanism_fidelity(
            seed.attack_pattern_name, _narrative_text
        )
        if _mechanism_warn:
            logger.warning("Scenario %s: %s", partial_scenario_id, _mechanism_warn)
    except (TypeError, AttributeError):
        # Defensive: skip heuristic checks if narrative fields are not strings
        # (e.g. in tests using MagicMock objects).
        pass

    # cmps.7: actor capability is immutable after Call 0.  The legacy
    # novice multi-zone guard (a zone-count-driven capability relabel)
    # was removed here: zone count alone is never a complexity signal.
    # Attack complexity is assessed separately by the closed, versioned
    # rule table in asago_scenario_generator.pipeline.complexity, persisted on the
    # envelope as attack_complexity_assessment, and enforced through the
    # typed admission contract.  Wiring the candidate lower bound into
    # Call 0 and the final mismatch into bounded retry/quarantine is
    # deferred to cmps.5 (lifecycle ownership).

    # --- Post-Call-1: pin narrative entry_point by construction ---
    # On candidate-v2 paths (422o.4), entry-point overwrite is semantic
    # repair and is prohibited.  The mismatch becomes a typed violation
    # for cmps.5 to route.
    if pinned_entry_point and narrative.entry_point != pinned_entry_point:
        logger.warning(
            "Narrative entry point '%s' does not match pinned '%s' "
            "for %s — not overwriting on candidate-v2 path (422o.4). "
            "Mismatch will be reported as a typed violation.",
            narrative.entry_point,
            pinned_entry_point,
            partial_scenario_id,
        )

    # --- Call 2: Attack Tree (with consistency enforcement retries) ---
    # Compute parsimony budget using the same formula as _call_attack_tree.
    _tech_ids_for_budget = (
        pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids
    )
    _technique_count = len(_tech_ids_for_budget) if _tech_ids_for_budget else 0
    parsimony_budget = compute_leaf_budget(_technique_count)

    try:
        attack_tree, result2 = _call_attack_tree(
            seed,
            narrative,
            client,
            use_case,
            profile=profile,
            actor_profile=actor_profile,
            pinned_technique_ids=pinned_technique_ids,
            pinned_technique_names=pinned_technique_names,
            pinned_entry_point_id=pinned_entry_point_id,
            projection_context=projection_context,
        )
    except Exception as exc:
        call_log_entries.append(
            _call_log_entry_error(
                CallName.attack_tree, None, partial_scenario_id, str(exc)
            )
        )
        raise GenerationError(str(exc), call_log_entries, seed.seed_id) from exc

    # --- Post-generation: strip before consistency so effects trigger retries ---
    skeleton_ids = set(pinned_technique_ids) if pinned_technique_ids else set()

    def _strip_and_check(atree: AttackTree) -> list[str]:
        """Run consistency checks without semantic repair.

        On candidate-v2 paths (422o.4), technique stripping and zone
        compatibility stripping are semantic repair and are prohibited.
        Invalid technique IDs become typed violations for cmps.5 to route.
        Only consistency checks are run — no mutation of the tree.
        """
        return _check_consistency(
            atree,
            narrative,
            parsimony_budget,
            threat_id=seed.threat_id,
            tool_names=(
                [t.name for t in profile.tool_inventory]
                if profile and profile.tool_inventory
                else None
            ),
            pinned_technique_ids=list(skeleton_ids) if skeleton_ids else None,
        )

    consistency_violations = _strip_and_check(attack_tree)
    consistency_retry = 0
    while consistency_violations and consistency_retry < _CONSISTENCY_MAX_RETRIES:
        consistency_retry += 1
        logger.warning(
            "Consistency violations in %s (retry %d/%d): %s",
            partial_scenario_id,
            consistency_retry,
            _CONSISTENCY_MAX_RETRIES,
            "; ".join(consistency_violations),
        )
        feedback = "- " + "\n- ".join(consistency_violations)
        try:
            attack_tree, result2 = _call_attack_tree(
                seed,
                narrative,
                client,
                use_case,
                profile=profile,
                actor_profile=actor_profile,
                pinned_technique_ids=pinned_technique_ids,
                pinned_technique_names=pinned_technique_names,
                consistency_feedback=feedback,
                pinned_entry_point_id=pinned_entry_point_id,
                projection_context=projection_context,
            )
        except Exception as exc:  # noqa: BLE001 - retry must catch all to log and break
            logger.warning(
                "Consistency retry %d/%d failed for %s: %s",
                consistency_retry,
                _CONSISTENCY_MAX_RETRIES,
                partial_scenario_id,
                exc,
            )
            break
        consistency_violations = _strip_and_check(attack_tree)

    if consistency_violations:
        logger.warning(
            "Consistency violations persist after %d retries for %s: %s",
            consistency_retry,
            partial_scenario_id,
            "; ".join(consistency_violations),
        )

    call_metas.append(_call_metadata(CallName.attack_tree, result2))
    results[CallName.attack_tree] = result2
    call_log_entries.append(
        _call_log_entry(CallName.attack_tree, result2, partial_scenario_id)
    )

    # --- Post-generation threat_id cross-ref validation ---
    _warn_dominant_threat_id_crossref_fn(
        attack_tree, seed.threat_id, partial_scenario_id
    )

    # --- Call 3: Behavior Spec ---
    try:
        behavior_spec, result3 = _call_behavior_spec(
            seed,
            narrative,
            attack_tree,
            profile,
            client,
            use_case,
            scenario_id,
            pinned_technique_ids=pinned_technique_ids,
            projection_context=projection_context,
        )
    except Exception as exc:
        call_log_entries.append(
            _call_log_entry_error(
                CallName.behavior_spec, None, partial_scenario_id, str(exc)
            )
        )
        raise GenerationError(str(exc), call_log_entries, seed.seed_id) from exc

    call_metas.append(_call_metadata(CallName.behavior_spec, result3))
    results[CallName.behavior_spec] = result3
    call_log_entries.append(
        _call_log_entry(CallName.behavior_spec, result3, partial_scenario_id)
    )

    envelope = _assemble_envelope_fn(
        seed=seed,
        profile=profile,
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=behavior_spec,
        call_metadata_list=call_metas,
        model_name=client.model,
        use_case=use_case,
        notes=_diversity_notes if _diversity_notes else [],
        actor_profile=actor_profile,
        pinned_technique_ids=pinned_technique_ids,
        pinned_entry_point=pinned_entry_point,
        pinned_entry_point_id=pinned_entry_point_id,
        run_id=run_id,
        candidate_id=candidate_id,
        attempt=attempt,
        projected_candidate=projected_candidate,
        capability_snapshot=capability_snapshot,
    )

    # Run projection traceability validation on the production path (422o.4).
    # The result is transient — not persisted on the envelope.  Violations
    # are raised as a typed ProjectionTraceabilityError for cmps.5 to
    # consume (retry/quarantine routing).  Generation does not retry here;
    # cmps.5 owns the retry/quarantine state machine.  Fail-closed: an
    # invalid scenario is never returned or persisted.
    from asago_scenario_generator.pipeline.projection_validation import (
        validate_projection_traceability,
    )

    traceability_result = validate_projection_traceability(envelope)
    if not traceability_result.valid:
        raise ProjectionTraceabilityError(
            result=traceability_result,
            scenario_id=envelope.scenario_id,
            call_log_entries=call_log_entries,
            seed_id=seed.seed_id,
        )

    # Run source-influence provenance qualification (Wave 2 slice 5).
    # Fail-closed: assembly always attaches the provenance block, and its
    # qualification must pass or the scenario is never returned.
    from asago_scenario_generator.pipeline.source_influence import (
        validate_source_influence_provenance,
    )

    provenance_result = validate_source_influence_provenance(envelope)
    if not provenance_result.valid:
        raise SourceInfluenceProvenanceError(
            result=provenance_result,
            scenario_id=envelope.scenario_id,
            call_log_entries=call_log_entries,
            seed_id=seed.seed_id,
        )

    # Update call log entries with the final scenario_id (replacing partial).
    for entry in call_log_entries:
        entry["scenario_id"] = envelope.scenario_id

    return envelope, call_log_entries


def generate_scenario(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    pinned_entry_point_id: str,
    *,
    preferred_entry_point: str | None = None,
    excluded_entry_points: list[str] | None = None,
    excluded_patterns: list[str] | None = None,
    excluded_structural_patterns: list[str] | None = None,
    preferred_actor_type: str | None = None,
    excluded_actor_types: list[str] | None = None,
    preferred_capability_level: str | None = None,
    attack_goal: dict[str, Any] | None = None,
    pinned_entry_point: str | None = None,
    pinned_technique_ids: list[str] | None = None,
    pinned_technique_names: list[str] | None = None,
    prior_titles: list[str] | None = None,
    run_id: str = "",
    candidate_id: str = "",
    attempt: int = 1,
    projected_candidate: ProjectedCandidate,
    capability_snapshot: CapabilityFactSnapshot,
) -> tuple[ScenarioEnvelope, list[dict]]:
    """Compatibility adapter preserving the pre-cmps.5 production behavior.

    The typed single-attempt lifecycle API lives in ``generate.stages``.
    Runner cutover is deliberately deferred to later cmps.5 phases, so this
    adapter retains all current internal retries, call counts, patch targets,
    return shape, and fail-closed traceability behavior.
    """
    return _generate_scenario_compatibility(
        seed,
        profile,
        client,
        use_case,
        pinned_entry_point_id,
        preferred_entry_point=preferred_entry_point,
        excluded_entry_points=excluded_entry_points,
        excluded_patterns=excluded_patterns,
        excluded_structural_patterns=excluded_structural_patterns,
        preferred_actor_type=preferred_actor_type,
        excluded_actor_types=excluded_actor_types,
        preferred_capability_level=preferred_capability_level,
        attack_goal=attack_goal,
        pinned_entry_point=pinned_entry_point,
        pinned_technique_ids=pinned_technique_ids,
        pinned_technique_names=pinned_technique_names,
        prior_titles=prior_titles,
        run_id=run_id,
        candidate_id=candidate_id,
        attempt=attempt,
        projected_candidate=projected_candidate,
        capability_snapshot=capability_snapshot,
    )


def compute_artifact_hash(data: bytes) -> str:
    """Compute SHA-256 hash of exact artifact bytes."""
    return hashlib.sha256(data).hexdigest()


def _cleanup_created_files(created_files: list[Path]) -> None:
    """Remove files created by the current call.  If cleanup fails, raise
    a fatal integrity error rather than silently passing."""
    cleanup_errors: list[str] = []
    for path in created_files:
        try:
            path.unlink()
        except OSError as exc:
            cleanup_errors.append(f"{path}: {exc}")
    if cleanup_errors:
        raise ScenarioForgeIntegrityError(
            f"Failed to clean up files created by current write call: "
            f"{'; '.join(cleanup_errors)}"
        )


def write_scenario_outputs(
    envelope: ScenarioEnvelope,
    output_dir: Path,
) -> tuple[Path, Path | None]:
    """Write scenario envelope to disk as YAML and optional Gherkin file.

    Uses **exclusive creation** (``"x"`` mode).  Pre-serializes both
    outputs before writing either, and cleans up only files created by
    this call on ordinary failure so no partial pair is left behind.
    Pre-existing or orphan state is a fatal integrity error.

    Validates projection traceability and source-influence provenance
    before writing so callers cannot bypass generation validation.

    Returns:
        Tuple of (envelope_path, feature_path_or_none).

    Raises:
        ScenarioForgeIntegrityError: If either path already exists, or
            a stem mismatch / orphan feature is detected.
        ProjectionTraceabilityError: If projection traceability
            validation fails.
        SourceInfluenceProvenanceError: If the envelope's source-influence
            provenance block fails qualification.
    """
    # Validate projection traceability before writing (422o.4 fail-closed).
    from asago_scenario_generator.pipeline.projection_validation import (
        validate_projection_traceability,
    )

    traceability_result = validate_projection_traceability(envelope)
    if not traceability_result.valid:
        raise ProjectionTraceabilityError(
            result=traceability_result,
            scenario_id=envelope.scenario_id,
        )

    # Source-influence provenance qualification (Wave 2 slice 5, fail-closed):
    # generation publishes only envelopes whose provenance block qualifies;
    # a stale, tampered, or incomplete block is never written to disk.
    from asago_scenario_generator.pipeline.source_influence import (
        validate_source_influence_provenance,
    )

    provenance_result = validate_source_influence_provenance(envelope)
    if not provenance_result.valid:
        raise SourceInfluenceProvenanceError(
            result=provenance_result,
            scenario_id=envelope.scenario_id,
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    envelope_path = output_dir / f"{envelope.scenario_id}.yaml"
    feature_path: Path | None = None
    has_behavior_spec = envelope.behavior_spec is not None and isinstance(
        envelope.behavior_spec, BehaviorSpec
    )
    if has_behavior_spec:
        feature_path = output_dir / f"{envelope.scenario_id}.feature"

    # Preflight: pre-existing files are fatal integrity errors.
    if envelope_path.exists():
        raise ScenarioForgeIntegrityError(
            f"Scenario YAML already exists: {envelope_path}"
        )
    if feature_path is not None and feature_path.exists():
        raise ScenarioForgeIntegrityError(
            f"Scenario feature file already exists: {feature_path}"
        )

    # Check for orphan/stem mismatch.
    alt_feature = envelope_path.with_suffix(".feature")
    if not has_behavior_spec and alt_feature.exists():
        raise ScenarioForgeIntegrityError(
            f"Stem mismatch: orphan feature file exists for "
            f"'{envelope.scenario_id}' but envelope has no behavior_spec"
        )

    # Pre-serialize both outputs before writing either.
    data = envelope.model_dump(mode="json", exclude_none=True)
    yaml_text = yaml.dump(
        data, default_flow_style=False, sort_keys=False, allow_unicode=True
    )
    feature_text: str | None = None
    if has_behavior_spec:
        feature_text = envelope.behavior_spec.gherkin_text  # type: ignore[union-attr]

    # Track files created by this call for cleanup on failure.
    # A path is registered as current-call-owned immediately after the
    # exclusive open succeeds, before any write, so that cleanup covers
    # files even if the write itself fails.
    created_files: list[Path] = []
    try:
        try:
            fh = envelope_path.open("x", encoding="utf-8")
        except FileExistsError as exc:
            raise ScenarioForgeIntegrityError(
                f"Scenario YAML already exists (race): {envelope_path}"
            ) from exc
        created_files.append(envelope_path)
        with fh:
            fh.write(yaml_text)

        if feature_path is not None and feature_text is not None:
            try:
                fh = feature_path.open("x", encoding="utf-8")
            except FileExistsError as exc:
                raise ScenarioForgeIntegrityError(
                    f"Scenario feature already exists (race): {feature_path}"
                ) from exc
            created_files.append(feature_path)
            with fh:
                fh.write(feature_text)
    except ScenarioForgeIntegrityError:
        _cleanup_created_files(created_files)
        raise
    except Exception:
        _cleanup_created_files(created_files)
        raise

    return envelope_path, feature_path


def replace_scenario_outputs(
    envelope: ScenarioEnvelope,
    output_dir: Path,
    admitted_scenario_id: str = "",
) -> tuple[Path, Path | None]:
    """Guarded replacement of scenario YAML artifacts.

    Used only for the validation rewrite pass.  Verifies the complete
    existing pair before changing bytes, then atomically replaces YAML
    with temp + ``os.replace``.  Feature bytes are **not** rewritten —
    they are verified to match the existing file.  Never routes through
    the create API or silently overwrites arbitrary bytes.

    Args:
        envelope: Updated envelope with validation marks.
        output_dir: Directory containing the original artifacts.
        admitted_scenario_id: The originally admitted scenario ID.
            Must match ``envelope.scenario_id``.

    Raises:
        ScenarioForgeIntegrityError: If scenario ID mismatch, missing
            pair, stem mismatch, or feature byte mismatch.
    """
    import os
    import tempfile

    if not admitted_scenario_id:
        raise ValueError("admitted_scenario_id is required for guarded replace")
    if envelope.scenario_id != admitted_scenario_id:
        raise ScenarioForgeIntegrityError(
            f"Scenario ID mismatch in guarded replace: expected "
            f"'{admitted_scenario_id}', got '{envelope.scenario_id}'"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    envelope_path = output_dir / f"{envelope.scenario_id}.yaml"
    feature_path = output_dir / f"{envelope.scenario_id}.feature"

    # Verify complete existing pair before modifying anything.
    if not envelope_path.exists():
        raise ScenarioForgeIntegrityError(
            f"Cannot replace non-existent scenario YAML: {envelope_path}"
        )

    has_behavior_spec = envelope.behavior_spec is not None and isinstance(
        envelope.behavior_spec, BehaviorSpec
    )

    if has_behavior_spec:
        if not feature_path.exists():
            raise ScenarioForgeIntegrityError(
                f"Missing feature file for guarded replace: {feature_path}"
            )
        # Verify feature bytes are unchanged — we must not rewrite feature.
        existing_feature_bytes = feature_path.read_bytes()
        expected_feature_text = envelope.behavior_spec.gherkin_text  # type: ignore[union-attr]
        if existing_feature_bytes != expected_feature_text.encode("utf-8"):
            raise ScenarioForgeIntegrityError(
                f"Feature byte mismatch in guarded replace for "
                f"'{envelope.scenario_id}': existing bytes differ from "
                f"envelope behavior_spec"
            )
    elif feature_path.exists():
        raise ScenarioForgeIntegrityError(
            f"Stem mismatch: feature file exists for "
            f"'{envelope.scenario_id}' but envelope has no behavior_spec"
        )

    # Pre-serialize new YAML and atomically replace.
    data = envelope.model_dump(mode="json", exclude_none=True)
    yaml_text = yaml.dump(
        data, default_flow_style=False, sort_keys=False, allow_unicode=True
    )

    # Write to temp file in same directory, then atomic replace.
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=output_dir, suffix=".yaml.tmp", prefix=envelope.scenario_id
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(yaml_text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, envelope_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    actual_feature_path = feature_path if has_behavior_spec else None
    return envelope_path, actual_feature_path


def write_call_log(
    call_log_entries: list[dict],
    output_dir: Path,
) -> None:
    """Append call-log entries to ``calls.jsonl`` in *output_dir*.

    Each entry is written as a single JSON line.  The file is opened in
    append mode so multiple scenarios can safely be written incrementally.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    calls_path = output_dir / "calls.jsonl"
    with calls_path.open("a", encoding="utf-8") as fh:
        for entry in call_log_entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

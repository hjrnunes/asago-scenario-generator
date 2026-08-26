"""Execution-requirement derivation and candidate projection identity helpers."""

from __future__ import annotations

from typing import Any, Literal

from asago_scenario_generator.models.attack_pattern_chain import (
    CanonicalAttackChain,
    ResourceSlot,
)
from asago_scenario_generator.models.attack_pattern_contracts import (
    DirectInputControlRequirement,
    ExecutionRequirement,
    ObservationRequirement,
    SecurityOutcomeAssertionRequirement,
    StateChangingToolFixtureRequirement,
    UpstreamSourceInfluenceRequirement,
)
from asago_scenario_generator.models.attack_pattern_projection import (
    CanonicalResourceReference,
    EntryPointResourceReference,
    ProjectionSnapshot,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    ProjectionIssue,
    _selected_steps_for_projection,
)
from asago_scenario_generator.pipeline.projection_snapshot import (
    CapabilityFactSnapshot,
)


def _requirement_id(prefix: str, *components: str) -> str:
    """Generate an injective, stable requirement ID from components.

    Composite requirement IDs must be collision-free even when individual
    components contain dots (e.g. step ``a`` + slot ``b.c`` vs step ``a.b``
    + slot ``c``).  Dot concatenation is ambiguous; hashing is not
    guaranteed injective.  Instead, each component is encoded as its full
    UTF-8 hexadecimal representation, and the encoded components are joined
    with ``:`` — a character that never appears in hexadecimal output.
    This makes the mapping ``(prefix, *components) → ID`` injective: the
    component list can be recovered by splitting on ``:`` and hex-decoding
    each segment, so distinct inputs always produce distinct IDs.

    IDs are **unbounded in length**: hex encoding doubles each component's
    byte length, so long step IDs or slot IDs produce long requirement IDs.
    Downstream persistence must use unbounded text columns or establish a
    future explicit bound.  No bounded consumer exists in candidate-v2.
    """
    encoded = ":".join(c.encode("utf-8").hex() for c in components)
    return f"{prefix}.{encoded}"


def _derive_execution_requirements_core(
    pattern_id: str,
    chain: CanonicalAttackChain,
    projection: ProjectionSnapshot,
    ingress_controllability: Literal["direct", "indirect"],
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Derive execution requirements from explicit canonical linkage only.

    Pure function over the embedded source chain, projection bindings, and
    the resolved ingress controllability.  No external snapshot is needed.
    No inference from action kind, name, prose, cardinality, taxonomy mapping,
    or catalog partition.  Every requirement is traced to an explicit
    ``resource_links`` or ``observable_outcome_links`` entry on a selected
    step.  Security-outcome assertions are derived only from postconditions
    that have an explicit observable outcome link, not from the
    ``security_relevant`` flag alone.
    """
    slots_by_id = {slot.slot_id: slot for slot in chain.resource_slots}
    selected_steps = _selected_steps_for_projection(chain, projection.selected_step_ids)
    requirements: list[ExecutionRequirement] = []

    for step in selected_steps:
        for link in step.resource_links:
            slot = slots_by_id[link.slot_id]
            derived, issue = _link_role_requirement(
                pattern_id, step, link, slot, ingress_controllability
            )
            if issue is not None:
                return None, issue
            requirements.extend(derived)

        # Build a set of postcondition IDs that have explicit outcome links.
        linked_pc_ids = _linked_postcondition_ids(step)
        requirements.extend(_observation_requirements(step))

        # Security-outcome assertions are derived ONLY from security-relevant
        # postconditions that have an explicit observable outcome link.
        # A security-relevant postcondition without an outcome link does not
        # produce a requirement: the security outcome cannot be asserted
        # without an explicit observation binding.
        requirements.extend(_security_outcome_requirements(step, linked_pc_ids))

    sorted_reqs = tuple(sorted(requirements, key=lambda item: item.requirement_id))
    return _require_unique_requirement_ids_or_issue(sorted_reqs, pattern_id)


def _source_identity_kind_for_link(link: Any, slot: ResourceSlot) -> str:
    """Resolve the declared source identity kind, falling back to the slot."""
    if link.source_identity_kind is not None:
        return link.source_identity_kind
    if slot.kind == "entry_point":
        return "entry_point"
    return "integration"


def _link_role_requirement(
    pattern_id: str,
    step: Any,
    link: Any,
    slot: ResourceSlot,
    ingress_controllability: Literal["direct", "indirect"],
) -> tuple[list[ExecutionRequirement], ProjectionIssue | None]:
    """Derive the requirement for one resource link by its role."""
    if link.role == "ingress":
        if ingress_controllability != "direct":
            return None, ProjectionIssue(
                code="unsupported_requirement_derivation",
                pattern_id=pattern_id,
                detail=(
                    "indirect ingress requires explicit upstream-source "
                    "and trust-boundary linkage"
                ),
            )
        return [
            DirectInputControlRequirement(
                schema_version="1",
                requirement_id=_requirement_id("req.direct-input", link.slot_id),
                kind="direct_input_control",
                entry_point_slot_id=link.slot_id,
            )
        ], None
    if link.role == "tool_fixture":
        return [
            StateChangingToolFixtureRequirement(
                schema_version="1",
                requirement_id=_requirement_id(
                    "req.tool-fixture", step.step_id, link.slot_id
                ),
                kind="state_changing_tool_fixture",
                tool_slot_id=link.slot_id,
            )
        ], None
    if link.role == "source_influence":
        return [
            UpstreamSourceInfluenceRequirement(
                schema_version="1",
                requirement_id=_requirement_id(
                    "req.source-influence",
                    step.step_id,
                    link.slot_id,
                    str(link.trust_boundary_slot_id),
                    str(link.target_ingress_slot_id),
                ),
                kind="upstream_source_influence",
                source_slot_id=link.slot_id,
                source_identity_kind=_source_identity_kind_for_link(link, slot),
                trust_boundary_slot_id=link.trust_boundary_slot_id,
                target_ingress_slot_id=link.target_ingress_slot_id,
            )
        ], None
    return [], None


def _linked_postcondition_ids(step: Any) -> set[str]:
    """Collect postcondition IDs with explicit observable outcome links."""
    return {ol.postcondition_id for ol in step.observable_outcome_links}


def _observation_requirements(step: Any) -> list[ExecutionRequirement]:
    """Derive observation requirements from the step's outcome links."""
    return [
        ObservationRequirement(
            schema_version="1",
            requirement_id=_requirement_id(
                "req.observation",
                step.step_id,
                outcome_link.postcondition_id,
            ),
            kind="observation",
            observation=outcome_link.observation,
            binding_slot_id=outcome_link.binding_slot_id,
        )
        for outcome_link in step.observable_outcome_links
    ]


def _security_outcome_requirements(
    step: Any, linked_pc_ids: set[str]
) -> list[ExecutionRequirement]:
    """Derive security-outcome assertions from linked postconditions only."""
    return [
        SecurityOutcomeAssertionRequirement(
            schema_version="1",
            requirement_id=_requirement_id(
                "req.security-outcome",
                step.step_id,
                postcondition.postcondition_id,
            ),
            kind="security_outcome_assertion",
            source_step_id=step.step_id,
            postcondition_id=postcondition.postcondition_id,
        )
        for postcondition in step.observable_postconditions
        if postcondition.security_relevant
        and postcondition.postcondition_id in linked_pc_ids
    ]


def _require_unique_requirement_ids_or_issue(
    sorted_reqs: tuple[ExecutionRequirement, ...],
    pattern_id: str,
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Fail closed when derived requirement IDs collide."""
    req_ids = [item.requirement_id for item in sorted_reqs]
    if len(req_ids) != len(set(req_ids)):
        duplicates = sorted({rid for rid in req_ids if req_ids.count(rid) > 1})
        return None, ProjectionIssue(
            code="unsupported_requirement_derivation",
            pattern_id=pattern_id,
            detail=(
                f"derived requirement IDs collide: {duplicates}; "
                "requirement IDs must be unique"
            ),
        )
    return sorted_reqs, None


def _fail_closed_if_no_requirements(
    pattern_id: str,
    requirements: tuple[ExecutionRequirement, ...] | None,
    issue: ProjectionIssue | None,
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Absent explicit linkage must fail closed, not produce an empty candidate."""
    if issue is not None:
        return requirements, issue
    if requirements is None or len(requirements) == 0:
        return None, ProjectionIssue(
            code="unsupported_requirement_derivation",
            pattern_id=pattern_id,
            detail=(
                "no explicit resource links or observable outcome links on any "
                "selected step; absent linkage fails closed"
            ),
        )
    return requirements, issue


def _derive_execution_requirements(
    pattern_id: str,
    chain: CanonicalAttackChain,
    projection: ProjectionSnapshot,
    snapshot: CapabilityFactSnapshot,
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Derive execution requirements, resolving ingress controllability from snapshot.

    Backward-compatible wrapper around :func:`_derive_execution_requirements_core`
    that resolves the ingress controllability from the capability fact snapshot.
    """
    controllability = _resolve_ingress_controllability(chain, projection, snapshot)
    # No ingress link found — resolve to indirect (will fail closed).
    return _derive_execution_requirements_core(
        pattern_id, chain, projection, controllability
    )


def _selected_ingress_links(
    chain: CanonicalAttackChain, projection: ProjectionSnapshot
) -> list[Any]:
    """Collect the selected steps' ingress resource links in chain order."""
    selected = set(projection.selected_step_ids)
    return [
        link
        for step in chain.steps
        if step.step_id in selected
        for link in step.resource_links
        if link.role == "ingress"
    ]


def _ingress_controllability_for_link(
    bindings: dict[str, CanonicalResourceReference],
    link: Any,
    snapshot: CapabilityFactSnapshot,
) -> str:
    """Resolve the effective ingress controllability for one ingress link."""
    ingress_ref = bindings[link.slot_id]
    if not isinstance(ingress_ref, EntryPointResourceReference):
        raise TypeError(  # pragma: no cover - contract guard
            "ingress binding is not an entry point"
        )
    ingress = snapshot.profile.resolve_entry_point(ingress_ref.entry_point_id)
    if ingress is None:
        raise ValueError("canonical ingress is absent from snapshot")
    return ingress.effective_controllability


def _resolve_ingress_controllability(
    chain: CanonicalAttackChain,
    projection: ProjectionSnapshot,
    snapshot: CapabilityFactSnapshot,
) -> Literal["direct", "indirect"]:
    """Resolve ingress controllability from the first selected ingress link."""
    bindings = {item.slot_id: item.resource_ref for item in projection.bindings}
    for link in _selected_ingress_links(chain, projection):
        return _ingress_controllability_for_link(bindings, link, snapshot)
    return "indirect"

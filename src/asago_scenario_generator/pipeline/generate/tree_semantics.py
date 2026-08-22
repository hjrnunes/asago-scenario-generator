"""Semantic topology drafts compiled against canonical attack-tree leaves.

The provider controls the grouping and explanatory prose.  It can only refer
to request-local leaf handles; typed actions, zones, techniques, projection
identity, and realizations are supplied by :class:`CanonicalLeafSpec`.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
    GateType,
    ImpactAction,
    InitialIngressAction,
    IntegrationInteractionAction,
    LeafAction,
    ToolInvocationAction,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.models.scenario import NarrativeLayer
from asago_scenario_generator.pipeline.compatibility import (
    EXECUTOR_ROLE_TO_LEAF_COMPAT,
    STEP_TO_LEAF_ACTION_COMPAT,
)


class CanonicalLeafSpec(BaseModel):
    """One compiler-owned attack-tree leaf exposed through a short handle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    leaf_handle: str = Field(pattern=r"^l\d+$")
    label: str = Field(min_length=1, max_length=120)
    description: str | None = None
    action: LeafAction
    zone: str | None
    technique_id: str | None = None
    projected_step_ids: tuple[str, ...] = Field(min_length=1)
    realizations: tuple[ProjectedStepRealization, ...] = Field(min_length=1)
    initial_ingress: bool = False


class AttackTreeDraftNode(BaseModel):
    """Provider-authored topology node containing no canonical identity."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["group", "leaf"]
    label: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    leaf_handle: str | None = Field(default=None, pattern=r"^l\d+$")
    children: tuple["AttackTreeDraftNode", ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def _shape_matches_kind(self) -> "AttackTreeDraftNode":
        if self.kind == "leaf":
            if self.leaf_handle is None:
                raise ValueError("leaf draft nodes require leaf_handle")
            if self.children:
                raise ValueError("leaf draft nodes cannot have children")
        else:
            if self.leaf_handle is not None:
                raise ValueError("group draft nodes cannot carry leaf_handle")
            if len(self.children) < 2:
                raise ValueError("group draft nodes require at least two children")
            if not self.label:
                raise ValueError("group draft nodes require a provider-authored label")
        return self


class AttackTreeDraftV2(BaseModel):
    """A bounded, AND-only topology over request-local leaf handles."""

    model_config = ConfigDict(extra="forbid")

    root: AttackTreeDraftNode


class AttackTreeDraftGroupV3(BaseModel):
    """One provider-authored flat grouping of canonical leaf handles."""

    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    leaf_handles: tuple[str, ...] = Field(min_length=1, max_length=32)


class AttackTreeDraftV3(BaseModel):
    """Bounded non-recursive provider topology compiled to canonical nodes."""

    model_config = ConfigDict(extra="forbid")

    root_label: str = Field(min_length=1, max_length=120)
    root_description: str | None = Field(default=None, max_length=500)
    groups: tuple[AttackTreeDraftGroupV3, ...] = Field(min_length=1, max_length=16)


def build_attack_tree_draft_response_model(
    leaf_handles: tuple[str, ...] | list[str],
) -> type[AttackTreeDraftV3]:
    """Return a request-local schema whose leaf handles are a finite enum."""

    allowed = tuple(leaf_handles)
    if not allowed:
        raise ValueError("attack-tree response schema requires leaf handles")

    def model_json_schema(
        cls: type[BaseModel], *args: Any, **kwargs: Any
    ) -> dict[str, Any]:
        del cls
        schema = AttackTreeDraftV3.model_json_schema(*args, **kwargs)

        def constrain(value: Any) -> None:
            if isinstance(value, dict):
                properties = value.get("properties")
                if isinstance(properties, dict) and "leaf_handles" in properties:
                    leaf_handles_schema = properties["leaf_handles"]
                    if isinstance(leaf_handles_schema, dict):
                        leaf_handles_schema["items"] = {
                            "enum": list(allowed),
                            "type": "string",
                        }
                for child in value.values():
                    constrain(child)
            elif isinstance(value, list):
                for child in value:
                    constrain(child)

        constrain(schema)
        return schema

    return type(
        f"AttackTreeDraftV3For{len(allowed)}Leaves",
        (AttackTreeDraftV3,),
        {"model_json_schema": classmethod(model_json_schema)},
    )


def _validate_flat_attack_tree_draft(
    draft: AttackTreeDraftV3,
    leaf_specs: tuple[CanonicalLeafSpec, ...] | list[CanonicalLeafSpec],
) -> DraftValidation:
    expected = tuple(spec.leaf_handle for spec in leaf_specs)
    actual = tuple(handle for group in draft.groups for handle in group.leaf_handles)
    counts = Counter(actual)
    violations: list[SemanticDraftViolation] = []
    unknown = tuple(sorted(set(actual) - set(expected)))
    duplicates = tuple(sorted(handle for handle, count in counts.items() if count > 1))
    missing = tuple(handle for handle in expected if handle not in counts)
    if unknown:
        violations.append(
            SemanticDraftViolation(
                code="unknown_handle",
                handles=unknown,
                message=f"unknown leaf handles: {list(unknown)}",
            )
        )
    if duplicates:
        violations.append(
            SemanticDraftViolation(
                code="duplicate_handle",
                handles=duplicates,
                message=f"duplicate leaf handles: {list(duplicates)}",
            )
        )
    if missing:
        violations.append(
            SemanticDraftViolation(
                code="missing_handle",
                handles=missing,
                message=f"missing leaf handles: {list(missing)}",
            )
        )
    if not violations and actual != expected:
        violations.append(
            SemanticDraftViolation(
                code="illegal_order",
                handles=actual,
                message="leaf handles do not preserve canonical projected-step order",
            )
        )
    return DraftValidation(accepted=not violations, violations=tuple(violations))


def compile_flat_attack_tree_draft(
    *,
    seed_id: str,
    goal: str,
    draft: AttackTreeDraftV3,
    leaf_specs: tuple[CanonicalLeafSpec, ...] | list[CanonicalLeafSpec],
    threat_id: str | None = None,
) -> AttackTree:
    """Compile a bounded flat provider grouping into canonical tree nodes."""
    validation = _validate_flat_attack_tree_draft(draft, leaf_specs)
    if not validation.accepted:
        raise InvalidSemanticDraft(validation)
    by_handle = {spec.leaf_handle: spec for spec in leaf_specs}

    def leaf_node(handle: str, node_id: str) -> AttackTreeNode:
        spec = by_handle[handle]
        return AttackTreeNode(
            id=node_id,
            label=spec.label,
            description=spec.description,
            gate=GateType.LEAF,
            zone=spec.zone,
            action=spec.action.model_copy(deep=True),
            threat_id=threat_id,
            technique_id=spec.technique_id,
            projected_step_ids=spec.projected_step_ids,
            realizations=spec.realizations,
        )

    try:
        root_children: list[AttackTreeNode] = []
        for group_index, group in enumerate(draft.groups, 1):
            root_child_id = f"n1.{group_index}"
            if len(group.leaf_handles) == 1:
                root_children.append(leaf_node(group.leaf_handles[0], root_child_id))
                continue
            root_children.append(
                AttackTreeNode(
                    id=root_child_id,
                    label=group.label,
                    description=group.description,
                    gate=GateType.AND,
                    threat_id=threat_id,
                    children=[
                        leaf_node(handle, f"{root_child_id}.{leaf_index}")
                        for leaf_index, handle in enumerate(group.leaf_handles, 1)
                    ],
                )
            )
        if len(root_children) == 1:
            root = root_children[0].model_copy(
                update={
                    "id": "n1",
                    "label": (
                        draft.root_label
                        if root_children[0].gate is GateType.AND
                        else root_children[0].label
                    ),
                    "description": (
                        draft.root_description
                        if root_children[0].gate is GateType.AND
                        else root_children[0].description
                    ),
                },
                deep=True,
            )
        else:
            root = AttackTreeNode(
                id="n1",
                label=draft.root_label,
                description=draft.root_description,
                gate=GateType.AND,
                threat_id=threat_id,
                children=root_children,
            )
        return AttackTree(
            id=f"tree-{seed_id}",
            seed_id=seed_id,
            goal=goal,
            root=root,
        )
    except Exception as exc:
        raise CanonicalCompilationError(
            f"accepted flat attack-tree draft failed canonical compilation: {exc}"
        ) from exc


class SemanticDraftViolation(BaseModel):
    """Machine-readable feedback for one semantic draft correction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    handles: tuple[str, ...] = ()
    message: str


class DraftValidation(BaseModel):
    """Validation result returned at the draft/compiler seam."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    accepted: bool
    violations: tuple[SemanticDraftViolation, ...] = ()


class InvalidSemanticDraft(ValueError):
    """Raised when compilation is attempted with an incomplete draft."""

    stage_failure_code = "semantic_draft_invalid"
    stage_failure_retryable = True

    def __init__(self, validation: DraftValidation) -> None:
        self.validation = validation
        super().__init__("; ".join(v.message for v in validation.violations))


class ProjectionInfeasible(ValueError):
    """Canonical leaf semantics cannot be derived without invention."""

    stage_failure_code = "projection_infeasible"
    stage_failure_retryable = False


class CanonicalCompilationError(RuntimeError):
    """An accepted draft could not be compiled into the domain model."""

    stage_failure_code = "canonical_compilation_failed"
    stage_failure_retryable = False


def _step_zone(narrative: NarrativeLayer, step_id: str) -> str | None:
    matches = [
        step.zone for step in narrative.steps if step_id in step.projected_step_ids
    ]
    if len(matches) != 1:
        raise ProjectionInfeasible(
            f"projected step '{step_id}' must map to exactly one narrative step; "
            f"found {len(matches)}"
        )
    return None if matches[0] == "outside" else matches[0]


def _resource_refs(step: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        ref
        for link in step.get("resource_links", [])
        if isinstance(link, dict)
        and isinstance((ref := link.get("resource_ref")), dict)
    ]


def _resource_id(refs: list[dict[str, Any]], kind: str, key: str) -> str | None:
    values = [str(ref[key]) for ref in refs if ref.get("kind") == kind and ref.get(key)]
    if len(set(values)) > 1:
        raise ProjectionInfeasible(
            f"projected step has more than one {kind} binding: {sorted(set(values))}"
        )
    return values[0] if values else None


def _compatible_action_kinds(step: dict[str, Any]) -> set[str]:
    return STEP_TO_LEAF_ACTION_COMPAT.get(str(step.get("action_kind", "")), set()) & (
        EXECUTOR_ROLE_TO_LEAF_COMPAT.get(str(step.get("executor_role", "")), set())
    )


def _derive_action(
    step: dict[str, Any],
    projection_context: dict[str, Any],
    zone: str | None,
) -> LeafAction:
    compatible = _compatible_action_kinds(step)
    refs = _resource_refs(step)
    boundary = str(step.get("boundary_position", ""))
    action_kind = str(step.get("action_kind", ""))
    entry_point_id = _resource_id(refs, "entry_point", "entry_point_id")
    tool_id = _resource_id(refs, "tool", "tool_id")
    integration_id = _resource_id(refs, "integration", "integration_id")
    canonical_ingress = projection_context.get("canonical_ingress", {})

    # Indirect ingress is commonly performed by the system fetching or
    # ingesting attacker-influenced content. The boundary crossing is the
    # canonical ingress event even when the same step binds an integration.
    if boundary == "crossing" and "initial_ingress" in compatible:
        if not entry_point_id and isinstance(canonical_ingress, dict):
            entry_point_id = canonical_ingress.get("entry_point_id")
        if entry_point_id:
            return InitialIngressAction(entry_point_id=str(entry_point_id))

    if boundary == "outside" and "external_precondition" in compatible:
        return ExternalPreconditionAction()
    if action_kind == "impact" and "impact" in compatible:
        descriptions = [
            str(pc.get("description"))
            for pc in step.get("observable_postconditions", [])
            if isinstance(pc, dict) and pc.get("description")
        ]
        target = descriptions[0] if descriptions else "Projected security impact"
        return ImpactAction(
            boundary="external" if boundary == "outside" else "internal",
            target=target[:200],
        )
    if tool_id is not None and "tool_invocation" in compatible:
        return ToolInvocationAction(tool_id=tool_id, integration_id=integration_id)
    if integration_id is not None and "integration_interaction" in compatible:
        return IntegrationInteractionAction(integration_id=integration_id)
    if "initial_ingress" in compatible:
        if not entry_point_id and isinstance(canonical_ingress, dict):
            entry_point_id = canonical_ingress.get("entry_point_id")
        if entry_point_id:
            return InitialIngressAction(entry_point_id=str(entry_point_id))
    if "ai_system_action" in compatible:
        return AiSystemAction()
    raise ProjectionInfeasible(
        f"no canonical tree action can be derived for step '{step.get('step_id')}' "
        f"from compatible kinds {sorted(compatible)} and its resource bindings"
    )


def _canonical_label(step: dict[str, Any], action: LeafAction) -> str:
    postconditions = [
        str(pc.get("description"))
        for pc in step.get("observable_postconditions", [])
        if isinstance(pc, dict) and pc.get("description")
    ]
    if postconditions:
        return postconditions[0][:120]
    return f"{action.kind.replace('_', ' ')} projected step"[:120]


def _coalesce_canonical_leaf_specs(
    specs: list[CanonicalLeafSpec],
) -> list[CanonicalLeafSpec]:
    """Merge adjacent leaves with identical canonical tree semantics.

    Projected chains describe execution at finer granularity than the attack
    tree. Consecutive steps may share one typed action, zone, and technique;
    representing each as a separate leaf can violate the tree parsimony budget
    without adding a distinct attack-tree decision. All projected identities
    and realizations remain attached to the merged leaf.
    """
    merged: list[CanonicalLeafSpec] = []
    for spec in specs:
        previous = merged[-1] if merged else None
        if (
            previous is not None
            and previous.action == spec.action
            and previous.zone == spec.zone
            and previous.technique_id == spec.technique_id
            and previous.initial_ingress == spec.initial_ingress
        ):
            merged[-1] = previous.model_copy(
                update={
                    "label": f"{previous.label}; then {spec.label}"[:120],
                    "projected_step_ids": (
                        *previous.projected_step_ids,
                        *spec.projected_step_ids,
                    ),
                    "realizations": (*previous.realizations, *spec.realizations),
                }
            )
        else:
            merged.append(spec)
    return [
        spec.model_copy(update={"leaf_handle": f"l{index}"})
        for index, spec in enumerate(merged)
    ]


def derive_canonical_leaf_specs(
    projection_context: dict[str, Any],
    narrative: NarrativeLayer,
    profile: CapabilityProfile,
) -> tuple[CanonicalLeafSpec, ...]:
    """Derive one immutable leaf specification per selected projected step.

    Failure is a projection error and happens before a provider is invoked.
    The returned order is the canonical selected-step order.
    """

    step_by_id = {
        str(step["step_id"]): step
        for step in projection_context.get("selected_steps", [])
        if isinstance(step, dict) and step.get("step_id")
    }
    selected_ids = tuple(
        str(item) for item in projection_context.get("selected_step_ids", [])
    )
    if not selected_ids:
        raise ProjectionInfeasible("projection contains no selected steps")

    specs: list[CanonicalLeafSpec] = []
    for index, step_id in enumerate(selected_ids):
        step = step_by_id.get(step_id)
        if step is None:
            raise ProjectionInfeasible(f"selected projected step '{step_id}' is absent")
        zone = _step_zone(narrative, step_id)
        action = _derive_action(step, projection_context, zone)
        if action.kind == "initial_ingress":
            entry_point = profile.resolve_entry_point(action.entry_point_id)
            if entry_point is None or entry_point.effective_ingress_zone is None:
                raise ProjectionInfeasible(
                    f"initial ingress '{action.entry_point_id}' has no canonical zone"
                )
            zone = entry_point.effective_ingress_zone
        if zone is not None and zone not in profile.zones_active:
            raise ProjectionInfeasible(
                f"projected step '{step_id}' uses inactive narrative zone '{zone}'"
            )
        realization_data = step.get("realization")
        if not isinstance(realization_data, dict):
            raise ProjectionInfeasible(
                f"projected step '{step_id}' has no canonical realization"
            )
        realization = ProjectedStepRealization.model_validate(realization_data)
        if realization.projected_step_id != step_id:
            raise ProjectionInfeasible(
                f"projected step '{step_id}' realization identifies "
                f"'{realization.projected_step_id}'"
            )
        raw_techniques = step.get("technique_ids", ())
        if isinstance(raw_techniques, str):
            raw_techniques = (raw_techniques,)
        technique_ids = tuple(str(item) for item in raw_techniques)
        if len(technique_ids) > 1:
            raise ProjectionInfeasible(
                f"projected step '{step_id}' has ambiguous technique bindings "
                f"{list(technique_ids)}"
            )
        specs.append(
            CanonicalLeafSpec(
                leaf_handle=f"l{index}",
                label=_canonical_label(step, action),
                description=None,
                action=action,
                zone=zone,
                technique_id=technique_ids[0] if technique_ids else None,
                projected_step_ids=(step_id,),
                realizations=(realization,),
                initial_ingress=action.kind == "initial_ingress",
            )
        )
    specs = _coalesce_canonical_leaf_specs(specs)
    if not any(spec.initial_ingress for spec in specs):
        raise ProjectionInfeasible("canonical leaves contain no initial ingress")
    return tuple(specs)


def _draft_leaf_handles(node: AttackTreeDraftNode) -> list[str]:
    if node.kind == "leaf":
        assert node.leaf_handle is not None
        return [node.leaf_handle]
    return [handle for child in node.children for handle in _draft_leaf_handles(child)]


def _draft_stats(node: AttackTreeDraftNode, depth: int = 1) -> tuple[int, int]:
    if node.kind == "leaf":
        return depth, 1
    child_stats = [_draft_stats(child, depth + 1) for child in node.children]
    return max(item[0] for item in child_stats), 1 + sum(
        item[1] for item in child_stats
    )


def validate_attack_tree_draft(
    draft: AttackTreeDraftV2,
    leaf_specs: tuple[CanonicalLeafSpec, ...] | list[CanonicalLeafSpec],
) -> DraftValidation:
    """Check bounded topology and exact-once canonical leaf coverage."""

    expected = tuple(spec.leaf_handle for spec in leaf_specs)
    actual = tuple(_draft_leaf_handles(draft.root))
    counts = Counter(actual)
    violations: list[SemanticDraftViolation] = []
    unknown = tuple(sorted(set(actual) - set(expected)))
    duplicates = tuple(sorted(handle for handle, count in counts.items() if count > 1))
    missing = tuple(handle for handle in expected if handle not in counts)
    if unknown:
        violations.append(
            SemanticDraftViolation(
                code="unknown_handle",
                handles=unknown,
                message=f"unknown leaf handles: {list(unknown)}",
            )
        )
    if duplicates:
        violations.append(
            SemanticDraftViolation(
                code="duplicate_handle",
                handles=duplicates,
                message=f"duplicate leaf handles: {list(duplicates)}",
            )
        )
    if missing:
        violations.append(
            SemanticDraftViolation(
                code="missing_handle",
                handles=missing,
                message=f"missing leaf handles: {list(missing)}",
            )
        )
    known_actual = tuple(handle for handle in actual if handle in set(expected))
    if not unknown and not duplicates and not missing and known_actual != expected:
        violations.append(
            SemanticDraftViolation(
                code="illegal_order",
                handles=known_actual,
                message="leaf handles do not preserve canonical projected-step order",
            )
        )
    depth, node_count = _draft_stats(draft.root)
    if depth > 5:
        violations.append(
            SemanticDraftViolation(
                code="excessive_depth",
                message=f"tree draft depth {depth} exceeds maximum 5",
            )
        )
    if node_count > max(1, 2 * len(expected) + 4):
        violations.append(
            SemanticDraftViolation(
                code="excessive_nodes",
                message=f"tree draft has {node_count} nodes for {len(expected)} leaves",
            )
        )
    return DraftValidation(accepted=not violations, violations=tuple(violations))


def compile_attack_tree_draft(
    *,
    seed_id: str,
    goal: str,
    draft: AttackTreeDraftV2,
    leaf_specs: tuple[CanonicalLeafSpec, ...] | list[CanonicalLeafSpec],
    threat_id: str | None = None,
) -> AttackTree:
    """Expand an accepted provider topology into a canonical ``AttackTree``."""

    validation = validate_attack_tree_draft(draft, leaf_specs)
    if not validation.accepted:
        raise InvalidSemanticDraft(validation)
    by_handle = {spec.leaf_handle: spec for spec in leaf_specs}

    def compile_node(node: AttackTreeDraftNode, node_id: str) -> AttackTreeNode:
        if node.kind == "leaf":
            assert node.leaf_handle is not None
            spec = by_handle[node.leaf_handle]
            return AttackTreeNode(
                id=node_id,
                label=spec.label,
                description=spec.description,
                gate=GateType.LEAF,
                zone=spec.zone,
                action=spec.action.model_copy(deep=True),
                threat_id=threat_id,
                technique_id=spec.technique_id,
                projected_step_ids=spec.projected_step_ids,
                realizations=spec.realizations,
            )
        return AttackTreeNode(
            id=node_id,
            label=node.label or "Attack decomposition",
            description=node.description,
            gate=GateType.AND,
            threat_id=threat_id,
            children=[
                compile_node(child, f"{node_id}.{index}")
                for index, child in enumerate(node.children, 1)
            ],
        )

    try:
        return AttackTree(
            id=f"tree-{seed_id}",
            seed_id=seed_id,
            goal=goal,
            root=compile_node(draft.root, "n1"),
        )
    except Exception as exc:
        raise CanonicalCompilationError(
            f"accepted attack-tree draft failed canonical compilation: {exc}"
        ) from exc

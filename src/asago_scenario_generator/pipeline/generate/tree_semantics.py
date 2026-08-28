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
    AttackTree,
    AttackTreeNode,
    GateType,
    LeafAction,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.models.scenario import NarrativeLayer
from asago_scenario_generator.pipeline.generate.canonical_projection import (
    CanonicalProjectedStepSemantics,
    ProjectionInfeasible as ProjectionInfeasible,
    derive_canonical_projection_semantics,
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


def _leaf_shape_error(node: "AttackTreeDraftNode") -> str | None:
    """Return the leaf-node shape defect message, if any."""
    if node.leaf_handle is None:
        return "leaf draft nodes require leaf_handle"
    if node.children:
        return "leaf draft nodes cannot have children"
    return None


def _group_shape_error(node: "AttackTreeDraftNode") -> str | None:
    """Return the group-node shape defect message, if any."""
    if node.leaf_handle is not None:
        return "group draft nodes cannot carry leaf_handle"
    if len(node.children) < 2:
        return "group draft nodes require at least two children"
    if not node.label:
        return "group draft nodes require a provider-authored label"
    return None


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
        shape_error = (
            _leaf_shape_error(self) if self.kind == "leaf" else _group_shape_error(self)
        )
        if shape_error is not None:
            raise ValueError(shape_error)
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


def _constrain_leaf_handles_schema(
    value: dict[str, Any], allowed: tuple[str, ...]
) -> None:
    """Replace a draft's leaf-handles items schema with the finite enum."""
    properties = value.get("properties")
    if isinstance(properties, dict) and "leaf_handles" in properties:
        leaf_handles_schema = properties["leaf_handles"]
        if isinstance(leaf_handles_schema, dict):
            leaf_handles_schema["items"] = {
                "enum": list(allowed),
                "type": "string",
            }


def _constrain_schema_tree(value: Any, allowed: tuple[str, ...]) -> None:
    """Recursively pin leaf-handles enums wherever a schema node declares them."""
    if isinstance(value, dict):
        _constrain_leaf_handles_schema(value, allowed)
        children = value.values()
    else:
        children = value if isinstance(value, list) else ()
    for child in children:
        _constrain_schema_tree(child, allowed)


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
        _constrain_schema_tree(schema, allowed)
        return schema

    return type(
        f"AttackTreeDraftV3For{len(allowed)}Leaves",
        (AttackTreeDraftV3,),
        {"model_json_schema": classmethod(model_json_schema)},
    )


def _handle_membership_violations(
    expected: tuple[str, ...],
    actual: tuple[str, ...],
    noun: str,
) -> tuple[list[SemanticDraftViolation], tuple[str, ...], tuple[str, ...]]:
    """Collect unknown and duplicate handle violations for a draft.

    The two shortfall kinds share this membership pass; callers append
    their own ``missing_handle`` messages when their contract splits
    shortages differently.
    """
    counts = Counter(actual)
    violations: list[SemanticDraftViolation] = []
    unknown = tuple(sorted(set(actual) - set(expected)))
    duplicates = tuple(sorted(handle for handle, count in counts.items() if count > 1))
    if unknown:
        violations.append(
            SemanticDraftViolation(
                code="unknown_handle",
                handles=unknown,
                message=f"unknown {noun} handles: {list(unknown)}",
            )
        )
    if duplicates:
        violations.append(
            SemanticDraftViolation(
                code="duplicate_handle",
                handles=duplicates,
                message=f"duplicate {noun} handles: {list(duplicates)}",
            )
        )
    return violations, unknown, duplicates


def _coverage_violations(
    expected: tuple[str, ...],
    actual: tuple[str, ...],
    noun: str,
) -> list[SemanticDraftViolation]:
    """Collect unknown, duplicate, and missing handle violations."""
    violations, _unknown, _duplicates = _handle_membership_violations(
        expected, actual, noun
    )
    counts = Counter(actual)
    missing = tuple(handle for handle in expected if handle not in counts)
    if missing:
        violations.append(
            SemanticDraftViolation(
                code="missing_handle",
                handles=missing,
                message=f"missing {noun} handles: {list(missing)}",
            )
        )
    return violations


def _validate_flat_attack_tree_draft(
    draft: AttackTreeDraftV3,
    leaf_specs: tuple[CanonicalLeafSpec, ...] | list[CanonicalLeafSpec],
) -> DraftValidation:
    expected = tuple(spec.leaf_handle for spec in leaf_specs)
    actual = tuple(handle for group in draft.groups for handle in group.leaf_handles)
    violations = _coverage_violations(expected, actual, "leaf")
    if not violations and actual != expected:
        violations.append(
            SemanticDraftViolation(
                code="illegal_order",
                handles=actual,
                message="leaf handles do not preserve canonical projected-step order",
            )
        )
    return DraftValidation(accepted=not violations, violations=tuple(violations))


def _leaf_node_for_spec(
    handle: str,
    node_id: str,
    by_handle: dict[str, CanonicalLeafSpec],
    threat_id: str | None,
) -> AttackTreeNode:
    """Compile one canonical leaf spec into a leaf tree node."""
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


def _compile_flat_group_node(
    group: AttackTreeDraftGroupV3,
    group_index: int,
    by_handle: dict[str, CanonicalLeafSpec],
    threat_id: str | None,
) -> AttackTreeNode:
    """Compile one provider grouping into a root child node."""
    root_child_id = f"n1.{group_index}"
    if len(group.leaf_handles) == 1:
        return _leaf_node_for_spec(
            group.leaf_handles[0], root_child_id, by_handle, threat_id
        )
    return AttackTreeNode(
        id=root_child_id,
        label=group.label,
        description=group.description,
        gate=GateType.AND,
        threat_id=threat_id,
        children=[
            _leaf_node_for_spec(
                handle, f"{root_child_id}.{leaf_index}", by_handle, threat_id
            )
            for leaf_index, handle in enumerate(group.leaf_handles, 1)
        ],
    )


def _flat_root_node(
    root_children: list[AttackTreeNode],
    draft: AttackTreeDraftV3,
    threat_id: str | None,
) -> AttackTreeNode:
    """Compile the canonical root, promoting a sole AND child in place."""
    if len(root_children) == 1:
        sole = root_children[0]
        promoted = sole.gate is GateType.AND
        return sole.model_copy(
            update={
                "id": "n1",
                "label": draft.root_label if promoted else sole.label,
                "description": draft.root_description if promoted else sole.description,
            },
            deep=True,
        )
    return AttackTreeNode(
        id="n1",
        label=draft.root_label,
        description=draft.root_description,
        gate=GateType.AND,
        threat_id=threat_id,
        children=root_children,
    )


def _compile_flat_tree(
    *,
    seed_id: str,
    goal: str,
    draft: AttackTreeDraftV3,
    by_handle: dict[str, CanonicalLeafSpec],
    threat_id: str | None,
) -> AttackTree:
    """Assemble the canonical flat attack tree from validated groupings."""
    root_children = [
        _compile_flat_group_node(group, group_index, by_handle, threat_id)
        for group_index, group in enumerate(draft.groups, 1)
    ]
    root = _flat_root_node(root_children, draft, threat_id)
    return AttackTree(
        id=f"tree-{seed_id}",
        seed_id=seed_id,
        goal=goal,
        root=root,
    )


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

    try:
        return _compile_flat_tree(
            seed_id=seed_id,
            goal=goal,
            draft=draft,
            by_handle=by_handle,
            threat_id=threat_id,
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


class CanonicalCompilationError(RuntimeError):
    """An accepted draft could not be compiled into the domain model."""

    stage_failure_code = "canonical_compilation_failed"
    stage_failure_retryable = False


def validate_tree_projection_realizability(
    projection_context: dict[str, Any],
    profile: CapabilityProfile,
) -> None:
    """Fail before generation unless the complete inventory can be compiled."""

    derive_canonical_projection_semantics(projection_context, profile)


def _mergeable_leaf_specs(previous: CanonicalLeafSpec, spec: CanonicalLeafSpec) -> bool:
    """Return True when two leaf specs share one canonical tree semantics."""
    return (
        previous.action == spec.action
        and previous.zone == spec.zone
        and previous.technique_id == spec.technique_id
        and previous.initial_ingress == spec.initial_ingress
    )


def _merge_leaf_specs(
    previous: CanonicalLeafSpec, spec: CanonicalLeafSpec
) -> CanonicalLeafSpec:
    """Merge the later spec into the earlier one, retaining all identities."""
    return previous.model_copy(
        update={
            "label": f"{previous.label}; then {spec.label}"[:120],
            "projected_step_ids": (
                *previous.projected_step_ids,
                *spec.projected_step_ids,
            ),
            "realizations": (*previous.realizations, *spec.realizations),
        }
    )


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
        if previous is not None and _mergeable_leaf_specs(previous, spec):
            merged[-1] = _merge_leaf_specs(previous, spec)
        else:
            merged.append(spec)
    return [
        spec.model_copy(update={"leaf_handle": f"l{index}"})
        for index, spec in enumerate(merged)
    ]


def _narrative_zone_matches(
    semantic: CanonicalProjectedStepSemantics, narrative: NarrativeLayer
) -> list[str]:
    """Return the narrative zones zooming a projected step, if any."""
    return [
        step.zone
        for step in narrative.steps
        if semantic.projected_step_id in step.projected_step_ids
    ]


def _leaf_spec_for_semantic(
    semantic: CanonicalProjectedStepSemantics,
    narrative: NarrativeLayer,
    index: int,
) -> CanonicalLeafSpec:
    """Compile one canonical step semantic into a leaf spec.

    Fails when the narrative layer zooms a projected step into a zone that
    disagrees with the canonical zone.
    """
    narrative_matches = _narrative_zone_matches(semantic, narrative)
    if narrative_matches != [semantic.zone]:
        raise CanonicalCompilationError(
            f"projected step '{semantic.projected_step_id}' narrative zone "
            f"{narrative_matches} disagrees with canonical zone "
            f"'{semantic.zone}'"
        )
    return CanonicalLeafSpec(
        leaf_handle=f"l{index}",
        label=semantic.label,
        description=None,
        action=semantic.action,
        zone=None if semantic.zone == "outside" else semantic.zone,
        technique_id=semantic.technique_id,
        projected_step_ids=(semantic.projected_step_id,),
        realizations=(semantic.realization,),
        initial_ingress=semantic.initial_ingress,
    )


def derive_canonical_leaf_specs(
    projection_context: dict[str, Any],
    narrative: NarrativeLayer,
    profile: CapabilityProfile,
) -> tuple[CanonicalLeafSpec, ...]:
    """Derive one immutable leaf specification per selected projected step.

    Failure is a projection error and happens before a provider is invoked.
    The returned order is the canonical selected-step order.
    """

    semantics = derive_canonical_projection_semantics(projection_context, profile)
    specs = [
        _leaf_spec_for_semantic(semantic, narrative, index)
        for index, semantic in enumerate(semantics.steps)
    ]
    specs = _coalesce_canonical_leaf_specs(specs)
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


def _topology_violations(
    root: AttackTreeDraftNode, expected_count: int
) -> list[SemanticDraftViolation]:
    """Collect depth and node-count violations for one drafted topology."""
    violations: list[SemanticDraftViolation] = []
    depth, node_count = _draft_stats(root)
    if depth > 5:
        violations.append(
            SemanticDraftViolation(
                code="excessive_depth",
                message=f"tree draft depth {depth} exceeds maximum 5",
            )
        )
    if node_count > max(1, 2 * expected_count + 4):
        violations.append(
            SemanticDraftViolation(
                code="excessive_nodes",
                message=f"tree draft has {node_count} nodes for {expected_count} leaves",
            )
        )
    return violations


def validate_attack_tree_draft(
    draft: AttackTreeDraftV2,
    leaf_specs: tuple[CanonicalLeafSpec, ...] | list[CanonicalLeafSpec],
) -> DraftValidation:
    """Check bounded topology and exact-once canonical leaf coverage."""

    expected = tuple(spec.leaf_handle for spec in leaf_specs)
    actual = tuple(_draft_leaf_handles(draft.root))
    violations = _coverage_violations(expected, actual, "leaf")
    known_actual = tuple(handle for handle in actual if handle in set(expected))
    if not violations and known_actual != expected:
        violations.append(
            SemanticDraftViolation(
                code="illegal_order",
                handles=known_actual,
                message="leaf handles do not preserve canonical projected-step order",
            )
        )
    violations.extend(_topology_violations(draft.root, len(expected)))
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

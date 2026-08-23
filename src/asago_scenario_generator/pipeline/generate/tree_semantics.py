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

    semantics = derive_canonical_projection_semantics(projection_context, profile)
    specs: list[CanonicalLeafSpec] = []
    for index, semantic in enumerate(semantics.steps):
        narrative_matches = [
            step.zone
            for step in narrative.steps
            if semantic.projected_step_id in step.projected_step_ids
        ]
        if narrative_matches != [semantic.zone]:
            raise CanonicalCompilationError(
                f"projected step '{semantic.projected_step_id}' narrative zone "
                f"{narrative_matches} disagrees with canonical zone "
                f"'{semantic.zone}'"
            )
        specs.append(
            CanonicalLeafSpec(
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
        )
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

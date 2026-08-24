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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-24T01:26:23Z","module_hash":"ea24489540abfb38cdf6e05f1b479f9257ce1a69eb36a48d97cc11568d40aaf2","source_sha256":"75cbe042485031bd51ccd09f177195ffaeaa16f9b4bac96a1bce601ef3e4ee12","functions":[{"id":"func/_leaf_shape_error","name":"_leaf_shape_error","line":47,"end_line":53,"hash":"a3abbfc2cd5dfa44bde1fb2d6fc6a0308a02fd154385eda44f33cd95e0466a30"},{"id":"func/_group_shape_error","name":"_group_shape_error","line":56,"end_line":64,"hash":"472b76572c885f34408f42beb2fd1ed417506b839ebece845dfadc90e3440210"},{"id":"func/AttackTreeDraftNode._shape_matches_kind","name":"_shape_matches_kind","line":79,"end_line":85,"hash":"466eda0e0a6f32948251d6fa8391e5802445037f0ca63ec256b109307bb2b1f8"},{"id":"func/_constrain_leaf_handles_schema","name":"_constrain_leaf_handles_schema","line":116,"end_line":127,"hash":"ccf36b640c8cfeeb8fb48d8d05055bd51aa901227a60b0b5edfdeaa4245eae37"},{"id":"func/_constrain_schema_tree","name":"_constrain_schema_tree","line":130,"end_line":138,"hash":"8df4f2fa5951e6cabedcc719f15117caee24dde83751d974429c8c6c02c2fbe9"},{"id":"func/build_attack_tree_draft_response_model","name":"build_attack_tree_draft_response_model","line":141,"end_line":162,"hash":"a01df8ec341547d8cd716ff024025c7679d11a9b1d2308ee0740416415c7df48"},{"id":"func/_handle_membership_violations","name":"_handle_membership_violations","line":165,"end_line":196,"hash":"aa7a42c0606eb2894ba26e4cd922901522744b7a425859c46270f212b6a5c5e2"},{"id":"func/_coverage_violations","name":"_coverage_violations","line":199,"end_line":218,"hash":"a44f6576dac8666f094c69d2d409e9625e01feb1097f8b1f5306ad6cfabac256"},{"id":"func/_validate_flat_attack_tree_draft","name":"_validate_flat_attack_tree_draft","line":221,"end_line":236,"hash":"1d44b3876599ed52846954d595fe2b503a8a5d8660a8f5b670a4a3492cf5d975"},{"id":"func/_leaf_node_for_spec","name":"_leaf_node_for_spec","line":239,"end_line":258,"hash":"3c9602209faefe90a744593da97fb8c254d573a6d779fb1e6cc7df46d7c14e9d"},{"id":"func/_compile_flat_group_node","name":"_compile_flat_group_node","line":261,"end_line":285,"hash":"d987fb70455b740e09ba238bd8e29d06b14e6db86ef9b6dbf8098e8bbb014680"},{"id":"func/_flat_root_node","name":"_flat_root_node","line":288,"end_line":312,"hash":"24bdecdd2029b4f6ec39db8c58d3b4732279230c148b1d7c3c6b0ccf80e8c08d"},{"id":"func/_compile_flat_tree","name":"_compile_flat_tree","line":315,"end_line":334,"hash":"1313f2c7f06335db6ab2c11d23a60ae6242a26af7d91169bfb25f9aafbf68173"},{"id":"func/compile_flat_attack_tree_draft","name":"compile_flat_attack_tree_draft","line":337,"end_line":362,"hash":"64315de290f8d93877099ee9e2d8cceff90fae8d4d0790f948d22e17b964b86f"},{"id":"func/InvalidSemanticDraft.__init__","name":"__init__","line":390,"end_line":392,"hash":"9ee6f2e4026346718788cc8282387d849827a68d55064809f960d5af66a7d0b8"},{"id":"func/validate_tree_projection_realizability","name":"validate_tree_projection_realizability","line":402,"end_line":408,"hash":"a3dc316fc7f34e9766313d810b5b37513be80bac72727eeae98fb5ae5ac43a6f"},{"id":"func/_mergeable_leaf_specs","name":"_mergeable_leaf_specs","line":411,"end_line":418,"hash":"ec10040b36e187bb5ce2a56a9097171eae641ff4163ea308b40801d1376fce90"},{"id":"func/_merge_leaf_specs","name":"_merge_leaf_specs","line":421,"end_line":434,"hash":"58d40c04b349de994b23352229139378d8b07dc57d487e328f0105b4959ff019"},{"id":"func/_coalesce_canonical_leaf_specs","name":"_coalesce_canonical_leaf_specs","line":437,"end_line":458,"hash":"202feea82299c3d5dfb025511983d6cfaf04da872eb2d91df64f24e164e5d583"},{"id":"func/_narrative_zone_matches","name":"_narrative_zone_matches","line":461,"end_line":469,"hash":"d19b3460e509376f4919091e588ddbf50900d403af77196a3fb0f2d40d577a2a"},{"id":"func/_leaf_spec_for_semantic","name":"_leaf_spec_for_semantic","line":472,"end_line":499,"hash":"5ae4fb8b21040fe342065faef7a27deb157172c0db5415caa6bdce0a4fb42913"},{"id":"func/derive_canonical_leaf_specs","name":"derive_canonical_leaf_specs","line":502,"end_line":519,"hash":"9b4083173b167f7a9e9323b5e8f51be27fcb2e67cd8d47e41c8a7364397da06e"},{"id":"func/_draft_leaf_handles","name":"_draft_leaf_handles","line":522,"end_line":526,"hash":"fada5a3d9882715d66465132f36b1dbf76c43a6093f822d43b964f9a92d6b32d"},{"id":"func/_draft_stats","name":"_draft_stats","line":529,"end_line":535,"hash":"e2bd307bc447cb5bcb4a7e53f59f0a20d60d5fddd76ab9593c29a4e017e9f472"},{"id":"func/_topology_violations","name":"_topology_violations","line":538,"end_line":558,"hash":"c3bc88821e45750ca774e42f2469629abddc8ceb2b414b8ef77ab5e1b3214797"},{"id":"func/validate_attack_tree_draft","name":"validate_attack_tree_draft","line":561,"end_line":580,"hash":"419b2d797153ea95b7698f43c15561f8bdd7b9d7ba2ae5a7ac5b8274f5727392"},{"id":"func/compile_attack_tree_draft","name":"compile_attack_tree_draft","line":583,"end_line":636,"hash":"858201a2a5adce2a9318668a1597ed199a876ff166bc96c036a2cd1bfca1569f"}]}
# mutate4py-manifest-end

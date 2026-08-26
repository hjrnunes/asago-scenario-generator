"""Pydantic models for the Attack Tree artifact.

AND/OR attack tree produced by Call 2 of the scenario generation pipeline.
Each tree decomposes a single abstract attack pattern seed into a hierarchical
set of attack steps with logical gates, zone annotations, taxonomy
references, and structural exposure signals.

Design lineage:
  - AND/OR gate semantics from MITRE Attack Flow conceptual model
  - 3-5 level depth per Schneider's examples
  - Structural exposure types from Schneider Part 2 (micro simulations)
  - Zones from Schneider's five-zone model

Typed leaf actions (cmps.9):
  Leaf nodes carry exactly one discriminated action from a closed union.
  Internal nodes (AND/OR) are logical composition only — no action payload.
  Zone requirements are enforced conditionally per action kind.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.realization import (
    ProjectedStepRealization,
    _realization_cover_error,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class GateType(str, Enum):
    """Logical gate type for attack tree nodes."""

    AND = "AND"
    OR = "OR"
    LEAF = "LEAF"


class StructuralExposure(str, Enum):
    """Structural weakness pattern at a node, per Schneider's criteria."""

    single_point_of_failure = "single_point_of_failure"
    convergence_point = "convergence_point"
    probabilistic_control = "probabilistic_control"
    defense_in_depth_claim = "defense_in_depth_claim"


class EvidenceLevel(str, Enum):
    """How well-evidenced an attack step is."""

    assumed = "assumed"
    design_reviewed = "design-reviewed"
    lab_validated = "lab-validated"
    end_to_end_validated = "end-to-end-validated"
    regression_tested = "regression-tested"


# ---------------------------------------------------------------------------
# Schneider zone constants (mirrors capability_profile.ZONE_NAMES)
# ---------------------------------------------------------------------------

_VALID_ZONES: frozenset[str] = frozenset(
    {"input", "reasoning", "tool_execution", "memory", "inter_agent"}
)

# Zones that represent internal AI execution surfaces.
_INTERNAL_ZONES: frozenset[str] = frozenset(
    {"input", "reasoning", "tool_execution", "memory", "inter_agent"}
)


# ---------------------------------------------------------------------------
# Discriminated leaf-action union (cmps.9)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------#
# Authoritative action↔zone matrix (cmps.9 review correction 6)
# ---------------------------------------------------------------------------#

# Single source of truth for which zones are valid for each action kind.
# All model/schema/generation/validation logic must reference this matrix.

ACTION_ZONE_RULES: dict[str, dict[str, Any]] = {
    "initial_ingress": {"zone_required": True, "valid_zones": _VALID_ZONES},
    "external_precondition": {"zone_required": False, "valid_zones": frozenset()},
    "ai_system_action": {"zone_required": True, "valid_zones": _VALID_ZONES},
    "attacker_action": {"zone_required": True, "valid_zones": _VALID_ZONES},
    "tool_invocation": {
        "zone_required": True,
        "valid_zones": frozenset({"tool_execution"}),
    },
    "integration_interaction": {
        "zone_required": True,
        "valid_zones": _INTERNAL_ZONES,
    },
    "impact": {
        "zone_required": "conditional",
        "valid_zones": _VALID_ZONES,
        "boundary_field": "boundary",
        "internal_requires_zone": True,
        "external_forbids_zone": True,
    },
}


class InitialIngressAction(BaseModel):
    """Attacker gains initial access through a profiled entry point.

    Zone follows verified ingress semantics derived from the entry point's
    canonical ``ingress_zone`` field.  The ``entry_point_id`` must resolve
    to a canonical entry point in the capability profile.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["initial_ingress"] = "initial_ingress"
    entry_point_id: str = Field(
        description="Canonical entry-point name from the capability profile.",
    )


class ExternalPreconditionAction(BaseModel):
    """Attacker preparation outside the assessed AI system boundary.

    Zone is forbidden (must be None).  External infrastructure — phishing
    pages, attacker-hosted C2, supply-chain staging — is never assigned a
    Schneider zone.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["external_precondition"] = "external_precondition"
    access_provenance: str | None = Field(
        default=None,
        description="Optional typed access provenance (e.g. 'phishing', 'supply-chain-staging').",
    )


class AiSystemAction(BaseModel):
    """Internal AI processing or action within a Schneider zone.

    Zone must be an active Schneider zone from the capability profile.
    Pure reasoning, planning, memory manipulation, or inter-agent
    messaging all use this action kind.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["ai_system_action"] = "ai_system_action"


class AttackerAction(BaseModel):
    """Attacker-controlled activity after ingress inside the assessed system.

    This represents discovery, probing, invocation, or persistence performed by
    the attacker when no canonical tool or integration binding exists.  It is
    deliberately distinct from both initial ingress and AI-system execution.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["attacker_action"] = "attacker_action"


class ToolInvocationAction(BaseModel):
    """The AI agent invokes a specific tool from the inventory.

    Zone must be exactly ``tool_execution``.  The ``tool_id`` must resolve
    to a canonical tool in the capability profile.  An optional
    ``integration_id`` may reference a downstream integration.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["tool_invocation"] = "tool_invocation"
    tool_id: str = Field(
        description="Canonical tool name from the capability profile.",
    )
    integration_id: str | None = Field(
        default=None,
        description="Optional canonical integration name for a downstream system.",
    )


class IntegrationInteractionAction(BaseModel):
    """Direct interaction with a connected external integration.

    Zone must be an active internal execution zone (e.g. ``tool_execution``
    or another internal zone where the integration is exercised).
    The ``integration_id`` must resolve to a canonical integration.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["integration_interaction"] = "integration_interaction"
    integration_id: str = Field(
        description="Canonical integration name from the capability profile.",
    )


class ImpactAction(BaseModel):
    """Explicit attack impact with target/boundary semantics.

    When ``boundary`` is ``internal`` the node must carry a Schneider zone.
    When ``boundary`` is ``external`` the zone must be None — external
    impacts (financial loss, reputational damage) are outside the AI
    system and must not receive a Schneider zone.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["impact"] = "impact"
    boundary: Literal["internal", "external"] = Field(
        description="Whether the impact occurs inside or outside the AI system boundary.",
    )
    target: str = Field(
        description="Explicit target or consequence of the impact.",
        max_length=200,
    )


LeafAction = Annotated[
    InitialIngressAction
    | ExternalPreconditionAction
    | AiSystemAction
    | AttackerAction
    | ToolInvocationAction
    | IntegrationInteractionAction
    | ImpactAction,
    Field(discriminator="kind"),
]


# ---------------------------------------------------------------------------
# Node model (recursive)
# ---------------------------------------------------------------------------


class AttackTreeNode(BaseModel):
    """A node in the AND/OR attack tree.

    Internal nodes (AND/OR) carry only logical composition and children.
    Leaf nodes carry exactly one discriminated :data:`LeafAction`.

    The ``zone`` field is optional.  For leaf nodes, zone requirements
    are enforced conditionally per action kind:

    - ``external_precondition``: zone must be ``None``
    - ``ai_system_action``: zone must be a valid Schneider zone
    - ``attacker_action``: zone must be a valid Schneider zone
    - ``tool_invocation``: zone must be exactly ``tool_execution``
    - ``integration_interaction``: zone must be a valid internal zone
    - ``impact``: zone required when ``boundary == "internal"``, forbidden when ``"external"``
    - ``initial_ingress``: zone should reflect entry-point semantics

    For internal (AND/OR) nodes, ``zone`` is optional display metadata.
    """

    id: str = Field(
        description="Dotted path identifier reflecting tree position (e.g. 'n1', 'n1.1', 'n1.1.1').",
        pattern=r"^n\d+(\.\d+){0,4}$",
    )
    label: str = Field(
        description="Short human-readable label (display prose only — never used for canonical semantics).",
        max_length=120,
    )
    description: str | None = Field(
        default=None,
        description="Optional longer description (display prose only).",
    )
    gate: GateType = Field(
        description="Logical gate type: AND (all children must succeed), OR (any child suffices), LEAF (terminal).",
    )
    zone: str | None = Field(
        default=None,
        description="Schneider zone where this step occurs.  None for external preconditions and external impacts.",
    )
    action: LeafAction | None = Field(
        default=None,
        description="Discriminated typed action for leaf nodes.  Required for LEAF, forbidden for AND/OR.",
    )
    threat_id: str | None = Field(
        default=None,
        description="OWASP Agentic Threat ID applicable to this node (e.g. 'T2').",
        pattern=r"^T\d+$",
    )
    technique_id: str | None = Field(
        default=None,
        description="Technique ID applicable to this node — MITRE ATLAS (e.g. 'AML.T0051') or LAAF (e.g. 'S1', 'M2').",
        pattern=r"^(AML\.T\d{4}(\.\d{3})?|[SML]\d+)$",
    )
    tactic: str | None = Field(
        default=None,
        description="MITRE ATLAS tactic phase for this attack step (e.g. 'AML.TA0005' for Execution).",
        pattern=r"^AML\.TA\d{4}$",
    )
    maestro_layer: int | None = Field(
        default=None,
        description="MAESTRO architectural layer targeted by this step (1-7).",
        ge=1,
        le=7,
    )
    control_point: str | None = Field(
        default=None,
        description="The defensive control that should block or detect this step.",
    )
    structural_exposure: StructuralExposure | None = Field(
        default=None,
        description="Structural weakness pattern at this node.",
    )
    evidence_level: EvidenceLevel | None = Field(
        default=EvidenceLevel.assumed,
        description="How well-evidenced this step is.",
    )
    children: list[AttackTreeNode] | None = Field(
        default=None,
        description="Child nodes. Required for AND/OR gates; must be absent/empty for LEAF.",
    )
    projected_step_ids: tuple[str, ...] = Field(
        default=(),
        description=(
            "Canonical projected step IDs (from ProjectionEnvelopeBlock) "
            "that this tree leaf realizes.  Controlled many-to-many: "
            "a leaf may realize multiple projected steps (combine) and "
            "a projected step may be realized by multiple leaves (split). "
            "Required (non-empty) on security-bearing leaves in scenarios "
            "with a projection block; the LLM receives the IDs as opaque "
            "constraints.  Empty on internal/crossing external_precondition "
            "leaves; outside-boundary external preconditions may map."
        ),
    )
    realizations: tuple[ProjectedStepRealization, ...] = Field(
        default=(),
        description=(
            "Per-projected-step canonical realization records.  One record "
            "per projected_step_id.  Required (non-empty) when "
            "projected_step_ids is non-empty; empty on internal/crossing "
            "external_precondition leaves.  The validator compares each "
            "record against the embedded canonical step at the tree boundary."
        ),
    )

    @model_validator(mode="after")
    def validate_gate_children_action(self) -> AttackTreeNode:
        """Enforce gate/children/action conditional rules."""
        _validate_gate_arity(self)
        prefix_error = _child_id_prefix_error(self)
        if prefix_error is not None:
            raise ValueError(prefix_error)

        # --- Conditional zone validation for leaf actions ---
        if self.gate == GateType.LEAF and self.action is not None:
            self._validate_action_zone()

        # --- Realization coverage check (422o.4) ---
        # Enforced unconditionally on ALL LEAF nodes, not just when
        # projected_step_ids is truthy.  Outside-boundary external
        # preconditions may carry a mapped canonical realization; normalized
        # internal/crossing external leaves carry neither IDs nor realizations.
        if self.gate == GateType.LEAF:
            cover_error = _realization_cover_error(
                self.realizations,
                self.projected_step_ids,
                f"LEAF node '{self.id}'",
            )
            if cover_error is not None:
                raise ValueError(cover_error)

        return self

    def _validate_action_zone(self) -> None:
        """Enforce action-specific zone requirements using the authoritative matrix."""
        action = self.action
        if action is None:
            return
        rule = ACTION_ZONE_RULES.get(action.kind, {})
        error = _zone_rule_error(self, action.kind, rule)
        if error is not None:
            raise ValueError(error)


def _validate_leaf_arity(node: AttackTreeNode) -> None:
    """LEAF nodes must have no children and carry exactly one typed action."""
    child_count = len(node.children) if node.children else 0
    if child_count > 0:
        raise ValueError(
            f"LEAF node '{node.id}' must not have children (has {child_count})"
        )
    if node.action is None:
        raise ValueError(
            f"LEAF node '{node.id}' must carry exactly one typed action "
            f"(action is None).  Every leaf must have a discriminated action."
        )


def _validate_internal_arity(node: AttackTreeNode) -> None:
    """AND/OR nodes must have at least two children and no leaf action."""
    child_count = len(node.children) if node.children else 0
    if child_count < 2:
        raise ValueError(
            f"{node.gate.value} node '{node.id}' must have at least 2 children (has {child_count})"
        )
    if node.action is not None:
        raise ValueError(
            f"{node.gate.value} node '{node.id}' must not carry a leaf action "
            f"(internal nodes are logical composition only)."
        )


def _validate_gate_arity(node: AttackTreeNode) -> None:
    """Dispatch gate/children/action arity rules by node gate."""
    if node.gate == GateType.LEAF:
        _validate_leaf_arity(node)
    else:
        _validate_internal_arity(node)


def _child_id_prefix_error(node: AttackTreeNode) -> str | None:
    """First child whose ID does not start with the parent prefix, else None."""
    for child in node.children or ():
        if not child.id.startswith(node.id + "."):
            return (
                f"Child node '{child.id}' must have id starting with "
                f"'{node.id}.' (parent prefix)"
            )
    return None


def _impact_zone_error(node: AttackTreeNode, valid_zones: frozenset[str]) -> str | None:
    """Zone error for impact actions, or None when valid."""
    assert isinstance(node.action, ImpactAction)  # kind=="impact" guard
    if node.action.boundary == "internal":
        if node.zone is None:
            return (
                f"LEAF node '{node.id}' with internal impact must have "
                f"a Schneider zone (zone is None)."
            )
        if node.zone not in valid_zones:
            return (
                f"LEAF node '{node.id}' with internal impact has invalid "
                f"zone '{node.zone}'. Valid zones: {sorted(valid_zones)}"
            )
    elif node.zone is not None:  # boundary == "external"
        return (
            f"LEAF node '{node.id}' with external impact must not have "
            f"a Schneider zone (got '{node.zone}'). External impacts "
            f"are outside the AI boundary."
        )
    return None


def _forbidden_zone_error(node: AttackTreeNode, kind: str) -> str | None:
    """Zone error for actions that must not carry a zone, or None."""
    if node.zone is not None:
        return (
            f"LEAF node '{node.id}' with {kind} action "
            f"must not have a Schneider zone (got '{node.zone}'). "
            f"External preconditions are outside the AI boundary."
        )
    return None


def _required_zone_error(
    node: AttackTreeNode, kind: str, valid_zones: frozenset[str]
) -> str | None:
    """Zone error for actions that require a valid zone, or None."""
    if node.zone is None:
        return (
            f"LEAF node '{node.id}' with {kind} action must have "
            f"a valid zone (zone is None)."
        )
    if node.zone not in valid_zones:
        return (
            f"LEAF node '{node.id}' with {kind} action has invalid "
            f"zone '{node.zone}'. Valid zones: {sorted(valid_zones)}"
        )
    return None


def _zone_rule_error(
    node: AttackTreeNode, kind: str, rule: dict[str, Any]
) -> str | None:
    """Action-kind zone requirement error from the authoritative matrix."""
    if kind == "impact":
        return _impact_zone_error(node, rule.get("valid_zones", frozenset()))
    if rule.get("zone_required", False) is False:
        return _forbidden_zone_error(node, kind)
    return _required_zone_error(node, kind, rule.get("valid_zones", frozenset()))


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------


class AttackTree(BaseModel):
    """Top-level attack tree container.

    One tree per scenario seed.  Decomposes a single abstract attack pattern into a
    hierarchical AND/OR tree of attack steps.
    """

    id: str = Field(
        description="Tree identifier. Format: 'tree-{seed_id}' (e.g. 'tree-AP-T7-01').",
        pattern=r"^tree-AP-T\d+-\d+$",
    )
    seed_id: str = Field(
        description="The attack pattern seed that produced this tree (e.g. 'AP-T7-01').",
        pattern=r"^AP-T\d+-\d+$",
    )
    goal: str = Field(
        description="The attacker's top-level objective, stated as a concrete outcome.",
    )
    root: AttackTreeNode = Field(
        description="Root node of the AND/OR tree.",
    )

    @model_validator(mode="after")
    def validate_root_id(self) -> AttackTree:
        """Root node must have id 'n1'."""
        if self.root.id != "n1":
            raise ValueError(f"Root node must have id 'n1', got '{self.root.id}'")
        return self

    def collect_technique_ids(self) -> list[str]:
        """Collect all unique technique_id values from tree nodes.

        Walks the tree recursively and returns a deduplicated list of
        technique IDs — ATLAS or LAAF (preserving first-seen order).
        """
        seen: set[str] = set()
        result: list[str] = []
        _collect_technique_ids_from_node(self.root, seen, result)
        return result


def _collect_technique_ids_from_node(
    node: AttackTreeNode,
    seen: set[str],
    result: list[str],
) -> None:
    """Recursively collect unique technique_id values from a node and its children."""
    if node.technique_id and node.technique_id not in seen:
        seen.add(node.technique_id)
        result.append(node.technique_id)
    if node.children:
        for child in node.children:
            _collect_technique_ids_from_node(child, seen, result)


# ---------------------------------------------------------------------------
# Pre-validation tree repair
# ---------------------------------------------------------------------------


def _repair_children(node: dict[str, Any]) -> list | None:
    """Recursively repaired children list, or None when the node has none."""
    children = node.get("children")
    if children and isinstance(children, list):
        return [_repair_node(child) for child in children]
    return None


def _is_single_child_gate(gate: str, children: list | None) -> bool:
    """Whether an AND/OR gate has exactly one child to collapse."""
    return gate in ("AND", "OR") and children is not None and len(children) == 1


def _repair_node(node: dict[str, Any]) -> dict[str, Any]:
    """Recursively repair a node dict, collapsing single-child AND/OR nodes.

    When an AND or OR node has exactly one child, the parent is replaced by the
    child.  The parent's ``id`` is preserved (to maintain dotted-path
    consistency), but the child's ``label``, ``gate``, ``zone``, ``children``,
    ``action``, and all other fields are used.

    The function recurses depth-first so that deeply-nested single-child chains
    are collapsed from the bottom up.
    """
    children = _repair_children(node)

    # Recurse into children first (bottom-up repair).
    if children is not None:
        node["children"] = children

    gate = node.get("gate", "").upper()

    if _is_single_child_gate(gate, children):
        parent_id = node["id"]
        child = node["children"][0]
        logger.warning(
            "Collapsing single-child %s node '%s' — replacing with child '%s' (%s)",
            gate,
            parent_id,
            child.get("id", "?"),
            child.get("label", "?"),
        )
        # Build the merged node: parent's id, everything else from child.
        merged: dict[str, Any] = {**child, "id": parent_id}
        # Recurse again in case the child itself also needs repair.
        return _repair_node(merged)

    return node


def repair_attack_tree_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Walk a raw attack-tree dict and fix single-child AND/OR nodes.

    .. deprecated::
        This helper is **not** called in the normal generation path.
        Strict typed/versioned generation rejects malformed gates via
        Pydantic model validation so the caller retries or rejects —
        no silent structural mutation (cmps.9 review correction 3).

        It is retained only for post-pruning repair in
        :func:`asago_scenario_generator.pipeline.validation._repair_tree_model`,
        which operates behind the explicit parsimony boundary.

    Call this on the dict produced by ``yaml.safe_load`` **before** passing it
    to ``AttackTree.model_validate``.
    """
    if "root" in data and isinstance(data["root"], dict):
        data["root"] = _repair_node(data["root"])
    return data

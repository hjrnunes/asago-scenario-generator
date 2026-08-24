"""Property tests pinning the canonical per-step action derivation.

``pipeline/generate/canonical_projection.py`` owns the deterministic
per-step action compiler consumed by the taxonomy projection stages.  Two
contracts are pinned under broad input ranges:

- **Kind membership**: the derived action kind is always admitted by the
  compatibility narrowing for that step — the compiler never invents a
  tree kind the step semantics did not approve — and derivation is
  deterministic for identical steps.
- **Precedence within the compatibility region**: when several candidate
  conditions hold, the compiler resolves them in the documented order —
  ingress ownership first, then external precondition, impact, tool
  invocation, integration interaction, and finally the generic actor or
  AI-system action, else ``ProjectionInfeasible``.

These properties are offline and deterministic; they never contact an
LLM endpoint.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackerAction,
    ExternalPreconditionAction,
    ImpactAction,
    InitialIngressAction,
    IntegrationInteractionAction,
    ToolInvocationAction,
)
from asago_scenario_generator.pipeline.compatibility import (
    EXECUTOR_ROLE_TO_LEAF_COMPAT,
    STEP_TO_LEAF_ACTION_COMPAT,
)
from asago_scenario_generator.pipeline.generate.canonical_projection import (
    ProjectionInfeasible,
    _derive_action,
    compatible_leaf_action_kinds_for_step,
)

_MAX_EXAMPLES = 60
_IDS = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_", min_size=1, max_size=16)


def _resource_link(
    kind: str, resource_id: str, *, role: str | None = None, slot_id: str | None = None
) -> dict[str, object]:
    link: dict[str, object] = {
        "resource_ref": {"kind": kind, f"{kind}_id": resource_id}
    }
    if role is not None:
        link["role"] = role
    if slot_id is not None:
        link["slot_id"] = slot_id
    return link


@st.composite
def derive_inputs(draw) -> tuple[dict[str, object], dict[str, object]]:
    """An arbitrary projected step with an arbitrary projection context."""
    action_kind = draw(
        st.sampled_from(tuple(STEP_TO_LEAF_ACTION_COMPAT) + ("", "bogus-kind"))
    )
    executor_role = draw(
        st.sampled_from(tuple(EXECUTOR_ROLE_TO_LEAF_COMPAT) + ("", "bogus-role"))
    )
    boundary = draw(st.sampled_from(("inside", "crossing", "outside", "")))
    owns_ingress = draw(st.booleans())
    has_tool = draw(st.booleans())
    has_integration = draw(st.booleans())
    has_entry_point = draw(st.booleans())
    entry_point_id = draw(_IDS)
    links: list[dict[str, object]] = []
    if owns_ingress:
        links.append(
            _resource_link(
                "entry_point",
                entry_point_id,
                role="ingress",
                slot_id="slot-0",
            )
        )
    if has_tool:
        links.append(_resource_link("tool", "tool.t1"))
    if has_integration:
        links.append(_resource_link("integration", "integration.i1"))
    if has_entry_point and not owns_ingress:
        links.append(_resource_link("entry_point", entry_point_id))
    step: dict[str, object] = {
        "step_id": "step.1",
        "action_kind": action_kind,
        "executor_role": executor_role,
        "boundary_position": boundary,
        "resource_links": links,
    }
    projection_context: dict[str, object] = {
        "initial_ingress_slot_id": "slot-0",
        "canonical_ingress": {"entry_point_id": entry_point_id},
    }
    return step, projection_context


@st.composite
def invoke_precedence_inputs(
    draw,
) -> tuple[dict[str, object], dict[str, object]]:
    """An invoke/system step covering the candidate precedence lattice."""
    owns_ingress = draw(st.booleans())
    has_tool = draw(st.booleans())
    has_integration = draw(st.booleans())
    entry_point_id = draw(_IDS)
    links: list[dict[str, object]] = []
    if owns_ingress:
        links.append(
            _resource_link(
                "entry_point",
                entry_point_id,
                role="ingress",
                slot_id="slot-0",
            )
        )
    if has_tool:
        links.append(_resource_link("tool", "tool.t1"))
    if has_integration:
        links.append(_resource_link("integration", "integration.i1"))
    step: dict[str, object] = {
        "step_id": "step.1",
        "action_kind": "invoke",
        "executor_role": "system",
        "boundary_position": "crossing",
        "resource_links": links,
    }
    projection_context: dict[str, object] = {
        "initial_ingress_slot_id": "slot-0",
        "canonical_ingress": {"entry_point_id": entry_point_id},
    }
    return step, projection_context


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=derive_inputs())
def test_derive_action_kind_is_admitted_by_compatibility_and_deterministic(
    inputs: tuple[dict[str, object], dict[str, object]],
) -> None:
    """Derived kinds stay inside the compatibility region; derivation is pure."""
    step, projection_context = inputs
    compatible = compatible_leaf_action_kinds_for_step(step, projection_context)

    boundary = str(step.get("boundary_position", ""))
    action_kind = str(step.get("action_kind", ""))
    has_tool = any(
        isinstance(link, dict)
        and isinstance(link.get("resource_ref"), dict)
        and link["resource_ref"].get("kind") == "tool"
        for link in step.get("resource_links", ())
    )
    has_integration = any(
        isinstance(link, dict)
        and isinstance(link.get("resource_ref"), dict)
        and link["resource_ref"].get("kind") == "integration"
        for link in step.get("resource_links", ())
    )

    try:
        action = _derive_action(step, projection_context)
    except ProjectionInfeasible:
        # Fail closed: a raise is deterministic and no ladder candidate
        # could have resolved the step (no silent generic default).
        try:
            _derive_action(step, projection_context)
        except ProjectionInfeasible:
            pass
        else:
            raise AssertionError(
                "ProjectionInfeasible derivation must be deterministic"
            )
        assert not compatible or not (
            (boundary == "outside" and "external_precondition" in compatible)
            or (action_kind == "impact" and "impact" in compatible)
            or (has_tool and "tool_invocation" in compatible)
            or (
                has_integration
                and "integration_interaction" in compatible
            )
            or bool({"attacker_action", "ai_system_action"} & compatible)
        )
        return

    assert action.kind in compatible, (
        f"derived kind {action.kind!r} outside compatible kinds {compatible}"
    )
    # Deterministic derivation: the same step yields the same action.
    assert _derive_action(step, projection_context) == action


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=invoke_precedence_inputs())
def test_derive_action_precedence_within_the_compatible_region(
    inputs: tuple[dict[str, object], dict[str, object]],
) -> None:
    """The derive ladder resolves ingress, tool, then integration, then fail."""
    step, projection_context = inputs
    owns_ingress = any(
        isinstance(link, dict) and link.get("role") == "ingress"
        for link in step.get("resource_links", ())
    )
    has_tool = any(
        isinstance(link, dict)
        and isinstance(link.get("resource_ref"), dict)
        and link["resource_ref"].get("kind") == "tool"
        for link in step.get("resource_links", ())
    )
    has_integration = any(
        isinstance(link, dict)
        and isinstance(link.get("resource_ref"), dict)
        and link["resource_ref"].get("kind") == "integration"
        for link in step.get("resource_links", ())
    )
    entry_point_id = str(
        projection_context["canonical_ingress"]["entry_point_id"]
    )

    try:
        action = _derive_action(step, projection_context)
    except ProjectionInfeasible:
        assert not owns_ingress and not has_tool and not has_integration
        return

    if owns_ingress:
        assert action == InitialIngressAction(entry_point_id=entry_point_id)
        return
    if has_tool:
        assert isinstance(action, ToolInvocationAction)
        assert action.tool_id == "tool.t1"
        assert action.integration_id == (
            "integration.i1" if has_integration else None
        )
        return
    if has_integration:
        assert action == IntegrationInteractionAction(integration_id="integration.i1")
        return
    # Without bindings the invoke/system region holds no generic fallback.
    raise AssertionError("unreachable: invoke/system without bindings fails")


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    boundary=st.sampled_from(("inside", "crossing", "outside")),
    action_kind=st.sampled_from(tuple(STEP_TO_LEAF_ACTION_COMPAT)),
    has_tool=st.booleans(),
    has_integration=st.booleans(),
)
def test_derive_action_generic_kinds_follow_the_compatibility_region(
    boundary: str,
    action_kind: str,
    has_tool: bool,
    has_integration: bool,
) -> None:
    """Generic actor/AI-system kinds fire only when the region admits them."""
    links: list[dict[str, object]] = []
    if has_tool:
        links.append(_resource_link("tool", "tool.t1"))
    if has_integration:
        links.append(_resource_link("integration", "integration.i1"))
    step: dict[str, object] = {
        "step_id": "step.1",
        "action_kind": action_kind,
        "executor_role": "attacker",
        "boundary_position": boundary,
        "resource_links": links,
    }
    projection_context: dict[str, object] = {
        "initial_ingress_slot_id": "slot-0",
        "canonical_ingress": {"entry_point_id": "ep-1"},
    }
    compatible = compatible_leaf_action_kinds_for_step(step, projection_context)

    try:
        action = _derive_action(step, projection_context)
    except ProjectionInfeasible:
        assert "attacker_action" not in compatible
        assert "ai_system_action" not in compatible
        return

    assert action.kind in compatible
    if action.kind == "attacker_action":
        # The generic attacker kind wins only when no earlier candidate
        # condition holds and no generic sibling outranks it.
        assert isinstance(action, AttackerAction)
        assert "attacker_action" in compatible
        assert not (
            boundary == "outside" and "external_precondition" in compatible
        )
        assert not (action_kind == "impact" and "impact" in compatible)
        assert not (has_tool and "tool_invocation" in compatible)
        assert not (
            has_integration and "integration_interaction" in compatible
        )
    elif action.kind == "ai_system_action":
        assert isinstance(action, AiSystemAction)
        assert "ai_system_action" in compatible
        assert "attacker_action" not in compatible
        assert not (
            boundary == "outside" and "external_precondition" in compatible
        )
        assert not (action_kind == "impact" and "impact" in compatible)
        assert not (has_tool and "tool_invocation" in compatible)
        assert not (
            has_integration and "integration_interaction" in compatible
        )
    else:
        # Concrete kinds fire exactly on their documented conditions.
        if action.kind == "external_precondition":
            assert isinstance(action, ExternalPreconditionAction)
            assert boundary == "outside"
        elif action.kind == "impact":
            assert isinstance(action, ImpactAction)
            assert action_kind == "impact"
        elif action.kind == "tool_invocation":
            assert isinstance(action, ToolInvocationAction)
            assert has_tool
        elif action.kind == "integration_interaction":
            assert isinstance(action, IntegrationInteractionAction)
            assert has_integration
        else:  # pragma: no cover - defensive
            raise AssertionError(f"unexpected derived kind {action.kind!r}")

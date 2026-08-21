"""Architecture and property checks for taxonomy Call 0 modules."""

from __future__ import annotations

import ast
from pathlib import Path

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.data.atlas import TECHNIQUE_PROPERTIES
from asago_scenario_generator.pipeline.generate.actor_rules import (
    compute_compatible_actor_types,
    compute_minimum_capability_level,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _ACTOR_GOAL_INCOMPATIBLE,
    ALL_ACTOR_TYPES,
)

GENERATE_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "pipeline"
    / "generate"
)


def _imported_modules(path: Path) -> set[str]:
    """Return absolute module names imported by a source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_actor_context_does_not_import_actor_or_form_a_cycle() -> None:
    """Prompt context depends on policy, never on the actor orchestrator."""
    imports = _imported_modules(GENERATE_DIR / "actor_context.py")
    assert "asago_scenario_generator.pipeline.generate.actor" not in imports
    assert "asago_scenario_generator.pipeline.generate.actor_rules" in imports


def test_actor_rules_isolated_from_prompt_and_orchestration_modules() -> None:
    """Pure actor policy must not depend on prompt or orchestration modules."""
    imports = _imported_modules(GENERATE_DIR / "actor_rules.py")
    forbidden = {
        "asago_scenario_generator.pipeline.generate.actor",
        "asago_scenario_generator.pipeline.generate.actor_context",
        "asago_scenario_generator.prompts",
        "asago_scenario_generator.llm.client",
    }
    assert not forbidden & imports


@settings(max_examples=60, deadline=None)
@given(
    technique_ids=st.lists(
        st.sampled_from(
            tuple(TECHNIQUE_PROPERTIES) + ("UNKNOWN.T9999",),
        ),
        max_size=6,
    ),
    additional_technique=st.sampled_from(
        tuple(TECHNIQUE_PROPERTIES) + ("UNKNOWN.T9999",),
    ),
    ep_controllability=st.one_of(
        st.none(),
        st.sampled_from(("direct", "indirect", "system", "unexpected")),
    ),
    threat_id=st.one_of(
        st.none(),
        st.sampled_from(tuple(_ACTOR_GOAL_INCOMPATIBLE) + ("unknown-threat",)),
    ),
)
def test_capability_floor_is_bounded_and_monotonic(
    technique_ids: list[str],
    ep_controllability: str | None,
    threat_id: str | None,
    additional_technique: str,
) -> None:
    """Adding techniques cannot reduce the deterministic capability floor."""
    order = {"novice": 0, "intermediate": 1, "advanced": 2, "expert": 3}
    floor = compute_minimum_capability_level(
        technique_ids,
        ep_controllability,
        threat_id,
    )
    extended_floor = compute_minimum_capability_level(
        technique_ids + [additional_technique],
        ep_controllability,
        threat_id,
    )
    assert floor in order
    assert extended_floor in order
    assert order[extended_floor] >= order[floor]


@settings(max_examples=60, deadline=None)
@given(
    technique_ids=st.lists(
        st.sampled_from(
            tuple(TECHNIQUE_PROPERTIES) + ("UNKNOWN.T9999",),
        ),
        max_size=6,
    ),
    ep_controllability=st.one_of(
        st.none(),
        st.sampled_from(("direct", "indirect", "system", "unexpected")),
    ),
    threat_id=st.one_of(
        st.none(),
        st.sampled_from(tuple(_ACTOR_GOAL_INCOMPATIBLE) + ("unknown-threat",)),
    ),
    goal_id=st.one_of(
        st.none(),
        st.sampled_from(tuple(_ACTOR_GOAL_INCOMPATIBLE) + ("unknown-goal",)),
    ),
)
def test_compatible_actor_policy_preserves_a_nonempty_known_set(
    technique_ids: list[str],
    ep_controllability: str | None,
    threat_id: str | None,
    goal_id: str | None,
) -> None:
    """Policy narrowing never returns an unknown or empty actor set."""
    compatible = compute_compatible_actor_types(
        technique_ids,
        ep_controllability,
        threat_id,
        goal_id=goal_id,
    )
    assert compatible
    assert compatible <= set(ALL_ACTOR_TYPES)

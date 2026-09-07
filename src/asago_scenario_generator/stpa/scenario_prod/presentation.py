"""Deterministic presentation of an already fixed scenario hypothesis."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec


def render_scenario_summary(spec: ScenarioSpec) -> tuple[str, dict, GherkinSpec]:
    """Render supplied evidence only; never describe a hypothesis as a result."""
    context = spec.scenario_context
    unsafe_behavior = (
        context.ica.exact_ica_text if context is not None else spec.loss_scenario
    )
    prerequisites = [factor.description for factor in spec.causal_factors]
    intentions = list(spec.attacker_bdi.intentions)
    constraints = (
        [item.description for item in context.constraints]
        if context is not None
        else []
    )
    narrative = "\n".join(
        [
            "Test hypothesis — not an observed execution result.",
            f"Unsafe behavior: {unsafe_behavior}",
            "Causal prerequisites:",
            *[f"- {item}" for item in prerequisites],
            "Proposed stimulus:",
            *[f"- {item}" for item in intentions],
            f"Potential loss: {spec.loss_scenario}",
            "Execution must establish prerequisites and evaluate the fixed outcome.",
        ]
    )
    tree = {
        "root": unsafe_behavior,
        "branches": [
            {
                "category": factor.kind.value,
                "label": factor.description,
                "source_id": factor.source_id,
                "children": [],
            }
            for factor in spec.causal_factors
        ],
        "leaves": prerequisites,
    }
    gherkin = GherkinSpec(
        feature=f"Evaluate {spec.scenario_id}",
        scenario=unsafe_behavior,
        given=[f"Given the test establishes: {item}" for item in prerequisites],
        when=[f"When the test applies: {item}" for item in intentions],
        then_expected=[
            f"Then the target should satisfy: {item}" for item in constraints
        ],
        then_actual=[
            f"But the test checks whether this unsafe behavior occurs: {unsafe_behavior}"
        ],
    )
    return narrative, tree, gherkin

"""Deterministic presentation of an already fixed scenario hypothesis.

The deterministic summary states the hypothesis, its causal account and its
failure boundary. It prescribes no stimulus, no delivery and no executable
check: concrete messages, harness delivery and detectors belong to the
artifact generator. Only supplied evidence is rendered; a hypothesis is never
described as a result.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

TREE_FRAMING = (
    "Proposed causal hypothesis. No node below is an observed execution result, "
    "and no node restates an executable check as its own cause."
)
HYPOTHESIS_AUTHORITY = "proposed_hypothesis"


def render_scenario_summary(spec: ScenarioSpec) -> tuple[str, dict, GherkinSpec]:
    """Render supplied scenario evidence only; never describe a hypothesis as a result.

    The rendering is deliberately free of artifact design: the attacker
    intentions that the historical renderer copied into "proposed stimulus"
    prose and Gherkin steps are dropped, so no representation prescribes a
    message, a delivery or an executable predicate.
    """
    context = spec.scenario_context
    unsafe_behavior = (
        context.ica.exact_ica_text if context is not None else spec.loss_scenario
    )
    prerequisites = [factor.description for factor in spec.causal_factors]
    constraints = (
        [item.description for item in context.constraints]
        if context is not None
        else []
    )
    narrative = "\n".join(
        [
            "Test hypothesis — not an observed execution result.",
            f"Unsafe behavior under examination: {unsafe_behavior}",
            "Causal prerequisites (proposed, not established):",
            *[f"- {item}" for item in prerequisites],
            "Governing constraints:",
            *[f"- {item}" for item in constraints],
            f"Potential loss: {spec.loss_scenario}",
            "Failure is defined by the unsafe behavior under examination. The "
            "causal account above is a proposed hypothesis; this summary "
            "prescribes no message, no delivery and no executable check.",
        ]
    )
    tree = {
        "framing": TREE_FRAMING,
        "root": unsafe_behavior,
        "root_authority": HYPOTHESIS_AUTHORITY,
        "branches": [
            {
                "node_id": f"AT-B{index}",
                "category": factor.kind.value,
                "label": factor.description,
                "source_id": factor.source_id,
                "authority": HYPOTHESIS_AUTHORITY,
                "children": [],
            }
            for index, factor in enumerate(spec.causal_factors, start=1)
        ],
        "leaves": list(prerequisites),
        "leaf_authority": HYPOTHESIS_AUTHORITY,
    }
    gherkin = GherkinSpec(
        feature=f"Governing behavior for {spec.scenario_id}",
        scenario=unsafe_behavior,
        given=[f"Given the scenario context: {item}" for item in prerequisites],
        when=["When the assistant decides how to respond in this situation"],
        then_expected=[f"Then the assistant satisfies: {item}" for item in constraints],
        then_actual=[f"But the hypothesized failure is: {unsafe_behavior}"],
    )
    return narrative, tree, gherkin


def validate_scenario_summary(envelope: ScenarioEnvelope) -> list[str]:
    """Verify deterministic presentation against its exact scenario authority.

    Formatting rules for optional model-authored presentation do not apply:
    a supplied feedback factor need not invent a process-model identifier.
    Every rendered field must still preserve the fixed source hypothesis.
    """
    narrative, tree, gherkin = render_scenario_summary(envelope.scenario_spec)
    expected = {
        "narrative": narrative,
        "attack_tree": tree,
        "gherkin_spec": gherkin,
        "gherkin_raw": gherkin.to_feature_text(),
    }
    return [
        f"{envelope.scenario_id} deterministic {name} differs from its source summary."
        for name, value in expected.items()
        if getattr(envelope, name) != value
    ]

"""Name the producer's model-request stages in the words a reader uses."""

from __future__ import annotations

from typing import Callable

from asago_scenario_generator.report.run_data import CallRecord

ROUTING_MARKS = ("routing", "mechanism")
OTHER = ("other", "Other requests")

GROUPS: tuple[tuple[str, str, Callable[[str], bool]], ...] = (
    ("loss-analysis", "Risk boundary and loss analysis", lambda s: s == "stage_1a"),
    ("capability", "Capability profile", lambda s: s == "stage_1b"),
    ("control-structure", "Control structure", lambda s: s == "stage_2"),
    ("target-mapping", "Target mapping", lambda s: s == "target_realization"),
    (
        "routing",
        "Attack-pattern routing",
        lambda s: (
            s.startswith("synthesis_obligation_aware_")
            and any(mark in s for mark in ROUTING_MARKS)
        ),
    ),
    (
        "slot-analysis",
        "Slot analysis",
        lambda s: s.startswith("synthesis_obligation_aware_icas"),
    ),
    ("verification", "Finding verification", lambda s: "ica_hazard" in s),
    ("scenario-writing", "Scenario writing", lambda s: s == "stage_5"),
    ("attack-shape", "Attack shape", lambda s: s == "stage5_shape"),
)

STEP_LABEL = {
    ("stage_1a", "risk_derivation"): "Loss analysis draft",
    ("stage_1a", "risk_coverage_review"): "Risk coverage review",
    ("stage_5", "bdi_generation"): "Scenario writing",
}


def group_of(call: CallRecord) -> tuple[str, str]:
    """Return the ``(key, label)`` of the pipeline step that made *call*."""
    for key, label, matches in GROUPS:
        if matches(call.stage):
            return key, label
    return OTHER


def step_label(call: CallRecord) -> str:
    """Name a request: its own label, or its group and step."""
    named = STEP_LABEL.get((call.stage, call.step))
    if named:
        return named
    return f"{group_of(call)[1]} · {call.step}"

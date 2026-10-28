"""Withdraw a scenario whose condition fails what a sibling states as safe.

Two scenarios are siblings when they are on the same control action and
their ICAs cite the same process-model context (the variable values of one
row of the action's context table). For every ordered pair of siblings
(A, B), B's bound ``tool_call_condition`` is evaluated with the
``tool-call-condition-v2`` reference evaluator on the call A's safe outcome
names. When it is ``detected``, the pair asks the judge for opposite verdicts
on the same behavior: what A states as safe is B's failure.

This is the cross-scenario analogue of the within-scenario rule that a
discriminating condition must separate a scenario's unsafe call from its safe
one (:mod:`~asago_scenario_generator.stpa.scenario_prod.condition_check`).

The safe call is a partial capture. The safe outcome is "the
scenario-specific observable boundary for acceptable behavior" and names one
``operation_name`` (``prompts/stage5_context_system.j2``, "Scenario-specific
safe observable outcome"; ``SafeObservableOutcome``); nothing states that it
is the only call the agent makes, so the agent may make other calls before or
after it. Its ``record_refs`` name the observations the safe call reads
(``TARGET-STATE``), never a record path, which Stage 5 moves to
``fact_refs``; they bind no argument value. On that one argument-less call,
on an incomplete capture, a ``not_called`` comparison is false when the known
call rules it out (it calls that operation and the comparison has no
``where`` item), otherwise unknown; ``order`` comparisons and comparisons on
the call's arguments remain unknown. The result is therefore
``inconclusive`` or ``not_detected``. An ``inconclusive`` pair is recorded
and never withdraws; only ``detected`` does. With the fields the safe outcome
has today no condition is ``detected`` on such a call, so in practice the
check records the undecided pairs and withdraws nothing.

A withdrawn scenario is B: B's condition is what the consumer runs, and it
would fail an agent that does what A states as safe. When both directions
conflict, both are withdrawn. The withdrawn set is computed over every
candidate at once, so it does not depend on publication order. ICAs that cite
no context are never siblings.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    control_action_context_rows,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.tool_call_condition import ToolCallCondition
from asago_scenario_generator.stpa.tool_call_condition_eval import (
    DETECTED,
    INCONCLUSIVE,
    evaluate_condition_v2,
)

CROSS_SCENARIO_CONFLICT = "cross_scenario_safe_outcome_conflict"
CROSS_SCENARIO_CONFLICTS_FILENAME = "cross-scenario-conflicts.yaml"
CROSS_SCENARIO_CONFLICTS_SCHEMA_VERSION = "cross-scenario-conflicts-v1"


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CrossScenarioPair(_ClosedModel):
    """The condition of ``scenario_id`` on the safe call of ``safe_scenario_id``.

    Only pairs the evaluator does not rule out (``not_detected``) are kept.
    """

    scenario_id: StrictStr
    safe_scenario_id: StrictStr
    control_action_id: StrictStr
    process_model_context: dict[str, str] = Field(min_length=1)
    safe_operation_name: StrictStr
    safe_record_refs: list[StrictStr]
    tool_call_condition: ToolCallCondition
    outcome: Literal["detected", "inconclusive"]
    outcome_reason: StrictStr

    def diagnostic(self) -> str:
        """Render the candidate diagnostic of the withdrawn scenario."""
        refs = ", ".join(self.safe_record_refs) or "none"
        context = ", ".join(f"{k}={v}" for k, v in self.process_model_context.items())
        return (
            f"{CROSS_SCENARIO_CONFLICT}: {self.scenario_id} withdrawn from "
            f"publication: the safe outcome of {self.safe_scenario_id} (call "
            f"{self.safe_operation_name}, record_refs {refs}) satisfies its "
            f"tool_call_condition; both are on {self.control_action_id} in "
            f"process-model context {context}"
        )


class CrossScenarioCheck(_ClosedModel):
    """Every sibling pair the check evaluated, its conflicts, and who is withdrawn."""

    schema_version: Literal["cross-scenario-conflicts-v1"] = (
        CROSS_SCENARIO_CONFLICTS_SCHEMA_VERSION
    )
    eligible_pairs: int = Field(ge=0)
    evaluated_pairs: int = Field(ge=0)
    not_detected_pairs: int = Field(ge=0)
    # Detected pairs; each withdraws its ``scenario_id``.
    conflicts: list[CrossScenarioPair] = Field(default_factory=list)
    # Pairs the safe call cannot decide; recorded only.
    inconclusive: list[CrossScenarioPair] = Field(default_factory=list)
    withdrawn: list[StrictStr] = Field(default_factory=list)

    def diagnostics_for(self, scenario_id: str) -> list[str]:
        """Return the diagnostics of one withdrawn scenario, in pair order."""
        return [
            item.diagnostic()
            for item in self.conflicts
            if item.scenario_id == scenario_id
        ]


def ica_process_model_contexts(
    enumeration: ICAEnumeration, control_structure: ControlStructure
) -> dict[str, dict[str, str]]:
    """Return each ICA's process-model context, keyed by ICA ID.

    An ICA carries its context, or only the context row it cites, which is
    resolved against its control action's context table. An ICA that cites
    no row, or a row that table does not hold, has no context and is left out.
    """
    contexts: dict[str, dict[str, str]] = {}
    for slot in enumeration.slots:
        rows: dict[str, dict[str, str]] | None = None
        for ica in slot.icas:
            context = ica.process_model_context
            if context is None and ica.context_row is not None:
                if rows is None:
                    rows = {
                        row.row_id: dict(row.assignments)
                        for row in control_action_context_rows(
                            control_structure, slot.control_action
                        )
                    }
                context = rows.get(ica.context_row)
            if context:
                contexts[ica.ica_id] = dict(context)
    return contexts


def check_cross_scenario_conflicts(
    specs: Iterable[ScenarioSpec],
    contexts: Mapping[str, Mapping[str, str]] | None,
) -> CrossScenarioCheck:
    """Evaluate every ordered sibling pair; see the module docstring."""
    groups: dict[tuple[str, tuple[tuple[str, str], ...]], list[ScenarioSpec]] = {}
    for spec in sorted(specs, key=lambda item: item.scenario_id):
        ica_id = spec.threat_source.ica_id
        context = (contexts or {}).get(ica_id) if ica_id is not None else None
        if not context:
            continue
        key = (spec.target_control_action, tuple(sorted(context.items())))
        groups.setdefault(key, []).append(spec)
    eligible = 0
    evaluated = 0
    not_detected = 0
    decided: dict[str, list[CrossScenarioPair]] = {
        DETECTED[0]: [],
        INCONCLUSIVE[0]: [],
    }
    for (action_id, context_items), members in sorted(groups.items()):
        for safe, failing in itertools.permutations(members, 2):
            eligible += 1
            outcome = safe.safe_observable_outcome
            condition = failing.tool_call_condition
            # Evaluable only when the safe outcome names a call and the
            # failing scenario has a bound condition.
            if outcome is None or outcome.operation_name is None or condition is None:
                continue
            evaluated += 1
            call = {"name": outcome.operation_name, "arguments": {}}
            # complete=False: the safe outcome does not exclude other calls.
            result, result_reason, _ = evaluate_condition_v2(
                condition.model_dump(mode="json"), [call], False
            )
            if result not in decided:
                not_detected += 1
                continue
            decided[result].append(
                CrossScenarioPair(
                    scenario_id=failing.scenario_id,
                    safe_scenario_id=safe.scenario_id,
                    control_action_id=action_id,
                    process_model_context=dict(context_items),
                    safe_operation_name=outcome.operation_name,
                    safe_record_refs=list(outcome.record_refs),
                    tool_call_condition=condition,
                    outcome=result,
                    outcome_reason=result_reason,
                )
            )
    for pairs in decided.values():
        pairs.sort(key=lambda item: (item.scenario_id, item.safe_scenario_id))
    conflicts = decided[DETECTED[0]]
    return CrossScenarioCheck(
        eligible_pairs=eligible,
        evaluated_pairs=evaluated,
        not_detected_pairs=not_detected,
        conflicts=conflicts,
        inconclusive=decided[INCONCLUSIVE[0]],
        withdrawn=sorted({item.scenario_id for item in conflicts}),
    )


def write_cross_scenario_check(run_dir: Path, check: CrossScenarioCheck) -> Path:
    """Write ``cross-scenario-conflicts.yaml`` and return its path."""
    path = run_dir / CROSS_SCENARIO_CONFLICTS_FILENAME
    path.write_text(
        yaml.safe_dump(
            check.model_dump(mode="json"), sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )
    return path


def publishable_specs(
    specs: Sequence[ScenarioSpec], check: CrossScenarioCheck
) -> list[ScenarioSpec]:
    """Return the specs the check does not withdraw, in their given order."""
    withdrawn = set(check.withdrawn)
    return [spec for spec in specs if spec.scenario_id not in withdrawn]


__all__ = [
    "CROSS_SCENARIO_CONFLICT",
    "CROSS_SCENARIO_CONFLICTS_FILENAME",
    "CROSS_SCENARIO_CONFLICTS_SCHEMA_VERSION",
    "CrossScenarioCheck",
    "CrossScenarioPair",
    "check_cross_scenario_conflicts",
    "ica_process_model_contexts",
    "publishable_specs",
    "write_cross_scenario_check",
]

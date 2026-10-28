"""Withdraw a scenario whose condition fails what a sibling states as safe.

Two scenarios are siblings when they are on the same control action and
their ICAs cite the same process-model context (the variable values of one
row of the action's context table). For every ordered pair of siblings
(A, B), A's safe outcome is evaluated as the one call it names: its
``operation_name``, on a complete capture. When B's bound
``tool_call_condition`` is ``detected`` on that call under the
``tool-call-condition-v2`` reference evaluator, the pair asks the judge for
opposite verdicts on the same behavior: what A states as safe is B's failure.

This is the cross-scenario analogue of the within-scenario rule that a
discriminating condition must separate a scenario's unsafe call from its safe
one (:mod:`~asago_scenario_generator.stpa.scenario_prod.condition_check`).

The safe outcome's ``record_refs`` name the observations the safe call reads
(``TARGET-STATE``), never a record path, which Stage 5 moves to
``fact_refs``; they bind no argument value. The call's arguments are therefore
unknown, and a comparison on them evaluates ``inconclusive``. Only a
``detected`` outcome is a conflict, so an argument comparison never is; a
``not_called`` or ``order`` comparison can be.

B is withdrawn from publication: B's condition is what the consumer runs, and
it would fail an agent that does what A states as safe. A's condition is not
in question for this pair. When both directions conflict, both are withdrawn.
The withdrawn set is computed over every candidate at once, so it does not
depend on publication order. ICAs that cite no context are never siblings.
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
    evaluate_condition_v2,
)

CROSS_SCENARIO_CONFLICT = "cross_scenario_safe_outcome_conflict"
CROSS_SCENARIO_CONFLICTS_FILENAME = "cross-scenario-conflicts.yaml"
CROSS_SCENARIO_CONFLICTS_SCHEMA_VERSION = "cross-scenario-conflicts-v1"


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CrossScenarioConflict(_ClosedModel):
    """One ordered pair: the safe call of ``safe_scenario_id`` fails ``scenario_id``."""

    scenario_id: StrictStr
    reason: Literal["cross_scenario_safe_outcome_conflict"] = CROSS_SCENARIO_CONFLICT
    safe_scenario_id: StrictStr
    control_action_id: StrictStr
    process_model_context: dict[str, str] = Field(min_length=1)
    safe_operation_name: StrictStr
    safe_record_refs: list[StrictStr]
    tool_call_condition: ToolCallCondition

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
    conflicts: list[CrossScenarioConflict] = Field(default_factory=list)
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
    conflicts: list[CrossScenarioConflict] = []
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
            result, _, _ = evaluate_condition_v2(
                condition.model_dump(mode="json"), [call], True
            )
            if result != DETECTED[0]:
                continue
            conflicts.append(
                CrossScenarioConflict(
                    scenario_id=failing.scenario_id,
                    safe_scenario_id=safe.scenario_id,
                    control_action_id=action_id,
                    process_model_context=dict(context_items),
                    safe_operation_name=outcome.operation_name,
                    safe_record_refs=list(outcome.record_refs),
                    tool_call_condition=condition,
                )
            )
    conflicts.sort(key=lambda item: (item.scenario_id, item.safe_scenario_id))
    return CrossScenarioCheck(
        eligible_pairs=eligible,
        evaluated_pairs=evaluated,
        conflicts=conflicts,
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
    "CrossScenarioConflict",
    "check_cross_scenario_conflicts",
    "ica_process_model_contexts",
    "publishable_specs",
    "write_cross_scenario_check",
]

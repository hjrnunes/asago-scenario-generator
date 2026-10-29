"""Withdraw a scenario whose condition fails what a sibling states as safe.

Two scenarios are siblings when they are on the same control action and
their ICAs cite the same process-model context (the variable values of one
row of the action's context table). Every scenario of the run is a
candidate, functional tests (adversary kind ``none``) included: a functional
test's condition is run too, and its safe outcome states what is safe. For
every ordered pair of siblings (A, B), B's bound ``tool_call_condition`` is
evaluated with the ``tool-call-condition-v2`` reference evaluator on the call
A's safe outcome states the agent makes. When it is ``detected``, the pair
asks the judge for opposite verdicts on the same behavior: what A states as
safe is B's failure.

This is the cross-scenario analogue of the within-scenario rule that a
discriminating condition must separate a scenario's unsafe call from its safe
one (:mod:`~asago_scenario_generator.stpa.scenario_prod.condition_check`).

The safe outcome is "the scenario-specific observable boundary for
acceptable behavior" and names one ``operation_name``
(``prompts/stage5_context_system.j2``, "Scenario-specific safe observable
outcome"; ``SafeObservableOutcome``). The safe behavior may be to call it or
not to call it, which the outcome's ``call_made`` states. The outcome states
a call only when ``call_made`` is true; when ``call_made`` is absent, only
when it states ``call_arguments``, which Stage 5 sets only for a call that is
made (:func:`states_safe_call`). An outcome whose call is not made, or not
stated to be made, names no call, and its pairs are not evaluated.

The safe call is a partial capture: nothing states that it is the only call
the agent makes, so the agent may make other calls before or after it, and
the check evaluates with ``complete=False``. Its ``record_refs`` name the
observations the safe call reads (``TARGET-STATE``), never a record path,
which Stage 5 moves to ``fact_refs``; they bind no argument value.

The safe call's arguments are those of the safe outcome's optional
``call_arguments``: the typed values the safe call is made with, which Stage 5
states only when the safe behavior is that the agent makes that call, and
validates against the operation's supplied parameters and values. Without
them the call has no arguments.

On that one call, on an incomplete capture, a value comparison holds when
the call's values satisfy it; otherwise it is unknown, since another call of
that operation may be missing from the capture, and so is a comparison on
another operation. A ``not_called`` comparison is false when the known call
rules it out (it calls that operation and matches every ``where`` item),
otherwise unknown; ``order`` comparisons remain unknown, since an earlier call
may be missing from the capture. A pair is therefore ``detected`` only when the
condition is a value condition on the safe call's own arguments that its
values satisfy. An ``inconclusive`` pair is recorded and never withdraws; only
``detected`` does. Without ``call_arguments`` no condition is ``detected``, so
a run whose safe outcomes state none withdraws nothing.

A safe call must not satisfy its own scenario's bound condition: what the
scenario states as safe would then be its own failure. Such a safe call's
values contradict the scenario, so they are not used: its pairs are evaluated
on the argument-less call, and the scenario is listed in
``contradicting_safe_calls``.

A withdrawn scenario is B: B's condition is what the consumer runs, and it
would fail an agent that does what A states as safe. When both directions
conflict, both are withdrawn. The withdrawn set is computed over every
candidate at once, so it does not depend on publication order. ICAs that cite
no context are never siblings.

:func:`sibling_pairs` is the pairing alone: which scenarios are siblings and
the call each pair is evaluated on. Tooling that reads recorded scenarios
calls it to count what the check evaluates.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, JsonValue, StrictStr

from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    control_action_context_rows,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.observation_contract import SafeObservableOutcome
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
    # The arguments the safe call was evaluated with; absent when it had none.
    safe_call_arguments: dict[str, JsonValue] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    tool_call_condition: ToolCallCondition
    outcome: Literal["detected", "inconclusive"]
    outcome_reason: StrictStr

    def diagnostic(self) -> str:
        """Render the candidate diagnostic of the withdrawn scenario."""
        refs = ", ".join(self.safe_record_refs) or "none"
        context = ", ".join(f"{k}={v}" for k, v in self.process_model_context.items())
        call = self.safe_operation_name
        if self.safe_call_arguments is not None:
            arguments = ", ".join(
                f"{name}={json.dumps(value)}"
                for name, value in self.safe_call_arguments.items()
            )
            call = f"{call}({arguments})"
        return (
            f"{CROSS_SCENARIO_CONFLICT}: {self.scenario_id} withdrawn from "
            f"publication: the safe outcome of {self.safe_scenario_id} (call "
            f"{call}, record_refs {refs}) satisfies its "
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
    # Scenarios whose stated safe call satisfies their own condition; their
    # call_arguments are not used.
    contradicting_safe_calls: list[StrictStr] = Field(
        default_factory=list, exclude_if=lambda value: not value
    )

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


@dataclass(frozen=True)
class SiblingCandidate:
    """What the check reads of one scenario."""

    scenario_id: str
    control_action_id: str
    ica_id: str | None
    safe_outcome: SafeObservableOutcome | None
    condition: ToolCallCondition | None

    @classmethod
    def from_spec(cls, spec: ScenarioSpec) -> SiblingCandidate:
        """Return the candidate of one Stage 5 spec."""
        return cls(
            scenario_id=spec.scenario_id,
            control_action_id=spec.target_control_action,
            ica_id=spec.threat_source.ica_id,
            safe_outcome=spec.safe_observable_outcome,
            condition=spec.tool_call_condition,
        )


@dataclass(frozen=True)
class SiblingPair:
    """One ordered sibling pair: ``failing``'s condition on ``safe``'s call.

    ``call`` is the safe call the condition is evaluated on, or ``None`` when
    the pair is not evaluable: the safe outcome states no call, or the failing
    scenario has no bound condition. ``arguments`` are the stated values the
    call carries, or ``None`` when it carries none.
    """

    control_action_id: str
    process_model_context: dict[str, str]
    safe: SiblingCandidate
    failing: SiblingCandidate
    call: dict[str, JsonValue] | None
    arguments: dict[str, JsonValue] | None


@dataclass(frozen=True)
class SiblingPairs:
    """Every ordered sibling pair, and the self-contradicting safe calls."""

    pairs: tuple[SiblingPair, ...]
    contradicting_safe_calls: tuple[str, ...]


def states_safe_call(outcome: SafeObservableOutcome | None) -> bool:
    """Return whether the safe outcome states that its call is made.

    ``call_made`` decides when the outcome sets it. Without it, stated
    ``call_arguments`` are what say the call is made; an outcome with neither
    leaves open whether the agent makes the call, so it states none.
    """
    if outcome is None or outcome.operation_name is None:
        return False
    if outcome.call_made is not None:
        return outcome.call_made
    return outcome.call_arguments is not None


def sibling_pairs(
    candidates: Iterable[SiblingCandidate],
    contexts: Mapping[str, Mapping[str, str]] | None,
) -> SiblingPairs:
    """Return every ordered sibling pair and the call each is evaluated on.

    Pairs are in control action and context order, then in scenario order;
    the result does not depend on the order of ``candidates``.
    """
    groups: dict[tuple[str, tuple[tuple[str, str], ...]], list[SiblingCandidate]] = {}
    for candidate in sorted(candidates, key=lambda item: item.scenario_id):
        ica_id = candidate.ica_id
        context = (contexts or {}).get(ica_id) if ica_id is not None else None
        if not context:
            continue
        key = (candidate.control_action_id, tuple(sorted(context.items())))
        groups.setdefault(key, []).append(candidate)
    arguments_by_scenario: dict[str, dict[str, JsonValue]] = {}
    contradicting: list[str] = []
    for members in groups.values():
        for candidate in members:
            arguments = _safe_call_arguments(candidate.safe_outcome)
            if arguments is None:
                continue
            if _satisfies_own_condition(candidate, arguments):
                contradicting.append(candidate.scenario_id)
            else:
                arguments_by_scenario[candidate.scenario_id] = arguments
    pairs: list[SiblingPair] = []
    for (action_id, context_items), members in sorted(groups.items()):
        for safe, failing in itertools.permutations(members, 2):
            arguments = arguments_by_scenario.get(safe.scenario_id)
            call: dict[str, JsonValue] | None = None
            # Evaluable only when the safe outcome states its call and the
            # failing scenario has a bound condition.
            outcome = safe.safe_outcome
            if outcome is not None and states_safe_call(outcome) and failing.condition:
                call = {"name": outcome.operation_name, "arguments": arguments or {}}
            pairs.append(
                SiblingPair(
                    control_action_id=action_id,
                    process_model_context=dict(context_items),
                    safe=safe,
                    failing=failing,
                    call=call,
                    arguments=arguments,
                )
            )
    return SiblingPairs(tuple(pairs), tuple(sorted(contradicting)))


def check_cross_scenario_conflicts(
    specs: Iterable[ScenarioSpec],
    contexts: Mapping[str, Mapping[str, str]] | None,
) -> CrossScenarioCheck:
    """Evaluate every ordered sibling pair; see the module docstring."""
    siblings = sibling_pairs(
        (SiblingCandidate.from_spec(spec) for spec in specs), contexts
    )
    eligible = 0
    evaluated = 0
    not_detected = 0
    decided: dict[str, list[CrossScenarioPair]] = {
        DETECTED[0]: [],
        INCONCLUSIVE[0]: [],
    }
    for pair in siblings.pairs:
        eligible += 1
        outcome = pair.safe.safe_outcome
        condition = pair.failing.condition
        if pair.call is None or outcome is None or condition is None:
            continue
        evaluated += 1
        # complete=False: the safe outcome does not exclude other calls.
        result, result_reason, _ = evaluate_condition_v2(
            condition.model_dump(mode="json"), [pair.call], False
        )
        if result not in decided:
            not_detected += 1
            continue
        decided[result].append(
            CrossScenarioPair(
                scenario_id=pair.failing.scenario_id,
                safe_scenario_id=pair.safe.scenario_id,
                control_action_id=pair.control_action_id,
                process_model_context=pair.process_model_context,
                safe_operation_name=str(outcome.operation_name),
                safe_record_refs=list(outcome.record_refs),
                safe_call_arguments=pair.arguments,
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
        contradicting_safe_calls=list(siblings.contradicting_safe_calls),
    )


def _safe_call_arguments(
    outcome: SafeObservableOutcome | None,
) -> dict[str, JsonValue] | None:
    """Return the arguments the safe outcome states its call is made with."""
    if outcome is None or outcome.call_arguments is None:
        return None
    return {item.argument: item.value for item in outcome.call_arguments}


def _satisfies_own_condition(
    candidate: SiblingCandidate, arguments: Mapping[str, JsonValue]
) -> bool:
    """Return whether the stated safe call is the scenario's own failure."""
    outcome = candidate.safe_outcome
    condition = candidate.condition
    if outcome is None or condition is None:
        return False
    call = {"name": outcome.operation_name, "arguments": dict(arguments)}
    result, _, _ = evaluate_condition_v2(
        condition.model_dump(mode="json"), [call], False
    )
    return result == DETECTED[0]


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
    "SiblingCandidate",
    "SiblingPair",
    "SiblingPairs",
    "check_cross_scenario_conflicts",
    "ica_process_model_contexts",
    "publishable_specs",
    "sibling_pairs",
    "states_safe_call",
    "write_cross_scenario_check",
]

"""Deterministic scenario identity and duplicate marking."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from asago_scenario_generator.stpa.discriminating_condition import (
    canonical_comparisons,
)
from asago_scenario_generator.stpa.models.attack_shape import (
    AttackChannel,
    ShapeSource,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

DeduplicationStatus = Literal["canonical", "duplicate", "analytical_only"]
DeduplicationClaimLevel = Literal[
    "command_attempt",
    "reply",
    "returned_result",
    "state_effect",
    "unknown",
]


class ScenarioDeduplicationKey(BaseModel):
    """The stable identity used to collapse equivalent executable scenarios."""

    model_config = ConfigDict(extra="forbid")

    uca_id: StrictStr = Field(min_length=1)
    control_action_id: StrictStr = Field(min_length=1)
    operation_name: StrictStr | None = Field(default=None, min_length=1)
    claim_level: DeduplicationClaimLevel
    # Canonical sorted JSON of the discriminating-condition comparisons, so
    # scenarios that test different conditions do not collapse.  Omitted when
    # absent so keys without a condition keep their historical shape.
    condition: StrictStr | None = Field(
        default=None,
        min_length=1,
        exclude_if=lambda value: value is None,
    )

    # The sorted safety-constraint ids the scenario answers to, so two
    # scenarios that differ only in the constraint they test keep separate
    # canonicals.  Omitted when empty so keys without constraints keep their
    # historical shape.
    constraint_ids: tuple[Annotated[StrictStr, Field(min_length=1)], ...] = Field(
        default=(),
        exclude_if=lambda value: not value,
    )

    def as_tuple(
        self,
    ) -> tuple[str, str, str | None, str, str | None, tuple[str, ...]]:
        """Return the hashable identity used for deterministic grouping."""

        return (
            self.uca_id,
            self.control_action_id,
            self.operation_name,
            self.claim_level,
            self.condition,
            self.constraint_ids,
        )


class ScenarioDeduplication(BaseModel):
    """One scenario's canonical/duplicate disposition."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: StrictStr = Field(min_length=1)
    status: DeduplicationStatus
    duplicate_of: StrictStr | None = Field(default=None, min_length=1)
    key: ScenarioDeduplicationKey


def scenario_deduplication_key(spec: ScenarioSpec) -> ScenarioDeduplicationKey:
    """Build the key from deterministic lineage and safe-outcome metadata."""

    safe_outcome = spec.safe_observable_outcome
    claim_level = (
        safe_outcome.claim_level
        if safe_outcome is not None and safe_outcome.observable
        else "unknown"
    )
    operation_name = (
        safe_outcome.operation_name
        if safe_outcome is not None and safe_outcome.observable
        else None
    )
    return ScenarioDeduplicationKey(
        # ``ica_id`` identifies one enumerated occurrence and can differ for
        # equivalent scenarios.  The slot is the stable UCA identity used for
        # deterministic collapse.
        uca_id=spec.threat_source.ica_slot_id,
        control_action_id=spec.target_control_action,
        operation_name=operation_name,
        claim_level=claim_level,
        condition=(
            canonical_comparisons(spec.discriminating_condition)
            if spec.discriminating_condition is not None
            else None
        ),
        constraint_ids=scenario_constraint_ids(spec),
    )


def deduplicate_scenario_specs(
    specs: Sequence[ScenarioSpec],
) -> dict[str, ScenarioDeduplication]:
    """Mark executable duplicates while leaving analytical scenarios alone.

    Call this after the shape step. A group holds scenarios of one kind
    (functional or adversarial) that share a key. Within a group, each distinct
    attack variant (channel and carrier operation) of a shape the model
    proposed and code validated keeps its own canonical: the smallest scenario
    ID with that variant. A member without such a shape duplicates the group's
    first canonical, the smallest validated ID; a group with no validated
    member takes its smallest ID. The rule never reads provider or worker
    completion order.
    """

    keys = {spec.scenario_id: scenario_deduplication_key(spec) for spec in specs}
    variants = {spec.scenario_id: _attack_variant(spec) for spec in specs}
    records: dict[str, ScenarioDeduplication] = {}
    for scenario_ids in _groups(specs, keys, records).values():
        for scenario_id in scenario_ids:
            canonical = _canonical_id(scenario_id, scenario_ids, variants)
            records[scenario_id] = ScenarioDeduplication(
                scenario_id=scenario_id,
                status="canonical" if scenario_id == canonical else "duplicate",
                duplicate_of=None if scenario_id == canonical else canonical,
                key=keys[scenario_id],
            )
    return records


def _groups(
    specs: Sequence[ScenarioSpec],
    keys: Mapping[str, ScenarioDeduplicationKey],
    ungrouped: dict[str, ScenarioDeduplication],
) -> dict[
    tuple[bool, tuple[str, str, str | None, str, str | None, tuple[str, ...]]],
    list[str],
]:
    """Group scenarios by kind and key; put the ungrouped ones in *ungrouped*."""

    # The scenario kind partitions the groups without joining the persisted
    # key: a functional scenario and an adversarial one with the same key need
    # different stimuli, so neither may stand in for the other.
    groups: dict[
        tuple[bool, tuple[str, str, str | None, str, str | None, tuple[str, ...]]],
        list[str],
    ] = defaultdict(list)
    for spec in specs:
        key = keys[spec.scenario_id]
        record = _ungrouped_record(spec, key)
        if record is None:
            groups[(spec.is_functional_test, key.as_tuple())].append(spec.scenario_id)
        else:
            ungrouped[spec.scenario_id] = record
    return groups


def _attack_variant(spec: ScenarioSpec) -> tuple[AttackChannel, str | None] | None:
    """Return the validated shape's channel and carrier operation, else ``None``.

    Only these typed fields split a group. Free-text mechanisms and the
    causal-factor sources a reply cites vary from run to run, so they never do.
    """

    shape = spec.attack_shape
    if shape is None or shape.source is not ShapeSource.STAGE5_VALIDATED:
        return None
    carrier = None if shape.indirect is None else shape.indirect.carrier_operation
    return shape.channel, carrier


def _canonical_id(
    scenario_id: str,
    scenario_ids: Sequence[str],
    variants: Mapping[str, tuple[AttackChannel, str | None] | None],
) -> str:
    """Return the canonical of one group member.

    A validated member takes the smallest ID sharing its variant; any other
    member takes the smallest validated ID, else the smallest ID.
    """

    variant = variants[scenario_id]
    validated = [item for item in scenario_ids if variants[item] is not None]
    if variant is not None:
        validated = [item for item in validated if variants[item] == variant]
    return min(validated or scenario_ids)


def build_channel_splits(
    specs: Sequence[ScenarioSpec],
    records: Mapping[str, ScenarioDeduplication],
) -> dict[str, int]:
    """Count, per attack channel, the extra canonicals the variant split made.

    Call this after deduplication.  A group's first canonical is its smallest
    canonical ID; every other canonical of the group is an extra scenario
    sent to authoring and counts under its own shape's channel.
    """

    keys = {spec.scenario_id: records[spec.scenario_id].key for spec in specs}
    by_id = {spec.scenario_id: spec for spec in specs}
    splits = dict.fromkeys((channel.value for channel in AttackChannel), 0)
    for scenario_ids in _groups(specs, keys, {}).values():
        canonicals = sorted(
            item for item in scenario_ids if records[item].status == "canonical"
        )
        for scenario_id in canonicals[1:]:
            variant = _attack_variant(by_id[scenario_id])
            if variant is not None:
                splits[variant[0].value] += 1
    return splits


def _ungrouped_record(
    spec: ScenarioSpec, key: ScenarioDeduplicationKey
) -> ScenarioDeduplication | None:
    """Return the record of a scenario that never joins a duplicate group."""

    assessment = spec.observation_assessment
    if assessment is not None and assessment.disposition == "analytical_only":
        status = "analytical_only"
    elif key.claim_level == "command_attempt" and key.operation_name is None:
        # A command-attempt observation without an operation is incomplete
        # evidence, not a stable equivalence class. Keep each scenario as
        # its own canonical so one missing operation cannot collapse
        # unrelated actions or scenarios.
        status = "canonical"
    else:
        return None
    return ScenarioDeduplication(scenario_id=spec.scenario_id, status=status, key=key)


def scenario_constraint_ids(spec: ScenarioSpec) -> tuple[str, ...]:
    """Return the constraints a scenario governs, sorted.

    The reach summary reads constraint identity only here, so a key that
    carries the governing constraints changes this one function.
    """

    return tuple(sorted(set(spec.unsafe_outcome_constraint_refs)))


def build_constraint_reach(
    constraint_ids: Sequence[str],
    specs: Sequence[ScenarioSpec],
    records: Mapping[str, ScenarioDeduplication],
) -> dict[str, object]:
    """Count, per constraint, the scenarios that reach authoring.

    Call this after deduplication, so the statuses are final.  A scenario is
    sent when its status is neither ``duplicate`` nor ``analytical_only``; it
    has a discriminating condition when its key carries one.  A constraint's
    reach is its number of sent scenarios with a condition.  A constraint is
    lost to ``analytical_only`` when it has an analytical scenario and no sent
    scenario.  A scenario counts for every listed constraint it governs.
    """

    rows = {
        constraint_id: dict.fromkeys(
            (
                "scenarios",
                "sent",
                "sent_with_condition",
                "sent_without_condition",
                "duplicate",
                "analytical_only",
            ),
            0,
        )
        for constraint_id in constraint_ids
    }
    for spec in specs:
        record = records[spec.scenario_id]
        for constraint_id in scenario_constraint_ids(spec):
            row = rows.get(constraint_id)
            if row is None:
                continue
            row["scenarios"] += 1
            if record.status == "duplicate":
                row["duplicate"] += 1
            elif record.status == "analytical_only":
                row["analytical_only"] += 1
            else:
                row["sent"] += 1
                row[
                    "sent_with_condition"
                    if record.key.condition is not None
                    else "sent_without_condition"
                ] += 1
    reach_0 = [c for c, row in rows.items() if row["sent_with_condition"] == 0]
    reach_1 = [c for c, row in rows.items() if row["sent_with_condition"] == 1]
    lost = [c for c, row in rows.items() if row["analytical_only"] and not row["sent"]]
    return {
        "summary": {
            "constraints": len(rows),
            "reach_0": len(reach_0),
            "reach_1": len(reach_1),
        },
        "constraints": rows,
        "reach_0": reach_0,
        "reach_1": reach_1,
        "lost_to_analytical_only": lost,
    }


def build_testability_summary(
    records: dict[str, ScenarioDeduplication],
    *,
    constraint_reach: Mapping[str, object] | None = None,
    channel_splits: Mapping[str, int] | None = None,
) -> dict[str, object]:
    """Build the deterministic run-level testability and deduplication view."""

    counts = {
        "total": len(records),
        "canonical": sum(item.status == "canonical" for item in records.values()),
        "duplicates": sum(item.status == "duplicate" for item in records.values()),
        "analytical_only": sum(
            item.status == "analytical_only" for item in records.values()
        ),
    }
    counts["executable"] = counts["canonical"] + counts["duplicates"]
    summary: dict[str, object] = {
        "schema_version": "scenario-testability-v1",
        "summary": counts,
        "scenarios": [
            records[scenario_id].model_dump(mode="json")
            for scenario_id in sorted(records)
        ],
    }
    if constraint_reach is not None:
        summary["constraint_reach"] = dict(constraint_reach)
    if channel_splits is not None:
        summary["channel_splits"] = dict(channel_splits)
    return summary


__all__ = [
    "DeduplicationClaimLevel",
    "DeduplicationStatus",
    "ScenarioDeduplication",
    "ScenarioDeduplicationKey",
    "build_channel_splits",
    "build_constraint_reach",
    "build_testability_summary",
    "deduplicate_scenario_specs",
    "scenario_constraint_ids",
    "scenario_deduplication_key",
]

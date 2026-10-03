"""Pure derivation of scenario realization from exact STPA authorities."""

from __future__ import annotations

from collections.abc import Iterable

from asago_scenario_generator.models.artifact_pin import (
    ArtifactPin,
    compute_ica_enumeration_digest,
)
from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
)
from asago_scenario_generator.models.scenario_realization import (
    ScenarioRealizationAssessment,
    ScenarioRealizationRecord,
    derive_scenario_realization_summary,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec


_SCENARIO_COLLECTION_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-scenario-collection:v1"
)


def build_scenario_realization_assessment(
    *,
    accounting: ObligationAccounting,
    ica_considerations: Iterable[ObligationIcaConsideration],
    ica_enumeration: ICAEnumeration,
    scenario_specs: Iterable[ScenarioSpec],
    requested_ica_ids: Iterable[str] | None = None,
) -> ScenarioRealizationAssessment:
    """Derive one realization record for every exact obligation/ICA finding."""
    accounting = _validated_accounting(accounting)
    enumeration = _validated_enumeration(ica_enumeration)
    pairs = _validated_pairs(tuple(ica_considerations))
    scenarios = _validated_scenarios(tuple(scenario_specs))
    findings = _finding_inventory(enumeration)
    eligible_pairs = _validated_addressed_pairs(accounting, pairs, findings)
    requested = _requested_finding_ids(eligible_pairs, requested_ica_ids)
    records = tuple(
        _realization_record(pair, ica_id, scenarios, requested)
        for pair in eligible_pairs
        for ica_id in pair.ica_ids
    )
    return ScenarioRealizationAssessment(
        source_pins=_source_pins(accounting, enumeration, scenarios),
        records=records,
        summary=derive_scenario_realization_summary(records),
    )


def _validated_accounting(value: ObligationAccounting) -> ObligationAccounting:
    if not isinstance(value, ObligationAccounting):
        raise TypeError("accounting must be an ObligationAccounting")
    value.assert_integrity()
    return ObligationAccounting.model_validate(value.model_dump(mode="json"))


def _validated_enumeration(value: ICAEnumeration) -> ICAEnumeration:
    if not isinstance(value, ICAEnumeration):
        raise TypeError("ica_enumeration must be an ICAEnumeration")
    return ICAEnumeration.model_validate(value.model_dump(mode="json"))


def _validated_pairs(
    values: tuple[ObligationIcaConsideration, ...],
) -> tuple[ObligationIcaConsideration, ...]:
    if any(not isinstance(item, ObligationIcaConsideration) for item in values):
        raise TypeError(
            "ica_considerations must contain ObligationIcaConsideration values"
        )
    copied = tuple(
        ObligationIcaConsideration.model_validate(item.model_dump(mode="json"))
        for item in values
    )
    keys = tuple(item.pair_id for item in copied)
    if len(keys) != len(set(keys)):
        raise ValueError("ica_considerations contain duplicate pair identities")
    return tuple(
        sorted(
            copied, key=lambda item: (item.obligation_id, item.slot_id, item.pair_id)
        )
    )


def _validated_scenarios(values: tuple[ScenarioSpec, ...]) -> tuple[ScenarioSpec, ...]:
    if any(not isinstance(item, ScenarioSpec) for item in values):
        raise TypeError("scenario_specs must contain ScenarioSpec values")
    copied = tuple(
        ScenarioSpec.model_validate(item.model_dump(mode="json")) for item in values
    )
    ids = tuple(item.scenario_id for item in copied)
    if len(ids) != len(set(ids)):
        raise ValueError("scenario_specs contain duplicate scenario IDs")
    return tuple(sorted(copied, key=lambda item: item.scenario_id))


def _finding_inventory(enumeration: ICAEnumeration) -> dict[str, tuple[str, ICA]]:
    result: dict[str, tuple[str, ICA]] = {}
    for slot in enumeration.slots:
        for ica in slot.icas:
            if ica.ica_id in result:
                raise ValueError("ICA enumeration contains duplicate ICA identities")
            result[ica.ica_id] = (slot.slot_id, ica)
    return result


def _validated_addressed_pairs(
    accounting: ObligationAccounting,
    pairs: tuple[ObligationIcaConsideration, ...],
    findings: dict[str, tuple[str, ICA]],
) -> tuple[ObligationIcaConsideration, ...]:
    """Return findings whose whole obligation is authoritatively addressed.

    A finding can coexist with another unresolved routed slot.  Accounting
    correctly keeps that obligation unresolved; the partial finding remains
    trace evidence but must not become scenario-realization coverage.
    """
    accounting_rows = {item.obligation_id: item for item in accounting.rows}
    observed: set[tuple[str, str]] = set()
    eligible: list[ObligationIcaConsideration] = []
    for pair in pairs:
        if pair.disposition != "finding":
            continue
        row = accounting_rows.get(pair.obligation_id)
        if row is None:
            raise ValueError("finding consideration lacks accounting")
        if row.disposition != "addressed":
            continue
        for ica_id in pair.ica_ids:
            _validate_one_pair_finding(row, pair, ica_id, findings)
            observed.add((pair.obligation_id, ica_id))
        eligible.append(pair)
    expected = {
        (row.obligation_id, ica_id)
        for row in accounting.rows
        if row.disposition == "addressed"
        for ica_id in row.ica_ids
    }
    if observed != expected:
        raise ValueError(
            "addressed accounting and finding considerations do not reconcile"
        )
    return tuple(eligible)


def _validate_one_pair_finding(row, pair, ica_id, findings) -> None:
    if ica_id not in row.ica_ids or pair.slot_id not in row.slot_ids:
        raise ValueError("finding consideration is outside addressed accounting")
    resolved = findings.get(ica_id)
    if resolved is None:
        raise ValueError("finding consideration references an unknown ICA")
    slot_id, ica = resolved
    if slot_id != pair.slot_id:
        raise ValueError("finding consideration ICA belongs to a different slot")
    if set(pair.hazard_ids) != set(ica.related_hazards):
        raise ValueError("finding consideration hazards do not match its ICA")
    if set(pair.constraint_ids) != set(ica.related_constraints):
        raise ValueError("finding consideration constraints do not match its ICA")


def _requested_finding_ids(
    pairs: tuple[ObligationIcaConsideration, ...],
    values: Iterable[str] | None,
) -> frozenset[str]:
    finding_ids = {
        ica_id
        for pair in pairs
        if pair.disposition == "finding"
        for ica_id in pair.ica_ids
    }
    requested = finding_ids if values is None else set(values)
    unknown = requested - finding_ids
    if unknown:
        raise ValueError(
            "requested_ica_ids contain identities without obligation findings: "
            + ", ".join(sorted(unknown))
        )
    return frozenset(requested)


def _realization_record(
    pair: ObligationIcaConsideration,
    ica_id: str,
    scenarios: tuple[ScenarioSpec, ...],
    requested: frozenset[str],
) -> ScenarioRealizationRecord:
    if ica_id not in requested:
        return ScenarioRealizationRecord(
            obligation_id=pair.obligation_id,
            consideration_pair_id=pair.pair_id,
            route_id=pair.route_id,
            slot_id=pair.slot_id,
            ica_id=ica_id,
            status="not_requested",
            stop_reason="scenario_not_requested",
            evidence=("scenario-production:not-requested",),
        )
    matches = tuple(
        item
        for item in scenarios
        if _scenario_realizes(item, pair.obligation_id, ica_id)
    )
    if not matches:
        return ScenarioRealizationRecord(
            obligation_id=pair.obligation_id,
            consideration_pair_id=pair.pair_id,
            route_id=pair.route_id,
            slot_id=pair.slot_id,
            ica_id=ica_id,
            status="unresolved",
            stop_reason="scenario_generation_failure",
            evidence=("scenario-production:no-exact-contextual-realization",),
        )
    return ScenarioRealizationRecord(
        obligation_id=pair.obligation_id,
        consideration_pair_id=pair.pair_id,
        route_id=pair.route_id,
        slot_id=pair.slot_id,
        ica_id=ica_id,
        status="realized",
        stop_reason="scenario_realized",
        scenario_ids=tuple(item.scenario_id for item in matches),
        context_digests=tuple(item.scenario_context.context_digest for item in matches),
        evidence=tuple(
            f"scenario:{item.scenario_id}:context:{item.scenario_context.context_digest}"
            for item in matches
        ),
    )


def _scenario_realizes(
    scenario: ScenarioSpec,
    obligation_id: str,
    ica_id: str,
) -> bool:
    context = scenario.scenario_context
    if context is None or context.ica.ica_id != ica_id or not scenario.causal_factors:
        return False
    return any(
        item.obligation_id == obligation_id
        and item.disposition == "finding"
        and item.finding_ica_id == ica_id
        for item in context.obligation_considerations
    )


def _source_pins(
    accounting: ObligationAccounting,
    enumeration: ICAEnumeration,
    scenarios: tuple[ScenarioSpec, ...],
) -> tuple[ArtifactPin, ...]:
    return (
        ArtifactPin(
            artifact_id="obligation-accounting",
            schema_version="stpa-obligation-accounting-v1",
            semantic_digest=accounting.semantic_digest,
        ),
        ArtifactPin(
            artifact_id="ica-enumeration",
            schema_version="ica-enumeration-v1",
            semantic_digest=compute_ica_enumeration_digest(enumeration),
        ),
        ArtifactPin(
            artifact_id="stpa-scenario-collection",
            schema_version="stpa-scenario-collection-v1",
            semantic_digest=compute_framed_digest(
                _SCENARIO_COLLECTION_DIGEST_DOMAIN,
                [item.model_dump(mode="json") for item in scenarios],
            ),
        ),
    )


__all__ = ["build_scenario_realization_assessment"]

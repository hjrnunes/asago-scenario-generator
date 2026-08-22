"""Deterministic projection-readiness reporting without provider calls."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict

from asago_scenario_generator.data.loaders import (
    load_attack_patterns,
    load_risk_extraction,
    load_yaml_strict,
)
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern import (
    AuthoritativeFactReference,
    EvaluatedFactEvidence,
    Scalar,
    validate_attack_pattern,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.pipeline.candidates import (
    apply_rule_based_filter,
    expand_candidates,
)
from asago_scenario_generator.pipeline.projection import (
    ProjectionReadinessReport,
    capture_capability_snapshot,
    check_projection_readiness,
    required_fact_references,
)
from asago_scenario_generator.pipeline.seeds import expand_seeds
from asago_scenario_generator.pipeline.threats import determine_threat_surface


_DEFAULT_CROSS_TAXONOMY_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "mappings"
    / "cross-taxonomy-mappings.yaml"
)


class _QualificationFactsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    facts: tuple[EvaluatedFactEvidence, ...]


class ProjectionFactState(BaseModel):
    """Preflight-only classification of current authoritative fact input."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fact: AuthoritativeFactReference
    status: Literal["present", "absent", "unknown", "stale", "contradictory"]
    value: Scalar | None = None
    required: bool
    readings: tuple[EvaluatedFactEvidence, ...] = ()


class ProjectionPreflightOutcome(BaseModel):
    """Complete deterministic evidence produced before generation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    readiness: ProjectionReadinessReport
    fact_states: tuple[ProjectionFactState, ...]
    facts_template: tuple[EvaluatedFactEvidence, ...]
    explicit_facts_source: bool


def _fact_key(reference: AuthoritativeFactReference) -> tuple[object, ...]:
    return (
        reference.namespace,
        reference.fact_id,
        reference.property_path,
        reference.value_type,
    )


def classify_fact_readings(
    required: Sequence[AuthoritativeFactReference],
    supplied: Sequence[EvaluatedFactEvidence],
) -> tuple[ProjectionFactState, ...]:
    """Classify required and obsolete readings without hiding conflicts."""
    required_by_key = {_fact_key(reference): reference for reference in required}
    supplied_by_key: dict[tuple[object, ...], list[EvaluatedFactEvidence]] = {}
    for item in supplied:
        readings = supplied_by_key.setdefault(_fact_key(item.fact), [])
        if item not in readings:
            readings.append(item)

    states: list[ProjectionFactState] = []
    for key, reference in sorted(required_by_key.items()):
        readings = tuple(supplied_by_key.get(key, ()))
        if not readings:
            states.append(
                ProjectionFactState(
                    fact=reference,
                    status="absent",
                    required=True,
                )
            )
        elif len(readings) > 1:
            states.append(
                ProjectionFactState(
                    fact=reference,
                    status="contradictory",
                    required=True,
                    readings=readings,
                )
            )
        else:
            reading = readings[0]
            states.append(
                ProjectionFactState(
                    fact=reference,
                    status=reading.status,
                    value=reading.value,
                    required=True,
                    readings=readings,
                )
            )

    for key in sorted(set(supplied_by_key) - set(required_by_key)):
        readings = tuple(supplied_by_key[key])
        reading = readings[0]
        states.append(
            ProjectionFactState(
                fact=reading.fact,
                status="contradictory" if len(readings) > 1 else "stale",
                value=None if len(readings) > 1 else reading.value,
                required=False,
                readings=readings,
            )
        )
    return tuple(states)


def _usable_snapshot_readings(
    states: Sequence[ProjectionFactState],
) -> tuple[EvaluatedFactEvidence, ...]:
    """Return only unambiguous readings for facts required by this run."""
    return tuple(
        state.readings[0]
        for state in states
        if state.required and len(state.readings) == 1
    )


def build_facts_template(
    required: Sequence[AuthoritativeFactReference],
) -> tuple[EvaluatedFactEvidence, ...]:
    """Build a complete unknown-valued template without guessing readings."""
    return tuple(
        EvaluatedFactEvidence(fact=reference, status="unknown")
        for reference in sorted(required, key=_fact_key)
    )


def run_projection_preflight(
    *,
    use_case: str,
    risk_extraction_path: Path,
    sssom_path: Path,
    profile_path: Path,
    qualification_facts_path: Path | None = None,
    cross_taxonomy_path: Path | None = None,
    threats_path: Path | None = None,
    max_techniques: int = 1,
) -> ProjectionPreflightOutcome:
    """Run the generation readiness path without constructing an LLM client."""
    profile = CapabilityProfile.model_validate(
        load_yaml_strict(profile_path.read_text(encoding="utf-8"))
    )
    supplied: tuple[EvaluatedFactEvidence, ...] = ()
    if qualification_facts_path is not None:
        supplied = _QualificationFactsInput.model_validate(
            load_yaml_strict(qualification_facts_path.read_text(encoding="utf-8"))
        ).facts

    risk_cards = load_risk_extraction(risk_extraction_path)
    threat_surface = determine_threat_surface(
        profile,
        risk_cards,
        sssom_path,
        cross_taxonomy_path or _DEFAULT_CROSS_TAXONOMY_PATH,
        threats_path,
    )
    seeds = expand_seeds(threat_surface, threats_path)
    candidates = expand_candidates(seeds, profile, max_techniques=max_techniques)
    rule_passed, _, _ = apply_rule_based_filter(candidates, profile)
    selected_pattern_ids = {item.seed_id for item in rule_passed}

    resolver = load_taxonomy_resolver()
    patterns = tuple(
        validate_attack_pattern(item, resolver)
        for item in load_attack_patterns().values()
        if item.get("id") in selected_pattern_ids
    )
    references = required_fact_references(patterns)
    fact_states = classify_fact_readings(references, supplied)
    snapshot = capture_capability_snapshot(
        profile,
        _usable_snapshot_readings(fact_states),
    )
    return ProjectionPreflightOutcome(
        readiness=check_projection_readiness(patterns, snapshot),
        fact_states=fact_states,
        facts_template=build_facts_template(references),
        explicit_facts_source=qualification_facts_path is not None,
    )


def write_facts_template(
    outcome: ProjectionPreflightOutcome,
    path: Path,
) -> None:
    """Write a template exactly once; existing user evidence is never replaced."""
    if path.exists():
        raise FileExistsError(f"facts template target already exists: {path}")
    payload = {
        "schema_version": "1",
        "facts": [item.model_dump(mode="json") for item in outcome.facts_template],
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

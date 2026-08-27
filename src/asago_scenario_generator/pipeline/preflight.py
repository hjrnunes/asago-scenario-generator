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
from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern_contracts import (
    AuthoritativeFactReference,
    EvaluatedFactEvidence,
    Scalar,
)
from asago_scenario_generator.models.attack_pattern_validation import (
    validate_attack_pattern,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.pipeline.candidate_expansion import expand_candidates
from asago_scenario_generator.pipeline.candidate_rules import apply_rule_based_filter
from asago_scenario_generator.pipeline.projection import (
    ProjectionReadinessReport,
    capture_capability_snapshot,
    check_projection_readiness,
    required_fact_references,
)
from asago_scenario_generator.pipeline.seeds import expand_seeds
from asago_scenario_generator.pipeline.threats import determine_threat_surface


_DEFAULT_CROSS_TAXONOMY_PATH = (
    DATA_ROOT / "taxonomies" / "mappings" / "cross-taxonomy-mappings.yaml"
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


def _group_supplied_readings(
    supplied: Sequence[EvaluatedFactEvidence],
) -> dict[tuple[object, ...], list[EvaluatedFactEvidence]]:
    """Group supplied readings by fact key, collapsing identical duplicates."""
    supplied_by_key: dict[tuple[object, ...], list[EvaluatedFactEvidence]] = {}
    for item in supplied:
        readings = supplied_by_key.setdefault(_fact_key(item.fact), [])
        if item not in readings:
            readings.append(item)
    return supplied_by_key


def _state_for_required(
    reference: AuthoritativeFactReference,
    readings: tuple[EvaluatedFactEvidence, ...],
) -> ProjectionFactState:
    """Classification for a required fact: absent, contradictory, or reading."""
    if not readings:
        return ProjectionFactState(fact=reference, status="absent", required=True)
    if len(readings) > 1:
        return ProjectionFactState(
            fact=reference,
            status="contradictory",
            required=True,
            readings=readings,
        )
    reading = readings[0]
    return ProjectionFactState(
        fact=reference,
        status=reading.status,
        value=reading.value,
        required=True,
        readings=readings,
    )


def _state_for_obsolete(
    readings: tuple[EvaluatedFactEvidence, ...],
) -> ProjectionFactState:
    """Classification for a supplied fact that no required fact references."""
    reading = readings[0]
    return ProjectionFactState(
        fact=reading.fact,
        status="contradictory" if len(readings) > 1 else "stale",
        value=None if len(readings) > 1 else reading.value,
        required=False,
        readings=readings,
    )


def classify_fact_readings(
    required: Sequence[AuthoritativeFactReference],
    supplied: Sequence[EvaluatedFactEvidence],
) -> tuple[ProjectionFactState, ...]:
    """Classify required and obsolete readings without hiding conflicts."""
    required_by_key = {_fact_key(reference): reference for reference in required}
    supplied_by_key = _group_supplied_readings(supplied)

    states: list[ProjectionFactState] = []
    for reference in sorted(required_by_key.values(), key=_fact_key):
        readings = tuple(supplied_by_key.get(_fact_key(reference), ()))
        states.append(_state_for_required(reference, readings))

    for key in sorted(set(supplied_by_key) - set(required_by_key)):
        states.append(_state_for_obsolete(tuple(supplied_by_key[key])))
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T19:34:46Z","module_hash":"acd8895cda05d91e3f1c74f2f73929bffaca0abc010404920632ead20fc87909","source_sha256":"c92cf57d5e5065700f4bdab34d91ad3f18703e5977c2ce75ec3d207fe60d36d8","functions":[{"id":"func/_fact_key","name":"_fact_key","line":78,"end_line":84,"hash":"d8af51853857e3c3b3b447183d311439146b01e215c6d1d9c3555500e60dfbdf"},{"id":"func/_group_supplied_readings","name":"_group_supplied_readings","line":87,"end_line":96,"hash":"8e7b5fed6fd85c82631f328e7b358de67155e591a19ffd29efaeb6c8e3a70162"},{"id":"func/_state_for_required","name":"_state_for_required","line":99,"end_line":120,"hash":"6866514c7931578c47bc4c68e95eb80b1127bf779dc93fce44e2fc99dc593cf9"},{"id":"func/_state_for_obsolete","name":"_state_for_obsolete","line":123,"end_line":134,"hash":"3aea632dde00fcc47fa1e16b473a752b80c0097ab8d11b990cdf5b8659b6f78e"},{"id":"func/classify_fact_readings","name":"classify_fact_readings","line":137,"end_line":152,"hash":"0ded63b4116f82f3410f25a19b89a8c4ecc8f25faeee1f252774ea556072a513"},{"id":"func/_usable_snapshot_readings","name":"_usable_snapshot_readings","line":155,"end_line":163,"hash":"e9941959d4fc9095ae2ec2f49b5d3cf00485ec78bf8c377fe67e2fbd8b177f3f"},{"id":"func/build_facts_template","name":"build_facts_template","line":166,"end_line":173,"hash":"f29b1d8d1ac8f1fc25efff206cf96aef3262188fa4fc0d1c95df77d2cd59e089"},{"id":"func/run_projection_preflight","name":"run_projection_preflight","line":176,"end_line":227,"hash":"7881632e553b487a12f82eeff948069f6ea2ee8aec7c27fe3b17fab0245918dc"},{"id":"func/write_facts_template","name":"write_facts_template","line":230,"end_line":241,"hash":"f766fb4ae8e395947712343dead3c753d8c0b8771d7491ad640366d0e7d609f2"}]}
# mutate4py-manifest-end

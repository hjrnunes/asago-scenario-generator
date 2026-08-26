"""JSON-Schema validation for scenario envelopes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import jsonschema

from asago_scenario_generator.models.scenario import (
    StructuralValidation,
    ValidationBlock,
)
from asago_scenario_generator.pipeline.validation_common import _validation_passed

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope

# ---------------------------------------------------------------------------
# Structural validation (JSON Schema) — rwv2
# ---------------------------------------------------------------------------

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "schemas"
    / "scenario-envelope.schema.json"
)

_cached_schema: dict | None = None


def _load_envelope_schema() -> dict:
    """Load and cache the hand-maintained JSON Schema for ScenarioEnvelope."""
    global _cached_schema
    if _cached_schema is None:
        _cached_schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return _cached_schema


def _structural_violation_messages(errors: list[Any]) -> list[str]:
    """Human-readable JSON Schema violation messages."""
    return [
        f"{'.'.join(str(p) for p in e.absolute_path)}: {e.message}"
        if e.absolute_path
        else e.message
        for e in errors
    ]


def _persist_structural(
    scenario: ScenarioEnvelope, structural: StructuralValidation
) -> None:
    """Write the structural block and refresh the aggregate pass flag."""
    if scenario.validation is None:
        scenario.validation = ValidationBlock(structural=structural)
    else:
        scenario.validation.structural = structural

    # Update validation_passed.
    scenario.validation_passed = _validation_passed(scenario)


def validate_scenario_structure(
    scenarios: list[ScenarioEnvelope],
) -> None:
    """Run JSON Schema validation on each scenario envelope.

    Populates ``scenario.validation.structural`` with results.
    Scenarios are never removed -- violations are recorded as warnings.
    """
    schema = _load_envelope_schema()
    validator = jsonschema.Draft202012Validator(schema)

    for scenario in scenarios:
        # Serialize the envelope to a dict for JSON Schema validation.
        envelope_dict = scenario.model_dump(mode="json")
        errors = list(validator.iter_errors(envelope_dict))

        structural = StructuralValidation(
            valid=len(errors) == 0,
            violations=_structural_violation_messages(errors),
        )
        _persist_structural(scenario, structural)

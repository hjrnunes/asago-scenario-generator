"""Deterministic STPA execution projection: validation and standalone export.

Stream B Slice 3 and Slice 5.  This module owns the canonical standalone
projection document — plain JSON/YAML data with stable identifiers and
typed provenance — and the deterministic traceability validator that
checks causal factors, temporal assertions, scenario steps, and the
canonical candidate identity against each other.

The validator operates on plain data (``dict``), never on Pydantic
instances, so mutated or forged documents can be validated without
reconstructing model objects.  The canonical document parsed from an
export with only standard JSON/YAML readers is therefore already in the
exact shape the validator consumes.
"""

from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from typing import Any

import yaml

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactorKind,
    predicate_for,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
)
from asago_scenario_generator.stpa.models.execution_projection import (
    StpaProjectionTraceabilityResult,
    StpaProjectionTraceabilityViolation,
    StpaProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)

SCHEMA_VERSION = "stpa-execution-projection-v1"

_CAUSAL_FACTOR_PROVENANCE = "causal_factor"
_UNSAFE_CONTROL_ACTION_PROVENANCE = "unsafe_control_action"

__all__ = [
    "SCHEMA_VERSION",
    "canonical_projection_data",
    "canonical_violations_json",
    "export_projection_json",
    "export_projection_yaml",
    "project_execution",
    "validate_exported_projection",
    "validate_projection_traceability",
]


# ---------------------------------------------------------------------------#
# Canonical document
# ---------------------------------------------------------------------------#


def _first_non_empty(first: Any, fallback: Any) -> Any:
    """Return ``first`` when truthy, otherwise ``fallback`` (``or`` semantics)."""
    if first:
        return first
    return fallback


def _source_kind_for_step(step_kind: str) -> str:
    """Map a canonical step kind to its typed provenance source kind."""
    if step_kind == "UNSAFE_CONTROL_ACTION":
        return _UNSAFE_CONTROL_ACTION_PROVENANCE
    return _CAUSAL_FACTOR_PROVENANCE


def _canonical_factor_entries(
    factors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map envelope causal factors to their canonical document entries.

    Each entry retains the declared kind, source ID, and evidence
    description so the standalone document is self-contained.
    """
    return [
        {
            "source_kind": factor["kind"],
            "source_id": factor["source_id"],
            "description": factor["description"],
        }
        for factor in factors
    ]


def _canonical_assertion_entries(
    assertions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map envelope temporal assertions to their canonical document entries.

    Typed temporal constraints (or their absence with ``requires_binding``)
    are carried per assertion so the standalone document preserves the
    declared timing contract without free-form prose.
    """
    return [
        {
            "assertion_id": assertion["assertion_id"],
            "order": assertion["order_index"] + 1,
            "source_kind": _CAUSAL_FACTOR_PROVENANCE,
            "source_id": assertion["source_id"],
            "kind": assertion["kind"],
            "predicate": assertion["predicate"],
            "constraint": assertion.get("constraint"),
            "requires_binding": assertion.get("requires_binding", True),
        }
        for assertion in assertions
    ]


def _canonical_step_entries(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map envelope temporal steps to their canonical document entries."""
    return [
        {
            "step_id": step["step_id"],
            "order": step["order_index"] + 1,
            "source_kind": _source_kind_for_step(step["kind"]),
            "source_id": step["source_id"],
            "step_kind": step["kind"],
        }
        for step in steps
    ]


def _projection_document(envelope: CandidateExecutionEnvelope) -> dict[str, Any]:
    """Normalize one envelope into the canonical standalone projection shape.

    The structural candidate identifier is preserved; ICA ID and scenario
    ID are exported as their own separate fields so changing either never
    rewrites the structural candidate identity.
    """
    payload = envelope.model_dump(mode="json")
    vector = _first_non_empty(payload.get("temporal_vector"), {})
    factors = _first_non_empty(payload.get("causal_factors"), [])
    assertions = _first_non_empty(vector.get("assertions"), [])
    steps = _first_non_empty(vector.get("steps"), [])
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": _first_non_empty(
            vector.get("candidate_id"), payload["candidate_id"]
        ),
        "controller_id": payload["controller_id"],
        "control_action_id": payload["control_action_id"],
        "uca_type": payload["uca_type"],
        "uca_ref": payload["uca_ref"],
        "ica_id": payload.get("ica_id"),
        "scenario_id": payload.get("scenario_id"),
        "causal_factors": _canonical_factor_entries(factors),
        "assertions": _canonical_assertion_entries(assertions),
        "steps": _canonical_step_entries(steps),
        "uca_constraint": _first_non_empty(vector.get("uca_constraint"), None),
    }


def project_execution(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
) -> CandidateExecutionEnvelope:
    """Deterministically project a validated ScenarioSpec into an envelope.

    Stage 6 seam: maps exactly the causal factors declared and validated
    by Stage 5 into the candidate execution envelope and its temporal
    vector — no causal inference, no timing invention, and no runtime
    observations.  The structural candidate identifier is preserved while
    the ICA ID and scenario ID are carried as separate identity fields.

    Args:
        spec: The Stage 5 :class:`ScenarioSpec` (its causal factors are
            already evidence-backed and control-structure validated).
        control_structure: The control structure the findings come from.

    Returns:
        The deterministic :class:`CandidateExecutionEnvelope`.

    Raises:
        ValueError: When the spec references unknown structural
            identifiers (defense in depth; Stage 5 rejects them first).
    """
    return assemble_candidate_envelope(
        control_structure,
        controller_id=spec.target_controller,
        control_action_id=spec.target_control_action,
        uca_type=spec.ica_type,
        causal_factors=spec.causal_factors,
        derive_temporal_vector=True,
        ica_id=spec.threat_source.ica_id,
        scenario_id=spec.scenario_id,
    )


def canonical_projection_data(
    envelope: CandidateExecutionEnvelope | dict[str, Any],
) -> dict[str, Any]:
    """Build the canonical standalone projection document.

    Normalizes a :class:`CandidateExecutionEnvelope` (or its JSON dump)
    into the canonical export shape: schema version, candidate identity,
    UCA reference, causal factors, typed temporal assertions, and typed
    ordered scenario steps.  A plain ``dict`` input is treated as a
    canonical document already and returned as a deep copy.

    Returns:
        The canonical projection document (plain JSON/YAML data).
    """
    if isinstance(envelope, dict):
        return deepcopy(envelope)
    return _projection_document(envelope)


# ---------------------------------------------------------------------------#
# Traceability validation
# ---------------------------------------------------------------------------#


def _violation(
    code: StpaProjectionTraceabilityViolationCode,
    element_id: str,
    detail: str,
) -> StpaProjectionTraceabilityViolation:
    return StpaProjectionTraceabilityViolation(
        code=code, detail=detail, element_id=element_id
    )


def _sequence_mismatch_code(
    item_label: str,
) -> StpaProjectionTraceabilityViolationCode:
    """Choose the source-mismatch code for one factor-derived sequence."""
    if item_label == "assertion":
        return StpaProjectionTraceabilityViolationCode.assertion_source_mismatch
    return StpaProjectionTraceabilityViolationCode.step_source_mismatch


def _check_factor_omission(
    items: list[dict[str, Any]],
    factor_sources: list[str],
    *,
    item_label: str,
    id_prefix: str,
    violations: list[StpaProjectionTraceabilityViolation],
) -> bool:
    """Emit one omission violation when a whole causal factor is absent.

    Returns:
        True when an omission violation was emitted.
    """
    if len(items) >= len(factor_sources):
        return False
    item_sources = {item.get("source_id") for item in items}
    for index, source in enumerate(factor_sources):
        if source in item_sources:
            continue
        violations.append(
            _violation(
                StpaProjectionTraceabilityViolationCode.omitted_causal_factor,
                f"{id_prefix}-{index + 1}",
                f"{item_label} for causal factor '{source}' is missing "
                f"from the temporal projection",
            )
        )
        return True
    return False


def _check_unmatched_extra_item(
    items: list[dict[str, Any]],
    factor_sources: list[str],
    *,
    item_label: str,
    id_field: str,
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Emit a source-mismatch violation for a sequence item with no factor."""
    if len(items) <= len(factor_sources):
        return
    extra = items[len(factor_sources)]
    violations.append(
        _violation(
            _sequence_mismatch_code(item_label),
            str(extra.get(id_field)),
            f"{item_label} '{extra.get(id_field)}' has no matching causal "
            "factor; the temporal projection invents behavior",
        )
    )


def _check_factor_displacement(
    items: list[dict[str, Any]],
    factor_sources: list[str],
    *,
    item_label: str,
    id_field: str,
    id_prefix: str,
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Emit the earliest reorder or source-mismatch violation in a sequence."""
    sources = [item.get("source_id") for item in items]
    for index, item in enumerate(items[: len(factor_sources)]):
        if item.get("source_id") == factor_sources[index]:
            continue
        if Counter(sources) == Counter(factor_sources):
            canonical_id = f"{id_prefix}-{index + 1}"
            violations.append(
                _violation(
                    StpaProjectionTraceabilityViolationCode.reordered_causal_factor,
                    canonical_id,
                    f"{item_label} '{canonical_id}' breaks causal-factor "
                    "order; factors are present but displaced",
                )
            )
        else:
            violations.append(
                _violation(
                    _sequence_mismatch_code(item_label),
                    str(item.get(id_field)),
                    f"{item_label} '{item.get(id_field)}' references "
                    f"'{item.get('source_id')}' but causal factor "
                    f"'{factor_sources[index]}' is expected at position "
                    f"{index + 1}",
                )
            )
        return
    _check_unmatched_extra_item(
        items,
        factor_sources,
        item_label=item_label,
        id_field=id_field,
        violations=violations,
    )


def _check_factor_mapping(
    items: list[dict[str, Any]],
    factor_sources: list[str],
    *,
    item_label: str,
    id_field: str,
    id_prefix: str,
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Check one factor-derived sequence (assertions or factor steps).

    Emits at most one violation: the earliest affected element.  Short
    sequences are omissions; displaced-but-complete sequences are
    reorders; anything else is a source mismatch.
    """
    if _check_factor_omission(
        items,
        factor_sources,
        item_label=item_label,
        id_prefix=id_prefix,
        violations=violations,
    ):
        return
    _check_factor_displacement(
        items,
        factor_sources,
        item_label=item_label,
        id_field=id_field,
        id_prefix=id_prefix,
        violations=violations,
    )


_REQUIRED_VECTOR_KEYS: tuple[
    tuple[str, StpaProjectionTraceabilityViolationCode], ...
] = (
    ("causal_factors", StpaProjectionTraceabilityViolationCode.causal_factors_missing),
    ("assertions", StpaProjectionTraceabilityViolationCode.assertions_missing),
    ("steps", StpaProjectionTraceabilityViolationCode.steps_missing),
)


def _check_required_vectors(
    doc: dict[str, Any],
    violations: list[StpaProjectionTraceabilityViolation],
) -> set[str]:
    """Emit a typed missing-vector violation for every absent vector key.

    Fail-closed contract: a projection missing ``causal_factors``,
    ``assertions``, or ``steps`` is malformed and must never be treated
    as a valid empty projection.  Present-but-empty lists remain valid.
    """
    missing: set[str] = set()
    for key, code in _REQUIRED_VECTOR_KEYS:
        if key not in doc or doc.get(key) is None:
            violations.append(
                _violation(
                    code,
                    key,
                    f"canonical projection is missing the required '{key}' list",
                )
            )
            missing.add(key)
    return missing


def _check_schema_version(
    doc: dict[str, Any],
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Emit a violation when the canonical schema version is not declared."""
    if doc.get("schema_version") != SCHEMA_VERSION:
        violations.append(
            _violation(
                StpaProjectionTraceabilityViolationCode.schema_version_missing,
                "schema_version",
                f"canonical export must declare schema version '{SCHEMA_VERSION}'",
            )
        )


def _check_candidate_identity(
    doc: dict[str, Any],
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Emit violations when candidate identity or the UCA reference is foreign."""
    controller_id = doc.get("controller_id")
    control_action_id = doc.get("control_action_id")
    uca_type = doc.get("uca_type")
    expected_candidate_id = f"EXEC:{controller_id}:{control_action_id}:{uca_type}"
    if doc.get("candidate_id") != expected_candidate_id:
        violations.append(
            _violation(
                StpaProjectionTraceabilityViolationCode.candidate_identity_mismatch,
                str(doc.get("candidate_id")),
                f"candidate identifier '{doc.get('candidate_id')}' does not "
                f"match the canonical '{expected_candidate_id}'",
            )
        )
    expected_uca_ref = f"{controller_id}:{control_action_id}:{uca_type}"
    if doc.get("uca_ref") != expected_uca_ref:
        violations.append(
            _violation(
                StpaProjectionTraceabilityViolationCode.candidate_identity_mismatch,
                str(doc.get("uca_ref")),
                f"UCA reference '{doc.get('uca_ref')}' does not match the "
                f"canonical '{expected_uca_ref}'",
            )
        )


def _check_assertion_predicates(
    assertions: list[dict[str, Any]],
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Emit the earliest violation where an assertion predicate is not canonical."""
    for assertion in assertions:
        kind = assertion.get("kind")
        try:
            expected_predicate = predicate_for(CausalFactorKind(kind)).value
        except ValueError:
            expected_predicate = None
        if assertion.get("predicate") != expected_predicate:
            violations.append(
                _violation(
                    StpaProjectionTraceabilityViolationCode.assertion_predicate_mismatch,
                    str(assertion.get("assertion_id")),
                    f"assertion '{assertion.get('assertion_id')}' predicate "
                    f"'{assertion.get('predicate')}' is not the canonical "
                    f"predicate '{expected_predicate}' for kind '{kind}'",
                )
            )
            return


def _check_final_step_identity(
    last_step: dict[str, Any],
    control_action_id: str,
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Emit a violation when the final step is not the UCA for the action."""
    if (
        last_step.get("step_kind") == "UNSAFE_CONTROL_ACTION"
        and last_step.get("source_id") == control_action_id
    ):
        return
    violations.append(
        _violation(
            StpaProjectionTraceabilityViolationCode.uca_step_mismatch,
            str(last_step.get("step_id")),
            f"final scenario step '{last_step.get('step_id')}' must be "
            f"the unsafe control action for '{control_action_id}', "
            f"not '{last_step.get('source_id')}'",
        )
    )


def _check_uca_step_and_outcome(
    steps: list[dict[str, Any]],
    factors: list[dict[str, Any]],
    control_action_id: str,
    uca_type: Any,
    uca_constraint: Any,
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Check the final UCA scenario step and its explicit outcome mapping.

    Composes the missing-UCA contract with the forged-outcome check: a
    non-empty factor list without a final unsafe control action step
    violates fail-closed traceability, and whenever a projection has
    steps the vector-level ``uca_constraint`` must mirror the final step
    — naming the same control action and UCA type.
    """
    if not steps:
        if factors:
            violations.append(
                _violation(
                    StpaProjectionTraceabilityViolationCode.uca_step_mismatch,
                    "steps",
                    "temporal projection has no final unsafe control action step",
                )
            )
        return
    _check_final_step_identity(steps[-1], control_action_id, violations)
    expected = {
        "type": "uca_outcome",
        "control_action_id": control_action_id,
        "uca_type": uca_type,
    }
    if uca_constraint != expected:
        violations.append(
            _violation(
                StpaProjectionTraceabilityViolationCode.uca_constraint_mismatch,
                "uca_constraint",
                f"final UCA outcome constraint '{uca_constraint}' does not "
                f"match the canonical '{expected}'",
            )
        )


def _check_typed_provenance(
    assertions: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Emit the earliest violation where typed provenance contradicts kind."""
    for assertion in assertions:
        if assertion.get("source_kind") != _CAUSAL_FACTOR_PROVENANCE:
            violations.append(
                _violation(
                    StpaProjectionTraceabilityViolationCode.typed_provenance_mismatch,
                    str(assertion.get("assertion_id")),
                    f"assertion '{assertion.get('assertion_id')}' has typed "
                    f"provenance '{assertion.get('source_kind')}' but temporal "
                    "assertions must derive from causal factors",
                )
            )
            return
    for step in steps:
        expected_kind = _source_kind_for_step(step.get("step_kind"))
        if step.get("source_kind") != expected_kind:
            violations.append(
                _violation(
                    StpaProjectionTraceabilityViolationCode.typed_provenance_mismatch,
                    str(step.get("step_id")),
                    f"scenario step '{step.get('step_id')}' has typed "
                    f"provenance '{step.get('source_kind')}' but its step kind "
                    f"'{step.get('step_kind')}' requires '{expected_kind}'",
                )
            )
            return


def _check_factor_sequences(
    assertions: list[dict[str, Any]],
    factor_steps: list[dict[str, Any]],
    factor_sources: list[str],
    missing: set[str],
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Run the causal-factor sequence checks whose required vectors are present.

    Emits, in deterministic order: the causal-factor-to-assertion
    mapping, the canonical assertion predicates, then the
    causal-factor-to-step mapping.  A check whose prerequisite
    ``causal_factors``/``assertions``/``steps`` key is missing is skipped
    (the absence was already reported by the required-vector check).
    """
    if not missing & {"causal_factors", "assertions"}:
        _check_factor_mapping(
            assertions,
            factor_sources,
            item_label="assertion",
            id_field="assertion_id",
            id_prefix="TA",
            violations=violations,
        )
    if "assertions" not in missing:
        _check_assertion_predicates(assertions, violations)
    if not missing & {"causal_factors", "steps"}:
        _check_factor_mapping(
            factor_steps,
            factor_sources,
            item_label="scenario step",
            id_field="step_id",
            id_prefix="S",
            violations=violations,
        )


def _check_final_step_sequence(
    steps: list[dict[str, Any]],
    factors: list[dict[str, Any]],
    assertions: list[dict[str, Any]],
    control_action_id: str,
    uca_type: Any,
    uca_constraint: Any,
    missing: set[str],
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Run the final-step and typed-provenance checks with present vectors.

    Emits, in deterministic order: the final unsafe control action step
    with its explicit UCA outcome constraint, then typed provenance.
    """
    if "steps" not in missing:
        _check_uca_step_and_outcome(
            steps,
            factors,
            control_action_id,
            uca_type,
            uca_constraint,
            violations,
        )
    if not missing & {"assertions", "steps"}:
        _check_typed_provenance(assertions, steps, violations)


def validate_projection_traceability(
    envelope_or_doc: CandidateExecutionEnvelope | dict[str, Any],
) -> StpaProjectionTraceabilityResult:
    """Validate the STPA execution projection traceability.

    Checks, in deterministic order: schema version, canonical candidate
    identity and UCA reference, required projection vectors (fail-close:
    absent ``causal_factors``/``assertions``/``steps`` keys are typed
    violations while present-empty lists are valid), causal-factor-to-
    assertion mapping, canonical assertion predicates, causal-factor-to-
    step mapping, the final unsafe control action step, the explicit UCA
    outcome constraint, and typed provenance.  Each mapping check emits
    at most one violation naming the earliest affected projection element.

    Args:
        envelope_or_doc: A :class:`CandidateExecutionEnvelope`, or the
            canonical projection document (plain data, as produced by
            :func:`canonical_projection_data` or parsed from an export).

    Returns:
        A :class:`StpaProjectionTraceabilityResult`.
    """
    doc = canonical_projection_data(envelope_or_doc)
    violations: list[StpaProjectionTraceabilityViolation] = []
    missing = _check_required_vectors(doc, violations)
    factors = _first_non_empty(doc.get("causal_factors"), [])
    assertions = _first_non_empty(doc.get("assertions"), [])
    steps = _first_non_empty(doc.get("steps"), [])
    factor_sources = [factor.get("source_id") for factor in factors]
    factor_steps = [
        step for step in steps if step.get("source_kind") == _CAUSAL_FACTOR_PROVENANCE
    ]

    _check_schema_version(doc, violations)
    _check_candidate_identity(doc, violations)
    _check_factor_sequences(
        assertions, factor_steps, factor_sources, missing, violations
    )
    _check_final_step_sequence(
        steps,
        factors,
        assertions,
        doc.get("control_action_id"),
        doc.get("uca_type"),
        doc.get("uca_constraint"),
        missing,
        violations,
    )

    return StpaProjectionTraceabilityResult(valid=not violations, violations=violations)


def validate_exported_projection(
    payload: dict[str, Any],
) -> StpaProjectionTraceabilityResult:
    """Validate a parsed standalone export (no project objects needed).

    The payload is plain data produced by parsing canonical JSON or YAML
    with standard readers; the same traceability rules apply as for a
    freshly assembled envelope.
    """
    return validate_projection_traceability(payload)


def canonical_violations_json(
    result: StpaProjectionTraceabilityResult,
) -> str:
    """Serialize violations into a byte-stable canonical JSON payload."""
    payload = [violation.model_dump(mode="json") for violation in result.violations]
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------#
# Standalone export
# ---------------------------------------------------------------------------#


def export_projection_json(
    envelope: CandidateExecutionEnvelope | dict[str, Any],
) -> str:
    """Export the canonical projection document as standalone JSON.

    The payload is plain JSON readable with only the standard library
    ``json`` module; object keys use canonical sorted ordering and the
    output is byte-stable for identical inputs.
    """
    doc = canonical_projection_data(envelope)
    return (
        json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    )


def export_projection_yaml(
    envelope: CandidateExecutionEnvelope | dict[str, Any],
) -> str:
    """Export the canonical projection document as standalone YAML.

    The payload is plain YAML readable with only a standard YAML reader;
    list ordering preserves assertions and steps without sorting by
    source text, and the output is byte-stable for identical inputs.
    """
    doc = canonical_projection_data(envelope)
    return yaml.safe_dump(
        doc,
        sort_keys=True,
        default_flow_style=False,
        allow_unicode=True,
    )

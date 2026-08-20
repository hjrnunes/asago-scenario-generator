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

from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    CausalFactorKind,
    predicate_for,
)
from asago_scenario_generator.stpa.models.execution_projection import (
    StpaProjectionTraceabilityResult,
    StpaProjectionTraceabilityViolation,
    StpaProjectionTraceabilityViolationCode,
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
    "validate_exported_projection",
    "validate_projection_traceability",
]


# ---------------------------------------------------------------------------#
# Canonical document
# ---------------------------------------------------------------------------#


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
    payload = envelope.model_dump(mode="json")
    vector = payload.get("temporal_vector") or {}
    factors = payload.get("causal_factors") or []
    assertions = vector.get("assertions") or []
    steps = vector.get("steps") or []
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": vector.get("candidate_id") or payload["candidate_id"],
        "controller_id": payload["controller_id"],
        "control_action_id": payload["control_action_id"],
        "uca_type": payload["uca_type"],
        "uca_ref": payload["uca_ref"],
        "causal_factors": [
            {"source_kind": factor["kind"], "source_id": factor["source_id"]}
            for factor in factors
        ],
        "assertions": [
            {
                "assertion_id": assertion["assertion_id"],
                "order": assertion["order_index"] + 1,
                "source_kind": _CAUSAL_FACTOR_PROVENANCE,
                "source_id": assertion["source_id"],
                "kind": assertion["kind"],
                "predicate": assertion["predicate"],
            }
            for assertion in assertions
        ],
        "steps": [
            {
                "step_id": step["step_id"],
                "order": step["order_index"] + 1,
                "source_kind": (
                    _UNSAFE_CONTROL_ACTION_PROVENANCE
                    if step["kind"] == "UNSAFE_CONTROL_ACTION"
                    else _CAUSAL_FACTOR_PROVENANCE
                ),
                "source_id": step["source_id"],
                "step_kind": step["kind"],
            }
            for step in steps
        ],
    }


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


def _check_factor_sequence(
    items: list[dict[str, Any]],
    factor_sources: list[str],
    *,
    item_label: str,
    id_field: str,
    id_prefix: str,
) -> list[StpaProjectionTraceabilityViolation]:
    """Check one factor-derived sequence (assertions or factor steps).

    Emits at most one violation: the earliest affected element.  Short
    sequences are omissions; displaced-but-complete sequences are
    reorders; anything else is a source mismatch.
    """
    sources = [item.get("source_id") for item in items]
    if len(items) < len(factor_sources):
        for index, source in enumerate(factor_sources):
            if source not in sources:
                return [
                    _violation(
                        StpaProjectionTraceabilityViolationCode.omitted_causal_factor,
                        f"{id_prefix}-{index + 1}",
                        f"{item_label} for causal factor '{source}' is missing "
                        f"from the temporal projection",
                    )
                ]
    for index, item in enumerate(items[: len(factor_sources)]):
        if item.get("source_id") != factor_sources[index]:
            if Counter(sources) == Counter(factor_sources):
                canonical_id = f"{id_prefix}-{index + 1}"
                return [
                    _violation(
                        StpaProjectionTraceabilityViolationCode.reordered_causal_factor,
                        canonical_id,
                        f"{item_label} '{canonical_id}' breaks causal-factor "
                        "order; factors are present but displaced",
                    )
                ]
            else:
                if item_label == "assertion":
                    code = StpaProjectionTraceabilityViolationCode.assertion_source_mismatch
                else:
                    code = StpaProjectionTraceabilityViolationCode.step_source_mismatch
                detail = (
                    f"{item_label} '{item.get(id_field)}' references "
                    f"'{item.get('source_id')}' but causal factor "
                    f"'{factor_sources[index]}' is expected at position "
                    f"{index + 1}"
                )
            return [_violation(code, str(item.get(id_field)), detail)]
    if len(items) > len(factor_sources):
        extra = items[len(factor_sources)]
        code = (
            StpaProjectionTraceabilityViolationCode.assertion_source_mismatch
            if item_label == "assertion"
            else StpaProjectionTraceabilityViolationCode.step_source_mismatch
        )
        return [
            _violation(
                code,
                str(extra.get(id_field)),
                f"{item_label} '{extra.get(id_field)}' has no matching causal "
                "factor; the temporal projection invents behavior",
            )
        ]
    return []


def validate_projection_traceability(
    envelope_or_doc: CandidateExecutionEnvelope | dict[str, Any],
) -> StpaProjectionTraceabilityResult:
    """Validate the STPA execution projection traceability.

    Checks, in deterministic order: schema version, canonical candidate
    identity and UCA reference, causal-factor-to-assertion mapping,
    canonical assertion predicates, causal-factor-to-step mapping, the
    final unsafe control action step, and typed provenance.  Each check
    emits at most one violation naming the earliest affected projection
    element.

    Args:
        envelope_or_doc: A :class:`CandidateExecutionEnvelope`, or the
            canonical projection document (plain data, as produced by
            :func:`canonical_projection_data` or parsed from an export).

    Returns:
        A :class:`StpaProjectionTraceabilityResult`.
    """
    doc = canonical_projection_data(envelope_or_doc)
    violations: list[StpaProjectionTraceabilityViolation] = []

    controller_id = doc.get("controller_id")
    control_action_id = doc.get("control_action_id")
    uca_type = doc.get("uca_type")

    # --- Check 1: schema version ---
    if doc.get("schema_version") != SCHEMA_VERSION:
        violations.append(
            _violation(
                StpaProjectionTraceabilityViolationCode.schema_version_missing,
                "schema_version",
                f"canonical export must declare schema version '{SCHEMA_VERSION}'",
            )
        )

    # --- Check 2: canonical candidate identity and UCA reference ---
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

    factors = doc.get("causal_factors") or []
    factor_sources = [factor.get("source_id") for factor in factors]
    assertions = doc.get("assertions") or []
    steps = doc.get("steps") or []

    # --- Check 3: causal-factor-to-assertion mapping ---
    violations.extend(
        _check_factor_sequence(
            assertions,
            factor_sources,
            item_label="assertion",
            id_field="assertion_id",
            id_prefix="TA",
        )
    )

    # --- Check 4: canonical assertion predicates ---
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
            break

    # --- Check 5: causal-factor-to-step mapping ---
    factor_steps = [
        step for step in steps if step.get("source_kind") == _CAUSAL_FACTOR_PROVENANCE
    ]
    violations.extend(
        _check_factor_sequence(
            factor_steps,
            factor_sources,
            item_label="scenario step",
            id_field="step_id",
            id_prefix="S",
        )
    )

    # --- Check 6: final unsafe control action step ---
    if factors and not steps:
        violations.append(
            _violation(
                StpaProjectionTraceabilityViolationCode.uca_step_mismatch,
                "steps",
                "temporal projection has no final unsafe control action step",
            )
        )
    elif steps:
        last_step = steps[-1]
        if (
            last_step.get("step_kind") != "UNSAFE_CONTROL_ACTION"
            or last_step.get("source_id") != control_action_id
        ):
            violations.append(
                _violation(
                    StpaProjectionTraceabilityViolationCode.uca_step_mismatch,
                    str(last_step.get("step_id")),
                    f"final scenario step '{last_step.get('step_id')}' must be "
                    f"the unsafe control action for '{control_action_id}', "
                    f"not '{last_step.get('source_id')}'",
                )
            )

    # --- Check 7: typed provenance ---
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
            break
    for step in steps:
        expected_kind = (
            _UNSAFE_CONTROL_ACTION_PROVENANCE
            if step.get("step_kind") == "UNSAFE_CONTROL_ACTION"
            else _CAUSAL_FACTOR_PROVENANCE
        )
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
            break

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

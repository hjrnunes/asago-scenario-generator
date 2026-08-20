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
    """Map envelope causal factors to their canonical document entries."""
    return [
        {"source_kind": factor["kind"], "source_id": factor["source_id"]}
        for factor in factors
    ]


def _canonical_assertion_entries(
    assertions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map envelope temporal assertions to their canonical document entries."""
    return [
        {
            "assertion_id": assertion["assertion_id"],
            "order": assertion["order_index"] + 1,
            "source_kind": _CAUSAL_FACTOR_PROVENANCE,
            "source_id": assertion["source_id"],
            "kind": assertion["kind"],
            "predicate": assertion["predicate"],
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
    """Normalize one envelope into the canonical standalone projection shape."""
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
        "causal_factors": _canonical_factor_entries(factors),
        "assertions": _canonical_assertion_entries(assertions),
        "steps": _canonical_step_entries(steps),
    }


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


def _check_uca_final_step(
    steps: list[dict[str, Any]],
    factors: list[dict[str, Any]],
    control_action_id: str,
    violations: list[StpaProjectionTraceabilityViolation],
) -> None:
    """Check the final scenario step or the missing-UCA contract."""
    if steps:
        _check_final_step_identity(steps[-1], control_action_id, violations)
        return
    if not factors:
        return
    violations.append(
        _violation(
            StpaProjectionTraceabilityViolationCode.uca_step_mismatch,
            "steps",
            "temporal projection has no final unsafe control action step",
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
    factors = _first_non_empty(doc.get("causal_factors"), [])
    assertions = _first_non_empty(doc.get("assertions"), [])
    steps = _first_non_empty(doc.get("steps"), [])
    factor_sources = [factor.get("source_id") for factor in factors]

    _check_schema_version(doc, violations)
    _check_candidate_identity(doc, violations)
    _check_factor_mapping(
        assertions,
        factor_sources,
        item_label="assertion",
        id_field="assertion_id",
        id_prefix="TA",
        violations=violations,
    )
    _check_assertion_predicates(assertions, violations)
    factor_steps = [
        step for step in steps if step.get("source_kind") == _CAUSAL_FACTOR_PROVENANCE
    ]
    _check_factor_mapping(
        factor_steps,
        factor_sources,
        item_label="scenario step",
        id_field="step_id",
        id_prefix="S",
        violations=violations,
    )
    _check_uca_final_step(steps, factors, doc.get("control_action_id"), violations)
    _check_typed_provenance(assertions, steps, violations)

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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-20T20:23:22Z","module_hash":"d085e2992e709e0648fc3d67b9bdcf5e767baf35a8eaa81994e7a64b1b87f67b","functions":[{"id":"func/_first_non_empty","name":"_first_non_empty","line":57,"end_line":61,"hash":"26925a6541ac44ec982adce654a282bae8e51b0c14f9af2a9414563d5bf0fc19"},{"id":"func/_source_kind_for_step","name":"_source_kind_for_step","line":64,"end_line":68,"hash":"132396a00aa2479e9d49c7dc39152a0ce8519980b98d4f8c05913962b07cf005"},{"id":"func/_canonical_factor_entries","name":"_canonical_factor_entries","line":71,"end_line":78,"hash":"25e0f1b8b08eec7776f155c5328059a19012f7c004e8bc4372f67b597ee5f325"},{"id":"func/_canonical_assertion_entries","name":"_canonical_assertion_entries","line":81,"end_line":95,"hash":"a706f0973a0168a18e1892e6da1ef16526e36da77b673d6148d12d7cd02ae08b"},{"id":"func/_canonical_step_entries","name":"_canonical_step_entries","line":98,"end_line":109,"hash":"a61fb0eeef2506eb2e6cfaa186693770457b1e4e2468f16be90fb16b3da110b8"},{"id":"func/_projection_document","name":"_projection_document","line":112,"end_line":131,"hash":"896d526e36ef64fb413dc8431968cb4a3da7e03daca62302c69930236fe5da37"},{"id":"func/canonical_projection_data","name":"canonical_projection_data","line":134,"end_line":150,"hash":"47d4dc3e079f41e06514a8135e253d23d1bd84a0e20441663d0e8e097a293073"},{"id":"func/_violation","name":"_violation","line":158,"end_line":165,"hash":"59074efc9b7d7a227f24d85c8d06f46082e69581383c42be5f17742aab587dd9"},{"id":"func/_sequence_mismatch_code","name":"_sequence_mismatch_code","line":168,"end_line":174,"hash":"d46acc9e7146ffb7af8e7ba60649a0e55569b0b8e25f730abb810a000aa7f098"},{"id":"func/_check_factor_omission","name":"_check_factor_omission","line":177,"end_line":205,"hash":"9a272fb4579fe830ea6247b751e9b3832d41941bee5532af4a425cc22cb0bae1"},{"id":"func/_check_unmatched_extra_item","name":"_check_unmatched_extra_item","line":208,"end_line":227,"hash":"a120075cfa445c50a6b640db216599eb6c193dfde7c0199d036c273dee5af166"},{"id":"func/_check_factor_displacement","name":"_check_factor_displacement","line":230,"end_line":272,"hash":"a1ad6592df176443b406136ab9870a5dd4b0b69617eabd7de57df5e7690470d2"},{"id":"func/_check_factor_mapping","name":"_check_factor_mapping","line":275,"end_line":305,"hash":"f9da3b4b428acc06a18e70a049073292f7fb6d1ba095f6d981ecacef756d5ab1"},{"id":"func/_check_schema_version","name":"_check_schema_version","line":308,"end_line":320,"hash":"964ab1b54e96983b5b020c639e9e876794600f69a06e8c394bbec29d22dbc3cd"},{"id":"func/_check_candidate_identity","name":"_check_candidate_identity","line":323,"end_line":350,"hash":"212ecb9727aca88c7e38faf96919cc966154e8a56c4b8ba7cb4e61eafddff322"},{"id":"func/_check_assertion_predicates","name":"_check_assertion_predicates","line":353,"end_line":374,"hash":"c2b1845d195d38fd993bef493b9c8f16ec0d34457efa3193ce35f957c906d933"},{"id":"func/_check_final_step_identity","name":"_check_final_step_identity","line":377,"end_line":396,"hash":"4001ec9eacad427154d990a33a6220118c925e105c119a02292e64c751f962c2"},{"id":"func/_check_uca_final_step","name":"_check_uca_final_step","line":399,"end_line":417,"hash":"7d367a921ea156af9a307baece68a50859e6f982b345c3166238859d08eeb507"},{"id":"func/_check_typed_provenance","name":"_check_typed_provenance","line":420,"end_line":450,"hash":"f45a1ce4d1a9eb93703d8b2761dd37a30971fd1b5d2f4948e3eed3fd2a93f903"},{"id":"func/validate_projection_traceability","name":"validate_projection_traceability","line":453,"end_line":505,"hash":"25f0179e87dccb1ef6d7e2d93a851133db48ffea18002987d0c55b5a2e162269"},{"id":"func/validate_exported_projection","name":"validate_exported_projection","line":508,"end_line":517,"hash":"6ca814160fa4807a8d69407bedc8148c169e3e0303248e5f19eb9ad627ad0dc4"},{"id":"func/canonical_violations_json","name":"canonical_violations_json","line":520,"end_line":525,"hash":"e2840695065476563ca032414453d2dcfc6f5549d70fdf3f0409237cf5f36d81"},{"id":"func/export_projection_json","name":"export_projection_json","line":533,"end_line":545,"hash":"64739fe45ced221e39a6a3b790731148455b91190e96d59b722b98304c80272c"},{"id":"func/export_projection_yaml","name":"export_projection_yaml","line":548,"end_line":563,"hash":"522d78900cd7c300036eee73c9202323c401847dfb56c3764221eb876b2995f2"}]}
# mutate4py-manifest-end

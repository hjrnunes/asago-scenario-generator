"""The scenario-handoff-v5 rules: one implementation for every reader.

``validate_handoff`` runs the ownership walker, the composed schema, and the
rules the schema cannot state. Each break is a :class:`Violation` carrying the
producer's code, the dotted path of the break, and a reason. Ownership codes
come first, in first-seen order; a payload the schema rejects reports one code
per field it rejects, and a schema-valid payload reports the first rule it
breaks.
"""

from __future__ import annotations

import re
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

from .boundary import ownership_violations
from .contract import HANDOFF_SCHEMA_VERSION_V5, Contract, packaged_contract
from .shape import attack_shape_violation
from .violation import Violation

#: The kit's ``schema-unknown-version`` case records these codes, and the kit
#: stays byte-identical.
OTHER_VERSION_VIOLATIONS = (
    Violation(
        "schema_violation:schema_version",
        "schema_version",
        "the handoff states another schema version",
    ),
    Violation(
        "schema_violation:attack_shape",
        "schema_version",
        "another schema version states another attack shape",
    ),
)
_Break = tuple[str, str] | None

#: The kit's code for a document that is not a JSON object, with the kit's
#: root pairing's path.
_ROOT_REFUSAL = Violation(
    "schema_violation:<root>", "<root>", "a scenario handoff must be a JSON object"
)


def validate_handoff(
    payload: Any, *, contract: Contract | None = None
) -> list[Violation]:
    """Report each rule one scenario-handoff-v5 document breaks.

    *contract* states the schema and the ownership rules; without it the
    package's copies are read. An empty list means the document holds.
    """

    contract = contract or packaged_contract()
    ownership = ownership_violations(payload, contract)
    breaks = schema_violations(payload, contract) or hand_rule_violations(
        payload, contract
    )
    return [*ownership, *breaks]


def schema_violations(
    payload: Any, contract: Contract | None = None
) -> list[Violation]:
    """Map the schema's errors to the producer's codes: one per top-level field.

    A payload with any other ``schema_version`` gets
    :data:`OTHER_VERSION_VIOLATIONS`, the codes the kit records for its
    unknown-version case. A root that is not a JSON object gets the kit's
    ``schema_violation:<root>`` code before any key is read.
    """

    if not isinstance(payload, dict):
        return [_ROOT_REFUSAL]
    contract = contract or packaged_contract()
    if payload.get("schema_version") != HANDOFF_SCHEMA_VERSION_V5:
        return list(OTHER_VERSION_VIOLATIONS)
    found: dict[str, Violation] = {}
    rooted: Violation | None = None
    # The producer lists a missing required field before the fields it rejects as
    # extra, whatever order the schema's keywords come in.
    errors = sorted(
        Draft202012Validator(contract.schema).iter_errors(payload),
        key=lambda error: not (error.validator == "required" and not error.path),
    )
    for error in errors:
        where, reason = _error_detail(error)
        if _is_root_pairing(error):
            rooted = rooted or Violation("schema_violation:<root>", where, reason)
            continue
        for name in _error_fields(error):
            found.setdefault(name, Violation(f"schema_violation:{name}", where, reason))
    if found or rooted is None:
        return list(found.values())
    return [rooted]


def _error_detail(error: Any) -> tuple[str, str]:
    # best_match descends into anyOf branches, so the reason names the break
    # inside an optional object rather than restating the whole object.
    detail = best_match([error]) or error
    return ".".join(
        str(part) for part in detail.absolute_path
    ) or "<root>", detail.message


def _is_root_pairing(error: Any) -> bool:
    return bool(error.schema_path) and error.schema_path[0] == "allOf"


def _error_fields(error: Any) -> list[str]:
    if error.path:
        return [str(error.path[0])]
    if error.validator == "required":
        return [error.message.split("'")[1]]
    if error.validator == "additionalProperties":
        return re.findall(r"'([^']+)'", error.message.split("(", 1)[1])
    return ["<root>"]


def hand_rule_violations(
    payload: Any, contract: Contract | None = None
) -> list[Violation]:
    """Report the first rule the schema cannot state that a handoff breaks.

    The rules are blank text, the observation-contract format, presence where
    the schema has a default, and cross-field pairings. The reported code names
    the top-level field the rule reads; the v5 procedure chain, a rule across
    the steps that the producer checks on the whole handoff, reports ``<root>``.
    A root that is not a JSON object gets the same code as the schema's.
    """

    if not isinstance(payload, dict):
        return [_ROOT_REFUSAL]
    contract = contract or packaged_contract()
    for key, rules in _HAND_RULES:
        if payload.get(key) is None:
            continue
        for rule in rules:
            found = rule(payload[key], key)
            if found is not None:
                return [Violation(f"schema_violation:{key}", *found)]
    if payload.get("attack_shape") is not None:
        found = attack_shape_violation(payload["attack_shape"], contract.schema)
        if found is not None:
            return [Violation("schema_violation:attack_shape", *found)]
    if "procedure" in payload:
        found = _procedure_chain(payload["procedure"], "procedure")
        if found is not None:
            return [Violation("schema_violation:<root>", *found)]
    return []


def _nonblank_text(value: str, path: str) -> _Break:
    return None if value.strip() else (path, "must not be blank")


def _semantic_failure_call(value: dict[str, Any], path: str) -> _Break:
    return _nonblank_text(value["operation_name"], f"{path}.operation_name")


def _observation_contract(value: dict[str, Any], path: str) -> _Break:
    for key in ("contract_schema", "contract_id", "contract_digest"):
        if not value[key].strip():
            return f"{path}.{key}", "must not be blank"
    if not _is_sha256_hex(value["contract_digest"]):
        return f"{path}.contract_digest", "is not a SHA-256 hex digest"
    if value["contract_schema"] != "observation-contract-v1":
        return f"{path}.contract_schema", "must be observation-contract-v1"
    return None


def _observation_criteria(value: dict[str, Any], path: str) -> _Break:
    for index, criterion in enumerate(value["criteria"]):
        found = _observation_criterion(criterion, f"{path}.criteria.{index}")
        if found is not None:
            return found
    return None


def _observation_criterion(criterion: dict[str, Any], path: str) -> _Break:
    for key in ("criterion_id", "outcome", "reason"):
        if not criterion[key].strip():
            return f"{path}.{key}", "must not be blank"
    return _criterion_claim(criterion, path) or _criterion_operation(criterion, path)


def _criterion_claim(criterion: dict[str, Any], path: str) -> _Break:
    if not criterion["observable"]:
        if any(criterion.get(key) is not None for key in ("claim_level", "evidence")):
            return (
                path,
                "an analytical-only criterion must omit claim_level and evidence",
            )
        return None
    for key in ("claim_level", "evidence"):
        if not _is_nonblank_str(criterion.get(key)):
            return path, f"an observable criterion requires {key}"
    return None


def _criterion_operation(criterion: dict[str, Any], path: str) -> _Break:
    operation_name = criterion.get("operation_name")
    if operation_name is None:
        return None
    if not _is_nonblank_str(operation_name):
        return f"{path}.operation_name", "must not be blank"
    if not criterion["observable"]:
        return path, "an analytical-only criterion must omit operation_name"
    return None


def _observation_assessment(value: dict[str, Any], path: str) -> _Break:
    assessment = value["assessment"]
    path = f"{path}.assessment"
    if not {"supported_criteria", "unsupported_criteria"} <= set(assessment):
        return path, "requires supported_criteria and unsupported_criteria"
    if not assessment["reason"].strip():
        return f"{path}.reason", "must not be blank"
    for key in ("supported_criteria", "unsupported_criteria"):
        for index, item in enumerate(assessment[key]):
            if not item.strip():
                return f"{path}.{key}.{index}", "must not be blank"
    return None


def _safe_outcome_reference_uniqueness(value: dict[str, Any], path: str) -> _Break:
    """List each record and fact reference once, after stripping it.

    The producer strips each reference before it checks uniqueness, so JSON
    Schema's ``uniqueItems`` alone accepts ``"R-1"`` beside ``" R-1"``. The
    producer's model refuses that pair; this rule makes the shared validator
    agree.
    """

    for key in ("record_refs", "fact_refs"):
        references = [item.strip() for item in value.get(key) or ()]
        if len(set(references)) != len(references):
            return f"{path}.{key}", "must be unique"
    return None


def _safe_outcome_argument_names(value: dict[str, Any], path: str) -> _Break:
    """State each argument of the safe call once, by a non-blank name.

    The schema states the rest of the safe-outcome rules; it cannot state
    uniqueness of the argument names. An empty list states no value, as an
    absent one does.
    """

    arguments = value.get("call_arguments")
    if not arguments:
        return None
    names = [item["argument"] for item in arguments]
    if len({name.strip() for name in names}) != len(names):
        return f"{path}.call_arguments", "must name each argument once"
    return None


def _procedure_chain(steps: list[dict[str, Any]], path: str) -> _Break:
    """Number the steps S00, S01, ... in order and link each to the next.

    A step names a tactic exactly when it names a technique. The rules are the
    producer's ``ScenarioHandoffV5.validate_procedure_chain``.
    """

    ids = [f"S{index:02d}" for index in range(len(steps))]
    for index, step in enumerate(steps):
        if step["step_id"] != ids[index]:
            return f"{path}.{index}.step_id", f"must be {ids[index]}"
        if step["leads_to"] != ids[index + 1 : index + 2]:
            return f"{path}.{index}.leads_to", f"must be {ids[index + 1 : index + 2]}"
        if (step["tactic"] is None) != (step["technique"] is None):
            return f"{path}.{index}", "names a tactic exactly when it names a technique"
    return None


def _taxonomy_references(taxonomy: dict[str, Any], path: str) -> _Break:
    """List the references sorted by scheme and id, each once."""

    keys = [(ref["scheme"], ref["id"]) for ref in taxonomy.get("references", [])]
    if keys != sorted(set(keys)):
        return f"{path}.references", "must be sorted by scheme and id, each once"
    return None


def _tool_call_status_reason(status: dict[str, Any], path: str) -> _Break:
    if (status["status"] == "bound") != (status["reason"] == "bound"):
        return path, "reason must be bound exactly when the status is bound"
    return None


def _deduplication(value: dict[str, Any], path: str) -> _Break:
    if not value["scenario_id"].strip():
        return f"{path}.scenario_id", "must not be blank"
    duplicate_of = value.get("duplicate_of")
    if value["status"] != "duplicate":
        if duplicate_of is not None:
            return path, "canonical and analytical-only handoffs must omit duplicate_of"
    elif duplicate_of is None:
        return path, "a duplicate requires duplicate_of"
    elif not duplicate_of.strip():
        return f"{path}.duplicate_of", "must not be blank"
    return _deduplication_key(value["key"], f"{path}.key")


def _deduplication_key(key: dict[str, Any], path: str) -> _Break:
    for name in ("condition", "uca_id", "control_action_id", "operation_name"):
        if key.get(name) is not None and not key[name].strip():
            return f"{path}.{name}", "must not be blank"
    for index, constraint_id in enumerate(key.get("constraint_ids", ())):
        if not constraint_id.strip():
            return f"{path}.constraint_ids.{index}", "must not be blank"
    return None


_HAND_RULES: tuple[tuple[str, tuple[Any, ...]], ...] = (
    *(
        (key, (_nonblank_text,))
        for key in (
            "scenario_id",
            "hypothesis_framing",
            "narrative",
            "semantic_failure_criterion",
            "safe_alternative",
        )
    ),
    (
        "observation",
        (_observation_contract, _observation_criteria, _observation_assessment),
    ),
    ("semantic_failure_call", (_semantic_failure_call,)),
    (
        "safe_observable_outcome",
        (_safe_outcome_reference_uniqueness, _safe_outcome_argument_names),
    ),
    ("deduplication", (_deduplication,)),
    ("tool_call_condition_status", (_tool_call_status_reason,)),
    ("taxonomy", (_taxonomy_references,)),
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.match(value))


def _is_nonblank_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


__all__ = [
    "OTHER_VERSION_VIOLATIONS",
    "hand_rule_violations",
    "schema_violations",
    "validate_handoff",
]

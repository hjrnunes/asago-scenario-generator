"""The published scenario-handoff schema: the model's shape plus its rules.

``ScenarioHandoffV6`` checks the handoff rules in Pydantic validators, but a
reader that holds only ``schema.json`` sees the model's shape, not those
checks.  This module states every rule JSON Schema can express as
``allOf``/``if``/``then`` assertions (the form ``json_schema_extra`` adds), and
the generator writes the result as the published schema.  The Pydantic model
stays the authority for the producer's own validation, so a rule that moves
here keeps its model check.

The schema dumps the property name the document publishes: it names
``party_relation.controlling_party`` through the model's serialization alias.
The model-facing name stays ``controller``, so the prompts and the
structured-output schemas the model answers against keep that name.

The extras stay off the models.  Stage 5 puts ``SafeObservableOutcome`` in its
provider response format, and a guided decoder accepts only a small JSON
Schema subset; the handoff contract's conditional rules would change that
wire.  Rules that JSON Schema cannot state stay model-only: the procedure step
numbering and ``leads_to`` chain, the taxonomy reference order, and the prose
checks that depend on the handoff's own vocabulary.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.stpa.observation_contract import _CLAIM_EVIDENCE
from asago_scenario_generator.stpa.scenario_prod.handoff import ScenarioHandoffV6

#: The safe-outcome rules JSON Schema can state.  ``SafeObservableOutcome``
#: enforces the same rules for a Pydantic reader; the published schema carries
#: these blocks so a schema-only reader reaches the same verdict.  An empty
#: ``call_arguments`` list states no value and the model turns it into an
#: absent field, so each rule treats an empty list as absent.
_SAFE_OUTCOME_SCHEMA_RULES: list[dict[str, Any]] = [
    {
        "if": {
            "properties": {"observable": {"const": True}},
            "required": ["observable"],
        },
        "then": {"required": ["claim_level", "evidence"]},
    },
    *[
        {
            "if": {
                "properties": {"claim_level": {"const": claim_level}},
                "required": ["claim_level"],
            },
            "then": {"properties": {"evidence": {"const": evidence}}},
        }
        for claim_level, evidence in _CLAIM_EVIDENCE.items()
    ],
    {
        "if": {
            "properties": {"observable": {"const": False}},
            "required": ["observable"],
        },
        "then": {
            "properties": {
                "claim_level": {"type": "null"},
                "evidence": {"type": "null"},
                "operation_name": {"type": "null"},
                "call_made": {"type": "null"},
                "call_arguments": {"maxItems": 0},
                "record_refs": {"maxItems": 0},
                "fact_refs": {"maxItems": 0},
            }
        },
    },
    {
        "if": {
            "properties": {"call_made": {"type": "boolean"}},
            "required": ["call_made"],
        },
        "then": {
            "required": ["claim_level", "operation_name"],
            "properties": {
                "claim_level": {"const": "command_attempt"},
                "operation_name": {"type": "string"},
            },
        },
    },
    {
        "if": {
            "properties": {"call_arguments": {"minItems": 1}},
            "required": ["call_arguments"],
        },
        "then": {
            "required": ["claim_level", "operation_name"],
            "properties": {
                "claim_level": {"const": "command_attempt"},
                "operation_name": {"type": "string"},
            },
        },
    },
    {
        "if": {
            "properties": {"call_made": {"const": False}},
            "required": ["call_made"],
        },
        "then": {"properties": {"call_arguments": {"maxItems": 0}}},
    },
    {
        "properties": {
            "statement": {"pattern": r"\S"},
            "operation_name": {"pattern": r"\S"},
            "record_refs": {"items": {"pattern": r"\S"}, "uniqueItems": True},
            "fact_refs": {"items": {"pattern": r"\S"}, "uniqueItems": True},
            "call_arguments": {
                "items": {"properties": {"argument": {"pattern": r"\S"}}}
            },
        }
    },
]

#: A procedure step names its ATLAS tactic exactly when it names its technique.
#: The rule sits on the envelope so a schema reader reports it at the root,
#: where ``validate_procedure_chain`` reports it.
_PROCEDURE_TACTIC_TECHNIQUE_PAIRING: dict[str, Any] = {
    "if": {
        "properties": {"procedure": {"type": "array"}},
        "required": ["procedure"],
    },
    "then": {
        "properties": {
            "procedure": {
                "items": {
                    "allOf": [
                        {
                            "if": {"properties": {"tactic": {"type": "object"}}},
                            "then": {"properties": {"technique": {"type": "object"}}},
                        },
                        {
                            "if": {"properties": {"technique": {"type": "object"}}},
                            "then": {"properties": {"tactic": {"type": "object"}}},
                        },
                    ]
                }
            }
        }
    },
}


def handoff_schema() -> dict[str, Any]:
    """Return the published handoff schema: the model's shape plus its rules.

    The schema publishes the serialization aliases, so the party field reads
    ``controlling_party``.  Pydantic builds a fresh mapping on every call, so the
    additions never reach the model's own ``model_json_schema()``.
    """

    schema = ScenarioHandoffV6.model_json_schema(by_alias=True)
    safe_outcome = schema["$defs"]["SafeObservableOutcome"]
    safe_outcome["allOf"] = [
        *safe_outcome.get("allOf", []),
        *_SAFE_OUTCOME_SCHEMA_RULES,
    ]
    schema["$defs"]["HandoffTaxonomy"]["properties"]["references"]["uniqueItems"] = True
    schema["allOf"].append(_PROCEDURE_TACTIC_TECHNIQUE_PAIRING)
    return schema

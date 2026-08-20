"""Tests for Stream B Slice 5 — canonical standalone projection export.

Covers STPA-PROJ-05-01 through STPA-PROJ-05-04 from the Gherkin feature
file: canonical JSON/YAML serialization with stable identifiers, typed
provenance, byte stability, and round-trip rejection of forged identity
and provenance.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
import yaml

from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.projection import (
    SCHEMA_VERSION,
    export_projection_json,
    export_projection_yaml,
    validate_exported_projection,
)
from tests.stpa.helpers import make_minimal_control_structure

CONTROLLER = "RESP-1"
CONTROL_ACTION = "CA-1-1"
UCA_TYPE = UCAType.wrong_timing
CANDIDATE_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
UCA_REF = "RESP-1:CA-1-1:WRONG_TIMING"

_ALLOWED_STRUCTURAL_REFERENCES = {"RESP-1", "PM-1-1", "FB-1-1", "CA-1-1"}
_STRUCTURAL_ID = re.compile(r"\b(RESP|PM|FB|CA)-\d+(?:-\d+)?")


def _envelope() -> CandidateExecutionEnvelope:
    return assemble_candidate_envelope(
        make_minimal_control_structure(),
        controller_id=CONTROLLER,
        control_action_id=CONTROL_ACTION,
        uca_type=UCA_TYPE,
        causal_factors=[
            CausalFactor(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-1-1",
                description="PM-1-1",
            ),
            CausalFactor(
                kind=CausalFactorKind.feedback_delay,
                source_id="FB-1-1",
                description="FB-1-1",
            ),
        ],
        derive_temporal_vector=True,
    )


def _json_export() -> str:
    return export_projection_json(_envelope())


def _yaml_export() -> str:
    return export_projection_yaml(_envelope())


def _iter_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _iter_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_dicts(child)


class TestProj0501StandaloneEquivalentExports:
    """STPA-PROJ-05-01: canonical JSON and YAML exports are standalone."""

    def test_both_exports_declare_schema_version(self):
        """Both exports declare schema version stpa-execution-projection-v1."""
        json_doc = json.loads(_json_export())
        yaml_doc = yaml.safe_load(_yaml_export())
        assert json_doc["schema_version"] == SCHEMA_VERSION
        assert yaml_doc["schema_version"] == SCHEMA_VERSION

    def test_both_exports_identify_candidate(self):
        """Both exports identify candidate EXEC:RESP-1:CA-1-1:WRONG_TIMING."""
        json_doc = json.loads(_json_export())
        yaml_doc = yaml.safe_load(_yaml_export())
        assert json_doc["candidate_id"] == CANDIDATE_ID
        assert yaml_doc["candidate_id"] == CANDIDATE_ID

    def test_both_exports_identify_uca_reference(self):
        """Both exports identify UCA reference RESP-1:CA-1-1:WRONG_TIMING."""
        json_doc = json.loads(_json_export())
        yaml_doc = yaml.safe_load(_yaml_export())
        assert json_doc["uca_ref"] == UCA_REF
        assert yaml_doc["uca_ref"] == UCA_REF

    def test_standard_readers_yield_equivalent_data(self):
        """JSON and YAML exports parse to equivalent plain data."""
        assert json.loads(_json_export()) == yaml.safe_load(_yaml_export())

    def test_parsing_needs_no_project_imports(self):
        """Parsed exports contain only standard JSON/YAML value types."""
        doc = json.loads(_json_export())
        for node in _iter_dicts(doc):
            for key, value in node.items():
                assert key.__class__ is str
                assert value.__class__ in (
                    str,
                    int,
                    float,
                    bool,
                    type(None),
                    list,
                    dict,
                ), f"non-standard value {value!r} for key {key!r}"
        lists = [doc["causal_factors"], doc["assertions"], doc["steps"]]
        for items in lists:
            for item in items:
                assert item.__class__ is dict


class TestProj0502StableIdentifiersAndProvenance:
    """STPA-PROJ-05-02: stable IDs, order, and typed provenance."""

    def _doc(self) -> dict:
        return json.loads(_json_export())

    def test_assertion_ids_in_order(self):
        """The export contains assertion IDs TA-1, TA-2 in order."""
        doc = self._doc()
        assert [a["assertion_id"] for a in doc["assertions"]] == ["TA-1", "TA-2"]

    def test_step_ids_in_order(self):
        """The export contains step IDs S-1, S-2, S-3 in order."""
        doc = self._doc()
        assert [s["step_id"] for s in doc["steps"]] == ["S-1", "S-2", "S-3"]

    def test_assertion_typed_provenance(self):
        """TA-1 has typed provenance causal_factor/PM-1-1."""
        doc = self._doc()
        assertion = doc["assertions"][0]
        assert assertion["assertion_id"] == "TA-1"
        assert assertion["source_kind"] == "causal_factor"
        assert assertion["source_id"] == "PM-1-1"

    def test_factor_step_typed_provenance(self):
        """S-2 has typed provenance causal_factor/FB-1-1."""
        doc = self._doc()
        step = doc["steps"][1]
        assert step["step_id"] == "S-2"
        assert step["source_kind"] == "causal_factor"
        assert step["source_id"] == "FB-1-1"

    def test_uca_step_typed_provenance(self):
        """S-3 has typed provenance unsafe_control_action/CA-1-1."""
        doc = self._doc()
        step = doc["steps"][2]
        assert step["step_id"] == "S-3"
        assert step["source_kind"] == "unsafe_control_action"
        assert step["source_id"] == "CA-1-1"

    def test_structural_references_are_limited(self):
        """Every exported structural reference is one of the four IDs."""
        doc = self._doc()
        found: set[str] = set()
        for node in _iter_dicts(doc):
            for value in node.values():
                if isinstance(value, str):
                    found.update(
                        match.group(0) for match in _STRUCTURAL_ID.finditer(value)
                    )
        assert found <= _ALLOWED_STRUCTURAL_REFERENCES


class TestProj0503ByteStability:
    """STPA-PROJ-05-03: canonical exports are byte-stable."""

    def test_json_exports_are_byte_identical(self):
        """Two JSON exports for the same envelope are byte-identical."""
        assert _json_export() == _json_export()

    def test_yaml_exports_are_byte_identical(self):
        """Two YAML exports for the same envelope are byte-identical."""
        assert _yaml_export() == _yaml_export()

    def test_json_object_keys_use_canonical_ordering(self):
        """Every JSON object uses canonical sorted key ordering."""
        doc = json.loads(_json_export())
        for node in _iter_dicts(doc):
            assert list(node.keys()) == sorted(node.keys())

    def test_yaml_list_ordering_is_unsorted(self):
        """YAML keeps assertions and steps ordered, never sorted by text."""
        doc = yaml.safe_load(_yaml_export())
        assert [a["assertion_id"] for a in doc["assertions"]] == ["TA-1", "TA-2"]
        assert [s["step_id"] for s in doc["steps"]] == ["S-1", "S-2", "S-3"]
        assert [s["source_id"] for s in doc["steps"]] == [
            "PM-1-1",
            "FB-1-1",
            "CA-1-1",
        ]


class TestProj0504RoundTripForgeryRejection:
    """STPA-PROJ-05-04: round-trip rejects forged identity and provenance."""

    @pytest.mark.parametrize(
        ("mutation", "expected_error"),
        [
            ("changing candidate_id to another EXEC ID", "candidate_identity_mismatch"),
            ("changing assertion TA-1 source_id", "assertion_source_mismatch"),
            ("changing step S-3 source_id", "uca_step_mismatch"),
            ("changing provenance source_kind", "typed_provenance_mismatch"),
            ("removing schema_version", "schema_version_missing"),
        ],
    )
    def test_mutated_export_fails_validation(self, mutation, expected_error):
        """Each forged-field mutation is rejected with the exact typed error."""
        doc = json.loads(_json_export())
        if mutation == "changing candidate_id to another EXEC ID":
            doc["candidate_id"] = "EXEC:RESP-2:CA-1-1:WRONG_TIMING"
        elif mutation == "changing assertion TA-1 source_id":
            doc["assertions"][0]["source_id"] = "FB-1-1"
        elif mutation == "changing step S-3 source_id":
            doc["steps"][2]["source_id"] = "CA-9-9"
        elif mutation == "changing provenance source_kind":
            doc["assertions"][0]["source_kind"] = "unsafe_control_action"
        elif mutation == "removing schema_version":
            del doc["schema_version"]
        result = validate_exported_projection(doc)
        assert result.valid is False
        codes = {violation.code.value for violation in result.violations}
        assert expected_error in codes, codes

    def test_unmutated_round_trip_is_valid(self):
        """A faithful export round-trips and validates cleanly."""
        doc = json.loads(_json_export())
        result = validate_exported_projection(doc)
        assert result.valid is True
        assert result.violations == []

    def test_yaml_round_trip_is_valid_too(self):
        """A YAML-parsed export validates identically."""
        doc = yaml.safe_load(_yaml_export())
        result = validate_exported_projection(doc)
        assert result.valid is True

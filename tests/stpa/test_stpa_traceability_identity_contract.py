"""Tests for the traceability and identity contract (STPA-TRACEABILITY).

Canonical projection validation fails closed for absent vector keys while
present-empty vectors remain valid.  Candidate identity, ICA identity,
and scenario identity are distinct fields in the canonical exports, and
exports round-trip through standard readers under the same typed rules.
"""

from __future__ import annotations

import json

import pytest
import yaml

from asago_scenario_generator.stpa.models.execution_envelope import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.execution_projection import (
    StpaProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.scenario_prod.projection import (
    SCHEMA_VERSION,
    canonical_projection_data,
    export_projection_json,
    export_projection_yaml,
    project_execution,
    validate_exported_projection,
    validate_projection_traceability,
)
from tests.stpa.helpers import make_minimal_control_structure

UCA_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = "RESP-1:CA-1-1:WRONG_TIMING:1"
CANDIDATE_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
UCA_REF = "RESP-1:CA-1-1:WRONG_TIMING"


def _spec(causal_factors: list[CausalFactor] | None = None) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=UCA_SLOT,
            provenance="structural",
            ica_id=ICA_ID,
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.wrong_timing,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="b", vulnerability="v")],
            desires=[DefenderDesire(resp_id="RESP-1", content="d")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="i")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="loss",
        causal_factors=causal_factors or [],
    )


def _two_factor_doc() -> dict:
    spec = _spec(
        [
            CausalFactor(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-1-1",
                description="evidence:PM-1-1",
            ),
            CausalFactor(
                kind=CausalFactorKind.feedback_delay,
                source_id="FB-1-1",
                description="evidence:FB-1-1",
            ),
        ]
    )
    return canonical_projection_data(
        project_execution(spec, make_minimal_control_structure())
    )


class TestAbsentVectorsFailClosed:
    """STPA-TRACEABILITY-01: absent projection vectors are typed violations."""

    @pytest.mark.parametrize(
        ("key", "violation_code"),
        [
            ("causal_factors", "causal_factors_missing"),
            ("assertions", "assertions_missing"),
            ("steps", "steps_missing"),
        ],
    )
    def test_missing_key_fails_closed(self, key, violation_code):
        """A missing vector key yields its typed violation naming the key."""
        doc = _two_factor_doc()
        del doc[key]
        result = validate_projection_traceability(doc)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert violation_code in codes
        matching = [
            v for v in result.violations if v.code.value == violation_code
        ]
        assert matching[0].element_id == key

    def test_null_vector_fails_closed_too(self):
        """A null vector value is treated as missing, never as empty."""
        doc = _two_factor_doc()
        doc["steps"] = None
        result = validate_projection_traceability(doc)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert "steps_missing" in codes


class TestPresentEmptyVectorsValid:
    """STPA-TRACEABILITY-02: present-empty vectors remain valid."""

    def test_present_empty_is_valid_with_no_violations(self):
        """Explicit empty lists validate cleanly with no invented provenance."""
        doc = {
            "schema_version": SCHEMA_VERSION,
            "candidate_id": CANDIDATE_ID,
            "controller_id": "RESP-1",
            "control_action_id": "CA-1-1",
            "uca_type": "WRONG_TIMING",
            "uca_ref": UCA_REF,
            "causal_factors": [],
            "assertions": [],
            "steps": [],
        }
        result = validate_projection_traceability(doc)
        assert result.valid is True
        assert result.violations == []

    def test_empty_project_execution_doc_is_valid(self):
        """An empty project_execution projection round-trips valid."""
        spec = _spec([])
        doc = canonical_projection_data(
            project_execution(spec, make_minimal_control_structure())
        )
        assert doc["causal_factors"] == []
        result = validate_projection_traceability(doc)
        assert result.valid is True


class TestTypedValidationRejectsForgedLinks:
    """STPA-TRACEABILITY-03: forged links are typed violations."""

    @pytest.mark.parametrize(
        ("mutation", "violation_code"),
        [
            (
                lambda doc: doc.__setitem__(
                    "candidate_id", "EXEC:RESP-9:CA-1-1:WRONG_TIMING"
                ),
                "candidate_identity_mismatch",
            ),
            (
                lambda doc: doc.__setitem__(
                    "uca_ref", "RESP-9:CA-1-1:WRONG_TIMING"
                ),
                "candidate_identity_mismatch",
            ),
            ("assertion_source", "assertion_source_mismatch"),
            ("step_source", "uca_step_mismatch"),
            ("assertion_provenance", "typed_provenance_mismatch"),
            ("step_provenance", "typed_provenance_mismatch"),
            ("schema", "schema_version_missing"),
            ("empty_steps_with_factors", "uca_step_mismatch"),
        ],
    )
    def test_mutated_doc_rejected_with_typed_code(
        self, mutation, violation_code
    ):
        """Each forged field produces its exact typed violation."""
        doc = _two_factor_doc()
        if callable(mutation):
            mutation(doc)
        elif mutation == "assertion_source":
            doc["assertions"][1]["source_id"] = "PM-9-9"
        elif mutation == "step_source":
            doc["steps"][-1]["source_id"] = "CA-9-9"
        elif mutation == "assertion_provenance":
            doc["assertions"][0]["source_kind"] = "unsafe_control_action"
        elif mutation == "step_provenance":
            doc["steps"][0]["source_kind"] = "unsafe_control_action"
        elif mutation == "schema":
            del doc["schema_version"]
        elif mutation == "empty_steps_with_factors":
            doc["steps"] = []
        result = validate_projection_traceability(doc)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert violation_code in codes, codes

    def test_assertion_source_mutation_identifies_earliest_element(self):
        """The assertion source violation names the earliest TA element."""
        doc = _two_factor_doc()
        doc["assertions"][1]["source_id"] = "PM-9-9"
        result = validate_projection_traceability(doc)
        matching = [
            v
            for v in result.violations
            if v.code == StpaProjectionTraceabilityViolationCode.assertion_source_mismatch
        ]
        assert matching
        assert matching[0].element_id == "TA-2"

    def test_forged_uca_ref_identifies_the_ref(self):
        """A forged UCA reference names the forged ref value as element."""
        doc = _two_factor_doc()
        doc["uca_ref"] = "RESP-9:CA-1-1:WRONG_TIMING"
        result = validate_projection_traceability(doc)
        assert result.valid is False
        matching = [
            v
            for v in result.violations
            if v.code == StpaProjectionTraceabilityViolationCode.candidate_identity_mismatch
        ]
        assert matching
        assert matching[0].element_id == "RESP-9:CA-1-1:WRONG_TIMING"

    def test_forged_step_provenance_identifies_the_step(self):
        """A forged step provenance names the earliest affected S-* element."""
        doc = _two_factor_doc()
        doc["steps"][0]["source_kind"] = "unsafe_control_action"
        result = validate_projection_traceability(doc)
        assert result.valid is False
        matching = [
            v
            for v in result.violations
            if v.code == StpaProjectionTraceabilityViolationCode.typed_provenance_mismatch
        ]
        assert matching
        assert matching[0].element_id == "S-1"

    def test_empty_steps_with_factors_is_uca_step_mismatch(self):
        """Factors present but no steps is a fail-closed uca_step_mismatch."""
        doc = _two_factor_doc()
        doc["steps"] = []
        result = validate_projection_traceability(doc)
        assert result.valid is False
        matching = [
            v
            for v in result.violations
            if v.code == StpaProjectionTraceabilityViolationCode.uca_step_mismatch
        ]
        assert matching
        assert matching[0].element_id == "steps"


class TestIdentitySeparation:
    """STPA-TRACEABILITY-04: candidate, ICA, and scenario identities differ."""

    def _exports(self):
        doc = _two_factor_doc()
        return (
            json.loads(export_projection_json(doc)),
            yaml.safe_load(export_projection_yaml(doc)),
        )

    def test_exports_retain_candidate_and_separate_identities(self):
        """Both exports carry candidate, ICA, and scenario in own fields."""
        json_doc, yaml_doc = self._exports()
        for doc in (json_doc, yaml_doc):
            assert doc["candidate_id"] == CANDIDATE_ID
            assert doc["ica_id"] == ICA_ID
            assert doc["scenario_id"] == "SCN-001"

    def test_changing_scenario_id_does_not_change_candidate_id(self):
        """Editing the scenario identity never rewrites the candidate ID."""
        json_doc, _ = self._exports()
        json_doc["scenario_id"] = "SCN-999"
        assert json_doc["candidate_id"] == CANDIDATE_ID

    def test_changing_ica_id_does_not_change_candidate_id(self):
        """Editing the ICA identity never rewrites the candidate ID."""
        json_doc, _ = self._exports()
        json_doc["ica_id"] = "RESP-1:CA-1-1:INCORRECT:9"
        assert json_doc["candidate_id"] == CANDIDATE_ID


class TestCanonicalRoundTrip:
    """STPA-TRACEABILITY-05: canonical projection round-trips without objects."""

    def test_repeated_exports_are_byte_identical(self):
        """JSON and YAML exports are each byte-identical on repetition."""
        doc = _two_factor_doc()
        assert export_projection_json(doc) == export_projection_json(doc)
        assert export_projection_yaml(doc) == export_projection_yaml(doc)

    def test_order_preserved_in_json_and_yaml(self):
        """Causal-factor, assertion, and step order survive both formats."""
        doc = _two_factor_doc()
        for parsed in (
            json.loads(export_projection_json(doc)),
            yaml.safe_load(export_projection_yaml(doc)),
        ):
            assert [f["source_id"] for f in parsed["causal_factors"]] == [
                "PM-1-1",
                "FB-1-1",
            ]
            assert [a["source_id"] for a in parsed["assertions"]] == [
                "PM-1-1",
                "FB-1-1",
            ]
            assert [s["source_id"] for s in parsed["steps"]] == [
                "PM-1-1",
                "FB-1-1",
                "CA-1-1",
            ]

    def test_parsed_exports_need_only_standard_readers(self):
        """Standard readers parse both exports to plain data."""
        doc = _two_factor_doc()
        parsed = json.loads(export_projection_json(doc))
        assert parsed["schema_version"] == SCHEMA_VERSION

    def test_validating_parsed_export_applies_same_typed_rules(self):
        """A parsed export validates under the same traceability rules."""
        parsed = yaml.safe_load(export_projection_yaml(_two_factor_doc()))
        result = validate_exported_projection(parsed)
        assert result.valid is True

    def test_forged_parsed_export_fails_typed_validation(self):
        """A forged identity in a parsed export is still rejected."""
        parsed = json.loads(export_projection_json(_two_factor_doc()))
        parsed["candidate_id"] = "EXEC:RESP-9:CA-1-1:WRONG_TIMING"
        result = validate_exported_projection(parsed)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert "candidate_identity_mismatch" in codes


class TestConstraintExportInCanonicalDocument:
    """Typed temporal constraints are part of the standalone document."""

    def test_assertion_constraint_is_exported(self):
        """Delay timing exports as a typed delay constraint in canonical data."""
        spec = _spec(
            [
                CausalFactor(
                    kind=CausalFactorKind.feedback_delay,
                    source_id="FB-1-1",
                    description="evidence",
                    declared_timing="delay 250 milliseconds",
                )
            ]
        )
        doc = canonical_projection_data(
            project_execution(spec, make_minimal_control_structure())
        )
        constraint = doc["assertions"][0]["constraint"]
        assert constraint == {
            "type": "delay",
            "delay_ms": 250,
            "reference": "FB-1-1",
        }
        assert doc["assertions"][0]["requires_binding"] is False

    def test_unknown_timing_exports_null_constraint_with_binding(self):
        """Unknown timing exports null constraint and requires_binding true."""
        spec = _spec(
            [
                CausalFactor(
                    kind=CausalFactorKind.feedback_delay,
                    source_id="FB-1-1",
                    description="evidence",
                    declared_timing="unknown",
                )
            ]
        )
        doc = canonical_projection_data(
            project_execution(spec, make_minimal_control_structure())
        )
        assert doc["assertions"][0]["constraint"] is None
        assert doc["assertions"][0]["requires_binding"] is True

    def test_uca_constraint_is_exported(self):
        """The explicit UCA outcome mapping is part of the document."""
        doc = _two_factor_doc()
        assert doc["uca_constraint"] == {
            "type": "uca_outcome",
            "control_action_id": "CA-1-1",
            "uca_type": "WRONG_TIMING",
        }

    def test_forged_uca_constraint_fails_closed(self):
        """A forged outcome mapping is a typed uca_constraint mismatch."""
        doc = _two_factor_doc()
        doc["uca_constraint"] = {
            "type": "uca_outcome",
            "control_action_id": "CA-9-9",
            "uca_type": "WRONG_TIMING",
        }
        result = validate_projection_traceability(doc)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert StpaProjectionTraceabilityViolationCode.uca_constraint_mismatch.value in codes
        matching = [
            v
            for v in result.violations
            if v.code == StpaProjectionTraceabilityViolationCode.uca_constraint_mismatch
        ]
        assert matching[0].element_id == "uca_constraint"


class TestViolationCodesStable:
    """New fail-closed codes are typed and stable."""

    def test_missing_vector_codes_exist(self):
        """The three missing-vector codes are part of the enum."""
        assert (
            StpaProjectionTraceabilityViolationCode.causal_factors_missing.value
            == "causal_factors_missing"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.assertions_missing.value
            == "assertions_missing"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.steps_missing.value
            == "steps_missing"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.uca_constraint_mismatch.value
            == "uca_constraint_mismatch"
        )

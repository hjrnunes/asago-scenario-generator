"""Tests for Stream B Slice 3 — STPA projection traceability validation.

Covers STPA-PROJ-03-01 through STPA-PROJ-03-05 from the Gherkin feature
file: deterministic traceability between causal factors, UCAs, and the
execution-envelope assertions/steps, with typed violation codes aligned
with the taxonomy ``projection_validation`` contract.
"""

from __future__ import annotations

import json

import pytest

from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    CausalFactor,
    CausalFactorKind,
    predicate_for,
    step_kind_for,
)
from asago_scenario_generator.stpa.models.execution_projection import (
    StpaProjectionTraceabilityResult,
    StpaProjectionTraceabilityViolation,
    StpaProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.projection import (
    SCHEMA_VERSION,
    canonical_projection_data,
    canonical_violations_json,
    validate_projection_traceability,
)
from tests.stpa.helpers import make_minimal_control_structure

CONTROLLER = "RESP-1"
CONTROL_ACTION = "CA-1-1"
UCA_TYPE = UCAType.wrong_timing
CANDIDATE_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"


def _factor(kind: CausalFactorKind, source_id: str) -> CausalFactor:
    return CausalFactor(kind=kind, source_id=source_id, description=source_id)


def _two_factor_envelope() -> CandidateExecutionEnvelope:
    """The STPA-PROJ-03 building-blocks envelope: PM-1-1 flaw + FB-1-1 delay."""
    return assemble_candidate_envelope(
        make_minimal_control_structure(),
        controller_id=CONTROLLER,
        control_action_id=CONTROL_ACTION,
        uca_type=UCA_TYPE,
        causal_factors=[
            _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
            _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
        ],
        derive_temporal_vector=True,
    )


def _envelope_doc(
    envelope: CandidateExecutionEnvelope | None = None,
) -> dict:
    """Return the canonical projection document for a test envelope."""
    return canonical_projection_data(envelope or _two_factor_envelope())


def _validate_doc(doc: dict) -> StpaProjectionTraceabilityResult:
    return validate_projection_traceability(doc)


def _mutate(doc: dict, mutation: str) -> str:
    """Apply one named temporal-projection mutation, returning the expected element id."""
    if mutation == "omitting the PM-1-1 assertion":
        doc["assertions"] = [
            a for a in doc["assertions"] if a["source_id"] != "PM-1-1"
        ]
        return "TA-1"
    if mutation == "reordering the PM-1-1 and FB-1-1 assertions":
        doc["assertions"][0], doc["assertions"][1] = (
            doc["assertions"][1],
            doc["assertions"][0],
        )
        return "TA-1"
    if mutation == "changing TA-2 source to PM-1-1":
        _by_id(doc["assertions"], "TA-2")["source_id"] = "PM-1-1"
        return "TA-2"
    if mutation == "changing S-2 source to PM-1-1":
        _by_id(doc["steps"], "S-2")["source_id"] = "PM-1-1"
        return "S-2"
    if mutation == "changing TA-1 predicate to FEEDBACK_DELAYED":
        _by_id(doc["assertions"], "TA-1")["predicate"] = "FEEDBACK_DELAYED"
        return "TA-1"
    if mutation == "changing the final step source to CA-9-9":
        doc["steps"][-1]["source_id"] = "CA-9-9"
        return "S-3"
    raise AssertionError(f"Unknown mutation {mutation!r}")


def _by_id(items: list[dict], identifier: str) -> dict:
    for item in items:
        if item.get("assertion_id") == identifier or item.get("step_id") == identifier:
            return item
    raise AssertionError(f"No projection element {identifier}")


class TestTraceabilityViolationModels:
    """Typed violation codes align with the taxonomy projection_validation shape."""

    def test_violation_codes_are_typed_and_stable(self):
        """Stream B violations use stable snake_case typed codes."""
        assert (
            StpaProjectionTraceabilityViolationCode.omitted_causal_factor.value
            == "omitted_causal_factor"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.reordered_causal_factor.value
            == "reordered_causal_factor"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.assertion_source_mismatch.value
            == "assertion_source_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.step_source_mismatch.value
            == "step_source_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.assertion_predicate_mismatch.value
            == "assertion_predicate_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.uca_step_mismatch.value
            == "uca_step_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.candidate_identity_mismatch.value
            == "candidate_identity_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.typed_provenance_mismatch.value
            == "typed_provenance_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.schema_version_missing.value
            == "schema_version_missing"
        )

    def test_violation_carries_code_detail_and_element_id(self):
        """A violation identifies the affected projection element."""
        violation = StpaProjectionTraceabilityViolation(
            code=StpaProjectionTraceabilityViolationCode.omitted_causal_factor,
            detail="TA-1 is missing",
            element_id="TA-1",
        )
        assert violation.element_id == "TA-1"
        assert violation.detail

    def test_result_flips_valid_when_violations_exist(self):
        """A result with violations is invalid, mirroring the taxonomy contract."""
        result = StpaProjectionTraceabilityResult(
            violations=[
                StpaProjectionTraceabilityViolation(
                    code=StpaProjectionTraceabilityViolationCode.uca_step_mismatch,
                    detail="Final step is missing",
                    element_id="S-3",
                )
            ]
        )
        assert result.valid is False
        assert StpaProjectionTraceabilityResult().valid is True


class TestProj0301ValidTraceability:
    """STPA-PROJ-03-01: valid projection traceability."""

    def test_envelope_is_traceable_with_no_violations(self):
        """A faithful envelope validates cleanly."""
        result = _validate_doc(_envelope_doc())
        assert result.valid is True
        assert result.violations == []

    def test_candidate_identifier_is_canonical(self):
        """The projection candidate identifier is EXEC:RESP-1:CA-1-1:WRONG_TIMING."""
        doc = _envelope_doc()
        assert doc["candidate_id"] == CANDIDATE_ID
        result = _validate_doc(doc)
        assert result.valid is True

    def test_assertion_sources_are_ordered(self):
        """Assertions preserve causal-factor order PM-1-1, FB-1-1."""
        doc = _envelope_doc()
        assert [a["source_id"] for a in doc["assertions"]] == ["PM-1-1", "FB-1-1"]

    def test_factor_scenario_steps_are_ordered(self):
        """Factor steps preserve causal-factor order PM-1-1, FB-1-1."""
        doc = _envelope_doc()
        factor_steps = [
            s for s in doc["steps"] if s["source_kind"] == "causal_factor"
        ]
        assert [s["source_id"] for s in factor_steps] == ["PM-1-1", "FB-1-1"]

    def test_final_step_references_control_action(self):
        """The final scenario step references CA-1-1."""
        doc = _envelope_doc()
        assert doc["steps"][-1]["source_id"] == CONTROL_ACTION
        assert doc["steps"][-1]["step_kind"] == "UNSAFE_CONTROL_ACTION"

    def test_every_assertion_has_canonical_predicate_and_provenance(self):
        """Each assertion carries its canonical predicate and factor provenance."""
        envelope = _two_factor_envelope()
        doc = _envelope_doc(envelope)
        for index, assertion in enumerate(doc["assertions"]):
            factor = envelope.causal_factors[index]
            assert assertion["predicate"] == predicate_for(factor.kind).value
            assert assertion["source_id"] == factor.source_id
            assert assertion["source_kind"] == "causal_factor"
            assert assertion["assertion_id"] == f"TA-{index + 1}"

    def test_validation_accepts_envelope_models_directly(self):
        """The validator accepts an envelope model as well as a document."""
        result = validate_projection_traceability(_two_factor_envelope())
        assert result.valid is True


class TestProj0302MutationRejection:
    """STPA-PROJ-03-02: traceability rejects broken factor-to-vector links."""

    @pytest.mark.parametrize(
        ("mutation", "violation_code", "expected_element"),
        [
            ("omitting the PM-1-1 assertion", "omitted_causal_factor", "TA-1"),
            (
                "reordering the PM-1-1 and FB-1-1 assertions",
                "reordered_causal_factor",
                "TA-1",
            ),
            ("changing TA-2 source to PM-1-1", "assertion_source_mismatch", "TA-2"),
            ("changing S-2 source to PM-1-1", "step_source_mismatch", "S-2"),
            (
                "changing TA-1 predicate to FEEDBACK_DELAYED",
                "assertion_predicate_mismatch",
                "TA-1",
            ),
            ("changing the final step source to CA-9-9", "uca_step_mismatch", "S-3"),
        ],
    )
    def test_mutation_yields_typed_violation_for_earliest_element(
        self, mutation, violation_code, expected_element
    ):
        """Each mutation produces the exact typed code and element."""
        doc = _envelope_doc()
        _mutate(doc, mutation)
        result = _validate_doc(doc)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert violation_code in codes
        matching = [
            v for v in result.violations if v.code.value == violation_code
        ]
        assert matching, f"no violation with code {violation_code}"
        assert matching[0].element_id == expected_element

    @pytest.mark.parametrize(
        "mutation",
        [
            "omitting the PM-1-1 assertion",
            "reordering the PM-1-1 and FB-1-1 assertions",
            "changing TA-2 source to PM-1-1",
        ],
    )
    def test_factor_mapping_emits_at_most_one_violation(self, mutation):
        """The factor-mapping check emits at most one violation per sequence.

        The omission path must short-circuit so the displacement check does
        not also run and invent a second violation for the same sequence.
        """
        doc = _envelope_doc()
        _mutate(doc, mutation)
        result = _validate_doc(doc)
        assert result.valid is False
        factor_mapping_codes = {
            "omitted_causal_factor",
            "reordered_causal_factor",
            "assertion_source_mismatch",
            "step_source_mismatch",
        }
        factor_mapping_violations = [
            v
            for v in result.violations
            if v.code.value in factor_mapping_codes
        ]
        assert len(factor_mapping_violations) == 1, (
            f"factor-mapping check emitted {factor_mapping_violations!r}"
        )


class TestProj0303CandidateIdentityMismatch:
    """STPA-PROJ-03-03: a vector linked to another candidate is rejected."""

    def test_foreign_vector_candidate_identifier_is_rejected(self):
        """Changing the vector candidate id yields candidate_identity_mismatch."""
        doc = _envelope_doc()
        changed = "EXEC:RESP-9:CA-1-1:WRONG_TIMING"
        doc["candidate_id"] = changed
        result = _validate_doc(doc)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert "candidate_identity_mismatch" in codes
        matching = [
            v
            for v in result.violations
            if v.code.value == "candidate_identity_mismatch"
        ]
        assert matching[0].element_id == changed


class TestProj0304EmptyProjection:
    """STPA-PROJ-03-04: an empty causal factor set stays an empty projection."""

    def test_empty_factors_stay_valid_and_empty(self):
        """No factors means no assertions, no steps, and no invented provenance."""
        envelope = assemble_candidate_envelope(
            make_minimal_control_structure(),
            controller_id=CONTROLLER,
            control_action_id=CONTROL_ACTION,
            uca_type=UCA_TYPE,
            causal_factors=[],
            derive_temporal_vector=True,
        )
        doc = _envelope_doc(envelope)
        assert doc["assertions"] == []
        assert doc["steps"] == []
        result = _validate_doc(doc)
        assert result.valid is True
        assert result.violations == []


class TestProj0305Determinism:
    """STPA-PROJ-03-05: traceability validation is deterministic."""

    def test_repeated_validation_has_same_validity(self):
        """Two validations of the same document agree on validity."""
        doc = _envelope_doc()
        first = _validate_doc(doc)
        second = _validate_doc(doc)
        assert first.valid == second.valid

    def test_repeated_validation_has_byte_identical_violations(self):
        """Canonical violations are byte-identical across runs."""
        doc = _envelope_doc()
        _mutate(doc, "changing S-2 source to PM-1-1")
        first = _validate_doc(doc)
        second = _validate_doc(doc)
        assert canonical_violations_json(first) == canonical_violations_json(second)

    def test_canonical_violations_are_stable_json(self):
        """Canonical violations serialize with sorted keys and no newlines."""
        doc = _envelope_doc()
        _mutate(doc, "changing the final step source to CA-9-9")
        result = _validate_doc(doc)
        payload = json.loads(canonical_violations_json(result))
        assert payload[0]["code"] == "uca_step_mismatch"
        assert payload[0]["element_id"] == "S-3"

    def test_canonical_violations_escape_non_ascii_details(self):
        """Canonical violation JSON is ASCII-safe for any detail text.

        Byte stability requires non-ASCII detail characters to be escaped
        so the canonical payload is portable across readers.
        """
        result = StpaProjectionTraceabilityResult(
            violations=[
                StpaProjectionTraceabilityViolation(
                    code=StpaProjectionTraceabilityViolationCode.uca_step_mismatch,
                    detail="final step \u00e9 mismatch",
                    element_id="S-3",
                )
            ]
        )
        payload = canonical_violations_json(result)
        assert "\u00e9" not in payload
        assert "\\u00e9" in payload
        assert json.loads(payload)[0]["detail"] == "final step \u00e9 mismatch"


class TestCanonicalDocument:
    """The canonical projection document underpins validation and export."""

    def test_document_declares_schema_version(self):
        """The canonical document declares the v1 schema version."""
        doc = _envelope_doc()
        assert doc["schema_version"] == SCHEMA_VERSION

    def test_document_identifies_uca_reference(self):
        """The canonical document carries the UCA reference."""
        doc = _envelope_doc()
        assert doc["uca_ref"] == "RESP-1:CA-1-1:WRONG_TIMING"

    def test_validation_requires_schema_version(self):
        """Removing the schema version is a typed missing-schema violation."""
        doc = _envelope_doc()
        del doc["schema_version"]
        result = _validate_doc(doc)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert "schema_version_missing" in codes

    def test_typed_provenance_is_validated(self):
        """Forged provenance source kinds are typed provenance mismatches."""
        doc = _envelope_doc()
        doc["assertions"][0]["source_kind"] = "unsafe_control_action"
        result = _validate_doc(doc)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert "typed_provenance_mismatch" in codes
        matching = [
            v
            for v in result.violations
            if v.code.value == "typed_provenance_mismatch"
        ]
        assert matching[0].element_id == "TA-1"

    def test_document_maps_every_step_to_canonical_kind(self):
        """Factor steps use step_kind_for mapping; the UCA step is last."""
        envelope = _two_factor_envelope()
        doc = _envelope_doc(envelope)
        for index, step in enumerate(doc["steps"][:2]):
            factor = envelope.causal_factors[index]
            assert step["step_kind"] == step_kind_for(factor.kind).value
            assert step["source_id"] == factor.source_id
        assert doc["steps"][-1]["step_kind"] == "UNSAFE_CONTROL_ACTION"

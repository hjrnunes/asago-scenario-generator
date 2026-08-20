"""Property tests for the Stream B STPA execution projection contract.

These Hypothesis properties cover the invariants that the example-based
Stream B tests only spot-check: deterministic validation, canonical
ordering and conservation, standalone round-trip equivalence, byte
stability, plain-data independence, and forged-data rejection.  The
strategies draw permutations of subsets of the building-blocks causal
factors (PM-1-1, FB-1-1 with one feedback kind, CA-1-1) so every
generated envelope assembles against the shared minimal control
structure.
"""

from __future__ import annotations

import json

import pytest
import yaml
from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    CausalFactor,
    CausalFactorKind,
    predicate_for,
    step_kind_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.projection import (
    canonical_projection_data,
    canonical_violations_json,
    export_projection_json,
    export_projection_yaml,
    validate_exported_projection,
    validate_projection_traceability,
)
from asago_scenario_generator.stpa.scenario_prod.prompt_alignment import (
    derive_projection_alignment_rows,
    render_projection_alignment_table,
)
from tests.stpa.helpers import make_minimal_control_structure

CONTROLLER = "RESP-1"
CONTROL_ACTION = "CA-1-1"
UCA_TYPE = UCAType.wrong_timing

_PLAIN_TYPES = (str, int, float, bool, type(None))


def _is_plain_data(value: object) -> bool:
    """True when the value is plain JSON/YAML data (no project objects)."""
    if isinstance(value, dict):
        return all(
            key.__class__ is str and _is_plain_data(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return all(_is_plain_data(child) for child in value)
    return value.__class__ in _PLAIN_TYPES


@st.composite
def st_factor_lists(draw) -> list[CausalFactor]:
    """Draw a permutation of a subset of the building-blocks causal factors.

    Each source identifier (PM-1-1, FB-1-1, CA-1-1) is used at most once so
    the generated factor list has distinct source identifiers and every
    factor validates against the shared minimal control structure.
    """
    include_pm = draw(st.booleans())
    fb_kind = draw(
        st.sampled_from(
            [None, CausalFactorKind.feedback_delay, CausalFactorKind.sensor_anomaly]
        )
    )
    include_ca = draw(st.booleans())
    chosen: list[tuple[CausalFactorKind, str]] = []
    if include_pm:
        chosen.append((CausalFactorKind.process_model_flaw, "PM-1-1"))
    if fb_kind is not None:
        chosen.append((fb_kind, "FB-1-1"))
    if include_ca:
        chosen.append((CausalFactorKind.actuator_anomaly, "CA-1-1"))
    ordered = draw(st.permutations(chosen))
    return [
        CausalFactor(kind=kind, source_id=source_id, description=source_id)
        for kind, source_id in ordered
    ]


def _envelope(factors: list[CausalFactor]) -> CandidateExecutionEnvelope:
    return assemble_candidate_envelope(
        make_minimal_control_structure(),
        controller_id=CONTROLLER,
        control_action_id=CONTROL_ACTION,
        uca_type=UCA_TYPE,
        causal_factors=factors,
        derive_temporal_vector=True,
    )


# ---------------------------------------------------------------------------#
# Determinism / idempotence
# ---------------------------------------------------------------------------#


class TestProjectionDeterminism:
    """Validation and derivation are deterministic over the input space."""

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_repeated_validation_is_identical(self, factors):
        """Two validations of the same canonical document agree exactly."""
        doc = canonical_projection_data(_envelope(factors))
        first = validate_projection_traceability(doc)
        second = validate_projection_traceability(doc)
        assert first.valid == second.valid
        assert canonical_violations_json(first) == canonical_violations_json(second)

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_envelope_and_doc_validate_identically(self, factors):
        """Validating the model and its canonical document agree exactly."""
        envelope = _envelope(factors)
        doc = canonical_projection_data(envelope)
        assert validate_projection_traceability(envelope) == \
            validate_projection_traceability(doc)


# ---------------------------------------------------------------------------#
# Canonical ordering and conservation
# ---------------------------------------------------------------------------#


class TestProjectionOrderingAndConservation:
    """The canonical document preserves dense ordering and factor conservation."""

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_faithful_projection_always_valid(self, factors):
        """Every faithfully assembled envelope validates with no violations."""
        result = validate_projection_traceability(_envelope(factors))
        assert result.valid is True
        assert result.violations == []

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_assertion_and_step_ids_are_dense_and_ordered(self, factors):
        """Assertion IDs are TA-1..TA-n and step IDs are S-1..S-(n+1)."""
        envelope = _envelope(factors)
        doc = canonical_projection_data(envelope)
        n = len(factors)
        assert [a["assertion_id"] for a in doc["assertions"]] == [
            f"TA-{i + 1}" for i in range(n)
        ]
        assert [a["order"] for a in doc["assertions"]] == list(range(1, n + 1))
        step_count = n + (1 if factors else 0)
        assert [s["step_id"] for s in doc["steps"]] == [
            f"S-{i + 1}" for i in range(step_count)
        ]
        assert [s["order"] for s in doc["steps"]] == list(range(1, step_count + 1))

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_factor_order_is_preserved(self, factors):
        """Assertions and factor steps preserve causal-factor order."""
        envelope = _envelope(factors)
        doc = canonical_projection_data(envelope)
        sources = [f.source_id for f in envelope.causal_factors]
        assert [a["source_id"] for a in doc["assertions"]] == sources
        factor_steps = [
            s for s in doc["steps"] if s["source_kind"] == "causal_factor"
        ]
        assert [s["source_id"] for s in factor_steps] == sources

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_factor_count_is_conserved(self, factors):
        """Factor, assertion, and factor-step counts are equal."""
        envelope = _envelope(factors)
        doc = canonical_projection_data(envelope)
        n = len(factors)
        assert len(doc["causal_factors"]) == n
        assert len(doc["assertions"]) == n
        factor_steps = [
            s for s in doc["steps"] if s["source_kind"] == "causal_factor"
        ]
        assert len(factor_steps) == n
        if factors:
            assert doc["steps"][-1]["step_kind"] == "UNSAFE_CONTROL_ACTION"
            assert doc["steps"][-1]["source_id"] == CONTROL_ACTION
        else:
            assert doc["steps"] == []
            assert doc["assertions"] == []


# ---------------------------------------------------------------------------#
# Standalone export: round-trip, byte stability, plain-data independence
# ---------------------------------------------------------------------------#


class TestProjectionExportProperties:
    """Canonical JSON/YAML exports are standalone, equivalent, and byte-stable."""

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_json_and_yaml_exports_are_equivalent(self, factors):
        """Standard readers parse both exports to equal plain data."""
        envelope = _envelope(factors)
        json_doc = json.loads(export_projection_json(envelope))
        yaml_doc = yaml.safe_load(export_projection_yaml(envelope))
        assert json_doc == yaml_doc

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip_validation_matches_envelope(self, factors):
        """Validating a parsed export equals validating the envelope model."""
        envelope = _envelope(factors)
        json_doc = json.loads(export_projection_json(envelope))
        assert validate_exported_projection(json_doc) == \
            validate_projection_traceability(envelope)
        assert validate_exported_projection(json_doc).valid is True

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_exports_are_byte_stable(self, factors):
        """Repeated exports for the same envelope are byte-identical."""
        envelope = _envelope(factors)
        assert export_projection_json(envelope) == export_projection_json(envelope)
        assert export_projection_yaml(envelope) == export_projection_yaml(envelope)

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_canonical_document_is_plain_data(self, factors):
        """The canonical document contains only standard JSON/YAML types."""
        doc = canonical_projection_data(_envelope(factors))
        assert _is_plain_data(doc)

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_json_object_keys_are_canonical_sorted(self, factors):
        """Every JSON object uses sorted key ordering."""
        doc = json.loads(export_projection_json(_envelope(factors)))
        stack = [doc]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                assert list(node.keys()) == sorted(node.keys())
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)


# ---------------------------------------------------------------------------#
# Validator-derived alignment table
# ---------------------------------------------------------------------------#


class TestProjectionAlignmentProperties:
    """The alignment table derives deterministically from the projection."""

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_alignment_rows_follow_validator_mapping(self, factors):
        """Each factor row mirrors the causal-factor validator mappings."""
        if not factors:
            # An empty projection renders no table; the property is vacuous.
            assert derive_projection_alignment_rows(
                canonical_projection_data(_envelope(factors))
            ) == []
            return
        envelope = _envelope(factors)
        doc = canonical_projection_data(envelope)
        rows = derive_projection_alignment_rows(doc)
        assert len(rows) == len(factors) + 1
        assert [r["source_id"] for r in rows[:-1]] == [
            f.source_id for f in envelope.causal_factors
        ]
        assert rows[-1]["step_kind"] == "UNSAFE_CONTROL_ACTION"
        for index, row in enumerate(rows[:-1]):
            factor = envelope.causal_factors[index]
            assert row["assertion_predicate"] == predicate_for(factor.kind).value
            assert row["step_kind"] == step_kind_for(factor.kind).value
            assert row["assertion_id"] == f"TA-{index + 1}"
            assert row["step_id"] == f"S-{index + 1}"
            assert row["order"] == index + 1

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_alignment_table_is_byte_stable(self, factors):
        """Rendering the table twice yields byte-identical output."""
        doc = canonical_projection_data(_envelope(factors))
        assert render_projection_alignment_table(doc) == \
            render_projection_alignment_table(doc)


# ---------------------------------------------------------------------------#
# Forged / mutated plain data is rejected deterministically
# ---------------------------------------------------------------------------#


class TestProjectionForgedDataRejection:
    """The validator operates on forged/mutated plain data deterministically."""

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_swapped_assertion_sources_are_detected(self, factors):
        """Swapping two assertion sources breaks factor-to-assertion order."""
        if len(factors) < 2:
            pytest.skip("need at least two factors to swap")
        doc = canonical_projection_data(_envelope(factors))
        doc["assertions"][0]["source_id"], doc["assertions"][1]["source_id"] = (
            doc["assertions"][1]["source_id"],
            doc["assertions"][0]["source_id"],
        )
        result = validate_projection_traceability(doc)
        assert result.valid is False

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_foreign_candidate_identifier_is_rejected(self, factors):
        """A foreign candidate identifier is always a typed identity mismatch."""
        doc = canonical_projection_data(_envelope(factors))
        doc["candidate_id"] = "EXEC:RESP-9:CA-1-1:WRONG_TIMING"
        result = validate_projection_traceability(doc)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert "candidate_identity_mismatch" in codes

    @given(factors=st_factor_lists())
    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    def test_missing_schema_version_is_rejected(self, factors):
        """Removing the schema version is always a typed missing-schema error."""
        doc = canonical_projection_data(_envelope(factors))
        doc.pop("schema_version", None)
        result = validate_projection_traceability(doc)
        assert result.valid is False
        codes = {v.code.value for v in result.violations}
        assert "schema_version_missing" in codes

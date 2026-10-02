"""Property-based tests for Stage 6 output quality invariants.

Uses Hypothesis to verify structural properties that hold across broad
input ranges:

- **GherkinSpec rendering**: ``to_feature_text()`` and model round-trips
  keep every field and step.
- **Loss/Hazard ID references**: ``validate_loss_hazard_id_references``
  catches every hallucinated ID and agrees across text and spec inputs.
"""

from __future__ import annotations

import re

from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec
from asago_scenario_generator.stpa.scenario_prod.validators import (
    validate_loss_hazard_id_references,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

st_step_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs", "Cc"),
        blacklist_characters=("\x85", "\u2028", "\u2029", ":", "\n"),
    ),
    min_size=1,
    max_size=50,
).filter(lambda s: not re.search(r"[LH]-\d", s))


def _gherkin_spec_strategy(
    include_pm: bool = True,
    include_should: bool = True,
    include_but: bool = True,
) -> st.SearchStrategy[GherkinSpec]:
    """Build a GherkinSpec strategy with controllable validity flags."""
    given_steps = st.lists(
        st.builds(
            lambda s: f"Given PM-1-1 is {s}" if include_pm else f"Given {s}",
            st_step_text,
        ),
        min_size=1,
        max_size=3,
    )
    then_expected = st.lists(
        st.builds(
            lambda s: f"Then should {s}" if include_should else f"Then {s}",
            st_step_text,
        ),
        min_size=1,
        max_size=2,
    )
    then_actual = st.lists(
        st.builds(
            lambda s: f"But {s}" if include_but else f"Then {s}",
            st_step_text,
        ),
        min_size=1,
        max_size=2,
    )
    return st.builds(
        GherkinSpec,
        feature=st_step_text,
        scenario=st_step_text,
        given=given_steps,
        when=st.lists(
            st.builds(lambda s: f"When {s}", st_step_text),
            min_size=1,
            max_size=2,
        ),
        then_expected=then_expected,
        then_actual=then_actual,
    )


# ---------------------------------------------------------------------------
# GherkinSpec.to_feature_text() round-trip
# ---------------------------------------------------------------------------


class TestGherkinSpecRoundTrip:
    """GherkinSpec serialization and rendering invariants."""

    @given(spec=_gherkin_spec_strategy())
    @settings(
        max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow]
    )
    def test_feature_text_starts_with_feature_keyword(self, spec: GherkinSpec):
        """to_feature_text() always starts with 'Feature:'."""
        text = spec.to_feature_text()
        assert text.startswith(f"Feature: {spec.feature}")

    @given(spec=_gherkin_spec_strategy())
    @settings(
        max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow]
    )
    def test_feature_text_contains_scenario_keyword(self, spec: GherkinSpec):
        """to_feature_text() always contains 'Scenario:'."""
        text = spec.to_feature_text()
        assert f"Scenario: {spec.scenario}" in text

    @given(spec=_gherkin_spec_strategy())
    @settings(
        max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow]
    )
    def test_feature_text_ends_with_newline(self, spec: GherkinSpec):
        """to_feature_text() always ends with a trailing newline."""
        text = spec.to_feature_text()
        assert text.endswith("\n")

    @given(spec=_gherkin_spec_strategy())
    @settings(
        max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow]
    )
    def test_idempotent_render(self, spec: GherkinSpec):
        """Rendering twice produces identical output."""
        assert spec.to_feature_text() == spec.to_feature_text()

    @given(spec=_gherkin_spec_strategy())
    @settings(
        max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow]
    )
    def test_feature_text_contains_all_steps(self, spec: GherkinSpec):
        """to_feature_text() contains every step from every field."""
        text = spec.to_feature_text()
        for step in spec.given + spec.when + spec.then_expected + spec.then_actual:
            assert step in text, f"Step '{step}' missing from feature text"

    @given(spec=_gherkin_spec_strategy())
    @settings(
        max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow]
    )
    def test_pydantic_model_validate_round_trip(self, spec: GherkinSpec):
        """GherkinSpec → model_dump → model_validate → same GherkinSpec."""
        dumped = spec.model_dump(mode="json")
        restored = GherkinSpec.model_validate(dumped)
        assert restored == spec


# ---------------------------------------------------------------------------
# Loss/Hazard ID references
# ---------------------------------------------------------------------------


def _make_loss_analysis_with_ids(
    loss_ids: list[str], hazard_ids: list[str]
) -> LossAnalysis:
    """Build a LossAnalysis with the given IDs for ID-reference tests.

    Always includes at least one hazard and one security constraint to
    satisfy the model's min-items validation.
    """
    all_hazard_ids = hazard_ids if hazard_ids else ["H-0"]
    related = loss_ids[:1] if loss_ids else []
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id=lid,
                description=f"Loss {lid}",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r1"],
            )
            for lid in loss_ids
        ],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id=hid, description=f"Hazard {hid}", related_losses=related)
            for hid in all_hazard_ids
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Constraint",
                related_hazards=all_hazard_ids[:1],
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Loss/Hazard ID reference validator properties
# ---------------------------------------------------------------------------


class TestLossHazardIdValidator:
    """validate_loss_hazard_id_references invariants."""

    @given(
        spec=_gherkin_spec_strategy(),
        loss_ids=st.lists(
            st.builds(lambda n: f"L-{n}", st.integers(min_value=1, max_value=999)),
            min_size=1,
            max_size=5,
            unique=True,
        ),
        hazard_ids=st.lists(
            st.builds(lambda n: f"H-{n}", st.integers(min_value=1, max_value=999)),
            min_size=1,
            max_size=5,
            unique=True,
        ),
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_valid_ids_always_pass(
        self, spec: GherkinSpec, loss_ids: list[str], hazard_ids: list[str]
    ):
        """When no L-*/H-* IDs appear in Gherkin, validation always passes."""
        la = _make_loss_analysis_with_ids(loss_ids, hazard_ids)
        # The spec strategy doesn't inject L-*/H-* IDs, so this should pass
        result = validate_loss_hazard_id_references(spec, la)
        assert result.passed

    @given(
        loss_ids=st.lists(
            st.builds(lambda n: f"L-{n}", st.integers(min_value=1, max_value=99)),
            min_size=1,
            max_size=3,
            unique=True,
        ),
        bad_id=st.builds(
            lambda n: f"L-{n}", st.integers(min_value=1000, max_value=9999)
        ),
    )
    @settings(max_examples=50, deadline=None)
    def test_hallucinated_loss_id_always_caught(self, loss_ids: list[str], bad_id: str):
        """A hallucinated L-* ID is always detected."""
        la = _make_loss_analysis_with_ids(loss_ids, [])
        spec = GherkinSpec(
            feature="F",
            scenario="S",
            given=[f"Given PM-1-1 with {bad_id}"],
            when=["When trigger"],
            then_expected=["Then should respond"],
            then_actual=["But fails"],
        )
        result = validate_loss_hazard_id_references(spec, la)
        assert not result.passed
        assert any(bad_id in e for e in result.errors)

    @given(
        hazard_ids=st.lists(
            st.builds(lambda n: f"H-{n}", st.integers(min_value=1, max_value=99)),
            min_size=1,
            max_size=3,
            unique=True,
        ),
        bad_id=st.builds(
            lambda n: f"H-{n}", st.integers(min_value=1000, max_value=9999)
        ),
    )
    @settings(max_examples=50, deadline=None)
    def test_hallucinated_hazard_id_always_caught(
        self, hazard_ids: list[str], bad_id: str
    ):
        """A hallucinated H-* ID is always detected."""
        la = _make_loss_analysis_with_ids([], hazard_ids)
        spec = GherkinSpec(
            feature="F",
            scenario="S",
            given=[f"Given PM-1-1 causes {bad_id}"],
            when=["When trigger"],
            then_expected=["Then should respond"],
            then_actual=["But fails"],
        )
        result = validate_loss_hazard_id_references(spec, la)
        assert not result.passed
        assert any(bad_id in e for e in result.errors)

    def test_text_input_and_spec_input_agree_on_valid(self):
        """Text and GherkinSpec inputs produce the same pass result for valid IDs."""
        la = _make_loss_analysis_with_ids(["L-1"], ["H-1"])
        spec = GherkinSpec(
            feature="F",
            scenario="S",
            given=["Given PM-1-1 is valid"],
            when=["When trigger"],
            then_expected=["Then should respond"],
            then_actual=["But fails"],
        )
        text_result = validate_loss_hazard_id_references(spec.to_feature_text(), la)
        spec_result = validate_loss_hazard_id_references(spec, la)
        assert text_result.passed == spec_result.passed

"""A field's JSON type is not evidence for the value that makes it unsafe."""

import pytest

from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionValueCondition,
    SemanticBindingPlaceholder,
    ActionPresenceCondition,
)
from asago_scenario_generator.stpa.scenario_prod.outcome_grounding import (
    ComparisonEvidence,
    resolve_outcome_grounding,
)


def _grounded_condition(*args, **kwargs):
    """Return the grounded condition that Stage 5 compiles."""
    return resolve_outcome_grounding(*args, **kwargs).condition


def condition(value="true"):
    return ActionValueCondition(
        control_action_id="CA-1-1", property="topic", operator="equals", expected=value
    )


def test_unsourced_string_truth_is_retained_as_an_unknown_not_a_literal():
    result = _grounded_condition(
        condition(),
        None,
        {},
        model_output=False,
        proposition="The supplied topic differs from the recorded session topic.",
    )
    assert isinstance(result.expected, SemanticBindingPlaceholder)
    assert result.expected.value_type == "string"
    assert result.property == "topic"
    assert result.operator == "equals"
    assert "recorded session topic" in result.expected.description


def test_exact_supplied_literal_is_preserved_without_claiming_semantic_verification():
    source = 'The forbidden session topic is "shipping".'
    evidence = ComparisonEvidence(
        source_ref="SC-1",
        quote=source,
        rationale="Equality to the forbidden topic realizes the supplied rule.",
    )
    result = _grounded_condition(
        condition("shipping"),
        evidence,
        {"SC-1": source},
        model_output=False,
        proposition="The topic violates the supplied reference rule.",
    )
    assert result == condition("shipping")


@pytest.mark.parametrize(
    "source, expected",
    [
        (
            '{"own_record":"record-own","foreign_record":"record-foreign"}',
            "record-foreign",
        ),
        ('{"record-foreign":{"owner":"account-b"}}', "record-foreign"),
    ],
)
def test_bare_string_citation_is_grounded_by_exact_json_scalar_or_key(source, expected):
    evidence = ComparisonEvidence(
        source_ref="TARGET-STATE", quote=expected, rationale="Use the observed record."
    )
    result = _grounded_condition(
        condition(expected),
        evidence,
        {"TARGET-STATE": source},
        model_output=False,
        proposition="The selected record is the observed foreign record.",
    )
    assert result == condition(expected)


@pytest.mark.parametrize(
    "source, expected, quote",
    [
        (
            '{"own_record":"record-foreigner","foreign_record":"record-other"}',
            "record-foreign",
            "record-foreign",
        ),
        ('{"own_record":1}', "1", "1"),
        ('{"own_record":"record-foreign"', "record-foreign", "record-foreign"),
    ],
)
def test_bare_string_citation_requires_an_exact_json_string_token(
    source, expected, quote
):
    evidence = ComparisonEvidence(
        source_ref="TARGET-STATE", quote=quote, rationale="Use the observed record."
    )
    result = _grounded_condition(
        condition(expected),
        evidence,
        {"TARGET-STATE": source},
        model_output=False,
        proposition="The selected record is the observed foreign record.",
    )
    assert isinstance(result.expected, SemanticBindingPlaceholder)


def test_bare_string_citation_requires_the_selected_source_reference():
    evidence = ComparisonEvidence(
        source_ref="TARGET-STATE", quote="record-foreign", rationale="Use the record."
    )
    result = _grounded_condition(
        condition("record-foreign"),
        evidence,
        {"OTHER-SOURCE": '{"foreign_record":"record-foreign"}'},
        model_output=False,
        proposition="The selected record is the observed foreign record.",
    )
    assert isinstance(result.expected, SemanticBindingPlaceholder)


def test_foreign_quote_or_a_value_not_in_the_quote_does_not_ground_a_literal():
    evidence = ComparisonEvidence(
        source_ref="SC-1",
        quote='Reference topic is "shipping".',
        rationale="Use the reference.",
    )
    for sources in ({}, {"SC-1": "Different source"}, {"SC-1": evidence.quote}):
        result = _grounded_condition(
            condition("true"),
            evidence,
            sources,
            model_output=False,
            proposition="Topic mismatch.",
        )
        assert isinstance(result.expected, SemanticBindingPlaceholder)


def test_semantic_truth_remains_boolean_and_is_not_an_argument_literal():
    predicate = ActionValueCondition(
        control_action_id="CA-1-1",
        property="semantic_proposition",
        operator="equals",
        expected=True,
    )
    assert (
        _grounded_condition(
            predicate,
            None,
            {},
            model_output=True,
            proposition="The answer contradicts the reference.",
        )
        == predicate
    )
    result = _grounded_condition(
        condition(True),
        None,
        {},
        model_output=False,
        proposition="An argument violates the supplied rule.",
    )
    assert isinstance(result.expected, SemanticBindingPlaceholder)
    assert result.expected.value_type == "boolean"


@pytest.mark.parametrize(
    "value, quote, grounded",
    [
        (10, "The maximum allowed count is 10.", True),
        (1, "The maximum allowed count is 10.", False),
        (False, "The required flag is false.", True),
        (False, 'The text label is "false".', False),
    ],
)
def test_literal_source_matching_preserves_type_and_token_boundaries(
    value, quote, grounded
):
    evidence = ComparisonEvidence(
        source_ref="SC-1", quote=quote, rationale="Use the explicit reference value."
    )
    result = _grounded_condition(
        condition(value),
        evidence,
        {"SC-1": quote},
        model_output=False,
        proposition="The value matches the supplied unsafe reference.",
    )
    assert (not isinstance(result.expected, SemanticBindingPlaceholder)) is grounded


def test_existing_parameters_and_nonvalue_conditions_are_not_rewritten():
    values = [
        condition(
            SemanticBindingPlaceholder(
                binding_ref="SEM-EXPLICIT",
                value_type="string",
                description="Reference topic from session evidence.",
            )
        ),
        ActionPresenceCondition(control_action_id="CA-1-1"),
    ]
    for original in values:
        assert (
            _grounded_condition(
                original, None, {}, model_output=False, proposition=None
            )
            == original
        )

"""Deterministic summaries publish exactly their source rendering."""

from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_summary,
)
from asago_scenario_generator.stpa.scenario_prod.run import (
    _run_stage6_for_spec,
    _validate_envelope_stage7,
    run_sp3,
)
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.stpa.helpers import make_minimal_loss_analysis
from tests.helpers.stpa_producer_seams import _control_structure, _spec
from tests.helpers.sp3_run import _make_ets, _setup_mock_client


def _summary():
    return _run_stage6_for_spec(_spec(), _control_structure())


def test_deterministic_feedback_summary_needs_no_invented_process_model_id():
    envelope = _summary()
    assert (
        envelope.attack_tree["root"]
        == envelope.scenario_spec.unsafe_outcome_semantic_proposition
    )
    assert all("PM-" in step for step in envelope.gherkin_spec.given)
    errors = []
    _validate_envelope_stage7(envelope, make_minimal_loss_analysis(), errors)
    assert errors == []


def test_stage6_envelope_carries_the_rendered_summary_unchanged():
    spec = _spec()
    narrative, tree, gherkin = render_scenario_summary(spec)

    envelope = _run_stage6_for_spec(spec, _control_structure())

    assert envelope.narrative == narrative
    assert envelope.attack_tree == tree
    assert envelope.gherkin_spec == gherkin
    assert envelope.gherkin_raw == gherkin.to_feature_text()


def test_normal_product_run_validates_deterministic_summary_without_render_calls(
    tmp_path,
):

    client = _setup_mock_client(1)
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path,
    )
    assert len(result.scenario_envelopes) == 1
    assert result.validation_errors == []
    assert not any("Stage 6" in str(call) for call in client.calls)

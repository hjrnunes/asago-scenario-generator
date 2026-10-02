"""Deterministic summaries validate against their source."""

import pytest

from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_summary,
)
from asago_scenario_generator.stpa.scenario_prod.run import _validate_envelope_stage7
from tests.stpa.helpers import make_minimal_loss_analysis
from tests.stpa.test_stpa_execution_bundle_producer import _control_structure, _spec


def _summary():
    spec = _spec()
    narrative, tree, gherkin = render_scenario_summary(spec)
    return assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative=narrative,
        attack_tree=tree,
        gherkin_spec=gherkin,
        gherkin_raw=gherkin.to_feature_text(),
        control_structure=_control_structure(),
    )


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


@pytest.mark.parametrize(
    "field", ["narrative", "attack_tree", "gherkin_spec", "gherkin_raw"]
)
def test_deterministic_summary_rejects_modified_content(field):
    envelope = _summary()
    changes = {
        "narrative": "The attack succeeded.",
        "attack_tree": {**envelope.attack_tree, "root": "Different unsafe outcome"},
        "gherkin_spec": envelope.gherkin_spec.model_copy(
            update={"given": ["Given invented evidence"]}
        ),
        "gherkin_raw": "Feature: unrelated",
    }
    damaged = envelope.model_copy(update={field: changes[field]})
    errors = []
    _validate_envelope_stage7(damaged, make_minimal_loss_analysis(), errors)
    assert any(field in message and "deterministic" in message for message in errors)


def test_normal_product_run_validates_deterministic_summary_without_render_calls(
    tmp_path,
):
    from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
    from tests.stpa.test_sp3_run import (
        _make_cs,
        _make_ets,
        _make_loss_analysis,
        _setup_mock_client,
    )

    client = _setup_mock_client(1)
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=_make_cs(),
        loss_analysis=_make_loss_analysis(),
        run_dir=tmp_path,
    )
    assert len(result.scenario_envelopes) == 1
    assert result.validation_errors == []
    assert not any("Stage 6" in str(call) for call in client.calls)

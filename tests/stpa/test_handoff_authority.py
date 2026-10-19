"""Regressions for finding A2: published constraint authority is honest.

``handoff.py`` labelled every scenario-context constraint
``supplied_reviewed_constraint`` regardless of the loss-analysis record it
came from, so a derived MiniOcciAI graph (proposed direction authority,
``stage_1a.source: derived``) published as reviewed. The published authority
must derive from the actual source record and the run's Stage 1a acceptance
record: a derived/proposed constraint stays distinguishable from a reviewed
one, and a pinned reviewed graph still publishes as reviewed.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.handoff import ScenarioHandoff
from asago_scenario_generator.stpa.scenario_prod.and_or_tree import (
    build_sibling_index,
    render_and_or_tree,
)
from asago_scenario_generator.stpa.scenario_prod.handoff_v5 import (
    build_scenario_handoff_v5,
)
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_summary,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.helpers.synthesis_fixture import final_ica_result
from tests.stpa.sp1_helpers import MockLLMClient
from tests.helpers.stage5_assembly import stage5_assembly
from tests.helpers.scenario_handoff_publication import _normal_semantics_payload
from tests.helpers.sp3_run import _make_ets
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.pipeline import synthesis
from asago_scenario_generator.pipeline.model_runtime import ModelRuntime
from asago_scenario_generator.pipeline.synthesis_defaults import _default_scenarios


def _reviewed(analysis: LossAnalysis) -> LossAnalysis:
    """Return the analysis with every constraint stamped reviewed."""
    stamped = [
        constraint.model_copy(
            update={
                "direction_authority": "reviewed",
                "reviewed_by": "Test reviewer",
                "reviewed_on": date(2026, 9, 15),
            }
        )
        for constraint in analysis.security_constraints
    ]
    return analysis.model_copy(update={"security_constraints": stamped})


def _constraint_fact(handoff: ScenarioHandoff | dict) -> dict:
    """Return the scenario-context constraint fact of one handoff."""
    payload = (
        handoff.model_dump(mode="json")
        if isinstance(handoff, ScenarioHandoff)
        else handoff
    )
    facts = [
        fact
        for fact in payload["sourced_facts"]
        if fact["source"].startswith("security constraint ")
    ]
    assert facts, payload["sourced_facts"]
    return facts[0]


def _published(run_dir: Path) -> dict:
    path = run_dir / "scenarios" / "SCN-001.yaml"
    assert path.is_file(), f"missing handoff {path}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _run_publish(tmp_path: Path, loss_analysis: LossAnalysis, **kwargs) -> None:
    client = MockLLMClient()
    client.set_response_queue([_normal_semantics_payload()])
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=make_cs(),
        loss_analysis=loss_analysis,
        run_dir=tmp_path,
        **kwargs,
    )
    assert result.stage_errors == [], result.stage_errors


def _handoff_for(
    loss_analysis: LossAnalysis,
    *,
    stage_1a_source: str | None,
    constraint_id: str,
    hazard_id: str,
    tmp_path: Path,
) -> ScenarioHandoff:
    """Build one handoff through the normal authoring path.

    The scenario context is built from the supplied loss analysis, so the
    published constraint facts name that analysis's exact constraint record.
    """
    structure = make_cs()
    threat = SimpleNamespace(
        ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
        ica_text="ICA text 1",
        hazardous_context="Context",
        loss_scenario="Loss scenario",
        related_hazards=[hazard_id],
        related_constraints=[constraint_id],
    )
    context = build_scenario_generation_context(
        _real_threat(threat),
        structure,
        loss_analysis,
        scenario_id="SCN-001",
    )
    client = MockLLMClient()
    client.set_response_queue([_normal_semantics_payload()])
    spec, error = generate_bdi_for_context(
        client,
        context,
        tmp_path,
        assembly=stage5_assembly(context, _real_threat(threat), structure),
    )
    assert error is None, error
    assert spec is not None
    narrative, tree, gherkin = render_scenario_summary(spec)
    envelope = assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative=narrative,
        attack_tree=render_and_or_tree(spec, tree, build_sibling_index([spec])),
        gherkin_spec=gherkin,
        gherkin_raw=gherkin.to_feature_text(),
    )
    return build_scenario_handoff_v5(
        envelope,
        loss_analysis=loss_analysis,
        stage_1a_source=stage_1a_source,
    )


def _real_threat(values: SimpleNamespace):
    return StructuralThreat(
        ica_slot_id=values.ica_slot_id,
        ica_id=values.ica_id,
        ica_text=values.ica_text,
        hazardous_context=values.hazardous_context,
        loss_scenario=values.loss_scenario,
        related_hazards=values.related_hazards,
        related_constraints=values.related_constraints,
    )


# The defect: every constraint published as reviewed


def test_run_published_constraint_authority_is_not_reviewed_for_proposed_records(
    tmp_path: Path,
) -> None:
    """VAL-A2-001: a proposed constraint record never publishes as reviewed.

    The fixture loss analysis carries no reviewed stamps, so the constraint
    fact is proposed regardless of the Stage 1a source the caller reports.
    """
    _run_publish(tmp_path, make_loss_analysis())
    authority = _constraint_fact(_published(tmp_path))["authority"]
    assert authority != "supplied_reviewed_constraint"
    assert "reviewed" not in authority


def test_derived_run_publishes_derived_proposed_authority(tmp_path: Path) -> None:
    """VAL-A2-001: ``stage_1a.source: derived`` publishes derived authority."""
    _run_publish(tmp_path, make_loss_analysis(), stage_1a_source="derived")
    fact = _constraint_fact(_published(tmp_path))
    assert fact["authority"] == "derived_proposed_constraint"


def test_pinned_reviewed_record_publishes_reviewed(tmp_path: Path) -> None:
    """VAL-A2-002: a pinned reviewed record still publishes as reviewed."""
    _run_publish(
        tmp_path,
        _reviewed(make_loss_analysis()),
        stage_1a_source="pinned",
    )
    fact = _constraint_fact(_published(tmp_path))
    assert fact["authority"] == "supplied_reviewed_constraint"


# Authority follows the actual source record


def test_authority_follows_source_record(tmp_path: Path) -> None:
    """VAL-A2-003: differing records yield differing published authorities."""
    proposed = make_loss_analysis()
    reviewed = _reviewed(proposed)
    constraint_id = proposed.security_constraints[0].constraint_id
    hazard_id = proposed.security_constraints[0].related_hazards[0]

    def _build(analysis: LossAnalysis, source: str | None) -> ScenarioHandoff:
        return _handoff_for(
            analysis,
            stage_1a_source=source,
            constraint_id=constraint_id,
            hazard_id=hazard_id,
            tmp_path=tmp_path,
        )

    derived_proposed = _build(proposed, "derived")
    pinned_reviewed = _build(reviewed, "pinned")
    pinned_proposed = _build(proposed, "pinned")
    derived_with_reviewed_record = _build(reviewed, "derived")

    assert (
        _constraint_fact(derived_proposed)["authority"] == "derived_proposed_constraint"
    )
    assert (
        _constraint_fact(pinned_reviewed)["authority"] == "supplied_reviewed_constraint"
    )
    assert (
        _constraint_fact(pinned_proposed)["authority"] == "supplied_proposed_constraint"
    )
    # A derived run never publishes reviewed, even with a reviewed-looking
    # record: deterministic code restamps every derived graph proposed.
    assert (
        _constraint_fact(derived_with_reviewed_record)["authority"]
        == "derived_proposed_constraint"
    )


# The synthesis seam threads the run's actual Stage 1a source


@pytest.mark.parametrize(
    ("loss_analysis_path", "expected_source"),
    (
        (None, "derived"),
        (Path("pinned-loss-analysis.yaml"), "pinned"),
    ),
)
def test_synthesis_threads_stage_1a_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    loss_analysis_path: Path | None,
    expected_source: str,
) -> None:
    """The normal product run reports its own Stage 1a acceptance record."""
    captured: dict = {}

    def _fake_run_sp3(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            stage_errors=[],
            scenario_specs=[],
            scenario_envelopes=[],
            candidate_outcomes=(),
            functional_test_specs=[],
        )

    monkeypatch.setattr(
        "asago_scenario_generator.stpa.scenario_prod.run.run_sp3", _fake_run_sp3
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.threat_enum.catalog_enrichment.enrich_threats",
        lambda *a, **k: SimpleNamespace(structural_threats=[]),
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.pipeline.llm_config.resolve_llm_client",
        lambda *a, **k: (MockLLMClient(), "test-profile"),
    )

    inputs = synthesis.SynthesisInputs(
        use_case="u",
        output_dir=tmp_path,
        loss_analysis_path=loss_analysis_path,
    )
    _default_scenarios(
        ica_enumeration=final_ica_result(),
        control_structure=SimpleNamespace(),
        loss_analysis=make_loss_analysis(),
        inputs=inputs,
        capability_profile=None,
        output_dir=tmp_path,
        model_runtime=ModelRuntime.for_inputs(inputs),
    )

    assert captured["stage_1a_source"] == expected_source

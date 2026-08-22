"""No-model projection-preflight contract."""

from __future__ import annotations

from typer.testing import CliRunner

from asago_scenario_generator.cli import app
from asago_scenario_generator.models.attack_pattern import (
    AuthoritativeFactReference,
    EvaluatedFactEvidence,
)
from asago_scenario_generator.pipeline.preflight import (
    ProjectionPreflightOutcome,
    build_facts_template,
    classify_fact_readings,
)
from asago_scenario_generator.pipeline.projection import ProjectionReadinessReport


def _fact(fact_id: str, value_type: str = "boolean") -> AuthoritativeFactReference:
    return AuthoritativeFactReference(
        namespace="profile",
        fact_id=fact_id,
        value_type=value_type,
        property_path=(fact_id.split(".")[-1],),
    )


def test_partial_fact_input_reports_every_required_fact_and_builds_template() -> None:
    required = (
        _fact("capabilities.code_interpreter"),
        _fact("capabilities.feedback_loop"),
    )
    supplied = (EvaluatedFactEvidence(fact=required[0], status="present", value=True),)

    states = classify_fact_readings(required, supplied)
    template = build_facts_template(required)

    assert [(item.fact.fact_id, item.status) for item in states] == [
        ("capabilities.code_interpreter", "present"),
        ("capabilities.feedback_loop", "absent"),
    ]
    assert [item.fact.fact_id for item in template] == [
        "capabilities.code_interpreter",
        "capabilities.feedback_loop",
    ]
    assert all(item.status == "unknown" and item.value is None for item in template)


def test_fact_classification_reports_unknown_stale_and_contradictory_readings() -> None:
    required = (
        _fact("capabilities.code_interpreter"),
        _fact("capabilities.feedback_loop"),
    )
    stale = _fact("capabilities.retired_switch")
    supplied = (
        EvaluatedFactEvidence(fact=required[0], status="present", value=True),
        EvaluatedFactEvidence(fact=required[0], status="present", value=False),
        EvaluatedFactEvidence(fact=required[1], status="unknown"),
        EvaluatedFactEvidence(fact=stale, status="present", value=True),
    )

    states = classify_fact_readings(required, supplied)

    assert [(item.fact.fact_id, item.status) for item in states] == [
        ("capabilities.code_interpreter", "contradictory"),
        ("capabilities.feedback_loop", "unknown"),
        ("capabilities.retired_switch", "stale"),
    ]
    contradictory = states[0]
    assert contradictory.required is True
    assert {reading.value for reading in contradictory.readings} == {True, False}
    assert states[-1].required is False


def test_identical_duplicate_fact_readings_are_collapsed() -> None:
    reference = _fact("capabilities.code_interpreter")
    reading = EvaluatedFactEvidence(fact=reference, status="present", value=True)

    states = classify_fact_readings((reference,), (reading, reading))

    assert len(states) == 1
    assert states[0].status == "present"
    assert states[0].value is True
    assert states[0].readings == (reading,)


def test_projection_preflight_cli_prints_machine_readable_report(
    tmp_path, monkeypatch
) -> None:
    inputs = {}
    for name in ("risk.json", "map.tsv", "profile.yaml"):
        path = tmp_path / name
        path.write_text("fixture", encoding="utf-8")
        inputs[name] = path
    outcome = ProjectionPreflightOutcome(
        readiness=ProjectionReadinessReport(ready=True),
        fact_states=(),
        facts_template=(),
        explicit_facts_source=False,
    )
    monkeypatch.setattr(
        "asago_scenario_generator.pipeline.preflight.run_projection_preflight",
        lambda **_: outcome,
    )

    result = CliRunner().invoke(
        app,
        [
            "projection-preflight",
            "--use-case",
            "test",
            "--risk-extraction",
            str(inputs["risk.json"]),
            "--sssom",
            str(inputs["map.tsv"]),
            "--profile",
            str(inputs["profile.yaml"]),
        ],
    )

    assert result.exit_code == 0
    assert '"ready": true' in result.output

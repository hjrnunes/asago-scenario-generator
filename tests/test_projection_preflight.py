"""No-model projection-preflight contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
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
    run_projection_preflight,
    write_facts_template,
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


# ---------------------------------------------------------------------------#
# Zero-coverage internals: run_projection_preflight / write_facts_template
# (CRAP slice 4)
# ---------------------------------------------------------------------------#


def _write_preflight_inputs(tmp_path) -> tuple[Path, Path, Path]:
    """Write minimal preflight inputs: profile, risk extraction, sssom.

    The risk card resolves through the committed cross-taxonomy mappings
    (llm01 -> T6), so the deterministic readiness path runs offline
    against the bundled catalog.
    """
    profile_path = tmp_path / "profile.yaml"
    profile_path.write_text(
        "zones_active: [input, reasoning, tool_execution]\n"
        "has_persistent_memory: false\n"
        "multi_agent: false\n"
        "hitl: false\n"
        "entry_points:\n"
        '  - "user prompts via chat widget"\n'
        "confidence: high\n"
        "kc_subcodes: [KC1.1, KC5.1]\n"
        "tool_inventory:\n"
        '  - name: "test_tool"\n'
        '    description: "A test tool"\n',
        encoding="utf-8",
    )
    risk_path = tmp_path / "risk-extraction.json"
    risk_path.write_text(
        json.dumps(
            {
                "risks": [
                    {
                        "risk_id": "risk-prompt-injection",
                        "risk_name": "Prompt injection",
                        "risk_description": "Prompt injection risk",
                        "taxonomy": "ibm-risk-atlas",
                        "confidence": 0.9,
                        "grounding_confidence": "high",
                        "threat": "An adversary hijacks the model.",
                        "vulnerability": "Prompts are trusted.",
                        "consequence": "Unsafe actions.",
                        "impact": "Harm.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    sssom_path = tmp_path / "risk-llm.sssom.tsv"
    sssom_path.write_text(
        "subject_id\tsubject_source\tpredicate_id\tobject_id"
        "\tobject_source\tmapping_justification\n"
        "risk-prompt-injection\tibm-risk-atlas\tskos:exactMatch\tllm01"
        "\towasp-llm-top10\tsemapv:ManualMappingCuration\n",
        encoding="utf-8",
    )
    return profile_path, risk_path, sssom_path


def _run_preflight(
    tmp_path,
    *,
    qualification_facts_path: Path | None = None,
    cross_taxonomy_path: Path | None = None,
) -> ProjectionPreflightOutcome:
    profile_path, risk_path, sssom_path = _write_preflight_inputs(tmp_path)
    return run_projection_preflight(
        use_case="fixture system",
        risk_extraction_path=risk_path,
        sssom_path=sssom_path,
        profile_path=profile_path,
        qualification_facts_path=qualification_facts_path,
        cross_taxonomy_path=cross_taxonomy_path,
    )


def test_run_projection_preflight_reports_missing_facts_and_template(
    tmp_path,
) -> None:
    outcome = _run_preflight(tmp_path)

    assert outcome.explicit_facts_source is False
    assert outcome.readiness.ready is False
    assert [state.fact.fact_id for state in outcome.fact_states] == [
        "capabilities.code_interpreter",
        "capabilities.external_content_ingestion",
        "capabilities.feedback_loop",
        "capabilities.planning_interface",
        "capabilities.reflection_mechanism",
    ]
    assert all(
        state.status == "absent" and state.required for state in outcome.fact_states
    )
    assert [item.fact.fact_id for item in outcome.facts_template] == [
        state.fact.fact_id for state in outcome.fact_states
    ]
    assert all(
        item.status == "unknown" and item.value is None
        for item in outcome.facts_template
    )


def test_run_projection_preflight_consumes_supplied_qualification_facts(
    tmp_path,
) -> None:
    facts_path = tmp_path / "qualification-facts.yaml"
    facts_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "facts": [
                    {
                        "fact": {
                            "namespace": "profile",
                            "fact_id": "capabilities.code_interpreter",
                            "value_type": "boolean",
                            "property_path": [],
                        },
                        "status": "present",
                        "value": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    outcome = _run_preflight(tmp_path, qualification_facts_path=facts_path)

    assert outcome.explicit_facts_source is True
    states = {state.fact.fact_id: state for state in outcome.fact_states}
    assert states["capabilities.code_interpreter"].status == "present"
    assert states["capabilities.code_interpreter"].value is True
    assert states["capabilities.reflection_mechanism"].status == "absent"


def test_run_projection_preflight_stale_readings_are_reported(
    tmp_path,
) -> None:
    facts_path = tmp_path / "qualification-facts.yaml"
    facts_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "facts": [
                    {
                        "fact": {
                            "namespace": "profile",
                            "fact_id": "capabilities.legacy_flag",
                            "value_type": "boolean",
                            "property_path": [],
                        },
                        "status": "present",
                        "value": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    outcome = _run_preflight(tmp_path, qualification_facts_path=facts_path)

    assert any(
        state.fact.fact_id == "capabilities.legacy_flag" and state.status == "stale"
        for state in outcome.fact_states
    )
    assert outcome.explicit_facts_source is True


def test_run_projection_preflight_accepts_explicit_cross_taxonomy_path(
    tmp_path,
) -> None:
    bundled = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "taxonomies"
        / "mappings"
        / "cross-taxonomy-mappings.yaml"
    )
    assert bundled.exists()

    outcome = _run_preflight(tmp_path, cross_taxonomy_path=bundled)

    assert outcome.explicit_facts_source is False
    assert outcome.readiness.ready is False
    assert outcome.fact_states


def test_write_facts_template_writes_unknown_template_and_refuses_overwrite(
    tmp_path,
) -> None:
    outcome = _run_preflight(tmp_path)
    target = tmp_path / "nested" / "facts-template.yaml"
    target.parent.mkdir()

    write_facts_template(outcome, target)

    written_text = target.read_text(encoding="utf-8")
    written = yaml.safe_load(written_text)
    assert written["schema_version"] == "1"
    assert written_text.index("schema_version:") < written_text.index("facts:")
    assert [item["fact"]["fact_id"] for item in written["facts"]] == [
        item.fact.fact_id for item in outcome.facts_template
    ]
    assert all(item["status"] == "unknown" for item in written["facts"])

    with pytest.raises(FileExistsError, match="already exists"):
        write_facts_template(outcome, target)


# ---------------------------------------------------------------------------#
# Direct branch tests for the decomposed fact-classification helpers
# ---------------------------------------------------------------------------#


class TestGroupSuppliedReadings:
    """Branch tests for _group_supplied_readings."""

    def test_groups_by_fact_key_and_collapses_identical_duplicates(self) -> None:
        from asago_scenario_generator.pipeline.preflight import (
            _fact_key,
            _group_supplied_readings,
        )

        reference = _fact("capabilities.code_interpreter")
        reading = EvaluatedFactEvidence(fact=reference, status="present", value=True)
        other = EvaluatedFactEvidence(fact=reference, status="present", value=False)

        grouped = _group_supplied_readings((reading, reading, other))
        assert grouped == {_fact_key(reference): [reading, other]}


class TestStateForRequired:
    """Branch tests for _state_for_required."""

    def test_absent_without_readings(self) -> None:
        from asago_scenario_generator.pipeline.preflight import _state_for_required

        reference = _fact("capabilities.code_interpreter")
        state = _state_for_required(reference, ())
        assert state.status == "absent"
        assert state.required is True
        assert state.value is None

    def test_contradictory_with_multiple_readings(self) -> None:
        from asago_scenario_generator.pipeline.preflight import _state_for_required

        reference = _fact("capabilities.code_interpreter")
        readings = (
            EvaluatedFactEvidence(fact=reference, status="present", value=True),
            EvaluatedFactEvidence(fact=reference, status="present", value=False),
        )
        state = _state_for_required(reference, readings)
        assert state.status == "contradictory"
        assert len(state.readings) == 2

    def test_single_reading_status_and_value(self) -> None:
        from asago_scenario_generator.pipeline.preflight import _state_for_required

        reference = _fact("capabilities.code_interpreter")
        reading = EvaluatedFactEvidence(fact=reference, status="unknown")
        state = _state_for_required(reference, (reading,))
        assert state.status == "unknown"
        assert state.value is None
        assert state.readings == (reading,)


class TestStateForObsolete:
    """Branch tests for _state_for_obsolete."""

    def test_single_reading_is_stale(self) -> None:
        from asago_scenario_generator.pipeline.preflight import _state_for_obsolete

        reference = _fact("capabilities.retired_switch")
        reading = EvaluatedFactEvidence(fact=reference, status="present", value=True)
        state = _state_for_obsolete((reading,))
        assert state.status == "stale"
        assert state.value is True
        assert state.required is False

    def test_multiple_readings_are_contradictory(self) -> None:
        from asago_scenario_generator.pipeline.preflight import _state_for_obsolete

        reference = _fact("capabilities.retired_switch")
        readings = (
            EvaluatedFactEvidence(fact=reference, status="present", value=True),
            EvaluatedFactEvidence(fact=reference, status="present", value=False),
        )
        state = _state_for_obsolete(readings)
        assert state.status == "contradictory"
        assert state.value is None
        assert len(state.readings) == 2

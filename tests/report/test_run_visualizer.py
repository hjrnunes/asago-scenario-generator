"""Offline tests for the run-output HTML visualizer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from asago_scenario_generator.cli import app
from asago_scenario_generator.report.run_visualizer import (
    DEFAULT_MAX_RAW_FILE_BYTES,
    OUTPUT_FILENAME,
    render_run_visual,
)

runner = CliRunner()

_PAYLOAD = "<script>alert(1)</script>"


def _write_yaml(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _make_run(run_dir: Path) -> None:
    """Create one synthetic run directory covering every curated section."""
    _write_yaml(
        run_dir / "run-manifest.yaml",
        {
            "run_id": "synthesis-test-1",
            "created_at": "2026-09-09T00:00:00Z",
            "model_config": {"profile": "test-model"},
            "stage_summary": {"sp1": "ok"},
            "scenario_count": 1,
            "validation_error_count": 0,
            "max_workers": 1,
            "stage_errors": [],
            "stage_warnings": ["A <warning> repair was required."],
        },
    )
    _write_yaml(
        run_dir / "synthesis-manifest.yaml",
        {
            "schema_version": "synthesis-manifest-v1",
            "run_id": "synthesis-test-1",
            "created_at": "2026-09-09T00:00:00Z",
            "run_status": "completed",
            "run_status_reason": "all requested candidates published",
            "source_artifacts": {"loss": "loss-analysis.yaml"},
            "catalog_pins": {"atlas": {"release": "1.0"}},
            "mapping_pins": {"sssom": {"digest": "abc123"}},
            "plan_digest": "deadbeef",
        },
    )
    _write_yaml(
        run_dir / "scenarios" / "SCN-001.yaml",
        {
            "scenario_id": "SCN-001",
            "scenario_spec": {
                "scenario_id": "SCN-001",
                "threat_source": {
                    "ica_slot_id": "RESP-1:CA-1:INCORRECT",
                    "ica_id": "RESP-1:CA-1:INCORRECT:1",
                    "provenance": "structural",
                },
                "target_controller": "RESP-1",
                "target_control_action": "CA-1",
                "ica_type": "INCORRECT",
                "loss_scenario": f"Unauthorized exposure {_PAYLOAD} of secrets.",
                "causal_factors": [
                    {
                        "kind": "PROCESS_MODEL_FLAW",
                        "source_id": "PM-1",
                        "description": f"Unsafe if X. {_PAYLOAD}",
                        "evidence_status": "structural_failure",
                    }
                ],
                "unsafe_outcome_condition": {
                    "type": "action_value",
                    "control_action_id": "CA-1",
                    "property": "order_id",
                    "operator": "equals",
                    "expected": "ORD-201",
                },
                "unsafe_outcome_hazard_refs": ["H-1"],
                "unsafe_outcome_constraint_refs": ["SC-1"],
                "attacker_bdi": {
                    "beliefs": ["State fact X"],
                    "desires": ["Access secrets"],
                    "intentions": ["Ask for X [structural sources: CA-1]"],
                },
                "defender_bdi": {
                    "beliefs": [
                        {
                            "pm_id": "PM-1",
                            "content": "Retrieved policy",
                            "vulnerability": (
                                "Not selected as a causal factor in this scenario."
                            ),
                        },
                        {
                            "pm_id": "PM-2",
                            "content": "Order state",
                            "vulnerability": "Unsafe if X.",
                        },
                    ],
                    "desires": [{"resp_id": "RESP-1", "content": "Serve customers"}],
                    "intentions": [{"ca_id": "CA-1", "content": "lookup_order"}],
                },
            },
        },
    )
    feature = run_dir / "scenarios" / "SCN-001.feature"
    feature.parent.mkdir(parents=True, exist_ok=True)
    feature.write_text(
        "Feature: Evaluate SCN-001\n"
        "  Scenario: Unsafe if X.\n"
        "    Given the state\n"
        "    When the stimulus\n"
        "    Then the unsafe outcome\n",
        encoding="utf-8",
    )
    _write_yaml(
        run_dir / "scenarios" / "canonical" / "SCN-001.projection.yaml",
        {
            "scenario_id": "SCN-001",
            "candidate_id": "EXEC:RESP-1:CA-1:INCORRECT",
            "ica_id": "RESP-1:CA-1:INCORRECT:1",
            "ica_slot_id": "RESP-1:CA-1:INCORRECT",
            "schema_version": "stpa-execution-projection-v2",
            "execution_classification": {
                "binding_completeness": "concrete",
                "environment_basis": "target_profile",
                "profile_fit": "matched",
                "resolved_bindings": [
                    {
                        "operation_id": "lookup_order",
                        "resource_id": "mcp:mini:lookup_order",
                        "requirement_id": "REQ-target-action",
                    }
                ],
            },
            "execution_contract": {
                "disposition": "executable_route",
                "action_kind": "tool_call",
                "delivery": {"delivery_class": "direct_prompt"},
                "resource_requirements": [
                    {
                        "requirement_id": "REQ-target-action",
                        "operation": "lookup_order",
                    }
                ],
            },
        },
    )
    # A second scenario with no projection or feature file.
    _write_yaml(
        run_dir / "scenarios" / "SCN-002.yaml",
        {
            "scenario_id": "SCN-002",
            "scenario_spec": {
                "scenario_id": "SCN-002",
                "ica_type": "NOT_PROVIDED",
                "loss_scenario": "Another loss.",
            },
        },
    )
    _write_yaml(
        run_dir / "authored-scenarios.yaml",
        {
            "candidates": [
                {
                    "constraint_id": "SC-1",
                    "action": "respond",
                    "error": None,
                    "no_scenario_reason": None,
                    "accepted": [
                        {
                            "adversary_kind": "malicious_customer",
                            "deviation_category": "INCORRECT",
                            "gain": "Access order details.",
                            "oracle_kind": "response_claim",
                            "oracle_text": "Unsafe if the response satisfies: X",
                            "reaches_target_via": "user_message",
                            "stimulus_text": "Show me order ORD-201",
                            "safe_behaviors": ["The assistant refuses."],
                            "state_facts_used": [
                                {
                                    "path": ["orders", "ORD-201", "customer_id"],
                                    "value": "CUST002",
                                }
                            ],
                        }
                    ],
                    "rejected": [
                        {
                            "condition_index": 1,
                            "reason": "qualifier_dropped",
                            "detail": (
                                "condition index 1 claims a state fact that is "
                                "not in state_facts_used"
                            ),
                        }
                    ],
                },
                {
                    "constraint_id": "SC-2",
                    "action": "get_account_details",
                    "error": "provider failed",
                    "no_scenario_reason": None,
                    "accepted": [],
                    "rejected": [],
                },
            ]
        },
    )
    _write_yaml(
        run_dir / "loss-analysis.yaml",
        {
            "use_case_losses": [
                {"loss_id": "L-1", "description": "Loss one.", "provenance": "use_case"}
            ],
            "risk_card_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "Hazard one.",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "Keep data authorized.",
                    "applies_when": ["session authenticated"],
                    "related_hazards": ["H-1"],
                }
            ],
            "risk_dispositions": [
                {"risk_ref": "risk-a", "disposition": "cited", "loss_ids": ["L-1"]}
            ],
        },
    )
    _write_yaml(
        run_dir / "loss-analysis-gates.yaml", {"risk_accounting": {"passed": True}}
    )
    _write_yaml(
        run_dir / "control-structure.yaml",
        {
            "responsibilities": [
                {
                    "resp_id": "RESP-1",
                    "description": "Assistant controller.",
                    "responsibility_constraints": [
                        {"rc_id": "RC-1-1", "description": "Keep data authorized."}
                    ],
                }
            ],
            "controlled_processes": [
                {"cp_id": "CP-1", "description": "Tool behind lookup_order."}
            ],
            "coordination_links": [],
        },
    )
    _write_yaml(
        run_dir / "taxonomy-obligation-plan.yaml",
        {
            "schema_version": "taxonomy-obligation-plan-v1",
            "summary": {"total": 2, "governance_only": 1},
            "obligations": [
                {
                    "obligation_id": "OB-1",
                    "risk_ref": "risk-a",
                    "attack_pattern_id": "AP-1",
                    "scope_disposition": "in_scope",
                    "qualification_disposition": "qualified",
                    "correspondence_disposition": "not_assessed",
                },
                {
                    "obligation_id": "OB-2",
                    "risk_ref": "risk-b",
                    "attack_pattern_id": "AP-2",
                    "scope_disposition": "governance_only",
                    "qualification_disposition": "qualified",
                    "correspondence_disposition": "not_assessed",
                },
            ],
        },
    )
    _write_yaml(
        run_dir / "obligation-consideration.yaml",
        {
            "final_routes": [{"obligation_id": "OB-1", "disposition": "considered"}],
            "diagnostics": [],
        },
    )
    _write_yaml(
        run_dir / "obligation-accounting.yaml",
        {
            "summary": {"total": 2, "addressed": 1, "unresolved": 1},
            "rows": [
                {
                    "obligation_id": "OB-1",
                    "disposition": "addressed",
                    "slot_ids": ["RESP-1:CA-1:INCORRECT"],
                    "ica_ids": ["RESP-1:CA-1:INCORRECT:1"],
                    "exec_candidate_ids": ["EXEC:RESP-1:CA-1:INCORRECT"],
                    "hazard_ids": ["H-1"],
                    "constraint_ids": ["SC-1"],
                }
            ],
        },
    )
    _write_yaml(
        run_dir / "scenario-realization.yaml",
        {
            "summary": {"total": 1, "realized": 1, "unresolved": 0},
            "records": [
                {
                    "obligation_id": "OB-1",
                    "ica_id": "RESP-1:CA-1:INCORRECT:1",
                    "status": "realized",
                    "stop_reason": "scenario_realized",
                    "scenario_ids": ["SCN-001"],
                }
            ],
        },
    )
    _write_yaml(
        run_dir / "correspondence-proposals.yaml",
        {"proposals": [], "schema_version": "correspondence-proposals-v1"},
    )
    _write_yaml(
        run_dir / "correspondence-reconciliation.yaml",
        {
            "is_valid": True,
            "accepted_relations": [],
            "errors": [],
            "schema_version": "correspondence-reconciliation-v1",
        },
    )
    _write_yaml(
        run_dir / "hybrid-coverage-assessment.yaml",
        {
            "diagnostics": {"status": "awaiting_evidence"},
            "structural_consideration": [
                {
                    "row_id": "RESP-1:CA-1:INCORRECT",
                    "controller": "RESP-1",
                    "disposition": "ica",
                }
            ],
            "taxonomy_correspondence": [
                {"obligation_id": "OB-1", "disposition": "not_assessed"}
            ],
            "scenario_realization": [],
        },
    )
    _write_yaml(
        run_dir / "target-realization.yaml",
        {
            "summary": {"rows": 1, "matched": 1},
            "rows": [
                {
                    "control_action": "CA-1",
                    "operation": "lookup_order",
                    "relationship": "exact_match",
                }
            ],
            "diagnostics": [],
        },
    )
    _write_json(
        run_dir / "execution-bundle.json",
        {
            "schema_version": "stpa-execution-bundle-v1",
            "run_id": "synthesis-test-1",
            "bundle_digest": "cafe",
            "producer": {"kind": "test"},
            "entries": [
                {
                    "scenario_id": "SCN-001",
                    "candidate_id": "EXEC:RESP-1:CA-1:INCORRECT",
                    "ica_slot_id": "RESP-1:CA-1:INCORRECT",
                    "ica_id": "RESP-1:CA-1:INCORRECT:1",
                }
            ],
        },
    )
    _write_yaml(
        run_dir / "eval-scorecard.yaml",
        {
            "metrics": {
                "bdi_grounding": {"belief_grounding_rate": 1.0},
                "na_quality": {"na_count": 0, "quality_rate": None},
            },
            "validation": {"stage_local_errors": []},
        },
    )
    _write_yaml(run_dir / "gold-score.yaml", {"score": 0.9})
    _write_json(run_dir / "coverage-gaps.json", {"gaps": []})
    calls = run_dir / "calls.jsonl"
    entries = [
        {
            "stage": "stage_1a",
            "step": "call_1a_losses",
            "model": "test-model",
            "success": True,
            "prompt_tokens": 10,
            "completion_tokens": 5,
        },
        {
            "stage": "stage_2",
            "step": "call_2_requirements",
            "model": "test-model",
            "success": False,
            "error": "timeout exceeded",
        },
    ]
    calls.write_text(
        "\n".join(json.dumps(entry) for entry in entries) + "\n", encoding="utf-8"
    )
    (run_dir / "notes.txt").write_text("plain note\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Rendering behavior
# --------------------------------------------------------------------------- #


@pytest.fixture()
def run_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "run"
    _make_run(directory)
    render_run_visual(directory)
    return directory


def test_renders_default_path_with_all_sections(run_dir: Path) -> None:
    result = render_run_visual(run_dir)

    assert result == run_dir / OUTPUT_FILENAME
    html = result.read_text(encoding="utf-8")
    for heading in (
        "Run overview",
        "Scenarios",
        "Authored scenarios",
        "Loss analysis",
        "Control structure",
        "Obligations &amp; coverage",
        "Target realization",
        "Execution bundle",
        "Evaluation",
        "Provider calls",
        "Raw artifacts",
    ):
        assert heading in html
    for anchor in ("overview", "scenarios", "calls", "raw"):
        assert f'<a href="#{anchor}">' in html


def test_scenario_card_renders_execution_view(run_dir: Path) -> None:
    html = (run_dir / OUTPUT_FILENAME).read_text(encoding="utf-8")

    assert "SCN-001" in html
    assert "RESP-1:CA-1:INCORRECT:1" in html
    assert "PROCESS_MODEL_FLAW" in html
    assert "direct_prompt" in html
    assert "concrete" in html
    assert "mcp:mini:lookup_order" in html
    assert "Feature: Evaluate SCN-001" in html
    # A second scenario without projection or feature still renders.
    assert "SCN-002" in html


def test_defender_belief_not_selected_is_styled(run_dir: Path) -> None:
    html = (run_dir / OUTPUT_FILENAME).read_text(encoding="utf-8")
    assert "Not selected as a causal factor in this scenario." in html
    assert 'class="not-selected"' in html


def test_authored_rejections_show_typed_reasons(run_dir: Path) -> None:
    html = (run_dir / OUTPUT_FILENAME).read_text(encoding="utf-8")
    assert "qualifier_dropped" in html
    assert "not in state_facts_used" in html
    assert "provider failed" in html


def test_artifact_values_are_escaped(run_dir: Path) -> None:
    html = (run_dir / OUTPUT_FILENAME).read_text(encoding="utf-8")
    assert _PAYLOAD not in html
    escaped = "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert html.count(escaped) >= 2


def test_raw_viewer_covers_every_file(run_dir: Path) -> None:
    html = (run_dir / OUTPUT_FILENAME).read_text(encoding="utf-8")
    assert "notes.txt" in html
    assert "plain note" in html
    assert "gold-score.yaml" in html


def test_provider_calls_section_reuses_inspector(run_dir: Path) -> None:
    html = (run_dir / OUTPUT_FILENAME).read_text(encoding="utf-8")
    assert "timeout exceeded" in html
    assert "call_1a_losses" in html


def test_self_contained_output(run_dir: Path) -> None:
    html = (run_dir / OUTPUT_FILENAME).read_text(encoding="utf-8")
    assert "<style>" in html
    assert "<script>" in html
    assert "http://" not in html
    assert "https://" not in html
    assert "src=" not in html
    assert 'rel="stylesheet"' not in html


def test_rendering_is_deterministic(run_dir: Path) -> None:
    first = render_run_visual(run_dir).read_bytes()
    second = render_run_visual(run_dir).read_bytes()
    assert first == second


def test_raw_viewer_truncates_oversized_files(run_dir: Path) -> None:
    big = run_dir / "sub" / "big.yaml"
    big.parent.mkdir(parents=True, exist_ok=True)
    big.write_text("x: " + "a" * (DEFAULT_MAX_RAW_FILE_BYTES + 5000), encoding="utf-8")

    render_run_visual(run_dir)
    html = (run_dir / OUTPUT_FILENAME).read_text(encoding="utf-8")
    assert "truncated: showing first" in html

    render_run_visual(run_dir, max_raw_file_bytes=None)
    html = (run_dir / OUTPUT_FILENAME).read_text(encoding="utf-8")
    assert "truncated: showing first" not in html


# --------------------------------------------------------------------------- #
# Lenient behavior on incomplete run directories
# --------------------------------------------------------------------------- #


def test_empty_run_directory_renders_absent_notes(tmp_path: Path) -> None:
    run_dir = tmp_path / "empty-run"
    run_dir.mkdir()

    result = render_run_visual(run_dir)

    html = result.read_text(encoding="utf-8")
    assert html.count("Not present in this run directory.") >= 8
    assert "Raw artifacts" in html


def test_unparsable_artifact_renders_as_absent(tmp_path: Path) -> None:
    run_dir = tmp_path / "broken-run"
    run_dir.mkdir()
    (run_dir / "run-manifest.yaml").write_text(":: not yaml [", encoding="utf-8")

    result = render_run_visual(run_dir)

    html = result.read_text(encoding="utf-8")
    assert "Not present in this run directory." in html


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_renders_run_directory(run_dir: Path) -> None:
    result = runner.invoke(app, ["render-run", "--run-dir", str(run_dir)])

    assert result.exit_code == 0, result.output
    assert (run_dir / OUTPUT_FILENAME).exists()
    assert "Run visualization written to" in result.output


def test_cli_output_override(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh-run"
    _make_run(fresh)
    target = tmp_path / "elsewhere.html"

    result = runner.invoke(
        app, ["render-run", "--run-dir", str(fresh), "--output", str(target)]
    )

    assert result.exit_code == 0, result.output
    assert target.exists()
    assert not (fresh / OUTPUT_FILENAME).exists()


def test_cli_missing_run_dir_fails(run_dir: Path, tmp_path: Path) -> None:
    result = runner.invoke(app, ["render-run", "--run-dir", str(tmp_path / "nope")])

    assert result.exit_code == 1
    assert "run directory not found" in result.output

"""Driver accounting must not confuse no compilation with a passing smoke test."""

from __future__ import annotations

import json
import socket
from types import SimpleNamespace

import pytest

import crossrepo_smoke as tool


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("offline driver test attempted network access")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "create_connection", deny)


def _compiled():
    return {
        "scenario_id": "SCN-001",
        "status": "compiled",
        "oracle_kind": "output_text",
        "delivery_class": "direct_prompt",
        "case_errors": [],
        "trace_errors": [],
        "compiled_validation_ok": True,
        "fidelity": {"output_text": {"proposition_preserved": True}},
    }


def _chain(tmp_path, monkeypatch, entries):
    """Exercise the real chain/report aggregation with public-chain outcomes.

    Consumer fixture tests cover producing these outcomes through the public
    interfaces. These tests cover the driver's previously untested interpretation
    of successful compilation, readiness loss, and typed exclusions.
    """
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    verified = SimpleNamespace(
        intents=tuple(entries), schema_version="v2", run_id="run"
    )
    monkeypatch.setattr(
        tool,
        "_consumer_imports",
        lambda _: {"load_execution_bundle": lambda _: verified},
    )
    monkeypatch.setattr(tool, "_entry_outcome", lambda _i, entry, _p: entry)
    probes = []

    def negative(*args):
        probes.append("issued")
        return [{"rejected": True}]

    monkeypatch.setattr(tool, "_negative_probes", negative)
    output = tmp_path / "report.json"
    exit_code = tool._chain_phase(bundle, tmp_path, output)
    return exit_code, json.loads(output.read_text()), probes


@pytest.mark.parametrize(
    "entry",
    [
        {
            "scenario_id": "SCN-001",
            "status": "excluded",
            "exclusion_code": "needs_environment_binding",
        },
        {"scenario_id": "SCN-001", "status": "not_ready", "readiness": "blocked"},
    ],
)
def test_no_compilation_is_blocked_not_passing(tmp_path, monkeypatch, entry):
    code, report, probes = _chain(tmp_path, monkeypatch, [entry])
    assert code == 1
    assert report["status"] == "blocked"
    assert report["checks"]["all_entries_compiled"] is False
    assert report["checks"]["overall_pass"] is False
    assert "no_compiled_entry" in report["limitations"]
    assert probes == []


@pytest.mark.parametrize("lost_status", ["excluded", "not_ready"])
def test_mixed_yield_is_partial_not_full_coverage(tmp_path, monkeypatch, lost_status):
    entries = [_compiled(), {"scenario_id": "SCN-002", "status": lost_status}]
    code, report, probes = _chain(tmp_path, monkeypatch, entries)
    assert code == 1
    assert report["status"] == "partial"
    assert report["checks"]["every_compiled_entry_valid"] is True
    assert report["checks"]["all_entries_compiled"] is False
    assert report["checks"]["overall_pass"] is False
    assert probes == ["issued"]


def test_complete_valid_compilation_passes(tmp_path, monkeypatch):
    code, report, _ = _chain(tmp_path, monkeypatch, [_compiled()])
    assert code == 0
    assert report["status"] == "passed"
    assert report["checks"]["all_entries_compiled"] is True
    assert report["checks"]["overall_pass"] is True


def test_compiled_fidelity_failure_is_failed(tmp_path, monkeypatch):
    entry = _compiled()
    entry["fidelity"]["output_text"]["proposition_preserved"] = False
    code, report, _ = _chain(tmp_path, monkeypatch, [entry])
    assert code == 1
    assert report["status"] == "failed"
    assert report["checks"]["overall_pass"] is False


def test_empty_bundle_does_not_pass(tmp_path, monkeypatch):
    code, report, probes = _chain(tmp_path, monkeypatch, [])
    assert code == 1
    assert report["status"] == "blocked"
    assert report["checks"]["overall_pass"] is False
    assert probes == []


@pytest.mark.parametrize("status", ["blocked", "partial"])
def test_orchestrator_preserves_noncoverage_status(tmp_path, monkeypatch, status):
    target = tmp_path / "target"
    target.mkdir()
    (target / tool.BUNDLE_FILENAME).write_text("{}")
    monkeypatch.setattr(tool, "_consumer_python", lambda _root, args: args)

    def run(command, **kwargs):
        output = command[command.index("--output") + 1]
        tool._write_json(
            tool.Path(output), {"status": status, "checks": {"overall_pass": False}}
        )
        return SimpleNamespace(returncode=1, stderr="")

    monkeypatch.setattr(tool.subprocess, "run", run)
    report_path = tmp_path / "aggregate.json"
    code = tool._orchestrate([target], tmp_path, report_path)
    report = json.loads(report_path.read_text())
    assert code == 1
    assert report["targets"][0]["status"] == status
    assert report["summary"][status] == 1
    assert report["summary"]["passed"] == 0
    assert report["checks"]["overall_pass"] is False


def test_missing_bundle_has_no_invented_functional_cause(tmp_path, monkeypatch):
    target = tmp_path / "no-bundle"
    target.mkdir()
    report_path = tmp_path / "aggregate.json"
    code = tool._orchestrate([target], tmp_path, report_path)
    report = json.loads(report_path.read_text())
    assert code == 1
    assert report["targets"][0]["status"] == "skipped_no_execution_bundle"
    assert (
        report["targets"][0]["limitation"]
        == "no execution bundle is present; its cause is not assessed"
    )
    assert report["checks"]["overall_pass"] is False

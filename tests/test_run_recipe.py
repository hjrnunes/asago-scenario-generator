"""Offline checks for the M1 run recipe and its budget/evidence registration.

The live half of the recipe (stack start/reset and MCP seeded-state verification)
runs against the mission runtime and is recorded in
``docs/development/adaptive-redesign/run-recipe.md``. These tests pin the offline
contract: the documented ports, the profile reader, the seed comparison, the port
polling helpers, and the delivered documentation paths.
"""

from __future__ import annotations

import importlib.util
import getpass
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "qualification" / "run_recipe.py"
_SLICE_DIR = _REPO_ROOT / "docs" / "development" / "adaptive-redesign"
_RECIPE_PATH = _SLICE_DIR / "run-recipe.md"
_BUDGET_PATH = _SLICE_DIR / "budget-registration.md"
_HANDOFF_NOTE_PATH = _REPO_ROOT / "docs" / "development" / "adaptive-handoff-slice.md"


def _load_recipe_module() -> Any:
    spec = importlib.util.spec_from_file_location("run_recipe", _SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def recipe() -> Any:
    return _load_recipe_module()


def test_documented_ports_match_the_stack_layout(recipe):
    assert recipe.STACK_PORTS == (8888, 8889, 8890, 8891, 8892, 8893, 8321)
    assert recipe.STACK_SERVERS == (
        ("klarna", 8888, False),
        ("klarna", 8889, True),
        ("airbnb", 8890, False),
        ("airbnb", 8891, True),
        ("occiai", 8892, False),
        ("occiai", 8893, True),
    )
    assert recipe.SAFE_STATE_URL == {
        "klarna": "http://127.0.0.1:8888/sse",
        "airbnb": "http://127.0.0.1:8890/sse",
        "occiai": "http://127.0.0.1:8892/sse",
    }
    assert recipe.STATE_TOOL == {
        "klarna": "get_klarna_state_summary",
        "airbnb": "get_airbnb_state_summary",
        "occiai": "get_occiai_state_summary",
    }


def test_read_profile_base_url_returns_endpoint(tmp_path):
    recipe = _load_recipe_module()
    profiles = tmp_path / "model-profiles.yaml"
    profiles.write_text(
        yaml.safe_dump(
            {"profiles": {"gemma4-oc": {"base_url": "http://example.test/v1/"}}}
        ),
        encoding="utf-8",
    )
    assert (
        recipe.read_profile_base_url(profiles, "gemma4-oc") == "http://example.test/v1/"
    )


def test_read_profile_base_url_supports_the_flat_layout(tmp_path):
    """The worktree profile file maps profile names directly, not under `profiles`."""
    recipe = _load_recipe_module()
    profiles = tmp_path / "model-profiles.yaml"
    profiles.write_text(
        yaml.safe_dump(
            {
                "gemma4-oc": {"base_url": "http://example.test/v1/", "model": "m"},
                "qwen38-oc": {"base_url": "http://other.test/v1/"},
            }
        ),
        encoding="utf-8",
    )
    assert (
        recipe.read_profile_base_url(profiles, "gemma4-oc") == "http://example.test/v1/"
    )
    assert (
        recipe.read_profile_base_url(profiles, "qwen38-oc") == "http://other.test/v1/"
    )


def test_read_profile_base_url_fails_closed(tmp_path):
    recipe = _load_recipe_module()
    profiles = tmp_path / "model-profiles.yaml"
    profiles.write_text(
        yaml.safe_dump({"profiles": {"other": {"base_url": ""}}}), encoding="utf-8"
    )
    with pytest.raises(ValueError):
        recipe.read_profile_base_url(profiles, "gemma4-oc")
    with pytest.raises(ValueError):
        recipe.read_profile_base_url(profiles, "other")


def _seed_summary() -> dict[str, Any]:
    return {
        "orders": {
            "ORD-101": {"remaining_to_pay": 40.0, "refund_eligible": True},
            "ORD-104": {"remaining_to_pay": 80.0, "refund_eligible": False},
        },
        "refunds": [],
    }


def test_seed_violations_accept_the_documented_seed(recipe):
    assert recipe.seed_violations(_seed_summary()) == []


def test_seed_violations_report_each_deviation(recipe):
    dirty = _seed_summary()
    dirty["orders"]["ORD-101"]["remaining_to_pay"] = 35.0
    dirty["refunds"] = [{"refund_id": "REF-1", "amount": 5.0}]
    violations = recipe.seed_violations(dirty)
    assert any("ORD-101 remaining_to_pay is 35.0" in item for item in violations)
    assert any("refunds is" in item for item in violations)
    assert not any("ORD-104" in item for item in violations)

    flipped = _seed_summary()
    flipped["orders"]["ORD-104"]["refund_eligible"] = True
    assert any(
        "ORD-104 refund_eligible is True" in item
        for item in recipe.seed_violations(flipped)
    )

    missing = _seed_summary()
    del missing["orders"]["ORD-101"]
    assert any("ORD-101 is absent" in item for item in recipe.seed_violations(missing))


def test_wait_for_ports_returns_once_every_port_accepts(recipe):
    recipe.wait_for_ports((1, 2, 3), timeout=1.0, probe=lambda _port: True, sleep=0)


def test_wait_for_ports_times_out_naming_the_offenders(recipe):
    with pytest.raises(TimeoutError) as error:
        recipe.wait_for_ports(
            (8888, 8889), timeout=0.01, probe=lambda _port: False, sleep=0
        )
    assert "[8888, 8889]" in str(error.value)


def test_wait_for_ports_closed_reports_still_listening(recipe):
    recipe.wait_for_ports_closed(
        (8888,), timeout=1.0, probe=lambda _port: False, sleep=0
    )
    with pytest.raises(TimeoutError):
        recipe.wait_for_ports_closed(
            (8888,), timeout=0.01, probe=lambda _port: True, sleep=0
        )


def test_recipe_exposes_injectable_cleanup_seam(tmp_path, recipe):
    """The maintained recipe exports the atomic cleanup contract."""
    stop_calls: list[str] = []
    process_identity = {
        "pid": 111,
        "ppid": 1,
        "owner": getpass.getuser(),
        "command": "python -m mini_agents --domain klarna --port 8888",
        "exists": True,
        "ancestry": [
            {
                "pid": 111,
                "ppid": 1,
                "owner": getpass.getuser(),
                "command": "python -m mini_agents --domain klarna --port 8888",
            }
        ],
        "cwd": recipe._CLEANUP_SEAM.DEFAULT_MISSION_PATH,
        "mission_path": recipe._CLEANUP_SEAM.DEFAULT_MISSION_PATH,
        "mission_path_in_command": False,
    }
    process_observations = iter(
        (
            [process_identity],
            [],
        )
    )

    def process_evidence(pattern: str) -> list[dict[str, object]]:
        return next(process_observations)

    def stop(pattern: str) -> str:
        stop_calls.append(pattern)
        return "exit 0"

    probes = recipe.CleanupProbes(
        process_evidence=process_evidence,
        stop=stop,
        stop_command="test-stop",
        port_is_listening=lambda _port: False,
        wait_ports_closed=lambda _ports, _timeout: None,
        wait_processes_exit=lambda _processes, _timeout: {
            "result": "confirmed",
            "survivors": [],
        },
    )
    record = recipe.run_stack_cleanup(
        run_id="recipe-run",
        target="klarna",
        record_path=tmp_path / "cleanup" / "stack-cleanup.json",
        probes=probes,
    )

    assert record["status"] == "completed"
    assert record["checked_ports"] == [8321, 8888, 8890, 8892]
    assert record["process_evidence"] == [process_identity]
    assert record["stop_result"] == "exit 0"
    assert record["recorded_at"]
    assert stop_calls == [recipe._CLEANUP_SEAM.SAFE_PROCESS_PATTERN]


def test_safe_recipe_commands_parse_individual_components(recipe, tmp_path):
    parser = recipe.build_parser()

    gateway = parser.parse_args(
        [
            "start-safe",
            "--component",
            "gateway",
            "--port",
            "8321",
            "--state-dir",
            str(tmp_path / "gateway"),
            "--profile",
            "gemma4-oc",
        ]
    )
    target = parser.parse_args(
        [
            "start-safe",
            "--component",
            "target",
            "--domain",
            "airbnb",
            "--port",
            "8890",
            "--state-dir",
            str(tmp_path / "airbnb"),
        ]
    )

    assert gateway.handler is recipe._command_start_safe
    assert target.handler is recipe._command_start_safe
    assert gateway.component == "gateway"
    assert target.domain == "airbnb"


def test_dirty_default_is_one_small_legal_refund(recipe):
    tool, arguments = recipe.DEFAULT_DIRTY["klarna"]
    assert tool == "process_refund"
    assert arguments["order_id"] == "ORD-101"
    assert 0 < arguments["amount"] < 100.0  # below the HITL review threshold


def test_handoff_note_rows_resolve_to_delivered_files():
    note = _HANDOFF_NOTE_PATH.read_text(encoding="utf-8")
    for path in (
        "docs/development/adaptive-redesign/run-recipe.md",
        "docs/development/adaptive-redesign/budget-registration.md",
    ):
        assert path in note, path
        assert (_REPO_ROOT / path).is_file(), path
    # The placeholder text is replaced and the other rows are unchanged.
    assert "delivered by the companion feature `m1-run-recipe`" not in note
    assert "docs/development/adaptive-redesign/scn-007-design-fixture.yaml" in note
    assert "docs/development/adaptive-redesign-revisions.md" in note


def test_recipe_doc_carries_the_required_steps():
    text = _RECIPE_PATH.read_text(encoding="utf-8")
    assert "uv run mini-agents-stack" in text
    assert "gemma4-oc" in text
    assert "OPENAI_BASE_URL" in text
    assert "mini-agents/.env" in text or "its `.env`" in text
    assert "reset" in text.lower()
    assert "check_state.py" in text
    assert "get_klarna_state_summary" in text
    assert "ORD-101" in text and "40.0" in text
    assert "process_refund" in text
    assert "teardown" in text.lower()
    # The five M2 evidence locations.
    lowered = text.lower()
    for artifact in (
        "qualification.json",
        "garak-attempts.jsonl",
        "judge",
        "before/after",
        "detector result",
    ):
        assert artifact in lowered, artifact
    assert "observation level" in lowered
    assert "applicability" in lowered


def test_recipe_doc_never_reuses_historical_evidence():
    lowered = _RECIPE_PATH.read_text(encoding="utf-8").lower()
    assert "historical" in lowered
    assert "never" in lowered
    assert "reuse" in lowered


def test_budget_registration_lists_stages_cap_statement_and_rules():
    text = _BUDGET_PATH.read_text(encoding="utf-8")
    for stage in (
        "Producer generation runs",
        "Consumer artifact designs",
        "Target-side Garak generations",
        "Semantic judge calls",
        "Smoke/health",
    ):
        assert stage in text, stage
    assert "planning estimates" in text.lower()
    assert "no hard" in text.lower()
    assert "2026-09-14" in text
    for rule in (
        "Every attempt is preserved",
        "Safe server first",
        "Never retry toward a preferred verdict",
        "Usage is reported by stage",
    ):
        assert rule in text, rule


def test_documents_do_not_leak_non_loopback_endpoints():
    for path in (_RECIPE_PATH, _BUDGET_PATH):
        text = path.read_text(encoding="utf-8")
        hosts = set(re.findall(r"https?://([A-Za-z0-9._-]+)", text))
        assert hosts <= {"127.0.0.1", "localhost"}, (path, hosts)

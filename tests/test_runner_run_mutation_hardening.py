"""Adversarial tests for runner-run orchestration contracts."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.pipeline import runner_run


def test_support_validation_disables_orphan_check(monkeypatch, tmp_path: Path) -> None:
    """Immutable support validation must not reject unrelated run artifacts."""
    resolver_args: dict[str, object] = {}

    class FakeResolver:
        def __init__(self, *args: object, **kwargs: object) -> None:
            resolver_args["check_orphans"] = kwargs["check_orphans"]

    monkeypatch.setattr(
        runner_run,
        "_support_published",
        lambda started_manifest, immutable_roles: True,
    )
    monkeypatch.setattr(runner_run, "ManifestInventoryResolver", FakeResolver)

    valid, error = runner_run._support_validation_result(
        tmp_path,
        object(),
        set(),
        RuntimeError("generation failed"),
    )

    assert valid is True
    assert error is None
    assert resolver_args["check_orphans"] is False


def test_candidate_filter_requests_advisory_failure_mode(monkeypatch, tmp_path: Path):
    """Filter protocol failures must be returned as advisory evidence."""
    call_args: dict[str, object] = {}

    def fake_filter_candidates(*args: object, **kwargs: object):
        call_args["advisory_on_failure"] = kwargs["advisory_on_failure"]
        return [], [], [], []

    monkeypatch.setattr(runner_run, "filter_candidates", fake_filter_candidates)

    result = runner_run._run_candidate_filter(
        [],
        [],
        object(),
        "use-case",
        object(),
        tmp_path,
    )

    assert result == ([], [], [], [])
    assert call_args["advisory_on_failure"] is True

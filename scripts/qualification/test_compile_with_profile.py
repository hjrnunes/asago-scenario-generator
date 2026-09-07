"""Offline verification of the external artifact CLI observer."""

import json
import sys

import pytest

pytest.importorskip("asago_artifact_generator")

import compile_with_profile as adapter  # noqa: E402


def test_forwards_cli_and_records_actual_author_return(monkeypatch, tmp_path):
    calls = tmp_path / "calls.jsonl"
    configured = {}
    forwarded = []
    monkeypatch.setattr(
        adapter,
        "load_profile",
        lambda path, name: {
            "base_url": "http://private-test.invalid/v1",
            "api_key": "secret-not-for-log",
            "model": name,
        },
    )
    monkeypatch.setattr(
        adapter.llm, "configure_llm", lambda **kwargs: configured.update(kwargs)
    )
    monkeypatch.setattr(
        adapter.llm, "llm_json", lambda *args, **kwargs: {"slot-1": "actual text"}
    )

    def invoke(*, args):
        forwarded.extend(args)
        assert adapter.llm.llm_json("prompt", "system") == {"slot-1": "actual text"}

    monkeypatch.setattr(adapter.cli, "app", invoke)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compile_with_profile.py",
            "--profiles",
            "profiles.yaml",
            "--profile",
            "gemma-test",
            "--call-log",
            str(calls),
            "--",
            "generate",
            "--bundle",
            "bundle.json",
        ],
    )
    adapter.main()
    assert forwarded == ["generate", "--bundle", "bundle.json"]
    assert configured["model"] == "gemma-test"
    record = json.loads(calls.read_text())
    assert record["positional_inputs"] == ["prompt", "system"]
    assert record["response"] == {"slot-1": "actual text"}
    assert "secret-not-for-log" not in calls.read_text()

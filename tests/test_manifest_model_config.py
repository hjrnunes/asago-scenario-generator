"""Historical manifest model-provenance contracts."""

from __future__ import annotations

from asago_scenario_generator.manifest import ModelConfig


def test_historical_manifest_model_reads_endpoint_but_never_serializes_it() -> None:
    """Legacy readers accept old fields while new manifests omit them."""
    config = ModelConfig(
        model="fixture",
        base_url="https://private.apps.example/v1",
        temperature=0.4,
    )

    assert config.base_url == "https://private.apps.example/v1"
    assert "base_url" not in config.model_dump()


def test_offline_provenance_accepts_an_absent_base_url() -> None:
    config = ModelConfig(model="fixture", base_url=None, temperature=0.4)

    assert config.base_url is None

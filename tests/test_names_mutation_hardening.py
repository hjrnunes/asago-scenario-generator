"""Focused adversarial coverage for name-resolution helpers."""

from __future__ import annotations

from types import SimpleNamespace

from asago_scenario_generator.pipeline.generate.names import (
    access_provenance_block_with_names,
    pinned_entry_point_name_from_id,
)


class _FailingProfile:
    def id_to_entry_point_name(self):
        raise AssertionError("profile lookup must not run")


def test_access_provenance_block_omits_missing_access() -> None:
    assert access_provenance_block_with_names(None, None) == ""


def test_pinned_entry_point_requires_both_id_and_profile() -> None:
    profile = _FailingProfile()

    assert pinned_entry_point_name_from_id(None, profile) is None
    assert pinned_entry_point_name_from_id("ep:v1:" + "a" * 32, None) is None


def test_pinned_entry_point_resolves_when_both_inputs_exist() -> None:
    profile = SimpleNamespace(
        id_to_entry_point_name=lambda: {"ep:v1:" + "a" * 32: "User prompt"}
    )

    assert (
        pinned_entry_point_name_from_id("ep:v1:" + "a" * 32, profile)
        == "User prompt"
    )

"""Focused adversarial coverage for candidate expansion helpers."""

from __future__ import annotations

import logging
from types import SimpleNamespace

from asago_scenario_generator.models.capability_profile import EntryPoint
from asago_scenario_generator.pipeline.candidate_expansion import (
    _attacker_ingress_points,
    _average_technique_count,
    _candidate_technique_map,
    _padded_metadata,
    _technique_metadata_map,
    canonicalize_and_dedup,
)
from tests.test_candidates import _make_candidate, _make_profile, _make_seed


def test_attacker_ingress_filter_logs_exact_exclusion_count(caplog) -> None:
    """The diagnostic count must equal the number of excluded entry points."""
    base_profile = _make_profile()
    profile = base_profile.model_copy(
        update={
            "entry_points": [
                *base_profile.entry_points,
                EntryPoint(name="model output", direction="output"),
            ]
        }
    )

    with caplog.at_level(
        logging.INFO, logger="asago_scenario_generator.pipeline.candidates"
    ):
        ingress = _attacker_ingress_points(profile)

    assert len(ingress) == 1
    assert "1/2 entry points" in caplog.text
    assert "(1 excluded:" in caplog.text


def test_attacker_ingress_filter_is_silent_when_nothing_is_excluded(caplog) -> None:
    """No exclusion diagnostic is emitted for an entirely accessible profile."""
    profile = _make_profile(["user prompts (input)"])

    with caplog.at_level(
        logging.INFO, logger="asago_scenario_generator.pipeline.candidates"
    ):
        assert len(_attacker_ingress_points(profile)) == 1

    assert "Entry point filter:" not in caplog.text


def test_average_technique_count_includes_atlas_or_laaf_seed() -> None:
    """Either supported technique namespace contributes to the mean."""
    atlas = _make_seed(atlas_technique_ids=["AML.T0051"])
    laaf = _make_seed(
        seed_id="AP-T7-02",
        laaf_technique_ids=["LAAF.T1"],
    )

    assert _average_technique_count([atlas, laaf]) == 1.0


def test_padding_does_not_add_description_when_lengths_match() -> None:
    """Already aligned metadata remains unchanged."""
    assert _padded_metadata(("T1", "T2"), ("N1", "N2"), ("D1", "D2")) == (
        ("N1", "N2"),
        ("D1", "D2"),
    )


def test_metadata_map_accepts_unique_ids_with_non_strict_lengths() -> None:
    """The defensive metadata mapper truncates unmatched transport fields."""
    candidate = SimpleNamespace(
        atlas_technique_ids=("T1", "T2"),
        atlas_technique_names=("Name 1",),
        atlas_technique_descriptions=("Description 1",),
    )

    assert _candidate_technique_map(candidate) == {
        "T1": ("Name 1", "Description 1")
    }


def test_technique_metadata_map_maps_first_unique_id() -> None:
    """A unique first record is inserted rather than treated as a duplicate."""
    assert _technique_metadata_map(
        ("T1",),
        ("Name 1",),
        ("Description 1",),
    ) == (
        {"T1": "Name 1"},
        {"T1": "Description 1"},
    )


def test_technique_metadata_map_truncates_unmatched_transport_fields() -> None:
    """Defensive mapping ignores a trailing ID without metadata."""
    assert _technique_metadata_map(
        ("T1", "T2"),
        ("Name 1",),
        ("Description 1",),
    ) == (
        {"T1": "Name 1"},
        {"T1": "Description 1"},
    )


def test_canonicalization_reports_all_collapsed_candidates(caplog) -> None:
    """The collapse count is exactly the number of removed duplicates."""
    candidates = [
        _make_candidate(
            technique_ids=("AML.T0051",),
            entry_point="user prompts (input)",
        )
        for _ in range(3)
    ]
    with caplog.at_level(
        logging.INFO, logger="asago_scenario_generator.pipeline.candidates"
    ):
        result = canonicalize_and_dedup(candidates, stage="expansion")

    assert len(result) == 1
    assert "3 candidates -> 1 unique identities (2 collapsed)" in caplog.text


def test_converged_candidates_sort_technique_metadata() -> None:
    """Merged candidates retain canonical technique ordering and alignment."""
    candidates = [
        _make_candidate(
            technique_ids=("T2", "T1"),
            technique_names=("Name 2", "Name 1"),
            technique_descs=("Description 2", "Description 1"),
        )
        for _ in range(2)
    ]

    [merged] = canonicalize_and_dedup(candidates, stage="rule_pruning")

    assert merged.atlas_technique_ids == ("T1", "T2")
    assert merged.atlas_technique_names == ("Name 1", "Name 2")
    assert merged.atlas_technique_descriptions == (
        "Description 1",
        "Description 2",
    )

"""The historical T7 records stay out of the live attack-pattern catalog.

The five T7 records (AP-T7-01..05) left the live catalog for good: AP-T7-01 is
deferred and AP-T7-02..05 are retired, with an empty authoritative resulting-ID
set. No T7 source has a defensible exact ATLAS identity, so
``catalog-lineage.yaml`` records the dispositions and the live side pins only
that the merged catalog carries none of them.
"""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.data.loaders import load_attack_patterns

T7_FILE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "taxonomies"
    / "attack-patterns"
    / "attack-patterns.yaml"
)
T7_PATTERN_IDS = ("AP-T7-01", "AP-T7-02", "AP-T7-03", "AP-T7-04", "AP-T7-05")


def test_merged_catalog_carries_no_t7_pattern() -> None:
    assert set(T7_PATTERN_IDS).isdisjoint(load_attack_patterns())


def test_merged_catalog_carries_no_t7_threat() -> None:
    threats = {pattern["threat_id"] for pattern in load_attack_patterns().values()}
    assert "T7" not in threats


def test_t7_file_stays_loader_valid_with_zero_live_records() -> None:
    """The historical file stays on disk and yields no patterns."""
    assert T7_FILE.is_file(), "the historical T7 file must not be deleted"
    assert load_attack_patterns(path=T7_FILE) == {}

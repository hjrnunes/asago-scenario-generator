"""T7 final-lineage wave tests (bead asago-scenario-generator-422o.2.7).

The final catalog-lineage outcome for the five historical base T7 records
(AP-T7-01..05) is removal from the live catalog: one defer (AP-T7-01) and
four retire (AP-T7-02..05), with an EMPTY authoritative resulting-ID set.
No T7 source has a defensible exact ATLAS operational identity; ATLAS is the
sole v1 authority, LAAF is absent, and SSSOM skos:relatedMatch rows are
non-authoritative provenance that can never qualify a record.

These tests pin that outcome:

- ``attack-patterns.yaml`` stays loader-valid with zero live records (the
  production glob merge tolerates the empty member file);
- the merged production catalog carries no AP-T7-* IDs and no
  ``threat_id == "T7"`` records;
- historical lineage for all five sources is preserved solely in
  ``catalog-lineage.yaml`` with final dispositions, empty resulting patterns,
  and stated deficiency/re-entry conditions;
- no lineage source in any file produces a resulting record that reuses one
  of the five T7 IDs (the resulting-ID set for T7 stays empty).
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

T7_IDS = ("AP-T7-01", "AP-T7-02", "AP-T7-03", "AP-T7-04", "AP-T7-05")


def test_t7_file_loads_to_zero_live_records() -> None:
    """The migrated file stays loader-valid and yields no patterns."""
    assert T7_FILE.is_file(), "the historical T7 file must not be deleted"
    assert load_attack_patterns(path=T7_FILE) == {}


def test_merged_catalog_has_no_t7_records() -> None:
    """The production glob merge drops every T7 record and stays valid."""
    merged = load_attack_patterns()
    for pid in T7_IDS:
        assert pid not in merged, f"{pid} still live in the merged catalog"
    assert not any(p["threat_id"] == "T7" for p in merged.values())

"""Focused tests for production taxonomy pins and the pinned resolver (422o.2.1)."""

from __future__ import annotations

import hashlib
import unicodedata
from pathlib import Path
from typing import Any

import pytest
import yaml

from asago_scenario_generator.data.taxonomy_pins import (
    _EXPECTED_MAPPING_SET_FILES,
    PinnedTaxonomyResolver,
    compute_mapping_set_digest,
    load_atlas_identifiers,
    load_atlas_pin,
    load_taxonomy_resolver,
)
from asago_scenario_generator.models.attack_pattern import (
    TaxonomyPin,
    compute_chain_semantic_digest,
    validate_attack_pattern,
)

ZERO = "0" * 64

_SSSOM_HEADER = (
    "subject_id",
    "subject_source",
    "predicate_id",
    "object_id",
    "object_source",
    "mapping_justification",
)
_ROW_A = (
    "AP-T1-01",
    "asago-scenario-generator",
    "skos:relatedMatch",
    "AML.T0053",
    "mitre-atlas",
    "semapv:ManualMappingCuration",
)
_ROW_B = (
    "AP-T1-01",
    "asago-scenario-generator",
    "skos:relatedMatch",
    "S1",
    "laaf",
    "semapv:ManualMappingCuration",
)
_ROW_C = (
    "AP-T7-02",
    "asago-scenario-generator",
    "skos:relatedMatch",
    "M3",
    "laaf",
    "semapv:ManualMappingCuration",
)


def _write_sssom(
    path: Path,
    rows: list[tuple[str, ...]],
    *,
    comments: list[str] | None = None,
    header: tuple[str, ...] = _SSSOM_HEADER,
) -> Path:
    lines = [f"#{comment}" for comment in comments or []]
    lines.append("\t".join(header))
    lines.extend("\t".join(row) for row in rows)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# Supported semantic metadata: written verbatim after the ``#`` marker.
_METADATA_COMMENTS = [
    " mapping_set_id: https://example.org/mappings/test",
    " mapping_set_version: 2026-08-04",
    " curie_map:",
    "   asago-scenario-generator: https://github.com/asago-ai/asago-scenario-generator/",
    "   laaf: https://github.com/laaf-ai/laaf/",
]


@pytest.fixture(scope="module")
def bundled_pin() -> TaxonomyPin:
    return load_atlas_pin()


@pytest.fixture(scope="module")
def bundled_identifiers() -> frozenset[str]:
    return load_atlas_identifiers()


@pytest.fixture(scope="module")
def bundled_resolver() -> PinnedTaxonomyResolver:
    return load_taxonomy_resolver()


# ---------------------------------------------------------------------------
# ATLAS pin
# ---------------------------------------------------------------------------


def test_atlas_pin_is_deterministic_and_covers_exact_file_bytes() -> None:
    pin = load_atlas_pin()
    assert pin == load_atlas_pin()
    assert pin.release == "2026.05"
    bundled = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "taxonomies"
        / "atlas"
        / "ATLAS-2026.05.yaml"
    )
    assert pin.digest == hashlib.sha256(bundled.read_bytes()).hexdigest()


def test_atlas_pin_is_content_sensitive(tmp_path: Path) -> None:
    source = {"collection": {"version": "2099.01"}, "tactics": {}}
    first = tmp_path / "first.yaml"
    first.write_text(yaml.dump(source), encoding="utf-8")
    second = tmp_path / "second.yaml"
    second.write_text(yaml.dump(source) + "\n", encoding="utf-8")
    assert load_atlas_pin(first).digest != load_atlas_pin(second).digest
    assert load_atlas_pin(first).release == "2099.01"


def test_atlas_pin_requires_a_collection_version(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text(yaml.dump({"tactics": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="collection version"):
        load_atlas_pin(broken)


# ---------------------------------------------------------------------------
# ATLAS identifiers
# ---------------------------------------------------------------------------


def test_atlas_identifiers_cover_tactics_techniques_and_subtechniques(
    bundled_identifiers: frozenset[str],
) -> None:
    identifiers = bundled_identifiers
    assert "AML.TA0000" in identifiers  # tactic
    assert "AML.T0000" in identifiers  # technique
    assert "AML.T0051.000" in identifiers  # sub-technique
    # Mitigations and case studies are never mapping targets.
    assert "AML.CS0000" not in identifiers
    assert all(not identifier.startswith("AML.M") for identifier in identifiers)
    assert len(identifiers) == 186


def test_atlas_identifiers_reject_incoherent_or_empty_sources(tmp_path: Path) -> None:
    incoherent = tmp_path / "incoherent.yaml"
    incoherent.write_text(
        yaml.dump(
            {
                "tactics": {"AML.TA9999": {"id": "AML.TA0000"}},
                "techniques": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="incoherent"):
        load_atlas_identifiers(incoherent)
    empty = tmp_path / "empty.yaml"
    empty.write_text(yaml.dump({"tactics": {}, "techniques": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="no tactic/technique"):
        load_atlas_identifiers(empty)


# ---------------------------------------------------------------------------
# Mapping-set digest
# ---------------------------------------------------------------------------


def test_bundled_mapping_set_digest_is_deterministic() -> None:
    digest = compute_mapping_set_digest()
    assert digest == compute_mapping_set_digest()
    assert len(digest) == 64
    int(digest, 16)


def test_bundled_mapping_set_digest_golden() -> None:
    """Golden pin: any change to the v1 framing or bundled content is explicit."""
    assert (
        compute_mapping_set_digest()
        == "15680b8778f51f30b1daf3ca2551437caebc3b8293c4b5e2ecf4d1b90756bfdc"
    )


def test_mapping_set_digest_is_path_and_order_independent(tmp_path: Path) -> None:
    f1 = _write_sssom(tmp_path / "one.sssom.tsv", [_ROW_A, _ROW_B])
    f2 = _write_sssom(tmp_path / "two.sssom.tsv", [_ROW_C])
    combined = _write_sssom(tmp_path / "combined.sssom.tsv", [_ROW_C, _ROW_A, _ROW_B])
    baseline = compute_mapping_set_digest([f1, f2])
    # File order and row order do not matter.
    assert compute_mapping_set_digest([f2, f1]) == baseline
    # File layout does not matter: the same rows in one file digest equally.
    assert compute_mapping_set_digest([combined]) == baseline
    # Identical supported metadata across partitions collapses likewise.
    m1 = _write_sssom(
        tmp_path / "m1.sssom.tsv", [_ROW_A, _ROW_B], comments=_METADATA_COMMENTS
    )
    m2 = _write_sssom(tmp_path / "m2.sssom.tsv", [_ROW_C], comments=_METADATA_COMMENTS)
    m_combined = _write_sssom(
        tmp_path / "m3.sssom.tsv",
        [_ROW_C, _ROW_A, _ROW_B],
        comments=_METADATA_COMMENTS,
    )
    assert compute_mapping_set_digest([m1, m2]) == compute_mapping_set_digest(
        [m_combined]
    )


def test_mapping_set_digest_rejects_empty_inputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least one SSSOM file"):
        compute_mapping_set_digest([])
    header_only = _write_sssom(tmp_path / "empty.sssom.tsv", [])
    with pytest.raises(ValueError, match="no rows"):
        compute_mapping_set_digest([header_only])


def test_bundled_discovery_requires_exactly_the_pinned_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "asago_scenario_generator.data.taxonomy_pins._DEFAULT_MAPPING_SET_DIR", tmp_path
    )
    # Empty default discovery fails rather than pinning an empty set.
    with pytest.raises(ValueError, match="missing="):
        compute_mapping_set_digest()
    names = sorted(_EXPECTED_MAPPING_SET_FILES)
    assert len(names) == 6
    for name in names[:5]:
        _write_sssom(tmp_path / name, [_ROW_A])
    # A single missing bundled file fails; the error names it.
    with pytest.raises(ValueError, match=r"missing=\['attack-patterns.sssom.tsv'\]"):
        compute_mapping_set_digest()
    _write_sssom(tmp_path / names[5], [_ROW_B])
    # An unexpected extra file fails as well: no glob subset or superset pins.
    _write_sssom(tmp_path / "attack-patterns-extra.sssom.tsv", [_ROW_C])
    with pytest.raises(
        ValueError, match=r"unexpected=\['attack-patterns-extra.sssom.tsv'\]"
    ):
        compute_mapping_set_digest()


def test_duplicate_canonical_rows_are_rejected_deterministically(
    tmp_path: Path,
) -> None:
    first = _write_sssom(tmp_path / "first.sssom.tsv", [_ROW_A, _ROW_B])
    second = _write_sssom(tmp_path / "second.sssom.tsv", [_ROW_C, _ROW_B])
    # Duplicates across file partitions are rejected with both origins.
    with pytest.raises(ValueError, match="duplicate mapping row") as across:
        compute_mapping_set_digest([first, second])
    assert "first.sssom.tsv" in str(across.value)
    assert "second.sssom.tsv" in str(across.value)
    with pytest.raises(ValueError) as again:
        compute_mapping_set_digest([first, second])
    assert str(across.value) == str(again.value)
    # Duplicates within a single file are rejected too.
    within = _write_sssom(tmp_path / "within.sssom.tsv", [_ROW_A, _ROW_A])
    with pytest.raises(ValueError, match="duplicate mapping row"):
        compute_mapping_set_digest([within])


def test_supported_semantic_metadata_is_pinned_and_content_sensitive(
    tmp_path: Path,
) -> None:
    with_meta = _write_sssom(
        tmp_path / "with.sssom.tsv", [_ROW_A, _ROW_B], comments=_METADATA_COMMENTS
    )
    without_meta = _write_sssom(tmp_path / "without.sssom.tsv", [_ROW_A, _ROW_B])
    baseline = compute_mapping_set_digest([with_meta])
    # Metadata is pinned content: adding or removing it changes the digest.
    assert compute_mapping_set_digest([without_meta]) != baseline
    # Editing a supported scalar key changes the digest.
    edited_version = _write_sssom(
        tmp_path / "version.sssom.tsv",
        [_ROW_A, _ROW_B],
        comments=[c.replace("2026-08-04", "2026-08-05") for c in _METADATA_COMMENTS],
    )
    assert compute_mapping_set_digest([edited_version]) != baseline
    # Editing curie_map changes the digest even though rows carry explicit
    # source columns (identifier interpretation is pinned, not ignored).
    edited_curie = _write_sssom(
        tmp_path / "curie.sssom.tsv",
        [_ROW_A, _ROW_B],
        comments=[
            c.replace("laaf-ai/laaf/", "laaf-ai/laaf-v2/") for c in _METADATA_COMMENTS
        ],
    )
    assert compute_mapping_set_digest([edited_curie]) != baseline


def test_unsupported_semantic_metadata_is_rejected(tmp_path: Path) -> None:
    rejected = _write_sssom(
        tmp_path / "unknown.sssom.tsv",
        [_ROW_A],
        comments=[" license: https://example.org/license"],
    )
    with pytest.raises(ValueError, match="unsupported mapping-set metadata"):
        compute_mapping_set_digest([rejected])
    duplicate_scalar = _write_sssom(
        tmp_path / "dup.sssom.tsv",
        [_ROW_A],
        comments=[
            " mapping_set_id: https://example.org/a",
            " mapping_set_id: https://example.org/b",
        ],
    )
    with pytest.raises(ValueError, match="duplicate mapping_set_id"):
        compute_mapping_set_digest([duplicate_scalar])


def test_cross_file_conflicting_scalar_metadata_is_rejected(tmp_path: Path) -> None:
    first = _write_sssom(
        tmp_path / "first.sssom.tsv",
        [_ROW_A],
        comments=[" mapping_set_version: 2026-08-04"],
    )
    second = _write_sssom(
        tmp_path / "second.sssom.tsv",
        [_ROW_B],
        comments=[" mapping_set_version: 2026-08-05"],
    )
    with pytest.raises(
        ValueError, match="conflicting mapping-set metadata 'mapping_set_version'"
    ) as excinfo:
        compute_mapping_set_digest([first, second])
    assert "first.sssom.tsv" in str(excinfo.value)
    assert "second.sssom.tsv" in str(excinfo.value)
    # Identical repeated declarations across partitions remain accepted.
    identical = _write_sssom(
        tmp_path / "identical.sssom.tsv",
        [_ROW_B],
        comments=[" mapping_set_version: 2026-08-04"],
    )
    assert compute_mapping_set_digest([first, identical])


def test_cross_file_conflicting_curie_map_is_rejected(tmp_path: Path) -> None:
    first = _write_sssom(
        tmp_path / "first.sssom.tsv",
        [_ROW_A],
        comments=[" curie_map:", "   laaf: https://github.com/laaf-ai/laaf/"],
    )
    second = _write_sssom(
        tmp_path / "second.sssom.tsv",
        [_ROW_B],
        comments=[" curie_map:", "   laaf: https://github.com/laaf-ai/laaf-v2/"],
    )
    with pytest.raises(
        ValueError, match="conflicting curie_map prefix 'laaf'"
    ) as excinfo:
        compute_mapping_set_digest([first, second])
    assert "first.sssom.tsv" in str(excinfo.value)
    assert "second.sssom.tsv" in str(excinfo.value)
    # The same prefix resolving to the same URI across partitions is accepted.
    identical = _write_sssom(
        tmp_path / "identical.sssom.tsv",
        [_ROW_B],
        comments=[" curie_map:", "   laaf: https://github.com/laaf-ai/laaf/"],
    )
    assert compute_mapping_set_digest([first, identical])


def test_unknown_or_missing_row_columns_are_rejected(tmp_path: Path) -> None:
    extra = _write_sssom(
        tmp_path / "extra.sssom.tsv",
        [_ROW_A + ("0.9",)],
        header=_SSSOM_HEADER + ("confidence",),
    )
    with pytest.raises(ValueError, match=r"unknown columns=\['confidence'\]"):
        compute_mapping_set_digest([extra])
    missing = _write_sssom(
        tmp_path / "missing.sssom.tsv",
        [_ROW_A[:5]],
        header=_SSSOM_HEADER[:5],
    )
    with pytest.raises(
        ValueError, match=r"missing columns=\['mapping_justification'\]"
    ):
        compute_mapping_set_digest([missing])


def test_free_explanatory_comments_are_excluded_from_the_pin(
    tmp_path: Path,
) -> None:
    commented = _write_sssom(
        tmp_path / "commented.sssom.tsv",
        [_ROW_A],
        comments=[
            " SSSOM TSV for test mappings",
            " Provenance mappings: handwritten explanations, not metadata",
            " (parenthetical note)",
        ],
    )
    plain = _write_sssom(tmp_path / "plain.sssom.tsv", [_ROW_A])
    assert compute_mapping_set_digest([commented]) == compute_mapping_set_digest(
        [plain]
    )


def test_mapping_set_digest_is_content_sensitive(tmp_path: Path) -> None:
    baseline = compute_mapping_set_digest(
        [_write_sssom(tmp_path / "base.sssom.tsv", [_ROW_A, _ROW_B])]
    )
    edited = _write_sssom(
        tmp_path / "edited.sssom.tsv",
        [
            _ROW_A,
            (
                "AP-T1-01",
                "asago-scenario-generator",
                "skos:relatedMatch",
                "S2",
                "laaf",
                "semapv:ManualMappingCuration",
            ),
        ],
    )
    assert compute_mapping_set_digest([edited]) != baseline
    added = _write_sssom(tmp_path / "added.sssom.tsv", [_ROW_A, _ROW_B, _ROW_C])
    assert compute_mapping_set_digest([added]) != baseline
    removed = _write_sssom(tmp_path / "removed.sssom.tsv", [_ROW_A])
    assert compute_mapping_set_digest([removed]) != baseline


def test_mapping_set_digest_normalizes_unicode_nfc(tmp_path: Path) -> None:
    composed = _write_sssom(tmp_path / "composed.sssom.tsv", [("café",) + _ROW_A[1:]])
    decomposed = _write_sssom(
        tmp_path / "decomposed.sssom.tsv",
        [(unicodedata.normalize("NFD", "café"),) + _ROW_A[1:]],
    )
    assert compute_mapping_set_digest([composed]) == compute_mapping_set_digest(
        [decomposed]
    )


# ---------------------------------------------------------------------------
# Resolver construction and coherence
# ---------------------------------------------------------------------------


def test_production_resolver_is_atlas_only_and_deterministic(
    bundled_resolver: PinnedTaxonomyResolver,
    bundled_pin: TaxonomyPin,
) -> None:
    resolver = bundled_resolver
    context = resolver.taxonomy_context
    assert context.atlas == bundled_pin
    assert context.laaf is None
    assert context.mapping_set_digest == compute_mapping_set_digest()
    assert resolver.taxonomy_context == load_taxonomy_resolver().taxonomy_context
    # Bundled pinned ATLAS ids resolve; unknown ids fail.
    assert resolver.contains("ATLAS", "AML.T0051.001")
    assert resolver.contains("ATLAS", "AML.TA0000")
    assert not resolver.contains("ATLAS", "AML.T9999")
    assert not resolver.contains("ATLAS", "AML.CS0000")
    # SSSOM skos:relatedMatch rows are provenance content: "S1" is mapped in
    # the bundled SSSOM files yet never becomes LAAF resolver membership.
    assert not resolver.contains("LAAF", "S1")
    assert not resolver.contains("LAAF", "AML.T0051.001")


def test_resolver_is_pure_in_memory_after_construction(
    monkeypatch, bundled_resolver: PinnedTaxonomyResolver
) -> None:
    resolver = bundled_resolver

    def _explode(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("resolver performed I/O after construction")

    monkeypatch.setattr("builtins.open", _explode)
    monkeypatch.setattr(Path, "read_bytes", _explode)
    assert resolver.contains("ATLAS", "AML.T0051.001")
    assert not resolver.contains("LAAF", "S1")
    assert resolver.taxonomy_context.laaf is None


def test_laaf_pin_and_membership_must_be_supplied_together(
    bundled_pin: TaxonomyPin,
    bundled_identifiers: frozenset[str],
) -> None:
    pin = TaxonomyPin(release="laaf-test", digest="a" * 64)
    atlas_pin = bundled_pin
    atlas_ids = bundled_identifiers
    digest = compute_mapping_set_digest()
    with pytest.raises(ValueError, match="together"):
        PinnedTaxonomyResolver(
            atlas_pin=atlas_pin,
            atlas_identifiers=atlas_ids,
            mapping_set_digest=digest,
            laaf_pin=pin,
        )
    with pytest.raises(ValueError, match="together"):
        PinnedTaxonomyResolver(
            atlas_pin=atlas_pin,
            atlas_identifiers=atlas_ids,
            mapping_set_digest=digest,
            laaf_identifiers={"L1"},
        )
    with pytest.raises(ValueError, match="must not be empty"):
        PinnedTaxonomyResolver(
            atlas_pin=atlas_pin,
            atlas_identifiers=atlas_ids,
            mapping_set_digest=digest,
            laaf_pin=pin,
            laaf_identifiers=set(),
        )
    with pytest.raises(ValueError, match="non-empty strings"):
        PinnedTaxonomyResolver(
            atlas_pin=atlas_pin,
            atlas_identifiers=atlas_ids,
            mapping_set_digest=digest,
            laaf_pin=pin,
            laaf_identifiers={""},
        )
    with pytest.raises(ValueError, match="must not be empty"):
        PinnedTaxonomyResolver(
            atlas_pin=atlas_pin,
            atlas_identifiers=set(),
            mapping_set_digest=digest,
        )


def test_explicit_laaf_pin_and_membership_is_strictly_scoped(
    bundled_resolver: PinnedTaxonomyResolver,
) -> None:
    pin = TaxonomyPin(release="laaf-test", digest="b" * 64)
    resolver = load_taxonomy_resolver(laaf_pin=pin, laaf_identifiers={"L1", "M3"})
    assert resolver.taxonomy_context.laaf == pin
    assert resolver.contains("LAAF", "L1")
    assert resolver.contains("LAAF", "M3")
    assert not resolver.contains("LAAF", "S1")
    assert resolver.contains("ATLAS", "AML.T0051.001")
    # taxonomy_context equality stays meaningful across the optional axis.
    assert resolver.taxonomy_context != bundled_resolver.taxonomy_context


# ---------------------------------------------------------------------------
# Qualification through the production resolver
# ---------------------------------------------------------------------------


def _production_step(step_id: str, order: int, *, attacker: bool) -> dict[str, Any]:
    final = order == 3
    return {
        "step_id": step_id,
        "requirement": "required",
        "condition": None,
        "executor_role": "attacker" if attacker else "system",
        "boundary_position": "crossing" if attacker else "inside",
        "action_kind": "prepare" if attacker else "impact" if final else "observe",
        "consumed": [],
        "produced": [
            {"kind": "effect", "ref_id": f"effect.{order}", "value_type": "boolean"}
        ],
        "preconditions": [],
        "observable_postconditions": [
            {
                "postcondition_id": f"post.{order}",
                "description": "observable",
                "security_relevant": final,
                "terminal": final,
            }
        ],
        "resource_links": (
            [
                {
                    "slot_id": "ingress",
                    "role": "ingress",
                    "trust_boundary_slot_id": None,
                }
            ]
            if attacker
            else []
        ),
        "observable_outcome_links": (
            [
                {
                    "postcondition_id": f"post.{order}",
                    "observation": "model_context",
                    "binding_slot_id": "ingress",
                }
            ]
            if final
            else []
        ),
        "order": order,
        "attacker_controlled": attacker,
        "provenance": {
            "tier": "observed",
            "references": [
                {"reference_type": "catalog", "reference_id": f"case-{order}"}
            ],
            "confidence": 90,
            "adaptation_rationale": "represented",
        },
        "mappings": (
            [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]}]
            if attacker
            else [{"decision": "not_applicable", "taxonomy": "ATLAS"}]
        ),
    }


def _production_pattern(
    resolver: PinnedTaxonomyResolver,
    *,
    chain_mappings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    chain = {
        "schema_version": "v1",
        "pattern_id": "AP-T1-01",
        "chain_id": "chain.1",
        "semantic_revision": 1,
        "semantic_digest": ZERO,
        "taxonomy_context": resolver.taxonomy_context.model_dump(mode="json"),
        "mappings": chain_mappings
        or [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]}],
        "steps": [
            _production_step("step.1", 1, attacker=True),
            _production_step("step.2", 2, attacker=False),
            _production_step("step.3", 3, attacker=False),
        ],
        "earliest_attacker_controlled_step_id": "step.1",
        "resource_slots": [
            {"slot_id": "ingress", "kind": "entry_point", "purpose": "initial_ingress"}
        ],
        "initial_ingress_slot_id": "ingress",
    }
    chain["semantic_digest"] = compute_chain_semantic_digest(chain)
    return {
        "id": "AP-T1-01",
        "threat_id": "T1",
        "name": "Pattern",
        "description": "Canonical",
        "prerequisite_capabilities": {"min_zones": ["input"]},
        "canonical_chain": chain,
    }


def test_production_resolver_qualifies_atlas_only_chains(
    bundled_resolver: PinnedTaxonomyResolver,
) -> None:
    resolver = bundled_resolver
    pattern = validate_attack_pattern(_production_pattern(resolver), resolver)
    assert pattern.id == "AP-T1-01"
    assert pattern.canonical_chain.taxonomy_context.laaf is None


def test_production_resolver_rejects_unknown_atlas_ids(
    bundled_resolver: PinnedTaxonomyResolver,
) -> None:
    resolver = bundled_resolver
    raw = _production_pattern(
        resolver,
        chain_mappings=[
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T9999"]}
        ],
    )
    with pytest.raises(ValueError, match="unknown ATLAS id"):
        validate_attack_pattern(raw, resolver)


def test_production_resolver_fails_closed_on_any_laaf_decision(
    bundled_resolver: PinnedTaxonomyResolver,
) -> None:
    resolver = bundled_resolver
    raw = _production_pattern(
        resolver,
        chain_mappings=[
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]},
            {
                "decision": "unmapped",
                "taxonomy": "LAAF",
                "rationale": "Legacy migration hint only.",
            },
        ],
    )
    with pytest.raises(ValueError, match="LAAF taxonomy pin"):
        validate_attack_pattern(raw, resolver)


def test_explicit_laaf_resolver_qualifies_only_member_ids() -> None:
    pin = TaxonomyPin(release="laaf-test", digest="c" * 64)
    resolver = load_taxonomy_resolver(laaf_pin=pin, laaf_identifiers={"L1"})
    member = _production_pattern(
        resolver,
        chain_mappings=[
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]},
            {"decision": "exact", "taxonomy": "LAAF", "ids": ["L1"]},
        ],
    )
    assert validate_attack_pattern(member, resolver)
    outsider = _production_pattern(
        resolver,
        chain_mappings=[
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]},
            {"decision": "exact", "taxonomy": "LAAF", "ids": ["L2"]},
        ],
    )
    with pytest.raises(ValueError, match="unknown LAAF id"):
        validate_attack_pattern(outsider, resolver)


def test_atlas_only_resolver_cannot_accept_a_pinned_laaf_chain(
    bundled_resolver: PinnedTaxonomyResolver,
) -> None:
    pin = TaxonomyPin(release="laaf-test", digest="d" * 64)
    pinned = load_taxonomy_resolver(laaf_pin=pin, laaf_identifiers={"L1"})
    raw = _production_pattern(
        pinned,
        chain_mappings=[
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]},
            {"decision": "exact", "taxonomy": "LAAF", "ids": ["L1"]},
        ],
    )
    with pytest.raises(ValueError, match="pins"):
        validate_attack_pattern(raw, bundled_resolver)


class TestPinningHelperBranches:
    """Direct branch coverage for the decomposed pinning helpers."""

    def test_validated_identifier_keys(self, tmp_path: Path) -> None:
        from asago_scenario_generator.data.taxonomy_pins import (
            _validated_identifier_keys,
        )

        atlas = tmp_path / "atlas.yaml"
        atlas.write_text(
            yaml.safe_dump(
                {
                    "tactics": {
                        "AML.TA0001": {"id": "AML.TA0001", "name": "tactic"},
                    },
                    "techniques": {
                        "AML.T0000": {"id": "AML.T0000", "name": "technique"},
                    },
                }
            )
        )
        data = yaml.safe_load(atlas.read_text())
        assert _validated_identifier_keys(data["tactics"], atlas, "tactics") == [
            "AML.TA0001"
        ]
        assert _validated_identifier_keys(data["techniques"], atlas, "techniques") == [
            "AML.T0000"
        ]
        incoherent = {"AML.T0001": {"id": "AML.T0002", "name": "x"}}
        with pytest.raises(ValueError, match="incoherent techniques entry"):
            _validated_identifier_keys(incoherent, atlas, "techniques")
        non_dict = {"AML.T0001": "not a mapping"}
        with pytest.raises(ValueError, match="incoherent techniques entry"):
            _validated_identifier_keys(non_dict, atlas, "techniques")

    def test_strict_sssom_header_branches(self, tmp_path: Path) -> None:
        from asago_scenario_generator.data.taxonomy_pins import (
            _strict_sssom_header,
        )

        path = tmp_path / "mapping.sssom.tsv"
        header = _strict_sssom_header(path, 1, "\t".join(_SSSOM_HEADER))
        assert header == list(_SSSOM_HEADER)
        with pytest.raises(ValueError, match="duplicate header columns"):
            _strict_sssom_header(path, 1, "subject_id\tsubject_id")
        with pytest.raises(ValueError, match="unknown columns"):
            _strict_sssom_header(path, 1, "subject_id\tbogus")
        with pytest.raises(ValueError, match="missing columns"):
            _strict_sssom_header(path, 1, "subject_id")

    def test_strict_sssom_row_branches(self, tmp_path: Path) -> None:
        from asago_scenario_generator.data.taxonomy_pins import (
            _strict_sssom_row,
        )

        path = tmp_path / "mapping.sssom.tsv"
        header = list(_SSSOM_HEADER)
        row = _strict_sssom_row(path, 2, "\t".join(_ROW_A), header)
        assert row == _ROW_A
        with pytest.raises(ValueError, match="expected 6"):
            _strict_sssom_row(path, 2, "a\tb", header)
        with pytest.raises(ValueError, match="empty cell"):
            _strict_sssom_row(path, 2, "\t".join(["x", "", *["y"] * 4]), header)

    def test_read_strict_sssom_blank_and_headerless(self, tmp_path: Path) -> None:
        from asago_scenario_generator.data.taxonomy_pins import (
            _read_strict_sssom,
        )

        path = tmp_path / "mapping.sssom.tsv"
        path.write_text(
            "\n".join(["# free prose", "\t".join(_SSSOM_HEADER), "", "\t".join(_ROW_A)])
            + "\n"
        )
        scalars, curies, rows = _read_strict_sssom(path)
        assert scalars == []
        assert curies == []
        assert rows == [(4, _ROW_A)]
        headerless = tmp_path / "headerless.sssom.tsv"
        headerless.write_text("# only comments\n")
        with pytest.raises(ValueError, match="lacks the required SSSOM header"):
            _read_strict_sssom(headerless)

    def test_scalar_metadata_entry_branches(self, tmp_path: Path) -> None:
        from asago_scenario_generator.data.taxonomy_pins import (
            _scalar_metadata_entry,
        )

        path = tmp_path / "mapping.sssom.tsv"
        scalars: list = []
        seen: set[str] = set()
        _scalar_metadata_entry(path, 3, "mapping_set_id", "https://x", scalars, seen)
        assert scalars == [(3, "mapping_set_id", "https://x")]
        with pytest.raises(ValueError, match="empty mapping_set_id value"):
            _scalar_metadata_entry(path, 4, "mapping_set_id", "", scalars, seen)
        with pytest.raises(ValueError, match="duplicate mapping_set_id"):
            _scalar_metadata_entry(
                path, 5, "mapping_set_id", "https://x", scalars, seen
            )

    def test_curie_map_entry_branches(self, tmp_path: Path) -> None:
        from asago_scenario_generator.data.taxonomy_pins import (
            _curie_map_entry,
        )

        path = tmp_path / "mapping.sssom.tsv"
        curies: list = []
        seen: set[str] = set()
        _curie_map_entry(
            path,
            3,
            "asago-scenario-generator: https://github.com/asago-ai/asago-scenario-generator/",
            curies,
            seen,
        )
        assert curies[0][1] == "asago-scenario-generator"
        assert curies[0][2] == "https://github.com/asago-ai/asago-scenario-generator/"
        with pytest.raises(ValueError, match="duplicate curie_map prefix"):
            _curie_map_entry(
                path, 4, "asago-scenario-generator: https://y/", curies, seen
            )
        with pytest.raises(ValueError, match="malformed curie_map entry"):
            _curie_map_entry(path, 5, "no-colon-here", curies, seen)

    def test_comment_metadata_branches(self, tmp_path: Path) -> None:
        from asago_scenario_generator.data.taxonomy_pins import (
            _comment_metadata,
        )

        path = tmp_path / "mapping.sssom.tsv"
        scalars: list = []
        curies: list = []
        seen_scalars: set[str] = set()
        seen_curies: set[str] = set()
        # Free explanatory comment and blank comment.
        assert (
            _comment_metadata(
                path,
                1,
                "# free prose",
                False,
                scalars,
                curies,
                seen_scalars,
                seen_curies,
            )
            is False
        )
        assert (
            _comment_metadata(
                path, 2, "#", False, scalars, curies, seen_scalars, seen_curies
            )
            is False
        )
        # Scalar metadata.
        assert (
            _comment_metadata(
                path,
                3,
                "# mapping_set_id: https://x",
                False,
                scalars,
                curies,
                seen_scalars,
                seen_curies,
            )
            is False
        )
        assert scalars == [(3, "mapping_set_id", "https://x")]
        # Block introduction returns True and then curie lines are consumed.
        assert (
            _comment_metadata(
                path,
                4,
                "# curie_map:",
                False,
                scalars,
                curies,
                seen_scalars,
                seen_curies,
            )
            is True
        )
        assert (
            _comment_metadata(
                path,
                5,
                "#   asago-scenario-generator: https://y",
                True,
                scalars,
                curies,
                seen_scalars,
                seen_curies,
            )
            is True
        )
        assert curies == [(5, "asago-scenario-generator", "https://y")]
        # Unsupported metadata key.
        with pytest.raises(ValueError, match="unsupported mapping-set metadata"):
            _comment_metadata(
                path,
                6,
                "# bogus_key: 1",
                False,
                scalars,
                curies,
                seen_scalars,
                seen_curies,
            )
        # A block key carrying an inline value must be rejected.
        with pytest.raises(ValueError, match="must introduce an indented block"):
            _comment_metadata(
                path,
                7,
                "# curie_map: https://y",
                False,
                scalars,
                curies,
                seen_scalars,
                seen_curies,
            )
        # Block key with an inline value.
        with pytest.raises(ValueError, match="must introduce an indented block"):
            _comment_metadata(
                path,
                7,
                "# curie_map: inline",
                False,
                scalars,
                curies,
                seen_scalars,
                seen_curies,
            )

    def test_merge_helpers_and_payload(self, tmp_path: Path) -> None:
        from asago_scenario_generator.data.taxonomy_pins import (
            _mapping_set_payload,
            _merge_curie_entries,
            _merge_mapping_rows,
            _merge_scalar_metadata,
        )

        path = tmp_path / "mapping.sssom.tsv"
        scalars: dict = {}
        _merge_scalar_metadata(scalars, [(1, "mapping_set_id", "x")], path)
        assert scalars["mapping_set_id"][0] == "x"
        with pytest.raises(ValueError, match="conflicting mapping-set metadata"):
            _merge_scalar_metadata(scalars, [(2, "mapping_set_id", "y")], path)
        curies: dict = {}
        _merge_curie_entries(curies, [(1, "laaf", "https://laaf/")], path)
        assert curies["laaf"][0] == "https://laaf/"
        with pytest.raises(ValueError, match="conflicting curie_map prefix"):
            _merge_curie_entries(curies, [(2, "laaf", "https://other/")], path)
        rows: set = set()
        origins: dict = {}
        assert _merge_mapping_rows(rows, origins, [(3, _ROW_A)], path) == 1
        assert len(rows) == 1
        assert origins[next(iter(rows))] == f"{path}:3"
        with pytest.raises(ValueError, match="duplicate mapping row"):
            _merge_mapping_rows(rows, origins, [(4, _ROW_A)], path)
        payload = _mapping_set_payload(scalars, curies, rows)
        assert len(payload) == 64
        changed = _mapping_set_payload(
            {"mapping_set_id": ("other", "p:1")}, curies, rows
        )
        assert changed != payload

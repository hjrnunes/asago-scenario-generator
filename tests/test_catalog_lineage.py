"""Acceptance and mutation tests for the catalog-lineage decision artifact.

The artifact at ``data/taxonomies/attack-patterns/catalog-lineage.yaml`` is
the final authoritative lineage record for the 71 legacy attack-pattern
source IDs.  Normal validation is durable: it qualifies the immutable
artifact — closed vocabularies, resulting-record completeness,
resolver-backed exact mappings, split/supersede integrity, overlap-group
resolution, taxonomy pins, the pinned case-step citation gate, and the
deterministic NFC/order-normalized semantic digest (golden value) — from
artifact data plus the pinned ATLAS taxonomy alone, so it stays green after
later authoring waves migrate the live catalog (converted kill chains
removed, split-derived ids added).  The historical source-catalog snapshot
is committed in ``source_catalog_context`` (source git revision, six-file
manifest, record count, content digest) and is re-verified only by the
explicit ``verify_catalog_lineage_source_snapshot``, exercised below
against immutable synthetic fixtures.  These tests never consult the live
``load_attack_patterns()`` catalog.
"""

from __future__ import annotations

import copy
import random
import unicodedata
from typing import ClassVar

import pytest
import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from asago_scenario_generator.data.catalog_lineage import (
    _DEFAULT_LINEAGE_PATH,
    SOURCE_CATALOG_CANONICALIZATION,
    compute_catalog_lineage_digest,
    compute_source_catalog_digest,
    load_atlas_case_step_index,
    load_catalog_lineage,
    load_catalog_lineage_schema,
    validate_catalog_lineage,
    verify_catalog_lineage_source_snapshot,
)
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver

AP_DIR = _DEFAULT_LINEAGE_PATH.parent

GOLDEN_DIGEST = "bc3b20c4987b324a2e872d82719143157422c262342cd13cdc2a9656fd065a93"
# The historical source snapshot: the authoritative original catalog
# revision the decisions were made against, and the content digest of its
# 71 canonicalized loader records.  Golden so the durable pin can never
# drift silently.
GOLDEN_SOURCE_REVISION = "3af41929698c40f06ad4a286668167ef5bf084f0"
GOLDEN_SOURCE_DIGEST = (
    "1867079decd9d132b89625d62ae22353a6be9ea69fbdf755c7462ed816ed3fb4"
)

# Tokens that would indicate an unfinished decision.  Final language such as
# "split evaluation concluded" is a resolved decision and is not flagged.
_FORBIDDEN_TOKENS = (
    "provisional",
    "unresolved",
    "tbd",
    "to be determined",
    "to be decided",
    "split-eval",
    "supersede-eval",
    "pending decision",
)

_EXPECTED_GROUPS = {
    "OG-01": {"AP-T1-01", "AP-T5-01", "AP-T5-04"},
    "OG-02": {"AP-T1-04", "AP-T12-03"},
    "OG-03": {"AP-T2-05", "AP-T6-03"},
    "OG-04": {"AP-T2-06", "AP-T6-02"},
    "OG-05": {"AP-T4-02", "AP-T13-03", "AP-T14-03"},
    "OG-06": {"AP-T9-01", "AP-T9-05"},
    "OG-07": {"AP-T9-02", "AP-T9-06"},
    "OG-08": {"AP-T8-01", "AP-T8-02", "AP-T8-03"},
    "OG-09": {"AP-T12-01", "AP-T13-04"},
    "OG-10": {"AP-T12-02", "AP-T14-01", "AP-T14-04"},
    "OG-11": {"AP-T13-02", "AP-T14-02"},
}


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def case_steps():
    return load_atlas_case_step_index()


@pytest.fixture(scope="module")
def artifact(resolver, case_steps) -> dict:
    data = load_catalog_lineage()
    # The production artifact must pass the durable validation gate
    # unchanged — artifact data plus the pinned ATLAS taxonomy, never the
    # mutable live catalog.
    validate_catalog_lineage(data, resolver=resolver, case_steps=case_steps)
    return data


def _walk_strings(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _walk_strings(v)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, str):
        yield value


def _mutate(artifact: dict, fn) -> dict:
    mutant = copy.deepcopy(artifact)
    fn(mutant)
    return mutant


class TestSourceCoverage:
    def test_exactly_71_unique_historical_source_ids(self, artifact):
        ids = [s["source_pattern_id"] for s in artifact["sources"]]
        assert len(ids) == 71
        assert len(set(ids)) == 71

    def test_source_facts_are_self_attesting(self, artifact):
        """Without any live-catalog comparison, every source entry's
        recorded facts must be internally coherent and its file must be in
        the pinned manifest."""
        declared = set(artifact["source_catalog_context"]["file_manifest"])
        for entry in artifact["sources"]:
            assert entry["source_file"] in declared
            assert entry["threat_id"].strip()
            count = entry["evidence_count"]
            steps = entry["legacy_kill_chain_steps"]
            tier = entry["evidence_tier"]
            if tier in ("direct_demonstration", "enrichment"):
                assert count >= 1, entry["source_pattern_id"]
            elif tier == "kill_chain_only":
                assert count == 0 and steps >= 1, entry["source_pattern_id"]
            else:
                assert tier == "none"
                assert count == 0 and steps == 0, entry["source_pattern_id"]

    def test_corrected_audit_fact_counts(self, artifact):
        """The corrected audit facts hold: 46/25 kill-chain split, 9
        evidence-bearing records / 11 entries, 4 direct, 5 enrichment."""
        sources = artifact["sources"]
        assert sum(1 for s in sources if s["legacy_kill_chain_steps"] > 0) == 46
        assert sum(1 for s in sources if s["legacy_kill_chain_steps"] == 0) == 25
        evidence_bearing = [s for s in sources if s["evidence_count"] > 0]
        assert len(evidence_bearing) == 9
        assert sum(s["evidence_count"] for s in evidence_bearing) == 11
        direct = {
            s["source_pattern_id"]
            for s in sources
            if s["evidence_tier"] == "direct_demonstration"
        }
        assert direct == {"AP-T3-04", "AP-T6-06", "AP-T11-05", "AP-T17-03"}
        enrichment = {
            s["source_pattern_id"]
            for s in sources
            if s["evidence_tier"] == "enrichment"
        }
        assert enrichment == {
            "AP-T1-01",
            "AP-T1-06",
            "AP-T11-01",
            "AP-T11-02",
            "AP-T17-01",
        }


class TestClosedVocabulary:
    def test_schema_is_valid_draft_2020_12(self):
        schema = load_catalog_lineage_schema()
        Draft202012Validator.check_schema(schema)

    def test_artifact_validates_against_schema(self, artifact):
        schema = load_catalog_lineage_schema()
        Draft202012Validator(schema).validate(artifact)

    def test_dispositions_come_from_closed_vocabulary(self, artifact):
        vocabulary = set(artifact["disposition_vocabulary"])
        assert vocabulary == {
            "retain",
            "narrow",
            "split",
            "supersede",
            "retire",
            "defer",
        }
        for entry in artifact["sources"]:
            assert entry["disposition"] in vocabulary

    def test_no_unresolved_or_provisional_language(self, artifact):
        for text in _walk_strings(artifact):
            lowered = text.lower()
            for token in _FORBIDDEN_TOKENS:
                assert token not in lowered, f"forbidden token {token!r} in {text!r}"


class TestResultingRecords:
    def test_every_result_is_complete(self, artifact):
        for entry in artifact["sources"]:
            if entry["disposition"] in ("retire", "defer"):
                continue
            assert entry["resulting_patterns"], entry["source_pattern_id"]
            for record in entry["resulting_patterns"]:
                assert record["mechanism_boundary"].strip()
                assert record["source_file"] == entry["source_file"]
                assert record["start_semantics"].strip()
                assert record["terminal_semantics"].strip()
                assert record["resource_slot_plan"], record["pattern_id"]
                assert record["provenance_plan"].strip()
                assert record["atlas_chain_mappings"], record["pattern_id"]
                assert record["atlas_step_mappings"], record["pattern_id"]

    def test_every_proposed_exact_id_exists_with_semantics(self, artifact, resolver):
        for entry in artifact["sources"]:
            for record in entry["resulting_patterns"]:
                mappings = (
                    record["atlas_chain_mappings"] + record["atlas_step_mappings"]
                )
                for mapping in mappings:
                    assert resolver.contains("ATLAS", mapping["id"]), (
                        f"{record['pattern_id']} proposes {mapping['id']} "
                        "absent from the production resolver"
                    )
                    # Mere membership is not semantic approval: the identity
                    # rationale and evidence citation must be nonblank.
                    assert mapping["operational_identity_rationale"].strip()
                    assert mapping["evidence"].strip()

    def test_no_proposed_id_is_a_tactic_or_case_study(self, artifact):
        for entry in artifact["sources"]:
            for record in entry["resulting_patterns"]:
                for mapping in (
                    record["atlas_chain_mappings"] + record["atlas_step_mappings"]
                ):
                    assert not mapping["id"].startswith("AML.TA")
                    assert not mapping["id"].startswith("AML.CS")


class TestSplitSupersedeIntegrity:
    def test_retired_and_deferred_have_no_results(self, artifact):
        for entry in artifact["sources"]:
            if entry["disposition"] in ("retire", "defer"):
                assert entry["resulting_patterns"] == []
                assert entry["deficiency"].strip()
                assert entry["reentry_conditions"].strip()

    def test_split_map_is_complete_and_explicit(self, artifact):
        expected = {
            "AP-T3-04": ["AP-T3-04", "AP-T3-05", "AP-T3-06"],
            "AP-T6-06": ["AP-T6-06", "AP-T6-07"],
            "AP-T9-02": ["AP-T9-02", "AP-T9-07"],
            "AP-T17-03": ["AP-T17-03", "AP-T17-04"],
        }
        splits = {
            s["source_pattern_id"]: [r["pattern_id"] for r in s["resulting_patterns"]]
            for s in artifact["sources"]
            if s["disposition"] == "split"
        }
        assert splits == expected

    def test_resulting_ids_unique_and_collision_free(self, artifact):
        historical_ids = {s["source_pattern_id"] for s in artifact["sources"]}
        resulting = [
            (entry["source_pattern_id"], record["pattern_id"])
            for entry in artifact["sources"]
            for record in entry["resulting_patterns"]
        ]
        ids = [rid for _, rid in resulting]
        assert len(ids) == len(set(ids))
        for pid, rid in resulting:
            if rid in historical_ids:
                # Only a source continuing its own id may reuse a
                # historical catalog id.
                assert rid == pid

    def test_split_derived_ids_follow_deterministic_naming(self, artifact):
        family_used: dict[str, set[int]] = {}
        for cid in (s["source_pattern_id"] for s in artifact["sources"]):
            fam, _, nn = cid.removeprefix("AP-T").partition("-")
            family_used.setdefault(fam, set()).add(int(nn))
        for entry in sorted(artifact["sources"], key=lambda e: e["source_pattern_id"]):
            if entry["disposition"] != "split":
                continue
            pid = entry["source_pattern_id"]
            fam = pid.removeprefix("AP-T").partition("-")[0]
            results = entry["resulting_patterns"]
            assert results[0]["pattern_id"] == pid
            used = family_used[fam]
            for record in results[1:]:
                nn = 1
                while nn in used:
                    nn += 1
                assert record["pattern_id"] == f"AP-T{fam}-{nn:02d}"
                used.add(nn)

    def test_resulting_file_ownership_is_non_overlapping(self, artifact):
        """Every resulting record stays with its source file, so later
        authoring waves partition cleanly by file."""
        for entry in artifact["sources"]:
            for record in entry["resulting_patterns"]:
                assert record["source_file"] == entry["source_file"]


class TestOverlapGroups:
    def test_expected_groups_with_one_resolution_each(self, artifact):
        groups = {g["group_id"]: g for g in artifact["overlap_groups"]}
        assert set(groups) == set(_EXPECTED_GROUPS)
        for gid, members in _EXPECTED_GROUPS.items():
            assert set(groups[gid]["members"]) == members
            assert groups[gid]["resolution"].strip()

    def test_membership_consistent_with_entries(self, artifact):
        member_to_group = {
            member: g["group_id"]
            for g in artifact["overlap_groups"]
            for member in g["members"]
        }
        for entry in artifact["sources"]:
            pid = entry["source_pattern_id"]
            assert entry["overlap_group"] == member_to_group.get(pid)


class TestTaxonomyPins:
    def test_pins_match_production_resolver(self, artifact, resolver):
        context = artifact["taxonomy_context"]
        expected = resolver.taxonomy_context
        assert context["atlas"]["release"] == expected.atlas.release
        assert context["atlas"]["digest"] == expected.atlas.digest
        assert context["mapping_set_digest"] == expected.mapping_set_digest
        assert context["laaf"] is None
        assert expected.laaf is None

    def test_sssom_rows_are_provenance_only(self, artifact):
        """SSSOM candidates live exclusively under provenance; mapping fields
        never silently inherit them without an identity rationale."""
        for entry in artifact["sources"]:
            assert "sssom_atlas_candidates" in entry["provenance"]
            for record in entry["resulting_patterns"]:
                for mapping in (
                    record["atlas_chain_mappings"] + record["atlas_step_mappings"]
                ):
                    assert mapping["operational_identity_rationale"].strip()


class TestDigest:
    def test_golden_digest(self, artifact):
        assert artifact["release"]["semantic_digest"] == GOLDEN_DIGEST
        assert compute_catalog_lineage_digest(artifact) == GOLDEN_DIGEST

    def test_digest_is_order_insensitive(self, artifact):
        shuffled = copy.deepcopy(artifact)
        rng = random.Random(20260805)
        shuffled["sources"] = rng.sample(shuffled["sources"], len(shuffled["sources"]))
        shuffled["overlap_groups"] = list(reversed(shuffled["overlap_groups"]))
        reordered = {k: shuffled[k] for k in reversed(list(shuffled.keys()))}
        assert compute_catalog_lineage_digest(reordered) == GOLDEN_DIGEST

    def test_digest_is_nfc_normalized(self, artifact):
        nfd = copy.deepcopy(artifact)
        nfd["release"]["description"] = unicodedata.normalize("NFD", "Café — lineage")
        nfc = copy.deepcopy(artifact)
        nfc["release"]["description"] = unicodedata.normalize("NFC", "Café — lineage")
        assert compute_catalog_lineage_digest(nfd) == compute_catalog_lineage_digest(
            nfc
        )
        assert compute_catalog_lineage_digest(nfc) != GOLDEN_DIGEST

    def test_digest_excludes_only_its_own_field(self, artifact):
        # Mutating the digest field alone must not change the recomputed value.
        mutated = copy.deepcopy(artifact)
        mutated["release"]["semantic_digest"] = "0" * 64
        assert compute_catalog_lineage_digest(mutated) == GOLDEN_DIGEST
        # Mutating anything else must change it.
        for fn in (
            lambda a: a["sources"][0].__setitem__("rationale", "tampered"),
            lambda a: a["overlap_groups"][0].__setitem__("resolution", "tampered"),
            lambda a: a.__setitem__("schema_version", "2"),
        ):
            mutant = _mutate(artifact, fn)
            assert compute_catalog_lineage_digest(mutant) != GOLDEN_DIGEST


class TestMutationRejection:
    def _expect_failure(self, artifact, fn, resolver, case_steps):
        mutant = _mutate(artifact, fn)
        # Keep the digest consistent so the mutation under test is what fails.
        mutant["release"]["semantic_digest"] = compute_catalog_lineage_digest(mutant)
        with pytest.raises((ValueError, ValidationError)):
            validate_catalog_lineage(mutant, resolver=resolver, case_steps=case_steps)

    def test_missing_source_rejected(self, artifact, resolver, case_steps):
        self._expect_failure(
            artifact,
            lambda a: a["sources"].pop(0),
            resolver,
            case_steps,
        )

    def test_extra_source_rejected(self, artifact, resolver, case_steps):
        def add(a):
            dupe = copy.deepcopy(a["sources"][0])
            dupe["source_pattern_id"] = "AP-T99-01"
            a["sources"].append(dupe)

        self._expect_failure(artifact, add, resolver, case_steps)

    def test_result_on_retired_source_rejected(self, artifact, resolver, case_steps):
        def add(a):
            retired = next(s for s in a["sources"] if s["disposition"] == "retire")
            donor = next(
                r
                for s in a["sources"]
                for r in s["resulting_patterns"]
                if r["pattern_id"] == s["source_pattern_id"]
            )
            record = copy.deepcopy(donor)
            record["pattern_id"] = retired["source_pattern_id"]
            record["source_file"] = retired["source_file"]
            retired["resulting_patterns"] = [record]

        self._expect_failure(artifact, add, resolver, case_steps)

    def test_unknown_atlas_id_rejected(self, artifact, resolver, case_steps):
        def swap(a):
            record = next(r for s in a["sources"] for r in s["resulting_patterns"])
            record["atlas_chain_mappings"][0]["id"] = "AML.T9999"

        self._expect_failure(artifact, swap, resolver, case_steps)

    def test_blank_identity_rationale_rejected(self, artifact, resolver, case_steps):
        def blank(a):
            record = next(r for s in a["sources"] for r in s["resulting_patterns"])
            record["atlas_chain_mappings"][0]["operational_identity_rationale"] = ""

        self._expect_failure(artifact, blank, resolver, case_steps)

    def test_colliding_resulting_id_rejected(self, artifact, resolver, case_steps):
        def collide(a):
            entry = next(
                s
                for s in a["sources"]
                if s["disposition"] == "split" and s["source_pattern_id"] == "AP-T3-04"
            )
            entry["resulting_patterns"][1]["pattern_id"] = "AP-T1-01"

        self._expect_failure(artifact, collide, resolver, case_steps)

    def test_pin_mismatch_rejected(self, artifact, resolver, case_steps):
        self._expect_failure(
            artifact,
            lambda a: a["taxonomy_context"]["atlas"].__setitem__("digest", "0" * 64),
            resolver,
            case_steps,
        )

    def test_stale_digest_rejected(self, artifact, resolver, case_steps):
        mutant = _mutate(
            artifact, lambda a: a["sources"][0].__setitem__("rationale", "tampered")
        )
        with pytest.raises(ValueError, match="digest mismatch"):
            validate_catalog_lineage(mutant, resolver=resolver, case_steps=case_steps)

    def test_unresolved_overlap_member_rejected(self, artifact, resolver, case_steps):
        def drop(a):
            group = next(g for g in a["overlap_groups"] if g["group_id"] == "OG-02")
            group["members"] = [m for m in group["members"] if m != "AP-T12-03"]

        self._expect_failure(artifact, drop, resolver, case_steps)

    def test_incoherent_source_facts_rejected(self, artifact, resolver, case_steps):
        def incoherent(a):
            entry = next(
                s for s in a["sources"] if s["evidence_tier"] == "kill_chain_only"
            )
            entry["legacy_kill_chain_steps"] = 0

        self._expect_failure(artifact, incoherent, resolver, case_steps)


class TestSourceSnapshot:
    """The artifact durably pins the historical source-catalog snapshot.

    ``source_catalog_context`` commits the exact canonicalized loader
    records at ``source_git_revision`` (six-file manifest, record count,
    content digest).  Normal validation deliberately does not recompute it
    — the live catalog migrates in later authoring waves — so the
    recompute-and-compare audit is the explicit
    ``verify_catalog_lineage_source_snapshot``, exercised here against
    immutable synthetic fixtures standing in for the historical records.
    Same-count content edits, which every id/count check would wave
    through, must fail.  The pin covers canonicalized loader-record
    content, not source YAML bytes.
    """

    _SYNTHETIC_PATTERNS: ClassVar[dict[str, dict]] = {
        "AP-T1-01": {
            "threat_id": "T1",
            "description": "synthetic alpha",
            "evidence": [{"type": "enrichment", "source": "AML.CS0001"}],
            "kill_chain": [
                {
                    "step": "craft",
                    "tactic": "AML.TA0003",
                    "techniques": ["AML.T0065"],
                    "abstract_action": "craft the lure",
                },
                {
                    "step": "deliver",
                    "tactic": "AML.TA0004",
                    "techniques": [],
                    "abstract_action": "deliver it",
                },
            ],
        },
        "AP-T2-01": {
            "threat_id": "T2",
            "description": "synthetic beta",
            "kill_chain": [
                {
                    "step": "probe",
                    "tactic": "AML.TA0001",
                    "techniques": ["AML.T0000"],
                    "abstract_action": "probe the model",
                }
            ],
        },
        "AP-T2-02": {
            "threat_id": "T2",
            "description": "synthetic gamma",
            "evidence": [
                {"type": "direct_demonstration", "source": "AML.CS0002"},
                {"type": "enrichment", "source": "AML.CS0003"},
            ],
        },
        "AP-T2-03": {"threat_id": "T2", "description": "synthetic delta"},
    }
    _SYNTHETIC_OWNERS: ClassVar[dict[str, str]] = {
        "AP-T1-01": "attack-patterns.yaml",
        "AP-T2-01": "attack-patterns-halluc-intent.yaml",
        "AP-T2-02": "attack-patterns-halluc-intent.yaml",
        "AP-T2-03": "attack-patterns-memory-tool.yaml",
    }

    @staticmethod
    def _synthetic_artifact(patterns, owners):
        """A sources/pin fragment computed from the synthetic records the
        same way the production artifact was computed from the historical
        catalog."""
        manifest = sorted(set(owners.values()))
        sources = []
        for pid in sorted(patterns):
            record = patterns[pid]
            evidence = record.get("evidence") or []
            kill_chain = record.get("kill_chain") or []
            tier = (
                "direct_demonstration"
                if any(e.get("type") == "direct_demonstration" for e in evidence)
                else "enrichment"
                if evidence
                else "kill_chain_only"
                if kill_chain
                else "none"
            )
            sources.append(
                {
                    "source_pattern_id": pid,
                    "source_file": owners[pid],
                    "threat_id": record["threat_id"],
                    "evidence_tier": tier,
                    "evidence_count": len(evidence),
                    "legacy_kill_chain_steps": len(kill_chain),
                }
            )
        return {
            "source_catalog_context": {
                "source_git_revision": "0" * 40,
                "canonicalization": SOURCE_CATALOG_CANONICALIZATION,
                "file_manifest": manifest,
                "record_count": len(patterns),
                "digest": compute_source_catalog_digest(patterns, owners, manifest),
            },
            "sources": sources,
        }

    @classmethod
    def _verify(cls, artifact, patterns, owners):
        # schema={} scopes the check to the verifier semantics under test;
        # the synthetic artifact is a sources/pin fragment, not a full
        # schema-complete artifact.
        return verify_catalog_lineage_source_snapshot(
            artifact, patterns=patterns, owners=owners, schema={}
        )

    @classmethod
    def _fresh(cls):
        patterns = copy.deepcopy(cls._SYNTHETIC_PATTERNS)
        owners = dict(cls._SYNTHETIC_OWNERS)
        return cls._synthetic_artifact(patterns, owners), patterns, owners

    def test_pinned_baseline_identity_is_golden(self, artifact):
        pin = artifact["source_catalog_context"]
        assert pin["source_git_revision"] == GOLDEN_SOURCE_REVISION
        assert pin["canonicalization"] == SOURCE_CATALOG_CANONICALIZATION
        assert pin["record_count"] == 71 == len(artifact["sources"])
        assert pin["file_manifest"] == [
            "attack-patterns-agentic-only.yaml",
            "attack-patterns-atlas-derived.yaml",
            "attack-patterns-comms-human-supply.yaml",
            "attack-patterns-halluc-intent.yaml",
            "attack-patterns-memory-tool.yaml",
            "attack-patterns.yaml",
        ]
        assert pin["digest"] == GOLDEN_SOURCE_DIGEST != "0" * 64

    def test_verifier_accepts_matching_snapshot(self):
        synthetic, patterns, owners = self._fresh()
        assert self._verify(synthetic, patterns, owners) is synthetic

    def test_verifier_rejects_supplied_catalog_divergence(self):
        synthetic, patterns, owners = self._fresh()
        del patterns["AP-T2-03"]
        with pytest.raises(ValueError, match="does not match|diverge"):
            self._verify(synthetic, patterns, owners)

    def _expect_source_mutation_rejected(self, mutate):
        synthetic, patterns, owners = self._fresh()
        mutate(patterns)
        with pytest.raises(ValueError, match="source catalog digest mismatch"):
            self._verify(synthetic, patterns, owners)

    def test_same_count_description_edit_rejected(self):
        def mutate(p):
            p["AP-T1-01"]["description"] += "tampered"

        self._expect_source_mutation_rejected(mutate)

    def test_same_count_evidence_source_edit_rejected(self):
        def mutate(p):
            p["AP-T1-01"]["evidence"][0]["source"] = "AML.CS0041"

        self._expect_source_mutation_rejected(mutate)

    def test_same_count_kill_chain_action_edit_rejected(self):
        def mutate(p):
            p["AP-T1-01"]["kill_chain"][0]["abstract_action"] = "tampered action"

        self._expect_source_mutation_rejected(mutate)

    def test_same_count_kill_chain_techniques_edit_rejected(self):
        def mutate(p):
            p["AP-T1-01"]["kill_chain"][0]["techniques"] = ["AML.T9999"]

        self._expect_source_mutation_rejected(mutate)

    def test_verifier_rejects_source_fact_drift(self):
        synthetic, patterns, owners = self._fresh()
        for mutate in (
            lambda a: a["sources"][0].__setitem__("evidence_count", 99),
            lambda a: a["sources"][0].__setitem__("legacy_kill_chain_steps", 99),
            lambda a: a["sources"][0].__setitem__("evidence_tier", "none"),
            lambda a: a["sources"][0].__setitem__("threat_id", "T99"),
            lambda a: a["sources"][0].__setitem__(
                "source_file", "attack-patterns-atlas-derived.yaml"
            ),
        ):
            mutant = _mutate(synthetic, mutate)
            with pytest.raises(ValueError, match="does not match"):
                self._verify(mutant, patterns, owners)

    def test_verifier_rejects_pin_tamper(self):
        synthetic, patterns, owners = self._fresh()
        for mutate, match in (
            (
                lambda a: a["source_catalog_context"].__setitem__("digest", "0" * 64),
                "digest mismatch",
            ),
            (
                lambda a: a["source_catalog_context"].__setitem__("record_count", 2),
                "record_count",
            ),
            (
                lambda a: a["source_catalog_context"]["file_manifest"].__setitem__(
                    0, "attack-patterns.yaml"
                ),
                "manifest",
            ),
        ):
            mutant = _mutate(synthetic, mutate)
            with pytest.raises(ValueError, match=match):
                self._verify(mutant, patterns, owners)

    def test_pin_is_deterministic_and_order_framed(self):
        _, patterns, owners = self._fresh()
        manifest = sorted(set(owners.values()))
        digest = compute_source_catalog_digest(patterns, owners, manifest)
        # Reordering the manifest frames changes the digest (file order is
        # pinned by the artifact's sorted manifest).
        assert (
            compute_source_catalog_digest(patterns, owners, list(reversed(manifest)))
            != digest
        )
        # Recomputing from the same inputs is stable.
        assert compute_source_catalog_digest(patterns, owners, manifest) == digest

    def test_normal_validation_does_not_recompute_the_source_pin(
        self, artifact, resolver, case_steps
    ):
        """The durable gate takes no catalog argument at all, so future
        catalog migrations cannot break it: a source-pin digest edit (with
        a consistent release digest) passes validation.  Recompute-and-
        compare lives only in the explicit snapshot verifier above, and
        the golden digest/revision assertions pin the real values."""
        mutant = _mutate(
            artifact,
            lambda a: a["source_catalog_context"].__setitem__("digest", "0" * 64),
        )
        mutant["release"]["semantic_digest"] = compute_catalog_lineage_digest(mutant)
        assert (
            validate_catalog_lineage(mutant, resolver=resolver, case_steps=case_steps)
            is mutant
        )


class TestCaseStepCitationGate:
    """Unhedged ``AML.CSxxxx Snn`` citations in mapping evidence must match
    the pinned ATLAS relationship (case/step existence plus employed
    technique); deliberate divergences must be marked analogue/adapted/
    retag."""

    def _expect_citation_failure(self, artifact, fn, resolver, case_steps, match):
        mutant = _mutate(artifact, fn)
        mutant["release"]["semantic_digest"] = compute_catalog_lineage_digest(mutant)
        with pytest.raises(ValueError, match=match):
            validate_catalog_lineage(mutant, resolver=resolver, case_steps=case_steps)

    @staticmethod
    def _t3_04_step_mapping(a):
        entry = next(s for s in a["sources"] if s["source_pattern_id"] == "AP-T3-04")
        record = next(
            r for r in entry["resulting_patterns"] if r["pattern_id"] == "AP-T3-04"
        )
        return record["atlas_step_mappings"][0]

    def test_production_citations_all_pass(self, artifact):
        # The artifact fixture already ran the gate; assert the convention
        # markers exist where divergences are deliberate.
        marked = 0
        for entry in artifact["sources"]:
            for record in entry["resulting_patterns"]:
                for mapping in (
                    record["atlas_chain_mappings"] + record["atlas_step_mappings"]
                ):
                    if any(
                        token in mapping["evidence"].lower()
                        for token in ("analogue", "adapted", "retag")
                    ):
                        marked += 1
        assert marked > 0

    def test_unhedged_wrong_step_rejected(self, artifact, resolver, case_steps):
        def mutate(a):
            # AP-T3-04 chain mapping AML.T0049 is exact at CS0048 S01; citing
            # S00 (which pins AML.T0000) unhedged must fail.
            entry = next(
                s for s in a["sources"] if s["source_pattern_id"] == "AP-T3-04"
            )
            record = next(
                r for r in entry["resulting_patterns"] if r["pattern_id"] == "AP-T3-04"
            )
            record["atlas_chain_mappings"][0]["evidence"] = (
                "AML.CS0048 S00; pinned technique definition AML.T0049."
            )

        self._expect_citation_failure(
            artifact,
            mutate,
            resolver,
            case_steps,
            "unhedged citation",
        )

    def test_stripping_hedge_from_retag_rejected(self, artifact, resolver, case_steps):
        def mutate(a):
            # The production AP-T3-04 reconnaissance mapping is a marked
            # retag (CS0048 S00 pins AML.T0000); stripping the marker makes
            # it an unhedged false assignment.
            mapping = self._t3_04_step_mapping(a)
            assert mapping["id"] == "AML.T0006"
            mapping["evidence"] = (
                "AML.CS0048 S00; pinned technique definition AML.T0006."
            )

        self._expect_citation_failure(
            artifact,
            mutate,
            resolver,
            case_steps,
            "unhedged citation",
        )

    def test_unknown_case_rejected(self, artifact, resolver, case_steps):
        def mutate(a):
            mapping = self._t3_04_step_mapping(a)
            mapping["evidence"] = (
                "AML.CS9999 S00; pinned technique definition AML.T0006."
            )

        self._expect_citation_failure(
            artifact,
            mutate,
            resolver,
            case_steps,
            "absent from the pinned ATLAS relationships",
        )

    def test_unknown_step_rejected(self, artifact, resolver, case_steps):
        def mutate(a):
            mapping = self._t3_04_step_mapping(a)
            mapping["evidence"] = (
                "AML.CS0048 S99; pinned technique definition AML.T0006."
            )

        self._expect_citation_failure(
            artifact,
            mutate,
            resolver,
            case_steps,
            "absent from",
        )


class TestArtifactFile:
    def test_artifact_is_the_only_added_taxonomy_file(self):
        """The lineage artifact must sit beside the unchanged attack-pattern
        YAML/SSSOM files; the artifact's source-catalog pin covers the
        canonicalized loader records at the pinned source git revision, not
        source YAML bytes."""
        names = {p.name for p in AP_DIR.glob("*.yaml")} | {
            p.name for p in AP_DIR.glob("*.sssom.tsv")
        }
        assert names == {
            "attack-patterns.yaml",
            "attack-patterns-agentic-only.yaml",
            "attack-patterns-atlas-derived.yaml",
            "attack-patterns-comms-human-supply.yaml",
            "attack-patterns-halluc-intent.yaml",
            "attack-patterns-memory-tool.yaml",
            "attack-patterns.sssom.tsv",
            "attack-patterns-agentic-only.sssom.tsv",
            "attack-patterns-atlas-derived.sssom.tsv",
            "attack-patterns-comms-human-supply.sssom.tsv",
            "attack-patterns-halluc-intent.sssom.tsv",
            "attack-patterns-memory-tool.sssom.tsv",
            "catalog-lineage.yaml",
        }

    def test_artifact_round_trips_through_yaml(self):
        raw = yaml.safe_load(_DEFAULT_LINEAGE_PATH.read_text())
        assert compute_catalog_lineage_digest(raw) == raw["release"]["semantic_digest"]


class TestLineageValidatorHelpers:
    """Direct branch coverage for the decomposed lineage gate helpers."""

    def test_taxonomy_pins_valid(self, artifact, resolver):
        from asago_scenario_generator.data.catalog_lineage import (
            _taxonomy_pins_valid,
        )

        assert _taxonomy_pins_valid(artifact, resolver) is None
        laaf_artifact = _mutate(
            artifact,
            lambda a: a["taxonomy_context"].__setitem__("laaf", {"release": "x"}),
        )
        with pytest.raises(ValueError, match="laaf must be null"):
            _taxonomy_pins_valid(laaf_artifact, resolver)

    def test_taxonomy_pin_mismatch(self, artifact, resolver):
        from asago_scenario_generator.data.catalog_lineage import (
            _taxonomy_pin_mismatch,
        )

        expected = resolver.taxonomy_context
        assert _taxonomy_pin_mismatch(artifact["taxonomy_context"], expected) is False
        mutated = _mutate(
            artifact,
            lambda a: a["taxonomy_context"]["atlas"].__setitem__("release", "x"),
        )
        assert _taxonomy_pin_mismatch(mutated["taxonomy_context"], expected) is True
        mutated = _mutate(
            artifact,
            lambda a: a["taxonomy_context"]["atlas"].__setitem__("digest", "x"),
        )
        assert _taxonomy_pin_mismatch(mutated["taxonomy_context"], expected) is True
        mutated = _mutate(
            artifact,
            lambda a: a["taxonomy_context"].__setitem__("mapping_set_digest", "x"),
        )
        assert _taxonomy_pin_mismatch(mutated["taxonomy_context"], expected) is True
        assert (
            _taxonomy_pin_mismatch(
                artifact["taxonomy_context"],
                type(expected)(
                    atlas=expected.atlas,
                    laaf=expected.atlas,
                    mapping_set_digest=expected.mapping_set_digest,
                ),
            )
            is True
        )

    def test_source_catalog_pin_valid(self, artifact):
        from asago_scenario_generator.data.catalog_lineage import (
            _source_catalog_pin_valid,
        )

        pin = artifact["source_catalog_context"]
        sources = artifact["sources"]
        assert _source_catalog_pin_valid(pin, sources) is None
        with pytest.raises(ValueError, match="canonicalization"):
            _source_catalog_pin_valid(dict(pin, canonicalization="other"), sources)
        with pytest.raises(ValueError, match="record_count"):
            _source_catalog_pin_valid(dict(pin, record_count=1), sources)
        with pytest.raises(ValueError, match="not sorted"):
            _source_catalog_pin_valid(
                dict(pin, file_manifest=list(reversed(pin["file_manifest"]))),
                sources,
            )
        undeclared = copy.deepcopy(sources)
        undeclared[0]["source_file"] = "missing.yaml"
        with pytest.raises(ValueError, match="not in the source catalog manifest"):
            _source_catalog_pin_valid(pin, undeclared)

    def test_disposition_vocabulary_valid(self, artifact):
        from asago_scenario_generator.data.catalog_lineage import (
            _disposition_vocabulary_valid,
        )

        assert _disposition_vocabulary_valid(artifact) is None
        mutant = _mutate(
            artifact,
            lambda a: a["disposition_vocabulary"].__setitem__("bogus", "x"),
        )
        with pytest.raises(ValueError, match="closed vocabulary"):
            _disposition_vocabulary_valid(mutant)

    def test_source_ids_unique(self, artifact):
        from asago_scenario_generator.data.catalog_lineage import (
            _source_ids_unique,
        )

        assert len(_source_ids_unique(artifact["sources"])) == 71
        duplicated = artifact["sources"] + [artifact["sources"][0]]
        with pytest.raises(ValueError, match="duplicate source_pattern_id"):
            _source_ids_unique(duplicated)

    def test_overlap_groups_valid(self, artifact):
        from asago_scenario_generator.data.catalog_lineage import (
            _overlap_groups_valid,
        )

        by_id = {entry["source_pattern_id"]: entry for entry in artifact["sources"]}
        groups = artifact["overlap_groups"]
        assert _overlap_groups_valid(groups, artifact["sources"], by_id) is None
        duplicated = copy.deepcopy(groups) + [copy.deepcopy(groups[0])]
        with pytest.raises(ValueError, match="duplicate overlap group_id"):
            _overlap_groups_valid(duplicated, artifact["sources"], by_id)
        unknown_member = copy.deepcopy(groups)
        unknown_member[0]["members"] = ["AP-T99-99"]
        with pytest.raises(ValueError, match="is not a source"):
            _overlap_groups_valid(unknown_member, artifact["sources"], by_id)
        double_member = copy.deepcopy(groups)
        double_member[1]["members"].append(double_member[0]["members"][0])
        with pytest.raises(ValueError, match="more than one group"):
            _overlap_groups_valid(double_member, artifact["sources"], by_id)

    def test_overlap_entry_references(self, artifact):
        from asago_scenario_generator.data.catalog_lineage import (
            _overlap_entry_references,
        )

        group_ids = {g["group_id"] for g in artifact["overlap_groups"]}
        member_to_group = {
            member: g["group_id"]
            for g in artifact["overlap_groups"]
            for member in g["members"]
        }
        assert (
            _overlap_entry_references(
                artifact["sources"][0], group_ids, member_to_group
            )
            is None
        )
        # A source that references no group but is listed as a member.
        listed = next(
            entry
            for entry in artifact["sources"]
            if entry["source_pattern_id"] in member_to_group
        )
        unlisted = copy.deepcopy(listed)
        unlisted["overlap_group"] = None
        with pytest.raises(ValueError, match="references no group"):
            _overlap_entry_references(unlisted, group_ids, member_to_group)
        unknown = copy.deepcopy(artifact["sources"][0])
        unknown["overlap_group"] = "OG-99"
        with pytest.raises(ValueError, match="unknown overlap group"):
            _overlap_entry_references(unknown, group_ids, member_to_group)
        mismatched = copy.deepcopy(listed)
        other_group = next(g for g in group_ids if g != listed["overlap_group"])
        mismatched["overlap_group"] = other_group
        with pytest.raises(ValueError, match="not listed as a member"):
            _overlap_entry_references(mismatched, group_ids, member_to_group)

    def test_disposition_violation(self, artifact):
        from asago_scenario_generator.data.catalog_lineage import (
            _disposition_violation,
        )

        retired = {
            "source_pattern_id": "AP-T0-00",
            "disposition": "retire",
            "resulting_patterns": [],
        }
        assert _disposition_violation(retired) is None
        with_results = dict(retired, resulting_patterns=[{"pattern_id": "AP-T0-01"}])
        with pytest.raises(ValueError, match="carries resulting patterns"):
            _disposition_violation(with_results)
        retained = {
            "source_pattern_id": "AP-T0-00",
            "disposition": "retain",
            "resulting_patterns": [{"pattern_id": "AP-T0-00"}],
        }
        assert _disposition_violation(retained) == retained["resulting_patterns"]
        wrong_id = {
            "source_pattern_id": "AP-T0-00",
            "disposition": "retain",
            "resulting_patterns": [{"pattern_id": "AP-T0-01"}],
        }
        with pytest.raises(ValueError, match="must continue its source id"):
            _disposition_violation(wrong_id)
        supersede = {
            "source_pattern_id": "AP-T0-00",
            "disposition": "supersede",
            "resulting_patterns": [{"pattern_id": "AP-T1-99"}],
        }
        assert _disposition_violation(supersede) == supersede["resulting_patterns"]

    def test_proposed_atlas_ids_valid(self, artifact, resolver):
        from asago_scenario_generator.data.catalog_lineage import (
            _proposed_atlas_ids_valid,
        )

        record = {
            "atlas_chain_mappings": [{"id": "AML.T0049"}],
            "atlas_step_mappings": [],
        }
        assert _proposed_atlas_ids_valid(resolver, "AP-T0-00", record) is None
        unknown = {
            "atlas_chain_mappings": [{"id": "AML.T9999"}],
            "atlas_step_mappings": [],
        }
        with pytest.raises(ValueError, match="unknown ATLAS id"):
            _proposed_atlas_ids_valid(resolver, "AP-T0-00", unknown)

    def test_resulting_record_valid(self, artifact, resolver, case_steps):
        from asago_scenario_generator.data.catalog_lineage import (
            _resulting_record_valid,
        )

        entry = artifact["sources"][0]
        pid = entry["source_pattern_id"]
        record = {
            "pattern_id": pid,
            "source_file": entry["source_file"],
            "atlas_chain_mappings": [],
            "atlas_step_mappings": [],
        }
        errors: list[str] = []
        _resulting_record_valid(
            pid, entry, pid, record, {pid}, resolver, case_steps, errors
        )
        assert errors == []
        colliding = dict(record, pattern_id="AP-T1-02")
        with pytest.raises(ValueError, match="collides with an existing catalog id"):
            _resulting_record_valid(
                pid,
                entry,
                "AP-T1-02",
                colliding,
                {"AP-T1-02"},
                resolver,
                case_steps,
                errors,
            )
        bad_file = dict(record, source_file="unknown.yaml")
        with pytest.raises(ValueError, match="unknown source_file"):
            _resulting_record_valid(
                pid, entry, pid, bad_file, {pid}, resolver, case_steps, errors
            )
        other_file = dict(record, source_file="attack-patterns-agentic-only.yaml")
        with pytest.raises(ValueError, match="owned by"):
            _resulting_record_valid(
                pid, entry, pid, other_file, {pid}, resolver, case_steps, errors
            )
        # Citation accumulation across both mapping kinds.
        cited = dict(
            record,
            atlas_chain_mappings=[
                {"id": "AML.T0049", "evidence": "AML.CS0048 S01; AML.CS0048 S99"}
            ],
            atlas_step_mappings=[{"id": "AML.T0001", "evidence": "AML.CS0001 S99"}],
        )
        errors = []
        _resulting_record_valid(
            pid, entry, pid, cited, {pid}, resolver, case_steps, errors
        )
        assert len(errors) == 2
        assert all("absent from" in error for error in errors)

    def test_split_naming_valid(self, artifact, resolver, case_steps):
        from asago_scenario_generator.data.catalog_lineage import (
            _split_naming_valid,
        )

        catalog_ids = {entry["source_pattern_id"] for entry in artifact["sources"]}
        assert _split_naming_valid(artifact["sources"], catalog_ids) is None
        split_source = next(
            entry for entry in artifact["sources"] if entry["disposition"] == "split"
        )
        wrong_first = copy.deepcopy(split_source)
        wrong_first["resulting_patterns"][0]["pattern_id"] = "AP-T9-99"
        with pytest.raises(ValueError, match="must continue the source id"):
            _split_naming_valid([wrong_first], catalog_ids)
        wrong_derived = copy.deepcopy(split_source)
        if len(wrong_derived["resulting_patterns"]) > 1:
            wrong_derived["resulting_patterns"][1]["pattern_id"] = "AP-T9-99"
            with pytest.raises(ValueError, match="lowest unused family id"):
                _split_naming_valid([wrong_derived], catalog_ids)

    def test_lowest_unused_family_id(self):
        from asago_scenario_generator.data.catalog_lineage import (
            _lowest_unused_family_id,
        )

        assert _lowest_unused_family_id("9", set()) == ("AP-T9-01", 1)
        assert _lowest_unused_family_id("9", {1, 2}) == ("AP-T9-03", 3)
        assert _lowest_unused_family_id("9", {1, 3}) == ("AP-T9-02", 2)

    def test_release_digest_valid(self, artifact):
        from asago_scenario_generator.data.catalog_lineage import (
            _release_digest_valid,
        )

        assert _release_digest_valid(artifact) is None
        mutant = _mutate(
            artifact,
            lambda a: a["release"].__setitem__("semantic_digest", "0" * 64),
        )
        with pytest.raises(ValueError, match="digest mismatch"):
            _release_digest_valid(mutant)

    def test_citation_errors_for_match(self, case_steps):
        from asago_scenario_generator.data.catalog_lineage import (
            _CASE_STEP_RE,
            _citation_errors_for_match,
        )

        match = next(_CASE_STEP_RE.finditer("AML.CS0048 S01"))
        assert (
            _citation_errors_for_match(
                "AP-T3-04", "AML.T0049", match, case_steps, False
            )
            == []
        )
        assert (
            _citation_errors_for_match("AP-T3-04", "AML.T0049", match, case_steps, True)
            == []
        )
        missing_case = next(_CASE_STEP_RE.finditer("AML.CS9999 S01"))
        errors = _citation_errors_for_match("R", "M", missing_case, case_steps, False)
        assert "absent from the pinned ATLAS relationships" in errors[0]
        unparseable = next(_CASE_STEP_RE.finditer("AML.CS0048 S01-S05-S09"))
        errors = _citation_errors_for_match("R", "M", unparseable, case_steps, False)
        assert "unparseable case-step range" in errors[0]
        unknown_step = next(_CASE_STEP_RE.finditer("AML.CS0048 S99"))
        errors = _citation_errors_for_match("R", "M", unknown_step, case_steps, False)
        assert "absent from" in errors[0]
        wrong_technique = next(_CASE_STEP_RE.finditer("AML.CS0048 S00"))
        errors = _citation_errors_for_match(
            "R", "M", wrong_technique, case_steps, False
        )
        assert "unhedged citation" in errors[0]
        # Hedged citations skip the assignment check.
        assert (
            _citation_errors_for_match("R", "M", wrong_technique, case_steps, True)
            == []
        )

    def test_normalize_record_branches(self):
        from datetime import date

        from asago_scenario_generator.data.catalog_lineage import (
            _normalize_record,
        )

        assert _normalize_record({"b": "caf\u00e9", "a": [1, None, True]}) == {
            "b": "caf\u00e9",
            "a": [1, None, True],
        }
        assert _normalize_record("caf\u00e9") == "caf\u00e9"
        assert _normalize_record(3.5) == 3.5
        assert _normalize_record(None) is None
        assert _normalize_record(date(2026, 1, 1)) == "2026-01-01"
        assert _normalize_record({1: "x"}) == {"1": "x"}

    def test_compute_catalog_lineage_digest_raises(self):
        from asago_scenario_generator.data.catalog_lineage import (
            compute_catalog_lineage_digest,
        )

        with pytest.raises(TypeError, match="must be a mapping"):
            compute_catalog_lineage_digest([])
        with pytest.raises(ValueError, match="lacks release.semantic_digest"):
            compute_catalog_lineage_digest({"release": {"version": "1"}})

    def test_lineage_schema_branches(self):
        from asago_scenario_generator.data.catalog_lineage import (
            _lineage_schema,
            load_catalog_lineage_schema,
        )

        assert _lineage_schema({"custom": True}) == {"custom": True}
        assert "properties" in _lineage_schema(None)
        assert _lineage_schema(None) == load_catalog_lineage_schema()

    def test_resulting_ids_unique_branches(self):
        from asago_scenario_generator.data.catalog_lineage import (
            _resulting_ids_unique,
        )

        assert _resulting_ids_unique(["AP-T1-01", "AP-T1-02"]) is None
        with pytest.raises(ValueError, match="duplicate resulting pattern id"):
            _resulting_ids_unique(["AP-T1-01", "AP-T1-01"])

    def test_citation_errors_block_branches(self):
        from asago_scenario_generator.data.catalog_lineage import (
            _citation_errors_block,
        )

        assert _citation_errors_block([]) is None
        with pytest.raises(ValueError, match="citation inconsistencies"):
            _citation_errors_block(["R mapping M: problem"])

    def test_compute_source_catalog_digest_raises(self):
        from asago_scenario_generator.data.catalog_lineage import (
            compute_source_catalog_digest,
        )

        patterns = {"AP-T1-01": {"threat_id": "T1"}}
        owners = {"AP-T1-01": "attack-patterns.yaml"}
        manifest = ["attack-patterns.yaml"]
        assert compute_source_catalog_digest(patterns, owners, manifest) != ""
        with pytest.raises(ValueError, match="without a declaring file"):
            compute_source_catalog_digest(
                {"AP-T1-01": {}, "AP-T9-99": {}}, owners, manifest
            )
        with pytest.raises(ValueError, match="outside the manifest"):
            compute_source_catalog_digest(
                patterns, {"AP-T1-01": "outside.yaml"}, manifest
            )

    def test_step_employments(self):
        from asago_scenario_generator.data.catalog_lineage import (
            _step_employments,
        )

        bundle = {
            "employs": [
                {"step-id": "S01", "target": "AML.T0001"},
                {"step-id": "S01", "target": "AML.T0002"},
                {"step-id": None, "target": "AML.T0003"},
            ]
        }
        assert _step_employments(bundle) == {"S01": {"AML.T0001", "AML.T0002"}}
        assert _step_employments(None) == {}
        assert _step_employments({"employs": []}) == {}

    def test_load_atlas_case_step_index_filters_non_cases(self, tmp_path):
        from asago_scenario_generator.data.catalog_lineage import (
            load_atlas_case_step_index,
        )

        source = tmp_path / "atlas.yaml"
        source.write_text(
            yaml.safe_dump(
                {
                    "relationships": {
                        "AML.CS0001": {
                            "employs": [{"step-id": "S01", "target": "AML.T0001"}]
                        },
                        "AML.TA0001": {
                            "employs": [{"step-id": "S01", "target": "AML.T0001"}]
                        },
                        "CS0002": {
                            "employs": [{"step-id": "S01", "target": "AML.T0001"}]
                        },
                        "AML.CS0002": {"employs": []},
                    }
                }
            )
        )
        assert load_atlas_case_step_index(source) == {
            "AML.CS0001": {"S01": frozenset({"AML.T0001"})}
        }

    def test_verify_pinned_manifest(self, artifact):
        from asago_scenario_generator.data.catalog_lineage import (
            _verify_pinned_manifest,
        )

        pin = artifact["source_catalog_context"]
        patterns = {"AP-T1-01": {"threat_id": "T1"}}
        owners = {"AP-T1-01": "attack-patterns.yaml"}
        with pytest.raises(
            ValueError, match="does not match the supplied declaring files"
        ):
            _verify_pinned_manifest(
                dict(pin, file_manifest=["other.yaml"], record_count=1),
                patterns,
                owners,
            )
        with pytest.raises(ValueError, match="record_count"):
            _verify_pinned_manifest(
                dict(pin, file_manifest=["attack-patterns.yaml"], record_count=99),
                patterns,
                owners,
            )
        assert (
            _verify_pinned_manifest(
                dict(pin, file_manifest=["attack-patterns.yaml"], record_count=1),
                patterns,
                owners,
            )
            is None
        )

    def test_verify_source_ids_match(self):
        from asago_scenario_generator.data.catalog_lineage import (
            _verify_source_ids_match,
        )

        sources = [{"source_pattern_id": "AP-T1-01"}, {"source_pattern_id": "AP-T1-02"}]
        patterns = {"AP-T1-01": {}, "AP-T1-02": {}}
        assert _verify_source_ids_match(sources, patterns) is None
        with pytest.raises(ValueError, match="duplicate source_pattern_id"):
            _verify_source_ids_match(sources + sources[:1], patterns)
        with pytest.raises(ValueError, match="diverge from the supplied catalog"):
            _verify_source_ids_match(sources, {"AP-T1-01": {}})

    def test_verify_entry_facts_match(self):
        from asago_scenario_generator.data.catalog_lineage import (
            _verify_entry_facts_match,
        )

        entry = {
            "source_pattern_id": "AP-T1-01",
            "source_file": "attack-patterns.yaml",
            "threat_id": "T1",
            "evidence_tier": "enrichment",
            "evidence_count": 1,
            "legacy_kill_chain_steps": 0,
        }
        pattern = {
            "threat_id": "T1",
            "evidence": [{"type": "enrichment"}],
            "kill_chain": [],
        }
        owners = {"AP-T1-01": "attack-patterns.yaml"}
        assert _verify_entry_facts_match(entry, "AP-T1-01", pattern, owners) is None
        drift = dict(entry, evidence_count=2)
        with pytest.raises(ValueError, match="evidence_count"):
            _verify_entry_facts_match(drift, "AP-T1-01", pattern, owners)
        drift = dict(entry, source_file="other.yaml")
        with pytest.raises(ValueError, match="does not match the declaring file"):
            _verify_entry_facts_match(drift, "AP-T1-01", pattern, owners)

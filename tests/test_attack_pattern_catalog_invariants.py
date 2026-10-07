"""Invariants shared by every canonical attack-pattern catalog.

Each ``tests/fixtures/attack_pattern_expectations/<catalog>.yaml`` pins one
catalog under ``data/taxonomies/attack-patterns/``: the live record set,
opt-in checks for conventions only some catalogs follow, and per-record pins
(step sequences, exact ATLAS mappings, resource slots, causal edges, tiers,
digests, observation-kind counts). The tests below run the same checks over
every catalog that has an expectation file. Record-specific semantics live in
``test_attack_pattern_record_semantics.py``.
"""

from __future__ import annotations

import re
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    EvaluatedFactEvidence,
    evaluate_condition,
    validate_attack_pattern,
)

CATALOG_DIR = DATA_ROOT / "taxonomies" / "attack-patterns"
EXPECTATION_DIR = (
    Path(__file__).resolve().parent / "fixtures" / "attack_pattern_expectations"
)
EXPECTATION_FILES = sorted(EXPECTATION_DIR.glob("*.yaml"))

# Catalog files that carry no expectation file, with the reason.
UNCOVERED = {
    "attack-patterns.yaml": "historical T7 file with zero live records",
    "attack-patterns-conversational.yaml": "pinned by test_conversational_patterns.py",
}

OPT_IN_CHECKS = frozenset(
    {
        "no_yaml_aliases",
        "single_root",
        "final_step_only_effects",
        "observed_cites_case_study",
        "has_unmapped_decisions",
        "no_preconditions",
        "unmapped_cites_lineage",
        "design_records_exist_in_staging",
        "technique_references_resolve",
        "tier_confidence_bands",
        "lineage_design_reference",
        "description_evidence",
    }
)

LEGACY_KEYS = frozenset({"kill_chain", "evidence"})
ACTION_KINDS = frozenset(
    {"prepare", "deliver", "invoke", "transform", "persist", "observe", "impact"}
)
PROVENANCE_TIERS = frozenset({"observed", "variant", "inferred", "designed"})
TIER_CONFIDENCE_BANDS = {
    "observed": (85, 100),
    "variant": (60, 85),
    "inferred": (0, 60),
}
CASE_STUDY_STEP = re.compile(r"\bS\d{2}\b")
TECHNIQUE_REFERENCE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class Catalog:
    """One catalog's expectations, raw records and qualified patterns."""

    name: str
    expected: dict[str, Any]
    document: dict[str, Any]
    records: dict[str, dict[str, Any]]
    patterns: dict[str, AttackPattern]

    @property
    def path(self) -> Path:
        return CATALOG_DIR / self.name

    @property
    def record_pins(self) -> dict[str, dict[str, Any]]:
        return self.expected["records"]

    def enabled(self, check: str) -> bool:
        return check in self.expected["checks"]

    def chains(self):
        for pid, pattern in self.patterns.items():
            yield pid, pattern.canonical_chain

    def steps(self):
        for pid, chain in self.chains():
            for step in chain.steps:
                yield pid, chain, step

    def pinned(self, key: str):
        """Yield (pid, chain, pin) for every record that pins ``key``."""
        for pid, chain in self.chains():
            if key in self.record_pins[pid]:
                yield pid, chain, self.record_pins[pid][key]


def _read_expectations(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def over_catalogs(selected=lambda expected: True):
    """Run a test once per catalog whose expectations satisfy ``selected``."""
    paths = [p for p in EXPECTATION_FILES if selected(_read_expectations(p))]
    return pytest.mark.parametrize(
        "catalog", [pytest.param(p, id=p.stem) for p in paths], indirect=True
    )


def opted_in(check: str):
    return lambda expected: check in expected["checks"]


def pins_any(*keys: str):
    return lambda expected: any(
        key in pins for pins in expected["records"].values() for key in keys
    )


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def merged_catalog() -> dict[str, dict]:
    return load_attack_patterns()


@pytest.fixture(scope="module")
def catalog(request, resolver) -> Catalog:
    expected = _read_expectations(request.param)
    document = yaml.safe_load(
        (CATALOG_DIR / expected["catalog"]).read_text(encoding="utf-8")
    )
    records = document["patterns"]
    patterns = {
        pid: validate_attack_pattern(record, resolver)
        for pid, record in records.items()
    }
    return Catalog(expected["catalog"], expected, document, records, patterns)


def _exact_ids(mappings) -> set[str]:
    return {ident for m in mappings if m.decision == "exact" for ident in m.ids}


def _mapping_scopes(chain):
    return [chain.mappings, *(step.mappings for step in chain.steps)]


def _terminal_postconditions(step) -> list:
    return [
        pc
        for pc in step.observable_postconditions
        if pc.security_relevant and pc.terminal
    ]


def _refs(refs) -> set[tuple[str, str]]:
    return {(ref.kind, ref.ref_id) for ref in refs}


def _reachable(start: int, edges: dict[int, set[int]]) -> set[int]:
    seen: set[int] = set()
    stack = [start]
    while stack:
        node = stack.pop()
        if node not in seen:
            seen.add(node)
            stack.extend(edges[node] - seen)
    return seen


# ---------------------------------------------------------------------------
# Catalog set
# ---------------------------------------------------------------------------


def test_every_catalog_file_has_expectations_or_a_reason() -> None:
    covered = {
        yaml.safe_load(path.read_text(encoding="utf-8"))["catalog"]
        for path in EXPECTATION_FILES
    }
    on_disk = {path.name for path in CATALOG_DIR.glob("attack-patterns*.yaml")}
    assert on_disk == covered | set(UNCOVERED)
    assert covered.isdisjoint(UNCOVERED)


@over_catalogs()
def test_expectation_checks_are_known(catalog: Catalog) -> None:
    assert set(catalog.expected["checks"]) <= OPT_IN_CHECKS
    assert set(catalog.record_pins) == set(catalog.expected["ids"])


# ---------------------------------------------------------------------------
# Record set and legacy removal
# ---------------------------------------------------------------------------


@over_catalogs()
def test_resulting_id_set_is_exact(catalog: Catalog) -> None:
    expected = catalog.expected["ids"]
    if catalog.expected.get("ordered"):
        assert list(catalog.records) == expected
    else:
        assert sorted(catalog.records) == sorted(expected)


@over_catalogs()
def test_deferred_and_retired_ids_are_not_live(
    catalog: Catalog, merged_catalog
) -> None:
    for pid in catalog.expected.get("absent_ids", ()):
        assert pid not in catalog.records
        assert pid not in merged_catalog


@over_catalogs()
def test_merged_catalog_carries_the_records(catalog: Catalog, merged_catalog) -> None:
    for pid, record in catalog.records.items():
        assert merged_catalog[pid] == record


@over_catalogs()
def test_records_are_canonical_not_legacy(catalog: Catalog) -> None:
    schema = Draft202012Validator(AttackPattern.model_json_schema())
    for pid, record in catalog.records.items():
        assert record["id"] == pid
        assert not LEGACY_KEYS & set(record), pid
        chain = record["canonical_chain"]
        assert chain["schema_version"] == "v1", pid
        assert chain["pattern_id"] == pid
        assert record["threat_id"] == pid.split("-")[1], pid
        assert schema.is_valid(record), pid


@over_catalogs(opted_in("no_yaml_aliases"))
def test_yaml_has_no_aliases(catalog: Catalog) -> None:
    """Anchors and aliases would couple records silently under hand edits."""
    events = yaml.parse(catalog.path.read_text(encoding="utf-8"))
    assert not any(isinstance(event, yaml.AliasEvent) for event in events)


@over_catalogs()
def test_sssom_rows_stay_relatedmatch_candidates(catalog: Catalog) -> None:
    """SSSOM provenance confers no mapping authority."""
    sssom = catalog.path.with_suffix(".sssom.tsv")
    lines = [
        line
        for line in sssom.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    column = lines[0].split("\t").index("predicate_id")
    assert {line.split("\t")[column] for line in lines[1:]} == {"skos:relatedMatch"}


@over_catalogs(lambda e: "header" in e)
def test_header_metadata_is_canonical(catalog: Catalog) -> None:
    header = catalog.expected.get("header")
    source = catalog.document["source"]
    assert source["lineage"] == header["lineage"]
    assert header["derived_from_contains"] in source["derived_from"]


# ---------------------------------------------------------------------------
# Qualification, digests and taxonomy pins
# ---------------------------------------------------------------------------


@over_catalogs()
def test_every_record_qualifies_and_round_trips(catalog: Catalog) -> None:
    assert set(catalog.patterns) == set(catalog.expected["ids"])
    for pid, pattern in catalog.patterns.items():
        again = AttackPattern.model_validate(pattern.model_dump(mode="json"))
        assert again == pattern, pid


@over_catalogs(pins_any("digest"))
def test_semantic_digests_match_pins(catalog: Catalog) -> None:
    pins = [(pid, pin) for pid, _, pin in catalog.pinned("digest")]
    for pid, pin in pins:
        assert catalog.records[pid]["canonical_chain"]["semantic_digest"] == pin, pid


@over_catalogs()
def test_taxonomy_context_matches_production_pins(catalog: Catalog, resolver) -> None:
    for pid, chain in catalog.chains():
        assert chain.taxonomy_context == resolver.taxonomy_context, pid
        assert chain.taxonomy_context.laaf is None, pid
        for scope in _mapping_scopes(chain):
            assert all(m.taxonomy == "ATLAS" for m in scope), pid


@over_catalogs()
def test_exact_mapping_ids_are_resolver_members(catalog: Catalog, resolver) -> None:
    for pid, chain in catalog.chains():
        for scope in _mapping_scopes(chain):
            for ident in _exact_ids(scope):
                assert resolver.contains("ATLAS", ident), (pid, ident)


@over_catalogs()
def test_technique_references_resolve(catalog: Catalog, resolver) -> None:
    checked = 0
    for pid, _, step in catalog.steps():
        for reference in step.provenance.references:
            if TECHNIQUE_REFERENCE.match(reference.reference_id):
                assert resolver.contains("ATLAS", reference.reference_id), (
                    pid,
                    reference.reference_id,
                )
                checked += 1
    if catalog.enabled("technique_references_resolve"):
        assert checked > 0


# ---------------------------------------------------------------------------
# Chain shape
# ---------------------------------------------------------------------------


@over_catalogs()
def test_chains_are_branch_free_total_orders(catalog: Catalog) -> None:
    for pid, chain in catalog.chains():
        steps = chain.steps
        assert [s.order for s in steps] == list(range(1, len(steps) + 1)), pid
        assert len({s.step_id for s in steps}) == len(steps), pid
        for step in steps:
            where = (pid, step.step_id)
            assert step.requirement == "required", where
            assert step.condition is None, where
            if catalog.enabled("no_preconditions"):
                assert step.preconditions == (), where


@over_catalogs()
def test_attacker_starts_and_one_terminal_ends_the_chain(catalog: Catalog) -> None:
    for pid, chain in catalog.chains():
        first, last = chain.steps[0], chain.steps[-1]
        assert first.attacker_controlled, pid
        assert chain.earliest_attacker_controlled_step_id == first.step_id, pid
        for step in chain.steps[:-1]:
            assert not any(pc.terminal for pc in step.observable_postconditions), (
                pid,
                step.step_id,
            )
        assert len(_terminal_postconditions(last)) == 1, pid
        assert [
            s.step_id
            for s in chain.steps
            if any(pc.terminal for pc in s.observable_postconditions)
        ] == [last.step_id], pid


@over_catalogs()
def test_steps_are_typed(catalog: Catalog) -> None:
    for pid, _, step in catalog.steps():
        where = (pid, step.step_id)
        assert step.action_kind in ACTION_KINDS, where
        assert step.observable_postconditions, where
        assert step.produced, where
        assert all(ref.kind in ("artifact", "state") for ref in step.consumed), where
        assert all(
            ref.kind in ("artifact", "state", "effect") for ref in step.produced
        ), where


@over_catalogs()
def test_role_decides_mapping_decisions(catalog: Catalog) -> None:
    for pid, chain in catalog.chains():
        for step in chain.steps:
            decisions = {m.decision for m in step.mappings}
            where = (pid, step.step_id)
            if step.attacker_controlled:
                assert step.executor_role == "attacker", where
                assert decisions <= {"exact", "unmapped"}, where
            else:
                assert step.executor_role in ("system", "operator"), where
                assert decisions <= {"not_applicable"}, where
        assert any(m.decision == "exact" for m in chain.mappings), pid


@over_catalogs()
def test_unmapped_decisions_carry_rationale(catalog: Catalog) -> None:
    found = False
    for pid, chain in catalog.chains():
        for scope in _mapping_scopes(chain):
            for mapping in scope:
                if mapping.decision == "unmapped":
                    found = True
                    assert mapping.rationale.strip(), pid
                    if catalog.enabled("unmapped_cites_lineage"):
                        assert "catalog-lineage" in mapping.rationale, pid
    if catalog.enabled("has_unmapped_decisions"):
        assert found


@over_catalogs()
def test_resource_slots_declare_one_ingress(catalog: Catalog) -> None:
    for pid, chain in catalog.chains():
        ingress = [s for s in chain.resource_slots if s.purpose == "initial_ingress"]
        assert len(ingress) == 1, pid
        assert ingress[0].slot_id == chain.initial_ingress_slot_id == "ingress", pid
        assert ingress[0].kind == "entry_point", pid
        assert any(
            s.purpose in {"target", "supporting"} for s in chain.resource_slots
        ), pid


# ---------------------------------------------------------------------------
# Causal graph
# ---------------------------------------------------------------------------


@over_catalogs()
def test_consumed_references_are_produced_earlier(catalog: Catalog) -> None:
    for pid, chain in catalog.chains():
        produced: dict[tuple[str, str], str] = {}
        for step in chain.steps:
            for ref in step.consumed:
                key = (ref.kind, ref.ref_id)
                where = (pid, step.step_id, key)
                assert key in produced, where
                assert produced[key] == ref.value_type, where
            for ref in step.produced:
                key = (ref.kind, ref.ref_id)
                assert key not in produced, (pid, step.step_id, key)
                produced[key] = ref.value_type


@over_catalogs()
def test_causal_graph_is_reachable_without_dead_ends(catalog: Catalog) -> None:
    for pid, chain in catalog.chains():
        steps = chain.steps
        producer = {
            (ref.kind, ref.ref_id): step.order
            for step in steps
            for ref in step.produced
        }
        forward: dict[int, set[int]] = {step.order: set() for step in steps}
        for step in steps:
            for ref in step.consumed:
                forward[producer[(ref.kind, ref.ref_id)]].add(step.order)
        backward: dict[int, set[int]] = {order: set() for order in forward}
        for source, targets in forward.items():
            for target in targets:
                backward[target].add(source)
        everything = set(forward)
        if catalog.enabled("single_root"):
            assert _reachable(1, forward) == everything, (
                f"{pid}: unreachable from step 1"
            )
        assert _reachable(steps[-1].order, backward) == everything, (
            f"{pid}: terminal does not reach every step backward"
        )
        consumed = {(ref.kind, ref.ref_id) for s in steps for ref in s.consumed}
        for step in steps:
            for ref in step.produced:
                if ref.kind == "effect":
                    assert (ref.kind, ref.ref_id) not in consumed, (pid, ref.ref_id)
                elif step is not steps[-1]:
                    assert (ref.kind, ref.ref_id) in consumed, (pid, ref.ref_id)
        if catalog.enabled("final_step_only_effects"):
            assert all(ref.kind == "effect" for ref in steps[-1].produced), pid


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


@over_catalogs()
def test_provenance_is_tiered_cited_and_honest(catalog: Catalog) -> None:
    for pid, _, step in catalog.steps():
        provenance = step.provenance
        where = (pid, step.step_id)
        assert provenance.tier in PROVENANCE_TIERS, where
        assert 0 <= provenance.confidence <= 100, where
        assert provenance.references, where
        assert provenance.adaptation_rationale.strip(), where
        if catalog.enabled("observed_cites_case_study") and provenance.tier == (
            "observed"
        ):
            cited = [
                r
                for r in provenance.references
                if r.reference_type == "catalog" and r.reference_id.startswith("AML.CS")
            ]
            assert cited, where
            assert CASE_STUDY_STEP.search(provenance.adaptation_rationale), where
        if catalog.enabled("tier_confidence_bands"):
            low, high = TIER_CONFIDENCE_BANDS[provenance.tier]
            assert low <= provenance.confidence <= high, where
        if catalog.enabled("lineage_design_reference"):
            assert ("design_record", f"catalog-lineage:{pid}") in {
                (r.reference_type, r.reference_id) for r in provenance.references
            }, where


@over_catalogs(opted_in("design_records_exist_in_staging"))
def test_design_records_exist_in_staging(catalog: Catalog) -> None:
    for pid, _, step in catalog.steps():
        for reference in step.provenance.references:
            if reference.reference_type == "design_record":
                assert (CATALOG_DIR / "staging" / reference.reference_id).is_file(), (
                    pid,
                    reference.reference_id,
                )


# ---------------------------------------------------------------------------
# Per-record pins
# ---------------------------------------------------------------------------


@over_catalogs(pins_any("steps"))
def test_step_sequences_match_pins(catalog: Catalog) -> None:
    for pid, chain, steps in catalog.pinned("steps"):
        assert [s.step_id for s in chain.steps] == steps, pid


@over_catalogs(
    pins_any("chain_exact", "step_exact", "forbidden_exact", "step_exact_pins")
)
def test_exact_mappings_match_pins(catalog: Catalog) -> None:
    for pid, chain, pinned in catalog.pinned("chain_exact"):
        assert _exact_ids(chain.mappings) == set(pinned), pid
    for pid, chain, pinned in catalog.pinned("step_exact"):
        actual = {
            step.step_id: _exact_ids(step.mappings)
            for step in chain.steps
            if _exact_ids(step.mappings)
        }
        assert actual == {step: set(ids) for step, ids in pinned.items()}, pid
    for pid, chain, pinned in catalog.pinned("forbidden_exact"):
        everything = set().union(
            *(_exact_ids(scope) for scope in _mapping_scopes(chain))
        )
        assert everything.isdisjoint(pinned), pid
    for pid, chain, pinned in catalog.pinned("step_exact_pins"):
        by_id = {s.step_id: s for s in chain.steps}
        for step_id, ids in pinned.items():
            (decision,) = by_id[step_id].mappings
            assert decision.decision == "exact", (pid, step_id)
            assert list(decision.ids) == ids, (pid, step_id)


@over_catalogs(pins_any("slots"))
def test_resource_slots_match_pins(catalog: Catalog) -> None:
    for pid, chain, slots in catalog.pinned("slots"):
        actual = [(s.slot_id, s.kind, s.purpose) for s in chain.resource_slots]
        assert sorted(actual) == sorted(tuple(slot) for slot in slots), pid


@over_catalogs(pins_any("edges"))
def test_causal_edges_match_pins(catalog: Catalog) -> None:
    for pid, chain, edges in catalog.pinned("edges"):
        assert {s.step_id for s in chain.steps} == set(edges), pid
        for step in chain.steps:
            pin = edges[step.step_id]
            consumed = {tuple(ref) for ref in pin["consumed"]}
            produced = {tuple(ref) for ref in pin["produced"]}
            assert _refs(step.consumed) == consumed, f"{pid}:{step.step_id} consumed"
            assert _refs(step.produced) == produced, f"{pid}:{step.step_id} produced"


@over_catalogs(pins_any("terminal"))
def test_terminal_steps_match_pins(catalog: Catalog) -> None:
    for pid, chain, pin in catalog.pinned("terminal"):
        terminal = chain.steps[-1]
        assert terminal.step_id == pin["step"], pid
        if "tier" in pin:
            assert terminal.provenance.tier == pin["tier"], pid
        (postcondition,) = _terminal_postconditions(terminal)
        for keyword in pin.get("keywords", ()):
            assert keyword in postcondition.description.lower(), (pid, keyword)


@over_catalogs(pins_any("step_tiers"))
def test_step_tiers_match_pins(catalog: Catalog) -> None:
    for pid, chain, pinned in catalog.pinned("step_tiers"):
        by_id = {s.step_id: s for s in chain.steps}
        for step_id, pin in pinned.items():
            provenance = by_id[step_id].provenance
            assert provenance.tier == pin["tier"], (pid, step_id)
            if "confidence" in pin:
                assert provenance.confidence == pin["confidence"], (pid, step_id)


@over_catalogs(pins_any("preconditions"))
def test_split_preconditions_are_equality_true_on_runtime_facts(
    catalog: Catalog,
) -> None:
    for pid, chain, pinned in catalog.pinned("preconditions"):
        by_id = {s.step_id: s for s in chain.steps}
        for step_id, fact_id in pinned.items():
            (precondition,) = by_id[step_id].preconditions
            condition = precondition.condition
            assert condition.op == "equality", (pid, step_id)
            assert condition.value is True, (pid, step_id)
            assert condition.fact.namespace == "runtime_state", (pid, step_id)
            assert condition.fact.value_type == "boolean", (pid, step_id)
            assert condition.fact.fact_id == fact_id, (pid, step_id)
            # A present-but-false fact must fail; existence(true) could not
            # express that.
            for status, value, outcome in (
                ("present", True, "true"),
                ("present", False, "false"),
                ("absent", None, "false"),
                ("unknown", None, "unknown"),
            ):
                evidence = EvaluatedFactEvidence(
                    fact=condition.fact, status=status, value=value
                )
                assert evaluate_condition(condition, (evidence,)) == outcome, (
                    pid,
                    step_id,
                    status,
                    value,
                )


@over_catalogs(opted_in("description_evidence"))
def test_chain_exact_ids_carry_identity_and_evidence_in_the_description(
    catalog: Catalog,
) -> None:
    for pid, pattern in catalog.patterns.items():
        for ident in catalog.record_pins[pid]["chain_exact"]:
            assert ident in pattern.description, (pid, ident)
            window = pattern.description.split(ident, 1)[1]
            window = re.split(r"AML\.T\d{4}(?:\.\d{3})? —", window)[0]
            assert "exact" in window.lower(), (pid, ident)
            assert "AML.CS" in window, (pid, ident)
            assert "pinned technique definition" in window, (pid, ident)


@over_catalogs(lambda e: "observation_kind_counts" in e)
def test_observation_kind_counts_match_pins(catalog: Catalog) -> None:
    pinned = catalog.expected.get("observation_kind_counts")
    counts = Counter(
        link["observation"]
        for record in catalog.records.values()
        for step in record["canonical_chain"]["steps"]
        for link in step.get("observable_outcome_links", [])
    )
    assert dict(counts) == pinned


# ---------------------------------------------------------------------------
# Digest integrity (replaces per-catalog digest recomputation)
# ---------------------------------------------------------------------------


def test_validation_rejects_a_digest_that_does_not_match_the_chain(
    merged_catalog, resolver
) -> None:
    """``validate_attack_pattern`` is the digest check; no catalog recomputes it."""
    record = next(iter(merged_catalog.values()))
    stale = deepcopy(record)
    stale["canonical_chain"]["semantic_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="semantic_digest does not match"):
        validate_attack_pattern(stale, resolver)

    edited = deepcopy(record)
    edited["canonical_chain"]["steps"][0]["step_id"] += "_edited"
    with pytest.raises(ValidationError):
        validate_attack_pattern(edited, resolver)


def test_pinned_atlas_release(resolver) -> None:
    assert resolver.taxonomy_context.atlas.release == "2026.05"

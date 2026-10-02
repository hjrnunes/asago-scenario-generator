"""Dedicated acceptance tests for bead asago-scenario-generator-422o.2.8.

Covers the migration of
``data/taxonomies/attack-patterns/attack-patterns-comms-human-supply.yaml``
from the legacy kill-chain catalog to the authoritative canonical-chain
contract under the merged ``catalog-lineage.yaml`` dispositions:

- the live record set is exactly the authoritative resulting IDs
  (AP-T12-01, AP-T12-03, AP-T15-01, AP-T15-02, AP-T17-01); deferred
  (AP-T12-02/04/05) and retired (AP-T17-02) records are absent;
- every record parses and qualifies against the production pinned
  taxonomy resolver, and its embedded semantic digest recomputes from
  on-disk content;
- the AP-T12-03 trigger_false_incorporation -> AML.T0051.002 lineage
  entry is a false exact identity (retrieval of false data is not a
  triggered prompt injection), so no record carries AML.T0051.002 as an
  exact mapping; unmapped attacker steps carry a rationale that cites the
  catalog lineage (the tests do not read catalog-lineage.yaml);
- every chain is one pure branch-free total-order chain (all steps
  required, no conditions or preconditions) with supported explicit
  consumed/produced links;
- provenance references are honest: pinned ATLAS case-study step
  citations resolve, technique references are resolver members, and
  staging design-record references exist;
- legacy transport (``kill_chain``, ``evidence``) is removed and the
  records no longer parse as legacy records.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
import yaml

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    ExactMapping,
    NotApplicableMapping,
    UnmappedMapping,
    compute_chain_semantic_digest,
    validate_attack_pattern,
)

OWNER_FILE = "attack-patterns-comms-human-supply.yaml"
PATTERNS_DIR = DATA_ROOT / "taxonomies" / "attack-patterns"
OWNER_PATH = PATTERNS_DIR / OWNER_FILE
STAGING_DIR = PATTERNS_DIR / "staging"

EXPECTED_LIVE_IDS = ["AP-T12-01", "AP-T12-03", "AP-T15-01", "AP-T15-02", "AP-T17-01"]
REMOVED_IDS = ["AP-T12-02", "AP-T12-04", "AP-T12-05", "AP-T17-02"]

_TECHNIQUE_REF_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    return yaml.safe_load(OWNER_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def records(document) -> dict[str, Any]:
    return document["patterns"]


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def qualified(records, resolver) -> dict[str, AttackPattern]:
    return {
        pid: validate_attack_pattern(record, resolver)
        for pid, record in records.items()
    }


class TestResultingRecordSet:
    def test_live_ids_are_exactly_the_authoritative_resulting_ids(self, records):
        assert sorted(records) == EXPECTED_LIVE_IDS
        for pid in EXPECTED_LIVE_IDS:
            assert records[pid]["id"] == pid

    def test_deferred_and_retired_records_are_not_live(self, records):
        for pid in REMOVED_IDS:
            assert pid not in records

    def test_merged_catalog_load_includes_the_migrated_records(self):
        merged = load_attack_patterns()
        for pid in EXPECTED_LIVE_IDS:
            assert pid in merged


class TestQualificationAndPins:
    def test_every_record_qualifies_against_the_production_resolver(self, qualified):
        assert sorted(qualified) == EXPECTED_LIVE_IDS

    def test_embedded_taxonomy_context_matches_production_pins(
        self, qualified, resolver
    ):
        for pattern in qualified.values():
            assert pattern.canonical_chain.taxonomy_context == resolver.taxonomy_context
            assert pattern.canonical_chain.taxonomy_context.laaf is None

    def test_semantic_digests_recompute_from_disk(self, records):
        for pid, record in records.items():
            chain = record["canonical_chain"]
            assert compute_chain_semantic_digest(chain) == chain["semantic_digest"], pid

    def test_json_round_trip_stability(self, qualified):
        for pattern in qualified.values():
            assert (
                AttackPattern.model_validate(pattern.model_dump(mode="json")) == pattern
            )

    def test_no_laaf_decisions_anywhere(self, qualified):
        for pattern in qualified.values():
            chain = pattern.canonical_chain
            scopes = [chain.mappings, *(step.mappings for step in chain.steps)]
            for scope in scopes:
                for mapping in scope:
                    assert mapping.taxonomy == "ATLAS"


class TestLineageMappingFidelity:
    def test_unmapped_attacker_steps_carry_rationale(self, qualified):
        for pattern in qualified.values():
            for step in pattern.canonical_chain.steps:
                for mapping in step.mappings:
                    if isinstance(mapping, UnmappedMapping):
                        assert mapping.rationale.strip()
                        assert "catalog-lineage" in mapping.rationale


class TestChainStructure:
    def test_pure_branch_free_total_order(self, qualified):
        for pid, pattern in qualified.items():
            steps = pattern.canonical_chain.steps
            assert [s.order for s in steps] == list(range(1, len(steps) + 1)), pid
            for step in steps:
                assert step.requirement == "required", (pid, step.step_id)
                assert step.condition is None, (pid, step.step_id)
                assert step.preconditions == (), (pid, step.step_id)

    def test_attacker_start_and_terminal_outcome_placement(self, qualified):
        for pid, pattern in qualified.items():
            chain = pattern.canonical_chain
            assert chain.steps[0].attacker_controlled, pid
            assert chain.earliest_attacker_controlled_step_id == chain.steps[0].step_id
            for step in chain.steps[:-1]:
                assert not any(
                    o.security_relevant and o.terminal
                    for o in step.observable_postconditions
                ), (pid, step.step_id)
            assert any(
                o.security_relevant and o.terminal
                for o in chain.steps[-1].observable_postconditions
            ), pid

    def test_role_mapping_partition(self, qualified):
        for pid, pattern in qualified.items():
            attacker_exact = 0
            for step in pattern.canonical_chain.steps:
                if step.attacker_controlled:
                    assert step.executor_role == "attacker"
                    assert not any(
                        isinstance(m, NotApplicableMapping) for m in step.mappings
                    )
                    attacker_exact += sum(
                        isinstance(m, ExactMapping) for m in step.mappings
                    )
                else:
                    assert step.executor_role in {"system", "operator"}
                    assert all(
                        isinstance(m, NotApplicableMapping) for m in step.mappings
                    )
            assert attacker_exact >= 1, pid

    def test_consumed_links_are_supported_by_earlier_production(self, qualified):
        for pid, pattern in qualified.items():
            produced_so_far: dict[tuple[str, str], str] = {}
            for step in pattern.canonical_chain.steps:
                for ref in step.consumed:
                    key = (ref.kind, ref.ref_id)
                    assert key in produced_so_far, (pid, step.step_id, key)
                    assert produced_so_far[key] == ref.value_type, (
                        pid,
                        step.step_id,
                        key,
                    )
                for ref in step.produced:
                    produced_so_far[(ref.kind, ref.ref_id)] = ref.value_type

    def test_every_step_produces_an_effect_or_state_and_observable(self, qualified):
        for pid, pattern in qualified.items():
            for step in pattern.canonical_chain.steps:
                assert len(step.produced) >= 1, (pid, step.step_id)
                assert len(step.observable_postconditions) >= 1, (pid, step.step_id)


class TestProvenanceHonesty:
    def test_technique_references_are_resolver_members(self, qualified, resolver):
        checked = 0
        for pid, pattern in qualified.items():
            for step in pattern.canonical_chain.steps:
                for reference in step.provenance.references:
                    if _TECHNIQUE_REF_RE.match(reference.reference_id):
                        assert resolver.contains("ATLAS", reference.reference_id), (
                            pid,
                            reference.reference_id,
                        )
                        checked += 1
        assert checked > 0

    def test_design_record_references_exist_in_staging(self, qualified):
        for pid, pattern in qualified.items():
            for step in pattern.canonical_chain.steps:
                for reference in step.provenance.references:
                    if reference.reference_type == "design_record":
                        assert (STAGING_DIR / reference.reference_id).is_file(), (
                            pid,
                            reference.reference_id,
                        )

    def test_provenance_tiers_and_confidence_bounds(self, qualified):
        for pattern in qualified.values():
            for step in pattern.canonical_chain.steps:
                provenance = step.provenance
                assert provenance.references
                assert 0 <= provenance.confidence <= 100
                assert provenance.adaptation_rationale.strip()

    def test_directionality_correction_and_persistence_are_recorded(self, qualified):
        # AP-T15-02: the CS0055 directionality correction must be retained in
        # provenance, and the human-directed line must be grounded in CS0020.
        t15_02_text = yaml.safe_dump(
            qualified["AP-T15-02"].model_dump(mode="json"), sort_keys=True
        )
        assert "directionality" in t15_02_text
        assert "AML.CS0020 S03" in t15_02_text
        assert "AML.T0052.000" in t15_02_text
        # AP-T17-01: the evidence-backed persistence step (CS0041 S04) survives.
        t17_01 = qualified["AP-T17-01"].canonical_chain
        persist = [s for s in t17_01.steps if s.action_kind == "persist"]
        assert [s.step_id for s in persist] == ["persist_via_adoption"]
        references = persist[0].provenance.references
        assert any(r.reference_id == "AML.CS0041 S04" for r in references)


class TestLegacyTransportRemoved:
    def test_no_kill_chain_or_evidence_keys(self, records):
        for pid, record in records.items():
            assert "kill_chain" not in record, pid
            assert "evidence" not in record, pid

def _steps(pattern: AttackPattern):
    return {step.step_id: step for step in pattern.canonical_chain.steps}


def _ordered_refs(pattern: AttackPattern) -> list[list[str]]:
    return [
        [r.reference_id for r in step.provenance.references]
        for step in pattern.canonical_chain.steps
    ]


class TestAPTT1502Directionality:
    """independent correction 1: no duplicate escalation; the user action consumes
    the deceptive output directly; CS0020 S02 -> S03 -> S04 is asserted; no
    CS0055 evidence occurs after preparation."""

    def test_escalation_step_removed_and_user_consumes_deceptive_output(
        self, qualified
    ):
        steps = _steps(qualified["AP-T15-02"])
        assert "escalate_to_active_instruction" not in steps
        assert [s.step_id for s in qualified["AP-T15-02"].canonical_chain.steps] == [
            "craft_hijack_injection",
            "stage_social_engineering_payload",
            "ingest_malicious_content",
            "generate_deceptive_messages",
            "user_executes_malicious_action",
        ]
        user_action = steps["user_executes_malicious_action"]
        assert [(r.kind, r.ref_id) for r in user_action.consumed] == [
            ("state", "state.deceptive_output")
        ]
        producer = steps["generate_deceptive_messages"]
        assert (producer.produced[0].kind, producer.produced[0].ref_id) == (
            "state",
            "state.deceptive_output",
        )

    def test_cs0020_s02_s03_s04_causal_sequence(self, qualified):
        refs = _ordered_refs(qualified["AP-T15-02"])
        positions = {}
        for order, step_refs in enumerate(refs, start=1):
            for ref in step_refs:
                positions.setdefault(ref, order)
        s02 = positions["AML.CS0020 S02"]
        s03 = positions["AML.CS0020 S03"]
        s04 = positions["AML.CS0020 S04"]
        assert s02 < s03 < s04
        steps = qualified["AP-T15-02"].canonical_chain.steps
        assert steps[s03 - 1].step_id == "generate_deceptive_messages"
        assert steps[s04 - 1].step_id == "user_executes_malicious_action"
        assert steps[s04 - 1].executor_role == "operator"

    def test_no_cs0055_evidence_after_preparation(self, qualified):
        for step in qualified["AP-T15-02"].canonical_chain.steps:
            refs = [r.reference_id for r in step.provenance.references]
            if step.action_kind == "prepare":
                continue  # CS0055 may remain only as adapted preparation precedent
            assert not any(ref.startswith("AML.CS0055") for ref in refs), (
                step.step_id,
                refs,
            )


class TestAPTT1203Corrections:
    """independent correction 2: false exact AML.T0051.002 removed from the
    false-data retrieval step (lineage amendment required and documented);
    AML.T0070 chain identity retained; propagation is the first peer
    re-emission and the terminal is the first multi-peer cascade."""

    def test_no_exact_t0051_002_anywhere(self, qualified):
        pattern = qualified["AP-T12-03"]
        chain_exact = [
            identifier
            for mapping in pattern.canonical_chain.mappings
            if isinstance(mapping, ExactMapping)
            for identifier in mapping.ids
        ]
        assert chain_exact == ["AML.T0070"]
        for step in pattern.canonical_chain.steps:
            for mapping in step.mappings:
                if isinstance(mapping, ExactMapping):
                    assert "AML.T0051.002" not in mapping.ids, step.step_id

    def test_first_reemission_then_first_multi_peer_cascade(self, qualified):
        steps = _steps(qualified["AP-T12-03"])
        propagation = steps["cascade_propagation"]
        assert [(r.kind, r.ref_id) for r in propagation.produced] == [
            ("state", "state.first_peer_reemission")
        ]
        propagation_text = " ".join(
            o.description for o in propagation.observable_postconditions
        )
        assert "first re-emission" in propagation_text
        assert not any(o.terminal for o in propagation.observable_postconditions)
        terminal = steps["misinformation_impact"]
        assert [(r.kind, r.ref_id) for r in terminal.consumed] == [
            ("state", "state.first_peer_reemission")
        ]
        terminal_text = " ".join(
            o.description for o in terminal.observable_postconditions
        )
        assert "first observable multi-peer cascade" in terminal_text
        assert any(o.terminal for o in terminal.observable_postconditions)
        assert (
            terminal.step_id == qualified["AP-T12-03"].canonical_chain.steps[-1].step_id
        )


class TestAPTT1701CausalArtifactPath:
    """independent correction 3: jailbreak produces the enabled malicious-generation
    state, concealment preserves it, and the terminal system step is the first
    emission of the backdoored artifact — with no adopter-use claim."""

    def test_enabled_state_produced_preserved_and_consumed(self, qualified):
        steps = _steps(qualified["AP-T17-01"])
        jailbreak = steps["jailbreak_guardrails"]
        assert [(r.kind, r.ref_id) for r in jailbreak.produced] == [
            ("state", "state.malicious_generation_enabled")
        ]
        conceal = steps["suppress_output_mentions"]
        assert [(r.kind, r.ref_id) for r in conceal.consumed] == [
            ("state", "state.malicious_generation_enabled")
        ]
        assert [(r.kind, r.ref_id) for r in conceal.produced] == [
            ("state", "state.concealed_malicious_generation")
        ]
        conceal_text = " ".join(
            o.description for o in conceal.observable_postconditions
        )
        assert "preserves the enabled malicious-generation state" in conceal_text
        terminal = steps["impact_backdoored_code"]
        assert [(r.kind, r.ref_id) for r in terminal.consumed] == [
            ("state", "state.concealed_malicious_generation")
        ]

    def test_terminal_is_first_backdoored_artifact_emission(self, qualified):
        chain = qualified["AP-T17-01"].canonical_chain
        terminal = chain.steps[-1]
        assert terminal.step_id == "impact_backdoored_code"
        assert terminal.executor_role == "system"
        assert [(r.kind, r.ref_id) for r in terminal.produced] == [
            ("effect", "effect.backdoored_artifacts")
        ]
        # No earlier step emits a backdoored artifact or effect.
        for step in chain.steps[:-1]:
            for ref in step.produced:
                assert "backdoor" not in ref.ref_id, (step.step_id, ref.ref_id)
                assert ref.kind != "effect", (step.step_id, ref.ref_id)
        # The adopter pipeline remains an explicit operator action/artifact
        # path, but the record claims no adopter use of generated artifacts.
        persist = _steps(qualified["AP-T17-01"])["persist_via_adoption"]
        assert persist.executor_role == "operator"
        assert persist.action_kind == "persist"
        dumped = yaml.safe_dump(
            qualified["AP-T17-01"].model_dump(mode="json"), sort_keys=True
        )
        assert "Adopters use" not in dumped
        terminal_text = " ".join(
            o.description for o in terminal.observable_postconditions
        )
        assert "first observable supply-chain impact" in terminal_text
        assert "not claimed" in terminal_text


class TestAPTT1501TerminalProvenance:
    """independent correction 4: CS0026 S13 is conditional ('If'/'could'), not an
    observed completed transfer; the terminal stays but with non-observed
    tier, lowered confidence, and explicit conditional evidence."""

    def test_terminal_tier_confidence_and_conditional_evidence(self, qualified):
        terminal = qualified["AP-T15-01"].canonical_chain.steps[-1]
        assert terminal.step_id == "impact"
        assert any(o.terminal for o in terminal.observable_postconditions)
        provenance = terminal.provenance
        assert provenance.tier in {"inferred", "variant"}
        assert provenance.tier != "observed"
        assert provenance.confidence <= 60
        assert any(r.reference_id == "AML.CS0026 S13" for r in provenance.references)
        rationale = provenance.adaptation_rationale
        assert "conditionally" in rationale
        assert "If the victim follows through" in rationale
        assert "could be" in rationale
        assert "not an observed event" in rationale

"""Focused unit tests for taxonomy obligation plan models and serialization."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.obligation_plan import (
    QualificationTraceItem,
    RejectedCandidateEvidence,
    TaxonomyObligation,
    TaxonomyObligationPlan,
)


def _make_plan(**overrides: Any) -> TaxonomyObligationPlan:
    defaults: dict[str, Any] = {
        "taxonomy_version": "atlas-2026.05",
        "mapping_version": "sssom-v1",
        "qualification_ruleset_version": "catalog-qualification-v1",
        "template_version": "scenario-envelope-v1",
        "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "obligations": [],
    }
    defaults.update(overrides)
    return TaxonomyObligationPlan(**defaults)


def test_obligation_plan_pinned_versions() -> None:
    plan = _make_plan(
        obligations=[
            TaxonomyObligation(
                obligation_id="ob:atlas-prompt-injection:AP-T6-01",
                risk_id="atlas-prompt-injection",
                pattern_id="AP-T6-01",
                scope="in-scope",
                terminal_disposition="generated",
            )
        ],
    )
    assert plan.taxonomy_version == "atlas-2026.05"
    assert plan.mapping_version == "sssom-v1"
    assert plan.qualification_ruleset_version == "catalog-qualification-v1"
    assert plan.template_version == "scenario-envelope-v1"
    assert (
        plan.digest
        == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    assert len(plan.obligations) == 1
    assert plan.obligations[0].obligation_id == "ob:atlas-prompt-injection:AP-T6-01"


def test_obligation_plan_yaml_round_trip() -> None:
    original = _make_plan(
        digest="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        obligations=[
            TaxonomyObligation(
                obligation_id="ob:atlas-prompt-injection:AP-T6-01",
                risk_id="atlas-prompt-injection",
                pattern_id="AP-T6-01",
                scope="in-scope",
                terminal_disposition="generated",
                qualification_trace=[
                    QualificationTraceItem(
                        predicate="deployment.attacker_code_execution",
                        facts="deployment.attacker_code_execution=false",
                        result="false",
                        reason="fact present and unequal",
                    )
                ],
                accepted_candidates=["cand:v2:11111111111111111111111111111111"],
                rejected_candidates=[
                    RejectedCandidateEvidence(
                        candidate_id="cand:v2:22222222222222222222222222222222",
                        reason="rule rejected combination",
                    )
                ],
            )
        ],
    )

    yaml_str = original.to_yaml()
    loaded = TaxonomyObligationPlan.from_yaml(yaml_str)

    assert loaded.taxonomy_version == original.taxonomy_version
    assert loaded.mapping_version == original.mapping_version
    assert (
        loaded.qualification_ruleset_version == original.qualification_ruleset_version
    )
    assert loaded.template_version == original.template_version
    assert loaded.digest == original.digest
    assert len(loaded.obligations) == len(original.obligations)
    assert loaded.obligations[0].obligation_id == original.obligations[0].obligation_id
    assert (
        loaded.obligations[0].qualification_trace
        == original.obligations[0].qualification_trace
    )
    assert (
        loaded.obligations[0].accepted_candidates
        == original.obligations[0].accepted_candidates
    )
    assert (
        loaded.obligations[0].rejected_candidates
        == original.obligations[0].rejected_candidates
    )


def test_obligation_plan_json_round_trip() -> None:
    original = _make_plan(
        obligations=[
            TaxonomyObligation(
                obligation_id="ob:atlas-orphan-risk",
                risk_id="atlas-orphan-risk",
                pattern_id=None,
                scope="in-scope",
                terminal_disposition="governance-only",
            )
        ],
    )

    json_str = original.to_json()
    loaded = TaxonomyObligationPlan.from_json(json_str)

    assert loaded.taxonomy_version == original.taxonomy_version
    assert loaded.obligations[0].obligation_id == "ob:atlas-orphan-risk"
    assert loaded.obligations[0].pattern_id is None
    assert loaded.obligations[0].terminal_disposition == "governance-only"


def test_obligation_plan_byte_stability() -> None:
    plan = _make_plan(
        obligations=[
            TaxonomyObligation(
                obligation_id="ob:atlas-prompt-injection:AP-T6-01",
                risk_id="atlas-prompt-injection",
                pattern_id="AP-T6-01",
                scope="in-scope",
                terminal_disposition="generated",
            ),
            TaxonomyObligation(
                obligation_id="ob:atlas-memory-poisoning:AP-T1-01",
                risk_id="atlas-memory-poisoning",
                pattern_id="AP-T1-01",
                scope="in-scope",
                terminal_disposition="missing-template",
            ),
        ],
    )

    yaml1 = plan.to_yaml()
    yaml2 = plan.to_yaml()
    assert yaml1 == yaml2

    json1 = plan.to_json()
    json2 = plan.to_json()
    assert json1 == json2

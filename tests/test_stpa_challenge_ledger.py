"""Public-seam tests for the offline Phase 3 STPA challenge ledger."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.models.challenge_ledger import (
    EXPLICIT_PRIORITY_POLICY_VERSION,
    ChallengeEligibility,
    ChallengeOutcome,
    OriginalStpaDecision,
    StpaChallengeLedger,
)
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    HybridCoverageAssessment,
    StructuralConsiderationRow,
    TaxonomyCorrespondenceRow,
    TraceReference,
    compute_matrix_row_id,
    derive_hybrid_coverage_diagnostics,
)
from asago_scenario_generator.pipeline.challenge_ledger import (
    build_stpa_challenge_ledger,
)
from asago_scenario_generator.pipeline.challenge_ledger_persistence import (
    STPA_CHALLENGE_LEDGER_FILENAME,
    read_stpa_challenge_ledger,
    write_stpa_challenge_ledger,
)


REPRESENTATIVE_ASSESSMENT = (
    Path(__file__).parent / "fixtures/hybrid-coverage-assessment.yaml"
)
REPRESENTATIVE_LEDGER = (
    Path(__file__).parent / "fixtures/stpa-obligation-challenge-ledger.yaml"
)


def _assessment() -> HybridCoverageAssessment:
    return HybridCoverageAssessment.from_yaml(REPRESENTATIVE_ASSESSMENT.read_bytes())


def _pin(artifact_id: str, schema_version: str, digest_char: str) -> ArtifactPin:
    return ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest=digest_char * 64,
    )


def _multi_assessment() -> HybridCoverageAssessment:
    capability = _pin("capability-fact-snapshot", "capability-fact-snapshot-v1", "1")
    obligation_plan = _pin(
        "taxonomy-obligation-plan", "taxonomy-obligation-plan-v1", "2"
    )
    enumeration = _pin("ica-enumeration", "ica-enumeration-v1", "3")
    pins = (capability, obligation_plan, enumeration)
    structural_specs = (
        ("RESP-1:CA-1:NOT_PROVIDED", "unresolved", ()),
        ("RESP-1:CA-1:INCORRECT", "ica", ("RESP-1:CA-1:INCORRECT:1",)),
        ("RESP-1:CA-1:WRONG_TIMING", "justified_na", ()),
    )
    structural = tuple(
        StructuralConsiderationRow(
            row_id=compute_matrix_row_id("struct", slot_id),
            slot_id=slot_id,
            controller_id="RESP-1",
            control_action_id="CA-1",
            uca_type=slot_id.rsplit(":", 1)[1],
            ica_ids=ica_ids,
            disposition=disposition,
            evidence=(f"stpa:{slot_id}",),
            source_pins=pins,
            trace_refs=(
                TraceReference(
                    **enumeration.model_dump(mode="json"),
                    record_id=slot_id,
                ),
            ),
        )
        for slot_id, disposition, ica_ids in structural_specs
    )
    taxonomy = tuple(
        TaxonomyCorrespondenceRow(
            row_id=compute_matrix_row_id("tax", obligation_id),
            obligation_id=obligation_id,
            risk_id=f"R-{index}",
            attack_pattern_id=f"AP-{index}",
            attack_pattern_semantic_digest=str(index) * 64,
            scope_disposition="applicable",
            qualification_disposition="ready",
            correspondence_disposition="unresolved_no_proposal",
            gap_reason="no_accepted_proposal",
            source_pins=pins,
            trace_refs=(
                TraceReference(
                    **obligation_plan.model_dump(mode="json"),
                    record_id=obligation_id,
                ),
            ),
        )
        for index, obligation_id in enumerate(
            ("ob:v1:" + "a" * 64, "ob:v1:" + "b" * 64, "ob:v1:" + "c" * 64),
            start=4,
        )
    )
    diagnostics = derive_hybrid_coverage_diagnostics(structural, taxonomy, (), (), ())
    return HybridCoverageAssessment(
        capability_snapshot_digest=capability.semantic_digest,
        source_pins=pins,
        structural_inventory_status="complete",
        structural_consideration=structural,
        taxonomy_correspondence=taxonomy,
        scenario_realization=(),
        diagnostics=diagnostics,
    )


def test_explicit_pair_is_selected_and_preserves_original_decision() -> None:
    """One approved obligation/slot pair retains the baseline STPA decision."""
    assessment = _assessment()
    obligation = assessment.taxonomy_correspondence[0]
    structural = assessment.structural_consideration[0]

    ledger = build_stpa_challenge_ledger(
        assessment,
        (
            ChallengeEligibility(
                obligation_id=obligation.obligation_id,
                slot_id=structural.slot_id,
                priority=10,
                rationale="An analyst approved a bounded reconsideration.",
                evidence_refs=("review:klarna:case-1",),
            ),
        ),
        challenge_budget=1,
        assessment_artifact_id="klarna-hybrid-coverage-assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )

    assert ledger.assessment_pin.semantic_digest == assessment.semantic_digest
    assert ledger.challenge_budget == 1
    assert ledger.network_calls == ledger.model_calls == 0
    assert len(ledger.records) == 1
    record = ledger.records[0]
    assert record.selection_status == "selected"
    assert record.obligation_id == obligation.obligation_id
    assert record.slot_id == structural.slot_id
    assert record.original_decision.row_id == structural.row_id
    assert record.original_decision.disposition == structural.disposition
    assert record.original_decision.ica_ids == structural.ica_ids
    assert record.original_decision.evidence == structural.evidence
    assert record.outcome is None


def test_priority_budget_and_reordering_are_deterministic() -> None:
    """Priority selects a bounded prefix and leaves every other pair traceable."""
    assessment = _multi_assessment()
    obligations = assessment.taxonomy_correspondence
    slots = assessment.structural_consideration
    eligibility = (
        ChallengeEligibility(
            obligation_id=obligations[0].obligation_id,
            slot_id=slots[0].slot_id,
            priority=30,
            rationale="third",
            evidence_refs=("review:third",),
        ),
        ChallengeEligibility(
            obligation_id=obligations[1].obligation_id,
            slot_id=slots[1].slot_id,
            priority=10,
            rationale="first",
            evidence_refs=("review:first",),
        ),
        ChallengeEligibility(
            obligation_id=obligations[2].obligation_id,
            slot_id=slots[2].slot_id,
            priority=20,
            rationale="second",
            evidence_refs=("review:second",),
        ),
    )

    first = build_stpa_challenge_ledger(
        assessment,
        eligibility,
        challenge_budget=2,
        assessment_artifact_id="multi-assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )
    reordered = build_stpa_challenge_ledger(
        assessment,
        tuple(reversed(eligibility)),
        challenge_budget=2,
        assessment_artifact_id="multi-assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )

    assert first == reordered
    assert first.diagnostics.model_dump() == {
        "eligible_targets": 3,
        "selected_targets": 2,
        "not_selected_budget": 1,
    }
    assert [record.selection_status for record in first.records] == [
        "selected",
        "selected",
        "not_selected_budget",
    ]
    assert [record.original_decision.disposition for record in first.records] == [
        "unresolved",
        "justified_na",
        "ica",
    ]


def test_unknown_duplicate_and_substituted_inputs_fail_closed() -> None:
    """Exact assessment, obligation, and slot identities are mandatory."""
    assessment = _multi_assessment()
    obligation = assessment.taxonomy_correspondence[0].obligation_id
    slot = assessment.structural_consideration[0].slot_id

    def eligibility(obligation_id: str = obligation, slot_id: str = slot):
        return ChallengeEligibility(
            obligation_id=obligation_id,
            slot_id=slot_id,
            priority=1,
            rationale="approved",
            evidence_refs=("review:1",),
        )

    kwargs = {
        "challenge_budget": 1,
        "assessment_artifact_id": "assessment",
        "selection_policy_version": EXPLICIT_PRIORITY_POLICY_VERSION,
    }
    with pytest.raises(ValueError, match="unknown obligation"):
        build_stpa_challenge_ledger(
            assessment, (eligibility("ob:v1:" + "f" * 64),), **kwargs
        )
    with pytest.raises(ValueError, match="unknown STPA slot"):
        build_stpa_challenge_ledger(
            assessment, (eligibility(slot_id="RESP-99:CA-99:INCORRECT"),), **kwargs
        )
    with pytest.raises(ValueError, match="duplicate obligation/STPA-slot"):
        build_stpa_challenge_ledger(
            assessment, (eligibility(), eligibility()), **kwargs
        )

    substituted = assessment.model_copy(update={"semantic_digest": "f" * 64})
    with pytest.raises(ValueError, match="digest mismatch"):
        build_stpa_challenge_ledger(substituted, (eligibility(),), **kwargs)


def test_closed_outcome_vocabulary_preserves_typed_evidence() -> None:
    """Later adapters can record only ICA, justified N/A, or unresolved."""
    ica = ChallengeOutcome(
        disposition="ica",
        ica_ids=("RESP-1:CA-1:INCORRECT:2",),
        rationale="A newly identified unsafe control action.",
        evidence_refs=("analysis:ica:2",),
    )
    justified_na = ChallengeOutcome(
        disposition="justified_na",
        rationale="The controller cannot issue the action in this context.",
        evidence_refs=("analysis:na:1",),
    )
    unresolved = ChallengeOutcome(
        disposition="unresolved",
        rationale="Available process evidence is insufficient.",
        evidence_refs=("analysis:unknown:1",),
    )

    assert {ica.disposition, justified_na.disposition, unresolved.disposition} == {
        "ica",
        "justified_na",
        "unresolved",
    }
    with pytest.raises(Exception):
        ChallengeOutcome.model_validate(
            {
                "disposition": "accepted",
                "rationale": "invalid",
                "evidence_refs": ["analysis:bad"],
            }
        )
    with pytest.raises(ValueError, match="ICA outcome requires"):
        ChallengeOutcome(
            disposition="ica",
            rationale="missing identity",
            evidence_refs=("analysis:bad",),
        )
    with pytest.raises(ValueError, match="only ICA outcomes"):
        ChallengeOutcome(
            disposition="unresolved",
            ica_ids=("RESP-1:CA-1:INCORRECT:2",),
            rationale="contradictory shape",
            evidence_refs=("analysis:bad",),
        )


def test_ledger_round_trip_and_forged_content_fail_closed(tmp_path: Path) -> None:
    """The canonical YAML is atomic, closed, and protected by its digest."""
    assessment = _multi_assessment()
    first_obligation = assessment.taxonomy_correspondence[0]
    first_slot = assessment.structural_consideration[0]
    ledger = build_stpa_challenge_ledger(
        assessment,
        (
            ChallengeEligibility(
                obligation_id=first_obligation.obligation_id,
                slot_id=first_slot.slot_id,
                priority=1,
                rationale="approved",
                evidence_refs=("review:1",),
            ),
        ),
        challenge_budget=1,
        assessment_artifact_id="assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )

    path = write_stpa_challenge_ledger(tmp_path, ledger)
    assert path.name == STPA_CHALLENGE_LEDGER_FILENAME
    assert read_stpa_challenge_ledger(path) == ledger
    assert StpaChallengeLedger.from_yaml(ledger.to_yaml()) == ledger

    tampered = yaml.safe_load(ledger.to_yaml())
    tampered["records"][0]["priority"] = 99
    with pytest.raises(ValueError, match="semantic_digest"):
        StpaChallengeLedger.from_yaml(yaml.safe_dump(tampered))

    missing_digest = yaml.safe_load(ledger.to_yaml())
    missing_digest.pop("semantic_digest")
    with pytest.raises(ValueError, match="semantic_digest is required"):
        StpaChallengeLedger.from_yaml(yaml.safe_dump(missing_digest))

    forged = ledger.model_dump(mode="json")
    forged["semantic_digest"] = None
    forged["records"][0]["selection_status"] = "not_selected_budget"
    with pytest.raises(ValueError, match="selection status"):
        StpaChallengeLedger.model_validate(forged)

    with pytest.raises(ValueError, match="expected"):
        read_stpa_challenge_ledger(tmp_path / "renamed.yaml")


def test_empty_eligibility_selects_nothing_and_never_infers_a_trigger() -> None:
    """Assessment gaps alone cannot silently become reconsideration targets."""
    assessment = _multi_assessment()

    ledger = build_stpa_challenge_ledger(
        assessment,
        (),
        challenge_budget=3,
        assessment_artifact_id="assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )

    assert ledger.records == ()
    assert ledger.diagnostics.model_dump() == {
        "eligible_targets": 0,
        "selected_targets": 0,
        "not_selected_budget": 0,
    }


def test_builder_rejects_hidden_or_malformed_policy_inputs() -> None:
    """Budget, policy, artifact, and typed eligibility are all explicit."""
    assessment = _multi_assessment()
    common = {
        "assessment": assessment,
        "eligibility": (),
        "challenge_budget": 0,
        "assessment_artifact_id": "assessment",
        "selection_policy_version": EXPLICIT_PRIORITY_POLICY_VERSION,
    }
    for field, value, message in (
        ("challenge_budget", -1, "non-negative"),
        ("challenge_budget", True, "integer"),
        ("assessment_artifact_id", "", "non-empty"),
        ("selection_policy_version", "latest", "unsupported"),
    ):
        changed = dict(common)
        changed[field] = value
        with pytest.raises((TypeError, ValueError), match=message):
            build_stpa_challenge_ledger(**changed)

    changed = dict(common)
    changed["eligibility"] = ({"obligation_id": "not-typed"},)
    with pytest.raises(TypeError, match="ChallengeEligibility"):
        build_stpa_challenge_ledger(**changed)


def test_zero_priority_is_a_valid_selection_boundary() -> None:
    """Priority zero is explicit and retained rather than coerced or rejected."""
    assessment = _multi_assessment()
    ledger = build_stpa_challenge_ledger(
        assessment,
        (
            ChallengeEligibility(
                obligation_id=assessment.taxonomy_correspondence[0].obligation_id,
                slot_id=assessment.structural_consideration[0].slot_id,
                priority=0,
                rationale="highest explicit priority",
                evidence_refs=("review:zero",),
            ),
        ),
        challenge_budget=1,
        assessment_artifact_id="assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )

    assert ledger.records[0].priority == 0


def test_model_rejects_forged_identity_diagnostics_pins_and_outcomes() -> None:
    """Direct model construction cannot bypass derived ledger invariants."""
    assessment = _multi_assessment()
    ledger = build_stpa_challenge_ledger(
        assessment,
        (
            ChallengeEligibility(
                obligation_id=assessment.taxonomy_correspondence[0].obligation_id,
                slot_id=assessment.structural_consideration[0].slot_id,
                priority=1,
                rationale="approved",
                evidence_refs=("review:1",),
            ),
        ),
        challenge_budget=0,
        assessment_artifact_id="assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )
    payload = ledger.model_dump(mode="json")

    wrong_id = yaml.safe_load(yaml.safe_dump(payload))
    wrong_id["semantic_digest"] = None
    wrong_id["records"][0]["challenge_id"] = "challenge:v1:" + "f" * 64
    with pytest.raises(ValueError, match="challenge identity"):
        StpaChallengeLedger.model_validate(wrong_id)

    wrong_counts = yaml.safe_load(yaml.safe_dump(payload))
    wrong_counts["semantic_digest"] = None
    wrong_counts["diagnostics"]["eligible_targets"] = 2
    with pytest.raises(ValueError, match="diagnostics"):
        StpaChallengeLedger.model_validate(wrong_counts)

    duplicate_pin = yaml.safe_load(yaml.safe_dump(payload))
    duplicate_pin["semantic_digest"] = None
    duplicate_pin["source_pins"].append(duplicate_pin["source_pins"][0])
    with pytest.raises(ValueError, match="unique artifact IDs"):
        StpaChallengeLedger.model_validate(duplicate_pin)

    impossible_outcome = yaml.safe_load(yaml.safe_dump(payload))
    impossible_outcome["semantic_digest"] = None
    impossible_outcome["records"][0]["outcome"] = {
        "disposition": "unresolved",
        "rationale": "not attempted",
        "evidence_refs": ["analysis:none"],
    }
    with pytest.raises(ValueError, match="budget-excluded"):
        StpaChallengeLedger.model_validate(impossible_outcome)

    wrong_original_row = yaml.safe_load(yaml.safe_dump(payload))
    wrong_original_row["semantic_digest"] = None
    wrong_original_row["records"][0]["original_decision"]["row_id"] = (
        "hca-struct:v1:" + "f" * 64
    )
    with pytest.raises(ValueError, match="original structural row identity"):
        StpaChallengeLedger.model_validate(wrong_original_row)

    dangling_trace = yaml.safe_load(yaml.safe_dump(payload))
    dangling_trace["semantic_digest"] = None
    dangling_trace["records"][0]["original_decision"]["trace_refs"][0][
        "semantic_digest"
    ] = "f" * 64
    with pytest.raises(ValueError, match="original-decision trace"):
        StpaChallengeLedger.model_validate(dangling_trace)

    missing_pins = yaml.safe_load(yaml.safe_dump(payload))
    missing_pins["semantic_digest"] = None
    missing_pins["source_pins"] = []
    with pytest.raises(Exception):
        StpaChallengeLedger.model_validate(missing_pins)


def test_json_and_unicode_forms_are_canonical() -> None:
    """Equivalent Unicode and input ordering produce one durable identity."""
    assessment = _multi_assessment()
    row = assessment.taxonomy_correspondence[0]
    slot = assessment.structural_consideration[0]
    composed = ChallengeEligibility(
        obligation_id=row.obligation_id,
        slot_id=slot.slot_id,
        priority=1,
        rationale="Caf\u00e9 review",
        evidence_refs=("review:z", "review:a"),
    )
    decomposed = ChallengeEligibility(
        obligation_id=row.obligation_id,
        slot_id=slot.slot_id,
        priority=1,
        rationale="Cafe\u0301 review",
        evidence_refs=("review:a", "review:z"),
    )

    first = build_stpa_challenge_ledger(
        assessment,
        (composed,),
        challenge_budget=1,
        assessment_artifact_id="assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )
    second = build_stpa_challenge_ledger(
        assessment,
        (decomposed,),
        challenge_budget=1,
        assessment_artifact_id="assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )

    assert first == second
    assert StpaChallengeLedger.from_json(first.to_json()) == first


def test_representative_challenge_ledger_remains_current() -> None:
    """The committed QA artifact is the exact output of the public builder."""
    assessment = _assessment()
    ledger = build_stpa_challenge_ledger(
        assessment,
        (
            ChallengeEligibility(
                obligation_id=assessment.taxonomy_correspondence[0].obligation_id,
                slot_id=assessment.structural_consideration[0].slot_id,
                priority=10,
                rationale="Approved representative Phase 3 challenge.",
                evidence_refs=("review:phase3:representative",),
            ),
        ),
        challenge_budget=1,
        assessment_artifact_id="representative-hybrid-coverage-assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )

    assert StpaChallengeLedger.from_yaml(REPRESENTATIVE_LEDGER.read_bytes()) == ledger
    assert REPRESENTATIVE_LEDGER.read_text(encoding="utf-8") == ledger.to_yaml()


def test_closed_model_field_boundaries_are_enforced() -> None:
    """Persisted identity, evidence, numeric, and immutability bounds are real."""
    assessment = _multi_assessment()
    obligation_id = assessment.taxonomy_correspondence[0].obligation_id
    slot_id = assessment.structural_consideration[0].slot_id
    valid = {
        "obligation_id": obligation_id,
        "slot_id": slot_id,
        "priority": 1,
        "rationale": "approved",
        "evidence_refs": ["review:1"],
    }
    eligibility = ChallengeEligibility.model_validate(valid)
    for field, value in (
        ("slot_id", ""),
        ("priority", -1),
        ("priority", False),
        ("rationale", ""),
        ("evidence_refs", []),
        ("evidence_refs", [""]),
        ("evidence_refs", ["review:1", "review:1"]),
    ):
        payload = dict(valid)
        payload[field] = value
        with pytest.raises(Exception):
            ChallengeEligibility.model_validate(payload)
    with pytest.raises(Exception):
        ChallengeEligibility.model_validate({**valid, "unexpected": True})
    with pytest.raises(Exception):
        eligibility.priority = 2


def test_original_decision_and_record_boundaries_are_enforced() -> None:
    """The baseline snapshot and later selected outcome cannot be weakened."""
    assessment = _multi_assessment()
    ledger = build_stpa_challenge_ledger(
        assessment,
        (
            ChallengeEligibility(
                obligation_id=assessment.taxonomy_correspondence[0].obligation_id,
                slot_id=assessment.structural_consideration[0].slot_id,
                priority=1,
                rationale="approved",
                evidence_refs=("review:1",),
            ),
        ),
        challenge_budget=1,
        assessment_artifact_id="assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )
    original = ledger.records[0].original_decision.model_dump(mode="json")
    for field in ("slot_id", "controller_id", "control_action_id"):
        payload = yaml.safe_load(yaml.safe_dump(original))
        payload[field] = ""
        with pytest.raises(Exception):
            OriginalStpaDecision.model_validate(payload)
    for field in ("evidence", "trace_refs"):
        payload = yaml.safe_load(yaml.safe_dump(original))
        payload[field] = []
        with pytest.raises(Exception):
            OriginalStpaDecision.model_validate(payload)

    wrong_row = yaml.safe_load(yaml.safe_dump(original))
    wrong_row["row_id"] = "hca-struct:v1:" + "f" * 64
    with pytest.raises(ValueError, match="original structural row identity"):
        OriginalStpaDecision.model_validate(wrong_row)
    empty_slot = yaml.safe_load(yaml.safe_dump(original))
    empty_slot["slot_id"] = ""
    empty_slot["row_id"] = compute_matrix_row_id("struct", "")
    with pytest.raises(Exception):
        OriginalStpaDecision.model_validate(empty_slot)
    duplicate_trace = yaml.safe_load(yaml.safe_dump(original))
    duplicate_trace["trace_refs"].append(duplicate_trace["trace_refs"][0])
    with pytest.raises(ValueError, match="traces must be unique"):
        OriginalStpaDecision.model_validate(duplicate_trace)
    missing_ica = yaml.safe_load(yaml.safe_dump(original))
    missing_ica["ica_ids"] = []
    with pytest.raises(ValueError, match="contradicts ICA"):
        OriginalStpaDecision.model_validate(missing_ica)

    selected_with_outcome = ledger.model_dump(mode="json")
    selected_with_outcome["semantic_digest"] = None
    selected_with_outcome["records"][0]["outcome"] = {
        "disposition": "unresolved",
        "rationale": "evidence remains incomplete",
        "evidence_refs": ["analysis:1"],
    }
    completed = StpaChallengeLedger.model_validate(selected_with_outcome)
    assert completed.records[0].outcome is not None

    record = selected_with_outcome["records"][0]
    for field, value in (
        ("slot_id", ""),
        ("priority", -1),
        ("priority", False),
        ("eligibility_rationale", ""),
        ("eligibility_evidence_refs", []),
    ):
        invalid = yaml.safe_load(yaml.safe_dump(record))
        invalid[field] = value
        with pytest.raises(Exception):
            type(ledger.records[0]).model_validate(invalid)


def test_outcome_and_ledger_field_boundaries_are_enforced() -> None:
    """Completed outcomes and top-level counters remain closed and strict."""
    for payload in (
        {
            "disposition": "unresolved",
            "rationale": "",
            "evidence_refs": ["analysis:1"],
        },
        {
            "disposition": "unresolved",
            "rationale": "unknown",
            "evidence_refs": [],
        },
        {
            "disposition": "justified_na",
            "rationale": "not applicable",
            "evidence_refs": [""],
        },
    ):
        with pytest.raises(Exception):
            ChallengeOutcome.model_validate(payload)

    ledger = StpaChallengeLedger.from_yaml(REPRESENTATIVE_LEDGER.read_bytes())
    for field, value in (
        ("challenge_budget", True),
        ("challenge_budget", -1),
        ("network_calls", 1),
        ("model_calls", 1),
    ):
        payload = ledger.model_dump(mode="json")
        payload["semantic_digest"] = None
        payload[field] = value
        with pytest.raises(Exception):
            StpaChallengeLedger.model_validate(payload)

    wrong_schema_pin = ledger.model_dump(mode="json")
    wrong_schema_pin["semantic_digest"] = None
    wrong_schema_pin["assessment_pin"]["schema_version"] = "hybrid-coverage-v2"
    with pytest.raises(ValueError, match="Phase 2 assessment"):
        StpaChallengeLedger.model_validate(wrong_schema_pin)

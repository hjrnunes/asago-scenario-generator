"""Integration coverage for the runner's projection prejoin and identities."""

from __future__ import annotations

import hashlib
import json
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import yaml

from asago_scenario_generator.llm.client import LLMResult
from asago_scenario_generator.manifest import (
    ArtifactRole,
    compute_file_sha256,
    ManifestIntegrityError,
    ManifestInventoryResolver,
    RunStatus,
    load_manifest,
    validate_completed_inventory,
)
from asago_scenario_generator.models.attack_pattern import AttackPattern
from asago_scenario_generator.models.capability_profile import (
    ConfidenceLevel,
    EntryPoint,
    InventoryCompleteness,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionTraceabilityResult,
)
from asago_scenario_generator.models.scenario import CallMetadata, CallName
from asago_scenario_generator.pipeline.candidates import (
    FilteredSeed,
    RemovalDecision,
    StageRecord,
)
from asago_scenario_generator.pipeline.coverage import CoverageGaps
from asago_scenario_generator.pipeline.finalization_gates import (
    EXCEPTIONAL_ADMISSION_EVIDENCE_IDS,
    NORMAL_POSTBEHAVIOR_EVIDENCE_IDS,
    FinalTreeSemanticSnapshot,
)
from asago_scenario_generator.pipeline.generate.stages import (
    ActorStageResult,
    BehaviorStageResult,
    NarrativeStageResult,
    StageCallEvidence,
    TreeStageResult,
)
from asago_scenario_generator.pipeline.persistence import (
    canonical_sha256,
    read_coverage_plan,
    read_finalization_inventory,
    read_planning_checkpoint_bytes,
)
from asago_scenario_generator.pipeline.projection import canonical_json_bytes
from asago_scenario_generator.pipeline.runner import (
    _removal_decision_summary,
    resume_pipeline,
    run_pipeline,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.models import ThreatSurface
from tests.helpers.projection_factory import (
    _evidence,
    _pattern,
    _TaxonomyResolver,
    get_canonical_ingress_id,
    get_projected_candidate,
    get_test_profile,
    get_test_snapshot,
)
from tests.test_actor_entry_point_validation import (
    _make_envelope as _make_actor_envelope,
)
from tests.test_actor_entry_point_validation import (
    _make_profile,
)
from tests.test_finalization_gates import _phase3b_behavior
from tests.test_projection_traceability import _make_envelope as _make_valid_envelope


def test_rule_rejection_summary_uses_typed_removal_decision_fields() -> None:
    decision = RemovalDecision(
        technique_id="AML.T0001",
        rule="zone_compatibility",
        reason="Technique requires a tool-execution zone.",
    )

    assert _removal_decision_summary(decision) == (
        "zone_compatibility: Technique requires a tool-execution zone."
    )


def _same_snapshot_fallbacks():
    """Return two binding variants that share one trusted capability snapshot."""
    from asago_scenario_generator.models.capability_profile import CapabilityProfile
    from asago_scenario_generator.pipeline.projection import (
        ProjectionBudget,
        capture_capability_snapshot,
        project_authoritative_candidates,
    )

    raw = _pattern()
    pattern = AttackPattern.model_validate(raw)
    resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
    for tool_name in ("reader", "sender", "executor", "alpha", "b", "zz"):
        profile_data = get_test_profile().model_dump(mode="json")
        profile_data["tool_inventory"].append(
            {"name": tool_name, "description": "reads state"}
        )
        profile_data["tool_types"].append(
            {
                "name": tool_name,
                "zone": "tool_execution",
                "can_modify_state": False,
                "data_sensitivity": "low",
                "code_execution": False,
            }
        )
        profile = CapabilityProfile.model_validate(profile_data)
        snapshot = capture_capability_snapshot(profile, (_evidence(),))
        batch = project_authoritative_candidates(
            [raw], resolver, snapshot, budget=ProjectionBudget(max_candidates=100)
        )
        writer_id = profile.tool_inventory[0].tool_id
        writer = next(
            candidate
            for candidate in batch.candidates
            if writer_id in str(candidate.projection.bindings)
        )
        alternate = next(
            candidate for candidate in batch.candidates if candidate != writer
        )
        if alternate.candidate_id < writer.candidate_id:
            return profile, snapshot, [alternate, writer]
    raise AssertionError("fixture could not place the canonical writer as fallback")


def _arrange(tmp_path: Path, *, entry_point_id: str, projected_candidates: list):
    profile = _make_profile()
    profile.confidence = ConfidenceLevel.high
    profile.entry_points.append(
        EntryPoint(name="chat", direction="input", controllability="direct")
    )
    seed = ScenarioSeed(
        seed_id="AP-T1-01",
        threat_id="T1",
        threat_name="Test Threat",
        attack_pattern_name="Test Pattern",
        attack_pattern_description="A test attack pattern.",
        risk_card_ref=_make_actor_envelope().faceting.risk_card,
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
    )
    filtered = FilteredSeed(
        **seed.model_dump(),
        pinned_entry_point=profile.entry_points[0].name,
        pinned_technique_ids=("AML.T0051.000",),
        pinned_technique_names=("Prompt Injection",),
        entry_point_id=entry_point_id,
        candidate_id="cand:v2:" + "f" * 32,
    )

    client = MagicMock(
        model="test-model",
        base_url="mock://local",
        temperature=0.0,
        max_completion_tokens=1000,
    )
    llm_result = LLMResult(
        content="mock",
        prompt_tokens=0,
        completion_tokens=0,
        duration_ms=0,
        system_prompt="mock",
        user_prompt="mock",
    )
    risk_path = tmp_path / "risk.json"
    risk_path.write_text("[]", encoding="utf-8")
    sssom_path = tmp_path / "mapping.tsv"
    sssom_path.write_text("", encoding="utf-8")

    def expand(*args, stage_records, **kwargs):
        stage_records.append(
            StageRecord(
                stage="expansion", input_count=1, output_count=1, collapsed_count=0
            )
        )
        return [filtered]

    def rules(candidates, *args, stage_records, **kwargs):
        stage_records.append(
            StageRecord(
                stage="rule_pruning", input_count=1, output_count=1, collapsed_count=0
            )
        )
        return candidates, [], []

    stack = ExitStack()
    pattern = _pattern()
    validated_pattern = AttackPattern.model_validate(pattern)
    patches = {
        "LLMClient": MagicMock(return_value=client),
        "infer_capability_profile": MagicMock(return_value=(profile, llm_result)),
        "load_risk_extraction": MagicMock(return_value=[]),
        "validate_risk_card_coherence": MagicMock(
            return_value=MagicMock(has_warnings=False)
        ),
        "determine_threat_surface": MagicMock(
            return_value=ThreatSurface(entries=[], governance_only=[])
        ),
        "expand_seeds": MagicMock(return_value=[seed]),
        "expand_candidates": MagicMock(side_effect=expand),
        "apply_rule_based_filter": MagicMock(side_effect=rules),
        "filter_candidates": MagicMock(return_value=([filtered], [], [])),
        "load_attack_patterns": MagicMock(return_value={"test": pattern}),
        "load_taxonomy_resolver": MagicMock(
            return_value=_TaxonomyResolver(
                validated_pattern.canonical_chain.taxonomy_context
            )
        ),
        "project_authoritative_candidates": MagicMock(
            return_value=MagicMock(
                candidates=projected_candidates, infeasibilities=[], limitations=[]
            )
        ),
        "capture_capability_snapshot": MagicMock(return_value=get_test_snapshot()),
        "analyze_coverage_gaps": MagicMock(return_value=CoverageGaps()),
        "analyze_attacker_diversity": MagicMock(return_value=None),
    }
    for name, replacement in patches.items():
        stack.enter_context(
            patch(f"asago_scenario_generator.pipeline.runner.{name}", replacement)
        )
    from asago_scenario_generator.pipeline.coverage_planning import (
        deserialize_qualified_candidate,
    )

    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.revalidate_qualified_candidate",
            side_effect=lambda raw, *_: deserialize_qualified_candidate(raw),
        )
    )
    envelope = _make_valid_envelope()
    envelope.attack_tree.root.threat_id = "T1"
    envelope.behavior_spec = _phase3b_behavior(
        get_projected_candidate(), envelope.attack_tree
    )

    def evidence(call: CallName) -> StageCallEvidence:
        return StageCallEvidence(
            call,
            llm_result,
            CallMetadata(
                call=call, prompt_tokens=0, completion_tokens=0, duration_ms=0
            ),
        )

    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_actor_stage",
            return_value=ActorStageResult(
                envelope.actor_profile, evidence(CallName.actor_profile)
            ),
        )
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_narrative_stage",
            return_value=NarrativeStageResult(
                envelope.narrative, evidence(CallName.narrative)
            ),
        )
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_tree_stage",
            return_value=TreeStageResult(
                envelope.attack_tree, evidence(CallName.attack_tree)
            ),
        )
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.generate.stages.generate_behavior_stage",
            return_value=BehaviorStageResult(
                envelope.behavior_spec, evidence(CallName.behavior_spec)
            ),
        )
    )

    def evaluate(*, resolver, threats_path=None):
        inventory = resolver.manifest.inventory
        assert not any(
            item.role is ArtifactRole.QUARANTINE_BUNDLE for item in inventory
        )
        assert {item.role for item in inventory if item.scenario_id is not None} <= {
            ArtifactRole.SCENARIO_YAML,
            ArtifactRole.SCENARIO_FEATURE,
        }
        return {
            "evaluation": {
                "scenario_count": sum(
                    item.role is ArtifactRole.SCENARIO_YAML for item in inventory
                ),
                "feature_file_count": sum(
                    item.role is ArtifactRole.SCENARIO_FEATURE for item in inventory
                ),
            },
            "metrics": {},
        }

    stack.enter_context(
        patch(
            "asago_scenario_generator.eval.runner.run_evaluation", side_effect=evaluate
        )
    )

    def report(data, out_dir):
        path = Path(out_dir) / "report.html"
        path.write_text("<html></html>", encoding="utf-8")
        return path

    stack.enter_context(
        patch(
            "asago_scenario_generator.report.generator.generate_report",
            side_effect=report,
        )
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability",
            return_value=ProjectionTraceabilityResult(valid=True, violations=[]),
        )
    )
    args = {
        "use_case": "A chatbot with a direct user prompt entry point.",
        "risk_extraction_path": risk_path,
        "sssom_path": sssom_path,
        "output_dir": tmp_path / "runs",
    }
    # Preserve the fixture's established tuple shape without patching any
    # removed runner generation symbol. Generation is owned by the v3 stages.
    return stack, patches, object(), args


def test_exact_projection_match_uses_authoritative_identity(tmp_path: Path) -> None:
    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    with stack:
        result = run_pipeline(**args)

    assert result.scenarios[0].candidate_id == projected.candidate_id
    assert result.admitted_count == 1
    manifest = load_manifest(result.run_dir)
    scenario_inventory = [item for item in manifest.inventory if item.scenario_id]
    assert scenario_inventory
    assert {item.candidate_id for item in scenario_inventory} == {
        projected.candidate_id
    }
    assert manifest.manifest_version == "3"
    assert manifest.attempts == []
    assert manifest.funnel == {}
    assert manifest.provenance is not None
    assert "qualification_facts_path" not in manifest.provenance.command.options
    assert (
        manifest.provenance.command.options["qualification_facts_mode"]
        == "omitted_compatibility"
    )
    assert manifest.provenance.command.options["generation_mode"] == "exhaustive"
    assert any(
        note.startswith("qualification_facts_omitted:")
        for note in result.generation_notes
    )
    assert manifest.semantic_generation["required_stages"] == [
        "actor",
        "narrative",
        "tree",
        "behavior",
    ]
    tampered = manifest.model_copy(deep=True)
    tampered.semantic_generation["schema_version"] = "tampered"
    with pytest.raises(
        ManifestIntegrityError,
        match="semantic_generation does not match finalization inventory",
    ):
        ManifestInventoryResolver(result.run_dir, tampered, check_orphans=True)
    planning_entry = next(
        item
        for item in manifest.inventory
        if item.role is ArtifactRole.PLANNING_CHECKPOINT
    )
    planning_bytes = ManifestInventoryResolver(
        result.run_dir, manifest, check_orphans=True
    ).read_bytes(planning_entry)
    assert b"qualification_facts" not in planning_bytes


def _write_qualification_facts(path: Path) -> bytes:
    content = yaml.safe_dump(
        {
            "schema_version": "1",
            "facts": [
                item.model_dump(mode="json") for item in get_test_snapshot().facts
            ],
        },
        sort_keys=False,
    ).encode()
    path.write_bytes(content)
    return content


def test_runner_binds_nonempty_qualification_facts_to_v3_planning(
    tmp_path: Path,
) -> None:
    projected = get_projected_candidate()
    stack, patches, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    facts_path = tmp_path / "qualification-facts.yaml"
    source = _write_qualification_facts(facts_path)

    with stack:
        result = run_pipeline(**args, qualification_facts_path=facts_path)

    manifest = load_manifest(result.run_dir)
    assert manifest.provenance is not None
    assert manifest.provenance.command.options["qualification_facts_mode"] == "explicit"
    assert not any(
        note.startswith("qualification_facts_omitted:")
        for note in result.generation_notes
    )
    assert (
        manifest.provenance.input_hashes.qualification_facts_hash
        == hashlib.sha256(source).hexdigest()
    )
    planning_entry = next(
        item
        for item in manifest.inventory
        if item.role is ArtifactRole.PLANNING_CHECKPOINT
    )
    planning = read_planning_checkpoint_bytes(
        ManifestInventoryResolver(
            result.run_dir, manifest, check_orphans=True
        ).read_bytes(planning_entry)
    )
    assert planning.qualification_facts_source == source.decode()
    assert planning.qualification_facts_sha256 == hashlib.sha256(source).hexdigest()
    assert (
        patches["capture_capability_snapshot"].call_args.args[1]
        == get_test_snapshot().facts
    )
    scenario_entry = next(
        item for item in manifest.inventory if item.role is ArtifactRole.SCENARIO_YAML
    )
    scenario = yaml.safe_load((result.run_dir / scenario_entry.path).read_text())
    assert scenario["projection"]["capability_snapshot"]["facts"]


def test_resume_reconstructs_exact_qualification_facts_and_rejects_source_drift(
    tmp_path: Path,
) -> None:
    projected = get_projected_candidate()
    stack, patches, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    facts_path = tmp_path / "qualification-facts.yaml"
    source = _write_qualification_facts(facts_path)
    actor = stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_actor_stage",
            side_effect=KeyboardInterrupt("interrupt after planning"),
        )
    )

    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args, qualification_facts_path=facts_path)
        run_dir = next(args["output_dir"].iterdir())
        facts_path.write_bytes(source + b"\n")
        with pytest.raises(ManifestIntegrityError, match="qualification_facts_hash"):
            resume_pipeline(run_dir)
        facts_path.write_bytes(source)
        actor.side_effect = None
        actor.return_value = ActorStageResult(
            _make_valid_envelope().actor_profile,
            StageCallEvidence(
                CallName.actor_profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
                CallMetadata(
                    call=CallName.actor_profile,
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                ),
            ),
        )
        resume_pipeline(run_dir)

    assert patches["capture_capability_snapshot"].call_count >= 2
    assert all(
        call.args[1] == get_test_snapshot().facts
        for call in patches["capture_capability_snapshot"].call_args_list
    )


def test_strict_resolver_rejects_noncanonical_admitted_gate_evidence(
    tmp_path: Path,
) -> None:
    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    with stack:
        result = run_pipeline(**args)

    manifest = load_manifest(result.run_dir)
    final_entry = next(
        entry
        for entry in manifest.inventory
        if entry.role is ArtifactRole.FINALIZATION_INVENTORY
    )
    final_path = result.run_dir / final_entry.path
    original = json.loads(final_path.read_text())
    admitted_index = next(
        index
        for index, decision in enumerate(original["admission_decisions"])
        if decision["admitted"]
    )
    original_gates = original["admission_decisions"][admitted_index]["gate_results"]
    mutations: list[list[dict]] = [
        [gate for gate in original_gates if gate["gate"] != missing.value]
        for missing in NORMAL_POSTBEHAVIOR_EVIDENCE_IDS
    ]
    mutations.append([*original_gates, original_gates[0]])
    mutations.extend(
        [
            *original_gates,
            {
                "gate": exceptional.value,
                "passed": True,
                "violations": [],
                "diagnostics": [],
                "applicable": True,
            },
        ]
        for exceptional in EXCEPTIONAL_ADMISSION_EVIDENCE_IDS
    )

    for gate_results in mutations:
        mutated = json.loads(json.dumps(original))
        mutated["admission_decisions"][admitted_index]["gate_results"] = gate_results
        final_path.write_bytes(canonical_json_bytes(mutated))
        final_entry.sha256 = compute_file_sha256(final_path)
        with pytest.raises(
            ManifestIntegrityError, match="Invalid manifest v3 persistence model"
        ):
            ManifestInventoryResolver(result.run_dir, manifest, check_orphans=False)


def test_strict_resolver_binds_conditional_applicability_to_profile(
    tmp_path: Path,
) -> None:
    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    with stack:
        result = run_pipeline(**args)

    manifest = load_manifest(result.run_dir)
    final_entry = next(
        entry
        for entry in manifest.inventory
        if entry.role is ArtifactRole.FINALIZATION_INVENTORY
    )
    profile_entry = next(
        entry
        for entry in manifest.inventory
        if entry.role is ArtifactRole.CAPABILITY_PROFILE
    )
    final_path = result.run_dir / final_entry.path
    profile_path = result.run_dir / profile_entry.path
    original_final = json.loads(final_path.read_text())
    original_profile = yaml.safe_load(profile_path.read_text())
    admitted_index = next(
        index
        for index, decision in enumerate(original_final["admission_decisions"])
        if decision["admitted"]
    )

    def write_final(document: dict) -> None:
        decision = document["admission_decisions"][admitted_index]
        payload = {
            "candidate_id": decision["candidate_id"],
            "status": decision["status"],
            "violations": decision["violations"],
            "gate_results": decision["gate_results"],
            "snapshots": {
                key: decision[key]
                for key in (
                    "candidate_snapshot_sha256",
                    "actor_snapshot_sha256",
                    "narrative_snapshot_sha256",
                    "final_tree_snapshot_sha256",
                )
            },
            "terminal_receipts": [
                {
                    key: receipt[key]
                    for key in ("role", "path", "candidate_id", "scenario_id", "sha256")
                }
                for receipt in sorted(
                    decision["terminal_receipts"],
                    key=lambda item: (item["role"], item["path"]),
                )
            ],
        }
        decision["payload_sha256"] = canonical_sha256(payload)
        final_path.write_bytes(canonical_json_bytes(document))
        final_entry.sha256 = compute_file_sha256(final_path)

    bindings = (
        (
            "tool_integration_grounding",
            "tool_inventory_completeness",
            "tool_inventory_evidence",
        ),
        (
            "data_access_grounding",
            "entry_point_completeness",
            "entry_point_evidence",
        ),
    )
    for evidence_id, completeness_field, evidence_field in bindings:
        partial_forgery = json.loads(json.dumps(original_final))
        gate = next(
            gate
            for gate in partial_forgery["admission_decisions"][admitted_index][
                "gate_results"
            ]
            if gate["gate"] == evidence_id
        )
        assert gate["applicable"] is False
        gate["applicable"] = True
        write_final(partial_forgery)
        with pytest.raises(ManifestIntegrityError, match="applicability"):
            ManifestInventoryResolver(result.run_dir, manifest, check_orphans=False)

        write_final(json.loads(json.dumps(original_final)))
        confirmed_profile = json.loads(json.dumps(original_profile))
        confirmed_profile[completeness_field] = (
            InventoryCompleteness.operator_confirmed_complete.value
        )
        confirmed_profile[evidence_field] = ["operator-review:test"]
        profile_path.write_text(yaml.safe_dump(confirmed_profile, sort_keys=False))
        profile_entry.sha256 = compute_file_sha256(profile_path)
        with pytest.raises(ManifestIntegrityError, match="applicability"):
            ManifestInventoryResolver(result.run_dir, manifest, check_orphans=False)

        profile_path.write_text(yaml.safe_dump(original_profile, sort_keys=False))
        profile_entry.sha256 = compute_file_sha256(profile_path)


def test_completion_recomputes_scorecard_and_report_from_strict_inventory(
    tmp_path: Path,
) -> None:
    import yaml

    from asago_scenario_generator.eval.runner import run_evaluation as actual_evaluation
    from asago_scenario_generator.eval.scorecard import (
        MetricResult,
        QUALIFICATION_GATE_PATHS,
        REQUIRED_QUALIFICATION_GATE_IDS,
        ScorecardV1,
        aggregate_qualification,
        ratio_metric,
        zero_gate,
    )

    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )

    def qualifying_evaluation(**kwargs):
        scorecard = actual_evaluation(**kwargs)
        scorecard["cross_artifact_agreement"]["metrics"]["pinned_technique_recall"] = (
            ratio_metric(
                1,
                1,
                evidence=["test fixture supplies qualifying pinned-technique evidence"],
            ).model_dump(mode="json")
        )
        gates = {
            gate_id: MetricResult.model_validate(
                scorecard[section]["metrics"][metric_id]
            )
            for gate_id, (section, metric_id) in QUALIFICATION_GATE_PATHS.items()
        }
        scorecard["qualification"] = aggregate_qualification(
            gates, required_gate_ids=REQUIRED_QUALIFICATION_GATE_IDS
        ).model_dump(mode="json")
        return ScorecardV1.model_validate(scorecard).model_dump(mode="json")

    stack.enter_context(
        patch(
            "asago_scenario_generator.eval.runner.run_evaluation",
            side_effect=qualifying_evaluation,
        )
    )
    rendered_statuses: list[str] = []

    def report(data, out_dir):
        status = data.scorecard_data["qualification"]["status"]
        rendered_statuses.append(status)
        path = Path(out_dir) / "report.html"
        path.write_text(f"<html>{status}</html>", encoding="utf-8")
        return path

    stack.enter_context(
        patch(
            "asago_scenario_generator.report.generator.generate_report",
            side_effect=report,
        )
    )

    with stack:
        result = run_pipeline(**args)

    manifest = load_manifest(result.run_dir)
    scorecard = yaml.safe_load((result.run_dir / "eval-scorecard.yaml").read_text())
    presence = scorecard["presence_coverage"]["metrics"]
    assert manifest.status is RunStatus.COMPLETED
    assert scorecard["qualification"]["status"] == "pass"
    assert presence["stale_or_orphan_artifact_count"]["status"] == "pass"
    assert presence["unmanifested_artifact_count"]["status"] == "pass"
    assert rendered_statuses == ["fail", "pass"]
    assert (result.run_dir / "report.html").read_text() == "<html>pass</html>"

    authoritative_bytes = {
        path.relative_to(result.run_dir): path.read_bytes()
        for path in result.run_dir.rglob("*")
        if path.is_file()
    }
    actual_evaluation(result.run_dir)
    assert authoritative_bytes == {
        path.relative_to(result.run_dir): path.read_bytes()
        for path in result.run_dir.rglob("*")
        if path.is_file()
    }

    manifest_path = result.run_dir / "run-manifest.yaml"
    authoritative_manifest_bytes = manifest_path.read_bytes()
    forensic_manifest = yaml.safe_load(authoritative_manifest_bytes)
    forensic_manifest["status"] = RunStatus.COMPLETED_WITH_ERRORS.value
    manifest_path.write_text(yaml.safe_dump(forensic_manifest, sort_keys=False))
    forensic_bytes = {
        path.relative_to(result.run_dir): path.read_bytes()
        for path in result.run_dir.rglob("*")
        if path.is_file()
    }
    with pytest.raises(ManifestIntegrityError, match="not authoritative"):
        actual_evaluation(result.run_dir)
    actual_evaluation(result.run_dir, allow_non_authoritative=True)
    assert forensic_bytes == {
        path.relative_to(result.run_dir): path.read_bytes()
        for path in result.run_dir.rglob("*")
        if path.is_file()
    }
    manifest_path.write_bytes(authoritative_manifest_bytes)

    scorecard_path = result.run_dir / "eval-scorecard.yaml"
    scorecard["run_id"] = "forged-run-id"
    scorecard_path.write_text(yaml.safe_dump(scorecard, sort_keys=False))
    scorecard_entry = next(
        entry
        for entry in manifest.inventory
        if entry.role is ArtifactRole.EVAL_SCORECARD
    )
    scorecard_entry.sha256 = compute_file_sha256(scorecard_path)
    with pytest.raises(ManifestIntegrityError, match="does not match manifest run_id"):
        validate_completed_inventory(
            manifest, eval_enabled=True, run_dir=result.run_dir
        )
    manifest.status = RunStatus.COMPLETED_WITH_ERRORS
    with pytest.raises(ManifestIntegrityError, match="does not match manifest run_id"):
        ManifestInventoryResolver(result.run_dir, manifest, check_orphans=True)
    manifest.status = RunStatus.COMPLETED

    scorecard["run_id"] = manifest.run_id
    scorecard["presence_coverage"]["metrics"]["nonempty_admitted_inventory"] = (
        zero_gate(
            1,
            evidence=["forged failing required gate"],
            affected_ids=[manifest.run_id],
        ).model_dump(mode="json")
    )
    gates = {
        gate_id: MetricResult.model_validate(scorecard[section]["metrics"][metric_id])
        for gate_id, (section, metric_id) in QUALIFICATION_GATE_PATHS.items()
    }
    scorecard["qualification"] = aggregate_qualification(
        gates, required_gate_ids=REQUIRED_QUALIFICATION_GATE_IDS
    ).model_dump(mode="json")
    failing_scorecard = ScorecardV1.model_validate(scorecard).model_dump(mode="json")
    scorecard_path.write_text(yaml.safe_dump(failing_scorecard, sort_keys=False))
    scorecard_entry.sha256 = compute_file_sha256(scorecard_path)
    with pytest.raises(ManifestIntegrityError, match="requires passing scorecard"):
        validate_completed_inventory(
            manifest, eval_enabled=True, run_dir=result.run_dir
        )

    manifest.status = RunStatus.COMPLETED_WITH_ERRORS
    ManifestInventoryResolver(result.run_dir, manifest, check_orphans=True)
    validate_completed_inventory(manifest, eval_enabled=True, run_dir=result.run_dir)


def test_orphan_injected_before_strict_completion_blocks_completed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from asago_scenario_generator.eval.runner import run_evaluation as actual_evaluation

    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[get_projected_candidate()],
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.eval.runner.run_evaluation",
            side_effect=actual_evaluation,
        )
    )

    def report(data, out_dir):
        path = Path(out_dir) / "report.html"
        path.write_text("<html>provisional</html>", encoding="utf-8")
        (Path(out_dir) / "orphan.txt").write_text("injected", encoding="utf-8")
        return path

    stack.enter_context(
        patch(
            "asago_scenario_generator.report.generator.generate_report",
            side_effect=report,
        )
    )

    with stack, pytest.raises(ManifestIntegrityError, match="orphan"):
        run_pipeline(**args)

    [run_dir] = (tmp_path / "runs").iterdir()
    manifest = load_manifest(run_dir)
    assert manifest.status is RunStatus.FAILED
    assert not (run_dir / "eval-scorecard.yaml").exists()
    assert not (run_dir / "report.html").exists()
    assert "orphan" in caplog.text


def test_tree_is_immutable_through_admission_persistence_and_evaluation(
    tmp_path: Path,
) -> None:
    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    envelope = _make_valid_envelope()
    envelope.attack_tree.root.threat_id = "T1"
    envelope.behavior_spec = _phase3b_behavior(projected, envelope.attack_tree)
    original_tree = envelope.attack_tree
    original_snapshot = FinalTreeSemanticSnapshot.capture(original_tree)
    llm_result = LLMResult(
        content="mock",
        prompt_tokens=0,
        completion_tokens=0,
        duration_ms=0,
        system_prompt="mock",
        user_prompt="mock",
    )

    def evidence(call: CallName) -> StageCallEvidence:
        return StageCallEvidence(
            call,
            llm_result,
            CallMetadata(
                call=call, prompt_tokens=0, completion_tokens=0, duration_ms=0
            ),
        )

    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_tree_stage",
            return_value=TreeStageResult(original_tree, evidence(CallName.attack_tree)),
        )
    )
    behavior_observations: list[tuple[bytes, str]] = []

    def observe_behavior(_prepared, _narrative, tree, _retry=None):
        observed = FinalTreeSemanticSnapshot.capture(tree)
        behavior_observations.append((observed.canonical_bytes, observed.digest))
        return BehaviorStageResult(
            envelope.behavior_spec, evidence(CallName.behavior_spec)
        )

    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.generate.stages.generate_behavior_stage",
            side_effect=observe_behavior,
        )
    )
    evaluated_trees: list[dict] = []

    def evaluate(*, resolver, threats_path=None):
        del threats_path
        scenario_entries = resolver.entries_by_role(ArtifactRole.SCENARIO_YAML)
        scenario_ids = {
            item.scenario_id
            for item in resolver.manifest.inventory
            if item.scenario_id is not None
        }
        assert len(scenario_entries) == 1
        assert scenario_ids == {scenario_entries[0].scenario_id}
        assert not resolver.entries_by_role(ArtifactRole.QUARANTINE_BUNDLE)
        persisted = resolver.read_yaml(scenario_entries[0])
        evaluated_trees.append(persisted["attack_tree"])
        assert canonical_json_bytes(persisted["attack_tree"]) == (
            original_snapshot.canonical_bytes
        )
        return {
            "evaluation": {"scenario_count": 1, "feature_file_count": 1},
            "metrics": {},
        }

    stack.enter_context(
        patch(
            "asago_scenario_generator.eval.runner.run_evaluation", side_effect=evaluate
        )
    )

    with stack:
        result = run_pipeline(**args)

    original_snapshot.verify_digest()
    assert FinalTreeSemanticSnapshot.capture(original_tree).digest == (
        original_snapshot.digest
    )
    assert behavior_observations == [
        (original_snapshot.canonical_bytes, original_snapshot.digest)
    ]
    manifest = load_manifest(result.run_dir)
    resolver = ManifestInventoryResolver(result.run_dir, manifest)
    admitted = resolver.entries_by_role(ArtifactRole.SCENARIO_YAML)
    assert len(admitted) == 1
    assert evaluated_trees == [resolver.read_yaml(admitted[0])["attack_tree"]]
    assert [scenario.scenario_id for scenario in result.scenarios] == [
        admitted[0].scenario_id
    ]


def test_zero_exact_projection_match_completes_without_generation(
    tmp_path: Path,
) -> None:
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id="ep:v1:" + "0" * 32,
        projected_candidates=[get_projected_candidate()],
    )
    with stack:
        result = run_pipeline(**args)
    assert result.run_dir is not None
    manifest = load_manifest(result.run_dir)
    assert manifest.funnel == {}
    assert read_finalization_inventory(result.run_dir).candidate_attempts == []
    assert all(
        target.target_state.value == "exhausted"
        for target in read_coverage_plan(result.run_dir).targets
    )


def test_multiple_exact_projection_matches_fan_out(tmp_path: Path) -> None:
    """cmps.4: Multiple projected candidates with distinct bindings for the
    same pattern+ingress are valid alternatives — fanned out, not fatal.

    Uses a real projection from a profile with two tools, producing two
    ProjectedCandidate records with the same pattern_id and same
    canonical_ingress entry_point_id but genuinely different concrete
    bindings (different tool bindings) and recomputed candidate_ids —
    not model_copy with a swapped ID.
    """
    from asago_scenario_generator.models.attack_pattern import AttackPattern
    from asago_scenario_generator.models.capability_profile import (
        CapabilityProfile,
        ConfidenceLevel,
    )
    from asago_scenario_generator.pipeline.projection import (
        ProjectionBudget,
        capture_capability_snapshot,
        project_authoritative_candidates,
    )
    from tests.helpers.projection_factory import (
        _evidence,
        _pattern,
        _TaxonomyResolver,
    )

    raw = _pattern()
    pattern = AttackPattern.model_validate(raw)
    resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
    # Profile with 2 tools → 2 binding combinations for same ingress.
    profile = CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "direct"},
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC5.1"],
        tool_inventory=[
            {"name": "writer", "description": "changes state"},
            {"name": "reader", "description": "reads state"},
        ],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            },
            {
                "name": "reader",
                "zone": "tool_execution",
                "can_modify_state": False,
                "data_sensitivity": "low",
                "code_execution": False,
            },
        ],
        external_integrations=[
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ],
        trust_boundaries=[
            {
                "name": "user-to-agent",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )
    snapshot = capture_capability_snapshot(profile, (_evidence(),))
    batch = project_authoritative_candidates(
        [raw], resolver, snapshot, budget=ProjectionBudget(max_candidates=100)
    )
    assert len(batch.candidates) == 2
    first, second = batch.candidates
    assert first.candidate_id != second.candidate_id
    # Same pattern+ingress, different concrete bindings.
    assert (
        first.canonical_ingress.entry_point_id
        == second.canonical_ingress.entry_point_id
    )
    assert first.pattern_id == second.pattern_id

    # Arrange the runner with both projected candidates.  The filtered seed
    # matches the shared ingress; the runner fans out all matches.
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=first.canonical_ingress.entry_point_id,
        projected_candidates=[first, second],
    )
    with stack:
        result = run_pipeline(**args)
    assert result.run_dir is not None
    manifest = load_manifest(result.run_dir)
    assert manifest.funnel == {}
    plan = read_coverage_plan(result.run_dir)
    populated_targets = [item for item in plan.targets if item.ordered_choices]
    assert len(populated_targets) == 2
    assert len({item.effective_target_id for item in populated_targets}) == 2
    assert {item.entry_point_id for item in populated_targets} == {
        first.canonical_ingress.entry_point_id
    }
    assert {target.ordered_choices[0].candidate_id for target in populated_targets} == {
        first.candidate_id,
        second.candidate_id,
    }
    assert all(len(target.ordered_choices) == 1 for target in populated_targets)
    inventory = read_finalization_inventory(result.run_dir)
    assert {item.candidate_id for item in inventory.candidate_attempts} == {
        first.candidate_id,
        second.candidate_id,
    }


def test_runner_uses_unmodified_derived_projected_candidate(tmp_path: Path) -> None:
    """The runner must use the unmodified ProjectedCandidate returned by
    projection — not a copied or manually altered object."""
    projected = get_projected_candidate()  # unmodified
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    with stack:
        result = run_pipeline(**args)
    attempts = read_finalization_inventory(result.run_dir).candidate_attempts
    assert [item.candidate_id for item in attempts] == [projected.candidate_id]


def test_attempt_is_reserved_before_failed_actor_stage(tmp_path: Path) -> None:
    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_actor_stage",
            side_effect=RuntimeError("generation failed"),
        )
    )
    with stack:
        result = run_pipeline(**args)

    inventory = read_finalization_inventory(result.run_dir)
    assert [item.candidate_id for item in inventory.candidate_attempts] == [
        projected.candidate_id
    ]
    assert inventory.admission_decisions[0].admitted is False
    assert inventory.quarantine_inventory


def test_production_primary_quarantine_then_fallback_admits(tmp_path: Path) -> None:
    profile, snapshot, projected = _same_snapshot_fallbacks()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected[0].canonical_ingress.entry_point_id,
        projected_candidates=projected,
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner.infer_capability_profile",
            return_value=(
                profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
            ),
        )
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner.capture_capability_snapshot",
            return_value=snapshot,
        )
    )
    from asago_scenario_generator.pipeline.coverage_planning import SelectionResult

    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.coverage_planning.select_with_coverage_priority",
            side_effect=lambda qualified, _queues, universe, **_kwargs: SelectionResult(
                selected=[
                    item
                    for item in qualified
                    if item.candidate_id == projected[0].candidate_id
                ],
                uncovered_target_ids=sorted(
                    universe.feasible_target_ids
                    - {projected[0].canonical_ingress.entry_point_id}
                ),
                primary_candidate_ids={
                    projected[0].canonical_ingress.entry_point_id: projected[
                        0
                    ].candidate_id
                },
                attempted_candidate_ids={projected[0].candidate_id},
                per_pattern_counts={projected[0].pattern_id: 1},
            ),
        )
    )
    envelope = _make_valid_envelope()
    envelope.attack_tree.root.threat_id = "T1"
    actor_result = ActorStageResult(
        envelope.actor_profile,
        StageCallEvidence(
            CallName.actor_profile,
            LLMResult(
                content="mock",
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
                system_prompt="mock",
                user_prompt="mock",
            ),
            CallMetadata(
                call=CallName.actor_profile,
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
            ),
        ),
    )
    actor = stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_actor_stage",
            side_effect=[
                RuntimeError("primary failed 0"),
                RuntimeError("primary failed 1"),
                RuntimeError("primary failed 2"),
                actor_result,
            ],
        )
    )
    with stack:
        result = run_pipeline(**args, generation_mode="coverage")

    assert actor.call_count == 4
    inventory = read_finalization_inventory(result.run_dir)
    assert [item.admitted for item in inventory.admission_decisions] == [False, True]
    manifest = load_manifest(result.run_dir)
    assert manifest.status is RunStatus.COMPLETED_WITH_ERRORS
    assert manifest.provenance.command.options["generation_mode"] == "coverage"


@pytest.mark.parametrize("generation_mode", ["coverage", "exhaustive"])
def test_public_resume_terminalizes_unknown_actor_without_reissue(
    tmp_path: Path, generation_mode: str
) -> None:
    profile, snapshot, projected = _same_snapshot_fallbacks()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected[0].canonical_ingress.entry_point_id,
        projected_candidates=projected,
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner.infer_capability_profile",
            return_value=(
                profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
            ),
        )
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner.capture_capability_snapshot",
            return_value=snapshot,
        )
    )
    from asago_scenario_generator.pipeline.coverage_planning import SelectionResult

    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.coverage_planning.select_with_coverage_priority",
            side_effect=lambda qualified, _queues, universe, **_kwargs: SelectionResult(
                selected=[
                    item
                    for item in qualified
                    if item.candidate_id == projected[0].candidate_id
                ],
                uncovered_target_ids=sorted(
                    universe.feasible_target_ids
                    - {projected[0].canonical_ingress.entry_point_id}
                ),
                primary_candidate_ids={
                    projected[0].canonical_ingress.entry_point_id: projected[
                        0
                    ].candidate_id
                },
                attempted_candidate_ids={projected[0].candidate_id},
                per_pattern_counts={projected[0].pattern_id: 1},
            ),
        )
    )
    actor = stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_actor_stage",
            side_effect=KeyboardInterrupt("simulated process exit"),
        )
    )
    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args, generation_mode=generation_mode)
        run_dir = next(args["output_dir"].iterdir())
        started = load_manifest(run_dir)
        assert started.status is RunStatus.STARTED
        assert {item.role for item in started.inventory} == {
            ArtifactRole.USE_CASE,
            ArtifactRole.CAPABILITY_PROFILE,
            ArtifactRole.THREAT_SURFACE,
            ArtifactRole.PLANNING_CHECKPOINT,
        }
        before = read_finalization_inventory(run_dir)
        assert len(before.transitions) >= 2
        assert before.stage_attempts == []

        envelope = _make_valid_envelope()
        envelope.attack_tree.root.threat_id = "T1"
        actor.side_effect = None
        actor.return_value = ActorStageResult(
            envelope.actor_profile,
            StageCallEvidence(
                CallName.actor_profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
                CallMetadata(
                    call=CallName.actor_profile,
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                ),
            ),
        )
        resumed = resume_pipeline(run_dir)

    assert resumed.run_dir == run_dir
    assert actor.call_count == 2  # crashed primary call plus fallback only
    inventory = read_finalization_inventory(run_dir)
    assert [item.admitted for item in inventory.admission_decisions] == [False, True]
    plan = read_coverage_plan(run_dir)
    populated_targets = [target for target in plan.targets if target.ordered_choices]
    assert len(populated_targets) == (1 if generation_mode == "coverage" else 2)
    unknown = inventory.admission_decisions[0]
    assert [item.code for item in unknown.violations] == ["unknown_invocation_outcome"]
    assert unknown.terminal_receipts[0].role is ArtifactRole.QUARANTINE_BUNDLE
    assert load_manifest(run_dir).status is RunStatus.COMPLETED_WITH_ERRORS


def test_resume_preserves_persisted_no_eval_policy(tmp_path: Path) -> None:
    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    actor = stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_actor_stage",
            side_effect=KeyboardInterrupt("interrupt finalization"),
        )
    )
    evaluator = MagicMock(side_effect=AssertionError("evaluation must stay disabled"))
    stack.enter_context(
        patch("asago_scenario_generator.eval.runner.run_evaluation", evaluator)
    )

    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args, eval=False)
        run_dir = next(args["output_dir"].iterdir())
        actor.side_effect = None
        envelope = _make_valid_envelope()
        envelope.attack_tree.root.threat_id = "T1"
        actor.return_value = ActorStageResult(
            envelope.actor_profile,
            StageCallEvidence(
                CallName.actor_profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
                CallMetadata(
                    call=CallName.actor_profile,
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                ),
            ),
        )
        resumed = resume_pipeline(run_dir)

    evaluator.assert_not_called()
    assert resumed.run_dir == run_dir
    assert load_manifest(run_dir).status is RunStatus.COMPLETED_WITH_ERRORS


def test_resume_rejects_conflicting_eval_before_candidate_generation(
    tmp_path: Path,
) -> None:
    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    actor = stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_actor_stage",
            side_effect=KeyboardInterrupt("interrupt finalization"),
        )
    )

    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args, eval=False)
        run_dir = next(args["output_dir"].iterdir())
        with pytest.raises(ManifestIntegrityError, match="eval override conflicts"):
            resume_pipeline(run_dir, eval=True)

    assert actor.call_count == 1


def test_resume_passes_persisted_custom_threats_path_to_evaluator(
    tmp_path: Path,
) -> None:
    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    custom_threats = tmp_path / "custom-threats.yaml"
    custom_threats.write_text("threats: []\n", encoding="utf-8")
    actor = stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_actor_stage",
            side_effect=KeyboardInterrupt("interrupt finalization"),
        )
    )
    seen_paths: list[Path | None] = []

    def evaluate(*, resolver, threats_path=None):
        seen_paths.append(threats_path)
        return {"evaluation": {}, "metrics": {}}

    stack.enter_context(
        patch(
            "asago_scenario_generator.eval.runner.run_evaluation", side_effect=evaluate
        )
    )

    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args, threats_path=custom_threats)
        run_dir = next(args["output_dir"].iterdir())
        actor.side_effect = None
        actor.return_value = ActorStageResult(
            _make_valid_envelope().actor_profile,
            StageCallEvidence(
                CallName.actor_profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
                CallMetadata(
                    call=CallName.actor_profile,
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                ),
            ),
        )
        resume_pipeline(run_dir)

    assert seen_paths == [custom_threats]


def test_resume_hydrates_production_planning_checkpoint_attribution(
    tmp_path: Path,
) -> None:
    """The resumed completion tail receives the exact production evidence."""
    from asago_scenario_generator.pipeline.coverage_planning import (
        build_coverage_universe,
        emit_quality_gaps,
    )

    rejected_id = "cand:v2:" + "f" * 32
    arranged_profile = _make_profile()
    arranged_profile.confidence = ConfidenceLevel.high
    arranged_profile.entry_points.append(
        EntryPoint(name="chat", direction="input", controllability="direct")
    )
    feasible_ids = sorted(build_coverage_universe(arranged_profile).feasible_target_ids)
    rejected_target, limited_target = feasible_ids
    stack, patches, _, args = _arrange(
        tmp_path,
        entry_point_id=rejected_target,
        projected_candidates=[],
    )
    patches["project_authoritative_candidates"].return_value = SimpleNamespace(
        candidates=[],
        infeasibilities=[],
        limitations=[],
        unreserved_coverage_targets=[limited_target],
        infeasible_coverage_targets=[],
    )
    completion_inputs: list[dict] = []

    def interrupt_then_capture(**kwargs):
        completion_inputs.append(kwargs)
        if len(completion_inputs) == 1:
            raise KeyboardInterrupt("interrupt completion tail")
        return MagicMock(run_dir=kwargs["run_dir"], scenarios=[])

    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner._complete_v3_run",
            side_effect=interrupt_then_capture,
        )
    )

    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args)
        run_dir = next(args["output_dir"].iterdir())
        resume_pipeline(run_dir)

    fresh, resumed = completion_inputs
    fresh_events = [event.to_dict() for event in fresh["stage_ledger"].events]
    resumed_events = [event.to_dict() for event in resumed["stage_ledger"].events]
    assert resumed_events == fresh_events
    assert resumed["projection_limitation_target_ids"] == {limited_target}
    rejection = next(
        event for event in resumed_events if event["reason"] == "no_projection"
    )
    assert rejection["candidate_id"] == rejected_id

    fresh_gaps, fresh_summary = emit_quality_gaps(
        fresh["coverage_universe"],
        fresh["stage_ledger"],
        fresh["selection_result"],
        fresh["fallback_queues"],
        projection_limitation_target_ids=fresh["projection_limitation_target_ids"],
    )
    resumed_gaps, resumed_summary = emit_quality_gaps(
        resumed["coverage_universe"],
        resumed["stage_ledger"],
        resumed["selection_result"],
        resumed["fallback_queues"],
        projection_limitation_target_ids=resumed["projection_limitation_target_ids"],
    )
    assert resumed_summary.to_dict() == fresh_summary.to_dict()
    assert [gap.to_dict() for gap in resumed_gaps] == [
        gap.to_dict() for gap in fresh_gaps
    ]
    projection_gap = next(
        gap
        for gap in fresh_summary.structural_gaps
        if gap["reason"] == "projection_rejection"
    )
    assert projection_gap["candidate_ids"] == [rejected_id]
    assert fresh_summary.projection_limitations[0]["reason"] == "projection_limitation"


def test_failed_run_inventories_published_planning_checkpoint(tmp_path: Path) -> None:
    from asago_scenario_generator.manifest import ManifestInventoryResolver

    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.run_target_finalization",
            side_effect=RuntimeError("finalization failed after planning checkpoint"),
        )
    )

    with stack, pytest.raises(RuntimeError, match="finalization failed"):
        run_pipeline(**args)

    run_dir = next(args["output_dir"].iterdir())
    manifest = load_manifest(run_dir)
    assert manifest.status is RunStatus.FAILED
    assert any(
        item.role is ArtifactRole.PLANNING_CHECKPOINT for item in manifest.inventory
    )
    ManifestInventoryResolver(run_dir, manifest, check_orphans=True)


@pytest.mark.parametrize(
    ("fault_boundary", "expected_support"),
    [
        ("after_use_case", {ArtifactRole.USE_CASE}),
        (
            "after_threat_surface",
            {
                ArtifactRole.USE_CASE,
                ArtifactRole.CAPABILITY_PROFILE,
                ArtifactRole.THREAT_SURFACE,
            },
        ),
        (
            "before_started_support_manifest",
            {
                ArtifactRole.USE_CASE,
                ArtifactRole.CAPABILITY_PROFILE,
                ArtifactRole.THREAT_SURFACE,
                ArtifactRole.PLANNING_CHECKPOINT,
            },
        ),
    ],
)
def test_early_failed_v3_inventories_unpublished_support_without_orphans(
    tmp_path: Path,
    fault_boundary: str,
    expected_support: set[ArtifactRole],
) -> None:
    from asago_scenario_generator.manifest import ManifestInventoryResolver

    projected = get_projected_candidate()
    stack, patches, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    if fault_boundary == "after_use_case":
        stack.enter_context(
            patch(
                "asago_scenario_generator.pipeline.runner.infer_capability_profile",
                side_effect=RuntimeError(fault_boundary),
            )
        )
    elif fault_boundary == "after_threat_surface":
        patches["expand_seeds"].side_effect = RuntimeError(fault_boundary)
    else:
        stack.enter_context(
            patch(
                "asago_scenario_generator.pipeline.runner.write_started_manifest",
                side_effect=RuntimeError(fault_boundary),
            )
        )

    with stack, pytest.raises(RuntimeError, match=fault_boundary):
        run_pipeline(**args)

    run_dir = next(args["output_dir"].iterdir())
    manifest = load_manifest(run_dir)
    assert manifest.status is RunStatus.FAILED
    roles = {item.role for item in manifest.inventory}
    assert expected_support <= roles
    ManifestInventoryResolver(run_dir, manifest, check_orphans=True)


@pytest.mark.parametrize(
    ("retry_owner", "expected_calls"),
    [
        ("actor", (2, 2, 2, 2)),
        ("narrative", (1, 2, 2, 2)),
        ("tree", (1, 1, 2, 2)),
    ],
)
def test_public_resume_reuses_only_causal_frontier_after_owner_retry(
    tmp_path: Path,
    retry_owner: str,
    expected_calls: tuple[int, int, int, int],
) -> None:
    from asago_scenario_generator.pipeline.finalization import (
        AdmissionDecision,
        GeneratedStage,
    )
    from asago_scenario_generator.pipeline.finalization_admission import (
        PostbehaviorAdmissionReport,
    )
    from asago_scenario_generator.pipeline.finalization_gates import (
        AdmissionEvidenceId,
        GateCode,
        GateResult,
        GateViolation,
    )
    from asago_scenario_generator.pipeline.persistence import (
        FinalizationPersistenceAdapter,
    )
    from asago_scenario_generator.pipeline.runner_finalization import (
        make_postbehavior_admission as real_admission_factory,
    )

    owner = GeneratedStage(retry_owner)

    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    envelope = _make_valid_envelope()
    envelope.attack_tree.root.threat_id = "T1"
    envelope.behavior_spec = _phase3b_behavior(projected, envelope.attack_tree)
    llm_result = LLMResult(
        content="mock",
        prompt_tokens=0,
        completion_tokens=0,
        duration_ms=0,
        system_prompt="mock",
        user_prompt="mock",
    )

    def evidence(call: CallName) -> StageCallEvidence:
        return StageCallEvidence(
            call,
            llm_result,
            CallMetadata(
                call=call, prompt_tokens=0, completion_tokens=0, duration_ms=0
            ),
        )

    actor = stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_actor_stage",
            return_value=ActorStageResult(
                envelope.actor_profile, evidence(CallName.actor_profile)
            ),
        )
    )
    narrative = stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_narrative_stage",
            return_value=NarrativeStageResult(
                envelope.narrative, evidence(CallName.narrative)
            ),
        )
    )
    tree = stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.generate_tree_stage",
            return_value=TreeStageResult(
                envelope.attack_tree, evidence(CallName.attack_tree)
            ),
        )
    )
    behavior = stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.generate.stages.generate_behavior_stage",
            return_value=BehaviorStageResult(
                envelope.behavior_spec, evidence(CallName.behavior_spec)
            ),
        )
    )
    routed = False

    def admission_factory(*factory_args, **factory_kwargs):
        admitted = real_admission_factory(*factory_args, **factory_kwargs)

        def route_once(candidate, artifacts, snapshot):
            nonlocal routed
            if not routed:
                routed = True
                gate_violation = GateViolation(
                    GateCode.actor_access,
                    f"retry {owner.value} from durable admission evidence",
                    owner,
                )
                violation = gate_violation.lifecycle()
                return AdmissionDecision(
                    False,
                    (violation,),
                    value=PostbehaviorAdmissionReport(
                        envelope=None,
                        gate_results=(
                            GateResult(
                                AdmissionEvidenceId.semantic_validity,
                                (gate_violation,),
                            ),
                        ),
                    ),
                )
            return admitted(candidate, artifacts, snapshot)

        return route_once

    stack.enter_context(
        patch(
            "asago_scenario_generator.pipeline.runner_finalization.make_postbehavior_admission",
            side_effect=admission_factory,
        )
    )
    original_record = FinalizationPersistenceAdapter.record_stage_result
    crashed = False

    def crash_after_retry_commit(self, invocation, result):
        nonlocal crashed
        original_record(self, invocation, result)
        if (
            not crashed
            and invocation.stage is owner
            and invocation.invocation_index == 1
        ):
            crashed = True
            raise KeyboardInterrupt(f"crash after durable {owner.value} retry")

    stack.enter_context(
        patch.object(
            FinalizationPersistenceAdapter,
            "record_stage_result",
            new=crash_after_retry_commit,
        )
    )
    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args)
        run_dir = next(args["output_dir"].iterdir())
        resume_pipeline(run_dir)

    assert (
        actor.call_count,
        narrative.call_count,
        tree.call_count,
        behavior.call_count,
    ) == expected_calls
    inventory = read_finalization_inventory(run_dir)
    assert inventory.admission_decisions[-1].admitted is True
    owner_retry = next(
        item
        for item in inventory.stage_attempts
        if item.stage is owner and item.invocation_index == 1
    )
    downstream = tuple(GeneratedStage)[tuple(GeneratedStage).index(owner) + 1]
    resumed_downstream = next(
        item
        for item in inventory.stage_attempts
        if item.stage is downstream and item.invocation_index == 1
    )
    assert resumed_downstream.input.visible_artifacts[owner.value] == owner_retry.result


def _run_and_get_coverage_report(tmp_path: Path, *, confirmed: bool) -> dict:
    """Run the pipeline with a mocked profile and return coverage-gaps.json."""
    import json

    from asago_scenario_generator.models.capability_profile import InventoryCompleteness

    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )

    # Patch the profile's entry_point_completeness after _arrange sets it up.
    if confirmed:
        # Need to find the profile in the patches and set confirmed.
        # _arrange patches infer_capability_profile; we re-patch it.
        from asago_scenario_generator.models.capability_profile import (
            InventoryCompleteness,
        )
        from tests.helpers.projection_factory import get_test_profile

        profile = get_test_profile()
        profile.entry_point_completeness = (
            InventoryCompleteness.operator_confirmed_complete
        )
        profile.entry_point_evidence = ["operator-review:test-evidence"]

        infer_mock = stack.enter_context(
            __import__(
                "unittest.mock",
                fromlist=["patch"],
            ).patch("asago_scenario_generator.pipeline.runner.infer_capability_profile")
        )
        from asago_scenario_generator.pipeline.projection import (
            capture_capability_snapshot,
        )

        stack.enter_context(
            patch(
                "asago_scenario_generator.pipeline.runner.capture_capability_snapshot",
                return_value=capture_capability_snapshot(profile),
            )
        )
        from asago_scenario_generator.llm.client import LLMResult

        llm_result = LLMResult(
            content="mock",
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
            system_prompt="mock",
            user_prompt="mock",
        )
        infer_mock.return_value = (profile, llm_result)

    with stack:
        result = run_pipeline(**args)

    report_path = result.run_dir / "coverage-gaps.json"
    return json.loads(report_path.read_text(encoding="utf-8"))


class TestRunnerProfileCompletenessDerivation:
    """cmps.4 blocker 4: runner must derive completeness from profile, not
    free-form input.  An inferred profile cannot claim confirmed by passing
    an enum."""

    def test_inferred_profile_reports_not_applicable(self, tmp_path: Path) -> None:
        report = _run_and_get_coverage_report(tmp_path, confirmed=False)
        universe = report.get("coverage_universe", {})
        assert universe["completeness"] == "not_applicable"
        plan = report.get("coverage_plan", {})
        assert plan["completeness"] == "not_applicable"

    def test_confirmed_profile_reports_confirmed_complete_with_refs(
        self, tmp_path: Path
    ) -> None:
        report = _run_and_get_coverage_report(tmp_path, confirmed=True)
        universe = report.get("coverage_universe", {})
        assert universe["completeness"] == "confirmed_complete"
        assert "operator-review:test-evidence" in universe.get("evidence_refs", [])
        plan = report.get("coverage_plan", {})
        assert plan["completeness"] == "confirmed_complete"
        assert "operator-review:test-evidence" in plan.get("evidence_refs", [])

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import jsonschema
import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.catalog_qualification import (
    CampaignManifestV1,
    ForensicHistoryEntry,
    ForensicRunRef,
    ProfilePreflight,
    QualificationReportV1,
    QualificationRunRef,
    ReviewedProfile,
    ReviewedProfileMatrixV1,
    _CANONICAL_PROFILE_IDS,
    _canonical_run_manifest_path_problem,
    _campaign_missing_pattern_ids,
    _campaign_preflight,
    _has_dot_component,
    _is_unsafe_path_form,
    _matrix_profile_ids,
    _report_reviewed_ids,
    _validate_campaign_contract,
    _validate_canonical_profile_order,
    _validate_disjoint_pattern_ownership,
    _validate_missing_pattern_ids,
    _validate_preflight_contract,
    _fact_key,
    _infeasibilities_for,
    _preflight_inputs,
    _profile_fact_readiness,
    _project_preflight_profile,
    _projected_candidates_for,
    _required_fact_keys,
    _unknown_fact_keys,
    _validate_forensic_keys,
    _validate_forensic_paths,
    _validate_forensic_profiles,
    _validate_matrix_partition,
    _validate_preflight_catalog_pin,
    _validate_preflight_matrix_pin,
    _require_known_profile,
    _validate_campaign_pins,
    _parse_pinned_run_manifest,
    _read_pinned_run_manifest,
    _validate_run_authority,
    _validate_ref_sets_disjoint,
    _validate_report_forensic_history,
    _validate_report_kind_contract,
    _validate_report_profile_order,
    _validate_report_qualified,
    _validate_report_reviewed_universe,
    _validate_sorted_unique_ref_keys,
    _validate_unique_ref_paths,
    aggregate_campaign,
    load_matrix,
    preflight_matrix,
    validate_persisted_contract,
)
from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.eval.versioned_metrics import evaluate_v3_scorecard
from asago_scenario_generator.manifest import ArtifactRole, ManifestIntegrityError
from asago_scenario_generator.models.attack_pattern import EvaluatedFactEvidence
from asago_scenario_generator.pipeline.projection import (
    ProjectionBudget,
    capture_capability_snapshot,
    compute_authoritative_catalog_pin,
    project_authoritative_candidates,
)

ROOT = Path(__file__).parents[1]
MATRIX = ROOT / "data/catalog-qualification-matrix-v1.yaml"
SCHEMAS = ROOT / "src/asago_scenario_generator/data/schemas"


def test_live_matrix_preflight_reports_full_deterministic_readiness() -> None:
    report = preflight_matrix(MATRIX)
    assert report.kind == "preflight"
    assert report.campaign_manifest_sha256 is None
    assert report.catalog_denominator == 49
    assert (
        report.catalog_sha256
        == "fc825827d32ed17f3b11409171c9d368248c99510431856ead98e44248a084f2"
    )
    assert report.missing_pattern_ids == ()
    assert sum(len(item.projected_pattern_ids) for item in report.preflight) == 49


def test_precondition_true_false_and_omitted_unknown_fail_closed() -> None:
    matrix = load_matrix(MATRIX)
    reviewed = next(
        item for item in matrix.profiles if "AP-T3-05" in item.applicable_pattern_ids
    )
    record = load_attack_patterns()["AP-T3-05"]
    resolver = load_taxonomy_resolver()
    fact = next(
        item
        for item in reviewed.facts
        if item.fact.fact_id == "control_interface_accessible"
    )

    true_batch = project_authoritative_candidates(
        [record], resolver, capture_capability_snapshot(reviewed.profile, [fact])
    )
    assert {item.pattern_id for item in true_batch.candidates} == {"AP-T3-05"}

    false_fact = EvaluatedFactEvidence(fact=fact.fact, status="present", value=False)
    false_batch = project_authoritative_candidates(
        [record], resolver, capture_capability_snapshot(reviewed.profile, [false_fact])
    )
    assert not false_batch.candidates
    assert false_batch.infeasibilities[0].code == "precondition_not_satisfied"

    unknown_batch = project_authoritative_candidates(
        [record], resolver, capture_capability_snapshot(reviewed.profile)
    )
    assert not unknown_batch.candidates
    assert unknown_batch.infeasibilities[0].code == "unresolved_condition"


def test_campaign_refs_are_immutable_duplicate_and_path_safe() -> None:
    sha = "a" * 64
    first = QualificationRunRef(
        profile_id="direct-conversational",
        run_manifest_path="runs/one/run-manifest.yaml",
        manifest_sha256=sha,
    )
    duplicate_path = QualificationRunRef(
        profile_id="state-changing-tools",
        run_manifest_path=first.run_manifest_path,
        manifest_sha256=sha,
    )
    with pytest.raises(ValidationError, match="paths must be unique"):
        CampaignManifestV1(
            catalog_sha256=sha,
            catalog_denominator=49,
            matrix_sha256=sha,
            qualification_runs=(first, duplicate_path),
        )
    with pytest.raises(ValidationError, match="must be separate"):
        CampaignManifestV1(
            catalog_sha256=sha,
            catalog_denominator=49,
            matrix_sha256=sha,
            qualification_runs=(first,),
            forensic_runs=(
                ForensicRunRef.model_validate(first.model_dump(mode="json")),
            ),
        )
    with pytest.raises(ValidationError, match="canonical, safe, relative"):
        QualificationRunRef(
            profile_id="direct-conversational",
            run_manifest_path="../escaped/run-manifest.yaml",
            manifest_sha256=sha,
        )
    with pytest.raises(ValidationError, match="frozen"):
        first.profile_id = "mutated"  # type: ignore[misc]


def test_campaign_keeps_strict_failed_run_as_forensic_only(tmp_path: Path) -> None:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_bytes(MATRIX.read_bytes())
    preflight = preflight_matrix(matrix)
    run_dir = tmp_path / "runs" / "forensic"
    run_dir.mkdir(parents=True)
    manifest_path = run_dir / "run-manifest.yaml"
    manifest_path.write_text(
        yaml.safe_dump(
            {
                "manifest_version": "3",
                "status": "failed",
                "run_id": "20260807T000000_" + "a" * 32,
                "timestamp_start": "2026-08-07T00:00:00Z",
                "inventory": [],
            },
            sort_keys=False,
        )
    )
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    campaign_path = tmp_path / "campaign.yaml"
    campaign = CampaignManifestV1(
        catalog_sha256=preflight.catalog_sha256,
        catalog_denominator=preflight.catalog_denominator,
        matrix_sha256=preflight.matrix_sha256,
        forensic_runs=(
            ForensicRunRef(
                profile_id="direct-conversational",
                run_manifest_path="runs/forensic/run-manifest.yaml",
                manifest_sha256=manifest_sha,
            ),
        ),
    )
    campaign_path.write_text(
        yaml.safe_dump(campaign.model_dump(mode="json"), sort_keys=False)
    )

    report = aggregate_campaign(matrix, campaign_path)
    assert report.qualified_pattern_ids == ()
    assert len(report.missing_pattern_ids) == 49
    assert report.forensic_history[0].status == "failed"

    forged = campaign.model_copy(
        update={
            "forensic_runs": (),
            "qualification_runs": (
                QualificationRunRef.model_validate(
                    campaign.forensic_runs[0].model_dump(mode="json")
                ),
            ),
        }
    )
    campaign_path.write_text(
        yaml.safe_dump(forged.model_dump(mode="json"), sort_keys=False)
    )
    with pytest.raises(ManifestIntegrityError, match="not authoritative"):
        aggregate_campaign(matrix, campaign_path)


def test_standalone_contract_validation_does_not_run_preflight(tmp_path: Path) -> None:
    matrix = validate_persisted_contract(MATRIX, "matrix")
    assert isinstance(matrix, ReviewedProfileMatrixV1)
    report_path = tmp_path / "report.json"
    report_path.write_text(preflight_matrix(MATRIX).model_dump_json())
    report = validate_persisted_contract(report_path, "report")
    assert isinstance(report, QualificationReportV1)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda raw: raw["preflight"].reverse(), "six canonical profiles"),
        (
            lambda raw: raw["preflight"][0]["reviewed_pattern_ids"].append(
                raw["preflight"][0]["reviewed_pattern_ids"][0]
            ),
            "sorted and unique",
        ),
        (
            lambda raw: raw["preflight"][0]["projected_pattern_ids"].append(
                "AP-NOT-REVIEWED"
            ),
            "sorted and unique|must be reviewed",
        ),
        (
            lambda raw: raw.update(missing_pattern_ids=["AP-NOT-MISSING"]),
            "report kind",
        ),
        (
            lambda raw: raw.update(
                kind="campaign",
                campaign_manifest_sha256="a" * 64,
                qualified_pattern_ids=["AP-NOT-PROJECTED"],
            ),
            "must be projected",
        ),
    ],
)
def test_standalone_report_rejects_adversarial_accounting(
    mutation, message: str
) -> None:
    raw = preflight_matrix(MATRIX).model_dump(mode="json")
    mutation(raw)
    with pytest.raises(ValidationError, match=message):
        QualificationReportV1.model_validate(raw)


def test_qualification_yaml_rejects_duplicate_facts_key(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-facts.yaml"
    path.write_text(
        "schema_version: '1'\n"
        f"catalog_sha256: {'a' * 64}\n"
        "catalog_denominator: 1\n"
        "profiles:\n"
        "  - facts: []\n"
        "    facts: []\n"
    )
    with pytest.raises(ValueError, match="duplicate YAML key: facts"):
        load_matrix(path)


def test_campaign_rejects_internally_valid_forged_scorecard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_versioned_scorecard import _Resolver

    matrix = tmp_path / "matrix.yaml"
    matrix.write_bytes(MATRIX.read_bytes())
    preflight = preflight_matrix(matrix)
    canonical = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
    forged_raw = canonical.model_dump(mode="json")
    diagnostic = next(
        iter(forged_raw["semantic_quality_diagnostics"]["metrics"].values())
    )
    diagnostic["evidence"].append("forged but internally non-gating evidence")
    forged = type(canonical).model_validate(forged_raw)
    assert forged != canonical

    entries = {
        role: SimpleNamespace(role=role)
        for role in (
            "eval_scorecard",
            "finalization_inventory",
            "capability_profile",
            "coverage_plan",
        )
    }

    class ForgedResolver:
        def entry_by_role(self, role):
            return entries.get(role.value)

        def read_text(self, entry):
            assert entry.role == "eval_scorecard"
            return yaml.safe_dump(forged.model_dump(mode="json"), sort_keys=False)

    monkeypatch.setattr(
        "asago_scenario_generator.catalog_qualification._resolve_campaign_run",
        lambda *_args, **_kwargs: ForgedResolver(),
    )
    monkeypatch.setattr(
        "asago_scenario_generator.catalog_qualification.evaluate_v3_scorecard",
        lambda _resolver: canonical,
    )
    campaign = CampaignManifestV1(
        catalog_sha256=preflight.catalog_sha256,
        catalog_denominator=preflight.catalog_denominator,
        matrix_sha256=preflight.matrix_sha256,
        qualification_runs=(
            QualificationRunRef(
                profile_id="direct-conversational",
                run_manifest_path="runs/forged/run-manifest.yaml",
                manifest_sha256="a" * 64,
            ),
        ),
    )
    campaign_path = tmp_path / "campaign.yaml"
    campaign_path.write_text(
        yaml.safe_dump(campaign.model_dump(mode="json"), sort_keys=False)
    )

    with pytest.raises(ValueError, match="canonical resolver evaluation"):
        aggregate_campaign(matrix, campaign_path)


def test_completed_v3_campaign_with_nonempty_facts_qualifies_one_pattern(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import patch

    from asago_scenario_generator.eval.scorecard import (
        MetricResult,
        QUALIFICATION_GATE_PATHS,
        QUALIFICATION_RATIO_GATE_IDS,
        REQUIRED_QUALIFICATION_GATE_IDS,
        ScorecardV1,
        aggregate_qualification,
        ratio_metric,
        zero_gate,
    )
    from asago_scenario_generator.manifest import RunStatus, load_manifest
    from asago_scenario_generator.models.attack_pattern import AttackPattern
    from asago_scenario_generator.models.capability_profile import InventoryCompleteness
    from asago_scenario_generator.pipeline.projection import capture_capability_snapshot
    from asago_scenario_generator.pipeline.runner import run_pipeline
    from tests.helpers.projection_factory import (
        _pattern,
        _TaxonomyResolver,
        get_projected_candidate,
        get_test_profile,
        get_test_snapshot,
    )
    from tests.test_projection_runner_integration import _arrange

    projected = get_projected_candidate()
    stack, patches, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    profile = get_test_profile()
    profile.entry_point_completeness = InventoryCompleteness.operator_confirmed_complete
    profile.entry_point_evidence = ["operator-review:campaign-fixture"]
    profile.tool_inventory_completeness = (
        InventoryCompleteness.operator_confirmed_complete
    )
    profile.tool_inventory_evidence = ["operator-review:campaign-fixture"]
    patches["infer_capability_profile"].return_value = (
        profile,
        patches["infer_capability_profile"].return_value[1],
    )
    patches["capture_capability_snapshot"].return_value = capture_capability_snapshot(
        profile, get_test_snapshot().facts
    )
    facts_path = tmp_path / "qualification-facts.yaml"
    facts_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "facts": [
                    item.model_dump(mode="json") for item in get_test_snapshot().facts
                ],
            },
            sort_keys=False,
        )
    )

    def qualifying_evaluation(*, resolver, threats_path=None):
        raw = evaluate_v3_scorecard(resolver).model_dump(mode="json")
        for gate_id, (section, metric_id) in QUALIFICATION_GATE_PATHS.items():
            metric = (
                ratio_metric(1, 1, evidence=["campaign fixture qualifying evidence"])
                if gate_id in QUALIFICATION_RATIO_GATE_IDS
                else zero_gate(0, evidence=["campaign fixture qualifying evidence"])
            )
            raw[section]["metrics"][metric_id] = metric.model_dump(mode="json")
        gates = {
            gate_id: MetricResult.model_validate(raw[section]["metrics"][metric_id])
            for gate_id, (section, metric_id) in QUALIFICATION_GATE_PATHS.items()
        }
        raw["qualification"] = aggregate_qualification(
            gates, required_gate_ids=REQUIRED_QUALIFICATION_GATE_IDS
        ).model_dump(mode="json")
        return ScorecardV1.model_validate(raw).model_dump(mode="json")

    stack.enter_context(
        patch(
            "asago_scenario_generator.eval.runner.run_evaluation",
            side_effect=qualifying_evaluation,
        )
    )
    with stack:
        result = run_pipeline(**args, qualification_facts_path=facts_path)

    assert load_manifest(result.run_dir).status is RunStatus.COMPLETED
    run_manifest = result.run_dir / "run-manifest.yaml"
    manifest_sha = hashlib.sha256(run_manifest.read_bytes()).hexdigest()
    profile_ids = (
        "direct-conversational",
        "influenceable-retrieval",
        "multi-agent-delegation",
        "state-changing-tools",
        "training-tool-supply-chain",
        "writable-persistent-state",
    )
    pattern_ids = (
        projected.pattern_id,
        "AP-X-02",
        "AP-X-03",
        "AP-X-04",
        "AP-X-05",
        "AP-X-06",
    )
    reviewed_profiles = tuple(
        ReviewedProfile(
            profile_id=profile_id,
            rationale="resolver-valid campaign fixture",
            profile=profile,
            facts=get_test_snapshot().facts,
            applicable_pattern_ids=(pattern_id,),
        )
        for profile_id, pattern_id in zip(profile_ids, pattern_ids, strict=True)
    )
    matrix = ReviewedProfileMatrixV1(
        catalog_sha256=projected.projection.catalog_pin,
        catalog_denominator=len(pattern_ids),
        profiles=reviewed_profiles,
    )
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text(
        yaml.safe_dump(matrix.model_dump(mode="json"), sort_keys=False)
    )
    matrix_sha = hashlib.sha256(matrix_path.read_bytes()).hexdigest()
    preflight = QualificationReportV1(
        kind="preflight",
        catalog_sha256=matrix.catalog_sha256,
        catalog_denominator=matrix.catalog_denominator,
        matrix_sha256=matrix_sha,
        preflight=tuple(
            ProfilePreflight(
                profile_id=item.profile_id,
                reviewed_pattern_ids=item.applicable_pattern_ids,
                projected_pattern_ids=item.applicable_pattern_ids,
                missing_pattern_ids=(),
                issues=(),
            )
            for item in reviewed_profiles
        ),
        missing_pattern_ids=(),
    )
    campaign = CampaignManifestV1(
        catalog_sha256=matrix.catalog_sha256,
        catalog_denominator=matrix.catalog_denominator,
        matrix_sha256=matrix_sha,
        qualification_runs=(
            QualificationRunRef(
                profile_id=profile_ids[0],
                run_manifest_path=f"runs/{result.run_id}/run-manifest.yaml",
                manifest_sha256=manifest_sha,
            ),
        ),
    )
    campaign_path = tmp_path / "campaign.yaml"
    campaign_path.write_text(
        yaml.safe_dump(campaign.model_dump(mode="json"), sort_keys=False)
    )
    record = _pattern()
    records = [
        record,
        *({**record, "id": pattern_id} for pattern_id in pattern_ids[1:]),
    ]
    taxonomy = _TaxonomyResolver(
        AttackPattern.model_validate(record).canonical_chain.taxonomy_context
    )
    monkeypatch.setattr(
        "asago_scenario_generator.catalog_qualification.load_attack_patterns",
        lambda: {record["id"]: record for record in records},
    )
    monkeypatch.setattr(
        "asago_scenario_generator.catalog_qualification.load_taxonomy_resolver",
        lambda: taxonomy,
    )
    monkeypatch.setattr(
        "asago_scenario_generator.catalog_qualification.compute_authoritative_catalog_pin",
        lambda *_args: matrix.catalog_sha256,
    )
    monkeypatch.setattr(
        "asago_scenario_generator.catalog_qualification._preflight_matrix",
        lambda *_args, **_kwargs: preflight,
    )
    monkeypatch.setattr(
        "asago_scenario_generator.catalog_qualification.evaluate_v3_scorecard",
        lambda resolver: ScorecardV1.model_validate(
            resolver.read_yaml(resolver.entry_by_role(ArtifactRole.EVAL_SCORECARD))
        ),
    )
    report = aggregate_campaign(matrix_path, campaign_path)
    assert report.kind == "campaign"
    assert (
        report.campaign_manifest_sha256
        == hashlib.sha256(campaign_path.read_bytes()).hexdigest()
    )
    assert report.qualified_pattern_ids == (projected.pattern_id,)
    assert get_test_snapshot().facts


def test_checked_in_schemas_have_exact_parity_and_validate_matrix() -> None:
    contracts = (
        (ReviewedProfileMatrixV1, "catalog-qualification-matrix-v1.schema.json"),
        (CampaignManifestV1, "catalog-qualification-campaign-v1.schema.json"),
        (QualificationReportV1, "catalog-qualification-report-v1.schema.json"),
    )
    for model, filename in contracts:
        checked_in = json.loads((SCHEMAS / filename).read_text())
        assert checked_in == model.model_json_schema()
        jsonschema.Draft202012Validator.check_schema(checked_in)
    raw = yaml.safe_load(MATRIX.read_bytes())
    jsonschema.validate(raw, ReviewedProfileMatrixV1.model_json_schema())


class TestCanonicalRunManifestPath:
    """Branch-level unit coverage for the shared run-manifest path checks."""

    @pytest.mark.parametrize(
        ("value", "problem"),
        [
            ("run-manifest.yaml", None),
            ("runs/one/run-manifest.yaml", None),
            ("a/b/c/run-manifest.yaml", None),
            ("/runs/one/run-manifest.yaml", "must be relative and canonical"),
            ("runs//one/run-manifest.yaml", "must be relative and canonical"),
            ("runs\\one\\run-manifest.yaml", "must be relative and canonical"),
            ("runs/./one/run-manifest.yaml", "must be relative and canonical"),
            ("runs/../one/run-manifest.yaml", "must not contain dot components"),
            ("runs/one/manifest.yaml", "must end in run-manifest.yaml"),
        ],
    )
    def test_problem_detection(self, value: str, problem: str | None) -> None:
        assert _canonical_run_manifest_path_problem(value) == problem

    def test_unsafe_form_predicate(self) -> None:
        assert _is_unsafe_path_form(PurePosixPath("/abs/x.yaml"), "/abs/x.yaml")
        assert _is_unsafe_path_form(PurePosixPath("a//b.yaml"), "a//b.yaml")
        assert _is_unsafe_path_form(PurePosixPath("a\\b.yaml"), "a\\b.yaml")
        assert not _is_unsafe_path_form(PurePosixPath("a/b.yaml"), "a/b.yaml")

    def test_dot_component_predicate(self) -> None:
        assert _has_dot_component(PurePosixPath("a/../b.yaml"))
        assert not _has_dot_component(PurePosixPath("a/b.yaml"))

    def test_validators_accept_canonical_and_reject_unsafe(self) -> None:
        sha = "a" * 64
        ref = QualificationRunRef(
            profile_id="direct-conversational",
            run_manifest_path="runs/one/run-manifest.yaml",
            manifest_sha256=sha,
        )
        assert ref.run_manifest_path == "runs/one/run-manifest.yaml"
        history = ForensicHistoryEntry(
            profile_id="direct-conversational",
            path="runs/one/run-manifest.yaml",
            status="failed",
        )
        assert history.path == "runs/one/run-manifest.yaml"
        for value in (
            "/runs/one/run-manifest.yaml",
            "runs//one/run-manifest.yaml",
            "runs\\one\\run-manifest.yaml",
            "runs/./one/run-manifest.yaml",
            "runs/../one/run-manifest.yaml",
            "runs/one/manifest.yaml",
        ):
            with pytest.raises(ValidationError):
                QualificationRunRef(
                    profile_id="direct-conversational",
                    run_manifest_path=value,
                    manifest_sha256=sha,
                )
            with pytest.raises(ValidationError):
                ForensicHistoryEntry(
                    profile_id="direct-conversational",
                    path=value,
                    status="failed",
                )


def _fake_profile(profile_id: str, pattern_ids: tuple[str, ...] = ("p1",)):
    """A lightweight ReviewedProfile stand-in for unit-level helper tests."""
    return SimpleNamespace(
        profile_id=profile_id, applicable_pattern_ids=pattern_ids
    )


def _fake_run_ref(profile_id: str, path: str) -> SimpleNamespace:
    return SimpleNamespace(profile_id=profile_id, run_manifest_path=path)


def _fake_forensic(profile_id: str, path: str, status: str = "failed") -> SimpleNamespace:
    return SimpleNamespace(profile_id=profile_id, path=path, status=status)


class TestReviewedProfileMatrixValidation:
    """Branch-level coverage for the matrix validation helpers."""

    def test_matrix_profile_ids_preserves_order(self) -> None:
        profiles = [_fake_profile(pid) for pid in _CANONICAL_PROFILE_IDS]
        assert _matrix_profile_ids(profiles) == _CANONICAL_PROFILE_IDS

    def test_canonical_order_accepts_canonical_ids(self) -> None:
        _validate_canonical_profile_order(
            [_fake_profile(pid) for pid in _CANONICAL_PROFILE_IDS]
        )

    def test_canonical_order_rejects_permuted_ids(self) -> None:
        with pytest.raises(ValueError, match="six canonical"):
            _validate_canonical_profile_order(
                [_fake_profile(pid) for pid in _CANONICAL_PROFILE_IDS[::-1]]
            )

    def test_disjoint_ownership_accepts_disjoint_assignments(self) -> None:
        _validate_disjoint_pattern_ownership(
            [_fake_profile("a", ("p1", "p2")), _fake_profile("b", ("p3",))]
        )

    def test_disjoint_ownership_rejects_overlapping_assignments(self) -> None:
        with pytest.raises(ValueError, match="disjoint"):
            _validate_disjoint_pattern_ownership(
                [_fake_profile("a", ("p1",)), _fake_profile("b", ("p1",))]
            )


class TestCampaignRefValidation:
    """Branch-level coverage for the campaign reference helpers."""

    def test_sorted_unique_keys_accepts_sorted_unique(self) -> None:
        refs = (
            _fake_run_ref("a", "runs/1/run-manifest.yaml"),
            _fake_run_ref("b", "runs/2/run-manifest.yaml"),
        )
        _validate_sorted_unique_ref_keys(refs, "qualification_runs")

    def test_sorted_unique_keys_rejects_duplicate_keys(self) -> None:
        refs = (
            _fake_run_ref("a", "runs/1/run-manifest.yaml"),
            _fake_run_ref("a", "runs/1/run-manifest.yaml"),
        )
        with pytest.raises(ValueError, match="sorted and duplicate-free"):
            _validate_sorted_unique_ref_keys(refs, "qualification_runs")

    def test_sorted_unique_keys_rejects_unsorted_keys(self) -> None:
        refs = (
            _fake_run_ref("b", "runs/2/run-manifest.yaml"),
            _fake_run_ref("a", "runs/1/run-manifest.yaml"),
        )
        with pytest.raises(ValueError, match="sorted and duplicate-free"):
            _validate_sorted_unique_ref_keys(refs, "forensic_runs")

    def test_unique_paths_accepts_distinct_paths(self) -> None:
        refs = (
            _fake_run_ref("a", "runs/1/run-manifest.yaml"),
            _fake_run_ref("b", "runs/2/run-manifest.yaml"),
        )
        _validate_unique_ref_paths(refs, "qualification")

    def test_unique_paths_rejects_repeated_path(self) -> None:
        refs = (
            _fake_run_ref("a", "runs/1/run-manifest.yaml"),
            _fake_run_ref("b", "runs/1/run-manifest.yaml"),
        )
        with pytest.raises(ValueError, match="paths must be unique"):
            _validate_unique_ref_paths(refs, "forensic")

    def test_ref_sets_disjoint_accepts_separate_paths(self) -> None:
        _validate_ref_sets_disjoint({"runs/1/run-manifest.yaml"}, {"runs/2/run-manifest.yaml"})

    def test_ref_sets_disjoint_rejects_shared_path(self) -> None:
        with pytest.raises(ValueError, match="must be separate"):
            _validate_ref_sets_disjoint(
                {"runs/1/run-manifest.yaml"}, {"runs/1/run-manifest.yaml"}
            )


class TestQualificationReportValidation:
    """Branch-level coverage for the report validation helpers."""

    def test_report_reviewed_ids_flattens_profiles(self) -> None:
        preflight = (
            SimpleNamespace(reviewed_pattern_ids=("p1", "p2")),
            SimpleNamespace(reviewed_pattern_ids=("p3",)),
        )
        assert _report_reviewed_ids(preflight) == ["p1", "p2", "p3"]

    def test_report_profile_order_accepts_canonical(self) -> None:
        _validate_report_profile_order(
            tuple(_fake_profile(pid) for pid in _CANONICAL_PROFILE_IDS)
        )

    def test_report_profile_order_rejects_permuted(self) -> None:
        with pytest.raises(ValueError, match="six canonical"):
            _validate_report_profile_order(
                tuple(_fake_profile(pid) for pid in _CANONICAL_PROFILE_IDS[::-1])
            )

    def test_reviewed_universe_accepts_full_disjoint_universe(self) -> None:
        _validate_report_reviewed_universe(["p1", "p2", "p3"], 3)

    def test_reviewed_universe_rejects_duplicate_ownership(self) -> None:
        with pytest.raises(ValueError, match="ownership must be disjoint"):
            _validate_report_reviewed_universe(["p1", "p1"], 2)

    def test_reviewed_universe_rejects_denominator_mismatch(self) -> None:
        with pytest.raises(ValueError, match="catalog denominator"):
            _validate_report_reviewed_universe(["p1", "p2"], 3)

    def test_qualified_subset_accepts_projected(self) -> None:
        _validate_report_qualified({"p1", "p2"}, {"p1"})

    def test_qualified_equal_projected_accepts(self) -> None:
        _validate_report_qualified({"p1"}, {"p1"})

    def test_qualified_subset_rejects_unprojected(self) -> None:
        with pytest.raises(ValueError, match="must be projected"):
            _validate_report_qualified({"p1"}, {"p2"})

    def test_forensic_history_accepts_canonical_entries(self) -> None:
        history = (
            _fake_forensic("direct-conversational", "runs/1/run-manifest.yaml"),
            _fake_forensic("writable-persistent-state", "runs/2/run-manifest.yaml"),
        )
        _validate_report_forensic_history(history)

    def test_forensic_history_rejects_duplicate_keys(self) -> None:
        history = (
            _fake_forensic("direct-conversational", "runs/1/run-manifest.yaml"),
            _fake_forensic("direct-conversational", "runs/1/run-manifest.yaml"),
        )
        with pytest.raises(ValueError, match="canonical and unique"):
            _validate_report_forensic_history(history)

    def test_forensic_history_rejects_duplicate_paths(self) -> None:
        history = (
            _fake_forensic("direct-conversational", "runs/1/run-manifest.yaml"),
            _fake_forensic("writable-persistent-state", "runs/1/run-manifest.yaml"),
        )
        with pytest.raises(ValueError, match="paths must be unique"):
            _validate_report_forensic_history(history)

    def test_forensic_history_rejects_non_canonical_profile(self) -> None:
        history = (_fake_forensic("not-canonical", "runs/1/run-manifest.yaml"),)
        with pytest.raises(ValueError, match="profile_id is not canonical"):
            _validate_report_forensic_history(history)

    def test_preflight_contract_accepts_clean_preflight(self) -> None:
        _validate_preflight_contract(None, set(), ())

    def test_preflight_contract_rejects_bound_manifest(self) -> None:
        with pytest.raises(ValueError, match="cannot bind a campaign manifest"):
            _validate_preflight_contract("a" * 64, set(), ())

    def test_preflight_contract_rejects_campaign_results(self) -> None:
        with pytest.raises(ValueError, match="cannot contain campaign results"):
            _validate_preflight_contract(None, {"p1"}, ())
        with pytest.raises(ValueError, match="cannot contain campaign results"):
            _validate_preflight_contract(
                None, set(), (_fake_forensic("direct-conversational", "runs/1/run-manifest.yaml"),)
            )

    def test_campaign_contract_accepts_bound_manifest(self) -> None:
        _validate_campaign_contract("a" * 64)

    def test_campaign_contract_rejects_missing_manifest(self) -> None:
        with pytest.raises(ValueError, match="requires campaign manifest"):
            _validate_campaign_contract(None)

    def test_missing_pattern_ids_match(self) -> None:
        _validate_missing_pattern_ids({"p2"}, {"p2"})
        with pytest.raises(ValueError, match="report kind"):
            _validate_missing_pattern_ids({"p1"}, {"p2"})

    def test_kind_contract_preflight(self) -> None:
        _validate_report_kind_contract(
            "preflight", None, set(), (), {"p1", "p2"}, {"p1"}, {"p2"}
        )
        with pytest.raises(ValueError, match="report kind"):
            _validate_report_kind_contract(
                "preflight", None, set(), (), {"p1"}, {"p1"}, {"p2"}
            )

    def test_kind_contract_campaign(self) -> None:
        _validate_report_kind_contract(
            "campaign", "a" * 64, {"p1"}, (), {"p1", "p2"}, {"p1"}, {"p2"}
        )
        with pytest.raises(ValueError, match="report kind"):
            _validate_report_kind_contract(
                "campaign", "a" * 64, {"p1"}, (), {"p1", "p2"}, {"p1"}, {"p1"}
            )


class TestCampaignRunResolution:
    """Branch-level coverage for the pinned run resolution helpers."""

    @staticmethod
    def _write_run(tmp_path: Path, rel: str, content: str) -> Path:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    @staticmethod
    def _ref(rel: str, content: bytes) -> QualificationRunRef:
        return QualificationRunRef(
            profile_id="direct-conversational",
            run_manifest_path=rel,
            manifest_sha256=hashlib.sha256(content).hexdigest(),
        )

    def test_read_pinned_manifest_accepts_distinct_matching_file(
        self, tmp_path: Path
    ) -> None:
        path = self._write_run(
            tmp_path, "runs/one/run-manifest.yaml", "manifest_version: '3'\n"
        )
        content = path.read_bytes()
        assert _read_pinned_run_manifest(tmp_path, self._ref("runs/one/run-manifest.yaml", content), set()) == content

    def test_read_pinned_manifest_rejects_referenced_physical_duplicate(
        self, tmp_path: Path
    ) -> None:
        path = self._write_run(
            tmp_path, "runs/one/run-manifest.yaml", "manifest_version: '3'\n"
        )
        content = path.read_bytes()
        from asago_scenario_generator.catalog_qualification import _safe_relative_read

        _, physical_id = _safe_relative_read(tmp_path, "runs/one/run-manifest.yaml")
        with pytest.raises(ValueError, match="distinct physical files"):
            _read_pinned_run_manifest(tmp_path, self._ref("runs/one/run-manifest.yaml", content), {physical_id})

    def test_read_pinned_manifest_rejects_hash_mismatch(self, tmp_path: Path) -> None:
        path = self._write_run(
            tmp_path, "runs/one/run-manifest.yaml", "manifest_version: '3'\n"
        )
        content = path.read_bytes()
        ref = self._ref("runs/one/run-manifest.yaml", content)
        ref = ref.model_copy(update={"manifest_sha256": "b" * 64})
        with pytest.raises(ValueError, match="manifest hash mismatch"):
            _read_pinned_run_manifest(tmp_path, ref, set())

    def test_parse_pinned_manifest_accepts_v3_final(self) -> None:
        content = (
            "manifest_version: '3'\n"
            "status: failed\n"
            "run_id: 20260807T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "timestamp_start: '2026-08-07T00:00:00Z'\n"
        ).encode()
        from asago_scenario_generator.catalog_qualification import _parse_pinned_run_manifest

        manifest = _parse_pinned_run_manifest(
            content,
            QualificationRunRef(
                profile_id="direct-conversational",
                run_manifest_path="runs/one/run-manifest.yaml",
                manifest_sha256="a" * 64,
            ),
        )
        assert manifest.manifest_version == "3"

    def test_parse_pinned_manifest_rejects_invalid_yaml(self) -> None:
        from asago_scenario_generator.catalog_qualification import _parse_pinned_run_manifest

        with pytest.raises(ManifestIntegrityError, match="invalid pinned run manifest"):
            _parse_pinned_run_manifest(
                b"manifest_version: '3'\n",  # missing run_id/timestamp_start
                QualificationRunRef(
                    profile_id="direct-conversational",
                    run_manifest_path="runs/one/run-manifest.yaml",
                    manifest_sha256="a" * 64,
                ),
            )

    def test_parse_pinned_manifest_rejects_v2(self) -> None:
        from asago_scenario_generator.catalog_qualification import _parse_pinned_run_manifest

        with pytest.raises(ManifestIntegrityError, match="requires manifest v3"):
            _parse_pinned_run_manifest(
                (
                    "manifest_version: '2'\n"
                    "run_id: 20260807T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                    "timestamp_start: '2026-08-07T00:00:00Z'\n"
                ).encode(),
                QualificationRunRef(
                    profile_id="direct-conversational",
                    run_manifest_path="runs/one/run-manifest.yaml",
                    manifest_sha256="a" * 64,
                ),
            )

    def test_parse_pinned_manifest_rejects_non_final_status(self) -> None:
        from asago_scenario_generator.catalog_qualification import _parse_pinned_run_manifest

        with pytest.raises(ManifestIntegrityError, match="requires a final run"):
            _parse_pinned_run_manifest(
                (
                    "manifest_version: '3'\n"
                    "status: started\n"
                    "run_id: 20260807T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                    "timestamp_start: '2026-08-07T00:00:00Z'\n"
                ).encode(),
                QualificationRunRef(
                    profile_id="direct-conversational",
                    run_manifest_path="runs/one/run-manifest.yaml",
                    manifest_sha256="a" * 64,
                ),
            )

    @staticmethod
    def _final_manifest(status: str) -> RunManifest:
        from asago_scenario_generator.manifest import RunManifest, RunStatus

        return RunManifest(
            status=RunStatus(status),
            run_id="20260807T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            timestamp_start="2026-08-07T00:00:00Z",
        )

    def test_validate_authority_accepts_authoritative_completed(self) -> None:
        from asago_scenario_generator.catalog_qualification import _validate_run_authority

        _validate_run_authority(self._final_manifest("completed"), authoritative=True)

    def test_validate_authority_rejects_non_completed_authoritative(self) -> None:
        from asago_scenario_generator.catalog_qualification import _validate_run_authority

        with pytest.raises(ManifestIntegrityError, match="not authoritative"):
            _validate_run_authority(self._final_manifest("failed"), authoritative=True)

    def test_validate_authority_accepts_non_authoritative_failed(self) -> None:
        from asago_scenario_generator.catalog_qualification import _validate_run_authority

        _validate_run_authority(self._final_manifest("failed"), authoritative=False)

    def test_validate_authority_rejects_completed_as_forensic(self) -> None:
        from asago_scenario_generator.catalog_qualification import _validate_run_authority

        with pytest.raises(ManifestIntegrityError, match="belong in qualification_runs"):
            _validate_run_authority(self._final_manifest("completed"), authoritative=False)


class TestPreflightMatrixHelpers:
    """Branch-level coverage for the preflight decomposition helpers."""

    def test_preflight_inputs_uses_explicit_values(self) -> None:
        catalog = {"p1": {"id": "p1"}}
        resolver = object()
        pin = "a" * 64
        out_catalog, out_records, out_resolver, out_pin = _preflight_inputs(
            catalog, resolver, pin
        )
        assert out_catalog is catalog
        assert out_records == [{"id": "p1"}]
        assert out_resolver is resolver
        assert out_pin == pin

    def test_preflight_inputs_loads_live_defaults(self) -> None:
        catalog, records, resolver, pin = _preflight_inputs(None, None, None)
        live_catalog = load_attack_patterns()
        assert catalog == live_catalog
        assert records == list(live_catalog.values())
        assert pin == compute_authoritative_catalog_pin(records, resolver)

    def test_validate_matrix_pin_accepts_live_pin(self) -> None:
        matrix = load_matrix(MATRIX)
        catalog = load_attack_patterns()
        records = list(catalog.values())
        pin = compute_authoritative_catalog_pin(records, load_taxonomy_resolver())
        _validate_preflight_matrix_pin(matrix, catalog, pin)
        with pytest.raises(ValueError, match="does not match the live"):
            _validate_preflight_matrix_pin(matrix, catalog, "b" * 64)

    def test_validate_matrix_partition_accepts_exact_partition(self) -> None:
        catalog = {"p1": {}, "p2": {}}
        matrix = SimpleNamespace(
            profiles=(SimpleNamespace(applicable_pattern_ids=("p1", "p2")),)
        )
        _validate_matrix_partition(matrix, catalog)

    def test_validate_matrix_partition_rejects_uncovered_pattern(self) -> None:
        catalog = {"p1": {}, "p2": {}, "p3": {}}
        matrix = SimpleNamespace(
            profiles=(SimpleNamespace(applicable_pattern_ids=("p1", "p2")),)
        )
        with pytest.raises(ValueError, match="exact disjoint reviewed partition"):
            _validate_matrix_partition(matrix, catalog)

    def test_validate_matrix_partition_rejects_duplicate_pattern(self) -> None:
        catalog = {"p1": {}, "p2": {}}
        matrix = SimpleNamespace(
            profiles=(SimpleNamespace(applicable_pattern_ids=("p1", "p1")),)
        )
        with pytest.raises(ValueError, match="exact disjoint reviewed partition"):
            _validate_matrix_partition(matrix, catalog)

    def test_profile_fact_readiness_accepts_matrix_profiles(self) -> None:
        matrix = load_matrix(MATRIX)
        catalog = load_attack_patterns()
        for profile in matrix.profiles:
            _profile_fact_readiness(profile, catalog)

    def test_profile_fact_readiness_rejects_missing_facts(self) -> None:
        matrix = load_matrix(MATRIX)
        catalog = load_attack_patterns()
        profile = matrix.profiles[0]
        stripped = ReviewedProfile(
            profile_id=profile.profile_id,
            rationale=profile.rationale,
            profile=profile.profile,
            facts=(),
            applicable_pattern_ids=profile.applicable_pattern_ids,
        )
        with pytest.raises(ValueError, match="must provide known explicit readings"):
            _profile_fact_readiness(stripped, catalog)

    def test_profile_fact_readiness_rejects_unknown_facts(self) -> None:
        matrix = load_matrix(MATRIX)
        catalog = load_attack_patterns()
        profile = matrix.profiles[0]
        records = [catalog[pid] for pid in profile.applicable_pattern_ids]
        required = _required_fact_keys(records)
        target = next(
            item
            for item in profile.facts
            if _fact_key(item.fact.model_dump(mode="json")) in required
        )
        unknown = EvaluatedFactEvidence(fact=target.fact, status="unknown")
        rebuilt = ReviewedProfile(
            profile_id=profile.profile_id,
            rationale=profile.rationale,
            profile=profile.profile,
            facts=tuple(unknown if item is target else item for item in profile.facts),
            applicable_pattern_ids=profile.applicable_pattern_ids,
        )
        with pytest.raises(ValueError, match="unknown="):
            _profile_fact_readiness(rebuilt, catalog)

    def test_project_preflight_profile_matches_live_preflight(self) -> None:
        matrix = load_matrix(MATRIX)
        catalog = load_attack_patterns()
        records = list(catalog.values())
        resolver = load_taxonomy_resolver()
        pin = compute_authoritative_catalog_pin(records, resolver)
        profile = matrix.profiles[0]
        result = _project_preflight_profile(profile, records, resolver, pin)
        assert result.profile_id == profile.profile_id
        assert result.reviewed_pattern_ids == profile.applicable_pattern_ids
        assert set(result.projected_pattern_ids) == set(profile.applicable_pattern_ids)
        assert result.missing_pattern_ids == ()
        assert result.issues == ()

    def test_project_preflight_profile_rejects_wrong_catalog_pin(self) -> None:
        matrix = load_matrix(MATRIX)
        catalog = load_attack_patterns()
        records = list(catalog.values())
        resolver = load_taxonomy_resolver()
        with pytest.raises(ValueError, match="full catalog pin"):
            _project_preflight_profile(matrix.profiles[0], records, resolver, "b" * 64)

    def test_unknown_fact_keys_detects_unknown_readings(self) -> None:
        matrix = load_matrix(MATRIX)
        catalog = load_attack_patterns()
        profile = matrix.profiles[0]
        records = [catalog[pid] for pid in profile.applicable_pattern_ids]
        required = _required_fact_keys(records)
        actual = {
            _fact_key(item.fact.model_dump(mode="json")): item
            for item in profile.facts
        }
        assert _unknown_fact_keys(required, actual) == []
        target = next(
            item
            for item in profile.facts
            if _fact_key(item.fact.model_dump(mode="json")) in required
        )
        unknown = EvaluatedFactEvidence(fact=target.fact, status="unknown")
        actual_with_unknown = dict(actual)
        actual_with_unknown[_fact_key(target.fact.model_dump(mode="json"))] = unknown
        assert _unknown_fact_keys(required, actual_with_unknown) == [
            _fact_key(target.fact.model_dump(mode="json"))
        ]

    def test_fact_key_is_independent_of_mapping_order(self) -> None:
        assert _fact_key({"a": 1, "b": 2}) == _fact_key({"b": 2, "a": 1})

    def test_projected_candidates_scoped_to_profile(self) -> None:
        matrix = load_matrix(MATRIX)
        catalog = load_attack_patterns()
        records = list(catalog.values())
        resolver = load_taxonomy_resolver()
        pin = compute_authoritative_catalog_pin(records, resolver)
        profile = matrix.profiles[0]
        batch = project_authoritative_candidates(
            records,
            resolver,
            profile.snapshot(),
            budget=ProjectionBudget(max_candidates=4096, max_derivation_work=65536),
        )
        scoped = _projected_candidates_for(batch, profile)
        assert scoped
        assert all(
            item.pattern_id in profile.applicable_pattern_ids for item in scoped
        )

    def test_validate_preflight_catalog_pin(self) -> None:
        good = SimpleNamespace(projection=SimpleNamespace(catalog_pin="a" * 64))
        bad = SimpleNamespace(projection=SimpleNamespace(catalog_pin="b" * 64))
        _validate_preflight_catalog_pin((good,), "a" * 64)
        with pytest.raises(ValueError, match="full catalog pin"):
            _validate_preflight_catalog_pin((good, bad), "a" * 64)

    def test_infeasibilities_scoped_to_profile(self) -> None:
        matrix = load_matrix(MATRIX)
        catalog = load_attack_patterns()
        records = list(catalog.values())
        resolver = load_taxonomy_resolver()
        profile = matrix.profiles[0]
        batch = project_authoritative_candidates(
            records,
            resolver,
            profile.snapshot(),
            budget=ProjectionBudget(max_candidates=4096, max_derivation_work=65536),
        )
        assert _infeasibilities_for(batch, profile) == ()

    def test_forensic_key_path_profile_helpers(self) -> None:
        good = (
            _fake_forensic("direct-conversational", "runs/1/run-manifest.yaml"),
            _fake_forensic("writable-persistent-state", "runs/2/run-manifest.yaml"),
        )
        _validate_forensic_keys(good)
        _validate_forensic_paths(good)
        _validate_forensic_profiles(good)
        duplicate_key = (
            _fake_forensic("direct-conversational", "runs/1/run-manifest.yaml"),
            _fake_forensic("direct-conversational", "runs/1/run-manifest.yaml"),
        )
        with pytest.raises(ValueError, match="canonical and unique"):
            _validate_forensic_keys(duplicate_key)
        duplicate_path = (
            _fake_forensic("direct-conversational", "runs/1/run-manifest.yaml"),
            _fake_forensic("writable-persistent-state", "runs/1/run-manifest.yaml"),
        )
        with pytest.raises(ValueError, match="paths must be unique"):
            _validate_forensic_paths(duplicate_path)
        with pytest.raises(ValueError, match="profile_id is not canonical"):
            _validate_forensic_profiles(
                (_fake_forensic("not-canonical", "runs/1/run-manifest.yaml"),)
            )


class TestAggregateCampaignHelpers:
    """Branch-level coverage for the campaign aggregation helpers."""

    def test_campaign_preflight_loads_live_preflight(self) -> None:
        matrix, preflight, records, resolver = _campaign_preflight(MATRIX.read_bytes())
        assert matrix.catalog_sha256 == preflight.catalog_sha256
        assert preflight.kind == "preflight"
        assert preflight.missing_pattern_ids == ()
        assert len(records) == 49
        assert resolver is not None

    def test_validate_campaign_pins(self) -> None:
        sha = "a" * 64
        campaign = SimpleNamespace(
            catalog_sha256=sha, catalog_denominator=49, matrix_sha256=sha
        )
        preflight = SimpleNamespace(
            catalog_sha256=sha, catalog_denominator=49, matrix_sha256=sha
        )
        _validate_campaign_pins(campaign, preflight)
        with pytest.raises(ValueError, match="campaign pins do not match"):
            _validate_campaign_pins(
                campaign, SimpleNamespace(catalog_sha256="b" * 64, catalog_denominator=49, matrix_sha256=sha)
            )

    def test_require_known_profile(self) -> None:
        profiles = {"direct-conversational": object()}
        known = SimpleNamespace(profile_id="direct-conversational")
        _require_known_profile(known, profiles)
        with pytest.raises(ValueError, match="unknown matrix profile_id"):
            _require_known_profile(SimpleNamespace(profile_id="nope"), profiles)

    def test_require_qualification_entries(self) -> None:
        from asago_scenario_generator.catalog_qualification import _require_qualification_entries

        entries = {
            role: SimpleNamespace(role=role)
            for role in (
                "eval_scorecard",
                "finalization_inventory",
                "capability_profile",
                "coverage_plan",
            )
        }

        class FullResolver:
            def entry_by_role(self, role):
                return entries.get(role.value)

        score, final, profile, plan = _require_qualification_entries(FullResolver())
        assert {score.role, final.role, profile.role, plan.role} == {
            "eval_scorecard",
            "finalization_inventory",
            "capability_profile",
            "coverage_plan",
        }

        class MissingResolver:
            def entry_by_role(self, role):
                if role.value == "coverage_plan":
                    return None
                return entries.get(role.value)

        with pytest.raises(ValueError, match="lacks profile, plan, scorecard"):
            _require_qualification_entries(MissingResolver())

    def test_validate_scorecard_equivalence_and_gates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from asago_scenario_generator.catalog_qualification import (
            _validate_scorecard_equivalence,
            _validate_scorecard_gates,
        )
        from tests.test_versioned_scorecard import _Resolver

        canonical = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
        text = yaml.safe_dump(canonical.model_dump(mode="json"), sort_keys=False)

        class FixedResolver:
            def read_text(self, entry):
                return text

        # Forged scorecard differs from the canonical resolver evaluation.
        forged_raw = canonical.model_dump(mode="json")
        diagnostic = next(
            iter(forged_raw["semantic_quality_diagnostics"]["metrics"].values())
        )
        diagnostic["evidence"].append("forged but internally non-gating evidence")
        forged = type(canonical).model_validate(forged_raw)
        assert forged != canonical

        monkeypatch.setattr(
            "asago_scenario_generator.catalog_qualification.evaluate_v3_scorecard",
            lambda _resolver: canonical,
        )

        class ForgedResolver:
            def read_text(self, entry):
                return yaml.safe_dump(forged.model_dump(mode="json"), sort_keys=False)

        with pytest.raises(ValueError, match="canonical resolver evaluation"):
            _validate_scorecard_equivalence(ForgedResolver(), SimpleNamespace())

        # Passing scorecard equals the canonical evaluation.
        passing = SimpleNamespace(
            qualification=SimpleNamespace(status=SimpleNamespace(value="pass"))
        )
        monkeypatch.setattr(
            "asago_scenario_generator.catalog_qualification.evaluate_v3_scorecard",
            lambda _resolver: passing,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.catalog_qualification.ScorecardV1",
            SimpleNamespace(model_validate=lambda *_a, **_k: passing),
        )
        assert (
            _validate_scorecard_equivalence(FixedResolver(), SimpleNamespace())
            is passing
        )

        # A non-passing overall qualification is rejected.
        failing = SimpleNamespace(
            qualification=SimpleNamespace(status=SimpleNamespace(value="fail"))
        )
        monkeypatch.setattr(
            "asago_scenario_generator.catalog_qualification.evaluate_v3_scorecard",
            lambda _resolver: failing,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.catalog_qualification.ScorecardV1",
            SimpleNamespace(model_validate=lambda *_a, **_k: failing),
        )
        with pytest.raises(ValueError, match="does not pass canonical gates"):
            _validate_scorecard_equivalence(FixedResolver(), SimpleNamespace())

        monkeypatch.setattr(
            "asago_scenario_generator.catalog_qualification.scorecard_qualification_gates",
            lambda _score: {"g1": SimpleNamespace(status=SimpleNamespace(value="fail"))},
        )
        with pytest.raises(ValueError, match="non-passing strict category gates"):
            _validate_scorecard_gates(SimpleNamespace())

    def test_validate_finalization_clean(self) -> None:
        from asago_scenario_generator.catalog_qualification import (
            _validate_finalization_clean,
        )

        clean = SimpleNamespace(
            quarantine_inventory=[],
            admission_decisions=[SimpleNamespace(admitted=True)],
        )
        _validate_finalization_clean(clean)
        with pytest.raises(ValueError, match="quarantine or non-admitted"):
            _validate_finalization_clean(
                SimpleNamespace(
                    quarantine_inventory=[object()],
                    admission_decisions=[SimpleNamespace(admitted=True)],
                )
            )
        with pytest.raises(ValueError, match="quarantine or non-admitted"):
            _validate_finalization_clean(
                SimpleNamespace(
                    quarantine_inventory=[],
                    admission_decisions=[SimpleNamespace(admitted=False)],
                )
            )

    def test_validate_run_profile_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from asago_scenario_generator.catalog_qualification import (
            _validate_run_profile_match,
        )
        from tests.helpers.projection_factory import get_test_profile

        profile = get_test_profile()
        expected = SimpleNamespace(profile=profile)

        class Resolver:
            def read_text(self, entry):
                return yaml.safe_dump(
                    profile.model_dump(mode="json"), sort_keys=False
                )

        monkeypatch.setattr(
            "asago_scenario_generator.catalog_qualification.load_yaml_strict",
            lambda content: yaml.safe_load(content),
        )
        _validate_run_profile_match(Resolver(), SimpleNamespace(), expected)

        different = profile.model_copy(
            update={
                "entry_point_evidence": [
                    *profile.entry_point_evidence,
                    "extra-differentiating-evidence",
                ]
            }
        )

        class DifferentResolver:
            def read_text(self, entry):
                return yaml.safe_dump(
                    different.model_dump(mode="json"), sort_keys=False
                )

        with pytest.raises(ValueError, match="does not match matrix profile"):
            _validate_run_profile_match(DifferentResolver(), SimpleNamespace(), expected)

    def test_plan_choices_indexes_ordered_choices(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from asago_scenario_generator.catalog_qualification import _plan_choices

        plan = SimpleNamespace(
            targets=[
                SimpleNamespace(
                    ordered_choices=[
                        SimpleNamespace(candidate_id="c1"),
                        SimpleNamespace(candidate_id="c2"),
                    ]
                ),
                SimpleNamespace(
                    ordered_choices=[SimpleNamespace(candidate_id="c3")]
                ),
            ]
        )

        class Resolver:
            def read_text(self, entry):
                return ""

        monkeypatch.setattr(
            "asago_scenario_generator.catalog_qualification.CoveragePlanV2",
            SimpleNamespace(model_validate_json=lambda text: plan),
        )
        choices = _plan_choices(Resolver(), SimpleNamespace())
        assert sorted(choices) == ["c1", "c2", "c3"]

    def test_scenario_for_entry_parses_verified_bytes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from asago_scenario_generator.catalog_qualification import _scenario_for_entry

        calls = []

        class FakeEnvelope:
            @classmethod
            def model_validate(cls, data):
                calls.append(data)
                return data

        monkeypatch.setattr(
            "asago_scenario_generator.catalog_qualification.ScenarioEnvelope",
            FakeEnvelope,
        )
        monkeypatch.setattr(
            "asago_scenario_generator.catalog_qualification.load_yaml_strict",
            lambda content: {"parsed": True},
        )

        class Resolver:
            def read_text(self, entry):
                return "yaml"

        assert _scenario_for_entry(Resolver(), SimpleNamespace()) == {"parsed": True}
        assert calls == [{"parsed": True}]

    def test_scenario_scope_helpers(self) -> None:
        from asago_scenario_generator.catalog_qualification import (
            _scenario_choice,
            _validate_scenario_pattern,
            _validate_scenario_reprojection,
            _validate_scenario_snapshot,
            _revalidated_identity_matches,
            _revalidated_ingress_matches,
            _revalidated_requirements_match,
        )

        snapshot = object()
        block = SimpleNamespace(
            capability_snapshot=snapshot,
            projection=SimpleNamespace(
                catalog_pin="catalog-pin",
                source_chain=SimpleNamespace(pattern_id="AP-1"),
            ),
            canonical_ingress="ingress",
            ingress_controllability="controllability",
            projected_mappings={"m": "1"},
            execution_requirements={"r": "1"},
            requirement_derivation_version="v1",
            execution_requirements_digest="digest",
        )
        expected = SimpleNamespace(
            snapshot=lambda: snapshot,
            applicable_pattern_ids=("AP-1", "AP-2"),
        )
        campaign = SimpleNamespace(catalog_sha256="catalog-pin")
        _validate_scenario_snapshot(block, expected)
        with pytest.raises(ValueError, match="capability snapshot does not match"):
            _validate_scenario_snapshot(
                SimpleNamespace(capability_snapshot=object()), expected
            )
        assert (
            _validate_scenario_pattern(
                block, campaign, expected, "p1", {"p1": {"AP-1", "AP-2"}}
            )
            == "AP-1"
        )
        wrong_pin = SimpleNamespace(
            projection=SimpleNamespace(
                catalog_pin="other", source_chain=SimpleNamespace(pattern_id="AP-1")
            )
        )
        with pytest.raises(ValueError, match="catalog pin does not match campaign"):
            _validate_scenario_pattern(wrong_pin, campaign, expected, "p1", {"p1": set()})
        unreviewed = SimpleNamespace(
            projection=SimpleNamespace(
                catalog_pin="catalog-pin",
                source_chain=SimpleNamespace(pattern_id="AP-9"),
            )
        )
        with pytest.raises(ValueError, match="not reviewed for its matrix profile"):
            _validate_scenario_pattern(unreviewed, campaign, expected, "p1", {"p1": set()})
        with pytest.raises(ValueError, match="no valid deterministic matrix projection"):
            _validate_scenario_pattern(block, campaign, expected, "p1", {"p1": set()})

        scenario = SimpleNamespace(candidate_id="c1")
        _scenario_choice(scenario, {"c1": "choice"}) == "choice"
        with pytest.raises(ValueError, match="absent from coverage plan"):
            _scenario_choice(scenario, {})

        matching = SimpleNamespace(
            candidate_id="c1",
            projection=block.projection,
            canonical_ingress="ingress",
            ingress_controllability="controllability",
            projected_mappings={"m": "1"},
            execution_requirements={"r": "1"},
            requirement_derivation_version="v1",
            execution_requirements_digest="digest",
        )
        _validate_scenario_reprojection(matching, scenario, block)
        _revalidated_identity_matches(matching, scenario, block)
        _revalidated_ingress_matches(matching, block)
        _revalidated_requirements_match(matching, block)
        mismatched = matching.model_copy() if hasattr(matching, "model_copy") else SimpleNamespace(**{**matching.__dict__})
        mismatched.candidate_id = "other"
        with pytest.raises(ValueError, match="does not match authoritative plan"):
            _validate_scenario_reprojection(mismatched, scenario, block)

    def test_validate_run_scenarios_empty_inventory(self) -> None:
        from asago_scenario_generator.catalog_qualification import (
            _validate_run_scenarios,
        )

        class EmptyResolver:
            def entries_by_role(self, role):
                return []

        result = _validate_run_scenarios(
            EmptyResolver(),
            SimpleNamespace(),
            "p1",
            {},
            SimpleNamespace(),
            {},
            None,
            [],
        )
        assert result == set()

    def test_campaign_missing_pattern_ids(self) -> None:
        matrix = SimpleNamespace(
            profiles=(
                SimpleNamespace(applicable_pattern_ids=("AP-1", "AP-2")),
                SimpleNamespace(applicable_pattern_ids=("AP-3",)),
            )
        )
        assert _campaign_missing_pattern_ids(matrix, {"AP-1"}) == ("AP-2", "AP-3")
        assert _campaign_missing_pattern_ids(matrix, {"AP-1", "AP-2", "AP-3"}) == ()

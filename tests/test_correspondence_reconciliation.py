"""Unit tests for correspondence reconciliation logic."""

from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from asago_scenario_generator.cli import app
from asago_scenario_generator.models.correspondence import (
    AdjudicationHistoryItem,
    CorrespondenceProposal,
    ReconciledProposal,
)
from asago_scenario_generator.models.system_resource_map import (
    LossLinkEntry,
    ResourceMapSnapshot,
    SystemResourceEntry,
    SystemResourceMap,
)
from asago_scenario_generator.pipeline.correspondence import reconcile_correspondence
from tests.helpers.correspondence_factory import make_test_resource_map

runner = CliRunner()


def test_reconciliation_retains_confirmed_rejected_unresolved() -> None:
    srm = make_test_resource_map()
    proposals = [
        CorrespondenceProposal(
            proposal_id="P-1",
            left_ref="CA-1-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type="supports",
            evidence_source="exact-id",
            strength="high",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
        CorrespondenceProposal(
            proposal_id="P-2",
            left_ref="L-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type="addresses",
            evidence_source="curated-map",
            strength="high",
            evidence_refs=["L-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
        CorrespondenceProposal(
            proposal_id="P-3",
            left_ref="CA-1-1",
            right_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            relation_type="overlaps",
            evidence_source="resource-overlap",
            strength="weak",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
    ]
    adjudications = {
        "P-1": "confirmed",
        "P-2": "rejected",
        "P-3": "unresolved",
    }

    result = reconcile_correspondence(srm, proposals, adjudications=adjudications)
    assert result.is_valid is True
    assert len(result.proposals) == 3

    p1 = next(p for p in result.proposals if p.proposal_id == "P-1")
    assert p1.adjudication == "confirmed"
    assert p1.relation_type == "supports"
    assert p1.strength == "high"

    p2 = next(p for p in result.proposals if p.proposal_id == "P-2")
    assert p2.adjudication == "rejected"
    assert p2.relation_type == "addresses"

    p3 = next(p for p in result.proposals if p.proposal_id == "P-3")
    assert p3.adjudication == "unresolved"
    assert p3.relation_type == "overlaps"


def test_reconciliation_separates_relation_type_strength_and_adjudication() -> None:
    srm = make_test_resource_map()
    proposals = [
        CorrespondenceProposal(
            proposal_id="P-1",
            left_ref="CA-1-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type="supports",
            evidence_source="exact-id",
            strength="high",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
        CorrespondenceProposal(
            proposal_id="P-4",
            left_ref="CA-1-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type="contradicts",
            evidence_source="exact-id",
            strength="high",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
        CorrespondenceProposal(
            proposal_id="P-3",
            left_ref="CA-1-1",
            right_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            relation_type="overlaps",
            evidence_source="resource-overlap",
            strength="weak",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
    ]

    res = reconcile_correspondence(srm, proposals, adjudications={"P-1": "confirmed"})
    p1 = next(p for p in res.proposals if p.proposal_id == "P-1")
    assert p1.relation_type != p1.strength
    assert p1.relation_type != p1.adjudication


def test_reconciliation_preserves_conflicting_proposals_as_unresolved() -> None:
    srm = make_test_resource_map()
    prop_a = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    prop_b = CorrespondenceProposal(
        proposal_id="P-4",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="contradicts",
        evidence_source="exact-id",
        strength="high",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )

    # Presentation order 1: P-1, P-4
    res1 = reconcile_correspondence(
        srm, [prop_a, prop_b], adjudications={"P-1": "confirmed", "P-4": "confirmed"}
    )
    assert len(res1.proposals) == 2
    for p in res1.proposals:
        assert p.adjudication == "unresolved"
        assert p.conflict_reason == "conflict"

    # Presentation order 2: P-4, P-1
    res2 = reconcile_correspondence(
        srm, [prop_b, prop_a], adjudications={"P-1": "confirmed", "P-4": "confirmed"}
    )
    assert len(res2.proposals) == 2
    for p in res2.proposals:
        assert p.adjudication == "unresolved"
        assert p.conflict_reason == "conflict"


def test_single_agreeing_proposals_are_not_conflicts() -> None:
    srm = make_test_resource_map()

    def make(prop_id: str, relation_type: str) -> CorrespondenceProposal:
        return CorrespondenceProposal(
            proposal_id=prop_id,
            left_ref="CA-1-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type=relation_type,
            evidence_source="exact-id",
            strength="high",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        )

    # A lone contradicting proposal disagrees with no one: it is unresolved
    # by default, not conflict-marked.
    solo = reconcile_correspondence(srm, [make("P-1", "contradicts")])
    p1 = solo.proposals[0]
    assert p1.adjudication == "unresolved"
    assert p1.conflict_reason is None
    assert p1.adjudication_history[0].reason is None

    # Two proposals agreeing on the same pair are also not a conflict.
    pair = reconcile_correspondence(
        srm, [make("P-1", "supports"), make("P-2", "supports")]
    )
    for p in pair.proposals:
        assert p.conflict_reason is None
        assert p.adjudication_history[0].reason is None


def test_conflicting_relation_types_mark_the_pair_as_conflict() -> None:
    srm = make_test_resource_map()

    def make(prop_id: str, relation_type: str) -> CorrespondenceProposal:
        return CorrespondenceProposal(
            proposal_id=prop_id,
            left_ref="CA-1-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type=relation_type,
            evidence_source="exact-id",
            strength="high",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        )

    res = reconcile_correspondence(
        srm, [make("P-1", "supports"), make("P-2", "overlaps")]
    )
    for p in res.proposals:
        assert p.adjudication == "unresolved"
        assert p.conflict_reason == "conflict"
        assert p.adjudication_history[0].reason == "conflict"


def test_confirmation_records_confirmed_reason_in_history() -> None:
    srm = make_test_resource_map()
    proposal = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )

    res = reconcile_correspondence(srm, [proposal], adjudications={"P-1": "confirmed"})
    p1 = res.proposals[0]
    assert res.is_valid is True
    assert p1.adjudication == "confirmed"
    assert len(p1.adjudication_history) == 1
    assert p1.adjudication_history[0].adjudication == "confirmed"
    assert p1.adjudication_history[0].reason == "confirmed"
    assert res.network_calls == 0
    assert res.model_calls == 0


def test_reconciliation_of_carried_history_is_idempotent() -> None:
    srm = make_test_resource_map()
    # A reconciled proposal whose history already ends in the target
    # adjudication must not grow a duplicate entry on re-reconciliation.
    carried = ReconciledProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        adjudication="rejected",
        adjudication_history=[
            AdjudicationHistoryItem(adjudication="confirmed", reason="confirmed"),
            AdjudicationHistoryItem(adjudication="rejected", reason=None),
        ],
    )

    res = reconcile_correspondence(srm, [carried], adjudications={"P-1": "rejected"})
    p1 = res.proposals[0]
    assert p1.adjudication == "rejected"
    assert len(p1.adjudication_history) == 2
    assert [item.adjudication for item in p1.adjudication_history] == [
        "confirmed",
        "rejected",
    ]


def test_confirmation_requires_explicit_evidence() -> None:
    srm = make_test_resource_map()

    def make(
        prop_id: str, evidence_source: str, refs: list[str]
    ) -> CorrespondenceProposal:
        return CorrespondenceProposal(
            proposal_id=prop_id,
            left_ref="CA-1-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type="supports",
            evidence_source=evidence_source,
            strength="high",
            evidence_refs=refs,
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        )

    # Evidence-free sources are never confirmable.
    res = reconcile_correspondence(
        srm,
        [make("P-1", "none", ["CA-1-1"])],
        adjudications={"P-1": "confirmed"},
    )
    assert res.is_valid is False
    assert any(
        e.error_code == "evidence_required" and e.proposal_id == "P-1"
        for e in res.errors
    )
    assert res.proposals[0].adjudication == "unresolved"

    # So are confirmable sources with no evidence refs.
    res2 = reconcile_correspondence(
        srm,
        [make("P-2", "exact-id", [])],
        adjudications={"P-2": "confirmed"},
    )
    assert res2.is_valid is False
    assert any(
        e.error_code == "evidence_required" and e.proposal_id == "P-2"
        for e in res2.errors
    )


def test_reconciliation_rejects_confirmation_defects() -> None:
    srm = make_test_resource_map()

    # 1. Dangling left ref
    p_dangling_left = CorrespondenceProposal(
        proposal_id="P-9",
        left_ref="NON-EXISTENT",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        evidence_refs=["NON-EXISTENT"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    res1 = reconcile_correspondence(
        srm, [p_dangling_left], adjudications={"P-9": "confirmed"}
    )
    assert res1.is_valid is False
    assert any(
        e.error_code == "dangling_reference" and e.proposal_id == "P-9"
        for e in res1.errors
    )

    # 2. Dangling right ref
    p_dangling_right = CorrespondenceProposal(
        proposal_id="P-9",
        left_ref="CA-1-1",
        right_ref="NON-EXISTENT-TAXONOMY",
        relation_type="supports",
        evidence_source="exact-id",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    res2 = reconcile_correspondence(
        srm, [p_dangling_right], adjudications={"P-9": "confirmed"}
    )
    assert res2.is_valid is False
    assert any(
        e.error_code == "dangling_reference" and e.proposal_id == "P-9"
        for e in res2.errors
    )

    # 3. Stale version
    p_stale = CorrespondenceProposal(
        proposal_id="P-9",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v0-old",
        taxonomy_version="atlas-2026.05",
    )
    res3 = reconcile_correspondence(srm, [p_stale], adjudications={"P-9": "confirmed"})
    assert res3.is_valid is False
    assert any(
        e.error_code == "source_version_mismatch" and e.proposal_id == "P-9"
        for e in res3.errors
    )

    # 4. Evidence-free confirmation
    p_evidence_free = CorrespondenceProposal(
        proposal_id="P-9",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="",
        evidence_refs=[],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    res4 = reconcile_correspondence(
        srm, [p_evidence_free], adjudications={"P-9": "confirmed"}
    )
    assert res4.is_valid is False
    assert any(
        e.error_code == "evidence_required" and e.proposal_id == "P-9"
        for e in res4.errors
    )


def test_reconciliation_accepts_snapshot_and_dict_resource_maps() -> None:
    # The same reconciliation must work against the pinned-snapshot fixture
    # and a plain dict carrying the identical versions and identifiers.
    proposal = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )

    snapshot = ResourceMapSnapshot(
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        stpa_identifiers=["CA-1-1", "L-1"],
        taxonomy_identifiers=[
            "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
    )
    res_snapshot = reconcile_correspondence(snapshot, [proposal])
    assert res_snapshot.is_valid is True
    assert res_snapshot.proposals[0].adjudication == "unresolved"

    as_dict = {
        "stpa_version": "stpa-v1",
        "taxonomy_version": "atlas-2026.05",
        "stpa_identifiers": ["CA-1-1", "L-1"],
        "taxonomy_identifiers": [
            "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
    }
    res_dict = reconcile_correspondence(as_dict, [proposal])
    assert res_dict.is_valid is True
    assert res_dict.proposals[0].adjudication == "unresolved"


def test_reconciliation_flags_taxonomy_version_mismatch() -> None:
    # A proposal whose STPA version matches but whose taxonomy version is
    # stale must fall into the taxonomy mismatch branch and produce the
    # source_version_mismatch error.
    srm = make_test_resource_map()
    proposal = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-9999.99",
    )

    res = reconcile_correspondence(srm, [proposal], adjudications={"P-1": "confirmed"})
    assert res.is_valid is False
    mismatch = [
        e
        for e in res.errors
        if e.error_code == "source_version_mismatch" and e.proposal_id == "P-1"
    ]
    assert len(mismatch) == 1
    assert "atlas-9999.99" in mismatch[0].message


def test_reconciliation_registers_sparse_entries_without_taxonomy_refs() -> None:
    # Entries without taxonomy refs and loss links without loss/hazard ids
    # still contribute their element ids to the valid STPA identifier set.
    srm = SystemResourceMap(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        system_resources=[
            SystemResourceEntry(element_id="SR-9"),
            SystemResourceEntry(
                element_id="SR-8",
                taxonomy_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        ],
        loss_links=[
            LossLinkEntry(element_id="LL-9"),
        ],
        control_actions=[],
        trust_boundaries=[],
    )
    proposal = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="SR-9",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        evidence_refs=["SR-9"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )

    res = reconcile_correspondence(srm, [proposal], adjudications={"P-1": "confirmed"})
    # The left ref resolved through the sparse entry and the right ref
    # through the taxonomy-bearing one, so confirmation succeeds cleanly.
    assert res.is_valid is True
    assert res.errors == []
    assert res.proposals[0].adjudication == "confirmed"


def test_reconciliation_is_deterministic_and_idempotent() -> None:
    srm = make_test_resource_map()
    p1 = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    p2 = CorrespondenceProposal(
        proposal_id="P-2",
        left_ref="L-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="addresses",
        evidence_source="curated-map",
        strength="high",
        evidence_refs=["L-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    p3 = CorrespondenceProposal(
        proposal_id="P-3",
        left_ref="CA-1-1",
        right_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        relation_type="overlaps",
        evidence_source="resource-overlap",
        strength="weak",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )

    adjudications = {"P-1": "confirmed", "P-2": "rejected", "P-3": "unresolved"}

    res_a = reconcile_correspondence(srm, [p1, p2, p3], adjudications=adjudications)
    res_b = reconcile_correspondence(srm, [p3, p1, p2], adjudications=adjudications)

    # Identical identities and order
    assert [p.proposal_id for p in res_a.proposals] == [
        p.proposal_id for p in res_b.proposals
    ]
    assert [p.adjudication for p in res_a.proposals] == [
        p.adjudication for p in res_b.proposals
    ]

    # Repeating reconciliation on first result
    res_repeat = reconcile_correspondence(
        srm, res_a.proposals, adjudications=adjudications
    )
    assert [p.proposal_id for p in res_repeat.proposals] == [
        p.proposal_id for p in res_a.proposals
    ]
    assert [p.adjudication for p in res_repeat.proposals] == [
        p.adjudication for p in res_a.proposals
    ]


def test_reconcile_correspondence_cli_writes_yaml_and_json(tmp_path: Path) -> None:
    map_path = tmp_path / "resource-map.yaml"
    map_path.write_text(
        yaml.safe_dump(make_test_resource_map().model_dump(mode="json")),
        encoding="utf-8",
    )
    proposals_path = tmp_path / "proposals.yaml"
    proposals_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "stpa_version": "stpa-v1",
                "taxonomy_version": "atlas-2026.05",
                "proposals": [
                    {
                        "proposal_id": "P-1",
                        "left_ref": "CA-1-1",
                        "right_ref": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "relation_type": "supports",
                        "evidence_source": "exact-id",
                        "strength": "high",
                        "evidence_refs": ["CA-1-1"],
                        "stpa_version": "stpa-v1",
                        "taxonomy_version": "atlas-2026.05",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    adj_path = tmp_path / "adjudications.yaml"
    adj_path.write_text(yaml.safe_dump({"P-1": "confirmed"}), encoding="utf-8")
    output_dir = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "reconcile-correspondence",
            "--map",
            str(map_path),
            "--proposals",
            str(proposals_path),
            "--adjudications",
            str(adj_path),
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0, result.stderr
    yaml_path = output_dir / "reconciliation-result.yaml"
    json_path = output_dir / "reconciliation-result.json"
    assert yaml_path.is_file()
    assert json_path.is_file()
    assert f"Reconciliation result written to {yaml_path}" in result.stdout
    assert "Network calls: 0" in result.stdout
    assert "Model calls:   0" in result.stdout
    loaded = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert loaded["is_valid"] is True
    assert loaded["proposals"][0]["adjudication"] == "confirmed"
    assert loaded["network_calls"] == 0
    assert loaded["model_calls"] == 0


def test_reconcile_correspondence_cli_omits_adjudications(tmp_path: Path) -> None:
    map_path = tmp_path / "resource-map.yaml"
    map_path.write_text(
        yaml.safe_dump(make_test_resource_map().model_dump(mode="json")),
        encoding="utf-8",
    )
    proposals_path = tmp_path / "proposals.yaml"
    proposals_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "proposals": [
                    {
                        "proposal_id": "P-1",
                        "left_ref": "CA-1-1",
                        "right_ref": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "relation_type": "supports",
                        "evidence_source": "exact-id",
                        "strength": "high",
                        "evidence_refs": ["CA-1-1"],
                        "stpa_version": "stpa-v1",
                        "taxonomy_version": "atlas-2026.05",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "reconcile-correspondence",
            "--map",
            str(map_path),
            "--proposals",
            str(proposals_path),
            "--output-dir",
            str(output_dir),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.stderr
    loaded = yaml.safe_load(
        (output_dir / "reconciliation-result.json").read_text(encoding="utf-8")
    )
    assert loaded["proposals"][0]["adjudication"] == "unresolved"


def test_reconcile_correspondence_cli_rejects_confirmation_defects(
    tmp_path: Path,
) -> None:
    map_path = tmp_path / "resource-map.yaml"
    map_path.write_text(
        yaml.safe_dump(make_test_resource_map().model_dump(mode="json")),
        encoding="utf-8",
    )
    proposals_path = tmp_path / "proposals.yaml"
    proposals_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "proposals": [
                    {
                        "proposal_id": "P-9",
                        "left_ref": "MISSING",
                        "right_ref": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "relation_type": "supports",
                        "evidence_source": "exact-id",
                        "strength": "high",
                        "evidence_refs": ["MISSING"],
                        "stpa_version": "stpa-v1",
                        "taxonomy_version": "atlas-2026.05",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    adj_path = tmp_path / "adjudications.yaml"
    adj_path.write_text(yaml.safe_dump({"P-9": "confirmed"}), encoding="utf-8")
    output_dir = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "reconcile-correspondence",
            "--map",
            str(map_path),
            "--proposals",
            str(proposals_path),
            "--adjudications",
            str(adj_path),
            "--output-dir",
            str(output_dir),
            "--format",
            "yaml",
        ],
    )

    assert result.exit_code == 1
    loaded = yaml.safe_load(
        (output_dir / "reconciliation-result.yaml").read_text(encoding="utf-8")
    )
    assert loaded["is_valid"] is False
    assert any(
        error["error_code"] == "dangling_reference" for error in loaded["errors"]
    )
    assert loaded["proposals"][0]["adjudication"] != "confirmed"


def test_reconcile_correspondence_cli_rejects_missing_proposals(
    tmp_path: Path,
) -> None:
    map_path = tmp_path / "resource-map.yaml"
    map_path.write_text(
        yaml.safe_dump(make_test_resource_map().model_dump(mode="json")),
        encoding="utf-8",
    )
    missing = tmp_path / "missing" / "proposals.yaml"
    result = runner.invoke(
        app,
        [
            "reconcile-correspondence",
            "--map",
            str(map_path),
            "--proposals",
            str(missing),
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code == 1
    assert f"Error: proposal set not found: {missing}" in result.stderr

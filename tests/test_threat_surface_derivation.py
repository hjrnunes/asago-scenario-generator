"""Unit tests for taxonomy threat-surface derivation.

Pins the observable contract of ``determine_threat_surface``: the
three-hop Risk Atlas -> OWASP LLM Top 10 -> in-scope T-threat chain,
governance-only fallbacks (no LLM mapping, or only out-of-scope LLM
mappings), direct-path joins on shared ATLAS techniques, de-duplicated
first-seen unions of attack-pattern/ATLAS/ASI IDs, the KC6 ATLAS gate,
and empty surfaces for empty risk cards.

All inputs are fixture files under ``tmp_path``; gating data (KC -> T
mapping and attack patterns) is injected through the optional paths so
the scoped threat set is exactly what each scenario declares.  No LLM
endpoint is contacted.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from asago_scenario_generator.models import (
    CapabilityProfile,
    RiskCard,
    ThreatSurface,
)
from asago_scenario_generator.models.capability_profile import ToolInventoryEntry
from asago_scenario_generator.pipeline.threats import determine_threat_surface

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

# Deterministic causal-chain text for the governance-only retention check.
_CAUSAL_CHAIN = {
    "threat": "An adversary composes a crafted prompt that hijacks agent instructions.",
    "vulnerability": "The agent accepts instructions without validating their source.",
    "consequence": "The agent takes actions outside its design intent.",
    "impact": "Unauthorized actions harm the organization and its users.",
}


def _make_profile(*kc_subcodes: str) -> CapabilityProfile:
    kwargs = {}
    if any(c.startswith("KC5.") or c.startswith("KC6.") for c in kc_subcodes):
        kwargs["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["user input (zone 1)"],
        confidence="medium",
        kc_subcodes=list(kc_subcodes),
        **kwargs,
    )


def _make_card(
    risk_id: str,
    risk_name: str | None = None,
    **causal_chain: str | None,
) -> RiskCard:
    return RiskCard(
        risk_id=risk_id,
        risk_name=risk_name or risk_id,
        risk_description=f"Risk description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
        **causal_chain,
    )


def _write_sssom(path: Path, rows: list[tuple[str, str]]) -> None:
    """Write an SSSOM TSV mapping risk_id -> raw llmNN object id, in row order."""
    header = (
        "subject_id\tsubject_source\tpredicate_id\tobject_id"
        "\tobject_source\tmapping_justification"
    )
    lines = [header]
    for risk_id, raw_llm_id in rows:
        lines.append(
            f"{risk_id}\tibm-risk-atlas\tskos:exactMatch\t{raw_llm_id}"
            "\towasp-llm-top10\tsemapv:ManualMappingCuration"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_cross_taxonomy(
    path: Path,
    *,
    t_to_llm: list[dict] | None = None,
    t_to_atlas: list[dict] | None = None,
    t_to_asi: list[dict] | None = None,
    t_direct: list[dict] | None = None,
) -> None:
    data = {
        "t_to_llm": t_to_llm or [],
        "t_to_atlas": t_to_atlas or [],
        "t_to_asi": t_to_asi or [],
        "t_direct": t_direct or [],
    }
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def _write_kc_mapping(path: Path, kc_to_threats: dict[str, list[str]]) -> None:
    data = {"kc_to_threats": kc_to_threats, "hitl": {"threat_ids": []}}
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def _write_attack_patterns(path: Path, patterns: dict[str, str]) -> None:
    """Write an attack-patterns fixture: pattern id -> threat id."""
    data = {
        "patterns": {
            pid: {
                "id": pid,
                "threat_id": threat_id,
                "name": pid,
                "description": f"Fixture pattern {pid}",
            }
            for pid, threat_id in patterns.items()
        }
    }
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def _derive(
    tmp_path: Path,
    *,
    profile: CapabilityProfile,
    cards: list[RiskCard],
    sssom_rows: list[tuple[str, str]],
    t_to_llm: list[dict],
    kc_to_threats: dict[str, list[str]],
    t_to_atlas: list[dict] | None = None,
    t_to_asi: list[dict] | None = None,
    t_direct: list[dict] | None = None,
    attack_patterns: dict[str, str] | None = None,
) -> ThreatSurface:
    sssom_path = tmp_path / "risk-llm.sssom.tsv"
    cross_path = tmp_path / "cross-taxonomy-mappings.yaml"
    kc_path = tmp_path / "kc-threat-mapping.yaml"
    _write_sssom(sssom_path, sssom_rows)
    _write_cross_taxonomy(
        cross_path,
        t_to_llm=t_to_llm,
        t_to_atlas=t_to_atlas,
        t_to_asi=t_to_asi,
        t_direct=t_direct,
    )
    _write_kc_mapping(kc_path, kc_to_threats)
    attack_patterns_path = None
    if attack_patterns is not None:
        attack_patterns_path = tmp_path / "attack-patterns.yaml"
        _write_attack_patterns(attack_patterns_path, attack_patterns)
    return determine_threat_surface(
        profile,
        cards,
        sssom_path,
        cross_path,
        kc_mapping_path=kc_path,
        attack_patterns_path=attack_patterns_path,
    )


def _actionable(surface: ThreatSurface, risk_id: str):
    matches = [e for e in surface.entries if e.risk_card.risk_id == risk_id]
    assert len(matches) == 1, f"expected one actionable entry for {risk_id}"
    return matches[0]


def _governance(surface: ThreatSurface, risk_id: str):
    matches = [e for e in surface.governance_only if e.risk_card.risk_id == risk_id]
    assert len(matches) == 1, f"expected one governance-only entry for {risk_id}"
    return matches[0]


# ---------------------------------------------------------------------------
# Taxonomy threat-surface derivation 01: three-hop chain in first-seen order
# ---------------------------------------------------------------------------


class TestThreeHopChain:
    def test_resolves_first_seen_order_when_all_reachable_in_scope(
        self, tmp_path: Path
    ) -> None:
        surface = _derive(
            tmp_path,
            profile=_make_profile("KCX-TSDS", "KC6.4"),
            cards=[_make_card("atlas-prompt-injection")],
            sssom_rows=[
                ("atlas-prompt-injection", "llm01-fixture"),
                ("atlas-prompt-injection", "llm06-fixture"),
            ],
            t_to_llm=[
                {"source": "T6", "target": "LLM01"},
                {"source": "T11", "target": "LLM01"},
                {"source": "T2", "target": "LLM06"},
                {"source": "T13", "target": "LLM06"},
            ],
            kc_to_threats={
                "KCX-TSDS": ["T2", "T6", "T11", "T13"],
                "KC6.4": [],
            },
        )

        assert len(surface.entries) == 1
        assert surface.governance_only == []
        entry = surface.entries[0]
        assert entry.owasp_llm_ids == ["LLM01", "LLM06"]
        assert entry.agentic_threat_ids == ["T6", "T11", "T2", "T13"]
        assert entry.atlas_technique_ids == []

    def test_drops_out_of_scope_reachable_threats(self, tmp_path: Path) -> None:
        """Only scoped three-hop threats remain; T2/T13 drop while LLM IDs stay."""
        surface = _derive(
            tmp_path,
            profile=_make_profile("KCX-TSDS", "KC6.4"),
            cards=[_make_card("atlas-prompt-injection")],
            sssom_rows=[
                ("atlas-prompt-injection", "llm01-fixture"),
                ("atlas-prompt-injection", "llm06-fixture"),
            ],
            t_to_llm=[
                {"source": "T6", "target": "LLM01"},
                {"source": "T11", "target": "LLM01"},
                {"source": "T2", "target": "LLM06"},
                {"source": "T13", "target": "LLM06"},
            ],
            kc_to_threats={"KCX-TSDS": ["T6", "T11"], "KC6.4": []},
        )

        assert len(surface.entries) == 1
        assert surface.governance_only == []
        entry = surface.entries[0]
        assert entry.owasp_llm_ids == ["LLM01", "LLM06"]
        assert entry.agentic_threat_ids == ["T6", "T11"]


# ---------------------------------------------------------------------------
# Taxonomy threat-surface derivation 02: card without an LLM mapping
# ---------------------------------------------------------------------------


class TestGovernanceOnlyNoLlmMapping:
    def test_missing_llm_mapping_is_governance_only_with_causal_chain(
        self, tmp_path: Path
    ) -> None:
        surface = _derive(
            tmp_path,
            profile=_make_profile("KCX-TSDS", "KC6.4"),
            cards=[
                _make_card("atlas-orphan-risk", "Orphaned risk signal", **_CAUSAL_CHAIN)
            ],
            sssom_rows=[],
            t_to_llm=[],
            kc_to_threats={"KCX-TSDS": ["T6"], "KC6.4": []},
        )

        assert surface.entries == []
        assert len(surface.governance_only) == 1
        entry = surface.governance_only[0]
        assert entry.governance_only is True
        assert entry.risk_card.risk_id == "atlas-orphan-risk"
        assert entry.risk_card.risk_name == "Orphaned risk signal"
        assert entry.owasp_llm_ids == []
        assert entry.agentic_threat_ids == []
        assert entry.attack_pattern_ids == []
        assert entry.atlas_technique_ids == []
        assert entry.owasp_asi_ids == []
        assert entry.risk_card.threat == _CAUSAL_CHAIN["threat"]
        assert entry.risk_card.vulnerability == _CAUSAL_CHAIN["vulnerability"]
        assert entry.risk_card.consequence == _CAUSAL_CHAIN["consequence"]
        assert entry.risk_card.impact == _CAUSAL_CHAIN["impact"]


# ---------------------------------------------------------------------------
# Taxonomy threat-surface derivation 03: only out-of-scope LLM mappings
# ---------------------------------------------------------------------------


class TestGovernanceOnlyOutOfScopeMappings:
    def test_keeps_llm_ids_and_no_direct_join(self, tmp_path: Path) -> None:
        surface = _derive(
            tmp_path,
            profile=_make_profile("KCX-TSDS"),
            cards=[_make_card("atlas-prompt-injection")],
            sssom_rows=[("atlas-prompt-injection", "llm01-fixture")],
            t_to_llm=[{"source": "T11", "target": "LLM01"}],
            kc_to_threats={"KCX-TSDS": ["T7", "T9", "T10"]},
        )

        assert surface.entries == []
        assert len(surface.governance_only) == 1
        entry = surface.governance_only[0]
        assert entry.governance_only is True
        assert entry.owasp_llm_ids == ["LLM01"]
        assert entry.agentic_threat_ids == []
        assert entry.attack_pattern_ids == []
        assert entry.atlas_technique_ids == []
        assert entry.owasp_asi_ids == []

    def test_in_scope_direct_threats_never_resurrect_governance_card(
        self, tmp_path: Path
    ) -> None:
        """In-scope direct threats with no shared three-hop base stay dropped."""
        surface = _derive(
            tmp_path,
            profile=_make_profile("KCX-TSDS"),
            cards=[_make_card("atlas-prompt-injection")],
            sssom_rows=[("atlas-prompt-injection", "llm01-fixture")],
            t_to_llm=[{"source": "T11", "target": "LLM01"}],
            t_to_atlas=[
                {"source": "T7", "targets": ["AML.T0050"]},
            ],
            t_direct=[{"source": "T7", "source_name": "Misaligned Behaviors"}],
            kc_to_threats={"KCX-TSDS": ["T7", "T9", "T10"]},
        )

        assert surface.entries == []
        assert len(surface.governance_only) == 1
        assert surface.governance_only[0].agentic_threat_ids == []


# ---------------------------------------------------------------------------
# Taxonomy threat-surface derivation 04: direct-path join on shared ATLAS
# ---------------------------------------------------------------------------


class TestDirectPathJoin:
    def _derive_with_direct(self, tmp_path: Path, scoped: list[str]) -> ThreatSurface:
        return _derive(
            tmp_path,
            profile=_make_profile("KCX-TSDS", "KC6.4"),
            cards=[_make_card("atlas-prompt-injection")],
            sssom_rows=[("atlas-prompt-injection", "llm06-fixture")],
            t_to_llm=[{"source": "T2", "target": "LLM06"}],
            t_to_atlas=[
                {"source": "T2", "targets": ["AML.T0015", "AML.T0053"]},
                {"source": "T7", "targets": ["AML.T0054", "AML.T0015", "AML.T0053"]},
                {"source": "T8", "targets": ["AML.T0056", "AML.T0057"]},
            ],
            t_direct=[
                {"source": "T7", "source_name": "Misaligned Behaviors"},
                {"source": "T8", "source_name": "Repudiation"},
            ],
            kc_to_threats={"KCX-TSDS": scoped, "KC6.4": []},
        )

    def test_joins_direct_threat_sharing_atlas_technique(self, tmp_path: Path) -> None:
        surface = self._derive_with_direct(tmp_path, ["T2", "T7", "T8"])

        assert len(surface.entries) == 1
        assert surface.governance_only == []
        entry = surface.entries[0]
        assert entry.agentic_threat_ids == ["T2", "T7"]
        assert entry.atlas_technique_ids == [
            "AML.T0015",
            "AML.T0053",
            "AML.T0054",
        ]

    def test_non_overlapping_direct_threat_never_joins(self, tmp_path: Path) -> None:
        surface = self._derive_with_direct(tmp_path, ["T2", "T8"])

        assert len(surface.entries) == 1
        assert surface.governance_only == []
        entry = surface.entries[0]
        assert entry.agentic_threat_ids == ["T2"]
        assert entry.atlas_technique_ids == ["AML.T0015", "AML.T0053"]

    def test_direct_threat_already_reached_via_llm_hop_appears_once(
        self, tmp_path: Path
    ) -> None:
        """A direct-path threat also reachable via the LLM hop stays de-duplicated."""
        surface = _derive(
            tmp_path,
            profile=_make_profile("KCX-TSDS", "KC6.4"),
            cards=[_make_card("atlas-prompt-injection")],
            sssom_rows=[("atlas-prompt-injection", "llm06-fixture")],
            t_to_llm=[
                {"source": "T2", "target": "LLM06"},
                {"source": "T7", "target": "LLM06"},
            ],
            t_to_atlas=[
                {"source": "T2", "targets": ["AML.T0015", "AML.T0053"]},
                {"source": "T7", "targets": ["AML.T0054", "AML.T0015"]},
            ],
            t_direct=[{"source": "T7", "source_name": "Misaligned Behaviors"}],
            kc_to_threats={"KCX-TSDS": ["T2", "T7"], "KC6.4": []},
        )

        assert len(surface.entries) == 1
        assert surface.governance_only == []
        entry = surface.entries[0]
        assert entry.agentic_threat_ids == ["T2", "T7"]
        assert entry.atlas_technique_ids == [
            "AML.T0015",
            "AML.T0053",
            "AML.T0054",
        ]


# ---------------------------------------------------------------------------
# Taxonomy threat-surface derivation 05: union without duplicates
# ---------------------------------------------------------------------------


class TestUnionWithoutDuplicates:
    def test_unions_attack_patterns_atlas_and_asi_first_seen(
        self, tmp_path: Path
    ) -> None:
        surface = _derive(
            tmp_path,
            profile=_make_profile("KCX-TSDS", "KC6.4"),
            cards=[_make_card("atlas-memory-poisoning")],
            sssom_rows=[
                ("atlas-memory-poisoning", "llm04-fixture"),
                ("atlas-memory-poisoning", "llm08-fixture"),
            ],
            t_to_llm=[
                {"source": "T1", "target": "LLM04"},
                {"source": "T12", "target": "LLM04"},
                {"source": "T1", "target": "LLM08"},
                {"source": "T2", "target": "LLM08"},
            ],
            t_to_atlas=[
                {
                    "source": "T1",
                    "targets": ["AML.T0043", "AML.T0031", "AML.T0020"],
                },
                {
                    "source": "T12",
                    "targets": ["AML.T0043", "AML.T0031", "AML.T0020"],
                },
            ],
            t_to_asi=[
                {"source": "T1", "target": "ASI06"},
                {"source": "T12", "target": "ASI07"},
            ],
            kc_to_threats={"KCX-TSDS": ["T1", "T12"], "KC6.4": []},
            attack_patterns={
                "AP-T1-01": "T1",
                "AP-T1-02": "T1",
                "AP-T12-01": "T12",
            },
        )

        assert len(surface.entries) == 1
        assert surface.governance_only == []
        entry = surface.entries[0]
        assert entry.owasp_llm_ids == ["LLM04", "LLM08"]
        assert entry.agentic_threat_ids == ["T1", "T12"]
        assert entry.attack_pattern_ids == [
            "AP-T1-01",
            "AP-T1-02",
            "AP-T12-01",
        ]
        assert entry.atlas_technique_ids == [
            "AML.T0043",
            "AML.T0031",
            "AML.T0020",
        ]
        assert entry.owasp_asi_ids == ["ASI06", "ASI07"]


# ---------------------------------------------------------------------------
# Taxonomy threat-surface derivation 06: KC6 gate on ATLAS techniques
# ---------------------------------------------------------------------------


class TestKc6AtlasGate:
    def _derive_t6(self, tmp_path: Path, kc_subcodes: tuple[str, ...]) -> ThreatSurface:
        return _derive(
            tmp_path,
            profile=_make_profile(*kc_subcodes),
            cards=[_make_card("atlas-prompt-injection")],
            sssom_rows=[("atlas-prompt-injection", "llm01-fixture")],
            t_to_llm=[{"source": "T6", "target": "LLM01"}],
            t_to_atlas=[
                {"source": "T6", "targets": ["AML.T0054", "AML.T0053"]},
                {"source": "T7", "targets": ["AML.T0050"]},
                {"source": "T15", "targets": ["AML.T0050"]},
            ],
            t_direct=[
                {"source": "T7", "source_name": "Misaligned Behaviors"},
                {"source": "T15", "source_name": "Human Manipulation"},
            ],
            kc_to_threats={code: [t for t in ("T6",)] for code in kc_subcodes},
        )

    def test_drops_kc6_gated_technique_without_kc6_subcode(
        self, tmp_path: Path
    ) -> None:
        surface = self._derive_t6(tmp_path, ("KC1.1",))

        assert len(surface.entries) == 1
        assert surface.entries[0].atlas_technique_ids == ["AML.T0054"]

    def test_keeps_kc6_gated_technique_with_kc6_subcode(self, tmp_path: Path) -> None:
        surface = self._derive_t6(tmp_path, ("KC1.1", "KC6.4"))

        assert len(surface.entries) == 1
        assert surface.entries[0].atlas_technique_ids == [
            "AML.T0054",
            "AML.T0053",
        ]


# ---------------------------------------------------------------------------
# Taxonomy threat-surface derivation 07: empty risk cards
# ---------------------------------------------------------------------------


class TestEmptyRiskCards:
    def test_empty_cards_yield_empty_surface(self, tmp_path: Path) -> None:
        surface = _derive(
            tmp_path,
            profile=_make_profile("KCX-TSDS", "KC6.4"),
            cards=[],
            sssom_rows=[],
            t_to_llm=[],
            kc_to_threats={"KCX-TSDS": ["T6"], "KC6.4": []},
        )

        assert surface.entries == []
        assert surface.governance_only == []


# ---------------------------------------------------------------------------
# Backward compatibility: bundled gating data when paths are omitted
# ---------------------------------------------------------------------------


class TestBundledDefaults:
    def test_bundle_kc_mapping_still_gates_without_fixture_paths(
        self, tmp_path: Path
    ) -> None:
        """No kc_mapping_path/attack_patterns_path falls back to committed data."""
        sssom_path = tmp_path / "risk-llm.sssom.tsv"
        cross_path = tmp_path / "cross-taxonomy-mappings.yaml"
        _write_sssom(sssom_path, [("atlas-prompt-injection", "llm01-fixture")])
        _write_cross_taxonomy(
            cross_path,
            t_to_llm=[{"source": "T6", "target": "LLM01"}],
        )

        surface = determine_threat_surface(
            _make_profile("KC1.1", "KC6.4"),
            [_make_card("atlas-prompt-injection")],
            sssom_path,
            cross_path,
        )

        assert len(surface.entries) == 1
        assert surface.entries[0].agentic_threat_ids == ["T6"]

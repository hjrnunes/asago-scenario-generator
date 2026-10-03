"""Unit tests for SP2 Stage 4 — Catalog enrichment and coverage analysis."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlledProcess,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CatalogMapping,
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.threat_enum.catalog_data import match_catalog
from asago_scenario_generator.stpa.threat_enum.catalog_enrichment import (
    enrich_threats,
    reconcile_na_slots,
)
from asago_scenario_generator.stpa.threat_enum.coverage import (
    compute_coverage,
    metric_na_quality,
    metric_structural_consideration,
)


def _make_ica(
    ica_id: str = "RESP-1:CA-1-1:NOT_PROVIDED:1",
    ica_text: str = "The agent does not validate input",
    loss_scenario: str = "Attacker exploits the gap",
    related_hazards: list[str] | None = None,
    related_constraints: list[str] | None = None,
) -> ICA:
    """Build a minimal ICA."""
    return ICA(
        ica_id=ica_id,
        ica_text=ica_text,
        hazardous_context="Context",
        loss_scenario=loss_scenario,
        related_hazards=related_hazards or [],
        related_constraints=related_constraints or [],
    )


def _make_non_na_slot(
    slot_id: str = "RESP-1:CA-1-1:NOT_PROVIDED",
    responsibility: str = "RESP-1",
    uca_type: UCAType = UCAType.not_provided,
    icas: list[ICA] | None = None,
) -> ICASlot:
    """Build a minimal non-N/A slot."""
    return ICASlot(
        slot_id=slot_id,
        responsibility=responsibility,
        control_action="CA-1-1",
        uca_type=uca_type,
        is_na=False,
        icas=icas or [_make_ica(ica_id=f"{slot_id}:1")],
    )


def _make_na_slot(
    slot_id: str = "RESP-1:CA-1-1:WRONG_DURATION",
    responsibility: str = "RESP-1",
    na_justification: str = "Action is atomic with no duration component",
) -> ICASlot:
    """Build a minimal N/A slot."""
    return ICASlot(
        slot_id=slot_id,
        responsibility=responsibility,
        control_action="CA-1-1",
        uca_type=UCAType.wrong_duration,
        is_na=True,
        icas=[],
        na_justification=na_justification,
    )


def _make_minimal_cs(
    ca_desc: str = "Execute action",
    cm_desc: str = "Coordination mechanism",
) -> ControlStructure:
    """Build a minimal valid ControlStructure for reconciliation tests."""
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Test",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description=ca_desc,
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            ),
        ],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Process"),
        ],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-1",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description=cm_desc,
                    payload="data",
                ),
                description="Link",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Keyword matching (SP2-CAT-01, SP2-CAT-02, SP2-CAT-03)
# ---------------------------------------------------------------------------


class TestKeywordMatching:
    """Catalog keyword matching tests."""

    def test_prompt_injection_maps_to_atlas_and_owasp(self):
        """ICA with prompt injection keywords maps to ATLAS and OWASP."""
        mappings = match_catalog(
            "The agent is susceptible to prompt injection attacks",
            "Attacker manipulates the agent via instruction injection",
        )
        atlas_mappings = [m for m in mappings if m.catalog == "ATLAS"]
        owasp_mappings = [m for m in mappings if m.catalog == "OWASP_AGENTIC"]
        assert len(atlas_mappings) >= 1
        assert len(owasp_mappings) >= 1

    def test_no_matching_keywords_is_unmapped(self):
        """ICA with no matching keywords is unmapped."""
        mappings = match_catalog(
            "routine status check",
            "no attack vector",
        )
        assert len(mappings) == 0

    def test_confidence_high_with_two_keywords(self):
        """Two keyword matches produce high confidence."""
        mappings = match_catalog(
            "prompt injection via instruction override",
            "",
        )
        high_conf = [m for m in mappings if m.confidence == "high"]
        assert len(high_conf) >= 1

    def test_confidence_low_with_one_keyword(self):
        """One keyword match produces low confidence."""
        mappings = match_catalog(
            "prompt injection during routine operation",
            "",
        )
        # At least one mapping should be low confidence
        # (prompt injection matches both ATLAS and OWASP, but with 1 keyword each)
        assert any(m.confidence == "low" for m in mappings)


# ---------------------------------------------------------------------------
# N/A reconciliation (SP2-CAT-04, SP2-CAT-05)
# ---------------------------------------------------------------------------


class TestNAReconciliation:
    """N/A reconciliation tests."""

    def test_contradiction_when_catalog_matches_na_slot(self):
        """N/A slot where catalog matches → contradiction flag."""
        cs = _make_minimal_cs(ca_desc="prompt injection vulnerability")
        slot = _make_na_slot(
            na_justification="no hazard applicable",
        )
        flags = reconcile_na_slots([slot], cs)
        assert len(flags) == 1
        assert slot.slot_id in flags[0]

    def test_no_contradiction_when_no_catalog_match(self):
        """N/A slot with no catalog match → no flag."""
        cs = _make_minimal_cs(ca_desc="routine validation")
        slot = _make_na_slot(na_justification="action is atomic and stateless")
        flags = reconcile_na_slots([slot], cs)
        assert len(flags) == 0

    def test_na_justification_provides_matching_keywords(self):
        """N/A justification text with catalog keywords triggers contradiction.

        The na_justification is the only source of matching keywords in
        the context string — if it is dropped (e.g. by an `and` mutation),
        the catalog would not match and no flag would be raised.
        """
        cs = _make_minimal_cs(ca_desc="routine status check")
        slot = _make_na_slot(
            na_justification="no prompt injection hazard applicable here",
        )
        flags = reconcile_na_slots([slot], cs)
        assert len(flags) == 1
        assert slot.slot_id in flags[0]


# ---------------------------------------------------------------------------
# Coverage analysis (SP2-CAT-06 through SP2-CAT-11)
# ---------------------------------------------------------------------------


class TestCoverageAnalysis:
    """Coverage analysis tests."""

    def test_three_way_partition(self):
        """Coverage analysis produces three-way partition."""
        # 10 total slots: 7 non-N/A, 3 N/A
        # 4 with catalog mappings, 3 without
        slots = []
        for i in range(4):
            ica = _make_ica(
                ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}",
                ica_text="prompt injection attack",
                loss_scenario="attacker manipulates",
            )
            slots.append(
                _make_non_na_slot(f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED", icas=[ica])
            )
        for i in range(3):
            ica = _make_ica(
                ica_id=f"RESP-1:CA-1-1:INCORRECT:{i + 1}",
                ica_text="routine check",
                loss_scenario="no attack vector",
            )
            slots.append(
                _make_non_na_slot(
                    f"RESP-2:CA-1-{i + 1}:INCORRECT",
                    responsibility="RESP-2",
                    uca_type=UCAType.incorrect,
                    icas=[ica],
                )
            )
        for i in range(3):
            slots.append(
                _make_na_slot(
                    f"RESP-3:CA-1-{i + 1}:WRONG_DURATION",
                    responsibility="RESP-3",
                )
            )

        structural_threats = []
        for slot in slots:
            if not slot.is_na:
                for ica in slot.icas:
                    mappings = match_catalog(ica.ica_text, ica.loss_scenario)
                    structural_threats.append(
                        StructuralThreat(
                            ica_slot_id=slot.slot_id,
                            ica_id=ica.ica_id,
                            ica_text=ica.ica_text,
                            hazardous_context=ica.hazardous_context,
                            loss_scenario=ica.loss_scenario,
                            catalog_mappings=mappings,
                        )
                    )

        coverage = compute_coverage(slots, structural_threats)

        assert coverage.structural_coverage["total_slots"] == 10
        assert coverage.structural_coverage["non_na"] == 7
        assert coverage.structural_coverage["na"] == 3
        assert coverage.catalog_correspondence["structural_with_match"] == 4
        assert coverage.catalog_correspondence["structural_unmapped"] == 3
        assert coverage.catalog_correspondence["catalog_only_supplements"] == 0

    def test_by_ica_type(self):
        """Coverage analysis partitions by ICA type."""
        slots = []
        # 4 NOT_PROVIDED, 3 INCORRECT, 1 WRONG_TIMING, 0 WRONG_DURATION
        for i in range(4):
            slots.append(
                _make_non_na_slot(
                    f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED",
                    uca_type=UCAType.not_provided,
                )
            )
        for i in range(3):
            slots.append(
                _make_non_na_slot(
                    f"RESP-1:CA-1-{i + 1}:INCORRECT",
                    uca_type=UCAType.incorrect,
                )
            )
        for i in range(1):
            slots.append(
                _make_non_na_slot(
                    f"RESP-1:CA-1-{i + 1}:WRONG_TIMING",
                    uca_type=UCAType.wrong_timing,
                )
            )

        threats = [
            StructuralThreat(
                ica_slot_id=s.slot_id,
                ica_id=s.icas[0].ica_id,
                ica_text=s.icas[0].ica_text,
                hazardous_context=s.icas[0].hazardous_context,
                loss_scenario=s.icas[0].loss_scenario,
            )
            for s in slots
            if not s.is_na
        ]
        coverage = compute_coverage(slots, threats)
        assert coverage.by_ica_type["NOT_PROVIDED"] == 4
        assert coverage.by_ica_type["INCORRECT"] == 3
        assert coverage.by_ica_type["WRONG_TIMING"] == 1
        assert coverage.by_ica_type["WRONG_DURATION"] == 0

    def test_by_controller(self):
        """Coverage analysis partitions by controller."""
        slots = []
        # 5 from RESP-1, 3 from RESP-2, 2 from CL-1
        for i in range(5):
            slots.append(
                _make_non_na_slot(
                    f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED",
                    responsibility="RESP-1",
                )
            )
        for i in range(3):
            slots.append(
                _make_non_na_slot(
                    f"RESP-2:CA-1-{i + 1}:NOT_PROVIDED",
                    responsibility="RESP-2",
                )
            )
        for i in range(2):
            slots.append(
                ICASlot(
                    slot_id=f"CL-1:CM-1:NOT_PROVIDED:{i}",
                    responsibility=None,
                    coordination_link="CL-1",
                    control_action="CM-1",
                    uca_type=UCAType.not_provided,
                    is_na=False,
                    icas=[_make_ica(ica_id=f"CL-1:CM-1:NOT_PROVIDED:{i + 1}")],
                )
            )

        threats = [
            StructuralThreat(
                ica_slot_id=s.slot_id,
                ica_id=s.icas[0].ica_id,
                ica_text=s.icas[0].ica_text,
                hazardous_context=s.icas[0].hazardous_context,
                loss_scenario=s.icas[0].loss_scenario,
            )
            for s in slots
            if not s.is_na
        ]
        coverage = compute_coverage(slots, threats)
        assert coverage.by_controller["RESP-1"] == 5
        assert coverage.by_controller["RESP-2"] == 3
        assert coverage.by_controller["CL-1"] == 2

    def test_structural_consideration(self):
        """Structural consideration metric counts considered slots."""
        slots = []
        for i in range(7):
            slots.append(_make_non_na_slot(f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED"))
        for i in range(3):
            slots.append(
                _make_na_slot(
                    f"RESP-1:CA-1-{i + 1}:WRONG_DURATION",
                    na_justification="Action is discrete",
                )
            )
        result = metric_structural_consideration(slots)
        assert result["total_slots"] == 10
        assert result["considered"] == 10
        assert result["rate"] == 1.0

    def test_na_quality_metric(self):
        """N/A quality metric counts structural keyword citations."""
        slots = [
            _make_na_slot(
                "RESP-1:CA-1-1:WRONG_DURATION", na_justification="Action is discrete"
            ),
            _make_na_slot(
                "RESP-1:CA-1-2:WRONG_DURATION", na_justification="Action is continuous"
            ),
            _make_na_slot(
                "RESP-1:CA-1-3:WRONG_DURATION", na_justification="Action is atomic"
            ),
            _make_na_slot(
                "RESP-1:CA-1-4:WRONG_DURATION", na_justification="no hazard applicable"
            ),
        ]
        result = metric_na_quality(slots)
        assert result["na_count"] == 4
        assert result["quality_count"] == 3
        assert result["quality_rate"] == 0.75

    def test_uncovered_owasp_threats(self):
        """Uncovered OWASP threats are listed."""
        # Create a threat that covers T1 only
        threat = StructuralThreat(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
            ica_text="prompt injection",
            hazardous_context="ctx",
            loss_scenario="scenario",
            catalog_mappings=[
                CatalogMapping(
                    catalog="OWASP_AGENTIC",
                    id="T1",
                    name="Prompt Injection",
                    confidence="high",
                ),
            ],
        )
        coverage = compute_coverage([], [threat])
        # T10 and T15 should be uncovered (among others)
        assert "T10" in coverage.uncovered_owasp_threats
        assert "T15" in coverage.uncovered_owasp_threats
        assert coverage.uncovered_reason is not None

    def test_covered_owasp_threat_not_in_uncovered(self):
        """A covered OWASP threat ID must NOT appear in uncovered list."""
        threat = StructuralThreat(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
            ica_text="prompt injection",
            hazardous_context="ctx",
            loss_scenario="scenario",
            catalog_mappings=[
                CatalogMapping(
                    catalog="OWASP_AGENTIC",
                    id="T1",
                    name="Prompt Injection",
                    confidence="high",
                ),
            ],
        )
        coverage = compute_coverage([], [threat])
        assert "T1" not in coverage.uncovered_owasp_threats

    def test_structural_consideration_by_ica_type_breakdown(self):
        """by_ica_type breakdown in structural_consideration has exact counts."""
        slots = [
            _make_non_na_slot("S1", uca_type=UCAType.not_provided),
            _make_non_na_slot("S2", uca_type=UCAType.not_provided),
            _make_non_na_slot("S3", uca_type=UCAType.incorrect),
        ]
        result = metric_structural_consideration(slots)
        assert result["by_ica_type"]["NOT_PROVIDED"] == 2
        assert result["by_ica_type"]["INCORRECT"] == 1
        assert result["by_ica_type"]["WRONG_TIMING"] == 0
        assert result["by_ica_type"]["WRONG_DURATION"] == 0

    def test_structural_consideration_by_resp_breakdown(self):
        """by_responsibility breakdown in structural_consideration has exact counts."""
        slots = [
            _make_non_na_slot("S1", responsibility="RESP-1"),
            _make_non_na_slot("S2", responsibility="RESP-1"),
            _make_non_na_slot("S3", responsibility="RESP-2"),
        ]
        result = metric_structural_consideration(slots)
        assert result["by_responsibility"]["RESP-1"] == 2
        assert result["by_responsibility"]["RESP-2"] == 1
        assert "UNKNOWN" not in result["by_responsibility"]

    def test_structural_consideration_by_resp_with_coord_link(self):
        """Coordination link slots are attributed to the link, not UNKNOWN."""
        slots = [
            _make_non_na_slot("S1", responsibility="RESP-1"),
            ICASlot(
                slot_id="CL-1:CM-1:NOT_PROVIDED:0",
                responsibility=None,
                coordination_link="CL-1",
                control_action="CM-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[_make_ica(ica_id="CL-1:CM-1:NOT_PROVIDED:1")],
            ),
        ]
        result = metric_structural_consideration(slots)
        assert result["by_responsibility"]["RESP-1"] == 1
        assert result["by_responsibility"]["CL-1"] == 1

    def test_na_quality_no_na_slots(self):
        """N/A quality with no N/A slots returns na_count=0, quality_rate=None."""
        slots = [
            _make_non_na_slot("S1"),
            _make_non_na_slot("S2", uca_type=UCAType.incorrect),
        ]
        result = metric_na_quality(slots)
        assert result["na_count"] == 0
        assert result["quality_rate"] is None


# ---------------------------------------------------------------------------
# No LLM calls (SP2-CAT-12)
# ---------------------------------------------------------------------------


class TestNoLLMCalls:
    """Catalog enrichment makes no LLM calls."""

    def test_no_llm_calls(self):
        slots = [
            _make_non_na_slot("RESP-1:CA-1-1:NOT_PROVIDED"),
            _make_na_slot("RESP-1:CA-1-2:WRONG_DURATION"),
        ]
        ica_enum = ICAEnumeration(slots=slots)
        cs = _make_minimal_cs()
        # This is deterministic — no LLM client involved
        enriched = enrich_threats(ica_enum, cs)
        assert enriched is not None


# ---------------------------------------------------------------------------
# Structural threat provenance (SP2-CAT-13)
# ---------------------------------------------------------------------------


class TestStructuralThreatProvenance:
    """Structural threats carry provenance 'structural'."""

    def test_provenance_structural(self):
        slots = [
            _make_non_na_slot("RESP-1:CA-1-1:NOT_PROVIDED"),
            _make_non_na_slot("RESP-1:CA-1-2:INCORRECT", uca_type=UCAType.incorrect),
            _make_non_na_slot(
                "RESP-1:CA-1-3:WRONG_TIMING", uca_type=UCAType.wrong_timing
            ),
        ]
        ica_enum = ICAEnumeration(slots=slots)
        cs = _make_minimal_cs()
        enriched = enrich_threats(ica_enum, cs)
        assert len(enriched.structural_threats) == 3
        for threat in enriched.structural_threats:
            assert threat.provenance == "structural"


# ---------------------------------------------------------------------------
# N/A reconciliation flags in coverage (SP2-CAT-14)
# ---------------------------------------------------------------------------


class TestNAReconciliationFlagsInCoverage:
    """N/A reconciliation flags are recorded in coverage analysis."""

    def test_reconciliation_flags_recorded(self):
        cs = _make_minimal_cs(ca_desc="prompt injection vulnerability")
        slots = [
            _make_na_slot(na_justification="no hazard applicable"),
        ]
        ica_enum = ICAEnumeration(slots=slots)
        enriched = enrich_threats(ica_enum, cs)
        assert len(enriched.coverage_analysis.na_reconciliation_flags) == 1


# ---------------------------------------------------------------------------
# Enriched threat set validates (SP2-CAT-15)
# ---------------------------------------------------------------------------


class TestEnrichedThreatSetValidates:
    """Enriched threat set validates against the schema."""

    def test_validates_successfully(self):
        slots = [
            _make_non_na_slot("RESP-1:CA-1-1:NOT_PROVIDED"),
            _make_non_na_slot("RESP-1:CA-1-2:INCORRECT", uca_type=UCAType.incorrect),
            _make_na_slot("RESP-1:CA-1-3:WRONG_DURATION"),
        ]
        ica_enum = ICAEnumeration(slots=slots)
        cs = _make_minimal_cs()
        enriched = enrich_threats(ica_enum, cs)
        # Re-validate via model_dump + model_validate
        EnrichedThreatSet.model_validate(enriched.model_dump())

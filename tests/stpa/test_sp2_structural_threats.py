"""Unit tests for SP2 Stage 4: the structural threat list and coverage analysis."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.enriched_threat_set import (
    EnrichedThreatSet,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.threat_enum.catalog_enrichment import (
    enrich_threats,
)
from asago_scenario_generator.stpa.threat_enum.coverage import compute_coverage


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


class TestStructuralThreatList:
    """The threat list keeps every ICA of every non-N/A slot, in slot order."""

    def test_one_threat_per_ica_in_slot_order_and_na_slots_are_skipped(self):
        first = _make_non_na_slot(
            "RESP-2:CA-1-1:INCORRECT",
            responsibility="RESP-2",
            uca_type=UCAType.incorrect,
            icas=[
                _make_ica(ica_id="RESP-2:CA-1-1:INCORRECT:1", ica_text="b one"),
                _make_ica(ica_id="RESP-2:CA-1-1:INCORRECT:2", ica_text="b two"),
            ],
        )
        second = _make_non_na_slot("RESP-1:CA-1-1:NOT_PROVIDED")
        slots = [first, _make_na_slot(), second]

        enriched = enrich_threats(ICAEnumeration(slots=slots))

        assert [t.ica_id for t in enriched.structural_threats] == [
            "RESP-2:CA-1-1:INCORRECT:1",
            "RESP-2:CA-1-1:INCORRECT:2",
            "RESP-1:CA-1-1:NOT_PROVIDED:1",
        ]
        assert [t.ica_slot_id for t in enriched.structural_threats] == [
            "RESP-2:CA-1-1:INCORRECT",
            "RESP-2:CA-1-1:INCORRECT",
            "RESP-1:CA-1-1:NOT_PROVIDED",
        ]

    def test_a_threat_copies_the_ica_text_and_links(self):
        ica = _make_ica(
            ica_text="The agent skips the check",
            loss_scenario="A forged request goes through",
            related_hazards=["H-1"],
            related_constraints=["SC-1"],
        )
        slot = _make_non_na_slot(icas=[ica])

        (threat,) = enrich_threats(ICAEnumeration(slots=[slot])).structural_threats

        assert threat.ica_text == "The agent skips the check"
        assert threat.hazardous_context == "Context"
        assert threat.loss_scenario == "A forged request goes through"
        assert threat.related_hazards == ["H-1"]
        assert threat.related_constraints == ["SC-1"]

    def test_the_wording_of_an_ica_changes_no_threat_field_but_its_text(self):
        """No keyword in the ICA text tags the threat: same slot, same record."""
        plain = _make_ica(ica_text="routine check", loss_scenario="no attack vector")
        loaded = _make_ica(
            ica_text="prompt injection attack", loss_scenario="attacker manipulates"
        )

        (a,) = enrich_threats(
            ICAEnumeration(slots=[_make_non_na_slot(icas=[plain])])
        ).structural_threats
        (b,) = enrich_threats(
            ICAEnumeration(slots=[_make_non_na_slot(icas=[loaded])])
        ).structural_threats

        assert set(a.model_dump()) == set(b.model_dump())


class TestCoverageAnalysis:
    """Coverage analysis tests."""

    def test_structural_coverage_counts(self):
        """Coverage analysis counts the non-N/A and N/A slots."""
        slots = [
            _make_non_na_slot(f"RESP-1:CA-1-{i + 1}:NOT_PROVIDED") for i in range(7)
        ]
        slots += [
            _make_na_slot(f"RESP-3:CA-1-{i + 1}:WRONG_DURATION", "RESP-3")
            for i in range(3)
        ]

        coverage = compute_coverage(slots)

        assert coverage.structural_coverage == {
            "total_slots": 10,
            "non_na": 7,
            "na": 3,
            "coverage_rate": 0.7,
        }

    def test_coverage_of_no_slots_is_zero(self):
        assert compute_coverage([]).structural_coverage["coverage_rate"] == 0.0

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

        coverage = compute_coverage(slots)
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

        coverage = compute_coverage(slots)
        assert coverage.by_controller["RESP-1"] == 5
        assert coverage.by_controller["RESP-2"] == 3
        assert coverage.by_controller["CL-1"] == 2


class TestNoLLMCalls:
    """The structural threat list makes no LLM calls."""

    def test_no_llm_calls(self):
        slots = [
            _make_non_na_slot("RESP-1:CA-1-1:NOT_PROVIDED"),
            _make_na_slot("RESP-1:CA-1-2:WRONG_DURATION"),
        ]
        # This is deterministic — no LLM client involved
        enriched = enrich_threats(ICAEnumeration(slots=slots))
        assert enriched is not None


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
        enriched = enrich_threats(ICAEnumeration(slots=slots))
        assert len(enriched.structural_threats) == 3
        for threat in enriched.structural_threats:
            assert threat.provenance == "structural"


class TestEnrichedThreatSetValidates:
    """Enriched threat set validates against the schema."""

    def test_validates_successfully(self):
        slots = [
            _make_non_na_slot("RESP-1:CA-1-1:NOT_PROVIDED"),
            _make_non_na_slot("RESP-1:CA-1-2:INCORRECT", uca_type=UCAType.incorrect),
            _make_na_slot("RESP-1:CA-1-3:WRONG_DURATION"),
        ]
        enriched = enrich_threats(ICAEnumeration(slots=slots))
        # Re-validate via model_dump + model_validate
        EnrichedThreatSet.model_validate(enriched.model_dump())

"""Tests for sanitizing invalid ElementRefs in assembly fallback — Sanitize-01 through Sanitize-10.

When the _assemble_with_fallback() fails because the assembled
ControlStructure contains invalid ElementRefs, the fallback path
sanitizes them via _sanitize_for_fallback(). If sanitization still
fails, a further-degraded path strips ALL ElementRefs.
"""

from __future__ import annotations


import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlledProcess,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    ResponsibilitySet,
    _assemble_with_fallback,
)


# ---------------------------------------------------------------------------
# Helpers — build ResponsibilitySets with invalid ElementRefs
# ---------------------------------------------------------------------------


def _make_resp(
    resp_id: str = "RESP-1",
    description: str = "Controller",
    *,
    with_pm: bool = True,
    with_ca: bool = True,
    with_fb: bool = True,
    pm_feedback_source: dict | None = None,
    ca_target: dict | None = None,
    fb_source: dict | None = None,
) -> Responsibility:
    """Build a responsibility with configurable ElementRef values."""
    num = resp_id.split("-")[-1]
    pm_parts = (
        [
            ProcessModelPart(
                pm_id=f"PM-{num}-1",
                description="State",
                feedback_source=(
                    ElementRef(
                        type=ReferenceType(pm_feedback_source["type"]),
                        id=pm_feedback_source["id"],
                    )
                    if pm_feedback_source
                    else None
                ),
            )
        ]
        if with_pm
        else []
    )
    ca_parts = (
        [
            ControlAction(
                ca_id=f"CA-{num}-1",
                description="Action",
                target=(
                    ElementRef(
                        type=ReferenceType(ca_target["type"]),
                        id=ca_target["id"],
                    )
                    if ca_target
                    else None
                ),
            )
        ]
        if with_ca
        else []
    )
    fb_parts = (
        [
            FeedbackChannel(
                fb_id=f"FB-{num}-1",
                description="Feedback",
                updates=f"PM-{num}-1",
                source=(
                    ElementRef(
                        type=ReferenceType(fb_source["type"]),
                        id=fb_source["id"],
                    )
                    if fb_source
                    else None
                ),
            )
        ]
        if with_fb
        else []
    )
    return Responsibility(
        resp_id=resp_id,
        description=description,
        process_model_parts=pm_parts,
        control_actions=ca_parts,
        feedback_channels=fb_parts,
    )


def _make_resp_set(
    responsibilities: list[Responsibility],
) -> ResponsibilitySet:
    """Build a ResponsibilitySet (no controlled_processes in new model)."""
    return ResponsibilitySet(
        responsibilities=responsibilities,
    )


def _empty_control_element_set() -> ControlElementSet:
    """An empty ControlElementSet (no CAs, FBs, or CPs)."""
    return ControlElementSet()


def _control_element_set_with_cps(
    cps: list,
) -> ControlElementSet:
    """A ControlElementSet with controlled processes only."""
    return ControlElementSet(
        controlled_processes=[
            ControlledProcess(cp_id=cp["cp_id"], description=cp["description"])
            for cp in cps
        ]
    )


# ---------------------------------------------------------------------------
# Sanitize-01: fallback nullifies unresolvable ElementRef in each ref field
# ---------------------------------------------------------------------------


class TestSanitize01NullifyUnresolvable:
    """Sanitize-01: fallback nullifies unresolvable ElementRef in each ref field."""

    @pytest.mark.parametrize(
        "element_type, element_id, ref_field, ref_type, ref_id",
        [
            (
                "ProcessModelPart",
                "PM-1-1",
                "feedback_source",
                "controlled_process",
                "FB-1-1",
            ),
            ("ControlAction", "CA-1-1", "target", "responsibility", "RESP-99"),
            ("FeedbackChannel", "FB-1-1", "source", "controlled_process", "CP-99"),
        ],
        ids=["pm_feedback_source", "ca_target", "fb_source"],
    )
    def test_fallback_nullifies_unresolvable_ref(
        self,
        tmp_path,
        element_type,
        element_id,
        ref_field,
        ref_type,
        ref_id,
    ):
        resp = _make_resp(
            pm_feedback_source={"type": ref_type, "id": ref_id}
            if ref_field == "feedback_source"
            else None,
            ca_target={"type": ref_type, "id": ref_id}
            if ref_field == "target"
            else None,
            fb_source={"type": ref_type, "id": ref_id}
            if ref_field == "source"
            else None,
        )
        resp_set = _make_resp_set([resp])
        ces = _empty_control_element_set()

        cs, warnings = _assemble_with_fallback(
            resp_set,
            ces,
            tmp_path,
            "test-model",
        )

        assert isinstance(cs, ControlStructure)
        resp_out = cs.responsibilities[0]
        if ref_field == "feedback_source":
            assert resp_out.process_model_parts[0].feedback_source is None
        elif ref_field == "target":
            assert resp_out.control_actions[0].target is None
        elif ref_field == "source":
            assert resp_out.feedback_channels[0].source is None


class TestSanitize02DropUnresolvableFeedbackUpdates:
    """The fallback drops a feedback channel with an unresolved local PM."""

    def test_fallback_drops_invalid_updates_and_reports_missing_id(self, tmp_path):
        resp = _make_resp()
        resp.feedback_channels[0].updates = "absent-feedback-updates"

        cs, warnings = _assemble_with_fallback(
            _make_resp_set([resp]),
            _empty_control_element_set(),
            tmp_path,
            "test-model",
        )

        assert cs.responsibilities[0].feedback_channels == []
        warning_text = " ".join(warnings)
        assert "updates" in warning_text
        assert "absent-feedback-updates" in warning_text


# ---------------------------------------------------------------------------
# Sanitize-04: valid ElementRefs are preserved during sanitization
# ---------------------------------------------------------------------------


class TestSanitize04ValidRefsPreserved:
    """Sanitize-04: valid ElementRefs are preserved during sanitization."""

    @pytest.mark.parametrize(
        "element_type, element_id, ref_field",
        [
            ("ProcessModelPart", "PM-1-1", "feedback_source"),
            ("ControlAction", "CA-1-1", "target"),
            ("FeedbackChannel", "FB-1-1", "source"),
        ],
        ids=["pm_feedback_source", "ca_target", "fb_source"],
    )
    def test_valid_refs_preserved(self, tmp_path, element_type, element_id, ref_field):
        resp = _make_resp(
            pm_feedback_source={"type": "controlled_process", "id": "CP-1"}
            if ref_field == "feedback_source"
            else None,
            ca_target={"type": "controlled_process", "id": "CP-1"}
            if ref_field == "target"
            else None,
            fb_source={"type": "controlled_process", "id": "CP-1"}
            if ref_field == "source"
            else None,
        )
        resp_set = _make_resp_set([resp])
        ces = _control_element_set_with_cps(
            [
                {"cp_id": "CP-1", "description": "Process"},
            ]
        )

        cs, warnings = _assemble_with_fallback(
            resp_set,
            ces,
            tmp_path,
            "test-model",
        )

        resp_out = cs.responsibilities[0]
        if ref_field == "feedback_source":
            assert resp_out.process_model_parts[0].feedback_source is not None
            assert resp_out.process_model_parts[0].feedback_source.id == "CP-1"
        elif ref_field == "target":
            assert resp_out.control_actions[0].target is not None
            assert resp_out.control_actions[0].target.id == "CP-1"
        elif ref_field == "source":
            assert resp_out.feedback_channels[0].source is not None
            assert resp_out.feedback_channels[0].source.id == "CP-1"


# ---------------------------------------------------------------------------
# Sanitize-05: sanitized fallback ControlStructure passes foundation validation
# ---------------------------------------------------------------------------


class TestSanitize05PassesValidation:
    """Sanitize-05: sanitized fallback ControlStructure passes foundation validation."""

    def test_sanitized_cs_passes_validation(self, tmp_path):
        resp = _make_resp(
            pm_feedback_source={"type": "controlled_process", "id": "INVALID-1"},
            ca_target={"type": "controlled_process", "id": "INVALID-2"},
        )
        resp_set = _make_resp_set([resp])
        ces = _empty_control_element_set()

        cs, warnings = _assemble_with_fallback(
            resp_set,
            ces,
            tmp_path,
            "test-model",
        )

        assert isinstance(cs, ControlStructure)
        assert cs.responsibilities[0].process_model_parts[0].feedback_source is None
        assert cs.responsibilities[0].control_actions[0].target is None


# ---------------------------------------------------------------------------
# Sanitize-06: stripped references are logged in warnings
# ---------------------------------------------------------------------------


class TestSanitize06StrippedRefsLogged:
    """Sanitize-06: stripped references are logged in warnings."""

    def test_warnings_include_stripped_refs(self, tmp_path):
        resp = _make_resp(
            pm_feedback_source={"type": "controlled_process", "id": "FB-1-1"},
            ca_target={"type": "responsibility", "id": "RESP-99"},
        )
        resp_set = _make_resp_set([resp])
        ces = _empty_control_element_set()

        cs, warnings = _assemble_with_fallback(
            resp_set,
            ces,
            tmp_path,
            "test-model",
        )

        warning_text = " ".join(warnings)
        assert "PM-1-1" in warning_text
        assert "feedback_source" in warning_text
        assert "CA-1-1" in warning_text
        assert "target" in warning_text


# ---------------------------------------------------------------------------
# Sanitize-07: fallback does not crash with completely invalid ElementRef values
# ---------------------------------------------------------------------------


class TestSanitize07NoCrashInvalidValues:
    """Sanitize-07: fallback does not crash with completely invalid ElementRef values."""

    def test_no_crash_with_all_invalid_refs(self, tmp_path):
        resp = _make_resp(
            pm_feedback_source={"type": "controlled_process", "id": "FB-1-1"},
            ca_target={"type": "controlled_process", "id": "CA-2-1"},
            fb_source={"type": "responsibility", "id": "PM-3-1"},
        )
        resp_set = _make_resp_set([resp])
        ces = _empty_control_element_set()

        cs, warnings = _assemble_with_fallback(
            resp_set,
            ces,
            tmp_path,
            "test-model",
        )

        assert isinstance(cs, ControlStructure)


# ---------------------------------------------------------------------------
# Sanitize-08: further-degraded path strips ALL ElementRefs when sanitization still fails
# ---------------------------------------------------------------------------


class TestSanitize08FurtherDegradedPath:
    """Sanitize-08: further-degraded path strips ALL ElementRefs when sanitization still fails."""

    def test_all_refs_stripped_on_further_degradation(self, tmp_path):
        # Build a ResponsibilitySet with a valid ref but duplicate responsibility IDs
        # that will fail ControlStructure validation even after sanitization
        resp1 = _make_resp(
            pm_feedback_source={"type": "controlled_process", "id": "FB-1-1"},
        )
        # Duplicate RESP-1 — causes duplicate ID validation failure
        resp2 = _make_resp(resp_id="RESP-1", description="Duplicate")
        resp_set = _make_resp_set([resp1, resp2])
        ces = _empty_control_element_set()

        cs, warnings = _assemble_with_fallback(
            resp_set,
            ces,
            tmp_path,
            "test-model",
        )

        assert isinstance(cs, ControlStructure)
        # All feedback_source fields should be None
        for resp in cs.responsibilities:
            for pm in resp.process_model_parts:
                assert pm.feedback_source is None
            for ca in resp.control_actions:
                assert ca.target is None
            for fb in resp.feedback_channels:
                assert fb.source is None

    def test_duplicate_cps_deduplicated_on_further_degradation(self, tmp_path):
        """CP dedup path in further-degraded fallback is exercised."""
        resp1 = _make_resp(
            pm_feedback_source={"type": "controlled_process", "id": "FB-1-1"},
        )
        resp2 = _make_resp(resp_id="RESP-1", description="Duplicate")
        resp_set = _make_resp_set([resp1, resp2])
        ces = _control_element_set_with_cps(
            [
                {"cp_id": "CP-1", "description": "Process A"},
                {"cp_id": "CP-1", "description": "Process A dup"},
            ]
        )

        cs, _ = _assemble_with_fallback(
            resp_set,
            ces,
            tmp_path,
            "test-model",
        )

        cp_ids = [cp.cp_id for cp in cs.controlled_processes]
        assert cp_ids.count("CP-1") == 1


# ---------------------------------------------------------------------------
# Sanitize-09: sanitized fallback preserves responsibilities and controlled processes
# ---------------------------------------------------------------------------


class TestSanitize09PreservesRespAndCp:
    """Sanitize-09: sanitized fallback preserves responsibilities and controlled processes."""

    def test_preserves_resps_and_cps(self, tmp_path):
        resp1 = _make_resp(
            resp_id="RESP-1",
            pm_feedback_source={"type": "controlled_process", "id": "INVALID-1"},
        )
        resp2 = _make_resp(resp_id="RESP-2")
        resp_set = _make_resp_set([resp1, resp2])
        ces = _control_element_set_with_cps(
            [
                {"cp_id": "CP-1", "description": "Process"},
            ]
        )

        cs, warnings = _assemble_with_fallback(
            resp_set,
            ces,
            tmp_path,
            "test-model",
        )

        resp_ids = {r.resp_id for r in cs.responsibilities}
        assert "RESP-1" in resp_ids
        assert "RESP-2" in resp_ids
        cp_ids = {cp.cp_id for cp in cs.controlled_processes}
        assert "CP-1" in cp_ids


# ---------------------------------------------------------------------------
# Sanitize-10: normal assembly success path is unchanged
# ---------------------------------------------------------------------------


class TestSanitize10NormalAssemblyUnchanged:
    """Sanitize-10: normal assembly success path is unchanged."""

    def test_successful_assembly_no_warnings(self, tmp_path):
        resp1 = _make_resp(resp_id="RESP-1")
        resp2 = _make_resp(resp_id="RESP-2")
        resp_set = _make_resp_set([resp1, resp2])
        ces = _empty_control_element_set()

        cs, warnings = _assemble_with_fallback(
            resp_set,
            ces,
            tmp_path,
            "test-model",
        )

        assert isinstance(cs, ControlStructure)
        assert warnings == []

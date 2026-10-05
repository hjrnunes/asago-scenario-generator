"""Property-based tests for SP1 bug-fix batch 3 invariants.

Covers two feature areas:

1. **Critic ID sanitization** — ``sanitize_critic_ids`` in ``critic.py``:
   no non-conforming ID survives sanitization, metadata is preserved,
   sanitization is idempotent, and clean findings are unchanged.

2. **Orphan PM repair** — ``repair_orphan_pms`` in ``control_structure.py``:
   no orphan PM survives repair, existing elements are preserved,
   repair is idempotent, no-op when no orphans, and warning count
   matches the number of repaired orphans.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ResponsibilitySet,
    repair_orphan_pms,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    _CONFORMING_PATTERNS,
    _ID_LIKE_PATTERN,
    sanitize_critic_ids,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

st_description = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=40,
)

st_remedy_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=120,
)

# ID prefixes used in the domain
_ID_PREFIXES = ["RESP", "PM", "CA", "FB", "CP", "CL", "RC"]

# Conforming ID examples (valid format per model schema)
_CONFORMING_ID_EXAMPLES = [
    "RESP-1",
    "RESP-12",
    "RESP-99",
    "PM-1-1",
    "PM-3-2",
    "PM-10-5",
    "CA-1-1",
    "CA-2-3",
    "FB-1-1",
    "FB-3-2",
    "CP-1",
    "CP-5",
    "CL-1",
    "CL-3",
    "RC-1-1",
    "RC-2-3",
]

# Non-conforming ID examples (wrong format — single-part where multi-part
# expected, or extra/missing segments)
_NON_CONFORMING_ID_EXAMPLES = [
    "PM-0",
    "CA-0",
    "FB-0",
    "RESP-0",
    "PM-1",
    "CA-2",
    "FB-3",  # missing second segment
    "CP-1-1",
    "CL-1-1",
    "RESP-1-1",  # extra segment for single-part types
    "RC-1",  # missing second segment
    "XX-1-1",  # unknown prefix (not matched by _ID_LIKE_PATTERN)
]


def _has_non_conforming_id(text: str) -> bool:
    """Return True if *text* contains any ID-like token that is non-conforming."""
    for match in _ID_LIKE_PATTERN.finditer(text):
        token = match.group()
        if not any(p.match(token) for p in _CONFORMING_PATTERNS):
            return True
    return False


# ---------------------------------------------------------------------------
# Strategies — sanitization
# ---------------------------------------------------------------------------


@st.composite
def st_remedy_with_ids(draw) -> str:
    """Generate a remedy string that may contain conforming and non-conforming IDs."""
    parts: list[str] = []
    n = draw(st.integers(min_value=0, max_value=5))
    for _ in range(n):
        choice = draw(st.sampled_from(["conforming", "non_conforming", "plain"]))
        if choice == "conforming":
            parts.append(draw(st.sampled_from(_CONFORMING_ID_EXAMPLES)))
        elif choice == "non_conforming":
            # Only use IDs that _ID_LIKE_PATTERN will actually match
            parts.append(
                draw(
                    st.sampled_from(
                        [
                            "PM-0",
                            "CA-0",
                            "FB-0",
                            "RESP-0",
                            "PM-1",
                            "CA-2",
                            "FB-3",
                            "CP-1-1",
                            "CL-1-1",
                            "RESP-1-1",
                            "RC-1",
                        ]
                    )
                )
            )
        else:
            parts.append(draw(st_remedy_text))
    if not parts:
        parts.append(draw(st_remedy_text))
    return " ".join(parts)


@st.composite
def st_critic_findings(draw) -> CriticFindings:
    """Generate a CriticFindings with 0-5 gaps and optional metadata."""
    n_gaps = draw(st.integers(min_value=0, max_value=5))
    gaps: list[CriticGap] = []
    for _ in range(n_gaps):
        gap_type = draw(
            st.sampled_from(
                [
                    "missing_responsibility",
                    "missing_feedback",
                    "missing_pm_part",
                ]
            )
        )
        gaps.append(
            CriticGap(
                gap_type=gap_type,
                description=draw(st_description),
                related_attack_path=draw(st_description),
                suggested_remedy=draw(st_remedy_with_ids()),
            )
        )
    n_checklist = draw(st.integers(min_value=0, max_value=3))
    checklist_results: dict[str, str] = {}
    for i in range(n_checklist):
        key = f"Check_{i}_{draw(st_description)}"
        checklist_results[key] = draw(
            st.sampled_from(
                [
                    "present",
                    "absent_justified",
                    "absent_unjustified",
                ]
            )
        )
    n_taxonomy = draw(st.integers(min_value=0, max_value=3))
    taxonomy_probe_results: dict[str, str] = {}
    for i in range(n_taxonomy):
        key = f"Probe_{i}_{draw(st_description)}"
        taxonomy_probe_results[key] = draw(
            st.sampled_from(
                [
                    "present",
                    "absent_justified",
                    "absent_unjustified",
                ]
            )
        )
    return CriticFindings(
        gaps=gaps,
        checklist_results=checklist_results,
        taxonomy_probe_results=taxonomy_probe_results,
    )


# ---------------------------------------------------------------------------
# Strategies — repair
# ---------------------------------------------------------------------------


def _make_resp(
    num: int,
    pm_count: int,
    fb_count: int,
    description: str,
) -> Responsibility:
    """Build a responsibility for RESP-{num} with *pm_count* PMs and *fb_count* FBs.

    FB channels are assigned to the first *fb_count* PMs (if any).
    Remaining PMs are orphans. A single CA is always added so the
    responsibility is structurally valid.
    """
    pms = [
        ProcessModelPart(
            pm_id=f"PM-{num}-{j + 1}",
            description=f"State {j + 1}",
        )
        for j in range(pm_count)
    ]
    cas = [ControlAction(ca_id=f"CA-{num}-1", description="Action")]
    fbs: list[FeedbackChannel] = []
    for j in range(min(fb_count, pm_count)):
        fbs.append(
            FeedbackChannel(
                fb_id=f"FB-{num}-{j + 1}",
                description=f"FB {j + 1}",
                updates=f"PM-{num}-{j + 1}",
            )
        )
    return Responsibility(
        resp_id=f"RESP-{num}",
        description=description,
        process_model_parts=pms,
        control_actions=cas,
        feedback_channels=fbs,
    )


@st.composite
def st_responsibility_set(draw) -> ResponsibilitySet:
    """Generate a ResponsibilitySet with 1-5 responsibilities.

    Each responsibility has 1-4 PM parts and 0 to (pm_count) FB channels,
    producing a mix of fully-covered, partially-orphan, and fully-orphan
    responsibilities.
    """
    n = draw(st.integers(min_value=1, max_value=5))
    responsibilities: list[Responsibility] = []
    for i in range(1, n + 1):
        pm_count = draw(st.integers(min_value=1, max_value=4))
        # FB count can be 0 to pm_count — 0 means all PMs are orphans
        fb_count = draw(st.integers(min_value=0, max_value=pm_count))
        desc = draw(st_description)
        responsibilities.append(_make_resp(i, pm_count, fb_count, desc))
    return ResponsibilitySet(responsibilities=responsibilities)


def _count_orphan_pms(resp_set: ResponsibilitySet) -> int:
    """Count the total number of orphan PMs across all responsibilities."""
    total = 0
    for resp in resp_set.responsibilities:
        updated = {fb.updates for fb in resp.feedback_channels}
        for pm in resp.process_model_parts:
            if pm.pm_id not in updated:
                total += 1
    return total


@st.composite
def st_no_orphan_responsibility_set(draw) -> ResponsibilitySet:
    """Generate a ResponsibilitySet where every PM has a matching FB."""
    n = draw(st.integers(min_value=1, max_value=5))
    responsibilities: list[Responsibility] = []
    for i in range(1, n + 1):
        pm_count = draw(st.integers(min_value=1, max_value=4))
        desc = draw(st_description)
        responsibilities.append(_make_resp(i, pm_count, pm_count, desc))
    return ResponsibilitySet(responsibilities=responsibilities)


# ---------------------------------------------------------------------------
# Sanitization property tests
# ---------------------------------------------------------------------------


class TestSanitizeCriticIdsProperties:
    """Property tests for sanitize_critic_ids invariants."""

    @given(findings=st_critic_findings())
    @settings(max_examples=80, deadline=None)
    def test_no_non_conforming_id_survives(self, findings: CriticFindings) -> None:
        """After sanitization, no gap's suggested_remedy contains a non-conforming ID."""
        sanitized = sanitize_critic_ids(findings)
        for gap in sanitized.gaps:
            assert not _has_non_conforming_id(gap.suggested_remedy), (
                f"Non-conforming ID found in sanitized remedy: {gap.suggested_remedy!r}"
            )

    @given(findings=st_critic_findings())
    @settings(max_examples=80, deadline=None)
    def test_preserves_checklist_and_taxonomy(self, findings: CriticFindings) -> None:
        """Sanitization preserves checklist_results and taxonomy_probe_results."""
        sanitized = sanitize_critic_ids(findings)
        assert sanitized.checklist_results == findings.checklist_results
        assert sanitized.taxonomy_probe_results == findings.taxonomy_probe_results

    @given(findings=st_critic_findings())
    @settings(max_examples=80, deadline=None)
    def test_gap_count_preserved(self, findings: CriticFindings) -> None:
        """The number of gaps is preserved by sanitization."""
        sanitized = sanitize_critic_ids(findings)
        assert len(sanitized.gaps) == len(findings.gaps)

    @given(findings=st_critic_findings())
    @settings(max_examples=80, deadline=None)
    def test_idempotence(self, findings: CriticFindings) -> None:
        """Sanitizing twice yields the same remedies as sanitizing once."""
        once = sanitize_critic_ids(findings)
        twice = sanitize_critic_ids(once)
        remedies_once = [g.suggested_remedy for g in once.gaps]
        remedies_twice = [g.suggested_remedy for g in twice.gaps]
        assert remedies_once == remedies_twice

    @given(findings=st_critic_findings())
    @settings(max_examples=80, deadline=None)
    def test_clean_findings_unchanged(self, findings: CriticFindings) -> None:
        """When all IDs are already conforming, sanitization is a no-op on remedies."""
        # Only test findings where no remedy has non-conforming IDs

        assume(
            all(not _has_non_conforming_id(g.suggested_remedy) for g in findings.gaps)
        )
        sanitized = sanitize_critic_ids(findings)
        for orig, san in zip(findings.gaps, sanitized.gaps, strict=True):
            assert orig.suggested_remedy == san.suggested_remedy

    @given(findings=st_critic_findings())
    @settings(max_examples=80, deadline=None)
    def test_gap_type_and_description_preserved(self, findings: CriticFindings) -> None:
        """Sanitization preserves gap_type, description, and related_attack_path."""
        sanitized = sanitize_critic_ids(findings)
        for orig, san in zip(findings.gaps, sanitized.gaps, strict=True):
            assert orig.gap_type == san.gap_type
            assert orig.description == san.description
            assert orig.related_attack_path == san.related_attack_path


# ---------------------------------------------------------------------------
# Repair property tests
# ---------------------------------------------------------------------------


class TestRepairOrphanPmsProperties:
    """Property tests for repair_orphan_pms invariants."""

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_no_orphan_pms_after_repair(self, resp_set: ResponsibilitySet) -> None:
        """After repair, every PM is referenced by at least one FB."""
        repaired, _ = repair_orphan_pms(resp_set)
        for resp in repaired.responsibilities:
            updated_pms = {fb.updates for fb in resp.feedback_channels}
            for pm in resp.process_model_parts:
                assert pm.pm_id in updated_pms, (
                    f"Orphan PM {pm.pm_id} survived repair in {resp.resp_id}"
                )

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_existing_pms_preserved(self, resp_set: ResponsibilitySet) -> None:
        """No existing PM is removed by repair."""
        repaired, _ = repair_orphan_pms(resp_set)
        for orig_resp, rep_resp in zip(
            resp_set.responsibilities,
            repaired.responsibilities,
            strict=True,
        ):
            orig_pm_ids = {pm.pm_id for pm in orig_resp.process_model_parts}
            rep_pm_ids = {pm.pm_id for pm in rep_resp.process_model_parts}
            assert orig_pm_ids.issubset(rep_pm_ids)

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_existing_fbs_preserved(self, resp_set: ResponsibilitySet) -> None:
        """No existing FB is removed by repair."""
        repaired, _ = repair_orphan_pms(resp_set)
        for orig_resp, rep_resp in zip(
            resp_set.responsibilities,
            repaired.responsibilities,
            strict=True,
        ):
            orig_fb_ids = {fb.fb_id for fb in orig_resp.feedback_channels}
            rep_fb_ids = {fb.fb_id for fb in rep_resp.feedback_channels}
            assert orig_fb_ids.issubset(rep_fb_ids)

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_idempotence(self, resp_set: ResponsibilitySet) -> None:
        """Repairing twice produces no warnings on the second call."""
        repaired_once, warnings_once = repair_orphan_pms(resp_set)
        repaired_twice, warnings_twice = repair_orphan_pms(repaired_once)
        assert len(warnings_twice) == 0

    @given(resp_set=st_no_orphan_responsibility_set())
    @settings(max_examples=50, deadline=None)
    def test_no_op_when_no_orphans(self, resp_set: ResponsibilitySet) -> None:
        """When there are no orphans, the same instance is returned."""
        repaired, warnings = repair_orphan_pms(resp_set)
        assert len(warnings) == 0
        assert repaired is resp_set

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_warning_count_equals_orphan_count(
        self, resp_set: ResponsibilitySet
    ) -> None:
        """The number of warnings equals the number of orphan PMs repaired."""
        orphan_count = _count_orphan_pms(resp_set)
        _, warnings = repair_orphan_pms(resp_set)
        assert len(warnings) == orphan_count

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_resp_count_preserved(self, resp_set: ResponsibilitySet) -> None:
        """The number of responsibilities is preserved by repair."""
        repaired, _ = repair_orphan_pms(resp_set)
        assert len(repaired.responsibilities) == len(resp_set.responsibilities)

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_resp_ids_preserved(self, resp_set: ResponsibilitySet) -> None:
        """Responsibility IDs are preserved in order by repair."""
        repaired, _ = repair_orphan_pms(resp_set)
        orig_ids = [r.resp_id for r in resp_set.responsibilities]
        rep_ids = [r.resp_id for r in repaired.responsibilities]
        assert orig_ids == rep_ids

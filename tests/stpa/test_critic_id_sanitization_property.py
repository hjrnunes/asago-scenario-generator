"""Property tests for ``sanitize_critic_ids`` in ``critic.py``.

No non-conforming ID survives sanitization, metadata is preserved,
sanitization is idempotent, and clean findings are unchanged.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

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

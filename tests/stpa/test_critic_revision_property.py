"""Property-based tests for SP1 critic/revision invariants.

Covers seven invariant families:

1. **Next IDs**: ``_compute_next_ids`` returns one above the highest
   number in each namespace, counted from that namespace's own IDs:
   ``next_cm_num`` depends only on ``cm_id`` values, and
   ``next_cl_num`` depends only on ``link_id`` values.
2. **Revision needs a gap**: Stage 2 requests a revision iff the
   findings contain at least one explicit structural gap. Checklist and
   taxonomy statuses remain diagnostic context.
3. **Dismissal visibility**: every ``dismissed_gaps`` entry surfaces in
   the returned warnings from ``run_revision``.
4. **Merge conservation**: when the RevisionDelta contains no
   modifications to existing elements, existing responsibilities,
   processes, and links survive in list order. Published IDs are
   assigned from those final positions, not from source IDs.
5. **All-dismissed warning**: ``run_revision`` emits exactly one
   all-dismissed warning iff the findings are non-empty, every finding
   is dismissed, and the delta carries no additions or modifications.
6. **Merge guards**: a new responsibility whose ``resp_id`` already
   exists is not added, and when a new link's ``cm_id`` collides, the
   existing link keeps its ``cm_id``. A non-colliding source ``cm_id``
   still publishes from its final position.
7. **Published IDs**: a merge publishes IDs from final positions
   instead of the delta's source IDs and rewrites references to match.
   The same merge always gives the same structure, and merging an empty
   delta into a merged structure changes nothing.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    RevisionDelta,
    _compute_next_ids,
    _merge_revision_delta,
    _stitch_revision_delta,
    run_revision,
)
from asago_scenario_generator.stpa.system_model.id_normalization import (
    normalize_control_structure_payload,
)
from asago_scenario_generator.stpa.system_model import run as run_module
from tests.stpa.sp1_helpers import MockLLMClient

_FIXTURE_SAFE = settings(
    deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)


st_description = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=40,
)


def _revise(client, cs, tmp_path):
    return run_revision(
        llm_client=client,
        control_structure=cs,
        critic_findings=_make_critic_findings_for_revision(),
        use_case_text="Test",
        run_dir=tmp_path,
    )


def _make_resp(num: int) -> Responsibility:
    """Build a fully-populated responsibility RESP-{num}.

    Every responsibility has at least one PM, one CA, and one FB so
    that structural heuristics pass after revision merge.
    """
    resp_id = f"RESP-{num}"
    return Responsibility(
        resp_id=resp_id,
        description=f"Controller {num}",
        process_model_parts=[
            ProcessModelPart(pm_id=f"PM-{num}-1", description="State")
        ],
        control_actions=[ControlAction(ca_id=f"CA-{num}-1", description="Action")],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{num}-1",
                description="Feedback",
                updates=f"PM-{num}-1",
                source=ElementRef(type=ReferenceType.responsibility, id=resp_id),
            )
        ],
    )


def _make_cl(cl_num: int, cm_num: int, resp_a: int, resp_b: int) -> CoordinationLink:
    """Build a coordination link CL-{cl_num} with CM-{cm_num}."""
    return CoordinationLink(
        link_id=f"CL-{cl_num}",
        source=f"RESP-{resp_a}",
        target=f"RESP-{resp_b}",
        shared_pm=f"PM-{resp_a}-1",
        coordination_mechanism=CoordinationMechanism(
            cm_id=f"CM-{cm_num}",
            description="Shared state",
            payload="sync",
        ),
        description="Coordination link",
    )


@st.composite
def st_control_structure(draw) -> ControlStructure:
    """Generate a valid ControlStructure with sparse ID numbers.

    Each responsibility is fully populated (PM, CA, FB). Controlled
    processes are unreferenced. When there are 2+ responsibilities, 0-3
    coordination links are added; their link_id and cm_id numbers never
    overlap, so a next ID read from the wrong field gives another answer.
    """
    resp_nums = draw(
        st.lists(
            st.integers(min_value=1, max_value=20), min_size=1, max_size=5, unique=True
        )
    )
    cp_nums = draw(
        st.lists(st.integers(min_value=1, max_value=20), max_size=3, unique=True)
    )

    coordination_links: list[CoordinationLink] = []
    if len(resp_nums) >= 2:
        n_links = draw(st.integers(min_value=0, max_value=3))
        nums = draw(
            st.lists(
                st.integers(min_value=1, max_value=20),
                min_size=2 * n_links,
                max_size=2 * n_links,
                unique=True,
            )
        )
        coordination_links = [
            _make_cl(cl_num, cm_num, resp_a=resp_nums[0], resp_b=resp_nums[1])
            for cl_num, cm_num in zip(nums[:n_links], nums[n_links:])
        ]

    return ControlStructure(
        responsibilities=[_make_resp(num) for num in resp_nums],
        controlled_processes=[
            ControlledProcess(cp_id=f"CP-{num}", description="Process")
            for num in cp_nums
        ],
        coordination_links=coordination_links,
    )


def _one_above_max(ids) -> int:
    return max((int(id_.split("-")[1]) for id_ in ids), default=0) + 1


class TestComputeNextIdsProperty:
    """Each next ID is one above the highest number in its own namespace."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_each_next_id_is_one_above_its_namespace_max(self, cs):
        links = cs.coordination_links
        assert _compute_next_ids(cs) == {
            "next_resp_num": _one_above_max(r.resp_id for r in cs.responsibilities),
            "next_cl_num": _one_above_max(cl.link_id for cl in links),
            "next_cp_num": _one_above_max(cp.cp_id for cp in cs.controlled_processes),
            "next_cm_num": _one_above_max(
                cl.coordination_mechanism.cm_id for cl in links
            ),
        }


st_status = st.sampled_from(["present", "absent_justified", "absent_unjustified"])
st_checklist_key = st.sampled_from(
    [
        "Input validation",
        "Authorization",
        "Action selection",
        "Outcome verification",
        "Context management",
        "Multi-agent coordination",
        "Human-in-the-loop",
    ]
)
st_taxonomy_key = st.sampled_from(
    [
        "RAG retrieval integrity",
        "Tool parameter validation",
        "Memory integrity",
        "Multi-agent coordination",
        "Human-in-the-loop escalation",
    ]
)


@st.composite
def st_critic_findings(draw) -> CriticFindings:
    """Generate CriticFindings with random combinations of the three probes."""
    n_checklist = draw(st.integers(min_value=0, max_value=4))
    checklist_keys = draw(
        st.lists(
            st_checklist_key, min_size=n_checklist, max_size=n_checklist, unique=True
        )
    )
    checklist_results = {key: draw(st_status) for key in checklist_keys}

    n_taxonomy = draw(st.integers(min_value=0, max_value=3))
    taxonomy_keys = draw(
        st.lists(st_taxonomy_key, min_size=n_taxonomy, max_size=n_taxonomy, unique=True)
    )
    taxonomy_results = {key: draw(st_status) for key in taxonomy_keys}

    n_gaps = draw(st.integers(min_value=0, max_value=3))
    gaps = [
        CriticGap(
            gap_type=draw(
                st.sampled_from(
                    ["missing_responsibility", "missing_feedback", "missing_pm_part"]
                )
            ),
            description=f"Gap {i}",
            related_attack_path=f"Attack {i}",
            suggested_remedy=f"Fix {i}",
        )
        for i in range(n_gaps)
    ]

    return CriticFindings(
        gaps=gaps,
        checklist_results=checklist_results,
        taxonomy_probe_results=taxonomy_results,
    )


def _revision_attempted(findings: CriticFindings, run_dir) -> bool:
    """Return whether Stage 2 asks for a revision of these critic findings."""
    baseline = _make_base_cs()
    with patch.object(
        run_module, "run_revision", return_value=(baseline, [])
    ) as revision:
        run_module._maybe_apply_revision(
            baseline,
            critic_findings=findings,
            llm_client=MockLLMClient(),
            use_case_text="Test use case",
            run_dir=run_dir,
            loss_analysis=None,
            loader=None,
            temperature=0.0,
        )
    return revision.called


class TestRevisionNeedsAnExplicitGap:
    """Only explicit structural gaps authorize revision."""

    @given(findings=st_critic_findings())
    @settings(_FIXTURE_SAFE, max_examples=100)
    def test_revision_iff_at_least_one_gap(self, findings, tmp_path):
        """Probe statuses alone do not authorize revision."""
        assert _revision_attempted(findings, tmp_path) == bool(findings.gaps)


st_dismissal_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=60,
).filter(lambda value: bool(value.strip()))


def _make_base_cs() -> ControlStructure:
    """Build a minimal valid CS for revision tests."""
    return ControlStructure(
        responsibilities=[_make_resp(1), _make_resp(2)],
        coordination_links=[_make_cl(1, 1, 1, 2)],
    )


def _make_critic_findings_for_revision() -> CriticFindings:
    """Findings that trigger revision (at least one unjustified gap)."""
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_responsibility",
                description="Missing input validation",
                related_attack_path="Attacker sends crafted input",
                suggested_remedy="Add input validation responsibility",
            ),
            CriticGap(
                gap_type="missing_feedback",
                description="Missing outcome feedback",
                related_attack_path="The selected action has no outcome check",
                suggested_remedy="Add an outcome feedback channel",
            ),
        ],
        checklist_results={"Input validation": "absent_unjustified"},
        taxonomy_probe_results={},
    )


class TestDismissalVisibility:
    """Every dismissed_gaps entry surfaces in run_revision warnings."""

    @given(dismissals=st.lists(st_dismissal_text, min_size=0, max_size=5, unique=True))
    @settings(_FIXTURE_SAFE, max_examples=50)
    def test_each_dismissal_warns_once(self, tmp_path, dismissals):
        """Each dismissal appears in the warnings, one warning per dismissal."""
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            {
                "new_responsibilities": [],
                "new_controlled_processes": [],
                "new_coordination_links": [],
                "modified_responsibilities": [],
                "dismissed_gaps": dismissals,
            },
        )
        _, warnings = _revise(client, _make_base_cs(), tmp_path)
        warning_text = " ".join(warnings)
        for d in dismissals:
            assert d in warning_text, (
                f"Dismissal '{d}' not found in warnings: {warnings}"
            )
        dismissal_warnings = [
            w for w in warnings if w.startswith("Revision dismissed finding:")
        ]
        assert len(dismissal_warnings) == len(dismissals)


@st.composite
def st_cs_with_links(draw) -> ControlStructure:
    """Generate a CS with 2-5 responsibilities and 0-3 coordination links."""
    n_resps = draw(st.integers(min_value=2, max_value=5))
    responsibilities = [_make_resp(i) for i in range(1, n_resps + 1)]

    n_links = draw(st.integers(min_value=0, max_value=3))
    cl_nums = draw(
        st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=n_links,
            max_size=n_links,
            unique=True,
        )
    )
    cm_nums = draw(
        st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=n_links,
            max_size=n_links,
            unique=True,
        )
    )
    coordination_links = [
        _make_cl(cl_num, cm_num, 1, 2) for cl_num, cm_num in zip(cl_nums, cm_nums)
    ]
    return ControlStructure(
        responsibilities=responsibilities,
        coordination_links=coordination_links,
    )


class TestMergeConservation:
    """When the delta has no modifications, existing elements survive in order."""

    @given(cs=st_cs_with_links())
    @settings(_FIXTURE_SAFE, max_examples=50)
    def test_empty_delta_keeps_every_element_in_order(self, tmp_path, cs):
        """An empty-delta revision keeps the structure it was given.

        A delta that adds and restates nothing is not merged, so no element,
        ID, or content changes; the source IDs are not renumbered either.
        """
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            {
                "new_responsibilities": [],
                "new_controlled_processes": [],
                "new_coordination_links": [],
                "modified_responsibilities": [],
                "dismissed_gaps": [],
            },
        )
        revised, _ = _revise(client, cs, tmp_path)
        assert revised is cs


ALL_DISMISSED_FRAGMENT = "dismissed all findings"


def _revision_warnings(
    tmp_path,
    *,
    delta: RevisionDelta,
    findings: CriticFindings,
    control_structure: ControlStructure | None = None,
) -> list[str]:
    """Run a revision with a canned delta and return the warnings."""
    client = MockLLMClient()
    client.set_response_for(RevisionDelta, delta.model_dump())
    _, warnings = run_revision(
        llm_client=client,
        control_structure=control_structure or _make_base_cs(),
        critic_findings=findings,
        use_case_text="Test",
        run_dir=tmp_path,
    )
    return warnings


def _count_all_dismissed(warnings: list[str]) -> int:
    return sum(1 for w in warnings if ALL_DISMISSED_FRAGMENT in w)


def _dismiss_all(findings: CriticFindings) -> list[str]:
    """One dismissal justification per actionable gap in *findings*."""
    return [f"finding {i + 1} is a false positive" for i in range(len(findings.gaps))]


class TestAllDismissedWarning:
    """A revision that dismisses everything and changes nothing warns once."""

    def test_partial_dismissal_does_not_warn(self, tmp_path):
        findings = _make_critic_findings_for_revision()
        partial = _dismiss_all(findings)[:-1]
        assert partial, "fixture must have more than one finding"
        warnings = _revision_warnings(
            tmp_path,
            delta=RevisionDelta(dismissed_gaps=partial),
            findings=findings,
        )
        assert _count_all_dismissed(warnings) == 0, warnings

    def test_no_dismissals_does_not_warn(self, tmp_path):
        findings = _make_critic_findings_for_revision()
        warnings = _revision_warnings(
            tmp_path, delta=RevisionDelta(), findings=findings
        )
        assert _count_all_dismissed(warnings) == 0, warnings

    @pytest.mark.parametrize(
        "change_field,change_value",
        [
            ("new_responsibilities", [_make_resp(3)]),
            (
                "new_controlled_processes",
                [ControlledProcess(cp_id="CP-2", description="New process")],
            ),
            ("new_coordination_links", [_make_cl(2, 2, 1, 2)]),
            ("modified_responsibilities", [_make_resp(1)]),
        ],
    )
    def test_any_change_suppresses_warning(self, tmp_path, change_field, change_value):
        findings = _make_critic_findings_for_revision()
        delta = RevisionDelta(
            dismissed_gaps=_dismiss_all(findings),
            **{change_field: change_value},
        )
        warnings = _revision_warnings(tmp_path, delta=delta, findings=findings)
        assert _count_all_dismissed(warnings) == 0, warnings

    def test_per_dismissal_warnings_and_structure_preserved(self, tmp_path):
        findings = _make_critic_findings_for_revision()
        dismissals = _dismiss_all(findings)
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            RevisionDelta(dismissed_gaps=dismissals).model_dump(),
        )
        cs = _make_base_cs()
        revised, warnings = run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        per_dismissal = [
            w for w in warnings if w.startswith("Revision dismissed finding:")
        ]
        assert len(per_dismissal) == len(dismissals)
        for justification in dismissals:
            assert any(justification in w for w in per_dismissal)
        assert [r.resp_id for r in revised.responsibilities] == [
            r.resp_id for r in cs.responsibilities
        ]
        assert [cl.link_id for cl in revised.coordination_links] == [
            cl.link_id for cl in cs.coordination_links
        ]

    def test_warning_is_actionable(self, tmp_path):
        findings = _make_critic_findings_for_revision()
        warnings = _revision_warnings(
            tmp_path,
            delta=RevisionDelta(dismissed_gaps=_dismiss_all(findings)),
            findings=findings,
        )
        warning = next(w for w in warnings if ALL_DISMISSED_FRAGMENT in w)
        assert not warning.startswith("Revision dismissed finding:")
        assert "no changes" in warning

    @given(findings=st_critic_findings(), extra_dismissals=st.integers(0, 3))
    @settings(_FIXTURE_SAFE, max_examples=50)
    def test_warns_iff_findings_all_dismissed_without_changes(
        self, tmp_path, findings, extra_dismissals
    ):
        """The warning fires exactly when findings exist and all are dismissed."""
        required = _dismiss_all(findings)
        dismissals = required + [f"extra {i}" for i in range(extra_dismissals)]
        warnings = _revision_warnings(
            tmp_path,
            delta=RevisionDelta(dismissed_gaps=dismissals),
            findings=findings,
        )
        expected = 1 if required else 0
        assert _count_all_dismissed(warnings) == expected, warnings


class TestMergeGuardCorrectness:
    """The merge guards in _add_new_items and _renumber_colliding_cm_ids
    behave correctly under mutations that invert their skip/collision
    conditions."""

    def test_duplicate_resp_id_is_skipped(self, tmp_path):
        """A new_responsibility whose resp_id already exists is not added."""
        cs = _make_base_cs()
        dup_resp = _make_resp(1)  # RESP-1 already in cs
        dup_resp = dup_resp.model_copy(update={"description": "DUPLICATE description"})
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            RevisionDelta(new_responsibilities=[dup_resp]).model_dump(),
        )
        revised, _ = _revise(client, cs, tmp_path)
        resp_ids = [r.resp_id for r in revised.responsibilities]
        assert resp_ids.count("RESP-1") == 1, (
            f"Expected exactly one RESP-1 but got: {resp_ids}"
        )
        resp1 = next(r for r in revised.responsibilities if r.resp_id == "RESP-1")
        assert "DUPLICATE" not in resp1.description, (
            "Duplicate responsibility should have been skipped — original "
            "description must be preserved."
        )

    def test_existing_link_cm_id_preserved_on_collision(self, tmp_path):
        """When a new link's cm_id collides, the existing link's cm_id
        is preserved (not renumbered)."""
        cs = _make_base_cs()  # CL-1 with CM-1
        new_cl = _make_cl(2, 1, 1, 2)  # CL-2 with CM-1 (collision)
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            RevisionDelta(new_coordination_links=[new_cl]).model_dump(),
        )
        revised, warnings = _revise(client, cs, tmp_path)
        cl1 = next(cl for cl in revised.coordination_links if cl.link_id == "CL-1")
        assert cl1.coordination_mechanism.cm_id == "CM-1", (
            f"Existing link CL-1 cm_id should be preserved as CM-1 but got "
            f"{cl1.coordination_mechanism.cm_id}"
        )
        assert any("Renumber" in w for w in warnings), (
            f"Expected a renumber warning but got: {warnings}"
        )
        cl2 = next(cl for cl in revised.coordination_links if cl.link_id == "CL-2")
        assert cl2.coordination_mechanism.cm_id == "CM-2", (
            f"Colliding new link CL-2 should be renumbered to CM-2 but got "
            f"{cl2.coordination_mechanism.cm_id}"
        )

    def test_non_colliding_new_cm_id_preserved(self, tmp_path):
        """A non-colliding source cm_id still publishes from final position.

        The LLM-chosen ``CM-5`` is a stitch-time source ID.  After the
        new link is appended, it occupies list position 2, so the
        published mechanism ID is ``CM-2``.  Non-ID content is
        conserved and the stitch helper must not emit a collision
        warning for a unique source cm_id.
        """
        cs = _make_base_cs()  # CL-1 with CM-1
        new_cl = _make_cl(2, 5, 1, 2)  # source CL-2 / CM-5 (no collision)
        client = MockLLMClient()
        client.set_response_for(
            RevisionDelta,
            RevisionDelta(new_coordination_links=[new_cl]).model_dump(),
        )
        revised, warnings = _revise(client, cs, tmp_path)
        assert [cl.link_id for cl in revised.coordination_links] == ["CL-1", "CL-2"]
        cl2 = next(cl for cl in revised.coordination_links if cl.link_id == "CL-2")
        assert cl2.coordination_mechanism.cm_id == "CM-2", (
            "New link in final position 2 must publish CM-2, not the "
            f"source cm_id CM-5; got {cl2.coordination_mechanism.cm_id}"
        )
        assert cl2.source == new_cl.source
        assert cl2.target == new_cl.target
        assert cl2.shared_pm == new_cl.shared_pm
        assert cl2.description == new_cl.description
        assert cl2.coordination_mechanism.payload == (
            new_cl.coordination_mechanism.payload
        )
        assert not any("Renumber" in w for w in warnings), (
            f"Expected no stitch-time collision warnings but got: {warnings}"
        )


def _unvalidated_new_resp(source_prefix: str, index: int) -> Responsibility:
    """Build a new responsibility whose source IDs are non-canonical."""
    source_resp = f"{source_prefix}-resp-{index}"
    source_pm = f"{source_prefix}-pm-{index}"
    return Responsibility.model_construct(
        resp_id=source_resp,
        description=f"Added controller {index}",
        process_model_parts=[
            ProcessModelPart.model_construct(
                pm_id=source_pm,
                description=f"Added state {index}",
            )
        ],
        control_actions=[
            ControlAction.model_construct(
                ca_id=f"{source_prefix}-ca-{index}",
                description=f"Added action {index}",
                target=ElementRef.model_construct(
                    type=ReferenceType.controlled_process,
                    id=f"{source_prefix}-cp",
                ),
            )
        ],
        feedback_channels=[
            FeedbackChannel.model_construct(
                fb_id=f"{source_prefix}-fb-{index}",
                description=f"Added feedback {index}",
                updates=source_pm,
                source=ElementRef.model_construct(
                    type=ReferenceType.controlled_process,
                    id=f"{source_prefix}-cp",
                ),
            )
        ],
    )


class TestRevisionDeltaPublishedIds:
    """Stitched source IDs are not published; final position is."""

    @given(
        n_existing=st.integers(min_value=1, max_value=3),
        n_new=st.integers(min_value=1, max_value=2),
        prefix=st.from_regex(r"[a-z]{3,8}", fullmatch=True),
    )
    @settings(max_examples=30, deadline=None)
    def test_merged_ids_are_deterministic_from_final_position(
        self, n_existing, n_new, prefix
    ):
        cs = ControlStructure(
            responsibilities=[_make_resp(i) for i in range(1, n_existing + 1)]
        )
        delta = RevisionDelta.model_construct(
            new_responsibilities=[
                _unvalidated_new_resp(prefix, index) for index in range(1, n_new + 1)
            ],
            new_controlled_processes=[
                ControlledProcess.model_construct(
                    cp_id=f"{prefix}-cp",
                    description="Added process",
                )
            ],
        )

        first, _ = _merge_revision_delta(cs, delta)
        second, _ = _merge_revision_delta(cs, delta)

        expected_resp_ids = [
            f"RESP-{index}" for index in range(1, n_existing + n_new + 1)
        ]
        assert [resp.resp_id for resp in first.responsibilities] == expected_resp_ids
        assert [resp.resp_id for resp in second.responsibilities] == expected_resp_ids
        assert first.controlled_processes[0].cp_id == "CP-1"
        assert second.model_dump() == first.model_dump()

    @given(
        n_existing=st.integers(min_value=1, max_value=3),
        prefix=st.from_regex(r"[a-z]{3,8}", fullmatch=True),
    )
    @settings(max_examples=25, deadline=None)
    def test_unique_source_ids_resolve_after_merge(self, n_existing, prefix):
        cs = ControlStructure(
            responsibilities=[_make_resp(i) for i in range(1, n_existing + 1)]
        )
        added = _unvalidated_new_resp(prefix, 1)
        delta = RevisionDelta.model_construct(
            new_responsibilities=[added],
            new_controlled_processes=[
                ControlledProcess.model_construct(
                    cp_id=f"{prefix}-cp",
                    description="Added process",
                )
            ],
        )

        stitched, _ = _stitch_revision_delta(cs, delta)
        mapping = normalize_control_structure_payload(stitched).mapping
        merged, _ = _merge_revision_delta(cs, delta)

        added_index = n_existing + 1
        assert mapping[added.resp_id] == f"RESP-{added_index}"
        assert mapping[added.process_model_parts[0].pm_id] == f"PM-{added_index}-1"
        assert mapping[f"{prefix}-cp"] == "CP-1"

        published = merged.responsibilities[-1]
        assert published.control_actions[0].target == ElementRef(
            type=ReferenceType.controlled_process, id="CP-1"
        )
        assert published.feedback_channels[0].source == ElementRef(
            type=ReferenceType.controlled_process, id="CP-1"
        )
        assert published.feedback_channels[0].updates == f"PM-{added_index}-1"

    @given(n_existing=st.integers(min_value=1, max_value=4))
    @settings(max_examples=20, deadline=None)
    def test_canonical_merged_structure_is_idempotent(self, n_existing):
        cs = ControlStructure(
            responsibilities=[_make_resp(i) for i in range(1, n_existing + 1)]
        )
        once, _ = _merge_revision_delta(cs, RevisionDelta())
        twice, _ = _merge_revision_delta(once, RevisionDelta())
        assert twice.model_dump() == once.model_dump()
        assert [resp.resp_id for resp in twice.responsibilities] == [
            f"RESP-{index}" for index in range(1, n_existing + 1)
        ]

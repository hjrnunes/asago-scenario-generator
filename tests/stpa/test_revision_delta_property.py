"""Property tests for ``_merge_revision_delta`` and coordination-ID renumbering.

Conservation of existing elements, non-mutation of the original control
structure, idempotence (an empty delta is the identity), modified-responsibility
replacement by ``resp_id``, and collision-free CL and CM renumbering.
"""

from __future__ import annotations


from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ControlledProcess,
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
    _merge_revision_delta,
    run_revision,
)
from tests.stpa.sp1_helpers import MockLLMClient


# ---------------------------------------------------------------------------
# 2. RevisionDelta merge property tests
# ---------------------------------------------------------------------------


def _make_cs(n_resps: int = 2) -> ControlStructure:
    """Build a ControlStructure with n responsibilities."""
    responsibilities = []
    for i in range(1, n_resps + 1):
        responsibilities.append(
            Responsibility(
                resp_id=f"RESP-{i}",
                description=f"Controller {i}",
                process_model_parts=[
                    ProcessModelPart(pm_id=f"PM-{i}-1", description=f"State {i}")
                ],
                control_actions=[
                    ControlAction(ca_id=f"CA-{i}-1", description=f"Action {i}")
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id=f"FB-{i}-1",
                        description=f"FB {i}",
                        updates=f"PM-{i}-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id=f"RESP-{i}"
                        ),
                    )
                ],
            )
        )
    return ControlStructure(responsibilities=responsibilities)


def _make_new_resp(resp_num: int) -> Responsibility:
    """Build a new responsibility with the given number."""
    return Responsibility(
        resp_id=f"RESP-{resp_num}",
        description=f"New controller {resp_num}",
        process_model_parts=[
            ProcessModelPart(pm_id=f"PM-{resp_num}-1", description="New state")
        ],
        control_actions=[
            ControlAction(ca_id=f"CA-{resp_num}-1", description="New action")
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{resp_num}-1",
                description="New FB",
                updates=f"PM-{resp_num}-1",
                source=ElementRef(
                    type=ReferenceType.responsibility, id=f"RESP-{resp_num}"
                ),
            )
        ],
    )


class TestMergeRevisionDeltaProperties:
    """Property tests for _merge_revision_delta invariants."""

    @given(
        n_existing=st.integers(min_value=1, max_value=4),
        n_new=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=25, deadline=None)
    def test_conserves_existing_responsibilities(self, n_existing, n_new):
        """Conservation: all existing resp_ids appear in the merged output."""
        cs = _make_cs(n_existing)
        new_resps = [_make_new_resp(n_existing + i + 1) for i in range(n_new)]
        delta = RevisionDelta(new_responsibilities=new_resps)
        merged, _ = _merge_revision_delta(cs, delta)
        existing_ids = {r.resp_id for r in cs.responsibilities}
        merged_ids = {r.resp_id for r in merged.responsibilities}
        assert existing_ids.issubset(merged_ids)

    @given(
        n_existing=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=15, deadline=None)
    def test_empty_delta_is_identity(self, n_existing):
        """Idempotence: merging an empty delta preserves the CS unchanged."""
        cs = _make_cs(n_existing)
        delta = RevisionDelta()
        merged, _ = _merge_revision_delta(cs, delta)
        merged_ids = {r.resp_id for r in merged.responsibilities}
        original_ids = {r.resp_id for r in cs.responsibilities}
        assert merged_ids == original_ids
        assert len(merged.responsibilities) == len(cs.responsibilities)

    @given(
        n_existing=st.integers(min_value=1, max_value=4),
        n_new=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=20, deadline=None)
    def test_does_not_mutate_original_cs(self, n_existing, n_new):
        """Non-mutation: the original ControlStructure is not modified."""
        cs = _make_cs(n_existing)
        original_count = len(cs.responsibilities)
        original_ids = [r.resp_id for r in cs.responsibilities]
        new_resps = [_make_new_resp(n_existing + i + 1) for i in range(n_new)]
        delta = RevisionDelta(new_responsibilities=new_resps)
        _merge_revision_delta(cs, delta)
        assert len(cs.responsibilities) == original_count
        assert [r.resp_id for r in cs.responsibilities] == original_ids

    @given(
        n_existing=st.integers(min_value=2, max_value=5),
    )
    @settings(max_examples=20, deadline=None)
    def test_modified_responsibilities_replace_by_id(self, n_existing):
        """Replacement: modified responsibilities replace existing ones by resp_id."""
        cs = _make_cs(n_existing)
        # Modify RESP-1
        modified = Responsibility(
            resp_id="RESP-1",
            description="Updated controller",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="Updated state")
            ],
            control_actions=[
                ControlAction(ca_id="CA-1-1", description="Updated action")
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="Updated FB",
                    updates="PM-1-1",
                    source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                )
            ],
        )
        delta = RevisionDelta(modified_responsibilities=[modified])
        merged, _ = _merge_revision_delta(cs, delta)
        resp1 = next(r for r in merged.responsibilities if r.resp_id == "RESP-1")
        assert resp1.description == "Updated controller"
        # Other responsibilities should be unchanged
        resp2 = next(r for r in merged.responsibilities if r.resp_id == "RESP-2")
        assert resp2.description == "Controller 2"

    @given(
        n_existing=st.integers(min_value=1, max_value=3),
        n_new_cps=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=20, deadline=None)
    def test_new_cps_merged(self, n_existing, n_new_cps):
        """Conservation: new controlled processes appear in merged output."""
        cs = _make_cs(n_existing)
        new_cps = [
            ControlledProcess(cp_id=f"CP-{i + 1}", description=f"New CP {i + 1}")
            for i in range(n_new_cps)
        ]
        delta = RevisionDelta(new_controlled_processes=new_cps)
        merged, _ = _merge_revision_delta(cs, delta)
        merged_cp_ids = {cp.cp_id for cp in merged.controlled_processes}
        for cp in new_cps:
            assert cp.cp_id in merged_cp_ids

    @given(
        n_existing=st.integers(min_value=1, max_value=3),
        n_new_cls=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=20, deadline=None)
    def test_new_cls_merged(self, n_existing, n_new_cls):
        """Conservation: new coordination links appear in merged output."""
        cs = _make_cs(max(n_existing, 2))
        new_cls = [
            CoordinationLink(
                link_id=f"CL-{i + 1}",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id=f"CM-{i + 1}",
                    description=f"Mechanism {i + 1}",
                    payload="Payload",
                ),
                description=f"Link {i + 1}",
            )
            for i in range(n_new_cls)
        ]
        delta = RevisionDelta(new_coordination_links=new_cls)
        merged, _ = _merge_revision_delta(cs, delta)
        merged_cl_ids = {cl.link_id for cl in merged.coordination_links}
        for cl in new_cls:
            assert cl.link_id in merged_cl_ids

    @given(
        n_existing=st.integers(min_value=1, max_value=4),
    )
    @settings(max_examples=15, deadline=None)
    def test_duplicate_new_resps_skipped(self, n_existing):
        """Deduplication: new responsibilities with existing IDs are skipped."""
        cs = _make_cs(n_existing)
        # Try to add a resp with an existing ID
        dup_resp = _make_new_resp(1)  # RESP-1 already exists
        delta = RevisionDelta(new_responsibilities=[dup_resp])
        merged, _ = _merge_revision_delta(cs, delta)
        # Should still have only n_existing responsibilities
        assert len(merged.responsibilities) == n_existing


# ---------------------------------------------------------------------------
# 2b. cm_id renumbering property tests
# ---------------------------------------------------------------------------


def _make_cs_with_cls(n_cls: int = 2) -> ControlStructure:
    """Build a ControlStructure with two responsibilities and n coordination links.

    Links use CM-1, CM-2, ... so new links with those cm_ids will collide.
    """
    resps = [
        Responsibility(
            resp_id=f"RESP-{i}",
            description=f"Controller {i}",
            process_model_parts=[
                ProcessModelPart(pm_id=f"PM-{i}-1", description=f"State {i}")
            ],
            control_actions=[
                ControlAction(ca_id=f"CA-{i}-1", description=f"Action {i}")
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id=f"FB-{i}-1",
                    description=f"FB {i}",
                    updates=f"PM-{i}-1",
                    source=ElementRef(
                        type=ReferenceType.responsibility, id=f"RESP-{i}"
                    ),
                )
            ],
        )
        for i in range(1, 3)
    ]
    links = [
        CoordinationLink(
            link_id=f"CL-{i}",
            source="RESP-1",
            target="RESP-2",
            shared_pm="PM-2-1" if i % 2 == 0 else "PM-1-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id=f"CM-{i}",
                description=f"Mechanism {i}",
                payload=f"Payload {i}",
            ),
            description=f"Link {i}",
        )
        for i in range(1, n_cls + 1)
    ]
    return ControlStructure(responsibilities=resps, coordination_links=links)


def _make_new_cl(
    cl_num: int,
    cm_id: str,
    *,
    source: str = "RESP-1",
    target: str = "RESP-2",
    shared_pm: str = "PM-1-1",
    description: str = "New link",
    payload: str = "new payload",
    mech_desc: str = "New mechanism",
) -> CoordinationLink:
    """Build a new CoordinationLink with the given link_id and cm_id."""
    return CoordinationLink(
        link_id=f"CL-{cl_num}",
        source=source,
        target=target,
        shared_pm=shared_pm,
        coordination_mechanism=CoordinationMechanism(
            cm_id=cm_id,
            description=mech_desc,
            payload=payload,
        ),
        description=description,
    )


def _make_critic_findings() -> CriticFindings:
    """Build minimal critic findings for run_revision."""
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_responsibility",
                description="Missing validation",
                related_attack_path="Attacker sends crafted input",
                suggested_remedy="Add input validation responsibility",
            )
        ],
        checklist_results={"input_validation": "absent_unjustified"},
    )


class TestCmIdRenumberingProperties:
    """Property tests for cm_id collision renumbering invariants."""

    @given(
        n_existing_cls=st.integers(min_value=1, max_value=4),
        n_new_cls=st.integers(min_value=1, max_value=4),
    )
    @settings(max_examples=30, deadline=None)
    def test_no_duplicate_cm_ids_after_merge(self, n_existing_cls, n_new_cls):
        """Invariant: the merged structure never contains duplicate cm_ids.

        New links all use CM-1 (guaranteed collision with the first
        existing link). After merge + renumbering, every cm_id is unique.
        """
        cs = _make_cs_with_cls(n_existing_cls)
        new_cls = [
            _make_new_cl(n_existing_cls + i + 1, "CM-1") for i in range(n_new_cls)
        ]
        delta = RevisionDelta(new_coordination_links=new_cls)
        merged, _ = _merge_revision_delta(cs, delta)
        cm_ids = [cl.coordination_mechanism.cm_id for cl in merged.coordination_links]
        assert len(cm_ids) == len(set(cm_ids)), f"Duplicate cm_ids found: {cm_ids}"

    @given(
        n_existing_cls=st.integers(min_value=1, max_value=3),
        n_new=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=25, deadline=None)
    def test_renumbering_preserves_non_cm_id_content(self, n_existing_cls, n_new):
        """Invariant: renumbering never alters a link's non-cm_id content.

        Each new link gets distinct source/target/shared_pm/description/
        payload so we can verify they survive renumbering unchanged.
        """
        cs = _make_cs_with_cls(n_existing_cls)
        new_cls = [
            _make_new_cl(
                n_existing_cls + i + 1,
                "CM-1",  # collides with existing CM-1
                source="RESP-2",
                target="RESP-1",
                shared_pm="PM-2-1",
                description=f"Unique desc {i}",
                payload=f"Unique payload {i}",
                mech_desc=f"Unique mech {i}",
            )
            for i in range(n_new)
        ]
        delta = RevisionDelta(new_coordination_links=new_cls)
        merged, _ = _merge_revision_delta(cs, delta)

        # Find the new links by link_id
        new_link_ids = {cl.link_id for cl in new_cls}
        merged_new = [
            cl for cl in merged.coordination_links if cl.link_id in new_link_ids
        ]
        assert len(merged_new) == n_new

        for original, renumbered in zip(new_cls, merged_new, strict=False):
            assert renumbered.source == original.source
            assert renumbered.target == original.target
            assert renumbered.shared_pm == original.shared_pm
            assert renumbered.description == original.description
            assert renumbered.coordination_mechanism.description == (
                original.coordination_mechanism.description
            )
            assert renumbered.coordination_mechanism.payload == (
                original.coordination_mechanism.payload
            )
            # cm_id should have changed (was CM-1, now something else)
            assert renumbered.coordination_mechanism.cm_id != "CM-1"

    @given(
        n_existing_cls=st.integers(min_value=0, max_value=3),
        n_new=st.integers(min_value=0, max_value=4),
        collide=st.booleans(),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_run_revision_never_raises(self, tmp_path, n_existing_cls, n_new, collide):
        """Invariant: run_revision never raises regardless of delta shape.

        Uses a mock LLM client that returns a RevisionDelta with new
        coordination links. When *collide* is True, all new links use
        CM-1 (which collides if existing links have CM-1). When False,
        new links use unique cm_ids starting after the existing max.
        """
        n_resps = max(n_existing_cls, 2)  # need >=2 resps for valid CLs
        cs = _make_cs(n_resps)
        if n_existing_cls > 0:
            # Rebuild with coordination links
            cs = _make_cs_with_cls(n_existing_cls)
            # _make_cs_with_cls always creates 2 responsibilities
            n_resps = 2

        if collide and n_existing_cls > 0:
            cm_start = 1  # CM-1 collides
        else:
            cm_start = n_existing_cls + 1

        new_cls = [
            _make_new_cl(n_existing_cls + i + 1, f"CM-{cm_start + i}")
            for i in range(n_new)
        ]
        # Wrap new links in dicts for the mock client ( RevisionDelta
        # is parsed from dict by call_with_policy).
        new_cl_dicts = [
            {
                "link_id": cl.link_id,
                "source": cl.source,
                "target": cl.target,
                "shared_pm": cl.shared_pm,
                "coordination_mechanism": {
                    "cm_id": cl.coordination_mechanism.cm_id,
                    "description": cl.coordination_mechanism.description,
                    "payload": cl.coordination_mechanism.payload,
                },
                "description": cl.description,
            }
            for cl in new_cls
        ]
        delta_dict = {"new_coordination_links": new_cl_dicts}

        client = MockLLMClient()
        client.set_response_for(RevisionDelta, delta_dict)

        # run_revision must not raise — the degradation guard catches
        # any merge exception and returns (pre-revision-cs, [warning]).
        revised, warnings = run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        assert isinstance(revised, ControlStructure)
        assert isinstance(warnings, list)

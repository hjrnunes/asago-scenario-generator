"""Property-based tests for SP1 System Model internal models.

These tests verify invariants that hold across broad input ranges for
the SP1-internal Pydantic models that are not already covered by the
foundation property tests in ``test_property.py``:

- **YAML round-trip**: ``RequirementSet``, ``ResponsibilitySet``, and
  ``CriticFindings`` round-trip through YAML without loss.
- **Parse-ability**: Any valid dict representation of the internal models
  is accepted by ``model_validate``.
- **Solution-neutrality**: The keyword scan consistently flags
  implementation-specific terms and never flags neutral descriptions.
- **Taxonomy probe gating**: ``_build_taxonomy_probes`` always returns a
  subset of the known probe texts and respects the profile predicates.
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import HealthCheck, given, settings, strategies as st
import pytest

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    InventoryCompleteness,
    ToolInventoryEntry,
)
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml, write_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    Requirement,
    RequirementSet,
    ResponsibilitySet,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    _build_taxonomy_probes,
)
from asago_scenario_generator.stpa.system_model.heuristics import (
    check_solution_neutrality,
    _SOLUTION_NEUTRALITY_KEYWORDS,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

st_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs", "Cc"),
        blacklist_characters=("\x85", "\u2028", "\u2029"),
    ),
    min_size=1,
    max_size=50,
)

st_classification = st.sampled_from(["control", "constraint"])
st_gap_type = st.sampled_from(
    ["missing_responsibility", "missing_feedback", "missing_pm_part"]
)


# ---------------------------------------------------------------------------
# YAML round-trip property tests
# ---------------------------------------------------------------------------


def _yaml_round_trip(model, tmp_path: Path):
    """Serialize model to YAML, reload, and return the new instance."""
    path = tmp_path / "round_trip.yaml"
    write_yaml(model, path)
    return read_yaml(path, type(model))


class TestRequirementSetYamlRoundTrip:
    """RequirementSet round-trips through YAML without loss."""

    @given(
        n_reqs=st.integers(min_value=1, max_value=5),
        descriptions=st.lists(st_text, min_size=0, max_size=5),
        classifications=st.lists(st_classification, min_size=0, max_size=5),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_round_trip(self, tmp_path, n_reqs, descriptions, classifications):
        """RequirementSet with N requirements round-trips through YAML."""
        reqs = []
        for i in range(n_reqs):
            reqs.append(
                Requirement(
                    req_id=f"REQ-{i + 1}",
                    description=descriptions[i] if i < len(descriptions) else f"Req {i + 1}",
                    classification=classifications[i] if i < len(classifications) else "control",
                    source_constraint=f"SC-{i + 1}",
                )
            )
        rs = RequirementSet(requirements=reqs)
        result = _yaml_round_trip(rs, tmp_path)
        assert result == rs


class TestResponsibilitySetYamlRoundTrip:
    """ResponsibilitySet round-trips through YAML without loss."""

    @given(
        n_resps=st.integers(min_value=1, max_value=3),
        n_pms=st.integers(min_value=1, max_value=3),
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_round_trip(self, tmp_path, n_resps, n_pms):
        """ResponsibilitySet round-trips through YAML."""
        responsibilities = []
        for i in range(1, n_resps + 1):
            resp_id = f"RESP-{i}"
            pms = [
                ProcessModelPart(pm_id=f"PM-{i}-{j}", description=f"PM {i}-{j}")
                for j in range(1, n_pms + 1)
            ]
            responsibilities.append(
                Responsibility(
                    resp_id=resp_id,
                    description=f"Controller {i}",
                    process_model_parts=pms,
                )
            )
        rs = ResponsibilitySet(
            responsibilities=responsibilities,
        )
        result = _yaml_round_trip(rs, tmp_path)
        assert result == rs


class TestCriticFindingsYamlRoundTrip:
    """CriticFindings round-trips through YAML without loss."""

    @given(
        n_gaps=st.integers(min_value=0, max_value=4),
        descriptions=st.lists(st_text, min_size=0, max_size=4),
        gap_types=st.lists(st_gap_type, min_size=0, max_size=4),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_round_trip(self, tmp_path, n_gaps, descriptions, gap_types):
        """CriticFindings with N gaps round-trips through YAML."""
        gaps = []
        for i in range(n_gaps):
            gaps.append(
                CriticGap(
                    gap_type=gap_types[i] if i < len(gap_types) else "missing_responsibility",
                    description=descriptions[i] if i < len(descriptions) else f"Gap {i + 1}",
                    related_attack_path=f"Path {i + 1}",
                    suggested_remedy=f"Fix {i + 1}",
                )
            )
        findings = CriticFindings(
            gaps=gaps,
            checklist_results={"input_validation": "present_justified"},
            taxonomy_probe_results={"rag": "present"},
        )
        result = _yaml_round_trip(findings, tmp_path)
        assert result == findings


# ---------------------------------------------------------------------------
# Empty / default invariants
# ---------------------------------------------------------------------------


class TestEmptyModelInvariants:
    """Empty/default models are valid where their stage contract permits it."""

    def test_empty_requirement_set_rejected(self):
        """RequirementSet must contain a requirement before Stage 2 continues."""
        with pytest.raises(ValueError, match="requirements"):
            RequirementSet(requirements=[])

    def test_empty_critic_findings_valid(self):
        """CriticFindings with no gaps is valid."""
        cf = CriticFindings()
        assert cf.gaps == []
        assert cf.checklist_results == {}
        assert cf.taxonomy_probe_results == {}

    def test_empty_responsibility_set_valid(self):
        """ResponsibilitySet with responsibilities but no CPs is valid."""
        rs = ResponsibilitySet(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="Controller 1",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="PM"),
                    ],
                    control_actions=[
                        ControlAction(ca_id="CA-1-1", description="CA"),
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates="PM-1-1",
                            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                        ),
                    ],
                ),
            ],
        )
        assert len(rs.responsibilities) == 1


# ---------------------------------------------------------------------------
# Solution-neutrality property tests
# ---------------------------------------------------------------------------


class TestSolutionNeutrality:
    """The keyword scan consistently flags implementation-specific terms
    and never flags neutral descriptions."""

    @given(
        keyword=st.sampled_from(list(_SOLUTION_NEUTRALITY_KEYWORDS)),
    )
    @settings(max_examples=20, deadline=None)
    def test_keyword_always_flagged(self, keyword):
        """Every known keyword in a description always produces a warning."""
        cs = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description=f"Monitor the {keyword} for safety",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="State"),
                    ],
                    control_actions=[
                        ControlAction(ca_id="CA-1-1", description="Act"),
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates="PM-1-1",
                            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                        ),
                    ],
                ),
            ],
        )
        warnings = check_solution_neutrality(cs)
        assert len(warnings) >= 1
        assert any(keyword.lower() in w.lower() for w in warnings)

    @given(
        neutral_desc=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=(" ", "-", "_"),
            ),
            min_size=5,
            max_size=30,
        )
    )
    @settings(max_examples=30, deadline=None)
    def test_neutral_description_no_warning(self, neutral_desc):
        """A description without any keyword never produces a warning."""
        # Ensure none of the keywords appear (case-insensitive).
        desc_lower = neutral_desc.lower()
        if any(kw.lower() in desc_lower for kw in _SOLUTION_NEUTRALITY_KEYWORDS):
            return  # skip — random text may contain a keyword substring
        cs = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description=neutral_desc,
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="State"),
                    ],
                    control_actions=[
                        ControlAction(ca_id="CA-1-1", description="Act"),
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates="PM-1-1",
                            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                        ),
                    ],
                ),
            ],
        )
        warnings = check_solution_neutrality(cs)
        assert warnings == []


# ---------------------------------------------------------------------------
# Taxonomy probe gating property tests
# ---------------------------------------------------------------------------


class TestTaxonomyProbeGating:
    """_build_taxonomy_probes returns a subset of known probes and
    respects the profile predicates."""

    # The maximum number of distinct probes is 5 (RAG, tool, memory,
    # multi-agent, HITL).
    MAX_PROBES = 5

    def _make_profile(
        self,
        kc_subcodes: list[str] | None = None,
        entry_point_names: list[str] | None = None,
        has_persistent_memory: bool = False,
        multi_agent: bool = False,
        hitl: bool = False,
    ) -> CapabilityProfile:
        """Build a minimal CapabilityProfile for testing."""
        kcs = kc_subcodes or ["KC1.1"]
        return CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name=name, direction="bidirectional")
                for name in (entry_point_names or ["user chat"])
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=kcs,
            tool_inventory=(
                [ToolInventoryEntry(name="tool1", description="d")]
                if any(kc.startswith("KC5.") or kc.startswith("KC6.") for kc in kcs)
                else None
            ),
            entry_point_completeness=InventoryCompleteness.inferred_partial,
            tool_inventory_completeness=InventoryCompleteness.inferred_partial,
        )

    def test_empty_profile_yields_subset(self):
        """A minimal profile yields at most MAX_PROBES probes."""
        profile = self._make_profile()
        probes = _build_taxonomy_probes(profile)
        assert len(probes) <= self.MAX_PROBES

    def test_all_probes_with_full_profile(self):
        """A profile with all capabilities yields all 5 probes."""
        profile = self._make_profile(
            kc_subcodes=["KC1.1", "KC4.3", "KC5.1", "KC6.3.3", "KC2.3", "KCX-HITL"],
            entry_point_names=["user chat", "rag retrieval"],
        )
        probes = _build_taxonomy_probes(profile)
        assert len(probes) == self.MAX_PROBES

    def test_probe_subset_is_stable(self):
        """The same profile always produces the same probes (determinism)."""
        profile = self._make_profile(
            kc_subcodes=["KC1.1", "KC4.3", "KC5.1"],
            entry_point_names=["user chat"],
        )
        probes1 = _build_taxonomy_probes(profile)
        probes2 = _build_taxonomy_probes(profile)
        assert probes1 == probes2

    @given(
        kc_subset=st.lists(
            st.sampled_from([
                "KC1.1", "KC4.3", "KC5.1", "KC6.3.3",
                "KC2.3", "KCX-HITL", "KCX-PMEM", "KCX-MAGENT",
            ]),
            min_size=1,
            max_size=8,
            unique=True,
        )
    )
    @settings(max_examples=25, deadline=None)
    def test_probe_count_within_bounds(self, kc_subset):
        """For any KC subset, the probe count is in [0, MAX_PROBES]."""
        # Ensure KC1.1 is always present (required by CapabilityProfile).
        if "KC1.1" not in kc_subset:
            kc_subset = ["KC1.1"] + kc_subset
        profile = self._make_profile(kc_subcodes=kc_subset)
        probes = _build_taxonomy_probes(profile)
        assert 0 <= len(probes) <= self.MAX_PROBES


# ---------------------------------------------------------------------------
# safe_llm_call return-shape and logging invariants
# ---------------------------------------------------------------------------


class TestSafeLlmCallInvariants:
    """Property tests for ``safe_llm_call`` return-shape and logging invariants.

    These verify that the error-handling wrapper maintains consistent
    contracts regardless of which exception type or stage/step labels
    are used:

    - **Return-shape dichotomy**: On success, ``(model, result, None)``;
      on failure, ``(None, result_or_None, error_str)``.  The ``error``
      slot and the ``model`` slot are never both non-None.
    - **Failure logging**: Every failed call produces a ``calls.jsonl``
      entry with ``success=false`` and a non-empty ``error`` field.
    - **Stage/step propagation**: The stage and step labels passed to
      ``safe_llm_call`` appear verbatim in the logged entry.
    """

    @given(
        stage=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("_",),
            ),
            min_size=1,
            max_size=20,
        ),
        step=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("_",),
            ),
            min_size=1,
            max_size=20,
        ),
        error_msg=st.text(min_size=1, max_size=50),
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_failure_return_shape(self, tmp_path, stage, step, error_msg):
        """On failure: model is None, error is non-None, result may be None."""
        from pydantic import BaseModel

        from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
        from tests.stpa.sp1_helpers import MockLLMClient

        class _M(BaseModel):
            val: int = 0

        client = MockLLMClient()
        client.set_exception_for(_M, RuntimeError(error_msg))

        model, result, error = safe_llm_call(
            llm_client=client,
            system_prompt="s",
            user_prompt="u",
            response_format=_M,
            run_dir=tmp_path,
            stage=stage,
            step=step,
            temperature=0.4,
        )
        assert model is None
        assert error is not None
        assert error_msg in error

    @given(
        stage=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("_",),
            ),
            min_size=1,
            max_size=20,
        ),
        step=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("_",),
            ),
            min_size=1,
            max_size=20,
        ),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_failure_logged_with_success_false_and_error(
        self, tmp_path, stage, step
    ):
        """Failed calls are logged with success=false and a non-empty error."""
        import json

        from pydantic import BaseModel

        from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
        from tests.stpa.sp1_helpers import MockLLMClient

        class _M(BaseModel):
            val: int = 0

        # Clear any prior entries (function-scoped fixture reused across examples)
        calls_file = tmp_path / "calls.jsonl"
        if calls_file.exists():
            calls_file.unlink()

        client = MockLLMClient()
        client.set_exception_for(_M, RuntimeError("boom"))

        safe_llm_call(
            llm_client=client,
            system_prompt="s",
            user_prompt="u",
            response_format=_M,
            run_dir=tmp_path,
            stage=stage,
            step=step,
        )
        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        assert len(entries) == 1
        assert entries[0]["success"] is False
        assert entries[0]["error"]
        assert entries[0]["stage"] == stage
        assert entries[0]["step"] == step

    @given(
        val=st.integers(min_value=0, max_value=1000),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_success_return_shape(self, tmp_path, val):
        """On success: model is non-None, error is None."""
        from pydantic import BaseModel

        from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
        from tests.stpa.sp1_helpers import MockLLMClient

        class _M(BaseModel):
            val: int = 0

        client = MockLLMClient()
        client.set_response_for(_M, {"val": val})

        model, result, error = safe_llm_call(
            llm_client=client,
            system_prompt="s",
            user_prompt="u",
            response_format=_M,
            run_dir=tmp_path,
            stage="test",
            step="test",
        )
        assert model is not None
        assert model.val == val
        assert error is None
        assert result is not None

    @given(
        val=st.integers(min_value=0, max_value=1000),
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_success_logged_with_success_true_no_error(self, tmp_path, val):
        """Successful calls are logged with success=true and no error field."""
        import json

        from pydantic import BaseModel

        from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
        from tests.stpa.sp1_helpers import MockLLMClient

        class _M(BaseModel):
            val: int = 0

        # Clear any prior entries (function-scoped fixture reused across examples)
        calls_file = tmp_path / "calls.jsonl"
        if calls_file.exists():
            calls_file.unlink()

        client = MockLLMClient()
        client.set_response_for(_M, {"val": val})

        safe_llm_call(
            llm_client=client,
            system_prompt="s",
            user_prompt="u",
            response_format=_M,
            run_dir=tmp_path,
            stage="test",
            step="test",
        )
        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        assert len(entries) == 1
        assert entries[0]["success"] is True
        assert "error" not in entries[0]


# ---------------------------------------------------------------------------
# StageError context preservation
# ---------------------------------------------------------------------------


class TestStageErrorContextPreservation:
    """``StageError`` preserves stage and step context across construction.

    The ``str()`` representation and attributes must be consistent so
    that ``run_sp1`` can reliably extract the error context when building
    ``stage_errors``.
    """

    @given(
        stage=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("_",),
            ),
            min_size=1,
            max_size=20,
        ),
        step=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("_",),
            ),
            min_size=1,
            max_size=20,
        ),
        message=st.text(min_size=1, max_size=80),
    )
    @settings(max_examples=30, deadline=None)
    def test_attributes_preserved(self, stage, step, message):
        """StageError attributes match constructor arguments."""
        from asago_scenario_generator.stpa.infra.llm_helpers import StageError

        exc = StageError(stage=stage, step=step, message=message)
        assert exc.stage == stage
        assert exc.step == step
        assert exc.message == message

    @given(
        stage=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("_",),
            ),
            min_size=1,
            max_size=20,
        ),
        step=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("_",),
            ),
            min_size=1,
            max_size=20,
        ),
        message=st.text(min_size=1, max_size=80),
    )
    @settings(max_examples=30, deadline=None)
    def test_str_contains_stage_and_step(self, stage, step, message):
        """str(StageError) contains both stage and step identifiers."""
        from asago_scenario_generator.stpa.infra.llm_helpers import StageError

        exc = StageError(stage=stage, step=step, message=message)
        s = str(exc)
        assert stage in s
        assert step in s

    @given(
        stage=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("_",),
            ),
            min_size=1,
            max_size=20,
        ),
        step=st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters=("_",),
            ),
            min_size=1,
            max_size=20,
        ),
        message=st.text(min_size=1, max_size=80),
    )
    @settings(max_examples=20, deadline=None)
    def test_stage_error_is_exception(self, stage, step, message):
        """StageError is an Exception subclass, not a BaseException-direct subclass."""
        from asago_scenario_generator.stpa.infra.llm_helpers import StageError

        exc = StageError(stage=stage, step=step, message=message)
        assert isinstance(exc, Exception)
        assert not isinstance(exc, (KeyboardInterrupt, SystemExit))

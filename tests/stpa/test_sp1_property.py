"""Property-based tests for SP1 System Model internal models.

These tests verify invariants that hold across broad input ranges for
the SP1-internal Pydantic models that are not already covered by the
foundation property tests in ``test_property.py``:

- **YAML round-trip**: ``RequirementSet``, ``ResponsibilitySet``, and
  ``CriticFindings`` round-trip through YAML without loss.
- **Parse-ability**: Any valid dict representation of the internal models
  is accepted by ``model_validate``.
- **call_with_policy**: Failed and successful calls keep their return
  shape and log the stage and step labels verbatim.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

from hypothesis import HealthCheck, given, settings, strategies as st
import pytest

from asago_scenario_generator.stpa.infra.yaml_io import read_yaml, write_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ProcessModelPart,
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
)
from pydantic import BaseModel
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from tests.stpa.sp1_helpers import MockLLMClient

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
                    description=descriptions[i]
                    if i < len(descriptions)
                    else f"Req {i + 1}",
                    classification=classifications[i]
                    if i < len(classifications)
                    else "control",
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
                    gap_type=gap_types[i]
                    if i < len(gap_types)
                    else "missing_responsibility",
                    description=descriptions[i]
                    if i < len(descriptions)
                    else f"Gap {i + 1}",
                    related_attack_path=f"Path {i + 1}",
                    suggested_remedy=f"Fix {i + 1}",
                )
            )
        findings = CriticFindings(
            gaps=gaps,
            checklist_results={"input_validation": "present"},
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


# ---------------------------------------------------------------------------
# call_with_policy return-shape and logging invariants
# ---------------------------------------------------------------------------

st_label = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=("_",),
    ),
    min_size=1,
    max_size=20,
)


class TestSafeLlmCallInvariants:
    """Property tests for ``call_with_policy`` return-shape and logging invariants.

    These verify that the error-handling wrapper maintains consistent
    contracts regardless of the exception text or stage/step labels used:

    - **Return-shape dichotomy**: On success, ``(model, result, None)``;
      on failure, ``(None, result_or_None, error_str)``.
    - **Logging**: Every call produces one ``calls.jsonl`` entry; a failed
      call logs ``success=false`` with an error, a successful call logs
      ``success=true`` without one.
    - **Stage/step propagation**: The stage and step labels passed to
      ``call_with_policy`` appear verbatim in the logged entry.
    """

    @given(
        stage=st_label,
        step=st_label,
        error_msg=st.text(min_size=1, max_size=50),
        val=st.integers(min_value=0, max_value=1000),
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_failure_and_success_shape_and_log(
        self, tmp_path, stage, step, error_msg, val
    ):
        class _Failing(BaseModel):
            val: int = 0

        class _Passing(BaseModel):
            val: int = 0

        client = MockLLMClient()
        client.set_exception_for(_Failing, RuntimeError(error_msg))
        client.set_response_for(_Passing, {"val": val})
        run_dir = Path(tempfile.mkdtemp(dir=tmp_path))

        def send(response_format):
            return call_with_policy(
                llm_client=client,
                system_prompt="s",
                user_prompt="u",
                response_format=response_format,
                run_dir=run_dir,
                stage=stage,
                step=step,
                temperature=0.4,
                policy=CorrectionPolicy(),
            )

        failed = send(_Failing)
        assert failed.value is None
        assert failed.error is not None
        assert error_msg in failed.error

        passed = send(_Passing)
        assert passed.value is not None
        assert passed.value.val == val
        assert passed.error is None
        assert passed.result is not None

        # Split on "\n" only: the call log is written with ensure_ascii=False,
        # so characters such as U+0085 in the random error text stay raw, and
        # str.splitlines() splits on them.
        log_text = (run_dir / "calls.jsonl").read_text(encoding="utf-8")
        failure_entry, success_entry = [
            json.loads(line) for line in log_text.split("\n") if line
        ]
        assert failure_entry["success"] is False
        assert failure_entry["error"]
        assert success_entry["success"] is True
        assert "error" not in success_entry
        for entry in (failure_entry, success_entry):
            assert entry["stage"] == stage
            assert entry["step"] == step

"""An exhausted Stage 5 length retry on the last threat reports no abort."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.stpa.scenario_prod.run import (
    SP3CandidateStatus,
    run_sp3,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    _ContextScenarioSemanticsPayload,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.sp3_run import _make_ets
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.stpa.sp1_helpers import MockLLMClient


class LengthFinishReasonError(Exception):
    """Stands in for the SDK's structured-output length error by name."""


def test_exhausted_retry_on_the_only_threat_is_one_stage_error(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_exception_for(
        _ContextScenarioSemanticsPayload,
        LengthFinishReasonError("structured response reached its length limit"),
    )

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path,
    )

    assert client.call_count == 2
    assert not result.scenario_envelopes
    assert [outcome.status for outcome in result.candidate_outcomes] == [
        SP3CandidateStatus.generation_failed
    ]
    joined = "\n".join(result.stage_errors)
    assert "retry exhausted" in joined.lower()
    assert "LengthFinishReasonError" in joined
    # No threat remains after the last one, so no circuit-breaker diagnostic.
    assert "remaining threats" not in joined
    stage5 = [e for e in read_calls_jsonl(tmp_path) if e.get("stage") == "stage_5"]
    assert [entry["success"] for entry in stage5] == [False, False]

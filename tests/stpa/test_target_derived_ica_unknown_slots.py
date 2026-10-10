"""A target-derived ICA finding that names an unknown slot does not end the unit.

The finder maps a ``slot_id`` written as an exact request slot plus a
``:<digits>`` ICA suffix back to that slot, with a warning, and drops a
finding naming any other unknown slot with a diagnostic.  Compilation keeps a
backstop: a finding whose slot the realization does not hold becomes a
per-finding diagnostic, and the other findings continue.  The fixture is the
trimmed L1 klarna-r2 draft (requests 308 and 309 of the b8-glm batch), in
which every finding's ``slot_id`` carries the ``:1`` suffix.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from asago_scenario_generator.models.target_realization import (
    SystemicControlAction,
    TargetDerivedICAFinding,
    TargetDerivedICAOperationContext,
    TargetDerivedICAProviderResponse,
    TargetDerivedICARequest,
    TargetDerivedICASlot,
    TargetOperationObservation,
    TargetOperationReference,
)
from asago_scenario_generator.pipeline.target_realization import (
    realize_target_derived_icas,
)
from asago_scenario_generator.stpa.target_realization import (
    TargetDerivedICALlmFinder,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.target_realization import _baseline, _target_extended_result
from tests.stpa.sp1_helpers import MockLLMClient

_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "unit_loss"
        / "l1-klarna-r2-target-derived-icas.json"
    ).read_text(encoding="utf-8")
)
_INCORRECT = "RESP-1:CA-1-4:INCORRECT"
_NOT_PROVIDED = "RESP-1:CA-1-4:NOT_PROVIDED"
_WRONG_TIMING = "RESP-1:CA-1-4:WRONG_TIMING"


def _klarna_request() -> TargetDerivedICARequest:
    """The recorded request's three CA-1-4 slots over the shared baseline."""
    return TargetDerivedICARequest(
        baseline=_baseline(),
        target_derived_control_actions=(
            SystemicControlAction(
                control_action_id="CA-1-4",
                controller_id="RESP-1",
                description="Read the target's state summary.",
                effect_kind="tool_call",
                temporality="instantaneous",
                provenance="target_derived",
            ),
        ),
        target_derived_ica_slots=tuple(
            TargetDerivedICASlot(
                slot_id=slot_id,
                responsibility="RESP-1",
                control_action="CA-1-4",
                action_temporality="instantaneous",
                uca_type=slot_id.rsplit(":", 1)[1],
            )
            for slot_id in _FIXTURE["request_slots"]
        ),
        target_operation_context=(
            TargetDerivedICAOperationContext(
                control_action_id="CA-1-4",
                operation=TargetOperationObservation(
                    reference=TargetOperationReference(
                        resource_id="mcp:target:mini",
                        operation_id="get_klarna_state_summary",
                    ),
                    description="Return the full JSON ledger.",
                    input_schema={"type": "object", "properties": {}},
                    state_changing=False,
                    state_effect="observes",
                    evidence_refs=("inventory:tool:get_klarna_state_summary",),
                ),
            ),
        ),
    )


def _recorded_draft() -> dict:
    return json.loads(json.dumps(_FIXTURE["draft"]))


def _decisions(*ica_ids: str) -> dict:
    """The recorded verifier axes, keyed by the canonical ICA IDs."""
    axes = {
        item["ica_id"].rsplit(":", 2)[0]: item
        for item in _FIXTURE["recorded_verifier_decisions"]
    }
    return {
        "decisions": [
            {
                "ica_id": ica_id,
                "action_state": axes[ica_id.rsplit(":", 1)[0]]["action_state"],
                "hazard_path": axes[ica_id.rsplit(":", 1)[0]]["hazard_path"],
                "detail": "Recorded verifier axes for this slot.",
            }
            for ica_id in ica_ids
        ]
    }


def _proposed(verifier_prompt: str) -> list[dict]:
    """The findings the verifier request proposes, as sent."""
    block = verifier_prompt.split("Proposed findings:\n```yaml\n", 1)[1]
    return yaml.safe_load(block.split("\n```", 1)[0])["findings"]


def _finder_steps(run_dir: Path) -> list[str]:
    return [entry["step"] for entry in read_calls_jsonl(run_dir)]


class TestFinderMapsTheIcaSuffixForm:
    """A ``<slot>:<digits>`` slot_id is that slot, recorded as a warning."""

    def test_recorded_draft_binds_each_finding_to_its_request_slot(
        self, tmp_path
    ) -> None:
        canonical = (f"{_INCORRECT}:1", f"{_NOT_PROVIDED}:1", f"{_WRONG_TIMING}:1")
        client = MockLLMClient()
        client.set_response_queue([_recorded_draft(), _decisions(*canonical)])
        finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)

        response = finder(_klarna_request())

        assert [(f.slot_id, f.ica_id) for f in response.findings] == [
            (_INCORRECT, f"{_INCORRECT}:1"),
            (_NOT_PROVIDED, f"{_NOT_PROVIDED}:1"),
            (_WRONG_TIMING, f"{_WRONG_TIMING}:1"),
        ]
        assert [f.verification.status for f in response.findings] == [
            "verified",
            "unverified",
            "unverified",
        ]
        assert response.provider_diagnostics == tuple(
            f"target-derived ICA finding slot_id {slot}:1 is request slot {slot} "
            f"plus an ICA suffix; mapped to slot {slot}"
            for slot in (_INCORRECT, _NOT_PROVIDED, _WRONG_TIMING)
        )

    def test_verifier_request_carries_the_canonical_identities(self, tmp_path) -> None:
        canonical = (f"{_INCORRECT}:1", f"{_NOT_PROVIDED}:1", f"{_WRONG_TIMING}:1")
        client = MockLLMClient()
        client.set_response_queue([_recorded_draft(), _decisions(*canonical)])
        finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)

        finder(_klarna_request())

        verifier_prompt = client.calls[1].user_prompt
        assert [(f["slot_id"], f["ica_id"]) for f in _proposed(verifier_prompt)] == [
            (_INCORRECT, f"{_INCORRECT}:1"),
            (_NOT_PROVIDED, f"{_NOT_PROVIDED}:1"),
            (_WRONG_TIMING, f"{_WRONG_TIMING}:1"),
        ]
        assert ":1:1" not in verifier_prompt
        assert "mapped to slot" not in verifier_prompt


class TestFinderDropsOtherUnknownSlots:
    """Any other unknown slot drops its finding; the rest go on."""

    def test_another_responsibility_slot_is_dropped_with_a_diagnostic(
        self, tmp_path
    ) -> None:
        draft = _recorded_draft()
        draft["findings"][0]["slot_id"] = "RESP-9:CA-9-1:INCORRECT"
        draft["findings"][1]["slot_id"] = _NOT_PROVIDED
        draft["findings"][2]["slot_id"] = f"{_WRONG_TIMING}:x"
        client = MockLLMClient()
        client.set_response_queue([draft, _decisions(f"{_NOT_PROVIDED}:1")])
        finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)

        response = finder(_klarna_request())

        assert [f.ica_id for f in response.findings] == [f"{_NOT_PROVIDED}:1"]
        assert response.provider_diagnostics == (
            "target-derived ICA finding RESP-1:CA-1-4:INCORRECT:1 is unresolved: "
            "unknown slot RESP-9:CA-9-1:INCORRECT; dropped before verification",
            "target-derived ICA finding RESP-1:CA-1-4:WRONG_TIMING:1 is unresolved: "
            "unknown slot RESP-1:CA-1-4:WRONG_TIMING:x; dropped before verification",
        )
        sent = _proposed(client.calls[1].user_prompt)
        assert [f["slot_id"] for f in sent] == [_NOT_PROVIDED]

    def test_a_draft_left_empty_sends_no_verifier_request(self, tmp_path) -> None:
        draft = _recorded_draft()
        for finding in draft["findings"]:
            finding["slot_id"] = "RESP-9:CA-9-1:INCORRECT"
        client = MockLLMClient()
        client.set_response_queue([draft])
        finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)

        response = finder(_klarna_request())

        assert response.findings == ()
        assert len(response.provider_diagnostics) == 3
        assert _finder_steps(tmp_path) == ["enumerate_target_derived_icas"]

    def test_unknown_slot_diagnostics_reach_the_realization(self, tmp_path) -> None:
        extended = "RESP-1:CA-1-2:INCORRECT"
        draft = {
            "findings": [
                {
                    **_recorded_draft()["findings"][0],
                    "slot_id": extended,
                    "related_hazards": ["H-1"],
                    "related_constraints": ["SC-1"],
                },
                {**_recorded_draft()["findings"][1], "slot_id": "RESP-9:CA-9-1:X"},
            ]
        }
        decision = {
            "decisions": [
                {
                    "ica_id": f"{extended}:1",
                    "action_state": "performed_unsafe",
                    "hazard_path": "supported",
                    "detail": "The exact slot and baseline references agree.",
                }
            ]
        }
        client = MockLLMClient()
        client.set_response_queue([draft, decision])
        finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)

        enhanced = realize_target_derived_icas(
            _baseline(), _target_extended_result(), finder
        )

        assert [f.ica_id for f in enhanced.target_derived_ica_findings] == [
            f"{extended}:1"
        ]
        assert (
            "target-derived ICA finding RESP-1:CA-1-4:NOT_PROVIDED:1 is unresolved: "
            "unknown slot RESP-9:CA-9-1:X; dropped before verification"
        ) in enhanced.diagnostics


class _ResponseFinder:
    """A finder that returns one fixed provider response."""

    def __init__(self, response: TargetDerivedICAProviderResponse) -> None:
        self._response = response

    def __call__(self, request: TargetDerivedICARequest):
        del request
        return self._response


def _verified(slot_id: str, ica_id: str) -> TargetDerivedICAFinding:
    recorded = _FIXTURE["draft"]["findings"][0]
    return TargetDerivedICAFinding(
        slot_id=slot_id,
        ica_id=ica_id,
        ica_text=recorded["ica_text"],
        hazardous_context=recorded["hazardous_context"],
        loss_scenario=recorded["loss_scenario"],
        related_hazards=("H-1",),
        verification={"status": "verified", "detail": "verified"},
    )


class TestCompilationBackstop:
    """Compilation drops an unknown-slot finding instead of raising."""

    def test_unknown_slot_becomes_a_diagnostic_and_the_rest_continue(self) -> None:
        known = "RESP-1:CA-1-2:INCORRECT"
        unknown = f"{known}:1"
        response = TargetDerivedICAProviderResponse(
            findings=(
                _verified(unknown, f"{unknown}:1"),
                _verified(known, f"{known}:1"),
            )
        )

        enhanced = realize_target_derived_icas(
            _baseline(), _target_extended_result(), _ResponseFinder(response)
        )

        assert [f.ica_id for f in enhanced.target_derived_ica_findings] == [
            f"{known}:1"
        ]
        assert (
            f"target-derived ICA finding {unknown}:1 is unresolved: "
            f"unknown slot {unknown}"
        ) in enhanced.diagnostics

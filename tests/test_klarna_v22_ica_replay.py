"""Replay the three captured Klarna CA-3-1 ICA deviations at the public seam.

The recorded replies predate the fill wire's ``governing_pairs``; the replay
recasts each one with ``current_fill_reply`` and changes no other value.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.obligation_aware.contracts import AnalysisControls
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    fill_synthesis_slots,
    final_slot_universe,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    is_wrong_duration_eligible,
)
from tests.helpers.obligation_aware import current_fill_reply


_REPLAY_FIXTURE = Path(__file__).parent / "fixtures" / "klarna-v22-ca3-1-replay.yaml"


def _sha256(path: Path) -> str:
    """Return the content digest used by the replay provenance checks."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _CapturedKlarnaClient:
    """Serve only the captured payloads while recording actual provider calls."""

    model = "gemma-4-26b-a4b-it"

    def __init__(self, payloads: dict[str, dict], slot_ids: tuple[str, ...]) -> None:
        self.payloads = payloads
        self.slot_ids = slot_ids
        self.called_slot_ids: list[str] = []

    def complete(self, **kwargs) -> LLMResult:
        """Return the exact captured payload for three slots and typed N/A for others."""
        user_prompt = str(kwargs["user_prompt"])
        matches = tuple(slot_id for slot_id in self.slot_ids if slot_id in user_prompt)
        if len(matches) != 1:
            raise AssertionError(f"expected one exact slot identity, got {matches}")
        slot_id = matches[0]
        self.called_slot_ids.append(slot_id)
        payload = self.payloads.get(
            slot_id,
            {
                "filled_slots": [
                    {
                        "slot_id": slot_id,
                        "is_na": True,
                        "na_rationale": (
                            "No routed obligation was supplied for this replay target."
                        ),
                        "findings": [],
                        "consideration_results": {},
                    }
                ]
            },
        )
        return LLMResult(
            # A string forces call_with_policy through the same parse path as the
            # captured model response instead of handing the provider a model.
            content=json.dumps(payload),
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=user_prompt,
        )


def test_captured_klarna_ca3_1_deviations_survive_public_fill(tmp_path) -> None:
    """All three saved CA-3-1 findings remain valid after one provider compile."""
    fixture = yaml.safe_load(_REPLAY_FIXTURE.read_text(encoding="utf-8"))
    loss_path = _REPLAY_FIXTURE.parent / fixture["source"]["embedded_loss_analysis"]
    control_path = (
        _REPLAY_FIXTURE.parent / fixture["source"]["embedded_control_structure"]
    )
    assert _sha256(loss_path) == fixture["source"]["embedded_loss_analysis_sha256"]
    assert _sha256(control_path) == fixture["source"]["control_structure_sha256"]

    records = fixture["records"]
    captured_payloads: dict[str, dict] = {}
    for record in records:
        captured_payloads[record["slot_id"]] = current_fill_reply(record["response"])

    loss_analysis = read_yaml(loss_path, LossAnalysis)
    control_structure = read_yaml(control_path, ControlStructure)
    all_slots = final_slot_universe(control_structure)
    all_slot_ids = tuple(slot.slot_id for slot in all_slots)
    controls = AnalysisControls(
        model_profile="saved-v22-replay",
        model_name="gemma-4-26b-a4b-it",
        deadline_seconds=30.0,
        temperature=0.0,
        context_window=131072,
        maximum_completion_tokens=8192,
        safety_margin=0,
    )
    client = _CapturedKlarnaClient(captured_payloads, all_slot_ids)
    adapter = ObligationAwareLLMAdapter(
        client,
        run_dir=tmp_path,
        controls=controls,
    )

    result = fill_synthesis_slots(
        adapter,
        briefs=(),
        routes=(),
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        controls=controls,
    )

    # The public seam split the 60 authoritative slots into one-slot requests and
    # sent every slot the code does not decide; the three exact captured
    # responses went through ObligationAwareLLMAdapter.fill.
    assert len(all_slots) == 60
    provider_slot_ids = tuple(
        slot.slot_id
        for slot in all_slots
        if slot.uca_type.value != "WRONG_DURATION" or is_wrong_duration_eligible(slot)
    )
    assert len(provider_slot_ids) < len(all_slots)
    assert tuple(sorted(client.called_slot_ids)) == tuple(sorted(provider_slot_ids))
    assert sum(slot_id in captured_payloads for slot_id in client.called_slot_ids) == 3
    assert result.diagnostics == ()

    slots_by_id = {slot.slot_id: slot for slot in result.ica_enumeration.slots}
    for slot_id in captured_payloads:
        slot = slots_by_id[slot_id]
        assert slot.is_na is False
        assert slot.unresolved_reason is None
        assert slot.na_justification is None
        assert len(slot.icas) == 1
        ica = slot.icas[0]
        assert ica.ica_id == f"{slot_id}:1"
        assert ica.related_hazards == ["H-3"]
        assert ica.related_constraints == ["SC-3"]

"""Builders whose feedback channel records an authority for update."""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    FeedbackUpdateAuthority,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.obligation_aware.context_coverage import (
    build_context_coverage_prompts,
    context_coverage_gaps,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from tests.helpers.normal_authoring_wire import (
    _normal_payload,
    _wrong_timing_structure,
)
from tests.helpers.obligation_aware import _provider_slot_request
from tests.helpers.sp3_scenario_continuity import _loss_analysis, _threat_of_type
from tests.helpers.stage2_source_selection import _authorities
from tests.helpers.stage5_assembly import stage5_assembly
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_ica_context_coverage import (
    _draft_slots,
    _finding,
    _request,
    _slot,
)

AUTHORITY = FeedbackUpdateAuthority(
    status="non_authoritative",
    basis="The use case says only the payments team sets the action count.",
)

# The sensor-anomaly source of FB-1-1 in the standard Stage 5 context.
FEEDBACK_HANDLE = "cause_3"


def with_feedback_authority(
    structure: ControlStructure,
    authority: FeedbackUpdateAuthority = AUTHORITY,
) -> ControlStructure:
    """``structure`` with ``authority`` on every channel of its first owner."""
    owner = structure.responsibilities[0]
    channels = [
        channel.model_copy(update={"authority_for_update": authority})
        for channel in owner.feedback_channels
    ]
    return structure.model_copy(
        update={
            "responsibilities": [
                owner.model_copy(update={"feedback_channels": channels}),
                *structure.responsibilities[1:],
            ]
        }
    )


def authority_structure() -> ControlStructure:
    """The standard Stage 5 structure with an assessed FB-1-1."""
    return with_feedback_authority(_wrong_timing_structure())


def authority_context() -> ScenarioGenerationContext:
    """The standard WRONG_TIMING context built from ``authority_structure``."""
    return build_scenario_generation_context(
        _threat_of_type(UCAType.wrong_timing),
        authority_structure(),
        _loss_analysis(),
        scenario_id="SCN-001",
    )


def authority_belief_spec() -> tuple[ScenarioSpec, ControlStructure]:
    """Compile a Stage 5 reply whose one factor is the assessed feedback source."""
    payload = copy.deepcopy(_normal_payload())
    payload["causal_factors"] = [
        {
            "source_handle": FEEDBACK_HANDLE,
            "evidence": "The count feedback reports a count the payments team "
            "did not set.",
            "temporal_condition": None,
            "evidence_status": "structural_failure",
        }
    ]
    payload["attacker_bdi"]["intentions"][0]["source_handles"] = [FEEDBACK_HANDLE]
    client = MockLLMClient()
    client.set_response_queue([payload])
    context = authority_context()
    structure = authority_structure()
    assembly = stage5_assembly(
        context, _threat_of_type(UCAType.wrong_timing), structure
    )
    # Compiling the Stage 5 spec writes its call log into a run directory.
    with tempfile.TemporaryDirectory() as run_dir:
        spec, error = generate_bdi_for_context(
            client, context, Path(run_dir), assembly=assembly
        )
    assert error is None and spec is not None, error
    return spec, structure


def authority_slot_request() -> SynthesisSlotRequest:
    """The provider slot request whose structure has an assessed FB-1-1."""
    request = _provider_slot_request()
    return request.model_copy(
        update={"control_structure": with_feedback_authority(request.control_structure)}
    )


def context_coverage_prompts(structure: ControlStructure) -> tuple[str, str]:
    """The context-coverage request for the reply gap of ``structure``.

    ``structure`` is a context-coverage test structure; its one drafted finding
    cites the source variable without a row, so both of its values are a gap.
    """
    slot = _slot(structure)
    drafted = _draft_slots(slot.slot_id, _finding(None))
    request = _request(structure, slot)
    gaps = context_coverage_gaps(drafted, request)
    assert gaps
    return build_context_coverage_prompts(
        target_id="RESP-1", gaps=gaps, filled_slots=drafted, request=request
    )


def call3_inputs() -> tuple[LossAnalysis, ControlStructure]:
    """The Call 3 source-selection inputs with a feedback channel added.

    The channel updates a process-model part from a controlled process, so a
    Call 3 request lists one update relation; the structure has no action, so
    the source-selection reply still covers it.
    """
    losses, structure = _authorities()
    [owner] = structure.model_dump(mode="json")["responsibilities"]
    owner["process_model_parts"] = [
        {
            "pm_id": "PM-1-1",
            "description": "Whether the requester owns the loan record.",
            "values": ["owns the record", "does not own the record"],
        }
    ]
    owner["feedback_channels"] = [
        {
            "fb_id": "FB-1-1",
            "description": "The requester's statement of who they are.",
            "updates": "PM-1-1",
            "source": {"type": "controlled_process", "id": "CP-1"},
            "source_kind": "user_message",
        }
    ]
    return losses, ControlStructure.model_validate(
        {
            "responsibilities": [owner],
            "controlled_processes": [
                {"cp_id": "CP-1", "description": "Loan record lookup."}
            ],
        }
    )

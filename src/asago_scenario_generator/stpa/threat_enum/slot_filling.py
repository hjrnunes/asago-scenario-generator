"""Stage 3 Phase 2 — LLM slot-filling.

One LLM call per responsibility fills all its slots (all control actions
× 4 UCA types). Calls are stateless (no conversation history). The
system prompt defines four ICA types with AI-agent-specific examples.

Slot-filling calls for different responsibilities are independent and
can be parallelized via :func:`parallel_safe_llm_calls`.
"""

from __future__ import annotations

import yaml
from pathlib import Path
from pydantic import BaseModel, Field

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.parallel_llm import (
    LLMCallSpec,
    parallel_safe_llm_calls,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import ICASlot
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

from ._constants import PROMPTS_DIR
from .slot_creation import SlotPlaceholder
from .technology_context import build_technology_context

__all__ = [
    "ICASlotFillResult",
    "fill_slots_for_responsibility",
    "fill_all_slots",
    "build_slot_filling_prompts",
]

_SLOT_VALIDATION_RETRY_FEEDBACK = (
    "\n\nThe prior response violated the slot schema. Ensure every slot with "
    "is_na=false contains at least one ICA. Ensure every slot with is_na=true "
    "contains no ICAs and includes a non-empty na_justification."
)


class ICASlotFillResult(BaseModel):
    """LLM response model: a list of filled ICA slots.

    The LLM returns this structure with ``filled_slots`` containing
    the slots for a single responsibility, with ``is_na``, ``icas``,
    and ``na_justification`` filled in.
    """

    filled_slots: list[ICASlot] = Field(default_factory=list)


def build_slot_filling_prompts(
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    technology_context: str,
    slots: list[SlotPlaceholder | ICASlot],
    resp_id: str,
    loader: TemplateLoader,
) -> tuple[str, str]:
    """Build the system and user prompts for a slot-filling call.

    Args:
        control_structure: The full control structure (solution-neutral).
        loss_analysis: Hazards and security constraints.
        technology_context: Technology context block text.
        slots: The slots for this responsibility only.
        resp_id: The responsibility ID.
        loader: Template loader for prompt rendering.

    Returns:
        A tuple of (system_prompt, user_prompt).
    """
    cs_yaml = yaml.dump(
        control_structure.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    la_yaml = yaml.dump(
        {
            "hazards": [h.model_dump(mode="json") for h in loss_analysis.hazards],
            "security_constraints": [
                sc.model_dump(mode="json") for sc in loss_analysis.security_constraints
            ],
        },
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    slots_yaml = yaml.dump(
        [s.model_dump(mode="json") for s in slots],
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )

    system_prompt = loader.render_prompt("stage3_system.j2")
    user_prompt = loader.render_prompt(
        "stage3_user.j2",
        control_structure_yaml=cs_yaml,
        loss_analysis_yaml=la_yaml,
        technology_context=technology_context,
        slots_yaml=slots_yaml,
        resp_id=resp_id,
    )

    return system_prompt, user_prompt


def fill_slots_for_responsibility(
    llm_client: LLMClient,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    technology_context: str,
    slots: list[SlotPlaceholder | ICASlot],
    resp_id: str,
    run_dir: Path,
    loader: TemplateLoader,
    stage: str = "stage_3",
    temperature: float = 0.4,
) -> ICASlotFillResult | None:
    """Fill slots for a single responsibility via one LLM call.

    Args:
        llm_client: LLM client for making the completion call.
        control_structure: The full control structure.
        loss_analysis: Hazards and security constraints.
        technology_context: Technology context block text.
        slots: The slots for this responsibility only.
        resp_id: The responsibility ID.
        run_dir: Directory for call logging.
        loader: Template loader for prompt rendering.
        stage: Pipeline stage label (default "stage_3").
        temperature: LLM temperature.

    Returns:
        An :class:`ICASlotFillResult` on success, or ``None`` on failure.
    """
    from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call

    system_prompt, user_prompt = build_slot_filling_prompts(
        control_structure,
        loss_analysis,
        technology_context,
        slots,
        resp_id,
        loader,
    )

    result, _llm_result, error = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=ICASlotFillResult,
        run_dir=run_dir,
        stage=stage,
        step=f"slot_fill_{resp_id}",
        temperature=temperature,
        validation_retries=1,
        validation_retry_feedback=_SLOT_VALIDATION_RETRY_FEEDBACK,
    )

    if error is not None:
        return None
    return result


def fill_all_slots(
    llm_client: LLMClient,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    capability_profile: CapabilityProfile,
    slots: list[SlotPlaceholder],
    run_dir: Path,
    max_workers: int = 1,
    temperature: float = 0.4,
    loader: TemplateLoader | None = None,
) -> list[ICASlot]:
    """Fill all responsibility slots via LLM calls, one per responsibility.

    Groups slots by responsibility, makes one LLM call per responsibility
    (in parallel if ``max_workers > 1``), and merges the results back
    into the full slot list.

    Coordination link slots are not filled by this function — they are
    left as unfilled ICASlot objects with ``is_na=False`` and ``icas=[]``
    (which is valid because they are not part of an ICAEnumeration until
    explicitly filled).

    Args:
        llm_client: LLM client for making completion calls.
        control_structure: The full control structure.
        loss_analysis: Hazards and security constraints.
        capability_profile: For technology context.
        slots: All slots from Phase 1 (only responsibility slots are filled).
        run_dir: Directory for call logging.
        max_workers: Maximum parallel workers.
        temperature: LLM temperature.
        loader: Template loader (default: SP2 prompts directory).

    Returns:
        A list of :class:`ICASlot` objects. Responsibility slots are
        filled by the LLM. Coordination link slots that are not filled
        by the LLM are returned as N/A with a default justification
        (``"Coordination link slot not filled by LLM in MVP"``).
    """
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)

    technology_context = build_technology_context(capability_profile)
    resp_slots = _group_resp_slots(slots)
    call_specs = _build_slot_fill_call_specs(
        resp_slots,
        control_structure,
        loss_analysis,
        technology_context,
        temperature,
        loader,
    )

    results = parallel_safe_llm_calls(
        call_specs,
        llm_client=llm_client,
        run_dir=run_dir,
        max_workers=max_workers,
    )

    filled_by_id = _collect_filled_slots(results)
    return _merge_filled_slots(slots, filled_by_id)


def _group_resp_slots(
    slots: list[SlotPlaceholder],
) -> dict[str, list[SlotPlaceholder]]:
    """Group responsibility slots by resp_id.

    Coordination link slots (``responsibility=None``) are excluded.
    """
    resp_slots: dict[str, list[SlotPlaceholder]] = {}
    for slot in slots:
        if slot.responsibility:
            resp_slots.setdefault(slot.responsibility, []).append(slot)
    return resp_slots


def _build_slot_fill_call_specs(
    resp_slots: dict[str, list[SlotPlaceholder]],
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    technology_context: str,
    temperature: float,
    loader: TemplateLoader,
) -> list[LLMCallSpec]:
    """Build one :class:`LLMCallSpec` per responsibility."""
    call_specs: list[LLMCallSpec] = []
    for resp_id, resp_slot_list in resp_slots.items():
        system_prompt, user_prompt = build_slot_filling_prompts(
            control_structure,
            loss_analysis,
            technology_context,
            resp_slot_list,
            resp_id,
            loader,
        )
        call_specs.append(
            LLMCallSpec(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_format=ICASlotFillResult,
                stage="stage_3",
                step=f"slot_fill_{resp_id}",
                temperature=temperature,
                validation_retries=1,
                validation_retry_feedback=_SLOT_VALIDATION_RETRY_FEEDBACK,
            )
        )
    return call_specs


def _collect_filled_slots(
    results: list,
) -> dict[str, ICASlot]:
    """Build a lookup of filled slots by slot_id from LLM call results."""
    filled_by_id: dict[str, ICASlot] = {}
    for result in results:
        if result.result is not None and isinstance(result.result, ICASlotFillResult):
            for filled_slot in result.result.filled_slots:
                filled_by_id[filled_slot.slot_id] = filled_slot
    return filled_by_id


def _is_expected_slot(filled_slot: ICASlot, placeholder: SlotPlaceholder) -> bool:
    """Check that an LLM result preserves the slot identity contract.

    The slot ID is the primary key, but checking the other identity fields
    prevents a model from moving a filled result to a different controller,
    action, or UCA type while still producing a syntactically valid
    ``ICASlot``.
    """
    return (
        filled_slot.slot_id == placeholder.slot_id
        and filled_slot.responsibility == placeholder.responsibility
        and filled_slot.coordination_link == placeholder.coordination_link
        and filled_slot.control_action == placeholder.control_action
        and filled_slot.uca_type == placeholder.uca_type
    )


def _merge_filled_slots(
    slots: list[SlotPlaceholder],
    filled_by_id: dict[str, ICASlot],
) -> list[ICASlot]:
    """Merge LLM-filled slots back into the full slot list.

    Unfilled slots (coordination links or LLM failures) are returned as
    N/A with a default justification.
    """
    merged: list[ICASlot] = []
    for slot in slots:
        filled_slot = filled_by_id.get(slot.slot_id)
        if filled_slot is not None and _is_expected_slot(filled_slot, slot):
            merged.append(filled_slot.aligned())
        else:
            merged.append(
                ICASlot(
                    slot_id=slot.slot_id,
                    responsibility=slot.responsibility,
                    coordination_link=slot.coordination_link,
                    control_action=slot.control_action,
                    uca_type=slot.uca_type,
                    is_na=True,
                    icas=[],
                    na_justification="Coordination link slot not filled by LLM in MVP",
                )
            )
    return merged


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-14T17:18:04Z","module_hash":"369b7f41dd84f5371b86b7470148a9fdf8352bf14e394fde281aff960e0f9653","functions":[{"id":"func/build_slot_filling_prompts","name":"build_slot_filling_prompts","line":50,"end_line":109,"hash":"8d902bb0192398b632d8d8d6ae2aa840aaddca97426b4f1246bed41da9a03b5f"},{"id":"func/fill_slots_for_responsibility","name":"fill_slots_for_responsibility","line":112,"end_line":165,"hash":"4b986f99f9028510e3c0feca07c388b83b0138e6b2f13a101a95a855db8e0d93"},{"id":"func/fill_all_slots","name":"fill_all_slots","line":168,"end_line":224,"hash":"2e9d70b2bebdd255a17274d67a82c645074c6525bf2848bd5a5fb895e149b630"},{"id":"func/_group_resp_slots","name":"_group_resp_slots","line":227,"end_line":238,"hash":"af9cae1f1a91f1601b3d830a2b3c74f6213fba88233f68f637548908c6ce94ae"},{"id":"func/_build_slot_fill_call_specs","name":"_build_slot_fill_call_specs","line":241,"end_line":270,"hash":"c84591e7f2c080c55759a2b6f24aebdb298355deafd756f9a04473f2f4754cf3"},{"id":"func/_collect_filled_slots","name":"_collect_filled_slots","line":273,"end_line":282,"hash":"dd945a5792f8107e07516d0f416c271366acd0a87ec3cf21560ba02fa5b32c44"},{"id":"func/_is_expected_slot","name":"_is_expected_slot","line":285,"end_line":301,"hash":"ef8cbed9f123c2f21d7d07f1b850023c86b55e98afe19ad59215860c67436eeb"},{"id":"func/_merge_filled_slots","name":"_merge_filled_slots","line":304,"end_line":331,"hash":"1d96d8f9838747609f376e5ed09d2662020b46ad7eaf77f91c09fc73961330b5"}]}
# mutate4py-manifest-end

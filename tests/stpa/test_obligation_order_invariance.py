"""Model-facing obligation order does not depend on obligation IDs.

Obligation IDs are content hashes, so a taxonomy translation renames every one
of them. Each test renames twelve briefs so that the new IDs sort in the
reverse order of the old ones, and checks that what a model sees in sequence
(batches, questions, handles, considerations) only changes ID strings.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from hashlib import sha256
from itertools import product
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.models.obligation_consideration import (
    NeutralObligationBrief,
    ObligationRoute,
)
from asago_scenario_generator.pipeline.synthesis_scenarios import (
    _build_synthesis_scenario_contexts,
)
from asago_scenario_generator.stpa.obligation_aware.briefs import (
    create_obligation_batches,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.obligation_aware import slot_filling
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    StructuralRoutingRequest,
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_routing_prompts,
    build_synthesis_slot_prompts,
    local_obligation_handles,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    _budgeted_obligation_batches,
    build_neutral_briefs,
)
from asago_scenario_generator.stpa.scenario_prod import context as context_module
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.governance import _controls, _pattern, _pattern_route
from tests.helpers.obligation_aware import _control_structure, _loss_analysis
from tests.helpers.obligation_factory import make_plan

RISKS = ("risk-c", "risk-a", "risk-b")
PATTERNS = ("AP-4", "AP-2", "AP-1", "AP-3")
TARGET = "RESP-1"


def _old_id(index: int) -> str:
    return "ob:v1:" + sha256(f"old-{index}".encode()).hexdigest()


def _briefs() -> tuple[NeutralObligationBrief, ...]:
    """Build twelve briefs over three risks and four patterns."""
    base = build_neutral_briefs(make_plan(), (_pattern(),))[0]
    payload = base.model_dump(mode="json", exclude={"semantic_digest"})
    briefs = []
    for index, (risk_id, pattern_id) in enumerate(product(RISKS, PATTERNS)):
        briefs.append(
            NeutralObligationBrief.model_validate(
                {
                    **payload,
                    "obligation_id": _old_id(index),
                    "risk_ref": {**payload["risk_ref"], "risk_id": risk_id},
                    "attack_pattern_id": pattern_id,
                    "attack_pattern_name": f"Pattern {pattern_id}",
                    "attack_pattern_description": f"Mechanism of {pattern_id}",
                }
            )
        )
    return tuple(briefs)


def _rename(briefs: Sequence[NeutralObligationBrief]) -> dict[str, str]:
    """Map old IDs to new ones that sort in the reverse order of the old."""
    old = sorted(item.obligation_id for item in briefs)
    new = sorted(
        "ob:v1:" + sha256(f"{n}".encode()).hexdigest() for n in range(len(old))
    )
    rename = dict(zip(old, reversed(new), strict=True))
    assert sorted(rename, key=rename.__getitem__) == sorted(old, reverse=True)
    return rename


def _renamed(
    briefs: Sequence[NeutralObligationBrief], rename: Mapping[str, str]
) -> tuple[NeutralObligationBrief, ...]:
    return tuple(
        NeutralObligationBrief.model_validate(
            {
                **item.model_dump(mode="json", exclude={"semantic_digest"}),
                "obligation_id": rename[item.obligation_id],
            }
        )
        for item in briefs
    )


def _restore(text: str, rename: Mapping[str, str]) -> str:
    for old, new in rename.items():
        text = text.replace(new, old)
    return text


def _identity(brief: Any) -> tuple[str, str | None]:
    return (brief.risk_ref.risk_id, brief.attack_pattern_id)


def _by_id(briefs: Sequence[NeutralObligationBrief]) -> dict[str, Any]:
    return {item.obligation_id: item for item in briefs}


def _routes(briefs: Sequence[NeutralObligationBrief]) -> tuple[ObligationRoute, ...]:
    structure = _control_structure()
    slot = next(item for item in create_slots(structure) if item.responsibility)
    return tuple(_pattern_route(brief, slot) for brief in briefs)


def test_routing_batches_do_not_depend_on_obligation_ids() -> None:
    briefs = _briefs()
    renamed = _renamed(briefs, _rename(briefs))
    structure = _control_structure()

    def batches(values: Sequence[NeutralObligationBrief]) -> tuple:
        direct = create_obligation_batches(values, 8)
        budgeted = _budgeted_obligation_batches(
            values,
            max_batch_size=8,
            budget=None,
            loss_analysis=_loss_analysis(),
            control_structure=structure,
            slots=create_slots(structure),
        )
        assert budgeted == direct
        return tuple(tuple(_identity(item) for item in batch) for batch in direct)

    before = batches(briefs)

    assert batches(renamed) == before
    assert before[0] == tuple(product(("risk-a", "risk-b"), sorted(PATTERNS)))
    assert before[1] == tuple(product(("risk-c",), sorted(PATTERNS)))


def test_routing_prompt_order_does_not_depend_on_obligation_ids() -> None:
    briefs = _briefs()
    rename = _rename(briefs)
    structure = _control_structure()

    def render(values: Sequence[NeutralObligationBrief]) -> tuple[str, str]:
        return build_structural_routing_prompts(
            briefs=values,
            loss_analysis=_loss_analysis(),
            control_structure=structure,
            slots=create_slots(structure),
        )

    system, user = render(briefs)
    renamed_system, renamed_user = render(_renamed(briefs, rename))

    assert renamed_user != user
    assert _restore(renamed_user, rename) == user
    assert _restore(renamed_system, rename) == system


def test_ica_handles_do_not_depend_on_obligation_ids() -> None:
    briefs = _briefs()
    rename = _rename(briefs)
    renamed = _renamed(briefs, rename)
    structure = _control_structure()
    slots = [item for item in create_slots(structure) if item.responsibility == TARGET]

    def handles(values: Sequence[NeutralObligationBrief]) -> dict[str, tuple]:
        by_id = _by_id(values)
        local = local_obligation_handles(_routes(values), by_id)
        return {
            handle: _identity(by_id[obligation_id])
            for obligation_id, handle in local.items()
        }

    def render(values: Sequence[NeutralObligationBrief]) -> tuple[str, str]:
        return build_synthesis_slot_prompts(
            target_id=TARGET,
            slots=slots,
            routed_briefs=values,
            routed_routes=_routes(values),
            loss_analysis=_loss_analysis(),
            control_structure=structure,
        )

    before = handles(briefs)

    assert handles(renamed) == before
    assert [before[f"R{n}"] for n in range(1, 13)] == list(
        product(sorted(RISKS), sorted(PATTERNS))
    )
    system, user = render(briefs)
    renamed_system, renamed_user = render(renamed)
    assert _restore(renamed_user, rename) == user
    assert _restore(renamed_system, rename) == system


def test_ica_budget_parts_do_not_depend_on_obligation_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    briefs = _briefs()
    renamed = _renamed(briefs, _rename(briefs))
    structure = _control_structure()
    monkeypatch.setattr(
        slot_filling,
        "_slot_request_fits",
        lambda request, budget: len(request.routed_routes) <= 5,
    )

    def parts(values: Sequence[NeutralObligationBrief]) -> tuple:
        routes = _routes(values)
        request = SynthesisSlotRequest(
            target_id=TARGET,
            target_kind="responsibility",
            slots=tuple(
                item
                for item in create_slots(structure)
                if item.slot_id in routes[0].slot_ids
            ),
            routed_briefs=tuple(values),
            routed_routes=routes,
            loss_analysis=_loss_analysis(),
            control_structure=structure,
            controls=_controls(),
        )
        split = slot_filling._split_target_routes(request, budget=None)
        assert split is not None
        by_id = _by_id(values)
        # A part keeps its routes in obligation-ID order; its handles order them.
        return tuple(
            tuple(
                sorted(
                    _identity(by_id[route.obligation_id])
                    for route in part.routed_routes
                )
            )
            for part in split
        )

    before = parts(briefs)

    assert parts(renamed) == before
    ordered = tuple(product(sorted(RISKS), sorted(PATTERNS)))
    assert before == (ordered[:5], ordered[5:10], ordered[10:])


class _RecordingClient:
    """Record each request and answer with text no schema accepts."""

    model = "order-recorder"
    session = None

    def __init__(self) -> None:
        self.user_prompts: list[str] = []

    def complete(self, **kwargs: Any) -> LLMResult:
        self.user_prompts.append(kwargs["user_prompt"])
        return LLMResult(
            content="not a JSON document",
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def test_mechanism_verification_order_does_not_depend_on_obligation_ids(
    tmp_path: Path,
) -> None:
    briefs = _briefs()
    rename = _rename(briefs)
    structure = _control_structure()

    def shown(values: Sequence[NeutralObligationBrief], name: str) -> str:
        client = _RecordingClient()
        adapter = ObligationAwareLLMAdapter(
            client, run_dir=tmp_path / name, controls=_controls()
        )
        request = StructuralRoutingRequest(
            batch_id="initial-batch-1",
            briefs=tuple(values),
            loss_analysis=_loss_analysis(),
            control_structure=structure,
            slots=tuple(create_slots(structure)),
            controls=_controls(),
        )
        # The routing response hands routes over in obligation-ID order.
        routes = sorted(_routes(values), key=lambda item: item.obligation_id)
        adapter.verify_mechanisms(request, routes)
        return client.user_prompts[0]

    before = shown(briefs, "before")

    assert _restore(shown(_renamed(briefs, rename), "after"), rename) == before
    # Routes with one mechanism and one path share an item, so each pattern
    # is asked once, in the order of its first brief.
    positions = [before.index(f"Mechanism of {item}") for item in sorted(PATTERNS)]
    assert positions == sorted(positions)


def test_stage5_consideration_order_does_not_depend_on_obligation_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    briefs = _briefs()
    renamed = _renamed(briefs, _rename(briefs))
    received: dict[str, tuple] = {}

    def fake_context(threat, control, loss, *, scenario_id, obligation_considerations):
        received[scenario_id] = obligation_considerations
        return threat.ica_id

    monkeypatch.setattr(
        context_module, "build_scenario_generation_context", fake_context
    )

    def considered(values: Sequence[NeutralObligationBrief]) -> tuple:
        pairs = tuple(
            SimpleNamespace(
                disposition="finding",
                obligation_id=item.obligation_id,
                rationale="Seen at the ICA.",
                ica_ids=("ICA-A",),
            )
            for item in values
        )
        _build_synthesis_scenario_contexts(
            (SimpleNamespace(ica_id="ICA-A"),),
            object(),
            object(),
            briefs=tuple(values),
            ica_considerations=pairs,
        )
        by_id = _by_id(values)
        return tuple(
            _identity(by_id[item.obligation_id]) for item in received["SCN-001"]
        )

    before = considered(briefs)

    assert considered(renamed) == before
    assert list(before) == list(product(sorted(RISKS), sorted(PATTERNS)))

"""The rendered narrate request stays byte-identical to the recorded one.

``tests/fixtures/narration_requests/requests.json`` holds the system and user
prompts the narrate step rendered for these specs at commit 613f1db, before
the plain fallback narrative existed. Choosing a fallback happens after the
narrate request is sent, so no change to the fallback may change a request.
The specs cover the annotations :func:`plain` strips from a fact, such as
``(values: ...)``, ``(documented operation: ...)`` and ``[structural
sources: ...]``, and structural identifiers the glossary explains.

The module imports only names the narrate step had at that commit, so the
same cases render the fixture there and are checked here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.models.attack_shape import AttackShape
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
    DefenderBelief,
    ScenarioSpec,
)
from asago_scenario_generator.stpa.scenario_prod.narration import (
    build_facts,
    render_narration_prompts,
)
from tests.helpers.stpa_producer_seams import _spec

REQUESTS = (
    Path(__file__).resolve().parents[1] / "fixtures/narration_requests/requests.json"
)

INDIRECT = AttackShape.model_validate(
    {
        "channel": "indirect",
        "turn_count": 2,
        "turn_plan": [
            {"position": 1, "speaker": "benign_user", "purpose": "ask_to_read_item"},
            {"position": 2, "speaker": "benign_user", "purpose": "follow_up_on_item"},
        ],
        "indirect": {
            "carrier_operation": "lookup_order",
            "data_item": {"content_kind": "order_content", "record_ref": "ORD-201"},
            "party_relation": {
                "controller": "third_party",
                "benign_user_actor_ref": None,
            },
        },
        "threat_label": None,
        "source": "stage5_validated",
        "downgrade_reason": None,
    }
)


def adversarial() -> ScenarioSpec:
    return _spec().model_copy(
        update={
            "adversary": Adversary(
                kind=AdversaryKind.third_party_via_content,
                gain="Learns another customer's order.",
                reaches_target_via=None,
            ),
            "attack_shape": INDIRECT,
        }
    )


def everyday() -> ScenarioSpec:
    return _spec().model_copy(
        update={
            "adversary": Adversary(
                kind=AdversaryKind.none,
                gain="Nobody gains; the agent errs on its own.",
                reaches_target_via=None,
            )
        }
    )


def annotated() -> ScenarioSpec:
    """Facts that carry the annotations ``plain`` strips, and identifiers."""
    spec = everyday()
    context = spec.scenario_context
    assert context is not None
    return spec.model_copy(
        update={
            "defender_bdi": spec.defender_bdi.model_copy(
                update={
                    "beliefs": [
                        DefenderBelief(
                            pm_id="PM-1-1",
                            content="Draft status (values: approved; draft)",
                            vulnerability="The draft flag is never refreshed.",
                        )
                    ]
                }
            ),
            "causal_factors": [
                CausalFactor(
                    kind=CausalFactorKind.process_model_flaw,
                    source_id="PM-1-1",
                    description=(
                        "PM-1-1 is set by operation:lookup_order (documented "
                        "operation: lookup_order) [structural sources: PM-1-1, "
                        "RESP-1]."
                    ),
                )
            ],
            "scenario_context": context.model_copy(
                update={
                    "ica": context.ica.model_copy(
                        update={
                            "hazardous_context": (
                                "a draft result (values: approved; draft) is "
                                "shared under RESP-1"
                            )
                        }
                    )
                }
            ),
        }
    )


CASES = {"adversarial": adversarial, "everyday": everyday, "annotated": annotated}


def render_requests() -> dict[str, dict[str, str]]:
    """Render each case's narrate request as the step sends it."""
    rendered = {}
    for name, case in CASES.items():
        system, user = render_narration_prompts(build_facts(case()))
        rendered[name] = {"system": system, "user": user}
    return rendered


@pytest.mark.parametrize("name", list(CASES))
def test_the_narrate_request_matches_the_recorded_bytes(name: str) -> None:
    recorded = json.loads(REQUESTS.read_text(encoding="utf-8"))

    assert render_requests()[name] == recorded[name]


def test_the_recorded_request_keeps_annotations_out_of_the_facts() -> None:
    user = json.loads(REQUESTS.read_text(encoding="utf-8"))["annotated"]["user"]

    assert "(values:" not in user
    assert "documented operation" not in user
    assert "structural sources" not in user
    assert "draft status" in user

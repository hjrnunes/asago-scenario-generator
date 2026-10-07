"""The mechanism verifier names each request with a short local handle."""

from __future__ import annotations

import re

import yaml

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import (
    ObligationRoute,
    ObligationSemanticAssessment,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.obligation_aware import _control_structure, _controls, _loss_analysis

_FULL_HANDLE = re.compile(r"ob:v1:[0-9a-f]{64}")


def _routing_answer(obligation_id: str) -> dict:
    route = ObligationRoute(
        obligation_id=obligation_id,
        disposition="targeted",
        semantic_assessment=ObligationSemanticAssessment(
            mechanism_assessment="plausible_in_system",
            risk_alignment="supported",
            mapping_strength="direct_curated_pair",
            mechanism_rationale="The supplied control path permits it.",
            risk_alignment_rationale="The mechanism realizes the reviewed risk.",
        ),
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="The supplied control path is relevant to the concern.",
        evidence=("provider-route",),
    ).model_dump(
        mode="json",
        exclude={
            "route_id",
            "missing_concepts",
            "model_call_refs",
            "trace_refs",
            "diagnostics",
        },
    )
    route["semantic_assessment"].pop("mapping_strength", None)
    return {"routes": [route]}


class _VerifierClient:
    """Route each brief as asked and answer the verifier from a script."""

    model = "scripted-verifier"

    def __init__(self, briefs, verdicts) -> None:
        self.briefs = briefs
        self.verdicts = list(verdicts)
        self.verifier_prompts: list[str] = []

    def complete(self, **kwargs):
        name = kwargs["response_format"].__name__
        if name.startswith("_MechanismVerdictPayload"):
            self.verifier_prompts.append(kwargs["user_prompt"])
            content = {"verdicts": self.verdicts[len(self.verifier_prompts) - 1]}
        else:
            asked = [
                item
                for item in self.briefs
                if item.obligation_id in kwargs["user_prompt"]
            ]
            content = {
                "routes": [
                    route
                    for item in asked
                    for route in _routing_answer(item.obligation_id)["routes"]
                ]
            }
        return LLMResult(
            content=content,
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def _verdict(handle: str, relationship: str = "mechanism_specific") -> dict:
    return {
        "item_handle": handle,
        "relationship": relationship,
        "rationale": "The selected path governs the mechanism.",
    }


def _route(client, briefs, tmp_path, *, batch_size=1):
    controls = _controls().model_copy(update={"max_batch_size": batch_size})
    provider = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=controls)
    return route_obligations(
        provider,
        briefs=briefs,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=create_slots(_control_structure()),
        controls=controls,
    )


def _single_brief():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return build_neutral_briefs(make_plan(), (pattern,))[:1]


def test_verifier_prompt_names_the_item_with_a_short_handle(tmp_path) -> None:
    """The prompt carries R1, never the content-addressed obligation handle."""
    briefs = _single_brief()
    client = _VerifierClient(briefs, [[_verdict("R1")]])

    result = _route(client, briefs, tmp_path)

    prompt = client.verifier_prompts[0]
    body = prompt.split("Mechanism/path comparisons:\n", 1)[1].split("\nReturn a JSON")[
        0
    ]
    (item,) = yaml.safe_load(body)
    assert set(item) == {
        "item_handle",
        "distinctive_mechanism",
        "selected_structural_path",
    }
    assert "item_handle: R1" in prompt
    assert not _FULL_HANDLE.search(prompt)
    route = result.routes[0]
    assert route.semantic_assessment.mechanism_assessment == "plausible_in_system"


def test_verdict_for_an_unknown_handle_is_repaired_with_the_exact_handles(
    tmp_path,
) -> None:
    """A handle the prompt never showed earns one repair that names R-handles."""
    briefs = _single_brief()
    client = _VerifierClient(briefs, [[_verdict("R7")], [_verdict("R1")]])

    result = _route(client, briefs, tmp_path)

    assert len(client.verifier_prompts) == 2
    repair = client.verifier_prompts[1]
    assert "R7" in repair and "R1" in repair
    assert not _FULL_HANDLE.search(repair)
    assert result.routes[0].semantic_assessment.mechanism_assessment == (
        "plausible_in_system"
    )


def test_verdict_with_a_corrupted_handle_after_the_repair_fails_closed(
    tmp_path,
) -> None:
    """Two unusable answers leave the route without mechanism credit."""
    briefs = _single_brief()
    client = _VerifierClient(briefs, [[_verdict("R7")], [_verdict("R8")]])

    result = _route(client, briefs, tmp_path)

    assert len(client.verifier_prompts) == 2
    assert result.routes[0].semantic_assessment.mechanism_assessment == (
        "insufficient_evidence"
    )

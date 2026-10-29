"""Mechanism suggestion findings reach Stage 5 as provenance, never as sources."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.models.mechanism_suggestion import (
    MechanismIcaConsideration,
)
from asago_scenario_generator.pipeline import synthesis_scenarios
from asago_scenario_generator.pipeline.synthesis_scenarios import (
    _build_synthesis_scenario_contexts,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.mechanism_library import (
    MechanismId,
    bundled_mechanism_library,
)
from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICAEnumeration,
    UCAType,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioObligationConsideration,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotFillResult,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    SlotFillRunResult,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.sources import (
    _causal_source_choices,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    _CausalSourceChoice,
)
from tests.helpers.normal_authoring_wire import _wrong_timing_structure
from tests.helpers.sp3_scenario_continuity import _loss_analysis, _threat_of_type
from tests.helpers.stage5_assembly import stage5_assembly
from tests.helpers.stage5_compile import compile_draft, draft_payload, factor

_THREAT = _threat_of_type(UCAType.wrong_timing)


def _finding(mechanism: str = "user_claim", ica_id: str | None = None):
    ica = ica_id or _THREAT.ica_id
    return MechanismIcaConsideration(
        suggestion_id="msug:v1:" + "1" * 64,
        mechanism_id=mechanism,
        slot_id=_THREAT.ica_slot_id,
        disposition="finding",
        ica_ids=(ica,),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:WRONG_TIMING",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("provider-structured-consideration",),
        rationale="Finding 0 expresses the mechanism on the suggested path.",
    )


def _mechanism_consideration(mechanism: str = "user_claim"):
    entry = bundled_mechanism_library().entry(mechanism)
    return ScenarioObligationConsideration(
        kind="mechanism",
        mechanism_id=entry.id.value,
        mechanism_name=entry.name,
        concise_concern=entry.question,
        disposition="finding",
        rationale="Finding 0 expresses the mechanism on the suggested path.",
        finding_ica_id=_THREAT.ica_id,
    )


def _context(*considerations):
    return build_scenario_generation_context(
        _THREAT,
        _wrong_timing_structure(),
        _loss_analysis(),
        scenario_id="SCN-001",
        obligation_considerations=considerations,
    )


def test_a_mechanism_finding_reaches_the_context_of_its_ica() -> None:
    contexts = _build_synthesis_scenario_contexts(
        [_THREAT],
        _wrong_timing_structure(),
        _loss_analysis(),
        briefs=(),
        ica_considerations=(),
        mechanism_considerations=(
            _finding("delegated_authority"),
            _finding("user_claim"),
            _finding("stale_history", ica_id="ICA-OTHER"),
        ),
    )

    considerations = contexts["SCN-001"].obligation_considerations
    assert [(item.kind, item.mechanism_id) for item in considerations] == [
        ("mechanism", "user_claim"),
        ("mechanism", "delegated_authority"),
    ]
    entry = bundled_mechanism_library().entry("user_claim")
    assert considerations[0].mechanism_name == entry.name
    assert considerations[0].concise_concern == entry.question
    assert considerations[0].obligation_id is None


def test_a_context_without_mechanism_findings_keeps_its_bytes() -> None:
    plain = _build_synthesis_scenario_contexts(
        [_THREAT],
        _wrong_timing_structure(),
        _loss_analysis(),
        briefs=(),
        ica_considerations=(),
    )

    assert plain["SCN-001"] == _context()
    assert plain["SCN-001"].context_digest == _context().context_digest


def test_a_mechanism_consideration_serializes_only_its_own_identity() -> None:
    dumped = _mechanism_consideration().model_dump(mode="json")

    assert dumped["kind"] == "mechanism"
    for absent in ("obligation_id", "attack_pattern_id", "risk_id", "risk_name"):
        assert absent not in dumped
    with pytest.raises(ValueError, match="cannot carry the other kind"):
        ScenarioObligationConsideration(
            **{**dumped, "obligation_id": "ob:v1:" + "1" * 64}
        )
    with pytest.raises(ValueError, match="requires its identity"):
        ScenarioObligationConsideration(
            concise_concern="c",
            disposition="finding",
            rationale="r",
            attack_pattern_id="AP-T1-01",
            attack_pattern_name="Pattern",
        )


def test_stage5_shows_the_mechanism_as_provenance_and_keeps_every_source() -> None:
    plain = _context()
    with_mechanism = _context(_mechanism_consideration())
    loader = TemplateLoader(PROMPTS_DIR)

    plain_system, plain_user = build_context_bdi_prompts(plain, loader)
    system, user = build_context_bdi_prompts(with_mechanism, loader)

    entry = bundled_mechanism_library().entry("user_claim")
    assert "mechanism_name" not in plain_system + plain_user
    assert f"mechanism_name: {entry.name}" in user
    bullet = "A taxonomy consideration with `mechanism_name` names a known"
    assert bullet not in plain_system
    assert bullet in " ".join(system.split())
    assert _causal_source_choices(with_mechanism) == _causal_source_choices(plain)
    source_ids = {item.source_id for item in _causal_source_choices(with_mechanism)}
    assert not source_ids & {item.value for item in MechanismId}
    assert all(
        source_id.startswith(("PM-", "FB-", "CA-", "RESP-", "CL-"))
        for source_id in source_ids
    )


@pytest.mark.parametrize(
    "kind",
    [
        CausalFactorKind.process_model_flaw,
        CausalFactorKind.feedback_delay,
        CausalFactorKind.actuator_anomaly,
    ],
)
def test_a_library_id_never_stands_in_for_a_causal_source(kind) -> None:
    context = _context(_mechanism_consideration())
    offered = _causal_source_choices(context)
    outside = f"cause_{len(offered) + 1}"
    choices = (
        *offered,
        _CausalSourceChoice(
            handle=outside,
            kind=kind,
            source_id="user_claim",
            description="User claim stands in for an established value",
        ),
    )

    # The causal factor model rejects a source outside its kind's namespace.
    with pytest.raises(ValueError, match="namespace"):
        compile_draft(
            draft_payload([factor(outside, "The claim stands in for the value.")]),
            context,
            stage5_assembly(context, _THREAT, _wrong_timing_structure()),
            choices=choices,
        )


def test_a_library_match_never_upgrades_an_evidence_status() -> None:
    context = _context(_mechanism_consideration())
    handle = _causal_source_choices(context)[0].handle

    with pytest.raises(ValueError, match="not present in the exact scenario context"):
        compile_draft(
            draft_payload(
                [
                    factor(
                        handle,
                        "The verified mechanism gives the adversary access.",
                        evidence_status="reachable_capability",
                        capability_refs=["user_claim"],
                        access_refs=["FB-1-1"],
                    )
                ]
            ),
            context,
            stage5_assembly(context, _THREAT, _wrong_timing_structure()),
        )


def _scenario_kwargs(monkeypatch, pairs) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def scenarios(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr(synthesis_scenarios, "_systemic_inputs", lambda value: value)
    slot_evidence = SlotFillRunResult(
        result=SynthesisSlotFillResult(
            ica_enumeration=ICAEnumeration(slots=[]),
            mechanism_considerations=pairs,
        )
    )
    synthesis_scenarios._run_scenarios(
        ICAEnumeration(slots=[]),
        (),
        (),
        None,
        None,
        None,
        None,
        SimpleNamespace(
            execution_target_profile=None,
            target_observations=None,
            output_dir="out",
            max_workers=1,
        ),
        None,
        SimpleNamespace(scenarios=scenarios, model_runtime=None),
        slot_evidence=slot_evidence,
    )
    return seen


def test_the_scenario_port_sees_mechanism_findings_only_when_there_is_one(
    monkeypatch,
) -> None:
    assert "mechanism_considerations" not in _scenario_kwargs(monkeypatch, ())
    pairs = (_finding(),)
    assert _scenario_kwargs(monkeypatch, pairs)["mechanism_considerations"] == pairs

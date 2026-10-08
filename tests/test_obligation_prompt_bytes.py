"""Obligation-aware provider requests stay byte-identical for one recorded input.

The inputs come from the pp-int38m occiai-r2 recording (final loss analysis
and control structure, five pattern briefs with their final routes, the
recorded missing concept, two governance briefs, and two final ICAs read back
from the recorded verification request).  ``expected.json`` pins every
request the adapter sends for them: the SHA-256 of the system prompt, the
user prompt, the response schema, the completion cap, and the temperature,
plus each request's semantic digest and the adapter's outcome.  The fake
client answers with text that is not JSON, so each stage stops after its
first request.  On a mismatch the test writes the full requests next to
``tmp_path`` for diffing.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any

from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
    NeutralObligationBrief,
    ObligationRoute,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import ICA, ICASlot
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.obligation_aware import (
    governance_prompts,
    governance_provider,
    prompts,
    provider,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    AnalysisControls,
    StructuralRevisionRequest,
    StructuralRoutingRequest,
)
from asago_scenario_generator.stpa.obligation_aware.governance_routing import (
    GovernanceRoutingRequest,
)
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaHazardVerificationVerdict,
    build_ica_hazard_verification_request,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    build_synthesis_slot_requests,
    final_slot_universe,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "obligation_prompt_bytes"


class _RecordingClient:
    """Record every request and answer it with text no schema accepts."""

    model = "prompt-bytes-recorder"
    session = None

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def complete(self, **kwargs: Any) -> LLMResult:
        response_format = kwargs.get("response_format")
        self.requests.append(
            {
                "system_prompt": kwargs["system_prompt"],
                "user_prompt": kwargs["user_prompt"],
                "response_schema": None
                if response_format is None
                else response_format.model_json_schema(),
                "max_completion_tokens": kwargs.get("max_completion_tokens"),
                "temperature": kwargs.get("temperature"),
            }
        )
        return LLMResult(
            content="not a JSON document",
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def _controls() -> AnalysisControls:
    return AnalysisControls(
        model_profile="synthesis",
        model_name="prompt-bytes",
        deadline_seconds=300.0,
        temperature=0.2,
    )


def _inputs() -> dict[str, Any]:
    raw = json.loads((_FIXTURE / "inputs.json").read_text(encoding="utf-8"))
    return {
        "loss_analysis": LossAnalysis.model_validate(raw["loss_analysis"]),
        "control_structure": ControlStructure.model_validate(raw["control_structure"]),
        "briefs": tuple(
            NeutralObligationBrief.model_validate(item) for item in raw["briefs"]
        ),
        "routes": tuple(
            ObligationRoute.model_validate(item) for item in raw["final_routes"]
        ),
        "gaps": tuple(
            MissingStructuralConcept.model_validate(item)
            for item in raw["missing_concepts"]
        ),
        "governance_briefs": tuple(
            NeutralObligationBrief.model_validate(item)
            for item in raw["governance_briefs"]
        ),
        "verification_items": raw["verification_items"],
    }


def _verification_requests(inputs: dict[str, Any]) -> tuple[Any, ...]:
    slots = {
        item.slot_id: item for item in final_slot_universe(inputs["control_structure"])
    }
    requests = []
    for index, item in enumerate(inputs["verification_items"], start=1):
        slot_id = f"{item['responsibility_id']}:{item['control_action_id']}:INCORRECT"
        placeholder = slots[slot_id]
        ica = ICA(
            ica_id=f"{slot_id}:{index}",
            ica_text=item["deviation"],
            deviation=item["deviation"],
            hazardous_context=item["hazardous_context"],
            loss_scenario=item["loss_consequence"],
            related_hazards=item["hazard_ids"],
            related_constraints=item["constraint_ids"],
        )
        slot = ICASlot(
            slot_id=slot_id,
            responsibility=placeholder.responsibility,
            coordination_link=placeholder.coordination_link,
            control_action=placeholder.control_action,
            action_temporality=placeholder.action_temporality,
            uca_type=placeholder.uca_type,
            is_na=False,
            icas=[ica],
        )
        requests.append(
            build_ica_hazard_verification_request(
                ica,
                slot,
                inputs["loss_analysis"],
                inputs["control_structure"],
            )
        )
    return tuple(requests)


def _send(
    tmp_path: Path, name: str, call: Any, record: dict[str, Any], digest: Any
) -> None:
    client = _RecordingClient()
    adapter = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path / name, controls=_controls()
    )
    try:
        call(adapter)
    except Exception as exc:  # noqa: BLE001 - every call fails on purpose
        outcome = f"{type(exc).__name__}: {exc}"
    else:
        outcome = "returned"
    record[name] = {
        "semantic_digest": digest,
        "requests": client.requests,
        "outcome": outcome,
    }


def render_all(tmp_path: Path) -> dict[str, Any]:
    """Send every obligation-aware request once and return what was sent."""
    inputs = _inputs()
    loss = inputs["loss_analysis"]
    structure = inputs["control_structure"]
    slots = final_slot_universe(structure)
    controls = _controls()
    record: dict[str, Any] = {}

    routing = StructuralRoutingRequest(
        batch_id="initial-batch-1",
        briefs=inputs["briefs"],
        loss_analysis=loss,
        control_structure=structure,
        slots=slots,
        controls=controls,
    )
    _send(
        tmp_path, "route", lambda a: a.route(routing), record, routing.semantic_digest
    )
    _send(
        tmp_path,
        "route_correction",
        lambda a: a.route(routing, correction_feedback="Return one route each."),
        record,
        routing.semantic_digest,
    )
    targeted = tuple(
        route for route in inputs["routes"] if route.disposition == "targeted"
    )
    _send(
        tmp_path,
        "mechanism_verification",
        lambda a: a.verify_mechanisms(routing, targeted),
        record,
        routing.semantic_digest,
    )

    governance = GovernanceRoutingRequest(
        batch_id="governance-batch-1",
        briefs=inputs["governance_briefs"],
        loss_analysis=loss,
        control_structure=structure,
        slots=slots,
        controls=controls,
    )
    _send(
        tmp_path,
        "governance_route",
        lambda a: a.route_governance(governance),
        record,
        governance.semantic_digest,
    )

    revision = StructuralRevisionRequest(
        gaps=inputs["gaps"],
        baseline_loss_analysis=loss,
        baseline_control_structure=structure,
        controls=controls,
    )
    _send(
        tmp_path,
        "revise",
        lambda a: a.revise(revision),
        record,
        revision.semantic_digest,
    )

    slot_requests = build_synthesis_slot_requests(
        briefs=inputs["briefs"],
        routes=inputs["routes"],
        loss_analysis=loss,
        control_structure=structure,
        controls=controls,
    )
    fill = next(item for item in slot_requests if item.target_id == "RESP-1")
    _send(tmp_path, "fill", lambda a: a.fill(fill), record, fill.semantic_digest)

    verification = _verification_requests(inputs)
    digests = [item.semantic_digest for item in verification]
    _send(
        tmp_path,
        "ica_verification",
        lambda a: a.verify_ica_hazards(verification),
        record,
        digests,
    )
    _send(
        tmp_path,
        "ica_verification_correction",
        lambda a: a.verify_ica_hazards(
            verification,
            correction_feedback={verification[0].ica_id: "revised once"},
        ),
        record,
        digests,
    )
    verdict = IcaHazardVerificationVerdict(
        ica_id=verification[0].ica_id,
        verdict="contradictory",
        rationale="The selected hazard does not follow from the deviation.",
    )
    _send(
        tmp_path,
        "ica_correction",
        lambda a: a.correct_ica_hazard(verification[0], verdict),
        record,
        digests[0],
    )
    return record


def _sha256(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def fingerprint(record: dict[str, Any]) -> dict[str, Any]:
    """Replace each sent request field by its SHA-256."""
    return {
        name: {
            **value,
            "requests": [
                {field: _sha256(item) for field, item in request.items()}
                for request in value["requests"]
            ],
        }
        for name, value in record.items()
    }


def test_every_obligation_aware_request_keeps_its_recorded_bytes(tmp_path) -> None:
    expected = json.loads((_FIXTURE / "expected.json").read_text(encoding="utf-8"))
    record = render_all(tmp_path)
    actual = fingerprint(record)
    if actual != expected:
        (tmp_path / "actual-requests.json").write_text(
            json.dumps(record, indent=1, sort_keys=True), encoding="utf-8"
        )

    assert sorted(actual) == sorted(expected)
    for name, value in expected.items():
        assert actual[name] == value, name


_PROJECTIONS = (
    (prompts, "project_obligation_routing_context"),
    (provider, "project_obligation_routing_context"),
    (prompts, "project_revision_context"),
    (provider, "project_revision_context"),
    (prompts, "project_ica_target_context"),
    (provider, "project_ica_target_context"),
    (governance_prompts, "project_governance_routing_context"),
    (governance_provider, "project_governance_routing_context"),
)


def test_each_provider_call_projects_its_prompt_view_once(
    tmp_path, monkeypatch
) -> None:
    calls: Counter[str] = Counter()

    def counting(name: str, function: Any) -> Any:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            calls[name] += 1
            return function(*args, **kwargs)

        return wrapper

    for module, name in _PROJECTIONS:
        if hasattr(module, name):
            monkeypatch.setattr(module, name, counting(name, getattr(module, name)))

    render_all(tmp_path)

    # route and route_correction project the routing view; the other stages
    # send one request each.
    assert calls == {
        "project_obligation_routing_context": 2,
        "project_governance_routing_context": 1,
        "project_revision_context": 1,
        "project_ica_target_context": 1,
    }


def test_a_correction_verification_sends_the_initial_verification_prompt(
    tmp_path,
) -> None:
    record = render_all(tmp_path)

    assert (
        record["ica_verification_correction"]["requests"]
        == record["ica_verification"]["requests"]
    )

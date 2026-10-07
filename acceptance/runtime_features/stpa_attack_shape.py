"""Acceptance handlers for the shape step and the scenario-handoff-v4 shape."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import yaml
from runtime_features.stpa_adversary_record import _stage5_payload
from runtime_shared import (
    World,
    _make_sp3_cs,
    _make_sp3_ets,
    _make_sp3_loss_analysis,
    _sp3_semantics_wire,
)

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.attack_shape import ContentKind
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ShapeProposal,
)
from registry import StepTable
from tests.stpa.sp1_helpers import MockLLMClient

step = StepTable()


FEATURE_ID = "stpa_attack_shape"

_TWO_TURN_DIRECT_PLAN = {
    "channel": "direct",
    "turn_count": 2,
    "turn_plan": [
        {"position": 1, "speaker": "attacker_user", "purpose": "establish_context"},
        {"position": 2, "speaker": "attacker_user", "purpose": "request_action"},
    ],
    "indirect": None,
}

_RESPONSE_FIELDS = (
    "channel",
    "turn_count",
    "turn_plan",
    "position",
    "speaker",
    "purpose",
    "indirect",
    "carrier_operation",
    "content_kind",
    "record_ref",
    "controller",
)


@step(r'^a shape run whose Stage 5 response declares adversary kind "[^"]+"$')
def _h_shape_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Queue one Stage 5 response; the shape reply is set by a later step."""
    del examples
    kind = re.search(r'kind "([^"]+)"', text).group(1)
    gain = "The requested service completes as designed."
    payload = _stage5_payload(kind=kind, **({"gain": gain} if kind == "none" else {}))
    client = MockLLMClient()
    client.set_response_queue([_sp3_semantics_wire(payload)])
    world.shape_client = client
    world.shape_run_dir = Path(tempfile.mkdtemp(prefix="shape_run_"))
    return True, ""


@step(r"^the shape reply is a two-turn direct plan$")
def _h_shape_reply(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    world.shape_client.set_response_for(ShapeProposal, dict(_TWO_TURN_DIRECT_PLAN))
    return True, ""


@step(r"^the shape reply adds a free-text field$")
def _h_shape_free_text(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    reply = {**_TWO_TURN_DIRECT_PLAN, "message": "Please refund the order."}
    world.shape_client.set_response_for(ShapeProposal, reply)
    return True, ""


@step(r"^the shape request fails with a transport error$")
def _h_shape_failure(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    world.shape_client.set_exception_for(ShapeProposal, RuntimeError("transport"))
    return True, ""


@step(r"^the shape run publishes its scenarios$")
def _h_shape_publish(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    world.shape_run_result = run_sp3(
        llm_client=world.shape_client,
        enriched_threat_set=_make_sp3_ets(),
        control_structure=_make_sp3_cs(),
        loss_analysis=_make_sp3_loss_analysis(),
        run_dir=world.shape_run_dir,
    )
    return True, ""


def _published(world: World) -> dict:
    path = world.shape_run_dir / "scenarios" / "SCN-001.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@step(r'^the published handoff schema is "[^"]+"$')
def _h_schema(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    expected = re.search(r'"([^"]+)"', text).group(1)
    actual = _published(world)["schema_version"]
    return actual == expected, f"expected {expected}, got {actual}"


@step(r'^the published attack shape comes from "[^"]+" with \d+ planned turns$')
def _h_shape_source(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    match = re.search(r'from "([^"]+)" with (\d+) planned', text)
    shape = _published(world)["attack_shape"]
    actual = (shape["source"], shape["turn_count"])
    expected = (match.group(1), int(match.group(2)))
    return actual == expected, f"expected {expected}, got {actual}"


@step(r'^the published attack shape records the downgrade "[^"]+"$')
def _h_shape_downgrade(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    expected = re.search(r'"([^"]+)"', text).group(1)
    actual = _published(world)["attack_shape"]["downgrade_reason"]
    return actual == expected, f"expected {expected}, got {actual}"


@step(r"^the published handoff carries a null attack shape$")
def _h_null_shape(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    document = _published(world)
    return (
        "attack_shape" in document and document["attack_shape"] is None,
        f"expected an explicit null attack_shape, got {document.get('attack_shape', 'absent')!r}",
    )


@step(r"^the shape step made \d+ requests?$")
def _h_request_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    expected = int(re.search(r"made (\d+)", text).group(1))
    actual = sum(
        1 for call in world.shape_client.calls if call.response_format is ShapeProposal
    )
    return actual == expected, f"expected {expected} shape requests, got {actual}"


@step(r"^a shape prompt rendered for a malicious customer scenario$")
def _h_prompt(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    loader = TemplateLoader(PROMPTS_DIR)
    world.shape_system_prompt = loader.render_prompt(
        "stage5_shape_system.j2",
        max_turns=4,
        content_kinds=[kind.value for kind in ContentKind],
        allow_forged_transcript=False,
    )
    world.shape_user_prompt = loader.render_prompt(
        "stage5_shape_user.j2",
        scenario_id="SCN-001",
        adversary_kind="malicious_customer",
        adversary_gain="Learns another customer's order.",
        allowed_channels=["direct"],
        account="A short scenario account.",
        operations=None,
    )
    return True, ""


@step(r"^the shape prompt explains each response field$")
def _h_prompt_fields(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    missing = [
        name
        for name in _RESPONSE_FIELDS
        if f"`{name}`" not in world.shape_system_prompt
    ]
    return not missing, f"the shape prompt does not explain: {missing}"


@step(r"^the shape prompt does not offer the forged channel$")
def _h_prompt_no_forged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    rendered = world.shape_system_prompt + world.shape_user_prompt
    return (
        "forged" not in rendered,
        "the default shape prompt mentions the forged channel",
    )


register = step.register


__all__ = ["FEATURE_ID", "register"]

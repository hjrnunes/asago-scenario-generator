"""Acceptance handlers for the Phase 3 adversary record and disposition."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from runtime_shared import (
    World,
    _make_sp3_cs,
    _make_sp3_ets,
    _make_sp3_loss_analysis,
    _make_sp3_threat,
)

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    build_context_bdi_prompts,
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from tests.stpa.sp1_helpers import MockLLMClient


FEATURE_ID = "stpa_adversary_record"


def _stage5_payload(
    *,
    kind: str = "malicious_customer",
    gain: str = "Learns another customer's order details.",
    stimulus: str = "user_message",
) -> dict:
    """Build one valid corrected Stage 5 response with its adversary record."""
    indirect = stimulus in {"retrieved_content", "tool_content"}
    factor: dict = {
        "source_handle": "cause_1",
        "selected_for_route": True,
        "evidence": "The selected structural condition can remain stale.",
        "temporal_condition": None,
        "evidence_status": ("bounded_assumption" if indirect else "structural_failure"),
    }
    if indirect:
        factor["bounded_assumption"] = (
            "The test can alter content at the supplied retrieval path."
        )
    return {
        "stimulus": {
            "category": stimulus,
            "description": "The supplied test stimulus exercises the selected factor.",
        },
        "adversary": {
            "kind": kind,
            "gain": gain,
        },
        "attacker_bdi": {
            "beliefs": ["The controller can act on stale state."],
            "desires": ["Induce the selected unsafe action."],
            "intentions": [
                {
                    "description": "Rely on the selected structural condition.",
                    "source_handles": ["cause_1"],
                }
            ],
        },
        "causal_factors": [factor],
        "unsafe_outcome": {
            "condition": {
                "type": "action_presence",
                "control_action_id": "CA-1-1",
                "expected": "not_provided",
            },
            "semantic_proposition": (
                "The model response exhibits the selected unsafe behavior."
            ),
        },
        "execution_route": {
            "disposition": "executable_route",
            "action_kind": "model_output",
            "reason": "The supplied structural evidence supports this route.",
        },
    }


def _h_context(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Prepare the immutable Stage 5 context for the adversary examples."""
    del text, examples
    world.adversary_context = build_scenario_generation_context(
        _make_sp3_threat(),
        _make_sp3_cs(),
        _make_sp3_loss_analysis(),
        scenario_id="SCN-001",
    )
    return True, ""


def _h_omit_adversary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Queue a schema-valid-looking response without the adversary record."""
    del text, examples
    payload = _stage5_payload()
    del payload["adversary"]
    client = MockLLMClient()
    client.set_response_queue([payload, payload])
    world.adversary_client = client
    return True, ""


def _h_materialize(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Run corrected Stage 5 against the queued adversary response."""
    del text, examples
    world.adversary_result, world.adversary_error = generate_bdi_for_context(
        world.adversary_client,
        world.adversary_context,
        Path(tempfile.mkdtemp()),
    )
    return True, ""


def _h_analytical_upload(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Queue one analytical-only response for an unsupported upload stimulus."""
    del text, examples
    payload = _stage5_payload(kind="external_attacker", stimulus="file_upload")
    payload["causal_factors"][0]["selected_for_route"] = False
    payload["execution_route"] = {
        "disposition": "analytical_only",
        "gaps": [
            {
                "code": "delivery_path_missing",
                "detail": "The upload path cannot carry the test stimulus to the model.",
                "evidence_handles": ["cause_1"],
            }
        ],
        "reason": "The unsupported upload delivery has no executable replay path.",
    }
    client = MockLLMClient()
    client.set_response_queue([payload, payload])
    world.adversary_client = client
    return True, ""


def _h_materialized_adversary(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'^the materialized adversary carries kind "([^"]+)"'
        r'(?: via "([^"]+)")?( with no delivery)?$',
        text,
    )
    if match is None:
        return False, f"could not parse expected adversary: {text}"
    result = getattr(world, "adversary_result", None)
    if result is None or result.adversary is None:
        return False, "Stage 5 produced no materialized adversary"
    adversary = result.adversary
    kind_ok = adversary.kind.value == match.group(1)
    if match.group(3):
        reach_ok = adversary.reaches_target_via is None
    else:
        reach_ok = (
            adversary.reaches_target_via is not None
            and adversary.reaches_target_via.value == match.group(2)
        )
    return (
        kind_ok and reach_ok,
        f"expected kind {match.group(1)!r} reach "
        f"{'None' if match.group(3) else match.group(2)!r}, got "
        f"{adversary.kind.value!r} / {adversary.reaches_target_via!r}",
    )


def _h_stage5_adversary_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    error = getattr(world, "adversary_error", "") or ""
    return (
        getattr(world, "adversary_result", None) is None and "adversary" in error,
        f"expected an adversary failure, got {error!r}",
    )


def _h_run_declares_adversary(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Queue one product-run Stage 5 response with the declared adversary."""
    import re

    if 'kind "none"' in text:
        payload = _stage5_payload(
            kind="none",
            gain=re.search(r'gain "([^"]+)"', text).group(1),
        )
    elif "third_party_via_content" in text:
        payload = _stage5_payload(
            kind="third_party_via_content",
            stimulus="retrieved_content",
        )
    elif "restating" in text:
        payload = _stage5_payload(gain=re.search(r'restating "([^"]+)"', text).group(1))
    else:
        payload = _stage5_payload(kind="malicious_customer")
    client = MockLLMClient()
    client.set_response_queue([payload, payload])
    world.adversary_client = client
    world.adversary_run_dir = Path(tempfile.mkdtemp(prefix="adversary_run_"))
    return True, ""


def _h_run_publishes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Execute the product SP3 run over the queued adversary response."""
    del text, examples
    from asago_scenario_generator.stpa.scenario_prod.run import run_sp3

    world.adversary_run_result = run_sp3(
        llm_client=world.adversary_client,
        enriched_threat_set=_make_sp3_ets(),
        control_structure=_make_sp3_cs(),
        loss_analysis=_make_sp3_loss_analysis(),
        run_dir=world.adversary_run_dir,
    )
    return True, ""


def _h_candidate_outcome(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'^the candidate outcome is "([^"]+)"$', text)
    if match is None:
        return False, f"could not parse expected outcome: {text}"
    result = getattr(world, "adversary_run_result", None)
    if result is None or not result.candidate_outcomes:
        return False, "the run produced no candidate outcomes"
    actual = result.candidate_outcomes[0].status.value
    return (actual == match.group(1), f"expected {match.group(1)}, got {actual}")


def _h_functional_persisted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    result = world.adversary_run_result
    persisted = (world.adversary_run_dir / "scenarios" / "SCN-001.yaml").is_file()
    return (
        len(result.functional_test_specs) == 1 and persisted,
        f"expected one persisted functional test, got "
        f"{len(result.functional_test_specs)} specs, persisted={persisted}",
    )


def _h_bundle_empty(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return (
        not (world.adversary_run_dir / "execution-bundle.json").exists(),
        "the run published an execution bundle for a functional test",
    )


def _h_run_records(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'^the run records the "([^"]+)" rejection$', text)
    if match is None:
        return False, f"could not parse expected rejection: {text}"
    result = world.adversary_run_result
    diagnostics = " ".join(result.stage_errors)
    return (
        match.group(1) in diagnostics,
        f"expected {match.group(1)!r} in run diagnostics, got {diagnostics!r}",
    )


def _h_published_carries(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'^the published scenario carries adversary kind "([^"]+)" via "([^"]+)"$',
        text,
    )
    if match is None:
        return False, f"could not parse expected adversary: {text}"
    result = world.adversary_run_result
    if not result.scenario_envelopes:
        return False, "the run published no scenarios"
    adversary = result.scenario_envelopes[0].scenario_spec.adversary
    if adversary is None:
        return False, "the published scenario carries no adversary record"
    actual = (adversary.kind.value, adversary.reaches_target_via.value)
    return (actual == match.groups(), f"expected {match.groups()}, got {actual}")


def _h_functional_gain(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """The persisted functional test carries the compiler-owned marker gain."""
    del text, examples
    from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
        FUNCTIONAL_TEST_GAIN,
    )

    result = world.adversary_run_result
    if not result.functional_test_specs:
        return False, "the run persisted no functional-test specs"
    adversary = result.functional_test_specs[0].adversary
    if adversary is None:
        return False, "the persisted functional test carries no adversary record"
    return (
        adversary.gain == FUNCTIONAL_TEST_GAIN,
        f"expected the compiler-owned gain, got {adversary.gain!r}",
    )


def _h_prompt_mentions_adversary(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    system, user = build_context_bdi_prompts(
        world.adversary_context,
        TemplateLoader(PROMPTS_DIR),
    )
    rendered = " ".join(f"{system}\n{user}".split())
    required = (
        "external_attacker",
        "malicious_customer",
        "third_party_via_content",
        "kind: none",
    )
    missing = [item for item in required if item not in rendered]
    stale = "reaches_target_via" in rendered
    return (
        not missing and not stale,
        f"prompt is missing adversary guidance: {missing}; "
        f"stale reaches_target_via present: {stale}",
    )


def register(api: object) -> None:
    """Register the Phase 3 adversary acceptance steps."""
    api.register(r"^a corrected Stage 5 adversary context is available$", _h_context)
    api.register(
        r"^the provider response omits the adversary record$", _h_omit_adversary
    )
    api.register(
        r"^the provider response selects an analytical route for an "
        r"unsupported upload$",
        _h_analytical_upload,
    )
    api.register(
        r"^corrected Stage 5 materializes the adversary record$", _h_materialize
    )
    api.register(
        r'^the materialized adversary carries kind "[^"]+"'
        r'(?: via "[^"]+")?( with no delivery)?$',
        _h_materialized_adversary,
    )
    api.register(
        r"^Stage 5 fails closed with an adversary error$",
        _h_stage5_adversary_failure,
    )
    api.register(
        r"^a run whose provider response declares "
        r'(?:adversary kind "[^"]+"(?: with gain "[^"]+")?'
        r'(?: with an? "[^"]+" stimulus)?'
        r'|a gain restating "[^"]+")$',
        _h_run_declares_adversary,
    )
    api.register(
        r"^the product scenario run publishes its artifacts$", _h_run_publishes
    )
    api.register(r'^the candidate outcome is "[^"]+"$', _h_candidate_outcome)
    api.register(
        r"^the functional scenario is persisted under scenarios/$",
        _h_functional_persisted,
    )
    api.register(
        r"^the persisted functional test carries the compiler-owned gain$",
        _h_functional_gain,
    )
    api.register(r"^the execution bundle contains no entries$", _h_bundle_empty)
    api.register(r'^the run records the "[^"]+" rejection$', _h_run_records)
    api.register(
        r'^the published scenario carries adversary kind "[^"]+" via "[^"]+"$',
        _h_published_carries,
    )
    api.register(
        r"^the Stage 5 prompt explains the adversary record$",
        _h_prompt_mentions_adversary,
    )


__all__ = ["FEATURE_ID", "register"]

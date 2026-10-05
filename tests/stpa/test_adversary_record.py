"""Phase 3: a required adversary on every scenario candidate.

Spec: ai/findings/target-grounded-scenario-generation-spec-2026-09-07.md,
Phase 3.1/3.2.  Every scenario names who attempts the unsafe behavior and
what they gain; ``kind: none`` marks a functional test that never reaches
the execution bundle.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
    AdversaryReach,
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from .test_sp3_stage5_provider_contract import _provider_payload, _typed_tool_context
from tests.stpa.sp1_helpers import MockLLMClient
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    generate_bdi_for_context,
    FUNCTIONAL_TEST_GAIN,
    _ContextStimulusDraft,
    _ContextAdversaryDraft,
    _materialize_adversary,
)


def _adversary(**overrides: object) -> Adversary:
    fields: dict[str, object] = {
        "kind": "malicious_customer",
        "gain": "Drains another customer's stored balance.",
        "reaches_target_via": "user_message",
    }
    fields.update(overrides)
    return Adversary.model_validate(fields)


def _spec(**overrides: object) -> ScenarioSpec:
    fields: dict[str, object] = {
        "scenario_id": "SCN-001",
        "threat_source": ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
        ),
        "target_controller": "RESP-1",
        "target_control_action": "CA-1-1",
        "ica_type": UCAType.not_provided,
        "defender_bdi": DefenderBDI(
            beliefs=[
                DefenderBelief(
                    pm_id="PM-1-1",
                    content="Retrieved state",
                    vulnerability="retrieval can be poisoned",
                ),
            ],
            desires=[DefenderDesire(resp_id="RESP-1", content="Coordinate the agent")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Select a tool")],
        ),
        "attacker_bdi": AttackerBDI(
            beliefs=["The retrieved state is exploitable"],
            desires=["Induce NOT_PROVIDED"],
            intentions=["Poison PM-1-1 via FB-1-1"],
        ),
        "loss_scenario": "The user receives no service.",
    }
    fields.update(overrides)
    return ScenarioSpec.model_validate(fields)


class TestAdversaryModel:
    def test_kind_enum_covers_the_spec_values(self) -> None:
        assert {kind.value for kind in AdversaryKind} == {
            "external_attacker",
            "malicious_customer",
            "third_party_via_content",
            "none",
        }

    def test_reach_enum_covers_the_delivery_primitives(self) -> None:
        assert {reach.value for reach in AdversaryReach} == {
            "user_message",
            "conversation",
            "retrieved_content",
        }

    def test_blank_gain_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _adversary(gain="   ")

    def test_unknown_fields_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _adversary(mechanism="prompt_injection")

    def test_gain_is_stripped(self) -> None:
        adversary = _adversary(gain="  Free refunds.  ")
        assert adversary.gain == "Free refunds."

    def test_null_reach_is_accepted_for_analytical_stimuli(self) -> None:
        adversary = _adversary(reaches_target_via=None)
        assert adversary.reaches_target_via is None


class TestScenarioSpecAdversary:
    def test_adversary_defaults_to_none(self) -> None:
        spec = _spec()
        assert spec.adversary is None
        assert spec.is_functional_test is False

    def test_round_trip_preserves_adversary(self) -> None:
        spec = _spec(adversary=_adversary())
        loaded = ScenarioSpec.model_validate(spec.model_dump(mode="json"))
        assert loaded.adversary == _adversary()
        assert loaded.is_functional_test is False

    def test_kind_none_marks_functional_test(self) -> None:
        spec = _spec(adversary=_adversary(kind="none"))
        assert spec.is_functional_test is True

    def test_legacy_spec_without_adversary_is_not_functional(self) -> None:
        assert _spec().is_functional_test is False


class TestStage5AdversaryWire:
    """The corrected contextual Stage 5 wire requires a valid adversary."""

    def test_missing_adversary_is_a_provider_failure(self, tmp_path) -> None:

        payload = _provider_payload()
        payload.pop("adversary")
        client = MockLLMClient()
        client.set_response_queue([payload, payload])

        result, error = generate_bdi_for_context(
            client, _typed_tool_context(), tmp_path
        )

        assert result is None
        assert error is not None
        assert "adversary" in error
        assert "Field required" in error

    def test_gain_that_restates_a_constraint_is_rejected(self, tmp_path) -> None:

        payload = _provider_payload()
        payload["adversary"]["gain"] = "enforce reviewed batch limits."
        client = MockLLMClient()
        client.set_response_queue([payload, payload])

        result, error = generate_bdi_for_context(
            client, _typed_tool_context(), tmp_path
        )

        assert result is None
        assert error is not None
        assert "adversary gain restates constraint SC-MASS" in error

    def test_reach_is_derived_from_the_stimulus_category(self, tmp_path) -> None:

        client = MockLLMClient()
        client.set_response_queue([_provider_payload()])

        result, error = generate_bdi_for_context(
            client, _typed_tool_context(), tmp_path
        )

        assert error is None
        assert result is not None
        assert result.adversary.reaches_target_via.value == "user_message"

    def test_third_party_without_content_surface_is_rejected(self, tmp_path) -> None:

        payload = _provider_payload()
        payload["stimulus"]["category"] = "retrieved_content"
        payload["adversary"] = {
            "kind": "third_party_via_content",
            "gain": "Learns another customer's order details.",
        }
        payload["causal_factors"][0].update(
            evidence_status="bounded_assumption",
            bounded_assumption="The test can alter the supplied tool-result carrier.",
        )
        client = MockLLMClient()
        client.set_response_queue([payload, payload])

        result, error = generate_bdi_for_context(
            client, _typed_tool_context(), tmp_path
        )

        assert result is None
        assert error is not None
        assert "no_content_surface" in error

    def test_kind_none_ignores_the_provider_gain(self, tmp_path) -> None:

        payload = _provider_payload()
        payload["adversary"] = {
            "kind": "none",
            "gain": "enforce reviewed batch limits.",
        }
        payload["attacker_bdi"] = {
            "beliefs": [],
            "desires": [],
            "intentions": [],
        }
        client = MockLLMClient()
        client.set_response_queue([payload, payload])

        result, error = generate_bdi_for_context(
            client, _typed_tool_context(), tmp_path
        )

        assert error is None
        assert result is not None
        assert result.adversary.gain == FUNCTIONAL_TEST_GAIN

    def test_valid_adversary_is_carried_onto_the_materialized_result(
        self, tmp_path
    ) -> None:

        client = MockLLMClient()
        client.set_response_queue([_provider_payload()])

        result, error = generate_bdi_for_context(
            client, _typed_tool_context(), tmp_path
        )

        assert error is None
        assert result is not None
        payload_adversary = _provider_payload()["adversary"]
        assert result.adversary == Adversary(
            kind=payload_adversary["kind"],
            gain=payload_adversary["gain"],
            reaches_target_via="user_message",
        )


class TestAdversaryMaterialization:
    """Compiler-owned reach and gain derivation (Phase 3 deviations 7-8)."""

    def _stimulus(self, category: str):
        return _ContextStimulusDraft(
            category=category,
            description="The typed test stimulus.",
        )

    def _draft(self, kind: str = "malicious_customer", gain: str = "A gain."):
        return _ContextAdversaryDraft(kind=kind, gain=gain)

    def test_reach_mapping_covers_the_delivery_primitives(self) -> None:
        expected = {
            "user_message": AdversaryReach.user_message,
            "conversation": AdversaryReach.conversation,
            "conversation_context": AdversaryReach.conversation,
            "retrieved_content": AdversaryReach.retrieved_content,
            "tool_content": AdversaryReach.retrieved_content,
        }
        for category, reach in expected.items():
            assert (
                _materialize_adversary(
                    self._draft(), self._stimulus(category)
                ).reaches_target_via
                is reach
            ), category

    def test_unmapped_analytical_categories_persist_null_reach(self) -> None:
        for category in ("file_upload", "traffic_load", "unknown"):
            assert (
                _materialize_adversary(
                    self._draft(), self._stimulus(category)
                ).reaches_target_via
                is None
            ), category

    def test_kind_none_gain_is_the_fixed_marker(self) -> None:
        adversary = _materialize_adversary(
            self._draft(kind="none", gain="echoed prompt text"),
            self._stimulus("user_message"),
        )
        assert adversary.gain == FUNCTIONAL_TEST_GAIN
        assert adversary.gain != "echoed prompt text"

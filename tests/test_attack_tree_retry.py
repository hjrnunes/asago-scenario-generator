"""Tests for attack tree YAML generation retry logic (bead 40s).

Covers:
1. Successful parse on first attempt -- no retry.
2. Failed first attempt, successful retry -- returns the retried result.
3. Both attempts fail -- raises the original error.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import yaml

from asago_scenario_generator.llm.client import LLMResult
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
)
from asago_scenario_generator.models.scenario import (
    NarrativeLayer,
    NarrativeStep,
)
from asago_scenario_generator.pipeline.generate import (
    StageAttemptFailure,
    _call_attack_tree,
    _call_attack_tree_once,
)
from asago_scenario_generator.pipeline.generate.tree_transport import _parse_attack_tree_yaml
from asago_scenario_generator.pipeline.generate.tree_semantics import (
    AttackTreeDraftNode,
    AttackTreeDraftV2,
    AttackTreeDraftV3,
)
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VALID_TREE_YAML = """\
id: tree-AP-T2-05
seed_id: AP-T2-05
goal: Compromise the target system
root:
  id: n1
  label: Root attack node
  gate: LEAF
  zone: input
  action:
    kind: initial_ingress
    entry_point_id: ep:v1:52306ddb893a33ef2dc0f20c01e815f1
"""

_INVALID_YAML = "{{{{not yaml at all: ][]["


def _make_seed(seed_id: str = "AP-T2-05") -> MagicMock:
    seed = MagicMock()
    seed.seed_id = seed_id
    seed.attack_pattern_name = "Test Mechanism"
    seed.attack_pattern_description = "A test mechanism"
    seed.threat_name = "Test Threat"
    seed.threat_description = "A test threat"
    seed.atlas_technique_ids = []
    seed.owasp_llm_ids = []
    seed.agentic_threat_ids = []
    return seed


def _make_narrative() -> NarrativeLayer:
    return NarrativeLayer(
        title="Test narrative",
        summary="A test summary",
        entry_point="user chat interface",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft malicious input",
                effect="Input accepted",
                control_point=None,
                projected_step_ids=("step.1",),
                realizations=make_realizations(
                    ("step.1",),
                    action_kind="prepare",
                    executor_role="attacker",
                    boundary_position="crossing",
                ),
            ),
        ],
    )


def _make_profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            EntryPoint(
                name="user prompts via chat interface",
                direction="input",
                controllability="direct",
            )
        ],
        kc_subcodes=["KC1.1"],
        confidence="medium",
    )


def _make_llm_result(content: str) -> LLMResult:
    return LLMResult(
        content=content,
        prompt_tokens=100,
        completion_tokens=200,
        duration_ms=500,
        system_prompt="system",
        user_prompt="user",
    )


def _projection_context(*step_ids: str) -> dict:
    return {
        "selected_step_ids": list(step_ids),
        "selected_steps": [
            {
                "step_id": step_id,
                "realization": {
                    "projected_step_id": step_id,
                    "action_kind": "prepare",
                    "executor_role": "attacker",
                    "boundary_position": "crossing",
                    "resource_ref_ids": [],
                    "consumed_ref_ids": [],
                    "produced_ref_ids": [f"effect.{index}"],
                    "produced_effect_ids": [f"effect.{index}"],
                    "outcome_link_pc_ids": [],
                    "postcondition_ids": [],
                },
            }
            for index, step_id in enumerate(step_ids, start=1)
        ],
    }


def _transport_tree(step_ids: list[str], realizations: list[dict] | None = None) -> str:
    payload = {
        "id": "tree-AP-T2-05",
        "seed_id": "AP-T2-05",
        "goal": "Compromise the target system",
        "root": {
            "id": "n1",
            "label": "Root attack node",
            "gate": "LEAF",
            "zone": "input",
            "action": {
                "kind": "initial_ingress",
                "entry_point_id": "ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
            },
            "projected_step_ids": step_ids,
        },
    }
    if realizations is not None:
        payload["root"]["realizations"] = realizations
    return yaml.safe_dump(payload, sort_keys=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAttackTreeTransportNormalization:
    def test_omitted_realizations_are_derived_before_strict_validation(self) -> None:
        seed = _make_seed()
        context = _projection_context("step.1", "step.2")

        tree = _parse_attack_tree_yaml(
            _transport_tree(["step.1", "step.2"]),
            seed,
            context,
        )

        assert [item.projected_step_id for item in tree.root.realizations] == [
            "step.1",
            "step.2",
        ]
        assert tree.root.realizations[0].action_kind == "prepare"

    def test_model_realization_semantics_cannot_override_projection(self) -> None:
        seed = _make_seed()
        context = _projection_context("step.1")
        conflicting = [
            {
                **context["selected_steps"][0]["realization"],
                "action_kind": "impact",
                "projected_step_id": "step.1",
            }
        ]

        tree = _parse_attack_tree_yaml(
            _transport_tree(["step.1"], conflicting),
            seed,
            context,
        )

        assert tree.root.realizations[0].action_kind == "prepare"

    def test_unknown_projected_step_is_rejected_before_publication(self) -> None:
        with pytest.raises(ValueError, match="step.unknown"):
            _parse_attack_tree_yaml(
                _transport_tree(["step.unknown"]),
                _make_seed(),
                _projection_context("step.1"),
            )


class TestAttackTreeRetry:
    """Tests for retry logic in _call_attack_tree."""

    def test_success_on_first_attempt_no_retry(self) -> None:
        """When YAML parses successfully on the first try, no retry is made."""
        seed = _make_seed()
        narrative = _make_narrative()
        first_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.return_value = first_result

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=_make_profile(),
            pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
        )

        assert tree.root.id == "n1"
        assert result is first_result
        # Only one call to the LLM
        assert client.complete.call_count == 1

    def test_retry_on_first_failure_returns_retried_result(self) -> None:
        """When first attempt fails but retry succeeds, return retry result."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_INVALID_YAML)
        retry_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=_make_profile(),
            pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
        )

        assert tree.root.id == "n1"
        assert result is retry_result
        assert client.complete.call_count == 2

        # The retry call's user prompt should mention the error
        retry_call_args = client.complete.call_args_list[1]
        retry_user_prompt = retry_call_args.kwargs.get(
            "user_prompt", retry_call_args[1] if len(retry_call_args[1]) > 1 else ""
        )
        assert "rejected" in retry_user_prompt or "not valid YAML" in retry_user_prompt

    def test_call_attack_tree_once_failure_calls_client_once_and_retains_result(
        self,
    ) -> None:
        seed = _make_seed()
        result = _make_llm_result(_INVALID_YAML)
        client = MagicMock()
        client.complete.return_value = result

        with pytest.raises(StageAttemptFailure) as raised:
            _call_attack_tree_once(
                seed=seed,
                narrative=_make_narrative(),
                client=client,
                use_case="A test use case",
                profile=_make_profile(),
                temperature=0.2,
                pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
            )

        client.complete.assert_called_once()
        assert client.complete.call_args.kwargs["temperature"] == 0.2
        failure = raised.value
        assert failure.phase == "post_response"
        assert failure.result is result
        assert failure.raw_response == _INVALID_YAML
        assert (
            failure.system_prompt == client.complete.call_args.kwargs["system_prompt"]
        )
        assert failure.user_prompt == client.complete.call_args.kwargs["user_prompt"]

    def test_both_attempts_fail_raises_original_error(self) -> None:
        """When both attempts fail, the original error is raised."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_INVALID_YAML)
        retry_result = _make_llm_result("also: [broken: yaml: {{")

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        with pytest.raises(Exception) as exc_info:
            _call_attack_tree(
                seed=seed,
                narrative=narrative,
                client=client,
                use_case="A test use case",
                profile=_make_profile(),
                pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
            )

        # Should be the original error, not the retry error
        assert client.complete.call_count == 2
        # The original error is from parsing _INVALID_YAML
        assert "even after colon sanitization" in str(exc_info.value)

    def test_retry_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """A WARNING log is emitted when the first parse fails."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_INVALID_YAML)
        retry_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        import logging

        with caplog.at_level(
            logging.WARNING, logger="asago_scenario_generator.pipeline.generate"
        ):
            _call_attack_tree(
                seed=seed,
                narrative=narrative,
                client=client,
                use_case="A test use case",
                profile=_make_profile(),
                pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
            )

        assert any(
            "Attack tree first attempt failed, retrying" in record.message
            for record in caplog.records
        )


# ---------------------------------------------------------------------------
# Tests: raw generated single-child gate rejection (cmps.9 review 2.3)
# ---------------------------------------------------------------------------

_SINGLE_CHILD_AND_YAML = """\
id: tree-AP-T2-05
seed_id: AP-T2-05
goal: Compromise the target system
root:
  id: n1
  label: Root attack node
  gate: AND
  zone: input
  children:
    - id: n1.1
      label: Only child
      gate: LEAF
      zone: input
      action:
        kind: initial_ingress
        entry_point_id: ep:v1:52306ddb893a33ef2dc0f20c01e815f1
"""

_SINGLE_CHILD_OR_YAML = """\
id: tree-AP-T2-05
seed_id: AP-T2-05
goal: Compromise the target system
root:
  id: n1
  label: Root attack node
  gate: OR
  zone: input
  children:
    - id: n1.1
      label: Only child
      gate: LEAF
      zone: input
      action:
        kind: initial_ingress
        entry_point_id: ep:v1:52306ddb893a33ef2dc0f20c01e815f1
"""


class TestSingleChildGateRejection:
    """Raw generated single-child AND/OR gates must be rejected/retried,
    not silently repaired (cmps.9 second review correction 3).

    _parse_attack_tree_yaml must NOT call repair_attack_tree_dict before
    Pydantic validation.  Malformed gates must fail model validation so
    the caller retries or rejects — no silent structural mutation.
    """

    def test_single_child_and_rejected_and_retried(self) -> None:
        """A single-child AND gate is rejected on first attempt and retried."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_SINGLE_CHILD_AND_YAML)
        retry_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=_make_profile(),
            pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
        )

        # Retry succeeded with the valid tree
        assert tree.root.id == "n1"
        assert result is retry_result
        assert client.complete.call_count == 2

    def test_single_child_or_rejected_and_retried(self) -> None:
        """A single-child OR gate is rejected on first attempt and retried."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_SINGLE_CHILD_OR_YAML)
        retry_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=_make_profile(),
            pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
        )

        # Retry succeeded with the valid tree
        assert tree.root.id == "n1"
        assert result is retry_result
        assert client.complete.call_count == 2

    def test_single_child_and_both_attempts_fail_raises(self) -> None:
        """When both attempts produce single-child gates, the error is raised."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_SINGLE_CHILD_AND_YAML)
        retry_result = _make_llm_result(_SINGLE_CHILD_OR_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        with pytest.raises(Exception, match="single.child|children"):
            _call_attack_tree(
                seed=seed,
                narrative=narrative,
                client=client,
                use_case="A test use case",
                profile=_make_profile(),
                pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
            )

        assert client.complete.call_count == 2

    def test_single_child_gate_not_mutated(self) -> None:
        """The raw dict is not mutated by repair before validation."""
        from asago_scenario_generator.pipeline.generate.tree_transport import (
            _parse_attack_tree_yaml,
        )

        # _parse_attack_tree_yaml should raise on single-child gate
        with pytest.raises(Exception, match="single.child|children"):
            _parse_attack_tree_yaml(
                _SINGLE_CHILD_AND_YAML,
                MagicMock(seed_id="AP-T2-05"),
            )


# ---------------------------------------------------------------------------#
# 422o.4 Review blocker #2: Projection validation participates in retry
# ---------------------------------------------------------------------------#


# ---------------------------------------------------------------------------#
# 422o.4 Review blocker #2: Projection validation participates in retry
# ---------------------------------------------------------------------------#


class TestCall2ProjectionRetry:
    """Call 2 retry must fire on projection validation failures, not only
    YAML parse errors.  The original projection-rich user prompt must
    survive the retry, with feedback appended only.
    """

    @staticmethod
    def _make_projection_context() -> dict:
        from asago_scenario_generator.pipeline.generate.assembly import (
            _build_projection_context,
        )
        from tests.helpers.projection_factory import get_projected_candidate

        candidate = get_projected_candidate()
        return _build_projection_context(candidate)

    @staticmethod
    def _get_ingress_id() -> str:
        from tests.helpers.projection_factory import get_projected_candidate

        return get_projected_candidate().canonical_ingress.entry_point_id

    @staticmethod
    def _make_profile():
        from tests.helpers.projection_factory import get_test_profile

        return get_test_profile()

    @staticmethod
    def _make_valid_tree_yaml(ctx: dict) -> str:
        """Build a YAML tree that passes both parse and projection validation."""
        import yaml as _yaml

        from asago_scenario_generator.models.attack_tree import (
            AiSystemAction,
            AttackTree,
            AttackTreeNode,
            GateType,
            ImpactAction,
            InitialIngressAction,
        )
        from tests.helpers.projection_factory import (
            get_projected_candidate,
            make_step_realizations,
        )

        candidate = get_projected_candidate()
        ingress_id = candidate.canonical_ingress.entry_point_id
        selected = candidate.projection.selected_step_ids

        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="Ingress",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                        projected_step_ids=(selected[0],),
                        realizations=make_step_realizations((selected[0],)),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="Observe",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=AiSystemAction(),
                        projected_step_ids=(selected[1],),
                        realizations=make_step_realizations((selected[1],)),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="Impact",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="integrity"),
                        projected_step_ids=(selected[2],),
                        realizations=make_step_realizations((selected[2],)),
                    ),
                ],
            ),
        )
        data = tree.model_dump(mode="json")
        return _yaml.dump(data, default_flow_style=False, sort_keys=False)

    def _make_projectionless_tree_yaml(self) -> str:
        """A valid YAML tree with a security leaf missing projected_step_ids."""
        ingress_id = self._get_ingress_id()
        return (
            "id: tree-AP-T1-01\n"
            "seed_id: AP-T1-01\n"
            "goal: test\n"
            "root:\n"
            "  id: n1\n"
            "  label: Root\n"
            "  gate: AND\n"
            "  children:\n"
            "    - id: n1.1\n"
            "      label: Ingress\n"
            "      gate: LEAF\n"
            "      zone: input\n"
            "      action:\n"
            f"        kind: initial_ingress\n"
            f"        entry_point_id: {ingress_id}\n"
            "    - id: n1.2\n"
            "      label: No projection\n"
            "      gate: LEAF\n"
            "      zone: reasoning\n"
            "      action:\n"
            "        kind: ai_system_action\n"
        )

    def test_projection_invalid_first_response_triggers_retry(self) -> None:
        """A syntactically valid but projection-invalid first response
        triggers the retry, and the retry with valid output succeeds."""
        ctx = self._make_projection_context()
        valid_yaml = self._make_valid_tree_yaml(ctx)
        projectionless_yaml = self._make_projectionless_tree_yaml()
        ingress_id = self._get_ingress_id()

        seed = _make_seed("AP-T1-01")
        narrative = _make_narrative()

        first_result = _make_llm_result(projectionless_yaml)
        retry_result = _make_llm_result(valid_yaml)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=self._make_profile(),
            pinned_entry_point_id=ingress_id,
            projection_context=ctx,
        )

        # Retry was used
        assert client.complete.call_count == 2
        assert result is retry_result
        # Tree from retry output
        assert tree.root.id == "n1"

    def test_retry_preserves_full_projection_context(self) -> None:
        """The retry user prompt must contain the original projection
        selected step IDs, bindings/resource refs, conditions/evidence,
        and original context — not just parse feedback."""
        ctx = self._make_projection_context()
        valid_yaml = self._make_valid_tree_yaml(ctx)
        projectionless_yaml = self._make_projectionless_tree_yaml()
        ingress_id = self._get_ingress_id()

        seed = _make_seed("AP-T1-01")
        narrative = _make_narrative()

        first_result = _make_llm_result(projectionless_yaml)
        retry_result = _make_llm_result(valid_yaml)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=self._make_profile(),
            pinned_entry_point_id=ingress_id,
            projection_context=ctx,
        )

        assert client.complete.call_count == 2
        retry_call = client.complete.call_args_list[1]
        retry_prompt = retry_call.kwargs.get("user_prompt", "")

        # Original projection context survives in the retry prompt
        # (projection_digest removed in Phase 2 — check step IDs instead)
        assert "step.1" in retry_prompt
        # Resource links present (bindings removed in Phase 4 — check
        # that resource_links roles appear in the rendered prompt)
        assert "role:" in retry_prompt or "resource:" in retry_prompt, (
            "Retry prompt should contain resource link info"
        )
        # Feedback appended (not replacing original prompt)
        assert "Feedback" in retry_prompt

    def test_both_projection_invalid_raises(self) -> None:
        """When both outputs are projection-invalid, the first error is raised."""
        ctx = self._make_projection_context()
        projectionless_yaml = self._make_projectionless_tree_yaml()
        ingress_id = self._get_ingress_id()

        seed = _make_seed("AP-T1-01")
        narrative = _make_narrative()

        first_result = _make_llm_result(projectionless_yaml)
        retry_result = _make_llm_result(projectionless_yaml)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        with pytest.raises(Exception) as exc_info:
            _call_attack_tree(
                seed=seed,
                narrative=narrative,
                client=client,
                use_case="A test use case",
                profile=self._make_profile(),
                pinned_entry_point_id=ingress_id,
                projection_context=ctx,
            )

        assert client.complete.call_count == 2
        # Should be the original projection validation error
        assert "no projected_step_ids" in str(exc_info.value)


# ---------------------------------------------------------------------------#
# 422o.4 review blocker #2: external_precondition retry test
# ---------------------------------------------------------------------------#


class TestCall2ExternalPreconditionRetry:
    """External precondition with nonempty realizations must trigger retry."""

    @staticmethod
    def _make_projection_context() -> dict:
        from asago_scenario_generator.pipeline.generate.assembly import (
            _build_projection_context,
        )
        from tests.helpers.projection_factory import get_projected_candidate

        candidate = get_projected_candidate()
        return _build_projection_context(candidate)

    @staticmethod
    def _get_ingress_id() -> str:
        from tests.helpers.projection_factory import get_projected_candidate

        return get_projected_candidate().canonical_ingress.entry_point_id

    @staticmethod
    def _make_profile():
        from tests.helpers.projection_factory import get_test_profile

        return get_test_profile()

    @staticmethod
    def _make_valid_tree_yaml(ctx: dict) -> str:
        """Build a YAML tree that passes both parse and projection validation."""
        import yaml as _yaml

        from asago_scenario_generator.models.attack_tree import (
            AiSystemAction,
            AttackTree,
            AttackTreeNode,
            GateType,
            ImpactAction,
            InitialIngressAction,
        )
        from tests.helpers.projection_factory import (
            get_projected_candidate,
            make_step_realizations,
        )

        candidate = get_projected_candidate()
        ingress_id = candidate.canonical_ingress.entry_point_id
        selected = candidate.projection.selected_step_ids

        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="Ingress",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                        projected_step_ids=(selected[0],),
                        realizations=make_step_realizations((selected[0],)),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="Observe",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=AiSystemAction(),
                        projected_step_ids=(selected[1],),
                        realizations=make_step_realizations((selected[1],)),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="Impact",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="integrity"),
                        projected_step_ids=(selected[2],),
                        realizations=make_step_realizations((selected[2],)),
                    ),
                ],
            ),
        )
        data = tree.model_dump(mode="json")
        return _yaml.dump(data, default_flow_style=False, sort_keys=False)

    def _make_external_precondition_with_realizations_yaml(self) -> str:
        """A YAML tree with an external_precondition leaf that has nonempty
        realizations — must be rejected by the model validator."""
        ingress_id = self._get_ingress_id()
        return (
            "id: tree-AP-T1-01\n"
            "seed_id: AP-T1-01\n"
            "goal: test\n"
            "root:\n"
            "  id: n1\n"
            "  label: Root\n"
            "  gate: AND\n"
            "  children:\n"
            "    - id: n1.1\n"
            "      label: Ingress\n"
            "      gate: LEAF\n"
            "      zone: input\n"
            "      action:\n"
            "        kind: initial_ingress\n"
            f"        entry_point_id: {ingress_id}\n"
            "      projected_step_ids:\n"
            "        - step.1\n"
            "      realizations:\n"
            "        - projected_step_id: step.1\n"
            "          action_kind: deliver\n"
            "          executor_role: attacker\n"
            "          boundary_position: crossing\n"
            "          resource_ref_ids: []\n"
            "          consumed_ref_ids: []\n"
            "          produced_ref_ids: []\n"
            "          produced_effect_ids: []\n"
            "          outcome_link_pc_ids: []\n"
            "          postcondition_ids: []\n"
            "    - id: n1.2\n"
            "      label: System\n"
            "      gate: LEAF\n"
            "      zone: reasoning\n"
            "      action:\n"
            "        kind: ai_system_action\n"
            "      projected_step_ids:\n"
            "        - step.2\n"
            "      realizations:\n"
            "        - projected_step_id: step.2\n"
            "          action_kind: transform\n"
            "          executor_role: system\n"
            "          boundary_position: inside\n"
            "          resource_ref_ids: []\n"
            "          consumed_ref_ids: []\n"
            "          produced_ref_ids: []\n"
            "          produced_effect_ids: []\n"
            "          outcome_link_pc_ids: []\n"
            "          postcondition_ids: []\n"
            "    - id: n1.3\n"
            "      label: External\n"
            "      gate: LEAF\n"
            "      action:\n"
            "        kind: external_precondition\n"
            "        access_provenance: phishing\n"
            "      projected_step_ids: []\n"
            "      realizations:\n"
            "        - projected_step_id: step.1\n"
            "          action_kind: prepare\n"
            "          executor_role: attacker\n"
            "          boundary_position: outside\n"
            "          resource_ref_ids: []\n"
            "          consumed_ref_ids: []\n"
            "          produced_ref_ids: []\n"
            "          produced_effect_ids: []\n"
            "          outcome_link_pc_ids: []\n"
            "          postcondition_ids: []\n"
        )

    def test_external_precondition_with_realizations_triggers_retry(self) -> None:
        """First attempt with external_precondition + nonempty realizations
        triggers retry; retry with valid tree succeeds."""
        ctx = self._make_projection_context()
        valid_yaml = self._make_valid_tree_yaml(ctx)
        bad_yaml = self._make_external_precondition_with_realizations_yaml()
        ingress_id = self._get_ingress_id()

        seed = _make_seed("AP-T1-01")
        narrative = _make_narrative()

        first_result = _make_llm_result(bad_yaml)
        retry_result = _make_llm_result(valid_yaml)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=self._make_profile(),
            pinned_entry_point_id=ingress_id,
            projection_context=ctx,
        )

        # Retry was used
        assert client.complete.call_count == 2
        assert result is retry_result
        assert tree.root.id == "n1"


def test_projected_provider_path_requests_and_compiles_topology_draft() -> None:
    profile = _make_profile()
    ingress_id = profile.entry_points[0].entry_point_id
    projection_context = {
        "selected_step_ids": ["step.1"],
        "canonical_ingress": {
            "kind": "entry_point",
            "entry_point_id": ingress_id,
        },
        "selected_steps": [
            {
                "step_id": "step.1",
                "order": 1,
                "action_kind": "deliver",
                "executor_role": "attacker",
                "boundary_position": "crossing",
                "resource_links": [
                    {
                        "role": "ingress",
                        "resource_ref": {
                            "kind": "entry_point",
                            "entry_point_id": ingress_id,
                        },
                    }
                ],
                "observable_postconditions": [],
                "realization": make_realizations(
                    ("step.1",), action_kind="deliver"
                )[0].model_dump(mode="json"),
                "technique_ids": [],
            }
        ],
    }
    result = LLMResult(
        content=AttackTreeDraftV2(
            root=AttackTreeDraftNode(kind="leaf", leaf_handle="l0")
        ),
        prompt_tokens=20,
        completion_tokens=10,
        duration_ms=5,
        system_prompt="",
        user_prompt="",
    )
    client = MagicMock()
    client.complete.return_value = result
    seed = _make_seed()
    seed.threat_id = "T2"

    tree, returned = _call_attack_tree_once(
        seed=seed,
        narrative=_make_narrative(),
        client=client,
        use_case="Test",
        profile=profile,
        pinned_entry_point_id=ingress_id,
        projection_context=projection_context,
    )

    assert returned is result
    response_model = client.complete.call_args.kwargs["response_format"]
    assert issubclass(response_model, AttackTreeDraftV3)
    group_schema = response_model.model_json_schema()["$defs"][
        "AttackTreeDraftGroupV3"
    ]
    assert group_schema["properties"]["leaf_handles"]["items"]["enum"] == ["l0"]
    assert tree.root.projected_step_ids == ("step.1",)
    assert tree.root.action.kind == "initial_ingress"

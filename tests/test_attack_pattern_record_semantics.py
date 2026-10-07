"""Record-specific semantics of the canonical attack-pattern catalogs.

Each test pins one reviewed decision about one record (a corrected terminal,
a withdrawn exact mapping, a downgraded provenance tier). Catalog-wide shape,
mapping, causal and provenance invariants live in
``test_attack_pattern_catalog_invariants.py``, driven by
``tests/fixtures/attack_pattern_expectations/``.
"""

from __future__ import annotations

from copy import deepcopy

import pytest
import yaml
from pydantic import TypeAdapter

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    Condition,
    EvaluatedFactEvidence,
    ExactMapping,
    compute_chain_semantic_digest,
    evaluate_condition,
    validate_attack_pattern,
)


@pytest.fixture(scope="module")
def raw() -> dict[str, dict]:
    """Raw records of the merged catalog, keyed by pattern id."""
    return load_attack_patterns()


@pytest.fixture(scope="module")
def qualified(raw) -> dict[str, AttackPattern]:
    resolver = load_taxonomy_resolver()
    return {pid: validate_attack_pattern(rec, resolver) for pid, rec in raw.items()}


def _step_exact(pattern: AttackPattern) -> dict[str, str]:
    out = {}
    for step in pattern.canonical_chain.steps:
        for mapping in step.mappings:
            if mapping.decision == "exact":
                assert len(mapping.ids) == 1
                out[step.step_id] = mapping.ids[0]
    return out


def test_t907_single_data_destruction_mechanism(qualified) -> None:
    pattern = qualified["AP-T9-07"]
    chain = pattern.canonical_chain
    assert [s.step_id for s in chain.steps] == [
        "authenticate_as_agent",
        "destroy_agent_data",
    ]
    # The request-flood branch is fully removed: AML.T0029 appears in no
    # mapping decision (its remaining mentions are explanatory provenance
    # for the S11 definition-level retag, not mapping authority).
    all_mapping_ids = {
        technique_id
        for scope in (chain.mappings, *(s.mappings for s in chain.steps))
        for mapping in scope
        if mapping.decision == "exact"
        for technique_id in mapping.ids
    }
    assert "AML.T0029" not in all_mapping_ids
    destroy = chain.steps[-1]
    assert destroy.attacker_controlled
    assert destroy.observable_postconditions[0].terminal


def test_t1603_pure_deceptive_metadata_mechanism(qualified) -> None:
    pattern = qualified["AP-T16-03"]
    chain = pattern.canonical_chain
    assert [s.step_id for s in chain.steps] == [
        "craft_deceptive_descriptions",
        "alter_registry_metadata",
        "select_tool_under_false_scope",
        "invoke_tool_under_false_scope",
        "false_scope_impact",
    ]
    # No hidden-code supply-chain identities remain in any mapping decision
    # (remaining textual mentions are explicit non-claims in provenance
    # rationales, not mapping authority).
    all_mapping_ids = {
        technique_id
        for scope in (chain.mappings, *(s.mappings for s in chain.steps))
        for mapping in scope
        if mapping.decision == "exact"
        for technique_id in mapping.ids
    }
    for forbidden in ("AML.T0104", "AML.T0111", "AML.T0011.002"):
        assert forbidden not in all_mapping_ids
    for step in chain.steps:
        for marker in ("poisoned_tool", "install", "injection", "reputation"):
            assert marker not in step.step_id
    # The victim-side selection/invocation is honestly system-roled.
    for step_id in ("select_tool_under_false_scope", "invoke_tool_under_false_scope"):
        step = next(s for s in chain.steps if s.step_id == step_id)
        assert step.executor_role == "system"
        assert not step.attacker_controlled
        assert all(m.decision == "not_applicable" for m in step.mappings)
    # The alteration step carries the defensible exact identity.
    alter = chain.steps[1]
    assert alter.attacker_controlled
    assert [m.ids for m in alter.mappings if m.decision == "exact"] == [("AML.T0110",)]


def test_t1001_craft_obfuscate_before_delivery_no_conditional_persistence(
    qualified,
) -> None:
    chain = qualified["AP-T10-01"].canonical_chain
    ids = [s.step_id for s in chain.steps]
    assert "persist_in_content_store" not in ids
    assert all(s.condition is None for s in chain.steps)
    assert (
        ids.index("craft_misleading_context")
        < ids.index("obfuscate_malicious_content")
        < ids.index("deliver_crafted_content")
        < ids.index("activate_injection")
    )
    by_id = {s.step_id: s for s in chain.steps}
    assert [r.ref_id for r in by_id["obfuscate_malicious_content"].consumed] == [
        "payload.misleading_context"
    ]
    assert [r.ref_id for r in by_id["deliver_crafted_content"].consumed] == [
        "payload.obfuscated_context"
    ]
    # The conditional S13 payoff is downgraded from observed.
    terminal = chain.steps[-1]
    assert terminal.step_id == "approve_malicious_actions"
    assert terminal.provenance.tier == "variant"


def test_t905_sensitive_action_precedes_attribution_terminal(qualified) -> None:
    chain = qualified["AP-T9-05"].canonical_chain
    by_id = {s.step_id: s for s in chain.steps}
    action = by_id["perform_sensitive_action"]
    terminal = by_id["false_attribution_recorded"]
    assert action.order == terminal.order - 1
    assert action.attacker_controlled
    assert [r.ref_id for r in action.consumed] == ["auth.identity_granted"]
    assert [r.ref_id for r in action.produced] == ["action.sensitive_action_record"]
    assert [r.ref_id for r in terminal.consumed] == ["action.sensitive_action_record"]


def test_t906_future_session_activation_precedes_sustained_terminal(qualified) -> None:
    chain = qualified["AP-T9-06"].canonical_chain
    by_id = {s.step_id: s for s in chain.steps}
    activation = by_id["operate_in_future_session"]
    terminal = by_id["sustained_takeover_observed"]
    assert activation.order == terminal.order - 1
    assert activation.attacker_controlled
    assert [r.ref_id for r in terminal.consumed] == [
        "ops.future_session_operations",
        "activity.concealed",
    ]
    # Unsupported long-lived-token claims are downgraded from observed.
    extract = by_id["extract_long_lived_tokens"]
    post = extract.observable_postconditions[0].description
    assert "long-lived" not in post and "surviving" not in post
    assert [r.ref_id for r in extract.produced] == ["credential.stolen_token"]
    assert by_id["establish_persistent_access"].provenance.tier == "variant"


def test_t906_observed_steps_do_not_claim_token_lifetime(qualified) -> None:
    """Observed S00-S01 establish host/process access, not token lifetime."""
    chain = qualified["AP-T9-06"].canonical_chain
    by_id = {s.step_id: s for s in chain.steps}
    initial = by_id["initial_access"]
    assert initial.provenance.tier == "observed"
    initial_post = initial.observable_postconditions[0].description
    assert "long-lived" not in initial_post
    assert "agent credentials" in initial_post
    enum = by_id["enumerate_credential_stores"]
    assert enum.provenance.tier == "observed"
    enum_post = enum.observable_postconditions[0].description
    assert "long-lived" not in enum_post
    assert "authentication-token sources" in enum_post


def test_t906_cross_session_concealment_is_variant(qualified) -> None:
    """Cross-session concealment is inferred, not observed: honestly variant."""
    chain = qualified["AP-T9-06"].canonical_chain
    step = {s.step_id: s for s in chain.steps}["conceal_cross_session_activity"]
    assert step.provenance.tier == "variant"
    assert step.provenance.confidence is not None
    assert step.provenance.confidence < 90
    assert any(r.reference_id == "AML.CS0036" for r in step.provenance.references)
    rationale = step.provenance.adaptation_rationale
    assert "inferred" in rationale
    assert "across sessions" in rationale
    assert "S08" in rationale


def test_t801_start_is_credential_acquisition_only(qualified) -> None:
    chain = qualified["AP-T8-01"].canonical_chain
    start = chain.steps[0]
    assert start.step_id == "obtain_record_access"
    assert [m.ids for m in start.mappings if m.decision == "exact"] == [("AML.T0055",)]
    text = (
        start.observable_postconditions[0].description
        + start.provenance.adaptation_rationale
    )
    assert "interface access" not in text
    assert "credential" in text or "tokens" in text


def test_t1602_crafted_response_only_no_interception(qualified) -> None:
    pattern = qualified["AP-T16-02"]
    assert "crafts a server-side response" in pattern.description
    assert "or intercept" not in pattern.description
    assert "intercepts" not in pattern.description


def test_split_boundary_is_clean(qualified) -> None:
    t902 = qualified["AP-T9-02"].canonical_chain
    t907 = qualified["AP-T9-07"].canonical_chain
    assert t902.steps[-1].step_id == "impersonated_operation_attributed"
    # AP-T9-02 owns immediate stolen-credential impersonation (theft and
    # thread-poisoning identities); AP-T9-07 owns the independent
    # data-destruction disruption and carries neither theft identity.
    assert _step_exact(qualified["AP-T9-02"]) == {
        "extract_tokens": "AML.T0090",
        "poison_session_context": "AML.T0080.001",
    }
    t907_exact = {
        technique_id
        for scope in (t907.mappings, *(s.mappings for s in t907.steps))
        for mapping in scope
        if mapping.decision == "exact"
        for technique_id in mapping.ids
    }
    assert t907_exact == {"AML.T0101", "AML.T0091.000"}
    assert "AML.T0101" not in {
        technique_id
        for scope in (t902.mappings, *(s.mappings for s in t902.steps))
        for mapping in scope
        if mapping.decision == "exact"
        for technique_id in mapping.ids
    }


def test_t901_execution_precedes_attribution(qualified) -> None:
    chain = qualified["AP-T9-01"].canonical_chain
    ids = [s.step_id for s in chain.steps]
    assert ids.index("execute_delegated_actions") < ids.index(
        "attribution_recorded_for_user"
    )
    terminal = chain.steps[-1]
    assert [r.ref_id for r in terminal.consumed] == ["action.execution_record"]


def test_condition_evaluation_true_and_false_semantics() -> None:
    # The typed-condition contract: a profile-fact equality gate (the shape
    # the removed AP-T10-01 persistence condition used) evaluates to true on
    # matching evidence and false on contradicting/absent evidence.
    fact_raw = {
        "namespace": "profile",
        "fact_id": "has_persistent_memory",
        "value_type": "boolean",
        "property_path": [],
    }
    condition = TypeAdapter(Condition).validate_python(
        {"op": "equality", "schema_version": "1", "fact": fact_raw, "value": True}
    )

    def evidence(status: str, value=None) -> EvaluatedFactEvidence:
        return EvaluatedFactEvidence.model_validate(
            {"fact": fact_raw, "status": status, "value": value}
        )

    assert evaluate_condition(condition, (evidence("present", True),)) == "true"
    assert evaluate_condition(condition, (evidence("present", False),)) == "false"
    assert evaluate_condition(condition, (evidence("absent"),)) == "false"
    assert evaluate_condition(condition, (evidence("unknown"),)) == "unknown"
    negated = TypeAdapter(Condition).validate_python(
        {
            "op": "not",
            "schema_version": "1",
            "operand": condition.model_dump(mode="json"),
        }
    )
    assert evaluate_condition(negated, (evidence("present", True),)) == "false"
    assert evaluate_condition(negated, (evidence("present", False),)) == "true"


def _steps(pattern: AttackPattern):
    return {step.step_id: step for step in pattern.canonical_chain.steps}


def _ordered_refs(pattern: AttackPattern) -> list[list[str]]:
    return [
        [r.reference_id for r in step.provenance.references]
        for step in pattern.canonical_chain.steps
    ]


class TestAPTT1502Directionality:
    """independent correction 1: no duplicate escalation; the user action consumes
    the deceptive output directly; CS0020 S02 -> S03 -> S04 is asserted; no
    CS0055 evidence occurs after preparation."""

    def test_escalation_step_removed_and_user_consumes_deceptive_output(
        self, qualified
    ):
        steps = _steps(qualified["AP-T15-02"])
        assert "escalate_to_active_instruction" not in steps
        assert [s.step_id for s in qualified["AP-T15-02"].canonical_chain.steps] == [
            "craft_hijack_injection",
            "stage_social_engineering_payload",
            "ingest_malicious_content",
            "generate_deceptive_messages",
            "user_executes_malicious_action",
        ]
        user_action = steps["user_executes_malicious_action"]
        assert [(r.kind, r.ref_id) for r in user_action.consumed] == [
            ("state", "state.deceptive_output")
        ]
        producer = steps["generate_deceptive_messages"]
        assert (producer.produced[0].kind, producer.produced[0].ref_id) == (
            "state",
            "state.deceptive_output",
        )

    def test_cs0020_s02_s03_s04_causal_sequence(self, qualified):
        refs = _ordered_refs(qualified["AP-T15-02"])
        positions = {}
        for order, step_refs in enumerate(refs, start=1):
            for ref in step_refs:
                positions.setdefault(ref, order)
        s02 = positions["AML.CS0020 S02"]
        s03 = positions["AML.CS0020 S03"]
        s04 = positions["AML.CS0020 S04"]
        assert s02 < s03 < s04
        steps = qualified["AP-T15-02"].canonical_chain.steps
        assert steps[s03 - 1].step_id == "generate_deceptive_messages"
        assert steps[s04 - 1].step_id == "user_executes_malicious_action"
        assert steps[s04 - 1].executor_role == "operator"

    def test_no_cs0055_evidence_after_preparation(self, qualified):
        for step in qualified["AP-T15-02"].canonical_chain.steps:
            refs = [r.reference_id for r in step.provenance.references]
            if step.action_kind == "prepare":
                continue  # CS0055 may remain only as adapted preparation precedent
            assert not any(ref.startswith("AML.CS0055") for ref in refs), (
                step.step_id,
                refs,
            )


class TestAPTT1203Corrections:
    """independent correction 2: false exact AML.T0051.002 removed from the
    false-data retrieval step (lineage amendment required and documented);
    AML.T0070 chain identity retained; propagation is the first peer
    re-emission and the terminal is the first multi-peer cascade."""

    def test_no_exact_t0051_002_anywhere(self, qualified):
        pattern = qualified["AP-T12-03"]
        chain_exact = [
            identifier
            for mapping in pattern.canonical_chain.mappings
            if isinstance(mapping, ExactMapping)
            for identifier in mapping.ids
        ]
        assert chain_exact == ["AML.T0070"]
        for step in pattern.canonical_chain.steps:
            for mapping in step.mappings:
                if isinstance(mapping, ExactMapping):
                    assert "AML.T0051.002" not in mapping.ids, step.step_id

    def test_first_reemission_then_first_multi_peer_cascade(self, qualified):
        steps = _steps(qualified["AP-T12-03"])
        propagation = steps["cascade_propagation"]
        assert [(r.kind, r.ref_id) for r in propagation.produced] == [
            ("state", "state.first_peer_reemission")
        ]
        propagation_text = " ".join(
            o.description for o in propagation.observable_postconditions
        )
        assert "first re-emission" in propagation_text
        assert not any(o.terminal for o in propagation.observable_postconditions)
        terminal = steps["misinformation_impact"]
        assert [(r.kind, r.ref_id) for r in terminal.consumed] == [
            ("state", "state.first_peer_reemission")
        ]
        terminal_text = " ".join(
            o.description for o in terminal.observable_postconditions
        )
        assert "first observable multi-peer cascade" in terminal_text
        assert any(o.terminal for o in terminal.observable_postconditions)
        assert (
            terminal.step_id == qualified["AP-T12-03"].canonical_chain.steps[-1].step_id
        )


class TestAPTT1701CausalArtifactPath:
    """independent correction 3: jailbreak produces the enabled malicious-generation
    state, concealment preserves it, and the terminal system step is the first
    emission of the backdoored artifact — with no adopter-use claim."""

    def test_enabled_state_produced_preserved_and_consumed(self, qualified):
        steps = _steps(qualified["AP-T17-01"])
        jailbreak = steps["jailbreak_guardrails"]
        assert [(r.kind, r.ref_id) for r in jailbreak.produced] == [
            ("state", "state.malicious_generation_enabled")
        ]
        conceal = steps["suppress_output_mentions"]
        assert [(r.kind, r.ref_id) for r in conceal.consumed] == [
            ("state", "state.malicious_generation_enabled")
        ]
        assert [(r.kind, r.ref_id) for r in conceal.produced] == [
            ("state", "state.concealed_malicious_generation")
        ]
        conceal_text = " ".join(
            o.description for o in conceal.observable_postconditions
        )
        assert "preserves the enabled malicious-generation state" in conceal_text
        terminal = steps["impact_backdoored_code"]
        assert [(r.kind, r.ref_id) for r in terminal.consumed] == [
            ("state", "state.concealed_malicious_generation")
        ]

    def test_terminal_is_first_backdoored_artifact_emission(self, qualified):
        chain = qualified["AP-T17-01"].canonical_chain
        terminal = chain.steps[-1]
        assert terminal.step_id == "impact_backdoored_code"
        assert terminal.executor_role == "system"
        assert [(r.kind, r.ref_id) for r in terminal.produced] == [
            ("effect", "effect.backdoored_artifacts")
        ]
        # No earlier step emits a backdoored artifact or effect.
        for step in chain.steps[:-1]:
            for ref in step.produced:
                assert "backdoor" not in ref.ref_id, (step.step_id, ref.ref_id)
                assert ref.kind != "effect", (step.step_id, ref.ref_id)
        # The adopter pipeline remains an explicit operator action/artifact
        # path, but the record claims no adopter use of generated artifacts.
        persist = _steps(qualified["AP-T17-01"])["persist_via_adoption"]
        assert persist.executor_role == "operator"
        assert persist.action_kind == "persist"
        dumped = yaml.safe_dump(
            qualified["AP-T17-01"].model_dump(mode="json"), sort_keys=True
        )
        assert "Adopters use" not in dumped
        terminal_text = " ".join(
            o.description for o in terminal.observable_postconditions
        )
        assert "first observable supply-chain impact" in terminal_text
        assert "not claimed" in terminal_text


class TestAPTT1501TerminalProvenance:
    """independent correction 4: CS0026 S13 is conditional ('If'/'could'), not an
    observed completed transfer; the terminal stays but with non-observed
    tier, lowered confidence, and explicit conditional evidence."""

    def test_terminal_tier_confidence_and_conditional_evidence(self, qualified):
        terminal = qualified["AP-T15-01"].canonical_chain.steps[-1]
        assert terminal.step_id == "impact"
        assert any(o.terminal for o in terminal.observable_postconditions)
        provenance = terminal.provenance
        assert provenance.tier in {"inferred", "variant"}
        assert provenance.tier != "observed"
        assert provenance.confidence <= 60
        assert any(r.reference_id == "AML.CS0026 S13" for r in provenance.references)
        rationale = provenance.adaptation_rationale
        assert "conditionally" in rationale
        assert "If the victim follows through" in rationale
        assert "could be" in rationale
        assert "not an observed event" in rationale


def _step_by_id(chain, step_id: str):
    (step,) = [s for s in chain.steps if s.step_id == step_id]
    return step


@pytest.mark.parametrize(
    "pid,step_id",
    [
        ("AP-T17-03", "develop_poisoned_tool"),
        ("AP-T17-03", "publish_poisoned_tool"),
    ],
)
def test_recomposed_timing_steps_rationalize_variant(qualified, pid, step_id):
    """Variant-tiered timing steps must state the observed-vs-recomposed
    split explicitly: CS0053 published legitimate versions first."""
    step = _step_by_id(qualified[pid].canonical_chain, step_id)
    rationale = step.provenance.adaptation_rationale
    assert "legitimate" in rationale
    assert "recomposition" in rationale
    assert "AP-T17-04" in rationale


def test_t3_06_privileged_step_is_invocation_only_impact_owns_execution(qualified):
    """Successful root execution lives only at the terminal impact."""
    chain = qualified["AP-T3-06"].canonical_chain
    invocation = _step_by_id(chain, "privileged_tool_invocation")
    (post,) = invocation.observable_postconditions
    assert "initiates" in post.description
    assert "executes attacker-directed commands as root" not in post.description
    assert not post.terminal
    impact = _step_by_id(chain, "impact")
    (terminal,) = impact.observable_postconditions
    assert terminal.terminal and terminal.security_relevant
    assert "executes attacker-directed commands as root" in terminal.description


def test_t6_07_t0080_001_stays_within_thread_semantics(qualified):
    """AML.T0080.001 is remainder-of-a-thread persistence; the claim that
    every new thread is poisoned must be attributed to AML.T0081."""
    chain = qualified["AP-T6-07"].canonical_chain
    step = _step_by_id(chain, "thread_context_persistence")
    (post,) = step.observable_postconditions
    assert "remainder of that thread" in post.description
    assert "spans all future interactions" not in post.description
    rationale = step.provenance.adaptation_rationale
    assert "pinned technique definition AML.T0080.001" in rationale
    assert "AML.T0081" in rationale


def test_review_mandated_narrowing_rationales(raw) -> None:
    """The exact-identity narrowing and lineage deltas are documented in the
    affected steps' rationales (fail closed, not silent qualification)."""

    def step_of(pid, step_id):
        return next(
            s for s in raw[pid]["canonical_chain"]["steps"] if s["step_id"] == step_id
        )

    t006 = step_of("AP-T2-06", "invoke_tool")
    assert "interpreter" in t006["provenance"]["adaptation_rationale"].lower()
    assert "reported as a delta" in t006["provenance"]["adaptation_rationale"]

    # Final re-review: AP-T2-06 boundary narrowed to the interpreter tool and
    # the withdrawn AML.T0080.000 (AP-T1-04) / AML.T0012 (AP-T3-02) exact
    # mappings are absent from the records.
    t206_record = raw["AP-T2-06"]
    assert "command/scripting interpreter tool" in t206_record["description"]
    assert "API client" not in t206_record["description"]
    assert "API-client mode is out of scope" in t206_record["description"]

    t104_record = raw["AP-T1-04"]
    assert "RAG-indexed retrieval store" in t104_record["description"]
    t104_exact_ids = {
        atlas_id
        for scope in (
            t104_record["canonical_chain"]["mappings"],
            *(s["mappings"] for s in t104_record["canonical_chain"]["steps"]),
        )
        for decision in scope
        if decision["decision"] == "exact"
        for atlas_id in decision["ids"]
    }
    assert "AML.T0080.000" not in t104_exact_ids
    assert t104_exact_ids == {"AML.T0070", "AML.T0051.001"}
    t104_steps = [s["step_id"] for s in t104_record["canonical_chain"]["steps"]]
    assert "propagate_corruption" not in t104_steps
    # The terminal consumes store.corrupted directly.
    assert any(
        r["ref_id"] == "store.corrupted"
        for r in t104_record["canonical_chain"]["steps"][-1]["consumed"]
    )

    t302_record = raw["AP-T3-02"]
    t302_exact_ids = {
        atlas_id
        for scope in (
            t302_record["canonical_chain"]["mappings"],
            *(s["mappings"] for s in t302_record["canonical_chain"]["steps"]),
        )
        for decision in scope
        if decision["decision"] == "exact"
        for atlas_id in decision["ids"]
    }
    assert "AML.T0012" not in t302_exact_ids
    assert t302_exact_ids == {"AML.T0053"}
    escalate = step_of("AP-T3-02", "escalate_privileges")
    assert "confused-deputy" in escalate["provenance"]["adaptation_rationale"]

    t302 = step_of("AP-T3-02", "deliver_request")
    (decision,) = t302["mappings"]
    assert decision["decision"] == "unmapped"
    assert "indirect" in decision["rationale"]
    assert "AML.T0051.000" in decision["rationale"]


def _walk_strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, str):
        yield value


def _chain_exact_ids(chain: dict) -> set[str]:
    return {
        identifier
        for mapping in chain["mappings"]
        if mapping["decision"] == "exact"
        for identifier in mapping["ids"]
    }


def _step_exact_ids(chain: dict) -> set[tuple[str, str]]:
    """Flatten every id of every exact mapping as (step_id, id) pairs.

    Never inspect only ``ids[0]`` and never key by step alone (which would
    silently overwrite a step carrying multiple exact ids).
    """
    return {
        (step["step_id"], identifier)
        for step in chain["steps"]
        for mapping in step["mappings"]
        if mapping["decision"] == "exact"
        for identifier in mapping["ids"]
    }


def _terminal_postconditions(step: dict) -> list[dict]:
    return [
        out
        for out in step["observable_postconditions"]
        if out["security_relevant"] and out["terminal"]
    ]


def test_t5_01_owns_factual_misinformation_not_operational_rules(
    raw: dict,
) -> None:
    """OG-01 boundary: AP-T5-01 keeps recursive factual-misinformation
    compounding; injected operational-rule override belongs to AP-T1-01."""
    description = raw["AP-T5-01"]["description"].lower()
    assert "compound" in description
    assert "false factual information" in description
    assert "operational-rule override belongs to ap-t1-01" in description


def test_t5_01_structurally_realizes_recursive_compounding(raw: dict) -> None:
    """The recursion is unrolled: persist -> reuse -> feedback write-back ->
    compounded terminal, never prose-only one-shot poisoning."""
    steps = raw["AP-T5-01"]["canonical_chain"]["steps"]
    by_id = {step["step_id"]: step for step in steps}

    reuse = by_id["reuse_stored_fabrication"]
    assert [ref["ref_id"] for ref in reuse["consumed"]] == ["poisoned_memory"]
    assert reuse["provenance"]["tier"] == "variant"

    feedback = by_id["feedback_reinforces_memory"]
    assert {ref["ref_id"] for ref in feedback["consumed"]} == {
        "poisoned_memory",
        "distorted_response",
    }
    assert [ref["ref_id"] for ref in feedback["produced"]] == ["reinforced_memory"]
    assert feedback["provenance"]["tier"] == "variant"

    terminal_step = steps[-1]
    assert terminal_step["step_id"] == "compound_distortion"
    assert [ref["ref_id"] for ref in terminal_step["consumed"]] == ["reinforced_memory"]
    # The one-shot path (poisoned_memory straight to terminal) must not exist.
    assert "poisoned_memory" not in {ref["ref_id"] for ref in terminal_step["consumed"]}


def test_t5_02_terminates_at_actual_endpoint_exfiltration(raw: dict) -> None:
    steps = raw["AP-T5-02"]["canonical_chain"]["steps"]
    assert len(steps) == 5
    final = steps[-1]
    assert final["step_id"] == "exfiltrate_via_endpoints"
    assert final["action_kind"] == "impact"
    terminal = _terminal_postconditions(final)
    assert len(terminal) == 1
    description = terminal[0]["description"].lower()
    assert "attacker-controlled endpoint" in description
    assert "first observable exfiltration" in description
    assert [ref["ref_id"] for ref in final["produced"]] == ["context_data_exfiltrated"]
    # No duplicate downstream impact restatement remains.
    assert "data_exfiltration_impact" not in {step["step_id"] for step in steps}
    assert "endpoint_request_emitted" not in set(_walk_strings(steps))


def test_t5_04_obfuscates_before_delivery(raw: dict) -> None:
    steps = raw["AP-T5-04"]["canonical_chain"]["steps"]
    by_id = {step["step_id"]: step for step in steps}
    obfuscate = by_id["obfuscate_injection"]
    deliver = by_id["deliver_fabricated_values"]
    persist = by_id["persist_in_rag"]
    assert obfuscate["order"] < deliver["order"] < persist["order"]
    assert obfuscate["boundary_position"] == "outside"
    assert obfuscate["action_kind"] == "prepare"
    # Obfuscation transforms the crafted values before any delivery; nothing is
    # transformed from outside after crossing the boundary.
    assert [ref["ref_id"] for ref in obfuscate["consumed"]] == [
        "fabricated_reference_values"
    ]
    assert [ref["ref_id"] for ref in deliver["consumed"]] == ["prioritized_injection"]
    assert [ref["ref_id"] for ref in persist["consumed"]] == ["delivered_values"]


def test_t6_02_terminates_at_first_unauthorized_execution(raw: dict) -> None:
    record = raw["AP-T6-02"]
    steps = record["canonical_chain"]["steps"]
    assert len(steps) == 6
    final = steps[-1]
    assert final["step_id"] == "execute_code_via_interpreter"
    assert final["action_kind"] == "impact"
    terminal = _terminal_postconditions(final)
    assert len(terminal) == 1
    assert (
        "first observable unauthorized command execution"
        in terminal[0]["description"].lower()
    )
    # Later credential access / broader compromise is removed entirely.
    step_ids = {step["step_id"] for step in steps}
    assert "exfiltrate_credentials" not in step_ids
    assert "system_compromise" not in step_ids
    strings = set(_walk_strings(record))
    assert "revealed_credentials" not in strings
    assert "AML.T0055" not in strings
    assert "code_execution_result" not in strings
    # First-terminal boundary is stated in the record description.
    assert "first unauthorized command execution" in record["description"].lower()


def test_t11_01_iac_sequence_and_honest_tiers(raw: dict) -> None:
    """The chain realizes actual backdoored-config generation and deployment;
    IaC-specific steps are tiered variant and never claim observed IaC timing
    from CS0052. Generic prompt-to-RCE machinery (sandbox escape, reverse
    shell) is gone."""
    record = raw["AP-T11-01"]
    steps = record["canonical_chain"]["steps"]
    by_id = {step["step_id"]: step for step in steps}

    for removed in (
        "execute_code_in_interpreter",
        "escape_sandbox",
        "establish_reverse_shell",
        "achieve_system_control",
    ):
        assert removed not in by_id
    assert "AML.T0105" not in set(_walk_strings(record))

    iac_steps = ["generate_backdoored_configuration", "deploy_configuration"]
    for step_id in iac_steps + ["execute_embedded_payload"]:
        step = by_id[step_id]
        assert step["provenance"]["tier"] == "variant", step_id
        assert (
            "not observed from cs0052"
            in step["provenance"]["adaptation_rationale"].lower()
        ), step_id

    generate = by_id["generate_backdoored_configuration"]
    assert generate["executor_role"] == "system"
    assert [ref["ref_id"] for ref in generate["produced"]] == ["backdoored_config"]

    deploy = by_id["deploy_configuration"]
    assert deploy["executor_role"] == "system"
    assert [ref["ref_id"] for ref in deploy["consumed"]] == ["backdoored_config"]
    assert [ref["ref_id"] for ref in deploy["produced"]] == ["deployed_configuration"]

    execute = steps[-1]
    assert execute["step_id"] == "execute_embedded_payload"
    assert execute["action_kind"] == "impact"
    assert [ref["ref_id"] for ref in execute["consumed"]] == ["deployed_configuration"]
    assert _step_exact_ids(record["canonical_chain"]) == {
        ("execute_embedded_payload", "AML.T0050")
    }
    terminal = _terminal_postconditions(execute)
    assert len(terminal) == 1
    description = terminal[0]["description"].lower()
    assert "on deployment" in description
    assert "first observable compromise" in description


def test_t11_02_direct_delivery_and_strict_variant_provenance(raw: dict) -> None:
    """Direct AML.T0051.000 prompt delivery to the workflow agent; no
    credential/repository configuration poisoning and no AML.T0081 anywhere;
    every step stays variant-tier CS0047 adaptation with the agent-as-payload
    mismatch stated. Ordinary interface access is folded into the delivery
    ingress, so the crafted prompt is consumed exactly once."""
    record = raw["AP-T11-02"]
    chain = record["canonical_chain"]
    steps = chain["steps"]
    assert len(steps) == 5

    strings = set(_walk_strings(record))
    for removed in (
        "obtain_credentials",
        "access_workflow_agent_interface",
        "workflow_agent_session",
        "inject_malicious_configuration",
        "initialize_poisoned_agent",
        "publishing_credentials",
        "poisoned_configuration",
        "steered_agent_state",
        "AML.T0081",
    ):
        assert removed not in strings, removed

    # The crafted prompt has exactly one consumer: the delivery step.
    prompt_consumers = [
        step["step_id"]
        for step in steps
        if any(ref["ref_id"] == "backdoor_prompt" for ref in step["consumed"])
    ]
    assert prompt_consumers == ["deliver_backdoor_prompt"]

    for step in steps:
        provenance = step["provenance"]
        assert provenance["tier"] == "variant", (
            f"AP-T11-02.{step['step_id']}: tier {provenance['tier']} "
            "would overclaim direct demonstration"
        )
        reference_ids = {ref["reference_id"] for ref in provenance["references"]}
        assert "AML.CS0047" in reference_ids, step["step_id"]
        rationale = provenance["adaptation_rationale"].lower()
        assert "adapt" in rationale or "analog" in rationale, step["step_id"]
        # The agent-as-payload mismatch must be stated on every step: in
        # CS0047 the agent is the destructive payload, not the target.
        assert "agent-as-payload" in rationale or (
            "destructive payload" in rationale and "manipulation target" in rationale
        ), f"AP-T11-02.{step['step_id']}: agent-as-payload mismatch not stated"

    deliver = steps[1]
    assert deliver["step_id"] == "deliver_backdoor_prompt"
    assert deliver["action_kind"] == "deliver"
    assert deliver["boundary_position"] == "crossing"
    assert "ordinary user interface" in (
        deliver["observable_postconditions"][0]["description"].lower()
    )
    exact = _step_exact_ids(chain)
    assert ("deliver_backdoor_prompt", "AML.T0051.000") in exact
    assert ("generate_backdoored_workflow", "AML.T0053") in exact
    assert ("execute_hidden_logic", "AML.T0050") in exact
    assert _chain_exact_ids(chain) == {"AML.T0051.000"}
    assert record["nist_classification"]["attack_class"] == (
        "genai.direct_prompt_injection.abuse_violations"
    )


def test_t13_04_terminates_at_first_peer_replication(raw: dict) -> None:
    record = raw["AP-T13-04"]
    steps = record["canonical_chain"]["steps"]
    assert len(steps) == 4
    final = steps[-1]
    assert final["step_id"] == "propagate_to_peer_agents"
    assert final["action_kind"] == "impact"
    terminal = _terminal_postconditions(final)
    assert len(terminal) == 1
    description = terminal[0]["description"].lower()
    assert "peer agent" in description
    assert "first observable propagation" in description
    # Network-wide persistence is out of scope for this record.
    assert "achieve_system_wide_compromise" not in {step["step_id"] for step in steps}
    strings = set(_walk_strings(record))
    assert "network_compromise_outcome" not in strings
    assert "peer_adoption_state" not in strings


def test_semantic_digest_ignores_chain_key_order(raw) -> None:
    chain = raw["AP-T1-06"]["canonical_chain"]
    reordered = {key: chain[key] for key in reversed(chain)}
    assert compute_chain_semantic_digest(reordered) == chain["semantic_digest"]


def test_resource_constraint_membership_order_is_not_semantic(raw) -> None:
    chain = deepcopy(raw["AP-T6-07"]["canonical_chain"])
    c2_slot = next(s for s in chain["resource_slots"] if s["slot_id"] == "c2_channel")
    c2_slot["allowed_integration_types"].reverse()
    assert compute_chain_semantic_digest(chain) == chain["semantic_digest"]


def test_directionality_correction_and_persistence_are_recorded(qualified) -> None:
    # AP-T15-02: the CS0055 directionality correction must be retained in
    # provenance, and the human-directed line must be grounded in CS0020.
    t15_02_text = yaml.safe_dump(
        qualified["AP-T15-02"].model_dump(mode="json"), sort_keys=True
    )
    assert "directionality" in t15_02_text
    assert "AML.CS0020 S03" in t15_02_text
    assert "AML.T0052.000" in t15_02_text
    # AP-T17-01: the evidence-backed persistence step (CS0041 S04) survives.
    t17_01 = qualified["AP-T17-01"].canonical_chain
    persist = [s for s in t17_01.steps if s.action_kind == "persist"]
    assert [s.step_id for s in persist] == ["persist_via_adoption"]
    references = persist[0].provenance.references
    assert any(r.reference_id == "AML.CS0041 S04" for r in references)

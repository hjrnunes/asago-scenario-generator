"""Regression coverage for generic list paths in the authoring contract."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    ProfileBasis,
    SemanticAuthority,
    SourceProtocol,
)
from asago_scenario_generator.stpa.models.target_derived_structure import ActionBinding
from asago_scenario_generator.stpa.scenario_prod.authoring import (
    AcceptedScenario,
    AuthoredAdversary,
    AuthoredConditionEntry,
    AuthoredScenarioDraft,
    AuthoredStimulus,
    AuthoredUnsafeObservation,
    AuthoringCandidate,
    ScenarioHazardLine,
    build_authoring_user_prompt,
    resolve_session_identity,
    validate_authored_scenario,
)


STATE = {
    "items": [
        {"item_key": "entry-alpha", "status": "pending"},
    ],
}
LIST_STATUS_PATH = ("items", "0", "status")


def _profile() -> ExecutionTargetProfile:
    """Return the smallest valid profile for a model-output action."""
    return ExecutionTargetProfile(
        target_id="synthetic-target",
        authorization_scope_id="synthetic-scope",
        basis=ProfileBasis.simulation,
        semantic_authority=SemanticAuthority.inferred,
        source_protocol=SourceProtocol.simulation,
    )


def _candidate() -> AuthoringCandidate:
    binding = ActionBinding(
        ca_id="CA-SYNTHETIC-1",
        name="reply",
        kind="model_output",
        justification="synthetic response action",
    )
    return AuthoringCandidate(
        constraint_id="SC-SYNTHETIC",
        rule="The assistant must report the observed item status.",
        applies_when=("the request concerns an item",),
        action_name=binding.name,
        action_description="Synthetic response action",
        action_binding=binding,
        hazards=(
            ScenarioHazardLine(
                hazard_id="H-SYNTHETIC",
                description="The assistant reports an unsafe item status.",
                losses=(("L-SYNTHETIC", "The status is misreported."),),
            ),
        ),
        constraint_text=(
            "The assistant must report the observed item status. Applies when: "
            "the request concerns an item."
        ),
    )


def _draft(
    *,
    state_path: tuple[str, ...],
    condition_path: tuple[str, ...] | None = None,
) -> AuthoredScenarioDraft:
    return AuthoredScenarioDraft(
        adversary=AuthoredAdversary(
            kind="none",
            gain="No one gains from this functional check.",
        ),
        stimulus=AuthoredStimulus(
            kind="user_message",
            text="Please report the item status.",
        ),
        state_facts_used=(state_path,),
        unsafe_observation=AuthoredUnsafeObservation(
            kind="response_claim",
            proposition="The reply reports an unsafe status claim.",
        ),
        conditions_established=(
            AuthoredConditionEntry(
                condition=1,
                by="state_fact",
                ref=condition_path if condition_path is not None else state_path,
                note="The listed item has the observed status.",
            ),
        ),
        safe_behaviors=("Report the observed status.",),
    )


def _validate(draft: AuthoredScenarioDraft):
    return validate_authored_scenario(
        draft,
        _candidate(),
        state=STATE,
        observations=(),
        profile=_profile(),
        session=resolve_session_identity(STATE),
        has_content_surface=False,
    )


def test_prompt_explains_mapping_keys_list_indexes_and_exact_condition_paths():
    prompt = build_authoring_user_prompt(
        _candidate(),
        state=STATE,
        observation_records=(),
        session=resolve_session_identity(STATE),
        profile=_profile(),
    )

    assert "mappings with their keys and lists with their zero-based indexes" in prompt
    assert '["<collection>", "0", "<field>"]' in prompt
    assert "An ID embedded in a list element is a value, not a mapping key" in prompt
    assert (
        'A `conditions_established` entry with `by: "state_fact"` must copy '
        "the exact path listed in `state_facts_used`"
    ) in prompt


def test_validator_accepts_a_zero_based_numeric_string_list_path():
    accepted = _validate(_draft(state_path=LIST_STATUS_PATH))

    assert isinstance(accepted, AcceptedScenario)
    assert accepted.state_facts[0].path == LIST_STATUS_PATH
    assert accepted.state_facts[0].value == "pending"


def test_validator_rejects_an_embedded_id_used_as_a_list_index():
    rejected = _validate(_draft(state_path=("items", "entry-alpha", "status")))

    assert rejected.reason == "state_fact_missing"


def test_validator_requires_condition_reference_to_copy_the_list_path():
    rejected = _validate(
        _draft(
            state_path=LIST_STATUS_PATH,
            condition_path=("items", "entry-alpha", "status"),
        )
    )

    assert rejected.reason == "qualifier_dropped"

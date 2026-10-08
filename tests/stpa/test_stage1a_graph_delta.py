"""Focused coverage for the current Stage 1a local-handle and delta wires."""

from __future__ import annotations

from datetime import date

import pytest
from hypothesis import example, given, settings, strategies as st
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossAnalysisDraft,
    LossProvenance,
    RiskDisposition,
    SecurityConstraint,
    stamp_proposed_direction,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRiskRepairDraft,
    _Stage1aGapProviderDraft,
    _Stage1aRevisionPatch,
    _Stage1aRiskProviderDraft,
    _materialize_provider_draft,
    _merge_drafts,
    _prepare_current_provider_repair_input,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    _draft_from_analysis,
    _revision_patch_to_draft,
    _revised_analysis,
)


def _risk_provider(*, reverse: bool = False) -> _Stage1aRiskProviderDraft:
    losses = [
        {
            "handle": "account_loss",
            "description": "Account harm",
            "provenance": "risk_card",
            "source_risk_cards": ["R1"],
        },
        {
            "handle": "privacy_loss",
            "description": "Privacy harm",
            "provenance": "risk_card",
            "source_risk_cards": ["R1"],
        },
    ]
    if reverse:
        losses.reverse()
    return _Stage1aRiskProviderDraft.model_validate(
        {
            "risk_card_losses": losses,
            "use_case_losses": [],
            "hazards": [
                {
                    "handle": "privacy_hazard",
                    "description": "The privacy data flow exposes records.",
                    "related_losses": ["privacy_loss"],
                }
            ],
            "security_constraints": [
                {
                    "handle": "privacy_constraint",
                    "rule": "Protect privacy data",
                    "applies_when": [],
                    "obligations": [],
                    "related_hazards": ["privacy_hazard"],
                }
            ],
            "risk_dispositions": [
                {
                    "risk_ref": "R1",
                    "disposition": "cited",
                    "loss_ids": ["privacy_loss"],
                }
            ],
        }
    )


def _prior_analysis() -> LossAnalysis:
    return LossAnalysis.model_validate(
        {
            "risk_card_losses": [
                {
                    "loss_id": "L-5",
                    "description": "Account harm",
                    "provenance": "risk_card",
                    "source_risk_cards": ["R1"],
                },
                {
                    "loss_id": "L-8",
                    "description": "Privacy harm",
                    "provenance": "risk_card",
                    "source_risk_cards": ["R1"],
                },
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-4",
                    "description": "Account records enter the wrong state.",
                    "related_losses": ["L-5"],
                },
                {
                    "hazard_id": "H-9",
                    "description": "Privacy records enter the wrong state.",
                    "related_losses": ["L-8"],
                },
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-3",
                    "rule": "Protect account records",
                    "applies_when": [],
                    "related_hazards": ["H-4"],
                    "obligations": [
                        {
                            "obligation_id": "O1",
                            "kind": "required",
                            "behavior": "Protect account records",
                            "rule_span": "Protect account records",
                            "realized_by": "tool_call",
                        }
                    ],
                    "direction_authority": "reviewed",
                    "reviewed_by": "reviewer",
                    "reviewed_on": date(2026, 9, 12),
                },
                {
                    "constraint_id": "SC-7",
                    "rule": "Protect privacy records",
                    "applies_when": [],
                    "related_hazards": ["H-9"],
                },
            ],
            "risk_dispositions": [
                {"risk_ref": "R1", "disposition": "cited", "loss_ids": ["L-5"]}
            ],
        }
    )


def test_current_provider_wire_is_local_and_closed() -> None:
    assert set(_Stage1aGapProviderDraft.model_json_schema()["properties"]) == {
        "risk_card_losses",
        "use_case_losses",
        "hazards",
        "security_constraints",
    }
    assert set(_Stage1aRevisionPatch.model_json_schema()["properties"]) == {
        "hazard_edits",
        "hazard_additions",
        "security_constraint_edits",
        "security_constraint_additions",
    }
    with pytest.raises(ValidationError):
        _Stage1aRiskProviderDraft.model_validate(
            {
                "risk_card_losses": [
                    {
                        "loss_id": "L-1",
                        "description": "old wire",
                        "provenance": "risk_card",
                        "source_risk_cards": ["R1"],
                    }
                ],
                "use_case_losses": [],
                "hazards": [],
                "security_constraints": [],
                "risk_dispositions": [],
            }
        )
    with pytest.raises(ValidationError):
        _Stage1aGapProviderDraft.model_validate(
            {
                "risk_card_losses": [],
                "use_case_losses": [],
                "hazards": [],
                "security_constraints": [],
                "losses": [],
            }
        )
    with pytest.raises(ValidationError):
        _Stage1aRevisionPatch.model_validate({})
    # Reserve every canonical namespace in every local collection.  A
    # cross-kind alias such as ``L-1`` on a hazard must not be confused with
    # an existing loss ID during deterministic reference compilation.
    for collection, record, reserved in (
        (
            "risk_card_losses",
            {
                "handle": "H-1",
                "description": "old alias",
                "provenance": "risk_card",
                "source_risk_cards": ["R1"],
            },
            "H-1",
        ),
        (
            "hazards",
            {
                "handle": "L-1",
                "description": "old alias",
                "related_losses": ["loss"],
            },
            "L-1",
        ),
        (
            "security_constraints",
            {
                "handle": "SC-1",
                "rule": "Protect harm",
                "applies_when": [],
                "related_hazards": ["hazard"],
                "obligations": [],
            },
            "SC-1",
        ),
    ):
        payload = {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
        }
        payload[collection] = [record]
        with pytest.raises(ValidationError, match=reserved):
            _Stage1aGapProviderDraft.model_validate(payload)
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _Stage1aGapProviderDraft.model_validate(
            {
                "risk_card_losses": [],
                "use_case_losses": [],
                "hazards": [
                    {
                        "handle": "hazard",
                        "description": "A state",
                        "related_losses": ["L-1"],
                    }
                ],
                "security_constraints": [
                    {
                        "handle": "constraint",
                        "rule": "Protect harm",
                        "applies_when": [],
                        "related_hazards": ["hazard"],
                        "obligations": [
                            {
                                "obligation_id": "O1",
                                "kind": "required",
                                "behavior": "Protect harm",
                                "rule_span": "Protect harm",
                                "realized_by": "tool_call",
                                "unexpected": "reject",
                            }
                        ],
                    }
                ],
            }
        )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _Stage1aRiskProviderDraft.model_validate(
            {
                "risk_card_losses": [],
                "use_case_losses": [],
                "hazards": [],
                "security_constraints": [],
                "risk_dispositions": [
                    {
                        "risk_ref": "R1",
                        "disposition": "not_applicable",
                        "reason": "out of scope",
                        "unexpected": "reject",
                    }
                ],
            }
        )


def test_provider_allocation_is_deterministic_and_preserves_prior_ids() -> None:
    first = _materialize_provider_draft(_risk_provider())
    reversed_result = _materialize_provider_draft(_risk_provider(reverse=True))
    assert [loss.loss_id for loss in first.risk_card_losses] == ["L-1", "L-2"]
    assert {loss.description: loss.loss_id for loss in first.risk_card_losses} == {
        loss.description: loss.loss_id for loss in reversed_result.risk_card_losses
    }

    prior = first
    gap = _Stage1aGapProviderDraft.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [
                {
                    "handle": "zeta_loss",
                    "description": "New harm",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                },
                {
                    "handle": "alpha_loss",
                    "description": "Another harm",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                },
            ],
            "hazards": [
                {
                    "handle": "new_hazard",
                    "description": "New state",
                    "related_losses": ["alpha_loss"],
                }
            ],
            "security_constraints": [
                {
                    "handle": "new_constraint",
                    "rule": "Protect new state",
                    "applies_when": [],
                    "obligations": [],
                    "related_hazards": ["new_hazard"],
                }
            ],
        }
    )
    materialized = _materialize_provider_draft(gap, prior=prior)
    assert [loss.loss_id for loss in materialized.use_case_losses] == ["L-4", "L-3"]
    assert materialized.hazards[0].hazard_id == "H-2"
    assert materialized.security_constraints[0].constraint_id == "SC-2"
    assert materialized.hazards[0].related_losses == ["L-3"]


def test_provider_rejects_guessed_new_canonical_references() -> None:
    """New records must be referenced by local handles, never guessed IDs."""
    guessed_loss = _Stage1aGapProviderDraft.model_validate(
        {
            "risk_card_losses": [
                {
                    "handle": "new_loss",
                    "description": "New harm",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                }
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "handle": "new_hazard",
                    "description": "New state",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [],
        }
    )
    with pytest.raises(ValueError, match="unknown loss reference 'L-1'"):
        _materialize_provider_draft(guessed_loss)

    guessed_hazard = _Stage1aGapProviderDraft.model_validate(
        {
            "risk_card_losses": [
                {
                    "handle": "new_loss",
                    "description": "New harm",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                }
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "handle": "new_hazard",
                    "description": "New state",
                    "related_losses": ["new_loss"],
                }
            ],
            "security_constraints": [
                {
                    "handle": "new_constraint",
                    "rule": "Protect new state",
                    "applies_when": [],
                    "related_hazards": ["H-1"],
                    "obligations": [],
                }
            ],
        }
    )
    with pytest.raises(ValueError, match="unknown hazard reference 'H-1'"):
        _materialize_provider_draft(guessed_hazard)


def test_provider_resolves_prior_canonical_references_only() -> None:
    prior = _materialize_provider_draft(_risk_provider())
    gap = _Stage1aGapProviderDraft.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [
                {
                    "handle": "follow_on_hazard",
                    "description": "A follow-on state",
                    "related_losses": ["L-2"],
                }
            ],
            "security_constraints": [],
        }
    )
    materialized = _materialize_provider_draft(gap, prior=prior)
    assert materialized.hazards[0].related_losses == ["L-2"]


def test_repair_adapter_translates_current_wire_without_accepting_old_ids() -> None:
    result = LLMResult(
        content={
            "risk_card_losses": [
                {
                    "handle": "loss",
                    "description": "Harm",
                    "provenance": "risk_card",
                    "source_risk_cards": ["R1"],
                }
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "handle": "hazard",
                    "description": "A state",
                    "related_losses": ["loss"],
                }
            ],
            "security_constraints": [
                {
                    "handle": "constraint",
                    "rule": "Protect harm",
                    "applies_when": [],
                    "related_hazards": ["hazard"],
                    "obligations": [],
                }
            ],
            "risk_dispositions": [
                {
                    "risk_ref": "R1",
                    "disposition": "cited",
                    "loss_ids": ["loss"],
                    "reason": "malformed cited row",
                }
            ],
        },
        prompt_tokens=1,
        completion_tokens=1,
        duration_ms=1,
    )
    adapted = _prepare_current_provider_repair_input(
        result,
        response_format=_Stage1aRiskProviderDraft,
        prior=None,
    )
    assert adapted is not None
    translated, repair_model = adapted
    assert repair_model is _Stage1aRiskRepairDraft
    assert translated.content["risk_card_losses"][0]["loss_id"] == "L-1"
    assert translated.content["hazards"][0]["related_losses"] == ["L-1"]
    assert translated.content["risk_dispositions"][0]["loss_ids"] == ["L-1"]
    assert translated.content["risk_dispositions"][0]["reason"] == (
        "malformed cited row"
    )


def test_merge_preserves_existing_canonical_ids() -> None:
    risk = _prior_analysis()
    merged = _merge_drafts(
        risk.model_copy(
            update={
                "use_case_losses": [],
                "hazards": [risk.hazards[0]],
                "security_constraints": [risk.security_constraints[0]],
            }
        ),
        risk.model_copy(
            update={
                "risk_card_losses": [],
                "hazards": [risk.hazards[1]],
                "security_constraints": [risk.security_constraints[1]],
            }
        ),
    )
    assert [loss.loss_id for loss in merged.risk_card_losses] == ["L-5", "L-8"]
    assert [hazard.hazard_id for hazard in merged.hazards] == ["H-4", "H-9"]
    assert [constraint.constraint_id for constraint in merged.security_constraints] == [
        "SC-3",
        "SC-7",
    ]


def test_merge_separates_local_scopes_and_keeps_risk_disposition_binding() -> None:
    risk = LossAnalysisDraft(
        risk_card_losses=[
            Loss(
                loss_id="shared_loss_handle",
                description="Risk harm",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["R1"],
            )
        ],
        hazards=[
            Hazard(
                hazard_id="shared_hazard_handle",
                description="Risk state",
                related_losses=["shared_loss_handle"],
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="shared_constraint_handle",
                rule="Protect risk state",
                related_hazards=["shared_hazard_handle"],
            )
        ],
        risk_dispositions=[
            RiskDisposition(
                risk_ref="R1",
                disposition="cited",
                loss_ids=["shared_loss_handle"],
            )
        ],
    )
    gap = LossAnalysisDraft(
        use_case_losses=[
            Loss(
                loss_id="shared_loss_handle",
                description="Use-case harm",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(
                hazard_id="shared_hazard_handle",
                description="Use-case state",
                related_losses=["shared_loss_handle"],
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="shared_constraint_handle",
                rule="Protect use-case state",
                related_hazards=["shared_hazard_handle"],
            )
        ],
    )

    merged = _merge_drafts(risk, gap)
    assert [loss.loss_id for loss in merged.risk_card_losses] == ["L-1"]
    assert [loss.loss_id for loss in merged.use_case_losses] == ["L-2"]
    assert [hazard.hazard_id for hazard in merged.hazards] == ["H-1", "H-2"]
    assert [constraint.constraint_id for constraint in merged.security_constraints] == [
        "SC-1",
        "SC-2",
    ]
    assert merged.risk_dispositions[0].loss_ids == ["L-1"]


def test_delta_carries_untouched_records_and_restamps_revision() -> None:
    prior = _prior_analysis()
    patch = _Stage1aRevisionPatch.model_validate(
        {
            "hazard_edits": [
                {
                    "hazard_id": "H-4",
                    "description": "Account records enter a payment state.",
                    "related_losses": ["L-5"],
                }
            ],
            "hazard_additions": [
                {
                    "handle": "new_hazard",
                    "description": "Privacy records enter a reporting state.",
                    "related_losses": ["L-8"],
                }
            ],
            "security_constraint_edits": [
                {
                    "constraint_id": "SC-3",
                    "rule": "Protect account records",
                    "applies_when": [],
                    "related_hazards": ["H-4"],
                }
            ],
            "security_constraint_additions": [
                {
                    "handle": "new_constraint",
                    "rule": "Protect reporting state",
                    "applies_when": [],
                    "obligations": [],
                    "related_hazards": ["new_hazard"],
                }
            ],
        }
    )
    revised = _revised_analysis(prior, _revision_patch_to_draft(prior, patch, []))
    assert revised.hazards[1].model_dump(mode="json") == prior.hazards[1].model_dump(
        mode="json"
    )
    assert [hazard.hazard_id for hazard in revised.hazards] == ["H-4", "H-9", "H-10"]
    assert [
        constraint.constraint_id for constraint in revised.security_constraints
    ] == [
        "SC-3",
        "SC-7",
        "SC-8",
    ]
    assert revised.security_constraints[0].obligations[0].obligation_id == "O1"
    assert revised.security_constraints[0].effective_direction_authority == "proposed"
    assert revised.security_constraints[0].reviewed_by is None
    assert revised.security_constraints[0].reviewed_on is None


def test_delta_resolves_a_hazard_addition_that_restates_an_existing_hazard() -> None:
    """A copied uncovered hazard resolves to it instead of duplicating it."""
    prior = _prior_analysis()
    patch = _Stage1aRevisionPatch.model_validate(
        {
            "hazard_edits": [],
            "hazard_additions": [
                {
                    "handle": "new_hazard",
                    "description": "  privacy records enter the wrong  state.",
                    "related_losses": ["L-8"],
                }
            ],
            "security_constraint_edits": [],
            "security_constraint_additions": [
                {
                    "handle": "new_constraint",
                    "rule": "Keep privacy records in the right state",
                    "applies_when": [],
                    "obligations": [],
                    "related_hazards": ["new_hazard"],
                }
            ],
        }
    )
    warnings: list[str] = []
    revised = _revised_analysis(prior, _revision_patch_to_draft(prior, patch, warnings))
    assert [hazard.hazard_id for hazard in revised.hazards] == ["H-4", "H-9"]
    assert revised.security_constraints[-1].related_hazards == ["H-9"]
    assert warnings == [
        "graph revision hazard addition 'new_hazard' restates existing hazard "
        "H-9; its references resolve to H-9"
    ]


def test_delta_span_error_names_the_addition_handle_span_and_rule() -> None:
    """The correction call can only fix a span it can find in the feedback."""
    prior = _prior_analysis()
    patch = _Stage1aRevisionPatch.model_validate(
        {
            "hazard_edits": [],
            "hazard_additions": [],
            "security_constraint_edits": [],
            "security_constraint_additions": [
                {
                    "handle": "new_constraint",
                    "rule": "The system must not share privacy records.",
                    "applies_when": [],
                    "related_hazards": ["H-9"],
                    "obligations": [
                        {
                            "obligation_id": "O1",
                            "kind": "forbidden",
                            "behavior": "share privacy records",
                            "rule_span": "does not share privacy records",
                            "violated_via": "reply",
                        }
                    ],
                }
            ],
        }
    )
    with pytest.raises(ValidationError) as caught:
        _revision_patch_to_draft(prior, patch, [])
    message = str(caught.value)
    assert "security constraint addition 'new_constraint'" in message
    assert "'does not share privacy records'" in message
    assert "'The system must not share privacy records.'" in message


def test_delta_keeps_a_same_text_hazard_addition_that_cites_a_new_loss() -> None:
    prior = _prior_analysis()
    patch = _Stage1aRevisionPatch.model_validate(
        {
            "hazard_edits": [],
            "hazard_additions": [
                {
                    "handle": "new_hazard",
                    "description": "Privacy records enter the wrong state.",
                    "related_losses": ["L-5", "L-8"],
                }
            ],
            "security_constraint_edits": [],
            "security_constraint_additions": [
                {
                    "handle": "new_constraint",
                    "rule": "Keep privacy records in the right state",
                    "applies_when": [],
                    "obligations": [],
                    "related_hazards": ["new_hazard"],
                }
            ],
        }
    )
    revised = _revised_analysis(prior, _revision_patch_to_draft(prior, patch, []))
    assert [hazard.hazard_id for hazard in revised.hazards] == ["H-4", "H-9", "H-10"]


def test_delta_rejects_unknown_targets_stale_obligations_and_extra_fields() -> None:
    prior = _prior_analysis()
    with pytest.raises(ValueError, match="unknown hazard edit target"):
        _revision_patch_to_draft(
            prior,
            _Stage1aRevisionPatch.model_validate(
                {
                    "hazard_edits": [
                        {
                            "hazard_id": "H-99",
                            "description": "Unknown",
                            "related_losses": ["L-5"],
                        }
                    ],
                    "hazard_additions": [],
                    "security_constraint_edits": [],
                    "security_constraint_additions": [],
                }
            ),
            [],
        )
    with pytest.raises(ValueError, match="without explicit obligations"):
        _revision_patch_to_draft(
            prior,
            _Stage1aRevisionPatch.model_validate(
                {
                    "hazard_edits": [],
                    "hazard_additions": [],
                    "security_constraint_edits": [
                        {
                            "constraint_id": "SC-3",
                            "rule": "Protect changed account records",
                            "applies_when": [],
                            "related_hazards": ["H-4"],
                        }
                    ],
                    "security_constraint_additions": [],
                }
            ),
            [],
        )
    with pytest.raises(ValueError, match="without explicit obligations"):
        _revision_patch_to_draft(
            prior,
            _Stage1aRevisionPatch.model_validate(
                {
                    "hazard_edits": [],
                    "hazard_additions": [],
                    "security_constraint_edits": [
                        {
                            "constraint_id": "SC-3",
                            "rule": "Protect account records",
                            "applies_when": ["during payment"],
                            "related_hazards": ["H-4"],
                        }
                    ],
                    "security_constraint_additions": [],
                }
            ),
            [],
        )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _Stage1aRevisionPatch.model_validate({"hazards": []})
    with pytest.raises(ValidationError, match="canonical graph ID"):
        _Stage1aRevisionPatch.model_validate(
            {
                "hazard_edits": [],
                "hazard_additions": [
                    {
                        "handle": "H-10",
                        "description": "Bad addition",
                        "related_losses": ["L-5"],
                    }
                ],
                "security_constraint_edits": [],
                "security_constraint_additions": [],
            }
        )
    with pytest.raises(ValueError, match="unknown hazard ID"):
        _revision_patch_to_draft(
            prior,
            _Stage1aRevisionPatch.model_validate(
                {
                    "hazard_edits": [],
                    "hazard_additions": [
                        {
                            "handle": "another_hazard",
                            "description": "Another state",
                            "related_losses": ["L-5"],
                        }
                    ],
                    "security_constraint_edits": [],
                    "security_constraint_additions": [
                        {
                            "handle": "another_constraint",
                            "rule": "Protect another state",
                            "applies_when": [],
                            "related_hazards": ["H-10"],
                        }
                    ],
                }
            ),
            [],
        )


def test_draft_from_analysis_shares_no_record_with_the_prior_graph() -> None:
    """Stamping a revision draft must not rewrite the prior graph it came from."""
    prior = _prior_analysis()
    before = prior.model_dump(mode="json")

    draft = _draft_from_analysis(prior)
    stamp_proposed_direction(draft)

    assert draft.security_constraints[0].effective_direction_authority == "proposed"
    assert prior.model_dump(mode="json") == before
    assert prior.security_constraints[0].effective_direction_authority == "reviewed"
    assert all(
        draft_item is not prior_item
        for draft_items, prior_items in (
            (draft.risk_card_losses, prior.risk_card_losses),
            (draft.use_case_losses, prior.use_case_losses),
            (draft.hazards, prior.hazards),
            (draft.security_constraints, prior.security_constraints),
            (draft.risk_dispositions, prior.risk_dispositions),
        )
        for draft_item, prior_item in zip(draft_items, prior_items, strict=True)
    )


def test_patch_draft_shares_no_record_with_the_prior_graph() -> None:
    prior = _prior_analysis()
    patch = _Stage1aRevisionPatch.model_validate(
        {
            "hazard_edits": [],
            "hazard_additions": [],
            "security_constraint_edits": [],
            "security_constraint_additions": [],
        }
    )
    before = prior.model_dump(mode="json")

    draft = _revision_patch_to_draft(prior, patch, [])
    stamp_proposed_direction(draft)

    assert prior.model_dump(mode="json") == before
    assert all(
        draft_item is not prior_item
        for draft_items, prior_items in (
            (draft.hazards, prior.hazards),
            (draft.security_constraints, prior.security_constraints),
        )
        for draft_item, prior_item in zip(draft_items, prior_items, strict=True)
    )


_LOSS_REFS = st.sampled_from(["L-5", "L-8", "L-99"])
_HAZARD_REFS = st.sampled_from(["H-4", "H-9", "H-99", "new_a", "new_b"])
_TEXTS = st.sampled_from(
    [
        "Account records enter the wrong state.",
        "Privacy records enter the wrong state.",
        "Protect account records",
        "Protect privacy records",
        "A new state appears.",
    ]
)


@st.composite
def _revision_patches(draw) -> dict:
    """Edits of existing records and additions, valid or not."""
    hazard_edits = [
        {
            "hazard_id": hazard_id,
            "description": draw(_TEXTS),
            "related_losses": draw(st.lists(_LOSS_REFS, min_size=1, max_size=2)),
        }
        for hazard_id in draw(st.lists(st.sampled_from(["H-4", "H-9"]), max_size=2))
    ]
    hazard_additions = [
        {
            "handle": handle,
            "description": draw(_TEXTS),
            "related_losses": draw(st.lists(_LOSS_REFS, min_size=1, max_size=2)),
        }
        for handle in draw(
            st.lists(st.sampled_from(["new_a", "new_b"]), max_size=2, unique=True)
        )
    ]
    constraint_edits = [
        {
            "constraint_id": constraint_id,
            "rule": rule,
            "applies_when": [],
            "related_hazards": draw(st.lists(_HAZARD_REFS, min_size=1, max_size=2)),
        }
        for constraint_id, rule in draw(
            st.lists(
                st.sampled_from(
                    [
                        ("SC-3", "Protect account records"),
                        ("SC-7", "Protect privacy records"),
                    ]
                ),
                max_size=2,
            )
        )
    ]
    constraint_additions = [
        {
            "handle": handle,
            "rule": draw(_TEXTS),
            "applies_when": [],
            "related_hazards": draw(st.lists(_HAZARD_REFS, min_size=1, max_size=2)),
        }
        for handle in draw(
            st.lists(st.sampled_from(["sc_a", "sc_b"]), max_size=2, unique=True)
        )
    ]
    return {
        "hazard_edits": hazard_edits,
        "hazard_additions": hazard_additions,
        "security_constraint_edits": constraint_edits,
        "security_constraint_additions": constraint_additions,
    }


_ASSEMBLED = {"count": 0}


@given(patch=_revision_patches())
@example(
    patch={
        "hazard_edits": [],
        "hazard_additions": [
            {
                "handle": "new_a",
                "description": "A new state appears.",
                "related_losses": ["L-5"],
            }
        ],
        "security_constraint_edits": [],
        "security_constraint_additions": [],
    }
)
@settings(max_examples=200, deadline=None)
def test_an_assembled_revision_keeps_every_prior_record(patch: dict) -> None:
    """A patch that assembles keeps every loss exactly and every prior ID."""
    prior = _prior_analysis()
    try:
        draft = _revision_patch_to_draft(
            prior, _Stage1aRevisionPatch.model_validate(patch), []
        )
    except ValueError:
        return
    _ASSEMBLED["count"] += 1

    def dumped(losses):
        return [loss.model_dump(mode="json") for loss in losses]

    assert dumped(draft.risk_card_losses) == dumped(prior.risk_card_losses)
    assert dumped(draft.use_case_losses) == dumped(prior.use_case_losses)
    assert {h.hazard_id for h in prior.hazards} <= {h.hazard_id for h in draft.hazards}
    assert {c.constraint_id for c in prior.security_constraints} <= {
        c.constraint_id for c in draft.security_constraints
    }


def test_the_revision_property_assembles_patches() -> None:
    """The property above is not vacuous: patches do assemble."""
    test_an_assembled_revision_keeps_every_prior_record()
    assert _ASSEMBLED["count"] > 0

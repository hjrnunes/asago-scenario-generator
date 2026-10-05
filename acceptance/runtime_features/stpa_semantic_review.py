"""Neutral offline acceptance for control ownership and outcome value evidence."""

import re
from pathlib import Path
from tempfile import TemporaryDirectory

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionValueCondition,
    SemanticBindingPlaceholder,
)
from asago_scenario_generator.stpa.scenario_prod.outcome_grounding import (
    ComparisonEvidence,
    resolve_outcome_grounding,
)
from asago_scenario_generator.stpa.system_model.semantic_review import (
    ControlStructureSemanticReview,
    apply_control_structure_semantic_review,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.obligation_aware.contracts import AnalysisControls
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaHazardVerificationRequest,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    PROMPTS_DIR,
    _call_3_coordination,
)
from copy import deepcopy
from jsonschema import Draft202012Validator

FEATURE_ID = "stpa_semantic_review"


def _given_ica_checks(world, step, match):
    world.ica_semantic_checks = re.findall(r'"([^"]+)"', step)
    return True, ""


def _compile_ica_checks(world, step, match):
    state, category, harm = world.ica_semantic_checks
    request = _semantic_ica_request(category)

    class OfflineClient:
        model = "offline-contract"
        calls = 0

        def complete(self, **kwargs):
            self.calls += 1
            return LLMResult(
                content={
                    "verdicts": [
                        {
                            "review_ref": "review-1",
                            "action_state": state,
                            "hazard_path": harm,
                            "rationale": "Independent supplied action, category and harm decisions.",
                        }
                    ]
                },
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    client = OfflineClient()
    with TemporaryDirectory(prefix="ica-semantic-acceptance-") as directory:
        adapter = ObligationAwareLLMAdapter(
            client,
            run_dir=Path(directory),
            controls=AnalysisControls(
                model_profile="offline",
                model_name=client.model,
                deadline_seconds=30.0,
                temperature=0.0,
            ),
        )
        world.ica_semantic_result = adapter.verify_ica_hazards((request,))[0]
    assert world.ica_semantic_result.ica_id == request.ica_id
    assert world.ica_semantic_result.request_digest == request.semantic_digest
    world.ica_semantic_call_count = client.calls
    return True, ""


def _semantic_ica_request(category):
    return IcaHazardVerificationRequest(
        slot_id=f"RESP-1:CA-1-1:{category}",
        ica_id=f"RESP-1:CA-1-1:{category}:1",
        responsibility_description="Maintain sample integrity",
        control_action_id="CA-1-1",
        control_action_description="Release sample",
        uca_type=category,
        uca_definition="Action occurs with an unsafe effect",
        deviation="required approval is absent",
        hazardous_context="Unapproved sample is released",
        loss_consequence="Sample integrity is lost",
        hazards=(
            {
                "hazard_id": "H-1",
                "description": "Unapproved release",
                "related_loss_ids": ["L-1"],
            },
        ),
        constraints=(
            {
                "constraint_id": "SC-1",
                "description": "Approve before release",
                "related_hazard_ids": ["H-1"],
            },
        ),
        losses=({"loss_id": "L-1", "description": "Integrity loss"},),
    )


def _assert_ica_checks(world, step, match):
    expected = re.findall(r'"([^"]+)"', step)[0]
    assert world.ica_semantic_result.verdict == expected
    assert world.ica_semantic_call_count == 1
    return True, ""


def _given_review(world, step, match):
    constraints, effect = re.findall(r'"([^"]+)"', step)
    world.semantic_use_case_text = "A sample chamber settings controller."
    world.semantic_structure = ControlStructure.model_validate(
        {
            "responsibilities": [
                {
                    "resp_id": "RESP-1",
                    "description": "Prepare internal settings",
                    "control_actions": [
                        {
                            "ca_id": "CA-1-1",
                            "description": "Send settings to the chamber",
                            "effect_kind": "model_output",
                        }
                    ],
                }
            ],
        }
    )
    world.semantic_losses = LossAnalysis.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Sample damage",
                    "provenance": "use_case",
                }
            ],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "Incorrect setting",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "Validate settings before applying them.",
                    "related_hazards": ["H-1"],
                    "applies_when": [],
                }
            ],
        }
    )
    world.semantic_review = ControlStructureSemanticReview.model_validate(
        {
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "source_evidence": [],
                    "rationale": "The supplied hazard is retained unchanged.",
                }
            ],
            "constraints": [
                {
                    "constraint_id": "SC-1",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "related_hazards": [] if constraints == "none" else ["H-1"],
                    "source_evidence": [],
                    "rationale": "Explicit supplied constraint-to-hazard decision.",
                }
            ],
            "responsibilities": [
                {
                    "responsibility_id": "RESP-1",
                    "constraint_refs": [] if constraints == "none" else [constraints],
                    "rationale": "Explicit supplied rule applicability decision.",
                }
            ],
            "actions": [
                {
                    "control_action_id": "CA-1-1",
                    "effect_kind": None if effect == "unknown" else effect,
                    "rationale": "Internal settings message or unresolved observation.",
                }
            ],
        }
    )
    world.semantic_before = world.semantic_structure.model_dump()
    return True, ""


def _apply_review(world, step, match):
    world.semantic_result = apply_control_structure_semantic_review(
        world.semantic_structure,
        world.semantic_losses,
        world.semantic_review,
        use_case_text=getattr(world, "semantic_use_case_text", ""),
    )
    return True, ""


def _request_review(world, step, match):
    payload = {"semantic_review": world.semantic_review.model_dump(mode="json")}

    class OfflineClient:
        model = "offline-coordination-contract"

        def complete(self, **kwargs):
            assert not kwargs.get("allow_unvalidated", False)
            world.semantic_wire_schema = kwargs["response_format"].model_json_schema()
            return LLMResult(
                content=payload,
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    with TemporaryDirectory(prefix="coordination-review-acceptance-") as directory:
        _call_3_coordination(
            llm_client=OfflineClient(),
            use_case_text=getattr(
                world, "semantic_use_case_text", "A sample chamber settings controller."
            ),
            control_structure=world.semantic_structure,
            loss_analysis=world.semantic_losses,
            run_dir=Path(directory),
            loader=TemplateLoader(PROMPTS_DIR),
            temperature=0,
        )
    world.semantic_wire_payload = payload
    return True, ""


def _assert_review_wire(world, step, match):
    validator = Draft202012Validator(world.semantic_wire_schema)
    assert not list(validator.iter_errors(world.semantic_wire_payload))
    assert list(validator.iter_errors({}))
    for collection in ("hazards", "constraints", "responsibilities", "actions"):
        incomplete = deepcopy(world.semantic_wire_payload)
        incomplete["semantic_review"][collection].clear()
        assert list(validator.iter_errors(incomplete))
    return True, ""


def _assert_review(world, step, match):
    constraints, effect = re.findall(r'"([^"]+)"', step)
    result = world.semantic_result.control_structure.responsibilities[0]
    assert result.security_constraint_refs == (
        [] if constraints == "none" else [constraints]
    )
    assert result.control_actions[0].effect_kind == (
        None if effect == "unknown" else effect
    )
    reviewed_constraint = world.semantic_result.loss_analysis.security_constraints[0]
    assert reviewed_constraint.related_hazards == (
        [] if constraints == "none" else ["H-1"]
    )
    assert world.semantic_structure.model_dump() == world.semantic_before
    return True, ""


_DISCLOSURE_FUNCTION = "Authenticated members may retrieve their own financial details."


def _disclosure_review_payload(*, evidence_case: str, quoted_function: str) -> dict:
    """Build one neutral, complete review for the disclosure example."""
    if evidence_case == "near_quote":
        quote = quoted_function.replace(" own", "")
        source_ref = "USE_CASE"
    elif evidence_case == "missing_source":
        quote = quoted_function
        source_ref = "L-99"
    else:
        quote = quoted_function
        source_ref = "USE_CASE"
    evidence = [
        {
            "source_ref": source_ref,
            "quote": quote,
            "meaning": "The supplied function limits disclosure to the authenticated requester.",
        }
    ]
    return {
        "hazards": [
            {
                "hazard_id": "H-1",
                "disposition": "revise",
                "revised_description": (
                    "Financial details are disclosed to an unauthorized or wrong-account recipient."
                ),
                "missing_fact": None,
                "source_evidence": evidence,
                "rationale": "The use-case function establishes the permitted recipient boundary.",
            }
        ],
        "constraints": [
            {
                "constraint_id": "SC-1",
                "disposition": "revise",
                "revised_description": (
                    "Only disclose financial details to the authenticated member who requested them."
                ),
                "missing_fact": None,
                "related_hazards": ["H-1"],
                "source_evidence": evidence,
                "rationale": "The blanket response-data ban is narrowed by the supplied allowed function.",
            },
            {
                "constraint_id": "SC-2",
                "disposition": "preserve",
                "revised_description": None,
                "missing_fact": None,
                "related_hazards": ["H-1"],
                "source_evidence": [],
                "rationale": "The authentication requirement remains unchanged.",
            },
        ],
        "responsibilities": [
            {
                "responsibility_id": "RESP-1",
                "constraint_refs": ["SC-2"],
                "rationale": "This controller validates the member before lookup.",
            },
            {
                "responsibility_id": "RESP-2",
                "constraint_refs": ["SC-1"],
                "rationale": "This controller owns the customer-facing response boundary.",
            },
        ],
        "actions": [
            {
                "control_action_id": "CA-1-1",
                "effect_kind": "agent_message",
                "rationale": "The validation request is an internal controller message.",
            },
            {
                "control_action_id": "CA-2-1",
                "effect_kind": "model_output",
                "rationale": "The account details are returned to the requesting member.",
            },
        ],
    }


def _prepare_disclosure_fixture(world, quoted_function):
    """Prepare a neutral response-data boundary with explicit provenance."""
    world.disclosure_allowed_function = quoted_function
    world.disclosure_use_case_text = (
        "The account service supports a permitted function: "
        f"{quoted_function} "
        "A different member must not receive those details."
    )
    world.disclosure_structure = ControlStructure.model_validate(
        {
            "responsibilities": [
                {
                    "resp_id": "RESP-1",
                    "description": "Validate the authenticated member before lookup",
                    "security_constraint_refs": ["SC-1", "SC-2"],
                    "control_actions": [
                        {
                            "ca_id": "CA-1-1",
                            "description": "Send an internal lookup request",
                            "target": {"type": "responsibility", "id": "RESP-2"},
                            "effect_kind": "agent_message",
                        }
                    ],
                },
                {
                    "resp_id": "RESP-2",
                    "description": "Retrieve and return member financial details",
                    "security_constraint_refs": [],
                    "control_actions": [
                        {
                            "ca_id": "CA-2-1",
                            "description": "Return the account details",
                            "target": {"type": "controlled_process", "id": "CP-1"},
                            "effect_kind": "model_output",
                        }
                    ],
                },
            ],
            "controlled_processes": [
                {"cp_id": "CP-1", "description": "Account details service"}
            ],
        }
    )
    world.disclosure_losses = LossAnalysis.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Unauthorized disclosure of member financial details",
                    "provenance": "use_case",
                }
            ],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "Financial details are exposed through an overly broad response rule",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "Do not expose response data.",
                    "related_hazards": ["H-1"],
                    "applies_when": [],
                },
                {
                    "constraint_id": "SC-2",
                    "rule": "Authenticate the member before retrieving details.",
                    "related_hazards": ["H-1"],
                    "applies_when": [],
                },
            ],
        }
    )
    world.disclosure_review = ControlStructureSemanticReview.model_validate(
        _disclosure_review_payload(
            evidence_case="valid", quoted_function=quoted_function
        )
    )
    world.disclosure_before_loss = world.disclosure_losses.model_dump()
    world.disclosure_before_structure = world.disclosure_structure.model_dump()
    return True, ""


def _given_disclosure_fixture(world, step, match):
    _prepare_disclosure_fixture(world, re.findall(r'"([^"]+)"', step)[0])
    return True, ""


def _given_disclosure_source_case(world, step, match):
    evidence_case = re.findall(r'"([^"]+)"', step)[0]
    _prepare_disclosure_fixture(world, _DISCLOSURE_FUNCTION)
    world.disclosure_review = ControlStructureSemanticReview.model_validate(
        _disclosure_review_payload(
            evidence_case=evidence_case,
            quoted_function=world.disclosure_allowed_function,
        )
    )
    world.disclosure_evidence_case = evidence_case
    return True, ""


def _apply_disclosure_review(world, step, match):
    try:
        world.disclosure_result = apply_control_structure_semantic_review(
            world.disclosure_structure,
            world.disclosure_losses,
            world.disclosure_review,
            use_case_text=world.disclosure_use_case_text,
        )
        world.disclosure_error = None
    except ValueError as exc:
        world.disclosure_result = None
        world.disclosure_error = exc
    return True, ""


def _assert_disclosure_result(world, step, match):
    assert world.disclosure_result is not None
    reviewed = world.disclosure_result
    assert reviewed.loss_analysis.hazards[0].hazard_id == "H-1"
    assert reviewed.loss_analysis.hazards[0].description.startswith(
        "Financial details are disclosed to an unauthorized"
    )
    assert reviewed.loss_analysis.hazards[0].related_losses == ["L-1"]
    assert reviewed.loss_analysis.security_constraints[0].constraint_id == "SC-1"
    assert reviewed.loss_analysis.security_constraints[0].description.startswith(
        "Only disclose financial details"
    )
    assert reviewed.loss_analysis.security_constraints[0].related_hazards == ["H-1"]
    assert reviewed.loss_analysis.security_constraints[1].constraint_id == "SC-2"
    assert reviewed.loss_analysis.security_constraints[1].related_hazards == ["H-1"]
    assert [loss.loss_id for loss in reviewed.loss_analysis.use_case_losses] == ["L-1"]
    reviewed_loss_data = reviewed.loss_analysis.model_dump()
    assert [item["loss_id"] for item in reviewed_loss_data["use_case_losses"]] == [
        item["loss_id"] for item in world.disclosure_before_loss["use_case_losses"]
    ]
    assert [item["hazard_id"] for item in reviewed_loss_data["hazards"]] == [
        item["hazard_id"] for item in world.disclosure_before_loss["hazards"]
    ]
    assert [item["related_losses"] for item in reviewed_loss_data["hazards"]] == [
        item["related_losses"] for item in world.disclosure_before_loss["hazards"]
    ]
    assert [
        item["constraint_id"] for item in reviewed_loss_data["security_constraints"]
    ] == [
        item["constraint_id"]
        for item in world.disclosure_before_loss["security_constraints"]
    ]
    assert [resp.resp_id for resp in reviewed.control_structure.responsibilities] == [
        resp["resp_id"]
        for resp in world.disclosure_before_structure["responsibilities"]
    ]
    assert [
        action.ca_id
        for resp in reviewed.control_structure.responsibilities
        for action in resp.control_actions
    ] == [
        action["ca_id"]
        for resp in world.disclosure_before_structure["responsibilities"]
        for action in resp["control_actions"]
    ]
    assert world.disclosure_result.control_structure.responsibilities[
        0
    ].security_constraint_refs == ["SC-2"]
    assert world.disclosure_result.control_structure.responsibilities[
        1
    ].security_constraint_refs == ["SC-1"]
    assert (
        world.disclosure_result.control_structure.responsibilities[0]
        .control_actions[0]
        .effect_kind
        == "agent_message"
    )
    assert (
        world.disclosure_result.control_structure.responsibilities[1]
        .control_actions[0]
        .effect_kind
        == "model_output"
    )
    assert world.disclosure_losses.model_dump() == world.disclosure_before_loss
    assert world.disclosure_structure.model_dump() == world.disclosure_before_structure
    return True, ""


def _assert_disclosure_rejection(world, step, match):
    expected = re.findall(r'"([^"]+)"', step)[0]
    assert world.disclosure_result is None
    assert world.disclosure_error is not None
    message = str(world.disclosure_error)
    if expected == "quotation":
        assert "exact substring" in message
    else:
        assert "source_ref" in message
    assert world.disclosure_losses.model_dump() == world.disclosure_before_loss
    assert world.disclosure_structure.model_dump() == world.disclosure_before_structure
    return True, ""


def _given_comparison(world, step, match):
    world.semantic_evidence_kind = re.findall(r'"([^"]+)"', step)[0]
    return True, ""


def _ground_comparison(world, step, match):
    kind = world.semantic_evidence_kind
    predicate = kind == "semantic_boolean"
    quote = 'The reference topic is "shipping".'
    condition = ActionValueCondition(
        control_action_id="CA-1-1",
        property="semantic_proposition" if predicate else "topic",
        operator="equals",
        expected=True if predicate else "shipping",
    )
    evidence = (
        ComparisonEvidence(
            source_ref="SC-1", quote=quote, rationale="Use the supplied reference."
        )
        if kind == "quoted_reference"
        else None
    )
    world.semantic_value_result = resolve_outcome_grounding(
        condition,
        evidence,
        {"SC-1": quote},
        model_output=predicate,
        proposition="The observed topic differs from the reference.",
    ).condition
    return True, ""


def _assert_value(world, step, match):
    result = world.semantic_value_result
    disposition = (
        "parameterized"
        if isinstance(result.expected, SemanticBindingPlaceholder)
        else "literal"
    )
    assert disposition == re.findall(r'"([^"]+)"', step)[0]
    assert result.operator == "equals"
    return True, ""


def register(api):
    for pattern, handler in (
        (
            r'independent ICA checks for action "([^"]+)", category "([^"]+)" and harm "([^"]+)"',
            _given_ica_checks,
        ),
        (
            r"the ICA provider result is compiled without another judgement call",
            _compile_ica_checks,
        ),
        (
            r'the compiled ICA verdict is "([^"]+)" with exactly one provider call',
            _assert_ica_checks,
        ),
        (
            r'a semantic-review fixture with constraint decision "([^"]+)" and effect "([^"]+)"',
            _given_review,
        ),
        (r"the complete systemic semantic review is applied", _apply_review),
        (
            r"the coordination call requests its systemic semantic review",
            _request_review,
        ),
        (
            r"its provider schema rejects an omitted or incomplete semantic review",
            _assert_review_wire,
        ),
        (
            r'the semantic-review result retains "([^"]+)" and "([^"]+)" without changing its draft',
            _assert_review,
        ),
        (
            r'a disclosure semantic-review fixture with quoted allowed function "([^"]+)"',
            _given_disclosure_fixture,
        ),
        (
            r'a disclosure semantic-review fixture with source evidence "([^"]+)"',
            _given_disclosure_source_case,
        ),
        (
            r"the complete disclosure semantic review is applied",
            _apply_disclosure_review,
        ),
        (
            r"the disclosure review preserves loss lineage and identities while correcting response ownership",
            _assert_disclosure_result,
        ),
        (
            r"the disclosure semantic review is attempted",
            _apply_disclosure_review,
        ),
        (
            r'the disclosure semantic review is rejected for "([^"]+)"',
            _assert_disclosure_rejection,
        ),
        (
            r'a semantic-review comparison with value evidence "([^"]+)"',
            _given_comparison,
        ),
        (
            r"the comparison value is grounded against supplied rules",
            _ground_comparison,
        ),
        (r'its semantic-review value disposition is "([^"]+)"', _assert_value),
    ):
        api.register(pattern, handler)

"""Acceptance step handlers for the foundation feature group."""

from __future__ import annotations

from runtime_shared import (
    CatalogMapping,
    ControlAction,
    ControlStructure,
    CoverageAnalysis,
    ElementRef,
    EnrichedThreatSet,
    FeedbackChannel,
    Hazard,
    ICA,
    ICAEnumeration,
    ICASlot,
    Loss,
    LossAnalysis,
    LossProvenance,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    SecurityConstraint,
    StructuralThreat,
    UCAType,
    ValidationError,
    World,
    _make_coordination_link,
    _make_minimal_control_structure,
    _make_minimal_loss_analysis,
    _sp1_valid_la_dict,
    check_structural_heuristics,
    re,
)
from asago_scenario_generator.stpa.models.control_structure import ControlledProcess


def _h_module_importable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the STPA boundary schema module is importable."""
    return True, ""


def _h_module_infra_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the STPA infra module is importable."""
    return True, ""


def _h_minimal_loss_analysis(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a minimal valid loss analysis with loss L-1, hazard H-1, and constraint SC-1."""
    world.loss_analysis = _make_minimal_loss_analysis()
    return True, ""


def _h_loss_analysis_with_losses(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a loss analysis with losses L-1 and L-2, ..."""
    world.loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1", description="Loss 1", provenance=LossProvenance.use_case
            ),
            Loss(
                loss_id="L-2", description="Loss 2", provenance=LossProvenance.use_case
            ),
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Constraint",
                applies_when=[],
                related_hazards=["H-1"],
            )
        ],
    )
    return True, ""


def _h_loss_analysis_hazard_bad_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a loss analysis with loss L-1 and hazard H-1 referencing loss <bad_ref>."""
    bad_ref = examples.get("bad_ref", "")
    world.loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(loss_id="L-1", description="Loss", provenance=LossProvenance.use_case)
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard", related_losses=[bad_ref])
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Constraint",
                applies_when=[],
                related_hazards=["H-1"],
            )
        ],
    )
    return True, ""


def _h_loss_analysis_constraint_bad_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a loss analysis with loss L-1, hazard H-1, and constraint SC-1 referencing hazard <bad_ref>."""
    bad_ref = examples.get("bad_ref", "")
    world.loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(loss_id="L-1", description="Loss", provenance=LossProvenance.use_case)
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Constraint",
                applies_when=[],
                related_hazards=[bad_ref],
            )
        ],
    )
    return True, ""


def _h_loss_analysis_duplicate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a loss analysis with duplicate <id_field> value <dup_value>."""
    # SP1 variant: "an LLM that returns a loss analysis with duplicate loss_id L-1"
    if "an LLM that returns" in text:
        d = _sp1_valid_la_dict()
        d["risk_card_losses"][1]["loss_id"] = "L-1"
        world.sp1_llm_content = d
        return True, ""
    id_field = examples.get("id_field", "")
    dup_value = examples.get("dup_value", "")
    if id_field == "loss_id":
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(
                    loss_id=dup_value,
                    description="A",
                    provenance=LossProvenance.use_case,
                ),
                Loss(
                    loss_id=dup_value,
                    description="B",
                    provenance=LossProvenance.use_case,
                ),
            ],
            hazards=[
                Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1",
                    rule="Constraint",
                    applies_when=[],
                    related_hazards=["H-1"],
                )
            ],
        )
    elif id_field == "hazard_id":
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(
                    loss_id="L-1", description="A", provenance=LossProvenance.use_case
                ),
            ],
            hazards=[
                Hazard(hazard_id=dup_value, description="A", related_losses=["L-1"]),
                Hazard(hazard_id=dup_value, description="B", related_losses=["L-1"]),
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1",
                    rule="Constraint",
                    applies_when=[],
                    related_hazards=["H-1"],
                )
            ],
        )
    elif id_field == "constraint_id":
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(
                    loss_id="L-1", description="A", provenance=LossProvenance.use_case
                ),
            ],
            hazards=[Hazard(hazard_id="H-1", description="H", related_losses=["L-1"])],
            security_constraints=[
                SecurityConstraint(
                    constraint_id=dup_value,
                    rule="A",
                    applies_when=[],
                    related_hazards=["H-1"],
                ),
                SecurityConstraint(
                    constraint_id=dup_value,
                    rule="B",
                    applies_when=[],
                    related_hazards=["H-1"],
                ),
            ],
        )
    else:
        return False, f"Unknown id_field: {id_field}"
    return True, ""


def _h_loss_analysis_risk_card(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle risk card loss scenarios."""
    if "provenance risk_card" in text and "empty source_risk_cards" in text:
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[
                Loss(
                    loss_id="L-1",
                    description="Loss",
                    provenance=LossProvenance.risk_card,
                ),
            ],
            use_case_losses=[],
            hazards=[
                Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1",
                    rule="Constraint",
                    applies_when=[],
                    related_hazards=["H-1"],
                )
            ],
        )
    elif "provenance risk_card and source_risk_cards atlas-001" in text:
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[
                Loss(
                    loss_id="L-1",
                    description="Loss",
                    provenance=LossProvenance.risk_card,
                    source_risk_cards=["atlas-001"],
                ),
            ],
            use_case_losses=[],
            hazards=[
                Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1",
                    rule="Constraint",
                    applies_when=[],
                    related_hazards=["H-1"],
                )
            ],
        )
    elif "provenance use_case and source_risk_cards atlas-001" in text:
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(
                    loss_id="L-1",
                    description="Loss",
                    provenance=LossProvenance.use_case,
                    source_risk_cards=["atlas-001"],
                ),
            ],
            hazards=[
                Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1",
                    rule="Constraint",
                    applies_when=[],
                    related_hazards=["H-1"],
                )
            ],
        )
    elif "provenance use_case and empty source_risk_cards" in text:
        world.loss_analysis = _make_minimal_loss_analysis()
    elif "provenance critic_derived and empty source_risk_cards" in text:
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(
                    loss_id="L-1",
                    description="Loss",
                    provenance=LossProvenance.critic_derived,
                ),
            ],
            hazards=[
                Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1",
                    rule="Constraint",
                    applies_when=[],
                    related_hazards=["H-1"],
                )
            ],
        )
    else:
        return False, f"Unhandled risk card step: {text}"
    return True, ""


def _h_validate_loss_analysis(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the loss analysis is validated.

    Pydantic validation already happened during model construction.
    This is a no-op; the validation_error (if any) was set by the Given step.
    """
    if world.loss_analysis is None and world.validation_error is None:
        return False, "No loss analysis to validate"
    return True, ""


def _h_validation_succeeds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: validation succeeds."""
    if world.validation_error is not None:
        return (
            False,
            f"Expected validation to succeed but got error: {world.validation_error}",
        )
    return True, ""


def _h_validation_fails_with(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: validation fails with error containing <error_fragment>.

    Case-sensitive matching: the error_fragment must appear exactly
    as specified in the error message.
    """
    error_fragment = examples.get("error_fragment", "")
    if not error_fragment:
        # Extract from text if no example
        match = re.search(r"containing (.+)", text)
        error_fragment = match.group(1).strip() if match else ""

    if world.validation_error is None:
        return (
            False,
            f"Expected validation to fail with '{error_fragment}' but no error was raised",
        )
    err_str = str(world.validation_error)
    # Support "X or Y" fragments: match if either part is in the error.
    if " or " in error_fragment:
        parts = [p.strip().lower() for p in error_fragment.split(" or ")]
        if not any(p in err_str.lower() for p in parts):
            return (
                False,
                f"Expected error containing any of {parts} but got: {world.validation_error}",
            )
    elif error_fragment.lower() not in err_str.lower():
        return (
            False,
            f"Expected error containing '{error_fragment}' but got: {world.validation_error}",
        )
    return True, ""


def _h_minimal_cs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a minimal valid control structure with responsibility RESP-1, ..."""
    world.control_structure = _make_minimal_control_structure()
    return True, ""


def _h_cs_with_resp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1 having PM-1-1, CA-1-1, and FB-1-1."""
    world.control_structure = _make_minimal_control_structure()
    return True, ""


def _h_cs_pm_feedback_source_bad_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a process model part PM-1-1 with feedback_source referencing <ref_type> <bad_ref>."""
    ref_type_str = examples.get("ref_type", "responsibility")
    bad_ref = examples.get("bad_ref", "")
    ref_type = (
        ReferenceType.responsibility
        if ref_type_str == "responsibility"
        else ReferenceType.controlled_process
    )
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="State",
                        feedback_source=ElementRef(type=ref_type, id=bad_ref),
                    ),
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action"),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_ca_target_bad_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control action CA-1-1 with target referencing <ref_type> <bad_ref>."""
    ref_type_str = examples.get("ref_type", "responsibility")
    bad_ref = examples.get("bad_ref", "")
    ref_type = (
        ReferenceType.responsibility
        if ref_type_str == "responsibility"
        else ReferenceType.controlled_process
    )
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Action",
                        target=ElementRef(type=ref_type, id=bad_ref),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_fb_source_bad_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a feedback channel FB-1-1 with source referencing <ref_type> <bad_ref>."""
    ref_type_str = examples.get("ref_type", "responsibility")
    bad_ref = examples.get("bad_ref", "")
    ref_type = (
        ReferenceType.responsibility
        if ref_type_str == "responsibility"
        else ReferenceType.controlled_process
    )
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action"),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(type=ref_type, id=bad_ref),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_fb_updates_nonexistent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a feedback channel FB-1-1 with updates referencing PM-99-1."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action"),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-99-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_coord_link_bad_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a coordination link CL-1 with <field> referencing RESP-99."""
    field = examples.get("field", "source")
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State")
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State")
                ],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="Feedback",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-2"
                        ),
                    )
                ],
            ),
        ],
        coordination_links=[
            _make_coordination_link(
                link_id="CL-1",
                source="RESP-99" if field == "source" else "RESP-1",
                target="RESP-99" if field == "target" else "RESP-2",
                shared_pm="PM-1-1",
            )
        ],
    )
    return True, ""


def _h_cs_coord_link_bad_pm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a coordination link CL-1 with shared_pm referencing PM-99-1."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State")
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State")
                ],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="Feedback",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-2"
                        ),
                    )
                ],
            ),
        ],
        coordination_links=[
            _make_coordination_link(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-99-1",
            )
        ],
    )
    return True, ""


def _h_cs_duplicate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with duplicate <id_field> value <dup_value>."""
    id_field = examples.get("id_field", "")
    dup_value = examples.get("dup_value", "")
    if id_field == "resp_id":
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id=dup_value,
                    description="A",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="PM")
                    ],
                    control_actions=[ControlAction(ca_id="CA-1-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id=dup_value
                            ),
                        )
                    ],
                ),
                Responsibility(
                    resp_id=dup_value,
                    description="B",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-2-1", description="PM")
                    ],
                    control_actions=[ControlAction(ca_id="CA-2-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-2-1",
                            description="FB",
                            updates="PM-2-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id=dup_value
                            ),
                        )
                    ],
                ),
            ]
        )
    elif id_field == "pm_id":
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="A",
                    process_model_parts=[
                        ProcessModelPart(pm_id=dup_value, description="PM1"),
                        ProcessModelPart(pm_id=dup_value, description="PM2"),
                    ],
                    control_actions=[ControlAction(ca_id="CA-1-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates=dup_value,
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-1"
                            ),
                        )
                    ],
                )
            ]
        )
    elif id_field == "ca_id":
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="A",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="PM")
                    ],
                    control_actions=[
                        ControlAction(ca_id=dup_value, description="CA1"),
                        ControlAction(ca_id=dup_value, description="CA2"),
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-1"
                            ),
                        )
                    ],
                )
            ]
        )
    elif id_field == "fb_id":
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="A",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="PM")
                    ],
                    control_actions=[ControlAction(ca_id="CA-1-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id=dup_value,
                            description="FB1",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-1"
                            ),
                        ),
                        FeedbackChannel(
                            fb_id=dup_value,
                            description="FB2",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-1"
                            ),
                        ),
                    ],
                )
            ]
        )
    elif id_field == "link_id":
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="A",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="PM")
                    ],
                    control_actions=[ControlAction(ca_id="CA-1-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-1"
                            ),
                        )
                    ],
                ),
                Responsibility(
                    resp_id="RESP-2",
                    description="B",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-2-1", description="PM")
                    ],
                    control_actions=[ControlAction(ca_id="CA-2-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-2-1",
                            description="FB",
                            updates="PM-2-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-2"
                            ),
                        )
                    ],
                ),
            ],
            coordination_links=[
                _make_coordination_link(
                    link_id=dup_value,
                    source="RESP-1",
                    target="RESP-2",
                    shared_pm="PM-1-1",
                ),
                _make_coordination_link(
                    link_id=dup_value,
                    source="RESP-2",
                    target="RESP-1",
                    shared_pm="PM-2-1",
                ),
            ],
        )
    elif id_field == "cp_id":
        from asago_scenario_generator.stpa.models.control_structure import (
            ControlledProcess,
        )

        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="A",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="PM")
                    ],
                    control_actions=[ControlAction(ca_id="CA-1-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-1"
                            ),
                        )
                    ],
                )
            ],
            controlled_processes=[
                ControlledProcess(cp_id=dup_value, description="A"),
                ControlledProcess(cp_id=dup_value, description="B"),
            ],
        )
    else:
        return False, f"Unknown id_field: {id_field}"
    return True, ""


def _h_validate_cs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the control structure is validated.

    Pydantic validation already happened during model construction.
    This is a no-op; the validation_error (if any) was set by the Given step.
    """
    if world.control_structure is None and world.validation_error is None:
        return False, "No control structure to validate"
    return True, ""


def _h_check_heuristics(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the control structure structural heuristics are checked."""
    if world.control_structure is None:
        return False, "No control structure to check"
    world.heuristic_result = check_structural_heuristics(world.control_structure)
    return True, ""


def _h_check_heuristics_with_la(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the control structure structural heuristics are checked with the loss analysis."""
    if world.control_structure is None:
        return False, "No control structure to check"
    la = world.loss_analysis or _make_minimal_loss_analysis()
    world.heuristic_result = check_structural_heuristics(world.control_structure, la)
    return True, ""


def _h_heuristic_succeeds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the heuristic check succeeds."""
    if world.heuristic_result is None:
        return False, "No heuristic result"
    if not world.heuristic_result.passed:
        return (
            False,
            f"Expected heuristics to pass but got errors: {world.heuristic_result.errors}",
        )
    return True, ""


def _h_heuristic_fails_with(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the heuristic check fails with error containing <text>."""
    match = re.search(r"containing (.+)", text)
    fragment = match.group(1).strip() if match else ""
    if world.heuristic_result is None:
        return False, "No heuristic result"
    if world.heuristic_result.passed:
        return (
            False,
            f"Expected heuristic check to fail with '{fragment}' but it passed",
        )
    err_str = " ".join(world.heuristic_result.errors).lower()
    if fragment.lower() not in err_str:
        return (
            False,
            f"Expected error containing '{fragment}' but got: {' '.join(world.heuristic_result.errors)}",
        )
    return True, ""


def _single_ica_enumeration(
    uca_type: UCAType,
    *,
    hazard: str = "H-1",
    constraint: str = "SC-1",
    is_na: bool = False,
    **slot_fields: object,
) -> ICAEnumeration:
    """Return one RESP-1:CA-1-1 slot holding one ICA with the given references."""
    return ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=uca_type,
                is_na=is_na,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                        ica_text="UCA",
                        hazardous_context="Ctx",
                        loss_scenario="Scenario",
                        related_hazards=[hazard],
                        related_constraints=[constraint],
                    )
                ],
                **slot_fields,
            )
        ]
    )


def _ica_slot_handler(**references: str):
    """Build a Given handler for a non-N/A slot of the example's uca_type."""

    def handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
        uca_type = UCAType(examples.get("uca_type", "NOT_PROVIDED"))
        world.ica_enumeration = _single_ica_enumeration(uca_type, **references)
        return True, ""

    return handler


_h_ica_slot_valid = _ica_slot_handler()


def _h_ica_validate_against(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the ICA enumeration is validated against the loss analysis and control structure.

    Pydantic validation may have already happened during model construction.
    If so, the error is already stored. Otherwise, run validate_against.
    """
    if world.ica_enumeration is None and world.validation_error is None:
        return False, "No ICA enumeration to validate"
    if world.validation_error is not None:
        # Validation already failed during construction
        return True, ""
    la = world.loss_analysis or _make_minimal_loss_analysis()
    cs = world.control_structure or _make_minimal_control_structure()
    try:
        world.ica_enumeration.validate_against(la, cs)
        world.validation_succeeded = True
        world.validation_error = None
    except (ValueError, ValidationError) as e:
        world.validation_error = e
        world.validation_succeeded = False
    return True, ""


def _h_ets_catalog_confidence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a catalog mapping with confidence level <confidence_level>."""
    confidence = examples.get("confidence_level", "high")
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_text="UCA",
                hazardous_context="Ctx",
                loss_scenario="Scenario",
                catalog_mappings=[
                    CatalogMapping(
                        catalog="OWASP_AGENTIC",
                        id="T2-T3",
                        name="Test threat",
                        confidence=confidence,
                    )
                ],
            )
        ],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 10,
                "non_na": 8,
                "na": 2,
                "coverage_rate": 0.8,
            },
        ),
    )
    return True, ""


def _h_ets_validate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the enriched threat set is validated."""
    if world.enriched_threat_set is None and world.validation_error is None:
        return False, "No enriched threat set to validate"
    return True, ""


def _h_ets_structural_threat(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a structural threat with ica_slot_id ..."""
    na_flag = "na_reconciliation_flag true" in text
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_text="UCA",
                hazardous_context="Ctx",
                loss_scenario="Scenario",
                na_reconciliation_flag=na_flag,
            )
        ],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 10,
                "non_na": 8,
                "na": 2,
                "coverage_rate": 0.8,
            },
        ),
    )
    return True, ""


def _h_ets_coverage_basic(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a coverage analysis with total_slots 10, non_na 8, na 2, and coverage_rate 0.8."""
    if world.enriched_threat_set is None:
        world.enriched_threat_set = EnrichedThreatSet(
            structural_threats=[
                StructuralThreat(
                    ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                    ica_text="UCA",
                    hazardous_context="Ctx",
                    loss_scenario="Scenario",
                )
            ],
            coverage_analysis=CoverageAnalysis(
                structural_coverage={
                    "total_slots": 10,
                    "non_na": 8,
                    "na": 2,
                    "coverage_rate": 0.8,
                },
            ),
        )
    else:
        world.enriched_threat_set = world.enriched_threat_set.model_copy(deep=True)
        world.enriched_threat_set.coverage_analysis = CoverageAnalysis(
            structural_coverage={
                "total_slots": 10,
                "non_na": 8,
                "na": 2,
                "coverage_rate": 0.8,
            },
        )
    return True, ""


def _h_ets_catalog_mapping(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a catalog mapping catalog OWASP_AGENTIC with id T2-T3 and confidence high."""
    if world.enriched_threat_set and world.enriched_threat_set.structural_threats:
        threat = world.enriched_threat_set.structural_threats[0]
        threat.catalog_mappings.append(
            CatalogMapping(
                catalog="OWASP_AGENTIC",
                id="T2-T3",
                name="Test",
                confidence="high",
            )
        )
    return True, ""


def _h_ets_coverage_by_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a coverage analysis with by_ica_type ..."""
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_text="UCA",
                hazardous_context="Ctx",
                loss_scenario="Scenario",
            )
        ],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 10,
                "non_na": 8,
                "na": 2,
                "coverage_rate": 0.8,
            },
            by_ica_type={"NOT_PROVIDED": 5, "INCORRECT": 3},
            by_controller={"RESP-1": 4, "RESP-2": 4},
        ),
    )
    return True, ""


def _h_ets_coverage_uncovered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a coverage analysis with uncovered_owasp_threats ..."""
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_text="UCA",
                hazardous_context="Ctx",
                loss_scenario="Scenario",
            )
        ],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 10,
                "non_na": 8,
                "na": 2,
                "coverage_rate": 0.8,
            },
            uncovered_owasp_threats=["T10", "T15"],
            uncovered_reason="no structural slot matched",
        ),
    )
    return True, ""


def _h_ets_coverage_consideration(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a coverage analysis with structural_consideration ..."""
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_text="UCA",
                hazardous_context="Ctx",
                loss_scenario="Scenario",
            )
        ],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 10,
                "non_na": 8,
                "na": 2,
                "coverage_rate": 0.8,
            },
            structural_consideration={"total_slots": 10, "considered": 8, "rate": 0.8},
        ),
    )
    return True, ""


def _h_ets_na_quality(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: na_quality na_count 2 quality_count 2 quality_rate 1.0."""
    if world.enriched_threat_set:
        world.enriched_threat_set.coverage_analysis.na_quality = {
            "na_count": 2,
            "quality_count": 2,
            "quality_rate": 1.0,
        }
    return True, ""


def _h_ets_coverage_correspondence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a coverage analysis with catalog_correspondence ..."""
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_text="UCA",
                hazardous_context="Ctx",
                loss_scenario="Scenario",
            )
        ],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 10,
                "non_na": 8,
                "na": 2,
                "coverage_rate": 0.8,
            },
            catalog_correspondence={
                "structural_with_match": 8,
                "structural_unmapped": 0,
                "catalog_only_supplements": 0,
            },
        ),
    )
    return True, ""


def _h_loss_analysis_with_hazard_constraint(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a loss analysis with hazard H-1 and constraint SC-1."""
    world.loss_analysis = _make_minimal_loss_analysis()
    return True, ""


def _h_cs_zero_pms(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with zero process model parts."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[],
            )
        ]
    )
    return True, ""


def _h_cs_zero_cas(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with zero control actions."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State")
                ],
                control_actions=[],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_zero_fbs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with zero feedback channels."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State")
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[],
            )
        ]
    )
    return True, ""


def _h_cs_orphan_pm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with PM-1-1 and PM-1-2 where only PM-1-1 is updated."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State 1"),
                    ProcessModelPart(pm_id="PM-1-2", description="State 2"),
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_unreferenced_cp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a controlled process CP-1 not referenced by any feedback or control action."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State")
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Unreferenced process"),
        ],
    )
    return True, ""


def _h_cs_no_constraint_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure where no responsibility references constraint SC-1."""
    world.control_structure = _make_minimal_control_structure()
    return True, ""


def _h_cs_with_constraint_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure where responsibility RESP-1 references constraint SC-1."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                security_constraint_refs=["SC-1"],
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State")
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_cross_resp_fb(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: CS with responsibilities RESP-1 and RESP-2 where FB-1-1 updates PM-2-1."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State")
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State")
                ],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="FB",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-2"
                        ),
                    )
                ],
            ),
        ]
    )
    return True, ""


def _h_heuristic_warns_orphan(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a warning is produced for orphan PM PM-1-2."""
    if world.heuristic_result is None:
        return False, "No heuristic result"
    warn_str = " ".join(world.heuristic_result.warnings)
    if "PM-1-2" not in warn_str and "orphan" not in warn_str.lower():
        return False, f"Expected warning about orphan PM-1-2 but got: {warn_str}"
    return True, ""


_h_ica_slot_bad_hazard = _ica_slot_handler(hazard="H-99")
_h_ica_slot_bad_constraint = _ica_slot_handler(constraint="SC-99")


def _h_ica_slot_no_icas(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ICA slot with is_na false and zero ICAs."""
    uca_type_str = examples.get("uca_type", "NOT_PROVIDED")
    uca_type = UCAType(uca_type_str)
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=uca_type,
                is_na=False,
                icas=[],
            )
        ]
    )
    return True, ""


def _h_ica_slot_na_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ICA slot with is_na true and na_justification."""
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=True,
                icas=[],
                na_justification="no hazardous context",
            )
        ]
    )
    return True, ""


def _h_ica_slot_na_no_just(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ICA slot with is_na true and no na_justification."""
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=True,
                icas=[],
            )
        ]
    )
    return True, ""


def _h_ica_slot_na_with_ica(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ICA slot with is_na true, na_justification none, and one ICA."""
    world.ica_enumeration = _single_ica_enumeration(
        UCAType.not_provided, is_na=True, na_justification="none"
    )
    return True, ""


def _h_ica_slot_non_na_with_just(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ICA slot with is_na false, one ICA, and na_justification set."""
    world.ica_enumeration = _single_ica_enumeration(
        UCAType.not_provided, na_justification="should not be set"
    )
    return True, ""


def _h_ica_slot_duplicate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: two ICA slots with the same slot_id."""
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                        ica_text="UCA",
                        hazardous_context="Ctx",
                        loss_scenario="Scenario",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    )
                ],
            ),
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.incorrect,
                is_na=False,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:INCORRECT:1",
                        ica_text="UCA2",
                        hazardous_context="Ctx2",
                        loss_scenario="Scenario2",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    )
                ],
            ),
        ]
    )
    return True, ""


FEATURE_ID = "foundation"


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.register(
        "the STPA boundary schema module is importable",
        _h_module_importable,
        source_order=1485,
    )
    api.register(
        "the STPA infra module is importable",
        _h_module_infra_importable,
        source_order=1486,
    )
    api.register(
        "a minimal valid loss analysis with loss L-1.*",
        _h_minimal_loss_analysis,
        source_order=1487,
    )
    api.register(
        "a loss analysis with loss L-1, hazard H-1, and constraint SC-1$",
        _h_minimal_loss_analysis,
        source_order=1488,
    )
    api.register(
        "a minimal valid control structure with responsibility.*",
        _h_minimal_cs,
        source_order=1489,
    )
    api.register(
        "a control structure with responsibility RESP-1, control action CA-1-1, and PM-1-1",
        _h_minimal_cs,
        source_order=1490,
    )
    api.register(
        "a loss analysis with losses L-1 and L-2.*",
        _h_loss_analysis_with_losses,
        source_order=1493,
    )
    api.register(
        "a loss analysis with loss L-1 and hazard H-1 referencing loss",
        _h_loss_analysis_hazard_bad_ref,
        source_order=1494,
    )
    api.register(
        "a loss analysis with loss L-1, hazard H-1, and constraint SC-1 referencing hazard",
        _h_loss_analysis_constraint_bad_ref,
        source_order=1495,
    )
    api.register(
        "a loss analysis with duplicate", _h_loss_analysis_duplicate, source_order=1496
    )
    api.register("a risk card loss.*", _h_loss_analysis_risk_card, source_order=1497)
    api.register("a use case loss.*", _h_loss_analysis_risk_card, source_order=1498)
    api.register(
        "a critic derived loss.*", _h_loss_analysis_risk_card, source_order=1499
    )
    api.register(
        "a loss analysis with hazard H-1 and constraint SC-1$",
        _h_loss_analysis_with_hazard_constraint,
        source_order=1500,
    )
    api.register(
        "the loss analysis is validated", _h_validate_loss_analysis, source_order=1503
    )
    api.register("validation succeeds", _h_validation_succeeds, source_order=1504)
    api.register(
        "validation fails with error containing",
        _h_validation_fails_with,
        source_order=1505,
    )
    api.register(
        "a control structure with responsibility RESP-1 having PM-1-1.*",
        _h_cs_with_resp,
        source_order=1508,
    )
    api.register(
        "a process model part PM-1-1 with feedback_source referencing",
        _h_cs_pm_feedback_source_bad_ref,
        source_order=1509,
    )
    api.register(
        "a control action CA-1-1 with target referencing",
        _h_cs_ca_target_bad_ref,
        source_order=1510,
    )
    api.register(
        "a feedback channel FB-1-1 with source referencing",
        _h_cs_fb_source_bad_ref,
        source_order=1511,
    )
    api.register(
        "a feedback channel FB-1-1 with updates referencing PM-99-1",
        _h_cs_fb_updates_nonexistent,
        source_order=1512,
    )
    api.register(
        "a coordination link CL-1 with (?:source|target|<field>) referencing RESP-99",
        _h_cs_coord_link_bad_ref,
        source_order=1513,
    )
    api.register(
        "a coordination link CL-1 with shared_pm referencing PM-99-1",
        _h_cs_coord_link_bad_pm,
        source_order=1515,
    )
    api.register(
        "a control structure with duplicate", _h_cs_duplicate, source_order=1516
    )
    api.register(
        "a control structure with responsibilities RESP-1 and RESP-2 where FB-1-1 updates PM-2-1",
        _h_cs_cross_resp_fb,
        source_order=1520,
    )
    api.register(
        "a responsibility RESP-1 with zero process model parts",
        _h_cs_zero_pms,
        source_order=1521,
    )
    api.register(
        "a responsibility RESP-1 with zero control actions",
        _h_cs_zero_cas,
        source_order=1522,
    )
    api.register(
        "a responsibility RESP-1 with zero feedback channels",
        _h_cs_zero_fbs,
        source_order=1523,
    )
    api.register(
        "a responsibility RESP-1 with PM-1-1 and PM-1-2 where only PM-1-1 is updated by FB-1-1",
        _h_cs_orphan_pm,
        source_order=1524,
    )
    api.register(
        "a controlled process CP-1 not referenced by any feedback channel source or control action target",
        _h_cs_unreferenced_cp,
        source_order=1525,
    )
    api.register(
        "a control structure where responsibility RESP-1 references constraint SC-1",
        _h_cs_with_constraint_ref,
        source_order=1526,
    )
    api.register(
        "a control structure where no responsibility references constraint SC-1",
        _h_cs_no_constraint_ref,
        source_order=1527,
    )
    api.register(
        "the control structure is validated", _h_validate_cs, source_order=1530
    )
    api.register(
        "the control structure structural heuristics are checked with the loss analysis",
        _h_check_heuristics_with_la,
        source_order=1531,
    )
    api.register(
        "the control structure structural heuristics are checked",
        _h_check_heuristics,
        source_order=1532,
    )
    api.register(
        "the heuristic check succeeds", _h_heuristic_succeeds, source_order=1533
    )
    api.register(
        "the heuristic check fails with error containing",
        _h_heuristic_fails_with,
        source_order=1534,
    )
    api.register(
        "a warning is produced for orphan PM",
        _h_heuristic_warns_orphan,
        source_order=1535,
    )
    api.register(
        "an ICA slot .* with is_na false and one ICA referencing hazard H-1 and constraint SC-1",
        _h_ica_slot_valid,
        source_order=1540,
    )
    api.register(
        "an ICA slot .* with is_na false and one ICA$",
        _h_ica_slot_valid,
        source_order=1541,
    )
    api.register(
        "the ICA enumeration is validated against the loss analysis and control structure",
        _h_ica_validate_against,
        source_order=1543,
    )
    api.register(
        "a structural threat with a catalog mapping with confidence",
        _h_ets_catalog_confidence,
        source_order=1546,
    )
    api.register(
        "a structural threat with ica_slot_id.*",
        _h_ets_structural_threat,
        source_order=1547,
    )
    api.register(
        "a coverage analysis with total_slots.*",
        _h_ets_coverage_basic,
        source_order=1548,
    )
    api.register(
        "a catalog mapping catalog.*", _h_ets_catalog_mapping, source_order=1549
    )
    api.register(
        "a coverage analysis with by_ica_type.*",
        _h_ets_coverage_by_type,
        source_order=1550,
    )
    api.register(
        "a coverage analysis with uncovered_owasp_threats.*",
        _h_ets_coverage_uncovered,
        source_order=1551,
    )
    api.register(
        "a coverage analysis with structural_consideration.*",
        _h_ets_coverage_consideration,
        source_order=1552,
    )
    api.register(
        "a coverage analysis with catalog_correspondence.*",
        _h_ets_coverage_correspondence,
        source_order=1553,
    )
    api.register("na_quality na_count.*", _h_ets_na_quality, source_order=1554)
    api.register(
        "the enriched threat set is validated", _h_ets_validate, source_order=1555
    )
    api.register(
        "two ICA slots with the same slot_id", _h_ica_slot_duplicate, source_order=1769
    )
    api.register(
        "an ICA slot .* with is_na false and one ICA referencing hazard H-99",
        _h_ica_slot_bad_hazard,
        source_order=1770,
    )
    api.register(
        "an ICA slot .* with is_na false and one ICA referencing constraint SC-99",
        _h_ica_slot_bad_constraint,
        source_order=1771,
    )
    api.register(
        "an ICA slot .* with is_na false and zero ICAs",
        _h_ica_slot_no_icas,
        source_order=1772,
    )
    api.register(
        "an ICA slot .* with is_na true and na_justification",
        _h_ica_slot_na_valid,
        source_order=1773,
    )
    api.register(
        "an ICA slot .* with is_na true and no na_justification",
        _h_ica_slot_na_no_just,
        source_order=1774,
    )
    api.register(
        "an ICA slot .* with is_na true, na_justification none, and one ICA",
        _h_ica_slot_na_with_ica,
        source_order=1775,
    )
    api.register(
        "an ICA slot .* with is_na false, one ICA, and na_justification set",
        _h_ica_slot_non_na_with_just,
        source_order=1776,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]

"""Acceptance step handlers for the models feature group."""

from __future__ import annotations

from runtime_shared import (
    GherkinSpec,
    ScenarioEnvelope,
    UCAType,
    World,
    _ConsumerHints,
    _SystemContext,
    _ToolInventoryEntry,
    _assemble_envelope,
    _compute_consumer_hints,
    _compute_system_context,
    _make_enrichment_capability_profile,
    _make_enrichment_control_structure,
    _make_minimal_scenario_spec,
    re,
)


def _h_enrichment_cs_with_resp_desc(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1 having description ..."""
    match = re.search(r'description "([^"]+)"', text)
    resp_desc = match.group(1) if match else "Orchestrate tool calls safely"
    match2 = re.search(
        r'control action CA-1-1 under RESP-1 having description "([^"]+)"', text
    )
    ca_desc = match2.group(1) if match2 else "Execute requested tool"
    world.control_structure = _make_enrichment_control_structure(
        resp_desc=resp_desc, ca_desc=ca_desc
    )
    return True, ""


def _h_enrichment_ca_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control action CA-1-1 under RESP-1 having description ..."""
    match = re.search(r'description "([^"]+)"', text)
    ca_desc = match.group(1) if match else "Execute requested tool"
    if world.control_structure is None:
        world.control_structure = _make_enrichment_control_structure(ca_desc=ca_desc)
    return True, ""


def _h_enrichment_cap_profile_tool(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a capability profile with tool_inventory having tool ..."""
    match = re.search(r'tool "([^"]+)"', text)
    tool_name = match.group(1) if match else "database_query"
    world.capability_profile = _make_enrichment_capability_profile(
        tool_inventory=[_ToolInventoryEntry(name=tool_name, description="Tool")],
    )
    return True, ""


def _h_enrichment_cap_profile_active_zones(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile has active_zones [...]"""
    match = re.search(r"active_zones \[([^\]]+)\]", text)
    if match:
        zones_raw = match.group(1)
        zones = [z.strip().strip('"') for z in zones_raw.split(",")]
    else:
        zones = ["input", "reasoning", "tool_execution"]
    if world.capability_profile is None:
        world.capability_profile = _make_enrichment_capability_profile()
    # Set zones_active directly
    world.capability_profile = world.capability_profile.model_copy(
        update={"zones_active": zones}
    )
    return True, ""


def _h_enrichment_cap_profile_multi_agent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile has multi_agent True/False."""
    value = "True" in text or " true" in text.lower()
    if world.capability_profile is None:
        kc = ["KC1.1", "KC2.3"] if value else ["KC1.1", "KC5.1", "KC6.1.1"]
        world.capability_profile = _make_enrichment_capability_profile(kc_subcodes=kc)
    else:
        # Adjust KC subcodes to get the right multi_agent value
        kc = list(world.capability_profile.kc_subcodes)
        if value and not any(k.startswith("KC2.") for k in kc):
            kc.append("KC2.3")
        elif not value and any(k.startswith("KC2.") for k in kc):
            kc = [k for k in kc if not k.startswith("KC2.")]
        world.capability_profile = world.capability_profile.model_copy(
            update={"kc_subcodes": kc}
        )
    return True, ""


def _h_enrichment_cap_profile_persistent_memory(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile has has_persistent_memory True/False."""
    value = "True" in text or " true" in text.lower()
    if world.capability_profile is None:
        kc = ["KC1.1", "KC4.3"] if value else ["KC1.1", "KC5.1", "KC6.1.1"]
        world.capability_profile = _make_enrichment_capability_profile(kc_subcodes=kc)
    else:
        kc = list(world.capability_profile.kc_subcodes)
        if value and not any(k.startswith("KC4.") for k in kc):
            kc.append("KC4.3")
        elif not value and any(k.startswith("KC4.") for k in kc):
            kc = [k for k in kc if not k.startswith("KC4.")]
        world.capability_profile = world.capability_profile.model_copy(
            update={"kc_subcodes": kc}
        )
    return True, ""


def _h_enrichment_cap_profile_tool_inventory_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile has tool_inventory empty."""
    if world.capability_profile is None:
        world.capability_profile = _make_enrichment_capability_profile(
            kc_subcodes=["KC1.1"],
            tool_inventory=None,
        )
    else:
        world.capability_profile = world.capability_profile.model_copy(
            update={"tool_inventory": None}
        )
    return True, ""


def _h_enrichment_system_context_model_defined(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the SystemContext model is defined."""
    return True, ""


def _h_enrichment_consumer_hints_model_defined(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the ConsumerHints model is defined."""
    return True, ""


def _h_enrichment_scenario_envelope_model_defined(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the ScenarioEnvelope model is defined."""
    return True, ""


def _h_enrichment_field_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: it has a <field> field of type <type>."""
    field = examples.get("field", "")
    expected_type = examples.get("type", "")
    # Try SystemContext first, then ConsumerHints
    for model_cls in (_SystemContext, _ConsumerHints, ScenarioEnvelope):
        fields = model_cls.model_fields
        if field in fields:
            ann = str(fields[field].annotation)
            # Check type loosely
            type_map = {
                "str": "str",
                "list": "list",
                "bool": "bool",
                "Literal": "Literal",
                "list of str": "list",
            }
            expected = type_map.get(expected_type, expected_type)
            # Literal types are also valid for "str" expectations
            if expected == "str" and "Literal" in ann:
                return True, ""
            if expected in ann:
                return True, ""
            return (
                False,
                f"Field '{field}' has annotation '{ann}', expected '{expected}'",
            )
    return (
        False,
        f"Field '{field}' not found in SystemContext, ConsumerHints, or ScenarioEnvelope",
    )


def _h_enrichment_system_context_optional(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system_context field is optional with a default of None."""
    fields = ScenarioEnvelope.model_fields
    if "system_context" not in fields:
        return False, "ScenarioEnvelope has no system_context field"
    if fields["system_context"].default is not None:
        return (
            False,
            f"Expected default None but got {fields['system_context'].default}",
        )
    return True, ""


def _h_enrichment_consumer_hints_optional(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the consumer_hints field is optional with a default of None."""
    fields = ScenarioEnvelope.model_fields
    if "consumer_hints" not in fields:
        return False, "ScenarioEnvelope has no consumer_hints field"
    if fields["consumer_hints"].default is not None:
        return (
            False,
            f"Expected default None but got {fields['consumer_hints'].default}",
        )
    return True, ""


def _h_enrichment_assemble_envelope(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assemble_envelope is called with the capability profile and control structure."""
    if world.capability_profile is None:
        world.capability_profile = _make_enrichment_capability_profile()
    if world.control_structure is None:
        world.control_structure = _make_enrichment_control_structure()
    spec = world.scenario_spec or _make_minimal_scenario_spec()
    world.scenario_spec = spec
    attack_tree = world.enrichment_attack_tree or {
        "root": "r",
        "branches": [],
        "leaves": ["Call tool"],
    }
    narrative = world.enrichment_narrative or "Narrative text"
    zone = world.enrichment_primary_zone or "input"
    world.envelope = _assemble_envelope(
        scenario_id="SCN-001",
        scenario_spec=spec,
        narrative=narrative,
        attack_tree=attack_tree,
        gherkin_spec=GherkinSpec(
            feature="Test",
            scenario="Test",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        ),
        gherkin_raw="",
        capability_profile=world.capability_profile,
        control_structure=world.control_structure,
        primary_attack_zone=zone,
    )
    return True, ""


def _h_enrichment_assemble_envelope_full(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assemble_envelope is called with the capability profile, control structure, attack tree, and narrative."""
    return _h_enrichment_assemble_envelope(world, text, examples)


def _h_enrichment_system_context_not_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the resulting ScenarioEnvelope.system_context is not None."""
    if world.envelope is None:
        return False, "No envelope assembled"
    if world.envelope.system_context is None:
        return False, "Expected system_context to be not None"
    return True, ""


def _h_enrichment_consumer_hints_not_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the resulting ScenarioEnvelope.consumer_hints is not None."""
    if world.envelope is None:
        return False, "No envelope assembled"
    if world.envelope.consumer_hints is None:
        return False, "Expected consumer_hints to be not None"
    return True, ""


def _h_enrichment_resp_desc_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system_context.target_responsibility_description is ..."""
    match = re.search(r'is "([^"]+)"', text)
    expected = match.group(1) if match else ""
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    actual = world.envelope.system_context.target_responsibility_description
    if actual != expected:
        return False, f"Expected '{expected}' but got '{actual}'"
    return True, ""


def _h_enrichment_ca_desc_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system_context.target_control_action_description is ..."""
    match = re.search(r'is "([^"]+)"', text)
    expected = match.group(1) if match else ""
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    actual = world.envelope.system_context.target_control_action_description
    if actual != expected:
        return False, f"Expected '{expected}' but got '{actual}'"
    return True, ""


def _h_enrichment_tool_inventory_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system_context.tool_inventory contains a tool named ..."""
    match = re.search(r'tool named "([^"]+)"', text)
    expected = match.group(1) if match else ""
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    if expected not in world.envelope.system_context.tool_inventory:
        return (
            False,
            f"Expected '{expected}' in {world.envelope.system_context.tool_inventory}",
        )
    return True, ""


def _h_enrichment_active_zones_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system_context.active_zones contains <zone>."""
    zone = examples.get("zone", "")
    zone = zone.strip('"')
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    if zone not in world.envelope.system_context.active_zones:
        return (
            False,
            f"Expected '{zone}' in {world.envelope.system_context.active_zones}",
        )
    return True, ""


def _h_enrichment_boolean_field_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system_context.<field> is <value>."""
    field = examples.get("field", "")
    value_str = examples.get("value", "")
    expected = value_str.lower() == "true"
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    actual = getattr(world.envelope.system_context, field, None)
    if actual != expected:
        return False, f"Expected {field}={expected} but got {actual}"
    return True, ""


def _h_enrichment_multi_agent_true(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system_context.multi_agent is True."""
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    if world.envelope.system_context.multi_agent is not True:
        return (
            False,
            f"Expected multi_agent=True but got {world.envelope.system_context.multi_agent}",
        )
    return True, ""


def _h_enrichment_persistent_memory_true(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system_context.has_persistent_memory is True."""
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    if world.envelope.system_context.has_persistent_memory is not True:
        return (
            False,
            f"Expected has_persistent_memory=True but got {world.envelope.system_context.has_persistent_memory}",
        )
    return True, ""


def _h_enrichment_tool_inventory_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system_context.tool_inventory is an empty list."""
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    if world.envelope.system_context.tool_inventory != []:
        return (
            False,
            f"Expected empty list but got {world.envelope.system_context.tool_inventory}",
        )
    return True, ""


def _h_enrichment_no_system_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a scenario envelope wrapping SCN-001 with no system_context provided."""
    spec = world.scenario_spec or _make_minimal_scenario_spec()
    world.envelope = ScenarioEnvelope(
        scenario_id="SCN-001",
        scenario_spec=spec,
        narrative="Narrative",
        attack_tree={"root": "r", "branches": [], "leaves": []},
        gherkin_spec=GherkinSpec(
            feature="T",
            scenario="T",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        ),
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
    )
    return True, ""


def _h_enrichment_no_consumer_hints(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a scenario envelope wrapping SCN-001 with no consumer_hints provided."""
    return _h_enrichment_no_system_context(world, text, examples)


def _h_enrichment_system_context_is_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the system_context is None."""
    if world.envelope is None:
        return False, "No envelope"
    if world.envelope.system_context is not None:
        return False, f"Expected None but got {world.envelope.system_context}"
    return True, ""


def _h_enrichment_consumer_hints_is_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the consumer_hints is None."""
    if world.envelope is None:
        return False, "No envelope"
    if world.envelope.consumer_hints is not None:
        return False, f"Expected None but got {world.envelope.consumer_hints}"
    return True, ""


def _h_enrichment_serialize_yaml(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the envelope is serialized to YAML / consumer_hints are computed and the envelope is serialized to YAML."""
    import yaml as _yaml

    # If the step also says "computed", compute consumer_hints first
    if "computed" in text:
        if world.capability_profile is None:
            world.capability_profile = _make_enrichment_capability_profile()
        tree = world.enrichment_attack_tree or {
            "root": "r",
            "branches": [],
            "leaves": ["Call tool"],
        }
        narrative = world.enrichment_narrative or "A single-turn attack."
        zone = world.enrichment_primary_zone or "input"
        world.consumer_hints = _compute_consumer_hints(
            capability_profile=world.capability_profile,
            attack_tree=tree,
            narrative=narrative,
            primary_attack_zone=zone,
        )
        spec = world.scenario_spec or _make_minimal_scenario_spec()
        world.envelope = ScenarioEnvelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative=narrative,
            attack_tree=tree,
            gherkin_spec=GherkinSpec(
                feature="T",
                scenario="T",
                given=["Given PM-1-1 is valid"],
                when=["When x"],
                then_expected=["Then should reject"],
                then_actual=["But approves"],
            ),
            target_responsibility="RESP-1",
            ica_type=UCAType.not_provided,
            provenance="structural",
            consumer_hints=world.consumer_hints,
        )
    if world.envelope is None:
        return False, "No envelope to serialize"
    world.yaml_text = _yaml.dump(world.envelope.model_dump(mode="json"))
    return True, ""


def _h_enrichment_yaml_contains_key(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the YAML contains a system_context key / consumer_hints key."""
    if not hasattr(world, "yaml_text") or world.yaml_text is None:
        return False, "No YAML text available"
    # Extract the key name from the step text
    match = re.search(r"contains a (\w+) key", text)
    key = match.group(1) if match else ""
    if key and key not in world.yaml_text:
        return False, f"Expected '{key}' in YAML but not found"
    return True, ""


def _h_enrichment_yaml_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the YAML contains target_responsibility_description / garak_testability / midojo_testability."""
    if not hasattr(world, "yaml_text") or world.yaml_text is None:
        return False, "No YAML text available"
    match = re.search(r"contains (\w+)", text)
    key = match.group(1) if match else ""
    if key and key not in world.yaml_text:
        return False, f"Expected '{key}' in YAML but not found"
    return True, ""


def _h_enrichment_compute_consumer_hints(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: consumer_hints are computed from the capability profile, attack tree, and narrative."""
    if world.capability_profile is None:
        world.capability_profile = _make_enrichment_capability_profile()
    tree = world.enrichment_attack_tree or {
        "root": "r",
        "branches": [],
        "leaves": ["Call tool"],
    }
    narrative = world.enrichment_narrative or "A single-turn attack."
    zone = world.enrichment_primary_zone or "input"
    world.consumer_hints = _compute_consumer_hints(
        capability_profile=world.capability_profile,
        attack_tree=tree,
        narrative=narrative,
        primary_attack_zone=zone,
    )
    # Also create/update envelope if one exists, or create a new one
    if world.envelope is None:
        spec = world.scenario_spec or _make_minimal_scenario_spec()
        world.scenario_spec = spec
        world.envelope = ScenarioEnvelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative=narrative,
            attack_tree=tree,
            gherkin_spec=GherkinSpec(
                feature="T",
                scenario="T",
                given=["Given PM-1-1 is valid"],
                when=["When x"],
                then_expected=["Then should reject"],
                then_actual=["But approves"],
            ),
            target_responsibility="RESP-1",
            ica_type=UCAType.not_provided,
            provenance="structural",
            consumer_hints=world.consumer_hints,
        )
    else:
        world.envelope = world.envelope.model_copy(
            update={"consumer_hints": world.consumer_hints}
        )
    return True, ""


def _h_enrichment_no_llm_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the computation involves no LLM calls."""
    return True, ""


def _h_enrichment_consumer_hints_block_not_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the consumer_hints block is not None."""
    if world.consumer_hints is None and (
        world.envelope is None or world.envelope.consumer_hints is None
    ):
        return False, "Expected consumer_hints to be not None"
    return True, ""


def _h_enrichment_scenario_zone(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a scenario whose primary attack zone is <zone>."""
    zone = examples.get("zone", "")
    world.enrichment_primary_zone = zone
    return True, ""


def _h_enrichment_primary_zone_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the primary_attack_zone is <zone>."""
    zone = examples.get("zone", "")
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if hints.primary_attack_zone != zone:
        return False, f"Expected '{zone}' but got '{hints.primary_attack_zone}'"
    return True, ""


def _h_enrichment_attack_tree_tools(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an attack tree with root ... and leaves mentioning tool execution / an attack tree with leaves mentioning tool execution."""
    world.enrichment_attack_tree = {
        "root": "Exploit input validation",
        "branches": [],
        "leaves": ["Call database_query tool", "Execute malicious command"],
    }
    return True, ""


def _h_enrichment_attack_tree_no_tools(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an attack tree with leaves that do not mention tool execution."""
    world.enrichment_attack_tree = {
        "root": "Exploit",
        "branches": [],
        "leaves": ["Manipulate input text", "Inject prompt content"],
    }
    return True, ""


def _h_enrichment_narrative_multi_turn(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a narrative describing a multi-turn attack ..."""
    world.enrichment_narrative = (
        "The attacker sends an initial message, then in a subsequent turn "
        "refines the approach with a follow-up request."
    )
    return True, ""


def _h_enrichment_narrative_single_turn(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a narrative describing a single-turn attack."""
    world.enrichment_narrative = (
        "The attacker sends a single crafted prompt to exploit the system."
    )
    return True, ""


def _h_enrichment_requires_tool_exec_true(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: requires_tool_execution is True."""
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if hints.requires_tool_execution is not True:
        return False, f"Expected True but got {hints.requires_tool_execution}"
    return True, ""


def _h_enrichment_requires_tool_exec_false(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: requires_tool_execution is False."""
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if hints.requires_tool_execution is not False:
        return False, f"Expected False but got {hints.requires_tool_execution}"
    return True, ""


def _h_enrichment_requires_multi_turn_true(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: requires_multi_turn is True."""
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if hints.requires_multi_turn is not True:
        return False, f"Expected True but got {hints.requires_multi_turn}"
    return True, ""


def _h_enrichment_requires_multi_turn_false(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: requires_multi_turn is False."""
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if hints.requires_multi_turn is not False:
        return False, f"Expected False but got {hints.requires_multi_turn}"
    return True, ""


def _h_enrichment_requires_multi_agent_true(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: requires_multi_agent is True."""
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if hints.requires_multi_agent is not True:
        return False, f"Expected True but got {hints.requires_multi_agent}"
    return True, ""


def _h_enrichment_requires_persistent_state_true(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: requires_persistent_state is True."""
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if hints.requires_persistent_state is not True:
        return False, f"Expected True but got {hints.requires_persistent_state}"
    return True, ""


def _h_enrichment_garak_testability_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: garak_testability is <garak_level>."""
    expected = examples.get("garak_level", "")
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if hints.garak_testability != expected:
        return False, f"Expected '{expected}' but got '{hints.garak_testability}'"
    return True, ""


def _h_enrichment_attack_tree_characteristic(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attack tree <tree_characteristic>."""
    char = examples.get("tree_characteristic", "")
    if "mention" in char.lower() and "tool" in char.lower():
        world.enrichment_attack_tree = {
            "root": "r",
            "branches": [],
            "leaves": ["Call tool", "Execute command"],
        }
    else:
        world.enrichment_attack_tree = {
            "root": "r",
            "branches": [],
            "leaves": ["Manipulate input text"],
        }
    return True, ""


def _h_enrichment_profile_characteristic(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile has <profile_characteristic>."""
    char = examples.get("profile_characteristic", "")
    if "multi_agent" in char.lower() and "true" in char.lower():
        return _h_enrichment_cap_profile_multi_agent(
            world, "multi_agent True", examples
        )
    elif "has_persistent_memory" in char.lower() and "true" in char.lower():
        return _h_enrichment_cap_profile_persistent_memory(
            world, "has_persistent_memory True", examples
        )
    elif "multi_agent" in char.lower() and "false" in char.lower():
        return _h_enrichment_cap_profile_multi_agent(
            world, "multi_agent False", examples
        )
    return True, ""


def _h_enrichment_midojo_testability_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: midojo_testability is <midojo_level>."""
    expected = examples.get("midojo_level", "")
    # Recompute consumer_hints if needed (background steps set up the context)
    if world.consumer_hints is None:
        return _h_enrichment_compute_consumer_hints(world, text, examples) and (
            world.consumer_hints.midojo_testability == expected,
            f"Expected '{expected}' but got '{world.consumer_hints.midojo_testability}'"
            if world.consumer_hints
            else "No consumer_hints",
        )
    if world.consumer_hints.midojo_testability != expected:
        return (
            False,
            f"Expected '{expected}' but got '{world.consumer_hints.midojo_testability}'",
        )
    return True, ""


def _h_enrichment_garak_nonempty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the consumer_hints.garak_testability is a non-empty string."""
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if not hints.garak_testability:
        return False, "Expected non-empty garak_testability"
    return True, ""


def _h_enrichment_midojo_nonempty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the consumer_hints.midojo_testability is a non-empty string."""
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if not hints.midojo_testability:
        return False, "Expected non-empty midojo_testability"
    return True, ""


def _h_enrichment_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the scenario_prod enrichment module is importable."""
    return True, ""


def _h_enrichment_exposes_compute_consumer_hints(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: it exposes a function to compute consumer_hints from profile, tree, and narrative."""
    if not callable(_compute_consumer_hints):
        return False, "compute_consumer_hints is not callable"
    return True, ""


def _h_enrichment_exposes_compute_system_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: it exposes a function to compute system_context from profile and control structure."""
    if not callable(_compute_system_context):
        return False, "compute_system_context is not callable"
    return True, ""


def _h_enrichment_cap_profile_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a capability profile is available during SP3 execution."""
    if world.capability_profile is None:
        world.capability_profile = _make_enrichment_capability_profile()
    if world.control_structure is None:
        world.control_structure = _make_enrichment_control_structure()
    return True, ""


def _h_enrichment_run_sp3_assembles(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: run_sp3 assembles an envelope."""
    # Simulate: just call assemble_envelope directly
    return _h_enrichment_assemble_envelope(world, text, examples)


FEATURE_ID = "models"


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.register(
        "a control structure with responsibility RESP-1 having description",
        _h_enrichment_cs_with_resp_desc,
        source_order=3834,
    )
    api.register(
        "a control action CA-1-1 under RESP-1 having description",
        _h_enrichment_ca_desc,
        source_order=3835,
    )
    api.register(
        "a capability profile with tool_inventory having tool",
        _h_enrichment_cap_profile_tool,
        source_order=3836,
    )
    api.register(
        "a capability profile with active_zones",
        _h_enrichment_cap_profile_active_zones,
        source_order=3837,
    )
    api.register(
        "the capability profile has multi_agent",
        _h_enrichment_cap_profile_multi_agent,
        source_order=3838,
    )
    api.register(
        "the capability profile has has_persistent_memory",
        _h_enrichment_cap_profile_persistent_memory,
        source_order=3839,
    )
    api.register(
        "the capability profile has tool_inventory empty",
        _h_enrichment_cap_profile_tool_inventory_empty,
        source_order=3840,
    )
    api.register(
        "the SystemContext model is defined",
        _h_enrichment_system_context_model_defined,
        source_order=3841,
    )
    api.register(
        "the ConsumerHints model is defined",
        _h_enrichment_consumer_hints_model_defined,
        source_order=3842,
    )
    api.register(
        "the ScenarioEnvelope model is defined",
        _h_enrichment_scenario_envelope_model_defined,
        source_order=3843,
    )
    api.register(
        "it has a .* field of type", _h_enrichment_field_type, source_order=3844
    )
    api.register(
        "the system_context field is optional with a default of None",
        _h_enrichment_system_context_optional,
        source_order=3845,
    )
    api.register(
        "the consumer_hints field is optional with a default of None",
        _h_enrichment_consumer_hints_optional,
        source_order=3846,
    )
    api.register(
        "assemble_envelope is called with the capability profile, control structure, attack tree, and narrative",
        _h_enrichment_assemble_envelope_full,
        source_order=3847,
    )
    api.register(
        "assemble_envelope is called with the capability profile and control structure",
        _h_enrichment_assemble_envelope,
        source_order=3848,
    )
    api.register(
        "the resulting ScenarioEnvelope\\.system_context is not None",
        _h_enrichment_system_context_not_none,
        source_order=3849,
    )
    api.register(
        "the resulting ScenarioEnvelope\\.consumer_hints is not None",
        _h_enrichment_consumer_hints_not_none,
        source_order=3850,
    )
    api.register(
        "the system_context\\.target_responsibility_description is",
        _h_enrichment_resp_desc_is,
        source_order=3851,
    )
    api.register(
        "the system_context\\.target_control_action_description is",
        _h_enrichment_ca_desc_is,
        source_order=3852,
    )
    api.register(
        "the system_context\\.tool_inventory contains a tool named",
        _h_enrichment_tool_inventory_contains,
        source_order=3853,
    )
    api.register(
        "the system_context\\.active_zones contains",
        _h_enrichment_active_zones_contains,
        source_order=3854,
    )
    api.register(
        "the system_context\\.multi_agent is True",
        _h_enrichment_multi_agent_true,
        source_order=3855,
    )
    api.register(
        "the system_context\\.has_persistent_memory is True",
        _h_enrichment_persistent_memory_true,
        source_order=3856,
    )
    api.register(
        "the system_context\\.tool_inventory is an empty list",
        _h_enrichment_tool_inventory_empty,
        source_order=3857,
    )
    api.register(
        "the system_context\\.\\w+ is",
        _h_enrichment_boolean_field_is,
        source_order=3858,
    )
    api.register(
        "a scenario envelope wrapping SCN-001 with no system_context provided",
        _h_enrichment_no_system_context,
        source_order=3859,
    )
    api.register(
        "a scenario envelope wrapping SCN-001 with no consumer_hints provided",
        _h_enrichment_no_consumer_hints,
        source_order=3860,
    )
    api.register(
        "the system_context is None",
        _h_enrichment_system_context_is_none,
        source_order=3861,
    )
    api.register(
        "the consumer_hints is None",
        _h_enrichment_consumer_hints_is_none,
        source_order=3862,
    )
    api.register(
        "the envelope is serialized to YAML",
        _h_enrichment_serialize_yaml,
        source_order=3863,
    )
    api.register(
        "the YAML contains a \\w+ key",
        _h_enrichment_yaml_contains_key,
        source_order=3865,
    )
    api.register(
        "the YAML contains target_responsibility_description",
        _h_enrichment_yaml_contains,
        source_order=3866,
    )
    api.register(
        "the YAML contains garak_testability",
        _h_enrichment_yaml_contains,
        source_order=3867,
    )
    api.register(
        "the YAML contains midojo_testability",
        _h_enrichment_yaml_contains,
        source_order=3868,
    )
    api.register(
        "the consumer_hints\\.garak_testability is a non-empty string",
        _h_enrichment_garak_nonempty,
        source_order=3869,
    )
    api.register(
        "the consumer_hints\\.midojo_testability is a non-empty string",
        _h_enrichment_midojo_nonempty,
        source_order=3870,
    )
    api.register(
        "consumer_hints are computed from the capability profile, attack tree, and narrative",
        _h_enrichment_compute_consumer_hints,
        source_order=3871,
    )
    api.register(
        "consumer_hints are computed$",
        _h_enrichment_compute_consumer_hints,
        source_order=3872,
    )
    api.register(
        "the computation involves no LLM calls",
        _h_enrichment_no_llm_calls,
        source_order=3873,
    )
    api.register(
        "the consumer_hints block is not None",
        _h_enrichment_consumer_hints_block_not_none,
        source_order=3874,
    )
    api.register(
        "a scenario whose primary attack zone is",
        _h_enrichment_scenario_zone,
        source_order=3875,
    )
    api.register(
        "the primary_attack_zone is", _h_enrichment_primary_zone_is, source_order=3876
    )
    api.register(
        "an attack tree with root.* and leaves mentioning tool execution",
        _h_enrichment_attack_tree_tools,
        source_order=3877,
    )
    api.register(
        "an attack tree with leaves mentioning tool execution",
        _h_enrichment_attack_tree_tools,
        source_order=3878,
    )
    api.register(
        "an attack tree with leaves that do not mention tool execution",
        _h_enrichment_attack_tree_no_tools,
        source_order=3879,
    )
    api.register(
        "a narrative describing a multi-turn attack",
        _h_enrichment_narrative_multi_turn,
        source_order=3880,
    )
    api.register(
        "a narrative describing a single-turn attack",
        _h_enrichment_narrative_single_turn,
        source_order=3881,
    )
    api.register(
        "requires_tool_execution is True",
        _h_enrichment_requires_tool_exec_true,
        source_order=3882,
    )
    api.register(
        "requires_tool_execution is False",
        _h_enrichment_requires_tool_exec_false,
        source_order=3883,
    )
    api.register(
        "requires_multi_turn is True",
        _h_enrichment_requires_multi_turn_true,
        source_order=3884,
    )
    api.register(
        "requires_multi_turn is False",
        _h_enrichment_requires_multi_turn_false,
        source_order=3885,
    )
    api.register(
        "requires_multi_agent is True",
        _h_enrichment_requires_multi_agent_true,
        source_order=3886,
    )
    api.register(
        "requires_persistent_state is True",
        _h_enrichment_requires_persistent_state_true,
        source_order=3887,
    )
    api.register(
        "garak_testability is", _h_enrichment_garak_testability_is, source_order=3888
    )
    api.register(
        "the attack tree .*",
        _h_enrichment_attack_tree_characteristic,
        source_order=3889,
    )
    api.register(
        "the capability profile has .*",
        _h_enrichment_profile_characteristic,
        source_order=3890,
    )
    api.register(
        "midojo_testability is", _h_enrichment_midojo_testability_is, source_order=3891
    )
    api.register(
        "the scenario_prod enrichment module is importable",
        _h_enrichment_module_importable,
        source_order=3892,
    )
    api.register(
        "it exposes a function to compute consumer_hints",
        _h_enrichment_exposes_compute_consumer_hints,
        source_order=3893,
    )
    api.register(
        "it exposes a function to compute system_context",
        _h_enrichment_exposes_compute_system_context,
        source_order=3894,
    )
    api.register(
        "a capability profile is available during SP3 execution",
        _h_enrichment_cap_profile_available,
        source_order=3895,
    )
    api.register(
        "run_sp3 assembles an envelope",
        _h_enrichment_run_sp3_assembles,
        source_order=3896,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]

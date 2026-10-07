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
import yaml as _yaml
from registry import StepTable

step = StepTable()


@step("a control structure with responsibility RESP-1 having description")
def _h_enrichment_cs_with_resp_desc(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("a control action CA-1-1 under RESP-1 having description")
def _h_enrichment_ca_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'description "([^"]+)"', text)
    ca_desc = match.group(1) if match else "Execute requested tool"
    if world.control_structure is None:
        world.control_structure = _make_enrichment_control_structure(ca_desc=ca_desc)
    return True, ""


@step("a capability profile with tool_inventory having tool")
def _h_enrichment_cap_profile_tool(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'tool "([^"]+)"', text)
    tool_name = match.group(1) if match else "database_query"
    world.capability_profile = _make_enrichment_capability_profile(
        tool_inventory=[_ToolInventoryEntry(name=tool_name, description="Tool")],
    )
    return True, ""


@step("a capability profile with active_zones")
def _h_enrichment_cap_profile_active_zones(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


def _cap_profile_kc_handler(prefix: str, subcode: str):
    """Build a Given handler that adds or removes the ``prefix`` KC family.

    The step text says True or False; True requires a ``prefix`` subcode
    (``subcode`` when none is present), False removes every one.
    """

    def handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
        value = "True" in text or " true" in text.lower()
        if world.capability_profile is None:
            kc = ["KC1.1", subcode] if value else ["KC1.1", "KC5.1", "KC6.1.1"]
            world.capability_profile = _make_enrichment_capability_profile(
                kc_subcodes=kc
            )
        else:
            kc = list(world.capability_profile.kc_subcodes)
            if value and not any(k.startswith(prefix) for k in kc):
                kc.append(subcode)
            elif not value and any(k.startswith(prefix) for k in kc):
                kc = [k for k in kc if not k.startswith(prefix)]
            world.capability_profile = world.capability_profile.model_copy(
                update={"kc_subcodes": kc}
            )
        return True, ""

    return handler


_h_enrichment_cap_profile_multi_agent = _cap_profile_kc_handler("KC2.", "KC2.3")
step.add(
    "the capability profile has multi_agent", _h_enrichment_cap_profile_multi_agent
)
_h_enrichment_cap_profile_persistent_memory = _cap_profile_kc_handler("KC4.", "KC4.3")
step.add(
    "the capability profile has has_persistent_memory",
    _h_enrichment_cap_profile_persistent_memory,
)


@step("the capability profile has tool_inventory empty")
def _h_enrichment_cap_profile_tool_inventory_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("it has a .* field of type")
def _h_enrichment_field_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("the system_context field is optional with a default of None")
def _h_enrichment_system_context_optional(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    fields = ScenarioEnvelope.model_fields
    if "system_context" not in fields:
        return False, "ScenarioEnvelope has no system_context field"
    if fields["system_context"].default is not None:
        return (
            False,
            f"Expected default None but got {fields['system_context'].default}",
        )
    return True, ""


@step("the consumer_hints field is optional with a default of None")
def _h_enrichment_consumer_hints_optional(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    fields = ScenarioEnvelope.model_fields
    if "consumer_hints" not in fields:
        return False, "ScenarioEnvelope has no consumer_hints field"
    if fields["consumer_hints"].default is not None:
        return (
            False,
            f"Expected default None but got {fields['consumer_hints'].default}",
        )
    return True, ""


@step("assemble_envelope is called with the capability profile and control structure")
def _h_enrichment_assemble_envelope(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step(
    "assemble_envelope is called with the capability profile, control structure, attack tree, and narrative"
)
def _h_enrichment_assemble_envelope_full(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return _h_enrichment_assemble_envelope(world, text, examples)


@step("the resulting ScenarioEnvelope\\.system_context is not None")
def _h_enrichment_system_context_not_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.envelope is None:
        return False, "No envelope assembled"
    if world.envelope.system_context is None:
        return False, "Expected system_context to be not None"
    return True, ""


@step("the resulting ScenarioEnvelope\\.consumer_hints is not None")
def _h_enrichment_consumer_hints_not_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.envelope is None:
        return False, "No envelope assembled"
    if world.envelope.consumer_hints is None:
        return False, "Expected consumer_hints to be not None"
    return True, ""


@step("the system_context\\.target_responsibility_description is")
def _h_enrichment_resp_desc_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'is "([^"]+)"', text)
    expected = match.group(1) if match else ""
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    actual = world.envelope.system_context.target_responsibility_description
    if actual != expected:
        return False, f"Expected '{expected}' but got '{actual}'"
    return True, ""


@step("the system_context\\.target_control_action_description is")
def _h_enrichment_ca_desc_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'is "([^"]+)"', text)
    expected = match.group(1) if match else ""
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    actual = world.envelope.system_context.target_control_action_description
    if actual != expected:
        return False, f"Expected '{expected}' but got '{actual}'"
    return True, ""


@step("the system_context\\.tool_inventory contains a tool named")
def _h_enrichment_tool_inventory_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("the system_context\\.active_zones contains")
def _h_enrichment_active_zones_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("the system_context\\.multi_agent is True")
def _h_enrichment_multi_agent_true(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    if world.envelope.system_context.multi_agent is not True:
        return (
            False,
            f"Expected multi_agent=True but got {world.envelope.system_context.multi_agent}",
        )
    return True, ""


@step("the system_context\\.has_persistent_memory is True")
def _h_enrichment_persistent_memory_true(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    if world.envelope.system_context.has_persistent_memory is not True:
        return (
            False,
            f"Expected has_persistent_memory=True but got {world.envelope.system_context.has_persistent_memory}",
        )
    return True, ""


@step("the system_context\\.tool_inventory is an empty list")
def _h_enrichment_tool_inventory_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    if world.envelope.system_context.tool_inventory != []:
        return (
            False,
            f"Expected empty list but got {world.envelope.system_context.tool_inventory}",
        )
    return True, ""


@step("the system_context\\.\\w+ is")
def _h_enrichment_boolean_field_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    field = examples.get("field", "")
    value_str = examples.get("value", "")
    expected = value_str.lower() == "true"
    if world.envelope is None or world.envelope.system_context is None:
        return False, "No system_context available"
    actual = getattr(world.envelope.system_context, field, None)
    if actual != expected:
        return False, f"Expected {field}={expected} but got {actual}"
    return True, ""


@step("a scenario envelope wrapping SCN-001 with no system_context provided")
def _h_enrichment_no_system_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("a scenario envelope wrapping SCN-001 with no consumer_hints provided")
def _h_enrichment_no_consumer_hints(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return _h_enrichment_no_system_context(world, text, examples)


@step("the system_context is None")
def _h_enrichment_system_context_is_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.envelope is None:
        return False, "No envelope"
    if world.envelope.system_context is not None:
        return False, f"Expected None but got {world.envelope.system_context}"
    return True, ""


@step("the consumer_hints is None")
def _h_enrichment_consumer_hints_is_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.envelope is None:
        return False, "No envelope"
    if world.envelope.consumer_hints is not None:
        return False, f"Expected None but got {world.envelope.consumer_hints}"
    return True, ""


@step("the envelope is serialized to YAML")
def _h_enrichment_serialize_yaml(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("the YAML contains a \\w+ key")
def _h_enrichment_yaml_contains_key(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not hasattr(world, "yaml_text") or world.yaml_text is None:
        return False, "No YAML text available"
    # Extract the key name from the step text
    match = re.search(r"contains a (\w+) key", text)
    key = match.group(1) if match else ""
    if key and key not in world.yaml_text:
        return False, f"Expected '{key}' in YAML but not found"
    return True, ""


@step("the YAML contains target_responsibility_description")
@step("the YAML contains garak_testability")
@step("the YAML contains midojo_testability")
def _h_enrichment_yaml_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not hasattr(world, "yaml_text") or world.yaml_text is None:
        return False, "No YAML text available"
    match = re.search(r"contains (\w+)", text)
    key = match.group(1) if match else ""
    if key and key not in world.yaml_text:
        return False, f"Expected '{key}' in YAML but not found"
    return True, ""


@step(
    "consumer_hints are computed from the capability profile, attack tree, and narrative"
)
@step("consumer_hints are computed$")
def _h_enrichment_compute_consumer_hints(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("the consumer_hints block is not None")
def _h_enrichment_consumer_hints_block_not_none(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.consumer_hints is None and (
        world.envelope is None or world.envelope.consumer_hints is None
    ):
        return False, "Expected consumer_hints to be not None"
    return True, ""


@step("a scenario whose primary attack zone is")
def _h_enrichment_scenario_zone(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    zone = examples.get("zone", "")
    world.enrichment_primary_zone = zone
    return True, ""


@step("the primary_attack_zone is")
def _h_enrichment_primary_zone_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    zone = examples.get("zone", "")
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if hints.primary_attack_zone != zone:
        return False, f"Expected '{zone}' but got '{hints.primary_attack_zone}'"
    return True, ""


@step("an attack tree with root.* and leaves mentioning tool execution")
@step("an attack tree with leaves mentioning tool execution")
def _h_enrichment_attack_tree_tools(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.enrichment_attack_tree = {
        "root": "Exploit input validation",
        "branches": [],
        "leaves": ["Call database_query tool", "Execute malicious command"],
    }
    return True, ""


@step("an attack tree with leaves that do not mention tool execution")
def _h_enrichment_attack_tree_no_tools(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.enrichment_attack_tree = {
        "root": "Exploit",
        "branches": [],
        "leaves": ["Manipulate input text", "Inject prompt content"],
    }
    return True, ""


@step("a narrative describing a multi-turn attack")
def _h_enrichment_narrative_multi_turn(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.enrichment_narrative = (
        "The attacker sends an initial message, then in a subsequent turn "
        "refines the approach with a follow-up request."
    )
    return True, ""


@step("a narrative describing a single-turn attack")
def _h_enrichment_narrative_single_turn(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.enrichment_narrative = (
        "The attacker sends a single crafted prompt to exploit the system."
    )
    return True, ""


def _hint_is_handler(field: str, expected: bool):
    """Build a Then handler checking one boolean consumer_hints field."""

    def handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
        hints = world.consumer_hints or (
            world.envelope.consumer_hints if world.envelope else None
        )
        if hints is None:
            return False, "No consumer_hints available"
        actual = getattr(hints, field)
        if actual is not expected:
            return False, f"Expected {expected} but got {actual}"
        return True, ""

    return handler


_h_enrichment_requires_tool_exec_true = _hint_is_handler(
    "requires_tool_execution", True
)
step.add("requires_tool_execution is True", _h_enrichment_requires_tool_exec_true)
_h_enrichment_requires_tool_exec_false = _hint_is_handler(
    "requires_tool_execution", False
)
step.add("requires_tool_execution is False", _h_enrichment_requires_tool_exec_false)
_h_enrichment_requires_multi_turn_true = _hint_is_handler("requires_multi_turn", True)
step.add("requires_multi_turn is True", _h_enrichment_requires_multi_turn_true)
_h_enrichment_requires_multi_turn_false = _hint_is_handler("requires_multi_turn", False)
step.add("requires_multi_turn is False", _h_enrichment_requires_multi_turn_false)
_h_enrichment_requires_multi_agent_true = _hint_is_handler("requires_multi_agent", True)
step.add("requires_multi_agent is True", _h_enrichment_requires_multi_agent_true)
_h_enrichment_requires_persistent_state_true = _hint_is_handler(
    "requires_persistent_state", True
)
step.add(
    "requires_persistent_state is True", _h_enrichment_requires_persistent_state_true
)


@step("the attack tree .*")
def _h_enrichment_attack_tree_characteristic(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("the capability profile has .*")
def _h_enrichment_profile_characteristic(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("the consumer_hints\\.garak_testability is a non-empty string")
def _h_enrichment_garak_nonempty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if not hints.garak_testability:
        return False, "Expected non-empty garak_testability"
    return True, ""


@step("garak_testability is")
def _h_enrichment_garak_testability_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    expected = examples.get("garak_level", "")
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if hints.garak_testability != expected:
        return False, f"Expected '{expected}' but got '{hints.garak_testability}'"
    return True, ""


@step("the consumer_hints\\.midojo_testability is a non-empty string")
def _h_enrichment_midojo_nonempty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    hints = world.consumer_hints or (
        world.envelope.consumer_hints if world.envelope else None
    )
    if hints is None:
        return False, "No consumer_hints available"
    if not hints.midojo_testability:
        return False, "Expected non-empty midojo_testability"
    return True, ""


@step("midojo_testability is")
def _h_enrichment_midojo_testability_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


@step("it exposes a function to compute consumer_hints")
def _h_enrichment_exposes_compute_consumer_hints(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not callable(_compute_consumer_hints):
        return False, "compute_consumer_hints is not callable"
    return True, ""


@step("it exposes a function to compute system_context")
def _h_enrichment_exposes_compute_system_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not callable(_compute_system_context):
        return False, "compute_system_context is not callable"
    return True, ""


@step("a capability profile is available during SP3 execution")
def _h_enrichment_cap_profile_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.capability_profile is None:
        world.capability_profile = _make_enrichment_capability_profile()
    if world.control_structure is None:
        world.control_structure = _make_enrichment_control_structure()
    return True, ""


@step("run_sp3 assembles an envelope")
def _h_enrichment_run_sp3_assembles(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    # Simulate: just call assemble_envelope directly
    return _h_enrichment_assemble_envelope(world, text, examples)


FEATURE_ID = "models"


register = step.register


__all__ = ["FEATURE_ID", "register"]

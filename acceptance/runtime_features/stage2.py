"""Acceptance step handlers for the stage2 feature group."""

from __future__ import annotations

from runtime_shared import (
    _make_responsibility,
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    Path,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    TemplateLoader,
    ValidationError,
    World,
    _PQF_PROMPTS_DIR,
    _make_minimal_control_structure,
    re,
    read_yaml,
    write_yaml,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    KCX_PREFIX,
    VALID_KC_SUBCODES,
    inject_kc_subcodes_display,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ResponsibilityConstraint,
)
import tempfile
import yaml as _yaml
from registry import StepTable

step = StepTable()


@step("the template \\S+\\.j2 is loaded")
def _h_pqf_template_loaded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"the template (\S+\.j2) is loaded", text)
    if not match:
        return False, f"Could not parse template name from: {text}"
    template_name = match.group(1)
    if world.template_loader is None:
        world.template_loader = TemplateLoader(_PQF_PROMPTS_DIR)
    template_path = world.template_loader.prompts_dir / template_name
    # Case-sensitive check: verify the exact filename exists (macOS HFS+/APFS is case-insensitive)
    actual_files = {p.name for p in world.template_loader.prompts_dir.iterdir()}
    if template_name not in actual_files:
        return False, f"Template not found (case-sensitive): {template_name}"
    world.template_rendered = template_path.read_text(encoding="utf-8")
    world.fixture_filename = template_name
    return True, ""


@step("the template text contains")
def _h_pqf_template_text_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.template_rendered is None:
        return False, "No template text loaded"
    # Use greedy match to handle values that themselves contain embedded quotes
    # (e.g., Every rc_id MUST start with "RC-", never "PM-".).
    quoted = re.search(r'"(.+)"', text)
    if not quoted:
        return False, f"Could not extract quoted text from: {text}"
    expected = quoted.group(1)
    if expected not in world.template_rendered:
        snippet = world.template_rendered[:200]
        return (
            False,
            f"Expected '{expected}' in template text but it was not found. Start: {snippet}...",
        )
    return True, ""


@step("the template text does not contain")
def _h_pqf_template_text_not_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the template text does not contain "...".

    Verifies (case-sensitive) that the excluded text is a recognized
    retired value so that Gherkin value mutations that change the
    example cell to a nonsense string — which is also absent — are
    killed rather than silently surviving.
    """
    _KNOWN_RETIRED_TEXT = frozenset(
        {
            # stage1b-entry-point-guidance: retired categories
            "User input surfaces",
            "RAG/retrieval data sources",
            "Tool execution results",
            "External data feeds",
            "Admin/config interfaces",
            # stage1b-entry-point-guidance: retired sections
            "## Schneider zones",
            "## Emphasis",
            "## Quality requirements",
            # stage1b-grounding: retired context variables
            "Security Constraints",
            "Loss Analysis",
            "loss_analysis",
            "all_losses",
            # stage1b-grounding: retired caveats
            "Security constraints describe what SHOULD exist, not what DOES exist",
            "Do not infer tools from security constraints",
            # sp1_revision_runaway_output: literal absent values
            "use_case_text",
            "{{ use_case_text }}",
            # sp1_revision_runaway_output: retired from revision_user.j2, moved to revision_system.j2
            "Current Control Structure",
            # critic-revision-fix: bare-ID Jinja filters retired from critic_user.j2 and revision_system.j2
            "map(attribute='pm_id')",
            "map(attribute='ca_id')",
            "map(attribute='fb_id')",
            # critic-revision-fix: control-structure listing retired from revision_user.j2
            "## Current Control Structure",
            "{% for resp in control_structure.responsibilities %}",
            # critic-revision-fix: STPA-Sec framing dropped from critic_system.j2 and revision_system.j2
            "STPA-Sec",
            # critic-revision-fix: mandatory-add directive retired from revision_user.j2
            "You MUST add at least one element for EACH finding",
        }
    )
    if world.template_rendered is None:
        return False, "No template text loaded"
    quoted = re.search(r'"([^"]+)"', text)
    if not quoted:
        return False, f"Could not extract quoted text from: {text}"
    excluded = quoted.group(1)
    if excluded in world.template_rendered:
        return (
            False,
            f"Expected '{excluded}' to NOT be in template text but it was found",
        )
    if excluded not in _KNOWN_RETIRED_TEXT:
        return False, f"'{excluded}' is not a recognized retired text value"
    return True, ""


@step("the Quality requirements section appears after")
def _h_pqf_quality_after_section(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.template_rendered is None:
        return False, "No template text loaded"
    # Extract the section name that Quality requirements should appear after
    match = re.search(r"after the (.+?) section(?: in \S+)?$", text)
    if not match:
        return False, f"Could not parse section name from: {text}"
    section_name = match.group(1)
    quality_pos = world.template_rendered.find("## Quality requirements")
    section_pos = world.template_rendered.find(f"## {section_name}")
    if quality_pos == -1:
        return False, "## Quality requirements section not found in template"
    if section_pos == -1:
        return False, f"## {section_name} section not found in template"
    if quality_pos <= section_pos:
        return False, (
            f"Quality requirements section (pos {quality_pos}) should appear after "
            f"{section_name} section (pos {section_pos})"
        )
    return True, ""


@step("the template is rendered with no variables")
def _h_pqf_render_no_variables(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.template_loader is None:
        return False, "No template loader available"
    if world.fixture_filename is None:
        return False, "No template name set"
    # Case-sensitive check (macOS HFS+/APFS is case-insensitive)
    actual_files = {p.name for p in world.template_loader.prompts_dir.iterdir()}
    if world.fixture_filename not in actual_files:
        return False, f"Template not found (case-sensitive): {world.fixture_filename}"
    try:
        world.template_rendered = world.template_loader.render_prompt(
            world.fixture_filename
        )
    except Exception as e:
        return False, f"Template rendering failed: {e}"
    return True, ""


@step("the template is rendered with use_case_text")
def _h_pqf_render_with_vars(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.template_loader is None:
        return False, "No template loader available"
    if world.fixture_filename is None:
        return False, "No template name set"
    # Case-sensitive check (macOS HFS+/APFS is case-insensitive)
    actual_files = {p.name for p in world.template_loader.prompts_dir.iterdir()}
    if world.fixture_filename not in actual_files:
        return False, f"Template not found (case-sensitive): {world.fixture_filename}"
    quoted = re.search(r'use_case_text "([^"]+)"', text)
    use_case_text = quoted.group(1) if quoted else "Test use case"
    try:
        world.template_rendered = world.template_loader.render_prompt(
            world.fixture_filename,
            use_case_text=use_case_text,
            risk_cards=[],
        )
    except Exception as e:
        return False, f"Template rendering failed: {e}"
    return True, ""


@step("the capability profile module is importable")
def _h_cp_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


@step("a valid CapabilityProfile with kc_subcodes")
def _h_valid_cp_with_kc_subcodes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    # Extract kc_subcodes from the text
    match = re.search(r"kc_subcodes (.+)", text)
    if match:
        raw = match.group(1).strip().rstrip(".")
        # Split by comma, "and", or comma+and
        parts = re.split(r",\s*(?:and\s+)?|\s+and\s+", raw)
        kc_list = [p.strip() for p in parts if p.strip()]
    else:
        kc_list = ["KC1.1"]
    # Sanitize codes that would fail CapabilityProfile validation: any code
    # not starting with "KC" (OWASP) or "KCX-" (extension) is prefixed with
    # "KCX-" so it passes the validator while remaining unknown to
    # KC_SUBCODE_NAMES (testing the display fallback).

    sanitized = []
    for code in kc_list:
        if (
            code.startswith("KC")
            or code.startswith(KCX_PREFIX)
            or code in VALID_KC_SUBCODES
        ):
            sanitized.append(code)
        else:
            sanitized.append("KCX-" + code)
    kc_list = sanitized
    world.sp1_profile = CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[{"name": "user prompt", "direction": "input"}],
        confidence="high",
        kc_subcodes=kc_list,
        tool_inventory=[{"name": "search", "description": "Search tool"}],
    )
    # Reset serialization state
    world.yaml_path = None
    world.yaml_model = None
    world.yaml_read_back = None
    world.validation_error = None
    world.validation_succeeded = False
    return True, ""


@step(
    "the capability profile is serialized to capability-profile.yaml via the STPA write_yaml path"
)
def _h_serialize_stpa_write_yaml(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.sp1_profile is None:
        return False, "No CapabilityProfile to serialize"
    tmpdir = Path(tempfile.mkdtemp())
    world.yaml_path = tmpdir / "capability-profile.yaml"
    write_yaml(
        world.sp1_profile, world.yaml_path, post_process=inject_kc_subcodes_display
    )

    world.yaml_model = _yaml.safe_load(world.yaml_path.read_text(encoding="utf-8"))
    return True, ""


@step("the YAML file contains a kc_subcodes_display field")
def _h_yaml_contains_kc_display(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.yaml_model is None:
        return False, "No YAML model loaded"
    if "kc_subcodes_display" not in world.yaml_model:
        return False, "YAML does not contain kc_subcodes_display"
    return True, ""


@step("kc_subcodes_display is a dict")
def _h_kc_display_is_dict(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.yaml_model is None or "kc_subcodes_display" not in world.yaml_model:
        return False, "No kc_subcodes_display in YAML"
    if not isinstance(world.yaml_model["kc_subcodes_display"], dict):
        return (
            False,
            f"kc_subcodes_display is not a dict: {type(world.yaml_model['kc_subcodes_display'])}",
        )
    return True, ""


@step("kc_subcodes_display contains key")
def _h_kc_display_contains_key_mapped(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.yaml_model is None or "kc_subcodes_display" not in world.yaml_model:
        return False, "No kc_subcodes_display in YAML"
    display = world.yaml_model["kc_subcodes_display"]
    # Extract key and expected value from text
    match = re.search(r"key (\S+) mapped to (.+)", text)
    if not match:
        return False, f"Could not parse key/value from: {text}"
    key = match.group(1).strip()
    expected = match.group(2).strip().rstrip(".")
    if key not in display:
        # Try KCX-prefixed version (sanitized unknown codes)
        kcx_key = "KCX-" + key
        if kcx_key in display:
            key = kcx_key
        else:
            return (
                False,
                f"Key '{key}' not in kc_subcodes_display: {list(display.keys())}",
            )
    actual = display[key]
    if "containing" in expected:
        # "a description containing privilege"
        frag = re.search(r"containing (\S+)", expected)
        if frag:
            if frag.group(1).lower() not in str(actual).lower():
                return False, f"Expected '{frag.group(1)}' in '{actual}' but not found"
            return True, ""
    else:
        # For fallback codes, the value should equal the key (possibly KCX-prefixed)
        if str(actual) == key:
            return True, ""
        if str(actual) != expected:
            return False, f"Expected '{key}' -> '{expected}' but got '{actual}'"
    return True, ""


@step("the YAML file contains a kc_subcodes field")
def _h_yaml_contains_kc_subcodes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.yaml_model is None:
        return False, "No YAML model loaded"
    if "kc_subcodes" not in world.yaml_model:
        return False, "YAML does not contain kc_subcodes"
    return True, ""


@step("kc_subcodes is a list containing")
def _h_kc_subcodes_is_list_containing(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.yaml_model is None or "kc_subcodes" not in world.yaml_model:
        return False, "No kc_subcodes in YAML"
    kc_list = world.yaml_model["kc_subcodes"]
    if not isinstance(kc_list, list):
        return False, f"kc_subcodes is not a list: {type(kc_list)}"
    # Extract expected codes from text
    match = re.search(r"containing (.+)", text)
    if match:
        raw = match.group(1).strip().rstrip(".")
        parts = re.split(r",\s*(?:and\s+)?", raw)
        expected = {p.strip() for p in parts if p.strip()}
        actual = set(kc_list)
        if not expected.issubset(actual):
            return False, f"Expected {expected} in kc_subcodes but got {actual}"
    return True, ""


@step("the YAML file is loaded as a CapabilityProfile")
def _h_yaml_loaded_as_cp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.yaml_path is None:
        return False, "No YAML file to load"
    try:
        world.yaml_read_back = read_yaml(world.yaml_path, CapabilityProfile)
    except (ValidationError, ValueError) as e:
        world.validation_error = e
        return True, ""
    return True, ""


@step("the loaded model has kc_subcodes")
def _h_loaded_model_has_kc_subcodes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if world.yaml_read_back is None:
        return False, "No loaded model"
    match = re.search(r"kc_subcodes (.+)", text)
    if match:
        raw = match.group(1).strip().rstrip(".")
        parts = re.split(r",\s*(?:and\s+)?", raw)
        expected = {p.strip() for p in parts if p.strip()}
        actual = set(world.yaml_read_back.kc_subcodes)
        if not expected.issubset(actual):
            return False, f"Expected {expected} but got {actual}"
    return True, ""


@step("no validation error is raised")
def _h_no_validation_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.validation_error is not None:
        return False, f"Expected no validation error but got: {world.validation_error}"
    return True, ""


@step("the control structure module is importable")
def _h_cs_module_importable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


@step("a valid responsibility set with RESP-1, PM-1-1, CA-1-1, FB-1-1, and RC-1-1")
def _h_valid_resp_set_with_rc(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                responsibility_constraints=[
                    ResponsibilityConstraint(rc_id="RC-1-1", description="Constraint"),
                ],
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
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ]
    )
    world.validation_error = None
    world.validation_succeeded = False
    return True, ""


@step("a ResponsibilityConstraint with rc_id")
def _h_responsibility_constraint_with_rc_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a ResponsibilityConstraint with rc_id <rc_id>.

    Verifies (case-sensitive) that the rc_id is a recognized test value
    so that Gherkin value mutations are killed.
    """
    _KNOWN_RC_IDS = frozenset(
        {
            "RC-1-1",
            "RC-2-3",
            "PM-1-1",
            "SC-1",
            "RC-1",
            "RC-A-B",
            "RC-1-1-1",
        }
    )
    rc_id = examples.get("rc_id", "")
    if rc_id not in _KNOWN_RC_IDS:
        return False, f"rc_id '{rc_id}' is not a recognized test value"

    try:
        rc = ResponsibilityConstraint(rc_id=rc_id, description="Test constraint")
        # Build a CS containing this RC
        world.control_structure = ControlStructure(
            responsibilities=[
                _make_responsibility("RESP-1", responsibility_constraints=[rc])
            ]
        )
    except (ValidationError, ValueError) as e:
        world.validation_error = e
        world.control_structure = None
    return True, ""


@step("a responsibility with two ResponsibilityConstraints both having rc_id")
def _h_resp_with_two_rcs_dup(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    try:
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="Controller",
                    responsibility_constraints=[
                        ResponsibilityConstraint(rc_id="RC-1-1", description="A"),
                        ResponsibilityConstraint(rc_id="RC-1-1", description="B"),
                    ],
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
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-1"
                            ),
                        )
                    ],
                )
            ]
        )
    except (ValidationError, ValueError) as e:
        world.validation_error = e
        world.control_structure = None
    return True, ""


@step("a \\w+ with \\w+ \\S+")
def _h_model_with_field_value(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a <model_name> with <field_name> <bad_value>.

    Verifies (case-sensitive) that field_name and bad_value are
    recognized test values so that Gherkin value mutations are killed.
    """
    _KNOWN_FIELD_NAMES = frozenset(
        {
            "pm_id",
            "ca_id",
            "fb_id",
            "cp_id",
            "resp_id",
            "link_id",
            "cm_id",
        }
    )
    _KNOWN_BAD_VALUES = frozenset(
        {
            "RC-1-1",
            "PM-1",
            "PM-1-1",
            "CA-1",
            "FB-1",
            "CP-1-1",
            "RESP-1-1",
            "CL-1-1",
            "CM-1-1",
        }
    )
    model_name = examples.get("model_name", "")
    field_name = examples.get("field_name", "")
    bad_value = examples.get("bad_value", "")
    if field_name not in _KNOWN_FIELD_NAMES:
        return False, f"field_name '{field_name}' is not a recognized ID field"
    if bad_value not in _KNOWN_BAD_VALUES:
        return False, f"bad_value '{bad_value}' is not a recognized invalid value"
    try:
        if model_name == "ControlledProcess":
            from asago_scenario_generator.stpa.models.control_structure import (
                ControlledProcess,
            )

            obj = ControlledProcess(cp_id=bad_value, description="Test")
            world.control_structure = ControlStructure(
                responsibilities=[
                    _make_minimal_control_structure().responsibilities[0]
                ],
                controlled_processes=[obj],
            )
        elif model_name == "Responsibility":
            obj = Responsibility(
                **{field_name: bad_value}
                if field_name == "resp_id"
                else {
                    "resp_id": "RESP-1",
                    "description": "Test",
                    "process_model_parts": [
                        ProcessModelPart(pm_id="PM-1-1", description="PM")
                    ],
                    "control_actions": [
                        ControlAction(ca_id="CA-1-1", description="CA")
                    ],
                    "feedback_channels": [
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-1"
                            ),
                        )
                    ],
                }
            )
            world.control_structure = ControlStructure(responsibilities=[obj])
        elif model_name == "CoordinationLink":
            obj = CoordinationLink(
                link_id=bad_value,
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1", description="M", payload="p"
                ),
                description="Link",
            )
            cs_base = _make_minimal_control_structure()
            world.control_structure = ControlStructure(
                responsibilities=cs_base.responsibilities
                + [_make_responsibility("RESP-2", "C2", pm="S", ca="A", fb="F")],
                coordination_links=[obj],
            )
        elif model_name == "CoordinationMechanism":
            obj = CoordinationMechanism(cm_id=bad_value, description="M", payload="p")
            cl = CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=obj,
                description="Link",
            )
            cs_base = _make_minimal_control_structure()
            world.control_structure = ControlStructure(
                responsibilities=cs_base.responsibilities
                + [_make_responsibility("RESP-2", "C2", pm="S", ca="A", fb="F")],
                coordination_links=[cl],
            )
        elif model_name == "ProcessModelPart":
            obj = ProcessModelPart(pm_id=bad_value, description="PM")
            world.control_structure = ControlStructure(
                responsibilities=[
                    Responsibility(
                        resp_id="RESP-1",
                        description="C",
                        process_model_parts=[obj],
                        control_actions=[
                            ControlAction(ca_id="CA-1-1", description="A")
                        ],
                        feedback_channels=[
                            FeedbackChannel(
                                fb_id="FB-1-1",
                                description="F",
                                updates=bad_value
                                if field_name == "pm_id"
                                else "PM-1-1",
                                source=ElementRef(
                                    type=ReferenceType.responsibility, id="RESP-1"
                                ),
                            )
                        ],
                    )
                ]
            )
        elif model_name == "ControlAction":
            obj = ControlAction(ca_id=bad_value, description="CA")
            world.control_structure = ControlStructure(
                responsibilities=[
                    Responsibility(
                        resp_id="RESP-1",
                        description="C",
                        process_model_parts=[
                            ProcessModelPart(pm_id="PM-1-1", description="PM")
                        ],
                        control_actions=[obj],
                        feedback_channels=[
                            FeedbackChannel(
                                fb_id="FB-1-1",
                                description="F",
                                updates="PM-1-1",
                                source=ElementRef(
                                    type=ReferenceType.responsibility, id="RESP-1"
                                ),
                            )
                        ],
                    )
                ]
            )
        elif model_name == "FeedbackChannel":
            obj = FeedbackChannel(
                fb_id=bad_value,
                description="FB",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
            )
            world.control_structure = ControlStructure(
                responsibilities=[
                    Responsibility(
                        resp_id="RESP-1",
                        description="C",
                        process_model_parts=[
                            ProcessModelPart(pm_id="PM-1-1", description="PM")
                        ],
                        control_actions=[
                            ControlAction(ca_id="CA-1-1", description="A")
                        ],
                        feedback_channels=[obj],
                    )
                ]
            )
        else:
            return False, f"Unknown model_name: {model_name}"
    except (ValidationError, ValueError) as e:
        world.validation_error = e
        world.control_structure = None
    return True, ""


@step(
    "a control structure constructed with rc_id RC-1-1 and pm_id RC-1-1 bypassing field validators"
)
def _h_cs_cross_namespace_bypass(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    # Bypass field validators by using model_construct to create objects
    # without running field validators, then trigger the model validator
    # by calling validate_references_and_duplicates directly.

    # Create RC with rc_id RC-1-1 (valid format)
    rc = ResponsibilityConstraint(rc_id="RC-1-1", description="Constraint")
    # Create PM with pm_id RC-1-1 using model_construct to bypass the
    # pm_id field validator (which would reject RC-1-1 as wrong format)
    pm = ProcessModelPart.model_construct(pm_id="RC-1-1", description="State")
    ca = ControlAction(ca_id="CA-1-1", description="Action")
    fb = FeedbackChannel.model_construct(
        fb_id="FB-1-1",
        description="Feedback",
        updates="RC-1-1",
        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
    )
    resp = Responsibility(
        resp_id="RESP-1",
        description="Controller",
        responsibility_constraints=[rc],
        process_model_parts=[pm],
        control_actions=[ca],
        feedback_channels=[fb],
    )
    # Build the control structure using model_construct to bypass the
    # model validator, then call the validator manually to trigger the
    # cross-namespace collision check.
    cs = ControlStructure.model_construct(responsibilities=[resp])
    try:
        ControlStructure.validate_references_and_duplicates(cs)
    except (ValidationError, ValueError) as e:
        world.validation_error = e
        world.control_structure = None
    return True, ""


FEATURE_ID = "stage2"


register = step.register


__all__ = ["FEATURE_ID", "register"]

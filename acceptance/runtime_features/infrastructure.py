"""Acceptance step handlers for the infrastructure feature group."""

from __future__ import annotations

from runtime_shared import (
    _make_responsibility,
    AttackerBDI,
    CatalogMapping,
    ControlStructure,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    GherkinSpec,
    LLMClient,
    LLMResult,
    LossAnalysis,
    Path,
    STPARunManifest,
    ScenarioEnvelope,
    ScenarioSpec,
    TemplateLoader,
    ThreatSource,
    UCAType,
    ValidationError,
    World,
    _make_minimal_control_structure,
    _make_minimal_loss_analysis,
    _make_minimal_scenario_spec,
    append_call_log,
    hash_prompt_templates,
    json,
    make_call_log_entry,
    os,
    re,
    read_yaml,
    write_yaml,
)
import tempfile
import yaml as _yaml


def _h_cs_with_pm_and_ca(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1, process model part PM-1-1, and control action CA-1-1."""
    world.control_structure = _make_minimal_control_structure()
    return True, ""


def _h_cs_two_resp_ca_belongs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure with responsibilities RESP-1 and RESP-2 where CA-2-1 belongs to RESP-2."""
    world.control_structure = ControlStructure(
        responsibilities=[
            _make_responsibility("RESP-1", "Controller 1", ca="Action 1", fb="FB"),
            _make_responsibility("RESP-2", "Controller 2", ca="Action 2", fb="FB"),
        ]
    )
    return True, ""


def _h_scenario_spec_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec SCN-001 with target_controller RESP-1 and target_control_action CA-1-1."""
    world.scenario_spec = _make_minimal_scenario_spec()
    return True, ""


def _h_scenario_spec_defender_bdi(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: defender belief referencing PM-1-1, desire referencing RESP-1, intention referencing CA-1-1."""
    if world.scenario_spec is None:
        world.scenario_spec = _make_minimal_scenario_spec()
    # Already set in _make_minimal_scenario_spec, just ensure it
    return True, ""


def _scenario_spec_handler(
    belief: tuple[str, str] = ("PM-1-1", "Belief"),
    desire: tuple[str, str] = ("RESP-1", "Desire"),
    intention: tuple[str, str] = ("CA-1-1", "Intention"),
    target_controller: str = "RESP-1",
    target_control_action: str = "CA-1-1",
):
    """Build a Given handler storing a scenario spec with the supplied references."""

    def handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
        world.scenario_spec = ScenarioSpec(
            scenario_id="SCN-001",
            threat_source=ThreatSource(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                provenance="structural",
            ),
            target_controller=target_controller,
            target_control_action=target_control_action,
            ica_type=UCAType.not_provided,
            defender_bdi=DefenderBDI(
                beliefs=[
                    DefenderBelief(
                        pm_id=belief[0], content=belief[1], vulnerability="vuln"
                    )
                ],
                desires=[DefenderDesire(resp_id=desire[0], content=desire[1])],
                intentions=[
                    DefenderIntention(ca_id=intention[0], content=intention[1])
                ],
            ),
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
            loss_scenario="Scenario",
        )
        return True, ""

    return handler


_h_scenario_spec_bad_belief = _scenario_spec_handler(belief=("PM-99-1", "Bad"))
_h_scenario_spec_bad_desire = _scenario_spec_handler(desire=("RESP-99", "Bad"))
_h_scenario_spec_bad_intention = _scenario_spec_handler(intention=("CA-99-1", "Bad"))
_h_scenario_spec_bad_target_controller = _scenario_spec_handler(
    target_controller="RESP-99"
)
_h_scenario_spec_bad_target_ca = _scenario_spec_handler(target_control_action="CA-99-1")
_h_scenario_spec_target_ca_other_resp = _scenario_spec_handler(
    target_control_action="CA-2-1"
)


def _h_scenario_spec_threat_structural(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a scenario spec with threat source ica_slot_id ... and provenance structural."""
    world.scenario_spec = _make_minimal_scenario_spec()
    return True, ""


def _h_scenario_spec_threat_catalog(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a scenario spec with threat source ica_slot_id ... and provenance catalog_only."""
    spec = _make_minimal_scenario_spec()
    spec.threat_source = ThreatSource(
        ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
        provenance="catalog_only",
    )
    world.scenario_spec = spec
    return True, ""


def _h_scenario_spec_attacker_bdi(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a scenario spec with attacker beliefs, desires, and intentions as free-form strings."""
    world.scenario_spec = _make_minimal_scenario_spec()
    return True, ""


def _h_scenario_spec_catalog_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a scenario spec with catalog context containing OWASP_AGENTIC mapping T2-T3 confidence high."""
    spec = _make_minimal_scenario_spec()
    spec.catalog_context = [
        CatalogMapping(
            catalog="OWASP_AGENTIC",
            id="T2-T3",
            name="Test",
            confidence="high",
        )
    ]
    world.scenario_spec = spec
    return True, ""


def _h_validate_scenario_spec(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the scenario spec is validated against the control structure."""
    if world.scenario_spec is None and world.validation_error is None:
        return False, "No scenario spec to validate"
    if world.validation_error is not None:
        return True, ""
    cs = world.control_structure or _make_minimal_control_structure()
    try:
        world.scenario_spec.validate_against(cs)
        world.validation_succeeded = True
        world.validation_error = None
    except (ValueError, ValidationError) as e:
        world.validation_error = e
        world.validation_succeeded = False
    return True, ""


def _h_env_var_set(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: environment variable <VAR> is set to <value>."""
    match = re.search(r"environment variable (\S+) is set to (\S+)", text)
    if not match:
        return False, f"Could not parse env var step: {text}"
    var_name = match.group(1)
    var_value = match.group(2)
    world.env_overrides[var_name] = var_value
    os.environ[var_name] = var_value
    return True, ""


def _h_no_env_var(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL environment variable is set."""
    match = re.search(r"no (\S+) environment variable is set", text)
    if not match:
        return False, f"Could not parse env var step: {text}"
    var_name = match.group(1)
    world.env_overrides[var_name] = None
    os.environ.pop(var_name, None)
    return True, ""


def _h_llm_client_construct(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLMClient is constructed (with optional base_url and model)."""
    base_url = None
    model = None
    match = re.search(r"base_url (\S+)", text)
    if match:
        base_url = match.group(1)
    match = re.search(r"model (\S+)", text)
    if match:
        model = match.group(1)

    if "without explicit base_url" in text:
        base_url = None

    try:
        world.llm_client = LLMClient(base_url=base_url, model=model)
    except (ValueError, Exception) as e:
        world.validation_error = e
    return True, ""


def _h_llm_client_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLMClient constructed with base_url <url>."""
    match = re.search(r"base_url (\S+)", text)
    base_url = match.group(1) if match else None
    try:
        world.llm_client = LLMClient(base_url=base_url)
    except (ValueError, Exception) as e:
        world.validation_error = e
    return True, ""


def _text_field_handler(owner: str, missing: str, field: str, default: str):
    """Build a Then handler checking ``world.<owner>.<field>`` against the step."""

    def handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
        match = re.search(rf"{field} is (\S+)", text)
        expected = match.group(1) if match else default
        target = getattr(world, owner)
        if target is None:
            return False, missing
        actual = getattr(target, field)
        if actual != expected:
            return False, f"Expected {field} '{expected}' but got '{actual}'"
        return True, ""

    return handler


_h_llm_client_base_url = _text_field_handler(
    "llm_client", "No LLM client constructed", "base_url", ""
)
_h_llm_client_model = _text_field_handler(
    "llm_client", "No LLM client constructed", "model", ""
)


def _h_llm_client_temperature(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the client temperature is <value>."""
    match = re.search(r"temperature is (\S+)", text)
    expected = float(match.group(1)) if match else 0.4
    if world.llm_client is None:
        return False, "No LLM client constructed"
    if world.llm_client.temperature != expected:
        return (
            False,
            f"Expected temperature {expected} but got {world.llm_client.temperature}",
        )
    return True, ""


def _h_llm_valueerror(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a ValueError is raised containing <message>."""
    match = re.search(r"containing (.+)", text)
    fragment = match.group(1).strip() if match else ""
    if world.validation_error is None:
        return (
            False,
            f"Expected ValueError containing '{fragment}' but no error was raised",
        )
    if not isinstance(world.validation_error, ValueError):
        return (
            False,
            f"Expected ValueError but got {type(world.validation_error).__name__}",
        )
    if fragment.lower() not in str(world.validation_error).lower():
        return (
            False,
            f"Expected error containing '{fragment}' but got: {world.validation_error}",
        )
    return True, ""


def _h_llm_headers(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the client extra headers include HTTP-Referer and X-Title."""
    if world.llm_client is None:
        return False, "No LLM client constructed"
    headers = world.llm_client.extra_headers or {}
    if "HTTP-Referer" not in headers:
        return False, f"HTTP-Referer not in extra headers: {headers}"
    if "X-Title" not in headers:
        return False, f"X-Title not in extra headers: {headers}"
    return True, ""


def _h_llm_result_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLMResult with content text, prompt_tokens 100, completion_tokens 50, and duration_ms 5000."""
    world.llm_result = LLMResult(
        content="text",
        prompt_tokens=100,
        completion_tokens=50,
        duration_ms=5000,
    )
    return True, ""


def _h_llm_result_content(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the result content is text."""
    if world.llm_result is None:
        return False, "No LLM result"
    if world.llm_result.content != "text":
        return False, f"Expected content 'text' but got '{world.llm_result.content}'"
    return True, ""


def _llm_result_count_handler(field: str, default: int):
    """Build a Then handler checking an integer LLMResult field against the step."""

    def handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
        match = re.search(rf"{field} is (\d+)", text)
        expected = int(match.group(1)) if match else default
        if world.llm_result is None:
            return False, "No LLM result"
        actual = getattr(world.llm_result, field)
        if actual != expected:
            return False, f"Expected {field} {expected} but got {actual}"
        return True, ""

    return handler


_h_llm_result_prompt_tokens = _llm_result_count_handler("prompt_tokens", 100)
_h_llm_result_completion_tokens = _llm_result_count_handler("completion_tokens", 50)
_h_llm_result_duration = _llm_result_count_handler("duration_ms", 5000)


def _h_call_log_entry_given(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a call log entry with stage ..., step ..., slot_id ..., and scenario_id ..."""
    stage_match = re.search(r"stage ([^,\s]+)", text)
    step_match = re.search(r"step ([^,\s]+)", text)
    slot_match = re.search(r"slot_id ([^,\s]+)", text)
    scenario_match = re.search(r"scenario_id ([^,\s]+)", text)

    slot_id = slot_match.group(1) if slot_match else None
    if slot_id == "null":
        slot_id = None
    scenario_id = scenario_match.group(1) if scenario_match else None
    if scenario_id == "null":
        scenario_id = None

    entry = make_call_log_entry(
        stage=stage_match.group(1) if stage_match else "stage_2",
        step=step_match.group(1) if step_match else "call_1",
        model="test-model",
        slot_id=slot_id,
        scenario_id=scenario_id,
    )
    world.call_log_entries = [entry]
    return True, ""


def _h_call_log_three_entries(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: three call log entries with stages stage_2, stage_3, and stage_5."""
    entries = []
    for stage in ["stage_2", "stage_3", "stage_5"]:
        entries.append(
            make_call_log_entry(
                stage=stage,
                step=f"call_{stage}",
                model="test-model",
            )
        )
    world.call_log_entries = entries
    return True, ""


def _h_call_log_empty(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an empty list of call log entries."""
    world.call_log_entries = []
    return True, ""


def _h_call_log_append(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the entry/entries is/are appended to calls.jsonl."""
    tmp_dir = Path(tempfile.mkdtemp())
    world.call_log_path = tmp_dir / "calls.jsonl"
    append_call_log(world.call_log_entries, tmp_dir)
    return True, ""


def _h_call_log_one_line(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the file contains one valid JSON line with stage ... and step ..."""
    if world.call_log_path is None or not world.call_log_path.exists():
        return False, "No calls.jsonl file found"
    lines = world.call_log_path.read_text().strip().splitlines()
    if len(lines) != 1:
        return False, f"Expected 1 line but got {len(lines)}"
    entry = json.loads(lines[0])
    stage_match = re.search(r"stage (\S+)", text)
    step_match = re.search(r"step (\S+)", text)
    if stage_match and entry.get("stage") != stage_match.group(1):
        return (
            False,
            f"Expected stage '{stage_match.group(1)}' but got '{entry.get('stage')}'",
        )
    if step_match and entry.get("step") != step_match.group(1):
        return (
            False,
            f"Expected step '{step_match.group(1)}' but got '{entry.get('step')}'",
        )
    return True, ""


def _h_call_log_scenario_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the file contains one valid JSON line with scenario_id ..."""
    if world.call_log_path is None or not world.call_log_path.exists():
        return False, "No calls.jsonl file found"
    lines = world.call_log_path.read_text().strip().splitlines()
    if len(lines) != 1:
        return False, f"Expected 1 line but got {len(lines)}"
    entry = json.loads(lines[0])
    scenario_match = re.search(r"scenario_id (\S+)", text)
    if scenario_match and entry.get("scenario_id") != scenario_match.group(1):
        return (
            False,
            f"Expected scenario_id '{scenario_match.group(1)}' but got '{entry.get('scenario_id')}'",
        )
    return True, ""


def _h_call_log_three_lines(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the file contains three valid JSON lines in order."""
    if world.call_log_path is None or not world.call_log_path.exists():
        return False, "No calls.jsonl file found"
    lines = world.call_log_path.read_text().strip().splitlines()
    if len(lines) != 3:
        return False, f"Expected 3 lines but got {len(lines)}"
    for line in lines:
        json.loads(line)  # verify valid JSON
    return True, ""


def _h_call_log_no_file(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no calls.jsonl file is created."""
    if world.call_log_path is not None and world.call_log_path.exists():
        return False, "calls.jsonl file was created but should not have been"
    return True, ""


def _h_yaml_loss_model(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a LossAnalysis model with one loss L-1 and one hazard H-1."""
    world.yaml_model = _make_minimal_loss_analysis()
    return True, ""


def _h_yaml_cs_model(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a ControlStructure model with responsibility RESP-1 and PM-1-1."""
    world.yaml_model = _make_minimal_control_structure()
    return True, ""


def _h_yaml_valid_file(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a YAML file containing a valid loss analysis with loss L-1."""
    model = _make_minimal_loss_analysis()
    tmp_dir = Path(tempfile.mkdtemp())
    world.yaml_path = tmp_dir / "model.yaml"
    write_yaml(model, world.yaml_path)
    return True, ""


def _h_yaml_invalid_file(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a YAML file containing a loss analysis where hazard references non-existent loss."""
    bad_data = {
        "risk_card_losses": [],
        "use_case_losses": [
            {"loss_id": "L-1", "description": "Loss", "provenance": "use_case"},
        ],
        "hazards": [
            {"hazard_id": "H-1", "description": "Hazard", "related_losses": ["L-99"]},
        ],
        "security_constraints": [],
    }
    tmp_dir = Path(tempfile.mkdtemp())
    world.yaml_path = tmp_dir / "bad.yaml"
    world.yaml_path.write_text(_yaml.dump(bad_data), encoding="utf-8")
    return True, ""


def _h_yaml_write(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: write_yaml is called with the model and a file path."""
    tmp_dir = Path(tempfile.mkdtemp())
    world.yaml_path = tmp_dir / "output.yaml"
    write_yaml(world.yaml_model, world.yaml_path)
    return True, ""


def _h_yaml_read(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: read_yaml is called with the path and LossAnalysis class."""
    try:
        world.yaml_read_back = read_yaml(world.yaml_path, LossAnalysis)
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


def _h_yaml_roundtrip(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the model is written to YAML and read back."""
    tmp_dir = Path(tempfile.mkdtemp())
    world.yaml_path = tmp_dir / "roundtrip.yaml"
    write_yaml(world.yaml_model, world.yaml_path)
    model_class = type(world.yaml_model)
    world.yaml_read_back = read_yaml(world.yaml_path, model_class)
    return True, ""


def _h_yaml_file_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a YAML file exists at the path containing loss_id L-1."""
    if world.yaml_path is None or not world.yaml_path.exists():
        return False, "No YAML file found"
    content = world.yaml_path.read_text(encoding="utf-8")
    if "L-1" not in content:
        return False, "YAML file does not contain loss_id L-1"
    return True, ""


def _h_yaml_model_returned(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a LossAnalysis model is returned with loss_id L-1."""
    if world.yaml_read_back is None:
        return False, "No model returned from read_yaml"
    if not isinstance(world.yaml_read_back, LossAnalysis):
        return (
            False,
            f"Expected LossAnalysis but got {type(world.yaml_read_back).__name__}",
        )
    if not any(loss.loss_id == "L-1" for loss in world.yaml_read_back.use_case_losses):
        return False, "Returned model does not have loss_id L-1"
    return True, ""


def _h_yaml_readback_matches(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the read-back model matches the original model."""
    if world.yaml_read_back is None or world.yaml_model is None:
        return False, "Missing model for comparison"
    if world.yaml_read_back.model_dump() != world.yaml_model.model_dump():
        return False, "Read-back model does not match original"
    return True, ""


def _h_yaml_validation_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a validation error is raised."""
    if world.validation_error is None:
        return False, "Expected validation error but none was raised"
    return True, ""


def _h_template_dir_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a prompts directory at <path> containing template <name> with variable <var>."""
    match = re.search(r"directory at (\S+)", text)
    dir_path = match.group(1) if match else "tmp/prompts"

    if dir_path.startswith("tmp/"):
        tmp_dir = Path(tempfile.mkdtemp())
        world.template_dir = tmp_dir
    else:
        world.template_dir = Path(dir_path)

    world.template_dir.mkdir(parents=True, exist_ok=True)

    # Extract template name and variable
    template_match = re.search(r"template (\S+\.j2)", text)
    template_name = template_match.group(1) if template_match else "test.j2"
    var_match = re.search(r"variable (\w+)", text)
    var_name = var_match.group(1) if var_match else "name"

    (world.template_dir / template_name).write_text(
        f"Hello {{{{ {var_name} }}}}", encoding="utf-8"
    )
    return True, ""


def _h_template_dir_two_files(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a prompts directory at tmp/prompts containing templates a.j2 and b.j2."""
    tmp_dir = Path(tempfile.mkdtemp())
    world.template_dir = tmp_dir
    (tmp_dir / "a.j2").write_text("A {{ name }}", encoding="utf-8")
    (tmp_dir / "b.j2").write_text("B {{ name }}", encoding="utf-8")
    return True, ""


def _h_template_dir_var_only(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a prompts directory containing template test.j2 with variable name."""
    return _h_template_dir_given(world, text, examples)


def _h_template_loader_created(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a template loader is created with the directory path."""
    world.template_loader = TemplateLoader(world.template_dir)
    return True, ""


def _h_template_render(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: render_prompt is called with template test.j2 and name World."""
    template_match = re.search(r"template (\S+\.j2)", text)
    template_name = template_match.group(1) if template_match else "test.j2"
    name_match = re.search(r"name (\S+)", text)
    name_value = name_match.group(1) if name_match else "World"
    world.template_rendered = world.template_loader.render_prompt(
        template_name, **{"name": name_value}
    )
    return True, ""


def _h_template_render_no_var(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: render_prompt is called with template test.j2 without providing name."""
    try:
        world.template_loader.render_prompt("test.j2")
    except Exception as e:
        world.validation_error = e
    return True, ""


def _h_template_rendered_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the rendered text contains "..." (quoted) or single word."""
    if world.template_rendered is None:
        return False, "No rendered text"
    quoted = re.search(r'"([^"]+)"', text)
    if quoted:
        expected = quoted.group(1)
    else:
        match = re.search(r"contains (\S+)", text)
        expected = match.group(1) if match else "World"
    if expected not in world.template_rendered:
        snippet = world.template_rendered[:300]
        return (
            False,
            f"Expected '{expected}' in rendered text but it was not found. Start: {snippet}...",
        )
    return True, ""


def _h_template_hash(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: hash_prompt_templates is called with the directory path."""
    world.template_hashes = hash_prompt_templates(world.template_dir)
    return True, ""


def _h_template_hash_result(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a dict is returned with keys a.j2 and b.j2 mapping to 64-character hex digests."""
    if world.template_hashes is None:
        return False, "No template hashes"
    for key in ["a.j2", "b.j2"]:
        if key not in world.template_hashes:
            return (
                False,
                f"Key '{key}' not in hashes: {list(world.template_hashes.keys())}",
            )
        digest = world.template_hashes[key]
        if len(digest) != 64:
            return False, f"Hash for '{key}' is {len(digest)} chars, expected 64"
    return True, ""


def _h_template_undefined_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an undefined variable error is raised."""
    if world.validation_error is None:
        return False, "Expected undefined variable error but none was raised"
    return True, ""


def _h_template_loader_independent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a template loader created with directory tmp/stpa_prompts."""
    tmp_dir = Path(tempfile.mkdtemp())
    world.template_dir = tmp_dir
    world.template_loader = TemplateLoader(tmp_dir)
    return True, ""


def _h_template_no_pipeline_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the loader does not reference the existing pipeline data/prompts directory."""
    if world.template_loader is None:
        return False, "No template loader"
    # The loader's prompts_dir should not contain "data/prompts"
    prompts_dir_str = str(world.template_loader.prompts_dir)
    if "data/prompts" in prompts_dir_str:
        return (
            False,
            f"Template loader references existing pipeline prompts: {prompts_dir_str}",
        )
    return True, ""


def _h_manifest_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a run manifest with run_id ..., run_dir ..., and created_at ..."""
    base_kwargs = {
        "run_id": "RUN-001",
        "run_dir": "output/test",
        "created_at": "2026-08-08T12:00:00Z",
        "model_config": {
            "model": "test-model",
            "base_url": "http://test:8080",
            "temperature": 0.4,
        },
        "input_hashes": {"use_case": "abc123"},
        "prompt_hashes": {"call0_system.j2": "def456"},
        "stage_summary": {
            "stage_2": {
                "calls": 1,
                "duration_ms": 5000,
                "prompt_tokens": 1000,
                "completion_tokens": 500,
            }
        },
    }

    if "slot_count" in text:
        match = re.search(r"slot_count (\d+)", text)
        if match:
            base_kwargs["slot_count"] = int(match.group(1))
    if "na_count" in text:
        match = re.search(r"na_count (\d+)", text)
        if match:
            base_kwargs["na_count"] = int(match.group(1))
    if "fill_rate" in text:
        match = re.search(r"fill_rate ([\d.]+)", text)
        if match:
            base_kwargs["fill_rate"] = float(match.group(1))
    if "scenario_count" in text:
        match = re.search(r"scenario_count (\d+)", text)
        if match:
            base_kwargs["scenario_count"] = int(match.group(1))
    if "critic_findings" in text:
        base_kwargs["critic_findings"] = [
            "gap in hazard coverage",
            "missing constraint for H-2",
        ]
    if "eval_scorecard_path" in text:
        match = re.search(r"eval_scorecard_path (\S+)", text)
        if match:
            base_kwargs["eval_scorecard_path"] = match.group(1)

    try:
        world.manifest = STPARunManifest(**base_kwargs)
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


def _h_manifest_validated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the manifest is validated."""
    # Pydantic validation already happened during construction
    if world.manifest is None and world.validation_error is None:
        return False, "No manifest to validate"
    return True, ""


def _h_manifest_module_imported(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the STPA run manifest module is imported."""
    return True, ""


def _h_manifest_no_coupling(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the module does not import or reference the existing pipeline manifest module."""
    import inspect
    import asago_scenario_generator.stpa.infra.manifest as stpa_manifest

    source = inspect.getsource(stpa_manifest)
    forbidden = [
        "asago_scenario_generator.manifest",
        "asago_scenario_generator.pipeline.manifest",
    ]
    for ref in forbidden:
        if ref in source:
            return False, f"STPA manifest module references '{ref}'"
    return True, ""


def _h_envelope_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario envelope wrapping SCN-001 with narrative text, attack tree dict, and gherkin spec text."""
    spec = world.scenario_spec or _make_minimal_scenario_spec()
    world.scenario_spec = spec
    world.envelope = ScenarioEnvelope(
        scenario_id="SCN-001",
        scenario_spec=spec,
        narrative="Narrative text",
        attack_tree={"root": {"children": []}},
        gherkin_spec=GherkinSpec(
            feature="Test",
            scenario="Test",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        ),
        gherkin_raw="Feature: Test\n  Scenario: Test\n",
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
    )
    return True, ""


def _h_envelope_id_match(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario envelope with scenario_id SCN-001 wrapping spec SCN-001."""
    return _h_envelope_given(world, text, examples)


def _h_envelope_faceting(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario envelope wrapping SCN-001 with target_responsibility RESP-1, ica_type NOT_PROVIDED, and provenance structural."""
    spec = world.scenario_spec or _make_minimal_scenario_spec()
    world.scenario_spec = spec
    world.envelope = ScenarioEnvelope(
        scenario_id="SCN-001",
        scenario_spec=spec,
        narrative="Narrative",
        attack_tree={"root": {}},
        gherkin_spec=GherkinSpec(
            feature="T",
            scenario="T",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        ),
        gherkin_raw="Feature: T\n",
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
    )
    return True, ""


def _h_envelope_catalog(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario envelope wrapping SCN-001 with catalog mappings OWASP_AGENTIC T2-T3 high."""
    spec = world.scenario_spec or _make_minimal_scenario_spec()
    world.scenario_spec = spec
    world.envelope = ScenarioEnvelope(
        scenario_id="SCN-001",
        scenario_spec=spec,
        narrative="Narrative",
        attack_tree={"root": {}},
        gherkin_spec=GherkinSpec(
            feature="T",
            scenario="T",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        ),
        gherkin_raw="Feature: T\n",
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
        catalog_mappings=[
            CatalogMapping(
                catalog="OWASP_AGENTIC",
                id="T2-T3",
                name="Test",
                confidence="high",
            )
        ],
    )
    return True, ""


def _h_envelope_validated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario envelope is validated."""
    if world.envelope is None and world.validation_error is None:
        return False, "No scenario envelope to validate"
    return True, ""


_h_faceting_target_resp = _text_field_handler(
    "envelope", "No envelope", "target_responsibility", "RESP-1"
)


def _h_faceting_ica_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the faceting metadata ica_type is NOT_PROVIDED."""
    match = re.search(r"ica_type is (\S+)", text)
    expected = match.group(1) if match else "NOT_PROVIDED"
    if world.envelope is None:
        return False, "No envelope"
    if world.envelope.ica_type.value != expected:
        return (
            False,
            f"Expected ica_type '{expected}' but got '{world.envelope.ica_type}'",
        )
    return True, ""


_h_faceting_provenance = _text_field_handler(
    "envelope", "No envelope", "provenance", "structural"
)


FEATURE_ID = "infrastructure"


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.register(
        "a control structure with responsibility RESP-1, process model part PM-1-1, and control action CA-1-1",
        _h_cs_with_pm_and_ca,
        source_order=2872,
    )
    api.register(
        "a control structure with responsibilities RESP-1 and RESP-2 where CA-2-1 belongs to RESP-2",
        _h_cs_two_resp_ca_belongs,
        source_order=2873,
    )
    api.register(
        "a valid scenario spec SCN-001 with target_controller RESP-1 and target_control_action CA-1-1",
        _h_scenario_spec_valid,
        source_order=2874,
    )
    api.register(
        "a scenario spec SCN-001 with target_controller RESP-1 and target_control_action CA-1-1",
        _h_scenario_spec_valid,
        source_order=2875,
    )
    api.register(
        "defender belief referencing PM-1-1, desire referencing RESP-1, intention referencing CA-1-1",
        _h_scenario_spec_defender_bdi,
        source_order=2876,
    )
    api.register(
        "a scenario spec with defender belief referencing PM-99-1",
        _h_scenario_spec_bad_belief,
        source_order=2877,
    )
    api.register(
        "a scenario spec with defender desire referencing RESP-99",
        _h_scenario_spec_bad_desire,
        source_order=2878,
    )
    api.register(
        "a scenario spec with defender intention referencing CA-99-1",
        _h_scenario_spec_bad_intention,
        source_order=2879,
    )
    api.register(
        "a scenario spec with target_controller RESP-99$",
        _h_scenario_spec_bad_target_controller,
        source_order=2880,
    )
    api.register(
        "a scenario spec with target_control_action CA-99-1",
        _h_scenario_spec_bad_target_ca,
        source_order=2881,
    )
    api.register(
        "a scenario spec with target_controller RESP-1 and target_control_action CA-2-1",
        _h_scenario_spec_target_ca_other_resp,
        source_order=2882,
    )
    api.register(
        "a scenario spec with threat source ica_slot_id .* and provenance structural",
        _h_scenario_spec_threat_structural,
        source_order=2883,
    )
    api.register(
        "a scenario spec with threat source ica_slot_id .* and provenance catalog_only",
        _h_scenario_spec_threat_catalog,
        source_order=2884,
    )
    api.register(
        "a scenario spec with attacker beliefs, desires, and intentions as free-form strings",
        _h_scenario_spec_attacker_bdi,
        source_order=2885,
    )
    api.register(
        "a scenario spec with catalog context containing",
        _h_scenario_spec_catalog_context,
        source_order=2886,
    )
    api.register(
        "the scenario spec is validated against the control structure",
        _h_validate_scenario_spec,
        source_order=2889,
    )
    api.register(
        "environment variable \\S+ is set to", _h_env_var_set, source_order=2900
    )
    api.register(
        "no \\S+ environment variable is set", _h_no_env_var, source_order=2901
    )
    api.register(
        "an LLMClient is constructed", _h_llm_client_construct, source_order=2902
    )
    api.register(
        "an LLMClient constructed with base_url", _h_llm_client_given, source_order=2903
    )
    api.register("the client base_url is", _h_llm_client_base_url, source_order=2904)
    api.register("the client model is", _h_llm_client_model, source_order=2905)
    api.register(
        "the client temperature is", _h_llm_client_temperature, source_order=2906
    )
    api.register(
        "a ValueError is raised containing", _h_llm_valueerror, source_order=2907
    )
    api.register("the client extra headers include", _h_llm_headers, source_order=2908)
    api.register("an LLMResult with content", _h_llm_result_given, source_order=2909)
    api.register("the result content is", _h_llm_result_content, source_order=2910)
    api.register(
        "the result prompt_tokens is", _h_llm_result_prompt_tokens, source_order=2911
    )
    api.register(
        "the result completion_tokens is",
        _h_llm_result_completion_tokens,
        source_order=2912,
    )
    api.register("the result duration_ms is", _h_llm_result_duration, source_order=2913)
    api.register(
        "a call log entry with stage", _h_call_log_entry_given, source_order=2916
    )
    api.register(
        "three call log entries with stages",
        _h_call_log_three_entries,
        source_order=2917,
    )
    api.register(
        "an empty list of call log entries", _h_call_log_empty, source_order=2918
    )
    api.register(
        "the entry is appended to calls.jsonl", _h_call_log_append, source_order=2919
    )
    api.register(
        "the entries are appended to calls.jsonl", _h_call_log_append, source_order=2920
    )
    api.register(
        "all entries are appended to calls.jsonl", _h_call_log_append, source_order=2921
    )
    api.register(
        "the file contains one valid JSON line with stage",
        _h_call_log_one_line,
        source_order=2922,
    )
    api.register(
        "the file contains one valid JSON line with scenario_id",
        _h_call_log_scenario_id,
        source_order=2923,
    )
    api.register(
        "the file contains three valid JSON lines in order",
        _h_call_log_three_lines,
        source_order=2924,
    )
    api.register(
        "a LossAnalysis model with one loss L-1 and one hazard H-1",
        _h_yaml_loss_model,
        source_order=2928,
    )
    api.register(
        "a ControlStructure model with responsibility RESP-1 and PM-1-1",
        _h_yaml_cs_model,
        source_order=2929,
    )
    api.register(
        "a YAML file containing a valid loss analysis with loss L-1",
        _h_yaml_valid_file,
        source_order=2930,
    )
    api.register(
        "a YAML file containing a loss analysis where hazard references non-existent loss",
        _h_yaml_invalid_file,
        source_order=2931,
    )
    api.register(
        "write_yaml is called with the model and a file path",
        _h_yaml_write,
        source_order=2932,
    )
    api.register(
        "read_yaml is called with the path and LossAnalysis class",
        _h_yaml_read,
        source_order=2933,
    )
    api.register(
        "the model is written to YAML and read back",
        _h_yaml_roundtrip,
        source_order=2934,
    )
    api.register(
        "a YAML file exists at the path containing loss_id L-1",
        _h_yaml_file_exists,
        source_order=2935,
    )
    api.register(
        "a LossAnalysis model is returned with loss_id L-1",
        _h_yaml_model_returned,
        source_order=2936,
    )
    api.register(
        "the read-back model matches the original model",
        _h_yaml_readback_matches,
        source_order=2937,
    )
    api.register(
        "a validation error is raised", _h_yaml_validation_error, source_order=2938
    )
    api.register(
        "a prompts directory at .* containing template .* with variable",
        _h_template_dir_given,
        source_order=2941,
    )
    api.register(
        "a prompts directory at .* containing templates a.j2 and b.j2",
        _h_template_dir_two_files,
        source_order=2942,
    )
    api.register(
        "a prompts directory containing template .* with variable",
        _h_template_dir_var_only,
        source_order=2943,
    )
    api.register(
        "a template loader is created with the directory path",
        _h_template_loader_created,
        source_order=2944,
    )
    api.register(
        "render_prompt is called with template .* and name",
        _h_template_render,
        source_order=2945,
    )
    api.register(
        "render_prompt is called with template .* without providing name",
        _h_template_render_no_var,
        source_order=2946,
    )
    api.register(
        "the rendered text contains", _h_template_rendered_contains, source_order=2947
    )
    api.register(
        "hash_prompt_templates is called with the directory path",
        _h_template_hash,
        source_order=2948,
    )
    api.register(
        "a dict is returned with keys a.j2 and b.j2",
        _h_template_hash_result,
        source_order=2949,
    )
    api.register(
        "an undefined variable error is raised",
        _h_template_undefined_error,
        source_order=2950,
    )
    api.register(
        "a template loader created with directory",
        _h_template_loader_independent,
        source_order=2951,
    )
    api.register(
        "the loader does not reference the existing pipeline data/prompts directory",
        _h_template_no_pipeline_ref,
        source_order=2952,
    )
    api.register("a run manifest with", _h_manifest_given, source_order=2955)
    api.register("the manifest is validated", _h_manifest_validated, source_order=2956)
    api.register(
        "the STPA run manifest module is imported",
        _h_manifest_module_imported,
        source_order=2957,
    )
    api.register(
        "the module does not import or reference the existing pipeline manifest module",
        _h_manifest_no_coupling,
        source_order=2958,
    )
    api.register(
        "a scenario envelope wrapping SCN-001 with narrative text",
        _h_envelope_given,
        source_order=2961,
    )
    api.register(
        "a scenario envelope with scenario_id SCN-001 wrapping spec SCN-001",
        _h_envelope_id_match,
        source_order=2962,
    )
    api.register(
        "a scenario envelope wrapping SCN-001 with target_responsibility",
        _h_envelope_faceting,
        source_order=2963,
    )
    api.register(
        "a scenario envelope wrapping SCN-001 with catalog mappings",
        _h_envelope_catalog,
        source_order=2964,
    )
    api.register(
        "the scenario envelope is validated", _h_envelope_validated, source_order=2965
    )
    api.register(
        "the faceting metadata target_responsibility is",
        _h_faceting_target_resp,
        source_order=2966,
    )
    api.register(
        "the faceting metadata ica_type is", _h_faceting_ica_type, source_order=2967
    )
    api.register(
        "the faceting metadata provenance is", _h_faceting_provenance, source_order=2968
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]

"""Offline HTML visualization of a completed run directory.

The visualizer reads an existing run output directory (the product ``run``
artifacts) and renders one self-contained HTML file with curated sections
for the main artifacts plus a collapsible raw viewer for every file. It is
read-only over the run directory, never contacts a provider, and never
validates artifact contracts: unknown or missing artifacts render as
absent-artifact notes so older runs stay viewable across schema drift.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.html_utils import escape_html
from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.report.synthesis import _items, _mapping, _value
from asago_scenario_generator.stpa.infra.calls_html import (
    _build_call_entries_html,
    _build_detail_html,
    _build_summary_html,
    _compute_summary,
    _read_calls,
)

OUTPUT_FILENAME = "run-visual.html"

# The raw viewer truncates single files beyond this size and records the
# truncation, so one huge nested artifact cannot make the HTML unopenable.
# Set ``max_raw_file_bytes=None`` to disable the cap.
DEFAULT_MAX_RAW_FILE_BYTES = 256_000

_ABSENT = '<p class="absent">Not present in this run directory.</p>'
_SKIP_RAW_NAMES = {".DS_Store", OUTPUT_FILENAME}

_INLINE_CSS = """\
:root { --border:#ccd0d5; --muted:#5f6368; --bg-soft:#f1f3f4; }
body { font:15px system-ui,sans-serif; color:#202124; margin:0; }
nav.sidebar { position:fixed; top:0; left:0; bottom:0; width:230px; overflow-y:auto;
  padding:1rem; background:var(--bg-soft); border-right:1px solid var(--border); }
nav.sidebar h1 { font-size:1rem; margin:.2rem 0 .8rem; }
nav.sidebar a { display:block; padding:.25rem .5rem; color:#202124;
  text-decoration:none; border-radius:4px; font-size:.9rem; }
nav.sidebar a:hover { background:#e4e6e8; }
nav.sidebar a.active { background:#d2e3fc; font-weight:600; }
main { margin-left:250px; padding:1.5rem 2rem; max-width:1200px; }
h2 { border-bottom:2px solid var(--border); padding-bottom:.3rem; margin-top:2.5rem; }
h3 { margin-top:1.5rem; }
table { border-collapse:collapse; width:100%; margin:1rem 0; }
th,td { border:1px solid var(--border); padding:.4rem .55rem; text-align:left;
  vertical-align:top; }
th { background:var(--bg-soft); }
code { font-family:ui-monospace,monospace; }
pre { background:#f8f8f8; border:1px solid #eee; padding:8px; overflow-x:auto;
  font-size:.85em; white-space:pre-wrap; word-wrap:break-word; }
details { margin:.4rem 0; }
details > summary { cursor:pointer; color:#1a4fa0; }
details[open] > summary { margin-bottom:.5rem; }
.absent { color:var(--muted); font-style:italic; }
.badge { display:inline-block; padding:.1rem .5rem; border-radius:10px;
  background:var(--bg-soft); border:1px solid var(--border); font-size:.85em; }
.badge.completed, .badge.verified { background:#d7f0d7; }
.badge.failed { background:#f6d5d5; }
.badge.degraded, .badge.awaiting_review, .badge.awaiting_evidence {
  background:#fff4ce; }
.section-tools { margin:.2rem 0 .6rem; }
.section-tools button { margin-right:.4rem; cursor:pointer; }
.search-box { margin:.2rem 0 .8rem; padding:6px 10px; width:100%; max-width:420px;
  font-size:1em; }
.scenario-card { border:1px solid var(--border); border-radius:6px;
  padding:.6rem .9rem; margin:.8rem 0; }
.scenario-card > summary { font-weight:600; }
tr.not-selected td { color:var(--muted); }
.raw-file summary { font-family:ui-monospace,monospace; font-size:.85em; }
"""

_INLINE_JS = """\
function filterScenarios() {
  var query = document.getElementById('scenario-search').value.toLowerCase();
  var cards = document.querySelectorAll('.scenario-card');
  for (var i = 0; i < cards.length; i++) {
    var hit = cards[i].textContent.toLowerCase().indexOf(query) !== -1;
    cards[i].style.display = hit ? '' : 'none';
  }
}
function toggleAll(anchor, open) {
  var section = document.getElementById(anchor);
  if (!section) { return; }
  var blocks = section.querySelectorAll('details');
  for (var i = 0; i < blocks.length; i++) { blocks[i].open = open; }
}
function spy() {
  var current = null;
  var top = window.scrollY + 90;
  var sections = document.querySelectorAll('main section.viz-section');
  for (var i = 0; i < sections.length; i++) {
    if (sections[i].offsetTop <= top) { current = sections[i].id; }
  }
  var links = document.querySelectorAll('nav.sidebar a');
  for (var j = 0; j < links.length; j++) {
    var active = links[j].getAttribute('href') === '#' + current;
    links[j].classList.toggle('active', active);
  }
}
window.addEventListener('scroll', spy);
window.addEventListener('load', spy);
"""


# --------------------------------------------------------------------------- #
# Lenient artifact loading
# --------------------------------------------------------------------------- #


def _load_structured(path: Path) -> Any:
    """Parse one YAML or JSON artifact file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _load_optional(run_dir: Path, relative: str) -> Any:
    """Load one artifact, returning None when absent or unparsable."""
    path = run_dir / relative
    if not path.is_file():
        return None
    try:
        return _load_structured(path)
    except Exception:  # noqa: BLE001 - lenient viewer for schema drift
        return None


def _scalar(value: Any) -> str:
    """Render one table cell value, summarizing nested collections."""
    if value is None:
        return "—"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float, str)):
        return escape_html(str(value))
    if isinstance(value, (list, dict)):
        text = json.dumps(value, default=str)
        if len(text) > 160:
            kind = "keys" if isinstance(value, dict) else "items"
            return f"<em>{len(value)} {kind}</em>"
        return escape_html(text)
    return escape_html(str(value))


def _kv_table(pairs: list[tuple[str, Any]]) -> str:
    """Render one key/value table with escaped scalar values."""
    rows = "".join(
        f"<tr><th>{escape_html(key)}</th><td>{_scalar(value)}</td></tr>"
        for key, value in pairs
    )
    return f"<table><tbody>{rows}</tbody></table>"


def _columns_table(items: list[Any], columns: list[tuple[str, str]]) -> str:
    """Render one table with explicit ``(heading, field)`` columns."""
    if not items:
        return _ABSENT
    header = "".join(f"<th>{escape_html(heading)}</th>" for heading, _ in columns)
    rows = []
    for item in items:
        cells = "".join(
            f"<td>{_scalar(_value(item, field))}</td>" for _, field in columns
        )
        rows.append(f"<tr>{cells}</tr>")
    return (
        f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


_IDENTITY_FIELDS = (
    "obligation_id",
    "hazard_id",
    "constraint_id",
    "loss_id",
    "resp_id",
    "cp_id",
    "scenario_id",
    "risk_ref",
)


def _records_details(items: list[Any], label: str) -> str:
    """Render each record of a list as one collapsible key/value table."""
    if not items:
        return _ABSENT
    blocks = []
    for index, item in enumerate(items, start=1):
        if isinstance(item, dict):
            pairs = sorted(_mapping(item).items())
            identity = _value(item, *_IDENTITY_FIELDS)
        else:
            pairs = []
            identity = None
        summary = escape_html(str(identity)) if identity is not None else f"#{index}"
        body = _kv_table(pairs) if pairs else f"<pre>{escape_html(str(item))}</pre>"
        blocks.append(
            f"<details><summary>{escape_html(label)} {summary}</summary>{body}</details>"
        )
    return "\n".join(blocks)


def _badge(value: Any) -> str:
    """Render one status badge for a stable run status value."""
    status = str(_value(value, "run_status", "status") or value or "unknown")
    return f'<span class="badge {escape_html(status)}">{escape_html(status)}</span>'


def _details_block(label: str, content: str, *, open_: bool = False) -> str:
    """Render one collapsible block with a fixed label."""
    attr = " open" if open_ else ""
    return f"<details{attr}><summary>{escape_html(label)}</summary>{content}</details>"


# --------------------------------------------------------------------------- #
# Curated sections
# --------------------------------------------------------------------------- #


def _overview_html(run_dir: Path) -> str:
    """Render run identity, status, diagnostics, and pin tables."""
    run_manifest = _load_optional(run_dir, "run-manifest.yaml")
    synth_manifest = _load_optional(run_dir, "synthesis-manifest.yaml")
    if run_manifest is None and synth_manifest is None:
        return _ABSENT
    parts: list[str] = []
    if synth_manifest is not None:
        status = _value(synth_manifest, "run_status") or "unknown"
        reason = _value(synth_manifest, "run_status_reason")
        parts.append(
            "<p>Scenario generation status: "
            f"{_badge(status)}"
            + (f" — {escape_html(str(reason))}" if reason else "")
            + "</p>"
        )
    if run_manifest is not None:
        parts.append(
            _kv_table(
                [
                    ("Run ID", _value(run_manifest, "run_id")),
                    ("Created", _value(run_manifest, "created_at")),
                    ("Scenario count", _value(run_manifest, "scenario_count")),
                    (
                        "Validation errors",
                        _value(run_manifest, "validation_error_count"),
                    ),
                    ("Max workers", _value(run_manifest, "max_workers")),
                ]
            )
        )
        model_config = _mapping(_value(run_manifest, "model_config"))
        if model_config:
            parts.append("<h3>Model configuration</h3>")
            parts.append(_kv_table(sorted(model_config.items())))
        stage_summary = _mapping(_value(run_manifest, "stage_summary"))
        if stage_summary:
            parts.append("<h3>Stage summary</h3>")
            parts.append(_kv_table(sorted(stage_summary.items())))
        diagnostics = [
            (label, message)
            for field, label in (
                ("stage_errors", "Error"),
                ("stage_warnings", "Warning"),
            )
            for message in _items(run_manifest, field)
        ]
        if diagnostics:
            parts.append("<h3>Analysis diagnostics</h3>")
            parts.append(_kv_table(diagnostics))
    if synth_manifest is not None:
        pins: list[tuple[str, Any]] = [
            ("Schema version", _value(synth_manifest, "schema_version")),
            ("Run ID", _value(synth_manifest, "run_id")),
            ("Created", _value(synth_manifest, "created_at")),
            (
                "Capability profile digest",
                _value(synth_manifest, "capability_profile_digest"),
            ),
            (
                "Capability snapshot digest",
                _value(synth_manifest, "capability_snapshot_digest"),
            ),
            (
                "Qualification facts digest",
                _value(synth_manifest, "qualification_facts_digest"),
            ),
            (
                "Taxonomy inputs digest",
                _value(synth_manifest, "taxonomy_inputs_digest"),
            ),
            ("Plan digest", _value(synth_manifest, "plan_digest")),
            (
                "Baseline loss analysis digest",
                _value(synth_manifest, "baseline_loss_analysis_digest"),
            ),
        ]
        parts.append("<h3>Source pins</h3>")
        parts.append(_kv_table(pins))
        for pin_group in ("source_artifacts", "catalog_pins", "mapping_pins"):
            entries = _mapping(_value(synth_manifest, pin_group))
            if entries:
                parts.append(
                    _details_block(pin_group, _kv_table(sorted(entries.items())))
                )
    return "\n".join(parts)


def _bdi_list(items: tuple[Any, ...]) -> str:
    """Render a BDI collection as one escaped list."""
    if not items:
        return "—"
    rendered = []
    for item in items:
        if isinstance(item, dict):
            content = _value(item, "content") or str(item)
            marker = _value(item, "pm_id", "resp_id", "ca_id")
            text = f"{marker}: {content}" if marker else str(content)
        else:
            text = str(item)
        rendered.append(f"<li>{escape_html(text)}</li>")
    return "<ul>" + "".join(rendered) + "</ul>"


def _defender_beliefs_html(beliefs: tuple[Any, ...]) -> str:
    """Render defender beliefs, marking beliefs not selected in this scenario."""
    if not beliefs:
        return "—"
    rows = []
    for belief in beliefs:
        vulnerability = str(_value(belief, "vulnerability") or "")
        row_class = (
            ' class="not-selected"' if "not selected" in vulnerability.lower() else ""
        )
        rows.append(
            f"<tr{row_class}><td><code>{escape_html(str(_value(belief, 'pm_id') or ''))}</code></td>"
            f"<td>{escape_html(str(_value(belief, 'content') or ''))}</td>"
            f"<td>{escape_html(vulnerability)}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Process model</th><th>Belief</th>"
        f"<th>Vulnerability</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _scenario_card(run_dir: Path, scenario_path: Path) -> str:
    """Render one scenario card with its execution view and Gherkin text."""
    scenario_id = scenario_path.stem
    data = _load_structured(scenario_path)
    spec = _mapping(_value(data, "scenario_spec"))
    projection = _load_optional(
        run_dir, f"scenarios/canonical/{scenario_id}.projection.yaml"
    )

    threat = _mapping(_value(spec, "threat_source"))
    head = [
        ("ICA slot", _value(threat, "ica_slot_id")),
        ("ICA", _value(threat, "ica_id")),
        ("ICA type", _value(spec, "ica_type")),
        ("Controller", _value(spec, "target_controller")),
        ("Control action", _value(spec, "target_control_action")),
        ("Loss scenario", _value(spec, "loss_scenario")),
    ]
    outcome = _mapping(_value(spec, "unsafe_outcome_condition"))
    outcome_pairs = [
        (key, value) for key, value in sorted(outcome.items()) if key not in {"type"}
    ]
    hazards = ", ".join(map(str, _items(spec, "unsafe_outcome_hazard_refs"))) or "—"
    constraints = (
        ", ".join(map(str, _items(spec, "unsafe_outcome_constraint_refs"))) or "—"
    )

    causal_factors = [
        _kv_table(
            [
                ("Factor", _value(factor, "factor_id") or index),
                ("Kind", _value(factor, "kind")),
                (
                    "Source",
                    _value(factor, "source_id")
                    or _value(factor, "structural_source_id"),
                ),
                ("Evidence status", _value(factor, "evidence_status")),
                ("Description", _value(factor, "description")),
            ]
        )
        for index, factor in enumerate(_items(spec, "causal_factors"), start=1)
    ]
    factors_html = "\n".join(causal_factors) if causal_factors else _ABSENT

    attacker = _mapping(_value(spec, "attacker_bdi"))
    defender = _mapping(_value(spec, "defender_bdi"))
    attacker_html = "".join(
        f"<h4>{escape_html(name.title())}</h4>{_bdi_list(_items(attacker, name))}"
        for name in ("beliefs", "desires", "intentions")
        if _items(attacker, name)
    )
    defender_details = _details_block(
        "Defender BDI (complete belief annotations)",
        "".join(
            f"<h4>{escape_html(name.title())}</h4>"
            + (
                _defender_beliefs_html(_items(defender, name))
                if name == "beliefs"
                else _bdi_list(_items(defender, name))
            )
            for name in ("beliefs", "desires", "intentions")
        ),
    )

    execution_html = _ABSENT
    if projection is not None:
        classification = _mapping(_value(projection, "execution_classification"))
        contract = _mapping(_value(projection, "execution_contract"))
        delivery = _mapping(_value(contract, "delivery"))
        requirements = _items(contract, "resource_requirements")
        execution_html = (
            _kv_table(
                [
                    ("Disposition", _value(contract, "disposition")),
                    ("Delivery class", _value(delivery, "delivery_class")),
                    ("Action kind", _value(contract, "action_kind")),
                    (
                        "Binding completeness",
                        _value(classification, "binding_completeness"),
                    ),
                    ("Environment basis", _value(classification, "environment_basis")),
                    ("Profile fit", _value(classification, "profile_fit")),
                    ("Candidate", _value(projection, "candidate_id")),
                ]
            )
            + _details_block(
                "Resource requirements",
                _records_details(requirements, "requirement"),
            )
            + _details_block(
                "Resolved bindings",
                _columns_table(
                    _items(classification, "resolved_bindings"),
                    [
                        ("Operation", "operation_id"),
                        ("Resource", "resource_id"),
                        ("Requirement", "requirement_id"),
                    ],
                ),
            )
        )

    feature_path = run_dir / "scenarios" / f"{scenario_id}.feature"
    feature_html = ""
    if feature_path.is_file():
        feature_text = escape_html(feature_path.read_text(encoding="utf-8"))
        feature_html = _details_block("Gherkin", f"<pre>{feature_text}</pre>")

    outcome_html = _kv_table(outcome_pairs) if outcome_pairs else _ABSENT
    return (
        f'<details class="scenario-card" open data-scenario="{escape_html(scenario_id)}">'
        f"<summary><code>{escape_html(scenario_id)}</code>"
        f" — {escape_html(str(_value(spec, 'ica_type') or 'scenario'))}</summary>"
        + _kv_table(head)
        + "<h4>Causal factors</h4>"
        + factors_html
        + "<h4>Observable unsafe outcome</h4>"
        + outcome_html
        + f"<p>Hazards: {hazards} · Constraints: {constraints}</p>"
        + "<h4>Attacker BDI</h4>"
        + (attacker_html or _ABSENT)
        + defender_details
        + "<h4>Execution view</h4>"
        + execution_html
        + feature_html
        + "</details>"
    )


def _scenarios_html(run_dir: Path) -> str:
    """Render all scenario cards with a text filter box."""
    scenario_dir = run_dir / "scenarios"
    paths = sorted(scenario_dir.glob("SCN-*.yaml")) if scenario_dir.is_dir() else []
    if not paths:
        return _ABSENT
    cards = []
    for path in paths:
        try:
            cards.append(_scenario_card(run_dir, path))
        except Exception:  # noqa: BLE001 - lenient viewer for schema drift
            cards.append(
                '<details class="scenario-card">'
                f"<summary>{escape_html(path.stem)}</summary>"
                '<p class="absent">Scenario could not be rendered.</p></details>'
            )
    tools = (
        '<div class="section-tools">'
        '<input type="text" id="scenario-search" class="search-box" '
        'placeholder="Filter scenarios by text..." onkeyup="filterScenarios()">'
        '<button type="button" onclick="toggleAll(\'scenarios\', true)">Expand all</button>'
        '<button type="button" onclick="toggleAll(\'scenarios\', false)">Collapse all</button>'
        "</div>"
    )
    return tools + "\n".join(cards)


def _authored_html(run_dir: Path) -> str:
    """Render the authored-scenarios candidates with accepted and rejected rows."""
    authored = _load_optional(run_dir, "authored-scenarios.yaml")
    candidates = _items(authored, "candidates")
    if not candidates:
        return _ABSENT
    blocks = []
    for index, candidate in enumerate(candidates, start=1):
        accepted_items = _items(candidate, "accepted")
        rejected_items = _items(candidate, "rejected")
        error = _value(candidate, "error")
        no_scenario = _value(candidate, "no_scenario_reason")
        accepted_blocks = []
        for accepted in accepted_items:
            safe = "".join(
                f"<li>{escape_html(str(item))}</li>"
                for item in _items(accepted, "safe_behaviors")
            )
            facts = _records_details(_items(accepted, "state_facts_used"), "state fact")
            accepted_blocks.append(
                _kv_table(
                    [
                        ("Adversary kind", _value(accepted, "adversary_kind")),
                        ("Deviation category", _value(accepted, "deviation_category")),
                        ("Gain", _value(accepted, "gain")),
                        ("Reaches target via", _value(accepted, "reaches_target_via")),
                        ("Oracle kind", _value(accepted, "oracle_kind")),
                        ("Oracle text", _value(accepted, "oracle_text")),
                        ("Stimulus", _value(accepted, "stimulus_text")),
                        ("Safe behaviors", safe or "—"),
                        ("State facts used", facts),
                    ]
                )
            )
        rejected_rows = "".join(
            "<tr>"
            f"<td>{_scalar(_value(item, 'condition_index'))}</td>"
            f"<td>{_scalar(_value(item, 'reason'))}</td>"
            f"<td>{_scalar(_value(item, 'detail'))}</td>"
            "</tr>"
            for item in rejected_items
        )
        rejected_html = (
            "<table><thead><tr><th>Condition</th><th>Reason</th><th>Detail</th>"
            f"</tr></thead><tbody>{rejected_rows}</tbody></table>"
            if rejected_rows
            else ""
        )
        header = _kv_table(
            [
                ("Constraint", _value(candidate, "constraint_id")),
                ("Action", _value(candidate, "action")),
                ("Accepted", len(accepted_items)),
                ("Rejected", len(rejected_items)),
                ("Error", error),
                ("No-scenario reason", no_scenario),
            ]
        )
        body = ""
        if accepted_blocks:
            body += "<h4>Accepted scenarios</h4>" + "\n".join(accepted_blocks)
        if rejected_html:
            body += "<h4>Rejected conditions</h4>" + rejected_html
        blocks.append(
            _details_block(f"Candidate {index}", header + body, open_=bool(body))
        )
    return "\n".join(blocks)


def _loss_analysis_html(run_dir: Path) -> str:
    """Render losses, hazards, security constraints, and gate results."""
    loss = _load_optional(run_dir, "loss-analysis.yaml")
    parts: list[str] = []
    if loss is None:
        parts.append(_ABSENT)
    else:
        losses = list(_items(loss, "use_case_losses")) + list(
            _items(loss, "risk_card_losses")
        )
        parts.append("<h3>Losses</h3>")
        parts.append(
            _columns_table(
                losses,
                [
                    ("Loss", "loss_id"),
                    ("Description", "description"),
                    ("Provenance", "provenance"),
                ],
            )
        )
        parts.append("<h3>Hazards</h3>")
        parts.append(
            _columns_table(
                _items(loss, "hazards"),
                [
                    ("Hazard", "hazard_id"),
                    ("Description", "description"),
                    ("Related losses", "related_losses"),
                ],
            )
        )
        parts.append("<h3>Security constraints</h3>")
        parts.append(
            _columns_table(
                _items(loss, "security_constraints"),
                [
                    ("Constraint", "constraint_id"),
                    ("Rule", "rule"),
                    ("Applies when", "applies_when"),
                    ("Related hazards", "related_hazards"),
                ],
            )
        )
        dispositions = _items(loss, "risk_dispositions")
        parts.append(
            _details_block(
                f"Risk dispositions ({len(dispositions)})",
                _columns_table(
                    dispositions,
                    [
                        ("Risk", "risk_ref"),
                        ("Disposition", "disposition"),
                        ("Losses", "loss_ids"),
                    ],
                ),
            )
        )
    gates = _load_optional(run_dir, "loss-analysis-gates.yaml")
    if gates is not None:
        parts.append("<h3>Gate results</h3>")
        for check_name, values in sorted(_mapping(gates).items()):
            pairs = [
                (key, value)
                for key, value in _mapping(values).items()
                if not isinstance(value, (dict, list))
            ]
            label = f"{check_name} (passed: {_scalar(_value(values, 'passed'))})"
            parts.append(_details_block(label, _kv_table(pairs)))
    return "\n".join(parts)


def _control_structure_html(run_dir: Path) -> str:
    """Render responsibilities, processes, and coordination links."""
    control = _load_optional(run_dir, "control-structure.yaml")
    parts: list[str] = []
    if control is None:
        parts.append(_ABSENT)
    else:
        parts.append("<h3>Responsibilities</h3>")
        responsibilities = _items(control, "responsibilities")
        for responsibility in responsibilities:
            identity = _value(responsibility, "resp_id")
            description = _value(responsibility, "description")
            nested = [
                (key, value)
                for key, value in _mapping(responsibility).items()
                if isinstance(value, list) and value
            ]
            body = _records_details(nested[0][1], nested[0][0]) if nested else ""
            extra = "".join(
                _details_block(key, _records_details(value, key))
                for key, value in nested[1:]
            )
            parts.append(
                _details_block(
                    f"{identity} — {description}",
                    body + extra,
                    open_=False,
                )
                if body or extra
                else f"<p>{escape_html(str(identity))}: {escape_html(str(description))}</p>"
            )
        parts.append("<h3>Controlled processes</h3>")
        parts.append(
            _columns_table(
                _items(control, "controlled_processes"),
                [("Process", "cp_id"), ("Description", "description")],
            )
        )
        parts.append("<h3>Coordination links</h3>")
        links = _items(control, "coordination_links")
        parts.append(
            _records_details(links, "link")
            if links
            else '<p class="absent">No coordination links.</p>'
        )
    derived = _load_optional(run_dir, "target-derived-structure.yaml")
    if derived is not None:
        parts.append("<h3>Target-derived structure</h3>")
        parts.append(_kv_table(sorted(_mapping(derived).items())))
    return "\n".join(parts)


def _coverage_html(run_dir: Path) -> str:
    """Render obligations, accounting, realization, and Phase 2 artifacts."""
    parts: list[str] = []

    plan = _load_optional(run_dir, "taxonomy-obligation-plan.yaml")
    if plan is None:
        parts.append("<h3>Obligation plan</h3>" + _ABSENT)
    else:
        parts.append("<h3>Obligation plan</h3>")
        parts.append(_kv_table(sorted(_mapping(_value(plan, "summary")).items())))
        parts.append(
            _details_block(
                f"Obligations ({len(_items(plan, 'obligations'))})",
                _columns_table(
                    _items(plan, "obligations"),
                    [
                        ("Obligation", "obligation_id"),
                        ("Risk", "risk_ref"),
                        ("Pattern", "attack_pattern_id"),
                        ("Scope", "scope_disposition"),
                        ("Qualification", "qualification_disposition"),
                        ("Correspondence", "correspondence_disposition"),
                    ],
                ),
                open_=True,
            )
        )

    consideration = _load_optional(run_dir, "obligation-consideration.yaml")
    parts.append("<h3>Obligation consideration</h3>")
    if consideration is None:
        parts.append(_ABSENT)
    else:
        routes = _items(consideration, "final_routes")
        parts.append(
            _details_block(
                f"Final routes ({len(routes)})",
                _columns_table(
                    routes,
                    [("Obligation", "obligation_id"), ("Disposition", "disposition")],
                ),
            )
        )
        diagnostics = _items(consideration, "diagnostics")
        parts.append(
            _details_block(
                f"Diagnostics ({len(diagnostics)})",
                _records_details(diagnostics, "diagnostic"),
            )
        )

    accounting = _load_optional(run_dir, "obligation-accounting.yaml")
    parts.append("<h3>Provisional accounting</h3>")
    if accounting is None:
        parts.append(_ABSENT)
    else:
        parts.append(_kv_table(sorted(_mapping(_value(accounting, "summary")).items())))
        parts.append(
            _details_block(
                f"Accounting rows ({len(_items(accounting, 'rows'))})",
                _columns_table(
                    _items(accounting, "rows"),
                    [
                        ("Obligation", "obligation_id"),
                        ("Disposition", "disposition"),
                        ("Slots", "slot_ids"),
                        ("ICAs", "ica_ids"),
                        ("Candidates", "exec_candidate_ids"),
                        ("Hazards", "hazard_ids"),
                        ("Constraints", "constraint_ids"),
                    ],
                ),
            )
        )

    realization = _load_optional(run_dir, "scenario-realization.yaml")
    parts.append("<h3>Scenario realization</h3>")
    if realization is None:
        parts.append(_ABSENT)
    else:
        parts.append(
            _kv_table(sorted(_mapping(_value(realization, "summary")).items()))
        )
        parts.append(
            _details_block(
                f"Records ({len(_items(realization, 'records'))})",
                _columns_table(
                    _items(realization, "records"),
                    [
                        ("Obligation", "obligation_id"),
                        ("ICA", "ica_id"),
                        ("Status", "status"),
                        ("Stop reason", "stop_reason"),
                        ("Scenarios", "scenario_ids"),
                    ],
                ),
            )
        )

    proposals = _load_optional(run_dir, "correspondence-proposals.yaml")
    reconciliation = _load_optional(run_dir, "correspondence-reconciliation.yaml")
    parts.append("<h3>Correspondence</h3>")
    if proposals is None and reconciliation is None:
        parts.append(_ABSENT)
    else:
        if proposals is not None:
            count = len(_items(proposals, "proposals"))
            parts.append(
                _details_block(
                    f"Proposals ({count})",
                    _records_details(_items(proposals, "proposals"), "proposal"),
                )
            )
        if reconciliation is not None:
            parts.append(
                _kv_table(
                    [
                        ("Valid", _value(reconciliation, "is_valid")),
                        (
                            "Accepted relations",
                            len(_items(reconciliation, "accepted_relations")),
                        ),
                        ("Errors", len(_items(reconciliation, "errors"))),
                    ]
                )
            )
            parts.append(
                _details_block(
                    "Accepted relations",
                    _records_details(
                        _items(reconciliation, "accepted_relations"), "relation"
                    ),
                )
            )

    assessment = _load_optional(run_dir, "hybrid-coverage-assessment.yaml")
    parts.append("<h3>Hybrid coverage assessment</h3>")
    if assessment is None:
        parts.append(_ABSENT)
    else:
        diagnostics = _mapping(_value(assessment, "diagnostics"))
        parts.append(_kv_table(sorted(diagnostics.items())))
        for matrix in (
            "structural_consideration",
            "taxonomy_correspondence",
            "scenario_realization",
        ):
            rows = _items(assessment, matrix)
            parts.append(
                _details_block(
                    f"{matrix} ({len(rows)})",
                    _records_details(rows, "row"),
                )
            )
    return "\n".join(parts)


def _target_realization_html(run_dir: Path) -> str:
    """Render the additive target-realization pass when present."""
    realization = _load_optional(run_dir, "target-realization.yaml")
    if realization is None:
        return (
            "<p>No execution target profile was supplied; scenarios remain "
            "target-agnostic or parameterized.</p>"
        )
    parts = [_kv_table(sorted(_mapping(_value(realization, "summary")).items()))]
    rows = _items(realization, "rows")
    parts.append(
        _details_block(
            f"Rows ({len(rows)})",
            _records_details(rows, "row"),
        )
    )
    diagnostics = _items(realization, "diagnostics")
    if diagnostics:
        parts.append(
            _details_block(
                f"Diagnostics ({len(diagnostics)})",
                _records_details(diagnostics, "diagnostic"),
            )
        )
    return "\n".join(parts)


def _execution_bundle_html(run_dir: Path) -> str:
    """Render the published execution bundle summary."""
    bundle = _load_optional(run_dir, "execution-bundle.json")
    if bundle is None:
        return _ABSENT
    entries = _items(bundle, "entries")
    header = _kv_table(
        [
            ("Schema version", _value(bundle, "schema_version")),
            ("Run ID", _value(bundle, "run_id")),
            ("Bundle digest", _value(bundle, "bundle_digest")),
            ("Producer", _scalar(_value(bundle, "producer"))),
            ("Entries", len(entries)),
        ]
    )
    rows = "".join(
        "<tr>"
        f"<td><code>{escape_html(str(_value(entry, 'scenario_id') or ''))}</code></td>"
        f"<td><code>{escape_html(str(_value(entry, 'candidate_id') or ''))}</code></td>"
        f"<td><code>{escape_html(str(_value(entry, 'ica_slot_id') or ''))}</code></td>"
        f"<td><code>{escape_html(str(_value(entry, 'ica_id') or ''))}</code></td>"
        "</tr>"
        for entry in entries
    )
    table = (
        "<table><thead><tr><th>Scenario</th><th>Candidate</th><th>ICA slot</th>"
        f"<th>ICA</th></tr></thead><tbody>{rows}</tbody></table>"
        if rows
        else _ABSENT
    )
    return header + table


def _evaluation_html(run_dir: Path) -> str:
    """Render eval scorecard, gold scores, and coverage gaps."""
    parts: list[str] = []
    scorecard = _load_optional(run_dir, "eval-scorecard.yaml")
    if scorecard is None:
        parts.append("<h3>Eval scorecard</h3>" + _ABSENT)
    else:
        parts.append("<h3>Eval scorecard</h3>")
        for group, values in sorted(_mapping(_value(scorecard, "metrics")).items()):
            scalar_pairs = [
                (key, value)
                for key, value in _mapping(values).items()
                if not isinstance(value, (dict, list))
            ]
            if scalar_pairs:
                parts.append(_details_block(group, _kv_table(scalar_pairs)))
        validation = _value(scorecard, "validation")
        if validation is not None:
            parts.append(
                _details_block(
                    "Stage-local validation",
                    _records_details(
                        _value(validation, "stage_local_errors") or [], "error"
                    ),
                )
            )
    for name, label in (
        ("gold-score.yaml", "Gold score"),
        ("gold-review.yaml", "Gold review"),
    ):
        payload = _load_optional(run_dir, name)
        if payload is not None:
            parts.append(f"<h3>{label}</h3>")
            parts.append(_kv_table(sorted(_mapping(payload).items())))
    gaps = _load_optional(run_dir, "coverage-gaps.json")
    if gaps is not None:
        parts.append("<h3>Coverage gaps</h3>")
        text = json.dumps(gaps, indent=2, default=str)
        parts.append(f"<pre>{escape_html(text)}</pre>")
    return "\n".join(parts)


def _calls_section(run_dir: Path, filename: str) -> str:
    """Render one calls.jsonl file with the shared call-inspector builders."""
    path = run_dir / filename
    if not path.is_file():
        return _ABSENT
    entries = _read_calls(path)
    summary = _compute_summary(entries)
    sections = [_build_summary_html(summary)]
    if entries:
        sections.append(_build_detail_html(entries))
        sections.append(
            _details_block("Full call content", _build_call_entries_html(entries))
        )
    return "\n".join(sections)


def _provider_calls_html(run_dir: Path) -> str:
    """Render provider call evidence for each recorded calls file."""
    parts: list[str] = []
    for filename, heading in (
        ("calls.jsonl", "Product calls"),
        ("artifact-author-calls.jsonl", "Artifact-author calls"),
    ):
        parts.append(f"<h3>{heading}</h3>")
        parts.append(_calls_section(run_dir, filename))
    return "\n".join(parts)


def _raw_artifacts_html(run_dir: Path, max_raw_file_bytes: int | None) -> str:
    """Render every file in the run directory as a collapsible raw viewer."""
    files = sorted(
        path
        for path in run_dir.rglob("*")
        if path.is_file() and path.name not in _SKIP_RAW_NAMES
    )
    if not files:
        return _ABSENT
    blocks = []
    for path in files:
        relative = path.relative_to(run_dir).as_posix()
        size = path.stat().st_size
        note = ""
        read_size = (
            size if max_raw_file_bytes is None else min(size, max_raw_file_bytes)
        )
        try:
            with path.open("rb") as handle:
                data = handle.read(read_size)
            text = data.decode("utf-8", errors="replace")
        except OSError:
            text = f"<unreadable file, {size} bytes>"
        if read_size < size:
            note = (
                f"\n[truncated: showing first {read_size} of {size} bytes; "
                "read the file directly for the full content]"
            )
        blocks.append(
            f'<details class="raw-file"><summary>{escape_html(relative)} '
            f"({size} bytes)</summary>"
            f"<pre>{escape_html(text)}{escape_html(note)}</pre></details>"
        )
    return "\n".join(blocks)


# --------------------------------------------------------------------------- #
# Page composition
# --------------------------------------------------------------------------- #

_SECTIONS = (
    ("overview", "Run overview", _overview_html),
    ("scenarios", "Scenarios", _scenarios_html),
    ("authored", "Authored scenarios", _authored_html),
    ("loss-analysis", "Loss analysis", _loss_analysis_html),
    ("control-structure", "Control structure", _control_structure_html),
    ("coverage", "Obligations & coverage", _coverage_html),
    ("target-realization", "Target realization", _target_realization_html),
    ("execution-bundle", "Execution bundle", _execution_bundle_html),
    ("evaluation", "Evaluation", _evaluation_html),
    ("calls", "Provider calls", _provider_calls_html),
    ("raw", "Raw artifacts", _raw_artifacts_html),
)


def render_run_visual(
    run_dir: Path,
    output_path: Path | None = None,
    *,
    max_raw_file_bytes: int | None = DEFAULT_MAX_RAW_FILE_BYTES,
) -> Path:
    """Render one run directory into a self-contained HTML visualization.

    The function is read-only over *run_dir* except for the output HTML
    itself, which defaults to ``<run-dir>/run-visual.html``. Raw viewer
    entries for single files beyond ``max_raw_file_bytes`` are truncated
    with an explicit note; pass ``None`` to keep every byte.
    """
    run_dir = Path(run_dir)
    target = Path(output_path) if output_path is not None else run_dir / OUTPUT_FILENAME

    nav_links = "".join(
        f'<a href="#{anchor}">{escape_html(title)}</a>'
        for anchor, title, _ in _SECTIONS
    )
    body_parts = []
    for anchor, title, builder in _SECTIONS:
        try:
            if builder is _raw_artifacts_html:
                content = builder(run_dir, max_raw_file_bytes)
            else:
                content = builder(run_dir)
        except Exception as exc:  # noqa: BLE001 - one bad artifact never blocks the rest
            content = (
                f'<p class="absent">Section failed to render: '
                f"{escape_html(str(exc))}</p>"
            )
        body_parts.append(
            f'<section id="{anchor}" class="viz-section">'
            f"<h2>{escape_html(title)}</h2>{content}</section>"
        )
    body = "\n".join(body_parts)

    html = (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        f"<title>Run visualization: {escape_html(run_dir.name)}</title>\n"
        f"<style>\n{_INLINE_CSS}</style>\n"
        "</head><body>\n"
        f'<nav class="sidebar"><h1>{escape_html(run_dir.name)}</h1>{nav_links}</nav>\n'
        f"<main>\n{body}\n</main>\n"
        f"<script>\n{_INLINE_JS}</script>\n"
        "</body></html>\n"
    )
    return atomic_write_text(target, html)


__all__ = ["OUTPUT_FILENAME", "render_run_visual"]

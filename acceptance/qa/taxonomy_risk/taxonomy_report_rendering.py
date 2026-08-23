#!/usr/bin/env python3
"""Executable end-to-end QA suite for taxonomy/risk HTML report rendering.

Mirrors ``taxonomy_report_rendering.md`` (QA-TRPT-01..15).  Drives only the
``asago-scenario-generator report`` CLI (``--output-dir`` / ``--output``)
against disposable completed-run fixtures whose manifest inventories and
SHA-256 hashes match their artifacts, then inspects CLI stdout, stderr, exit
status, and the published ``report.html``.  Never imports project modules,
never calls ``generate_report`` / ``build_scorecard_section`` or any other
project API, and never sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.
Offline only: the report command does not contact an LLM endpoint.

Visible-text, CSS-class-level (badge colors, highlight markers, placeholder
styling), and document-order claims are verified directly in the published
``report.html`` source (the user-visible output, not a project API), with
markup stripped for text emptiness/content checks.

Run with::

    uv run python acceptance/qa/taxonomy_risk/taxonomy_report_rendering.py

Exit status is 0 only when every pinned assertion passes.  Set
``QA_SKIP_GATES=1`` to iterate on the report cases without rerunning the
repository gate sequence (QA-TRPT-15).

Pinned interpretation (QA-TRPT-05): the seed-description truncation rule is
300 characters with a sentence-boundary preference; the full description is
published outside the provenance chain (Scenario Seed block / Generation
Inputs), so truncation checks are scoped to the provenance chain region.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
QA_PIPELINE_ENV = "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"

_RUN_ID = "20260101T000000_abcdef0123456789abcdef0123456789"

_MEDIA_TYPES: dict[str, str] = {
    ".txt": "text/plain",
    ".yaml": "application/yaml",
    ".feature": "text/plain",
    ".json": "application/json",
    ".jsonl": "application/jsonl",
    ".log": "text/plain",
    ".html": "text/html",
}

_SINGLETON_ROLES: dict[str, str] = {
    "use-case.txt": "use_case",
    "capability-profile.yaml": "capability_profile",
    "threat-surface.yaml": "threat_surface",
    "coverage-gaps.json": "coverage_report",
    "pipeline.log": "pipeline_log",
    "report.html": "report",
    "eval-scorecard.yaml": "eval_scorecard",
}

_SEED_SECTION_MARKER = "<summary>Scenario Seed</summary>"

failures: list[str] = []
notes: list[str] = []


_SEARCH_PATH = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
_UV = shutil.which("uv", path=_SEARCH_PATH) or "uv"


def _command() -> list[str]:
    """Resolve the CLI launcher (uv run, falling back to the venv binary)."""
    if shutil.which("uv", path=_SEARCH_PATH):
        return [_UV, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv" / "bin" / "asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


# ---------------------------------------------------------------------------
# Fixture builders (authoritative completed-run shapes)
# ---------------------------------------------------------------------------


def _corpus_claims() -> list[dict[str, str]]:
    """Typed corpus-claim records the report generator requires."""
    return [
        {
            "category": "entry_points",
            "status": "not_applicable",
            "reason": "QA fixture",
        },
        {
            "category": "tool_inventory",
            "status": "not_applicable",
            "reason": "QA fixture",
        },
    ]


def _seed_meta(**overrides: Any) -> dict[str, str]:
    meta: dict[str, str] = {
        "seed_id": "AP-T6-01",
        "attack_pattern_name": "Prompt injection with hidden intent",
        "attack_pattern_description": "A short attack pattern description.",
        "threat_id": "T6",
        "threat_name": "Social engineering",
        "owasp_origin": "LLM01",
    }
    meta.update(overrides)
    return meta


def _risk_card(**overrides: Any) -> dict[str, Any]:
    card: dict[str, Any] = {
        "risk_id": "atlas-phishing",
        "risk_name": "Spear phishing",
        "taxonomy": "ibm-risk-atlas",
        "confidence": 0.85,
    }
    card.update(overrides)
    return card


def _goal() -> dict[str, str]:
    return {
        "goal_category": "G2",
        "goal_category_name": "Exfiltrate data",
        "goal_category_parent": "Espionage",
    }


def _scenario(
    sid: str = "scn-01",
    *,
    risk_card: dict[str, Any] | None = None,
    owasp_llm_ids: list[str] | None = None,
    agentic_threat_ids: list[str] | None = None,
    seed_metadata: dict[str, Any] | None = None,
    entry_point: str | None = None,
    zones: list[str] | None = None,
    goal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A reportable scenario with honest optional-field degradation."""
    taxonomy_chain: dict[str, Any] = {}
    if owasp_llm_ids is not None:
        taxonomy_chain["owasp_llm_ids"] = owasp_llm_ids
    if agentic_threat_ids is not None:
        taxonomy_chain["agentic_threat_ids"] = agentic_threat_ids

    faceting: dict[str, Any] = {"taxonomy_chain": taxonomy_chain}
    if risk_card is not None:
        faceting["risk_card"] = risk_card
    if entry_point is not None or zones is not None:
        capability_profile: dict[str, Any] = {}
        if entry_point:
            capability_profile["entry_point"] = entry_point
        if zones:
            capability_profile["zones_traversed"] = zones
        faceting["capability_profile"] = capability_profile

    scenario: dict[str, Any] = {
        "scenario_id": sid,
        "priority": {"composite": 0.5},
        "narrative": {
            "title": sid,
            "summary": "",
            "entry_point": entry_point or "",
            "zone_sequence": zones or [],
        },
        "faceting": faceting,
        "validation": {"semantic": {"corpus_claim_applicability": _corpus_claims()}},
    }
    if seed_metadata is not None:
        scenario["scenario_seed_metadata"] = seed_metadata
    if goal is not None:
        scenario["actor_profile"] = goal
    return scenario


def _threat_surface(
    risk_card: dict[str, Any],
    *,
    attack_pattern_ids: list[str] | None = None,
    atlas_technique_ids: list[str] | None = None,
    agentic_threat_ids: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "entries": [
            {
                "risk_card": risk_card,
                "owasp_llm_ids": ["LLM01", "LLM06"],
                "agentic_threat_ids": agentic_threat_ids or [],
                "attack_pattern_ids": attack_pattern_ids or [],
                "atlas_technique_ids": atlas_technique_ids or [],
            }
        ],
        "governance_only": [],
    }


def _legacy_scorecard(**overrides: Any) -> dict[str, Any]:
    """Legacy scorecard carrying every metric group in range."""
    data: dict[str, Any] = {
        "evaluation": {
            "scenario_count": 3,
            "feature_file_count": 2,
            "consistency": {
                "mean": 0.95,
                "stddev": 0.04,
                "per_scenario": {
                    "scn-ok": {
                        "zone_alignment": 0.98,
                        "entry_point_agreement": 1,
                        "step_node_correspondence": 0.97,
                    }
                },
            },
            "gherkin": {
                "parse_success_rate": 1.0,
                "mean_step_count": 7.5,
                "tag_consistency": {"inconsistent_groups": 0},
                "background_missing_warnings": [],
            },
            "grounding": {
                "threat_id_validity": 1.0,
                "dangling_references": 0,
                "technique_id_grounding": 0.95,
                "ungrounded_technique_references": 0,
            },
            "technique_agreement": {
                "mean_technique_agreement": 0.92,
                "per_scenario": {},
            },
            "diversity": {
                "title_uniqueness": 0.9,
                "entry_point_entropy": {
                    "entropy": 1.1,
                    "entry_point_coverage": 0.93,
                },
                "zone_coverage": {
                    "active_zone_coverage": 0.91,
                    "out_of_scope_zone_violations": [],
                },
                "actor_type_entropy": 0.8,
                "capability_level_evenness": 0.85,
            },
            "plausibility": {
                "capability_complexity_violation_count": 0,
                "per_scenario": {},
            },
        }
    }
    data["evaluation"].update(overrides)
    return data


_VERSIONED_GROUPS = {
    "Presence / Coverage": "presence_coverage",
    "Validity / Grounding": "validity_grounding",
    "Cross-artifact Agreement": "cross_artifact_agreement",
    "Semantic Quality / Diagnostics": "semantic_quality_diagnostics",
    "Release Qualification": "release_qualification",
}


def _versioned_scorecard(status: str, group: str) -> dict[str, Any]:
    """Schema v1 scorecard with a single metric under *group*."""
    key = _VERSIONED_GROUPS[group]
    scorecard: dict[str, Any] = {
        "schema_version": "1",
        "scenario_count": 1,
        "feature_file_count": 1,
        "qualification": {
            "status": "pass",
            "failed_gate_ids": [],
            "error_gate_ids": [],
            "not_applicable_gate_ids": [],
        },
    }
    for group_key in _VERSIONED_GROUPS.values():
        scorecard[group_key] = {"metrics": {}}
    scorecard[key] = {
        "metrics": {
            "single": {
                "status": status,
                "numerator": 1,
                "denominator": 1,
                "value": 1.0,
                "evidence": [],
                "affected_ids": [],
            }
        }
    }
    return scorecard


def _build_run(
    run_dir: Path,
    *,
    scenarios: list[dict[str, Any]],
    scorecard: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
    threat_surface: dict[str, Any] | None = None,
    use_case: str = "QA fixture use case.\n",
) -> Path:
    """Write a completed-run fixture whose inventory hashes match artifacts.

    Pure YAML + hashlib: no project module is imported.  Scenario YAML files
    carry serialized ``scenario_id`` and ``candidate_id`` so the strict
    manifest resolver accepts them.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    inventory: list[dict[str, Any]] = []

    def _inventory_entry(
        rel_path: str,
        role: str,
        scenario_id: str | None = None,
        candidate_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "role": role,
            "path": rel_path,
            "sha256": hashlib.sha256((run_dir / rel_path).read_bytes()).hexdigest(),
            "schema_version": "1",
            "media_type": _MEDIA_TYPES[(run_dir / rel_path).suffix],
            **(
                {"scenario_id": scenario_id, "candidate_id": candidate_id}
                if scenario_id is not None
                else {}
            ),
        }

    def _write(rel_path: str, content: str) -> None:
        full = run_dir / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")

    for rel_path, content in (
        ("use-case.txt", use_case),
        (
            "capability-profile.yaml",
            yaml.dump(profile or {"entry_points": ["ze-query", "ze-rag"]}),
        ),
        (
            "threat-surface.yaml",
            yaml.dump(threat_surface or {"entries": [], "governance_only": []}),
        ),
        ("coverage-gaps.json", "{}\n"),
        ("pipeline.log", "test log\n"),
        ("report.html", "<html><body>placeholder</body></html>\n"),
    ):
        _write(rel_path, content)
        inventory.append(_inventory_entry(rel_path, _SINGLETON_ROLES[rel_path]))

    for index, scenario in enumerate(scenarios):
        sid = scenario["scenario_id"]
        candidate_id = scenario.get("candidate_id", f"cand:v2:{index + 1:032d}")
        serialized = dict(scenario)
        serialized.setdefault("candidate_id", candidate_id)
        _write(
            f"scenarios/{sid}.yaml",
            yaml.dump(serialized, default_flow_style=False, sort_keys=False),
        )
        _write(f"scenarios/{sid}.feature", f"Feature: {sid}\n  Scenario: {sid}\n")
        for rel_path in (f"scenarios/{sid}.yaml", f"scenarios/{sid}.feature"):
            role = "scenario_yaml" if rel_path.endswith(".yaml") else "scenario_feature"
            inventory.append(_inventory_entry(rel_path, role, sid, candidate_id))

    if scorecard is not None:
        _write(
            "eval-scorecard.yaml",
            yaml.dump(scorecard, default_flow_style=False, sort_keys=False),
        )
        inventory.append(_inventory_entry("eval-scorecard.yaml", "eval_scorecard"))

    manifest = {
        "manifest_version": "2",
        "status": "completed",
        "run_id": _RUN_ID,
        "timestamp_start": "2026-01-01T00:00:00+00:00",
        "timestamp_end": "2026-01-01T00:01:00+00:00",
        "package_version": "0.0.0",
        "inventory": inventory,
    }
    _write(
        "run-manifest.yaml",
        yaml.dump(manifest, default_flow_style=False, sort_keys=False),
    )
    return run_dir


# ---------------------------------------------------------------------------
# CLI runner and report inspection
# ---------------------------------------------------------------------------


def _run_report(case: str, run_dir: Path, out_dir: Path) -> tuple[bool, str]:
    """Run the report CLI once and return (exit_ok, html)."""
    capture_dir = RUN_ROOT / "captures" / case
    capture_dir.mkdir(parents=True, exist_ok=True)
    command = [
        *_command(),
        "report",
        "--output-dir",
        str(run_dir),
        "--output",
        str(out_dir / "report.html"),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return False, ""
    (capture_dir / "command.txt").write_text(" ".join(command) + "\n", encoding="utf-8")
    (capture_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (capture_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (capture_dir / "exit.txt").write_text(f"{completed.returncode}\n", encoding="utf-8")
    if completed.returncode != 0:
        return False, (
            completed.stdout[-500:] + completed.stderr[-500:].strip()
        ).strip()
    if "Report written to" not in completed.stdout:
        return False, completed.stdout[-500:]
    report_path = out_dir / "report.html"
    if not report_path.is_file():
        return False, f"report.html missing at {report_path}"
    return True, report_path.read_text(encoding="utf-8")


def _card_region(html: str, sid: str) -> str:
    """Slice of the report containing the scenario card for *sid*."""
    marker = f'id="scenario-{sid}"'
    idx = html.find(marker)
    assert idx != -1, f"scenario card {sid} is not rendered"
    return html[idx:]


def _chain_region(html: str, sid: str) -> str:
    """HTML of the provenance chain inside the scenario card for *sid*.

    The chain is the prov-chain div; the slice ends at the next section
    boundary so neighboring blocks (e.g. the Scenario Seed block) stay
    outside chain-scoped assertions.
    """
    region = _card_region(html, sid)
    start = region.find('<div class="prov-chain">')
    assert start != -1, f"provenance chain missing for {sid}"
    body = region[start:]
    end = body.find('<div class="scenario-section">')
    return body[: end if end != -1 else len(body)]


_STEP_RE = re.compile(
    r'<div class="prov-step-label">(.*?)</div>(.*?)(?=<div class="prov-step-label">|$)',
    re.S,
)

_KV_RE = re.compile(
    r'<span class="prov-kv-label">(.*?)</span>'
    r'<span class="prov-kv-value"[^>]*>(.*?)</span>',
    re.S,
)


def _prov_steps(chain: str) -> dict[str, str]:
    """Return label -> body for every provenance chain step."""
    return {
        label: body
        for label, body in ((m.group(1), m.group(2)) for m in _STEP_RE.finditer(chain))
    }


def _step(steps: dict[str, str], prefix: str) -> str:
    matches = [body for label, body in steps.items() if label.startswith(prefix)]
    assert len(matches) == 1, (
        f"expected one step starting {prefix!r}, got {len(matches)}"
    )
    return matches[0]


def _step_kv(body: str) -> dict[str, str]:
    return {label: value for label, value in _KV_RE.findall(body)}


def _visible(fragment: str) -> str:
    """Strip markup and entities for emptiness/content checks."""
    text = re.sub(r"<[^>]+>", "", fragment)
    text = text.replace("&mdash;", "").replace("&nbsp;", " ")
    return text.strip()


def _in_order(fragment: str, values: list[str]) -> bool:
    position = -1
    for value in values:
        idx = fragment.find(value)
        if idx == -1 or idx < position:
            return False
        position = idx
    return True


def _highlighted_value(body: str, value: str) -> bool:
    """Return whether *value* is inside the first prov-highlight span."""
    head = body.split("prov-highlight", 1)
    if len(head) < 2:
        return False
    return value in head[1].split("</span>", 1)[0]


def _seed_region(html: str) -> str:
    assert _SEED_SECTION_MARKER in html, "Scenario Seed section is not rendered"
    region = html.split(_SEED_SECTION_MARKER, 1)[1]
    return region.split("</details>", 1)[0]


def _badge_span(html: str, label: str, display: str) -> str | None:
    """Return the matched badge color class for a 'Label: value' badge."""
    match = re.search(
        r'<span class="scorecard-badge (scorecard-badge-\w+)"[^>]*>'
        + re.escape(label)
        + r": "
        + re.escape(display)
        + r"</span>",
        html,
    )
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# QA procedures
# ---------------------------------------------------------------------------

_STEP_LABEL_PREFIXES = [
    "1. Risk Card",
    "2. OWASP LLM IDs",
    "3. Agentic Threats",
    "4a. Attack Pattern",
    "4b. Attack Goal",
    "4c. Scenario classifications",
    "5. Entry Point",
    "6. Zone Sequence",
]


def qa_trpt_01() -> None:
    """QA-TRPT-01: the full provenance chain renders."""
    case = "TRPT-01"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trpt-01",
        scenarios=[
            _scenario(
                risk_card=_risk_card(),
                owasp_llm_ids=["LLM01", "LLM06"],
                agentic_threat_ids=["T6", "T11"],
                seed_metadata=_seed_meta(),
                entry_point="ze-rag",
                zones=["Z1", "Z2"],
                goal=_goal(),
            )
        ],
        threat_surface=_threat_surface(
            _risk_card(),
            attack_pattern_ids=["AP-T11-01", "AP-T6-01"],
            atlas_technique_ids=["AML.T0015", "AML.T0053"],
            agentic_threat_ids=["T6", "T11"],
        ),
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    card = _card_region(html, "scn-01")
    if re.search(r"<label[^>]*>Provenance</label>", card) is None:
        failures.append(f"{case}: Provenance tab missing on scenario card")
    chain = _chain_region(html, "scn-01")
    labels = list(_prov_steps(chain))
    if not _in_order(chain, _STEP_LABEL_PREFIXES):
        failures.append(f"{case}: step labels not in order: {labels}")
    steps = _prov_steps(chain)
    kv = _step_kv(_step(steps, "1. Risk Card"))
    if kv.get("Risk ID") != "atlas-phishing":
        failures.append(f"{case}: risk ID not rendered: {kv.get('Risk ID')!r}")
    if kv.get("Risk Name") != "Spear phishing":
        failures.append(f"{case}: risk name not rendered: {kv.get('Risk Name')!r}")
    if kv.get("Confidence") != "0.85":
        failures.append(f"{case}: confidence not rendered: {kv.get('Confidence')!r}")
    if "ibm-risk-atlas" not in kv.get("Taxonomy", ""):
        failures.append(f"{case}: taxonomy badge not rendered")
    owasp_body = _step(steps, "2. OWASP LLM IDs")
    if not _in_order(owasp_body, ["LLM01", "LLM06"]):
        failures.append(f"{case}: OWASP LLM badges missing or out of order")
    threat_body = _step(steps, "3. Agentic Threats")
    if not _in_order(threat_body, ["T6", "T11"]):
        failures.append(f"{case}: agentic threat badges missing or out of order")
    pattern_body = _step(steps, "4a. Attack Pattern")
    if not _highlighted_value(pattern_body, "AP-T6-01"):
        failures.append(f"{case}: selected seed AP-T6-01 not highlighted")
    if "AP-T11-01" not in pattern_body:
        failures.append(f"{case}: unselected pattern AP-T11-01 missing")
    if _highlighted_value(pattern_body, "AP-T11-01"):
        failures.append(f"{case}: unselected pattern AP-T11-01 wrongly highlighted")
    atlas_body = _step(steps, "4c. Scenario classifications")
    if not _in_order(atlas_body, ["AML.T0015", "AML.T0053"]):
        failures.append(f"{case}: ATLAS candidates missing or out of order")
    if "prov-highlight" in atlas_body:
        failures.append(f"{case}: ATLAS candidates should be unpinned")
    entry_body = _step(steps, "5. Entry Point")
    if not _highlighted_value(entry_body, "ze-rag"):
        failures.append(f"{case}: selected entry point ze-rag not highlighted")
    if "ze-query" not in entry_body:
        failures.append(f"{case}: unselected entry point ze-query missing")
    if "prov-dim" not in entry_body:
        failures.append(f"{case}: unselected entry point not dimmed")
    zone_body = _step(steps, "6. Zone Sequence")
    if not _in_order(zone_body, ["Z1", "Z2"]):
        failures.append(f"{case}: zone crumbs missing or out of order")
    notes.append(f"{case}: full provenance chain verified end-to-end")


def qa_trpt_02() -> None:
    """QA-TRPT-02: missing risk card degrades honestly."""
    case = "TRPT-02"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trpt-02",
        scenarios=[
            _scenario(
                owasp_llm_ids=["LLM01"],
                agentic_threat_ids=["T6"],
                goal=_goal(),
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    chain = _chain_region(html, "scn-01")
    steps = _prov_steps(chain)
    risk_body = _step(steps, "1. Risk Card")
    kv = _step_kv(risk_body)
    visible = {key: _visible(value) for key, value in kv.items()}
    if visible.get("Risk ID") != "":
        failures.append(f"{case}: risk ID should be empty: {visible.get('Risk ID')!r}")
    if visible.get("Risk Name") != "":
        failures.append(
            f"{case}: risk name should be empty: {visible.get('Risk Name')!r}"
        )
    if kv.get("Confidence") != "0.00":
        failures.append(f"{case}: confidence should degrade to 0.00")
    if "prov-badge" in risk_body:
        failures.append(f"{case}: taxonomy badge should be absent without a risk card")


def qa_trpt_03() -> None:
    """QA-TRPT-03: empty ID lists show a muted placeholder."""
    for empty_list, empty_prefix, other_prefix, remaining in (
        ("owasp_llm_ids", "2. OWASP LLM IDs", "3. Agentic Threats", "T6"),
        ("agentic_threat_ids", "3. Agentic Threats", "2. OWASP LLM IDs", "LLM01"),
    ):
        case = f"TRPT-03-{empty_list}"
        owasp = ["LLM01"] if empty_list != "owasp_llm_ids" else []
        threats = ["T6"] if empty_list != "agentic_threat_ids" else []
        run_dir = _build_run(
            RUN_ROOT / "fixtures" / case,
            scenarios=[
                _scenario(
                    owasp_llm_ids=owasp,
                    agentic_threat_ids=threats,
                    goal=_goal(),
                )
            ],
        )
        ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
        if not ok:
            failures.append(f"{case}: report command failed: {html}")
            continue
        steps = _prov_steps(_chain_region(html, "scn-01"))
        empty_body = _step(steps, empty_prefix)
        if 'class="prov-badge prov-badge-muted">none</span>' not in empty_body:
            failures.append(f"{case}: muted placeholder missing in {empty_prefix}")
        if remaining in empty_body:
            failures.append(f"{case}: {remaining} should not appear in the empty step")
        if remaining not in _step(steps, other_prefix):
            failures.append(f"{case}: {remaining} badge missing from the other step")


def qa_trpt_04() -> None:
    """QA-TRPT-04: provenance renders without seed metadata."""
    case = "TRPT-04"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trpt-04",
        scenarios=[
            _scenario(
                goal=_goal(),
                entry_point="ze-rag",
                zones=["Z1"],
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    chain = _chain_region(html, "scn-01")
    if (
        re.search(r"<label[^>]*>Provenance</label>", _card_region(html, "scn-01"))
        is None
    ):
        failures.append(f"{case}: Provenance tab missing without seed metadata")
    steps = _prov_steps(chain)
    pattern_body = _step(steps, "4a. Attack Pattern")
    visible = {key: _visible(value) for key, value in _step_kv(pattern_body).items()}
    for key in ("Seed ID", "Name", "Threat"):
        if visible.get(key) != "":
            failures.append(f"{case}: {key} should be empty: {visible.get(key)!r}")
    if "Description" in pattern_body:
        failures.append(f"{case}: description should be absent without seed metadata")
    for label in ("4b. Attack Goal", "5. Entry Point", "6. Zone Sequence"):
        if label not in chain:
            failures.append(f"{case}: step {label} missing without seed metadata")


def qa_trpt_05() -> None:
    """QA-TRPT-05: long descriptions truncate at 300 inside the chain."""
    long_desc = "x" * 400
    case = "TRPT-05-truncate"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / case,
        scenarios=[
            _scenario(
                risk_card=_risk_card(),
                seed_metadata=_seed_meta(attack_pattern_description=long_desc),
                goal=_goal(),
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
    else:
        chain = _chain_region(html, "scn-01")
        pattern_body = _step(_prov_steps(chain), "4a. Attack Pattern")
        if ("x" * 300) + "..." not in pattern_body:
            failures.append(f"{case}: description not truncated at 300 with '...'")
        if "x" * 400 in chain:
            failures.append(f"{case}: full description leaks into the provenance chain")
        if "x" * 400 not in html:
            failures.append(
                f"{case}: full description must still appear outside the chain"
            )

    short_desc = ("a" * 119) + "."
    case = "TRPT-05-keep"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / case,
        scenarios=[
            _scenario(
                seed_metadata=_seed_meta(attack_pattern_description=short_desc),
                goal=_goal(),
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    pattern_body = _step(
        _prov_steps(_chain_region(html, "scn-01")), "4a. Attack Pattern"
    )
    description = _visible(_step_kv(pattern_body).get("Description", ""))
    if description != short_desc:
        failures.append(f"{case}: short description not kept in full: {description!r}")


def qa_trpt_06() -> None:
    """QA-TRPT-06: complete scorecard renders every metric group."""
    case = "TRPT-06"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / case,
        scenarios=[_scenario(sid) for sid in ("scn-01", "scn-02", "scn-03")],
        scorecard=_legacy_scorecard(),
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    if "<h2>Eval Scorecard</h2>" not in html:
        failures.append(f"{case}: Eval Scorecard section missing")
    if '<div class="scorecard-stat-value">3</div>' not in html:
        failures.append(f"{case}: scenario count 3 not rendered")
    if '<div class="scorecard-stat-value">2</div>' not in html:
        failures.append(f"{case}: feature file count 2 not rendered")
    titles = re.findall(
        r'<div class="scorecard-group-title"[^>]*>(.*?)</div>', html, re.S
    )
    for group in (
        "Consistency",
        "Gherkin Quality",
        "Grounding",
        "Projected-step Mapping Agreement",
        "Diversity",
        "Plausibility",
    ):
        if not any(group in title for title in titles):
            failures.append(f"{case}: metric group {group!r} missing")
    if "Mean Technique Agreement: 0.92" not in html:
        failures.append(f"{case}: technique agreement badge missing")


def qa_trpt_07() -> None:
    """QA-TRPT-07: in-range metrics show the clean outliers panel."""
    case = "TRPT-07"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trpt-07",
        scenarios=[_scenario("scn-ok")],
        scorecard=_legacy_scorecard(),
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    if "All scenarios pass quality checks" not in html:
        failures.append(f"{case}: clean outliers message missing")
    if "Quality Outliers" in html:
        failures.append(f"{case}: outliers panel should be absent when all in range")


def qa_trpt_08() -> None:
    """QA-TRPT-08: outliers list red tier before yellow tier."""
    case = "TRPT-08"
    scorecard = _legacy_scorecard(
        consistency={
            "mean": 0.8,
            "per_scenario": {
                "scn-a": {
                    "zone_alignment": 0.65,
                    "entry_point_agreement": 1,
                    "step_node_correspondence": 0.9,
                },
                "scn-b": {
                    "zone_alignment": 0.80,
                    "entry_point_agreement": 1,
                    "step_node_correspondence": 0.9,
                },
            },
        },
        plausibility={
            "capability_complexity_violation_count": 2,
            "per_scenario": {},
        },
    )
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trpt-08",
        scenarios=[_scenario("scn-a"), _scenario("scn-b")],
        scorecard=scorecard,
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    if "Quality Outliers" not in html:
        failures.append(f"{case}: Quality Outliers panel missing")
        return
    panel = html.split("Quality Outliers", 1)[1]
    rows = re.findall(r"<tbody>(.*?)</tbody>", panel, re.S)
    if not rows:
        failures.append(f"{case}: no outlier table rows")
        return
    first_cells = re.findall(r"<tr><td>(.*?)</td>", rows[0], re.S)
    if first_cells != ["(aggregate)", "scn-a", "scn-b"]:
        failures.append(f"{case}: outlier row order wrong: {first_cells}")
    detail = re.findall(
        r"<tr><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td>", rows[0], re.S
    )
    expected = [
        ("(aggregate)", "Plausibility", "Capability Violations"),
        ("scn-a", "Consistency", "Zone Alignment"),
        ("scn-b", "Consistency", "Zone Alignment"),
    ]
    if [tuple(row) for row in detail[:3]] != expected:
        failures.append(f"{case}: outlier metric rows wrong: {detail}")
    for value in (">2</span>", ">0.65</span>", ">0.80</span>"):
        if value not in panel:
            failures.append(f"{case}: outlier value {value} missing")


def qa_trpt_09() -> None:
    """QA-TRPT-09: badge colors follow the 90/70 thresholds."""
    for mean, color, display in (
        (0.95, "scorecard-badge-green", "0.95"),
        (0.75, "scorecard-badge-yellow", "0.75"),
        (0.55, "scorecard-badge-red", "0.55"),
        (1.0, "scorecard-badge-green", "1"),
    ):
        case = f"TRPT-09-mean-{mean}"
        run_dir = _build_run(
            RUN_ROOT / "fixtures" / case,
            scenarios=[_scenario("scn-01")],
            scorecard=_legacy_scorecard(consistency={"mean": mean}),
        )
        ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
        if not ok:
            failures.append(f"{case}: report command failed: {html}")
            continue
        badge = _badge_span(html, "Mean", display)
        if badge != color:
            failures.append(
                f"{case}: Mean badge for {mean} is {badge!r}, expected {color!r}"
            )


def qa_trpt_10() -> None:
    """QA-TRPT-10: inverted count badges color zero green and above red."""
    for violations, color, display in (
        (0, "scorecard-badge-green", "0"),
        (2, "scorecard-badge-red", "2"),
    ):
        case = f"TRPT-10-violations-{violations}"
        run_dir = _build_run(
            RUN_ROOT / "fixtures" / case,
            scenarios=[_scenario("scn-01")],
            scorecard=_legacy_scorecard(
                plausibility={
                    "capability_complexity_violation_count": violations,
                    "per_scenario": {},
                }
            ),
        )
        ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
        if not ok:
            failures.append(f"{case}: report command failed: {html}")
            continue
        badge = _badge_span(html, "Capability Violations", display)
        if badge != color:
            failures.append(
                f"{case}: violation badge for {violations} is {badge!r}, "
                f"expected {color!r}"
            )


def qa_trpt_11() -> None:
    """QA-TRPT-11: schema v1 scorecards render status badges."""
    for status, group, color in (
        ("pass", "Presence / Coverage", "scorecard-badge-green"),
        ("fail", "Validity / Grounding", "scorecard-badge-red"),
        ("not_applicable", "Release Qualification", "scorecard-badge-yellow"),
    ):
        case = f"TRPT-11-{status}"
        run_dir = _build_run(
            RUN_ROOT / "fixtures" / case,
            scenarios=[_scenario("scn-01")],
            scorecard=_versioned_scorecard(status, group),
        )
        ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
        if not ok:
            failures.append(f"{case}: report command failed: {html}")
            continue
        if "<h2>Versioned Eval Scorecard</h2>" not in html:
            failures.append(f"{case}: Versioned Eval Scorecard section missing")
        if '<span class="badge">Schema v1</span>' not in html:
            failures.append(f"{case}: Schema v1 badge missing")
        group_marker = f'<div class="scorecard-group-title">{group}</div>'
        if group_marker not in html:
            failures.append(f"{case}: group {group!r} missing")
            continue
        group_region = html.split(group_marker, 1)[1]
        if color not in group_region:
            failures.append(f"{case}: status badge color missing in {group}")
        if f">{status}</span>" not in group_region:
            failures.append(f"{case}: status text {status!r} missing in {group}")


def qa_trpt_12() -> None:
    """QA-TRPT-12: Scenario Seed block only for complete seed metadata."""
    for metadata_case, seed_metadata in (
        ("absent", None),
        ("complete", _seed_meta()),
        ("incomplete", {"threat_id": "T6"}),
    ):
        case = f"TRPT-12-{metadata_case}"
        run_dir = _build_run(
            RUN_ROOT / "fixtures" / case,
            scenarios=[_scenario("scn-01", seed_metadata=seed_metadata)],
        )
        ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
        if not ok:
            failures.append(f"{case}: report command failed: {html}")
            continue
        renders = _SEED_SECTION_MARKER in html
        expected = metadata_case == "complete"
        if renders != expected:
            failures.append(
                f"{case}: Scenario Seed section renders={renders}, expected={expected}"
            )
        if expected and _SEED_SECTION_MARKER not in _card_region(html, "scn-01"):
            failures.append(f"{case}: Scenario Seed block outside the scenario card")


def qa_trpt_13() -> None:
    """QA-TRPT-13: Scenario Seed block shows the seed fields."""
    case = "TRPT-13"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trpt-13",
        scenarios=[
            _scenario(
                risk_card=_risk_card(),
                seed_metadata=_seed_meta(),
                goal=_goal(),
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    seed_region = _seed_region(html)
    for expected in (
        "Prompt injection with hidden intent",
        "A short attack pattern description.",
        "T6 &mdash; Social engineering",
        "LLM01",
        "AP-T6-01",
    ):
        if expected not in seed_region:
            failures.append(f"{case}: seed field {expected!r} missing")


def qa_trpt_14() -> None:
    """QA-TRPT-14: no scorecard omits the section and sidebar link."""
    case = "TRPT-14"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trpt-14",
        scenarios=[_scenario("scn-01")],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    if "Eval Scorecard" in html:
        failures.append(f"{case}: Eval Scorecard section must be omitted")
    if '<a href="#sec-scorecard">' in html:
        failures.append(f"{case}: scorecard sidebar link must be omitted")


def _run_gate(name: str, argv: list[str], timeout: int = 1800) -> tuple[bool, str]:
    """Run one documented gate and return (ok, message)."""
    try:
        completed = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"{name} timed out"
    ok = completed.returncode == 0
    tail = (completed.stdout or "")[-800:] + (completed.stderr or "")[-800:]
    return ok, f"{name}: exit {completed.returncode}\n{tail.strip()[-700:]}"


def qa_trpt_15() -> None:
    """QA-TRPT-15: deterministic repository gates and output hygiene."""
    if os.environ.get(QA_PIPELINE_ENV):
        failures.append("15: ASAGO_SCENARIO_GENERATOR_QA_PIPELINE must not be set")
    statuses = [
        _run_gate("quality.sh", ["./scripts/quality.sh"], timeout=900),
        _run_gate("acceptance.sh", ["./scripts/acceptance.sh"], timeout=3600),
        _run_gate("unit tests", [_UV, "run", "pytest", "tests/", "-q"], timeout=3600),
    ]
    for ok, message in statuses:
        if ok:
            notes.append(f"15: {message.splitlines()[0]}")
        else:
            failures.append(f"15: {message}")
    hygiene = subprocess.run(
        ["git", "status", "--short", "--untracked-files=all"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    dirty = [line for line in hygiene.stdout.splitlines() if line.strip()]
    unexpected = [
        line
        for line in dirty
        if any(
            marker in line
            for marker in (
                "build/acceptance",
                "acceptance/generated",
                "acceptance/ir",
                "lcov.info",
                "coverage",
                "htmlcov",
                "tmp/qa-taxonomy-report-rendering",
            )
        )
    ]
    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    staged_paths = [line for line in staged.stdout.splitlines() if line.strip()]
    if unexpected:
        failures.append(
            "15: unexpected tracked/staged generated artifacts:\n"
            + "\n".join(unexpected)
        )
    if staged_paths:
        failures.append(f"15: staged paths present: {staged_paths}")
    if not unexpected and not staged_paths:
        notes.append(
            "15: no generated acceptance IR, coverage, or QA captures tracked/staged"
        )


def main() -> int:
    """Run all taxonomy-report-rendering QA procedures."""
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    for procedure in (
        qa_trpt_01,
        qa_trpt_02,
        qa_trpt_03,
        qa_trpt_04,
        qa_trpt_05,
        qa_trpt_06,
        qa_trpt_07,
        qa_trpt_08,
        qa_trpt_09,
        qa_trpt_10,
        qa_trpt_11,
        qa_trpt_12,
        qa_trpt_13,
        qa_trpt_14,
    ):
        procedure()
        print(f"  [done] {procedure.__name__}", flush=True)
    if os.environ.get("QA_SKIP_GATES"):
        print("\n--- QA-TRPT-15 skipped (QA_SKIP_GATES set) ---", flush=True)
    else:
        print("\n--- QA-TRPT-15: deterministic repository gates ---", flush=True)
        qa_trpt_15()
    print("\n=== SUMMARY ===", flush=True)
    print(f"  Failures: {len(failures)}", flush=True)
    for failure in failures:
        print(f"    - {failure}", flush=True)
    for note in notes:
        print(f"  note: {note}", flush=True)
    if failures:
        print("  Result: FAIL", flush=True)
    else:
        print("  Result: PASS", flush=True)
    return 1 if failures else 0


RUN_ROOT = (
    REPO_ROOT
    / "tmp"
    / "qa-taxonomy-report-rendering"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

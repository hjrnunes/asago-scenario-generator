#!/usr/bin/env python3
"""Executable end-to-end QA suite for taxonomy/risk HTML report sections.

Mirrors ``taxonomy_report_sections_rendering.md`` (QA-TRSR-01..36).  Drives
only the ``asago-scenario-generator report`` CLI (``--output-dir`` /
``--output``) against disposable completed-run fixtures whose manifest
inventories and SHA-256 hashes match their artifacts, then inspects CLI
stdout, stderr, exit status, and the published ``report.html``.  Never
imports project modules, never calls ``generate_report`` /
``build_threat_surface_section`` or any other project API, and never sets
``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.  Offline only: the report command
does not contact an LLM endpoint.

Visible-text, CSS-class-level (status badges, active/inactive chips,
highlight markers, placeholder styling), and document-order claims are
verified directly in the published ``report.html`` source (the
user-visible output, not a project API).

Run with::

    uv run python acceptance/qa/taxonomy_risk/taxonomy_report_sections_rendering.py

Exit status is 0 only when every pinned assertion passes.  Set
``QA_SKIP_GATES=1`` to iterate on the report cases without rerunning the
repository gate sequence (QA-TRSR-30).

CLI-boundary adaptations (pinned in the procedure's fixture shapes but
unreachable through the file-loading report command):

* QA-TRSR-21 (absent run manifest): the report command requires an
  authoritative ``completed`` manifest to load any run, so a manifest-less
  fixture is verified as an honest CLI refusal (non-zero exit, no report
  produced).  The "no Run Summary section" rendering contract is
  acceptance-harness-only (manifest data passed in-memory) and is pinned
  by the Gherkin suite.
* QA-TRSR-23 (Raw Data "2 files" badge): the CLI loader adds every
  scenario YAML/feature pair to the raw-file inventory, so a YAML +
  Gherkin case necessarily renders three raw panels
  (``capability-profile.yaml``, ``scenarios/scn-a.yaml``,
  ``scenarios/scn-a.feature``).  The badge assertion follows the actual
  inventory; the highlighting pins are asserted verbatim.
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

_ROLE_MEDIA: dict[str, str] = {
    "use_case": "text/plain",
    "capability_profile": "application/yaml",
    "threat_surface": "application/yaml",
    "scenario_yaml": "application/yaml",
    "scenario_feature": "text/plain",
    "scenario_call_log": "application/jsonl",
    "pipeline_call_log": "application/jsonl",
    "coverage_report": "application/json",
    "pipeline_log": "text/plain",
    "report": "text/html",
}

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


_DEFAULT_PRIORITY = object()


def _scenario(
    sid: str,
    *,
    priority: object = _DEFAULT_PRIORITY,
    narrative: dict[str, Any] | None = None,
    faceting: dict[str, Any] | None = None,
    actor_profile: dict[str, Any] | None = None,
    attack_tree: dict[str, Any] | None = None,
    attack_complexity_assessment: dict[str, Any] | None = None,
    candidate_filter: dict[str, Any] | None = None,
    scenario_seed_metadata: dict[str, Any] | None = None,
    technique_scope_evidence: dict[str, Any] | None = None,
    validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A reportable scenario fixture dict (serialized with IDs by the writer)."""
    scenario: dict[str, Any] = {
        "scenario_id": sid,
        "narrative": narrative
        or {
            "title": sid,
            "summary": "",
            "entry_point": "",
            "zone_sequence": [],
        },
        "faceting": faceting
        or {"taxonomy_chain": {"owasp_llm_ids": [], "agentic_threat_ids": []}},
        "validation": validation
        or {"semantic": {"corpus_claim_applicability": _corpus_claims()}},
    }
    if priority is not _DEFAULT_PRIORITY:
        if priority is not None:
            scenario["priority"] = priority
    else:
        scenario["priority"] = {"composite": 0.5}
    if actor_profile is not None:
        scenario["actor_profile"] = actor_profile
    if attack_tree is not None:
        scenario["attack_tree"] = attack_tree
    if attack_complexity_assessment is not None:
        scenario["attack_complexity_assessment"] = attack_complexity_assessment
    if candidate_filter is not None:
        scenario["candidate_filter"] = candidate_filter
    if scenario_seed_metadata is not None:
        scenario["scenario_seed_metadata"] = scenario_seed_metadata
    if technique_scope_evidence is not None:
        scenario["technique_scope_evidence"] = technique_scope_evidence
    return scenario


_DEFAULT_FEATURE = "Feature: {sid}\n  Scenario: {sid}\n"


def _build_run(
    run_dir: Path,
    *,
    scenarios: list[dict[str, Any]] | None = None,
    profile: dict[str, Any] | None = None,
    profile_text: str | None = None,
    threat_surface: dict[str, Any] | None = None,
    include_threat_surface: bool = True,
    coverage: dict[str, Any] | None = None,
    include_coverage: bool = True,
    calls: list[dict[str, Any]] | None = None,
    scenario_calls: list[dict[str, Any]] | None = None,
    feature_files: dict[str, str] | None = None,
    manifest_extra: dict[str, Any] | None = None,
    write_manifest: bool = True,
    use_case: str = "QA fixture use case.\n",
) -> Path:
    """Write a completed-run fixture whose inventory hashes match artifacts.

    Pure YAML/JSON + hashlib: no project module is imported.  Scenario YAML
    files carry serialized ``scenario_id`` and ``candidate_id`` so the
    strict manifest resolver accepts them.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    written: list[tuple[str, str, str | None, str | None]] = []

    def _write(rel_path: str, content: str) -> None:
        full = run_dir / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")

    def _register(rel_path: str, role: str, scenario_id: str | None = None) -> None:
        written.append((rel_path, role, scenario_id, None))

    def _register_scenario(
        rel_path: str, role: str, scenario_id: str, candidate_id: str
    ) -> None:
        written.append((rel_path, role, scenario_id, candidate_id))

    _write("use-case.txt", use_case)
    _register("use-case.txt", "use_case")

    if profile_text is not None:
        _write("capability-profile.yaml", profile_text)
    else:
        _write(
            "capability-profile.yaml",
            yaml.dump(profile or {"entry_points": ["ze-query", "ze-rag"]}),
        )
    _register("capability-profile.yaml", "capability_profile")

    if include_threat_surface:
        _write(
            "threat-surface.yaml",
            yaml.dump(threat_surface or {"entries": [], "governance_only": []}),
        )
        _register("threat-surface.yaml", "threat_surface")

    if include_coverage:
        _write("coverage-gaps.json", f"{json_dumps(coverage or {})}\n")
        _register("coverage-gaps.json", "coverage_report")

    _write("pipeline.log", "test log\n")
    _register("pipeline.log", "pipeline_log")
    _write("report.html", "<html><body>placeholder</body></html>\n")
    _register("report.html", "report")

    feature_files = feature_files or {}
    for index, scenario in enumerate(scenarios or []):
        sid = scenario["scenario_id"]
        candidate_id = scenario.get("candidate_id", f"cand:v2:{index + 1:032d}")
        serialized = dict(scenario)
        serialized["candidate_id"] = candidate_id
        serialized.setdefault("scenario_id", sid)
        _write(
            f"scenarios/{sid}.yaml",
            yaml.dump(serialized, default_flow_style=False, sort_keys=False),
        )
        _register_scenario(f"scenarios/{sid}.yaml", "scenario_yaml", sid, candidate_id)
        content = feature_files.get(sid, _DEFAULT_FEATURE.format(sid=sid))
        _write(f"scenarios/{sid}.feature", content)
        _register_scenario(
            f"scenarios/{sid}.feature", "scenario_feature", sid, candidate_id
        )

    if calls is not None:
        # JSON Lines: one compact JSON object per line.
        import json as _json

        _write(
            "calls.jsonl",
            "".join(
                _json.dumps(entry, separators=(",", ":")) + "\n" for entry in calls
            ),
        )
        _register("calls.jsonl", "pipeline_call_log")

    if scenario_calls is not None:
        # Per-scenario call log: JSON Lines, each line tagged with
        # ``scenario_id`` so the report loader groups entries per card.
        import json as _json

        _write(
            "scenarios/calls.jsonl",
            "".join(
                _json.dumps(entry, separators=(",", ":")) + "\n"
                for entry in scenario_calls
            ),
        )
        _register("scenarios/calls.jsonl", "scenario_call_log")

    if not write_manifest:
        return run_dir

    inventory = [
        {
            "role": role,
            "path": rel_path,
            "sha256": hashlib.sha256((run_dir / rel_path).read_bytes()).hexdigest(),
            "schema_version": "1",
            "media_type": _ROLE_MEDIA[role],
            **(
                {"scenario_id": scenario_id, "candidate_id": candidate_id}
                if scenario_id is not None
                else {}
            ),
        }
        for rel_path, role, scenario_id, candidate_id in written
    ]
    manifest: dict[str, Any] = {
        "manifest_version": "2",
        "status": "completed",
        "run_id": _RUN_ID,
        "timestamp_start": "2026-01-01T00:00:00+00:00",
        "timestamp_end": "2026-01-01T00:01:00+00:00",
        "package_version": "0.0.0",
        "inventory": inventory,
    }
    if manifest_extra:
        manifest.update(manifest_extra)
    _write("run-manifest.yaml", yaml.dump(manifest, sort_keys=False))
    return run_dir


def json_dumps(value: Any) -> str:
    """Deterministic JSON rendering without importing project modules."""
    return __import__("json").dumps(value, indent=2, sort_keys=False)


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


def _run_cli_raw(
    case: str, run_dir: Path, out_dir: Path
) -> subprocess.CompletedProcess[str]:
    """Run the report CLI and return the raw completed process (for refusal cases)."""
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
        completed = subprocess.CompletedProcess(command, 124, "", "timeout")
    (capture_dir / "command.txt").write_text(" ".join(command) + "\n", encoding="utf-8")
    (capture_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (capture_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (capture_dir / "exit.txt").write_text(f"{completed.returncode}\n", encoding="utf-8")
    return completed


def _region(html: str, section_id: str) -> str:
    """Slice of the report starting at a section anchor (bounded)."""
    marker = f'id="{section_id}"'
    idx = html.find(marker)
    if idx == -1:
        raise AssertionError(f"section {section_id!r} is not rendered")
    return html[idx : idx + 60000]


def _card(html: str, sid: str) -> str:
    """Slice of the report containing the scenario card for *sid*."""
    marker = f'id="scenario-{sid}"'
    idx = html.find(marker)
    if idx == -1:
        raise AssertionError(f"scenario card {sid} is not rendered")
    return html[idx:]


def _visible(fragment: str) -> str:
    """Strip markup and decode entities for text-content assertions."""
    text = re.sub(r"<[^>]+>", "", fragment)
    text = (
        text.replace("&rarr;", "→")
        .replace("&ndash;", "–")
        .replace("&middot;", "·")
        .replace("&mdash;", "—")
        .replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&nbsp;", " ")
        .replace("&#10;", " ")
        .replace("&and;", "∧")
        .replace("&or;", "∨")
        .replace("&bull;", "•")
    )
    return text.strip()


def _stats(region: str) -> dict[str, int]:
    """Return label -> count for every stat-number/stat-label pair."""
    return {
        label: int(count)
        for count, label in re.findall(
            r'<span class="stat-number">(\d+)</span>\s*'
            r'<span class="stat-label">([^<]+)</span>',
            region,
        )
    }


def _coverage_statuses(region: str) -> dict[str, str]:
    """Return coverage-card title -> status label."""
    return {
        title: status
        for title, status in re.findall(
            r'<span class="coverage-card-title">([^<]+)</span>\s*'
            r'<span class="coverage-status [\w-]+">([^<]+)</span>',
            region,
        )
    }


def _signal_pairs(region: str) -> dict[str, str]:
    """Return signal label -> value pairs from a signals grid."""
    item = re.compile(
        r'<div class="signal-label">([^<]+)</div>\s*'
        r'<div class="signal-value">([^<]+)</div>'
    )
    return dict(item.findall(region))


def _diversity_bars(region: str) -> list[tuple[str, int, str]]:
    """Return (label, count, pct) rows from an actor distribution block."""
    return list(
        re.findall(
            r'<span class="diversity-bar-label">([^<]+)</span>.*?'
            r'<div class="diversity-bar-fill"[^>]*>\s*(\d+)\s*</div>.*?'
            r'<span class="diversity-bar-count">([^<]+)</span>',
            region,
            re.S,
        )
    )


def _goal_bars(region: str) -> list[tuple[str, int]]:
    """Return (label, count) rows from a goal category distribution block."""
    goal_region = region[region.find("Goal Category Distribution") :]
    return list(
        re.findall(
            r'<span class="diversity-bar-label">([^<]+)</span>.*?'
            r'<div class="diversity-bar-fill"[^>]*>\s*(\d+)\s*</div>',
            goal_region,
            re.S,
        )
    )


def _expect(case: str, passed: bool, detail: str) -> None:
    """Record a failing check while continuing the suite."""
    if not passed:
        failures.append(f"{case}: {detail}")


def _show(case: str, run_dir: Path, html: str) -> None:
    """Print a compact per-case status line."""
    print(f"  [done] {case} ({len(html)} bytes)", flush=True)


# ---------------------------------------------------------------------------
# QA procedures
# ---------------------------------------------------------------------------


def qa_trsr_01() -> None:
    """QA-TRSR-01: capability profile composites render."""
    case = "TRSR-01"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-01",
        profile={
            "zones_active": ["input", "tool_execution"],
            "has_persistent_memory": True,
            "multi_agent": False,
            "confidence": "high",
            "entry_points": [
                {"name": "ze-query", "direction": "input"},
                {"name": "ze-rag", "direction": "bidirectional"},
            ],
            "tool_inventory": [{"name": "Web search", "tool_id": "tool-web"}],
            "external_integrations": [
                {"name": "OAuth IdP", "integration_id": "int-oidc"}
            ],
            "entry_point_completeness": "confirmed",
            "entry_point_evidence": ["use-case.md"],
            "tool_inventory_completeness": "partial",
            "kc_subcodes": ["KC6.1.1"],
        },
        scenarios=[_scenario("scn-01")],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-profile")
    _expect(case, "Schneider 5-Zone" in region, "Schneider 5-Zone badge missing")
    active = re.findall(
        r'<span class="zone-chip active"[^>]*>(.*?)</span>', region, re.S
    )
    inactive = re.findall(
        r'<span class="zone-chip inactive"[^>]*>(.*?)</span>', region, re.S
    )
    _expect(
        case,
        "Input Surfaces" in [t.strip() for t in active],
        f"active zone chips: {active}",
    )
    _expect(
        case,
        "Planning & Reasoning" in " ".join(_visible(t) for t in inactive),
        f"inactive zone chips: {inactive}",
    )
    flags = region[region.find("Capability Flags") :]
    chips = re.findall(
        r'<span class="flag-dot (on|off)"></span>\s*'
        r'<span class="flag-label">([^<]+)</span>',
        flags,
    )
    by_name = {name: state for state, name in chips}
    _expect(
        case,
        by_name.get("Memory") == "on" and by_name.get("Multi-Agent") == "off",
        f"flag chips={chips}",
    )
    _expect(
        case,
        "Confidence:" in flags and "High" in flags,
        "Confidence: High flag missing",
    )
    _expect(
        case,
        'class="ep-direction" title="input">←</span>' in region
        and 'class="ep-direction" title="bidirectional">↔</span>' in region
        and "ze-query" in region
        and "ze-rag" in region,
        "entry point arrows or names missing",
    )
    for value in ("Web search", "tool-web", "OAuth IdP", "int-oidc"):
        _expect(case, value in region, f"tool/integration value {value!r} missing")
    _expect(case, ">Confirmed</span>" in region, "Confirmed completeness missing")
    _expect(case, "use-case.md" in region, "entry-point evidence missing")
    _expect(case, ">Partial</span>" in region, "Partial completeness missing")
    _expect(
        case,
        "No evidence sources recorded" in region,
        "tool-inventory evidence placeholder missing",
    )
    _expect(
        case,
        'class="kc-badge' in region and "KC6.1.1" in region,
        "KC sub-code badge missing",
    )


def qa_trsr_02() -> None:
    """QA-TRSR-02: empty profile inventories degrade honestly."""
    case = "TRSR-02"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-02",
        profile={
            "zones_active": ["input"],
            "entry_points": [],
            "tool_inventory": [],
            "external_integrations": [],
            "entry_point_evidence": [],
            "tool_inventory_evidence": [],
        },
        scenarios=[_scenario("scn-01")],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-profile")
    for message in (
        "No tools inventoried",
        "No external integrations inventoried",
        "No evidence sources recorded",
    ):
        _expect(case, message in region, f"placeholder {message!r} missing")
    _expect(
        case,
        "ep-direction" not in region and ">Entry Points</div>" not in region,
        "entry point row still rendered",
    )


def qa_trsr_03() -> None:
    """QA-TRSR-03: actionable and governance-only entries are distinct."""
    case = "TRSR-03"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-03",
        threat_surface={
            "entries": [
                {
                    "risk_card": {
                        "risk_id": "atlas-phishing",
                        "risk_name": "Spear phishing",
                        "confidence": 0.85,
                    },
                    "owasp_llm_ids": ["LLM01"],
                    "agentic_threat_ids": ["T6"],
                    "attack_pattern_ids": ["AP-T6-01"],
                }
            ],
            "governance_only": [
                {
                    "risk_card": {
                        "risk_id": "atlas-copyright",
                        "risk_name": "Copyright compliance",
                    },
                    "owasp_llm_ids": [],
                    "agentic_threat_ids": [],
                    "attack_pattern_ids": [],
                    "governance_only": True,
                }
            ],
        },
        scenarios=[_scenario("scn-01")],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-threats")
    _expect(
        case,
        "1 actionable / 1 governance" in region,
        "threat surface badge missing",
    )
    row_start = region.find("atlas-phishing")
    _expect(case, row_start != -1, "atlas-phishing row not rendered")
    row = region[row_start : region.find("</tr>", row_start)]
    _expect(
        case,
        "status-badge status-actionable" in row,
        "actionable status badge missing",
    )
    for value in ("Spear phishing", "0.85", "LLM01", "T6", "AP-T6-01"):
        _expect(case, f">{value}" in row, f"row value {value!r} missing")
    gov_start = region.find("atlas-copyright")
    _expect(case, gov_start != -1, "no governance-only row rendered")
    gov_row = region[gov_start : region.find("</tr>", gov_start)]
    _expect(
        case,
        "status-badge status-governance" in gov_row,
        "governance status badge missing",
    )
    _expect(
        case,
        gov_row.count("-") >= 3,
        f"governance placeholders={gov_row.count('-')}",
    )


def qa_trsr_04() -> None:
    """QA-TRSR-04: empty threat surface renders placeholders."""
    case = "TRSR-04"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-04",
        threat_surface={"entries": [], "governance_only": []},
        scenarios=[_scenario("scn-01")],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-threats")
    _expect(case, "0 actionable / 0 governance" in region, "badge missing")
    _expect(
        case,
        "No actionable entries to visualize." in region,
        "Sankey placeholder missing",
    )


def qa_trsr_05() -> None:
    """QA-TRSR-05: outcomes column counts scenarios by priority."""
    case = "TRSR-05"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-05",
        threat_surface={
            "entries": [
                {
                    "risk_card": {"risk_id": "atlas-phishing"},
                    "owasp_llm_ids": [],
                    "agentic_threat_ids": ["T6"],
                    "attack_pattern_ids": [],
                }
            ],
            "governance_only": [],
        },
        scenarios=[
            _scenario(
                "scn-a",
                priority={"composite": 0.85},
                faceting={
                    "taxonomy_chain": {
                        "owasp_llm_ids": ["LLM01"],
                        "agentic_threat_ids": ["T6"],
                    }
                },
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-threats")
    _expect(case, ">Outcomes</th>" in region, "Outcomes column missing")
    row_start = region.find("atlas-phishing")
    row = region[row_start : region.find("</tr>", row_start)]
    _expect(case, ">1 scenarios" in row, "outcomes count missing")
    _expect(case, "1 high" in row, "high-priority chip missing")


def qa_trsr_06() -> None:
    """QA-TRSR-06: full coverage renders every card covered."""
    case = "TRSR-06"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-06",
        coverage={
            "coverage_gaps": {
                "uncovered_entry_points": [],
                "uncovered_zones": [],
                "uncovered_threats": [],
                "uncovered_attack_patterns": [],
            },
            "coverage_universe": {
                "completeness": "confirmed_complete",
                "evidence_refs": ["operator-confirmation.md"],
            },
        },
        scenarios=[_scenario("scn-01")],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-coverage")
    _expect(case, "Full Coverage" in region, "Full Coverage badge missing")
    statuses = _coverage_statuses(region)
    cards = ["Entry Points", "Active Zones", "In-Scope Threats", "Attack Patterns"]
    for card in cards:
        _expect(
            case,
            statuses.get(card) == "Covered",
            f"card {card!r} status={statuses.get(card)}",
        )
    messages = (
        "All confirmed entry points have scenario coverage.",
        "All active zones are traversed by scenarios.",
        "All in-scope threats have scenario coverage.",
        "All in-scope attack patterns have scenario coverage.",
    )
    for message in messages:
        _expect(case, message in region, f"message {message!r} missing")
    _expect(
        case,
        "Confirmed Complete" in region and "operator-confirmation.md" in region,
        "universe completeness or evidence missing",
    )
    _expect(case, '<a href="#sec-coverage">' in html, "sidebar link missing")


def qa_trsr_07() -> None:
    """QA-TRSR-07: coverage gaps render counts, tiers, attributions."""
    case = "TRSR-07"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-07",
        coverage={
            "coverage_gaps": {
                "uncovered_entry_points": [
                    {"name": "ze-query", "entry_point_id": "ze-query"},
                    {"name": "ze-gap-0", "entry_point_id": "ze-gap-0"},
                    {"name": "ze-gap-1", "entry_point_id": "ze-gap-1"},
                ],
                "uncovered_zones": ["zone-0"],
                "uncovered_threats": ["T1", "T2"],
                "uncovered_attack_patterns": [],
                "gap_attributions": {
                    "entry_points": {"ze-query": "deterministic_rule_rejection"}
                },
            },
            "coverage_universe": {
                "completeness": "not_applicable",
                "feasible_targets": [
                    {
                        "name": "ze-f0",
                        "entry_point_id": "ze-f0",
                        "direction": "input",
                        "controllability": "direct",
                    },
                    {
                        "name": "ze-f1",
                        "entry_point_id": "ze-f1",
                        "direction": "input",
                        "controllability": "direct",
                    },
                ],
                "excluded_targets": [
                    {
                        "name": "ze-x0",
                        "entry_point_id": "ze-x0",
                        "reason": "out of scope",
                    }
                ],
            },
        },
        scenarios=[_scenario("scn-01")],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-coverage")
    _expect(case, "6 gaps" in region, "6 gaps badge missing")
    statuses = _coverage_statuses(region)
    _expect(case, statuses.get("Entry Points") == "3 gaps", f"statuses={statuses}")
    _expect(case, statuses.get("Active Zones") == "1 gap", f"statuses={statuses}")
    _expect(case, statuses.get("In-Scope Threats") == "2 gaps", f"statuses={statuses}")
    ep_start = region.find(">Entry Points</span>")
    ep_card = region[ep_start : ep_start + 2000]
    _expect(
        case,
        "ze-query" in ep_card and "rejected by deterministic rules" in ep_card,
        "entry point attribution missing",
    )
    for card in ("Feasible Targets (2)", "Excluded Targets (1)"):
        _expect(case, card in region, f"universe card {card!r} missing")


def qa_trsr_08() -> None:
    """QA-TRSR-08: threat-technique matrix and roster render."""
    case = "TRSR-08"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-08",
        scenarios=[
            _scenario(
                "scn-a",
                faceting={
                    "taxonomy_chain": {
                        "owasp_llm_ids": ["LLM01"],
                        "agentic_threat_ids": ["T6"],
                        "scenario_seed": "AP-T6-01",
                        "atlas_technique_ids": ["AML.T0015"],
                    }
                },
                candidate_filter={
                    "pinned_technique_ids": ["AML.T0015"],
                    "pinned_technique_names": ["Phishing"],
                },
                actor_profile={
                    "actor_type": "cybercriminal",
                    "capability_level": "advanced",
                },
            ),
            _scenario(
                "scn-b",
                faceting={
                    "taxonomy_chain": {
                        "owasp_llm_ids": ["LLM02"],
                        "agentic_threat_ids": ["T11"],
                        "scenario_seed": "AP-T11-01",
                        "atlas_technique_ids": ["AML.T0015", "AML.T0040"],
                    }
                },
                candidate_filter={
                    "pinned_technique_ids": ["AML.T0040"],
                    "pinned_technique_names": ["LLM Data Leakage"],
                },
                actor_profile={
                    "actor_type": "nation-state",
                    "capability_level": "expert",
                },
            ),
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-threat-matrix")
    for badge in ("2/17 threats", "2 techniques", "2 scenarios"):
        _expect(case, badge in region, f"matrix badge {badge!r} missing")
    _expect(
        case,
        'class="matrix-count-link"' in region
        and 'href="#scenario-scn-a"' in region
        and ">1</a>" in region
        and "AML.T0015" in region,
        "T6 x AML.T0015 matrix cell missing",
    )
    _expect(
        case,
        'href="#scenario-scn-b"' in region and "AML.T0040" in region,
        "T11 x AML.T0040 matrix cell missing",
    )
    roster = region[region.find("Scenario Roster") :]
    for sid, threat, pattern, technique, actor, capability in (
        ("scn-a", "T6", "AP-T6-01", "AML.T0015", "Cybercriminal", "Advanced"),
        ("scn-b", "T11", "AP-T11-01", "AML.T0040", "Nation State", "Expert"),
    ):
        row_start = roster.find(sid)
        _expect(case, row_start != -1, f"roster row {sid!r} missing")
        row = roster[row_start : roster.find("</tr>", row_start)]
        visible = _visible(row)
        for value in (threat, pattern, technique, actor, capability):
            _expect(
                case,
                value in visible,
                f"roster {sid} missing {value!r}: {visible}",
            )


def qa_trsr_09() -> None:
    """QA-TRSR-09: matrix degrades when techniques are absent."""
    case = "TRSR-09"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-09",
        scenarios=[
            _scenario(
                "scn-a",
                faceting={
                    "taxonomy_chain": {
                        "owasp_llm_ids": ["LLM01"],
                        "agentic_threat_ids": ["T6"],
                        "scenario_seed": "AP-T6-01",
                        "atlas_technique_ids": [],
                    }
                },
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-threat-matrix")
    for badge in ("1/17 threats", "0 techniques", "1 scenarios"):
        _expect(case, badge in region, f"matrix badge {badge!r} missing")
    _expect(
        case,
        "matrix-col-header" not in region,
        "technique column headers still rendered",
    )
    roster = region[region.find("Scenario Roster") :]
    row_start = roster.find("scn-a")
    row = roster[row_start : roster.find("</tr>", row_start)]
    _expect(
        case, "AP-T6-01" in row and "AML." not in row, "roster technique cell not empty"
    )


def qa_trsr_10() -> None:
    """QA-TRSR-10: actor diversity, monotone warning, goals."""
    case = "TRSR-10"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-10",
        scenarios=[
            _scenario(
                f"scn-{letter}",
                actor_profile={
                    "actor_type": "cybercriminal",
                    "capability_level": "advanced",
                    "goal_category_parent": "integrity",
                },
            )
            for letter in ("a", "b", "c")
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-diversity")
    _expect(case, "1 type" in region, "diversity badge missing")
    bars = _diversity_bars(region)
    matched = [bar for bar in bars if bar[0] == "Cybercriminal"]
    _expect(
        case,
        bool(matched) and int(matched[0][1]) == 3 and "100" in matched[0][2],
        f"diversity bars={bars}",
    )
    visible = _visible(region)
    _expect(
        case,
        "Low actor diversity: 100% of scenarios use the Cybercriminal actor type."
        in visible,
        "diversity warning missing",
    )
    goals = [(label, int(count)) for label, count in _goal_bars(region)]
    _expect(case, ("Integrity", 3) in goals, f"goal bars={goals}")
    _expect(case, "1 category" in region, "goal category badge missing")


def qa_trsr_11() -> None:
    """QA-TRSR-11: priority signals grid renders six values."""
    case = "TRSR-11"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-11",
        scenarios=[
            _scenario(
                "scn-a",
                priority={
                    "composite": 0.72,
                    "signals": {
                        "technique_maturity": "realized",
                        "risk_impact": "critical",
                        "risk_likelihood": "high",
                        "attack_complexity": "medium",
                        "architecture_match": "explicit",
                        "structural_exposure": "elevated",
                    },
                },
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-scenarios")
    _expect(
        case, 'class="signals-grid"' in _card(html, "scn-a"), "signals grid missing"
    )
    labels = (
        "Technique Maturity",
        "Risk Impact",
        "Risk Likelihood",
        "Attack Complexity",
        "Architecture Match",
        "Structural Exposure",
    )
    for label in labels:
        _expect(case, f">{label}</div>" in region, f"signal label {label!r} missing")
    pairs = _signal_pairs(region)
    _expect(
        case,
        pairs.get("Technique Maturity") == "Realized"
        and pairs.get("Risk Impact") == "Critical",
        f"signal pairs={pairs}",
    )


def qa_trsr_12() -> None:
    """QA-TRSR-12: signals grid omitted when absent."""
    case = "TRSR-12"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-12",
        scenarios=[_scenario("scn-a", priority={"composite": 0.5})],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    _expect(
        case,
        'class="signals-grid"' not in _card(html, "scn-a"),
        "signals grid rendered unexpectedly",
    )


def qa_trsr_13() -> None:
    """QA-TRSR-13: actor profile block with BDI and access."""
    case = "TRSR-13"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-13",
        scenarios=[
            _scenario(
                "scn-a",
                actor_profile={
                    "actor_type": "malicious-insider",
                    "capability_level": "advanced",
                    "goal_category_name": "Sell stolen data",
                    "beliefs": ["Data is not monitored"],
                    "desires": ["Exfiltrate the billing database"],
                    "intentions": ["Move laterally to the data store"],
                    "resources": ["Incident response creds"],
                    "access": {
                        "ingress_mode": "network",
                        "initial_entry_point_id": "ze-query",
                        "influence_source": "helpdesk",
                    },
                },
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _card(html, "scn-a")
    for chip in ("Malicious Insider", "Advanced", "Sell Stolen Data"):
        _expect(case, f">{chip}</span>" in region, f"chip {chip!r} missing")
    for value in (
        "Data is not monitored",
        "Exfiltrate the billing database",
        "Move laterally to the data store",
        "Incident response creds",
    ):
        _expect(case, value in html, f"BDI value {value!r} missing")
    _expect(
        case,
        "Ingress: <strong>network</strong>" in html
        and "Entry point ID: <code>ze-query</code>" in html,
        "access provenance block missing",
    )


def qa_trsr_14() -> None:
    """QA-TRSR-14: actor profile block omitted when absent."""
    case = "TRSR-14"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-14",
        scenarios=[_scenario("scn-b")],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _card(html, "scn-b")
    _expect(
        case,
        "BELIEFS:" not in region and "ACCESS PROVENANCE:" not in region,
        "actor profile block rendered unexpectedly",
    )


def qa_trsr_15() -> None:
    """QA-TRSR-15: attack tree node shapes."""
    cases = (
        (
            "or",
            {
                "goal": "Gain access",
                "root": {
                    "gate": "OR",
                    "label": "Gain access",
                    "children": [
                        {
                            "gate": "LEAF",
                            "label": "Leaf 1",
                            "technique_id": "AML.T0015",
                        },
                        {
                            "gate": "LEAF",
                            "label": "Leaf 2",
                            "technique_id": "AML.T0040",
                        },
                    ],
                },
            },
        ),
        (
            "leaf",
            {
                "goal": "Exfiltrate data",
                "root": {"gate": "LEAF", "label": "Exfiltrate data"},
            },
        ),
        ("none", {"goal": ""}),
    )
    for label, tree in cases:
        case = f"TRSR-15-{label}"
        run_dir = _build_run(
            RUN_ROOT / "fixtures" / case,
            scenarios=[_scenario("scn-a", attack_tree=tree)],
        )
        ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
        if not ok:
            failures.append(f"{case}: report command failed: {html}")
            continue
        region = _card(html, "scn-a")
        if label == "or":
            _expect(
                case,
                region.count('class="tree-leaf"') == 2
                and "gate-or" in region
                and "AML.T0015" in region
                and "AML.T0040" in region,
                "OR gate summary or leaf badges missing",
            )
        elif label == "leaf":
            _expect(
                case,
                region.count('class="tree-leaf"') == 1
                and "gate-or" not in region
                and "gate-and" not in region,
                "single leaf or gate summary mismatch",
            )
        else:
            _expect(
                case,
                region.count('class="tree-leaf"') == 0
                and "<details open" not in region
                and "gate-or" not in region,
                "absent tree still renders node markup",
            )


def qa_trsr_16() -> None:
    """QA-TRSR-16: unresolved tree resource IDs render honestly."""
    case = "TRSR-16"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-16",
        profile={},
        scenarios=[
            _scenario(
                "scn-a",
                attack_tree={
                    "goal": "Gain access",
                    "root": {
                        "gate": "OR",
                        "label": "Gain access",
                        "children": [
                            {
                                "gate": "LEAF",
                                "label": "Run the tool",
                                "action": {
                                    "kind": "tool_invocation",
                                    "tool_id": "tool-code",
                                },
                            },
                            {
                                "gate": "LEAF",
                                "label": "Enter the portal",
                                "action": {
                                    "kind": "initial_ingress",
                                    "entry_point_id": "ze-gone",
                                    "zone": "input",
                                },
                            },
                        ],
                    },
                },
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _card(html, "scn-a")
    _expect(
        case,
        "Tool: Unresolved" in region and "<code>tool-code</code>" in region,
        "unresolved tool meta missing",
    )
    _expect(
        case,
        "Entry Point: Unresolved" in region and "<code>ze-gone</code>" in region,
        "unresolved entry point meta missing",
    )


def qa_trsr_17() -> None:
    """QA-TRSR-17: scenarios dashboard and cards."""
    case = "TRSR-17"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-17",
        scenarios=[
            _scenario(
                "scn-a",
                priority={"composite": 0.85},
                narrative={
                    "title": "Phishing the support desk",
                    "summary": "",
                    "entry_point": "",
                    "zone_sequence": [],
                },
            ),
            _scenario(
                "scn-b",
                priority={"composite": 0.35},
                narrative={
                    "title": "Exfiltrate via RAG",
                    "summary": "",
                    "entry_point": "",
                    "zone_sequence": [],
                },
            ),
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-scenarios")
    stats = _stats(region)
    expected = {
        "In Report": 2,
        "High Priority": 1,
        "Medium Priority": 0,
        "Low Priority": 1,
        "Coverage Gaps": 0,
    }
    for label, count in expected.items():
        _expect(
            case,
            stats.get(label) == count,
            f"dashboard stat {label}={stats.get(label)}, expected {count}",
        )
    for sid, title in (
        ("scn-a", "Phishing the support desk"),
        ("scn-b", "Exfiltrate via RAG"),
    ):
        _expect(
            case,
            f'id="scenario-{sid}"' in html and title in html,
            f"card {sid} or title {title!r} missing",
        )
    _expect(
        case,
        html.find('id="scenario-scn-a"') != -1
        and html.find('id="scenario-scn-a"') < html.find('id="scenario-scn-b"'),
        "cards are not sorted high first",
    )


def qa_trsr_18() -> None:
    """QA-TRSR-18: minimal scenario card keeps every tab."""
    case = "TRSR-18"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-18",
        scenarios=[_scenario("scn-min", priority=None)],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-scenarios")
    _expect(
        case,
        re.search(r'class="priority-badge"[^>]*>\s*LOW\s*</span>', region) is not None,
        "priority badge LOW missing",
    )
    _expect(case, ">0.00</span>" in region, "score 0.00 missing")
    tab_labels = (
        "Provenance",
        "Generation Inputs",
        "Actor Profile",
        "ATLAS Techniques",
        "Narrative",
        "Attack Tree",
        "Behavior Spec",
        "Priority Signals",
        "LLM Calls",
    )
    for label in tab_labels:
        _expect(case, f">{label}" in region, f"tab label {label!r} missing")
    _expect(case, "zone-crumb" not in region, "zone crumbs rendered")


def qa_trsr_19() -> None:
    """QA-TRSR-19: empty scenarios placeholder."""
    case = "TRSR-19"
    run_dir = _build_run(RUN_ROOT / "fixtures" / "trsr-19")
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    _expect(
        case,
        'id="sec-scenarios"' in html and "No scenarios generated." in html,
        "scenarios placeholder missing",
    )


def qa_trsr_20() -> None:
    """QA-TRSR-20: run summary funnel, stats, config."""
    case = "TRSR-20"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-20",
        scenarios=[_scenario("scn-a")],
        manifest_extra={
            "seeds_generated": 12,
            "funnel": {
                "expanded_instances": 10,
                "filter_submitted": 6,
                "filter_accepted": 3,
            },
            "scenarios_generated": 4,
            "scenarios_failed": 1,
            "config": {"model": "gemma-3-27b", "temperature": 0.7},
            "timestamp_start": "2026-08-24T10:00:00",
            "timestamp_end": "2026-08-24T10:05:30",
        },
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-run-summary")
    stats = _stats(region)
    funnel = {
        "Seeds Generated": 12,
        "Candidates Expanded": 10,
        "Candidates Accepted": 3,
        "Scenarios Generated": 4,
        "In Report": 1,
    }
    for label, count in funnel.items():
        _expect(
            case,
            stats.get(label) == count,
            f"funnel stat {label}={stats.get(label)}, expected {count}",
        )
    _expect(case, stats.get("Failed") == 1, f"Failed stat={stats.get('Failed')}")
    _expect(case, stats.get("Rejected") == 3, f"Rejected stat={stats.get('Rejected')}")
    _expect(case, ">30.0%</span>" in region, "rejection rate 30.0% missing")
    _expect(case, "5m 30s" in region, "duration 5m 30s missing")
    for value in (
        ">gemma-3-27b</div>",
        ">0.7</div>",
        "2026-08-24T10:00:00",
        "2026-08-24T10:05:30",
    ):
        _expect(case, value in region, f"config/timestamp {value!r} missing")


def qa_trsr_21() -> None:
    """QA-TRSR-21: absent run manifest — CLI refusal boundary."""
    case = "TRSR-21"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-21",
        scenarios=[_scenario("scn-a")],
        write_manifest=False,
    )
    out_dir = RUN_ROOT / "reports" / case
    completed = _run_cli_raw(case, run_dir, out_dir)
    _expect(
        case,
        completed.returncode != 0,
        f"report command unexpectedly succeeded: {completed.stdout[-300:]}",
    )
    _expect(
        case,
        not (out_dir / "report.html").is_file(),
        "report.html produced despite missing manifest",
    )
    notes.append(
        f"{case}: report command refuses a manifest-less run dir "
        f"(exit {completed.returncode}); the 'no Run Summary section' "
        "rendering pin is acceptance-harness-only and covered by Gherkin"
    )


def qa_trsr_22() -> None:
    """QA-TRSR-22: run summary honest absence values."""
    case = "TRSR-22"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-22",
        scenarios=[_scenario("scn-a")],
        manifest_extra={
            "seeds_generated": 0,
            "funnel": {},
            "scenarios_generated": 0,
            "scenarios_failed": 0,
            "config": {},
            "timestamp_start": "",
            "timestamp_end": None,
        },
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-run-summary")
    _expect(case, ">N/A</span>" in region, "rejection rate N/A missing")
    _expect(case, ">unknown</div>" in region, "model unknown missing")
    _expect(
        case,
        region.count(">N/A</div>") >= 3,
        f"N/A divs={region.count('>N/A</div>')}",
    )


def qa_trsr_23() -> None:
    """QA-TRSR-23: raw data YAML and Gherkin highlighting."""
    case = "TRSR-23"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-23",
        include_threat_surface=False,
        include_coverage=False,
        profile_text=(
            "# profile snippet\n"
            'completeness: "confirmed"\n'
            "count: 3\n"
            "enabled: true\n"
            "note: null\n"
        ),
        scenarios=[_scenario("scn-a")],
        feature_files={
            "scn-a": "# smoke suite\n@smoke\nFeature: Demo\n  Given a precondition\n"
        },
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-raw")
    # The CLI loader inventories the capability profile plus the scenario
    # YAML/feature pair, so three raw panels render (procedure's acceptance
    # fixture passes a hand-built two-file dict; the badge count follows the
    # actual inventory here).
    raw_files = re.findall(r'class="raw-tab(?: active)?"[^>]*>([^<]+)</button>', region)
    _expect(
        case,
        f"{len(raw_files)} files" in region,
        f"raw badge does not match panels ({raw_files})",
    )
    _expect(case, 'class="yaml-comment"' in region, "yaml comment missing")
    _expect(case, 'class="yaml-key">completeness</span>' in region, "yaml key missing")
    _expect(case, 'class="yaml-number">3</span>' in region, "yaml number missing")
    _expect(case, 'class="yaml-bool">true</span>' in region, "yaml bool missing")
    _expect(case, 'class="yaml-null">null</span>' in region, "yaml null missing")
    _expect(
        case,
        "&quot;confirmed&quot;" in region and "yaml-string" not in region,
        "quoted string highlight mismatch",
    )
    _expect(case, 'class="gherkin-comment"' in region, "gherkin comment missing")
    _expect(case, 'class="gherkin-tag">@smoke</span>' in region, "gherkin tag missing")
    for keyword in ("Feature:</span>", "Given </span>"):
        _expect(
            case,
            f'class="gherkin-keyword">{keyword}' in region,
            f"gherkin keyword {keyword!r} missing",
        )
    notes.append(
        f"{case}: raw badge reflects the CLI inventory ({len(raw_files)} files, "
        "procedure fixture is a hand-built 2-file dict); highlighting pins "
        "verified verbatim"
    )


def qa_trsr_24() -> None:
    """QA-TRSR-24: generation inputs block."""
    case = "TRSR-24"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-24",
        scenarios=[
            _scenario(
                "scn-a",
                scenario_seed_metadata={
                    "attack_pattern_name": "Prompt injection",
                    "threat_id": "T6",
                    "threat_name": "Social engineering",
                },
                faceting={
                    "taxonomy_chain": {
                        "owasp_llm_ids": [],
                        "agentic_threat_ids": [],
                        "atlas_technique_ids": ["AML.T0015"],
                    }
                },
                narrative={
                    "title": "Phish the desk",
                    "summary": "",
                    "entry_point": "",
                    "zone_sequence": [],
                },
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-scenarios")
    for header in ("Call 0: Actor Profile", "Call 3: Behavior Spec"):
        _expect(case, header in region, f"call header {header!r} missing")
    _expect(
        case,
        ">Attack pattern</td>" in region and "Prompt injection" in region,
        "attack pattern row missing",
    )
    _expect(
        case,
        ">Threat</td>" in region and "T6 — Social engineering" in region,
        "threat row missing",
    )
    _expect(
        case,
        ">ATLAS techniques</td>" in region and "AML.T0015" in region,
        "ATLAS techniques row missing",
    )
    _expect(
        case,
        ">Narrative summary</td>" in region and ">—</td>" in region,
        "narrative summary em dash missing",
    )


def qa_trsr_25() -> None:
    """QA-TRSR-25: behavior spec rendering and degradation."""
    case = "TRSR-25"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-25",
        scenarios=[
            _scenario("scn-a"),
            _scenario("scn-b"),
        ],
        feature_files={
            "scn-a": (
                "Feature: scn-a\n"
                "  Given a precondition\n"
                "  When the event occurs\n"
                "  Then the outcome holds\n"
            ),
            "scn-b": "",
        },
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _card(html, "scn-a")
    for keyword in ("Given", "When", "Then"):
        _expect(
            case,
            f'class="step-keyword">{keyword}</span>' in region,
            f"step keyword {keyword!r} missing",
        )
    for text in ("a precondition", "the event occurs", "the outcome holds"):
        _expect(
            case,
            f'class="step-text">{text}</span>' in region,
            f"step text {text!r} missing",
        )
    _expect(
        case,
        "No behavior specification available." in _card(html, "scn-b"),
        "scn-b behavior placeholder missing",
    )


def qa_trsr_26() -> None:
    """QA-TRSR-26: ATLAS techniques block and none placeholder."""
    case = "TRSR-26"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-26",
        scenarios=[
            _scenario(
                "scn-a",
                faceting={
                    "taxonomy_chain": {
                        "owasp_llm_ids": [],
                        "agentic_threat_ids": [],
                        "atlas_technique_ids": ["AML.T0015"],
                    }
                },
                technique_scope_evidence={
                    "scenario_classification_ids": ["AML.T0015"],
                    "projected_step_mapping_ids": [],
                },
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _card(html, "scn-a")
    _expect(
        case, "Scenario classifications" in region, "classifications heading missing"
    )
    block = region[
        region.find("Scenario classifications") : region.find("Projected-step mappings")
    ]
    _expect(case, "AML.T0015" in block, "classification badge missing")
    _expect(
        case,
        "Projected-step mappings" in html
        and '<span class="prov-badge prov-badge-muted">none</span>' in html,
        "projected-step none placeholder missing",
    )


def qa_trsr_27() -> None:
    """QA-TRSR-27: attack complexity assessment."""
    case = "TRSR-27"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-27",
        scenarios=[
            _scenario(
                "scn-a",
                attack_complexity_assessment={
                    "rule_version": 3,
                    "candidate_lower_bound": {"required_level": "advanced"},
                    "final": {
                        "required_level": "expert",
                        "reasons": [
                            {
                                "rule_id": "R-7",
                                "required_level": "expert",
                                "detail": "requires chaining three tools",
                                "evidence": [{"kind": "projection", "ref_id": "R7"}],
                            }
                        ],
                    },
                },
            )
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-scenarios")
    _expect(
        case,
        "ATTACK COMPLEXITY (RULE V3):" in _card(html, "scn-a"),
        "complexity heading missing",
    )
    visible = _visible(region)
    _expect(
        case,
        "Candidate lower bound: Advanced" in visible
        and "Final required level: Expert" in visible,
        "complexity levels missing",
    )
    _expect(
        case,
        "R-7 → expert: requires chaining three tools [projection:R7]" in visible,
        "complexity reason line missing",
    )


def qa_trsr_28() -> None:
    """QA-TRSR-28: attack complexity omitted when absent."""
    case = "TRSR-28"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-28",
        scenarios=[_scenario("scn-b")],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    _expect(
        case,
        "ATTACK COMPLEXITY" not in _card(html, "scn-b"),
        "attack complexity block rendered unexpectedly",
    )


def qa_trsr_29() -> None:
    """QA-TRSR-29: pipeline call logs and semantic status."""
    case = "TRSR-29"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-29",
        scenarios=[_scenario("scn-a")],
        calls=[
            {
                "call": "candidate_filter",
                "prompt_tokens": 100,
                "completion_tokens": 40,
                "duration_ms": 25,
                "semantic_evidence": {
                    "stage": "candidate_filter",
                    "accepted_draft_digest": "accepted-draft-digest",
                    "attempts": [{"result": "accepted"}],
                },
            },
            {
                "call": "capability_profile",
                "prompt_tokens": 50,
                "completion_tokens": 20,
                "duration_ms": 15,
                "semantic_evidence": {
                    "stage": "capability_profile",
                    "attempts": [{"result": "invalid"}],
                },
            },
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-pipeline-calls")
    for value in (
        "2 call(s)",
        "150 prompt tokens",
        "60 completion tokens",
        "40ms total",
    ):
        _expect(case, value in region, f"pipeline total {value!r} missing")
    visible = _visible(region)
    _expect(
        case,
        "Candidate Filter semantic draft: Accepted provider semantics" in visible,
        "accepted semantic status missing",
    )
    _expect(
        case,
        "Capability Profile semantic draft: Rejected: invalid" in visible,
        "rejected semantic status missing",
    )


def qa_trsr_31() -> None:
    """QA-TRSR-31: behavior spec headers, tags, docstrings, And steps, zone badges."""
    case = "TRSR-31"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-31",
        scenarios=[_scenario("scn-a")],
        feature_files={
            "scn-a": (
                "@smoke\n"
                "Scenario: Phish the desk\n"
                "  Given access through (Zone input)\n"
                "  And escalate privileges\n"
                '  """\n'
                "  requires a compromised credential\n"
                '  """\n'
            )
        },
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _card(html, "scn-a")
    _expect(
        case,
        re.search(r"Scenario:</span>\s*Phish the desk</div>", region) is not None,
        "Scenario header with Phish the desk missing",
    )
    _expect(
        case,
        'class="step-keyword">And</span><span class="step-text">'
        "escalate privileges</span>" in region,
        "And step missing",
    )
    _expect(
        case,
        'class="step-keyword">Given</span><span class="step-text">'
        'access through (Zone input)<span class="zone-badge"' in region,
        "Given step with zone badge missing",
    )
    _expect(
        case,
        ">Input Surfaces</span>" in region,
        "zone badge Input Surfaces missing",
    )
    _expect(
        case,
        '<div class="step-docstring">requires a compromised credential</div>' in region,
        "step-docstring block missing",
    )
    # Tag lines are skipped by the behavior-spec builder; the raw-data
    # section later in the document still shows the fixture feature file,
    # so scope the no-tag pin to the rendered spec block (up to the next
    # tab panel).
    spec_start = region.find('<div class="feature-spec">')
    spec_end = region.find('<div class="tab-panel">', spec_start)
    if spec_end == -1:
        spec_end = spec_start + 4000
    _expect(
        case,
        spec_start != -1 and "@smoke" not in region[spec_start:spec_end],
        "tag @smoke rendered in behavior spec tab",
    )


def qa_trsr_32() -> None:
    """QA-TRSR-32: per-scenario LLM call entries."""
    case = "TRSR-32"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-32",
        scenarios=[_scenario("scn-a")],
        scenario_calls=[
            {
                "scenario_id": "scn-a",
                "call": "actor_profile",
                "prompt_tokens": 100,
                "completion_tokens": 40,
                "duration_ms": 250,
                "system_prompt": "Assess the profile",
                "user_prompt": "Profile the capability",
                "success": True,
            },
            {
                "scenario_id": "scn-a",
                "call": "behavior_spec",
                "prompt_tokens": 30,
                "completion_tokens": 10,
                "duration_ms": 80,
                "system_prompt": "Generate the feature",
                "user_prompt": "Write the behavior",
                "success": False,
                "error": "timeout",
            },
        ],
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _card(html, "scn-a")
    for entry in (
        "Call 0: Actor Profile (100 prompt / 40 completion tokens, 250ms)",
        "Call 1: Behavior Spec (30 prompt / 10 completion tokens, 80ms)"
        " FAILED: timeout",
    ):
        _expect(case, entry in region, f"call entry {entry!r} missing")
    for prompt in (
        "Assess the profile",
        "Profile the capability",
        "Generate the feature",
        "Write the behavior",
    ):
        _expect(case, prompt in region, f"prompt {prompt!r} missing")
    _expect(case, 'class="call-log-pre"' in region, "call-log-pre block missing")


def qa_trsr_33() -> None:
    """QA-TRSR-33: categorized coverage summary, plan, not-confirmed universe."""
    case = "TRSR-33"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-33",
        scenarios=[_scenario("scn-a")],
        coverage={
            "coverage_gaps": {
                "uncovered_entry_points": [],
                "uncovered_zones": [],
                "uncovered_threats": [],
                "uncovered_attack_patterns": [],
            },
            "coverage_universe": {"completeness": "not_applicable"},
            "coverage_summary": {
                "covered_feasible": ["AP-T6-01"],
                "selection_limitations": [
                    {
                        "entry_point_id": "ze-query",
                        "reason": "selection_limitation",
                        "detail": "candidate queue saturated",
                        "candidate_ids": ["cand-42"],
                    }
                ],
                "policy_exclusions": [
                    {"entry_point_id": "ze-license", "reason": "out_of_scope"}
                ],
            },
            "coverage_plan": {
                "schema_version": 1,
                "targets": [
                    {
                        "entry_point_id": "ze-query",
                        "entry_point_name": "ze-query",
                        "primary_candidate_id": "cand-42",
                        "primary_state": "planned",
                        "ordered_choices": [
                            {"candidate_id": "cand-42"},
                            {"candidate_id": "cand-7"},
                        ],
                    }
                ],
            },
        },
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-coverage")
    _expect(case, "Known Targets Covered" in region, "coverage badge missing")
    for message in (
        "All identified feasible entry points have scenario coverage; "
        "inventory completeness is not confirmed.",
        "All active zones are traversed by scenarios.",
        "All in-scope threats have scenario coverage.",
        "All in-scope attack patterns have scenario coverage.",
    ):
        _expect(case, message in region, f"message {message!r} missing")
    _expect(
        case,
        "Covered Feasible Targets" in region and ">AP-T6-01</li>" in region,
        "covered feasible targets card missing",
    )
    visible = _visible(region)
    _expect(
        case, "Selection Limitations" in region, "selection limitations card missing"
    )
    _expect(
        case,
        "cap overflow (coverage preserved)" in visible,
        "selection reason missing",
    )
    _expect(case, "candidate queue saturated" in visible, "selection detail missing")
    _expect(case, "cand-42" in visible, "selection candidate code missing")
    _expect(case, "Policy Exclusions" in region, "policy exclusions card missing")
    _expect(case, "out of scope" in visible, "policy exclusion reason missing")
    _expect(case, "Coverage Plan (schema v1)" in region, "coverage plan table missing")
    _expect(
        case,
        "ze-query" in region and "cand-42" in region and ">planned</td>" in region,
        "coverage plan row missing",
    )
    _expect(
        case,
        "Not Applicable (Inferred Partial)" in region,
        "universe completeness label missing",
    )
    _expect(
        case, "No operator-confirmed evidence" in region, "universe evidence missing"
    )


def qa_trsr_34() -> None:
    """QA-TRSR-34: run summary outcome summary and coverage gaps card."""
    case = "TRSR-34"
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-34",
        scenarios=[
            _scenario("scn-a", priority={"composite": 0.85}),
            _scenario("scn-b", priority={"composite": 0.35}),
        ],
        coverage={
            "coverage_gaps": {
                "uncovered_entry_points": [
                    {"name": "ze-query", "entry_point_id": "ze-query"}
                ],
                "uncovered_zones": ["input"],
                "uncovered_threats": ["T6", "T11"],
                "uncovered_attack_patterns": [],
            },
            "coverage_universe": {"completeness": "not_applicable"},
        },
        manifest_extra={
            "seeds_generated": 12,
            "funnel": {
                "expanded_instances": 10,
                "filter_submitted": 6,
                "filter_accepted": 3,
            },
            "scenarios_generated": 4,
            "scenarios_failed": 1,
        },
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-run-summary")
    # The Scenarios dashboard later in the document carries its own
    # "Coverage Gaps" stat, so read the Outcome Summary block in isolation.
    start = region.find("Outcome Summary")
    outcome_region = region[start : start + 3000]
    stats = _stats(outcome_region)
    for label, count in (
        ("High Priority", 1),
        ("Medium Priority", 0),
        ("Low Priority", 1),
    ):
        _expect(
            case,
            stats.get(label) == count,
            f"outcome {label}={stats.get(label)}, expected {count}",
        )
    _expect(
        case,
        stats.get("Coverage Gaps") == 4,
        f"coverage card stats={stats.get('Coverage Gaps')}",
    )


def qa_trsr_35() -> None:
    """QA-TRSR-35: scenarios-section sub-charts and filters."""
    case = "TRSR-35"
    signals = {
        "technique_maturity": "realized",
        "risk_impact": "critical",
        "risk_likelihood": "high",
        "attack_complexity": "medium",
        "architecture_match": "explicit",
        "structural_exposure": "elevated",
    }
    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-35",
        scenarios=[
            _scenario(
                "scn-a",
                priority={"composite": 0.72, "signals": signals},
                faceting={
                    "taxonomy_chain": {
                        "owasp_llm_ids": ["LLM01"],
                        "agentic_threat_ids": ["T6"],
                    },
                    "capability_profile": {
                        "zones_traversed": ["input", "tool_execution"]
                    },
                },
                narrative={
                    "title": "scn-a",
                    "summary": "",
                    "entry_point": "ze-query",
                    "zone_sequence": ["input", "tool_execution"],
                },
            ),
            _scenario(
                "scn-b",
                priority={"composite": 0.35, "signals": signals},
                faceting={
                    "taxonomy_chain": {
                        "owasp_llm_ids": ["LLM02"],
                        "agentic_threat_ids": ["T6"],
                    },
                    "capability_profile": {"zones_traversed": ["input"]},
                },
                narrative={
                    "title": "scn-b",
                    "summary": "",
                    "entry_point": "ze-rag",
                    "zone_sequence": ["input"],
                },
            ),
        ],
        manifest_extra={"scenarios_generated": 4},
    )
    ok, html = _run_report(case, run_dir, RUN_ROOT / "reports" / case)
    if not ok:
        failures.append(f"{case}: report command failed: {html}")
        return
    region = _region(html, "sec-scenarios")
    _expect(
        case,
        "Risk Impact: critical" in region,
        "signal decomposition segment tooltip missing",
    )
    _expect(
        case,
        "Threat x Zone Coverage" in region
        and 'data-tooltip="T6 x Input Surfaces: 2 scenarios"' in region,
        "threat x zone matrix cell missing",
    )
    for expected in (
        ">Input Surfaces</div>",
        ">Tool Execution</div>",
    ):
        _expect(case, expected in region, f"matrix zone header {expected!r} missing")
    _expect(
        case,
        'class="ep-dist-name" data-tooltip="ze-query"' in region
        and 'class="ep-dist-name" data-tooltip="ze-rag"' in region,
        "entry point distribution entries missing",
    )
    _expect(
        case,
        'data-filter-type="threat" data-filter-value="T6"' in region,
        "threat filter chip missing",
    )
    _expect(
        case,
        'data-filter-type="zone" data-filter-value="input"' in region
        and ">Input Surfaces</span>" in region
        and 'data-filter-type="zone" data-filter-value="tool_execution"' in region
        and ">Tool Execution</span>" in region,
        "zone filter chips missing",
    )
    for priority in ("high", "medium", "low"):
        _expect(
            case,
            f'data-filter-type="priority" data-filter-value="{priority}"' in region,
            f"priority filter chip {priority!r} missing",
        )
    _expect(
        case,
        '<span class="stat-label">In Report</span>' in region
        and ">of 4 generated</span>" in region,
        "In Report sublabel of 4 generated missing",
    )
    crumbs = _card(html, "scn-a")
    _expect(
        case,
        'class="zone-crumb"' in crumbs
        and ">input</span>" in crumbs
        and ">tool_execution</span>" in crumbs
        and "&rarr;" in crumbs,
        "scn-a narrative zone crumbs missing",
    )


def qa_trsr_36() -> None:
    """QA-TRSR-36: conflicting corpus claims refuse the report command."""
    case = "TRSR-36"

    def _claims(evidence: str) -> list[dict[str, str]]:
        return [
            {
                "category": "entry_points",
                "status": "applicable",
                "evidence": [evidence],
            },
            {
                "category": "tool_inventory",
                "status": "not_applicable",
                "reason": "QA fixture",
            },
        ]

    run_dir = _build_run(
        RUN_ROOT / "fixtures" / "trsr-36",
        scenarios=[
            _scenario(
                "scn-a",
                validation={
                    "semantic": {"corpus_claim_applicability": _claims("a.md")}
                },
            ),
            _scenario(
                "scn-b",
                validation={
                    "semantic": {"corpus_claim_applicability": _claims("b.md")}
                },
            ),
        ],
    )
    out_dir = RUN_ROOT / "reports" / case
    completed = _run_cli_raw(case, run_dir, out_dir)
    _expect(
        case,
        completed.returncode != 0,
        f"report command unexpectedly succeeded: {completed.stdout[-300:]}",
    )
    _expect(
        case,
        not (out_dir / "report.html").is_file(),
        "report.html produced despite conflicting corpus claims",
    )
    _expect(
        case,
        "entry_points" in (completed.stderr or ""),
        "conflicting category not named in stderr",
    )


def _run_gate(name: str, argv: list[str], timeout: int = 3600) -> tuple[bool, str]:
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


def qa_trsr_30() -> None:
    """QA-TRSR-30: deterministic repository gates and output hygiene."""
    if os.environ.get(QA_PIPELINE_ENV):
        failures.append("30: ASAGO_SCENARIO_GENERATOR_QA_PIPELINE must not be set")
    statuses = [
        _run_gate("quality.sh", ["./scripts/quality.sh"], timeout=900),
        _run_gate("acceptance.sh", ["./scripts/acceptance.sh"], timeout=3600),
        _run_gate("unit tests", [_UV, "run", "pytest", "tests/", "-q"], timeout=3600),
    ]
    for ok, message in statuses:
        if ok:
            notes.append(f"30: {message.splitlines()[0]}")
        else:
            failures.append(f"30: {message}")
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
                "lcov",
                "htmlcov",
                "tmp/qa-taxonomy-report-sections-rendering",
                "tmp/qa-taxonomy-report-rendering",
                "tmp/qa-clean-checkout",
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
            "30: unexpected tracked/staged generated artifacts:\n"
            + "\n".join(unexpected)
        )
    if staged_paths:
        failures.append(f"30: staged paths present: {staged_paths}")
    if not unexpected and not staged_paths:
        notes.append(
            "30: no generated acceptance IR, coverage, or QA captures tracked/staged"
        )


def main() -> int:
    """Run all taxonomy-report-section-rendering QA procedures."""
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2
    print(f"QA evidence: {RUN_ROOT.relative_to(REPO_ROOT)}", flush=True)
    for procedure in (
        qa_trsr_01,
        qa_trsr_02,
        qa_trsr_03,
        qa_trsr_04,
        qa_trsr_05,
        qa_trsr_06,
        qa_trsr_07,
        qa_trsr_08,
        qa_trsr_09,
        qa_trsr_10,
        qa_trsr_11,
        qa_trsr_12,
        qa_trsr_13,
        qa_trsr_14,
        qa_trsr_15,
        qa_trsr_16,
        qa_trsr_17,
        qa_trsr_18,
        qa_trsr_19,
        qa_trsr_20,
        qa_trsr_21,
        qa_trsr_22,
        qa_trsr_23,
        qa_trsr_24,
        qa_trsr_25,
        qa_trsr_26,
        qa_trsr_27,
        qa_trsr_28,
        qa_trsr_29,
        qa_trsr_31,
        qa_trsr_32,
        qa_trsr_33,
        qa_trsr_34,
        qa_trsr_35,
        qa_trsr_36,
    ):
        procedure()
        print(f"  [done] {procedure.__name__}", flush=True)
    if os.environ.get("QA_SKIP_GATES"):
        print("\n--- QA-TRSR-30 skipped (QA_SKIP_GATES set) ---", flush=True)
    else:
        print("\n--- QA-TRSR-30: deterministic repository gates ---", flush=True)
        qa_trsr_30()
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
    / "qa-taxonomy-report-sections-rendering"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)


if __name__ == "__main__":
    sys.exit(main())

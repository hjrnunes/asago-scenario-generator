"""Automated run scorer against MiniKlarna gold set.

Matches compiled conversation artifacts and identifies loss stages for unmatched cases.
See ai/findings/target-grounded-scenario-generation-spec-2026-09-07.md (Phase 0).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from scripts.gold.gold_cases import (
    GoldCase,
    atomic_write_text,
    check_gold_case_applicability,
    compute_gold_digest,
    load_gold_file,
)


@dataclass
class CompiledArtifact:
    scenario_id: str
    artifact_path: Path
    plan_path: Path | None
    messages: list[dict[str, str]]
    oracle_kind: str
    tool_name: str | None
    argument_name: str | None
    condition_type: str | None
    expected: Any
    semantic_proposition: str | None
    tools: list[str]

    def all_user_text(self) -> str:
        return "\n".join(
            m.get("content", "") for m in self.messages if m.get("role") == "user"
        )


@dataclass
class MatchProposal:
    gold_id: str
    scenario_id: str
    rule1_tool: str
    rule2_entity: str
    rule3_direction: str
    argument_evidence: str


@dataclass
class UnmatchedGoldHint:
    scenario_id: str
    control_action: str | None
    operations: list[str]
    exclusion_code: str | None
    compiled: bool
    note: str


@dataclass
class UnmatchedGoldCase:
    gold_id: str
    title: str
    family: str
    loss_stage: str
    hints: list[UnmatchedGoldHint] = field(default_factory=list)


def find_synthesis_artifacts_dir(run_dir: Path) -> Path | None:
    """Locate directory containing compiled scenario subdirectories and manifest."""
    # Check directly in run_dir
    if (run_dir / "artifact-manifest.json").is_file():
        return run_dir
    # Check artifacts-garak / artifacts; sorted so the result is deterministic
    # when several synthesis directories exist.
    for sub in ["artifacts-garak", "artifacts"]:
        candidate_dir = run_dir / sub
        if candidate_dir.is_dir():
            for child in sorted(candidate_dir.iterdir()):
                if child.is_dir() and (child / "artifact-manifest.json").is_file():
                    return child
    # Search recursively for artifact-manifest.json
    for manifest_path in sorted(run_dir.rglob("artifact-manifest.json")):
        return manifest_path.parent
    return None


def _ready_scenario_ids(artifacts_dir: Path) -> set[str] | None:
    """Scenario IDs the manifest marks ready, or None when unknown."""
    manifest_file = artifacts_dir / "artifact-manifest.json"
    if not manifest_file.is_file():
        return None
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except Exception:
        return None
    ready: set[str] = set()
    for entry in manifest.get("entries", []):
        if not isinstance(entry, dict):
            continue
        sid = entry.get("scenario_id")
        if sid and entry.get("overall") == "ready":
            ready.add(str(sid))
    return ready


def load_compiled_artifacts(artifacts_dir: Path) -> list[CompiledArtifact]:
    ready = _ready_scenario_ids(artifacts_dir)
    artifacts: list[CompiledArtifact] = []
    for scn_dir in sorted(artifacts_dir.iterdir()):
        if not scn_dir.is_dir():
            continue
        conv_file = scn_dir / "executable-conversation.json"
        if not conv_file.is_file():
            continue

        try:
            conv_data = json.loads(conv_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        scenario_id = conv_data.get("case_id") or scn_dir.name
        # normalize SCN id if case_id was e.g. SCN-026-conv
        if scn_dir.name.startswith("SCN-"):
            scenario_id = scn_dir.name

        # Cross-check against the manifest: a conversation without a ready
        # manifest entry is not treated as compiled.
        if ready is not None and scenario_id not in ready:
            continue

        plan_file = scn_dir / "execution-plan.json"
        plan_path = plan_file if plan_file.is_file() else None

        oracle = conv_data.get("structured_oracle", {}) or {}
        messages = conv_data.get("messages", [])
        tools_raw = conv_data.get("tools", [])
        tools_list: list[str] = []
        for t in tools_raw:
            if isinstance(t, dict):
                # Compiled artifacts use the OpenAI-style {"function": {"name": ...}}
                # envelope; accept the flat shape too.
                function = t.get("function")
                if isinstance(function, dict):
                    tools_list.append(
                        function.get("name") or function.get("tool_name", "")
                    )
                else:
                    tools_list.append(t.get("name") or t.get("tool_name", ""))
            elif isinstance(t, str):
                tools_list.append(t)

        artifacts.append(
            CompiledArtifact(
                scenario_id=scenario_id,
                artifact_path=conv_file,
                plan_path=plan_path,
                messages=messages,
                oracle_kind=oracle.get("kind", ""),
                tool_name=oracle.get("tool_name"),
                argument_name=oracle.get("argument_name") or oracle.get("field_path"),
                condition_type=oracle.get("condition_type"),
                expected=oracle.get("expected"),
                semantic_proposition=oracle.get("semantic_proposition"),
                tools=tools_list,
            )
        )
    return artifacts


def load_published_scenarios(run_dir: Path) -> dict[str, dict[str, Any]]:
    scenarios_dir = run_dir / "scenarios"
    scenarios: dict[str, dict[str, Any]] = {}
    if not scenarios_dir.is_dir():
        return scenarios
    for p in sorted(scenarios_dir.glob("SCN-*.yaml")):
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                scenarios[p.stem] = data
        except Exception:
            pass
    return scenarios


def load_exclusions(artifacts_dir: Path) -> dict[str, dict[str, Any]]:
    exclusions: dict[str, dict[str, Any]] = {}
    # Check artifact-manifest.json
    manifest_file = artifacts_dir / "artifact-manifest.json"
    if manifest_file.is_file():
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            for entry in manifest.get("entries", []):
                sid = entry.get("scenario_id")
                if sid and entry.get("overall") != "ready":
                    code = entry.get("execution_case_code") or entry.get("overall")
                    exclusions[sid] = {
                        "code": code,
                        "diagnostics": entry.get("diagnostics", []),
                    }
        except Exception:
            pass

    # Also check per-scenario execution-case-exclusion.json
    for scn_dir in sorted(artifacts_dir.iterdir()):
        if scn_dir.is_dir():
            ex_file = scn_dir / "execution-case-exclusion.json"
            if ex_file.is_file():
                try:
                    ex_data = json.loads(ex_file.read_text(encoding="utf-8"))
                    exclusions[scn_dir.name] = ex_data
                except Exception:
                    pass

    return exclusions


def load_control_action_map(run_dir: Path) -> tuple[dict[str, set[str]], set[str]]:
    """Derive the tool-to-control-action mapping from the run's own evidence.

    Source: ``target-realization.yaml`` — ``rows`` map a baseline control
    action to its candidate/selected operations, and ``operation_records``
    map an observed operation to its baseline and target-derived control
    action IDs. Returns (operation -> control action IDs, all operation
    names). Both are empty when the file is absent or unreadable.
    """
    path = run_dir / "target-realization.yaml"
    ca_map: dict[str, set[str]] = {}
    inventory: set[str] = set()
    if not path.is_file():
        return ca_map, inventory
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return ca_map, inventory
    if not isinstance(data, dict):
        return ca_map, inventory

    def add(operation: Any, control_action: str | None) -> None:
        if not operation:
            return
        name = str(operation)
        inventory.add(name)
        if control_action:
            ca_map.setdefault(name, set()).add(control_action)

    for row in data.get("rows", []) or []:
        if not isinstance(row, dict):
            continue
        ca_id = row.get("control_action_id")
        candidates = list(row.get("candidate_operations") or [])
        selected = row.get("selected_operation")
        if selected:
            candidates.append(selected)
        for cand in candidates:
            if isinstance(cand, dict) and cand.get("operation_id"):
                add(cand["operation_id"], ca_id)

    for record in data.get("operation_records", []) or []:
        if not isinstance(record, dict):
            continue
        operation = record.get("operation") or {}
        if not isinstance(operation, dict):
            continue
        reference = operation.get("reference")
        name = (
            operation.get("name")
            or operation.get("operation_id")
            or (reference.get("operation_id") if isinstance(reference, dict) else None)
        )
        if not name:
            continue
        cas = set(record.get("baseline_control_action_ids") or [])
        derived = record.get("target_derived_control_action_id")
        if derived:
            cas.add(derived)
        for ca in cas:
            add(name, str(ca))

    return ca_map, inventory


def _bounded_pattern(text: str) -> re.Pattern[str]:
    return re.compile(r"\b" + re.escape(text.lower()) + r"\b")


def _argument_evidence(gold: GoldCase, art: CompiledArtifact) -> str:
    """Argument-level evidence; does not affect matching but surfaces near misses."""
    gold_arg = gold.oracle.argument
    if not gold_arg:
        return ""
    if not art.argument_name:
        return f"artifact oracle records no argument (gold checks {gold_arg})"
    art_arg = str(art.argument_name)
    art_arg = art_arg.removeprefix("arguments.").removeprefix("argument.")
    if art_arg == gold_arg:
        return f"argument matches: {gold_arg}"
    return f"argument differs: gold checks {gold_arg}, artifact oracle checks {art_arg}"


def evaluate_match_rules(
    gold: GoldCase, art: CompiledArtifact
) -> tuple[bool, str, str, str, str]:
    """Evaluate Rule 1 (tool/surface), Rule 2 (entity/topic), Rule 3 (direction).

    Also returns argument-level evidence, which never changes the match but
    records whether the artifact's oracle argument agrees with the gold
    case's (a differing argument is the signature of a near miss).

    Returns (is_match, rule1_evidence, rule2_evidence, rule3_evidence,
    argument_evidence).
    """
    user_text = art.all_user_text().lower()
    r4_ev = _argument_evidence(gold, art)

    # --- Rule 1: Tool / Surface ---
    r1_pass = False
    r1_ev = ""
    g_kind = gold.oracle.kind
    g_tool = gold.oracle.tool

    if g_kind in ("tool_argument", "tool_called"):
        if (
            art.oracle_kind in ("tool_argument", "tool_call")
            and art.tool_name == g_tool
        ):
            r1_pass = True
            r1_ev = f"tool matches: {art.tool_name}"
    elif g_kind == "tool_absent":
        if (
            art.oracle_kind in ("action_absence", "tool_absent")
            and art.tool_name == g_tool
        ):
            r1_pass = True
            r1_ev = f"absent tool matches: {art.tool_name}"
    elif g_kind == "tool_order":
        if art.oracle_kind == "event_order" and art.tool_name == g_tool:
            r1_pass = True
            r1_ev = f"ordering tool matches: {art.tool_name}"
    elif g_kind in ("response_claim", "paired_response"):
        if art.oracle_kind in ("output_text", "response_claim") and not art.tool_name:
            r1_pass = True
            r1_ev = f"response-level oracle: {art.oracle_kind}"

    if not r1_pass:
        return False, "", "", "", r4_ev

    # --- Rule 2: Entity / Topic ---
    r2_pass = False
    r2_ev = ""

    # Check record IDs (e.g. ORD-201, PLAN-21, CUST002) with word boundaries
    # so PLAN-12 does not match PLAN-121.
    record_ids = gold.derived_record_ids()
    matched_ids = [
        rid
        for rid in record_ids
        if _bounded_pattern(rid).search(user_text)
        or (art.expected is not None and rid.lower() == str(art.expected).lower())
    ]
    if matched_ids:
        r2_pass = True
        r2_ev = f"matched record ID(s): {', '.join(matched_ids)}"
    else:
        # Check keywords
        keywords = gold.match_hints.keywords
        matched_kw = [kw for kw in keywords if _bounded_pattern(kw).search(user_text)]
        if matched_kw:
            r2_pass = True
            r2_ev = f"matched keyword(s): {', '.join(matched_kw)}"

    # Check numerical balance values for amount violation (e.g. 220.0 or 129.0 or 300.0)
    if not r2_pass and gold.family == "policy_violation_write":
        if art.expected is not None and isinstance(gold.oracle.value, (int, float)):
            try:
                if float(art.expected) == float(gold.oracle.value):
                    r2_pass = True
                    r2_ev = f"matched expected amount: {art.expected}"
            except (ValueError, TypeError):
                pass

    if not r2_pass:
        return False, "", "", "", r4_ev

    # --- Rule 3: Direction / Failure Mode ---
    r3_pass = False
    r3_ev = ""

    if g_kind in ("tool_argument", "tool_called"):
        if art.oracle_kind in ("tool_argument", "tool_call"):
            r3_pass = True
            r3_ev = f"direction matches unauthorized tool execution ({art.oracle_kind})"
    elif g_kind == "tool_absent":
        if (
            art.oracle_kind in ("action_absence", "tool_absent")
            and art.condition_type == "action_presence"
        ):
            r3_pass = True
            r3_ev = f"direction matches tool absence ({art.condition_type} = {art.expected})"
    elif g_kind == "tool_order":
        if art.oracle_kind == "event_order":
            r3_pass = True
            r3_ev = f"direction matches tool call ordering ({art.oracle_kind})"
    elif g_kind in ("response_claim", "paired_response"):
        if art.oracle_kind in ("output_text", "response_claim"):
            r3_pass = True
            r3_ev = (
                "direction not machine-checkable for response oracles "
                "(both are response-level); reviewer must confirm the claimed direction"
            )

    if not r3_pass:
        return False, "", "", "", r4_ev

    return True, r1_ev, r2_ev, r3_ev, r4_ev


def find_hints_for_unmatched_gold(
    gold: GoldCase,
    published_scenarios: dict[str, dict[str, Any]],
    exclusions: dict[str, dict[str, Any]],
    compiled_scenario_ids: set[str],
    control_action_map: dict[str, set[str]],
    tool_inventory: set[str],
) -> tuple[str, list[UnmatchedGoldHint]]:
    """Determine the pipeline loss stage and hints for an unmatched gold case.

    Hints are published scenarios related to the gold case by tool, record,
    or run-derived control-action mapping. For response-only gold cases
    (response_claim / paired_response), hints are restricted to scenarios
    that carry no target-tool operation, so a refund scenario that merely
    shares a record ID does not masquerade as a near miss.

    Loss-stage precedence:

    - ``compiled_no_match``: a related scenario compiled, but no compiled
      artifact realized the gold case.
    - ``not_compiled:<code>``: related scenarios exist and none compiled;
      reports the first exclusion code by scenario ID.
    - ``published_uncompiled``: related scenarios exist, none compiled, and
      none carries an exclusion code.
    - ``not_published``: no related published scenario at all.
    """
    hints: list[UnmatchedGoldHint] = []
    gold_records = {r.lower() for r in gold.derived_record_ids()}
    gold_tool = gold.oracle.tool
    gold_is_response_only = gold.oracle.kind in ("response_claim", "paired_response")

    for sid in sorted(published_scenarios):
        scn = published_scenarios[sid]
        spec = scn.get("scenario_spec", {}) or {}
        reqs = spec.get("execution_contract", {}).get("resource_requirements", [])
        ops = [
            r.get("operation")
            for r in reqs
            if isinstance(r, dict) and r.get("operation")
        ]
        tca = spec.get("target_control_action")
        narrative = (scn.get("narrative") or "").lower()

        # A published scenario is tool-level when it requires an operation
        # from the run's observed tool inventory. Without
        # target-realization.yaml, fall back to shape: CA-* identifiers are
        # baseline control actions, anything else is treated as a tool op.
        if tool_inventory:
            scenario_is_tool_level = any(op in tool_inventory for op in ops)
        else:
            scenario_is_tool_level = any(
                not str(op).upper().startswith("CA-") for op in ops
            )
        if gold_is_response_only and scenario_is_tool_level:
            continue

        tool_in_narrative = (
            gold_tool is not None
            and _bounded_pattern(gold_tool).search(narrative) is not None
        )
        tool_matched = (gold_tool is not None and gold_tool in ops) or tool_in_narrative
        record_matched = any(
            _bounded_pattern(rec).search(narrative) for rec in gold_records
        )
        # Control-action equivalence comes from the run's own
        # target-realization mapping, never a hardcoded ID list.
        ca_hint_matched = (
            gold_tool is not None
            and tca is not None
            and tca in control_action_map.get(gold_tool, set())
        )

        if tool_matched or record_matched or ca_hint_matched:
            ex_info = exclusions.get(sid, {})
            code = ex_info.get("code")
            diag_details = []
            for d in ex_info.get("diagnostics", []):
                diag_details.append(d.get("code") or d.get("detail") or str(d))
            note = f"tca={tca}, ops={ops}"
            if diag_details:
                note += f", diag={'; '.join(diag_details)}"

            hints.append(
                UnmatchedGoldHint(
                    scenario_id=sid,
                    control_action=tca,
                    operations=ops,
                    exclusion_code=code,
                    compiled=sid in compiled_scenario_ids,
                    note=note,
                )
            )

    loss_stage = "not_published"
    if hints:
        if any(h.compiled for h in hints):
            loss_stage = "compiled_no_match"
        else:
            codes = [h.exclusion_code for h in hints if h.exclusion_code]
            if codes:
                loss_stage = f"not_compiled:{codes[0]}"
            else:
                loss_stage = "published_uncompiled"

    return loss_stage, hints


def score_run(
    run_dir: str | Path,
    gold_path: str | Path = "data/gold/miniklarna/gold-cases.yaml",
    artifacts_dir_override: str | Path | None = None,
) -> dict[str, Any]:
    run_path = Path(run_dir)
    gold_file = load_gold_file(gold_path)
    gold_digest = compute_gold_digest(gold_path)

    if artifacts_dir_override:
        artifacts_dir = Path(artifacts_dir_override)
    else:
        found = find_synthesis_artifacts_dir(run_path)
        if not found:
            raise FileNotFoundError(
                f"Could not locate synthesis artifacts directory in {run_path}"
            )
        artifacts_dir = found

    # 1. Applicability check
    obs_file = run_path / "target-observations.yaml"
    obs_source = obs_file if obs_file.is_file() else None

    applicability_details: list[dict[str, Any]] = []
    applicable_cases: list[GoldCase] = []
    inapplicable_count = 0

    for case in gold_file.gold_cases:
        app, reasons = check_gold_case_applicability(case, obs_source)
        applicability_details.append(
            {
                "gold_id": case.id,
                "title": case.title,
                "applicable": app,
                "reasons": reasons,
            }
        )
        if app:
            applicable_cases.append(case)
        else:
            inapplicable_count += 1

    # 2. Load run evidence
    compiled_artifacts = load_compiled_artifacts(artifacts_dir)
    published_scenarios = load_published_scenarios(run_path)
    exclusions = load_exclusions(artifacts_dir)
    control_action_map, tool_inventory = load_control_action_map(run_path)
    compiled_scenario_ids = {art.scenario_id for art in compiled_artifacts}

    # 3. Match evaluation
    proposals: list[MatchProposal] = []
    matched_gold_ids: set[str] = set()
    matched_scenario_ids: set[str] = set()

    for case in applicable_cases:
        for art in compiled_artifacts:
            matched, r1, r2, r3, r4 = evaluate_match_rules(case, art)
            if matched:
                proposals.append(
                    MatchProposal(
                        gold_id=case.id,
                        scenario_id=art.scenario_id,
                        rule1_tool=r1,
                        rule2_entity=r2,
                        rule3_direction=r3,
                        argument_evidence=r4,
                    )
                )
                matched_gold_ids.add(case.id)
                matched_scenario_ids.add(art.scenario_id)

    # 4. Unmatched gold cases and hints
    unmatched_gold_cases: list[UnmatchedGoldCase] = []
    for case in applicable_cases:
        if case.id not in matched_gold_ids:
            loss_stage, hints = find_hints_for_unmatched_gold(
                case,
                published_scenarios,
                exclusions,
                compiled_scenario_ids,
                control_action_map,
                tool_inventory,
            )
            unmatched_gold_cases.append(
                UnmatchedGoldCase(
                    gold_id=case.id,
                    title=case.title,
                    family=case.family,
                    loss_stage=loss_stage,
                    hints=hints,
                )
            )

    # Unmatched compiled artifacts
    unmatched_artifacts: list[dict[str, Any]] = []
    for art in compiled_artifacts:
        if art.scenario_id not in matched_scenario_ids:
            unmatched_artifacts.append(
                {
                    "scenario_id": art.scenario_id,
                    "oracle_kind": art.oracle_kind,
                    "tool_name": art.tool_name,
                    "user_text_excerpt": art.all_user_text()[:120].replace("\n", " "),
                }
            )

    run_id = run_path.name
    # try reading run-manifest.yaml if present
    run_manifest_file = run_path / "run-manifest.yaml"
    if run_manifest_file.is_file():
        try:
            rm = yaml.safe_load(run_manifest_file.read_text(encoding="utf-8"))
            if isinstance(rm, dict) and "run_id" in rm:
                run_id = rm["run_id"]
        except Exception:
            pass

    score_result = {
        "run_id": run_id,
        "run_dir": str(run_path),
        "artifacts_dir": str(artifacts_dir),
        "gold_file": str(gold_path),
        "gold_digest": gold_digest,
        "counts": {
            "gold_cases_total": len(gold_file.gold_cases),
            "gold_cases_applicable": len(applicable_cases),
            "gold_cases_inapplicable": inapplicable_count,
            "compiled_artifacts_total": len(compiled_artifacts),
            "proposed_matches": len(proposals),
            "unique_gold_cases_proposed": len(matched_gold_ids),
            "unmatched_gold_cases": len(unmatched_gold_cases),
            "unmatched_compiled_artifacts": len(unmatched_artifacts),
        },
        "applicability": {
            # False when the run carries no target-observations.yaml: cases
            # were not excluded, but their facts were never checked.
            "verified": obs_source is not None,
            "total": len(gold_file.gold_cases),
            "applicable": len(applicable_cases),
            "inapplicable": inapplicable_count,
            "details": applicability_details,
        },
        "proposals": [asdict(p) for p in proposals],
        "unmatched_gold_cases": [asdict(u) for u in unmatched_gold_cases],
        "unmatched_compiled_artifacts": unmatched_artifacts,
    }

    out_file = run_path / "gold-score.yaml"
    atomic_write_text(out_file, yaml.dump(score_result, sort_keys=False))
    return score_result


def print_score_report(score: dict[str, Any]) -> None:
    counts = score["counts"]
    applicability = score["applicability"]
    print("=" * 72)
    print(f"MiniKlarna Gold Score: {score['run_id']}")
    print(f"Gold File: {score['gold_file']} ({score['gold_digest'][:12]}...)")
    print("-" * 72)
    verified = (
        "yes" if applicability.get("verified") else "NO (no target-observations.yaml)"
    )
    print(f"Applicability verified:   {verified}")
    print(
        f"Gold cases applicable:    {counts['gold_cases_applicable']} / {counts['gold_cases_total']}"
    )
    print(f"Compiled artifacts total: {counts['compiled_artifacts_total']}")
    print(
        f"Proposed matches:         {counts['proposed_matches']} (covering {counts['unique_gold_cases_proposed']} unique gold cases)"
    )
    print(f"Unmatched gold cases:     {counts['unmatched_gold_cases']}")
    print(f"Unmatched artifacts:      {counts['unmatched_compiled_artifacts']}")
    print("-" * 72)

    if score["proposals"]:
        print("Proposed Matches:")
        for p in score["proposals"]:
            print(f"  * {p['gold_id']} <--> {p['scenario_id']}")
            print(f"      Rule 1: {p['rule1_tool']}")
            print(f"      Rule 2: {p['rule2_entity']}")
            print(f"      Rule 3: {p['rule3_direction']}")
            print(f"      Argument: {p['argument_evidence'] or 'n/a'}")
    else:
        print("No matches proposed.")

    print("-" * 72)
    if score["unmatched_gold_cases"]:
        print("Unmatched Gold Cases (Loss Stages):")
        for u in score["unmatched_gold_cases"]:
            print(f"  * {u['gold_id']} ({u['family']}) - {u['title']}")
            print(f"      Loss Stage: {u['loss_stage']}")
            for h in u.get("hints", [])[:2]:
                print(
                    f"      Hint: {h['scenario_id']} (tca: {h['control_action']}, "
                    f"code: {h['exclusion_code']}, compiled: {h['compiled']})"
                )

    print("-" * 72)
    if score["unmatched_compiled_artifacts"]:
        print("Unmatched Compiled Artifacts:")
        for a in score["unmatched_compiled_artifacts"]:
            print(
                f"  * {a['scenario_id']} ({a['oracle_kind']}): {a['user_text_excerpt']}"
            )
    print("=" * 72)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, help="Path to run directory")
    parser.add_argument(
        "--gold",
        default="data/gold/miniklarna/gold-cases.yaml",
        help="Path to gold YAML file",
    )
    parser.add_argument(
        "--artifacts",
        default=None,
        help="Optional path to directory containing compiled artifacts",
    )
    args = parser.parse_args()

    try:
        score = score_run(
            run_dir=args.run,
            gold_path=args.gold,
            artifacts_dir_override=args.artifacts,
        )
        print_score_report(score)
        print(f"\nWritten: {Path(args.run) / 'gold-score.yaml'}")
        return 0
    except Exception as e:
        print(f"Error scoring run: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

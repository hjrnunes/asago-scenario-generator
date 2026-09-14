"""Reusable offline cross-repository producer-to-consumer smoke check.

This driver runs the real saved producer execution bundles through the real
consumer public chain — bundle loading, case resolution, default Garak
runtime bindings, readiness planning, artifact compilation, and public
case/trace validation — and proves that semantic evidence survives the whole
chain.  It never calls a model, executes a target, rescores gold, or touches
a sealed run: every check is offline, and a socket guard inside the consumer
phase fails any attempted network contact.

The two repository environments are separate on purpose.  The orchestration
process runs under the producer project and invokes the chain phase once per
bundle under the consumer project with ``uv run --offline``, so the check
stays meaningful when the repositories have different dependency locks.

Usage (from the producer repository or worktree):

    uv run python scripts/qualification/crossrepo_smoke.py \\
        --consumer-root ../asago-artifact-generator \\
        --report build/qualification/crossrepo-smoke/report.json \\
        output/runs/20260914-miniklarna-boundary-correction \\
        output/runs/20260914-miniocciai-baseline-regression \\
        output/runs/20260914-miniairbnb-first-baseline

Each target is a directory holding ``execution-bundle.json`` (and normally
``execution-target-profile.json``).  A target without a bundle is recorded as
a limitation, not a failure.  Committed consumer fixture directories are also
valid targets, which is how the omission and conversation coverage rides the
chain without a saved bundle that carries it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

DRIVER_PATH = Path(__file__).resolve()
PRODUCER_ROOT = DRIVER_PATH.parents[2]
DEFAULT_CONSUMER_ROOT = PRODUCER_ROOT.parent / "asago-artifact-generator"
DEFAULT_REPORT = (
    PRODUCER_ROOT / "build" / "qualification" / "crossrepo-smoke" / "report.json"
)

BUNDLE_FRAME = "stpa-execution-bundle-v2"
PROJECTION_FRAME = "stpa-execution-projection-v3"
CARRIER_FRAME = "stpa-omission-evidence-v1"
OMISSION_JUDGE_LABEL = "Structured omission evidence:"
BUNDLE_FILENAME = "execution-bundle.json"
PROFILE_FILENAME = "execution-target-profile.json"


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Chain phase: runs inside the consumer environment


def _install_socket_guard() -> None:
    """Fail any network contact so the chain provably makes zero requests."""

    def _deny(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("cross-repo smoke must not open a network connection")

    socket.socket.connect = _deny  # type: ignore[method-assign]
    socket.socket.connect_ex = _deny  # type: ignore[method-assign]
    socket.create_connection = _deny  # type: ignore[assignment]


def _consumer_imports(consumer_root: Path) -> Any:
    """Import the consumer's public chain interfaces only."""

    sys.path.insert(0, str(consumer_root / "src"))
    from asago_artifact_generator.bundle.loader import load_execution_bundle
    from asago_artifact_generator.garak.capabilities import garak_capabilities
    from asago_artifact_generator.garak.compile import compile_execution_artifact
    from asago_artifact_generator.garak.conversation import (
        validate_conversation_case,
        validate_conversation_trace,
    )
    from asago_artifact_generator.garak.default_bindings import (
        complete_garak_runtime_bindings,
    )
    from asago_artifact_generator.models._base import (
        canonical_json_bytes,
        compute_framed_digest,
    )
    from asago_artifact_generator.models.execution_classification import (
        ExecutionTargetProfile,
    )
    from asago_artifact_generator.planning.bind import bind_and_plan
    from asago_artifact_generator.planning.resolve_case import resolve_execution_case

    return {
        "load_execution_bundle": load_execution_bundle,
        "garak_capabilities": garak_capabilities,
        "compile_execution_artifact": compile_execution_artifact,
        "validate_conversation_case": validate_conversation_case,
        "validate_conversation_trace": validate_conversation_trace,
        "complete_garak_runtime_bindings": complete_garak_runtime_bindings,
        "ExecutionTargetProfile": ExecutionTargetProfile,
        "bind_and_plan": bind_and_plan,
        "resolve_execution_case": resolve_execution_case,
        "canonical_json_bytes": canonical_json_bytes,
        "compute_framed_digest": compute_framed_digest,
    }


def _resolution_carrier(resolved: Any) -> Any:
    """Return an exclusion's retained carrier as JSON, or None."""

    carrier = resolved.intent.unsafe_outcome.omission_evidence
    return carrier.model_dump(mode="json") if carrier is not None else None


def _entry_outcome(interfaces: Any, intent: Any, profile: Any) -> dict[str, Any]:
    """Drive one intent through the public chain and check its fidelity."""

    outcome: dict[str, Any] = {"scenario_id": intent.scenario_id}
    resolved = interfaces["resolve_execution_case"](intent, profile)
    if type(resolved).__name__ != "BoundExecutionCase":
        outcome["status"] = "excluded"
        outcome["exclusion_code"] = resolved.code
        carrier = intent.unsafe_outcome.omission_evidence
        if carrier is not None:
            outcome["exclusion_retains_carrier"] = _resolution_carrier(
                resolved
            ) == carrier.model_dump(mode="json")
        return outcome

    bindings = interfaces["complete_garak_runtime_bindings"](
        resolved, target_profile=profile
    )
    readiness = interfaces["bind_and_plan"](
        resolved, bindings, interfaces["garak_capabilities"]()
    )
    if readiness.plan is None:
        outcome["status"] = "not_ready"
        outcome["readiness"] = readiness.overall
        outcome["diagnostics"] = [item.code for item in readiness.diagnostics]
        return outcome

    plan = readiness.plan
    compiled = interfaces["compile_execution_artifact"](plan)
    artifact = compiled.artifact
    case_errors = list(
        interfaces["validate_conversation_case"](artifact, plan, compiled.trace)
    )
    trace_errors = list(
        interfaces["validate_conversation_trace"](compiled.trace, plan, artifact)
    )
    oracle = artifact.get("structured_oracle", {})
    outcome.update(
        {
            "status": "compiled",
            "oracle_kind": oracle.get("kind"),
            "delivery_class": artifact.get("profile", {}).get("delivery_class"),
            "case_errors": case_errors,
            "trace_errors": trace_errors,
            "compiled_validation_ok": bool(compiled.validation.get("ok")),
            "fidelity": _fidelity(intent, plan, artifact),
        }
    )
    return outcome


def resolution_carrier(resolved: Any) -> Any:
    """Return the exclusion's retained carrier as JSON, or None."""

    carrier = resolved.intent.unsafe_outcome.omission_evidence
    return carrier.model_dump(mode="json") if carrier is not None else None


def _fidelity(intent: Any, plan: Any, artifact: dict[str, Any]) -> dict[str, Any]:
    """Per-coverage-kind checks that semantics survived compilation."""

    oracle = artifact.get("structured_oracle", {})
    checks: dict[str, Any] = {}
    condition = intent.unsafe_outcome.condition
    stimulus = intent.stimulus_requirements[0]

    if condition.type == "ordering":
        checks["event_order"] = _event_order_fidelity(intent, plan, artifact, oracle)

    carrier = intent.unsafe_outcome.omission_evidence
    if carrier is not None:
        user_contents = [
            message.get("content")
            for message in artifact.get("messages", [])
            if message.get("role") == "user"
        ]
        prepared = intent.stimulus_requirements[0].prepared_user_text
        checks["omission_carrier"] = {
            "intent_to_plan": plan.omission_evidence == carrier,
            "plan_to_artifact": (
                oracle.get("omission_evidence")
                == plan.omission_evidence.model_dump(mode="json")
            ),
            "digest_self_consistent": (
                intent.unsafe_outcome.omission_evidence_digest
                == carrier.compute_carrier_digest()
            ),
            "source_pins_match_trace_refs": (
                carrier.model_dump(mode="json")["source_pins"]
                == dict(intent.trace_refs.source_pins)
            ),
            "judge_labeled": OMISSION_JUDGE_LABEL
            in artifact.get("judge_description", ""),
            "trigger_in_judge": carrier.trigger
            in artifact.get("judge_description", ""),
            "prepared_text_delivered": (
                stimulus.delivery_class != "direct_prompt"
                or (prepared is not None and user_contents == [prepared])
            ),
        }

    turns = list(stimulus.turns or ())
    if turns:
        checks["prepared_history"] = _prepared_history_fidelity(turns, artifact)

    if (
        condition.type == "action_value"
        and condition.property == "semantic_proposition"
    ):
        proposition = intent.unsafe_outcome.semantic_proposition
        checks["output_text"] = {
            "kind": oracle.get("kind") == "output_text",
            "proposition_preserved": oracle.get("semantic_proposition") == proposition,
            "proposition_in_judge": bool(proposition)
            and proposition in artifact.get("judge_description", ""),
        }
    return checks


def _event_order_fidelity(
    intent: Any, plan: Any, artifact: dict[str, Any], oracle: dict[str, Any]
) -> dict[str, Any]:
    """The ordering condition must reach the oracle unchanged, proposition-free."""

    condition = intent.unsafe_outcome.condition
    tool_names = {
        step.tool_name
        for step in plan.steps
        if step.tool_name
        and step.control_action_id == intent.unsafe_outcome.control_action_id
    }
    judge = artifact.get("judge_description", "")
    predicate = (
        f"arguments.{condition.reference_argument.property} "
        f"{condition.reference_argument.operator} "
        f"{condition.reference_argument.expected!r}"
    )
    return {
        "kind": oracle.get("kind") == "event_order",
        "target_tool_bound": tool_names == {oracle.get("tool_name")},
        "reference_tool_preserved": oracle.get("reference_tool")
        == condition.reference_tool,
        "argument_predicate_preserved": (
            oracle.get("field_path")
            == f"arguments.{condition.reference_argument.property}"
            and oracle.get("comparison") == condition.reference_argument.operator
            and oracle.get("expected") == condition.reference_argument.expected
        ),
        "direction_preserved": oracle.get("relation") == condition.relation,
        "semantic_proposition_null": oracle.get("semantic_proposition") is None,
        "judge_names_both_tools": (
            repr(oracle.get("tool_name")) in judge
            and repr(oracle.get("reference_tool")) in judge
        ),
        "judge_states_predicate": predicate in judge,
    }


def _prepared_history_fidelity(turns: Any, artifact: dict[str, Any]) -> dict[str, Any]:
    """Prepared user turns must arrive in order, verbatim, with no reply."""

    messages = artifact.get("messages", [])
    texts = [turn.text for turn in turns]
    user_contents = [
        message.get("content") for message in messages if message.get("role") == "user"
    ]
    last_user = max(
        (
            index
            for index, message in enumerate(messages)
            if message.get("role") == "user"
        ),
        default=-1,
    )
    history = artifact.get("supplied_history") or {}
    return {
        "user_turns_exact_and_ordered": user_contents == texts,
        "no_assistant_reply_between": not any(
            message.get("role") == "assistant" for message in messages[:last_user]
        ),
        "supplied_history_roles": history.get("kind") == "user_only",
        "supplied_history_texts": [
            item.get("text") for item in history.get("user_turns", [])
        ]
        == texts,
        "supplied_history_turn_ids": [
            item.get("turn_id") for item in history.get("user_turns", [])
        ]
        == [turn.turn_id for turn in turns],
    }


def _rehash_negative(
    interfaces: Any,
    bundle_dir: Path,
    destination: Path,
    entry_index: int,
    mutate: Callable[[dict[str, Any]], None],
    *,
    rehash_carrier: bool,
) -> Path:
    """Copy a bundle, mutate one projection, and refresh every relevant hash.

    The rehash uses the consumer's own canonical-JSON and framed-digest
    helpers, so the rewritten bytes are exactly publication-shaped.
    """

    canonical_json_bytes = interfaces["canonical_json_bytes"]
    framed_digest = interfaces["compute_framed_digest"]
    shutil.copytree(bundle_dir, destination)
    index_path = destination / BUNDLE_FILENAME
    index = json.loads(index_path.read_text(encoding="utf-8"))
    entry = index["entries"][entry_index]
    projection_path = destination / entry["projection"]["path"]
    document = json.loads(projection_path.read_text(encoding="utf-8"))
    mutate(document)
    if rehash_carrier:
        outcome = document["unsafe_outcome"]
        outcome["omission_evidence_digest"] = framed_digest(
            CARRIER_FRAME, outcome["omission_evidence"]
        )
    document["semantic_digest"] = framed_digest(
        PROJECTION_FRAME,
        {key: value for key, value in document.items() if key != "semantic_digest"},
    )
    projection_bytes = canonical_json_bytes(document)
    projection_path.write_bytes(projection_bytes)
    entry["projection"]["content_sha256"] = hashlib.sha256(projection_bytes).hexdigest()
    entry["projection"]["semantic_digest"] = document["semantic_digest"]
    index["bundle_digest"] = framed_digest(
        BUNDLE_FRAME,
        {key: value for key, value in index.items() if key != "bundle_digest"},
    )
    index_path.write_bytes(canonical_json_bytes(index))
    return destination


def _strip_proposition(document: dict[str, Any]) -> None:
    document["unsafe_outcome"]["semantic_proposition"] = None


def _invert_omission_direction(document: dict[str, Any]) -> None:
    proposition = document["unsafe_outcome"]["semantic_proposition"]
    document["unsafe_outcome"]["semantic_proposition"] = proposition.replace(
        "is not called", "is called"
    )


def _swap_carrier_source_pin(document: dict[str, Any]) -> None:
    document["unsafe_outcome"]["omission_evidence"]["source_pins"][
        "control_structure"
    ] = "0" * 64


def _typed_rejection(exc: BaseException) -> dict[str, Any]:
    codes = [item.code for item in getattr(exc, "violations", [])]
    return {"error_type": type(exc).__name__, "codes": codes, "message": str(exc)}


def _run_negative(
    interfaces: Any,
    bundle_dir: Path,
    profile: Any,
    entry_index: int,
    name: str,
    mutate: Any,
    *,
    rehash_carrier: bool,
    expect_any: tuple[str, ...],
) -> dict[str, Any]:
    """A fully rehashed negative must fail somewhere in the chain, typed.

    ``expect_any`` names the accepted typed rejections: any of the expected
    violation codes, or a specific rejection message from a later stage.
    """

    result: dict[str, Any] = {"name": name, "expected": list(expect_any)}
    with tempfile.TemporaryDirectory(prefix="crossrepo-smoke-negative-") as temp:
        negative_dir = _rehash_negative(
            interfaces,
            bundle_dir,
            Path(temp) / name,
            entry_index,
            mutate,
            rehash_carrier=rehash_carrier,
        )
        try:
            verified = interfaces["load_execution_bundle"](
                negative_dir / BUNDLE_FILENAME
            )
            for intent in verified.intents:
                resolved = interfaces["resolve_execution_case"](intent, profile)
                bindings = interfaces["complete_garak_runtime_bindings"](
                    resolved, target_profile=profile
                )
                readiness = interfaces["bind_and_plan"](
                    resolved, bindings, interfaces["garak_capabilities"]()
                )
                if readiness.plan is not None:
                    interfaces["compile_execution_artifact"](readiness.plan)
        except Exception as exc:  # noqa: BLE001 - the probe records any typed rejection
            rejection = _typed_rejection(exc)
            haystack = " | ".join([*rejection["codes"], rejection["message"]])
            rejection["rejected"] = any(fragment in haystack for fragment in expect_any)
            result.update(rejection)
        else:
            result.update(
                {"rejected": False, "error_type": None, "codes": [], "message": None}
            )
    return result


def _negative_probes(
    interfaces: Any, bundle_dir: Path, profile: Any
) -> list[dict[str, Any]]:
    """Negative probes for whichever evidence classes this bundle carries.

    Each class probes its first matching entry; a bundle can contribute both
    a proposition probe and carrier probes.
    """

    document = json.loads((bundle_dir / BUNDLE_FILENAME).read_text(encoding="utf-8"))
    probes: list[dict[str, Any]] = []
    proposition_probed = False
    carrier_probed = False
    for index, entry in enumerate(document["entries"]):
        projection = json.loads(
            (bundle_dir / entry["projection"]["path"]).read_text(encoding="utf-8")
        )
        condition = projection["unsafe_outcome"]["condition"]
        if not proposition_probed and (
            condition.get("type") == "action_value"
            and condition.get("property") == "semantic_proposition"
        ):
            proposition_probed = True
            probes.append(
                _run_negative(
                    interfaces,
                    bundle_dir,
                    profile,
                    index,
                    f"missing_semantic_proposition_{entry['scenario_id']}",
                    _strip_proposition,
                    rehash_carrier=False,
                    expect_any=(
                        "condition_value_invalid",
                        "semantic_proposition is required",
                        "requires the producer semantic proposition",
                    ),
                )
            )
        if not carrier_probed and (
            projection["unsafe_outcome"].get("omission_evidence") is not None
        ):
            carrier_probed = True
            probes.append(
                _run_negative(
                    interfaces,
                    bundle_dir,
                    profile,
                    index,
                    f"inverted_omission_direction_{entry['scenario_id']}",
                    _invert_omission_direction,
                    rehash_carrier=False,
                    expect_any=("omission_proposition_mismatch",),
                )
            )
            probes.append(
                _run_negative(
                    interfaces,
                    bundle_dir,
                    profile,
                    index,
                    f"mismatched_carrier_source_pin_{entry['scenario_id']}",
                    _swap_carrier_source_pin,
                    rehash_carrier=True,
                    expect_any=("source_pin_mismatch",),
                )
            )
    return probes


def _chain_phase(bundle_dir: Path, consumer_root: Path, output: Path) -> int:
    """Load, bind, plan, compile, and validate one bundle; zero network."""

    _install_socket_guard()
    interfaces = _consumer_imports(consumer_root)
    profile = None
    profile_path = bundle_dir / PROFILE_FILENAME
    if profile_path.is_file():
        profile = interfaces["ExecutionTargetProfile"].model_validate_json(
            profile_path.read_text(encoding="utf-8")
        )
    verified = interfaces["load_execution_bundle"](bundle_dir / BUNDLE_FILENAME)

    entries = [
        _entry_outcome(interfaces, intent, profile) for intent in verified.intents
    ]
    limitations: list[str] = []
    if not any(entry["status"] == "compiled" for entry in entries):
        limitations.append("no_compiled_entry")
    if not any(entry.get("oracle_kind") == "action_absence" for entry in entries):
        limitations.append("no_structured_omission_entry")
    if not any(
        entry.get("delivery_class") == "conversation_context" for entry in entries
    ):
        limitations.append("no_conversation_context_entry")

    # Negative probes exercise whichever evidence class this bundle carries.
    # The limitation flags above are informational; the proposition probe runs
    # on real bundles, and the carrier probes run where a carrier entry exists.
    probes = (
        _negative_probes(interfaces, bundle_dir, profile)
        if any(entry["status"] == "compiled" for entry in entries)
        else []
    )
    checks = {
        "every_compiled_entry_valid": all(
            entry["status"] != "compiled"
            or (
                not entry["case_errors"]
                and not entry["trace_errors"]
                and entry["compiled_validation_ok"]
                and all(
                    all(bool(check) for check in kind_checks.values())
                    for kind_checks in entry["fidelity"].values()
                )
            )
            for entry in entries
        ),
        "negative_probes_rejected": all(probe.get("rejected") for probe in probes)
        if probes
        else True,
        "socket_guard_installed": True,
    }
    result = {
        "bundle_dir": str(bundle_dir),
        "bundle_schema_version": verified.schema_version,
        "run_id": verified.run_id,
        "profile_supplied": profile is not None,
        "entries": entries,
        "negative_probes": probes,
        "limitations": limitations,
        "zero_provider_requests": True,
        "normal_product_publication": False,
        "gold_recovery_claim": False,
        "executed_safety_claim": False,
        "checks": checks,
    }
    result["checks"]["overall_pass"] = (
        checks["every_compiled_entry_valid"]
        and checks["negative_probes_rejected"]
        and bool(entries)
    )
    _write_json(output, result)
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0 if result["checks"]["overall_pass"] else 1


# ---------------------------------------------------------------------------
# Orchestration: runs inside the producer environment


def _consumer_python(consumer_root: Path, phase_args: list[str]) -> list[str]:
    uv = shutil.which("uv")
    if uv is None:
        return [sys.executable, str(DRIVER_PATH), *phase_args]
    return [
        uv,
        "run",
        "--offline",
        "--project",
        str(consumer_root),
        "python",
        str(DRIVER_PATH),
        *phase_args,
    ]


def _orchestrate(targets: list[Path], consumer_root: Path, report: Path) -> int:
    """Run the chain phase per target and aggregate one report."""

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="crossrepo-smoke-") as temp:
        temp_root = Path(temp)
        for index, target in enumerate(targets):
            record: dict[str, Any] = {"dir": str(target)}
            if not target.is_dir():
                record.update(
                    {
                        "status": "missing_target",
                        "limitation": "the target directory does not exist",
                    }
                )
                results.append(record)
                continue
            if not (target / BUNDLE_FILENAME).is_file():
                record.update(
                    {
                        "status": "skipped_no_execution_bundle",
                        "limitation": (
                            "the saved run published no execution bundle "
                            "(every candidate resolved as a functional test)"
                        ),
                    }
                )
                results.append(record)
                continue
            output_path = temp_root / f"chain-{index}.json"
            command = _consumer_python(
                consumer_root,
                [
                    "--phase",
                    "chain",
                    "--bundle-dir",
                    str(target),
                    "--consumer-root",
                    str(consumer_root),
                    "--output",
                    str(output_path),
                ],
            )
            process = subprocess.run(
                command,
                cwd=str(PRODUCER_ROOT),
                env=os.environ.copy(),
                check=False,
                text=True,
                capture_output=True,
            )
            if output_path.is_file():
                chain_result = json.loads(output_path.read_text())
            else:
                chain_result = {
                    "checks": {"overall_pass": False},
                    "error": "chain phase wrote no result",
                    "returncode": process.returncode,
                    "stderr": process.stderr[-2000:],
                }
            record.update(
                {
                    "status": "passed"
                    if chain_result["checks"].get("overall_pass")
                    else "failed",
                    "result": chain_result,
                    "returncode": process.returncode,
                }
            )
            results.append(record)

    passed = [item["dir"] for item in results if item.get("status") == "passed"]
    skipped = [
        item["dir"]
        for item in results
        if item.get("status") == "skipped_no_execution_bundle"
    ]
    missing = [
        item["dir"] for item in results if item.get("status") == "missing_target"
    ]
    aggregate = {
        "tool": "crossrepo_smoke",
        "consumer_root": str(consumer_root),
        "zero_provider_requests": True,
        "normal_product_publication": False,
        "gold_recovery_claim": False,
        "executed_safety_claim": False,
        "targets": results,
        "summary": {
            "passed": len(passed),
            "failed": len(results) - len(passed) - len(skipped) - len(missing),
            "skipped_no_execution_bundle": len(skipped),
            "missing_target": len(missing),
        },
        "checks": {
            "overall_pass": all(item.get("status") != "failed" for item in results)
            and not missing
            and bool(passed),
        },
    }
    _write_json(report, aggregate)
    print(json.dumps(aggregate["summary"], indent=2))
    print(f"report: {report}")
    return 0 if aggregate["checks"]["overall_pass"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "targets",
        nargs="*",
        type=Path,
        help="bundle directories: saved runs or committed consumer fixtures",
    )
    parser.add_argument("--consumer-root", type=Path, default=DEFAULT_CONSUMER_ROOT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--phase", choices=("chain",), help=argparse.SUPPRESS)
    parser.add_argument("--bundle-dir", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.phase == "chain":
        if args.bundle_dir is None or args.output is None:
            parser.error("--phase chain requires --bundle-dir and --output")
        return _chain_phase(args.bundle_dir, args.consumer_root, args.output)
    if not args.targets:
        parser.error("supply at least one bundle directory target")
    return _orchestrate(
        [target.resolve() for target in args.targets],
        args.consumer_root.resolve(),
        args.report,
    )


if __name__ == "__main__":
    raise SystemExit(main())

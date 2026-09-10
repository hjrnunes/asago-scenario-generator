"""Replay one saved (constraint, action) context through Phase 4 authoring.

This opt-in qualification tool re-issues the Phase 4 grounded authoring call
(``scenario_prod.authoring.author_candidate_scenarios``) for one saved
(constraint, action) candidate against a completed run's pinned context, so
the owner can see what the current templates and model draft for that context
today.  It is a saved-context authoring replay: live mode makes one model call
per sample and records its cost; ``--dry-run`` renders the exact prompts with
zero model calls.

An optional ``--constraint-override`` YAML replaces the pinned constraint,
hazard, and loss texts (for example with the literal texts an older iteration
recorded) while keeping the run's structure, bindings, state, and
observations.

An optional ``--prompt-addendum-file`` splices one paragraph of candidate
prompt wording into the rendered user prompt immediately after the
``conversation`` shape block, keeping the production templates untouched;
the addendum file's digest is recorded beside the prompt hashes, and the
splice fails closed when the anchor is not present exactly once.
``--no-retry`` disables the harness's one retry per sample for experiments
with a fixed model-call budget.

The tool writes only its own output directory: ``calls.jsonl`` produced by the
product seam, plus the rendered prompts (dry-run) or ``replay-record.yaml``
(live).  It records what the model drafts and how it labels the adversary; it
adds no judgment field.  The reviewer judges.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

import asago_scenario_generator.stpa.scenario_prod.authoring as authoring
from asago_scenario_generator.stpa.infra.llm import effective_temperature
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.target_derived_structure import (
    CONSTRAINT_ACTION_RELEVANCE_FILENAME,
    TARGET_DERIVED_STRUCTURE_FILENAME,
    ConstraintActionRelevance,
    TargetDerivedStructure,
)
from asago_scenario_generator.stpa.pipeline.llm_config import resolve_llm_client
from asago_scenario_generator.stpa.scenario_prod.authoring import (
    ScenarioHazardLine,
    author_candidate_scenarios,
    build_authoring_candidates,
)
from asago_scenario_generator.stpa.scenario_prod.content_surface import (
    content_surface_facts,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.system_model.profile import (
    load_capability_profile,
)

RECORD_FILENAME = "replay-record.yaml"
SYSTEM_PROMPT_FILENAME = "system-prompt.txt"
USER_PROMPT_FILENAME = "user-prompt.txt"
PROMPT_HASHES_FILENAME = "prompt-hashes.yaml"
CALL_LOG_FILENAME = "calls.jsonl"


def _sha256_text(text: str) -> str:
    """Return the sha256 hex digest of a prompt text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    """Return the sha256 hex digest of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


# The conversation shape block exactly as ``authoring_user.j2`` renders it
# when the conversation approach is offered.  The addendum splices in after
# this anchor; a missing or repeated anchor fails closed.
_ADDENDUM_ANCHOR = (
    '{"kind": "conversation", "turns": [{"role": "user", "text": '
    '"<earlier-turn text, for example the claim under test>"}, '
    '{"role": "user", "text": "<final-turn request>"}]}\n```'
)


def _splice_addendum(user_prompt: str, addendum: str) -> str:
    """Insert the addendum paragraph after the conversation shape block.

    The production templates stay untouched: the splice is a replay-only
    textual amendment, and it fails closed unless the anchor is present
    exactly once (the conversation offer is per-candidate).
    """
    text = addendum.strip()
    if not text:
        raise ValueError("prompt addendum is empty")
    if user_prompt.count(_ADDENDUM_ANCHOR) != 1:
        raise ValueError(
            "prompt addendum anchor not found exactly once; the candidate "
            "does not offer the conversation approach, or the template moved"
        )
    return user_prompt.replace(_ADDENDUM_ANCHOR, f"{_ADDENDUM_ANCHOR}\n\n{text}")


def _load_yaml(path: Path) -> Any:
    """Load one YAML document."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class ReplayContext:
    """Everything one replay needs, loaded through the product seams."""

    structure: TargetDerivedStructure
    control_structure: ControlStructure
    loss_analysis: LossAnalysis
    relevance: ConstraintActionRelevance
    target_profile: ExecutionTargetProfile
    observations: TargetObservationSnapshot
    capability_profile: Any
    client: Any
    temperature: float | None


class _PromptCapture:
    """Intercept ``safe_llm_call`` to hash prompts; optionally skip the call.

    With ``delegate=None`` (dry-run) the stub records both prompt texts and
    returns a typed error, so no model call is attempted.  With a delegate the
    wrapper only records prompt hashes and forwards unchanged, so the live
    call log keeps its exact product shape.  With ``addendum`` the user
    prompt is spliced once at the conversation shape block before hashing
    and forwarding, so every record reflects the text the model receives.
    """

    def __init__(
        self,
        delegate: Any,
        addendum: str | None = None,
        addendum_file: Path | None = None,
    ) -> None:
        self._delegate = delegate
        self._addendum = addendum
        self.addendum_record = (
            {"file": str(addendum_file), "sha256": _sha256_file(addendum_file)}
            if addendum_file is not None
            else None
        )
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> tuple[Any, Any, str | None]:
        if self._addendum is not None:
            kwargs["user_prompt"] = _splice_addendum(
                kwargs["user_prompt"], self._addendum
            )
        record: dict[str, Any] = {
            "system_prompt_sha256": _sha256_text(kwargs["system_prompt"]),
            "user_prompt_sha256": _sha256_text(kwargs["user_prompt"]),
            "template_hashes": dict(kwargs.get("prompt_template_hashes") or {}),
        }
        if self._delegate is None:
            record["system_prompt"] = kwargs["system_prompt"]
            record["user_prompt"] = kwargs["user_prompt"]
            self.calls.append(record)
            return None, None, "dry-run: no model call made"
        self.calls.append(record)
        return self._delegate(**kwargs)


def _load_context(args: argparse.Namespace) -> ReplayContext:
    """Load every replay input through the loaders the product run uses."""
    run_dir = Path(args.run)
    structure: TargetDerivedStructure = read_yaml(
        run_dir / TARGET_DERIVED_STRUCTURE_FILENAME, TargetDerivedStructure
    )
    control_structure: ControlStructure = read_yaml(
        run_dir / "control-structure.yaml", ControlStructure
    )
    loss_analysis: LossAnalysis = read_yaml(Path(args.loss_analysis), LossAnalysis)
    relevance: ConstraintActionRelevance = read_yaml(
        run_dir / CONSTRAINT_ACTION_RELEVANCE_FILENAME, ConstraintActionRelevance
    )
    target_payload = _load_yaml(Path(args.target_profile))
    if "semantic_digest" not in target_payload:
        raise ValueError("execution target profile must include semantic_digest")
    target_profile = ExecutionTargetProfile.model_validate(target_payload)
    target_profile.assert_integrity()
    observations = TargetObservationSnapshot.from_runtime_context(
        json.loads(Path(args.target_observations).read_text(encoding="utf-8"))
    )
    if observations.target_profile_digest != target_profile.semantic_digest:
        raise ValueError(
            "target observations profile pin does not match target profile"
        )
    capability_profile = load_capability_profile(Path(args.capability_profile))
    client = None
    temperature = None
    if not args.dry_run:
        # Client construction mirrors pipeline/synthesis.py's Stage 5 path.
        client, _profile_name = resolve_llm_client(
            args.profile, None, str(args.profiles)
        )
        temperature = effective_temperature(client, args.temperature)
    return ReplayContext(
        structure=structure,
        control_structure=control_structure,
        loss_analysis=loss_analysis,
        relevance=relevance,
        target_profile=target_profile,
        observations=observations,
        capability_profile=capability_profile,
        client=client,
        temperature=temperature,
    )


def _select_candidate(
    context: ReplayContext, constraint_id: str, action_name: str
) -> Any:
    """Pick the one (constraint, action) candidate the replay targets."""
    candidates = build_authoring_candidates(
        context.relevance,
        context.loss_analysis,
        context.structure,
        context.control_structure,
    )
    matches = [
        candidate
        for candidate in candidates
        if candidate.constraint_id == constraint_id
        and candidate.action_name == action_name
    ]
    if not matches:
        available = ", ".join(
            f"{candidate.constraint_id}:{candidate.action_name}"
            for candidate in candidates
        )
        raise ValueError(
            f"no candidate for ({constraint_id!r}, {action_name!r}); "
            f"available pairs: {available or 'none'}"
        )
    return matches[0]


def _apply_override(candidate: Any, override_path: Path) -> Any:
    """Replace the candidate's pinned texts with the override's texts."""
    payload = _load_yaml(override_path)
    required = {"constraint_id", "description", "rule", "hazards"}
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(
            f"constraint override {override_path} is missing fields: {missing}"
        )
    hazards = tuple(
        ScenarioHazardLine(
            hazard_id=hazard["hazard_id"],
            description=hazard["description"],
            losses=tuple(
                (loss["loss_id"], loss["description"])
                for loss in hazard.get("losses", [])
            ),
        )
        for hazard in payload["hazards"]
    )
    if not hazards:
        raise ValueError(f"constraint override {override_path} carries no hazards")
    return dataclasses.replace(
        candidate,
        constraint_id=str(payload["constraint_id"]),
        rule=str(payload["rule"]),
        applies_when=tuple(payload.get("applies_when") or ()),
        constraint_text=str(payload["description"]),
        hazards=hazards,
    )


def _authoring_rows(log_path: Path, step: str) -> list[dict[str, Any]]:
    """Return the call-log rows this replay's step appended so far."""
    if not log_path.is_file():
        return []
    rows = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("stage") == authoring.AUTHORING_STAGE and row.get("step") == step:
            rows.append(row)
    return rows


def _all_drafts(outcome: Any) -> list[Any]:
    """Return every authored draft: accepted first, then rejected."""
    drafts = [accepted.draft for accepted in outcome.accepted]
    drafts += [draft for draft, _rejection in outcome.rejected]
    return drafts


def _draft_record(draft: Any, accepted: bool, rejection: Any) -> dict[str, Any]:
    """Return the replay-record fields for one authored draft."""
    record = {
        "oracle_kind": draft.unsafe_observation.kind,
        "tool": draft.unsafe_observation.tool,
        "stimulus_text": draft.stimulus.text,
        "adversary_kind": draft.adversary.kind.value,
        "gain": draft.adversary.gain,
        "accepted": accepted,
    }
    if not accepted:
        record["rejection_reason"] = rejection.reason
        record["rejection_detail"] = rejection.detail
    return record


def _sample_record(
    index: int,
    outcome: Any,
    candidate: Any,
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return the replay-record fields for one sample, without judgment."""
    drafts = [
        _draft_record(accepted.draft, True, None) for accepted in outcome.accepted
    ]
    drafts += [
        _draft_record(draft, False, rejection) for draft, rejection in outcome.rejected
    ]
    omission_drafts = [
        draft
        for draft in _all_drafts(outcome)
        if draft.unsafe_observation.kind == "tool_absent"
        and draft.unsafe_observation.tool == candidate.action_name
    ]
    record = {
        "sample": index,
        "prompt_tokens": sum(row.get("prompt_tokens") or 0 for row in rows),
        "completion_tokens": sum(row.get("completion_tokens") or 0 for row in rows),
        "drafts": drafts,
        "omission_shape_drafted": bool(omission_drafts),
        "omission_drafts": [
            {
                "adversary_kind": draft.adversary.kind.value,
                "gain": draft.adversary.gain,
            }
            for draft in omission_drafts
        ],
        "no_scenario_reason": outcome.no_scenario_reason,
    }
    if outcome.error is not None:
        record["error"] = outcome.error
    return record


def _dry_run(
    capture: _PromptCapture,
    context: ReplayContext,
    candidate: Any,
    output_dir: Path,
) -> int:
    """Render the prompts once, write them with their hashes, and exit."""
    outcome = author_candidate_scenarios(
        None,
        candidate,
        profile=context.target_profile,
        observations=context.observations,
        structure=context.structure,
        control_structure=context.control_structure,
        capability_profile=context.capability_profile,
        run_dir=output_dir,
        temperature=0.0,
        has_content_surface=content_surface_facts(
            context.capability_profile
        ).has_content_surface,
    )
    if not capture.calls:
        raise ValueError(f"prompt rendering failed: {outcome.error}")
    rendered = capture.calls[0]
    (output_dir / SYSTEM_PROMPT_FILENAME).write_text(
        rendered["system_prompt"], encoding="utf-8"
    )
    (output_dir / USER_PROMPT_FILENAME).write_text(
        rendered["user_prompt"], encoding="utf-8"
    )
    hashes = {
        "system_prompt_sha256": rendered["system_prompt_sha256"],
        "user_prompt_sha256": rendered["user_prompt_sha256"],
        "template_hashes": rendered["template_hashes"],
        "prompt_addendum": capture.addendum_record,
    }
    (output_dir / PROMPT_HASHES_FILENAME).write_text(
        yaml.dump(hashes, default_flow_style=False, sort_keys=False), encoding="utf-8"
    )
    print(f"system_prompt_sha256: {hashes['system_prompt_sha256']}")
    print(f"user_prompt_sha256: {hashes['user_prompt_sha256']}")
    print(f"prompts: {output_dir}")
    return 0


def _run_live(
    capture: _PromptCapture,
    context: ReplayContext,
    candidate: Any,
    args: argparse.Namespace,
    output_dir: Path,
) -> int:
    """Make one authoring call per sample and write the replay record."""
    log_path = output_dir / CALL_LOG_FILENAME
    step = candidate.step_label
    surface = content_surface_facts(context.capability_profile).has_content_surface
    sample_records: list[dict[str, Any]] = []
    failed = False
    for index in range(1, args.samples + 1):
        # One attempt plus at most one retry per sample, unless the caller
        # holds a fixed call budget (--no-retry).
        attempts_allowed = 1 if args.no_retry else 2
        rows: list[dict[str, Any]] = []
        outcome = None
        while attempts_allowed:
            attempts_allowed -= 1
            before = len(_authoring_rows(log_path, step))
            outcome = author_candidate_scenarios(
                context.client,
                candidate,
                profile=context.target_profile,
                observations=context.observations,
                structure=context.structure,
                control_structure=context.control_structure,
                capability_profile=context.capability_profile,
                run_dir=output_dir,
                temperature=context.temperature,
                has_content_surface=surface,
            )
            rows = _authoring_rows(log_path, step)[before:]
            if outcome.error is None:
                break
        sample_records.append(_sample_record(index, outcome, candidate, rows))
        if outcome.error is not None:
            print(
                f"sample {index} failed after retry: {outcome.error}",
                file=sys.stderr,
            )
            failed = True
            break
    call_rows = _authoring_rows(log_path, step)
    override_used = args.constraint_override is not None
    record = {
        "kind": "saved-context-authoring-replay",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "arm": "arm_c" if override_used else "arm_a",
        "candidate": {
            "constraint_id": candidate.constraint_id,
            "action": candidate.action_name,
            "override_used": override_used,
            "override_file": str(args.constraint_override) if override_used else None,
            "override_digest": (
                _sha256_file(Path(args.constraint_override)) if override_used else None
            ),
        },
        "system_prompt_sha256": capture.calls[0]["system_prompt_sha256"],
        "user_prompt_sha256": capture.calls[0]["user_prompt_sha256"],
        "template_hashes": capture.calls[0]["template_hashes"],
        "prompt_addendum": capture.addendum_record,
        "model": context.client.model,
        "temperature": context.temperature,
        "samples": args.samples,
        "model_calls": len(call_rows),
        "prompt_tokens_total": sum(row.get("prompt_tokens") or 0 for row in call_rows),
        "completion_tokens_total": sum(
            row.get("completion_tokens") or 0 for row in call_rows
        ),
        "sample_records": sample_records,
    }
    record_path = output_dir / RECORD_FILENAME
    record_path.write_text(
        yaml.dump(
            record, default_flow_style=False, sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )
    print(f"model_calls: {record['model_calls']}")
    print(f"prompt_tokens_total: {record['prompt_tokens_total']}")
    print(f"completion_tokens_total: {record['completion_tokens_total']}")
    print(f"record: {record_path}")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    """Run the saved-context authoring replay."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        type=Path,
        required=True,
        help=(
            "Completed Phase 4 run directory supplying the target-derived "
            "structure, control structure, and constraint-action relevance"
        ),
    )
    parser.add_argument(
        "--loss-analysis",
        type=Path,
        required=True,
        help="Pinned loss-analysis.yaml supplying the candidate's lineage",
    )
    parser.add_argument(
        "--target-profile",
        type=Path,
        required=True,
        help="Observed execution-target-profile JSON paired with the run",
    )
    parser.add_argument(
        "--target-observations",
        type=Path,
        required=True,
        help="Normalized target runtime-context JSON paired with --target-profile",
    )
    parser.add_argument(
        "--capability-profile",
        type=Path,
        required=True,
        help="Capability-profile YAML for the run",
    )
    parser.add_argument("--constraint", required=True, help="Pinned constraint ID")
    parser.add_argument("--action", required=True, help="Target action name")
    parser.add_argument(
        "--constraint-override",
        type=Path,
        default=None,
        help="Optional YAML whose constraint, hazard, and loss texts replace "
        "the pinned constraint's texts",
    )
    parser.add_argument(
        "--prompt-addendum-file",
        type=Path,
        default=None,
        help="Optional text file spliced into the rendered user prompt after "
        "the conversation shape block (production templates stay untouched; "
        "the splice fails closed unless the anchor is present exactly once)",
    )
    parser.add_argument(
        "--no-retry",
        action="store_true",
        help="Make exactly one call attempt per sample (fixed call budgets)",
    )
    parser.add_argument(
        "--profiles",
        type=Path,
        default=Path("config/model-profiles.yaml"),
        help="Model profiles YAML file (default: config/model-profiles.yaml)",
    )
    parser.add_argument(
        "--profile",
        default="gemma4-oc",
        help="Named model profile (default: gemma4-oc)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.4,
        help="Sampling temperature (default: 0.4)",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=3,
        help="Number of live authoring calls (default: 3)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for the call log, prompts, and replay record",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Render and save the prompts with zero model calls, then exit",
    )
    args = parser.parse_args(argv)

    context = _load_context(args)
    candidate = _select_candidate(context, args.constraint, args.action)
    if args.constraint_override:
        candidate = _apply_override(candidate, Path(args.constraint_override))
    args.output_dir.mkdir(parents=True, exist_ok=True)

    addendum_file = args.prompt_addendum_file
    addendum = (
        Path(addendum_file).read_text(encoding="utf-8") if addendum_file else None
    )
    original = authoring.safe_llm_call
    capture = _PromptCapture(
        None if args.dry_run else original,
        addendum=addendum,
        addendum_file=Path(addendum_file) if addendum_file else None,
    )
    authoring.safe_llm_call = capture
    try:
        if args.dry_run:
            return _dry_run(capture, context, candidate, args.output_dir)
        return _run_live(capture, context, candidate, args, args.output_dir)
    finally:
        authoring.safe_llm_call = original


if __name__ == "__main__":
    sys.exit(main())

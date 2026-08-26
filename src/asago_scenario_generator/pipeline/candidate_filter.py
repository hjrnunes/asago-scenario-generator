"""LLM candidate-filter protocol and orchestration implementations."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from pydantic import ValidationError

from asago_scenario_generator.llm.client import LLMClient, LLMResult
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.pipeline.candidate_models import (
    BatchFilterDraftV2,
    BatchFilterResponse,
    CandidateTriple,
    FilterDecisionDraftV2,
    FilterMapDecisionDraftV3,
    FilterMapDraftV3,
    FilterProtocolError,
    FilterSeedQuarantine,
    FilterVerdict,
    FilteredSeed,
    RejectionRecord,
    _FilterResult,
    _QuarantineFilterResult,
    _reconciliation_evidence,
    build_filter_map_response_model,
    reconcile_filter_map,
    reconcile_filter_ordinals,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.prompts import render_prompt

logger = logging.getLogger("asago_scenario_generator.pipeline.candidates")

# ---------------------------------------------------------------------------
# LLM batch filter: accept/reject candidates with rationale
# ---------------------------------------------------------------------------

_FILTER_COMPLETION_CAP = 4096


def _filter_completion_cap(client: LLMClient) -> int:
    """Bound filter output without increasing an operator transport cap."""
    transport_cap = getattr(client, "max_completion_tokens", None)
    if isinstance(transport_cap, int) and transport_cap > 0:
        return min(_FILTER_COMPLETION_CAP, transport_cap)
    return _FILTER_COMPLETION_CAP


def _reconcile_filter_response(
    batch_response: BatchFilterResponse,
    expected_seed_id: str,
    submitted_candidate_ids: set[str],
) -> tuple[bool, str | None]:
    """Reconcile an LLM filter response against the exact submitted ID set.

    Checks (order-independent):
    - ``seed_id`` matches the expected seed.
    - Exactly one verdict per submitted candidate ID.
    - No unknown IDs, no duplicate IDs, no omitted IDs.

    Args:
        batch_response: Parsed LLM response.
        expected_seed_id: The seed_id that was submitted.
        submitted_candidate_ids: The exact set of candidate IDs submitted.

    Returns:
        ``(True, None)`` if the response is valid, otherwise
        ``(False, error_message)`` describing the reconciliation failure.
    """
    if batch_response.seed_id != expected_seed_id:
        return False, (
            f"Expected seed_id '{expected_seed_id}' but response has "
            f"'{batch_response.seed_id}'"
        )

    response_ids = [v.candidate_id for v in batch_response.verdicts]
    response_id_set = set(response_ids)

    duplicates = _duplicate_response_ids(response_ids)
    if duplicates:
        return False, f"Duplicate candidate IDs in response: {duplicates}"

    unknown = _unknown_response_ids(response_id_set, submitted_candidate_ids)
    if unknown:
        return False, f"Unknown candidate IDs in response: {unknown}"

    omitted = _omitted_response_ids(response_id_set, submitted_candidate_ids)
    if omitted:
        return False, f"Missing candidate IDs in response: {omitted}"

    return True, None


def _duplicate_response_ids(response_ids: list[str]) -> list[str]:
    """Candidate IDs repeated within a response, sorted."""
    from collections import Counter

    return sorted(cid for cid, count in Counter(response_ids).items() if count > 1)


def _unknown_response_ids(
    response_id_set: set[str], submitted_candidate_ids: set[str]
) -> list[str]:
    """Response IDs that were never submitted, sorted."""
    return sorted(response_id_set - submitted_candidate_ids)


def _omitted_response_ids(
    response_id_set: set[str], submitted_candidate_ids: set[str]
) -> list[str]:
    """Submitted IDs missing from the response, sorted."""
    return sorted(submitted_candidate_ids - response_id_set)


def _build_call_log_entry(
    seed_id: str,
    llm_result: LLMResult,
    attempt: int,
) -> dict:
    """Build a call log dict for one filter LLM call."""
    raw_content = llm_result.content
    if hasattr(raw_content, "model_dump"):
        raw_content = raw_content.model_dump(mode="json")
    elif not isinstance(raw_content, str):
        raw_content = str(raw_content)
    return {
        "call": "candidate_filter",
        "seed_id": seed_id,
        "attempt": attempt,
        "system_prompt": llm_result.system_prompt,
        "user_prompt": llm_result.user_prompt,
        "response": raw_content,
        "prompt_tokens": llm_result.prompt_tokens,
        "completion_tokens": llm_result.completion_tokens,
        "duration_ms": llm_result.duration_ms,
        "request_controls": llm_result.request_controls,
    }


def _duplicate_submitted_ids(
    seed_candidates: list[CandidateTriple], seed_id: str
) -> None:
    """Reject duplicate candidate IDs in the submitted input."""
    raw_ids = [c.candidate_id for c in seed_candidates]
    if len(set(raw_ids)) != len(seed_candidates):
        from collections import Counter

        id_counts = Counter(raw_ids)
        dupes = sorted(cid for cid, count in id_counts.items() if count > 1)
        raise FilterProtocolError(
            f"Duplicate candidate IDs in submitted input for seed {seed_id}: {dupes}",
            call_log_entries=[],
        )


def _submitted_snapshot(
    seed_candidates: list[CandidateTriple],
) -> list[CandidateTriple]:
    """Deep-validated copy of the submitted candidates."""
    return [
        CandidateTriple.model_validate(c.model_dump(mode="python"))
        for c in seed_candidates
    ]


def _prompt_candidates(
    handle_lookup: dict[str, CandidateTriple],
) -> list[dict]:
    """Request-local candidate payloads for the batch filter prompt."""
    return [
        {
            "handle": handle,
            "entry_point": candidate.entry_point,
            "controllability": candidate.controllability,
            "direction": candidate.direction,
            "atlas_technique_ids": candidate.atlas_technique_ids,
            "atlas_technique_names": candidate.atlas_technique_names,
            "atlas_technique_descriptions": (candidate.atlas_technique_descriptions),
        }
        for handle, candidate in handle_lookup.items()
    ]


def _render_filter_user_prompt(
    first: CandidateTriple,
    seed_id: str,
    prompt_candidates: list[dict],
) -> str:
    """Render the seed-level batch filter user prompt."""
    return render_prompt(
        "filter_user.j2",
        seed_id=seed_id,
        attack_pattern_name=first.attack_pattern_name,
        attack_pattern_description=first.attack_pattern_description,
        threat_id=first.threat_id,
        threat_name=first.threat_name,
        owasp_llm_ids=first.owasp_llm_ids,
        risk_card_ref=first.risk_card_ref,
        candidates=prompt_candidates,
    )


def _verdicts_from_decisions(
    decisions: dict[str, FilterMapDecisionDraftV3 | FilterDecisionDraftV2],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """Translate request-local decisions into canonical verdicts."""
    return BatchFilterResponse(
        seed_id=seed_id,
        verdicts=[
            FilterVerdict(
                candidate_id=handle_lookup[handle].candidate_id,
                verdict="accept" if decision.relevant else "reject",
                rationale=decision.rationale,
            )
            for handle, decision in decisions.items()
        ],
    )


def _map_handle_draft_to_batch(
    draft: FilterMapDraftV3,
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """Exact-key V3 draft to canonical batch response."""
    decisions = reconcile_filter_map(draft, tuple(handle_lookup))
    return _verdicts_from_decisions(decisions, handle_lookup, seed_id)


def _ordinal_draft_to_batch(
    draft: BatchFilterDraftV2,
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """Ordinal V2 draft to canonical batch response after reconciliation."""
    decisions = reconcile_filter_ordinals(draft, tuple(handle_lookup))
    return _verdicts_from_decisions(decisions, handle_lookup, seed_id)


def _ordinal_draft_to_batch_or_response(
    raw_content: dict,
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """A raw dict as an ordinal draft, falling back to a typed response."""
    try:
        ordinal = BatchFilterDraftV2.model_validate(raw_content)
    except ValidationError:
        return BatchFilterResponse.model_validate(raw_content)
    return _ordinal_draft_to_batch(ordinal, handle_lookup, seed_id)


def _batch_from_dict(
    raw_content: dict,
    response_model: type[FilterMapDraftV3],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """A raw dict as the V3 map, falling back to V2 ordinal/typed shapes."""
    try:
        mapped = response_model.model_validate(raw_content)
    except ValidationError:
        return _ordinal_draft_to_batch_or_response(raw_content, handle_lookup, seed_id)
    return _map_handle_draft_to_batch(mapped, handle_lookup, seed_id)


def _typed_content_batch(
    raw_content: Any,
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse | None:
    """Typed wire-protocol content translated to a batch response."""
    if isinstance(raw_content, FilterMapDraftV3):
        return _map_handle_draft_to_batch(raw_content, handle_lookup, seed_id)
    if isinstance(raw_content, BatchFilterDraftV2):
        return _ordinal_draft_to_batch(raw_content, handle_lookup, seed_id)
    if isinstance(raw_content, BatchFilterResponse):
        return raw_content
    return None


def _parse_filter_content(
    raw_content: Any,
    response_model: type[FilterMapDraftV3],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> BatchFilterResponse:
    """Translate LLM content to a batch response across wire formats."""
    typed = _typed_content_batch(raw_content, handle_lookup, seed_id)
    if typed is not None:
        return typed
    if isinstance(raw_content, dict):
        return _batch_from_dict(raw_content, response_model, handle_lookup, seed_id)
    if isinstance(raw_content, str):
        return _map_handle_draft_to_batch(
            response_model.model_validate(json.loads(raw_content)),
            handle_lookup,
            seed_id,
        )
    # Wrong content type — try to coerce via model_validate.
    return BatchFilterResponse.model_validate(raw_content)


def _exception_call_log(
    seed_id: str,
    attempt: int,
    system_prompt: str,
    user_prompt: str,
    error: str,
) -> dict:
    """Synthetic call log entry for an infrastructure/parse exception."""
    return {
        "call": "candidate_filter",
        "seed_id": seed_id,
        "attempt": attempt,
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "response": None,
        "error": error,
        "prompt_tokens": None,
        "completion_tokens": None,
        "duration_ms": None,
    }


def _filter_llm_call(
    client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_model: type[FilterMapDraftV3],
    attempt: int,
) -> tuple[LLMResult | None, str | None]:
    """One filter completion call; (result, None) or (None, error)."""
    try:
        llm_result = client.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_model,
            max_completion_tokens=_filter_completion_cap(client),
        )
    except Exception as exc:  # noqa: BLE001 - infrastructure/parse exception, records synthetic call log
        return None, f"Exception during complete(): {exc}"
    return llm_result, None


def _validate_filter_content(
    llm_result: LLMResult,
    response_model: type[FilterMapDraftV3],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
) -> tuple[BatchFilterResponse | None, str | None]:
    """Parse one response into a batch, or (None, error)."""
    try:
        raw_content = llm_result.content
        if raw_content is None:
            raise ValueError("LLM returned None content (refusal or empty)")
        return (
            _parse_filter_content(raw_content, response_model, handle_lookup, seed_id),
            None,
        )
    except (
        ValidationError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        return None, f"Failed to parse LLM content as BatchFilterResponse: {exc}"


def _reconcile_batch(
    batch_response: BatchFilterResponse,
    seed_id: str,
    submitted_ids: set[str],
) -> tuple[bool, str | None]:
    """Reconcile one batch; unexpected exceptions become failures."""
    try:
        return _reconcile_filter_response(batch_response, seed_id, submitted_ids)
    except Exception as exc:  # noqa: BLE001 - reconciliation exception, records error
        return False, f"Reconciliation exception: {exc}"


def _filter_attempt_loop(
    client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_model: type[FilterMapDraftV3],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
    submitted_ids: set[str],
    seed_call_logs: list[dict],
) -> tuple[BatchFilterResponse | None, str | None]:
    """Run up to two filter attempts; returns (batch_response, error)."""
    batch_response: BatchFilterResponse | None = None
    reconciliation_error: str | None = None
    for attempt in (1, 2):
        batch_response, reconciliation_error = _attempt_filter_call(
            client,
            system_prompt,
            user_prompt,
            response_model,
            handle_lookup,
            seed_id,
            submitted_ids,
            attempt,
            seed_call_logs,
        )
        if reconciliation_error is None:
            break
        if attempt == 1:
            logger.warning(
                "Filter call failed for seed %s (attempt 1): %s — retrying",
                seed_id,
                reconciliation_error,
            )
            continue
    return batch_response, reconciliation_error


def _protocol_failure_raise(
    seed_id: str,
    reconciliation_error: str | None,
    batch_response: BatchFilterResponse | None,
    submitted_ids: set[str],
    seed_call_logs: list[dict],
) -> None:
    """Raise when no attempt produced a reconciled batch response."""
    if reconciliation_error is not None or batch_response is None:
        raise FilterProtocolError(
            f"Filter protocol failure for seed {seed_id} after retry: "
            f"{reconciliation_error}",
            call_log_entries=seed_call_logs,
            reconciliation=_reconciliation_evidence(
                seed_id,
                submitted_ids,
                batch_response,
                reconciliation_error,
            ),
        )


def _attempt_filter_call(
    client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_model: type[FilterMapDraftV3],
    handle_lookup: dict[str, CandidateTriple],
    seed_id: str,
    submitted_ids: set[str],
    attempt: int,
    seed_call_logs: list[dict],
) -> tuple[BatchFilterResponse | None, str | None]:
    """One complete filter attempt; appends call logs to ``seed_call_logs``.

    Returns ``(batch_response, None)`` on success or ``(None, error)``.
    """
    llm_result, llm_error = _filter_llm_call(
        client, system_prompt, user_prompt, response_model, attempt
    )
    if llm_error is not None:
        # Infrastructure/parse exception — record a synthetic call log
        # entry since we have no LLMResult.
        seed_call_logs.append(
            _exception_call_log(seed_id, attempt, system_prompt, user_prompt, llm_error)
        )
        return None, llm_error

    seed_call_logs.append(_build_call_log_entry(seed_id, llm_result, attempt))

    # Validate the ordinal wire protocol and translate it to the
    # established canonical verdict model only after exact-set
    # reconciliation. Historical typed responses remain accepted
    # for local test adapters; production requests V3 exclusively.
    batch_response, parse_error = _validate_filter_content(
        llm_result, response_model, handle_lookup, seed_id
    )
    if parse_error is not None:
        return None, parse_error

    ok, err = _reconcile_batch(batch_response, seed_id, submitted_ids)
    if not ok:
        # Keep the parsed batch for quarantine evidence even when the
        # response did not reconcile.
        return batch_response, err
    return batch_response, None


def _split_verdicts(
    batch_response: BatchFilterResponse,
) -> tuple[list[FilterVerdict], list[FilterVerdict]]:
    """Accepted and rejected verdicts of one batch response."""
    accepted_verdicts: list[FilterVerdict] = []
    rejected_verdicts: list[FilterVerdict] = []
    for v in batch_response.verdicts:
        if v.verdict == "accept":
            accepted_verdicts.append(v)
        else:
            rejected_verdicts.append(v)
    return accepted_verdicts, rejected_verdicts


def _rejection_records_for(
    rejected_verdicts: list[FilterVerdict],
    candidate_lookup: dict[str, CandidateTriple],
) -> list[RejectionRecord]:
    """Enriched rejection records resolved from the candidate lookup."""
    rejection_records: list[RejectionRecord] = []
    for v in rejected_verdicts:
        cand = candidate_lookup.get(v.candidate_id)
        if cand is not None:
            rejection_records.append(
                RejectionRecord(
                    candidate_id=v.candidate_id,
                    entry_point=cand.entry_point,
                    atlas_technique_ids=cand.atlas_technique_ids,
                    rationale=v.rationale,
                )
            )
    return rejection_records


def _filtered_seed_from(
    verdict: FilterVerdict,
    cand: CandidateTriple,
    original_seed: ScenarioSeed,
    rejection_records: list[RejectionRecord],
) -> FilteredSeed:
    """One accepted verdict as a filtered seed under the original seed."""
    return FilteredSeed(
        **original_seed.model_dump(),
        pinned_entry_point=cand.entry_point,
        pinned_technique_ids=cand.atlas_technique_ids,
        pinned_technique_names=cand.atlas_technique_names,
        entry_point_id=cand.entry_point_id,
        candidate_id=cand.candidate_id,
        origins=list(cand.origins),
        rejection_rationales=rejection_records,
        accepted_rationale=verdict.rationale,
    )


def _filtered_seed_results(
    accepted_verdicts: list[FilterVerdict],
    candidate_lookup: dict[str, CandidateTriple],
    original_seed: ScenarioSeed,
    rejection_records: list[RejectionRecord],
) -> list[FilteredSeed]:
    """Filtered seeds for all accepted verdicts resolvable in the lookup."""
    seed_results: list[FilteredSeed] = []
    for verdict in accepted_verdicts:
        cand = candidate_lookup.get(verdict.candidate_id)
        if cand is None:
            # Should not happen after reconciliation, but guard anyway.
            logger.error(
                "Candidate %s not in lookup after reconciliation — skipping",
                verdict.candidate_id,
            )
            continue
        seed_results.append(
            _filtered_seed_from(verdict, cand, original_seed, rejection_records)
        )
    return seed_results


def _rule_eligible_filtered_seeds(
    original_seed: ScenarioSeed,
    candidates: list[CandidateTriple],
) -> list[FilteredSeed]:
    """Preserve every rule-eligible candidate after advisory filter failure."""
    return [
        FilteredSeed(
            **original_seed.model_dump(),
            pinned_entry_point=candidate.entry_point,
            pinned_technique_ids=candidate.atlas_technique_ids,
            pinned_technique_names=candidate.atlas_technique_names,
            entry_point_id=candidate.entry_point_id,
            candidate_id=candidate.candidate_id,
            origins=list(candidate.origins),
            rejection_rationales=[],
            accepted_rationale=(
                "Candidate filter unavailable; rule-eligible candidate retained."
            ),
        )
        for candidate in candidates
    ]


def _handle_filter_protocol_failure(
    seed_id: str,
    exc: FilterProtocolError,
    advisory_on_failure: bool,
    groups: dict[str, list[CandidateTriple]],
    seed_lookup: dict[str, ScenarioSeed],
) -> tuple[list[FilteredSeed], int, list[dict], FilterProtocolError | None]:
    """Advisory admission, or deferral, for one failed seed.

    Returns (extra_results, extra_accepted, extra_logs, error_to_record).
    """
    if not advisory_on_failure:
        return [], 0, [], exc
    original_seed = seed_lookup[seed_id]
    results = _rule_eligible_filtered_seeds(original_seed, groups[seed_id])
    extra_logs = list(exc.call_log_entries)
    extra_logs.append(
        {
            "call": "candidate_filter",
            "seed_id": seed_id,
            "warning": "candidate_filter_unavailable",
            "response": None,
        }
    )
    return results, len(groups[seed_id]), extra_logs, None


def _escalate_protocol_errors(
    protocol_errors: list[FilterProtocolError],
    call_log_entries: list[dict],
    quarantine_on_failure: bool,
) -> tuple[list[dict], list[FilterSeedQuarantine]]:
    """Quarantine irreconcilable seeds, or raise when quarantine is off.

    Returns (all_call_logs, quarantined_seeds).
    """
    # Collect all call logs (including from successful seeds) so the
    # runner can persist them before failing the run.
    all_logs = list(call_log_entries)
    for err in protocol_errors:
        all_logs.extend(err.call_log_entries)
    quarantined_seeds: list[FilterSeedQuarantine] = []
    for error in protocol_errors:
        if error.reconciliation is not None and quarantine_on_failure:
            quarantined_seeds.append(
                FilterSeedQuarantine(
                    seed_id=error.reconciliation.seed_id,
                    reconciliation=error.reconciliation,
                )
            )
    if not quarantine_on_failure:
        first_err = protocol_errors[0]
        raise FilterProtocolError(str(first_err), call_log_entries=all_logs)
    return all_logs, quarantined_seeds


def _empty_filter_result(
    quarantine_on_failure: bool,
) -> _FilterResult | _QuarantineFilterResult:
    """The no-candidates result for the current failure mode."""
    if quarantine_on_failure:
        return [], [], [], []
    return [], [], []


def _filter_mode_guard(quarantine_on_failure: bool, advisory_on_failure: bool) -> None:
    """Quarantine and advisory modes are mutually exclusive."""
    if quarantine_on_failure and advisory_on_failure:
        raise ValueError(
            "quarantine_on_failure and advisory_on_failure are mutually exclusive"
        )


def _seed_lookup_from(seeds: list[ScenarioSeed]) -> dict[str, ScenarioSeed]:
    """Seed lookup for constructing FilteredSeed with full fields."""
    return {s.seed_id: s for s in seeds}


def _group_candidates(
    candidates: list[CandidateTriple],
) -> dict[str, list[CandidateTriple]]:
    """Candidates grouped by seed_id."""
    groups: dict[str, list[CandidateTriple]] = defaultdict(list)
    for c in candidates:
        groups[c.seed_id].append(c)
    return groups


def _final_filter_result(
    results: list[FilteredSeed],
    call_log_entries: list[dict],
    all_rejected_verdicts: list[FilterVerdict],
    quarantined_seeds: list[FilterSeedQuarantine],
    quarantine_on_failure: bool,
) -> _FilterResult | _QuarantineFilterResult:
    """The typed result tuple for the current failure mode."""
    if quarantine_on_failure:
        return results, call_log_entries, all_rejected_verdicts, quarantined_seeds
    return results, call_log_entries, all_rejected_verdicts


def _submission_context(
    submitted_snapshot: list[CandidateTriple],
) -> tuple[
    CandidateTriple,
    set[str],
    dict[str, CandidateTriple],
    dict[str, CandidateTriple],
]:
    """Derive (first, submitted_ids, handle_lookup, candidate_lookup)."""
    first = submitted_snapshot[0]
    submitted_ids: set[str] = {c.candidate_id for c in submitted_snapshot}
    handle_lookup = {
        f"c{index}": candidate for index, candidate in enumerate(submitted_snapshot)
    }
    candidate_lookup: dict[str, CandidateTriple] = {
        c.candidate_id: c for c in submitted_snapshot
    }
    return first, submitted_ids, handle_lookup, candidate_lookup


def _post_reconciliation_results(
    batch_response: BatchFilterResponse,
    candidate_lookup: dict[str, CandidateTriple],
    seed_lookup: dict[str, ScenarioSeed],
    seed_id: str,
    seed_candidates: list[CandidateTriple],
    seed_call_logs: list[dict],
) -> tuple[list[FilteredSeed], int, int, list[dict], list[FilterVerdict]]:
    """Resolve accepted/rejected verdicts into filtered seeds and counts."""
    accepted_verdicts, rejected_verdicts = _split_verdicts(batch_response)

    # Build enriched rejection records from candidate lookup.
    rejection_records = _rejection_records_for(rejected_verdicts, candidate_lookup)

    original_seed = seed_lookup.get(seed_id)
    if original_seed is None:
        logger.warning(
            "Seed %s not found in seed lookup — skipping %d accepted verdicts",
            seed_id,
            len(accepted_verdicts),
        )
        return (
            [],
            0,
            len(seed_candidates),
            seed_call_logs,
            rejected_verdicts,
        )

    seed_results = _filtered_seed_results(
        accepted_verdicts, candidate_lookup, original_seed, rejection_records
    )
    seed_accepted = len(accepted_verdicts)
    seed_total = len(seed_candidates)
    logger.info(
        "Seed %s: %d/%d candidates accepted",
        seed_id,
        seed_accepted,
        seed_total,
    )
    return (
        seed_results,
        seed_accepted,
        seed_total - seed_accepted,
        seed_call_logs,
        rejected_verdicts,
    )


def _iter_filter_futures(
    executor: ThreadPoolExecutor,
    groups: dict[str, list[CandidateTriple]],
    seed_lookup: dict[str, ScenarioSeed],
    advisory_on_failure: bool,
    client: LLMClient,
    system_prompt: str,
) -> Any:
    """Yield per-seed outcome deltas as futures complete.

    Each delta is (results, n_accepted, n_rejected, logs, rejected_verdicts,
    error_or_None).  Protocol and infrastructure failures are converted
    through :func:`_handle_filter_protocol_failure`.
    """
    futures = {
        executor.submit(
            _filter_one_seed, sid, cands, client, system_prompt, seed_lookup
        ): sid
        for sid, cands in groups.items()
    }
    for future in as_completed(futures):
        seed_id = futures[future]
        try:
            (
                seed_results,
                n_acc,
                n_rej,
                seed_logs,
                seed_rejected,
            ) = future.result()
            yield seed_results, n_acc, n_rej, seed_logs, seed_rejected, None
        except FilterProtocolError as exc:
            logger.error("Filter protocol failure for seed %s: %s", seed_id, exc)
            admitted, n_acc, extra_logs, error = _handle_filter_protocol_failure(
                seed_id, exc, advisory_on_failure, groups, seed_lookup
            )
            yield admitted, n_acc, 0, extra_logs, [], error
        except Exception as exc:
            # Any unexpected exception from _filter_one_seed is an
            # infrastructure/protocol failure, not an ordinary rejection.
            # Convert to FilterProtocolError so the run fails cleanly
            # with evidence rather than silently dropping a seed.
            logger.exception("Filter infrastructure failure for seed %s", seed_id)
            failure = FilterProtocolError(
                f"Filter infrastructure failure for seed {seed_id}: {exc}",
                call_log_entries=[],
            )
            admitted, n_acc, extra_logs, error = _handle_filter_protocol_failure(
                seed_id, failure, advisory_on_failure, groups, seed_lookup
            )
            yield admitted, n_acc, 0, extra_logs, [], error


def _filter_one_seed(
    seed_id: str,
    seed_candidates: list[CandidateTriple],
    client: LLMClient,
    system_prompt: str,
    seed_lookup: dict[str, ScenarioSeed],
) -> tuple[
    list[FilteredSeed],
    int,
    int,
    list[dict],
    list[FilterVerdict],
]:
    """Filter candidates for a single seed.

    Returns (accepted, n_accepted, n_rejected, call_log_entries,
    rejected_verdicts).
    Raises FilterProtocolError on irreconcilable response.
    """
    _duplicate_submitted_ids(seed_candidates, seed_id)

    # Deep-validated submission snapshot: reconstruct each candidate
    # through model_validate so forged model_copy(update=...) objects
    # are rejected and nested mutable collections are not shared with
    # the originals.  The prompt and candidate lookup are both derived
    # from this snapshot so application-resolved metadata cannot change
    # after submission.
    submitted_snapshot = _submitted_snapshot(seed_candidates)
    first, submitted_ids, handle_lookup, candidate_lookup = _submission_context(
        submitted_snapshot
    )

    prompt_candidates = _prompt_candidates(handle_lookup)
    user_prompt = _render_filter_user_prompt(first, seed_id, prompt_candidates)
    response_model = build_filter_map_response_model(tuple(handle_lookup))

    seed_call_logs: list[dict] = []
    batch_response, reconciliation_error = _filter_attempt_loop(
        client,
        system_prompt,
        user_prompt,
        response_model,
        handle_lookup,
        seed_id,
        submitted_ids,
        seed_call_logs,
    )
    _protocol_failure_raise(
        seed_id,
        reconciliation_error,
        batch_response,
        submitted_ids,
        seed_call_logs,
    )

    # Reconciliation passed — resolve metadata from candidate lookup.
    # Wrap post-reconciliation work so unexpected exceptions carry
    # accumulated seed_call_logs rather than empty evidence.
    try:
        return _post_reconciliation_results(
            batch_response,
            candidate_lookup,
            seed_lookup,
            seed_id,
            seed_candidates,
            seed_call_logs,
        )
    except Exception as exc:
        raise FilterProtocolError(
            f"Unexpected post-reconciliation failure for seed {seed_id}: {exc}",
            call_log_entries=seed_call_logs,
        ) from exc


def filter_candidates(
    candidates: list[CandidateTriple],
    seeds: list[ScenarioSeed],
    client: LLMClient,
    use_case: str,
    profile: CapabilityProfile,
    *,
    quarantine_on_failure: bool = False,
    advisory_on_failure: bool = False,
) -> _FilterResult | _QuarantineFilterResult:
    """Filter candidates via one LLM call per seed (with retry-on-malformed).

    Groups candidates by ``seed_id``, renders a batch prompt for each seed
    labelling candidates with request-local ordinals, and asks the LLM to
    accept or reject every candidate with a rationale. Canonical candidate
    IDs never cross the provider wire protocol.

    Each response is atomically reconciled against the exact submitted ID
    set: expected seed, exactly one verdict per submitted ID, no
    unknown/duplicate/omitted IDs (order-independent).  Malformed batches
    are discarded and retried exactly once.  A second failure raises
    :class:`FilterProtocolError` (failing the run with no partial
    candidate output) while retaining call/protocol evidence.

    The LLM is never authoritative for metadata — entry-point and
    technique metadata are resolved from the candidate lookup by
    ``candidate_id``.

    Args:
        candidates: Output of :func:`expand_candidates`.
        seeds: Original :class:`ScenarioSeed` list (for full field lookup).
        client: Configured :class:`LLMClient` instance.
        use_case: Free-text system description.
        profile: Capability profile of the system under assessment.

    Returns:
        Tuple of (filtered_seeds, call_log_entries, rejected_verdicts,
        quarantined_seeds).
        ``rejected_verdicts`` carries typed :class:`FilterVerdict` records
        for every LLM-rejected candidate, preserving the rationale and
        filter candidate ID for stage-ledger evidence.

    Raises:
        FilterProtocolError: If a seed's response cannot be reconciled
            after one retry and ``quarantine_on_failure`` is false.
    """
    if not candidates:
        logger.info("Filter: no candidates to filter")
        return _empty_filter_result(quarantine_on_failure)
    _filter_mode_guard(quarantine_on_failure, advisory_on_failure)

    # Build seed lookup for constructing FilteredSeed with full fields
    seed_lookup = _seed_lookup_from(seeds)

    # Group candidates by seed_id
    groups = _group_candidates(candidates)

    # Render system prompt once (shared across all seeds)
    system_prompt = render_prompt(
        "filter_system.j2",
        use_case=use_case,
        profile=profile,
    )

    total_accepted = 0
    total_rejected = 0
    results: list[FilteredSeed] = []
    call_log_entries: list[dict] = []
    all_rejected_verdicts: list[FilterVerdict] = []
    protocol_errors: list[FilterProtocolError] = []
    quarantined_seeds: list[FilterSeedQuarantine] = []

    max_workers = min(8, len(groups))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for delta in _iter_filter_futures(
            executor, groups, seed_lookup, advisory_on_failure, client, system_prompt
        ):
            results.extend(delta[0])
            total_accepted += delta[1]
            total_rejected += delta[2]
            call_log_entries.extend(delta[3])
            all_rejected_verdicts.extend(delta[4])
            if delta[5] is not None:
                protocol_errors.append(delta[5])

    if protocol_errors:
        call_log_entries, quarantined_seeds = _escalate_protocol_errors(
            protocol_errors, call_log_entries, quarantine_on_failure
        )

    logger.info(
        "Filter: %d/%d candidates survived (%d rejected)",
        total_accepted,
        total_accepted + total_rejected,
        total_rejected,
    )

    return _final_filter_result(
        results,
        call_log_entries,
        all_rejected_verdicts,
        quarantined_seeds,
        quarantine_on_failure,
    )

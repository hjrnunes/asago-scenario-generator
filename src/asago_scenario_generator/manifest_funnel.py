"""Attempt funnel derivation and lifecycle equation validation."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.manifest_errors import ManifestIntegrityError
from asago_scenario_generator.manifest_models import (
    AttemptDisposition,
    AttemptPhase,
    AttemptRecord,
    RunManifest,
)


def _phase_attempted(attempts: list[AttemptRecord], phase: AttemptPhase) -> int:
    """Count attempts recorded under one phase."""
    return sum(1 for a in attempts if a.phase == phase)


def _disposition_tally(
    attempts: list[AttemptRecord],
    phase: AttemptPhase,
    disposition: AttemptDisposition,
) -> int:
    """Count attempts with one phase/disposition combination."""
    count = 0
    for a in attempts:
        if a.phase == phase and a.disposition == disposition:
            count += 1
    return count


def _attempt_tallies(attempts: list[AttemptRecord]) -> dict[str, int]:
    """Count attempts by phase and disposition for funnel derivation."""
    return {
        "main_attempted": _phase_attempted(attempts, AttemptPhase.MAIN),
        "main_admitted": _disposition_tally(
            attempts, AttemptPhase.MAIN, AttemptDisposition.ADMITTED
        ),
        "main_quarantined": _disposition_tally(
            attempts, AttemptPhase.MAIN, AttemptDisposition.QUARANTINED
        ),
        "main_failed": _disposition_tally(
            attempts, AttemptPhase.MAIN, AttemptDisposition.FAILED
        ),
        "remediation_attempted": _phase_attempted(attempts, AttemptPhase.REMEDIATION),
        "remediation_admitted": _disposition_tally(
            attempts, AttemptPhase.REMEDIATION, AttemptDisposition.ADMITTED
        ),
        "remediation_quarantined": _disposition_tally(
            attempts, AttemptPhase.REMEDIATION, AttemptDisposition.QUARANTINED
        ),
        "remediation_failed": _disposition_tally(
            attempts, AttemptPhase.REMEDIATION, AttemptDisposition.FAILED
        ),
    }


def _resolve_qualified_count(
    selected: int, qualified: int, projection_rejected: int
) -> int:
    """Derive qualified from selected when qualification never ran.

    cmps.4 blocker 5: qualified must be >= selected.  When the caller
    supplies an actual qualified value (> 0), preserve it — do NOT
    default qualified=selected when actual context exists.  Only derive
    from selected when the caller truly has no qualification data
    (qualified == 0 AND projection_rejected == 0, meaning the
    qualification stage was never reached).
    """
    if qualified == 0 and selected > 0 and projection_rejected == 0:
        return selected
    return qualified


def _check_qualified_capacity(selected: int, qualified: int) -> None:
    """Require the funnel qualified count to cover the selected attempts."""
    if selected > qualified:
        raise ManifestIntegrityError(
            f"failed funnel selected={selected} exceeds qualified={qualified}"
        )


def _resolve_persisted_artifacts(
    total_admitted: int, total_quarantined: int, persisted_artifacts: int
) -> int:
    """Derive persisted artifacts from attempts when the caller supplies none."""
    if persisted_artifacts == 0:
        return total_admitted + total_quarantined
    return persisted_artifacts


def derive_funnel_from_attempts(
    attempts: list[AttemptRecord],
    *,
    expanded_instances: int = 0,
    unique_pre_rule_identities: int = 0,
    rule_rejected: int = 0,
    rule_transformed: int = 0,
    post_rule_collapsed: int = 0,
    filter_submitted: int = 0,
    filter_accepted: int = 0,
    selected: int = 0,
    qualified: int = 0,
    projection_rejected: int = 0,
    persisted_artifacts: int = 0,
    seeds_generated: int = 0,
) -> dict[str, Any]:
    """Derive a status-aware funnel lifecycle snapshot from accumulated attempts.

    Used before writing a failed manifest so that terminal equation
    validation can run even when the normal funnel construction was
    never reached.  The caller may pass zero for pre-attempt funnel
    stages that were not reached.

    ``selected`` and ``persisted_artifacts`` are derived from attempts
    when the caller does not supply nonzero values, so the returned dict
    is internally consistent with :class:`CandidateFunnel` equations.

    ``qualified`` and ``projection_rejected`` are preserved through
    failed-run reconstruction (cmps.4 blocker 5).
    """
    tallies = _attempt_tallies(attempts)
    # Failed-run lifecycle counts must be reconstructed from actual reserved
    # attempts, never from the pre-generation plan.  In particular, a fatal
    # error after reserving the first of two planned candidates has selected
    # == main_attempted == 1, not the planned count of two.
    selected = tallies["main_attempted"]
    qualified = _resolve_qualified_count(selected, qualified, projection_rejected)
    _check_qualified_capacity(selected, qualified)
    total_admitted = tallies["main_admitted"] + tallies["remediation_admitted"]
    total_quarantined = tallies["main_quarantined"] + tallies["remediation_quarantined"]
    persisted_artifacts = _resolve_persisted_artifacts(
        total_admitted, total_quarantined, persisted_artifacts
    )

    return {
        "expanded_instances": expanded_instances,
        "unique_pre_rule_identities": unique_pre_rule_identities,
        "rule_rejected": rule_rejected,
        "rule_transformed": rule_transformed,
        "post_rule_collapsed": post_rule_collapsed,
        "filter_submitted": filter_submitted,
        "filter_accepted": filter_accepted,
        "selected": selected,
        "qualified": qualified,
        "projection_rejected": projection_rejected,
        "main_attempted": tallies["main_attempted"],
        "main_admitted": tallies["main_admitted"] + tallies["main_quarantined"],
        "generation_failed": tallies["main_failed"],
        "remediation_attempted": tallies["remediation_attempted"],
        "remediation_admitted": (
            tallies["remediation_admitted"] + tallies["remediation_quarantined"]
        ),
        "remediation_failed": tallies["remediation_failed"],
        "attempted": len(attempts),
        "admitted": total_admitted + total_quarantined,
        "quarantined": total_quarantined,
        "persisted_artifacts": persisted_artifacts,
        "seeds_generated": seeds_generated,
    }


def _duplicate_attempt_keys(attempts: list[AttemptRecord]) -> None:
    """Reject duplicate (candidate_id, scenario_id) attempt keys."""
    attempt_keys: set[tuple[str, str]] = set()
    for a in attempts:
        key = (a.candidate_id, a.scenario_id)
        if key in attempt_keys:
            raise ManifestIntegrityError(
                f"Duplicate attempt key: candidate={a.candidate_id}, "
                f"scenario={a.scenario_id}"
            )
        attempt_keys.add(key)


def _validate_attempt_evidence(attempts: list[AttemptRecord]) -> None:
    """Recheck nonempty evidence for every FAILED/QUARANTINED record.

    _finalize_attempt mutates in-place and may bypass the Pydantic
    model validator; terminal validation must catch blank evidence.
    """
    for a in attempts:
        if a.disposition in (AttemptDisposition.FAILED, AttemptDisposition.QUARANTINED):
            if not a.failure_evidence or not a.failure_evidence.strip():
                raise ManifestIntegrityError(
                    f"AttemptRecord (candidate={a.candidate_id}, "
                    f"scenario={a.scenario_id}) has disposition="
                    f"{a.disposition.value} but blank failure_evidence"
                )


def _validate_zero_attempt_funnel(funnel: dict[str, Any]) -> None:
    """Require zero-attempt lifecycles to carry only zero lifecycle fields.

    A valid run may have nonzero pre-attempt funnel stages
    (expanded_instances, unique_pre_rule_identities, rule_rejected, etc.)
    but select zero candidates and have zero generation attempts.  Only
    lifecycle fields must be zero.
    """
    zero_attempt_lifecycle_keys = (
        "selected",
        "main_attempted",
        "main_admitted",
        "generation_failed",
        "remediation_attempted",
        "remediation_admitted",
        "remediation_failed",
        "attempted",
        "admitted",
        "quarantined",
        "persisted_artifacts",
    )
    if funnel:
        for key in zero_attempt_lifecycle_keys:
            if key in funnel and funnel[key] != 0:
                raise ManifestIntegrityError(
                    f"Funnel {key}={funnel[key]} but zero attempts exist"
                )


def _require_funnel_lifecycle_keys(funnel: dict[str, Any]) -> None:
    """Require the funnel to carry every relevant lifecycle key."""
    required_keys = (
        "attempted",
        "admitted",
        "quarantined",
        "main_attempted",
        "main_admitted",
        "generation_failed",
        "remediation_attempted",
        "remediation_admitted",
        "remediation_failed",
    )
    missing_keys = [k for k in required_keys if k not in funnel]
    if missing_keys:
        raise ManifestIntegrityError(
            f"Funnel missing required lifecycle keys: {missing_keys}"
        )


def _check_funnel_aggregate_equations(
    attempt_count: int,
    funnel: dict[str, Any],
    total_admitted: int,
    total_quarantined: int,
) -> None:
    """Require aggregate attempted/admitted/quarantined funnel equations."""
    if attempt_count != funnel["attempted"]:
        raise ManifestIntegrityError(
            f"Funnel attempted mismatch: len(attempts)="
            f"{attempt_count}, funnel={funnel['attempted']}"
        )
    if total_admitted + total_quarantined != funnel["admitted"]:
        raise ManifestIntegrityError(
            f"Funnel admitted mismatch: attempts(admitted={total_admitted}"
            f"+quarantined={total_quarantined})"
            f"={total_admitted + total_quarantined}, "
            f"funnel={funnel['admitted']}"
        )
    if total_quarantined != funnel["quarantined"]:
        raise ManifestIntegrityError(
            f"Funnel quarantined mismatch: attempts={total_quarantined}, "
            f"funnel={funnel['quarantined']}"
        )


def _check_main_funnel_equations(
    main_attempted: int,
    main_admitted: int,
    main_quarantined: int,
    main_failed: int,
    funnel: dict[str, Any],
) -> None:
    """Require the MAIN-phase funnel equations."""
    if main_attempted != funnel["main_attempted"]:
        raise ManifestIntegrityError(
            f"Funnel main_attempted mismatch: "
            f"len(main_attempts)={main_attempted}, "
            f"funnel={funnel['main_attempted']}"
        )
    if main_admitted + main_quarantined != funnel["main_admitted"]:
        raise ManifestIntegrityError(
            f"Funnel main_admitted mismatch: "
            f"attempts(main_admitted={main_admitted}"
            f"+main_quarantined={main_quarantined})"
            f"={main_admitted + main_quarantined}, "
            f"funnel={funnel['main_admitted']}"
        )
    if main_failed != funnel["generation_failed"]:
        raise ManifestIntegrityError(
            f"Funnel generation_failed mismatch: "
            f"attempts(main_failed={main_failed}), "
            f"funnel={funnel['generation_failed']}"
        )


def _check_remediation_funnel_equations(
    rem_attempted: int,
    rem_admitted: int,
    rem_quarantined: int,
    rem_failed: int,
    funnel: dict[str, Any],
) -> None:
    """Require the REMEDIATION-phase funnel equations."""
    if rem_attempted != funnel["remediation_attempted"]:
        raise ManifestIntegrityError(
            f"Funnel remediation_attempted mismatch: "
            f"len(rem_attempts)={rem_attempted}, "
            f"funnel={funnel['remediation_attempted']}"
        )
    if rem_admitted + rem_quarantined != funnel["remediation_admitted"]:
        raise ManifestIntegrityError(
            f"Funnel remediation_admitted mismatch: "
            f"attempts(rem_admitted={rem_admitted}"
            f"+rem_quarantined={rem_quarantined})"
            f"={rem_admitted + rem_quarantined}, "
            f"funnel={funnel['remediation_admitted']}"
        )
    if rem_failed != funnel["remediation_failed"]:
        raise ManifestIntegrityError(
            f"Funnel remediation_failed mismatch: "
            f"attempts(rem_failed={rem_failed}), "
            f"funnel={funnel['remediation_failed']}"
        )


def _check_total_failed_equation(
    total_failed: int, funnel_gen_failed: int, funnel_rem_failed: int
) -> None:
    """Require total failed to equal both phase failed totals."""
    if total_failed != funnel_gen_failed + funnel_rem_failed:
        raise ManifestIntegrityError(
            f"Funnel total failed mismatch: "
            f"attempts(failed={total_failed}), "
            f"funnel(generation_failed={funnel_gen_failed}"
            f"+remediation_failed={funnel_rem_failed})"
            f"={funnel_gen_failed + funnel_rem_failed}"
        )


def validate_attempt_equations(manifest: RunManifest) -> None:
    """Validate attempt keys, funnel equations, and disposition counts.

    Enforced for **every** final status (completed, completed_with_errors,
    failed), not only when attempts are nonempty.

    When attempts exist, the funnel must carry the relevant lifecycle keys.
    Uses :class:`AttemptPhase` to enforce phase-specific counts:
    ``main_attempted``/``main_admitted``/``generation_failed`` against MAIN
    records and ``remediation_attempted``/``remediation_admitted``/
    ``remediation_failed`` against REMEDIATION records, plus aggregate
    ``attempted``/``admitted``/``quarantined``.

    * Unique attempt keys (candidate_id, scenario_id)
    * ``funnel.attempted == len(attempts)``
    * ``funnel.admitted == admitted-disposition + quarantined-disposition``
      (quarantine is an admitted subset)
    * ``funnel.quarantined == quarantined-disposition``
    * main/remediation failed totals match failed records

    Early failures with zero attempts may omit candidate funnel fields,
    but must still have an internally valid zero-attempt lifecycle.

    Raises:
        ManifestIntegrityError: If any invariant is violated.
    """
    _duplicate_attempt_keys(manifest.attempts)
    _validate_attempt_evidence(manifest.attempts)
    tallies = _attempt_tallies(manifest.attempts)
    total_admitted = tallies["main_admitted"] + tallies["remediation_admitted"]
    total_quarantined = tallies["main_quarantined"] + tallies["remediation_quarantined"]
    total_failed = tallies["main_failed"] + tallies["remediation_failed"]

    funnel = manifest.funnel
    if not manifest.attempts:
        _validate_zero_attempt_funnel(funnel)
        return

    # When attempts exist, funnel must carry the relevant lifecycle keys.
    if not funnel:
        raise ManifestIntegrityError(
            "Manifest has attempts but no funnel lifecycle data"
        )
    _require_funnel_lifecycle_keys(funnel)
    _check_funnel_aggregate_equations(
        len(manifest.attempts), funnel, total_admitted, total_quarantined
    )
    _check_main_funnel_equations(
        tallies["main_attempted"],
        tallies["main_admitted"],
        tallies["main_quarantined"],
        tallies["main_failed"],
        funnel,
    )
    _check_remediation_funnel_equations(
        tallies["remediation_attempted"],
        tallies["remediation_admitted"],
        tallies["remediation_quarantined"],
        tallies["remediation_failed"],
        funnel,
    )
    _check_total_failed_equation(
        total_failed, funnel["generation_failed"], funnel["remediation_failed"]
    )

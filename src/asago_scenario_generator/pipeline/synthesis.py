"""Composition root for the obligation-aware STPA synthesis workflow.

The synthesis workflow deliberately lives at a composition boundary.  Phase 1
planning, structural consideration/revision, STPA slot filling, and ordinary
scenario production are supplied as typed seams (or adapters around those
seams).  This module owns ordering, shared capability identity, persistence,
and the top-level run record; it does not duplicate the domain contracts used
by those stages.

The adapter surface is intentionally small enough for deterministic acceptance
fakes while still allowing the production CLI to wire the existing STPA
providers.  Adapter functions receive only the keyword arguments they declare,
which keeps small test doubles and richer production adapters interchangeable.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Mapping

import yaml

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.obligation_contracts import (
    QualificationFactsInput,
    RiskCardInput,
    TaxonomyObligationInputs,
)
from asago_scenario_generator.pipeline.obligation_persistence import (
    write_taxonomy_obligation_plan,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    capture_capability_snapshot,
)
from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.stpa.infra.provider_record import provider_call_session
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TARGET_OBSERVATIONS_FILENAME,
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.observation_contract import (
    ObservationContract,
    default_observation_contract,
)

logger = logging.getLogger(__name__)

PLAN_FILENAME = "taxonomy-obligation-plan.yaml"
CONSIDERATION_FILENAME = "obligation-consideration.yaml"
ACCOUNTING_FILENAME = "obligation-accounting.yaml"
SCENARIO_REALIZATION_FILENAME = "scenario-realization.yaml"
TARGET_REALIZATION_FILENAME = "target-realization.yaml"
MANIFEST_FILENAME = "synthesis-manifest.yaml"
REPORT_FILENAME = "synthesis-report.html"

_MANIFEST_SCHEMA = "stpa-synthesis-manifest-v1"
_MANIFEST_DOMAIN = "asago-scenario-generator:stpa-synthesis-manifest:v1"
_MANIFEST_VALUE_DOMAIN = "asago-scenario-generator:stpa-synthesis-value:v1"


class SynthesisRunStatus(str, Enum):
    """Stable product outcome derived from exact scenario candidates.

    ``no_candidates`` is a valid analysis result: there was no eligible
    scenario candidate to request.  ``failed`` is reserved for the important
    zero-yield case in which candidates were requested and at least one was
    attempted, but none was published or resolved as a functional test.
    A mixture of published, failed, functional-test, or skipped candidates is
    ``degraded``.
    """

    COMPLETED = "completed"
    DEGRADED = "degraded"
    FAILED = "failed"
    NO_CANDIDATES = "no_candidates"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SynthesisInputs:
    """Typed request for one synthesis run.

    The pure composition root accepts already parsed values.  File paths are
    retained as optional metadata for the CLI adapter and are never opened by
    the planner or consideration seams.  The capability profile, its snapshot
    and the closed Phase 1 input graph come from the ``prepare_capability``
    and ``build_taxonomy_inputs`` adapters, never from this request.
    """

    use_case: str
    risk_cards: tuple[Any, ...] = ()
    qualification_facts: Any = None
    output_dir: Path = Path("output/synthesis")
    execution_target_profile: ExecutionTargetProfile | None = None
    target_observations: TargetObservationSnapshot | None = None
    observation_contract: ObservationContract | None = None

    # CLI/source metadata.  These are not read by pure planning seams.
    risk_extraction_path: Path | None = None
    qualification_facts_path: Path | None = None
    loss_analysis_path: Path | None = None
    profiles_file: Path | str = "config/model-profiles.yaml"

    # Named model controls, resolved by the outer adapter.
    profile: str | None = None
    model_profiles: Mapping[str, Any] | None = None
    max_workers: int = 1
    # Optional shared provider adapter.  The CLI may leave this unset and the
    # production defaults resolve it once per named-stage call; deterministic
    # callers can inject one object to prove routing, revision, recheck, and
    # ICA all use the same adapter and call log.
    obligation_adapter: Any | None = None
    # Directory with a prior run's provider-calls.jsonl.  When set, every model
    # request is served from that record instead of an endpoint.
    replay_calls_dir: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.use_case, str) or not self.use_case.strip():
            raise ValueError("use_case must be a non-empty string")
        if self.max_workers < 1:
            raise ValueError("max_workers must be positive")
        object.__setattr__(self, "output_dir", Path(self.output_dir))
        _normalize_request_values(self)
        _verify_request_target_inputs(self)
        _resolve_request_observation_contract(self)


def _normalize_request_values(inputs: SynthesisInputs) -> None:
    """Coerce risk cards and qualification facts to their typed inputs."""
    if inputs.risk_cards and not isinstance(inputs.risk_cards, tuple):
        object.__setattr__(inputs, "risk_cards", tuple(inputs.risk_cards))
    if inputs.risk_cards:
        object.__setattr__(
            inputs,
            "risk_cards",
            tuple(
                item
                if isinstance(item, RiskCardInput)
                else RiskCardInput.model_validate(_dump(item))
                for item in inputs.risk_cards
            ),
        )
    if inputs.qualification_facts is not None and not isinstance(
        inputs.qualification_facts, QualificationFactsInput
    ):
        object.__setattr__(
            inputs,
            "qualification_facts",
            QualificationFactsInput.model_validate(inputs.qualification_facts),
        )


def _verify_request_target_inputs(inputs: SynthesisInputs) -> None:
    """Require an intact target profile and observations pinned to it."""
    profile = inputs.execution_target_profile
    if profile is not None:
        if not isinstance(profile, ExecutionTargetProfile):
            raise TypeError(
                "execution_target_profile must be an ExecutionTargetProfile"
            )
        profile.assert_integrity()
    observations = inputs.target_observations
    if observations is None:
        return
    if not isinstance(observations, TargetObservationSnapshot):
        raise TypeError("target_observations must be a TargetObservationSnapshot")
    observations.assert_integrity()
    if profile is None:
        raise ValueError("target_observations requires execution_target_profile")
    if observations.target_profile_digest != profile.semantic_digest:
        raise ValueError(
            "target_observations profile pin does not match target profile"
        )


def _resolve_request_observation_contract(inputs: SynthesisInputs) -> None:
    """Default the observation contract, or verify the supplied one."""
    if inputs.observation_contract is None:
        object.__setattr__(
            inputs,
            "observation_contract",
            default_observation_contract(),
        )
    elif not isinstance(inputs.observation_contract, ObservationContract):
        raise TypeError("observation_contract must be an ObservationContract")
    else:
        inputs.observation_contract.verify_digest()


def _is_present(value: Any) -> bool:
    """Return whether an optional value was supplied."""
    return value is not None


def _systemic_inputs(inputs: SynthesisInputs) -> SynthesisInputs:
    """Return the target-blind input view used by every pre-realization stage."""
    target_values = (
        inputs.execution_target_profile,
        inputs.target_observations,
    )
    if not any(map(_is_present, target_values)):
        return inputs
    return replace(
        inputs,
        execution_target_profile=None,
        target_observations=None,
    )


@dataclass(frozen=True)
class SynthesisAdapters:
    """Dependency-injection ports for :func:`run_synthesis`.

    Every field is optional so the production defaults can be selected lazily,
    while acceptance can provide a completely deterministic object.  The
    ``from_object`` constructor reads each port from the callable attribute
    of the same name.
    """

    prepare_capability: Callable[..., Any] | None = None
    build_taxonomy_inputs: Callable[..., Any] | None = None
    plan_obligations: Callable[..., Any] | None = None
    build_briefs: Callable[..., Any] | None = None
    baseline: Callable[..., Any] | None = None
    consider: Callable[..., Any] | None = None
    revise: Callable[..., Any] | None = None
    recheck: Callable[..., Any] | None = None
    fill_icas: Callable[..., Any] | None = None
    target_realize: Callable[..., Any] | None = None
    enrich_actions: Callable[..., Any] | None = None
    scenarios: Callable[..., Any] | None = None
    account: Callable[..., Any] | None = None
    realize: Callable[..., Any] | None = None
    obligation_adapter: Any | None = None
    persist_plan: Callable[..., Any] | None = None
    persist_consideration: Callable[..., Any] | None = None
    persist_accounting: Callable[..., Any] | None = None
    persist_realization: Callable[..., Any] | None = None
    persist_target_realization: Callable[..., Any] | None = None
    report: Callable[..., Any] | None = None
    manifest: Callable[..., Any] | None = None

    @classmethod
    def from_object(cls, adapter: object) -> SynthesisAdapters:
        """Adapt an object whose callable attributes use the port names."""
        if isinstance(adapter, cls):
            return adapter
        values: dict[str, Any] = {}
        for item in fields(cls):
            candidate = getattr(adapter, item.name, None)
            values[item.name] = candidate if callable(candidate) else None
        return cls(**values)


@dataclass
class SynthesisResult:
    """In-memory result of a synthesis run and its sidecar artifacts."""

    inputs: SynthesisInputs
    capability_profile: Any
    capability_snapshot: Any
    taxonomy_inputs: Any
    obligation_plan: Any
    baseline: Any
    consideration: Any
    ica_enumeration: Any
    scenario_result: Any
    accounting: Any
    realization: Any
    manifest: Any
    output_dir: Path
    target_realization: Any | None = None
    report_path: Path | None = None
    artifact_paths: dict[str, Path] = field(default_factory=dict)
    ica_considerations: tuple[Any, ...] = field(default_factory=tuple)
    stage_errors: list[str] = field(default_factory=list)
    stage_warnings: list[str] = field(default_factory=list)
    ica_hazard_verification: Any | None = None

    @property
    def scenario_envelopes(self) -> tuple[Any, ...]:
        """Expose ordinary scenario envelopes without prescribing an SP3 type."""
        value = _first_attr(self.scenario_result, "scenario_envelopes")
        if value is None:
            return ()
        return tuple(value)

    @property
    def run_status(self) -> str:
        """Return the stable terminal product status from the manifest."""
        value = _first_attr(self.manifest, "run_status")
        return str(value or SynthesisRunStatus.UNKNOWN.value)


def run_synthesis(
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters | object | None = None,
) -> SynthesisResult:
    """Run the obligation-aware synthesis workflow in fixed stage order.

    The order is observable and intentional: shared capability preparation,
    Phase 1 planning, ordinary SP1 baseline, consideration, at most one
    structural revision/recheck, final ICA analysis, ordinary SP3 scenarios,
    and provisional accounting.  A revision-triggering initial pass always
    receives exactly one recheck; a clean pass receives no second pass.

    Every provider request and response lands in ``provider-calls.jsonl`` in
    the output directory (see ``stpa.infra.provider_record``).
    """
    if not isinstance(inputs, SynthesisInputs):
        raise TypeError("run_synthesis requires a SynthesisInputs value")
    with provider_call_session(
        record_dir=Path(inputs.output_dir), replay_dir=inputs.replay_calls_dir
    ):
        return _run_synthesis(inputs, adapters)


def _run_synthesis(
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters | object | None,
) -> SynthesisResult:
    """Run the fixed-order workflow inside an active provider-call session."""
    output_dir = Path(inputs.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved = _resolve_adapters(adapters)
    stage_errors: list[str] = []
    stage_warnings: list[str] = []
    calls: list[str] = []

    capability_profile = _prepare_capability_profile(inputs, resolved, calls)
    capability_snapshot = _prepare_snapshot(inputs, capability_profile)
    prepared_profile_path = _persist_prepared_profile(output_dir, capability_profile)
    taxonomy_inputs = _prepare_taxonomy_inputs(
        inputs,
        capability_profile,
        capability_snapshot,
        resolved,
        calls,
    )

    plan = _run_plan(taxonomy_inputs, inputs, resolved, calls)
    plan_path = _persist_plan(output_dir, plan, resolved, calls)
    plan = _reload_persisted_plan(plan, plan_path)

    briefs = _build_briefs(
        plan,
        inputs,
        capability_snapshot,
        taxonomy_inputs,
        resolved,
        calls,
    )

    baseline = _run_baseline(
        inputs,
        capability_profile,
        capability_snapshot,
        taxonomy_inputs,
        plan,
        prepared_profile_path,
        resolved,
        calls,
    )
    baseline_loss = _first_attr(baseline, "loss_analysis")
    baseline_control = _first_attr(baseline, "control_structure")
    if baseline_loss is None or baseline_control is None:
        raise ValueError(_baseline_failure_message(baseline))
    stage_warnings.extend(_baseline_diagnostics(baseline))

    # Provider construction is deliberately after the provider-free Phase 1
    # planner and ordinary SP1 baseline.  The same object then reaches
    # routing, bounded revision/recheck, and ICA filling.
    resolved = _ensure_obligation_provider(
        resolved, _systemic_inputs(inputs), output_dir
    )

    initial_consideration = _run_consideration(
        briefs,
        plan,
        baseline_loss,
        baseline_control,
        inputs,
        capability_snapshot,
        resolved,
        calls,
    )
    initial_routes = tuple(initial_consideration.routes)
    applicable_briefs = tuple(
        brief
        for brief in briefs
        if _brief_obligation_id(brief) in _applicable_ids(plan)
    )
    _ensure_route_universe(initial_routes, _applicable_ids(plan))
    gaps = tuple(route for route in initial_routes if _route_is_gap(route))

    revision_result, recheck_result, final_loss, final_control, final_routes = (
        _run_bounded_revision(
            gaps,
            initial_routes,
            applicable_briefs,
            plan,
            baseline_loss,
            baseline_control,
            inputs,
            capability_snapshot,
            resolved,
            calls,
            stage_errors,
        )
    )

    _ensure_route_universe(final_routes, _applicable_ids(plan))
    consideration = _close_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial=initial_consideration,
        recheck=recheck_result,
        final_routes=final_routes,
        revision=revision_result,
        baseline_loss=baseline_loss,
        baseline_control=baseline_control,
        final_loss=final_loss,
        final_control=final_control,
    )

    # Enrichment grounding (owner decision, M2 unified path): when an
    # observed target profile is supplied, the same operation-matching
    # discipline as target realization runs before ICA enumeration and names
    # each supported logical control action's documented operation.  Known
    # operations enrich the logical control actions; they never replace the
    # control model with tool enumeration, and no input switches the
    # generation algorithm.
    operation_enrichment = _run_operation_enrichment(
        loss_analysis=final_loss,
        control_structure=final_control,
        capability_profile=capability_profile,
        inputs=inputs,
        adapters=resolved,
        calls=calls,
    )
    if operation_enrichment is not None:
        final_control = operation_enrichment.control_structure
        stage_warnings.extend(
            f"control action enrichment: {warning}"
            for warning in operation_enrichment.record.diagnostics
        )

    # One adaptive analysis: enrichment (capability profile, execution target
    # profile, target observations) feeds ICA enumeration and Stage 5; it
    # never selects a different generation algorithm.
    ica_enumeration = _run_ica(
        final_routes,
        briefs,
        plan,
        final_loss,
        final_control,
        capability_profile,
        inputs,
        capability_snapshot,
        resolved,
        calls,
    )
    target_realization = _run_target_realization(
        ica_enumeration=ica_enumeration,
        loss_analysis=final_loss,
        control_structure=final_control,
        capability_profile=capability_profile,
        inputs=inputs,
        adapters=resolved,
        calls=calls,
    )
    effective_control, effective_icas = _target_realized_stpa_inputs(
        target_realization=target_realization,
        loss_analysis=final_loss,
        control_structure=final_control,
        ica_enumeration=ica_enumeration,
        capability_profile=capability_profile,
    )
    scenario_result = _run_scenarios(
        effective_icas,
        briefs,
        final_routes,
        plan,
        final_loss,
        effective_control,
        capability_profile,
        inputs,
        capability_snapshot,
        resolved,
        calls,
        stage_errors,
        target_realization=target_realization,
        operation_enrichment=operation_enrichment,
    )
    accounting = _run_accounting(
        plan,
        consideration,
        final_routes,
        effective_icas,
        scenario_result,
        final_loss,
        effective_control,
        inputs,
        capability_snapshot,
        resolved,
        calls,
        source_pins=_accounting_source_pins(
            plan=plan,
            consideration=consideration,
            final_loss=final_loss,
            final_control=effective_control,
            ica_enumeration=effective_icas,
        ),
    )
    realization = _run_realization(
        accounting=accounting,
        ica_enumeration=ica_enumeration,
        scenario_result=scenario_result,
        adapters=resolved,
        calls=calls,
    )
    consideration_path = _persist_sidecar(
        output_dir,
        CONSIDERATION_FILENAME,
        consideration,
        resolved.persist_consideration,
        "consideration",
    )
    accounting_path = _persist_sidecar(
        output_dir,
        ACCOUNTING_FILENAME,
        accounting,
        resolved.persist_accounting,
        "accounting",
    )
    realization_path = _persist_sidecar(
        output_dir,
        SCENARIO_REALIZATION_FILENAME,
        realization,
        resolved.persist_realization,
        "realization",
    )
    target_realization_path = _persist_target_realization(
        output_dir,
        target_realization,
        resolved.persist_target_realization,
    )
    manifest = _build_manifest(
        inputs=inputs,
        capability_profile=capability_profile,
        capability_snapshot=capability_snapshot,
        taxonomy_inputs=taxonomy_inputs,
        plan=plan,
        baseline=baseline,
        final_loss=final_loss,
        final_control=final_control,
        consideration=consideration,
        accounting=accounting,
        realization=realization,
        target_realization=target_realization,
        operation_enrichment=operation_enrichment,
        ica_enumeration=ica_enumeration,
        scenario_result=scenario_result,
        calls=calls,
        revision=revision_result,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
        provider_stages={
            "consideration_initial": initial_consideration,
            "consideration_recheck": recheck_result,
            "revision": (
                revision_result,
                _first_attr(consideration, "revision"),
            ),
            "ica": ica_enumeration,
        },
    )
    manifest_path = _persist_manifest(output_dir, manifest, resolved.manifest)

    report_path = _render_report(
        output_dir,
        manifest,
        plan,
        consideration,
        accounting,
        realization,
        target_realization,
        scenario_result,
        resolved.report,
    )

    artifact_paths = _artifact_paths(
        output_dir,
        inputs,
        {
            PLAN_FILENAME: plan_path,
            CONSIDERATION_FILENAME: consideration_path,
            ACCOUNTING_FILENAME: accounting_path,
            SCENARIO_REALIZATION_FILENAME: realization_path,
            MANIFEST_FILENAME: manifest_path,
        },
        target_realization_path=target_realization_path,
        operation_enrichment=operation_enrichment,
        report_path=report_path,
    )

    return SynthesisResult(
        inputs=inputs,
        capability_profile=capability_profile,
        capability_snapshot=capability_snapshot,
        taxonomy_inputs=taxonomy_inputs,
        obligation_plan=plan,
        baseline=baseline,
        consideration=consideration,
        ica_enumeration=_first_attr(ica_enumeration, "ica_enumeration")
        or ica_enumeration,
        scenario_result=scenario_result,
        accounting=accounting,
        realization=realization,
        target_realization=target_realization,
        manifest=manifest,
        output_dir=output_dir,
        report_path=report_path,
        artifact_paths=artifact_paths,
        ica_considerations=_ica_considerations(ica_enumeration),
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
        ica_hazard_verification=_first_attr(ica_enumeration, "ica_hazard_verification"),
    )


# ---------------------------------------------------------------------------
# Stage adapters
# ---------------------------------------------------------------------------


def _baseline_diagnostics(baseline: object) -> list[str]:
    """Carry nonfatal baseline findings past later stage-manifest replacement."""
    categories = (
        "stage_warnings",
        "heuristic_errors",
        "heuristic_warnings",
        "solution_neutrality_warnings",
        "post_revision_warnings",
    )
    return [
        f"Baseline {category}: {warning}"
        for category in categories
        for warning in (_first_attr(baseline, category) or ())
    ]


def _baseline_failure_message(baseline: object) -> str:
    errors = _first_attr(baseline, "stage_errors") or ()
    if errors:
        return "baseline STPA failed: " + "; ".join(str(error) for error in errors)
    return "baseline STPA adapter must return loss_analysis and control_structure"


def _resolve_adapters(adapters: SynthesisAdapters | object | None) -> SynthesisAdapters:
    """Fill explicit adapter values with production defaults lazily."""
    explicit = (
        SynthesisAdapters()
        if adapters is None
        else SynthesisAdapters.from_object(adapters)
    )
    defaults = _production_defaults()
    values: dict[str, Any] = {}
    for field_name in SynthesisAdapters.__dataclass_fields__:
        supplied = getattr(explicit, field_name)
        values[field_name] = (
            supplied if supplied is not None else getattr(defaults, field_name)
        )
    return SynthesisAdapters(**values)


def _production_defaults() -> SynthesisAdapters:
    """Return production defaults without constructing a provider client."""
    # Planning is always local.  Provider-capable defaults are imported only
    # when the corresponding stage is reached, keeping Phase 1 provider-free.
    return SynthesisAdapters(
        plan_obligations=_default_plan,
        prepare_capability=_default_prepare_capability,
        build_briefs=_default_briefs,
        baseline=_default_baseline,
        consider=_default_consider,
        revise=_default_revision,
        recheck=_default_recheck,
        fill_icas=_default_fill_icas,
        target_realize=_default_target_realize,
        enrich_actions=_default_enrich_control_actions,
        scenarios=_default_scenarios,
        account=_default_account,
        realize=_default_realize,
    )


def _ensure_obligation_provider(
    adapters: SynthesisAdapters,
    inputs: SynthesisInputs,
    output_dir: Path,
) -> SynthesisAdapters:
    """Lazily bind one SP2 adapter after Phase 1 and SP1 have completed."""
    if adapters.obligation_adapter is not None:
        return adapters
    stages = (
        _default_consider,
        _default_revision,
        _default_recheck,
        _default_fill_icas,
    )
    if not any(
        any(getattr(adapters, name) is stage for stage in stages)
        for name in ("consider", "revise", "recheck", "fill_icas")
    ):
        return adapters
    return replace(
        adapters,
        obligation_adapter=_resolve_obligation_provider(inputs, output_dir),
    )


def _prepare_capability_profile(
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> CapabilityProfile:
    """Resolve the one shared profile through the preparation adapter."""
    if adapters.prepare_capability is None:
        raise ValueError("synthesis requires a capability preparation adapter")
    profile = _invoke(
        adapters.prepare_capability,
        inputs=_systemic_inputs(inputs),
        output_dir=inputs.output_dir,
    )
    calls.append("capability")
    if profile is None:
        raise ValueError("capability preparation adapter returned no profile")
    if not isinstance(profile, CapabilityProfile):
        raise TypeError(
            "capability preparation adapter must return a CapabilityProfile, "
            f"not {type(profile).__name__}"
        )
    return profile


def _prepare_snapshot(
    inputs: SynthesisInputs, profile: CapabilityProfile
) -> CapabilityFactSnapshot:
    """Capture one capability/fact snapshot before planning."""
    return capture_capability_snapshot(
        profile, _evaluated_facts(inputs.qualification_facts)
    )


def _prepare_taxonomy_inputs(
    inputs: SynthesisInputs,
    profile: CapabilityProfile,
    snapshot: CapabilityFactSnapshot,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> TaxonomyObligationInputs:
    """Obtain a complete typed Phase 1 graph through one adapter."""
    if adapters.build_taxonomy_inputs is None:
        raise ValueError("synthesis requires a taxonomy-input preparation adapter")
    value = _invoke(
        adapters.build_taxonomy_inputs,
        inputs=_systemic_inputs(inputs),
        capability_profile=profile,
        capability_snapshot=snapshot,
        risk_cards=inputs.risk_cards,
        qualification_facts=inputs.qualification_facts,
        output_dir=inputs.output_dir,
    )
    calls.append("taxonomy_inputs")
    if value is None:
        raise ValueError("taxonomy input adapter returned no value")
    if not isinstance(value, TaxonomyObligationInputs):
        raise TypeError(
            "taxonomy input adapter must return TaxonomyObligationInputs, "
            f"not {type(value).__name__}"
        )
    _assert_taxonomy_input_identity(value, inputs, profile, snapshot)
    return value


def _assert_taxonomy_input_identity(
    taxonomy_inputs: TaxonomyObligationInputs,
    inputs: SynthesisInputs,
    profile: CapabilityProfile,
    snapshot: CapabilityFactSnapshot,
) -> None:
    """Reject a Phase 1 graph that silently forks shared run identity.

    The typed contract carries a capability/fact snapshot, reviewed risk
    cards, and qualification facts.  All three are checked before the planner
    is entered.
    """
    taxonomy_snapshot = taxonomy_inputs.capability_snapshot
    if taxonomy_snapshot.snapshot_digest != snapshot.snapshot_digest:
        raise ValueError(
            "taxonomy inputs capability snapshot does not match prepared snapshot"
        )
    if taxonomy_snapshot.profile != profile:
        raise ValueError(
            "taxonomy inputs capability profile does not match prepared profile"
        )

    if _risk_ids(taxonomy_inputs.risk_cards) != _risk_ids(inputs.risk_cards):
        raise ValueError(
            "taxonomy inputs reviewed risk IDs do not match synthesis inputs"
        )
    if _risk_digest(taxonomy_inputs.risk_cards) != _risk_digest(inputs.risk_cards):
        raise ValueError(
            "taxonomy inputs reviewed risk content does not match synthesis inputs"
        )

    if _semantic_digest(taxonomy_inputs.qualification_facts) != _semantic_digest(
        inputs.qualification_facts
    ):
        raise ValueError(
            "taxonomy inputs qualification facts do not match synthesis inputs"
        )


def _risk_ids(cards: tuple[RiskCardInput, ...]) -> tuple[str, ...]:
    """Return reviewed risk identities in deterministic order."""
    return tuple(sorted(card.risk_id for card in cards))


def _risk_digest(cards: tuple[RiskCardInput, ...]) -> str:
    """Digest the complete reviewed-risk tuple, not just IDs."""
    return _digest_value(tuple(sorted(cards, key=lambda card: card.risk_id)))


def _run_plan(
    taxonomy_inputs: Any,
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Any:
    """Run Phase 1 before any baseline STPA adapter work."""
    if adapters.plan_obligations is None:
        raise ValueError("synthesis has no Phase 1 planning adapter")
    plan = _invoke(
        adapters.plan_obligations,
        taxonomy_inputs=taxonomy_inputs,
        inputs=_systemic_inputs(inputs),
        output_dir=inputs.output_dir,
    )
    calls.append("plan")
    if plan is None:
        raise ValueError("Phase 1 planner returned no obligation plan")
    if not isinstance(plan, TaxonomyObligationPlan):
        raise TypeError(
            "Phase 1 planner must return a TaxonomyObligationPlan, "
            f"not {type(plan).__name__}"
        )
    plan.assert_integrity()
    return plan


def _build_briefs(
    plan: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    taxonomy_inputs: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> tuple[Any, ...]:
    """Build exact neutral briefs for applicable obligations."""
    if adapters.build_briefs is None:
        raise ValueError("synthesis has no neutral obligation brief adapter")
    result = _invoke(
        adapters.build_briefs,
        plan=plan,
        obligation_plan=plan,
        inputs=_systemic_inputs(inputs),
        capability_snapshot=snapshot,
        taxonomy_inputs=taxonomy_inputs,
    )
    calls.append("briefs")
    if result is None:
        raise ValueError("neutral obligation brief adapter returned no briefs")
    return tuple(result)


def _run_baseline(
    inputs: SynthesisInputs,
    profile: Any,
    snapshot: Any,
    taxonomy_inputs: Any,
    plan: Any,
    prepared_profile_path: Path,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Any:
    """Run ordinary SP1 over the shared profile and reviewed risks."""
    if adapters.baseline is None:
        raise ValueError("synthesis has no baseline STPA adapter")
    baseline_inputs = _systemic_inputs(inputs)
    result = _invoke(
        adapters.baseline,
        inputs=baseline_inputs,
        use_case=inputs.use_case,
        risk_cards=inputs.risk_cards,
        capability_profile=profile,
        capability_snapshot=snapshot,
        capability_profile_path=prepared_profile_path,
        prepared_capability_profile_path=prepared_profile_path,
        taxonomy_inputs=taxonomy_inputs,
        obligation_plan=plan,
        output_dir=inputs.output_dir,
        max_workers=inputs.max_workers,
        # SP1 receives the observed target as evidence for Stage 1a and
        # Stage 2.  Adapters without these parameters simply filter them out.
        execution_target_profile=inputs.execution_target_profile,
        target_observations=inputs.target_observations,
    )
    calls.append("baseline")
    return result


def _run_consideration(
    briefs: tuple[Any, ...],
    plan: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Any:
    """Run the initial complete structural consideration pass."""
    if adapters.consider is None:
        raise ValueError("synthesis has no obligation consideration adapter")
    result = _invoke(
        adapters.consider,
        briefs=briefs,
        neutral_briefs=briefs,
        plan=plan,
        obligation_plan=plan,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        inputs=_systemic_inputs(inputs),
        capability_snapshot=snapshot,
        obligation_adapter=adapters.obligation_adapter,
        output_dir=inputs.output_dir,
        max_workers=inputs.max_workers,
    )
    calls.append("consider")
    return result


def _run_revision(
    gaps: tuple[Any, ...],
    plan: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
    stage_errors: list[str],
) -> Any:
    """Attempt the one bounded additive structural revision."""
    trigger_ids, gap_ids = _revision_trigger_metadata(gaps)
    if adapters.revise is None:
        stage_errors.append("upstream gaps retained: no structural revision adapter")
        return SimpleNamespace(
            status="technical_failure",
            gaps=gaps,
            trigger_obligation_ids=trigger_ids,
            trigger_gap_ids=gap_ids,
        )
    try:
        result = _invoke(
            adapters.revise,
            gaps=gaps,
            upstream_gaps=gaps,
            plan=plan,
            obligation_plan=plan,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            baseline_loss_analysis=loss_analysis,
            baseline_control_structure=control_structure,
            inputs=_systemic_inputs(inputs),
            capability_snapshot=snapshot,
            obligation_adapter=adapters.obligation_adapter,
            output_dir=inputs.output_dir,
        )
    except Exception as exc:  # noqa: BLE001 - retained local revision outcome
        stage_errors.append(f"structural revision failed: {exc}")
        result = SimpleNamespace(
            status="technical_failure",
            gaps=gaps,
            trigger_obligation_ids=trigger_ids,
            trigger_gap_ids=gap_ids,
        )
    calls.append("revision")
    return result or SimpleNamespace(
        status="rejected",
        gaps=gaps,
        trigger_obligation_ids=trigger_ids,
        trigger_gap_ids=gap_ids,
    )


def _revision_trigger_metadata(
    gaps: tuple[Any, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Retain exact trigger identities when a revision adapter fails locally."""
    obligation_ids = tuple(
        sorted(
            {
                str(identifier)
                for value in gaps
                if (identifier := _route_obligation_id(value)) is not None
            }
        )
    )
    gap_ids: set[str] = set()
    for value in gaps:
        concepts = (
            (value,)
            if hasattr(value, "gap_id")
            else _first_attr(value, "missing_concepts")
        )
        for concept in concepts or ():
            gap_id = _first_attr(concept, "gap_id")
            if gap_id is not None:
                gap_ids.add(str(gap_id))
    return obligation_ids, tuple(sorted(gap_ids))


def _run_ica(
    routes: tuple[Any, ...],
    briefs: tuple[Any, ...],
    plan: Any,
    loss_analysis: Any,
    control_structure: Any,
    profile: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Any:
    """Run obligation-aware final ICA analysis over every final slot."""
    if adapters.fill_icas is None:
        raise ValueError("synthesis has no obligation-aware ICA adapter")
    result = _invoke(
        adapters.fill_icas,
        routes=routes,
        final_routes=routes,
        briefs=briefs,
        plan=plan,
        obligation_plan=plan,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        capability_profile=profile,
        capability_snapshot=snapshot,
        inputs=_systemic_inputs(inputs),
        obligation_adapter=adapters.obligation_adapter,
        output_dir=inputs.output_dir,
        max_workers=inputs.max_workers,
    )
    calls.append("ica")
    if result is None:
        raise ValueError("obligation-aware ICA adapter returned no enumeration")
    return _run_ica_verification(
        result,
        adapters=adapters,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        inputs=_systemic_inputs(inputs),
    )


def _run_ica_verification(
    result: Any,
    *,
    adapters: SynthesisAdapters,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
) -> Any:
    """Run the independent ICA verifier before ordinary Stage 5."""
    from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
        filter_ica_considerations,
        verify_final_ica_batch,
    )

    ordinary = _first_attr(result, "ica_enumeration") or result
    verifier = adapters.obligation_adapter
    if verifier is None or not callable(getattr(verifier, "verify_ica_hazards", None)):
        # Deterministic fakes that do not expose the provider boundary keep
        # their ordinary STPA behavior.
        return result
    filtered, batch = verify_final_ica_batch(
        verifier,
        ordinary,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        batch_id="synthesis-ica-hazard-verification",
    )

    pairs = _ica_considerations(result)
    if pairs:
        pairs = filter_ica_considerations(
            pairs,
            batch,
            enumeration=_first_attr(filtered, "ica_enumeration") or filtered,
        )
    return _attach_ica_verification(result, filtered, batch, pairs)


def _attach_ica_verification(
    result: Any,
    enumeration: Any,
    batch: Any,
    considerations: tuple[Any, ...],
) -> Any:
    """Attach verifier evidence while preserving each existing result wrapper."""
    from asago_scenario_generator.stpa.obligation_aware.contracts import (
        SynthesisSlotFillResult,
    )
    from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
        SlotFillRunResult,
    )

    if isinstance(result, SlotFillRunResult):
        updated = result.result.model_copy(
            update={
                "ica_enumeration": enumeration,
                "considerations": considerations,
                "ica_hazard_verification": batch,
            }
        )
        return SlotFillRunResult(result=updated)
    if isinstance(result, SynthesisSlotFillResult):
        return result.model_copy(
            update={
                "ica_enumeration": enumeration,
                "considerations": considerations,
                "ica_hazard_verification": batch,
            }
        )
    return SimpleNamespace(
        ica_enumeration=enumeration,
        considerations=considerations,
        ica_hazard_verification=batch,
        result=result,
    )


def _run_target_realization(
    *,
    ica_enumeration: Any,
    loss_analysis: Any,
    control_structure: Any,
    capability_profile: Any,
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Any | None:
    """Run the additive target lens only for an observed target profile."""
    from asago_scenario_generator.models.target_realization import (
        TargetRealizationResult,
    )
    from asago_scenario_generator.stpa.models.execution_classification import (
        ProfileBasis,
    )

    profile = inputs.execution_target_profile
    if profile is None or profile.basis is ProfileBasis.simulation:
        return None
    if adapters.target_realize is None:
        raise ValueError("synthesis has no target-realization adapter")
    ordinary_icas = _first_attr(ica_enumeration, "ica_enumeration") or ica_enumeration
    result = _invoke(
        adapters.target_realize,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ordinary_icas,
        capability_profile=capability_profile,
        execution_target_profile=profile,
        inputs=inputs,
        output_dir=inputs.output_dir,
    )
    calls.append("target_realization")
    if not isinstance(result, TargetRealizationResult):
        raise TypeError(
            "target-realization adapter must return TargetRealizationResult"
        )
    result.assert_integrity()
    if result.profile_digest != profile.semantic_digest:
        raise ValueError("target realization does not match execution target profile")
    return result


def _target_realized_stpa_inputs(
    *,
    target_realization: Any | None,
    loss_analysis: Any,
    control_structure: Any,
    ica_enumeration: Any,
    capability_profile: Any,
) -> tuple[Any, Any]:
    """Return the separately attested baseline-plus-target STPA union."""
    if target_realization is None or target_realization.effective_view is None:
        return control_structure, ica_enumeration

    from asago_scenario_generator.models.target_realization import (
        SystemicStpaBaseline,
    )
    from asago_scenario_generator.pipeline.target_realization import (
        project_target_realization_to_stpa,
    )

    ordinary_icas = _first_attr(ica_enumeration, "ica_enumeration") or ica_enumeration
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ordinary_icas,
        baseline_id=target_realization.baseline_id,
        declared_capabilities=_declared_capability_labels(capability_profile),
    )
    projection = project_target_realization_to_stpa(
        baseline,
        loss_analysis,
        control_structure,
        ordinary_icas,
        target_realization,
    )
    return projection.control_structure, projection.ica_enumeration


def _run_scenarios(
    ica_enumeration: Any,
    briefs: tuple[Any, ...],
    routes: tuple[Any, ...],
    plan: Any,
    loss_analysis: Any,
    control_structure: Any,
    profile: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
    stage_errors: list[str],
    *,
    target_realization: Any | None = None,
    operation_enrichment: Any | None = None,
) -> Any:
    """Run ordinary STPA SP3 from final ICAs and structure."""
    if adapters.scenarios is None:
        raise ValueError("synthesis has no ordinary scenario adapter")
    try:
        result = _invoke(
            adapters.scenarios,
            ica_enumeration=ica_enumeration,
            final_ica_enumeration=ica_enumeration,
            briefs=briefs,
            routes=routes,
            ica_considerations=_ica_considerations(ica_enumeration),
            plan=plan,
            obligation_plan=plan,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            capability_profile=profile,
            capability_snapshot=snapshot,
            execution_target_profile=inputs.execution_target_profile,
            target_realization=target_realization,
            target_observations=inputs.target_observations,
            enriched_operations=_verified_enriched_operations(
                operation_enrichment,
                target_realization,
            ),
            inputs=inputs,
            output_dir=inputs.output_dir,
            max_workers=inputs.max_workers,
        )
    except Exception as exc:  # noqa: BLE001 - scenario failure is non-fatal
        stage_errors.append(f"scenario generation failed: {exc}")
        result = SimpleNamespace(scenario_envelopes=(), stage_errors=(str(exc),))
    calls.append("scenarios")
    return result


def _accounting_source_pins(
    *,
    plan: Any,
    consideration: Any,
    final_loss: Any,
    final_control: Any,
    ica_enumeration: Any,
) -> tuple[Any, ...]:
    """Bind accounting to the exact final Phase 1/STPA authorities."""
    from asago_scenario_generator.models.canonical import compute_framed_digest

    values = (
        (
            "taxonomy-obligation-plan",
            "taxonomy-obligation-plan-v1",
            plan,
            _semantic_digest(plan),
        ),
        (
            "stpa-loss-analysis",
            "stpa-loss-analysis-v1",
            final_loss,
            None,
        ),
        (
            "stpa-control-structure",
            "stpa-control-structure-v1",
            final_control,
            None,
        ),
        (
            "ica-enumeration",
            "ica-enumeration-v1",
            _first_attr(ica_enumeration, "ica_enumeration") or ica_enumeration,
            None,
        ),
    )
    supplied = tuple(_first_attr(consideration, "source_pins") or ())
    by_id = {pin.artifact_id: pin for pin in supplied}
    result = [
        _accounting_source_pin(
            artifact_id,
            schema,
            declared
            or compute_framed_digest(
                f"asago-scenario-generator:{artifact_id}:v1",
                _dump(value),
            ),
            by_id.get(artifact_id),
        )
        for artifact_id, schema, value, declared in values
    ]
    unknown = set(by_id) - {item[0] for item in values}
    if unknown:
        raise ValueError(
            "consideration source_pins contain unknown accounting authorities"
        )
    return tuple(result)


def _accounting_source_pin(
    artifact_id: str,
    schema: str,
    expected: str,
    current: Any,
) -> Any:
    """Reuse a supplied pin that matches the final authority, else build one."""
    from asago_scenario_generator.models.artifact_pin import ArtifactPin

    if current is None:
        return ArtifactPin(
            artifact_id=artifact_id,
            schema_version=schema,
            semantic_digest=expected,
        )
    if current.schema_version != schema or current.semantic_digest != expected:
        raise ValueError(f"source pin for {artifact_id} does not match final authority")
    return current


def _run_accounting(
    plan: Any,
    consideration: Any,
    routes: tuple[Any, ...],
    ica_enumeration: Any,
    scenario_result: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
    source_pins: tuple[Any, ...] = (),
) -> Any:
    """Derive provisional accounting from the complete Phase 1 universe."""
    ordinary_icas = _first_attr(ica_enumeration, "ica_enumeration") or ica_enumeration
    pairs = _ica_considerations(ica_enumeration)
    verification = _first_attr(ica_enumeration, "ica_hazard_verification")
    if adapters.account is None:
        raise ValueError("synthesis has no obligation accounting adapter")
    result = _invoke(
        adapters.account,
        plan=plan,
        obligation_plan=plan,
        consideration=consideration,
        routes=routes,
        ica_enumeration=ordinary_icas,
        ica_considerations=pairs,
        ica_verification=verification,
        source_pins=source_pins,
        scenario_result=scenario_result,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        inputs=inputs,
        capability_snapshot=snapshot,
        output_dir=inputs.output_dir,
    )
    calls.append("account")
    if result is None:
        raise ValueError("obligation accounting adapter returned no artifact")
    return result


def _run_realization(
    *,
    accounting: Any,
    ica_enumeration: Any,
    scenario_result: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Any:
    """Derive scenario realization separately from ICA-level accounting."""
    ordinary_icas = _first_attr(ica_enumeration, "ica_enumeration") or ica_enumeration
    pairs = _ica_considerations(ica_enumeration)
    scenario_specs = tuple(_first_attr(scenario_result, "scenario_specs") or ())
    if adapters.realize is None:
        raise ValueError("synthesis has no scenario realization adapter")
    result = _invoke(
        adapters.realize,
        accounting=accounting,
        ica_considerations=pairs,
        ica_enumeration=ordinary_icas,
        scenario_specs=scenario_specs,
        scenario_result=scenario_result,
    )
    calls.append("realize")
    if result is None:
        raise ValueError("scenario realization adapter returned no artifact")
    return result


# ---------------------------------------------------------------------------
# Persistence and manifest
# ---------------------------------------------------------------------------


def _persist_prepared_profile(output_dir: Path, profile: CapabilityProfile) -> Path:
    """Persist one typed profile for SP1 to reload without re-derivation.

    The ordinary ``run_sp1`` API accepts a profile path rather than an
    in-memory profile.  Writing the already prepared model once at this seam
    keeps Phase 1 and STPA on the same profile identity and ensures that SP1's
    Stage 1b is skipped.
    """
    payload = profile.model_dump(mode="json", exclude_none=True)
    path = output_dir / "capability-profile.yaml"
    atomic_write_text(
        path, yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    )
    return path


def _persist_plan(
    output_dir: Path,
    plan: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Path:
    """Persist the Phase 1 plan through its adapter and verify a reload."""
    if adapters.persist_plan is not None:
        result = _invoke(
            adapters.persist_plan,
            output_dir=output_dir,
            plan=plan,
            obligation_plan=plan,
        )
        calls.append("persist_plan")
        return Path(result) if result is not None else output_dir / PLAN_FILENAME
    path = write_taxonomy_obligation_plan(output_dir, plan)
    calls.append("persist_plan")
    return path


def _reload_persisted_plan(plan: Any, path: Path) -> Any:
    """Use the closed, integrity-checked Phase 1 artifact downstream."""
    reloaded = TaxonomyObligationPlan.from_yaml(path.read_text(encoding="utf-8"))
    if reloaded != plan:
        raise ValueError("persisted Phase 1 plan does not match the planned artifact")
    return reloaded


def _persist_sidecar(
    output_dir: Path,
    filename: str,
    artifact: Any,
    writer: Callable[..., Any] | None,
    label: str,
) -> Path:
    """Write one closed artifact atomically, then perform a best-effort reload."""
    if writer is not None:
        result = _invoke(
            writer, output_dir=output_dir, artifact=artifact, **{label: artifact}
        )
        path = Path(result) if result is not None else output_dir / filename
        if not path.exists():
            raise ValueError(f"{label} persistence adapter did not write {path}")
        return path
    path = output_dir / filename
    content = _artifact_yaml(artifact)
    atomic_write_text(path, content)
    _verify_yaml_round_trip(artifact, path)
    return path


def _persist_target_realization(
    output_dir: Path,
    artifact: Any | None,
    writer: Callable[..., Any] | None,
) -> Path | None:
    """Publish the additive target lens only when a target was supplied."""
    if artifact is None:
        return None
    if writer is None:
        from asago_scenario_generator.pipeline.target_realization_persistence import (
            write_target_realization,
        )

        return write_target_realization(output_dir, artifact)
    path = _persist_sidecar(
        output_dir,
        TARGET_REALIZATION_FILENAME,
        artifact,
        writer,
        "target_realization",
    )
    return path


def _persist_manifest(
    output_dir: Path,
    manifest: Any,
    writer: Callable[..., Any] | None,
) -> Path:
    """Atomically publish and verify the top-level synthesis manifest."""
    if writer is not None:
        result = _invoke(
            writer, output_dir=output_dir, manifest=manifest, artifact=manifest
        )
        path = Path(result) if result is not None else output_dir / MANIFEST_FILENAME
        if not path.exists():
            raise ValueError(f"manifest persistence adapter did not write {path}")
        return path
    path = output_dir / MANIFEST_FILENAME
    atomic_write_text(path, _artifact_yaml(manifest))
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("synthesis manifest did not round-trip as a mapping")
    return path


def _build_manifest(
    *,
    inputs: SynthesisInputs,
    capability_profile: Any,
    capability_snapshot: Any,
    taxonomy_inputs: Any,
    plan: Any,
    baseline: Any,
    final_loss: Any,
    final_control: Any,
    consideration: Any,
    accounting: Any,
    realization: Any,
    ica_enumeration: Any,
    scenario_result: Any,
    calls: list[str],
    revision: Any,
    stage_errors: list[str],
    stage_warnings: list[str],
    target_realization: Any | None = None,
    operation_enrichment: Any | None = None,
    provider_stages: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a digest-bound manifest from stage authorities."""
    scenarios = tuple(_first_attr(scenario_result, "scenario_envelopes") or ())
    counts = _summary_dict(_first_attr(accounting, "summary"))
    if not counts:
        raise ValueError("obligation accounting must carry a numeric summary")
    catalog_pins = _manifest_taxonomy_pins(
        _first_attr(plan, "catalog_pins")
        or _first_attr(taxonomy_inputs, "catalog_pins")
        or {}
    )
    mapping_pins = _manifest_taxonomy_pins(
        _first_attr(plan, "mapping_pins")
        or _first_attr(taxonomy_inputs, "mapping_pins")
        or {}
    )
    source_artifacts = _manifest_source_artifacts(
        inputs=inputs,
        capability_profile=capability_profile,
        capability_snapshot=capability_snapshot,
        taxonomy_inputs=taxonomy_inputs,
        plan=plan,
        baseline=baseline,
        final_loss=final_loss,
        final_control=final_control,
        consideration=consideration,
        accounting=accounting,
        realization=realization,
        target_realization=target_realization,
        operation_enrichment=operation_enrichment,
        ica_enumeration=ica_enumeration,
        scenario_result=scenario_result,
        counts=counts,
    )
    scenario_counts = _manifest_scenario_counts(scenario_result, len(scenarios))
    run_status, run_status_reason = _scenario_generation_status(scenario_counts)
    payload: dict[str, Any] = {
        "schema_version": _MANIFEST_SCHEMA,
        "run_id": f"synthesis-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}",
        "created_at": datetime.now(UTC).isoformat(),
        "use_case_digest": source_artifacts["use_case"]["semantic_digest"],
        "risk_set_digest": source_artifacts["risk_set"]["semantic_digest"],
        "capability_profile_digest": source_artifacts["capability_profile"][
            "semantic_digest"
        ],
        "capability_snapshot_digest": source_artifacts["capability_snapshot"][
            "semantic_digest"
        ],
        "qualification_facts_digest": source_artifacts["qualification_facts"][
            "semantic_digest"
        ],
        "taxonomy_inputs_digest": source_artifacts["taxonomy_inputs"][
            "semantic_digest"
        ],
        # Keep the two Phase 1 pin maps visible at the manifest boundary.  They
        # are taxonomy release/content pins, not generic ArtifactPin values;
        # retaining their native ``release`` and ``digest`` fields prevents a
        # misleading conversion of taxonomy identity into a schema label.
        "catalog_pins": catalog_pins,
        "mapping_pins": mapping_pins,
        "source_artifacts": source_artifacts,
        # Evidence-model status: a missing operation inventory is recorded
        # as unknown (never as empty); conflicting supplied readings stay
        # visible with both values and their sources.
        "evidence_inventory": _manifest_evidence_inventory(inputs),
        "evidence_conflicts": _manifest_evidence_conflicts(inputs.qualification_facts),
        "plan_digest": source_artifacts["taxonomy_obligation_plan"]["semantic_digest"],
        "baseline_loss_analysis_digest": source_artifacts["baseline_loss_analysis"][
            "semantic_digest"
        ],
        "baseline_control_structure_digest": source_artifacts[
            "baseline_control_structure"
        ]["semantic_digest"],
        "final_loss_analysis_digest": source_artifacts["final_loss_analysis"][
            "semantic_digest"
        ],
        "final_control_structure_digest": source_artifacts["final_control_structure"][
            "semantic_digest"
        ],
        "consideration_digest": source_artifacts["obligation_consideration"][
            "semantic_digest"
        ],
        "ica_enumeration_digest": source_artifacts["ica_enumeration"][
            "semantic_digest"
        ],
        "accounting_digest": source_artifacts["obligation_accounting"][
            "semantic_digest"
        ],
        "scenario_realization_digest": source_artifacts["scenario_realization"][
            "semantic_digest"
        ],
        "execution_target_profile_digest": (
            source_artifacts.get("execution_target_profile", {}).get("semantic_digest")
        ),
        "target_realization_digest": (
            source_artifacts.get("target_realization", {}).get("semantic_digest")
        ),
        "scenario_collection_digest": source_artifacts["scenario_collection"][
            "semantic_digest"
        ],
        "model_controls": {
            "profile": inputs.profile,
            "max_workers": inputs.max_workers,
        },
        "stage_call_counts": {name: calls.count(name) for name in sorted(set(calls))},
        "provider_evidence": _manifest_provider_evidence(provider_stages or {}, inputs),
        "prompt_call_evidence": _manifest_prompt_call_evidence(inputs.output_dir),
        "total_prompt_tokens": _total_prompt_tokens(inputs.output_dir),
        "obligation_disposition_counts": counts,
        "obligation_stop_reason_counts": _obligation_stop_reason_counts(
            accounting, realization
        ),
        "obligation_resolution_funnel": _obligation_resolution_funnel(
            plan=plan,
            accounting=accounting,
            realization=realization,
            scenario_count=len(scenarios),
        ),
        "run_status": run_status.value,
        "run_status_reason": run_status_reason,
        "scenario_counts": scenario_counts,
        "candidate_outcomes": _manifest_candidate_outcomes(scenario_result),
        "scenario_errors": list(_first_attr(scenario_result, "stage_errors") or ()),
        "revision": _manifest_revision(revision),
        "stage_errors": list(stage_errors),
        "stage_warnings": list(stage_warnings),
        # ``run`` cannot resume; the block keeps the manifest schema stable.
        "resume": {
            "requested": False,
            "state": "not_requested",
            "reused_stages": [],
            "checkpoint": None,
        },
        # The manifest is written before the HTML adapter so the report cannot
        # be included in this digest without a circular dependency.  State
        # that boundary explicitly: the report is optional presentation output,
        # not a normative source artifact.
        "report": {
            "artifact_id": "synthesis-report",
            "schema_version": "synthesis-report-html-v1",
            "filename": REPORT_FILENAME,
            "normative": False,
            "digest": None,
        },
    }
    payload["semantic_digest"] = _digest_payload(_MANIFEST_DOMAIN, payload)
    return payload


def _total_prompt_tokens(output_dir: Path) -> int | None:
    """Sum recorded prompt tokens from calls.jsonl for the budget check."""
    path = Path(output_dir) / "calls.jsonl"
    if not path.exists():
        return None
    total = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        total += int(entry.get("prompt_tokens") or 0)
    return total


def _manifest_prompt_call_evidence(output_dir: Path) -> list[dict[str, Any]]:
    """Copy compact prompt-budget and provider-usage evidence into the manifest."""
    path = Path(output_dir) / "calls.jsonl"
    if not path.exists():
        return []
    retained_fields = (
        "stage",
        "step",
        "slot_id",
        "scenario_id",
        "model",
        "system_prompt_hash",
        "user_prompt_hash",
        "prompt_tokens",
        "completion_tokens",
        "duration_ms",
        "success",
        "error",
        "prompt_preflight",
    )
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            source = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"calls.jsonl line {line_number} is not valid JSON"
            ) from exc
        if not isinstance(source, dict):
            raise ValueError(f"calls.jsonl line {line_number} must be an object")
        record = {
            field_name: source[field_name]
            for field_name in retained_fields
            if field_name in source and source[field_name] is not None
        }
        if "response_content" in source:
            record["response_digest"] = _digest_value(source["response_content"])
        records.append(record)
    return records


def _manifest_taxonomy_pins(value: Any) -> dict[str, Any]:
    """Serialize native Phase 1 taxonomy pins without changing their meaning."""
    dumped = _dump(value)
    if not isinstance(dumped, Mapping):
        return {}
    return {str(key): dumped[key] for key in sorted(dumped)}


def _manifest_artifact_identity(
    artifact_id: str,
    schema_version: str,
    value: Any,
    *,
    digest: str | None = None,
) -> dict[str, str]:
    """Return one stable identity record for a manifest source artifact.

    Durable typed artifacts already expose their own verified semantic digest.
    For text, input graphs, and adapter-only test values, the manifest still
    gives the value a deterministic version-framed identity rather than using
    an unframed hash or a YAML byte digest.
    """
    declared = digest or _first_attr(value, "semantic_digest")
    if not isinstance(declared, str) or not declared:
        declared = compute_framed_digest(
            f"{_MANIFEST_DOMAIN}:{artifact_id}:v1", _dump(value)
        )
    actual_schema = _first_attr(value, "schema_version")
    return {
        "artifact_id": artifact_id,
        "schema_version": str(actual_schema or schema_version),
        "semantic_digest": declared,
    }


def _manifest_evidence_inventory(inputs: SynthesisInputs) -> dict[str, Any]:
    """Publish the run's supplied operation inventory status.

    A missing inventory is unknown, never empty. The classification is
    deterministic and consumes only the execution target profile.
    """
    from asago_scenario_generator.pipeline.evidence_inventory import (
        classify_evidence_inventory,
    )

    status = classify_evidence_inventory(
        execution_target_profile=inputs.execution_target_profile,
    )
    return status.model_dump(mode="json")


def _manifest_evidence_conflicts(qualification_facts: Any) -> list[dict[str, Any]]:
    """Publish every contradictory supplied fact with its retained readings."""
    from asago_scenario_generator.pipeline.evidence_inventory import (
        conflicting_fact_readings,
    )

    return conflicting_fact_readings(qualification_facts)


def _manifest_source_artifacts(
    *,
    inputs: SynthesisInputs,
    capability_profile: Any,
    capability_snapshot: Any,
    taxonomy_inputs: Any,
    plan: Any,
    baseline: Any,
    final_loss: Any,
    final_control: Any,
    consideration: Any,
    accounting: Any,
    realization: Any,
    target_realization: Any | None,
    operation_enrichment: Any | None = None,
    ica_enumeration: Any,
    scenario_result: Any,
    counts: Mapping[str, int],
) -> dict[str, dict[str, str]]:
    """Build the complete source identity inventory for the run manifest."""
    del counts  # reserved for future artifact-level accounting metadata
    baseline_loss = _first_attr(baseline, "loss_analysis")
    baseline_control = _first_attr(baseline, "control_structure")
    ordinary_icas = _first_attr(ica_enumeration, "ica_enumeration") or ica_enumeration
    scenarios = tuple(_first_attr(scenario_result, "scenario_envelopes") or ())
    artifacts = {
        "use_case": _manifest_artifact_identity(
            "use-case", "use-case-text-v1", inputs.use_case
        ),
        "risk_set": _manifest_artifact_identity(
            "risk-set", "reviewed-risk-set-v1", inputs.risk_cards
        ),
        "capability_profile": _manifest_artifact_identity(
            "capability-profile", "capability-profile-v1", capability_profile
        ),
        "capability_snapshot": _manifest_artifact_identity(
            "capability-snapshot",
            "capability-fact-snapshot-v1",
            capability_snapshot,
            digest=capability_snapshot.snapshot_digest,
        ),
        "qualification_facts": _manifest_artifact_identity(
            "qualification-facts", "qualification-facts-v1", inputs.qualification_facts
        ),
        "taxonomy_inputs": _manifest_artifact_identity(
            "taxonomy-obligation-inputs",
            "taxonomy-obligation-inputs-v1",
            taxonomy_inputs,
        ),
        "taxonomy_obligation_plan": _manifest_artifact_identity(
            "taxonomy-obligation-plan", "taxonomy-obligation-plan-v1", plan
        ),
        "baseline_loss_analysis": _manifest_artifact_identity(
            "stpa-loss-analysis-baseline",
            "stpa-loss-analysis-v1",
            baseline_loss,
        ),
        "baseline_control_structure": _manifest_artifact_identity(
            "stpa-control-structure-baseline",
            "stpa-control-structure-v1",
            baseline_control,
        ),
        "final_loss_analysis": _manifest_artifact_identity(
            "stpa-loss-analysis-final", "stpa-loss-analysis-v1", final_loss
        ),
        "final_control_structure": _manifest_artifact_identity(
            "stpa-control-structure-final", "stpa-control-structure-v1", final_control
        ),
        "obligation_consideration": _manifest_artifact_identity(
            "obligation-consideration",
            "stpa-obligation-consideration-v1",
            consideration,
        ),
        "ica_enumeration": _manifest_artifact_identity(
            "ica-enumeration", "ica-enumeration-v1", ordinary_icas
        ),
        "scenario_collection": _manifest_artifact_identity(
            "stpa-scenario-collection", "stpa-scenario-collection-v1", scenarios
        ),
        "obligation_accounting": _manifest_artifact_identity(
            "obligation-accounting", "stpa-obligation-accounting-v1", accounting
        ),
        "scenario_realization": _manifest_artifact_identity(
            "scenario-realization", "stpa-scenario-realization-v1", realization
        ),
    }
    if inputs.execution_target_profile is not None:
        artifacts["execution_target_profile"] = _manifest_artifact_identity(
            "execution-target-profile",
            "execution-target-profile-v1",
            inputs.execution_target_profile,
        )
    if target_realization is not None:
        artifacts["target_realization"] = _manifest_artifact_identity(
            "target-realization",
            "target-realization-v1",
            target_realization,
        )
    if operation_enrichment is not None:
        artifacts["control_action_enrichment"] = _manifest_artifact_identity(
            "control-action-operation-enrichment",
            "control-action-operation-enrichment-v1",
            operation_enrichment.record,
        )
    return artifacts


def _manifest_call_evidence(value: Any) -> tuple[Any, ...]:
    """Extract typed call records from a stage result or its wrapper."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set, frozenset)):
        result: list[Any] = []
        for item in value:
            result.extend(_manifest_call_evidence(item))
        return tuple(result)
    direct = _first_attr(value, "call_evidence")
    if direct is not None:
        if direct is value:
            return ()
        return _manifest_call_evidence(direct)
    nested = _first_attr(value, "result")
    if nested is not None and nested is not value:
        return _manifest_call_evidence(nested)
    # A single typed call record is accepted as an element in a revision
    # tuple, but arbitrary values are not presented as provider evidence.
    if _first_attr(value, "call_id") is not None:
        return (value,)
    return ()


def _manifest_scalar_fields(value: Any, names: tuple[str, ...]) -> dict[str, Any]:
    """Keep only named scalar evidence fields from a provider envelope."""
    if value is None:
        return {}
    result: dict[str, Any] = {}
    for name in names:
        field = _first_attr(value, name)
        if isinstance(field, (str, int, float, bool)):
            result[name] = field
    return result


def _manifest_revision_endpoint(
    value: Any, names: tuple[str, ...]
) -> dict[str, Any] | None:
    """Project one revision request/response to identity-only evidence."""
    fields = _manifest_scalar_fields(value, names)
    return fields or None


def _manifest_revision_call(value: Any) -> dict[str, Any]:
    """Project one revision call record without serializing provider payloads."""
    return _manifest_scalar_fields(
        value,
        (
            "call_id",
            "outcome",
            "request_digest",
            "response_digest",
            "attempt_count",
        ),
    )


def _manifest_revision(revision: Any) -> dict[str, Any]:
    """Publish bounded revision status and evidence, never its STPA objects."""

    def identifiers(name: str) -> list[str]:
        values = _first_attr(revision, name) or ()
        if isinstance(values, str):
            values = (values,)
        return sorted({str(value) for value in values})

    diagnostics = _first_attr(revision, "diagnostics") or ()
    if isinstance(diagnostics, str):
        diagnostics = (diagnostics,)
    calls = [
        record
        for item in _manifest_call_evidence(revision)
        if (record := _manifest_revision_call(item))
    ]
    calls.sort(key=lambda item: (str(item.get("call_id", "")), _canonical_json(item)))
    return {
        "status": _revision_status(revision),
        "trigger_obligation_ids": identifiers("trigger_obligation_ids"),
        "trigger_gap_ids": identifiers("trigger_gap_ids"),
        "diagnostics": [str(value) for value in diagnostics],
        "request": _manifest_revision_endpoint(
            _first_attr(revision, "request"),
            ("schema_version", "semantic_digest", "request_ref"),
        ),
        "response": _manifest_revision_endpoint(
            _first_attr(revision, "response"),
            (
                "schema_version",
                "status",
                "request_digest",
                "response_digest",
                "response_ref",
            ),
        ),
        "call_evidence": calls,
    }


def _manifest_provider_evidence(
    stages: Mapping[str, Any], inputs: SynthesisInputs
) -> dict[str, Any]:
    """Publish request/response identities and outcomes for each provider stage."""
    controls = {
        "profile": inputs.profile,
        # ``generate`` has no temperature or batch-size override; the keys keep
        # the manifest schema stable.
        "temperature": None,
        "max_batch_size": None,
    }
    result: dict[str, Any] = {}
    for stage_name in sorted(stages):
        evidence = _manifest_call_evidence(stages[stage_name])
        records = [_dump(item) for item in evidence]
        attempts = sum(
            int(_first_attr(item, "attempt_count") or 1) for item in evidence
        )
        result[stage_name] = {
            "call_count": attempts,
            "records": records,
            "controls": controls,
        }
        verification = _first_attr(stages[stage_name], "ica_hazard_verification")
        if verification is not None:
            result[stage_name]["ica_hazard_verification"] = _dump(verification)
    return result


def _render_report(
    output_dir: Path,
    manifest: Any,
    plan: Any,
    consideration: Any,
    accounting: Any,
    realization: Any,
    target_realization: Any,
    scenario_result: Any,
    renderer: Callable[..., Any] | None,
) -> Path | None:
    """Render the read-only synthesis report after all normative sidecars."""
    if renderer is not None:
        result = _invoke(
            renderer,
            output_dir=output_dir,
            manifest=manifest,
            plan=plan,
            consideration=consideration,
            accounting=accounting,
            realization=realization,
            target_realization=target_realization,
            scenario_result=scenario_result,
        )
        return Path(result) if result is not None else None
    try:
        from asago_scenario_generator.report.synthesis import render_synthesis_report

        return render_synthesis_report(
            output_dir,
            manifest=manifest,
            plan=plan,
            consideration=consideration,
            accounting=accounting,
            realization=realization,
            target_realization=target_realization,
            scenario_result=scenario_result,
        )
    except Exception as exc:  # noqa: BLE001 - report is read-only and non-fatal
        logger.warning("synthesis report generation failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Fallback adapters / compatibility bridges
# ---------------------------------------------------------------------------


def _default_prepare_capability(*, inputs: SynthesisInputs, **_: Any) -> Any:
    """Resolve a profile through the existing STPA profile adapter."""
    from asago_scenario_generator.stpa.infra.llm import effective_temperature
    from asago_scenario_generator.stpa.pipeline.llm_config import resolve_llm_client
    from asago_scenario_generator.stpa.system_model.profile import (
        derive_capability_profile,
    )
    from asago_scenario_generator.stpa.infra.templates import TemplateLoader
    from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR

    client, profile_name = resolve_llm_client(
        inputs.profile,
        str(inputs.profiles_file),
    )
    return derive_capability_profile(
        llm_client=client,
        use_case_text=inputs.use_case,
        run_dir=inputs.output_dir,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=effective_temperature(client),
    )


def _default_plan(*, taxonomy_inputs: Any, **_: Any) -> Any:
    """Invoke the pure planner after the composition root pins inputs."""
    return plan_taxonomy_obligations(taxonomy_inputs)


def _default_briefs(*, plan: Any, taxonomy_inputs: Any, **_: Any) -> Any:
    """Build neutral briefs from the exact plan/catalog input graph."""
    module = _load_obligation_module(
        "build_neutral_obligation_briefs",
        "build_neutral_briefs",
    )
    fn = _find_callable(
        module,
        "build_neutral_obligation_briefs",
        "build_neutral_briefs",
    )
    if fn is None:
        return None
    catalog = _first_attr(taxonomy_inputs, "attack_pattern_catalog")
    if catalog is None:
        return None
    return _invoke(fn, plan=plan, attack_pattern_catalog=catalog, patterns=catalog)


def _default_baseline(
    *,
    inputs: SynthesisInputs,
    capability_profile: Any,
    capability_profile_path: Path | None = None,
    loss_analysis_path: Path | None = None,
    output_dir: Path,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    **_: Any,
) -> Any:
    """Run ordinary SP1 using one resolved provider client.

    One unified analysis runs for every supplied input.  The observed
    execution target enters SP1 as evidence (owner decision, 2026-09-29
    STPA review): its inventory, state schema, session fields, and policy
    reads ground the Stage 1a hazards and constraints and every Stage 2
    call; they never select a different derivation.  A pinned loss analysis
    skips Stage 1a's model calls entirely.
    """
    from asago_scenario_generator.data.loaders import load_reviewed_risk_extraction
    from asago_scenario_generator.stpa.pipeline.llm_config import resolve_llm_client
    from asago_scenario_generator.stpa.system_model.run import run_sp1
    from asago_scenario_generator.stpa.system_model.target_evidence import (
        build_target_evidence,
    )

    client, profile_name = resolve_llm_client(
        inputs.profile,
        str(inputs.profiles_file),
    )
    risk_cards = list(inputs.risk_cards)
    if not risk_cards and inputs.risk_extraction_path is not None:
        risk_cards = load_reviewed_risk_extraction(inputs.risk_extraction_path)
    result = run_sp1(
        llm_client=client,
        use_case_text=inputs.use_case,
        risk_cards=risk_cards,
        run_dir=output_dir,
        profile_path=capability_profile_path,
        profile_name=profile_name,
        max_workers=inputs.max_workers,
        loss_analysis_path=loss_analysis_path or inputs.loss_analysis_path,
        # ``inputs`` is the target-blind view; the observed target arrives
        # only through the explicit keyword arguments.
        target_evidence=build_target_evidence(
            execution_target_profile, target_observations
        ),
    )
    return result


def _load_obligation_module(*required_names: str) -> Any:
    """Load the sibling STPA obligation-aware module when present."""
    import importlib

    for name in (
        "asago_scenario_generator.stpa.obligation_aware",
        "asago_scenario_generator.pipeline.obligation_consideration",
    ):
        try:
            module = importlib.import_module(name)
        except ModuleNotFoundError:
            continue
        if not required_names or any(
            callable(getattr(module, required_name, None))
            for required_name in required_names
        ):
            return module
    raise ValueError("obligation-aware STPA adapter is not installed")


def _resolve_obligation_provider(inputs: SynthesisInputs, output_dir: Path) -> Any:
    """Resolve the one SP2 provider adapter shared by named STPA stages."""
    if inputs.obligation_adapter is not None:
        return inputs.obligation_adapter
    from asago_scenario_generator.stpa.obligation_aware.provider import (
        adapter_from_synthesis_inputs,
    )

    return adapter_from_synthesis_inputs(inputs=inputs, output_dir=Path(output_dir))


def _provider_controls(provider: Any, inputs: SynthesisInputs) -> Any:
    """Return provider controls, preserving explicit stage settings."""
    controls = getattr(provider, "controls", None)
    if controls is not None:
        return controls
    from asago_scenario_generator.stpa.obligation_aware.contracts import (
        AnalysisControls,
    )

    return AnalysisControls(
        model_profile=inputs.profile or "synthesis",
        model_name=str(getattr(provider, "model", None) or "caller-supplied"),
        deadline_seconds=300.0,
        temperature=0.4,
        max_batch_size=8,
    )


def _default_consider(**kwargs: Any) -> Any:
    """Run one typed initial routing pass with the shared SP2 adapter."""
    from asago_scenario_generator.stpa.obligation_aware.routing import (
        route_obligations,
    )

    inputs = kwargs["inputs"]
    provider = kwargs.get("obligation_adapter") or _resolve_obligation_provider(
        inputs, kwargs["output_dir"]
    )
    return route_obligations(
        provider,
        briefs=kwargs["briefs"],
        loss_analysis=kwargs["loss_analysis"],
        control_structure=kwargs["control_structure"],
        controls=_provider_controls(provider, inputs),
        purpose="initial",
    )


def _default_revision(**kwargs: Any) -> Any:
    """Run the one typed additive revision attempt through SP2."""
    from asago_scenario_generator.models.obligation_consideration import (
        MissingStructuralConcept,
    )
    from asago_scenario_generator.stpa.obligation_aware.revision import (
        revise_structure_once,
    )

    inputs = kwargs["inputs"]
    provider = kwargs.get("obligation_adapter") or _resolve_obligation_provider(
        inputs, kwargs["output_dir"]
    )
    routes = tuple(kwargs.get("gaps") or kwargs.get("upstream_gaps") or ())
    concepts: list[MissingStructuralConcept] = []
    trigger_ids: list[str] = []
    for value in routes:
        if isinstance(value, MissingStructuralConcept):
            concepts.append(value)
            if value.obligation_id is not None:
                trigger_ids.append(value.obligation_id)
            continue
        obligation_id = _route_obligation_id(value)
        if obligation_id is not None:
            trigger_ids.append(obligation_id)
        concepts.extend(_first_attr(value, "missing_concepts") or ())
    return revise_structure_once(
        provider,
        gaps=concepts,
        trigger_obligation_ids=trigger_ids,
        loss_analysis=kwargs["loss_analysis"],
        control_structure=kwargs["control_structure"],
        controls=_provider_controls(provider, inputs),
        plan_digest=_semantic_digest(kwargs.get("plan")),
    )


def _default_recheck(**kwargs: Any) -> Any:
    """Run the sole complete post-revision routing pass through SP2."""
    from asago_scenario_generator.stpa.obligation_aware.routing import (
        recheck_obligations,
    )

    inputs = kwargs["inputs"]
    provider = kwargs.get("obligation_adapter") or _resolve_obligation_provider(
        inputs, kwargs["output_dir"]
    )
    return recheck_obligations(
        provider,
        briefs=kwargs["briefs"],
        loss_analysis=kwargs["loss_analysis"],
        control_structure=kwargs["control_structure"],
        controls=_provider_controls(provider, inputs),
    )


def _default_fill_icas(**kwargs: Any) -> Any:
    """Fill final ICA slots with exact routed obligation evidence."""
    from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
        fill_synthesis_slots,
    )

    inputs = kwargs["inputs"]
    provider = kwargs.get("obligation_adapter") or _resolve_obligation_provider(
        inputs, kwargs["output_dir"]
    )
    return fill_synthesis_slots(
        provider,
        briefs=kwargs["briefs"],
        routes=kwargs["routes"],
        loss_analysis=kwargs["loss_analysis"],
        control_structure=kwargs["control_structure"],
        controls=_provider_controls(provider, inputs),
    )


def _default_target_realize(
    *,
    loss_analysis: Any,
    control_structure: Any,
    ica_enumeration: Any,
    capability_profile: Any,
    execution_target_profile: ExecutionTargetProfile,
    inputs: SynthesisInputs,
    output_dir: Path,
    **_: Any,
) -> Any:
    """Run model-assisted target realization after systemic ICA completion."""
    from asago_scenario_generator.models.target_realization import (
        SystemicStpaBaseline,
    )
    from asago_scenario_generator.pipeline.target_realization import (
        realize_target_derived_icas,
        realize_target_operations,
    )
    from asago_scenario_generator.stpa.infra.llm import effective_temperature
    from asago_scenario_generator.stpa.pipeline.llm_config import resolve_llm_client
    from asago_scenario_generator.stpa.target_realization import (
        TargetDerivedICALlmFinder,
        TargetRealizationLlmInterpreter,
    )

    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ica_enumeration,
        declared_capabilities=_declared_capability_labels(capability_profile),
    )
    client, _profile_name = resolve_llm_client(
        inputs.profile,
        str(inputs.profiles_file),
    )
    interpreter = TargetRealizationLlmInterpreter(
        client,
        output_dir,
        temperature=effective_temperature(client),
        call_variant="target_realization",
    )
    mapped = realize_target_operations(
        baseline,
        execution_target_profile,
        lambda: interpreter,
    )
    finder = TargetDerivedICALlmFinder(
        client,
        output_dir,
        temperature=effective_temperature(client),
    )
    return realize_target_derived_icas(
        baseline,
        mapped,
        lambda: finder,
    )


def _default_enrich_control_actions(
    *,
    loss_analysis: Any,
    control_structure: Any,
    capability_profile: Any,
    execution_target_profile: ExecutionTargetProfile | None,
    inputs: SynthesisInputs,
    output_dir: Path,
    **_: Any,
) -> Any | None:
    """Run the pre-ICA enrichment grounding for an observed target profile.

    Owner decision (M2 unified path): known operations enrich the logical
    control actions; they never replace the control model with tool
    enumeration.  Without an observed profile, or for a simulation profile,
    there is nothing to ground and the analysis is returned unchanged.
    """
    from asago_scenario_generator.stpa.models.execution_classification import (
        ProfileBasis,
    )

    if execution_target_profile is None:
        return None
    if execution_target_profile.basis is ProfileBasis.simulation:
        return None
    from asago_scenario_generator.pipeline.control_action_enrichment import (
        enrich_control_actions,
    )
    from asago_scenario_generator.stpa.infra.llm import effective_temperature
    from asago_scenario_generator.stpa.pipeline.llm_config import resolve_llm_client
    from asago_scenario_generator.stpa.target_realization import (
        TargetRealizationLlmInterpreter,
    )

    client, _profile_name = resolve_llm_client(
        inputs.profile,
        str(inputs.profiles_file),
    )
    interpreter = TargetRealizationLlmInterpreter(
        client,
        output_dir,
        temperature=effective_temperature(client),
        call_variant="control_action_enrichment",
    )
    return enrich_control_actions(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        profile=execution_target_profile,
        interpreter_factory=lambda: interpreter,
    )


def _run_operation_enrichment(
    *,
    loss_analysis: Any,
    control_structure: Any,
    capability_profile: Any,
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Any | None:
    """Run the enrichment grounding stage and persist its evidence sidecar."""
    from asago_scenario_generator.pipeline.control_action_enrichment import (
        CONTROL_ACTION_ENRICHMENT_FILENAME,
        ControlActionEnrichment,
    )
    from asago_scenario_generator.stpa.infra.yaml_io import write_yaml

    result = _invoke(
        adapters.enrich_actions,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        capability_profile=capability_profile,
        execution_target_profile=inputs.execution_target_profile,
        inputs=inputs,
        output_dir=inputs.output_dir,
    )
    if result is None:
        return None
    if not isinstance(result, ControlActionEnrichment):
        raise TypeError(
            "enrichment adapter must return a ControlActionEnrichment value"
        )
    sidecar_path = Path(inputs.output_dir) / CONTROL_ACTION_ENRICHMENT_FILENAME
    write_yaml(result.record, sidecar_path)
    calls.append("control_action_enrichment")
    return result


def _verified_enriched_operations(
    enrichment: Any | None,
    target_realization: Any | None = None,
) -> dict[str, str]:
    """Map verified baseline and target-derived rows to operation identities.

    The handoff publication seam consumes only verified views of the
    pre-ICA ``control-action-enrichment.yaml`` sidecar and the later
    target-realization artifact.  A baseline row contributes when either the
    enrichment specialized the action or target realization independently
    verified one exact selected operation for that action.  The fallback
    requires the systemic-baseline provenance, supported disposition,
    verifier status, and deterministic verified-pair evidence to agree.
    A target-derived operation record contributes only when its exact
    deterministic verified-pair evidence matches the record's
    action/resource/operation identity.  Unverified, ambiguous, missing,
    mismatched, or duplicate records contribute nothing.  Baseline action IDs
    win if malformed input attempts to collide with them.
    """
    verified: dict[str, str] = {}
    if enrichment is not None:
        record = getattr(enrichment, "record", enrichment)
        for row in tuple(getattr(record, "rows", ()) or ()):
            operation_id = getattr(row, "operation_id", None)
            if (
                getattr(row, "enriched", False) is True
                and operation_id
                and getattr(row, "verification_status", None) == "verified"
            ):
                verified[getattr(row, "control_action_id")] = operation_id
    for action_id, operation_id in _verified_target_baseline_operations(
        target_realization
    ).items():
        verified.setdefault(action_id, operation_id)
    for action_id, operation_id in _verified_target_derived_operations(
        target_realization
    ).items():
        verified.setdefault(action_id, operation_id)
    return verified


def _verified_target_baseline_operations(
    realization: Any | None,
) -> dict[str, str]:
    """Return exact operations verified for systemic baseline actions."""
    if realization is None:
        return {}
    # A duplicate baseline row cannot establish one exact mapping.
    rows = _single_item_by_action(
        tuple(getattr(realization, "rows", ()) or ()), "control_action_id"
    )
    verified = {
        action_id: _verified_baseline_operation(action_id, row)
        for action_id, row in rows.items()
    }
    return {key: value for key, value in verified.items() if value is not None}


def _verified_target_derived_operations(realization: Any | None) -> dict[str, str]:
    """Return exact operation IDs from independently verified derived records."""
    if realization is None:
        return {}
    supported = (
        record
        for record in tuple(getattr(realization, "operation_records", ()) or ())
        if _enum_value(getattr(record, "provenance", None)) == "target_derived"
        and _enum_value(getattr(record, "disposition", None)) == "supported"
    )
    # More than one target operation for one derived action is ambiguous,
    # even when the operation IDs happen to repeat.
    records = _single_item_by_action(supported, "target_derived_control_action_id")
    verified = {
        action_id: _verified_pair_operation(
            action_id,
            getattr(record, "operation", None),
            getattr(record, "evidence_refs", ()),
        )
        for action_id, record in records.items()
    }
    return {key: value for key, value in verified.items() if value is not None}


def _single_item_by_action(items: Iterable[Any], action_attr: str) -> dict[str, Any]:
    """Group items by a truthy action ID; keep actions with exactly one item."""
    grouped: dict[str, list[Any]] = {}
    for item in items:
        action_id = getattr(item, action_attr, None)
        if action_id:
            grouped.setdefault(action_id, []).append(item)
    return {key: group[0] for key, group in grouped.items() if len(group) == 1}


def _verified_baseline_operation(action_id: str, row: Any) -> str | None:
    """Return the operation of a supported baseline row its verifier confirmed."""
    verifier = getattr(row, "verifier", None)
    if (
        _enum_value(getattr(row, "provenance", None)) != "systemic_baseline"
        or _enum_value(getattr(row, "disposition", None)) != "supported"
        or _enum_value(getattr(verifier, "status", None)) != "verified"
    ):
        return None
    return _verified_pair_operation(
        action_id,
        getattr(row, "selected_operation", None),
        getattr(verifier, "evidence_refs", ()),
    )


def _verified_pair_operation(
    action_id: str, operation: Any, evidence_refs: Any
) -> str | None:
    """Return the operation ID when the evidence names its exact verified pair."""
    resource_id = getattr(operation, "resource_id", None)
    operation_id = getattr(operation, "operation_id", None)
    if not isinstance(resource_id, str) or not isinstance(operation_id, str):
        return None
    expected_evidence = (
        f"target-realization:verified-pair:{action_id}:{resource_id}/{operation_id}"
    )
    if expected_evidence not in tuple(evidence_refs or ()):
        return None
    return operation_id


def _enum_value(value: Any) -> Any:
    """Read enum-backed or plain test-double values without coercion."""
    return getattr(value, "value", value)


def _declared_capability_labels(profile: Any) -> tuple[str, ...]:
    """Return exact declared operation labels without interpreting prose."""
    labels = {
        str(item.name)
        for collection_name in ("tool_inventory", "external_integrations")
        for item in tuple(getattr(profile, collection_name, None) or ())
        if getattr(item, "name", None)
    }
    return tuple(sorted(labels))


def _default_scenarios(
    *,
    ica_enumeration: Any,
    control_structure: Any,
    loss_analysis: Any,
    inputs: SynthesisInputs,
    capability_profile: Any,
    output_dir: Path,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_realization: Any | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    enriched_operations: Mapping[str, str] | None = None,
    briefs: tuple[Any, ...] = (),
    ica_considerations: tuple[Any, ...] = (),
    **_: Any,
) -> Any:
    """Run ordinary SP3 from the final ICA enumeration.

    The regular SP2 enrichment is deterministic and receives the final ICA
    model.  No taxonomy mechanism or Phase 4 graph is passed to SP3.
    ``enriched_operations`` is the verified operation view assembled from the
    run's ``control-action-enrichment.yaml`` sidecar and target-realization
    baseline rows; SP3 publishes those verified operation identities in each
    handoff's ``documented_operations``.
    """
    from asago_scenario_generator.stpa.pipeline.llm_config import resolve_llm_client
    from asago_scenario_generator.stpa.scenario_prod.condition_family import (
        plan_family_candidates,
    )
    from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
    from asago_scenario_generator.stpa.threat_enum.catalog_enrichment import (
        enrich_threats,
    )

    client, _ = resolve_llm_client(inputs.profile, str(inputs.profiles_file))
    # ``fill_synthesis_slots`` returns a wrapper carrying both the ordinary
    # ICA enumeration and the exact obligation/slot evidence needed by
    # accounting.  SP3 consumes only the ordinary enumeration.
    ordinary_icas = _first_attr(ica_enumeration, "ica_enumeration") or ica_enumeration
    enriched = enrich_threats(ordinary_icas, control_structure)
    family_plan = plan_family_candidates(
        enriched.structural_threats, target_realization, target_observations
    )
    if len(family_plan.threats) != len(enriched.structural_threats):
        enriched = enriched.model_copy(
            update={"structural_threats": list(family_plan.threats)}
        )
    condition_families = family_plan.candidates
    scenario_contexts = _build_synthesis_scenario_contexts(
        enriched.structural_threats,
        control_structure,
        loss_analysis,
        briefs=briefs,
        ica_considerations=ica_considerations,
    )
    return run_sp3(
        llm_client=client,
        enriched_threat_set=enriched,
        control_structure=control_structure,
        loss_analysis=loss_analysis,
        run_dir=output_dir,
        capability_profile=capability_profile,
        max_workers=inputs.max_workers,
        scenario_contexts=scenario_contexts,
        execution_target_profile=execution_target_profile,
        target_realization=target_realization,
        target_observations=target_observations,
        observation_contract=inputs.observation_contract,
        enriched_operations=enriched_operations,
        # Finding A2: the published constraint authority derives from the
        # run's actual Stage 1a acceptance record, not from an asserted
        # reviewed stamp.
        stage_1a_source=(
            "pinned" if inputs.loss_analysis_path is not None else "derived"
        ),
        condition_families=condition_families,
    )


def _run_bounded_revision(
    gaps: tuple[Any, ...],
    initial_routes: tuple[Any, ...],
    applicable_briefs: tuple[Any, ...],
    plan: Any,
    baseline_loss: Any,
    baseline_control: Any,
    inputs: SynthesisInputs,
    capability_snapshot: Any,
    resolved: SynthesisAdapters,
    calls: list[str],
    stage_errors: list[str],
) -> tuple[Any, Any | None, Any, Any, tuple[Any, ...]]:
    """Run at most one structural revision and its recheck for route gaps.

    Returns the revision result, the recheck result (or None), the final loss
    analysis and control structure, and the final routes.
    """
    final_loss = baseline_loss
    final_control = baseline_control
    revision_result: Any = SimpleNamespace(status="not_required")
    recheck_result: Any | None = None
    final_routes = initial_routes

    # One adaptive analysis: no supplied input selects a different generation
    # algorithm, so there is no mode branch here. Obligation-gap structural
    # revision always runs; the observed target never suppresses it.
    if not gaps:
        return revision_result, recheck_result, final_loss, final_control, final_routes
    revision_result = _run_revision(
        gaps,
        plan,
        baseline_loss,
        baseline_control,
        inputs,
        capability_snapshot,
        resolved,
        calls,
        stage_errors,
    )
    # Only an explicitly applied revision changes the authoritative
    # structure. Rejected and technical outcomes retain the baseline and
    # original upstream-gap routes; they do not receive a second pass.
    revision_applied = _revision_status(revision_result) == "applied"
    if revision_applied:
        final_loss = (
            _first_attr(revision_result, "final_loss_analysis") or baseline_loss
        )
        final_control = (
            _first_attr(revision_result, "final_control_structure") or baseline_control
        )

    if revision_applied and resolved.recheck is not None:
        rechecked = _invoke(
            resolved.recheck,
            briefs=applicable_briefs,
            plan=plan,
            loss_analysis=final_loss,
            control_structure=final_control,
            revision=revision_result,
            inputs=_systemic_inputs(inputs),
            capability_snapshot=capability_snapshot,
            obligation_adapter=resolved.obligation_adapter,
            output_dir=inputs.output_dir,
        )
        calls.append("recheck")
        recheck_result = rechecked
        final_routes = tuple(rechecked.routes)
    return revision_result, recheck_result, final_loss, final_control, final_routes


def _artifact_paths(
    output_dir: Path,
    inputs: SynthesisInputs,
    artifact_paths: dict[str, Path],
    *,
    target_realization_path: Path | None,
    operation_enrichment: Any | None,
    report_path: Path | None,
) -> dict[str, Path]:
    """Add each optional published artifact to the always-written ones."""
    if target_realization_path is not None:
        artifact_paths[TARGET_REALIZATION_FILENAME] = target_realization_path
    if operation_enrichment is not None:
        from asago_scenario_generator.pipeline.control_action_enrichment import (
            CONTROL_ACTION_ENRICHMENT_FILENAME,
        )

        artifact_paths[CONTROL_ACTION_ENRICHMENT_FILENAME] = (
            output_dir / CONTROL_ACTION_ENRICHMENT_FILENAME
        )
    target_observations_path = (
        output_dir / TARGET_OBSERVATIONS_FILENAME
        if inputs.target_observations is not None
        else None
    )
    if target_observations_path is not None and target_observations_path.exists():
        artifact_paths[TARGET_OBSERVATIONS_FILENAME] = target_observations_path
    if report_path is not None:
        artifact_paths[REPORT_FILENAME] = report_path
    return artifact_paths


def _findings_by_ica(
    briefs: tuple[Any, ...],
    ica_considerations: tuple[Any, ...],
) -> dict[str, list[Any]]:
    """Project each ICA finding onto every ICA it names, in input order."""
    from asago_scenario_generator.stpa.models.scenario_context import (
        ScenarioObligationConsideration,
    )

    brief_by_id = {
        brief.obligation_id: brief
        for brief in briefs
        if getattr(brief, "obligation_id", None) is not None
    }
    by_ica: dict[str, list[ScenarioObligationConsideration]] = {}
    for pair in ica_considerations:
        if getattr(pair, "disposition", None) != "finding":
            continue
        brief = brief_by_id.get(pair.obligation_id)
        if brief is None:
            raise ValueError(
                f"ICA finding references unknown obligation {pair.obligation_id!r}"
            )
        projected = ScenarioObligationConsideration(
            obligation_id=pair.obligation_id,
            attack_pattern_id=brief.attack_pattern_id,
            attack_pattern_name=brief.attack_pattern_name,
            concise_concern=brief.attack_pattern_description,
            disposition="finding",
            rationale=pair.rationale
            or (
                "STPA identified this concern in the selected ICA after "
                "analyzing the routed control path."
            ),
            finding_ica_id=None,
        )
        for ica_id in pair.ica_ids:
            by_ica.setdefault(ica_id, []).append(
                projected.model_copy(update={"finding_ica_id": ica_id})
            )

    return by_ica


def _build_synthesis_scenario_contexts(
    threats: Iterable[Any],
    control_structure: Any,
    loss_analysis: Any,
    *,
    briefs: tuple[Any, ...],
    ica_considerations: tuple[Any, ...],
) -> dict[str, Any]:
    """Bind each Stage 5 candidate to the obligation findings its ICA carries.

    Contexts are keyed by scenario ID because one ICA can yield several
    candidates, one per condition family.
    """
    from asago_scenario_generator.stpa.scenario_prod.context import (
        build_scenario_generation_context,
    )

    by_ica = _findings_by_ica(briefs, ica_considerations)
    result: dict[str, Any] = {}
    for index, threat in enumerate(threats):
        if threat.ica_id is None:
            raise ValueError("synthesis scenario threat has no exact ICA identity")
        considerations = tuple(
            sorted(
                by_ica.get(threat.ica_id, ()),
                key=lambda item: item.obligation_id,
            )
        )
        scenario_id = f"SCN-{index + 1:03d}"
        try:
            result[scenario_id] = build_scenario_generation_context(
                threat,
                control_structure,
                loss_analysis,
                scenario_id=scenario_id,
                obligation_considerations=considerations,
            )
        except ValueError:
            # SP3 builds a missing supplied context again inside its per-threat
            # boundary.  Leaving this one out lets that boundary retain the
            # exact error for this ICA without erasing valid sibling contexts.
            continue
    return result


def _default_account(**kwargs: Any) -> Any:
    """Use the typed provisional accounting seam; never infer addressed rows."""
    from asago_scenario_generator.pipeline.obligation_consideration import (
        build_obligation_accounting,
    )

    return _invoke(build_obligation_accounting, **kwargs)


def _default_realize(**kwargs: Any) -> Any:
    """Derive exact scenario realization without changing ICA accounting."""
    from asago_scenario_generator.pipeline.scenario_realization import (
        build_scenario_realization_assessment,
    )

    return _invoke(build_scenario_realization_assessment, **kwargs)


# ---------------------------------------------------------------------------
# Generic typed/duck-typed helpers
# ---------------------------------------------------------------------------


def _invoke(fn: Callable[..., Any] | None, **kwargs: Any) -> Any:
    """Call an adapter with only the keyword arguments it accepts."""
    if fn is None:
        return None
    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(**kwargs)
    parameters = signature.parameters
    if any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    ):
        return fn(**kwargs)
    accepted = {
        name: value
        for name, value in kwargs.items()
        if name in parameters
        and parameters[name].kind
        in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    }
    return fn(**accepted)


def _find_callable(module: Any, *names: str) -> Callable[..., Any] | None:
    return next(
        (value for name in names if callable(value := getattr(module, name, None))),
        None,
    )


def _first_attr(value: Any, *names: str) -> Any:
    if value is None:
        return None
    for name in names:
        if isinstance(value, Mapping) and name in value:
            return value[name]
        result = getattr(value, name, None)
        if result is not None:
            return result
    return None


def _plan_rows(plan: Any) -> tuple[Any, ...]:
    value = _first_attr(plan, "obligations")
    return tuple(value or ())


def _applicable_ids(plan: Any) -> set[str]:
    return {
        getattr(row, "obligation_id")
        for row in _plan_rows(plan)
        if getattr(row, "scope_disposition", None) == "applicable"
    }


def _brief_obligation_id(brief: Any) -> str | None:
    return _first_attr(brief, "obligation_id")


def _route_obligation_id(route: Any) -> str | None:
    return _first_attr(route, "obligation_id")


def _route_disposition(route: Any) -> str:
    return str(_first_attr(route, "disposition") or "unresolved")


def _route_is_gap(route: Any) -> bool:
    return _route_disposition(route) == "upstream_gap"


def _revision_status(value: Any) -> str:
    """Read status from either the bounded outcome or its nested revision."""
    status = _first_attr(value, "status")
    if status is None:
        nested = _first_attr(value, "revision")
        status = _first_attr(nested, "status")
    return str(status or "technical_failure")


def _ensure_route_universe(routes: tuple[Any, ...], applicable: set[str]) -> None:
    actual = [_route_obligation_id(route) for route in routes]
    if set(actual) != applicable or len(actual) != len(set(actual)):
        missing = sorted(applicable - set(actual))
        extra = sorted(set(actual) - applicable)
        raise ValueError(
            "final obligation route universe does not match Phase 1: "
            f"missing={missing} extra={extra}"
        )


def _close_consideration_artifact(
    *,
    plan: Any,
    briefs: tuple[Any, ...],
    initial: Any,
    recheck: Any | None,
    final_routes: tuple[Any, ...],
    revision: Any,
    baseline_loss: Any,
    baseline_control: Any,
    final_loss: Any,
    final_control: Any,
) -> Any:
    """Close the real routing passes into the shared consideration model.

    The routing and revision workers deliberately return provider-local run
    envelopes.  Accounting accepts only the durable
    ``ObligationConsideration`` contract, so the composition root performs
    this conversion once after the final route universe is known.
    """
    from asago_scenario_generator.pipeline.obligation_consideration import (
        build_consideration_artifact,
    )

    initial_routes = _typed_consideration_routes(briefs, initial, final_routes)
    revision_record = _closed_revision(
        revision,
        plan=plan,
        baseline_loss=baseline_loss,
        baseline_control=baseline_control,
        final_loss=final_loss,
        final_control=final_control,
    )
    diagnostics = _consideration_diagnostics(briefs, initial, recheck)
    rechecked = final_routes if revision_record.status == "applied" else ()
    return build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=initial_routes,
        final_routes=final_routes,
        revision=revision_record,
        rechecked_routes=rechecked,
        diagnostics=diagnostics,
    )


def _typed_consideration_routes(
    briefs: tuple[Any, ...],
    initial: Any,
    final_routes: tuple[Any, ...],
) -> tuple[Any, ...]:
    """Require typed briefs and routes; return the initial routes as a tuple."""
    from asago_scenario_generator.models.obligation_consideration import (
        NeutralObligationBrief,
        ObligationRoute,
    )

    if any(not isinstance(item, NeutralObligationBrief) for item in briefs):
        raise TypeError("typed Phase 1 plans require typed neutral obligation briefs")
    initial_routes = tuple(initial.routes)
    if any(not isinstance(item, ObligationRoute) for item in initial_routes):
        raise TypeError("typed Phase 1 plans require typed initial obligation routes")
    if any(not isinstance(item, ObligationRoute) for item in final_routes):
        raise TypeError("typed Phase 1 plans require typed final obligation routes")
    return initial_routes


def _consideration_diagnostics(
    briefs: tuple[Any, ...],
    initial: Any,
    recheck: Any | None,
) -> list[Any]:
    """Collect routing then recheck diagnostics as typed diagnostic records.

    An untyped detail becomes a ``<source>_diagnostic`` record that names
    every briefed obligation.
    """
    from asago_scenario_generator.models.obligation_consideration import (
        ConsiderationDiagnostic,
    )

    diagnostics: list[ConsiderationDiagnostic] = []
    for source, values in (
        ("routing", _first_attr(initial, "diagnostics") or ()),
        ("recheck", _first_attr(recheck, "diagnostics") or ()),
    ):
        for detail in values:
            if isinstance(detail, ConsiderationDiagnostic):
                diagnostics.append(detail)
            else:
                diagnostics.append(
                    ConsiderationDiagnostic(
                        code=f"{source}_diagnostic",
                        detail=str(detail),
                        obligation_ids=tuple(item.obligation_id for item in briefs),
                    )
                )
    return diagnostics


def _revision_structure_pin(
    artifact_id: str,
    schema_version: str,
    value: Any,
) -> Any:
    """Pin one mutable STPA structure at the revision boundary."""
    from asago_scenario_generator.models.canonical import compute_framed_digest
    from asago_scenario_generator.models.artifact_pin import ArtifactPin

    return ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest=compute_framed_digest(
            f"asago-scenario-generator:{artifact_id}:v1",
            value.model_dump(mode="json"),
        ),
    )


def _revision_trigger_ids(value: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Read the two identity sets required by a closed revision."""
    trigger_ids = tuple(
        str(item) for item in (_first_attr(value, "trigger_obligation_ids") or ())
    )
    trigger_gap_ids = tuple(
        str(item) for item in (_first_attr(value, "trigger_gap_ids") or ())
    )
    if not trigger_ids or not trigger_gap_ids:
        # A provider-local technical failure may not carry typed gap IDs.  It
        # cannot be represented as a closed revision without inventing
        # authority, so fail closed before accounting.
        raise ValueError("typed revision outcome is missing trigger obligation/gap IDs")
    return trigger_ids, trigger_gap_ids


def _revision_baseline_pins(
    plan: Any,
    baseline_loss: Any,
    baseline_control: Any,
) -> tuple[Any, ...]:
    """Pin Phase 1 and the pre-revision STPA structures."""
    from asago_scenario_generator.models.artifact_pin import ArtifactPin

    return (
        ArtifactPin(
            artifact_id="taxonomy-obligation-plan",
            schema_version="taxonomy-obligation-plan-v1",
            semantic_digest=plan.semantic_digest,
        ),
        _revision_structure_pin(
            "stpa-loss-analysis",
            "stpa-loss-analysis-v1",
            baseline_loss,
        ),
        _revision_structure_pin(
            "stpa-control-structure",
            "stpa-control-structure-v1",
            baseline_control,
        ),
    )


def _revision_revised_pins(
    status: str,
    delta: Any,
    final_loss: Any,
    final_control: Any,
) -> tuple[Any, ...]:
    """Return post-revision pins and enforce the applied-delta invariant."""
    if status != "applied":
        return ()
    if delta is None:
        raise ValueError("applied typed revision has no structural delta")
    return (
        _revision_structure_pin(
            "stpa-loss-analysis",
            "stpa-loss-analysis-v1",
            final_loss,
        ),
        _revision_structure_pin(
            "stpa-control-structure",
            "stpa-control-structure-v1",
            final_control,
        ),
    )


def _closed_revision(
    value: Any,
    *,
    plan: Any,
    baseline_loss: Any,
    baseline_control: Any,
    final_loss: Any,
    final_control: Any,
) -> Any:
    """Map the typed revision worker result to its durable revision record."""
    from asago_scenario_generator.models.obligation_consideration import (
        BoundedStructuralRevision,
        StructuralRevisionDelta,
    )

    if isinstance(value, BoundedStructuralRevision):
        return value
    status = _revision_status(value)
    if status == "not_required":
        return BoundedStructuralRevision()
    trigger_ids, trigger_gap_ids = _revision_trigger_ids(value)
    delta = _first_attr(value, "delta")
    if delta is not None and not isinstance(delta, StructuralRevisionDelta):
        delta = None
    call = _first_attr(value, "call_evidence")
    return BoundedStructuralRevision(
        status=status,
        baseline_pins=_revision_baseline_pins(plan, baseline_loss, baseline_control),
        trigger_obligation_ids=trigger_ids,
        trigger_gap_ids=trigger_gap_ids,
        proposed_delta=delta,
        accepted_delta=delta if status == "applied" else None,
        rejected_additions=()
        if status == "applied" or delta is None
        else tuple(delta.additions),
        revised_pins=_revision_revised_pins(
            status,
            delta,
            final_loss,
            final_control,
        ),
        call_evidence=() if call is None else (call,),
    )


def _artifact_yaml(value: Any) -> str:
    to_yaml = getattr(value, "to_yaml", None)
    if callable(to_yaml):
        text = to_yaml()
        if isinstance(text, str):
            return text
    payload = _dump(value)
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def _verify_yaml_round_trip(original: Any, path: Path) -> None:
    """Reload through a closed ``from_yaml`` hook when the artifact has one."""
    loader = getattr(type(original), "from_yaml", None)
    if callable(loader):
        loaded = loader(path.read_text(encoding="utf-8"))
        if loaded != original:
            raise ValueError(f"{path.name} failed closed-model round-trip equality")


def _manifest_candidate_outcomes(result: Any) -> list[dict[str, Any]] | None:
    """Project explicit terminal records; absence is unknown, not zero failures."""
    outcomes = _first_attr(result, "candidate_outcomes")
    if outcomes is None:
        return None
    return [
        {
            "scenario_id": item.scenario_id,
            "ica_slot_id": item.ica_slot_id,
            "ica_id": item.ica_id,
            "status": getattr(item.status, "value", item.status),
            "diagnostics": list(item.diagnostics),
        }
        for item in outcomes
    ]


def _manifest_scenario_counts(result: Any, generated: int) -> dict[str, int | None]:
    """Count candidates independently from their possibly repeated diagnostics."""
    outcomes = _manifest_candidate_outcomes(result)
    counts: dict[str, int | None] = {
        "generated": generated,
        "failed": None,
        "requested": None,
        "attempted": None,
        "skipped": None,
        "functional_test": None,
        "diagnostic_count": len(_first_attr(result, "stage_errors") or ()),
    }
    if outcomes is None:
        return counts
    failures = {"generation_failed", "rendering_failed", "publication_failed"}
    published = sum(item["status"] == "published" for item in outcomes)
    functional_test = sum(item["status"] == "functional_test" for item in outcomes)
    skipped = sum(item["status"] == "skipped" for item in outcomes)
    counts.update(
        # Once explicit terminal outcomes exist, ``published`` is the
        # authoritative adversarial yield.  An envelope can exist briefly
        # before the bundle/index publication fails, so counting envelopes
        # here would incorrectly turn a zero-publication run into a
        # successful one.  ``functional_test`` candidates are resolved
        # outcomes for the owner's information; they are neither failures
        # nor published adversarial yield.
        generated=published,
        failed=sum(item["status"] in failures for item in outcomes),
        requested=len(outcomes),
        attempted=len(outcomes) - skipped,
        skipped=skipped,
        functional_test=functional_test,
    )
    return counts


def _scenario_generation_status(
    counts: Mapping[str, int | None],
) -> tuple[SynthesisRunStatus, str]:
    """Derive a truthful product status from candidate lifecycle counts."""
    requested = counts.get("requested")
    attempted = counts.get("attempted")
    generated = counts.get("generated")
    functional_test = counts.get("functional_test") or 0
    if None in (requested, attempted, generated):
        return (
            SynthesisRunStatus.UNKNOWN,
            "candidate_outcomes_unavailable",
        )
    resolved = (generated or 0) + functional_test
    choices = (
        (
            requested == 0,
            (SynthesisRunStatus.NO_CANDIDATES, "no_eligible_candidates"),
        ),
        (
            attempted > 0 and generated == 0 and functional_test == 0,
            (SynthesisRunStatus.FAILED, "zero_yield_after_attempts"),
        ),
        (
            resolved == requested and attempted == requested,
            (
                SynthesisRunStatus.COMPLETED,
                "all_requested_candidates_resolved",
            ),
        ),
        (
            (generated or 0) > 0,
            (SynthesisRunStatus.DEGRADED, "partial_candidate_yield"),
        ),
    )
    return next(
        (outcome for condition, outcome in choices if condition),
        (
            SynthesisRunStatus.DEGRADED,
            "requested_candidates_not_attempted",
        ),
    )


def _dump(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _dump(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_dump(item) for item in value]
    return _dump_object(value)


def _dump_object(value: Any) -> Any:
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return _dump(model_dump(mode="json"))
        except TypeError:
            return _dump(model_dump())
    if hasattr(value, "__dict__"):
        return {
            key: _dump(item)
            for key, item in vars(value).items()
            if not key.startswith("_") and not callable(item)
        }
    return str(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _dump(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _digest_value(value: Any) -> str:
    return compute_framed_digest(_MANIFEST_VALUE_DOMAIN, _dump(value))


def _digest_payload(domain: str, value: Any) -> str:
    return compute_framed_digest(domain, _dump(value))


def _semantic_digest(value: Any) -> str | None:
    if value is None:
        return None
    declared = _first_attr(value, "semantic_digest")
    if isinstance(declared, str) and declared:
        return declared
    return _digest_value(value)


def _summary_dict(summary: Any) -> dict[str, int]:
    if summary is None:
        return {}
    values = _dump(summary)
    if not isinstance(values, Mapping):
        return {}
    return {
        str(key): int(value)
        for key, value in values.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }


def _obligation_stop_reason_counts(accounting: Any, realization: Any) -> dict[str, int]:
    """Count exactly one terminal reason for each applicable accounting row."""
    realization_reasons = _realization_reasons_by_obligation(realization)
    reasons = (
        _accounting_terminal_reason(row, realization_reasons)
        for row in tuple(_first_attr(accounting, "rows") or ())
    )
    counts: dict[str, int] = {}
    for reason in reasons:
        if reason is not None:
            counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))


def _realization_reasons_by_obligation(realization: Any) -> dict[str, set[str]]:
    """Index exact realization outcomes by obligation identity."""
    realization_reasons: dict[str, set[str]] = {}
    for record in tuple(_first_attr(realization, "records") or ()):
        item = _realization_reason(record)
        if item is not None:
            obligation_id, reason = item
            realization_reasons.setdefault(obligation_id, set()).add(reason)
    return realization_reasons


def _realization_reason(record: Any) -> tuple[str, str] | None:
    """Return one complete obligation/reason pair or no index entry."""
    obligation_id = str(_first_attr(record, "obligation_id") or "")
    reason = _first_attr(record, "stop_reason")
    if not obligation_id or reason is None:
        return None
    return obligation_id, str(reason)


def _accounting_terminal_reason(
    row: Any, realization_reasons: Mapping[str, set[str]]
) -> str | None:
    """Prefer later scenario evidence over the earlier addressed marker."""
    obligation_id = str(_first_attr(row, "obligation_id") or "")
    reasons = realization_reasons.get(obligation_id, set())
    for reason in (
        "scenario_realized",
        "scenario_generation_failure",
        "scenario_not_requested",
    ):
        if reason in reasons:
            return reason
    value = _first_attr(row, "stop_reason")
    return str(value) if value is not None else None


def _obligation_resolution_funnel(
    *, plan: Any, accounting: Any, realization: Any, scenario_count: int
) -> dict[str, Any]:
    """Expose full and survivor denominators with exact reconciliation."""
    rows = tuple(_first_attr(accounting, "rows") or ())
    reasons = _obligation_stop_reason_counts(accounting, realization)
    applicable = _count_rows_with_value(rows, "stop_reason")
    realized_obligations = _realized_obligation_count(realization)
    return {
        "all_plan_rows": len(_plan_rows(plan)),
        "governance_only": _count_rows_with_value(
            rows, "disposition", "governance_only"
        ),
        "capability_excluded": _count_rows_with_value(
            rows, "disposition", "capability_excluded"
        ),
        "applicable_and_considered": applicable,
        "terminal_reasons": reasons,
        "terminal_reason_total": sum(reasons.values()),
        "reconciles": sum(reasons.values()) == applicable,
        "realized_obligation_denominator": realized_obligations,
        "admitted_scenario_denominator": scenario_count,
    }


def _count_rows_with_value(
    rows: tuple[Any, ...], field: str, expected: str | None = None
) -> int:
    """Count present fields or fields equal to one exact value."""
    values = (_first_attr(row, field) for row in rows)
    if expected is None:
        return sum(value is not None for value in values)
    return sum(value == expected for value in values)


def _realized_obligation_count(realization: Any) -> int:
    """Count distinct obligations with at least one admitted scenario."""
    records = tuple(_first_attr(realization, "records") or ())
    return len(
        {
            str(_first_attr(record, "obligation_id"))
            for record in records
            if _first_attr(record, "stop_reason") == "scenario_realized"
        }
    )


def _ica_considerations(value: Any) -> tuple[Any, ...]:
    """Expose exact obligation/slot evidence from the final ICA result."""
    result = _first_attr(value, "considerations")
    values = tuple(result or ())
    verification = _first_attr(value, "ica_hazard_verification")
    if verification is None or not values:
        return values
    from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
        filter_ica_considerations,
    )

    return filter_ica_considerations(
        values,
        verification,
        enumeration=_first_attr(value, "ica_enumeration"),
    )


def _fact_items(value: Any) -> tuple[Any, ...]:
    """Extract explicit fact records from typed or serialized input."""
    if value is None:
        return ()
    if isinstance(value, CapabilityFactSnapshot):
        return tuple(value.facts)
    raw = _dump(value)
    if isinstance(raw, Mapping):
        raw = raw.get("facts", ())
    if isinstance(raw, Mapping):
        raw = tuple(raw.values())
    return tuple(raw) if isinstance(raw, (list, tuple)) else ()


def _coerce_evaluated_fact(item: Any) -> Any | None:
    """Convert one profile fact mapping to conservative evidence."""
    if not isinstance(item, Mapping):
        return None
    from asago_scenario_generator.models.attack_pattern_contracts import (
        EvaluatedFactEvidence,
    )

    status = item.get("status", "unknown")
    if status == "contradictory":
        status = "unknown"
    try:
        return EvaluatedFactEvidence.model_validate(
            {"fact": item["fact"], "status": status, "value": item.get("value")}
        )
    except Exception:
        # The typed Phase 1 adapter reports malformed evidence.  The
        # profile-only path remains conservative instead of raising.
        return None


def _evaluated_facts(value: Any) -> tuple[Any, ...]:
    """Adapt explicit qualification values to snapshot evidence models."""
    return tuple(
        fact
        for item in _fact_items(value)
        if (fact := _coerce_evaluated_fact(item)) is not None
    )


__all__ = [
    "ACCOUNTING_FILENAME",
    "CONSIDERATION_FILENAME",
    "MANIFEST_FILENAME",
    "PLAN_FILENAME",
    "REPORT_FILENAME",
    "SCENARIO_REALIZATION_FILENAME",
    "SynthesisAdapters",
    "SynthesisInputs",
    "SynthesisRunStatus",
    "SynthesisResult",
    "run_synthesis",
]

"""Request, stage adapters, and result of one synthesis run."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, fields, replace
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, NamedTuple

from asago_scenario_generator.pipeline.model_runtime import ModelRuntime
from asago_scenario_generator.pipeline.obligation_contracts import (
    QualificationFactsInput,
    RiskCardInput,
)
from asago_scenario_generator.pipeline.synthesis_values import _dump
from asago_scenario_generator.stpa.infra.provider_record import ReplayFill
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.observation_contract import (
    ObservationContract,
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)


PLAN_FILENAME = "taxonomy-obligation-plan.yaml"


CONSIDERATION_FILENAME = "obligation-consideration.yaml"


ACCOUNTING_FILENAME = "obligation-accounting.yaml"


SCENARIO_REALIZATION_FILENAME = "scenario-realization.yaml"


MANIFEST_FILENAME = "synthesis-manifest.yaml"


REPORT_FILENAME = "synthesis-report.html"


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
    sssom_path: Path | None = None
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
    # With replay_calls_dir, send the requests that record lacks live instead of
    # ending the run in a replay miss, within a live-request budget.
    replay_fill: ReplayFill | None = None

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


class StageRun(NamedTuple):
    """One stage's value with the errors and call records it produced.

    ``calls`` names each stage call in call order (the manifest's stage call
    counts); ``diagnostics`` holds nonfatal stage errors, which the run
    reports in the manifest and the result.
    """

    value: Any
    diagnostics: tuple[str, ...] = ()
    calls: tuple[str, ...] = ()


@dataclass(frozen=True)
class SynthesisAdapters:
    """Dependency-injection ports for :func:`run_synthesis`.

    Every field is optional so the production defaults can be selected lazily,
    while tests can provide a completely deterministic object.  The
    ``from_object`` constructor reads each port from the callable attribute
    of the same name.  The stage runners in ``synthesis_baseline``,
    ``synthesis_consideration``, ``synthesis_governance``, and
    ``synthesis_scenarios`` call each port with keyword arguments only and
    name the arguments it receives.

    ``enrich_actions`` may return ``None``, which means the target gave
    nothing to enrich.  The default ``target_realize`` needs the enrichment
    rows for an observed profile and raises ``ValueError`` when it receives
    ``None`` there, so an adapter set that replaces ``enrich_actions`` must
    return rows whenever it keeps the default ``target_realize``.
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
    govern: Callable[..., Any] | None = None
    obligation_adapter: Any | None = None
    persist_target_realization: Callable[..., Any] | None = None
    model_runtime: ModelRuntime | None = None

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
        """Expose the ordinary scenario envelopes."""
        return tuple(self.scenario_result.scenario_envelopes)

    @property
    def run_status(self) -> str:
        """Return the stable terminal product status from the manifest."""
        value = self.manifest.get("run_status")
        return str(value or SynthesisRunStatus.UNKNOWN.value)

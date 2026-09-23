"""Bounded live dispatch for one verified frozen artifact package.

This module owns the downstream boundary only. Package verification, frozen
execution, evidence adaptation, detector execution, receipt writing, and
identity-checked cleanup remain in their existing modules. The injected
generation callable is the sole transport edge.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlparse

from artifact_package_runtime import (
    ArtifactPackage,
    ArtifactPackageError,
    load_artifact_package,
)
from frozen_runtime import (
    FrozenExecutionStatus,
    _base_receipt,
    _write_receipt,
    execute_frozen_package,
)
from runtime_bindings import BindingError, select_value

SAFE_GATEWAY_PORT = 8321
SAFE_KLARNA_PORT = 8888
SAFE_AIRBNB_PORT = 8890
SAFE_OCCIAI_PORT = 8892
A03_SCENARIO_ID = "A03"
G07_SCENARIO_ID = "G07"
O03_SCENARIO_ID = "O03"
O04_SCENARIO_ID = "O04"
SCN030_SCENARIO_ID = "SCN-030"
MAX_READ_ONLY_PREREQUISITES = 4
SOCKET_READINESS_TIMEOUT = 90.0

# The documented MiniOcciAI read operations (execution-target-profile). O03
# admits these as additional setup steps beside its one draft-creation setup.
OCCIAI_READ_SETUPS = frozenset(
    {
        "ask_clinical_question",
        "get_education",
        "get_occiai_state_summary",
        "get_referral",
    }
)


class PreGenerationMismatch(RuntimeError):
    """Raised when setup, binding, or request evidence disagrees pre-generation.

    The live dispatch raises this instead of invoking the generation transport
    so a package whose captured setup results, resolved bindings, and rendered
    request disagree on the intended record never reaches generation.
    """


@dataclass(frozen=True)
class _LiveRoutePolicy:
    scenario_id: str
    target_domain: str
    target_port: int
    gateway_port: int
    lifecycle_service: str
    max_semantic_judge: int
    observation_level: str
    # Route-owned setup permissions. ``creation_setups`` names the only
    # state-creating setup operations the route permits (at most one per
    # case). ``allowed_read_setups`` is None for the generic read-only
    # policy, or the explicit read allowlist for stricter routes.
    creation_setups: frozenset[str] = frozenset()
    allowed_read_setups: frozenset[str] | None = None
    # Route-owned observation and reporting identity fields.
    observed_operation: str = "modify_booking"
    record_arguments: tuple[str, ...] = ("record_id",)
    reporting_fields: tuple[tuple[str, str], ...] = ()


_A03_ROUTE = _LiveRoutePolicy(
    scenario_id=A03_SCENARIO_ID,
    target_domain="airbnb",
    target_port=SAFE_AIRBNB_PORT,
    gateway_port=SAFE_GATEWAY_PORT,
    lifecycle_service="airbnb",
    max_semantic_judge=0,
    observation_level="command_attempt",
    observed_operation="modify_booking",
    record_arguments=("reservation_id", "booking_id", "record_id"),
    reporting_fields=(("reservation_dates_changed", "not_observed"),),
)
_G07_ROUTE = _LiveRoutePolicy(
    scenario_id=G07_SCENARIO_ID,
    target_domain="klarna",
    target_port=SAFE_KLARNA_PORT,
    gateway_port=SAFE_GATEWAY_PORT,
    lifecycle_service="klarna",
    max_semantic_judge=0,
    observation_level="command_attempt",
    observed_operation="process_refund",
    record_arguments=("order_id", "refund_id", "record_id"),
)
_O03_ROUTE = _LiveRoutePolicy(
    scenario_id=O03_SCENARIO_ID,
    target_domain="occiai",
    target_port=SAFE_OCCIAI_PORT,
    gateway_port=SAFE_GATEWAY_PORT,
    lifecycle_service="occiai",
    max_semantic_judge=0,
    observation_level="command_attempt",
    creation_setups=frozenset({"summarize_for_ehr"}),
    allowed_read_setups=OCCIAI_READ_SETUPS,
    observed_operation="commit_to_ehr",
    record_arguments=("draft_id", "patient_id", "record_id"),
)
_O04_ROUTE = _LiveRoutePolicy(
    scenario_id=O04_SCENARIO_ID,
    target_domain="occiai",
    target_port=SAFE_OCCIAI_PORT,
    gateway_port=SAFE_GATEWAY_PORT,
    lifecycle_service="occiai",
    max_semantic_judge=1,
    observation_level="reply",
    observed_operation="commit_to_ehr",
    record_arguments=("draft_id", "patient_id", "record_id"),
)
_SCN030_ROUTE = _LiveRoutePolicy(
    scenario_id=SCN030_SCENARIO_ID,
    target_domain="klarna",
    target_port=SAFE_KLARNA_PORT,
    gateway_port=SAFE_GATEWAY_PORT,
    lifecycle_service="klarna",
    max_semantic_judge=0,
    observation_level="command_attempt",
    observed_operation="process_refund",
    record_arguments=("order_id", "refund_id", "record_id"),
)


class FrozenLiveDispatchStatus(StrEnum):
    """Terminal status of the bounded downstream adapter."""

    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


@dataclass(frozen=True)
class FrozenLiveDispatch:
    """Receipt and terminal status for one bounded live dispatch."""

    status: FrozenLiveDispatchStatus
    receipt: dict[str, Any]
    incomplete_reason: str | None = None


class SafeLifecycle(Protocol):
    """The small lifecycle seam used by the adapter and its offline tests."""

    def start(self, service: str, port: int) -> dict[str, Any]:
        """Start one allowlisted service and return its captured identity."""

    def verify(self, service: str, port: int) -> dict[str, Any]:
        """Verify one started service and its persisted identity."""

    def wait_for_readiness(self, service: str, port: int) -> None:
        """Wait until one verified service accepts socket connections."""

    def cleanup(self, identities: list[dict[str, Any]]) -> dict[str, Any]:
        """Stop only the captured identities that still match."""


class SafeOnlyLifecycle:
    """Production lifecycle facade over the existing safe-only primitives."""

    def __init__(
        self,
        *,
        state_dir: Path,
        target_root: Path,
        gateway_config_source: Path,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.target_root = Path(target_root)
        self.gateway_config_source = Path(gateway_config_source)
        self.environment = dict(environment or {})
        self._services: dict[tuple[str, int], Any] = {}

    def _service(self, service: str, port: int) -> Any:
        from safe_lifecycle import safe_gateway_service, safe_target_service

        key = (service, port)
        if key in self._services:
            return self._services[key]
        if service == "gateway":
            if port != SAFE_GATEWAY_PORT:
                raise ValueError(f"gateway is not allowed on port {port}")
            value = safe_gateway_service(
                gateway_config=self.state_dir / "gateway-safe.yaml",
                port=port,
                target_root=self.target_root,
            )
        elif service in {"klarna", "airbnb", "occiai"}:
            expected_port = {
                "klarna": SAFE_KLARNA_PORT,
                "airbnb": SAFE_AIRBNB_PORT,
                "occiai": SAFE_OCCIAI_PORT,
            }[service]
            if port != expected_port:
                raise ValueError(f"{service} is not allowed on port {port}")
            value = safe_target_service(
                service,
                port=port,
                target_root=self.target_root,
            )
        else:
            raise ValueError(
                f"service is outside the live route allowlist: {service!r}"
            )
        self._services[key] = value
        return value

    def start(self, service: str, port: int) -> dict[str, Any]:
        from safe_lifecycle import (
            build_safe_gateway_config,
            start_safe_service,
        )

        definition = self._service(service, port)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        environment = self.environment if service == "gateway" else {}
        if service == "gateway":
            build_safe_gateway_config(
                self.gateway_config_source,
                self.state_dir / "gateway-safe.yaml",
            )
        return start_safe_service(
            definition,
            state_dir=self.state_dir,
            environment=environment,
        )

    def verify(self, service: str, port: int) -> dict[str, Any]:
        from safe_lifecycle import verify_persisted_identity

        definition = self._service(service, port)
        result = verify_persisted_identity(definition, state_dir=self.state_dir)
        if result.get("status") != "verified":
            raise RuntimeError(f"safe identity verification failed for {service}")
        return result

    def wait_for_readiness(self, service: str, port: int) -> None:
        from run_recipe import _safe_port_probe, wait_for_ports
        from safe_lifecycle import verify_persisted_identity

        definition = self._service(service, port)

        def probe(candidate_port: int) -> bool:
            identity = verify_persisted_identity(
                definition,
                state_dir=self.state_dir,
            )
            if identity.get("status") != "verified":
                raise RuntimeError(
                    f"safe identity verification failed for {service} "
                    "before socket readiness"
                )
            return _safe_port_probe(candidate_port)

        wait_for_ports(
            (port,),
            timeout=SOCKET_READINESS_TIMEOUT,
            probe=probe,
        )

    def cleanup(self, identities: list[dict[str, Any]]) -> dict[str, Any]:
        from safe_lifecycle import cleanup_captured_identities

        if not identities:
            return {"status": "not_requested", "identities": []}
        result = cleanup_captured_identities(
            identities,
            current_identity=_current_identity_or_none,
        )
        result["status"] = "completed" if result.get("complete") else "failed"
        result["identities"] = list(identities)
        return result


def execute_frozen_live_package(
    package: str | Path | ArtifactPackage,
    *,
    lifecycle: SafeLifecycle | None = None,
    setup_dispatch: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    generation_dispatch: Callable[..., dict[str, Any]] | None = None,
    detector_runner: Callable[[dict[str, Any], ArtifactPackage], Any] | None = None,
    judge_client: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    receipt_path: str | Path | None = None,
    target_domain: str = "airbnb",
    target_port: int = SAFE_AIRBNB_PORT,
    gateway_port: int = SAFE_GATEWAY_PORT,
    expected_scenario_id: str = A03_SCENARIO_ID,
    state_dir: str | Path | None = None,
    target_root: str | Path = "/Users/hjrnunes/workspace/hjrnunes/mini-agents",
    gateway_config_source: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
    target_url: str | None = None,
    model_url: str | None = None,
    model: str | None = None,
    discovery_records: list[dict[str, Any]] | None = None,
    service_revisions: dict[str, Any] | None = None,
    port_probes: dict[int, bool] | None = None,
) -> FrozenLiveDispatch:
    """Execute one immutable package against a closed safe live route.

    The adapter performs all package and target checks before constructing or
    starting the lifecycle. A03, O03, and SCN-030 keep their zero-judge
    policies; O04 uses the MiniOcciAI route and can dispatch one
    package-declared semantic judge. The same lifecycle environment stays
    alive from setup through generation; the adapter never restarts or resets
    it between setup captures and the generation dispatch.
    """

    route = _route_policy(expected_scenario_id)
    if route is None:
        receipt = _failure_receipt(
            None,
            reason="scenario_not_allowed",
            discovery_records=discovery_records,
            target_domain=target_domain,
            target_port=target_port,
            gateway_port=gateway_port,
            max_semantic_judge=0,
        )
        _write_receipt(receipt_path, receipt)
        return FrozenLiveDispatch(
            FrozenLiveDispatchStatus.FAILED,
            receipt,
            "scenario_not_allowed",
        )
    loaded, failure = _load_and_validate_package(
        package,
        route=route,
        target_domain=target_domain,
        target_port=target_port,
        gateway_port=gateway_port,
    )
    if loaded is None or failure is not None:
        receipt = _failure_receipt(
            loaded,
            reason=failure or "package_invalid",
            discovery_records=discovery_records,
            target_domain=target_domain,
            target_port=target_port,
            gateway_port=gateway_port,
            max_semantic_judge=route.max_semantic_judge,
        )
        _write_receipt(receipt_path, receipt)
        return FrozenLiveDispatch(
            FrozenLiveDispatchStatus.FAILED,
            receipt,
            failure or "package_invalid",
        )
    endpoint_failure = _validate_endpoints(
        target_url=target_url,
        model_url=model_url,
        target_port=target_port,
        gateway_port=gateway_port,
    )
    if endpoint_failure is not None:
        receipt = _failure_receipt(
            loaded,
            reason=endpoint_failure,
            discovery_records=discovery_records,
            target_domain=target_domain,
            target_port=target_port,
            gateway_port=gateway_port,
            max_semantic_judge=route.max_semantic_judge,
        )
        _write_receipt(receipt_path, receipt)
        return FrozenLiveDispatch(
            FrozenLiveDispatchStatus.FAILED,
            receipt,
            endpoint_failure,
        )

    setup, setup_failure = _validate_setup_permissions(loaded, route=route)
    if setup_failure is not None:
        receipt = _failure_receipt(
            loaded,
            reason=setup_failure,
            discovery_records=discovery_records,
            target_domain=target_domain,
            target_port=target_port,
            gateway_port=gateway_port,
            max_semantic_judge=route.max_semantic_judge,
        )
        receipt["live_dispatch"]["declared_setup"] = setup
        _write_receipt(receipt_path, receipt)
        return FrozenLiveDispatch(
            FrozenLiveDispatchStatus.FAILED,
            receipt,
            setup_failure,
        )

    active_lifecycle = lifecycle or SafeOnlyLifecycle(
        state_dir=Path(
            state_dir
            or f"build/qualification/runtime/{expected_scenario_id.lower()}-live-dispatch"
        ),
        target_root=Path(target_root),
        gateway_config_source=Path(
            gateway_config_source or Path(target_root) / "ogx-config.yaml"
        ),
        environment=environment,
    )
    identities: list[dict[str, Any]] = []
    service_starts: list[dict[str, Any]] = []
    service_verifications: list[dict[str, Any]] = []
    cleanup_called = False
    cleanup_result: dict[str, Any] | None = None
    generation_calls = 0
    setup_calls = 0
    judge_calls = 0
    setup_results: dict[str, dict[str, Any]] = {}
    live_dispatch = _live_dispatch_record(
        loaded,
        route=route,
        target_domain=target_domain,
        target_port=target_port,
        gateway_port=gateway_port,
        declared_setup=setup,
        max_semantic_judge=route.max_semantic_judge,
    )

    def cleanup_captured(captured: list[dict[str, Any]]) -> dict[str, Any]:
        nonlocal cleanup_called, cleanup_result
        cleanup_called = True
        try:
            cleanup_result = active_lifecycle.cleanup(list(captured))
        except Exception as exc:  # pragma: no cover - lifecycle boundary
            cleanup_result = {
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "identities": list(captured),
            }
        return cleanup_result

    def bounded_setup(operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        nonlocal setup_calls
        setup_calls += 1
        if setup_calls > MAX_READ_ONLY_PREREQUISITES:
            raise RuntimeError("read-only prerequisite limit exceeded")
        if setup_dispatch is None:
            raise RuntimeError("read-only prerequisite dispatch unavailable")
        result = setup_dispatch(operation, arguments)
        if isinstance(result, dict):
            setup_results[operation] = result
        return result

    def bounded_generation(**kwargs: Any) -> dict[str, Any]:
        nonlocal generation_calls
        mismatch = _pre_generation_mismatch(
            loaded.json_member("bindings.json", default=[]),
            declared_setup=setup,
            bindings=kwargs.get("bindings"),
            stimulus=kwargs.get("stimulus"),
            setup_results=setup_results,
        )
        if mismatch is not None:
            live_dispatch["pre_generation_mismatch"] = mismatch
            raise PreGenerationMismatch(mismatch)
        generation_calls += 1
        if generation_calls > 1:
            raise RuntimeError("generation limit exceeded")
        if generation_dispatch is None:
            raise RuntimeError("generation dispatch unavailable")
        enriched = dict(kwargs)
        enriched.update(
            {
                "target_domain": target_domain,
                "target_port": target_port,
                "gateway_port": gateway_port,
                "target_url": target_url or f"http://127.0.0.1:{target_port}/sse",
                "model_url": model_url or f"http://127.0.0.1:{gateway_port}/v1/",
                "model": model,
            }
        )
        response = generation_dispatch(**enriched)
        if isinstance(response, dict):
            return response
        raw = getattr(response, "raw", None)
        if isinstance(raw, dict):
            return raw
        raise TypeError("generation dispatch must return a native evidence object")

    def bounded_judge(request: dict[str, Any]) -> dict[str, Any]:
        nonlocal judge_calls
        judge_calls += 1
        if judge_calls > route.max_semantic_judge:
            raise RuntimeError("semantic judge limit exceeded")
        if judge_client is None:
            raise RuntimeError("semantic judge dispatch unavailable")
        response = judge_client(request)
        if not isinstance(response, dict):
            raise TypeError("semantic judge dispatch must return an object")
        return response

    try:
        for service, port in (
            ("gateway", gateway_port),
            (route.lifecycle_service, target_port),
        ):
            started = active_lifecycle.start(service, port)
            _require_captured_identity(started, service, port)
            identities.append(started)
            service_starts.append(_safe_record(started))
            verified = active_lifecycle.verify(service, port)
            _require_verified_service(verified, service, port)
            service_verifications.append(_safe_record(verified))
            active_lifecycle.wait_for_readiness(service, port)
        live_dispatch["service_starts"] = service_starts
        live_dispatch["service_verifications"] = service_verifications
        execution = execute_frozen_package(
            loaded,
            setup_dispatch=bounded_setup,
            generation_dispatch=bounded_generation,
            detector_runner=detector_runner,
            judge_client=bounded_judge if route.max_semantic_judge else None,
            discovery_records=discovery_records,
            receipt_path=receipt_path,
            service_identities=identities,
            cleanup=cleanup_captured,
            service_revisions=service_revisions,
            port_probes=port_probes,
        )
    except Exception as exc:  # pragma: no cover - lifecycle boundary
        execution = None
        receipt = _failure_receipt(
            loaded,
            reason="lifecycle_failed",
            discovery_records=discovery_records,
            target_domain=target_domain,
            target_port=target_port,
            gateway_port=gateway_port,
            max_semantic_judge=route.max_semantic_judge,
        )
        receipt["runtime_failure"] = f"{type(exc).__name__}: {exc}"
    finally:
        if identities and not cleanup_called:
            try:
                cleanup_result = active_lifecycle.cleanup(list(identities))
                cleanup_called = True
            except Exception as exc:  # pragma: no cover - lifecycle boundary
                cleanup_result = {
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                    "identities": list(identities),
                }

    if execution is not None:
        receipt = execution.receipt
        status = _map_execution_status(execution.status)
        reason = execution.incomplete_reason or (
            receipt.get("runtime_failure")
            if status is FrozenLiveDispatchStatus.FAILED
            else None
        )
        pre_generation_mismatch = live_dispatch.get("pre_generation_mismatch")
        if pre_generation_mismatch is not None:
            receipt["incomplete_reason"] = pre_generation_mismatch
            if status is FrozenLiveDispatchStatus.FAILED:
                reason = pre_generation_mismatch
    else:
        status = FrozenLiveDispatchStatus.FAILED
        reason = receipt.get("incomplete_reason", "lifecycle_failed")
    receipt["live_dispatch"] = live_dispatch
    live_dispatch["service_starts"] = service_starts
    live_dispatch["service_verifications"] = service_verifications
    live_dispatch["cleanup"] = cleanup_result or receipt.get(
        "cleanup", {"status": "not_requested", "identities": []}
    )
    if cleanup_result is not None:
        receipt["cleanup"] = cleanup_result
        if (
            status is FrozenLiveDispatchStatus.COMPLETED
            and cleanup_result.get("status") != "completed"
        ):
            status = FrozenLiveDispatchStatus.FAILED
            reason = "cleanup_failed"
            receipt["status"] = FrozenLiveDispatchStatus.FAILED.value
            receipt["runtime_failure"] = "cleanup_failed"
    live_dispatch["limits"]["setup_capture"] = setup_calls
    live_dispatch["limits"]["generation"] = generation_calls
    live_dispatch["limits"]["semantic_judge"] = judge_calls
    if route.observation_level == "reply":
        _attach_reply_observation(receipt)
    else:
        _attach_attempt_observation(receipt, route=route)
    if receipt_path is not None:
        _write_receipt(receipt_path, receipt)
    return FrozenLiveDispatch(status, receipt, reason)


def execute_o04_frozen_live_package(
    package: str | Path | ArtifactPackage,
    **kwargs: Any,
) -> FrozenLiveDispatch:
    """Execute one verified O04 package on the closed MiniOcciAI route."""

    kwargs["expected_scenario_id"] = O04_SCENARIO_ID
    kwargs["target_domain"] = "occiai"
    kwargs["target_port"] = SAFE_OCCIAI_PORT
    kwargs["gateway_port"] = SAFE_GATEWAY_PORT
    return execute_frozen_live_package(package, **kwargs)


def execute_g07_frozen_live_package(
    package: str | Path | ArtifactPackage,
    **kwargs: Any,
) -> FrozenLiveDispatch:
    """Execute one verified G07 package on the closed MiniKlarna route.

    The route dispatches zero semantic judges, keeps the read-only setup
    policy, and reports ``process_refund`` as a command attempt.
    """

    kwargs["expected_scenario_id"] = G07_SCENARIO_ID
    kwargs["target_domain"] = "klarna"
    kwargs["target_port"] = SAFE_KLARNA_PORT
    kwargs["gateway_port"] = SAFE_GATEWAY_PORT
    return execute_frozen_live_package(package, **kwargs)


def execute_o03_frozen_live_package(
    package: str | Path | ArtifactPackage,
    **kwargs: Any,
) -> FrozenLiveDispatch:
    """Execute one verified O03 package on the closed MiniOcciAI route.

    The route dispatches zero semantic judges, permits exactly one declared
    ``summarize_for_ehr`` draft-creation setup beside explicitly allowed
    reads, and reports ``commit_to_ehr`` as a command attempt.
    """

    kwargs["expected_scenario_id"] = O03_SCENARIO_ID
    kwargs["target_domain"] = "occiai"
    kwargs["target_port"] = SAFE_OCCIAI_PORT
    kwargs["gateway_port"] = SAFE_GATEWAY_PORT
    return execute_frozen_live_package(package, **kwargs)


def execute_scn030_frozen_live_package(
    package: str | Path | ArtifactPackage,
    **kwargs: Any,
) -> FrozenLiveDispatch:
    """Execute one verified SCN-030 package on the closed MiniKlarna route.

    The route dispatches zero semantic judges, keeps the read-only setup
    policy, and reports ``process_refund`` as a command attempt.
    """

    kwargs["expected_scenario_id"] = SCN030_SCENARIO_ID
    kwargs["target_domain"] = "klarna"
    kwargs["target_port"] = SAFE_KLARNA_PORT
    kwargs["gateway_port"] = SAFE_GATEWAY_PORT
    return execute_frozen_live_package(package, **kwargs)


def _load_and_validate_package(
    package: str | Path | ArtifactPackage,
    *,
    route: _LiveRoutePolicy,
    target_domain: str,
    target_port: int,
    gateway_port: int,
) -> tuple[ArtifactPackage | None, str | None]:
    try:
        if isinstance(package, ArtifactPackage):
            # Re-open the package root so callers cannot bypass the immutable
            # member and manifest checks by constructing the dataclass.
            loaded = load_artifact_package(package.root)
            if loaded.digest != package.digest or loaded.members != package.members:
                return None, "package_invalid"
        else:
            loaded = load_artifact_package(package)
    except (ArtifactPackageError, OSError, ValueError):
        return None, "package_invalid"
    try:
        loaded.detector_digest
    except ArtifactPackageError:
        return None, "package_invalid"
    if loaded.manifest.scenario_id != route.scenario_id:
        return loaded, "package_target_mismatch"
    if (
        target_domain != route.target_domain
        or target_port != route.target_port
        or gateway_port != route.gateway_port
    ):
        return loaded, "target_not_allowed"
    if not _package_is_accepted(loaded):
        return loaded, "package_not_accepted"
    try:
        metadata = [loaded.manifest.raw, loaded.manifest.runtime_capabilities]
        for name in ("plan.json", "inputs.json"):
            value = loaded.json_member(name, default={})
            if isinstance(value, dict):
                metadata.append(value)
                if isinstance(value.get("runtime_contract"), dict):
                    metadata.append(value["runtime_contract"])
    except ArtifactPackageError:
        return None, "package_invalid"
    if any(
        item.get(key) is not None and item.get(key) != expected
        for item in metadata
        for key, expected in (
            ("target_domain", target_domain),
            ("target", target_domain),
            ("domain", target_domain),
            ("target_port", target_port),
            ("gateway_port", gateway_port),
        )
    ):
        return loaded, "package_target_mismatch"
    return loaded, None


def _route_policy(scenario_id: str) -> _LiveRoutePolicy | None:
    return {
        A03_SCENARIO_ID: _A03_ROUTE,
        G07_SCENARIO_ID: _G07_ROUTE,
        O03_SCENARIO_ID: _O03_ROUTE,
        O04_SCENARIO_ID: _O04_ROUTE,
        SCN030_SCENARIO_ID: _SCN030_ROUTE,
    }.get(scenario_id)


def _package_is_accepted(package: ArtifactPackage) -> bool:
    authoring = package.manifest.authoring
    if not isinstance(authoring, dict):
        return False
    if authoring.get("status") == "accepted":
        return True
    if authoring.get("terminal_status") == "accepted":
        return True
    review_status = authoring.get("review_status")
    return (
        isinstance(review_status, dict) and review_status.get("artifact") == "accepted"
    )


def _validate_setup_permissions(
    package: ArtifactPackage,
    *,
    route: _LiveRoutePolicy,
) -> tuple[list[dict[str, Any]], str | None]:
    """Validate declared setup steps against the route-owned permissions.

    Every case runs at most four setup/read operations. A03, O04, and SCN-030
    keep the generic read-only setup policy. O03 additionally admits exactly
    one declared draft-creation setup and requires every additional setup to
    be one of its explicitly allowed read operations.
    """

    try:
        setup = package.json_member("setup.json", default=[])
        inputs = package.json_member("inputs.json", default={})
    except ArtifactPackageError:
        return [], "package_invalid"
    if not isinstance(setup, list):
        return [], "state_creating_setup"
    declared = list(item for item in setup if isinstance(item, dict))
    if len(setup) > MAX_READ_ONLY_PREREQUISITES:
        return declared, "prerequisite_limit_exceeded"
    inventory = inputs.get("inventory", {}) if isinstance(inputs, dict) else {}
    operation_map = {
        item.get("name"): item
        for item in inventory.get("operations", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    creation_setups_seen = 0
    for item in setup:
        if not isinstance(item, dict) or not isinstance(item.get("operation"), str):
            return declared, "state_creating_setup"
        name = item["operation"]
        operation = operation_map.get(name)
        if not isinstance(operation, dict):
            return declared, "state_creating_setup"
        if name in route.creation_setups:
            creation_setups_seen += 1
            if creation_setups_seen > 1:
                return declared, "excess_creation_setup"
        elif _is_read_only(operation):
            if (
                route.allowed_read_setups is not None
                and name not in route.allowed_read_setups
            ):
                return declared, "setup_not_allowed"
        elif (
            route.allowed_read_setups is not None
            and name in route.allowed_read_setups
            and _is_explicitly_non_mutating(operation)
        ):
            # Some accepted packages predate the optional read_only annotation.
            # The route-owned allowlist admits only its exact known read while
            # still rejecting mutation markers and mutating operation names.
            pass
        else:
            return declared, "state_creating_setup"
    if route.creation_setups and creation_setups_seen != 1:
        return declared, "required_creation_setup_missing"
    return declared, None


def _validate_endpoints(
    *,
    target_url: str | None,
    model_url: str | None,
    target_port: int,
    gateway_port: int,
) -> str | None:
    for _label, value, expected_port in (
        ("target_url", target_url, target_port),
        ("model_url", model_url, gateway_port),
    ):
        if value is None:
            continue
        try:
            parsed = urlparse(value)
            port = parsed.port
        except (TypeError, ValueError):
            return "target_not_allowed"
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or port != expected_port
        ):
            return "target_not_allowed"
    return None


def _pre_generation_mismatch(
    declared_bindings: Any,
    *,
    declared_setup: Any,
    bindings: Any,
    stimulus: Any,
    setup_results: dict[str, dict[str, Any]],
) -> str | None:
    """Validate setup results, bindings, and the request against one record.

    Returns a typed mismatch reason before the generation transport runs, or
    None when the captured setup results, the resolved bindings, and the
    rendered request agree on the intended record. The gate is defensive: it
    fails closed if the environment was reset between setup and generation or
    if the rendered request references a record the setup did not produce.
    """

    if isinstance(declared_setup, list):
        for step in declared_setup:
            if not isinstance(step, dict) or not isinstance(step.get("operation"), str):
                continue
            if not isinstance(setup_results.get(step["operation"]), dict):
                return f"setup_result_missing:{step['operation']}"
    if not isinstance(declared_bindings, list):
        return None
    values = bindings if isinstance(bindings, dict) else {}
    user_text = (
        stimulus.get("user_text")
        if isinstance(stimulus, dict) and isinstance(stimulus.get("user_text"), str)
        else None
    )
    for declaration in declared_bindings:
        if not isinstance(declaration, dict) or not isinstance(
            declaration.get("name"), str
        ):
            continue
        name = declaration["name"]
        if declaration.get("source_kind") == "setup_output":
            operation = str(declaration.get("source_ref", "")).partition(":")[2]
            captured = setup_results.get(operation)
            if not isinstance(captured, dict):
                return f"setup_result_missing:{operation}"
            try:
                selected = select_value(
                    {"result": captured}, str(declaration.get("selector", ""))
                )
            except BindingError:
                return f"binding_setup_missing:{name}"
            if values.get(name) != selected:
                return f"binding_setup_mismatch:{name}"
        consumers = declaration.get("consumers")
        if (
            isinstance(consumers, list)
            and "stimulus.user_text" in consumers
            and isinstance(user_text, str)
            and isinstance(values.get(name), str)
            and values[name] not in user_text
        ):
            return f"request_record_mismatch:{name}"
    return None


def _is_read_only(operation: dict[str, Any]) -> bool:
    name = operation.get("name")
    if isinstance(name, str) and any(
        token
        in {
            "create",
            "modify",
            "update",
            "delete",
            "write",
            "set",
            "process",
            "commit",
            "submit",
            "cancel",
            "book",
            "refund",
        }
        for token in name.lower().split("_")
    ):
        return False
    if operation.get("read_only") is False or operation.get("mutates_state") is True:
        return False
    if any(
        operation.get(key)
        in {
            "write",
            "mutate",
            "state_effect",
            "state_change",
            "create",
            "update",
            "delete",
        }
        for key in ("effect", "state_effect", "side_effect")
    ):
        return False
    if operation.get("read_only") is True:
        return True
    if operation.get("mutates_state") is False:
        return True
    for key in ("effect", "state_effect", "side_effect"):
        if operation.get(key) in {"read", "read_only", "observe", "none"}:
            return True
    # Older accepted package inventories do not carry a read_only annotation.
    # The mutating-name and explicit-marker checks above plus a conventional
    # read verb are the closed fallback for the generic route.
    first_token = name.lower().split("_", 1)[0]
    return first_token in {
        "ask",
        "check",
        "fetch",
        "find",
        "get",
        "inspect",
        "list",
        "lookup",
        "read",
        "retrieve",
    }


def _is_explicitly_non_mutating(operation: dict[str, Any]) -> bool:
    """Allow a route-owned read name when optional metadata is absent."""

    name = operation.get("name")
    if not isinstance(name, str):
        return False
    if any(
        token in {
            "create",
            "modify",
            "update",
            "delete",
            "write",
            "set",
            "process",
            "commit",
            "submit",
            "cancel",
            "book",
            "refund",
        }
        for token in name.lower().split("_")
    ):
        return False
    if operation.get("read_only") is False or operation.get("mutates_state") is True:
        return False
    return not any(
        operation.get(key)
        in {
            "write",
            "mutate",
            "state_effect",
            "state_change",
            "create",
            "update",
            "delete",
        }
        for key in ("effect", "state_effect", "side_effect")
    )


def _live_dispatch_record(
    package: ArtifactPackage,
    *,
    route: _LiveRoutePolicy,
    target_domain: str,
    target_port: int,
    gateway_port: int,
    declared_setup: list[dict[str, Any]],
    max_semantic_judge: int,
) -> dict[str, Any]:
    return {
        "schema": "frozen-live-dispatch-v1",
        "package": {
            "package_id": package.manifest.package_id,
            "scenario_id": package.manifest.scenario_id,
            "manifest_digest": package.digest,
            "detector_digest": package.detector_digest,
            "verified": True,
        },
        "route": {
            "scenario_id": route.scenario_id,
            "observed_operation": route.observed_operation,
            "record_arguments": list(route.record_arguments),
            "creation_setups": sorted(route.creation_setups),
            "read_setups": (
                sorted(route.allowed_read_setups)
                if route.allowed_read_setups is not None
                else None
            ),
        },
        "target": {
            "domain": target_domain,
            "target_port": target_port,
            "gateway_port": gateway_port,
        },
        "declared_setup": declared_setup,
        "service_starts": [],
        "service_verifications": [],
        "cleanup": {"status": "not_started"},
        "limits": {
            "max_setup_capture": MAX_READ_ONLY_PREREQUISITES,
            "max_generation": 1,
            "max_semantic_judge": max_semantic_judge,
            "setup_capture": 0,
            "generation": 0,
            "semantic_judge": 0,
        },
    }


def _failure_receipt(
    package: ArtifactPackage | None,
    *,
    reason: str,
    discovery_records: list[dict[str, Any]] | None,
    target_domain: str,
    target_port: int,
    gateway_port: int,
    max_semantic_judge: int = 0,
) -> dict[str, Any]:
    receipt = _base_receipt(package, discovery_records)
    receipt["status"] = FrozenLiveDispatchStatus.FAILED.value
    receipt["incomplete_reason"] = reason
    receipt["live_dispatch"] = {
        "schema": "frozen-live-dispatch-v1",
        "package": (
            {
                "package_id": package.manifest.package_id,
                "scenario_id": package.manifest.scenario_id,
                "manifest_digest": package.digest,
                "detector_digest": package.detector_digest,
                "verified": True,
            }
            if package is not None
            else {"verified": False}
        ),
        "target": {
            "domain": target_domain,
            "target_port": target_port,
            "gateway_port": gateway_port,
        },
        "service_starts": [],
        "service_verifications": [],
        "cleanup": {"status": "not_requested", "identities": []},
        "limits": {
            "max_setup_capture": MAX_READ_ONLY_PREREQUISITES,
            "max_generation": 1,
            "max_semantic_judge": max_semantic_judge,
            "setup_capture": 0,
            "generation": 0,
            "semantic_judge": 0,
        },
    }
    return receipt


def _require_captured_identity(result: Any, service: str, port: int) -> None:
    if not isinstance(result, dict) or not isinstance(result.get("pid"), int):
        raise RuntimeError(
            f"{service}:{port} did not return a captured process identity"
        )
    identity = result.get("identity")
    if (
        not isinstance(identity, dict)
        or identity.get("pid", result["pid"]) != result["pid"]
    ):
        raise RuntimeError(
            f"{service}:{port} returned an unverifiable process identity"
        )


def _require_verified_service(result: Any, service: str, port: int) -> None:
    if not isinstance(result, dict) or result.get("status") != "verified":
        raise RuntimeError(f"{service}:{port} failed safe identity verification")


def _safe_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "verified"}
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _attach_attempt_observation(
    receipt: dict[str, Any], *, route: _LiveRoutePolicy
) -> None:
    """Record the route's command attempts without replacing detector results.

    The observation preserves every actual tool call on the route's observed
    operation, including wrong-record calls, and never claims an effect or an
    outcome: the packaged detector alone decides the case result.
    """

    operation = route.observed_operation
    record_arguments = route.record_arguments
    calls = receipt.get("evidence", {}).get("tool_calls", [])
    attempts = [
        call
        for call in calls
        if isinstance(call, dict) and call.get("name") == operation
    ]

    def _record_id(arguments: Any) -> str | None:
        if not isinstance(arguments, dict):
            return None
        return next(
            (
                arguments.get(key)
                for key in record_arguments
                if arguments.get(key) is not None
            ),
            None,
        )

    record_ids: list[Any] = []
    for call in attempts:
        record_id = _record_id(call.get("decoded_arguments"))
        if record_id is not None and record_id not in record_ids:
            record_ids.append(record_id)
    observation: dict[str, Any] = {
        "claim_level": "command_attempt",
        "operation": operation,
        "record_id": _record_id(attempts[0].get("decoded_arguments"))
        if attempts
        else None,
        "record_ids": record_ids,
        "attempt_observed": bool(attempts),
        "evidence_refs": [
            f"evidence.tool_calls[{index}]"
            for index, call in enumerate(calls)
            if isinstance(call, dict) and call.get("name") == operation
        ],
        "backend_state_effect": "not_established",
        "target_effect": "not_established",
        "vulnerability_confirmed": False,
    }
    observation.update(dict(route.reporting_fields))
    receipt["observation"] = observation


def _attach_reply_observation(receipt: dict[str, Any]) -> None:
    result = receipt.get("rich_result")
    outcome = (
        result.get("outcome")
        if isinstance(result, dict)
        and result.get("claim_level") == "reply"
        and result.get("outcome") in {"detected", "not_detected", "inconclusive"}
        else "inconclusive"
    )
    reason = (
        result.get("reason")
        if isinstance(result, dict) and isinstance(result.get("reason"), str)
        else "reply evidence is unavailable or unresolved"
    )
    evidence_refs = (
        list(result.get("evidence_refs", []))
        if isinstance(result, dict) and isinstance(result.get("evidence_refs"), list)
        else []
    )
    receipt["observation"] = {
        "claim_level": "reply",
        "outcome": outcome,
        "reply_outcome": outcome,
        "reason": reason,
        "evidence_refs": evidence_refs,
        "backend_effect": "not_established",
        "target_effect": "not_established",
        "vulnerability_confirmed": False,
    }


def _map_execution_status(status: FrozenExecutionStatus) -> FrozenLiveDispatchStatus:
    if status is FrozenExecutionStatus.COMPLETED:
        return FrozenLiveDispatchStatus.COMPLETED
    if status is FrozenExecutionStatus.INCOMPLETE:
        return FrozenLiveDispatchStatus.INCOMPLETE
    return FrozenLiveDispatchStatus.FAILED


def _current_identity_or_none(pid: int) -> dict[str, Any] | None:
    from safe_lifecycle import capture_process_identity

    try:
        return capture_process_identity(pid)
    except (OSError, RuntimeError, ValueError):
        return None


__all__ = [
    "A03_SCENARIO_ID",
    "G07_SCENARIO_ID",
    "FrozenLiveDispatch",
    "FrozenLiveDispatchStatus",
    "MAX_READ_ONLY_PREREQUISITES",
    "O03_SCENARIO_ID",
    "O04_SCENARIO_ID",
    "PreGenerationMismatch",
    "SCN030_SCENARIO_ID",
    "SOCKET_READINESS_TIMEOUT",
    "SAFE_AIRBNB_PORT",
    "SAFE_GATEWAY_PORT",
    "SAFE_KLARNA_PORT",
    "SAFE_OCCIAI_PORT",
    "SafeLifecycle",
    "SafeOnlyLifecycle",
    "execute_g07_frozen_live_package",
    "execute_o03_frozen_live_package",
    "execute_o04_frozen_live_package",
    "execute_frozen_live_package",
    "execute_scn030_frozen_live_package",
]

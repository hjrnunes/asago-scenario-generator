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
SAFE_TARGET_PORTS = {
    "klarna": SAFE_KLARNA_PORT,
    "airbnb": SAFE_AIRBNB_PORT,
    "occiai": SAFE_OCCIAI_PORT,
}
LIVE_TARGETS = tuple(SAFE_TARGET_PORTS)
SUPPORTED_OBSERVATION_LEVELS = ("command_attempt", "reply")
MAX_READ_ONLY_PREREQUISITES = 4
MAX_CREATION_SETUPS = 1
MAX_SEMANTIC_JUDGE = 1
SOCKET_READINESS_TIMEOUT = 90.0


class PreGenerationMismatch(RuntimeError):
    """Raised when setup, binding, or request evidence disagrees pre-generation.

    The live dispatch raises this instead of invoking the generation transport
    so a package whose captured setup results, resolved bindings, and rendered
    request disagree on the intended record never reaches generation.
    """


class RouteDerivationError(ValueError):
    """Raised when a package cannot be given a supported live route."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class LiveTarget:
    """One allowlisted local mini-agent target and its safe ports."""

    domain: str
    target_port: int
    gateway_port: int
    lifecycle_service: str


@dataclass(frozen=True)
class LiveRoutePolicy:
    """Route for one package: target-owned ports, package-owned policy."""

    scenario_id: str
    target_domain: str
    target_port: int
    gateway_port: int
    lifecycle_service: str
    max_semantic_judge: int
    observation_level: str
    # Non-read-only inventory operations that the package runtime contract
    # lists in setup_permissions; a case may run at most one of them.
    creation_setups: frozenset[str] = frozenset()
    # Every non-read-only inventory operation; command-attempt observation
    # records calls to any of them.
    observed_operations: tuple[str, ...] = ()
    generation_tools: tuple[str, ...] = ()


def live_target(target: str) -> LiveTarget:
    """Return the safe loopback route for one allowlisted target name."""

    port = SAFE_TARGET_PORTS.get(target)
    if port is None:
        raise ValueError(
            f"target is outside the live route allowlist: {target!r} "
            f"(supported: {', '.join(LIVE_TARGETS)})"
        )
    return LiveTarget(
        domain=target,
        target_port=port,
        gateway_port=SAFE_GATEWAY_PORT,
        lifecycle_service=target,
    )


def package_runtime_contract(package: ArtifactPackage) -> dict[str, Any]:
    """Return the package runtime contract from its first declaring member."""

    plan = package.json_member("plan.json", default={})
    inputs = package.json_member("inputs.json", default={})
    for candidate in (
        inputs.get("runtime_contract") if isinstance(inputs, dict) else None,
        plan.get("runtime_contract") if isinstance(plan, dict) else None,
        package.manifest.runtime_capabilities,
    ):
        if isinstance(candidate, dict):
            return candidate
    return {}


def package_operations(package: ArtifactPackage) -> list[dict[str, Any]]:
    """Return the named inventory operations declared by the package."""

    inputs = package.json_member("inputs.json", default={})
    inventory = inputs.get("inventory", {}) if isinstance(inputs, dict) else {}
    operations = inventory.get("operations", []) if isinstance(inventory, dict) else []
    if not isinstance(operations, list):
        return []
    return [
        item
        for item in operations
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]


def package_observation_level(package: ArtifactPackage) -> str:
    """Return ``plan.json`` ``observation_claim.claim_level`` if supported."""

    plan = package.json_member("plan.json", default={})
    claim = plan.get("observation_claim") if isinstance(plan, dict) else None
    level = claim.get("claim_level") if isinstance(claim, dict) else None
    if not isinstance(level, str) or not level:
        raise RouteDerivationError("observation_level_undeclared")
    if level not in SUPPORTED_OBSERVATION_LEVELS:
        raise RouteDerivationError(f"observation_level_unsupported:{level}")
    return level


def package_semantic_judge_limit(package: ArtifactPackage) -> int:
    """Allow one judge only when the package declares a well-formed judge."""

    judge = package.json_member("judge.json")
    if judge is None:
        return 0
    if not isinstance(judge, dict) or not isinstance(judge.get("question"), str):
        raise RouteDerivationError("judge_invalid")
    criteria = judge.get("criteria")
    if not isinstance(criteria, (str, list)) or not criteria:
        raise RouteDerivationError("judge_invalid")
    return MAX_SEMANTIC_JUDGE


def derive_route_policy(package: ArtifactPackage, *, target: str) -> LiveRoutePolicy:
    """Build the live route from the chosen target and the package declarations.

    Raises ``ValueError`` for a target outside the allowlist and
    ``RouteDerivationError`` for a package the runtime cannot observe.
    """

    selected = live_target(target)
    observation_level = package_observation_level(package)
    max_semantic_judge = package_semantic_judge_limit(package)
    operations = package_operations(package)
    writes = sorted(item["name"] for item in operations if not _is_read_only(item))
    permissions = package_runtime_contract(package).get("setup_permissions", [])
    permitted = (
        {name for name in permissions if isinstance(name, str)}
        if isinstance(permissions, list)
        else set()
    )
    return LiveRoutePolicy(
        scenario_id=package.manifest.scenario_id,
        target_domain=selected.domain,
        target_port=selected.target_port,
        gateway_port=selected.gateway_port,
        lifecycle_service=selected.lifecycle_service,
        max_semantic_judge=max_semantic_judge,
        observation_level=observation_level,
        creation_setups=frozenset(name for name in writes if name in permitted),
        observed_operations=tuple(writes),
        generation_tools=tuple(sorted({item["name"] for item in operations})),
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
        elif service in SAFE_TARGET_PORTS:
            if port != SAFE_TARGET_PORTS[service]:
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
    target: str,
    lifecycle: SafeLifecycle | None = None,
    setup_dispatch: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    generation_dispatch: Callable[..., dict[str, Any]] | None = None,
    detector_runner: Callable[[dict[str, Any], ArtifactPackage], Any] | None = None,
    judge_client: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    receipt_path: str | Path | None = None,
    state_dir: str | Path | None = None,
    target_root: str | Path | None = None,
    gateway_config_source: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
    target_url: str | None = None,
    model_url: str | None = None,
    model: str | None = None,
    discovery_records: list[dict[str, Any]] | None = None,
    service_revisions: dict[str, Any] | None = None,
    port_probes: dict[int, bool] | None = None,
) -> FrozenLiveDispatch:
    """Execute one immutable package against one allowlisted local target.

    The target chooses the domain, ports, and lifecycle service. The package
    supplies the scenario, observation level, judge allowance, and permitted
    creation setup. Every package and target check completes before the
    lifecycle is constructed or started. The same lifecycle environment stays
    alive from setup through generation; the adapter never restarts or resets
    it between setup captures and the generation dispatch.
    """

    def reject(
        loaded: ArtifactPackage | None,
        reason: str,
        *,
        route: LiveRoutePolicy | None = None,
        declared_setup: list[dict[str, Any]] | None = None,
    ) -> FrozenLiveDispatch:
        receipt = _failure_receipt(
            loaded,
            reason=reason,
            discovery_records=discovery_records,
            target=target,
            route=route,
        )
        if declared_setup is not None:
            receipt["live_dispatch"]["declared_setup"] = declared_setup
        _write_receipt(receipt_path, receipt)
        return FrozenLiveDispatch(FrozenLiveDispatchStatus.FAILED, receipt, reason)

    try:
        selected = live_target(target)
    except ValueError:
        return reject(None, "target_not_allowed")
    loaded, failure = _load_and_validate_package(package, target=selected)
    if loaded is None or failure is not None:
        return reject(loaded, failure or "package_invalid")
    try:
        route = derive_route_policy(loaded, target=target)
    except RouteDerivationError as exc:
        return reject(loaded, exc.reason)
    except ArtifactPackageError:
        return reject(loaded, "package_invalid")
    endpoint_failure = _validate_endpoints(
        target_url=target_url,
        model_url=model_url,
        target_port=route.target_port,
        gateway_port=route.gateway_port,
    )
    if endpoint_failure is not None:
        return reject(loaded, endpoint_failure, route=route)

    setup, setup_failure = _validate_setup_permissions(loaded, route=route)
    if setup_failure is not None:
        return reject(loaded, setup_failure, route=route, declared_setup=setup)

    if lifecycle is None and target_root is None:
        raise ValueError("target_root is required for the safe lifecycle")
    active_lifecycle = lifecycle or SafeOnlyLifecycle(
        state_dir=Path(
            state_dir
            or f"build/qualification/runtime/{route.scenario_id.lower()}-live-dispatch"
        ),
        target_root=Path(target_root),
        gateway_config_source=Path(
            gateway_config_source or Path(target_root) / "ogx-config.yaml"
        ),
        environment=environment,
    )
    target_port = route.target_port
    gateway_port = route.gateway_port
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
        declared_setup=setup,
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
            raise RuntimeError("setup operation limit exceeded")
        if setup_dispatch is None:
            raise RuntimeError("setup dispatch unavailable")
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
                "target_domain": route.target_domain,
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
            target=target,
            route=route,
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


def _load_and_validate_package(
    package: str | Path | ArtifactPackage,
    *,
    target: LiveTarget,
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
    if SAFE_TARGET_PORTS.get(target.domain) != target.target_port or (
        target.gateway_port != SAFE_GATEWAY_PORT
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
            ("target_domain", target.domain),
            ("target", target.domain),
            ("domain", target.domain),
            ("target_port", target.target_port),
            ("gateway_port", target.gateway_port),
        )
    ):
        return loaded, "package_target_mismatch"
    return loaded, None


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
    route: LiveRoutePolicy,
) -> tuple[list[dict[str, Any]], str | None]:
    """Validate declared setup steps against the package-derived permissions.

    Every case runs at most four setup operations. Read-only setups are always
    admitted; a state-creating setup is admitted only when the runtime
    contract lists it in ``setup_permissions``, and at most one per case.
    """

    try:
        setup = package.json_member("setup.json", default=[])
        operations = package_operations(package)
    except ArtifactPackageError:
        return [], "package_invalid"
    if not isinstance(setup, list):
        return [], "state_creating_setup"
    declared = list(item for item in setup if isinstance(item, dict))
    if len(setup) > MAX_READ_ONLY_PREREQUISITES:
        return declared, "prerequisite_limit_exceeded"
    operation_map = {item["name"]: item for item in operations}
    creation_setups_seen = 0
    for item in setup:
        if not isinstance(item, dict) or not isinstance(item.get("operation"), str):
            return declared, "state_creating_setup"
        name = item["operation"]
        operation = operation_map.get(name)
        if operation is None:
            return declared, "state_creating_setup"
        if _is_read_only(operation):
            continue
        if name not in route.creation_setups:
            return declared, "state_creating_setup"
        creation_setups_seen += 1
        if creation_setups_seen > MAX_CREATION_SETUPS:
            return declared, "excess_creation_setup"
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


def _route_record(route: LiveRoutePolicy) -> dict[str, Any]:
    return {
        "scenario_id": route.scenario_id,
        "target_domain": route.target_domain,
        "target_port": route.target_port,
        "gateway_port": route.gateway_port,
        "lifecycle_service": route.lifecycle_service,
        "observation_level": route.observation_level,
        "max_semantic_judge": route.max_semantic_judge,
        "creation_setups": sorted(route.creation_setups),
        "observed_operations": list(route.observed_operations),
        "generation_tools": list(route.generation_tools),
    }


def _package_record(package: ArtifactPackage | None) -> dict[str, Any]:
    if package is None:
        return {"verified": False}
    return {
        "package_id": package.manifest.package_id,
        "scenario_id": package.manifest.scenario_id,
        "manifest_digest": package.digest,
        "detector_digest": package.detector_digest,
        "verified": True,
    }


def _limits_record(max_semantic_judge: int) -> dict[str, Any]:
    return {
        "max_setup_capture": MAX_READ_ONLY_PREREQUISITES,
        "max_creation_setup": MAX_CREATION_SETUPS,
        "max_generation": 1,
        "max_semantic_judge": max_semantic_judge,
        "setup_capture": 0,
        "generation": 0,
        "semantic_judge": 0,
    }


def _live_dispatch_record(
    package: ArtifactPackage,
    *,
    route: LiveRoutePolicy,
    declared_setup: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": "frozen-live-dispatch-v1",
        "package": _package_record(package),
        "route": _route_record(route),
        "target": {
            "domain": route.target_domain,
            "target_port": route.target_port,
            "gateway_port": route.gateway_port,
        },
        "declared_setup": declared_setup,
        "service_starts": [],
        "service_verifications": [],
        "cleanup": {"status": "not_started"},
        "limits": _limits_record(route.max_semantic_judge),
    }


def _failure_receipt(
    package: ArtifactPackage | None,
    *,
    reason: str,
    discovery_records: list[dict[str, Any]] | None,
    target: str,
    route: LiveRoutePolicy | None = None,
) -> dict[str, Any]:
    receipt = _base_receipt(package, discovery_records)
    receipt["status"] = FrozenLiveDispatchStatus.FAILED.value
    receipt["incomplete_reason"] = reason
    target_port = SAFE_TARGET_PORTS.get(target)
    receipt["live_dispatch"] = {
        "schema": "frozen-live-dispatch-v1",
        "package": _package_record(package),
        "route": _route_record(route) if route is not None else None,
        "target": {
            "domain": target,
            "target_port": target_port,
            "gateway_port": SAFE_GATEWAY_PORT if target_port is not None else None,
        },
        "service_starts": [],
        "service_verifications": [],
        "cleanup": {"status": "not_requested", "identities": []},
        "limits": _limits_record(route.max_semantic_judge if route else 0),
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


def _record_ids(arguments: Any) -> list[Any]:
    """Return scalar values of arguments named ``id`` or ending in ``_id``."""

    if not isinstance(arguments, dict):
        return []
    return [
        value
        for key, value in arguments.items()
        if isinstance(key, str)
        and (key == "id" or key.endswith("_id"))
        and isinstance(value, (str, int))
        and not isinstance(value, bool)
    ]


def _attach_attempt_observation(
    receipt: dict[str, Any], *, route: LiveRoutePolicy
) -> None:
    """Record command attempts without replacing detector results.

    The observation preserves every actual call to any non-read-only
    inventory operation, including wrong-record calls, and never claims an
    effect or an outcome: the packaged detector alone decides the case result.
    """

    observed = set(route.observed_operations)
    calls = receipt.get("evidence", {}).get("tool_calls", [])
    if not isinstance(calls, list):
        calls = []
    attempts: list[dict[str, Any]] = []
    for index, call in enumerate(calls):
        if isinstance(call, dict) and call.get("name") in observed:
            attempts.append(
                {
                    "operation": call["name"],
                    "record_ids": _record_ids(call.get("decoded_arguments")),
                    "evidence_ref": f"evidence.tool_calls[{index}]",
                }
            )
    record_ids: list[Any] = []
    attempted_operations: list[str] = []
    for attempt in attempts:
        if attempt["operation"] not in attempted_operations:
            attempted_operations.append(attempt["operation"])
        for record_id in attempt["record_ids"]:
            if record_id not in record_ids:
                record_ids.append(record_id)
    first_ids = attempts[0]["record_ids"] if attempts else []
    receipt["observation"] = {
        "claim_level": "command_attempt",
        "observed_operations": list(route.observed_operations),
        "attempted_operations": attempted_operations,
        "attempts": attempts,
        "record_id": first_ids[0] if first_ids else None,
        "record_ids": record_ids,
        "attempt_observed": bool(attempts),
        "evidence_refs": [attempt["evidence_ref"] for attempt in attempts],
        "backend_state_effect": "not_established",
        "target_effect": "not_established",
        "vulnerability_confirmed": False,
    }


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
    "FrozenLiveDispatch",
    "FrozenLiveDispatchStatus",
    "LIVE_TARGETS",
    "LiveRoutePolicy",
    "LiveTarget",
    "MAX_CREATION_SETUPS",
    "MAX_READ_ONLY_PREREQUISITES",
    "MAX_SEMANTIC_JUDGE",
    "PreGenerationMismatch",
    "RouteDerivationError",
    "SAFE_AIRBNB_PORT",
    "SAFE_GATEWAY_PORT",
    "SAFE_KLARNA_PORT",
    "SAFE_OCCIAI_PORT",
    "SAFE_TARGET_PORTS",
    "SOCKET_READINESS_TIMEOUT",
    "SUPPORTED_OBSERVATION_LEVELS",
    "SafeLifecycle",
    "SafeOnlyLifecycle",
    "derive_route_policy",
    "execute_frozen_live_package",
    "live_target",
    "package_observation_level",
    "package_operations",
    "package_runtime_contract",
    "package_semantic_judge_limit",
]

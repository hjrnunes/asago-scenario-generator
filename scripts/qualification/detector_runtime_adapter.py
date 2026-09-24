"""Producer-side Docker adapter for exact package detector bytes.

The implementation deliberately mirrors the consumer's closed detector
interface without importing consumer Python.  It returns runtime status
separately from the authored rich result.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import tempfile
import textwrap
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from artifact_package_runtime import (
    ArtifactPackage,
    ArtifactPackageError,
    load_artifact_package,
)

DOCKER = "/usr/local/bin/docker"
PYTHON_IMAGE = "python:3.12-slim"
CLAIM_LEVELS = frozenset(
    {"command_attempt", "reply", "returned_result", "state_effect"}
)
OUTCOMES = frozenset({"detected", "not_detected", "inconclusive"})


@dataclass(frozen=True)
class DetectorExecution:
    status: str
    result: dict[str, Any] | None
    failure: str | None
    package_digest: str | None
    package_digest_after: str | None
    detector_sha256: str | None
    detector_sha256_after: str | None
    docker_argv: tuple[str, ...]
    stdout: bytes = b""
    stderr: bytes = b""


def execute_detector(
    package: str | Path | ArtifactPackage,
    evidence: dict[str, Any],
    *,
    timeout_seconds: float = 10.0,
    docker_path: str = DOCKER,
    image: str = PYTHON_IMAGE,
) -> DetectorExecution:
    """Execute unchanged detector.py bytes in a constrained official image."""

    if isinstance(package, ArtifactPackage):
        loaded = package
        package_path = package.root
    else:
        try:
            package_path = Path(package).expanduser().resolve()
            loaded = load_artifact_package(package_path)
        except (ArtifactPackageError, OSError, ValueError) as exc:
            return _failed(str(exc))
    if not isinstance(evidence, dict):
        return _failed("evidence packet must be an object", package=loaded)
    try:
        detector = loaded.members["detector.py"]
    except KeyError:
        return _failed("package is missing detector.py", package=loaded)
    try:
        detector.decode("utf-8")
        _validate_detector_source(detector)
        evidence_bytes = json.dumps(
            evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        return _failed(str(exc), package=loaded)

    container = f"asago-producer-detector-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory(prefix="asago-producer-detector-") as temporary:
        root = Path(temporary)
        input_path = root / "evidence.json"
        detector_path = root / "detector.py"
        runner_path = root / "runner.py"
        input_path.write_bytes(evidence_bytes)
        detector_path.write_bytes(detector)
        runner_path.write_text(_RUNNER, encoding="utf-8")
        argv = tuple(
            _docker_argv(
                docker_path,
                image,
                package_path,
                input_path,
                detector_path,
                runner_path,
                container,
            )
        )
        try:
            process = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
                env=_docker_environment(),
            )
        except subprocess.TimeoutExpired as exc:
            _remove_container(docker_path, container)
            return DetectorExecution(
                "timeout",
                None,
                f"detector exceeded {timeout_seconds:g}s wall-clock timeout",
                loaded.digest,
                _after_digest(package_path, "manifest"),
                loaded.detector_digest,
                _after_digest(package_path, "detector.py"),
                argv,
                _bounded(exc.stdout),
                _bounded(exc.stderr),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            _remove_container(docker_path, container)
            return DetectorExecution(
                "failed",
                None,
                f"detector runtime unavailable: {exc}",
                loaded.digest,
                _after_digest(package_path, "manifest"),
                loaded.detector_digest,
                _after_digest(package_path, "detector.py"),
                argv,
            )
        finally:
            _remove_container(docker_path, container)

    stdout, stderr = _bounded(process.stdout), _bounded(process.stderr)
    if process.returncode != 0:
        return _finished(
            "failed",
            _runtime_error(stdout, stderr, process.returncode),
            loaded,
            package_path,
            argv,
            stdout,
            stderr,
        )
    try:
        message = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _finished(
            "failed",
            f"detector protocol error: {exc}",
            loaded,
            package_path,
            argv,
            stdout,
            stderr,
        )
    if not isinstance(message, dict) or message.get("status") != "ok":
        return _finished(
            "failed",
            _runtime_error(stdout, stderr, process.returncode),
            loaded,
            package_path,
            argv,
            stdout,
            stderr,
        )
    try:
        result = validate_detector_result(message.get("result"), evidence)
    except ValueError as exc:
        return _finished("failed", str(exc), loaded, package_path, argv, stdout, stderr)
    after = load_artifact_package(package_path)
    if after.digest != loaded.digest or after.detector_digest != loaded.detector_digest:
        return _finished(
            "failed",
            "package or detector digest changed during execution",
            loaded,
            package_path,
            argv,
            stdout,
            stderr,
            after,
        )
    return DetectorExecution(
        "completed",
        result,
        None,
        loaded.digest,
        after.digest,
        loaded.detector_digest,
        after.detector_digest,
        argv,
        stdout,
        stderr,
    )


def validate_detector_result(value: Any, evidence: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("detector result must be an object")
    required = {"outcome", "reason", "evidence_refs", "claim_level"}
    if set(value) != required:
        raise ValueError("detector result fields are not closed")
    if value["outcome"] not in OUTCOMES:
        raise ValueError("detector result outcome is invalid")
    if not isinstance(value["reason"], str) or not value["reason"].strip():
        raise ValueError("detector result reason must be nonblank")
    refs = value["evidence_refs"]
    if not isinstance(refs, list) or not all(
        isinstance(ref, str) and ref for ref in refs
    ):
        raise ValueError("detector result evidence_refs must be nonblank strings")
    if value["outcome"] != "inconclusive" and not refs:
        raise ValueError("detected and not_detected results require evidence_refs")
    for reference in refs:
        _resolve_evidence_ref(evidence, reference)
    if value["claim_level"] not in CLAIM_LEVELS:
        raise ValueError("detector result claim level is invalid")
    return value


def _docker_argv(
    docker_path: str,
    image: str,
    package: Path,
    evidence: Path,
    detector: Path,
    runner: Path,
    container: str,
) -> list[str]:
    return [
        docker_path,
        "run",
        "--rm",
        "--name",
        container,
        "--label",
        "asago-producer-detector=1",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "128m",
        "--pids-limit",
        "64",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--env",
        "HOME=/tmp",
        "--env",
        "PYTHONNOUSERSITE=1",
        "--mount",
        f"type=bind,src={package},dst=/package,readonly",
        "--mount",
        f"type=bind,src={evidence},dst=/input/evidence.json,readonly",
        "--mount",
        f"type=bind,src={detector},dst=/input/detector.py,readonly",
        "--mount",
        f"type=bind,src={runner},dst=/runner.py,readonly",
        "--workdir",
        "/tmp",
        image,
        "python",
        "/runner.py",
    ]


def _validate_detector_source(source: bytes) -> None:
    text = source.decode("utf-8")
    try:
        module = ast.parse(text, filename="detector.py")
    except SyntaxError as exc:
        raise ValueError("detector.py must contain valid Python syntax") from exc
    definitions = [
        item
        for item in module.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == "evaluate"
    ]
    if len(definitions) != 1 or isinstance(definitions[0], ast.AsyncFunctionDef):
        raise ValueError("detector.py must define evaluate(evidence)")
    arguments = definitions[0].args
    positional = [*arguments.posonlyargs, *arguments.args]
    if not positional and arguments.vararg is None:
        raise ValueError("detector.py evaluate must accept one positional argument")
    defaults_start = len(positional) - len(arguments.defaults)
    if defaults_start > 1:
        raise ValueError("detector.py evaluate requires more than one argument")
    if any(default is None for default in arguments.kw_defaults):
        raise ValueError("detector.py evaluate has a required keyword-only argument")


def _docker_environment() -> dict[str, str]:
    result = {"PATH": os.environ.get("PATH", "")}
    for key in ("DOCKER_CONFIG", "DOCKER_HOST"):
        if os.environ.get(key):
            result[key] = os.environ[key]
    return result


def _remove_container(docker: str, name: str) -> None:
    try:
        subprocess.run(
            [docker, "rm", "--force", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_docker_environment(),
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return


def _finished(
    status: str,
    failure: str,
    package: ArtifactPackage,
    path: Path,
    argv: tuple[str, ...],
    stdout: bytes,
    stderr: bytes,
    after: ArtifactPackage | None = None,
) -> DetectorExecution:
    after = after or _load_after(path)
    return DetectorExecution(
        status,
        None,
        failure,
        package.digest,
        after.digest if after else None,
        package.detector_digest,
        after.detector_digest if after else None,
        argv,
        stdout,
        stderr,
    )


def _failed(failure: str, package: ArtifactPackage | None = None) -> DetectorExecution:
    return DetectorExecution(
        "failed",
        None,
        failure,
        package.digest if package else None,
        None,
        package.detector_digest if package else None,
        None,
        (),
    )


def _load_after(path: Path) -> ArtifactPackage | None:
    try:
        return load_artifact_package(path)
    except (ArtifactPackageError, OSError, ValueError):
        return None


def _after_digest(path: Path, name: str) -> str | None:
    package = _load_after(path)
    if package is None:
        return None
    return package.digest if name == "manifest" else package.detector_digest


def _runtime_error(stdout: bytes, stderr: bytes, returncode: int | None) -> str:
    for payload in (stdout, stderr):
        try:
            value = json.loads(payload.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and isinstance(value.get("error"), str):
            return f"detector runtime error: {value['error']}"
    return f"detector container failed with exit code {returncode}"


def _resolve_evidence_ref(evidence: dict[str, Any], reference: str) -> Any:
    if reference in evidence:
        return evidence[reference]
    current: Any = evidence
    if reference.startswith("/"):
        parts = reference.split("/")[1:]
        for part in parts:
            current = _step(current, part.replace("~1", "/").replace("~0", "~"))
        return current
    tokens = re.findall(r"(?:([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\])", reference)
    if not tokens:
        raise ValueError(f"evidence reference does not resolve: {reference}")
    for name, index in tokens:
        part = name or index
        current = _step(current, part)
    return current


def _step(current: Any, part: str) -> Any:
    if isinstance(current, dict) and part in current:
        return current[part]
    if isinstance(current, list) and part.isdigit() and int(part) < len(current):
        return current[int(part)]
    raise ValueError(f"evidence path segment is missing: {part}")


def _bounded(value: bytes | str | None, limit: int = 65536) -> bytes:
    if value is None:
        return b""
    if isinstance(value, str):
        value = value.encode()
    return value[:limit]


_RUNNER = textwrap.dedent(
    """
    import contextlib, importlib.util, io, json, sys
    try:
        with open("/input/evidence.json", encoding="utf-8") as stream:
            evidence = json.load(stream)
        spec = importlib.util.spec_from_file_location("generated_detector", "/input/detector.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        captured_out, captured_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
            result = module.evaluate(evidence)
        if len(captured_out.getvalue().encode()) + len(captured_err.getvalue().encode()) > 65536:
            raise RuntimeError("detector output exceeded 65536 bytes")
        json.dumps(result)
        sys.__stdout__.write(json.dumps({"status": "ok", "result": result}, separators=(",", ":")))
    except BaseException as exc:
        sys.__stdout__.write(json.dumps({"status": "error", "error": f"{type(exc).__name__}: {exc}"}))
        raise SystemExit(3)
    """
)


__all__ = [
    "CLAIM_LEVELS",
    "DOCKER",
    "DetectorExecution",
    "OUTCOMES",
    "PYTHON_IMAGE",
    "execute_detector",
    "validate_detector_result",
]

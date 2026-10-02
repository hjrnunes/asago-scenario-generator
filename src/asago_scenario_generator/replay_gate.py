"""Replay gate: prove a code change leaves a recorded ``run`` unchanged.

Record once (any live ``run`` writes ``provider-calls.jsonl``), then after
every change replay that record through the current code, offline, and compare
every output file with the recording::

    python -m asago_scenario_generator.replay_gate check RECORDED_OUTPUT_DIR

The gate re-runs ``run`` with the recorded arguments, inputs copied into a
scratch directory, ``--replay-calls`` pointing at a copy of the record, model
settings stripped from the environment, and outbound sockets refused.  It then
compares the trees.  Only the differences in :data:`ALLOWED_DIFFERENCES` are
normalised; the first other difference fails the gate.

A change that deletes a prompt template also drops that template's entry from
the prompt-hash tables a run records.  A recorded entry whose ``.j2`` key the
replay lacks passes only when no template of that name exists in the checkout;
the gate reports it as a removed template instead of a difference.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import yaml

from asago_scenario_generator.stpa.infra.provider_record import RECORD_FILENAME

STAGE_FILENAME = "stage.json"
NETWORK_LOG = "network-attempts.log"

# Options whose value is a path the run only writes or that the gate replaces.
_OUTPUT_OPTIONS = frozenset({"--output-dir"})
_GATE_OPTIONS = frozenset({"--replay-calls"})
# Read in place: the profiles file holds endpoint credentials, and copying it
# into scratch space would spread them.  Its content is already in each
# request digest.
_IN_PLACE_OPTIONS = frozenset({"--profiles-file"})
_STRIPPED_ENV_PREFIXES = ("ASAGO_SCENARIO_GENERATOR_", "OPENAI_", "OPENROUTER_")


@dataclass(frozen=True)
class AllowedDifference:
    """One documented, narrowly scoped difference between record and replay.

    *fields* are dotted paths from the document root (from each line's root
    for ``.jsonl``); ``[]`` steps into every list item.
    """

    file: str
    fields: tuple[str, ...]
    reason: str


# The fields whose values legitimately differ between two executions of the
# same code on the same responses.  Keep this list short and specific; a new
# entry needs a reason that is not "the output changed".  Besides these, the
# gate maps scratch paths back to the recorded input and output paths, and the
# replay's wall-clock run id back to the recorded one, in every file.
ALLOWED_DIFFERENCES: tuple[AllowedDifference, ...] = (
    AllowedDifference(
        RECORD_FILENAME,
        ("sequence", "timestamp", "duration_ms"),
        "wall-clock time and arrival order of concurrent requests; records are "
        "compared as a multiset ordered by identity, digest, and sequence",
    ),
    AllowedDifference(
        "calls.jsonl",
        ("timestamp", "duration_ms"),
        "wall-clock time of each call",
    ),
    AllowedDifference(
        "run-manifest.yaml",
        ("created_at",),
        "wall-clock time of the run",
    ),
    AllowedDifference(
        "synthesis-manifest.yaml",
        ("created_at", "prompt_call_evidence.[].duration_ms", "semantic_digest"),
        "wall-clock time of the run and of each call; the digest covers them, "
        "so the gate recomputes it on both sides instead of comparing it",
    ),
)

# Files that carry a framed digest over their own payload.  The gate checks
# that each side's digest matches its payload, then compares the payloads.
_SELF_DIGESTED = {"synthesis-manifest.yaml"}
_TEMPLATE_SUFFIX = ".j2"
_RUN_ID_SOURCES = ("run-manifest.yaml", "synthesis-manifest.yaml")


@dataclass
class Difference:
    path: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}: {self.detail}"


@dataclass
class GateResult:
    recorded: Path
    replayed: Path
    exit_code: int
    seconds: float
    expected_exit_code: int = 0
    network_attempts: list[str] = field(default_factory=list)
    differences: list[Difference] = field(default_factory=list)
    files_compared: int = 0
    removed_templates: list[str] = field(default_factory=list)
    log_tail: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return (
            self.exit_code == self.expected_exit_code
            and not self.network_attempts
            and not self.differences
        )


# --- argument preparation --------------------------------------------------


def recorded_stage(
    recorded: Path, stage_json: Path | None = None
) -> tuple[list[str], int]:
    """Return the ``run`` arguments and exit code the recording came from.

    *stage_json* (default: the orch ``stage.json`` beside the output
    directory) holds the full command line as ``argv`` and its ``exit_code``.
    """
    stage = stage_json or recorded.parent / STAGE_FILENAME
    if not stage.is_file():
        raise FileNotFoundError(
            f"{stage} not found; pass --stage-json or the run arguments after --"
        )
    document = json.loads(stage.read_text(encoding="utf-8"))
    argv = document["argv"]
    try:
        start = argv.index("run")
    except ValueError as error:
        raise ValueError(f"{stage} argv has no 'run' command: {argv}") from error
    return list(argv[start:]), int(document.get("exit_code") or 0)


@dataclass
class PreparedRun:
    arguments: list[str]
    output_dir: Path
    path_map: dict[str, str]


def prepare_run(arguments: Sequence[str], *, recorded: Path, work: Path) -> PreparedRun:
    """Rewrite *arguments* to read copied inputs and write into *work*.

    ``path_map`` maps every scratch path back to the recorded path so outputs
    that echo an input or output path compare equal.
    """
    inputs = work / "inputs"
    inputs.mkdir(parents=True)
    record = work / "record"
    record.mkdir()
    shutil.copy2(recorded / RECORD_FILENAME, record / RECORD_FILENAME)
    output_dir = work / "output"

    path_map: dict[str, str] = {}
    original_output: str | None = None
    rewritten: list[str] = []
    items = list(arguments)
    index = 0
    while index < len(items):
        item = items[index]
        option = item.split("=", 1)[0]
        if option in _GATE_OPTIONS:
            index += 1 if "=" in item else 2
            continue
        if option in _OUTPUT_OPTIONS and "=" not in item:
            original_output = items[index + 1]
            rewritten += [item, str(output_dir)]
            index += 2
            continue
        if index > 0 and items[index - 1] in _IN_PLACE_OPTIONS or item.startswith("-"):
            rewritten.append(item)
            index += 1
            continue
        prefix, raw = ("@", item[1:]) if item.startswith("@") else ("", item)
        source = Path(raw)
        if source.is_absolute() and source.is_file():
            copy = inputs / f"{len(path_map):02d}-{source.name}"
            shutil.copy2(source, copy)
            path_map[str(copy)] = str(source)
            rewritten.append(prefix + str(copy))
        else:
            rewritten.append(item)
        index += 1
    if original_output is None:
        raise ValueError("the recorded arguments have no --output-dir")
    path_map[str(output_dir)] = original_output
    rewritten += ["--replay-calls", str(record)]
    return PreparedRun(rewritten, output_dir, path_map)


def replay_environment(base: dict[str, str] | None = None) -> dict[str, str]:
    """Return *base* without model endpoint, credential, or control settings."""
    env = dict(os.environ if base is None else base)
    for key in list(env):
        if key.startswith(_STRIPPED_ENV_PREFIXES) or key.endswith("_API_KEY"):
            del env[key]
    env.pop("FORCE_COLOR", None)
    return env


# --- network guard -----------------------------------------------------------


def install_network_guard(log_path: Path) -> None:
    """Refuse and log every outbound IP connection made by this process."""

    def refuse(target: object) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{target}\n")
        raise ConnectionRefusedError(f"replay gate refused network access: {target}")

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def connect(self: socket.socket, address: Any) -> Any:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            refuse(address)
        return original_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> Any:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            refuse(address)
        return original_connect_ex(self, address)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        refuse(f"resolve {host}")

    socket.socket.connect = connect  # type: ignore[method-assign]
    socket.socket.connect_ex = connect_ex  # type: ignore[method-assign]
    socket.getaddrinfo = getaddrinfo  # type: ignore[assignment]


def _guarded_run(log_path: Path, arguments: list[str]) -> None:
    install_network_guard(log_path)
    from asago_scenario_generator.cli import app

    app(args=arguments, prog_name="asago-scenario-generator")


# --- comparison --------------------------------------------------------------


def _files(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
    }


def _allowed_fields(relative: str) -> tuple[tuple[str, ...], ...]:
    return tuple(
        tuple(field.split("."))
        for allowed in ALLOWED_DIFFERENCES
        if fnmatch.fnmatch(relative, allowed.file)
        for field in allowed.fields
    )


def _drop_field(value: Any, steps: tuple[str, ...]) -> Any:
    if not steps:
        return value
    head, rest = steps[0], steps[1:]
    if head == "[]":
        if isinstance(value, list):
            return [_drop_field(item, rest) for item in value]
        return value
    if not isinstance(value, dict) or head not in value:
        return value
    if not rest:
        return {key: item for key, item in value.items() if key != head}
    return {
        key: _drop_field(item, rest) if key == head else item
        for key, item in value.items()
    }


def _normalise(value: Any, relative: str, *, jsonl: bool) -> Any:
    for steps in _allowed_fields(relative):
        if jsonl:
            value = [_drop_field(line, steps) for line in value]
        else:
            value = _drop_field(value, steps)
    return value


def checkout_templates() -> frozenset[str]:
    """Return the name of every prompt template in this checkout."""
    root = Path(__file__).resolve().parent
    return frozenset(path.name for path in root.rglob(f"*{_TEMPLATE_SUFFIX}"))


def _drop_removed_templates(
    left: Any, right: Any, present: frozenset[str], removed: set[str]
) -> Any:
    """Drop recorded template keys the replay lacks and the checkout deleted."""
    if isinstance(left, dict) and isinstance(right, dict):
        kept: dict[Any, Any] = {}
        for key, value in left.items():
            if (
                isinstance(key, str)
                and key.endswith(_TEMPLATE_SUFFIX)
                and key not in right
                and key not in present
            ):
                removed.add(key)
                continue
            kept[key] = (
                _drop_removed_templates(value, right[key], present, removed)
                if key in right
                else value
            )
        return kept
    if isinstance(left, list) and isinstance(right, list):
        paired = [
            _drop_removed_templates(a, b, present, removed) for a, b in zip(left, right)
        ]
        return paired + left[len(right) :]
    return left


def _first_difference(left: Any, right: Any, where: str = "$") -> str | None:
    if type(left) is not type(right):
        return f"{where}: {_short(left)} != {_short(right)}"
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right), key=str):
            if key not in left:
                return f"{where}.{key}: only in replay"
            if key not in right:
                return f"{where}.{key}: only in recording"
            found = _first_difference(left[key], right[key], f"{where}.{key}")
            if found:
                return found
        if list(left) != list(right):
            return f"{where}: key order {list(left)} != {list(right)}"
        return None
    if isinstance(left, list):
        for index, (a, b) in enumerate(zip(left, right)):
            found = _first_difference(a, b, f"{where}[{index}]")
            if found:
                return found
        if len(left) != len(right):
            return f"{where}: length {len(left)} != {len(right)}"
        return None
    if left != right:
        return f"{where}: {_short(left)} != {_short(right)}"
    return None


def _short(value: Any, limit: int = 160) -> str:
    text = json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + "..."


def _parse(text: str, suffix: str) -> Any:
    if suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if suffix == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _substitute(text: str, aliases: dict[str, str]) -> str:
    for replay_value in sorted(aliases, key=len, reverse=True):
        text = text.replace(replay_value, aliases[replay_value])
    return text


def _provider_record_order(record: dict[str, Any]) -> str:
    # Concurrent requests arrive in any order; within one identity and digest
    # the recorded sequence order is what replay reproduces.
    return json.dumps(
        [record.get("identity"), record["request_sha256"], record["sequence"]],
        sort_keys=True,
    )


def _self_digest_difference(document: Any, side: str) -> str | None:
    from asago_scenario_generator.pipeline.synthesis import (
        _MANIFEST_DOMAIN,
        _digest_payload,
    )

    if not isinstance(document, dict) or "semantic_digest" not in document:
        return f"{side} has no semantic_digest"
    payload = {k: v for k, v in document.items() if k != "semantic_digest"}
    if _digest_payload(_MANIFEST_DOMAIN, payload) != document["semantic_digest"]:
        return f"{side} semantic_digest does not match its payload"
    return None


def compare_file(
    recorded: Path,
    replayed: Path,
    relative: str,
    aliases: dict[str, str],
    *,
    present_templates: frozenset[str] = frozenset(),
    removed_templates: set[str] | None = None,
) -> str | None:
    """Return the first unexplained difference in one file, or ``None``.

    Files compare byte for byte after *aliases* map replay-only strings back
    to the recorded ones; structured files that still differ compare as
    parsed data after dropping only their :data:`ALLOWED_DIFFERENCES` and the
    recorded hashes of templates absent from *present_templates*, which are
    added to *removed_templates*.  Self-digested files check their digest
    over the full recorded payload first, and the digest itself is an allowed
    difference, so dropping a template entry never leaves a stale digest in
    the comparison.
    """
    left = recorded.read_bytes()
    right = replayed.read_bytes()
    if left == right:
        return None
    try:
        left_text = left.decode("utf-8")
        raw_right_text = right.decode("utf-8")
    except UnicodeDecodeError:
        return "binary content differs"
    right_text = _substitute(raw_right_text, aliases)
    if left_text == right_text:
        return None
    suffix = recorded.suffix
    if suffix not in {".json", ".jsonl", ".yaml", ".yml"}:
        for number, (a, b) in enumerate(
            zip(left_text.splitlines(), right_text.splitlines()), start=1
        ):
            if a != b:
                return f"line {number}: {a[:160]!r} != {b[:160]!r}"
        return "content differs in length"
    left_data = _parse(left_text, suffix)
    right_data = _parse(right_text, suffix)
    if relative in _SELF_DIGESTED:
        # Check each digest against the payload it was computed over, before
        # any alias substitution.
        sides = ((left_data, "recording"), (_parse(raw_right_text, suffix), "replay"))
        for document, side in sides:
            problem = _self_digest_difference(document, side)
            if problem:
                return problem
    if relative == RECORD_FILENAME:
        left_data = sorted(left_data, key=_provider_record_order)
        right_data = sorted(right_data, key=_provider_record_order)
    jsonl = suffix == ".jsonl"
    left_data = _normalise(left_data, relative, jsonl=jsonl)
    right_data = _normalise(right_data, relative, jsonl=jsonl)
    removed: set[str] = set()
    left_data = _drop_removed_templates(
        left_data, right_data, present_templates, removed
    )
    difference = _first_difference(left_data, right_data)
    if difference is None and removed_templates is not None:
        removed_templates |= removed
    return difference


def _run_id_aliases(recorded: Path, replayed: Path) -> dict[str, str]:
    """Map each replay run id (derived from wall-clock time) to the recorded one."""
    aliases: dict[str, str] = {}
    for name in _RUN_ID_SOURCES:
        if not (recorded / name).is_file() or not (replayed / name).is_file():
            continue
        left = yaml.safe_load((recorded / name).read_text(encoding="utf-8"))
        right = yaml.safe_load((replayed / name).read_text(encoding="utf-8"))
        if isinstance(left, dict) and isinstance(right, dict):
            if isinstance(left.get("run_id"), str) and isinstance(
                right.get("run_id"), str
            ):
                aliases[right["run_id"]] = left["run_id"]
    return aliases


def compare_trees(
    recorded: Path,
    replayed: Path,
    path_map: dict[str, str],
    *,
    present_templates: frozenset[str] | None = None,
    removed_templates: set[str] | None = None,
) -> tuple[int, list[Difference]]:
    """Compare every file under *recorded* and *replayed*.

    *present_templates* defaults to :func:`checkout_templates`; recorded
    hashes of other templates are collected in *removed_templates*.
    """
    present = checkout_templates() if present_templates is None else present_templates
    aliases = {**path_map, **_run_id_aliases(recorded, replayed)}
    left, right = _files(recorded), _files(replayed)
    differences = [
        Difference(name, "only in recording") for name in sorted(left - right)
    ] + [Difference(name, "only in replay") for name in sorted(right - left)]
    shared = sorted(left & right)
    for relative in shared:
        detail = compare_file(
            recorded / relative,
            replayed / relative,
            relative,
            aliases,
            present_templates=present,
            removed_templates=removed_templates,
        )
        if detail:
            differences.append(Difference(relative, detail))
    return len(shared), differences


# --- the gate ----------------------------------------------------------------


def run_gate(
    recorded: Path,
    *,
    arguments: Sequence[str] | None = None,
    stage_json: Path | None = None,
    work: Path | None = None,
    runner: Callable[[list[str], dict[str, str]], int] | None = None,
) -> GateResult:
    """Replay *recorded* through the current code and compare the outputs."""
    recorded = recorded.resolve()
    work = Path(tempfile.mkdtemp(prefix="replay-gate-")) if work is None else work
    work.mkdir(parents=True, exist_ok=True)
    if arguments:
        args, expected_exit_code = list(arguments), 0
    else:
        args, expected_exit_code = recorded_stage(recorded, stage_json)
    prepared = prepare_run(args, recorded=recorded, work=work)
    network_log = work / NETWORK_LOG
    command = [
        sys.executable,
        "-m",
        "asago_scenario_generator.replay_gate",
        "_guarded-run",
        str(network_log),
        "--",
        *prepared.arguments,
    ]
    started = time.perf_counter()
    if runner is None:
        with (work / "run.log").open("w", encoding="utf-8") as log:
            exit_code = subprocess.run(
                command, env=replay_environment(), stdout=log, stderr=log
            ).returncode
    else:
        exit_code = runner(command, replay_environment())
    seconds = time.perf_counter() - started
    attempts = (
        network_log.read_text(encoding="utf-8").splitlines()
        if network_log.exists()
        else []
    )
    result = GateResult(
        recorded,
        prepared.output_dir,
        exit_code,
        seconds,
        expected_exit_code=expected_exit_code,
        network_attempts=attempts,
    )
    run_log = work / "run.log"
    if exit_code != expected_exit_code and run_log.is_file():
        result.log_tail = run_log.read_text(encoding="utf-8").splitlines()[-5:]
    if prepared.output_dir.is_dir():
        removed: set[str] = set()
        result.files_compared, result.differences = compare_trees(
            recorded,
            prepared.output_dir,
            prepared.path_map,
            removed_templates=removed,
        )
        result.removed_templates = sorted(removed)
    else:
        result.differences = [Difference(".", "replay wrote no output directory")]
    return result


def _report(result: GateResult, work: Path, limit: int) -> str:
    lines = [
        f"recorded:  {result.recorded}",
        f"replayed:  {result.replayed}",
        f"exit code: {result.exit_code}, recorded {result.expected_exit_code} "
        f"(log: {work / 'run.log'})",
        f"time:      {result.seconds:.1f}s",
        f"files:     {result.files_compared} compared",
    ]
    lines += [f"  {line[:300]}" for line in result.log_tail]
    if result.network_attempts:
        lines.append(f"network:   {len(result.network_attempts)} refused attempt(s)")
        lines += [f"  {attempt}" for attempt in result.network_attempts[:limit]]
    if result.removed_templates:
        lines.append(
            f"removed templates: {len(result.removed_templates)} recorded prompt "
            "hash(es) for templates absent from this checkout"
        )
        lines += [f"  {name}" for name in result.removed_templates]
    if result.differences:
        lines.append(f"differences: {len(result.differences)} file(s)")
        lines += [f"  {item}" for item in result.differences[:limit]]
    lines.append("PASS" if result.passed else "FAIL")
    return "\n".join(lines)


def main(argv: Iterable[str] | None = None) -> int:
    items = list(sys.argv[1:] if argv is None else argv)
    if items[:1] == ["_guarded-run"]:
        log_path, separator, *arguments = items[1:]
        if separator != "--":
            raise SystemExit("usage: _guarded-run LOG -- ARGS...")
        _guarded_run(Path(log_path), arguments)
        return 0
    parser = argparse.ArgumentParser(
        prog="python -m asago_scenario_generator.replay_gate",
        description="Replay a recorded run offline and compare every output.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="replay one recorded output directory")
    check.add_argument("recorded", type=Path, help="recorded run output directory")
    check.add_argument(
        "--stage-json",
        type=Path,
        help="file whose 'argv' holds the recorded command (default: ../stage.json)",
    )
    check.add_argument(
        "--work-dir", type=Path, help="scratch directory (default: a new temp dir)"
    )
    check.add_argument("--show", type=int, default=10, help="differences to print")
    parser.epilog = check.epilog = (
        "After '--', give the recorded 'run ...' command instead of reading stage.json."
    )
    arguments: list[str] | None = None
    if "--" in items:
        split = items.index("--")
        items, arguments = items[:split], items[split + 1 :]
    options = parser.parse_args(items)
    work = options.work_dir or Path(tempfile.mkdtemp(prefix="replay-gate-"))
    result = run_gate(
        options.recorded,
        arguments=arguments,
        stage_json=options.stage_json,
        work=work,
    )
    print(_report(result, work, options.show))
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())

"""Replay gate: prove a code change leaves a recorded ``generate`` unchanged.

Record once (any live ``generate`` writes ``provider-calls.jsonl``), then after
every change replay that record through the current code, offline, and compare
every output file with the recording::

    uv run python scripts/replay_gate.py check RECORDED_OUTPUT_DIR

The gate re-runs ``generate`` with the recorded arguments, inputs copied into a
scratch directory, ``--replay-calls`` pointing at a copy of the record, model
settings stripped from the environment, and outbound sockets refused.  It then
compares the trees.  Only the differences in :data:`ALLOWED_DIFFERENCES` and
:data:`ALLOWED_TEXT_DIFFERENCES` are normalised; the first other difference
fails the gate.  The named versions in :data:`VERSION_CHAINS` compare as the
sequence of distinct versions each side holds; :data:`RETIRED_FIELDS`,
:data:`REMOVED_TEXT` and :data:`ALLOWED_FILE_CHANGES` name what a recording
may hold that the replay no longer writes.

The lists cover output differences only.  A change that alters a model request
on purpose, such as its prompt or the inputs a stage receives, cannot pass on a
recording made before it: the replay finds no recorded response for the new
request digest, the run diverges from that request on, and the comparison
fails.  Re-record the corpus after such a change instead of listing the
divergence.

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
import re
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

import asago_scenario_generator
from asago_scenario_generator.stpa.infra.call_log import (
    CALLS_FILENAME,
    call_entries,
    jsonl_lines,
)
from asago_scenario_generator.stpa.infra.provider_record import RECORD_FILENAME

_SCRIPT = Path(__file__).resolve()
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
        CALLS_FILENAME,
        ("timestamp", "duration_ms", "retry_of"),
        "wall-clock time of each call; a recording made before calls.jsonl named "
        "the attempt a retry repeats lacks retry_of",
    ),
    AllowedDifference(
        "run-manifest.yaml",
        ("created_at",),
        "wall-clock time of the run",
    ),
    AllowedDifference(
        "synthesis-manifest.yaml",
        ("created_at", "semantic_digest"),
        "wall-clock time of the run; the digest covers it, so the gate "
        "recomputes it on both sides instead of comparing it",
    ),
)

# Manifest fields the current code no longer writes.  A recording made before
# a field was retired may hold it and the gate compares without it; a replay
# that writes it again fails.
RETIRED_MANIFEST_FIELDS: dict[str, str] = {
    "prompt_call_evidence": "the manifest's copy of the call records, which "
    "calls.jsonl keeps",
}
_MANIFEST_FILENAME = "synthesis-manifest.yaml"


@dataclass(frozen=True)
class RetiredField:
    """A nested field the current code no longer writes in one file.

    *field* is a dotted path from the document root.  A recording may hold
    it and the gate compares without it; a replay that writes it fails.
    """

    file: str
    field: str
    meaning: str


RETIRED_FIELDS: tuple[RetiredField, ...] = (
    RetiredField(
        "run-manifest.yaml",
        "stage_summary.stage_1a.target_evidence.artifact",
        "the name of target-evidence.yaml, which the run no longer writes",
    ),
)

# Successive versions of one artifact, in step order, each ending with its
# canonical file.  A named version is written only when it differs from the
# next one, so an absent version equals the next one present.  A recording
# made before that rule wrote a version whenever its step ran, so the gate
# compares the sequence of distinct versions each side holds, not the names.
VERSION_CHAINS: dict[str, tuple[str, ...]] = {
    "loss-analysis.yaml": (
        "loss-analysis-draft.yaml",
        "loss-analysis-reviewed.yaml",
        "loss-analysis-reviewed-corrected.yaml",
    ),
    "control-structure.yaml": (
        "control-structure-draft.yaml",
        "control-structure-reviewed.yaml",
        "control-structure-evidence-bound.yaml",
        "control-structure-revised.yaml",
        "control-structure-placed.yaml",
    ),
}


@dataclass(frozen=True)
class AllowedTextDifference:
    """One documented difference in a text file the gate cannot parse.

    Each capture group of *pattern* is masked on both sides before the text
    comparison; the rest of every match must still be equal.
    """

    file: str
    pattern: re.Pattern[str]
    reason: str


_REPLAY_SECONDS_REASON = (
    "the summed duration_ms of replayed calls, rounded to seconds; a replayed "
    "call's duration is the local lookup time, so a step near 500 ms shows 0 or 1"
)
ALLOWED_TEXT_DIFFERENCES: tuple[AllowedTextDifference, ...] = (
    AllowedTextDifference(
        "report/index.html",
        re.compile(r'<b data-metric="effort\.seconds" data-value="(\d+)">([\d,]+)</b>'),
        _REPLAY_SECONDS_REASON,
    ),
    AllowedTextDifference(
        "report/index.html",
        # The Seconds cell closes each effort row.
        re.compile(
            r'<tr id="effort-[^"]+">(?:(?!</tr>).)*?'
            r'<td class="n" data-v="(\d+)">([\d,]+)</td></tr>'
        ),
        _REPLAY_SECONDS_REASON,
    ),
)


@dataclass(frozen=True)
class RemovedText:
    """Text a recording may hold in an unparsed file that the replay no longer writes.

    Every match of *pattern* is deleted from the recording before the text
    comparison; a replay that still writes a match fails.
    """

    file: str
    pattern: re.Pattern[str]
    reason: str


REMOVED_TEXT: tuple[RemovedText, ...] = (
    RemovedText(
        "report/index.html",
        re.compile(
            r'<tr><td>Target profile</td><td><a class="artifact" '
            r'href="\.\./execution-target-profile\.json">.*?</tr>'
        ),
        "the report row that linked the run's copy of the target profile input",
    ),
)


@dataclass(frozen=True)
class AllowedFileChange:
    """A file one side may lack because recordings predate the report rewrite.

    *side* names the side that holds the file: ``"recording"`` for a file the
    replay no longer writes, ``"replay"`` for one a recording lacks.
    """

    file: str
    side: str
    reason: str


# Recordings made before the generate report moved to the shared report kit
# hold synthesis-report.html and neither report/ nor policy-coverage.json.
# Recordings made before the run stopped copying its inputs hold those
# copies.  Re-record the corpus to retire these entries.
ALLOWED_FILE_CHANGES: tuple[AllowedFileChange, ...] = (
    AllowedFileChange(
        "synthesis-report.html",
        "recording",
        "the generate report now lives at report/index.html",
    ),
    AllowedFileChange(
        "report/index.html", "replay", "the generate report on the report kit"
    ),
    AllowedFileChange(
        "report/stage-summary.json", "replay", "the stage summary of that report"
    ),
    AllowedFileChange(
        "policy-coverage.json", "replay", "the policy funnel the report reads"
    ),
    AllowedFileChange(
        "observation-contract.yaml",
        "recording",
        "a copy of the observation contract input",
    ),
    AllowedFileChange(
        "execution-target-profile.json",
        "recording",
        "a copy of the target profile input; downstream reads the discovery copy",
    ),
    AllowedFileChange(
        "target-evidence.yaml",
        "recording",
        "a projection of the target profile input that nothing read",
    ),
)

# A calls.jsonl entry names the provider-calls.jsonl records its call wrote
# (``provider_requests``, with ``response_parsed``), or has an empty list and
# holds the prompt and response text when it wrote none.  An entry logged
# before entries named their records has no ``provider_requests`` and holds
# the text.  Only such an entry compares with a current one without the text
# and link fields; two current entries compare their request digests, after
# each side's links are checked against its own record.  Sequence numbers
# follow the arrival order of concurrent requests, so only that check reads
# them: within an entry the links must rise without repeats (a transport
# retry's records share their digest and identity), and no record may be
# named twice.  A record need not be named at all: an interrupted call or a
# direct client request writes one without a call entry, and the gate
# compares provider-calls.jsonl itself.
_CALL_TEXT_FIELDS = (
    "system_prompt_text",
    "user_prompt_text",
    "raw_response",
    "cleaned_response",
    "response_content",
)
_CALL_LINK_FIELDS = ("provider_requests", "response_parsed")
_CALL_IDENTITY_FIELDS = ("stage", "step", "slot_id", "scenario_id", "attempt_number")

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
    """Return the ``generate`` arguments and exit code the recording came from.

    *stage_json* (default: the orchestrator's ``stage.json`` beside the output
    directory) holds the full command line as ``argv`` and its ``exit_code``.
    """
    stage = stage_json or recorded.parent / STAGE_FILENAME
    if not stage.is_file():
        raise FileNotFoundError(
            f"{stage} not found; pass --stage-json or the generate arguments after --"
        )
    document = json.loads(stage.read_text(encoding="utf-8"))
    argv = document["argv"]
    try:
        start = argv.index("generate")
    except ValueError as error:
        raise ValueError(f"{stage} argv has no 'generate' command: {argv}") from error
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
    rewritten, original_output = _rewrite_arguments(
        list(arguments), inputs, output_dir, path_map
    )
    if original_output is None:
        raise ValueError("the recorded arguments have no --output-dir")
    path_map[str(output_dir)] = original_output
    rewritten += ["--replay-calls", str(record)]
    return PreparedRun(rewritten, output_dir, path_map)


def _rewrite_arguments(
    items: list[str], inputs: Path, output_dir: Path, path_map: dict[str, str]
) -> tuple[list[str], str | None]:
    """Return the rewritten arguments and the recorded ``--output-dir``."""
    original_output: str | None = None
    rewritten: list[str] = []
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
        else:
            rewritten.append(_copied_input(item, inputs, path_map))
        index += 1
    return rewritten, original_output


def _copied_input(item: str, inputs: Path, path_map: dict[str, str]) -> str:
    """Copy an absolute input file into *inputs*; return the argument to use.

    Each copy keeps its file name inside a numbered folder, because outputs may
    record an input's base name (``policy-coverage.json`` does).
    """
    prefix, raw = ("@", item[1:]) if item.startswith("@") else ("", item)
    source = Path(raw)
    if not (source.is_absolute() and source.is_file()):
        return item
    copy = inputs / f"{len(path_map):02d}" / source.name
    copy.parent.mkdir()
    shutil.copy2(source, copy)
    path_map[str(copy)] = str(source)
    return prefix + str(copy)


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
    return _drop_dict_field(value, head, rest)


def _drop_dict_field(value: dict[Any, Any], head: str, rest: tuple[str, ...]) -> Any:
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
    root = Path(asago_scenario_generator.__file__).resolve().parent
    return frozenset(path.name for path in root.rglob(f"*{_TEMPLATE_SUFFIX}"))


def _drop_removed_templates(
    left: Any, right: Any, present: frozenset[str], removed: set[str]
) -> Any:
    """Drop recorded template keys the replay lacks and the checkout deleted."""
    if isinstance(left, dict) and isinstance(right, dict):
        return _drop_removed_template_keys(left, right, present, removed)
    if isinstance(left, list) and isinstance(right, list):
        paired = [
            _drop_removed_templates(a, b, present, removed) for a, b in zip(left, right)
        ]
        return paired + left[len(right) :]
    return left


def _drop_removed_template_keys(
    left: dict[Any, Any],
    right: dict[Any, Any],
    present: frozenset[str],
    removed: set[str],
) -> dict[Any, Any]:
    kept: dict[Any, Any] = {}
    for key, value in left.items():
        if _is_removed_template(key, right, present):
            removed.add(key)
            continue
        kept[key] = (
            _drop_removed_templates(value, right[key], present, removed)
            if key in right
            else value
        )
    return kept


def _is_removed_template(
    key: Any, right: dict[Any, Any], present: frozenset[str]
) -> bool:
    return (
        isinstance(key, str)
        and key.endswith(_TEMPLATE_SUFFIX)
        and key not in right
        and key not in present
    )


def _first_difference(left: Any, right: Any, where: str = "$") -> str | None:
    if type(left) is not type(right):
        return f"{where}: {_short(left)} != {_short(right)}"
    if isinstance(left, dict):
        return _first_dict_difference(left, right, where)
    if isinstance(left, list):
        return _first_list_difference(left, right, where)
    if left != right:
        return f"{where}: {_short(left)} != {_short(right)}"
    return None


def _first_dict_difference(
    left: dict[Any, Any], right: dict[Any, Any], where: str
) -> str | None:
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


def _first_list_difference(left: list[Any], right: list[Any], where: str) -> str | None:
    for index, (a, b) in enumerate(zip(left, right)):
        found = _first_difference(a, b, f"{where}[{index}]")
        if found:
            return found
    if len(left) != len(right):
        return f"{where}: length {len(left)} != {len(right)}"
    return None


def _short(value: Any, limit: int = 160) -> str:
    text = json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + "..."


def _parse(text: str, suffix: str, relative: str = "") -> Any:
    if relative == CALLS_FILENAME:
        # Publication events fold into their calls, so a recording that
        # marked a call published in place compares with one that appended
        # the event.
        return call_entries(text)
    if suffix == ".jsonl":
        return [json.loads(line) for line in jsonl_lines(text)]
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


def _pair_call_forms(left: list[Any], right: list[Any]) -> None:
    """Make each pair of call entries comparable on what both forms hold."""
    for a, b in zip(left, right):
        if not (isinstance(a, dict) and isinstance(b, dict)):
            continue
        if ("provider_requests" in a) != ("provider_requests" in b):
            for entry in (a, b):
                for name in _CALL_TEXT_FIELDS + _CALL_LINK_FIELDS:
                    entry.pop(name, None)
        elif "provider_requests" in a:
            for entry in (a, b):
                entry["provider_requests"] = [
                    link.get("request_sha256") for link in entry["provider_requests"]
                ]


def _provider_records(directory: Path) -> dict[Any, dict[str, Any]]:
    path = directory / RECORD_FILENAME
    if not path.is_file():
        return {}
    records = (json.loads(line) for line in jsonl_lines(path.read_text("utf-8")))
    return {record.get("sequence"): record for record in records}


def _link_problem(
    link: Any, entry: dict[str, Any], records: dict[Any, dict[str, Any]]
) -> str | None:
    """Check that one link names a record of the entry's own call."""
    record = records.get(link.get("sequence"))
    if record is None or record.get("request_sha256") != link.get("request_sha256"):
        return f"names no record of {RECORD_FILENAME}"
    identity = record.get("identity")
    if identity is not None and any(
        identity.get(name) != entry.get(name) for name in _CALL_IDENTITY_FIELDS
    ):
        return "names the record of another call"
    return None


def _call_link_problem(calls: Path, side: str) -> str | None:
    """Check that the calls name the records of their own ``provider-calls.jsonl``.

    Each link must give the sequence and request digest of one record whose
    call identity is the entry's.  An entry's links rise in sequence without
    repeats, and no record is named by two entries.
    """
    entries = call_entries(calls.read_text(encoding="utf-8"))
    records = _provider_records(calls.parent)
    claimed: dict[Any, int] = {}
    for index, entry in enumerate(entries):
        links = entry.get("provider_requests", ())
        where = f"{side} $[{index}].provider_requests"
        for link in links:
            problem = _link_problem(link, entry, records)
            if problem:
                return f"{where} {_short(link)} {problem}"
        sequences = [link["sequence"] for link in links]
        if sequences != sorted(set(sequences)):
            return f"{where} {sequences} does not rise in sequence without repeats"
        for sequence in sequences:
            if sequence in claimed:
                return (
                    f"{where} names record {sequence}, which "
                    f"$[{claimed[sequence]}] names too"
                )
            claimed[sequence] = index
    return None


def _retired_field_problem(replayed: Path) -> str | None:
    """Fail a replay manifest that writes a retired field again."""
    document = yaml.safe_load(replayed.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return None
    for name, meaning in RETIRED_MANIFEST_FIELDS.items():
        if name in document:
            return f"replay writes {name}, {meaning}, which the manifest retired"
    return None


def _retired_fields(relative: str) -> list[RetiredField]:
    return [retired for retired in RETIRED_FIELDS if retired.file == relative]


def _has_field(value: Any, steps: list[str]) -> bool:
    for step in steps:
        if not isinstance(value, dict) or step not in value:
            return False
        value = value[step]
    return True


def _retired_nested_problem(replayed: Path, relative: str) -> str | None:
    """Fail a replay that writes a :data:`RETIRED_FIELDS` entry again."""
    retired = _retired_fields(relative)
    if not retired:
        return None
    document = yaml.safe_load(replayed.read_text(encoding="utf-8"))
    for item in retired:
        if _has_field(document, item.field.split(".")):
            return f"replay writes {item.field}, {item.meaning}, which is retired"
    return None


def _self_digest_difference(document: Any, side: str) -> str | None:
    from asago_scenario_generator.pipeline.synthesis_manifest import (
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
    the comparison.  ``calls.jsonl`` first checks each side's links against
    that side's own ``provider-calls.jsonl``; the synthesis manifest first
    fails a replay that writes a :data:`RETIRED_MANIFEST_FIELDS` entry, and
    the recording's copy of one is dropped before comparing.
    """
    if relative == CALLS_FILENAME:
        for path, side in ((recorded, "recording"), (replayed, "replay")):
            problem = _call_link_problem(path, side)
            if problem:
                return problem
    if relative == _MANIFEST_FILENAME:
        problem = _retired_field_problem(replayed)
        if problem:
            return problem
    problem = _retired_nested_problem(replayed, relative)
    if problem:
        return problem
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
        for removed_text in REMOVED_TEXT:
            if removed_text.file != relative:
                continue
            if removed_text.pattern.search(right_text):
                return f"replay writes {removed_text.reason}, which is removed"
            left_text = removed_text.pattern.sub("", left_text)
        left_text = _mask_text(left_text, relative)
        right_text = _mask_text(right_text, relative)
        if left_text == right_text:
            return None
        return _text_difference(left_text, right_text)
    left_data = _parse(left_text, suffix, relative)
    right_data = _parse(right_text, suffix, relative)
    if relative in _SELF_DIGESTED:
        problem = _self_digest_problem(left_data, raw_right_text, suffix)
        if problem:
            return problem
    if relative == RECORD_FILENAME:
        left_data = sorted(left_data, key=_provider_record_order)
        right_data = sorted(right_data, key=_provider_record_order)
    if relative == CALLS_FILENAME:
        _pair_call_forms(left_data, right_data)
    if relative == _MANIFEST_FILENAME and isinstance(left_data, dict):
        left_data = {
            key: value
            for key, value in left_data.items()
            if key not in RETIRED_MANIFEST_FIELDS
        }
    for retired in _retired_fields(relative):
        left_data = _drop_field(left_data, tuple(retired.field.split(".")))
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


def _mask_text(text: str, relative: str) -> str:
    """Mask the capture groups of every :data:`ALLOWED_TEXT_DIFFERENCES` match."""
    for allowed in ALLOWED_TEXT_DIFFERENCES:
        if allowed.file == relative:
            text = allowed.pattern.sub(_masked_match, text)
    return text


def _masked_match(match: re.Match[str]) -> str:
    whole, start = match.group(0), match.start()
    for index in range(match.re.groups, 0, -1):
        left, right = match.span(index)
        whole = whole[: left - start] + "*" + whole[right - start :]
    return whole


def _text_difference(left_text: str, right_text: str) -> str:
    for number, (a, b) in enumerate(
        zip(left_text.splitlines(), right_text.splitlines()), start=1
    ):
        if a != b:
            return f"line {number}: {a[:160]!r} != {b[:160]!r}"
    return "content differs in length"


def _self_digest_problem(
    left_data: Any, raw_right_text: str, suffix: str
) -> str | None:
    # Check each digest against the payload it was computed over, before any
    # alias substitution.
    sides = ((left_data, "recording"), (_parse(raw_right_text, suffix), "replay"))
    for document, side in sides:
        problem = _self_digest_difference(document, side)
        if problem:
            return problem
    return None


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


def _file_change_allowed(name: str, side: str) -> bool:
    return any(
        change.side == side and change.file == name for change in ALLOWED_FILE_CHANGES
    )


def _distinct_versions(
    root: Path, canonical: str, aliases: dict[str, str] | None = None
) -> list[Any]:
    """Return the chain's versions on disk in step order, repeats collapsed."""
    versions: list[Any] = []
    for name in (*VERSION_CHAINS[canonical], canonical):
        path = root / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if aliases is not None:
            text = _substitute(text, aliases)
        document = yaml.safe_load(text)
        if not versions or versions[-1] != document:
            versions.append(document)
    return versions


def _version_chain_differences(
    recorded: Path, replayed: Path, aliases: dict[str, str]
) -> list[Difference]:
    differences = []
    for canonical in VERSION_CHAINS:
        left = _distinct_versions(recorded, canonical)
        right = _distinct_versions(replayed, canonical, aliases)
        if left == right:
            continue
        index = next(
            (n for n, (a, b) in enumerate(zip(left, right)) if a != b),
            min(len(left), len(right)),
        )
        differences.append(
            Difference(
                f"{canonical} versions",
                f"recording holds {len(left)} distinct versions, replay "
                f"{len(right)}; they first differ at version {index + 1}",
            )
        )
    return differences


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
    named_versions = {name for names in VERSION_CHAINS.values() for name in names}
    left = _files(recorded) - named_versions
    right = _files(replayed) - named_versions
    differences = (
        _version_chain_differences(recorded, replayed, aliases)
        + [
            Difference(name, "only in recording")
            for name in sorted(left - right)
            if not _file_change_allowed(name, "recording")
        ]
        + [
            Difference(name, "only in replay")
            for name in sorted(right - left)
            if not _file_change_allowed(name, "replay")
        ]
    )
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
    """Replay *recorded* through the current code and compare the outputs.

    Without *work*, the replay runs in a temporary directory that is removed
    before this returns; pass *work* to keep the scratch files.
    """
    if work is not None:
        return _run_gate_in(work, recorded, arguments, stage_json, runner)
    with tempfile.TemporaryDirectory(prefix="replay-gate-") as scratch:
        return _run_gate_in(Path(scratch), recorded, arguments, stage_json, runner)


def _run_gate_in(
    work: Path,
    recorded: Path,
    arguments: Sequence[str] | None,
    stage_json: Path | None,
    runner: Callable[[list[str], dict[str, str]], int] | None,
) -> GateResult:
    recorded = recorded.resolve()
    work.mkdir(parents=True, exist_ok=True)
    if arguments:
        args, expected_exit_code = list(arguments), 0
    else:
        args, expected_exit_code = recorded_stage(recorded, stage_json)
    prepared = prepare_run(args, recorded=recorded, work=work)
    network_log = work / NETWORK_LOG
    command = [
        sys.executable,
        str(_SCRIPT),
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


def _report(result: GateResult, work: Path | None, limit: int) -> str:
    """Render *result*; *work* is the kept scratch directory, if any."""
    log = "" if work is None else f" (log: {work / 'run.log'})"
    lines = [
        f"recorded:  {result.recorded}",
        f"replayed:  {result.replayed}",
        f"exit code: {result.exit_code}, recorded {result.expected_exit_code}{log}",
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
    if work is None and not result.passed:
        lines.append("rerun with --work-dir DIR to keep the scratch files")
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
        prog="python scripts/replay_gate.py",
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
        "--work-dir",
        type=Path,
        help="scratch directory to keep (default: a temporary one, removed afterwards)",
    )
    check.add_argument("--show", type=int, default=10, help="differences to print")
    parser.epilog = check.epilog = (
        "After '--', give the recorded 'generate ...' command instead of reading "
        "stage.json."
    )
    arguments: list[str] | None = None
    if "--" in items:
        split = items.index("--")
        items, arguments = items[:split], items[split + 1 :]
    options = parser.parse_args(items)
    result = run_gate(
        options.recorded,
        arguments=arguments,
        stage_json=options.stage_json,
        work=options.work_dir,
    )
    print(_report(result, options.work_dir, options.show))
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())

"""Gold case schema, loader, digest, and applicability checker.

See ai/findings/target-grounded-scenario-generation-spec-2026-09-07.md (Phase 0).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

Family = Literal[
    "cross_account_read",
    "cross_account_write",
    "policy_violation_write",
    "ungrounded_answer",
    "missed_escalation",
    "instruction_override",
    "discriminatory_response",
]

AdversaryKind = Literal[
    "external_attacker",
    "malicious_customer",
    "third_party_via_content",
    "none",
]

TestClass = Literal["adversarial", "functional"]

StimulusKind = Literal["user_message", "conversation", "retrieved_content"]

OracleKind = Literal[
    "tool_argument",
    "tool_called",
    "tool_absent",
    "tool_order",
    "response_claim",
    "paired_response",
]

OracleOperator = Literal[
    "equals",
    "not_equals",
    "greater_than",
    "less_than",
    "owner_differs_from_session",
]


class AdversarySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: AdversaryKind
    gain: str = Field(min_length=1)
    reaches_target_via: StimulusKind = "user_message"


class StateFact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: list[str | int]
    value: Any


class PolicyFact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_name: str
    content_contains: str


class StimulusTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = "user"
    text: str


class StimulusSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: StimulusKind
    turns: list[StimulusTurn] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_turn_count(self) -> StimulusSpec:
        if self.kind == "user_message" and len(self.turns) != 1:
            raise ValueError("a user_message stimulus must have exactly one turn")
        if self.kind == "conversation" and len(self.turns) < 2:
            raise ValueError("a conversation stimulus must have at least two turns")
        return self

    def all_text(self) -> str:
        return "\n".join(t.text for t in self.turns)


class OracleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: OracleKind
    tool: str | None = None
    argument: str | None = None
    operator: OracleOperator | None = None
    value: Any = None
    reference_tool: str | None = None
    unsafe_when: str
    safe_behaviors: list[str] = Field(default_factory=list, min_length=1)

    @model_validator(mode="after")
    def _check_kind_fields(self) -> OracleSpec:
        kind = self.kind
        if kind != "tool_order" and self.reference_tool is not None:
            raise ValueError(f"oracle kind {kind!r} must not set reference_tool")
        if (
            kind in ("tool_argument", "tool_called", "tool_absent", "tool_order")
            and not self.tool
        ):
            raise ValueError(f"oracle kind {kind!r} requires tool")
        if kind == "tool_argument":
            missing = [
                name
                for name, v in (
                    ("argument", self.argument),
                    ("operator", self.operator),
                    ("value", self.value),
                )
                if v is None
            ]
            if missing:
                raise ValueError(
                    f"oracle kind tool_argument requires {', '.join(missing)}"
                )
        if kind == "tool_order":
            missing = [
                name
                for name, v in (
                    ("argument", self.argument),
                    ("operator", self.operator),
                    ("value", self.value),
                    ("reference_tool", self.reference_tool),
                )
                if v is None
            ]
            if missing:
                raise ValueError(
                    f"oracle kind tool_order requires {', '.join(missing)}"
                )
            if self.reference_tool == self.tool:
                raise ValueError(
                    "oracle kind tool_order reference_tool must differ from tool"
                )
        if kind in ("tool_called", "tool_absent"):
            present = [
                name
                for name, v in (
                    ("argument", self.argument),
                    ("operator", self.operator),
                    ("value", self.value),
                )
                if v is not None
            ]
            if present:
                raise ValueError(
                    f"oracle kind {kind!r} must not set {', '.join(present)}"
                )
        if kind in ("response_claim", "paired_response"):
            present = [
                name
                for name, v in (
                    ("tool", self.tool),
                    ("argument", self.argument),
                    ("operator", self.operator),
                    ("value", self.value),
                )
                if v is not None
            ]
            if present:
                raise ValueError(
                    f"oracle kind {kind!r} must not set {', '.join(present)}"
                )
        return self


class MatchHints(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keywords: list[str] = Field(default_factory=list)


RECORD_ID_PATTERN = re.compile(r"\b(?:ORD-\d+|PLAN-\d+|CUST\d+|POL-[A-Z0-9_\-]+)\b")


class GoldCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    family: Family
    title: str
    test_class: TestClass = "adversarial"
    adversary: AdversarySpec
    constraint_meaning: str
    state_facts: list[StateFact] = Field(default_factory=list)
    policy_facts: list[PolicyFact] = Field(default_factory=list)
    match_hints: MatchHints = Field(default_factory=MatchHints)
    stimulus: StimulusSpec
    oracle: OracleSpec
    notes: str | None = None

    @model_validator(mode="after")
    def _check_reaches_target_via(self) -> GoldCase:
        if self.adversary.reaches_target_via != self.stimulus.kind:
            raise ValueError(
                "adversary.reaches_target_via "
                f"({self.adversary.reaches_target_via}) must equal "
                f"stimulus.kind ({self.stimulus.kind})"
            )
        return self

    @model_validator(mode="after")
    def _check_functional_adversary(self) -> GoldCase:
        is_none = self.adversary.kind == "none"
        is_functional = self.test_class == "functional"
        if is_none != is_functional:
            raise ValueError(
                "adversary.kind must be 'none' if and only if "
                "test_class is 'functional'"
            )
        return self

    def derived_record_ids(self) -> set[str]:
        """Collect target record IDs (e.g. ORD-201, CUST002) for matching.

        Sources: state-fact paths (which name the target record), the oracle
        value, and stimulus text. State-fact values are ownership and context
        metadata (for example ``customer_id = CUST001``) and are not treated
        as targets. The session identity from the
        ``authenticated_customer_id`` state fact is excluded everywhere.
        """
        session_id = next(
            (
                str(fact.value)
                for fact in self.state_facts
                if fact.path == ["authenticated_customer_id"]
            ),
            None,
        )
        excluded = {session_id} if session_id else set()

        found: set[str] = set()

        def collect(text: str) -> None:
            for match in RECORD_ID_PATTERN.findall(text):
                if match not in excluded:
                    found.add(match)

        for fact in self.state_facts:
            for element in fact.path:
                collect(str(element))
        if self.oracle.value is not None:
            collect(str(self.oracle.value))
        for turn in self.stimulus.turns:
            collect(turn.text)
        return found


class GoldFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_environment: str
    version: int
    gold_cases: list[GoldCase] = Field(min_length=1)

    def case_by_id(self, case_id: str) -> GoldCase | None:
        for c in self.gold_cases:
            if c.id == case_id:
                return c
        return None


class OracleAmendment(BaseModel):
    """Amended oracle text for one benchmark case.

    Only ``unsafe_when`` may be amended; kind, tool, argument, operator,
    value, and safe_behaviors stay from the base gold file.
    """

    model_config = ConfigDict(extra="forbid")

    unsafe_when: str = Field(min_length=1)


class BenchmarkCaseRevision(BaseModel):
    """One gold case's entry in a benchmark revision sidecar."""

    model_config = ConfigDict(extra="forbid")

    id: str
    test_class: TestClass
    adversary: AdversarySpec | None = None
    oracle: OracleAmendment | None = None

    @model_validator(mode="after")
    def _check_class_adversary(self) -> BenchmarkCaseRevision:
        if self.test_class == "functional":
            if self.adversary is None:
                raise ValueError(
                    "a functional benchmark case requires an adversary block"
                )
            if self.adversary.kind != "none":
                raise ValueError(
                    "a functional benchmark case adversary must have kind 'none'"
                )
        elif self.adversary is not None:
            raise ValueError("an adversarial benchmark case must not set an adversary")
        return self


class BenchmarkAmendment(BaseModel):
    """One recorded owner ruling that amends a gold case's oracle."""

    model_config = ConfigDict(extra="forbid")

    id: str
    gold_id: str
    field: Literal["oracle.unsafe_when"]
    ruling: str
    rationale: str


class BenchmarkRevision(BaseModel):
    """Benchmark revision 2 or 3 sidecar over a pinned version 1 gold file.

    Version 3 amends oracle text: each amendment records one owner ruling
    and pairs with exactly one case ``oracle`` override.
    """

    model_config = ConfigDict(extra="forbid")

    benchmark_version: Literal[2, 3]
    base_gold_file: str
    base_gold_digest: str
    classification_test: str
    thresholds: dict[str, int]
    cases: list[BenchmarkCaseRevision] = Field(min_length=1)
    previous_revision_file: str | None = None
    previous_revision_digest: str | None = None
    amendments: list[BenchmarkAmendment] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_unique_case_ids(self) -> BenchmarkRevision:
        ids = [c.id for c in self.cases]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise ValueError(f"duplicate benchmark case ids: {', '.join(duplicates)}")
        return self

    @model_validator(mode="after")
    def _check_previous_revision_pins(self) -> BenchmarkRevision:
        has_file = self.previous_revision_file is not None
        has_digest = self.previous_revision_digest is not None
        if has_file != has_digest:
            raise ValueError(
                "previous_revision_file and previous_revision_digest must "
                "be set together or not at all"
            )
        if self.benchmark_version == 2 and has_file:
            raise ValueError("benchmark version 2 must not pin a previous revision")
        if self.benchmark_version == 3 and not has_file:
            raise ValueError(
                "benchmark version 3 requires previous_revision_file and "
                "previous_revision_digest"
            )
        return self

    @model_validator(mode="after")
    def _check_amendments_match_oracle_overrides(self) -> BenchmarkRevision:
        overridden = {c.id for c in self.cases if c.oracle is not None}
        if self.benchmark_version == 2:
            if self.amendments or overridden:
                raise ValueError(
                    "benchmark version 2 must not carry amendments or case "
                    "oracle overrides"
                )
            return self
        amendment_ids = [a.id for a in self.amendments]
        duplicates = sorted({i for i in amendment_ids if amendment_ids.count(i) > 1})
        if duplicates:
            raise ValueError(f"duplicate amendment ids: {', '.join(duplicates)}")
        gold_ids = [a.gold_id for a in self.amendments]
        duplicates = sorted({g for g in gold_ids if gold_ids.count(g) > 1})
        if duplicates:
            raise ValueError(
                "each amended gold case needs exactly one amendment; "
                f"duplicate amendment gold_ids: {', '.join(duplicates)}"
            )
        if set(gold_ids) != overridden:
            raise ValueError(
                "amendment gold_ids must equal the case ids carrying an "
                "oracle override (amendments without oracle override: "
                f"{sorted(set(gold_ids) - overridden) or 'none'}; oracle "
                "overrides without amendment: "
                f"{sorted(overridden - set(gold_ids)) or 'none'})"
            )
        return self


def load_gold_file(path: str | Path) -> GoldFile:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    gold = GoldFile.model_validate(data)
    # Validate unique IDs
    seen: set[str] = set()
    for c in gold.gold_cases:
        if c.id in seen:
            raise ValueError(f"Duplicate gold case id: {c.id}")
        seen.add(c.id)
    return gold


def compute_gold_digest(path: str | Path) -> str:
    """Deterministic sha256 digest of the gold file bytes."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sidecar_digest(path: str | Path) -> str:
    """Deterministic sha256 digest of a benchmark sidecar file's bytes."""
    return compute_gold_digest(path)


def load_benchmark_revision(
    sidecar_path: str | Path,
    base_gold_path: str | Path | None = None,
) -> tuple[GoldFile, BenchmarkRevision]:
    """Load a benchmark revision sidecar over a pinned base gold file.

    The sidecar is version 2 (classification only) or version 3
    (classification plus oracle amendments). The base path defaults to the
    sidecar's ``base_gold_file`` (relative to the current working directory).
    A version 3 sidecar pins its previous revision file and every amendment
    replaces one case's ``oracle.unsafe_when`` from the base gold file.
    Returns a new ``GoldFile`` whose cases carry their sidecar classification
    and amendments, plus the validated revision. Never writes to disk.
    """
    sidecar_path = Path(sidecar_path)
    raw = yaml.safe_load(sidecar_path.read_text(encoding="utf-8"))
    revision = BenchmarkRevision.model_validate(raw)

    if revision.previous_revision_file is not None:
        previous_path = Path(revision.previous_revision_file)
        previous_actual = sidecar_digest(previous_path)
        if previous_actual != revision.previous_revision_digest:
            raise ValueError(
                "previous revision sidecar digest mismatch for "
                f"{previous_path}: sidecar pins "
                f"{revision.previous_revision_digest} but the file computes "
                f"{previous_actual}"
            )

    base = (
        Path(base_gold_path)
        if base_gold_path is not None
        else Path(revision.base_gold_file)
    )
    actual_digest = compute_gold_digest(base)
    if actual_digest != revision.base_gold_digest:
        raise ValueError(
            f"base gold file digest mismatch for {base}: sidecar pins "
            f"{revision.base_gold_digest} but the file computes {actual_digest}"
        )
    gold = load_gold_file(base)

    base_by_id = {c.id: c for c in gold.gold_cases}
    base_ids = set(base_by_id)
    sidecar_ids = {c.id for c in revision.cases}
    missing = sorted(base_ids - sidecar_ids)
    extra = sorted(sidecar_ids - base_ids)
    if missing or extra:
        raise ValueError(
            "benchmark sidecar ids must match the base gold file ids exactly "
            f"(missing from sidecar: {missing or 'none'}; "
            f"absent from base: {extra or 'none'})"
        )

    revised: list[GoldCase] = []
    for rev in revision.cases:
        update: dict[str, Any] = {"test_class": rev.test_class}
        if rev.adversary is not None:
            update["adversary"] = rev.adversary
        if rev.oracle is not None:
            base_oracle = base_by_id[rev.id].oracle
            update["oracle"] = base_oracle.model_copy(
                update={"unsafe_when": rev.oracle.unsafe_when}
            )
        copy = base_by_id[rev.id].model_copy(update=update)
        # Re-validate so the kind/test-class iff validator runs on the copy.
        revised.append(GoldCase.model_validate(copy.model_dump()))
    return (
        GoldFile(
            target_environment=gold.target_environment,
            version=gold.version,
            gold_cases=revised,
        ),
        revision,
    )


def amended_case_ids(revision: BenchmarkRevision) -> frozenset[str]:
    """Gold case ids whose oracle the revision overrides."""
    return frozenset(c.id for c in revision.cases if c.oracle is not None)


def compute_benchmark_digest(
    sidecar_path: str | Path, base_gold_path: str | Path
) -> str:
    """Deterministic digest binding base gold file bytes to sidecar bytes."""
    base_digest = compute_gold_digest(base_gold_path).encode("utf-8")
    sidecar_bytes = Path(sidecar_path).read_bytes()
    return hashlib.sha256(base_digest + b"\n" + sidecar_bytes).hexdigest()


def atomic_write_text(path: Path, text: str) -> None:
    """Write text to path atomically via a same-directory temp file."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _resolve_path(data: Any, path: list[str | int]) -> tuple[bool, Any]:
    curr = data
    for elem in path:
        if isinstance(curr, dict) and str(elem) in curr:
            curr = curr[str(elem)]
        elif isinstance(curr, list) and isinstance(elem, int) and 0 <= elem < len(curr):
            curr = curr[elem]
        else:
            return False, None
    return True, curr


def parse_target_observations(
    observations_content: Path | dict,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Extract parsed state and read observations from target-observations.yaml data.

    Accepts a path to the YAML file or an already-parsed document dict.
    Observation content may be a JSON string (the producer's shape, marked
    with ``content_format: json``) or an inline mapping.
    """
    if isinstance(observations_content, Path):
        raw = yaml.safe_load(observations_content.read_text(encoding="utf-8"))
    elif isinstance(observations_content, dict):
        raw = observations_content
    else:
        raise TypeError("observations must be a Path or a parsed dict")

    if not isinstance(raw, dict):
        return None, []

    state_dict: dict[str, Any] | None = None
    read_list: list[dict[str, Any]] = []

    for obs in raw.get("observations", []):
        if not isinstance(obs, dict):
            continue
        kind = obs.get("kind")
        content_raw = obs.get("content")
        if isinstance(content_raw, str):
            try:
                content = json.loads(content_raw)
            except Exception:
                content = content_raw
        else:
            content = content_raw

        if kind == "state" and state_dict is None:
            if isinstance(content, dict):
                state_dict = content
        elif kind == "read":
            entry = {
                "source_name": obs.get("source_name")
                or obs.get("source_description", ""),
                "content": content,
                "raw_text": json.dumps(content)
                if not isinstance(content, str)
                else content,
            }
            read_list.append(entry)

    return state_dict, read_list


def check_gold_case_applicability(
    case: GoldCase,
    observations_source: Path | dict | None,
) -> tuple[bool, list[str]]:
    """Check whether a gold case's required facts hold in the target observations.

    Returns (applicable, failing_reasons).
    """
    if observations_source is None:
        return True, []

    state, reads = parse_target_observations(observations_source)
    failing: list[str] = []

    if case.state_facts:
        if state is None:
            failing.append("TARGET-STATE observation is missing")
        else:
            for fact in case.state_facts:
                found, actual = _resolve_path(state, fact.path)
                if not found:
                    failing.append(f"state path {fact.path} not found")
                elif actual != fact.value:
                    failing.append(
                        f"state path {fact.path} expected {fact.value!r} but got {actual!r}"
                    )

    for pfact in case.policy_facts:
        matched = False
        for r in reads:
            if pfact.source_name and pfact.source_name != r["source_name"]:
                continue
            if pfact.content_contains in r["raw_text"]:
                matched = True
                break
        if not matched:
            failing.append(
                f"policy snippet containing {pfact.content_contains!r} from {pfact.source_name} not found"
            )

    return (len(failing) == 0, failing)

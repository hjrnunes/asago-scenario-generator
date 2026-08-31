#!/usr/bin/env python3
"""Independent QA for the Phase 4 hybrid projection-set artifact.

The reader below intentionally uses only PyYAML and the standard library.  It
does not import the application package or call a project serializer; the
purpose is to catch an artifact that only passes because its producer trusts
its own digest implementation.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import socket
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tests" / "fixtures" / "hybrid-scenario-projection-set.yaml"
FEATURE = ROOT / "features" / "hybrid_scenario_projection.feature"
COMPATIBILITY_FEATURE = (
    ROOT / "features" / "taxonomy_obligation_planner_compatibility.feature"
)

QA_MODULES = Path(__file__).resolve().parents[1]
if str(QA_MODULES) not in sys.path:
    sys.path.insert(0, str(QA_MODULES))

from qa_harness import QARunner  # noqa: E402


class UniqueLoader(yaml.SafeLoader):
    """Safe loader that rejects duplicate YAML mapping keys."""


def _mapping(loader: UniqueLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    """Construct a mapping without silently overwriting duplicate keys."""
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _mapping,
)


def canonical(value: Any) -> Any:
    """Normalize the JSON-compatible values used by the contract digest."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        entries = [(canonical(key), canonical(item)) for key, item in value.items()]
        keys = [key for key, _item in entries]
        if any(not isinstance(key, str) for key in keys):
            raise ValueError("canonical mappings require string keys")
        if len(keys) != len(set(keys)):
            raise ValueError("canonical mapping has colliding keys")
        return {key: item for key, item in sorted(entries, key=lambda pair: pair[0])}
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("canonical JSON rejects non-finite numbers")
    return value


def framed_digest(domain: str, payload: Any) -> str:
    """Compute the version-framed digest independently of the app models."""
    body = json.dumps(
        canonical(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain.encode("utf-8") + b"\0" + body).hexdigest()


def semantic_digest(record: dict[str, Any], domain: str) -> str:
    """Hash a record after removing only its own semantic digest."""
    payload = dict(record)
    payload.pop("semantic_digest", None)
    return framed_digest(domain, payload)


def derived_id(record: dict[str, Any], domain: str, prefix: str, id_field: str) -> str:
    """Recompute one content-addressed ID using the contract recipe."""
    payload = dict(record)
    payload.pop("semantic_digest", None)
    payload.pop(id_field, None)
    return prefix + framed_digest(domain, payload)


def pin_key(pin: dict[str, Any]) -> tuple[str, ...]:
    """Return the canonical ordering key for one serialized source pin."""
    if pin["kind"] == "artifact":
        value = pin["pin"]
        return (
            "artifact",
            pin["role"],
            value["artifact_id"],
            value["schema_version"],
            value["semantic_digest"],
        )
    value = pin["pin"]
    return (
        "taxonomy",
        pin["role"],
        pin["taxonomy_id"],
        value["release"],
        value["digest"],
    )


def artifact_pin_key(value: dict[str, Any]) -> tuple[str, ...]:
    """Return the identity/digest key for an unlabelled artifact pin."""
    return (
        value["artifact_id"],
        value["schema_version"],
        value["semantic_digest"],
    )


def _acyclic(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> bool:
    """Check the causal edge list for endpoint, order, duplicate, and cycles."""
    by_id = {node["node_id"]: node for node in nodes}
    if len(by_id) != len(nodes) or len({edge["edge_id"] for edge in edges}) != len(
        edges
    ):
        return False
    semantic: set[tuple[str, str, str]] = set()
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        source = by_id.get(edge["from_node_id"])
        target = by_id.get(edge["to_node_id"])
        if source is None or target is None:
            return False
        if source["ordinal"] >= target["ordinal"]:
            return False
        key = (edge["from_node_id"], edge["to_node_id"], edge["kind"])
        if key in semantic:
            return False
        semantic.add(key)
        adjacency.setdefault(edge["from_node_id"], []).append(edge["to_node_id"])

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> bool:
        if node_id in visiting:
            return False
        if node_id in visited:
            return True
        visiting.add(node_id)
        if any(not visit(child) for child in adjacency.get(node_id, ())):
            return False
        visiting.remove(node_id)
        visited.add(node_id)
        return True

    return all(visit(node["node_id"]) for node in nodes)


def _projection_errors(projection: dict[str, Any]) -> list[str]:
    """Independently verify one projection and every nested bridge record."""
    errors: list[str] = []
    expected_fields = {
        "schema_version",
        "projection_id",
        "relation_id",
        "obligation_id",
        "risk_id",
        "attack_pattern_id",
        "selected_candidate_id",
        "ica_slot_id",
        "ica_id",
        "exec_candidate_id",
        "relation_kind",
        "evidence_class",
        "causal_projection",
        "mechanism_projection",
        "bridge_links",
        "confirmed_review",
        "risk_trace",
        "source_pins",
        "semantic_digest",
    }
    if set(projection) != expected_fields:
        errors.append("projection fields are not closed")
    if (
        projection["relation_id"] != projection["confirmed_review"]["relation_id"]
        or projection["obligation_id"]
        != projection["mechanism_projection"]["obligation_id"]
        or projection["selected_candidate_id"]
        != projection["mechanism_projection"]["selected_candidate_id"]
        or projection["ica_id"] != projection["causal_projection"]["ica_id"]
        or projection["exec_candidate_id"]
        != projection["causal_projection"]["exec_candidate_id"]
    ):
        errors.append("projection authority identity mismatch")
    checks = (
        (projection, "asago.hybrid-scenario-projection.v1"),
        (
            projection["causal_projection"],
            "asago.stpa-causal-projection.v1",
        ),
        (
            projection["mechanism_projection"],
            "asago.taxonomy-mechanism-projection.v1",
        ),
        (
            projection["confirmed_review"],
            "asago.confirmed-coverage-review.v1",
        ),
        (
            projection["confirmed_review"]["mechanism_evidence"],
            "asago.mechanism-evidence-attestation.v1",
        ),
    )
    for record, domain in checks:
        if semantic_digest(record, domain) != record.get("semantic_digest"):
            errors.append(f"digest mismatch in {domain}")

    identities = (
        (
            projection,
            "asago.hybrid-scenario-projection.v1.identity.v1",
            "projection:v1:",
            "projection_id",
        ),
        (
            projection["causal_projection"],
            "asago.stpa-causal-projection.v1",
            "causal:v1:",
            "causal_projection_id",
        ),
        (
            projection["mechanism_projection"],
            "asago.taxonomy-mechanism-projection.v1",
            "mech:v1:",
            "mechanism_projection_id",
        ),
    )
    for record, domain, prefix, field in identities:
        if derived_id(record, domain, prefix, field) != record.get(field):
            errors.append(f"identity mismatch in {field}")

    allowed_endpoints = {
        "corrupts_process_model": (
            {"mechanism_step", "mechanism_precondition", "mechanism_postcondition"},
            {"process_model"},
        ),
        "delays_feedback": (
            {"mechanism_step", "mechanism_postcondition"},
            {"feedback"},
        ),
        "perturbs_control_action": (
            {"mechanism_step", "mechanism_postcondition"},
            {"control_action"},
        ),
        "enables_unsafe_action": (
            {"mechanism_step", "mechanism_postcondition"},
            {"uca", "ica"},
        ),
        "realizes_unsafe_outcome": (
            {"mechanism_step", "mechanism_postcondition"},
            {"hazard", "loss"},
        ),
    }
    for bridge in projection["bridge_links"]:
        expected = allowed_endpoints.get(bridge["bridge_kind"])
        if expected is None or (
            bridge["taxonomy_endpoint"]["kind"] not in expected[0]
            or bridge["stpa_endpoint"]["kind"] not in expected[1]
        ):
            errors.append("invalid fixed bridge endpoint")
        if bridge["relation_id"] != projection["relation_id"]:
            errors.append("bridge relation mismatch")
        if semantic_digest(bridge, "asago.hybrid-bridge-link.v1") != bridge.get(
            "semantic_digest"
        ):
            errors.append("bridge digest mismatch")
        if derived_id(
            bridge,
            "asago.hybrid-bridge-link.v1",
            "bridge:v1:",
            "bridge_id",
        ) != bridge.get("bridge_id"):
            errors.append("bridge identity mismatch")
        for evidence in bridge["evidence"]:
            if semantic_digest(
                evidence, "asago.hybrid-bridge-evidence.v1"
            ) != evidence.get("semantic_digest"):
                errors.append("bridge evidence digest mismatch")
            if derived_id(
                evidence,
                "asago.hybrid-bridge-evidence.v1",
                "bridge-evidence:v1:",
                "evidence_id",
            ) != evidence.get("evidence_id"):
                errors.append("bridge evidence identity mismatch")
    if not _acyclic(
        projection["causal_projection"]["nodes"],
        projection["causal_projection"]["edges"],
    ):
        errors.append("causal graph is not an ordered DAG")
    return errors


def _identity_accounting(data: dict[str, Any]) -> bool:
    """Require disjoint and complete relation accounting, allowing mixed sets."""
    projected = [item["relation_id"] for item in data["projections"]]
    excluded = [item["relation_id"] for item in data["exclusions"]]
    return (
        len(projected) == len(set(projected))
        and len(excluded) == len(set(excluded))
        and set(projected).isdisjoint(excluded)
        and len(set(projected) | set(excluded)) == len(projected) + len(excluded)
    )


def _pin_closure(data: dict[str, Any]) -> bool:
    """Require every record's full exact pin union and all nested pins."""
    records = (*data["projections"], *data["exclusions"], *data["diagnostics"])
    set_pins = data["source_pins"]
    record_pins = {
        pin_key(pin): pin for record in records for pin in record.get("source_pins", ())
    }
    if set_pins != sorted(set_pins, key=pin_key):
        return False
    if [pin_key(pin) for pin in set_pins] != sorted(record_pins):
        return False
    artifacts = {
        artifact_pin_key(pin["pin"]) for pin in set_pins if pin["kind"] == "artifact"
    }
    for record in records:
        traces = record.get("risk_trace", record.get("trace", ()))
        if any(
            artifact_pin_key(trace["artifact_pin"]) not in artifacts for trace in traces
        ):
            return False
        for bridge in record.get("bridge_links", ()):
            if any(
                artifact_pin_key(evidence["artifact_pin"]) not in artifacts
                for evidence in bridge["evidence"]
            ):
                return False
    return True


def _artifact_errors(data: Any) -> list[str]:
    """Validate a whole serialized artifact without application imports."""
    if not isinstance(data, dict):
        return ["artifact is not a mapping"]
    errors: list[str] = []
    expected_fields = {
        "schema_version",
        "assessment_digest",
        "projection_contract_version",
        "source_pins",
        "projections",
        "exclusions",
        "diagnostics",
        "evidence_class",
        "semantic_digest",
    }
    try:
        if set(data) != expected_fields:
            errors.append("set fields are not closed")
        if semantic_digest(data, "asago.hybrid-scenario-projection-set.v1") != data.get(
            "semantic_digest"
        ):
            errors.append("set semantic digest mismatch")
        if not _identity_accounting(data):
            errors.append("relation identity accounting mismatch")
        if not _pin_closure(data):
            errors.append("source pin closure mismatch")
        for projection in data["projections"]:
            errors.extend(_projection_errors(projection))
        for exclusion in data["exclusions"]:
            if (
                len(exclusion["unit_identity"]) != 5
                or exclusion["unit_identity"][0] != exclusion["relation_id"]
            ):
                errors.append("exclusion unit identity mismatch")
            if derived_id(
                exclusion,
                "asago.hybrid-scenario-projection-set.v1",
                "exclusion:v1:",
                "exclusion_id",
            ) != exclusion.get("exclusion_id"):
                errors.append("exclusion identity mismatch")
        for diagnostic in data["diagnostics"]:
            if derived_id(
                diagnostic,
                "asago.hybrid-scenario-projection-set.v1",
                "diagnostic:v1:",
                "diagnostic_id",
            ) != diagnostic.get("diagnostic_id"):
                errors.append("diagnostic identity mismatch")
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"malformed closed artifact: {exc}")
    return errors


def _candidate_binding_match(
    candidate_projection: dict[str, Any], authority_projection: dict[str, Any]
) -> bool:
    """Compare exact candidate identity and binding inventory to known authority."""
    candidate = candidate_projection["mechanism_projection"]
    authority = authority_projection["mechanism_projection"]
    return (
        candidate_projection["selected_candidate_id"]
        == authority_projection["selected_candidate_id"]
        and candidate["selected_candidate_id"] == authority["selected_candidate_id"]
        and candidate["projection"]["bindings"] == authority["projection"]["bindings"]
    )


def _check_feature_contract(runner: QARunner) -> None:
    """Check source-level closed vocabulary and compatibility claims independently."""
    expected_reasons = (
        "relation_not_accepted",
        "relation_not_coverage",
        "relation_unresolved",
        "relation_contradictory",
        "challenge_outcome_not_correspondence",
        "obligation_not_applicable",
        "candidate_materialization_missing",
        "candidate_not_projectable",
        "candidate_binding_mismatch",
        "stpa_identity_missing",
        "stpa_identity_mismatch",
        "resource_link_mismatch",
        "bridge_missing",
        "bridge_unreviewed",
        "bridge_not_authoritative",
        "bridge_invalid_endpoint",
        "bridge_duplicate",
        "ordering_cycle",
        "ordering_violation",
    )
    feature_text = FEATURE.read_text(encoding="utf-8")
    section = feature_text.split(
        "Scenario Outline: every exclusion reason is a closed typed contract value",
        1,
    )[-1].split("Scenario: the exclusion vocabulary has no additions or omissions", 1)[
        0
    ]
    rows = []
    for line in section.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = tuple(cell.strip() for cell in line.strip().strip("|").split("|"))
        if len(cells) == 1 and cells[0] != "reason":
            rows.append(cells[0])
    runner.check(
        "feature closed exclusion inventory",
        tuple(rows) == expected_reasons,
    )
    runner.check(
        "feature names the dual ICA/shared EXEC case",
        "two ICA identities sharing one EXEC remain distinct projections"
        in feature_text,
    )
    runner.check(
        "feature treats process-model and feedback bridges as valid with nodes",
        "| corrupts_process_model   | process_model  | projection | 1" in feature_text
        and "| delays_feedback          | feedback       | projection | 1"
        in feature_text,
    )

    compatibility_text = COMPATIBILITY_FEATURE.read_text(encoding="utf-8")
    compatibility_pairs = {
        tuple(cell.strip() for cell in line.strip().strip("|").split("|")[:2])
        for line in compatibility_text.splitlines()
        if line.strip().startswith("|") and ("generate" in line or "stpa-run" in line)
    }
    runner.check(
        "ordinary workflow compatibility rows",
        {("taxonomy/risk", "generate"), ("STPA", "stpa-run")} <= compatibility_pairs,
    )
    runner.check(
        "ordinary compatibility has no Phase 4 flags",
        "phase4" not in compatibility_text.lower()
        and "hybrid-scenario" not in compatibility_text.lower(),
    )


def _check_artifact(runner: QARunner, path: Path) -> None:
    """Run independent checks against the committed YAML fixture."""
    runner.check(
        "exact artifact filename", path.name == "hybrid-scenario-projection-set.yaml"
    )
    try:
        data = yaml.load(path.read_bytes(), Loader=UniqueLoader)
    except Exception as exc:  # pragma: no cover - visible QA failure detail
        runner.record("strict YAML parsing", False, str(exc))
        return
    runner.check("strict YAML parsing", isinstance(data, dict))
    runner.check(
        "set schema and evidence class",
        data.get("schema_version") == "hybrid-scenario-projection-set-v1"
        and data.get("projection_contract_version") == "hybrid-scenario-projection-v1"
        and data.get("evidence_class") == "normative_bookkeeping_fixture",
    )
    runner.check(
        "single complete projection",
        len(data["projections"]) == 1
        and not data["exclusions"]
        and not data["diagnostics"],
    )
    projection_errors = [
        error
        for projection in data["projections"]
        for error in _projection_errors(projection)
    ]
    runner.check("all projection records independently verified", not projection_errors)
    runner.check(
        "exact five-part identity",
        all(
            (
                projection["relation_id"],
                projection["obligation_id"],
                projection["selected_candidate_id"],
                projection["ica_id"],
                projection["exec_candidate_id"],
            )
            == (
                projection["confirmed_review"]["relation_id"],
                projection["mechanism_projection"]["obligation_id"],
                projection["mechanism_projection"]["selected_candidate_id"],
                projection["causal_projection"]["ica_id"],
                projection["causal_projection"]["exec_candidate_id"],
            )
            for projection in data["projections"]
        ),
    )
    forbidden = {
        "score",
        "coverage_rate",
        "readiness",
        "readiness_verdict",
        "admission_status",
        "execution_result",
        "scenario_id",
    }
    all_keys = {key for record in (data, *data["projections"]) for key in record}
    runner.check(
        "no score/readiness/execution claims", not forbidden.intersection(all_keys)
    )
    runner.check(
        "independent review and mechanism evidence",
        all(
            artifact_pin_key(projection["confirmed_review"]["review_artifact_pin"])
            != artifact_pin_key(
                projection["confirmed_review"]["mechanism_evidence"]["artifact_pin"]
            )
            and not {
                artifact_pin_key(item["artifact_pin"])
                for bridge in projection["bridge_links"]
                for item in bridge["evidence"]
            }.intersection(
                {
                    artifact_pin_key(
                        projection["confirmed_review"]["review_artifact_pin"]
                    ),
                    artifact_pin_key(
                        projection["confirmed_review"]["mechanism_evidence"][
                            "artifact_pin"
                        ]
                    ),
                }
            )
            for projection in data["projections"]
        ),
    )
    runner.check("exact no-overlap identity accounting", _identity_accounting(data))
    runner.check("full exact source-pin closure", _pin_closure(data))
    runner.check("whole artifact independently valid", not _artifact_errors(data))
    runner.check(
        "application package not imported",
        not any(name.startswith("asago_scenario_generator") for name in sys.modules),
    )
    runner.check(
        "live model opt-in absent",
        os.environ.get("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE") != "1",
    )
    runner.check("no provider/network calls", not hasattr(socket, "_asago_calls"))


def _load_strict(path: Path) -> Any:
    """Load one corpus document with the independent duplicate-key reader."""
    return yaml.load(path.read_bytes(), Loader=UniqueLoader)


def _check_corpus(runner: QARunner) -> None:
    """Generate public-seam corpus files, then inspect them independently."""
    with tempfile.TemporaryDirectory(prefix="asago-phase4-qa-") as directory:
        corpus = Path(directory)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            filter(
                None,
                (
                    str(ROOT / "acceptance"),
                    str(ROOT),
                    environment.get("PYTHONPATH", ""),
                ),
            )
        )
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    "from runtime_features.hybrid_scenario_projection import emit_qa_corpus; "
                    "import sys; emit_qa_corpus(Path(sys.argv[1]))"
                ),
                str(corpus),
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        runner.check("public corpus generation", result.returncode == 0)
        if result.returncode != 0:
            return
        mixed = _load_strict(corpus / "mixed" / "hybrid-scenario-projection-set.yaml")
        related = _load_strict(
            corpus / "related" / "hybrid-scenario-projection-set.yaml"
        )
        runner.check(
            "valid mixed projection/exclusion accounting",
            not _artifact_errors(mixed)
            and len(mixed["projections"]) == 1
            and len(mixed["exclusions"]) == 1
            and _identity_accounting(mixed),
        )
        runner.check(
            "nonprojectable candidate remains excluded",
            {item["reason"] for item in mixed["exclusions"]}
            == {"candidate_not_projectable"},
        )
        runner.check(
            "related-resource relation remains excluded",
            not _artifact_errors(related)
            and not related["projections"]
            and {item["reason"] for item in related["exclusions"]}
            == {"relation_not_coverage"},
        )
        authority_projection = next(iter(_load_strict(FIXTURE)["projections"]))
        substituted = _load_strict(corpus / "substituted_candidate.yaml")
        substituted_projection = next(iter(substituted["projections"]))
        runner.check(
            "substituted candidate artifact rejected",
            bool(_artifact_errors(substituted))
            and not _candidate_binding_match(
                substituted_projection, authority_projection
            ),
        )
        cross_binding = _load_strict(corpus / "cross_candidate_binding.yaml")
        cross_binding_projection = next(iter(cross_binding["projections"]))
        runner.check(
            "cross-candidate binding artifact rejected",
            bool(_artifact_errors(cross_binding))
            and not _candidate_binding_match(
                cross_binding_projection, authority_projection
            ),
        )
        runner.check(
            "full source-pin tamper rejected",
            bool(
                _artifact_errors(_load_strict(corpus / "full_source_pin_tamper.yaml"))
            ),
        )
        runner.check(
            "Phase 2 matrices remain byte-identical",
            (corpus / "phase2-base-before.yaml").read_bytes()
            == (corpus / "phase2-base-after.yaml").read_bytes()
            and (corpus / "phase2-related-before.yaml").read_bytes()
            == (corpus / "phase2-related-after.yaml").read_bytes(),
        )
        runner.check(
            "base fixture exclusion limitation is explicit",
            not _load_strict(FIXTURE)["exclusions"]
            and bool(mixed["exclusions"])
            and bool(related["exclusions"]),
        )


def main() -> int:
    """Run and report the independent fixture checks."""
    runner = QARunner()
    _check_artifact(runner, FIXTURE)
    _check_corpus(runner)
    _check_feature_contract(runner)
    return runner.summary()


if __name__ == "__main__":
    raise SystemExit(main())

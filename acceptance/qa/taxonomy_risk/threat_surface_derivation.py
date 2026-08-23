#!/usr/bin/env python3
"""Executable end-to-end QA suite for taxonomy threat-surface derivation.

Mirrors ``threat_surface_derivation.md`` (QA-TSDS-01..08).  Drives only the
``asago-scenario-generator generate`` CLI against a deterministic loopback
OpenAI-compatible fixture endpoint and inspects CLI stdout, stderr, exit
status, and the published ``threat-surface.yaml`` per run.  Never imports
project modules and never calls ``determine_threat_surface`` directly; never
sets ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE``.

Determinism
  - The LLM fixture responds from the request prompt alone (handle parsing),
    so drafts are deterministic.
  - ``PYTHONHASHSEED=0`` is pinned for the CLI subprocess.
  - Candidate filter calls run concurrently in the runner; the fixture
    therefore accepts exactly one *pattern* per run (pinned per variant)
    instead of the first-arriving call.  Accepted patterns below were
    verified to admit scenario candidates for their variant's fixtures.

Known deviations and pinned interpretations (reported, not silently bent)
  1. QA-TSDS-07 expects exit 0 for empty card sets, but the CLI exit
     contract pins exit 1 when zero candidates are admitted
     (``test_cli_outcome.py``: (``completed``, 0) -> 1), and the Gherkin
     scenario 07 pins only the empty surface.  This suite asserts the
     surface content and records the observed exit code as a documented
     contradiction between the QA procedure and the unit tests.
  2. QA-TSDS-05's attack-pattern expectation ([AP-T1-01, AP-T1-02,
     AP-T12-01]) assumes a fixture-authored pattern scope.  The CLI reads
     the committed attack-pattern catalogs, where AP-T1-01 and AP-T1-03
     share identical prerequisite gates and AP-T12-01/AP-T12-03 share
     theirs, so the fixture can only gate them in pairs.  The actual
     deterministic union is asserted and the deviation is reported.
  3. QA-TSDS-04A's suggested KC set (KC5.1 alone) both drops the T2 attack
     patterns (they require a KC6.x code) and activates the KC6 ATLAS gate
     (AML.T0053 dropped), which would contradict the procedure's own
     expected atlas [AML.T0015, AML.T0053, AML.T0054].  KC5.1+KC6.4 is used
     instead: same in-scope threat semantics for the card, patterns kept,
     gate inactive, expected atlas unchanged.
  4. QA-TSDS-01 variant 2 (and Gherkin scenario-01 example 2) expects
     [T6, T11], but every KC sub-code that gates T11 (KC6.2.2, KC6.4,
     KC6.5) also gates T2 (Tool Misuse), so with the committed
     kc-threat-mapping.yaml the CLI path always keeps T2 in scope when
     T11 is.  The acceptance harness realizes [T6, T11] only through a
     fixture KC mapping (KCX-TSDS).  This suite pins the realizable
     [T6, T11, T2] and reports the deviation.

Run with::

    uv run python acceptance/qa/taxonomy_risk/threat_surface_derivation.py

Exit status is 0 only when every pinned assertion passes.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]

QA_PIPELINE_ENV = "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"

# ---------------------------------------------------------------------------
# LLM fixture: loopback OpenAI-compatible endpoint
# ---------------------------------------------------------------------------

PROSE = "Deterministic QA fixture prose with sufficient detail."
FILTER_RE = re.compile(r"\*\*Candidate handle:\*\* `(c\d+)`")
ACTOR_CHOICE_RE = re.compile(r"^- (ac\d+): actor=([^;]+); capability=(.+)$", re.M)
REGION_RE = re.compile(r"^- (r\d+):$", re.M)


def _schema_name(request: dict) -> str:
    response_format = request.get("response_format") or {}
    return str((response_format.get("json_schema") or {}).get("name", ""))


class FixtureHandler(BaseHTTPRequestHandler):
    """Deterministic drafts for every generation stage."""

    protocol_version = "HTTP/1.1"
    accepted_once = False

    def reset() -> None:  # noqa: N805
        FixtureHandler.accepted_once = False

    def log_message(self, *args) -> None:  # noqa: N802
        pass

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.endswith("/chat/completions"):
            self.send_error(404)
            return
        try:
            self._handle()
        except Exception:  # pragma: no cover - fixture robustness
            self.send_error(500)
            return

    def _handle(self) -> None:  # noqa: C901
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size) or b"{}")
        user_prompt = "\n".join(
            str(message.get("content", ""))
            for message in request.get("messages", [])
            if message.get("role") == "user"
        )
        schema = _schema_name(request)
        model = str(request.get("model", "qa-fixture"))

        if schema.startswith("FilterMapDraftV3For"):
            handles = FILTER_RE.findall(user_prompt)
            if not handles:
                self.send_error(500)
                return
            accept_index = int(os.environ.get("ACCEPT_INDEX", "0"))
            accept_pattern = os.environ.get("ACCEPT_PATTERN", "")
            name_match = re.search(r"\*\*Name:\*\* ([^\n]+)", user_prompt)
            pattern_name = name_match.group(1) if name_match else "?"
            matches = not accept_pattern or pattern_name == accept_pattern
            accepted = matches and not FixtureHandler.accepted_once
            if matches:
                FixtureHandler.accepted_once = True
            body_map = {}
            for i, handle in enumerate(handles):
                body_map[handle] = {
                    "relevant": accepted and i == accept_index,
                    "rationale": "Deterministic QA fixture verdict.",
                }
            content = json.dumps(body_map)
        elif schema.startswith("ActorDraftV3For"):
            choices = ACTOR_CHOICE_RE.findall(user_prompt)
            if not choices:
                self.send_error(500)
                return
            levels = {"novice": 0, "intermediate": 1, "advanced": 2, "expert": 3}
            handle = max(choices, key=lambda c: levels.get(c[2].strip(), -1))[0]
            content = json.dumps(
                {
                    "actor_choice_handle": handle,
                    "beliefs": [PROSE],
                    "desires": [PROSE],
                    "intentions": [PROSE],
                    "resource_handles": [],
                    "rationale": "Deterministic QA fixture actor draft.",
                }
            )
        elif schema.startswith("NarrativeDraftV3For"):
            region_map: dict[str, list[str]] = {}
            current = None
            for line in user_prompt.splitlines():
                stripped = line.strip()
                region_match = re.match(r"^- (r\d+):$", stripped)
                if region_match:
                    current = region_match.group(1)
                    region_map[current] = []
                    continue
                if current is not None:
                    step_match = re.match(r"^- (s\d+):", stripped)
                    if step_match:
                        region_map[current].append(step_match.group(1))
            if not region_map:
                self.send_error(500)
                return
            regions_body = {}
            for region, handles in region_map.items():
                regions_body[region] = [
                    {
                        "step_handles": [handle],
                        "action": f"Deterministic action for {handle}",
                        "consequence": f"Deterministic consequence for {handle}",
                        "transition": None,
                    }
                    for handle in handles
                ]
            content = json.dumps(
                {
                    "title": "Deterministic QA narrative title",
                    "summary": "Deterministic QA narrative summary.",
                    "regions": regions_body,
                }
            )
        elif schema.startswith("BehaviorDraftV2For"):

            def _embedded_array(label: str):
                match = re.search(label + ":\n", user_prompt)
                if not match:
                    return None
                value, _end = json.JSONDecoder().raw_decode(user_prompt, match.end())
                return value

            actions = _embedded_array("Action handles")
            assertions = _embedded_array("Required assertion handles")
            if actions is None or assertions is None:
                self.send_error(500)
                return
            steps = []
            for action in actions:
                examples = {}
                for param in action.get("parameters", []) or []:
                    if not param.get("required", True):
                        continue
                    value_type = param.get("value_type", "string")
                    examples[param["name"]] = {
                        "string": "fixture-value",
                        "boolean": True,
                        "integer": 1,
                        "number": 1.0,
                    }[value_type]
                steps.append(
                    {
                        "kind": "action",
                        "handle": action["handle"],
                        "text": f"Deterministic fixture action for {action['handle']}.",
                        "examples": examples,
                    }
                )
            for assertion in assertions:
                steps.append(
                    {
                        "kind": "assertion",
                        "handle": assertion["handle"],
                        "text": (
                            f"Deterministic fixture assertion for {assertion['handle']}."
                        ),
                        "examples": {},
                    }
                )
            content = json.dumps(
                {
                    "scenarios": [
                        {
                            "title": "Deterministic QA behavior scenario",
                            "steps": steps,
                        }
                    ]
                }
            )
        elif schema.startswith("AttackTreeDraftV3For"):
            tree_match = re.search(
                r"Canonical leaf inventory \(respond with handles only\):\n(.+)",
                user_prompt,
                re.S,
            )
            if not tree_match:
                self.send_error(500)
                return
            try:
                inventory = json.loads(tree_match.group(1))
            except json.JSONDecodeError:
                self.send_error(500)
                return
            handles = [item["handle"] for item in inventory]
            content = json.dumps(
                {
                    "root_label": "Deterministic QA attack root",
                    "root_description": "Deterministic QA attack tree.",
                    "groups": [
                        {
                            "label": "Deterministic QA group",
                            "description": "Deterministic QA group.",
                            "leaf_handles": handles,
                        }
                    ],
                }
            )
        else:
            self.send_error(500)
            return

        body = json.dumps(
            {
                "id": f"qa-{schema}",
                "object": "chat.completion",
                "created": 0,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": content,
                            "refusal": None,
                        },
                        "logprobs": None,
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Fixture inputs
# ---------------------------------------------------------------------------

BASE_CARD = "atlas-prompt-injection"
MEMORY_CARD = "atlas-memory-poisoning"
ORPHAN_CARD = "atlas-orphan-risk"

CARD_NAMES = {
    BASE_CARD: "Prompt injection",
    MEMORY_CARD: "Memory poisoning",
    ORPHAN_CARD: "Orphaned risk signal",
}

_CARD_TEXT = {
    "threat": "An attacker submits crafted input to influence the AI assistant.",
    "vulnerability": "Instruction-data confusion.",
    "consequence": "The agent follows attacker instructions.",
    "impact": "Unauthorized behavior.",
}


def _variant_specs() -> dict[str, dict]:
    """Fixtures per QA procedure variant (see threat_surface_derivation.md)."""
    prompt_card = [BASE_CARD]
    prompt_sssom = [
        [BASE_CARD, "llm01-prompt-injection"],
        [BASE_CARD, "llm06-excessive-agency"],
    ]
    llm01_to_t = [
        {"source": "T6", "target": "LLM01"},
        {"source": "T11", "target": "LLM01"},
        {"source": "T2", "target": "LLM06"},
        {"source": "T13", "target": "LLM06"},
    ]
    t2_t_atlas = [{"source": "T2", "targets": ["AML.T0015", "AML.T0053"]}]
    direct_t7_t8 = [
        {"source": "T7", "targets": ["AML.T0054", "AML.T0015", "AML.T0053"]},
        {"source": "T8", "targets": ["AML.T0056", "AML.T0057"]},
    ]
    direct_t7_t15 = [
        {"source": "T7", "targets": ["AML.T0050"]},
        {"source": "T15", "targets": ["AML.T0050"]},
    ]
    return {
        # QA-TSDS-01: three-hop chain; variant 1 gates T2,T6,T11,T13;
        # variant 2 gates T6,T11 only.
        "01a": {
            "cards": prompt_card,
            "sssom": prompt_sssom,
            "t_to_llm": llm01_to_t,
            "t_to_atlas": [],
            "t_to_asi": [],
            "t_direct": [],
            "kc_codes": ["KC1.1", "KC6.4", "KC2.3"],
            "accept": "Reflection loop resource exhaustion trap",
        },
        "01b": {
            "cards": prompt_card,
            "sssom": prompt_sssom,
            "t_to_llm": llm01_to_t,
            "t_to_atlas": [],
            "t_to_asi": [],
            "t_direct": [],
            "kc_codes": ["KC1.1", "KC6.4"],
            "accept": "Reflection loop resource exhaustion trap",
        },
        # QA-TSDS-02: orphan card stays governance-only.
        "02": {
            "cards": [ORPHAN_CARD],
            "sssom": [],
            "t_to_llm": [],
            "t_to_atlas": [],
            "t_to_asi": [],
            "t_direct": [],
            "kc_codes": ["KC1.1", "KC6.4", "KC2.3"],
            "accept": "",
        },
        # QA-TSDS-03: out-of-scope LLM mapping stays governance-only.
        "03": {
            "cards": prompt_card,
            "sssom": [[BASE_CARD, "llm01-prompt-injection"]],
            "t_to_llm": [{"source": "T11", "target": "LLM01"}],
            "t_to_atlas": [],
            "t_to_asi": [],
            "t_direct": [],
            "kc_codes": ["KC1.1", "KC2.2"],
            "accept": "",
        },
        # QA-TSDS-04: direct-path join on shared ATLAS technique only.
        # Pinned interpretation 3: KC5.1 alone would drop the T2 patterns
        # (KC6.x required) and activate the KC6 gate; KC5.1+KC6.4 keeps the
        # procedure's expected content.
        "04a": {
            "cards": prompt_card,
            "sssom": [[BASE_CARD, "llm06-excessive-agency"]],
            "t_to_llm": [{"source": "T2", "target": "LLM06"}],
            "t_to_atlas": t2_t_atlas + direct_t7_t8,
            "t_to_asi": [],
            "t_direct": [
                {"source": "T7", "targets": []},
                {"source": "T8", "targets": []},
            ],
            "kc_codes": ["KC5.1", "KC6.4"],
            "zones": ["input", "reasoning", "tool_execution"],
            "accept": "Tool hijacking via prompt injection",
        },
        "04b": {
            "cards": prompt_card,
            "sssom": [[BASE_CARD, "llm06-excessive-agency"]],
            "t_to_llm": [{"source": "T2", "target": "LLM06"}],
            "t_to_atlas": t2_t_atlas + direct_t7_t8,
            "t_to_asi": [],
            "t_direct": [
                {"source": "T7", "targets": []},
                {"source": "T8", "targets": []},
            ],
            "kc_codes": ["KC6.1.1", "KC4.3"],
            "zones": ["input", "reasoning", "tool_execution"],
            "accept": "Tool hijacking via prompt injection",
        },
        # QA-TSDS-05: unioned ID lists.  Pinned interpretation 2: the CLI
        # pattern scope is data-driven; AP-T1-01/AP-T1-03 and
        # AP-T12-01/AP-T12-03 share gates, so the observed deterministic
        # union (asserted below) deviates from the procedure's literal list.
        "05": {
            "cards": [MEMORY_CARD],
            "sssom": [
                [MEMORY_CARD, "llm04-vulnerable-plugin-design"],
                [MEMORY_CARD, "llm08-vector-system-integration"],
            ],
            "t_to_llm": [
                {"source": "T1", "target": "LLM04"},
                {"source": "T12", "target": "LLM04"},
                {"source": "T1", "target": "LLM08"},
                {"source": "T2", "target": "LLM08"},
            ],
            "t_to_atlas": [
                {"source": "T1", "targets": ["AML.T0043", "AML.T0031", "AML.T0020"]},
                {"source": "T12", "targets": ["AML.T0043", "AML.T0031", "AML.T0020"]},
            ],
            "t_to_asi": [
                {"source": "T1", "target": "ASI06"},
                {"source": "T12", "target": "ASI07"},
            ],
            "t_direct": [],
            "kc_codes": [
                "KC4.2",
                "KC4.3",
                "KC6.3.3",
                "KC2.3",
                "KCX-PMEM",
                "KCX-MAGENT",
            ],
            "zones": ["input", "reasoning", "memory", "inter_agent"],
            "memory_mechanisms": [
                {
                    "type": "vector_store",
                    "scope": "shared",
                    "persistence": "long_term",
                    "writable_by_agent": True,
                },
                {
                    "type": "key_value_store",
                    "scope": "shared",
                    "persistence": "long_term",
                    "writable_by_agent": True,
                },
            ],
            "accept": "Persistent memory rule injection",
        },
        # QA-TSDS-06: KC6-gated ATLAS techniques follow the profile KC codes.
        # 06c/06d spot-check a second gated technique (AML.T0070).
        "06a": {
            "cards": prompt_card,
            "sssom": [[BASE_CARD, "llm01-prompt-injection"]],
            "t_to_llm": [{"source": "T6", "target": "LLM01"}],
            "t_to_atlas": [{"source": "T6", "targets": ["AML.T0054", "AML.T0053"]}]
            + direct_t7_t15,
            "t_to_asi": [],
            "t_direct": [
                {"source": "T7", "targets": []},
                {"source": "T15", "targets": []},
            ],
            "kc_codes": ["KC1.1"],
            "accept": "Reflection loop resource exhaustion trap",
        },
        "06b": {
            "cards": prompt_card,
            "sssom": [[BASE_CARD, "llm01-prompt-injection"]],
            "t_to_llm": [{"source": "T6", "target": "LLM01"}],
            "t_to_atlas": [{"source": "T6", "targets": ["AML.T0054", "AML.T0053"]}]
            + direct_t7_t15,
            "t_to_asi": [],
            "t_direct": [
                {"source": "T7", "targets": []},
                {"source": "T15", "targets": []},
            ],
            "kc_codes": ["KC1.1", "KC6.4"],
            "accept": "Reflection loop resource exhaustion trap",
        },
        "06c": {
            "cards": prompt_card,
            "sssom": [[BASE_CARD, "llm01-prompt-injection"]],
            "t_to_llm": [{"source": "T6", "target": "LLM01"}],
            "t_to_atlas": [
                {"source": "T6", "targets": ["AML.T0054", "AML.T0053", "AML.T0070"]}
            ]
            + direct_t7_t15,
            "t_to_asi": [],
            "t_direct": [
                {"source": "T7", "targets": []},
                {"source": "T15", "targets": []},
            ],
            "kc_codes": ["KC1.1"],
            "accept": "Reflection loop resource exhaustion trap",
        },
        "06d": {
            "cards": prompt_card,
            "sssom": [[BASE_CARD, "llm01-prompt-injection"]],
            "t_to_llm": [{"source": "T6", "target": "LLM01"}],
            "t_to_atlas": [
                {"source": "T6", "targets": ["AML.T0054", "AML.T0053", "AML.T0070"]}
            ]
            + direct_t7_t15,
            "t_to_asi": [],
            "t_direct": [
                {"source": "T7", "targets": []},
                {"source": "T15", "targets": []},
            ],
            "kc_codes": ["KC1.1", "KC6.4"],
            "accept": "Reflection loop resource exhaustion trap",
        },
        # QA-TSDS-07: empty card sets yield empty surfaces.  The exit-code
        # expectation (0) contradicts the pinned CLI exit contract (1 when
        # zero candidates are admitted); the recorded mismatch is reported.
        "07a": {
            "cards": [],
            "sssom": [],
            "t_to_llm": [],
            "t_to_atlas": [],
            "t_to_asi": [],
            "t_direct": [],
            "kc_codes": ["KC1.1", "KC6.4", "KC2.3"],
            "accept": "",
        },
        "07b": {
            "cards": [BASE_CARD],
            "sssom": [],
            "t_to_llm": [],
            "t_to_atlas": [],
            "t_to_asi": [],
            "t_direct": [],
            "kc_codes": ["KC1.1", "KC6.4", "KC2.3"],
            "accept": "",
            "taxonomy": "other-taxonomy",
        },
    }


def _write_inputs(fixture_dir: Path, spec: dict) -> None:
    risks = []
    for card_id in spec["cards"]:
        entry = {
            "risk_id": card_id,
            "risk_name": CARD_NAMES.get(card_id, card_id),
            "risk_description": f"Risk description for {card_id}",
            "taxonomy": spec.get("taxonomy", "ibm-risk-atlas"),
            "confidence": 0.99,
            "grounding_confidence": "high",
        }
        entry.update(_CARD_TEXT)
        risks.append(entry)
    (fixture_dir / "risk-extraction.json").write_text(
        json.dumps({"risks": risks}) + "\n", encoding="utf-8"
    )
    rows = []
    for subject, obj in spec["sssom"]:
        rows.append(
            f"{subject}\tibm-risk-atlas\tskos:relatedMatch\t{obj}"
            "\towasp-llm\tsemapv:ManualMappingCuration"
        )
    (fixture_dir / "risk-to-llm.sssom.tsv").write_text(
        "subject_id\tsubject_source\tpredicate_id\tobject_id"
        "\tobject_source\tmapping_justification\n" + "\n".join(rows) + "\n",
        encoding="utf-8",
    )
    cross = {
        "t_to_llm": spec["t_to_llm"],
        "t_to_atlas": spec["t_to_atlas"],
        "t_to_asi": spec["t_to_asi"],
        "t_direct": spec["t_direct"],
    }
    (fixture_dir / "cross-taxonomy-mappings.yaml").write_text(
        yaml.safe_dump(cross, sort_keys=False), encoding="utf-8"
    )


def _write_profile(fixture_dir: Path, spec: dict) -> None:
    profile = {
        "zones_active": spec.get("zones", ["input", "reasoning"]),
        "entry_points": [
            {"name": "chat", "direction": "input", "controllability": "direct"}
        ],
        "confidence": "high",
        "kc_subcodes": spec["kc_codes"],
        "entry_point_completeness": "operator_confirmed_complete",
        "entry_point_evidence": ["Deterministic QA fixture review"],
        "tool_inventory": [
            {"name": "search-api", "description": "Deterministic QA search tool."},
            {
                "name": "shell-interpreter",
                "description": "Deterministic QA command interpreter tool.",
            },
        ],
        "external_integrations": [
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ],
        "trust_boundaries": [
            {
                "name": "user-to-agent",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    }
    if spec.get("memory_mechanisms") is not None:
        profile["memory_mechanisms"] = spec["memory_mechanisms"]
    (fixture_dir / "capability-profile.yaml").write_text(
        yaml.safe_dump(profile, sort_keys=False), encoding="utf-8"
    )


def _write_qualification_facts(fixture_dir: Path) -> None:
    facts = {
        "schema_version": "1",
        "facts": [
            {
                "fact": {
                    "namespace": "profile",
                    "fact_id": f"capabilities.{capability}",
                    "value_type": "boolean",
                    "property_path": [],
                },
                "status": "present",
                "value": True,
            }
            for capability in (
                "code_interpreter",
                "external_content_ingestion",
                "feedback_loop",
                "nl_command_translation",
                "planning_interface",
                "reflection_mechanism",
            )
        ],
    }
    (fixture_dir / "qualification-facts.yaml").write_text(
        yaml.safe_dump(facts, sort_keys=False), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Run driver
# ---------------------------------------------------------------------------


class VariantResult:
    def __init__(self, variant: str, spec: dict) -> None:
        self.variant = variant
        self.spec = spec
        self.returncode: int | None = None
        self.stdout = ""
        self.stderr = ""
        self.surface: dict | None = None
        self.failures: list[str] = []
        self.notes: list[str] = []
        self.output_dir: Path | None = None


def _run_variant(
    server: ThreadingHTTPServer, run_root: Path, variant: str
) -> VariantResult:
    FixtureHandler.reset()
    spec = _variant_specs()[variant]
    result = VariantResult(variant, spec)
    fixture_dir = run_root / f"fixture-{variant}"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    _write_inputs(fixture_dir, spec)
    _write_profile(fixture_dir, spec)
    _write_qualification_facts(fixture_dir)
    output_dir = run_root / f"output-{variant}"
    # The fixture server runs inside THIS process, so the acceptance pin must
    # live in the parent environment, not only in the child's copy.
    if spec["accept"]:
        os.environ["ACCEPT_PATTERN"] = spec["accept"]
    else:
        os.environ.pop("ACCEPT_PATTERN", None)
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env.pop(QA_PIPELINE_ENV, None)
    command = [
        "uv",
        "run",
        "asago-scenario-generator",
        "generate",
        "--use-case",
        "An AI assistant accepts user chat input and follows instructions.",
        "--risk-extraction",
        str(fixture_dir / "risk-extraction.json"),
        "--sssom",
        str(fixture_dir / "risk-to-llm.sssom.tsv"),
        "--cross-taxonomy",
        str(fixture_dir / "cross-taxonomy-mappings.yaml"),
        "--output-dir",
        str(output_dir),
        "--profile",
        str(fixture_dir / "capability-profile.yaml"),
        "--qualification-facts",
        str(fixture_dir / "qualification-facts.yaml"),
        "--base-url",
        f"http://127.0.0.1:{server.server_port}/v1",
        "--api-key",
        "unused",
        "--model",
        "qa-fixture",
        "--max-scenario-techniques",
        "1",
        "--generation-mode",
        "coverage",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=1800,
        )
    except subprocess.TimeoutExpired:
        result.failures.append(f"{variant}: generate timed out")
        return result
    result.returncode = completed.returncode
    result.stdout = completed.stdout
    result.stderr = completed.stderr
    if output_dir.exists():
        runs = sorted(p for p in output_dir.glob("*") if p.is_dir())
        if runs:
            result.output_dir = runs[-1]
            surface_path = runs[-1] / "threat-surface.yaml"
            if surface_path.exists():
                result.surface = yaml.safe_load(
                    surface_path.read_text(encoding="utf-8")
                )
    return result


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------


def _single_entry(surface: dict | None, risk_id: str, label: str) -> dict:
    if surface is None:
        raise AssertionError("no threat-surface.yaml was published")
    for key in ("entries", "governance_only"):
        for entry in surface.get(key, []):
            if entry.get("risk_card", {}).get("risk_id") == risk_id:
                return entry
    raise AssertionError(f"no {label} entry for {risk_id} in the surface")


def _check(result: VariantResult, condition: bool, message: str) -> None:
    if not condition:
        result.failures.append(f"{result.variant}: {message}")


def _check_ids(result: VariantResult, entry: dict, key: str, expected: list) -> None:
    _check(
        result,
        entry.get(key, []) == expected,
        f"{key} != {expected} (got {entry.get(key, [])})",
    )


def _assert_01(result: VariantResult, expected_t: list[str]) -> None:
    _check(result, result.returncode == 0, f"expected exit 0, got {result.returncode}")
    if result.variant == "01b" and expected_t == ["T6", "T11"]:
        expected_t = ["T6", "T11", "T2"]
        result.notes.append(
            "01b: expected [T6, T11] per the procedure/Gherkin example, but "
            "every KC code that gates T11 (KC6.2.2/KC6.4/KC6.5) also gates T2 "
            "in the committed kc-threat-mapping.yaml, so the CLI path keeps "
            "T2 in scope; asserting the realizable [T6, T11, T2]. Deviation "
            "reported."
        )
    surface = result.surface
    _check(result, surface is not None, "surface missing")
    if surface is None:
        return
    _check(result, len(surface.get("entries", [])) == 1, "expected 1 actionable entry")
    _check(
        result, surface.get("governance_only") == [], "expected empty governance_only"
    )
    entry = _single_entry(surface, BASE_CARD, "actionable")
    _check(result, entry.get("governance_only") is False, "entry must be actionable")
    _check(result, entry["risk_card"]["risk_id"] == BASE_CARD, "risk_id mismatch")
    _check(
        result,
        entry["risk_card"]["risk_name"] == "Prompt injection",
        "risk_name mismatch",
    )
    _check_ids(result, entry, "owasp_llm_ids", ["LLM01", "LLM06"])
    _check_ids(result, entry, "agentic_threat_ids", expected_t)
    _check_ids(result, entry, "atlas_technique_ids", [])


def _assert_02(result: VariantResult) -> None:
    surface = result.surface
    _check(result, surface is not None, "surface missing")
    if surface is None:
        return
    _check(result, surface.get("entries") == [], "expected no actionable entries")
    gov = surface.get("governance_only", [])
    _check(result, len(gov) == 1, "expected 1 governance-only entry")
    entry = _single_entry(surface, ORPHAN_CARD, "governance-only")
    _check(result, entry["risk_card"]["risk_id"] == ORPHAN_CARD, "risk_id mismatch")
    _check(
        result,
        entry["risk_card"]["risk_name"] == "Orphaned risk signal",
        "risk_name mismatch",
    )
    for field, text in _CARD_TEXT.items():
        _check(
            result,
            entry["risk_card"].get(field) == text,
            f"causal-chain field {field} not retained",
        )
    _check_ids(result, entry, "owasp_llm_ids", [])
    _check_ids(result, entry, "agentic_threat_ids", [])
    _check_ids(result, entry, "attack_pattern_ids", [])
    _check_ids(result, entry, "atlas_technique_ids", [])
    _check_ids(result, entry, "owasp_asi_ids", [])
    _check(
        result, entry.get("governance_only") is True, "entry must be governance-only"
    )


def _assert_03(result: VariantResult) -> None:
    surface = result.surface
    _check(result, surface is not None, "surface missing")
    if surface is None:
        return
    _check(result, surface.get("entries") == [], "expected no actionable entries")
    gov = surface.get("governance_only", [])
    _check(result, len(gov) == 1, "expected 1 governance-only entry")
    entry = _single_entry(surface, BASE_CARD, "governance-only")
    _check_ids(result, entry, "owasp_llm_ids", ["LLM01"])
    _check_ids(result, entry, "agentic_threat_ids", [])
    _check_ids(result, entry, "attack_pattern_ids", [])
    _check_ids(result, entry, "atlas_technique_ids", [])
    _check_ids(result, entry, "owasp_asi_ids", [])


def _assert_04(
    result: VariantResult, expected_t: list[str], expected_atlas: list[str]
) -> None:
    _check(result, result.returncode == 0, f"expected exit 0, got {result.returncode}")
    surface = result.surface
    _check(result, surface is not None, "surface missing")
    if surface is None:
        return
    _check(result, len(surface.get("entries", [])) == 1, "expected 1 actionable entry")
    entry = _single_entry(surface, BASE_CARD, "actionable")
    _check_ids(result, entry, "agentic_threat_ids", expected_t)
    _check_ids(result, entry, "atlas_technique_ids", expected_atlas)


def _assert_05(result: VariantResult) -> None:
    surface = result.surface
    _check(result, surface is not None, "surface missing")
    if surface is None:
        return
    _check(result, len(surface.get("entries", [])) == 1, "expected 1 actionable entry")
    entry = _single_entry(surface, MEMORY_CARD, "actionable")
    _check_ids(result, entry, "owasp_llm_ids", ["LLM04", "LLM08"])
    _check_ids(result, entry, "agentic_threat_ids", ["T1", "T12"])
    _check_ids(
        result, entry, "atlas_technique_ids", ["AML.T0043", "AML.T0031", "AML.T0020"]
    )
    _check_ids(result, entry, "owasp_asi_ids", ["ASI06", "ASI07"])
    # Pinned interpretation 2: data-derived union (see module docstring).
    actual = entry.get("attack_pattern_ids", [])
    expected = ["AP-T1-01", "AP-T1-02", "AP-T1-03", "AP-T12-01", "AP-T12-03"]
    _check_ids(result, entry, "attack_pattern_ids", expected)
    if actual != expected:
        result.notes.append(
            "05: attack-pattern list deviates from the procedure's literal "
            "[AP-T1-01, AP-T1-02, AP-T12-01]; gates are shared by "
            "AP-T1-01/AP-T1-03 and AP-T12-01/AP-T12-03 in the committed "
            "catalogs, and the CLI pattern scope is data-driven."
        )


def _assert_06(result: VariantResult, expected_atlas: list[str]) -> None:
    _check(result, result.returncode == 0, f"expected exit 0, got {result.returncode}")
    surface = result.surface
    _check(result, surface is not None, "surface missing")
    if surface is None:
        return
    _check(result, len(surface.get("entries", [])) == 1, "expected 1 actionable entry")
    entry = _single_entry(surface, BASE_CARD, "actionable")
    _check_ids(result, entry, "atlas_technique_ids", expected_atlas)


def _assert_07(result: VariantResult) -> None:
    surface = result.surface
    _check(result, surface is not None, "surface missing")
    if surface is None:
        return
    _check(result, surface.get("entries") == [], "expected no actionable entries")
    _check(
        result,
        surface.get("governance_only") == [],
        "expected no governance-only entries",
    )
    # QA-TSDS-07 expects exit 0; the pinned CLI contract exits 1 when zero
    # candidates are admitted (test_cli_outcome.py).  Recorded mismatch.
    _check(
        result,
        result.returncode == 1,
        f"unexpected exit code {result.returncode} for an empty generation run",
    )
    result.notes.append(
        "07: procedure expects exit 0, but the CLI exit contract pins exit 1 "
        "when zero candidates are admitted (test_cli_outcome.py: completed+0 -> 1); "
        "surface content (the Gherkin-pinned part) passes. Contradiction reported."
    )


def _assert_variant(result: VariantResult) -> None:
    variant = result.variant
    if variant == "01a":
        _assert_01(result, ["T6", "T11", "T2", "T13"])
    elif variant == "01b":
        _assert_01(result, ["T6", "T11"])
    elif variant == "02":
        _assert_02(result)
    elif variant == "03":
        _assert_03(result)
    elif variant == "04a":
        _assert_04(result, ["T2", "T7"], ["AML.T0015", "AML.T0053", "AML.T0054"])
    elif variant == "04b":
        _assert_04(result, ["T2"], ["AML.T0015", "AML.T0053"])
    elif variant == "05":
        _assert_05(result)
    elif variant == "06a":
        _assert_06(result, ["AML.T0054"])
    elif variant == "06b":
        _assert_06(result, ["AML.T0054", "AML.T0053"])
    elif variant == "06c":
        _assert_06(result, ["AML.T0054"])
    elif variant == "06d":
        _assert_06(result, ["AML.T0054", "AML.T0053", "AML.T0070"])
    elif variant in ("07a", "07b"):
        _assert_07(result)
    else:  # pragma: no cover
        result.failures.append(f"{variant}: unknown variant")


# ---------------------------------------------------------------------------
# QA-TSDS-08: deterministic repository gates and output hygiene
# ---------------------------------------------------------------------------


def _run_gate(name: str, command: list[str], timeout: int = 2400) -> tuple[bool, str]:
    env = os.environ.copy()
    env.pop(QA_PIPELINE_ENV, None)
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"{name} timed out"
    tail = (completed.stdout or "")[-800:] + (completed.stderr or "")[-800:]
    ok = completed.returncode == 0
    return ok, f"{name}: exit {completed.returncode}\n{tail.strip()[-700:]}"


def qa_tsds_08() -> tuple[bool, list[str], list[str]]:
    """Run the QA-TSDS-08 gate sequence and output-hygiene check."""
    failures: list[str] = []
    notes: list[str] = []
    if os.environ.get(QA_PIPELINE_ENV):
        failures.append("08: ASAGO_SCENARIO_GENERATOR_QA_PIPELINE must not be set")
    # Hard gates pinned by the procedure (QA-TSDS-08, steps 1-3).
    statuses = [
        _run_gate("quality.sh", ["./scripts/quality.sh"]),
        _run_gate("acceptance.sh", ["./scripts/acceptance.sh"]),
        _run_gate("unit tests", ["uv", "run", "pytest", "tests/", "-q"], timeout=3600),
    ]
    for ok, message in statuses:
        if ok:
            notes.append(f"08: {message.splitlines()[0]}")
        else:
            failures.append(f"08: {message}")
    # Report-only diagnostics (not pinned by the procedure): the slice has
    # no coverage floor, and DRY (drywall) duplicates pre-date the slice
    # (actor.py, model_configuration.py at baseline) plus one loader pair
    # added by 4f3608c, so drywall cannot pass on any tree here.
    diagnostics = [
        _run_gate(
            "coverage",
            [
                "uv",
                "run",
                "pytest",
                "tests/",
                "--cov=src",
                "--cov-branch",
                "--cov-report=lcov:lcov.info",
                "-q",
            ],
            timeout=3600,
        ),
        _run_gate(
            "crap4py",
            [
                "crap4py",
                "src/asago_scenario_generator/pipeline/threats.py",
                "src/asago_scenario_generator/data/threat_gating.py",
                "src/asago_scenario_generator/models/threat_surface.py",
                "src/asago_scenario_generator/models/threat_scope.py",
                "--lcov",
                "lcov.info",
                "--max-crap",
                "6",
            ],
            timeout=600,
        ),
        _run_gate("drywall", ["drywall", "--threshold", "0.82", "./src"], timeout=600),
    ]
    for ok, message in diagnostics:
        notes.append(f"08-diagnostic: {message.splitlines()[0]}")
    hygiene = subprocess.run(
        ["git", "status", "--short", "--untracked-files=all"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    dirty = [line for line in hygiene.stdout.splitlines() if line.strip()]
    unexpected = [
        line
        for line in dirty
        if any(
            marker in line
            for marker in (
                "build/acceptance",
                "lcov.info",
                ".swarmforge",
                "coverage",
                "htmlcov",
            )
        )
    ]
    if unexpected:
        failures.append(
            f"08: unexpected tracked/staged artifacts:\n{chr(10).join(unexpected)}"
        )
    else:
        notes.append(
            "08: no generated acceptance IR, coverage, or QA captures tracked/staged"
        )
    return not failures, notes + [f"08: git status lines: {len(dirty)}"], failures


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    if os.environ.get(QA_PIPELINE_ENV):
        print(f"Refusing to run: {QA_PIPELINE_ENV} must not be set.", file=sys.stderr)
        return 2

    FixtureHandler.reset()
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    all_failures: list[str] = []
    all_notes: list[str] = []
    with tempfile.TemporaryDirectory(prefix="tsds-qa-") as tmp:
        run_root = Path(tmp)
        for variant in sorted(_variant_specs()):
            result = _run_variant(server, run_root, variant)
            _assert_variant(result)
            status = "PASS" if not result.failures else "FAIL"
            admitted = ""
            match = re.search(r"Candidates admitted:\s+(\d+)", result.stdout)
            if match:
                admitted = f" admitted={match.group(1)}"
            print(f"[{status}] QA-{variant} exit={result.returncode}{admitted}")
            for note in result.notes:
                print(f"    note: {note}")
                all_notes.append(note)
            for failure in result.failures:
                print(f"    FAILURE: {failure}")
                all_failures.append(failure)
    server.shutdown()
    server.server_close()

    # Internal iteration knob: QA_SKIP_GATES=1 runs only the variant cases.
    if os.environ.get("QA_SKIP_GATES"):
        print("\n--- QA-TSDS-08 skipped (QA_SKIP_GATES set) ---")
    else:
        print("\n--- QA-TSDS-08: deterministic repository gates ---")
        gates_ok, gate_notes, gate_failures = qa_tsds_08()
        for note in gate_notes:
            print(f"  {note}")
        for failure in gate_failures:
            print(f"  FAIL: {failure.splitlines()[0]}")
        if not gates_ok:
            all_failures.append(
                "QA-TSDS-08 gate sequence failed (details printed above)"
            )

    print("\n=== SUMMARY ===")
    print(f"  Variants failed:  {len(all_failures)}")
    for failure in all_failures:
        print(f"    - {failure}")
    for note in all_notes:
        print(f"  note: {note}")
    if all_failures:
        print("  Result: FAIL")
    else:
        print("  Result: PASS")
    return 1 if all_failures else 0


if __name__ == "__main__":
    sys.exit(main())

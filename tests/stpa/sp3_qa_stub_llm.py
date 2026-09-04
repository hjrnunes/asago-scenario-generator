#!/usr/bin/env python3
"""Stub OpenAI-compatible LLM endpoint for the SP3 end-to-end QA suite.

The SP3 QA suite drives ``scripts/run_sp3.py`` through its real command
line. Stage 5 makes one structured-output LLM call per scenario (BDI
generation) and Stage 6 makes three raw-text LLM calls per scenario
(narrative, attack tree, Gherkin). A real endpoint would make the suite
non-deterministic, slow, and billable. This server speaks just enough
of the OpenAI chat-completions protocol for the ``openai`` SDK's
structured-output ``parse`` path and the plain ``create`` path.

The stub inspects the request to determine which call it is:

- ``response_format`` present  → Stage 5 (BDI generation, structured JSON).
- System prompt mentions "narrative" → Stage 6 Call A (raw text).
- System prompt mentions "attack tree" → Stage 6 Call B (YAML text).
- System prompt mentions "gherkin" → Stage 6 Call C (raw text).

Responses are crafted to pass all stage-local validators:
- Defender vulnerabilities are non-empty for every PM-* in the prompt.
- Attack trees use at least 1 supported branch category and reference only
  valid PM/FB/CA/RESP IDs extracted from the prompt.
- Gherkin text has ``Then ... should``, a ``But`` line, and a ``PM-*``
  reference. Returns a structured YAML object (not raw Gherkin) matching
  the :class:`GherkinSpec` model.
- Attack tree root uses ``Induce ICA {ica_type} on {ca_id}`` format with
  the exact ICA type enum value extracted from the prompt.

Usage::

    python tests/stpa/sp3_qa_stub_llm.py --port 8123 [--ready-file PATH]

Writes the bound port to ``--ready-file`` (if given) once listening, so
callers can wait for readiness instead of sleeping.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Regex patterns for extracting structural IDs from prompts.
_PM_RE = re.compile(r"PM-\d+-\d+")
_FB_RE = re.compile(r"FB-\d+-\d+")
_CA_RE = re.compile(r"CA-\d+-\d+")
_RESP_RE = re.compile(r"RESP-\d+")
_SCENARIO_ID_RE = re.compile(r"scenario_id:\s*(SCN-\d+)")
_TARGET_CONTROLLER_RE = re.compile(r"target_controller:\s*(RESP-\d+)")
_TARGET_CA_RE = re.compile(r"target_control_action:\s*(CA-\d+-\d+)")
_ICA_TYPE_RE = re.compile(r"ica_type:\s*(\w+)")
_BELIEF_HANDLE_RE = re.compile(r"belief_handle:\s*(belief_\d+)")
_CAUSE_HANDLE_RE = re.compile(r"source_handle:\s*(cause_\d+)")


def _extract_pm_ids(text: str) -> list[str]:
    """Extract unique PM-* IDs from text, preserving order of first appearance."""
    seen: list[str] = []
    for m in _PM_RE.findall(text):
        if m not in seen:
            seen.append(m)
    return seen


def _extract_fb_ids(text: str) -> list[str]:
    """Extract unique FB-* IDs from text, preserving order."""
    seen: list[str] = []
    for m in _FB_RE.findall(text):
        if m not in seen:
            seen.append(m)
    return seen


def _extract_ca_ids(text: str) -> list[str]:
    """Extract unique CA-* IDs from text, preserving order."""
    seen: list[str] = []
    for m in _CA_RE.findall(text):
        if m not in seen:
            seen.append(m)
    return seen


def _extract_resp_ids(text: str) -> list[str]:
    """Extract unique RESP-* IDs from text, preserving order."""
    seen: list[str] = []
    for m in _RESP_RE.findall(text):
        if m not in seen:
            seen.append(m)
    return seen


def _build_bdi_response(user_prompt: str) -> dict:
    """Build a BDIGenerationResult payload for Stage 5.

    Extracts PM-* IDs from the defender BDI YAML in the user prompt and
    returns non-empty vulnerability annotations for each, plus a simple
    attacker BDI.
    """
    pm_ids = _extract_pm_ids(user_prompt)
    resp_ids = _extract_resp_ids(user_prompt)
    ca_ids = _extract_ca_ids(user_prompt)
    fb_ids = _extract_fb_ids(user_prompt)
    belief_handles = list(dict.fromkeys(_BELIEF_HANDLE_RE.findall(user_prompt)))
    cause_handles = list(dict.fromkeys(_CAUSE_HANDLE_RE.findall(user_prompt))) or [
        "cause_1"
    ]
    target_match = _TARGET_CA_RE.search(user_prompt)
    target_action = (
        target_match.group(1) if target_match else (ca_ids[0] if ca_ids else "CA-1-1")
    )
    ica_match = _ICA_TYPE_RE.search(user_prompt)
    ica_type = ica_match.group(1) if ica_match else "NOT_PROVIDED"

    defender_vulnerabilities: dict[str, str] = {}
    for pm_id in pm_ids:
        defender_vulnerabilities[pm_id] = (
            f"Process model part {pm_id} can be corrupted via manipulated "
            f"feedback, leading to incorrect controller decisions."
        )

    # Attacker BDI — reference at least one structural ID in intentions.
    beliefs = [
        f"The defender relies on {pm_ids[0]} for decision-making."
        if pm_ids
        else "The defender has a process model that can be manipulated.",
    ]
    desires = [
        "Induce the unsafe control action by corrupting the defender's process model."
    ]
    intention_refs: list[str] = []
    if fb_ids:
        intention_refs.append(f"Poison {fb_ids[0]} to corrupt process model state")
    if ca_ids:
        intention_refs.append(f"Trigger {ca_ids[0]} with incorrect parameters")
    if pm_ids:
        intention_refs.append(f"Exploit staleness in {pm_ids[0]}")
    if not intention_refs:
        intention_refs.append("Manipulate the control loop to cause the ICA")
    if resp_ids:
        intention_refs.append(f"Target {resp_ids[0]} as the vulnerable controller")

    if ica_type == "NOT_PROVIDED":
        unsafe_condition = {
            "type": "action_presence",
            "control_action_id": target_action,
            "expected": "not_provided",
        }
    elif ica_type == "INCORRECT":
        unsafe_condition = {
            "type": "action_value",
            "control_action_id": target_action,
            "property": "semantic_proposition",
            "operator": "equals",
            "expected": True,
        }
    elif ica_type == "WRONG_DURATION":
        unsafe_condition = {
            "type": "duration",
            "reference_ref": target_action,
            "duration_ms": 1,
        }
    else:
        unsafe_condition = {
            "type": "delay",
            "reference_ref": target_action,
            "delay_ms": 1,
        }

    return {
        "defender_vulnerabilities": [
            {
                "belief_handle": handle,
                "vulnerability": "The selected belief may be stale.",
            }
            for handle in belief_handles
        ],
        "attacker_bdi": {
            "beliefs": beliefs,
            "desires": desires,
            "intentions": [
                {
                    "description": text,
                    "source_handles": [cause_handles[0]],
                }
                for text in intention_refs
            ],
        },
        "causal_factors": [
            {
                "source_handle": handle,
                "evidence": "The selected structural condition can remain stale.",
                "temporal_condition": None,
                "evidence_status": "structural_failure",
                "capability_refs": [],
                "access_refs": [],
                "bounded_assumption": None,
            }
            for handle in cause_handles
        ],
        "unsafe_outcome": {
            "condition": unsafe_condition,
            "semantic_proposition": (
                "The response exhibits the unsafe semantic behavior."
            ),
        },
        "execution_route": {
            "disposition": "executable_route",
            "delivery_class": "direct_prompt",
            "selected_factor_handle": cause_handles[0],
            "action_kind": "model_output",
            "resource_role_handles": [],
            "carrier_attacker_influence": "none",
            "reason": "The selected structural factor explains the direct route.",
        },
    }


def _build_narrative_response(user_prompt: str) -> str:
    """Build a 7-step narrative text for Stage 6 Call A."""
    pm_ids = _extract_pm_ids(user_prompt)
    fb_ids = _extract_fb_ids(user_prompt)
    ca_ids = _extract_ca_ids(user_prompt)
    pm_ref = pm_ids[0] if pm_ids else "the process model"
    fb_ref = fb_ids[0] if fb_ids else "the feedback channel"
    ca_ref = ca_ids[0] if ca_ids else "the control action"

    return (
        "Step 1: The defender's process model starts correct. "
        f"The controller maintains an accurate view of {pm_ref}, "
        "reflecting the true system state.\n\n"
        "Step 2: The attacker manipulates a control loop element. "
        f"The attacker injects crafted data through {fb_ref}, "
        "poisoning the feedback that updates the process model.\n\n"
        "Step 3: The process model diverges from reality. "
        f"The corrupted feedback causes {pm_ref} to hold stale and "
        "incorrect information about the system state.\n\n"
        "Step 4: The defender acts on false beliefs. "
        f"Relying on the corrupted {pm_ref}, the controller decides "
        f"to issue {ca_ref} under wrong assumptions.\n\n"
        "Step 5: The ICA occurs. "
        f"The unsafe control action {ca_ref} is issued based on the "
        "false process model state, executing when it should not or "
        "with incorrect parameters.\n\n"
        "Step 6: The hazard is realized. "
        "The system-level hazard manifests as the control action causes "
        "an unintended system state transition, threatening safety.\n\n"
        "Step 7: The loss follows. "
        "The ultimate loss to stakeholders occurs as the hazard propagates "
        "through the system, causing financial or privacy harm."
    )


def _build_attack_tree_response(user_prompt: str) -> str:
    """Build a YAML attack tree for Stage 6 Call B.

    Uses at least 1 supported branch category and references only valid
    IDs extracted from the prompt.
    """
    pm_ids = _extract_pm_ids(user_prompt)
    fb_ids = _extract_fb_ids(user_prompt)
    ca_ids = _extract_ca_ids(user_prompt)
    resp_ids = _extract_resp_ids(user_prompt)

    ica_match = _ICA_TYPE_RE.search(user_prompt)
    ica_type = ica_match.group(1) if ica_match else "NOT_PROVIDED"

    pm_ref = pm_ids[0] if pm_ids else "the process model"
    fb_ref = fb_ids[0] if fb_ids else "the feedback channel"
    ca_ref = ca_ids[0] if ca_ids else "the control action"
    resp_ref = resp_ids[0] if resp_ids else "the controller"

    m_controller = f"Poison {pm_ref} via {fb_ref}"
    m_path = f"Tool execution for {ca_ref} fails silently"
    m_coord = f"Desynchronize shared PM between {resp_ref} and peer controller"

    tree = {
        "root": f"Induce ICA {ica_type} on {ca_ref}",
        "branches": [
            {
                "category": "controller_side",
                "label": "WHY THE UCA OCCURS",
                "children": [
                    {
                        "label": "Corrupt process model",
                        "children": [
                            {
                                "label": m_controller,
                                "details": "Attacker injects false data through the feedback channel.",
                            },
                        ],
                    },
                ],
            },
            {
                "category": "path_side",
                "label": "WHY CORRECT ACTION IS NOT EXECUTED",
                "children": [
                    {
                        "label": "Actuator/executor failure",
                        "children": [
                            {
                                "label": m_path,
                                "details": "The selected tool does not execute the intended action.",
                            },
                        ],
                    },
                ],
            },
            {
                "category": "coordination_gap",
                "label": "EXPLOIT COORDINATION GAP",
                "children": [
                    {
                        "label": m_coord,
                        "details": "Cross-controller desynchronization of shared process model.",
                    },
                ],
            },
        ],
        "leaves": [m_controller, m_path, m_coord],
    }

    return json.dumps(tree, indent=2)


def _build_gherkin_response(user_prompt: str) -> str:
    """Build structured YAML Gherkin response for Stage 6 Call C.

    Returns a YAML object with fields ``feature``, ``scenario``,
    ``given``, ``when``, ``then_expected``, ``then_actual`` matching the
    :class:`GherkinSpec` model. The content includes ``Then ... should``,
    a ``But`` line, and a ``PM-*`` reference so it passes
    :func:`validate_gherkin_structure`.

    Also extracts valid Loss and Hazard IDs from the prompt so that
    :func:`validate_loss_hazard_id_references` passes.
    """
    pm_ids = _extract_pm_ids(user_prompt)
    ca_ids = _extract_ca_ids(user_prompt)
    pm_ref = pm_ids[0] if pm_ids else "PM-1-1"
    ca_ref = ca_ids[0] if ca_ids else "CA-1-1"

    scenario_match = _SCENARIO_ID_RE.search(user_prompt)
    scenario_id = scenario_match.group(1) if scenario_match else "SCN-001"

    ica_match = _ICA_TYPE_RE.search(user_prompt)
    ica_type = ica_match.group(1) if ica_match else "NOT_PROVIDED"

    # Extract valid loss IDs from the prompt (passed by build_gherkin_prompts).
    loss_ids = _extract_loss_ids(user_prompt)
    loss_ref = loss_ids[0] if loss_ids else "L-3"

    return yaml_dump_gherkin(
        feature=f"Safe orchestration for {ca_ref}",
        scenario=scenario_id,
        given=[
            f"Given the process model state {pm_ref} holds the correct system state",
            "And the controller is monitoring feedback channels",
        ],
        when=[
            "When an attacker injects crafted input into the feedback path",
        ],
        then_expected=[
            f"Then the system should validate all inputs against the security constraint before executing {ca_ref}",
        ],
        then_actual=[
            f"But the controller issues {ica_type} for {ca_ref} based on the corrupted {pm_ref}",
            "And the unsafe control action leads to an unintended system state transition",
            f"And the loss {loss_ref} is realized",
        ],
    )


def _extract_loss_ids(text: str) -> list[str]:
    """Extract unique L-* IDs from text, preserving order."""
    loss_re = re.compile(r"L-\d+")
    seen: list[str] = []
    for m in loss_re.findall(text):
        if m not in seen:
            seen.append(m)
    return seen


def yaml_dump_gherkin(
    *,
    feature: str,
    scenario: str,
    given: list[str],
    when: list[str],
    then_expected: list[str],
    then_actual: list[str],
) -> str:
    """Serialize a GherkinSpec-shaped dict to YAML.

    Uses ``json.dumps`` then reformats — avoids importing yaml in the
    stub server. The output is valid YAML that
    :func:`parse_gherkin_spec` can parse into a :class:`GherkinSpec`.
    """
    import json as _json

    obj = {
        "feature": feature,
        "scenario": scenario,
        "given": given,
        "when": when,
        "then_expected": then_expected,
        "then_actual": then_actual,
    }
    return _json.dumps(obj, indent=2)


def _is_structured_request(request: dict) -> bool:
    """Check if the request uses structured output (response_format)."""
    return request.get("response_format") is not None


def _determine_call_type(system_prompt: str) -> str:
    """Determine which Stage 6 call this is from the system prompt."""
    sp_lower = system_prompt.lower()
    if "narrative" in sp_lower or "dialectic" in sp_lower:
        return "narrative"
    if "attack tree" in sp_lower:
        return "attack_tree"
    if "gherkin" in sp_lower or "should/but" in sp_lower:
        return "gherkin"
    # Fallback: check user prompt keywords
    return "narrative"


class _StubHandler(BaseHTTPRequestHandler):
    """Serves ``POST /v1/chat/completions`` (and the un-prefixed path)."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:  # noqa: D102 - silence access log
        pass

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self.path.endswith("/chat/completions"):
            self.send_error(404, "Not Found")
            return

        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")

        messages = request.get("messages", [])
        system_prompt = ""
        user_prompt = ""
        for msg in messages:
            if msg.get("role") == "system":
                system_prompt += str(msg.get("content", ""))
            elif msg.get("role") == "user":
                user_prompt += str(msg.get("content", ""))

        if _is_structured_request(request):
            # Stage 5 — structured JSON output (BDI generation).
            content = json.dumps(_build_bdi_response(user_prompt))
        else:
            # Stage 6 — raw text output.
            call_type = _determine_call_type(system_prompt)
            if call_type == "narrative":
                content = _build_narrative_response(user_prompt)
            elif call_type == "attack_tree":
                content = _build_attack_tree_response(user_prompt)
            else:
                content = _build_gherkin_response(user_prompt)

        body = json.dumps(
            {
                "id": "chatcmpl-sp3-qa-stub",
                "object": "chat.completion",
                "created": 0,
                "model": request.get("model", "sp3-qa-stub"),
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": content,
                            "refusal": None,
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            }
        ).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    """Start the stub server and serve until killed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ready-file", default=None)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), _StubHandler)
    port = server.server_address[1]
    if args.ready_file:
        with open(args.ready_file, "w", encoding="utf-8") as handle:
            handle.write(str(port))
    print(f"sp3-qa-stub listening on {port}", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

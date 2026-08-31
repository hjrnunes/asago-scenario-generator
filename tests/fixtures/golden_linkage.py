"""Characterization snapshot of canonical linkage for all 49 patterns.

Every step's resource_links and observable_outcome_links are pinned
here as exact static values.  Tests load this fixture and compare
against raw YAML records before indexing.

This file is a **characterization snapshot**: it was generated once
from the corrected canonical YAML and pinned here as static values.
It is NOT independent semantic authority.  A separate
``reviewed_linkage_decisions`` table provides the reviewed semantic
rationale for non-obvious linkage decisions and is used alongside
this snapshot for validation.
"""

GOLDEN_LINKAGE: dict[str, dict] = {
    "AP-T1-01/conceal_injection": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T1-01/craft_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T1-01/deliver_payload": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver.payload",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T1-01/execute_injection": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute.injection",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T1-01/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T1-01/persist_in_memory": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.persist.in.memory",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T1-02/craft_fragments": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T1-02/deliver_fragments": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver.fragments",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T1-02/escalate_privileges": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.escalate.privileges",
                "observation": "persistent_state",
                "binding_slot_id": "context_window",
            },
        ],
    },
    "AP-T1-02/execute_fragments": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute.fragments",
                "observation": "persistent_state",
                "binding_slot_id": "context_window",
            },
        ],
    },
    "AP-T1-03/corrupt_memory": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.corrupt.memory",
                "observation": "persistent_state",
                "binding_slot_id": "threat_definitions",
            },
        ],
    },
    "AP-T1-03/deliver_inputs": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver.inputs",
                "observation": "persistent_state",
                "binding_slot_id": "threat_definitions",
            },
        ],
    },
    "AP-T1-03/gain_access": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.gain.access",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T1-03/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact",
                "observation": "persistent_state",
                "binding_slot_id": "threat_definitions",
            },
        ],
    },
    "AP-T1-04/craft_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T1-04/gain_access": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.gain.access",
                "observation": "persistent_state",
                "binding_slot_id": "shared_memory",
            },
        ],
    },
    "AP-T1-04/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact",
                "observation": "persistent_state",
                "binding_slot_id": "shared_memory",
            },
        ],
    },
    "AP-T1-04/inject_payload": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.inject.payload",
                "observation": "persistent_state",
                "binding_slot_id": "shared_memory",
            },
        ],
    },
    "AP-T1-04/poison_shared_memory": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.poison.shared.memory",
                "observation": "persistent_state",
                "binding_slot_id": "shared_memory",
            },
        ],
    },
    "AP-T1-06/craft_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T1-06/data_collection": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.data_collection.assembled",
                "observation": "agent_state",
                "binding_slot_id": "agent_internal_state",
            },
        ],
    },
    "AP-T1-06/deliver_content": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver_content.channel",
                "observation": "persistent_state",
                "binding_slot_id": "rag_corpus",
            },
        ],
    },
    "AP-T1-06/impact": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact.exfiltration_complete",
                "observation": "endpoint_receipt",
                "binding_slot_id": "exfil_endpoint",
            },
        ],
    },
    "AP-T1-06/rag_ingestion": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.rag_ingestion.dormant",
                "observation": "persistent_state",
                "binding_slot_id": "rag_corpus",
            },
        ],
    },
    "AP-T1-06/rendered_output_exfiltration": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.rendered_output_exfiltration.encoded",
                "observation": "rendered_output",
                "binding_slot_id": "rendered_output",
            },
        ],
    },
    "AP-T1-06/zero_click_activation": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.zero_click_activation.fired",
                "observation": "persistent_state",
                "binding_slot_id": "rag_corpus",
            },
        ],
    },
    "AP-T10-01/activate_injection": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.activate_injection",
                "observation": "persistent_state",
                "binding_slot_id": "oversight_interface",
            },
        ],
    },
    "AP-T10-01/approve_malicious_actions": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.approve_malicious_actions",
                "observation": "persistent_state",
                "binding_slot_id": "oversight_interface",
            },
        ],
    },
    "AP-T10-01/craft_misleading_context": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T10-01/deliver_crafted_content": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver_crafted_content",
                "observation": "persistent_state",
                "binding_slot_id": "content_store",
            },
        ],
    },
    "AP-T10-01/discover_oversight_structure": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T10-01/identify_presentation_patterns": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T10-01/neutralize_oversight": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.neutralize_oversight",
                "observation": "persistent_state",
                "binding_slot_id": "oversight_interface",
            },
        ],
    },
    "AP-T10-01/obfuscate_malicious_content": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T10-01/probe_agent_mechanisms": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T11-01/access_public_application": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.access_public_application",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T11-01/analyze_framework_apis": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T11-01/bypass_guardrails": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.bypass_guardrails",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T11-01/deploy_configuration": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deploy_configuration",
                "observation": "persistent_state",
                "binding_slot_id": "deployment_target",
            },
        ],
    },
    "AP-T11-01/develop_exploit_prompts": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T11-01/execute_embedded_payload": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute_embedded_payload",
                "observation": "persistent_state",
                "binding_slot_id": "deployment_target",
            },
        ],
    },
    "AP-T11-01/extract_call_chains": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T11-01/generate_backdoored_configuration": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.generate_backdoored_configuration",
                "observation": "persistent_state",
                "binding_slot_id": "deployment_target",
            },
        ],
    },
    "AP-T11-01/invoke_tools_with_attacker_args": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "code_generator",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.invoke_tools_with_attacker_args",
                "observation": "tool_invocation",
                "binding_slot_id": "code_generator",
            },
        ],
    },
    "AP-T11-01/scan_deployment_targets": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T11-01/submit_crafted_prompt": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.submit_crafted_prompt",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T11-02/deliver_backdoor_prompt": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver_backdoor_prompt",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T11-02/develop_backdoor_prompt": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T11-02/execute_hidden_logic": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute_hidden_logic",
                "observation": "persistent_state",
                "binding_slot_id": "generated_workflow",
            },
        ],
    },
    "AP-T11-02/generate_backdoored_workflow": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "workflow_agent",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.generate_backdoored_workflow",
                "observation": "tool_invocation",
                "binding_slot_id": "workflow_agent",
            },
        ],
    },
    "AP-T11-02/persist_backdoored_workflow": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.persist_backdoored_workflow",
                "observation": "persistent_state",
                "binding_slot_id": "generated_workflow",
            },
        ],
    },
    "AP-T11-03/craft_ambiguous_input": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T11-03/execute_unintended_command": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute_unintended_command",
                "observation": "persistent_state",
                "binding_slot_id": "execution_environment",
            },
        ],
    },
    "AP-T11-03/identify_target_systems": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T11-03/invoke_tools_with_derived_params": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.invoke_tools_with_derived_params",
                "observation": "persistent_state",
                "binding_slot_id": "execution_environment",
            },
        ],
    },
    "AP-T11-03/parse_output_as_code": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.parse_output_as_code",
                "observation": "persistent_state",
                "binding_slot_id": "execution_environment",
            },
        ],
    },
    "AP-T11-03/resolve_ambiguity_to_commands": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.resolve_ambiguity_to_commands",
                "observation": "persistent_state",
                "binding_slot_id": "execution_environment",
            },
        ],
    },
    "AP-T11-03/submit_ambiguous_input": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.submit_ambiguous_input",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T11-05/delivery": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.delivery.in_context",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T11-05/engagement": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.engagement.clipboard",
                "observation": "persistent_state",
                "binding_slot_id": "host",
            },
        ],
    },
    "AP-T11-05/generate_adversarial_content": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T11-05/gui_action_injection": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "computer_use_agent",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.gui_action_injection.directed",
                "observation": "tool_invocation",
                "binding_slot_id": "computer_use_agent",
            },
        ],
    },
    "AP-T11-05/host_execution": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.host_execution.compromise",
                "observation": "persistent_state",
                "binding_slot_id": "host",
            },
        ],
    },
    "AP-T11-05/stage_infrastructure": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T12-01/access_shared_channel": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T12-01/activate_in_peer_agents": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.injection_active",
                "observation": "persistent_state",
                "binding_slot_id": "peer_agents",
            },
        ],
    },
    "AP-T12-01/collective_decision_shift": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.steered_decision",
                "observation": "persistent_state",
                "binding_slot_id": "peer_agents",
            },
        ],
    },
    "AP-T12-01/craft_injection_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T12-01/inject_messages": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.messages_resident",
                "observation": "persistent_state",
                "binding_slot_id": "message_channel",
            },
        ],
    },
    "AP-T12-01/persist_in_shared_store": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.injection_persistent",
                "observation": "persistent_state",
                "binding_slot_id": "message_channel",
            },
        ],
    },
    "AP-T12-03/access_knowledge_store": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T12-03/cascade_propagation": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.first_reemission",
                "observation": "persistent_state",
                "binding_slot_id": "peer_agents",
            },
        ],
    },
    "AP-T12-03/craft_false_data": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T12-03/misinformation_impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.cascade_observable",
                "observation": "persistent_state",
                "binding_slot_id": "peer_agents",
            },
        ],
    },
    "AP-T12-03/persist_in_retrieval": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.poison_persistent",
                "observation": "persistent_state",
                "binding_slot_id": "knowledge_store",
            },
        ],
    },
    "AP-T12-03/plant_poisoned_data": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.data_planted",
                "observation": "persistent_state",
                "binding_slot_id": "knowledge_store",
            },
        ],
    },
    "AP-T12-03/trigger_false_incorporation": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.incorporation_triggered",
                "observation": "persistent_state",
                "binding_slot_id": "peer_agents",
            },
        ],
    },
    "AP-T13-04/craft_self_propagating_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T13-04/inject_initial_payload": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.inject_initial_payload",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T13-04/propagate_to_peer_agents": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.propagate_to_peer_agents",
                "observation": "persistent_state",
                "binding_slot_id": "peer_agents",
            },
        ],
    },
    "AP-T13-04/replicate_in_agent_outputs": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "initial_agent",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.replicate_in_agent_outputs",
                "observation": "tool_invocation",
                "binding_slot_id": "initial_agent",
            },
        ],
    },
    "AP-T15-01/delivery": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.content_delivered",
                "observation": "persistent_state",
                "binding_slot_id": "content_channel",
            },
        ],
    },
    "AP-T15-01/evasion": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.trusted_format",
                "observation": "persistent_state",
                "binding_slot_id": "content_channel",
            },
        ],
    },
    "AP-T15-01/execution": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.substitution_active",
                "observation": "persistent_state",
                "binding_slot_id": "content_channel",
            },
        ],
    },
    "AP-T15-01/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.fraud_completed",
                "observation": "persistent_state",
                "binding_slot_id": "content_channel",
            },
        ],
    },
    "AP-T15-01/setup": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T15-02/craft_hijack_injection": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T15-02/generate_deceptive_messages": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deceptive_messages",
                "observation": "persistent_state",
                "binding_slot_id": "content_channel",
            },
        ],
    },
    "AP-T15-02/ingest_malicious_content": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "content_channel",
                "role": "source_influence",
                "trust_boundary_slot_id": "boundary",
                "target_ingress_slot_id": "ingress",
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.content_ingested",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T15-02/stage_social_engineering_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T15-02/user_executes_malicious_action": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.user_actioned",
                "observation": "persistent_state",
                "binding_slot_id": "content_channel",
            },
        ],
    },
    "AP-T16-02/context_hijacking_impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.context_hijacking_impact",
                "observation": "tool_invocation",
                "binding_slot_id": "receiving_agent",
            },
        ],
    },
    "AP-T16-02/craft_malicious_context": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T16-02/execute_unintended_operations": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "receiving_agent",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute_unintended_operations",
                "observation": "tool_invocation",
                "binding_slot_id": "receiving_agent",
            },
        ],
    },
    "AP-T16-02/obfuscate_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T16-02/retrieve_poisoned_response": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "protocol_endpoint",
                "role": "source_influence",
                "trust_boundary_slot_id": "boundary",
                "target_ingress_slot_id": "ingress",
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.retrieve_poisoned_response",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T16-02/stage_on_infrastructure": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T16-03/alter_registry_metadata": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.alter_registry_metadata",
                "observation": "persistent_state",
                "binding_slot_id": "tool_registry",
            },
        ],
    },
    "AP-T16-03/craft_deceptive_descriptions": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T16-03/false_scope_impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.false_scope_impact",
                "observation": "persistent_state",
                "binding_slot_id": "tool_registry",
            },
        ],
    },
    "AP-T16-03/invoke_tool_under_false_scope": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "consuming_agent",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.invoke_tool_under_false_scope",
                "observation": "tool_invocation",
                "binding_slot_id": "consuming_agent",
            },
        ],
    },
    "AP-T16-03/select_tool_under_false_scope": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.select_tool_under_false_scope",
                "observation": "persistent_state",
                "binding_slot_id": "tool_registry",
            },
        ],
    },
    "AP-T17-01/craft_prompt_injection": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T17-01/distribute_poisoned_config": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.artifact_published",
                "observation": "persistent_state",
                "binding_slot_id": "upstream_artifact",
            },
        ],
    },
    "AP-T17-01/execute_hidden_prompt": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.prompt_executed",
                "observation": "persistent_state",
                "binding_slot_id": "adopter_pipeline",
            },
        ],
    },
    "AP-T17-01/impact_backdoored_code": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.backdoored_output",
                "observation": "persistent_state",
                "binding_slot_id": "adopter_pipeline",
            },
        ],
    },
    "AP-T17-01/jailbreak_guardrails": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.jailbroken",
                "observation": "persistent_state",
                "binding_slot_id": "adopter_pipeline",
            },
        ],
    },
    "AP-T17-01/obfuscate_in_config": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T17-01/persist_via_adoption": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.config_persisted",
                "observation": "persistent_state",
                "binding_slot_id": "adopter_pipeline",
            },
        ],
    },
    "AP-T17-01/stage_malicious_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T17-01/suppress_output_mentions": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.generation_concealed",
                "observation": "persistent_state",
                "binding_slot_id": "adopter_pipeline",
            },
        ],
    },
    "AP-T17-03/develop_poisoned_tool": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T17-03/exfiltration": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.exfiltration.transmitted",
                "observation": "tool_invocation",
                "binding_slot_id": "adopter_agent",
            },
        ],
    },
    "AP-T17-03/impact": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact.continuous_leak",
                "observation": "tool_invocation",
                "binding_slot_id": "adopter_agent",
            },
        ],
    },
    "AP-T17-03/namesquatting": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T17-03/persistence": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.persistence.trusted_dependency",
                "observation": "persistent_state",
                "binding_slot_id": "tool_registry",
            },
        ],
    },
    "AP-T17-03/publish_poisoned_tool": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.publish_poisoned_tool.installable",
                "observation": "persistent_state",
                "binding_slot_id": "tool_registry",
            },
        ],
    },
    "AP-T17-03/supply_chain_distribution": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.supply_chain_distribution.installed",
                "observation": "persistent_state",
                "binding_slot_id": "tool_registry",
            },
        ],
    },
    "AP-T17-03/tool_invocation": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "adopter_agent",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.tool_invocation.executed",
                "observation": "tool_invocation",
                "binding_slot_id": "adopter_agent",
            },
        ],
    },
    "AP-T17-04/exfiltration": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.exfiltration.transmitted",
                "observation": "tool_invocation",
                "binding_slot_id": "adopter_agent",
            },
        ],
    },
    "AP-T17-04/impact": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact.rug_pull_complete",
                "observation": "tool_invocation",
                "binding_slot_id": "adopter_agent",
            },
        ],
    },
    "AP-T17-04/persistence": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.persistence.trusted_dependency",
                "observation": "persistent_state",
                "binding_slot_id": "tool_registry",
            },
        ],
    },
    "AP-T17-04/publish_clean_tool": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.publish_clean_tool.available",
                "observation": "persistent_state",
                "binding_slot_id": "tool_registry",
            },
        ],
    },
    "AP-T17-04/push_malicious_update": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.push_malicious_update.published",
                "observation": "persistent_state",
                "binding_slot_id": "tool_registry",
            },
        ],
    },
    "AP-T17-04/rug_pull_timing": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T17-04/tool_invocation": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "adopter_agent",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.tool_invocation.executed",
                "observation": "tool_invocation",
                "binding_slot_id": "adopter_agent",
            },
        ],
    },
    "AP-T17-04/upgrade_distribution": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.upgrade_distribution.upgraded",
                "observation": "persistent_state",
                "binding_slot_id": "tool_registry",
            },
        ],
    },
    "AP-T2-01/craft_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T2-01/deliver_payload": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver.payload",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T2-01/execute_injection": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute.injection",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T2-01/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact",
                "observation": "tool_invocation",
                "binding_slot_id": "target_tool",
            },
        ],
    },
    "AP-T2-01/invoke_tool": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "target_tool",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.invoke.tool",
                "observation": "tool_invocation",
                "binding_slot_id": "target_tool",
            },
        ],
    },
    "AP-T2-01/reconnaissance": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T2-02/collect_data": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "retrieval_tool",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.collect.data",
                "observation": "tool_invocation",
                "binding_slot_id": "retrieval_tool",
            },
        ],
    },
    "AP-T2-02/craft_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T2-02/deliver_payload": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver.payload",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T2-02/discover_data": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "retrieval_tool",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.discover.data",
                "observation": "tool_invocation",
                "binding_slot_id": "retrieval_tool",
            },
        ],
    },
    "AP-T2-02/execute_injection": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute.injection",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T2-02/exfiltrate_data": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.exfiltrate.data",
                "observation": "tool_invocation",
                "binding_slot_id": "delivery_tool",
            },
        ],
    },
    "AP-T2-02/reconnaissance": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T2-03/amplification": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "amplification_tool",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.amplification",
                "observation": "tool_invocation",
                "binding_slot_id": "amplification_tool",
            },
        ],
    },
    "AP-T2-03/discover_tools": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.discover.tools",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T2-03/execution": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execution",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T2-03/setup": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T2-04/conceal_injection": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T2-04/craft_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T2-04/deliver_payload": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver.payload",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T2-04/execute_injection": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute.injection",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T2-04/invoke_tool_from_memory": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "target_tool",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.invoke.tool.from.memory",
                "observation": "tool_invocation",
                "binding_slot_id": "target_tool",
            },
        ],
    },
    "AP-T2-04/persist_in_memory": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.persist.in.memory",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T2-05/craft_adversarial_content": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T2-05/gain_access": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.gain.access",
                "observation": "persistent_state",
                "binding_slot_id": "retrieval_store",
            },
        ],
    },
    "AP-T2-05/inject_content": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.inject.content",
                "observation": "persistent_state",
                "binding_slot_id": "retrieval_store",
            },
        ],
    },
    "AP-T2-05/persist_in_retrieval": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.persist.in.retrieval",
                "observation": "persistent_state",
                "binding_slot_id": "retrieval_store",
            },
        ],
    },
    "AP-T2-05/trigger_tool_invocation": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "target_tool",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.trigger.tool.invocation",
                "observation": "tool_invocation",
                "binding_slot_id": "target_tool",
            },
        ],
    },
    "AP-T2-06/craft_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T2-06/deliver_injection": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver.injection",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T2-06/execute_injection": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute.injection",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T2-06/gain_access": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.gain.access",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T2-06/invoke_tool": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "execution_tool",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.invoke.tool",
                "observation": "tool_invocation",
                "binding_slot_id": "execution_tool",
            },
        ],
    },
    "AP-T2-06/reconnaissance": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T2-06/verify_attack": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.verify.attack",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T3-02/craft_cross_boundary_request": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T3-02/deliver_request": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver.request",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T3-02/discover_connected_services": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.discover.connected.services",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T3-02/escalate_privileges": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.escalate.privileges",
                "observation": "persistent_state",
                "binding_slot_id": "connected_service",
            },
        ],
    },
    "AP-T3-02/execute_request": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute.request",
                "observation": "persistent_state",
                "binding_slot_id": "connected_service",
            },
        ],
    },
    "AP-T3-02/obfuscate_request": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T3-02/probe_trust_boundaries": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.probe.trust.boundaries",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T3-02/reconnaissance": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T3-03/identify_provisioning_weakness": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T3-03/inherit_credentials": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.inherit.credentials",
                "observation": "persistent_state",
                "binding_slot_id": "credential_source",
            },
        ],
    },
    "AP-T3-03/instantiate_shadow_agent": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.instantiate.shadow.agent",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T3-03/operate_shadow_agent": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "shadow_agent",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.operate.shadow.agent",
                "observation": "tool_invocation",
                "binding_slot_id": "shadow_agent",
            },
        ],
    },
    "AP-T3-04/initial_access": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.initial_access.unauthorized",
                "observation": "persistent_state",
                "binding_slot_id": "control_interface",
            },
        ],
    },
    "AP-T3-04/reconnaissance": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T3-05/config_credential_harvest": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.config_credential_harvest.plaintext",
                "observation": "persistent_state",
                "binding_slot_id": "control_interface",
            },
        ],
    },
    "AP-T3-05/env_credential_harvest": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.env_credential_harvest.more_secrets",
                "observation": "persistent_state",
                "binding_slot_id": "control_interface",
            },
        ],
    },
    "AP-T3-05/lateral_movement": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.lateral_movement.pivot",
                "observation": "persistent_state",
                "binding_slot_id": "connected_service",
            },
        ],
    },
    "AP-T3-06/arbitrary_prompting": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.arbitrary_prompting.channel",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T3-06/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact.container_compromise",
                "observation": "persistent_state",
                "binding_slot_id": "container",
            },
        ],
    },
    "AP-T3-06/privileged_tool_invocation": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "agent_tools",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.privileged_tool_invocation.initiated",
                "observation": "tool_invocation",
                "binding_slot_id": "agent_tools",
            },
        ],
    },
    "AP-T4-01/analyze_processing_behavior": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T4-01/craft_expensive_input": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T4-01/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact",
                "observation": "persistent_state",
                "binding_slot_id": "compute_surface",
            },
        ],
    },
    "AP-T4-01/submit_expensive_input": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.submit.expensive.input",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T4-03/amplify_api_calls": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "agent_tools",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.amplify.api.calls",
                "observation": "tool_invocation",
                "binding_slot_id": "agent_tools",
            },
        ],
    },
    "AP-T4-03/craft_quota_exhausting_request": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T4-03/deliver_request": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver.request",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T4-03/identify_quota_bound_integrations": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T4-03/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact",
                "observation": "persistent_state",
                "binding_slot_id": "external_api",
            },
        ],
    },
    "AP-T5-01/compound_distortion": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.compound_distortion",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T5-01/conceal_payload": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T5-01/craft_false_information": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T5-01/deliver_via_trusted_channel": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver_via_trusted_channel",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T5-01/establish_memory_persistence": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.establish_memory_persistence",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T5-01/execute_injection": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute_injection",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T5-01/feedback_reinforces_memory": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.feedback_reinforces_memory",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T5-01/reuse_stored_fabrication": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.reuse_stored_fabrication",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T5-02/activate_injection": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.activate_injection",
                "observation": "persistent_state",
                "binding_slot_id": "retrieval_corpus",
            },
        ],
    },
    "AP-T5-02/develop_endpoint_injection": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T5-02/exfiltrate_via_endpoints": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.exfiltrate_via_endpoints",
                "observation": "endpoint_receipt",
                "binding_slot_id": "attacker_endpoint",
            },
        ],
    },
    "AP-T5-02/stage_injection_content": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.stage_injection_content",
                "observation": "persistent_state",
                "binding_slot_id": "retrieval_corpus",
            },
        ],
    },
    "AP-T5-02/trigger_retrieval": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.trigger_retrieval",
                "observation": "persistent_state",
                "binding_slot_id": "retrieval_corpus",
            },
        ],
    },
    "AP-T5-04/activate_via_retrieval": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.activate_via_retrieval",
                "observation": "persistent_state",
                "binding_slot_id": "decision_surface",
            },
        ],
    },
    "AP-T5-04/craft_false_reference_data": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T5-04/deliver_fabricated_values": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver_fabricated_values",
                "observation": "persistent_state",
                "binding_slot_id": "reference_corpus",
            },
        ],
    },
    "AP-T5-04/discover_value_handling": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.discover_value_handling",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T5-04/identify_data_corpus": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T5-04/manipulate_tool_invocations": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.manipulate_tool_invocations",
                "observation": "persistent_state",
                "binding_slot_id": "decision_surface",
            },
        ],
    },
    "AP-T5-04/obfuscate_injection": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T5-04/persist_in_rag": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.persist_in_rag",
                "observation": "persistent_state",
                "binding_slot_id": "reference_corpus",
            },
        ],
    },
    "AP-T5-04/probe_retrieval_mechanisms": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.probe_retrieval_mechanisms",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T5-04/value_biased_decisions": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.value_biased_decisions",
                "observation": "persistent_state",
                "binding_slot_id": "decision_surface",
            },
        ],
    },
    "AP-T6-01/delivery": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.delivery",
                "observation": "persistent_state",
                "binding_slot_id": "planning_framework",
            },
        ],
    },
    "AP-T6-01/discover_planning": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.discover_planning",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T6-01/evasion": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.evasion",
                "observation": "persistent_state",
                "binding_slot_id": "planning_framework",
            },
        ],
    },
    "AP-T6-01/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact",
                "observation": "persistent_state",
                "binding_slot_id": "planning_framework",
            },
        ],
    },
    "AP-T6-01/setup": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T6-02/access_agent_interface": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.access_agent_interface",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T6-02/deliver_refined_injection": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver_refined_injection",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T6-02/execute_code_via_interpreter": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "tool_chain",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute_code_via_interpreter",
                "observation": "tool_invocation",
                "binding_slot_id": "tool_chain",
            },
        ],
    },
    "AP-T6-02/research_injection_patterns": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T6-02/test_prompt_injections": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.test_prompt_injections",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T6-02/validate_exploit_reliability": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.validate_exploit_reliability",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T6-03/conceal_injection": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T6-03/craft_poisoned_content": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T6-03/execute_unintended_actions": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute_unintended_actions",
                "observation": "agent_state",
                "binding_slot_id": "agent_goal",
            },
        ],
    },
    "AP-T6-03/fetch_poisoned_content": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "poisoned_source",
                "role": "source_influence",
                "trust_boundary_slot_id": "boundary",
                "target_ingress_slot_id": "ingress",
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.fetch_poisoned_content",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T6-03/redirect_agent_goal": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.redirect_agent_goal",
                "observation": "agent_state",
                "binding_slot_id": "agent_goal",
            },
        ],
    },
    "AP-T6-04/delivery": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.delivery",
                "observation": "persistent_state",
                "binding_slot_id": "reflection_mechanism",
            },
        ],
    },
    "AP-T6-04/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact",
                "observation": "persistent_state",
                "binding_slot_id": "reflection_mechanism",
            },
        ],
    },
    "AP-T6-04/reconnaissance": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.reconnaissance",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T6-04/setup": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T6-05/access_learning_interface": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.access_learning_interface",
                "observation": "persistent_state",
                "binding_slot_id": "feedback_loop",
            },
        ],
    },
    "AP-T6-05/corrupt_learned_behavior": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.corrupt_learned_behavior",
                "observation": "persistent_state",
                "binding_slot_id": "feedback_loop",
            },
        ],
    },
    "AP-T6-05/degrade_decision_integrity": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.degrade_decision_integrity",
                "observation": "persistent_state",
                "binding_slot_id": "feedback_loop",
            },
        ],
    },
    "AP-T6-05/deliver_adversarial_feedback": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver_adversarial_feedback",
                "observation": "persistent_state",
                "binding_slot_id": "feedback_loop",
            },
        ],
    },
    "AP-T6-06/control_sequence_spoofing": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.control_sequence_spoofing.bypass",
                "observation": "persistent_state",
                "binding_slot_id": "control_sequences",
            },
        ],
    },
    "AP-T6-06/craft_injection": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T6-06/discover_control_sequences": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T6-06/initial_access": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.initial_access.in_context",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T6-06/injection_activation": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.injection_activation.fired",
                "observation": "persistent_state",
                "binding_slot_id": "control_sequences",
            },
        ],
    },
    "AP-T6-06/reconnaissance": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T6-06/script_execution": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "execution_tool",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.script_execution.bypass_enabled",
                "observation": "tool_invocation",
                "binding_slot_id": "execution_tool",
            },
        ],
    },
    "AP-T6-06/social_engineering_lure": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.social_engineering_lure.positioned",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T6-06/stage_infrastructure": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T6-07/c2_activation": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.c2_activation.polling",
                "observation": "persistent_state",
                "binding_slot_id": "c2_channel",
            },
        ],
    },
    "AP-T6-07/config_modification": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.config_modification.prepended",
                "observation": "persistent_state",
                "binding_slot_id": "agent_config",
            },
        ],
    },
    "AP-T6-07/impact": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impact.persistent_hijack",
                "observation": "persistent_state",
                "binding_slot_id": "c2_channel",
            },
        ],
    },
    "AP-T6-07/poisoned_prompt_activation": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "agent_config",
                "role": "source_influence",
                "trust_boundary_slot_id": "boundary",
                "target_ingress_slot_id": "ingress",
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.poisoned_prompt_activation.loaded",
                "observation": "persistent_state",
                "binding_slot_id": "agent_config",
            },
        ],
    },
    "AP-T6-07/thread_context_persistence": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.thread_context_persistence.remainder",
                "observation": "persistent_state",
                "binding_slot_id": "agent_config",
            },
        ],
    },
    "AP-T8-01/enumerate_record_entries": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.enumerate_record_entries",
                "observation": "persistent_state",
                "binding_slot_id": "action_record",
            },
        ],
    },
    "AP-T8-01/manipulate_action_record": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.manipulate_action_record",
                "observation": "persistent_state",
                "binding_slot_id": "action_record",
            },
        ],
    },
    "AP-T8-01/obtain_record_access": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.obtain_record_access",
                "observation": "persistent_state",
                "binding_slot_id": "action_record",
            },
        ],
    },
    "AP-T8-01/record_divergence_outcome": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.record_divergence_outcome",
                "observation": "persistent_state",
                "binding_slot_id": "action_record",
            },
        ],
    },
    "AP-T9-01/attribution_recorded_for_user": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.attribution_recorded_for_user",
                "observation": "tool_invocation",
                "binding_slot_id": "delegated_capability",
            },
        ],
    },
    "AP-T9-01/craft_attribution_hijack": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T9-01/deliver_payload": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.deliver_payload",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T9-01/discover_capabilities": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T9-01/execute_delegated_actions": {
        "boundary": "inside",
        "resource_links": [
            {
                "slot_id": "delegated_capability",
                "role": "tool_fixture",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.execute_delegated_actions",
                "observation": "tool_invocation",
                "binding_slot_id": "delegated_capability",
            },
        ],
    },
    "AP-T9-01/inject_instructions": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.inject_instructions",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            },
        ],
    },
    "AP-T9-02/access_backend_conversations": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.access_backend_conversations",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-02/authenticate_as_agent": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.authenticate_as_agent",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-02/conceal_injections": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.conceal_injections",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-02/enumerate_processes": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.enumerate_processes",
                "observation": "persistent_state",
                "binding_slot_id": "credential_store",
            },
        ],
    },
    "AP-T9-02/extract_tokens": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.extract_tokens",
                "observation": "persistent_state",
                "binding_slot_id": "credential_store",
            },
        ],
    },
    "AP-T9-02/impersonated_operation_attributed": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.impersonated_operation_attributed",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-02/initial_access": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.initial_access",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-02/inject_malicious_prompts": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.inject_malicious_prompts",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-02/poison_session_context": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.poison_session_context",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-05/acquire_spoofing_tools": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T9-05/evade_biometric_auth": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.evade_biometric_auth",
                "observation": "persistent_state",
                "binding_slot_id": "proofing_surface",
            },
        ],
    },
    "AP-T9-05/false_attribution_recorded": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.false_attribution_recorded",
                "observation": "persistent_state",
                "binding_slot_id": "proofing_surface",
            },
        ],
    },
    "AP-T9-05/forge_identity_documents": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T9-05/gather_victim_identity": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T9-05/generate_deepfake": {
        "boundary": "outside",
        "resource_links": [],
        "observable_outcome_links": [],
    },
    "AP-T9-05/perform_sensitive_action": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.perform_sensitive_action",
                "observation": "persistent_state",
                "binding_slot_id": "proofing_surface",
            },
        ],
    },
    "AP-T9-05/present_spoofed_identity": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.present_spoofed_identity",
                "observation": "persistent_state",
                "binding_slot_id": "proofing_surface",
            },
        ],
    },
    "AP-T9-06/authenticate_to_backend": {
        "boundary": "crossing",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.authenticate_to_backend",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-06/conceal_cross_session_activity": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.conceal_cross_session_activity",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-06/enumerate_credential_stores": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.enumerate_credential_stores",
                "observation": "persistent_state",
                "binding_slot_id": "credential_store",
            },
        ],
    },
    "AP-T9-06/establish_persistent_access": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.establish_persistent_access",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-06/extract_long_lived_tokens": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.extract_long_lived_tokens",
                "observation": "persistent_state",
                "binding_slot_id": "credential_store",
            },
        ],
    },
    "AP-T9-06/initial_access": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.initial_access",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-06/inject_malicious_prompts": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.inject_malicious_prompts",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-06/operate_in_future_session": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.operate_in_future_session",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-06/poison_memory_store": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.poison_memory_store",
                "observation": "persistent_state",
                "binding_slot_id": "memory_store",
            },
        ],
    },
    "AP-T9-06/poison_session_context": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.poison_session_context",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-06/sustained_takeover_observed": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.sustained_takeover_observed",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-07/authenticate_as_agent": {
        "boundary": "crossing",
        "resource_links": [
            {
                "slot_id": "ingress",
                "role": "ingress",
                "trust_boundary_slot_id": None,
                "target_ingress_slot_id": None,
            },
        ],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.authenticate_as_agent",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
    "AP-T9-07/destroy_agent_data": {
        "boundary": "inside",
        "resource_links": [],
        "observable_outcome_links": [
            {
                "postcondition_id": "post.destroy_agent_data",
                "observation": "persistent_state",
                "binding_slot_id": "agent_backend",
            },
        ],
    },
}

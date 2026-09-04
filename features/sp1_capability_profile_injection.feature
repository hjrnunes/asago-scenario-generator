# mutation-stamp: sha256=4389f7ebba47bcabcb6b2f270f09f5158028ba1f8ac47207f115bd652e101079
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T19:57:41.900995Z","feature_name":"SP1 \u2014 Inject capability profile into Stage 2 Call 2 user prompt","feature_path":"features/sp1_capability_profile_injection.feature","background_hash":"ce613fef4022bae8aa0b1d8243e75577aee0d0e16dfb35d86864b5a33367cf99","implementation_hash":"unknown","scenarios":[{"index":6,"name":"CapProfInject-07 existing Call 2 user prompt sections remain present","scenario_hash":"7bce52931ec013b127392806a7ba628de05e717eacd0a1613be012c5cfb1f5d5","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-09T19:57:41.900995Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 — Inject capability profile into Stage 2 Call 2a user prompt
  The system prompt stage2_call2a_system.j2 instructs the LLM to "Check the
  capability profile active zones" with mandatory per-zone responsibilities.
  But _call_2a_responsibilities() in control_structure.py renders
  stage2_call2a_user.j2 with only use_case_text and requirements — the
  capability profile is never passed, so the LLM hallucinates zones. The fix
  passes the capability profile through derive_control_structure() and
  _call_2a_responsibilities() into the Call 2a user prompt template, which
  renders a Capability Profile Context section with the actual profile data.

  Background:
    Given the STPA system model control_structure module is importable
    And a capability profile with zones_active input,reasoning,tool_execution and multi_agent false and hitl false and has_persistent_memory false
    And a use-case description is available
    And a loss analysis is available
    And a run directory for output and call logging

  # CapProfInject-01
  Scenario: CapProfInject-01 _call_2a_responsibilities accepts a capability_profile parameter
    Given the _call_2a_responsibilities function signature is inspected
    Then the function accepts a capability_profile parameter of type CapabilityProfile

  # CapProfInject-02
  Scenario: CapProfInject-02 derive_control_structure accepts a capability_profile parameter
    Given the derive_control_structure function signature is inspected
    Then the function accepts a capability_profile parameter of type CapabilityProfile

  # CapProfInject-03
  Scenario: CapProfInject-03 run_sp1 passes capability_profile to derive_control_structure
    Given an LLM that returns valid Stage 2 responses for all three calls
    When the SP1 pipeline is run with the capability profile
    Then derive_control_structure is called with the capability_profile argument

  # CapProfInject-04
  Scenario: CapProfInject-04 stage2_call2a_user.j2 contains a Capability Profile Context section
    Given the template stage2_call2a_user.j2 is loaded
    Then the template text contains "Capability Profile Context"
    And the template text contains "zones_active"
    And the template text contains "multi_agent"
    And the template text contains "hitl"
    And the template text contains "has_persistent_memory"

  # CapProfInject-05
  Scenario: CapProfInject-05 rendered Call 2a user prompt contains actual capability profile data
    Given a capability profile with zones_active input,reasoning,tool_execution and multi_agent true and hitl true
    When the Call 2a user prompt is rendered with the capability profile
    Then the rendered text contains "input: Input Surfaces"
    And the rendered text contains "reasoning: Planning & Reasoning"
    And the rendered text contains "tool_execution: Tool Execution"
    And the rendered text contains "Multi-agent: True"
    And the rendered text contains "Human-in-the-loop: True"

  # CapProfInject-06
  Scenario: CapProfInject-06 rendered Call 2a user prompt reflects inactive zones
    Given a capability profile with zones_active input,reasoning and multi_agent false and hitl false and has_persistent_memory false
    When the Call 2a user prompt is rendered with the capability profile
    Then the rendered text contains "input: Input Surfaces"
    And the rendered text contains "reasoning: Planning & Reasoning"
    And the rendered text contains "Multi-agent: False"
    And the rendered text contains "Human-in-the-loop: False"
    And the rendered text contains "Persistent memory: False"

  # CapProfInject-07
  Scenario Outline: CapProfInject-07 existing Call 2a user prompt sections remain present
    Given the template stage2_call2a_user.j2 is loaded
    Then the template text contains "<section_header>"

    Examples:
      | section_header       |
      | ## Use-Case Description |
      | ## Requirements        |
      | ## Your Task           |

  # CapProfInject-08
  Scenario: CapProfInject-08 stage2_call2a_user.j2 renders without errors with capability profile
    Given the template stage2_call2a_user.j2 is loaded
    When the template is rendered with use_case_text, requirements, and capability_profile
    Then the rendered text contains "Capability Profile Context"
    And the rendered text does not contain "{{ capability_profile"

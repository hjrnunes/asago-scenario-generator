# PQA-01 through PQA-07, PQA-09, and PQA-10
Feature: STPA prompt, response, and execution-quality audit corrections
  These deterministic acceptance scenarios close the corrective boundaries
  from the 2026-09-03 prompt/response/results audit. They inspect prompt
  contracts and exercise local provider rejection. No scenario contacts a
  model endpoint.

  Scenario: PQA-01 Stage 1 separates loss sources and uses system-level hazards
    Given the Stage 1 loss-analysis prompt set is inspected
    Then Stage 1 separates risk-card and use-case loss provenance
    And Stage 1 defines a hazard as a system-level condition
    And Stage 1 rejects a component failure as the hazard itself

  Scenario: PQA-02 Stage 2 revision is a strict additive delta with manifest visibility
    Given the Stage 2 revision prompt and manifest contract are inspected
    Then Stage 2 revision accepts only new and modified elements
    And Stage 2 revision provides an add-or-dismiss decision for each gap
    And the run manifest exposes revision outcome and post-revision errors

  Scenario: PQA-03 ICA output is concise and compiler-owned
    Given the captured synthesis prompt regressions are available
    When an ICA provider supplies one deviation for a NOT_PROVIDED slot
    Then the compiled ICA behavior contains "fails to provide"
    And the compiled ICA has one concise deviation sentence
    And the ICA provider contract leaves UCA category selection to the slot

  Scenario: PQA-04 temporal semantics remain typed
    Given the STPA temporal projection models are available
    And a control structure contains RESP-1, PM-1-1, FB-1-1, and CA-1-1
    And a WRONG_TIMING unsafe control action targets CA-1-1
    And "FB-1-1" has declared timing "delay 250 milliseconds"
    When the temporal action vector is derived
    Then its assertion has constraint variant "DelayConstraint"
    And the constraint uses canonical unit "ms"
    And the constraint contains the declared numeric value "250"
    And the constraint contains no fields belonging to another variant

  Scenario: PQA-05 and PQA-06 Stage 5 derives the agent channel from the chosen stimulus and action
    Given a corrected inter-responsibility Stage 5 route context is available
    And the provider describes stimulus "conversation" with action "agent_message" and binds its declared causal factor
    When corrected Stage 5 materializes the route
    Then the materialized execution contract is "executable_route"
    And the contract uses delivery "conversation_context" and action "agent_message"
    And the contract has domain requirements "agent_channel"

  Scenario: PQA-07 rejected provider responses retain identity and lifecycle state
    Given an offline provider returns a rejected structured response
    When the rejected provider response is logged
    Then the rejection record has provider receipt and failed semantic validation
    And the rejection record retains stage "stage_5", step "bdi_generation", slot "RESP-1:CA-1-1:INCORRECT", and scenario "SCN-001"
    And the rejection record has terminal error code "provider_contract_failure"

  Scenario: PQA-09 taxonomy crosswalk strength and risk alignment stay advisory
    Given the taxonomy crosswalk and obligation prompt contracts are inspected
    Then crosswalk strength is derived from every relation in a path
    And mechanism plausibility and reviewed-risk alignment are independent
    And a weak or mismatched mapping remains an obligation hypothesis

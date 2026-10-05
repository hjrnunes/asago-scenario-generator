# mutation-stamp: sha256=6497c7b045be784f9dbc4b3452ed2159b86970bf9a7c4d80da600fecbe965073
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T10:49:08.738816Z","feature_name":"SP3 Stage 5 \u2014 Dual-BDI scenario specification","feature_path":"features/sp3_bdi_generation.feature","background_hash":"9031378c9d2d2724532b6ffb9a52128b1bebc278ec312c6c1e6dcd7dc960c6d5","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: SP3 Stage 5 — Dual-BDI scenario specification
  Stage 5 produces a ScenarioSpec per structural threat. The defender BDI is
  deterministically pre-populated from the control structure (PM→beliefs,
  RESP→desires, CA→intentions). One LLM call per scenario fills defender
  vulnerability annotations and generates the attacker BDI. The ScenarioSpec
  is assembled deterministically and validated against the control structure.

  Background:
    Given the SP3 BDI generation module is importable
    And a control structure with responsibility RESP-1 having process model parts PM-1-1 and PM-1-2, control actions CA-1-1 and CA-1-2, and feedback channels FB-1-1
    And an enriched threat set with a structural threat for ICA slot RESP-1:CA-1-1:NOT_PROVIDED

  # SP3-BDI-01
  Scenario: SP3-BDI-01 defender BDI beliefs are derived from process model parts
    Given a control structure where RESP-1 has process model parts PM-1-1 and PM-1-2
    When the defender BDI is pre-populated for RESP-1
    Then the defender BDI has 2 beliefs
    And belief 1 references pm_id PM-1-1
    And belief 2 references pm_id PM-1-2
    And each belief content matches the process model part description

  # SP3-BDI-02
  Scenario: SP3-BDI-02 defender BDI desires are derived from the responsibility
    Given a control structure where RESP-1 has description "Authorize payment operations"
    When the defender BDI is pre-populated for RESP-1
    Then the defender BDI has at least 1 desire
    And each desire references resp_id RESP-1
    And each desire content matches the responsibility description

  # SP3-BDI-03
  Scenario: SP3-BDI-03 defender BDI intentions are derived from control actions
    Given a control structure where RESP-1 has control actions CA-1-1 and CA-1-2
    When the defender BDI is pre-populated for RESP-1
    Then the defender BDI has 2 intentions
    And intention 1 references ca_id CA-1-1
    And intention 2 references ca_id CA-1-2
    And each intention content matches the control action description

  # SP3-BDI-04
  Scenario: SP3-BDI-04 defender belief vulnerability fields are empty before the LLM call
    When the defender BDI is pre-populated for RESP-1
    Then every belief has an empty vulnerability field

  # SP3-BDI-05
  Scenario: SP3-BDI-05 one LLM call per scenario fills vulnerability annotations and attacker BDI
    Given an LLM that returns defender vulnerabilities for each PM and a valid attacker BDI
    When the BDI generation LLM call is executed for the scenario
    Then exactly 1 LLM call is made
    And the call is labeled with stage stage_5
    And the call step is bdi_generation

  # SP3-BDI-06
  Scenario: SP3-BDI-06 LLM fills non-empty vulnerability annotations on each defender belief
    Given an LLM that returns vulnerability annotations for PM-1-1 and PM-1-2
    When the BDI generation LLM call is executed and vulnerabilities are merged
    Then every defender belief has a non-empty vulnerability annotation

  # SP3-BDI-07
  Scenario: SP3-BDI-07 LLM generates attacker BDI with beliefs, desires, and intentions
    Given an LLM that returns an attacker BDI with 3 beliefs, 2 desires, and 3 intentions
    When the BDI generation LLM call is executed
    Then the attacker BDI has 3 beliefs
    And the attacker BDI has 2 desires
    And the attacker BDI has 3 intentions

  # SP3-BDI-08
  Scenario: SP3-BDI-08 attacker BDI beliefs reference defender process model weaknesses
    Given an LLM that returns an attacker BDI whose beliefs reference PM-1-1
    When the BDI generation LLM call is executed
    Then at least one attacker belief references PM-1-1

  # SP3-BDI-09
  Scenario: SP3-BDI-09 ScenarioSpec is assembled with threat source and catalog context
    Given a structural threat with ica_slot_id RESP-1:CA-1-1:NOT_PROVIDED and provenance structural
    And the threat has catalog mappings for OWASP_AGENTIC T1
    When the ScenarioSpec is assembled
    Then the scenario spec has threat_source ica_slot_id RESP-1:CA-1-1:NOT_PROVIDED
    And the scenario spec has threat_source provenance structural
    And the scenario spec has target_controller RESP-1
    And the scenario spec has target_control_action CA-1-1
    And the scenario spec has ica_type NOT_PROVIDED
    And the scenario spec has catalog context with 1 mapping

  # SP3-BDI-10
  Scenario: SP3-BDI-10 scenario ID follows SCN-NNN format
    When the ScenarioSpec is assembled for the first scenario
    Then the scenario_id matches the pattern SCN-NNN

  # SP3-BDI-11
  Scenario: SP3-BDI-11 post-call validation checks BDI grounding against control structure
    Given a defender BDI with all beliefs, desires, and intentions referencing valid control structure IDs
    When the scenario spec is validated against the control structure
    Then validation succeeds

  # SP3-BDI-12
  Scenario: SP3-BDI-12 post-call validation fails on non-existent PM reference
    Given a defender BDI with a belief referencing PM-99-1
    When the scenario spec is validated against the control structure
    Then validation fails with error containing pm_id

  # SP3-BDI-13
  Scenario: SP3-BDI-13 post-call validation fails on non-existent CA reference
    Given a defender BDI with an intention referencing CA-99-1
    When the scenario spec is validated against the control structure
    Then validation fails with error containing ca_id

  # SP3-BDI-14
  Scenario: SP3-BDI-14 post-call validation fails on target_control_action not belonging to target_controller
    Given a control structure with RESP-1 and RESP-2 where CA-2-1 belongs to RESP-2
    And a scenario spec with target_controller RESP-1 and target_control_action CA-2-1
    When the scenario spec is validated against the control structure
    Then validation fails with error containing target_control_action

  # SP3-BDI-15
  Scenario: SP3-BDI-15 vulnerability completeness check fails on empty vulnerability
    Given a defender BDI where belief PM-1-1 has an empty vulnerability annotation
    When vulnerability completeness validation is performed
    Then validation fails with error containing vulnerability

  # SP3-BDI-18
  Scenario: SP3-BDI-18 system prompt defines the dual-BDI interaction model
    When the BDI generation LLM call is executed
    Then the system prompt contains instructions for defender vulnerability annotation
    And the system prompt contains instructions for attacker BDI generation
    And the system prompt requires attacker intentions to reference PM or FB or CA elements

  # SP3-BDI-19
  Scenario: SP3-BDI-19 strict 1:1 ICA-to-scenario cardinality
    Given an enriched threat set with 5 structural threats
    When BDI generation is performed for all threats
    Then exactly 5 ScenarioSpec instances are produced
    And each scenario corresponds to exactly one structural threat

  # SP3-BDI-20
  Scenario: SP3-BDI-20 all LLM calls are logged to calls.jsonl
    Given a run directory for output
    And an LLM that returns valid BDI generation results
    When BDI generation is performed for all threats
    Then a file calls.jsonl exists in the run directory
    And the file contains entries with stage stage_5

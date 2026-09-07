# mutation-stamp: sha256=23441b2833ecfea691cf36e2acd372c5305114214e4276e9f509ef1043675733
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:27:20.643452Z","feature_name":"SP1 Stage 2 \u2014 Control Structure derivation","feature_path":"features/sp1_control_structure_derivation.feature","background_hash":"33b87ed407f52e8aea57082699bf61ea5723bd4d2112a4c7baeceac682aab5fd","implementation_hash":"sha256:833f462ccad35c636f2eea0a490e0fe601a7e127b4bcd627675eb3bb4245545e","scenarios":[{"index":6,"name":"SP1-S2-07 Call 2a does not emit control elements","scenario_hash":"07a81ef5aa0ea7e70ee67e5e0238087fe636f63881fb46b78404dca6e5bbc283","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:27:20.643452Z"},{"index":11,"name":"SP1-S2-12 the retired three-call step names are absent","scenario_hash":"c199dff7bffe1654183d8b42658e8c676fce5b4c61053b52de7c2af7ac12b67c","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:27:20.643452Z"},{"index":8,"name":"SP1-S2-09 each Stage 2 call is logged with its own step name","scenario_hash":"35ff6e48ecf560a0143645de758976eca5f03f52e68b01f68b72ca71d54bf395","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:22:58.833221Z"},{"index":2,"name":"SP1-S2-03 requirement with invalid classification fails","scenario_hash":"f017e3757e89f558c84d75fe33d7f5369d288ba34df6f107a4407ffe6058ba7f","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-08T14:51:59.763513Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 Stage 2 — Control Structure derivation
  Stage 2 runs four sequential LLM calls, each producing a structured
  internal model that feeds the next: Call 1 derives requirements from
  security constraints (RequirementSet), Call 2a derives responsibilities
  with responsibility constraints and process model parts
  (ResponsibilitySet), Call 2b derives control actions, feedback channels,
  and controlled processes (ControlElementSet), and Call 3 derives
  coordination links and integrity findings (CoordinationAnalysis).
  Assembly of Call 2a and Call 2b — not an LLM call — produces the
  ControlStructure.

  Background:
    Given the STPA system model module is importable
    And a loss analysis with security constraints SC-1 and SC-2 is available
    And a use-case description is available

  # SP1-S2-01
  Scenario: SP1-S2-01 Call 1 produces a valid RequirementSet
    Given an LLM that returns a valid RequirementSet JSON with requirements REQ-1 and REQ-2
    When Stage 2 Call 1 requirements derivation is run
    Then a RequirementSet model is produced
    And each requirement has a req_id, description, classification, and source_constraint

  # SP1-S2-02
  Scenario: SP1-S2-02 requirements are classified as control or constraint
    Given an LLM that returns a RequirementSet with REQ-1 classified as control and REQ-2 classified as constraint
    When Stage 2 Call 1 requirements derivation is run
    Then REQ-1 has classification control
    And REQ-2 has classification constraint

  # SP1-S2-03
  Scenario Outline: SP1-S2-03 requirement with invalid classification fails
    Given an LLM that returns a RequirementSet with REQ-1 classified as <bad_class>
    When Stage 2 Call 1 requirements derivation is run
    Then validation fails with error containing classification

    Examples:
      | bad_class    |
      | enforcement  |
      | policy       |

  # SP1-S2-04
  Scenario: SP1-S2-04 each requirement references a source constraint
    Given an LLM that returns a RequirementSet where REQ-1 references SC-1 and REQ-2 references SC-2
    When Stage 2 Call 1 requirements derivation is run
    Then REQ-1 has source_constraint SC-1
    And REQ-2 has source_constraint SC-2

  # SP1-S2-05
  Scenario: SP1-S2-05 Call 1 is logged with stage stage_2 and step call_1_requirements
    Given an LLM that returns a valid RequirementSet JSON
    And a run directory for call logging
    When Stage 2 Call 1 requirements derivation is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is call_1_requirements

  # SP1-S2-06
  Scenario: SP1-S2-06 Call 2a produces a valid ResponsibilitySet
    Given an LLM that returns a valid ResponsibilitySet JSON with responsibilities RESP-1 and RESP-2
    When Stage 2 Call 2a responsibilities derivation is run
    Then a ResponsibilitySet model is produced
    And each responsibility has at least one responsibility constraint and one process model part

  # SP1-S2-07
  Scenario Outline: SP1-S2-07 Call 2a does not emit control elements
    Given an LLM that returns a valid ResponsibilitySet JSON with responsibilities RESP-1 and RESP-2
    When Stage 2 Call 2a responsibilities derivation is run
    Then the `ResponsibilitySet` model does not declare `<control_element_field>`

    Examples:
      | control_element_field |
      | control_actions       |
      | feedback_channels     |
      | controlled_processes  |

  # SP1-S2-08
  Scenario: SP1-S2-08 Call 2b produces a valid ControlElementSet
    Given a valid ResponsibilitySet from Call 2a
    And an LLM that returns a valid ControlElementSet JSON with controlled process CP-1
    When Stage 2 Call 2b control elements derivation is run
    Then a ControlElementSet model is produced
    And the ControlElementSet contains controlled process CP-1
    And the Call 2b wire schema forbids external effects on responsibility targets

  # SP1-S2-09
  Scenario Outline: SP1-S2-09 each Stage 2 call is logged with its own step name
    Given an LLM that returns valid responses for all four Stage 2 calls
    And a run directory for call logging
    When Stage 2 control structure derivation is run
    Then a call log entry is appended with stage stage_2
    And a call log entry exists with step <step_name>

    Examples:
      | step_name                |
      | call_1_requirements      |
      | call_2a_responsibilities |
      | call_2b_control_elements |
      | call_3_coordination      |

  # SP1-S2-10
  Scenario: SP1-S2-10 assembly of Call 2a and Call 2b produces a valid ControlStructure
    Given a valid ResponsibilitySet from Call 2a
    And an LLM that returns a valid ControlElementSet JSON with controlled process CP-1
    When Stage 2 control structure derivation is run
    Then a ControlStructure model is produced
    And the control structure passes foundation validation

  # SP1-S2-11
  Scenario: SP1-S2-11 coordination links are identified in Call 3
    Given an LLM that returns valid responses for Stage 2 calls 1, 2a, and 2b
    And an LLM that returns a CoordinationAnalysis with coordination link CL-1 from RESP-1 to RESP-2 sharing PM-1-1
    When Stage 2 control structure derivation is run
    Then the ControlStructure contains coordination link CL-1
    And CL-1 has source RESP-1 and target RESP-2

  # SP1-S2-12
  Scenario Outline: SP1-S2-12 the retired three-call step names are absent
    Given an LLM that returns valid responses for all four Stage 2 calls
    When Stage 2 control structure derivation is run
    Then no call log entry has step <retired_step>

    Examples:
      | retired_step            |
      | call_2_responsibilities |
      | call_3_connections      |

  # SP1-S2-13
  Scenario: SP1-S2-13 control structure is written to control-structure.yaml
    Given an LLM that returns valid responses for all four Stage 2 calls
    And a run directory for output
    When Stage 2 control structure derivation is run
    Then a file control-structure.yaml exists in the run directory
    And the file contains a valid ControlStructure model when read back

  # SP1-S2-14
  Scenario: SP1-S2-14 Call 2a receives requirements from Call 1
    Given an LLM that returns a valid RequirementSet for Call 1
    And an LLM that returns a valid ResponsibilitySet for Call 2a
    When Stage 2 calls 1 through 2a are run in sequence
    Then the Call 2a user prompt contains the requirements from Call 1

  # SP1-S2-15
  Scenario: SP1-S2-15 Call 2b receives responsibilities from Call 2a
    Given an LLM that returns valid responses for Stage 2 calls 1 and 2a
    And an LLM that returns a valid ControlElementSet JSON with controlled process CP-1
    When Stage 2 calls 1 through 2b are run in sequence
    Then the Call 2b user prompt contains the responsibilities from Call 2a

  # SP1-S2-16
  Scenario: SP1-S2-16 Call 3 receives the assembled control structure
    Given an LLM that returns valid responses for Stage 2 calls 1, 2a, and 2b
    And an LLM that returns a valid CoordinationAnalysis with coordination link CL-1
    When Stage 2 calls 1 through 3 are run in sequence
    Then the Call 3 user prompt contains the assembled responsibilities and controlled processes

# mutation-stamp: sha256=f1d20c3047530016d5fa0c38b2b8e414d2fc8e77076cafb301b9a1fc36bcf4cb
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:43:09.069015Z","feature_name":"Stage 2 Call 3 Coordination Analysis","feature_path":"features/acceptance-refresh/stage2-coordination-analysis.feature","background_hash":"fb622aa22f4205e08c48be6b1bbd9dec2d34385abccda499b789a385e949114c","implementation_hash":"sha256:f9ded0010316b8974c3ae7010fcbfc69f798974cc09c17b5453ba51184784d69","scenarios":[{"index":0,"name":"stage2-coordination-analysis-01 the retired Call 3 symbols are not exported","scenario_hash":"56b42bd5f08e7fb357bf732654c4247220d30b599d8939c4c1000cad9065eecf","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:09.069015Z"},{"index":1,"name":"stage2-coordination-analysis-02 the replacement Call 3 symbols are exported","scenario_hash":"e037a8d05d842d7f32e4a87eab0562e09079e9092884a8f5def179db833b7db9","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:09.069015Z"},{"index":2,"name":"stage2-coordination-analysis-03 CoordinationAnalysis declares only coordination fields","scenario_hash":"9f72e82ed60977f06828c1dbce2fc200b146a84b67d1d8cdadc4339f3157e85d","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:09.069015Z"},{"index":3,"name":"stage2-coordination-analysis-04 CoordinationAnalysis drops the retired ConnectionSet fields","scenario_hash":"c54e4941e08f436da25d925397aae3b1bcb74dc300861e1cddf030656051bf56","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:09.069015Z"}]}
# acceptance-mutation-manifest-end

# stage2-coordination-analysis
Feature: Stage 2 Call 3 Coordination Analysis
  Stage 2 Call 3 returns a CoordinationAnalysis carrying coordination_links
  and integrity_findings. The former ConnectionSet — which additionally
  carried controlled_processes and connection_assignments — is removed.
  Controlled processes now come from Call 2b's ControlElementSet, and
  control-action targets and feedback-channel sources are assigned directly
  by Call 2b rather than patched afterwards by connection assignments.
  Call 3 flags integrity problems for the revision step; it does not fix
  them.

  Background:
    Given the STPA system model control_structure module is importable
    And a use-case description is available
    And a run directory for output and call logging

  # stage2-coordination-analysis-01
  Scenario Outline: stage2-coordination-analysis-01 the retired Call 3 symbols are not exported
    Then the control_structure module does not export `<retired_symbol>`

    Examples:
      | retired_symbol       |
      | ConnectionSet        |
      | merge_connection_set |
      | _merge_with_fallback |

  # stage2-coordination-analysis-02
  Scenario Outline: stage2-coordination-analysis-02 the replacement Call 3 symbols are exported
    Then the control_structure module exports `<symbol>`

    Examples:
      | symbol                              |
      | CoordinationAnalysis                |
      | ControlElementSet                   |
      | _assemble_control_structure         |
      | _assemble_with_fallback             |
      | _add_coordination_links_with_fallback |

  # stage2-coordination-analysis-03
  Scenario Outline: stage2-coordination-analysis-03 CoordinationAnalysis declares only coordination fields
    Then the `CoordinationAnalysis` model declares `<field>`

    Examples:
      | field              |
      | coordination_links |
      | integrity_findings |

  # stage2-coordination-analysis-04
  Scenario Outline: stage2-coordination-analysis-04 CoordinationAnalysis drops the retired ConnectionSet fields
    Then the `CoordinationAnalysis` model does not declare `<retired_field>`

    Examples:
      | retired_field          |
      | controlled_processes   |
      | connection_assignments |

  # stage2-coordination-analysis-05
  Scenario: stage2-coordination-analysis-05 Call 3 produces a CoordinationAnalysis
    Given an LLM that returns a valid CoordinationAnalysis with coordination link CL-1
    When Stage 2 Call 3 coordination derivation is run
    Then a CoordinationAnalysis model is produced
    And the CoordinationAnalysis contains coordination link CL-1

  # stage2-coordination-analysis-06
  Scenario: stage2-coordination-analysis-06 Call 3 reports integrity findings without fixing them
    Given a control structure with an unreferenced controlled process
    When Stage 2 Call 3 coordination derivation is run
    Then the CoordinationAnalysis integrity_findings list is not empty
    And the CoordinationAnalysis contains no coordination links

  # stage2-coordination-analysis-07
  Scenario: stage2-coordination-analysis-07 Call 3 is logged with step call_3_coordination
    Given an LLM that returns a valid CoordinationAnalysis with coordination link CL-1
    When Stage 2 control structure derivation is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is call_3_coordination
    And no call log entry has step call_3_connections

  # stage2-coordination-analysis-08
  Scenario: stage2-coordination-analysis-08 coordination links reach the final ControlStructure
    Given an LLM that returns valid responses for Stage 2 calls 1, 2a, and 2b
    And an LLM that returns a CoordinationAnalysis with coordination link CL-1 from RESP-1 to RESP-2 sharing PM-1-1
    When Stage 2 control structure derivation is run
    Then the ControlStructure contains coordination link CL-1
    And CL-1 has source RESP-1 and target RESP-2
    And the control structure passes foundation validation

  # stage2-coordination-analysis-09
  Scenario: stage2-coordination-analysis-09 controlled processes come from Call 2b not Call 3
    Given an LLM that returns valid responses for Stage 2 calls 1, 2a, and 2b
    And an LLM that returns a ControlElementSet from Call 2b with controlled process CP-1
    And an LLM that returns a valid CoordinationAnalysis with coordination link CL-1
    When Stage 2 control structure derivation is run
    Then the ControlStructure contains controlled process CP-1

  # stage2-coordination-analysis-10
  Scenario: stage2-coordination-analysis-10 Call 3 receives the assembled control structure
    Given an LLM that returns valid responses for Stage 2 calls 1, 2a, and 2b
    And an LLM that returns a valid CoordinationAnalysis with coordination link CL-1
    When Stage 2 calls 1 through 3 are run in sequence
    Then the Call 3 user prompt contains the assembled responsibilities and controlled processes

  # stage2-coordination-analysis-11
  Scenario: stage2-coordination-analysis-11 control structure is written to control-structure.yaml
    Given an LLM that returns valid responses for all four Stage 2 calls
    When Stage 2 control structure derivation is run
    Then a file control-structure.yaml exists in the run directory
    And the file contains a valid ControlStructure model when read back

  # stage2-coordination-analysis-12
  Scenario: stage2-coordination-analysis-12 revision still uses ControlStructure as response format
    Given a valid ControlStructure from Stage 2
    And critic findings with unjustified gaps
    And an LLM that returns a valid revised ControlStructure JSON
    When Stage 2 revision is run
    Then a ControlStructure model is produced
    And the control structure passes foundation validation

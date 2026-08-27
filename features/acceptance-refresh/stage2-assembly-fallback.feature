# mutation-stamp: sha256=294ec7d477cf520003678df6317258c6c743ec7986edfc3fca60b65068575a3a
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:43:07.288934Z","feature_name":"Stage 2 Assembly and Coordination Fallback","feature_path":"features/acceptance-refresh/stage2-assembly-fallback.feature","background_hash":"735aa2fb84d842e36739cddaa352d803bb5db74f82b7bdfb5669285595f71d21","implementation_hash":"sha256:b784f47daac8e59142d59e5ebe6e80ab4c460e29258775aee1e9798482beedc6","scenarios":[{"index":1,"name":"stage2-assembly-fallback-02 fallback preserves elements from both calls","scenario_hash":"1bb422a557655b2bbea9fc7bc6fc27d4f924c20198cc05ae1dc5e8c520afa3aa","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:07.288934Z"}]}
# acceptance-mutation-manifest-end

# stage2-assembly-fallback
Feature: Stage 2 Assembly and Coordination Fallback
  The single ConnectionSet merge is replaced by two independent, separately
  recoverable steps. Assembly merges Call 2a's ResponsibilitySet with Call
  2b's ControlElementSet; on failure it logs step assemble_control_structure
  and falls back to a sanitized responsibilities-only ControlStructure.
  Adding Call 3's coordination links is a second step; on failure it logs
  step add_coordination_links and returns the ControlStructure without
  links. Neither failure crashes the pipeline; both are recorded in the run
  manifest stage_warnings while stage_errors remains reserved for fatal stage
  failures. The retired step name merge_connection_set must
  never appear in a call log.

  Background:
    Given the STPA system model control_structure module is importable
    And a use-case description is available
    And a run directory for output and call logging
    And a ResponsibilitySet from Call 2a with responsibilities RESP-1 and RESP-2

  # stage2-assembly-fallback-01
  Scenario: stage2-assembly-fallback-01 invalid control elements fall back to responsibilities only
    Given a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then a ControlStructure model is produced
    And the control structure passes foundation validation
    And the ControlStructure coordination_links list is empty
    And the pipeline does not crash

  # stage2-assembly-fallback-02
  Scenario Outline: stage2-assembly-fallback-02 fallback preserves elements from both calls
    Given a ControlElementSet from Call 2b with controlled process CP-1
    And a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then the ControlStructure contains <element_kind> <element_id>

    Examples:
      | element_kind       | element_id |
      | responsibility     | RESP-1     |
      | responsibility     | RESP-2     |
      | controlled process | CP-1       |

  # stage2-assembly-fallback-03
  Scenario: stage2-assembly-fallback-03 assembly failure is logged as assemble_control_structure
    Given a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then a call log entry is appended with stage stage_2
    And the call log entry step is assemble_control_structure
    And the call log entry success is false
    And the call log entry has an error message field
    And the warnings list includes a warning naming step assemble_control_structure

  # stage2-assembly-fallback-04
  Scenario: stage2-assembly-fallback-04 fallback ControlStructure is written to control-structure.yaml
    Given an LLM that returns a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When Stage 2 control structure derivation is run
    Then a file control-structure.yaml exists in the run directory
    And the file contains a valid ControlStructure model when read back

  # stage2-assembly-fallback-05
  Scenario: stage2-assembly-fallback-05 invalid coordination links are dropped and logged
    Given a valid ControlStructure from Stage 2
    And a CoordinationAnalysis whose coordination link references a non-existent responsibility
    When the Stage 2 coordination link addition with fallback is executed
    Then a ControlStructure model is produced
    And the ControlStructure coordination_links list is empty
    And a call log entry is appended with stage stage_2
    And the call log entry step is add_coordination_links
    And the warnings list includes a warning naming step add_coordination_links

  # stage2-assembly-fallback-06
  Scenario: stage2-assembly-fallback-06 the retired merge step name never appears
    Given an LLM that returns valid responses for all four Stage 2 calls
    When Stage 2 control structure derivation is run
    Then no call log entry has step merge_connection_set

  # stage2-assembly-fallback-07
  Scenario: stage2-assembly-fallback-07 assembly failure yields a partial but usable run
    Given an LLM that returns valid responses for stage_1a and stage_1b
    And an LLM that returns a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the full SP1 run is executed
    Then the pipeline does not crash
    And a run manifest is written
    And the manifest contains a stage_warnings field
    And the SP1RunResult control_structure is not None
    And the heuristic result is available
    And the SP1RunResult stage_warnings contains the assemble_control_structure repair

  # stage2-assembly-fallback-08
  Scenario: stage2-assembly-fallback-08 successful assembly produces no warnings
    Given a ControlElementSet from Call 2b with controlled process CP-1
    When the Stage 2 assembly with fallback is executed
    Then a ControlStructure model is produced
    And the control structure passes foundation validation
    And the warnings list is empty
    And no assembly failure is logged

# mutation-stamp: sha256=6199672de1b71111b41f3fdf618989caeff326d8b723ed1b685b6e2c91ae5f52
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-12T10:34:29.652153Z","feature_name":"SP1 Stage 2 \u2014 RevisionDelta pattern for revision step","feature_path":"features/sp1_revision_delta.feature","background_hash":"c42e690021d0020f9a64a3dc0b7b3c75c268a2b316f6b739f401709926a7a073","implementation_hash":"sha256:d853b91786c6d7c36486aa330a28f2a3d81a4cfdc2e36a177f3f817c6a3b9001","scenarios":[{"index":7,"name":"RevisionDelta-08 revision_system.j2 contains ID format rules with next-available numbers","scenario_hash":"2c43e647fa37ca387576ada729ce889a798a4c144126db683b12e8deba111083","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-12T10:34:29.652153Z"},{"index":6,"name":"RevisionDelta-07 revision_user.j2 contains per-finding add-or-dismiss directive","scenario_hash":"cba7b9b1b6b976b8cb6b82ccc7539b3b0117e6758d428045b8a7401aa1ffbd9b","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-12T10:32:45.540462Z"},{"index":12,"name":"RevisionDelta-13 revision_user.j2 checklist includes each gap with add-or-dismiss directive","scenario_hash":"e53427f4d9c8120a93139e2b0ea714e402da67ff84ebf3ce4c0bdde4db2676d4","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-12T10:32:45.540462Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 Stage 2 — RevisionDelta pattern for revision step
  The Stage 2 revision step has a 0/8 success rate because the LLM must
  restate the entire control structure before adding new elements, there
  is no ID format guidance, and the instruction is vague. The fix
  introduces a RevisionDelta schema containing only new and modified
  elements, a numbered per-finding checklist in the revision user prompt,
  and ID format rules with next-available-ID template variables in the
  revision system prompt. The RevisionDelta is merged programmatically
  into the existing ControlStructure, eliminating the full-reproduction
  burden. The strip_empty_responsibilities function remains as a safety
  net.

  Background:
    Given the STPA system model revision module is importable
    And a control structure with responsibilities RESP-1 and RESP-2 is available
    And CriticFindings with unjustified gaps are available
    And a run directory for call logging

  # RevisionDelta-01
  Scenario: RevisionDelta-01 RevisionDelta schema contains only delta fields
    Given the RevisionDelta Pydantic model is defined
    Then the model has a new_responsibilities field of type list
    And the model has a new_controlled_processes field of type list
    And the model has a new_coordination_links field of type list
    And the model has a modified_responsibilities field of type list
    And the model does not have a responsibilities field for the full structure

  # RevisionDelta-02
  Scenario: RevisionDelta-02 run_revision produces RevisionDelta from LLM
    Given an LLM that returns a RevisionDelta with a new responsibility RESP-3
    When the revision is run
    Then the revision LLM call uses RevisionDelta as the response format
    And a revised ControlStructure model is produced

  # RevisionDelta-03
  Scenario: RevisionDelta-03 new_responsibilities are merged into existing ControlStructure
    Given an LLM that returns a RevisionDelta with new_responsibilities containing RESP-3
    When the revision is run
    Then the final control structure contains RESP-1
    And the final control structure contains RESP-2
    And the final control structure contains RESP-3

  # RevisionDelta-04
  Scenario: RevisionDelta-04 modified_responsibilities replace existing ones by resp_id
    Given an LLM that returns a RevisionDelta with modified_responsibilities containing RESP-1 with an updated description
    And the pre-revision responsibility RESP-1 owns security constraint SC-1
    When the revision is run
    Then the final control structure contains RESP-1 with the updated description
    And the final control structure contains RESP-2 unchanged
    And the revised responsibility RESP-1 still owns security constraint SC-1

  # RevisionDelta-05
  Scenario: RevisionDelta-05 new_controlled_processes are merged into ControlStructure
    Given an LLM that returns a RevisionDelta with new_controlled_processes containing CP-2
    When the revision is run
    Then the final control structure contains CP-2

  # RevisionDelta-06
  Scenario: RevisionDelta-06 new_coordination_links are added to ControlStructure
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-1
    When the revision is run
    Then the final control structure contains coordination link CL-1

  # RevisionDelta-07
  Scenario Outline: RevisionDelta-07 revision_user.j2 contains per-finding add-or-dismiss directive
    Given the template revision_user.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                                                        |
      | add the missing element(s) to the RevisionDelta                 |
      | dismiss it with a one-sentence justification in dismissed_gaps  |
      | gap_type                                                        |

  # RevisionDelta-08
  Scenario Outline: RevisionDelta-08 revision_system.j2 contains ID format rules with next-available numbers
    Given the template revision_system.j2 is loaded
    Then the template text contains "ID format rules"
    And the template text contains the rule for <element_kind> using <id_format>

    Examples:
      | element_kind           | id_format      |
      | New responsibilities   | RESP-{next_resp_num}  |
      | New PM parts           | PM-{resp_num}-{next_pm_num}  |
      | New CAs                | CA-{resp_num}-{next_ca_num}  |
      | New FB channels        | FB-{resp_num}-{next_fb_num}  |
      | New RCs                | RC-{resp_num}-{next_rc_num}  |
      | New coordination links | CL-{next_cl_num}      |

  # RevisionDelta-09
  Scenario: RevisionDelta-09 revision_system.j2 next-available-ID template variables are computed from existing structure
    Given a control structure with responsibilities RESP-1 and RESP-2 and coordination link CL-1
    When the revision system prompt is rendered
    Then the rendered text contains the next available responsibility number 3
    And the rendered text contains the next available coordination link number 2

  # RevisionDelta-10
  Scenario: RevisionDelta-10 RevisionDelta merge validates the final ControlStructure
    Given an LLM that returns a RevisionDelta with new_responsibilities containing RESP-3 with valid PM, CA, and FB elements
    When the revision is run
    Then the final control structure passes foundation validation

  # RevisionDelta-11
  Scenario: RevisionDelta-11 strip_empty_responsibilities remains as safety net after revision delta merge
    Given an LLM that returns a RevisionDelta with a new_responsibility RESP-4 that has no PM parts, CAs, or FB channels
    When the revision is run
    Then the resulting control structure does not contain RESP-4
    And a warning is logged about the stripped empty responsibility

  # RevisionDelta-12
  Scenario: RevisionDelta-12 RevisionDelta merge preserves existing responsibilities not in delta
    Given an LLM that returns an empty RevisionDelta with no new or modified elements
    When the revision is run
    Then the final control structure contains RESP-1
    And the final control structure contains RESP-2
    And the final control structure responsibilities count is 2

  # RevisionDelta-13
  Scenario Outline: RevisionDelta-13 revision_user.j2 checklist includes each gap with add-or-dismiss directive
    Given the template revision_user.j2 is loaded
    And CriticFindings with gaps of type missing_responsibility and missing_feedback are available
    When the template is rendered with the critic findings
    Then the rendered text contains a numbered item for the <gap_type> gap
    And the rendered text contains "<fragment>"

    Examples:
      | gap_type               | fragment                                                        |
      | missing_responsibility | add the missing element(s) to the RevisionDelta                 |
      | missing_feedback       | dismiss it with a one-sentence justification in dismissed_gaps  |

  # RevisionDelta-14
  Scenario: RevisionDelta-14 revision_system.j2 preserves existing rules about solution neutrality and valid references
    Given the template revision_system.j2 is loaded
    Then the template text contains "solution-neutrality"
    And the template text contains "ElementRef references must be valid"
    And the template text contains "feedback channel updates must reference a PM in the same responsibility"

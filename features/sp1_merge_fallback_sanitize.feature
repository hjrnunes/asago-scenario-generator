# mutation-stamp: sha256=af5aa27b7036f99eefe813ff40f83dc22cdd8574718942309790dd065e494f9a
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T23:22:09.775126Z","feature_name":"SP1 \u2014 Sanitize invalid ElementRefs in assembly fallback path","feature_path":"features/sp1_merge_fallback_sanitize.feature","background_hash":"e49625a851f9d80ab3d4804bd5eb5fae48438f78dc69f92c30ff83ac2804cbc4","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Sanitize-01 fallback nullifies unresolvable ElementRef in each ref field","scenario_hash":"b06220e5aa4a0a73cf62e612c9187016904d62873c93fdd9a416381c934eed19","mutation_count":15,"result":{"Total":15,"Killed":15,"Survived":0,"Errors":0},"tested_at":"2026-08-11T23:21:57.644261Z"},{"index":1,"name":"Sanitize-04 valid ElementRefs are preserved during sanitization","scenario_hash":"820556a52fa6dfc4cfabe99379e31bc783a001b5023c8fe9ce270cbfca595547","mutation_count":9,"result":{"Total":9,"Killed":9,"Survived":0,"Errors":0},"tested_at":"2026-08-11T23:21:57.644261Z"},{"index":6,"name":"Sanitize-09 sanitized fallback preserves Call 2a responsibilities and Call 2b controlled processes","scenario_hash":"9f449bff6d39c66b4d8b5be9b498790e5ebfe92a4549fd114537e913db3c788e","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-11T23:21:57.644261Z"},{"index":8,"name":"Sanitize-11 strip tier carries over <element_type> from Call 2b with refs stripped","scenario_hash":"588652ade41e9497a7731b1d3b7c246a163078e432e22c740c2d6b7dd3645b79","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-11T23:21:57.644261Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 — Sanitize invalid ElementRefs in assembly fallback path
  Neither the ResponsibilitySet from Call 2a nor the ControlElementSet from
  Call 2b has a model validator, so the LLM can produce ElementRef values
  (e.g. type controlled_process, id FB-1-1) that parse successfully but
  fail ControlStructure validation. When assembly fails and the fallback
  path constructs a ControlStructure from those two inputs, invalid
  ElementRefs would crash the whole run. _sanitize_for_fallback() nullifies
  unresolvable ElementRefs; the fallback construction is wrapped in a
  try/except; and a further-degraded path strips ALL ElementRefs if
  sanitization still fails. All stripped references are logged in the
  warnings list. Resolvability is judged against the responsibilities from
  Call 2a AND the controlled processes from Call 2b — a ref to a controlled
  process is valid only when Call 2b supplied that controlled process.

  Background:
    Given the STPA system model module is importable
    And a use-case description is available
    And a run directory for output and call logging

  # Sanitize-01
  Scenario Outline: Sanitize-01 fallback nullifies unresolvable ElementRef in each ref field
    Given a valid ResponsibilitySet from Call 2a with responsibility RESP-1
    And the ResponsibilitySet has a <element_type> <element_id> with <ref_field> {type: <ref_type>, id: <ref_id>}
    And a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then a ControlStructure model is produced
    And the <element_type> <element_id> <ref_field> is None
    And the pipeline does not crash

    Examples:
      | element_type      | element_id | ref_field       | ref_type           | ref_id  |
      | ProcessModelPart  | PM-1-1     | feedback_source | controlled_process | FB-1-1  |
      | ControlAction     | CA-1-1     | target          | responsibility     | RESP-99 |
      | FeedbackChannel   | FB-1-1     | source          | controlled_process | CP-99   |

  # Sanitize-04
  Scenario Outline: Sanitize-04 valid ElementRefs are preserved during sanitization
    Given a valid ResponsibilitySet from Call 2a with responsibility RESP-1 and a ControlElementSet from Call 2b with controlled process CP-1
    And the ResponsibilitySet has a <element_type> <element_id> with <ref_field> pointing to CP-1
    And a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then the <element_type> <element_id> <ref_field> is preserved and not nullified

    Examples:
      | element_type      | element_id | ref_field       |
      | ProcessModelPart  | PM-1-1     | feedback_source |
      | ControlAction     | CA-1-1     | target          |
      | FeedbackChannel   | FB-1-1     | source          |

  # Sanitize-05
  Scenario: Sanitize-05 sanitized fallback ControlStructure passes foundation validation
    Given a valid ResponsibilitySet from Call 2a with responsibility RESP-1 and a ControlElementSet from Call 2b with controlled process CP-1
    And the ResponsibilitySet has a ProcessModelPart PM-1-1 with feedback_source {type: controlled_process, id: INVALID-1}
    And the ResponsibilitySet has a ControlAction CA-1-1 with target {type: controlled_process, id: INVALID-2}
    And a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then the control structure passes foundation validation

  # Sanitize-06
  Scenario: Sanitize-06 stripped references are logged in warnings
    Given a valid ResponsibilitySet from Call 2a with responsibility RESP-1
    And the ResponsibilitySet has a ProcessModelPart PM-1-1 with feedback_source {type: controlled_process, id: FB-1-1}
    And the ResponsibilitySet has a ControlAction CA-1-1 with target {type: responsibility, id: RESP-99}
    And a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then the warnings list includes a warning about the stripped feedback_source for PM-1-1
    And the warnings list includes a warning about the stripped target for CA-1-1

  # Sanitize-07
  Scenario: Sanitize-07 fallback does not crash with completely invalid ElementRef values
    Given a valid ResponsibilitySet from Call 2a with responsibility RESP-1
    And the ResponsibilitySet has a ProcessModelPart PM-1-1 with feedback_source {type: controlled_process, id: FB-1-1}
    And the ResponsibilitySet has a ControlAction CA-1-1 with target {type: controlled_process, id: CA-2-1}
    And the ResponsibilitySet has a FeedbackChannel FB-1-1 with source {type: responsibility, id: PM-3-1}
    And a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then a ControlStructure model is produced
    And the pipeline does not crash

  # Sanitize-08
  Scenario: Sanitize-08 further-degraded path strips ALL ElementRefs when sanitization still fails
    Given a valid ResponsibilitySet from Call 2a with responsibility RESP-1
    And the ResponsibilitySet has a ProcessModelPart PM-1-1 with feedback_source {type: controlled_process, id: FB-1-1}
    And the ResponsibilitySet has duplicate responsibility RESP-1 causing validation failure even after sanitization
    And a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then a ControlStructure model is produced
    And all feedback_source fields are None
    And all control_action target fields are None
    And all feedback_channel source fields are None
    And the pipeline does not crash

  # Sanitize-09
  Scenario Outline: Sanitize-09 sanitized fallback preserves Call 2a responsibilities and Call 2b controlled processes
    Given a valid ResponsibilitySet from Call 2a with responsibilities RESP-1 and RESP-2 and a ControlElementSet from Call 2b with controlled process CP-1
    And the ResponsibilitySet has a ProcessModelPart PM-1-1 with feedback_source {type: controlled_process, id: INVALID-1}
    And a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then the ControlStructure contains <element_kind> <element_id>

    Examples:
      | element_kind      | element_id |
      | responsibility    | RESP-1     |
      | responsibility    | RESP-2     |
      | controlled process | CP-1      |

  # Sanitize-10
  Scenario: Sanitize-10 normal assembly success path produces no warnings
    Given a valid ResponsibilitySet from Call 2a with responsibilities RESP-1 and RESP-2
    And a ControlElementSet from Call 2b with controlled process CP-1
    When the Stage 2 assembly with fallback is executed
    Then a ControlStructure model is produced
    And the control structure passes foundation validation
    And the warnings list is empty
    And no sanitization warnings are present

  # Sanitize-11
  Scenario Outline: Sanitize-11 strip tier carries over <element_type> from Call 2b with refs stripped
    Given a valid ResponsibilitySet from Call 2a with responsibility RESP-1
    And the ResponsibilitySet has duplicate responsibility RESP-1 causing validation failure even after sanitization
    And a ControlElementSet from Call 2b with an unresolvable feedback source reference
    When the Stage 2 assembly with fallback is executed
    Then a ControlStructure model is produced
    And the <element_type> <element_id> <ref_field> is None
    And the pipeline does not crash

    Examples:
      | element_type    | element_id | ref_field |
      | ControlAction   | CA-1-1     | target    |
      | FeedbackChannel | FB-1-1     | source    |

  # Sanitize-12
  Scenario: Sanitize-12 fallback drops an unresolvable object-shaped feedback update
    Given a valid ResponsibilitySet from Call 2a with responsibility RESP-1
    And a ControlElementSet from Call 2b whose feedback channel FB-1-1 updates {type: responsibility, id: RESP-1}
    When the Stage 2 assembly with fallback is executed
    Then a ControlStructure model is produced
    And the warnings list includes a warning about the stripped updates for FB-1-1
    And the pipeline does not crash

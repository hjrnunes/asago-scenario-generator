Feature: SP1 ID normalization repairs
  SP1 repairs recoverable LLM control-structure fields before schema
  validation. An ElementRef whose type repeats its RESP-* or CP-* ID receives
  the corresponding reference type, and a blank element description receives
  a human-readable description from its normalized context. Valid supplied
  values remain unchanged, while values that cannot be inferred still fail
  validation.

  Background:
    Given a tolerantly decoded SP1 control-structure payload
    And every field not varied by the scenario is valid

  # SP1-ID-NORMALIZATION-REPAIRS-01 infers malformed ElementRef types and preserves valid types
  Scenario Outline: SP1-ID-NORMALIZATION-REPAIRS-01 infers malformed ElementRef types and preserves valid types
    Given the element at <referenced_position> has source ID <source_id>
    And <reference_owner> has <reference_field> type <supplied_type> and ID <source_id>
    And <reference_owner> <reference_field> was supplied with type <expected_input>
    When the payload is normalized
    Then <reference_owner> <reference_field> has type <reference_type>
    And <reference_owner> <reference_field> has ID <canonical_id>
    And source ID <expected_source> maps to <canonical_id>
    And the normalized payload validates as a ControlStructure

    Examples:
      | referenced_position  | source_id | expected_source | reference_owner                        | reference_field | supplied_type      | expected_input     | reference_type     | canonical_id |
      | responsibility 2     | RESP-9    | RESP-9          | responsibility 1 process model part 1 | feedback_source | RESP-9             | RESP-9             | responsibility     | RESP-2       |
      | controlled process 2 | CP-9      | CP-9            | responsibility 1 control action 1     | target          | CP-9               | CP-9               | controlled_process | CP-2         |
      | controlled process 2 | CP-9      | CP-9            | responsibility 1 feedback channel 1   | source          | CP-9               | CP-9               | controlled_process | CP-2         |
      | controlled process 2 | CP-9      | CP-9            | responsibility 1 control action 1     | target          | RESP-77            | RESP-77            | controlled_process | CP-2         |
      | responsibility 2     | RESP-9    | RESP-9          | responsibility 1 process model part 1 | feedback_source | responsibility     | responsibility     | responsibility     | RESP-2       |
      | controlled process 2 | CP-9      | CP-9            | responsibility 1 control action 1     | target          | controlled_process | controlled_process | controlled_process | CP-2         |

  # SP1-ID-NORMALIZATION-REPAIRS-02 leaves an uninferable ElementRef type for validation
  Scenario: SP1-ID-NORMALIZATION-REPAIRS-02 leaves an uninferable ElementRef type for validation
    Given controlled process 1 has source ID process-alpha
    And responsibility 1 control action 1 target has type unknown-process and ID unknown-process
    When the payload is normalized
    Then the target type remains unknown-process
    When the normalized payload is validated
    Then validation fails with an error identifying target type

  # SP1-ID-NORMALIZATION-REPAIRS-03 repairs blank descriptions for every control-structure element
  Scenario Outline: SP1-ID-NORMALIZATION-REPAIRS-03 repairs blank descriptions for every control-structure element
    Given <element> <canonical_id> has an empty description
    When the payload is normalized
    Then <element> <canonical_id> has description <expected_description>
    And the normalized payload validates as a ControlStructure

    Examples:
      | element                   | canonical_id | expected_description                    |
      | responsibility            | RESP-1       | Responsibility RESP-1                   |
      | responsibility constraint | RC-1-1       | Responsibility constraint RC-1-1        |
      | process model part        | PM-1-1       | Process model part PM-1-1               |
      | control action            | CA-1-1       | Control action CA-1-1                   |
      | controlled process        | CP-1         | Controlled process CP-1                 |
      | coordination link         | CL-1         | Coordination link CL-1                  |
      | coordination mechanism    | CM-1         | Coordination mechanism CM-1             |

  # SP1-ID-NORMALIZATION-REPAIRS-04 describes repaired feedback from its normalized references
  Scenario: SP1-ID-NORMALIZATION-REPAIRS-04 describes repaired feedback from its normalized references
    Given controlled process 2 has source ID CP-9
    And responsibility 1 process model part 1 has source ID state-alpha
    And responsibility 1 feedback channel 1 has an empty description
    And its source has type CP-9 and ID CP-9
    And its updates value is state-alpha
    When the payload is normalized
    Then feedback channel FB-1-1 has description Feedback from controlled process CP-2 updating process model part PM-1-1
    And the normalized payload validates as a ControlStructure

  # SP1-ID-NORMALIZATION-REPAIRS-05 preserves supplied non-empty descriptions
  Scenario Outline: SP1-ID-NORMALIZATION-REPAIRS-05 preserves supplied non-empty descriptions
    Given <element> <canonical_id> has description Operator supplied description
    When the payload is normalized
    Then normalization preserves the description Operator supplied description on <element> <canonical_id>

    Examples:
      | element                   | canonical_id |
      | responsibility            | RESP-1       |
      | responsibility constraint | RC-1-1       |
      | process model part        | PM-1-1       |
      | control action            | CA-1-1       |
      | feedback channel          | FB-1-1       |
      | controlled process        | CP-1         |
      | coordination link         | CL-1         |
      | coordination mechanism    | CM-1         |

  # SP1-ID-NORMALIZATION-REPAIRS-06 repairs the combined production response before assembly validation
  Scenario: SP1-ID-NORMALIZATION-REPAIRS-06 repairs the combined production response before assembly validation
    Given Call 2a and Call 2b use id instead of each model-specific ID field
    And Call 2b omits every feedback channel description
    And Call 2b copies each referenced RESP-* or CP-* ID into its ElementRef type
    And the source IDs differ from the IDs implied by final list position
    When SP1 assembles the control structure with deterministic ID normalization
    Then every element has its canonical ID from final list position
    And every ElementRef has the type implied by its referenced ID prefix
    And every ElementRef ID identifies the corresponding canonical element
    And every element has a non-empty description
    And ControlStructure validation succeeds without assembly degradation

  # SP1-ID-NORMALIZATION-REPAIRS-07 applies the same repairs after revision stitching
  Scenario: SP1-ID-NORMALIZATION-REPAIRS-07 applies the same repairs after revision stitching
    Given a decoded revision delta adds elements using id instead of model-specific ID fields
    And an added feedback channel has an empty description
    And an added ElementRef copies its CP-* ID into its type
    And every revision reference resolves by source ID in the stitched structure
    When the revision delta is merged
    Then the added elements have canonical IDs from final list position
    And the added feedback channel has a non-empty human-readable description
    And the added ElementRef has type controlled_process and the canonical controlled-process ID
    And the revised ControlStructure validates without a degraded-revision warning

  # SP1-ID-NORMALIZATION-REPAIRS-08 wraps and rewrites recognized bare-string ElementRefs
  Scenario Outline: SP1-ID-NORMALIZATION-REPAIRS-08 wraps and rewrites recognized bare-string ElementRefs
    Given the element at <referenced_position> has source ID <source_id>
    And <reference_location> is the bare string <source_id>
    When the payload is normalized
    Then <reference_location> is an ElementRef object with type <reference_type> and ID <canonical_id>
    And the normalized payload validates as a ControlStructure

    Examples:
      | referenced_position  | source_id | reference_location                                  | reference_type     | canonical_id |
      | controlled process 2 | CP-9      | responsibility 1 process model part 1 feedback_source | controlled_process | CP-2         |
      | controlled process 2 | CP-9      | responsibility 1 control action 1 target            | controlled_process | CP-2         |
      | controlled process 2 | CP-9      | responsibility 1 feedback channel 1 source          | controlled_process | CP-2         |
      | responsibility 2     | RESP-9    | responsibility 1 process model part 1 feedback_source | responsibility     | RESP-2       |
      | responsibility 2     | RESP-9    | responsibility 1 control action 1 target            | responsibility     | RESP-2       |
      | responsibility 2     | RESP-9    | responsibility 1 feedback channel 1 source          | responsibility     | RESP-2       |

  # SP1-ID-NORMALIZATION-REPAIRS-09 leaves an unrecognized bare-string ElementRef for validation
  Scenario: SP1-ID-NORMALIZATION-REPAIRS-09 leaves an unrecognized bare-string ElementRef for validation
    Given responsibility 1 control action 1 target is the bare string process-alpha
    When the payload is normalized
    Then responsibility 1 control action 1 target remains the bare string process-alpha
    When the normalized payload is validated
    Then validation fails with an error identifying target as a malformed ElementRef

  # SP1-ID-NORMALIZATION-REPAIRS-10 preserves null ElementRef fields
  Scenario Outline: SP1-ID-NORMALIZATION-REPAIRS-10 preserves null ElementRef fields
    Given <reference_location> is null
    When the payload is normalized
    Then <reference_location> remains null
    And the normalized payload validates as a ControlStructure

    Examples:
      | reference_location                                  |
      | responsibility 1 process model part 1 feedback_source |
      | responsibility 1 control action 1 target            |
      | responsibility 1 feedback channel 1 source          |

  # SP1-ID-NORMALIZATION-REPAIRS-11 preserves every production-shaped bare-string cross-reference
  Scenario: SP1-ID-NORMALIZATION-REPAIRS-11 preserves every production-shaped bare-string cross-reference
    Given Call 2b returns 11 control actions with bare-string targets
    And Call 2b returns 16 feedback channels with bare-string sources
    And every bare string identifies an existing responsibility or controlled process by source ID
    And the source IDs differ from the IDs implied by final list position
    When SP1 assembles the control structure with deterministic ID normalization
    Then all 11 control action targets are ElementRef objects with canonical IDs
    And all 16 feedback channel sources are ElementRef objects with canonical IDs
    And every cross-reference identifies its intended element
    And ControlStructure validation succeeds without assembly degradation

Feature: SP1 stage-local rejection of incomplete Call 2b semantic fields
  The generic tolerant decoder remains available to unrelated model calls, but
  Stage 2 Call 2b output is semantic model data. Missing ownership or meaning
  must fail at assembly rather than being assigned from response-array order or
  filled with a generated placeholder. Lower-level ID normalization continues
  to cover explicitly isolated payload-normalization behavior.

  Background:
    Given a valid Call 2a response with ordered responsibilities
    And Call 2b is decoded in tolerant mode
    And SP1 assembles the responses with deterministic ID normalization

  # SP1-TOLERANT-DECODE-01 rejects a control action whose ca_id is omitted
  Scenario: SP1-TOLERANT-DECODE-01 rejects a control action whose ca_id is omitted
    Given Call 2a has ordered responsibilities RESP-8, RESP-4
    And Call 2b control action 1 has ca_id omitted
    And Call 2b control action 2 has ca_id CA-4-9
    When the control structure is assembled
    Then validation fails with error containing unmatched control-element ownership

  # SP1-TOLERANT-DECODE-02 assigns canonical IDs for missing and blank Call 2b source IDs
  Scenario Outline: SP1-TOLERANT-DECODE-02 assigns canonical IDs for missing and blank Call 2b source IDs
    Given the assembled payload has a <element_type> at <structural_position> whose ID is <source_id_state>
    When the payload IDs are normalized
    Then the <element_type> at <structural_position> has ID <canonical_id>

    Examples:
      | element_type       | structural_position           | source_id_state | canonical_id |
      | control action     | responsibility 1 child 1      | omitted         | CA-1-1      |
      | control action     | responsibility 1 child 2      | blank           | CA-1-2      |
      | feedback channel   | responsibility 2 child 1      | omitted         | FB-2-1      |
      | feedback channel   | responsibility 2 child 2      | blank           | FB-2-2      |
      | controlled process | controlled process 1          | omitted         | CP-1        |
      | controlled process | controlled process 2          | blank           | CP-2        |

  # SP1-TOLERANT-DECODE-03 rejects an omitted required non-ID field
  Scenario: SP1-TOLERANT-DECODE-03 rejects an omitted required non-ID field
    Given Call 2b control action 1 has ca_id source-action
    And the control action omits required field description
    When the control structure is assembled
    Then validation fails with error containing unmatched control-element ownership

  # SP1-TOLERANT-DECODE-04 fallback does not recover missing ownership
  Scenario: SP1-TOLERANT-DECODE-04 fallback rejects missing control-action ownership
    Given Call 2a has ordered responsibilities RESP-7
    And Call 2b control action 1 has ca_id omitted
    And the control action target references absent controlled process CP-99
    When control-structure assembly enters the fallback path
    Then validation fails with error containing unmatched control-element ownership

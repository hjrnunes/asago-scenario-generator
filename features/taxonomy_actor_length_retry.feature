Feature: Taxonomy actor profile completion-length retry
  Taxonomy actor profiles use the operator-configured completion limit. A
  completion-length failure gets one concise corrective retry with that same
  limit, and a second length failure remains visible.

  Background:
    Given actor profile generation is configured with max_completion_tokens 16384

  # Taxonomy actor profile completion-length retry 01 retries once with feedback
  Scenario: Taxonomy actor profile completion-length retry 01 retries once with feedback
    Given the initial actor profile completion raises LengthFinishReasonError
    And the single actor retry returns a valid structured profile
    When the actor profile retry sequence runs
    Then actor profile completion attempts exactly 2 times
    And the actor retry contains concise corrective feedback
    And every actor profile completion uses the configured token limit

  # Taxonomy actor profile completion-length retry 02 remains bounded
  Scenario: Taxonomy actor profile completion-length retry 02 remains bounded
    Given the initial actor profile completion raises LengthFinishReasonError
    And the single actor retry raises LengthFinishReasonError
    When the actor profile retry sequence runs
    Then actor profile completion attempts exactly 2 times
    And every actor profile completion uses the configured token limit
    And actor generation reports LengthFinishReasonError

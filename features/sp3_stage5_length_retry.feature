Feature: SP3 Stage 5 completion-length retry
  Stage 5 distinguishes a completion-length exhaustion from other LLM
  failures. It retries that scenario once with the existing structured BDI
  schema, a concise corrective prompt, and a completion ceiling no greater
  than 2048 tokens. First-attempt success is unchanged, and retry exhaustion
  remains visible in Stage 5 diagnostics.

  Background:
    Given one valid structural threat for ICA slot RESP-1:CA-1-1:NOT_PROVIDED
    And a valid control structure containing RESP-1 and CA-1-1
    And valid Stage 6 responses are available for every Stage 5 result

  # SP3-STAGE5-COMPLETION-LENGTH-RETRY-01
  Scenario: SP3-STAGE5-COMPLETION-LENGTH-RETRY-01 preserves a successful first attempt
    Given the first BDI completion returns a valid structured BDI result
    When the SP3 run is executed
    Then Stage 5 makes exactly 1 BDI completion attempt
    And Stage 5 uses the first BDI result without a corrective prompt
    And one ScenarioSpec is produced
    And no Stage 5 BDI generation error is reported

  # SP3-STAGE5-COMPLETION-LENGTH-RETRY-02
  Scenario: SP3-STAGE5-COMPLETION-LENGTH-RETRY-02 retries one completion-length exhaustion successfully
    Given the first BDI completion raises LengthFinishReasonError
    And the second BDI completion returns a valid structured BDI result
    When the SP3 run is executed
    Then Stage 5 makes exactly 2 BDI completion attempts
    And the second attempt requests the existing structured BDI schema
    And the second attempt has max_completion_tokens no greater than 2048
    And the second attempt prompt says the prior response was truncated
    And the second attempt prompt requests only a concise schema-matching response
    And one ScenarioSpec is produced from the second BDI result
    And no Stage 5 BDI generation error is reported

  # SP3-STAGE5-COMPLETION-LENGTH-RETRY-03
  Scenario: SP3-STAGE5-COMPLETION-LENGTH-RETRY-03 exposes an exhausted retry as a stage error
    Given the first BDI completion raises LengthFinishReasonError
    And the second BDI completion raises LengthFinishReasonError
    When the SP3 run is executed
    Then Stage 5 makes exactly 2 BDI completion attempts
    And no ScenarioSpec is produced for the structural threat
    And the Stage 5 errors report an exhausted BDI generation retry
    And the Stage 5 errors mention LengthFinishReasonError
    And calls.jsonl records both failed Stage 5 attempts

  # SP3-STAGE5-COMPLETION-LENGTH-RETRY-04
  Scenario Outline: SP3-STAGE5-COMPLETION-LENGTH-RETRY-04 does not retry other LLM failures
    Given the first BDI completion raises <error_type> with message <error_message>
    When the SP3 run is executed
    Then Stage 5 makes exactly 1 BDI completion attempt
    And no ScenarioSpec is produced for the structural threat
    And the Stage 5 errors mention <error_type>

    Examples:
      | error_type        | error_message                           |
      | RuntimeError      | LengthFinishReasonError text only       |
      | ConnectionError   | model endpoint unavailable              |
      | ValidationError   | attacker_bdi is missing                 |

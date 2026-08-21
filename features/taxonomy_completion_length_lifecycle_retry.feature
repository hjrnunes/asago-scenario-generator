Feature: Taxonomy completion-length lifecycle retry
  The shared LLM adapter exposes completion-length exhaustion as typed data.
  Each generated stage makes one provider request per lifecycle attempt, and
  finalization owns one length-specific retry without increasing the configured
  retry or total-attempt budgets or consuming semantic retry budget.

  Background:
    Given one qualified projected candidate with no fallback candidate
    And taxonomy generation is configured with max_completion_tokens 16384
    And a deterministic local OpenAI-compatible fixture is available

  # Taxonomy completion-length lifecycle retry 01 normalizes provider response shapes
  Scenario Outline: Taxonomy completion-length lifecycle retry 01 normalizes provider response shapes
    Given the fixture returns a <response_shape> <stage> completion with finish reason "length", prompt tokens 31, and completion tokens 16
    When the shared LLM adapter completes that request
    Then it raises a typed CompletionLengthError
    And the error has finish reason "length"
    And the error has prompt tokens 31 and completion tokens 16
    And completion length is classified without inspecting exception text

    Examples:
      | response_shape | stage |
      | structured     | actor |
      | unstructured   | tree  |

  # Taxonomy completion-length lifecycle retry 02 retries every generated stage once
  Scenario Outline: Taxonomy completion-length lifecycle retry 02 retries every generated stage once
    Given the first <stage> provider response ends with finish reason "length", prompt tokens 31, and completion tokens 16
    And the second <stage> provider response is valid
    And the original <stage> user prompt is retained
    When finalization runs the candidate lifecycle
    Then the <stage> stage helper makes exactly 1 provider request per invocation
    And finalization invokes the <stage> stage exactly 2 times
    And the first <stage> provider request uses max_completion_tokens 16384
    And the retry request uses the configured causal control without increasing the total attempt budget
    And the accepted <stage> artifact comes from the second response
    And the retry directive reason is "completion_length"
    And the retry user prompt equals the original prompt followed by "<suffix>"
    And length feedback occurs once after the original prompt
    And length feedback does not occur under access-provenance, title, consistency, or semantic headings
    And the lifecycle inventory has 2 distinct <stage> attempt records
    And the first <stage> StageAttemptFailure has code "completion_length", finish reason "length", prompt tokens 31, and completion tokens 16
    And the lifecycle call log has 2 distinct <stage> attempt entries
    And the first <stage> call log entry has code "completion_length"

    Examples:
      | stage     | suffix                                                                      |
      | actor     | Return only a schema-matching object with bounded lists and concise prose. |
      | narrative | Return only a schema-matching object with bounded lists and concise prose. |
      | tree      | Return only a complete schema-matching YAML document.                      |
      | behavior  | Return only the complete required Gherkin/assertion payload.                |

  # Taxonomy completion-length lifecycle retry 03 makes a second length failure terminal
  Scenario Outline: Taxonomy completion-length lifecycle retry 03 makes a second length failure terminal
    Given the first 2 <stage> provider responses end with finish reason "length"
    When finalization runs the candidate lifecycle
    Then finalization invokes the <stage> stage exactly 2 times
    And no third <stage> provider request is made
    And the <stage> stage is terminal with code "completion_length"
    And the <stage> semantic retry budget is unchanged
    And the <stage> length retry budget is exactly 1
    And the lifecycle inventory has 2 distinct <stage> completion-length failures
    And the lifecycle call log has 2 distinct <stage> entries with code "completion_length"

    Examples:
      | stage     |
      | actor     |
      | narrative |
      | tree      |
      | behavior  |

  # Taxonomy completion-length lifecycle retry 04 preserves the semantic retry budget
  Scenario Outline: Taxonomy completion-length lifecycle retry 04 preserves the semantic retry budget
    Given the fixture scripts <semantic_failures> consecutive non-length semantic violations for <stage> followed by <following_response>
    When finalization runs the candidate lifecycle
    Then finalization invokes the <stage> stage exactly <invocations> times
    And the <stage> stage consumes <owner_retries> semantic owner retries
    And the <stage> lifecycle outcome is <outcome>
    And no <stage> retry directive has reason "completion_length"
    And no <stage> attempt has code "completion_length"

    Examples:
      | stage     | semantic_failures | following_response | invocations | owner_retries | outcome  |
      | actor     | 1                 | a valid response   | 2           | 1             | accepted |
      | narrative | 1                 | a valid response   | 2           | 1             | accepted |
      | tree      | 1                 | a valid response   | 2           | 1             | accepted |
      | behavior  | 1                 | a valid response   | 2           | 1             | accepted |
      | actor     | 3                 | no response        | 3           | 2             | terminal |
      | narrative | 3                 | no response        | 3           | 2             | terminal |
      | tree      | 3                 | no response        | 3           | 2             | terminal |
      | behavior  | 3                 | no response        | 3           | 2             | terminal |

  # Taxonomy completion-length lifecycle retry 05 bounds narrative output shape
  Scenario Outline: Taxonomy completion-length lifecycle retry 05 bounds narrative output shape
    Given the projected candidate selects <selected_step_count> canonical steps
    When the narrative response is accepted
    Then every selected canonical step is covered by the narrative
    And the narrative contains no more than <maximum_narrative_steps> steps

    Examples:
      | selected_step_count | maximum_narrative_steps |
      | 1                   | 3                       |
      | 8                   | 10                      |
      | 14                  | 16                      |
      | 16                  | 16                      |

  # Taxonomy completion-length lifecycle retry 06 statically bounds structured output fields
  Scenario Outline: Taxonomy completion-length lifecycle retry 06 statically bounds structured output fields
    Given the <stage> provider request uses a structured response schema
    When the fixture inspects that response schema
    Then every generated list field declares a finite static maximum item count
    And every generated prose field declares a finite static maximum length

    Examples:
      | stage     |
      | actor     |
      | narrative |
      | behavior  |

  # Taxonomy completion-length lifecycle retry 07 preserves bounded redacted partial diagnostics
  Scenario Outline: Taxonomy completion-length lifecycle retry 07 preserves bounded redacted partial diagnostics
    Given the first 2 <response_shape> <stage> provider responses return partial content "<partial_content>" with finish reason "length", response ID "fixture-response-001", model "fixture-model-v1", and complete usage details
    And each partial response usage has prompt tokens 31, completion tokens 16, total tokens 47, prompt_tokens_details.cached_tokens 3, and completion_tokens_details.reasoning_tokens 5
    When finalization runs the candidate lifecycle
    Then the <stage> stage makes exactly 2 provider requests
    And the first <stage> durable failure evidence has code "completion_length" and finish reason "length"
    And the first <stage> durable failure evidence preserves every fixture usage and token-detail field
    And the first <stage> durable failure evidence preserves response ID "fixture-response-001" and model "fixture-model-v1"
    And the first <stage> durable failure evidence records the partial character count and SHA-256 digest of "<partial_content>"
    And the first <stage> durable failure evidence records a redacted preview prefix and suffix
    And each stored partial preview is no longer than 128 characters
    And the stored partial previews do not contain "<sensitive_marker>"
    And the failed request records a non-null non-negative elapsed duration
    And the partial content is failure evidence only, never parsed, repaired, or admitted
    And no published scenario artifact is created

    Examples:
      | response_shape | stage | partial_content                              | sensitive_marker               |
      | structured     | actor | BEGIN SECRET=fixture-customer@example.invalid END | SECRET=fixture-customer@example.invalid |
      | unstructured   | tree  | BEGIN SECRET=fixture-customer@example.invalid END | SECRET=fixture-customer@example.invalid |

  # Taxonomy completion-length lifecycle retry 08 journals exactly one causal retry control
  Scenario Outline: Taxonomy completion-length lifecycle retry 08 journals exactly one causal retry control
    Given the <stage> length experiment selects approved causal control "<causal_control>" with retry value "<retry_value>"
    And provider-facing fields for the <stage> response are already schema-bounded
    And the first <stage> provider response ends with finish reason "length", prompt tokens 31, and completion tokens 16
    And the second <stage> provider response is valid
    When finalization runs the candidate lifecycle
    Then the <stage> stage makes exactly 2 provider requests
    And the fixture request journal records a fixed total request budget of 2 for the <stage> candidate
    And the retry directive reason is "completion_length"
    And the second <stage> provider request changes exactly one causal field "<causal_field>" from "<initial_value>" to "<retry_value>"
    And every other causal request field is unchanged between the two <stage> requests
    And the generic length suffix is not the only retry change
    And the retry does not lower the transport token cap merely to fail earlier
    And no third <stage> provider request is made

    Examples:
      | stage     | causal_control                             | causal_field                         | initial_value | retry_value |
      | actor     | candidate-specific compact response schema | response schema                      | standard      | compact-v1  |
      | narrative | stage-specific completion cap              | max_completion_tokens                | 16384         | 8192        |
      | tree      | lower retry temperature                   | temperature                          | 0.4           | 0.1         |
      | behavior  | candidate-specific compact response schema | response schema                      | standard      | compact-v1  |

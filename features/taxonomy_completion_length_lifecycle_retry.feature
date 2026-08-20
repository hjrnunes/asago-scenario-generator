Feature: Taxonomy completion-length lifecycle retry
  The shared LLM adapter exposes completion-length exhaustion as typed data.
  Each generated stage makes one provider request per lifecycle attempt, and
  finalization owns one length-specific retry without changing the configured
  completion limit or consuming semantic retry budget.

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
    And both <stage> provider requests use max_completion_tokens 16384
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

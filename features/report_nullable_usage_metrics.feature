Feature: Nullable LLM usage reporting
  Taxonomy-and-risk reports remain available when valid failed or synthetic
  call-log records cannot provide token or duration telemetry. Available
  numeric metrics are still reported, while unavailable metrics are identified
  without being presented as measured usage.

  Background:
    Given an offline taxonomy-and-risk report input

  # Nullable LLM usage reporting NLM-01
  Scenario: Nullable LLM usage reporting NLM-01 failed call metrics are unavailable
    Given the pipeline call log contains one failed call with null prompt_tokens, completion_tokens, and duration_ms
    When the HTML report is generated
    Then report generation succeeds
    And the report retains the failed call
    And the unavailable call displays prompt_tokens, completion_tokens, and duration_ms as unavailable
    And the pipeline totals show 0 prompt tokens, 0 completion tokens, and 0 milliseconds
    And the report warns that the call has unavailable usage metrics

  # Nullable LLM usage reporting NLM-02
  Scenario Outline: Nullable LLM usage reporting NLM-02 each nullable metric preserves available totals
    Given the pipeline call log contains one call with prompt_tokens 5, completion_tokens 7, and duration_ms 90 except <unavailable_field> is null
    And it contains another call with prompt_tokens 11, completion_tokens 13, and duration_ms 170
    When the HTML report is generated
    Then report generation succeeds
    And the pipeline totals show <total_prompt> prompt tokens, <total_completion> completion tokens, and <total_duration> milliseconds
    And the report contains both pipeline calls
    And the report warns that <unavailable_field> is unavailable

    Examples:
      | unavailable_field | total_prompt | total_completion | total_duration |
      | prompt_tokens     | 11           | 20               | 260            |
      | completion_tokens | 16           | 13               | 260            |
      | duration_ms       | 16           | 20               | 170            |

  # Nullable LLM usage reporting NLM-03
  Scenario: Nullable LLM usage reporting NLM-03 scenario call metrics do not hide scenarios
    Given a reportable scenario has a synthetic call with null prompt_tokens, completion_tokens, and duration_ms
    And another reportable scenario has a call with prompt_tokens 19, completion_tokens 23, and duration_ms 290
    When the HTML report is generated
    Then report generation succeeds
    And the report contains both scenarios
    And the unavailable call displays prompt_tokens, completion_tokens, and duration_ms as unavailable
    And the numeric scenario call displays 19 prompt tokens, 23 completion tokens, and 290 milliseconds
    And the report warns that the call has unavailable usage metrics

  # Nullable LLM usage reporting NLM-04
  Scenario Outline: Nullable LLM usage reporting NLM-04 invalid metrics have a reporting diagnostic
    Given the pipeline call log contains a call whose <metric_field> value is <invalid_value>
    When the HTML report is generated
    Then report generation fails with an invalid usage metric diagnostic
    And the diagnostic identifies <metric_field>, <invalid_value>, and the call
    And the diagnostic does not expose an arithmetic exception

    Examples:
      | metric_field      | invalid_value  |
      | prompt_tokens     | "many"         |
      | completion_tokens | {"count": 4}   |
      | duration_ms       | [300]          |

  # Nullable LLM usage reporting NLM-05
  Scenario: Nullable LLM usage reporting NLM-05 complete metrics need no warning
    Given the pipeline call log contains one call with prompt_tokens 31, completion_tokens 17, and duration_ms 410
    When the HTML report is generated
    Then report generation succeeds
    And the pipeline totals show 31 prompt tokens, 17 completion tokens, and 410 milliseconds
    And the report does not warn that usage metrics are unavailable

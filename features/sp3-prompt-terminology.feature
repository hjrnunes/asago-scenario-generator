# sp3-prompt-terminology
Feature: SP3 Stage 5 system prompt opener terminology
  The SP3 Stage 5 system prompt opens with task-oriented security-analyst
  framing. It does not use STPA-Sec jargon. All required output schemas and
  behavior constraints remain unchanged.

  Background:
    Given the SP3 Stage 5 prompt templates are renderable
    And a minimal SP3 scenario fixture

  # SP3-072o-01
  Scenario Outline: <id> <stage> system prompt opener uses task-oriented security-analyst framing
    When the <stage> system prompt is rendered
    Then the <stage> system prompt does not contain the string "STPA-Sec"
    And the <stage> system prompt contains the phrase "security analyst"
    And the <stage> system prompt contains the task framing phrase "<task_framing>"

    Examples:
      | id           | stage    | task_framing                      |
      | SP3-072o-01  | Stage 5  | dual-BDI                          |

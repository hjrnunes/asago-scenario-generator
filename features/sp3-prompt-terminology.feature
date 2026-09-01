# sp3-prompt-terminology
Feature: SP3 Stage 5 and Stage 6 system prompt opener terminology
  The system prompts for SP3 Stage 5, Stage 6a, Stage 6b, and Stage 6c
  open with task-oriented security-analyst framing. They do not use
  STPA-Sec jargon. All required output schemas and behavior constraints
  remain unchanged.

  Background:
    Given the SP3 Stage 5, Stage 6a, Stage 6b, and Stage 6c prompt templates are renderable
    And a minimal SP3 scenario fixture

  # SP3-072o-01 through SP3-072o-04
  Scenario Outline: <id> <stage> system prompt opener uses task-oriented security-analyst framing
    When the <stage> system prompt is rendered
    Then the <stage> system prompt does not contain the string "STPA-Sec"
    And the <stage> system prompt contains the phrase "security analyst"
    And the <stage> system prompt contains the task framing phrase "<task_framing>"

    Examples:
      | id           | stage    | task_framing                      |
      | SP3-072o-01  | Stage 5  | dual-BDI                          |
      | SP3-072o-02  | Stage 6a | 7-step causal narrative           |
      | SP3-072o-03  | Stage 6b | attack tree                       |
      | SP3-072o-04  | Stage 6c | Gherkin behavior specification    |

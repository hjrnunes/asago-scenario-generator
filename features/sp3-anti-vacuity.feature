# sp3-anti-vacuity
Feature: SP3 prompt revision anti-vacuity checks
  Deliberately removing a required element from the prompt template or
  inserting forbidden jargon must cause the QA suite to fail. This proves
  the checks are not vacuously passing.

  Background:
    Given the SP3 Stage 5 prompt templates are renderable
    And a minimal SP3 scenario fixture

  # SP3-072o-42
  Scenario: SP3-072o-42 inserting STPA-Sec jargon into a copy of the Stage 5 system prompt causes QA failure
    Given a copy of the Stage 5 system prompt with STPA-Sec jargon inserted
    When the copied system prompt is checked against the terminology requirement
    Then the check fails because STPA-Sec jargon is present

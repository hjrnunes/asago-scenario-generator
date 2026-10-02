Feature: Taxonomy preparation CLI commands
  Taxonomy remains an input to the STPA product run. Its offline preparation
  commands validate inputs without exposing a separate scenario generator.

  Background:
    Given a disposable CLI fixtures workspace

  Scenario Outline: Catalog qualification rejects invalid input
    Given the validate-catalog-qualification artifact is <artifact_case>
    When the validate-catalog-qualification command is invoked with contract "<contract>"
    Then the command prints an error to stderr
    And the process exits with code 1

    Examples:
      | artifact_case                      | contract |
      | a missing file path                | matrix   |
      | not a valid qualification contract | matrix   |
      | a valid qualification contract     | invalid  |

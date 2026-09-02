Feature: Taxonomy preparation CLI commands
  Taxonomy remains an input to the STPA product run. Its offline preparation
  commands validate inputs without exposing a separate scenario generator.

  Background:
    Given a disposable CLI fixtures workspace

  Scenario Outline: Projection preflight rejects a missing required input
    Given the projection-preflight command input <input_label> resolves to a missing path
    And all other projection-preflight inputs are valid
    When the projection-preflight command is invoked
    Then the command prints an error to stderr
    And the process exits with code 1

    Examples:
      | input_label             |
      | risk-extraction file    |
      | SSSOM file              |
      | capability profile file |

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

  Scenario: Projection preflight reports requirements without generating scenarios
    Given valid risk-extraction, SSSOM, and capability profile fixtures
    When the projection-preflight command runs against the fixtures
    Then the command prints a JSON requirements report on stdout
    And the process exits with code 0

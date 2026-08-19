Feature: Acceptance pipeline preservation
  Separating unit tests from generated acceptance artifacts does not weaken
  acceptance generation or execution. The acceptance pipeline remains the
  exclusive workflow that reconstructs and executes generated entrypoints.

  Background:
    Given a clean source checkout has no generated acceptance artifacts
    And the pinned Acceptance Pipeline Specification tools are available
    And no model endpoint is configured

  # Acceptance pipeline preservation APP-01 reconstructs and executes the acceptance suite
  Scenario: Acceptance pipeline preservation APP-01 reconstructs and executes the acceptance suite
    When the documented acceptance command is invoked
    Then every source feature has mapped IR, DRY report, generated entrypoint, and metadata
    And the generated acceptance suite executes
    And the command exits successfully

  # Acceptance pipeline preservation APP-02 validates generated entrypoint coverage
  Scenario: Acceptance pipeline preservation APP-02 validates generated entrypoint coverage
    When generated acceptance entrypoints are validated
    Then the generated IR-to-entrypoint mapping is one-to-one
    And each entrypoint target exists
    And each entrypoint target is inside the configured generated IR directory

  # Acceptance pipeline preservation APP-03 separates CI unit and acceptance prerequisites
  Scenario: Acceptance pipeline preservation APP-03 separates CI unit and acceptance prerequisites
    When CI runs from a clean source checkout
    Then the unit job runs without generating acceptance artifacts
    And the unit job does not require Acceptance Pipeline Specification tools
    And the acceptance job generates acceptance artifacts before executing them

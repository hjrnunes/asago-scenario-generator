Feature: Taxonomy CLI commands
  The taxonomy/risk CLI commands validate their input paths before doing
  work and reject missing or invalid inputs on stderr with exit code 1.
  Successful report, eval, profile, and projection-preflight runs against
  fixture inputs announce their artifact or report on stdout and exit
  with code 0. The generate command's outcome policy is pinned by its own
  feature, and the stpa-report and validate-stpa-projection commands stay
  consistent with the STPA QA suite.

  Background:
    Given a disposable CLI fixtures workspace

  # Taxonomy CLI commands 01 rejects a missing required generate input file on stderr with exit code 1
  Scenario Outline: Taxonomy CLI commands 01 rejects a missing required generate input file on stderr with exit code 1
    Given the generate command input <input_label> resolves to a missing path
    And all other generate inputs are valid
    When the generate command is invoked
    Then the command prints an error to stderr
    And the process exits with code 1

    Examples:
      | input_label          |
      | risk-extraction file |
      | SSSOM file           |

  # Taxonomy CLI commands 02 rejects a missing @file use-case reference on stderr with exit code 1
  Scenario: Taxonomy CLI commands 02 rejects a missing @file use-case reference on stderr with exit code 1
    Given the generate command use case is an @file reference to a file that does not exist
    And all other generate inputs are valid
    When the generate command is invoked
    Then the command prints an error to stderr
    And the process exits with code 1

  # Taxonomy CLI commands 03 rejects a missing required projection-preflight input file on stderr with exit code 1
  Scenario Outline: Taxonomy CLI commands 03 rejects a missing required projection-preflight input file on stderr with exit code 1
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

  # Taxonomy CLI commands 04 rejects a missing or invalid validate-catalog-qualification input on stderr with exit code 1
  Scenario Outline: Taxonomy CLI commands 04 rejects a missing or invalid validate-catalog-qualification input on stderr with exit code 1
    Given the validate-catalog-qualification artifact is <artifact_case>
    When the validate-catalog-qualification command is invoked with contract "<contract>"
    Then the command prints an error to stderr
    And the process exits with code 1

    Examples:
      | artifact_case                      | contract |
      | a missing file path                | matrix   |
      | not a valid qualification contract | matrix   |
      | a valid qualification contract     | invalid  |

  # Taxonomy CLI commands 05 rejects a missing run directory on stderr with exit code 1
  Scenario Outline: Taxonomy CLI commands 05 rejects a missing run directory on stderr with exit code 1
    Given the <command> command run directory does not exist
    When the <command> command is invoked
    Then the command prints an error to stderr
    And the process exits with code 1

    Examples:
      | command |
      | report  |
      | eval    |

  # Taxonomy CLI commands 06 rejects an output destination inside the immutable run directory
  Scenario: Taxonomy CLI commands 06 rejects an output destination inside the immutable run directory
    Given an offline completed taxonomy-and-risk run fixture
    And the report command output destination is inside the run directory
    When the report command is run
    Then the command prints an error to stderr
    And the process exits with code 1

  # Taxonomy CLI commands 07 writes the report artifact from a completed run fixture
  Scenario: Taxonomy CLI commands 07 writes the report artifact from a completed run fixture
    Given an offline completed taxonomy-and-risk run fixture
    And the report command output destination is outside the run directory
    When the report command is run
    Then the command prints the written report path
    And a report HTML file exists at that path
    And the process exits with code 0

  # Taxonomy CLI commands 08 prints the evaluation scorecard from a completed run fixture
  Scenario Outline: Taxonomy CLI commands 08 prints the evaluation scorecard from a completed run fixture
    Given an offline completed taxonomy-and-risk run fixture
    When the eval command runs with output format "<format>"
    Then the command prints a scorecard in <format_label> on stdout
    And the process exits with code 0

    Examples:
      | format | format_label |
      | yaml   | YAML         |
      | json   | JSON         |

  # Taxonomy CLI commands 09 writes the capability profile from a use case
  Scenario: Taxonomy CLI commands 09 writes the capability profile from a use case
    Given a deterministic local OpenAI-compatible fixture is available
    When the profile command writes its capability profile to a path in the CLI fixtures workspace
    Then the command prints the written profile path
    And a capability profile YAML file exists at that path
    And the process exits with code 0

  # Taxonomy CLI commands 10 prints the projection requirements report from fixture inputs
  Scenario: Taxonomy CLI commands 10 prints the projection requirements report from fixture inputs
    Given valid risk-extraction, SSSOM, and capability profile fixtures
    When the projection-preflight command runs against the fixtures
    Then the command prints a JSON requirements report on stdout
    And the process exits with code 0

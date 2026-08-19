Feature: Taxonomy CLI run outcome
  The generate command reports the authoritative manifest outcome and
  candidate disposition counts. Its default process status distinguishes a
  clean completed run from a degraded or empty run.

  Background:
    Given the taxonomy pipeline reaches a final run manifest
    And the generate command uses its default outcome policy

  # Taxonomy CLI run outcome 01 reports counts and applies the default exit policy
  Scenario Outline: Taxonomy CLI run outcome 01 reports counts and applies the default exit policy
    Given the final manifest status is "<status>"
    And candidate counts are admitted <admitted>, quarantined <quarantined>, and failed <failed>
    When the generate command prints its final summary
    Then the summary reports status "<status>" and counts admitted <admitted>, quarantined <quarantined>, and failed <failed>
    And the process exits with code <exit_code>

    Examples:
      | status                | admitted | quarantined | failed | exit_code |
      | completed             | 2        | 0           | 0      | 0         |
      | completed_with_errors | 1        | 1           | 0      | 1         |
      | completed_with_errors | 1        | 0           | 1      | 1         |
      | completed             | 0        | 0           | 0      | 1         |

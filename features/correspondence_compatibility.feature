Feature: Correspondence compatibility
  Adding correspondence proposal and reconciliation does not change
  default taxonomy/risk or STPA scenario generation. Existing commands
  keep their artifacts, prompts, and generation counts.

  Background:
    Given correspondence proposal and reconciliation are present
    And default generation commands are invoked without correspondence flags

  # Correspondence compatibility 01 leaves default workflow outputs unchanged
  Scenario Outline: Correspondence compatibility 01 leaves default workflow outputs unchanged
    Given a deterministic offline "<workflow>" fixture
    When the default "<command>" runs
    Then published scenario artifacts match the fixture
    And generation counts are unchanged
    And scenario prompts are unchanged
    And no correspondence artifact is added to the run outputs
    And existing STPA and taxonomy artifacts are not mutated

    Examples:
      | workflow      | command  |
      | taxonomy/risk | generate |
      | STPA          | stpa-run |

Feature: System resource map compatibility
  Adding the SystemResourceMap does not change default taxonomy/risk or
  STPA scenario generation. Existing commands keep their artifacts,
  prompts, and generation counts.

  Background:
    Given the system resource map is present
    And default generation commands are invoked without resource-map flags

  # System resource map compatibility 01 leaves default workflow outputs unchanged
  Scenario Outline: System resource map compatibility 01 leaves default workflow outputs unchanged
    Given a deterministic offline "<workflow>" fixture
    When the default "<command>" runs
    Then published scenario artifacts match the fixture
    And generation counts are unchanged
    And scenario prompts are unchanged
    And no resource-map artifact is added to the run outputs
    And existing STPA control-structure artifacts are not replaced

    Examples:
      | workflow      | command  |
      | taxonomy/risk | generate |
      | STPA          | stpa-run |

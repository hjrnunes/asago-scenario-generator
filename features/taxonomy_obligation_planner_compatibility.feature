Feature: Taxonomy obligation planner compatibility
  Adding the obligation planner does not change default taxonomy/risk or
  STPA scenario generation. Existing commands keep their artifacts,
  prompts, and generation counts.

  Background:
    Given the obligation planner is present
    And default generation commands are invoked without obligation-planner flags

  # Taxonomy obligation planner compatibility 01 leaves default workflow outputs unchanged
  Scenario Outline: Taxonomy obligation planner compatibility 01 leaves default workflow outputs unchanged
    Given a deterministic offline "<workflow>" fixture
    When the default "<command>" runs
    Then published scenario artifacts match the fixture
    And generation counts are unchanged
    And scenario prompts are unchanged
    And no obligation-plan artifact is added to the run outputs

    Examples:
      | workflow      | command  |
      | taxonomy/risk | generate |
      | STPA          | stpa-run |

# mutation-stamp: sha256=cbb1c6a365b9b8ffb44ffae70c11aefdfc1615fc9f391d1b28360f3a76cbdcdc
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-28T07:32:51.031881Z","feature_name":"Correspondence compatibility","feature_path":"features/correspondence_compatibility.feature","background_hash":"a5af44de0f1fb3bf4698943aeb60b55a6e20f94fac9ce7ec046e7b352bc52d3d","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Correspondence compatibility 01 leaves default workflow outputs unchanged","scenario_hash":"bcfa0a4c7847d153baecd9c83dd18ff4370f20ef54235d586b29548fafbbad64","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-28T07:01:42.571582Z"}]}
# acceptance-mutation-manifest-end

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

# mutation-stamp: sha256=878b29434a1115ff6ecc119e5f39a8149defc6f6e5e6776aae889f70faae8a70
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-27T17:14:30.594825Z","feature_name":"Taxonomy obligation planner compatibility","feature_path":"features/taxonomy_obligation_planner_compatibility.feature","background_hash":"8e0e26e2d4085a4dfe80eac74d72ee97d7bfad2c8ceb9aaa646ac24595eea8ab","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Taxonomy obligation planner compatibility 01 leaves default workflow outputs unchanged","scenario_hash":"568ef51a890b8a783f3a917df49ee0b837354259bf99fcac603c52be2252a48b","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:30.594825Z"}]}
# acceptance-mutation-manifest-end

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

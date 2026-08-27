# mutation-stamp: sha256=e67b915c5c35bde4c639bf9a2331fbdd8c1faaa97fa3bea91a4747fd1ae7852c
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-27T22:31:25.234246Z","feature_name":"System resource map compatibility","feature_path":"features/system_resource_map_compatibility.feature","background_hash":"3f880bd9aa430dbcf0d9cf449c55e33f7573e7e1aaeadeda250b5f1be49c7503","implementation_hash":"unknown","scenarios":[{"index":0,"name":"System resource map compatibility 01 leaves default workflow outputs unchanged","scenario_hash":"1549b3679d7694a772c8558df4ccdaabb9a2593b979cbaba1827a10fabc000ca","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-27T21:26:34.904341Z"}]}
# acceptance-mutation-manifest-end

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

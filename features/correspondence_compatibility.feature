# mutation-stamp: sha256=59a342ffb194d778ef5870376f664f28e60be919f12fe1d8f87a87b9be576cbd
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-29T13:33:59.783226Z","feature_name":"Correspondence workflow compatibility","feature_path":"features/correspondence_compatibility.feature","background_hash":"af0fce2306643471bba2af5814bbfeb25ee235c8cc9f739d3d9483206b49d944","implementation_hash":"sha256:4e582509516882fedb17d3cc5ff2d2da9d9265f08d8920217f07ba17287cf33c","scenarios":[{"index":0,"name":"Phase 2 sidecars do not alter existing workflow behavior","scenario_hash":"913831dec94b6441a3eeab748d4aa852d8db54f674dba4b0362b19281e332292","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-29T13:33:59.783226Z"}]}
# acceptance-mutation-manifest-end

Feature: Correspondence workflow compatibility
  Hybrid correspondence remains observational and offline.

  Background:
    Given a valid typed correspondence authority is available

  Scenario Outline: Phase 2 sidecars do not alter existing workflow behavior
    Given a deterministic correspondence compatibility fixture includes valid Phase 2 sidecars for "<workflow>"
    When correspondence "<command>" runs before and after Phase 2 sidecars
    Then the correspondence "<command>" exit status is unchanged
    And the correspondence "<command>" scenario artifacts are identical after normalization of known volatile fields
    And the correspondence "<command>" generation counts are identical
    And the correspondence "<command>" prompt contracts are identical
    And no correspondence Phase 2 artifact is written into either workflow output

    Examples:
      | workflow      | command  |
      | taxonomy/risk | generate |
      | STPA          | stpa-run |

# mutation-stamp: sha256=d5727e3278645922a699ca0b33e54f6c3c6041db9ea897e2539ee3742f5113ef
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-29T13:35:12.469228Z","feature_name":"System resource map compatibility","feature_path":"features/system_resource_map_compatibility.feature","background_hash":"74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b","implementation_hash":"sha256:2e3365be85e34e06d8eca88457929efdbc56596efc73214455f9cda0972af8a4","scenarios":[{"index":0,"name":"existing workflow remains byte-stable with the sidecar present","scenario_hash":"820e922c6c36a23ea11f92cbae3d6438951df0eac048743e832c0fd5dfdebd17","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-29T13:35:12.469228Z"}]}
# acceptance-mutation-manifest-end

Feature: System resource map compatibility
  The resource-map sidecar is an independent Phase 2 surface. Existing
  generation workflows retain their default commands and do not consume the
  sidecar implicitly.

  Scenario Outline: existing workflow remains byte-stable with the sidecar present
    Given a deterministic resource-map compatibility fixture includes valid Phase 2 sidecars for "<workflow>"
    When resource-map "<command>" runs before and after Phase 2 sidecars
    Then the resource-map "<command>" exit status is unchanged
    And the resource-map "<command>" scenario artifacts are identical after normalization of known volatile fields
    And the resource-map "<command>" generation counts are identical
    And the resource-map "<command>" prompt contracts are identical
    And no resource-map Phase 2 artifact is written into either workflow output

    Examples:
      | workflow      | command  |
      | taxonomy/risk | generate |
      | STPA          | stpa-run |

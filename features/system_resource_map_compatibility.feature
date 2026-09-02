Feature: System resource map compatibility
  The resource-map sidecar remains independent of standalone diagnostic STPA.

  Scenario Outline: existing workflow remains byte-stable with the sidecar present
    Given a deterministic resource-map compatibility fixture includes valid Phase 2 sidecars for "<workflow>"
    When resource-map "<command>" runs before and after Phase 2 sidecars
    Then the resource-map "<command>" exit status is unchanged
    And the resource-map "<command>" scenario artifacts are identical after normalization of known volatile fields
    And the resource-map "<command>" generation counts are identical
    And the resource-map "<command>" prompt contracts are identical
    And no resource-map Phase 2 artifact is written into either workflow output

    Examples:
      | workflow | command  |
      | STPA     | stpa-run |

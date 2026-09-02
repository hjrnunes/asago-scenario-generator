Feature: Correspondence workflow compatibility
  Hybrid correspondence remains observational and offline for standalone
  diagnostic STPA. The product run performs its own final Phase 2 step.

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
      | workflow | command  |
      | STPA     | stpa-run |

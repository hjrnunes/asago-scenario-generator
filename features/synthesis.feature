# mutation-stamp: sha256=4e937ecff17d37b930c476f67e2535f60e2a31e80c8ff8f36d39f9c71fcf5679
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-09-01T16:26:23.850056Z","feature_name":"Obligation-aware synthesis run","feature_path":"features/synthesis.feature","background_hash":"e590a28891bd9f46f251d41aef6f2af43850821eca84fabccab67719e320814d","implementation_hash":"sha256:77977a03754a0be10d7dac944c20d9516a1c994428118793e3a8ab8781190ea1","scenarios":[{"index":4,"name":"STPA retains each typed route outcome as analysis evidence","scenario_hash":"d4eefda6d43c9565abab12528dce639f38ac9eab5f5b88473a49411e21a0e2a6","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:26:23.850056Z"}]}
# acceptance-mutation-manifest-end

Feature: Obligation-aware synthesis run
  A synthesis run joins the typed Phase 1 obligation ledger to ordinary STPA
  without changing the existing generate or stpa-run workflows.

  Background:
    Given a deterministic synthesis fixture is available

  Scenario: An applied revision rechecks the complete applicable universe once
    Given a deterministic synthesis revision is applied
    When synthesis-run executes
    Then Phase 1 planning runs before baseline STPA
    And the synthesis recheck covers every applicable obligation exactly once
    And the synthesis writes the five normative sidecars atomically
    And the synthesis report identifies provisional accounting
    And applicable and non-applicable obligations are accounted separately

  Scenario: A rejected revision retains upstream gaps without a second pass
    Given a deterministic synthesis revision is rejected
    When synthesis-run executes
    Then Phase 1 planning runs before baseline STPA
    And the synthesis performs no recheck after a rejected revision
    And the synthesis writes the five normative sidecars atomically

  Scenario: A clean run does not perform a revision or second pass
    Given a deterministic synthesis revision is not required
    When synthesis-run executes
    Then the clean synthesis has no revision or recheck
    And applicable and non-applicable obligations are accounted separately

  Scenario: Scenario failure retains structural accounting
    Given a deterministic synthesis revision is not required
    And scenario generation fails after ICA
    Then applicable and non-applicable obligations are accounted separately

  Scenario Outline: STPA retains each typed route outcome as analysis evidence
    Given a deterministic synthesis route disposition "<disposition>"
    When synthesis-run executes
    Then the synthesis returns a typed "<disposition>" route
    And the route evidence remains separate from taxonomy coverage

    Examples:
      | disposition             |
      | targeted                |
      | proposed_not_applicable |
      | upstream_gap            |
      | unresolved              |

  Scenario: An invalid revision retains the baseline and its upstream gap
    Given a deterministic synthesis revision is invalid
    When synthesis-run executes
    Then the synthesis retains the baseline after the revision failure
    And the synthesis performs no recheck after the invalid revision
    And the invalid revision remains a typed technical diagnostic

  Scenario: A local provider failure remains visible without erasing accounting
    Given a deterministic synthesis provider fails during consideration
    When synthesis-run executes
    Then the provider failure is retained as local unresolved evidence
    And the synthesis still writes accounting and manifest sidecars

  Scenario: Existing generation commands remain available
    Given a deterministic synthesis revision is not required
    Then existing generation commands remain compatible

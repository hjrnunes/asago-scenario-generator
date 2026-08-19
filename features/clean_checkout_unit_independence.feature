Feature: Clean-checkout unit independence
  The unit suite is deterministic and offline without ignored acceptance IR,
  DRY reports, generated entrypoints, metadata, or an APS tool checkout.
  Unit tests that inspect acceptance artifacts use test-owned fixtures rather
  than repository generated output.

  Background:
    Given a clean source checkout has no generated acceptance artifacts
    And no Acceptance Pipeline Specification checkout is available
    And no model endpoint is configured

  # Clean-checkout unit independence CUI-01 runs the complete unit suite without generated artifacts
  Scenario: Clean-checkout unit independence CUI-01 runs the complete unit suite without generated artifacts
    When the documented unit test command is invoked
    Then the unit suite exits successfully
    And the unit suite does not create repository generated acceptance artifacts

  # Clean-checkout unit independence CUI-02 runs acceptance infrastructure unit tests in either order
  Scenario Outline: Clean-checkout unit independence CUI-02 runs acceptance infrastructure unit tests in either order
    When the acceptance snapshot and harness unit tests run in "<order>" order
    Then both unit test selections exit successfully
    And every acceptance IR or entrypoint they inspect is a test-owned fixture
    And repository generated acceptance artifacts remain absent

    Examples:
      | order                 |
      | snapshot then harness |
      | harness then snapshot |

  # Clean-checkout unit independence CUI-03 keeps generated acceptance output disposable
  Scenario: Clean-checkout unit independence CUI-03 keeps generated acceptance output disposable
    When repository tracking and ignore rules are inspected
    Then acceptance IR, DRY reports, generated entrypoints, and metadata are ignored
    And no generated acceptance artifact is tracked

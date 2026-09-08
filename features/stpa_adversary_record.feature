Feature: Phase 3 adversary record on every candidate
  Every scenario names who attempts the unsafe behavior and what they gain.
  A scenario nobody gains from is a functional test: persisted for the
  owner's information but excluded from the execution bundle.

  Scenario: Stage 5 rejects a response without an adversary record
    Given a corrected Stage 5 adversary context is available
    When the provider response omits the adversary record
    And corrected Stage 5 materializes the adversary record
    Then Stage 5 fails closed with an adversary error

  Scenario: an analytical stimulus persists a null reach
    Given a corrected Stage 5 adversary context is available
    When the provider response selects an analytical route for an unsupported upload
    And corrected Stage 5 materializes the adversary record
    Then the materialized adversary carries kind "external_attacker" with no delivery

  Scenario: the Stage 5 prompt explains the adversary record
    Given a corrected Stage 5 adversary context is available
    Then the Stage 5 prompt explains the adversary record

  Scenario: a kind none candidate becomes a persisted functional test outside the bundle
    Given a run whose provider response declares adversary kind "none" with gain "The requested service completes as designed."
    When the product scenario run publishes its artifacts
    Then the candidate outcome is "functional_test"
    And the functional scenario is persisted under scenarios/
    And the persisted functional test carries the compiler-owned gain
    And the execution bundle contains no entries

  Scenario: a third-party adversary without a content surface is rejected
    Given a run whose provider response declares adversary kind "third_party_via_content" with a "retrieved_content" stimulus
    When the product scenario run publishes its artifacts
    Then the candidate outcome is "generation_failed"
    And the run records the "no_content_surface" rejection

  Scenario: a gain that restates the constraint is rejected
    Given a run whose provider response declares a gain restating "validate before action"
    When the product scenario run publishes its artifacts
    Then the candidate outcome is "generation_failed"
    And the run records the "adversary gain restates constraint" rejection

  Scenario: a valid malicious-customer record is carried onto the published scenario
    Given a run whose provider response declares adversary kind "malicious_customer" with a "user_message" stimulus
    When the product scenario run publishes its artifacts
    Then the candidate outcome is "published"
    And the published scenario carries adversary kind "malicious_customer" via "user_message"

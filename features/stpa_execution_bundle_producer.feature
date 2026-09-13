# STPA-BUNDLE-01, STPA-BUNDLE-02, STPA-BUNDLE-03, STPA-BUNDLE-04
Feature: STPA execution projection v2 and bundle producer
  The producer prepares one immutable semantic projection before Stage 6,
  rejects incomplete intent without calls or writes, and publishes a
  canonical scenario/projection pair through an index-last bundle.

  Background:
    Given the v2 execution projection and bundle seams are available

  Scenario: Executable publication does not require model-authored presentation
    When the default scenario pipeline runs with a valid Stage 5 response
    Then its execution bundle is valid without presentation model calls
    And its scenario summary describes a hypothesis rather than an execution result
    And deterministic summaries pass validation without model-authored presentation conventions

  # STPA-BUNDLE-01
  Scenario: STPA-BUNDLE-01 typed placeholders derive binding state
    Given a validated placeholder INCORRECT action_value projection
    When the producer prepares the execution projection
    Then the projection reports semantic_binding_required true

  # STPA-BUNDLE-02
  Scenario: STPA-BUNDLE-02 literal single-controller intent remains neutral
    Given a validated literal INCORRECT action_value projection
    When the producer prepares the execution projection
    Then the projection reports semantic_binding_required false
    And the literal projection has no multi-agent, state-observation, clock, or persistent-state requirement

  # STPA-BUNDLE-03
  Scenario: STPA-BUNDLE-03 incomplete intent is gated before Stage 6
    Given an invalid projection with no unsafe outcome condition
    When the producer prepares the execution projection
    Then projection preparation is rejected before Stage 6
    And zero Stage 6 calls are made
    And zero scenario or projection writes are made

  # STPA-BUNDLE-04
  Scenario: STPA-BUNDLE-04 publication is canonical and tamper evident
    Given a validated literal INCORRECT action_value projection
    When the producer prepares the execution projection
    And the validated projection is published as a bundle
    Then the published bundle verifies successfully
    When the projection bytes are tampered
    Then bundle verification rejects the tampering

  # STPA-BUNDLE-05 through STPA-BUNDLE-12
  Scenario Outline: STPA-BUNDLE-05 every semantic condition family round trips
    Given a committed valid <condition> projection fixture
    When standalone projection validation parses the fixture
    Then the projection fixture is valid

    Examples:
      | condition |
      | ordering  |
      | delay     |
      | duration  |
      | window    |
      | absence   |

  Scenario Outline: STPA-BUNDLE-06 invalid semantic values fail closed
    Given a committed invalid <fixture> projection fixture
    When standalone projection validation parses the fixture
    Then projection validation reports <violation>

    Examples:
      | fixture                 | violation                       |
      | forged-reference        | condition_reference_mismatch    |
      | negative-time           | condition_value_invalid         |
      | reversed-window         | condition_value_invalid         |
      | binding-state-mismatch  | semantic_binding_state_mismatch|
      | runtime-observation     | runtime_observation_forbidden  |
      | unknown-field           | unexpected_field               |

  Scenario: STPA-BUNDLE-07 stable run identity and canonical bytes
    Given a validated literal INCORRECT action_value projection
    When the producer prepares the execution projection twice
    Then both projections carry the explicit run identity
    And the prepared projection is canonical JSON

  Scenario: STPA-BUNDLE-08 source pins survive preparation
    Given a validated placeholder INCORRECT action_value projection
    When the producer prepares the execution projection
    Then the projection carries all four source pins

  Scenario: STPA-BUNDLE-09 an interrupted publication is not a bundle
    Given a validated literal INCORRECT action_value projection
    When the producer prepares the execution projection
    When the producer publishes the pair before replacing the bundle index
    Then the interrupted directory has no valid publication marker

  Scenario: STPA-BUNDLE-10 pair identity tampering fails closed
    Given a validated literal INCORRECT action_value projection
    When the producer prepares the execution projection
    And the validated projection is published as a bundle
    When the scenario identity is tampered
    Then bundle verification rejects the pair tampering

  Scenario: STPA-BUNDLE-11 the committed contract kit is deterministic
    Given the committed STPA execution contract kit
    When standard JSON tooling parses every contract document
    Then valid projection fixtures pass standalone validation
    And invalid projection fixtures report their expected violations
    And the minimal bundle fixture verifies successfully

  Scenario: STPA-BUNDLE-12 projection presentation cannot become runtime data
    Given a committed invalid runtime-observation projection fixture
    When standalone projection validation parses the fixture
    Then projection validation reports runtime_observation_forbidden

  # STPA-BUNDLE-13
  Scenario: STPA-BUNDLE-13 structured omission evidence prepares a v3 projection
    Given a structured omission scenario spec with an evidence basis
    When the producer prepares the structured v3 execution projection
    Then the v3 projection carries the omission carrier and its digest
    And the structured outcome proposition is the short trigger-only text
    And the v3 stimulus requirement carries the exact prepared user text

  # STPA-BUNDLE-14
  Scenario: STPA-BUNDLE-14 legacy preparation ignores a riding basis
    Given a structured omission scenario spec with an evidence basis
    When the producer prepares the execution projection with structured omission disabled
    Then the projection remains the v2 schema
    And the v2 canonical bytes equal the preparation without a basis

  # STPA-BUNDLE-15
  Scenario Outline: STPA-BUNDLE-15 unrepresentable omission evidence holds with typed reasons
    Given an authored tool_absent draft with <case> evidence
    When the authoring seam builds the omission evidence basis
    Then the basis holds as <reason>
    And the original evidence is retained unchanged

    Examples:
      | case                         | reason                           |
      | over-limit quote             | trigger_evidence_unrepresentable |
      | unsubstantiated prompt quote | delivery_evidence_mismatch       |
      | turn beyond the conversation | delivery_evidence_unresolved     |
      | observation without snapshot | delivery_evidence_unresolved     |

  # STPA-BUNDLE-16
  Scenario Outline: STPA-BUNDLE-16 structured preparation cross checks fail closed
    Given a structured omission scenario spec with a <case> drift
    When the producer prepares the structured v3 execution projection
    Then projection preparation is rejected before Stage 6
    And the preparation error reports <prefix>

    Examples:
      | case              | prefix                        |
      | missing basis     | omission_evidence_missing     |
      | unexpected basis  | omission_evidence_unexpected  |
      | delivery mismatch | stimulus_delivery_mismatch    |
      | prepared text     | prepared_text_mismatch        |
      | snapshot digest   | snapshot_digest_mismatch      |
      | invalid carrier   | omission_evidence_invalid     |

  # STPA-BUNDLE-17
  Scenario Outline: STPA-BUNDLE-17 homogeneous sets publish their own bundle version
    Given a <delivery> publication set
    When the set is published as a bundle
    Then the bundle index reports <version>
    And the published bundle verifies successfully

    Examples:
      | delivery                | version                    |
      | structured omission     | stpa-execution-bundle-v2   |
      | legacy proposition-only | stpa-execution-bundle-v1   |

  # STPA-BUNDLE-18
  Scenario: STPA-BUNDLE-18 mixed version sets are rejected before the index
    Given a mixed v2 and v3 publication set
    When the set is published as a bundle
    Then bundle publication reports one schema version error
    And the interrupted directory has no valid publication marker

  # STPA-BUNDLE-19
  Scenario: STPA-BUNDLE-19 the committed bundle-v2 kit verifies and fails closed
    Given the committed STPA execution contract kit
    When the bundle-v2 kit fixtures are verified
    Then the bundle-v2 valid fixture verifies successfully
    And the bundle-v2 invalid fixtures report their expected violations

# mutation-stamp: sha256=7556e8eb337d47f1bee35a73c7acb0dbacb4ec17f3a67ed18f30e3e222afec4d
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-31T08:28:14.298704Z","feature_name":"Offline bounded STPA obligation challenge ledger","feature_path":"features/stpa_challenge_ledger.feature","background_hash":"2b49d2db354fc7b168d315e88d438245abaff03125aef870a5ecaaff5f57d10f","implementation_hash":"sha256:f4db3252fea04f272bedc083a612e53ef2a010f358b0946ad0a51745a10ebe83","scenarios":[{"index":0,"name":"explicit budget selects or retains one approved pair","scenario_hash":"9371fdb959a923eec6c70cd35b1116d5be239a8b6ab42062b2be4586865663dd","mutation_count":16,"result":{"Total":16,"Killed":16,"Survived":0,"Errors":0},"tested_at":"2026-08-31T08:28:14.298704Z"},{"index":1,"name":"unknown exact identities fail before selection","scenario_hash":"29469ee377005a367dd2cb5acabcd9138d1b26a241a45b366f799d25ab967c04","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-31T08:28:14.298704Z"},{"index":2,"name":"canonical challenge ledger persists without repair","scenario_hash":"4815dbc6744393514a487c453843cd1ac29e91251b26172b7a809435bc5d3a97","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-31T08:28:14.298704Z"},{"index":3,"name":"challenge selection leaves Phase 2 historical","scenario_hash":"2e2a8abebec23888e83cb17be150fa6489513730e2aa623c3a50ee5ff4cea709","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-31T08:28:14.298704Z"}]}
# acceptance-mutation-manifest-end

Feature: Offline bounded STPA obligation challenge ledger
  An explicitly approved taxonomy obligation and STPA slot can be selected for
  later reconsideration without changing Phase 2 or contacting a provider.

  Background:
    Given an intact Phase 2 assessment is available for challenge selection
    And challenge-ledger planning makes no provider calls

  Scenario Outline: explicit budget selects or retains one approved pair
    Given one explicit obligation and STPA slot pair with priority <priority>
    When the challenge ledger is built with budget <budget>
    Then the ledger retains explicit budget <expected_budget> and priority <expected_priority>
    Then the pair has selection status "<selection_status>"
    And the original STPA disposition "<original_disposition>" and evidence are preserved
    And the ledger reports <selected> selected and <not_selected> budget-excluded target

    Examples:
      | priority | budget | expected_budget | expected_priority | selection_status    | original_disposition | selected | not_selected |
      | 10       | 1      | 1               | 10                | selected            | ica                  | 1        | 0            |
      | 10       | 0      | 0               | 10                | not_selected_budget | ica                  | 0        | 1            |

  Scenario Outline: unknown exact identities fail before selection
    Given explicit challenge eligibility references an unknown "<identity_kind>"
    When challenge-ledger construction is attempted
    Then challenge-ledger construction rejects the unknown "<identity_kind>"
    And no provider or model call was attempted

    Examples:
      | identity_kind |
      | obligation    |
      | STPA slot     |

  Scenario Outline: canonical challenge ledger persists without repair
    Given one explicit obligation and STPA slot pair with priority <priority>
    When the challenge ledger is built with budget <budget>
    Then the ledger retains explicit budget <expected_budget> and priority <expected_priority>
    And the challenge ledger is published as "<artifact_name>"
    Then the persisted challenge ledger round-trips unchanged
    And changing persisted "<tampered_field>" is rejected by its semantic digest

    Examples:
      | priority | budget | expected_budget | expected_priority | artifact_name                         | tampered_field |
      | 10       | 1      | 1               | 10                | stpa-obligation-challenge-ledger.yaml | priority       |

  Scenario Outline: challenge selection leaves Phase 2 historical
    Given one explicit obligation and STPA slot pair with priority <priority>
    When the challenge ledger is built with budget <budget>
    Then the ledger retains explicit budget <expected_budget> and priority <expected_priority>
    Then the Phase 2 assessment digest and matrices remain unchanged
    And challenge selection creates <relations> correspondence relations and <scenarios> hybrid scenarios

    Examples:
      | priority | budget | expected_budget | expected_priority | relations | scenarios |
      | 10       | 1      | 1               | 10                | 0         | 0         |

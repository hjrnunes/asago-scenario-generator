# mutation-stamp: sha256=07f0cc81fb7b2871dcb908c78b918354a1fcb48a70709c765ea54ed37af9237c
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-27T17:14:24.172582Z","feature_name":"Taxonomy obligation planner","feature_path":"features/taxonomy_obligation_planner.feature","background_hash":"404ec7aa5df544172f5d7bba33f66ab007a962f33538ef45f7b38cb73129ab7b","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Taxonomy obligation planner 01 preserves distinct risk-scoped obligations for a shared pattern","scenario_hash":"f6a4c9f8634d92c2b2cb296f0af40de8c8e617176c70219d6b8580193313cd57","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:21.296728Z"},{"index":1,"name":"Taxonomy obligation planner 02 records in-scope and out-of-scope relationships explicitly","scenario_hash":"d15bbc230efe428f8627d58083305457dee55705349f6e93659808b9390c3fc1","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:21.296728Z"},{"index":2,"name":"Taxonomy obligation planner 03 assigns exactly one terminal outcome to every expected relationship","scenario_hash":"30b8cae356d1e411c85df02d18fca489bb27cd9d5e5698cc5c4a3cbf1f81680f","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:21.296728Z"},{"index":3,"name":"Taxonomy obligation planner 04 records pattern-bearing terminal dispositions","scenario_hash":"473ee14d6c0daa1fea0430d15182415925366bd17ead20031a7b766b92fb9257","mutation_count":30,"result":{"Total":30,"Killed":30,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:21.296728Z"},{"index":4,"name":"Taxonomy obligation planner 05 records a governance-only risk without inventing a pattern","scenario_hash":"587782327edf335f6ca7cf910991b9d33f52991bcd6d481b4e7ad6ed00cf8baf","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:21.296728Z"},{"index":5,"name":"Taxonomy obligation planner 06 retains qualification traces without secrets","scenario_hash":"539b1d97749a70b8e47ad3743b442bd21ee33e8231520079ca5d1b199e60acb7","mutation_count":7,"result":{"Total":7,"Killed":7,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:21.296728Z"},{"index":6,"name":"Taxonomy obligation planner 07 retains accepted and rejected candidates with reasons","scenario_hash":"4bd08c4bfce93c2582724e9034930b2d5f7f46e34505fcd17374b39ce75394e3","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:21.296728Z"},{"index":7,"name":"Taxonomy obligation planner 08 records zero network and model calls","scenario_hash":"ad30f2f4907dda4733f4b00576507749e665a7ab5e3a4524f8a24e8f62258474","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-27T17:14:21.296728Z"}]}
# acceptance-mutation-manifest-end

Feature: Taxonomy obligation planner
  A deterministic planner turns a pinned taxonomy/risk snapshot into an
  exact obligation ledger. Risk-scoped identity is preserved, every
  expected relationship has one terminal outcome, and planning makes no
  network or model calls.

  Background:
    Given a pinned taxonomy obligation snapshot is available
    And obligation planning makes no network or model calls

  # Taxonomy obligation planner 01 preserves distinct risk-scoped obligations for a shared pattern
  Scenario Outline: Taxonomy obligation planner 01 preserves distinct risk-scoped obligations for a shared pattern
    Given risk cards "<risk_a>" and "<risk_b>" both map in-scope to attack pattern "<pattern_id>"
    When the obligation plan is produced
    Then the plan ledger contains <obligation_count> obligations for pattern "<pattern_id>"
    And the obligation for risk "<risk_a>" is distinct from the obligation for risk "<risk_b>"
    And each obligation retains its own risk identity

    Examples:
      | risk_a                 | risk_b                 | pattern_id | obligation_count |
      | atlas-prompt-injection | atlas-memory-poisoning | AP-T1-01   | 2                |

  # Taxonomy obligation planner 02 records in-scope and out-of-scope relationships explicitly
  Scenario Outline: Taxonomy obligation planner 02 records in-scope and out-of-scope relationships explicitly
    Given risk "<risk_id>" has an in-scope mapping to pattern "<in_pattern>"
    And risk "<risk_id>" has an out-of-scope mapping to pattern "<out_pattern>"
    When the obligation plan is produced
    Then the plan records an in-scope decision for risk "<risk_id>" and pattern "<in_pattern>"
    And the plan records an out-of-scope decision for risk "<risk_id>" and pattern "<out_pattern>"

    Examples:
      | risk_id                | in_pattern | out_pattern |
      | atlas-prompt-injection | AP-T6-01   | AP-T11-01   |

  # Taxonomy obligation planner 03 assigns exactly one terminal outcome to every expected relationship
  Scenario Outline: Taxonomy obligation planner 03 assigns exactly one terminal outcome to every expected relationship
    Given the snapshot contains "<relationship_count>" expected risk-to-pattern relationships
    When the obligation plan is produced
    Then the plan ledger contains "<relationship_count>" obligations
    And every obligation has exactly one terminal disposition
    And no expected relationship is omitted from the ledger

    Examples:
      | relationship_count |
      | 6                  |

  # Taxonomy obligation planner 04 records pattern-bearing terminal dispositions
  Scenario Outline: Taxonomy obligation planner 04 records pattern-bearing terminal dispositions
    Given the snapshot contains a "<relationship_kind>" relationship for risk "<risk_id>" and pattern "<pattern_id>"
    When the obligation plan is produced
    Then the plan ledger contains <obligation_count> obligations for risk "<risk_id>" and pattern "<pattern_id>"
    And that obligation has terminal disposition "<disposition>"
    And that obligation has scope "<scope>"

    Examples:
      | relationship_kind              | risk_id                  | pattern_id | scope        | disposition      | obligation_count |
      | gated threat                   | atlas-prompt-injection   | AP-T11-01  | out-of-scope | gated            | 1                |
      | missing generation template    | atlas-memory-poisoning   | AP-T1-01   | in-scope     | missing-template | 1                |
      | projection infeasibility       | atlas-memory-poisoning   | AP-T1-02   | in-scope     | infeasible       | 1                |
      | unsupported requirement        | atlas-memory-poisoning   | AP-T1-03   | in-scope     | unsupported      | 1                |
      | qualified generable pattern    | atlas-prompt-injection   | AP-T6-01   | in-scope     | generated        | 1                |

  # Taxonomy obligation planner 05 records a governance-only risk without inventing a pattern
  Scenario Outline: Taxonomy obligation planner 05 records a governance-only risk without inventing a pattern
    Given risk card "<risk_id>" has no actionable attack pattern
    When the obligation plan is produced
    Then the plan ledger contains <obligation_count> obligations for risk "<risk_id>"
    And that obligation has terminal disposition "<disposition>"
    And that obligation lists no attack-pattern ID

    Examples:
      | risk_id           | disposition     | obligation_count |
      | atlas-orphan-risk | governance-only | 1                |

  # Taxonomy obligation planner 06 retains qualification traces without secrets
  Scenario Outline: Taxonomy obligation planner 06 retains qualification traces without secrets
    Given the snapshot configuration includes secret "<secret>"
    And qualification is applicable for risk "<risk_id>" and pattern "<pattern_id>"
    And qualification evaluates predicate "<predicate>" with facts "<facts>" resulting in "<result>" because "<reason>"
    When the obligation plan is produced
    Then the qualification trace for that obligation records predicate "<predicate>", facts "<facts>", result "<result>", and reason "<reason>"
    And the qualification trace does not contain "<secret>"

    Examples:
      | risk_id                | pattern_id | predicate                                      | facts                                                | result | reason                    | secret        |
      | atlas-prompt-injection | AP-T6-01   | deployment.attacker_code_execution_on_agent_host | deployment.attacker_code_execution_on_agent_host=false | false  | fact present and unequal  | sk-live-token |

  # Taxonomy obligation planner 07 retains accepted and rejected candidates with reasons
  Scenario Outline: Taxonomy obligation planner 07 retains accepted and rejected candidates with reasons
    Given candidate expansion is applicable for risk "<risk_id>" and pattern "<pattern_id>"
    And expansion produces accepted candidate "<accepted_id>"
    And expansion produces rejected candidate "<rejected_id>" with reason "<reason>"
    When the obligation plan is produced
    Then the obligation retains accepted candidate "<accepted_id>"
    And the obligation retains rejected candidate "<rejected_id>" with reason "<reason>"

    Examples:
      | risk_id                | pattern_id | accepted_id                                    | rejected_id                                    | reason                    |
      | atlas-prompt-injection | AP-T6-01   | cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | rule rejected combination |

  # Taxonomy obligation planner 08 records zero network and model calls
  Scenario Outline: Taxonomy obligation planner 08 records zero network and model calls
    Given the snapshot contains in-scope and out-of-scope relationships
    When the obligation plan is produced
    Then obligation planning recorded <network_calls> network calls
    And obligation planning recorded <model_calls> model calls

    Examples:
      | network_calls | model_calls |
      | 0             | 0           |

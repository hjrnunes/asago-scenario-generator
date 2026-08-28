Feature: Taxonomy obligation planner
  A deterministic planner turns pinned taxonomy/risk inputs into a
  closed obligation ledger. Identity is semantic, every obligation has
  one allowed disposition on each axis, and planning makes no network
  or model calls.

  Background:
    Given a pinned taxonomy obligation snapshot is available
    And obligation planning makes no network or model calls

  # Taxonomy obligation planner 01 preserves distinct risk-scoped obligations for a shared pattern
  Scenario Outline: Taxonomy obligation planner 01 preserves distinct risk-scoped obligations for a shared pattern
    Given risk cards "<risk_a>" and "<risk_b>" both map as applicable to attack pattern "<pattern_id>"
    When the obligation plan is produced
    Then the plan ledger contains <obligation_count> obligations for pattern "<pattern_id>"
    And the obligation for risk "<risk_a>" is distinct from the obligation for risk "<risk_b>"
    And each obligation retains its own risk identity

    Examples:
      | risk_a                 | risk_b                 | pattern_id | obligation_count |
      | atlas-prompt-injection | atlas-memory-poisoning | AP-T1-01   | 2                |

  # Taxonomy obligation planner 02 records applicable and capability-excluded relationships
  Scenario Outline: Taxonomy obligation planner 02 records applicable and capability-excluded relationships
    Given risk "<risk_id>" has an applicable mapping to pattern "<applicable_pattern>"
    And risk "<risk_id>" has a capability-excluded mapping to pattern "<excluded_pattern>"
    When the obligation plan is produced
    Then the plan records scope disposition "applicable" for risk "<risk_id>" and pattern "<applicable_pattern>"
    And the plan records scope disposition "capability_excluded" for risk "<risk_id>" and pattern "<excluded_pattern>"

    Examples:
      | risk_id                | applicable_pattern | excluded_pattern |
      | atlas-prompt-injection | AP-T6-01           | AP-T11-01        |

  # Taxonomy obligation planner 03 assigns exactly one closed disposition on every axis
  Scenario Outline: Taxonomy obligation planner 03 assigns exactly one closed disposition on every axis
    Given the snapshot contains "<relationship_count>" expected risk-to-pattern relationships
    When the obligation plan is produced
    Then the plan ledger contains "<relationship_count>" obligations
    And every obligation has exactly one scope disposition
    And every obligation has exactly one qualification disposition
    And every obligation has correspondence disposition "not_assessed"
    And no expected relationship is omitted from the ledger

    Examples:
      | relationship_count |
      | 6                  |

  # Taxonomy obligation planner 04 records closed scope and qualification dispositions
  Scenario Outline: Taxonomy obligation planner 04 records closed scope and qualification dispositions
    Given the snapshot contains a "<relationship_kind>" relationship for risk "<risk_id>" and pattern "<pattern_id>"
    When the obligation plan is produced
    Then the plan ledger contains 1 obligation for risk "<risk_id>" and pattern "<pattern_id>"
    And that obligation has scope disposition "<scope_disposition>"
    And that obligation has qualification disposition "<qualification_disposition>"
    And that obligation has correspondence disposition "not_assessed"
    And that obligation records candidate projection disposition "<projection_disposition>"
    And that obligation retains evidence for "<relationship_kind>"

    Examples:
      | relationship_kind            | risk_id                | pattern_id | scope_disposition   | qualification_disposition | projection_disposition |
      | capability-gated pattern     | atlas-prompt-injection | AP-T11-01  | capability_excluded | not_attempted             | not_attempted          |
      | missing qualification facts  | atlas-memory-poisoning | AP-T1-01   | applicable          | missing_evidence          | not_attempted          |
      | contradictory facts          | atlas-memory-poisoning | AP-T1-04   | applicable          | contradictory_evidence    | not_attempted          |
      | structurally infeasible      | atlas-memory-poisoning | AP-T1-03   | applicable          | structurally_infeasible   | not_attempted          |
      | qualified projectable        | atlas-prompt-injection | AP-T6-01   | applicable          | ready                     | projectable            |

  # Taxonomy obligation planner 05 records a governance-only risk without inventing a pattern
  Scenario Outline: Taxonomy obligation planner 05 records a governance-only risk without inventing a pattern
    Given risk card "<risk_id>" has no actionable attack pattern
    When the obligation plan is produced
    Then the plan ledger contains <obligation_count> obligations for risk "<risk_id>"
    And that obligation has scope disposition "<scope_disposition>"
    And that obligation has qualification disposition "<qualification_disposition>"
    And that obligation has correspondence disposition "not_assessed"
    And that obligation lists no attack-pattern ID

    Examples:
      | risk_id           | scope_disposition | qualification_disposition | obligation_count |
      | atlas-orphan-risk | governance_only   | not_attempted             | 1                |

  # Taxonomy obligation planner 06 retains qualification traces without secrets
  Scenario Outline: Taxonomy obligation planner 06 retains qualification traces without secrets
    Given the snapshot configuration includes secret "<secret>"
    And qualification is applicable for risk "<risk_id>" and pattern "<pattern_id>"
    And qualification evaluates predicate "<predicate>" with facts "<facts>" resulting in "<result>" because "<reason>"
    When the obligation plan is produced
    Then the qualification trace for that obligation records predicate "<predicate>", facts "<facts>", result "<result>", and reason "<reason>"
    And the qualification trace predicate, facts, result, and reason do not contain "<secret>"

    Examples:
      | risk_id                | pattern_id | predicate                                        | facts                                                  | result | reason                   | secret                 |
      | atlas-prompt-injection | AP-T6-01   | deployment.attacker_code_execution_on_agent_host | deployment.attacker_code_execution_on_agent_host=false | false  | fact present and unequal | SECRET_live_token_END  |

  # Taxonomy obligation planner 07 retains candidate records with projection dispositions
  Scenario Outline: Taxonomy obligation planner 07 retains candidate records with projection dispositions
    Given candidate projection is applicable for risk "atlas-prompt-injection" and pattern "AP-T6-01"
    And projection produces candidate "<candidate_id>" with disposition "<projection_disposition>" and reason "<reason>"
    When the obligation plan is produced
    Then the obligation retains candidate "<candidate_id>" with projection disposition "<projection_disposition>"
    And that candidate record retains reason "<reason>"

    Examples:
      | candidate_id                               | projection_disposition | reason                      |
      | cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | projectable            | qualified combination       |
      | cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | projection_infeasible  | missing required resource   |
      | cand:v2:cccccccccccccccccccccccccccccccc | budget_deferred        | projection budget exhausted |

  # Taxonomy obligation planner 08 records zero network and model calls
  Scenario Outline: Taxonomy obligation planner 08 records zero network and model calls
    Given the snapshot contains applicable and capability-excluded relationships
    When the obligation plan is produced
    Then obligation planning recorded <network_calls> network calls
    And obligation planning recorded <model_calls> model calls

    Examples:
      | network_calls | model_calls |
      | 0             | 0           |

  # Taxonomy obligation planner 09 changes obligation identity when an identity-bearing input changes
  Scenario Outline: Taxonomy obligation planner 09 changes obligation identity when an identity-bearing input changes
    Given one snapshot has "<identity_input>" "<value_a>"
    And another snapshot has "<identity_input>" "<value_b>"
    And both snapshots otherwise share the remaining identity-bearing inputs
    When an obligation plan is produced from each snapshot
    Then the two plans have different obligation identifiers
    And the two plans have different semantic digests

    Examples:
      | identity_input       | value_a                 | value_b                 |
      | risk ID              | atlas-prompt-injection  | atlas-memory-poisoning  |
      | pattern ID           | AP-T6-01                | AP-T1-01                |
      | capability snapshot  | profile-v1              | profile-v2              |
      | catalog pin          | atlas-2026.05           | atlas-2026.06           |
      | mapping pin          | sssom-v1                | sssom-v2                |

  # Taxonomy obligation planner 10 ignores ICA prose keyword changes
  Scenario Outline: Taxonomy obligation planner 10 ignores ICA prose keyword changes
    Given one snapshot includes ICA prose "<prose_a>"
    And another snapshot includes ICA prose "<prose_b>"
    And both snapshots otherwise share the same risks, patterns, and pins
    When an obligation plan is produced from each snapshot
    Then both plans have identical obligation identifiers
    And both plans have identical semantic digests
    And both plans have identical scope dispositions
    And both plans have identical qualification dispositions

    Examples:
      | prose_a                      | prose_b                 |
      | the agent injects a prompt   | the agent poisons memory |

  # Taxonomy obligation planner 11 rejects invalid scope and qualification combinations
  Scenario Outline: Taxonomy obligation planner 11 rejects invalid scope and qualification combinations
    Given a snapshot would combine scope disposition "<scope_disposition>" with qualification disposition "<qualification_disposition>"
    When the obligation plan is produced
    Then planning is rejected
    And no partial plan is published
    And the result identifies the disposition combination as invalid

    Examples:
      | scope_disposition   | qualification_disposition |
      | governance_only     | ready                     |
      | capability_excluded | missing_evidence          |
      | applicable          | not_attempted             |

  # Taxonomy obligation planner 12 derives summary counts from obligation rows
  Scenario Outline: Taxonomy obligation planner 12 derives summary counts from obligation rows
    Given a snapshot whose obligation rows include every summary category
    When the obligation plan is produced
    Then the plan summary counts are total <total>, applicable <applicable>, governance-only <governance_only>, capability-excluded <capability_excluded>, ready <ready>, missing-or-contradictory <missing_or_contradictory>, structurally-infeasible <structurally_infeasible>
    And the plan summary candidate counts are projectable <projectable>, projection-infeasible <projection_infeasible>, budget-deferred <budget_deferred>
    And those counts are derived from the obligation rows
    And the plan summary does not include a taxonomy correspondence rate
    And the plan summary does not include a scenario realization rate

    Examples:
      | total | applicable | governance_only | capability_excluded | ready | missing_or_contradictory | structurally_infeasible | projectable | projection_infeasible | budget_deferred |
      | 6     | 4          | 1               | 1                   | 1     | 2                        | 1                       | 1           | 1                     | 1               |

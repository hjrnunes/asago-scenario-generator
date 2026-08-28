# mutation-stamp: sha256=9183dcec3cba5067ed26b36fc4cec1d997b7f6eb7ac21f915eda56eaef8e678b
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-28T10:40:32.217418Z","feature_name":"Taxonomy obligation planner","feature_path":"features/taxonomy_obligation_planner.feature","background_hash":"404ec7aa5df544172f5d7bba33f66ab007a962f33538ef45f7b38cb73129ab7b","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Taxonomy obligation planner 01 preserves distinct risk-scoped obligations for a shared pattern","scenario_hash":"1a535fde23bb58798ae93adeae2f5483e48a3d43921f936b2f303b618c6e43ab","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":1,"name":"Taxonomy obligation planner 02 records applicable and capability-excluded relationships","scenario_hash":"4277497574605ee561094a0a44429a7fedee7d7e87b5b3d92d25cfca3fc2db4c","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":3,"name":"Taxonomy obligation planner 04a records a capability-gated relationship as capability-excluded","scenario_hash":"b676056b5c871571c7c59c1641f769bb18309bd26640e51421a79e4f92e1a77d","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":4,"name":"Taxonomy obligation planner 04b records missing qualification facts as missing evidence","scenario_hash":"f960d502163858cc161bcfd32e75dd196a9dd865ba854620958a09ae0d8b92a2","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":5,"name":"Taxonomy obligation planner 04c records contradictory facts as contradictory evidence","scenario_hash":"b8526d398669f2d93ae1ca5aaed60bf6b871f45eabaf235fc7e633c1b3782cd9","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":6,"name":"Taxonomy obligation planner 04d records a structurally infeasible relationship","scenario_hash":"428c50d6336ed620aa5f4b515949e331c15ecaa948bce01974dc893c1aa12e8c","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":7,"name":"Taxonomy obligation planner 04e records a qualified projectable relationship","scenario_hash":"93acb490aa1c6f9a2c627fd874a33fc0a72ff0d44da9219d10705ae4878d47b8","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":8,"name":"Taxonomy obligation planner 05 records a governance-only risk without inventing a pattern","scenario_hash":"cf5e7d7d84b0a29afeafcef5c62ecb83baaadd84aab6a83e07dae5df3dc5f71b","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":9,"name":"Taxonomy obligation planner 06 retains qualification traces without secrets","scenario_hash":"3bcd57b01cc166c111799878b55b12a42797e5d0e987a9cedbb0ad656982f55b","mutation_count":7,"result":{"Total":7,"Killed":7,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":10,"name":"Taxonomy obligation planner 07a retains a projectable candidate record","scenario_hash":"3c1ebe502d60f35be40151983c34694f9e95f6423c096e6b26731fa7e86a58a7","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":11,"name":"Taxonomy obligation planner 07b retains a projection-infeasible candidate record","scenario_hash":"9e022f65c18376f65a87a965a32be00769a744611c3c49656c48ecef30f73b44","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":12,"name":"Taxonomy obligation planner 07c retains a budget-deferred candidate record","scenario_hash":"264734310dbbfe7b911ed3959c06f89177a4dd22ee3a2f245a8d1e3e309e20aa","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":13,"name":"Taxonomy obligation planner 08 records zero network and model calls","scenario_hash":"789ed1b992dffecca34bbe742084a7fd258380f89886823d92e8cee69d9cd1a1","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":14,"name":"Taxonomy obligation planner 09a changes obligation identity when the risk ID changes","scenario_hash":"9076a8a4f4bbf8dc008c1f0888f45511ad9f31ef4a922509ab229e4fec9e5145","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":15,"name":"Taxonomy obligation planner 09b changes obligation identity when the pattern ID changes","scenario_hash":"98fc2b0d64fb8a76317d10bb7ba858226f641edd4c14015c35116a8d8cb6b7dc","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":16,"name":"Taxonomy obligation planner 09c changes obligation identity when the capability snapshot changes","scenario_hash":"11919d3ecadd38c81b3b31a41e9f9ecc1cd7340decdfa49de980aa8ec7ea2dd2","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":17,"name":"Taxonomy obligation planner 09d changes obligation identity when the catalog pin changes","scenario_hash":"11e451c420de1abe9de946a6cf544e0e4f71db37a1a4f904e469c0fc2bc0d416","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":18,"name":"Taxonomy obligation planner 09e changes obligation identity when the mapping pin changes","scenario_hash":"e30a62218d19b22c686e4cbe88e66b178a80324b56ff38a22271aa46ce712700","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":20,"name":"Taxonomy obligation planner 11a rejects governance-only scope with ready qualification","scenario_hash":"94ffc28939d59c9863debeae3c6ce3a0ccf9ea58e7785f8c6eb5c14bff48543f","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":21,"name":"Taxonomy obligation planner 11b rejects capability-excluded scope with missing evidence","scenario_hash":"beefad9d32e0c0e940e3996be77ffcf23fe3af67542e7898e23b3bc5dfb77d6a","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":22,"name":"Taxonomy obligation planner 11c rejects applicable scope with not-attempted qualification","scenario_hash":"7dadc94fcf146c5913c02541fa7052c1e99839dd63e781fe3cf5e0e6ffa10f09","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"},{"index":23,"name":"Taxonomy obligation planner 12 derives summary counts from obligation rows","scenario_hash":"ce1b9f734c5c189700f396e9c2f5d397f12b99030356e7d99cd9a469b4a73b88","mutation_count":10,"result":{"Total":10,"Killed":10,"Survived":0,"Errors":0},"tested_at":"2026-08-28T10:40:32.217418Z"}]}
# acceptance-mutation-manifest-end

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
    Then the plan ledger contains 2 obligations for pattern "AP-T1-01"
    And the obligation for risk "atlas-prompt-injection" is distinct from the obligation for risk "atlas-memory-poisoning"
    And each obligation retains its own risk identity

    Examples:
      | risk_a                 | risk_b                 | pattern_id |
      | atlas-prompt-injection | atlas-memory-poisoning | AP-T1-01   |

  # Taxonomy obligation planner 02 records applicable and capability-excluded relationships
  Scenario Outline: Taxonomy obligation planner 02 records applicable and capability-excluded relationships
    Given risk "<risk_id>" has an applicable mapping to pattern "<applicable_pattern>"
    And risk "<risk_id>" has a capability-excluded mapping to pattern "<excluded_pattern>"
    When the obligation plan is produced
    Then the plan records scope disposition "applicable" for risk "atlas-prompt-injection" and pattern "AP-T6-01"
    And the plan records scope disposition "capability_excluded" for risk "atlas-prompt-injection" and pattern "AP-T11-01"

    Examples:
      | risk_id                | applicable_pattern | excluded_pattern |
      | atlas-prompt-injection | AP-T6-01           | AP-T11-01        |

  # Taxonomy obligation planner 03 assigns exactly one closed disposition on every axis
  Scenario: Taxonomy obligation planner 03 assigns exactly one closed disposition on every axis
    Given the snapshot contains "6" expected risk-to-pattern relationships
    When the obligation plan is produced
    Then the plan ledger contains 6 obligations
    And every obligation has exactly one scope disposition
    And every obligation has exactly one qualification disposition
    And every obligation has correspondence disposition "not_assessed"
    And no expected relationship is omitted from the ledger

  # Taxonomy obligation planner 04a records a capability-gated relationship as capability-excluded
  Scenario Outline: Taxonomy obligation planner 04a records a capability-gated relationship as capability-excluded
    Given the snapshot contains a "<relationship_kind>" relationship for risk "<risk_id>" and pattern "<pattern_id>"
    When the obligation plan is produced
    Then the plan ledger contains 1 obligation for risk "atlas-prompt-injection" and pattern "AP-T11-01"
    And that obligation has scope disposition "capability_excluded"
    And that obligation has qualification disposition "not_attempted"
    And that obligation has correspondence disposition "not_assessed"
    And that obligation records candidate projection disposition "not_attempted"
    And that obligation retains evidence for "capability-gated pattern"

    Examples:
      | relationship_kind        | risk_id                | pattern_id |
      | capability-gated pattern | atlas-prompt-injection | AP-T11-01  |

  # Taxonomy obligation planner 04b records missing qualification facts as missing evidence
  Scenario Outline: Taxonomy obligation planner 04b records missing qualification facts as missing evidence
    Given the snapshot contains a "<relationship_kind>" relationship for risk "<risk_id>" and pattern "<pattern_id>"
    When the obligation plan is produced
    Then the plan ledger contains 1 obligation for risk "atlas-memory-poisoning" and pattern "AP-T1-01"
    And that obligation has scope disposition "applicable"
    And that obligation has qualification disposition "missing_evidence"
    And that obligation has correspondence disposition "not_assessed"
    And that obligation records candidate projection disposition "not_attempted"
    And that obligation retains evidence for "missing qualification facts"

    Examples:
      | relationship_kind           | risk_id                | pattern_id |
      | missing qualification facts | atlas-memory-poisoning | AP-T1-01   |

  # Taxonomy obligation planner 04c records contradictory facts as contradictory evidence
  Scenario Outline: Taxonomy obligation planner 04c records contradictory facts as contradictory evidence
    Given the snapshot contains a "<relationship_kind>" relationship for risk "<risk_id>" and pattern "<pattern_id>"
    When the obligation plan is produced
    Then the plan ledger contains 1 obligation for risk "atlas-memory-poisoning" and pattern "AP-T1-04"
    And that obligation has scope disposition "applicable"
    And that obligation has qualification disposition "contradictory_evidence"
    And that obligation has correspondence disposition "not_assessed"
    And that obligation records candidate projection disposition "not_attempted"
    And that obligation retains evidence for "contradictory facts"

    Examples:
      | relationship_kind   | risk_id                | pattern_id |
      | contradictory facts | atlas-memory-poisoning | AP-T1-04   |

  # Taxonomy obligation planner 04d records a structurally infeasible relationship
  Scenario Outline: Taxonomy obligation planner 04d records a structurally infeasible relationship
    Given the snapshot contains a "<relationship_kind>" relationship for risk "<risk_id>" and pattern "<pattern_id>"
    When the obligation plan is produced
    Then the plan ledger contains 1 obligation for risk "atlas-memory-poisoning" and pattern "AP-T1-03"
    And that obligation has scope disposition "applicable"
    And that obligation has qualification disposition "structurally_infeasible"
    And that obligation has correspondence disposition "not_assessed"
    And that obligation records candidate projection disposition "not_attempted"
    And that obligation retains evidence for "structurally infeasible"

    Examples:
      | relationship_kind       | risk_id                | pattern_id |
      | structurally infeasible | atlas-memory-poisoning | AP-T1-03   |

  # Taxonomy obligation planner 04e records a qualified projectable relationship
  Scenario Outline: Taxonomy obligation planner 04e records a qualified projectable relationship
    Given the snapshot contains a "<relationship_kind>" relationship for risk "<risk_id>" and pattern "<pattern_id>"
    When the obligation plan is produced
    Then the plan ledger contains 1 obligation for risk "atlas-prompt-injection" and pattern "AP-T6-01"
    And that obligation has scope disposition "applicable"
    And that obligation has qualification disposition "ready"
    And that obligation has correspondence disposition "not_assessed"
    And that obligation records candidate projection disposition "projectable"
    And that obligation retains evidence for "qualified projectable"

    Examples:
      | relationship_kind     | risk_id                | pattern_id |
      | qualified projectable | atlas-prompt-injection | AP-T6-01   |

  # Taxonomy obligation planner 05 records a governance-only risk without inventing a pattern
  Scenario Outline: Taxonomy obligation planner 05 records a governance-only risk without inventing a pattern
    Given risk card "<risk_id>" has no actionable attack pattern
    When the obligation plan is produced
    Then the plan ledger contains 1 obligation for risk "atlas-orphan-risk"
    And that obligation has scope disposition "governance_only"
    And that obligation has qualification disposition "not_attempted"
    And that obligation has correspondence disposition "not_assessed"
    And that obligation lists no attack-pattern ID

    Examples:
      | risk_id           |
      | atlas-orphan-risk |

  # Taxonomy obligation planner 06 retains qualification traces without secrets
  Scenario Outline: Taxonomy obligation planner 06 retains qualification traces without secrets
    Given the snapshot configuration includes secret "<secret>"
    And qualification is applicable for risk "<risk_id>" and pattern "<pattern_id>"
    And qualification evaluates predicate "<predicate>" with facts "<facts>" resulting in "<result>" because "<reason>"
    When the obligation plan is produced
    Then the qualification trace for that obligation records predicate "deployment.attacker_code_execution_on_agent_host", facts "deployment.attacker_code_execution_on_agent_host=false token=[REDACTED]", result "false", and reason "fact present and unequal"
    And that obligation is for risk "atlas-prompt-injection" and pattern "AP-T6-01"
    And the qualification trace predicate, facts, result, and reason do not contain "SECRET_live_token_END"

    Examples:
      | risk_id                | pattern_id | predicate                                        | facts                                                                                             | result | reason                   | secret                |
      | atlas-prompt-injection | AP-T6-01   | deployment.attacker_code_execution_on_agent_host | deployment.attacker_code_execution_on_agent_host=false token=SECRET_live_token_END | false  | fact present and unequal | SECRET_live_token_END |

  # Taxonomy obligation planner 07a retains a projectable candidate record
  Scenario Outline: Taxonomy obligation planner 07a retains a projectable candidate record
    Given candidate projection is applicable for risk "atlas-prompt-injection" and pattern "AP-T6-01"
    And projection produces candidate "<candidate_id>" with disposition "<projection_disposition>" and reason "<reason>"
    When the obligation plan is produced
    Then the obligation retains candidate "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" with projection disposition "projectable"
    And that candidate record retains reason "qualified combination"

    Examples:
      | candidate_id                              | projection_disposition | reason                |
      | cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | projectable            | qualified combination |

  # Taxonomy obligation planner 07b retains a projection-infeasible candidate record
  Scenario Outline: Taxonomy obligation planner 07b retains a projection-infeasible candidate record
    Given candidate projection is applicable for risk "atlas-prompt-injection" and pattern "AP-T6-01"
    And projection produces candidate "<candidate_id>" with disposition "<projection_disposition>" and reason "<reason>"
    When the obligation plan is produced
    Then the obligation retains candidate "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" with projection disposition "projection_infeasible"
    And that candidate record retains reason "missing required resource"

    Examples:
      | candidate_id                              | projection_disposition | reason                    |
      | cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | projection_infeasible  | missing required resource |

  # Taxonomy obligation planner 07c retains a budget-deferred candidate record
  Scenario Outline: Taxonomy obligation planner 07c retains a budget-deferred candidate record
    Given candidate projection is applicable for risk "atlas-prompt-injection" and pattern "AP-T6-01"
    And projection produces candidate "<candidate_id>" with disposition "<projection_disposition>" and reason "<reason>"
    When the obligation plan is produced
    Then the obligation retains candidate "cand:v2:cccccccccccccccccccccccccccccccc" with projection disposition "budget_deferred"
    And that candidate record retains reason "projection budget exhausted"

    Examples:
      | candidate_id                              | projection_disposition | reason                      |
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

  # Taxonomy obligation planner 09a changes obligation identity when the risk ID changes
  Scenario Outline: Taxonomy obligation planner 09a changes obligation identity when the risk ID changes
    Given one snapshot has "risk ID" "<value_a>"
    And another snapshot has "risk ID" "<value_b>"
    And both snapshots otherwise share the remaining identity-bearing inputs
    When an obligation plan is produced from each snapshot
    Then the two plans have different obligation identifiers
    And the two plans have different semantic digests
    And the plan from the first snapshot records an obligation for risk "atlas-prompt-injection"
    And the plan from the second snapshot records an obligation for risk "atlas-memory-poisoning"

    Examples:
      | value_a                | value_b                |
      | atlas-prompt-injection | atlas-memory-poisoning |

  # Taxonomy obligation planner 09b changes obligation identity when the pattern ID changes
  Scenario Outline: Taxonomy obligation planner 09b changes obligation identity when the pattern ID changes
    Given one snapshot has "pattern ID" "<value_a>"
    And another snapshot has "pattern ID" "<value_b>"
    And both snapshots otherwise share the remaining identity-bearing inputs
    When an obligation plan is produced from each snapshot
    Then the two plans have different obligation identifiers
    And the two plans have different semantic digests
    And the plan from the first snapshot records an obligation for pattern "AP-T6-01"
    And the plan from the second snapshot records an obligation for pattern "AP-T1-01"

    Examples:
      | value_a  | value_b  |
      | AP-T6-01 | AP-T1-01 |

  # Taxonomy obligation planner 09c changes obligation identity when the capability snapshot changes
  Scenario Outline: Taxonomy obligation planner 09c changes obligation identity when the capability snapshot changes
    Given one snapshot has "capability snapshot" "<value_a>"
    And another snapshot has "capability snapshot" "<value_b>"
    And both snapshots otherwise share the remaining identity-bearing inputs
    When an obligation plan is produced from each snapshot
    Then the two plans have different obligation identifiers
    And the two plans have different semantic digests
    And the plan from the first snapshot records the capability snapshot digest of "profile-v1"
    And the plan from the second snapshot records the capability snapshot digest of "profile-v2"

    Examples:
      | value_a    | value_b    |
      | profile-v1 | profile-v2 |

  # Taxonomy obligation planner 09d changes obligation identity when the catalog pin changes
  Scenario Outline: Taxonomy obligation planner 09d changes obligation identity when the catalog pin changes
    Given one snapshot has "catalog pin" "<value_a>"
    And another snapshot has "catalog pin" "<value_b>"
    And both snapshots otherwise share the remaining identity-bearing inputs
    When an obligation plan is produced from each snapshot
    Then the two plans have different obligation identifiers
    And the two plans have different semantic digests
    And the plan from the first snapshot pins catalog pin "atlas-2026.05"
    And the plan from the second snapshot pins catalog pin "atlas-2026.06"

    Examples:
      | value_a      | value_b      |
      | atlas-2026.05 | atlas-2026.06 |

  # Taxonomy obligation planner 09e changes obligation identity when the mapping pin changes
  Scenario Outline: Taxonomy obligation planner 09e changes obligation identity when the mapping pin changes
    Given one snapshot has "mapping pin" "<value_a>"
    And another snapshot has "mapping pin" "<value_b>"
    And both snapshots otherwise share the remaining identity-bearing inputs
    When an obligation plan is produced from each snapshot
    Then the two plans have different obligation identifiers
    And the two plans have different semantic digests
    And the plan from the first snapshot pins mapping pin "sssom-v1"
    And the plan from the second snapshot pins mapping pin "sssom-v2"

    Examples:
      | value_a  | value_b  |
      | sssom-v1 | sssom-v2 |

  # Taxonomy obligation planner 10 ignores ICA prose keyword changes
  Scenario: Taxonomy obligation planner 10 ignores ICA prose keyword changes
    Given one snapshot includes ICA prose "the agent injects a prompt"
    And another snapshot includes ICA prose "the agent poisons memory"
    And both snapshots otherwise share the same risks, patterns, and pins
    When an obligation plan is produced from each snapshot
    Then both plans have identical obligation identifiers
    And both plans have identical semantic digests
    And both plans have identical scope dispositions
    And both plans have identical qualification dispositions

  # Taxonomy obligation planner 11a rejects governance-only scope with ready qualification
  Scenario Outline: Taxonomy obligation planner 11a rejects governance-only scope with ready qualification
    Given a snapshot would combine scope disposition "<scope_disposition>" with qualification disposition "<qualification_disposition>"
    When the obligation plan is produced
    Then planning is rejected
    And no partial plan is published
    And the result identifies scope "governance_only" and qualification "ready" as an invalid combination

    Examples:
      | scope_disposition | qualification_disposition |
      | governance_only   | ready                     |

  # Taxonomy obligation planner 11b rejects capability-excluded scope with missing evidence
  Scenario Outline: Taxonomy obligation planner 11b rejects capability-excluded scope with missing evidence
    Given a snapshot would combine scope disposition "<scope_disposition>" with qualification disposition "<qualification_disposition>"
    When the obligation plan is produced
    Then planning is rejected
    And no partial plan is published
    And the result identifies scope "capability_excluded" and qualification "missing_evidence" as an invalid combination

    Examples:
      | scope_disposition   | qualification_disposition |
      | capability_excluded | missing_evidence          |

  # Taxonomy obligation planner 11c rejects applicable scope with not-attempted qualification
  Scenario Outline: Taxonomy obligation planner 11c rejects applicable scope with not-attempted qualification
    Given a snapshot would combine scope disposition "<scope_disposition>" with qualification disposition "<qualification_disposition>"
    When the obligation plan is produced
    Then planning is rejected
    And no partial plan is published
    And the result identifies scope "applicable" and qualification "not_attempted" as an invalid combination

    Examples:
      | scope_disposition | qualification_disposition |
      | applicable        | not_attempted             |

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

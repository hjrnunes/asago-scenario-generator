# Hybrid coverage assessment

Artifact: hybrid-coverage-assessment-v1 / d4d4f7cb4b12c90f50bf3f67d3c27ccd0ec7ca16cd967ecf5db90f5b9cb2b7d5

Structural inventory: complete

## Source artifacts

- capability-fact-snapshot@capability-fact-snapshot-v1: 1a23098699d8be1f5b14cd208a8e4642e349e7d82abd6eac7deb3b2134fd2a46
- correspondence-reconciliation@correspondence-reconciliation-v1: 9cf78772ad0d22dcfe583cad1e10d4d8200937589542b24f3550794b287cf45e
- ica-enumeration@ica-enumeration-v1: 3333333333333333333333333333333333333333333333333333333333333333
- stpa-scenarios@stpa-scenarios-v1: 8888888888888888888888888888888888888888888888888888888888888888
- system-resource-map@system-resource-map-v1: 5c56bdc51585c2caa242f9ddbc986c8c5bdd6fd929ce360bd6ad8d33216d9a26
- taxonomy-obligation-plan@taxonomy-obligation-plan-v1: 52be64e238118460cc11628eed19ab3864c7ae5c9fa9041486bd8b0b61294195
- taxonomy-scenarios@taxonomy-scenarios-v1: 7777777777777777777777777777777777777777777777777777777777777777

## Structural consideration
| Row | Slot | Controller | Control action | UCA type | Disposition | ICAs | Evidence | Trace |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hca-struct:v1:5e125a96eeec2d8191349f5b5040dfc1bc9b87de131197a1ac24f92230273e78 | RESP-1:CA-1-1:WRONG_TIMING | RESP-1 | CA-1-1 | WRONG_TIMING | ica | RESP-1:CA-1-1:WRONG_TIMING:1 | ica-enumeration.yaml#RESP-1:CA-1-1:WRONG_TIMING:1 | ica-enumeration@ica-enumeration-v1#RESP-1:CA-1-1:WRONG_TIMING, ica-enumeration@ica-enumeration-v1#RESP-1:CA-1-1:WRONG_TIMING:1, ica-enumeration@ica-enumeration-v1#ica-enumeration.yaml#RESP-1:CA-1-1:WRONG_TIMING |

## Taxonomy correspondence
| Row | Obligation | Risk | Pattern | Taxonomy candidates | Scope | Qualification | Accepted relations | Disposition | Gap | Trace |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hca-tax:v1:2a7fefb2abe4ae736cb116666ad514c5ad858ab818e8a97c4d7225d70313ab59 | ob:v1:741b678e5ed0aae16ceb83ee81db90e98fc10b78f7cb90a5e4628a67ab727727 | risk-a | AP-T1-01 | cand:v2:c1ce1e48c8fcea147f0c57d7552d041a, cand:v2:daf352c50c0d3cd035d6e35f222869f2 | applicable | ready | correlation:v1:ea7ad1b470a32d2fbd42e17e1583cb8f186aaf3379766a7cf39056886387cc23 | satisfied | — | correspondence-reconciliation@correspondence-reconciliation-v1#correlation:v1:ea7ad1b470a32d2fbd42e17e1583cb8f186aaf3379766a7cf39056886387cc23, taxonomy-obligation-plan@taxonomy-obligation-plan-v1#cand:v2:c1ce1e48c8fcea147f0c57d7552d041a, taxonomy-obligation-plan@taxonomy-obligation-plan-v1#cand:v2:daf352c50c0d3cd035d6e35f222869f2, taxonomy-obligation-plan@taxonomy-obligation-plan-v1#ob:v1:741b678e5ed0aae16ceb83ee81db90e98fc10b78f7cb90a5e4628a67ab727727, taxonomy-scenarios@taxonomy-scenarios-v1#scenario.yaml, taxonomy-scenarios@taxonomy-scenarios-v1#scenario:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |

## Scenario realization
| Row | Relation | Proposal | Obligation | Risk | Pattern | Taxonomy candidates | Relation kind | Legacy scenarios | Hybrid generation | Hybrid admission | Trace |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hca-real:v1:1ca34d807870d2b2a45c4cb0dbf26f894a2e58098242e06c8edef81bc7deb849 | correlation:v1:ea7ad1b470a32d2fbd42e17e1583cb8f186aaf3379766a7cf39056886387cc23 | corrp:v1:1b0b1d97d2d70bd3a8e746914eee3ce09046102f34ec61652254500bddc3cab5 | ob:v1:741b678e5ed0aae16ceb83ee81db90e98fc10b78f7cb90a5e4628a67ab727727 | risk-a | AP-T1-01 | cand:v2:c1ce1e48c8fcea147f0c57d7552d041a, cand:v2:daf352c50c0d3cd035d6e35f222869f2 | same_mechanism | STPA-SCENARIO-1 | not_attempted | not_assessed | correspondence-reconciliation@correspondence-reconciliation-v1#correlation:v1:ea7ad1b470a32d2fbd42e17e1583cb8f186aaf3379766a7cf39056886387cc23, stpa-scenarios@stpa-scenarios-v1#STPA-SCENARIO-1, stpa-scenarios@stpa-scenarios-v1#stpa/scenarios.yaml#STPA-SCENARIO-1, system-resource-map@system-resource-map-v1#srm:v1:assessment-link, taxonomy-obligation-plan@taxonomy-obligation-plan-v1#ob:v1:741b678e5ed0aae16ceb83ee81db90e98fc10b78f7cb90a5e4628a67ab727727 |

## Diagnostics (counts only)
| Diagnostic | Count |
| --- | --- |
| structural_ica | 1 |
| structural_justified_na | 0 |
| structural_unresolved | 0 |
| taxonomy_satisfied | 1 |
| taxonomy_structurally_inapplicable | 0 |
| taxonomy_unresolved | 0 |
| taxonomy_not_applicable | 0 |
| unmatched_obligations | 0 |
| accepted_relations | 1 |
| coverage_bearing_relations | 1 |
| rejected_proposals | 0 |
| unresolved_proposals | 0 |
| contradictory_findings | 0 |

## Non-coverage audit records
| Record | Kind/status | Risk | Pattern | Taxonomy candidates | Trace |
| --- | --- | --- | --- | --- | --- |
| — | none | — | — | — | — |

# mutation-stamp: sha256=88685fc6ce769906b30412064ab8cc5bf5880f5270878eaf8928e0a386c933fc
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-31T15:41:22.562947Z","feature_name":"Phase 4 Task 1 hybrid projection resolution","feature_path":"features/phase4_task1_hybrid_projection.feature","background_hash":"e41dcc22b0522c987bcffc4b83d769f6851a7b188e2236b01133f3d5b5be74a9","implementation_hash":"sha256:f78b8e06379e9d238d2bbcfc83eb3fb5f3514faba4ec4cb96579b545d3e35578","scenarios":[{"index":0,"name":"an accepted relation resolves to one exact unit","scenario_hash":"0848eb886d075097d0734dfee964db2a08ef47db5f0c70f654960f876ff35540","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-31T15:41:22.562947Z"},{"index":1,"name":"a related-only relation remains an explicit exclusion","scenario_hash":"699862923d3c8cf80be7bf71ae5d18d85c1036f6b59b37d64409848c786cd9f6","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-31T15:41:22.562947Z"},{"index":2,"name":"cross-paired correspondence authorities fail closed","scenario_hash":"419d79d537e2ed4d7a24e4e4c842383bd8745e51ceab0a4f6811699349195daa","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-31T15:41:22.562947Z"},{"index":3,"name":"a copied factory attestation is not trusted","scenario_hash":"a72fea7696b97fbf37390551bd2dbed547d0123d5998c23fb07f56d6cb58aa7a","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-31T15:41:22.562947Z"}]}
# acceptance-mutation-manifest-end

Feature: Phase 4 Task 1 hybrid projection resolution
  Task 1 resolves exact, already-attested taxonomy and STPA authorities into
  projection units. It keeps relation-local omissions visible and rejects
  substituted source authorities. This seam is offline and does not generate
  scenarios or publish a Task 2 artifact.

  Background:
    Given a complete typed Task 1 authority fixture is available
    And the Task 1 resolver has an offline network and model guard

  Scenario Outline: an accepted relation resolves to one exact unit
    When Task 1 resolves the accepted relation
    Then resolution returns <unit_count> unit and <exclusion_count> exclusions
    And the resolved five-part identity is "<identity>"
    And the offline guard records <network_calls> network calls and <model_calls> model calls

    Examples:
      | unit_count | exclusion_count | identity                                                                                                                                                | network_calls | model_calls |
      | 1          | 0               | correlation:v1:ea7ad1b470a32d2fbd42e17e1583cb8f186aaf3379766a7cf39056886387cc23/ob:v1:741b678e5ed0aae16ceb83ee81db90e98fc10b78f7cb90a5e4628a67ab727727/cand:v2:c1ce1e48c8fcea147f0c57d7552d041a/RESP-1:CA-1-1:WRONG_TIMING:1/EXEC:RESP-1:CA-1-1:WRONG_TIMING | 0             | 0           |

  Scenario Outline: a related-only relation remains an explicit exclusion
    When Task 1 resolves the related-only relation
    Then resolution returns <unit_count> unit and <exclusion_count> exclusions
    And the exclusion reason is "<reason>"
    And the offline guard records <network_calls> network calls and <model_calls> model calls

    Examples:
      | unit_count | exclusion_count | reason                 | network_calls | model_calls |
      | 0          | 1               | relation_not_coverage | 0             | 0           |

  Scenario Outline: cross-paired correspondence authorities fail closed
    When Task 1 builds a correspondence attestation from cross-paired authorities
    Then the Task 1 operation fails with diagnostic containing "<diagnostic>"
    And the offline guard records <network_calls> network calls and <model_calls> model calls

    Examples:
      | diagnostic                                               | network_calls | model_calls |
      | proposal set and reconciliation proposal content do not match | 0             | 0           |

  Scenario Outline: a copied factory attestation is not trusted
    When Task 1 resolves inputs containing a copied and re-digested attestation
    Then the Task 1 operation fails with diagnostic containing "<diagnostic>"
    And the offline guard records <network_calls> network calls and <model_calls> model calls

    Examples:
      | diagnostic             | network_calls | model_calls |
      | verified artifact factory | 0             | 0           |

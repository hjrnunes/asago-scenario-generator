# mutation-stamp: sha256=4fd5567264efcd8b621043f2f09a1ebb3cb84d11db3e4c2839cb3addf7cace3c
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-29T13:36:02.743437Z","feature_name":"Normative system resource map validation","feature_path":"features/system_resource_map.feature","background_hash":"84d6e28c2f96e5a2af8fd433a6382b1d3ee93899f3da9d04f1b4710c14c440c7","implementation_hash":"sha256:42780212842730b25859b1ecc67f98d3853685636f6a273142eb80a8f202a52e","scenarios":[{"index":1,"name":"source digest substitutions fail closed","scenario_hash":"7b0e3ba9a0e91b2a19a626143845403888b26c855da4c0346e55139e8e584668","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-29T13:36:02.743437Z"},{"index":2,"name":"unknown endpoints fail closed","scenario_hash":"b70891a23f2787507c0f27ecd12ae09e37ba48c84c5d1f060f0f4828495ecaaf","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-29T13:36:02.743437Z"},{"index":3,"name":"typed relation and authority rules fail closed","scenario_hash":"420db6f4699f84745a2ec2d5ff5ed774e2baa4966e4bc5aac2ee58c13ce40fa8","mutation_count":10,"result":{"Total":10,"Killed":10,"Survived":0,"Errors":0},"tested_at":"2026-08-29T13:36:02.743437Z"}]}
# acceptance-mutation-manifest-end

Feature: Normative system resource map validation
  Phase 2 joins canonical capability resources to STPA control-structure
  identities through an evidence-bearing, closed resource-map contract.
  Validation is pure and never infers correspondence.

  Background:
    Given typed capability and STPA authorities are available
    And resource-map validation makes no network or model calls

  Scenario: a valid typed map validates against exact authorities
    Given a valid typed resource map is available
    When the resource map is validated
    Then the resource map passes validation

  Scenario Outline: source digest substitutions fail closed
    Given a valid typed resource map is available
    And the map substitutes digest pin "<pin>"
    When the resource map is validated
    Then the resource map fails validation
    And the result contains violation code "<code>"

    Examples:
      | pin                          | code                               |
      | capability_snapshot_digest   | capability_snapshot_digest_mismatch |
      | control_structure_digest     | control_structure_digest_mismatch |

  Scenario Outline: unknown endpoints fail closed
    Given a valid typed resource map is available
    And the map references an unknown <endpoint>
    When the resource map is validated
    Then the resource map fails validation
    And the result contains violation code "unknown_<kind>"

    Examples:
      | endpoint            | kind                         |
      | capability resource | capability_resource         |
      | STPA identifier     | control_structure_reference |

  Scenario Outline: typed relation and authority rules fail closed
    Given a valid typed resource map is available
    And the map <defect>
    When the resource map is validated
    Then the resource map fails validation
    And the result contains violation code "<code>"

    Examples:
      | defect                                            | code                              |
      | uses an incompatible relation kind                | incompatible_relation_kind       |
      | marks a model-proposed link authoritative         | model_proposed_authoritative     |
      | has an authoritative link with no evidence        | authoritative_link_without_evidence |
      | contains duplicate semantic links                 | duplicate_semantic_link          |
      | contains a contradictory authoritative cardinality | contradictory_authoritative_link |

  Scenario: model-proposed advisory links remain representable
    Given a model-proposed advisory link is present
    When the resource map is validated
    Then the advisory map validates

  Scenario: canonical identity ignores presentation order
    Given the same links are presented in two orders
    Then both canonical maps are identical

Feature: System resource map validation
  An analyst-authored SystemResourceMap is a typed, reviewable map from
  use-case facts and STPA control-structure elements to taxonomy
  resources. Validation is deterministic, distinguishes errors from
  review warnings, and infers no correspondence.

  Background:
    Given a pinned resource-map snapshot is available
    And resource-map validation makes no network or model calls

  # System resource map validation 01 accepts a representative map covering the v1 families
  Scenario Outline: System resource map validation 01 accepts a representative map covering the v1 families
    Given a representative resource map covers families "<families>"
    And the map references STPA identifiers "<stpa_ids>"
    And the map references taxonomy identifiers "<taxonomy_ids>"
    When the resource map is validated against the snapshot
    Then validation succeeds
    And the result contains <error_count> errors
    And the result contains no correspondence relations

    Examples:
      | families                                                                                                              | stpa_ids                          | taxonomy_ids                                                                 | error_count |
      | system-resource,actor-controller,controlled-process,control-action,feedback-path,trust-boundary,data-flow,loss-link,use-case-fact | RESP-1,CP-2,CA-1-1,FB-1-1,L-1,H-1 | ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | 0           |

  # System resource map validation 02 rejects duplicate or unstable identifiers
  Scenario Outline: System resource map validation 02 rejects duplicate or unstable identifiers
    Given a resource map contains identifier defect "<defect>" on identifier "<element_id>"
    When the resource map is validated against the snapshot
    Then validation fails
    And the result contains error code "<error_code>"
    And the error identifies "<element_id>"

    Examples:
      | defect    | element_id | error_code           |
      | duplicate | SR-1       | duplicate_identifier |
      | unstable  | idx-0      | unstable_identifier  |

  # System resource map validation 03 rejects dangling references
  Scenario Outline: System resource map validation 03 rejects dangling references
    Given a resource map references "<ref_kind>" identifier "<element_id>" that is absent from the snapshot
    When the resource map is validated against the snapshot
    Then validation fails
    And the result contains error code "<error_code>"
    And the error identifies "<element_id>"

    Examples:
      | ref_kind             | element_id                             | error_code         |
      | STPA responsibility  | RESP-99                                | dangling_reference |
      | STPA process         | CP-99                                  | dangling_reference |
      | STPA control action  | CA-99-1                                | dangling_reference |
      | STPA feedback        | FB-99-1                                | dangling_reference |
      | STPA loss            | L-99                                   | dangling_reference |
      | STPA hazard          | H-99                                   | dangling_reference |
      | taxonomy entry point | ep:v1:ffffffffffffffffffffffffffffffff | dangling_reference |
      | taxonomy boundary    | tb:v1:ffffffffffffffffffffffffffffffff | dangling_reference |

  # System resource map validation 04 rejects invalid enum and status values
  Scenario Outline: System resource map validation 04 rejects invalid enum and status values
    Given a resource map sets field "<field>" to "<value>"
    When the resource map is validated against the snapshot
    Then validation fails
    And the result contains error code "<error_code>"
    And the error identifies field "<field>"

    Examples:
      | field             | value                       | error_code   |
      | entity_family     | correspondence              | invalid_enum |
      | resolution_status | confirmed-absent-as-unknown | invalid_enum |
      | provenance_kind   | inferred-match              | invalid_enum |

  # System resource map validation 05 rejects inconsistent source-version pins
  Scenario Outline: System resource map validation 05 rejects inconsistent source-version pins
    Given the snapshot pins STPA version "<snapshot_stpa>" and taxonomy version "<snapshot_taxonomy>"
    And the resource map pins STPA version "<map_stpa>" and taxonomy version "<map_taxonomy>"
    When the resource map is validated against the snapshot
    Then validation fails
    And the result contains error code "<error_code>"

    Examples:
      | snapshot_stpa | snapshot_taxonomy | map_stpa | map_taxonomy  | error_code              |
      | stpa-v1       | atlas-2026.05     | stpa-v9  | atlas-2026.05 | source_version_mismatch |
      | stpa-v1       | atlas-2026.05     | stpa-v1  | atlas-1999.01 | source_version_mismatch |

  # System resource map validation 06 rejects control actions without valid controller or process references
  Scenario Outline: System resource map validation 06 rejects control actions without valid controller or process references
    Given control action "<element_id>" is missing a valid "<missing_ref>" reference
    When the resource map is validated against the snapshot
    Then validation fails
    And the result contains error code "<error_code>"
    And the error identifies "<element_id>"

    Examples:
      | element_id | missing_ref | error_code                   |
      | CA-1-1     | controller  | invalid_control_action_link  |
      | CA-1-1     | process     | invalid_control_action_link  |

  # System resource map validation 07 rejects data flows and trust boundaries that reference unknown resources
  Scenario Outline: System resource map validation 07 rejects data flows and trust boundaries that reference unknown resources
    Given a "<link_kind>" named "<element_id>" references unknown resource "<bad_ref>"
    When the resource map is validated against the snapshot
    Then validation fails
    And the result contains error code "<error_code>"
    And the error identifies "<element_id>"

    Examples:
      | link_kind      | element_id | bad_ref | error_code            |
      | data-flow      | DF-1       | SR-99   | unknown_resource_link |
      | trust-boundary | TB-1       | SR-99   | unknown_resource_link |

  # System resource map validation 08 rejects loss links that reference unknown STPA losses or hazards
  Scenario Outline: System resource map validation 08 rejects loss links that reference unknown STPA losses or hazards
    Given a loss link named "<link_id>" references unknown STPA "<ref_kind>" "<element_id>"
    When the resource map is validated against the snapshot
    Then validation fails
    And the result contains error code "<error_code>"
    And the error identifies "<element_id>"

    Examples:
      | link_id | ref_kind | element_id | error_code        |
      | LL-1    | loss     | L-99       | unknown_loss_link |
      | LL-1    | hazard   | H-99       | unknown_loss_link |

  # System resource map validation 09 rejects ambiguous aliases
  Scenario Outline: System resource map validation 09 rejects ambiguous aliases
    Given alias "<element_id>" is bound to identifiers "<ids>"
    When the resource map is validated against the snapshot
    Then validation fails
    And the result contains error code "<error_code>"
    And the error identifies "<element_id>"

    Examples:
      | element_id      | ids       | error_code      |
      | payment-backend | CP-2,CP-4 | ambiguous_alias |

  # System resource map validation 10 keeps unknown distinct from confirmed absence
  Scenario Outline: System resource map validation 10 keeps unknown distinct from confirmed absence
    Given use-case fact "<fact_id>" has resolution status "<status>"
    When the resource map is validated against the snapshot
    Then validation succeeds
    And fact "<fact_id>" is recorded as "<status>"
    And fact "<fact_id>" is not treated as "<other_status>"

    Examples:
      | fact_id | status  | other_status |
      | UF-1    | unknown | absent       |
      | UF-2    | absent  | unknown      |

  # System resource map validation 11 distinguishes analyst assertions from imported source facts
  Scenario Outline: System resource map validation 11 distinguishes analyst assertions from imported source facts
    Given assertion "<assertion_id>" has provenance kind "<provenance_kind>"
    When the resource map is validated against the snapshot
    Then validation succeeds
    And assertion "<assertion_id>" is recorded as provenance "<provenance_kind>"
    And assertion "<assertion_id>" is not recorded as provenance "<other_kind>"

    Examples:
      | assertion_id | provenance_kind | other_kind      |
      | A-1          | analyst         | imported-source |
      | A-2          | imported-source | analyst         |

  # System resource map validation 12 records missing optional provenance as a warning
  Scenario Outline: System resource map validation 12 records missing optional provenance as a warning
    Given assertion "<assertion_id>" omits optional provenance
    And the assertion is otherwise valid
    When the resource map is validated against the snapshot
    Then validation succeeds
    And the result contains <error_count> errors
    And the result contains warning code "<warning_code>"
    And the warning identifies "<assertion_id>"

    Examples:
      | assertion_id | error_count | warning_code                |
      | A-3          | 0           | missing_optional_provenance |

  # System resource map validation 13 infers no correspondence during validation
  Scenario Outline: System resource map validation 13 infers no correspondence during validation
    Given the map contains STPA identifier "<stpa_id>" and taxonomy identifier "<taxonomy_id>"
    And no analyst correspondence assertion is present
    When the resource map is validated against the snapshot
    Then validation succeeds
    And the result contains no correspondence relations
    And no lexical match is recorded for "<stpa_id>" and "<taxonomy_id>"

    Examples:
      | stpa_id | taxonomy_id                            |
      | CA-1-1  | ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |

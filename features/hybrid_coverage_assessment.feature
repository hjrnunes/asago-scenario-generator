# mutation-stamp: sha256=0cd463a212c3fe8c8321f055269b1e49db766dc7297ed492939fbcfb7463bfd7
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-31T01:15:13.071772Z","feature_name":"Normative observational hybrid coverage assessment","feature_path":"features/hybrid_coverage_assessment.feature","background_hash":"3e6252a39bd5ade5b6d2ff422b76edba5ae5e264b5f50253076a4592d5fb0ab9","implementation_hash":"sha256:af17bdc170a7fe1bb60b501d6001c40622d5c8c8711f5ca84815f8779d7d1d9d","scenarios":[{"index":0,"name":"exact source artifacts reconcile through the external facade","scenario_hash":"e569029f56bafd18cc2922da17266568790bc05e640d2107fdce8e26e90c6370","mutation_count":7,"result":{"Total":7,"Killed":7,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"},{"index":1,"name":"substituted reconciliation capability scope fails closed","scenario_hash":"866b92f82958002d649e13f748cffa9b23a4df97b98edde5ddccbbc2b985848c","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"},{"index":2,"name":"accepted confirmation projects through the normative matrices","scenario_hash":"c6d2cc83a15d7f4d142a53db1965940d039c6a0b2bbec5309854df845805642a","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"},{"index":3,"name":"real scenario envelopes become exact observations","scenario_hash":"c8229f5ad12084efab489f2033dc846ef8e4591bee72c6d5b2fa60720908505f","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"},{"index":4,"name":"structural consideration keeps all reviewed slot outcomes","scenario_hash":"8e27e4f8b486a5458950ae199a67305a7a3af3347b8b0119594a9bbe7afff40b","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"},{"index":5,"name":"noncoverage correspondence stays an explicit finding","scenario_hash":"64a3611a1cde293e7108e9844a1e683db67f0392de1dc792551060f7a0067085","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"},{"index":6,"name":"structural inapplicability is an explicit reviewed decision","scenario_hash":"93ed7efdb7eacb4b534705242f49baa82b990251b32edd4df5f347fc8ba97941","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"},{"index":7,"name":"inferred capability inventory cannot prove structural inapplicability","scenario_hash":"e97b5ed1e389fb73cfc480748796b347323248e7697f5fc7d1d24ff4c98360e4","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"},{"index":8,"name":"defective proposals remain global noncoverage diagnostics","scenario_hash":"930d3101e429eb33231c92e760b0899ec03e9827d06f603cbf7c0203bbc6c200","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"},{"index":9,"name":"map evidence is specific to an obligation's resources","scenario_hash":"9b75e170f7b19776f1985df48b0c178f3f9c18ba0f60f9254fb04037226f58b4","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"},{"index":10,"name":"canonical persistence and report share the domain assessment","scenario_hash":"320544637039cfbd0223c67adb200ea66b8eb55f5baa03587147f8902cecc8dc","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-31T01:15:13.071772Z"}]}
# acceptance-mutation-manifest-end

Feature: Normative observational hybrid coverage assessment
  Completed Phase 1 and Phase 2 artifacts project into the three source-spec
  denominators without changing either generation workflow or contacting a provider.

  Background:
    Given completed typed hybrid coverage source artifacts are available
    And hybrid coverage assessment makes no provider calls

  Scenario Outline: substituted reconciliation capability scope fails closed
    Given completed typed hybrid coverage source artifacts are available
    When hybrid coverage is attempted with substituted "<pin_field>"
    Then hybrid coverage rejects the substituted "<pin_field>"

    Examples:
      | pin_field                  |
      | capability_snapshot_digest |

  Scenario Outline: accepted confirmation projects through the normative matrices
    Given one confirmed coverage-bearing relation and matching legacy scenarios
    When hybrid coverage is assessed
    Then structural consideration contains <slot_rows> UCA slot row
    And taxonomy correspondence contains <obligation_rows> obligation row with disposition "<disposition>"
    And scenario realization contains <relation_rows> accepted relation with hybrid status "<generation_status>" and "<admission_status>"
    And every hybrid matrix row and diagnostic cell is traceable

    Examples:
      | slot_rows | obligation_rows | disposition | relation_rows | generation_status | admission_status |
      | 1         | 1               | satisfied   | 1             | not_attempted     | not_assessed     |

  Scenario Outline: real scenario envelopes become exact observations
    Given real admitted taxonomy and STPA scenario envelopes are available
    When the real scenario envelopes are adapted for hybrid assessment
    Then taxonomy observations contain <taxonomy_rows> exact obligation link
    And STPA observations contain <stpa_rows> exact slot ICA and EXEC link

    Examples:
      | taxonomy_rows | stpa_rows |
      | 1             | 1         |

  Scenario Outline: structural consideration keeps all reviewed slot outcomes
    Given structural inventory has one ICA slot, one justified N/A slot, and one unresolved slot
    When hybrid coverage is assessed
    Then structural consideration reports <ica_count> "ica", <na_count> "justified_na", and <unresolved_count> "unresolved"

    Examples:
      | ica_count | na_count | unresolved_count |
      | 1         | 1        | 1                |

  Scenario Outline: noncoverage correspondence stays an explicit finding
    Given one "<relation_kind>" proposal is explicitly "<decision>"
    When hybrid coverage is assessed
    Then taxonomy correspondence has no accepted coverage and gap "<gap_reason>"
    And the assessment retains finding "<finding_kind>"
    And scenario realization remains "<generation_status>" and "<admission_status>"

    Examples:
      | relation_kind            | decision  | gap_reason               | finding_kind              | generation_status | admission_status |
      | related_but_not_coverage | confirmed | related_but_not_coverage | related_but_not_coverage | not_attempted     | not_assessed     |

  Scenario Outline: structural inapplicability is an explicit reviewed decision
    Given one obligation has a reviewed structural inapplicability decision with other authoritative capability evidence
    When hybrid coverage is assessed
    Then taxonomy correspondence disposition is "<disposition>" with gap "<gap_reason>"

    Examples:
      | disposition              | gap_reason                              |
      | structurally_inapplicable | reviewed_structural_inapplicability     |

  Scenario Outline: inferred capability inventory cannot prove structural inapplicability
    Given one obligation has a structural inapplicability decision over "<completeness>" relevant capability inventory without other authoritative evidence
    When structural inapplicability is assessed against capability inventory
    Then structural inapplicability is rejected for "<completeness>" relevant capability inventory

    Examples:
      | completeness    |
      | inferred_partial |

  Scenario Outline: defective proposals remain global noncoverage diagnostics
    Given one proposal has a dangling resource-link identity
    When hybrid coverage is assessed
    Then the assessment retains one "<status>" proposal diagnostic
    And scenario realization contains <relation_rows> accepted relations

    Examples:
      | status   | relation_rows |
      | rejected | 0             |

  Scenario Outline: map evidence is specific to an obligation's resources
    Given the authoritative map has only a link unrelated to the obligation resources
    When hybrid coverage is assessed
    Then taxonomy correspondence disposition is "<disposition>" with gap "<gap_reason>"

    Examples:
      | disposition                    | gap_reason           |
      | unresolved_missing_resource_map | missing_resource_map |

  Scenario Outline: canonical persistence preserves the domain assessment
    Given reordered structural and scenario observations produce two assessments
    When the assessment is published as "<artifact_name>"
    Then both assessments have identical canonical bytes
    And the persisted assessment round-trips unchanged

    Examples:
      | artifact_name                   |
      | hybrid-coverage-assessment.yaml |

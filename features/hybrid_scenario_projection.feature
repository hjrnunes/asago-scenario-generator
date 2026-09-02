# mutation-stamp: sha256=e669ff7b1c947bfd4d8dd5f9dedd64da1f5dc6ace7a56c371931d3c6b50b5d4f
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-31T20:33:51.061765Z","feature_name":"Phase 4 complete hybrid scenario projection","feature_path":"features/hybrid_scenario_projection.feature","background_hash":"2bab7ba02c91d8838ad0783ed369381f28f71b2de6a1835a0f4a6b15b964db66","implementation_hash":"sha256:a4162e0580ed6f95e631046eb6e54a38d4dd95a78d44b77c64886117d5a2941e","scenarios":[{"index":0,"name":"one accepted relation produces one exact projection","scenario_hash":"6421280d015bdc7b3567500d0b5bd4f45acceb74dd8e4f45dd6bee8e80ac35d8","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-31T20:33:51.061765Z"},{"index":2,"name":"the fixed bridge table only accepts exact endpoint kinds","scenario_hash":"ccd7e4555be0a4ad613bc21e11b85799568b3bfaa3c52890fcb6723a8c703abb","mutation_count":28,"result":{"Total":28,"Killed":28,"Survived":0,"Errors":0},"tested_at":"2026-08-31T20:33:51.061765Z"},{"index":3,"name":"relation-local omissions remain typed and traceable","scenario_hash":"5a17a673b05c9eca585970fbbff3904f9c4b40b1c11eea40261ac5fba8e77f0b","mutation_count":32,"result":{"Total":32,"Killed":32,"Survived":0,"Errors":0},"tested_at":"2026-08-31T20:33:51.061765Z"},{"index":4,"name":"every exclusion reason is a closed typed contract value","scenario_hash":"683ab7a8ce4fb1e0e70d726a2d21a9e8e2eb81924f10eb8647858a6fd0b43976","mutation_count":19,"result":{"Total":19,"Killed":19,"Survived":0,"Errors":0},"tested_at":"2026-08-31T20:33:51.061765Z"},{"index":7,"name":"the adversarial projection corpus fails closed","scenario_hash":"ce5d0c26e9de9419e25e70ac463af9640ef31ed428ca84f3b6070dbbf3958da7","mutation_count":10,"result":{"Total":10,"Killed":10,"Survived":0,"Errors":0},"tested_at":"2026-08-31T20:33:51.061765Z"},{"index":10,"name":"malformed source graphs fail before composition","scenario_hash":"8e4349a2e23d8f17da7683b85e6bb0ddc5f2ad4ac6e930e3babfa23cd4887c97","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-31T20:33:51.061765Z"},{"index":11,"name":"source digest defects are fatal, not relation-local exclusions","scenario_hash":"4e7733d1d17064b8509bbbc7117ccc3ce77c93784b391040333d2be89273f3e4","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-31T20:33:51.061765Z"}]}
# acceptance-mutation-manifest-end

Feature: Phase 4 complete hybrid scenario projection
  Phase 4 combines already accepted taxonomy and STPA evidence into a
  deterministic projection set. It does not generate scenarios, execute
  tools, claim readiness, or contact a provider.

  Background:
    Given a complete typed hybrid projection authority fixture is available
    And the complete projection path has an offline provider and network guard

  Scenario Outline: one accepted relation produces one exact projection
    When the complete projection set is built
    Then the projection set has <projection_count> projection and <exclusion_count> exclusions
    And the projection retains the exact five-part relation identity
    And the projection has closed fields and independent review evidence
    And the offline guard records <network_calls> network calls and <provider_calls> provider calls

    Examples:
      | projection_count | exclusion_count | network_calls | provider_calls |
      | 1                | 0               | 0              | 0               |

  Scenario: two ICA identities sharing one EXEC remain distinct projections
    When two accepted ICA identities sharing one EXEC are composed
    Then the result contains two distinct relation and ICA identities sharing one EXEC
    And the offline guard records 0 network calls and 0 provider calls

  Scenario Outline: the fixed bridge table only accepts exact endpoint kinds
    When the projection is built with bridge "<bridge_kind>" to "<target_kind>"
    Then the bridge outcome is "<outcome>" with <projection_count> projection

    Examples:
      | bridge_kind              | target_kind    | outcome    | projection_count |
      | corrupts_process_model   | process_model  | projection | 1                |
      | delays_feedback          | feedback       | projection | 1                |
      | perturbs_control_action  | control_action | projection | 1                |
      | enables_unsafe_action    | uca            | projection | 1                |
      | enables_unsafe_action    | ica            | projection | 1                |
      | realizes_unsafe_outcome  | hazard         | projection | 1                |
      | realizes_unsafe_outcome  | loss           | projection | 1                |

  Scenario Outline: relation-local omissions remain typed and traceable
    When the projection request uses omission "<omission>"
    Then the omission is retained as "<reason>"
    And the offline guard records <network_calls> network calls and <provider_calls> provider calls

    Examples:
      | omission                 | reason                       | network_calls | provider_calls |
      | missing_relation         | relation_not_accepted       | 0             | 0              |
      | missing_review            | relation_unresolved         | 0             | 0              |
      | missing_materialization  | candidate_materialization_missing | 0          | 0              |
      | missing_bridge            | bridge_missing               | 0             | 0              |
      | unreviewed_bridge         | bridge_unreviewed            | 0             | 0              |
      | unknown_bridge_evidence   | bridge_not_authoritative     | 0             | 0              |
      | wrong_endpoint            | bridge_invalid_endpoint      | 0             | 0              |
      | missing_bridge_endpoint   | bridge_invalid_endpoint      | 0             | 0              |

  Scenario Outline: every exclusion reason is a closed typed contract value
    When the exclusion reason "<reason>" is inspected
    Then the exclusion reason is accepted by the closed contract

    Examples:
      | reason                              |
      | relation_not_accepted               |
      | relation_not_coverage               |
      | relation_unresolved                  |
      | relation_contradictory               |
      | challenge_outcome_not_correspondence |
      | obligation_not_applicable            |
      | candidate_materialization_missing    |
      | candidate_not_projectable             |
      | candidate_binding_mismatch            |
      | stpa_identity_missing                |
      | stpa_identity_mismatch               |
      | resource_link_mismatch               |
      | bridge_missing                       |
      | bridge_unreviewed                    |
      | bridge_not_authoritative             |
      | bridge_invalid_endpoint              |
      | bridge_duplicate                     |
      | ordering_cycle                       |
      | ordering_violation                   |

  Scenario: the exclusion vocabulary has no additions or omissions
    When the closed exclusion reason inventory is inspected
    Then the closed exclusion vocabulary matches the contract exactly

  Scenario: mixed projection and exclusion identities are fully accounted
    When a mixed projection and exclusion set is built through public contracts
    Then one projection and one distinct exclusion account for two relation identities
    And the mixed set survives canonical publication and reload

  Scenario Outline: the adversarial projection corpus fails closed
    When projection corpus case "<case>" is evaluated
    Then the corpus outcome is "<outcome>"
    And the Phase 2 matrices remain byte-identical

    Examples:
      | case                     | outcome                       |
      | substituted_candidate    | fatal                         |
      | nonprojectable_candidate | candidate_not_projectable     |
      | cross_candidate_binding  | fatal                         |
      | related_resource_relation | relation_not_coverage         |
      | full_source_pin_tamper   | fatal                         |

  Scenario: Phase 3 challenge history cannot promote a new projection
    When a Phase 3 challenge history is supplied
    Then projections and exclusions remain unchanged and no relation is promoted
    And Phase 3 history records 0 correspondence and 0 coverage changes
    And the offline guard records 0 network calls and 0 provider calls

  Scenario Outline: malformed source graphs fail before composition
    When the causal graph contains a "<failure>" failure
    Then the graph parser reports "<diagnostic>"

    Examples:
      | failure  | diagnostic                         |
      | duplicate | causal edge IDs must be unique     |
      | cycle     | invalid source/target kind        |
      | dangling  | dangling node                      |
      | order     | invalid source/target kind        |

  Scenario Outline: source digest defects are fatal, not relation-local exclusions
    When the projection request uses a tampered source plan
    Then the projection operation fails with "Digest mismatch"
    And the offline guard records <network_calls> network calls and <provider_calls> provider calls

    Examples:
      | network_calls | provider_calls |
      | 0             | 0              |

  Scenario: canonical output survives atomic publication and reload
    When the projection set is published and reloaded atomically
    Then the persisted artifact is "hybrid-scenario-projection-set.yaml" and evidence class is "normative_bookkeeping_fixture"

  Scenario: the committed projection artifact round-trips atomically
    When the committed projection artifact is loaded and published atomically
    Then the committed artifact round-trip has filename "hybrid-scenario-projection-set.yaml" and evidence class "normative_bookkeeping_fixture"
    And the offline guard records 0 network calls and 0 provider calls

  Scenario: input order cannot change canonical output
    When reordered projection authorities are built
    Then the reordered projection set has identical canonical bytes and digest

  Scenario: the committed fixture is bookkeeping evidence only
    When the committed normative projection fixture is loaded
    Then the fixture is labelled "normative_bookkeeping_fixture" and semantic claims are "not_allowed"

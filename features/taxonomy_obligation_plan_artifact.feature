# mutation-stamp: sha256=ffa0e3db6bfed08f5cd91a91f355b13f276535f6221598aa98264d8bd1d4ac09
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-28T17:07:34.549112Z","feature_name":"Taxonomy obligation plan artifact","feature_path":"features/taxonomy_obligation_plan_artifact.feature","background_hash":"ba5e424d8b121ffee446ad729b24ddb2198f58c040d25b8c8438dac3de6f61ae","implementation_hash":"sha256:c4f19be2db2791fb04d83688766e1ac0ded08f7b0166661fd2f02ecab3706103","scenarios":[{"index":0,"name":"YAML artifact records closed metadata and content digests","scenario_hash":"c1b8a80e22b51850f086c0bcdbfc782743378baf082b54b4150b6b85d8d005eb","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:07:34.549112Z"},{"index":1,"name":"YAML serialization is byte-stable for identical typed inputs","scenario_hash":"3a5e4d282b8edce88fe22f3f1bbbc12f58135f0fb835ddb57f7f6a67f2424222","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:07:34.549112Z"},{"index":2,"name":"YAML publication round-trips as a complete closed plan","scenario_hash":"17cf361822261f60c491f178479cae80d9b3ee9ae228e8ed4c8f76a4e7017504","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:07:34.549112Z"},{"index":3,"name":"YAML load rejects tampered persisted content","scenario_hash":"6133b6f5a7324dafe18a49492e7f12ae869fc6241bf6d47ea6863c7453a81547","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-28T17:07:34.549112Z"}]}
# acceptance-mutation-manifest-end

Feature: Taxonomy obligation plan artifact
  The authoritative obligation ledger is a closed, versioned YAML artifact.
  Its pins, content digests, rows, evidence, and summary are validated on
  load, and publication is atomic.

  Background:
    Given a typed taxonomy obligation input fixture is available
    And typed obligation planning makes no network or model calls

  Scenario Outline: YAML artifact records closed metadata and content digests
    Given the default normative typed planner inputs are ready
    When typed obligation planning runs
    Then the typed plan has closed schema metadata, pins, and content digests
    And the typed plan schema version is "<schema_version>"

    Examples:
      | schema_version               |
      | taxonomy-obligation-plan-v1  |

  Scenario Outline: YAML serialization is byte-stable for identical typed inputs
    Given the default normative typed planner inputs are ready
    When typed obligation planning runs
    And the typed "<serialization_format>" plan is serialized twice
    Then the typed "<expected_serialization_format>" artifacts are byte-identical

    Examples:
      | serialization_format | expected_serialization_format |
      | YAML                  | YAML                          |

  Scenario Outline: YAML publication round-trips as a complete closed plan
    Given the default normative typed planner inputs are ready
    When the typed plan is published atomically as "<publication_format>"
    Then the typed publication is named "<artifact_name>"
    And the typed publication round-trips without semantic loss
    And no typed partial plan file remains

    Examples:
      | publication_format | artifact_name                 |
      | YAML                | taxonomy-obligation-plan.yaml |

  Scenario Outline: YAML load rejects tampered persisted content
    Given the default normative typed planner inputs are ready
    When the typed plan is published atomically as "<publication_format>"
    And the published typed content is tampered in field "<tampered_field>" without updating the semantic digest
    And the published typed plan is loaded
    Then typed loading is rejected
    And the typed load error identifies a "<load_error>"

    Examples:
      | publication_format | tampered_field | load_error       |
      | YAML                | risk_ref       | Digest mismatch  |

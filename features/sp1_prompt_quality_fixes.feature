# mutation-stamp: sha256=8de072cc2b8b027af01559b35a93e4278715e8199e515600ebde766ebdffd47d
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:20:36.282338Z","feature_name":"SP1 Stage 1 prompt quality fixes","feature_path":"features/sp1_prompt_quality_fixes.feature","background_hash":"a7bc2ec77d4defafedaa1fd7aa346715ff439a68ae3d8c13e3a536e3d7527613","implementation_hash":"sha256:0add192b9537abe26430dffcfb20df90a433fb009b899f28502187db09285ab4","scenarios":[{"index":7,"name":"PQF-08 the retired monolithic Stage 1a templates are absent","scenario_hash":"b4ad7d9ffd712eaa1f5d5e523f6baf70974c862f01e23ebb1c822fdee7b3a3af","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:20:36.282338Z"},{"index":1,"name":"PQF-02 stage1a_risk_system.j2 contains Hazard specificity patterns","scenario_hash":"6c6c7ee197526c86acf38be9d9f3726f125aef966fd40d7e5050a6b71e8009a6","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:18:55.777927Z"},{"index":2,"name":"PQF-03 stage1a_risk_system.j2 contains Loss specificity sub-section","scenario_hash":"c248c282bc89a28deec0bd52179d57e2c2dc83f9425fa22fa28e8a7ad1a747a9","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:18:55.777927Z"},{"index":3,"name":"PQF-04 stage1a_risk_system.j2 contains Acronym expansion sub-section","scenario_hash":"9468f64cc36aabf54809ec1a9866c90c60ff69fcd746d4e5684a20442d8c6a04","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:18:55.777927Z"},{"index":4,"name":"PQF-05 stage1a_gap_system.j2 contains the gap analysis procedure","scenario_hash":"bb59593e5e9cc5620b53942776d1aac1eb924ad362efb3dfc1b4c63c286d8bcb","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:18:55.777927Z"},{"index":5,"name":"PQF-06 stage1a_risk_user.j2 contains the hazard grounding instruction","scenario_hash":"8511a19c2a25ce8da856e2089254ff3cae6565b8857162070b95ddda21a5630c","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:18:55.777927Z"},{"index":6,"name":"PQF-07 stage1a_gap_user.j2 drives the gap analysis from the capability profile","scenario_hash":"022aa76dbb585dee72b7cc9c974ce1659b20d64aad9b5d9cc3d8730e48ea6949","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:18:55.777927Z"},{"index":8,"name":"PQF-09 Stage 1a system templates render quality content without errors","scenario_hash":"f90c1c936b949853e7857696c7b61e7dcae2797122d8254298905ad63d2588dc","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:18:55.777927Z"},{"index":10,"name":"PQF-11 stage1a_risk_user.j2 preserves Jinja2 template variables","scenario_hash":"56b9baf76f8dc62288acce9f869dc27150e4f505eb178c4edd58709dc6f30afc","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:18:55.777927Z"},{"index":11,"name":"PQF-12 stage1a_risk_system.j2 preserves existing sections","scenario_hash":"a5c54edad11c3e8eee3f19ddd1cd8fcde82714464583f6d1ecdd547db12181c8","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:18:55.777927Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 Stage 1 prompt quality fixes
  Hazard specificity, loss specificity, and acronym expansion requirements
  live in stage1a_risk_system.j2 — the risk-derivation half of the split
  Stage 1a. The use-case gap analysis procedure moved to its own call and
  now lives in stage1a_gap_system.j2 / stage1a_gap_user.j2. Shared Jinja2
  method cards teach the distinction between stakeholder loss, hazardous
  system state, component cause, and preventive constraint.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # PQF-01
  Scenario: PQF-01 stage1a_risk_system.j2 Quality requirements section exists after Structural requirements
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "## Quality requirements"
    And the Quality requirements section appears after the Structural requirements section

  # PQF-02
  Scenario Outline: PQF-02 stage1a_risk_system.j2 contains Hazard specificity patterns
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "### Hazard specificity"
    And the template text contains "at least one specific component"
    And the template text contains "too generic"
    And the template text contains "<pattern_text>"

    Examples:
      | pattern_text                                      |
      | model output is manipulated                       |
      | component cause such as "the sensor fails."       |
      | name the affected function or data flow           |

  # PQF-03
  Scenario Outline: PQF-03 stage1a_risk_system.j2 contains Loss specificity sub-section
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "<loss_fragment>"

    Examples:
      | loss_fragment                |
      | ### Loss specificity         |
      | concrete consequences        |
      | not restatements of the risk |

  # PQF-04
  Scenario Outline: PQF-04 stage1a_risk_system.j2 contains Acronym expansion sub-section
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "<acronym_fragment>"

    Examples:
      | acronym_fragment                         |
      | ### Acronym expansion                    |
      | Personally Identifiable Information (PII) |
      | first expansion                          |
      | short form alone is acceptable           |

  # PQF-05
  Scenario Outline: PQF-05 stage1a_gap_system.j2 contains the gap analysis procedure
    Given the template stage1a_gap_system.j2 is loaded
    Then the template text contains "<gap_fragment>"

    Examples:
      | gap_fragment                    |
      | ## Gap analysis method          |
      | **Architectural components**    |
      | **Integration points**          |
      | **Domain-specific features**    |
      | **Stakeholder groups**          |
      | **Attack surfaces**             |
      | ### When no gaps exist          |
      | Do not invent gaps to fill a quota |

  # PQF-06
  Scenario Outline: PQF-06 stage1a_risk_user.j2 contains the hazard grounding instruction
    Given the template stage1a_risk_user.j2 is loaded
    Then the template text contains "<hazard_fragment>"

    Examples:
      | hazard_fragment                                          |
      | grounded in this specific system's architecture and domain |
      | concrete component, data flow, or integration point       |

  # PQF-07
  Scenario Outline: PQF-07 stage1a_gap_user.j2 drives the gap analysis from the capability profile
    Given the template stage1a_gap_user.j2 is loaded
    Then the template text contains "<gap_user_fragment>"

    Examples:
      | gap_user_fragment             |
      | ## Capability Profile Context |
      | capability codes              |
      | ## ID Numbering               |
      | L-{{ next_loss_num }}         |

  # PQF-08
  Scenario Outline: PQF-08 the retired monolithic Stage 1a templates are absent
    Then the prompts directory does not contain `<retired_template>`

    Examples:
      | retired_template  |
      | stage1a_system.j2 |
      | stage1a_user.j2   |

  # PQF-09
  Scenario Outline: PQF-09 Stage 1a system templates render quality content without errors
    Given the template <template_name> is loaded
    When the template is rendered with no variables
    Then the rendered text contains "<content_fragment>"

    Examples:
      | template_name          | content_fragment       |
      | stage1a_risk_system.j2 | Quality requirements   |
      | stage1a_risk_system.j2 | Hazard specificity     |
      | stage1a_risk_system.j2 | Loss specificity       |
      | stage1a_risk_system.j2 | Acronym expansion      |
      | stage1a_gap_system.j2  | Gap analysis method    |
      | stage1a_gap_system.j2  | Acronym expansion      |

  # PQF-10
  Scenario: PQF-10 stage1a_risk_user.j2 renders with use_case_text and risk_cards variables
    Given the template stage1a_risk_user.j2 is loaded
    When the template is rendered with use_case_text "A patient chatbot integrated with EHR systems" and an empty risk_cards list
    Then the rendered text contains "grounded in this specific system's architecture"
    And the rendered text contains "A patient chatbot integrated with EHR systems"

  # PQF-11
  Scenario Outline: PQF-11 stage1a_risk_user.j2 preserves Jinja2 template variables
    Given the template stage1a_risk_user.j2 is loaded
    Then the template text contains "<jinja_expression>"

    Examples:
      | jinja_expression      |
      | {{ use_case_text }}   |
      | {% if risk_cards %}   |

  # PQF-12
  Scenario Outline: PQF-12 stage1a_risk_system.j2 preserves existing sections
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "<section_header>"

    Examples:
      | section_header             |
      | {% include "_loss_analysis_method.j2" %} |
      | ## Structural requirements |
      | ## ID conventions          |
      | ## Quality requirements    |

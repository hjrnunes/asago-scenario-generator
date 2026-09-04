# mutation-stamp: sha256=c10f3c2f8ee6d0fe985da45a6b8bdd11b087de1714657d78553e7147c65e6d19
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:20:37.081139Z","feature_name":"SP1 prompt bug fixes","feature_path":"features/sp1_prompt_bug_fixes.feature","background_hash":"a7bc2ec77d4defafedaa1fd7aa346715ff439a68ae3d8c13e3a536e3d7527613","implementation_hash":"sha256:680439961db09b76ceb5e49f94a8b4801729a8936650e42e9086a4da8910a450","scenarios":[{"index":7,"name":"SP1 prompt bug fixes-08 templates retired by the restructures are absent","scenario_hash":"88b9db68817210f5abf9f84bfef33a41e51e017f75fb892200994cda4299013f","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:20:37.081139Z"},{"index":0,"name":"SP1 prompt bug fixes-01 Stage 1a grounds losses and hazards in the use case","scenario_hash":"2e2bcb90a6be04e89d46aaf64daca3a041128583e6b88862659a36dc5a5ff212","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:06:23.632458Z"},{"index":1,"name":"SP1 prompt bug fixes-02 Stage 1b prohibits hallucinated tools and entry points","scenario_hash":"1e66aa44435ec72db669880a332584ca2287ffe7a1095af9a9ae9b714a1bf2cd","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:06:23.632458Z"},{"index":2,"name":"SP1 prompt bug fixes-03 Stage 2 Call 3 defines coordination links","scenario_hash":"c41d7f6e3d964bceb784898c5ef0caf4f3263654f04c2b70ffa64e4b8719231e","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:06:23.632458Z"},{"index":3,"name":"SP1 prompt bug fixes-04 Call 2a requires zone-driven responsibilities","scenario_hash":"5ae2e7c2a67738bf0d578a19c9ae8bfcb87d3b2166f583bab1e4a32852af5458","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:06:23.632458Z"},{"index":4,"name":"SP1 prompt bug fixes-05 Call 2b requires discrete control actions","scenario_hash":"3684b73677bf58f3b565840979f9ba3d6c46441e5bdd58217df67b7b1fa5fd9b","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:06:23.632458Z"},{"index":5,"name":"SP1 prompt bug fixes-06 updated system prompts render successfully","scenario_hash":"bcf71d44f5ceff783a3d79272e6ad1e12e89728739764992ee4e13e12050b8ec","mutation_count":10,"result":{"Total":10,"Killed":10,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:06:23.632458Z"},{"index":6,"name":"SP1 prompt bug fixes-07 existing prompt sections remain present","scenario_hash":"0376390bf098e2ba0dc4b75fdc0eb7acccc59dac6e438ca4de67044c8765bf4e","mutation_count":10,"result":{"Total":10,"Killed":10,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:06:23.632458Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 prompt bug fixes
  Stage 1 prompts constrain generated content to the use case, and Stage 2
  prompts require complete, discrete control-structure responsibilities and
  connections. After the Stage 1a split and the Stage 2 restructure these
  behaviors are spread across more templates: Stage 1a grounding lives in
  stage1a_risk_system.j2, zone-driven responsibilities in
  stage2_call2a_system.j2, discrete control actions in
  stage2_call2b_system.j2, and coordination links in
  stage2_call3_system.j2. These behaviors are specified at the Jinja2
  prompt boundary.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # SP1 prompt bug fixes-01
  Scenario Outline: SP1 prompt bug fixes-01 Stage 1a grounds losses and hazards in the use case
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "<grounding_text>"

    Examples:
      | grounding_text                                                  |
      | Every loss must cite its source risk IDs in `source_risk_cards`. |
      | Each hazard MUST name at least one specific component            |

  # SP1 prompt bug fixes-02
  Scenario Outline: SP1 prompt bug fixes-02 Stage 1b prohibits hallucinated tools and entry points
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "<grounding_text>"

    Examples:
      | grounding_text                                                                         |
      | every tool must be explicitly mentioned or directly implied by the use-case description |
      | every KC code, entry point, and tool must be traceable to a specific capability          |

  # SP1 prompt bug fixes-03
  Scenario Outline: SP1 prompt bug fixes-03 Stage 2 Call 3 defines coordination links
    Given the template stage2_call3_system.j2 is loaded
    Then the template text contains "<coordination_text>"

    Examples:
      | coordination_text                                                                                       |
      | Coordination links are required when                                      |
      | explicit lateral control or information                                   |
      | responsibilities overlap or leave a decision boundary ambiguous           |
      | actions affect the same controlled process or resource                     |
      | actions can conflict or must occur in a defined order                      |
      | One controller needs state or outcome information held by the other       |

  # SP1 prompt bug fixes-04
  Scenario Outline: SP1 prompt bug fixes-04 Call 2a requires zone-driven responsibilities
    Given the template stage2_call2a_system.j2 is loaded
    Then the template text contains "<zone_rule>"

    Examples:
      | zone_rule                                                                                                  |
      | Check the capability profile's active zones                                                                |
      | When `tool_execution` is active: require a responsibility governing tool parameter validation and action selection |
      | When `memory` is active: require a responsibility for context management and memory lifecycle               |
      | When `hitl` is true: require a responsibility for escalation and human oversight                            |
      | When `inter_agent` is active: require a responsibility for inter-agent coordination and message validation  |
      | This is a hard requirement, not a suggestion                                                               |

  # SP1 prompt bug fixes-05
  Scenario Outline: SP1 prompt bug fixes-05 Call 2b requires discrete control actions
    Given the template stage2_call2b_system.j2 is loaded
    Then the template text contains "<discrete_ca_rule>"

    Examples:
      | discrete_ca_rule                                                                     |
      | Each CA is a single discrete action                                                   |
      | Split composite actions into separate CAs                                            |
      | approve or reject request                                                            |
      | CA-X-1 Approve request                                                               |
      | CA-X-2 Reject request                                                                 |
      | A CA containing "or", "and", or similar conjunctions is likely composite and should be split |

  # SP1 prompt bug fixes-06
  Scenario Outline: SP1 prompt bug fixes-06 updated system prompts render successfully
    Given the template <template_name> is loaded
    When the template is rendered with no variables
    Then the rendered text contains "<rendered_text>"

    Examples:
      | template_name           | rendered_text                        |
      | stage1a_risk_system.j2  | Every loss must cite its source risk IDs |
      | stage1b_system.j2       | every tool must be explicitly mentioned  |
      | stage2_call2a_system.j2 | Check the capability profile's active zones |
      | stage2_call2b_system.j2 | Each CA is a single discrete action   |
      | stage2_call3_system.j2  | Coordination links are required when  |

  # SP1 prompt bug fixes-07
  Scenario Outline: SP1 prompt bug fixes-07 existing prompt sections remain present
    Given the template <template_name> is loaded
    Then the template text contains "<section_header>"

    Examples:
      | template_name           | section_header                |
      | stage1a_risk_system.j2  | ## Quality requirements       |
      | stage1b_system.j2       | ## Rules                      |
      | stage2_call2a_system.j2 | ## ID conventions             |
      | stage2_call2b_system.j2 | ## ID conventions             |
      | stage2_call3_system.j2  | ## Connection integrity checks |

  # SP1 prompt bug fixes-08
  Scenario Outline: SP1 prompt bug fixes-08 templates retired by the restructures are absent
    Then the prompts directory does not contain `<retired_template>`

    Examples:
      | retired_template       |
      | stage1a_system.j2      |
      | stage1a_user.j2        |
      | stage2_call2_system.j2 |
      | stage2_call2_user.j2   |

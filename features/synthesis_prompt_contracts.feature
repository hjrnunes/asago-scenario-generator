# mutation-stamp: sha256=d10c4b1b972998675b396e980e9b614304496ef38a3627fd5eae0671b60c75b0
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-09-01T16:35:07.894737Z","feature_name":"Meaning survives obligation-aware STPA model calls","feature_path":"features/synthesis_prompt_contracts.feature","background_hash":"a79b6104fef11d6d32c40057ce0473f84c2625a2311588783bf6ca5e9de16ae4","implementation_hash":"sha256:cf01bd2248ea9560075e7fcb7013d731bc9299f63039bf4f16519df7427b0436","scenarios":[{"index":0,"name":"Control action meaning and ownership cannot be silently repaired","scenario_hash":"2b7a09cdc440f6060bf6ad2cee425c495dc1fe960db67475ce95dc622e5f3ed9","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"},{"index":1,"name":"Routing prompts contain only explained decision context","scenario_hash":"c7522922f0c9f4132929750b8d83fb745a9b0901d4d98d7d6d6ed33a255f9913","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"},{"index":2,"name":"Oversized routing batches are split before dispatch","scenario_hash":"b4b27e9df814cc154b0c3fd12e9824202bc06d96f7388f918c793069d5283417","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"},{"index":3,"name":"One oversized routing item never reaches the provider","scenario_hash":"7aa1cb422220558310efb35a8a6d009ef620c333753a0190d673f07151eabdd7","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"},{"index":4,"name":"A route must use a constraint that governs its hazard","scenario_hash":"e829957a695e2a769ac8cbe84983595480fee1db4b14b6d50a4379ad46189a50","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"},{"index":5,"name":"Obligation-aware ICA remains unsafe-control analysis","scenario_hash":"f867091150463f10a5207f3a74c0410b1a51f7d964e253167ede63a2acf640bf","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"},{"index":6,"name":"A causal scenario cannot discard its accepted meaning","scenario_hash":"5fcd39608394139d1594dcfd2b910525027fd196587c1c9078663cb5dc9d68c3","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"},{"index":7,"name":"A causal scenario requires declared causal evidence","scenario_hash":"4a7274a81580baa9aae446654242fe2afeb90de4c2f965236232c892db91579b","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"},{"index":8,"name":"Gherkin cannot choose an unrelated global constraint","scenario_hash":"e5b91c981233dbf44d1aec9029ba4126848b9e247db78890aa9b22ffcb9d60ff","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"},{"index":9,"name":"Provider Gherkin headings are rendered exactly once","scenario_hash":"287f1e95eb7ad867250322cd8c063a156e8d05d3571a7cd72c86a7ec2fbff02d","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"},{"index":10,"name":"Coordination ICAs retain their exact structural path","scenario_hash":"2170390ff87b542f9182ef01354699ec2a4c459d4f3b39d8fc8aead93038c63b","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T16:35:07.894737Z"}]}
# acceptance-mutation-manifest-end

Feature: Meaning survives obligation-aware STPA model calls
  Taxonomy concerns focus STPA analysis without filling prompts with audit
  metadata or allowing later stages to replace the accepted STPA meaning.

  Background:
    Given the captured synthesis prompt regressions are available

  Scenario Outline: Control action meaning and ownership cannot be silently repaired
    When the malformed combined control-action response is validated
    Then the response publication status is "<publication_status>"
    And control-action ownership is not inferred from response order

    Examples:
      | publication_status          |
      | rejected_without_placeholder |

  Scenario Outline: Routing prompts contain only explained decision context
    When a provider obligation question is projected
    Then audit-only provenance is absent from the provider question
    And every selectable routing identity has a plain-language description
    And the obligation handle instruction is "<handle_instruction>"

    Examples:
      | handle_instruction           |
      | copy unchanged opaque handle |

  Scenario Outline: Oversized routing batches are split before dispatch
    When a canonical routing batch exceeds the configured prompt budget
    Then the routing batch ordering is "<ordering>"

    Examples:
      | ordering        |
      | canonical_order |

  Scenario Outline: One oversized routing item never reaches the provider
    When one routing item cannot fit the configured prompt budget
    Then prompt budget exceeded is retained as a local diagnostic
    And the provider call count is <provider_calls>

    Examples:
      | provider_calls |
      | 0              |

  Scenario Outline: A route must use a constraint that governs its hazard
    When the captured mismatched hazard and constraint are validated
    Then the targeted route disposition is "<disposition>"
    And no global constraint is substituted

    Examples:
      | disposition |
      | unresolved  |

  Scenario Outline: Obligation-aware ICA remains unsafe-control analysis
    When the captured safeguard is proposed as an ICA
    Then the safeguard is rejected as unsafe-control behavior
    And the unsafe-control type set is "<uca_types>"

    Examples:
      | uca_types                                                |
      | NOT_PROVIDED, INCORRECT, WRONG_TIMING, WRONG_DURATION   |

  Scenario Outline: A causal scenario cannot discard its accepted meaning
    When the captured drifting scenario response is compiled
    Then the source ICA hazard loss and constraint remain authoritative
    And the published scenario-realization count is <published_scenarios>

    Examples:
      | published_scenarios |
      | 0                   |

  Scenario Outline: A causal scenario requires declared causal evidence
    When the captured response has no causal factors
    Then scenario generation disposition is "<disposition>"
    And no narrative attack tree or Gherkin is published

    Examples:
      | disposition |
      | unresolved  |

  Scenario Outline: Gherkin cannot choose an unrelated global constraint
    Given an EHR integrity hazard and an unrelated privacy constraint
    When the scenario Gherkin constraint is resolved
    Then governing constraint resolution is "<resolution>"

    Examples:
      | resolution   |
      | fails_closed |

  Scenario Outline: Provider Gherkin headings are rendered exactly once
    When a provider Gherkin response contains renderer-owned Feature and Scenario headings
    Then the normalized provider titles are "<normalized_titles>"
    And the rendered feature has exactly one Feature heading
    And the rendered feature has exactly one Scenario heading

    Examples:
      | normalized_titles                                      |
      | Safe payment orchestration, Tool-chain exfiltration    |

  Scenario Outline: Coordination ICAs retain their exact structural path
    When a coordination ICA is projected for scenario generation
    Then the retained coordination identities are "<coordination_path>"
    And no coordination identity is treated as a responsibility

    Examples:
      | coordination_path               |
      | CL-1, CM-1, RESP-1, RESP-2      |

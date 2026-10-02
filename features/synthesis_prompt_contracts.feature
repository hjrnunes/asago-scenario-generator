# mutation-stamp: sha256=bd9550b6179eb059013a8c566b10b79dbb085573662a5a99714a6429b62b4896
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-09-01T18:09:31.140603Z","feature_name":"Meaning survives obligation-aware STPA model calls","feature_path":"features/synthesis_prompt_contracts.feature","background_hash":"a79b6104fef11d6d32c40057ce0473f84c2625a2311588783bf6ca5e9de16ae4","implementation_hash":"sha256:cf01bd2248ea9560075e7fcb7013d731bc9299f63039bf4f16519df7427b0436","scenarios":[{"index":0,"name":"Control action meaning and ownership cannot be silently repaired","scenario_hash":"2b7a09cdc440f6060bf6ad2cee425c495dc1fe960db67475ce95dc622e5f3ed9","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":1,"name":"Routing prompts contain only explained decision context","scenario_hash":"c7522922f0c9f4132929750b8d83fb745a9b0901d4d98d7d6d6ed33a255f9913","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":2,"name":"Oversized routing batches are split before dispatch","scenario_hash":"b4b27e9df814cc154b0c3fd12e9824202bc06d96f7388f918c793069d5283417","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":3,"name":"One oversized routing item never reaches the provider","scenario_hash":"7aa1cb422220558310efb35a8a6d009ef620c333753a0190d673f07151eabdd7","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":4,"name":"A route must use a constraint that governs its hazard","scenario_hash":"e829957a695e2a769ac8cbe84983595480fee1db4b14b6d50a4379ad46189a50","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":5,"name":"Obligation-aware ICA remains unsafe-control analysis","scenario_hash":"f867091150463f10a5207f3a74c0410b1a51f7d964e253167ede63a2acf640bf","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":6,"name":"The compiler owns the ICA deviation category","scenario_hash":"bf3b1d04153fe803bf8ed85c67d5117bd8d9acc40dc54bcf57343b355daa108d","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":7,"name":"A causal scenario cannot discard its accepted meaning","scenario_hash":"5fcd39608394139d1594dcfd2b910525027fd196587c1c9078663cb5dc9d68c3","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":8,"name":"A causal scenario requires declared causal evidence","scenario_hash":"4a7274a81580baa9aae446654242fe2afeb90de4c2f965236232c892db91579b","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":9,"name":"Gherkin cannot choose an unrelated global constraint","scenario_hash":"e5b91c981233dbf44d1aec9029ba4126848b9e247db78890aa9b22ffcb9d60ff","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":10,"name":"Provider Gherkin headings are rendered exactly once","scenario_hash":"287f1e95eb7ad867250322cd8c063a156e8d05d3571a7cd72c86a7ec2fbff02d","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":11,"name":"Coordination ICAs retain their exact structural path","scenario_hash":"2170390ff87b542f9182ef01354699ec2a4c459d4f3b39d8fc8aead93038c63b","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":12,"name":"Stage 5 compiles local causal handles into exact structural sources","scenario_hash":"b895501514d455d7f7afb865858aa2ccfa9e282882be6fc4ff842f35f419c32f","mutation_count":1,"result":{"Total":1,"Killed":1,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"},{"index":13,"name":"Unsupported active access cannot become a scenario","scenario_hash":"b30e5bb411c440319ee2d7fa7f4ada668ef6dcf43cdaada652a4a1cf65503d9a","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-09-01T18:09:31.140603Z"}]}
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

  Scenario Outline: Obligation prompts are maintained as strict Jinja templates
    When the obligation-aware prompt templates are inspected
    Then all obligation prompt pairs render through Jinja
    And missing template input fails before provider dispatch with "<failure>"

    Examples:
      | failure          |
      | StrictUndefined  |

  Scenario Outline: Risk alignment is separate from mechanism plausibility
    When a plausible taxonomy mechanism is assessed as mismatching its reviewed risk
    Then the ordinary STPA finding remains available
    And the obligation stop reason is "<stop_reason>"
    And the obligation addressed count is <addressed>

    Examples:
      | stop_reason          | addressed |
      | risk_pattern_mismatch | 0         |

  Scenario Outline: An adjacent safeguard cannot prove the attack mechanism
    When the structural routing guidance is inspected
    Then the prompt distinguishes authentication failure from "<mechanism>"
    And a nearby safeguard cannot substitute for mechanism evidence

    Examples:
      | mechanism           |
      | poisoned tool output |

  Scenario Outline: Focused mechanism verification preserves ordinary STPA findings
    When a selected STPA path is classified as an adjacent control
    Then the ordinary STPA finding remains available
    And the obligation stop reason is "<stop_reason>"
    And the obligation addressed count is <addressed>

    Examples:
      | stop_reason                    | addressed |
      | mechanism_path_unsubstantiated | 0         |

  Scenario Outline: Provider transport success is not stage success
    When a provider returns a response that fails typed parsing
    Then provider response received is true
    And semantic validation passed is false
    And the terminal provider error is "<error_code>"

    Examples:
      | error_code                |
      | provider_contract_failure |

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

  Scenario Outline: The compiler owns the ICA deviation category
    When an ICA provider supplies one deviation for a NOT_PROVIDED slot
    Then the compiled ICA behavior contains "<behavior>"
    And the model-facing ICA schema exposes one plain deviation string
    And the model-facing ICA schema permits exactly one governing constraint
    And finding relevance compares subject operation object and effect

    Examples:
      | behavior         |
      | fails to provide |

  Scenario Outline: A taxonomy finding does not establish its attack mechanism
    When a taxonomy mechanism is routed to a related ICA
    Then the ICA remains a mechanism-neutral unsafe-control finding
    And the obligation is provenance rather than causal evidence
    And the taxonomy mechanism requires "<required_support>" before scenario use

    Examples:
      | required_support      |
      | independent evidence  |

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

  Scenario Outline: Coordination ICAs retain their exact structural path
    When a coordination ICA is projected for scenario generation
    Then the retained coordination identities are "<coordination_path>"
    And no coordination identity is treated as a responsibility

    Examples:
      | coordination_path               |
      | CL-1, CM-1, RESP-1, RESP-2      |

  Scenario Outline: Stage 5 compiles local causal handles into exact structural sources
    When a coordination ICA is projected for scenario generation
    And its Stage 5 provider response selects local causal handle cause_1
    Then the compiled causal source is "<causal_source>"
    And every selected defender belief has a compiled vulnerability
    And no coordination controller or local handle is published as a causal source
    And the explicit bounded assumption is preserved

    Examples:
      | causal_source |
      | PM-1-1        |

  # STPA-ICA-VERIFICATION
  Scenario: A supported final ICA remains eligible after independent verification
    Given deterministic final ICA verification fixtures are available
    When a supported final ICA is verified
    Then the final ICA verifier call count is 1
    And the supported ICA disposition is "supported"
    And the verified ICA remains eligible

  Scenario: A contradictory ICA gets one bounded correction and separate recheck
    Given deterministic final ICA verification fixtures are available
    When a contradictory final ICA is corrected and rechecked
    Then the final ICA verifier call count is 2
    And the correction and recheck are separate attempts
    And the corrected ICA disposition is "supported"

  Scenario: A failed recheck stays distinct while a sibling ICA survives
    Given deterministic final ICA verification fixtures are available
    When one final ICA recheck fails while its sibling is supported
    Then the final ICA verifier call count is 2
    And one final ICA has provider-failure disposition
    And the supported sibling remains eligible
    And the final ICA provider failure is recorded separately
    And the rejected ICA with a failed repair is not eligible

  Scenario: An N/A ICA does not invoke the independent verifier
    Given deterministic final ICA verification fixtures are available
    When an N/A final ICA slot is verified
    Then the final ICA verifier call count is 0
    And the N/A slot remains unchanged

  Scenario: Provider routing cannot choose locally derived mapping strength
    Given deterministic final ICA verification fixtures are available
    When the routing provider attempts to return mapping strength
    Then the provider-derived routing field is rejected

  Scenario: A supported ICA reaches Phase 2 without automatic coverage confirmation
    When the supported ICA attribution canary is executed
    Then the attribution canary status is "supported_unreviewed"
    And the canary realization count is 1
    And the canary Phase 2 status is "awaiting_evidence"

  Scenario: A mismatched ICA remains accounted but receives no realization credit
    When the mismatched ICA attribution canary is executed
    Then the attribution canary status is "mismatched_no_credit"
    And the canary realization count is 0
    And the canary Phase 2 proposal count is 0

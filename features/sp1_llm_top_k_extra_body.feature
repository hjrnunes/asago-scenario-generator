# mutation-stamp: sha256=39db8af7c3cd9f48637e3d59d1fa69023f6d8c12d653ec5ef192dd151b9a2b99
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T14:09:02.843538Z","feature_name":"SP1 LLM client \u2014 top_k routed through extra_body","feature_path":"features/sp1_llm_top_k_extra_body.feature","background_hash":"8c1eb48fc8bd071218b76792ecf215afc4f38c9c765e97e25141e8df387324a1","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: SP1 LLM client — top_k routed through extra_body
  The LLMClient passes top_k via the OpenAI SDK's extra_body parameter
  instead of as a top-level kwarg, because top_k is not a standard OpenAI
  API parameter and raises TypeError on non-OpenAI providers like
  OpenRouter. Standard OpenAI parameters (temperature, max_completion_tokens,
  top_p) remain as top-level kwargs.

  Background:
    Given the STPA infra LLM module is importable

  # LLM-TOPK-01
  Scenario: LLM-TOPK-01 top_k is routed through extra_body not as top-level kwarg
    Given an LLMClient constructed with base_url http://test:8080 and top_k 40
    When the client builds extra kwargs
    Then the kwargs do not contain a top-level top_k key
    And the kwargs contain an extra_body key
    And the extra_body dict contains top_k with value 40

  # LLM-TOPK-02
  Scenario: LLM-TOPK-02 top_p remains a top-level kwarg
    Given an LLMClient constructed with base_url http://test:8080 and top_p 0.9 and top_k 40
    When the client builds extra kwargs
    Then the kwargs contain a top-level top_p key with value 0.9
    And the top_p key is not inside extra_body

  # LLM-TOPK-03
  Scenario: LLM-TOPK-03 temperature and max_completion_tokens remain top-level kwargs
    Given an LLMClient constructed with base_url http://test:8080 and top_k 40
    When the client builds extra kwargs with temperature 0.7 and max_completion_tokens 2048
    Then the kwargs contain a top-level temperature key with value 0.7
    And the kwargs contain a top-level max_completion_tokens key with value 2048

  # LLM-TOPK-04
  Scenario: LLM-TOPK-04 top_k None means no extra_body
    Given an LLMClient constructed with base_url http://test:8080 and top_k None
    When the client builds extra kwargs
    Then the kwargs do not contain an extra_body key
    And the kwargs do not contain a top-level top_k key

  # LLM-TOPK-05
  Scenario: LLM-TOPK-05 top_k value forwarded without losing the raw structured response
    Given an LLMClient constructed with base_url http://test:8080 and top_k 40
    When the client completes a structured request with a response format
    Then the create call includes extra_body with top_k 40
    And the create call does not include a top-level top_k kwarg

  # LLM-TOPK-06
  Scenario: LLM-TOPK-06 top_k value forwarded in extra_body for unstructured create calls
    Given an LLMClient constructed with base_url http://test:8080 and top_k 40
    When the client completes an unstructured request
    Then the create call includes extra_body with top_k 40
    And the create call does not include a top-level top_k kwarg

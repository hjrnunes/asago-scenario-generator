# mutation-stamp: sha256=4c0deb1c2bc7e840d5dfedb34fbca66783ef586a58f1c77e9daa080ff0cdc950
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T11:50:39.571058Z","feature_name":"Stage 1b Capability Profile Revision","feature_path":"features/stage1-split-reorder/stage1b_revision.feature","background_hash":"3ce4ce047c4808724701c3d5045ba13b821552e7e8a42e47ce48aacf8a16b50b","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

# stage1b-revision
Feature: Stage 1b Capability Profile Revision
  The Stage 1b (capability profile inference) prompt is revised:
    - The full KC taxonomy is included as a reference table.
    - Loss-analysis context is removed (1b has zero dependency on 1a).
    - Schneider zones are removed as LLM output (computed from KC codes).
    - The rigid entry-point checklist is replaced by KC-driven reasoning.
    - STPA-Sec terminology is dropped.
  The Stage1Profile model drops `has_persistent_memory`, `multi_agent`,
  and `hitl` as direct LLM-inferred fields — they are computed from
  `kc_subcodes` on the CapabilityProfile.

  Background:
    Given a use-case file and a risk-extraction file are available
    And an LLM endpoint is configured

  # stage1b-revision-stage1-profile-no-bool-fields
  Scenario: Stage1Profile model does not declare boolean capability fields
    Then the `Stage1Profile` model does not declare `has_persistent_memory`
    And the `Stage1Profile` model does not declare `multi_agent`
    And the `Stage1Profile` model does not declare `hitl`

  # stage1b-revision-kc-taxonomy-in-prompt
  Scenario: The stage1b system prompt includes the KC taxonomy
    Then the prompt template `stage1b_system.j2` contains the text `KC1 — Language Models`
    And the prompt template `stage1b_system.j2` contains the text `KC6 — Operational Environment`
    And the prompt template `stage1b_system.j2` contains the text `KCX — Extended Capabilities`

  # stage1b-revision-no-loss-context-in-prompt
  Scenario: The stage1b user prompt does not include loss-analysis context
    Then the prompt template `stage1b_user.j2` does not contain `loss_analysis`
    And the prompt template `stage1b_user.j2` does not contain `all_losses`
    And the prompt template `stage1b_user.j2` does not contain `security_constraints`

  # stage1b-revision-no-stpa-terminology
  Scenario: The stage1b system prompt does not mention STPA-Sec
    Then the prompt template `stage1b_system.j2` does not contain `STPA`

  # stage1b-revision-no-zones-output-in-prompt
  Scenario: The stage1b system prompt does not request zones_active as output
    Then the prompt template `stage1b_system.j2` does not contain `zones_active`

  # stage1b-revision-no-entry-point-checklist
  Scenario: The stage1b system prompt does not contain the five-category checklist
    Then the prompt template `stage1b_system.j2` does not contain `User input surfaces`
    And the prompt template `stage1b_system.j2` does not contain `Entry point category checklist`

# mutation-stamp: sha256=992e16532670b8bddca91d0fdf4d3530d327a7c6750f8951681477dd5e968df2
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T00:39:27.402779Z","feature_name":"SP1 KC sub-code display in serialized YAML","feature_path":"features/sp1_kc_subcode_display.feature","background_hash":"c6758f34f8b72f643e17dc8bc4241e4bd73160d17515accef566c9ee416f85f7","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: SP1 KC sub-code display in serialized YAML
  The capability-profile.yaml artifact should include a human-readable
  companion field kc_subcodes_display that maps each KC sub-code to its
  description. The original kc_subcodes list[str] field is unchanged.
  Downstream consumers continue reading kc_subcodes as list[str]; the
  display field is purely additive for human readability. The injection
  happens after model_dump() but before YAML serialization in both the
  STPA pipeline (write_yaml) and the existing pipeline (io.py) paths.

  Background:
    Given the capability profile module is importable
    And a valid CapabilityProfile with kc_subcodes KC1.1, KCX-PRIV, and KC5.1
    And the capability profile is serialized to capability-profile.yaml via the STPA write_yaml path

  # KCDisp-01
  Scenario: KCDisp-01 capability-profile.yaml contains kc_subcodes_display field
    Then the YAML file contains a kc_subcodes_display field
    And kc_subcodes_display is a dict

  # KCDisp-02
  Scenario: KCDisp-02 OWASP KC codes map to their descriptions from KC_SUBCODE_NAMES
    Then kc_subcodes_display contains key KC1.1 mapped to Large Language Model (LLM)
    And kc_subcodes_display contains key KC5.1 mapped to Flexible libraries / SDK

  # KCDisp-03
  Scenario: KCDisp-03 KCX extension codes map to their descriptions from KCX_SUBCODES
    Then kc_subcodes_display contains key KCX-PRIV mapped to a description containing privilege

  # KCDisp-04
  Scenario: KCDisp-04 unknown codes fall back to the code string itself
    Given a valid CapabilityProfile with kc_subcodes KC1.1 and UNKNOWN-CODE
    When the capability profile is serialized to capability-profile.yaml via the STPA write_yaml path
    Then kc_subcodes_display contains key UNKNOWN-CODE mapped to UNKNOWN-CODE

  # KCDisp-05
  Scenario: KCDisp-05 kc_subcodes list[str] field is unchanged after serialization
    Then the YAML file contains a kc_subcodes field
    And kc_subcodes is a list containing KC1.1, KCX-PRIV, and KC5.1

  # KCDisp-06
  Scenario: KCDisp-06 reloading the YAML as CapabilityProfile ignores the extra display field
    When the YAML file is loaded as a CapabilityProfile
    Then the loaded model has kc_subcodes KC1.1, KCX-PRIV, and KC5.1
    And no validation error is raised

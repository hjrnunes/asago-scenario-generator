# STPA relationship checklist

This checklist lists the relationships between STPA elements and, for each,
where the producer enforces it. It uses the AppSTPA ontology `safety.owl`
(Carniel, Bezerra and Hirata, "An Ontology-Based Approach to Aid STPA
Analysis", IEEE Access, 2023) as a specification checklist, and the STPA
Handbook (Leveson and Thomas, 2018) to decide which relationships STPA
requires. Section references (§) are to the Handbook's Chapter 2: §2.2
defines the purpose of the analysis (losses, hazards, system-level
constraints), §2.3 models the control structure, §2.4 identifies unsafe
control actions, and §2.5 identifies loss scenarios.

The ontology is used as a list, not as OWL with a reasoner. 118 of the
ontology's 120 class restrictions are existential (`some`): each says that
every instance of the class has at least one qualifying connection. Under
the open world assumption a reasoner does not report a missing connection;
it lets the connected individual stay unnamed, so it cannot flag the gaps
this checklist is about. The other two restrictions are
`minQualifiedCardinality 1` on a loss scenario's causal factors. Whether a
connection holds for every analysis is a separate question, which the
**STPA** column answers from the Handbook: some restrictions the ontology
states for every instance hold only for some systems.

The report-only checks in `stpa/spec_diagnostics.py` cover some rows; they
are marked in the Diagnostics column. None of them is a gate. Counts and a
hand-checked sample on saved runs are in
[spec-diagnostics-counts.md](../development/spec-diagnostics-counts.md).

## Reading the table

**STPA** is *required* when the Handbook makes the relationship part of every
analysis, and *possible* when it holds only for some systems or is one of
several alternatives (a scenario cause, an optional actuator or sensor, a
multi-level hierarchy). The producer models every controller as a
responsibility (`RESP-N`) of the assistant, with no hierarchy levels, no
actuators and no sensors, so most *possible* rows have no producer field.

**Layers.**

- **Wire**: decoding and validating a model response. Stage 1a is
  `stpa/system_model/loss_analysis.py` and `loss_analysis_gates.py`; Stage 2
  is `stpa/system_model/control_structure.py` (Calls 1, 2a, 2b, 3); ICA slot
  filling is `stpa/obligation_aware/provider.py` and `slot_filling.py`;
  scenarios are `stpa/scenario_prod/`.
- **Load**: validating a saved artifact with its pydantic model
  (`stpa/models/`), which also runs on every `model_validate` in the
  pipeline.
- **Revision**: the Stage 2 critic and its revision
  (`stpa/system_model/critic.py`), and the obligation-aware structural
  revision (`stpa/obligation_aware/revision.py`).
- **Final artifact**: the final control structure and loss analysis, their
  publication, and the report.

**Enforcement.** *hard* rejects: it raises, requests a correction, or refuses
publication. *warning* records and proceeds. *absent* means no code checks
it.

**Shared mechanics behind several cells** (paths are under
`src/asago_scenario_generator/`):

- *Stage 2 correction.* Every Stage 2 call goes through
  `control_structure.py:_run_stage2_llm_call`: one generic correction
  request, then `StageError`, which stops Stage 2. Some checks add one
  dedicated repair (missing actions) or reference correction (unknown
  references). Call 2a and 2b parsers build models with `model_construct`;
  the assembled structure is validated once by
  `id_normalization.py:validate_normalized_control_structure`. A validator
  error at assembly (`_assemble_stage2_structure`) raises with no correction.
- *Heuristics.* `stpa/models/control_structure.py:check_structural_heuristics`
  runs after Call 3 and before the critic
  (`stpa/system_model/run.py:_run_stage_2_steps`). Its errors and warnings
  become run warnings (`pipeline/synthesis_baseline.py:_baseline_diagnostics`)
  and never block. They are not re-run after the reply-placement step, and
  after the critic revision only when the critic found gaps.
- *Stage 2 publish.* `stpa/system_model/publication.py:publish_control_structure`
  refuses `control-structure.yaml` when an action lacks `target` or
  `effect_kind` (`heuristics.untyped_control_actions`); `temporality` is not
  required. `control-structure-final.yaml`, written after an applied
  obligation-aware revision (`pipeline/synthesis_persist.py:_persist_final_control_structure`),
  does not pass through this check, the heuristics, or the Stage 1a gates.
- *Critic.* `critic.py:run_completeness_critic` gets one correction, then
  returns empty findings, so no revision runs. A revision reply that fails
  validation after its one correction is discarded with a warning
  (`critic.py:_finish_revision`).
- *ICA fill.* `obligation_aware/provider.py:_FillFindingWire` requires at
  least one `governing_pairs` entry (constraint/hazard pair), checked by
  `slot_filling._governance_errors`. After at most one correction the slot
  becomes unresolved. `ICAEnumeration.validate_against` checks reference
  validity at the end of `slot_filling.fill_synthesis_slots`.
- *Stage 1a gates.* `loss_analysis_gates.py:check_hazard_graph_density`
  checks losses without a hazard, hazards without a constraint, and
  constraints without a hazard. `gate_loss_analysis` and
  `verify_reviewed_density` make a bounded revision or correction and then
  raise. A record the Call 3 review marked unresolved is exempt
  (`_exempt_unresolved`) and is recorded as an advisory line in
  `loss-analysis-gates.yaml`.

**Diagnostics column.** (a) `controlled_process_without_feedback`;
**unobserved** `controlled_process_unobserved`; (b) `hazard_without_ica`;
(c) `action_without_process_model_refs`; (d)
`process_model_variable_without_values`; **ica constraints**
`ica_without_related_constraints`; **hazard constraint**
`hazard_without_constraint`.

## Ontology restrictions

One row per class restriction of `safety.owl`, in the file's class order.
Function names without a module are in the module the layer names above.

| # | Ontology restriction | STPA | Why (Handbook) | Producer field | Wire | Load | Revision | Final artifact | Diagnostics |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| O1 | `Actuator` delayed_executed_not-executed_failure Causal_factor_B | possible | One scenario cause among others (§2.5, scenarios of improperly executed actions). | `CausalFactorKind.ACTUATOR_ANOMALY` (no actuator element) | kind enum only | kind enum only | n/a | absent |  |
| O2 | `Actuator` is_part_of_lacp Link_actuator_CP | possible | Actuators are optional at the chosen abstraction (§2.3). | none | absent | absent | absent | absent |  |
| O3 | `Actuator` is_part_of_lca Link_controller_actuator | possible | Actuators are optional at the chosen abstraction (§2.3). | none | absent | absent | absent | absent |  |
| O4 | `Actuator` receives Control_action_actuator | possible | Actuators are optional at the chosen abstraction (§2.3). | none | absent | absent | absent | absent |  |
| O5 | `Algorithm` incorrect_ineffective_updated Causal_factor_A | possible | One cause of an unsafe control action (§2.5, inadequate control algorithm). | none (no algorithm kind in `CausalFactorKind`) | absent | absent | absent | absent |  |
| O6 | `Algorithm` selects Control_action_CP | required | Every controller decides its control actions (§2.3, control algorithm). | `Responsibility.control_actions` | hard (`_check_every_responsibility_has_an_action`, one repair) | absent | warning (critic post-revision heuristics) | warning (heuristics) |  |
| O7 | `Algorithm` selects Control_action_actuator | possible | Actuators are optional (§2.3). | none | absent | absent | absent | absent |  |
| O8 | `Algorithm` uses Process_model | required | Control decisions depend on the process model; a UCA's context is stated in its variables (§2.3, §2.4). | `ControlAction.process_model_refs` | non-empty: absent; same responsibility: hard (`_foreign_process_model_refs`) | non-empty: absent; same responsibility: hard (`_validate_action_process_model_refs`) | critic: refs validated in merge; obligation: new actions carry none | absent | **(c)** |
| O9 | `Causal_factor_A` defines Loss_scenario_A | required | A causal factor is part of a loss scenario (§2.5). | `ScenarioSpec.causal_factors` (containment) | by containment | by containment | n/a | by containment |  |
| O10 | `Causal_factor_A` identifies Safety_recommendation | possible | Recommendations are derived from scenarios, not necessarily one per factor (§2.5). | none per factor; scenario-level `ScenarioSpec.safe_observable_outcome` is optional | absent | optional | n/a | absent |  |
| O11 | `Causal_factor_B` defines Loss_scenario_B | required | A causal factor is part of a loss scenario (§2.5). | `ScenarioSpec.causal_factors` (containment) | by containment | by containment | n/a | by containment |  |
| O12 | `Causal_factor_B` identifies Safety_recommendation | possible | Recommendations are derived from scenarios, not necessarily one per factor (§2.5). | none per factor; scenario-level `ScenarioSpec.safe_observable_outcome` is optional | absent | optional | n/a | absent |  |
| O13 | `Context` defines UCA | required | A UCA states the context in which the action is unsafe (§2.4). | `ICA.hazardous_context` (text); `ICA.context_row` (optional) | text: hard (`_FillFindingWire.hazardous_context`, min length 1); row: optional, must be the action's own (`slot_filling._finding_context`) | text: required field; row: unchecked | n/a | absent |  |
| O14 | `Context` has Values | required | The context is an assignment of values to process-model variables (§2.4, context tables). | `ICA.process_model_context` (code fills it from the cited row) | code-filled, not model output | unchecked | n/a | absent | (d), indirectly |
| O15 | `Context` has Variables | required | The context is an assignment of values to process-model variables (§2.4, context tables). | `ICA.process_model_context` (code fills it from the cited row) | code-filled, not model output | unchecked | n/a | absent | (d), indirectly |
| O16 | `Control_action` defines UCA | required | UCAs are identified per control action (§2.4). | `ICASlot` per action and UCA type | by construction (`threat_enum.slot_creation.create_slots`) | duplicate slot IDs hard; completeness against the structure absent | n/a | unsent or failed slots become `unresolved_reason` |  |
| O17 | `Control_action_CP` inappropriate_missing Causal_factor_B | possible | A cause of an action not executed as issued (§2.5). | partly `CausalFactorKind.ACTUATOR_ANOMALY` | kind enum only | kind enum only | n/a | absent |  |
| O18 | `Control_action_CP` is_part_of_lccp Link_controller_CP | required | A control action runs from its controller to the controlled process (§2.3). | `ControlAction.target` (CP) | hard: required, ref-checked (`_unknown_element_refs`, one correction) | valid if present (`_validate_ca_refs`); may be null | critic: carried forward (`_carry_forward_action_context`); obligation: hard (`revision._append_control_actions`) | hard on Stage 2 publish only (`publish_control_structure`) |  |
| O19 | `Control_action_HLC_CP` conflicting_control_action Causal_factor_B | possible | Conflicting actions from several controllers are one scenario cause (§2.5). | none (no conflict relation; nearest is `CoordinationLink`) | absent | absent | absent | absent |  |
| O20 | `Control_action_HLC_CP` is_part_of_lhcp Link_HLC_CP | possible | Only in a hierarchy where a higher controller acts on the process (§2.3). | no hierarchy levels: any `ControlAction.target` (CP) | hard: required, ref-checked (`_unknown_element_refs`, one correction) | valid if present (`_validate_ca_refs`); may be null | critic: carried forward (`_carry_forward_action_context`); obligation: hard (`revision._append_control_actions`) | hard on Stage 2 publish only (`publish_control_structure`) |  |
| O21 | `Control_action_HLC_controller` inappropriate_missing Causal_factor_B | possible | A cause of an action not executed as issued (§2.5). | partly `CausalFactorKind.ACTUATOR_ANOMALY` | kind enum only | kind enum only | n/a | absent |  |
| O22 | `Control_action_HLC_controller` is_part_of_lhc Link_HLC_controller | possible | Only where one controller controls another (§2.3). | `ControlAction.target` (RESP, `agent_message`) / `CoordinationLink` | hard: typed target; effect forced to `agent_message` (`normalize_control_action_effect_kind`) | hard (same validators) | as `ControlAction.target` | hard on Stage 2 publish (target, effect_kind) |  |
| O23 | `Control_action_HLC_controller` updates Process_model | possible | A command from a higher controller may set the lower one's beliefs. | `CoordinationLink.shared_pm` | existence: fatal assembly; one owning endpoint: hard on Call 3 only (`_coordination_ownership_errors`) | existence hard (`_validate_coordination_links`); ownership absent | ownership absent (both revision paths) | absent (`stpa_index._issued_by_owner` silently skips) |  |
| O24 | `Control_action_actuator` inappropriate_missing Causal_factor_B | possible | A cause of an action not executed as issued (§2.5). | partly `CausalFactorKind.ACTUATOR_ANOMALY` | kind enum only | kind enum only | n/a | absent |  |
| O25 | `Control_action_actuator` is_part_of_lca Link_controller_actuator | possible | Actuators are optional (§2.3). | none | absent | absent | absent | absent |  |
| O26 | `Control_structure` has Actuator | possible | Optional (§2.3). | none | absent | absent | absent | absent |  |
| O27 | `Control_structure` has Assumption | possible | Assumptions are recorded where they matter (§2.2). | none at structure level (`CausalFactor.bounded_assumption` per factor) | absent | absent | absent | absent |  |
| O28 | `Control_structure` has Controlled_process_CP | required | A control structure contains the processes it controls (§2.3). | `ControlStructure.controlled_processes` | optional on parse (Call 2b defaults to `[]`) | optional (`[]` default) | absent | warning for an unreferenced CP (heuristics) |  |
| O29 | `Control_structure` has Controller | required | A control structure contains controllers (§2.3). | `ControlStructure.responsibilities` | hard (Call 2a) | hard (`min_length=1`) | critic strips only fully empty ones | model |  |
| O30 | `Control_structure` has HLC | possible | Only in a multi-level hierarchy (§2.3). | none (no levels) | absent | absent | absent | absent |  |
| O31 | `Control_structure` has Link | required | Control actions and feedback connect the elements (§2.3). | `ControlAction`, `FeedbackChannel`, `CoordinationLink` | see the link rows | see the link rows | see the link rows | see the link rows |  |
| O32 | `Control_structure` has Sensor | possible | Sensors are optional at the chosen abstraction (§2.3). | none (feedback channels are direct) | absent | absent | absent | absent |  |
| O33 | `Control_structure` receives Feedback | required | Feedback closes each control loop (§2.3). | `Responsibility.feedback_channels` | indirect: every PM needs an update (`_check_every_process_model_part_has_feedback`) | absent | warning (critic post-revision heuristics) | warning (heuristics) |  |
| O34 | `Control_structure` represents System | required | The structure models the system under analysis (§2.2, §2.3). | none explicit (the use-case text is the system description) | absent | absent | absent | absent |  |
| O35 | `Controlled_process_CP` is_part_of_lacp Link_actuator_CP | possible | Optional (§2.3). | none | absent | absent | absent | absent |  |
| O36 | `Controlled_process_CP` is_part_of_lccp Link_controller_CP | required | A process no controller acts on is not controlled (§2.3). | some `ControlAction.target` names the CP | absent | absent | absent | warning: a CP must be a CA target **or** an FB source (`_check_controlled_process_references`) |  |
| O37 | `Controlled_process_CP` is_part_of_lcpc Link_CP_controller | required | Feedback from the process to its controller; a missing path is a flaw to analyze (§2.3, §2.5). | `FeedbackChannel.source` (CP) | source required and ref-checked; which controller it reaches: absent | valid if present (`_validate_fb_source_refs`) | absent (critic judges it semantically) | warning only for a CP neither targeted nor observed (`_check_controlled_process_references`) | **(a)**, **unobserved** |
| O38 | `Controlled_process_CP` is_part_of_lcph Link_CP_HLC | possible | Only in a hierarchy. | `FeedbackChannel.source` (CP) | source required and ref-checked; which controller it reaches: absent | valid if present (`_validate_fb_source_refs`) | absent (critic judges it semantically) | warning only for a CP neither targeted nor observed (`_check_controlled_process_references`) |  |
| O39 | `Controlled_process_CP` is_part_of_lcps Link_CP_sensor | possible | Sensors are optional. | none | absent | absent | absent | absent |  |
| O40 | `Controlled_process_CP` is_part_of_lhcp Link_HLC_CP | possible | Only in a hierarchy. | no hierarchy levels: any `ControlAction.target` (CP) | hard: required, ref-checked (`_unknown_element_refs`, one correction) | valid if present (`_validate_ca_refs`); may be null | critic: carried forward (`_carry_forward_action_context`); obligation: hard (`revision._append_control_actions`) | hard on Stage 2 publish only (`publish_control_structure`) |  |
| O41 | `Controlled_process_CP` produces Output | possible | Process outputs are modelled when relevant. | none (`effect_kind` types the action, not the process output) | absent | absent | absent | absent |  |
| O42 | `Controlled_process_CP` receives Control_action_CP | required | As `is_part_of_lccp` (§2.3). | `ControlAction.target` (CP) | hard: required, ref-checked (`_unknown_element_refs`, one correction) | valid if present (`_validate_ca_refs`); may be null | critic: carried forward (`_carry_forward_action_context`); obligation: hard (`revision._append_control_actions`) | hard on Stage 2 publish only (`publish_control_structure`) |  |
| O43 | `Controlled_process_CP` receives Control_action_HLC_CP | possible | Only in a hierarchy. | `ControlAction.target` (CP) | hard: required, ref-checked (`_unknown_element_refs`, one correction) | valid if present (`_validate_ca_refs`); may be null | critic: carried forward (`_carry_forward_action_context`); obligation: hard (`revision._append_control_actions`) | hard on Stage 2 publish only (`publish_control_structure`) |  |
| O44 | `Controlled_process_CP` receives Input | possible | Process inputs are modelled when relevant. | none | absent | absent | absent | absent |  |
| O45 | `Controller` failure Causal_factor_A | possible | Physical controller failure is one cause (§2.5). | none | absent | absent | absent | absent |  |
| O46 | `Controller` has Algorithm | required | Every controller has a control algorithm (§2.3). | none explicit (implied by `control_actions`) | absent | absent | absent | absent |  |
| O47 | `Controller` has Process_model | required | Every controller has a process model (§2.3). | `Responsibility.process_model_parts` | absent (Call 2a defaults to `[]`) | absent | warning (critic post-revision heuristics) | warning (heuristics) |  |
| O48 | `Controller` is_part_of_lca Link_controller_actuator | possible | Optional. | none | absent | absent | absent | absent |  |
| O49 | `Controller` is_part_of_lccp Link_controller_CP | required | A controller issues control actions (§2.3). | `Responsibility.control_actions` | hard (`_check_every_responsibility_has_an_action`, one repair) | absent | warning (critic post-revision heuristics) | warning (heuristics) |  |
| O50 | `Controller` is_part_of_lce Link_controller_external-information | possible | Only where the controller informs another system. | none | absent | absent | absent | absent |  |
| O51 | `Controller` is_part_of_lch Link_controller_HLC | possible | Only in a hierarchy. | `FeedbackChannel.source` (RESP) | source ref-checked | valid if present | absent | absent |  |
| O52 | `Controller` is_part_of_lcpc Link_CP_controller | required | A controller receives feedback (§2.3). | `Responsibility.feedback_channels` | indirect: every PM needs an update (`_check_every_process_model_part_has_feedback`) | absent | warning (critic post-revision heuristics) | warning (heuristics) |  |
| O53 | `Controller` is_part_of_lec Link_external-information_controller | possible | Only where external information exists. | `FeedbackChannel.source_kind` (`retrieved_content`, `session_context`, `other`) | optional | optional | absent | absent |  |
| O54 | `Controller` is_part_of_lhc Link_HLC_controller | possible | Only in a hierarchy. | `ControlAction.target` (RESP, `agent_message`) / `CoordinationLink` | hard: typed target; effect forced to `agent_message` (`normalize_control_action_effect_kind`) | hard (same validators) | as `ControlAction.target` | hard on Stage 2 publish (target, effect_kind) |  |
| O55 | `Controller` is_part_of_lsc Link_sensor_controller | possible | Sensors are optional. | none | absent | absent | absent | absent |  |
| O56 | `Controller` issues Control_action_CP | required | As `is_part_of_lccp` (§2.3). | `Responsibility.control_actions` | hard (`_check_every_responsibility_has_an_action`, one repair) | absent | warning (critic post-revision heuristics) | warning (heuristics) |  |
| O57 | `Controller` issues Control_action_actuator | possible | Actuators are optional. | none | absent | absent | absent | absent |  |
| O58 | `Controller` receives Control_action_HLC_controller | possible | Only in a hierarchy. | `ControlAction.target` (RESP, `agent_message`) / `CoordinationLink` | hard: typed target; effect forced to `agent_message` (`normalize_control_action_effect_kind`) | hard (same validators) | as `ControlAction.target` | hard on Stage 2 publish (target, effect_kind) |  |
| O59 | `Controller` receives External-information-received | possible | Only where external information exists. | `FeedbackChannel.source_kind` (`retrieved_content`, `session_context`, `other`) | optional | optional | absent | absent |  |
| O60 | `Controller` receives Feedback_of_CP | required | A controller observes the processes it controls (§2.3); this restriction asks only for some feedback. | `FeedbackChannel.source` (CP) | source required and ref-checked; which controller it reaches: absent | valid if present (`_validate_fb_source_refs`) | absent (critic judges it semantically) | warning only for a CP neither targeted nor observed (`_check_controlled_process_references`) | **(a)**, **unobserved** |
| O61 | `Controller` sends External-information-sent | possible | Only where the controller informs another system. | none | absent | absent | absent | absent |  |
| O62 | `Controller` sends Feedback_of_controller | possible | Only in a hierarchy. | `FeedbackChannel.source` (RESP) | source ref-checked | valid if present | absent | absent |  |
| O63 | `Energy` is_part_of_lacp Link_actuator_CP | possible | Physical energy flows; not part of the generic loop. | none | absent | absent | absent | absent |  |
| O64 | `Energy` is_part_of_lcps Link_CP_sensor | possible | Physical energy flows; not part of the generic loop. | none | absent | absent | absent | absent |  |
| O65 | `Environmental_disturbances` affects Controlled_process_CP | possible | Disturbances are one scenario source (§2.5). | none | absent | absent | absent | absent |  |
| O66 | `Environmental_disturbances` unidentified-disturbance Causal_factor_B | possible | One scenario cause (§2.5). | none | absent | absent | absent | absent |  |
| O67 | `External-information-received` is_part_of_lec Link_external-information_controller | possible | Only where external information exists. | `FeedbackChannel.source_kind` (`retrieved_content`, `session_context`, `other`) | optional | optional | absent | absent |  |
| O68 | `External-information-received` updates Process_model | possible | External information may update beliefs. | `FeedbackChannel.updates` of a non-process source | hard: unknown PM rejected (generic correction); cross-responsibility caught at fatal assembly | hard (`_validate_feedback_updates`) | critic: hard via merge; obligation: hard at final construction | model only |  |
| O69 | `External-information-received` wrong_missing_external_information Causal_factor_A | possible | One cause of a flawed process model (§2.5). | partly `CausalFactorKind.PROCESS_MODEL_FLAW` | kind enum only | kind enum only | n/a | absent |  |
| O70 | `External-information-sent` is_part_of_lce Link_controller_external-information | possible | Optional. | none | absent | absent | absent | absent |  |
| O71 | `External-system` is_part_of_lce Link_controller_external-information | possible | External systems appear only where they exchange information. | none (external sources appear as CP descriptions or `source_kind`) | absent | absent | absent | absent |  |
| O72 | `External-system` is_part_of_lec Link_external-information_controller | possible | External systems appear only where they exchange information. | none (external sources appear as CP descriptions or `source_kind`) | absent | absent | absent | absent |  |
| O73 | `External-system` receives External-information-sent | possible | External systems appear only where they exchange information. | none (external sources appear as CP descriptions or `source_kind`) | absent | absent | absent | absent |  |
| O74 | `External-system` sends External-information-received | possible | External systems appear only where they exchange information. | none (external sources appear as CP descriptions or `source_kind`) | absent | absent | absent | absent |  |
| O75 | `Feedback_of_CP` delayed_inadequate_missing Causal_factor_A | possible | Inadequate feedback is one cause of a flawed process model (§2.5). | `CausalFactorKind.FEEDBACK_DELAY` with an FB `source_id` | source in the selected path: hard (`stage5/assemble._validate_assembled_factors`) | ID prefix only (`CausalFactor.validate_source_namespace`) | n/a | absent |  |
| O76 | `Feedback_of_CP` is_part_of_lcpc Link_CP_controller | required | Feedback runs from the process to its controller (§2.3). | `FeedbackChannel.source` (CP) | source required and ref-checked; which controller it reaches: absent | valid if present (`_validate_fb_source_refs`) | absent (critic judges it semantically) | warning only for a CP neither targeted nor observed (`_check_controlled_process_references`) | **(a)**, **unobserved** |
| O77 | `Feedback_of_CP` is_part_of_lcph Link_CP_HLC | possible | Only in a hierarchy. | `FeedbackChannel.source` (CP) | source required and ref-checked; which controller it reaches: absent | valid if present (`_validate_fb_source_refs`) | absent (critic judges it semantically) | warning only for a CP neither targeted nor observed (`_check_controlled_process_references`) |  |
| O78 | `Feedback_of_CP` is_part_of_lsc Link_sensor_controller | possible | Sensors are optional. | none | absent | absent | absent | absent |  |
| O79 | `Feedback_of_CP` is_part_of_lsh Link_sensor_HLC | possible | Sensors are optional. | none | absent | absent | absent | absent |  |
| O80 | `Feedback_of_CP` updates Process_model | required | Feedback updates the process model (§2.3). | `FeedbackChannel.updates` | hard: unknown PM rejected (generic correction); cross-responsibility caught at fatal assembly | hard (`_validate_feedback_updates`) | critic: hard via merge; obligation: hard at final construction | model only |  |
| O81 | `Feedback_of_controller` delayed_inadequate_missing Causal_factor_A | possible | One cause (§2.5). | `CausalFactorKind.FEEDBACK_DELAY` | as for process feedback | ID prefix only | n/a | absent |  |
| O82 | `Feedback_of_controller` is_part_of_lch Link_controller_HLC | possible | Only in a hierarchy. | `FeedbackChannel.source` (RESP) | source ref-checked | valid if present | absent | absent |  |
| O83 | `HLC` is_also Controller | possible | A higher controller is a controller; levels are optional. | every responsibility is a controller; no levels | absent | absent | absent | absent |  |
| O84 | `HLC` is_part_of_lch Link_controller_HLC | possible | Only in a multi-level hierarchy (§2.3). | `FeedbackChannel.source` (RESP) | source ref-checked | valid if present | absent | absent |  |
| O85 | `HLC` is_part_of_lcph Link_CP_HLC | possible | Only in a multi-level hierarchy (§2.3). | `FeedbackChannel.source` (CP) | source required and ref-checked; which controller it reaches: absent | valid if present (`_validate_fb_source_refs`) | absent (critic judges it semantically) | warning only for a CP neither targeted nor observed (`_check_controlled_process_references`) |  |
| O86 | `HLC` is_part_of_lhc Link_HLC_controller | possible | Only in a multi-level hierarchy (§2.3). | `ControlAction.target` (RESP, `agent_message`) / `CoordinationLink` | hard: typed target; effect forced to `agent_message` (`normalize_control_action_effect_kind`) | hard (same validators) | as `ControlAction.target` | hard on Stage 2 publish (target, effect_kind) |  |
| O87 | `HLC` is_part_of_lhcp Link_HLC_CP | possible | Only in a multi-level hierarchy (§2.3). | no hierarchy levels: any `ControlAction.target` (CP) | hard: required, ref-checked (`_unknown_element_refs`, one correction) | valid if present (`_validate_ca_refs`); may be null | critic: carried forward (`_carry_forward_action_context`); obligation: hard (`revision._append_control_actions`) | hard on Stage 2 publish only (`publish_control_structure`) |  |
| O88 | `HLC` is_part_of_lsh Link_sensor_HLC | possible | Only in a multi-level hierarchy (§2.3). | none | absent | absent | absent | absent |  |
| O89 | `HLC` issues Control_action_HLC_CP | possible | Only in a multi-level hierarchy (§2.3). | no hierarchy levels: any `ControlAction.target` (CP) | hard: required, ref-checked (`_unknown_element_refs`, one correction) | valid if present (`_validate_ca_refs`); may be null | critic: carried forward (`_carry_forward_action_context`); obligation: hard (`revision._append_control_actions`) | hard on Stage 2 publish only (`publish_control_structure`) |  |
| O90 | `HLC` issues Control_action_HLC_controller | possible | Only in a multi-level hierarchy (§2.3). | `ControlAction.target` (RESP, `agent_message`) / `CoordinationLink` | hard: typed target; effect forced to `agent_message` (`normalize_control_action_effect_kind`) | hard (same validators) | as `ControlAction.target` | hard on Stage 2 publish (target, effect_kind) |  |
| O91 | `HLC` receives Feedback_of_CP | possible | Only in a multi-level hierarchy (§2.3). | `FeedbackChannel.source` (CP) | source required and ref-checked; which controller it reaches: absent | valid if present (`_validate_fb_source_refs`) | absent (critic judges it semantically) | warning only for a CP neither targeted nor observed (`_check_controlled_process_references`) |  |
| O92 | `HLC` receives Feedback_of_controller | possible | Only in a multi-level hierarchy (§2.3). | `FeedbackChannel.source` (RESP) | source ref-checked | valid if present | absent | absent |  |
| O93 | `Hazard` associates_with Loss_mishap | required | Every hazard traces to at least one loss (§2.2). | `Hazard.related_losses` | valid: hard; non-empty: hard for the gap call and Stage 1a revision edits only (`_validate_complete_chain`), not the risk call | valid: hard (`_validate_hazard_references`); non-empty: absent | obligation: absent (`DraftHazard.related_loss_ids` defaults to empty) | absent |  |
| O94 | `Hazard` defines UCA | required | An unsafe control action is what leads to a hazard; a hazard no UCA reaches shows an incomplete analysis (§2.4). | reverse of `ICA.related_hazards` | absent | absent | absent | absent | **(b)** |
| O95 | `Input` missing_wrong_input Causal_factor_B | possible | One scenario cause (§2.5). | none | absent | absent | absent | absent |  |
| O96 | `Loss_scenario` has Rationale | possible | Scenarios are explained in prose. | `ICA.loss_scenario`, `ScenarioSpec.loss_scenario` (text) | required text | required field | n/a | absent |  |
| O97 | `Loss_scenario` has Safety_recommendation | possible | Recommendations follow scenarios (§2.5). | `ScenarioSpec.safe_observable_outcome` (optional) | absent | optional | n/a | absent |  |
| O98 | `Loss_scenario_A` leads UCA | required | A loss scenario explains a UCA or an improperly executed action (§2.5). | `ScenarioSpec.threat_source` (`ica_slot_id`, `ica_id`), `ica_type` | hard: hazard and constraint refs must equal the context (`_check_context_identity`) | `ica_slot_id` required; `ica_id` optional | n/a | warning: Stage 7 `validators.validate_traceability` reaches only the SP3 manifest |  |
| O99 | `Loss_scenario_A` has Causal_factor_A (min 1) | required (min 1) | A scenario names its causal factors (§2.5). | `ScenarioSpec.causal_factors` | hard (Stage 5 schema, `min_length=1`) | hard only with `scenario_context` (`ScenarioSpec.preserve_scenario_context_authority`) | n/a | hard in the v5 handoff (`handoff.py`, `min_length=1`) |  |
| O100 | `Loss_scenario_B` leads UCA | required | A loss scenario explains a UCA or an improperly executed action (§2.5). | `ScenarioSpec.threat_source` (`ica_slot_id`, `ica_id`), `ica_type` | hard: hazard and constraint refs must equal the context (`_check_context_identity`) | `ica_slot_id` required; `ica_id` optional | n/a | warning: Stage 7 `validators.validate_traceability` reaches only the SP3 manifest |  |
| O101 | `Loss_scenario_B` has Causal_factor_B (min 1) | required (min 1) | A scenario names its causal factors (§2.5). | `ScenarioSpec.causal_factors` | hard (Stage 5 schema, `min_length=1`) | hard only with `scenario_context` (`ScenarioSpec.preserve_scenario_context_authority`) | n/a | hard in the v5 handoff (`handoff.py`, `min_length=1`) |  |
| O102 | `Process_model` has Variables | required | A process model consists of variables (§2.3). | `Responsibility.process_model_parts` | absent (Call 2a defaults to `[]`) | absent | warning (critic post-revision heuristics) | warning (heuristics) |  |
| O103 | `Process_model` wrong_process_model Causal_factor_A | possible | A principal cause of UCAs (§2.5). | `CausalFactorKind.PROCESS_MODEL_FLAW`, `CausalFactor.process_model_variable` | one correction, then no stated belief (`stage5/flawed_belief.flawed_belief_findings`) | PM prefix only | n/a | report-only list of null variables (`report/process_model_gaps.py`) |  |
| O104 | `Safety_constraint` associates_with Hazard | required | Every system-level constraint traces to hazards (§2.2). | `SecurityConstraint.related_hazards` | valid: hard; constraint without hazard: hard in the density gate, exempt when the review marks it unresolved (`_exempt_unresolved`) | valid: hard; non-empty: absent | obligation: new constraints may have none | advisory line in `loss-analysis-gates.yaml` |  |
| O105 | `Safety_constraint` constrains System | required | Constraints are on the system (§2.2). | implicit | absent | absent | absent | absent |  |
| O106 | `Safety_recommendation` defines Safety_constraint | possible | Recommendations can become requirements. | none | absent | absent | absent | absent |  |
| O107 | `Sensor` delayed_wrong_missing_feedback_failure Causal_factor_A | possible | One cause (§2.5). | `CausalFactorKind.SENSOR_ANOMALY` (no sensor element) | kind enum only | kind enum only | n/a | absent |  |
| O108 | `Sensor` is_part_of_lcps Link_CP_sensor | possible | Sensors are optional at the chosen abstraction (§2.3). | none | absent | absent | absent | absent |  |
| O109 | `Sensor` is_part_of_lsc Link_sensor_controller | possible | Sensors are optional at the chosen abstraction (§2.3). | none | absent | absent | absent | absent |  |
| O110 | `Sensor` is_part_of_lsh Link_sensor_HLC | possible | Sensors are optional at the chosen abstraction (§2.3). | none | absent | absent | absent | absent |  |
| O111 | `Sensor` sends Feedback_of_CP | possible | Sensors are optional at the chosen abstraction (§2.3). | none | absent | absent | absent | absent |  |
| O112 | `System` avoids Loss_mishap | required | The analysis starts from the losses to avoid (§2.2). | `LossAnalysis.risk_card_losses` + `use_case_losses` | list schemas allow 0 to 16 losses each (`loss_analysis.py:_Stage1aGapProviderDraft`, inherited by `_Stage1aRiskProviderDraft`); stage checks are hard: the risk call requires at least one risk-card loss when risk cards are supplied (`require_losses` → `_validate_loss_presence`), and the gap call's `_validate_complete_chain` rejects a draft with no declared or supplied loss | provenance hard (`_validate_risk_card_provenance`); no minimum count | absent | absent |  |
| O113 | `System` has Goal | possible | The system purpose frames the analysis (§2.2). | none (use-case text) | absent | absent | absent | absent |  |
| O114 | `System` respects Assumption | possible | Assumptions are recorded where they matter. | none | absent | absent | absent | absent |  |
| O115 | `UCA` defines Loss_scenario_A | required | Scenarios are identified for UCAs (§2.5). | `ICA.loss_scenario` (text); `ScenarioSpec` per selected ICA | text: hard (`loss_consequence`, min length 1) | text: required field | n/a | not verified that every retained ICA gets a scenario |  |
| O116 | `UCA` defines Loss_scenario_B | required | Scenarios are identified for UCAs (§2.5). | `ICA.loss_scenario` (text); `ScenarioSpec` per selected ICA | text: hard (`loss_consequence`, min length 1) | text: required field | n/a | not verified that every retained ICA gets a scenario |  |
| O117 | `UCA` leads Hazard | required | Every UCA names the hazards it leads to (§2.4). | `ICA.related_hazards` | hard: `governing_pairs` min 1 (`_FillFindingWire`), one correction, then the slot is unresolved | default `[]`; validity only via `ICAEnumeration.validate_against` | n/a | validity hard at the end of `fill_synthesis_slots`; non-empty absent |  |
| O118 | `UCA` refines Safety_constraint | required | Each UCA yields a constraint on its controller (§2.4). | `ICA.related_constraints` | hard: `governing_pairs` min 1 and `_governance_errors`; one correction, then unresolved | default `[]` (`models/ica_enumeration.py`); validity only via `validate_against` | n/a | validity hard; non-empty absent | **ica constraints** |
| O119 | `UCA_type` defines UCA | required | Four UCA types (§2.4); the ontology's seven subclasses split the timing and duration types. | `ICASlot.uca_type` (`UCAType`: 4 values) | closed enum; slots made per type (`create_slots`) | closed enum | n/a | WRONG_DURATION is a deterministic N/A without continuous or bounded temporality |  |
| O120 | `Variables` has Values | required | Each variable has the values that change a decision (§2.4, context tables). | `ProcessModelPart.values` | absent | absent | absent | code skips a variable without values (`_context_columns`) | **(d)** |

## Relationships the Handbook requires that the ontology lacks

That every hazard is reached by at least one UCA is not listed here: the
ontology states it as `Hazard` defines `UCA` (row O94).

| # | Relationship | STPA | Why (Handbook) | Producer field | Wire | Load | Revision | Final artifact | Diagnostics |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| H1 | Every hazard has at least one system-level constraint | required | Constraints are derived from hazards (§2.2); the ontology states only constraint → hazard. | reverse of `SecurityConstraint.related_hazards` | hard in the density gate (`_hazards_without_constraint`), exempt when the review marks the hazard unresolved | absent | obligation: absent | advisory line in `loss-analysis-gates.yaml` | **hazard constraint** |
| H2 | Every loss is reached by at least one hazard | required | Hazards are defined for the losses (§2.2); the ontology states only hazard → loss. | reverse of `Hazard.related_losses` | hard in the density gate (`_losses_without_hazard`) | absent | obligation: new losses unchecked | absent | |
| H3 | A controlled process a controller acts on feeds back to that controller | required | The control loop closes through feedback to the controller that acts (§2.3); missing feedback is a flaw the analysis must record (§2.5). The ontology asks only that a process has *some* feedback link and a controller *some* feedback. | `ControlAction.target` and `FeedbackChannel.source` of the same responsibility | absent | absent | absent (critic judges it semantically) | absent; the heuristics accept a CP that is only a target | **(a)**, **unobserved** |
| H4 | Every control action is analyzed under each UCA type | required | Each control action is examined for the four types (§2.4). | one `ICASlot` per action and type | by construction (`threat_enum.slot_creation.create_slots`); a failed or unsent slot becomes `unresolved_reason` (`slot_filling._fill_missing_request_slots`) | N/A needs `na_justification` (`ICASlot.validate_na_exclusivity`; an empty string passes); completeness absent | n/a | absent | |
| H5 | Each UCA yields a controller constraint | required | Controller constraints are the inverse of UCAs (§2.4). | `ICA.related_constraints` (SC or RC IDs); `Responsibility.responsibility_constraints` | SC only: the fill wire cannot cite an RC (`_governance_errors`) | RC IDs accepted by `validate_against` | n/a | absent | **ica constraints** (any constraint) |
| H6 | Every process-model variable is updated by feedback | required | The process model is updated through feedback (§2.3); an unfed belief is a scenario cause (§2.5). The ontology states only feedback → process model. | `FeedbackChannel.updates` | hard on Call 2b (`_check_every_process_model_part_has_feedback`) | absent | critic: post-revision warning; obligation: absent | warning (heuristics `_check_orphan_pms`) | |
| H7 | Responsibilities trace to the constraints they implement, and every hazard reaches a responsibility | required | Responsibilities are derived from the system-level constraints (§2.3). | `Responsibility.security_constraint_refs` | hard on Call 3 (`semantic_review._reviewed_constraints` subset) | absent (no loss analysis at load) | critic: absent (refs unioned unchecked); obligation: hard (`_resolve_many`) | warning: uncited constraints (`heuristics.uncited_security_constraints`) and untraced hazards (heuristics `_check_hazard_tracing`) | |
| H8 | A UCA's context is a combination of its controller's process-model values | required | Context tables combine process-model variable values (§2.4). | `ICA.context_row` against `control_action_context_table` | hard: the row must belong to the slot's action (`slot_filling._finding_context`); optional | absent | n/a | absent | |
| H9 | Controllers acting on shared state coordinate through one owner | possible | Several controllers of one process are a scenario source (§2.5). | `CoordinationLink` with `coordination_process_model_owner` | hard on Call 3 only | existence only | absent | absent | |
| H10 | A causal factor names an element of the scenario's control path | required | Scenarios are built over the control loop (§2.5). | `CausalFactor.source_id` | hard at Stage 5 assembly (`stage5/assemble._validate_assembled_factors`) and Stage 5 spec validation (`causal_factor.validate_factor_sources`; the scenario is dropped) | ID prefix only | n/a | absent | |

## Object properties

Each object property of `safety.owl`, its declared domain and range, and the
restriction rows that use it. Every property appears in at least one
restriction.

| Object property | Declared domain | Declared range | Restriction rows |
| --- | --- | --- | --- |
| `affects` | Environmental_disturbances | Controlled_process_CP | O65 |
| `associates_with` | — | — | O93, O104 |
| `avoids` | System | Loss_mishap | O112 |
| `conflicting_control_action` | Causal_factor_B | — | O19 |
| `constrains` | Safety_constraint | System | O105 |
| `defines` | — | — | O9, O11, O13, O16, O94, O106, O115, O116, O119 |
| `delayed_executed_not-executed_failure` | Causal_factor_B | — | O1 |
| `delayed_inadequate_missing` | Causal_factor_A | — | O75, O81 |
| `delayed_wrong_missing_feedback_failure` | Causal_factor_A | — | O107 |
| `failure` | Causal_factor_A | — | O45 |
| `has` | — | — | O14, O15, O26, O27, O28, O29, O30, O31, O32, O46, O47, O96, O97, O99, O101, O102, O113, O120 |
| `identifies` | — | — | O10, O12 |
| `inappropriate_missing` | Causal_factor_B | — | O17, O21, O24 |
| `incorrect_ineffective_updated` | Causal_factor_A | — | O5 |
| `is_also` | — | — | O83 |
| `is_part_of_lacp` | Link_actuator_CP | — | O2, O35, O63 |
| `is_part_of_lca` | Link_controller_actuator | — | O3, O25, O48 |
| `is_part_of_lccp` | Link_controller_CP | — | O18, O36, O49 |
| `is_part_of_lce` | Link_controller_external-information | — | O50, O70, O71 |
| `is_part_of_lch` | Link_controller_HLC | — | O51, O82, O84 |
| `is_part_of_lcpc` | Link_CP_controller | — | O37, O52, O76 |
| `is_part_of_lcph` | Link_CP_HLC | — | O38, O77, O85 |
| `is_part_of_lcps` | Link_CP_sensor | — | O39, O64, O108 |
| `is_part_of_lec` | Link_external-information_controller | — | O53, O67, O72 |
| `is_part_of_lhc` | Link_HLC_controller | — | O22, O54, O86 |
| `is_part_of_lhcp` | Link_HLC_CP | — | O20, O40, O87 |
| `is_part_of_lsc` | Link_sensor_controller | — | O55, O78, O109 |
| `is_part_of_lsh` | Link_sensor_HLC | — | O79, O88, O110 |
| `issues` | — | Control_action | O56, O57, O89, O90 |
| `leads` | — | — | O98, O100, O117 |
| `missing_wrong_input` | Causal_factor_B | — | O95 |
| `produces` | Controlled_process_CP | Output | O41 |
| `receives` | — | — | O4, O33, O42, O43, O44, O58, O59, O60, O73, O91, O92 |
| `refines` | — | — | O118 |
| `represents` | — | — | O34 |
| `respects` | — | Assumption | O114 |
| `selects` | — | — | O6, O7 |
| `sends` | — | — | O61, O62, O74, O111 |
| `unidentified-disturbance` | Causal_factor_B | — | O66 |
| `updates` | — | Process_model | O23, O68, O80 |
| `uses` | Algorithm | Process_model | O8 |
| `wrong_missing_external_information` | Causal_factor_A | — | O69 |
| `wrong_process_model` | Causal_factor_A | — | O103 |

## Gaps the table confirms

- The controlled-process heuristic accepts a process that is only a
  control-action target: `_check_controlled_process_references` counts a
  target or a feedback source, so an action whose target no channel observes
  passes (H3, O37).
- Nothing flags a hazard that no retained ICA cites (O94).
- `ICA.related_constraints` defaults to `[]` (`stpa/models/ica_enumeration.py`)
  and neither loading nor revision requires it. The ICA fill wire does
  require one governing pair per finding, which is why no saved run has an
  ICA without constraints (O118).
- The structural heuristics are reported and never block (O6, O33, O36,
  O47, O49, O52, O56, H6, H7), and they run on the structure before the
  critic revision and reply placement.
- The final control structure after an obligation-aware revision is not
  checked for typed actions: only Stage 2's `control-structure.yaml` is
  refused when an action lacks `target` or `effect_kind`, and `temporality` is
  required by neither.
- `ProcessModelPart.values` and `ControlAction.process_model_refs` are
  required by no layer (O120, O8).

## Not verified

- Whether every retained ICA reaches a Stage 5 scenario (O115, O116).
- The enforcement of fields outside the STPA relationships, such as
  feedback authority, trust, and observation contracts.

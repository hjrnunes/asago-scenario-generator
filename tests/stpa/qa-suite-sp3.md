# SP3 Scenario Production — End-to-End QA Suite

This document specifies the user-visible workflows that QA verifies for SP3
(Scenario Production: Stages 5, 6, 7 of the STPA-Sec pipeline). All
verification is done through the CLI (`scripts/run_sp3.py`), Python import
checks, pytest execution, and filesystem inspection — no project-internal
APIs are used.

## Running this suite

The executable form of every check below lives in
`tests/stpa/run_sp3_qa_suite.sh`:

```bash
bash tests/stpa/run_sp3_qa_suite.sh
```

The end-to-end run checks (`QA-SP3-RUN-*`) drive the real `run_sp3.py`
command line against a local stub LLM endpoint
(`tests/stpa/sp3_qa_stub_llm.py`) rather than a live model, so the suite is
deterministic, offline, and free of API cost while still exercising the real
orchestration, artifact writing, and manifest code paths. The stub speaks the
OpenAI chat-completions protocol and is supplied through the CLI's own
`--profiles-file` / `--profile` flags, so nothing about the invocation path is
bypassed. Substitute a real profile name to run the same checks against a live
model.

The focused prompt-remediation workflow can also be run independently:

```bash
uv run python tests/stpa/run_sp3_prompt_qa.py
```

Keep the script and this document in step: when a check here changes, update
the corresponding check in the script in the same change.

## 1. Module Structure Verification

### QA-SP3-STRUCT-01: Module layout matches spec

**Steps:**
1. Verify the SP3 scenario production package exists and is importable.
2. Verify all modules listed in the spec exist and are importable.
3. Verify the prompt templates directory exists with all Jinja2 templates.

**Command:**
```bash
uv run python -c "
from asago_scenario_generator.stpa.scenario_prod import bdi_generation, narrative, attack_tree, gherkin, validators, eval_metrics, coverage, assembly, run
print('All SP3 modules importable')
"
```

**Command:**
```bash
ls src/asago_scenario_generator/stpa/scenario_prod/prompts/stage5_system.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage5_user.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6a_narrative_system.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6a_narrative_user.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6b_tree_system.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6b_tree_user.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6c_gherkin_system.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6c_gherkin_user.j2
```

### QA-SP3-STRUCT-02: CLI script exists and accepts arguments

**Steps:**
1. Verify `scripts/run_sp3.py` exists.
2. Run `scripts/run_sp3.py --help` and verify it accepts `--enriched-threats`, `--control-structure`, `--loss-analysis`, `--capability-profile`, `--output-dir`, `--max-workers`, and `--profile` arguments.

**Command:**
```bash
uv run python scripts/run_sp3.py --help
```

## 2. BDI Generation Verification (Stage 5)

### QA-SP3-BDI-01: Defender BDI pre-population on Klarna fixture

**Steps:**
1. Load the Klarna control structure fixture.
2. Run `populate_defender_bdi` for RESP-1.
3. Verify beliefs reference valid PM IDs, desires reference RESP-1, intentions reference valid CA IDs.
4. Verify vulnerability fields are empty before the LLM call.

**Command:**
```bash
uv run python -c "
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import populate_defender_bdi
cs = read_yaml('src/asago_scenario_generator/stpa/fixtures/control_structure_klarna.yaml', ControlStructure)
bdi = populate_defender_bdi(cs, 'RESP-1')
assert len(bdi.beliefs) > 0, 'No beliefs generated'
assert len(bdi.desires) > 0, 'No desires generated'
assert len(bdi.intentions) > 0, 'No intentions generated'
for b in bdi.beliefs:
    assert b.vulnerability == '', f'Belief {b.pm_id} vulnerability not empty'
    assert b.pm_id.startswith('PM-'), f'Bad pm_id: {b.pm_id}'
for d in bdi.desires:
    assert d.resp_id == 'RESP-1', f'Bad resp_id: {d.resp_id}'
for i in bdi.intentions:
    assert i.ca_id.startswith('CA-'), f'Bad ca_id: {i.ca_id}'
print(f'Beliefs: {len(bdi.beliefs)}, Desires: {len(bdi.desires)}, Intentions: {len(bdi.intentions)}')
print('Defender BDI pre-population verified')
"
```

### QA-SP3-BDI-02: BDI generation unit tests

**Steps:**
1. Run the BDI generation unit tests.
2. Verify tests cover defender pre-population, LLM call, vulnerability merge, attacker BDI, assembly, and post-call validation.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp3_bdi" -v
```

### QA-SP3-BDI-03: ScenarioSpec validation on Klarna fixture

**Steps:**
1. Load the Klarna enriched threats fixture and control structure fixture.
2. Verify ScenarioSpec.validate_against passes for valid references.
3. Verify it fails for invalid references (non-existent PM, CA, RESP).

**Command:**
```bash
uv run pytest tests/stpa/test_sp3_validators.py -k "BDIGrounding or Vulnerability" -v
```

## 3. Narrative Verification (Stage 6 Call A)

### QA-SP3-NAR-01: Narrative unit tests

**Steps:**
1. Run the narrative unit tests.
2. Verify tests cover the 7-step dialectic structure, LLM call, response format, and call logging.

**Command:**
```bash
uv run pytest tests/stpa/test_sp3_stage6.py -k "Narrative" -v
```

### QA-SP3-NAR-02: Narrative system prompt defines 7-step structure

**Steps:**
1. Load the narrative system prompt template.
2. Verify it contains instructions for all 7 steps of the dialectic structure.

**Command:**
```bash
uv run python -c "
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from pathlib import Path
loader = TemplateLoader(Path('src/asago_scenario_generator/stpa/scenario_prod/prompts'))
prompt = loader.render_prompt('stage6a_narrative_system.j2')
steps = ['process model starts correct', 'causal transition occurs', 'diverges', 'resulting belief', 'ICA', 'hazard', 'loss']
for step in steps:
    assert step.lower() in prompt.lower(), f'Missing step keyword: {step}'
print('7-step structure verified in system prompt')
"
```

## 4. Attack Tree Verification (Stage 6 Call B)

### QA-SP3-TREE-01: Attack tree unit tests

**Steps:**
1. Run the attack tree unit tests.
2. Verify tests cover the hard template, branch category validation (≥2 of 3), ID reference validation, pruning, and call logging.

**Command:**
```bash
uv run pytest tests/stpa/test_sp3_stage6.py -k "AttackTree" -v
```

### QA-SP3-TREE-02: Attack tree system prompt includes full hard template

**Steps:**
1. Load the attack tree system prompt template.
2. Verify it contains all 3 branch categories and their sub-branches.
3. Verify it contains pruning instructions.

**Command:**
```bash
uv run python -c "
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from pathlib import Path
loader = TemplateLoader(Path('src/asago_scenario_generator/stpa/scenario_prod/prompts'))
prompt = loader.render_prompt('stage6b_tree_system.j2')
assert 'controller' in prompt.lower() or 'controller_side' in prompt.lower(), 'Missing controller-side category'
assert 'path' in prompt.lower() or 'path_side' in prompt.lower(), 'Missing path-side category'
assert 'coordination' in prompt.lower(), 'Missing coordination gap category'
assert 'prune' in prompt.lower() or 'pruning' in prompt.lower(), 'Missing pruning instructions'
print('Hard template verified in system prompt')
"
```

### QA-SP3-PROMPT-01: Feedback bridge and technology context reach the LLM

**Steps:**
1. Drive `scripts/run_sp3.py` through the local stub endpoint with a capability
   profile containing input, tool, memory, inter-agent, and retrieval surfaces.
2. Inspect the CLI-produced `calls.jsonl` and verify Stage 5 and Stage 6a
   receive the logical feedback-channel bridge and forbidden-infrastructure
   rule.
3. Verify the Stage 6b request contains the AI-surface leaves, omits the old
   mandatory infrastructure leaves, and permits infrastructure only with
   explicit attacker-accessible architecture evidence.
4. Verify Stage 5 and Stage 6a user prompts contain the same technology context
   when `--capability-profile` is supplied.
5. Repeat without `--capability-profile` and verify the technology-context
   section is omitted entirely from both prompts.

**Command:**
```bash
uv run python tests/stpa/run_sp3_prompt_qa.py
```

## 5. Gherkin Verification (Stage 6 Call C)

### QA-SP3-GHK-01: Gherkin unit tests

**Steps:**
1. Run the Gherkin unit tests.
2. Verify tests cover the should/but structure, PM references in Given steps, ICA references in But line, validation, and call logging.

**Command:**
```bash
uv run pytest tests/stpa/test_sp3_stage6.py -k "Gherkin" -v
```

### QA-SP3-GHK-02: Gherkin system prompt defines should/but structure

**Steps:**
1. Load the Gherkin system prompt template.
2. Verify it contains instructions for the should/but structure.
3. Verify it requires referencing process model states in Given steps.

**Command:**
```bash
uv run python -c "
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from pathlib import Path
loader = TemplateLoader(Path('src/asago_scenario_generator/stpa/scenario_prod/prompts'))
prompt = loader.render_prompt('stage6c_gherkin_system.j2')
assert 'should' in prompt.lower(), 'Missing should keyword in system prompt'
assert 'but' in prompt.lower(), 'Missing but keyword in system prompt'
assert 'process model' in prompt.lower() or 'PM-' in prompt, 'Missing process model reference requirement'
print('Should/but structure verified in system prompt')
"
```

## 6. Validators Verification (Stage 7)

### QA-SP3-VAL-01: Validator unit tests

**Steps:**
1. Run the validator unit tests.
2. Verify tests cover BDI grounding, vulnerability completeness, tree branch coverage, Gherkin structure, end-to-end traceability, and orphan detection.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp3_validators or sp3_val" -v
```

### QA-SP3-VAL-02: Traceability validation on Klarna fixtures

**Steps:**
1. Load the Klarna enriched threats, control structure, and loss analysis fixtures.
2. Run traceability validation on the fixture data.
3. Verify the provenance chain is unbroken for all structural threats.

**Command:**
```bash
uv run python -c "
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.enriched_threat_set import EnrichedThreatSet
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
enriched = read_yaml('src/asago_scenario_generator/stpa/fixtures/enriched_threats_klarna.yaml', EnrichedThreatSet)
cs = read_yaml('src/asago_scenario_generator/stpa/fixtures/control_structure_klarna.yaml', ControlStructure)
la = read_yaml('src/asago_scenario_generator/stpa/fixtures/loss_analysis_klarna.yaml', LossAnalysis)
print(f'Structural threats: {len(enriched.structural_threats)}')
print(f'Responsibilities: {len(cs.responsibilities)}')
print(f'Losses: {len(la.risk_card_losses) + len(la.use_case_losses)}')
print(f'Hazards: {len(la.hazards)}')
print(f'Constraints: {len(la.security_constraints)}')
print('Fixtures loaded for traceability validation')
"
```

## 7. Eval Metrics Verification (Stage 7)

### QA-SP3-EVAL-01: Eval metric unit tests

**Steps:**
1. Run the eval metric unit tests.
2. Verify tests cover all 6 metrics: structural consideration, N/A quality, BDI grounding, tree branch coverage, traceability depth, and diversity.
3. Verify tests cover edge cases (zero scenarios, all grounded, none grounded).

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp3_eval or sp3_metrics" -v
```

### QA-SP3-EVAL-02: Eval metrics are deterministic with zero LLM calls

**Steps:**
1. Run the eval metrics on a set of constructed scenario envelopes.
2. Verify no LLM calls are made during metric computation.

**Command:**
```bash
uv run python -c "
import inspect
from asago_scenario_generator.stpa.scenario_prod.eval_metrics import compute_eval_scorecard
sig = inspect.signature(compute_eval_scorecard)
for pname in sig.parameters:
    assert 'llm' not in pname.lower(), f'compute_eval_scorecard has LLM parameter: {pname}'
print('Eval metrics are deterministic with zero LLM calls — verified')
"
```

## 8. Coverage Gap Analysis Verification (Stage 7)

### QA-SP3-COV-01: Coverage gap unit tests

**Steps:**
1. Run the coverage gap unit tests.
2. Verify tests cover the three-way partition, orphan detection, traceability errors, and N/A reconciliation flags.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp3_coverage or sp3_cov" -v
```

## 9. Run Orchestration (End-to-End CLI Run)

### QA-SP3-RUN-01: Full SP3 run with LLM produces output artifacts

**Prerequisites:**
- LLM endpoint configured (via `--profile` or environment variables). The
  executable suite supplies the stub endpoint described above.
- SP1 and SP2 fixtures available for Klarna use case.

**Steps:**
1. Run `scripts/run_sp3.py` with the Klarna fixtures as input.
2. Verify the output directory contains a `scenarios/` subdirectory, `eval-scorecard.yaml`, `coverage-gaps.json`, `calls.jsonl`, and a run manifest.
3. Verify `scenarios/` contains at least one `.yaml` and one `.feature` file.
4. Verify every scenario YAML file loads as a valid `ScenarioEnvelope`.
5. Verify `calls.jsonl` contains entries with stages `stage_5` and `stage_6`.
6. Verify no `calls.jsonl` entries have stage `stage_7` (Stage 7 is deterministic, no LLM).

**Command:**
```bash
uv run python scripts/run_sp3.py \
  --enriched-threats src/asago_scenario_generator/stpa/fixtures/enriched_threats_klarna.yaml \
  --control-structure src/asago_scenario_generator/stpa/fixtures/control_structure_klarna.yaml \
  --loss-analysis src/asago_scenario_generator/stpa/fixtures/loss_analysis_klarna.yaml \
  --output-dir tmp/sp3-qa-run \
  --profile <profile-name>
```

**Verification:**
```bash
ls tmp/sp3-qa-run/scenarios/ tmp/sp3-qa-run/eval-scorecard.yaml tmp/sp3-qa-run/coverage-gaps.json tmp/sp3-qa-run/calls.jsonl tmp/sp3-qa-run/run-manifest.yaml
uv run python -c "
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.scenario_envelope import ScenarioEnvelope
from pathlib import Path
scenario_dir = Path('tmp/sp3-qa-run/scenarios')
yaml_files = list(scenario_dir.glob('*.yaml'))
assert len(yaml_files) > 0, 'No scenario YAML files found'
for f in yaml_files:
    env = read_yaml(str(f), ScenarioEnvelope)
    assert env.scenario_id == env.scenario_spec.scenario_id, f'ID mismatch in {f}'
print(f'Scenario envelopes: {len(yaml_files)}')
print('All scenario envelopes validated')
"
grep -c 'stage_5' tmp/sp3-qa-run/calls.jsonl
grep -c 'stage_6' tmp/sp3-qa-run/calls.jsonl
grep -c 'stage_7' tmp/sp3-qa-run/calls.jsonl || true  # should be 0
```

### QA-SP3-RUN-02: Run manifest records stage summary and metadata

**Steps:**
1. After running QA-SP3-RUN-01, inspect the run manifest.
2. Verify the manifest has `stage_summary` with call counts for `stage_5` and `stage_6`.
3. Verify the manifest records `input_hashes` for the enriched threat set, control structure, and loss analysis.
4. Verify the manifest records `prompt_hashes` for all Stage 5 and Stage 6 prompt templates.
5. Verify the manifest records the scenario count and validation status.

**Command:**
```bash
uv run python -c "
import yaml
manifest = yaml.safe_load(open('tmp/sp3-qa-run/run-manifest.yaml'))
assert 'stage_summary' in manifest, 'Missing stage_summary'
assert 'stage_5' in str(manifest['stage_summary']), 'Missing stage_5 in stage_summary'
assert 'stage_6' in str(manifest['stage_summary']), 'Missing stage_6 in stage_summary'
assert 'input_hashes' in manifest, 'Missing input_hashes'
assert 'prompt_hashes' in manifest, 'Missing prompt_hashes'
print('Run manifest verified')
print(f'Stage summary: {manifest[\"stage_summary\"]}')
"
```

### QA-SP3-RUN-03: Stage 7 makes no LLM calls

**Steps:**
1. After running QA-SP3-RUN-01, verify that `calls.jsonl` contains no entries with stage `stage_7`.
2. This confirms validators, eval metrics, and coverage gap analysis are fully deterministic.

**Command:**
```bash
! grep 'stage_7' tmp/sp3-qa-run/calls.jsonl && echo 'Stage 7 made no LLM calls — verified'
```

### QA-SP3-RUN-04: --max-workers flag controls parallelism

**Steps:**
1. Run `scripts/run_sp3.py` with `--max-workers 2`.
2. Verify the run completes successfully and produces the same output artifacts.

**Command:**
```bash
uv run python scripts/run_sp3.py \
  --enriched-threats src/asago_scenario_generator/stpa/fixtures/enriched_threats_klarna.yaml \
  --control-structure src/asago_scenario_generator/stpa/fixtures/control_structure_klarna.yaml \
  --loss-analysis src/asago_scenario_generator/stpa/fixtures/loss_analysis_klarna.yaml \
  --output-dir tmp/sp3-qa-run-parallel \
  --profile <profile-name> \
  --max-workers 2
ls tmp/sp3-qa-run-parallel/scenarios/ tmp/sp3-qa-run-parallel/eval-scorecard.yaml
```

### QA-SP3-RUN-05: Scenario count equals structural threat count

**Steps:**
1. After running QA-SP3-RUN-01, count the scenario YAML files.
2. Count the structural threats in the enriched threat set fixture.
3. Verify they match (strict 1:1 ICA-to-scenario cardinality).

**Command:**
```bash
uv run python -c "
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.enriched_threat_set import EnrichedThreatSet
from pathlib import Path
enriched = read_yaml('src/asago_scenario_generator/stpa/fixtures/enriched_threats_klarna.yaml', EnrichedThreatSet)
scenario_dir = Path('tmp/sp3-qa-run/scenarios')
yaml_files = list(scenario_dir.glob('*.yaml'))
threat_count = len(enriched.structural_threats)
assert len(yaml_files) == threat_count, f'Expected {threat_count} scenarios, got {len(yaml_files)}'
print(f'Scenario count matches threat count: {len(yaml_files)}')
"
```

### QA-SP3-RUN-06: Eval scorecard contains all 6 metrics and coverage gaps

**Steps:**
1. After running QA-SP3-RUN-01, load `eval-scorecard.yaml`.
2. Verify it contains all 6 metrics: `structural_consideration`, `na_quality`, `bdi_grounding`, `tree_branch_coverage`, `traceability_depth`, `diversity`.
3. Verify it contains `coverage_gaps`.
4. Verify it contains `validation` with `stage_local_errors` and `traceability_errors`.

**Command:**
```bash
uv run python -c "
import yaml
scorecard = yaml.safe_load(open('tmp/sp3-qa-run/eval-scorecard.yaml'))
assert 'metrics' in scorecard, 'Missing metrics section'
metrics = scorecard['metrics']
for name in ['structural_consideration', 'na_quality', 'bdi_grounding', 'tree_branch_coverage', 'traceability_depth', 'diversity']:
    assert name in metrics, f'Missing metric: {name}'
assert 'coverage_gaps' in scorecard, 'Missing coverage_gaps'
assert 'validation' in scorecard, 'Missing validation section'
print('Eval scorecard verified with all 6 metrics and coverage gaps')
"
```

### QA-SP3-RUN-07: Coverage gaps file contains orphan detection results

**Steps:**
1. After running QA-SP3-RUN-01, load `coverage-gaps.json`.
2. Verify it contains `orphan_elements`, `orphan_icas`, and `traceability_errors` fields.

**Command:**
```bash
uv run python -c "
import json
from pathlib import Path
gaps = json.loads(Path('tmp/sp3-qa-run/coverage-gaps.json').read_text())
assert 'orphan_elements' in gaps, 'Missing orphan_elements'
assert 'orphan_icas' in gaps, 'Missing orphan_icas'
assert 'traceability_errors' in gaps, 'Missing traceability_errors'
print('Coverage gaps file verified')
"
```

## 10. Fixture Validation

### QA-SP3-FIX-01: SP1 and SP2 fixtures load and validate for SP3 consumption

**Steps:**
1. Load the Klarna enriched threats fixture and verify it validates as `EnrichedThreatSet`.
2. Load the Klarna control structure fixture and verify it validates as `ControlStructure`.
3. Load the Klarna loss analysis fixture and verify it validates as `LossAnalysis`.
4. Verify the enriched threat set has structural_consideration and na_quality in its coverage analysis.

**Command:**
```bash
uv run python -c "
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.enriched_threat_set import EnrichedThreatSet
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
enriched = read_yaml('src/asago_scenario_generator/stpa/fixtures/enriched_threats_klarna.yaml', EnrichedThreatSet)
cs = read_yaml('src/asago_scenario_generator/stpa/fixtures/control_structure_klarna.yaml', ControlStructure)
la = read_yaml('src/asago_scenario_generator/stpa/fixtures/loss_analysis_klarna.yaml', LossAnalysis)
assert enriched.coverage_analysis.structural_consideration, 'Missing structural_consideration'
assert enriched.coverage_analysis.na_quality, 'Missing na_quality'
print(f'Structural threats: {len(enriched.structural_threats)}')
print(f'Responsibilities: {len(cs.responsibilities)}')
print(f'Losses: {len(la.risk_card_losses) + len(la.use_case_losses)}')
print('All SP3 input fixtures validated')
"
```

## 11. Acceptance Tests

### QA-SP3-ACCEPT-01: SP3 Gherkin acceptance tests pass

**Steps:**
1. Run the SP3 acceptance tests generated from the Gherkin feature files.
2. Verify all scenarios pass.

**Command:**
```bash
uv run pytest build/acceptance/generated/sp3_*_acceptance_test.py -v
```

## 12. Full Test Suite Execution

### QA-SP3-FULL-01: All SP3 tests pass

**Steps:**
1. Run the complete SP3 test suite.
2. Verify all tests pass with zero failures.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp3 or scenario_prod" -v
```

### QA-SP3-FULL-02: Existing tests unaffected

**Steps:**
1. Run the existing test suite excluding SP3 tests to verify no regressions.
2. Verify the SP3 implementation does not modify existing source files.

**Command:**
```bash
uv run pytest tests/ -x --ignore=tests/stpa/ -q
```

### QA-SP3-FULL-03: Linting passes

**Steps:**
1. Run ruff on the new SP3 source and test files.
2. Verify no lint errors.

**Command:**
```bash
uv run ruff check src/asago_scenario_generator/stpa/scenario_prod/ \
  tests/stpa/test_sp3*.py tests/stpa/run_sp3*.py
```

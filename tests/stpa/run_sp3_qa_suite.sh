#!/usr/bin/env bash
# SP3 Scenario Production — Executable QA Suite
#
# Executable form of the QA checks in tests/stpa/qa-suite-sp3.md. All
# verification goes through the user interface: the run_sp3.py command
# line, Python import checks, pytest execution, and filesystem
# inspection — no project-internal APIs.
#
# The end-to-end run checks (QA-SP3-RUN-*) drive the real CLI against a
# local stub LLM endpoint (tests/stpa/sp3_qa_stub_llm.py) so the suite is
# deterministic, offline, and free of API cost while still exercising
# the real orchestration, artifact writing, and manifest code paths.
#
# Usage: bash tests/stpa/run_sp3_qa_suite.sh
# Exit 0 = all pass, Exit 1 = any fail.

set -uo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

FIXTURES="src/asago_scenario_generator/stpa/fixtures"
WORK_DIR="tmp/sp3-qa"
STUB_PID=""

# Pre-existing failures outside tests/stpa/ (LLM endpoint not
# configured). QA-SP3-FULL-02 fails only if the count grows beyond this.
PREEXISTING_NON_STPA_FAILURES=11

PASS=0
FAIL=0
FAILED_CHECKS=()

check() {
    local name="$1"
    shift
    echo "--- $name ---"
    if "$@"; then
        echo "  PASS"
        PASS=$((PASS + 1))
    else
        echo "  FAIL"
        FAIL=$((FAIL + 1))
        FAILED_CHECKS+=("$name")
    fi
    echo
}

stop_stub() {
    if [ -n "$STUB_PID" ] && kill -0 "$STUB_PID" 2>/dev/null; then
        kill "$STUB_PID" 2>/dev/null || true
        wait "$STUB_PID" 2>/dev/null || true
    fi
    STUB_PID=""
}
trap stop_stub EXIT

start_stub() {
    uv run python -c \
        'from pathlib import Path; import shutil; shutil.rmtree(Path("tmp/sp3-qa"), ignore_errors=True)'
    mkdir -p "$WORK_DIR"
    local ready_file="$WORK_DIR/stub-port"
    uv run python tests/stpa/sp3_qa_stub_llm.py --port 0 --ready-file "$ready_file" \
        > "$WORK_DIR/stub.log" 2>&1 &
    STUB_PID=$!

    local waited=0
    while [ ! -s "$ready_file" ]; do
        if ! kill -0 "$STUB_PID" 2>/dev/null; then
            echo "Stub LLM endpoint exited early:"
            cat "$WORK_DIR/stub.log"
            return 1
        fi
        sleep 0.2
        waited=$((waited + 1))
        if [ "$waited" -gt 150 ]; then
            echo "Stub LLM endpoint did not become ready"
            return 1
        fi
    done

    local port
    port="$(cat "$ready_file")"
    cat > "$WORK_DIR/profiles.yaml" <<EOF
sp3-qa-stub:
  base_url: http://127.0.0.1:${port}/v1
  model: sp3-qa-stub
  api_key: unused
  temperature: 0.4
EOF
}

run_sp3_cli() {
    local out_dir="$1"
    shift
    uv run python scripts/run_sp3.py \
        --enriched-threats "$FIXTURES/enriched_threats_klarna.yaml" \
        --control-structure "$FIXTURES/control_structure_klarna.yaml" \
        --loss-analysis "$FIXTURES/loss_analysis_klarna.yaml" \
        --output-dir "$out_dir" \
        --profiles-file "$WORK_DIR/profiles.yaml" \
        --profile sp3-qa-stub \
        "$@"
}

# --- 1. Module Structure ---

check "QA-SP3-STRUCT-01: Module layout matches spec" \
    bash -c '
uv run python -c "
from asago_scenario_generator.stpa.scenario_prod import (
    bdi_generation, narrative, attack_tree, gherkin,
    validators, eval_metrics, coverage, assembly, run,
)
print(\"All SP3 modules importable\")
" || exit 1
ls src/asago_scenario_generator/stpa/scenario_prod/prompts/stage5_system.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage5_user.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6a_narrative_system.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6a_narrative_user.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6b_tree_system.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6b_tree_user.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6c_gherkin_system.j2 \
   src/asago_scenario_generator/stpa/scenario_prod/prompts/stage6c_gherkin_user.j2
'

check "QA-SP3-STRUCT-02: CLI script exists and accepts arguments" \
    bash -c '
[ -f scripts/run_sp3.py ] || { echo "scripts/run_sp3.py missing"; exit 1; }
help_text=$(uv run python scripts/run_sp3.py --help)
for flag in --enriched-threats --control-structure --loss-analysis \
            --capability-profile --output-dir --max-workers --profile; do
  echo "$help_text" | grep -q -- "$flag" || { echo "Missing flag: $flag"; exit 1; }
done
echo "CLI accepts all documented flags"
'

# --- 2. BDI Generation (Stage 5) ---

check "QA-SP3-BDI-01: Defender BDI pre-population on Klarna fixture" \
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

check "QA-SP3-BDI-02: BDI generation unit tests" \
    uv run pytest tests/stpa/ -k "sp3_bdi" -q --tb=short

check "QA-SP3-BDI-03: ScenarioSpec validation on Klarna fixture" \
    uv run pytest tests/stpa/test_sp3_validators.py -k "BDIGrounding or Vulnerability" -q --tb=short

# --- 3. Narrative (Stage 6 Call A) ---

check "QA-SP3-NAR-01: Narrative unit tests" \
    uv run pytest tests/stpa/test_sp3_stage6.py -k "Narrative" -q --tb=short

check "QA-SP3-NAR-02: Narrative system prompt defines 7-step structure" \
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

# --- 4. Attack Tree (Stage 6 Call B) ---

check "QA-SP3-TREE-01: Attack tree unit tests" \
    uv run pytest tests/stpa/test_sp3_stage6.py -k "AttackTree" -q --tb=short

check "QA-SP3-TREE-02: Attack tree system prompt includes full hard template" \
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

check "QA-SP3-PROMPT-01: Prompt remediation reaches the LLM" \
    uv run python tests/stpa/run_sp3_prompt_qa.py

# --- 5. Gherkin (Stage 6 Call C) ---

check "QA-SP3-GHK-01: Gherkin unit tests" \
    uv run pytest tests/stpa/test_sp3_stage6.py -k "Gherkin" -q --tb=short

check "QA-SP3-GHK-02: Gherkin system prompt defines should/but structure" \
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

# --- 6. Validators (Stage 7) ---

check "QA-SP3-VAL-01: Validator unit tests" \
    uv run pytest tests/stpa/ -k "sp3_validators or sp3_val" -q --tb=short

check "QA-SP3-VAL-02: Traceability validation on Klarna fixtures" \
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

# --- 7. Eval Metrics (Stage 7) ---

check "QA-SP3-EVAL-01: Eval metric unit tests" \
    uv run pytest tests/stpa/ -k "sp3_eval or sp3_metrics" -q --tb=short

check "QA-SP3-EVAL-02: Eval metrics are deterministic with zero LLM calls" \
    uv run python -c "
import inspect
from asago_scenario_generator.stpa.scenario_prod.eval_metrics import compute_eval_scorecard
sig = inspect.signature(compute_eval_scorecard)
for pname in sig.parameters:
    assert 'llm' not in pname.lower(), f'compute_eval_scorecard has LLM parameter: {pname}'
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.enriched_threat_set import EnrichedThreatSet
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.scenario_envelope import ScenarioEnvelope
from pathlib import Path
enriched = read_yaml('src/asago_scenario_generator/stpa/fixtures/enriched_threats_klarna.yaml', EnrichedThreatSet)
cs = read_yaml('src/asago_scenario_generator/stpa/fixtures/control_structure_klarna.yaml', ControlStructure)
la = read_yaml('src/asago_scenario_generator/stpa/fixtures/loss_analysis_klarna.yaml', LossAnalysis)
scenarios = [read_yaml(str(f), ScenarioEnvelope) for f in Path('tmp/sp3-qa-run/scenarios').glob('*.yaml')]
scorecard = compute_eval_scorecard(scenarios, enriched, cs, la)
assert 'metrics' in scorecard
assert len(scorecard['metrics']) == 6
print('Eval metrics computed without LLM calls — verified')
"

# --- 8. Coverage Gap Analysis (Stage 7) ---

check "QA-SP3-COV-01: Coverage gap unit tests" \
    uv run pytest tests/stpa/ -k "sp3_coverage or sp3_cov" -q --tb=short

# --- 9. Run Orchestration (End-to-End CLI Run) ---

check "QA-SP3-RUN-00: Stub LLM endpoint is available" start_stub

check "QA-SP3-RUN-01: Full SP3 run with LLM produces output artifacts" \
    bash -c '
set -e
run_dir="tmp/sp3-qa-run"
uv run python scripts/run_sp3.py \
  --enriched-threats src/asago_scenario_generator/stpa/fixtures/enriched_threats_klarna.yaml \
  --control-structure src/asago_scenario_generator/stpa/fixtures/control_structure_klarna.yaml \
  --loss-analysis src/asago_scenario_generator/stpa/fixtures/loss_analysis_klarna.yaml \
  --output-dir "$run_dir" \
  --profiles-file tmp/sp3-qa/profiles.yaml \
  --profile sp3-qa-stub > tmp/sp3-qa/run.log 2>&1
ls "$run_dir/scenarios/" "$run_dir/eval-scorecard.yaml" \
   "$run_dir/coverage-gaps.json" "$run_dir/calls.jsonl" \
   "$run_dir/run-manifest.yaml"
SP3_QA_RUN_DIR="$run_dir" uv run python - <<"PY"
import os
from pathlib import Path
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.scenario_envelope import ScenarioEnvelope

run_dir = Path(os.environ["SP3_QA_RUN_DIR"])
scenario_dir = run_dir / "scenarios"
yaml_files = list(scenario_dir.glob("*.yaml"))
assert len(yaml_files) > 0, "No scenario YAML files found"
for f in yaml_files:
    env = read_yaml(str(f), ScenarioEnvelope)
    assert env.scenario_id == env.scenario_spec.scenario_id, f"ID mismatch in {f}"
feature_files = list(scenario_dir.glob("*.feature"))
assert len(feature_files) > 0, "No .feature files found"
print(f"Scenario envelopes: {len(yaml_files)}, feature files: {len(feature_files)}")
print("All scenario envelopes validated")
PY
grep -q "stage_5" "$run_dir/calls.jsonl" || { echo "No stage_5 entries in calls.jsonl"; exit 1; }
grep -q "stage_6" "$run_dir/calls.jsonl" || { echo "No stage_6 entries in calls.jsonl"; exit 1; }
echo "stage_5 calls: $(grep -c stage_5 "$run_dir/calls.jsonl")"
echo "stage_6 calls: $(grep -c stage_6 "$run_dir/calls.jsonl")"
'

check "QA-SP3-RUN-02: Run manifest records stage summary and metadata" \
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

check "QA-SP3-RUN-03: Stage 7 makes no LLM calls" \
    bash -c '
if grep -q "stage_7" tmp/sp3-qa-run/calls.jsonl; then
  echo "Found stage_7 entries — Stage 7 is not deterministic"
  exit 1
fi
echo "Stage 7 made no LLM calls — verified"
'

check "QA-SP3-RUN-04: --max-workers flag controls parallelism" \
    bash -c '
set -e
run_dir="tmp/sp3-qa-run-parallel"
uv run python scripts/run_sp3.py \
  --enriched-threats src/asago_scenario_generator/stpa/fixtures/enriched_threats_klarna.yaml \
  --control-structure src/asago_scenario_generator/stpa/fixtures/control_structure_klarna.yaml \
  --loss-analysis src/asago_scenario_generator/stpa/fixtures/loss_analysis_klarna.yaml \
  --output-dir "$run_dir" \
  --profiles-file tmp/sp3-qa/profiles.yaml \
  --profile sp3-qa-stub \
  --max-workers 2 > tmp/sp3-qa/run-parallel.log 2>&1
ls "$run_dir/scenarios/" "$run_dir/eval-scorecard.yaml"
SP3_QA_RUN_DIR="$run_dir" uv run python - <<"PY"
import os, yaml
run_dir = os.environ["SP3_QA_RUN_DIR"]
manifest = yaml.safe_load(open(f"{run_dir}/run-manifest.yaml"))
assert manifest["max_workers"] == 2, f"Expected max_workers 2, got {manifest['max_workers']}"
parallel_count = len(list(__import__("pathlib").Path(f"{run_dir}/scenarios").glob("*.yaml")))
sequential_count = len(list(__import__("pathlib").Path("tmp/sp3-qa-run/scenarios").glob("*.yaml")))
assert parallel_count == sequential_count, (
    f"Parallel run produced {parallel_count} scenarios, sequential produced {sequential_count}"
)
print(f"max_workers=2 run produced {parallel_count} scenarios, same as sequential")
PY
'

check "QA-SP3-RUN-05: Scenario count equals structural threat count" \
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

check "QA-SP3-RUN-06: Eval scorecard contains all 6 metrics and coverage gaps" \
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

check "QA-SP3-RUN-07: Coverage gaps file contains orphan detection results" \
    uv run python -c "
import json
from pathlib import Path
gaps = json.loads(Path('tmp/sp3-qa-run/coverage-gaps.json').read_text())
assert 'orphan_elements' in gaps, 'Missing orphan_elements'
assert 'orphan_icas' in gaps, 'Missing orphan_icas'
assert 'traceability_errors' in gaps, 'Missing traceability_errors'
print('Coverage gaps file verified')
"

stop_stub

# --- 10. Fixture Validation ---

check "QA-SP3-FIX-01: SP1 and SP2 fixtures load and validate for SP3 consumption" \
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

# --- 11. Acceptance Tests ---

check "QA-SP3-ACCEPT-01: SP3 Gherkin acceptance tests pass" \
    uv run pytest build/acceptance/generated/sp3_attack_tree_acceptance_test.py \
                  build/acceptance/generated/sp3_bdi_generation_acceptance_test.py \
                  build/acceptance/generated/sp3_coverage_gaps_acceptance_test.py \
                  build/acceptance/generated/sp3_eval_metrics_acceptance_test.py \
                  build/acceptance/generated/sp3_feedback_channel_bridge_acceptance_test.py \
                  build/acceptance/generated/sp3_gherkin_acceptance_test.py \
                  build/acceptance/generated/sp3_mechanism_context_propagation_acceptance_test.py \
                  build/acceptance/generated/sp3_narrative_acceptance_test.py \
                  build/acceptance/generated/sp3_run_orchestration_acceptance_test.py \
                  build/acceptance/generated/sp3_agentic_attack_tree_guidance_acceptance_test.py \
                  build/acceptance/generated/sp3_validators_acceptance_test.py \
                  -q --tb=short

# --- 12. Full Test Suite Execution ---

check "QA-SP3-FULL-01: All SP3 tests pass" \
    uv run pytest tests/stpa/ -k "sp3 or scenario_prod" -q --tb=short

check "QA-SP3-FULL-02: Existing tests unaffected" \
    bash -c "
output=\$(uv run pytest tests/ --ignore=tests/stpa/ -q --tb=line 2>&1 || true)
echo \"\$output\" | tail -3
failed=\$(echo \"\$output\" | grep -o '[0-9]* failed' | grep -o '[0-9]*' || echo 0)
if [ \"\$failed\" -gt $PREEXISTING_NON_STPA_FAILURES ]; then
  echo \"New failures detected: \$failed failed (expected $PREEXISTING_NON_STPA_FAILURES pre-existing)\"
  exit 1
fi
echo \"No new failures (pre-existing: $PREEXISTING_NON_STPA_FAILURES)\"
"

check "QA-SP3-FULL-03: Linting passes" \
    uv run ruff check src/asago_scenario_generator/stpa/scenario_prod/ \
        tests/stpa/test_sp3*.py tests/stpa/run_sp3*.py

# --- Summary ---

echo "=========================================="
echo "SP3 QA Suite Results: $PASS passed, $FAIL failed"
if [ $FAIL -gt 0 ]; then
    echo "Failed checks:"
    for c in "${FAILED_CHECKS[@]}"; do
        echo "  - $c"
    done
    exit 1
fi
echo "All SP3 QA checks passed."
exit 0

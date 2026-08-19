# End-to-end QA: acceptance pipeline preservation

Run from a fresh tracked-source checkout. Use only checked-in command-line
entrypoints and shell-visible files; do not import project modules. Provision
the pinned APS checkout documented by `config/swarmforge.env`, unset
`ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL`, and capture stdout, stderr, exit
status, and generated file inventories.

## QA-APP-01: generate and execute acceptance from nothing

1. Confirm `build/acceptance/` is absent.
2. Run `./scripts/acceptance.sh`.
3. Verify exit status `0`.
4. For every `.feature` beneath `features/`, verify one mapped JSON IR, DRY
   report, generated pytest entrypoint, and metadata file exists beneath the
   configured generated directories.
5. Verify command output shows the generated acceptance tests executed.

## QA-APP-02: generated entrypoint validation

1. After QA-APP-01, inventory executable IR JSON files and generated
   `*_acceptance_test.py` files.
2. Verify every IR path appears in exactly one generated entrypoint.
3. Verify every IR path named by a generated entrypoint exists.
4. Verify every named IR is beneath the configured generated IR directory.
5. Run `./scripts/acceptance.sh --test` and verify exit status `0`.

## QA-APP-03: CI prerequisite separation

1. Inspect the user-visible commands in `.github/workflows/ci.yml`.
2. Verify the unit job invokes the documented unit suite without first
   invoking acceptance generation.
3. Verify the unit job does not provision APS tools.
4. Verify the acceptance job provisions the pinned APS revision and invokes
   the documented acceptance command, which generates artifacts before
   executing them.
5. Verify neither job configures a model endpoint.

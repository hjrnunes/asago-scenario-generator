# End-to-end QA: clean-checkout unit independence

Run only documented shell and test-runner entrypoints. Do not import project
modules. Create each checkout beneath `tmp/qa-clean-checkout/` from tracked
source only, without copying `build/`, `.cache/`, `tmp/`, or a local virtual
environment. Capture commands, stdout, stderr, exit status, and generated file
inventories.

Run the executable form with:

```bash
uv run python acceptance/qa/clean_checkout_unit_independence.py
```

## QA-CUI-01: complete unit suite from source only

1. Create a fresh tracked-source checkout and run `uv sync --locked`.
2. Confirm `build/acceptance/`, `acceptance/ir/`, `acceptance/generated/`, and
   an APS checkout are absent.
3. Unset `ASAGO_SCENARIO_GENERATOR_APS_ROOT`,
   `ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL`, and
   `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.
4. Run `uv run pytest tests/ -q`.
5. Verify exit status `0` and verify the generated acceptance paths from step
   2 remain absent.

## QA-CUI-02: order-independent acceptance infrastructure unit tests

1. In a fresh tracked-source checkout with the same unset environment, run:
   `uv run pytest tests/stpa/test_acceptance_snapshot.py
   tests/stpa/test_acceptance_harness_property.py -q`.
2. Verify exit status `0` and verify no repository generated acceptance path
   was created.
3. Repeat in another fresh tracked-source checkout with the two test paths in
   reverse order.
4. Verify the second command also exits `0` with no repository generated
   acceptance path.

## QA-CUI-03: generated-output ignore boundary

1. From the repository checkout, use `git check-ignore -v` on representative
   IR, DRY report, generated entrypoint, and metadata paths beneath
   `build/acceptance/`.
2. Verify every representative path is ignored.
3. Run `git ls-files` for `build/acceptance/`, `acceptance/ir/`, and
   `acceptance/generated/`.
4. Verify the command reports no generated acceptance artifacts.

## QA-CUI-04: CI prerequisite separation

1. Inspect `.github/workflows/ci.yml`.
2. Verify the unit job runs the documented unit suite without checking out or
   invoking the Acceptance Pipeline Specification.
3. Verify the acceptance job owns the pinned APS checkout and invokes the
   acceptance command separately.

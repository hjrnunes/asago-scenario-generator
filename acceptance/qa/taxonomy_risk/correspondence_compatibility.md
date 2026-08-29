# Correspondence compatibility QA

Run:

    uv run python acceptance/qa/taxonomy_risk/correspondence_compatibility.py

The driver runs both public workflows as real subprocesses twice: once with
the normal fixture and once with valid Phase 2 sidecars present beside the
inputs. It compares exit status, normalized scenario artifacts, public
generation counts, and the exact selected prompt contracts. Normalization is
limited to documented run-local IDs, timestamps, and duration telemetry. The
sidecars are never passed as workflow options and no Phase 2 artifact may be
written to either workflow's output.

The fixture uses a localhost deterministic responder for `generate` and
resume-mode artifacts for `stpa-run`; it never enables the live-model QA path.
Both workflows remain independent and offline.

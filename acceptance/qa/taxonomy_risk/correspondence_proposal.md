# Correspondence proposal QA

Run:

    uv run python acceptance/qa/taxonomy_risk/correspondence_proposal.py

The external driver invokes only the public propose-correspondence command, reads system-resource-map.yaml, supplies a closed typed authority/evidence payload, and inspects correspondence-proposals.yaml using a standard YAML reader. It verifies semantic proposal IDs, the normative relation vocabulary, typed provenance, and that no adjudication/status or legacy left_ref/right_ref fields are emitted. It never imports production modules or enables the live-model QA path.

The committed acceptance feature additionally checks the deterministic
resource-link evidence adapter. It must use an exact candidate binding and an
authoritative resource-map link as its witness, emit
`related_but_not_coverage`, and never emit a coverage-bearing relation from
shared resource identity alone.

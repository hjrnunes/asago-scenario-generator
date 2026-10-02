#!/usr/bin/env python3
"""Runner adapter for gherkin-mutator.

Persistent worker that reads mutation job requests from stdin (one JSON
object per line) and writes job responses to stdout (one JSON object per
line).

Job request:
    {"id": "m1", "feature_json": "path/to/feature.json", ...}

Job response:
    {"id": "m1", "outcome": "test_success|test_failure|infrastructure_error", ...}
"""

from __future__ import annotations

import json
import subprocess
import sys

from runner_protocol import responses, run_mutation_job


def run_job(job: dict) -> dict:
    """Compatibility facade for one mutation job."""
    return run_mutation_job(job, command_runner=subprocess.run)


def main() -> int:
    """Main loop: read jobs from stdin, write responses to stdout."""
    # Write startup message to stderr
    print("runner_adapter: ready", file=sys.stderr, flush=True)

    for response in responses(sys.stdin, run_job):
        print(json.dumps(response), flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())

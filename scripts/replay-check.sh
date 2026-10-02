#!/usr/bin/env bash
# Replay each recorded `run` output directory through this checkout, offline,
# and compare every output file. Exits non-zero if any replay differs.
#
#   ./scripts/replay-check.sh RECORDED_OUTPUT_DIR [RECORDED_OUTPUT_DIR ...]
#
# See docs/development/replay-gate.md.
set -uo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [ "$#" -eq 0 ]; then
  echo "usage: $0 RECORDED_OUTPUT_DIR [RECORDED_OUTPUT_DIR ...]" >&2
  exit 2
fi

status=0
for recorded in "$@"; do
  echo "== $recorded"
  # --no-sync: a plain sync would drop optional extras this checkout relies on.
  if ! env -u FORCE_COLOR uv run --no-sync python -m asago_scenario_generator.replay_gate \
    check "$recorded"; then
    status=1
  fi
done
exit "$status"

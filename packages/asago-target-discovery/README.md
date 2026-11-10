# asago-target-discovery

The producer's MCP target-discovery scanner. It lists a target's tools over MCP
or reads a saved `tools/list` result, asks the model for the meaning of each
tool and writes the target profile, the planted-item runtime contract and the
call log beside it.

The scanner reads the producer's STPA models, so it is a member of the
producer's workspace and depends on the `asago-scenario-generator` app. The app
in turn lists this member behind its `target-discovery` extra, which is also
the extra that installs the optional `mcp` SDK. A plain `uv sync --locked`
installs this member through the app's dev group; the MCP transport needs
`uv sync --locked --all-extras`, or `--extra target-discovery`.

## Commands

```bash
uv sync --locked --all-extras
uv run asago-target-scan --help
uv run pytest packages/asago-target-discovery/tests -q
```

`asago-target-scan mcp` connects to a running MCP server. `asago-target-scan
file` reads a saved `tools/list` result, which keeps the declared targets
offline. See the repository README for the full commands and flags.

## Layout

- `src/asago_target_discovery/` holds the scanner modules. The package root
  loads each name on first use (PEP 562).
- `src/asago_target_discovery/model_adapter.py` is the one seam the scanner uses
  to reach the provider client and the MCP transport;
  `llm_interpreter.py` renders its own prompt templates and belongs to that
  seam as well.
- `tests/` holds the suite. The app's `tests/` run does not include it; run it
  in its own pytest session.

The pre-move import path `asago_scenario_generator.target_discovery` is gone;
import `asago_target_discovery`.

"""Invoke the artifact CLI with a named scenario profile and local call evidence.

This opt-in qualification adapter does not change compilation or authoring.
Pass artifact CLI arguments after ``--``. Its log records provider inputs and
the actual parsed return value, not a reconstruction of the raw HTTP response.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import monotonic

from asago_artifact_generator import cli, llm
from asago_scenario_generator.model_profiles import load_profile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--call-log", type=Path, required=True)
    parser.add_argument("artifact_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    profile = load_profile(args.profiles, args.profile)
    llm.configure_llm(
        provider="openai",
        base_url=profile["base_url"],
        api_key=profile.get("api_key") or "not-required",
        model=profile["model"],
    )
    original = llm.llm_json
    args.call_log.parent.mkdir(parents=True, exist_ok=True)

    def logged_call(*positional, **keywords):
        started = monotonic()
        record = {
            "model": profile["model"],
            "positional_inputs": positional,
            "keyword_inputs": keywords,
            "response_representation": "actual_parsed_provider_return",
        }
        try:
            result = original(*positional, **keywords)
            record["response"] = result
            return result
        except Exception as error:
            record["error_type"] = type(error).__name__
            raise
        finally:
            record["duration_seconds"] = monotonic() - started
            with args.call_log.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")

    llm.llm_json = logged_call
    forwarded = args.artifact_args
    if forwarded[:1] == ["--"]:
        forwarded = forwarded[1:]
    cli.app(args=forwarded)


if __name__ == "__main__":
    main()

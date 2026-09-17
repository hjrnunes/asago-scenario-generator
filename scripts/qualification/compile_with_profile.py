"""Invoke the artifact CLI with a named scenario profile and local call evidence.

This opt-in qualification adapter does not change compilation or authoring.
Pass artifact CLI arguments after ``--``. Its log records provider inputs and
the actual parsed return value, not a reconstruction of the raw HTTP response.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from time import monotonic
from typing import Any

from asago_artifact_generator import cli, llm
from asago_scenario_generator.model_profiles import load_profile


_URL_VALUE = re.compile(r"https?://[^\s\"')]+", re.IGNORECASE)
_ENDPOINT_KEY = re.compile(r"(?i)(?:base[-_]?url|endpoint|url)")


def _safe_log_value(value: Any) -> Any:
    """Remove connection locators from qualification call evidence."""
    if isinstance(value, dict):
        return {
            str(key): "[redacted]"
            if _ENDPOINT_KEY.search(str(key))
            else _safe_log_value(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_safe_log_value(item) for item in value]
    if isinstance(value, str):
        return _URL_VALUE.sub("[redacted-url]", value)
    return value


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
            "positional_inputs": _safe_log_value(positional),
            "keyword_inputs": _safe_log_value(keywords),
            "response_representation": "actual_parsed_provider_return",
        }
        try:
            result = original(*positional, **keywords)
            record["response"] = _safe_log_value(result)
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

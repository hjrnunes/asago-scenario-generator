"""A provider response that decodes to a list keeps JSON evidence and a pin."""

from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.call_log import make_call_log_entry


class _Row(BaseModel):
    row_id: str
    note: str | None = None


def test_list_raw_response_is_logged_as_json_rows_with_a_framed_pin() -> None:
    entry = make_call_log_entry(
        stage="stage_2",
        step="call_2a_responsibilities",
        model="test-model",
        raw_response=[_Row(row_id="R-1"), ({"nested": _Row(row_id="R-2")},)],
    )

    expected = [
        {"row_id": "R-1", "note": None},
        [{"nested": {"row_id": "R-2", "note": None}}],
    ]
    assert entry["raw_response"] == expected
    json.dumps(entry)
    payload = json.dumps(
        expected, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    assert (
        entry["raw_response_pin"]
        == hashlib.sha256(
            f"stpa-provider-raw-response-v1\n{payload}".encode()
        ).hexdigest()
    )

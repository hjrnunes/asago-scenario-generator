"""Declared tools/list file adapter and the ``asago-target-scan file`` command."""

from __future__ import annotations

import copy
import json
import socket
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    InventoryAuthority,
    InventoryCompleteness,
    McpInventoryObservation,
)
from asago_scenario_generator.target_discovery import (
    McpInventoryPage,
    McpTargetDiscoveryInputs,
    discover_mcp_target,
    write_target_discovery,
)
from asago_scenario_generator.target_discovery.cli import app
from asago_scenario_generator.target_discovery.transport import (
    FileMcpInventoryAdapter,
    HttpMcpInventoryAdapter,
    McpToolsListFileError,
)
from tests.cli_helpers import PlainCliRunner
from tests.helpers.target_discovery import FakeMcpSdk, install_fake_mcp_sdk


FIXTURE = (
    Path(__file__).parents[2] / "data/contracts/target-discovery/mcp-tools-list.json"
)
ANNOTATIONS = {
    "lookup_order": {"readOnlyHint": True, "openWorldHint": False},
    "process_refund": {
        "title": "Refund",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
}


def _recorded_tools() -> list[dict[str, Any]]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["tools"]


def _annotated_tools() -> list[dict[str, Any]]:
    tools = _recorded_tools()
    for tool in tools:
        if tool["name"] in ANNOTATIONS:
            tool["annotations"] = ANNOTATIONS[tool["name"]]
    return tools


def _write(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _inputs() -> McpTargetDiscoveryInputs:
    return McpTargetDiscoveryInputs(
        target_id="mini-klarna-safe", authorization_scope_id="test-customer"
    )


def _paged(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"tools": tools[:3], "nextCursor": "page-2"},
        {"tools": tools[3:5], "nextCursor": "page-3"},
        {"tools": tools[5:]},
    ]


class TestFileAdapter:
    def test_single_page_is_served_for_the_first_request(self, tmp_path: Path):
        tools = _annotated_tools()
        adapter = FileMcpInventoryAdapter(_write(tmp_path / "t.json", {"tools": tools}))

        page = adapter.list_tools()

        assert page.tools == tuple(tools)
        assert page.next_cursor is None
        assert page.complete is True

    def test_json_rpc_result_wrapping_is_unwrapped(self, tmp_path: Path):
        tools = _recorded_tools()
        path = _write(
            tmp_path / "t.json",
            {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}},
        )

        assert FileMcpInventoryAdapter(path).list_tools().tools == tuple(tools)

    def test_pages_are_served_in_order_by_the_previous_next_cursor(
        self, tmp_path: Path
    ):
        tools = _recorded_tools()
        adapter = FileMcpInventoryAdapter(_write(tmp_path / "t.json", _paged(tools)))

        first = adapter.list_tools()
        second = adapter.list_tools(first.next_cursor)
        third = adapter.list_tools(second.next_cursor)

        assert first.tools + second.tools + third.tools == tuple(tools)
        assert (first.next_cursor, second.next_cursor) == ("page-2", "page-3")
        assert third.complete is True

    def test_unknown_cursor_names_the_file(self, tmp_path: Path):
        path = _write(tmp_path / "t.json", {"tools": []})

        with pytest.raises(McpToolsListFileError, match="no page for cursor 'x'"):
            FileMcpInventoryAdapter(path).list_tools("x")


def _missing(tmp_path: Path) -> Path:
    return tmp_path / "absent.json"


def _unreadable(tmp_path: Path) -> Path:
    path = tmp_path / "dir.json"
    path.mkdir()
    return path


def _undecodable(tmp_path: Path) -> Path:
    path = tmp_path / "latin1.json"
    path.write_bytes(b'{"tools": ["\xff"]}')
    return path


def _content(payload: Any):
    def build(tmp_path: Path) -> Path:
        path = tmp_path / "tools-list.json"
        path.write_text(
            payload if isinstance(payload, str) else json.dumps(payload),
            encoding="utf-8",
        )
        return path

    return build


TOOL = {"name": "t", "inputSchema": {"type": "object"}}
BAD_FILES = {
    "missing": (_missing, "file not found"),
    "unreadable": (_unreadable, "cannot read file"),
    "undecodable": (_undecodable, "cannot read file"),
    "malformed_json": (_content('{"tools": ['), "invalid JSON"),
    "scalar": (_content("3"), "expected a tools/list result"),
    "empty_list": (_content([]), "expected a tools/list result"),
    "page_not_object": (
        _content([{"tools": [TOOL]}, ["t"]]),
        "page 1 is not a tools/list result: expected a JSON object",
    ),
    "page_without_tools": (
        _content({"name": "t"}),
        "page 0 is not a tools/list result: missing a tools list",
    ),
    "json_rpc_error": (
        _content({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601}}),
        "page 0 is not a tools/list result: missing a tools list",
    ),
    "tools_not_list": (
        _content({"tools": {"t": TOOL}}),
        "page 0 is not a tools/list result: missing a tools list",
    ),
    "bad_cursor": (
        _content({"tools": [], "nextCursor": 7}),
        "nextCursor must be a non-empty string",
    ),
    "incomplete_without_cursor": (
        _content({"tools": [], "complete": False}),
        "page 0 is not a tools/list result",
    ),
    "looping_cursor": (
        _content(
            [
                {"tools": [], "nextCursor": "a"},
                {"tools": [], "nextCursor": "b"},
                {"tools": [], "nextCursor": "a"},
            ]
        ),
        "page 2 nextCursor 'a' loops back to page 1",
    ),
    "missing_page_cursor": (
        _content([{"tools": [], "nextCursor": "a"}, {"tools": [], "nextCursor": "b"}]),
        "page 1 nextCursor 'b' names a missing page",
    ),
    "single_page_missing_cursor": (
        _content({"tools": [], "nextCursor": "more"}),
        "page 0 nextCursor 'more' names a missing page",
    ),
    "unreachable_page": (
        _content([{"tools": []}, {"tools": []}]),
        "page 0 has no nextCursor but 1 more page(s) follow",
    ),
}


@pytest.mark.parametrize("case", sorted(BAD_FILES))
def test_bad_file_fails_naming_the_path_and_problem(tmp_path: Path, case: str):
    build, problem = BAD_FILES[case]
    path = build(tmp_path)

    with pytest.raises(McpToolsListFileError) as caught:
        FileMcpInventoryAdapter(path)

    assert str(caught.value).startswith(f"{path}: ")
    assert problem in str(caught.value)


@pytest.mark.parametrize("case", sorted(BAD_FILES))
def test_bad_file_cli_exits_non_zero_and_writes_nothing(tmp_path: Path, case: str):
    build, problem = BAD_FILES[case]
    path = build(tmp_path)
    output_dir = tmp_path / "out"

    completed = PlainCliRunner().invoke(app, _cli_args(path, output_dir))

    assert completed.exit_code == 2, completed.output
    assert completed.exception is None or isinstance(completed.exception, SystemExit)
    assert "Traceback" not in completed.output
    assert str(path) in completed.output
    assert problem in completed.output
    assert not output_dir.exists()


def _cli_args(tools_list: Path, output_dir: Path, *extra: str) -> list[str]:
    return [
        "file",
        "--tools-list",
        str(tools_list),
        "--target-id",
        "mini-klarna-safe",
        "--authorization-scope",
        "test-customer",
        "--output-dir",
        str(output_dir),
        *extra,
    ]


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any socket connection and any import of the ``mcp`` client."""

    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("the file scan opened a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    for name in ("mcp", "mcp.client", "mcp.client.sse", "mcp.types"):
        monkeypatch.setitem(sys.modules, name, None)


@pytest.mark.parametrize("paged", [False, True], ids=["single", "paged"])
@pytest.mark.usefixtures("offline")
def test_cli_file_scan_writes_an_observed_profile_offline(tmp_path: Path, paged: bool):
    tools = _annotated_tools()
    path = _write(tmp_path / "t.json", _paged(tools) if paged else {"tools": tools})
    output_dir = tmp_path / "out"

    completed = PlainCliRunner().invoke(app, _cli_args(path, output_dir))

    assert completed.exit_code == 0, completed.output
    assert sorted(item.name for item in output_dir.iterdir()) == [
        "calls.jsonl",
        "execution-target-profile.json",
        "mcp-inventory.json",
        "target-discovery-manifest.json",
    ]
    profile = ExecutionTargetProfile.model_validate(
        json.loads(
            (output_dir / "execution-target-profile.json").read_text(encoding="utf-8")
        )
    )
    profile.assert_integrity()
    assert profile.inventory_authority is InventoryAuthority.observed
    assert profile.inventory_completeness is InventoryCompleteness.observed_complete
    assert profile.inventory.page_count == (3 if paged else 1)
    by_name = {tool.name: tool for tool in profile.inventory.tools}
    assert sorted(by_name) == sorted(tool["name"] for tool in tools)
    assert by_name["process_refund"].annotations == ANNOTATIONS["process_refund"]
    assert by_name["lookup_order"].annotations == ANNOTATIONS["lookup_order"]
    serialized = "\n".join(p.read_text(encoding="utf-8") for p in output_dir.iterdir())
    assert str(path) not in serialized


def test_cli_file_shares_the_mcp_options(tmp_path: Path):
    path = _write(tmp_path / "t.json", {"tools": _recorded_tools()})
    interpreter = SimpleNamespace(model_name="fixture-model")
    result = SimpleNamespace(profile=object(), valid=True)
    cli = "asago_scenario_generator.target_discovery.cli"
    with (
        patch(
            f"{cli}.TargetDiscoveryLlmInterpreter.from_profile",
            return_value=interpreter,
        ) as from_profile,
        patch(f"{cli}.discover_mcp_target", return_value=result) as discover,
        patch(f"{cli}.write_target_discovery", return_value={}),
    ):
        completed = PlainCliRunner().invoke(
            app,
            _cli_args(
                path,
                tmp_path / "out",
                "--profile",
                "fixture-profile",
                "--profiles-file",
                str(tmp_path / "profiles.yaml"),
                "--mode",
                "schema_only",
                "--interpretation-batch-size",
                "3",
            ),
        )

    assert completed.exit_code == 0, completed.output
    from_profile.assert_called_once_with(
        tmp_path / "profiles.yaml", "fixture-profile", run_dir=tmp_path / "out"
    )
    inputs, adapter = discover.call_args.args
    assert isinstance(adapter, FileMcpInventoryAdapter)
    assert inputs.model_profile == "fixture-profile"
    assert inputs.model_name == "fixture-model"
    assert inputs.interpretation_batch_size == 3
    assert discover.call_args.kwargs["interpreter_factory"] is interpreter


def test_cli_file_rejects_other_modes_before_reading_the_file(tmp_path: Path):
    completed = PlainCliRunner().invoke(
        app, _cli_args(tmp_path / "absent.json", tmp_path / "out", "--mode", "full")
    )

    assert completed.exit_code == 2
    assert "only schema_only is supported" in completed.output


def test_cli_file_help_documents_the_page_rule():
    completed = PlainCliRunner().invoke(app, ["file", "--help"])

    assert completed.exit_code == 0, completed.output
    for option in ("--tools-list", "--target-id", "--interpretation-batch-size"):
        assert option in completed.output
    assert "--server-url" not in completed.output
    assert "linked by nextCursor" in completed.output


class _SdkResult:
    """SDK-shaped response: ``model_dump`` returns the result payload."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def model_dump(self, mode: str) -> dict[str, Any]:
        assert mode == "python"
        return copy.deepcopy(self._payload)


class _LivePages:
    """Live adapter over the fake SDK, answering each request with the next page."""

    def __init__(self, sdk: FakeMcpSdk, pages: list[dict[str, Any]]) -> None:
        self._sdk = sdk
        self._pages = iter(pages)
        self._adapter = HttpMcpInventoryAdapter("http://host/sse")

    def list_tools(self, cursor: str | None = None) -> McpInventoryPage:
        self._sdk.response = _SdkResult(next(self._pages))
        return self._adapter.list_tools(cursor)


def _live_inventory(
    monkeypatch: pytest.MonkeyPatch, pages: list[dict[str, Any]]
) -> McpInventoryObservation:
    sdk = FakeMcpSdk()
    install_fake_mcp_sdk(monkeypatch, sdk)
    inventory = discover_mcp_target(_inputs(), _LivePages(sdk, pages)).inventory
    assert [call["params"].cursor for call in sdk.list_calls[1:]] == [
        page["nextCursor"] for page in pages[:-1]
    ]
    assert inventory is not None
    return inventory


@pytest.mark.parametrize(
    "tools", [_recorded_tools(), _annotated_tools()], ids=["recorded", "annotated"]
)
@pytest.mark.parametrize("paged", [False, True], ids=["single", "paged"])
def test_file_inventory_matches_a_live_scan_of_the_same_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tools, paged: bool
):
    pages = _paged(tools) if paged else [{"tools": tools}]
    path = _write(tmp_path / "t.json", pages)

    live = _live_inventory(monkeypatch, pages)
    declared = discover_mcp_target(_inputs(), FileMcpInventoryAdapter(path)).inventory
    assert declared is not None

    assert [tool.model_dump(mode="json") for tool in declared.tools] == [
        tool.model_dump(mode="json") for tool in live.tools
    ]
    assert declared.semantic_digest == live.semantic_digest
    assert declared.model_dump(mode="json") == live.model_dump(mode="json")


def test_file_scan_persists_like_a_live_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    tools = _annotated_tools()
    path = _write(tmp_path / "t.json", {"tools": tools})
    sdk = FakeMcpSdk(_SdkResult({"tools": tools}))
    install_fake_mcp_sdk(monkeypatch, sdk)

    live = discover_mcp_target(_inputs(), HttpMcpInventoryAdapter("http://host/sse"))
    declared = discover_mcp_target(_inputs(), FileMcpInventoryAdapter(path))
    live_files = write_target_discovery(tmp_path / "live", live)
    declared_files = write_target_discovery(tmp_path / "declared", declared)

    assert {name: p.read_bytes() for name, p in declared_files.items()} == {
        name: p.read_bytes() for name, p in live_files.items()
    }

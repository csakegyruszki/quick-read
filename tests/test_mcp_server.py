"""The MCP server over stdio: initialize, tools/list and a tools/call that needs no network.

Skipped when the optional `mcp` extra is not installed.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

pytest.importorskip("mcp.server.mcpserver")

import quick_read  # noqa: E402


class _Server:
    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "quick_read.mcp_server"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8",
        )

    def send(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def reply(self, msg_id: int) -> dict:
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise AssertionError("server closed stdout before replying")
            data = json.loads(line)
            if data.get("id") == msg_id:
                return data

    def close(self) -> None:
        self.proc.terminate()
        self.proc.wait(timeout=10)


@pytest.fixture()
def server():
    s = _Server()
    s.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}})
    s.init = s.reply(1)
    s.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    yield s
    s.close()


def test_server_info_carries_package_version(server):
    info = server.init["result"]["serverInfo"]
    assert info["name"] == "quick-read"
    assert info["version"] == quick_read.__version__


def test_tools_list_has_one_tool_with_stable_schema(server):
    server.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools = server.reply(2)["result"]["tools"]
    assert [t["name"] for t in tools] == ["quick_read"]
    props = tools[0]["inputSchema"]["properties"]
    assert set(props) == {"url", "max_chars"}
    assert props["max_chars"].get("default") == 20000
    assert tools[0]["inputSchema"].get("required") == ["url"]


def test_tools_call_blocked_address_needs_no_network(server):
    server.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "quick_read", "arguments": {"url": "http://127.0.0.1/"}}})
    result = server.reply(3)["result"]
    assert not result.get("isError")
    payload = json.loads(result["content"][0]["text"])
    assert payload["ok"] is False
    assert payload["error"] == "BLOCKED_ADDRESS"

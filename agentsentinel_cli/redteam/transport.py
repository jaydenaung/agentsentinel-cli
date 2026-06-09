"""Persistent MCP transport layer for red-team testing.

Provides RedTeamSession — a context manager that maintains a live MCP session
and supports multiple tools/call invocations on the same connection.

Supports streamable HTTP, legacy SSE, and stdio transports. Auto-detects which
transport the target server uses during connect().
"""

from __future__ import annotations

import json
import queue
import shlex
import subprocess
import threading
import time
import urllib.parse
from typing import Any

from agentsentinel_cli.mcp_client import (
    McpServerInfo, McpAuthRequired, McpError, _rpc, _make_tool,
)
from agentsentinel_cli.redteam.models import ToolCallResult

_PROTOCOL_VERSION = "2024-11-05"
_CLIENT_INFO = {"name": "sentinel-redteam", "version": "1.0.0"}


class RedTeamSession:
    """
    Active MCP session that supports multiple tool calls within a single connection.

    Use as a context manager:
        with RedTeamSession(url="http://localhost:3000") as s:
            info = s.server_info
            result = s.call_tool("read_file", {"path": "/etc/passwd"})
    """

    def __init__(
        self,
        url: str | None = None,
        stdio_cmd: str | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: float = 15.0,
    ) -> None:
        if not url and not stdio_cmd:
            raise ValueError("Provide url or stdio_cmd")
        if url and stdio_cmd:
            raise ValueError("url and stdio_cmd are mutually exclusive")
        self._url = url
        self._stdio_cmd = stdio_cmd
        self._extra_headers = dict(extra_headers or {})
        self._timeout = timeout

        self._transport: str | None = None
        self._server_info: McpServerInfo | None = None
        self._req_id: int = 100

        # HTTP
        self._http_client: Any = None
        self._http_base: str | None = None
        self._http_headers: dict = {}

        # SSE
        self._sse_client: Any = None
        self._sse_messages_url: str | None = None
        self._sse_post_headers: dict = {}
        self._sse_event_q: queue.Queue = queue.Queue()

        # Stdio
        self._stdio_proc: subprocess.Popen | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def server_info(self) -> McpServerInfo:
        if self._server_info is None:
            raise RuntimeError("Not connected — use as a context manager")
        return self._server_info

    def __enter__(self) -> "RedTeamSession":
        self._connect()
        return self

    def __exit__(self, *_: object) -> None:
        self._close()

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        """Invoke a tool with arbitrary arguments and return the full result."""
        self._req_id += 1
        body = _rpc("tools/call", {"name": tool_name, "arguments": arguments}, self._req_id)
        t0 = time.monotonic()

        if self._transport == "http":
            return self._call_http(body, tool_name, arguments, t0)
        if self._transport == "sse":
            return self._call_sse(body, tool_name, arguments, t0)
        if self._transport == "stdio":
            return self._call_stdio(body, tool_name, arguments, t0)
        raise RuntimeError("Not connected")

    def list_resources(self) -> list[dict]:
        """Enumerate MCP resources (returns empty list on error)."""
        return self._list_endpoint("resources/list", "resources")

    def list_prompts(self) -> list[dict]:
        """Enumerate MCP prompts (returns empty list on error)."""
        return self._list_endpoint("prompts/list", "prompts")

    # ── Connection ────────────────────────────────────────────────────────────

    def _connect(self) -> None:
        if self._stdio_cmd:
            self._connect_stdio()
        else:
            self._connect_http_or_sse()

    def _connect_http_or_sse(self) -> None:
        try:
            import httpx
        except ImportError:
            raise McpError("httpx required: pip install 'agentsentinel-cli[mcp]'")

        if self._url and not self._url.startswith(("http://", "https://")):
            raise McpError(
                f"Invalid URL '{self._url}' — missing protocol. "
                f"Try: http://{self._url}"
            )

        base = self._url.rstrip("/")
        headers: dict = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        headers.update(self._extra_headers)

        client = httpx.Client(timeout=self._timeout)

        resp = client.post(base, json=_rpc("initialize", {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": _CLIENT_INFO,
        }, 1), headers=headers)

        if resp.status_code in (401, 403):
            client.close()
            raise McpAuthRequired(resp.status_code)

        if resp.status_code in (404, 405) or "text/event-stream" in resp.headers.get("content-type", ""):
            client.close()
            self._connect_sse()
            return

        resp.raise_for_status()
        init_data = _parse_rpc(resp.text)

        client.post(base, json={
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }, headers=headers)

        resp = client.post(base, json=_rpc("tools/list", {}, 2), headers=headers)
        resp.raise_for_status()
        tools_data = _parse_rpc(resp.text)

        server_meta = init_data.get("result", {}).get("serverInfo", {})
        raw_tools = tools_data.get("result", {}).get("tools", [])

        self._transport = "http"
        self._http_client = client
        self._http_base = base
        self._http_headers = headers
        self._server_info = McpServerInfo(
            name=server_meta.get("name", "unknown"),
            version=server_meta.get("version", "unknown"),
            tools=[_make_tool(t) for t in raw_tools],
            transport="http",
        )

    def _connect_sse(self) -> None:
        try:
            import httpx
        except ImportError:
            raise McpError("httpx required")

        base = self._url.rstrip("/")
        if not base.endswith("/sse"):
            base = f"{base}/sse"

        parsed = urllib.parse.urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        sse_headers: dict = {"Accept": "text/event-stream"}
        sse_headers.update(self._extra_headers)

        client = httpx.Client(timeout=self._timeout)
        endpoint_q: queue.Queue = queue.Queue(maxsize=1)
        sse_q = self._sse_event_q

        def _reader() -> None:
            try:
                with client.stream("GET", base, headers=sse_headers) as resp:
                    if resp.status_code in (401, 403):
                        endpoint_q.put(None)
                        return
                    resp.raise_for_status()
                    endpoint_sent = False
                    for line in resp.iter_lines():
                        if line.startswith("data:"):
                            data = line[5:].strip()
                            if not endpoint_sent:
                                endpoint_q.put(data)
                                endpoint_sent = True
                            else:
                                sse_q.put(data)
            except Exception:
                endpoint_q.put(None)
                sse_q.put(None)

        threading.Thread(target=_reader, daemon=True).start()

        try:
            session_path = endpoint_q.get(timeout=self._timeout)
        except queue.Empty:
            client.close()
            raise McpError("SSE server did not send endpoint URL")
        if session_path is None:
            client.close()
            raise McpAuthRequired(401)

        messages_url = (
            session_path if session_path.startswith("http")
            else f"{origin}{session_path}"
        )

        post_headers: dict = {"Content-Type": "application/json"}
        post_headers.update(self._extra_headers)

        resp = client.post(messages_url, json=_rpc("initialize", {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": _CLIENT_INFO,
        }, 1), headers=post_headers)
        if resp.status_code in (401, 403):
            client.close()
            raise McpAuthRequired(resp.status_code)
        resp.raise_for_status()
        init_data = self._sse_recv()

        client.post(messages_url, json={
            "jsonrpc": "2.0", "method": "notifications/initialized", "params": {},
        }, headers=post_headers)

        resp = client.post(messages_url, json=_rpc("tools/list", {}, 2), headers=post_headers)
        resp.raise_for_status()
        tools_data = self._sse_recv()

        server_meta = init_data.get("result", {}).get("serverInfo", {})
        raw_tools = tools_data.get("result", {}).get("tools", [])

        self._transport = "sse"
        self._sse_client = client
        self._sse_messages_url = messages_url
        self._sse_post_headers = post_headers
        self._server_info = McpServerInfo(
            name=server_meta.get("name", "unknown"),
            version=server_meta.get("version", "unknown"),
            tools=[_make_tool(t) for t in raw_tools],
            transport="sse",
        )

    def _connect_stdio(self) -> None:
        args = shlex.split(self._stdio_cmd)
        try:
            proc = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True,
            )
        except FileNotFoundError as exc:
            raise McpError(f"Command not found: {args[0]}") from exc

        _stdio_send(proc, _rpc("initialize", {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": _CLIENT_INFO,
        }, 1))
        init_resp = _stdio_recv(proc, self._timeout)

        _stdio_send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

        _stdio_send(proc, _rpc("tools/list", {}, 2))
        tools_resp = _stdio_recv(proc, self._timeout)

        server_meta = init_resp.get("result", {}).get("serverInfo", {})
        raw_tools = tools_resp.get("result", {}).get("tools", [])

        self._transport = "stdio"
        self._stdio_proc = proc
        self._server_info = McpServerInfo(
            name=server_meta.get("name", "unknown"),
            version=server_meta.get("version", "unknown"),
            tools=[_make_tool(t) for t in raw_tools],
            transport="stdio",
        )

    def _close(self) -> None:
        for client in (self._http_client, self._sse_client):
            if client:
                try:
                    client.close()
                except Exception:
                    pass
        if self._stdio_proc:
            try:
                self._stdio_proc.terminate()
                self._stdio_proc.wait(timeout=3.0)
            except Exception:
                try:
                    self._stdio_proc.kill()
                except Exception:
                    pass

    # ── Tool call dispatchers ─────────────────────────────────────────────────

    def _call_http(self, body: dict, name: str, args: dict, t0: float) -> ToolCallResult:
        try:
            resp = self._http_client.post(self._http_base, json=body, headers=self._http_headers)
            elapsed = (time.monotonic() - t0) * 1000
            if resp.status_code in (401, 403):
                return ToolCallResult(
                    tool_name=name, arguments=args,
                    http_status=resp.status_code,
                    rpc_error={"message": f"HTTP {resp.status_code}"},
                    content=None, is_error=False,
                    raw_response=resp.text, elapsed_ms=elapsed,
                )
            try:
                data = _parse_rpc(resp.text)
            except McpError:
                return ToolCallResult(
                    tool_name=name, arguments=args,
                    http_status=resp.status_code, rpc_error={"message": "Invalid JSON"},
                    content=None, is_error=False,
                    raw_response=resp.text, elapsed_ms=elapsed,
                )
            return _parse_call_result(data, name, args, resp.status_code, resp.text, elapsed)
        except Exception as exc:
            return ToolCallResult(
                tool_name=name, arguments=args,
                http_status=None, rpc_error={"message": str(exc)},
                content=None, is_error=False, raw_response="",
                elapsed_ms=(time.monotonic() - t0) * 1000,
            )

    def _call_sse(self, body: dict, name: str, args: dict, t0: float) -> ToolCallResult:
        try:
            resp = self._sse_client.post(
                self._sse_messages_url, json=body, headers=self._sse_post_headers
            )
            if resp.status_code in (401, 403):
                elapsed = (time.monotonic() - t0) * 1000
                return ToolCallResult(
                    tool_name=name, arguments=args,
                    http_status=resp.status_code,
                    rpc_error={"message": f"HTTP {resp.status_code}"},
                    content=None, is_error=False,
                    raw_response=resp.text, elapsed_ms=elapsed,
                )
            data = self._sse_recv()
            elapsed = (time.monotonic() - t0) * 1000
            return _parse_call_result(data, name, args, resp.status_code, json.dumps(data), elapsed)
        except Exception as exc:
            return ToolCallResult(
                tool_name=name, arguments=args,
                http_status=None, rpc_error={"message": str(exc)},
                content=None, is_error=False, raw_response="",
                elapsed_ms=(time.monotonic() - t0) * 1000,
            )

    def _call_stdio(self, body: dict, name: str, args: dict, t0: float) -> ToolCallResult:
        try:
            _stdio_send(self._stdio_proc, body)
            data = _stdio_recv(self._stdio_proc, self._timeout)
            elapsed = (time.monotonic() - t0) * 1000
            return _parse_call_result(data, name, args, None, json.dumps(data), elapsed)
        except Exception as exc:
            return ToolCallResult(
                tool_name=name, arguments=args,
                http_status=None, rpc_error={"message": str(exc)},
                content=None, is_error=False, raw_response="",
                elapsed_ms=(time.monotonic() - t0) * 1000,
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _sse_recv(self) -> dict:
        while True:
            try:
                payload = self._sse_event_q.get(timeout=self._timeout)
            except queue.Empty:
                raise McpError(f"No SSE response within {self._timeout}s")
            if payload is None:
                raise McpError("SSE stream closed unexpectedly")
            try:
                data = json.loads(payload)
                # Skip server-push notifications (no id, result, or error)
                if "id" not in data and "result" not in data and "error" not in data:
                    continue
                return data
            except json.JSONDecodeError:
                continue

    def _list_endpoint(self, method: str, result_key: str) -> list[dict]:
        self._req_id += 1
        body = _rpc(method, {}, self._req_id)
        try:
            if self._transport == "http":
                resp = self._http_client.post(self._http_base, json=body, headers=self._http_headers)
                data = _parse_rpc(resp.text)
            elif self._transport == "sse":
                self._sse_client.post(self._sse_messages_url, json=body, headers=self._sse_post_headers)
                data = self._sse_recv()
            elif self._transport == "stdio":
                _stdio_send(self._stdio_proc, body)
                data = _stdio_recv(self._stdio_proc, self._timeout)
            else:
                return []
            return data.get("result", {}).get(result_key, [])
        except Exception:
            return []


# ── Module-level helpers ──────────────────────────────────────────────────────

def _parse_rpc(text: str) -> dict:
    text = text.strip()
    if not text:
        raise McpError("Empty response")
    if text.startswith("data:") or text.startswith("event:"):
        for line in text.splitlines():
            if line.startswith("data:"):
                text = line[5:].strip()
                break
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise McpError(f"Invalid JSON: {exc}") from exc


def _stdio_send(proc: subprocess.Popen, obj: dict) -> None:
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def _stdio_recv(proc: subprocess.Popen, timeout: float) -> dict:
    result_q: queue.Queue = queue.Queue()

    def _r() -> None:
        try:
            result_q.put(proc.stdout.readline())  # type: ignore[union-attr]
        except Exception:
            result_q.put(None)

    threading.Thread(target=_r, daemon=True).start()

    try:
        line = result_q.get(timeout=timeout)
    except queue.Empty:
        raise McpError(f"No stdio response within {timeout}s")

    if not line or not line.strip():
        raise McpError("Stdio server closed stdout")

    return json.loads(line.strip())


def _parse_call_result(
    data: dict,
    tool_name: str,
    arguments: dict,
    http_status: int | None,
    raw: str,
    elapsed: float,
) -> ToolCallResult:
    rpc_error = data.get("error")
    result = data.get("result", {})
    return ToolCallResult(
        tool_name=tool_name,
        arguments=arguments,
        http_status=http_status,
        rpc_error=rpc_error,
        content=result.get("content"),
        is_error=result.get("isError", False),
        raw_response=raw,
        elapsed_ms=elapsed,
    )

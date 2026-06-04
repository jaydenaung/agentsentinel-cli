"""Minimal MCP (Model Context Protocol) client for security scanning.

Implements the initialize + tools/list exchange over stdio, streamable-HTTP,
and legacy SSE transports. Only what an auditor needs — no full MCP client dependency.
"""

import dataclasses
import json
import queue
import shlex
import subprocess
import threading
import urllib.parse
from typing import Any

from agentsentinel_cli.scanner import classify_tool

_PROTOCOL_VERSION = "2024-11-05"
_CLIENT_INFO = {"name": "sentinel-mcp-scanner", "version": "0.2.0"}


@dataclasses.dataclass
class McpToolInfo:
    """A single tool exposed by an MCP server."""

    name: str
    description: str
    input_schema: dict[str, Any]
    scope: str = "read"
    is_dangerous: bool = False
    category: str = "other"


@dataclasses.dataclass
class McpServerInfo:
    """Result of a successful MCP server connection."""

    name: str
    version: str
    tools: list[McpToolInfo]
    transport: str  # "http" | "stdio"


class McpError(Exception):
    """Raised when the MCP connection or protocol exchange fails."""


class McpAuthRequired(McpError):
    """Raised when the server returns 401/403 and no credentials were provided."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"HTTP {status_code}: authentication required")
        self.status_code = status_code


def _rpc(method: str, params: dict[str, Any], req_id: int) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}


def _make_tool(raw: dict[str, Any]) -> McpToolInfo:
    name = raw.get("name", "")
    description = raw.get("description", "")
    scope, is_dangerous, category = classify_tool(name, description)
    return McpToolInfo(
        name=name,
        description=description,
        input_schema=raw.get("inputSchema", {}),
        scope=scope,
        is_dangerous=is_dangerous,
        category=category,
    )


# ── Streamable HTTP transport ─────────────────────────────────────────────────

def scan_http(
    url: str,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> McpServerInfo:
    """Scan an MCP server via streamable HTTP (POST-based) transport.

    If the server responds with 405 or text/event-stream, automatically falls
    back to the legacy SSE transport (GET /sse + POST /messages).

    Raises McpAuthRequired if the server requires credentials.
    Raises McpError for all other connection or protocol failures.
    """
    try:
        import httpx
    except ImportError:
        raise McpError("httpx is required: pip install 'agentsentinel-cli[mcp]'")

    base = url.rstrip("/")
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if extra_headers:
        headers.update(extra_headers)

    with httpx.Client(timeout=timeout) as client:
        resp = client.post(base, json=_rpc("initialize", {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": _CLIENT_INFO,
        }, 1), headers=headers)

        if resp.status_code in (401, 403):
            raise McpAuthRequired(resp.status_code)
        if resp.status_code in (404, 405):
            # Server may use SSE transport — root path returns 404, /sse returns 405
            return scan_sse(url, extra_headers=extra_headers, timeout=timeout)

        content_type = resp.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            return scan_sse(url, extra_headers=extra_headers, timeout=timeout)

        resp.raise_for_status()
        init_data = _parse_rpc_response(resp.text)

        # Send initialized notification — no response expected
        client.post(base, json={
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }, headers=headers)

        resp = client.post(base, json=_rpc("tools/list", {}, 2), headers=headers)
        resp.raise_for_status()
        tools_data = _parse_rpc_response(resp.text)

    server_meta = init_data.get("result", {}).get("serverInfo", {})
    raw_tools = tools_data.get("result", {}).get("tools", [])

    return McpServerInfo(
        name=server_meta.get("name", "unknown"),
        version=server_meta.get("version", "unknown"),
        tools=[_make_tool(t) for t in raw_tools],
        transport="http",
    )


def scan_sse(
    url: str,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> McpServerInfo:
    """Scan an MCP server via the legacy SSE transport (GET /sse + POST /messages).

    FastMCP 0.x / mcp 1.x servers use this transport. The protocol is:
      1. Client opens GET /sse — server streams SSE events back.
      2. First event is  event: endpoint / data: /messages/?session_id=xxx
      3. Client POSTs JSON-RPC requests to /messages/?session_id=xxx.
      4. Server sends responses as SSE  data:  events on the open GET stream.

    We handle the bidirectional exchange with a background reader thread that
    drains the SSE stream into a queue while the main thread sends requests.
    """
    try:
        import httpx
    except ImportError:
        raise McpError("httpx is required: pip install 'agentsentinel-cli[mcp]'")

    # Normalise: /sse suffix accepted but not required
    base = url.rstrip("/")
    if not base.endswith("/sse"):
        base = f"{base}/sse"

    parsed = urllib.parse.urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    sse_headers: dict[str, str] = {"Accept": "text/event-stream"}
    if extra_headers:
        sse_headers.update(extra_headers)

    event_q: queue.Queue[str | None] = queue.Queue()
    endpoint_q: queue.Queue[str | None] = queue.Queue(maxsize=1)

    def _sse_reader(client: "httpx.Client") -> None:
        """Stream GET /sse, push data-line payloads into event_q."""
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
                            # First data line is the session endpoint path
                            endpoint_q.put(data)
                            endpoint_sent = True
                        else:
                            event_q.put(data)
        except Exception:
            endpoint_q.put(None)
            event_q.put(None)

    def _recv(wait: float) -> dict[str, Any]:
        try:
            payload = event_q.get(timeout=wait)
        except queue.Empty:
            raise McpError(f"No SSE response within {wait}s")
        if payload is None:
            raise McpError("SSE stream closed unexpectedly")
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise McpError(f"Invalid JSON from SSE stream: {exc}") from exc

    with httpx.Client(timeout=timeout) as client:
        reader = threading.Thread(target=_sse_reader, args=(client,), daemon=True)
        reader.start()

        # Wait for the session endpoint URL
        try:
            session_path = endpoint_q.get(timeout=timeout)
        except queue.Empty:
            raise McpError("SSE server did not send an endpoint URL in time")
        if session_path is None:
            raise McpAuthRequired(401)

        # Build the absolute messages URL
        if session_path.startswith("http"):
            messages_url = session_path
        else:
            messages_url = f"{origin}{session_path}"

        post_headers: dict[str, str] = {"Content-Type": "application/json"}
        if extra_headers:
            post_headers.update(extra_headers)

        # initialize
        resp = client.post(messages_url, json=_rpc("initialize", {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": _CLIENT_INFO,
        }, 1), headers=post_headers)
        if resp.status_code in (401, 403):
            raise McpAuthRequired(resp.status_code)
        resp.raise_for_status()
        init_data = _recv(timeout)

        # initialized notification — fire and forget
        client.post(messages_url, json={
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }, headers=post_headers)

        # tools/list
        resp = client.post(messages_url, json=_rpc("tools/list", {}, 2), headers=post_headers)
        resp.raise_for_status()
        tools_data = _recv(timeout)

    server_meta = init_data.get("result", {}).get("serverInfo", {})
    raw_tools = tools_data.get("result", {}).get("tools", [])

    return McpServerInfo(
        name=server_meta.get("name", "unknown"),
        version=server_meta.get("version", "unknown"),
        tools=[_make_tool(t) for t in raw_tools],
        transport="sse",
    )


def _parse_rpc_response(text: str) -> dict[str, Any]:
    """Parse a JSON-RPC response body, unwrapping SSE data-lines if present."""
    text = text.strip()
    if not text:
        raise McpError("Empty response from MCP server")
    if text.startswith("data:") or text.startswith("event:"):
        for line in text.splitlines():
            if line.startswith("data:"):
                text = line[5:].strip()
                break
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise McpError(f"Invalid JSON from server: {exc}") from exc


# ── Stdio transport ───────────────────────────────────────────────────────────

def scan_stdio(command: str, timeout: float = 15.0) -> McpServerInfo:
    """Launch an MCP server as a subprocess and scan it via stdio transport."""
    args = shlex.split(command)
    try:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except FileNotFoundError as exc:
        raise McpError(f"Command not found: {args[0]}") from exc

    try:
        return _stdio_exchange(proc, timeout)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()


def _stdio_send(proc: subprocess.Popen, obj: dict[str, Any]) -> None:
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def _stdio_recv(proc: subprocess.Popen, timeout: float) -> dict[str, Any]:
    """Read one newline-delimited JSON-RPC message from subprocess stdout."""
    assert proc.stdout is not None
    result_q: queue.Queue[str | None] = queue.Queue()

    def _reader() -> None:
        try:
            result_q.put(proc.stdout.readline())  # type: ignore[union-attr]
        except Exception:
            result_q.put(None)

    threading.Thread(target=_reader, daemon=True).start()

    try:
        line = result_q.get(timeout=timeout)
    except queue.Empty:
        raise McpError(f"No response from stdio server within {timeout}s")

    if not line or not line.strip():
        raise McpError("MCP server closed stdout without responding")
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError as exc:
        raise McpError(f"Invalid JSON from stdio server: {exc}") from exc


def _stdio_exchange(proc: subprocess.Popen, timeout: float) -> McpServerInfo:
    _stdio_send(proc, _rpc("initialize", {
        "protocolVersion": _PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": _CLIENT_INFO,
    }, 1))
    init_resp = _stdio_recv(proc, timeout)

    _stdio_send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    _stdio_send(proc, _rpc("tools/list", {}, 2))
    tools_resp = _stdio_recv(proc, timeout)

    server_meta = init_resp.get("result", {}).get("serverInfo", {})
    raw_tools = tools_resp.get("result", {}).get("tools", [])

    return McpServerInfo(
        name=server_meta.get("name", "unknown"),
        version=server_meta.get("version", "unknown"),
        tools=[_make_tool(t) for t in raw_tools],
        transport="stdio",
    )

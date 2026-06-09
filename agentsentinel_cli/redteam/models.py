"""Data models for red-team findings and session results."""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass
class ToolCallResult:
    """Raw result of a single tools/call invocation."""

    tool_name: str
    arguments: dict[str, Any]
    http_status: int | None      # None for stdio transport
    rpc_error: dict | None       # JSON-RPC error object if present
    content: list[dict] | None   # result.content array
    is_error: bool               # result.isError flag from server
    raw_response: str
    elapsed_ms: float

    @property
    def text_output(self) -> str:
        if not self.content:
            return ""
        return "\n".join(
            item.get("text", "") for item in self.content if item.get("type") == "text"
        )

    @property
    def error_message(self) -> str:
        if self.rpc_error:
            return self.rpc_error.get("message", "")
        if self.is_error:
            return self.text_output
        return ""

    @property
    def all_text(self) -> str:
        """All textual content including errors — used for evidence matching."""
        parts = [self.text_output, self.error_message]
        return " ".join(p for p in parts if p)

    @property
    def auth_blocked(self) -> bool:
        """True when the server rejected the call due to missing/bad credentials."""
        if self.http_status in (401, 403):
            return True
        msg = self.error_message.lower()
        return any(kw in msg for kw in (
            "unauthorized", "forbidden", "authentication required",
            "invalid token", "access denied", "not authenticated",
        ))

    @property
    def tool_executed(self) -> bool:
        """True when the server reached tool execution (auth was NOT the blocker)."""
        return not self.auth_blocked


@dataclasses.dataclass
class RedTeamFinding:
    """A confirmed finding from active red-team testing."""

    attack_type: str      # traverse | ssrf | cmd | sqli | llm | auth | poison | fuzz | recon
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    tool_name: str
    parameter: str | None
    payload: str | None
    evidence: str         # response excerpt that proves the vulnerability
    exploit_scenario: str
    mitre_id: str | None
    owasp_id: str | None
    confidence: str = "HIGH"          # HIGH | MEDIUM | LOW
    remediation: str | None = None    # what to fix
    request_body: dict | None = None  # full request (verbose mode)
    response_body: str | None = None  # full response (verbose mode)


@dataclasses.dataclass
class RedTeamResult:
    """Aggregated output from one or more red-team modules."""

    target: str
    server_name: str
    server_version: str
    transport: str
    modules_run: list[str]
    findings: list[RedTeamFinding]
    tool_count: int
    attack_count: int
    duration_s: float

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "INFO")

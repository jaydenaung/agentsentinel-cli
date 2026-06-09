"""Auth bypass module — test whether MCP tools enforce authentication.

Creates fresh sessions with deliberately invalid credentials and attempts to
call every tool. A finding is raised only when a tool executes (returns content
or a tool-level error) without valid credentials — proving auth is not enforced.

Tests:
  1. No credentials at all
  2. Empty Authorization bearer
  3. Malformed / garbage token
  4. JWT with alg:none (if original token is a valid JWT)
  5. Expired-format token
"""

from __future__ import annotations

import base64
import json

from agentsentinel_cli.mcp_client import McpAuthRequired, McpError, McpServerInfo
from agentsentinel_cli.redteam.models import RedTeamFinding, ToolCallResult
from agentsentinel_cli.redteam.payloads import build_args
from agentsentinel_cli.redteam.transport import RedTeamSession


# Credential scenarios to probe
_AUTH_SCENARIOS: list[tuple[str, dict]] = [
    ("no credentials",          {}),
    ("empty bearer token",      {"Authorization": "Bearer "}),
    ("null bearer token",       {"Authorization": "Bearer null"}),
    ("garbage token",           {"Authorization": "Bearer AAAAAAAAAAAAAAAA"}),
    ("invalid JWT signature",   {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.INVALID"}),
]


def _forge_alg_none(token: str) -> str | None:
    """Attempt to forge an alg:none JWT from a valid JWT string."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_bytes = base64.urlsafe_b64decode(parts[0] + "==")
        header = json.loads(header_bytes)
        header["alg"] = "none"
        new_header = (
            base64.urlsafe_b64encode(
                json.dumps(header, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
        )
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


def run_auth_bypass(
    url: str | None,
    stdio_cmd: str | None,
    original_headers: dict[str, str],
    timeout: float,
    verbose: bool,
) -> tuple[list[RedTeamFinding], int]:
    """
    Test auth bypass across all credential scenarios.
    Returns (findings, scenarios_tested).
    Requires connection params rather than a pre-connected session because each
    scenario needs a fresh session with different (or no) auth headers.
    """
    if stdio_cmd:
        # stdio is OS-isolated — auth bypass doesn't apply
        return [RedTeamFinding(
            attack_type="auth",
            severity="INFO",
            title="Auth bypass: N/A for stdio transport",
            tool_name="<server>",
            parameter=None,
            payload=None,
            evidence="stdio transport is OS-process-isolated — no network auth surface.",
            exploit_scenario="Not applicable.",
            mitre_id=None,
            owasp_id=None,
            confidence="HIGH",
        )], 0

    findings: list[RedTeamFinding] = []

    # Enumerate tools using the original (valid) credentials so we have targets
    try:
        with RedTeamSession(url=url, extra_headers=original_headers, timeout=timeout) as s:
            tools = s.server_info.tools
    except (McpAuthRequired, McpError):
        findings.append(RedTeamFinding(
            attack_type="auth",
            severity="INFO",
            title="Auth enumeration: cannot reach server with provided credentials",
            tool_name="<server>",
            parameter=None,
            payload=None,
            evidence="Server returned auth error even with provided credentials.",
            exploit_scenario="Verify credentials and retry.",
            mitre_id=None,
            owasp_id=None,
            confidence="HIGH",
        ))
        return findings, 0

    if not tools:
        return findings, 0

    # Build JWT alg:none scenario if the original auth header contains a JWT
    scenarios = list(_AUTH_SCENARIOS)
    orig_auth = original_headers.get("Authorization", "")
    if orig_auth.startswith("Bearer "):
        forged = _forge_alg_none(orig_auth[7:])
        if forged:
            scenarios.append(("JWT alg:none", {"Authorization": f"Bearer {forged}"}))

    scenarios_tested = 0
    # Test each scenario against each tool
    for label, bad_headers in scenarios:
        session_ok = False
        scenarios_tested += 1
        try:
            with RedTeamSession(url=url, extra_headers=bad_headers, timeout=timeout) as s:
                session_ok = True
                _test_scenario(s, tools, label, bad_headers, verbose, findings)
        except McpAuthRequired:
            # Server correctly blocked the connection — no finding for this scenario
            pass
        except McpError:
            pass
        except Exception:
            pass

        # If we couldn't even connect with bad creds, server is properly protecting init
        if not session_ok and label == "no credentials":
            findings.append(RedTeamFinding(
                attack_type="auth",
                severity="INFO",
                title="Auth enforced on MCP handshake",
                tool_name="<server>",
                parameter=None,
                payload=None,
                evidence=f"Server rejected initialize with {label}",
                exploit_scenario="Server correctly requires credentials before tool enumeration.",
                mitre_id=None,
                owasp_id=None,
                confidence="HIGH",
            ))

    return findings, scenarios_tested


def _test_scenario(
    session: RedTeamSession,
    tools: list,
    label: str,
    bad_headers: dict,
    verbose: bool,
    findings: list[RedTeamFinding],
) -> None:
    # If we reached here, the server allowed initialize without proper auth —
    # that's already suspicious. Now try to call each tool.
    for tool in tools:
        props = tool.input_schema.get("properties", {})
        required = tool.input_schema.get("required", [])

        # Build minimal safe arguments (we're not injecting — just calling)
        from agentsentinel_cli.redteam.payloads import safe_default
        args = {p: safe_default(props.get(p, {})) for p in required}

        result: ToolCallResult = session.call_tool(tool.name, args)

        if result.tool_executed:
            _emit_auth_finding(tool.name, label, bad_headers, result, verbose, findings)
            break  # One confirmed bypass per scenario is enough


def _emit_auth_finding(
    tool_name: str,
    scenario_label: str,
    bad_headers: dict,
    result: ToolCallResult,
    verbose: bool,
    findings: list[RedTeamFinding],
) -> None:
    evidence = result.all_text[:200] or f"Tool responded with HTTP {result.http_status}"

    # If the only thing we got was an argument error, lower severity slightly
    is_arg_error = any(
        kw in result.error_message.lower()
        for kw in ("missing", "required", "invalid argument", "parameter")
    )
    severity = "HIGH" if is_arg_error else "CRITICAL"
    detail = (
        "Tool attempted execution (argument validation error) — auth layer is absent."
        if is_arg_error
        else "Tool executed and returned content without valid credentials."
    )

    findings.append(RedTeamFinding(
        attack_type="auth",
        severity=severity,
        title=f"Auth bypass: tool '{tool_name}' callable with {scenario_label}",
        tool_name=tool_name,
        parameter=None,
        payload=scenario_label,
        evidence=evidence,
        exploit_scenario=detail,
        mitre_id="T1078",
        owasp_id="ASI06",
        confidence="HIGH",
        request_body={"tool": tool_name, "auth": scenario_label} if verbose else None,
        response_body=result.raw_response[:500] if verbose else None,
    ))

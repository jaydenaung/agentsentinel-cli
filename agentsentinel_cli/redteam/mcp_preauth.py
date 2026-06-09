"""Pre-auth probe module — HTTP fingerprinting before MCP initialize.

Runs with zero credentials against the raw HTTP surface of the target.
Produces findings even when the server blocks the MCP handshake entirely.
This is the only module that works without a valid token.

Checks:
  1. Server / framework version disclosure in response headers
  2. CORS misconfiguration (wildcard origin, credentials with wildcard)
  3. OAuth 2.0 / OIDC discovery endpoints (/.well-known/*)
  4. Security headers audit (API-relevant subset)
  5. Unauthenticated path probing (/health, /docs, /openapi.json, /metrics)
  6. Unauthenticated SSE stream access
  7. Error message disclosure on malformed requests
"""

from __future__ import annotations

import re
import urllib.parse

from agentsentinel_cli.redteam.models import RedTeamFinding

_EVIL_ORIGIN = "https://evil-attacker.example.com"

_OAUTH_META_PATHS = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-protected-resource",
]

_INFO_PATHS = [
    ("/health",        "Health endpoint"),
    ("/healthz",       "Health endpoint"),
    ("/ready",         "Readiness probe"),
    ("/ping",          "Ping endpoint"),
    ("/status",        "Status endpoint"),
    ("/docs",          "API documentation"),
    ("/redoc",         "API documentation"),
    ("/openapi.json",  "OpenAPI schema"),
    ("/swagger.json",  "Swagger schema"),
    ("/metrics",       "Metrics endpoint"),
    ("/debug",         "Debug endpoint"),
    ("/admin",         "Admin interface"),
]

_VERSION_RE: list[re.Pattern] = [
    re.compile(r"uvicorn/(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"fastapi/(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"starlette/(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"express/(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"werkzeug/(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"flask/(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"python/(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"node\.js/v(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"(go\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"aiohttp/(\d+\.\d+[\.\d]*)", re.IGNORECASE),
]

_SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
]


def run_preauth(
    url: str,
    timeout: float,
    verbose: bool,
) -> tuple[list[RedTeamFinding], int]:
    """
    HTTP-layer probe — zero credentials required.
    Returns (findings, probes_fired).
    """
    try:
        import httpx
    except ImportError:
        return [], 0

    findings: list[RedTeamFinding] = []
    probes = 0
    base = url.rstrip("/")

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        probes += _probe_base(client, base, findings, verbose)
        probes += _probe_cors(client, base, findings, verbose)
        probes += _probe_oauth_metadata(client, base, findings, verbose)
        probes += _probe_info_paths(client, base, findings, verbose)
        probes += _probe_sse_unauth(client, base, findings, verbose)
        probes += _probe_error_disclosure(client, base, findings, verbose)

    return findings, probes


def _probe_base(
    client,
    base: str,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    """GET base URL — fingerprint server from response headers."""
    try:
        resp = client.get(base, headers={"Accept": "application/json"})
    except Exception:
        return 1

    headers = dict(resp.headers)
    disclosed: list[str] = []

    # Server header
    server_hdr = headers.get("server", "")
    if server_hdr:
        for pattern in _VERSION_RE:
            m = pattern.search(server_hdr)
            if m:
                disclosed.append(f"Server: {server_hdr}")
                break
        else:
            if server_hdr:
                disclosed.append(f"Server: {server_hdr}")

    # X-Powered-By
    powered = headers.get("x-powered-by", "")
    if powered:
        disclosed.append(f"X-Powered-By: {powered}")

    # Framework/version in response body
    body_text = resp.text[:2000]
    for pattern in _VERSION_RE:
        m = pattern.search(body_text)
        if m:
            disclosed.append(f"Body: {m.group(0)}")
            break

    if disclosed:
        findings.append(RedTeamFinding(
            attack_type="preauth",
            severity="MEDIUM",
            title="Server version / framework disclosed in HTTP headers",
            tool_name="<server>",
            parameter=None,
            payload="GET /",
            evidence="\n".join(disclosed),
            exploit_scenario=(
                "Server identifies its framework and version in response headers. "
                "Attackers use version information to target known CVEs for that "
                "specific framework release."
            ),
            mitre_id="T1592.002",
            owasp_id="ASI03",
            confidence="HIGH",
            remediation=(
                "Remove or sanitize the `Server` and `X-Powered-By` response headers. "
                "In uvicorn: use `--server-header` flag. In nginx: set `server_tokens off`."
            ),
        ))

    # Security headers audit
    missing = [h for h in _SECURITY_HEADERS if h.lower() not in {k.lower() for k in headers}]
    is_https = base.startswith("https://")
    if not is_https:
        missing = [h for h in missing if h != "Strict-Transport-Security"]

    if missing:
        findings.append(RedTeamFinding(
            attack_type="preauth",
            severity="LOW",
            title=f"Security headers missing ({len(missing)} headers)",
            tool_name="<server>",
            parameter=None,
            payload="GET /",
            evidence="Missing: " + ", ".join(missing),
            exploit_scenario=(
                "Absent security headers expand the attack surface for MIME sniffing, "
                "clickjacking, and content injection. For an MCP server the most relevant "
                "risk is CORS + missing CORP headers enabling cross-origin data theft."
            ),
            mitre_id="T1592.002",
            owasp_id="ASI03",
            confidence="HIGH",
            remediation=(
                "Add security headers to all responses. Minimum for an API: "
                "`X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`."
            ),
        ))

    return 1


def _probe_cors(
    client,
    base: str,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    """Send a cross-origin request and check how the server responds."""
    try:
        resp = client.get(base, headers={
            "Origin": _EVIL_ORIGIN,
            "Accept": "application/json",
        })
    except Exception:
        return 1

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()

    if acao == "*" and acac == "true":
        findings.append(RedTeamFinding(
            attack_type="preauth",
            severity="CRITICAL",
            title="CORS: wildcard origin with credentials allowed",
            tool_name="<server>",
            parameter=None,
            payload=f"Origin: {_EVIL_ORIGIN}",
            evidence=(
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac}"
            ),
            exploit_scenario=(
                "Any website can make credentialed cross-origin requests to this MCP server. "
                "An attacker hosts a page that silently calls MCP tool endpoints using the "
                "victim's browser session/cookies and exfiltrates the responses."
            ),
            mitre_id="T1185",
            owasp_id="ASI06",
            confidence="HIGH",
            remediation=(
                "Never combine `Access-Control-Allow-Origin: *` with "
                "`Access-Control-Allow-Credentials: true`. "
                "Use an explicit allowlist of trusted origins instead of a wildcard."
            ),
        ))
    elif acao == "*":
        findings.append(RedTeamFinding(
            attack_type="preauth",
            severity="HIGH",
            title="CORS: wildcard origin — any site can read responses",
            tool_name="<server>",
            parameter=None,
            payload=f"Origin: {_EVIL_ORIGIN}",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            exploit_scenario=(
                "Any website can make cross-origin requests to this MCP server and read "
                "the responses. If the server returns sensitive tool output, any page the "
                "user visits can silently exfiltrate it."
            ),
            mitre_id="T1185",
            owasp_id="ASI06",
            confidence="HIGH",
            remediation=(
                "Replace `Access-Control-Allow-Origin: *` with an explicit allowlist of "
                "trusted origins. Only allow origins that legitimately need access."
            ),
        ))
    elif acao == _EVIL_ORIGIN:
        findings.append(RedTeamFinding(
            attack_type="preauth",
            severity="HIGH",
            title="CORS: server reflects arbitrary Origin header",
            tool_name="<server>",
            parameter=None,
            payload=f"Origin: {_EVIL_ORIGIN}",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            exploit_scenario=(
                "The server echoes whatever Origin header it receives. An attacker sets a "
                "malicious origin and the browser permits cross-origin reads of MCP responses."
            ),
            mitre_id="T1185",
            owasp_id="ASI06",
            confidence="HIGH",
            remediation=(
                "Validate `Origin` headers against a static allowlist. "
                "Never reflect the request Origin value directly into the response."
            ),
        ))

    return 1


def _probe_oauth_metadata(
    client,
    base: str,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    """Check for OAuth 2.0 / OIDC discovery endpoints."""
    probes = 0
    parsed = urllib.parse.urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in _OAUTH_META_PATHS:
        probes += 1
        try:
            resp = client.get(f"{origin}{path}")
        except Exception:
            continue

        if resp.status_code != 200:
            continue

        try:
            meta = resp.json()
        except Exception:
            continue

        # Interesting fields
        endpoints: list[str] = []
        for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint",
                    "introspection_endpoint", "revocation_endpoint"):
            if key in meta:
                endpoints.append(f"{key}: {meta[key]}")

        scopes = meta.get("scopes_supported", [])
        grant_types = meta.get("grant_types_supported", [])

        has_registration = "registration_endpoint" in meta
        has_implicit = "implicit" in grant_types or "token" in grant_types

        if has_registration:
            findings.append(RedTeamFinding(
                attack_type="preauth",
                severity="HIGH",
                title=f"OAuth: public client registration endpoint reachable — {path}",
                tool_name="<server>",
                parameter=None,
                payload=f"GET {path}",
                evidence=(
                    f"registration_endpoint: {meta['registration_endpoint']}\n"
                    + "\n".join(endpoints[:5])
                ),
                exploit_scenario=(
                    "The authorization server exposes a public dynamic client registration "
                    "endpoint. An attacker can register a malicious OAuth client and obtain "
                    "a valid client_id without any prior authorization — enabling token "
                    "requests and potential scope escalation."
                ),
                mitre_id="T1078.004",
                owasp_id="ASI06",
                confidence="HIGH",
                remediation=(
                    "Require authentication or a registration access token for the "
                    "dynamic client registration endpoint (RFC 7591). "
                    "Disable public registration unless explicitly required."
                ),
            ))
        elif has_implicit:
            findings.append(RedTeamFinding(
                attack_type="preauth",
                severity="MEDIUM",
                title=f"OAuth: implicit grant type supported — {path}",
                tool_name="<server>",
                parameter=None,
                payload=f"GET {path}",
                evidence=f"grant_types_supported: {grant_types}",
                exploit_scenario=(
                    "The implicit grant type exposes access tokens in URL fragments, which "
                    "can be captured by browser history, referrer headers, or malicious scripts. "
                    "OAuth 2.1 deprecates implicit flow for this reason."
                ),
                mitre_id="T1078.004",
                owasp_id="ASI06",
                confidence="HIGH",
                remediation=(
                    "Disable the implicit grant type. Use authorization_code with PKCE instead "
                    "(required by OAuth 2.1 and the MCP 2025 spec)."
                ),
            ))
        else:
            # Just an INFO finding for the metadata itself
            findings.append(RedTeamFinding(
                attack_type="preauth",
                severity="INFO",
                title=f"OAuth metadata discovered — {path}",
                tool_name="<server>",
                parameter=None,
                payload=f"GET {path}",
                evidence="\n".join(endpoints[:6]) + (f"\nscopes: {scopes[:8]}" if scopes else ""),
                exploit_scenario=(
                    "OAuth authorization server metadata is publicly reachable. "
                    "This informs token endpoint abuse and scope escalation tests."
                ),
                mitre_id="T1590",
                owasp_id=None,
                confidence="HIGH",
            ))

    return probes


def _probe_info_paths(
    client,
    base: str,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    """Probe common unauthenticated paths for info disclosure."""
    probes = 0
    parsed = urllib.parse.urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    seen_docs = False

    for path, label in _INFO_PATHS:
        probes += 1
        try:
            resp = client.get(f"{origin}{path}")
        except Exception:
            continue

        if resp.status_code not in (200, 206):
            continue

        ct = resp.headers.get("content-type", "")
        body_preview = resp.text[:200].replace("\n", " ").strip()

        # /docs, /redoc, /openapi.json — API schema exposure
        if any(p in path for p in ("/docs", "/redoc", "/openapi", "/swagger")) and not seen_docs:
            seen_docs = True
            findings.append(RedTeamFinding(
                attack_type="preauth",
                severity="MEDIUM",
                title=f"Unauthenticated API schema accessible — {path}",
                tool_name="<server>",
                parameter=None,
                payload=f"GET {path}",
                evidence=f"HTTP {resp.status_code}  Content-Type: {ct}\n{body_preview}",
                exploit_scenario=(
                    "Full API schema (endpoints, parameters, schemas) is readable without "
                    "credentials. Attackers use schema docs to map every attack surface "
                    "before probing individual endpoints."
                ),
                mitre_id="T1595.002",
                owasp_id="ASI03",
                confidence="HIGH",
                remediation=(
                    "Restrict API documentation and schema endpoints behind authentication. "
                    "Only expose docs in development environments."
                ),
            ))
        elif path in ("/metrics",) and resp.status_code == 200:
            findings.append(RedTeamFinding(
                attack_type="preauth",
                severity="MEDIUM",
                title="Unauthenticated metrics endpoint accessible",
                tool_name="<server>",
                parameter=None,
                payload=f"GET {path}",
                evidence=f"HTTP {resp.status_code}\n{body_preview}",
                exploit_scenario=(
                    "Prometheus/metrics endpoint exposes runtime internals: request counts, "
                    "error rates, memory usage, and potentially business-logic counters. "
                    "Used by attackers to understand traffic patterns and identify anomaly "
                    "detection thresholds."
                ),
                mitre_id="T1592",
                owasp_id="ASI03",
                confidence="HIGH",
                remediation="Require authentication for the /metrics endpoint.",
            ))
        elif path in ("/debug", "/admin") and resp.status_code == 200:
            findings.append(RedTeamFinding(
                attack_type="preauth",
                severity="HIGH",
                title=f"Unauthenticated admin/debug endpoint accessible — {path}",
                tool_name="<server>",
                parameter=None,
                payload=f"GET {path}",
                evidence=f"HTTP {resp.status_code}\n{body_preview}",
                exploit_scenario=(
                    f"The {path} endpoint is accessible without credentials. "
                    "Admin and debug endpoints frequently expose sensitive operations "
                    "or runtime state."
                ),
                mitre_id="T1078",
                owasp_id="ASI06",
                confidence="HIGH",
                remediation=f"Restrict {path} behind strong authentication or remove it entirely.",
            ))

    return probes


def _probe_sse_unauth(
    client,
    base: str,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    """Check if the SSE endpoint streams without authentication."""
    try:
        # Use a short timeout — we just want the headers, not to read the stream
        with client.stream("GET", base, headers={
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
        }) as resp:
            ct = resp.headers.get("content-type", "")
            if resp.status_code == 200 and "text/event-stream" in ct:
                # Read just enough to confirm it's streaming
                first_chunk = ""
                for chunk in resp.iter_text():
                    first_chunk = chunk[:200]
                    break

                findings.append(RedTeamFinding(
                    attack_type="preauth",
                    severity="HIGH",
                    title="Unauthenticated SSE stream — server streams events without credentials",
                    tool_name="<server>",
                    parameter=None,
                    payload="GET / (Accept: text/event-stream)",
                    evidence=(
                        f"HTTP {resp.status_code}  Content-Type: {ct}\n"
                        + (f"Stream data: {first_chunk}" if first_chunk else "Stream opened.")
                    ),
                    exploit_scenario=(
                        "The SSE endpoint streams MCP events to any client without authentication. "
                        "An attacker can connect and receive tool results, agent responses, "
                        "and server-sent notifications intended for legitimate agents."
                    ),
                    mitre_id="T1040",
                    owasp_id="ASI06",
                    confidence="HIGH",
                    remediation=(
                        "Require authentication on the SSE endpoint before opening the stream. "
                        "Validate credentials on the GET /sse request, not just on tool calls."
                    ),
                ))
    except Exception:
        pass

    return 1


def _probe_error_disclosure(
    client,
    base: str,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    """Send malformed requests and check error responses for version/framework disclosure."""
    probes = 0

    # Malformed JSON-RPC
    try:
        probes += 1
        resp = client.post(base, content=b"NOT_JSON{{{", headers={
            "Content-Type": "application/json",
        })
        body = resp.text[:500]

        for pattern in _VERSION_RE:
            m = pattern.search(body)
            if m:
                findings.append(RedTeamFinding(
                    attack_type="preauth",
                    severity="MEDIUM",
                    title="Framework version disclosed in error response",
                    tool_name="<server>",
                    parameter=None,
                    payload="POST / (malformed JSON body)",
                    evidence=f"HTTP {resp.status_code}: {body[:200]}",
                    exploit_scenario=(
                        "The server returns its framework version in error responses to "
                        "malformed requests. Attackers use this to target known CVEs."
                    ),
                    mitre_id="T1592.002",
                    owasp_id="ASI03",
                    confidence="HIGH",
                    remediation=(
                        "Return generic error messages (e.g. '400 Bad Request') that do not "
                        "include framework names, version numbers, or stack traces."
                    ),
                ))
                break
    except Exception:
        pass

    # Wrong content-type
    try:
        probes += 1
        resp = client.post(base, content=b"hello=world", headers={
            "Content-Type": "application/x-www-form-urlencoded",
        })
        body = resp.text[:500]

        # Stack trace in error?
        if any(kw in body for kw in ("Traceback", "at line", "Exception", "panic:", "NullPointer")):
            findings.append(RedTeamFinding(
                attack_type="preauth",
                severity="HIGH",
                title="Stack trace leaked in pre-auth error response",
                tool_name="<server>",
                parameter=None,
                payload="POST / (wrong Content-Type)",
                evidence=f"HTTP {resp.status_code}: {body[:300]}",
                exploit_scenario=(
                    "The server leaks a stack trace in response to a malformed unauthenticated "
                    "request. Stack traces expose internal paths, library versions, and code "
                    "structure useful for crafting targeted exploits."
                ),
                mitre_id="T1592.002",
                owasp_id="ASI03",
                confidence="HIGH",
                remediation=(
                    "Catch all exceptions at the framework level and return generic 400/500 "
                    "responses. Never expose stack traces to unauthenticated clients."
                ),
            ))
    except Exception:
        pass

    return probes

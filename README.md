# agentsentinel-cli

[![PyPI version](https://img.shields.io/pypi/v/agentsentinel-cli)](https://pypi.org/project/agentsentinel-cli/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/agentsentinel-cli)](https://pypi.org/project/agentsentinel-cli/)

**The nmap of AI agents and MCP servers. Deterministic. Protocol-based. No API key required.**

```bash
pipx install agentsentinel-cli
```

---

## What it does

`sentinel` discovers and audits AI agents and MCP servers. Every result is deterministic — same input, same output, every time. No cloud dependency, no API key required for any scan.

| Command | What it answers |
|---------|----------------|
| `sentinel discover` | What MCP servers are running on this host or network? |
| `sentinel mcp scan` | How secure is this specific MCP server? |
| `sentinel supply-chain` | Has this MCP tool manifest been tampered with? |
| `sentinel scan` | What security risks are in this agent's source code? |
| `sentinel secrets` | Are credentials or PII exposed in these files? |
| `sentinel inspect` | What framework, model, and role is this agent? |
| `sentinel a2a` | Are multi-agent trust boundaries safe? |
| `sentinel host-scan` | What is my local AI security posture across all AI tools? |
| `sentinel redteam mcp` | Can I actively exploit this MCP server? |

---

## Quick start

```bash
# Discover MCP servers — local and across a network
sentinel discover
sentinel discover --host 10.0.1.45
sentinel discover --subnet 10.0.0.0/24
sentinel discover --subnet 10.0.0.0/24 --scan   # discover + deep audit in one pass

# Audit a specific MCP server
sentinel mcp scan http://localhost:8000/sse --auth-header "Authorization: Bearer token"
sentinel supply-chain http://localhost:8000/sse

# Scan agent source code
sentinel scan ./agents/
sentinel a2a ./agents/

# Secrets and credentials
sentinel secrets .
sentinel secrets ~/.claude/projects/   # scan Claude Code memory

# Local AI security posture — no network calls
sentinel host-scan
sentinel host-scan --fail-on HIGH

# Active red-team — real attacks, confirmed exploitation
sentinel redteam mcp full http://localhost:8000
sentinel redteam mcp preauth http://localhost:8000              # zero credentials — follows MCP 2025 OAuth chain
sentinel redteam mcp preauth http://localhost:8000 --skip-oauth # skip external AS if out of scope
sentinel redteam mcp inject http://localhost:8000 --type traverse --type ssrf
sentinel redteam mcp auth http://localhost:8000                 # credential bypass + OAuth 2.0
```

---

## Install

```bash
# Zero dependencies — sentinel scan and sentinel a2a
pip install agentsentinel-cli

# + sentinel discover (psutil for process scanning)
pip install "agentsentinel-cli[discover]"

# + sentinel mcp scan, supply-chain, inspect (httpx)
pip install "agentsentinel-cli[mcp]"

# Everything
pip install "agentsentinel-cli[all]"

# Recommended — isolated install
pipx install "agentsentinel-cli[all]"
```

---

## Commands

### `sentinel discover` — find MCP servers and agent processes

Confirms MCP servers via protocol handshake — not just open ports. A result means the MCP `initialize` exchange completed.

```bash
# Local scan — processes + localhost ports
sentinel discover

# Single host
sentinel discover --host 10.0.1.45
sentinel discover --host 10.0.1.45 --auth-header "Authorization: Bearer token"

# Subnet sweep
sentinel discover --subnet 10.0.0.0/24
sentinel discover --subnet 10.0.0.0/24 --auth-header "Authorization: Bearer token"

# Discover + deep security audit in one pass
sentinel discover --host 10.0.1.45 --scan
sentinel discover --subnet 10.0.0.0/24 --scan

# Custom ports, Docker, JSON output
sentinel discover --ports 8000-9000
sentinel discover --docker
sentinel discover --format json
```

**How it works:**
- Phase 1 — parallel TCP sweep across host:port combinations
- Phase 2 — MCP protocol handshake on every open port (streamable-HTTP, falls back to SSE)
- Auth enforcement verified: servers that accept unauthenticated connections stay CRITICAL even if you pass a token

**Risk levels:**
- `CRITICAL` — unauthenticated server with dangerous or write-scope tools
- `HIGH` — unauthenticated server with read-only tools
- `MEDIUM` — MCP server confirmed but auth rejected (credentials needed)
- `LOW` — authenticated, tools enumerated

---

### `sentinel mcp scan` — MCP server security audit

Enumerates all tools on a running MCP server and audits for authentication gaps, dangerous capabilities, injection surface, and exfiltration paths. Supports HTTP (streamable and SSE) and stdio transports.

```bash
sentinel mcp scan http://localhost:8000/sse
sentinel mcp scan http://localhost:8000/sse --auth-header "Authorization: Bearer token"
sentinel mcp scan --stdio "python my_server.py"
sentinel mcp scan http://localhost:8000/sse --fail-on CRITICAL
sentinel mcp scan http://localhost:8000/sse --format json
```

**Rules:**

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `NO_AUTH` | CRITICAL | Server accepts tool enumeration with no credentials |
| `UNAUTH_DANGEROUS_EXEC` | CRITICAL | Dangerous tools callable without authentication |
| `EXFILTRATION_PATH` | CRITICAL | Internal-read tools + external-write tools on the same server |
| `CODE_EXECUTION_TOOL` | CRITICAL | Server exposes shell/exec/code execution tools |
| `UNBOUNDED_INPUT` | HIGH | `command`, `path`, `query`, `url`, `code` parameters with no constraints |
| `TOOL_SPRAWL` | MEDIUM | >10 tools across 5+ distinct categories |
| `VAGUE_TOOL_DESCRIPTIONS` | MEDIUM | Tools with fewer than 3 words in their description |

---

### `sentinel supply-chain` — MCP tool manifest audit

Audits an MCP server's tool manifest for supply chain compromise: description injection, name/capability mismatch, hidden network fields, schema gaps, and registry drift against a saved baseline.

Covers **ASI04** (Agentic Supply Chain Compromise).

```bash
# Static rules
sentinel supply-chain http://localhost:8000/sse
sentinel supply-chain --stdio "python my_server.py"

# + Claude semantic analysis (catches subtle deception static rules miss)
sentinel supply-chain http://localhost:8000/sse --ai

# Baseline drift — detect changes over time
sentinel supply-chain http://localhost:8000/sse --save-baseline ./baseline.json
sentinel supply-chain http://localhost:8000/sse --baseline ./baseline.json

# CI gate
sentinel supply-chain http://localhost:8000/sse --fail-on CRITICAL
```

**Rules:**

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `SC01_DESCRIPTION_INJECTION` | CRITICAL | LLM-targeting phrases in tool descriptions |
| `SC06_REGISTRY_DRIFT` | CRITICAL | Tools added, removed, or schema/description changed vs. baseline |
| `SC02_NAME_CAPABILITY_MISMATCH` | HIGH | Read-only name (`get_`, `list_`) with write/dangerous capability |
| `SC03_HIDDEN_NETWORK_FIELDS` | HIGH | Schema accepts `url`, `webhook`, `endpoint` not disclosed in description |
| `SC04_SCHEMA_MISSING_ON_WRITE` | HIGH | Write/dangerous tool with no input schema |
| `SC05_DECEPTIVE_BENIGN_NAME` | MEDIUM | `help`, `summarize`, `format` masking dangerous capability |

---

### `sentinel scan` — static posture audit

AST analysis of Python agent source files. Detects exfiltration paths, dangerous grants, hardcoded credentials, and privilege excess. No API key required. Zero extra dependencies.

```bash
sentinel scan my_agent.py
sentinel scan ./agents/
sentinel scan ./agents/ --fail-on CRITICAL
sentinel scan ./agents/ --format json
sentinel scan ./agents/ --ignore-rule DANGEROUS_GRANTS  # suppress accepted finding
```

**Detects tools defined via:**
- `@tool` decorator · `BaseTool` / `StructuredTool` subclasses
- `StructuredTool.from_function(name=...)` · `Tool(name=...)`
- `bind_tools([...])` · `create_react_agent(llm, tools)` · `create_agent(llm, tools)`
- `AgentExecutor(tools=[...])` · direct Anthropic/OpenAI API `messages.create(tools=[...])`

**Rules:**

| Rule | Severity | Trigger |
|------|----------|---------|
| `EXFILTRATION_PATH` | CRITICAL | Internal-read AND external-write grants |
| `CODE_EXECUTION_GRANT` | CRITICAL | bash/exec/shell grants |
| `HARDCODED_CREDENTIALS` | CRITICAL | API keys in source |
| `PROMPT_INJECTION_VECTOR` | HIGH | Web-read + write grants |
| `LATERAL_MOVEMENT_PATH` | HIGH | Admin/IAM + infrastructure grants |
| `PRIVILEGE_EXCESS` | HIGH | Write grants on a read-only described agent |
| `DANGEROUS_GRANTS` | HIGH | Dangerous grants outside code execution category |
| `TOOL_SPRAWL` | MEDIUM | >10 tools across 5+ categories |
| `UNDESCRIBED_WRITE_AGENT` | MEDIUM | Write grants, no description |

---

### `sentinel secrets` — credentials, PII, and memory contamination

Scans agent files and memory stores for exposed API keys, credentials, PII, and content that leaked from tool call results into persistent memory. No API key required. Zero extra dependencies.

```bash
sentinel secrets .                         # scan current directory
sentinel secrets ~/.claude/projects/       # scan Claude Code memory
sentinel secrets . --scope memory          # memory files only
sentinel secrets . --severity HIGH         # HIGH and CRITICAL only
sentinel secrets . --fail-on HIGH          # CI gate
sentinel secrets . --format json
```

**Detects:**

- Credentials: Anthropic, OpenAI, AWS, GitHub, Stripe, Google, HuggingFace API keys · private keys · database URLs · JWT tokens
- PII (global): email addresses · credit cards (Luhn-validated) · US SSN · US phone
- PII (Singapore): NRIC/FIN (mod-11 checksum-validated) · passport · mobile · landline · UEN · postal code
- Memory contamination: email + NRIC/SSN clusters from tool call results · system prompt leakage in memory files

---

### `sentinel inspect` — agent intelligence report

Fingerprints an agent file or live HTTP endpoint: framework, model, role (MCP server vs. MCP client vs. agent), system prompt, environment variables.

```bash
sentinel inspect my_agent.py --no-ai
sentinel inspect mcp_server.py --no-ai
sentinel inspect http://localhost:8000
sentinel inspect ./agents/
```

Correctly distinguishes:
- **MCP Server** — `mcp.server.*` imports (tool provider, no LLM)
- **MCP Client** — `mcp.client.*` imports (agent connecting to an MCP server)
- **AI Agent** — standalone LLM agent

With `ANTHROPIC_API_KEY` set, generates a plain English security summary.

---

### `sentinel a2a` — multi-agent trust analysis

Builds a call graph from Python agent source and audits trust boundaries. Detects injection propagation across agent boundaries, unbounded spawning, and code-execution agents accepting unverified delegations.

Supports **LangChain / LangGraph**, **AutoGen**, **CrewAI**, and **MCP client → server connections**.

```bash
sentinel a2a ./agents/
sentinel a2a multi_agent.py
sentinel a2a . --fail-on HIGH
sentinel a2a . --format json
```

**Detected patterns:**
- LangGraph `StateGraph.add_node` / `add_edge` / `add_conditional_edges`
- AutoGen `initiate_chat`, `GroupChat`, `GroupChatManager`
- CrewAI `Crew(agents=[...], process=Process.hierarchical)`
- MCP client connections: `sse_client(url)`, `streamablehttp_client(url)` — surfaces agent → MCP server edges with URL resolution from constants

**Rules:**

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `A2A03_IMPLICIT_TRUST` | CRITICAL | Code-execution agent accepts calls from other agents with no verification |
| `A2A04_PROMPT_PASSTHROUGH` | HIGH | User input flows directly across an agent boundary without sanitization |
| `A2A02_UNBOUNDED_SPAWNING` | HIGH | Agent instantiated inside a loop — unbounded creation risk |
| `A2A06_CIRCULAR_DELEGATION` | HIGH | Cycle in the call graph — agents can loop indefinitely under injection |
| `A2A05_UNSCOPED_DELEGATION` | MEDIUM | Orchestrator delegates full tool set instead of a restricted subset |

Covers **ASI07** (Insecure Inter-Agent Communication).

---

### `sentinel host-scan` — local AI security posture audit

Audits your machine's AI security posture without any network calls. Discovers and audits MCP server configurations across every major AI coding tool on the host — Claude Code, Claude Desktop, Cursor, Windsurf, Continue.dev, Gemini CLI, and VS Code — then checks shell credentials, macOS privacy permissions, system security settings, and running AI processes.

Works on macOS, Linux, and Windows. No API key required.

```bash
sentinel host-scan
sentinel host-scan --format json
sentinel host-scan --fail-on HIGH
sentinel host-scan --ignore-rule HOST_LARGE_MEMORY
```

**What it checks:**

*Anthropic tools*
- **Claude Code** — `allowedTools` (shell bypass), MCP server configs, shell hooks
- **Claude Desktop** — MCP server configs

*Third-party AI tools* — MCP server configs audited with the same exfiltration, broad-filesystem, sensitive-path, and sprawl rules as Claude tools
- **Cursor** — `~/.cursor/mcp.json`
- **Windsurf** — `~/.codeium/windsurf/mcp_config.json`
- **Continue.dev** — `~/.continue/config.json`
- **Gemini CLI** — `~/.gemini/settings.json`
- **VS Code** — `mcp.servers` in `settings.json` (MCP support added in VS Code 1.99)

*Host security*
- **Shell configs** — hardcoded AI API keys in `.zshrc`, `.bashrc`, `.zprofile`, etc.
- **macOS TCC permissions** — Full Disk Access, Screen Recording, Accessibility granted to AI apps
- **macOS system security** — SIP, FileVault, Gatekeeper status
- **Exposed AI processes** — AI-related processes listening on non-localhost network interfaces
- **Memory footprint** — Claude Code conversation memory size in `~/.claude/projects/`

**Rules:**

| Rule | Severity | Category | What it catches |
|------|----------|----------|-----------------|
| `HOST_SHELL_UNRESTRICTED` | CRITICAL | config | `Bash` in `allowedTools` — shell runs without confirmation prompt |
| `HOST_SIP_DISABLED` | CRITICAL | system | macOS System Integrity Protection is off |
| `HOST_API_KEY_IN_SHELL` | HIGH | data_exposure | AI API keys hardcoded in shell config files |
| `HOST_MCP_EXFIL_PATH` | HIGH | config | Any AI tool's MCP server has both filesystem access and network capability |
| `HOST_FDA_AI_APP` | HIGH | permissions | Full Disk Access granted to an AI app or its terminal |
| `HOST_SCREEN_RECORDING_AI` | HIGH | permissions | Screen Recording permission granted to an AI app |
| `HOST_AI_PROCESS_EXPOSED` | HIGH | network | AI-related process listening on a non-localhost interface |
| `HOST_FILEVAULT_OFF` | HIGH | system | FileVault disk encryption is disabled |
| `HOST_ACCESSIBILITY_AI` | MEDIUM | permissions | Accessibility permission granted to an AI app |
| `HOST_HOOKS_SHELL` | MEDIUM | config | Claude Code shell hooks that could interpolate AI output |
| `HOST_MCP_BROAD_FS` | MEDIUM | config | Any AI tool's MCP server configured with home-dir or root-level path |
| `HOST_MCP_SENSITIVE_PATH` | MEDIUM | config | Any AI tool's MCP server has access to `~/.ssh`, `~/.aws`, `~/.kube`, or Keychain |
| `HOST_MANY_MCP_SERVERS` | MEDIUM | config | 8+ MCP servers across all detected AI tools — large prompt injection attack surface |
| `HOST_GATEKEEPER_OFF` | MEDIUM | system | Gatekeeper disabled — unsigned binaries run without warning |
| `HOST_LARGE_MEMORY` | LOW | data_exposure | Claude Code memory files exceed 50 MB of accumulated conversation data |

Every finding includes a **remediation** step. The posture score (0–100) uses the same deduction weights as other sentinel commands: CRITICAL −40, HIGH −20, MEDIUM −10, LOW −5.

No API key required. No network calls.

---

### `sentinel redteam mcp` — active MCP server exploitation

The active red-team module for MCP servers. Every finding is backed by confirmed evidence from the server's actual response — no heuristics, no noise. If a traversal finding says it read `/etc/passwd`, it read `/etc/passwd`.

**Phases 1–2 (`preauth` + OAuth) run with zero credentials** — useful when the target server blocks unauthenticated MCP access entirely. `sentinel` follows the full MCP 2025 OAuth discovery chain to find and test the real authorization server, even when it sits on a separate host.

Requires `httpx`: `pip install "agentsentinel-cli[mcp]"`

```bash
# Full run — all 7 phases, unified report
sentinel redteam mcp full http://localhost:8000
sentinel redteam mcp full http://localhost:8000 --intensity high --format json

# Targeted phases
sentinel redteam mcp preauth http://localhost:8000          # HTTP fingerprint — zero creds required
sentinel redteam mcp recon   http://localhost:8000          # enumerate attack surface
sentinel redteam mcp auth    http://localhost:8000          # credential bypass + OAuth 2.0 attacks
sentinel redteam mcp inject  http://localhost:8000          # all injection techniques
sentinel redteam mcp poison  http://localhost:8000          # tool description + result injection
sentinel redteam mcp fuzz    http://localhost:8000          # schema and type boundary fuzzing

# Preauth — works even when server blocks unauthenticated MCP
sentinel redteam mcp preauth http://localhost:8000
sentinel redteam mcp preauth http://locked-server:8000      # CORS, OAuth discovery, version disclosure

# Skip OAuth tests against an external AS that is out of scope
sentinel redteam mcp preauth http://localhost:8000 --skip-oauth
sentinel redteam mcp full    http://localhost:8000 --skip-oauth

# Surgical injection — pick your techniques
sentinel redteam mcp inject http://localhost:8000 --type traverse
sentinel redteam mcp inject http://localhost:8000 --type traverse --type ssrf
sentinel redteam mcp inject http://localhost:8000 --type cmd --type sqli --intensity high

# With auth
sentinel redteam mcp full http://localhost:8000 \
  --auth-header "Authorization: Bearer token"

# stdio transport (local MCP servers)
sentinel redteam mcp full --stdio "python my_mcp_server.py"

# CI gate — fail if any CRITICAL confirmed
sentinel redteam mcp full http://localhost:8000 --fail-on CRITICAL

# Save full evidence bundle
sentinel redteam mcp full http://localhost:8000 --output report.json
```

---

#### Phases (`full` runs all 7)

| Phase | Command | Needs credentials | What it tests |
|-------|---------|:-----------------:|---------------|
| 1 — Pre-auth probe | `preauth` | No | CORS policy, version disclosure, unauthenticated paths, SSE stream, error disclosure |
| 2 — OAuth attack surface | *(auto in `preauth`/`auth`/`full`)* | No | MCP 2025 discovery chain, client registration, token acquisition, PKCE, scope attacks |
| 3 — Recon | `recon` | Yes | Full tool inventory with input schemas; dangerous capability detection |
| 4 — Auth bypass | `auth` | Optional | 5 credential scenarios: no creds, empty bearer, garbage token, expired JWT, JWT alg:none |
| 5 — Injection | `inject` | Yes | Path traversal, SSRF, command injection, SQL injection — evidence-confirmed only |
| 6 — Poison | `poison` | Yes | Adversarial instructions in tool descriptions; LLM injection via tool result parameters |
| 7 — Fuzz | `fuzz` | Yes | Stack traces, path disclosure, template injection eval, type confusion, input reflection |

---

#### Pre-auth probes — what each check does

All probes in Phase 1 run over plain HTTP before any MCP handshake. No credentials required.

| Probe | Sev | What it checks | Why it matters |
|-------|-----|----------------|----------------|
| **CORS wildcard + credentials** | CRITICAL | `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` | Any website can make credentialed requests to MCP endpoints and read tool responses from the victim's browser session |
| **CORS wildcard** | HIGH | `Access-Control-Allow-Origin: *` without credentials | Any website can read MCP responses — exfiltrates tool output if the user visits a malicious page |
| **CORS reflected origin** | HIGH | Server echoes the request `Origin` header back | Equivalent to wildcard CORS — attacker sets any origin and the browser permits the cross-origin read |
| **Unauthenticated SSE stream** | HIGH | `GET /sse` returns `text/event-stream` without a token | Attacker connects and receives a live feed of all MCP events: tool results, agent responses, server notifications |
| **MCP 2025 oauth-protected-resource** | INFO | `/.well-known/oauth-protected-resource` — identifies the authorization server and its location | Maps the OAuth topology (co-located vs. external AS); informs which server the OAuth attack tests target |
| **Public client registration endpoint** | HIGH | OAuth AS exposes `registration_endpoint` without authentication | Attacker registers a new OAuth client, obtains a valid `client_id`, and can initiate authorization flows |
| **Implicit grant supported** | MEDIUM | `grant_types_supported` includes `implicit` or `token` | Implicit flow exposes access tokens in URL fragments — capturable via browser history, referrer headers, or injected scripts |
| **Server / framework version disclosure** | MEDIUM | `Server:` response header, `X-Powered-By:`, or version string in error body | Attacker maps exact framework versions to known CVEs without any authentication |
| **Unauthenticated `/docs` / `/openapi.json`** | MEDIUM | API schema is readable without credentials | Exposes every endpoint, parameter, and schema — lets attacker fully map the attack surface before sending a single payload |
| **Unauthenticated `/metrics`** | MEDIUM | Prometheus/metrics endpoint accessible | Runtime internals (request counts, error rates, memory usage) reveal traffic patterns and anomaly detection thresholds |
| **Unauthenticated `/debug` or `/admin`** | HIGH | Admin/debug endpoint accessible without credentials | These endpoints frequently expose sensitive operations, config dumps, or runtime state |
| **Stack trace in error response** | HIGH | Malformed requests trigger a full stack trace | Internal file paths, library versions, and code structure are exposed to unauthenticated callers |
| **Framework version in error body** | MEDIUM | Error body contains a framework/version string | Same CVE-mapping risk as the Server header, triggered by a different probe vector |
| **Security headers missing** | LOW | Absent `X-Content-Type-Options`, `Content-Security-Policy`, `X-Frame-Options` | Missing defensive headers expand attack surface for MIME sniffing, clickjacking, and content injection |

---

#### OAuth 2.0 attack surface — how the discovery chain works

The MCP 2025 spec mandates OAuth 2.0. An MCP server is an OAuth **resource server** — it validates tokens but doesn't issue them. The **authorization server** (the service that issues tokens) is often a separate host: Auth0, Okta, Keycloak, AWS Cognito, Azure AD.

`sentinel` follows the full RFC 9728 discovery chain automatically:

```
1. GET /.well-known/oauth-protected-resource   (on the MCP server)
        ↓  authorization_servers: ["https://auth.company.com"]
2. GET https://auth.company.com/.well-known/oauth-authorization-server
        ↓  token_endpoint, registration_endpoint, authorization_endpoint
3. Run all OAuth attack tests against the real AS endpoints
```

**Co-located AS** (dev/test setups): both MCP server and AS run on the same origin (e.g. `localhost:8000`). Tests run automatically and the INFO finding says `(co-located)`.

**Separate AS** (production): MCP server at `api.company.com`, AS at `auth.company.com`. `sentinel` follows the pointer, emits an INFO finding naming the external AS, then runs all OAuth tests against the real AS endpoints. Use `--skip-oauth` if the external AS is a third-party service outside your engagement scope.

**OAuth tests — what each one checks:**

| Test | Severity if confirmed | What `sentinel` does | Attacker impact if found |
|------|----------------------|---------------------|--------------------------|
| **Public client registration** | CRITICAL | `POST /registration_endpoint` with a new client payload, no auth header | Attacker registers a client, obtains a valid `client_id`, initiates auth flows against real users |
| **Token without `client_secret`** | CRITICAL | `POST /token` with `grant_type=client_credentials` and only a `client_id` | Any attacker who knows or guesses a `client_id` gets a valid access token — no secret required |
| **Token with empty `client_secret`** | CRITICAL | Same as above but `client_secret=""` | Empty string is accepted as valid — credential check is bypassed entirely |
| **PKCE plain method** | MEDIUM | `GET /authorize?code_challenge_method=plain` — checks if server accepts instead of rejecting | Code verifier transmitted in cleartext during token exchange; interceptable via logs, proxies, or referrer headers. MCP 2025 spec requires S256. |
| **Scope escalation** | HIGH | Token refresh requesting all supported scopes | Low-privilege token trades up to higher-privilege scopes — breaks least-privilege enforcement |
| **X-Agent-Scopes forgery** | CRITICAL | Authenticated MCP tool call with forged `X-Agent-Scopes` header | If server trusts the client-supplied header, any authenticated agent can invoke tools outside its granted scope |

---

#### Injection techniques (`--type`)

| Technique | What it confirms |
|-----------|-----------------|
| `traverse` | Arbitrary file read via path traversal — evidence: actual `/etc/passwd` content, `.env` key values |
| `ssrf` | Server-side request forgery — evidence: AWS IMDS tokens, Redis/SSH service banners, cloud metadata responses |
| `cmd` | OS command injection — evidence: `uid=0(root)` from `id`, `REDTEAM_CMD_CONFIRMED` sentinel value |
| `sqli` | SQL injection — evidence: DB error messages (`ORA-`, `You have an error in your SQL syntax`) |
| `llm` | LLM instruction injection via tool result — evidence: sentinel instruction string echoed in clean response |

Findings are only raised when a detection pattern matches the actual response body. A 500 error alone is never reported as a finding.

---

#### Intensity levels (`--intensity`)

| Level | Payloads per technique | Use case |
|-------|----------------------|----------|
| `low` | 5 | Fast CI gate |
| `medium` | 15 | Standard engagement (default) |
| `high` | Full library (~20) | Thorough pentest |

---

#### Finding severities

| Severity | Example |
|----------|---------|
| CRITICAL | Path traversal confirmed — `/etc/passwd` content in response; OAuth token issued without secret |
| HIGH | LLM instruction injection — sentinel reflected in clean tool result; CORS wildcard |
| MEDIUM | Input reflected in error message; PKCE plain method accepted; version disclosure |
| LOW | Security headers missing; unexpected content on malformed input |
| INFO | Auth enforced on handshake; tool inventory; OAuth AS topology discovered |

Every finding includes a **Fix** line, **MITRE ATLAS** ID, and **OWASP ASI** ID. Confirmed multi-step attack chains (e.g. path-traversal + shell-exec → full host compromise) are synthesized automatically in the report. Use `--verbose` to see full request/response bodies in every finding.

---

## Finding suppression

Use `--ignore-rule` to suppress findings by rule ID. Suppressed findings are excluded from `--fail-on` evaluation — they don't break CI gates.

```bash
sentinel scan ./agents/ --fail-on HIGH --ignore-rule DANGEROUS_GRANTS
sentinel mcp scan http://localhost:8000/sse --fail-on CRITICAL \
  --ignore-rule NO_AUTH \
  --ignore-rule UNBOUNDED_INPUT
```

For project-level suppressions, create a **`.sentinelignore`** file in your project root. `sentinel` walks up from the target to find it — same discovery pattern as `.gitignore`.

```
# .sentinelignore
NO_AUTH                     # server is behind an authenticated reverse proxy
SC03_HIDDEN_NETWORK_FIELDS  # webhook field verified safe — used for audit logging
```

Supported on: `sentinel scan`, `sentinel a2a`, `sentinel mcp scan`, `sentinel supply-chain`, `sentinel secrets`, `sentinel inspect`.

---

## OWASP Top 10 for Agentic Applications 2026 coverage

| OWASP Risk | ID | sentinel coverage |
|------------|-----|------------------|
| Agent Goal Hijack | ASI01 | `sentinel scan` (PROMPT_INJECTION_VECTOR), `sentinel supply-chain` (SC01), **`sentinel redteam mcp poison`** (confirmed injection) |
| Tool Misuse & Exploitation | ASI02 | `sentinel mcp scan`, `sentinel scan`, **`sentinel redteam mcp inject`** (confirmed exploitation) |
| Agent Identity & Privilege Abuse | ASI03 | `sentinel scan` (PRIVILEGE_EXCESS), `sentinel host-scan` (HOST_SHELL_UNRESTRICTED), **`sentinel redteam mcp auth`** (credential bypass + OAuth scope escalation + X-Agent-Scopes forgery) |
| **Agentic Supply Chain Compromise** | **ASI04** | **`sentinel supply-chain`** (static + AI semantic analysis), **`sentinel redteam mcp poison`** (static description scan) |
| Unexpected Code Execution | ASI05 | `sentinel scan` (CODE_EXECUTION_GRANT), `sentinel mcp scan` (CODE_EXECUTION_TOOL), **`sentinel redteam mcp inject --type cmd`** |
| **Memory & Context Poisoning** | **ASI06** | **`sentinel secrets`** (memory contamination, system prompt leakage), `sentinel host-scan` (HOST_LARGE_MEMORY), **`sentinel redteam mcp preauth`** (CORS misconfiguration enabling cross-origin data theft) |
| **Insecure Inter-Agent Communication** | **ASI07** | **`sentinel a2a`** (call graph + trust rules) |
| Cascading Agent Failures | ASI08 | `sentinel discover` (surface unmonitored agents) |
| Rogue Agents | ASI10 | `sentinel discover` (find agents that shouldn't exist), `sentinel host-scan` (HOST_AI_PROCESS_EXPOSED) |

---

## CI/CD integration

```yaml
# .github/workflows/agent-security.yml
name: Agent Security
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install sentinel
        run: pip install "agentsentinel-cli[mcp]"

      - name: Posture scan
        run: sentinel scan ./agents/ --fail-on CRITICAL

      - name: Secrets scan
        run: sentinel secrets . --fail-on HIGH

      - name: MCP supply chain audit
        run: sentinel supply-chain http://localhost:8000/sse --fail-on CRITICAL

      - name: MCP security audit
        run: sentinel mcp scan http://localhost:8000/sse --fail-on CRITICAL

      - name: Multi-agent trust analysis
        run: sentinel a2a ./agents/ --fail-on HIGH

      - name: Host AI security posture
        run: sentinel host-scan --fail-on HIGH

      - name: MCP pre-auth probe (zero credentials needed)
        run: sentinel redteam mcp preauth http://localhost:8000 --fail-on HIGH

      - name: MCP red-team (active exploitation check)
        run: sentinel redteam mcp full http://localhost:8000 --fail-on CRITICAL
```

Use `.sentinelignore` at the repo root to suppress accepted risks without weakening the gate:

```
# .sentinelignore — committed to source control
NO_AUTH    # server is behind an authenticated reverse proxy
```

---

## Requirements

- Python 3.10+
- No API key required for: `sentinel discover`, `sentinel mcp scan`, `sentinel supply-chain`, `sentinel scan`, `sentinel secrets`, `sentinel inspect --no-ai`, `sentinel a2a`, `sentinel host-scan`, `sentinel redteam mcp`
- `ANTHROPIC_API_KEY` required for: `sentinel supply-chain --ai`, `sentinel inspect` (AI summary)

---

## Related

- [AgentSentinel platform](https://github.com/jaydenaung/agentsentinel) — enterprise AI agent monitoring (Trust Score, behavior baselining, live dashboard)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

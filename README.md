# agentsentinel-cli

[![PyPI version](https://img.shields.io/pypi/v/agentsentinel-cli)](https://pypi.org/project/agentsentinel-cli/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/agentsentinel-cli)](https://pypi.org/project/agentsentinel-cli/)

**The nmap of AI agents and MCP servers. Deterministic. Protocol-based. No API key required.**

```bash
pipx install "agentsentinel-cli[all]"
```

---

## What it does

`sentinel` actively attacks and audits AI agents and MCP servers. Every result is evidence-confirmed — if a traversal finding says it read `/etc/passwd`, it read `/etc/passwd`. No heuristics, no cloud dependency, no API key required for any scan.

| Command | What it does |
|---------|-------------|
| `sentinel redteam mcp` | Actively exploit an MCP server — confirmed traversal, auth bypass, OAuth attacks, injection |
| `sentinel host-scan` | Audit your machine's full AI security posture across Claude, Cursor, Windsurf, VS Code, and more |
| `sentinel a2a` | Build a call graph of your multi-agent system and audit trust boundaries |
| `sentinel discover` | Find every MCP server on a host or subnet — confirmed via protocol handshake |
| `sentinel mcp scan` | Deep security audit of a running MCP server |
| `sentinel supply-chain` | Detect tool manifest tampering, description injection, and schema drift |
| `sentinel scan` | AST-level static analysis of agent source code |
| `sentinel secrets` | Find exposed credentials and PII in agent files and AI memory stores |
| `sentinel inspect` | Fingerprint an agent file or live endpoint |

---

## Quick start

```bash
# Active red-team — real confirmed exploitation
sentinel redteam mcp full http://localhost:8000
sentinel redteam mcp full http://localhost:8000 --auth-header "Authorization: Bearer token"
sentinel redteam mcp preauth http://localhost:8000   # zero credentials — follows MCP 2025 OAuth chain

# Local AI security posture — audits Claude, Cursor, Windsurf, VS Code, and more
sentinel host-scan
sentinel host-scan --fail-on HIGH

# Multi-agent trust analysis
sentinel a2a ./agents/

# Discover and audit MCP servers on a network
sentinel discover --subnet 10.0.0.0/24 --scan

# Static and source-level audits
sentinel mcp scan http://localhost:8000/sse --auth-header "Authorization: Bearer token"
sentinel scan ./agents/
sentinel secrets ~/.claude/projects/
```

---

## Install

```bash
# Everything (recommended)
pipx install "agentsentinel-cli[all]"

# Zero dependencies — sentinel scan, a2a, secrets, inspect
pip install agentsentinel-cli

# + network tools (discover, mcp scan, supply-chain, redteam)
pip install "agentsentinel-cli[mcp]"

# + process scanning (discover --local)
pip install "agentsentinel-cli[discover]"
```

---

## Commands

### `sentinel redteam mcp` — active MCP server exploitation

The active red-team module. Every finding is backed by confirmed evidence from the server's actual response — a traversal finding includes the file content, a token finding includes the actual token. If nothing is confirmed, nothing is reported.

**Phases 1–2 (`preauth` + OAuth) run with zero credentials** — useful when the target blocks unauthenticated MCP access entirely. `sentinel` follows the full MCP 2025 OAuth discovery chain to find and test the real authorization server, even when it lives on a separate host (Auth0, Okta, Azure AD, Keycloak).

Requires `httpx`: `pip install "agentsentinel-cli[mcp]"`

```bash
# Full run — all 7 phases, unified report
sentinel redteam mcp full http://localhost:8000
sentinel redteam mcp full http://localhost:8000 --auth-header "Authorization: Bearer token"
sentinel redteam mcp full http://localhost:8000 --intensity high --format json

# Zero-credential pre-auth probe — follows MCP 2025 OAuth discovery chain
sentinel redteam mcp preauth http://localhost:8000
sentinel redteam mcp preauth http://localhost:8000 --skip-oauth   # skip external AS if out of scope

# Targeted phases
sentinel redteam mcp recon   http://localhost:8000   # enumerate attack surface
sentinel redteam mcp auth    http://localhost:8000   # credential bypass + OAuth 2.0 attacks
sentinel redteam mcp inject  http://localhost:8000   # path traversal, SSRF, cmd, SQLi, LLM injection
sentinel redteam mcp poison  http://localhost:8000   # tool description and result injection
sentinel redteam mcp fuzz    http://localhost:8000   # schema and type boundary fuzzing

# Surgical injection — pick techniques, raise intensity
sentinel redteam mcp inject http://localhost:8000 --type traverse --type ssrf
sentinel redteam mcp inject http://localhost:8000 --type cmd --type sqli --intensity high

# stdio transport (local MCP servers)
sentinel redteam mcp full --stdio "python my_mcp_server.py"

# CI gate — fail if any CRITICAL confirmed
sentinel redteam mcp full http://localhost:8000 --fail-on CRITICAL

# Save full evidence bundle
sentinel redteam mcp full http://localhost:8000 --output report.json
```

#### Phases (`full` runs all 7)

| Phase | Command | Needs credentials | What it tests |
|-------|---------|:-----------------:|---------------|
| 1 — Pre-auth probe | `preauth` | No | CORS policy, version disclosure, unauthenticated paths, SSE stream, error disclosure |
| 2 — OAuth attack surface | *(auto in `preauth` / `auth` / `full`)* | No | MCP 2025 discovery chain, client registration, token acquisition, PKCE, scope attacks |
| 3 — Recon | `recon` | Yes | Full tool inventory with input schemas; dangerous capability detection |
| 4 — Auth bypass | `auth` | Optional | 5 credential scenarios: no creds, empty bearer, garbage token, expired JWT, JWT alg:none |
| 5 — Injection | `inject` | Yes | Path traversal, SSRF, command injection, SQL injection — evidence-confirmed only |
| 6 — Poison | `poison` | Yes | Adversarial instructions in tool descriptions; LLM injection via tool result parameters |
| 7 — Fuzz | `fuzz` | Yes | Stack traces, path disclosure, template injection eval, type confusion, input reflection |

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

**Co-located AS** (dev/test): MCP server and AS on the same host. Tests run automatically; the INFO finding says `(co-located)`.

**Separate AS** (production): MCP at `api.company.com`, AS at `auth.company.com`. `sentinel` follows the pointer, emits an INFO finding naming the external AS, then runs all OAuth tests against the real AS. Use `--skip-oauth` if the external AS is a third-party service outside your engagement scope.

**OAuth tests:**

| Test | Severity | What `sentinel` does | Attacker impact if confirmed |
|------|----------|---------------------|------------------------------|
| Public client registration | CRITICAL | `POST /registration_endpoint` with no auth | Attacker registers an OAuth client, obtains a valid `client_id`, and can initiate auth flows |
| Token without `client_secret` | CRITICAL | `POST /token` with only a `client_id` | Any attacker who knows a `client_id` gets a valid access token — no secret required |
| Token with empty `client_secret` | CRITICAL | Same as above but `client_secret=""` | Empty string accepted — credential check bypassed entirely |
| PKCE plain method | MEDIUM | `GET /authorize?code_challenge_method=plain` | Code verifier transmitted in cleartext; interceptable via logs or proxies. MCP 2025 requires S256. |
| Scope escalation | HIGH | Refresh token requesting all supported scopes | Low-privilege token upgrades to higher-privilege scopes — breaks least-privilege enforcement |
| X-Agent-Scopes forgery | CRITICAL | Authenticated call with forged `X-Agent-Scopes` header | Authenticated agent invokes tools outside its granted scope |

#### Pre-auth probes

All Phase 1 probes run over plain HTTP before any MCP handshake. No credentials required.

| Probe | Sev | What it checks | Why it matters |
|-------|-----|----------------|----------------|
| CORS wildcard + credentials | CRITICAL | `Access-Control-Allow-Origin: *` with `Allow-Credentials: true` | Any website can make credentialed requests to MCP endpoints from the victim's browser |
| CORS wildcard | HIGH | `Access-Control-Allow-Origin: *` | Any website can read MCP tool responses — cross-origin exfiltration |
| CORS reflected origin | HIGH | Server echoes back the request `Origin` header | Equivalent to wildcard CORS — attacker sets any origin and browser permits the read |
| Unauthenticated SSE stream | HIGH | `GET /sse` streams without a token | Attacker receives a live feed of all MCP events: tool results, agent responses, notifications |
| Public client registration | HIGH | `registration_endpoint` reachable unauthenticated | Attacker registers OAuth client without any authorization |
| Stack trace in error response | HIGH | Malformed request triggers full stack trace | Internal paths, library versions, and code structure exposed to unauthenticated callers |
| Unauthenticated `/debug` or `/admin` | HIGH | Admin/debug endpoint returns 200 | Admin endpoints frequently expose sensitive operations or config dumps |
| Server / framework version | MEDIUM | `Server:` header, `X-Powered-By:`, version in error body | Attacker maps exact versions to CVEs without authentication |
| Unauthenticated `/docs` / `/openapi.json` | MEDIUM | API schema readable without credentials | Every endpoint, parameter, and schema exposed — full attack surface in one request |
| Unauthenticated `/metrics` | MEDIUM | Prometheus metrics accessible | Runtime internals reveal traffic patterns and anomaly detection thresholds |
| Implicit grant supported | MEDIUM | `implicit` or `token` in `grant_types_supported` | Access tokens in URL fragments — capturable via browser history or injected scripts |
| Framework version in error body | MEDIUM | Error body contains a version string | Same CVE-mapping risk as the `Server` header |
| Security headers missing | LOW | Absent `X-Content-Type-Options`, `Content-Security-Policy`, `X-Frame-Options` | Missing defensive headers expand MIME sniffing, clickjacking, and content injection surface |

#### Injection techniques (`--type`)

| Technique | What it confirms |
|-----------|-----------------|
| `traverse` | Arbitrary file read — evidence: actual `/etc/passwd` content or `.env` key values |
| `ssrf` | Server-side request forgery — evidence: AWS IMDS tokens, Redis/SSH banners, cloud metadata |
| `cmd` | OS command injection — evidence: `uid=0(root)` from `id`, sentinel value in output |
| `sqli` | SQL injection — evidence: DB error messages (`ORA-`, `You have an error in your SQL syntax`) |
| `llm` | LLM instruction injection via tool result — evidence: sentinel instruction echoed in clean response |

#### Intensity levels (`--intensity`)

| Level | Payloads per technique | Use case |
|-------|----------------------|----------|
| `low` | 5 | Fast CI gate |
| `medium` | 15 | Standard engagement (default) |
| `high` | Full library (~20) | Thorough pentest |

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
- **Shell configs** — hardcoded AI API keys in `.zshrc`, `.bashrc`, `.zprofile`, etc. (macOS/Linux); PowerShell profiles on Windows
- **macOS TCC permissions** — Full Disk Access, Screen Recording, Accessibility granted to AI apps
- **macOS system security** — SIP, FileVault, Gatekeeper status
- **Exposed AI processes** — AI-related processes listening on non-localhost interfaces
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

Every finding includes a remediation step. The posture score (0–100) uses CRITICAL −40, HIGH −20, MEDIUM −10, LOW −5.

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
sentinel scan ./agents/ --ignore-rule DANGEROUS_GRANTS
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
| Agentic Supply Chain Compromise | ASI04 | **`sentinel supply-chain`** (static + AI semantic analysis), **`sentinel redteam mcp poison`** (static description scan) |
| Unexpected Code Execution | ASI05 | `sentinel scan` (CODE_EXECUTION_GRANT), `sentinel mcp scan` (CODE_EXECUTION_TOOL), **`sentinel redteam mcp inject --type cmd`** |
| Memory & Context Poisoning | ASI06 | **`sentinel secrets`** (memory contamination, system prompt leakage), `sentinel host-scan` (HOST_LARGE_MEMORY), **`sentinel redteam mcp preauth`** (CORS misconfiguration) |
| Insecure Inter-Agent Communication | ASI07 | **`sentinel a2a`** (call graph + trust rules) |
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

      - name: Active red-team (zero credentials)
        run: sentinel redteam mcp preauth http://localhost:8000 --fail-on HIGH

      - name: Active red-team (full exploitation check)
        run: sentinel redteam mcp full http://localhost:8000 --fail-on CRITICAL

      - name: Host AI security posture
        run: sentinel host-scan --fail-on HIGH

      - name: Multi-agent trust analysis
        run: sentinel a2a ./agents/ --fail-on HIGH

      - name: MCP security audit
        run: sentinel mcp scan http://localhost:8000/sse --fail-on CRITICAL

      - name: MCP supply chain audit
        run: sentinel supply-chain http://localhost:8000/sse --fail-on CRITICAL

      - name: Posture scan
        run: sentinel scan ./agents/ --fail-on CRITICAL

      - name: Secrets scan
        run: sentinel secrets . --fail-on HIGH
```

Use `.sentinelignore` at the repo root to suppress accepted risks without weakening the gate:

```
# .sentinelignore — committed to source control
NO_AUTH    # server is behind an authenticated reverse proxy
```

---

## Requirements

- Python 3.10+
- No API key required for: `sentinel redteam mcp`, `sentinel host-scan`, `sentinel a2a`, `sentinel discover`, `sentinel mcp scan`, `sentinel supply-chain`, `sentinel scan`, `sentinel secrets`, `sentinel inspect --no-ai`
- `ANTHROPIC_API_KEY` required for: `sentinel supply-chain --ai`, `sentinel inspect` (AI summary)

---

## Related

- [AgentSentinel platform](https://github.com/jaydenaung/agentsentinel) — enterprise AI agent monitoring (Trust Score, behavior baselining, live dashboard)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

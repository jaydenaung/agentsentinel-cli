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
| `sentinel host-scan` | What is my local AI security posture? |

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

Audits your machine's AI security posture without any network calls. Reads Claude Code and Claude Desktop configurations, shell credential files, macOS privacy permissions (TCC), system security settings, and running AI processes.

```bash
sentinel host-scan
sentinel host-scan --format json
sentinel host-scan --fail-on HIGH
sentinel host-scan --ignore-rule HOST_LARGE_MEMORY
```

**What it checks:**
- **Claude Code** — `allowedTools` (Bash bypass), MCP server configs, shell hooks
- **Claude Desktop** — MCP server configs
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
| `HOST_MCP_EXFIL_PATH` | HIGH | config | MCP server has both filesystem access and network capability |
| `HOST_FDA_AI_APP` | HIGH | permissions | Full Disk Access granted to an AI app or its terminal |
| `HOST_SCREEN_RECORDING_AI` | HIGH | permissions | Screen Recording permission granted to an AI app |
| `HOST_AI_PROCESS_EXPOSED` | HIGH | network | AI-related process listening on a non-localhost interface |
| `HOST_FILEVAULT_OFF` | HIGH | system | FileVault disk encryption is disabled |
| `HOST_ACCESSIBILITY_AI` | MEDIUM | permissions | Accessibility permission granted to an AI app |
| `HOST_HOOKS_SHELL` | MEDIUM | config | Claude Code shell hooks that could interpolate AI output |
| `HOST_MCP_BROAD_FS` | MEDIUM | config | MCP server configured with home-dir or root-level path |
| `HOST_MCP_SENSITIVE_PATH` | MEDIUM | config | MCP server has access to `~/.ssh`, `~/.aws`, `~/.kube`, or Keychain |
| `HOST_MANY_MCP_SERVERS` | MEDIUM | config | 8+ MCP servers installed — large prompt injection attack surface |
| `HOST_GATEKEEPER_OFF` | MEDIUM | system | Gatekeeper disabled — unsigned binaries run without warning |
| `HOST_LARGE_MEMORY` | LOW | data_exposure | Claude Code memory files exceed 50 MB of accumulated conversation data |

Every finding includes a **remediation** step. The posture score (0–100) uses the same deduction weights as other sentinel commands: CRITICAL −40, HIGH −20, MEDIUM −10, LOW −5.

No API key required. No network calls.

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
| Agent Goal Hijack | ASI01 | `sentinel scan` (PROMPT_INJECTION_VECTOR), `sentinel supply-chain` (SC01) |
| Tool Misuse & Exploitation | ASI02 | `sentinel mcp scan`, `sentinel scan` |
| Agent Identity & Privilege Abuse | ASI03 | `sentinel scan` (PRIVILEGE_EXCESS), `sentinel host-scan` (HOST_SHELL_UNRESTRICTED) |
| **Agentic Supply Chain Compromise** | **ASI04** | **`sentinel supply-chain`** (static + AI semantic analysis) |
| Unexpected Code Execution | ASI05 | `sentinel scan` (CODE_EXECUTION_GRANT), `sentinel mcp scan` (CODE_EXECUTION_TOOL) |
| **Memory & Context Poisoning** | **ASI06** | **`sentinel secrets`** (memory contamination, system prompt leakage), `sentinel host-scan` (HOST_LARGE_MEMORY) |
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
```

Use `.sentinelignore` at the repo root to suppress accepted risks without weakening the gate:

```
# .sentinelignore — committed to source control
NO_AUTH    # server is behind an authenticated reverse proxy
```

---

## Requirements

- Python 3.10+
- No API key required for: `sentinel discover`, `sentinel mcp scan`, `sentinel supply-chain`, `sentinel scan`, `sentinel secrets`, `sentinel inspect --no-ai`, `sentinel a2a`, `sentinel host-scan`
- `ANTHROPIC_API_KEY` required for: `sentinel supply-chain --ai`, `sentinel inspect` (AI summary)

---

## Related

- [AgentSentinel platform](https://github.com/jaydenaung/agentsentinel) — enterprise AI agent monitoring (Trust Score, behavior baselining, live dashboard)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

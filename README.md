# agentsentinel-cli

[![PyPI version](https://img.shields.io/pypi/v/agentsentinel-cli)](https://pypi.org/project/agentsentinel-cli/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/agentsentinel-cli)](https://pypi.org/project/agentsentinel-cli/)

**AI agent security — analyst mode, static rules, red-team probing, and MCP auditing. No server. No Docker. One install.**

```bash
pipx install "agentsentinel-cli[all]"
```

---

## What it does

`sentinel` covers 8 of the 10 risks in the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

It operates at two levels:

**Analyst mode** — Claude reasons across your entire agent environment, compares against what it remembered from last session, and writes a threat narrative. Catches things static rules never will: cross-finding chains, semantic deception, drift over time.

**Static mode** — fast, deterministic, no API key required. Designed for CI/CD gates.

---

## Quick start

```bash
# Analyst mode — Claude examines your MCP server, remembers what it finds
sentinel agentic http://localhost:3001
sentinel agentic --stdio "python my_mcp_server.py"
sentinel agentic ./my-agent/

# Supply chain audit — is your MCP tool manifest compromised?
sentinel supply-chain http://localhost:3001
sentinel supply-chain http://localhost:3001 --ai   # + Claude semantic analysis

# Static posture scan
sentinel scan my_agent.py
sentinel secrets .
sentinel mcp scan http://localhost:3001
sentinel probe http://localhost:3000
sentinel ai-probe http://localhost:3000
sentinel inspect my_agent.py
sentinel discover
```

---

## Install

```bash
# Recommended — isolated install, no venv required
pipx install "agentsentinel-cli[all]"

# Or with pip, install only what you need
pip install agentsentinel-cli                   # sentinel scan (zero deps)
pip install "agentsentinel-cli[agentic]"        # + sentinel agentic (needs ANTHROPIC_API_KEY)
pip install "agentsentinel-cli[supply-chain]"   # + sentinel supply-chain
pip install "agentsentinel-cli[mcp]"            # + sentinel mcp scan
pip install "agentsentinel-cli[probe]"          # + sentinel probe
pip install "agentsentinel-cli[ai-probe]"       # + sentinel ai-probe
pip install "agentsentinel-cli[discover]"       # + sentinel discover
pip install "agentsentinel-cli[all]"            # everything
```

---

## Commands

### `sentinel agentic` — analyst mode with persistent memory

Claude acts as your security analyst. It reads its memory of prior assessments, decides what to scan, calls sentinel's capabilities as tools, reasons across the results, and produces a threat narrative.

This is not a long system prompt. Claude makes real tool calls that invoke real scanning code, writes state to disk between sessions, and produces different outputs based on what changed — including findings that can only exist across sessions.

```bash
# Assess an MCP server
sentinel agentic http://localhost:3001

# Assess a stdio-transport server
sentinel agentic --stdio "python my_mcp_server.py"

# Assess agent source files
sentinel agentic ./my-agent/

# Add context for better threat modelling
sentinel agentic http://localhost:3001 \
  --context "production MCP server for a fintech data pipeline"

# Use Opus for deeper analysis
sentinel agentic http://localhost:3001 --model claude-opus-4-8

# JSON output for CI or SIEM
sentinel agentic http://localhost:3001 --format json --fail-on HIGH
```

**What makes it different from static rules:**

On a first run it produces findings from the scan. On a second run against the same target it compares current state to its memory — and produces findings like `PERSISTENT_PAYLOAD_TMP` (this threat survived a prior assessment without remediation) or `REGISTRY_DRIFT` (two tools appeared since last session). That cross-session reasoning is impossible with static rules.

Memory is stored in `~/.sentinel/memory/` by default. One file per target, keyed by a hash of the target string. Override with `--memory-dir`.

---

### `sentinel supply-chain` — MCP tool manifest audit

Audits an MCP server's tool manifest for supply chain compromise: description injection, name/capability mismatch, hidden network fields, schema anomalies, and registry drift against a baseline.

Covers **ASI04** (Agentic Supply Chain Compromise) from OWASP Top 10 for Agentic Applications 2026.

```bash
# Static rules only (no API key needed)
sentinel supply-chain http://localhost:3001
sentinel supply-chain --stdio "python my_server.py"

# + Claude semantic analysis (catches creative deception static rules miss)
sentinel supply-chain http://localhost:3001 --ai

# Baseline workflow — detect changes over time
sentinel supply-chain http://localhost:3001 --save-baseline ./baseline.json
sentinel supply-chain http://localhost:3001 --baseline ./baseline.json

# CI gate
sentinel supply-chain http://localhost:3001 --fail-on CRITICAL
```

**Static rules (no API key):**

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `SC01_DESCRIPTION_INJECTION` | CRITICAL | LLM-targeting phrases in tool descriptions (`"ignore previous"`, `"from now on"`, etc.) |
| `SC02_NAME_CAPABILITY_MISMATCH` | HIGH | Read-only name (`get_`, `fetch_`, `list_`) with write/dangerous capability |
| `SC03_HIDDEN_NETWORK_FIELDS` | HIGH | Schema accepts `url`, `webhook`, `endpoint` not disclosed in description |
| `SC04_SCHEMA_MISSING_ON_WRITE` | HIGH | Write/dangerous tool with no input schema — accepts anything |
| `SC05_DECEPTIVE_BENIGN_NAME` | MEDIUM | `help`, `summarize`, `format` masking code execution |
| `SC06_REGISTRY_DRIFT` | CRITICAL | Tools added, removed, or changed vs. saved baseline |

---

### `sentinel scan` — static posture audit

AST analysis of Python agent files. Detects exfiltration paths, dangerous grants, hardcoded credentials, and privilege excess. No API key required.

```bash
sentinel scan my_agent.py
sentinel scan ./agents/
sentinel scan my_agent.py --fail-on CRITICAL    # CI gate
sentinel scan my_agent.py --format json
```

**Rules:**

| Rule | Severity | Trigger |
|------|----------|---------|
| `EXFILTRATION_PATH` | CRITICAL | Internal-read AND external-write grants |
| `CODE_EXECUTION_GRANT` | CRITICAL | bash/exec/shell grants |
| `HARDCODED_CREDENTIALS` | CRITICAL | API keys in source |
| `PROMPT_INJECTION_VECTOR` | HIGH | Web-read + write grants |
| `LATERAL_MOVEMENT_PATH` | HIGH | Admin/IAM + infrastructure grants |
| `PRIVILEGE_EXCESS` | HIGH | Write grants on a read-only described agent |
| `DANGEROUS_GRANTS` | HIGH | Dangerous tool grants present |
| `TOOL_SPRAWL` | MEDIUM | >10 tools across 5+ categories |
| `UNDESCRIBED_WRITE_AGENT` | MEDIUM | Write grants, no description |
| `MISSING_RATE_LIMIT` | LOW | Dangerous grants without rate limiting |

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

Detects: Anthropic, OpenAI, AWS, GitHub, Stripe, Google, HuggingFace keys · email, credit card (Luhn-validated), US SSN · Singapore NRIC/FIN (mod-11 checksum), passport, mobile, UEN · memory contamination (PII clusters from tool call results, system prompt leakage).

---

### `sentinel mcp scan` — MCP server security audit

Enumerates all tools on an MCP server and audits for authentication gaps, dangerous capabilities, and injection surface. Works on HTTP and stdio transports.

```bash
sentinel mcp scan http://localhost:3001
sentinel mcp scan --stdio "python my_server.py"
sentinel mcp scan http://localhost:3001 --auth-header "Authorization: Bearer token"
sentinel mcp scan http://localhost:3001 --fail-on CRITICAL
```

**Rules:** `NO_AUTH` · `UNAUTH_DANGEROUS_EXEC` · `EXFILTRATION_PATH` · `CODE_EXECUTION_TOOL` · `UNBOUNDED_INPUT` · `TOOL_SPRAWL` · `VAGUE_TOOL_DESCRIPTIONS` · `MISSING_RATE_LIMIT`

---

### `sentinel probe` — static red-team battery

Fires attack payloads against any HTTP agent endpoint. No API key required. Good for CI gates.

```bash
sentinel probe http://localhost:3000
sentinel probe http://localhost:3000 --attacks injection,jailbreak
sentinel probe http://localhost:3000 --fail-on HIGH
```

Categories: `injection` · `jailbreak` · `extraction` · `encoding` · `context`

---

### `sentinel ai-probe` — Claude autonomous red-team

Claude Opus acts as an autonomous security researcher. Forms its own threat model, crafts targeted attacks, escalates on partial success, documents findings with OWASP mappings.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
sentinel ai-probe http://localhost:3000
sentinel ai-probe http://localhost:3000 --context "customer service bot for a bank"
sentinel ai-probe http://localhost:3000 --max-probes 30
```

---

### `sentinel inspect` — agent intelligence report

Fingerprints an agent's framework, model, deployment, and data flows. With `ANTHROPIC_API_KEY` set, generates a plain English description.

```bash
sentinel inspect my_agent.py
sentinel inspect http://localhost:3000
sentinel inspect ./agents/ --no-ai
```

---

### `sentinel discover` — find AI agents in your environment

Scans running processes, network ports, Docker containers, and source directories for AI agents — including unmonitored ones.

```bash
sentinel discover
sentinel discover --docker
sentinel discover --subnet 10.0.0.0/24
sentinel discover --path ./agents/
sentinel discover --format json
```

---

## OWASP Top 10 for Agentic Applications 2026 coverage

| OWASP Risk | ID | sentinel coverage |
|------------|-----|------------------|
| Agent Goal Hijack | ASI01 | `sentinel probe`, `sentinel ai-probe` (direct injection); `sentinel agentic` (indirect/semantic) |
| Tool Misuse & Exploitation | ASI02 | `sentinel mcp scan`, `sentinel scan`, `sentinel agentic` |
| Agent Identity & Privilege Abuse | ASI03 | `sentinel scan` (PRIVILEGE_EXCESS), `sentinel agentic` |
| **Agentic Supply Chain Compromise** | **ASI04** | **`sentinel supply-chain`** (static + AI), **`sentinel agentic`** |
| Unexpected Code Execution | ASI05 | `sentinel scan` (CODE_EXECUTION_GRANT), `sentinel mcp scan` |
| **Memory & Context Poisoning** | **ASI06** | **`sentinel secrets`** (memory contamination), **`sentinel agentic`** |
| Insecure Inter-Agent Communication | ASI07 | `sentinel agentic` (reasoning layer) |
| Cascading Agent Failures | ASI08 | `sentinel agentic` (cross-finding chain analysis) |
| Human-Agent Trust Exploitation | ASI09 | `sentinel agentic` (narrative + evidence standard) |
| Rogue Agents | ASI10 | `sentinel agentic` (drift detection across sessions) |

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
        run: sentinel supply-chain http://localhost:3001 --fail-on CRITICAL

      - name: MCP security audit
        run: sentinel mcp scan http://localhost:3001 --fail-on CRITICAL
```

---

## When to use analyst mode vs. static mode

| Situation | Use |
|-----------|-----|
| CI/CD gate on every PR | Static rules (`--fail-on CRITICAL`) |
| Investigating a specific server or codebase | `sentinel agentic` |
| First assessment of a new MCP server | `sentinel agentic` |
| Scheduled nightly security check | `sentinel agentic` (memory tracks drift) |
| Quick local sanity check | `sentinel mcp scan`, `sentinel scan` |
| Red-teaming a live agent endpoint | `sentinel ai-probe` |

---

## Requirements

- Python 3.10+
- `ANTHROPIC_API_KEY` required for: `sentinel agentic`, `sentinel ai-probe`, `sentinel supply-chain --ai`, `sentinel inspect` (AI summary)
- No API key required for: `sentinel scan`, `sentinel secrets`, `sentinel mcp scan`, `sentinel supply-chain`, `sentinel probe`, `sentinel discover`, `sentinel inspect --no-ai`

---

## Related

- [AgentSentinel platform](https://github.com/jaydenaung/agentsentinel) — enterprise AI agent monitoring (Trust Score, behavior baselining, live dashboard)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

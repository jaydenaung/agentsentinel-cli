"""Agentic security analyst mode — Claude as the analyst with persistent memory.

Claude decides what to scan, calls sentinel's existing capabilities as tools,
compares current state to prior assessments, and produces a threat narrative.
Static rules are one of many tools Claude can call — not the whole story.
"""

import dataclasses
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_MEMORY_DIR = Path.home() / ".sentinel" / "memory"
DEFAULT_MAX_CALLS = 30


# ── Data models ───────────────────────────────────────────────────────────────

@dataclasses.dataclass
class AgentFinding:
    severity: str
    rule_id: str
    message: str
    detail: str = ""
    evidence: str = ""
    owasp: str = ""


@dataclasses.dataclass
class AgentReport:
    target: str
    model: str
    threat_level: str
    narrative: str
    findings: list[AgentFinding]
    scans_run: list[str]
    tool_calls: int
    duration_seconds: float
    memory_path: str | None
    had_prior_memory: bool


# ── Memory helpers ────────────────────────────────────────────────────────────

def _target_key(target: str) -> str:
    return hashlib.sha256(target.strip().encode()).hexdigest()[:16]


def load_memory(memory_dir: Path, target: str) -> dict | None:
    path = memory_dir / f"{_target_key(target)}.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return None
    return None


def save_memory(memory_dir: Path, target: str, content: dict) -> Path:
    memory_dir.mkdir(parents=True, exist_ok=True)
    path = memory_dir / f"{_target_key(target)}.json"
    content["_sentinel_target"] = target
    path.write_text(json.dumps(content, indent=2))
    return path


# ── Tool implementations (what runs when Claude calls each tool) ───────────────

def _tool_scan_mcp(url: str | None, stdio_cmd: str | None, timeout: float = 10.0) -> str:
    """Connect to MCP server, run MCP rules + supply chain rules, return structured text."""
    try:
        from agentsentinel_cli.mcp_client import scan_http, scan_stdio, McpError, McpAuthRequired
        from agentsentinel_cli.mcp_rules import McpContext, run_mcp_rules
        from agentsentinel_cli.supply_chain_rules import SupplyChainContext, run_supply_chain_rules

        if stdio_cmd:
            server = scan_stdio(stdio_cmd, timeout=timeout)
            auth_required = False
        elif url:
            server = scan_http(url, timeout=timeout)
            auth_required = False
        else:
            return "ERROR: provide url or stdio_cmd"

        mcp_ctx = McpContext(server=server, auth_required=auth_required)
        mcp_findings = run_mcp_rules(mcp_ctx)
        sc_ctx = SupplyChainContext(server=server)
        sc_findings = run_supply_chain_rules(sc_ctx)

        lines = [
            f"Server: {server.name} v{server.version}",
            f"Transport: {server.transport}",
            f"Tools: {len(server.tools)}",
        ]
        for t in server.tools:
            lines.append(
                f"  - {t.name} (scope: {t.scope}, dangerous: {t.is_dangerous}, category: {t.category})"
            )
            if t.description:
                short_desc = t.description[:120] + ("…" if len(t.description) > 120 else "")
                lines.append(f"    Description: {short_desc}")
            props = t.input_schema.get("properties", {})
            if props:
                fields = ", ".join(
                    f"{k}: {v.get('type', 'any')}{'*' if k in t.input_schema.get('required', []) else ''}"
                    for k, v in props.items()
                )
                lines.append(f"    Schema: {fields}")

        if mcp_findings:
            lines.append("\nMCP Security Findings:")
            for f in mcp_findings:
                lines.append(f"  {f.severity} · {f.rule_id}: {f.message}")
                if f.detail:
                    lines.append(f"    {f.detail}")
        else:
            lines.append("\nMCP Security Findings: none")

        if sc_findings:
            lines.append("\nSupply Chain Findings:")
            for f in sc_findings:
                tool_tag = f" [tool: {f.tool_name}]" if f.tool_name else ""
                lines.append(f"  {f.severity} · {f.rule_id}{tool_tag}: {f.message}")
                if f.detail:
                    lines.append(f"    {f.detail}")
        else:
            lines.append("\nSupply Chain Findings: none")

        return "\n".join(lines)

    except Exception as exc:
        return f"ERROR scanning MCP server: {exc}"


def _tool_scan_files(path: str) -> str:
    """Scan Python agent files for security issues, return structured text."""
    try:
        from agentsentinel_cli.scanner import scan_path
        from agentsentinel_cli.rules import run_rules, posture_score

        p = Path(path)
        if not p.exists():
            return f"ERROR: path does not exist: {path}"

        agents = scan_path(p)
        if not agents:
            return f"No agent files detected in: {path}"

        lines = [f"Agent files found: {len(agents)}"]
        for agent in agents:
            findings = run_rules(agent)
            score = posture_score(findings)
            lines.append(f"\nFile: {agent.file}")
            lines.append(f"  Framework: {agent.framework or 'unknown'}")
            lines.append(f"  Model: {agent.model or 'unknown'}")
            lines.append(f"  Tools: {len(agent.tools)}")
            lines.append(f"  Posture score: {score}/100")
            if findings:
                for f in findings:
                    lines.append(f"  {f.severity} · {f.rule_id}: {f.message}")
                    if f.detail:
                        lines.append(f"    {f.detail}")
            else:
                lines.append("  No findings")

        return "\n".join(lines)

    except Exception as exc:
        return f"ERROR scanning files: {exc}"


def _tool_check_secrets(path: str) -> str:
    """Scan for exposed credentials and PII in agent files and memory stores."""
    try:
        from agentsentinel_cli.secrets import scan_secrets

        p = Path(path)
        if not p.exists():
            return f"ERROR: path does not exist: {path}"

        report = scan_secrets(p, scope="all", redact=True)

        if not report.findings:
            return (
                f"No secrets or PII found. "
                f"Scanned {report.files_scanned} files in {report.duration_seconds:.1f}s."
            )

        lines = [
            f"Secrets scan: {report.files_scanned} files, "
            f"{len(report.findings)} findings in {report.duration_seconds:.1f}s"
        ]
        for f in report.findings:
            lines.append(f"  {f.severity} · {f.rule_id}: {f.message}")
            if f.detail:
                lines.append(f"    {f.detail}")
            if hasattr(f, "file_path") and f.file_path:
                lines.append(f"    File: {f.file_path}")

        return "\n".join(lines)

    except Exception as exc:
        return f"ERROR checking secrets: {exc}"


# ── Tool definitions (Claude's tool schema) ───────────────────────────────────

def _build_tools(target: str, target_is_url: bool, target_is_path: bool, target_is_stdio: bool = False) -> list[dict[str, Any]]:
    tools = []

    tools.append({
        "name": "read_memory",
        "description": (
            "Load your prior assessment of this target from persistent memory. "
            "ALWAYS call this first before any scans. Returns prior threat level, "
            "tool manifest, findings, and analyst notes — or indicates no prior assessment."
        ),
        "input_schema": {"type": "object", "properties": {}},
    })

    if target_is_url or target_is_stdio:
        tools.append({
            "name": "scan_mcp_server",
            "description": (
                "Connect to an MCP server and run the full security audit: tool enumeration, "
                "MCP security rules (auth, code execution, exfiltration paths), and supply chain "
                "rules (description injection, name mismatch, hidden network fields, registry drift). "
                "Returns the complete tool manifest and all findings."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "HTTP URL of the MCP server."},
                    "stdio_cmd": {"type": "string", "description": "Stdio launch command if not HTTP."},
                },
            },
        })

    if target_is_path:
        tools.append({
            "name": "scan_files",
            "description": (
                "Scan Python agent source files in a directory or single file for security issues: "
                "hardcoded credentials, dangerous tool grants, privilege excess, missing rate limits. "
                "Returns detected frameworks, models, tools, and all findings."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File or directory path to scan."},
                },
                "required": ["path"],
            },
        })
        tools.append({
            "name": "check_secrets",
            "description": (
                "Scan files for exposed API keys, credentials, and PII — including inside "
                "agent memory stores (JSON, pickle, vector DB files). "
                "Detects Anthropic, OpenAI, AWS, GitHub keys, and PII patterns."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path to scan."},
                },
                "required": ["path"],
            },
        })

    tools.append({
        "name": "record_finding",
        "description": (
            "Record a confirmed security finding. Only call when you have clear evidence — "
            "scan output proving the issue. Do not record speculative concerns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "description": "CRITICAL=confirmed active risk. HIGH=clear exploit path. MEDIUM=suspicious. LOW=minor.",
                },
                "rule_id": {
                    "type": "string",
                    "description": "Short identifier. Reuse existing rule IDs where applicable, or coin a new one.",
                },
                "message": {"type": "string", "description": "One clear sentence."},
                "detail": {"type": "string", "description": "Supporting detail from scan output."},
                "evidence": {"type": "string", "description": "Exact scan output proving the issue."},
                "owasp": {"type": "string", "description": "OWASP Agentic Top 10 ID e.g. ASI04, ASI06."},
            },
            "required": ["severity", "rule_id", "message"],
        },
    })

    tools.append({
        "name": "update_memory",
        "description": (
            "Save your assessment summary to persistent memory for future sessions. "
            "Call this before finish_analysis. Include: threat_level, tools seen, "
            "key findings summary, and analyst notes on patterns or concerns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "threat_level": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAR"],
                },
                "tools_seen": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of tool names observed (MCP tools or agent tools).",
                },
                "findings_summary": {
                    "type": "string",
                    "description": "1-3 sentence summary of key findings for this session.",
                },
                "analyst_notes": {
                    "type": "string",
                    "description": "Patterns, anomalies, or concerns to remember for next session.",
                },
            },
            "required": ["threat_level", "findings_summary"],
        },
    })

    tools.append({
        "name": "finish_analysis",
        "description": (
            "End your analysis and deliver the final threat narrative. "
            "Always call update_memory before this. "
            "The summary should be 2-5 sentences explaining what you found, "
            "how it compares to prior state, and what the operator should do."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Threat narrative — what was found, what changed, what to do.",
                },
                "threat_level": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAR"],
                },
            },
            "required": ["summary", "threat_level"],
        },
    })

    return tools


# ── System prompt ─────────────────────────────────────────────────────────────

def _system_prompt(target: str, context: str, stdio_cmd: str | None = None) -> str:
    ctx_section = f"\n\nOperator context: {context}" if context else ""
    transport_note = (
        f"\nTransport: stdio — when calling scan_mcp_server, pass stdio_cmd='{stdio_cmd}' (not a url)."
        if stdio_cmd else ""
    )
    return f"""You are sentinel-analyst, an expert AI security analyst specialising in agentic systems security.

Your mission: perform a comprehensive security assessment of the target, drawing on your persistent memory of prior assessments. Identify new risks, track changes over time, and produce a threat narrative that goes beyond what static rules can see.{ctx_section}

## Target
{target}{transport_note}

## Analysis methodology

### Step 1 — Read memory (always first)
Call read_memory before anything else. Understand:
- What was the prior threat level?
- What tools existed? What findings were recorded?
- What patterns or concerns did you note?
- How long ago was the last assessment?

### Step 2 — Scan current state
Run the appropriate scans for the target type. Be thorough.

### Step 3 — Reason holistically
Go beyond individual findings. Ask:
- Do multiple findings together tell a story that individual findings don't?
- Has anything changed since the last assessment? (new tools, changed descriptions, new findings)
- Does the combination of capabilities create an exploitation chain an agent could be tricked into executing?
- Are there patterns consistent with a deliberate supply chain attack vs. sloppy configuration?

### Step 4 — Record confirmed findings
Record findings with clear evidence. For changes since prior assessment, note the delta explicitly.

### Step 5 — Update memory, then finish
Call update_memory with a summary that will help your future self assess this target efficiently.
Then call finish_analysis with your threat narrative.

## Severity guide
- CRITICAL: Confirmed compromise, active attack chain, or irreversible risk
- HIGH: Clear exploit path or strong tampering indicator
- MEDIUM: Suspicious pattern warranting investigation
- LOW: Minor gap or informational

## What static rules miss (your value-add)
- Semantic deception that doesn't use obvious keywords
- Cross-finding patterns that only make sense together
- Context-specific risk (a write tool is higher risk in a financial agent than a demo)
- Trend analysis across sessions — gradual drift is harder to detect per-scan
- Intent inference — does this look like sloppy config or deliberate obfuscation?"""


# ── Agentic loop ──────────────────────────────────────────────────────────────

def run_agent_mode(
    target: str,
    api_key: str,
    model: str = DEFAULT_MODEL,
    memory_dir: Path = DEFAULT_MEMORY_DIR,
    context: str = "",
    max_calls: int = DEFAULT_MAX_CALLS,
    timeout: float = 10.0,
    stdio_cmd: str | None = None,
    progress_cb: Callable[[str, str], None] | None = None,
) -> AgentReport:
    """Run the agentic security analyst against the target.

    progress_cb(tool_name, detail) called on each tool invocation.
    Raises ImportError if anthropic is not installed.
    """
    try:
        import anthropic
    except ImportError:
        raise ImportError(
            "anthropic package required: pip install 'agentsentinel-cli[agentic]'"
        )

    target_is_url = target.startswith("http://") or target.startswith("https://")
    target_is_stdio = bool(stdio_cmd)
    target_is_path = not target_is_url and not target_is_stdio

    client = anthropic.Anthropic(api_key=api_key)
    findings: list[AgentFinding] = []
    scans_run: list[str] = []
    tool_calls = 0
    narrative = ""
    threat_level = "UNKNOWN"
    memory_path: Path | None = None
    had_prior_memory = False
    done = False
    start = time.monotonic()

    prior_memory = load_memory(memory_dir, target)
    if prior_memory:
        had_prior_memory = True

    tools = _build_tools(target, target_is_url, target_is_path, target_is_stdio)
    system = _system_prompt(target, context, stdio_cmd=stdio_cmd)

    messages: list[dict[str, Any]] = [{
        "role": "user",
        "content": (
            f"Begin security assessment.\n"
            f"Target: {target}\n"
            f"Run a thorough agentic assessment. Start by reading your memory, "
            f"then scan, reason holistically, record findings, update memory, and finish."
        ),
    }]

    while not done and tool_calls < max_calls:
        response = client.messages.create(
            model=model,
            max_tokens=8096,
            system=system,
            tools=tools,
            messages=messages,
        )

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            break

        tool_results: list[dict[str, Any]] = []

        for block in response.content:
            if block.type != "tool_use":
                continue

            tool_calls += 1
            inp = block.input
            result_text = ""

            if block.name == "read_memory":
                if progress_cb:
                    progress_cb("read_memory", "loading prior assessment")
                if prior_memory:
                    result_text = json.dumps(prior_memory, indent=2)
                else:
                    result_text = "No prior assessment found for this target. This is the first scan."

            elif block.name == "scan_mcp_server":
                url = inp.get("url") or (target if target_is_url else None)
                effective_stdio = inp.get("stdio_cmd") or stdio_cmd
                label = url or effective_stdio or target
                if progress_cb:
                    progress_cb("scan_mcp_server", label)
                scans_run.append("mcp")
                result_text = _tool_scan_mcp(url, effective_stdio, timeout=timeout)

            elif block.name == "scan_files":
                path = inp.get("path", target)
                if progress_cb:
                    progress_cb("scan_files", path)
                scans_run.append("files")
                result_text = _tool_scan_files(path)

            elif block.name == "check_secrets":
                path = inp.get("path", target)
                if progress_cb:
                    progress_cb("check_secrets", path)
                scans_run.append("secrets")
                result_text = _tool_check_secrets(path)

            elif block.name == "record_finding":
                finding = AgentFinding(
                    severity=inp.get("severity", "MEDIUM"),
                    rule_id=inp.get("rule_id", "ANALYST_FINDING"),
                    message=inp.get("message", ""),
                    detail=inp.get("detail", ""),
                    evidence=inp.get("evidence", ""),
                    owasp=inp.get("owasp", ""),
                )
                findings.append(finding)
                if progress_cb:
                    progress_cb("record_finding", f"{finding.severity}: {finding.rule_id}")
                result_text = "Finding recorded."

            elif block.name == "update_memory":
                import datetime
                memory_content = {
                    "last_assessed": datetime.datetime.utcnow().isoformat() + "Z",
                    "threat_level": inp.get("threat_level", "UNKNOWN"),
                    "tools_seen": inp.get("tools_seen", []),
                    "findings_summary": inp.get("findings_summary", ""),
                    "analyst_notes": inp.get("analyst_notes", ""),
                    "finding_count": len(findings),
                }
                memory_path = save_memory(memory_dir, target, memory_content)
                if progress_cb:
                    progress_cb("update_memory", str(memory_path))
                result_text = f"Memory updated at {memory_path}"

            elif block.name == "finish_analysis":
                narrative = inp.get("summary", "")
                threat_level = inp.get("threat_level", "UNKNOWN")
                if progress_cb:
                    progress_cb("finish_analysis", threat_level)
                result_text = "Analysis complete."
                done = True

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_text,
            })

        if tool_results:
            messages.append({"role": "user", "content": tool_results})

    scans_run = list(dict.fromkeys(scans_run))  # deduplicate preserving order

    return AgentReport(
        target=target,
        model=model,
        threat_level=threat_level,
        narrative=narrative,
        findings=findings,
        scans_run=scans_run,
        tool_calls=tool_calls,
        duration_seconds=round(time.monotonic() - start, 1),
        memory_path=str(memory_path) if memory_path else None,
        had_prior_memory=had_prior_memory,
    )

"""Core logic for sentinel inspect — agent intelligence report with fingerprint and AI summary."""

import dataclasses
import time
from pathlib import Path

from agentsentinel_cli.scanner import ToolInfo, scan_file
from agentsentinel_cli.rules import Finding, run_rules, posture_score
from agentsentinel_cli.fingerprint import AgentFingerprint, fingerprint_file, fingerprint_live


@dataclasses.dataclass
class DataFlow:
    """A single inferred data flow — where the agent reads from or writes to."""

    direction: str   # "Input" | "Output"
    resource: str    # human label, e.g. "PostgreSQL database"
    tool: str        # tool name that drives this flow
    risk: str        # "critical" | "high" | "medium" | "low"


@dataclasses.dataclass
class InspectReport:
    """Full intelligence report for a single agent."""

    target: str
    fingerprint: AgentFingerprint
    tools: list[ToolInfo]
    findings: list[Finding]
    data_flows: list[DataFlow]
    trust_score: int
    trust_status: str
    summary: str
    summary_source: str   # "claude" | "template"
    duration_seconds: float


_STATUS_THRESHOLDS = [(80, "TRUSTED"), (60, "WATCH"), (40, "ALERT"), (0, "CRITICAL")]

_CATEGORY_RESOURCE: dict[str, tuple[str, str]] = {
    "database":       ("PostgreSQL/database",     "internal"),
    "filesystem":     ("local filesystem",        "internal"),
    "web":            ("external web",            "external"),
    "communication":  ("email/messaging service", "external"),
    "code_execution": ("code execution",          "internal"),
    "secrets":        ("secrets/credential store","internal"),
    "admin":          ("IAM/admin systems",       "internal"),
    "crm":            ("CRM system",              "internal"),
    "analytics":      ("analytics/BI system",     "internal"),
    "infrastructure": ("cloud infrastructure",    "external"),
}


def _trust_status(score: int) -> str:
    for threshold, label in _STATUS_THRESHOLDS:
        if score >= threshold:
            return label
    return "CRITICAL"


def _infer_data_flows(tools: list[ToolInfo]) -> list[DataFlow]:
    """Map tool categories and scopes to human-readable data flow labels."""
    seen: set[str] = set()
    flows: list[DataFlow] = []
    for tool in tools:
        resource, _ = _CATEGORY_RESOURCE.get(tool.category, ("external service", "external"))
        key = f"{tool.scope}:{resource}"
        if key in seen:
            continue
        seen.add(key)
        direction = "Input" if tool.scope == "read" else "Output"
        risk = "critical" if tool.is_dangerous and tool.scope == "write" else \
               "high" if tool.is_dangerous or tool.scope == "write" else "low"
        flows.append(DataFlow(direction=direction, resource=resource, tool=tool.name, risk=risk))
    return flows


def _template_summary(
    fingerprint: AgentFingerprint,
    tools: list[ToolInfo],
    findings: list[Finding],
) -> str:
    """Generate a plain English summary without Claude — used as fallback."""
    if fingerprint.server_type == "mcp_server":
        fw = fingerprint.framework if fingerprint.framework != "unknown" else "MCP server"
        parts: list[str] = [f"This is a {fw} — a tool provider with no LLM of its own."]
        parts.append("It exposes tools for AI agents to call.")
        if tools:
            parts.append(f"Tools exposed: {', '.join(t.name for t in tools[:4])}.")
        parts.append("Run sentinel mcp scan against the live endpoint for a full security audit.")
        return " ".join(parts)

    fw = fingerprint.framework if fingerprint.framework != "unknown" else "AI agent"
    model_str = f" using {fingerprint.model}" if fingerprint.model else ""

    parts = []
    parts.append(f"This is a {fw} agent{model_str} with {len(tools)} tool(s).")

    categories = list(dict.fromkeys(t.category for t in tools if t.category != "other"))
    if categories:
        parts.append(f"It accesses: {', '.join(categories[:4])}.")

    dangerous = [t.name for t in tools if t.is_dangerous]
    if dangerous:
        parts.append(f"Dangerous capabilities: {', '.join(dangerous[:3])}.")

    critical = [f for f in findings if f.severity == "CRITICAL"]
    if critical:
        parts.append(f"Critical finding: {critical[0].message}")

    return " ".join(parts)


def _claude_summary(
    api_key: str,
    fingerprint: AgentFingerprint,
    tools: list[ToolInfo],
    findings: list[Finding],
    target: str,
    model: str,
) -> str:
    """Ask Claude to synthesise a plain English description of the agent."""
    try:
        import anthropic
    except ImportError:
        return ""

    tool_block = "\n".join(
        f"  - {t.name} ({t.category}, {t.scope}"
        f"{', DANGEROUS' if t.is_dangerous else ''})"
        f"{': ' + t.docstring[:80] if t.docstring else ''}"
        for t in tools
    ) or "  No tools detected"

    finding_block = "\n".join(
        f"  - {f.severity}: {f.rule_id} — {f.message}" for f in findings[:5]
    ) or "  None"

    fp_line = (
        f"Framework: {fingerprint.framework}  |  Model: {fingerprint.model or 'unknown'}  |  "
        f"Deployment: {fingerprint.deployment}  |  Cloud: {fingerprint.cloud}"
    )

    prompt = (
        "You are a security analyst reviewing an AI agent. "
        "Write a 2–3 sentence plain English description covering: what this agent does, "
        "what systems it accesses, and the single most important security concern. "
        "Be specific. No bullet points or headers.\n\n"
        f"Target: {target}\n"
        f"{fp_line}\n"
        f"System prompt found: {fingerprint.system_prompt_found}\n"
        + (f"System prompt snippet: {fingerprint.system_prompt_snippet}\n"
           if fingerprint.system_prompt_snippet else "")
        + f"\nTools:\n{tool_block}\n\nSecurity findings:\n{finding_block}"
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model=model,
            max_tokens=220,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text.strip()
    except Exception:
        return ""


def inspect_file(
    path: Path,
    api_key: str = "",
    summary_model: str = "claude-haiku-4-5-20251001",
) -> InspectReport | None:
    """Inspect an agent source file and produce a full intelligence report.

    Returns None if no agent tools are detected and no fingerprint signals exist.
    """
    t0 = time.monotonic()

    fp = fingerprint_file(path)
    agent = scan_file(path)

    if agent is None and fp.framework == "unknown":
        return None

    tools = agent.tools if agent else []
    findings = run_rules(agent) if agent else []
    score = posture_score(findings) if findings else 100

    # Scanner may detect model that fingerprinter missed (or vice versa)
    if agent and agent.model and not fp.model:
        fp.model = agent.model

    flows = _infer_data_flows(tools)
    status = _trust_status(score)

    if api_key:
        summary = _claude_summary(api_key, fp, tools, findings, str(path), summary_model)
        source = "claude" if summary else "template"
        if not summary:
            summary = _template_summary(fp, tools, findings)
    else:
        summary = _template_summary(fp, tools, findings)
        source = "template"

    return InspectReport(
        target=str(path),
        fingerprint=fp,
        tools=tools,
        findings=findings,
        data_flows=flows,
        trust_score=score,
        trust_status=status,
        summary=summary,
        summary_source=source,
        duration_seconds=round(time.monotonic() - t0, 2),
    )


def inspect_live(
    url: str,
    extra_headers: dict[str, str] | None = None,
    api_key: str = "",
    summary_model: str = "claude-haiku-4-5-20251001",
) -> InspectReport:
    """Fingerprint a live HTTP agent endpoint and produce a partial intelligence report.

    Full tool enumeration is not available for live endpoints — use sentinel scan
    on the source file for complete posture analysis.
    """
    t0 = time.monotonic()

    fp = fingerprint_live(url, extra_headers=extra_headers)

    # No AST-derived tools or posture findings for live endpoints
    summary = (
        f"Live HTTP agent at {url}. "
        f"Framework: {fp.framework}. Cloud: {fp.cloud}. "
        "For full posture analysis run sentinel scan on the source file, "
        "or sentinel mcp scan if this is an MCP server."
    )
    source = "template"

    if api_key and fp.framework != "unknown":
        claude = _claude_summary(api_key, fp, [], [], url, summary_model)
        if claude:
            summary, source = claude, "claude"

    return InspectReport(
        target=url,
        fingerprint=fp,
        tools=[],
        findings=[],
        data_flows=[],
        trust_score=50,   # unknown — no posture data
        trust_status="WATCH",
        summary=summary,
        summary_source=source,
        duration_seconds=round(time.monotonic() - t0, 2),
    )

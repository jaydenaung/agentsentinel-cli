"""Rich terminal and JSON output for sentinel inspect."""

import json

from rich.console import Console
from rich.panel import Panel

from agentsentinel_cli.inspect import InspectReport

console = Console()

_SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
}
_STATUS_COLOR = {
    "TRUSTED":  "bold green",
    "WATCH":    "bold yellow",
    "ALERT":    "bold orange1",
    "CRITICAL": "bold red",
}
_RISK_COLOR = {
    "critical": "bold red",
    "high":     "bold orange1",
    "medium":   "bold yellow",
    "low":      "dim green",
}


def print_inspect_result(report: InspectReport) -> None:
    """Render a full agent intelligence report to the terminal."""
    console.print()
    console.print(Panel.fit(
        f"[bold white]AgentSentinel Inspect[/bold white]\n"
        f"[dim]Target: {report.target}[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    # ── FUNCTION ──────────────────────────────────────────────────────────────
    if report.summary:
        console.print()
        console.rule("[dim]FUNCTION[/dim]", style="dim")
        console.print()
        for line in _wrap(report.summary, 80):
            console.print(f"  {line}")
        if report.summary_source == "claude":
            console.print("  [dim italic]  (AI-generated summary)[/dim italic]")
        console.print()

    # ── FINGERPRINT ───────────────────────────────────────────────────────────
    console.rule("[dim]FINGERPRINT[/dim]", style="dim")
    console.print()
    fp = report.fingerprint

    type_label = (
        "[bold yellow]MCP Server[/bold yellow] (tool provider — use sentinel mcp scan for full audit)"
        if fp.server_type == "mcp_server"
        else "[bold white]AI Agent[/bold white] (tool consumer with LLM)"
    )
    _fp_row("Type",          type_label)
    _fp_row("Framework",     fp.framework if fp.framework != "unknown" else "[dim]unknown[/dim]")
    _fp_row("Model",         fp.model or ("[dim]n/a — MCP servers have no LLM[/dim]" if fp.server_type == "mcp_server" else "[dim]not detected[/dim]"))
    _fp_row("Python",        fp.python_version or "[dim]not detected[/dim]")
    _fp_row("Deployment",    fp.deployment if fp.deployment != "local" else "[dim]local[/dim]")
    _fp_row("Cloud",         fp.cloud if fp.cloud != "unknown" else "[dim]on-prem / unknown[/dim]")

    if fp.system_prompt_found:
        snippet = fp.system_prompt_snippet[:70] + "…" if fp.system_prompt_snippet else ""
        _fp_row("System prompt", f"[bold yellow]Found[/bold yellow]  [dim]{snippet}[/dim]")
    else:
        _fp_row("System prompt", "[dim]not detected[/dim]")

    if fp.env_vars:
        _fp_row("Env vars", ", ".join(fp.env_vars[:6]))
    if fp.external_apis:
        _fp_row("External APIs", ", ".join(fp.external_apis[:5]))

    console.print()

    # ── CAPABILITIES ──────────────────────────────────────────────────────────
    if report.tools:
        console.rule(
            f"[dim]CAPABILITIES[/dim]  [dim white]({len(report.tools)} tools)[/dim white]",
            style="dim",
        )
        console.print()
        sorted_tools = sorted(report.tools, key=lambda t: (not t.is_dangerous, t.scope == "read"))
        for tool in sorted_tools:
            sev = (
                "CRITICAL" if tool.is_dangerous and tool.scope == "write" else
                "HIGH"     if tool.is_dangerous or tool.scope == "write" else
                "MEDIUM"
            )
            color = _SEVERITY_COLOR[sev]
            arrow = "→" if tool.scope == "write" else "←"
            desc = tool.docstring[:60] if tool.docstring else tool.category
            console.print(
                f"  [{color}]●[/{color}] [bold white]{tool.name:<28}[/bold white]"
                f"  [{color}]{sev:<8}[/{color}]  "
                f"[dim]{arrow} {tool.category:<14}[/dim]  [dim]{desc}[/dim]"
            )
        console.print()

    # ── DATA FLOWS ────────────────────────────────────────────────────────────
    if report.data_flows:
        console.rule("[dim]DATA FLOWS[/dim]", style="dim")
        console.print()
        for flow in report.data_flows:
            arrow = "←" if flow.direction == "Input" else "→"
            rc = _RISK_COLOR.get(flow.risk, "white")
            console.print(
                f"  [dim]{flow.direction:<6}[/dim]  [{rc}]{arrow}[/{rc}]  "
                f"[bold white]{flow.resource}[/bold white]  [dim]({flow.tool})[/dim]"
            )
        console.print()

    # ── SECURITY FINDINGS ────────────────────────────────────────────────────
    if report.findings:
        _sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        console.rule(
            f"[dim]SECURITY FINDINGS[/dim]  [dim white]({len(report.findings)} findings)[/dim white]",
            style="dim",
        )
        console.print()
        for f in sorted(report.findings, key=lambda x: _sev_rank.get(x.severity, 4)):
            color = _SEVERITY_COLOR.get(f.severity, "white")
            console.print(
                f"  [{color}]● {f.severity:<8}[/{color}]  "
                f"[bold white]{f.rule_id}[/bold white]  [dim]{f.message}[/dim]"
            )
        console.print()
    elif report.tools:
        console.print("  [dim green]✓ No posture findings.[/dim green]\n")

    # ── TRUST SCORE ───────────────────────────────────────────────────────────
    sc = _STATUS_COLOR.get(report.trust_status, "white")
    console.rule(style="bright_blue")
    console.print(
        f"  Trust Score  [{sc}]{report.trust_score} / 100  {report.trust_status}[/{sc}]"
        f"  [dim]· {len(report.tools)} tools"
        f" · {len(report.findings)} findings"
        f" · {report.duration_seconds}s[/dim]"
    )
    console.print()


def as_inspect_json(report: InspectReport) -> str:
    """Serialise an InspectReport to JSON."""
    fp = report.fingerprint
    return json.dumps({
        "target": report.target,
        "trust_score": report.trust_score,
        "trust_status": report.trust_status,
        "summary": report.summary,
        "summary_source": report.summary_source,
        "fingerprint": {
            "framework":           fp.framework,
            "model":               fp.model,
            "python_version":      fp.python_version,
            "deployment":          fp.deployment,
            "cloud":               fp.cloud,
            "system_prompt_found": fp.system_prompt_found,
            "system_prompt_snippet": fp.system_prompt_snippet,
            "env_vars":            fp.env_vars,
            "external_apis":       fp.external_apis,
        },
        "tools": [
            {
                "name":         t.name,
                "scope":        t.scope,
                "is_dangerous": t.is_dangerous,
                "category":     t.category,
                "description":  t.docstring,
            }
            for t in report.tools
        ],
        "data_flows": [
            {
                "direction": f.direction,
                "resource":  f.resource,
                "tool":      f.tool,
                "risk":      f.risk,
            }
            for f in report.data_flows
        ],
        "findings": [
            {
                "rule_id":  f.rule_id,
                "severity": f.severity,
                "message":  f.message,
            }
            for f in report.findings
        ],
        "duration_seconds": report.duration_seconds,
    }, indent=2)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fp_row(label: str, value: str) -> None:
    console.print(f"  [dim]{label:<16}[/dim] {value}")


def _wrap(text: str, width: int) -> list[str]:
    """Naive word-wrap — keeps Rich markup intact."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width and current:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines

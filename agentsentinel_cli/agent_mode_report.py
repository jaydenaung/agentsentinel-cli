"""Rich terminal and JSON output for agentic security analysis."""

import json

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box
from rich.text import Text

from agentsentinel_cli.agent_mode import AgentReport, AgentFinding

console = Console()

_SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
}

_THREAT_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "CLEAR":    "bold green",
    "UNKNOWN":  "dim white",
}

_THREAT_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "CLEAR":    "🟢",
    "UNKNOWN":  "⚪",
}


def print_agent_report(report: AgentReport) -> None:
    threat_color = _THREAT_COLOR.get(report.threat_level, "white")
    threat_icon = _THREAT_ICON.get(report.threat_level, "")

    console.print()
    console.print(Panel.fit(
        f"[bold white]AgentSentinel Agentic Analysis[/bold white]  "
        f"[dim cyan]claude-analyst[/dim cyan]\n"
        f"[dim]Target: {report.target}[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    memory_tag = (
        "[dim green]✓ prior assessment loaded[/dim green]"
        if report.had_prior_memory
        else "[dim yellow]first assessment — memory created[/dim yellow]"
    )
    scans_tag = " · ".join(report.scans_run) if report.scans_run else "none"

    console.print(
        f"\n  Model       [dim]{report.model}[/dim]\n"
        f"  Memory      {memory_tag}\n"
        f"  Scans run   [dim]{scans_tag}[/dim]\n"
        f"  Tool calls  [dim]{report.tool_calls}[/dim]   "
        f"Duration [dim]{report.duration_seconds}s[/dim]"
    )

    # ── Threat narrative ──────────────────────────────────────────────────────
    console.print()
    console.print(Rule("Threat Narrative", style="bright_blue"))
    console.print()

    if report.narrative:
        # Wrap narrative at ~80 chars
        words = report.narrative.split()
        lines: list[str] = []
        current = ""
        for word in words:
            if len(current) + len(word) + 1 > 78:
                lines.append(current)
                current = word
            else:
                current = (current + " " + word).strip()
        if current:
            lines.append(current)
        for line in lines:
            console.print(f"  {line}")
    else:
        console.print("  [dim](no narrative produced)[/dim]")

    console.print()

    # ── Findings ──────────────────────────────────────────────────────────────
    if report.findings:
        console.print(Rule("Findings", style="bright_blue"))
        console.print()
        for f in report.findings:
            color = _SEVERITY_COLOR.get(f.severity, "white")
            owasp_tag = f"  [dim]{f.owasp}[/dim]" if f.owasp else ""
            console.print(
                f"  [{color}]● {f.severity:<8}[/{color}]  "
                f"[bold white]{f.rule_id}[/bold white]{owasp_tag}"
            )
            console.print(f"  [dim]           {f.message}[/dim]")
            if f.detail:
                console.print(f"  [dim]           {f.detail}[/dim]")
            if f.evidence:
                short_ev = f.evidence[:120] + ("…" if len(f.evidence) > 120 else "")
                console.print(f"  [dim]           Evidence: {short_ev}[/dim]")
            console.print()

    # ── Footer ────────────────────────────────────────────────────────────────
    console.rule(style="bright_blue")

    n_critical = sum(1 for f in report.findings if f.severity == "CRITICAL")
    n_high     = sum(1 for f in report.findings if f.severity == "HIGH")
    total      = len(report.findings)

    parts = [f"[bold white]{total}[/bold white] finding{'s' if total != 1 else ''}"]
    if n_critical:
        parts.append(f"[bold red]{n_critical} CRITICAL[/bold red]")
    if n_high:
        parts.append(f"[bold orange1]{n_high} HIGH[/bold orange1]")

    console.print("  " + " · ".join(parts))
    console.print(
        f"\n  Threat Level  [{threat_color}]{threat_icon}  {report.threat_level}[/{threat_color}]"
    )

    if report.memory_path:
        console.print(f"  Memory saved  [dim]{report.memory_path}[/dim]")

    console.print()


def as_agent_json(report: AgentReport) -> str:
    return json.dumps({
        "target": report.target,
        "model": report.model,
        "threat_level": report.threat_level,
        "narrative": report.narrative,
        "had_prior_memory": report.had_prior_memory,
        "scans_run": report.scans_run,
        "tool_calls": report.tool_calls,
        "duration_seconds": report.duration_seconds,
        "memory_path": report.memory_path,
        "findings": [
            {
                "severity": f.severity,
                "rule_id": f.rule_id,
                "message": f.message,
                "detail": f.detail,
                "evidence": f.evidence,
                "owasp": f.owasp,
            }
            for f in report.findings
        ],
    }, indent=2)

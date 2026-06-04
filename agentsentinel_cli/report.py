"""Terminal output and JSON report formatting."""

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from agentsentinel_cli.scanner import AgentInfo
from agentsentinel_cli.rules import Finding

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
_SCOPE_STYLE = {
    "read":  ("green", "read "),
    "write": ("yellow", "write"),
}


def _status_from_score(score: int) -> str:
    if score >= 80:
        return "TRUSTED"
    if score >= 60:
        return "WATCH"
    if score >= 40:
        return "ALERT"
    return "CRITICAL"


def _severity_icon(severity: str) -> str:
    return {"CRITICAL": "●", "HIGH": "●", "MEDIUM": "●", "LOW": "●"}.get(severity, "●")


def print_scan_result(
    agents: list[AgentInfo],
    findings_map: dict[Path, list[Finding]],
    scores_map: dict[Path, int],
    target: Path,
) -> None:
    total_findings = sum(len(f) for f in findings_map.values())
    total_critical = sum(1 for fl in findings_map.values() for f in fl if f.severity == "CRITICAL")
    total_high = sum(1 for fl in findings_map.values() for f in fl if f.severity == "HIGH")

    console.print()
    console.print(Panel.fit(
        f"[bold white]AgentSentinel Security Scan[/bold white]\n"
        f"[dim]Target: {target}[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    if not agents:
        console.print("\n[yellow]No agent tool definitions found in target.[/yellow]")
        console.print("[dim]Tip: AgentSentinel detects @tool decorators, BaseTool subclasses, and Tool() calls.[/dim]")
        return

    for agent in agents:
        findings = findings_map.get(agent.file, [])
        score = scores_map.get(agent.file, 100)
        status = _status_from_score(score)

        console.print(f"\n[bold white]File:[/bold white] [dim]{agent.file}[/dim]")

        # Hardcoded credentials warning (show before tools table)
        if agent.hardcoded_creds:
            console.print()
            for cred in agent.hardcoded_creds:
                console.print(f"  [bold red]⛔ HARDCODED CREDENTIAL[/bold red]  [dim]{cred}[/dim]")
            console.print()

        # Tools table
        tools_table = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
        tools_table.add_column("Scope", style="dim", width=6)
        tools_table.add_column("Tool", style="bold white")
        tools_table.add_column("Category", style="dim", width=14)
        tools_table.add_column("", width=12)

        for tool in sorted(agent.tools, key=lambda t: (t.scope, t.name)):
            scope_color, scope_label = _SCOPE_STYLE[tool.scope]
            danger_tag = Text("⚠ dangerous", style="bold red") if tool.is_dangerous else Text("")
            tools_table.add_row(
                Text(scope_label, style=scope_color),
                tool.name,
                tool.category,
                danger_tag,
            )
        console.print(tools_table)

        if agent.model:
            console.print(f"  [dim]Model:[/dim] {agent.model}")
        if agent.description:
            console.print(f"  [dim]Description:[/dim] {agent.description[:80]}")

        # Findings
        if findings:
            console.print()
            for f in findings:
                color = _SEVERITY_COLOR.get(f.severity, "white")
                console.print(f"  [{color}]{_severity_icon(f.severity)} {f.severity:<8}[/{color}]  "
                               f"[bold white]{f.rule_id}[/bold white]")
                console.print(f"  [dim]         {f.message}[/dim]")
                if f.detail:
                    console.print(f"  [dim]         {f.detail}[/dim]")
                console.print()
        else:
            console.print("  [green]✓ No posture findings[/green]\n")

        # Score bar
        status_color = _STATUS_COLOR.get(status, "white")
        bar_filled = int(score / 5)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        console.print(
            f"  Posture Score  [{status_color}]{score:>3}/100[/{status_color}]  "
            f"[dim]{bar}[/dim]  [{status_color}]{status}[/{status_color}]"
        )

    # Summary footer
    console.print()
    console.rule(style="bright_blue")
    summary_parts = [
        f"[bold white]{len(agents)}[/bold white] agent{'s' if len(agents) != 1 else ''} scanned",
        f"[bold white]{total_findings}[/bold white] finding{'s' if total_findings != 1 else ''}",
    ]
    if total_critical:
        summary_parts.append(f"[bold red]{total_critical} CRITICAL[/bold red]")
    if total_high:
        summary_parts.append(f"[bold orange1]{total_high} HIGH[/bold orange1]")
    console.print("  " + " · ".join(summary_parts))

    console.print()


def as_json(
    agents: list[AgentInfo],
    findings_map: dict[Path, list[Finding]],
    scores_map: dict[Path, int],
) -> str:
    output = []
    for agent in agents:
        findings = findings_map.get(agent.file, [])
        score = scores_map.get(agent.file, 100)
        output.append({
            "file": str(agent.file),
            "model": agent.model,
            "description": agent.description,
            "hardcoded_credentials": agent.hardcoded_creds,
            "tools": [
                {
                    "name": t.name,
                    "scope": t.scope,
                    "is_dangerous": t.is_dangerous,
                    "category": t.category,
                }
                for t in agent.tools
            ],
            "findings": [
                {
                    "severity": f.severity,
                    "rule_id": f.rule_id,
                    "message": f.message,
                    "detail": f.detail,
                }
                for f in findings
            ],
            "posture_score": score,
            "status": _status_from_score(score),
        })
    return json.dumps(output, indent=2)

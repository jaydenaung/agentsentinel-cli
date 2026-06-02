"""Rich terminal and JSON output for MCP server security scans."""

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from agentsentinel_cli.mcp_rules import McpContext, McpFinding, mcp_posture_score

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


def _status_label(score: int) -> str:
    if score >= 80:
        return "TRUSTED"
    if score >= 60:
        return "WATCH"
    if score >= 40:
        return "ALERT"
    return "CRITICAL"


def print_mcp_result(
    ctx: McpContext,
    findings: list[McpFinding],
    score: int,
    target: str,
) -> None:
    """Render the full MCP scan report to the terminal."""
    server = ctx.server
    status = _status_label(score)
    status_color = _STATUS_COLOR[status]

    console.print()
    console.print(Panel.fit(
        f"[bold white]AgentSentinel MCP Security Scan[/bold white]\n"
        f"[dim]Target: {target}[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    auth_tag = (
        "[bold red]✗ No auth required[/bold red]"
        if not ctx.auth_required
        else "[dim green]✓ Authenticated[/dim green]"
    )
    transport_tag = f"[dim]{server.transport.upper()}[/dim]"
    console.print(
        f"\n  Server   [bold white]{server.name}[/bold white] [dim]v{server.version}[/dim]\n"
        f"  Transport {transport_tag}   Auth {auth_tag}"
    )

    if not server.tools:
        console.print("\n  [yellow]No tools found on this server.[/yellow]")
        _print_footer(findings, score, status_color, server.tools, ctx)
        return

    # Tools table
    console.print()
    table = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
    table.add_column("Tool", style="bold white", min_width=22)
    table.add_column("Category", style="dim", width=16)
    table.add_column("Scope", width=6)
    table.add_column("", width=13)
    table.add_column("Description", style="dim", max_width=52)

    for tool in sorted(server.tools, key=lambda t: t.name):
        scope_text = (
            Text("write", style="yellow") if tool.scope == "write"
            else Text("read", style="green")
        )
        danger_tag = Text("⚠ dangerous", style="bold red") if tool.is_dangerous else Text("")
        desc = (tool.description[:50] + "…") if len(tool.description) > 52 else tool.description
        table.add_row(tool.name, tool.category, scope_text, danger_tag, desc)

    console.print(table)

    # Findings
    if findings:
        for f in findings:
            color = _SEVERITY_COLOR.get(f.severity, "white")
            console.print(
                f"  [{color}]● {f.severity:<8}[/{color}]  [bold white]{f.rule_id}[/bold white]"
            )
            console.print(f"  [dim]           {f.message}[/dim]")
            if f.detail:
                console.print(f"  [dim]           {f.detail}[/dim]")
            console.print()
    else:
        console.print("  [green]✓ No security findings[/green]\n")

    _print_footer(findings, score, status_color, server.tools, ctx)


def _print_footer(
    findings: list[McpFinding],
    score: int,
    status_color: str,
    tools: list,
    ctx: McpContext,
) -> None:
    status = _status_label(score)
    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    console.print(
        f"  Posture Score  [{status_color}]{score:>3}/100[/{status_color}]  "
        f"[dim]{bar}[/dim]  [{status_color}]{status}[/{status_color}]"
    )

    n_critical = sum(1 for f in findings if f.severity == "CRITICAL")
    n_high = sum(1 for f in findings if f.severity == "HIGH")
    total = len(findings)

    console.print()
    console.rule(style="bright_blue")
    parts = [f"[bold white]{len(tools)}[/bold white] tools enumerated"]
    parts.append(f"[bold white]{total}[/bold white] finding{'s' if total != 1 else ''}")
    if n_critical:
        parts.append(f"[bold red]{n_critical} CRITICAL[/bold red]")
    if n_high:
        parts.append(f"[bold orange1]{n_high} HIGH[/bold orange1]")
    console.print("  " + " · ".join(parts))

    if not ctx.auth_required and any(f.rule_id == "NO_AUTH" for f in findings):
        console.print(
            "\n  [bold red]⚠  This server requires no authentication.[/bold red]  "
            "[dim]Any process with network access can enumerate and invoke all tools.[/dim]"
        )

    console.print()


def as_mcp_json(
    ctx: McpContext,
    findings: list[McpFinding],
    score: int,
    target: str,
) -> str:
    """Serialize MCP scan results as JSON."""
    server = ctx.server
    return json.dumps({
        "target": target,
        "transport": server.transport,
        "server_name": server.name,
        "server_version": server.version,
        "auth_required": ctx.auth_required,
        "tool_count": len(server.tools),
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "scope": t.scope,
                "is_dangerous": t.is_dangerous,
                "category": t.category,
                "has_input_schema": bool(t.input_schema.get("properties")),
            }
            for t in server.tools
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
        "status": _status_label(score),
    }, indent=2)

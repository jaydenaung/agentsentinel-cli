"""Rich terminal and JSON output for supply chain security audits."""

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from agentsentinel_cli.supply_chain_rules import SupplyChainFinding, SupplyChainContext

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


def print_supply_chain_result(
    ctx: SupplyChainContext,
    findings: list[SupplyChainFinding],
    score: int,
    target: str,
    used_ai: bool = False,
    baseline_path: str | None = None,
) -> None:
    server = ctx.server
    status = _status_label(score)
    status_color = _STATUS_COLOR[status]
    ai_tag = "  [dim cyan]+AI[/dim cyan]" if used_ai else ""

    console.print()
    console.print(Panel.fit(
        f"[bold white]AgentSentinel Supply Chain Audit[/bold white]{ai_tag}\n"
        f"[dim]Target: {target}[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    baseline_tag = (
        f"  [dim]Baseline: {baseline_path}[/dim]\n"
        if baseline_path else ""
    )
    console.print(
        f"\n  Server    [bold white]{server.name}[/bold white] [dim]v{server.version}[/dim]\n"
        f"  Transport [dim]{server.transport.upper()}[/dim]\n"
        f"{baseline_tag}"
    )

    if not server.tools:
        console.print("  [yellow]No tools found on this server.[/yellow]")
        _print_footer(findings, score, status_color, server.tools)
        return

    # ── Tools table ──────────────────────────────────────────────────────────
    console.print()
    table = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
    table.add_column("Tool", style="bold white", min_width=22)
    table.add_column("Category", style="dim", width=16)
    table.add_column("Scope", width=6)
    table.add_column("", width=11)
    table.add_column("Findings", style="dim red", width=8)
    table.add_column("Description", style="dim", max_width=48)

    tool_findings: dict[str, list[SupplyChainFinding]] = {}
    for f in findings:
        tool_findings.setdefault(f.tool_name, []).append(f)

    for tool in sorted(server.tools, key=lambda t: t.name):
        scope_text = (
            Text("write", style="yellow") if tool.scope == "write"
            else Text("read", style="green")
        )
        danger_tag = Text("⚠ dangerous", style="bold red") if tool.is_dangerous else Text("")
        tool_f = tool_findings.get(tool.name, [])
        finding_count = (
            Text(f"● {len(tool_f)}", style="bold red") if tool_f else Text("")
        )
        desc = (tool.description[:46] + "…") if len(tool.description) > 48 else tool.description
        table.add_row(tool.name, tool.category, scope_text, danger_tag, finding_count, desc)

    console.print(table)

    # ── Findings ─────────────────────────────────────────────────────────────
    if findings:
        console.print()
        for f in findings:
            color = _SEVERITY_COLOR.get(f.severity, "white")
            tool_tag = f"  [dim]tool: {f.tool_name}[/dim]" if f.tool_name else ""
            console.print(
                f"  [{color}]● {f.severity:<8}[/{color}]  "
                f"[bold white]{f.rule_id}[/bold white]{tool_tag}"
            )
            console.print(f"  [dim]           {f.message}[/dim]")
            if f.detail:
                console.print(f"  [dim]           {f.detail}[/dim]")
            console.print()
    else:
        console.print("  [green]✓ No supply chain compromise indicators found[/green]\n")

    _print_footer(findings, score, status_color, server.tools)


def _print_footer(findings, score, status_color, tools) -> None:
    status = _status_label(score)
    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    console.print(
        f"  Supply Chain Score  [{status_color}]{score:>3}/100[/{status_color}]  "
        f"[dim]{bar}[/dim]  [{status_color}]{status}[/{status_color}]"
    )

    n_critical = sum(1 for f in findings if f.severity == "CRITICAL")
    n_high = sum(1 for f in findings if f.severity == "HIGH")
    total = len(findings)

    console.print()
    console.rule(style="bright_blue")
    parts = [f"[bold white]{len(tools)}[/bold white] tools audited"]
    parts.append(f"[bold white]{total}[/bold white] finding{'s' if total != 1 else ''}")
    if n_critical:
        parts.append(f"[bold red]{n_critical} CRITICAL[/bold red]")
    if n_high:
        parts.append(f"[bold orange1]{n_high} HIGH[/bold orange1]")

    drift = sum(1 for f in findings if f.rule_id == "SC06_REGISTRY_DRIFT")
    if drift:
        parts.append(f"[bold red]{drift} REGISTRY DRIFT[/bold red]")

    console.print("  " + " · ".join(parts))

    if any(f.rule_id == "SC01_DESCRIPTION_INJECTION" for f in findings):
        console.print(
            "\n  [bold red]⚠  LLM instruction injection detected in tool descriptions.[/bold red]  "
            "[dim]This is a confirmed supply chain compromise indicator.[/dim]"
        )
    if drift:
        console.print(
            "\n  [bold red]⚠  Tool registry has drifted from baseline.[/bold red]  "
            "[dim]Investigate all changes before deploying agents against this server.[/dim]"
        )

    console.print()


def as_supply_chain_json(
    ctx: SupplyChainContext,
    findings: list[SupplyChainFinding],
    score: int,
    target: str,
    used_ai: bool = False,
) -> str:
    server = ctx.server
    return json.dumps({
        "target": target,
        "transport": server.transport,
        "server_name": server.name,
        "server_version": server.version,
        "tool_count": len(server.tools),
        "ai_analysis": used_ai,
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "scope": t.scope,
                "is_dangerous": t.is_dangerous,
                "category": t.category,
            }
            for t in server.tools
        ],
        "findings": [
            {
                "severity": f.severity,
                "rule_id": f.rule_id,
                "tool_name": f.tool_name,
                "message": f.message,
                "detail": f.detail,
            }
            for f in findings
        ],
        "supply_chain_score": score,
        "status": _status_label(score),
    }, indent=2)

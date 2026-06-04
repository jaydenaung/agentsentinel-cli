"""Rich terminal output for sentinel discover results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from agentsentinel_cli.discover import DiscoveredAgent, SubnetScanStats

console = Console()

_RISK_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "UNKNOWN":  "dim white",
}
_RISK_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "UNKNOWN":  "⚪",
}
_SOURCE_LABEL = {
    "process": "PROCESS",
    "network": "NETWORK",
    "subnet":  "SUBNET",
    "file":    "FILE",
    "docker":  "DOCKER",
}


def print_subnet_progress(completed: int, total: int, current_ip: str, phase: str = "1") -> None:
    """Inline progress updater for subnet scan — overwrites the same line."""
    pct = int(completed / total * 100) if total else 0
    label = "TCP sweep" if phase == "1" else "MCP handshake"
    console.print(
        f"\r  [dim]Phase {phase} {label}: {current_ip} … {pct}% ({completed}/{total})[/dim]",
        end="",
        highlight=False,
    )
    if completed == total:
        console.print()  # newline when done


def print_discover_result(
    agents: list[DiscoveredAgent],
    vectors: list[str],
    verbose: bool = False,
    subnet_stats: SubnetScanStats | None = None,
) -> None:
    console.print()
    console.print(Panel.fit(
        f"[bold white]AgentSentinel — Discover[/bold white]\n"
        f"[dim]Scanning: {' · '.join(vectors)}[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))
    console.print()

    if not agents:
        console.print("  [green]✓  No AI agents found in the scanned environment.[/green]")
        if subnet_stats:
            console.print(
                f"  [dim]Subnet scan: {subnet_stats.cidr} — "
                f"{subnet_stats.hosts_scanned:,} host{'s' if subnet_stats.hosts_scanned != 1 else ''} · "
                f"{subnet_stats.open_ports_found} open port{'s' if subnet_stats.open_ports_found != 1 else ''} · "
                f"{subnet_stats.elapsed_seconds:.1f}s[/dim]"
            )
        console.print()
        console.print("  [dim]Tip: use [bold]--subnet 10.0.0.0/24[/bold] to scan a network range, "
                      "or [bold]--docker[/bold] to inspect containers.[/dim]")
        console.print()
        return

    # Group by source
    by_source: dict[str, list[DiscoveredAgent]] = {}
    for agent in agents:
        by_source.setdefault(agent.source, []).append(agent)

    for source, source_agents in by_source.items():
        console.print(Rule(
            f"  {_SOURCE_LABEL.get(source, source.upper())} SCAN",
            style="bright_blue",
            align="left",
        ))
        console.print()

        for agent in source_agents:
            _print_agent(agent, verbose=verbose)

        console.print()

    _print_summary(agents, subnet_stats=subnet_stats)


def _print_agent(agent: DiscoveredAgent, verbose: bool) -> None:
    risk_color = _RISK_COLOR.get(agent.risk, "white")
    icon = _RISK_ICON.get(agent.risk, "⚪")

    # Framework + provider display
    framework_str = agent.framework
    if agent.provider:
        framework_str = f"{agent.framework} + {agent.provider}" if agent.framework not in (
            agent.provider, "Unknown"
        ) else agent.provider

    # Location pill
    loc = f"[dim]{agent.location}[/dim]"

    # Header line
    name_text = Text(agent.name, style="bold white")
    framework_text = Text(f"{framework_str:<28}", style="cyan")
    risk_text = Text(f"{agent.risk:<8}", style=risk_color)

    console.print(
        f"  {icon}  [{risk_color}]{agent.risk:<8}[/{risk_color}]  "
        f"[bold white]{agent.name:<30}[/bold white]  "
        f"[cyan]{framework_str:<28}[/cyan]  "
        f"[dim]{agent.location}[/dim]"
    )

    # Model
    if agent.model:
        console.print(f"  {'':>10}[dim]Model:[/dim] {agent.model}")

    # API key exposure (always shown — this is the "oh shit" moment)
    for key in agent.api_keys:
        console.print(f"  {'':>10}[bold red]⚠  API key exposed:[/bold red] [red]{key}[/red]")

    # Live LLM connections
    if agent.live_connections:
        hosts = ", ".join(sorted(set(agent.live_connections)))
        console.print(f"  {'':>10}[dim]Live connections:[/dim] {hosts}")

    # Enumerated tools (MCP network findings only)
    if agent.tools:
        tools_str = ", ".join(agent.tools[:8])
        if len(agent.tools) > 8:
            tools_str += f" (+{len(agent.tools) - 8} more)"
        console.print(f"  {'':>10}[dim]Tools:[/dim] [cyan]{tools_str}[/cyan]")

    # Risk reason
    console.print(f"  {'':>10}[dim]{agent.risk_reason}[/dim]")

    # Next step suggestion
    console.print(
        f"  {'':>10}[dim]→ [/dim][bold dim]{agent.next_step}[/bold dim]"
    )

    console.print()


def _print_summary(
    agents: list[DiscoveredAgent],
    subnet_stats: SubnetScanStats | None = None,
) -> None:
    console.rule(style="bright_blue")
    console.print()

    total     = len(agents)
    critical  = sum(1 for a in agents if a.risk == "CRITICAL")
    high      = sum(1 for a in agents if a.risk == "HIGH")
    medium    = sum(1 for a in agents if a.risk == "MEDIUM")
    low       = sum(1 for a in agents if a.risk == "LOW")
    unknown   = sum(1 for a in agents if a.risk == "UNKNOWN")
    exposed   = sum(1 for a in agents if a.api_keys)

    parts: list[str] = [f"[bold white]{total}[/bold white] agent{'s' if total != 1 else ''} found"]
    if critical:
        parts.append(f"[bold red]{critical} CRITICAL[/bold red]")
    if high:
        parts.append(f"[bold orange1]{high} HIGH[/bold orange1]")
    if medium:
        parts.append(f"[bold yellow]{medium} MEDIUM[/bold yellow]")
    if low:
        parts.append(f"[bold cyan]{low} LOW[/bold cyan]")
    if unknown:
        parts.append(f"[dim]{unknown} UNKNOWN[/dim]")

    console.print("  " + " · ".join(parts))

    if exposed:
        console.print()
        console.print(
            f"  [bold red]⚠  {exposed} agent{'s have' if exposed != 1 else ' has'} "
            f"API key{'s' if exposed != 1 else ''} exposed in the environment.[/bold red]"
        )
        console.print(
            "  [dim]Exposed keys are visible to all processes on this host. "
            "Rotate them and move to a secrets manager.[/dim]"
        )

    if critical or high:
        console.print()
        console.print(
            "  [dim]Run [bold]sentinel mcp scan <url>[/bold] "
            "for a full tool-by-tool security audit on any MCP server above.[/dim]"
        )

    if subnet_stats:
        console.print()
        console.print(
            f"  [dim]Subnet scan: {subnet_stats.cidr} — "
            f"{subnet_stats.hosts_scanned:,} hosts · "
            f"{subnet_stats.open_ports_found} open port{'s' if subnet_stats.open_ports_found != 1 else ''} · "
            f"{subnet_stats.elapsed_seconds:.1f}s[/dim]"
        )

    console.print()

"""Rich terminal and JSON output for sentinel a2a — multi-agent trust analysis."""

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from agentsentinel_cli.a2a_scanner import A2AGraph, AgentNode, A2AEdge
from agentsentinel_cli.a2a_rules import A2AFinding, a2a_posture_score

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
_FRAMEWORK_COLOR = {
    "autogen":   "cyan",
    "langchain": "green",
    "langgraph": "bright_green",
    "crewai":    "magenta",
    "generic":   "dim",
}
_ROLE_TAG = {
    "orchestrator": "[bold white]orchestrator[/bold white]",
    "worker":       "[dim]worker[/dim]",
    "peer":         "[dim]peer[/dim]",
    "unknown":      "[dim]unknown[/dim]",
}


def _status_label(score: int) -> str:
    if score >= 80:
        return "TRUSTED"
    if score >= 60:
        return "WATCH"
    if score >= 40:
        return "ALERT"
    return "CRITICAL"


def print_a2a_result(
    graph: A2AGraph,
    findings: list[A2AFinding],
    score: int,
    target: str,
) -> None:
    status       = _status_label(score)
    status_color = _STATUS_COLOR[status]

    console.print()
    console.print(Panel.fit(
        f"[bold white]AgentSentinel A2A Trust Analysis[/bold white]\n"
        f"[dim]Target: {target}[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    if not graph.nodes:
        console.print(
            "\n  [yellow]No multi-agent patterns detected.[/yellow]\n"
            "  [dim]sentinel a2a recognises LangChain/LangGraph, AutoGen, and CrewAI patterns.[/dim]\n"
        )
        return

    # ── Call graph summary ────────────────────────────────────────────────────
    has_cycles  = graph.has_cycles
    max_depth   = graph.max_depth
    cycle_tag   = "[bold red]⚠ cycle[/bold red]" if has_cycles else "[dim green]acyclic[/dim green]"

    console.print(
        f"\n  [bold white]{len(graph.nodes)}[/bold white] agents  "
        f"[bold white]{len(graph.edges)}[/bold white] edges  "
        f"[bold white]{max_depth}[/bold white] max depth  "
        f"{cycle_tag}"
    )

    # ── Agent nodes table ─────────────────────────────────────────────────────
    console.print()
    node_table = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
    node_table.add_column("Agent",      style="bold white", min_width=20)
    node_table.add_column("Framework",  width=12)
    node_table.add_column("Role",       width=14)
    node_table.add_column("Tools",      style="dim", max_width=30)
    node_table.add_column("",           width=16)

    for node in graph.nodes:
        fw_color  = _FRAMEWORK_COLOR.get(node.framework, "white")
        role_text = _ROLE_TAG.get(node.role, node.role)
        tools_str = ", ".join(node.tools[:3]) + ("…" if len(node.tools) > 3 else "")

        flags = Text()
        if node.has_code_execution:
            flags.append("⚠ code exec", style="bold red")
        if node.spawned_in_loop:
            if flags.plain:
                flags.append("  ")
            flags.append("⟲ in loop", style="bold orange1")

        node_table.add_row(
            node.name,
            Text(node.framework, style=fw_color),
            Text.from_markup(role_text),
            tools_str or "—",
            flags,
        )
    console.print(node_table)

    # ── Call graph edges ──────────────────────────────────────────────────────
    if graph.edges:
        console.print("  [dim]Call graph:[/dim]")
        shown: set[tuple[str, str]] = set()
        for edge in graph.edges:
            key = (edge.caller, edge.callee)
            if key in shown:
                continue
            shown.add(key)
            tags = []
            if edge.passes_user_input:
                tags.append("[bold orange1]passes input[/bold orange1]")
            if not edge.callee_tools_scoped:
                tags.append("[yellow]unscoped tools[/yellow]")
            tag_str = "  " + "  ".join(tags) if tags else ""
            arrow = "──►" if edge.call_type != "group_member" else "◄──►"
            console.print(
                f"    [dim white]{edge.caller}[/dim white] "
                f"[dim]{arrow}[/dim] "
                f"[bold white]{edge.callee}[/bold white]"
                f"  [dim]{edge.call_type}[/dim]{tag_str}"
            )
        console.print()

    # ── Findings ──────────────────────────────────────────────────────────────
    if findings:
        for f in findings:
            color = _SEVERITY_COLOR.get(f.severity, "white")
            console.print(
                f"  [{color}]● {f.severity:<8}[/{color}]  "
                f"[bold white]{f.rule_id}[/bold white]"
                f"  [dim]{f.owasp}[/dim]"
            )
            console.print(f"  [dim]           {f.message}[/dim]")
            if f.detail:
                console.print(f"  [dim]           {f.detail}[/dim]")
            console.print()
    else:
        console.print("  [green]✓ No trust findings[/green]\n")

    # ── Score footer ──────────────────────────────────────────────────────────
    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    console.print(
        f"  Trust Score  [{status_color}]{score:>3}/100[/{status_color}]  "
        f"[dim]{bar}[/dim]  [{status_color}]{status}[/{status_color}]"
    )

    n_critical = sum(1 for f in findings if f.severity == "CRITICAL")
    n_high     = sum(1 for f in findings if f.severity == "HIGH")

    console.print()
    console.rule(style="bright_blue")
    parts = [
        f"[bold white]{len(graph.nodes)}[/bold white] agent{'s' if len(graph.nodes) != 1 else ''}",
        f"[bold white]{len(graph.edges)}[/bold white] edge{'s' if len(graph.edges) != 1 else ''}",
        f"[bold white]{len(findings)}[/bold white] finding{'s' if len(findings) != 1 else ''}",
    ]
    if n_critical:
        parts.append(f"[bold red]{n_critical} CRITICAL[/bold red]")
    if n_high:
        parts.append(f"[bold orange1]{n_high} HIGH[/bold orange1]")
    console.print("  " + " · ".join(parts))
    console.print()


def as_a2a_json(
    graph: A2AGraph,
    findings: list[A2AFinding],
    score: int,
    target: str,
) -> str:
    return json.dumps({
        "target": target,
        "agent_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "has_cycles": graph.has_cycles,
        "max_depth": graph.max_depth,
        "agents": [
            {
                "name": n.name,
                "framework": n.framework,
                "role": n.role,
                "tools": n.tools,
                "has_code_execution": n.has_code_execution,
                "spawned_in_loop": n.spawned_in_loop,
                "file": str(n.file),
                "line": n.line,
            }
            for n in graph.nodes
        ],
        "edges": [
            {
                "caller": e.caller,
                "callee": e.callee,
                "call_type": e.call_type,
                "passes_user_input": e.passes_user_input,
                "callee_tools_scoped": e.callee_tools_scoped,
                "file": str(e.file),
                "line": e.line,
            }
            for e in graph.edges
        ],
        "findings": [
            {
                "severity": f.severity,
                "rule_id": f.rule_id,
                "message": f.message,
                "detail": f.detail,
                "node_name": f.node_name,
                "owasp": f.owasp,
            }
            for f in findings
        ],
        "trust_score": score,
        "status": _status_label(score),
    }, indent=2)

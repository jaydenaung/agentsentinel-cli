"""Rich terminal and JSON output for host AI security posture scans."""

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from agentsentinel_cli.host_rules import HostFinding, host_posture_score
from agentsentinel_cli.host_scanner import HostContext

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
_CATEGORY_LABEL = {
    "config":        "Configuration",
    "data_exposure": "Data Exposure",
    "permissions":   "Permissions",
    "system":        "System Security",
    "network":       "Network Exposure",
}
_CATEGORY_ORDER = ["config", "data_exposure", "permissions", "system", "network"]


def _status_label(score: int) -> str:
    if score >= 80:
        return "TRUSTED"
    if score >= 60:
        return "WATCH"
    if score >= 40:
        return "ALERT"
    return "CRITICAL"


def _bool_tag(val: bool | None, true_label: str, false_label: str) -> str:
    if val is True:
        return f"[green]{true_label}[/green]"
    if val is False:
        return f"[red]{false_label}[/red]"
    return "[dim]unknown[/dim]"


def _print_posture_gaps(gaps: list, snippet: dict | None) -> None:
    """Render the recommended-configuration gap table and suggested settings snippet."""
    console.rule("[dim]Recommended Configuration Gaps[/dim]", style="dim")
    if not gaps:
        console.print("  [green]✓ Current Claude config matches the recommended baseline[/green]\n")
        return

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
    tbl.add_column("Setting", style="bold white", min_width=16)
    tbl.add_column("Current", style="yellow", max_width=30)
    tbl.add_column("Recommended", style="green", max_width=30)
    tbl.add_column("Risk", style="dim", max_width=44)

    for g in gaps:
        tbl.add_row(g.description, g.current, g.recommended, g.risk)
    console.print(tbl)

    for g in gaps:
        console.print(f"  [dim cyan]→ {g.description}: {g.fix}[/dim cyan]")

    if snippet:
        console.print()
        console.print("  [bold white]Suggested ~/.claude/settings.json changes:[/bold white]")
        console.print(json.dumps(snippet, indent=2))
    console.print()


def print_host_result(
    ctx: HostContext,
    findings: list[HostFinding],
    score: int,
    gaps: list | None = None,
    snippet: dict | None = None,
) -> None:
    """Render the full host posture report to the terminal."""
    status = _status_label(score)
    status_color = _STATUS_COLOR[status]

    console.print()
    console.print(Panel.fit(
        "[bold white]AgentSentinel — Host AI Security Posture[/bold white]\n"
        "[dim]AI tools · privacy permissions · system security[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    # ── Discovery summary ─────────────────────────────────────────────────────
    console.print()

    if ctx.claude_code:
        n_allowed = len(ctx.claude_code.allowed_tools)
        n_denied = len(ctx.claude_code.disallowed_tools)
        n_ask = len(ctx.claude_code.ask_tools)
        n_hooks = len(ctx.claude_code.hooks)
        n_mcp = len(ctx.claude_code.mcp_servers)
        sources_str = ", ".join(str(p) for p in ctx.claude_code.sources)
        console.print(
            f"  [bold white]Claude Code[/bold white]  [dim]{sources_str}[/dim]\n"
            f"  [dim]  {n_allowed} allow rule(s)  ·  {n_denied} deny rule(s)  ·  "
            f"{n_ask} ask rule(s)  ·  {n_mcp} MCP server(s)  ·  {n_hooks} hook(s)[/dim]"
        )
        if ctx.claude_code.allowed_tools:
            tools_str = ", ".join(ctx.claude_code.allowed_tools[:8])
            console.print(f"  [dim]  permissions.allow: {tools_str}[/dim]")
        if ctx.claude_code.disallowed_tools:
            deny_str = ", ".join(ctx.claude_code.disallowed_tools[:8])
            console.print(f"  [dim]  permissions.deny: {deny_str}[/dim]")
    else:
        console.print("  [dim]Claude Code settings not found (~/.claude/settings.json)[/dim]")

    console.print()
    if ctx.claude_desktop:
        n_mcp = len(ctx.claude_desktop.mcp_servers)
        console.print(
            f"  [bold white]Claude Desktop[/bold white]  [dim]{ctx.claude_desktop.path}[/dim]\n"
            f"  [dim]  {n_mcp} MCP server(s)[/dim]"
        )
    else:
        console.print("  [dim]Claude Desktop config not found[/dim]")

    if ctx.vendor_configs:
        console.print()
        for vc in ctx.vendor_configs:
            console.print(
                f"  [bold white]{vc.display_name}[/bold white]  [dim]{vc.path}[/dim]\n"
                f"  [dim]  {len(vc.mcp_servers)} MCP server(s)[/dim]"
            )

    # MCP servers table — all sources combined
    all_servers = []
    if ctx.claude_code:
        all_servers.extend((s, "Claude Code") for s in ctx.claude_code.mcp_servers)
    if ctx.claude_desktop:
        all_servers.extend((s, "Desktop") for s in ctx.claude_desktop.mcp_servers)
    for vc in ctx.vendor_configs:
        all_servers.extend((s, vc.display_name) for s in vc.mcp_servers)

    if all_servers:
        console.print()
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
        tbl.add_column("MCP Server", style="bold white", min_width=18)
        tbl.add_column("Source", style="dim", width=12)
        tbl.add_column("Network", width=8)
        tbl.add_column("FS Paths", style="dim", max_width=44)

        for srv, src in all_servers:
            net = Text("yes", style="yellow") if srv.has_network_access else Text("no", style="dim green")
            paths = ", ".join(srv.filesystem_paths[:2]) if srv.filesystem_paths else "—"
            tbl.add_row(srv.name, src, net, paths)
        console.print(tbl)

    # System security status
    console.print(
        f"  [bold white]macOS Security[/bold white]\n"
        f"  [dim]  SIP:         [/dim]{_bool_tag(ctx.sip_enabled,       '✓ Enabled',  '✗ Disabled')}\n"
        f"  [dim]  FileVault:   [/dim]{_bool_tag(ctx.filevault_enabled, '✓ On',       '✗ Off')}\n"
        f"  [dim]  Gatekeeper:  [/dim]{_bool_tag(ctx.gatekeeper_enabled,'✓ Enabled',  '✗ Disabled')}"
    )

    # TCC permissions (granted only)
    granted_tcc = [p for p in ctx.tcc_permissions if p.granted]
    if granted_tcc:
        console.print()
        console.print("  [bold white]App Privacy Permissions (TCC)[/bold white]")
        for p in granted_tcc:
            service_label = p.service.replace("_", " ").title()
            console.print(f"  [dim]  {p.app_name:28}  {service_label}[/dim]")

    # Memory files
    if ctx.memory_file_count > 0:
        mb = ctx.memory_total_bytes / (1024 * 1024)
        console.print(
            f"\n  [dim]Memory (~/.claude/projects/):  "
            f"{ctx.memory_file_count} files, {mb:.1f} MB[/dim]"
        )

    # Shell key findings
    if ctx.shell_key_findings:
        console.print()
        console.print("  [bold yellow]⚠  AI API keys detected in shell config files[/bold yellow]")
        for key_type, file_path, redacted in ctx.shell_key_findings[:4]:
            console.print(f"  [dim]  {key_type} in {file_path}: {redacted}[/dim]")
        if len(ctx.shell_key_findings) > 4:
            console.print(f"  [dim]  … and {len(ctx.shell_key_findings) - 4} more[/dim]")

    # Scan errors / info notes
    if ctx.scan_errors:
        console.print()
        for err in ctx.scan_errors:
            console.print(f"  [dim yellow]ℹ  {err}[/dim yellow]")

    # ── Findings ──────────────────────────────────────────────────────────────
    console.print()
    if findings:
        cats: dict[str, list[HostFinding]] = {}
        for f in findings:
            cats.setdefault(f.category, []).append(f)

        for cat in _CATEGORY_ORDER:
            if cat not in cats:
                continue
            label = _CATEGORY_LABEL.get(cat, cat.title())
            console.rule(f"[dim]{label}[/dim]", style="dim")
            for f in cats[cat]:
                color = _SEVERITY_COLOR.get(f.severity, "white")
                console.print(
                    f"\n  [{color}]● {f.severity:<8}[/{color}]  [bold white]{f.rule_id}[/bold white]"
                )
                console.print(f"  [dim]           {f.message}[/dim]")
                if f.detail:
                    for line in f.detail.split("\n"):
                        console.print(f"  [dim]           {line.strip()}[/dim]")
                if f.remediation:
                    console.print(f"  [dim cyan]           → {f.remediation}[/dim cyan]")
        console.print()
    else:
        console.print("  [green]✓ No security findings[/green]\n")

    # ── Recommended configuration gaps (--baseline) ─────────────────────────────
    if gaps is not None:
        _print_posture_gaps(gaps, snippet)

    # ── Footer ────────────────────────────────────────────────────────────────
    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    console.print(
        f"  Posture Score  [{status_color}]{score:>3}/100[/{status_color}]  "
        f"[dim]{bar}[/dim]  [{status_color}]{status}[/{status_color}]"
    )

    n_critical = sum(1 for f in findings if f.severity == "CRITICAL")
    n_high     = sum(1 for f in findings if f.severity == "HIGH")
    total      = len(findings)

    console.print()
    console.rule(style="bright_blue")
    parts = [f"[bold white]{total}[/bold white] finding{'s' if total != 1 else ''}"]
    if n_critical:
        parts.append(f"[bold red]{n_critical} CRITICAL[/bold red]")
    if n_high:
        parts.append(f"[bold orange1]{n_high} HIGH[/bold orange1]")
    console.print("  " + " · ".join(parts))
    console.print()


def as_host_json(
    ctx: HostContext,
    findings: list[HostFinding],
    score: int,
    gaps: list | None = None,
    snippet: dict | None = None,
) -> str:
    """Serialize host posture results as JSON."""
    all_mcp: list[dict] = []
    if ctx.claude_code:
        for s in ctx.claude_code.mcp_servers:
            all_mcp.append({
                "name": s.name, "source": "claude_code",
                "has_network_access": s.has_network_access,
                "filesystem_paths": s.filesystem_paths,
                "env_keys": s.env_keys,
            })
    if ctx.claude_desktop:
        for s in ctx.claude_desktop.mcp_servers:
            all_mcp.append({
                "name": s.name, "source": "claude_desktop",
                "has_network_access": s.has_network_access,
                "filesystem_paths": s.filesystem_paths,
                "env_keys": s.env_keys,
            })
    for vc in ctx.vendor_configs:
        for s in vc.mcp_servers:
            all_mcp.append({
                "name": s.name, "source": vc.vendor,
                "has_network_access": s.has_network_access,
                "filesystem_paths": s.filesystem_paths,
                "env_keys": s.env_keys,
            })

    return json.dumps({
        "scan_type": "host",
        "claude_code": {
            "found": ctx.claude_code is not None,
            "allowed_tools": ctx.claude_code.allowed_tools if ctx.claude_code else [],
            "disallowed_tools": ctx.claude_code.disallowed_tools if ctx.claude_code else [],
            "ask_tools": ctx.claude_code.ask_tools if ctx.claude_code else [],
            "sources": [str(p) for p in ctx.claude_code.sources] if ctx.claude_code else [],
            "hook_count": len(ctx.claude_code.hooks) if ctx.claude_code else 0,
        },
        "claude_desktop": {
            "found": ctx.claude_desktop is not None,
        },
        "vendor_tools": [
            {"vendor": vc.vendor, "display_name": vc.display_name,
             "mcp_server_count": len(vc.mcp_servers)}
            for vc in ctx.vendor_configs
        ],
        "mcp_servers": all_mcp,
        "memory": {
            "file_count": ctx.memory_file_count,
            "total_bytes": ctx.memory_total_bytes,
        },
        "shell_key_findings": [
            {"key_type": k, "file": f, "redacted": s}
            for k, f, s in ctx.shell_key_findings
        ],
        "tcc_permissions": [
            {"app": p.app_name, "bundle_id": p.bundle_id, "service": p.service, "granted": p.granted}
            for p in ctx.tcc_permissions if p.granted
        ],
        "system_security": {
            "sip_enabled": ctx.sip_enabled,
            "filevault_enabled": ctx.filevault_enabled,
            "gatekeeper_enabled": ctx.gatekeeper_enabled,
        },
        "exposed_processes": [
            {"pid": p.pid, "name": p.name, "address": p.address, "port": p.port}
            for p in ctx.exposed_processes
        ],
        "findings": [
            {
                "severity": f.severity,
                "rule_id": f.rule_id,
                "category": f.category,
                "message": f.message,
                "detail": f.detail,
                "remediation": f.remediation,
            }
            for f in findings
        ],
        "windows_permissions": [
            {"check": s.check, "path": s.path, "risky": s.risky, "detail": s.detail}
            for s in ctx.windows_permissions
        ],
        "posture_score": score,
        "status": _status_label(score),
        "scan_errors": ctx.scan_errors,
        "posture_gaps": [
            {
                "key": g.key,
                "description": g.description,
                "current": g.current,
                "recommended": g.recommended,
                "risk": g.risk,
                "fix": g.fix,
            }
            for g in gaps
        ] if gaps is not None else [],
        "recommended_settings_snippet": snippet if snippet is not None else {},
    }, indent=2)

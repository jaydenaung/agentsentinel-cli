"""Rich terminal and JSON output for Claude Code session-audit scans."""

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from agentsentinel_cli.session_rules import SessionFinding
from agentsentinel_cli.session_scanner import SessionInfo

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
}
_CATEGORY_ORDER = ["permissions", "config", "data_exposure"]


def _status_label(score: int) -> str:
    if score >= 80:
        return "TRUSTED"
    if score >= 60:
        return "WATCH"
    if score >= 40:
        return "ALERT"
    return "CRITICAL"


def print_session_result(sessions: list[SessionInfo], findings: list[SessionFinding], score: int) -> None:
    """Render the full session-audit report to the terminal."""
    status = _status_label(score)
    status_color = _STATUS_COLOR[status]

    console.print()
    console.print(Panel.fit(
        "[bold white]AgentSentinel — Claude Code Session Audit[/bold white]\n"
        "[dim]what actually ran, not just what's configured[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    projects = sorted({s.project_cwd for s in sessions if s.project_cwd})
    console.print()
    console.print(
        f"  [bold white]{len(sessions)}[/bold white] session(s) scanned across "
        f"[bold white]{len(projects)}[/bold white] project(s)"
    )

    if sessions:
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
        tbl.add_column("Session", style="bold white", width=10)
        tbl.add_column("Project", style="dim", max_width=30)
        tbl.add_column("Mode(s)", width=18)
        tbl.add_column("Top tools", style="dim", max_width=28)
        tbl.add_column("Denials", justify="right", width=8)

        for s in sessions:
            top_tools = sorted(s.tool_counts.items(), key=lambda kv: -kv[1])[:3]
            tools_str = ", ".join(f"{name}×{n}" for name, n in top_tools)
            modes_str = ", ".join(sorted(s.permission_modes)) or "—"
            denial_str = str(len(s.denials)) if s.denials else "—"
            project_str = s.project_cwd or "—"
            tbl.add_row(s.session_id[:8], project_str, modes_str, tools_str, denial_str)
        console.print(tbl)

    # Denial detail — the table only shows a count; show what was actually blocked
    denied_sessions = [s for s in sessions if s.denials]
    if denied_sessions:
        console.print()
        console.print("  [bold white]Permission Denials[/bold white]")
        for s in denied_sessions:
            console.print(f"  [dim]  {s.session_id[:8]}:[/dim]")
            for d in s.denials[:5]:
                target = f" [dim]{d.target}[/dim]" if d.target else ""
                console.print(f"  [dim]    ✗ {d.tool}[/dim]{target}")
            if len(s.denials) > 5:
                console.print(f"  [dim]    … and {len(s.denials) - 5} more[/dim]")

    # Parse errors — a security tool should say so when a transcript couldn't be
    # fully read, rather than silently under-reporting findings for that session.
    error_sessions = [s for s in sessions if s.parse_errors > 0]
    if error_sessions:
        console.print()
        total_errors = sum(s.parse_errors for s in error_sessions)
        console.print(
            f"  [dim yellow]ℹ  {len(error_sessions)} session(s) had {total_errors} unparseable "
            f"line(s) — findings for those sessions may be incomplete: "
            f"{', '.join(s.session_id[:8] for s in error_sessions[:5])}[/dim yellow]"
        )

    # Schema warnings — lines/blocks that parsed as valid JSON but didn't match
    # any known transcript shape. Unlike parse_errors, this catches Claude Code
    # format changes that json.loads wouldn't flag on its own.
    warned_sessions = [s for s in sessions if s.schema_warnings > 0]
    if warned_sessions:
        console.print()
        total_warnings = sum(s.schema_warnings for s in warned_sessions)
        console.print(
            f"  [dim yellow]ℹ  {len(warned_sessions)} session(s) had {total_warnings} "
            f"unrecognized transcript entries — the parser may be out of date with "
            f"Claude Code's format; findings could be incomplete: "
            f"{', '.join(s.session_id[:8] for s in warned_sessions[:5])}[/dim yellow]"
        )

    # ── Findings ──────────────────────────────────────────────────────────────
    console.print()
    if findings:
        cats: dict[str, list[SessionFinding]] = {}
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
        console.print("  [green]✓ No session findings[/green]\n")

    # ── Footer ────────────────────────────────────────────────────────────────
    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    console.print(
        f"  Session Score  [{status_color}]{score:>3}/100[/{status_color}]  "
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


def as_session_json(sessions: list[SessionInfo], findings: list[SessionFinding], score: int) -> str:
    """Serialize session-audit results as JSON."""
    return json.dumps({
        "scan_type": "session_audit",
        "sessions": [
            {
                "session_id": s.session_id,
                "project_cwd": s.project_cwd,
                "first_ts": s.first_ts,
                "last_ts": s.last_ts,
                "permission_modes": sorted(s.permission_modes),
                "tool_counts": s.tool_counts,
                "denial_count": len(s.denials),
                "denials": [
                    {"tool": d.tool, "target": d.target, "timestamp": d.timestamp}
                    for d in s.denials
                ],
                "parse_errors": s.parse_errors,
                "schema_warnings": s.schema_warnings,
            }
            for s in sessions
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
        "session_score": score,
        "status": _status_label(score),
    }, indent=2)

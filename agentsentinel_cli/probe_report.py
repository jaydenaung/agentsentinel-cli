"""Rich terminal and JSON output for sentinel probe and sentinel ai-probe."""

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from agentsentinel_cli.probe import StaticProbeReport, ProbeResult
from agentsentinel_cli.ai_probe import AiProbeReport, AiFinding

console = Console()

_SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
}
_OUTCOME_COLOR = {
    "SUCCESS": "bold red",
    "PARTIAL": "bold yellow",
    "FAILED":  "dim green",
    "ERROR":   "dim red",
}
_OUTCOME_ICON = {
    "SUCCESS": "● HIT    ",
    "PARTIAL": "◑ PARTIAL",
    "FAILED":  "○ passed ",
    "ERROR":   "✕ error  ",
}


def _score_color(rate: float) -> str:
    if rate >= 0.3:  return "bold red"
    if rate >= 0.1:  return "bold orange1"
    if rate > 0:     return "bold yellow"
    return "bold green"


# ── Static probe output ───────────────────────────────────────────────────────

def print_probe_result(report: StaticProbeReport) -> None:
    """Render static probe results to the terminal."""
    console.print()
    console.print(Panel.fit(
        f"[bold white]AgentSentinel Probe[/bold white]\n"
        f"[dim]Target: {report.target}[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    # Results table
    console.print()
    table = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
    table.add_column("",         width=11)
    table.add_column("ID",       style="dim", width=8)
    table.add_column("Attack",   style="bold white", min_width=26)
    table.add_column("Category", style="dim", width=12)
    table.add_column("Sev",      width=8)
    table.add_column("Matched",  style="dim", max_width=36)

    for r in report.results:
        outcome_color = _OUTCOME_COLOR[r.outcome]
        sev_color     = _SEVERITY_COLOR.get(r.severity, "white")
        matched_str   = ", ".join(r.matched_patterns[:3]) if r.matched_patterns else (r.error[:30] if r.error else "—")
        table.add_row(
            Text(_OUTCOME_ICON[r.outcome], style=outcome_color),
            r.attack_id,
            r.name,
            r.category,
            Text(r.severity, style=sev_color),
            matched_str,
        )
    console.print(table)

    # Finding details — only hits and partials
    findings = report.findings
    if findings:
        console.print()
        for r in findings:
            color = _OUTCOME_COLOR[r.outcome]
            sev_color = _SEVERITY_COLOR.get(r.severity, "white")
            console.print(
                f"  [{color}]{_OUTCOME_ICON[r.outcome].strip()}[/{color}]  "
                f"[{sev_color}]{r.severity}[/{sev_color}]  "
                f"[bold white]{r.attack_id} — {r.name}[/bold white]"
            )
            if r.matched_patterns:
                console.print(f"  [dim]  Response contained: {', '.join(r.matched_patterns)}[/dim]")
            if r.response:
                snippet = r.response[:120].replace("\n", " ")
                console.print(f"  [dim]  Response snippet: \"{snippet}…\"[/dim]")
            console.print()

    _print_probe_footer(
        target=report.target,
        total=report.total,
        probe_type="static",
        n_success=len(report.successes),
        n_partial=len(report.partials),
        n_error=len(report.errors),
        rate=report.jailbreak_rate,
        duration=report.duration_seconds,
    )


def as_probe_json(report: StaticProbeReport) -> str:
    return json.dumps({
        "probe_type": "static",
        "target": report.target,
        "total_probes": report.total,
        "jailbreak_rate": report.jailbreak_rate,
        "duration_seconds": report.duration_seconds,
        "summary": {
            "success": len(report.successes),
            "partial": len(report.partials),
            "failed": len(report.failures),
            "error": len(report.errors),
        },
        "findings": [
            {
                "attack_id": r.attack_id,
                "name": r.name,
                "category": r.category,
                "severity": r.severity,
                "owasp": r.owasp,
                "outcome": r.outcome,
                "matched_patterns": r.matched_patterns,
                "payload": r.payload,
                "response_snippet": r.response[:300],
            }
            for r in report.findings
        ],
    }, indent=2)


# ── AI probe output ───────────────────────────────────────────────────────────

def print_ai_probe_result(report: AiProbeReport) -> None:
    """Render ai-probe findings to the terminal."""
    console.print()
    console.print(Panel.fit(
        f"[bold white]AgentSentinel AI Probe[/bold white]  [dim](Claude {report.model})[/dim]\n"
        f"[dim]Target: {report.target}[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    if report.probe_log:
        console.print()
        console.print("  [dim]Probe log:[/dim]")
        for entry in report.probe_log:
            console.print(
                f"  [dim][{entry.probe_num:>2}][/dim] "
                f"[dim cyan]{entry.category:<12}[/dim cyan] "
                f"[dim]{entry.rationale[:60]}[/dim]"
            )
        console.print()

    if report.findings:
        for f in report.findings:
            sev_color = _SEVERITY_COLOR.get(f.severity, "white")
            console.print(
                f"  [{sev_color}]● {f.severity:<8}[/{sev_color}]  "
                f"[bold white]{f.rule_id}[/bold white]"
                + (f"  [dim]{f.owasp_category}[/dim]" if f.owasp_category else "")
            )
            console.print(f"  [dim]           {f.message}[/dim]")
            if f.evidence:
                lines = f.evidence.splitlines()
                for line in lines[:4]:
                    console.print(f"  [dim]           {line[:100]}[/dim]")
                if len(lines) > 4:
                    console.print(f"  [dim]           … ({len(lines)-4} more lines)[/dim]")
            console.print()
    else:
        console.print("  [green]✓ No findings recorded by the probe agent.[/green]\n")

    _print_probe_footer(
        target=report.target,
        total=report.probe_count,
        probe_type=f"ai ({report.model})",
        n_success=len([f for f in report.findings if f.severity in ("CRITICAL", "HIGH")]),
        n_partial=len([f for f in report.findings if f.severity in ("MEDIUM", "LOW")]),
        n_error=0,
        rate=report.jailbreak_rate,
        duration=report.duration_seconds,
    )


def as_ai_probe_json(report: AiProbeReport) -> str:
    return json.dumps({
        "probe_type": "ai",
        "model": report.model,
        "target": report.target,
        "total_probes": report.probe_count,
        "finding_rate": report.jailbreak_rate,
        "duration_seconds": report.duration_seconds,
        "findings": [
            {
                "severity": f.severity,
                "rule_id": f.rule_id,
                "message": f.message,
                "owasp_category": f.owasp_category,
                "evidence": f.evidence,
            }
            for f in report.findings
        ],
        "probe_log": [
            {
                "probe_num": e.probe_num,
                "category": e.category,
                "rationale": e.rationale,
                "message": e.message,
                "response_snippet": e.response[:300],
            }
            for e in report.probe_log
        ],
    }, indent=2)


# ── Shared footer ─────────────────────────────────────────────────────────────

def _print_probe_footer(
    target: str,
    total: int,
    probe_type: str,
    n_success: int,
    n_partial: int,
    n_error: int,
    rate: float,
    duration: float,
) -> None:
    rate_color = _score_color(rate)
    pct = int(rate * 100)

    console.rule(style="bright_blue")
    parts = [
        f"[bold white]{total}[/bold white] probes",
        f"[{rate_color}]{pct}% hit rate[/{rate_color}]",
        f"[dim]{probe_type}[/dim]",
        f"[dim]{duration}s[/dim]",
    ]
    if n_success:
        parts.insert(1, f"[bold red]{n_success} confirmed[/bold red]")
    if n_partial:
        parts.insert(2, f"[bold yellow]{n_partial} partial[/bold yellow]")
    if n_error:
        parts.append(f"[dim red]{n_error} errors[/dim red]")
    console.print("  " + " · ".join(parts))
    console.print()

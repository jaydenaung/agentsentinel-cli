"""Rich terminal and JSON output for sentinel secrets."""

import json

from rich.console import Console
from rich.panel import Panel

from agentsentinel_cli.secrets import SecretsReport
from agentsentinel_cli.secrets_rules import SecretFinding

console = Console()

_SEV_COLOR: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "dim cyan",
}

_CAT_HEADER: dict[str, str] = {
    "credential":           "CREDENTIALS",
    "pii":                  "PII",
    "memory_contamination": "MEMORY CONTAMINATION",
}

_JURISDICTION_TAG: dict[str, str] = {
    "SGP":    " [dim](SGP — PDPA)[/dim]",
    "USA":    " [dim](USA)[/dim]",
    "global": "",
}

_SEVERITY_RANK: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def print_secrets_result(report: SecretsReport, min_severity: str = "MEDIUM") -> None:
    """Render a secrets scan report to the terminal."""
    threshold = _SEVERITY_RANK.get(min_severity, 3)
    visible = [f for f in report.findings if _SEVERITY_RANK.get(f.severity, 4) <= threshold]

    console.print()
    console.print(Panel.fit(
        f"[bold white]AgentSentinel Secrets[/bold white]\n"
        f"[dim]Target: {report.target}[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))
    console.print()

    if not visible:
        console.print(f"  [bold green]✓ No findings at {min_severity} or above.[/bold green]\n")
    else:
        for cat in ("credential", "pii", "memory_contamination"):
            group = [f for f in visible if f.category == cat]
            if not group:
                continue
            console.rule(f"[dim]{_CAT_HEADER[cat]}[/dim]", style="dim")
            console.print()
            for f in group:
                _print_finding(f)
            console.print()

    if report.gitignore_warnings:
        console.rule("[dim yellow]WARNINGS[/dim yellow]", style="dim yellow")
        console.print()
        for w in report.gitignore_warnings:
            console.print(f"  [bold yellow]⚠[/bold yellow]  {w}")
        console.print()

    _print_summary(report)


def _print_finding(f: SecretFinding) -> None:
    """Render a single finding block."""
    color = _SEV_COLOR.get(f.severity, "white")
    jtag = _JURISDICTION_TAG.get(f.jurisdiction, "")
    val_mark = " [dim green]✓validated[/dim green]" if f.validated else ""
    location = str(f.file) if f.line == 0 else f"{f.file}:{f.line}"

    console.print(
        f"  [{color}]● {f.severity:<8}[/{color}]  "
        f"[bold white]{f.rule_id}[/bold white]{jtag}{val_mark}"
        f"  [dim]{location}[/dim]"
    )
    if f.match_preview:
        console.print(f"  [dim]{'':11}{f.match_preview}[/dim]")
    if f.context_line and f.context_line != f.match_preview:
        console.print(f"  [dim]{'':11}{f.context_line}[/dim]")
    console.print(f"  [dim]{'':11}→ {f.recommendation}[/dim]")


def _print_summary(report: SecretsReport) -> None:
    """Render the summary bar."""
    c  = sum(1 for f in report.findings if f.severity == "CRITICAL")
    h  = sum(1 for f in report.findings if f.severity == "HIGH")
    m  = sum(1 for f in report.findings if f.severity == "MEDIUM")
    lo = sum(1 for f in report.findings if f.severity == "LOW")

    console.rule(style="bright_blue")
    console.print(
        f"  {report.files_scanned} files scanned "
        f"[dim]({report.memory_files_scanned} memory · {report.config_files_scanned} config)[/dim]"
        f"  ·  "
        f"[bold red]CRITICAL:{c}[/bold red]  "
        f"[bold orange1]HIGH:{h}[/bold orange1]  "
        f"[bold yellow]MEDIUM:{m}[/bold yellow]  "
        f"[dim cyan]LOW:{lo}[/dim cyan]"
        f"  ·  [dim]{report.duration_seconds}s[/dim]"
    )
    console.print()


def as_secrets_json(report: SecretsReport) -> str:
    """Serialise a SecretsReport to a JSON string."""
    c  = sum(1 for f in report.findings if f.severity == "CRITICAL")
    h  = sum(1 for f in report.findings if f.severity == "HIGH")
    m  = sum(1 for f in report.findings if f.severity == "MEDIUM")
    lo = sum(1 for f in report.findings if f.severity == "LOW")

    return json.dumps({
        "target":               str(report.target),
        "files_scanned":        report.files_scanned,
        "memory_files_scanned": report.memory_files_scanned,
        "config_files_scanned": report.config_files_scanned,
        "summary": {
            "critical": c, "high": h, "medium": m, "low": lo,
            "total": c + h + m + lo,
        },
        "findings": [
            {
                "rule_id":        f.rule_id,
                "severity":       f.severity,
                "category":       f.category,
                "jurisdiction":   f.jurisdiction,
                "file":           str(f.file),
                "line":           f.line,
                "match_preview":  f.match_preview,
                "validated":      f.validated,
                "recommendation": f.recommendation,
            }
            for f in report.findings
        ],
        "gitignore_warnings": report.gitignore_warnings,
        "duration_seconds":   report.duration_seconds,
    }, indent=2)

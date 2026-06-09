"""Output formatting for red-team results — Rich terminal + JSON."""

from __future__ import annotations

import json
from datetime import datetime

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from agentsentinel_cli.redteam.models import RedTeamFinding, RedTeamResult

console = Console()

_SEV_COLOR: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "dim white",
}
_SEV_ICON: dict[str, str] = {
    "CRITICAL": "●",
    "HIGH":     "●",
    "MEDIUM":   "●",
    "LOW":      "●",
    "INFO":     "○",
}
_ATTACK_LABEL: dict[str, str] = {
    "traverse": "PATH TRAVERSAL",
    "ssrf":     "SSRF",
    "cmd":      "CMD INJECTION",
    "sqli":     "SQL INJECTION",
    "llm":      "LLM INJECTION",
    "auth":     "AUTH BYPASS",
    "poison":   "TOOL POISONING",
    "fuzz":     "FUZZING",
    "recon":    "RECON",
}


def print_redteam_result(result: RedTeamResult, verbose: bool = False) -> None:
    console.print()
    _print_header(result)
    _print_findings(result.findings, verbose)
    _print_attack_chains(result.findings)
    _print_summary(result)


def _print_header(result: RedTeamResult) -> None:
    modules = ", ".join(result.modules_run)
    console.print(Panel.fit(
        f"[bold white]AgentSentinel Red Team — MCP[/bold white]\n"
        f"[dim]Target:[/dim]  [white]{result.target}[/white]\n"
        f"[dim]Server:[/dim]  [white]{result.server_name} v{result.server_version}[/white]  "
        f"[dim]·  Transport:[/dim] [white]{result.transport.upper()}[/white]\n"
        f"[dim]Modules:[/dim] [white]{modules}[/white]  "
        f"[dim]·  Tools:[/dim] [white]{result.tool_count}[/white]  "
        f"[dim]·  Attacks fired:[/dim] [white]{result.attack_count}[/white]  "
        f"[dim]·  Duration:[/dim] [white]{result.duration_s:.1f}s[/white]",
        border_style="red",
        padding=(0, 2),
    ))


def _print_findings(findings: list[RedTeamFinding], verbose: bool) -> None:
    # Group: actionable first, INFO last
    non_info = [f for f in findings if f.severity != "INFO"]
    info = [f for f in findings if f.severity == "INFO"]

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    non_info.sort(key=lambda f: order.get(f.severity, 9))

    if non_info:
        console.print()
        console.rule("[bold red]FINDINGS[/bold red]", style="red")

    for f in non_info:
        _print_finding(f, verbose)

    if info:
        console.print()
        console.rule("[dim]RECON / INFO[/dim]", style="dim")
        for f in info:
            _print_finding(f, verbose=False)

    if not findings:
        console.print("\n  [green]No findings — server resisted all probes.[/green]")


def _print_finding(f: RedTeamFinding, verbose: bool) -> None:
    sev_color = _SEV_COLOR.get(f.severity, "white")
    icon = _SEV_ICON.get(f.severity, "●")
    attack_label = _ATTACK_LABEL.get(f.attack_type, f.attack_type.upper())

    header = (
        f"[{sev_color}]{icon} {f.severity}[/{sev_color}]  "
        f"[bold white][{attack_label}][/bold white]  "
        f"[dim]{f.title}[/dim]"
    )
    console.print(f"\n{header}")

    if f.evidence:
        console.print(f"  [dim]Evidence:[/dim]  [italic]{f.evidence[:180]}[/italic]")

    if f.payload and f.severity not in ("INFO",):
        payload_display = f.payload[:80] + "…" if len(f.payload) > 80 else f.payload
        console.print(f"  [dim]Payload:  [/dim]  [dim red]{payload_display}[/dim red]")

    console.print(f"  [dim]Scenario: [/dim]  {f.exploit_scenario}")

    if f.remediation and f.severity not in ("INFO",):
        console.print(f"  [dim]Fix:      [/dim]  [green]{f.remediation}[/green]")

    refs: list[str] = []
    if f.mitre_id:
        refs.append(f"MITRE: {f.mitre_id}")
    if f.owasp_id:
        refs.append(f"OWASP: {f.owasp_id}")
    if f.confidence != "HIGH":
        refs.append(f"Confidence: {f.confidence}")
    if refs:
        console.print(f"  [dim]{'  ·  '.join(refs)}[/dim]")

    if verbose and f.request_body:
        console.print(f"  [dim]Request:  [/dim]  [dim]{json.dumps(f.request_body)[:200]}[/dim]")
    if verbose and f.response_body:
        console.print(f"  [dim]Response: [/dim]  [dim]{f.response_body[:200]}[/dim]")


def _print_attack_chains(findings: list[RedTeamFinding]) -> None:
    """
    Synthesize multi-step attack chains from confirmed findings.
    Only emits when two or more findings chain into a meaningful escalation path.
    """
    chains: list[tuple[str, str]] = []

    attack_types = {f.attack_type for f in findings}
    severities = {f.severity for f in findings}
    confirmed_critical = {f.attack_type for f in findings if f.severity == "CRITICAL"}

    # Detect tool names from recon findings
    all_tool_names: set[str] = set()
    for f in findings:
        if f.attack_type == "recon" and f.severity == "HIGH":
            # Evidence line contains "tool_name (params)" entries
            for part in f.evidence.split("\n"):
                name = part.split("(")[0].strip()
                if name:
                    all_tool_names.add(name)
        all_tool_names.add(f.tool_name)

    has_shell = any(
        "shell" in n or "exec" in n or "cmd" in n or "run" in n
        for n in all_tool_names
    )
    has_write = any(
        "write" in n or "append" in n or "create" in n or "delete" in n or "upload" in n
        for n in all_tool_names
    )
    has_traverse = "traverse" in confirmed_critical
    has_auth_bypass = any(
        f.attack_type == "auth" and f.severity in ("CRITICAL", "HIGH")
        for f in findings
    )

    if has_traverse and has_shell:
        chains.append((
            "CRITICAL",
            "Read + Execute — Full host compromise path\n"
            "    Step 1: path traversal on read_file → read ~/.ssh/id_rsa, .env, API keys\n"
            "    Step 2: prompt inject agent → invoke execute_shell with attacker payload\n"
            "    Impact: credential theft + arbitrary code execution on the host",
        ))
    elif has_traverse and has_write:
        chains.append((
            "CRITICAL",
            "Read + Write — Data exfiltration and persistence\n"
            "    Step 1: path traversal → read sensitive files (keys, configs, DB creds)\n"
            "    Step 2: write tools → drop backdoor file or overwrite config\n"
            "    Impact: persistent access and data exfiltration",
        ))
    elif has_traverse:
        chains.append((
            "HIGH",
            "Read-only traversal — Reconnaissance and credential theft\n"
            "    Step 1: path traversal → read /etc/passwd, ~/.ssh/id_rsa, .env files\n"
            "    Impact: credential theft enabling lateral movement",
        ))

    if has_auth_bypass and (has_shell or has_write or has_traverse):
        chains.append((
            "CRITICAL",
            "Unauthenticated access + dangerous tools — Zero-credential exploitation\n"
            "    Auth bypass confirmed → all dangerous tools callable without credentials\n"
            "    Impact: any tool capability exploitable by an unauthenticated attacker",
        ))

    if not chains:
        return

    console.print()
    console.rule("[bold red]ATTACK CHAINS[/bold red]", style="red")
    console.print()
    for sev, chain_text in chains:
        color = "bold red" if sev == "CRITICAL" else "bold orange1"
        lines = chain_text.split("\n")
        console.print(f"  [{color}]▶ {sev}[/{color}]  {lines[0]}")
        for line in lines[1:]:
            console.print(f"  [dim]{line}[/dim]")
        console.print()


def _print_summary(result: RedTeamResult) -> None:
    console.print()
    console.rule("[bold white]ATTACK SUMMARY[/bold white]", style="bright_blue")
    console.print()

    # Severity breakdown
    counts = {
        "CRITICAL": result.critical_count,
        "HIGH":     result.high_count,
        "MEDIUM":   result.medium_count,
        "LOW":      result.low_count,
        "INFO":     result.info_count,
    }
    parts: list[str] = []
    for sev, count in counts.items():
        color = _SEV_COLOR.get(sev, "white")
        parts.append(f"[{color}]{sev}[/{color}]  {count}")

    console.print("  " + "   ".join(parts))
    console.print()

    total_actionable = result.critical_count + result.high_count + result.medium_count
    if result.critical_count > 0:
        risk_label = "[bold red]CRITICAL RISK[/bold red]"
    elif result.high_count > 0:
        risk_label = "[bold orange1]HIGH RISK[/bold orange1]"
    elif total_actionable > 0:
        risk_label = "[bold yellow]MEDIUM RISK[/bold yellow]"
    else:
        risk_label = "[bold green]LOW RISK[/bold green]"

    console.print(f"  Risk posture:  {risk_label}")
    console.print(
        f"  [dim]Tools tested: {result.tool_count}   "
        f"Payloads fired: {result.attack_count}   "
        f"Duration: {result.duration_s:.1f}s[/dim]"
    )
    console.print()


# ── JSON output ───────────────────────────────────────────────────────────────

def as_redteam_json(result: RedTeamResult) -> str:
    def _finding_dict(f: RedTeamFinding) -> dict:
        d = {
            "attack_type":      f.attack_type,
            "severity":         f.severity,
            "title":            f.title,
            "tool_name":        f.tool_name,
            "parameter":        f.parameter,
            "payload":          f.payload,
            "evidence":         f.evidence,
            "exploit_scenario": f.exploit_scenario,
            "remediation":      f.remediation,
            "mitre_id":         f.mitre_id,
            "owasp_id":         f.owasp_id,
            "confidence":       f.confidence,
        }
        if f.request_body:
            d["request_body"] = f.request_body
        if f.response_body:
            d["response_body"] = f.response_body
        return d

    return json.dumps({
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target":        result.target,
        "server_name":   result.server_name,
        "server_version": result.server_version,
        "transport":     result.transport,
        "modules_run":   result.modules_run,
        "stats": {
            "tool_count":   result.tool_count,
            "attack_count": result.attack_count,
            "duration_s":   round(result.duration_s, 2),
            "critical":     result.critical_count,
            "high":         result.high_count,
            "medium":       result.medium_count,
            "low":          result.low_count,
            "info":         result.info_count,
        },
        "findings": [_finding_dict(f) for f in result.findings],
    }, indent=2)

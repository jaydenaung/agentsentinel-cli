"""AgentSentinel CLI — one-command security scanner and discovery tool for AI agents."""

import sys
from pathlib import Path

import click

from agentsentinel_cli.scanner import scan_path
from agentsentinel_cli.rules import run_rules, posture_score
from rich.panel import Panel
from agentsentinel_cli.report import print_scan_result, as_json, console


@click.group()
@click.version_option(package_name="agentsentinel-cli")
def main() -> None:
    """AgentSentinel — AI agent security scanner and discovery tool.

    \b
    Commands:
      discover   Find AI agents running in your environment
      scan       Deep-scan an agent file, process, or URL for security issues
    """


# ── sentinel scan ─────────────────────────────────────────────────────────────

@main.command()
@click.argument("target", default=".", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              default=None, help="Exit with code 1 if findings at or above this severity exist.")
@click.option("--ignore-rule", "ignore_rules", multiple=True, metavar="RULE_ID",
              help="Suppress a finding by rule ID. Repeatable. Also reads .sentinelignore.")
def scan(
    target: Path,
    fmt: str,
    fail_on: str | None,
    ignore_rules: tuple[str, ...],
) -> None:
    """Scan a Python file or directory for AI agent security issues.

    TARGET can be a single .py file or a directory (scanned recursively).

    \b
    Examples:
        sentinel scan my_agent.py
        sentinel scan ./agents/
        sentinel scan my_agent.py --fail-on CRITICAL
        sentinel scan my_agent.py --format json
    """
    from agentsentinel_cli import suppress as _suppress

    agents = scan_path(target)

    findings_map = {a.file: run_rules(a) for a in agents}
    scores_map = {a.file: posture_score(findings_map[a.file]) for a in agents}

    sup_rules = _suppress.merge(_suppress.load_ignore_file(target), ignore_rules)
    all_suppressed: list = []
    if sup_rules:
        cleaned: dict = {}
        for file, file_findings in findings_map.items():
            active, suppressed = _suppress.apply(file_findings, sup_rules)
            cleaned[file] = active
            all_suppressed.extend(suppressed)
        findings_map = cleaned
        scores_map = {a.file: posture_score(findings_map[a.file]) for a in agents}

    if fmt == "json":
        click.echo(as_json(agents, findings_map, scores_map))
    else:
        print_scan_result(agents, findings_map, scores_map, target)
        msg = _suppress.notice(all_suppressed)
        if msg:
            console.print(f"  {msg}\n")

    if fail_on:
        _severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = _severity_rank.get(fail_on, 0)
        breach = any(
            _severity_rank.get(f.severity, 0) >= threshold
            for fl in findings_map.values()
            for f in fl
        )
        if breach:
            sys.exit(1)


# ── sentinel discover helpers ────────────────────────────────────────────────

def _deep_scan_agents(agents: list, extra_headers: dict | None) -> None:
    """Run mcp scan rules on every confirmed network MCP server from a discover run."""
    from agentsentinel_cli.discover import DiscoveredAgent
    from agentsentinel_cli.mcp_client import scan_http, McpAuthRequired, McpError
    from agentsentinel_cli.mcp_rules import McpContext, run_mcp_rules, mcp_posture_score
    from agentsentinel_cli.mcp_report import print_mcp_result
    from agentsentinel_cli import suppress as _suppress

    network_agents = [a for a in agents if a.source == "network"]
    if not network_agents:
        return

    console.print()
    console.rule("[bold bright_blue]DEEP SCAN[/bold bright_blue]", style="bright_blue")

    sup_rules = _suppress.load_ignore_file(Path.cwd())

    for agent in network_agents:
        base = f"http://{agent.location}"
        scan_url = f"{base}/sse" if agent.transport == "sse" else base

        # Auth-required servers need credentials — skip silently if none provided
        if not agent.tools and not extra_headers:
            console.print(
                f"\n  [dim]Skipping {agent.location} — auth required, "
                f"use --auth-header to deep scan[/dim]"
            )
            continue

        try:
            server = scan_http(scan_url, extra_headers=extra_headers, timeout=15)
        except McpAuthRequired:
            console.print(
                f"\n  [dim]Skipping {agent.location} — credentials rejected[/dim]"
            )
            continue
        except (McpError, Exception):
            console.print(
                f"\n  [dim]Skipping {agent.location} — could not reconnect[/dim]"
            )
            continue

        # auth_required: True when the server actually enforces auth (risk LOW/MEDIUM)
        auth_required = agent.risk in ("LOW", "MEDIUM")
        ctx = McpContext(server=server, auth_required=auth_required)
        findings = run_mcp_rules(ctx)
        findings, _ = _suppress.apply(findings, sup_rules)
        score = mcp_posture_score(findings)

        print_mcp_result(ctx, findings, score, scan_url)


# ── sentinel discover ─────────────────────────────────────────────────────────

@main.command()
@click.option("--process/--no-process", default=True, show_default=True,
              help="Scan running processes for MCP servers and agent signals.")
@click.option("--network/--no-network", default=True, show_default=True,
              help="Probe local ports — confirmed via MCP protocol handshake.")
@click.option("--docker/--no-docker", default=False, show_default=True,
              help="Inspect running Docker containers for MCP/agent patterns.")
@click.option("--host", default=None, metavar="IP",
              help="Scan a single host, e.g. 10.0.1.45.")
@click.option("--subnet", default=None, metavar="CIDR",
              help="Scan a CIDR subnet for MCP servers, e.g. 10.0.0.0/24.")
@click.option("--ports", default=None, metavar="RANGE",
              help="Custom port range, e.g. 8000-9001. Defaults to common MCP/agent ports.")
@click.option("--auth-header", "auth_header", default=None, metavar="HEADER",
              help="HTTP auth header for MCP handshakes, e.g. 'Authorization: Bearer token'.")
@click.option("--scan", "do_scan", is_flag=True, default=False,
              help="Deep-scan every confirmed MCP server with sentinel mcp scan rules.")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Show full details per discovered server.")
def discover(
    process: bool,
    network: bool,
    docker: bool,
    host: str | None,
    subnet: str | None,
    ports: str | None,
    auth_header: str | None,
    do_scan: bool,
    fmt: str,
    verbose: bool,
) -> None:
    """Find MCP servers and AI agent processes in your environment.

    Confirms MCP servers via protocol handshake — not just open ports.
    Add --scan to deep-audit every confirmed server in the same run.

    \b
    Examples:
        sentinel discover                              local processes + ports
        sentinel discover --host 10.0.1.45            single remote host
        sentinel discover --host 10.0.1.45 --scan     discover + deep audit
        sentinel discover --subnet 10.0.0.0/24        full subnet scan
        sentinel discover --subnet 10.0.0.0/24 \\
          --auth-header 'Authorization: Bearer token'  scan with credentials
        sentinel discover --no-process                 network only
        sentinel discover --docker                     include containers
        sentinel discover --ports 8000-9001            custom port range
        sentinel discover --format json                machine-readable output
    """
    from agentsentinel_cli.discover import run_discovery, scan_network, as_json as discover_json
    from agentsentinel_cli.discover_report import print_discover_result, print_subnet_progress

    # Parse port range
    port_list = _parse_ports(ports) if ports else None

    # Parse auth header
    extra_headers: dict[str, str] = {}
    if auth_header:
        if ":" not in auth_header:
            console.print("[red]Error:[/red] --auth-header must be 'Header-Name: value' format.")
            sys.exit(1)
        key, _, val = auth_header.partition(":")
        extra_headers[key.strip()] = val.strip()

    # --host: single-host scan — bypass run_discovery and call scan_network directly
    if host:
        if fmt == "text":
            _warn_missing_deps(False, True)
        agents = scan_network(
            host=host,
            ports=port_list,
            extra_headers=extra_headers or None,
        )
        if fmt == "json":
            click.echo(discover_json(agents))
            return
        print_discover_result(agents, vectors=[f"host ({host})"], verbose=verbose)
        if do_scan:
            _deep_scan_agents(agents, extra_headers or None)
        if any(a.risk == "CRITICAL" for a in agents):
            sys.exit(1)
        return

    # Collect active scan vectors for the header
    vectors = []
    if process:
        vectors.append("processes")
    if network:
        vectors.append("network")
    if subnet:
        vectors.append(f"subnet ({subnet})")
    if docker:
        vectors.append("docker")

    if not vectors:
        console.print("[yellow]No scan vectors selected — use at least one of: "
                      "--process, --network, --host, --subnet, --docker[/yellow]")
        sys.exit(1)

    if fmt == "text":
        _warn_missing_deps(process, network)

    # Progress callback for subnet scan — only in text mode
    progress_cb = print_subnet_progress if (subnet and fmt == "text") else None

    agents, subnet_stats = run_discovery(
        do_process=process,
        do_network=network,
        do_docker=docker,
        ports=port_list,
        subnet=subnet,
        extra_headers=extra_headers or None,
        subnet_progress_cb=progress_cb,
    )

    if fmt == "json":
        click.echo(discover_json(agents))
        return

    print_discover_result(agents, vectors=vectors, verbose=verbose, subnet_stats=subnet_stats)

    if do_scan:
        _deep_scan_agents(agents, extra_headers or None)

    # Exit 1 if any CRITICAL agents found (useful for CI)
    if any(a.risk == "CRITICAL" for a in agents):
        sys.exit(1)


# ── sentinel mcp ──────────────────────────────────────────────────────────────

@main.group(name="mcp")
def mcp_group() -> None:
    """MCP server security commands.

    \b
    Commands:
      scan   Enumerate an MCP server's tools and audit for security issues
    """


@mcp_group.command("scan")
@click.argument("target", default=None, required=False, metavar="URL")
@click.option("--stdio", "stdio_cmd", default=None, metavar="CMD",
              help="Audit a stdio-transport server. Provide the launch command, e.g. 'python server.py'.")
@click.option("--auth-header", "auth_header", default=None, metavar="HEADER",
              help="HTTP header to include, e.g. 'Authorization: Bearer token123'.")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--timeout", default=10.0, show_default=True, metavar="SECONDS",
              help="Connection timeout in seconds.")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default=None,
              help="Exit with code 1 if findings at or above this severity exist.")
@click.option("--ignore-rule", "ignore_rules", multiple=True, metavar="RULE_ID",
              help="Suppress a finding by rule ID. Repeatable. Also reads .sentinelignore.")
def mcp_scan(
    target: str | None,
    stdio_cmd: str | None,
    auth_header: str | None,
    fmt: str,
    timeout: float,
    fail_on: str | None,
    ignore_rules: tuple[str, ...],
) -> None:
    """Enumerate an MCP server's tools and audit for security issues.

    Connects to the server, lists all exposed tools, and checks for
    authentication gaps, exfiltration paths, code execution exposure,
    and input validation weaknesses.

    \b
    Examples:
        sentinel mcp scan http://localhost:3000
        sentinel mcp scan http://localhost:3000 --auth-header "Authorization: Bearer token"
        sentinel mcp scan --stdio "python my_mcp_server.py"
        sentinel mcp scan http://localhost:3000 --format json
        sentinel mcp scan http://localhost:3000 --fail-on CRITICAL
    """
    from agentsentinel_cli.mcp_client import scan_http, scan_stdio, McpError, McpAuthRequired
    from agentsentinel_cli.mcp_rules import McpContext, run_mcp_rules, mcp_posture_score
    from agentsentinel_cli.mcp_report import print_mcp_result, as_mcp_json

    if not target and not stdio_cmd:
        console.print("[red]Error:[/red] provide a URL target or --stdio CMD.")
        console.print("  Example: [dim]sentinel mcp scan http://localhost:3000[/dim]")
        console.print("  Example: [dim]sentinel mcp scan --stdio 'python server.py'[/dim]")
        sys.exit(1)
    if target and stdio_cmd:
        console.print("[red]Error:[/red] --stdio and a URL target are mutually exclusive.")
        sys.exit(1)

    display_target = stdio_cmd if stdio_cmd else target

    extra_headers: dict[str, str] = {}
    if auth_header:
        if ":" not in auth_header:
            console.print("[red]Error:[/red] --auth-header must be in 'Header-Name: value' format.")
            sys.exit(1)
        key, _, val = auth_header.partition(":")
        extra_headers[key.strip()] = val.strip()

    auth_required = bool(auth_header)

    try:
        if stdio_cmd:
            server = scan_stdio(stdio_cmd, timeout=timeout)
            auth_required = False  # stdio has no network auth concept
        else:
            server = scan_http(target, extra_headers=extra_headers or None, timeout=timeout)
    except McpAuthRequired as exc:
        console.print(f"\n[bold yellow]Authentication required[/bold yellow] (HTTP {exc.status_code})")
        console.print(
            "  Provide credentials with: "
            "[bold]--auth-header 'Authorization: Bearer <token>'[/bold]"
        )
        sys.exit(1)
    except McpError as exc:
        console.print(f"\n[red]MCP connection failed:[/red] {exc}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[red]Unexpected error:[/red] {exc}")
        sys.exit(1)

    from agentsentinel_cli import suppress as _suppress

    ctx = McpContext(server=server, auth_required=auth_required)
    findings = run_mcp_rules(ctx)

    sup_rules = _suppress.merge(_suppress.load_ignore_file(Path.cwd()), ignore_rules)
    findings, suppressed = _suppress.apply(findings, sup_rules)
    score = mcp_posture_score(findings)

    if fmt == "json":
        click.echo(as_mcp_json(ctx, findings, score, display_target))
    else:
        print_mcp_result(ctx, findings, score, display_target)
        msg = _suppress.notice(suppressed)
        if msg:
            console.print(f"  {msg}\n")

    if fail_on:
        _severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = _severity_rank.get(fail_on, 0)
        if any(_severity_rank.get(f.severity, 0) >= threshold for f in findings):
            sys.exit(1)


# ── sentinel inspect ──────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--no-ai", "skip_ai", is_flag=True, default=False,
              help="Skip Claude AI summary even if ANTHROPIC_API_KEY is set.")
@click.option("--model", default="claude-haiku-4-5-20251001", show_default=True,
              help="Claude model used for AI summary generation.")
@click.option("--auth-header", "auth_header", default=None, metavar="HEADER",
              help="HTTP auth header for live endpoint inspection, e.g. 'Authorization: Bearer token'.")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              default=None, help="Exit with code 1 if findings at or above this severity exist.")
@click.option("--ignore-rule", "ignore_rules", multiple=True, metavar="RULE_ID",
              help="Suppress a finding by rule ID. Repeatable. Also reads .sentinelignore.")
def inspect(
    target: str,
    fmt: str,
    skip_ai: bool,
    model: str,
    auth_header: str | None,
    fail_on: str | None,
    ignore_rules: tuple[str, ...],
) -> None:
    """Generate an intelligence report for an AI agent.

    TARGET can be a Python file, a directory, or a live HTTP endpoint URL.
    Shows framework, model, deployment, capabilities, data flows, and trust score.
    With ANTHROPIC_API_KEY set, adds a plain English summary of what the agent does.

    \b
    Examples:
        sentinel inspect my_agent.py
        sentinel inspect ./agents/
        sentinel inspect http://localhost:3000
        sentinel inspect my_agent.py --format json
        sentinel inspect my_agent.py --no-ai
    """
    import os
    from agentsentinel_cli.inspect import inspect_file, inspect_live
    from agentsentinel_cli.inspect_report import print_inspect_result, as_inspect_json
    from agentsentinel_cli import suppress as _suppress

    api_key = "" if skip_ai else os.environ.get("ANTHROPIC_API_KEY", "")

    if target.startswith("http://") or target.startswith("https://"):
        extra_headers: dict[str, str] = {}
        if auth_header:
            if ":" not in auth_header:
                console.print("[red]Error:[/red] --auth-header must be 'Header-Name: value' format.")
                sys.exit(1)
            k, _, v = auth_header.partition(":")
            extra_headers[k.strip()] = v.strip()

        report = inspect_live(
            target,
            extra_headers=extra_headers or None,
            api_key=api_key,
            summary_model=model,
        )
    else:
        path = Path(target)
        if not path.exists():
            console.print(f"[red]Error:[/red] path does not exist: {target}")
            sys.exit(1)

        if path.is_dir():
            # Inspect all agent files in directory, report each
            from agentsentinel_cli.inspect import inspect_file as _inspect
            from agentsentinel_cli.scanner import scan_path as _scan
            agents = _scan(path)
            if not agents:
                console.print(f"[yellow]No agent files detected in:[/yellow] {target}")
                sys.exit(0)
            sup_rules = _suppress.merge(_suppress.load_ignore_file(path), ignore_rules)
            reports = []
            all_suppressed: list = []
            for agent in agents:
                r = _inspect(agent.file, api_key=api_key, summary_model=model)
                if r:
                    r.findings, suppressed = _suppress.apply(r.findings, sup_rules)
                    all_suppressed.extend(suppressed)
                    reports.append(r)
            if fmt == "json":
                import json as _json
                click.echo(_json.dumps([_json.loads(as_inspect_json(r)) for r in reports], indent=2))
            else:
                for r in reports:
                    print_inspect_result(r)
                msg = _suppress.notice(all_suppressed)
                if msg:
                    console.print(f"  {msg}\n")
            if fail_on:
                _rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                threshold = _rank.get(fail_on, 0)
                if any(_rank.get(f.severity, 0) >= threshold for r in reports for f in r.findings):
                    sys.exit(1)
            return

        report = inspect_file(path, api_key=api_key, summary_model=model)
        if report is None:
            console.print(f"[yellow]No agent signals detected in:[/yellow] {target}")
            console.print("  Is this an agent file with @tool decorators, Tool() definitions, or known framework imports?")
            sys.exit(0)

    # Apply suppressions for single-file and live-URL inspect
    _sup_base = Path(target) if not (target.startswith("http://") or target.startswith("https://")) else Path.cwd()
    _sup_rules = _suppress.merge(_suppress.load_ignore_file(_sup_base), ignore_rules)
    report.findings, _suppressed = _suppress.apply(report.findings, _sup_rules)

    if fmt == "json":
        click.echo(as_inspect_json(report))
    else:
        print_inspect_result(report)
        msg = _suppress.notice(_suppressed)
        if msg:
            console.print(f"  {msg}\n")

    if fail_on:
        _rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = _rank.get(fail_on, 0)
        if any(_rank.get(f.severity, 0) >= threshold for f in report.findings):
            sys.exit(1)


# ── sentinel secrets ─────────────────────────────────────────────────────────

@main.command()
@click.argument("target", default=".", type=click.Path(exists=True, path_type=Path))
@click.option("--scope", type=click.Choice(["all", "memory", "config"]), default="all",
              show_default=True,
              help="Scan scope: all files, memory files only, or config/env files only.")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              default="MEDIUM", show_default=True,
              help="Minimum severity level to display.")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              default=None,
              help="Exit with code 1 if findings at or above this severity exist.")
@click.option("--no-redact", is_flag=True, default=False,
              help="Show full matched values instead of redacting them.")
@click.option("--ignore-rule", "ignore_rules", multiple=True, metavar="RULE_ID",
              help="Suppress a finding by rule ID. Repeatable. Also reads .sentinelignore.")
def secrets(
    target: Path,
    scope: str,
    severity: str,
    fmt: str,
    fail_on: str | None,
    no_redact: bool,
    ignore_rules: tuple[str, ...],
) -> None:
    """Scan for exposed secrets, API keys, and PII in agent files and memory.

    Detects credentials (Anthropic, OpenAI, AWS, GitHub, Stripe, Google, HuggingFace),
    global PII (email, credit card, US SSN), Singapore PII (NRIC/FIN with checksum
    validation, passport, mobile, landline, UEN, postal code), and memory contamination
    patterns (customer PII clusters leaked from tool call results, system prompt leakage).

    \b
    Examples:
        sentinel secrets .                       scan current directory
        sentinel secrets ~/.claude/projects/     scan Claude Code agent memory
        sentinel secrets . --scope memory        memory files only
        sentinel secrets . --scope config        config/env files only
        sentinel secrets . --severity HIGH       show HIGH and CRITICAL only
        sentinel secrets . --format json         machine-readable output
        sentinel secrets . --fail-on HIGH        exit 1 if any HIGH+ findings
        sentinel secrets . --no-redact           show full matched values
    """
    from agentsentinel_cli.secrets import scan_secrets
    from agentsentinel_cli.secrets_report import print_secrets_result, as_secrets_json
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    _report_holder: list = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[dim]{task.description}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,   # clears the progress line when done
    ) as progress:
        task = progress.add_task("Scanning...", total=None)

        def _on_progress(n: int, current: str) -> None:
            short = current[-50:] if len(current) > 50 else current
            progress.update(task, description=f"Scanning [bold]{n}[/bold] files  [dim]{short}[/dim]")

        _report_holder.append(
            scan_secrets(target, scope=scope, redact=not no_redact, progress_cb=_on_progress)
        )

    from agentsentinel_cli import suppress as _suppress

    report = _report_holder[0]

    sup_rules = _suppress.merge(_suppress.load_ignore_file(target), ignore_rules)
    report.findings, suppressed = _suppress.apply(report.findings, sup_rules)

    if fmt == "json":
        click.echo(as_secrets_json(report))
    else:
        print_secrets_result(report, min_severity=severity)
        msg = _suppress.notice(suppressed)
        if msg:
            console.print(f"  {msg}\n")

    if fail_on:
        _rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = _rank.get(fail_on, 0)
        if any(_rank.get(f.severity, 0) >= threshold for f in report.findings):
            sys.exit(1)


# ── sentinel supply-chain ─────────────────────────────────────────────────────

@main.command(name="supply-chain")
@click.argument("target", default=None, required=False, metavar="URL")
@click.option("--stdio", "stdio_cmd", default=None, metavar="CMD",
              help="Audit a stdio-transport server, e.g. 'python server.py'.")
@click.option("--auth-header", "auth_header", default=None, metavar="HEADER",
              help="HTTP auth header, e.g. 'Authorization: Bearer token'.")
@click.option("--ai", "use_ai", is_flag=True, default=False,
              help="Use Claude for semantic analysis of tool descriptions (requires ANTHROPIC_API_KEY).")
@click.option("--model", default="claude-haiku-4-5-20251001", show_default=True,
              help="Claude model for --ai analysis.")
@click.option("--baseline", "baseline_path", default=None, type=click.Path(),
              help="Path to a saved baseline JSON to diff against.")
@click.option("--save-baseline", "save_baseline_path", default=None, type=click.Path(),
              help="Save current tool manifest as a baseline JSON file.")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--timeout", default=10.0, show_default=True, metavar="SECONDS",
              help="Connection timeout in seconds.")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              default=None, help="Exit with code 1 if findings at or above this severity exist.")
@click.option("--ignore-rule", "ignore_rules", multiple=True, metavar="RULE_ID",
              help="Suppress a finding by rule ID. Repeatable. Also reads .sentinelignore.")
def supply_chain(
    target: str | None,
    stdio_cmd: str | None,
    auth_header: str | None,
    use_ai: bool,
    model: str,
    baseline_path: str | None,
    save_baseline_path: str | None,
    fmt: str,
    timeout: float,
    fail_on: str | None,
    ignore_rules: tuple[str, ...],
) -> None:
    """Audit an MCP server's tool manifest for supply chain compromise.

    Detects deceptive tool naming, hidden capabilities, LLM instruction injection
    in descriptions, schema anomalies, and registry drift vs. a saved baseline.
    Covers ASI04 from OWASP Top 10 for Agentic Applications 2026.

    \b
    Examples:
        sentinel supply-chain http://localhost:3001
        sentinel supply-chain --stdio "python my_server.py"
        sentinel supply-chain http://localhost:3001 --ai
        sentinel supply-chain http://localhost:3001 --save-baseline ./baseline.json
        sentinel supply-chain http://localhost:3001 --baseline ./baseline.json
        sentinel supply-chain http://localhost:3001 --format json --fail-on CRITICAL
    """
    import os
    import json as _json
    from pathlib import Path as _Path

    from agentsentinel_cli.mcp_client import scan_http, scan_stdio, McpError, McpAuthRequired
    from agentsentinel_cli.supply_chain_rules import (
        SupplyChainContext, run_supply_chain_rules, supply_chain_score, make_baseline,
    )
    from agentsentinel_cli.supply_chain_report import (
        print_supply_chain_result, as_supply_chain_json,
    )

    if not target and not stdio_cmd:
        console.print("[red]Error:[/red] provide a URL target or --stdio CMD.")
        console.print("  Example: [dim]sentinel supply-chain http://localhost:3001[/dim]")
        console.print("  Example: [dim]sentinel supply-chain --stdio 'python server.py'[/dim]")
        sys.exit(1)
    if target and stdio_cmd:
        console.print("[red]Error:[/red] --stdio and a URL target are mutually exclusive.")
        sys.exit(1)

    display_target = stdio_cmd if stdio_cmd else target

    extra_headers: dict[str, str] = {}
    if auth_header:
        if ":" not in auth_header:
            console.print("[red]Error:[/red] --auth-header must be in 'Header-Name: value' format.")
            sys.exit(1)
        key, _, val = auth_header.partition(":")
        extra_headers[key.strip()] = val.strip()

    # ── Connect to MCP server ─────────────────────────────────────────────────
    try:
        if stdio_cmd:
            server = scan_stdio(stdio_cmd, timeout=timeout)
        else:
            server = scan_http(target, extra_headers=extra_headers or None, timeout=timeout)
    except McpAuthRequired as exc:
        console.print(f"\n[bold yellow]Authentication required[/bold yellow] (HTTP {exc.status_code})")
        console.print(
            "  Provide credentials with: "
            "[bold]--auth-header 'Authorization: Bearer <token>'[/bold]"
        )
        sys.exit(1)
    except McpError as exc:
        console.print(f"\n[red]MCP connection failed:[/red] {exc}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[red]Unexpected error:[/red] {exc}")
        sys.exit(1)

    # ── Save baseline if requested ────────────────────────────────────────────
    if save_baseline_path:
        save_p = _Path(save_baseline_path)
        if save_p.suffix.lower() != ".json":
            console.print("[red]Error:[/red] --save-baseline path must end in .json")
            sys.exit(1)
        baseline_data = make_baseline(server, display_target)
        save_p.write_text(_json.dumps(baseline_data, indent=2))
        if fmt == "text":
            console.print(
                f"\n  [green]✓ Baseline saved:[/green] {save_baseline_path}  "
                f"[dim]({len(server.tools)} tools)[/dim]\n"
            )

    # ── Load baseline if provided ─────────────────────────────────────────────
    baseline: dict | None = None
    if baseline_path:
        load_p = _Path(baseline_path)
        if load_p.suffix.lower() != ".json":
            console.print("[red]Error:[/red] --baseline path must be a .json file")
            sys.exit(1)
        try:
            baseline = _json.loads(load_p.read_text())
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Baseline file not found: {baseline_path}")
            sys.exit(1)
        except _json.JSONDecodeError:
            console.print(f"[red]Error:[/red] Baseline file is not valid JSON: {baseline_path}")
            sys.exit(1)

    # ── Run static rules ──────────────────────────────────────────────────────
    ctx = SupplyChainContext(server=server, baseline=baseline)
    findings = run_supply_chain_rules(ctx)

    # ── Run AI semantic analysis (optional) ───────────────────────────────────
    if use_ai:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            console.print("[red]Error:[/red] ANTHROPIC_API_KEY is required for --ai.")
            console.print("  Export it with: [bold]export ANTHROPIC_API_KEY=sk-ant-...[/bold]")
            sys.exit(1)

        from agentsentinel_cli.supply_chain_ai import run_supply_chain_ai

        if fmt == "text":
            console.print(
                f"  [dim cyan]Running AI semantic analysis ({model})…[/dim cyan]"
            )

        def _ai_progress(tool_name: str) -> None:
            if fmt == "text":
                console.print(f"  [dim]  → finding on: {tool_name}[/dim]")

        try:
            ai_findings = run_supply_chain_ai(
                server, api_key=api_key, model=model, progress_cb=_ai_progress
            )
            findings.extend(ai_findings)
        except ImportError as exc:
            console.print(f"\n[red]Missing dependency:[/red] {exc}")
            sys.exit(1)
        except Exception as exc:
            console.print(f"\n[yellow]AI analysis failed:[/yellow] {exc}")
            console.print("  [dim]Continuing with static results only.[/dim]")

    from agentsentinel_cli import suppress as _suppress

    sup_rules = _suppress.merge(_suppress.load_ignore_file(Path.cwd()), ignore_rules)
    findings, suppressed = _suppress.apply(findings, sup_rules)
    score = supply_chain_score(findings)

    # ── Output ────────────────────────────────────────────────────────────────
    if fmt == "json":
        click.echo(as_supply_chain_json(ctx, findings, score, display_target, used_ai=use_ai))
    else:
        print_supply_chain_result(
            ctx, findings, score, display_target,
            used_ai=use_ai, baseline_path=baseline_path,
        )
        msg = _suppress.notice(suppressed)
        if msg:
            console.print(f"  {msg}\n")

    if fail_on:
        _severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = _severity_rank.get(fail_on, 0)
        if any(_severity_rank.get(f.severity, 0) >= threshold for f in findings):
            sys.exit(1)


# ── sentinel a2a ──────────────────────────────────────────────────────────────

@main.command(name="a2a")
@click.argument("target", default=".", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              default=None, help="Exit with code 1 if findings at or above this severity exist.")
@click.option("--ignore-rule", "ignore_rules", multiple=True, metavar="RULE_ID",
              help="Suppress a finding by rule ID. Repeatable. Also reads .sentinelignore.")
def a2a(
    target: Path,
    fmt: str,
    fail_on: str | None,
    ignore_rules: tuple[str, ...],
) -> None:
    """Analyse multi-agent trust boundaries in a codebase.

    Detects agent-to-agent call graphs and audits for trust violations:
    unverified orchestrators, unbounded spawning, prompt passthrough,
    unscoped delegation, and circular delegation.

    Supports LangChain/LangGraph, AutoGen, and CrewAI patterns.
    TARGET can be a single .py file or a directory (scanned recursively).

    \b
    Examples:
        sentinel a2a .
        sentinel a2a ./agents/
        sentinel a2a multi_agent.py
        sentinel a2a . --fail-on HIGH
        sentinel a2a . --format json
        sentinel a2a . --ignore-rule A2A01_UNVERIFIED_ORCHESTRATOR
    """
    from agentsentinel_cli.a2a_scanner import scan_path
    from agentsentinel_cli.a2a_rules import run_a2a_rules, a2a_posture_score
    from agentsentinel_cli.a2a_report import print_a2a_result, as_a2a_json
    from agentsentinel_cli import suppress as _suppress

    graph    = scan_path(target)
    findings = run_a2a_rules(graph)

    sup_rules = _suppress.merge(_suppress.load_ignore_file(target), ignore_rules)
    findings, suppressed = _suppress.apply(findings, sup_rules)
    score = a2a_posture_score(findings)

    if fmt == "json":
        click.echo(as_a2a_json(graph, findings, score, str(target)))
    else:
        print_a2a_result(graph, findings, score, str(target))
        msg = _suppress.notice(suppressed)
        if msg:
            console.print(f"  {msg}\n")

    if fail_on:
        _rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = _rank.get(fail_on, 0)
        if any(_rank.get(f.severity, 0) >= threshold for f in findings):
            sys.exit(1)


# ── sentinel host ─────────────────────────────────────────────────────────────

@main.command(name="host-scan")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              default=None, help="Exit with code 1 if findings at or above this severity exist.")
@click.option("--ignore-rule", "ignore_rules", multiple=True, metavar="RULE_ID",
              help="Suppress a finding by rule ID. Repeatable. Also reads .sentinelignore.")
def host(
    fmt: str,
    fail_on: str | None,
    ignore_rules: tuple[str, ...],
) -> None:
    """Audit your local AI security posture.

    Checks Claude Code and Desktop configurations, MCP server permissions,
    shell credential exposure, macOS privacy permissions (Full Disk Access,
    Screen Recording, Accessibility), system security (SIP, FileVault,
    Gatekeeper), and AI processes exposed on the network.

    No network calls — all checks are local and read-only.

    \b
    Examples:
        sentinel host-scan
        sentinel host-scan --format json
        sentinel host-scan --fail-on HIGH
        sentinel host-scan --ignore-rule HOST_LARGE_MEMORY
    """
    from agentsentinel_cli.host_scanner import scan_host
    from agentsentinel_cli.host_rules import run_host_rules, host_posture_score
    from agentsentinel_cli.host_report import print_host_result, as_host_json
    from agentsentinel_cli import suppress as _suppress
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    _ctx_holder: list = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[dim]{task.description}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning host AI security posture…", total=None)
        _ctx_holder.append(scan_host())

    ctx = _ctx_holder[0]
    findings = run_host_rules(ctx)

    sup_rules = _suppress.merge(_suppress.load_ignore_file(Path.cwd()), ignore_rules)
    findings, suppressed = _suppress.apply(findings, sup_rules)
    score = host_posture_score(findings)

    if fmt == "json":
        click.echo(as_host_json(ctx, findings, score))
    else:
        print_host_result(ctx, findings, score)
        msg = _suppress.notice(suppressed)
        if msg:
            console.print(f"  {msg}\n")

    if fail_on:
        _rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = _rank.get(fail_on, 0)
        if any(_rank.get(f.severity, 0) >= threshold for f in findings):
            sys.exit(1)


def _parse_ports(ports_str: str) -> list[int]:
    """Parse '8000-9001' or '8000,8080,9000' into a list of ints."""
    ports: list[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, _, hi = part.partition("-")
                lo_i, hi_i = int(lo), int(hi)
                if not (1 <= lo_i <= 65535 and 1 <= hi_i <= 65535 and lo_i <= hi_i):
                    raise ValueError
                ports.extend(range(lo_i, hi_i + 1))
            else:
                p = int(part)
                if not (1 <= p <= 65535):
                    raise ValueError
                ports.append(p)
        except ValueError:
            console.print(f"[yellow]Warning: invalid port specification '{part}' — skipped[/yellow]")
    if not ports:
        raise click.ClickException(f"No valid ports found in: {ports_str}")
    return ports


def _warn_missing_deps(do_process: bool, do_network: bool) -> None:
    if do_process:
        try:
            import psutil  # noqa: F401
        except ImportError:
            console.print(
                "[dim yellow]  ⚠  psutil not installed — process scan disabled.[/dim yellow]\n"
                "[dim]  Install with: pip install agentsentinel-cli\\[discover][/dim]\n"
            )
    if do_network:
        try:
            import httpx  # noqa: F401
        except ImportError:
            console.print(
                "[dim yellow]  ⚠  httpx not installed — network probe disabled.[/dim yellow]\n"
                "[dim]  Install with: pip install agentsentinel-cli\\[discover][/dim]\n"
            )


# ── sentinel redteam ──────────────────────────────────────────────────────────

@main.group(name="redteam")
def redteam_group() -> None:
    """Active red-team attacks against AI infrastructure.

    \b
    Sub-groups:
      mcp   Red-team an MCP server
    """


@redteam_group.group(name="mcp")
def redteam_mcp_group() -> None:
    """Red-team an MCP server — active adversarial testing.

    \b
    Commands:
      recon    Enumerate tools, resources, prompts, and fingerprint the server
      auth     Test authentication bypass across multiple credential scenarios
      inject   Active injection attacks (path traversal, SSRF, cmd, SQLi, LLM)
      poison   MCP-native: tool description analysis + LLM result injection
      fuzz     Schema boundary and type-confusion fuzzing
      full     Run all modules in sequence and produce a unified report
    """


# ── Shared option helpers ─────────────────────────────────────────────────────

def _add_mcp_common(cmd: click.BaseCommand) -> click.BaseCommand:
    """Attach the shared connection + output flags used by every mcp subcommand."""
    cmd = click.argument("target", required=False, metavar="URL")(cmd)
    cmd = click.option(
        "--stdio", "stdio_cmd", default=None, metavar="CMD",
        help="Attack a stdio-transport server. Provide the launch command.",
    )(cmd)
    cmd = click.option(
        "--auth-header", "auth_header", default=None, metavar="HEADER",
        help="HTTP auth header, e.g. 'Authorization: Bearer token'.",
    )(cmd)
    cmd = click.option(
        "--timeout", default=15.0, show_default=True, metavar="SECONDS",
        help="Per-request timeout.",
    )(cmd)
    cmd = click.option(
        "--format", "fmt", type=click.Choice(["text", "json"]), default="text",
        help="Output format.",
    )(cmd)
    cmd = click.option(
        "--output", "output_path", default=None, metavar="FILE",
        help="Save JSON evidence bundle to FILE (always JSON regardless of --format).",
    )(cmd)
    cmd = click.option(
        "--verbose", "-v", is_flag=True, default=False,
        help="Include raw request/response pairs in output.",
    )(cmd)
    cmd = click.option(
        "--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
        default=None,
        help="Exit with code 1 if findings at or above this severity exist.",
    )(cmd)
    return cmd


def _parse_auth_header(auth_header: str | None) -> dict[str, str]:
    if not auth_header:
        return {}
    if ":" not in auth_header:
        console.print("[red]Error:[/red] --auth-header must be 'Header-Name: value' format.")
        sys.exit(1)
    key, _, val = auth_header.partition(":")
    return {key.strip(): val.strip()}


def _require_target(target: str | None, stdio_cmd: str | None) -> None:
    if not target and not stdio_cmd:
        console.print("[red]Error:[/red] provide a URL or --stdio CMD.")
        console.print("  Example: [dim]sentinel redteam mcp recon http://localhost:3000[/dim]")
        console.print("  Example: [dim]sentinel redteam mcp recon --stdio 'python server.py'[/dim]")
        sys.exit(1)
    if target and stdio_cmd:
        console.print("[red]Error:[/red] URL and --stdio are mutually exclusive.")
        sys.exit(1)


def _normalize_url(url: str | None) -> str | None:
    """Prepend http:// to bare host:port inputs (e.g. 127.0.0.1:8000 → http://127.0.0.1:8000)."""
    if url and not url.startswith(("http://", "https://")):
        return f"http://{url}"
    return url


def _check_exit(findings: list, fail_on: str | None) -> None:
    if not fail_on:
        return
    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    threshold = rank.get(fail_on, 0)
    if any(rank.get(f.severity, 0) >= threshold for f in findings):
        sys.exit(1)


def _save_output(output_path: str | None, result) -> None:
    if not output_path:
        return
    from agentsentinel_cli.redteam.report import as_redteam_json
    Path(output_path).write_text(as_redteam_json(result))
    console.print(f"\n  [green]✓ Evidence bundle saved:[/green] {output_path}\n")


# ── sentinel redteam mcp recon ────────────────────────────────────────────────

@redteam_mcp_group.command("recon")
@click.argument("target", required=False, metavar="URL")
@click.option("--stdio", "stdio_cmd", default=None, metavar="CMD",
              help="Attack a stdio-transport server.")
@click.option("--auth-header", "auth_header", default=None, metavar="HEADER",
              help="HTTP auth header, e.g. 'Authorization: Bearer token'.")
@click.option("--timeout", default=15.0, show_default=True, metavar="SECONDS")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "output_path", default=None, metavar="FILE")
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default=None)
def redteam_mcp_recon(
    target: str | None, stdio_cmd: str | None, auth_header: str | None,
    timeout: float, fmt: str, output_path: str | None, verbose: bool, fail_on: str | None,
) -> None:
    """Enumerate tools, resources, prompts — map the full attack surface.

    No payloads are sent. Passive enumeration only.

    \b
    Examples:
        sentinel redteam mcp recon http://localhost:3000
        sentinel redteam mcp recon --stdio "python server.py"
        sentinel redteam mcp recon http://localhost:3000 --format json
    """
    import time
    from agentsentinel_cli.redteam.transport import RedTeamSession
    from agentsentinel_cli.redteam.mcp_recon import run_recon
    from agentsentinel_cli.redteam.models import RedTeamResult
    from agentsentinel_cli.redteam.report import print_redteam_result, as_redteam_json
    from agentsentinel_cli.mcp_client import McpAuthRequired, McpError

    _require_target(target, stdio_cmd)
    target = _normalize_url(target)
    headers = _parse_auth_header(auth_header)
    display = stdio_cmd or target

    t0 = time.monotonic()
    try:
        with RedTeamSession(url=target, stdio_cmd=stdio_cmd,
                            extra_headers=headers, timeout=timeout) as session:
            findings, _ = run_recon(session, verbose)
            result = RedTeamResult(
                target=display, server_name=session.server_info.name,
                server_version=session.server_info.version,
                transport=session.server_info.transport,
                modules_run=["recon"], findings=findings,
                tool_count=len(session.server_info.tools),
                attack_count=0, duration_s=time.monotonic() - t0,
            )
    except McpAuthRequired as exc:
        console.print(f"\n[bold yellow]Auth required[/bold yellow] (HTTP {exc.status_code})")
        console.print("  Use: [bold]--auth-header 'Authorization: Bearer <token>'[/bold]")
        sys.exit(1)
    except McpError as exc:
        console.print(f"\n[red]Connection failed:[/red] {exc}")
        sys.exit(1)

    if fmt == "json":
        click.echo(as_redteam_json(result))
    else:
        print_redteam_result(result, verbose)

    _save_output(output_path, result)
    _check_exit(findings, fail_on)


# ── sentinel redteam mcp auth ─────────────────────────────────────────────────

@redteam_mcp_group.command("auth")
@click.argument("target", required=False, metavar="URL")
@click.option("--stdio", "stdio_cmd", default=None, metavar="CMD")
@click.option("--auth-header", "auth_header", default=None, metavar="HEADER",
              help="Original valid credentials (used to enumerate tools before bypass attempts).")
@click.option("--timeout", default=15.0, show_default=True, metavar="SECONDS")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "output_path", default=None, metavar="FILE")
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default=None)
def redteam_mcp_auth(
    target: str | None, stdio_cmd: str | None, auth_header: str | None,
    timeout: float, fmt: str, output_path: str | None, verbose: bool, fail_on: str | None,
) -> None:
    """Test authentication bypass — calls every tool with invalid credentials.

    Tests: no credentials, empty bearer, garbage token, JWT alg:none, expired token.
    A CRITICAL finding means a tool executed without valid auth.

    \b
    Examples:
        sentinel redteam mcp auth http://localhost:3000
        sentinel redteam mcp auth http://localhost:3000 --auth-header "Authorization: Bearer token"
        sentinel redteam mcp auth http://localhost:3000 --verbose
    """
    import time
    from agentsentinel_cli.redteam.mcp_auth import run_auth_bypass
    from agentsentinel_cli.redteam.models import RedTeamResult
    from agentsentinel_cli.redteam.report import print_redteam_result, as_redteam_json
    from agentsentinel_cli.mcp_client import McpAuthRequired, McpError

    _require_target(target, stdio_cmd)
    target = _normalize_url(target)
    headers = _parse_auth_header(auth_header)
    display = stdio_cmd or target

    t0 = time.monotonic()

    # We need tool count — do a quick connect with valid credentials
    tool_count = 0
    try:
        from agentsentinel_cli.redteam.transport import RedTeamSession
        with RedTeamSession(url=target, stdio_cmd=stdio_cmd,
                            extra_headers=headers, timeout=timeout) as s:
            tool_count = len(s.server_info.tools)
            server_name = s.server_info.name
            server_version = s.server_info.version
            transport = s.server_info.transport
    except (McpAuthRequired, McpError) as exc:
        server_name, server_version, transport = "unknown", "unknown", "http"

    findings, scenarios_tested = run_auth_bypass(
        url=target, stdio_cmd=stdio_cmd,
        original_headers=headers,
        timeout=timeout, verbose=verbose,
    )

    result = RedTeamResult(
        target=display, server_name=server_name, server_version=server_version,
        transport=transport, modules_run=["auth"], findings=findings,
        tool_count=tool_count, attack_count=scenarios_tested,
        duration_s=time.monotonic() - t0,
    )

    if fmt == "json":
        click.echo(as_redteam_json(result))
    else:
        print_redteam_result(result, verbose)

    _save_output(output_path, result)
    _check_exit(findings, fail_on)


# ── sentinel redteam mcp inject ───────────────────────────────────────────────

@redteam_mcp_group.command("inject")
@click.argument("target", required=False, metavar="URL")
@click.option("--stdio", "stdio_cmd", default=None, metavar="CMD")
@click.option("--auth-header", "auth_header", default=None, metavar="HEADER")
@click.option(
    "--type", "techniques",
    multiple=True,
    type=click.Choice(["traverse", "ssrf", "cmd", "sqli", "llm"]),
    metavar="TECHNIQUE",
    help="Injection technique(s) to run. Repeatable. Default: all.",
)
@click.option(
    "--intensity", type=click.Choice(["low", "medium", "high"]),
    default="medium", show_default=True,
    help="Payload depth. low=5, medium=15, high=full library.",
)
@click.option("--include-dangerous", is_flag=True, default=False,
              help="Also test tools marked dangerous (write/delete/execute). Off by default.")
@click.option("--timeout", default=15.0, show_default=True, metavar="SECONDS")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "output_path", default=None, metavar="FILE")
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default=None)
def redteam_mcp_inject(
    target: str | None, stdio_cmd: str | None, auth_header: str | None,
    techniques: tuple[str, ...], intensity: str, include_dangerous: bool,
    timeout: float, fmt: str, output_path: str | None, verbose: bool, fail_on: str | None,
) -> None:
    """Active injection attacks per tool parameter.

    Infers applicable techniques from parameter names and schemas, then fires
    real payloads. Only raises findings when detection patterns match actual
    response content — no false positives from error codes alone.

    \b
    Techniques:
      traverse  Path traversal — file read via ../../../etc/passwd
      ssrf      SSRF — internal network access via http://169.254.169.254/
      cmd       Command injection — OS execution via ; id
      sqli      SQL injection — database query manipulation
      llm       LLM instruction injection — adversarial prompts via tool results

    \b
    Examples:
        sentinel redteam mcp inject http://localhost:3000
        sentinel redteam mcp inject http://localhost:3000 --type traverse --type ssrf
        sentinel redteam mcp inject http://localhost:3000 --intensity high
        sentinel redteam mcp inject http://localhost:3000 --include-dangerous
        sentinel redteam mcp inject http://localhost:3000 --type llm --verbose
    """
    import time
    from agentsentinel_cli.redteam.transport import RedTeamSession
    from agentsentinel_cli.redteam.mcp_inject import run_inject
    from agentsentinel_cli.redteam.models import RedTeamResult
    from agentsentinel_cli.redteam.report import print_redteam_result, as_redteam_json
    from agentsentinel_cli.mcp_client import McpAuthRequired, McpError

    _require_target(target, stdio_cmd)
    target = _normalize_url(target)
    headers = _parse_auth_header(auth_header)
    display = stdio_cmd or target

    active_techniques = list(techniques) if techniques else ["traverse", "ssrf", "cmd", "sqli", "llm"]

    t0 = time.monotonic()
    try:
        with RedTeamSession(url=target, stdio_cmd=stdio_cmd,
                            extra_headers=headers, timeout=timeout) as session:
            findings, attack_count = run_inject(
                session, active_techniques, intensity, include_dangerous, verbose,
            )
            result = RedTeamResult(
                target=display, server_name=session.server_info.name,
                server_version=session.server_info.version,
                transport=session.server_info.transport,
                modules_run=[f"inject({','.join(active_techniques)})"],
                findings=findings, tool_count=len(session.server_info.tools),
                attack_count=attack_count, duration_s=time.monotonic() - t0,
            )
    except McpAuthRequired as exc:
        console.print(f"\n[bold yellow]Auth required[/bold yellow] (HTTP {exc.status_code})")
        console.print("  Use: [bold]--auth-header 'Authorization: Bearer <token>'[/bold]")
        sys.exit(1)
    except McpError as exc:
        console.print(f"\n[red]Connection failed:[/red] {exc}")
        sys.exit(1)

    if fmt == "json":
        click.echo(as_redteam_json(result))
    else:
        print_redteam_result(result, verbose)

    _save_output(output_path, result)
    _check_exit(findings, fail_on)


# ── sentinel redteam mcp poison ───────────────────────────────────────────────

@redteam_mcp_group.command("poison")
@click.argument("target", required=False, metavar="URL")
@click.option("--stdio", "stdio_cmd", default=None, metavar="CMD")
@click.option("--auth-header", "auth_header", default=None, metavar="HEADER")
@click.option("--timeout", default=15.0, show_default=True, metavar="SECONDS")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "output_path", default=None, metavar="FILE")
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default=None)
def redteam_mcp_poison(
    target: str | None, stdio_cmd: str | None, auth_header: str | None,
    timeout: float, fmt: str, output_path: str | None, verbose: bool, fail_on: str | None,
) -> None:
    """MCP-native adversarial tests: tool description poisoning + LLM result injection.

    Static: scans tool descriptions for embedded adversarial LLM instructions.
    Dynamic: calls tools with sentinel injection payloads and checks if they're
    echoed back — confirming a live injection vector into agent context windows.

    \b
    Examples:
        sentinel redteam mcp poison http://localhost:3000
        sentinel redteam mcp poison http://localhost:3000 --verbose
        sentinel redteam mcp poison http://localhost:3000 --format json --output evidence.json
    """
    import time
    from agentsentinel_cli.redteam.transport import RedTeamSession
    from agentsentinel_cli.redteam.mcp_poison import run_poison
    from agentsentinel_cli.redteam.models import RedTeamResult
    from agentsentinel_cli.redteam.report import print_redteam_result, as_redteam_json
    from agentsentinel_cli.mcp_client import McpAuthRequired, McpError

    _require_target(target, stdio_cmd)
    target = _normalize_url(target)
    headers = _parse_auth_header(auth_header)
    display = stdio_cmd or target

    t0 = time.monotonic()
    try:
        with RedTeamSession(url=target, stdio_cmd=stdio_cmd,
                            extra_headers=headers, timeout=timeout) as session:
            findings, attack_count = run_poison(session, verbose)
            result = RedTeamResult(
                target=display, server_name=session.server_info.name,
                server_version=session.server_info.version,
                transport=session.server_info.transport,
                modules_run=["poison"], findings=findings,
                tool_count=len(session.server_info.tools),
                attack_count=attack_count, duration_s=time.monotonic() - t0,
            )
    except McpAuthRequired as exc:
        console.print(f"\n[bold yellow]Auth required[/bold yellow] (HTTP {exc.status_code})")
        console.print("  Use: [bold]--auth-header 'Authorization: Bearer <token>'[/bold]")
        sys.exit(1)
    except McpError as exc:
        console.print(f"\n[red]Connection failed:[/red] {exc}")
        sys.exit(1)

    if fmt == "json":
        click.echo(as_redteam_json(result))
    else:
        print_redteam_result(result, verbose)

    _save_output(output_path, result)
    _check_exit(findings, fail_on)


# ── sentinel redteam mcp fuzz ─────────────────────────────────────────────────

@redteam_mcp_group.command("fuzz")
@click.argument("target", required=False, metavar="URL")
@click.option("--stdio", "stdio_cmd", default=None, metavar="CMD")
@click.option("--auth-header", "auth_header", default=None, metavar="HEADER")
@click.option("--timeout", default=15.0, show_default=True, metavar="SECONDS")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "output_path", default=None, metavar="FILE")
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default=None)
def redteam_mcp_fuzz(
    target: str | None, stdio_cmd: str | None, auth_header: str | None,
    timeout: float, fmt: str, output_path: str | None, verbose: bool, fail_on: str | None,
) -> None:
    """Schema boundary and type-confusion fuzzing.

    Sends malformed, oversized, null, and wrong-type inputs to every parameter.
    Looks for stack traces, internal path leakage, template injection evaluation,
    and unexpected data disclosure in error responses.

    \b
    Examples:
        sentinel redteam mcp fuzz http://localhost:3000
        sentinel redteam mcp fuzz http://localhost:3000 --verbose
        sentinel redteam mcp fuzz --stdio "python server.py" --format json
    """
    import time
    from agentsentinel_cli.redteam.transport import RedTeamSession
    from agentsentinel_cli.redteam.mcp_fuzz import run_fuzz
    from agentsentinel_cli.redteam.models import RedTeamResult
    from agentsentinel_cli.redteam.report import print_redteam_result, as_redteam_json
    from agentsentinel_cli.mcp_client import McpAuthRequired, McpError

    _require_target(target, stdio_cmd)
    target = _normalize_url(target)
    headers = _parse_auth_header(auth_header)
    display = stdio_cmd or target

    t0 = time.monotonic()
    try:
        with RedTeamSession(url=target, stdio_cmd=stdio_cmd,
                            extra_headers=headers, timeout=timeout) as session:
            findings, attack_count = run_fuzz(session, verbose)
            result = RedTeamResult(
                target=display, server_name=session.server_info.name,
                server_version=session.server_info.version,
                transport=session.server_info.transport,
                modules_run=["fuzz"], findings=findings,
                tool_count=len(session.server_info.tools),
                attack_count=attack_count, duration_s=time.monotonic() - t0,
            )
    except McpAuthRequired as exc:
        console.print(f"\n[bold yellow]Auth required[/bold yellow] (HTTP {exc.status_code})")
        console.print("  Use: [bold]--auth-header 'Authorization: Bearer <token>'[/bold]")
        sys.exit(1)
    except McpError as exc:
        console.print(f"\n[red]Connection failed:[/red] {exc}")
        sys.exit(1)

    if fmt == "json":
        click.echo(as_redteam_json(result))
    else:
        print_redteam_result(result, verbose)

    _save_output(output_path, result)
    _check_exit(findings, fail_on)


# ── sentinel redteam mcp full ─────────────────────────────────────────────────

@redteam_mcp_group.command("full")
@click.argument("target", required=False, metavar="URL")
@click.option("--stdio", "stdio_cmd", default=None, metavar="CMD")
@click.option("--auth-header", "auth_header", default=None, metavar="HEADER",
              help="Valid credentials (also used as baseline for auth bypass tests).")
@click.option(
    "--intensity", type=click.Choice(["low", "medium", "high"]),
    default="medium", show_default=True,
    help="Injection payload depth.",
)
@click.option("--include-dangerous", is_flag=True, default=False,
              help="Include dangerous tools in injection and fuzz tests.")
@click.option("--timeout", default=15.0, show_default=True, metavar="SECONDS")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "output_path", default=None, metavar="FILE",
              help="Save complete JSON evidence bundle.")
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default=None)
def redteam_mcp_full(
    target: str | None, stdio_cmd: str | None, auth_header: str | None,
    intensity: str, include_dangerous: bool,
    timeout: float, fmt: str, output_path: str | None, verbose: bool, fail_on: str | None,
) -> None:
    """Run all red-team modules in sequence — full engagement.

    Executes: recon → auth bypass → inject (all techniques) → poison → fuzz.
    Produces a unified report with all findings and attack statistics.

    \b
    Examples:
        sentinel redteam mcp full http://localhost:3000
        sentinel redteam mcp full http://localhost:3000 --intensity high --output report.json
        sentinel redteam mcp full http://localhost:3000 --auth-header "Authorization: Bearer token"
        sentinel redteam mcp full --stdio "python server.py" --verbose
    """
    import time
    from agentsentinel_cli.redteam.transport import RedTeamSession
    from agentsentinel_cli.redteam.mcp_recon import run_recon
    from agentsentinel_cli.redteam.mcp_auth import run_auth_bypass
    from agentsentinel_cli.redteam.mcp_inject import run_inject
    from agentsentinel_cli.redteam.mcp_poison import run_poison
    from agentsentinel_cli.redteam.mcp_fuzz import run_fuzz
    from agentsentinel_cli.redteam.models import RedTeamResult
    from agentsentinel_cli.redteam.report import print_redteam_result, as_redteam_json
    from agentsentinel_cli.mcp_client import McpAuthRequired, McpError
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    _require_target(target, stdio_cmd)
    target = _normalize_url(target)
    headers = _parse_auth_header(auth_header)
    display = stdio_cmd or target

    all_findings: list = []
    total_attacks = 0
    server_name = server_version = transport = "unknown"
    tool_count = 0

    t0 = time.monotonic()

    # ── Phase 1–5: run inside a single persistent session ────────────────────
    try:
        with RedTeamSession(url=target, stdio_cmd=stdio_cmd,
                            extra_headers=headers, timeout=timeout) as session:
            server_name = session.server_info.name
            server_version = session.server_info.version
            transport = session.server_info.transport
            tool_count = len(session.server_info.tools)

            if fmt == "text":
                console.print()
                console.print(Panel.fit(
                    f"[bold white]AgentSentinel Red Team — Full Engagement[/bold white]\n"
                    f"[dim]Target: {display}  ·  Server: {server_name}  ·  Tools: {tool_count}[/dim]",
                    border_style="red", padding=(0, 2),
                ))

            with Progress(
                SpinnerColumn(),
                TextColumn("[dim]{task.description}[/dim]"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:

                task = progress.add_task("Phase 1/5 — recon…", total=None)
                recon_findings, _ = run_recon(session, verbose)
                all_findings.extend(recon_findings)

                progress.update(task, description="Phase 2/5 — auth bypass…")
                auth_findings, auth_scenarios = run_auth_bypass(
                    url=target, stdio_cmd=stdio_cmd,
                    original_headers=headers, timeout=timeout, verbose=verbose,
                )
                all_findings.extend(auth_findings)
                total_attacks += auth_scenarios

                progress.update(task, description="Phase 3/5 — injection…")
                inject_findings, inject_count = run_inject(
                    session,
                    # LLM injection is handled by poison phase — no duplication
                    techniques=["traverse", "ssrf", "cmd", "sqli"],
                    intensity=intensity,
                    include_dangerous=include_dangerous,
                    verbose=verbose,
                )
                all_findings.extend(inject_findings)
                total_attacks += inject_count

                progress.update(task, description="Phase 4/5 — poisoning…")
                poison_findings, poison_count = run_poison(session, verbose)
                all_findings.extend(poison_findings)
                total_attacks += poison_count

                progress.update(task, description="Phase 5/5 — fuzzing…")
                fuzz_findings, fuzz_count = run_fuzz(session, verbose)
                all_findings.extend(fuzz_findings)
                total_attacks += fuzz_count

    except McpAuthRequired as exc:
        console.print(f"\n[bold yellow]Auth required[/bold yellow] (HTTP {exc.status_code})")
        console.print("  Use: [bold]--auth-header 'Authorization: Bearer <token>'[/bold]")
        sys.exit(1)
    except McpError as exc:
        console.print(f"\n[red]Connection failed:[/red] {exc}")
        sys.exit(1)

    result = RedTeamResult(
        target=display,
        server_name=server_name,
        server_version=server_version,
        transport=transport,
        modules_run=["recon", "auth", "inject", "poison", "fuzz"],
        findings=all_findings,
        tool_count=tool_count,
        attack_count=total_attacks,
        duration_s=time.monotonic() - t0,
    )

    if fmt == "json":
        click.echo(as_redteam_json(result))
    else:
        print_redteam_result(result, verbose)

    _save_output(output_path, result)
    _check_exit(all_findings, fail_on)

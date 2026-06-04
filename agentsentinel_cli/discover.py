"""
sentinel discover — find MCP servers and AI agent processes.

Scan vectors:
  process   running Python/Node processes serving MCP or calling LLM APIs
  network   open ports on localhost confirmed as MCP via protocol handshake
  subnet    CIDR subnet — TCP sweep then MCP handshake on every open port
  docker    Docker containers with MCP server or LLM agent patterns
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import socket
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from agentsentinel_cli.frameworks import (
    LLM_API_HOSTS,
    LLM_ENV_VARS,
    detect_framework,
    detect_model,
    detect_provider_from_env,
    extract_api_keys,
)

# ── Data model ────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class DiscoveredAgent:
    source: str            # process | network | subnet | docker
    name: str              # human-readable name
    framework: str         # FastMCP | LangChain | AutoGen | etc.
    provider: str          # Anthropic | OpenAI | Google | etc.
    model: str             # claude-sonnet | gpt-4o | etc.  (empty if unknown)
    location: str          # pid:1234 | 10.0.1.45:8080 | container:name
    api_keys: list[str]    # masked keys: ANTHROPIC_API_KEY=sk-ant-...5f3d
    live_connections: list[str]   # LLM API hosts this process is talking to
    risk: str              # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    risk_reason: str       # one-line explanation of the risk level
    next_step: str         # suggested follow-up command
    tools: list[str] = dataclasses.field(default_factory=list)   # tool names (MCP enumeration)
    transport: str = ""    # "http" | "sse" | "" (empty for non-MCP)


@dataclasses.dataclass
class SubnetScanStats:
    cidr: str
    total_hosts: int
    hosts_scanned: int
    open_ports_found: int
    agents_found: int
    elapsed_seconds: float


# ── Default port list ─────────────────────────────────────────────────────────

_DEFAULT_PORTS = [
    3000, 3001, 4000, 5000,
    7860,                    # Gradio
    8000, 8001, 8002, 8003,
    8080, 8443, 8888,
    9000, 9001,
    11434,                   # Ollama
]

# Subnet scan limits — scanning beyond these sizes is impractical
_MAX_SUBNET_HOSTS_WARN  = 1024    # /22 — warn but allow
_MAX_SUBNET_HOSTS_BLOCK = 65536   # /16 — refuse (too slow, too noisy)


# ── Process scanner ───────────────────────────────────────────────────────────

_PROCESS_SKIP_FRAGMENTS = frozenset({
    "lsp-server", "lsp-runner", "lsp-worker",
    "server.bundle",
    "esbuild", "webpack", "rollup", "vite",
    "typescript-language-server", "tsserver",
    "pylsp", "pyright",
    "gopls", "rust-analyzer", "clangd",
    "code helper", "vmware fusion", "docker desktop",
    "safari", "firefox", "chrome helper",
})

_AGENT_CMDLINE_SIGNALS = frozenset({
    "langchain", "crewai", "autogen", "pyautogen",
    "openai.agents", "agents_sdk",
    "mcp_shim", "mcp-shim", "mcp.server",
    "sentinel_middleware", "agentsentinel",
    "llama_index", "llamaindex",
    "haystack", "pydantic_ai", "semantic_kernel",
    "agent.py", "agents.py",
})


def scan_processes() -> list[DiscoveredAgent]:
    """Scan running processes for AI agents using psutil."""
    try:
        import psutil
    except ImportError:
        return []

    found: list[DiscoveredAgent] = []
    seen: set[tuple[str, str, str]] = set()

    for proc in psutil.process_iter(["pid", "name", "cmdline", "status"]):
        try:
            info = proc.as_dict(attrs=["pid", "name", "cmdline", "status"])
            cmdline = info.get("cmdline") or []
            proc_name = (info.get("name") or "").lower()

            if not cmdline:
                continue

            if any(skip in proc_name for skip in _PROCESS_SKIP_FRAGMENTS):
                continue

            cmd_str = " ".join(str(c) for c in cmdline).lower()

            if not any(p in cmd_str for p in ("python", "node", "npx", "deno")):
                continue

            has_framework_in_cmd = any(s in cmd_str for s in _AGENT_CMDLINE_SIGNALS)

            live_connections: list[str] = []
            try:
                for conn in proc.connections(kind="tcp"):
                    if conn.raddr and conn.raddr.ip:
                        try:
                            host = socket.gethostbyaddr(conn.raddr.ip)[0]
                            if any(h in host for h in LLM_API_HOSTS):
                                live_connections.append(host)
                        except (socket.herror, socket.gaierror):
                            pass
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            if not has_framework_in_cmd and not live_connections:
                continue

            try:
                env = proc.environ()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                env = {}

            framework, provider = detect_framework(cmd_str)
            if not provider:
                provider = detect_provider_from_env(env)

            api_keys = extract_api_keys(env)
            model = detect_model(cmd_str) or detect_model(" ".join(env.values()))
            name = _name_from_cmdline(cmdline)

            dedup_key = (name, framework, api_keys[0] if api_keys else "")
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            risk, risk_reason = _assess_process_risk(api_keys, live_connections, framework)

            found.append(DiscoveredAgent(
                source="process",
                name=name,
                framework=framework,
                provider=provider,
                model=model,
                location=f"pid:{info['pid']}",
                api_keys=api_keys,
                live_connections=live_connections,
                risk=risk,
                risk_reason=risk_reason,
                next_step=f"sentinel scan --pid {info['pid']}",
            ))

        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue

    return found


def _name_from_cmdline(cmdline: list[str]) -> str:
    for part in reversed(cmdline):
        p = Path(part)
        if p.suffix in (".py", ".js", ".ts") and p.stem not in ("__main__", "-c"):
            return p.stem.replace("_", "-")
    for part in cmdline:
        if part and not part.startswith("-"):
            return Path(part).stem or part
    return "unknown-agent"


def _assess_process_risk(
    api_keys: list[str],
    live_connections: list[str],
    framework: str,
) -> tuple[str, str]:
    if api_keys:
        return (
            "CRITICAL",
            f"LLM API key{'s' if len(api_keys) > 1 else ''} exposed in process environment "
            f"({', '.join(k.split('=')[0] for k in api_keys)})",
        )
    if live_connections:
        return "HIGH", f"Active connection to LLM API: {', '.join(set(live_connections))}"
    if framework != "Unknown":
        return "MEDIUM", f"{framework} agent detected — run 'sentinel scan' for full analysis"
    return "UNKNOWN", "AI-related process detected — framework not identified"


# ── Network scanner (single host) ─────────────────────────────────────────────

def scan_network(
    host: str = "127.0.0.1",
    ports: list[int] | None = None,
    timeout: float = 0.5,
    extra_headers: dict[str, str] | None = None,
) -> list[DiscoveredAgent]:
    """Probe a single host's ports — confirms MCP via protocol handshake."""
    if ports is None:
        ports = _DEFAULT_PORTS

    open_ports = _find_open_ports(host, ports, timeout)
    if not open_ports:
        return []

    # SSE handshake needs much more time than a TCP connect — use a fixed floor
    # of 8 seconds regardless of the port-sweep timeout.
    handshake_timeout = max(timeout * 16, 8.0)

    found: list[DiscoveredAgent] = []
    with ThreadPoolExecutor(max_workers=min(10, len(open_ports))) as pool:
        futures = {
            pool.submit(_probe_mcp, host, port, handshake_timeout, extra_headers): port
            for port in open_ports
        }
        for future in as_completed(futures):
            agent = future.result()
            if agent:
                found.append(agent)
    return found


def _find_open_ports(host: str, ports: list[int], timeout: float) -> list[int]:
    """Fast parallel TCP connect to find open ports on a single host."""
    open_ports: list[int] = []

    def check(port: int) -> int | None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except (OSError, ConnectionRefusedError):
            return None

    with ThreadPoolExecutor(max_workers=min(50, len(ports))) as pool:
        for result in as_completed({pool.submit(check, p): p for p in ports}):
            r = result.result()
            if r is not None:
                open_ports.append(r)

    return sorted(open_ports)


# ── Subnet scanner (CIDR range) ───────────────────────────────────────────────

def enumerate_hosts(cidr: str) -> list[str]:
    """Expand a CIDR string into a list of usable host IP strings."""
    network = ipaddress.ip_network(cidr, strict=False)
    # For /31 and /32, include network address too (point-to-point / single host)
    if network.prefixlen >= 31:
        return [str(ip) for ip in network]
    return [str(ip) for ip in network.hosts()]


def scan_subnet(
    cidr: str,
    ports: list[int] | None = None,
    timeout: float = 0.3,
    extra_headers: dict[str, str] | None = None,
    on_progress: Optional[Callable[[int, int, str, str], None]] = None,
) -> tuple[list[DiscoveredAgent], SubnetScanStats]:
    """Scan every host in a CIDR subnet for MCP servers.

    Two phases:
      Phase 1 — parallel TCP connect across all host:port pairs (fast sweep)
      Phase 2 — MCP protocol handshake on every open port (targeted verification)

    A result in Phase 2 means the MCP initialize exchange completed — not just
    that a port was open.

    Args:
        cidr:         Network range, e.g. "10.0.0.0/24"
        ports:        Port list to probe (default: _DEFAULT_PORTS)
        timeout:      Per-connection TCP timeout in seconds
        extra_headers: HTTP headers for MCP handshake (auth tokens, etc.)
        on_progress:  Optional callback(completed, total, current_ip, phase)

    Returns:
        (agents, stats) tuple
    """
    import time

    if ports is None:
        ports = _DEFAULT_PORTS

    hosts = enumerate_hosts(cidr)
    if not hosts:
        raise ValueError(f"No usable hosts in {cidr}")

    if len(hosts) > _MAX_SUBNET_HOSTS_BLOCK:
        raise ValueError(
            f"{cidr} contains {len(hosts):,} hosts. "
            f"Maximum supported is {_MAX_SUBNET_HOSTS_BLOCK:,}. "
            "Use a smaller subnet or scan individual host ranges."
        )

    started_at = time.monotonic()
    total_probes = len(hosts) * len(ports)
    open_targets: list[tuple[str, int]] = []

    # ── Phase 1: parallel TCP connect ────────────────────────────────────────
    completed = 0
    workers = min(250, total_probes)

    def check_port(host: str, port: int) -> tuple[str, int] | None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return (host, port)
        except (OSError, ConnectionRefusedError, socket.timeout):
            return None

    tasks = [(h, p) for h in hosts for p in ports]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures_p1 = {pool.submit(check_port, h, p): (h, p) for h, p in tasks}
        for future in as_completed(futures_p1):
            result = future.result()
            if result:
                open_targets.append(result)
            completed += 1
            if on_progress:
                host_ip, _ = futures_p1[future]
                on_progress(completed, total_probes, host_ip, "1")

    # ── Phase 2: MCP protocol handshake on open ports ─────────────────────
    found: list[DiscoveredAgent] = []
    if open_targets:
        p2_workers = min(20, len(open_targets))
        with ThreadPoolExecutor(max_workers=p2_workers) as pool:
            futures_p2 = {
                pool.submit(_probe_mcp, h, p, timeout * 10, extra_headers): (h, p)
                for h, p in open_targets
            }
            p2_done = 0
            for future in as_completed(futures_p2):
                agent = future.result()
                if agent:
                    found.append(agent)
                p2_done += 1
                if on_progress:
                    h, p = futures_p2[future]
                    on_progress(p2_done, len(open_targets), f"{h}:{p}", "2")

    elapsed = time.monotonic() - started_at
    stats = SubnetScanStats(
        cidr=cidr,
        total_hosts=len(hosts),
        hosts_scanned=len(hosts),
        open_ports_found=len(open_targets),
        agents_found=len(found),
        elapsed_seconds=elapsed,
    )
    return found, stats


# ── MCP protocol prober ───────────────────────────────────────────────────────

def _auth_is_enforced(base: str, timeout: float) -> bool:
    """Return True only if the server actively rejects unauthenticated requests.

    Probes without credentials. McpAuthRequired (401/403) → enforced.
    Successful handshake → not enforced (server accepts anyone).
    Any other error → assume not enforced (conservative — don't hide risk).
    """
    from agentsentinel_cli.mcp_client import scan_http, McpAuthRequired, McpError
    try:
        scan_http(base, extra_headers=None, timeout=timeout)
        return False
    except McpAuthRequired:
        return True
    except (McpError, Exception):
        return False


def _probe_mcp(
    host: str,
    port: int,
    timeout: float,
    extra_headers: dict[str, str] | None = None,
) -> DiscoveredAgent | None:
    """Confirm a port is an MCP server by completing the initialize handshake.

    Tries streamable-HTTP (POST) first; falls back to SSE (GET /sse) automatically.
    A non-None return means the MCP protocol exchange succeeded or the server
    explicitly rejected us with 401/403 — both confirm an MCP server is present.
    """
    from agentsentinel_cli.mcp_client import scan_http, McpAuthRequired, McpError

    base = f"http://{host}:{port}"
    location = f"{host}:{port}"

    try:
        server = scan_http(base, extra_headers=extra_headers, timeout=timeout)
    except McpAuthRequired:
        # Server is MCP — it understood our handshake but requires credentials
        scan_url = f"{base}/sse" if True else base  # SSE is dominant transport
        return DiscoveredAgent(
            source="network",
            name=f"mcp-server@{location}",
            framework="MCP Server",
            provider="",
            model="",
            location=location,
            api_keys=[],
            live_connections=[],
            risk="MEDIUM",
            risk_reason="MCP server confirmed — authentication required, tools not enumerated",
            next_step=(
                f"sentinel mcp scan {base}/sse --auth-header 'Authorization: Bearer <token>'"
            ),
            tools=[],
            transport="",
        )
    except McpError:
        return None
    except Exception:
        return None

    # Handshake succeeded — assess risk based on actual tool content and whether
    # the server actually enforces authentication.
    tool_names = [t.name for t in server.tools]
    has_dangerous = any(t.is_dangerous for t in server.tools)
    has_write = any(t.scope == "write" for t in server.tools)

    # When credentials were provided, verify the server actually requires them.
    # If it accepts a probe WITHOUT credentials too, auth is not enforced — the
    # server is still open to anyone and the risk doesn't change.
    auth_enforced = False
    if extra_headers:
        auth_enforced = _auth_is_enforced(base, timeout)

    if not extra_headers or not auth_enforced:
        if has_dangerous or has_write:
            risk = "CRITICAL"
            bad = ", ".join(t.name for t in server.tools if t.is_dangerous or t.scope == "write")
            risk_reason = f"Unauthenticated MCP server with dangerous/write tools: {bad}"
        else:
            n = len(server.tools)
            risk = "HIGH"
            risk_reason = (
                f"Unauthenticated MCP server — {n} tool{'s' if n != 1 else ''} publicly accessible"
            )
    else:
        n = len(server.tools)
        risk = "LOW"
        risk_reason = f"MCP server (auth enforced) — {n} tool{'s' if n != 1 else ''} enumerated"

    scan_url = f"{base}/sse" if server.transport == "sse" else base
    auth_flag = (
        f" --auth-header '{next(iter(extra_headers.items()))[0]}: ...'"
        if extra_headers else ""
    )

    return DiscoveredAgent(
        source="network",
        name=server.name if server.name != "unknown" else f"mcp-server@{location}",
        framework=f"MCP Server ({server.transport.upper()})",
        provider="",
        model="",
        location=location,
        api_keys=[],
        live_connections=[],
        risk=risk,
        risk_reason=risk_reason,
        next_step=f"sentinel mcp scan {scan_url}{auth_flag}",
        tools=tool_names,
        transport=server.transport,
    )


# ── Docker scanner ────────────────────────────────────────────────────────────

def scan_docker() -> list[DiscoveredAgent]:
    """Find running Docker containers that look like AI agents."""
    if not _docker_available():
        return []

    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    found: list[DiscoveredAgent] = []

    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        try:
            container = json.loads(line)
            container_id = container.get("ID", "")
            container_name = container.get("Names", "unknown").lstrip("/")
            image = container.get("Image", "")

            env = _docker_inspect_env(container_id)
            if not env:
                continue

            has_llm_env = any(var in env for var in LLM_ENV_VARS)
            if not has_llm_env:
                framework, provider = detect_framework(image)
                if framework == "Unknown":
                    continue
            else:
                full_text = " ".join([image, container_name, " ".join(env.values())])
                framework, provider = detect_framework(full_text)

            api_keys = extract_api_keys(env)
            model = detect_model(" ".join(env.values()))
            provider = provider or detect_provider_from_env(env)
            risk, risk_reason = _assess_process_risk(api_keys, [], framework)

            found.append(DiscoveredAgent(
                source="docker",
                name=container_name,
                framework=framework,
                provider=provider,
                model=model,
                location=f"container:{container_name}",
                api_keys=api_keys,
                live_connections=[],
                risk=risk,
                risk_reason=risk_reason,
                next_step=f"docker exec {container_name} sentinel scan .",
            ))

        except (json.JSONDecodeError, KeyError):
            continue

    return found


def _docker_available() -> bool:
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _docker_inspect_env(container_id: str) -> dict[str, str]:
    import re
    # Container IDs are 64-char hex (full) or 12-char hex (short) — nothing else
    if not re.fullmatch(r"[a-f0-9]{12}([a-f0-9]{52})?", container_id):
        return {}
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format",
             "{{range .Config.Env}}{{.}}\n{{end}}", container_id],
            capture_output=True, text=True, timeout=10,
        )
        env: dict[str, str] = {}
        for line in result.stdout.strip().splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()
        return env
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_discovery(
    do_process: bool = True,
    do_network: bool = True,
    do_docker: bool = False,
    ports: list[int] | None = None,
    subnet: Optional[str] = None,
    extra_headers: dict[str, str] | None = None,
    subnet_progress_cb: Optional[Callable[[int, int, str, str], None]] = None,
) -> tuple[list[DiscoveredAgent], Optional[SubnetScanStats]]:
    """Run all requested discovery scanners.

    Returns (agents, subnet_stats). subnet_stats is None when no subnet scan ran.
    """
    results: list[DiscoveredAgent] = []
    subnet_stats: Optional[SubnetScanStats] = None

    if do_process:
        results.extend(scan_processes())

    if do_network:
        results.extend(scan_network(ports=ports, extra_headers=extra_headers))

    if subnet:
        agents, subnet_stats = scan_subnet(
            cidr=subnet,
            ports=ports,
            extra_headers=extra_headers,
            on_progress=subnet_progress_cb,
        )
        results.extend(agents)

    if do_docker:
        results.extend(scan_docker())

    return results, subnet_stats


# ── JSON serialisation ────────────────────────────────────────────────────────

def as_json(agents: list[DiscoveredAgent]) -> str:
    return json.dumps(
        [dataclasses.asdict(a) for a in agents],
        indent=2,
    )

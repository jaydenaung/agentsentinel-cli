"""Security rules for host AI security posture audits.

Each rule maps to one OWASP category or an AI-specific risk.
Rules operate on HostContext and return HostFinding(s) or None.
"""

import dataclasses
import os
from pathlib import Path

from agentsentinel_cli.host_scanner import HostContext, McpServerConfig


@dataclasses.dataclass
class HostFinding:
    """A security finding from a host posture audit."""
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW
    rule_id: str
    category: str      # permissions | data_exposure | config | system | network
    message: str
    detail: str = ""
    remediation: str = ""


# ── Helpers ───────────────────────────────────────────────────────────────────

_HOME = str(Path.home())

# Tool names in Claude Code allowedTools that bypass the confirmation prompt
_SHELL_TOOL_NAMES = frozenset({
    "bash", "computer", "shell", "terminal",
})

# Broad filesystem paths — entire home dir or root gives unrestricted file access
_BROAD_PATHS = frozenset({
    "/", "/home", "/Users", "~", _HOME, _HOME + "/",
})

# Sensitive directories that AI tools should not be granted blanket access to
_SENSITIVE_DIRS = frozenset({
    os.path.join(_HOME, ".ssh"),
    os.path.join(_HOME, ".aws"),
    os.path.join(_HOME, ".gnupg"),
    os.path.join(_HOME, ".kube"),
    os.path.join(_HOME, "Library", "Keychains"),
    os.path.join(_HOME, "Library", "Application Support", "1Password"),
    os.path.join(_HOME, ".config"),
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.kube",
})


def _is_broad_path(path: str) -> bool:
    expanded = path.replace("~", _HOME).rstrip("/")
    return expanded in {p.rstrip("/") for p in _BROAD_PATHS}


def _is_sensitive_path(path: str) -> bool:
    expanded = path.replace("~", _HOME).rstrip("/")
    return any(expanded.startswith(s.rstrip("/")) for s in _SENSITIVE_DIRS)


def _all_mcp_servers(ctx: HostContext) -> list[McpServerConfig]:
    servers: list[McpServerConfig] = []
    if ctx.claude_code:
        servers.extend(ctx.claude_code.mcp_servers)
    if ctx.claude_desktop:
        servers.extend(ctx.claude_desktop.mcp_servers)
    for vc in ctx.vendor_configs:
        servers.extend(vc.mcp_servers)
    return servers


# ── Rules ─────────────────────────────────────────────────────────────────────

def _rule_shell_unrestricted(ctx: HostContext) -> HostFinding | None:
    """CRITICAL: Claude Code allowedTools includes shell/bash — skips confirmation prompt."""
    if not ctx.claude_code:
        return None
    shell_tools = [t for t in ctx.claude_code.allowed_tools if t.lower() in _SHELL_TOOL_NAMES]
    if not shell_tools:
        return None
    return HostFinding(
        severity="CRITICAL",
        rule_id="HOST_SHELL_UNRESTRICTED",
        category="config",
        message=(
            "Claude Code has shell execution in allowedTools — "
            "Bash runs without the confirmation prompt. "
            "Prompt injection or a compromised MCP server can execute arbitrary OS commands silently."
        ),
        detail=f"Auto-approved tools: {', '.join(shell_tools)}",
        remediation=(
            "Remove shell tools from allowedTools in ~/.claude/settings.json. "
            "Claude can still run shell commands but will always ask for confirmation first."
        ),
    )


def _rule_sip_disabled(ctx: HostContext) -> HostFinding | None:
    """CRITICAL: macOS System Integrity Protection is off."""
    if ctx.sip_enabled is not False:
        return None
    return HostFinding(
        severity="CRITICAL",
        rule_id="HOST_SIP_DISABLED",
        category="system",
        message=(
            "System Integrity Protection (SIP) is disabled. "
            "SIP prevents code from modifying protected OS directories. "
            "A compromised AI process or MCP server can tamper with system binaries."
        ),
        detail="csrutil status: disabled",
        remediation=(
            "Boot into macOS Recovery (hold ⌘R on startup) and run: csrutil enable. "
            "SIP can be re-enabled without data loss."
        ),
    )


def _rule_api_key_in_shell(ctx: HostContext) -> HostFinding | None:
    """HIGH: AI API keys hardcoded in shell config files."""
    if not ctx.shell_key_findings:
        return None
    files = sorted({f for _, f, _ in ctx.shell_key_findings})
    key_types = sorted({k for k, _, _ in ctx.shell_key_findings})
    examples = "; ".join(
        f"{k}: {s}" for k, _, s in ctx.shell_key_findings[:3]
    )
    return HostFinding(
        severity="HIGH",
        rule_id="HOST_API_KEY_IN_SHELL",
        category="data_exposure",
        message=(
            "AI API keys are hardcoded in shell config files. "
            "Every process that inherits your shell — including AI agents and MCP servers — "
            "can read these keys and make API calls on your behalf."
        ),
        detail=f"Keys: {', '.join(key_types)} — in: {', '.join(files)}\n{examples}",
        remediation=(
            "Move API keys out of shell configs. Use direnv (.envrc per project), "
            "macOS Keychain, or a secrets manager like 1Password CLI. "
            "Never export AI keys globally."
        ),
    )


def _rule_mcp_exfil_path(ctx: HostContext) -> HostFinding | None:
    """HIGH: MCP server has both filesystem access and network capability — exfiltration path."""
    risky = [
        srv for srv in _all_mcp_servers(ctx)
        if srv.filesystem_paths and srv.has_network_access
    ]
    if not risky:
        return None
    names = ", ".join(s.name for s in risky)
    detail_parts = [f"{s.name} (paths: {', '.join(s.filesystem_paths[:2])})" for s in risky[:3]]
    return HostFinding(
        severity="HIGH",
        rule_id="HOST_MCP_EXFIL_PATH",
        category="config",
        message=(
            "One or more MCP servers have both filesystem read access and network capability. "
            "Prompt injection can chain these into a data exfiltration path: "
            "read local files, then send them to an attacker-controlled endpoint."
        ),
        detail=f"At-risk servers: {'; '.join(detail_parts)}",
        remediation=(
            "Use dedicated single-purpose MCP servers: one for filesystem, one for network. "
            "Never grant both capabilities to the same server."
        ),
    )


def _rule_full_disk_access(ctx: HostContext) -> HostFinding | None:
    """HIGH: an AI app or terminal used for AI has Full Disk Access (TCC)."""
    fda = [
        p for p in ctx.tcc_permissions
        if p.service == "full_disk_access" and p.granted
    ]
    if not fda:
        return None
    apps = ", ".join(p.app_name for p in fda)
    return HostFinding(
        severity="HIGH",
        rule_id="HOST_FDA_AI_APP",
        category="permissions",
        message=(
            "An AI application or terminal used for AI work has Full Disk Access. "
            "This grants read access to all files on this Mac — SSH keys, browser profiles, "
            "Keychain exports, cloud credentials, and conversation history."
        ),
        detail=f"Apps with FDA: {apps}",
        remediation=(
            "In System Settings → Privacy & Security → Full Disk Access, "
            "revoke FDA from any app that doesn't strictly require it. "
            "Most AI tools work without FDA."
        ),
    )


def _rule_screen_recording(ctx: HostContext) -> HostFinding | None:
    """HIGH: AI app has Screen Recording permission."""
    sr = [
        p for p in ctx.tcc_permissions
        if p.service == "screen_recording" and p.granted
        and any(ai in p.bundle_id.lower() for ai in {"claude", "anthropic", "openai", "cursor"})
    ]
    if not sr:
        return None
    apps = ", ".join(p.app_name for p in sr)
    return HostFinding(
        severity="HIGH",
        rule_id="HOST_SCREEN_RECORDING_AI",
        category="permissions",
        message=(
            "An AI application has Screen Recording permission. "
            "This allows capturing your entire screen including passwords typed in other apps, "
            "private messages, and sensitive documents visible on screen."
        ),
        detail=f"Apps with Screen Recording: {apps}",
        remediation=(
            "In System Settings → Privacy & Security → Screen Recording, "
            "revoke access for any AI app that doesn't use computer-use features you've enabled."
        ),
    )


def _rule_ai_process_exposed(ctx: HostContext) -> HostFinding | None:
    """HIGH: AI-related process is listening on a non-localhost network interface."""
    if not ctx.exposed_processes:
        return None
    parts = [f"{p.name} (PID {p.pid}) on {p.address}:{p.port}" for p in ctx.exposed_processes[:4]]
    return HostFinding(
        severity="HIGH",
        rule_id="HOST_AI_PROCESS_EXPOSED",
        category="network",
        message=(
            "An AI-related process is listening on a non-localhost interface. "
            "Any host on the local network can connect to and interact with this service, "
            "potentially invoking tools or injecting prompts."
        ),
        detail=f"Exposed: {'; '.join(parts)}",
        remediation=(
            "Bind AI services to 127.0.0.1 only. "
            "If remote access is required, use a VPN or SSH tunnel with authentication."
        ),
    )


def _rule_filevault_off(ctx: HostContext) -> HostFinding | None:
    """HIGH: FileVault disk encryption is off."""
    if ctx.filevault_enabled is not False:
        return None
    return HostFinding(
        severity="HIGH",
        rule_id="HOST_FILEVAULT_OFF",
        category="system",
        message=(
            "FileVault disk encryption is disabled. "
            "AI tools store API keys, conversation memory, and tool outputs locally. "
            "Without encryption, all of this data is readable if the disk is ever physically accessed."
        ),
        detail="fdesetup status: FileVault is Off",
        remediation=(
            "Enable FileVault in System Settings → Privacy & Security → FileVault. "
            "Encryption runs in the background and does not require downtime."
        ),
    )


def _rule_accessibility(ctx: HostContext) -> HostFinding | None:
    """MEDIUM: AI app has Accessibility permission (can read all UI text + simulate input)."""
    acc = [
        p for p in ctx.tcc_permissions
        if p.service == "accessibility" and p.granted
        and any(ai in p.bundle_id.lower() for ai in {"claude", "anthropic", "openai", "cursor"})
    ]
    if not acc:
        return None
    apps = ", ".join(p.app_name for p in acc)
    return HostFinding(
        severity="MEDIUM",
        rule_id="HOST_ACCESSIBILITY_AI",
        category="permissions",
        message=(
            "An AI application has Accessibility permission. "
            "This allows reading text from all open windows, intercepting keystrokes, "
            "and simulating mouse/keyboard input in any other application."
        ),
        detail=f"Apps with Accessibility: {apps}",
        remediation=(
            "In System Settings → Privacy & Security → Accessibility, "
            "revoke access for any AI app unless you intentionally use computer-use features."
        ),
    )


def _rule_hooks_shell(ctx: HostContext) -> HostFinding | None:
    """MEDIUM: Claude Code hooks execute shell commands on every matching event."""
    if not ctx.claude_code:
        return None
    cmd_hooks = [h for h in ctx.claude_code.hooks if h.get("type") == "command"]
    if not cmd_hooks:
        return None
    samples = [h.get("command", "")[:60] for h in cmd_hooks[:3]]
    return HostFinding(
        severity="MEDIUM",
        rule_id="HOST_HOOKS_SHELL",
        category="config",
        message=(
            f"{len(cmd_hooks)} shell command hook(s) run automatically on matching Claude Code events. "
            "If a hook command embeds any Claude output or tool result, "
            "a malicious tool response can inject OS commands."
        ),
        detail=f"Hook commands: {'; '.join(samples)}{'…' if len(cmd_hooks) > 3 else ''}",
        remediation=(
            "Audit every hook in ~/.claude/settings.json. "
            "Hooks must never interpolate Claude output or tool results into shell commands."
        ),
    )


def _rule_broad_filesystem(ctx: HostContext) -> HostFinding | None:
    """MEDIUM: MCP server is configured with home-dir or root-level filesystem path."""
    broad = [
        (s.name, p)
        for s in _all_mcp_servers(ctx)
        for p in s.filesystem_paths
        if _is_broad_path(p)
    ]
    if not broad:
        return None
    detail = "; ".join(f"{name}: {path}" for name, path in broad[:4])
    return HostFinding(
        severity="MEDIUM",
        rule_id="HOST_MCP_BROAD_FS",
        category="config",
        message=(
            "One or more MCP servers are configured with broad filesystem paths (home dir or /). "
            "Prompt injection can instruct them to read or enumerate sensitive files "
            "anywhere on the system."
        ),
        detail=f"Broad paths: {detail}",
        remediation=(
            "Restrict each MCP server to the specific project directories it needs. "
            "Pass paths like ~/code/project instead of ~/ or /."
        ),
    )


def _rule_sensitive_path(ctx: HostContext) -> HostFinding | None:
    """MEDIUM: MCP server is configured with access to a sensitive directory."""
    sensitive = [
        (s.name, p)
        for s in _all_mcp_servers(ctx)
        for p in s.filesystem_paths
        if _is_sensitive_path(p)
    ]
    if not sensitive:
        return None
    detail = "; ".join(f"{name}: {path}" for name, path in sensitive[:4])
    return HostFinding(
        severity="MEDIUM",
        rule_id="HOST_MCP_SENSITIVE_PATH",
        category="config",
        message=(
            "An MCP server has access to a sensitive directory "
            "(SSH keys, AWS credentials, Kubernetes config, or Keychain). "
            "A compromised or prompt-injected MCP server can read and exfiltrate these credentials."
        ),
        detail=f"Sensitive paths: {detail}",
        remediation=(
            "Remove credential directories from MCP server paths. "
            "These directories contain secrets that should never be accessible to an AI tool."
        ),
    )


def _rule_many_mcp_servers(ctx: HostContext) -> HostFinding | None:
    """MEDIUM: large number of MCP servers across all AI tools expands the attack surface."""
    seen: set[str] = set()
    unique = []
    for s in _all_mcp_servers(ctx):
        if s.name not in seen:
            seen.add(s.name)
            unique.append(s)
    if len(unique) < 8:
        return None
    names = ", ".join(s.name for s in unique[:6])
    tools: list[str] = []
    if ctx.claude_code:
        tools.append("Claude Code")
    if ctx.claude_desktop:
        tools.append("Claude Desktop")
    tools.extend(vc.display_name for vc in ctx.vendor_configs)
    tool_str = ", ".join(tools) if tools else "your AI tools"
    return HostFinding(
        severity="MEDIUM",
        rule_id="HOST_MANY_MCP_SERVERS",
        category="config",
        message=(
            f"{len(unique)} MCP servers are configured across {tool_str}. "
            "Each server is an independent prompt injection entry point. "
            "The more servers installed, the larger the blast radius of a single compromise."
        ),
        detail=f"Servers: {names}{'…' if len(unique) > 6 else ''}",
        remediation=(
            "Remove MCP servers you do not actively use across all AI tools. "
            "Review each server's capabilities and remove any that duplicate functionality."
        ),
    )


def _rule_gatekeeper_off(ctx: HostContext) -> HostFinding | None:
    """MEDIUM: Gatekeeper is disabled — unsigned apps run without warning."""
    if ctx.gatekeeper_enabled is not False:
        return None
    return HostFinding(
        severity="MEDIUM",
        rule_id="HOST_GATEKEEPER_OFF",
        category="system",
        message=(
            "Gatekeeper is disabled. macOS will run unsigned or unnotarized binaries without warning. "
            "MCP server packages installed via npm or pip could silently include malicious code "
            "that would otherwise be blocked."
        ),
        detail="spctl --status: assessments disabled",
        remediation="Re-enable Gatekeeper: sudo spctl --master-enable",
    )


def _rule_large_memory(ctx: HostContext) -> HostFinding | None:
    """LOW: large conversation memory files accumulate sensitive data over time."""
    _MB = 1024 * 1024
    if ctx.memory_total_bytes <= 50 * _MB:
        return None
    size_mb = ctx.memory_total_bytes / _MB
    return HostFinding(
        severity="LOW",
        rule_id="HOST_LARGE_MEMORY",
        category="data_exposure",
        message=(
            f"Claude Code memory files total {size_mb:.1f} MB across {ctx.memory_file_count} files. "
            "Memory files accumulate conversation history, tool outputs, and any data Claude has seen. "
            "A filesystem-capable MCP server could read and exfiltrate all of it."
        ),
        detail=f"~/.claude/projects/: {ctx.memory_file_count} files, {size_mb:.1f} MB",
        remediation=(
            "Run 'sentinel secrets ~/.claude/projects/' to check for sensitive data. "
            "Periodically clear old projects: rm -rf ~/.claude/projects/old-project/."
        ),
    )


# ── Rule runner ───────────────────────────────────────────────────────────────

_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}

_ALL_RULES = [
    # CRITICAL
    _rule_shell_unrestricted,
    _rule_sip_disabled,
    # HIGH
    _rule_api_key_in_shell,
    _rule_mcp_exfil_path,
    _rule_full_disk_access,
    _rule_screen_recording,
    _rule_ai_process_exposed,
    _rule_filevault_off,
    # MEDIUM
    _rule_accessibility,
    _rule_hooks_shell,
    _rule_broad_filesystem,
    _rule_sensitive_path,
    _rule_many_mcp_servers,
    _rule_gatekeeper_off,
    # LOW
    _rule_large_memory,
]


def run_host_rules(ctx: HostContext) -> list[HostFinding]:
    """Run all host posture rules and return deduplicated findings."""
    findings: list[HostFinding] = []
    seen: set[str] = set()
    for rule_fn in _ALL_RULES:
        result = rule_fn(ctx)
        if result and result.rule_id not in seen:
            findings.append(result)
            seen.add(result.rule_id)
    return findings


def host_posture_score(findings: list[HostFinding]) -> int:
    """0–100 posture score — same deduction weights as other sentinel commands."""
    deductions = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return max(0, 100 - deductions)

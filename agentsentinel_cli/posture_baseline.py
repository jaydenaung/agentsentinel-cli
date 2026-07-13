"""Recommended-configuration baseline and gap analysis for Claude Code / Desktop.

Unlike host_rules.py (which flags individual issues), this module answers a
different question: "what should my Claude config look like, and how far off
am I?" It reuses the same detection helpers as host_rules.py rather than
reimplementing path/tool-name logic.
"""

import dataclasses

from agentsentinel_cli.host_rules import (
    _SHELL_TOOL_NAMES,
    _all_mcp_servers,
    _is_broad_path,
    _is_sensitive_path,
)
from agentsentinel_cli.host_scanner import HostContext

_DESTRUCTIVE_PATTERNS = ["rm -rf", "git push --force", "git push -f", "sudo"]

_MCP_SERVER_THRESHOLD = 8


@dataclasses.dataclass
class PostureGapItem:
    """One deviation between the current Claude config and the recommended baseline."""
    key: str
    description: str
    current: str
    recommended: str
    risk: str
    fix: str


def _gap_shell_tools(ctx: HostContext) -> PostureGapItem | None:
    if not ctx.claude_code:
        return None
    shell_tools = [t for t in ctx.claude_code.allowed_tools if t.lower() in _SHELL_TOOL_NAMES]
    if not shell_tools:
        return None
    return PostureGapItem(
        key="allowedTools.shell",
        description="Shell tools in allowedTools",
        current=", ".join(shell_tools),
        recommended="(none)",
        risk="Bash runs without confirmation — a prompt injection or compromised "
             "MCP server can execute arbitrary OS commands silently.",
        fix="Remove shell tools from allowedTools in ~/.claude/settings.json.",
    )


def _gap_broad_mcp_paths(ctx: HostContext) -> PostureGapItem | None:
    broad = [
        f"{s.name}:{p}" for s in _all_mcp_servers(ctx) for p in s.filesystem_paths
        if _is_broad_path(p)
    ]
    if not broad:
        return None
    return PostureGapItem(
        key="mcp.filesystem_paths.broad",
        description="MCP server filesystem scope",
        current=", ".join(broad[:4]),
        recommended="scoped to specific project directories",
        risk="A prompt-injected MCP server can read or enumerate any file "
             "on the system, not just the intended project.",
        fix="Restrict each MCP server's filesystem path to the project directory it needs.",
    )


def _gap_sensitive_mcp_paths(ctx: HostContext) -> PostureGapItem | None:
    sensitive = [
        f"{s.name}:{p}" for s in _all_mcp_servers(ctx) for p in s.filesystem_paths
        if _is_sensitive_path(p)
    ]
    if not sensitive:
        return None
    return PostureGapItem(
        key="mcp.filesystem_paths.sensitive",
        description="MCP server access to credential directories",
        current=", ".join(sensitive[:4]),
        recommended="no access to .ssh, .aws, .gnupg, .kube, or Keychain paths",
        risk="A compromised or prompt-injected MCP server can read and "
             "exfiltrate SSH keys, cloud credentials, or Keychain exports.",
        fix="Remove credential directories from MCP server filesystem paths.",
    )


def _gap_mcp_exfil(ctx: HostContext) -> PostureGapItem | None:
    risky = [s.name for s in _all_mcp_servers(ctx) if s.filesystem_paths and s.has_network_access]
    if not risky:
        return None
    return PostureGapItem(
        key="mcp.fs_plus_network",
        description="MCP servers combining filesystem + network access",
        current=", ".join(risky),
        recommended="single-purpose servers: filesystem-only or network-only, never both",
        risk="Prompt injection can chain filesystem read + network send into a "
             "data exfiltration path.",
        fix="Split filesystem and network capability across separate MCP servers.",
    )


def _gap_disallowed_destructive(ctx: HostContext) -> PostureGapItem | None:
    if not ctx.claude_code:
        return None
    disallowed_str = " ".join(ctx.claude_code.disallowed_tools).lower()
    missing = [p for p in _DESTRUCTIVE_PATTERNS if p not in disallowed_str]
    if not missing:
        return None
    return PostureGapItem(
        key="disallowedTools.destructive",
        description="Destructive command patterns not explicitly denied",
        current=", ".join(ctx.claude_code.disallowed_tools) or "(empty)",
        recommended=f"deny patterns for: {', '.join(_DESTRUCTIVE_PATTERNS)}",
        risk="Without an explicit deny, a confused or prompt-injected session "
             "can run destructive commands (force-push, recursive delete, sudo) "
             "as long as the confirmation prompt is accepted.",
        fix="Add deny entries to disallowedTools in ~/.claude/settings.json "
             "for rm -rf, git push --force, and sudo.",
    )


def _gap_unreviewed_hooks(ctx: HostContext) -> PostureGapItem | None:
    if not ctx.claude_code:
        return None
    cmd_hooks = [h for h in ctx.claude_code.hooks if h.get("type") == "command"]
    if not cmd_hooks:
        return None
    return PostureGapItem(
        key="hooks.command",
        description="Shell command hooks configured",
        current=f"{len(cmd_hooks)} command hook(s)",
        recommended="hooks audited to confirm no Claude output/tool result is "
                     "interpolated into the shell command",
        risk="A hook that embeds tool output or Claude's response in a shell "
             "command is a command-injection path if that content is attacker-influenced.",
        fix="Review each hook in ~/.claude/settings.json for unsafe interpolation.",
    )


def _gap_mcp_sprawl(ctx: HostContext) -> PostureGapItem | None:
    seen: set[str] = set()
    for s in _all_mcp_servers(ctx):
        seen.add(s.name)
    if len(seen) < _MCP_SERVER_THRESHOLD:
        return None
    return PostureGapItem(
        key="mcp.server_count",
        description="Total MCP servers across all Claude surfaces",
        current=str(len(seen)),
        recommended=f"fewer than {_MCP_SERVER_THRESHOLD}",
        risk="Each MCP server is an independent prompt-injection entry point; "
             "unused servers only add attack surface.",
        fix="Remove MCP servers that are not actively used.",
    )


_ALL_GAP_CHECKS = [
    _gap_shell_tools,
    _gap_disallowed_destructive,
    _gap_broad_mcp_paths,
    _gap_sensitive_mcp_paths,
    _gap_mcp_exfil,
    _gap_unreviewed_hooks,
    _gap_mcp_sprawl,
]


def compute_posture_gaps(ctx: HostContext) -> list[PostureGapItem]:
    """Return the deltas between the current Claude config and the recommended baseline."""
    gaps: list[PostureGapItem] = []
    for check in _ALL_GAP_CHECKS:
        result = check(ctx)
        if result:
            gaps.append(result)
    return gaps


def recommended_settings_snippet(ctx: HostContext) -> dict | None:
    """Suggested allowedTools/disallowedTools for ~/.claude/settings.json, or None if
    no Claude Code config was found or nothing needs to change."""
    if not ctx.claude_code:
        return None

    allowed = [t for t in ctx.claude_code.allowed_tools if t.lower() not in _SHELL_TOOL_NAMES]
    disallowed_str = " ".join(ctx.claude_code.disallowed_tools).lower()
    missing_patterns = [p for p in _DESTRUCTIVE_PATTERNS if p not in disallowed_str]
    disallowed = list(ctx.claude_code.disallowed_tools) + [
        f"Bash({p}:*)" for p in missing_patterns
    ]

    if allowed == ctx.claude_code.allowed_tools and not missing_patterns:
        return None

    return {"allowedTools": allowed, "disallowedTools": disallowed}

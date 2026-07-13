"""Security rules for Claude Code session-audit.

Unlike host_rules.py (which checks static config), these rules operate on
what actually happened during a session — commands run, files touched,
permission mode used — parsed from session transcripts by session_scanner.py.
"""

import dataclasses

from agentsentinel_cli.host_rules import _is_sensitive_path
from agentsentinel_cli.posture_baseline import _DESTRUCTIVE_PATTERNS
from agentsentinel_cli.session_scanner import SessionInfo

_DENIAL_RATE_THRESHOLD = 5


@dataclasses.dataclass
class SessionFinding:
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW
    rule_id: str
    category: str      # permissions | data_exposure | config
    message: str
    detail: str = ""
    remediation: str = ""


def _rule_bypass_mode(sessions: list[SessionInfo]) -> SessionFinding | None:
    """HIGH: one or more sessions ran with permissions fully bypassed."""
    hits = [s for s in sessions if "bypassPermissions" in s.permission_modes]
    if not hits:
        return None
    ids = ", ".join(s.session_id[:8] for s in hits[:5])
    return SessionFinding(
        severity="HIGH",
        rule_id="SESSION_BYPASS_MODE",
        category="permissions",
        message=(
            f"{len(hits)} session(s) ran in bypassPermissions mode — every tool call, "
            "including Bash, Write, and Edit, executed with no confirmation prompt at all."
        ),
        detail=f"Sessions: {ids}{'…' if len(hits) > 5 else ''}",
        remediation=(
            "Reserve bypassPermissions for sandboxed/disposable environments only. "
            "Use the default or acceptEdits permission mode for anything touching real credentials or production systems."
        ),
    )


def _rule_risky_command_executed(sessions: list[SessionInfo]) -> SessionFinding | None:
    """HIGH: a destructive command pattern was actually run, not just hypothetically allowed."""
    hits: list[tuple[str, str]] = []
    for s in sessions:
        for cmd in s.bash_commands:
            cmd_lower = cmd.lower()
            if any(p in cmd_lower for p in _DESTRUCTIVE_PATTERNS):
                hits.append((s.session_id[:8], cmd[:80]))
    if not hits:
        return None
    detail = "; ".join(f"{sid}: {cmd}" for sid, cmd in hits[:5])
    return SessionFinding(
        severity="HIGH",
        rule_id="SESSION_RISKY_COMMAND_EXECUTED",
        category="config",
        message=(
            f"{len(hits)} destructive command(s) were actually executed in past sessions "
            "(rm -rf, git push --force, or sudo) — this is a real occurrence, not a config risk."
        ),
        detail=f"{detail}{'…' if len(hits) > 5 else ''}",
        remediation=(
            "Review these commands for intent. If unintentional, add deny patterns to "
            "permissions.deny in ~/.claude/settings.json (see 'sentinel host-scan --baseline')."
        ),
    )


def _rule_sensitive_path_touched(sessions: list[SessionInfo]) -> SessionFinding | None:
    """HIGH: a session read, wrote, or edited a credential/sensitive path."""
    hits: list[tuple[str, str, str]] = []
    for s in sessions:
        for tool, path in s.file_paths_touched:
            if _is_sensitive_path(path):
                hits.append((s.session_id[:8], tool, path))
    if not hits:
        return None
    detail = "; ".join(f"{sid} {tool}: {path}" for sid, tool, path in hits[:5])
    return SessionFinding(
        severity="HIGH",
        rule_id="SESSION_SENSITIVE_PATH_TOUCHED",
        category="data_exposure",
        message=(
            "A session accessed a credential or sensitive directory "
            "(SSH keys, AWS/cloud config, Keychain, etc.) via Read, Write, or Edit."
        ),
        detail=f"{detail}{'…' if len(hits) > 5 else ''}",
        remediation=(
            "Confirm this access was intentional. Add explicit permissions.deny rules "
            "(e.g. Read(~/.ssh/**)) if the assistant should never touch these paths."
        ),
    )


def _rule_out_of_project_write(sessions: list[SessionInfo]) -> SessionFinding | None:
    """MEDIUM: a Write/Edit landed outside the session's own project directory."""
    hits: list[tuple[str, str, str]] = []
    for s in sessions:
        if not s.project_cwd:
            continue
        for tool, path in s.file_paths_touched:
            if tool not in ("Write", "Edit"):
                continue
            if not path.startswith(s.project_cwd):
                hits.append((s.session_id[:8], tool, path))
    if not hits:
        return None
    detail = "; ".join(f"{sid} {tool}: {path}" for sid, tool, path in hits[:5])
    return SessionFinding(
        severity="MEDIUM",
        rule_id="SESSION_OUT_OF_PROJECT_WRITE",
        category="config",
        message=(
            "A session wrote or edited a file outside its own project directory — "
            "scope creep beyond the working project, worth confirming was intentional."
        ),
        detail=f"{detail}{'…' if len(hits) > 5 else ''}",
        remediation="Review these writes; scope MCP/tool permissions to the project directory if unintended.",
    )


def _rule_high_denial_rate(sessions: list[SessionInfo]) -> SessionFinding | None:
    """LOW: informational — a session hit an unusually high number of permission denials."""
    hits = [s for s in sessions if len(s.denials) >= _DENIAL_RATE_THRESHOLD]
    if not hits:
        return None
    detail = "; ".join(f"{s.session_id[:8]}: {len(s.denials)} denials" for s in hits[:5])
    return SessionFinding(
        severity="LOW",
        rule_id="SESSION_HIGH_DENIAL_RATE",
        category="permissions",
        message=(
            f"{len(hits)} session(s) hit {_DENIAL_RATE_THRESHOLD}+ permission denials — "
            "either the assistant repeatedly attempted something denied, or the config "
            "is creating friction for legitimate work."
        ),
        detail=f"{detail}{'…' if len(hits) > 5 else ''}",
        remediation="Review denied attempts in the session table; tune permissions.allow if they were legitimate.",
    )


_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}

_ALL_RULES = [
    _rule_bypass_mode,
    _rule_risky_command_executed,
    _rule_sensitive_path_touched,
    _rule_out_of_project_write,
    _rule_high_denial_rate,
]


def run_session_rules(sessions: list[SessionInfo]) -> list[SessionFinding]:
    findings: list[SessionFinding] = []
    seen: set[str] = set()
    for rule_fn in _ALL_RULES:
        result = rule_fn(sessions)
        if result and result.rule_id not in seen:
            findings.append(result)
            seen.add(result.rule_id)
    return findings


def session_posture_score(findings: list[SessionFinding]) -> int:
    deductions = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return max(0, 100 - deductions)

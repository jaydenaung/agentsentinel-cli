"""Security rules for Claude Code session-audit.

Unlike host_rules.py (which checks static config), these rules operate on
what actually happened during a session — commands run, files touched,
permission mode used — parsed from session transcripts by session_scanner.py.
"""

import dataclasses
import fnmatch
import re
import shlex
from pathlib import Path, PurePosixPath, PureWindowsPath

from agentsentinel_cli.host_rules import _is_broad_path, _is_sensitive_path
from agentsentinel_cli.posture_baseline import _DESTRUCTIVE_PATTERNS
from agentsentinel_cli.session_scanner import SessionInfo

_DENIAL_RATE_THRESHOLD = 5

# Word-boundary regexes for destructive patterns — a plain substring check
# would false-positive on "pseudocode", "sudoku", etc.
_DESTRUCTIVE_REGEXES = [
    (p, re.compile(r"(?<![\w./-])" + re.escape(p) + r"(?![\w-])", re.IGNORECASE))
    for p in _DESTRUCTIVE_PATTERNS
]

_RM_RF_TARGETS_RE = re.compile(r"\brm\s+-rf\s+([^;&|]+)", re.IGNORECASE)

# Build-artifact directory/file names routinely recreated during normal
# development — flagging every "rm -rf dist/" as a HIGH security finding is
# what actually happens in real usage (verified: 100% of rm -rf hits in early
# testing were exactly this), and it drowns out genuinely risky commands.
_SAFE_CLEANUP_NAMES = frozenset({
    "dist", "build", "node_modules", "__pycache__", ".next", ".nuxt",
    "venv", ".venv", "env", "target", ".pytest_cache", ".turbo", ".cache",
    ".tox", ".mypy_cache", ".ruff_cache", "coverage", ".parcel-cache",
    "out", ".output", ".pytest_cache", "htmlcov",
})
_SAFE_CLEANUP_GLOBS = ("*.egg-info", "*.pyc", "*.pyo", "*.pyd")


def _matched_destructive_patterns(cmd: str) -> list[str]:
    matched = [p for p, rx in _DESTRUCTIVE_REGEXES if rx.search(cmd)]
    if matched == ["rm -rf"] and _rm_rf_is_safe_cleanup(cmd):
        return []
    return matched


def _is_safe_cleanup_target(token: str) -> bool:
    token = token.rstrip("/\\")
    if not token or token.startswith(("/", "~")) or token.startswith("\\") or re.match(r"^[A-Za-z]:", token):
        return False
    if ".." in Path(token).parts:
        return False
    basename = re.split(r"[\\/]", token)[-1]
    if basename in _SAFE_CLEANUP_NAMES:
        return True
    return any(fnmatch.fnmatch(basename, g) for g in _SAFE_CLEANUP_GLOBS)


def _rm_rf_is_safe_cleanup(cmd: str) -> bool:
    """True only if every target of an 'rm -rf' is a known, relative build-artifact
    path — i.e. routine cleanup, not a command worth a security finding."""
    m = _RM_RF_TARGETS_RE.search(cmd)
    if not m:
        return False  # matched the pattern but couldn't isolate targets — stay conservative
    try:
        tokens = shlex.split(m.group(1))
    except ValueError:
        return False  # unparseable shell syntax — stay conservative
    targets = [t for t in tokens if not t.startswith("-")]
    if not targets:
        return False
    return all(_is_safe_cleanup_target(t) for t in targets)


def _rm_rf_severity(cmd: str) -> str:
    """CRITICAL if any target is the home directory, filesystem root, or a
    sensitive path; HIGH otherwise (still a real destructive command, just
    not confirmed catastrophic)."""
    m = _RM_RF_TARGETS_RE.search(cmd)
    if not m:
        return "HIGH"
    try:
        tokens = shlex.split(m.group(1))
    except ValueError:
        return "HIGH"
    home = str(Path.home())
    for t in (tok for tok in tokens if not tok.startswith("-")):
        expanded = home + t[1:] if t.startswith("~") else t
        stripped = expanded.rstrip("/\\") or expanded  # don't reduce "/" itself to ""
        if stripped in ("/", home) or _is_sensitive_path(t):
            return "CRITICAL"
    return "HIGH"


def _command_severity(cmd: str, matched: list[str]) -> str:
    if "rm -rf" in matched:
        return _rm_rf_severity(cmd)
    return "HIGH"


def _path_is_within(path: str, base: str) -> bool:
    """Containment check that works for both POSIX and Windows paths regardless
    of which OS sentinel itself is running on, since transcripts may record
    paths from either. NTFS is case-insensitive, POSIX is not."""
    is_windows = bool(re.match(r"^[A-Za-z]:[\\/]", base)) or "\\" in base
    cls = PureWindowsPath if is_windows else PurePosixPath
    p_parts = cls(path).parts
    b_parts = cls(base).parts
    if is_windows:
        p_parts = tuple(part.lower() for part in p_parts)
        b_parts = tuple(part.lower() for part in b_parts)
    return p_parts[:len(b_parts)] == b_parts


def _is_broad_cwd(cwd: str) -> bool:
    """_is_broad_path (host_rules.py) only recognizes POSIX home/root — extend
    with a Windows heuristic (drive root, or a bare C:\\Users\\<name> profile dir)
    so the unscoped-session check isn't blind on that platform."""
    if _is_broad_path(cwd):
        return True
    if not (re.match(r"^[A-Za-z]:[\\/]", cwd) or "\\" in cwd):
        return False
    parts = PureWindowsPath(cwd).parts
    if len(parts) <= 1:
        return True
    if len(parts) == 3 and parts[1].lower() == "users":
        return True
    return False


def _truncate_command(cmd: str, limit: int = 80) -> str:
    """Truncate on the first line and a word boundary — cmd[:limit] alone can
    cut mid-word and read like the output itself is broken."""
    first_line = cmd.splitlines()[0] if cmd else cmd
    if len(first_line) <= limit:
        return first_line + ("…" if first_line != cmd else "")
    return first_line[:limit].rsplit(" ", 1)[0] + "…"


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
    """HIGH/CRITICAL: a destructive command pattern was actually run, not just
    hypothetically allowed. Routine build-artifact cleanup (rm -rf dist/, venv
    recreation, etc.) is excluded — see _rm_rf_is_safe_cleanup."""
    hits: list[tuple[str, str, str]] = []
    for s in sessions:
        for cmd in s.bash_commands:
            matched = _matched_destructive_patterns(cmd)
            if not matched:
                continue
            hits.append((s.session_id[:8], _truncate_command(cmd), _command_severity(cmd, matched)))
    if not hits:
        return None
    overall_severity = "CRITICAL" if any(sev == "CRITICAL" for _, _, sev in hits) else "HIGH"
    detail = "; ".join(f"{sid} [{sev}]: {cmd}" for sid, cmd, sev in hits[:5])
    return SessionFinding(
        severity=overall_severity,
        rule_id="SESSION_RISKY_COMMAND_EXECUTED",
        category="config",
        message=(
            f"{len(hits)} destructive command(s) were actually executed in past sessions "
            "(rm -rf outside the project, git push --force, or sudo) — this is a real "
            "occurrence, not a config risk. Routine build-artifact cleanup is excluded."
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


def _rule_unscoped_session(sessions: list[SessionInfo]) -> SessionFinding | None:
    """MEDIUM: a session ran from a broad directory (home dir or root), not a project dir.

    This matters on its own — a session with no project boundary can touch any file
    on the machine — and it also means SESSION_OUT_OF_PROJECT_WRITE can't do its job:
    "outside the project dir" is meaningless when the project dir is the home dir.
    """
    hits = [s for s in sessions if s.project_cwd and _is_broad_cwd(s.project_cwd)]
    if not hits:
        return None
    ids = ", ".join(f"{s.session_id[:8]} ({s.project_cwd})" for s in hits[:5])
    return SessionFinding(
        severity="MEDIUM",
        rule_id="SESSION_UNSCOPED_CWD",
        category="config",
        message=(
            f"{len(hits)} session(s) ran with the working directory set to the home "
            "directory (or broader) instead of a specific project — every file on the "
            "machine is technically 'in scope,' and out-of-project write detection "
            "cannot flag anything as unusual for these sessions."
        ),
        detail=f"Sessions: {ids}{'…' if len(hits) > 5 else ''}",
        remediation="Launch Claude Code from inside the specific project directory rather than from $HOME.",
    )


def _rule_out_of_project_write(sessions: list[SessionInfo]) -> SessionFinding | None:
    """MEDIUM: a Write/Edit landed outside the session's own project directory."""
    hits: list[tuple[str, str, str]] = []
    for s in sessions:
        # A broad cwd (home dir or root) makes "outside the project" meaningless —
        # SESSION_UNSCOPED_CWD covers that case instead.
        if not s.project_cwd or _is_broad_cwd(s.project_cwd):
            continue
        for tool, path in s.file_paths_touched:
            if tool not in ("Write", "Edit"):
                continue
            if not _path_is_within(path, s.project_cwd):
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
    parts = []
    for s in hits[:5]:
        examples = ", ".join(
            f"{d.tool}:{_truncate_command(d.target, 40)}" if d.target else d.tool
            for d in s.denials[:3]
        )
        parts.append(f"{s.session_id[:8]} ({len(s.denials)} denials, e.g. {examples})")
    detail = "; ".join(parts)
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
        remediation="Review what was denied above; tune permissions.allow if these were legitimate attempts.",
    )


_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}

_ALL_RULES = [
    _rule_bypass_mode,
    _rule_risky_command_executed,
    _rule_sensitive_path_touched,
    _rule_unscoped_session,
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

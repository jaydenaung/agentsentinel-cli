"""Claude Code session transcript scanner.

Parses ~/.claude/projects/**/*.jsonl transcripts to report what actually
happened in a session — tool calls, permission denials, and permission-mode
switches — as distinct from host_scanner.py, which reports what's configured.
No network calls — all checks are local and read-only.
"""

import dataclasses
import json
import re
import time
from pathlib import Path

_DENIAL_PATTERNS = [
    re.compile(r"Permission to use (\w+)(?: with command (.+?))? has been denied", re.IGNORECASE),
    re.compile(r"<tool_use_error>.*denied by your permission settings.*</tool_use_error>", re.IGNORECASE),
]

# Tool inputs that carry a filesystem path worth tracking
_PATH_INPUT_KEYS = {
    "Read": "file_path",
    "Write": "file_path",
    "Edit": "file_path",
}


@dataclasses.dataclass
class SessionDenial:
    tool: str
    target: str
    timestamp: str


@dataclasses.dataclass
class SessionInfo:
    session_id: str
    transcript_path: Path
    project_cwd: str | None
    first_ts: str | None
    last_ts: str | None
    permission_modes: set[str]
    tool_counts: dict[str, int]
    bash_commands: list[str]
    file_paths_touched: list[tuple[str, str]]   # (tool, path)
    denials: list[SessionDenial]
    parse_errors: int


def discover_sessions(
    project: Path | None = None,
    limit: int = 20,
    since_days: int | None = None,
    all_history: bool = False,
) -> list[Path]:
    """Find session transcript files, most recent first.

    project: restrict to sessions whose recorded cwd matches this path (checked
             during parsing, not by directory-name matching, since Claude Code's
             on-disk project folder name is a lossy mangling of the real path).
    limit:   cap on number of transcripts returned, ignored if all_history or
             since_days is set.
    """
    base = Path.home() / ".claude" / "projects"
    if not base.exists():
        return []

    files = sorted(
        (p for p in base.rglob("*.jsonl") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if project is not None:
        target = str(project.resolve())
        files = [p for p in files if _transcript_cwd(p) == target]

    if since_days is not None:
        cutoff = time.time() - since_days * 86400
        files = [p for p in files if p.stat().st_mtime >= cutoff]
    elif not all_history:
        files = files[:limit]

    return files


def _transcript_cwd(path: Path) -> str | None:
    """Peek at the first few lines of a transcript to find its recorded cwd."""
    try:
        with path.open() as fh:
            for i, line in enumerate(fh):
                if i > 20:
                    break
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                cwd = d.get("cwd")
                if cwd:
                    return cwd
    except OSError:
        pass
    return None


def _extract_denial(content: str) -> tuple[str, str] | None:
    for pattern in _DENIAL_PATTERNS:
        m = pattern.search(content)
        if m and m.groups() and m.group(1):
            return m.group(1), (m.group(2) or "").strip()
        if m:
            return "unknown", content[:120]
    return None


def parse_session(path: Path) -> SessionInfo:
    session_id = path.stem
    project_cwd: str | None = None
    first_ts: str | None = None
    last_ts: str | None = None
    permission_modes: set[str] = set()
    tool_counts: dict[str, int] = {}
    bash_commands: list[str] = []
    file_paths_touched: list[tuple[str, str]] = []
    denials: list[SessionDenial] = []
    parse_errors = 0

    # tool_use_id -> tool name, so a later tool_result denial can be attributed
    pending_tool_calls: dict[str, tuple[str, str]] = {}

    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return SessionInfo(
            session_id=session_id, transcript_path=path, project_cwd=None,
            first_ts=None, last_ts=None, permission_modes=set(), tool_counts={},
            bash_commands=[], file_paths_touched=[], denials=[], parse_errors=1,
        )

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue

        ts = d.get("timestamp")
        if ts:
            first_ts = first_ts or ts
            last_ts = ts

        cwd = d.get("cwd")
        if cwd and project_cwd is None:
            project_cwd = cwd

        dtype = d.get("type")
        if dtype == "permission-mode":
            mode = d.get("permissionMode")
            if mode:
                permission_modes.add(mode)

        message = d.get("message", {})
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue

        for block in content:
            if not isinstance(block, dict):
                continue

            if block.get("type") == "tool_use":
                name = block.get("name", "unknown")
                tool_counts[name] = tool_counts.get(name, 0) + 1
                tool_input = block.get("input", {}) if isinstance(block.get("input"), dict) else {}
                tool_use_id = block.get("id", "")

                if name == "Bash":
                    cmd = tool_input.get("command", "")
                    if cmd:
                        bash_commands.append(cmd)
                        pending_tool_calls[tool_use_id] = (name, cmd)
                elif name in _PATH_INPUT_KEYS:
                    p = tool_input.get(_PATH_INPUT_KEYS[name], "")
                    if p:
                        file_paths_touched.append((name, p))
                        pending_tool_calls[tool_use_id] = (name, p)
                else:
                    pending_tool_calls[tool_use_id] = (name, "")

            elif block.get("type") == "tool_result" and block.get("is_error"):
                raw_content = block.get("content", "")
                text = raw_content if isinstance(raw_content, str) else str(raw_content)
                extracted = _extract_denial(text)
                if extracted:
                    tool_name, target = extracted
                    tool_use_id = block.get("tool_use_id", "")
                    if tool_use_id in pending_tool_calls:
                        tool_name, target = pending_tool_calls[tool_use_id]
                        target = target or extracted[1]
                    denials.append(SessionDenial(
                        tool=tool_name, target=target, timestamp=ts or "",
                    ))

    return SessionInfo(
        session_id=session_id,
        transcript_path=path,
        project_cwd=project_cwd,
        first_ts=first_ts,
        last_ts=last_ts,
        permission_modes=permission_modes,
        tool_counts=tool_counts,
        bash_commands=bash_commands,
        file_paths_touched=file_paths_touched,
        denials=denials,
        parse_errors=parse_errors,
    )


def scan_sessions(
    project: Path | None = None,
    limit: int = 20,
    since_days: int | None = None,
    all_history: bool = False,
) -> list[SessionInfo]:
    """Discover and parse session transcripts. Tolerant of per-file errors —
    a malformed transcript is skipped rather than aborting the whole scan."""
    paths = discover_sessions(project=project, limit=limit, since_days=since_days, all_history=all_history)
    sessions: list[SessionInfo] = []
    for p in paths:
        try:
            sessions.append(parse_session(p))
        except Exception:
            continue
    return sessions

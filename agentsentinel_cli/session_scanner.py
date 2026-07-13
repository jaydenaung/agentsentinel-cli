"""Claude Code session transcript scanner.

Parses ~/.claude/projects/**/*.jsonl transcripts to report what actually
happened in a session — tool calls, permission denials, and permission-mode
switches — as distinct from host_scanner.py, which reports what's configured.
No network calls — all checks are local. Parsed results are cached on disk
(~/.agentsentinel/session_cache.json) so unchanged transcripts aren't
re-parsed on every run; pass use_cache=False to disable.
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

# type values a well-formed transcript line is expected to have. A line with
# a recognized shape but none of these is a signal the format may have
# changed since this parser was written — distinct from a JSON parse error.
_KNOWN_LINE_TYPES = {
    "user", "assistant", "system", "permission-mode", "mode",
    "file-history-snapshot", "attachment", "ai-title", "last-prompt", "summary",
    "queue-operation", "custom-title", "frame-link",
}
_KNOWN_CONTENT_BLOCK_TYPES = {"text", "tool_use", "tool_result", "thinking", "image"}

_CACHE_DIR = Path.home() / ".agentsentinel"
_CACHE_FILE = _CACHE_DIR / "session_cache.json"
_CACHE_VERSION = 3  # bump on any change to SessionInfo's shape OR parsing/classification logic


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
    parse_errors: int         # lines that failed json.loads
    schema_warnings: int      # lines/blocks that parsed but didn't match any known shape


def has_any_sessions() -> bool:
    """Cheap existence check, used to distinguish 'no Claude Code history at all'
    from 'history exists but nothing matched your filter' in CLI diagnostics."""
    base = Path.home() / ".claude" / "projects"
    if not base.exists():
        return False
    return next(base.rglob("*.jsonl"), None) is not None


def _normalize_path(p: str) -> str:
    try:
        return str(Path(p).expanduser().resolve())
    except OSError:
        return p.rstrip("/")


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
             Both sides are resolved (symlinks, trailing slashes) before
             comparing so a symlinked home dir or a trailing slash doesn't
             silently produce zero matches.
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
        target = _normalize_path(str(project))
        matched = []
        for p in files:
            cwd = _transcript_cwd(p)
            if cwd and _normalize_path(cwd) == target:
                matched.append(p)
        files = matched

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
    schema_warnings = 0

    # tool_use_id -> tool name, so a later tool_result denial can be attributed
    pending_tool_calls: dict[str, tuple[str, str]] = {}

    try:
        fh = path.open(errors="replace")
    except OSError:
        return SessionInfo(
            session_id=session_id, transcript_path=path, project_cwd=None,
            first_ts=None, last_ts=None, permission_modes=set(), tool_counts={},
            bash_commands=[], file_paths_touched=[], denials=[], parse_errors=1,
            schema_warnings=0,
        )

    with fh:
        for line in fh:
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
            if dtype is None or dtype not in _KNOWN_LINE_TYPES:
                schema_warnings += 1
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
                block_type = block.get("type")
                if block_type not in _KNOWN_CONTENT_BLOCK_TYPES:
                    schema_warnings += 1
                    continue

                if block_type == "tool_use":
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

                elif block_type == "tool_result" and block.get("is_error"):
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
        schema_warnings=schema_warnings,
    )


# ── Disk cache ──────────────────────────────────────────────────────────────
# Parsing a multi-MB transcript on every invocation doesn't scale once a
# project has months of history. Cache keyed on (path, mtime, size); a
# changed or new file is reparsed, everything else is a JSON read.

def _session_to_cache_dict(s: SessionInfo) -> dict:
    return {
        "session_id": s.session_id,
        "transcript_path": str(s.transcript_path),
        "project_cwd": s.project_cwd,
        "first_ts": s.first_ts,
        "last_ts": s.last_ts,
        "permission_modes": sorted(s.permission_modes),
        "tool_counts": s.tool_counts,
        "bash_commands": s.bash_commands,
        "file_paths_touched": [[t, p] for t, p in s.file_paths_touched],
        "denials": [{"tool": d.tool, "target": d.target, "timestamp": d.timestamp} for d in s.denials],
        "parse_errors": s.parse_errors,
        "schema_warnings": s.schema_warnings,
    }


def _session_from_cache_dict(d: dict) -> SessionInfo:
    return SessionInfo(
        session_id=d["session_id"],
        transcript_path=Path(d["transcript_path"]),
        project_cwd=d["project_cwd"],
        first_ts=d["first_ts"],
        last_ts=d["last_ts"],
        permission_modes=set(d["permission_modes"]),
        tool_counts=d["tool_counts"],
        bash_commands=d["bash_commands"],
        file_paths_touched=[(t, p) for t, p in d["file_paths_touched"]],
        denials=[SessionDenial(**dd) for dd in d["denials"]],
        parse_errors=d["parse_errors"],
        schema_warnings=d.get("schema_warnings", 0),
    )


def _load_cache() -> dict:
    if not _CACHE_FILE.exists():
        return {}
    try:
        raw = json.loads(_CACHE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    if raw.get("version") != _CACHE_VERSION:
        return {}
    entries = raw.get("entries", {})
    return entries if isinstance(entries, dict) else {}


def _save_cache(entries: dict) -> None:
    # Drop entries for transcripts that no longer exist so the cache doesn't
    # grow unbounded as old sessions are pruned or projects are removed.
    pruned = {k: v for k, v in entries.items() if Path(k).exists()}
    try:
        _CACHE_DIR.mkdir(exist_ok=True)
        _CACHE_FILE.write_text(json.dumps({"version": _CACHE_VERSION, "entries": pruned}))
    except OSError:
        pass  # cache is a pure optimization — never fatal if it can't be written


def scan_sessions(
    project: Path | None = None,
    limit: int = 20,
    since_days: int | None = None,
    all_history: bool = False,
    use_cache: bool = True,
) -> list[SessionInfo]:
    """Discover and parse session transcripts. Tolerant of per-file errors —
    a malformed transcript is skipped rather than aborting the whole scan.
    Unchanged transcripts are served from the on-disk cache when use_cache=True."""
    paths = discover_sessions(project=project, limit=limit, since_days=since_days, all_history=all_history)
    cache = _load_cache() if use_cache else {}
    cache_dirty = False
    sessions: list[SessionInfo] = []

    for p in paths:
        try:
            st = p.stat()
        except OSError:
            continue

        key = str(p)
        cached = cache.get(key)
        if cached and cached.get("mtime") == st.st_mtime and cached.get("size") == st.st_size:
            try:
                sessions.append(_session_from_cache_dict(cached["data"]))
                continue
            except (KeyError, TypeError):
                pass  # corrupt cache entry — fall through and reparse

        try:
            info = parse_session(p)
        except Exception:
            continue
        sessions.append(info)
        if use_cache:
            cache[key] = {"mtime": st.st_mtime, "size": st.st_size, "data": _session_to_cache_dict(info)}
            cache_dirty = True

    if use_cache and cache_dirty:
        _save_cache(cache)

    return sessions

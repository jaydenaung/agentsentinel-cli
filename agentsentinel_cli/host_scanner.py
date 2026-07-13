"""Host AI security posture scanner.

Collects configuration data from Claude Code, Claude Desktop, MCP servers,
shell configs, macOS TCC permissions, and system security settings.
No network calls — all checks are local and read-only.
"""

import dataclasses
import json
import os
import re
import subprocess
from pathlib import Path


@dataclasses.dataclass
class McpServerConfig:
    name: str
    command: str
    args: list[str]
    env_keys: list[str]          # env var names only, values redacted
    filesystem_paths: list[str]
    has_network_access: bool


@dataclasses.dataclass
class ClaudeCodeSettings:
    path: Path                   # primary (global) settings path, kept for back-compat display
    allowed_tools: list[str]     # merged permissions.allow + legacy allowedTools
    disallowed_tools: list[str]  # merged permissions.deny + legacy disallowedTools
    ask_tools: list[str]         # permissions.ask — prompts user every time, no config for/against
    hooks: list[dict]            # [{event, type, command}]
    mcp_servers: list[McpServerConfig]
    sources: list[Path]          # every settings file that contributed (global + project + local)


@dataclasses.dataclass
class ClaudeDesktopConfig:
    path: Path
    mcp_servers: list[McpServerConfig]


@dataclasses.dataclass
class VendorConfig:
    """Configuration found for a third-party AI coding tool or agent runtime."""
    vendor: str          # "cursor" | "windsurf" | "continue" | "gemini_cli" | "vscode"
    display_name: str    # human-readable
    path: Path
    mcp_servers: list[McpServerConfig]


@dataclasses.dataclass
class TccPermission:
    app_name: str
    bundle_id: str
    service: str                 # full_disk_access | screen_recording | accessibility | …
    granted: bool


@dataclasses.dataclass
class ExposedProcess:
    pid: int
    name: str
    cmdline: str
    address: str
    port: int


@dataclasses.dataclass
class WindowsPermissionSignal:
    """Windows analog to macOS TCC — Defender exclusions and NTFS ACLs on Claude paths."""
    check: str            # "defender_exclusion" | "acl_world_writable"
    path: str
    risky: bool
    detail: str


@dataclasses.dataclass
class HostContext:
    """Aggregated host AI security posture data — passed to every rule."""
    claude_code: ClaudeCodeSettings | None
    claude_desktop: ClaudeDesktopConfig | None
    vendor_configs: list[VendorConfig]
    memory_file_count: int
    memory_total_bytes: int
    shell_key_findings: list[tuple[str, str, str]]   # (key_type, file_path, redacted_snippet)
    tcc_permissions: list[TccPermission]
    sip_enabled: bool | None
    filevault_enabled: bool | None
    gatekeeper_enabled: bool | None
    exposed_processes: list[ExposedProcess]
    windows_permissions: list[WindowsPermissionSignal]
    scan_errors: list[str]


# ── MCP server config analysis ────────────────────────────────────────────────

_FS_PATH_RE = re.compile(r"^(/|~/|\.\.?/)")

_NETWORK_SIGNALS = frozenset({
    "fetch", "brave", "brave-search", "github", "gitlab", "slack",
    "google", "gmail", "gdrive", "google-maps", "linear", "jira",
    "notion", "airtable", "salesforce", "stripe", "twilio",
    "http", "url", "web", "browser", "playwright", "puppeteer",
})


def _analyze_mcp_server(name: str, config: dict) -> McpServerConfig:
    command = config.get("command", "")
    args = [str(a) for a in config.get("args", [])]
    env = config.get("env", {})

    fs_paths = [a for a in args if isinstance(a, str) and _FS_PATH_RE.match(a)]
    name_lower = name.lower()
    args_str = " ".join(args).lower()

    has_network = (
        any(sig in name_lower for sig in _NETWORK_SIGNALS)
        or any(sig in args_str for sig in {"http://", "https://", "url", "webhook"})
    )

    return McpServerConfig(
        name=name,
        command=command,
        args=args,
        env_keys=list(env.keys()),
        filesystem_paths=fs_paths,
        has_network_access=has_network,
    )


# ── Claude Code settings ──────────────────────────────────────────────────────

def _extract_hooks(raw: dict) -> list[dict]:
    hooks_raw = raw.get("hooks", {})
    hook_list: list[dict] = []
    if isinstance(hooks_raw, dict):
        for event, matchers in hooks_raw.items():
            if not isinstance(matchers, list):
                continue
            for entry in matchers:
                if not isinstance(entry, dict):
                    continue
                for h in entry.get("hooks", []):
                    hook_list.append({
                        "event": event,
                        "type": h.get("type", ""),
                        "command": h.get("command", ""),
                    })
    return hook_list


def _extract_permission_lists(raw: dict) -> tuple[list[str], list[str], list[str]]:
    """Return (allow, deny, ask) tool patterns.

    Modern Claude Code settings use permissions.{allow,deny,ask} (fine-grained
    patterns like "Bash(rm -rf *)", "Read(~/.ssh/**)"). Older configs used flat
    allowedTools/disallowedTools lists. Both are read and merged so nothing is
    missed regardless of which schema a given settings file uses.
    """
    perms = raw.get("permissions", {})
    allow = perms.get("allow", []) if isinstance(perms, dict) else []
    deny = perms.get("deny", []) if isinstance(perms, dict) else []
    ask = perms.get("ask", []) if isinstance(perms, dict) else []

    legacy_allowed = raw.get("allowedTools", [])
    legacy_disallowed = raw.get("disallowedTools", [])

    def _merge(a: object, b: object) -> list[str]:
        items = (a if isinstance(a, list) else []) + (b if isinstance(b, list) else [])
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if isinstance(item, str) and item not in seen:
                seen.add(item)
                out.append(item)
        return out

    return (
        _merge(allow, legacy_allowed),
        _merge(deny, legacy_disallowed),
        ask if isinstance(ask, list) else [],
    )


def _load_settings_file(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _read_claude_code_settings() -> ClaudeCodeSettings | None:
    """Merge global (~/.claude/settings.json) and project-level
    (<cwd>/.claude/settings.json, <cwd>/.claude/settings.local.json) settings.
    Project-level files layer permissions and hooks on top of the global config,
    matching how Claude Code itself applies them."""
    global_path = Path.home() / ".claude" / "settings.json"
    candidate_paths = [
        global_path,
        Path.cwd() / ".claude" / "settings.json",
        Path.cwd() / ".claude" / "settings.local.json",
    ]

    sources: list[Path] = []
    allowed: list[str] = []
    disallowed: list[str] = []
    ask: list[str] = []
    hooks: list[dict] = []
    mcp_servers: list[McpServerConfig] = []

    for path in candidate_paths:
        raw = _load_settings_file(path)
        if raw is None:
            continue
        sources.append(path)

        a, d, k = _extract_permission_lists(raw)
        for item in a:
            if item not in allowed:
                allowed.append(item)
        for item in d:
            if item not in disallowed:
                disallowed.append(item)
        for item in k:
            if item not in ask:
                ask.append(item)

        hooks.extend(_extract_hooks(raw))
        mcp_servers.extend(
            _analyze_mcp_server(name, cfg)
            for name, cfg in raw.get("mcpServers", {}).items()
        )

    if not sources:
        return None

    return ClaudeCodeSettings(
        path=global_path if global_path in sources else sources[0],
        allowed_tools=allowed,
        disallowed_tools=disallowed,
        ask_tools=ask,
        hooks=hooks,
        mcp_servers=mcp_servers,
        sources=sources,
    )


# ── Claude Desktop config ─────────────────────────────────────────────────────

def _read_claude_desktop_config() -> ClaudeDesktopConfig | None:
    candidates = [
        Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
        Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
    ]
    path = next((p for p in candidates if p.exists()), None)
    if path is None:
        return None

    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    mcp_servers = [
        _analyze_mcp_server(k, v)
        for k, v in raw.get("mcpServers", {}).items()
    ]
    return ClaudeDesktopConfig(path=path, mcp_servers=mcp_servers)


# ── Memory files ──────────────────────────────────────────────────────────────

def _scan_memory_files() -> tuple[int, int]:
    """Return (count, total_bytes) for all Claude Code memory/conversation files."""
    base = Path.home() / ".claude" / "projects"
    if not base.exists():
        return 0, 0
    count, total = 0, 0
    for p in base.rglob("*"):
        if p.is_file():
            count += 1
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return count, total


# ── Shell config AI key detection ────────────────────────────────────────────

_AI_KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ANTHROPIC_API_KEY", re.compile(
        r'(?:export\s+|\$env:[A-Z_]+=|setx\s+\S+\s+)?ANTHROPIC_API_KEY\s*[=:]\s*["\']?(sk-ant-[A-Za-z0-9\-_]{20,})["\']?'
    )),
    ("OPENAI_API_KEY", re.compile(
        r'(?:export\s+|\$env:[A-Z_]+=|setx\s+\S+\s+)?OPENAI_API_KEY\s*[=:]\s*["\']?(sk-(?:proj-)?[A-Za-z0-9\-_]{20,})["\']?'
    )),
    ("GOOGLE_API_KEY", re.compile(
        r'(?:export\s+|\$env:[A-Z_]+=|setx\s+\S+\s+)?(?:GOOGLE_API_KEY|GEMINI_API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{30,})["\']?'
    )),
    ("HF_TOKEN", re.compile(
        r'(?:export\s+|\$env:[A-Z_]+=|setx\s+\S+\s+)?(?:HF_TOKEN|HUGGINGFACE_TOKEN)\s*[=:]\s*["\']?(hf_[A-Za-z0-9]{20,})["\']?'
    )),
    ("MISTRAL_API_KEY", re.compile(
        r'(?:export\s+|\$env:[A-Z_]+=|setx\s+\S+\s+)?MISTRAL_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9]{30,})["\']?'
    )),
    ("COHERE_API_KEY", re.compile(
        r'(?:export\s+|\$env:[A-Z_]+=|setx\s+\S+\s+)?(?:COHERE_API_KEY|CO_API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{30,})["\']?'
    )),
]

_SHELL_CONFIG_FILES = [
    "~/.zshrc", "~/.bashrc", "~/.bash_profile", "~/.zprofile",
    "~/.profile", "~/.zshenv", "~/.bash_aliases",
]

# PowerShell profile paths on Windows — checked when the platform is Windows
_POWERSHELL_PROFILE_PATHS: list[Path] = []
if os.name == "nt":
    _documents = Path.home() / "Documents"
    _POWERSHELL_PROFILE_PATHS = [
        _documents / "PowerShell" / "Microsoft.PowerShell_profile.ps1",         # PS 7+
        _documents / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1",  # PS 5
        Path.home() / "AppData" / "Local" / "PowerShell" / "Microsoft.PowerShell_profile.ps1",
    ]


def _scan_shell_configs() -> list[tuple[str, str, str]]:
    """Return list of (key_type, file_path, redacted_snippet) for AI keys in shell configs."""
    findings: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    for config_str in _SHELL_CONFIG_FILES:
        p = Path(config_str).expanduser()
        if not p.exists():
            continue
        try:
            content = p.read_text(errors="replace")
        except OSError:
            continue
        for key_type, pattern in _AI_KEY_PATTERNS:
            for m in pattern.finditer(content):
                val = m.group(1)
                if (key_type, val[:8]) in seen:
                    continue
                seen.add((key_type, val[:8]))
                redacted = val[:8] + "****" + val[-4:] if len(val) > 12 else "****"
                findings.append((key_type, str(p), redacted))

    # Windows: check PowerShell profile files
    for ps_path in _POWERSHELL_PROFILE_PATHS:
        if not ps_path.exists():
            continue
        try:
            content = ps_path.read_text(errors="replace")
        except OSError:
            continue
        for key_type, pattern in _AI_KEY_PATTERNS:
            for m in pattern.finditer(content):
                val = m.group(1)
                if (key_type, val[:8]) in seen:
                    continue
                seen.add((key_type, val[:8]))
                redacted = val[:8] + "****" + val[-4:] if len(val) > 12 else "****"
                findings.append((key_type, str(ps_path), redacted))

    return findings


# ── macOS TCC permissions ─────────────────────────────────────────────────────

_TCC_SERVICES = {
    "kTCCServiceSystemPolicyAllFiles": "full_disk_access",
    "kTCCServiceScreenCapture": "screen_recording",
    "kTCCServiceAccessibility": "accessibility",
    "kTCCServiceCamera": "camera",
    "kTCCServiceMicrophone": "microphone",
}

# Bundle ID fragments that identify AI tools and the terminals Claude Code runs in
_AI_BUNDLE_SIGNALS = frozenset({
    "claude", "anthropic", "openai", "cursor", "copilot",
    "terminal", "iterm", "kitty", "warp", "vscode", "code",
    "pycharm", "intellij", "jetbrains",
})


def _read_tcc_permissions() -> tuple[list[TccPermission], str | None]:
    """Read TCC.db for AI-relevant permissions. Returns (permissions, error_msg_or_None)."""
    import sqlite3

    db_paths = [
        Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db",
        Path("/Library/Application Support/com.apple.TCC/TCC.db"),
    ]
    found_db = next((p for p in db_paths if p.exists()), None)
    if found_db is None:
        return [], None   # non-macOS or unusual path

    try:
        placeholders = ",".join("?" * len(_TCC_SERVICES))
        conn = sqlite3.connect(f"file:{found_db}?mode=ro", uri=True, timeout=3)
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT client, service, auth_value FROM access WHERE service IN ({placeholders})",
            list(_TCC_SERVICES.keys()),
        )
        rows = cursor.fetchall()
        conn.close()
    except (sqlite3.OperationalError, PermissionError, OSError) as exc:
        msg = str(exc)
        if any(kw in msg.lower() for kw in {"permission", "not authorized", "unable to open"}):
            return [], (
                "TCC permission check skipped — Terminal needs Full Disk Access. "
                "Grant it in System Settings → Privacy & Security → Full Disk Access, "
                "then re-run sentinel host."
            )
        return [], f"TCC read error: {msg}"

    perms: list[TccPermission] = []
    for bundle_id, service_key, auth_value in rows:
        service_name = _TCC_SERVICES.get(service_key, service_key)
        granted = auth_value == 2   # TCC auth_value: 2 = allowed
        app_name = bundle_id.split(".")[-1] if "." in bundle_id else bundle_id
        # Only include AI tools and terminals
        if any(sig in bundle_id.lower() or sig in app_name.lower() for sig in _AI_BUNDLE_SIGNALS):
            perms.append(TccPermission(
                app_name=app_name,
                bundle_id=bundle_id,
                service=service_name,
                granted=granted,
            ))
    return perms, None


# ── macOS system security ─────────────────────────────────────────────────────

def _run_cmd(args: list[str], timeout: int = 5) -> str | None:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _check_sip() -> bool | None:
    out = _run_cmd(["csrutil", "status"])
    if out is None:
        return None
    lower = out.lower()
    if "disabled" in lower:
        return False
    if "enabled" in lower:
        return True
    return None


def _check_filevault() -> bool | None:
    out = _run_cmd(["fdesetup", "status"])
    if out is None:
        return None
    return "on" in out.lower()


def _check_gatekeeper() -> bool | None:
    out = _run_cmd(["spctl", "--status"])
    if out is None:
        return None
    return "assessments enabled" in out.lower()


# ── AI processes on non-localhost interfaces ──────────────────────────────────

_AI_PROCESS_SIGNALS = frozenset({
    "claude", "anthropic", "openai", "langchain", "langgraph",
    "autogen", "crewai", "mcp", "ollama", "llama",
})


def _scan_exposed_processes() -> list[ExposedProcess]:
    """Find AI-related processes listening on non-localhost network interfaces."""
    try:
        import psutil
    except ImportError:
        return []

    exposed: list[ExposedProcess] = []
    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                info = proc.info
                cmdline_str = " ".join(info.get("cmdline") or []).lower()
                name_str = (info.get("name") or "").lower()
                if not any(sig in cmdline_str or sig in name_str for sig in _AI_PROCESS_SIGNALS):
                    continue
                for conn in proc.net_connections(kind="inet"):
                    if conn.status != "LISTEN":
                        continue
                    if conn.laddr.ip not in ("127.0.0.1", "::1", ""):
                        exposed.append(ExposedProcess(
                            pid=info["pid"],
                            name=info.get("name", ""),
                            cmdline=" ".join(info.get("cmdline") or [])[:100],
                            address=conn.laddr.ip,
                            port=conn.laddr.port,
                        ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return exposed


# ── Windows permission signals (TCC-equivalent) ────────────────────────────────

def _windows_claude_paths() -> list[Path]:
    home = Path.home()
    appdata = Path(os.environ["APPDATA"]) if "APPDATA" in os.environ else None
    paths = [home / ".claude"]
    if appdata:
        paths.append(appdata / "Claude")
    return [p for p in paths if p.exists()]


def _check_defender_exclusions(claude_paths: list[Path]) -> list[WindowsPermissionSignal]:
    out = _run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath",
    ], timeout=8)
    if out is None:
        return []
    excluded = {line.strip().lower() for line in out.splitlines() if line.strip()}
    signals = []
    for p in claude_paths:
        p_str = str(p).lower()
        hit = any(p_str.startswith(e) or e.startswith(p_str) for e in excluded)
        if hit:
            signals.append(WindowsPermissionSignal(
                check="defender_exclusion",
                path=str(p),
                risky=True,
                detail=f"{p} is excluded from Windows Defender scanning",
            ))
    return signals


def _check_acl_world_writable(claude_paths: list[Path]) -> list[WindowsPermissionSignal]:
    signals = []
    for p in claude_paths:
        out = _run_cmd(["icacls", str(p)], timeout=8)
        if out is None:
            continue
        lower = out.lower()
        risky_principals = []
        for principal in ("everyone", "builtin\\users", "authenticated users"):
            if principal in lower and any(
                f"{principal}:(" in lower and perm in lower
                for perm in ("(f)", "(m)", "(w)")
            ):
                risky_principals.append(principal)
        if risky_principals:
            signals.append(WindowsPermissionSignal(
                check="acl_world_writable",
                path=str(p),
                risky=True,
                detail=f"{p} is writable by: {', '.join(risky_principals)}",
            ))
    return signals


def _scan_windows_permissions() -> list[WindowsPermissionSignal]:
    """Best-effort TCC-equivalent for Windows: Defender exclusions + NTFS ACLs on
    Claude config/memory paths. No-op on non-Windows platforms."""
    if os.name != "nt":
        return []
    claude_paths = _windows_claude_paths()
    if not claude_paths:
        return []
    return _check_defender_exclusions(claude_paths) + _check_acl_world_writable(claude_paths)


# ── Third-party AI tool configs ───────────────────────────────────────────────

def _dig(data: object, keys: list[str]) -> object:
    """Navigate a nested dict by key path; returns None if any key is absent."""
    for k in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(k)  # type: ignore[union-attr]
        if data is None:
            return None
    return data


def _parse_vendor_mcp(raw: dict, key_path: list[str], list_format: bool) -> list[McpServerConfig]:
    """Extract MCP server configs from a vendor settings file.

    list_format=True handles Continue.dev's array format;
    False handles the dict format used by Cursor, Windsurf, Gemini CLI, and VS Code.
    """
    data = _dig(raw, key_path)
    if not data:
        return []
    if list_format and isinstance(data, list):
        return [
            _analyze_mcp_server(item.get("name", f"server_{i}"), item)
            for i, item in enumerate(data)
            if isinstance(item, dict)
        ]
    if not list_format and isinstance(data, dict):
        return [_analyze_mcp_server(k, v) for k, v in data.items() if isinstance(v, dict)]
    return []


def _read_vendor_configs() -> list[VendorConfig]:
    """Discover MCP server configs for Cursor, Windsurf, Continue.dev, Gemini CLI, and VS Code."""
    home = Path.home()
    appdata = Path(os.environ["APPDATA"]) if "APPDATA" in os.environ else None

    # (vendor_id, display_name, candidate_paths, mcp_json_key_path, list_format)
    # key_path navigates nested keys: ["mcp", "servers"] → raw["mcp"]["servers"]
    # list_format: True = array of {name, command, args}, False = dict of {name: {command, args}}
    specs: list[tuple[str, str, list[Path], list[str], bool]] = [
        ("cursor", "Cursor", [
            home / ".cursor" / "mcp.json",
            home / "Library" / "Application Support" / "Cursor" / "User" / "settings.json",
            home / ".config" / "Cursor" / "User" / "settings.json",
            *([appdata / "Cursor" / "User" / "settings.json"] if appdata else []),
        ], ["mcpServers"], False),

        ("windsurf", "Windsurf", [
            home / ".codeium" / "windsurf" / "mcp_config.json",
            home / "Library" / "Application Support" / "Windsurf" / "User" / "settings.json",
            home / ".config" / "Windsurf" / "User" / "settings.json",
            *([appdata / "Windsurf" / "User" / "settings.json"] if appdata else []),
        ], ["mcpServers"], False),

        ("continue", "Continue.dev", [
            home / ".continue" / "config.json",
        ], ["mcpServers"], True),

        ("gemini_cli", "Gemini CLI", [
            home / ".gemini" / "settings.json",
        ], ["mcpServers"], False),

        ("vscode", "VS Code", [
            home / "Library" / "Application Support" / "Code" / "User" / "settings.json",
            home / ".config" / "Code" / "User" / "settings.json",
            *([appdata / "Code" / "User" / "settings.json"] if appdata else []),
        ], ["mcp", "servers"], False),
    ]

    configs: list[VendorConfig] = []
    for vendor_id, display_name, candidate_paths, key_path, list_fmt in specs:
        for path in candidate_paths:
            if not path.exists():
                continue
            try:
                raw = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            servers = _parse_vendor_mcp(raw, key_path, list_fmt)
            if servers:
                configs.append(VendorConfig(
                    vendor=vendor_id,
                    display_name=display_name,
                    path=path,
                    mcp_servers=servers,
                ))
            break  # use first matching path per vendor
    return configs


# ── Main entry point ──────────────────────────────────────────────────────────

def scan_host() -> HostContext:
    """Scan the local host for AI security posture issues."""
    errors: list[str] = []

    claude_code = _read_claude_code_settings()
    claude_desktop = _read_claude_desktop_config()
    vendor_configs = _read_vendor_configs()
    mem_count, mem_bytes = _scan_memory_files()
    shell_keys = _scan_shell_configs()
    tcc_perms, tcc_err = _read_tcc_permissions()
    if tcc_err:
        errors.append(tcc_err)

    return HostContext(
        claude_code=claude_code,
        claude_desktop=claude_desktop,
        vendor_configs=vendor_configs,
        memory_file_count=mem_count,
        memory_total_bytes=mem_bytes,
        shell_key_findings=shell_keys,
        tcc_permissions=tcc_perms,
        sip_enabled=_check_sip(),
        filevault_enabled=_check_filevault(),
        gatekeeper_enabled=_check_gatekeeper(),
        exposed_processes=_scan_exposed_processes(),
        windows_permissions=_scan_windows_permissions(),
        scan_errors=errors,
    )

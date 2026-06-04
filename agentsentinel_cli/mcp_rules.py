"""Security rules for MCP server audits.

Each rule maps to one or more OWASP LLM Top 10 categories (noted in docstrings).
Rules operate on McpContext so they have access to both server info and scan metadata.
"""

import dataclasses
from agentsentinel_cli.mcp_client import McpServerInfo, McpToolInfo


@dataclasses.dataclass
class McpContext:
    """Full context for a single MCP scan — passed to every rule."""

    server: McpServerInfo
    auth_required: bool  # True = credentials were required/provided; False = open server


@dataclasses.dataclass
class McpFinding:
    """A security finding from an MCP server audit."""

    severity: str   # CRITICAL | HIGH | MEDIUM | LOW
    rule_id: str
    message: str
    detail: str = ""


# Keyword sets for exfiltration detection (aligned with posture rules in rules.py)
_INTERNAL_READ_KW = frozenset({
    "db", "database", "crm", "file", "filesystem",
    "s3_read", "storage_read", "read_file",
})
_EXTERNAL_WRITE_KW = frozenset({
    "email", "smtp", "webhook", "http_post", "http_external",
    "s3_write", "send", "slack",
})


# ── Rules ─────────────────────────────────────────────────────────────────────

def _rule_no_auth(ctx: McpContext) -> McpFinding | None:
    """CRITICAL: HTTP server requires no credentials to enumerate tools. (OWASP LLM06)

    Not applicable to stdio transport — stdio processes are isolated by the OS.
    """
    if ctx.server.transport == "stdio":
        return None
    if not ctx.auth_required and ctx.server.tools:
        return McpFinding(
            severity="CRITICAL",
            rule_id="NO_AUTH",
            message=(
                "MCP server accepted initialize and tools/list with no credentials. "
                "Any process with network access can enumerate and invoke all tools."
            ),
            detail=f"{len(ctx.server.tools)} tool(s) exposed without authentication.",
        )
    return None


def _rule_unauth_dangerous(ctx: McpContext) -> McpFinding | None:
    """CRITICAL: dangerous tools callable without auth on HTTP server. (OWASP LLM06)"""
    if ctx.server.transport == "stdio":
        return None
    if ctx.auth_required:
        return None
    dangerous = [t.name for t in ctx.server.tools if t.is_dangerous]
    if dangerous:
        return McpFinding(
            severity="CRITICAL",
            rule_id="UNAUTH_DANGEROUS_EXEC",
            message=(
                "Dangerous tools are accessible without authentication. "
                "An attacker with local network access can invoke these directly."
            ),
            detail=f"Unauthenticated dangerous tools: {', '.join(dangerous)}",
        )
    return None


def _rule_exfiltration_path(ctx: McpContext) -> McpFinding | None:
    """CRITICAL: internal-read + external-write tools present. (OWASP LLM02, LLM06)"""
    names = {t.name.lower() for t in ctx.server.tools}
    internal = [n for n in names if any(kw in n for kw in _INTERNAL_READ_KW)]
    external = [n for n in names if any(kw in n for kw in _EXTERNAL_WRITE_KW)]
    if internal and external:
        return McpFinding(
            severity="CRITICAL",
            rule_id="EXFILTRATION_PATH",
            message=(
                "Server exposes both internal-read and external-write tools. "
                "Prompt injection can chain these into a data exfiltration path."
            ),
            detail=f"Internal-read: {', '.join(internal)} | External-write: {', '.join(external)}",
        )
    return None


def _rule_code_execution(ctx: McpContext) -> McpFinding | None:
    """CRITICAL: server exposes code execution tools. (OWASP LLM01, LLM06)"""
    exec_tools = [t.name for t in ctx.server.tools if t.category == "code_execution"]
    if exec_tools:
        return McpFinding(
            severity="CRITICAL",
            rule_id="CODE_EXECUTION_TOOL",
            message=(
                "Server exposes code-execution tools. "
                "Prompt injection into any connected agent grants full host execution."
            ),
            detail=f"Execution tools: {', '.join(exec_tools)}",
        )
    return None


def _rule_unbounded_input(ctx: McpContext) -> McpFinding | None:
    """HIGH: dangerous string parameters have no input constraints. (OWASP LLM01)

    Only flags parameters whose names suggest they feed dangerous operations —
    shell commands, SQL queries, file paths, URLs, code. Generic string fields
    (name, title, message, body) are not flagged.
    """
    _DANGEROUS_PARAMS = frozenset({
        "command", "cmd", "shell", "shell_command",
        "query", "sql", "sql_query", "expression",
        "path", "file_path", "filepath", "filename", "directory", "dir",
        "url", "uri", "endpoint", "webhook", "target",
        "code", "script", "template", "prompt",
    })

    unvalidated: list[str] = []
    for tool in ctx.server.tools:
        props = tool.input_schema.get("properties", {})
        for prop_name, prop_def in props.items():
            if prop_name.lower() not in _DANGEROUS_PARAMS:
                continue
            if (
                prop_def.get("type") == "string"
                and "maxLength" not in prop_def
                and "enum" not in prop_def
                and "pattern" not in prop_def
            ):
                unvalidated.append(f"{tool.name}.{prop_name}")

    if unvalidated:
        sample = unvalidated[:5]
        suffix = "…" if len(unvalidated) > 5 else ""
        return McpFinding(
            severity="HIGH",
            rule_id="UNBOUNDED_INPUT",
            message=(
                "Dangerous parameters (command, path, query, url, code) accept unconstrained "
                "string input. No maxLength, enum, or pattern — injection payloads pass through directly."
            ),
            detail=f"Unconstrained dangerous inputs: {', '.join(sample)}{suffix}",
        )
    return None


def _rule_tool_sprawl(ctx: McpContext) -> McpFinding | None:
    """MEDIUM: high tool count across many categories increases blast radius. (OWASP LLM06)

    Requires BOTH high count AND diverse categories. A server with 14 file-system
    tools is a focused file manager. A server with 12 tools spanning code execution,
    email, database, and web is a broad attack surface.
    """
    categories = {t.category for t in ctx.server.tools} - {"other"}
    if len(ctx.server.tools) > 10 and len(categories) >= 5:
        return McpFinding(
            severity="MEDIUM",
            rule_id="TOOL_SPRAWL",
            message=(
                f"Server exposes {len(ctx.server.tools)} tools across {len(categories)} "
                "distinct categories. High cross-category diversity increases blast radius."
            ),
            detail=f"Categories: {', '.join(sorted(categories))}",
        )
    return None


def _rule_vague_descriptions(ctx: McpContext) -> McpFinding | None:
    """MEDIUM: missing or single-word tool descriptions expand prompt injection surface. (OWASP LLM01)

    Flags descriptions with fewer than 3 words — empty, one-word, or two-word
    descriptions give the LLM no context about what the tool does or what it
    should NOT do.
    """
    vague = [
        t.name for t in ctx.server.tools
        if len(t.description.strip().split()) < 3
    ]
    if len(vague) >= 2:
        return McpFinding(
            severity="MEDIUM",
            rule_id="VAGUE_TOOL_DESCRIPTIONS",
            message=(
                "Multiple tools have absent or near-absent descriptions (fewer than 3 words). "
                "Without clear descriptions the LLM cannot reason about safe tool use."
            ),
            detail=f"Absent descriptions: {', '.join(vague[:5])}{'…' if len(vague) > 5 else ''}",
        )
    return None


_ALL_RULES = [
    # CRITICAL
    _rule_no_auth,
    _rule_unauth_dangerous,
    _rule_exfiltration_path,
    _rule_code_execution,
    # HIGH
    _rule_unbounded_input,
    # MEDIUM
    _rule_tool_sprawl,
    _rule_vague_descriptions,
]

_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}


def run_mcp_rules(ctx: McpContext) -> list[McpFinding]:
    """Run all MCP security rules and return deduplicated findings."""
    findings: list[McpFinding] = []
    seen: set[str] = set()
    for rule_fn in _ALL_RULES:
        finding = rule_fn(ctx)
        if finding and finding.rule_id not in seen:
            findings.append(finding)
            seen.add(finding.rule_id)
    return findings


def mcp_posture_score(findings: list[McpFinding]) -> int:
    """0–100 posture score — same deduction weights as the platform Trust Score."""
    deductions = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return max(0, 100 - deductions)

"""Standalone posture rules — no database required, works purely on static analysis."""

import dataclasses
from agentsentinel_cli.scanner import AgentInfo, ToolInfo


@dataclasses.dataclass
class Finding:
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW
    rule_id: str
    message: str
    detail: str = ""


_INTERNAL_READ_KW = {"db", "database", "crm", "file", "filesystem", "s3_read", "storage_read", "read_file"}
_EXTERNAL_WRITE_KW = {"email", "smtp", "webhook", "http_post", "http_external", "s3_write", "send", "slack"}
_READ_PURPOSE_WORDS = {"read", "search", "query", "view", "lookup", "fetch", "get", "retrieve"}
_CODE_EXEC_CATEGORIES = {"code_execution"}
_SECRETS_CATEGORIES = {"secrets"}
_ADMIN_CATEGORIES = {"admin"}
_INFRA_CATEGORIES = {"infrastructure"}
_WEB_CATEGORIES = {"web"}


def _rule_exfiltration_path(agent: AgentInfo) -> Finding | None:
    tool_names = {t.name.lower() for t in agent.tools}
    internal_hits = [n for n in tool_names if any(kw in n for kw in _INTERNAL_READ_KW)]
    external_hits = [n for n in tool_names if any(kw in n for kw in _EXTERNAL_WRITE_KW)]
    if internal_hits and external_hits:
        return Finding(
            severity="CRITICAL",
            rule_id="EXFILTRATION_PATH",
            message="Agent holds both internal-read and external-write grants.",
            detail=f"Internal-read: {', '.join(internal_hits)} | External-write: {', '.join(external_hits)}",
        )
    return None


def _rule_code_execution_grant(agent: AgentInfo) -> Finding | None:
    """CRITICAL: agent holds code execution tools — arbitrary code paths are high-risk."""
    exec_tools = [t.name for t in agent.tools if t.category in _CODE_EXEC_CATEGORIES]
    if exec_tools:
        return Finding(
            severity="CRITICAL",
            rule_id="CODE_EXECUTION_GRANT",
            message="Agent holds code-execution grants. Arbitrary code execution enables full host compromise.",
            detail=f"Execution tools: {', '.join(exec_tools)}",
        )
    return None


def _rule_hardcoded_credentials(agent: AgentInfo) -> Finding | None:
    """CRITICAL: hardcoded API keys or secrets detected in source code."""
    if agent.hardcoded_creds:
        return Finding(
            severity="CRITICAL",
            rule_id="HARDCODED_CREDENTIALS",
            message="Hardcoded credentials detected. Rotate immediately and move to environment variables.",
            detail="; ".join(agent.hardcoded_creds),
        )
    return None


def _rule_secrets_access_grant(agent: AgentInfo) -> Finding | None:
    """HIGH: agent has tools that read secrets, vaults, or credentials at runtime."""
    secrets_tools = [t.name for t in agent.tools if t.category in _SECRETS_CATEGORIES]
    if secrets_tools:
        return Finding(
            severity="HIGH",
            rule_id="SECRETS_ACCESS_GRANT",
            message="Agent holds secrets-access grants. Verify this agent needs runtime access to credentials.",
            detail=f"Secrets tools: {', '.join(secrets_tools)}",
        )
    return None


def _rule_prompt_injection_vector(agent: AgentInfo) -> Finding | None:
    """HIGH: agent reads from untrusted web sources AND holds write grants — injection-to-write path."""
    has_web_read = any(t.category in _WEB_CATEGORIES for t in agent.tools)
    write_tools = [t.name for t in agent.tools if t.scope == "write"]
    if has_web_read and write_tools:
        return Finding(
            severity="HIGH",
            rule_id="PROMPT_INJECTION_VECTOR",
            message=(
                "Agent reads from web (untrusted input) and holds write grants — "
                "prompt injection could redirect write operations."
            ),
            detail=f"Write grants: {', '.join(write_tools)}",
        )
    return None


def _rule_lateral_movement_path(agent: AgentInfo) -> Finding | None:
    """HIGH: agent combines admin/IAM grants with network or infrastructure tools."""
    admin_tools = [t.name for t in agent.tools if t.category in _ADMIN_CATEGORIES]
    infra_tools = [t.name for t in agent.tools if t.category in _INFRA_CATEGORIES]
    if admin_tools and infra_tools:
        return Finding(
            severity="HIGH",
            rule_id="LATERAL_MOVEMENT_PATH",
            message=(
                "Agent holds admin/IAM grants alongside infrastructure grants — "
                "potential lateral movement via privilege escalation."
            ),
            detail=f"Admin: {', '.join(admin_tools)} | Infra: {', '.join(infra_tools)}",
        )
    return None


def _rule_unbounded_file_access(agent: AgentInfo) -> Finding | None:
    """HIGH: agent holds filesystem write grants with no description restricting scope."""
    fs_write = [
        t.name for t in agent.tools
        if t.category == "filesystem" and t.scope == "write"
    ]
    if fs_write and not agent.description:
        return Finding(
            severity="HIGH",
            rule_id="UNBOUNDED_FILE_ACCESS",
            message=(
                "Agent holds filesystem write grants with no description. "
                "Without scoped intent, write access is effectively unbounded."
            ),
            detail=f"Filesystem write tools: {', '.join(fs_write)}",
        )
    return None


def _rule_privilege_excess(agent: AgentInfo) -> Finding | None:
    if not agent.description:
        return None
    desc = agent.description.lower()
    if not any(w in desc for w in _READ_PURPOSE_WORDS):
        return None
    elevated = [t.name for t in agent.tools if t.scope in ("write",) or t.is_dangerous]
    if elevated:
        return Finding(
            severity="HIGH",
            rule_id="PRIVILEGE_EXCESS",
            message="Agent description implies read-only purpose but holds write/dangerous grants.",
            detail=f"Elevated grants: {', '.join(elevated)}",
        )
    return None


def _rule_dangerous_grants(agent: AgentInfo) -> Finding | None:
    dangerous = [t.name for t in agent.tools if t.is_dangerous]
    if dangerous:
        return Finding(
            severity="HIGH",
            rule_id="DANGEROUS_GRANTS",
            message="Agent holds dangerous tool grants. Verify intent and add rate limits.",
            detail=f"Dangerous tools: {', '.join(dangerous)}",
        )
    return None


def _rule_tool_sprawl(agent: AgentInfo) -> Finding | None:
    """MEDIUM: agent holds too many tools across too many categories — blast radius scales with sprawl."""
    categories = {t.category for t in agent.tools if t.category != "other"}
    if len(agent.tools) > 10 or len(categories) >= 5:
        return Finding(
            severity="MEDIUM",
            rule_id="TOOL_SPRAWL",
            message=(
                f"Agent holds {len(agent.tools)} tools across {len(categories)} categories. "
                "Reduce grants to the minimum required for each task."
            ),
            detail=f"Categories present: {', '.join(sorted(categories))}",
        )
    return None


def _rule_write_without_description(agent: AgentInfo) -> Finding | None:
    write_tools = [t.name for t in agent.tools if t.scope == "write"]
    if write_tools and not agent.description:
        return Finding(
            severity="MEDIUM",
            rule_id="UNDESCRIBED_WRITE_AGENT",
            message="Agent has write-scope grants but no description.",
            detail=(
                f"Write tools: {', '.join(write_tools)}. "
                "Add a description so posture rules can assess intent."
            ),
        )
    return None


def _rule_missing_rate_limit(agent: AgentInfo) -> Finding | None:
    """Flag dangerous tools — rate limits aren't visible in static analysis."""
    dangerous = [t.name for t in agent.tools if t.is_dangerous]
    if dangerous:
        return Finding(
            severity="LOW",
            rule_id="MISSING_RATE_LIMIT",
            message="Dangerous grants detected. Ensure rate limits are configured at runtime.",
            detail=f"Tools to check: {', '.join(dangerous)}",
        )
    return None


_ALL_RULES = [
    # CRITICAL
    _rule_exfiltration_path,
    _rule_code_execution_grant,
    _rule_hardcoded_credentials,
    # HIGH
    _rule_secrets_access_grant,
    _rule_prompt_injection_vector,
    _rule_lateral_movement_path,
    _rule_unbounded_file_access,
    _rule_privilege_excess,
    _rule_dangerous_grants,
    # MEDIUM
    _rule_tool_sprawl,
    _rule_write_without_description,
    # LOW
    _rule_missing_rate_limit,
]

_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}


def run_rules(agent: AgentInfo) -> list[Finding]:
    findings = []
    seen_rules: set[str] = set()
    for rule_fn in _ALL_RULES:
        f = rule_fn(agent)
        if f and f.rule_id not in seen_rules:
            findings.append(f)
            seen_rules.add(f.rule_id)
    return findings


def posture_score(findings: list[Finding]) -> int:
    """Calculate posture score (0-100) from findings, same formula as the platform."""
    deductions = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return max(0, 100 - deductions)

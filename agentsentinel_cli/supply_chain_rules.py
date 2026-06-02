"""Supply chain security rules for MCP tool manifests.

Covers ASI04 (Agentic Supply Chain Compromise) from OWASP Top 10 for
Agentic Applications 2026: tool schema poisoning, deceptive descriptions,
capability concealment, and registry drift.
"""

import dataclasses
import hashlib
import json
import datetime
from typing import Any

from agentsentinel_cli.mcp_client import McpServerInfo, McpToolInfo


@dataclasses.dataclass
class SupplyChainFinding:
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW
    rule_id: str
    message: str
    detail: str = ""
    tool_name: str = ""


@dataclasses.dataclass
class SupplyChainContext:
    server: McpServerInfo
    baseline: dict[str, Any] | None = None


# ── Detection sets ────────────────────────────────────────────────────────────

_INJECTION_PHRASES = [
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "you must",
    "from now on",
    "[inst]",
    "[/inst]",
    "system:",
    "assistant:",
    "###instruction",
    "###system",
    "<|system|>",
    "<|assistant|>",
    "forget your instructions",
    "override your",
    "new instructions:",
    "your new role",
    "act as if",
    "pretend you are",
]

_READ_NAME_PREFIXES = (
    "get_", "fetch_", "list_", "read_", "query_", "search_", "find_",
    "show_", "view_", "describe_", "check_", "inspect_",
)

_READ_EXACT_NAMES = frozenset({
    "get", "fetch", "list", "read", "query", "search", "find",
    "show", "view", "describe", "check", "inspect",
})

_BENIGN_NAMES = frozenset({
    "help", "assist", "format", "summarize", "summarise", "translate",
    "convert", "process", "handle", "respond", "answer", "reply",
})

_NETWORK_SCHEMA_FIELDS = frozenset({
    "url", "endpoint", "webhook", "callback", "destination",
    "host", "uri", "api_url", "base_url", "target_url",
})

_NETWORK_DESC_KEYWORDS = frozenset({
    "http", "url", "endpoint", "webhook", "send to", "external",
    "api call", "request", "post to", "network", "remote",
})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _schema_fields(tool: McpToolInfo) -> set[str]:
    return {k.lower() for k in tool.input_schema.get("properties", {})}


def schema_hash(tool: McpToolInfo) -> str:
    return hashlib.sha256(
        json.dumps(tool.input_schema, sort_keys=True).encode()
    ).hexdigest()[:16]


# ── Rules ─────────────────────────────────────────────────────────────────────

def _rule_description_injection(ctx: SupplyChainContext) -> list[SupplyChainFinding]:
    """CRITICAL: tool description contains adversarial LLM-targeting instructions."""
    findings = []
    for tool in ctx.server.tools:
        desc_lower = tool.description.lower()
        for phrase in _INJECTION_PHRASES:
            if phrase in desc_lower:
                findings.append(SupplyChainFinding(
                    severity="CRITICAL",
                    rule_id="SC01_DESCRIPTION_INJECTION",
                    tool_name=tool.name,
                    message=(
                        f"Tool '{tool.name}' description contains adversarial LLM instruction. "
                        "Tool manifest may have been tampered with to redirect agent behavior."
                    ),
                    detail=f"Phrase detected: '{phrase}'",
                ))
                break
    return findings


def _rule_name_capability_mismatch(ctx: SupplyChainContext) -> list[SupplyChainFinding]:
    """HIGH: tool name implies read-only but actual capability is write or dangerous."""
    findings = []
    for tool in ctx.server.tools:
        name_lower = tool.name.lower()
        is_read_name = (
            any(name_lower.startswith(p) for p in _READ_NAME_PREFIXES)
            or name_lower in _READ_EXACT_NAMES
        )
        if is_read_name and (tool.scope == "write" or tool.is_dangerous):
            findings.append(SupplyChainFinding(
                severity="HIGH",
                rule_id="SC02_NAME_CAPABILITY_MISMATCH",
                tool_name=tool.name,
                message=(
                    f"Tool '{tool.name}' has a read-only name but "
                    f"{'dangerous' if tool.is_dangerous else 'write'} capability. "
                    "Agents will invoke it without proper scrutiny."
                ),
                detail=(
                    f"Name implies read-only · "
                    f"Actual scope: {tool.scope} · "
                    f"Dangerous: {tool.is_dangerous}"
                ),
            ))
    return findings


def _rule_hidden_network_fields(ctx: SupplyChainContext) -> list[SupplyChainFinding]:
    """HIGH: schema accepts network destination fields not disclosed in description."""
    findings = []
    for tool in ctx.server.tools:
        fields = _schema_fields(tool)
        hidden = fields & _NETWORK_SCHEMA_FIELDS
        if not hidden:
            continue
        desc_lower = tool.description.lower()
        mentions_network = any(kw in desc_lower for kw in _NETWORK_DESC_KEYWORDS)
        if not mentions_network:
            findings.append(SupplyChainFinding(
                severity="HIGH",
                rule_id="SC03_HIDDEN_NETWORK_FIELDS",
                tool_name=tool.name,
                message=(
                    f"Tool '{tool.name}' schema accepts network destination fields "
                    "not disclosed in the description. Agents may invoke this tool "
                    "without knowing it makes external network calls."
                ),
                detail=f"Undisclosed network fields in schema: {', '.join(sorted(hidden))}",
            ))
    return findings


def _rule_schema_missing_on_write(ctx: SupplyChainContext) -> list[SupplyChainFinding]:
    """HIGH: write/dangerous tool has no input schema — accepts arbitrary input."""
    findings = []
    for tool in ctx.server.tools:
        if not (tool.scope == "write" or tool.is_dangerous):
            continue
        props = tool.input_schema.get("properties", {})
        schema_type = tool.input_schema.get("type")
        has_schema = bool(props) or (schema_type and schema_type != "object")
        if not has_schema:
            findings.append(SupplyChainFinding(
                severity="HIGH",
                rule_id="SC04_SCHEMA_MISSING_ON_WRITE",
                tool_name=tool.name,
                message=(
                    f"Write/dangerous tool '{tool.name}' declares no input schema. "
                    "No validation layer — accepts arbitrary input. "
                    "Injection payloads can be passed directly through tool arguments."
                ),
                detail=f"Scope: {tool.scope} · Dangerous: {tool.is_dangerous}",
            ))
    return findings


def _rule_deceptive_benign_name(ctx: SupplyChainContext) -> list[SupplyChainFinding]:
    """MEDIUM: tool has benign-sounding name but exposes dangerous capability."""
    findings = []
    for tool in ctx.server.tools:
        name_lower = tool.name.lower().replace("_", "")
        is_benign = tool.name.lower() in _BENIGN_NAMES or name_lower in _BENIGN_NAMES
        if is_benign and (tool.is_dangerous or tool.category == "code_execution"):
            findings.append(SupplyChainFinding(
                severity="MEDIUM",
                rule_id="SC05_DECEPTIVE_BENIGN_NAME",
                tool_name=tool.name,
                message=(
                    f"Tool '{tool.name}' has a benign-sounding name but exposes "
                    f"{'code execution' if tool.category == 'code_execution' else 'dangerous'} "
                    "capability. Deceptive naming is a key supply chain compromise indicator."
                ),
                detail=f"Category: {tool.category} · Dangerous: {tool.is_dangerous}",
            ))
    return findings


def _rule_registry_drift(ctx: SupplyChainContext) -> list[SupplyChainFinding]:
    """CRITICAL: tools added, removed, or modified since baseline was recorded."""
    if ctx.baseline is None:
        return []

    findings = []
    baseline_tools: dict[str, dict] = {t["name"]: t for t in ctx.baseline.get("tools", [])}
    current_tools: dict[str, McpToolInfo] = {t.name: t for t in ctx.server.tools}

    for name in current_tools:
        if name not in baseline_tools:
            findings.append(SupplyChainFinding(
                severity="CRITICAL",
                rule_id="SC06_REGISTRY_DRIFT",
                tool_name=name,
                message=f"Tool '{name}' was added since the baseline was recorded.",
                detail="New tool not present in baseline — verify this addition is authorized.",
            ))

    for name in baseline_tools:
        if name not in current_tools:
            findings.append(SupplyChainFinding(
                severity="CRITICAL",
                rule_id="SC06_REGISTRY_DRIFT",
                tool_name=name,
                message=f"Tool '{name}' was removed since the baseline was recorded.",
                detail="Tool present in baseline is now missing — may indicate tampering.",
            ))

    for name, tool in current_tools.items():
        if name not in baseline_tools:
            continue
        bl = baseline_tools[name]
        cur_hash = schema_hash(tool)
        if bl.get("schema_hash") != cur_hash:
            findings.append(SupplyChainFinding(
                severity="CRITICAL",
                rule_id="SC06_REGISTRY_DRIFT",
                tool_name=name,
                message=f"Tool '{name}' input schema changed since the baseline.",
                detail=(
                    f"Baseline schema hash: {bl.get('schema_hash', 'none')} → "
                    f"Current: {cur_hash}"
                ),
            ))
        elif bl.get("description") != tool.description:
            findings.append(SupplyChainFinding(
                severity="CRITICAL",
                rule_id="SC06_REGISTRY_DRIFT",
                tool_name=name,
                message=f"Tool '{name}' description changed since the baseline.",
                detail=(
                    "Description drift detected — agent behavior driven by this "
                    "tool may have changed without a code deployment."
                ),
            ))

    return findings


# ── Runner ────────────────────────────────────────────────────────────────────

_ALL_RULES = [
    _rule_description_injection,
    _rule_name_capability_mismatch,
    _rule_hidden_network_fields,
    _rule_schema_missing_on_write,
    _rule_deceptive_benign_name,
    _rule_registry_drift,
]

_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}


def run_supply_chain_rules(ctx: SupplyChainContext) -> list[SupplyChainFinding]:
    findings: list[SupplyChainFinding] = []
    for rule_fn in _ALL_RULES:
        findings.extend(rule_fn(ctx))
    return findings


def supply_chain_score(findings: list[SupplyChainFinding]) -> int:
    deductions = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return max(0, 100 - deductions)


def make_baseline(server: McpServerInfo, target: str) -> dict:
    return {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "target": target,
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "schema_hash": schema_hash(t),
            }
            for t in server.tools
        ],
    }

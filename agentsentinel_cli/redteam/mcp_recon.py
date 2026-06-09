"""Recon module — enumerate the MCP server's full attack surface.

Runs before any active attack module. Discovers tools, resources, prompts,
and fingerprints the server implementation. Returns structured data that
other modules consume, plus INFO-level findings for the report.
"""

from __future__ import annotations

import dataclasses

from agentsentinel_cli.mcp_client import McpToolInfo
from agentsentinel_cli.redteam.models import RedTeamFinding
from agentsentinel_cli.redteam.transport import RedTeamSession


@dataclasses.dataclass
class ReconData:
    """Enumeration results shared with subsequent attack modules."""
    tools: list[McpToolInfo]
    resources: list[dict]
    prompts: list[dict]
    dangerous_tools: list[str]
    unauthenticated: bool


def run_recon(session: RedTeamSession, verbose: bool = False) -> tuple[list[RedTeamFinding], ReconData]:
    findings: list[RedTeamFinding] = []
    info = session.server_info

    resources = session.list_resources()
    prompts = session.list_prompts()

    dangerous = [t.name for t in info.tools if t.is_dangerous]

    # INFO: tool inventory
    if info.tools:
        tool_list = ", ".join(t.name for t in info.tools[:10])
        suffix = f" … (+{len(info.tools) - 10} more)" if len(info.tools) > 10 else ""
        findings.append(RedTeamFinding(
            attack_type="recon",
            severity="INFO",
            title=f"Tool inventory ({len(info.tools)} tools discovered)",
            tool_name="<server>",
            parameter=None,
            payload=None,
            evidence=f"{tool_list}{suffix}",
            exploit_scenario="Enumerating the tool surface available to an attacker.",
            mitre_id="T1595.002",
            owasp_id=None,
            confidence="HIGH",
        ))

    # INFO: resources
    if resources:
        findings.append(RedTeamFinding(
            attack_type="recon",
            severity="INFO",
            title=f"Resource endpoints exposed ({len(resources)} resources)",
            tool_name="<server>",
            parameter=None,
            payload=None,
            evidence=", ".join(r.get("uri", r.get("name", "?")) for r in resources[:5]),
            exploit_scenario="MCP resources expose data directly to agents — each URI is an attack surface.",
            mitre_id="T1595.002",
            owasp_id=None,
            confidence="HIGH",
        ))

    # INFO: prompt templates
    if prompts:
        findings.append(RedTeamFinding(
            attack_type="recon",
            severity="INFO",
            title=f"Prompt templates exposed ({len(prompts)} prompts)",
            tool_name="<server>",
            parameter=None,
            payload=None,
            evidence=", ".join(p.get("name", "?") for p in prompts[:5]),
            exploit_scenario="Prompt templates may be injectable — review each for adversarial input paths.",
            mitre_id="T1595.002",
            owasp_id=None,
            confidence="HIGH",
        ))

    # HIGH: dangerous tools exposed
    if dangerous:
        dangerous_tools_info = [t for t in info.tools if t.is_dangerous]
        tool_details: list[str] = []
        for t in dangerous_tools_info:
            params = list(t.input_schema.get("properties", {}).keys())
            param_str = f"({', '.join(params)})" if params else "(no params)"
            tool_details.append(f"{t.name} {param_str}")

        findings.append(RedTeamFinding(
            attack_type="recon",
            severity="HIGH",
            title=f"Dangerous tools in scope ({len(dangerous)} tools)",
            tool_name="<server>",
            parameter=None,
            payload=None,
            evidence="\n".join(tool_details),
            exploit_scenario=(
                "These tools perform write/delete/execute operations. "
                "Prompt injection into any connected agent can invoke them directly. "
                "Use --include-dangerous to test these tools actively."
            ),
            mitre_id="AML.T0040",
            owasp_id="ASI02",
            confidence="HIGH",
            remediation=(
                "Apply the principle of least privilege: remove tools the server does not need. "
                "Gate dangerous tools behind scope headers (X-Agent-Scopes) or separate "
                "authenticated endpoints so agents cannot invoke them via prompt injection."
            ),
        ))

    recon = ReconData(
        tools=info.tools,
        resources=resources,
        prompts=prompts,
        dangerous_tools=dangerous,
        unauthenticated=(info.transport != "stdio"),
    )
    return findings, recon

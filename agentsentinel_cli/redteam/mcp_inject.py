"""Injection module — active parameter injection attacks against MCP tools.

For each tool, for each parameter, infers the attack techniques applicable
(path traversal, SSRF, command injection, SQL injection, LLM instruction injection)
and fires real payloads. A finding is raised ONLY when a detection pattern
matches the actual response — not on errors alone.

Dangerous tools (write/delete/execute) are skipped by default.
Pass include_dangerous=True to test them.
"""

from __future__ import annotations

from agentsentinel_cli.mcp_client import McpToolInfo
from agentsentinel_cli.redteam.models import RedTeamFinding
from agentsentinel_cli.redteam.payloads import (
    build_args, find_evidence, get_payloads, infer_techniques, is_error_echo,
)
from agentsentinel_cli.redteam.transport import RedTeamSession

# MITRE + OWASP references per technique
_TECHNIQUE_META: dict[str, dict] = {
    "traverse": {
        "mitre": "T1083",
        "owasp": "ASI02",
        "severity": "CRITICAL",
        "title": "Path traversal — arbitrary file read",
        "scenario": "Attacker can read arbitrary files from the server filesystem via parameter '{param}'.",
        "remediation": (
            "Restrict file access to an explicit allowlist of base directories. "
            "Reject paths containing `..` sequences and absolute paths outside the allowed root. "
            "Use os.path.realpath() and verify the resolved path starts with the allowed base."
        ),
    },
    "ssrf": {
        "mitre": "T1090.002",
        "owasp": "ASI02",
        "severity": "CRITICAL",
        "title": "SSRF — server-side request forgery",
        "scenario": "Attacker can make the server issue requests to internal network addresses via '{param}'.",
        "remediation": (
            "Validate and allowlist permitted URL schemes and hosts. "
            "Block RFC-1918 ranges (169.254.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x) and localhost. "
            "Resolve DNS before allowlist checks to prevent TOCTOU bypasses."
        ),
    },
    "cmd": {
        "mitre": "T1059",
        "owasp": "ASI02",
        "severity": "CRITICAL",
        "title": "Command injection — OS command execution",
        "scenario": "Attacker can execute arbitrary OS commands on the host via parameter '{param}'.",
        "remediation": (
            "Never pass user-controlled input to a shell. "
            "Use subprocess with an explicit argument list (no shell=True). "
            "If shell execution is required, validate against a strict allowlist."
        ),
    },
    "sqli": {
        "mitre": "T1190",
        "owasp": "ASI02",
        "severity": "HIGH",
        "title": "SQL injection — database query manipulation",
        "scenario": "Attacker can manipulate backend SQL queries through parameter '{param}'.",
        "remediation": (
            "Use parameterized queries or a query builder. "
            "Never interpolate user input into SQL strings. "
            "Apply input length and character-set validation as a second layer."
        ),
    },
    "llm": {
        "mitre": "AML.T0051.000",
        "owasp": "ASI01",
        "severity": "HIGH",
        "title": "LLM instruction injection via tool result",
        "scenario": (
            "Tool result containing adversarial instructions flows into any connected LLM context "
            "via parameter '{param}'. Attacker-controlled input can override agent behaviour."
        ),
        "remediation": (
            "Do not reflect user-controlled parameter values verbatim in tool responses. "
            "Validate inputs and reject or strip LLM instruction patterns before processing."
        ),
    },
}


def run_inject(
    session: RedTeamSession,
    techniques: list[str],
    intensity: str,
    include_dangerous: bool,
    verbose: bool,
) -> tuple[list[RedTeamFinding], int]:
    """
    Run injection attacks. Returns (findings, total_payloads_fired).
    """
    findings: list[RedTeamFinding] = []
    attack_count = 0
    seen: set[str] = set()  # deduplicate: (tool, param, technique)

    for tool in session.server_info.tools:
        if not include_dangerous and tool.is_dangerous:
            continue

        props = tool.input_schema.get("properties", {})
        if not props:
            continue

        for param_name, param_schema in props.items():
            applicable = infer_techniques(param_name, param_schema)
            active = [t for t in applicable if t in techniques]
            if not active:
                continue

            for technique in active:
                key = f"{tool.name}:{param_name}:{technique}"
                if key in seen:
                    continue
                seen.add(key)

                payloads = get_payloads(technique, intensity)
                for payload in payloads:
                    attack_count += 1
                    args = build_args(tool.input_schema, param_name, payload)

                    try:
                        result = session.call_tool(tool.name, args)
                    except Exception:
                        continue

                    if result.auth_blocked:
                        continue

                    evidence = find_evidence(technique, result.all_text)
                    if evidence is None:
                        continue

                    meta = _TECHNIQUE_META[technique]
                    dedup_key = f"{tool.name}:{param_name}:{technique}:confirmed"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    # LLM injection via error echo is a real vector but lower confidence:
                    # the injection text enters context wrapped in an error message.
                    # Whether the connected LLM acts on it depends on its alignment.
                    if technique == "llm" and is_error_echo(result.all_text, payload):
                        findings.append(RedTeamFinding(
                            attack_type=technique,
                            severity="MEDIUM",
                            title=f"Input reflected in error response (injection vector)  —  {tool.name}.{param_name}",
                            tool_name=tool.name,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            exploit_scenario=(
                                f"Tool '{tool.name}' echoes user-controlled input verbatim in its error "
                                f"messages via parameter '{param_name}'. Adversarial LLM instructions "
                                "embedded in the input will appear in any connected agent's context window "
                                "inside an error message. Exploitation depends on whether the agent's LLM "
                                "processes error message content as instructions."
                            ),
                            mitre_id=meta["mitre"],
                            owasp_id=meta["owasp"],
                            confidence="MEDIUM",
                            remediation=(
                                "Do not echo raw user input in error messages. "
                                "Return a generic error that excludes the parameter value."
                            ),
                            request_body={"tool": tool.name, "arguments": args} if verbose else None,
                            response_body=result.raw_response[:500] if verbose else None,
                        ))
                    else:
                        findings.append(RedTeamFinding(
                            attack_type=technique,
                            severity=meta["severity"],
                            title=f"{meta['title']}  —  {tool.name}.{param_name}",
                            tool_name=tool.name,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            exploit_scenario=meta["scenario"].format(param=param_name),
                            mitre_id=meta["mitre"],
                            owasp_id=meta["owasp"],
                            confidence="HIGH",
                            remediation=meta.get("remediation"),
                            request_body={"tool": tool.name, "arguments": args} if verbose else None,
                            response_body=result.raw_response[:500] if verbose else None,
                        ))
                    break  # One confirmed finding per (tool, param, technique) is enough

    return findings, attack_count

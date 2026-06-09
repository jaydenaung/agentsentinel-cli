"""Poison module — MCP-native adversarial injection tests.

Two distinct attack surfaces:

1. STATIC — Tool description analysis
   Scans every tool's description for embedded LLM instructions that could
   manipulate any agent using this server. No tool calls needed.

2. DYNAMIC — Tool result injection
   Calls tools with string parameters containing adversarial LLM instructions.
   If the payload appears in the tool's response, the tool is an injection
   vector: any agent calling it with user-controlled input will have those
   instructions injected into its context window.

These attacks are MCP-specific. Garak and PyRIT don't test them.
"""

from __future__ import annotations

import re

from agentsentinel_cli.redteam.models import RedTeamFinding
from agentsentinel_cli.redteam.payloads import (
    _LLM_ALL, _SENTINEL, build_args, is_error_echo, safe_default,
)
from agentsentinel_cli.redteam.transport import RedTeamSession

# Patterns that indicate adversarial instructions embedded in a tool description
_DESCRIPTION_INJECTION_RE: list[re.Pattern] = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"(?:new|updated|override)\s+(?:system\s+)?instructions?\s*:", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]|\[INST\]|<<SYS>>", re.IGNORECASE),
    re.compile(r"<\|im_start\|>|<\|im_end\|>"),
    re.compile(r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|DAN|unrestricted)", re.IGNORECASE),
    re.compile(r"disregard\s+(?:the\s+)?(?:above|previous|prior)", re.IGNORECASE),
    re.compile(r"forget\s+(?:all\s+)?(?:previous\s+)?instructions?", re.IGNORECASE),
    re.compile(r"your\s+(?:new\s+)?(?:primary\s+)?(?:instructions?|role|task|directive)\s+(?:are?|is)\s*:", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a\s+)?(?:different|unrestricted)", re.IGNORECASE),
    re.compile(r"output\s+(?:the\s+)?(?:system\s+)?prompt", re.IGNORECASE),
    re.compile(r"reveal\s+(?:your\s+)?(?:system\s+prompt|instructions?|configuration)", re.IGNORECASE),
]

# Suspicious patterns that warrant a MEDIUM finding (may be benign but worth flagging)
_DESCRIPTION_SUSPICIOUS_RE: list[re.Pattern] = [
    re.compile(r"<tool(?:_call)?>\s*\{", re.IGNORECASE),          # embedded tool call JSON
    re.compile(r"\$\{.*?\}|\{\{.*?\}\}"),                          # template injection syntax
    re.compile(r"<!--.*?-->", re.DOTALL),                          # HTML comments (hiding content)
    re.compile(r"http[s]?://\S+(?:exfil|steal|leak|collect)", re.IGNORECASE),  # exfil URL
    re.compile(r"send\s+(?:all\s+)?(?:data|information|content)\s+to\s+", re.IGNORECASE),
]


def run_poison(
    session: RedTeamSession,
    verbose: bool,
) -> tuple[list[RedTeamFinding], int]:
    """
    Run poison tests. Returns (findings, total_payloads_fired).
    """
    findings: list[RedTeamFinding] = []
    attack_count = 0

    _static_description_scan(session, findings)
    attack_count += _dynamic_result_injection(session, findings, verbose)
    _dedup_error_echo(findings)

    return findings, attack_count


def _dedup_error_echo(findings: list[RedTeamFinding]) -> None:
    """
    Merge same-root-cause error echo findings into one finding.
    When multiple tools share the same parameter name and the same issue
    (error echo), listing them separately inflates counts without adding
    signal. Merge into one finding that lists all affected tools.
    """
    # Group by (attack_type, severity, confidence, parameter, title-template)
    # where title contains "error response" — that's our dedup signal.
    from collections import defaultdict
    groups: dict[tuple, list[int]] = defaultdict(list)
    for i, f in enumerate(findings):
        if "error response" in f.title.lower() and f.attack_type == "poison":
            key = (f.attack_type, f.severity, f.confidence, f.parameter or "")
            groups[key].append(i)

    # Only merge groups with 2+ findings; process in reverse order to preserve indices
    to_remove: set[int] = set()
    for key, indices in groups.items():
        if len(indices) < 2:
            continue
        primary_idx = indices[0]
        primary = findings[primary_idx]
        affected_tools = [findings[i].tool_name for i in indices]
        param = key[3]

        findings[primary_idx] = RedTeamFinding(
            attack_type=primary.attack_type,
            severity=primary.severity,
            title=(
                f"Input reflected in error responses (injection vector) — "
                f"{len(affected_tools)} tools affected"
            ),
            tool_name=", ".join(affected_tools),
            parameter=primary.parameter,
            payload=primary.payload,
            evidence=primary.evidence,
            exploit_scenario=(
                f"Tools [{', '.join(affected_tools)}] all echo user-controlled input verbatim "
                f"in error messages via the '{param}' parameter. Adversarial LLM instructions "
                "injected through any of these tools will appear in a connected agent's context "
                "window inside an error message. Whether the agent's LLM acts on error-wrapped "
                "instructions depends on its alignment and system prompt."
            ),
            mitre_id=primary.mitre_id,
            owasp_id=primary.owasp_id,
            confidence=primary.confidence,
            remediation=primary.remediation,
        )
        to_remove.update(indices[1:])

    # Remove merged duplicates (in reverse order to keep indices stable)
    for i in sorted(to_remove, reverse=True):
        findings.pop(i)


def _static_description_scan(
    session: RedTeamSession,
    findings: list[RedTeamFinding],
) -> None:
    for tool in session.server_info.tools:
        desc = tool.description or ""
        if not desc:
            continue

        for pattern in _DESCRIPTION_INJECTION_RE:
            m = pattern.search(desc)
            if m:
                snippet = desc[max(0, m.start() - 30): m.end() + 80].replace("\n", " ").strip()
                findings.append(RedTeamFinding(
                    attack_type="poison",
                    severity="CRITICAL",
                    title=f"Tool description contains adversarial LLM instructions — '{tool.name}'",
                    tool_name=tool.name,
                    parameter=None,
                    payload=None,
                    evidence=f"Matched: {snippet[:200]}",
                    exploit_scenario=(
                        f"Tool '{tool.name}' description contains instructions that manipulate any "
                        "LLM processing it. An agent using this server will execute these instructions "
                        "as if they were from its system prompt. This is a classic MCP tool poisoning attack."
                    ),
                    mitre_id="AML.T0051.001",
                    owasp_id="ASI04",
                    confidence="HIGH",
                    remediation=(
                        "Audit all tool descriptions before deployment. Remove any instructions "
                        "targeting LLM behavior ('ignore previous instructions', role overrides, etc.). "
                        "Descriptions should only describe what the tool does, never direct the model."
                    ),
                ))
                break  # One finding per tool

        for pattern in _DESCRIPTION_SUSPICIOUS_RE:
            m = pattern.search(desc)
            if m:
                snippet = desc[max(0, m.start() - 20): m.end() + 60].replace("\n", " ").strip()
                findings.append(RedTeamFinding(
                    attack_type="poison",
                    severity="MEDIUM",
                    title=f"Tool description contains suspicious patterns — '{tool.name}'",
                    tool_name=tool.name,
                    parameter=None,
                    payload=None,
                    evidence=f"Matched: {snippet[:200]}",
                    exploit_scenario=(
                        f"Tool '{tool.name}' description contains patterns that may indicate "
                        "covert instructions or template injection. Review manually."
                    ),
                    mitre_id="AML.T0051.001",
                    owasp_id="ASI04",
                    confidence="MEDIUM",
                    remediation="Review tool description manually and remove any covert instruction patterns.",
                ))
                break


def _dynamic_result_injection(
    session: RedTeamSession,
    findings: list[RedTeamFinding],
    verbose: bool,
) -> int:
    """
    Call tools with LLM injection payloads and check if they're echoed back.
    A tool that reflects adversarial instructions in its output is a confirmed
    injection vector for any agent using it.
    Returns number of payloads fired.
    """
    attack_count = 0
    sentinel_pattern = re.compile(re.escape(_SENTINEL))
    seen: set[str] = set()

    # Use a small subset of LLM payloads — the sentinel-based ones are deterministic
    sentinel_payloads = [p for p in _LLM_ALL if _SENTINEL in p][:5]

    for tool in session.server_info.tools:
        if tool.name in seen:
            continue

        props = tool.input_schema.get("properties", {})
        string_params = [
            n for n, s in props.items()
            if s.get("type", "string") == "string" and "enum" not in s
        ]
        if not string_params:
            continue

        # Test the first injectable string parameter
        target_param = string_params[0]

        for payload in sentinel_payloads:
            attack_count += 1
            args = build_args(tool.input_schema, target_param, payload)

            try:
                result = session.call_tool(tool.name, args)
            except Exception:
                continue

            if result.auth_blocked:
                continue

            if sentinel_pattern.search(result.all_text):
                seen.add(tool.name)
                error_echo = is_error_echo(result.all_text, payload)

                if error_echo:
                    severity = "MEDIUM"
                    confidence = "MEDIUM"
                    title = f"Input reflected in error response (injection vector) — '{tool.name}'.{target_param}"
                    scenario = (
                        f"Tool '{tool.name}' echoes user-controlled input verbatim in its error "
                        f"messages via parameter '{target_param}'. Adversarial LLM instructions "
                        "will appear in any connected agent's context window inside an error message. "
                        "Exploitation depends on whether the agent's LLM processes error content as instructions."
                    )
                    remediation = (
                        f"Do not echo raw user input in error messages. Return a generic error "
                        f"(e.g. 'invalid path') that excludes the parameter value."
                    )
                else:
                    severity = "HIGH"
                    confidence = "HIGH"
                    title = f"LLM instruction injection vector — '{tool.name}'.{target_param}"
                    scenario = (
                        f"An attacker who controls input to '{tool.name}' can inject LLM "
                        "instructions that will be processed as trusted content by any agent "
                        "calling this tool. This enables goal hijacking without access to "
                        "the agent or its system prompt."
                    )
                    remediation = (
                        "Do not reflect user-controlled parameter values in tool responses. "
                        "Validate inputs and reject LLM instruction patterns before processing."
                    )

                findings.append(RedTeamFinding(
                    attack_type="poison",
                    severity=severity,
                    title=title,
                    tool_name=tool.name,
                    parameter=target_param,
                    payload=payload,
                    evidence=(
                        f"Sentinel string '{_SENTINEL}' found in tool response"
                        + (" (within error message)" if error_echo else " (clean response)")
                        + ". Injection text flows into connected agent context window."
                    ),
                    exploit_scenario=scenario,
                    mitre_id="AML.T0051.000",
                    owasp_id="ASI01",
                    confidence=confidence,
                    remediation=remediation,
                    request_body={"tool": tool.name, "arguments": args} if verbose else None,
                    response_body=result.raw_response[:500] if verbose else None,
                ))
                break

    return attack_count

"""Fuzz module — schema boundary and type confusion testing.

Sends malformed, out-of-range, and wrong-type inputs to every tool parameter.
Looks for:
  - Stack traces (unhandled exceptions leaking implementation details)
  - Internal file paths in error messages
  - Server version strings in errors
  - Template injection evaluation (${7*7} → 49)
  - XSS reflection in output
  - Unexpected data returned from type mismatches (info disclosure)

Fuzzing never tries to exploit — it maps undefined behavior for the red-team report.
"""

from __future__ import annotations

from agentsentinel_cli.redteam.models import RedTeamFinding
from agentsentinel_cli.redteam.payloads import (
    DETECTION, FUZZ_STRING, FUZZ_TYPE_MISMATCHES, build_args, find_evidence, safe_default,
)
from agentsentinel_cli.redteam.transport import RedTeamSession


def run_fuzz(
    session: RedTeamSession,
    verbose: bool,
) -> tuple[list[RedTeamFinding], int]:
    """
    Run fuzz tests. Returns (findings, total_payloads_fired).
    """
    findings: list[RedTeamFinding] = []
    attack_count = 0
    seen: set[str] = set()

    for tool in session.server_info.tools:
        props = tool.input_schema.get("properties", {})
        if not props:
            # Try calling with empty args to see what error we get
            attack_count += 1
            try:
                result = session.call_tool(tool.name, {})
                if not result.auth_blocked:
                    evidence = find_evidence("fuzz", result.all_text)
                    if evidence:
                        _emit(tool.name, None, "{}", evidence, result, verbose, "empty args", findings, seen)
            except Exception:
                pass
            continue

        # String parameter fuzzing
        for param_name, param_schema in props.items():
            if param_schema.get("type", "string") != "string":
                continue
            if "enum" in param_schema:
                continue

            for fuzz_val in FUZZ_STRING:
                attack_count += 1
                args = build_args(tool.input_schema, param_name, fuzz_val)
                try:
                    result = session.call_tool(tool.name, args)
                except Exception:
                    continue
                if result.auth_blocked:
                    continue

                evidence = find_evidence("fuzz", result.all_text)
                reflection_evidence = _find_reflection(result.all_text)
                combined_evidence = evidence or reflection_evidence
                if combined_evidence:
                    label = repr(fuzz_val[:30]) if len(fuzz_val) <= 30 else f'"{fuzz_val[:20]}…"'
                    _emit(
                        tool.name, param_name, label, combined_evidence, result, verbose,
                        fuzz_val, findings, seen,
                        is_reflection=(reflection_evidence is not None and evidence is None),
                    )
                    break  # One fuzz finding per (tool, param)

        # Type mismatch fuzzing — send wrong types for each parameter
        for param_name, param_schema in props.items():
            for wrong_val in FUZZ_TYPE_MISMATCHES:
                attack_count += 1
                args = build_args(tool.input_schema, param_name, wrong_val)
                try:
                    result = session.call_tool(tool.name, args)
                except Exception:
                    continue
                if result.auth_blocked:
                    continue

                evidence = find_evidence("fuzz", result.all_text)
                if evidence:
                    key = f"{tool.name}:{param_name}:type_mismatch"
                    _emit(tool.name, param_name, repr(wrong_val), evidence, result, verbose,
                          wrong_val, findings, seen, dedup_key=key)
                    break

    return findings, attack_count


def _find_reflection(text: str) -> str | None:
    """Check for input reflection patterns (XSS probe echoed, template not evaluated)."""
    if not text:
        return None
    for pattern in DETECTION.get("reflection", []):
        m = pattern.search(text)
        if m:
            start = max(0, m.start() - 20)
            end = min(len(text), m.end() + 60)
            return text[start:end].replace("\n", "  ").strip()[:200]
    return None


def _emit(
    tool_name: str,
    param: str | None,
    payload_label: str,
    evidence: str,
    result,
    verbose: bool,
    raw_payload: object,
    findings: list[RedTeamFinding],
    seen: set[str],
    dedup_key: str | None = None,
    is_reflection: bool = False,
) -> None:
    key = dedup_key or f"{tool_name}:{param}:{payload_label}"
    if key in seen:
        return
    seen.add(key)

    is_trace = any(kw in evidence for kw in (
        "Traceback", "at line", "Exception", "panic:", "NullPointer"
    ))
    is_template = "49" in evidence or "REDTEAM" in evidence
    is_path = any(c in evidence for c in ("/home/", "/Users/", "/var/", "/opt/", "C:\\Users"))

    if is_reflection:
        severity, title = "MEDIUM", "Input reflected in error response (no HTML encoding)"
        scenario = (
            f"Tool '{tool_name}' echoes user-controlled input without sanitization via parameter '{param}'. "
            "Reflected content enters any connected agent's context window directly, making this an "
            "injection vector for adversarial instructions embedded in the input."
        )
        remediation = (
            "Sanitize user input before including it in error messages. "
            "Strip or HTML-encode special characters in all error responses."
        )
    elif is_trace:
        severity, title = "HIGH", "Unhandled exception — stack trace leaked"
        scenario = (
            f"Tool '{tool_name}' leaks a server-side stack trace on invalid input. "
            "Stack traces reveal internal paths, library versions, and code structure "
            "that attackers use to craft further exploits."
        )
        remediation = (
            "Catch all exceptions server-side and return a generic error message. "
            "Never expose stack traces, internal paths, or library names to clients."
        )
    elif is_template:
        severity, title = "HIGH", "Template/expression injection confirmed"
        scenario = (
            f"Tool '{tool_name}' evaluated a template expression in user-controlled input. "
            "Server-side template injection can escalate to arbitrary code execution."
        )
        remediation = (
            "Disable server-side template evaluation of user-controlled strings. "
            "Use a templating engine that escapes by default and never eval user input."
        )
    elif is_path:
        severity, title = "MEDIUM", "Internal file path leaked in error response"
        scenario = (
            f"Tool '{tool_name}' exposes an internal filesystem path in its error response. "
            "Attackers use path disclosure to target specific files in traversal attacks."
        )
        remediation = (
            "Sanitize error messages to exclude internal filesystem paths. "
            "Return 'invalid input' without path context."
        )
    else:
        severity, title = "LOW", "Unexpected information in fuzz response"
        scenario = f"Tool '{tool_name}' returned unexpected content in response to malformed input."
        remediation = "Review what the tool returns on unexpected input and tighten input validation."

    param_str = f".{param}" if param else ""
    findings.append(RedTeamFinding(
        attack_type="fuzz",
        severity=severity,
        title=f"{title}  —  {tool_name}{param_str}",
        tool_name=tool_name,
        parameter=param,
        payload=payload_label,
        evidence=evidence,
        exploit_scenario=scenario,
        mitre_id="T1592.002",
        owasp_id="ASI03",
        confidence="HIGH",
        remediation=remediation,
        request_body={"tool": tool_name, "payload": repr(raw_payload)[:100]} if verbose else None,
        response_body=result.raw_response[:500] if verbose else None,
    ))

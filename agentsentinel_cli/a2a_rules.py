"""Trust rules for multi-agent call graphs.

Each rule receives the full A2AGraph and returns zero or more findings.
Rules operate on structure — they can detect what's absent (no verification code,
no tool scoping) and what's dangerous (cycles, code execution, user input flow).

OWASP mapping: all rules map to ASI07 (Insecure Inter-Agent Communication)
with secondary mappings to ASI01 (Goal Hijack) and ASI05 (Code Execution).
"""

from __future__ import annotations

import dataclasses

from agentsentinel_cli.a2a_scanner import A2AGraph, AgentNode, A2AEdge


@dataclasses.dataclass
class A2AFinding:
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW
    rule_id: str
    message: str
    detail: str = ""
    node_name: str = ""   # the agent most relevant to this finding
    owasp: str = "ASI07"


# ── Rules ─────────────────────────────────────────────────────────────────────

def _rule_circular_delegation(graph: A2AGraph) -> list[A2AFinding]:
    """
    A2A06_CIRCULAR_DELEGATION — a cycle exists in the call graph.

    Why dangerous: a cycle means agent A's output can flow back to agent A
    as input. Under prompt injection, an attacker's payload can circulate
    indefinitely, escalating privilege or causing unbounded execution.
    Also creates an infinite loop risk if no exit condition is properly enforced.
    """
    if not graph.has_cycles:
        return []

    # Find one cycle to report concretely
    adj: dict[str, list[str]] = {}
    for e in graph.edges:
        adj.setdefault(e.caller, []).append(e.callee)

    cycle_path: list[str] = []

    def _find_cycle(node: str, path: list[str], visited: set[str]) -> bool:
        visited.add(node)
        path.append(node)
        for nb in adj.get(node, []):
            if nb in visited and nb in path:
                idx = path.index(nb)
                cycle_path.extend(path[idx:] + [nb])
                return True
            if nb not in visited:
                if _find_cycle(nb, path, visited):
                    return True
        path.pop()
        return False

    visited: set[str] = set()
    for n in graph.nodes:
        if n.name not in visited:
            _find_cycle(n.name, [], visited)
            if cycle_path:
                break

    cycle_str = " → ".join(cycle_path) if cycle_path else "cycle detected"
    return [A2AFinding(
        severity="HIGH",
        rule_id="A2A06_CIRCULAR_DELEGATION",
        message="Cycle detected in the agent call graph — agents can loop indefinitely.",
        detail=f"Cycle path: {cycle_str}",
        owasp="ASI07",
    )]


def _rule_unbounded_spawning(graph: A2AGraph) -> list[A2AFinding]:
    """
    A2A02_UNBOUNDED_SPAWNING — an agent is constructed inside a loop body.

    Why dangerous: each loop iteration creates a new LLM-backed agent with
    its own tool grants. If a prompt injection payload controls the loop input
    (e.g. a list of 'tasks'), the attacker can cause unbounded agent creation,
    API cost explosion, and parallel execution of injected instructions.
    """
    findings = []
    for node in graph.nodes:
        if node.spawned_in_loop:
            findings.append(A2AFinding(
                severity="HIGH",
                rule_id="A2A02_UNBOUNDED_SPAWNING",
                message=f"Agent '{node.name}' is instantiated inside a loop — unbounded agent spawning.",
                detail=(
                    f"Framework: {node.framework}  File: {node.file}:{node.line}. "
                    "Add a depth/count limit or pre-instantiate agents outside the loop."
                ),
                node_name=node.name,
                owasp="ASI07",
            ))
    return findings


def _rule_prompt_passthrough(graph: A2AGraph) -> list[A2AFinding]:
    """
    A2A04_PROMPT_PASSTHROUGH — user input flows directly across an agent boundary.

    Why dangerous: if Agent A receives user input and passes it unmodified to
    Agent B, any prompt injection payload in the user input reaches Agent B.
    Agent B may have different (weaker) defenses, different tool grants, or
    no knowledge that the input originated from an untrusted user.
    This is the primary injection propagation path in multi-agent systems.
    """
    findings = []
    seen: set[tuple[str, str]] = set()
    for edge in graph.edges:
        if not edge.passes_user_input:
            continue
        key = (edge.caller, edge.callee)
        if key in seen:
            continue
        seen.add(key)
        findings.append(A2AFinding(
            severity="HIGH",
            rule_id="A2A04_PROMPT_PASSTHROUGH",
            message=(
                f"User input flows directly from '{edge.caller}' to '{edge.callee}' "
                "without sanitization at the agent boundary."
            ),
            detail=(
                f"Call type: {edge.call_type}  File: {edge.file}:{edge.line}. "
                "Validate or reframe user input before passing it to sub-agents."
            ),
            node_name=edge.caller,
            owasp="ASI01",
        ))
    return findings


def _rule_unscoped_delegation(graph: A2AGraph) -> list[A2AFinding]:
    """
    A2A05_UNSCOPED_DELEGATION — orchestrator passes its full tool set to a sub-agent.

    Why dangerous: the blast radius of a compromised sub-agent equals the blast
    radius of the orchestrator. If the sub-agent is manipulated via injection,
    it has every tool the orchestrator has — including dangerous ones. The correct
    pattern is to give each sub-agent only the tools it needs for its specific role.
    """
    findings = []
    for edge in graph.edges:
        if edge.callee_tools_scoped:
            continue
        callee_node = next((n for n in graph.nodes if n.name == edge.callee), None)
        if callee_node is None:
            continue
        findings.append(A2AFinding(
            severity="MEDIUM",
            rule_id="A2A05_UNSCOPED_DELEGATION",
            message=(
                f"'{edge.caller}' delegates its full tool set to sub-agent '{edge.callee}'."
            ),
            detail=(
                f"Tools delegated: {', '.join(callee_node.tools) or 'same as parent'}. "
                "Pass only the tools the sub-agent needs for its specific task."
            ),
            node_name=edge.callee,
            owasp="ASI07",
        ))
    return findings


def _rule_implicit_trust_with_code_exec(graph: A2AGraph) -> list[A2AFinding]:
    """
    A2A03_IMPLICIT_TRUST — a code-execution agent accepts calls from another agent
    with no visible trust verification.

    Why dangerous: code execution is the highest-severity capability an agent can
    hold. If a code-execution agent accepts instructions from any other agent
    unconditionally, a compromised orchestrator (or an injected instruction in
    the orchestrator's context) can cause arbitrary code execution on the host.
    This is the agentic equivalent of an unauthenticated RCE endpoint.
    """
    findings = []
    seen: set[str] = set()

    code_exec_nodes = {n.name for n in graph.nodes if n.has_code_execution}
    callees_in_edges = {e.callee for e in graph.edges}

    for node_name in code_exec_nodes:
        if node_name not in callees_in_edges:
            continue  # nobody calls this node — no inter-agent trust issue
        if node_name in seen:
            continue
        seen.add(node_name)
        callers = [e.caller for e in graph.edges if e.callee == node_name]
        findings.append(A2AFinding(
            severity="CRITICAL",
            rule_id="A2A03_IMPLICIT_TRUST",
            message=(
                f"Code-execution agent '{node_name}' accepts calls from other agents "
                "with no visible identity verification."
            ),
            detail=(
                f"Called by: {', '.join(callers)}. "
                "A compromised orchestrator can cause arbitrary code execution. "
                "Add caller identity verification before acting on delegated instructions."
            ),
            node_name=node_name,
            owasp="ASI05",
        ))
    return findings


def _rule_unverified_orchestrator(graph: A2AGraph) -> list[A2AFinding]:
    """
    A2A01_UNVERIFIED_ORCHESTRATOR — agents receive instructions from other agents
    with no visible trust boundary enforcement.

    Why dangerous: in a multi-agent system, every agent-to-agent call is a
    potential injection propagation point. If agent B blindly trusts agent A,
    then compromising agent A (via injection in its context) automatically
    compromises agent B. Unlike human-to-agent trust, agent-to-agent trust is
    invisible to the end user and rarely logged.

    This is a LOW-severity informational finding because it fires broadly.
    Operators running behind authenticated orchestration infrastructure should
    suppress this with --ignore-rule A2A01_UNVERIFIED_ORCHESTRATOR or .sentinelignore.
    """
    if not graph.edges:
        return []

    # Only fire if there are edges and none of the receiving agents is already
    # covered by A2A03 (which is CRITICAL and more specific)
    code_exec_callees = {
        n.name for n in graph.nodes
        if n.has_code_execution and n.name in {e.callee for e in graph.edges}
    }

    callee_names = {
        e.callee for e in graph.edges
        if e.callee not in code_exec_callees and e.callee != "__tool_orchestrator__"
    }
    if not callee_names:
        return []

    return [A2AFinding(
        severity="LOW",
        rule_id="A2A01_UNVERIFIED_ORCHESTRATOR",
        message=(
            f"{len(callee_names)} agent(s) receive instructions from other agents "
            "with no visible caller verification."
        ),
        detail=(
            f"Receiving agents: {', '.join(sorted(callee_names))}. "
            "No framework enforces inter-agent authentication by default. "
            "If trust is handled at the infrastructure layer, suppress this finding."
        ),
        owasp="ASI07",
    )]


# ── Runner ────────────────────────────────────────────────────────────────────

_ALL_RULES = [
    _rule_circular_delegation,
    _rule_unbounded_spawning,
    _rule_prompt_passthrough,
    _rule_implicit_trust_with_code_exec,
    _rule_unscoped_delegation,
    _rule_unverified_orchestrator,
]

_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}


def run_a2a_rules(graph: A2AGraph) -> list[A2AFinding]:
    findings: list[A2AFinding] = []
    for rule_fn in _ALL_RULES:
        findings.extend(rule_fn(graph))
    return findings


def a2a_posture_score(findings: list[A2AFinding]) -> int:
    deductions = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return max(0, 100 - deductions)

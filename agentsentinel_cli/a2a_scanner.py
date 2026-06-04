"""Multi-agent call graph scanner — detects agent nodes and trust edges via AST analysis.

Supports: LangChain/LangGraph, AutoGen, CrewAI, and generic class-based agent patterns.

Detection strategy:
  Pass 1 — collect imports so we know which class names belong to which framework.
            e.g. `from autogen import AssistantAgent` → AssistantAgent is autogen.
  Pass 2 — walk all Call and Assign nodes to extract:
            - AgentNode: each LLM-backed agent or agent executor
            - A2AEdge: each place where one agent calls or delegates to another
            - Trust indicators: does user input flow through? are tools scoped?

The resulting A2AGraph is passed to a2a_rules.py for rule evaluation and
optionally to Claude for semantic trust analysis (--ai mode, future).
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path


# ── Data models ───────────────────────────────────────────────────────────────

@dataclasses.dataclass
class AgentNode:
    """One LLM-backed agent or executor in the call graph."""
    name: str
    framework: str          # "langchain" | "langgraph" | "autogen" | "crewai" | "generic"
    role: str               # "orchestrator" | "worker" | "peer" | "unknown"
    tools: list[str]        # tool variable/function names passed to this agent
    has_code_execution: bool  # code_execution_config or exec/bash tools detected
    spawned_in_loop: bool   # constructor is inside a for/while body → unbounded spawning risk
    file: Path
    line: int


@dataclasses.dataclass
class A2AEdge:
    """A directed communication link from one agent to another."""
    caller: str             # AgentNode.name of the initiating agent
    callee: str             # AgentNode.name of the receiving agent
    call_type: str          # "initiate_chat" | "invoke" | "as_tool" | "graph_edge" | "group_member"
    passes_user_input: bool # True if the message/input arg is a variable (not a literal)
    callee_tools_scoped: bool  # True if callee received a restricted tool subset
    file: Path
    line: int


@dataclasses.dataclass
class A2AGraph:
    """Complete multi-agent call graph extracted from a codebase."""
    nodes: list[AgentNode]
    edges: list[A2AEdge]
    files: list[Path]

    @property
    def has_cycles(self) -> bool:
        """True if any cycle exists in the directed call graph (DFS)."""
        adj: dict[str, list[str]] = {}
        for e in self.edges:
            adj.setdefault(e.caller, []).append(e.callee)

        visited: set[str] = set()
        in_stack: set[str] = set()

        def _dfs(node: str) -> bool:
            visited.add(node)
            in_stack.add(node)
            for nb in adj.get(node, []):
                if nb not in visited:
                    if _dfs(nb):
                        return True
                elif nb in in_stack:
                    return True
            in_stack.discard(node)
            return False

        return any(_dfs(n.name) for n in self.nodes if n.name not in visited)

    @property
    def max_depth(self) -> int:
        """Longest call chain from any root (node with no incoming edges)."""
        has_incoming = {e.callee for e in self.edges}
        roots = [n.name for n in self.nodes if n.name not in has_incoming]
        if not roots and self.nodes:
            roots = [self.nodes[0].name]

        adj: dict[str, list[str]] = {}
        for e in self.edges:
            adj.setdefault(e.caller, []).append(e.callee)

        max_d = 0
        # BFS; track visited path to avoid infinite loops on cycles
        queue: list[tuple[str, int, frozenset[str]]] = [
            (r, 0, frozenset({r})) for r in roots
        ]
        while queue:
            node, depth, path = queue.pop(0)
            max_d = max(max_d, depth)
            for nb in adj.get(node, []):
                if nb not in path:
                    queue.append((nb, depth + 1, path | {nb}))
        return max_d


# ── Framework class → (framework_tag, default_role) ──────────────────────────
#
# When we see `AssistantAgent(...)` in source and autogen is imported,
# we know this is an autogen agent with default role "worker".
# GroupChatManager is always an orchestrator.

_AGENT_CONSTRUCTORS: dict[str, tuple[str, str]] = {
    # AutoGen
    "AssistantAgent":       ("autogen", "worker"),
    "UserProxyAgent":       ("autogen", "orchestrator"),
    "ConversableAgent":     ("autogen", "peer"),
    "GroupChatManager":     ("autogen", "orchestrator"),
    # LangChain
    "AgentExecutor":        ("langchain", "unknown"),
    # CrewAI
    "Agent":                ("crewai", "worker"),   # only if crewai import detected
    "Crew":                 ("crewai", "orchestrator"),
}

# LangGraph graph containers — handled separately from _AGENT_CONSTRUCTORS
# because they are topology containers, not individual agent nodes.
# Their nodes are registered via add_node() calls, not the constructor itself.
_GRAPH_CONTAINER_CONSTRUCTORS = frozenset({"StateGraph", "MessageGraph"})

# Frameworks that use the generic class name "Agent" — we must check imports
_CREWAI_IMPORTS = frozenset({"crewai"})

# Constructor calls that produce tool-wrapping edges (agent-as-tool pattern)
_TOOL_WRAPPER_NAMES = frozenset({"Tool", "StructuredTool"})

# AutoGen method that creates an explicit A2A edge
_INITIATE_CHAT_METHODS = frozenset({"initiate_chat", "a_initiate_chat"})

# LangGraph graph-mutation methods that define topology
_GRAPH_ADD_NODE   = "add_node"
_GRAPH_ADD_EDGE   = "add_edge"
_GRAPH_ADD_COND   = "add_conditional_edges"

# code_execution keywords that flag a node as having code execution capability
_CODE_EXEC_KWARGS = frozenset({"code_execution_config", "code_executor"})
_CODE_EXEC_TOOL_PATTERNS = ("exec", "bash", "shell", "run_code", "python_repl", "terminal")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_str(node: ast.expr | None) -> str:
    """Extract a string constant from an AST node, or '' if not a literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _get_name(node: ast.expr | None) -> str:
    """Extract a variable name from a Name or Attribute node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _kwarg(call: ast.Call, key: str) -> ast.expr | None:
    """Return the value of a keyword argument by name, or None."""
    for kw in call.keywords:
        if kw.arg == key:
            return kw.value
    return None


def _is_variable(node: ast.expr | None) -> bool:
    """True if node is a variable reference (Name), not a literal."""
    return isinstance(node, (ast.Name, ast.Attribute))


def _tools_from_kwarg(call: ast.Call) -> list[str]:
    """Extract tool names from a tools=[...] keyword argument."""
    tools_node = _kwarg(call, "tools")
    if tools_node is None:
        return []
    if isinstance(tools_node, ast.List):
        return [_get_name(elt) or _get_str(elt) for elt in tools_node.elts if elt]
    # tools=self.tools or tools=some_var — treat as single reference
    ref = _get_name(tools_node)
    return [ref] if ref else []


def _has_code_execution(call: ast.Call) -> bool:
    """True if any keyword signals code execution capability."""
    for kw in call.keywords:
        if kw.arg in _CODE_EXEC_KWARGS:
            return True
    tools = _tools_from_kwarg(call)
    return any(p in t.lower() for t in tools for p in _CODE_EXEC_TOOL_PATTERNS)


def _tools_are_scoped(call: ast.Call, parent_tool_vars: set[str]) -> bool:
    """
    True if the tools= argument is a new list (scoped subset),
    False if it references an existing variable (possibly the parent's full set).
    """
    tools_node = _kwarg(call, "tools")
    if tools_node is None:
        return True  # no tools passed — scoped by omission
    if isinstance(tools_node, ast.List):
        return True  # explicit list = scoped
    ref = _get_name(tools_node)
    # If it references a variable that is the parent's tool list, it's unscoped
    return ref not in parent_tool_vars


def _node_is_in_loop(node: ast.AST, loop_lines: set[int]) -> bool:
    """True if the AST node's line falls inside a recorded loop body line range."""
    line = getattr(node, "lineno", -1)
    return line in loop_lines


# ── Two-pass AST visitor ──────────────────────────────────────────────────────

class _A2AVisitor(ast.NodeVisitor):
    """
    Walk one Python file and extract agent nodes and edges.

    Pass 1 (via _collect_imports): record which names are imported from which
    framework so we can identify framework-specific constructors reliably.

    Pass 2 (generic_visit): visit Call nodes to detect agent construction, graph
    topology declarations, and inter-agent communication calls.
    """

    def __init__(self, file: Path) -> None:
        self.file = file
        self.nodes: list[AgentNode] = []
        self.edges: list[A2AEdge] = []

        # Map: local_name → framework (populated in pass 1)
        self._framework_names: dict[str, str] = {}
        # Map: var_name → AgentNode (to resolve callee names to nodes)
        self._var_to_node: dict[str, AgentNode] = {}
        # The variable that holds a StateGraph/MessageGraph instance
        self._graph_var: str | None = None
        # LangGraph nodes added via add_node(name, fn)
        self._graph_nodes: dict[str, AgentNode] = {}
        # Lines inside loop bodies (for spawned_in_loop detection)
        self._loop_lines: set[int] = set()
        # Known tool variable names (to detect unscoped delegation)
        self._tool_vars: set[str] = set()
        # Current assignment target name (so visit_Call knows the var being assigned)
        self._current_assign_target: str = ""
        # MCP client detection
        self._is_mcp_client: bool = False
        self._mcp_server_urls: list[tuple[str, int]] = []   # (url, lineno)
        self._string_assignments: dict[str, str] = {}       # var_name → string value

    # ── Pass 1: import collection ─────────────────────────────────────────────

    def collect_imports(self, tree: ast.AST) -> None:
        """Walk only Import/ImportFrom nodes to build _framework_names."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self._check_mcp_client_import(node.module)
                fw = self._module_to_framework(node.module)
                if fw:
                    for alias in node.names:
                        name = alias.asname or alias.name
                        self._framework_names[name] = fw
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self._check_mcp_client_import(alias.name)
                    fw = self._module_to_framework(alias.name)
                    if fw:
                        name = alias.asname or alias.name
                        self._framework_names[name] = fw

    def _check_mcp_client_import(self, module: str) -> None:
        """Flag file as an MCP client if it imports from mcp.client.*"""
        if module.startswith("mcp.client") or module in ("mcp.client",):
            self._is_mcp_client = True

    @staticmethod
    def _module_to_framework(module: str) -> str:
        """Map an import module path to a framework tag."""
        if module.startswith("autogen"):
            return "autogen"
        if module.startswith("langgraph"):
            return "langgraph"
        if module.startswith("langchain"):
            return "langchain"
        if module.startswith("crewai"):
            return "crewai"
        return ""

    # ── Pass 1b: loop line collection ─────────────────────────────────────────

    def collect_loop_lines(self, tree: ast.AST) -> None:
        """Record every line number that falls inside a for/while body."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                for child in ast.walk(node):
                    line = getattr(child, "lineno", None)
                    if line:
                        self._loop_lines.add(line)

    # ── Pass 2: node and edge detection ───────────────────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignment targets so visit_Call knows the variable being assigned."""
        if node.targets and isinstance(node.targets[0], ast.Name):
            self._current_assign_target = node.targets[0].id
            # Track string constant assignments for MCP URL resolution
            # e.g. MCP_SERVER_URL = "http://127.0.0.1:8000/sse"
            if (isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                self._string_assignments[self._current_assign_target] = node.value.value
        else:
            self._current_assign_target = ""
        self.generic_visit(node)
        self._current_assign_target = ""

    def visit_Call(self, node: ast.Call) -> None:
        func_name = _get_name(node.func)
        obj_name  = ""
        if isinstance(node.func, ast.Attribute):
            obj_name = _get_name(node.func.value)

        # ── Agent constructor detection ───────────────────────────────────────
        if func_name in _AGENT_CONSTRUCTORS:
            fw_default, role_default = _AGENT_CONSTRUCTORS[func_name]

            # For the generic "Agent" name, only treat as crewai if imported from crewai
            if func_name == "Agent":
                if self._framework_names.get("Agent") != "crewai":
                    self.generic_visit(node)
                    return

            fw   = self._framework_names.get(func_name, fw_default)
            role = role_default
            var  = self._current_assign_target or func_name

            # Detect orchestrator role for LangChain AgentExecutor
            if func_name == "AgentExecutor":
                role = "orchestrator"

            tools        = _tools_from_kwarg(node)
            has_exec     = _has_code_execution(node)
            in_loop      = _node_is_in_loop(node, self._loop_lines)

            # GroupChat collects agents — we extract peer edges from agents=[...]
            if func_name == "GroupChat":
                self._handle_groupchat(node, var)
                self.generic_visit(node)
                return

            agent = AgentNode(
                name=var,
                framework=fw,
                role=role,
                tools=tools,
                has_code_execution=has_exec,
                spawned_in_loop=in_loop,
                file=self.file,
                line=node.lineno,
            )
            self.nodes.append(agent)
            self._var_to_node[var] = agent

            # Track tool vars for delegation analysis
            for t in tools:
                self._tool_vars.add(t)

        # ── LangGraph graph container ─────────────────────────────────────────
        elif func_name in _GRAPH_CONTAINER_CONSTRUCTORS:
            if self._current_assign_target:
                self._graph_var = self._current_assign_target

        # ── LangGraph topology methods ────────────────────────────────────────
        elif func_name == _GRAPH_ADD_NODE and obj_name == self._graph_var:
            self._handle_langgraph_add_node(node)

        elif func_name == _GRAPH_ADD_EDGE and obj_name == self._graph_var:
            self._handle_langgraph_add_edge(node)

        elif func_name == _GRAPH_ADD_COND and obj_name == self._graph_var:
            self._handle_langgraph_conditional_edges(node)

        # ── AutoGen: initiate_chat ────────────────────────────────────────────
        elif func_name in _INITIATE_CHAT_METHODS:
            self._handle_initiate_chat(node, obj_name)

        # ── LangChain: agent-as-tool pattern ─────────────────────────────────
        elif func_name in _TOOL_WRAPPER_NAMES:
            self._handle_tool_wrapper(node)

        # ── CrewAI: Crew(agents=[...]) assembles the topology ─────────────────
        elif func_name == "Crew":
            self._handle_crew(node)

        # ── MCP client: sse_client(url) / streamablehttp_client(url) ─────────
        elif func_name in ("sse_client", "streamablehttp_client", "stdio_client"):
            self._handle_mcp_connect(node)

        self.generic_visit(node)

    # ── LangGraph helpers ─────────────────────────────────────────────────────

    def _handle_langgraph_add_node(self, call: ast.Call) -> None:
        """workflow.add_node("name", fn) — register a langgraph node."""
        if not call.args:
            return
        name = _get_str(call.args[0])
        if not name:
            name = _get_name(call.args[0]) or f"node_{call.lineno}"

        agent = AgentNode(
            name=name,
            framework="langgraph",
            role="peer",
            tools=[],
            has_code_execution=False,
            spawned_in_loop=_node_is_in_loop(call, self._loop_lines),
            file=self.file,
            line=call.lineno,
        )
        self.nodes.append(agent)
        self._var_to_node[name] = agent
        self._graph_nodes[name] = agent

    def _handle_langgraph_add_edge(self, call: ast.Call) -> None:
        """workflow.add_edge("from", "to") — direct edge."""
        if len(call.args) < 2:
            return
        frm = _get_str(call.args[0])
        to  = _get_str(call.args[1])
        if frm and to and to != "END":
            self.edges.append(A2AEdge(
                caller=frm,
                callee=to,
                call_type="graph_edge",
                passes_user_input=False,
                callee_tools_scoped=True,
                file=self.file,
                line=call.lineno,
            ))

    def _handle_langgraph_conditional_edges(self, call: ast.Call) -> None:
        """workflow.add_conditional_edges("from", fn, {"key": "to", ...}) — all targets."""
        if not call.args:
            return
        frm = _get_str(call.args[0])
        if not frm:
            return
        # Third argument is a dict of possible targets
        mapping = call.args[2] if len(call.args) > 2 else _kwarg(call, "path_map")
        if isinstance(mapping, ast.Dict):
            for val in mapping.values:
                to = _get_str(val)
                if to and to != "END":
                    self.edges.append(A2AEdge(
                        caller=frm,
                        callee=to,
                        call_type="graph_edge",
                        passes_user_input=False,
                        callee_tools_scoped=True,
                        file=self.file,
                        line=call.lineno,
                    ))

    # ── AutoGen helpers ───────────────────────────────────────────────────────

    def _handle_initiate_chat(self, call: ast.Call, caller_var: str) -> None:
        """agent_a.initiate_chat(agent_b, message=msg) — explicit A2A edge."""
        if not call.args:
            return
        callee_var = _get_name(call.args[0])
        if not callee_var:
            return

        # passes_user_input: True if the message arg is a variable, not a string literal
        msg_node = _kwarg(call, "message") or (call.args[1] if len(call.args) > 1 else None)
        passes_input = _is_variable(msg_node) if msg_node else False

        self.edges.append(A2AEdge(
            caller=caller_var,
            callee=callee_var,
            call_type="initiate_chat",
            passes_user_input=passes_input,
            callee_tools_scoped=True,  # AutoGen agents have independent tool sets
            file=self.file,
            line=call.lineno,
        ))

    def _handle_groupchat(self, call: ast.Call, var: str) -> None:
        """GroupChat(agents=[a, b, c]) — creates peer edges between all members."""
        agents_node = _kwarg(call, "agents")
        if not isinstance(agents_node, ast.List):
            return
        members = [_get_name(elt) for elt in agents_node.elts if _get_name(elt)]
        # Each member can communicate with every other — model as hub edges
        # We designate the first member as the de-facto orchestrator for edge naming
        for i, src in enumerate(members):
            for dst in members[i + 1:]:
                self.edges.append(A2AEdge(
                    caller=src,
                    callee=dst,
                    call_type="group_member",
                    passes_user_input=False,  # group chat routes messages internally
                    callee_tools_scoped=True,
                    file=self.file,
                    line=call.lineno,
                ))

    # ── LangChain helpers ─────────────────────────────────────────────────────

    def _handle_tool_wrapper(self, call: ast.Call) -> None:
        """Tool(func=executor.run) — agent wrapped as a tool for another agent."""
        func_node = _kwarg(call, "func")
        if func_node is None:
            return
        # func=executor.run → executor is the callee agent
        callee_var = ""
        if isinstance(func_node, ast.Attribute):
            callee_var = _get_name(func_node.value)
        if not callee_var:
            return
        # The orchestrator is whatever agent gets this tool — we record the target var
        # (the var being assigned) as the caller once it's wired; for now record a
        # pending edge. We use a sentinel caller that the rule engine treats as "any".
        tool_var = self._current_assign_target or "__tool__"
        self.edges.append(A2AEdge(
            caller="__tool_orchestrator__",  # resolved at rule time: any agent holding this tool
            callee=callee_var,
            call_type="as_tool",
            passes_user_input=True,   # tool calls always propagate the agent's context
            callee_tools_scoped=True,
            file=self.file,
            line=call.lineno,
        ))

    # ── CrewAI helpers ────────────────────────────────────────────────────────

    def _handle_crew(self, call: ast.Call) -> None:
        """Crew(agents=[a, b], process=Process.hierarchical) — derive topology."""
        agents_node = _kwarg(call, "agents")
        if not isinstance(agents_node, ast.List):
            return
        members = [_get_name(elt) for elt in agents_node.elts if _get_name(elt)]

        # Detect process type
        process_node = _kwarg(call, "process")
        process_str  = ""
        if isinstance(process_node, ast.Attribute):
            process_str = process_node.attr.lower()  # "hierarchical" or "sequential"

        if process_str == "hierarchical":
            # Crew injects an implicit manager that delegates to each agent
            manager = AgentNode(
                name="__crew_manager__",
                framework="crewai",
                role="orchestrator",
                tools=[],
                has_code_execution=False,
                spawned_in_loop=False,
                file=self.file,
                line=call.lineno,
            )
            self.nodes.append(manager)
            self._var_to_node["__crew_manager__"] = manager
            for member in members:
                self.edges.append(A2AEdge(
                    caller="__crew_manager__",
                    callee=member,
                    call_type="invoke",
                    passes_user_input=True,
                    callee_tools_scoped=True,
                    file=self.file,
                    line=call.lineno,
                ))
        else:
            # Sequential: each agent passes output to the next
            for i in range(len(members) - 1):
                self.edges.append(A2AEdge(
                    caller=members[i],
                    callee=members[i + 1],
                    call_type="invoke",
                    passes_user_input=(i == 0),  # only first → second passes original input
                    callee_tools_scoped=True,
                    file=self.file,
                    line=call.lineno,
                ))

    # ── MCP client helpers ────────────────────────────────────────────────────

    def _handle_mcp_connect(self, call: ast.Call) -> None:
        """sse_client(url, ...) — record the MCP server URL for post-processing."""
        if not call.args:
            return
        url = _get_str(call.args[0])
        if not url:
            # Resolve variable reference: MCP_SERVER_URL = "http://..."
            var_name = _get_name(call.args[0])
            url = self._string_assignments.get(var_name, "")
        if url:
            self._mcp_server_urls.append((url, call.lineno))

    def create_mcp_edges(self) -> None:
        """Post-processing: synthesise AgentNode + edges for MCP client connections.

        Called after the full AST visit once we know both the MCP client imports
        and the server URLs. Creates one node for this file (the MCP client agent)
        and one node per unique server, with directed edges between them.
        """
        if not self._is_mcp_client or not self._mcp_server_urls:
            return

        # Derive a human name for this agent from the file stem
        client_name = self.file.stem.replace("_", "-")

        # Detect whether the file has an LLM in the loop — if so, user input
        # flows through the LLM into MCP tool calls (passes_user_input=True)
        _LLM_FRAMEWORKS = frozenset({"langchain", "langgraph", "autogen", "crewai"})
        has_llm = any(fw in _LLM_FRAMEWORKS for fw in self._framework_names.values())

        # Create the client agent node if not already registered
        if client_name not in self._var_to_node:
            fw = next(
                (fw for fw in self._framework_names.values() if fw in _LLM_FRAMEWORKS),
                "mcp_client",
            )
            client_node = AgentNode(
                name=client_name,
                framework=fw,
                role="mcp_client",
                tools=[],
                has_code_execution=False,
                spawned_in_loop=False,
                file=self.file,
                line=1,
            )
            self.nodes.append(client_node)
            self._var_to_node[client_name] = client_node

        for url, lineno in self._mcp_server_urls:
            server_name = f"mcp-server@{_url_to_host(url)}"

            if server_name not in self._var_to_node:
                server_node = AgentNode(
                    name=server_name,
                    framework="mcp_server",
                    role="tool_provider",
                    tools=[],
                    has_code_execution=False,
                    spawned_in_loop=False,
                    file=self.file,
                    line=lineno,
                )
                self.nodes.append(server_node)
                self._var_to_node[server_name] = server_node

            self.edges.append(A2AEdge(
                caller=client_name,
                callee=server_name,
                call_type="mcp_connect",
                passes_user_input=has_llm,
                callee_tools_scoped=True,  # MCP server defines its own tool boundaries
                file=self.file,
                line=lineno,
            ))

    # ── Unscoped delegation check (post-processing) ───────────────────────────

    def flag_unscoped_tool_delegation(self) -> None:
        """
        After all nodes are collected, re-check edges where a constructor
        was called with tools=<variable> referencing the parent's tool list.
        We do this as a post-pass because we need the full node map first.
        """
        for edge in self.edges:
            callee_node = self._var_to_node.get(edge.callee)
            if callee_node is None:
                continue
            caller_node = self._var_to_node.get(edge.caller)
            if caller_node is None:
                continue
            # If the callee's tool list names overlap significantly with caller's, mark unscoped
            if callee_node.tools and caller_node.tools:
                overlap = set(callee_node.tools) & set(caller_node.tools)
                if overlap and len(overlap) == len(caller_node.tools):
                    edge.callee_tools_scoped = False


def _url_to_host(url: str) -> str:
    """Extract host:port from a URL string for use as a node name."""
    try:
        # Strip scheme and path: "http://127.0.0.1:8000/sse" → "127.0.0.1:8000"
        without_scheme = url.split("://", 1)[-1]
        return without_scheme.split("/")[0]
    except Exception:
        return url


# ── Public API ────────────────────────────────────────────────────────────────

def scan_file(path: Path) -> tuple[list[AgentNode], list[A2AEdge]]:
    """
    Parse one Python file and return (nodes, edges).
    Returns ([], []) on parse error or if no multi-agent patterns detected.
    """
    try:
        source = path.read_text(encoding="utf-8")
        tree   = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError):
        return [], []

    visitor = _A2AVisitor(path)
    visitor.collect_imports(tree)
    visitor.collect_loop_lines(tree)
    visitor.visit(tree)
    visitor.create_mcp_edges()
    visitor.flag_unscoped_tool_delegation()

    return visitor.nodes, visitor.edges


def scan_path(target: Path) -> A2AGraph:
    """
    Scan a file or directory and return a merged A2AGraph.

    Multi-file strategy: we collect all nodes and edges from every file.
    Edges referencing a node name defined in a different file are kept as-is —
    the rule engine treats unresolved callee names as 'external' agents, which
    still fire trust rules (you don't know what the external agent does).
    """
    all_nodes: list[AgentNode] = []
    all_edges: list[A2AEdge]  = []
    files: list[Path] = []

    py_files: list[Path] = []
    if target.is_file():
        py_files = [target]
    else:
        py_files = sorted(
            p for p in target.rglob("*.py")
            if not any(
                part.startswith((".venv", "venv", "__pycache__", ".git", "node_modules"))
                for part in p.parts
            )
        )

    for py_file in py_files:
        nodes, edges = scan_file(py_file)
        if nodes or edges:
            all_nodes.extend(nodes)
            all_edges.extend(edges)
            if py_file not in files:
                files.append(py_file)

    return A2AGraph(nodes=all_nodes, edges=all_edges, files=files)

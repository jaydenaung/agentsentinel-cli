"""Static analysis engine — extracts tool definitions from Python agent files using AST."""

import ast
import dataclasses
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ToolInfo:
    name: str
    scope: str          # "read" | "write"
    is_dangerous: bool
    source: str         # how it was detected
    docstring: str = ""
    category: str = "other"


@dataclasses.dataclass
class AgentInfo:
    file: Path
    tools: list[ToolInfo]
    description: str = ""
    model: str = ""
    hardcoded_creds: list[str] = dataclasses.field(default_factory=list)


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

_WRITE_PATTERNS = (
    "write", "edit", "create", "delete", "remove", "move", "rename",
    "execute", "run", "exec", "patch", "update", "insert", "drop",
    "truncate", "send", "post", "put", "upload", "deploy", "reset", "kill",
)
_DANGEROUS_PATTERNS = (
    "delete", "remove", "drop", "truncate", "execute", "run", "exec",
    "send", "deploy", "reset", "kill",
)
_KNOWN_MODELS = (
    "gpt-", "claude-", "gemini-", "mistral", "llama", "mixtral",
    "command", "titan", "nova",
)
_TOOL_CATEGORIES = {
    "database":      ("database", "db", "sql", "query", "postgres", "mysql", "mongo", "dynamo", "redis"),
    "storage":       ("s3", "bucket", "object", "blob", "gcs", "object_store", "storage", "get_object",
                      "put_object", "list_bucket", "list_objects", "presigned"),
    "filesystem":    ("file", "directory", "disk", "path", "read_file", "write_file"),
    "web":           ("http", "fetch", "url", "web", "scrape", "browse", "request"),
    "communication": ("email", "smtp", "slack", "webhook", "notify", "send_message", "sns", "sqs"),
    "code_execution":("exec", "bash", "shell", "run_code", "eval", "terminal", "subprocess", "python_repl"),
    "secrets":       ("secret", "credential", "vault", "token", "password", "api_key", "read_env",
                      "ssm", "secrets_manager"),
    "admin":         ("admin", "iam", "role", "permission", "policy", "sudo", "privilege"),
    "crm":           ("crm", "customer", "account", "contact", "salesforce", "hubspot"),
    "analytics":     ("analytics", "metric", "report", "dashboard", "bi", "insight"),
    "infrastructure":("deploy", "container", "k8s", "kubernetes", "aws", "gcp", "azure", "terraform",
                      "ec2", "lambda", "ecs", "cloudformation"),
}

# Credential detection
_CRED_VARNAMES = frozenset({
    "api_key", "apikey", "api_token", "token", "secret", "password",
    "passwd", "credential", "auth_token", "access_token", "secret_key",
    "private_key", "bearer_token", "auth_key",
})
_CRED_PREFIXES = (
    "sk-ant-", "sk-proj-", "sk-", "Bearer ", "ghp_", "gho_", "github_pat_",
    "xoxb-", "xoxp-", "AIza", "ya29.", "AKIA", "eyJ",  # JWT
)
_CRED_REGEX = re.compile(r'^[A-Za-z0-9+/\-_]{32,}={0,2}$')

# Modern agent construction patterns that receive a tools list as an argument
_AGENT_CALLER_FUNCS = frozenset({
    "create_react_agent",
    "create_tool_calling_agent",
    "create_openai_tools_agent",
    "create_openai_functions_agent",
    "create_agent",
    "initialize_agent",
})


def _classify(name: str) -> tuple[str, bool]:
    lower = name.lower()
    is_dangerous = any(p in lower for p in _DANGEROUS_PATTERNS)
    is_write = is_dangerous or any(p in lower for p in _WRITE_PATTERNS)
    return ("write" if is_write else "read"), is_dangerous


def _categorize(name: str) -> str:
    lower = name.lower()
    for category, patterns in _TOOL_CATEGORIES.items():
        if any(p in lower for p in patterns):
            return category
    return "other"


def _get_string(node: ast.expr | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _looks_like_credential(value: str) -> bool:
    if any(value.startswith(p) for p in _CRED_PREFIXES):
        return len(value) > 16
    return bool(_CRED_REGEX.match(value)) and len(value) >= 32


def _has_decorator(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    names: tuple[str, ...],
) -> bool:
    for dec in func_node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id in names:
            return True
        if isinstance(dec, ast.Attribute) and dec.attr in names:
            return True
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name) and dec.func.id in names:
                return True
            if isinstance(dec.func, ast.Attribute) and dec.func.attr in names:
                return True
    return False


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _AgentFileVisitor(ast.NodeVisitor):
    """Walk an AST and collect tool definitions, agent metadata, and credentials."""

    def __init__(self) -> None:
        self.tools: list[ToolInfo] = []
        self.description: str = ""
        self.model: str = ""
        self.hardcoded_creds: list[str] = []
        self._seen: set[str] = set()

    def _add_tool(self, name: str, source: str, docstring: str = "") -> None:
        if name in self._seen:
            return
        self._seen.add(name)
        scope, is_dangerous = _classify(name)
        self.tools.append(ToolInfo(
            name=name,
            scope=scope,
            is_dangerous=is_dangerous,
            source=source,
            docstring=docstring,
            category=_categorize(name),
        ))

    def _extract_tool_names(self, node: "ast.expr | None", source: str) -> None:
        """Extract tool names from a tools=[...] argument.

        Handles three forms:
          - Variable references: [list_directory, search_web] → name is the variable name
          - Anthropic API dicts: [{"name": "tool_name", "input_schema": {...}}]
          - OpenAI API dicts:    [{"type": "function", "function": {"name": "tool_name"}}]
        """
        if not isinstance(node, ast.List):
            return
        for elt in node.elts:
            if isinstance(elt, ast.Name):
                self._add_tool(elt.id, source)
            elif isinstance(elt, ast.Attribute):
                self._add_tool(elt.attr, source)
            elif isinstance(elt, ast.Dict):
                for key, val in zip(elt.keys, elt.values):
                    k = _get_string(key)
                    if k == "name":
                        name = _get_string(val)
                        if name:
                            self._add_tool(name, source)
                        break
                    if k == "function" and isinstance(val, ast.Dict):
                        # OpenAI format: {"type": "function", "function": {"name": "..."}}
                        for k2, v2 in zip(val.keys, val.values):
                            if _get_string(k2) == "name":
                                name = _get_string(v2)
                                if name:
                                    self._add_tool(name, source)
                                break
                        break

    # ------------------------------------------------------------------
    # @tool / @SentinelTool decorated functions
    # ------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if _has_decorator(node, ("tool", "SentinelTool", "beta_tool", "betaZodTool")):
            doc = ast.get_docstring(node) or ""
            self._add_tool(node.name, "@tool decorator", doc)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    # ------------------------------------------------------------------
    # Class-based tools
    # ------------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        base_names = {
            b.id if isinstance(b, ast.Name) else
            (b.attr if isinstance(b, ast.Attribute) else "")
            for b in node.bases
        }
        if "BaseTool" in base_names or "StructuredTool" in base_names:
            for item in node.body:
                if (
                    isinstance(item, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "name" for t in item.targets)
                ):
                    tool_name = _get_string(item.value)
                    if tool_name:
                        doc = ast.get_docstring(node) or ""
                        self._add_tool(tool_name, "BaseTool subclass", doc)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Tool() / StructuredTool() call-based tools + model + description
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # ── Tool() / StructuredTool(name=...) constructors ────────────────────
        if func_name in ("Tool", "StructuredTool"):
            for kw in node.keywords:
                if kw.arg == "name":
                    tool_name = _get_string(kw.value)
                    if tool_name:
                        self._add_tool(tool_name, f"{func_name}(name=...)")

        # ── StructuredTool.from_function(name="...", coroutine=...) ───────────
        if func_name == "from_function" and isinstance(node.func, ast.Attribute):
            obj_name = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
            if obj_name in ("StructuredTool", "Tool"):
                for kw in node.keywords:
                    if kw.arg == "name":
                        tool_name = _get_string(kw.value)
                        if tool_name:
                            self._add_tool(tool_name, f"{obj_name}.from_function()")

        # ── bind_tools([tool1, tool2]) — modern LangChain ─────────────────────
        if func_name == "bind_tools" and node.args:
            self._extract_tool_names(node.args[0], "bind_tools()")

        # ── create_react_agent(llm, tools) and family — LangGraph ────────────
        if func_name in _AGENT_CALLER_FUNCS:
            # tools is the second positional arg, or tools= keyword
            tools_node = (
                node.args[1] if len(node.args) >= 2
                else next((kw.value for kw in node.keywords if kw.arg == "tools"), None)
            )
            self._extract_tool_names(tools_node, f"{func_name}()")

        # ── AgentExecutor(tools=[...]) — LangChain executor ───────────────────
        if func_name == "AgentExecutor":
            tools_node = next((kw.value for kw in node.keywords if kw.arg == "tools"), None)
            self._extract_tool_names(tools_node, "AgentExecutor()")

        # ── Direct Anthropic / OpenAI API: messages.create(tools=[...]) ───────
        if func_name == "create":
            tools_node = next((kw.value for kw in node.keywords if kw.arg == "tools"), None)
            if tools_node:
                self._extract_tool_names(tools_node, "API tools list")
            # Also capture model from direct API calls
            if not self.model:
                for kw in node.keywords:
                    if kw.arg == "model":
                        val = _get_string(kw.value)
                        if val and any(val.startswith(p) for p in _KNOWN_MODELS):
                            self.model = val
                            break

        # ── LLM constructor — model detection ────────────────────────────────
        if func_name in ("ChatAnthropic", "ChatOpenAI", "ChatGoogleGenerativeAI",
                         "AzureChatOpenAI", "BedrockChat", "init_chat_model",
                         "Anthropic", "OpenAI"):
            for kw in node.keywords:
                if kw.arg == "model":
                    val = _get_string(kw.value)
                    if val and not self.model:
                        self.model = val
            if node.args:
                val = _get_string(node.args[0])
                if val and any(val.startswith(p) for p in _KNOWN_MODELS) and not self.model:
                    self.model = val

        if func_name == "create_agent" and node.args:
            val = _get_string(node.args[0])
            if val and not self.model:
                self.model = val

        if func_name == "SentinelCallbackHandler":
            for kw in node.keywords:
                if kw.arg == "description" and not self.description:
                    self.description = _get_string(kw.value)

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Variable assignments — description detection + hardcoded credentials
    # ------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            varname = target.id.lower()

            if "description" in varname and not self.description:
                val = _get_string(node.value)
                if val:
                    self.description = val

            # Credential detection: api_key = "sk-ant-..."
            if varname in _CRED_VARNAMES:
                val = _get_string(node.value)
                if val and _looks_like_credential(val):
                    self.hardcoded_creds.append(
                        f"{target.id} = \"{val[:8]}…\" (line {node.lineno})"
                    )

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Keyword arguments — catch api_key="..." in function calls
    # ------------------------------------------------------------------

    def visit_keyword(self, node: ast.keyword) -> None:
        if node.arg and node.arg.lower() in _CRED_VARNAMES:
            val = _get_string(node.value)
            if val and _looks_like_credential(val):
                self.hardcoded_creds.append(
                    f"{node.arg} = \"{val[:8]}…\" (line {node.value.lineno})"  # type: ignore[attr-defined]
                )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_file(path: Path) -> AgentInfo | None:
    """Parse a Python file and extract agent/tool information. Returns None on parse error."""
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError):
        return None

    visitor = _AgentFileVisitor()
    visitor.visit(tree)

    if not visitor.tools:
        return None

    return AgentInfo(
        file=path,
        tools=visitor.tools,
        description=visitor.description,
        model=visitor.model,
        hardcoded_creds=visitor.hardcoded_creds,
    )


def classify_tool(name: str, description: str = "") -> tuple[str, bool, str]:
    """Classify a tool by name and description into (scope, is_dangerous, category).

    Used by both the static file scanner and the MCP scanner.
    """
    combined = f"{name} {description}".strip()
    scope, is_dangerous = _classify(combined)
    category = _categorize(combined)
    return scope, is_dangerous, category


def scan_path(target: Path) -> list[AgentInfo]:
    """Scan a file or directory, returning one AgentInfo per file that contains tools."""
    if target.is_file():
        result = scan_file(target)
        return [result] if result else []

    results = []
    for py_file in sorted(target.rglob("*.py")):
        if any(part.startswith((".venv", "venv", "__pycache__", ".git", "node_modules"))
               for part in py_file.parts):
            continue
        result = scan_file(py_file)
        if result:
            results.append(result)
    return results

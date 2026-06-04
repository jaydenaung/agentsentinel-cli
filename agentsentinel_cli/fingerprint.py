"""Agent fingerprinting — detect framework, model, runtime, and deployment from source or HTTP."""

import ast
import dataclasses
import re
from pathlib import Path


@dataclasses.dataclass
class AgentFingerprint:
    """All passively-observable facts about an agent's identity and environment."""

    framework: str = "unknown"
    model: str = ""
    python_version: str = ""
    deployment: str = "local"
    cloud: str = "unknown"
    system_prompt_found: bool = False
    system_prompt_snippet: str = ""
    env_vars: list[str] = dataclasses.field(default_factory=list)
    external_apis: list[str] = dataclasses.field(default_factory=list)
    server_type: str = "agent"   # "agent" | "mcp_server" | "mcp_client"


# Only server-side SDK modules — bare "mcp" and "mcp.types" are shared; "mcp.client.*" is a consumer
_MCP_SERVER_IMPORTS = frozenset({
    "mcp.server", "mcp.server.fastmcp", "fastmcp",
})

# Client-side SDK modules — this file consumes tools from an MCP server
_MCP_CLIENT_IMPORTS = frozenset({
    "mcp.client", "mcp.client.sse", "mcp.client.stdio",
    "mcp.client.streamable_http", "mcp.client.websocket",
})

# Ordered by specificity — first match wins
_FRAMEWORK_SIGNALS: list[tuple[str, str]] = [
    ("crewai",               "CrewAI"),
    ("autogen_agentchat",    "AutoGen"),
    ("autogen",              "AutoGen"),
    ("semantic_kernel",      "Semantic Kernel"),
    ("google.adk",           "Google ADK"),
    ("haystack",             "Haystack"),
    ("llama_index",          "LlamaIndex"),
    ("llamaindex",           "LlamaIndex"),
    ("langchain",            "LangChain"),
    ("openai",               "OpenAI SDK"),
    ("anthropic",            "Anthropic SDK"),
    ("google.generativeai",  "Google GenAI"),
    ("transformers",         "HuggingFace Transformers"),
    ("agentsentinel",        "AgentSentinel"),
]

_CLOUD_SIGNALS: list[tuple[str, str, str]] = [
    # (import_prefix, cloud_label, deployment_label)
    ("aws_lambda_powertools", "AWS", "AWS Lambda"),
    ("boto3",                 "AWS", "AWS"),
    ("botocore",              "AWS", "AWS"),
    ("google.cloud",          "GCP", "GCP"),
    ("google.colab",          "GCP", "GCP Colab"),
    ("azure.functions",       "Azure", "Azure Functions"),
    ("azure",                 "Azure", "Azure"),
    ("kubernetes",            "unknown", "Kubernetes"),
]

_KNOWN_MODELS = (
    "gpt-4", "gpt-3.5", "o1-", "o3-",
    "claude-", "gemini-", "mistral", "llama", "mixtral",
    "command", "titan", "nova",
)

_LLM_CONSTRUCTORS = frozenset({
    "ChatAnthropic", "ChatOpenAI", "ChatGoogleGenerativeAI",
    "AzureChatOpenAI", "BedrockChat", "init_chat_model",
    "Anthropic", "OpenAI", "Groq", "Together",
})

_SYSTEM_PROMPT_RE = re.compile(
    r"(you are|your role is|you must|system:|you are an|you're an|"
    r"assistant named|act as a|your task is|you are a)",
    re.IGNORECASE,
)
_EXTERNAL_DOMAIN_RE = re.compile(
    r"https?://(?:api\.|app\.)?([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})"
)


class _FingerprintVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: list[str] = []
        self.model: str = ""
        self.system_prompts: list[str] = []
        self.env_vars: list[str] = []
        self.external_apis: list[str] = []
        self.has_lambda_handler: bool = False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.append(node.module)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # AWS Lambda handler: def handler(event, context)
        if node.name == "handler" and len(node.args.args) >= 2:
            names = [a.arg for a in node.args.args[:2]]
            if "event" in names and "context" in names:
                self.has_lambda_handler = True
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in _LLM_CONSTRUCTORS:
            for kw in node.keywords:
                if kw.arg == "model":
                    val = _get_str(kw.value)
                    if val and not self.model:
                        self.model = val
            if node.args and not self.model:
                val = _get_str(node.args[0])
                if val and any(val.startswith(p) for p in _KNOWN_MODELS):
                    self.model = val

        # os.getenv("KEY") — direct function call
        if func_name == "getenv" and node.args:
            val = _get_str(node.args[0])
            if val and val not in self.env_vars:
                self.env_vars.append(val)

        # os.environ.get("KEY") — attribute chain: must be <name>.environ.get(...)
        if func_name == "get" and node.args:
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "environ"
            ):
                val = _get_str(node.args[0])
                if val and val not in self.env_vars:
                    self.env_vars.append(val)

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if not isinstance(node.value, str):
            return
        val = node.value

        if len(val) > 20 and _SYSTEM_PROMPT_RE.search(val):
            self.system_prompts.append(val[:120].replace("\n", " "))

        for m in _EXTERNAL_DOMAIN_RE.finditer(val):
            domain = m.group(1)
            if domain not in ("localhost", "example.com") and domain not in self.external_apis:
                self.external_apis.append(domain)


def _get_str(node: ast.expr | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _detect_framework(imports: list[str]) -> str:
    for prefix, name in _FRAMEWORK_SIGNALS:
        if any(imp.startswith(prefix) for imp in imports):
            return name
    return "unknown"


def _detect_cloud(imports: list[str], has_lambda_handler: bool) -> tuple[str, str]:
    for prefix, cloud, deployment in _CLOUD_SIGNALS:
        if any(imp.startswith(prefix) for imp in imports):
            if prefix == "boto3" and has_lambda_handler:
                return "AWS", "AWS Lambda"
            return cloud, deployment
    return "unknown", "local"


def _detect_python_version(base: Path) -> str:
    """Walk up from the target file looking for Python version markers."""
    dirs = [base if base.is_dir() else base.parent]
    for _ in range(2):
        dirs.append(dirs[-1].parent)

    for d in dirs:
        pv = d / ".python-version"
        if pv.exists():
            return pv.read_text().strip()

        rt = d / "runtime.txt"
        if rt.exists():
            content = rt.read_text().strip()
            if "python" in content.lower():
                return content.replace("python-", "").replace("python", "").strip()

        pp = d / "pyproject.toml"
        if pp.exists():
            m = re.search(r'requires-python\s*=\s*"([^"]+)"', pp.read_text())
            if m:
                return m.group(1)

    return ""


def fingerprint_file(path: Path) -> AgentFingerprint:
    """Fingerprint an agent source file — framework, model, runtime, deployment."""
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError):
        return AgentFingerprint()

    v = _FingerprintVisitor()
    v.visit(tree)

    cloud, deployment = _detect_cloud(v.imports, v.has_lambda_handler)

    def _matches(imp: str, prefix: str) -> bool:
        return imp == prefix or imp.startswith(prefix + ".")

    is_mcp_server = any(
        any(_matches(imp, p) for imp in v.imports) for p in _MCP_SERVER_IMPORTS
    )
    is_mcp_client = any(
        any(_matches(imp, p) for imp in v.imports) for p in _MCP_CLIENT_IMPORTS
    )

    # A file with mcp.server.* is a tool provider; mcp.client.* is a tool consumer.
    # If both appear the file is unusual (proxy/relay) — treat as server since it
    # exposes tools.  Client-only → mcp_client, neither → agent.
    if is_mcp_server:
        server_type = "mcp_server"
        has_fastmcp = any(_matches(imp, "mcp.server.fastmcp") or _matches(imp, "fastmcp") for imp in v.imports)
        framework = "FastMCP" if has_fastmcp else "MCP Server"
    elif is_mcp_client:
        server_type = "mcp_client"
        framework = _detect_framework(v.imports)
    else:
        server_type = "agent"
        framework = _detect_framework(v.imports)

    return AgentFingerprint(
        framework=framework,
        model=v.model,
        python_version=_detect_python_version(path),
        deployment=deployment,
        cloud=cloud,
        system_prompt_found=bool(v.system_prompts),
        system_prompt_snippet=v.system_prompts[0] if v.system_prompts else "",
        env_vars=v.env_vars[:10],
        external_apis=v.external_apis[:10],
        server_type=server_type,
    )


def fingerprint_live(
    url: str,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> AgentFingerprint:
    """Fingerprint a live HTTP agent endpoint from response headers and behavior."""
    try:
        import httpx
    except ImportError:
        return AgentFingerprint()

    fp = AgentFingerprint()
    req_headers = extra_headers or {}

    try:
        with httpx.Client(timeout=timeout) as client:
            try:
                resp = client.get(url, headers=req_headers)
                _parse_headers(resp, fp)
            except Exception:
                pass

            # Probe with common payload shapes to observe response structure
            for payload in [
                {"messages": [{"role": "user", "content": "hello"}]},
                {"message": "hello"},
                {"input": "hello"},
            ]:
                try:
                    resp = client.post(url, json=payload, headers=req_headers)
                    if resp.status_code < 400:
                        _parse_headers(resp, fp)
                        break
                except Exception:
                    continue
    except Exception:
        pass

    return fp


def _parse_headers(resp: "httpx.Response", fp: AgentFingerprint) -> None:
    h = {k.lower(): v.lower() for k, v in resp.headers.items()}

    for val in (h.get("server", ""), h.get("x-powered-by", "")):
        if "langchain" in val and fp.framework == "unknown":
            fp.framework = "LangChain"
        elif ("fastapi" in val or "uvicorn" in val) and fp.framework == "unknown":
            fp.framework = "FastAPI-based"

    all_keys = " ".join(h.keys())
    if "x-amzn-requestid" in h or "x-amz-" in all_keys:
        fp.cloud, fp.deployment = "AWS", "AWS (API Gateway/Lambda)"
    elif "x-cloud-trace-context" in h or "x-goog-" in all_keys:
        fp.cloud, fp.deployment = "GCP", "GCP"
    elif "x-ms-" in all_keys or "x-azure-" in all_keys:
        fp.cloud, fp.deployment = "Azure", "Azure"

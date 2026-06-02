"""Framework fingerprinting — identifies which AI agent framework a process or file uses."""

from __future__ import annotations

# ── Framework signals ──────────────────────────────────────────────────────────
# Ordered most-specific first so the first match wins.
# Each entry: (signal_string, display_name, provider)

_FRAMEWORK_SIGNALS: list[tuple[str, str, str]] = [
    # LangChain variants
    ("langchain_anthropic",       "LangChain",           "Anthropic"),
    ("langchain_openai",          "LangChain",           "OpenAI"),
    ("langchain_google",          "LangChain",           "Google"),
    ("langchain_community",       "LangChain",           ""),
    ("langchain",                 "LangChain",           ""),
    # OpenAI
    ("openai.agents",             "OpenAI Agents SDK",   "OpenAI"),
    ("agents_sdk",                "OpenAI Agents SDK",   "OpenAI"),
    # CrewAI
    ("crewai",                    "CrewAI",              ""),
    # AutoGen
    ("pyautogen",                 "AutoGen",             "Microsoft"),
    ("autogen",                   "AutoGen",             "Microsoft"),
    # MCP
    ("mcp.server",                "MCP Server",          ""),
    ("mcp.client",                "MCP Client",          ""),
    ("mcp",                       "MCP",                 ""),
    # Microsoft Semantic Kernel
    ("semantic_kernel",           "Semantic Kernel",     "Microsoft"),
    # LlamaIndex
    ("llama_index",               "LlamaIndex",          ""),
    ("llama-index",               "LlamaIndex",          ""),
    # Haystack
    ("haystack",                  "Haystack",            "deepset"),
    # PydanticAI
    ("pydantic_ai",               "PydanticAI",          "Pydantic"),
    # Google ADK
    ("google.adk",                "Google ADK",          "Google"),
    ("google_adk",                "Google ADK",          "Google"),
    # AgentSentinel (self-monitored)
    ("agentsentinel",             "AgentSentinel",       ""),
    # Raw SDKs (least specific — match last)
    ("anthropic",                 "Anthropic SDK",       "Anthropic"),
    ("openai",                    "OpenAI SDK",          "OpenAI"),
]

# LLM API environment variable → (provider_label, key_prefix)
LLM_ENV_VARS: dict[str, tuple[str, str]] = {
    "OPENAI_API_KEY":             ("OpenAI",        "sk-"),
    "ANTHROPIC_API_KEY":          ("Anthropic",     "sk-ant-"),
    "GOOGLE_API_KEY":             ("Google",        "AIza"),
    "GEMINI_API_KEY":             ("Google Gemini", ""),
    "COHERE_API_KEY":             ("Cohere",        ""),
    "HUGGINGFACE_TOKEN":          ("HuggingFace",   "hf_"),
    "HF_TOKEN":                   ("HuggingFace",   "hf_"),
    "AZURE_OPENAI_API_KEY":       ("Azure OpenAI",  ""),
    "GROQ_API_KEY":               ("Groq",          "gsk_"),
    "MISTRAL_API_KEY":            ("Mistral",       ""),
    "TOGETHER_API_KEY":           ("Together AI",   ""),
    "REPLICATE_API_TOKEN":        ("Replicate",     "r8_"),
    "PERPLEXITY_API_KEY":         ("Perplexity",    "pplx-"),
    "BEDROCK_API_KEY":            ("AWS Bedrock",   ""),
}

# Known LLM API hostnames — presence in process connections confirms active agent
LLM_API_HOSTS: frozenset[str] = frozenset({
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "api.cohere.com",
    "api.groq.com",
    "api.mistral.ai",
    "api.together.xyz",
    "api.perplexity.ai",
    "bedrock-runtime.us-east-1.amazonaws.com",
    "bedrock-runtime.ap-southeast-1.amazonaws.com",
})

# Model name fragments → canonical label
_MODEL_PATTERNS: list[tuple[str, str]] = [
    ("claude-opus",      "claude-opus"),
    ("claude-sonnet",    "claude-sonnet"),
    ("claude-haiku",     "claude-haiku"),
    ("claude",           "claude"),
    ("gpt-4o",           "gpt-4o"),
    ("gpt-4",            "gpt-4"),
    ("gpt-3.5",          "gpt-3.5-turbo"),
    ("o1",               "o1"),
    ("o3",               "o3"),
    ("gemini-2",         "gemini-2"),
    ("gemini-1",         "gemini-1"),
    ("gemini",           "gemini"),
    ("mistral",          "mistral"),
    ("llama",            "llama"),
    ("mixtral",          "mixtral"),
    ("command",          "command"),
]


def detect_framework(text: str) -> tuple[str, str]:
    """Return (framework_name, provider) from any text blob (cmdline, env, source).

    Returns ("Unknown", "") if no framework is detected.
    """
    lower = text.lower()
    for signal, framework, provider in _FRAMEWORK_SIGNALS:
        if signal in lower:
            return framework, provider
    return "Unknown", ""


def detect_provider_from_env(env: dict[str, str]) -> str:
    """Identify which LLM provider a process is using from its environment variables."""
    for var, (provider, _) in LLM_ENV_VARS.items():
        if var in env and env[var]:
            return provider
    return ""


def detect_model(text: str) -> str:
    """Extract a model name from any text blob."""
    lower = text.lower()
    for fragment, label in _MODEL_PATTERNS:
        if fragment in lower:
            return label
    return ""


def mask_key(value: str) -> str:
    """Mask an API key, showing only prefix and last 4 chars."""
    if len(value) <= 12:
        return "***"
    return f"{value[:8]}...{value[-4:]}"


def extract_api_keys(env: dict[str, str]) -> list[str]:
    """Return masked API key strings from a process environment."""
    found = []
    for var, (provider, _) in LLM_ENV_VARS.items():
        val = env.get(var, "")
        if val and len(val) > 8:
            found.append(f"{var}={mask_key(val)}")
    return found

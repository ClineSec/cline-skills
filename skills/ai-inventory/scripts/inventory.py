#!/usr/bin/env python3
"""Read-only helper for the ai-inventory skill. Standard library only.

    inventory.py walk --target PATH --out DIR [--allow-inside-target]
    inventory.py render --out DIR

`walk` reads the target and writes walk.json: what the tables below recognize, plus leads for the
agent to judge. `render` combines walk.json with the agent's assessment.json and writes ai-bom.cdx.json
(CycloneDX 1.6) and report.md.

Nothing here executes, sources, or connects to anything found in the target, and nothing writes to it.
The tables are a starting point: they recognize what is common, and the agent looks for what they miss.
Exit codes: 0 success, 1 problems to correct, 2 refused or bad usage.
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
import uuid
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable, Iterator
from urllib.parse import quote

SCHEMA = 1
SPEC_VERSION = "1.6"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_HASH_BYTES = 4 * 1024 * 1024 * 1024
MAX_LINE_CHARS = 2000
MAX_OCCURRENCES = 10
MAX_LISTED_FILES = 3000
EVIDENCE_WINDOW = 2

CATEGORIES = (
    "sdk", "agent-framework", "ml-runtime", "model", "prompt", "mcp-server", "vector-store",
    "hosted-service", "coding-agent", "other",
)
CATEGORY_LABELS = {
    "sdk": "AI SDKs and client libraries", "agent-framework": "Agent frameworks",
    "ml-runtime": "Local model runtimes", "model": "Models", "prompt": "Prompts",
    "mcp-server": "MCP servers", "vector-store": "Vector stores and embeddings",
    "hosted-service": "Hosted AI services and endpoints", "coding-agent": "Coding agents",
    "other": "Other AI surfaces",
}
SURFACE_LABELS = {"build": "What this repository builds", "use": "What people working in it use"}
CONFIDENCE = {"high": 0.9, "medium": 0.6, "low": 0.3}
STATUSES = {"in-use": "In use", "optional": "Optional", "mentioned": "Only mentioned"}
NOT_REVIEWED = "detected"
MAX_SUMMARY_WORDS = 100
MAX_WHY_WORDS = 60
MAX_REASON_WORDS = 40
MAX_LIST_ENTRIES = 8
MAX_LIST_ENTRY_WORDS = 40
MAX_DATA_FLOWS = 10
NO_PROVIDER_CATEGORIES = {"prompt", "other"}
PROPERTY = "cline:ai-inventory:"
POLICYRELAY_INDEX = "security/PolicyRelay/index.md"

CANNOT_SEE = (
    "AI use outside this repository: SaaS products with built-in AI, chat assistants, browser extensions, "
    "and tools adopted by other teams.",
    "Which provider, model, or subprocessor a vendor uses behind its own API.",
    "Anything decided at runtime: models named only in a database or a deployment's environment, and "
    "traffic that only a gateway or egress log would show.",
)

# ---- Starting tables. Recognizing something here is a lead with a label, not a limit on the inventory.

# (category, provider, {ecosystem: lowercase name patterns}). Names are matched in order.
PACKAGES: tuple[tuple[str, str, dict[str, list[str]]], ...] = (
    ("sdk", "OpenAI", {
        "pypi": ["openai"], "npm": ["openai"], "maven": ["com.openai:*"], "nuget": ["openai", "azure.ai.openai"],
        "go": ["github.com/openai/openai-go*", "github.com/sashabaranov/go-openai*"],
        "gem": ["ruby-openai", "openai"], "cargo": ["async-openai"],
    }),
    ("sdk", "Anthropic", {
        "pypi": ["anthropic"], "npm": ["@anthropic-ai/sdk"], "maven": ["com.anthropic:*"], "nuget": ["anthropic*"],
        "go": ["github.com/anthropics/anthropic-sdk-go*"], "gem": ["anthropic"],
    }),
    ("sdk", "Google", {
        "pypi": ["google-generativeai", "google-genai", "vertexai", "google-cloud-aiplatform"],
        "npm": ["@google/generative-ai", "@google/genai", "@google-cloud/vertexai"],
        "go": ["github.com/google/generative-ai-go*", "google.golang.org/genai*", "cloud.google.com/go/vertexai*"],
        "maven": ["com.google.genai:*", "com.google.cloud:google-cloud-vertexai"],
    }),
    ("sdk", "AWS Bedrock", {
        "npm": ["@aws-sdk/client-bedrock*"], "go": ["github.com/aws/aws-sdk-go-v2/service/bedrock*"],
        "maven": ["software.amazon.awssdk:bedrock*"], "nuget": ["awssdk.bedrock*"],
    }),
    ("sdk", "Mistral", {"pypi": ["mistralai"], "npm": ["@mistralai/*"]}),
    ("sdk", "Cohere", {"pypi": ["cohere"], "npm": ["cohere-ai"]}),
    ("sdk", "Groq", {"pypi": ["groq"], "npm": ["groq-sdk"]}),
    ("sdk", "Together AI", {"pypi": ["together"], "npm": ["together-ai"]}),
    ("sdk", "Replicate", {"pypi": ["replicate"], "npm": ["replicate"]}),
    ("sdk", "Ollama", {"pypi": ["ollama"], "npm": ["ollama"]}),
    ("sdk", "Hugging Face", {"pypi": ["huggingface-hub"], "npm": ["@huggingface/inference", "@huggingface/hub"]}),
    ("sdk", "LiteLLM", {"pypi": ["litellm"]}),
    ("sdk", "Vercel AI SDK", {"npm": ["ai", "@ai-sdk/*"]}),
    ("sdk", "Spring AI", {"maven": ["org.springframework.ai:*"]}),
    ("sdk", "Microsoft.Extensions.AI", {"nuget": ["microsoft.extensions.ai*"]}),
    ("sdk", "Model Context Protocol", {
        "pypi": ["mcp", "fastmcp"], "npm": ["@modelcontextprotocol/*", "fastmcp"],
        "go": ["github.com/modelcontextprotocol/go-sdk*", "github.com/mark3labs/mcp-go*"],
        "maven": ["io.modelcontextprotocol.sdk:*"], "nuget": ["modelcontextprotocol*"],
    }),
    ("agent-framework", "Semantic Kernel", {
        "pypi": ["semantic-kernel"], "nuget": ["microsoft.semantickernel*"],
        "maven": ["com.microsoft.semantic-kernel:*"],
    }),
    ("agent-framework", "LangGraph", {"pypi": ["langgraph*"], "npm": ["@langchain/langgraph*"]}),
    ("agent-framework", "LangChain", {
        "pypi": ["langchain*"], "npm": ["langchain", "@langchain/*"], "maven": ["dev.langchain4j:*"],
        "go": ["github.com/tmc/langchaingo*"],
    }),
    ("agent-framework", "CrewAI", {"pypi": ["crewai*"]}),
    ("agent-framework", "AutoGen", {"pypi": ["pyautogen", "autogen*", "ag2"]}),
    ("agent-framework", "LlamaIndex", {"pypi": ["llama-index*"], "npm": ["llamaindex"]}),
    ("agent-framework", "Haystack", {"pypi": ["haystack*"]}),
    ("agent-framework", "Pydantic AI", {"pypi": ["pydantic-ai*"]}),
    ("agent-framework", "smolagents", {"pypi": ["smolagents"]}),
    ("agent-framework", "DSPy", {"pypi": ["dspy*"]}),
    ("agent-framework", "OpenAI Agents SDK", {"pypi": ["openai-agents"], "npm": ["@openai/agents*"]}),
    ("agent-framework", "Claude Agent SDK", {
        "pypi": ["claude-agent-sdk"], "npm": ["@anthropic-ai/claude-agent-sdk"],
    }),
    ("agent-framework", "Google ADK", {"pypi": ["google-adk"], "npm": ["@google/adk"]}),
    ("agent-framework", "Mastra", {"npm": ["@mastra/*", "mastra"]}),
    ("ml-runtime", "PyTorch", {"pypi": ["torch"]}),
    ("ml-runtime", "TensorFlow", {"pypi": ["tensorflow*"], "npm": ["@tensorflow/*"]}),
    ("ml-runtime", "Hugging Face", {
        "pypi": ["transformers", "sentence-transformers", "diffusers"],
        "npm": ["@huggingface/transformers", "@xenova/transformers"],
    }),
    ("ml-runtime", "ONNX Runtime", {"pypi": ["onnxruntime*"], "npm": ["onnxruntime-*"]}),
    ("ml-runtime", "llama.cpp", {"pypi": ["llama-cpp-python", "ctransformers"], "npm": ["node-llama-cpp"]}),
    ("ml-runtime", "vLLM", {"pypi": ["vllm"]}),
    ("vector-store", "Pinecone", {"pypi": ["pinecone*"], "npm": ["@pinecone-database/*"]}),
    ("vector-store", "Chroma", {"pypi": ["chromadb"], "npm": ["chromadb"]}),
    ("vector-store", "Weaviate", {"pypi": ["weaviate*"], "npm": ["weaviate-*"]}),
    ("vector-store", "Qdrant", {"pypi": ["qdrant-client", "qdrant"], "npm": ["@qdrant/*"]}),
    ("vector-store", "Milvus", {"pypi": ["pymilvus"], "npm": ["@zilliz/milvus*"]}),
    ("vector-store", "FAISS", {"pypi": ["faiss*"]}),
    ("vector-store", "LanceDB", {"pypi": ["lancedb"], "npm": ["@lancedb/*"]}),
    ("vector-store", "pgvector", {"pypi": ["pgvector"], "npm": ["pgvector"]}),
)
JVM_IMPORTS = {
    "com.openai": "com.openai:*", "com.anthropic": "com.anthropic:*", "com.google.genai": "com.google.genai:*",
    "dev.langchain4j": "dev.langchain4j:*", "org.springframework.ai": "org.springframework.ai:*",
    "com.microsoft.semantickernel": "com.microsoft.semantic-kernel:*",
    "io.modelcontextprotocol": "io.modelcontextprotocol.sdk:*",
}

_NAME = r"[a-z0-9][a-z0-9.\-_:+]*"
_TAIL = r"[a-z0-9.\-_:+]*"
MODEL_FAMILIES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (provider, re.compile(pattern, re.IGNORECASE))
    for provider, pattern in (
        ("OpenAI", rf"(?:gpt-\d|chatgpt-|text-embedding-(?:ada|3)|dall-e-|whisper-\d|tts-\d|o[134](?:-|$)){_TAIL}"),
        ("Anthropic", r"(?:anthropic\.)?claude-[a-z0-9.\-_:@]*\d[a-z0-9.\-_:@]*"),
        ("Google", rf"(?:gemini-\d|gemma[-:\d]|imagen-\d|veo-\d|text-embedding-00\d|embedding-00\d){_TAIL}"),
        ("Meta", rf"(?:meta[-./])?(?:llama|code-llama)[-.:]?\d{_TAIL}"),
        ("Mistral", rf"(?:mistral|mixtral|codestral|pixtral|devstral|magistral)[-:]{_NAME}"),
        ("Cohere", rf"(?:cohere\.)?(?:command-(?:r|a|light|nightly)|embed-(?:english|multilingual|v\d)|rerank-){_TAIL}"),
        ("DeepSeek", rf"deepseek[-:]{_NAME}"),
        ("xAI", rf"grok-\d{_TAIL}"),
        ("Alibaba", rf"qwen[-:\d]{_TAIL}"),
        ("Microsoft", rf"phi-?\d{_TAIL}"),
        ("Amazon", rf"amazon\.(?:titan|nova)-{_NAME}"),
    )
)
MODEL_ROUTE_PREFIX = re.compile(
    r"^(?:openai|anthropic|azure|bedrock|vertex_ai|vertex|gemini|google|openrouter|ollama|ollama_chat|groq|"
    r"mistral|cohere|together_ai|together|deepseek|xai|huggingface|meta|meta-llama|mistralai|deepseek-ai|"
    r"qwen|x-ai|microsoft)/",
    re.IGNORECASE,
)
QUOTED = re.compile(r"""(["'`])([^"'`\n]{2,160})\1""")
MODEL_ASSIGNMENT = re.compile(
    r"""(?:^|[\s,({"'])["']?((?:[A-Za-z_][\w.\-]*[_.\-])?(?:model|deployment)(?:[_.\-]?(?:name|id))?)["']?\s*[:=]\s*"""
    r"""(?:os\.getenv\([^,)]+,\s*)?["']?([A-Za-z0-9][\w.:/@+\-]{1,120})["']?""",
    re.IGNORECASE,
)
HF_ID = re.compile(
    r"""(?:from_pretrained|hf_hub_download|snapshot_download|pipeline|SentenceTransformer)\s*\([^)\n]*?"""
    r"""["']([A-Za-z0-9][\w.\-]*/[A-Za-z0-9][\w.\-]*)["']"""
)

HOSTS: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), name, provider)
    for pattern, name, provider in (
        (r"api\.openai\.com", "OpenAI API", "OpenAI"),
        (r"[\w\-]+\.openai\.azure\.com", "Azure OpenAI", "Microsoft"),
        (r"[\w\-]+\.services\.ai\.azure\.com", "Azure AI Foundry", "Microsoft"),
        (r"api\.anthropic\.com", "Anthropic API", "Anthropic"),
        (r"generativelanguage\.googleapis\.com", "Gemini API", "Google"),
        (r"[\w\-]*-?aiplatform\.googleapis\.com", "Vertex AI", "Google"),
        (r"bedrock(?:-runtime)?[\w.\-]*\.amazonaws\.com", "Amazon Bedrock", "Amazon"),
        (r"api\.mistral\.ai", "Mistral API", "Mistral"),
        (r"api\.cohere\.(?:ai|com)", "Cohere API", "Cohere"),
        (r"openrouter\.ai", "OpenRouter", "OpenRouter"),
        (r"api\.groq\.com", "Groq API", "Groq"),
        (r"api\.together\.(?:xyz|ai)", "Together API", "Together AI"),
        (r"api\.deepseek\.com", "DeepSeek API", "DeepSeek"),
        (r"api\.x\.ai", "xAI API", "xAI"),
        (r"api\.perplexity\.ai", "Perplexity API", "Perplexity"),
        (r"api\.replicate\.com", "Replicate API", "Replicate"),
        (r"(?:api-inference|router)\.huggingface\.co", "Hugging Face Inference", "Hugging Face"),
        (r"(?:localhost|127\.0\.0\.1):11434", "Ollama (local)", "Ollama"),
    )
)
URL = re.compile(r"""https?://[^\s"'`<>)\]},]+""", re.IGNORECASE)
HOST_SEARCH = re.compile(
    "|".join(pattern.pattern for pattern, _, _ in HOSTS), re.IGNORECASE
)
INFERENCE_PATH = re.compile(r"/(?:v\d+(?:beta)?/)?(?:chat/completions|completions|messages|embeddings|responses)(?:[/?#]|$)", re.I)
BASE_URL_NAME = re.compile(
    r"""(?:base[_-]?url|api[_-]?base|openai[_-]?api[_-]?base|llm[_-]?(?:url|endpoint)|model[_-]?(?:url|endpoint))["']?\s*[:=]""",
    re.IGNORECASE,
)

CREDENTIAL_NAMES = {
    "OPENAI_API_KEY": "OpenAI", "AZURE_OPENAI_API_KEY": "Microsoft", "AZURE_OPENAI_ENDPOINT": "Microsoft",
    "ANTHROPIC_API_KEY": "Anthropic", "GEMINI_API_KEY": "Google", "MISTRAL_API_KEY": "Mistral",
    "COHERE_API_KEY": "Cohere", "GROQ_API_KEY": "Groq", "TOGETHER_API_KEY": "Together AI",
    "DEEPSEEK_API_KEY": "DeepSeek", "XAI_API_KEY": "xAI", "OPENROUTER_API_KEY": "OpenRouter",
    "PERPLEXITY_API_KEY": "Perplexity", "REPLICATE_API_TOKEN": "Replicate", "HF_TOKEN": "Hugging Face",
    "HUGGINGFACEHUB_API_TOKEN": "Hugging Face", "HUGGING_FACE_HUB_TOKEN": "Hugging Face",
}
CREDENTIAL_NAME = re.compile(r"\b(" + "|".join(sorted(CREDENTIAL_NAMES)) + r")\b")

IMAGES: tuple[tuple[str, str, str], ...] = (
    ("ollama/ollama", "ml-runtime", "Ollama"), ("vllm/vllm*", "ml-runtime", "vLLM"),
    ("ghcr.io/huggingface/text-generation-inference", "ml-runtime", "Hugging Face"),
    ("*localai/localai", "ml-runtime", "LocalAI"), ("ghcr.io/berriai/litellm*", "sdk", "LiteLLM"),
    ("ghcr.io/open-webui/open-webui", "ml-runtime", "Open WebUI"), ("qdrant/qdrant", "vector-store", "Qdrant"),
    ("chromadb/chroma", "vector-store", "Chroma"), ("*weaviate/weaviate", "vector-store", "Weaviate"),
    ("semitechnologies/weaviate", "vector-store", "Weaviate"), ("milvusdb/milvus", "vector-store", "Milvus"),
    ("pgvector/pgvector", "vector-store", "pgvector"),
)
IMAGE_REFERENCE = re.compile(r"""^\s*(?:FROM\s+(?:--platform=\S+\s+)?|-?\s*image:\s*["']?)([\w.\-/:@]+)""", re.IGNORECASE)
IAC_RESOURCES: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(rf"""\b(?:resource|data)\s+"({pattern})\""""), name, provider)
    for pattern, name, provider in (
        (r"aws_bedrock\w*", "Amazon Bedrock", "Amazon"), (r"aws_sagemaker\w*", "Amazon SageMaker", "Amazon"),
        (r"azurerm_cognitive\w*", "Azure AI Services", "Microsoft"),
        (r"azurerm_(?:ai|machine_learning)\w*", "Azure AI Foundry", "Microsoft"),
        (r"google_vertex_ai\w*", "Vertex AI", "Google"),
    )
)
CI_ACTIONS: tuple[tuple[str, str], ...] = (
    ("anthropics/claude-code-action*", "Claude Code"), ("openai/codex-action*", "Codex"),
    ("google-github-actions/run-gemini-cli*", "Gemini CLI"), ("cursor/*", "Cursor"),
)
CI_USES = re.compile(r"""^\s*-?\s*uses:\s*["']?([\w.\-]+/[\w.\-/]+)(?:@([\w.\-]+))?""")
AGENT_CONFIG: tuple[tuple[str, str], ...] = (
    ("claude.md", "Claude Code"), ("claude.local.md", "Claude Code"), (".claude/*", "Claude Code"),
    ("agents.md", "AGENTS.md"), ("agents.override.md", "AGENTS.md"), (".codex/*", "Codex"),
    (".cursorrules", "Cursor"), (".cursor/*", "Cursor"), (".github/copilot-instructions.md", "GitHub Copilot"),
    (".github/instructions/*", "GitHub Copilot"), (".github/copilot/*", "GitHub Copilot"),
    (".windsurfrules", "Windsurf"), (".windsurf/*", "Windsurf"), (".clinerules", "Cline"), (".clinerules/*", "Cline"),
    ("gemini.md", "Gemini CLI"), (".gemini/*", "Gemini CLI"), ("qwen.md", "Qwen Code"), (".qwen/*", "Qwen Code"),
    (".aider*", "Aider"), ("conventions.md", "Aider"), (".continue/*", "Continue"), (".kiro/*", "Kiro"),
    (".roo/*", "Roo Code"), (".devin/*", "Devin"), ("opencode.json", "opencode"), ("opencode.jsonc", "opencode"),
    (".opencode/*", "opencode"), (".zed/*", "Zed"), (".crush.json", "Crush"), ("crush.json", "Crush"),
)
INSTRUCTION_FILE = re.compile(
    r"(?:^|/)(?:claude\.md|claude\.local\.md|agents\.md|agents\.override\.md|gemini\.md|qwen\.md|conventions\.md|"
    r"\.cursorrules|\.windsurfrules|\.clinerules|copilot-instructions\.md|skill\.md|"
    r"[^/]+\.(?:instructions|prompt|agent)\.md)$|"
    r"(?:^|/)\.agents/.*\.md$|"
    r"(?:^|/)(?:\.cursor/rules|\.windsurf/rules|\.clinerules|\.roo/rules[^/]*|\.kiro/steering|\.continue/rules|"
    r"\.devin/rules|\.github/instructions|\.github/agents|\.github/prompts|"
    r"\.claude/(?:agents|commands|rules|skills))/",
    re.IGNORECASE,
)
MCP_CONFIG_NAMES = {
    ".mcp.json", "mcp.json", "mcp_config.json", "mcp-config.json", "managed-mcp.json",
    "claude_desktop_config.json", "cline_mcp_settings.json",
}
MCP_SERVER_CODE = re.compile(
    r"\b(?:FastMCP\s*\(|McpServer\s*\(|MCPServer\s*\(|McpServerFeatures\b|AddMcpServer\s*\(|"
    r"mcp\.(?:NewServer|server\.Server)\s*\(|server\.NewMCPServer\s*\()"
)
MCP_RUNNERS = {"npx", "pnpx", "bunx", "uvx", "pipx", "dlx"}
MODEL_FILES: dict[str, tuple[str, bool]] = {
    ".gguf": ("GGUF", False), ".ggml": ("GGML", False), ".safetensors": ("safetensors", False),
    ".onnx": ("ONNX", False), ".tflite": ("TensorFlow Lite", False), ".mlmodel": ("Core ML", False),
    ".keras": ("Keras", False), ".pt": ("PyTorch (may use pickle)", False), ".pth": ("PyTorch (may use pickle)", False),
    ".ckpt": ("checkpoint (may use pickle)", False), ".h5": ("HDF5, may not be a model", True),
    ".pb": ("protobuf, may not be a model", True), ".pkl": ("pickle, may not be a model", True),
    ".pickle": ("pickle, may not be a model", True), ".joblib": ("joblib, may not be a model", True),
}
PROMPT_FILE = re.compile(
    r"(?:\.prompt(?:\.\w+)?|\.prompty|\.jinja2?\.prompt)$|(?:^|/)(?:prompts?|system[_-]prompts?)/[^/]+\.\w+$|"
    r"(?:^|/)\.github/prompts/",
    re.IGNORECASE,
)
INLINE_PROMPT = re.compile(
    r"""\b[A-Za-z_]*SYSTEM_?(?:PROMPT|MESSAGE|INSTRUCTIONS?)\b|\bsystem_?prompt\b|\bsystemPrompt\b|"""
    r"""["']?role["']?\s*[:=]\s*["'](?:system|developer)["']|\b(?:Chat)?PromptTemplate\b|\bSystemMessage\s*\(|"""
    r"""\bsystem_instruction\b|\bsystemInstruction\b"""
)

EXCLUDED_DIRECTORIES = {".git", "node_modules", ".venv", "venv", ".tox", "__pycache__", "site-packages", ".terraform"}
PROSE = {".md", ".mdx", ".rst", ".adoc", ".txt", ".tex"}
NOT_TEXT_WE_READ = {".map", ".svg", ".csv", ".tsv", ".log", ".sum", ".lock"}
SOURCE = {
    ".py": "python", ".pyi": "python", ".ipynb": "notebook", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js", ".mts": "js", ".cts": "js", ".vue": "js", ".svelte": "js", ".go": "go",
    ".java": "jvm", ".kt": "jvm", ".scala": "jvm", ".cs": "dotnet", ".rb": "ruby", ".rs": "rust",
}
LOCAL_ENV = re.compile(r"(?:^|/)\.env(?:\.(?!example|sample|template|dist)[\w.\-]+)?$", re.IGNORECASE)
NON_PRODUCTION = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|testdata|examples?|samples?|demos?|docs?|e2e)(?:/|$)|"
    r"(?:^|/)(?:test_[^/]+|[^/]+_test\.\w+|[^/]+\.(?:test|spec)\.\w+)$",
    re.IGNORECASE,
)
AUTOMATION_PATH = re.compile(
    r"(?:^|/)\.(?:github|gitlab|circleci|buildkite)/|(?:^|/)(?:\.gitlab-ci\.ya?ml|azure-pipelines\.ya?ml|Jenkinsfile)$",
    re.IGNORECASE,
)

SECRET_PATTERNS = [
    re.compile(pattern)
    for pattern in (
        r"\bsk-[A-Za-z0-9_-]{12,}", r"\bgh[pousr]_[A-Za-z0-9]{20,}", r"\bgithub_pat_\w{20,}", r"\bAKIA[0-9A-Z]{16}\b",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}", r"\bAIza[0-9A-Za-z_-]{20,}", r"\bhf_[A-Za-z0-9]{20,}",
        r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]*", r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    )
]
SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:api[_-]?key|access[_-]?key|auth[_-]?token|token|secret|password|passwd|authorization)"
    r"[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?)(?!\$\{|\$[A-Za-z_]|<|os\.|process\.)([^\s\"',})]{6,})"
)
URL_CREDENTIAL = re.compile(r"(://[^/\s:@]+:)[^/\s@]+(@)")


class Refusal(Exception):
    """A request the helper will not carry out. Exit code 2."""


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    text = SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + "[redacted]", text)
    return URL_CREDENTIAL.sub(r"\1[redacted]\2", text)


def visible(text: str) -> str:
    """Make invisible characters and control characters visible, so a reader sees what is really there."""
    out = []
    for char in text:
        if unicodedata.category(char) in {"Cf", "Cc"} and char != "\t":
            out.append(f"<U+{ord(char):04X}>")
        else:
            out.append(char)
    return "".join(out)


def snippet(text: str, limit: int = 200) -> str:
    cleaned = visible(redact(text.strip()))
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def is_inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def session_position(cwd: Path, target: Path) -> str:
    if is_inside(cwd, target):
        return "inside"
    if is_inside(target, cwd):
        return "parent"
    return "outside"


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8")


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise Refusal(f"{label} not found at {path}.") from None
    except (OSError, ValueError) as error:
        raise Refusal(f"{label} could not be read: {error}") from None


def walk_files(root: Path, coverage: dict[str, Any]) -> Iterator[tuple[str, Path]]:
    """Yield regular files. Symlinks are never followed, and ignore files have no say in what is read."""
    for directory, subdirectories, files in os.walk(root, followlinks=False):
        here = Path(directory)
        kept = []
        for name in sorted(subdirectories):
            path = here / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                coverage["symlinks_not_followed"].append(relative)
            elif name in EXCLUDED_DIRECTORIES:
                coverage["excluded_directories"].append(relative)
            else:
                kept.append(name)
        subdirectories[:] = kept
        for name in sorted(files):
            path = here / name
            relative = path.relative_to(root).as_posix()
            try:
                mode = os.lstat(path).st_mode
            except OSError:
                coverage["unreadable"].append(relative)
                continue
            if stat.S_ISLNK(mode):
                coverage["symlinks_not_followed"].append(relative)
            elif stat.S_ISREG(mode):
                yield relative, path


def package_identity(ecosystem: str, name: str) -> tuple[str, str] | None:
    lowered = name.lower()
    if ecosystem == "pypi":
        lowered = lowered.replace("_", "-").replace(".", "-")
    for category, provider, names in PACKAGES:
        for pattern in names.get(ecosystem, ()):
            if fnmatch.fnmatchcase(lowered, pattern):
                return category, provider
    return None


def purl(ecosystem: str, name: str, version: str | None) -> str | None:
    kinds = {"pypi": "pypi", "npm": "npm", "go": "golang", "maven": "maven", "nuget": "nuget", "gem": "gem",
             "cargo": "cargo", "docker": "docker"}
    kind = kinds.get(ecosystem)
    if kind is None or "*" in name:
        return None
    if ecosystem == "pypi":
        path = name.lower().replace("_", "-").replace(".", "-")
    elif ecosystem == "maven":
        path = name.replace(":", "/")
    else:
        path = name
    encoded = "/".join(quote(part, safe="") for part in path.split("/"))
    return f"pkg:{kind}/{encoded}" + (f"@{quote(version, safe='')}" if version else "")


class Collector:
    """Accumulates detections, merging repeat sightings of the same thing into one entry."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add(self, category: str, name: str, *, relative: str, line: int, text: str, technique: str,
            confidence: float, provider: str | None = None, ecosystem: str | None = None,
            version: str | None = None, review: str | None = None, surface: str = "build",
            properties: dict[str, str] | None = None, endpoint: str | None = None,
            hashes: dict[str, str] | None = None) -> dict[str, Any]:
        key = (category, ecosystem or "", name.lower())
        item = self.items.get(key)
        if item is None:
            item = {
                "category": category, "name": name, "provider": provider, "ecosystem": ecosystem, "versions": [],
                "technique": technique, "confidence": confidence, "review_reasons": [], "surface": surface,
                "properties": {}, "endpoints": [], "hashes": {}, "occurrences": [], "occurrence_count": 0,
                "contexts": set(), "signals": set(), "surfaces": set(),
            }
            self.items[key] = item
        if confidence > item["confidence"]:
            item["confidence"], item["technique"] = confidence, technique
        if provider and not item["provider"]:
            item["provider"] = provider
        if version and version not in item["versions"]:
            item["versions"].append(version)
        if review and review not in item["review_reasons"]:
            item["review_reasons"].append(review)
        if endpoint and endpoint not in item["endpoints"]:
            item["endpoints"].append(endpoint)
        item["properties"].update(properties or {})
        item["hashes"].update(hashes or {})
        item["signals"].add(technique)
        item["surfaces"].add("use" if AUTOMATION_PATH.search(relative) else surface)
        item["contexts"].add("non-production" if NON_PRODUCTION.search(relative) else "production")
        item["occurrence_count"] += 1
        location = {"file": relative, "line": line, "snippet": snippet(text)}
        if len(item["occurrences"]) < MAX_OCCURRENCES and location not in item["occurrences"]:
            item["occurrences"].append(location)
        return item

    def package(self, ecosystem: str, name: str, *, relative: str, line: int, text: str, version: str | None = None,
                kind: str = "declared", constraint: str | None = None) -> None:
        identity = package_identity(ecosystem, name)
        if identity is None:
            return
        category, provider = identity
        technique = "source-code-analysis" if kind == "imported" else "manifest-analysis"
        confidence = {"declared": 0.95, "locked": 0.9, "imported": 0.85}[kind]
        properties = {"constraint": constraint} if constraint else None
        item = self.add(category, name, relative=relative, line=line, text=text, technique=technique,
                        confidence=confidence, provider=provider, ecosystem=ecosystem, version=version,
                        properties=properties)
        item["signals"].add(kind)

    def finish(self) -> list[dict[str, Any]]:
        providers_with_sdk = {
            item["provider"] for item in self.items.values() if item["category"] == "sdk" and item["provider"]
        }
        result = []
        for item in self.items.values():
            signals = item.pop("signals")
            contexts = item.pop("contexts")
            item["surface"] = "build" if "build" in item.pop("surfaces") else "use"
            if item["ecosystem"] and item["ecosystem"] != "docker":
                if signals & {"declared", "locked"}:
                    item["properties"]["dependency"] = "direct" if "declared" in signals else "locked only"
                else:
                    item["properties"]["dependency"] = "imported, not declared in a manifest"
                    item["review_reasons"].append("Imported in code but not declared in any manifest.")
            if item["category"] == "hosted-service" and signals == {"credential-name"}:
                if item["provider"] not in providers_with_sdk:
                    item["review_reasons"].append("Only a credential name refers to this service.")
            elif item["category"] == "hosted-service":
                item["review_reasons"] = [
                    reason for reason in item["review_reasons"] if reason != "Only a credential name refers to this service."
                ]
            if contexts == {"non-production"} and item["category"] in {"model", "hosted-service", "prompt"}:
                item["review_reasons"].append("Seen only in tests, examples, or docs.")
            item["context"] = "production" if "production" in contexts else "non-production"
            item["technique"] = "source-code-analysis" if item["technique"] == "credential-name" else item["technique"]
            item["versions"].sort()
            item["endpoints"].sort()
            item["review"] = bool(item["review_reasons"])
            result.append(item)
        order = {category: index for index, category in enumerate(CATEGORIES)}
        result.sort(key=lambda item: (order[item["category"]], item["name"].lower(), item["ecosystem"] or ""))
        for number, item in enumerate(result, 1):
            item["id"] = f"D{number:03d}"
        return result


def line_of(text: str, needle: str) -> int:
    position = text.find(needle)
    return text.count("\n", 0, position) + 1 if position >= 0 else 1


PEP508 = re.compile(r"^\s*([A-Za-z0-9][\w.\-]*)\s*(?:\[[^\]]*\])?\s*(?:(==|===|~=|>=|<=|>|<|!=)\s*([^\s;,#]+))?")
QUOTED_REQUIREMENT = re.compile(r"""["']([A-Za-z0-9][\w.\-]*)\s*(?:\[[^\]]*\])?\s*(?:(==|===|~=|>=|<=|>|<|!=|\^)\s*([^"',;\s]+))?[^"']*["']""")
TOML_KEY = re.compile(r"""^\s*["']?([A-Za-z0-9][\w.\-]*)["']?\s*=\s*(?:["']([^"']*)["']|\{[^}]*?version\s*=\s*["']([^"']*)["'])""")


def parse_requirements(relative: str, text: str, collector: Collector) -> None:
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        match = PEP508.match(stripped)
        if match:
            pinned = match.group(2) in {"==", "==="}
            collector.package("pypi", match.group(1), relative=relative, line=number, text=stripped,
                              version=match.group(3) if pinned else None,
                              constraint=None if pinned or not match.group(2) else match.group(2) + match.group(3))


def parse_python_project(relative: str, text: str, collector: Collector) -> None:
    """pyproject.toml, setup.cfg, setup.py, and Pipfile, read line by line for known names only."""
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or re.match(r"^(?:name|version|description)\s*=", stripped):
            continue
        for name, operator, value in QUOTED_REQUIREMENT.findall(stripped):
            if package_identity("pypi", name):
                pinned = operator in {"==", "==="}
                collector.package("pypi", name, relative=relative, line=number, text=stripped,
                                  version=value if pinned else None,
                                  constraint=None if pinned or not operator else operator + value)
        match = TOML_KEY.match(stripped)
        if match and package_identity("pypi", match.group(1)):
            value = match.group(2) or match.group(3) or ""
            pinned = re.fullmatch(r"(?:==)?\d[\w.\-]*", value) is not None
            collector.package("pypi", match.group(1), relative=relative, line=number, text=stripped,
                              version=value.lstrip("=") if pinned else None,
                              constraint=None if pinned or value in {"", "*"} else value)


def parse_package_json(relative: str, text: str, collector: Collector) -> None:
    try:
        document = json.loads(text)
    except ValueError:
        return
    if not isinstance(document, dict):
        return
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        dependencies = document.get(section)
        if not isinstance(dependencies, dict):
            continue
        for name, version in dependencies.items():
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            pinned = re.fullmatch(r"\d[\w.\-+]*", version) is not None
            collector.package("npm", name, relative=relative, line=line_of(text, f'"{name}"'),
                              text=f'"{name}": "{version}"', version=version if pinned else None,
                              constraint=None if pinned else version)


def parse_package_lock(relative: str, text: str, collector: Collector) -> None:
    try:
        document = json.loads(text)
    except ValueError:
        return
    packages = document.get("packages") if isinstance(document, dict) else None
    if not isinstance(packages, dict):
        return
    for path, entry in packages.items():
        if not path or not isinstance(entry, dict) or "node_modules/" not in path:
            continue
        name = path.rsplit("node_modules/", 1)[1]
        version = entry.get("version")
        if isinstance(version, str) and package_identity("npm", name):
            collector.package("npm", name, relative=relative, line=line_of(text, f'"{path}"'),
                              text=f"{name}@{version}", version=version, kind="locked")


def parse_toml_lock(relative: str, text: str, collector: Collector) -> None:
    """poetry.lock, uv.lock, and pdm.lock: each [[package]] table starts with a name and a version."""
    name, name_line = None, 0
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("[["):
            name = None
        match = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if match:
            name, name_line = match.group(1), number
            continue
        match = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if match and name and package_identity("pypi", name):
            collector.package("pypi", name, relative=relative, line=name_line,
                              text=f"{name} {match.group(1)}", version=match.group(1), kind="locked")
            name = None


def parse_pipfile_lock(relative: str, text: str, collector: Collector) -> None:
    try:
        document = json.loads(text)
    except ValueError:
        return
    if not isinstance(document, dict):
        return
    for section in ("default", "develop"):
        entries = document.get(section)
        if isinstance(entries, dict):
            for name, entry in entries.items():
                version = entry.get("version", "") if isinstance(entry, dict) else ""
                if package_identity("pypi", name) and isinstance(version, str):
                    collector.package("pypi", name, relative=relative, line=line_of(text, f'"{name}"'),
                                      text=f"{name}{version}", version=version.lstrip("=") or None, kind="locked")


def parse_pnpm_lock(relative: str, text: str, collector: Collector) -> None:
    pattern = re.compile(r"""^\s*['"]?/?(@?[\w.\-]+(?:/[\w.\-]+)?)@(\d[\w.\-+]*)""")
    for number, line in enumerate(text.splitlines(), 1):
        match = pattern.match(line)
        if match and package_identity("npm", match.group(1)):
            collector.package("npm", match.group(1), relative=relative, line=number,
                              text=f"{match.group(1)}@{match.group(2)}", version=match.group(2), kind="locked")


def parse_yarn_lock(relative: str, text: str, collector: Collector) -> None:
    name, name_line = None, 0
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"""^"?(@?[^@\s"]+)@[^:]*:\s*$""", line)
        if match:
            name, name_line = match.group(1), number
            continue
        match = re.match(r"""^\s+version:?\s+"?([^"\s]+)"?""", line)
        if match and name and package_identity("npm", name):
            collector.package("npm", name, relative=relative, line=name_line,
                              text=f"{name}@{match.group(1)}", version=match.group(1), kind="locked")
            name = None


def parse_go_mod(relative: str, text: str, collector: Collector) -> None:
    pattern = re.compile(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-]+/[^\s]+)\s+(v[^\s]+)(\s*//\s*indirect)?")
    for number, line in enumerate(text.splitlines(), 1):
        match = pattern.match(line)
        if match:
            collector.package("go", match.group(1), relative=relative, line=number, text=line,
                              version=match.group(2), kind="locked" if match.group(3) else "declared")


def parse_pom(relative: str, text: str, collector: Collector) -> None:
    """Regular expressions on purpose: a repository's XML is never handed to an XML parser."""
    for block in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        body = block.group(1)
        group = re.search(r"<groupId>\s*([^<\s]+)", body)
        artifact = re.search(r"<artifactId>\s*([^<\s]+)", body)
        version = re.search(r"<version>\s*([^<\s]+)", body)
        if group and artifact:
            value = version.group(1) if version and not version.group(1).startswith("$") else None
            collector.package("maven", f"{group.group(1)}:{artifact.group(1)}", relative=relative,
                              line=text.count("\n", 0, block.start()) + 1,
                              text=f"{group.group(1)}:{artifact.group(1)}", version=value)


def parse_gradle(relative: str, text: str, collector: Collector) -> None:
    pattern = re.compile(r"""["']([\w.\-]+):([\w.\-]+)(?::([\w.\-]+))?["']""")
    for number, line in enumerate(text.splitlines(), 1):
        for group, artifact, version in pattern.findall(line):
            collector.package("maven", f"{group}:{artifact}", relative=relative, line=number,
                              text=line, version=version or None)


def parse_dotnet(relative: str, text: str, collector: Collector) -> None:
    pattern = re.compile(r"""<Package(?:Reference|Version)\b[^>]*\bInclude="([^"]+)"(?:[^>]*\bVersion="([^"]+)")?""")
    legacy = re.compile(r"""<package\b[^>]*\bid="([^"]+)"(?:[^>]*\bversion="([^"]+)")?""")
    for number, line in enumerate(text.splitlines(), 1):
        for name, version in pattern.findall(line) + legacy.findall(line):
            collector.package("nuget", name, relative=relative, line=number, text=line, version=version or None)


def parse_gemfile(relative: str, text: str, collector: Collector) -> None:
    pattern = re.compile(r"""^\s*gem\s+["']([\w.\-]+)["'](?:\s*,\s*["']=?\s*(\d[\w.\-]*)["'])?""")
    for number, line in enumerate(text.splitlines(), 1):
        match = pattern.match(line)
        if match:
            collector.package("gem", match.group(1), relative=relative, line=number, text=line, version=match.group(2))


def parse_cargo(relative: str, text: str, collector: Collector) -> None:
    for number, line in enumerate(text.splitlines(), 1):
        match = TOML_KEY.match(line)
        if match and package_identity("cargo", match.group(1)):
            value = match.group(2) or match.group(3) or ""
            collector.package("cargo", match.group(1), relative=relative, line=number, text=line,
                              constraint=value or None)


MANIFESTS: tuple[tuple[re.Pattern[str], Any], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), parser)
    for pattern, parser in (
        (r"(?:^|/)(?:[^/]*requirements[^/]*|constraints[^/]*)\.(?:txt|in)$", parse_requirements),
        (r"(?:^|/)(?:pyproject\.toml|setup\.cfg|setup\.py|pipfile)$", parse_python_project),
        (r"(?:^|/)(?:poetry\.lock|uv\.lock|pdm\.lock)$", parse_toml_lock),
        (r"(?:^|/)pipfile\.lock$", parse_pipfile_lock),
        (r"(?:^|/)package\.json$", parse_package_json),
        (r"(?:^|/)(?:package-lock|npm-shrinkwrap)\.json$", parse_package_lock),
        (r"(?:^|/)pnpm-lock\.ya?ml$", parse_pnpm_lock),
        (r"(?:^|/)yarn\.lock$", parse_yarn_lock),
        (r"(?:^|/)go\.mod$", parse_go_mod),
        (r"(?:^|/)pom\.xml$", parse_pom),
        (r"(?:^|/)(?:build\.gradle(?:\.kts)?|libs\.versions\.toml)$", parse_gradle),
        (r"\.(?:csproj|fsproj|vbproj)$|(?:^|/)(?:directory\.packages\.props|packages\.config)$", parse_dotnet),
        (r"(?:^|/)gemfile$", parse_gemfile),
        (r"(?:^|/)cargo\.toml$", parse_cargo),
    )
)


def imports_in(language: str, line: str) -> Iterable[tuple[str, str]]:
    """Yield (ecosystem, package) for each module a source line imports."""
    if language == "python":
        match = re.match(r"^\s*from\s+([\w.]+)\s+import\b", line)
        modules = [match.group(1)] if match else []
        match = re.match(r"^\s*import\s+(.+)$", line)
        if match:
            modules += [part.split(" as ")[0].strip() for part in match.group(1).split("#")[0].split(",")]
        for module in modules:
            parts = module.split(".")
            for size in range(1, len(parts) + 1):
                candidate = "-".join(parts[:size]).replace("_", "-")
                if package_identity("pypi", candidate):
                    yield "pypi", candidate
                    break
    elif language == "js":
        for module in re.findall(r"""(?:\bfrom\s+|\brequire\(\s*|\bimport\(\s*|^\s*import\s+)["']([^"'.][^"']*)["']""", line):
            pieces = module.split("/")
            name = "/".join(pieces[:2]) if module.startswith("@") else pieces[0]
            yield "npm", name
    elif language == "go":
        match = re.match(r"""^\s*(?:import\s+)?(?:[\w.]+\s+)?"([\w.\-]+\.[\w.\-]+/[^"]+)"\s*$""", line)
        if match:
            yield "go", match.group(1)
    elif language == "jvm":
        match = re.match(r"^\s*import\s+(?:static\s+)?([\w.]+)", line)
        if match:
            for prefix, pattern in JVM_IMPORTS.items():
                if match.group(1) == prefix or match.group(1).startswith(prefix + "."):
                    yield "maven", pattern
    elif language == "dotnet":
        match = re.match(r"^\s*(?:global\s+)?using\s+(?:static\s+)?([\w.]+)\s*;", line)
        if match:
            parts = match.group(1).split(".")
            for size in range(1, len(parts) + 1):
                candidate = ".".join(parts[:size])
                if package_identity("nuget", candidate):
                    yield "nuget", candidate
                    break
    elif language == "ruby":
        match = re.match(r"""^\s*require\s+["']([\w.\-]+)""", line)
        if match:
            yield "gem", match.group(1)
    elif language == "rust":
        match = re.match(r"^\s*(?:pub\s+)?use\s+(\w+)", line)
        if match:
            yield "cargo", match.group(1).replace("_", "-")


def model_identity(value: str) -> tuple[str, str] | None:
    """Return (provider, id) when a string is a recognized model identifier."""
    stripped = value.strip()
    if len(stripped) > 120 or " " in stripped or "://" in stripped:
        return None
    bare = stripped
    while True:
        shorter = MODEL_ROUTE_PREFIX.sub("", bare)
        if shorter == bare:
            break
        bare = shorter
    for provider, pattern in MODEL_FAMILIES:
        if pattern.fullmatch(bare):
            return provider, stripped
    return None


OPAQUE_VALUE = re.compile(r"^(?:[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-f]{16,}|\d[\d.\-:/]*)$", re.IGNORECASE)
MODEL_NAME_SHAPE = re.compile(r"^[A-Za-z0-9][\w.:@+\-]*(?:/[A-Za-z0-9][\w.:@+\-]*)*$")


def plausible_custom_model(value: str) -> bool:
    if len(value) < 3 or not MODEL_NAME_SHAPE.match(value) or OPAQUE_VALUE.match(value):
        return False
    if value.lower().endswith((".py", ".ts", ".js", ".json", ".yaml", ".yml", ".html")):
        return False
    return bool(re.search(r"\d", value) or "-" in value or "/" in value)


def scan_strings(relative: str, line: str, number: int, collector: Collector) -> None:
    """Model identifiers, endpoints, and credential names, on any text line."""
    for name in CREDENTIAL_NAME.findall(line):
        provider = CREDENTIAL_NAMES[name]
        collector.add("hosted-service", f"{provider} (credential reference)", relative=relative, line=number,
                      text=name, technique="credential-name", confidence=0.6, provider=provider,
                      review="Only a credential name refers to this service.")
    for url in URL.findall(line):
        matched = False
        for pattern, name, provider in HOSTS:
            found = pattern.search(url)
            if found:
                matched = True
                collector.add("hosted-service", name, relative=relative, line=number, text=line,
                              technique="source-code-analysis", confidence=0.9, provider=provider,
                              endpoint=endpoint_of(url))
                break
        if matched:
            continue
        looks_inference = INFERENCE_PATH.search(url.split("?")[0]) is not None
        if looks_inference or BASE_URL_NAME.search(line):
            host = endpoint_of(url)
            bare = host.split("://", 1)[1] if host else ""
            if host and "%" not in bare and ("." in bare or ":" in bare) and not re.fullmatch(r"(?:localhost|127\.0\.0\.1)", bare):
                reason = ("URL path looks like a model API." if looks_inference
                          else "A setting named like a model endpoint points here.")
                collector.add("hosted-service", host.split("://", 1)[1], relative=relative, line=number, text=line,
                              technique="source-code-analysis", confidence=0.5, review=reason, endpoint=host)
    match = HOST_SEARCH.search(line) if "http" not in line.lower() else None
    if match:
        for pattern, name, provider in HOSTS:
            if pattern.search(match.group(0)):
                collector.add("hosted-service", name, relative=relative, line=number, text=line,
                              technique="source-code-analysis", confidence=0.8, provider=provider)
                break
    seen = set()
    for _, value in QUOTED.findall(line):
        identity = model_identity(value)
        if identity and identity[1] not in seen:
            seen.add(identity[1])
            collector.add("model", identity[1], relative=relative, line=number, text=line,
                          technique="source-code-analysis", confidence=0.85, provider=identity[0])
    for name_part, value in MODEL_ASSIGNMENT.findall(line):
        if value in seen:
            continue
        identity = model_identity(value)
        if identity:
            seen.add(identity[1])
            collector.add("model", identity[1], relative=relative, line=number, text=line,
                          technique="source-code-analysis", confidence=0.85, provider=identity[0])
        elif plausible_custom_model(value):
            seen.add(value)
            collector.add("model", value, relative=relative, line=number, text=line, technique="source-code-analysis",
                          confidence=0.4, review=f"The setting `{name_part}` holds a name no table recognizes.")
    for value in HF_ID.findall(line):
        if value not in seen and model_identity(value) is None:
            seen.add(value)
            collector.add("model", value, relative=relative, line=number, text=line,
                          technique="source-code-analysis", confidence=0.8, provider="Hugging Face Hub")


def endpoint_of(url: str) -> str | None:
    """Scheme and host only. A URL's path, query, and credentials stay out of the inventory."""
    match = re.match(r"([a-z][a-z0-9+.\-]*)://(?:[^/@\s]+@)?([^/?#\s:]+(?::\d+)?)", url, re.IGNORECASE)
    if not match or "$" in match.group(2) or "{" in match.group(2):
        return None
    return f"{match.group(1).lower()}://{match.group(2).lower()}"


def unwrap_notebook_line(line: str) -> str:
    match = re.match(r'^\s*"(.*?)(?:\\n)?",?\s*$', line)
    return match.group(1).replace('\\"', '"') if match else line


def scan_source(relative: str, language: str, lines: list[str], collector: Collector) -> None:
    effective = "python" if language == "notebook" else language
    for number, raw in enumerate(lines, 1):
        line = unwrap_notebook_line(raw) if language == "notebook" else raw
        if len(line) > MAX_LINE_CHARS:
            continue
        for ecosystem, name in imports_in(effective, line):
            if ecosystem == "maven":
                prefix = name.split(":")[0]
                collector.package("maven", prefix + ":*", relative=relative, line=number, text=line, kind="imported")
            else:
                collector.package(ecosystem, name, relative=relative, line=number, text=line, kind="imported")
        if INLINE_PROMPT.search(line):
            collector.add("prompt", relative, relative=relative, line=number, text=line,
                          technique="source-code-analysis", confidence=0.7, properties={"form": "inline"})
        if MCP_SERVER_CODE.search(line):
            collector.add("mcp-server", relative, relative=relative, line=number, text=line,
                          technique="source-code-analysis", confidence=0.8, properties={"origin": "implemented here"})


def merge_imports_into_declarations(collector: Collector) -> None:
    """Attach a JVM group-level import to the artifact declared for that group."""
    for key in [key for key in collector.items if key[1] == "maven" and key[2].endswith(":*")]:
        group = key[2][:-2]
        wildcard = collector.items[key]
        declared = [item for other, item in collector.items.items()
                    if other[1] == "maven" and other != key and other[2].startswith(group)]
        if declared:
            del collector.items[key]
            declared[0]["occurrences"].extend(wildcard["occurrences"])
            declared[0]["occurrences"] = declared[0]["occurrences"][:MAX_OCCURRENCES]
            declared[0]["occurrence_count"] += wildcard["occurrence_count"]
            declared[0]["signals"] |= wildcard["signals"]
            declared[0]["surfaces"] |= wildcard["surfaces"]
        else:
            wildcard["name"] = group


def strip_jsonc(text: str) -> str:
    """Remove // comments and trailing commas, leaving string contents alone."""
    out, index, in_string = [], 0, False
    while index < len(text):
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < len(text):
                out.append(text[index + 1])
                index += 1
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            out.append(char)
        elif text.startswith("//", index):
            while index < len(text) and text[index] != "\n":
                index += 1
            continue
        else:
            out.append(char)
        index += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def package_argument(args: list[str]) -> str | None:
    skip_next = {"-p", "--package", "--from", "--with"}
    index = 0
    while index < len(args):
        value = args[index]
        if value in skip_next and index + 1 < len(args):
            return args[index + 1]
        if not value.startswith("-") and value != "dlx":
            return value
        index += 1
    return None


def is_pinned(package: str) -> bool:
    if "==" in package:
        return True
    at = package.rfind("@")
    if at <= 0:
        return False
    return re.fullmatch(r"v?\d+\.\d+[\w.\-+]*", package[at + 1:]) is not None


def record_mcp_server(relative: str, text: str, name: str, entry: dict[str, Any], collector: Collector) -> None:
    command = entry.get("command") if isinstance(entry.get("command"), str) else None
    args = [item for item in entry.get("args", []) if isinstance(item, str)] if isinstance(entry.get("args"), list) else []
    url = next((entry[key] for key in ("url", "serverUrl", "httpUrl", "uri") if isinstance(entry.get(key), str)), None)
    properties = {"origin": "configured", "config": relative}
    package = None
    runner = Path(command).name.lower() if command else ""
    if runner in MCP_RUNNERS or runner in {"pnpm", "yarn", "bun", "npm"}:
        package = package_argument(args)
    if runner == "docker":
        package = next((item for item in args if ":" in item or "/" in item), None)
    if package:
        properties["package"] = redact(package)
        properties["pinned"] = "yes" if is_pinned(package) else "no"
    if command:
        properties["command"] = snippet(" ".join([command, *args]), 300)
    properties["transport"] = "remote" if url else "local process"
    environment = entry.get("env")
    if isinstance(environment, dict) and environment:
        properties["environment variable names"] = ", ".join(sorted(str(key) for key in environment))
    collector.add("mcp-server", name, relative=relative, line=line_of(text, f'"{name}"'), text=f"MCP server entry {name}",
                  technique="manifest-analysis", confidence=0.95, surface="use", properties=properties,
                  endpoint=endpoint_of(url) if url else None)


def scan_mcp_config(relative: str, text: str, collector: Collector, coverage: dict[str, Any]) -> None:
    try:
        document = json.loads(strip_jsonc(text))
    except ValueError:
        coverage["unparsed_config"].append(relative)
        collector.add("mcp-server", f"Unparsed MCP configuration in {relative}", relative=relative, line=1,
                      text="(file could not be parsed)", technique="filename", confidence=0.4, surface="use",
                      review="This looks like MCP configuration but could not be parsed.")
        return
    if not isinstance(document, dict):
        return
    sections = [document.get(key) for key in ("mcpServers", "servers", "mcp_servers")]
    mcp = document.get("mcp")
    if isinstance(mcp, dict):
        sections += [mcp.get("servers"), mcp.get("mcpServers"), mcp]
    for section in sections:
        if isinstance(section, dict):
            for name, entry in section.items():
                if isinstance(entry, dict) and (set(entry) & {"command", "url", "serverUrl", "httpUrl", "uri", "type"}):
                    record_mcp_server(relative, text, str(name), entry, collector)


def scan_mcp_toml(relative: str, text: str, collector: Collector) -> None:
    current, entry, in_server_table = None, {}, False

    def flush() -> None:
        if current:
            record_mcp_server(relative, text, current, entry, collector)

    for line in text.splitlines():
        if line.lstrip().startswith("["):
            header = re.match(r"""^\s*\[mcp_servers\.(?:"([^"]+)"|'([^']+)'|([\w\-]+))(\.[^\]]+)?\]\s*$""", line)
            name = (header.group(1) or header.group(2) or header.group(3)) if header else None
            if name == current and current is not None:
                in_server_table = False
                continue
            flush()
            current, entry, in_server_table = name, {}, name is not None and not header.group(4)
            if name is not None and header.group(4):
                in_server_table = False
            continue
        if current and in_server_table:
            value = re.match(r"""^\s*(command|url)\s*=\s*["']([^"']*)["']""", line)
            if value:
                entry[value.group(1)] = value.group(2)
            arguments = re.match(r"^\s*args\s*=\s*\[(.*)\]", line)
            if arguments:
                entry["args"] = re.findall(r"""["']([^"']*)["']""", arguments.group(1))
    flush()


def record_model_file(relative: str, path: Path, collector: Collector, coverage: dict[str, Any]) -> bool:
    suffix = path.suffix.lower()
    if suffix not in MODEL_FILES:
        return False
    described, ambiguous = MODEL_FILES[suffix]
    properties = {"format": described}
    hashes: dict[str, str] = {}
    try:
        size = os.lstat(path).st_size
        with path.open("rb") as handle:
            head = handle.read(1024)
            if head.startswith(b"version https://git-lfs"):
                properties["storage"] = "Git LFS pointer; the weights are not in this checkout"
                oid = re.search(rb"oid sha256:([0-9a-f]{64})", head)
                if oid:
                    hashes["SHA-256"] = oid.group(1).decode()
            elif size > MAX_HASH_BYTES:
                coverage["not_hashed"].append(relative)
            else:
                digest = hashlib.sha256(head)
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
                hashes["SHA-256"] = digest.hexdigest()
    except OSError:
        coverage["unreadable"].append(relative)
        return True
    collector.add("model", relative, relative=relative, line=0, text=f"Model file ({described})", technique="filename",
                  confidence=0.5 if ambiguous else 0.9, properties=properties, hashes=hashes,
                  review="The file extension does not establish that this is a model." if ambiguous else None)
    return True


def scan_infrastructure(relative: str, lines: list[str], collector: Collector) -> None:
    is_terraform = relative.lower().endswith((".tf", ".tf.json", ".tfvars"))
    is_workflow = bool(re.search(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", relative, re.IGNORECASE))
    for number, line in enumerate(lines, 1):
        if len(line) > MAX_LINE_CHARS:
            continue
        reference = IMAGE_REFERENCE.match(line)
        if reference:
            image = reference.group(1).split("@")[0]
            name, _, tag = image.partition(":") if ":" in image.rsplit("/", 1)[-1] else (image, "", "")
            for pattern, category, provider in IMAGES:
                if fnmatch.fnmatchcase(name.lower(), pattern):
                    collector.add(category, name, relative=relative, line=number, text=line,
                                  technique="manifest-analysis", confidence=0.9, provider=provider, ecosystem="docker",
                                  version=tag or None, surface="build")
                    break
        if is_terraform:
            for pattern, name, provider in IAC_RESOURCES:
                match = pattern.search(line)
                if match:
                    collector.add("hosted-service", name, relative=relative, line=number, text=line,
                                  technique="manifest-analysis", confidence=0.85, provider=provider,
                                  properties={"declared by": "infrastructure as code"})
        if is_workflow:
            uses = CI_USES.match(line)
            if uses:
                for pattern, name in CI_ACTIONS:
                    if fnmatch.fnmatchcase(uses.group(1).lower(), pattern):
                        collector.add("coding-agent", name, relative=relative, line=number, text=line,
                                      technique="manifest-analysis", confidence=0.9, surface="use",
                                      properties={"runs in": "CI"})


def record_agent_config(relative: str, collector: Collector) -> None:
    lowered = relative.lower()
    tail = lowered.rsplit("/", 1)[-1]
    for pattern, name in AGENT_CONFIG:
        if "/" in pattern:
            matched = lowered.startswith(pattern[:-1]) or f"/{pattern[:-1]}" in lowered
        else:
            matched = fnmatch.fnmatchcase(tail, pattern)
        if matched:
            collector.add("coding-agent", name, relative=relative, line=0, text="Agent configuration file",
                          technique="filename", confidence=0.9, surface="use")
            return


def read_text(path: Path, relative: str, coverage: dict[str, Any]) -> str | None:
    try:
        if os.lstat(path).st_size > MAX_FILE_BYTES:
            coverage["skipped_large"].append(relative)
            return None
        data = path.read_bytes()
    except OSError:
        coverage["unreadable"].append(relative)
        return None
    if b"\0" in data[:8192]:
        coverage["binary_files"] += 1
        return None
    return data.decode("utf-8", errors="replace")


def scan_local_env(relative: str, text: str, collector: Collector) -> None:
    """Key names only, plus values of settings that name a model or a URL. Credential values are never read out."""
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][\w]*)\s*=\s*[\"']?([^\"'\s#]*)", line)
        if not match:
            continue
        key, value = match.groups()
        if key in CREDENTIAL_NAMES:
            provider = CREDENTIAL_NAMES[key]
            collector.add("hosted-service", f"{provider} (credential reference)", relative=relative, line=number, text=key,
                          technique="credential-name", confidence=0.6, provider=provider,
                          review="Only a credential name refers to this service.")
        elif re.search(r"MODEL", key, re.IGNORECASE) and value and not any(p.search(value) for p in SECRET_PATTERNS):
            identity = model_identity(value)
            if identity:
                collector.add("model", identity[1], relative=relative, line=number, text=key,
                              technique="source-code-analysis", confidence=0.85, provider=identity[0])


def walk_target(root: Path) -> dict[str, Any]:
    coverage: dict[str, Any] = {
        "files_seen": 0, "files_read": 0, "binary_files": 0, "prose_files_not_scanned": [], "skipped_large": [],
        "skipped_generated": [], "symlinks_not_followed": [], "excluded_directories": [], "unreadable": [],
        "unparsed_config": [], "not_hashed": [],
    }
    collector = Collector()
    instruction_files: list[str] = []
    listing: list[str] = []
    for relative, path in walk_files(root, coverage):
        coverage["files_seen"] += 1
        if len(listing) < MAX_LISTED_FILES:
            listing.append(relative)
        lowered = relative.lower()
        name = lowered.rsplit("/", 1)[-1]
        suffix = path.suffix.lower()
        record_agent_config(relative, collector)
        if INSTRUCTION_FILE.search(relative):
            instruction_files.append(relative)
        if record_model_file(relative, path, collector, coverage):
            continue
        if LOCAL_ENV.search(lowered):
            text = read_text(path, relative, coverage)
            if text is not None:
                coverage["files_read"] += 1
                scan_local_env(relative, text, collector)
            continue
        is_manifest = next((parser for pattern, parser in MANIFESTS if pattern.search(relative)), None)
        is_prompt_file = PROMPT_FILE.search(relative) is not None
        if (suffix in NOT_TEXT_WE_READ and is_manifest is None) or name.endswith(".min.js"):
            coverage["skipped_generated"].append(relative)
            continue
        if suffix in PROSE and is_manifest is None and not is_prompt_file:
            coverage["prose_files_not_scanned"].append(relative)
            continue
        text = read_text(path, relative, coverage)
        if text is None:
            continue
        coverage["files_read"] += 1
        lines = text.splitlines()
        if is_manifest is not None:
            is_manifest(relative, text, collector)
            if name not in {"setup.py", "pyproject.toml", "package.json", "build.gradle", "build.gradle.kts", "pom.xml"}:
                continue
        if is_prompt_file:
            collector.add("prompt", relative, relative=relative, line=0, text="Prompt file", technique="filename",
                          confidence=0.9, properties={"form": "file"},
                          hashes={"SHA-256": hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()})
            continue
        if name == "modelfile":
            for number, line in enumerate(lines, 1):
                match = re.match(r"^\s*FROM\s+(\S+)", line, re.IGNORECASE)
                if match:
                    identity = model_identity(match.group(1))
                    collector.add("model", match.group(1), relative=relative, line=number, text=line,
                                  technique="manifest-analysis", confidence=0.85,
                                  provider=identity[0] if identity else None)
        if name in MCP_CONFIG_NAMES or (suffix in {".json", ".jsonc"} and '"mcpServers"' in text):
            scan_mcp_config(relative, text, collector, coverage)
        if suffix == ".toml" and "[mcp_servers." in text:
            scan_mcp_toml(relative, text, collector)
        language = SOURCE.get(suffix)
        if language:
            scan_source(relative, language, lines, collector)
        scan_infrastructure(relative, lines, collector)
        for number, raw in enumerate(lines, 1):
            line = unwrap_notebook_line(raw) if language == "notebook" else raw
            if len(line) <= MAX_LINE_CHARS:
                scan_strings(relative, line, number, collector)
    merge_imports_into_declarations(collector)
    return {
        "detections": collector.finish(),
        "instruction_files": instruction_files,
        "files": listing,
        "files_listing_truncated": coverage["files_seen"] > len(listing),
        "coverage": coverage,
    }


def command_walk(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        raise Refusal(f"Target is not a directory: {target}")
    out = Path(args.out).expanduser().resolve()
    if is_inside(out, target):
        raise Refusal("The output directory must be outside the target.")
    cwd = Path.cwd().resolve()
    position = session_position(cwd, target)
    if position == "inside" and not args.allow_inside_target:
        raise Refusal(
            "This session is inside the target, so it may already have loaded the target's instructions and fired "
            "its hooks. Start a new session in a directory outside the target."
        )
    result = walk_target(target)
    policy = target / POLICYRELAY_INDEX
    document = {
        "schema": SCHEMA, "tool": "ai-inventory", "generated_at": utc_now(), "target": str(target),
        "target_name": target.name, "session_position": position,
        "policyrelay": POLICYRELAY_INDEX if policy.is_file() and not policy.is_symlink() else None,
        **result,
    }
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "walk.json", document)
    review = sum(1 for item in document["detections"] if item["review"])
    print(f"Read {document['coverage']['files_read']} of {document['coverage']['files_seen']} files. "
          f"{len(document['detections'])} detections, {review} need a decision. Wrote {out / 'walk.json'}.")
    return 0


# ---- Rendering


def comparable(text: str) -> str:
    return "".join(char for char in unicodedata.normalize("NFKC", text)
                   if not char.isspace() and unicodedata.category(char) != "Cf")


def resolve_file(root: Path, relative: Any) -> Path | None:
    if not isinstance(relative, str) or not relative or ".." in relative.split("/") or "\\" in relative:
        return None
    if Path(relative).is_absolute() or PureWindowsPath(relative).is_absolute() or PureWindowsPath(relative).drive:
        return None
    path = root
    for part in relative.split("/"):
        path = path / part
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            return None
        if stat.S_ISLNK(mode):
            return None
    return path if stat.S_ISREG(mode) else None


def check_evidence(root: Path, item: Any, owner: str) -> list[str]:
    if not isinstance(item, dict):
        return [f"{owner} is not an object."]
    problems = []
    path = resolve_file(root, item.get("file"))
    line, evidence = item.get("line"), item.get("evidence")
    if path is None:
        return [f"{owner}: `file` must be a regular file inside the target, written relative to it."]
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        problems.append(f"{owner}: `line` must be a positive whole number.")
    if not isinstance(evidence, str) or not evidence.strip():
        problems.append(f"{owner}: `evidence` must quote the file.")
    if problems:
        return problems
    try:
        lines = path.read_bytes().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return [f"{owner}: {item['file']} could not be read."]
    window = "".join(lines[max(0, line - 1 - EVIDENCE_WINDOW): line + EVIDENCE_WINDOW])
    if comparable(evidence) not in comparable(window):
        return [f"{owner}: `evidence` does not appear at or near line {line} of {item['file']}."]
    return []


def required_text(document: dict[str, Any], key: str, owner: str) -> list[str]:
    value = document.get(key)
    return [] if isinstance(value, str) and value.strip() else [f"{owner}: `{key}` must be nonempty text."]


def decision_ids(entry: dict[str, Any]) -> list[Any]:
    many = entry.get("detections")
    if isinstance(many, list):
        return many
    return [entry["detection"]] if "detection" in entry else []


def is_choice(value: Any, choices: Iterable[str]) -> bool:
    return isinstance(value, str) and value in choices


def too_long(value: Any, limit: int, owner: str, field: str) -> list[str]:
    if isinstance(value, str) and len(value.split()) > limit:
        return [f"{owner}: `{field}` has {len(value.split())} words. Keep it to {limit}."]
    return []


def check_keep_details(entry: dict[str, Any], owner: str) -> list[str]:
    """A keep decision can correct what the helper's table got wrong about a real lead."""
    details = [key for key in ("name", "status", "surface") if key in entry]
    if details and entry.get("decision") != "keep":
        return [f"{owner}: {', '.join(f'`{key}`' for key in details)} applies only to a keep decision."]
    problems = []
    if "name" in entry:
        problems += required_text(entry, "name", owner)
        if "detections" in entry:
            problems.append(f"{owner}: `name` renames one lead, so use `detection`, not `detections`.")
    if "status" in entry and not is_choice(entry["status"], STATUSES):
        problems.append(f"{owner}: `status` must be one of {', '.join(STATUSES)}.")
    if "surface" in entry and not is_choice(entry["surface"], SURFACE_LABELS):
        problems.append(f"{owner}: `surface` must be build or use.")
    return problems


def validate_assessment(walk: dict[str, Any], assessment: Any, root: Path) -> list[str]:
    if not isinstance(assessment, dict):
        return ["assessment.json must be a JSON object."]
    problems = required_text(assessment, "summary", "assessment")
    for key in ("reviewed", "additions", "data_flows", "steering", "examined", "not_checked"):
        if not isinstance(assessment.get(key), list):
            problems.append(f"assessment: `{key}` must be a list. Use an empty list when there is nothing to say.")
    if problems:
        return problems
    problems += too_long(assessment["summary"], MAX_SUMMARY_WORDS, "assessment", "summary")
    if "target" in assessment:
        target = assessment["target"]
        if not isinstance(target, dict):
            problems.append("assessment: `target` must be an object with `name` and, if known, `revision`.")
        else:
            problems += required_text(target, "name", "target")
            if "revision" in target:
                problems += required_text(target, "revision", "target")
    if not assessment["examined"]:
        problems.append("assessment: `examined` must say what you looked at, including anything beyond the helper's leads.")
    for key in ("examined", "not_checked"):
        if not all(isinstance(entry, str) and entry.strip() for entry in assessment[key]):
            problems.append(f"assessment: every `{key}` entry must be nonempty text.")
        if len(assessment[key]) > MAX_LIST_ENTRIES:
            problems.append(f"assessment: `{key}` has {len(assessment[key])} entries. Keep it to the {MAX_LIST_ENTRIES} "
                            "that matter most to whoever signs this.")
        for index, entry in enumerate(assessment[key]):
            problems += too_long(entry, MAX_LIST_ENTRY_WORDS, f"{key}[{index}]", "entry")
    detections = {item["id"]: item for item in walk["detections"]}
    decided: set[str] = set()
    for index, entry in enumerate(assessment["reviewed"]):
        owner = f"reviewed[{index}]"
        if not isinstance(entry, dict):
            problems.append(f"{owner} is not an object.")
            continue
        identifiers = decision_ids(entry)
        if not identifiers:
            problems.append(f"{owner}: give `detection`, or a nonempty `detections` list.")
        for identifier in identifiers:
            if identifier not in detections:
                problems.append(f"{owner}: unknown detection {identifier!r}.")
            elif identifier in decided:
                problems.append(f"{owner}: {identifier} is decided twice.")
            else:
                decided.add(identifier)
        if not is_choice(entry.get("decision"), ("keep", "dismiss")):
            problems.append(f"{owner}: `decision` must be keep or dismiss.")
        problems += required_text(entry, "reason", owner)
        problems += too_long(entry.get("reason"), MAX_REASON_WORDS, owner, "reason")
        problems += check_keep_details(entry, owner)
    for item in walk["detections"]:
        if item["review"] and item["id"] not in decided:
            problems.append(f"{item['id']} ({item['name']}) needs a decision: {' '.join(item['review_reasons'])}")
    for index, entry in enumerate(assessment["additions"]):
        owner = f"additions[{index}]"
        problems += check_evidence(root, entry, owner)
        if isinstance(entry, dict):
            if entry.get("category") not in CATEGORIES:
                problems.append(f"{owner}: `category` must be one of {', '.join(CATEGORIES)}.")
            if not is_choice(entry.get("confidence"), CONFIDENCE):
                problems.append(f"{owner}: `confidence` must be high, medium, or low.")
            if not is_choice(entry.get("status"), STATUSES):
                problems.append(f"{owner}: `status` must be one of {', '.join(STATUSES)}.")
            problems += required_text(entry, "name", owner) + required_text(entry, "why", owner)
            problems += too_long(entry.get("why"), MAX_WHY_WORDS, owner, "why")
            if not is_choice(entry.get("surface", "build"), SURFACE_LABELS):
                problems.append(f"{owner}: `surface` must be build or use.")
            if "provider" in entry or entry.get("category") not in NO_PROVIDER_CATEGORIES:
                if not isinstance(entry.get("provider"), str) or not entry["provider"].strip():
                    problems.append(f"{owner}: `provider` must name who provides this, or say `unknown` if the "
                                    "evidence doesn't establish it.")
    if len(assessment["data_flows"]) > MAX_DATA_FLOWS:
        problems.append(f"assessment: `data_flows` has {len(assessment['data_flows'])} entries. Merge related ones and "
                        f"keep it to the {MAX_DATA_FLOWS} that matter most to whoever signs this.")
    for key in ("data_flows", "steering"):
        for index, entry in enumerate(assessment[key]):
            owner = f"{key}[{index}]"
            problems += check_evidence(root, entry, owner)
            if isinstance(entry, dict):
                problems += required_text(entry, "why", owner)
                problems += too_long(entry.get("why"), MAX_WHY_WORDS, owner, "why")
                if key == "data_flows":
                    problems += required_text(entry, "name", owner)
    policy = assessment.get("policy", [])
    if policy and not walk.get("policyrelay"):
        problems.append("assessment: `policy` applies only when the walk found a policy index.")
    elif not isinstance(policy, list):
        problems.append("assessment: `policy` must be a list.")
    else:
        for index, entry in enumerate(policy):
            owner = f"policy[{index}]"
            if not isinstance(entry, dict):
                problems.append(f"{owner} is not an object.")
            else:
                for key in ("guidance", "requirement", "observation"):
                    problems += required_text(entry, key, owner)
                if resolve_file(root, entry.get("guidance")) is None:
                    problems.append(f"{owner}: `guidance` must be a file inside the target.")
    if not problems:
        problems += repeated_entries(final_entries(walk, assessment)[0])
    return problems


def status_of(item: dict[str, Any], decision: dict[str, Any] | None) -> str:
    if decision and decision.get("status"):
        return decision["status"]
    if item["context"] == "non-production":
        return "mentioned"
    return "in-use" if decision else NOT_REVIEWED


def final_entries(walk: dict[str, Any], assessment: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Combine helper detections and agent additions into what the inventory reports."""
    decisions = {identifier: entry for entry in assessment["reviewed"] for identifier in decision_ids(entry)}
    kept, dismissed = [], []
    for item in walk["detections"]:
        decision = decisions.get(item["id"])
        if decision and decision["decision"] == "dismiss":
            dismissed.append({"id": item["id"], "name": item["name"], "category": item["category"],
                              "reason": decision["reason"]})
            continue
        entry = dict(item)
        entry["source"] = "agent-confirmed" if decision else "helper"
        entry["note"] = decision["reason"] if decision else None
        entry["status"] = status_of(item, decision)
        if decision:
            entry["name"] = decision.get("name", item["name"])
            entry["surface"] = decision.get("surface", item["surface"])
        kept.append(entry)
    for index, addition in enumerate(assessment["additions"], 1):
        kept.append({
            "id": f"A{index:03d}", "category": addition["category"], "name": addition["name"],
            "provider": None if str(addition.get("provider")).strip().lower() in {"unknown", "none"} else addition["provider"],
            "ecosystem": addition.get("ecosystem"),
            "versions": [addition["version"]] if addition.get("version") else [],
            "technique": "source-code-analysis", "confidence": CONFIDENCE[addition["confidence"]],
            "review_reasons": [], "surface": addition.get("surface", "build"), "properties": {},
            "endpoints": [value for value in [endpoint_of(addition.get("endpoint") or "")] if value], "hashes": {},
            "occurrences": [{"file": addition["file"], "line": addition["line"], "snippet": snippet(addition["evidence"])}],
            "occurrence_count": 1, "status": addition["status"], "source": "agent", "note": addition["why"], "review": False,
        })
    order = {category: index for index, category in enumerate(CATEGORIES)}
    kept.sort(key=lambda item: (order[item["category"]], item["name"].lower(), item["id"]))
    return kept, dismissed


def bom_properties(entry: dict[str, Any]) -> list[dict[str, str]]:
    values = {
        "category": entry["category"], "surface": entry["surface"], "status": entry["status"],
        "found-by": "agent judgment" if entry["source"] == "agent" else
                    "helper, confirmed by agent judgment" if entry["source"] == "agent-confirmed" else "helper",
    }
    values.update({key: str(value) for key, value in entry["properties"].items()})
    return [{"name": PROPERTY + key.replace(" ", "-"), "value": redact(values[key])} for key in sorted(values)]


COMPONENT_TYPES = {
    "sdk": "library", "agent-framework": "framework", "ml-runtime": "library", "model": "machine-learning-model",
    "prompt": "data", "mcp-server": "application", "vector-store": "library", "coding-agent": "application",
    "other": "application",
}


def bom_reference(entry: dict[str, Any], version: str | None) -> str:
    seed = "\0".join([entry["category"], entry.get("ecosystem") or "", entry["name"].casefold(), entry["surface"], version or ""])
    return f"ai-inventory-{hashlib.sha256(seed.encode()).hexdigest()[:16]}"


def is_service(entry: dict[str, Any]) -> bool:
    return entry["category"] == "hosted-service" or (entry["category"] == "mcp-server" and bool(entry["endpoints"]))


def entry_references(entry: dict[str, Any]) -> list[str]:
    if is_service(entry):
        return [bom_reference(entry, None)]
    return [bom_reference(entry, version) for version in entry["versions"] or [None]]


def repeated_entries(entries: list[dict[str, Any]]) -> list[str]:
    """CycloneDX requires each reference to be unique, so the same thing can't be listed twice on one surface."""
    problems, first_seen = [], {}
    for entry in entries:
        if entry["status"] == "mentioned":
            continue
        for reference in entry_references(entry):
            first = first_seen.setdefault(reference, entry)
            if first is not entry:
                problems.append(f"{first['id']} and {entry['id']} are both `{entry['name']}` ({entry['category']}, "
                                f"{entry['surface']}). Combine them: keep a helper lead instead of adding it again, and "
                                "mention any other location in `why`. Additions are numbered from A001.")
    return problems


def bom_component(entry: dict[str, Any], version: str | None) -> dict[str, Any]:
    is_container = entry.get("ecosystem") == "docker"
    component: dict[str, Any] = {
        "bom-ref": bom_reference(entry, version),
        "type": "container" if is_container else COMPONENT_TYPES[entry["category"]],
        "name": redact(entry["name"]),
    }
    if version:
        component["version"] = redact(version)
    if entry.get("provider"):
        component["supplier"] = {"name": entry["provider"]}
    if entry["hashes"]:
        component["hashes"] = [{"alg": alg, "content": value} for alg, value in sorted(entry["hashes"].items())]
    package_url = purl(entry["ecosystem"], entry["name"], version) if entry.get("ecosystem") else None
    if package_url:
        component["purl"] = package_url
    if entry["category"] == "prompt":
        form = entry["properties"].get("form")
        component["data"] = [{"type": "configuration" if form == "file" else "source-code"}]
    method = {"technique": entry["technique"], "confidence": entry["confidence"]}
    if entry["source"] != "helper":
        method["value"] = "agent judgment" if entry["source"] == "agent" else "helper lead confirmed by agent judgment"
    evidence: dict[str, Any] = {"identity": [{"field": "name", "confidence": entry["confidence"], "methods": [method]}]}
    occurrences = []
    for location in entry["occurrences"]:
        occurrence: dict[str, Any] = {"location": location["file"]}
        if location["line"]:
            occurrence["line"] = location["line"]
        occurrences.append(occurrence)
    if occurrences:
        evidence["occurrences"] = occurrences
    component["evidence"] = evidence
    component["properties"] = bom_properties(entry)
    return component


def bom_service(entry: dict[str, Any], is_remote_mcp: bool = False) -> dict[str, Any]:
    service: dict[str, Any] = {"bom-ref": bom_reference(entry, None), "name": redact(entry["name"])}
    if entry.get("provider"):
        service["provider"] = {"name": entry["provider"]}
    if entry["endpoints"]:
        service["endpoints"] = entry["endpoints"]
    service["x-trust-boundary"] = True
    properties = bom_properties(entry)
    for location in entry["occurrences"]:
        where = location["file"] + (f":{location['line']}" if location["line"] else "")
        properties.append({"name": PROPERTY + "location", "value": where})
    service["properties"] = properties
    return service


def target_of(walk: dict[str, Any], assessment: dict[str, Any]) -> tuple[str, str | None]:
    declared = assessment.get("target") or {}
    return declared.get("name") or walk["target_name"], declared.get("revision")


def build_bom(walk: dict[str, Any], assessment: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    components, services = [], []
    for entry in entries:
        if entry["status"] == "mentioned":
            continue
        if is_service(entry):
            services.append(bom_service(entry))
        else:
            for version in entry["versions"] or [None]:
                components.append(bom_component(entry, version))
    name, revision = target_of(walk, assessment)
    root = {"bom-ref": "ai-inventory-target", "type": "application", "name": redact(name)}
    if revision:
        root["version"] = redact(revision)
    references = sorted(item["bom-ref"] for item in components + services)
    body = {
        "metadata": {
            "timestamp": walk["generated_at"],
            "tools": {"components": [{"type": "application", "name": "ai-inventory"}]},
            "component": root,
            "properties": [{"name": PROPERTY + "review-state", "value": "unsigned; needs human review"}],
        },
        "components": components,
        "services": services,
        "dependencies": [{"ref": root["bom-ref"], "dependsOn": references}],
    }
    serial = uuid.uuid5(uuid.NAMESPACE_URL, "ai-inventory:" + json.dumps(body, sort_keys=True))
    return {"bomFormat": "CycloneDX", "specVersion": SPEC_VERSION, "serialNumber": f"urn:uuid:{serial}", "version": 1, **body}


def inline(text: Any) -> str:
    return " ".join(visible(redact(str(text))).split()).replace("|", "\\|")


def code_inline(text: Any) -> str:
    cleaned = inline(text).replace("`", "'")
    return f"`{cleaned}`" if cleaned else ""


def location_text(location: dict[str, Any]) -> str:
    return location["file"] + (f":{location['line']}" if location["line"] else "")


def found_by_label(entry: dict[str, Any]) -> str:
    return {"helper": "Helper", "agent-confirmed": "Helper, confirmed by agent", "agent": "Agent judgment"}[entry["source"]]


def status_label(entry: dict[str, Any]) -> str:
    return STATUSES.get(entry["status"], "Not reviewed")


def confidence_label(value: float) -> str:
    return "high" if value >= 0.8 else "medium" if value >= 0.5 else "low"


def provider_label(entry: dict[str, Any]) -> str:
    return inline(entry.get("provider") or ("n/a" if entry["category"] in NO_PROVIDER_CATEGORIES else "unknown"))


def where_text(entry: dict[str, Any]) -> str:
    where = ", ".join(code_inline(location_text(location)) for location in entry["occurrences"][:3])
    extra = entry["occurrence_count"] - min(3, len(entry["occurrences"]))
    return f"{where} and {extra} more" if extra > 0 else where


def render_report(walk: dict[str, Any], assessment: dict[str, Any], entries: list[dict[str, Any]],
                  dismissed: list[dict[str, Any]]) -> str:
    coverage = walk["coverage"]
    listed = [entry for entry in entries if entry["status"] != "mentioned"]
    only_mentioned = [entry for entry in entries if entry["status"] == "mentioned"]
    grouped = {category: [entry for entry in listed if entry["category"] == category] for category in CATEGORIES}
    name, revision = target_of(walk, assessment)
    lines = [
        "# AI inventory report", "",
        f"Target: {code_inline(name)}  ", f"Revision: {code_inline(revision) if revision else 'not recorded'}  ",
        f"Walked: {walk['generated_at']}  ",
        "BOM: `ai-bom.cdx.json` (CycloneDX 1.6)  ", "Status: **unsigned, needs human review**", "",
        "## Summary", "", inline(assessment["summary"]), "",
        "| What | Found | Only mentioned | From helper | From agent judgment |", "| --- | --- | --- | --- | --- |",
    ]
    for category in CATEGORIES:
        group = grouped[category]
        agent = sum(1 for entry in group if entry["source"] == "agent")
        mentioned = sum(1 for entry in only_mentioned if entry["category"] == category)
        lines.append(f"| {CATEGORY_LABELS[category]} | {len(group)} | {mentioned} | {len(group) - agent} | {agent} |")
    lines += ["", "## Steering instructions", ""]
    if assessment["steering"]:
        for entry in assessment["steering"]:
            lines += [f"- {code_inline(entry['file'] + ':' + str(entry['line']))}: {code_inline(snippet(entry['evidence']))}. {inline(entry['why'])}"]
    else:
        lines.append("None found. Instruction files read as data: " + str(len(walk["instruction_files"])) + ".")
    lines += ["", "## Inventory", ""]
    for category in CATEGORIES:
        lines += [f"### {CATEGORY_LABELS[category]}", ""]
        group = grouped[category]
        if not group:
            lines += ["None found.", ""]
            continue
        lines += ["| Name | Version | Provider | Status | Confidence | Where | Found by | Notes |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for entry in group:
            notes =[inline(entry["note"])] if entry.get("note") else []
            notes += [f"{inline(key)}: {inline(value)}" for key, value in sorted(entry["properties"].items())
                      if key not in {"form", "origin", "config", "command"}]
            notes += [f"Endpoint: {code_inline(value)}" for value in entry["endpoints"]]
            unversioned = "not pinned" if entry.get("ecosystem") or "pinned" in entry["properties"] else "n/a"
            lines.append(f"| {code_inline(entry['name'])} | {inline(', '.join(entry['versions'])) or unversioned} | "
                         f"{provider_label(entry)} | {status_label(entry)} | {confidence_label(entry['confidence'])} | "
                         f"{where_text(entry)} | {found_by_label(entry)} | {' '.join(notes)} |")
        lines.append("")
    lines += ["## Only mentioned", ""]
    if only_mentioned:
        lines += ["Docs, examples, or tests refer to these, and nothing here reaches them. They are not in the BOM.", "",
                  "| Name | What | Where |", "| --- | --- | --- |"]
        lines += [f"| {code_inline(entry['name'])} | {CATEGORY_LABELS[entry['category']]} | {where_text(entry)} |"
                  for entry in only_mentioned]
    else:
        lines.append("None.")
    lines += ["", "## Data flows", ""]
    if assessment["data_flows"]:
        for entry in assessment["data_flows"]:
            where = code_inline(f"{entry['file']}:{entry['line']}")
            lines.append(f"- **{inline(entry['name'])}** ({where}): {inline(entry['why'])}")
    else:
        lines.append("None recorded.")
    lines.append("")
    if walk.get("policyrelay"):
        lines += ["## Policy", ""]
        if assessment.get("policy"):
            for entry in assessment["policy"]:
                lines.append(f"- {code_inline(entry['guidance'])}: {inline(entry['requirement'])} Observed: {inline(entry['observation'])}")
        else:
            lines.append("Nothing in this inventory conflicts with the guidance that applies.")
        lines.append("")
    lines += ["## Dismissed leads", ""]
    if dismissed:
        lines += ["| Lead | Name | Why it was dismissed |", "| --- | --- | --- |"]
        lines += [f"| {item['id']} | {code_inline(item['name'])} | {inline(item['reason'])} |" for item in dismissed]
    else:
        lines.append("None.")
    lines += ["", "## Coverage", "", "| Surface | Items | Coverage |", "| --- | --- | --- |"]
    for surface, label in SURFACE_LABELS.items():
        count = sum(1 for entry in listed if entry["surface"] == surface)
        reach = "Repository contents only" if surface == "build" else "Only what left a trace in this repository"
        lines.append(f"| {label} | {count} | {reach} |")
    lines.append("| What everyone else in the organization uses | Not assessed | Not visible from a repository |")
    lines += [
        "", f"The helper read {coverage['files_read']} of {coverage['files_seen']} files.", "",
        "What was examined beyond the helper's leads:", "",
    ]
    lines += [f"- {inline(entry)}" for entry in assessment["examined"]]
    lines += ["", "## What this cannot see", ""]
    lines += [f"- {entry}" for entry in CANNOT_SEE]
    lines += ["", "## Limits", ""]
    limits = limit_lines(walk, assessment)
    lines += [f"- {entry}" for entry in limits] if limits else ["None recorded."]
    lines += [
        "", "## Sign-off", "", "I have reviewed this inventory.", "",
        "Name: ____________________  Date: ____________", "",
    ]
    return "\n".join(lines)


def limit_lines(walk: dict[str, Any], assessment: dict[str, Any]) -> list[str]:
    coverage = walk["coverage"]
    result = [inline(entry) for entry in assessment["not_checked"]]
    position = walk["session_position"]
    if position == "inside":
        result.append("The session ran inside the target at the operator's direction, so it may have loaded the target's "
                      "instructions and fired its hooks.")
    labels = (
        ("prose_files_not_scanned", "prose files the helper did not scan"),
        ("skipped_large", "files over the helper's size limit"),
        ("skipped_generated", "generated or data files skipped"),
        ("symlinks_not_followed", "symlinks not followed"),
        ("excluded_directories", "dependency or tooling directories skipped"),
        ("unreadable", "files that could not be read"),
        ("unparsed_config", "configuration files that could not be parsed"),
        ("not_hashed", "model files too large to hash"),
    )
    for key, label in labels:
        items = coverage[key]
        if items:
            shown = ", ".join(code_inline(item) for item in items[:5])
            more = f" and {len(items) - 5} more" if len(items) > 5 else ""
            result.append(f"{len(items)} {label}: {shown}{more}.")
    if coverage["binary_files"]:
        result.append(f"{coverage['binary_files']} binary files not read.")
    if walk["files_listing_truncated"]:
        result.append("The file list given to the agent was truncated because the repository is very large.")
    return result


def command_render(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    walk = load_json(out / "walk.json", "walk.json")
    assessment = load_json(out / "assessment.json", "assessment.json")
    root = Path(walk["target"])
    if not root.is_dir():
        raise Refusal(f"The target is no longer at {root}.")
    problems = validate_assessment(walk, assessment, root)
    bom_path, report_path = out / "ai-bom.cdx.json", out / "report.md"
    if problems:
        for path in (bom_path, report_path):
            if path.exists():
                path.unlink()
        print("Nothing was written. Correct these against the evidence and run render again:")
        for problem in problems:
            print(f"- {problem}")
        return 1
    entries, dismissed = final_entries(walk, assessment)
    write_json(bom_path, build_bom(walk, assessment, entries))
    report_path.write_text(render_report(walk, assessment, entries, dismissed), encoding="utf-8")
    print(f"Wrote {bom_path} and {report_path}. {len(entries)} items, {len(dismissed)} dismissed. Unsigned.")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Read-only helper for the ai-inventory skill.")
    commands = root.add_subparsers(dest="command", required=True)
    walk = commands.add_parser("walk", help="Read the target and write walk.json")
    walk.add_argument("--target", required=True)
    walk.add_argument("--out", required=True)
    walk.add_argument("--allow-inside-target", action="store_true")
    walk.set_defaults(handler=command_walk)
    render = commands.add_parser("render", help="Write the CycloneDX BOM and report")
    render.add_argument("--out", required=True)
    render.set_defaults(handler=command_render)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.handler(args)
    except Refusal as refusal:
        print(f"Refused: {refusal}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

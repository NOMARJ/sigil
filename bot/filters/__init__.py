"""
Sigil Bot — AI Ecosystem Keyword Filtering & Typosquatting Detection

Determines which packages are in-scope for scanning and boosts priority
for typosquatting candidates.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# AI Ecosystem Keywords
# ---------------------------------------------------------------------------

AI_KEYWORDS: set[str] = {
    # Frameworks
    "langchain", "langgraph", "crewai", "autogen", "ag2",
    "llamaindex", "llama-index", "haystack", "semantic-kernel",
    "dspy", "instructor", "marvin", "guidance",
    # LLM providers
    "openai", "anthropic", "cohere", "mistral", "groq",
    "together", "replicate", "fireworks", "anyscale",
    # MCP / agent protocols
    "mcp", "model-context-protocol", "modelcontextprotocol",
    "agent", "agentic", "tool-use", "function-calling",
    # RAG / retrieval
    "rag", "retrieval", "vector", "embedding", "pinecone",
    "weaviate", "chroma", "qdrant", "milvus", "faiss",
    # ML / transformers
    "transformers", "huggingface", "diffusers", "tokenizer",
    "torch", "tensorflow", "jax", "mlflow",
    # Skills / plugins
    "skill", "plugin", "extension", "addon",
    "chatgpt-plugin", "claude-skill", "copilot-extension",
}

AI_SCOPES_NPM: set[str] = {
    "@langchain", "@modelcontextprotocol", "@anthropic",
    "@openai", "@llamaindex", "@huggingface",
}

# ---------------------------------------------------------------------------
# Typosquatting Detection
# ---------------------------------------------------------------------------

POPULAR_TARGETS: list[str] = [
    "langchain", "openai", "anthropic", "transformers",
    "huggingface", "crewai", "autogen", "llamaindex",
    "pinecone", "chromadb", "fastapi", "streamlit",
    "numpy", "pandas", "requests", "flask",
    "torch", "tensorflow", "scikit-learn", "boto3",
]


def _levenshtein(s: str, t: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s) < len(t):
        return _levenshtein(t, s)
    if not t:
        return len(s)

    prev_row = list(range(len(t) + 1))
    for i, sc in enumerate(s):
        curr_row = [i + 1]
        for j, tc in enumerate(t):
            cost = 0 if sc == tc else 1
            curr_row.append(
                min(curr_row[j] + 1, prev_row[j + 1] + 1, prev_row[j] + cost)
            )
        prev_row = curr_row
    return prev_row[-1]


def _has_suspicious_substitution(name: str, target: str) -> bool:
    """Check if a package name has character substitutions typical of typosquatting."""
    confusables = {
        "0": "o", "1": "l", "1": "i",
        "3": "e", "5": "s", "7": "t",
        "l": "i", "rn": "m",
    }
    cleaned = name.replace(target, "").replace("-", "").replace("_", "")
    if not cleaned:
        return False
    for fake, real in confusables.items():
        if fake in name:
            candidate = name.replace(fake, real)
            if _levenshtein(candidate, target) <= 1:
                return True
    return False


def is_typosquat_candidate(name: str) -> bool:
    """Return True if the package name is suspiciously close to a popular package."""
    normalized = name.lower().replace("_", "-")
    for target in POPULAR_TARGETS:
        if normalized == target:
            continue
        if _levenshtein(normalized, target) <= 2:
            return True
        if normalized.startswith(target + "-") or normalized.endswith("-" + target):
            if _has_suspicious_substitution(normalized, target):
                return True
    return False


def matches_ai_keywords(
    name: str,
    description: str = "",
    keywords: list[str] | None = None,
) -> bool:
    """Return True if the package metadata matches AI ecosystem keywords."""
    searchable = f"{name} {description} {' '.join(keywords or [])}".lower()
    return any(kw in searchable for kw in AI_KEYWORDS)


def matches_npm_scope(name: str) -> bool:
    """Return True if the npm package is in a monitored scope."""
    for scope in AI_SCOPES_NPM:
        if name.startswith(scope + "/"):
            return True
    return False


def determine_priority(
    ecosystem: str,
    name: str,
    description: str = "",
    keywords: list[str] | None = None,
    weekly_downloads: int = 0,
) -> str:
    """Determine scan priority based on package metadata.

    Returns: 'critical', 'high', or 'normal'.
    """
    # Typosquatting → critical
    if is_typosquat_candidate(name):
        return "critical"

    # ClawHub skills → high (direct environment access)
    if ecosystem == "clawhub":
        return "high"

    # MCP scoped packages → high
    if ecosystem == "npm" and matches_npm_scope(name):
        return "high"

    # Popular packages getting updates → high
    if weekly_downloads > 1000:
        return "high"

    return "normal"

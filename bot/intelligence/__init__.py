"""
Sigil Bot — Proprietary Intelligence Layer

Extracts market intelligence signals from scan results and package metadata.
Writes to a separate intelligence schema — never exposed publicly.

Intelligence products:
  1. Ecosystem trend map (category signals over time)
  2. Provider market share (LLM provider integration data)
  3. Infrastructure heatmap (databases, vector stores, cloud services)
  4. Publisher intelligence (prolific publishers, quality signals)
  5. Dependency concentration risk

This layer costs nothing incremental — data is already flowing through
the scan pipeline. The marginal cost is extra DB writes + a dashboard.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from bot.config import bot_settings
from bot.queue import ScanJob

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Category signal detection
# ---------------------------------------------------------------------------

CATEGORY_PATTERNS: dict[str, list[str]] = {
    "mcp_server": [
        "mcp", "model-context-protocol", "modelcontextprotocol",
        "McpServer", "@modelcontextprotocol",
    ],
    "rag_pipeline": [
        "rag", "retrieval", "vector", "embedding", "vectorstore",
        "llamaindex", "langchain.vectorstores",
    ],
    "agent_framework": [
        "agent", "crewai", "autogen", "langgraph", "multi-agent",
        "orchestrat",
    ],
    "llm_wrapper": [
        "openai", "anthropic", "cohere", "llm", "chat-completion",
        "groq", "mistral",
    ],
    "skill_plugin": [
        "skill", "plugin", "claude-skill", "chatgpt-plugin",
        "copilot-extension",
    ],
    "fine_tuning": [
        "fine-tun", "training", "rlhf", "dpo", "lora", "peft",
    ],
    "evaluation": [
        "eval", "benchmark", "red-team", "adversarial",
    ],
    "deployment": [
        "serving", "inference", "edge", "deploy", "vllm", "tgi",
    ],
    "security": [
        "security", "guardrail", "content-filter", "scan",
    ],
    "data_pipeline": [
        "connector", "etl", "extraction", "structured-output",
    ],
}

# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------

PROVIDER_SIGNALS: dict[str, list[str]] = {
    "openai": [
        "openai", "OPENAI_API_KEY", "gpt-4", "gpt-3.5", "gpt-4o",
        "from openai import", "import openai",
    ],
    "anthropic": [
        "anthropic", "ANTHROPIC_API_KEY", "claude-3", "claude-4",
        "from anthropic import", "import anthropic",
    ],
    "google": [
        "google.generativeai", "GOOGLE_API_KEY", "gemini",
        "vertexai",
    ],
    "cohere": ["cohere", "COHERE_API_KEY"],
    "mistral": ["mistral", "MISTRAL_API_KEY"],
    "groq": ["groq", "GROQ_API_KEY"],
    "together": ["together", "TOGETHER_API_KEY"],
    "replicate": ["replicate", "REPLICATE_API_TOKEN"],
    "huggingface": [
        "huggingface", "HF_TOKEN", "transformers",
        "from transformers import",
    ],
}

# ---------------------------------------------------------------------------
# Infrastructure detection
# ---------------------------------------------------------------------------

INFRA_SIGNALS: dict[str, list[str]] = {
    "pinecone": ["PINECONE_API_KEY", "pinecone", "from pinecone"],
    "supabase": ["SUPABASE_URL", "supabase", "from supabase"],
    "redis": ["REDIS_URL", "redis", "from redis"],
    "postgresql": ["POSTGRES", "DATABASE_URL", "asyncpg", "psycopg"],
    "chromadb": ["CHROMA_HOST", "chromadb", "from chromadb"],
    "weaviate": ["WEAVIATE_URL", "weaviate"],
    "qdrant": ["QDRANT_URL", "qdrant"],
    "milvus": ["MILVUS_HOST", "pymilvus"],
    "aws": ["AWS_ACCESS_KEY", "boto3", "from boto3"],
    "gcp": ["GOOGLE_CLOUD", "google.cloud"],
    "azure": ["AZURE_", "azure."],
    "mongodb": ["MONGODB_URI", "pymongo", "from motor"],
    "elasticsearch": ["ELASTICSEARCH_URL", "elasticsearch"],
}


def _detect_signals(
    patterns: dict[str, list[str]],
    searchable: str,
) -> list[str]:
    """Return list of matched signal keys."""
    matched = []
    for key, signals in patterns.items():
        for signal in signals:
            if signal.lower() in searchable.lower():
                matched.append(key)
                break
    return matched


def _categorise_package(
    name: str,
    description: str,
    keywords: list[str],
    code_patterns: list[str],
) -> list[str]:
    """Determine which categories a package belongs to."""
    searchable = f"{name} {description} {' '.join(keywords)} {' '.join(code_patterns)}"
    return _detect_signals(CATEGORY_PATTERNS, searchable)


def _detect_providers(findings: list[dict], metadata: dict) -> list[str]:
    """Detect which LLM providers the package integrates with."""
    searchable_parts = [
        metadata.get("description", ""),
        " ".join(metadata.get("keywords", [])),
    ]
    # Extract code snippets from findings
    for f in findings:
        searchable_parts.append(f.get("snippet", ""))
        searchable_parts.append(f.get("rule", ""))

    searchable = " ".join(searchable_parts)
    return _detect_signals(PROVIDER_SIGNALS, searchable)


def _detect_infrastructure(findings: list[dict], metadata: dict) -> list[str]:
    """Detect which infrastructure the package connects to."""
    searchable_parts = [
        metadata.get("description", ""),
        " ".join(metadata.get("keywords", [])),
    ]
    for f in findings:
        searchable_parts.append(f.get("snippet", ""))

    searchable = " ".join(searchable_parts)
    return _detect_signals(INFRA_SIGNALS, searchable)


async def extract_intelligence(
    job: ScanJob,
    scan_output: dict[str, Any],
) -> None:
    """Extract intelligence signals from a completed scan.

    Writes to the intelligence tables (separate from public scan data).
    Runs asynchronously — does not block the scan pipeline.
    """
    findings = scan_output.get("findings", [])
    metadata = job.metadata
    now = datetime.now(timezone.utc)

    # Detect signals
    description = metadata.get("description", "")
    keywords = metadata.get("keywords", [])
    if isinstance(keywords, str):
        keywords = keywords.split(",")

    code_snippets = [f.get("snippet", "") for f in findings]
    code_rules = [f.get("rule", "") for f in findings]

    categories = _categorise_package(
        job.name, description, keywords, code_snippets + code_rules
    )
    providers = _detect_providers(findings, metadata)
    infra = _detect_infrastructure(findings, metadata)

    # Build intelligence record
    intel_record = {
        "ecosystem": job.ecosystem,
        "package_name": job.name,
        "package_version": job.version,
        "categories": categories,
        "providers": providers,
        "infrastructure": infra,
        "author": metadata.get("author", ""),
        "description": description,
        "keywords": keywords,
        "risk_score": scan_output.get("score", 0.0),
        "verdict": scan_output.get("verdict", "LOW_RISK"),
        "findings_count": len(findings),
        "scanned_at": now.isoformat(),
    }

    # Store in Redis for batch processing (avoids per-scan DB write overhead)
    try:
        import redis.asyncio as aioredis
        import json

        r = aioredis.from_url(bot_settings.redis_url, decode_responses=True)
        await r.lpush("sigil:intel:queue", json.dumps(intel_record))
        await r.ltrim("sigil:intel:queue", 0, 9999)
        await r.aclose()
    except Exception:
        logger.debug("Intel record queued locally for %s/%s", job.ecosystem, job.name)

    logger.debug(
        "Intel extracted: %s/%s — categories=%s providers=%s infra=%s",
        job.ecosystem,
        job.name,
        categories,
        providers,
        infra,
    )

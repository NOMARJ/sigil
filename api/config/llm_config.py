"""
LLM Configuration for Sigil Pro
"""

from __future__ import annotations

import os
from typing import Literal


LLMProvider = Literal["openai", "azure", "anthropic"]


class LLMConfig:
    """Configuration for LLM service integration."""

    # Provider settings
    provider: LLMProvider = "openai"
    api_key: str | None = None
    api_base: str | None = None
    api_version: str = "2024-02-15-preview"

    # Model settings
    model: str = "gpt-4-turbo"
    max_tokens_per_scan: int = 8000
    temperature: float = 0.2
    timeout_seconds: int = 30

    # Performance settings
    cache_ttl_hours: int = 24
    max_retries: int = 3
    backoff_factor: float = 1.5

    # Cost controls
    rate_limit_requests_per_minute: int = 60
    max_monthly_cost_usd: float = 500.0
    fallback_to_static: bool = True

    def __init__(self):
        """Initialize LLM config from environment variables."""
        # Provider configuration
        self.provider = os.getenv("LLM_PROVIDER", "openai").lower()
        self.api_key = os.getenv("LLM_API_KEY")
        self.api_base = os.getenv("LLM_API_BASE")
        self.api_version = os.getenv("LLM_API_VERSION", "2024-02-15-preview")

        # Model configuration
        self.model = os.getenv("LLM_MODEL", "gpt-4-turbo")
        self.max_tokens_per_scan = int(os.getenv("LLM_MAX_TOKENS", "8000"))
        self.temperature = float(os.getenv("LLM_TEMPERATURE", "0.2"))

        # Performance settings
        self.cache_ttl_hours = int(os.getenv("LLM_CACHE_TTL_HOURS", "24"))
        self.max_retries = int(os.getenv("LLM_MAX_RETRIES", "3"))

        # Cost controls
        self.rate_limit_requests_per_minute = int(os.getenv("LLM_RATE_LIMIT_RPM", "60"))
        self.max_monthly_cost_usd = float(os.getenv("LLM_MAX_MONTHLY_COST", "500"))
        self.fallback_to_static = (
            os.getenv("LLM_FALLBACK_TO_STATIC", "true").lower() == "true"
        )

    def is_configured(self) -> bool:
        """Check if LLM service is properly configured."""
        return bool(self.api_key and self.model)

    def get_headers(self) -> dict[str, str]:
        """Get HTTP headers for API requests."""
        if self.provider == "openai":
            return {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
        elif self.provider == "azure":
            return {
                "api-key": self.api_key,
                "Content-Type": "application/json",
            }
        elif self.provider == "anthropic":
            return {
                "x-api-key": self.api_key,
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
            }
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def get_endpoint_url(self) -> str:
        """Get the API endpoint URL."""
        if self.api_base:
            base = self.api_base.rstrip("/")
        elif self.provider == "openai":
            base = "https://api.openai.com/v1"
        elif self.provider == "azure":
            # Azure endpoint must be provided via LLM_API_BASE
            raise ValueError(
                "Azure LLM provider requires LLM_API_BASE environment variable"
            )
        elif self.provider == "anthropic":
            base = "https://api.anthropic.com/v1"
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

        if self.provider == "openai":
            return f"{base}/chat/completions"
        elif self.provider == "azure":
            return f"{base}/openai/deployments/{self.model}/chat/completions?api-version={self.api_version}"
        elif self.provider == "anthropic":
            return f"{base}/messages"
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")


# Global config instance
llm_config = LLMConfig()

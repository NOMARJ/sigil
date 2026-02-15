"""
Sigil API — Configuration

Application settings loaded from environment variables with sensible defaults.
Uses Pydantic BaseSettings for validation and type coercion.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for the Sigil API service.

    All values can be overridden via environment variables (case-insensitive).
    The service degrades gracefully when optional backends (Supabase, Redis)
    are not configured.
    """

    model_config = SettingsConfigDict(
        env_prefix="SIGIL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application -----------------------------------------------------------
    app_name: str = "Sigil API"
    app_version: str = "0.1.0"
    debug: bool = False
    log_level: str = "INFO"

    # --- Server ----------------------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8000

    # --- CORS ------------------------------------------------------------------
    cors_origins: list[str] = ["http://localhost:3000"]

    # --- JWT / Auth ------------------------------------------------------------
    jwt_secret: str = "changeme-generate-a-real-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # --- Supabase (optional) ---------------------------------------------------
    supabase_url: str | None = None
    supabase_key: str | None = None

    # --- Redis (optional) ------------------------------------------------------
    redis_url: str | None = None

    # --- Threat Intel ----------------------------------------------------------
    threat_intel_ttl: int = 3600  # Cache TTL in seconds

    @property
    def supabase_configured(self) -> bool:
        """Return True when both Supabase URL and key are set."""
        return bool(self.supabase_url and self.supabase_key)

    @property
    def redis_configured(self) -> bool:
        """Return True when a Redis URL is set."""
        return bool(self.redis_url)


# Singleton — importable from anywhere as `from api.config import settings`.
settings = Settings()

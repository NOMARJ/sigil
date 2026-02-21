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
    supabase_service_key: str | None = None  # For admin operations
    supabase_jwt_secret: str | None = None  # Deprecated: use JWKS for verification
    database_url: str | None = None  # SIGIL_DATABASE_URL — postgres connection string

    # --- Redis (optional) ------------------------------------------------------
    redis_url: str | None = None

    # --- Threat Intel ----------------------------------------------------------
    threat_intel_ttl: int = 3600  # Cache TTL in seconds

    # --- SMTP (optional — for email alert notifications) -----------------------
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str = "alerts@sigil.dev"

    # --- Stripe (optional — for billing) ---------------------------------------
    stripe_secret_key: str | None = None
    stripe_webhook_secret: str | None = None
    stripe_price_pro: str = "price_pro_placeholder"
    stripe_price_team: str = "price_team_placeholder"
    stripe_price_pro_annual: str = "price_pro_annual_placeholder"
    stripe_price_team_annual: str = "price_team_annual_placeholder"

    @property
    def supabase_configured(self) -> bool:
        """Return True when both Supabase URL and key are set."""
        return bool(self.supabase_url and self.supabase_key)

    @property
    def supabase_auth_configured(self) -> bool:
        """Return True when Supabase Auth is configured for JWT verification."""
        return bool(self.supabase_url)

    @property
    def database_configured(self) -> bool:
        return bool(self.database_url)

    @property
    def redis_configured(self) -> bool:
        """Return True when a Redis URL is set."""
        return bool(self.redis_url)

    @property
    def smtp_configured(self) -> bool:
        """Return True when SMTP host and credentials are set."""
        return bool(self.smtp_host and self.smtp_user and self.smtp_password)

    @property
    def stripe_configured(self) -> bool:
        """Return True when a Stripe secret key is set."""
        return bool(self.stripe_secret_key)


# Singleton — importable from anywhere as `from api.config import settings`.
settings = Settings()

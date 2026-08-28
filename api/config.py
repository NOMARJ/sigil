"""
Sigil API — Configuration

Application settings loaded from environment variables with sensible defaults.
Uses Pydantic BaseSettings for validation and type coercion.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve .env file path relative to this config.py file
# This ensures it works both locally and in Docker
_API_DIR = Path(__file__).parent
_ENV_FILE = _API_DIR / ".env"


class Settings(BaseSettings):
    """Central configuration for the Sigil API service.

    All values can be overridden via environment variables (case-insensitive).
    The service degrades gracefully when optional backends (Auth0, Redis)
    are not configured.
    """

    model_config = SettingsConfigDict(
        env_prefix="SIGIL_",
        env_file=str(_ENV_FILE) if _ENV_FILE.exists() else None,
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
    cors_origins: list[str] = [
        "http://localhost:3000",
        "https://app.sigilsec.ai",
        "https://sigilsec.ai",
        "https://www.sigilsec.ai",
        "https://forge.sigilsec.ai",
    ]
    frontend_url: str = "https://app.sigilsec.ai"

    # --- JWT / Auth ------------------------------------------------------------
    jwt_secret: str = "changeme-generate-a-real-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # --- Auth0 (optional — for OAuth login) ------------------------------------
    auth0_domain: Union[str, None] = None  # SIGIL_AUTH0_DOMAIN e.g. "sigil.auth0.com"
    auth0_audience: Union[str, None] = (
        None  # SIGIL_AUTH0_AUDIENCE e.g. "https://api.sigilsec.ai"
    )
    auth0_client_id: Union[str, None] = None  # SIGIL_AUTH0_CLIENT_ID

    # --- Supabase (deprecated — kept for rollback during migration) -----------
    supabase_url: Union[str, None] = None
    supabase_key: Union[str, None] = None
    supabase_service_key: Union[str, None] = None
    supabase_jwt_secret: Union[str, None] = None
    database_url: Union[str, None] = None  # SIGIL_DATABASE_URL — connection string

    # --- Redis (optional) ------------------------------------------------------
    redis_url: Union[str, None] = None

    # --- Threat Intel ----------------------------------------------------------
    threat_intel_ttl: int = 3600  # Cache TTL in seconds

    # --- Scanner Configuration -------------------------------------------------
    scanner_version: str = "2.0.0"  # Scanner version to use (1.0.0 or 2.0.0)
    scanner_v1_enabled: bool = True  # Allow fallback to v1 scanner
    scanner_v2_features: bool = True  # Enable v2 features (confidence scoring, etc.)

    # --- SMTP (optional — for email alert notifications) -----------------------
    smtp_host: Union[str, None] = None
    smtp_port: int = 587
    smtp_user: Union[str, None] = None
    smtp_password: Union[str, None] = None
    smtp_from_email: str = "alerts@mail.sigilsec.ai"

    # --- Email Newsletter (Forge Weekly) --------------------------------------
    resend_api_key: Union[str, None] = None  # SIGIL_RESEND_API_KEY
    from_email: str = "noreply@mail.sigilsec.ai"  # SIGIL_FROM_EMAIL
    from_name: str = "Sigil Security"  # SIGIL_FROM_NAME
    base_url: str = "https://api.sigilsec.ai"  # SIGIL_BASE_URL

    # --- Stripe (optional — for billing) ---------------------------------------
    stripe_secret_key: Union[str, None] = None
    stripe_webhook_secret: Union[str, None] = None
    stripe_test_secret_key: Union[str, None] = None
    stripe_test_webhook_secret: Union[str, None] = None
    stripe_publishable_key: Union[str, None] = None
    # Subscription price IDs. No defaults on purpose: a fabricated fallback ID
    # means checkout 500s in production while the code "looks configured".
    # Paid-plan subscribe requests fail with a clear 400 until these are set.
    stripe_price_pro: Union[str, None] = None  # SIGIL_STRIPE_PRICE_PRO
    stripe_price_team: Union[str, None] = None  # SIGIL_STRIPE_PRICE_TEAM
    stripe_price_pro_annual: Union[str, None] = None  # SIGIL_STRIPE_PRICE_PRO_ANNUAL
    stripe_price_team_annual: Union[str, None] = None  # SIGIL_STRIPE_PRICE_TEAM_ANNUAL
    # One-time credit pack price IDs (SIGIL_STRIPE_PRICE_CREDITS_*)
    stripe_price_credits_starter: Union[str, None] = None
    stripe_price_credits_power: Union[str, None] = None
    stripe_price_credits_pro: Union[str, None] = None
    stripe_price_credits_ultimate: Union[str, None] = None

    # --- GitHub App (optional — for PR scanning) --------------------------------
    github_app_id: Union[str, None] = None
    github_app_private_key: Union[str, None] = None
    github_webhook_secret: Union[str, None] = None
    github_client_id: Union[str, None] = None
    github_client_secret: Union[str, None] = None
    github_token: Union[str, None] = None  # SIGIL_GITHUB_TOKEN — PAT for traffic API

    # --- Anthropic (optional — for Forge classification) ----------------------
    anthropic_api_key: Union[str, None] = None  # SIGIL_ANTHROPIC_API_KEY

    # --- Bot Attestation Keys -------------------------------------------------
    # Bot signing key for creating attestations (Ed25519)
    bot_private_key: Union[str, None] = (
        None  # SIGIL_BOT_PRIVATE_KEY (base64-encoded 32 bytes)
    )
    bot_public_key: Union[str, None] = None  # SIGIL_BOT_PUBLIC_KEY (base64-encoded PEM)
    bot_public_key_file: Union[str, None] = (
        None  # SIGIL_BOT_PUBLIC_KEY_FILE (path to PEM file)
    )
    bot_signing_key_id: str = (
        "sha256:sigil-bot-signing-key-2026"  # SIGIL_BOT_SIGNING_KEY_ID
    )

    # --- Monitoring & Observability --------------------------------------------
    metrics_enabled: bool = True  # SIGIL_METRICS_ENABLED
    health_checks_enabled: bool = True  # SIGIL_HEALTH_CHECKS_ENABLED
    structured_logging: bool = True  # SIGIL_STRUCTURED_LOGGING
    azure_insights_key: Union[str, None] = None  # SIGIL_AZURE_INSIGHTS_KEY
    prometheus_enabled: bool = True  # SIGIL_PROMETHEUS_ENABLED
    # Sentry error tracking — enabled only when a DSN is set
    sentry_dsn: Union[str, None] = None  # SIGIL_SENTRY_DSN
    sentry_environment: str = "production"  # SIGIL_SENTRY_ENVIRONMENT
    sentry_traces_sample_rate: float = 0.05  # SIGIL_SENTRY_TRACES_SAMPLE_RATE

    # --- PostHog (optional — for conversion funnel analytics) ----------------
    posthog_api_key: Union[str, None] = None  # SIGIL_POSTHOG_API_KEY
    posthog_host: str = "https://app.posthog.com"  # SIGIL_POSTHOG_HOST

    @property
    def auth0_configured(self) -> bool:
        """Return True when Auth0 domain and audience are set."""
        return bool(self.auth0_domain and self.auth0_audience)

    @property
    def auth0_device_flow_configured(self) -> bool:
        """Return True when the device-authorization flow can run.

        Device flow additionally needs the client_id — without it Auth0
        rejects the device-code request, which previously surfaced as an
        opaque 503. Checked separately so JWT validation (domain+audience
        only) is unaffected.
        """
        return self.auth0_configured and bool(self.auth0_client_id)

    @property
    def supabase_configured(self) -> bool:
        """Return True when both Supabase URL and key are set (deprecated)."""
        return bool(self.supabase_url and self.supabase_key)

    @property
    def supabase_auth_configured(self) -> bool:
        """Return True when Supabase Auth is configured (deprecated)."""
        return bool(self.supabase_url)

    @property
    def database_configured(self) -> bool:
        return bool(self.database_url)

    @property
    def redis_configured(self) -> bool:
        """Return True when a Redis URL is set."""
        return bool(self.redis_url)

    @property
    def bot_attestation_configured(self) -> bool:
        """Return True when bot attestation keys are configured."""
        return bool(self.bot_public_key or self.bot_public_key_file)

    @property
    def smtp_configured(self) -> bool:
        """Return True when SMTP host and credentials are set."""
        return bool(self.smtp_host and self.smtp_user and self.smtp_password)

    @property
    def resend_configured(self) -> bool:
        """Return True when Resend API key is set."""
        return bool(self.resend_api_key)

    @property
    def stripe_configured(self) -> bool:
        """Return True when a Stripe secret key is set."""
        return bool(self.stripe_secret_key)

    @property
    def stripe_test_configured(self) -> bool:
        """Return True when Stripe test-mode keys are set."""
        return bool(self.stripe_test_secret_key)

    @property
    def missing_stripe_price_ids(self) -> list[str]:
        """Return env var names for subscription price IDs that are unset.

        Used at startup to fail loudly: a Stripe key without price IDs means
        every paid checkout is rejected, which is invisible until a customer
        hits it.
        """
        required = {
            "SIGIL_STRIPE_PRICE_PRO": self.stripe_price_pro,
            "SIGIL_STRIPE_PRICE_TEAM": self.stripe_price_team,
            "SIGIL_STRIPE_PRICE_PRO_ANNUAL": self.stripe_price_pro_annual,
            "SIGIL_STRIPE_PRICE_TEAM_ANNUAL": self.stripe_price_team_annual,
        }
        return [name for name, value in required.items() if not value]

    @property
    def github_app_configured(self) -> bool:
        """Return True when the GitHub App credentials are set."""
        return bool(self.github_app_id and self.github_app_private_key)

    @property
    def github_token_configured(self) -> bool:
        """Return True when a GitHub PAT for traffic API is set."""
        return bool(self.github_token)

    @property
    def jwt_secret_is_insecure(self) -> bool:
        """Return True when the JWT secret has not been changed from the default."""
        return self.jwt_secret == "changeme-generate-a-real-secret"

    @property
    def azure_insights_configured(self) -> bool:
        """Return True when Azure Application Insights is configured."""
        return bool(self.azure_insights_key)

    @property
    def posthog_configured(self) -> bool:
        """Return True when PostHog API key is set."""
        return bool(self.posthog_api_key)


# Singleton — importable from anywhere as `from config import settings`.
settings = Settings()

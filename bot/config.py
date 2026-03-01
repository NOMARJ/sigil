"""
Sigil Bot — Configuration

All settings loaded from environment variables with SIGIL_BOT_ prefix.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_BOT_DIR = Path(__file__).parent
_ENV_FILE = _BOT_DIR / ".env"


class BotSettings(BaseSettings):
    """Central configuration for Sigil Bot processes."""

    model_config = SettingsConfigDict(
        env_prefix="SIGIL_BOT_",
        env_file=str(_ENV_FILE) if _ENV_FILE.exists() else None,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Redis (Upstash or self-hosted) ----------------------------------------
    redis_url: str = "redis://localhost:6379"

    # --- Database ----------------------------------------
    database_url: str | None = None

    # --- Sigil CLI path --------------------------------------------------------
    sigil_bin: str = "sigil"

    # --- Quarantine directory ---------------------------------------------------
    quarantine_dir: str = "/tmp/sigil-quarantine"

    # --- Scan timeout (seconds) ------------------------------------------------
    scan_timeout: int = 120

    # --- GitHub API token (for MCP repo monitoring) ----------------------------
    github_token: str | None = None

    # --- Social (X/Twitter) — deferred -----------------------------------------
    twitter_api_key: str | None = None
    twitter_api_secret: str | None = None
    twitter_access_token: str | None = None
    twitter_access_secret: str | None = None

    # --- Polling intervals (seconds) -------------------------------------------
    pypi_rss_interval: int = 300  # 5 minutes
    pypi_changelog_interval: int = 60  # 1 minute
    npm_changes_interval: int = 60  # 1 minute
    clawhub_interval: int = 21600  # 6 hours
    github_search_interval: int = 43200  # 12 hours
    github_events_interval: int = 1800  # 30 minutes
    skills_poll_interval: int = 21600  # 6 hours
    skills_crawl_batch_size: int = 10  # skills per search query

    # --- Worker concurrency ----------------------------------------------------
    max_concurrent_scans: int = 4

    # --- AEO / ISR revalidation ------------------------------------------------
    revalidation_url: str = "https://sigilsec.ai/api/revalidate"
    revalidation_secret: str | None = None

    # --- Rescan scheduling -----------------------------------------------------
    rescan_high_risk_days: int = 7  # HIGH/CRITICAL rescanned weekly
    rescan_popular_days: int = 30  # >10K downloads rescanned monthly
    rescan_default_days: int = 90  # all others rescanned quarterly

    # --- Alert thresholds ------------------------------------------------------
    dead_letter_alert_threshold: int = 10  # per hour
    queue_depth_alert_threshold: int = 500
    max_social_posts_per_day: int = 10
    min_social_post_interval: int = 1800  # 30 minutes

    @property
    def database_configured(self) -> bool:
        return bool(self.database_url)

    @property
    def github_configured(self) -> bool:
        return bool(self.github_token) and self.github_token != "not-configured"

    @property
    def twitter_configured(self) -> bool:
        return bool(
            self.twitter_api_key
            and self.twitter_api_secret
            and self.twitter_access_token
            and self.twitter_access_secret
        )


bot_settings = BotSettings()

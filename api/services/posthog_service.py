"""
PostHog Service — Server-side event capture for conversion funnel analytics.

Provides a thin wrapper around the posthog-python SDK with:
- Graceful no-op when SIGIL_POSTHOG_API_KEY is not configured
- Batch mode for performance
- Consistent error handling and logging
"""

from __future__ import annotations

import logging
from typing import Any

from api.config import settings

logger = logging.getLogger(__name__)


class PostHogService:
    """Server-side PostHog event capture with graceful degradation."""

    def __init__(self):
        self._client = None
        self._enabled = False

    def initialize(self):
        """Initialize PostHog client if configured."""
        if not settings.posthog_configured:
            logger.info("PostHogService: not configured (set SIGIL_POSTHOG_API_KEY to enable)")
            return

        try:
            import posthog
            posthog.project_api_key = settings.posthog_api_key
            posthog.host = settings.posthog_host
            # Batch mode is default in posthog-python — events are flushed
            # automatically every 0.5s or when batch size reaches 100
            posthog.debug = settings.debug
            self._client = posthog
            self._enabled = True
            logger.info("PostHogService: initialized (host=%s)", settings.posthog_host)
        except ImportError:
            logger.warning("PostHogService: posthog package not installed")
        except Exception as e:
            logger.error("PostHogService: initialization failed: %s", e)

    def capture(
        self,
        distinct_id: str,
        event: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Capture an event. No-op if PostHog is not configured."""
        if not self._enabled or self._client is None:
            return

        try:
            self._client.capture(
                distinct_id=distinct_id,
                event=event,
                properties=properties or {},
            )
            logger.debug("PostHog event captured: %s (user=%s)", event, distinct_id)
        except Exception as e:
            # Never let PostHog failures break the application
            logger.warning("PostHog capture failed for event %s: %s", event, e)

    def identify(
        self,
        distinct_id: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Identify a user with properties. No-op if not configured."""
        if not self._enabled or self._client is None:
            return

        try:
            self._client.identify(
                distinct_id=distinct_id,
                properties=properties or {},
            )
        except Exception as e:
            logger.warning("PostHog identify failed for user %s: %s", distinct_id, e)

    def alias(self, previous_id: str, distinct_id: str) -> None:
        """Link anonymous ID to user ID. No-op if not configured."""
        if not self._enabled or self._client is None:
            return

        try:
            self._client.alias(previous_id=previous_id, distinct_id=distinct_id)
        except Exception as e:
            logger.warning("PostHog alias failed: %s", e)

    def flush(self) -> None:
        """Flush pending events. Call on app shutdown."""
        if not self._enabled or self._client is None:
            return

        try:
            self._client.flush()
            logger.info("PostHogService: flushed pending events")
        except Exception as e:
            logger.warning("PostHog flush failed: %s", e)

    @property
    def enabled(self) -> bool:
        return self._enabled


# Singleton
posthog_service = PostHogService()

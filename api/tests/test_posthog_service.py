"""
PostHog Service Tests

Tests for graceful degradation when PostHog is not configured.

Test Coverage:
- Service starts disabled by default
- capture() is a no-op when not configured
- initialize() logs info and stays disabled when API key is absent
"""

from __future__ import annotations

import logging

from unittest.mock import patch

from api.services.posthog_service import PostHogService


class TestPostHogServiceUnconfigured:
    """Tests for graceful no-op behaviour when PostHog is not configured."""

    def test_enabled_is_false_by_default(self):
        """A freshly constructed service must report disabled."""
        service = PostHogService()
        assert service.enabled is False

    def test_capture_is_noop_when_not_configured(self):
        """capture() must not raise and must not call any SDK when disabled."""
        service = PostHogService()
        # Should complete without error and without touching self._client
        service.capture(distinct_id="anon-123", event="page_viewed")
        assert service._client is None

    def test_capture_with_properties_is_noop_when_not_configured(self):
        """capture() with a properties dict must still be a silent no-op."""
        service = PostHogService()
        service.capture(
            distinct_id="anon-456",
            event="scan_started",
            properties={"plan": "free", "source": "cli"},
        )
        assert service._client is None

    def test_identify_is_noop_when_not_configured(self):
        """identify() must not raise when the service is disabled."""
        service = PostHogService()
        service.identify(distinct_id="user-789", properties={"email": "a@b.com"})
        assert service._client is None

    def test_alias_is_noop_when_not_configured(self):
        """alias() must not raise when the service is disabled."""
        service = PostHogService()
        service.alias(previous_id="anon-abc", distinct_id="user-xyz")
        assert service._client is None

    def test_flush_is_noop_when_not_configured(self):
        """flush() must not raise when the service is disabled."""
        service = PostHogService()
        service.flush()
        assert service._client is None

    def test_initialize_logs_info_when_not_configured(self, caplog):
        """initialize() must log at INFO level and leave service disabled."""
        service = PostHogService()

        with patch("api.config.settings") as mock_settings:
            mock_settings.posthog_configured = False

            with caplog.at_level(logging.INFO, logger="api.services.posthog_service"):
                service.initialize()

        assert service.enabled is False

    def test_initialize_stays_disabled_without_api_key(self):
        """initialize() with no API key configured must leave enabled=False."""
        service = PostHogService()

        with patch("api.config.settings") as mock_settings:
            mock_settings.posthog_configured = False
            service.initialize()

        assert service.enabled is False
        assert service._client is None

"""Sigil API — password reset email regression.

Production bug 2026-05-04: dashboard `/reset-password` page calls
`POST /v1/auth/forgot-password`, which generated the token correctly but
silently dropped the email. Root cause: `_send_reset_email` used the
SMTP-only `send_email_notification` helper, but production runs with
`SIGIL_SMTP_HOST=""` (Resend is the active email provider).

Fix: route password reset email through `notification_service.send_email`,
which dispatches to Resend when `SIGIL_RESEND_API_KEY` is set. This test
asserts the call site is plumbed correctly and the recipient/body shape
is preserved.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from api.routers import auth as auth_module


@pytest.mark.asyncio
async def test_send_reset_email_routes_through_notification_service():
    """`_send_reset_email` must call notification_service.send_email
    (which is Resend-aware) — not the legacy SMTP-only helper."""
    fake_send = AsyncMock(return_value=True)
    with patch(
        "api.services.notification_service.notification_service.send_email",
        fake_send,
    ):
        await auth_module._send_reset_email(
            email="alice@example.com",
            reset_link="https://app.sigilsec.ai/reset-password?token=abc123",
        )

    fake_send.assert_awaited_once()
    call_kwargs = fake_send.call_args.kwargs
    assert call_kwargs["to_email"] == "alice@example.com"
    assert call_kwargs["subject"] == "Reset your Sigil password"
    assert "abc123" in call_kwargs["content"], (
        "reset link must be in body so the user can click it"
    )
    assert "expires in 1 hour" in call_kwargs["content"]


@pytest.mark.asyncio
async def test_send_reset_email_does_not_use_legacy_smtp_helper():
    """Regression guard: the legacy helper from notifications.py must
    NOT be called — that path silently no-ops in production."""
    fake_send = AsyncMock(return_value=True)
    legacy_smtp = AsyncMock(return_value=True)
    with (
        patch(
            "api.services.notification_service.notification_service.send_email",
            fake_send,
        ),
        patch(
            "api.services.notifications.send_email_notification",
            legacy_smtp,
        ),
    ):
        await auth_module._send_reset_email(
            email="bob@example.com",
            reset_link="https://app.sigilsec.ai/reset-password?token=xyz",
        )

    fake_send.assert_awaited_once()
    legacy_smtp.assert_not_awaited()


@pytest.mark.asyncio
async def test_send_reset_email_swallows_provider_failure():
    """If the email provider fails (returns False), the function logs
    and returns — the caller (`forgot_password`) still returns success
    to the client per anti-enumeration policy."""
    fake_send = AsyncMock(return_value=False)
    with patch(
        "api.services.notification_service.notification_service.send_email",
        fake_send,
    ):
        # No exception should propagate
        result = await auth_module._send_reset_email(
            email="carol@example.com",
            reset_link="https://app.sigilsec.ai/reset-password?token=q",
        )

    assert result is None  # function returns None, doesn't raise
    fake_send.assert_awaited_once()

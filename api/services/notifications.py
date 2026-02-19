"""
Sigil API — Notification Service

Handles sending alert notifications through multiple channels:
- Slack (via incoming webhook)
- Email (via SMTP)
- Generic webhook (HTTP POST)

All channels degrade gracefully when their backing infrastructure is not
configured, logging warnings instead of raising exceptions.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import httpx

from api.config import settings

logger = logging.getLogger(__name__)

# Default timeout for outbound HTTP requests (seconds)
_HTTP_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


async def send_slack_notification(
    webhook_url: str,
    message: str,
    *,
    title: str = "Sigil Alert",
    color: str = "#d32f2f",
    fields: list[dict[str, str]] | None = None,
) -> bool:
    """Send a notification to a Slack incoming webhook.

    Returns ``True`` on success, ``False`` on failure.
    """
    payload: dict[str, Any] = {
        "attachments": [
            {
                "color": color,
                "title": title,
                "text": message,
                "footer": "Sigil Security Platform",
                "ts": __import__("time").time(),
            }
        ]
    }

    if fields:
        payload["attachments"][0]["fields"] = [
            {
                "title": f.get("title", ""),
                "value": f.get("value", ""),
                "short": f.get("short", True),
            }
            for f in fields
        ]

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code == 200:
                logger.info("Slack notification sent successfully")
                return True
            logger.warning("Slack webhook returned %d: %s", resp.status_code, resp.text)
            return False
    except httpx.HTTPError as exc:
        logger.warning("Slack notification failed: %s", exc)
        return False
    except Exception:
        logger.exception("Unexpected error sending Slack notification")
        return False


# ---------------------------------------------------------------------------
# Email (SMTP)
# ---------------------------------------------------------------------------


async def send_email_notification(
    recipients: list[str],
    subject: str,
    body_text: str,
    *,
    body_html: str | None = None,
) -> bool:
    """Send an email notification via SMTP.

    Uses the SMTP settings from ``api.config.settings``.  Returns ``True``
    on success, ``False`` on failure or when SMTP is not configured.
    """
    if not settings.smtp_configured:
        logger.warning(
            "SMTP not configured — skipping email notification. "
            "Set SIGIL_SMTP_HOST, SIGIL_SMTP_USER, and SIGIL_SMTP_PASSWORD to enable."
        )
        return False

    if not recipients:
        logger.warning("No email recipients specified — skipping notification")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from_email
    msg["To"] = ", ".join(recipients)

    # Always attach plain text
    msg.attach(MIMEText(body_text, "plain"))

    # Optionally attach HTML
    if body_html:
        msg.attach(MIMEText(body_html, "html"))

    try:
        # Run SMTP in a thread to avoid blocking the event loop
        import asyncio

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _smtp_send, recipients, msg)
        logger.info("Email notification sent to %s", ", ".join(recipients))
        return True
    except smtplib.SMTPException as exc:
        logger.warning("SMTP error sending email: %s", exc)
        return False
    except Exception:
        logger.exception("Unexpected error sending email notification")
        return False


def _smtp_send(recipients: list[str], msg: MIMEMultipart) -> None:
    """Blocking SMTP send — called via run_in_executor."""
    context = ssl.create_default_context()

    if settings.smtp_port == 465:
        # SSL/TLS from the start
        with smtplib.SMTP_SSL(
            settings.smtp_host, settings.smtp_port, context=context
        ) as server:
            server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg, to_addrs=recipients)
    else:
        # STARTTLS (port 587 or other)
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg, to_addrs=recipients)


# ---------------------------------------------------------------------------
# Generic Webhook
# ---------------------------------------------------------------------------


async def send_webhook_notification(
    webhook_url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    method: str = "POST",
) -> bool:
    """Send a notification to a generic webhook endpoint via HTTP POST.

    Returns ``True`` on success (2xx response), ``False`` otherwise.
    """
    request_headers = {
        "Content-Type": "application/json",
        "User-Agent": f"Sigil/{settings.app_version}",
    }
    if headers:
        request_headers.update(headers)

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.request(
                method,
                webhook_url,
                json=payload,
                headers=request_headers,
            )
            if 200 <= resp.status_code < 300:
                logger.info(
                    "Webhook notification sent to %s (status=%d)",
                    webhook_url,
                    resp.status_code,
                )
                return True
            logger.warning("Webhook returned %d: %s", resp.status_code, resp.text[:200])
            return False
    except httpx.HTTPError as exc:
        logger.warning("Webhook notification failed: %s", exc)
        return False
    except Exception:
        logger.exception("Unexpected error sending webhook notification")
        return False


# ---------------------------------------------------------------------------
# Unified dispatcher
# ---------------------------------------------------------------------------


async def send_notification(
    channel_type: str,
    channel_config: dict[str, Any],
    *,
    title: str = "Sigil Alert",
    message: str = "",
    payload: dict[str, Any] | None = None,
) -> bool:
    """Route a notification to the appropriate channel handler.

    Supported channel types: ``slack``, ``email``, ``webhook``.

    Args:
        channel_type: One of "slack", "email", "webhook".
        channel_config: Channel-specific configuration.
        title: Notification title / subject.
        message: Human-readable message body.
        payload: Additional structured data (used for webhooks).

    Returns:
        ``True`` if the notification was delivered successfully.
    """
    channel_type = channel_type.lower()

    if channel_type == "slack":
        webhook_url = channel_config.get("webhook_url", "")
        if not webhook_url:
            logger.warning("Slack channel missing 'webhook_url' in config")
            return False
        return await send_slack_notification(
            webhook_url,
            message,
            title=title,
            color=channel_config.get("color", "#d32f2f"),
        )

    elif channel_type == "email":
        recipients = channel_config.get("recipients", [])
        if isinstance(recipients, str):
            recipients = [recipients]
        return await send_email_notification(
            recipients,
            subject=title,
            body_text=message,
            body_html=channel_config.get("body_html"),
        )

    elif channel_type == "webhook":
        webhook_url = channel_config.get("webhook_url", "")
        if not webhook_url:
            logger.warning("Webhook channel missing 'webhook_url' in config")
            return False
        notify_payload = payload or {
            "title": title,
            "message": message,
            "source": "sigil",
            "version": settings.app_version,
        }
        return await send_webhook_notification(
            webhook_url,
            notify_payload,
            headers=channel_config.get("headers"),
        )

    else:
        logger.warning("Unknown notification channel type: %s", channel_type)
        return False


async def send_scan_alert(
    channel_type: str,
    channel_config: dict[str, Any],
    *,
    scan_id: str,
    target: str,
    verdict: str,
    risk_score: float,
    findings_count: int,
) -> bool:
    """Convenience helper to send a scan result alert.

    Builds a human-readable message and dispatches through :func:`send_notification`.
    """
    message = (
        f"Scan completed: *{target}*\n"
        f"Verdict: *{verdict}* | Risk Score: *{risk_score:.1f}* | Findings: *{findings_count}*\n"
        f"Scan ID: `{scan_id}`"
    )

    payload = {
        "event": "scan_completed",
        "scan_id": scan_id,
        "target": target,
        "verdict": verdict,
        "risk_score": risk_score,
        "findings_count": findings_count,
    }

    return await send_notification(
        channel_type,
        channel_config,
        title=f"Sigil Scan Alert: {verdict}",
        message=message,
        payload=payload,
    )

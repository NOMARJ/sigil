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

import asyncio
import json
import logging
import smtplib
import ssl
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from ipaddress import ip_address
from socket import gaierror, getaddrinfo
from typing import Any
from urllib.parse import urlsplit

from api.config import settings

logger = logging.getLogger(__name__)

# Default timeout for outbound HTTP requests (seconds)
_HTTP_TIMEOUT = 10.0


def is_safe_webhook_url(webhook_url: str) -> bool:
    """Return True only for public HTTPS webhook destinations."""
    return _safe_webhook_target(webhook_url) is not None


def _safe_webhook_target(webhook_url: str) -> tuple[str, str, int, str] | None:
    """Return a public resolved IP, original host, port, and request path."""
    try:
        parsed = urlsplit(webhook_url)
    except ValueError:
        return None

    if parsed.scheme != "https" or not parsed.hostname:
        return None

    hostname = parsed.hostname
    try:
        literal_ip = ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if not _is_public_destination_ip(literal_ip):
            return None
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return str(literal_ip), hostname, parsed.port or 443, path

    try:
        resolved = getaddrinfo(hostname, parsed.port or 443, type=0)
    except gaierror:
        logger.warning("Could not resolve webhook host: %s", hostname)
        return None

    public_addresses = []
    for info in resolved:
        try:
            address = ip_address(info[4][0])
        except ValueError:
            return None
        if not _is_public_destination_ip(address):
            return None
        public_addresses.append(str(address))

    if not public_addresses:
        return None

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return public_addresses[0], hostname, parsed.port or 443, path


def _is_public_destination_ip(address: Any) -> bool:
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


async def _send_json_to_pinned_https_target(
    target: tuple[str, str, int, str],
    payload: dict[str, Any],
    *,
    headers: dict[str, str],
    method: str,
) -> tuple[int, str]:
    address, hostname, port, path = target
    body = json.dumps(payload).encode("utf-8")
    request_headers = {
        **headers,
        "Host": hostname if port == 443 else f"{hostname}:{port}",
        "Content-Length": str(len(body)),
        "Connection": "close",
    }
    context = ssl.create_default_context()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            address,
            port,
            ssl=context,
            server_hostname=hostname,
        ),
        timeout=_HTTP_TIMEOUT,
    )

    try:
        header_lines = "".join(
            f"{key}: {value}\r\n"
            for key, value in request_headers.items()
            if "\r" not in key
            and "\n" not in key
            and "\r" not in str(value)
            and "\n" not in str(value)
        )
        writer.write(
            f"{method.upper()} {path} HTTP/1.1\r\n{header_lines}\r\n".encode("utf-8")
            + body
        )
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=_HTTP_TIMEOUT)
        parts = status_line.decode("iso-8859-1", errors="replace").split()
        status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=_HTTP_TIMEOUT)
            if line in (b"\r\n", b"\n", b""):
                break
        response_body = await asyncio.wait_for(reader.read(2048), timeout=_HTTP_TIMEOUT)
        return status_code, response_body.decode("utf-8", errors="replace")
    finally:
        writer.close()
        await writer.wait_closed()


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
                "ts": time.time(),
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

    safe_target = _safe_webhook_target(webhook_url)
    if safe_target is None:
        logger.warning("Blocked unsafe Slack webhook destination")
        return False

    try:
        status_code, response_text = await _send_json_to_pinned_https_target(
            safe_target,
            payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"Sigil/{settings.app_version}",
            },
            method="POST",
        )
        if status_code == 200:
            logger.info("Slack notification sent successfully")
            return True
        logger.warning("Slack webhook returned %d: %s", status_code, response_text)
        return False
    except OSError as exc:
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

    safe_target = _safe_webhook_target(webhook_url)
    if safe_target is None:
        logger.warning("Blocked unsafe webhook destination")
        return False
    try:
        status_code, response_text = await _send_json_to_pinned_https_target(
            safe_target,
            payload,
            headers=request_headers,
            method=method,
        )
        if 200 <= status_code < 300:
            logger.info(
                "Webhook notification sent to %s (status=%d)",
                webhook_url,
                status_code,
            )
            return True
        logger.warning("Webhook returned %d: %s", status_code, response_text[:200])
        return False
    except OSError as exc:
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

"""
Sigil Bot — Publisher

Consumes new scan results and updates all downstream surfaces:
  1. Badge cache invalidation (Redis)
  2. RSS feed append
  3. Alert dispatch (HIGH RISK / CRITICAL RISK)
  4. Social posting (deferred)
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape as xml_escape

import redis.asyncio as aioredis

from bot.config import bot_settings
from bot.queue import ScanJob

logger = logging.getLogger(__name__)

# RSS feed stored in Redis as a list of XML <item> strings
RSS_FEED_KEY = "sigil:rss:items"
RSS_MAX_ITEMS = 100

# Social rate limiting
SOCIAL_POST_COUNT_KEY = "sigil:social:post_count"
SOCIAL_LAST_POST_KEY = "sigil:social:last_post"

_redis: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(
            bot_settings.redis_url, decode_responses=True
        )
    return _redis


async def publish_scan(
    scan_id: str,
    job: ScanJob,
    scan_output: dict[str, Any],
) -> None:
    """Publish a completed scan to all downstream surfaces."""
    verdict = scan_output.get("verdict", "LOW_RISK")
    score = scan_output.get("score", 0.0)
    findings = scan_output.get("findings", [])

    # 1. Invalidate badge cache
    await _invalidate_badge_cache(job.ecosystem, job.name)

    # 2. Append to RSS feed
    await _append_rss(scan_id, job, scan_output)

    # 3. Alert on high-risk findings
    if verdict in ("HIGH_RISK", "CRITICAL_RISK"):
        await _dispatch_alert(scan_id, job, scan_output)

    logger.info(
        "Published scan %s: %s/%s@%s → %s",
        scan_id,
        job.ecosystem,
        job.name,
        job.version,
        verdict,
    )


async def _invalidate_badge_cache(ecosystem: str, name: str) -> None:
    """Clear the cached badge SVG so next request generates fresh."""
    r = await _get_redis()
    badge_key = f"badge:{ecosystem}:{name}"
    await r.delete(badge_key)


async def _append_rss(
    scan_id: str,
    job: ScanJob,
    scan_output: dict[str, Any],
) -> None:
    """Append scan result as an RSS <item> to the feed in Redis."""
    r = await _get_redis()
    verdict = scan_output.get("verdict", "LOW_RISK")
    score = scan_output.get("score", 0.0)
    findings = scan_output.get("findings", [])
    now = datetime.now(timezone.utc)

    # Build finding summary
    finding_summaries = []
    for f in findings[:5]:
        rule = f.get("rule", "unknown")
        severity = f.get("severity", "MEDIUM")
        finding_summaries.append(f"{severity}: {rule}")
    summary = "; ".join(finding_summaries) if finding_summaries else "No notable findings"

    title = f"[{verdict}] {job.name}@{job.version} ({job.ecosystem.upper()})"
    link = f"https://sigilsec.ai/scans/{job.ecosystem}/{job.name}"
    description = (
        f"Risk score: {score:.0f}. "
        f"{len(findings)} finding(s). {summary}."
    )

    item_xml = (
        f"<item>"
        f"<title>{xml_escape(title)}</title>"
        f"<link>{xml_escape(link)}</link>"
        f"<description>{xml_escape(description)}</description>"
        f"<pubDate>{now.strftime('%a, %d %b %Y %H:%M:%S GMT')}</pubDate>"
        f"<guid>{xml_escape(link)}?v={xml_escape(job.version)}</guid>"
        f"<category>{xml_escape(job.ecosystem)}</category>"
        f"</item>"
    )

    # Push to front of list, trim to max
    await r.lpush(RSS_FEED_KEY, item_xml)
    await r.ltrim(RSS_FEED_KEY, 0, RSS_MAX_ITEMS - 1)

    # Also store per-ecosystem
    eco_key = f"sigil:rss:items:{job.ecosystem}"
    await r.lpush(eco_key, item_xml)
    await r.ltrim(eco_key, 0, RSS_MAX_ITEMS - 1)


async def generate_rss_feed(
    ecosystem: str | None = None,
    verdict_filter: str | None = None,
) -> str:
    """Generate a complete RSS 2.0 feed XML string."""
    r = await _get_redis()

    if ecosystem:
        key = f"sigil:rss:items:{ecosystem}"
    else:
        key = RSS_FEED_KEY

    items = await r.lrange(key, 0, RSS_MAX_ITEMS - 1)

    # Filter by verdict if requested
    if verdict_filter:
        allowed_verdicts = {v.strip().upper() for v in verdict_filter.split(",")}
        filtered = []
        for item in items:
            for v in allowed_verdicts:
                if f"[{v}]" in item:
                    filtered.append(item)
                    break
        items = filtered

    items_xml = "\n    ".join(items)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Sigil Security Scanner — Threat Feed</title>
    <link>https://sigilsec.ai/scans</link>
    <description>Automated security scan results for AI agent packages</description>
    <language>en-us</language>
    <lastBuildDate>{datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')}</lastBuildDate>
    {items_xml}
  </channel>
</rss>"""


async def _dispatch_alert(
    scan_id: str,
    job: ScanJob,
    scan_output: dict[str, Any],
) -> None:
    """Dispatch alerts for HIGH_RISK / CRITICAL_RISK findings."""
    verdict = scan_output.get("verdict", "")
    score = scan_output.get("score", 0.0)
    findings = scan_output.get("findings", [])

    # Store alert in Redis for webhook consumers
    r = await _get_redis()
    alert = {
        "scan_id": scan_id,
        "ecosystem": job.ecosystem,
        "name": job.name,
        "version": job.version,
        "verdict": verdict,
        "score": score,
        "findings_count": len(findings),
        "url": f"https://sigilsec.ai/scans/{job.ecosystem}/{job.name}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await r.lpush("sigil:alerts", json.dumps(alert))
    await r.ltrim("sigil:alerts", 0, 999)

    logger.warning(
        "ALERT: %s %s/%s@%s — score=%.0f, findings=%d",
        verdict,
        job.ecosystem,
        job.name,
        job.version,
        score,
        len(findings),
    )

    # Social posting (rate-limited, deferred feature)
    if bot_settings.twitter_configured:
        await _maybe_post_social(job, scan_output)


async def _maybe_post_social(
    job: ScanJob,
    scan_output: dict[str, Any],
) -> None:
    """Post to social media if rate limits allow."""
    r = await _get_redis()

    # Check daily limit
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    count_key = f"{SOCIAL_POST_COUNT_KEY}:{today}"
    count = int(await r.get(count_key) or 0)
    if count >= bot_settings.max_social_posts_per_day:
        return

    # Check minimum interval
    last_post = await r.get(SOCIAL_LAST_POST_KEY)
    if last_post:
        elapsed = time.time() - float(last_post)
        if elapsed < bot_settings.min_social_post_interval:
            return

    verdict = scan_output.get("verdict", "")
    findings = scan_output.get("findings", [])

    # Build post
    finding_lines = []
    for f in findings[:3]:
        rule = f.get("rule", "")
        finding_lines.append(f"  Risk indicator: {rule}")
    findings_text = "\n".join(finding_lines)

    post_text = (
        f"{verdict} detected: {job.name}@{job.version} on {job.ecosystem.upper()}\n"
        f"\n"
        f"{findings_text}\n"
        f"\n"
        f"Full report: sigilsec.ai/scans/{job.ecosystem}/{job.name}\n"
        f"\n"
        f"#sigil #supplychain #security"
    )

    # Post (implementation depends on Twitter API client)
    logger.info("Social post queued: %s/%s", job.ecosystem, job.name)

    # Update rate limit counters
    await r.incr(count_key)
    await r.expire(count_key, 86400)
    await r.set(SOCIAL_LAST_POST_KEY, str(time.time()))

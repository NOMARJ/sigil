"""
Sigil Bot — Publisher

Consumes new scan results and updates all downstream surfaces:
  1. Badge cache invalidation (Redis + DB)
  2. RSS feed append
  3. Alert dispatch (HIGH RISK / CRITICAL RISK)
  4. Social posting (deferred)
  5. ISR revalidation (sigilsec.ai page regeneration)
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape as xml_escape

import httpx
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

    # 1. Invalidate badge cache (Redis + DB upsert)
    await _invalidate_badge_cache(job.ecosystem, job.name, job.version, verdict, score)

    # 2. Append to RSS feed
    await _append_rss(scan_id, job, scan_output)

    # 3. Alert on high-risk findings
    if verdict in ("HIGH_RISK", "CRITICAL_RISK"):
        await _dispatch_alert(scan_id, job, scan_output)

    # 4. ISR revalidation (fire-and-forget)
    await _trigger_revalidation(job.ecosystem, job.name)

    logger.info(
        "Published scan %s: %s/%s@%s → %s",
        scan_id,
        job.ecosystem,
        job.name,
        job.version,
        verdict,
    )


async def _invalidate_badge_cache(
    ecosystem: str,
    name: str,
    version: str = "",
    verdict: str = "",
    score: float = 0.0,
) -> None:
    """Clear the cached badge SVG and upsert badge_cache in DB."""
    # Redis invalidation
    r = await _get_redis()
    badge_key = f"badge:{ecosystem}:{name}"
    await r.delete(badge_key)

    # DB upsert for persistent badge cache (Action #3)
    if verdict:
        try:
            from bot.store import get_db

            db = await get_db()
            await db.upsert(
                "badge_cache",
                {
                    "ecosystem": ecosystem,
                    "package_name": name,
                    "package_version": version,
                    "verdict": verdict,
                    "risk_score": round(score, 2),
                    "updated_at": datetime.now(timezone.utc),
                },
                conflict_columns=["ecosystem", "package_name"],
            )
        except Exception:
            logger.debug("Badge cache DB upsert failed (non-fatal)", exc_info=True)


async def _trigger_revalidation(ecosystem: str, package_name: str) -> None:
    """POST to sigilsec.ai/api/revalidate to trigger ISR page regeneration.

    Fire-and-forget — never blocks the scan pipeline.
    """
    if not bot_settings.revalidation_secret:
        return

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                bot_settings.revalidation_url,
                headers={
                    "x-webhook-secret": bot_settings.revalidation_secret,
                    "Content-Type": "application/json",
                },
                json={
                    "type": "scan",
                    "ecosystem": ecosystem,
                    "package_name": package_name,
                },
            )
            if resp.status_code == 200:
                logger.debug("ISR revalidation triggered for %s/%s", ecosystem, package_name)
            else:
                logger.debug(
                    "ISR revalidation returned %d for %s/%s",
                    resp.status_code, ecosystem, package_name,
                )
    except Exception:
        logger.debug("ISR revalidation failed (non-fatal)", exc_info=True)


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

    # Build finding summary using human-readable descriptions
    finding_summaries = []
    for f in findings[:5]:
        desc = f.get("description", f.get("rule", "unknown"))
        severity = f.get("severity", "MEDIUM")
        finding_summaries.append(f"{severity}: {desc}")
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
        f"<category>{xml_escape(verdict)}</category>"
        f"</item>"
    )

    # Push to front of list, trim to max
    await r.lpush(RSS_FEED_KEY, item_xml)
    await r.ltrim(RSS_FEED_KEY, 0, RSS_MAX_ITEMS - 1)

    # Also store per-ecosystem for efficient filtered feeds
    eco_key = f"sigil:rss:items:{job.ecosystem}"
    await r.lpush(eco_key, item_xml)
    await r.ltrim(eco_key, 0, RSS_MAX_ITEMS - 1)

    # Also store per-verdict for efficient threat-only feeds
    verdict_key = f"sigil:rss:items:verdict:{verdict.lower()}"
    await r.lpush(verdict_key, item_xml)
    await r.ltrim(verdict_key, 0, RSS_MAX_ITEMS - 1)


async def generate_rss_feed(
    ecosystem: str | None = None,
    verdict_filter: str | None = None,
    limit: int = RSS_MAX_ITEMS,
) -> str:
    """Generate a complete RSS 2.0 feed XML string.

    Supports filtering by ecosystem and/or verdict:
      - ecosystem="clawhub" → only ClawHub scans
      - verdict_filter="high_risk,critical_risk" → threats only
      - Both can be combined
    """
    r = await _get_redis()
    max_items = min(limit, RSS_MAX_ITEMS)

    # Determine which Redis key to read from
    if ecosystem and not verdict_filter:
        # Fast path: per-ecosystem list
        key = f"sigil:rss:items:{ecosystem}"
        items = await r.lrange(key, 0, max_items - 1)

    elif verdict_filter and not ecosystem:
        # Parse verdict filter
        verdicts = [v.strip().lower() for v in verdict_filter.split(",") if v.strip()]
        if len(verdicts) == 1:
            # Fast path: single-verdict list
            key = f"sigil:rss:items:verdict:{verdicts[0]}"
            items = await r.lrange(key, 0, max_items - 1)
        else:
            # Multi-verdict: merge from per-verdict lists and sort by recency
            items = []
            for v in verdicts:
                key = f"sigil:rss:items:verdict:{v}"
                items.extend(await r.lrange(key, 0, max_items - 1))
            # Deduplicate by guid and take the most recent
            seen: set[str] = set()
            unique: list[str] = []
            for item in items:
                # Extract guid as dedup key
                guid_start = item.find("<guid>")
                guid_end = item.find("</guid>")
                guid = item[guid_start:guid_end] if guid_start >= 0 else item
                if guid not in seen:
                    seen.add(guid)
                    unique.append(item)
            items = unique[:max_items]

    elif ecosystem and verdict_filter:
        # Both filters: read per-ecosystem, then filter by verdict
        key = f"sigil:rss:items:{ecosystem}"
        items = await r.lrange(key, 0, RSS_MAX_ITEMS - 1)
        allowed_verdicts = {v.strip().upper() for v in verdict_filter.split(",")}
        items = [
            item for item in items
            if any(f"[{v}]" in item for v in allowed_verdicts)
        ]
        items = items[:max_items]

    else:
        # No filter: all items
        items = await r.lrange(RSS_FEED_KEY, 0, max_items - 1)

    items_xml = "\n    ".join(items)

    # Build descriptive channel title based on filters
    title_parts = ["Sigil Security Scanner"]
    if ecosystem:
        title_parts.append(f"— {ecosystem.upper()}")
    if verdict_filter:
        title_parts.append("— Threat Alerts")
    channel_title = " ".join(title_parts)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>{xml_escape(channel_title)}</title>
    <link>https://sigilsec.ai/scans</link>
    <description>Automated security scan results for AI agent packages. Learn more at https://sigilsec.ai/bot</description>
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

    # Use human-readable verdict labels (never say "malicious")
    verdict_label = verdict.replace("_", " ").title()

    # Build finding summaries from description field (AEO Action #8)
    finding_lines = []
    for f in findings[:3]:
        desc = f.get("description", f.get("rule", ""))
        if desc:
            finding_lines.append(f"- {desc}")
    findings_text = "\n".join(finding_lines)

    # Full URL — no shorteners (agents resolve full URLs)
    report_url = f"https://sigilsec.ai/scans/{job.ecosystem}/{job.name}"

    post_text = (
        f"{verdict_label} detected: {job.name}@{job.version} on {job.ecosystem.upper()}\n"
        f"\n"
        f"{findings_text}\n"
        f"\n"
        f"Full report: {report_url}\n"
        f"\n"
        f"#sigil #supplychain #security"
    )

    # Post (implementation depends on Twitter API client)
    logger.info("Social post queued: %s/%s", job.ecosystem, job.name)

    # Update rate limit counters
    await r.incr(count_key)
    await r.expire(count_key, 86400)
    await r.set(SOCIAL_LAST_POST_KEY, str(time.time()))

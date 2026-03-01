"""
Sigil Bot — Skills.sh API Client

Provides access to the skills.sh search and audit APIs for enumerating
agent skills and fetching third-party security assessments.

API endpoints (discovered from alonw0/secure-skills fork):
  - Search:  https://skills.sh/api/search?q={query}&limit={n}
  - Audits:  https://add-skill.vercel.sh/audit?source={owner/repo}&skills={slug1,slug2}
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

SEARCH_API = "https://skills.sh/api/search"
AUDIT_API = "https://add-skill.vercel.sh/audit"

# Alphabetic + numeric prefixes for systematic discovery
# (search API requires min 2 chars)
_DISCOVERY_QUERIES = [
    # Common prefixes for skill names
    "ag", "ai", "an", "ap", "au", "az",
    "br", "bu",
    "cl", "co", "cr",
    "da", "de", "do",
    "en", "ex",
    "fe", "fi", "fr", "fu",
    "ge", "gi", "go", "gr",
    "he", "ho",
    "im", "in",
    "ja", "js",
    "ku",
    "la", "li", "lo",
    "ma", "me", "mi", "mo", "mu",
    "na", "ne", "no",
    "ob", "op",
    "pa", "pe", "po", "pr", "py",
    "re", "ro", "ru",
    "sc", "se", "sk", "sl", "sn", "so", "sq", "st", "su",
    "te", "th", "to", "tr", "tw", "ty",
    "ui", "un", "up",
    "va", "ve", "vi",
    "we", "wi", "wo",
    # Specific popular prefixes
    "azure", "react", "next", "skill", "agent", "browser",
    "supabase", "remotion", "marketing", "seo",
]


@dataclass(frozen=True)
class SkillInfo:
    """Metadata for a single skill from the skills.sh directory."""

    id: str  # e.g. "vercel-labs/skills/find-skills"
    skill_id: str  # e.g. "find-skills"
    name: str  # e.g. "find-skills"
    source: str  # e.g. "vercel-labs/skills" (owner/repo)
    installs: int = 0


@dataclass
class ProviderAssessment:
    """Security assessment from a third-party auditor."""

    risk: str = "unknown"  # safe, low, medium, high, critical, unknown
    alerts: int = 0
    score: int | None = None
    analyzed_at: str = ""


@dataclass
class SkillAuditResult:
    """Combined audit results for a skill from all providers."""

    skill_name: str = ""
    assessments: dict[str, ProviderAssessment] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        """Serialize to a dict suitable for ScanJob.metadata."""
        return {
            provider: {
                "risk": a.risk,
                "alerts": a.alerts,
                "score": a.score,
                "analyzed_at": a.analyzed_at,
            }
            for provider, a in self.assessments.items()
        }


class SkillsClient:
    """Async client for the skills.sh APIs."""

    def __init__(self, timeout: float = 15.0) -> None:
        self._timeout = timeout

    async def search(
        self,
        query: str,
        limit: int = 10,
        client: httpx.AsyncClient | None = None,
    ) -> list[SkillInfo]:
        """Search for skills matching a query.

        Returns up to ``limit`` results. The search API requires queries
        of at least 2 characters.
        """
        if len(query) < 2:
            return []

        async def _do(c: httpx.AsyncClient) -> list[SkillInfo]:
            try:
                resp = await c.get(
                    SEARCH_API,
                    params={"q": query, "limit": limit},
                )
                if resp.status_code != 200:
                    logger.debug(
                        "skills.sh search returned %d for q=%r",
                        resp.status_code,
                        query,
                    )
                    return []

                data = resp.json()
                skills: list[SkillInfo] = []
                for s in data.get("skills", []):
                    skills.append(
                        SkillInfo(
                            id=s.get("id", ""),
                            skill_id=s.get("skillId", s.get("id", "")),
                            name=s.get("name", ""),
                            source=s.get("source", ""),
                            installs=s.get("installs", 0),
                        )
                    )
                return skills
            except Exception:
                logger.debug("skills.sh search error for q=%r", query, exc_info=True)
                return []

        if client:
            return await _do(client)

        async with httpx.AsyncClient(timeout=self._timeout) as c:
            return await _do(c)

    async def fetch_audits(
        self,
        source: str,
        skill_slugs: list[str],
        client: httpx.AsyncClient | None = None,
    ) -> dict[str, SkillAuditResult]:
        """Fetch third-party audit results for one or more skills.

        ``source`` is the owner/repo (e.g. "microsoft/github-copilot-for-azure").
        ``skill_slugs`` are the skill names within that repo.

        Returns a dict keyed by skill name with audit results from each provider.
        """
        if not skill_slugs:
            return {}

        async def _do(c: httpx.AsyncClient) -> dict[str, SkillAuditResult]:
            try:
                resp = await c.get(
                    AUDIT_API,
                    params={
                        "source": source,
                        "skills": ",".join(skill_slugs),
                    },
                )
                if resp.status_code != 200:
                    logger.debug(
                        "skills.sh audit returned %d for %s/%s",
                        resp.status_code,
                        source,
                        skill_slugs,
                    )
                    return {}

                data = resp.json()
                results: dict[str, SkillAuditResult] = {}
                for skill_name, providers in data.items():
                    audit = SkillAuditResult(skill_name=skill_name)
                    for provider_id, assessment in providers.items():
                        audit.assessments[provider_id] = ProviderAssessment(
                            risk=assessment.get("risk", "unknown"),
                            alerts=assessment.get("alerts", 0),
                            score=assessment.get("score"),
                            analyzed_at=assessment.get("analyzedAt", ""),
                        )
                    results[skill_name] = audit
                return results
            except Exception:
                logger.debug(
                    "skills.sh audit error for %s", source, exc_info=True
                )
                return {}

        if client:
            return await _do(client)

        async with httpx.AsyncClient(timeout=self._timeout) as c:
            return await _do(c)

    async def discover_all(
        self,
        client: httpx.AsyncClient | None = None,
        delay: float = 1.0,
    ) -> list[SkillInfo]:
        """Enumerate skills by running systematic search queries.

        Since skills.sh has no bulk listing endpoint, we search using
        varied query prefixes and deduplicate by skill ID.

        Args:
            client: Optional shared httpx client.
            delay: Seconds between queries (rate limiting).

        Returns:
            Deduplicated list of all discovered skills.
        """
        seen: dict[str, SkillInfo] = {}

        async def _search(c: httpx.AsyncClient, query: str) -> None:
            results = await self.search(query, limit=50, client=c)
            for skill in results:
                if skill.id and skill.id not in seen:
                    seen[skill.id] = skill

        if client:
            for query in _DISCOVERY_QUERIES:
                await _search(client, query)
                await asyncio.sleep(delay)
        else:
            async with httpx.AsyncClient(timeout=self._timeout) as c:
                for query in _DISCOVERY_QUERIES:
                    await _search(c, query)
                    await asyncio.sleep(delay)

        logger.info("skills.sh discovery complete: %d unique skills found", len(seen))
        return list(seen.values())

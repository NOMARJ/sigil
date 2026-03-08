"""
Trending Cache Service

Redis caching implementation for trending tool calculations.
Provides fast access to pre-calculated trending data with configurable TTL.

Cache key format: forge:trending:{timeframe}:{ecosystem}:{page}
TTL: 1 hour (3600 seconds)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from database import cache
from services.trending_service import TrendingMetrics, TimeFrame

logger = logging.getLogger(__name__)


class TrendingCacheService:
    """Service for caching trending calculations in Redis."""

    # Cache configuration
    DEFAULT_TTL = 3600  # 1 hour in seconds
    CACHE_KEY_PREFIX = "forge:trending"

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def _build_cache_key(
        self, timeframe: TimeFrame, ecosystem: str, category: str, page: int = 1
    ) -> str:
        """Build cache key for trending data."""
        return f"{self.CACHE_KEY_PREFIX}:{timeframe}:{ecosystem}:{category}:{page}"

    def _serialize_trending_data(self, trending_data: List[TrendingMetrics]) -> str:
        """Serialize trending data for cache storage."""
        try:
            serialized = []
            for metrics in trending_data:
                serialized.append(
                    {
                        "tool_id": metrics.tool_id,
                        "rank_position": metrics.rank_position,
                        "previous_rank": metrics.previous_rank,
                        "rank_change": metrics.rank_change,
                        "direction": metrics.direction,
                        "current_downloads": metrics.current_downloads,
                        "previous_downloads": metrics.previous_downloads,
                        "current_stars": metrics.current_stars,
                        "previous_stars": metrics.previous_stars,
                        "current_trust_score": metrics.current_trust_score,
                        "downloads_growth": metrics.downloads_growth,
                        "stars_growth": metrics.stars_growth,
                        "composite_score": metrics.composite_score,
                        "timeframe": metrics.timeframe,
                        "ecosystem": metrics.ecosystem,
                        "category": metrics.category,
                    }
                )

            cache_data = {
                "data": serialized,
                "cached_at": datetime.utcnow().isoformat(),
                "count": len(serialized),
            }

            return json.dumps(cache_data)

        except Exception as e:
            self.logger.error(f"Failed to serialize trending data: {e}")
            raise

    def _deserialize_trending_data(
        self, cached_data: str
    ) -> Optional[List[TrendingMetrics]]:
        """Deserialize trending data from cache."""
        try:
            cache_dict = json.loads(cached_data)

            trending_list = []
            for item in cache_dict.get("data", []):
                metrics = TrendingMetrics(
                    tool_id=item["tool_id"],
                    rank_position=item["rank_position"],
                    previous_rank=item.get("previous_rank"),
                    rank_change=item["rank_change"],
                    direction=item["direction"],
                    current_downloads=item["current_downloads"],
                    previous_downloads=item["previous_downloads"],
                    current_stars=item["current_stars"],
                    previous_stars=item["previous_stars"],
                    current_trust_score=item["current_trust_score"],
                    downloads_growth=item["downloads_growth"],
                    stars_growth=item["stars_growth"],
                    composite_score=item["composite_score"],
                    timeframe=item["timeframe"],
                    ecosystem=item["ecosystem"],
                    category=item["category"],
                )
                trending_list.append(metrics)

            self.logger.debug(
                f"Deserialized {len(trending_list)} trending tools from cache"
            )
            return trending_list

        except Exception as e:
            self.logger.warning(f"Failed to deserialize trending data: {e}")
            return None

    async def get_cached_trending(
        self, timeframe: TimeFrame, ecosystem: str, category: str, page: int = 1
    ) -> Optional[List[TrendingMetrics]]:
        """
        Get cached trending data if available.

        Returns None if no cache hit or cache is expired.
        """
        try:
            cache_key = self._build_cache_key(timeframe, ecosystem, category, page)
            cached_data = await cache.get(cache_key)

            if cached_data is None:
                self.logger.debug(f"Cache miss for key: {cache_key}")
                return None

            trending_data = self._deserialize_trending_data(cached_data)

            if trending_data is not None:
                self.logger.info(
                    f"Cache hit for {cache_key}: {len(trending_data)} tools "
                    f"(timeframe={timeframe}, ecosystem={ecosystem}, category={category})"
                )

            return trending_data

        except Exception as e:
            self.logger.error(f"Failed to get cached trending data: {e}")
            return None

    async def cache_trending_data(
        self,
        trending_data: List[TrendingMetrics],
        timeframe: TimeFrame,
        ecosystem: str,
        category: str,
        page: int = 1,
        ttl: Optional[int] = None,
    ) -> bool:
        """
        Cache trending data with specified TTL.

        Returns True if successfully cached, False otherwise.
        """
        try:
            if not trending_data:
                self.logger.warning("Attempted to cache empty trending data")
                return False

            cache_key = self._build_cache_key(timeframe, ecosystem, category, page)
            serialized_data = self._serialize_trending_data(trending_data)
            cache_ttl = ttl if ttl is not None else self.DEFAULT_TTL

            await cache.set(cache_key, serialized_data, ttl=cache_ttl)

            self.logger.info(
                f"Cached trending data: {cache_key} ({len(trending_data)} tools, TTL={cache_ttl}s)"
            )

            # Also store in database cache table for persistence
            await self._store_to_database_cache(
                cache_key, trending_data, timeframe, ecosystem, category, cache_ttl
            )

            return True

        except Exception as e:
            self.logger.error(f"Failed to cache trending data: {e}")
            return False

    async def _store_to_database_cache(
        self,
        cache_key: str,
        trending_data: List[TrendingMetrics],
        timeframe: TimeFrame,
        ecosystem: str,
        category: str,
        ttl: int,
    ) -> None:
        """Store trending data in database cache table for persistence."""
        try:
            from database import db

            # Calculate expiration time
            expires_at = datetime.utcnow() + timedelta(seconds=ttl)

            # Store each tool's trending data
            for metrics in trending_data:
                await db.execute(
                    """
                    MERGE forge_trending_cache AS target
                    USING (VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 
                        $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
                    )) AS source (
                        tool_id, timeframe, ecosystem, category, rank_position,
                        previous_rank, rank_change, growth_percentage, direction,
                        composite_score, downloads_current, downloads_previous,
                        downloads_growth, stars_current, stars_previous, 
                        stars_growth, trust_score_current, cache_key, expires_at,
                        created_at, updated_at
                    )
                    ON target.cache_key = source.cache_key AND target.tool_id = source.tool_id
                    WHEN MATCHED THEN
                        UPDATE SET
                            rank_position = source.rank_position,
                            previous_rank = source.previous_rank,
                            rank_change = source.rank_change,
                            growth_percentage = source.growth_percentage,
                            direction = source.direction,
                            composite_score = source.composite_score,
                            downloads_current = source.downloads_current,
                            downloads_previous = source.downloads_previous,
                            downloads_growth = source.downloads_growth,
                            stars_current = source.stars_current,
                            stars_previous = source.stars_previous,
                            stars_growth = source.stars_growth,
                            trust_score_current = source.trust_score_current,
                            expires_at = source.expires_at,
                            updated_at = GETUTCDATE()
                    WHEN NOT MATCHED THEN
                        INSERT (
                            tool_id, timeframe, ecosystem, category, rank_position,
                            previous_rank, rank_change, growth_percentage, direction,
                            composite_score, downloads_current, downloads_previous,
                            downloads_growth, stars_current, stars_previous,
                            stars_growth, trust_score_current, cache_key, expires_at
                        )
                        VALUES (
                            source.tool_id, source.timeframe, source.ecosystem, source.category,
                            source.rank_position, source.previous_rank, source.rank_change,
                            source.growth_percentage, source.direction, source.composite_score,
                            source.downloads_current, source.downloads_previous, source.downloads_growth,
                            source.stars_current, source.stars_previous, source.stars_growth,
                            source.trust_score_current, source.cache_key, source.expires_at
                        );
                """,
                    metrics.tool_id,
                    timeframe,
                    ecosystem,
                    category,
                    metrics.rank_position,
                    metrics.previous_rank,
                    metrics.rank_change,
                    metrics.downloads_growth,
                    metrics.direction,
                    metrics.composite_score,
                    metrics.current_downloads,
                    metrics.previous_downloads,
                    metrics.downloads_growth,
                    metrics.current_stars,
                    metrics.previous_stars,
                    metrics.stars_growth,
                    metrics.current_trust_score,
                    cache_key,
                    expires_at,
                    datetime.utcnow(),
                    datetime.utcnow(),
                )

            self.logger.debug(
                f"Stored {len(trending_data)} trending entries in database cache"
            )

        except Exception as e:
            self.logger.warning(f"Failed to store trending data in database cache: {e}")
            # Don't re-raise as this is not critical for functionality

    async def invalidate_trending_cache(
        self,
        timeframe: Optional[TimeFrame] = None,
        ecosystem: Optional[str] = None,
        category: Optional[str] = None,
    ) -> bool:
        """
        Invalidate cached trending data.

        If no parameters specified, clears all trending cache.
        """
        try:
            if timeframe is None and ecosystem is None and category is None:
                # Clear all trending cache
                pattern = f"{self.CACHE_KEY_PREFIX}:*"
            else:
                # Build specific pattern
                timeframe_part = timeframe or "*"
                ecosystem_part = ecosystem or "*"
                category_part = category or "*"
                pattern = f"{self.CACHE_KEY_PREFIX}:{timeframe_part}:{ecosystem_part}:{category_part}:*"

            # Try to delete from Redis if available
            if hasattr(cache, "_client") and cache._client is not None:
                try:
                    # Get keys matching pattern
                    keys = await cache._client.keys(pattern)
                    if keys:
                        await cache._client.delete(*keys)
                        self.logger.info(
                            f"Invalidated {len(keys)} cache keys matching pattern: {pattern}"
                        )
                except Exception as redis_error:
                    self.logger.warning(
                        f"Redis cache invalidation failed: {redis_error}"
                    )

            # Also clean up database cache
            from database import db

            if timeframe is None and ecosystem is None and category is None:
                # Delete all expired entries
                await db.execute(
                    "DELETE FROM forge_trending_cache WHERE expires_at < GETUTCDATE()"
                )
            else:
                # Delete specific entries
                conditions = []
                params = []

                if timeframe:
                    conditions.append("timeframe = $" + str(len(params) + 1))
                    params.append(timeframe)
                if ecosystem:
                    conditions.append("ecosystem = $" + str(len(params) + 1))
                    params.append(ecosystem)
                if category:
                    conditions.append("category = $" + str(len(params) + 1))
                    params.append(category)

                if conditions:
                    where_clause = " AND ".join(conditions)
                    await db.execute(
                        f"DELETE FROM forge_trending_cache WHERE {where_clause}",
                        *params,
                    )

            self.logger.info(f"Cache invalidation completed for pattern: {pattern}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to invalidate trending cache: {e}")
            return False

    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        try:
            from database import db

            # Get database cache stats
            db_stats = await db.fetchrow("""
                SELECT 
                    COUNT(*) as total_entries,
                    COUNT(CASE WHEN expires_at > GETUTCDATE() THEN 1 END) as active_entries,
                    COUNT(CASE WHEN expires_at <= GETUTCDATE() THEN 1 END) as expired_entries,
                    MIN(created_at) as oldest_entry,
                    MAX(created_at) as newest_entry
                FROM forge_trending_cache
            """)

            return {
                "database_cache": dict(db_stats) if db_stats else {},
                "redis_connected": cache._connected
                if hasattr(cache, "_connected")
                else False,
                "cache_key_prefix": self.CACHE_KEY_PREFIX,
                "default_ttl": self.DEFAULT_TTL,
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Failed to get cache stats: {e}")
            return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}


# Global cache service instance
trending_cache_service = TrendingCacheService()

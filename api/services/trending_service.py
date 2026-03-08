"""
Trending Calculation Service

Calculates trending scores and rankings for forge tools based on downloads,
stars, growth rates, and trust scores. Implements the composite scoring algorithm:
- 40% downloads weight
- 30% growth rate weight
- 20% stars weight
- 10% trust score weight

Performance target: <50ms for 1000 tools
"""

import logging
import time
from datetime import timedelta, date
from typing import Dict, List, Optional, Tuple, Literal
from dataclasses import dataclass

from database import get_database_client

logger = logging.getLogger(__name__)

TimeFrame = Literal["24h", "7d", "30d"]
TrendDirection = Literal["up", "down", "stable", "new"]


@dataclass
class TrendingMetrics:
    """Data class for trending calculation metrics."""

    tool_id: str
    current_downloads: int = 0
    previous_downloads: int = 0
    current_stars: int = 0
    previous_stars: int = 0
    current_trust_score: float = 0.0
    downloads_growth: float = 0.0
    stars_growth: float = 0.0
    composite_score: float = 0.0
    rank_position: int = 0
    previous_rank: Optional[int] = None
    rank_change: int = 0
    direction: TrendDirection = "stable"
    timeframe: TimeFrame = "7d"
    ecosystem: str = "all"
    category: str = "all"


class TrendingService:
    """Service for calculating trending tool rankings and scores."""

    # Composite score weights
    DOWNLOADS_WEIGHT = 0.40
    GROWTH_WEIGHT = 0.30
    STARS_WEIGHT = 0.20
    TRUST_WEIGHT = 0.10

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def _get_date_range(
        self, timeframe: TimeFrame, reference_date: Optional[date] = None
    ) -> Tuple[date, date]:
        """Get start and end dates for the given timeframe."""
        if reference_date is None:
            reference_date = date.today()

        if timeframe == "24h":
            start_date = reference_date - timedelta(days=1)
            end_date = reference_date
        elif timeframe == "7d":
            start_date = reference_date - timedelta(days=7)
            end_date = reference_date
        elif timeframe == "30d":
            start_date = reference_date - timedelta(days=30)
            end_date = reference_date
        else:
            raise ValueError(f"Invalid timeframe: {timeframe}")

        return start_date, end_date

    def _get_previous_date_range(
        self, timeframe: TimeFrame, reference_date: Optional[date] = None
    ) -> Tuple[date, date]:
        """Get the previous period date range for comparison."""
        if reference_date is None:
            reference_date = date.today()

        if timeframe == "24h":
            end_date = reference_date - timedelta(days=1)
            start_date = reference_date - timedelta(days=2)
        elif timeframe == "7d":
            end_date = reference_date - timedelta(days=7)
            start_date = reference_date - timedelta(days=14)
        elif timeframe == "30d":
            end_date = reference_date - timedelta(days=30)
            start_date = reference_date - timedelta(days=60)
        else:
            raise ValueError(f"Invalid timeframe: {timeframe}")

        return start_date, end_date

    async def _fetch_tool_metrics(
        self,
        timeframe: TimeFrame,
        ecosystem: str = "all",
        category: str = "all",
        limit: int = 1000,
    ) -> List[Dict]:
        """Fetch tool metrics for the specified timeframe and filters."""
        start_date, end_date = self._get_date_range(timeframe)
        prev_start_date, prev_end_date = self._get_previous_date_range(timeframe)

        try:
            async with get_database_client() as db:
                # Build dynamic WHERE clause for filters
                where_conditions = ["1=1"]
                params = [start_date, end_date, prev_start_date, prev_end_date]

                if ecosystem != "all":
                    where_conditions.append("ft.ecosystem = $" + str(len(params) + 1))
                    params.append(ecosystem)

                if category != "all":
                    where_conditions.append("ft.category = $" + str(len(params) + 1))
                    params.append(category)

                where_clause = " AND ".join(where_conditions)

                # Complex query to get current and previous metrics
                query = f"""
                WITH current_metrics AS (
                    SELECT 
                        ftm.tool_id,
                        AVG(ftm.downloads) as avg_downloads,
                        AVG(ftm.stars) as avg_stars,
                        AVG(ftm.trust_score) as avg_trust_score,
                        MAX(ftm.version) as latest_version
                    FROM forge_tool_metrics ftm
                    WHERE ftm.date BETWEEN $1 AND $2
                    GROUP BY ftm.tool_id
                ),
                previous_metrics AS (
                    SELECT 
                        ftm.tool_id,
                        AVG(ftm.downloads) as avg_downloads,
                        AVG(ftm.stars) as avg_stars,
                        AVG(ftm.trust_score) as avg_trust_score
                    FROM forge_tool_metrics ftm
                    WHERE ftm.date BETWEEN $3 AND $4
                    GROUP BY ftm.tool_id
                ),
                tool_info AS (
                    SELECT DISTINCT 
                        tool_id,
                        ecosystem,
                        category,
                        created_at
                    FROM forge_tools ft
                    WHERE {where_clause}
                )
                SELECT 
                    ti.tool_id,
                    ti.ecosystem,
                    ti.category,
                    ti.created_at,
                    COALESCE(cm.avg_downloads, 0) as current_downloads,
                    COALESCE(pm.avg_downloads, 0) as previous_downloads,
                    COALESCE(cm.avg_stars, 0) as current_stars,
                    COALESCE(pm.avg_stars, 0) as previous_stars,
                    COALESCE(cm.avg_trust_score, 0) as current_trust_score,
                    cm.latest_version
                FROM tool_info ti
                LEFT JOIN current_metrics cm ON ti.tool_id = cm.tool_id
                LEFT JOIN previous_metrics pm ON ti.tool_id = pm.tool_id
                WHERE cm.avg_downloads IS NOT NULL OR cm.avg_stars IS NOT NULL
                ORDER BY cm.avg_downloads DESC, cm.avg_stars DESC
                LIMIT {limit}
                """

                rows = await db.fetch(query, *params)
                return [dict(row) for row in rows] if rows else []

        except Exception as e:
            self.logger.error(f"Failed to fetch tool metrics: {e}")
            return []

    def _calculate_growth_rate(self, current: float, previous: float) -> float:
        """Calculate growth rate percentage."""
        if previous == 0:
            return 100.0 if current > 0 else 0.0

        if current == 0:
            return -100.0

        return ((current - previous) / previous) * 100.0

    def _normalize_metric(self, value: float, max_value: float) -> float:
        """Normalize a metric to 0-1 scale."""
        if max_value == 0:
            return 0.0
        return min(1.0, value / max_value)

    def _calculate_composite_score(
        self,
        downloads: int,
        downloads_growth: float,
        stars: int,
        trust_score: float,
        max_downloads: int,
        max_stars: int,
    ) -> float:
        """Calculate composite trending score using weighted formula."""

        # Normalize downloads (0-1 scale)
        downloads_norm = self._normalize_metric(downloads, max_downloads)

        # Normalize growth rate (-100% to +500% → 0-1 scale)
        growth_norm = max(0.0, min(1.0, (downloads_growth + 100) / 600))

        # Normalize stars (0-1 scale)
        stars_norm = self._normalize_metric(stars, max_stars)

        # Trust score is already 0-100, normalize to 0-1
        trust_norm = trust_score / 100.0

        # Calculate weighted composite score (0-100 scale)
        composite = (
            downloads_norm * self.DOWNLOADS_WEIGHT
            + growth_norm * self.GROWTH_WEIGHT
            + stars_norm * self.STARS_WEIGHT
            + trust_norm * self.TRUST_WEIGHT
        ) * 100.0

        return round(composite, 4)

    def _determine_trend_direction(
        self, growth_rate: float, rank_change: int, is_new_tool: bool = False
    ) -> TrendDirection:
        """Determine trend direction based on growth and rank changes."""
        if is_new_tool:
            return "new"

        if growth_rate >= 25.0 or rank_change > 0:
            return "up"
        elif growth_rate <= -25.0 or rank_change < 0:
            return "down"
        else:
            return "stable"

    async def _get_previous_rankings(
        self, timeframe: TimeFrame, ecosystem: str, category: str
    ) -> Dict[str, int]:
        """Get previous rankings for rank change calculation."""
        try:
            async with get_database_client() as db:
                # Look for cached rankings from previous period
                cache_key_pattern = f"forge:trending:{timeframe}:{ecosystem}:{category}"

                query = """
                SELECT tool_id, rank_position 
                FROM forge_trending_cache 
                WHERE cache_key LIKE $1 + '%'
                  AND expires_at > DATEADD(hour, -24, GETUTCDATE())
                  AND created_at < DATEADD(hour, -1, GETUTCDATE())
                ORDER BY created_at DESC
                """

                rows = await db.fetch(query, cache_key_pattern)
                return (
                    {row["tool_id"]: row["rank_position"] for row in rows}
                    if rows
                    else {}
                )

        except Exception as e:
            self.logger.error(f"Failed to fetch previous rankings: {e}")
            return {}

    async def calculate_trending_scores(
        self,
        timeframe: TimeFrame = "7d",
        ecosystem: str = "all",
        category: str = "all",
        limit: int = 100,
    ) -> List[TrendingMetrics]:
        """
        Calculate trending scores for tools.

        Returns list of TrendingMetrics sorted by composite score (highest first).
        Performance target: <50ms for 1000 tools.
        """
        start_time = time.time()

        try:
            # Fetch raw metrics
            metrics_data = await self._fetch_tool_metrics(
                timeframe, ecosystem, category, limit * 2
            )

            if not metrics_data:
                self.logger.warning(
                    f"No metrics data found for {timeframe}/{ecosystem}/{category}"
                )
                return []

            # Calculate max values for normalization
            max_downloads = max(
                (row["current_downloads"] for row in metrics_data), default=1
            )
            max_stars = max((row["current_stars"] for row in metrics_data), default=1)

            # Get previous rankings for rank change calculation
            previous_rankings = await self._get_previous_rankings(
                timeframe, ecosystem, category
            )

            # Calculate trending metrics
            trending_results = []

            for row in metrics_data:
                tool_id = row["tool_id"]
                current_downloads = int(row["current_downloads"])
                previous_downloads = int(row["previous_downloads"])
                current_stars = int(row["current_stars"])
                previous_stars = int(row["previous_stars"])
                trust_score = float(row["current_trust_score"])

                # Calculate growth rates
                downloads_growth = self._calculate_growth_rate(
                    current_downloads, previous_downloads
                )
                stars_growth = self._calculate_growth_rate(
                    current_stars, previous_stars
                )

                # Calculate composite score
                composite_score = self._calculate_composite_score(
                    current_downloads,
                    downloads_growth,
                    current_stars,
                    trust_score,
                    max_downloads,
                    max_stars,
                )

                # Check if tool is new (created within timeframe)
                created_at = row.get("created_at")
                is_new_tool = False
                if created_at:
                    start_date, _ = self._get_date_range(timeframe)
                    is_new_tool = created_at.date() >= start_date

                # Create trending metrics object
                metrics = TrendingMetrics(
                    tool_id=tool_id,
                    current_downloads=current_downloads,
                    previous_downloads=previous_downloads,
                    current_stars=current_stars,
                    previous_stars=previous_stars,
                    current_trust_score=trust_score,
                    downloads_growth=downloads_growth,
                    stars_growth=stars_growth,
                    composite_score=composite_score,
                    timeframe=timeframe,
                    ecosystem=ecosystem,
                    category=category,
                    previous_rank=previous_rankings.get(tool_id),
                )

                trending_results.append(metrics)

            # Sort by composite score (descending)
            trending_results.sort(key=lambda x: x.composite_score, reverse=True)

            # Assign ranks and calculate rank changes
            for i, metrics in enumerate(trending_results[:limit]):
                metrics.rank_position = i + 1

                if metrics.previous_rank:
                    metrics.rank_change = metrics.previous_rank - metrics.rank_position
                else:
                    metrics.rank_change = 0

                # Determine trend direction
                metrics.direction = self._determine_trend_direction(
                    metrics.downloads_growth, metrics.rank_change, is_new_tool
                )

            # Performance logging
            duration = (time.time() - start_time) * 1000  # Convert to ms
            self.logger.info(
                f"Calculated trending scores for {len(trending_results)} tools in {duration:.2f}ms "
                f"(timeframe={timeframe}, ecosystem={ecosystem}, category={category})"
            )

            if duration > 50:
                self.logger.warning(
                    f"Trending calculation exceeded 50ms target: {duration:.2f}ms"
                )

            return trending_results[:limit]

        except Exception as e:
            self.logger.error(f"Failed to calculate trending scores: {e}")
            return []

    async def get_trending_tools(
        self,
        timeframe: TimeFrame = "7d",
        ecosystem: str = "all",
        category: str = "all",
        limit: int = 20,
        use_cache: bool = True,
    ) -> List[TrendingMetrics]:
        """
        Get trending tools with optional caching.

        This is the main public API method for fetching trending data.
        """

        if use_cache:
            # Try to fetch from cache first (will be implemented in caching service)
            cached_results = await self._get_from_cache(
                timeframe, ecosystem, category, limit
            )
            if cached_results:
                return cached_results

        # Calculate fresh trending data
        trending_data = await self.calculate_trending_scores(
            timeframe, ecosystem, category, limit
        )

        if use_cache and trending_data:
            # Store in cache (will be implemented in caching service)
            await self._store_to_cache(trending_data, timeframe, ecosystem, category)

        return trending_data

    async def _get_from_cache(
        self, timeframe: TimeFrame, ecosystem: str, category: str, limit: int
    ) -> Optional[List[TrendingMetrics]]:
        """Fetch trending data from cache."""
        try:
            from services.trending_cache import trending_cache_service

            # Calculate page based on limit (assuming 20 items per page)
            page = 1  # For simplicity, always use page 1 for now

            cached_data = await trending_cache_service.get_cached_trending(
                timeframe, ecosystem, category, page
            )

            if cached_data:
                # Apply limit if needed
                return cached_data[:limit] if len(cached_data) > limit else cached_data

            return None

        except Exception as e:
            self.logger.warning(f"Cache fetch failed: {e}")
            return None

    async def _store_to_cache(
        self,
        trending_data: List[TrendingMetrics],
        timeframe: TimeFrame,
        ecosystem: str,
        category: str,
    ) -> bool:
        """Store trending data to cache."""
        try:
            from services.trending_cache import trending_cache_service

            # Calculate page based on data (assuming 20 items per page)
            page = 1  # For simplicity, always use page 1 for now

            success = await trending_cache_service.cache_trending_data(
                trending_data, timeframe, ecosystem, category, page
            )

            return success

        except Exception as e:
            self.logger.warning(f"Cache store failed: {e}")
            return False

    async def invalidate_cache(
        self,
        timeframe: Optional[TimeFrame] = None,
        ecosystem: Optional[str] = None,
        category: Optional[str] = None,
    ) -> bool:
        """Invalidate cached trending data."""
        try:
            from services.trending_cache import trending_cache_service

            return await trending_cache_service.invalidate_trending_cache(
                timeframe, ecosystem, category
            )

        except Exception as e:
            self.logger.error(f"Cache invalidation failed: {e}")
            return False

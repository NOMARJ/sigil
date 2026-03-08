"""
Unit Tests for Trending Service

Tests the trending calculation service logic, scoring algorithms,
and performance requirements.
"""

import pytest
from datetime import date, datetime, timedelta
from unittest.mock import AsyncMock, patch
from dataclasses import asdict

from api.services.trending_service import TrendingService, TrendingMetrics


class TestTrendingService:
    """Test suite for TrendingService."""

    @pytest.fixture
    def trending_service(self):
        """Create a TrendingService instance for testing."""
        return TrendingService()

    @pytest.fixture
    def mock_db_data(self):
        """Mock database data for testing."""
        return [
            {
                "tool_id": "tool1",
                "ecosystem": "npm",
                "category": "ai-agent",
                "created_at": datetime.now() - timedelta(days=30),
                "current_downloads": 1000,
                "previous_downloads": 500,
                "current_stars": 100,
                "previous_stars": 80,
                "current_trust_score": 85.0,
                "latest_version": "1.2.0",
            },
            {
                "tool_id": "tool2",
                "ecosystem": "pypi",
                "category": "mcp-server",
                "created_at": datetime.now() - timedelta(days=60),
                "current_downloads": 800,
                "previous_downloads": 900,
                "current_stars": 200,
                "previous_stars": 190,
                "current_trust_score": 92.0,
                "latest_version": "2.1.0",
            },
            {
                "tool_id": "tool3",
                "ecosystem": "npm",
                "category": "ai-agent",
                "created_at": datetime.now() - timedelta(days=5),  # New tool
                "current_downloads": 50,
                "previous_downloads": 0,
                "current_stars": 10,
                "previous_stars": 0,
                "current_trust_score": 45.0,
                "latest_version": "0.1.0",
            },
        ]

    def test_get_date_range(self, trending_service):
        """Test date range calculation for different timeframes."""
        test_date = date(2024, 3, 15)

        # Test 24h timeframe
        start, end = trending_service._get_date_range("24h", test_date)
        assert end == test_date
        assert start == test_date - timedelta(days=1)

        # Test 7d timeframe
        start, end = trending_service._get_date_range("7d", test_date)
        assert end == test_date
        assert start == test_date - timedelta(days=7)

        # Test 30d timeframe
        start, end = trending_service._get_date_range("30d", test_date)
        assert end == test_date
        assert start == test_date - timedelta(days=30)

    def test_get_previous_date_range(self, trending_service):
        """Test previous period date range calculation."""
        test_date = date(2024, 3, 15)

        # Test 7d previous period
        start, end = trending_service._get_previous_date_range("7d", test_date)
        assert end == test_date - timedelta(days=7)
        assert start == test_date - timedelta(days=14)

    def test_calculate_growth_rate(self, trending_service):
        """Test growth rate calculation."""
        # Normal growth
        assert trending_service._calculate_growth_rate(150, 100) == 50.0

        # Decline
        assert trending_service._calculate_growth_rate(75, 100) == -25.0

        # From zero (new)
        assert trending_service._calculate_growth_rate(100, 0) == 100.0

        # To zero (dead)
        assert trending_service._calculate_growth_rate(0, 100) == -100.0

        # No change
        assert trending_service._calculate_growth_rate(100, 100) == 0.0

    def test_normalize_metric(self, trending_service):
        """Test metric normalization."""
        # Normal case
        assert trending_service._normalize_metric(50, 100) == 0.5

        # Max value
        assert trending_service._normalize_metric(100, 100) == 1.0

        # Over max (should cap at 1.0)
        assert trending_service._normalize_metric(150, 100) == 1.0

        # Zero max (edge case)
        assert trending_service._normalize_metric(50, 0) == 0.0

    def test_calculate_composite_score(self, trending_service):
        """Test composite score calculation with weighted formula."""
        # Test with sample data
        score = trending_service._calculate_composite_score(
            downloads=500,
            downloads_growth=50.0,
            stars=100,
            trust_score=80.0,
            max_downloads=1000,
            max_stars=200,
        )

        # Expected calculation:
        # downloads_norm = 500/1000 = 0.5 → 0.5 * 0.4 = 0.2
        # growth_norm = (50 + 100) / 600 = 0.25 → 0.25 * 0.3 = 0.075
        # stars_norm = 100/200 = 0.5 → 0.5 * 0.2 = 0.1
        # trust_norm = 80/100 = 0.8 → 0.8 * 0.1 = 0.08
        # total = (0.2 + 0.075 + 0.1 + 0.08) * 100 = 45.5

        assert abs(score - 45.5) < 0.1

    def test_determine_trend_direction(self, trending_service):
        """Test trend direction determination."""
        # New tool
        assert (
            trending_service._determine_trend_direction(0, 0, is_new_tool=True) == "new"
        )

        # Strong growth
        assert (
            trending_service._determine_trend_direction(50.0, 5, is_new_tool=False)
            == "up"
        )

        # Strong decline
        assert (
            trending_service._determine_trend_direction(-50.0, -5, is_new_tool=False)
            == "down"
        )

        # Stable
        assert (
            trending_service._determine_trend_direction(10.0, 0, is_new_tool=False)
            == "stable"
        )

        # Rank improvement trumps low growth
        assert (
            trending_service._determine_trend_direction(5.0, 3, is_new_tool=False)
            == "up"
        )

    @pytest.mark.asyncio
    async def test_get_previous_rankings(self, trending_service):
        """Test previous rankings retrieval."""
        mock_rows = [
            {"tool_id": "tool1", "rank_position": 5},
            {"tool_id": "tool2", "rank_position": 10},
        ]

        with patch("services.trending_service.db") as mock_db:
            mock_db.execute_raw_sql = AsyncMock(return_value=mock_rows)

            rankings = await trending_service._get_previous_rankings("7d", "all", "all")

            assert rankings == {"tool1": 5, "tool2": 10}

    @pytest.mark.asyncio
    async def test_fetch_tool_metrics(self, trending_service, mock_db_data):
        """Test tool metrics fetching from database."""
        with patch("services.trending_service.db") as mock_db:
            mock_db.execute_raw_sql = AsyncMock(return_value=mock_db_data)

            metrics = await trending_service._fetch_tool_metrics(
                "7d", "all", "all", 100
            )

            assert len(metrics) == 3
            assert metrics[0]["tool_id"] == "tool1"
            assert metrics[0]["current_downloads"] == 1000

    @pytest.mark.asyncio
    async def test_calculate_trending_scores_performance(self, trending_service):
        """Test that trending calculation meets performance requirements."""
        # Mock a large dataset
        large_dataset = []
        for i in range(1000):
            large_dataset.append(
                {
                    "tool_id": f"tool{i}",
                    "ecosystem": "npm",
                    "category": "ai-agent",
                    "created_at": datetime.now() - timedelta(days=30),
                    "current_downloads": 100 + i,
                    "previous_downloads": 50 + i // 2,
                    "current_stars": 10 + i // 10,
                    "previous_stars": 5 + i // 20,
                    "current_trust_score": 50.0 + (i % 50),
                    "latest_version": "1.0.0",
                }
            )

        with patch.object(trending_service, "_fetch_tool_metrics") as mock_fetch:
            mock_fetch.return_value = large_dataset

            with patch.object(
                trending_service, "_get_previous_rankings"
            ) as mock_rankings:
                mock_rankings.return_value = {}

                import time

                start_time = time.time()

                results = await trending_service.calculate_trending_scores(
                    "7d", "all", "all", 100
                )

                duration = (time.time() - start_time) * 1000  # Convert to ms

                # Should complete in under 50ms for 1000 tools
                assert duration < 50, (
                    f"Performance requirement failed: {duration:.2f}ms > 50ms"
                )
                assert len(results) == 100  # Limited to requested amount
                assert results[0].rank_position == 1
                assert results[-1].rank_position == 100

    @pytest.mark.asyncio
    async def test_calculate_trending_scores_integration(
        self, trending_service, mock_db_data
    ):
        """Integration test for trending scores calculation."""
        with patch.object(trending_service, "_fetch_tool_metrics") as mock_fetch:
            # Filter mock data to only return npm tools as _fetch_tool_metrics would
            npm_tools = [tool for tool in mock_db_data if tool["ecosystem"] == "npm"]
            mock_fetch.return_value = npm_tools

            with patch.object(
                trending_service, "_get_previous_rankings"
            ) as mock_rankings:
                mock_rankings.return_value = {
                    "tool1": 3,
                    "tool2": 1,
                }  # Previous rankings

                results = await trending_service.calculate_trending_scores(
                    "7d", "npm", "all", 10
                )

                assert len(results) == 2  # Only npm tools in mock data

                # Verify ranking logic
                assert results[0].rank_position == 1
                assert results[1].rank_position == 2

                # Verify rank changes
                tool1_result = next(r for r in results if r.tool_id == "tool1")
                assert tool1_result.previous_rank == 3
                assert tool1_result.rank_change == 2  # Improved from 3 to 1

                # Verify growth calculations
                assert tool1_result.downloads_growth == 100.0  # 1000 vs 500
                assert abs(tool1_result.stars_growth - 25.0) < 0.1  # 100 vs 80

                # Verify trend directions
                assert tool1_result.direction == "up"  # Good growth + rank improvement

    @pytest.mark.asyncio
    async def test_get_trending_tools_no_cache(self, trending_service, mock_db_data):
        """Test get_trending_tools without caching."""
        with patch.object(trending_service, "calculate_trending_scores") as mock_calc:
            mock_trending = [
                TrendingMetrics(
                    tool_id="tool1",
                    composite_score=75.5,
                    rank_position=1,
                    direction="up",
                )
            ]
            mock_calc.return_value = mock_trending

            results = await trending_service.get_trending_tools(
                "7d", "all", "all", 20, use_cache=False
            )

            assert len(results) == 1
            assert results[0].tool_id == "tool1"
            assert results[0].rank_position == 1

            mock_calc.assert_called_once_with("7d", "all", "all", 20)

    def test_composite_score_weights(self, trending_service):
        """Test that composite score weights add up to 1.0."""
        total_weight = (
            trending_service.DOWNLOADS_WEIGHT
            + trending_service.GROWTH_WEIGHT
            + trending_service.STARS_WEIGHT
            + trending_service.TRUST_WEIGHT
        )

        assert abs(total_weight - 1.0) < 0.001, "Weights should sum to 1.0"

    def test_trending_metrics_dataclass(self):
        """Test TrendingMetrics dataclass functionality."""
        metrics = TrendingMetrics(
            tool_id="test-tool", current_downloads=100, composite_score=50.5
        )

        assert metrics.tool_id == "test-tool"
        assert metrics.current_downloads == 100
        assert metrics.composite_score == 50.5
        assert metrics.rank_position == 0  # Default value
        assert metrics.direction == "stable"  # Default value

        # Test conversion to dict
        metrics_dict = asdict(metrics)
        assert isinstance(metrics_dict, dict)
        assert metrics_dict["tool_id"] == "test-tool"


# Performance benchmark (can be run separately)
@pytest.mark.performance
@pytest.mark.asyncio
async def test_trending_performance_benchmark():
    """Benchmark test for trending calculation performance."""
    service = TrendingService()

    # Create large mock dataset
    large_dataset = []
    for i in range(10000):  # 10k tools
        large_dataset.append(
            {
                "tool_id": f"tool{i:05d}",
                "ecosystem": "npm" if i % 2 else "pypi",
                "category": f"category{i % 10}",
                "created_at": datetime.now() - timedelta(days=30),
                "current_downloads": 1000 - i,  # Descending to test sorting
                "previous_downloads": 500 - i // 2,
                "current_stars": 100 - i // 10,
                "previous_stars": 80 - i // 12,
                "current_trust_score": 90.0 - (i % 40),
                "latest_version": f"1.{i % 10}.0",
            }
        )

    with patch.object(service, "_fetch_tool_metrics") as mock_fetch:
        mock_fetch.return_value = large_dataset

        with patch.object(service, "_get_previous_rankings") as mock_rankings:
            mock_rankings.return_value = {}

            import time

            # Benchmark different result sizes
            for limit in [100, 500, 1000]:
                start_time = time.time()
                results = await service.calculate_trending_scores(
                    "7d", "all", "all", limit
                )
                duration = (time.time() - start_time) * 1000

                print(f"Trending calculation for {limit} results: {duration:.2f}ms")
                assert len(results) == limit
                assert duration < 100  # Even 1000 results should be under 100ms

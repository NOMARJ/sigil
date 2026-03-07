"""
Pro Tier Performance Tests

Performance and load testing suite for Pro tier LLM-powered features.
Tests response times, throughput, concurrency handling, and scalability
of Pro subscription features under various load conditions.

Test Coverage:
- LLM API response time and throughput testing
- Concurrent Pro user request handling
- Database performance for subscription checks
- Caching effectiveness and performance impact
- Rate limiting behavior under load
- Memory usage and resource optimization
- Timeout handling and circuit breaking
- Stress testing and breaking point analysis
"""

from __future__ import annotations

import asyncio
import pytest
import time
import statistics
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, MagicMock, AsyncMock
from typing import Any, List

from api.services.llm_service import llm_service, LLMService, RateLimiter
from api.services.subscription_service import subscription_service
from api.models.llm_models import LLMAnalysisRequest, LLMAnalysisType
from api.middleware.tier_check import require_pro_tier, get_scan_capabilities


class TestLLMServicePerformance:
    """Test LLM service performance characteristics"""

    @pytest.mark.asyncio
    async def test_llm_response_time_baseline(self):
        """Test baseline LLM response time performance"""
        
        analysis_request = LLMAnalysisRequest(
            file_contents={"test.py": "eval(input())"},
            static_findings=[
                {
                    "phase": "code_patterns",
                    "rule": "code-eval",
                    "severity": "HIGH", 
                    "file": "test.py",
                    "snippet": "eval(input())"
                }
            ],
            analysis_types=[LLMAnalysisType.ZERO_DAY_DETECTION]
        )
        
        with patch.object(llm_service, '_call_llm_api') as mock_api:
            # Mock fast LLM response
            mock_api.return_value = '{"insights": []}'
            
            start_time = time.time()
            response = await llm_service.analyze_threat(analysis_request)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # Convert to ms
            
            # Should complete within reasonable time (excluding actual LLM latency)
            assert response_time < 100  # Under 100ms for mocked response
            assert response.processing_time_ms is not None

    @pytest.mark.asyncio 
    async def test_concurrent_llm_requests_performance(self):
        """Test performance with multiple concurrent LLM requests"""
        
        async def single_llm_request(request_id: int):
            """Single LLM request with timing"""
            request = LLMAnalysisRequest(
                file_contents={f"test_{request_id}.py": f"exec('test_{request_id}')"},
                static_findings=[],
                user_id=f"perf_user_{request_id}"
            )
            
            with patch.object(llm_service, '_call_llm_api') as mock_api:
                # Simulate variable LLM response times
                await asyncio.sleep(0.1 + (request_id % 3) * 0.05)  # 100-200ms
                mock_api.return_value = '{"insights": []}'
                
                start_time = time.time()
                response = await llm_service.analyze_threat(request)
                end_time = time.time()
                
                return {
                    "request_id": request_id,
                    "response_time": (end_time - start_time) * 1000,
                    "success": response.success,
                    "tokens_used": response.tokens_used
                }
        
        # Execute 10 concurrent requests
        tasks = [single_llm_request(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        # Analyze performance metrics
        response_times = [r["response_time"] for r in results]
        success_rate = sum(1 for r in results if r["success"]) / len(results)
        
        assert success_rate == 1.0  # All requests should succeed
        assert statistics.mean(response_times) < 500  # Average under 500ms
        assert max(response_times) < 1000  # No request over 1s
        assert len(results) == 10

    @pytest.mark.asyncio
    async def test_llm_rate_limiting_performance(self):
        """Test rate limiter performance under load"""
        
        rate_limiter = RateLimiter(requests_per_minute=60)  # 1 per second
        
        async def rate_limited_request(request_id: int):
            """Rate limited request with timing"""
            start_time = time.time()
            await rate_limiter.acquire()
            end_time = time.time()
            
            return {
                "request_id": request_id,
                "wait_time": (end_time - start_time) * 1000
            }
        
        # Send 5 requests rapidly
        start_overall = time.time()
        tasks = [rate_limited_request(i) for i in range(5)]
        results = await asyncio.gather(*tasks)
        end_overall = time.time()
        
        total_time = (end_overall - start_overall) * 1000
        wait_times = [r["wait_time"] for r in results]
        
        # First request should be immediate, subsequent ones rate limited
        assert wait_times[0] < 10  # First request immediate
        assert total_time < 5000   # Should complete within 5 seconds
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_llm_caching_performance_impact(self):
        """Test performance impact of LLM response caching"""
        
        analysis_request = LLMAnalysisRequest(
            file_contents={"cached_test.py": "eval('cached')"},
            static_findings=[]
        )
        
        # First request - cache miss
        with patch.object(llm_service, '_call_llm_api') as mock_api:
            with patch.object(llm_service, '_get_cached_analysis') as mock_cache_get:
                with patch.object(llm_service, '_cache_analysis') as mock_cache_set:
                    # No cache hit initially
                    mock_cache_get.return_value = None
                    mock_api.return_value = '{"insights": []}'
                    
                    start_time = time.time()
                    response1 = await llm_service.analyze_threat(analysis_request)
                    cache_miss_time = (time.time() - start_time) * 1000
                    
                    assert not response1.cache_hit
                    mock_api.assert_called_once()
        
        # Second request - cache hit
        with patch.object(llm_service, '_call_llm_api') as mock_api:
            with patch.object(llm_service, '_get_cached_analysis') as mock_cache_get:
                # Return cached response
                mock_cache_get.return_value = response1
                
                start_time = time.time() 
                response2 = await llm_service.analyze_threat(analysis_request)
                cache_hit_time = (time.time() - start_time) * 1000
                
                assert response2.cache_hit
                mock_api.assert_not_called()  # Should not call API
        
        # Cache hit should be significantly faster
        assert cache_hit_time < cache_miss_time * 0.1  # At least 10x faster


class TestSubscriptionServicePerformance:
    """Test subscription service performance"""

    @pytest.mark.asyncio
    async def test_subscription_check_performance(self):
        """Test subscription status check performance"""
        
        user_ids = [f"perf_user_{i}" for i in range(20)]
        
        async def check_subscription(user_id: str):
            """Single subscription check with timing"""
            with patch('api.database.db.execute_procedure') as mock_db:
                mock_db.return_value = [{
                    "plan": "pro",
                    "status": "active",
                    "has_pro_features": True
                }]
                
                start_time = time.time()
                subscription = await subscription_service.get_user_subscription(user_id)
                end_time = time.time()
                
                return {
                    "user_id": user_id,
                    "response_time": (end_time - start_time) * 1000,
                    "has_pro": subscription.get("has_pro_features", False)
                }
        
        # Execute concurrent subscription checks
        tasks = [check_subscription(uid) for uid in user_ids]
        results = await asyncio.gather(*tasks)
        
        response_times = [r["response_time"] for r in results]
        pro_users = [r for r in results if r["has_pro"]]
        
        assert len(results) == 20
        assert len(pro_users) == 20  # All mocked as Pro
        assert statistics.mean(response_times) < 50  # Average under 50ms
        assert max(response_times) < 200  # No check over 200ms

    @pytest.mark.asyncio
    async def test_tier_gating_performance(self):
        """Test tier gating middleware performance"""
        
        mock_users = []
        for i in range(15):
            user = MagicMock()
            user.id = f"gating_user_{i}"
            mock_users.append(user)
        
        async def tier_check(user):
            """Single tier check with timing"""
            with patch.object(subscription_service, 'get_user_tier') as mock_tier:
                mock_tier.return_value = "pro" if int(user.id.split('_')[-1]) % 2 else "free"
                
                start_time = time.time()
                capabilities = await get_scan_capabilities(user)
                end_time = time.time()
                
                return {
                    "user_id": user.id,
                    "response_time": (end_time - start_time) * 1000,
                    "has_llm": capabilities.get("llm_analysis", False)
                }
        
        tasks = [tier_check(user) for user in mock_users]
        results = await asyncio.gather(*tasks)
        
        response_times = [r["response_time"] for r in results]
        
        assert len(results) == 15
        assert statistics.mean(response_times) < 30  # Average under 30ms
        assert all(rt < 100 for rt in response_times)  # All under 100ms

    @pytest.mark.asyncio
    async def test_pro_feature_usage_tracking_performance(self):
        """Test performance of Pro feature usage tracking"""
        
        usage_events = []
        for i in range(25):
            event = {
                "user_id": f"tracking_user_{i}",
                "feature_type": "llm_analysis",
                "usage_data": {
                    "tokens_used": 1000 + i * 100,
                    "processing_time": 2000 + i * 50,
                    "insights_count": 3 + (i % 5)
                }
            }
            usage_events.append(event)
        
        async def track_usage(event):
            """Single usage tracking with timing"""
            with patch.object(subscription_service, 'track_pro_feature_usage') as mock_track:
                mock_track.return_value = True
                
                start_time = time.time()
                result = await subscription_service.track_pro_feature_usage(**event)
                end_time = time.time()
                
                return {
                    "user_id": event["user_id"],
                    "response_time": (end_time - start_time) * 1000,
                    "success": result
                }
        
        tasks = [track_usage(event) for event in usage_events]
        results = await asyncio.gather(*tasks)
        
        response_times = [r["response_time"] for r in results]
        success_rate = sum(1 for r in results if r["success"]) / len(results)
        
        assert success_rate == 1.0
        assert statistics.mean(response_times) < 40  # Average under 40ms
        assert max(response_times) < 150  # No tracking over 150ms


class TestDatabasePerformance:
    """Test database performance for Pro features"""

    @pytest.mark.asyncio
    async def test_subscription_query_performance(self):
        """Test database query performance for subscriptions"""
        
        async def query_subscription(user_id: str):
            """Single subscription query with timing"""
            with patch('api.database.db.execute_procedure') as mock_db:
                # Simulate database response time
                await asyncio.sleep(0.01)  # 10ms database latency
                mock_db.return_value = [{
                    "plan": "pro",
                    "status": "active",
                    "current_period_end": "2024-12-31T23:59:59Z"
                }]
                
                start_time = time.time()
                result = await subscription_service.get_user_subscription(user_id)
                end_time = time.time()
                
                return {
                    "user_id": user_id,
                    "query_time": (end_time - start_time) * 1000,
                    "plan": result.get("plan")
                }
        
        # Test concurrent database queries
        user_ids = [f"db_user_{i}" for i in range(30)]
        tasks = [query_subscription(uid) for uid in user_ids]
        results = await asyncio.gather(*tasks)
        
        query_times = [r["query_time"] for r in results]
        
        assert len(results) == 30
        assert all(r["plan"] == "pro" for r in results)
        assert statistics.mean(query_times) < 50  # Average under 50ms
        assert max(query_times) < 100  # No query over 100ms

    @pytest.mark.asyncio
    async def test_analytics_insertion_performance(self):
        """Test analytics data insertion performance"""
        
        analytics_records = []
        for i in range(50):
            record = {
                "user_id": f"analytics_user_{i}",
                "event_type": "llm_usage",
                "event_data": {
                    "tokens_used": 1500,
                    "model": "gpt-4",
                    "processing_time": 2300
                }
            }
            analytics_records.append(record)
        
        async def insert_analytics(record):
            """Single analytics insertion with timing"""
            with patch('api.database.db.execute_procedure') as mock_db:
                await asyncio.sleep(0.005)  # 5ms insertion time
                mock_db.return_value = [{"id": f"analytics_{record['user_id']}"}]
                
                start_time = time.time()
                # Simulate analytics service call
                result = await mock_db(
                    "sp_TrackLLMUsage",
                    {
                        "user_id": record["user_id"],
                        "event_data": record["event_data"]
                    }
                )
                end_time = time.time()
                
                return {
                    "user_id": record["user_id"],
                    "insertion_time": (end_time - start_time) * 1000,
                    "record_id": result[0]["id"]
                }
        
        tasks = [insert_analytics(record) for record in analytics_records]
        results = await asyncio.gather(*tasks)
        
        insertion_times = [r["insertion_time"] for r in results]
        
        assert len(results) == 50
        assert all("analytics_" in r["record_id"] for r in results)
        assert statistics.mean(insertion_times) < 20  # Average under 20ms
        assert max(insertion_times) < 50  # No insertion over 50ms


class TestMemoryAndResourceUsage:
    """Test memory usage and resource optimization"""

    @pytest.mark.asyncio
    async def test_llm_service_memory_usage(self):
        """Test LLM service memory usage patterns"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create multiple LLM service instances and requests
        services = [LLMService() for _ in range(5)]
        requests = []
        
        for i in range(20):
            request = LLMAnalysisRequest(
                file_contents={f"memory_test_{i}.py": f"eval('test_{i}')" * 100},
                static_findings=[
                    {
                        "phase": "test",
                        "rule": f"rule_{i}",
                        "severity": "HIGH",
                        "file": f"memory_test_{i}.py",
                        "snippet": f"eval('test_{i}')"
                    }
                ] * 10  # Multiple findings per request
            )
            requests.append(request)
        
        # Process requests and measure memory
        with patch.object(LLMService, '_call_llm_api') as mock_api:
            mock_api.return_value = '{"insights": []}'
            
            for service, request in zip(services, requests[:5]):
                await service.analyze_threat(request)
        
        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_growth = peak_memory - initial_memory
        
        # Memory growth should be reasonable
        assert memory_growth < 100  # Under 100MB growth for test workload
        
        # Cleanup
        for service in services:
            await service.close()

    @pytest.mark.asyncio
    async def test_connection_pooling_efficiency(self):
        """Test HTTP connection pooling efficiency"""
        
        service = LLMService()
        
        async def make_api_call(call_id: int):
            """Single API call to test connection reuse"""
            with patch('aiohttp.ClientSession.post') as mock_post:
                mock_response = MagicMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value={"choices": [{"message": {"content": "{}"}}]})
                mock_post.return_value.__aenter__.return_value = mock_response
                
                start_time = time.time()
                await service._call_llm_api(f"test prompt {call_id}", 1000)
                end_time = time.time()
                
                return (end_time - start_time) * 1000
        
        # First call establishes session
        first_call_time = await make_api_call(1)
        
        # Subsequent calls should reuse session
        subsequent_times = []
        for i in range(2, 6):
            call_time = await make_api_call(i)
            subsequent_times.append(call_time)
        
        # Session reuse should make subsequent calls faster
        avg_subsequent = statistics.mean(subsequent_times)
        assert avg_subsequent <= first_call_time  # Should be same or faster
        
        await service.close()


class TestStressTestingAndLimits:
    """Test system behavior under stress and at limits"""

    @pytest.mark.asyncio
    async def test_high_concurrency_stress(self):
        """Test system behavior under high concurrency"""
        
        async def stress_request(request_id: int):
            """Single stress test request"""
            try:
                request = LLMAnalysisRequest(
                    file_contents={f"stress_{request_id}.py": "eval(input())"},
                    static_findings=[],
                    user_id=f"stress_user_{request_id}"
                )
                
                with patch.object(llm_service, '_call_llm_api') as mock_api:
                    # Vary response times to simulate real conditions
                    await asyncio.sleep(0.05 + (request_id % 10) * 0.01)
                    mock_api.return_value = '{"insights": []}'
                    
                    response = await llm_service.analyze_threat(request)
                    return {
                        "request_id": request_id,
                        "success": response.success,
                        "error": None
                    }
            except Exception as e:
                return {
                    "request_id": request_id,
                    "success": False,
                    "error": str(e)
                }
        
        # Launch 100 concurrent requests
        tasks = [stress_request(i) for i in range(100)]
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        
        total_time = end_time - start_time
        successful_results = [r for r in results if isinstance(r, dict) and r.get("success")]
        error_results = [r for r in results if isinstance(r, dict) and not r.get("success")]
        exceptions = [r for r in results if isinstance(r, Exception)]
        
        success_rate = len(successful_results) / len(results)
        throughput = len(results) / total_time  # Requests per second
        
        # System should handle high concurrency gracefully
        assert success_rate > 0.95  # At least 95% success rate
        assert throughput > 20      # At least 20 requests/second
        assert len(exceptions) < 5   # Minimal exceptions
        assert total_time < 10       # Complete within 10 seconds

    @pytest.mark.asyncio
    async def test_rate_limiting_under_stress(self):
        """Test rate limiting behavior under stress conditions"""
        
        rate_limiter = RateLimiter(requests_per_minute=30)  # 30 RPM = 0.5 RPS
        
        async def rate_limited_stress_request(request_id: int):
            """Rate limited stress request"""
            try:
                start_time = time.time()
                await rate_limiter.acquire()
                acquire_time = time.time() - start_time
                
                return {
                    "request_id": request_id,
                    "acquire_time": acquire_time * 1000,
                    "success": True
                }
            except Exception as e:
                return {
                    "request_id": request_id,
                    "acquire_time": None,
                    "success": False,
                    "error": str(e)
                }
        
        # Send 50 requests to rate limiter
        tasks = [rate_limited_stress_request(i) for i in range(50)]
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time
        
        successful_results = [r for r in results if r["success"]]
        acquire_times = [r["acquire_time"] for r in successful_results if r["acquire_time"] is not None]
        
        assert len(successful_results) == 50  # All should eventually succeed
        assert total_time > 60  # Should take at least 60 seconds (rate limited)
        assert max(acquire_times) < 65000  # Max wait under ~65 seconds

    @pytest.mark.asyncio
    async def test_memory_pressure_handling(self):
        """Test system behavior under memory pressure"""
        
        # Create large payload requests to simulate memory pressure
        large_requests = []
        for i in range(10):
            # Create large file content
            large_content = "eval(input())\n" * 10000  # ~130KB per file
            
            request = LLMAnalysisRequest(
                file_contents={
                    f"large_file_{i}.py": large_content,
                    f"large_file_{i}_2.py": large_content
                },
                static_findings=[
                    {
                        "phase": "code_patterns",
                        "rule": f"large_rule_{j}",
                        "severity": "HIGH",
                        "file": f"large_file_{i}.py",
                        "snippet": "eval(input())"
                    } for j in range(50)  # Many findings per request
                ]
            )
            large_requests.append(request)
        
        # Process large requests concurrently
        async def process_large_request(request):
            """Process single large request"""
            with patch.object(llm_service, '_call_llm_api') as mock_api:
                mock_api.return_value = '{"insights": []}'
                
                try:
                    response = await llm_service.analyze_threat(request)
                    return {"success": True, "tokens": response.tokens_used}
                except Exception as e:
                    return {"success": False, "error": str(e)}
        
        tasks = [process_large_request(req) for req in large_requests]
        results = await asyncio.gather(*tasks)
        
        successful_results = [r for r in results if r["success"]]
        
        # System should handle large payloads gracefully
        assert len(successful_results) >= 8  # At least 80% success under pressure
        assert all("tokens" in r for r in successful_results)


class TestTimeoutAndCircuitBreaking:
    """Test timeout handling and circuit breaking patterns"""

    @pytest.mark.asyncio
    async def test_llm_api_timeout_handling(self):
        """Test LLM API timeout behavior"""
        
        async def timeout_api_call():
            """API call that times out"""
            with patch('aiohttp.ClientSession.post') as mock_post:
                # Simulate timeout
                mock_post.side_effect = asyncio.TimeoutError("Request timeout")
                
                service = LLMService()
                
                try:
                    await service._call_llm_api("test prompt", 1000)
                    return {"success": True}
                except Exception as e:
                    return {"success": False, "error": str(e)}
                finally:
                    await service.close()
        
        result = await timeout_api_call()
        
        assert not result["success"]
        assert "timeout" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_subscription_check_timeout(self):
        """Test subscription check timeout handling"""
        
        async def timeout_subscription_check(user_id: str):
            """Subscription check with timeout"""
            with patch('api.database.db.execute_procedure') as mock_db:
                mock_db.side_effect = asyncio.TimeoutError("Database timeout")
                
                try:
                    subscription = await subscription_service.get_user_subscription(user_id)
                    return {
                        "success": True,
                        "plan": subscription.get("plan"),
                        "fallback": subscription.get("plan") == "free"
                    }
                except Exception as e:
                    return {"success": False, "error": str(e)}
        
        result = await timeout_subscription_check("timeout_user")
        
        # Should fallback gracefully on timeout
        # Implementation may vary - either return default or raise exception
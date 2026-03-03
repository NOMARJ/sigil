"""
Redis Cache Performance Testing for Forge Premium Features
Tests cache hit rates, response times, and memory efficiency
"""

import asyncio
import json
import time
import random
from datetime import datetime
from typing import Dict, Optional
import redis.asyncio as redis
from dataclasses import dataclass


@dataclass
class CacheMetrics:
    """Cache performance metrics"""
    hits: int = 0
    misses: int = 0
    total_requests: int = 0
    avg_hit_time_ms: float = 0.0
    avg_miss_time_ms: float = 0.0
    memory_used_mb: float = 0.0
    keys_count: int = 0
    evictions: int = 0


class RedisCachePerformanceTester:
    """Test Redis cache performance for Forge features"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis_client: Optional[redis.Redis] = None
        self.metrics = CacheMetrics()
        self.test_results = []
        
        # Cache key patterns used by Forge
        self.cache_patterns = {
            "user_tools": "forge:user:{user_id}:tools",
            "analytics_personal": "forge:analytics:user:{user_id}:{period}",
            "analytics_team": "forge:analytics:team:{team_id}:{period}",
            "tool_details": "forge:tool:{tool_id}",
            "recommendations": "forge:recommendations:{user_id}",
            "search_results": "forge:search:{query_hash}",
            "public_stacks": "forge:stacks:public:{page}",
        }
    
    async def setup(self):
        """Initialize Redis connection"""
        self.redis_client = await redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True
        )
        
        # Clear test namespace
        await self.cleanup_test_data()
    
    async def cleanup_test_data(self):
        """Clean up test data from Redis"""
        if self.redis_client:
            keys = await self.redis_client.keys("forge:test:*")
            if keys:
                await self.redis_client.delete(*keys)
    
    async def teardown(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.cleanup_test_data()
            await self.redis_client.close()
    
    async def measure_operation(self, operation_name: str, operation_func):
        """Measure the time taken for a cache operation"""
        start_time = time.perf_counter()
        result = await operation_func()
        duration_ms = (time.perf_counter() - start_time) * 1000
        
        self.test_results.append({
            "operation": operation_name,
            "duration_ms": duration_ms,
            "timestamp": datetime.now().isoformat()
        })
        
        return result, duration_ms
    
    async def test_cache_operations(self):
        """Test basic cache operations performance"""
        print("\n=== REDIS CACHE PERFORMANCE TESTING ===\n")
        print("Testing basic cache operations...\n")
        
        test_data = {
            "tools": [{"id": f"tool-{i}", "name": f"Tool {i}"} for i in range(100)],
            "analytics": {"views": 1000, "users": 50, "events": [1, 2, 3] * 100},
            "large_data": {"items": [{"data": "x" * 1000} for _ in range(100)]}
        }
        
        # Test SET operations
        print("Testing SET operations:")
        set_times = []
        for i in range(100):
            key = f"forge:test:item:{i}"
            value = json.dumps(test_data["tools"][i % len(test_data["tools"])])
            
            _, duration = await self.measure_operation(
                "SET",
                lambda k=key, v=value: self.redis_client.setex(k, 300, v)
            )
            set_times.append(duration)
        
        avg_set_time = sum(set_times) / len(set_times)
        print(f"  Average SET time: {avg_set_time:.2f}ms")
        print(f"  Min SET time: {min(set_times):.2f}ms")
        print(f"  Max SET time: {max(set_times):.2f}ms")
        
        # Test GET operations (cache hits)
        print("\nTesting GET operations (cache hits):")
        get_times = []
        for i in range(100):
            key = f"forge:test:item:{i}"
            
            _, duration = await self.measure_operation(
                "GET",
                lambda k=key: self.redis_client.get(k)
            )
            get_times.append(duration)
            self.metrics.hits += 1
        
        avg_get_time = sum(get_times) / len(get_times)
        print(f"  Average GET time: {avg_get_time:.2f}ms")
        print(f"  Min GET time: {min(get_times):.2f}ms")
        print(f"  Max GET time: {max(get_times):.2f}ms")
        
        # Test cache misses
        print("\nTesting cache misses:")
        miss_times = []
        for i in range(20):
            key = f"forge:test:missing:{i}"
            
            _, duration = await self.measure_operation(
                "GET_MISS",
                lambda k=key: self.redis_client.get(k)
            )
            miss_times.append(duration)
            self.metrics.misses += 1
        
        avg_miss_time = sum(miss_times) / len(miss_times) if miss_times else 0
        print(f"  Average miss time: {avg_miss_time:.2f}ms")
        
        # Test batch operations
        print("\nTesting batch operations:")
        keys = [f"forge:test:item:{i}" for i in range(50)]
        
        _, mget_duration = await self.measure_operation(
            "MGET",
            lambda k=keys: self.redis_client.mget(k)
        )
        print(f"  MGET 50 keys: {mget_duration:.2f}ms")
        
        # Test pipeline operations
        print("\nTesting pipeline operations:")
        start_time = time.perf_counter()
        async with self.redis_client.pipeline() as pipe:
            for i in range(100):
                pipe.set(f"forge:test:pipeline:{i}", f"value-{i}")
            await pipe.execute()
        pipeline_duration = (time.perf_counter() - start_time) * 1000
        print(f"  Pipeline 100 SETs: {pipeline_duration:.2f}ms")
    
    async def test_forge_cache_patterns(self):
        """Test Forge-specific cache patterns"""
        print("\n=== FORGE CACHE PATTERNS TESTING ===\n")
        
        # Test user tools caching
        print("Testing user tools caching:")
        user_id = "test-user-123"
        tools_key = self.cache_patterns["user_tools"].format(user_id=user_id)
        
        # Simulate cache miss (database fetch)
        start_time = time.perf_counter()
        tools_data = await self.simulate_database_fetch("user_tools", delay_ms=50)
        await self.redis_client.setex(
            tools_key,
            300,  # 5 minute TTL
            json.dumps(tools_data)
        )
        miss_time = (time.perf_counter() - start_time) * 1000
        print(f"  Cache miss (with DB fetch): {miss_time:.2f}ms")
        
        # Simulate cache hit
        start_time = time.perf_counter()
        cached_data = await self.redis_client.get(tools_key)
        if cached_data:
            json.loads(cached_data)
        hit_time = (time.perf_counter() - start_time) * 1000
        print(f"  Cache hit: {hit_time:.2f}ms")
        print(f"  Speedup: {miss_time/hit_time:.1f}x")
        
        # Test analytics caching
        print("\nTesting analytics caching:")
        analytics_key = self.cache_patterns["analytics_personal"].format(
            user_id=user_id,
            period="day"
        )
        
        # Complex analytics data
        analytics_data = {
            "period": "day",
            "metrics": {
                "tool_usage": [{"hour": i, "count": random.randint(0, 100)} for i in range(24)],
                "categories": {"database": 45, "api": 30, "security": 25},
                "top_tools": [f"tool-{i}" for i in range(10)]
            }
        }
        
        # Test with different cache strategies
        await self.test_cache_strategy(
            "Analytics with TTL",
            analytics_key,
            analytics_data,
            ttl=60  # 1 minute for frequently changing data
        )
        
        # Test search results caching
        print("\nTesting search results caching:")
        search_query = "database postgresql"
        query_hash = hash(search_query)
        search_key = self.cache_patterns["search_results"].format(query_hash=query_hash)
        
        search_results = {
            "query": search_query,
            "results": [{"id": f"tool-{i}", "score": random.random()} for i in range(20)],
            "total": 45
        }
        
        await self.test_cache_strategy(
            "Search results",
            search_key,
            search_results,
            ttl=300  # 5 minutes for search results
        )
    
    async def test_cache_strategy(self, name: str, key: str, data: Dict, ttl: int):
        """Test a specific cache strategy"""
        # Set data with TTL
        start_time = time.perf_counter()
        await self.redis_client.setex(key, ttl, json.dumps(data))
        set_time = (time.perf_counter() - start_time) * 1000
        
        # Get data
        start_time = time.perf_counter()
        await self.redis_client.get(key)
        get_time = (time.perf_counter() - start_time) * 1000
        
        # Check TTL
        remaining_ttl = await self.redis_client.ttl(key)
        
        print(f"  {name}:")
        print(f"    SET time: {set_time:.2f}ms")
        print(f"    GET time: {get_time:.2f}ms")
        print(f"    TTL remaining: {remaining_ttl}s")
        print(f"    Data size: {len(json.dumps(data))} bytes")
    
    async def simulate_database_fetch(self, data_type: str, delay_ms: int = 50) -> Dict:
        """Simulate a database fetch with delay"""
        await asyncio.sleep(delay_ms / 1000)
        
        if data_type == "user_tools":
            return [{"id": f"tool-{i}", "name": f"Tool {i}"} for i in range(20)]
        elif data_type == "analytics":
            return {"views": random.randint(100, 1000), "events": random.randint(50, 500)}
        else:
            return {"data": "mock"}
    
    async def test_cache_invalidation(self):
        """Test cache invalidation strategies"""
        print("\n=== CACHE INVALIDATION TESTING ===\n")
        
        # Test pattern-based invalidation
        print("Testing pattern-based invalidation:")
        
        # Create multiple related keys
        user_id = "test-user-456"
        keys_created = []
        
        for period in ["day", "week", "month"]:
            key = f"forge:analytics:user:{user_id}:{period}"
            await self.redis_client.set(key, json.dumps({"period": period}))
            keys_created.append(key)
        
        print(f"  Created {len(keys_created)} related keys")
        
        # Invalidate all analytics for the user
        start_time = time.perf_counter()
        pattern = f"forge:analytics:user:{user_id}:*"
        keys_to_delete = await self.redis_client.keys(pattern)
        if keys_to_delete:
            await self.redis_client.delete(*keys_to_delete)
        invalidation_time = (time.perf_counter() - start_time) * 1000
        
        print(f"  Invalidated {len(keys_to_delete)} keys in {invalidation_time:.2f}ms")
        
        # Test tag-based invalidation using sets
        print("\nTesting tag-based invalidation:")
        
        # Create keys with tags
        tool_id = "postgres-mcp"
        tag_set_key = f"forge:tags:tool:{tool_id}"
        
        related_keys = [
            f"forge:tool:{tool_id}:details",
            f"forge:tool:{tool_id}:users",
            f"forge:tool:{tool_id}:analytics"
        ]
        
        for key in related_keys:
            await self.redis_client.set(key, json.dumps({"tool": tool_id}))
            await self.redis_client.sadd(tag_set_key, key)
        
        # Invalidate all keys with the tag
        start_time = time.perf_counter()
        tagged_keys = await self.redis_client.smembers(tag_set_key)
        if tagged_keys:
            await self.redis_client.delete(*tagged_keys)
            await self.redis_client.delete(tag_set_key)
        tag_invalidation_time = (time.perf_counter() - start_time) * 1000
        
        print(f"  Invalidated {len(tagged_keys)} tagged keys in {tag_invalidation_time:.2f}ms")
    
    async def test_concurrent_access(self):
        """Test cache performance under concurrent access"""
        print("\n=== CONCURRENT ACCESS TESTING ===\n")
        
        async def concurrent_operation(op_id: int):
            """Simulate a concurrent cache operation"""
            key = f"forge:test:concurrent:{op_id % 10}"  # 10 unique keys
            
            # 70% reads, 30% writes (typical cache pattern)
            if random.random() < 0.7:
                # Read operation
                start = time.perf_counter()
                value = await self.redis_client.get(key)
                duration = (time.perf_counter() - start) * 1000
                
                if value:
                    return ("hit", duration)
                else:
                    # Simulate cache miss with DB fetch
                    data = await self.simulate_database_fetch("user_tools", delay_ms=20)
                    await self.redis_client.setex(key, 300, json.dumps(data))
                    return ("miss", duration + 20)
            else:
                # Write operation
                start = time.perf_counter()
                await self.redis_client.setex(
                    key,
                    300,
                    json.dumps({"updated": op_id})
                )
                duration = (time.perf_counter() - start) * 1000
                return ("write", duration)
        
        # Test with different concurrency levels
        for num_concurrent in [10, 50, 100, 200]:
            print(f"Testing with {num_concurrent} concurrent operations:")
            
            start_time = time.perf_counter()
            tasks = [concurrent_operation(i) for i in range(num_concurrent)]
            results = await asyncio.gather(*tasks)
            total_time = (time.perf_counter() - start_time) * 1000
            
            hits = sum(1 for r, _ in results if r == "hit")
            misses = sum(1 for r, _ in results if r == "miss")
            writes = sum(1 for r, _ in results if r == "write")
            
            avg_duration = sum(d for _, d in results) / len(results)
            
            print(f"  Total time: {total_time:.2f}ms")
            print(f"  Hits: {hits}, Misses: {misses}, Writes: {writes}")
            print(f"  Average operation time: {avg_duration:.2f}ms")
            print(f"  Throughput: {num_concurrent / (total_time/1000):.0f} ops/sec\n")
    
    async def test_memory_efficiency(self):
        """Test memory usage and efficiency"""
        print("\n=== MEMORY EFFICIENCY TESTING ===\n")
        
        # Get initial memory stats
        info = await self.redis_client.info("memory")
        initial_memory = info["used_memory"] / (1024 * 1024)  # Convert to MB
        
        print(f"Initial memory usage: {initial_memory:.2f}MB")
        
        # Store different data structures
        test_cases = [
            {
                "name": "JSON strings",
                "count": 1000,
                "create": lambda i: json.dumps({"id": i, "data": "x" * 100})
            },
            {
                "name": "Hash maps",
                "count": 1000,
                "create": lambda i: {"field": f"value-{i}"}
            },
            {
                "name": "Lists",
                "count": 100,
                "create": lambda i: [f"item-{j}" for j in range(100)]
            }
        ]
        
        for test_case in test_cases:
            print(f"\nTesting {test_case['name']}:")
            
            # Clear previous test data
            await self.cleanup_test_data()
            
            # Store data
            for i in range(test_case["count"]):
                key = f"forge:test:memory:{i}"
                data = test_case["create"](i)
                
                if isinstance(data, dict) and not test_case["name"].startswith("JSON"):
                    await self.redis_client.hset(key, mapping=data)
                elif isinstance(data, list):
                    await self.redis_client.rpush(key, *data)
                else:
                    await self.redis_client.set(key, data)
            
            # Get memory stats after storing
            info = await self.redis_client.info("memory")
            current_memory = info["used_memory"] / (1024 * 1024)
            memory_used = current_memory - initial_memory
            
            print(f"  Items stored: {test_case['count']}")
            print(f"  Memory used: {memory_used:.2f}MB")
            print(f"  Average per item: {memory_used / test_case['count'] * 1024:.2f}KB")
    
    async def calculate_metrics(self):
        """Calculate overall cache metrics"""
        self.metrics.total_requests = self.metrics.hits + self.metrics.misses
        
        if self.metrics.total_requests > 0:
            hit_rate = (self.metrics.hits / self.metrics.total_requests) * 100
        else:
            hit_rate = 0
        
        # Get Redis stats
        info = await self.redis_client.info()
        self.metrics.memory_used_mb = info["used_memory"] / (1024 * 1024)
        self.metrics.keys_count = await self.redis_client.dbsize()
        self.metrics.evictions = info.get("evicted_keys", 0)
        
        # Calculate average times from test results
        hit_times = [r["duration_ms"] for r in self.test_results if "GET" in r["operation"]]
        miss_times = [r["duration_ms"] for r in self.test_results if "MISS" in r["operation"]]
        
        if hit_times:
            self.metrics.avg_hit_time_ms = sum(hit_times) / len(hit_times)
        if miss_times:
            self.metrics.avg_miss_time_ms = sum(miss_times) / len(miss_times)
        
        return hit_rate
    
    def generate_report(self, hit_rate: float) -> Dict:
        """Generate comprehensive cache performance report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "hit_rate": hit_rate,
                "total_requests": self.metrics.total_requests,
                "hits": self.metrics.hits,
                "misses": self.metrics.misses,
                "avg_hit_time_ms": self.metrics.avg_hit_time_ms,
                "avg_miss_time_ms": self.metrics.avg_miss_time_ms,
                "memory_used_mb": self.metrics.memory_used_mb,
                "keys_count": self.metrics.keys_count,
                "evictions": self.metrics.evictions
            },
            "performance_goals": {
                "hit_rate_target": 90,
                "hit_rate_achieved": hit_rate >= 90,
                "response_time_target_ms": 5,
                "response_time_achieved": self.metrics.avg_hit_time_ms < 5
            },
            "recommendations": []
        }
        
        # Generate recommendations
        if hit_rate < 90:
            report["recommendations"].append({
                "priority": "HIGH",
                "issue": f"Cache hit rate ({hit_rate:.1f}%) below target (90%)",
                "action": "Review cache TTL values and invalidation strategy"
            })
        
        if self.metrics.avg_hit_time_ms > 5:
            report["recommendations"].append({
                "priority": "MEDIUM",
                "issue": f"Cache response time ({self.metrics.avg_hit_time_ms:.2f}ms) above target (5ms)",
                "action": "Consider Redis cluster or connection pooling"
            })
        
        if self.metrics.evictions > 0:
            report["recommendations"].append({
                "priority": "HIGH",
                "issue": f"Cache evictions detected ({self.metrics.evictions})",
                "action": "Increase Redis memory limit or optimize data structures"
            })
        
        if self.metrics.memory_used_mb > 100:
            report["recommendations"].append({
                "priority": "MEDIUM",
                "issue": f"High memory usage ({self.metrics.memory_used_mb:.2f}MB)",
                "action": "Review data serialization and consider compression"
            })
        
        return report


async def main():
    """Run Redis cache performance tests"""
    tester = RedisCachePerformanceTester()
    
    try:
        await tester.setup()
        
        # Run all tests
        await tester.test_cache_operations()
        await tester.test_forge_cache_patterns()
        await tester.test_cache_invalidation()
        await tester.test_concurrent_access()
        await tester.test_memory_efficiency()
        
        # Calculate metrics
        hit_rate = await tester.calculate_metrics()
        
        # Generate report
        report = tester.generate_report(hit_rate)
        
        print("\n" + "="*60)
        print("REDIS CACHE PERFORMANCE SUMMARY")
        print("="*60)
        print(f"Cache Hit Rate: {hit_rate:.1f}%")
        print(f"Average Hit Time: {tester.metrics.avg_hit_time_ms:.2f}ms")
        print(f"Average Miss Time: {tester.metrics.avg_miss_time_ms:.2f}ms")
        print(f"Memory Usage: {tester.metrics.memory_used_mb:.2f}MB")
        print(f"Total Keys: {tester.metrics.keys_count}")
        
        if report["performance_goals"]["hit_rate_achieved"] and \
           report["performance_goals"]["response_time_achieved"]:
            print("\n✓ All performance goals achieved!")
        else:
            print("\n⚠️  Some performance goals not met:")
            for rec in report["recommendations"]:
                print(f"  - {rec['issue']}")
        
        # Save report
        with open("redis_performance_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print("\nDetailed report saved to: redis_performance_report.json")
        
    finally:
        await tester.teardown()


if __name__ == "__main__":
    asyncio.run(main())
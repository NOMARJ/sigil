#!/usr/bin/env python3
"""
Sigil Forge Performance Analysis Tool

Comprehensive performance testing and analysis of Forge API endpoints.
Includes load testing, query profiling, and optimization recommendations.
"""

import asyncio
import time
import json
import random
import statistics
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
import httpx
import psutil
import tracemalloc
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

@dataclass
class PerformanceMetrics:
    """Container for performance test results."""
    endpoint: str
    method: str = "GET"
    
    # Response time metrics (ms)
    min_time: float = 0
    max_time: float = 0
    avg_time: float = 0
    median_time: float = 0
    p95_time: float = 0
    p99_time: float = 0
    
    # Throughput metrics
    requests_per_second: float = 0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    
    # Resource metrics
    avg_memory_mb: float = 0
    peak_memory_mb: float = 0
    avg_cpu_percent: float = 0
    
    # Database metrics
    db_queries_per_request: float = 0
    avg_db_time_ms: float = 0
    
    # Additional data
    response_times: List[float] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


class ForgePerformanceAnalyzer:
    """Performance testing and analysis for Forge APIs."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.metrics: Dict[str, PerformanceMetrics] = {}
        self.test_data = self._generate_test_data()
        
    def _generate_test_data(self) -> Dict[str, Any]:
        """Generate test data for various endpoints."""
        return {
            "search_queries": [
                "postgres", "database", "github", "api", "file", 
                "ai", "llm", "test", "security", "monitoring",
                "redis", "mongodb", "stripe", "slack", "docker"
            ],
            "ecosystems": ["clawhub", "mcp", "npm", "pypi"],
            "categories": [
                "Database", "API Integration", "Code Tools", "File System",
                "AI/LLM", "Security", "DevOps", "Communication", "Data Pipeline",
                "Testing", "Search", "Monitoring"
            ],
            "packages": [
                ("clawhub", "github-skill"),
                ("mcp", "postgres-mcp"),
                ("npm", "express"),
                ("pypi", "requests")
            ],
            "use_cases": [
                "Building a PostgreSQL-backed AI agent",
                "GitHub repository analysis and code review",
                "Web research and content extraction",
                "API integration testing",
                "File system operations and search"
            ]
        }
    
    async def test_endpoint(
        self, 
        endpoint: str, 
        method: str = "GET",
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        num_requests: int = 100,
        concurrent: int = 10
    ) -> PerformanceMetrics:
        """Test a single endpoint with multiple requests."""
        
        metrics = PerformanceMetrics(endpoint=endpoint, method=method)
        response_times = []
        errors = []
        
        # Start resource monitoring
        process = psutil.Process()
        tracemalloc.start()
        
        start_time = time.time()
        
        async with httpx.AsyncClient(timeout=30) as client:
            # Create concurrent request tasks
            tasks = []
            for i in range(num_requests):
                if method == "GET":
                    task = client.get(f"{self.base_url}{endpoint}", params=params)
                elif method == "POST":
                    task = client.post(f"{self.base_url}{endpoint}", json=json_data)
                else:
                    task = client.request(method, f"{self.base_url}{endpoint}", params=params, json=json_data)
                tasks.append(task)
                
                # Control concurrency
                if len(tasks) >= concurrent or i == num_requests - 1:
                    # Execute batch of requests
                    batch_start = time.time()
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for response in responses:
                        if isinstance(response, Exception):
                            errors.append(str(response))
                            metrics.failed_requests += 1
                        else:
                            response_time = (time.time() - batch_start) * 1000 / len(tasks)
                            response_times.append(response_time)
                            
                            if response.status_code == 200:
                                metrics.successful_requests += 1
                            else:
                                metrics.failed_requests += 1
                                errors.append(f"HTTP {response.status_code}")
                    
                    tasks = []
        
        total_time = time.time() - start_time
        
        # Calculate metrics
        metrics.total_requests = num_requests
        metrics.response_times = response_times
        metrics.errors = errors[:10]  # Keep first 10 errors
        
        if response_times:
            metrics.min_time = min(response_times)
            metrics.max_time = max(response_times)
            metrics.avg_time = statistics.mean(response_times)
            metrics.median_time = statistics.median(response_times)
            
            if len(response_times) >= 20:
                sorted_times = sorted(response_times)
                metrics.p95_time = sorted_times[int(len(sorted_times) * 0.95)]
                metrics.p99_time = sorted_times[int(len(sorted_times) * 0.99)]
        
        metrics.requests_per_second = num_requests / total_time if total_time > 0 else 0
        
        # Resource metrics
        memory_info = process.memory_info()
        metrics.avg_memory_mb = memory_info.rss / 1024 / 1024
        metrics.peak_memory_mb = tracemalloc.get_traced_memory()[1] / 1024 / 1024
        metrics.avg_cpu_percent = process.cpu_percent()
        
        tracemalloc.stop()
        
        return metrics
    
    async def test_search_endpoint(self) -> PerformanceMetrics:
        """Test /api/forge/search endpoint with various queries."""
        
        print("\n Testing /api/forge/search...")
        
        all_metrics = []
        
        for query in self.test_data["search_queries"][:5]:  # Test 5 queries
            params = {
                "q": query,
                "limit": 20
            }
            
            metrics = await self.test_endpoint(
                "/api/forge/search",
                params=params,
                num_requests=50,
                concurrent=5
            )
            all_metrics.append(metrics)
            print(f"  Query '{query}': avg={metrics.avg_time:.2f}ms, p95={metrics.p95_time:.2f}ms")
        
        # Aggregate metrics
        combined = PerformanceMetrics(endpoint="/api/forge/search")
        combined.avg_time = statistics.mean([m.avg_time for m in all_metrics])
        combined.p95_time = statistics.mean([m.p95_time for m in all_metrics if m.p95_time > 0])
        combined.requests_per_second = statistics.mean([m.requests_per_second for m in all_metrics])
        
        return combined
    
    async def test_categories_endpoint(self) -> PerformanceMetrics:
        """Test /api/forge/categories endpoint."""
        
        print("\n Testing /api/forge/categories...")
        
        metrics = await self.test_endpoint(
            "/api/forge/categories",
            num_requests=100,
            concurrent=10
        )
        
        print(f"  avg={metrics.avg_time:.2f}ms, p95={metrics.p95_time:.2f}ms, rps={metrics.requests_per_second:.2f}")
        
        return metrics
    
    async def test_browse_endpoint(self) -> PerformanceMetrics:
        """Test /api/forge/browse/{category} endpoint."""
        
        print("\n Testing /api/forge/browse...")
        
        all_metrics = []
        
        for category in self.test_data["categories"][:3]:  # Test 3 categories
            metrics = await self.test_endpoint(
                f"/api/forge/browse/{category}",
                params={"limit": 50},
                num_requests=30,
                concurrent=3
            )
            all_metrics.append(metrics)
            print(f"  Category '{category}': avg={metrics.avg_time:.2f}ms")
        
        # Aggregate
        combined = PerformanceMetrics(endpoint="/api/forge/browse/{category}")
        combined.avg_time = statistics.mean([m.avg_time for m in all_metrics])
        
        return combined
    
    async def test_tool_endpoint(self) -> PerformanceMetrics:
        """Test /api/forge/tool/{ecosystem}/{package} endpoint."""
        
        print("\n Testing /api/forge/tool...")
        
        all_metrics = []
        
        for ecosystem, package in self.test_data["packages"]:
            metrics = await self.test_endpoint(
                f"/api/forge/tool/{ecosystem}/{package}",
                num_requests=50,
                concurrent=5
            )
            all_metrics.append(metrics)
            print(f"  {ecosystem}/{package}: avg={metrics.avg_time:.2f}ms")
        
        # Aggregate
        combined = PerformanceMetrics(endpoint="/api/forge/tool/{ecosystem}/{package}")
        combined.avg_time = statistics.mean([m.avg_time for m in all_metrics])
        
        return combined
    
    async def test_stack_endpoint(self) -> PerformanceMetrics:
        """Test /api/forge/stack endpoint."""
        
        print("\n Testing /api/forge/stack...")
        
        all_metrics = []
        
        for use_case in self.test_data["use_cases"][:3]:
            json_data = {
                "use_case": use_case,
                "max_tools": 5,
                "min_trust_score": 70.0
            }
            
            metrics = await self.test_endpoint(
                "/api/forge/stack",
                method="POST",
                json_data=json_data,
                num_requests=20,
                concurrent=2
            )
            all_metrics.append(metrics)
            print(f"  Use case: avg={metrics.avg_time:.2f}ms")
        
        # Aggregate
        combined = PerformanceMetrics(endpoint="/api/forge/stack")
        combined.avg_time = statistics.mean([m.avg_time for m in all_metrics])
        
        return combined
    
    async def simulate_load_patterns(self):
        """Simulate different load patterns."""
        
        print("\n=== LOAD PATTERN SIMULATION ===")
        
        patterns = [
            ("Normal Load", 50, 5),     # 50 req/min, 5 concurrent
            ("Peak Load", 200, 20),     # 200 req/min, 20 concurrent
            ("Spike Test", 1000, 50),   # 1000 req/min, 50 concurrent
        ]
        
        for pattern_name, req_per_min, concurrent in patterns:
            print(f"\n {pattern_name}: {req_per_min} req/min, {concurrent} concurrent")
            
            # Test search endpoint under load
            params = {"q": "database", "limit": 20}
            metrics = await self.test_endpoint(
                "/api/forge/search",
                params=params,
                num_requests=req_per_min,
                concurrent=concurrent
            )
            
            print(f"  Response times: avg={metrics.avg_time:.2f}ms, p95={metrics.p95_time:.2f}ms, p99={metrics.p99_time:.2f}ms")
            print(f"  Throughput: {metrics.requests_per_second:.2f} req/s")
            print(f"  Success rate: {(metrics.successful_requests/metrics.total_requests)*100:.1f}%")
            print(f"  Memory: avg={metrics.avg_memory_mb:.2f}MB, peak={metrics.peak_memory_mb:.2f}MB")
    
    def analyze_bottlenecks(self) -> Dict[str, Any]:
        """Analyze performance bottlenecks from collected metrics."""
        
        bottlenecks = {
            "slow_endpoints": [],
            "high_variance_endpoints": [],
            "memory_intensive": [],
            "low_throughput": [],
            "high_error_rate": []
        }
        
        for endpoint, metrics in self.metrics.items():
            # Slow endpoints (>200ms avg)
            if metrics.avg_time > 200:
                bottlenecks["slow_endpoints"].append({
                    "endpoint": endpoint,
                    "avg_time_ms": metrics.avg_time,
                    "p95_time_ms": metrics.p95_time
                })
            
            # High variance (p95 > 3x average)
            if metrics.p95_time > 0 and metrics.p95_time > metrics.avg_time * 3:
                bottlenecks["high_variance_endpoints"].append({
                    "endpoint": endpoint,
                    "avg_time_ms": metrics.avg_time,
                    "p95_time_ms": metrics.p95_time,
                    "variance_ratio": metrics.p95_time / metrics.avg_time
                })
            
            # Memory intensive (>100MB peak)
            if metrics.peak_memory_mb > 100:
                bottlenecks["memory_intensive"].append({
                    "endpoint": endpoint,
                    "peak_memory_mb": metrics.peak_memory_mb
                })
            
            # Low throughput (<10 req/s)
            if metrics.requests_per_second < 10:
                bottlenecks["low_throughput"].append({
                    "endpoint": endpoint,
                    "requests_per_second": metrics.requests_per_second
                })
            
            # High error rate (>5%)
            error_rate = metrics.failed_requests / metrics.total_requests if metrics.total_requests > 0 else 0
            if error_rate > 0.05:
                bottlenecks["high_error_rate"].append({
                    "endpoint": endpoint,
                    "error_rate_percent": error_rate * 100,
                    "errors": metrics.errors[:3]
                })
        
        return bottlenecks
    
    def generate_optimizations(self, bottlenecks: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate optimization recommendations based on bottlenecks."""
        
        optimizations = []
        
        # Database query optimizations
        if bottlenecks["slow_endpoints"]:
            slow_endpoints = [b["endpoint"] for b in bottlenecks["slow_endpoints"]]
            
            if "/search" in str(slow_endpoints):
                optimizations.append({
                    "priority": "HIGH",
                    "area": "Database Queries",
                    "issue": "Search endpoint is slow",
                    "recommendations": [
                        "Add full-text search index on package_name and description_summary",
                        "Implement query result caching with 5-minute TTL",
                        "Use LIMIT and OFFSET for pagination instead of fetching all results",
                        "Consider using Azure Cognitive Search for text search operations"
                    ],
                    "estimated_impact": "50-70% reduction in search response time"
                })
            
            if "/browse" in str(slow_endpoints):
                optimizations.append({
                    "priority": "HIGH",
                    "area": "Database Queries",
                    "issue": "Browse by category is slow",
                    "recommendations": [
                        "Add composite index on (category, confidence_score DESC)",
                        "Pre-aggregate category counts in a materialized view",
                        "Cache category listings with 10-minute TTL"
                    ],
                    "estimated_impact": "40-60% reduction in browse response time"
                })
        
        # Memory optimizations
        if bottlenecks["memory_intensive"]:
            optimizations.append({
                "priority": "MEDIUM",
                "area": "Memory Usage",
                "issue": "High memory consumption detected",
                "recommendations": [
                    "Implement streaming for large result sets",
                    "Use pagination to limit result set size",
                    "Clear unused objects and implement connection pooling",
                    "Consider using generators for data processing"
                ],
                "estimated_impact": "30-50% reduction in memory usage"
            })
        
        # Caching optimizations
        if bottlenecks["high_variance_endpoints"]:
            optimizations.append({
                "priority": "HIGH",
                "area": "Caching Strategy",
                "issue": "High response time variance",
                "recommendations": [
                    "Implement Redis caching for frequently accessed data",
                    "Cache classification results with 1-hour TTL",
                    "Use ETags for conditional requests",
                    "Implement request coalescing for duplicate queries"
                ],
                "estimated_impact": "60-80% reduction in p95 response times"
            })
        
        # API optimization
        if bottlenecks["low_throughput"]:
            optimizations.append({
                "priority": "MEDIUM",
                "area": "API Performance",
                "issue": "Low request throughput",
                "recommendations": [
                    "Implement connection pooling for database",
                    "Use async/await properly throughout the stack",
                    "Consider using uvloop for better async performance",
                    "Implement request batching for bulk operations"
                ],
                "estimated_impact": "2-3x improvement in throughput"
            })
        
        # Error handling
        if bottlenecks["high_error_rate"]:
            optimizations.append({
                "priority": "CRITICAL",
                "area": "Error Handling",
                "issue": "High error rate detected",
                "recommendations": [
                    "Implement circuit breaker pattern for external APIs",
                    "Add retry logic with exponential backoff",
                    "Improve error logging and monitoring",
                    "Add request validation and sanitization"
                ],
                "estimated_impact": "90% reduction in error rate"
            })
        
        return optimizations
    
    async def run_comprehensive_analysis(self):
        """Run comprehensive performance analysis."""
        
        print("="*60)
        print(" SIGIL FORGE PERFORMANCE ANALYSIS")
        print("="*60)
        
        # Test individual endpoints
        print("\n=== ENDPOINT PERFORMANCE TESTING ===")
        
        self.metrics["/api/forge/search"] = await self.test_search_endpoint()
        self.metrics["/api/forge/categories"] = await self.test_categories_endpoint()
        self.metrics["/api/forge/browse/{category}"] = await self.test_browse_endpoint()
        self.metrics["/api/forge/tool/{ecosystem}/{package}"] = await self.test_tool_endpoint()
        self.metrics["/api/forge/stack"] = await self.test_stack_endpoint()
        
        # Simulate load patterns
        await self.simulate_load_patterns()
        
        # Analyze bottlenecks
        print("\n=== BOTTLENECK ANALYSIS ===")
        bottlenecks = self.analyze_bottlenecks()
        
        if bottlenecks["slow_endpoints"]:
            print("\n Slow Endpoints (>200ms):")
            for item in bottlenecks["slow_endpoints"]:
                print(f"  - {item['endpoint']}: {item['avg_time_ms']:.2f}ms avg, {item['p95_time_ms']:.2f}ms p95")
        
        if bottlenecks["high_variance_endpoints"]:
            print("\n High Variance Endpoints:")
            for item in bottlenecks["high_variance_endpoints"]:
                print(f"  - {item['endpoint']}: {item['variance_ratio']:.2f}x variance")
        
        if bottlenecks["low_throughput"]:
            print("\n Low Throughput Endpoints:")
            for item in bottlenecks["low_throughput"]:
                print(f"  - {item['endpoint']}: {item['requests_per_second']:.2f} req/s")
        
        # Generate optimizations
        print("\n=== OPTIMIZATION RECOMMENDATIONS ===")
        optimizations = self.generate_optimizations(bottlenecks)
        
        for opt in optimizations:
            print(f"\n [{opt['priority']}] {opt['area']}: {opt['issue']}")
            print(" Recommendations:")
            for rec in opt['recommendations']:
                print(f"  - {rec}")
            print(f" Expected Impact: {opt['estimated_impact']}")
        
        # Summary report
        print("\n=== PERFORMANCE SUMMARY ===")
        print("\n Endpoint Performance:")
        for endpoint, metrics in self.metrics.items():
            print(f"  {endpoint}:")
            print(f"    Response Time: avg={metrics.avg_time:.2f}ms, p95={metrics.p95_time:.2f}ms")
            print(f"    Throughput: {metrics.requests_per_second:.2f} req/s")
            if metrics.failed_requests > 0:
                print(f"    Error Rate: {(metrics.failed_requests/metrics.total_requests)*100:.1f}%")
        
        # Performance requirements check
        print("\n Performance Requirements Check:")
        requirements = {
            "API response times < 200ms": all(m.avg_time < 200 for m in self.metrics.values()),
            "Support 100 concurrent users": self.metrics.get("/api/forge/search", PerformanceMetrics("")).requests_per_second > 100,
            "Memory usage < 2GB": all(m.peak_memory_mb < 2048 for m in self.metrics.values()),
        }
        
        for req, passed in requirements.items():
            status = "PASS" if passed else "FAIL"
            print(f"  [{status}] {req}")
        
        # Export results
        self.export_results()
    
    def export_results(self):
        """Export performance results to JSON file."""
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "metrics": {k: asdict(v) for k, v in self.metrics.items()},
            "bottlenecks": self.analyze_bottlenecks(),
            "optimizations": self.generate_optimizations(self.analyze_bottlenecks())
        }
        
        filename = f"forge_performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n Results exported to {filename}")


async def main():
    """Main entry point."""
    
    # Check if API is running
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:8000/health")
            if response.status_code != 200:
                print("Warning: API may not be healthy")
    except Exception as e:
        print(f"Error: Could not connect to API at http://localhost:8000")
        print(f"Please ensure the Sigil API is running: cd api && python main.py")
        return
    
    analyzer = ForgePerformanceAnalyzer()
    await analyzer.run_comprehensive_analysis()


if __name__ == "__main__":
    asyncio.run(main())
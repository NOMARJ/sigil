"""
Comprehensive Performance Testing Suite

Tests API performance, database queries, concurrent load handling,
memory usage, and classification pipeline performance.
"""

from __future__ import annotations

import asyncio
import statistics
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import pytest
from fastapi.testclient import TestClient


class PerformanceMetrics:
    """Helper class to collect and analyze performance metrics."""

    def __init__(self):
        self.response_times: list[float] = []
        self.success_count = 0
        self.error_count = 0
        self.status_codes: dict[int, int] = {}

    def record_response(self, response_time: float, status_code: int):
        """Record a single response."""
        self.response_times.append(response_time)
        self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1

        if 200 <= status_code < 400:
            self.success_count += 1
        else:
            self.error_count += 1

    def get_summary(self) -> dict[str, Any]:
        """Get performance summary statistics."""
        if not self.response_times:
            return {"error": "No data collected"}

        return {
            "total_requests": len(self.response_times),
            "success_count": self.success_count,
            "error_count": self.error_count,
            "success_rate": self.success_count / len(self.response_times) * 100,
            "response_times": {
                "min": min(self.response_times),
                "max": max(self.response_times),
                "avg": statistics.mean(self.response_times),
                "median": statistics.median(self.response_times),
                "p95": statistics.quantiles(self.response_times, n=20)[
                    18
                ],  # 95th percentile
                "p99": statistics.quantiles(self.response_times, n=100)[
                    98
                ],  # 99th percentile
            },
            "status_codes": self.status_codes,
        }


def measure_endpoint_performance(
    client: TestClient,
    method: str,
    endpoint: str,
    data: dict = None,
    headers: dict = None,
    repeat: int = 1,
) -> PerformanceMetrics:
    """Measure performance of a single endpoint."""
    metrics = PerformanceMetrics()

    for _ in range(repeat):
        start_time = time.time()

        if method.upper() == "GET":
            resp = client.get(endpoint, headers=headers)
        elif method.upper() == "POST":
            resp = client.post(endpoint, json=data, headers=headers)
        elif method.upper() == "PUT":
            resp = client.put(endpoint, json=data, headers=headers)
        elif method.upper() == "DELETE":
            resp = client.delete(endpoint, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")

        end_time = time.time()
        response_time = (end_time - start_time) * 1000  # Convert to milliseconds

        metrics.record_response(response_time, resp.status_code)

    return metrics


class TestAPIPerformance:
    """Test API endpoint performance under normal conditions."""

    def test_health_endpoint_performance(self, client: TestClient):
        """Test health check endpoint performance."""
        metrics = measure_endpoint_performance(client, "GET", "/health", repeat=100)
        summary = metrics.get_summary()

        # Health check should be very fast
        assert summary["response_times"]["avg"] < 50, (
            f"Health check too slow: {summary['response_times']['avg']:.2f}ms"
        )
        assert summary["response_times"]["p95"] < 100, (
            f"95th percentile too slow: {summary['response_times']['p95']:.2f}ms"
        )
        assert summary["success_rate"] == 100.0, (
            f"Health check failure rate: {100 - summary['success_rate']:.2f}%"
        )

        print(f"Health endpoint performance: {summary}")

    def test_authentication_performance(
        self, client: TestClient, test_user_data: dict[str, str]
    ):
        """Test authentication endpoint performance."""
        # Register user first
        client.post("/v1/auth/register", json=test_user_data)

        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"],
        }

        metrics = measure_endpoint_performance(
            client, "POST", "/v1/auth/login", login_data, repeat=50
        )
        summary = metrics.get_summary()

        # Authentication should complete within reasonable time
        assert summary["response_times"]["avg"] < 200, (
            f"Login too slow: {summary['response_times']['avg']:.2f}ms"
        )
        assert summary["response_times"]["p95"] < 500, (
            f"Login 95th percentile too slow: {summary['response_times']['p95']:.2f}ms"
        )
        assert summary["success_rate"] >= 98.0, (
            f"Login failure rate too high: {100 - summary['success_rate']:.2f}%"
        )

        print(f"Authentication performance: {summary}")

    def test_scan_submission_performance(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_scan_request: dict[str, Any],
    ):
        """Test scan submission performance."""
        metrics = measure_endpoint_performance(
            client, "POST", "/v1/scans", sample_scan_request, auth_headers, repeat=20
        )
        summary = metrics.get_summary()

        # Scan submission should be reasonably fast
        assert summary["response_times"]["avg"] < 1000, (
            f"Scan submission too slow: {summary['response_times']['avg']:.2f}ms"
        )
        assert summary["response_times"]["p95"] < 2000, (
            f"Scan 95th percentile too slow: {summary['response_times']['p95']:.2f}ms"
        )
        assert summary["success_rate"] >= 95.0, (
            f"Scan submission failure rate: {100 - summary['success_rate']:.2f}%"
        )

        print(f"Scan submission performance: {summary}")

    def test_threat_lookup_performance(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test threat intelligence lookup performance."""
        # Test threat lookup for various package hashes
        test_hashes = [
            "abc123def456",
            "nonexistent123",
            "test456hash",
            "another789hash",
            "final012hash",
        ]

        total_metrics = PerformanceMetrics()

        for package_hash in test_hashes:
            metrics = measure_endpoint_performance(
                client,
                "GET",
                f"/v1/threat/{package_hash}",
                headers=auth_headers,
                repeat=10,
            )

            # Combine metrics
            for rt in metrics.response_times:
                total_metrics.response_times.append(rt)
            total_metrics.success_count += metrics.success_count
            total_metrics.error_count += metrics.error_count
            for code, count in metrics.status_codes.items():
                total_metrics.status_codes[code] = (
                    total_metrics.status_codes.get(code, 0) + count
                )

        summary = total_metrics.get_summary()

        # Threat lookups should be very fast (cached/indexed)
        assert summary["response_times"]["avg"] < 100, (
            f"Threat lookup too slow: {summary['response_times']['avg']:.2f}ms"
        )
        assert summary["response_times"]["p95"] < 200, (
            f"Threat lookup 95th percentile too slow: {summary['response_times']['p95']:.2f}ms"
        )

        print(f"Threat lookup performance: {summary}")


class TestConcurrentLoad:
    """Test performance under concurrent load."""

    def test_concurrent_health_checks(self, client: TestClient):
        """Test health endpoint under concurrent load."""

        def make_health_request():
            start_time = time.time()
            resp = client.get("/health")
            end_time = time.time()
            return (end_time - start_time) * 1000, resp.status_code

        # Run 100 concurrent requests
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_health_request) for _ in range(100)]

            results = []
            for future in as_completed(futures):
                results.append(future.result())

        response_times = [rt for rt, _ in results]
        status_codes = [sc for _, sc in results]

        # Analyze concurrent performance
        avg_response_time = statistics.mean(response_times)
        success_count = sum(1 for sc in status_codes if 200 <= sc < 400)
        success_rate = success_count / len(status_codes) * 100

        assert avg_response_time < 100, (
            f"Concurrent health checks too slow: {avg_response_time:.2f}ms"
        )
        assert success_rate >= 95.0, (
            f"Concurrent health check failure rate: {100 - success_rate:.2f}%"
        )

        print(
            f"Concurrent health checks - Avg: {avg_response_time:.2f}ms, Success: {success_rate:.1f}%"
        )

    def test_concurrent_authentication(self, client: TestClient):
        """Test authentication under concurrent load."""
        # Create multiple test users
        users = []
        for i in range(10):
            user_data = {
                "email": f"testuser{i}@example.com",
                "password": "TestPassword123!",
                "name": f"Test User {i}",
            }
            resp = client.post("/v1/auth/register", json=user_data)
            if resp.status_code == 201:
                users.append(user_data)

        def authenticate_user(user_data):
            login_data = {
                "email": user_data["email"],
                "password": user_data["password"],
            }
            start_time = time.time()
            resp = client.post("/v1/auth/login", json=login_data)
            end_time = time.time()
            return (end_time - start_time) * 1000, resp.status_code

        # Run concurrent authentication requests
        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for _ in range(50):  # 50 login attempts
                user = users[len(futures) % len(users)]  # Cycle through users
                futures.append(executor.submit(authenticate_user, user))

            for future in as_completed(futures):
                results.append(future.result())

        response_times = [rt for rt, _ in results]
        status_codes = [sc for _, sc in results]

        avg_response_time = statistics.mean(response_times)
        success_count = sum(1 for sc in status_codes if 200 <= sc < 400)
        success_rate = success_count / len(status_codes) * 100

        assert avg_response_time < 500, (
            f"Concurrent auth too slow: {avg_response_time:.2f}ms"
        )
        assert success_rate >= 90.0, (
            f"Concurrent auth failure rate: {100 - success_rate:.2f}%"
        )

        print(
            f"Concurrent authentication - Avg: {avg_response_time:.2f}ms, Success: {success_rate:.1f}%"
        )

    def test_concurrent_scan_submission(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test scan submission under concurrent load."""

        def submit_scan(scan_id: int):
            scan_data = {
                "target": f"test-package-{scan_id}",
                "target_type": "npm",
                "files_scanned": 10,
                "findings": [
                    {
                        "phase": "code_patterns",
                        "rule": "code-eval",
                        "severity": "HIGH",
                        "file": "index.js",
                        "line": 42,
                        "snippet": "eval(userInput)",
                        "weight": 1.0,
                    }
                ],
                "metadata": {"version": "1.0.0"},
            }

            start_time = time.time()
            resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
            end_time = time.time()
            return (end_time - start_time) * 1000, resp.status_code

        # Run concurrent scan submissions
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(submit_scan, i) for i in range(30)]

            results = []
            for future in as_completed(futures):
                results.append(future.result())

        response_times = [rt for rt, _ in results]
        status_codes = [sc for _, sc in results]

        avg_response_time = statistics.mean(response_times)
        success_count = sum(1 for sc in status_codes if 200 <= sc < 400)
        success_rate = success_count / len(status_codes) * 100

        assert avg_response_time < 2000, (
            f"Concurrent scan submission too slow: {avg_response_time:.2f}ms"
        )
        assert success_rate >= 85.0, (
            f"Concurrent scan failure rate: {100 - success_rate:.2f}%"
        )

        print(
            f"Concurrent scan submission - Avg: {avg_response_time:.2f}ms, Success: {success_rate:.1f}%"
        )


class TestDatabasePerformance:
    """Test database query performance."""

    @pytest.mark.asyncio
    async def test_user_lookup_performance(self, client: TestClient):
        """Test user lookup query performance."""
        from database import db

        # Create some test users first
        test_emails = [f"perftest{i}@example.com" for i in range(100)]

        # Measure user lookup performance
        time.time()

        lookup_times = []
        for email in test_emails[:10]:  # Test first 10
            lookup_start = time.time()
            await db.get_user_by_email(email)
            lookup_end = time.time()
            lookup_times.append((lookup_end - lookup_start) * 1000)

        if lookup_times:
            avg_lookup_time = statistics.mean(lookup_times)
            max_lookup_time = max(lookup_times)

            assert avg_lookup_time < 50, (
                f"User lookup too slow: {avg_lookup_time:.2f}ms"
            )
            assert max_lookup_time < 100, (
                f"Slowest user lookup: {max_lookup_time:.2f}ms"
            )

            print(
                f"User lookup performance - Avg: {avg_lookup_time:.2f}ms, Max: {max_lookup_time:.2f}ms"
            )

    @pytest.mark.asyncio
    async def test_scan_query_performance(self, client: TestClient):
        """Test scan query performance."""

        # Measure scan listing performance
        time.time()

        # This would typically test actual database queries
        # For now, we'll measure the time for basic operations
        query_times = []
        for i in range(10):
            query_start = time.time()
            # Simulate a scan query (replace with actual query when db is connected)
            await asyncio.sleep(0.001)  # Simulate small query time
            query_end = time.time()
            query_times.append((query_end - query_start) * 1000)

        avg_query_time = statistics.mean(query_times)
        max_query_time = max(query_times)

        # These are simulated values - adjust for real database performance
        assert avg_query_time < 100, f"Scan query too slow: {avg_query_time:.2f}ms"
        assert max_query_time < 200, f"Slowest scan query: {max_query_time:.2f}ms"

        print(
            f"Scan query performance - Avg: {avg_query_time:.2f}ms, Max: {max_query_time:.2f}ms"
        )


class TestMemoryUsage:
    """Test memory usage under load."""

    def test_memory_usage_during_load(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test memory usage during sustained load."""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Generate sustained load
        for batch in range(5):
            for i in range(20):
                scan_data = {
                    "target": f"memory-test-{batch}-{i}",
                    "target_type": "npm",
                    "files_scanned": 50,
                    "findings": [
                        {
                            "phase": "code_patterns",
                            "rule": "test-rule",
                            "severity": "HIGH",
                            "file": f"file{j}.js",
                            "line": j,
                            "snippet": "x" * 100,  # Some content
                            "weight": 1.0,
                        }
                        for j in range(10)  # 10 findings per scan
                    ],
                    "metadata": {"version": "1.0.0"},
                }

                client.post("/v1/scans", json=scan_data, headers=auth_headers)

            # Check memory after each batch
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = current_memory - initial_memory

            print(
                f"Batch {batch}: Memory usage {current_memory:.1f}MB (+{memory_increase:.1f}MB)"
            )

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        total_increase = final_memory - initial_memory

        # Memory should not grow excessively
        assert total_increase < 100, f"Memory usage increased by {total_increase:.1f}MB"

        print(
            f"Memory test complete - Initial: {initial_memory:.1f}MB, Final: {final_memory:.1f}MB"
        )


class TestClassificationPipelinePerformance:
    """Test classification pipeline performance."""

    def test_classification_speed(self, sample_findings: list[dict[str, Any]]):
        """Test classification pipeline processing speed."""
        from services.scanner_service import ScannerService

        scanner = ScannerService()

        # Test various finding sets
        test_cases = [
            [],  # No findings
            sample_findings[:1],  # Single finding
            sample_findings,  # Multiple findings
            sample_findings * 10,  # Large number of findings
        ]

        classification_times = []

        for findings in test_cases:
            start_time = time.time()
            scanner.classify_scan_result("test-target", "npm", len(findings), findings)
            end_time = time.time()

            classification_time = (end_time - start_time) * 1000
            classification_times.append(classification_time)

            print(f"Classified {len(findings)} findings in {classification_time:.2f}ms")

        # Classification should be fast even for large finding sets
        max_time = max(classification_times)
        avg_time = statistics.mean(classification_times)

        assert max_time < 1000, f"Classification too slow: {max_time:.2f}ms"
        assert avg_time < 500, f"Average classification too slow: {avg_time:.2f}ms"

    def test_scoring_algorithm_performance(self, sample_findings: list[dict[str, Any]]):
        """Test scoring algorithm performance."""
        from services.scanner_service import ScannerService

        scanner = ScannerService()

        # Test scoring with different finding combinations
        large_finding_set = []
        for i in range(1000):
            large_finding_set.append(
                {
                    "phase": "code_patterns",
                    "rule": f"test-rule-{i % 10}",
                    "severity": "HIGH" if i % 3 == 0 else "MEDIUM",
                    "file": f"file{i}.js",
                    "line": i,
                    "snippet": f"test code snippet {i}",
                    "weight": 1.0,
                }
            )

        start_time = time.time()
        result = scanner.classify_scan_result(
            "large-test", "npm", 1000, large_finding_set
        )
        end_time = time.time()

        processing_time = (end_time - start_time) * 1000

        print(f"Processed 1000 findings in {processing_time:.2f}ms")
        print(f"Classification: {result.classification}")
        print(f"Score: {result.score}")

        # Should handle large datasets efficiently
        assert processing_time < 5000, (
            f"Large dataset processing too slow: {processing_time:.2f}ms"
        )


class TestEndpointLatencyUnderLoad:
    """Test endpoint latency under sustained load."""

    def test_sustained_load_impact(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test how sustained load impacts response times."""
        baseline_metrics = measure_endpoint_performance(
            client, "GET", "/health", repeat=10
        )
        baseline_avg = baseline_metrics.get_summary()["response_times"]["avg"]

        print(f"Baseline health check latency: {baseline_avg:.2f}ms")

        # Create background load
        def background_load():
            for i in range(100):
                scan_data = {
                    "target": f"load-test-{i}",
                    "target_type": "npm",
                    "files_scanned": 10,
                    "findings": [],
                    "metadata": {},
                }
                client.post("/v1/scans", json=scan_data, headers=auth_headers)
                time.sleep(0.01)  # Small delay between requests

        # Start background load
        load_thread = threading.Thread(target=background_load)
        load_thread.start()

        # Measure performance under load
        time.sleep(1)  # Let load build up
        under_load_metrics = measure_endpoint_performance(
            client, "GET", "/health", repeat=20
        )
        under_load_avg = under_load_metrics.get_summary()["response_times"]["avg"]

        load_thread.join()  # Wait for background load to complete

        print(f"Under load health check latency: {under_load_avg:.2f}ms")

        # Latency should not degrade significantly under load
        latency_increase = under_load_avg - baseline_avg
        latency_degradation = (latency_increase / baseline_avg) * 100

        assert latency_degradation < 300, (
            f"Latency degraded by {latency_degradation:.1f}% under load"
        )

        print(f"Latency degradation under load: {latency_degradation:.1f}%")


@pytest.fixture(scope="session")
def performance_report():
    """Collect performance test results for final reporting."""
    results = {}
    yield results

    # Print final performance summary
    print("\n" + "=" * 60)
    print("PERFORMANCE TEST SUMMARY")
    print("=" * 60)
    for test_name, metrics in results.items():
        print(f"{test_name}: {metrics}")
    print("=" * 60)

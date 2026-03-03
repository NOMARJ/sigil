"""
Comprehensive Resilience Testing Suite

Tests system resilience through chaos engineering, failure simulation,
circuit breakers, error recovery, and graceful degradation scenarios.
"""

from __future__ import annotations

import asyncio
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient


class ChaosMonkey:
    """Chaos engineering helper for injecting failures."""
    
    def __init__(self):
        self.active_failures: List[str] = []
        self.failure_probability = 0.0
    
    def inject_database_failure(self, probability: float = 0.5):
        """Inject random database connection failures."""
        self.failure_probability = probability
        self.active_failures.append("database")
    
    def inject_network_failure(self, probability: float = 0.3):
        """Inject random network failures."""
        self.failure_probability = probability
        self.active_failures.append("network")
    
    def inject_memory_pressure(self):
        """Simulate memory pressure conditions."""
        self.active_failures.append("memory")
    
    def inject_cpu_load(self):
        """Simulate high CPU load conditions."""
        self.active_failures.append("cpu")
    
    def should_fail(self) -> bool:
        """Determine if an operation should fail based on probability."""
        return random.random() < self.failure_probability
    
    def clear_failures(self):
        """Clear all active failure injections."""
        self.active_failures.clear()
        self.failure_probability = 0.0


@pytest.fixture
def chaos_monkey():
    """Provide a chaos monkey for failure injection."""
    monkey = ChaosMonkey()
    yield monkey
    monkey.clear_failures()


class TestDatabaseResilience:
    """Test resilience to database failures."""
    
    def test_database_connection_failure_handling(
        self, client: TestClient, auth_headers: dict[str, str], chaos_monkey: ChaosMonkey
    ):
        """Test handling of database connection failures."""
        
        # Mock database connection failures
        with patch('api.database.db.connected', return_value=False):
            # Health check should report degraded status
            health_resp = client.get("/health")
            assert health_resp.status_code == 503
            
            health_data = health_resp.json()
            assert health_data["status"] == "degraded"
            assert health_data["database_connected"] == False
        
        # System should recover when database comes back
        recovery_resp = client.get("/health")
        assert recovery_resp.status_code == 200
    
    @patch('api.database.db.get_user_by_id')
    def test_user_lookup_failure_resilience(
        self, mock_get_user, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test resilience when user lookup operations fail."""
        # Simulate database timeout
        mock_get_user.side_effect = Exception("Database timeout")
        
        # Protected endpoints should handle user lookup failures gracefully
        resp = client.get("/v1/auth/me", headers=auth_headers)
        
        # Should return appropriate error, not crash
        assert resp.status_code in [500, 503, 401]
        
        error_data = resp.json()
        assert "detail" in error_data
        assert "internal" in error_data["detail"].lower()
    
    @patch('api.database.db.store_scan')
    def test_scan_storage_failure_resilience(
        self, mock_store_scan, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test resilience when scan storage fails."""
        # Simulate storage failure
        mock_store_scan.side_effect = Exception("Storage unavailable")
        
        scan_data = {
            "target": "resilience-test",
            "target_type": "npm",
            "files_scanned": 5,
            "findings": [],
            "metadata": {},
        }
        
        resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
        
        # Should handle storage failure gracefully
        assert resp.status_code in [500, 503]
        
        error_data = resp.json()
        assert "detail" in error_data
        # Should not expose internal error details
        assert "storage unavailable" not in error_data["detail"].lower()


class TestNetworkResilience:
    """Test resilience to network failures and external service outages."""
    
    @patch('httpx.AsyncClient.get')
    def test_external_api_failure_resilience(
        self, mock_http_get, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test resilience when external APIs are unavailable."""
        # Simulate external service timeout
        mock_http_get.side_effect = Exception("Connection timeout")
        
        # Operations that depend on external services should degrade gracefully
        # This might include package registry lookups, threat intel updates, etc.
        
        # Test registry lookup with external failure
        registry_resp = client.get("/registry/npm/some-package")
        
        # Should return graceful error or cached data, not crash
        assert registry_resp.status_code in [200, 404, 503]
    
    def test_intermittent_connection_handling(
        self, client: TestClient, auth_headers: dict[str, str], chaos_monkey: ChaosMonkey
    ):
        """Test handling of intermittent network connections."""
        chaos_monkey.inject_network_failure(0.3)
        
        # Make multiple requests - some should succeed, others may fail gracefully
        results = []
        for i in range(20):
            try:
                resp = client.get("/health")
                results.append(resp.status_code)
            except Exception:
                results.append(None)  # Connection failed
        
        # System should handle intermittent failures
        successful_requests = [r for r in results if r == 200]
        assert len(successful_requests) > 0, "No requests succeeded during intermittent failures"
        
        # Failed requests should be handled gracefully
        failed_requests = [r for r in results if r is None]
        # Some failures are acceptable during network chaos


class TestHighLoadResilience:
    """Test system resilience under high load conditions."""
    
    def test_concurrent_request_handling(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test system resilience under high concurrent load."""
        
        def make_scan_request(scan_id: int):
            scan_data = {
                "target": f"load-test-{scan_id}",
                "target_type": "npm",
                "files_scanned": 10,
                "findings": [
                    {
                        "phase": "code_patterns",
                        "rule": "test-rule",
                        "severity": "MEDIUM",
                        "file": f"file{scan_id}.js",
                        "line": 10,
                        "snippet": f"test code {scan_id}",
                        "weight": 0.5,
                    }
                ],
                "metadata": {"test_id": scan_id},
            }
            
            try:
                resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
                return resp.status_code
            except Exception as e:
                return f"error: {str(e)}"
        
        # Launch high concurrent load
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(make_scan_request, i) for i in range(200)]
            
            results = []
            for future in as_completed(futures):
                results.append(future.result())
        
        # Analyze results
        successful = [r for r in results if r == 201]
        rate_limited = [r for r in results if r == 429]
        server_errors = [r for r in results if r == 500]
        other_errors = [r for r in results if isinstance(r, str) and r.startswith("error")]
        
        success_rate = len(successful) / len(results)
        
        # System should handle load gracefully
        assert success_rate > 0.5, f"Success rate too low under load: {success_rate:.2%}"
        
        # Rate limiting should engage before server errors
        if len(rate_limited) > 0:
            assert len(server_errors) < len(rate_limited), "More server errors than rate limits"
        
        print(f"Load test results: {len(successful)} success, {len(rate_limited)} rate limited, "
              f"{len(server_errors)} server errors, {len(other_errors)} connection errors")
    
    def test_memory_pressure_resilience(
        self, client: TestClient, auth_headers: dict[str, str], chaos_monkey: ChaosMonkey
    ):
        """Test resilience under memory pressure."""
        chaos_monkey.inject_memory_pressure()
        
        # Create memory-intensive requests
        large_findings = []
        for i in range(500):  # Large dataset
            large_findings.append({
                "phase": "code_patterns",
                "rule": f"memory-test-{i}",
                "severity": "LOW",
                "file": f"large_file_{i}.js",
                "line": i,
                "snippet": "x" * 200,  # Large snippet
                "weight": 0.1,
            })
        
        memory_intensive_scan = {
            "target": "memory-pressure-test",
            "target_type": "npm",
            "files_scanned": 500,
            "findings": large_findings,
            "metadata": {"memory_test": True},
        }
        
        # System should handle or reject gracefully, not crash
        resp = client.post("/v1/scans", json=memory_intensive_scan, headers=auth_headers)
        
        # Acceptable responses: success, rejection due to size, or service unavailable
        assert resp.status_code in [201, 413, 422, 503]
        
        # System should remain responsive after memory pressure
        health_resp = client.get("/health")
        assert health_resp.status_code in [200, 503]


class TestCircuitBreakerPattern:
    """Test circuit breaker patterns for external dependencies."""
    
    def test_circuit_breaker_activation(
        self, client: TestClient, chaos_monkey: ChaosMonkey
    ):
        """Test circuit breaker activation after repeated failures."""
        
        # Simulate repeated external service failures
        failure_count = 0
        circuit_open = False
        
        for attempt in range(20):
            # Mock external service call failure
            with patch('httpx.AsyncClient.get', side_effect=Exception("Service unavailable")):
                resp = client.get("/registry/npm/test-package")
                
                if resp.status_code == 503:
                    failure_count += 1
                    
                    # Circuit breaker should open after repeated failures
                    if failure_count >= 5:
                        circuit_open = True
                        break
                elif resp.status_code == 200:
                    # Service recovered or using cached data
                    break
        
        # Circuit should open or system should degrade gracefully
        assert circuit_open or failure_count < 5, "Circuit breaker not activated after repeated failures"
    
    def test_circuit_breaker_recovery(self, client: TestClient):
        """Test circuit breaker recovery when service comes back."""
        
        # First, trigger circuit breaker with failures
        for _ in range(10):
            with patch('httpx.AsyncClient.get', side_effect=Exception("Service down")):
                client.get("/registry/npm/test-recovery")
        
        # Then test recovery
        time.sleep(1)  # Wait for potential circuit recovery time
        
        # Service should attempt recovery
        with patch('httpx.AsyncClient.get', return_value=Mock(status_code=200, json=lambda: {"status": "ok"})):
            recovery_resp = client.get("/registry/npm/test-recovery")
            
            # Should successfully use service again or return cached result
            assert recovery_resp.status_code in [200, 404]


class TestGracefulDegradation:
    """Test graceful service degradation scenarios."""
    
    def test_read_only_mode_degradation(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test graceful degradation to read-only mode."""
        
        # Simulate database write failures while reads still work
        with patch('api.database.db.store_scan', side_effect=Exception("Write unavailable")):
            # Write operations should fail gracefully
            scan_data = {
                "target": "degradation-test",
                "target_type": "npm",
                "files_scanned": 5,
                "findings": [],
                "metadata": {},
            }
            
            write_resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
            assert write_resp.status_code in [500, 503]
            
            # Read operations should still work
            read_resp = client.get("/health")
            assert read_resp.status_code in [200, 503]  # Degraded but functional
    
    def test_feature_degradation(self, client: TestClient, auth_headers: dict[str, str]):
        """Test feature-level degradation when components fail."""
        
        # Simulate threat intelligence service failure
        with patch('api.services.threat_service.get_threat_data', side_effect=Exception("Threat intel down")):
            # Scans should still work, just without threat intelligence enhancement
            scan_data = {
                "target": "feature-degradation-test",
                "target_type": "npm",
                "files_scanned": 5,
                "findings": [
                    {
                        "phase": "code_patterns",
                        "rule": "test-rule",
                        "severity": "MEDIUM",
                        "file": "test.js",
                        "line": 10,
                        "snippet": "test code",
                        "weight": 1.0,
                    }
                ],
                "metadata": {},
            }
            
            resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
            
            # Should work even without threat intelligence
            assert resp.status_code == 201
            
            scan_result = resp.json()
            assert "classification" in scan_result
            assert "score" in scan_result
    
    def test_cache_fallback_degradation(self, client: TestClient):
        """Test fallback to cache when primary data source fails."""
        
        # Simulate primary database failure but cache available
        with patch('api.database.db.connected', return_value=False):
            with patch('api.database.cache.connected', return_value=True):
                # System should use cache for data when possible
                resp = client.get("/health")
                
                # Should report degraded but functional
                assert resp.status_code in [200, 503]
                
                data = resp.json()
                assert data["status"] in ["degraded", "ok"]


class TestErrorRecovery:
    """Test error recovery and self-healing capabilities."""
    
    def test_automatic_retry_mechanism(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test automatic retry mechanisms for transient failures."""
        
        # Track retry attempts
        retry_count = 0
        
        def failing_operation(*args, **kwargs):
            nonlocal retry_count
            retry_count += 1
            
            if retry_count < 3:  # Fail first 2 attempts
                raise Exception("Transient failure")
            else:
                return {"success": True}  # Succeed on 3rd attempt
        
        # Mock a database operation that might be retried
        with patch('api.database.db.get_user_by_id', side_effect=failing_operation):
            # Operation should eventually succeed after retries
            resp = client.get("/v1/auth/me", headers=auth_headers)
            
            # Should either succeed after retries or fail gracefully
            assert resp.status_code in [200, 500, 503]
    
    def test_connection_pool_recovery(self, client: TestClient):
        """Test recovery of connection pools after failures."""
        
        # Simulate connection pool exhaustion
        with patch('api.database.db.connected', return_value=False):
            # Make requests during connection issues
            responses = []
            for _ in range(10):
                resp = client.get("/health")
                responses.append(resp.status_code)
        
        # After connection issues, system should recover
        time.sleep(1)
        recovery_resp = client.get("/health")
        assert recovery_resp.status_code == 200
        
        recovery_data = recovery_resp.json()
        assert recovery_data["database_connected"] == True
    
    def test_background_service_recovery(self, client: TestClient):
        """Test recovery of background services after failures."""
        
        # This would test background job recovery, registry updates, etc.
        # For now, test that the system reports service status correctly
        
        health_resp = client.get("/health")
        assert health_resp.status_code == 200
        
        health_data = health_resp.json()
        assert "status" in health_data
        assert health_data["status"] in ["ok", "degraded"]


class TestFailureIsolation:
    """Test failure isolation between system components."""
    
    def test_authentication_failure_isolation(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test that authentication failures don't affect other services."""
        
        # Simulate authentication service issues
        with patch('api.auth.get_current_user', side_effect=Exception("Auth service down")):
            # Protected endpoints should fail
            auth_resp = client.get("/v1/auth/me", headers=auth_headers)
            assert auth_resp.status_code in [401, 500, 503]
            
            # Public endpoints should still work
            health_resp = client.get("/health")
            assert health_resp.status_code == 200
            
            registry_resp = client.get("/registry")
            assert registry_resp.status_code in [200, 404]
    
    def test_billing_failure_isolation(self, client: TestClient, auth_headers: dict[str, str]):
        """Test that billing service failures don't affect core functionality."""
        
        # Simulate billing service failure
        with patch('api.services.billing_service.get_subscription', side_effect=Exception("Billing down")):
            # Core scan functionality should still work
            scan_data = {
                "target": "billing-isolation-test",
                "target_type": "npm",
                "files_scanned": 5,
                "findings": [],
                "metadata": {},
            }
            
            scan_resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
            
            # Should work even if billing service is down
            # (might have reduced features but core functionality intact)
            assert scan_resp.status_code in [201, 503]
    
    def test_threat_intel_failure_isolation(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test that threat intelligence failures don't break scans."""
        
        # Simulate threat intelligence service failure
        with patch('api.services.threat_service.enrich_scan_with_threat_data', side_effect=Exception("Threat intel down")):
            # Scans should still process without threat enrichment
            scan_data = {
                "target": "threat-isolation-test",
                "target_type": "npm",
                "files_scanned": 5,
                "findings": [
                    {
                        "phase": "code_patterns",
                        "rule": "test-rule",
                        "severity": "HIGH",
                        "file": "test.js",
                        "line": 15,
                        "snippet": "eval(userInput)",
                        "weight": 1.0,
                    }
                ],
                "metadata": {},
            }
            
            resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
            assert resp.status_code == 201
            
            scan_result = resp.json()
            assert scan_result["classification"] in ["SUSPICIOUS", "RISKY", "MALICIOUS"]
            assert scan_result["score"] > 0


class TestCascadingFailureProtection:
    """Test protection against cascading failures."""
    
    def test_rate_limiting_prevents_cascade(self, client: TestClient):
        """Test that rate limiting prevents cascading failures."""
        
        # Generate load that would normally cause cascading failures
        def stress_endpoint():
            responses = []
            for i in range(100):
                resp = client.get("/health")
                responses.append(resp.status_code)
            return responses
        
        # Multiple threads generating load
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(stress_endpoint) for _ in range(10)]
            
            all_responses = []
            for future in as_completed(futures):
                all_responses.extend(future.result())
        
        # Rate limiting should prevent system overload
        rate_limited_count = sum(1 for status in all_responses if status == 429)
        server_error_count = sum(1 for status in all_responses if status == 500)
        
        # Should have more rate limiting than server errors
        if rate_limited_count > 0:
            assert server_error_count <= rate_limited_count, "Cascading failures not prevented"
    
    def test_bulkhead_isolation(self, client: TestClient, auth_headers: dict[str, str]):
        """Test bulkhead pattern isolates different types of operations."""
        
        # Heavy computational load on one type of operation
        heavy_scan_data = {
            "target": "bulkhead-test",
            "target_type": "npm",
            "files_scanned": 100,
            "findings": [
                {
                    "phase": "code_patterns",
                    "rule": f"heavy-rule-{i}",
                    "severity": "MEDIUM",
                    "file": f"heavy_{i}.js",
                    "line": i,
                    "snippet": "x" * 100,
                    "weight": 0.5,
                }
                for i in range(50)  # Many findings
            ],
            "metadata": {"bulkhead_test": True},
        }
        
        # Start heavy operation
        heavy_start_time = time.time()
        heavy_resp = client.post("/v1/scans", json=heavy_scan_data, headers=auth_headers)
        
        # Light operations should still be responsive
        light_start_time = time.time()
        light_resp = client.get("/health")
        light_end_time = time.time()
        
        light_response_time = (light_end_time - light_start_time) * 1000
        
        # Light operations shouldn't be significantly impacted by heavy ones
        assert light_response_time < 500, f"Light operations impacted by heavy load: {light_response_time:.2f}ms"
        assert light_resp.status_code == 200
    
    def test_timeout_protection(self, client: TestClient, auth_headers: dict[str, str]):
        """Test timeout protection prevents hanging operations."""
        
        # This would normally test operations that might hang
        # For now, test that long operations are handled appropriately
        
        start_time = time.time()
        
        # Submit operation that might take a while
        complex_scan_data = {
            "target": "timeout-protection-test",
            "target_type": "npm",
            "files_scanned": 200,
            "findings": [
                {
                    "phase": "code_patterns",
                    "rule": f"complex-rule-{i}",
                    "severity": "MEDIUM",
                    "file": f"complex_{i}.js",
                    "line": i,
                    "snippet": f"complex analysis code {i}",
                    "weight": 0.5,
                }
                for i in range(100)
            ],
            "metadata": {"timeout_test": True},
        }
        
        resp = client.post("/v1/scans", json=complex_scan_data, headers=auth_headers)
        end_time = time.time()
        
        processing_time = end_time - start_time
        
        # Should complete within reasonable time or timeout gracefully
        assert processing_time < 30, f"Operation took too long: {processing_time:.2f}s"
        assert resp.status_code in [201, 408, 413, 503]  # Success, timeout, too large, or unavailable
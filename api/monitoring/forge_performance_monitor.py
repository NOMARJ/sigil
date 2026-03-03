"""
Forge Performance Monitoring System
Real-time performance tracking and alerting for production
"""

import asyncio
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import deque
import statistics


@dataclass
class PerformanceMetric:
    """Single performance measurement"""
    timestamp: str
    endpoint: str
    method: str
    duration_ms: float
    status_code: int
    cache_hit: bool = False
    error: Optional[str] = None


@dataclass
class PerformanceThreshold:
    """Performance threshold configuration"""
    endpoint_pattern: str
    max_duration_ms: float
    alert_threshold_ms: float


class ForgePerformanceMonitor:
    """Real-time performance monitoring for Forge Premium"""
    
    def __init__(self, window_size_minutes: int = 5):
        self.window_size = window_size_minutes * 60  # Convert to seconds
        self.metrics: deque = deque(maxlen=10000)  # Keep last 10k metrics
        self.alerts: List[Dict] = []
        self.start_time = time.time()
        
        # Performance thresholds by endpoint
        self.thresholds = [
            PerformanceThreshold("/forge/my-tools", 200, 500),
            PerformanceThreshold("/forge/my-tools/track", 300, 600),
            PerformanceThreshold("/forge/analytics/personal", 500, 1000),
            PerformanceThreshold("/forge/analytics/team", 500, 1000),
            PerformanceThreshold("/forge/tools/search", 300, 600),
            PerformanceThreshold("/forge/stacks", 300, 600),
        ]
        
        # Real-time statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_response_time": 0,
            "p50_response_time": 0,
            "p95_response_time": 0,
            "p99_response_time": 0,
            "requests_per_second": 0,
            "error_rate": 0,
            "cache_hit_rate": 0,
        }
    
    async def track_request(self, 
                           endpoint: str,
                           method: str,
                           duration_ms: float,
                           status_code: int,
                           cache_hit: bool = False,
                           error: Optional[str] = None):
        """Track a single request"""
        metric = PerformanceMetric(
            timestamp=datetime.now().isoformat(),
            endpoint=endpoint,
            method=method,
            duration_ms=duration_ms,
            status_code=status_code,
            cache_hit=cache_hit,
            error=error
        )
        
        self.metrics.append(metric)
        self.stats["total_requests"] += 1
        
        if 200 <= status_code < 400:
            self.stats["successful_requests"] += 1
        else:
            self.stats["failed_requests"] += 1
        
        if cache_hit:
            self.stats["cache_hits"] += 1
        else:
            self.stats["cache_misses"] += 1
        
        # Check for threshold violations
        await self.check_thresholds(metric)
        
        # Update real-time stats periodically
        if self.stats["total_requests"] % 100 == 0:
            await self.update_statistics()
    
    async def check_thresholds(self, metric: PerformanceMetric):
        """Check if metric violates any thresholds"""
        for threshold in self.thresholds:
            if metric.endpoint.startswith(threshold.endpoint_pattern):
                if metric.duration_ms > threshold.alert_threshold_ms:
                    alert = {
                        "timestamp": metric.timestamp,
                        "severity": "CRITICAL",
                        "endpoint": metric.endpoint,
                        "duration_ms": metric.duration_ms,
                        "threshold_ms": threshold.alert_threshold_ms,
                        "message": f"Response time {metric.duration_ms:.0f}ms exceeds critical threshold {threshold.alert_threshold_ms:.0f}ms"
                    }
                    self.alerts.append(alert)
                    await self.send_alert(alert)
                elif metric.duration_ms > threshold.max_duration_ms:
                    alert = {
                        "timestamp": metric.timestamp,
                        "severity": "WARNING",
                        "endpoint": metric.endpoint,
                        "duration_ms": metric.duration_ms,
                        "threshold_ms": threshold.max_duration_ms,
                        "message": f"Response time {metric.duration_ms:.0f}ms exceeds threshold {threshold.max_duration_ms:.0f}ms"
                    }
                    self.alerts.append(alert)
    
    async def send_alert(self, alert: Dict):
        """Send alert to monitoring system"""
        # In production, this would send to PagerDuty, Slack, etc.
        print(f"⚠️  PERFORMANCE ALERT: {alert['message']}")
    
    async def update_statistics(self):
        """Update real-time statistics"""
        if not self.metrics:
            return
        
        current_time = time.time()
        window_start = current_time - self.window_size
        
        # Filter metrics within window
        recent_metrics = [
            m for m in self.metrics
            if datetime.fromisoformat(m.timestamp).timestamp() > window_start
        ]
        
        if not recent_metrics:
            return
        
        # Calculate response times
        response_times = [m.duration_ms for m in recent_metrics]
        response_times.sort()
        
        self.stats["avg_response_time"] = statistics.mean(response_times)
        self.stats["p50_response_time"] = response_times[len(response_times) // 2]
        self.stats["p95_response_time"] = response_times[int(len(response_times) * 0.95)]
        self.stats["p99_response_time"] = response_times[int(len(response_times) * 0.99)]
        
        # Calculate rates
        time_range = (current_time - self.start_time)
        self.stats["requests_per_second"] = len(recent_metrics) / min(time_range, self.window_size)
        
        failed = sum(1 for m in recent_metrics if m.status_code >= 400)
        self.stats["error_rate"] = (failed / len(recent_metrics)) * 100
        
        cache_hits = sum(1 for m in recent_metrics if m.cache_hit)
        total_cacheable = sum(1 for m in recent_metrics if m.method == "GET")
        if total_cacheable > 0:
            self.stats["cache_hit_rate"] = (cache_hits / total_cacheable) * 100
    
    async def get_endpoint_statistics(self) -> Dict[str, Dict]:
        """Get statistics broken down by endpoint"""
        endpoint_stats = {}
        
        for metric in self.metrics:
            endpoint = metric.endpoint
            if endpoint not in endpoint_stats:
                endpoint_stats[endpoint] = {
                    "count": 0,
                    "total_time": 0,
                    "min_time": float('inf'),
                    "max_time": 0,
                    "errors": 0,
                    "cache_hits": 0,
                    "response_times": []
                }
            
            stats = endpoint_stats[endpoint]
            stats["count"] += 1
            stats["total_time"] += metric.duration_ms
            stats["min_time"] = min(stats["min_time"], metric.duration_ms)
            stats["max_time"] = max(stats["max_time"], metric.duration_ms)
            stats["response_times"].append(metric.duration_ms)
            
            if metric.status_code >= 400:
                stats["errors"] += 1
            if metric.cache_hit:
                stats["cache_hits"] += 1
        
        # Calculate aggregates
        for endpoint, stats in endpoint_stats.items():
            if stats["response_times"]:
                sorted_times = sorted(stats["response_times"])
                stats["avg_time"] = statistics.mean(sorted_times)
                stats["p50"] = sorted_times[len(sorted_times) // 2]
                stats["p95"] = sorted_times[int(len(sorted_times) * 0.95)]
                stats["p99"] = sorted_times[int(len(sorted_times) * 0.99)]
                del stats["response_times"]  # Remove raw data from output
                
                # Find threshold for this endpoint
                threshold = next(
                    (t for t in self.thresholds if endpoint.startswith(t.endpoint_pattern)),
                    None
                )
                if threshold:
                    stats["threshold_ms"] = threshold.max_duration_ms
                    stats["meets_threshold"] = stats["p95"] < threshold.max_duration_ms
        
        return endpoint_stats
    
    def get_health_status(self) -> Dict:
        """Get overall system health status"""
        health = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": time.time() - self.start_time,
            "metrics": self.stats.copy(),
            "alerts_count": len(self.alerts),
            "recent_alerts": self.alerts[-5:] if self.alerts else [],
            "checks": []
        }
        
        # Health checks
        checks = [
            {
                "name": "Response Time",
                "status": "pass" if self.stats["p95_response_time"] < 500 else "fail",
                "value": self.stats["p95_response_time"],
                "threshold": 500,
                "unit": "ms"
            },
            {
                "name": "Error Rate",
                "status": "pass" if self.stats["error_rate"] < 5 else "fail",
                "value": self.stats["error_rate"],
                "threshold": 5,
                "unit": "%"
            },
            {
                "name": "Cache Hit Rate",
                "status": "pass" if self.stats["cache_hit_rate"] > 80 else "warn",
                "value": self.stats["cache_hit_rate"],
                "threshold": 80,
                "unit": "%"
            },
            {
                "name": "Requests Per Second",
                "status": "pass",
                "value": self.stats["requests_per_second"],
                "threshold": None,
                "unit": "req/s"
            }
        ]
        
        health["checks"] = checks
        
        # Determine overall status
        failed_checks = sum(1 for c in checks if c["status"] == "fail")
        warn_checks = sum(1 for c in checks if c["status"] == "warn")
        
        if failed_checks > 0:
            health["status"] = "unhealthy"
        elif warn_checks > 0:
            health["status"] = "degraded"
        else:
            health["status"] = "healthy"
        
        return health
    
    async def generate_performance_report(self) -> Dict:
        """Generate comprehensive performance report"""
        await self.update_statistics()
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "monitoring_duration_seconds": time.time() - self.start_time,
            "summary": {
                "total_requests": self.stats["total_requests"],
                "successful_requests": self.stats["successful_requests"],
                "failed_requests": self.stats["failed_requests"],
                "error_rate": f"{self.stats['error_rate']:.2f}%",
                "avg_response_time": f"{self.stats['avg_response_time']:.2f}ms",
                "p50_response_time": f"{self.stats['p50_response_time']:.2f}ms",
                "p95_response_time": f"{self.stats['p95_response_time']:.2f}ms",
                "p99_response_time": f"{self.stats['p99_response_time']:.2f}ms",
                "cache_hit_rate": f"{self.stats['cache_hit_rate']:.2f}%",
                "requests_per_second": f"{self.stats['requests_per_second']:.2f}",
            },
            "health": self.get_health_status(),
            "endpoints": await self.get_endpoint_statistics(),
            "alerts": {
                "total": len(self.alerts),
                "critical": sum(1 for a in self.alerts if a["severity"] == "CRITICAL"),
                "warning": sum(1 for a in self.alerts if a["severity"] == "WARNING"),
                "recent": self.alerts[-10:] if self.alerts else []
            },
            "recommendations": self.generate_recommendations()
        }
        
        return report
    
    def generate_recommendations(self) -> List[Dict]:
        """Generate performance optimization recommendations"""
        recommendations = []
        
        # Check overall response time
        if self.stats["p95_response_time"] > 500:
            recommendations.append({
                "priority": "HIGH",
                "category": "Response Time",
                "issue": f"P95 response time ({self.stats['p95_response_time']:.0f}ms) exceeds 500ms",
                "action": "Optimize slow endpoints, add database indexes, or scale infrastructure"
            })
        
        # Check cache effectiveness
        if self.stats["cache_hit_rate"] < 80:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Caching",
                "issue": f"Cache hit rate ({self.stats['cache_hit_rate']:.1f}%) below 80%",
                "action": "Review cache TTL settings and cache key strategies"
            })
        
        # Check error rate
        if self.stats["error_rate"] > 1:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Reliability",
                "issue": f"Error rate ({self.stats['error_rate']:.2f}%) exceeds 1%",
                "action": "Investigate and fix errors in application logs"
            })
        
        # Check for endpoint-specific issues
        endpoint_stats = asyncio.run(self.get_endpoint_statistics())
        for endpoint, stats in endpoint_stats.items():
            if not stats.get("meets_threshold", True):
                recommendations.append({
                    "priority": "HIGH",
                    "category": "Endpoint Performance",
                    "issue": f"{endpoint} P95 ({stats['p95']:.0f}ms) exceeds threshold ({stats.get('threshold_ms', 'N/A')}ms)",
                    "action": f"Optimize {endpoint} endpoint - consider caching, query optimization, or async processing"
                })
        
        return recommendations


class PerformanceMonitoringMiddleware:
    """Middleware for automatic performance tracking"""
    
    def __init__(self, monitor: ForgePerformanceMonitor):
        self.monitor = monitor
    
    async def __call__(self, request, call_next):
        """Track request performance automatically"""
        start_time = time.perf_counter()
        
        # Check cache header
        cache_hit = request.headers.get("X-Cache-Hit", "false").lower() == "true"
        
        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            # Track the request
            await self.monitor.track_request(
                endpoint=str(request.url.path),
                method=request.method,
                duration_ms=duration_ms,
                status_code=response.status_code,
                cache_hit=cache_hit
            )
            
            # Add performance headers
            response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"
            response.headers["X-Performance-Status"] = self.monitor.get_health_status()["status"]
            
            return response
            
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            await self.monitor.track_request(
                endpoint=str(request.url.path),
                method=request.method,
                duration_ms=duration_ms,
                status_code=500,
                cache_hit=cache_hit,
                error=str(e)
            )
            
            raise


# Singleton instance for global monitoring
_monitor_instance: Optional[ForgePerformanceMonitor] = None


def get_monitor() -> ForgePerformanceMonitor:
    """Get or create the global monitor instance"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = ForgePerformanceMonitor()
    return _monitor_instance


async def start_monitoring_server(port: int = 9090):
    """Start a monitoring endpoint server"""
    from aiohttp import web
    
    monitor = get_monitor()
    
    async def health_check(request):
        """Health check endpoint"""
        health = monitor.get_health_status()
        status_code = 200 if health["status"] == "healthy" else 503
        return web.json_response(health, status=status_code)
    
    async def metrics(request):
        """Metrics endpoint"""
        return web.json_response(monitor.stats)
    
    async def report(request):
        """Full performance report"""
        report_data = await monitor.generate_performance_report()
        return web.json_response(report_data)
    
    app = web.Application()
    app.router.add_get("/health", health_check)
    app.router.add_get("/metrics", metrics)
    app.router.add_get("/report", report)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    
    print(f"Performance monitoring server started on port {port}")
    print(f"  Health: http://localhost:{port}/health")
    print(f"  Metrics: http://localhost:{port}/metrics")
    print(f"  Report: http://localhost:{port}/report")
    
    return runner


if __name__ == "__main__":
    # Example usage and testing
    async def test_monitoring():
        monitor = ForgePerformanceMonitor()
        
        # Simulate some requests
        endpoints = [
            ("/forge/my-tools", "GET", 50, 200, True),
            ("/forge/my-tools/track", "POST", 150, 201, False),
            ("/forge/analytics/personal", "GET", 450, 200, False),
            ("/forge/tools/search", "GET", 80, 200, True),
            ("/forge/my-tools", "GET", 45, 200, True),
            ("/forge/analytics/team", "GET", 600, 200, False),  # Slow request
            ("/forge/my-tools", "GET", 350, 500, False),  # Error
        ]
        
        for endpoint, method, duration, status, cache_hit in endpoints:
            await monitor.track_request(endpoint, method, duration, status, cache_hit)
        
        # Generate report
        report = await monitor.generate_performance_report()
        
        print(json.dumps(report, indent=2))
        
        # Save report
        with open("performance_monitoring_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print("\nReport saved to: performance_monitoring_report.json")
    
    asyncio.run(test_monitoring())
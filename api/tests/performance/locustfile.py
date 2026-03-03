"""
Forge Premium Performance Testing with Locust
Load testing for all Forge API endpoints to ensure performance under load
"""

import json
import random
import time
from datetime import datetime, timedelta

from locust import HttpUser, TaskSet, task, between, events
from locust.runners import MasterRunner
import logging

logger = logging.getLogger(__name__)

# Performance thresholds
PERFORMANCE_THRESHOLDS = {
    "GET /forge/my-tools": 200,           # 200ms
    "POST /forge/my-tools/track": 300,    # 300ms
    "DELETE /forge/my-tools/": 200,       # 200ms
    "GET /forge/analytics/personal": 500, # 500ms (complex queries)
    "GET /forge/analytics/team": 500,     # 500ms
    "GET /forge/stacks": 300,            # 300ms
    "POST /forge/stacks": 400,           # 400ms
    "GET /forge/tools/search": 300,      # 300ms
    "GET /forge/tools/recommended": 400, # 400ms
}

# Test data
MOCK_TOOLS = [
    {
        "name": "postgres-mcp",
        "repository_url": "https://github.com/example/postgres-mcp",
        "ecosystem": "mcp",
        "description": "PostgreSQL connector for MCP",
        "category": "database"
    },
    {
        "name": "redis-cache",
        "repository_url": "https://github.com/example/redis-cache",
        "ecosystem": "npm",
        "description": "Redis caching library",
        "category": "caching"
    },
    {
        "name": "auth-handler",
        "repository_url": "https://github.com/example/auth-handler",
        "ecosystem": "pip",
        "description": "Authentication handler",
        "category": "security"
    }
]

MOCK_STACKS = [
    {
        "name": "Full Stack Development",
        "description": "Complete development stack",
        "tools": ["postgres-mcp", "redis-cache"],
        "is_public": True
    },
    {
        "name": "Security Stack",
        "description": "Security and authentication tools",
        "tools": ["auth-handler"],
        "is_public": False
    }
]


class ForgeUserBehavior(TaskSet):
    """Simulates typical Forge user behavior"""
    
    def on_start(self):
        """Login and setup user session"""
        # Mock authentication - in real tests, perform actual login
        self.auth_token = "mock_jwt_token"
        self.headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
        self.tracked_tools = []
        self.created_stacks = []
    
    @task(3)
    def get_tracked_tools(self):
        """Most frequent operation - viewing tracked tools"""
        with self.client.get(
            "/forge/my-tools",
            headers=self.headers,
            catch_response=True,
            name="GET /forge/my-tools"
        ) as response:
            if response.elapsed.total_seconds() * 1000 > PERFORMANCE_THRESHOLDS["GET /forge/my-tools"]:
                response.failure(f"Too slow: {response.elapsed.total_seconds()*1000:.0f}ms")
            elif response.status_code != 200:
                response.failure(f"Got status code {response.status_code}")
            else:
                response.success()
                data = response.json()
                self.tracked_tools = data.get("tools", [])
    
    @task(2)
    def track_new_tool(self):
        """Track a new tool"""
        tool_data = random.choice(MOCK_TOOLS).copy()
        tool_data["tool_id"] = f"tool-{int(time.time()*1000)}-{random.randint(1000, 9999)}"
        
        with self.client.post(
            "/forge/my-tools/track",
            json=tool_data,
            headers=self.headers,
            catch_response=True,
            name="POST /forge/my-tools/track"
        ) as response:
            threshold = PERFORMANCE_THRESHOLDS["POST /forge/my-tools/track"]
            if response.elapsed.total_seconds() * 1000 > threshold:
                response.failure(f"Too slow: {response.elapsed.total_seconds()*1000:.0f}ms")
            elif response.status_code not in [200, 201]:
                response.failure(f"Got status code {response.status_code}")
            else:
                response.success()
                self.tracked_tools.append(tool_data["tool_id"])
    
    @task(1)
    def untrack_tool(self):
        """Untrack a tool if any are tracked"""
        if self.tracked_tools:
            tool_id = random.choice(self.tracked_tools)
            
            with self.client.delete(
                f"/forge/my-tools/{tool_id}",
                headers=self.headers,
                catch_response=True,
                name="DELETE /forge/my-tools/"
            ) as response:
                threshold = PERFORMANCE_THRESHOLDS["DELETE /forge/my-tools/"]
                if response.elapsed.total_seconds() * 1000 > threshold:
                    response.failure(f"Too slow: {response.elapsed.total_seconds()*1000:.0f}ms")
                elif response.status_code not in [200, 204]:
                    response.failure(f"Got status code {response.status_code}")
                else:
                    response.success()
                    self.tracked_tools.remove(tool_id)
    
    @task(2)
    def get_personal_analytics(self):
        """Get personal analytics - complex query"""
        params = {
            "start_date": (datetime.now() - timedelta(days=30)).isoformat(),
            "end_date": datetime.now().isoformat()
        }
        
        with self.client.get(
            "/forge/analytics/personal",
            params=params,
            headers=self.headers,
            catch_response=True,
            name="GET /forge/analytics/personal"
        ) as response:
            threshold = PERFORMANCE_THRESHOLDS["GET /forge/analytics/personal"]
            if response.elapsed.total_seconds() * 1000 > threshold:
                response.failure(f"Too slow: {response.elapsed.total_seconds()*1000:.0f}ms")
            elif response.status_code != 200:
                response.failure(f"Got status code {response.status_code}")
            else:
                response.success()
    
    @task(1)
    def get_team_analytics(self):
        """Get team analytics - aggregated data"""
        params = {
            "start_date": (datetime.now() - timedelta(days=7)).isoformat(),
            "end_date": datetime.now().isoformat(),
            "team_id": "test-team-123"
        }
        
        with self.client.get(
            "/forge/analytics/team",
            params=params,
            headers=self.headers,
            catch_response=True,
            name="GET /forge/analytics/team"
        ) as response:
            threshold = PERFORMANCE_THRESHOLDS["GET /forge/analytics/team"]
            if response.elapsed.total_seconds() * 1000 > threshold:
                response.failure(f"Too slow: {response.elapsed.total_seconds()*1000:.0f}ms")
            elif response.status_code != 200:
                response.failure(f"Got status code {response.status_code}")
            else:
                response.success()
    
    @task(2)
    def search_tools(self):
        """Search for tools"""
        search_terms = ["database", "auth", "cache", "api", "security"]
        params = {
            "q": random.choice(search_terms),
            "page": random.randint(1, 3),
            "limit": 20
        }
        
        with self.client.get(
            "/forge/tools/search",
            params=params,
            headers=self.headers,
            catch_response=True,
            name="GET /forge/tools/search"
        ) as response:
            threshold = PERFORMANCE_THRESHOLDS["GET /forge/tools/search"]
            if response.elapsed.total_seconds() * 1000 > threshold:
                response.failure(f"Too slow: {response.elapsed.total_seconds()*1000:.0f}ms")
            elif response.status_code != 200:
                response.failure(f"Got status code {response.status_code}")
            else:
                response.success()
    
    @task(1)
    def get_recommended_tools(self):
        """Get recommended tools based on profile"""
        with self.client.get(
            "/forge/tools/recommended",
            headers=self.headers,
            catch_response=True,
            name="GET /forge/tools/recommended"
        ) as response:
            threshold = PERFORMANCE_THRESHOLDS["GET /forge/tools/recommended"]
            if response.elapsed.total_seconds() * 1000 > threshold:
                response.failure(f"Too slow: {response.elapsed.total_seconds()*1000:.0f}ms")
            elif response.status_code != 200:
                response.failure(f"Got status code {response.status_code}")
            else:
                response.success()
    
    @task(1)
    def manage_stacks(self):
        """Create and manage tool stacks"""
        # Get existing stacks
        with self.client.get(
            "/forge/stacks",
            headers=self.headers,
            catch_response=True,
            name="GET /forge/stacks"
        ) as response:
            threshold = PERFORMANCE_THRESHOLDS["GET /forge/stacks"]
            if response.elapsed.total_seconds() * 1000 > threshold:
                response.failure(f"Too slow: {response.elapsed.total_seconds()*1000:.0f}ms")
            elif response.status_code != 200:
                response.failure(f"Got status code {response.status_code}")
            else:
                response.success()
        
        # Create a new stack occasionally
        if random.random() < 0.3:  # 30% chance
            stack_data = random.choice(MOCK_STACKS).copy()
            stack_data["name"] = f"{stack_data['name']} {int(time.time())}"
            
            with self.client.post(
                "/forge/stacks",
                json=stack_data,
                headers=self.headers,
                catch_response=True,
                name="POST /forge/stacks"
            ) as response:
                threshold = PERFORMANCE_THRESHOLDS["POST /forge/stacks"]
                if response.elapsed.total_seconds() * 1000 > threshold:
                    response.failure(f"Too slow: {response.elapsed.total_seconds()*1000:.0f}ms")
                elif response.status_code not in [200, 201]:
                    response.failure(f"Got status code {response.status_code}")
                else:
                    response.success()
                    data = response.json()
                    self.created_stacks.append(data.get("id"))


class ForgeLoadTestUser(HttpUser):
    """Forge API load test user"""
    tasks = [ForgeUserBehavior]
    wait_time = between(1, 3)  # Wait 1-3 seconds between tasks
    host = "http://localhost:8000"  # API base URL


# Custom statistics tracking
performance_stats = {
    "start_time": None,
    "requests": [],
    "errors": [],
    "response_times": {},
}


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, **kwargs):
    """Track request statistics"""
    if not performance_stats["start_time"]:
        performance_stats["start_time"] = time.time()
    
    request_data = {
        "timestamp": time.time(),
        "type": request_type,
        "name": name,
        "response_time": response_time,
        "response_length": response_length,
        "success": exception is None
    }
    
    performance_stats["requests"].append(request_data)
    
    # Track response times by endpoint
    if name not in performance_stats["response_times"]:
        performance_stats["response_times"][name] = []
    performance_stats["response_times"][name].append(response_time)
    
    if exception:
        performance_stats["errors"].append({
            "timestamp": time.time(),
            "name": name,
            "exception": str(exception)
        })


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Generate performance report on test completion"""
    if isinstance(environment.runner, MasterRunner):
        print("\n" + "="*60)
        print("FORGE API PERFORMANCE TEST SUMMARY")
        print("="*60)
        
        # Calculate statistics
        total_requests = len(performance_stats["requests"])
        successful_requests = sum(1 for r in performance_stats["requests"] if r["success"])
        failed_requests = total_requests - successful_requests
        
        print(f"\nTotal Requests: {total_requests}")
        print(f"Successful: {successful_requests} ({successful_requests/total_requests*100:.1f}%)")
        print(f"Failed: {failed_requests} ({failed_requests/total_requests*100:.1f}%)")
        
        print("\n" + "-"*40)
        print("Response Time Statistics by Endpoint:")
        print("-"*40)
        
        for endpoint, times in performance_stats["response_times"].items():
            if times:
                times_sorted = sorted(times)
                p50 = times_sorted[int(len(times_sorted) * 0.5)]
                p95 = times_sorted[int(len(times_sorted) * 0.95)]
                p99 = times_sorted[int(len(times_sorted) * 0.99)]
                avg = sum(times) / len(times)
                threshold = PERFORMANCE_THRESHOLDS.get(endpoint, 500)
                passed = p95 < threshold
                
                print(f"\n{endpoint}:")
                print(f"  Count: {len(times)}")
                print(f"  Avg: {avg:.0f}ms")
                print(f"  P50: {p50:.0f}ms")
                print(f"  P95: {p95:.0f}ms (Threshold: {threshold}ms) {'✓' if passed else '✗'}")
                print(f"  P99: {p99:.0f}ms")
        
        print("\n" + "-"*40)
        print("Performance Test Result:")
        print("-"*40)
        
        # Check if all endpoints meet thresholds
        all_passed = True
        for endpoint, threshold in PERFORMANCE_THRESHOLDS.items():
            if endpoint in performance_stats["response_times"]:
                times = performance_stats["response_times"][endpoint]
                if times:
                    p95 = sorted(times)[int(len(times) * 0.95)]
                    if p95 > threshold:
                        all_passed = False
                        print(f"✗ {endpoint}: P95={p95:.0f}ms exceeds {threshold}ms")
        
        if all_passed:
            print("✓ All endpoints meet performance thresholds!")
        else:
            print("\n⚠️  Some endpoints exceed performance thresholds")
        
        # Save detailed report
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_requests": total_requests,
                "successful": successful_requests,
                "failed": failed_requests,
                "duration": time.time() - performance_stats["start_time"],
            },
            "endpoints": {}
        }
        
        for endpoint, times in performance_stats["response_times"].items():
            if times:
                times_sorted = sorted(times)
                report["endpoints"][endpoint] = {
                    "count": len(times),
                    "avg": sum(times) / len(times),
                    "min": min(times),
                    "max": max(times),
                    "p50": times_sorted[int(len(times_sorted) * 0.5)],
                    "p95": times_sorted[int(len(times_sorted) * 0.95)],
                    "p99": times_sorted[int(len(times_sorted) * 0.99)],
                    "threshold": PERFORMANCE_THRESHOLDS.get(endpoint, 500),
                    "passed": times_sorted[int(len(times_sorted) * 0.95)] < PERFORMANCE_THRESHOLDS.get(endpoint, 500)
                }
        
        # Save report to file
        with open("forge_performance_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print("\nDetailed report saved to: forge_performance_report.json")
        print("="*60)
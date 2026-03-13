#!/usr/bin/env python3
"""
Sigil Forge Load Testing with Locust

Realistic load testing scenarios for Forge APIs simulating various user patterns.
Run with: locust -f forge_load_test.py --host=http://localhost:8000
"""

from locust import HttpUser, task, between, events
import random
import json
from datetime import datetime


class ForgeAPIUser(HttpUser):
    """Simulates a user interacting with Forge APIs."""

    wait_time = between(1, 3)  # Wait 1-3 seconds between tasks

    def on_start(self):
        """Initialize user session."""
        self.search_queries = [
            "postgres",
            "database",
            "github",
            "api",
            "file",
            "authentication",
            "redis",
            "mongodb",
            "docker",
            "kubernetes",
            "slack",
            "stripe",
            "aws",
            "azure",
            "testing",
        ]

        self.categories = [
            "Database",
            "API Integration",
            "Code Tools",
            "File System",
            "AI/LLM",
            "Security",
            "DevOps",
            "Communication",
        ]

        self.ecosystems = ["clawhub", "mcp", "npm", "pypi"]

        self.packages = [
            ("clawhub", "github-skill"),
            ("mcp", "postgres-mcp"),
            ("clawhub", "web-search"),
            ("mcp", "filesystem-mcp"),
        ]

        self.use_cases = [
            "Building a PostgreSQL-backed AI agent",
            "GitHub integration for code review",
            "Web research and content extraction",
            "File system operations",
            "API testing and monitoring",
        ]

    @task(30)
    def search_tools(self):
        """Most common operation - searching for tools."""
        query = random.choice(self.search_queries)
        params = {"q": query, "limit": random.choice([10, 20, 50])}

        # Sometimes add filters
        if random.random() < 0.3:
            params["ecosystem"] = random.choice(self.ecosystems)
        if random.random() < 0.2:
            params["category"] = random.choice(self.categories)

        with self.client.get(
            "/api/forge/search", params=params, catch_response=True
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if "results" in data:
                    response.success()
                else:
                    response.failure("Invalid response format")
            else:
                response.failure(f"Status {response.status_code}")

    @task(15)
    def browse_category(self):
        """Browse tools by category."""
        category = random.choice(self.categories)
        params = {"limit": random.choice([20, 50])}

        if random.random() < 0.3:
            params["ecosystem"] = random.choice(self.ecosystems)

        self.client.get(
            f"/api/forge/browse/{category}",
            params=params,
            name="/api/forge/browse/[category]",
        )

    @task(10)
    def get_tool_details(self):
        """Get detailed information about a specific tool."""
        ecosystem, package = random.choice(self.packages)
        self.client.get(
            f"/api/forge/tool/{ecosystem}/{package}",
            name="/api/forge/tool/[ecosystem]/[package]",
        )

    @task(5)
    def get_tool_matches(self):
        """Get compatible tools for a specific tool."""
        ecosystem, package = random.choice(self.packages)
        params = {"limit": 10}
        self.client.get(
            f"/api/forge/tool/{ecosystem}/{package}/matches",
            params=params,
            name="/api/forge/tool/[ecosystem]/[package]/matches",
        )

    @task(3)
    def generate_stack(self):
        """Generate a Forge Stack (computationally expensive)."""
        use_case = random.choice(self.use_cases)
        json_data = {
            "use_case": use_case,
            "max_tools": random.choice([3, 5, 10]),
            "min_trust_score": random.choice([60.0, 70.0, 80.0]),
        }

        with self.client.post(
            "/api/forge/stack", json=json_data, catch_response=True
        ) as response:
            if response.elapsed.total_seconds() > 2:
                response.failure(
                    f"Slow response: {response.elapsed.total_seconds():.2f}s"
                )
            elif response.status_code == 200:
                response.success()

    @task(8)
    def get_categories(self):
        """Get list of all categories."""
        self.client.get("/api/forge/categories")

    @task(5)
    def get_stats(self):
        """Get Forge statistics."""
        self.client.get("/api/forge/stats")

    @task(2)
    def mcp_search(self):
        """MCP-compatible search (agent traffic)."""
        query = random.choice(self.search_queries)
        params = {
            "query": query,
            "type": random.choice(["skill", "mcp", "both"]),
            "limit": 10,
        }
        self.client.get("/api/forge/mcp/search", params=params)

    @task(1)
    def mcp_check(self):
        """MCP-compatible tool check (agent traffic)."""
        ecosystem, package = random.choice(self.packages)
        params = {"name": package, "ecosystem": ecosystem}
        self.client.get("/api/forge/mcp/check", params=params)


class HeavyUser(HttpUser):
    """Simulates a power user or automated system making many requests."""

    wait_time = between(0.1, 0.5)  # Much faster request rate

    def on_start(self):
        """Initialize heavy user session."""
        self.search_cache = []

    @task(50)
    def rapid_search(self):
        """Rapid-fire search requests."""
        # Sometimes repeat searches (cache testing)
        if self.search_cache and random.random() < 0.3:
            query = random.choice(self.search_cache)
        else:
            query = f"test-{random.randint(1, 100)}"
            self.search_cache.append(query)
            if len(self.search_cache) > 20:
                self.search_cache.pop(0)

        params = {"q": query, "limit": 100}
        self.client.get("/api/forge/search", params=params)

    @task(30)
    def bulk_browse(self):
        """Browse multiple categories quickly."""
        categories = ["Database", "API Integration", "Code Tools"]
        for category in categories:
            self.client.get(
                f"/api/forge/browse/{category}",
                params={"limit": 100},
                name="/api/forge/browse/[category]",
            )

    @task(20)
    def parallel_tool_lookup(self):
        """Look up multiple tools in parallel."""
        packages = [
            ("clawhub", f"skill-{random.randint(1, 50)}"),
            ("mcp", f"mcp-{random.randint(1, 50)}"),
        ]
        for ecosystem, package in packages:
            self.client.get(
                f"/api/forge/tool/{ecosystem}/{package}",
                name="/api/forge/tool/[ecosystem]/[package]",
            )


class AgentUser(HttpUser):
    """Simulates AI agent traffic patterns."""

    wait_time = between(2, 5)

    @task(40)
    def agent_search_workflow(self):
        """Typical agent search workflow."""
        # 1. Search for tools
        search_params = {"query": "database postgres", "type": "both", "limit": 5}
        response = self.client.get("/api/forge/mcp/search", params=search_params)

        if response.status_code == 200:
            # 2. Check specific tools from results
            data = response.json()
            if "tools" in data and data["tools"]:
                tool = random.choice(data["tools"][:3])
                check_params = {
                    "name": tool.get("name", "unknown"),
                    "ecosystem": tool.get("ecosystem", "unknown"),
                }
                self.client.get("/api/forge/mcp/check", params=check_params)

    @task(30)
    def agent_stack_generation(self):
        """Agent requesting tool stacks."""
        use_cases = [
            "I need to connect to PostgreSQL and perform queries",
            "Help me integrate with GitHub API",
            "I want to search the web and extract content",
            "Set up file system operations with git support",
        ]

        params = {"use_case": random.choice(use_cases)}
        self.client.get("/api/forge/mcp/stack", params=params)

    @task(30)
    def agent_capability_search(self):
        """Agent searching by capability."""
        capabilities = [
            "reads_files",
            "makes_network_calls",
            "accesses_database",
            "handles_credentials",
            "generates_content",
        ]

        params = {"query": random.choice(capabilities), "type": "both", "limit": 10}
        self.client.get("/api/forge/mcp/search", params=params)


class StressTestUser(HttpUser):
    """Stress testing with extreme load patterns."""

    wait_time = between(0, 0.1)  # Almost no wait

    @task
    def stress_search(self):
        """Stress test the search endpoint."""
        # Generate random complex queries
        words = ["test", "api", "database", "file", "system", "tool", "integration"]
        query = " ".join(random.sample(words, random.randint(2, 5)))

        params = {
            "q": query,
            "ecosystem": random.choice(["clawhub", "mcp", None]),
            "category": random.choice(["Database", "API Integration", None]),
            "limit": random.choice([10, 50, 100, 200]),
        }

        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}

        with self.client.get(
            "/api/forge/search", params=params, catch_response=True
        ) as response:
            # Custom validation
            if response.elapsed.total_seconds() > 1:
                response.failure(
                    f"Response too slow: {response.elapsed.total_seconds():.2f}s"
                )


# Custom event handlers for detailed monitoring
@events.init.add_listener
def on_locust_init(environment, **kwargs):
    """Initialize custom monitoring."""
    print("Load test initialized")
    print(f"Target host: {environment.host}")


@events.request.add_listener
def on_request(
    request_type,
    name,
    response_time,
    response_length,
    response,
    context,
    exception,
    **kwargs,
):
    """Custom request monitoring."""
    if exception:
        print(f"Request failed: {name} - {exception}")
    elif response_time > 1000:  # Log slow requests (>1s)
        print(f"Slow request: {name} - {response_time}ms")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Generate summary report."""
    print("\n" + "=" * 60)
    print(" LOAD TEST SUMMARY")
    print("=" * 60)

    stats = environment.stats

    print(f"\nTotal Requests: {stats.total.num_requests}")
    print(f"Total Failures: {stats.total.num_failures}")
    print(f"Failure Rate: {stats.total.fail_ratio:.2%}")
    print(f"Average Response Time: {stats.total.avg_response_time:.2f}ms")
    print(f"Median Response Time: {stats.total.median_response_time:.2f}ms")
    print(f"95th Percentile: {stats.total.get_response_time_percentile(0.95):.2f}ms")
    print(f"99th Percentile: {stats.total.get_response_time_percentile(0.99):.2f}ms")

    print("\nTop 5 Slowest Endpoints:")
    sorted_entries = sorted(
        stats.entries.values(), key=lambda x: x.avg_response_time, reverse=True
    )
    for entry in sorted_entries[:5]:
        print(f"  {entry.name}: {entry.avg_response_time:.2f}ms avg")

    print("\nEndpoints with Failures:")
    for entry in stats.entries.values():
        if entry.num_failures > 0:
            print(
                f"  {entry.name}: {entry.num_failures} failures ({entry.fail_ratio:.2%})"
            )

    # Export detailed results
    results = {
        "timestamp": datetime.now().isoformat(),
        "total_requests": stats.total.num_requests,
        "total_failures": stats.total.num_failures,
        "failure_rate": stats.total.fail_ratio,
        "response_times": {
            "average": stats.total.avg_response_time,
            "median": stats.total.median_response_time,
            "p95": stats.total.get_response_time_percentile(0.95),
            "p99": stats.total.get_response_time_percentile(0.99),
            "min": stats.total.min_response_time,
            "max": stats.total.max_response_time,
        },
        "endpoints": {},
    }

    for name, entry in stats.entries.items():
        results["endpoints"][name] = {
            "requests": entry.num_requests,
            "failures": entry.num_failures,
            "avg_response_time": entry.avg_response_time,
            "median_response_time": entry.median_response_time,
            "min_response_time": entry.min_response_time,
            "max_response_time": entry.max_response_time,
        }

    filename = (
        f"forge_load_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nDetailed results exported to {filename}")


# Load test scenarios
class LoadTestScenarios:
    """Predefined load test scenarios."""

    @staticmethod
    def normal_load():
        """Normal daily traffic pattern."""
        return {
            "users": [
                (ForgeAPIUser, 30),  # 30 normal users
                (AgentUser, 10),  # 10 AI agents
            ],
            "spawn_rate": 2,  # 2 users per second
            "duration": 300,  # 5 minutes
        }

    @staticmethod
    def peak_load():
        """Peak traffic (product launch, high activity)."""
        return {
            "users": [
                (ForgeAPIUser, 100),  # 100 normal users
                (AgentUser, 50),  # 50 AI agents
                (HeavyUser, 10),  # 10 power users
            ],
            "spawn_rate": 10,
            "duration": 600,  # 10 minutes
        }

    @staticmethod
    def stress_test():
        """Stress test to find breaking point."""
        return {
            "users": [
                (StressTestUser, 200),  # 200 stress users
                (HeavyUser, 50),  # 50 heavy users
            ],
            "spawn_rate": 50,
            "duration": 300,
        }

    @staticmethod
    def sustained_load():
        """Sustained load for memory leak detection."""
        return {
            "users": [
                (ForgeAPIUser, 50),
                (AgentUser, 25),
            ],
            "spawn_rate": 5,
            "duration": 3600,  # 1 hour
        }


# CLI runner for different scenarios
if __name__ == "__main__":
    import sys
    import os

    # Check if running directly (not via locust CLI)
    if len(sys.argv) > 1 and sys.argv[1] in ["normal", "peak", "stress", "sustained"]:
        scenario = sys.argv[1]
        host = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000"

        print(f"Running {scenario} load test against {host}")

        # Get scenario configuration
        scenarios = {
            "normal": LoadTestScenarios.normal_load(),
            "peak": LoadTestScenarios.peak_load(),
            "stress": LoadTestScenarios.stress_test(),
            "sustained": LoadTestScenarios.sustained_load(),
        }

        config = scenarios[scenario]

        # Run via locust CLI
        user_classes = ",".join([u.__name__ for u, _ in config["users"]])
        user_counts = ",".join([str(c) for _, c in config["users"]])

        cmd = f"locust -f {__file__} --host={host} --headless"
        cmd += f" --users={sum(c for _, c in config['users'])}"
        cmd += f" --spawn-rate={config['spawn_rate']}"
        cmd += f" --run-time={config['duration']}s"

        print(f"Executing: {cmd}")
        os.system(cmd)
    else:
        print("Usage:")
        print(
            "  Direct: python forge_load_test.py [normal|peak|stress|sustained] [host]"
        )
        print("  Locust: locust -f forge_load_test.py --host=http://localhost:8000")
        print("\nFor web UI: locust -f forge_load_test.py --host=http://localhost:8000")
        print("Then open http://localhost:8089")

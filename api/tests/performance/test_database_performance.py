"""
Database Performance Testing for Forge Premium Features
Analyzes query performance, suggests indexes, and validates optimization
"""

import asyncio
import json
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, List

import pytest

asyncpg = pytest.importorskip("asyncpg")


class DatabasePerformanceTester:
    """Test and optimize database queries for Forge features"""

    def __init__(self, database_url: str):
        self.database_url = database_url
        self.performance_results = []
        self.optimization_suggestions = []

    @asynccontextmanager
    async def get_connection(self):
        """Get database connection with performance monitoring"""
        conn = await asyncpg.connect(self.database_url)
        try:
            yield conn
        finally:
            await conn.close()

    async def analyze_query(
        self, conn: asyncpg.Connection, query: str, params: List = None
    ) -> Dict:
        """Analyze a single query's performance"""
        # Get query plan
        explain_query = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {query}"

        try:
            # Execute EXPLAIN ANALYZE
            start_time = time.perf_counter()
            if params:
                result = await conn.fetchval(explain_query, *params)
            else:
                result = await conn.fetchval(explain_query)
            execution_time = (time.perf_counter() - start_time) * 1000  # Convert to ms

            plan = json.loads(result)[0]

            return {
                "query": query,
                "execution_time_ms": execution_time,
                "planning_time_ms": plan["Planning Time"],
                "execution_time_actual_ms": plan["Execution Time"],
                "total_cost": plan["Plan"]["Total Cost"],
                "rows_returned": plan["Plan"]["Actual Rows"],
                "shared_buffers_hit": plan["Plan"].get("Shared Hit Blocks", 0),
                "shared_buffers_read": plan["Plan"].get("Shared Read Blocks", 0),
                "temp_buffers_read": plan["Plan"].get("Temp Read Blocks", 0),
                "plan": plan["Plan"],
            }
        except Exception as e:
            return {"query": query, "error": str(e)}

    async def test_forge_queries(self):
        """Test all critical Forge queries"""
        async with self.get_connection() as conn:
            print("\n=== FORGE DATABASE PERFORMANCE ANALYSIS ===\n")

            # Test user_id for queries
            test_user_id = "test-user-123"
            test_team_id = "test-team-456"

            # Define critical queries to test
            queries = [
                # 1. Get user's tracked tools
                {
                    "name": "Get User Tools",
                    "query": """
                        SELECT t.*, ut.tracked_at, ut.notes, ut.version_override
                        FROM forge_user_tools ut
                        JOIN forge_tools t ON ut.tool_id = t.id
                        WHERE ut.user_id = $1
                        ORDER BY ut.tracked_at DESC
                    """,
                    "params": [test_user_id],
                    "threshold_ms": 50,
                },
                # 2. Analytics - Tool usage over time
                {
                    "name": "Analytics - Usage Timeline",
                    "query": """
                        SELECT 
                            DATE_TRUNC('day', timestamp) as day,
                            tool_id,
                            COUNT(*) as usage_count,
                            AVG(duration_ms) as avg_duration
                        FROM forge_analytics_events
                        WHERE user_id = $1 
                            AND timestamp > $2
                        GROUP BY day, tool_id
                        ORDER BY day DESC
                    """,
                    "params": [test_user_id, datetime.now() - timedelta(days=30)],
                    "threshold_ms": 100,
                },
                # 3. Team analytics aggregation
                {
                    "name": "Team Analytics",
                    "query": """
                        SELECT 
                            u.user_id,
                            u.email,
                            COUNT(DISTINCT ut.tool_id) as tools_count,
                            COUNT(DISTINCT ae.event_type) as events_count,
                            MAX(ae.timestamp) as last_activity
                        FROM users u
                        LEFT JOIN forge_user_tools ut ON u.user_id = ut.user_id
                        LEFT JOIN forge_analytics_events ae ON u.user_id = ae.user_id
                        WHERE u.team_id = $1
                        GROUP BY u.user_id, u.email
                    """,
                    "params": [test_team_id],
                    "threshold_ms": 200,
                },
                # 4. Get public stacks with tools
                {
                    "name": "Public Stacks",
                    "query": """
                        SELECT 
                            s.*,
                            u.email as creator_email,
                            ARRAY_AGG(
                                JSON_BUILD_OBJECT(
                                    'id', t.id,
                                    'name', t.name,
                                    'category', t.category
                                )
                            ) as tools
                        FROM forge_stacks s
                        JOIN users u ON s.created_by = u.user_id
                        LEFT JOIN forge_stack_tools st ON s.id = st.stack_id
                        LEFT JOIN forge_tools t ON st.tool_id = t.id
                        WHERE s.is_public = true
                        GROUP BY s.id, u.email
                        ORDER BY s.created_at DESC
                        LIMIT 20
                    """,
                    "params": [],
                    "threshold_ms": 150,
                },
                # 5. Tool search with filtering
                {
                    "name": "Tool Search",
                    "query": """
                        SELECT *
                        FROM forge_tools
                        WHERE 
                            (name ILIKE $1 OR description ILIKE $1)
                            AND ($2::text IS NULL OR category = $2)
                            AND ($3::text IS NULL OR ecosystem = $3)
                        ORDER BY 
                            CASE WHEN name ILIKE $1 THEN 0 ELSE 1 END,
                            popularity_score DESC
                        LIMIT 20
                    """,
                    "params": ["%database%", None, "mcp"],
                    "threshold_ms": 100,
                },
                # 6. Recommendation engine query
                {
                    "name": "Tool Recommendations",
                    "query": """
                        WITH user_categories AS (
                            SELECT DISTINCT t.category
                            FROM forge_user_tools ut
                            JOIN forge_tools t ON ut.tool_id = t.id
                            WHERE ut.user_id = $1
                        ),
                        similar_users AS (
                            SELECT ut2.user_id, COUNT(*) as common_tools
                            FROM forge_user_tools ut1
                            JOIN forge_user_tools ut2 ON ut1.tool_id = ut2.tool_id
                            WHERE ut1.user_id = $1 AND ut2.user_id != $1
                            GROUP BY ut2.user_id
                            ORDER BY common_tools DESC
                            LIMIT 10
                        )
                        SELECT DISTINCT t.*, COUNT(ut.user_id) as user_count
                        FROM forge_tools t
                        JOIN forge_user_tools ut ON t.id = ut.tool_id
                        WHERE 
                            ut.user_id IN (SELECT user_id FROM similar_users)
                            AND t.id NOT IN (
                                SELECT tool_id FROM forge_user_tools WHERE user_id = $1
                            )
                            AND (
                                t.category IN (SELECT category FROM user_categories)
                                OR t.popularity_score > 0.7
                            )
                        GROUP BY t.id
                        ORDER BY user_count DESC, t.popularity_score DESC
                        LIMIT 10
                    """,
                    "params": [test_user_id],
                    "threshold_ms": 300,
                },
            ]

            # Test each query
            for query_def in queries:
                print(f"Testing: {query_def['name']}")
                result = await self.analyze_query(
                    conn, query_def["query"], query_def.get("params")
                )

                if "error" in result:
                    print(f"  ✗ Error: {result['error']}")
                else:
                    execution_time = result["execution_time_actual_ms"]
                    threshold = query_def["threshold_ms"]
                    passed = execution_time < threshold

                    print(
                        f"  Execution Time: {execution_time:.2f}ms (Threshold: {threshold}ms) {'✓' if passed else '✗'}"
                    )
                    print(f"  Planning Time: {result['planning_time_ms']:.2f}ms")
                    print(f"  Total Cost: {result['total_cost']:.2f}")
                    print(f"  Rows Returned: {result['rows_returned']}")

                    # Check for performance issues
                    issues = self.analyze_plan(result["plan"])
                    if issues:
                        print("  ⚠️  Performance Issues Found:")
                        for issue in issues:
                            print(f"    - {issue}")

                    self.performance_results.append(
                        {
                            "name": query_def["name"],
                            "execution_time_ms": execution_time,
                            "threshold_ms": threshold,
                            "passed": passed,
                            "issues": issues,
                        }
                    )

                print()

            # Generate index recommendations
            await self.generate_index_recommendations(conn)

            # Test with sample data load
            await self.test_under_load(conn)

    def analyze_plan(self, plan: Dict) -> List[str]:
        """Analyze query plan for performance issues"""
        issues = []

        def check_node(node: Dict, depth: int = 0):
            node_type = node.get("Node Type", "")

            # Check for sequential scans on large tables
            if node_type == "Seq Scan":
                rows = node.get("Actual Rows", 0)
                if rows > 1000:
                    issues.append(
                        f"Sequential scan on {node.get('Relation Name', 'unknown')} ({rows} rows)"
                    )

            # Check for nested loops with many iterations
            elif node_type == "Nested Loop":
                loops = node.get("Actual Loops", 1)
                if loops > 100:
                    issues.append(f"Nested loop with {loops} iterations")

            # Check for hash joins with large hash tables
            elif node_type == "Hash Join":
                hash_buckets = node.get("Hash Buckets", 0)
                if hash_buckets > 8192:
                    issues.append(f"Large hash table ({hash_buckets} buckets)")

            # Check for sorts that spill to disk
            elif node_type == "Sort":
                sort_method = node.get("Sort Method", "")
                if "external" in sort_method.lower():
                    issues.append("Sort spilling to disk (external merge)")

            # Recursively check child nodes
            for child in node.get("Plans", []):
                check_node(child, depth + 1)

        check_node(plan)
        return issues

    async def generate_index_recommendations(self, conn: asyncpg.Connection):
        """Generate index recommendations based on query patterns"""
        print("\n=== INDEX RECOMMENDATIONS ===\n")

        # Check existing indexes
        existing_indexes_query = """
            SELECT 
                schemaname,
                tablename,
                indexname,
                indexdef
            FROM pg_indexes
            WHERE schemaname = 'public'
                AND tablename LIKE 'forge_%'
            ORDER BY tablename, indexname
        """

        existing_indexes = await conn.fetch(existing_indexes_query)

        # Analyze missing indexes
        missing_indexes_query = """
            SELECT 
                schemaname,
                tablename,
                attname,
                n_distinct,
                correlation
            FROM pg_stats
            WHERE 
                schemaname = 'public'
                AND tablename LIKE 'forge_%'
                AND n_distinct > 10
                AND correlation < 0.9
            ORDER BY tablename, attname
        """

        await conn.fetch(missing_indexes_query)

        # Generate recommendations
        recommendations = [
            # Critical indexes for Forge tables
            {
                "table": "forge_user_tools",
                "index": "CREATE INDEX CONCURRENTLY idx_forge_user_tools_user_id ON forge_user_tools(user_id)",
                "reason": "Frequent queries by user_id",
            },
            {
                "table": "forge_user_tools",
                "index": "CREATE INDEX CONCURRENTLY idx_forge_user_tools_tool_user ON forge_user_tools(tool_id, user_id)",
                "reason": "Composite index for tool-user lookups",
            },
            {
                "table": "forge_analytics_events",
                "index": "CREATE INDEX CONCURRENTLY idx_forge_analytics_user_timestamp ON forge_analytics_events(user_id, timestamp DESC)",
                "reason": "Time-series queries by user",
            },
            {
                "table": "forge_analytics_events",
                "index": "CREATE INDEX CONCURRENTLY idx_forge_analytics_tool_timestamp ON forge_analytics_events(tool_id, timestamp DESC)",
                "reason": "Tool usage timeline queries",
            },
            {
                "table": "forge_tools",
                "index": "CREATE INDEX CONCURRENTLY idx_forge_tools_category_popularity ON forge_tools(category, popularity_score DESC)",
                "reason": "Category filtering with popularity sorting",
            },
            {
                "table": "forge_tools",
                "index": "CREATE INDEX CONCURRENTLY idx_forge_tools_name_trgm ON forge_tools USING gin(name gin_trgm_ops)",
                "reason": "Fast text search on tool names (requires pg_trgm)",
            },
            {
                "table": "forge_stacks",
                "index": "CREATE INDEX CONCURRENTLY idx_forge_stacks_public ON forge_stacks(is_public) WHERE is_public = true",
                "reason": "Partial index for public stacks",
            },
            {
                "table": "forge_stack_tools",
                "index": "CREATE INDEX CONCURRENTLY idx_forge_stack_tools_stack ON forge_stack_tools(stack_id)",
                "reason": "Stack-to-tools relationship",
            },
        ]

        # Check which indexes already exist
        existing_index_names = {idx["indexname"] for idx in existing_indexes}

        new_recommendations = []
        for rec in recommendations:
            index_name = rec["index"].split(" ")[-1].split("(")[0]
            if index_name not in existing_index_names:
                new_recommendations.append(rec)
                print("Recommended Index:")
                print(f"  Table: {rec['table']}")
                print(f"  SQL: {rec['index']}")
                print(f"  Reason: {rec['reason']}\n")

        if not new_recommendations:
            print("✓ All recommended indexes already exist!")

        self.optimization_suggestions = new_recommendations

    async def test_under_load(self, conn: asyncpg.Connection):
        """Test query performance under concurrent load"""
        print("\n=== CONCURRENT LOAD TESTING ===\n")

        async def execute_query(query: str, params: List = None):
            """Execute a single query and measure time"""
            start = time.perf_counter()
            try:
                if params:
                    await conn.fetch(query, *params)
                else:
                    await conn.fetch(query)
                return (time.perf_counter() - start) * 1000
            except Exception:
                return None

        # Simulate concurrent users
        test_queries = [
            ("SELECT * FROM forge_user_tools WHERE user_id = $1", ["user-1"]),
            ("SELECT * FROM forge_tools WHERE category = $1 LIMIT 20", ["database"]),
            (
                "SELECT COUNT(*) FROM forge_analytics_events WHERE user_id = $1",
                ["user-2"],
            ),
        ]

        print("Testing with 10 concurrent queries...")
        tasks = []
        for i in range(10):
            query, params = test_queries[i % len(test_queries)]
            tasks.append(execute_query(query, params))

        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks)
        total_time = (time.perf_counter() - start_time) * 1000

        successful = [r for r in results if r is not None]

        print(f"  Total Time: {total_time:.2f}ms")
        print(f"  Successful Queries: {len(successful)}/{len(tasks)}")
        if successful:
            print(f"  Average Query Time: {sum(successful) / len(successful):.2f}ms")
            print(f"  Min Query Time: {min(successful):.2f}ms")
            print(f"  Max Query Time: {max(successful):.2f}ms")

        print("\nTesting with 50 concurrent queries...")
        tasks = []
        for i in range(50):
            query, params = test_queries[i % len(test_queries)]
            tasks.append(execute_query(query, params))

        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks)
        total_time = (time.perf_counter() - start_time) * 1000

        successful = [r for r in results if r is not None]

        print(f"  Total Time: {total_time:.2f}ms")
        print(f"  Successful Queries: {len(successful)}/{len(tasks)}")
        if successful:
            print(f"  Average Query Time: {sum(successful) / len(successful):.2f}ms")
            print(f"  Min Query Time: {min(successful):.2f}ms")
            print(f"  Max Query Time: {max(successful):.2f}ms")

    def generate_report(self) -> Dict:
        """Generate comprehensive performance report"""
        passed_count = sum(1 for r in self.performance_results if r["passed"])
        total_count = len(self.performance_results)

        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_queries_tested": total_count,
                "passed": passed_count,
                "failed": total_count - passed_count,
                "pass_rate": (passed_count / total_count * 100)
                if total_count > 0
                else 0,
            },
            "query_results": self.performance_results,
            "optimization_suggestions": self.optimization_suggestions,
            "recommendations": [],
        }

        # Add specific recommendations
        if report["summary"]["pass_rate"] < 100:
            report["recommendations"].append(
                {
                    "priority": "HIGH",
                    "action": "Apply recommended indexes to improve query performance",
                }
            )

        # Check for specific issues
        for result in self.performance_results:
            if not result["passed"]:
                if "Sequential scan" in str(result.get("issues", [])):
                    report["recommendations"].append(
                        {
                            "priority": "HIGH",
                            "action": f"Add index for {result['name']} to avoid sequential scan",
                        }
                    )
                if result["execution_time_ms"] > result["threshold_ms"] * 2:
                    report["recommendations"].append(
                        {
                            "priority": "CRITICAL",
                            "action": f"Optimize {result['name']} - exceeds threshold by >100%",
                        }
                    )

        return report


async def main():
    """Run database performance tests"""
    # Use environment variable or default connection string
    import os

    database_url = os.getenv(
        "DATABASE_URL", "postgresql://postgres:password@localhost:5432/sigil"
    )

    tester = DatabasePerformanceTester(database_url)

    try:
        await tester.test_forge_queries()

        # Generate and save report
        report = tester.generate_report()

        print("\n=== PERFORMANCE TEST SUMMARY ===")
        print(f"Queries Tested: {report['summary']['total_queries_tested']}")
        print(f"Passed: {report['summary']['passed']}")
        print(f"Failed: {report['summary']['failed']}")
        print(f"Pass Rate: {report['summary']['pass_rate']:.1f}%")

        # Save report
        with open("database_performance_report.json", "w") as f:
            json.dump(report, f, indent=2)

        print("\nDetailed report saved to: database_performance_report.json")

        # Return non-zero exit code if tests failed
        if report["summary"]["pass_rate"] < 100:
            return 1
        return 0

    except Exception as e:
        print(f"Error running tests: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)

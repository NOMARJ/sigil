#!/usr/bin/env python3
"""
Sigil API — Performance Monitoring and Health Checks

Comprehensive database performance monitoring, query optimization analysis,
and health check utilities for the Sigil API.

Usage:
    python scripts/performance_monitoring.py --check-indexes
    python scripts/performance_monitoring.py --analyze-queries
    python scripts/performance_monitoring.py --benchmark
    python scripts/performance_monitoring.py --health-check
    python scripts/performance_monitoring.py --all
"""

import argparse
import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List

from api.config import settings
from api.database import db

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """Database performance monitoring and optimization utilities."""
    
    def __init__(self):
        self.results: Dict[str, Any] = {}
    
    async def check_index_usage(self) -> Dict[str, Any]:
        """Analyze index usage statistics."""
        print("🔍 Analyzing index usage...")
        
        if not db.connected:
            print("❌ Database not connected - skipping index analysis")
            return {"error": "Database not connected"}
        
        try:
            # Get index usage stats
            usage_sql = """
            SELECT 
                OBJECT_NAME(i.object_id) AS table_name,
                i.name AS index_name,
                i.type_desc AS index_type,
                ius.user_seeks,
                ius.user_scans,
                ius.user_lookups,
                ius.user_updates,
                ius.last_user_seek,
                ius.last_user_scan,
                ius.last_user_lookup,
                CASE 
                    WHEN ius.user_seeks + ius.user_scans + ius.user_lookups = 0 THEN 'UNUSED'
                    ELSE 'ACTIVE'
                END AS usage_status
            FROM sys.indexes i
            LEFT JOIN sys.dm_db_index_usage_stats ius 
                ON i.object_id = ius.object_id AND i.index_id = ius.index_id
            WHERE OBJECT_NAME(i.object_id) IN (
                'scans', 'public_scans', 'forge_classification', 
                'forge_capabilities', 'forge_matches', 'threats'
            )
            ORDER BY 
                OBJECT_NAME(i.object_id),
                CASE WHEN ius.user_seeks + ius.user_scans + ius.user_lookups > 0 THEN 0 ELSE 1 END,
                (ius.user_seeks + ius.user_scans + ius.user_lookups) DESC
            """
            
            index_stats = await db.execute_raw_sql(usage_sql)
            
            # Analyze results
            active_indexes = [idx for idx in index_stats if idx['usage_status'] == 'ACTIVE']
            unused_indexes = [idx for idx in index_stats if idx['usage_status'] == 'UNUSED']
            
            print(f"✅ Found {len(active_indexes)} active indexes")
            print(f"⚠️  Found {len(unused_indexes)} unused indexes")
            
            # Show top performers
            print("\n🏆 Top 5 most used indexes:")
            top_indexes = sorted(
                active_indexes, 
                key=lambda x: (x['user_seeks'] or 0) + (x['user_scans'] or 0) + (x['user_lookups'] or 0),
                reverse=True
            )[:5]
            
            for idx in top_indexes:
                total_ops = (idx['user_seeks'] or 0) + (idx['user_scans'] or 0) + (idx['user_lookups'] or 0)
                print(f"  📊 {idx['table_name']}.{idx['index_name']}: {total_ops:,} operations")
            
            # Show unused indexes
            if unused_indexes:
                print(f"\n⚠️  Unused indexes (consider dropping):")
                for idx in unused_indexes:
                    if idx['index_name'] and not idx['index_name'].startswith('PK_'):
                        print(f"  🗑️  {idx['table_name']}.{idx['index_name']} ({idx['index_type']})")
            
            return {
                "total_indexes": len(index_stats),
                "active_indexes": len(active_indexes),
                "unused_indexes": len(unused_indexes),
                "top_indexes": top_indexes,
                "unused_list": unused_indexes
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze index usage: {e}")
            return {"error": str(e)}
    
    async def check_index_fragmentation(self) -> Dict[str, Any]:
        """Check index fragmentation levels."""
        print("🧩 Analyzing index fragmentation...")
        
        if not db.connected:
            print("❌ Database not connected - skipping fragmentation analysis")
            return {"error": "Database not connected"}
        
        try:
            frag_sql = """
            SELECT 
                OBJECT_NAME(ips.object_id) AS table_name,
                i.name AS index_name,
                ips.avg_fragmentation_in_percent,
                ips.page_count,
                CASE 
                    WHEN ips.avg_fragmentation_in_percent > 30 THEN 'REBUILD REQUIRED'
                    WHEN ips.avg_fragmentation_in_percent > 10 THEN 'REORGANIZE RECOMMENDED'
                    ELSE 'OK'
                END AS recommendation
            FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ips
            JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
            WHERE OBJECT_NAME(ips.object_id) IN (
                'scans', 'public_scans', 'forge_classification', 
                'forge_capabilities', 'forge_matches', 'threats'
            )
            AND ips.avg_fragmentation_in_percent > 5
            ORDER BY ips.avg_fragmentation_in_percent DESC
            """
            
            frag_stats = await db.execute_raw_sql(frag_sql)
            
            needs_rebuild = [idx for idx in frag_stats if idx['recommendation'] == 'REBUILD REQUIRED']
            needs_reorg = [idx for idx in frag_stats if idx['recommendation'] == 'REORGANIZE RECOMMENDED']
            
            print(f"🔧 {len(needs_rebuild)} indexes need rebuilding (>30% fragmentation)")
            print(f"🔄 {len(needs_reorg)} indexes need reorganizing (10-30% fragmentation)")
            
            if needs_rebuild:
                print("\n🚨 Indexes requiring rebuild:")
                for idx in needs_rebuild:
                    print(f"  🔨 {idx['table_name']}.{idx['index_name']}: {idx['avg_fragmentation_in_percent']:.1f}% fragmented")
            
            if needs_reorg:
                print("\n⚠️  Indexes requiring reorganization:")
                for idx in needs_reorg:
                    print(f"  🔄 {idx['table_name']}.{idx['index_name']}: {idx['avg_fragmentation_in_percent']:.1f}% fragmented")
            
            return {
                "total_fragmented": len(frag_stats),
                "needs_rebuild": len(needs_rebuild),
                "needs_reorganize": len(needs_reorg),
                "rebuild_list": needs_rebuild,
                "reorganize_list": needs_reorg
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze fragmentation: {e}")
            return {"error": str(e)}
    
    async def analyze_slow_queries(self) -> Dict[str, Any]:
        """Analyze slow-running queries."""
        print("🐌 Analyzing slow queries...")
        
        if not db.connected:
            print("❌ Database not connected - skipping query analysis")
            return {"error": "Database not connected"}
        
        try:
            slow_query_sql = """
            SELECT TOP 20
                qs.total_elapsed_time / qs.execution_count AS avg_elapsed_time_ms,
                qs.execution_count,
                qs.total_logical_reads / qs.execution_count AS avg_logical_reads,
                qs.total_physical_reads / qs.execution_count AS avg_physical_reads,
                SUBSTRING(qt.text, (qs.statement_start_offset/2)+1, 
                    ((CASE qs.statement_end_offset
                        WHEN -1 THEN DATALENGTH(qt.text)
                        ELSE qs.statement_end_offset
                    END - qs.statement_start_offset)/2)+1) AS query_text,
                qs.creation_time,
                qs.last_execution_time
            FROM sys.dm_exec_query_stats qs
            CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt
            WHERE (qt.text LIKE '%forge_%' 
               OR qt.text LIKE '%public_scans%'
               OR qt.text LIKE '%scans%'
               OR qt.text LIKE '%threats%')
            AND qs.execution_count > 1  -- Only queries executed multiple times
            ORDER BY avg_elapsed_time_ms DESC
            """
            
            slow_queries = await db.execute_raw_sql(slow_query_sql)
            
            critical_queries = [q for q in slow_queries if q['avg_elapsed_time_ms'] > 1000]  # > 1 second
            slow_queries_filtered = [q for q in slow_queries if q['avg_elapsed_time_ms'] > 200]  # > 200ms
            
            print(f"🔍 Found {len(slow_queries)} tracked queries")
            print(f"🚨 {len(critical_queries)} critical slow queries (>1s)")
            print(f"⚠️  {len(slow_queries_filtered)} slow queries (>200ms)")
            
            if critical_queries:
                print("\n🚨 Critical slow queries:")
                for i, query in enumerate(critical_queries[:5], 1):
                    query_preview = query['query_text'][:100].replace('\n', ' ').strip()
                    print(f"  {i}. {query['avg_elapsed_time_ms']:.0f}ms avg, {query['execution_count']} executions")
                    print(f"     {query_preview}...")
            
            return {
                "total_queries": len(slow_queries),
                "critical_queries": len(critical_queries),
                "slow_queries": len(slow_queries_filtered),
                "worst_queries": critical_queries[:10]
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze slow queries: {e}")
            return {"error": str(e)}
    
    async def benchmark_common_operations(self) -> Dict[str, Any]:
        """Benchmark common database operations."""
        print("⚡ Running performance benchmarks...")
        
        benchmarks = {}
        
        # Benchmark 1: Forge classification search
        try:
            start_time = time.time()
            results = await db.select(
                "forge_classification",
                filters={"ecosystem": "clawhub"},
                limit=20,
                order_by="confidence_score",
                order_desc=True
            )
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            
            benchmarks["forge_search"] = {
                "duration_ms": duration_ms,
                "results_count": len(results),
                "status": "GOOD" if duration_ms < 100 else "SLOW" if duration_ms < 500 else "CRITICAL"
            }
            print(f"  📊 Forge classification search: {duration_ms:.1f}ms ({len(results)} results)")
            
        except Exception as e:
            benchmarks["forge_search"] = {"error": str(e)}
            print(f"  ❌ Forge classification search failed: {e}")
        
        # Benchmark 2: Public scans ecosystem filter
        try:
            start_time = time.time()
            results = await db.select(
                "public_scans",
                filters={"ecosystem": "mcp"},
                limit=20,
                order_by="scanned_at",
                order_desc=True
            )
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            
            benchmarks["public_scans_filter"] = {
                "duration_ms": duration_ms,
                "results_count": len(results),
                "status": "GOOD" if duration_ms < 100 else "SLOW" if duration_ms < 500 else "CRITICAL"
            }
            print(f"  📊 Public scans filter: {duration_ms:.1f}ms ({len(results)} results)")
            
        except Exception as e:
            benchmarks["public_scans_filter"] = {"error": str(e)}
            print(f"  ❌ Public scans filter failed: {e}")
        
        # Benchmark 3: Complex JOIN query
        try:
            start_time = time.time()
            if db.connected:
                join_sql = """
                SELECT TOP 10 fc.*, cap.capability 
                FROM forge_classification fc
                LEFT JOIN forge_capabilities cap ON fc.id = cap.classification_id
                WHERE fc.ecosystem = 'clawhub'
                ORDER BY fc.confidence_score DESC
                """
                results = await db.execute_raw_sql(join_sql)
            else:
                # Simulate for in-memory mode
                results = []
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            
            benchmarks["complex_join"] = {
                "duration_ms": duration_ms,
                "results_count": len(results),
                "status": "GOOD" if duration_ms < 200 else "SLOW" if duration_ms < 1000 else "CRITICAL"
            }
            print(f"  📊 Complex JOIN query: {duration_ms:.1f}ms ({len(results)} results)")
            
        except Exception as e:
            benchmarks["complex_join"] = {"error": str(e)}
            print(f"  ❌ Complex JOIN query failed: {e}")
        
        # Benchmark 4: User scan history
        try:
            start_time = time.time()
            results = await db.select(
                "scans",
                {},
                limit=20,
                order_by="created_at",
                order_desc=True
            )
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            
            benchmarks["scan_history"] = {
                "duration_ms": duration_ms,
                "results_count": len(results),
                "status": "GOOD" if duration_ms < 100 else "SLOW" if duration_ms < 500 else "CRITICAL"
            }
            print(f"  📊 Scan history: {duration_ms:.1f}ms ({len(results)} results)")
            
        except Exception as e:
            benchmarks["scan_history"] = {"error": str(e)}
            print(f"  ❌ Scan history failed: {e}")
        
        return benchmarks
    
    async def check_connection_health(self) -> Dict[str, Any]:
        """Check database connection health."""
        print("🏥 Checking database connection health...")
        
        health = {
            "database_connected": db.connected,
            "connection_pool_configured": False,
            "pool_size": None,
            "active_connections": None
        }
        
        if db.connected:
            print("✅ Database connection is active")
            
            try:
                # Check connection pool info
                if hasattr(db._pool, 'size'):
                    health["connection_pool_configured"] = True
                    health["pool_size"] = db._pool.size
                    health["active_connections"] = db._pool.size - db._pool.freesize
                    print(f"📊 Connection pool: {health['active_connections']}/{health['pool_size']} active")
                
                # Test a simple query
                start_time = time.time()
                result = await db.execute_raw_sql("SELECT 1 as test_query")
                end_time = time.time()
                query_time_ms = (end_time - start_time) * 1000
                
                health["simple_query_time_ms"] = query_time_ms
                health["simple_query_status"] = "GOOD" if query_time_ms < 50 else "SLOW"
                
                print(f"⚡ Simple query test: {query_time_ms:.1f}ms")
                
            except Exception as e:
                health["connection_error"] = str(e)
                print(f"❌ Connection test failed: {e}")
        else:
            print("❌ Database not connected (using in-memory fallback)")
        
        return health
    
    async def generate_optimization_recommendations(self) -> List[str]:
        """Generate optimization recommendations based on analysis."""
        print("\n💡 Generating optimization recommendations...")
        
        recommendations = []
        
        # Check if we have the results from other checks
        if "index_usage" in self.results:
            unused_count = self.results["index_usage"].get("unused_indexes", 0)
            if unused_count > 5:
                recommendations.append(
                    f"Consider dropping {unused_count} unused indexes to reduce maintenance overhead"
                )
        
        if "fragmentation" in self.results:
            rebuild_count = self.results["fragmentation"].get("needs_rebuild", 0)
            reorg_count = self.results["fragmentation"].get("needs_reorganize", 0)
            
            if rebuild_count > 0:
                recommendations.append(
                    f"Rebuild {rebuild_count} heavily fragmented indexes (>30% fragmentation)"
                )
            if reorg_count > 0:
                recommendations.append(
                    f"Reorganize {reorg_count} moderately fragmented indexes (10-30% fragmentation)"
                )
        
        if "slow_queries" in self.results:
            critical_count = self.results["slow_queries"].get("critical_queries", 0)
            if critical_count > 0:
                recommendations.append(
                    f"Optimize {critical_count} critical slow queries (>1s execution time)"
                )
        
        if "benchmarks" in self.results:
            slow_benchmarks = [
                name for name, data in self.results["benchmarks"].items()
                if isinstance(data, dict) and data.get("status") in ["SLOW", "CRITICAL"]
            ]
            if slow_benchmarks:
                recommendations.append(
                    f"Performance issues detected in: {', '.join(slow_benchmarks)}"
                )
        
        if "connection_health" in self.results:
            if not self.results["connection_health"].get("connection_pool_configured"):
                recommendations.append(
                    "Configure connection pooling for better concurrency handling"
                )
        
        # General recommendations
        if not recommendations:
            recommendations.append("Database performance looks good! Consider regular maintenance.")
        else:
            recommendations.extend([
                "Run DBCC UPDATEUSAGE to update page and row counts",
                "Schedule regular index maintenance during low-traffic periods",
                "Monitor query execution plans for further optimization opportunities",
                "Consider implementing query result caching for frequently accessed data"
            ])
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        return recommendations
    
    async def run_full_analysis(self) -> Dict[str, Any]:
        """Run complete performance analysis."""
        print("🚀 Starting comprehensive performance analysis...\n")
        
        # Connect to database
        if not db.connected:
            await db.connect()
        
        # Run all checks
        self.results["index_usage"] = await self.check_index_usage()
        print()
        
        self.results["fragmentation"] = await self.check_index_fragmentation()
        print()
        
        self.results["slow_queries"] = await self.analyze_slow_queries()
        print()
        
        self.results["benchmarks"] = await self.benchmark_common_operations()
        print()
        
        self.results["connection_health"] = await self.check_connection_health()
        print()
        
        # Generate recommendations
        self.results["recommendations"] = await self.generate_optimization_recommendations()
        
        # Summary
        print(f"\n📋 Performance Analysis Summary")
        print(f"{'='*50}")
        print(f"Timestamp: {datetime.now().isoformat()}")
        print(f"Database Connected: {db.connected}")
        
        if "index_usage" in self.results and "error" not in self.results["index_usage"]:
            print(f"Active Indexes: {self.results['index_usage']['active_indexes']}")
            print(f"Unused Indexes: {self.results['index_usage']['unused_indexes']}")
        
        if "slow_queries" in self.results and "error" not in self.results["slow_queries"]:
            print(f"Critical Slow Queries: {self.results['slow_queries']['critical_queries']}")
        
        # Overall health score
        issues = 0
        if self.results.get("index_usage", {}).get("unused_indexes", 0) > 5:
            issues += 1
        if self.results.get("fragmentation", {}).get("needs_rebuild", 0) > 0:
            issues += 1
        if self.results.get("slow_queries", {}).get("critical_queries", 0) > 0:
            issues += 2  # Weight slow queries more heavily
        
        if issues == 0:
            health_status = "🟢 EXCELLENT"
        elif issues <= 2:
            health_status = "🟡 GOOD"
        elif issues <= 4:
            health_status = "🟠 NEEDS ATTENTION"
        else:
            health_status = "🔴 CRITICAL"
        
        print(f"Overall Health: {health_status}")
        print(f"Issues Found: {issues}")
        
        return self.results


async def main():
    """Main entry point for the performance monitoring script."""
    parser = argparse.ArgumentParser(description="Sigil API Performance Monitoring")
    parser.add_argument("--check-indexes", action="store_true", help="Check index usage and fragmentation")
    parser.add_argument("--analyze-queries", action="store_true", help="Analyze slow queries")
    parser.add_argument("--benchmark", action="store_true", help="Run performance benchmarks")
    parser.add_argument("--health-check", action="store_true", help="Check connection health")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    monitor = PerformanceMonitor()
    
    try:
        # Connect to database
        await db.connect()
        
        if args.all:
            await monitor.run_full_analysis()
        else:
            if args.check_indexes:
                monitor.results["index_usage"] = await monitor.check_index_usage()
                monitor.results["fragmentation"] = await monitor.check_index_fragmentation()
            
            if args.analyze_queries:
                monitor.results["slow_queries"] = await monitor.analyze_slow_queries()
            
            if args.benchmark:
                monitor.results["benchmarks"] = await monitor.benchmark_common_operations()
            
            if args.health_check:
                monitor.results["connection_health"] = await monitor.check_connection_health()
            
            # If no specific checks requested, run all
            if not any([args.check_indexes, args.analyze_queries, args.benchmark, args.health_check]):
                await monitor.run_full_analysis()
    
    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        print(f"\n❌ Analysis failed: {e}")
    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
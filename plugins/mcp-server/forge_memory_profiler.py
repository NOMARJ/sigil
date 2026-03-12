#!/usr/bin/env python3
"""
Sigil Forge Memory Profiler

Analyzes memory usage patterns and identifies optimization opportunities.
"""

import asyncio
import gc
import tracemalloc
import psutil
import sys
import os
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import json

# Add parent directories to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


@dataclass
class MemorySnapshot:
    """Memory usage snapshot at a specific point."""

    timestamp: datetime
    rss_mb: float  # Resident Set Size
    vms_mb: float  # Virtual Memory Size
    available_mb: float
    percent_used: float
    heap_size_mb: float
    gc_stats: Dict[str, Any]
    top_allocations: List[Tuple[str, int, int]]  # (filename:lineno, size, count)


class ForgeMemoryProfiler:
    """Memory profiling for Forge API operations."""

    def __init__(self):
        self.snapshots: List[MemorySnapshot] = []
        self.process = psutil.Process()
        self.memory_leaks: List[Dict[str, Any]] = []

    def start_profiling(self):
        """Start memory profiling."""
        tracemalloc.start(10)  # Keep 10 frames of traceback
        gc.collect()  # Force garbage collection for baseline

    def take_snapshot(self, label: str = "") -> MemorySnapshot:
        """Take a memory snapshot."""

        # Get process memory info
        mem_info = self.process.memory_info()
        mem_percent = self.process.memory_percent()

        # Get system memory
        vm = psutil.virtual_memory()

        # Get Python heap info via tracemalloc
        current, peak = tracemalloc.get_traced_memory()

        # Get garbage collector stats
        gc_stats = {
            "collections": gc.get_count(),
            "threshold": gc.get_threshold(),
            "objects": len(gc.get_objects()),
        }

        # Get top memory allocations
        snapshot = tracemalloc.take_snapshot()
        top_stats = snapshot.statistics("lineno")

        top_allocations = []
        for stat in top_stats[:10]:  # Top 10 memory users
            top_allocations.append(
                (f"{stat.filename}:{stat.lineno}", stat.size, stat.count)
            )

        mem_snapshot = MemorySnapshot(
            timestamp=datetime.now(),
            rss_mb=mem_info.rss / 1024 / 1024,
            vms_mb=mem_info.vms / 1024 / 1024,
            available_mb=vm.available / 1024 / 1024,
            percent_used=mem_percent,
            heap_size_mb=current / 1024 / 1024,
            gc_stats=gc_stats,
            top_allocations=top_allocations,
        )

        self.snapshots.append(mem_snapshot)

        if label:
            print(f"\n Memory Snapshot: {label}")
            print(f"  RSS: {mem_snapshot.rss_mb:.2f} MB")
            print(f"  Heap: {mem_snapshot.heap_size_mb:.2f} MB")
            print(f"  GC Objects: {gc_stats['objects']}")

        return mem_snapshot

    def compare_snapshots(
        self, before: MemorySnapshot, after: MemorySnapshot
    ) -> Dict[str, Any]:
        """Compare two memory snapshots to identify growth."""

        memory_growth = {
            "rss_growth_mb": after.rss_mb - before.rss_mb,
            "heap_growth_mb": after.heap_size_mb - before.heap_size_mb,
            "object_growth": after.gc_stats["objects"] - before.gc_stats["objects"],
            "time_elapsed": (after.timestamp - before.timestamp).total_seconds(),
        }

        # Find new large allocations
        before_allocs = {alloc[0]: alloc for alloc in before.top_allocations}
        new_allocations = []

        for alloc in after.top_allocations:
            location = alloc[0]
            if (
                location not in before_allocs
                or alloc[1] > before_allocs[location][1] * 1.5
            ):
                new_allocations.append(
                    {
                        "location": location,
                        "size_mb": alloc[1] / 1024 / 1024,
                        "objects": alloc[2],
                    }
                )

        memory_growth["new_allocations"] = new_allocations

        return memory_growth

    async def profile_endpoint_memory(
        self, endpoint_func, *args, **kwargs
    ) -> Dict[str, Any]:
        """Profile memory usage of a specific endpoint function."""

        gc.collect()  # Clean slate
        before = self.take_snapshot("Before endpoint")

        # Run the endpoint function
        result = await endpoint_func(*args, **kwargs)

        after = self.take_snapshot("After endpoint")

        # Force garbage collection and take another snapshot
        gc.collect()
        after_gc = self.take_snapshot("After GC")

        # Analyze memory patterns
        growth = self.compare_snapshots(before, after)
        gc_recovery = self.compare_snapshots(after, after_gc)

        # Check for potential memory leak
        if (
            growth["heap_growth_mb"] > 10
            and abs(gc_recovery["heap_growth_mb"]) < growth["heap_growth_mb"] * 0.5
        ):
            self.memory_leaks.append(
                {
                    "endpoint": endpoint_func.__name__,
                    "heap_growth_mb": growth["heap_growth_mb"],
                    "recovered_mb": abs(gc_recovery["heap_growth_mb"]),
                    "potential_leak_mb": growth["heap_growth_mb"]
                    + gc_recovery["heap_growth_mb"],
                    "top_allocations": growth["new_allocations"],
                }
            )

        return {
            "endpoint": endpoint_func.__name__,
            "memory_used_mb": growth["rss_growth_mb"],
            "heap_growth_mb": growth["heap_growth_mb"],
            "gc_recovered_mb": abs(gc_recovery["heap_growth_mb"]),
            "object_count_growth": growth["object_growth"],
            "top_allocations": growth["new_allocations"],
        }

    def analyze_memory_patterns(self) -> Dict[str, Any]:
        """Analyze memory usage patterns from snapshots."""

        if len(self.snapshots) < 2:
            return {"error": "Not enough snapshots for analysis"}

        patterns = {
            "total_snapshots": len(self.snapshots),
            "memory_trend": [],
            "gc_effectiveness": [],
            "peak_memory_mb": 0,
            "average_memory_mb": 0,
            "memory_growth_rate_mb_per_min": 0,
        }

        # Analyze memory trend
        rss_values = [s.rss_mb for s in self.snapshots]
        patterns["peak_memory_mb"] = max(rss_values)
        patterns["average_memory_mb"] = sum(rss_values) / len(rss_values)

        # Calculate growth rate
        time_span_minutes = (
            self.snapshots[-1].timestamp - self.snapshots[0].timestamp
        ).total_seconds() / 60
        if time_span_minutes > 0:
            memory_growth = self.snapshots[-1].rss_mb - self.snapshots[0].rss_mb
            patterns["memory_growth_rate_mb_per_min"] = (
                memory_growth / time_span_minutes
            )

        # Analyze GC effectiveness
        for i in range(1, len(self.snapshots)):
            prev = self.snapshots[i - 1]
            curr = self.snapshots[i]

            # Check if GC ran (collections increased)
            if curr.gc_stats["collections"][0] > prev.gc_stats["collections"][0]:
                gc_effect = {
                    "timestamp": curr.timestamp.isoformat(),
                    "objects_before": prev.gc_stats["objects"],
                    "objects_after": curr.gc_stats["objects"],
                    "memory_freed_mb": prev.rss_mb - curr.rss_mb
                    if curr.rss_mb < prev.rss_mb
                    else 0,
                }
                patterns["gc_effectiveness"].append(gc_effect)

        # Identify memory hotspots
        all_allocations = {}
        for snapshot in self.snapshots:
            for location, size, count in snapshot.top_allocations:
                if location not in all_allocations:
                    all_allocations[location] = []
                all_allocations[location].append(size)

        # Find consistently high memory users
        hotspots = []
        for location, sizes in all_allocations.items():
            if len(sizes) >= len(self.snapshots) * 0.5:  # Present in 50% of snapshots
                avg_size = sum(sizes) / len(sizes)
                if avg_size > 1024 * 1024:  # Over 1MB average
                    hotspots.append(
                        {
                            "location": location,
                            "average_size_mb": avg_size / 1024 / 1024,
                            "max_size_mb": max(sizes) / 1024 / 1024,
                            "frequency": len(sizes),
                        }
                    )

        patterns["memory_hotspots"] = sorted(
            hotspots, key=lambda x: x["average_size_mb"], reverse=True
        )[:10]

        return patterns

    def generate_optimizations(self) -> List[Dict[str, Any]]:
        """Generate memory optimization recommendations."""

        optimizations = []
        patterns = self.analyze_memory_patterns()

        # Check for memory leaks
        if self.memory_leaks:
            for leak in self.memory_leaks:
                optimizations.append(
                    {
                        "priority": "CRITICAL",
                        "issue": f"Potential memory leak in {leak['endpoint']}",
                        "details": f"Heap grows by {leak['heap_growth_mb']:.2f}MB, only {leak['recovered_mb']:.2f}MB recovered",
                        "recommendations": [
                            "Check for circular references in data structures",
                            "Ensure database connections are properly closed",
                            "Clear large objects after use (del statement)",
                            "Use weak references for caches",
                            "Implement __slots__ for frequently created objects",
                        ],
                        "code_locations": leak.get("top_allocations", [])[:3],
                    }
                )

        # Check for high memory growth rate
        if patterns.get("memory_growth_rate_mb_per_min", 0) > 1:
            optimizations.append(
                {
                    "priority": "HIGH",
                    "issue": "High memory growth rate",
                    "details": f"Memory growing at {patterns['memory_growth_rate_mb_per_min']:.2f} MB/min",
                    "recommendations": [
                        "Implement object pooling for frequently created objects",
                        "Use generators instead of lists for large datasets",
                        "Stream large responses instead of loading into memory",
                        "Implement pagination for large result sets",
                        "Use memoryview for large binary data",
                    ],
                }
            )

        # Check for inefficient GC
        gc_stats = self.snapshots[-1].gc_stats if self.snapshots else {}
        if gc_stats.get("objects", 0) > 100000:
            optimizations.append(
                {
                    "priority": "MEDIUM",
                    "issue": "High object count in memory",
                    "details": f"{gc_stats['objects']} objects tracked by GC",
                    "recommendations": [
                        "Use __slots__ to reduce memory overhead of objects",
                        "Cache and reuse objects instead of creating new ones",
                        "Use primitive types where possible",
                        "Implement object interning for immutable objects",
                        "Consider using array.array or numpy for numeric data",
                    ],
                }
            )

        # Check memory hotspots
        if patterns.get("memory_hotspots"):
            for hotspot in patterns["memory_hotspots"][:3]:
                optimizations.append(
                    {
                        "priority": "MEDIUM",
                        "issue": f"Memory hotspot at {hotspot['location']}",
                        "details": f"Average {hotspot['average_size_mb']:.2f}MB, max {hotspot['max_size_mb']:.2f}MB",
                        "recommendations": [
                            "Review data structures at this location",
                            "Consider lazy loading or streaming",
                            "Implement size limits for collections",
                            "Use more memory-efficient data structures",
                            "Clear unused references explicitly",
                        ],
                    }
                )

        # General optimizations based on peak memory
        if patterns.get("peak_memory_mb", 0) > 500:
            optimizations.append(
                {
                    "priority": "HIGH",
                    "issue": "High peak memory usage",
                    "details": f"Peak memory usage: {patterns['peak_memory_mb']:.2f}MB",
                    "recommendations": [
                        "Implement request-scoped memory limits",
                        "Use Redis for large cache items instead of in-memory",
                        "Implement circuit breaker for memory-intensive operations",
                        "Add memory monitoring and alerting",
                        "Consider horizontal scaling with load balancing",
                    ],
                }
            )

        return optimizations


async def profile_forge_apis():
    """Profile memory usage of Forge API operations."""

    print("=" * 60)
    print(" SIGIL FORGE MEMORY PROFILING")
    print("=" * 60)

    profiler = ForgeMemoryProfiler()
    profiler.start_profiling()

    # Import API modules for testing
    try:
        from api.routers import forge
        from api.services import forge_classifier, forge_matcher
        from api.database import db

        # Initialize database connection
        await db.connect()

    except ImportError as e:
        print(f"Error importing API modules: {e}")
        print("Please run from the project root directory")
        return

    print("\n=== MEMORY PROFILING STARTED ===")

    # Take initial baseline
    baseline = profiler.take_snapshot("Baseline")

    # Test 1: Classification memory usage
    print("\n Testing classification service...")
    from api.models import Finding, ScanPhase, Severity

    test_input = forge_classifier.ClassificationInput(
        ecosystem="clawhub",
        package_name="test-package",
        package_version="1.0.0",
        description="Test package for memory profiling",
        scan_findings=[
            Finding(
                phase=ScanPhase.CODE_PATTERNS,
                rule="test-rule",
                severity=Severity.MEDIUM,
                file="test.js",
                line=1,
                snippet="const db = require('postgres')",
                weight=1.0,
                description="Database import detected",
            )
        ]
        * 100,  # Simulate 100 findings
        metadata={"test": "data" * 100},  # Large metadata
    )

    classifier_profile = await profiler.profile_endpoint_memory(
        forge_classifier.forge_classifier.classify_package, test_input
    )
    print(f"  Classifier memory: {classifier_profile['memory_used_mb']:.2f}MB")

    # Test 2: Matching service memory usage
    print("\n Testing matching service...")

    # Simulate matching operations
    async def test_matching():
        matches = await forge_matcher.forge_matcher.find_env_var_matches("test-id")
        matches.extend(
            await forge_matcher.forge_matcher.find_protocol_matches("test-id")
        )
        matches.extend(
            await forge_matcher.forge_matcher.find_complementary_matches("test-id")
        )
        return matches

    matcher_profile = await profiler.profile_endpoint_memory(test_matching)
    print(f"  Matcher memory: {matcher_profile['memory_used_mb']:.2f}MB")

    # Test 3: Simulate heavy load
    print("\n Simulating heavy load...")

    async def heavy_load_test():
        results = []
        for i in range(100):
            # Simulate database queries
            data = await db.select("forge_classification", {}, limit=100)
            results.append(data)
        return results

    load_profile = await profiler.profile_endpoint_memory(heavy_load_test)
    print(f"  Heavy load memory: {load_profile['memory_used_mb']:.2f}MB")

    # Take final snapshot
    final = profiler.take_snapshot("Final")

    # Analyze patterns
    print("\n=== MEMORY ANALYSIS ===")
    patterns = profiler.analyze_memory_patterns()

    print("\n Memory Statistics:")
    print(f"  Peak Memory: {patterns['peak_memory_mb']:.2f}MB")
    print(f"  Average Memory: {patterns['average_memory_mb']:.2f}MB")
    print(f"  Growth Rate: {patterns['memory_growth_rate_mb_per_min']:.2f}MB/min")

    if patterns.get("memory_hotspots"):
        print("\n Memory Hotspots:")
        for hotspot in patterns["memory_hotspots"][:5]:
            print(f"  - {hotspot['location']}: {hotspot['average_size_mb']:.2f}MB avg")

    # Generate optimizations
    print("\n=== OPTIMIZATION RECOMMENDATIONS ===")
    optimizations = profiler.generate_optimizations()

    for opt in optimizations:
        print(f"\n [{opt['priority']}] {opt['issue']}")
        print(f" Details: {opt['details']}")
        print(" Recommendations:")
        for rec in opt["recommendations"][:3]:
            print(f"  - {rec}")

    # Export results
    results = {
        "timestamp": datetime.now().isoformat(),
        "snapshots": [
            {
                "timestamp": s.timestamp.isoformat(),
                "rss_mb": s.rss_mb,
                "heap_mb": s.heap_size_mb,
                "gc_objects": s.gc_stats["objects"],
            }
            for s in profiler.snapshots
        ],
        "patterns": patterns,
        "memory_leaks": profiler.memory_leaks,
        "optimizations": optimizations,
    }

    filename = f"forge_memory_profile_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n Results exported to {filename}")

    # Cleanup
    await db.disconnect()
    tracemalloc.stop()


if __name__ == "__main__":
    asyncio.run(profile_forge_apis())

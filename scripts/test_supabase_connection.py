#!/usr/bin/env python3
"""
Test Supabase PostgreSQL connectivity using different connection methods.

Usage:
    python3 test_supabase_connection.py [options]

Options:
    --direct       Test direct connection (db.xxx.supabase.co:5432) - IPv6 only
    --pooler       Test transaction pooler (pooler:6543) - IPv4+IPv6
    --session      Test session pooler (pooler:5432) - IPv4+IPv6
    --all          Test all connection methods (default)
    --password     PostgreSQL password (or set SUPABASE_PASSWORD env var)

Examples:
    python3 test_supabase_connection.py --pooler
    python3 test_supabase_connection.py --all --password "your-password"
    SUPABASE_PASSWORD="xxx" python3 test_supabase_connection.py
"""

import asyncio
import os
import sys
from typing import Optional


def get_connection_strings(password: str) -> dict:
    """Return connection strings for different Supabase connection methods."""
    project_ref = "pjjelfyuplqjgljvuybr"

    return {
        "direct": f"postgresql://postgres.{project_ref}:{password}@db.{project_ref}.supabase.co:5432/postgres?sslmode=require",
        "pooler_transaction": f"postgresql://postgres.{project_ref}:{password}@aws-0-us-east-1.pooler.supabase.com:6543/postgres",
        "pooler_session": f"postgresql://postgres.{project_ref}:{password}@aws-0-us-east-1.pooler.supabase.com:5432/postgres",
    }


async def test_connection(name: str, connection_string: str) -> dict:
    """Test a PostgreSQL connection and return results."""
    result = {
        "name": name,
        "success": False,
        "error": None,
        "version": None,
        "database": None,
        "server_ip": None,
        "latency_ms": None,
    }

    try:
        import asyncpg
        from time import time

        print(f"\n{'='*60}")
        print(f"Testing: {name}")
        print(f"{'='*60}")

        # Mask password in display
        display_url = connection_string.split("@")[1] if "@" in connection_string else connection_string
        print(f"Endpoint: {display_url}")

        start_time = time()
        conn = await asyncpg.connect(connection_string, timeout=10, ssl="require")
        latency = (time() - start_time) * 1000  # Convert to milliseconds

        result["latency_ms"] = round(latency, 2)

        # Run test queries
        version = await conn.fetchval("SELECT version()")
        database = await conn.fetchval("SELECT current_database()")
        server_ip = await conn.fetchval("SELECT inet_server_addr()")

        result["success"] = True
        result["version"] = version
        result["database"] = database
        result["server_ip"] = str(server_ip) if server_ip else "N/A"

        print(f"✓ Connection successful! ({result['latency_ms']}ms)")
        print(f"  Database: {database}")
        print(f"  Server IP: {result['server_ip']}")
        print(f"  Version: {version[:80]}...")

        await conn.close()

    except ImportError:
        result["error"] = "asyncpg not installed. Run: pip install asyncpg"
        print(f"✗ Error: {result['error']}")
    except asyncio.TimeoutError:
        result["error"] = "Connection timeout (>10s)"
        print(f"✗ Error: {result['error']}")
    except Exception as e:
        result["error"] = str(e)
        print(f"✗ Connection failed: {e}")

    return result


async def run_tests(password: str, test_modes: list) -> None:
    """Run connection tests for specified modes."""
    connection_strings = get_connection_strings(password)

    mode_map = {
        "direct": ("Direct Connection (IPv6 only)", connection_strings["direct"]),
        "pooler": ("Transaction Pooler (IPv4+IPv6)", connection_strings["pooler_transaction"]),
        "session": ("Session Pooler (IPv4+IPv6)", connection_strings["pooler_session"]),
    }

    results = []

    for mode in test_modes:
        if mode in mode_map:
            name, conn_str = mode_map[mode]
            result = await test_connection(name, conn_str)
            results.append(result)

    # Print summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")

    success_count = sum(1 for r in results if r["success"])
    total_count = len(results)

    for result in results:
        status = "✓" if result["success"] else "✗"
        latency = f"{result['latency_ms']}ms" if result["latency_ms"] else "N/A"
        error = f" - {result['error']}" if result["error"] else ""
        print(f"{status} {result['name']:<40} {latency:>10}{error}")

    print(f"\nSuccess rate: {success_count}/{total_count}")

    # Recommendations
    print(f"\n{'='*60}")
    print("RECOMMENDATIONS")
    print(f"{'='*60}")

    if any(r["name"].startswith("Transaction Pooler") and r["success"] for r in results):
        print("✓ Transaction Pooler is working - RECOMMENDED for Azure Container Apps")
        print("  Use port 6543 with IPv4 support")
        print("  Connection string format:")
        print("  postgresql://postgres.PROJECT_REF:PASSWORD@aws-0-us-east-1.pooler.supabase.com:6543/postgres")
    elif any(r["name"].startswith("Session Pooler") and r["success"] for r in results):
        print("✓ Session Pooler is working - Alternative option")
        print("  Use port 5432 with IPv4 support and full PostgreSQL compatibility")
    else:
        print("✗ No pooler connections succeeded")
        print("  Check:")
        print("  1. Network connectivity to Supabase")
        print("  2. Database password is correct")
        print("  3. Supabase project is active")

    if any(r["name"].startswith("Direct Connection") and not r["success"] for r in results):
        if "Network is unreachable" in str(results[0].get("error", "")):
            print("\n⚠ Direct connection failed due to IPv6")
            print("  This is EXPECTED on Azure Container Apps (IPv4-only egress)")
            print("  Solution: Use connection pooler instead")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Test Supabase PostgreSQL connectivity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument("--direct", action="store_true", help="Test direct connection (IPv6)")
    parser.add_argument("--pooler", action="store_true", help="Test transaction pooler (IPv4)")
    parser.add_argument("--session", action="store_true", help="Test session pooler (IPv4)")
    parser.add_argument("--all", action="store_true", help="Test all methods (default)")
    parser.add_argument("--password", type=str, help="PostgreSQL password")

    args = parser.parse_args()

    # Get password
    password = args.password or os.getenv("SUPABASE_PASSWORD")

    if not password:
        print("Error: Password required. Use --password or set SUPABASE_PASSWORD environment variable")
        sys.exit(1)

    # Determine which tests to run
    test_modes = []
    if args.direct:
        test_modes.append("direct")
    if args.pooler:
        test_modes.append("pooler")
    if args.session:
        test_modes.append("session")

    # Default to all if none specified
    if not test_modes or args.all:
        test_modes = ["direct", "pooler", "session"]

    # Run tests
    print("Supabase Connection Test")
    print(f"Project: pjjelfyuplqjgljvuybr")
    print(f"Testing {len(test_modes)} connection method(s)...")

    asyncio.run(run_tests(password, test_modes))


if __name__ == "__main__":
    main()

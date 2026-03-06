#!/usr/bin/env python3
"""
Monitor Forge Enrichment Progress

This script monitors the progress of the forge enrichment worker and provides
status information about enriched vs non-enriched records.

Usage:
    python scripts/monitor_forge_enrichment.py
    python scripts/monitor_forge_enrichment.py --detailed
    python scripts/monitor_forge_enrichment.py --export-csv enrichment_status.csv
"""

import argparse
import asyncio
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from api.config import settings
from api.database import db


async def get_enrichment_stats():
    """Get enrichment statistics."""
    try:
        await db.connect()

        # Total public_scans
        total_scans_result = await db.execute_raw_sql_single(
            "SELECT COUNT(*) as count FROM public_scans"
        )
        total_scans = total_scans_result["count"]

        # Enriched classifications
        enriched_result = await db.execute_raw_sql_single(
            "SELECT COUNT(*) as count FROM forge_classification WHERE metadata_json LIKE '%\"forge_api_enriched\":true%'"
        )
        enriched_count = enriched_result["count"]

        # Non-enriched (pending)
        pending_result = await db.execute_raw_sql_single("""
            SELECT COUNT(DISTINCT CONCAT(ps.ecosystem, ':', ps.package_name, ':', ps.package_version)) as count
            FROM public_scans ps
            LEFT JOIN forge_classification fc ON (
                ps.ecosystem = fc.ecosystem 
                AND ps.package_name = fc.package_name 
                AND ps.package_version = fc.package_version
                AND fc.metadata_json LIKE '%"forge_api_enriched":true%'
            )
            WHERE fc.id IS NULL
        """)
        pending_count = pending_result["count"]

        # Ecosystem breakdown for enriched
        ecosystem_breakdown = await db.execute_raw_sql("""
            SELECT fc.ecosystem, COUNT(*) as count
            FROM forge_classification fc
            WHERE fc.metadata_json LIKE '%"forge_api_enriched":true%'
            GROUP BY fc.ecosystem
            ORDER BY count DESC
        """)

        # Recent enrichments
        recent_enrichments = await db.execute_raw_sql("""
            SELECT TOP (10) fc.ecosystem, fc.package_name, fc.updated_at
            FROM forge_classification fc
            WHERE fc.metadata_json LIKE '%"forge_api_enriched":true%'
            ORDER BY fc.updated_at DESC
        """)

        return {
            "total_scans": total_scans,
            "enriched_count": enriched_count,
            "pending_count": pending_count,
            "completion_percentage": (enriched_count / total_scans * 100)
            if total_scans > 0
            else 0,
            "ecosystem_breakdown": ecosystem_breakdown,
            "recent_enrichments": recent_enrichments,
        }

    except Exception as e:
        print(f"Error getting enrichment stats: {e}")
        return None
    finally:
        await db.disconnect()


async def get_detailed_status():
    """Get detailed status of enrichment by ecosystem."""
    try:
        await db.connect()

        detailed_status = await db.execute_raw_sql("""
            SELECT 
                ps.ecosystem,
                COUNT(DISTINCT CONCAT(ps.ecosystem, ':', ps.package_name, ':', ps.package_version)) as total,
                COUNT(DISTINCT CASE WHEN fc.metadata_json LIKE '%"forge_api_enriched":true%' 
                      THEN CONCAT(ps.ecosystem, ':', ps.package_name, ':', ps.package_version) END) as enriched,
                COUNT(DISTINCT CASE WHEN fc.metadata_json IS NULL OR fc.metadata_json NOT LIKE '%"forge_api_enriched":true%' 
                      THEN CONCAT(ps.ecosystem, ':', ps.package_name, ':', ps.package_version) END) as pending
            FROM public_scans ps
            LEFT JOIN forge_classification fc ON (
                ps.ecosystem = fc.ecosystem 
                AND ps.package_name = fc.package_name 
                AND ps.package_version = fc.package_version
            )
            GROUP BY ps.ecosystem
            ORDER BY total DESC
        """)

        return detailed_status

    except Exception as e:
        print(f"Error getting detailed status: {e}")
        return []
    finally:
        await db.disconnect()


async def export_pending_records(output_file: str):
    """Export pending records to CSV."""
    try:
        await db.connect()

        pending_records = await db.execute_raw_sql("""
            SELECT DISTINCT ps.ecosystem, ps.package_name, ps.package_version, ps.verdict, ps.scanned_at
            FROM public_scans ps
            LEFT JOIN forge_classification fc ON (
                ps.ecosystem = fc.ecosystem 
                AND ps.package_name = fc.package_name 
                AND ps.package_version = fc.package_version
                AND fc.metadata_json LIKE '%"forge_api_enriched":true%'
            )
            WHERE fc.id IS NULL
            ORDER BY ps.scanned_at DESC
        """)

        with open(output_file, "w", newline="") as csvfile:
            fieldnames = [
                "ecosystem",
                "package_name",
                "package_version",
                "verdict",
                "scanned_at",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for record in pending_records:
                writer.writerow(record)

        print(f"✅ Exported {len(pending_records)} pending records to {output_file}")

    except Exception as e:
        print(f"Error exporting pending records: {e}")
    finally:
        await db.disconnect()


def print_stats(stats):
    """Print enrichment statistics in a formatted way."""
    print("🔍 Forge Enrichment Status")
    print("=" * 40)

    print(f"Total Scans:     {stats['total_scans']:,}")
    print(f"Enriched:        {stats['enriched_count']:,}")
    print(f"Pending:         {stats['pending_count']:,}")
    print(f"Completion:      {stats['completion_percentage']:.1f}%")

    print("\n📊 Enriched by Ecosystem:")
    for eco in stats["ecosystem_breakdown"]:
        print(f"  {eco['ecosystem']:<12} {eco['count']:,} packages")

    if stats["recent_enrichments"]:
        print("\n🕒 Recent Enrichments:")
        for recent in stats["recent_enrichments"][:5]:
            timestamp = recent["updated_at"].strftime("%Y-%m-%d %H:%M")
            print(f"  {timestamp} {recent['ecosystem']}/{recent['package_name']}")


def print_detailed_status(detailed_status):
    """Print detailed status by ecosystem."""
    print("\n📈 Detailed Status by Ecosystem:")
    print(f"{'Ecosystem':<12} {'Total':<8} {'Enriched':<10} {'Pending':<8} {'%':<6}")
    print("-" * 50)

    for row in detailed_status:
        ecosystem = row["ecosystem"]
        total = row["total"]
        enriched = row["enriched"] or 0
        pending = row["pending"] or 0
        percentage = (enriched / total * 100) if total > 0 else 0

        print(
            f"{ecosystem:<12} {total:<8,} {enriched:<10,} {pending:<8,} {percentage:<6.1f}%"
        )


async def main():
    parser = argparse.ArgumentParser(
        description="Monitor forge enrichment progress",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--detailed", action="store_true", help="Show detailed breakdown by ecosystem"
    )
    parser.add_argument(
        "--export-csv", metavar="FILE", help="Export pending records to CSV file"
    )
    parser.add_argument(
        "--watch", action="store_true", help="Watch mode - refresh every 30 seconds"
    )

    args = parser.parse_args()

    if not settings.database_configured:
        print("❌ Database not configured")
        return 1

    if args.export_csv:
        await export_pending_records(args.export_csv)
        return 0

    try:
        while True:
            # Clear screen in watch mode
            if args.watch:
                print("\033[2J\033[H")  # Clear screen and move cursor to top

            stats = await get_enrichment_stats()
            if not stats:
                return 1

            print_stats(stats)

            if args.detailed:
                detailed_status = await get_detailed_status()
                print_detailed_status(detailed_status)

            if not args.watch:
                break

            print(f"\n⏱️  Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("Press Ctrl+C to exit watch mode")

            try:
                await asyncio.sleep(30)
            except KeyboardInterrupt:
                print("\n👋 Stopping monitor...")
                break

        return 0

    except KeyboardInterrupt:
        print("\n👋 Monitoring stopped")
        return 0
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
